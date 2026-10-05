mod cli;

use anyhow::{Context, bail};
use bytes::Bytes;
use capsule_host::{api, store::Store};
use clap::{CommandFactory, Parser};
use cli::Cli;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::{
    env, fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
};

#[tokio::main]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let directory = match cli.state {
        Some(directory) => directory,
        None => default_directory()?,
    };
    // this binary currently either starts a host daemon or a local admin client
    // the daemon serves admin requests, peer-listeners etc
    if let cli::Command::Run {
        peer_listen,
        advertise,
        coordination_interval,
    } = command
    {
        return run_daemon(directory, peer_listen, advertise, coordination_interval).await;
    }
    let request = command.request().expect("local control command");
    let value = tokio::time::timeout(
        Duration::from_secs(10),
        call(
            directory.join("admin.sock"),
            request.method,
            request.path,
            request.body,
        ),
    )
    .await
    .context("local host daemon request timed out")??;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn default_directory() -> anyhow::Result<PathBuf> {
    if let Some(directory) = env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            bail!("XDG_STATE_HOME must be an absolute path");
        }
        return Ok(directory.join("capsule/host"));
    }
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/state/capsule/host"))
}

/// Removes the socket on orderly shutdown. A crash leaves a stale socket that
/// the next owner of the exclusive state lock can remove.
struct SocketCleanup(PathBuf);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

async fn run_daemon(
    directory: PathBuf,
    peer_listen: Option<std::net::SocketAddr>,
    advertise: Option<std::net::SocketAddr>,
    coordination_interval: u64,
) -> anyhow::Result<()> {
    let store = Arc::new(Store::open(&directory)?);
    store.set_coordination_interval(coordination_interval);
    let path = store.socket_path();
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                bail!("admin socket path contains a non-socket file");
            }
            fs::remove_file(&path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&path)?;
    let _cleanup = SocketCleanup(path.clone());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let adapter_path = directory.join("adapter.sock");
    match fs::symlink_metadata(&adapter_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                bail!("adapter socket path contains a non-socket file");
            }
            fs::remove_file(&adapter_path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let adapter_listener = UnixListener::bind(&adapter_path)?;
    let _adapter_cleanup = SocketCleanup(adapter_path.clone());
    fs::set_permissions(&adapter_path, fs::Permissions::from_mode(0o600))?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    eprintln!(
        "host daemon {} listening on local control socket {}",
        store.identity().id,
        path.display()
    );
    let peer_listener = match peer_listen {
        Some(address) => {
            let listener = TcpListener::bind(address).await?;
            let bound = listener.local_addr()?;
            let advertised = match advertise {
                Some(address) => address.to_string(),
                None if !bound.ip().is_unspecified() => bound.to_string(),
                None => String::new(),
            };
            eprintln!("peer listener {bound} (advertising {advertised:?})");
            store.set_advertised(advertised);
            Some(listener)
        }
        None => None,
    };
    let (shutdown, peer_shutdown) = tokio::sync::watch::channel(false);
    let mut adapter_shutdown = peer_shutdown.clone();
    let adapter = axum::serve(
        adapter_listener,
        capsule_host::adapter::router(store.clone()),
    )
    .with_graceful_shutdown(async move {
        let _ = adapter_shutdown.changed().await;
    })
    .into_future();
    let admin = axum::serve(listener, api::router(store.clone()))
        .with_graceful_shutdown(async move {
            tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
            let _ = shutdown.send(true);
        })
        .into_future();
    let coordination = capsule_host::network::coordinate(store.clone(), peer_shutdown.clone());
    let peers = async {
        if let Some(listener) = peer_listener {
            capsule_host::peer::serve(listener, store, peer_shutdown).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    use std::future::IntoFuture;
    tokio::try_join!(
        async { admin.await.map_err(anyhow::Error::from) },
        async { adapter.await.map_err(anyhow::Error::from) },
        peers,
        async {
            coordination.await;
            Ok(())
        }
    )?;
    Ok(())
}

async fn call(
    socket: PathBuf,
    method: Method,
    path: String,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect to local host daemon")?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let encoded = match body {
        Some(body) => serde_json::to_vec(&body)?,
        None => Vec::new(),
    };
    let request = Request::builder()
        .method(method)
        .uri(format!("http://localhost{path}"))
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(encoded)))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let bytes = http_body_util::Limited::new(response.into_body(), 1 << 20)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read host response: {e}"))?
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes)?;
    if status.is_client_error() || status.is_server_error() {
        bail!(
            "host daemon: {}",
            value["error"].as_str().unwrap_or("request failed")
        );
    }
    Ok(value)
}
