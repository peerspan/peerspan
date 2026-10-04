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
    net::{UnixListener, UnixStream},
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
    let Some(request) = command.request() else {
        return run_daemon(directory).await;
    };
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

async fn run_daemon(directory: PathBuf) -> anyhow::Result<()> {
    let store = Arc::new(Store::open(&directory)?);
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
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    eprintln!(
        "host daemon {} listening on local control socket {}",
        store.identity().id,
        path.display()
    );
    axum::serve(listener, api::router(store))
        .with_graceful_shutdown(async move {
            tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
        })
        .await?;
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
