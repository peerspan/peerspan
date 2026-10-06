mod cli;
mod integration;

use anyhow::{Context, bail};
use bytes::Bytes;
use capsule_host::{api, membership, model, persons, store::Store};
use clap::{CommandFactory, Parser};
use cli::Cli;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    env, fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
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
    if matches!(
        &command,
        cli::Command::Session(
            cli::SessionCommand::Setup { .. }
                | cli::SessionCommand::Start { .. }
                | cli::SessionCommand::Doctor { .. }
        )
    ) {
        let cli::Command::Session(operation) = command else {
            unreachable!()
        };
        return integration::run(operation, cli.state).await;
    }
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
    if let Some(value) = person_command(&command, &directory).await? {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
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

/// Commands that sign with a person key. The key stays with the CLI (an
/// ssh-agent identity or a key file); the daemon only receives the signed
/// statement. `person show` needs no daemon at all.
async fn person_command(command: &cli::Command, directory: &Path) -> anyhow::Result<Option<Value>> {
    use cli::{Command, NetworkCommand, PersonCommand, encoded};
    let socket = directory.join("admin.sock");
    let signer = |path: &Option<PathBuf>| {
        persons::PersonSigner::open(path.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))
    };
    let at = || chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let local = |method: Method, path: String, body: Option<Value>| {
        let socket = socket.clone();
        async move {
            tokio::time::timeout(Duration::from_secs(10), call(socket, method, path, body))
                .await
                .context("local host daemon request timed out")?
        }
    };
    let value = match command {
        Command::Person(PersonCommand::Show { person_key }) => {
            let signer = signer(person_key)?;
            let key = signer.public_key();
            json!({
                "person_id": persons::person_id(&key),
                "public_key": signer.public_key_b64(),
                "ssh_public_key": persons::ssh_public_line(&key),
            })
        }
        Command::Network(NetworkCommand::Create {
            name,
            member,
            coordinator,
            coordinator_key,
            person_key,
            no_person,
        }) => {
            let found = explicit_key(*no_person, person_key)?;
            let mut body = json!({
                "name": name,
                "member": member,
                "coordinator_address": coordinator,
                "coordinator_public_key": coordinator_key,
            });
            if let Ok(signer) = &found {
                body["person_public_key"] = json!(signer.public_key_b64());
            }
            let mut value = local(Method::POST, "/v1/networks".into(), Some(body)).await?;
            let network = value["id"].as_str().unwrap_or_default().to_owned();
            match found {
                Ok(signer) if value["person"]["admitted"] == json!(true) => {
                    // Admitted with the new root: bind this host now, signed
                    // here so the person key never reaches the daemon.
                    let result = async {
                        let host = local(Method::GET, "/v1/host".into(), None).await?;
                        let key = host["public_key"]
                            .as_str()
                            .context("host daemon returned no public key")?;
                        let binding = persons::HostBinding::sign(&signer, &network, key, &at())
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        local(
                            Method::POST,
                            format!("/v1/networks/{}/bindings", encoded(&network)),
                            Some(json!({"binding": binding})),
                        )
                        .await
                    }
                    .await;
                    match result {
                        Ok(_) => {
                            value["person"]["bound"] = json!(true);
                            value["person"]["next"] = Value::Null;
                        }
                        Err(e) => {
                            value["person"]["skipped"] = json!(format!("binding failed: {e:#}"));
                            value["person"]["next"] = json!(bind_next(&network));
                        }
                    }
                }
                Ok(_) => {}
                Err(reason) => {
                    let next = (!*no_person).then(|| {
                        format!(
                            "an administrator runs: capsule-host network admit --network {network} --person '<your ssh-ed25519 public key>' --member {member}; then: {}",
                            bind_next(&network)
                        )
                    });
                    value["person"] = skipped(reason, next);
                }
            }
            value
        }
        Command::Network(NetworkCommand::Join {
            token,
            descriptor,
            person_key,
            no_person,
        }) => {
            let found = explicit_key(*no_person, person_key)?;
            let mut body = match (token, descriptor) {
                (Some(token), _) => json!({"token": token}),
                (None, descriptor) => json!({"descriptor": descriptor}),
            };
            let network = token.as_deref().and_then(token_network).or_else(|| {
                descriptor
                    .as_deref()
                    .and_then(|d| persons::Descriptor::decode(d).ok())
                    .map(|d| d.network_id)
            });
            if let Ok(signer) = &found {
                body["person_public_key"] = json!(signer.public_key_b64());
                // Sign the binding before joining: the token or descriptor names
                // the network, and the daemon names this host. If either is
                // unavailable, the daemon reports the missing binding.
                if let Some(network) = &network
                    && let Ok(host) = local(Method::GET, "/v1/host".into(), None).await
                    && let Some(key) = host["public_key"].as_str()
                    && let Ok(binding) = persons::HostBinding::sign(signer, network, key, &at())
                {
                    body["binding"] = json!(binding);
                }
            }
            let mut value = local(Method::POST, "/v1/networks/join".into(), Some(body)).await?;
            if let Err(reason) = found {
                let id = value["id"].as_str().unwrap_or_default().to_owned();
                let member_token = token
                    .as_deref()
                    .is_some_and(|t| t.trim().starts_with(persons::MEMBER_TOKEN_PREFIX));
                let next = (!*no_person).then(|| match token {
                    Some(token) if member_token => format!(
                        "capsule-host network redeem-person --token {token} --person-key PATH; then: {} --person-key PATH",
                        bind_next(&id)
                    ),
                    _ => format!(
                        "after an administrator admits your person: {} --person-key PATH",
                        bind_next(&id)
                    ),
                });
                value["person"] = skipped(reason, next);
            }
            value
        }
        Command::Network(NetworkCommand::RedeemPerson { token, person_key }) => {
            let signer = signer(person_key)?;
            local(
                Method::POST,
                "/v1/networks/redeem-person".into(),
                Some(json!({"token": token, "person_public_key": signer.public_key_b64()})),
            )
            .await?
        }
        Command::Network(NetworkCommand::Bind {
            network,
            person_key,
        }) => {
            let signer = signer(person_key)?;
            let host = local(Method::GET, "/v1/host".into(), None).await?;
            let key = host["public_key"]
                .as_str()
                .context("host daemon returned no public key")?;
            let binding = persons::HostBinding::sign(&signer, network, key, &at())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            local(
                Method::POST,
                format!("/v1/networks/{}/bindings", encoded(network)),
                Some(json!({"binding": binding})),
            )
            .await?
        }
        Command::Network(NetworkCommand::Unbind {
            network,
            host,
            person_key,
        }) => {
            let signer = signer(person_key)?;
            let members = local(
                Method::GET,
                format!("/v1/networks/{}/members", encoded(network)),
                None,
            )
            .await?;
            let key = members
                .as_array()
                .into_iter()
                .flatten()
                .find(|m| m["host_id"].as_str() == Some(host.as_str()))
                .and_then(|m| m["public_key"].as_str())
                .context("that host is not a member of this network")?
                .to_owned();
            let unbinding = persons::HostUnbinding::sign(&signer, network, &key, &at())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            local(
                Method::POST,
                format!("/v1/networks/{}/unbindings", encoded(network)),
                Some(json!({"unbinding": unbinding})),
            )
            .await?
        }
        _ => return Ok(None),
    };
    Ok(Some(value))
}

/// Finds the person key for the one-command flows. A missing or ambiguous key
/// is never an error: the person step is skipped and the reason reported.
fn discover(no_person: bool, path: &Option<PathBuf>) -> Result<persons::PersonSigner, String> {
    if no_person {
        return Err("person step disabled with --no-person".into());
    }
    persons::PersonSigner::open(path.as_deref()).map_err(|e| match e {
        model::Error::Invalid(message) => message,
        other => other.to_string(),
    })
}
/// An explicit --person-key must be usable before anything happens; only
/// automatic discovery skips.
fn explicit_key(
    no_person: bool,
    path: &Option<PathBuf>,
) -> anyhow::Result<Result<persons::PersonSigner, String>> {
    let found = discover(no_person, path);
    if let (Some(path), Err(reason)) = (path, &found) {
        bail!("--person-key {}: {reason}", path.display());
    }
    Ok(found)
}
/// The network a token names, read locally so the CLI can sign a binding
/// before joining. The daemon verifies the token itself.
fn token_network(token: &str) -> Option<String> {
    persons::MemberInviteToken::decode(token)
        .map(|t| t.network_id)
        .or_else(|_| membership::InviteToken::decode(token).map(|t| t.network_id))
        .ok()
}
fn bind_next(network: &str) -> String {
    format!("capsule-host network bind --network {network}")
}
fn skipped(reason: String, next: Option<String>) -> Value {
    json!({
        "person_id": Value::Null,
        "admitted": false,
        "bound": false,
        "skipped": reason,
        "next": next,
    })
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
    let listening = match peer_listen {
        Some(address) => {
            let bound = capsule_host::quic::listen(&store, address)?;
            let advertised = match advertise {
                Some(address) => address.to_string(),
                None if !bound.ip().is_unspecified() => bound.to_string(),
                None => String::new(),
            };
            eprintln!("peer listener udp {bound} (advertising {advertised:?})");
            store.set_advertised(advertised);
            true
        }
        None => false,
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
    let reply_workers =
        capsule_host::adapter_outbound::reply_workers(store.clone(), peer_shutdown.clone());
    let retries = capsule_host::retry::retry_worker(store.clone(), peer_shutdown.clone());
    let peers = async {
        if listening {
            capsule_host::quic::serve(store, peer_shutdown).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    use std::future::IntoFuture;
    tokio::try_join!(
        async { admin.await.map_err(anyhow::Error::from) },
        async { adapter.await.map_err(anyhow::Error::from) },
        peers,
        async {
            reply_workers.await;
            Ok(())
        },
        async {
            retries.await;
            Ok(())
        },
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
        .uri(path)
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
        return Err(integration::DaemonError {
            status: status.as_u16(),
            message: value["error"]
                .as_str()
                .unwrap_or("request failed")
                .to_owned(),
        }
        .into());
    }
    Ok(value)
}
