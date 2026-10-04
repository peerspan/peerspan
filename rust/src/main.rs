use anyhow::{Context, bail};
use bytes::Bytes;
use capsule_host::{api, store::Store};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
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

const HELP: &str = "capsule-host manages a local agent host.

Usage:
  capsule-host [--state DIR] serve
  capsule-host [--state DIR] info
  capsule-host [--state DIR] agent register --name NAME --owner OWNER [--capability NAME]
  capsule-host [--state DIR] agent list
  capsule-host [--state DIR] agent inspect ID
  capsule-host [--state DIR] session attach --agent ID --integration NAME
  capsule-host [--state DIR] session list [--agent ID]
  capsule-host [--state DIR] session inspect ID
  capsule-host [--state DIR] session detach ID
  capsule-host [--state DIR] activity [--after SEQUENCE] [--limit COUNT]

Session attachment records metadata only; agent integration is a later milestone.
";

#[tokio::main]
async fn main() {
    if let Err(error) = run(env::args().skip(1).collect()).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(mut args: Vec<String>) -> anyhow::Result<()> {
    let mut directory = None;
    while args.first().is_some_and(|a| a.starts_with('-')) {
        match args[0].as_str() {
            "--help" | "-h" => {
                print!("{HELP}");
                return Ok(());
            }
            "--state" => {
                //BUG: this doesn't check if the directory exists, or is a directory - assumes the second arg (if it exists) is always a valid dir
                if args.len() < 2 {
                    bail!("--state requires a directory");
                }
                directory = Some(PathBuf::from(args.remove(1)));
                args.remove(0);
            }
            other => bail!("unknown option: {other}"),
        }
    }
    if args.is_empty() || args[0] == "help" {
        print!("{HELP}");
        return Ok(());
    }
    let directory = match directory {
        Some(d) => d,
        None => default_directory()?,
    };
    if args[0] == "serve" {
        if args.len() != 1 {
            bail!("serve accepts no positional arguments");
        }
        return serve(directory).await;
    }
    let (method, path, body) = request(&args)?;
    let value = tokio::time::timeout(
        Duration::from_secs(10),
        call(directory.join("admin.sock"), method, path, body),
    )
    .await
    .context("local host service request timed out")??;
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

async fn serve(directory: PathBuf) -> anyhow::Result<()> {
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
        "host {} listening on {}",
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
        .context("connect to local host service")?;
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
            "host service: {}",
            value["error"].as_str().unwrap_or("request failed")
        );
    }
    Ok(value)
}

fn options(args: &[String], allowed: &[&str]) -> anyhow::Result<HashMap<String, Vec<String>>> {
    let mut values: HashMap<String, Vec<String>> = HashMap::new();
    let mut args = args.iter();
    while let Some(key) = args.next() {
        let name = key
            .strip_prefix("--")
            .context("unexpected positional argument")?;
        if !allowed.contains(&name) {
            bail!("unknown option: {key}");
        }
        let value = args
            .next()
            .with_context(|| format!("{key} requires a value"))?;
        values.entry(name.into()).or_default().push(value.clone());
    }
    Ok(values)
}
fn one(options: &HashMap<String, Vec<String>>, name: &str) -> String {
    options
        .get(name)
        .and_then(|v| v.last())
        .cloned()
        .unwrap_or_default()
}

fn request(args: &[String]) -> anyhow::Result<(Method, String, Option<Value>)> {
    let (method, path, body) = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["info"] => (Method::GET, "/v1/host".into(), None),
        ["agent", "list"] => (Method::GET, "/v1/agents".into(), None),
        ["agent", "inspect", id] => (Method::GET, format!("/v1/agents/{}", encoded(id)), None),
        ["agent", "register", ..] => {
            let values = options(&args[2..], &["name", "owner", "capability"])?;
            (
                Method::POST,
                "/v1/agents".into(),
                Some(
                    json!({"name": one(&values, "name"), "owner": one(&values, "owner"), "capabilities": values.get("capability").cloned().unwrap_or_default()}),
                ),
            )
        }
        ["session", "attach", ..] => {
            let values = options(&args[2..], &["agent", "integration"])?;
            (
                Method::POST,
                "/v1/sessions".into(),
                Some(
                    json!({"agent_id": one(&values, "agent"), "integration": one(&values, "integration")}),
                ),
            )
        }
        ["session", "list", ..] => {
            let values = options(&args[2..], &["agent"])?;
            (
                Method::GET,
                format!("/v1/sessions?agent_id={}", encoded(&one(&values, "agent"))),
                None,
            )
        }
        ["session", "inspect", id] => (Method::GET, format!("/v1/sessions/{}", encoded(id)), None),
        ["session", "detach", id] => (
            Method::POST,
            format!("/v1/sessions/{}/detach", encoded(id)),
            None,
        ),
        ["activity", ..] => {
            let values = options(&args[1..], &["after", "limit"])?;
            let after = values
                .get("after")
                .map(|_| one(&values, "after").parse::<i64>())
                .transpose()?
                .unwrap_or(0);
            let limit = values
                .get("limit")
                .map(|_| one(&values, "limit").parse::<i64>())
                .transpose()?
                .unwrap_or(100);
            (
                Method::GET,
                format!("/v1/activity?after={after}&limit={limit}"),
                None,
            )
        }
        _ => bail!("invalid command; see capsule-host --help"),
    };
    Ok((method, path, body))
}

fn encoded(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
