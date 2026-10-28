//! `peerspan-peer-probe`: a conformance test client for the peer wire format,
//! never installed with the host bundle. It presents a certificate for the
//! given host key but performs no pin check, so suites can exercise peer
//! routers directly. It is not a daemon client.
//!
//! ```text
//! peerspan-peer-probe (--state DIR | --seed-hex HEX) --address IP:PORT [--method M] [--path P]
//!     [--body RAW | --body-stdin] [--alpn ALPN]
//! peerspan-peer-probe sign-link (--state DIR | --seed-hex HEX) --network-id ID --index N
//!     --previous P --issuer HOST --audience HOST --task-id ID --originator-agent ID
//!     --principal P [--principal P ...] --deadline TIME --depth N
//! peerspan-peer-probe link-hash < LINK_JSON
//! peerspan-peer-probe submit-task (--state DIR | --seed-hex HEX) --address IP:PORT
//!     --request JSON --chain JSON
//! ```
//!
//! The exchange prints `{"body":…,"status":N}`. sign-link prints the link
//! signed with that host key exactly as given: principals keep their order and
//! nothing is validated. link-hash prints the `previous` value a following
//! link names. submit-task posts the request to `/peer/v1/tasks` with
//! `delegation` set to the chain.
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use peerspan_host::chain::Link;
use serde::Deserialize;
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

const PEER_ALPN: &str = "peerspan-peer/1";

#[derive(Parser)]
#[command(
    name = "peerspan-peer-probe",
    about = "Send a conformance request directly to a peer",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    exchange: Exchange,
}
#[derive(Args)]
struct KeyArgs {
    /// 32-byte Ed25519 seed, hex
    #[arg(long, default_value = "")]
    seed_hex: String,
    /// Host state directory whose key authenticates, instead of --seed-hex
    #[arg(long, default_value = "")]
    state: String,
}
#[derive(Args)]
struct Exchange {
    #[command(flatten)]
    key: KeyArgs,
    /// Peer IP:PORT
    #[arg(long, default_value = "")]
    address: String,
    /// HTTP method
    #[arg(long, default_value = "GET")]
    method: String,
    /// Request path
    #[arg(long, default_value = "/")]
    path: String,
    /// Raw request body, sent verbatim
    #[arg(long, default_value = "")]
    body: String,
    /// Read the raw request body from standard input
    #[arg(long)]
    body_stdin: bool,
    /// ALPN to offer
    #[arg(long, default_value = PEER_ALPN)]
    alpn: String,
}
#[derive(Subcommand)]
enum Command {
    /// Sign a delegation link with a host key
    SignLink(SignLink),
    /// Hash a delegation link read from standard input
    LinkHash,
    /// Post a task with a supplied delegation chain
    SubmitTask(SubmitTask),
}
#[derive(Args)]
struct SignLink {
    #[command(flatten)]
    key: KeyArgs,
    #[arg(long, default_value = "")]
    network_id: String,
    #[arg(long, default_value_t = 0)]
    index: u64,
    #[arg(long, default_value = peerspan_host::chain::NONE)]
    previous: String,
    /// issuer_host_id; default the signing host
    #[arg(long, default_value = "")]
    issuer: String,
    #[arg(long, default_value = "")]
    audience: String,
    #[arg(long, default_value = "")]
    task_id: String,
    #[arg(long, default_value = "")]
    originator_agent: String,
    /// Principal, in the given order; repeatable
    #[arg(long)]
    principal: Vec<String>,
    #[arg(long, default_value = "")]
    deadline: String,
    #[arg(long, default_value_t = 0)]
    depth: u64,
}
#[derive(Args)]
struct SubmitTask {
    #[command(flatten)]
    key: KeyArgs,
    /// Peer IP:PORT
    #[arg(long, default_value = "")]
    address: String,
    /// Task request JSON object, without delegation
    #[arg(long, default_value = "")]
    request: String,
    /// Delegation chain JSON, sent verbatim
    #[arg(long, default_value = "")]
    chain: String,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Some(Command::SignLink(args)) => sign_link(args),
        Some(Command::LinkHash) => link_hash(),
        Some(Command::SubmitTask(args)) => {
            let mut body: serde_json::Map<String, serde_json::Value> =
                match serde_json::from_str::<Option<serde_json::Map<_, _>>>(&args.request) {
                    Ok(Some(body)) => body,
                    _ => bail!("--request must be a JSON object"),
                };
            let chain: serde_json::Value =
                serde_json::from_str(&args.chain).context("--chain must be JSON")?;
            body.insert("delegation".into(), chain);
            let payload = serde_json::to_vec(&body)?;
            let key = host_key(&args.key)?;
            exchange(
                key,
                &args.address,
                PEER_ALPN,
                "POST",
                "/peer/v1/tasks",
                Some(payload),
            )
        }
        None => {
            let e = cli.exchange;
            let key = host_key(&e.key)?;
            let payload = if e.body_stdin {
                let mut payload = Vec::new();
                std::io::stdin().read_to_end(&mut payload)?;
                Some(payload)
            } else if !e.body.is_empty() {
                Some(e.body.into_bytes())
            } else {
                None
            };
            exchange(key, &e.address, &e.alpn, &e.method, &e.path, payload)
        }
    }
}

/// A host key from `--seed-hex` or from a state directory's database, which a
/// running daemon may hold open.
fn host_key(args: &KeyArgs) -> anyhow::Result<SigningKey> {
    if args.seed_hex.is_empty() == args.state.is_empty() {
        bail!("give exactly one of --seed-hex or --state");
    }
    if !args.state.is_empty() {
        let database = rusqlite::Connection::open_with_flags(
            PathBuf::from(&args.state).join("host.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        database.busy_timeout(Duration::from_secs(10))?;
        let key: Vec<u8> = database.query_row(
            "SELECT private_key FROM identity WHERE singleton = 1",
            [],
            |r| r.get(0),
        )?;
        let key: [u8; 64] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid stored host key"))?;
        let seed: [u8; 32] = key[..32].try_into().expect("64-byte key");
        return Ok(SigningKey::from_bytes(&seed));
    }
    let seed = hex::decode(&args.seed_hex)
        .ok()
        .and_then(|s| <[u8; 32]>::try_from(s).ok())
        .ok_or_else(|| anyhow::anyhow!("--seed-hex must be 32 bytes of hex"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sign_link(args: SignLink) -> anyhow::Result<()> {
    let key = host_key(&args.key)?;
    let issuer = if args.issuer.is_empty() {
        peerspan_host::peer_store::key_id(key.verifying_key().as_bytes())
    } else {
        args.issuer
    };
    let mut link = Link {
        network_id: args.network_id,
        index: args.index,
        previous: args.previous,
        issuer_host_id: issuer,
        audience_host_id: args.audience,
        task_id: args.task_id,
        originator_agent_id: args.originator_agent,
        principals: args.principal,
        deadline: args.deadline,
        depth: args.depth,
        signature: String::new(),
    };
    link.signature = STANDARD.encode(key.sign(link.statement().as_bytes()).to_bytes());
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &link)?;
    writeln!(out)?;
    Ok(())
}

/// Plain decoding, so a deliberately malformed link still hashes: missing
/// fields are empty, unknown fields are ignored.
#[derive(Deserialize, Default)]
#[serde(default)]
struct PlainLink {
    network_id: String,
    index: u64,
    previous: String,
    issuer_host_id: String,
    audience_host_id: String,
    task_id: String,
    originator_agent_id: String,
    principals: Option<Vec<String>>,
    deadline: String,
    depth: u64,
    signature: String,
}
fn link_hash() -> anyhow::Result<()> {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;
    let l: PlainLink = serde_json::from_slice(&data)?;
    let link = Link {
        network_id: l.network_id,
        index: l.index,
        previous: l.previous,
        issuer_host_id: l.issuer_host_id,
        audience_host_id: l.audience_host_id,
        task_id: l.task_id,
        originator_agent_id: l.originator_agent_id,
        principals: l.principals.unwrap_or_default(),
        deadline: l.deadline,
        depth: l.depth,
        signature: l.signature,
    };
    println!("{}", link.digest());
    Ok(())
}

/// Sends one request on a fresh QUIC connection and prints `{body, status}`.
fn exchange(
    key: SigningKey,
    address: &str,
    alpn: &str,
    method: &str,
    path: &str,
    payload: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (status, data) = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(8),
            request(key, address, alpn, method, path, payload),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout: no recent network activity"))?
    })?;
    let body = if data.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&data)
            .unwrap_or_else(|_| String::from_utf8_lossy(&data).into_owned().into())
    };
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(
        &mut out,
        &serde_json::json!({"status": status, "body": body}),
    )?;
    writeln!(out)?;
    Ok(())
}
async fn request(
    key: SigningKey,
    address: &str,
    alpn: &str,
    method: &str,
    path: &str,
    payload: Option<Vec<u8>>,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let remote = tokio::net::lookup_host(address)
        .await?
        .next()
        .context("address resolved to nothing")?;
    let tls = peerspan_host::peer::unpinned_client_config(&key, alpn.as_bytes())?;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(Duration::from_secs(30).try_into()?))
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window((16u32 << 10).into())
        .receive_window((16u32 << 10).into())
        .datagram_receive_buffer_size(None)
        .enable_segmentation_offload(false);
    config.transport_config(Arc::new(transport));
    let local: std::net::SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let endpoint = quinn::Endpoint::client(local)?;
    let connection = endpoint
        .connect_with(config, remote, "peerspan-peer")?
        .await?;
    let result = stream_request(&connection, address, method, path, payload).await;
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    result
}
/// One HTTP/1.1 request framed as Go's client writes it, then one bounded
/// response under the route's peer response limit.
async fn stream_request(
    connection: &quinn::Connection,
    address: &str,
    method: &str,
    path: &str,
    payload: Option<Vec<u8>>,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let (mut send, mut recv) = connection.open_bi().await?;
    let path = if path.is_empty() { "/" } else { path };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nUser-Agent: peerspan-peer-probe\r\n"
    );
    let body = payload.unwrap_or_default();
    if !body.is_empty() || !matches!(method, "GET" | "HEAD") {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Content-Type: application/json\r\n\r\n");
    send.write_all(head.as_bytes()).await?;
    send.write_all(&body).await?;
    send.finish()?;
    let limit = peerspan_host::quic::response_limit(method, path);
    let mut response = Vec::new();
    let mut chunk = [0u8; 16 << 10];
    while let Some(n) = recv.read(&mut chunk).await? {
        response.extend_from_slice(&chunk[..n]);
        if response.len() > limit + (64 << 10) {
            bail!("peer response too large");
        }
        if complete(&response) {
            break;
        }
    }
    peerspan_host::quic::parse_limited(&response, limit)
}
/// Whether a response with a declared length (or chunked framing) is whole,
/// so a server that keeps its stream open does not stall the probe.
fn complete(data: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let Ok(httparse::Status::Complete(start)) = response.parse(data) else {
        return false;
    };
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_ascii_lowercase())
    };
    if header("transfer-encoding").is_some_and(|v| v.ends_with("chunked")) {
        return data.ends_with(b"0\r\n\r\n");
    }
    header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|length| data.len() >= start + length)
}
