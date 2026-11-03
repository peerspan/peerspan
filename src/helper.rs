//! The optional transport-only operator `peerspan-helper` (spec section 9.7,
//! docs/decentralized-helper-contract.md). It serves opaque mailboxes on
//! `peerspan-bootstrap/1` and the relay on `peerspan-relay/4`, and nothing
//! else. It owns a transport key and resource storage only: it never opens a
//! host database and holds no network records or authority.
mod relay;
mod state;

use crate::decentralized::{bootstrap, codec, mailbox::ParticipantMailbox};
use serde::Serialize;
use std::{
    collections::HashMap,
    io::Write,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinSet};

pub use state::default_state;

const RELAY_ALPN: &[u8] = b"peerspan-relay/4";
pub const PROTOCOLS: [&str; 2] = ["peerspan-bootstrap/1", "peerspan-relay/4"];

/// The actual TLS client: its canonical Base64 key and socket source bucket.
#[derive(Clone)]
pub(crate) struct Peer {
    key: String,
    raw: Vec<u8>,
    source: String,
}

#[derive(Serialize)]
struct Info<'a> {
    public_key: String,
    protocols: [&'a str; 2],
}
#[derive(Serialize)]
struct Listening<'a> {
    public_key: String,
    address: String,
    protocols: [&'a str; 2],
}

/// Why `info` failed: no identity yet, or anything else.
pub enum InfoError {
    NotFound,
    Failed,
}
/// Prints `{public_key, protocols}` for an existing identity; creates nothing.
pub fn info(state: &Path, out: &mut impl Write) -> Result<(), InfoError> {
    let key = state::public_identity(state).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            InfoError::NotFound
        } else {
            InfoError::Failed
        }
    })?;
    let line = serde_json::to_string(&Info {
        public_key: key,
        protocols: PROTOCOLS,
    })
    .map_err(|_| InfoError::Failed)?;
    writeln!(out, "{line}")
        .and_then(|_| out.flush())
        .map_err(|_| InfoError::Failed)
}

/// `HOST:PORT` with a literal port; an empty host binds every interface.
fn listen_address(listen: &str) -> anyhow::Result<String> {
    let invalid = || anyhow::anyhow!("invalid listen address");
    let (host, port) = if let Some(rest) = listen.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or_else(invalid)?;
        (host, port)
    } else {
        let (host, port) = listen.rsplit_once(':').ok_or_else(invalid)?;
        if host.contains(':') {
            return Err(invalid());
        }
        (host, port)
    };
    if host.contains(['\r', '\n', '\0', '[', ']']) {
        return Err(invalid());
    }
    let number: u16 = port.parse().map_err(|_| invalid())?;
    if number.to_string() != port {
        return Err(invalid());
    }
    Ok(if host.is_empty() {
        format!("[::]:{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// Full IPv4, or the IPv6 /64 after IPv4-mapped normalization.
fn source_bucket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v) => v.to_string(),
            None => {
                let mut segments = v.segments();
                segments[4..].fill(0);
                format!("{}/64", std::net::Ipv6Addr::from(segments))
            }
        },
    }
}

/// TCP admission: 1024 connections, 64 per source, and 16 pending TLS
/// handshakes per source with 128 in total.
#[derive(Default)]
struct Admission {
    counts: Mutex<Counts>,
}
#[derive(Default)]
struct Counts {
    total: usize,
    sources: HashMap<String, usize>,
    pending: usize,
    pending_sources: HashMap<String, usize>,
}
fn decrement(map: &mut HashMap<String, usize>, key: &str) {
    if let Some(v) = map.get_mut(key) {
        *v -= 1;
        if *v == 0 {
            map.remove(key);
        }
    }
}
struct Admitted {
    owner: Arc<Admission>,
    source: String,
    pending: bool,
}
impl Admission {
    fn admit(self: &Arc<Self>, source: &str) -> Option<Admitted> {
        let mut c = self.counts.lock().ok()?;
        if c.total >= 1024
            || c.sources.get(source).copied().unwrap_or(0) >= 64
            || c.pending >= 128
            || c.pending_sources.get(source).copied().unwrap_or(0) >= 16
        {
            return None;
        }
        c.total += 1;
        c.pending += 1;
        *c.sources.entry(source.into()).or_default() += 1;
        *c.pending_sources.entry(source.into()).or_default() += 1;
        Some(Admitted {
            owner: self.clone(),
            source: source.into(),
            pending: true,
        })
    }
}
impl Admitted {
    fn handshaken(&mut self) {
        if self.pending
            && let Ok(mut c) = self.owner.counts.lock()
        {
            c.pending -= 1;
            decrement(&mut c.pending_sources, &self.source);
            self.pending = false;
        }
    }
}
impl Drop for Admitted {
    fn drop(&mut self) {
        self.handshaken();
        if let Ok(mut c) = self.owner.counts.lock() {
            c.total -= 1;
            decrement(&mut c.sources, &self.source);
        }
    }
}

/// Serves until `shutdown` resolves. Stdout gets exactly one metadata line
/// once listening and nothing afterwards.
pub async fn serve(
    state: &Path,
    listen: &str,
    tokens_file: Option<&Path>,
    out: &mut (impl Write + Send),
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    let address = listen_address(listen)?;
    let accounts = match tokens_file {
        Some(path) => Some(
            state::load_accounts(path)
                .map_err(|_| anyhow::anyhow!("invalid resource configuration"))?,
        ),
        None => None,
    };
    let owned = state::own_state(state)?;
    let mailboxes = ParticipantMailbox::open_helper(&owned.path, accounts.clone())?;
    let relay = relay::Hub::new(accounts);
    let listener = TcpListener::bind(&address)
        .await
        .map_err(|_| anyhow::anyhow!("helper listen failed"))?;
    let tls = crate::peer::helper_server_config(owned.key.clone(), &[bootstrap::ALPN, RELAY_ALPN])?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let line = serde_json::to_string(&Listening {
        public_key: codec::encode(owned.key.verifying_key().as_bytes()),
        address: listener.local_addr()?.to_string(),
        protocols: PROTOCOLS,
    })?;
    writeln!(out, "{line}")?;
    out.flush()?;
    let admission = Arc::new(Admission::default());
    let mut tasks = JoinSet::new();
    let mut health = tokio::time::interval(Duration::from_secs(1));
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break Ok(()),
            _ = health.tick() => if mailboxes.unavailable() {
                break Err(anyhow::anyhow!("helper storage unavailable"));
            },
            Some(_) = tasks.join_next() => {}
            accepted = listener.accept() => {
                let Ok((stream, remote)) = accepted else {
                    break Err(anyhow::anyhow!("helper accept failed"));
                };
                let source = source_bucket(remote.ip());
                let Some(admitted) = admission.admit(&source) else { continue };
                tasks.spawn(connection(
                    acceptor.clone(), stream, admitted, mailboxes.clone(), relay.clone(),
                ));
            }
        }
    };
    drop(listener);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(owned);
    result
}

async fn connection(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    mut admitted: Admitted,
    mailboxes: Arc<ParticipantMailbox>,
    relay: Arc<relay::Hub>,
) {
    let _ = stream.set_nodelay(true);
    let Ok(remote) = stream.peer_addr() else {
        return;
    };
    let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await
    else {
        return;
    };
    admitted.handshaken();
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    if alpn.as_deref() == Some(bootstrap::ALPN) {
        let _ = mailboxes.serve_connection(tls).await;
        return;
    }
    if alpn.as_deref() != Some(RELAY_ALPN) {
        return;
    }
    let Some(raw) = tls
        .get_ref()
        .1
        .peer_certificates()
        .filter(|c| c.len() == 1)
        .and_then(|c| crate::peer::certificate_key(&c[0], rustls::pki_types::UnixTime::now()).ok())
    else {
        return;
    };
    let key = codec::encode(&raw);
    if !codec::key(&key) {
        return;
    }
    let peer = Peer {
        key,
        raw,
        source: source_bucket(remote.ip()),
    };
    relay.serve(tls, peer).await;
}
