//! QUIC peer transport. One UDP endpoint per daemon accepts and dials peer
//! connections; each bidirectional stream carries exactly one HTTP/1.1
//! request and response. The owner-local router is never served here.
use crate::{
    api::blocking,
    disco::{Discovery, PathState},
    membership,
    peer::{certificate_key, client_config, peer_router, server_config},
    peer_store::{Peer, key_id, peer_key},
    relay::{Combined, Coordinator, Relays, raw_host},
    store::Store,
};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use quinn::{
    Connection, Endpoint, Incoming, TransportConfig, VarInt,
    crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig},
};
use rustls::pki_types::{CertificateDer, UnixTime};
use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::watch, task::JoinSet};

pub(crate) const ALPN: &[u8] = b"peerspan-peer/1";
const HANDSHAKE: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 64;
const MAX_STREAMS: u32 = 16;
const MAX_BODY: usize = 1 << 20;
/// A tool listing, or a call's status with a result of up to 1 MiB, may be
/// larger than other peer responses.
const MAX_LARGE_RESPONSE: usize = 4 << 20;
/// The response bound of a peer request.
fn response_limit(method: &str, path: &str) -> usize {
    let large = method == "GET"
        && (path == "/peer/v1/tools"
            || path.starts_with("/peer/v1/tools?")
            || path
                .strip_prefix("/peer/v1/calls/")
                .is_some_and(|id| !id.is_empty() && !id.contains('/')));
    if large { MAX_LARGE_RESPONSE } else { MAX_BODY }
}
const MAX_HEADERS: usize = 64 * 1024;
const SERVER_NAME: &str = "peerspan-peer";
const CID_LENGTH: usize = 4;
/// A direct attempt is bounded so a relay fallback still fits the request bound.
const DIRECT_HANDSHAKE: Duration = Duration::from_secs(2);
const RELAY_READY: Duration = Duration::from_secs(2);
const RELAY_REFRESH: Duration = Duration::from_secs(5);
/// Connection setup (direct attempt, relay readiness, and handshake) fits in
/// the 8-second request bound.
const REQUEST_BOUND: Duration = Duration::from_secs(8);
/// Peer requests are served within 15 seconds, except artifact transfers,
/// whose stalls the connection's idle timeout bounds instead.
const SERVE_BOUND: Duration = Duration::from_secs(15);
const TRANSFER_BOUND: Duration = Duration::from_secs(3600);

/// Set by a handler whose response may outlast the usual serve bound.
#[derive(Clone, Default)]
pub(crate) struct LongTransfer(Arc<std::sync::atomic::AtomicBool>);
impl LongTransfer {
    pub(crate) fn allow(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    fn allowed(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The daemon's single peer endpoint and its reusable outbound connections.
pub struct Transport {
    endpoint: Endpoint,
    relays: Arc<Relays>,
    discovery: Arc<Discovery>,
    cache: Mutex<HashMap<String, Cached>>,
}
struct Cached {
    key: Vec<u8>,
    address: SocketAddr,
    connection: Connection,
}

fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config
        .max_idle_timeout(Some(IDLE.try_into().expect("idle timeout fits")))
        .max_concurrent_bidi_streams(MAX_STREAMS.into())
        .max_concurrent_uni_streams(0u32.into())
        .datagram_receive_buffer_size(None)
        // quinn's GSO batches on loopback were silently lost by the Go
        // (quic-go) peer, stalling connections after the handshake. Peer
        // requests are small, so segmentation offload gains nothing here.
        .enable_segmentation_offload(false);
    Arc::new(config)
}

/// Binds the listening endpoint. Without a listener, the first outbound call
/// creates a client-only endpoint on an ephemeral port instead.
pub fn listen(store: &Arc<Store>, address: SocketAddr) -> anyhow::Result<SocketAddr> {
    let crypto = QuicServerConfig::try_from(server_config(store.clone())?)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport_config());
    let relays = Relays::new();
    let (endpoint, discovery) = endpoint(store, Some(config), address, relays.clone())?;
    let bound = endpoint.local_addr()?;
    install(store, endpoint, relays, discovery)?;
    if let Ok(mut peer_bound) = store.peer_bound.write() {
        *peer_bound = Some(bound);
    }
    Ok(bound)
}
/// The stateless reset key is derived from the host key exactly as the Go
/// daemon derives it, so a restarted daemon of either implementation on the
/// same socket resets connections its previous process held. Both QUIC
/// libraries compute reset tokens as HMAC-SHA256(key, connection ID).
fn endpoint(
    store: &Arc<Store>,
    server: Option<quinn::ServerConfig>,
    address: SocketAddr,
    relays: Arc<Relays>,
) -> anyhow::Result<(Endpoint, Arc<Discovery>)> {
    let reset = reset_key(&store.signing_key.to_bytes());
    let mut config = quinn::EndpointConfig::new(Arc::new(ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &reset,
    )));
    // A restarted daemon must parse its predecessor's short-header packets to
    // reset them, so both implementations use quic-go's 4-byte connection IDs.
    config.cid_generator(|| Box::new(ShortConnectionIds));
    // Peers must never clear the QUIC fixed bit toward this socket: path
    // discovery tells QUIC apart from STUN and discovery datagrams by it.
    config.grease_quic_bit(false);
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC"))?;
    // One socket for both paths: real UDP, plus synthetic addresses that the
    // combined socket carries over relay connections.
    let inner = runtime.wrap_udp_socket(std::net::UdpSocket::bind(address)?)?;
    let discovery = Discovery::new(store, inner.clone(), relays.clone());
    let socket = Arc::new(Combined {
        inner,
        relays,
        discovery: discovery.clone(),
    });
    Ok((
        Endpoint::new_with_abstract_socket(config, server, socket, runtime)?,
        discovery,
    ))
}
/// HMAC-SHA256(host key seed, "peerspan-peer stateless reset").
fn reset_key(seed: &[u8]) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, seed);
    ring::hmac::sign(&key, b"peerspan-peer stateless reset")
        .as_ref()
        .to_vec()
}
/// Random connection IDs of quic-go's default length.
struct ShortConnectionIds;
impl quinn::ConnectionIdGenerator for ShortConnectionIds {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut bytes = [0u8; CID_LENGTH];
        getrandom::fill(&mut bytes).expect("random source for connection IDs");
        quinn::ConnectionId::new(&bytes)
    }
    fn cid_len(&self) -> usize {
        CID_LENGTH
    }
    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}
fn install(
    store: &Arc<Store>,
    endpoint: Endpoint,
    relays: Arc<Relays>,
    discovery: Arc<Discovery>,
) -> anyhow::Result<Arc<Transport>> {
    let transport = Arc::new(Transport {
        endpoint,
        relays,
        discovery,
        cache: Mutex::new(HashMap::new()),
    });
    *store
        .peer_transport
        .lock()
        .map_err(|_| anyhow::anyhow!("peer transport lock poisoned"))? = Some(transport.clone());
    sweep_relays(&transport);
    Ok(transport)
}
fn transport(store: &Arc<Store>) -> anyhow::Result<Arc<Transport>> {
    let mut current = store
        .peer_transport
        .lock()
        .map_err(|_| anyhow::anyhow!("peer transport lock poisoned"))?;
    if let Some(transport) = current.as_ref() {
        return Ok(transport.clone());
    }
    // A client-only endpoint has no server configuration, so it never accepts
    // inbound connections, direct or relayed.
    let relays = Relays::new();
    let (endpoint, discovery) = endpoint(
        store,
        None,
        SocketAddr::from(([0, 0, 0, 0], 0)),
        relays.clone(),
    )?;
    let transport = Arc::new(Transport {
        endpoint,
        relays,
        discovery,
        cache: Mutex::new(HashMap::new()),
    });
    *current = Some(transport.clone());
    sweep_relays(&transport);
    Ok(transport)
}
/// The daemon's relay connections, if its peer endpoint exists.
pub(crate) fn relays(store: &Arc<Store>) -> Option<Arc<Relays>> {
    store
        .peer_transport
        .lock()
        .ok()?
        .as_ref()
        .map(|t| t.relays.clone())
}
/// The daemon's path discovery, if its peer endpoint exists.
pub(crate) fn discovery(store: &Arc<Store>) -> Option<Arc<Discovery>> {
    store
        .peer_transport
        .lock()
        .ok()?
        .as_ref()
        .map(|t| t.discovery.clone())
}
/// The current path to a known peer, for owner inspection.
#[derive(Debug, serde::Serialize)]
pub struct PathStatus {
    pub host_id: String,
    pub path: &'static str,
    pub endpoint: Option<String>,
    pub rtt_ms: Option<f64>,
}
pub(crate) fn path_status(store: &Arc<Store>, id: &str) -> Result<PathStatus, crate::model::Error> {
    use crate::model::Error;
    let host = raw_host(id).ok_or_else(|| Error::Invalid("invalid host ID".into()))?;
    let poisoned = || Error::Internal(anyhow::anyhow!("peer pins lock poisoned"));
    let known = store
        .peer_pins
        .read()
        .map_err(|_| poisoned())?
        .contains_key(id)
        || store
            .member_pins
            .read()
            .map_err(|_| poisoned())?
            .contains_key(id);
    if !known {
        return Err(Error::NotFound);
    }
    let state = discovery(store).map_or(PathState::None, |d| d.path(&host));
    Ok(match state {
        PathState::Direct(endpoint, rtt) => PathStatus {
            host_id: id.to_owned(),
            path: "direct",
            endpoint: Some(endpoint.to_string()),
            rtt_ms: Some((rtt.as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0),
        },
        PathState::Relay => PathStatus {
            host_id: id.to_owned(),
            path: "relay",
            endpoint: None,
            rtt_ms: None,
        },
        PathState::None => PathStatus {
            host_id: id.to_owned(),
            path: "none",
            endpoint: None,
            rtt_ms: None,
        },
    })
}
/// Closes on-demand relay connections that no live relayed connection uses.
/// The task ends with its transport.
fn sweep_relays(transport: &Arc<Transport>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let weak = Arc::downgrade(transport);
    runtime.spawn(async move {
        loop {
            tokio::time::sleep(RELAY_REFRESH).await;
            let Some(transport) = weak.upgrade() else {
                return;
            };
            transport
                .relays
                .sweep(&transport.relays_in_use(), std::time::Instant::now());
        }
    });
}

impl Transport {
    /// Relays that live cached relayed connections route through.
    fn relays_in_use(&self) -> Vec<Coordinator> {
        let Ok(cache) = self.cache.lock() else {
            return Vec::new();
        };
        cache
            .values()
            .filter(|entry| entry.connection.close_reason().is_none())
            .filter_map(|entry| self.relays.host_of(entry.address))
            .filter_map(|host| self.relays.route_of(&host))
            .collect()
    }
    /// A live cached connection to this peer and key on any of its current
    /// paths. A changed key or address never reuses the old connection.
    fn cached(&self, id: &str, key: &[u8], paths: &[SocketAddr]) -> Option<Connection> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(id)?;
        (entry.key == key
            && paths.contains(&entry.address)
            && entry.connection.close_reason().is_none())
        .then(|| entry.connection.clone())
    }
    /// Uses a cached connection, or dials the direct address (bounded by
    /// `DIRECT_HANDSHAKE` when a relay can take over) and then the relay.
    /// Every step is trimmed to what remains before `deadline`.
    async fn connection(
        &self,
        store: &Arc<Store>,
        peer: &Peer,
        key: &[u8],
        paths: &Paths,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<Connection> {
        if let Some(connection) = self.cached(&peer.id, key, &paths.all()) {
            return Ok(connection);
        }
        let remaining = |bound: Duration| {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            (!left.is_zero())
                .then(|| bound.min(left))
                .ok_or_else(|| anyhow::anyhow!("peer request bound exhausted"))
        };
        let mut failure = None;
        if let Some(direct) = paths.direct {
            let bound = if paths.relay.is_some() {
                DIRECT_HANDSHAKE
            } else {
                HANDSHAKE
            };
            match self.dial(store, peer, key, direct, remaining(bound)?).await {
                Ok(connection) => return Ok(connection),
                Err(error) => failure = Some(error),
            }
        }
        if let Some((coordinator, synthetic)) = &paths.relay {
            self.relays.ensure(store, coordinator, false);
            if let Some(host) = raw_host(&peer.id) {
                self.relays.route(&host, coordinator);
            }
            if !self
                .relays
                .connected(coordinator, remaining(RELAY_READY)?)
                .await
            {
                anyhow::bail!("relay {} is not connected", coordinator.address);
            }
            return self
                .dial(store, peer, key, *synthetic, remaining(HANDSHAKE)?)
                .await;
        }
        Err(failure.unwrap_or_else(|| anyhow::anyhow!("peer has no dial address")))
    }
    async fn dial(
        &self,
        store: &Arc<Store>,
        peer: &Peer,
        key: &[u8],
        address: SocketAddr,
        bound: Duration,
    ) -> anyhow::Result<Connection> {
        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            client_config(store.clone(), peer)?,
        )?));
        config.transport_config(transport_config());
        let connecting = self.endpoint.connect_with(config, address, SERVER_NAME)?;
        let connection = tokio::time::timeout(bound, connecting)
            .await
            .map_err(|_| anyhow::anyhow!("peer handshake timed out"))??;
        if negotiated(&connection).as_deref() != Some(ALPN) {
            connection.close(VarInt::from_u32(1), b"alpn");
            anyhow::bail!("peer did not negotiate {}", String::from_utf8_lossy(ALPN));
        }
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                peer.id.clone(),
                Cached {
                    key: key.to_vec(),
                    address,
                    connection: connection.clone(),
                },
            );
        }
        Ok(connection)
    }
    fn evict(&self, id: &str, connection: &Connection) {
        if let Ok(mut cache) = self.cache.lock()
            && cache
                .get(id)
                .is_some_and(|entry| entry.connection.stable_id() == connection.stable_id())
        {
            cache.remove(id);
        }
    }
}
fn negotiated(connection: &Connection) -> Option<Vec<u8>> {
    connection
        .handshake_data()?
        .downcast::<HandshakeData>()
        .ok()?
        .protocol
}

/// Sends one HTTP/1.1 request to a peer over a reused or new pinned QUIC
/// connection and returns the response status and bounded body.
pub(crate) async fn request(
    store: Arc<Store>,
    peer: &Peer,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<(u16, Vec<u8>)> {
    request_on(store, peer, method, path, body, false).await
}
/// `request` on the peer's direct path only, never through a relay.
pub(crate) async fn request_direct(
    store: Arc<Store>,
    peer: &Peer,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<(u16, Vec<u8>)> {
    request_on(store, peer, method, path, body, true).await
}
async fn request_on(
    store: Arc<Store>,
    peer: &Peer,
    method: &str,
    path: &str,
    body: &[u8],
    direct_only: bool,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let key = peer_key(peer).map_err(|e| anyhow::anyhow!("{e}"))?;
    let transport = transport(&store)?;
    let mut paths = paths(&store, &transport, peer).await?;
    if direct_only {
        paths.relay = None;
        if paths.direct.is_none() {
            anyhow::bail!("peer has no direct address");
        }
    }
    let deadline = tokio::time::Instant::now() + REQUEST_BOUND;
    let reused = transport.cached(&peer.id, &key, &paths.all()).is_some();
    let connection = transport
        .connection(&store, peer, &key, &paths, deadline)
        .await?;
    match exchange(&connection, method, path, body).await {
        Ok(response) => Ok(response),
        Err(failure) => {
            transport.evict(&peer.id, &connection);
            // TLS 1.3 lets the client finish first; a peer that does not
            // accept this host's certificate closes the connection after.
            if connection.close_reason().is_some_and(|r| crypto_close(&r)) {
                return Err(failure.error.context(Unauthenticated));
            }
            // A reused connection may have died silently, for example when the
            // peer restarted. Receivers deduplicate appends by request ID and
            // lookups are reads, so retry exactly once on a fresh connection,
            // but only if no response bytes arrived.
            if !reused || failure.responded {
                return Err(failure.error);
            }
            let connection = transport
                .connection(&store, peer, &key, &paths, deadline)
                .await?;
            let retried = exchange(&connection, method, path, body).await;
            if retried.is_err() {
                transport.evict(&peer.id, &connection);
            }
            retried.map_err(|f| {
                if connection.close_reason().is_some_and(|r| crypto_close(&r)) {
                    f.error.context(Unauthenticated)
                } else {
                    f.error
                }
            })
        }
    }
}
/// Marks a peer request that failed because the peer refused this host's
/// TLS authentication, typically because it does not know this host yet.
#[derive(Debug)]
pub(crate) struct Unauthenticated;
impl std::fmt::Display for Unauthenticated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("peer refused this host's authentication")
    }
}
/// Whether a QUIC connection closed with a TLS (crypto) error, either side.
fn crypto_close(error: &quinn::ConnectionError) -> bool {
    let code = match error {
        quinn::ConnectionError::ConnectionClosed(close) => u64::from(close.error_code),
        quinn::ConnectionError::TransportError(error) => u64::from(error.code),
        _ => return false,
    };
    (0x100..0x200).contains(&code)
}
/// Whether a peer request failed the TLS authentication of either host.
pub(crate) fn unauthenticated(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Unauthenticated>().is_some()
        || error.chain().any(|e| {
            e.downcast_ref::<quinn::ConnectionError>()
                .is_some_and(crypto_close)
        })
}
/// A response whose body is read incrementally: an artifact transfer, which
/// may exceed the 1 MiB bound on other peer responses.
pub(crate) struct Download {
    pub status: u16,
    /// The exact `Content-Length`, when given.
    pub length: Option<u64>,
    pending: Vec<u8>,
    recv: quinn::RecvStream,
}
impl Download {
    /// The next body bytes, or `None` at the end of the response.
    pub(crate) async fn chunk(&mut self) -> anyhow::Result<Option<bytes::Bytes>> {
        if !self.pending.is_empty() {
            return Ok(Some(std::mem::take(&mut self.pending).into()));
        }
        match tokio::time::timeout(IDLE, self.recv.read_chunk(64 * 1024, true)).await {
            Err(_) => anyhow::bail!("peer transfer stalled"),
            Ok(Ok(Some(chunk))) => Ok(Some(chunk.bytes)),
            Ok(Ok(None)) => Ok(None),
            Ok(Err(e)) => anyhow::bail!("read peer response: {e}"),
        }
    }
}
/// Sends a GET request to a peer and returns once the response head
/// arrives, leaving the body to be streamed.
pub(crate) async fn download(
    store: Arc<Store>,
    peer: &Peer,
    path: &str,
) -> anyhow::Result<Download> {
    let key = peer_key(peer).map_err(|e| anyhow::anyhow!("{e}"))?;
    let transport = transport(&store)?;
    let paths = paths(&store, &transport, peer).await?;
    let deadline = tokio::time::Instant::now() + REQUEST_BOUND;
    let reused = transport.cached(&peer.id, &key, &paths.all()).is_some();
    let connection = transport
        .connection(&store, peer, &key, &paths, deadline)
        .await?;
    match open_download(&connection, path).await {
        Ok(response) => Ok(response),
        Err(failure) => {
            transport.evict(&peer.id, &connection);
            if !reused || failure.responded {
                return Err(failure.error);
            }
            let connection = transport
                .connection(&store, peer, &key, &paths, deadline)
                .await?;
            let retried = open_download(&connection, path).await;
            if retried.is_err() {
                transport.evict(&peer.id, &connection);
            }
            retried.map_err(|f| f.error)
        }
    }
}
async fn open_download(connection: &Connection, path: &str) -> Result<Download, Failure> {
    let before = |error: anyhow::Error| Failure {
        error,
        responded: false,
    };
    let (mut send, mut recv) = connection.open_bi().await.map_err(|e| before(e.into()))?;
    let head = format!("GET {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n\r\n");
    send.write_all(head.as_bytes())
        .await
        .map_err(|e| before(e.into()))?;
    send.finish().map_err(|e| before(e.into()))?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let read_head = async {
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut response = httparse::Response::new(&mut headers);
            if let httparse::Status::Complete(start) =
                response.parse(&data).map_err(|e| Failure {
                    error: e.into(),
                    responded: true,
                })?
            {
                let status = response.code.unwrap_or_default();
                let header = |name: &str| {
                    response
                        .headers
                        .iter()
                        .find(|h| h.name.eq_ignore_ascii_case(name))
                        .map(|h| String::from_utf8_lossy(h.value).trim().to_ascii_lowercase())
                };
                let length = header("content-length").and_then(|v| v.parse::<u64>().ok());
                let pending = data[start..].to_vec();
                return Ok((status, length, pending));
            }
            match recv.read(&mut chunk).await {
                Ok(Some(n)) => {
                    data.extend_from_slice(&chunk[..n]);
                    if data.len() > MAX_HEADERS {
                        return Err(Failure {
                            error: anyhow::anyhow!("peer response head too large"),
                            responded: true,
                        });
                    }
                }
                Ok(None) => {
                    return Err(Failure {
                        error: anyhow::anyhow!("incomplete peer response"),
                        responded: !data.is_empty(),
                    });
                }
                Err(e) => {
                    return Err(Failure {
                        error: anyhow::anyhow!("read peer response: {e}"),
                        responded: !data.is_empty(),
                    });
                }
            }
        }
    };
    let (status, length, pending) = tokio::time::timeout(REQUEST_BOUND, read_head)
        .await
        .map_err(|_| before(anyhow::anyhow!("peer response timed out")))??;
    Ok(Download {
        status,
        length,
        pending,
        recv,
    })
}
/// Where a peer can be reached: its direct UDP address, and the relay of the
/// lowest-ID network both hosts belong to with the peer's synthetic address.
struct Paths {
    direct: Option<SocketAddr>,
    relay: Option<(Coordinator, SocketAddr)>,
}
impl Paths {
    fn all(&self) -> Vec<SocketAddr> {
        self.direct
            .into_iter()
            .chain(self.relay.as_ref().map(|(_, a)| *a))
            .collect()
    }
}
async fn paths(store: &Arc<Store>, transport: &Transport, peer: &Peer) -> anyhow::Result<Paths> {
    let direct = if peer.address.is_empty() {
        None
    } else {
        Some(peer.address.parse()?)
    };
    let id = peer.id.clone();
    let coordinator = blocking(store.clone(), move |s| s.relay_coordinator(&id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let relay = match (coordinator, raw_host(&peer.id)) {
        (Some((address, key)), Some(host)) => {
            let key = membership::canonical(&key, 32).map_err(|e| anyhow::anyhow!("{e}"))?;
            transport
                .relays
                .address_for(&host)
                .map(|synthetic| (Coordinator { address, key }, SocketAddr::V4(synthetic)))
        }
        _ => None,
    };
    if direct.is_none() && relay.is_none() {
        anyhow::bail!("peer has no dial address or shared relay");
    }
    Ok(Paths { direct, relay })
}
/// Keeps a relay connection to every coordinator of this host's networks, so
/// relayed peers can reach a listening host and every host receives change
/// notifications, and closes those to coordinators that no longer serve any.
async fn keep_relays(store: Arc<Store>, transport: Arc<Transport>) {
    loop {
        // A failed lookup leaves the current relay connections in place.
        if let Ok(coordinators) = blocking(store.clone(), |s| s.coordinators()).await {
            let current: Vec<Coordinator> = coordinators
                .into_iter()
                .filter_map(|(address, key)| {
                    let key = membership::canonical(&key, 32).ok()?;
                    Some(Coordinator { address, key })
                })
                .collect();
            for coordinator in &current {
                transport.relays.ensure(&store, coordinator, true);
            }
            transport.relays.retain(&current);
        }
        // Polling is the fallback; creating or joining a network wakes this early.
        tokio::select! {
            _ = tokio::time::sleep(RELAY_REFRESH) => {}
            _ = store.relay_wake.notified() => {}
        }
    }
}
/// Keeps the relay connections of a host without `--peer-listen` once it is
/// a member of a network, so its coordinators can push change
/// notifications. Its client-only endpoint still accepts no inbound peer
/// connections through them.
pub async fn keep_without_listener(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    loop {
        let member = blocking(store.clone(), |s| s.coordinators())
            .await
            .is_ok_and(|c| !c.is_empty());
        if member {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(RELAY_REFRESH) => {}
            _ = store.relay_wake.notified() => {}
            _ = shutdown.changed() => return,
        }
    }
    let transport = match transport(&store) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("relay: {error:#}");
            return;
        }
    };
    tokio::select! {
        _ = keep_relays(store, transport) => {}
        _ = shutdown.changed() => {}
    }
}
struct Failure {
    error: anyhow::Error,
    /// Whether any response bytes arrived before the failure.
    responded: bool,
}
async fn exchange(
    connection: &Connection,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), Failure> {
    let before = |error: anyhow::Error| Failure {
        error,
        responded: false,
    };
    let (mut send, mut recv) = connection.open_bi().await.map_err(|e| before(e.into()))?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\n");
    if !body.is_empty() {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("Connection: close\r\n\r\n");
    send.write_all(head.as_bytes())
        .await
        .map_err(|e| before(e.into()))?;
    send.write_all(body).await.map_err(|e| before(e.into()))?;
    send.finish().map_err(|e| before(e.into()))?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => {
                response.extend_from_slice(&chunk[..n]);
                if response.len() > response_limit(method, path) + MAX_HEADERS {
                    return Err(Failure {
                        error: anyhow::anyhow!("peer response too large"),
                        responded: true,
                    });
                }
            }
            Ok(None) => break,
            Err(e) => {
                return Err(Failure {
                    error: anyhow::anyhow!("read peer response: {e}"),
                    responded: !response.is_empty(),
                });
            }
        }
    }
    parse_limited(&response, response_limit(method, path)).map_err(|error| Failure {
        error,
        responded: true,
    })
}
/// Parses a complete HTTP/1.1 response, honoring Content-Length or chunked
/// transfer encoding, and bounds the body.
#[cfg(test)]
fn parse_response(data: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
    parse_limited(data, MAX_BODY)
}
fn parse_limited(data: &[u8], limit: usize) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(start) = response.parse(data)? else {
        anyhow::bail!("incomplete peer response");
    };
    let status = response
        .code
        .ok_or_else(|| anyhow::anyhow!("missing status"))?;
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_ascii_lowercase())
    };
    let rest = &data[start..];
    let body = if header("transfer-encoding").is_some_and(|v| v.ends_with("chunked")) {
        dechunk(rest, limit)?
    } else if let Some(length) = header("content-length") {
        let length: usize = length.parse()?;
        rest.get(..length)
            .ok_or_else(|| anyhow::anyhow!("truncated peer response"))?
            .to_vec()
    } else {
        rest.to_vec()
    };
    if body.len() > limit {
        anyhow::bail!("peer response too large");
    }
    Ok((status, body))
}
fn dechunk(mut data: &[u8], limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let httparse::Status::Complete((start, size)) = httparse::parse_chunk_size(data)
            .map_err(|_| anyhow::anyhow!("invalid chunked peer response"))?
        else {
            anyhow::bail!("truncated chunked peer response");
        };
        if size == 0 {
            return Ok(body);
        }
        let size = usize::try_from(size)?;
        let chunk = data
            .get(start..start + size)
            .ok_or_else(|| anyhow::anyhow!("truncated chunked peer response"))?;
        if body.len() + size > limit {
            anyhow::bail!("peer response too large");
        }
        body.extend_from_slice(chunk);
        data = data
            .get(start + size..)
            .and_then(|d| d.strip_prefix(b"\r\n"))
            .ok_or_else(|| anyhow::anyhow!("invalid chunked peer response"))?;
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One QUIC bidirectional stream as a byte stream for hyper.
struct Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}
impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// Accepts peer connections until shutdown. Requests that outlive the bounded
/// drain remain unknown to their senders.
pub async fn serve(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let transport = transport(&store)?;
    let relays = tokio::spawn(keep_relays(store.clone(), transport.clone()));
    let _relays = AbortOnDrop(relays);
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            incoming = transport.endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                if connections.len() >= MAX_CONNECTIONS {
                    incoming.refuse();
                    continue;
                }
                connections.spawn(connection(store.clone(), incoming));
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    transport.endpoint.close(VarInt::from_u32(0), b"shutdown");
    Ok(())
}
async fn connection(store: Arc<Store>, incoming: Incoming) {
    let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE, async {
        match incoming.accept() {
            Ok(connecting) => connecting.await,
            Err(error) => Err(error),
        }
    })
    .await
    else {
        return;
    };
    // Rustls accepts a client that offers no ALPN at all; require ours.
    if negotiated(&connection).as_deref() != Some(ALPN) {
        connection.close(VarInt::from_u32(1), b"alpn");
        return;
    }
    let Some(key) = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|certs| certificate_key(certs.first()?, UnixTime::now()).ok())
    else {
        connection.close(VarInt::from_u32(1), b"identity");
        return;
    };
    let router = peer_router(store.clone(), key_id(&key));
    // Answers every request from a host that is no longer known.
    let forbidden: axum::Router = axum::Router::new()
        .fallback(|| async { Err::<(), crate::model::Error>(crate::model::Error::Forbidden) });
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
            accepted = connection.accept_bi() => {
                let Ok((send, recv)) = accepted else { break };
                // Each request re-authenticates: a host removed while its
                // connection stays open gets 403 for anything it submits or
                // queries, as on a fresh request, and is never routed.
                let known = store.knows(&key).unwrap_or(false);
                let long = LongTransfer::default();
                let service = TowerToHyperService::new(if known {
                    router.clone().layer(axum::Extension(long.clone()))
                } else {
                    forbidden.clone()
                });
                streams.spawn(async move {
                    let served = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        // The client finishes its send side after the request.
                        .half_close(true)
                        .serve_connection(TokioIo::new(Stream { send, recv }), service);
                    let mut served = std::pin::pin!(served);
                    if tokio::time::timeout(SERVE_BOUND, served.as_mut()).await.is_err()
                        && long.allowed()
                    {
                        let _ = tokio::time::timeout(TRANSFER_BOUND, served).await;
                    }
                });
            }
        }
    }
    while streams.join_next().await.is_some() {}
}

#[cfg(test)]
mod connectivity_bench;

#[cfg(test)]
mod connectivity_network;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::pinned_client_config;
    use base64::Engine;

    struct Host {
        _directory: tempfile::TempDir,
        store: Arc<Store>,
    }
    fn host() -> Host {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&directory.path().join("host")).unwrap());
        Host {
            _directory: directory,
            store,
        }
    }
    fn as_peer(host: &Host, address: &str) -> Peer {
        let identity = host.store.identity();
        Peer {
            id: identity.id,
            public_key: identity.public_key,
            address: address.into(),
        }
    }
    fn receipt_path() -> String {
        format!("/peer/v1/receipts/request_{}", "0".repeat(32))
    }
    async fn listening(receiver: &Host) -> String {
        let bound = listen(&receiver.store, "127.0.0.1:0".parse().unwrap()).unwrap();
        let (shutdown, rx) = watch::channel(false);
        tokio::spawn(serve(receiver.store.clone(), rx));
        // Keep the daemon serving for the rest of the test.
        std::mem::forget(shutdown);
        bound.to_string()
    }

    #[tokio::test]
    async fn pinned_requests_reuse_and_reauthenticate() {
        let (sender, receiver) = (host(), host());
        let address = listening(&receiver).await;
        receiver
            .store
            .add_peer(as_peer(&sender, "127.0.0.1:9"))
            .unwrap();
        let target = as_peer(&receiver, &address);
        let (status, _) = request(sender.store.clone(), &target, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 404);
        // The same connection is reused for the next request.
        let first = transport(&sender.store)
            .unwrap()
            .cached(
                &target.id,
                &peer_key(&target).unwrap(),
                &[address.parse().unwrap()],
            )
            .unwrap();
        let (status, body) = request(
            sender.store.clone(),
            &target,
            "POST",
            "/peer/v1/messages",
            b"{\"bad\":true}",
        )
        .await
        .unwrap();
        assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
        let second = transport(&sender.store)
            .unwrap()
            .cached(
                &target.id,
                &peer_key(&target).unwrap(),
                &[address.parse().unwrap()],
            )
            .unwrap();
        assert_eq!(first.stable_id(), second.stable_id());
        // Removing the sender's pin refuses further requests on that open
        // connection with 403, the same answer a fresh request would get.
        receiver
            .store
            .peer_pins
            .write()
            .unwrap()
            .remove(&sender.store.identity().id);
        let (status, _) = request(sender.store.clone(), &target, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 403);
        let third = transport(&sender.store)
            .unwrap()
            .cached(
                &target.id,
                &peer_key(&target).unwrap(),
                &[address.parse().unwrap()],
            )
            .unwrap();
        assert_eq!(
            first.stable_id(),
            third.stable_id(),
            "refused on the same connection"
        );
        // Restoring it lets a fresh connection through.
        receiver.store.peer_pins.write().unwrap().insert(
            sender.store.identity().id,
            base64::engine::general_purpose::STANDARD
                .decode(sender.store.identity().public_key)
                .unwrap(),
        );
        let (status, _) = request(sender.store.clone(), &target, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn unknown_keys_and_wrong_pins_fail() {
        let (sender, receiver, stranger) = (host(), host(), host());
        let address = listening(&receiver).await;
        // The receiver does not know this sender.
        let target = as_peer(&receiver, &address);
        assert!(
            request(sender.store.clone(), &target, "GET", &receipt_path(), b"")
                .await
                .is_err()
        );
        // The sender pins another key for the receiver's address.
        receiver
            .store
            .add_peer(as_peer(&sender, "127.0.0.1:9"))
            .unwrap();
        let wrong = as_peer(&stranger, &address);
        assert!(
            request(sender.store.clone(), &wrong, "GET", &receipt_path(), b"")
                .await
                .is_err()
        );
        let (status, _) = request(sender.store.clone(), &target, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn other_alpn_is_rejected() {
        let (sender, receiver) = (host(), host());
        let address: SocketAddr = listening(&receiver).await.parse().unwrap();
        receiver
            .store
            .add_peer(as_peer(&sender, "127.0.0.1:9"))
            .unwrap();
        let key = peer_key(&as_peer(&receiver, "")).unwrap();
        let endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        for alpn in [vec![b"h3".to_vec()], vec![]] {
            let mut crypto = pinned_client_config(sender.store.clone(), key.clone(), ALPN).unwrap();
            crypto.alpn_protocols = alpn;
            let mut config =
                quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
            config.transport_config(transport_config());
            let attempt = async {
                let connection = endpoint.connect_with(config, address, SERVER_NAME)?.await?;
                exchange(&connection, "GET", &receipt_path(), b"")
                    .await
                    .map_err(|f| f.error)
            };
            assert!(
                tokio::time::timeout(Duration::from_secs(5), attempt)
                    .await
                    .map_or(true, |r| r.is_err())
            );
        }
    }

    /// A minimal relay with the contract's framing, standing in for the Go
    /// coordinator: it forwards send frames between connected hosts.
    async fn fake_relay(coordinator: &Host, hosts: &[&Host]) -> String {
        use crate::relay::{Frame, decode, encode};
        use sha2::Digest;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for host in hosts {
            coordinator
                .store
                .add_peer(as_peer(host, "127.0.0.1:9"))
                .unwrap();
        }
        let mut config = server_config(coordinator.store.clone()).unwrap();
        config.alpn_protocols = vec![crate::relay::ALPN.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        type Writers = Arc<Mutex<HashMap<[u8; 32], tokio::sync::mpsc::Sender<Vec<u8>>>>>;
        let writers: Writers = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (acceptor, writers) = (acceptor.clone(), writers.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let key = certificate_key(
                        &tls.get_ref().1.peer_certificates().unwrap()[0],
                        UnixTime::now(),
                    )
                    .unwrap();
                    let source: [u8; 32] = sha2::Sha256::digest(&key).into();
                    let (mut reader, mut writer) = tokio::io::split(tls);
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
                    writers.lock().unwrap().insert(source, tx);
                    tokio::spawn(async move {
                        while let Some(frame) = rx.recv().await {
                            if writer.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                    });
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 16 * 1024];
                    loop {
                        while let Ok(Some((frame, used))) = decode(&buffer) {
                            buffer.drain(..used);
                            if let Frame::Send { host, datagram } = frame {
                                let target = writers.lock().unwrap().get(&host).cloned();
                                if let Some(target) = target {
                                    let _ = target
                                        .send(encode(&Frame::Receive {
                                            host: source,
                                            datagram,
                                        }))
                                        .await;
                                }
                            }
                        }
                        match reader.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        }
                    }
                });
            }
        });
        address
    }
    /// Records that `host` shares a network served by `coordinator` with `other`.
    fn share_network(host: &Host, other: &Host, coordinator: &Host, address: &str) {
        let network = serde_json::json!({
            "id": "net_test", "name": "test", "root_public_key": "", "member": "test",
            "coordinator_address": address,
            "coordinator_public_key": coordinator.store.identity().public_key,
            "administrator": false, "last_sync_at": null, "last_sync_error": null,
        });
        let connection = host.store.connection().unwrap();
        connection
            .execute(
                "INSERT OR IGNORE INTO networks VALUES ('net_test', ?1, NULL)",
                [network.to_string()],
            )
            .unwrap();
        // A relay-only member: no direct address. The membership is not
        // verified here; only the record's shape matters to these tests.
        let identity = other.store.identity();
        let member = serde_json::json!({
            "host_id": identity.id, "public_key": identity.public_key, "member": "test",
            "address": "", "updated_at": "2026-10-06T00:00:00Z",
            "membership": {
                "network_id": "net_test", "member": "test", "invite_public_key": "",
                "invite_expires_at": "", "invite_signature": "", "host_public_key": "",
                "joined_at": "", "host_signature": "",
            },
        });
        connection
            .execute(
                "INSERT INTO network_members VALUES ('net_test', ?1, ?2)",
                [identity.id, member.to_string()],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn relayed_peers_switch_to_a_validated_direct_path() {
        let (sender, receiver, coordinator) = (host(), host(), host());
        let relay = fake_relay(&coordinator, &[&sender, &receiver]).await;
        share_network(&sender, &receiver, &coordinator, &relay);
        share_network(&receiver, &sender, &coordinator, &relay);
        let direct = listening(&receiver).await;
        // Each knows the other as a verified member, and the receiver's
        // published candidate is its real socket.
        for (a, b) in [(&sender, &receiver), (&receiver, &sender)] {
            let identity = b.store.identity();
            let key = crate::membership::canonical(&identity.public_key, 32).unwrap();
            a.store
                .member_pins
                .write()
                .unwrap()
                .insert(identity.id, key);
        }
        let id = receiver.store.identity().id;
        {
            let connection = sender.store.connection().unwrap();
            let record: String = connection
                .query_row(
                    "SELECT record FROM network_members WHERE host_id = ?1",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            let mut member: serde_json::Value = serde_json::from_str(&record).unwrap();
            member["candidates"] = serde_json::json!([direct]);
            connection
                .execute(
                    "UPDATE network_members SET record = ?1 WHERE host_id = ?2",
                    [member.to_string(), id.clone()],
                )
                .unwrap();
        }
        let relayed = as_peer(&receiver, "");
        let (status, _) = request(sender.store.clone(), &relayed, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 404);
        // The connection was dialed through the relay. Discovery may already
        // have validated the direct endpoint during that first round trip on
        // loopback, so either path is acceptable at this instant.
        let first = path_status(&sender.store, &id).unwrap().path;
        assert!(first == "relay" || first == "direct", "{first}");
        let key = peer_key(&relayed).unwrap();
        let synthetic = SocketAddr::V4(crate::relay::synthetic(&raw_host(&id).unwrap()));
        let before = transport(&sender.store)
            .unwrap()
            .cached(&id, &key, &[synthetic])
            .unwrap()
            .stable_id();
        // Discovery validates the candidate with a signed ping/pong and moves
        // the peer's packets onto it, below the unchanged QUIC connection.
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let status = loop {
            let status = path_status(&sender.store, &id).unwrap();
            if status.path == "direct" || std::time::Instant::now() > deadline {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(status.path, "direct", "{status:?}");
        assert_eq!(status.endpoint.as_deref(), Some(direct.as_str()));
        assert!(status.rtt_ms.is_some());
        for _ in 0..3 {
            let (status, _) = request(sender.store.clone(), &relayed, "GET", &receipt_path(), b"")
                .await
                .unwrap();
            assert_eq!(status, 404);
        }
        // The same QUIC connection carried the requests across the switch.
        let after = transport(&sender.store)
            .unwrap()
            .cached(&id, &key, &[synthetic])
            .unwrap()
            .stable_id();
        assert_eq!(before, after);
        // An unknown host has no path to report.
        assert!(matches!(
            path_status(&sender.store, &format!("host_{}", "1".repeat(64))),
            Err(crate::model::Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn relayed_requests_and_path_choice() {
        let (sender, receiver, coordinator) = (host(), host(), host());
        let late = host();
        let relay = fake_relay(&coordinator, &[&sender, &receiver, &late]).await;
        for (a, b) in [
            (&sender, &receiver),
            (&receiver, &sender),
            (&late, &receiver),
            (&receiver, &late),
        ] {
            share_network(a, b, &coordinator, &relay);
        }
        let direct = listening(&receiver).await;
        for host in [&sender, &late] {
            receiver
                .store
                .add_peer(as_peer(host, "127.0.0.1:9"))
                .unwrap();
        }
        let id = receiver.store.identity().id;
        let synthetic = SocketAddr::V4(crate::relay::synthetic(&raw_host(&id).unwrap()));

        // A member with no direct address is reached through the relay.
        let relayed = as_peer(&receiver, "");
        let (status, _) = request(sender.store.clone(), &relayed, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 404);
        let key = peer_key(&relayed).unwrap();
        let sender_transport = transport(&sender.store).unwrap();
        assert!(sender_transport.cached(&id, &key, &[synthetic]).is_some());

        // A dead direct address falls back to the relay after the bounded attempt.
        let dead = as_peer(&receiver, "127.0.0.1:9");
        let started = std::time::Instant::now();
        let (status, _) = request(late.store.clone(), &dead, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 404);
        assert!(started.elapsed() >= DIRECT_HANDSHAKE);
        let late_transport = transport(&late.store).unwrap();
        assert!(late_transport.cached(&id, &key, &[synthetic]).is_some());

        // A working direct address is preferred over the relay.
        let reachable = as_peer(&receiver, &direct);
        late_transport.cache.lock().unwrap().clear();
        let (status, _) = request(late.store.clone(), &reachable, "GET", &receipt_path(), b"")
            .await
            .unwrap();
        assert_eq!(status, 404);
        assert!(
            late_transport
                .cached(&id, &key, &[direct.parse().unwrap()])
                .is_some()
        );

        // A host without a peer listener accepts nothing through the relay, even
        // with its relay connection open from its own outbound request.
        late.store
            .add_peer(as_peer(&receiver, "127.0.0.1:9"))
            .unwrap();
        let client_only = as_peer(&late, "");
        assert!(
            request(
                receiver.store.clone(),
                &client_only,
                "GET",
                &receipt_path(),
                b""
            )
            .await
            .is_err()
        );

        // A host that shares no network has no relay path.
        let stranger = host();
        let error = request(
            stranger.store.clone(),
            &relayed,
            "GET",
            &receipt_path(),
            b"",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("no dial address"), "{error}");
    }

    #[tokio::test]
    async fn relay_setup_fits_the_request_bound() {
        // The relay is up but the receiver never registered with it, so the
        // relayed handshake can only end at the trimmed budget.
        let (sender, receiver, coordinator) = (host(), host(), host());
        let relay = fake_relay(&coordinator, &[&sender, &receiver]).await;
        share_network(&sender, &receiver, &coordinator, &relay);
        let transport = transport(&sender.store).unwrap();
        let peer = as_peer(&receiver, "127.0.0.1:9");
        let paths = paths(&sender.store, &transport, &peer).await.unwrap();
        let key = peer_key(&peer).unwrap();
        let budget = DIRECT_HANDSHAKE + Duration::from_secs(1);
        let started = tokio::time::Instant::now();
        let failed = transport
            .connection(&sender.store, &peer, &key, &paths, started + budget)
            .await;
        assert!(failed.is_err());
        let elapsed = started.elapsed();
        assert!(elapsed >= DIRECT_HANDSHAKE, "{elapsed:?}");
        assert!(elapsed < budget + Duration::from_millis(500), "{elapsed:?}");
        // With nothing left, no attempt is made at all.
        let spent = transport
            .connection(
                &sender.store,
                &peer,
                &key,
                &paths,
                tokio::time::Instant::now(),
            )
            .await
            .unwrap_err();
        assert!(spent.to_string().contains("bound exhausted"), "{spent}");
    }

    #[tokio::test]
    async fn listening_hosts_close_relays_for_departed_networks() {
        let (receiver, other, coordinator) = (host(), host(), host());
        let relay = fake_relay(&coordinator, &[&receiver]).await;
        share_network(&receiver, &other, &coordinator, &relay);
        listening(&receiver).await;
        let transport = transport(&receiver.store).unwrap();
        let served = crate::relay::Coordinator {
            address: relay.clone(),
            key: peer_key(&as_peer(&coordinator, "")).unwrap(),
        };
        let deadline = tokio::time::Instant::now() + RELAY_REFRESH * 2;
        while !transport.relays.has_client(&served) {
            assert!(tokio::time::Instant::now() < deadline, "relay never opened");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(transport.relays.connected(&served, RELAY_READY).await);
        // Leaving the network closes the relay on the next refresh.
        {
            let connection = receiver.store.connection().unwrap();
            connection
                .execute("DELETE FROM network_members", [])
                .unwrap();
            connection.execute("DELETE FROM networks", []).unwrap();
        }
        let deadline = tokio::time::Instant::now() + RELAY_REFRESH * 2;
        while transport.relays.has_client(&served) {
            assert!(tokio::time::Instant::now() < deadline, "relay never closed");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn relay_only_reply_lookup_uses_the_relay() {
        // The owner `message reply` and the automatic reply workers resolve a
        // relay-only member (empty address) and must still reach it.
        let (sender, receiver, coordinator) = (host(), host(), host());
        let relay = fake_relay(&coordinator, &[&sender, &receiver]).await;
        share_network(&sender, &receiver, &coordinator, &relay);
        share_network(&receiver, &sender, &coordinator, &relay);
        listening(&receiver).await;
        receiver
            .store
            .add_peer(as_peer(&sender, "127.0.0.1:9"))
            .unwrap();
        let peer = receiver.store.identity().id;
        assert_eq!(sender.store.dial_target(&peer).unwrap().address, "");
        let out = sender
            .store
            .prepare_outbound(crate::peer_store::SendMessage {
                peer_host_id: peer.clone(),
                request_id: String::new(),
                grant_id: Some(format!("grant_{}", "1".repeat(32))),
                target_agent_id: format!("agent_{}", "2".repeat(32)),
                deadline: crate::store::rfc3339(chrono::Utc::now() + chrono::Duration::minutes(5)),
                content: "hello".into(),
                origin: None,
            })
            .unwrap();
        let status =
            crate::adapter::fetch_reply_status(sender.store.clone(), peer, out.request.request_id)
                .await
                .unwrap();
        // The receiver answered over the relay: no reply yet.
        assert_eq!(status.state, "pending", "{:?}", status.error);
    }

    #[test]
    fn stateless_reset_key_matches_go_derivation() {
        assert_eq!(
            hex::encode(reset_key(&[1; 32])),
            "f3a7a6d03341cd2f67814def4cbb6e8496ff741d358ad21fb2077d1a4c510c4d"
        );
    }

    #[test]
    fn responses_parse_with_length_or_chunks() {
        let (status, body) =
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((status, body.as_slice()), (200, b"{}".as_slice()));
        let chunked =
            b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let (status, body) = parse_response(chunked).unwrap();
        assert_eq!((status, body.as_slice()), (403, b"abcde".as_slice()));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}").is_err());
    }
}
