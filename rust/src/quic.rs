//! QUIC peer transport. One UDP endpoint per daemon accepts and dials peer
//! connections; each bidirectional stream carries exactly one HTTP/1.1
//! request and response. The owner-local router is never served here.
use crate::{
    peer::{certificate_key, client_config, peer_router, server_config},
    peer_store::{Peer, key_id, peer_key},
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

pub(crate) const ALPN: &[u8] = b"capsule-peer/1";
const HANDSHAKE: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 64;
const MAX_STREAMS: u32 = 16;
const MAX_BODY: usize = 1 << 20;
const MAX_HEADERS: usize = 64 * 1024;
const SERVER_NAME: &str = "capsule-peer";
const CID_LENGTH: usize = 4;

/// The daemon's single peer endpoint and its reusable outbound connections.
pub struct Transport {
    endpoint: Endpoint,
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
    let endpoint = endpoint(store, Some(config), address)?;
    let bound = endpoint.local_addr()?;
    install(store, endpoint)?;
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
) -> anyhow::Result<Endpoint> {
    let reset = reset_key(&store.signing_key.to_bytes());
    let mut config = quinn::EndpointConfig::new(Arc::new(ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &reset,
    )));
    // A restarted daemon must parse its predecessor's short-header packets to
    // reset them, so both implementations use quic-go's 4-byte connection IDs.
    config.cid_generator(|| Box::new(ShortConnectionIds));
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC"))?;
    Ok(Endpoint::new(
        config,
        server,
        std::net::UdpSocket::bind(address)?,
        runtime,
    )?)
}
/// HMAC-SHA256(host key seed, "capsule-peer stateless reset").
fn reset_key(seed: &[u8]) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, seed);
    ring::hmac::sign(&key, b"capsule-peer stateless reset")
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
fn install(store: &Arc<Store>, endpoint: Endpoint) -> anyhow::Result<Arc<Transport>> {
    let transport = Arc::new(Transport {
        endpoint,
        cache: Mutex::new(HashMap::new()),
    });
    *store
        .peer_transport
        .lock()
        .map_err(|_| anyhow::anyhow!("peer transport lock poisoned"))? = Some(transport.clone());
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
    let transport = Arc::new(Transport {
        endpoint: endpoint(store, None, SocketAddr::from(([0, 0, 0, 0], 0)))?,
        cache: Mutex::new(HashMap::new()),
    });
    *current = Some(transport.clone());
    Ok(transport)
}

impl Transport {
    fn cached(&self, id: &str, key: &[u8], address: SocketAddr) -> Option<Connection> {
        let cache = self.cache.lock().ok()?;
        let entry = cache.get(id)?;
        (entry.key == key && entry.address == address && entry.connection.close_reason().is_none())
            .then(|| entry.connection.clone())
    }
    async fn connection(
        &self,
        store: &Arc<Store>,
        peer: &Peer,
        key: Vec<u8>,
        address: SocketAddr,
    ) -> anyhow::Result<Connection> {
        if let Some(connection) = self.cached(&peer.id, &key, address) {
            return Ok(connection);
        }
        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(
            client_config(store.clone(), peer)?,
        )?));
        config.transport_config(transport_config());
        let connecting = self.endpoint.connect_with(config, address, SERVER_NAME)?;
        let connection = tokio::time::timeout(HANDSHAKE, connecting)
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
                    key,
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
    let key = peer_key(peer).map_err(|e| anyhow::anyhow!("{e}"))?;
    if peer.address.is_empty() {
        anyhow::bail!("peer has no dial address");
    }
    let address: SocketAddr = peer.address.parse()?;
    let transport = transport(&store)?;
    let reused = transport.cached(&peer.id, &key, address).is_some();
    let connection = transport
        .connection(&store, peer, key.clone(), address)
        .await?;
    match exchange(&connection, method, path, body).await {
        Ok(response) => Ok(response),
        Err(failure) => {
            transport.evict(&peer.id, &connection);
            // A reused connection may have died silently, for example when the
            // peer restarted. Receivers deduplicate appends by request ID and
            // lookups are reads, so retry exactly once on a fresh connection,
            // but only if no response bytes arrived.
            if !reused || failure.responded {
                return Err(failure.error);
            }
            let connection = transport.connection(&store, peer, key, address).await?;
            let retried = exchange(&connection, method, path, body).await;
            if retried.is_err() {
                transport.evict(&peer.id, &connection);
            }
            retried.map_err(|f| f.error)
        }
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
                if response.len() > MAX_BODY + MAX_HEADERS {
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
    parse_response(&response).map_err(|error| Failure {
        error,
        responded: true,
    })
}
/// Parses a complete HTTP/1.1 response, honoring Content-Length or chunked
/// transfer encoding, and bounds the body.
fn parse_response(data: &[u8]) -> anyhow::Result<(u16, Vec<u8>)> {
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
        dechunk(rest)?
    } else if let Some(length) = header("content-length") {
        let length: usize = length.parse()?;
        rest.get(..length)
            .ok_or_else(|| anyhow::anyhow!("truncated peer response"))?
            .to_vec()
    } else {
        rest.to_vec()
    };
    if body.len() > MAX_BODY {
        anyhow::bail!("peer response too large");
    }
    Ok((status, body))
}
fn dechunk(mut data: &[u8]) -> anyhow::Result<Vec<u8>> {
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
        if body.len() + size > MAX_BODY {
            anyhow::bail!("peer response too large");
        }
        body.extend_from_slice(chunk);
        data = data
            .get(start + size..)
            .and_then(|d| d.strip_prefix(b"\r\n"))
            .ok_or_else(|| anyhow::anyhow!("invalid chunked peer response"))?;
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
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
            accepted = connection.accept_bi() => {
                let Ok((send, recv)) = accepted else { break };
                // Each request re-authenticates: a host removed while its
                // connection stays open cannot submit or query anything.
                if !store.knows(&key).unwrap_or(false) {
                    connection.close(VarInt::from_u32(2), b"unknown peer");
                    break;
                }
                let service = TowerToHyperService::new(router.clone());
                streams.spawn(async move {
                    let served = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        // The client finishes its send side after the request.
                        .half_close(true)
                        .serve_connection(TokioIo::new(Stream { send, recv }), service);
                    let _ = tokio::time::timeout(Duration::from_secs(15), served).await;
                });
            }
        }
    }
    while streams.join_next().await.is_some() {}
}

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
                address.parse().unwrap(),
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
                address.parse().unwrap(),
            )
            .unwrap();
        assert_eq!(first.stable_id(), second.stable_id());
        // Removing the sender's pin refuses further requests on that connection.
        receiver
            .store
            .peer_pins
            .write()
            .unwrap()
            .remove(&sender.store.identity().id);
        assert!(
            request(sender.store.clone(), &target, "GET", &receipt_path(), b"")
                .await
                .is_err()
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

    #[test]
    fn stateless_reset_key_matches_go_derivation() {
        assert_eq!(
            hex::encode(reset_key(&[1; 32])),
            "f4eab59f27ab42a4ef063c10e4ec5e9360836198f1979427e8dd36a612839715"
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
