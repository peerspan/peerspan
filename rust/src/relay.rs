//! Coordinator relay client and the peer endpoint's combined socket. A relay
//! forwards already-encrypted peer QUIC datagrams addressed by host ID over a
//! pinned TLS-over-TCP connection to a network's coordinator. Relayed peers
//! appear to the QUIC endpoint as synthetic addresses that are never sent on
//! the real UDP socket, so every peer TLS and request check still applies.
use crate::{
    disco::{Discovery, Kind, Source, classify},
    membership,
    peer::pinned_client_config,
    store::Store,
};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::HashMap,
    fmt,
    io::{self, IoSliceMut},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, watch},
};
use tokio_rustls::TlsConnector;

pub(crate) const ALPN: &[u8] = b"capsule-relay/1";
pub(crate) const MAX_DATAGRAM: usize = 1500;
const HOST_ID: usize = 32;
const HEADER: usize = 3;
const PING_AFTER: Duration = Duration::from_secs(15);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const QUEUE: usize = 1024;
/// An on-demand relay connection closes after this long with no relayed QUIC
/// connection using it, and reopens on the next demand.
pub(crate) const ON_DEMAND_IDLE: Duration = Duration::from_secs(60);

const SEND: u8 = 0x01;
const RECEIVE: u8 = 0x02;
const UNREACHABLE: u8 = 0x03;
const PING: u8 = 0x04;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Frame {
    Send {
        host: [u8; HOST_ID],
        datagram: Vec<u8>,
    },
    Receive {
        host: [u8; HOST_ID],
        datagram: Vec<u8>,
    },
    Unreachable {
        host: [u8; HOST_ID],
    },
    Ping,
}

pub(crate) fn encode(frame: &Frame) -> Vec<u8> {
    let (kind, host, datagram): (u8, Option<&[u8; HOST_ID]>, &[u8]) = match frame {
        Frame::Send { host, datagram } => (SEND, Some(host), datagram),
        Frame::Receive { host, datagram } => (RECEIVE, Some(host), datagram),
        Frame::Unreachable { host } => (UNREACHABLE, Some(host), &[]),
        Frame::Ping => (PING, None, &[]),
    };
    let length = host.map_or(0, |_| HOST_ID) + datagram.len();
    let mut out = Vec::with_capacity(HEADER + length);
    out.push(kind);
    out.extend_from_slice(&(length as u16).to_be_bytes());
    if let Some(host) = host {
        out.extend_from_slice(host);
    }
    out.extend_from_slice(datagram);
    out
}

/// Decodes one frame from the front of `buf`. `Ok(None)` means more bytes are
/// needed. Any error closes the relay connection.
pub(crate) fn decode(buf: &[u8]) -> anyhow::Result<Option<(Frame, usize)>> {
    if buf.len() < HEADER {
        return Ok(None);
    }
    let kind = buf[0];
    let length = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    let valid = match kind {
        SEND | RECEIVE => (HOST_ID + 1..=HOST_ID + MAX_DATAGRAM).contains(&length),
        UNREACHABLE => length == HOST_ID,
        PING => length == 0,
        other => anyhow::bail!("unknown relay frame type {other:#04x}"),
    };
    if !valid {
        anyhow::bail!("invalid relay frame length {length} for type {kind:#04x}");
    }
    let Some(payload) = buf.get(HEADER..HEADER + length) else {
        return Ok(None);
    };
    let host = || -> [u8; HOST_ID] { payload[..HOST_ID].try_into().expect("checked length") };
    let frame = match kind {
        SEND => Frame::Send {
            host: host(),
            datagram: payload[HOST_ID..].to_vec(),
        },
        RECEIVE => Frame::Receive {
            host: host(),
            datagram: payload[HOST_ID..].to_vec(),
        },
        UNREACHABLE => Frame::Unreachable { host: host() },
        _ => Frame::Ping,
    };
    Ok(Some((frame, HEADER + length)))
}

/// The raw 32-byte digest that a `host_` ID spells in hex.
pub(crate) fn raw_host(id: &str) -> Option<[u8; HOST_ID]> {
    hex::decode(id.strip_prefix("host_")?).ok()?.try_into().ok()
}

/// A synthetic IPv4 address for a relayed peer, in the reserved 240.0.0.0/4
/// block, with 44 bits taken from the host ID digest. Never sent on the real
/// socket; `Relays` keeps the reverse map and rejects collisions.
pub(crate) fn synthetic(host: &[u8; HOST_ID]) -> SocketAddrV4 {
    let ip = Ipv4Addr::new(0xf0 | (host[0] & 0x0f), host[1], host[2], host[3]);
    let port = u16::from_be_bytes([host[4], host[5]]).max(1);
    SocketAddrV4::new(ip, port)
}
/// Normalizes an endpoint address: IPv4-mapped IPv6 becomes IPv4.
fn normalize(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => addr,
        },
        v4 => v4,
    }
}
pub(crate) fn is_synthetic(addr: SocketAddr) -> bool {
    matches!(normalize(addr), SocketAddr::V4(v4) if v4.ip().octets()[0] & 0xf0 == 0xf0)
}

/// A coordinator relay, identified by its address and pinned key.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Coordinator {
    pub address: String,
    pub key: Vec<u8>,
}
struct Client {
    frames: mpsc::Sender<Vec<u8>>,
    connected: watch::Receiver<bool>,
    /// Kept for a listening host's networks; otherwise opened on demand.
    persistent: bool,
    /// When an on-demand client was first seen without a relayed connection.
    idle_since: Option<std::time::Instant>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Client {
    // Aborting the task drops its TLS stream and closes the relay connection.
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Default)]
struct State {
    clients: HashMap<Coordinator, Client>,
    /// Which relay carries packets to each host: the one chosen for an
    /// outbound connection, or the one its datagrams last arrived on.
    routes: HashMap<[u8; HOST_ID], Coordinator>,
    hosts: HashMap<SocketAddrV4, [u8; HOST_ID]>,
}

/// All relay connections of one daemon and the datagrams they deliver.
pub(crate) struct Relays {
    state: Mutex<State>,
    inbound: mpsc::Sender<(SocketAddrV4, Vec<u8>)>,
    received: Mutex<mpsc::Receiver<(SocketAddrV4, Vec<u8>)>>,
}
impl fmt::Debug for Relays {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Relays")
    }
}
impl Relays {
    pub(crate) fn new() -> Arc<Self> {
        let (inbound, received) = mpsc::channel(QUEUE);
        Arc::new(Self {
            state: Mutex::new(State::default()),
            inbound,
            received: Mutex::new(received),
        })
    }
    /// Registers the synthetic address for `host`, refusing a collision with
    /// another host's address.
    pub(crate) fn address_for(&self, host: &[u8; HOST_ID]) -> Option<SocketAddrV4> {
        let addr = synthetic(host);
        let mut state = self.state.lock().ok()?;
        match state.hosts.get(&addr) {
            Some(existing) if existing != host => None,
            Some(_) => Some(addr),
            None => {
                state.hosts.insert(addr, *host);
                Some(addr)
            }
        }
    }
    pub(crate) fn route(&self, host: &[u8; HOST_ID], coordinator: &Coordinator) {
        if let Ok(mut state) = self.state.lock() {
            state.routes.insert(*host, coordinator.clone());
        }
    }
    /// Starts a relay client for `coordinator` if none is running. A
    /// persistent request upgrades an existing on-demand client.
    pub(crate) fn ensure(
        self: &Arc<Self>,
        store: &Arc<Store>,
        coordinator: &Coordinator,
        persistent: bool,
    ) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(client) = state.clients.get_mut(coordinator) {
            client.persistent |= persistent;
            client.idle_since = None;
            return;
        }
        let (frames, outgoing) = mpsc::channel(QUEUE);
        let (status, connected) = watch::channel(false);
        let task = tokio::spawn(run(
            self.clone(),
            store.clone(),
            coordinator.clone(),
            outgoing,
            status,
        ));
        state.clients.insert(
            coordinator.clone(),
            Client {
                frames,
                connected,
                persistent,
                idle_since: None,
                task,
            },
        );
    }
    /// Closes persistent relay connections to coordinators that no longer serve
    /// any of this host's networks, with their routes.
    pub(crate) fn retain(&self, current: &[Coordinator]) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let State {
            clients, routes, ..
        } = &mut *state;
        clients.retain(|c, client| !client.persistent || current.contains(c));
        routes.retain(|_, c| clients.contains_key(c));
    }
    /// Closes on-demand relay connections that have had no relayed QUIC
    /// connection using them for `ON_DEMAND_IDLE`. `in_use` lists the relays
    /// that live relayed connections currently route through.
    pub(crate) fn sweep(&self, in_use: &[Coordinator], now: std::time::Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let State {
            clients, routes, ..
        } = &mut *state;
        clients.retain(|c, client| {
            if client.persistent || in_use.contains(c) {
                client.idle_since = None;
                return true;
            }
            let since = *client.idle_since.get_or_insert(now);
            now.saturating_duration_since(since) < ON_DEMAND_IDLE
        });
        routes.retain(|_, c| clients.contains_key(c));
    }
    /// The relay currently carrying packets to `host`.
    pub(crate) fn route_of(&self, host: &[u8; HOST_ID]) -> Option<Coordinator> {
        self.state.lock().ok()?.routes.get(host).cloned()
    }
    /// The relayed host behind a synthetic address.
    pub(crate) fn host_of(&self, addr: SocketAddr) -> Option<[u8; HOST_ID]> {
        let SocketAddr::V4(addr) = normalize(addr) else {
            return None;
        };
        self.state.lock().ok()?.hosts.get(&addr).copied()
    }
    #[cfg(test)]
    pub(crate) fn has_client(&self, coordinator: &Coordinator) -> bool {
        self.state
            .lock()
            .is_ok_and(|s| s.clients.contains_key(coordinator))
    }
    /// Waits up to `bound` for the relay connection to `coordinator`.
    pub(crate) async fn connected(&self, coordinator: &Coordinator, bound: Duration) -> bool {
        let Some(mut connected) = self
            .state
            .lock()
            .ok()
            .and_then(|s| s.clients.get(coordinator).map(|c| c.connected.clone()))
        else {
            return false;
        };
        tokio::time::timeout(bound, connected.wait_for(|up| *up))
            .await
            .is_ok_and(|r| r.is_ok())
    }
    /// Queues one datagram for a relayed host. Datagram semantics: a full
    /// queue or missing route drops it, and QUIC recovers.
    fn send(&self, addr: SocketAddrV4, datagram: &[u8]) {
        let Ok(state) = self.state.lock() else {
            return;
        };
        let Some(host) = state.hosts.get(&addr) else {
            return;
        };
        let Some(client) = state.routes.get(host).and_then(|c| state.clients.get(c)) else {
            return;
        };
        if datagram.is_empty() || datagram.len() > MAX_DATAGRAM {
            return;
        }
        let _ = client.frames.try_send(encode(&Frame::Send {
            host: *host,
            datagram: datagram.to_vec(),
        }));
    }
    /// Queues one datagram for `host` through its current relay route.
    pub(crate) fn send_host(&self, host: &[u8; HOST_ID], datagram: &[u8]) {
        if let Some(addr) = self.address_for(host) {
            self.send(addr, datagram);
        }
    }
    fn deliver(&self, host: [u8; HOST_ID], datagram: Vec<u8>, coordinator: &Coordinator) {
        let Some(addr) = self.address_for(&host) else {
            return;
        };
        self.route(&host, coordinator);
        let _ = self.inbound.try_send((addr, datagram));
    }
}

async fn run(
    relays: Arc<Relays>,
    store: Arc<Store>,
    coordinator: Coordinator,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    status: watch::Sender<bool>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect(&store, &coordinator).await {
            Ok(stream) => {
                backoff = Duration::from_secs(1);
                let _ = status.send(true);
                let ended = session(&relays, &coordinator, stream, &mut outgoing).await;
                let _ = status.send(false);
                if let Err(error) = ended {
                    eprintln!("relay {}: {error}", coordinator.address);
                }
            }
            Err(error) => eprintln!("relay {}: {error}", coordinator.address),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn connect(
    store: &Arc<Store>,
    coordinator: &Coordinator,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let (host, _) =
        membership::split_host_port(&coordinator.address).map_err(|e| anyhow::anyhow!("{e}"))?;
    let config = pinned_client_config(store.clone(), coordinator.key.clone(), ALPN)?;
    let name = rustls::pki_types::ServerName::try_from(host)?;
    let attempt = async {
        let stream = TcpStream::connect(&coordinator.address).await?;
        stream.set_nodelay(true)?;
        Ok::<_, anyhow::Error>(
            TlsConnector::from(Arc::new(config))
                .connect(name, stream)
                .await?,
        )
    };
    let stream = tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .map_err(|_| anyhow::anyhow!("relay connect timed out"))??;
    if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
        anyhow::bail!(
            "coordinator did not negotiate {}",
            String::from_utf8_lossy(ALPN)
        );
    }
    Ok(stream)
}

async fn session(
    relays: &Relays,
    coordinator: &Coordinator,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    outgoing: &mut mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async {
        loop {
            let frame = match tokio::time::timeout(PING_AFTER, outgoing.recv()).await {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok::<_, anyhow::Error>(()),
                Err(_) => encode(&Frame::Ping),
            };
            writer.write_all(&frame).await?;
        }
    };
    let read = async {
        let mut buffer = Vec::with_capacity(4 * 1024);
        let mut chunk = [0u8; 16 * 1024];
        loop {
            while let Some((frame, used)) = decode(&buffer)? {
                buffer.drain(..used);
                match frame {
                    Frame::Receive { host, datagram } => {
                        relays.deliver(host, datagram, coordinator)
                    }
                    Frame::Unreachable { .. } | Frame::Ping => {}
                    Frame::Send { .. } => anyhow::bail!("relay sent a host-only frame type"),
                }
            }
            let n = reader.read(&mut chunk).await?;
            if n == 0 {
                anyhow::bail!("relay closed the connection");
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
    };
    tokio::select! {
        result = write => result,
        result = read => result,
    }
}

/// The peer endpoint's socket: real UDP for direct addresses, and for
/// synthetic addresses either the relay or an endpoint that path discovery
/// validated. QUIC only ever sees the synthetic address of a relayed peer.
#[derive(Debug)]
pub(crate) struct Combined {
    pub inner: Arc<dyn AsyncUdpSocket>,
    pub relays: Arc<Relays>,
    pub discovery: Arc<Discovery>,
}
impl Combined {
    /// A synthetic address in the socket's address family.
    fn present(&self, addr: SocketAddrV4) -> SocketAddr {
        if self.inner.local_addr().is_ok_and(|a| a.is_ipv6()) {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                addr.ip().to_ipv6_mapped(),
                addr.port(),
                0,
                0,
            ))
        } else {
            SocketAddr::V4(addr)
        }
    }
    /// Keeps QUIC datagrams from the UDP socket, presenting those from a
    /// validated endpoint under the peer's synthetic address, and hands STUN
    /// and discovery datagrams to path discovery. Returns how many entries
    /// remain, compacted to the front.
    fn filter(&self, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta], count: usize) -> usize {
        let mut kept = 0;
        for i in 0..count {
            let entry = meta[i];
            let len = entry.len.min(bufs[i].len());
            let stride = if entry.stride == 0 { len } else { entry.stride };
            let quic = classify(&bufs[i][..stride.min(len)]) == Kind::Quic;
            if !quic {
                // Coalesced segments come from one source; handle each.
                for segment in bufs[i][..len].chunks(stride.max(1)) {
                    if classify(segment) != Kind::Quic {
                        self.discovery.receive(Source::Udp(entry.addr), segment);
                    }
                }
                continue;
            }
            let mut entry = entry;
            if let Some(host) = self.discovery.host_at(entry.addr)
                && let Some(synthetic) = self.relays.address_for(&host)
            {
                entry.addr = self.present(synthetic);
            }
            if kept != i {
                let (left, right) = bufs.split_at_mut(i);
                if left[kept].len() < len {
                    continue;
                }
                left[kept][..len].copy_from_slice(&right[0][..len]);
            }
            meta[kept] = entry;
            kept += 1;
        }
        kept
    }
}
impl AsyncUdpSocket for Combined {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if !is_synthetic(transmit.destination) {
            return self.inner.try_send(transmit);
        }
        let SocketAddr::V4(addr) = normalize(transmit.destination) else {
            return Ok(());
        };
        if let Some(host) = self.relays.host_of(transmit.destination)
            && let Some(endpoint) = self.discovery.route(&host)
        {
            // A validated direct endpoint carries this peer's packets now.
            let destination = match (endpoint, self.inner.local_addr()) {
                (SocketAddr::V4(v4), Ok(SocketAddr::V6(_))) => SocketAddr::V6(
                    std::net::SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
                ),
                (endpoint, _) => endpoint,
            };
            return self.inner.try_send(&Transmit {
                destination,
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: None,
            });
        }
        match transmit.segment_size {
            Some(size) => {
                for segment in transmit.contents.chunks(size) {
                    self.relays.send(addr, segment);
                }
            }
            None => self.relays.send(addr, transmit.contents),
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let Ok(mut received) = self.relays.received.lock() else {
                break;
            };
            let Poll::Ready(Some((addr, datagram))) = received.poll_recv(cx) else {
                break;
            };
            drop(received);
            match classify(&datagram) {
                Kind::Quic => {}
                Kind::Disco => {
                    if let Some(host) = self.relays.host_of(SocketAddr::V4(addr)) {
                        self.discovery.receive(Source::Relay(host), &datagram);
                    }
                    continue;
                }
                Kind::Stun | Kind::Other => continue,
            }
            let (Some(buf), Some(slot)) = (bufs.first_mut(), meta.first_mut()) else {
                break;
            };
            let len = datagram.len().min(buf.len());
            buf[..len].copy_from_slice(&datagram[..len]);
            *slot = RecvMeta {
                addr: self.present(addr),
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
        loop {
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => {
                    let kept = self.filter(bufs, meta, count);
                    if kept > 0 {
                        return Poll::Ready(Ok(kept));
                    }
                    // Everything was STUN or discovery; poll the socket again.
                }
                other => return other,
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let host = [7u8; HOST_ID];
        for frame in [
            Frame::Send {
                host,
                datagram: vec![1, 2, 3],
            },
            Frame::Receive {
                host,
                datagram: vec![9; MAX_DATAGRAM],
            },
            Frame::Unreachable { host },
            Frame::Ping,
        ] {
            let mut bytes = encode(&frame);
            bytes.extend_from_slice(&[PING, 0]);
            let (decoded, used) = decode(&bytes).unwrap().unwrap();
            assert_eq!(decoded, frame);
            assert_eq!(used, bytes.len() - 2);
            // Incomplete input waits for more bytes.
            assert!(decode(&bytes[..used - 1]).unwrap().is_none());
        }
        assert_eq!(encode(&Frame::Ping), vec![PING, 0, 0]);
    }

    #[test]
    fn malformed_frames_are_rejected() {
        // Unknown type.
        assert!(decode(&[0x05, 0, 0]).is_err());
        // Empty datagram, oversized datagram, short host ID, ping with payload.
        assert!(decode(&[SEND, 0, HOST_ID as u8]).is_err());
        let oversized = ((HOST_ID + MAX_DATAGRAM + 1) as u16).to_be_bytes();
        assert!(decode(&[RECEIVE, oversized[0], oversized[1]]).is_err());
        assert!(decode(&[UNREACHABLE, 0, 31]).is_err());
        assert!(decode(&[PING, 0, 1, 0]).is_err());
        // A header alone is incomplete, not invalid.
        assert!(decode(&[SEND, 0, 40]).unwrap().is_none());
        assert!(decode(&[SEND]).unwrap().is_none());
    }

    #[tokio::test]
    async fn stale_and_idle_relays_close() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&directory.path().join("host")).unwrap());
        // Unreachable coordinators: the clients just keep retrying.
        let coordinator = |port: u16| Coordinator {
            address: format!("127.0.0.1:{port}"),
            key: vec![port as u8; 32],
        };
        let (kept, dropped, demand, busy) = (
            coordinator(1),
            coordinator(2),
            coordinator(3),
            coordinator(4),
        );
        let relays = Relays::new();
        relays.ensure(&store, &kept, true);
        relays.ensure(&store, &dropped, true);
        relays.ensure(&store, &demand, false);
        relays.ensure(&store, &busy, false);
        let host = [9u8; HOST_ID];
        relays.route(&host, &dropped);
        // A coordinator that no longer serves this host's networks is closed,
        // with its routes; on-demand clients are left to the idle sweep.
        relays.retain(std::slice::from_ref(&kept));
        assert!(relays.has_client(&kept) && !relays.has_client(&dropped));
        assert!(relays.has_client(&demand) && relays.route_of(&host).is_none());
        // On-demand clients close after the idle period without a relayed
        // connection; one in use, and persistent ones, stay.
        let start = std::time::Instant::now();
        let busy_only = std::slice::from_ref(&busy);
        relays.sweep(busy_only, start);
        relays.sweep(busy_only, start + ON_DEMAND_IDLE / 2);
        assert!(relays.has_client(&demand));
        relays.sweep(busy_only, start + ON_DEMAND_IDLE);
        assert!(!relays.has_client(&demand));
        assert!(relays.has_client(&busy) && relays.has_client(&kept));
        // Demand reopens it, and a persistent request upgrades it.
        relays.ensure(&store, &demand, false);
        relays.ensure(&store, &demand, true);
        relays.sweep(&[], start + ON_DEMAND_IDLE * 2);
        relays.sweep(&[], start + ON_DEMAND_IDLE * 4);
        assert!(relays.has_client(&demand) && !relays.has_client(&busy));
    }

    #[test]
    fn synthetic_addresses_are_stable_and_distinct() {
        let a = raw_host(&format!("host_{}", "ab".repeat(32))).unwrap();
        let b = raw_host(&format!("host_{}", "cd".repeat(32))).unwrap();
        assert!(raw_host("host_xyz").is_none() && raw_host(&"ab".repeat(32)).is_none());
        let relays = Relays::new();
        let (sa, sb) = (
            relays.address_for(&a).unwrap(),
            relays.address_for(&b).unwrap(),
        );
        assert_ne!(sa, sb);
        assert_eq!(relays.address_for(&a), Some(sa));
        assert!(is_synthetic(SocketAddr::V4(sa)));
        let mapped = SocketAddr::V6(std::net::SocketAddrV6::new(
            sa.ip().to_ipv6_mapped(),
            1,
            0,
            0,
        ));
        assert!(is_synthetic(mapped));
        assert!(!is_synthetic("127.0.0.1:7401".parse().unwrap()));
        assert!(!is_synthetic("[::1]:7401".parse().unwrap()));
        assert_ne!(sa.port(), 0);
        // A different host whose digest collides on the synthetic bits is refused.
        let mut collision = a;
        collision[31] ^= 1;
        assert_eq!(synthetic(&collision), sa);
        assert!(relays.address_for(&collision).is_none());
    }
}
