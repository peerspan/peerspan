//! Direct paths through NAT, below QUIC. QUIC always addresses a relayed peer
//! by its synthetic address; this module decides whether that address means
//! "through the relay" or a validated UDP endpoint. It speaks STUN to learn
//! reflexive addresses and signed ping/pong/call-me-maybe messages to open and
//! validate endpoints. Only this host's own completed ping/pong exchange
//! validates an endpoint, so forged or replayed messages cannot redirect
//! traffic; QUIC packet protection still authenticates everything QUIC accepts.
use crate::{peer_store::key_id, relay::Relays, store::Store};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use quinn::{AsyncUdpSocket, udp::Transmit};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;

pub(crate) const MAGIC: [u8; 8] = *b"\0capdisc";
const COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const PING: u8 = 0x01;
const PONG: u8 = 0x02;
const CALL_ME_MAYBE: u8 = 0x03;
const HOST: usize = 32;
const TX: usize = 12;
const HEADER: usize = MAGIC.len() + 1 + HOST + TX + 8;
const SIGNATURE: usize = 64;
pub(crate) const MAX_ENDPOINTS: usize = 8;
const FRESHNESS: Duration = Duration::from_secs(30);
const REPLAY: Duration = Duration::from_secs(60);
const PING_EVERY: Duration = Duration::from_secs(2);
const BURST: Duration = Duration::from_secs(10);
const CALL_EVERY: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(5);
const EXPIRE: Duration = Duration::from_secs(15);
const RETRY: Duration = Duration::from_secs(30);
const TICK: Duration = Duration::from_millis(500);
/// Relay use this recent starts discovery for that peer.
const RELAY_USE: Duration = Duration::from_secs(10);
const STUN_WAIT: Duration = Duration::from_secs(1);
/// Candidates kept per peer from the map, call-me-maybe, and ping sources.
const MAX_CANDIDATES: usize = 16;

/// What a datagram on the peer socket or in a relay frame is.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Quic,
    Stun,
    Disco,
    Other,
}
pub(crate) fn classify(datagram: &[u8]) -> Kind {
    if datagram.first().is_some_and(|b| b & 0x40 != 0) {
        Kind::Quic
    } else if datagram.len() >= 20 && datagram[4..8] == COOKIE {
        Kind::Stun
    } else if datagram.starts_with(&MAGIC) {
        Kind::Disco
    } else {
        Kind::Other
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    Ping,
    Pong { tx: [u8; TX], observed: SocketAddr },
    CallMeMaybe(Vec<SocketAddr>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Message {
    pub sender: [u8; HOST],
    pub tx: [u8; TX],
    pub time_ms: u64,
    pub body: Body,
}

/// IPv4-mapped IPv6 becomes IPv4, so one endpoint has one spelling.
pub(crate) fn normalize(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => addr,
        },
        v4 => v4,
    }
}
fn put_endpoint(out: &mut Vec<u8>, addr: SocketAddr) {
    match normalize(addr) {
        SocketAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}
fn take_endpoint(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    match buf.first()? {
        4 if buf.len() >= 7 => {
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Some((SocketAddr::from((ip, port)), 7))
        }
        6 if buf.len() >= 19 => {
            let octets: [u8; 16] = buf[1..17].try_into().ok()?;
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Some((
                normalize(SocketAddr::from((Ipv6Addr::from(octets), port))),
                19,
            ))
        }
        _ => None,
    }
}

pub(crate) fn encode(message: &Message, key: &SigningKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + 64 + SIGNATURE);
    out.extend_from_slice(&MAGIC);
    out.push(match message.body {
        Body::Ping => PING,
        Body::Pong { .. } => PONG,
        Body::CallMeMaybe(_) => CALL_ME_MAYBE,
    });
    out.extend_from_slice(&message.sender);
    out.extend_from_slice(&message.tx);
    out.extend_from_slice(&message.time_ms.to_be_bytes());
    match &message.body {
        Body::Ping => {}
        Body::Pong { tx, observed } => {
            out.extend_from_slice(tx);
            put_endpoint(&mut out, *observed);
        }
        Body::CallMeMaybe(endpoints) => {
            let endpoints = &endpoints[..endpoints.len().min(MAX_ENDPOINTS)];
            out.push(endpoints.len() as u8);
            for endpoint in endpoints {
                put_endpoint(&mut out, *endpoint);
            }
        }
    }
    let signature = key.sign(&out);
    out.extend_from_slice(&signature.to_bytes());
    out
}
/// Parses a message without checking its signature; `verify` does that.
pub(crate) fn decode(buf: &[u8]) -> Option<Message> {
    if buf.len() < HEADER + SIGNATURE || !buf.starts_with(&MAGIC) {
        return None;
    }
    let kind = buf[MAGIC.len()];
    let mut at = MAGIC.len() + 1;
    let sender: [u8; HOST] = buf[at..at + HOST].try_into().ok()?;
    at += HOST;
    let tx: [u8; TX] = buf[at..at + TX].try_into().ok()?;
    at += TX;
    let time_ms = u64::from_be_bytes(buf[at..at + 8].try_into().ok()?);
    at += 8;
    let body_end = buf.len() - SIGNATURE;
    let body = &buf[at..body_end];
    let parsed = match kind {
        PING if body.is_empty() => Body::Ping,
        PONG if body.len() > TX => {
            let ping: [u8; TX] = body[..TX].try_into().ok()?;
            let (observed, used) = take_endpoint(&body[TX..])?;
            if TX + used != body.len() {
                return None;
            }
            Body::Pong { tx: ping, observed }
        }
        CALL_ME_MAYBE if !body.is_empty() => {
            let count = body[0] as usize;
            if count > MAX_ENDPOINTS {
                return None;
            }
            let mut endpoints = Vec::with_capacity(count);
            let mut used = 1;
            for _ in 0..count {
                let (endpoint, n) = take_endpoint(&body[used..])?;
                endpoints.push(endpoint);
                used += n;
            }
            if used != body.len() {
                return None;
            }
            Body::CallMeMaybe(endpoints)
        }
        _ => return None,
    };
    Some(Message {
        sender,
        tx,
        time_ms,
        body: parsed,
    })
}
pub(crate) fn verify(buf: &[u8], key: &VerifyingKey) -> bool {
    if buf.len() < HEADER + SIGNATURE {
        return false;
    }
    let (signed, signature) = buf.split_at(buf.len() - SIGNATURE);
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(signed, &signature).is_ok()
}
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}
pub(crate) fn fresh(time_ms: u64, now_ms: u64) -> bool {
    time_ms.abs_diff(now_ms) <= FRESHNESS.as_millis() as u64
}

/// A STUN Binding request (RFC 8489) with no attributes.
pub(crate) fn stun_request(tx: [u8; TX]) -> Vec<u8> {
    let mut out = vec![0x00, 0x01, 0x00, 0x00];
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&tx);
    out
}
/// A Binding success response carrying only XOR-MAPPED-ADDRESS.
#[cfg(test)]
pub(crate) fn stun_response(tx: [u8; TX], mapped: SocketAddr) -> Vec<u8> {
    let mut value = vec![0u8];
    let port = mapped.port() ^ u16::from_be_bytes([COOKIE[0], COOKIE[1]]);
    match normalize(mapped) {
        SocketAddr::V4(v4) => {
            value.push(0x01);
            value.extend_from_slice(&port.to_be_bytes());
            for (b, c) in v4.ip().octets().iter().zip(COOKIE) {
                value.push(b ^ c);
            }
        }
        SocketAddr::V6(v6) => {
            value.push(0x02);
            value.extend_from_slice(&port.to_be_bytes());
            let mask: Vec<u8> = COOKIE.iter().chain(tx.iter()).copied().collect();
            for (b, m) in v6.ip().octets().iter().zip(mask) {
                value.push(b ^ m);
            }
        }
    }
    let mut out = vec![0x01, 0x01];
    out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&tx);
    out.extend_from_slice(&[0x00, 0x20]);
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    out
}
/// The transaction ID and XOR-MAPPED-ADDRESS of a Binding success response.
pub(crate) fn parse_stun_response(buf: &[u8]) -> Option<([u8; TX], SocketAddr)> {
    if buf.len() < 20 || buf[0..2] != [0x01, 0x01] || buf[4..8] != COOKIE {
        return None;
    }
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 20 + length {
        return None;
    }
    let tx: [u8; TX] = buf[8..20].try_into().ok()?;
    let mut attributes = &buf[20..20 + length];
    while attributes.len() >= 4 {
        let kind = u16::from_be_bytes([attributes[0], attributes[1]]);
        let len = u16::from_be_bytes([attributes[2], attributes[3]]) as usize;
        let value = attributes.get(4..4 + len)?;
        if kind == 0x0020 && len >= 8 {
            let port = u16::from_be_bytes([value[2], value[3]])
                ^ u16::from_be_bytes([COOKIE[0], COOKIE[1]]);
            let ip = match value[1] {
                0x01 if len == 8 => {
                    let mut octets = [0u8; 4];
                    for (i, o) in octets.iter_mut().enumerate() {
                        *o = value[4 + i] ^ COOKIE[i];
                    }
                    IpAddr::from(octets)
                }
                0x02 if len == 20 => {
                    let mask: Vec<u8> = COOKIE.iter().chain(tx.iter()).copied().collect();
                    let mut octets = [0u8; 16];
                    for (i, o) in octets.iter_mut().enumerate() {
                        *o = value[4 + i] ^ mask[i];
                    }
                    IpAddr::from(octets)
                }
                _ => return None,
            };
            return Some((tx, normalize(SocketAddr::new(ip, port))));
        }
        let padded = (len + 3) & !3;
        attributes = attributes.get(4 + padded..).unwrap_or_default();
    }
    None
}

/// Where a discovery message arrived from, and so where a reply goes back.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Source {
    Udp(SocketAddr),
    Relay([u8; HOST]),
}

#[derive(Debug, Default)]
pub(crate) struct PeerPath {
    candidates: Vec<SocketAddr>,
    /// An advertised direct address; dialed directly, so never rerouted here.
    excluded: Vec<SocketAddr>,
    pings: HashMap<[u8; TX], (SocketAddr, Instant)>,
    /// Validated endpoints: round trip and last pong.
    validated: HashMap<SocketAddr, (Duration, Instant)>,
    best: Option<SocketAddr>,
    relay_used: Option<Instant>,
    burst_until: Option<Instant>,
    last_burst_ping: Option<Instant>,
    last_call: Option<Instant>,
    retry_after: Option<Instant>,
    last_keepalive: Option<Instant>,
}
impl PeerPath {
    fn add_candidate(&mut self, addr: SocketAddr) {
        let addr = normalize(addr);
        if addr.port() == 0
            || addr.ip().is_unspecified()
            || self.excluded.contains(&addr)
            || self.candidates.contains(&addr)
        {
            return;
        }
        if self.candidates.len() >= MAX_CANDIDATES {
            self.candidates.remove(0);
        }
        self.candidates.push(addr);
    }
    /// A pong for one of this host's own pings, from the endpoint pinged.
    fn validate(&mut self, tx: &[u8; TX], from: SocketAddr, now: Instant) -> bool {
        let Some((endpoint, sent)) = self.pings.get(tx).copied() else {
            return false;
        };
        if endpoint != normalize(from) {
            return false;
        }
        self.pings.remove(tx);
        self.validated
            .insert(endpoint, (now.saturating_duration_since(sent), now));
        self.choose();
        true
    }
    fn choose(&mut self) {
        self.best = self
            .validated
            .iter()
            .min_by_key(|(_, (rtt, _))| *rtt)
            .map(|(addr, _)| *addr);
    }
    /// Drops endpoints without a pong for `EXPIRE`. Returns the dropped ones.
    /// Losing the last validated endpoint sends traffic back through the
    /// relay and defers rediscovery by `RETRY`.
    fn expire(&mut self, now: Instant) -> Vec<SocketAddr> {
        let dropped: Vec<SocketAddr> = self
            .validated
            .iter()
            .filter(|(_, (_, last))| now.saturating_duration_since(*last) > EXPIRE)
            .map(|(addr, _)| *addr)
            .collect();
        for addr in &dropped {
            self.validated.remove(addr);
        }
        if !dropped.is_empty() {
            let had = self.best.is_some();
            self.choose();
            if had && self.best.is_none() {
                self.retry_after = Some(now + RETRY);
                self.burst_until = None;
            }
        }
        self.pings
            .retain(|_, (_, sent)| now.saturating_duration_since(*sent) < EXPIRE);
        dropped
    }
}

#[derive(Default)]
struct State {
    peers: HashMap<[u8; HOST], PeerPath>,
    /// Validated endpoint → host, for presenting its QUIC packets to QUIC
    /// under the host's synthetic address.
    endpoints: HashMap<SocketAddr, [u8; HOST]>,
    seen: HashMap<([u8; HOST], [u8; TX]), Instant>,
    stun: HashMap<[u8; TX], (SocketAddr, oneshot::Sender<SocketAddr>)>,
}

/// Path discovery for one peer endpoint (one UDP socket).
pub(crate) struct Discovery {
    store: Weak<Store>,
    inner: Arc<dyn AsyncUdpSocket>,
    relays: Arc<Relays>,
    state: Mutex<State>,
}
impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Discovery")
    }
}
/// The current path to one peer, for owner inspection.
#[derive(Debug, PartialEq)]
pub(crate) enum PathState {
    Direct(SocketAddr, Duration),
    Relay,
    None,
}

impl Discovery {
    pub(crate) fn new(
        store: &Arc<Store>,
        inner: Arc<dyn AsyncUdpSocket>,
        relays: Arc<Relays>,
    ) -> Arc<Self> {
        let discovery = Arc::new(Self {
            store: Arc::downgrade(store),
            inner,
            relays,
            state: Mutex::new(State::default()),
        });
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&discovery);
            runtime.spawn(async move {
                loop {
                    tokio::time::sleep(TICK).await;
                    let Some(discovery) = weak.upgrade() else {
                        return;
                    };
                    discovery.tick().await;
                }
            });
        }
        discovery
    }
    /// A destination in the socket's address family.
    fn destination(&self, addr: SocketAddr) -> SocketAddr {
        match (normalize(addr), self.inner.local_addr()) {
            (SocketAddr::V4(v4), Ok(SocketAddr::V6(_))) => {
                SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
            }
            (addr, _) => addr,
        }
    }
    fn usable(&self, addr: SocketAddr) -> bool {
        let addr = normalize(addr);
        match self.inner.local_addr() {
            Ok(SocketAddr::V4(_)) => addr.is_ipv4(),
            Ok(SocketAddr::V6(_)) => true,
            Err(_) => false,
        }
    }
    pub(crate) fn send_udp(&self, to: SocketAddr, datagram: &[u8]) {
        if !self.usable(to) {
            return;
        }
        let _ = self.inner.try_send(&Transmit {
            destination: self.destination(to),
            ecn: None,
            contents: datagram,
            segment_size: None,
            src_ip: None,
        });
    }
    fn signing(&self) -> Option<(SigningKey, [u8; HOST])> {
        let store = self.store.upgrade()?;
        let host = crate::relay::raw_host(&store.identity().id)?;
        Some((store.signing_key.clone(), host))
    }
    fn message(&self, body: Body) -> Option<(Vec<u8>, [u8; TX])> {
        let (key, sender) = self.signing()?;
        let mut tx = [0u8; TX];
        getrandom::fill(&mut tx).ok()?;
        let message = Message {
            sender,
            tx,
            time_ms: now_ms(),
            body,
        };
        Some((encode(&message, &key), tx))
    }
    /// The pinned key of a known host (manual peer or verified member).
    fn key_of(&self, host: &[u8; HOST]) -> Option<VerifyingKey> {
        let store = self.store.upgrade()?;
        let id = format!("host_{}", hex::encode(host));
        let key = store
            .peer_pins
            .read()
            .ok()?
            .get(&id)
            .cloned()
            .or_else(|| store.member_pins.read().ok()?.get(&id).cloned())?;
        if key_id(&key) != id {
            return None;
        }
        VerifyingKey::from_bytes(&key.try_into().ok()?).ok()
    }

    /// Where QUIC packets for a relayed host go: a validated endpoint, or
    /// `None` for the relay (which also marks the relay as in use).
    pub(crate) fn route(&self, host: &[u8; HOST]) -> Option<SocketAddr> {
        let mut state = self.state.lock().ok()?;
        let path = state.peers.entry(*host).or_default();
        if path.best.is_none() {
            path.relay_used = Some(Instant::now());
        }
        path.best
    }
    /// The relayed host whose validated endpoint sent a QUIC packet.
    pub(crate) fn host_at(&self, from: SocketAddr) -> Option<[u8; HOST]> {
        self.state
            .lock()
            .ok()?
            .endpoints
            .get(&normalize(from))
            .copied()
    }
    pub(crate) fn path(&self, host: &[u8; HOST]) -> PathState {
        let Ok(state) = self.state.lock() else {
            return PathState::None;
        };
        if let Some(path) = state.peers.get(host)
            && let Some(best) = path.best
            && let Some((rtt, _)) = path.validated.get(&best)
        {
            return PathState::Direct(best, *rtt);
        }
        drop(state);
        if self.relays.route_of(host).is_some() {
            PathState::Relay
        } else {
            PathState::None
        }
    }

    /// Handles one STUN or discovery datagram. QUIC never reaches here.
    pub(crate) fn receive(&self, from: Source, datagram: &[u8]) {
        match classify(datagram) {
            Kind::Stun => {
                if let Source::Udp(addr) = from {
                    self.stun_response(addr, datagram);
                }
            }
            Kind::Disco => self.disco(from, datagram),
            _ => {}
        }
    }
    fn stun_response(&self, from: SocketAddr, datagram: &[u8]) {
        let Some((tx, mapped)) = parse_stun_response(datagram) else {
            return;
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state
            .stun
            .get(&tx)
            .is_some_and(|(expected, _)| *expected == normalize(from))
            && let Some((_, reply)) = state.stun.remove(&tx)
        {
            let _ = reply.send(mapped);
        }
    }
    /// Accepts a transaction ID once per sender within the replay window.
    fn first_use(&self, sender: [u8; HOST], tx: [u8; TX], now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state
            .seen
            .retain(|_, at| now.saturating_duration_since(*at) < REPLAY);
        state.seen.insert((sender, tx), now).is_none()
    }
    fn disco(&self, from: Source, datagram: &[u8]) {
        let Some(message) = decode(datagram) else {
            return;
        };
        let Some(key) = self.key_of(&message.sender) else {
            return;
        };
        if !verify(datagram, &key)
            || !fresh(message.time_ms, now_ms())
            || !self.first_use(message.sender, message.tx, Instant::now())
        {
            return;
        }
        let host = message.sender;
        match message.body {
            Body::Ping => {
                let observed = match from {
                    Source::Udp(addr) => normalize(addr),
                    Source::Relay(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
                };
                if let Source::Udp(addr) = from
                    && let Ok(mut state) = self.state.lock()
                {
                    // Pinging this source back lets the reply cross the
                    // sender's NAT; only that pong could validate it.
                    let path = state.peers.entry(host).or_default();
                    path.add_candidate(addr);
                    start_burst(path, Instant::now());
                }
                if let Some((pong, _)) = self.message(Body::Pong {
                    tx: message.tx,
                    observed,
                }) {
                    self.reply(from, &pong);
                }
            }
            Body::Pong { tx, .. } => {
                // Only a pong over UDP from the endpoint pinged validates it.
                let Source::Udp(addr) = from else {
                    return;
                };
                if let Ok(mut state) = self.state.lock() {
                    let now = Instant::now();
                    let validated = state
                        .peers
                        .get_mut(&host)
                        .is_some_and(|path| path.validate(&tx, addr, now));
                    if validated {
                        state.endpoints.insert(normalize(addr), host);
                    }
                }
            }
            Body::CallMeMaybe(endpoints) => {
                if !matches!(from, Source::Relay(_)) {
                    return;
                }
                if let Ok(mut state) = self.state.lock() {
                    let path = state.peers.entry(host).or_default();
                    for endpoint in endpoints {
                        path.add_candidate(endpoint);
                    }
                    start_burst(path, Instant::now());
                }
            }
        }
    }
    fn reply(&self, to: Source, datagram: &[u8]) {
        match to {
            Source::Udp(addr) => self.send_udp(addr, datagram),
            Source::Relay(host) => self.relays.send_host(&host, datagram),
        }
    }

    /// Learns this socket's reflexive address as seen by a coordinator.
    pub(crate) async fn reflexive(&self, coordinator: &str) -> Option<SocketAddr> {
        let v4_only = matches!(self.inner.local_addr(), Ok(SocketAddr::V4(_)));
        let target = tokio::net::lookup_host(coordinator)
            .await
            .ok()?
            .map(normalize)
            .find(|a| !v4_only || a.is_ipv4())?;
        let mut tx = [0u8; TX];
        getrandom::fill(&mut tx).ok()?;
        let (reply, mapped) = oneshot::channel();
        self.state.lock().ok()?.stun.insert(tx, (target, reply));
        self.send_udp(target, &stun_request(tx));
        let result = tokio::time::timeout(STUN_WAIT, mapped).await;
        if let Ok(mut state) = self.state.lock() {
            state.stun.remove(&tx);
        }
        result.ok()?.ok()
    }

    async fn tick(&self) {
        let now = Instant::now();
        // Load map candidates for peers about to start a discovery burst.
        let starting: Vec<[u8; HOST]> = match self.state.lock() {
            Ok(state) => state
                .peers
                .iter()
                .filter(|(_, p)| wants_burst(p, now))
                .map(|(h, _)| *h)
                .collect(),
            Err(_) => return,
        };
        let mut loaded = Vec::new();
        if !starting.is_empty()
            && let Some(store) = self.store.upgrade()
        {
            for host in &starting {
                let id = format!("host_{}", hex::encode(host));
                let lookup = store.clone();
                if let Ok(Ok(found)) =
                    tokio::task::spawn_blocking(move || lookup.member_candidates(&id)).await
                {
                    loaded.push((*host, found));
                }
            }
        }
        let own: Vec<SocketAddr> = self
            .store
            .upgrade()
            .map(|s| s.published_candidates())
            .unwrap_or_default();
        let mut udp: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut relayed: Vec<([u8; HOST], Vec<u8>)> = Vec::new();
        {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            for (host, (candidates, excluded)) in loaded {
                let path = state.peers.entry(host).or_default();
                path.excluded = excluded;
                path.candidates.retain(|c| !path.excluded.contains(c));
                for candidate in candidates {
                    path.add_candidate(candidate);
                }
            }
            let mut dropped = Vec::new();
            for (host, path) in state.peers.iter_mut() {
                if wants_burst(path, now) {
                    start_burst(path, now);
                    if path
                        .last_call
                        .is_none_or(|t| now.saturating_duration_since(t) >= CALL_EVERY)
                    {
                        path.last_call = Some(now);
                        if let Some((call, _)) = self.message(Body::CallMeMaybe(own.clone())) {
                            relayed.push((*host, call));
                        }
                    }
                }
                let bursting = path.burst_until.is_some_and(|until| now < until);
                if bursting
                    && path
                        .last_burst_ping
                        .is_none_or(|t| now.saturating_duration_since(t) >= PING_EVERY)
                {
                    path.last_burst_ping = Some(now);
                    for candidate in path.candidates.clone() {
                        if let Some((ping, tx)) = self.message(Body::Ping) {
                            path.pings.insert(tx, (candidate, now));
                            udp.push((candidate, ping));
                        }
                    }
                }
                if let Some(best) = path.best
                    && path
                        .last_keepalive
                        .is_none_or(|t| now.saturating_duration_since(t) >= KEEPALIVE)
                {
                    path.last_keepalive = Some(now);
                    if let Some((ping, tx)) = self.message(Body::Ping) {
                        path.pings.insert(tx, (best, now));
                        udp.push((best, ping));
                    }
                }
                dropped.extend(path.expire(now));
            }
            for addr in dropped {
                state.endpoints.remove(&addr);
            }
            state.stun.retain(|_, (_, reply)| !reply.is_closed());
        }
        for (to, datagram) in udp {
            self.send_udp(to, &datagram);
        }
        for (host, datagram) in relayed {
            self.relays.send_host(&host, &datagram);
        }
    }
}
fn wants_burst(path: &PeerPath, now: Instant) -> bool {
    path.best.is_none()
        && path.burst_until.is_none_or(|until| now >= until)
        && path.retry_after.is_none_or(|after| now >= after)
        && path
            .relay_used
            .is_some_and(|t| now.saturating_duration_since(t) < RELAY_USE)
}
fn start_burst(path: &mut PeerPath, now: Instant) {
    if path.burst_until.is_none_or(|until| now >= until) {
        path.burst_until = Some(now + BURST);
        path.last_burst_ping = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn raw(key: &SigningKey) -> [u8; HOST] {
        crate::relay::raw_host(&key_id(key.verifying_key().as_bytes())).unwrap()
    }
    fn signed(key: &SigningKey, tx: u8, time_ms: u64, body: Body) -> Vec<u8> {
        encode(
            &Message {
                sender: raw(key),
                tx: [tx; TX],
                time_ms,
                body,
            },
            key,
        )
    }

    #[test]
    fn messages_round_trip_and_classify() {
        let k = key(7);
        for body in [
            Body::Ping,
            Body::Pong {
                tx: [9; TX],
                observed: "203.0.113.10:41000".parse().unwrap(),
            },
            Body::Pong {
                tx: [9; TX],
                observed: "[2001:db8::1]:7401".parse().unwrap(),
            },
            Body::CallMeMaybe(vec![
                "198.51.100.2:7401".parse().unwrap(),
                "[2001:db8::2]:9".parse().unwrap(),
            ]),
            Body::CallMeMaybe(vec![]),
        ] {
            let bytes = signed(&k, 1, 1234, body.clone());
            assert_eq!(classify(&bytes), Kind::Disco);
            let message = decode(&bytes).unwrap();
            assert_eq!(message.body, body);
            assert_eq!(message.sender, raw(&k));
            assert_eq!(message.time_ms, 1234);
            assert!(verify(&bytes, &k.verifying_key()));
        }
        // QUIC long and short headers carry the fixed bit; STUN has the cookie.
        assert_eq!(classify(&[0xc3, 0, 0, 0, 1]), Kind::Quic);
        assert_eq!(classify(&[0x41, 1, 2, 3]), Kind::Quic);
        assert_eq!(classify(&stun_request([1; TX])), Kind::Stun);
        assert_eq!(classify(&[0, 1, 2, 3]), Kind::Other);
    }

    #[test]
    fn malformed_messages_are_rejected() {
        let k = key(7);
        let good = signed(
            &k,
            1,
            1,
            Body::CallMeMaybe(vec!["192.0.2.1:1".parse().unwrap()]),
        );
        assert!(decode(&good[..good.len() - 1]).is_none());
        let mut extra = good.clone();
        extra.insert(good.len() - SIGNATURE, 0);
        assert!(decode(&extra).is_none());
        let mut kind = good.clone();
        kind[MAGIC.len()] = 9;
        assert!(decode(&kind).is_none());
        let mut too_many = signed(&k, 1, 1, Body::CallMeMaybe(vec![]));
        too_many[HEADER] = (MAX_ENDPOINTS + 1) as u8;
        assert!(decode(&too_many).is_none());
        let mut family = signed(
            &k,
            1,
            1,
            Body::Pong {
                tx: [1; TX],
                observed: "192.0.2.1:1".parse().unwrap(),
            },
        );
        family[HEADER + TX] = 5;
        assert!(decode(&family).is_none());
    }

    #[test]
    fn signatures_and_freshness_are_checked() {
        let (k, other) = (key(7), key(8));
        let bytes = signed(&k, 1, now_ms(), Body::Ping);
        assert!(verify(&bytes, &k.verifying_key()));
        assert!(!verify(&bytes, &other.verifying_key()));
        for at in [MAGIC.len() + 1, HEADER - 1, bytes.len() - 1] {
            let mut tampered = bytes.clone();
            tampered[at] ^= 1;
            assert!(!verify(&tampered, &k.verifying_key()), "byte {at}");
        }
        let now = 1_800_000_000_000;
        assert!(fresh(now - 30_000, now) && fresh(now + 30_000, now));
        assert!(!fresh(now - 30_001, now) && !fresh(now + 30_001, now));
    }

    #[test]
    fn stun_round_trips_and_checks_its_fields() {
        let tx = [3; TX];
        let request = stun_request(tx);
        assert_eq!(request.len(), 20);
        assert_eq!(&request[..4], &[0, 1, 0, 0]);
        for mapped in ["203.0.113.10:41234", "[2001:db8::7]:7401"] {
            let mapped: SocketAddr = mapped.parse().unwrap();
            assert_eq!(
                parse_stun_response(&stun_response(tx, mapped)),
                Some((tx, mapped))
            );
        }
        let mut wrong_cookie = stun_response(tx, "192.0.2.1:9".parse().unwrap());
        wrong_cookie[4] ^= 1;
        assert!(parse_stun_response(&wrong_cookie).is_none());
        let mut request_type = stun_response(tx, "192.0.2.1:9".parse().unwrap());
        request_type[1] = 0x01;
        request_type[0] = 0x00;
        assert!(parse_stun_response(&request_type).is_none());
        assert!(parse_stun_response(&request).is_none());
    }

    #[test]
    fn only_own_pongs_validate_and_silence_falls_back() {
        let now = Instant::now();
        let endpoint: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let mut path = PeerPath::default();
        path.add_candidate(endpoint);
        // A pong for a ping this host never sent validates nothing.
        assert!(!path.validate(&[1; TX], endpoint, now));
        path.pings.insert([2; TX], (endpoint, now));
        // Right transaction, wrong endpoint: still nothing.
        assert!(!path.validate(&[2; TX], "198.51.100.8:40000".parse().unwrap(), now));
        assert!(path.best.is_none());
        let later = now + Duration::from_millis(40);
        assert!(path.validate(&[2; TX], endpoint, later));
        assert_eq!(path.best, Some(endpoint));
        // A replayed pong for the same ping cannot validate again.
        assert!(!path.validate(&[2; TX], endpoint, later));
        // No pong for 15 seconds: back to the relay, retry after 30.
        assert!(path.expire(later + Duration::from_secs(15)).is_empty());
        let silent = later + Duration::from_secs(16);
        assert_eq!(path.expire(silent), vec![endpoint]);
        assert!(path.best.is_none());
        assert_eq!(path.retry_after, Some(silent + RETRY));
        path.relay_used = Some(silent);
        assert!(!wants_burst(&path, silent + Duration::from_secs(29)));
        path.relay_used = Some(silent + Duration::from_secs(30));
        assert!(wants_burst(&path, silent + Duration::from_secs(30)));
    }

    #[test]
    fn the_fastest_validated_endpoint_wins() {
        let now = Instant::now();
        let (slow, fast): (SocketAddr, SocketAddr) = (
            "198.51.100.7:1".parse().unwrap(),
            "10.0.0.7:1".parse().unwrap(),
        );
        let mut path = PeerPath::default();
        path.pings.insert([1; TX], (slow, now));
        path.pings.insert([2; TX], (fast, now));
        assert!(path.validate(&[1; TX], slow, now + Duration::from_millis(30)));
        assert!(path.validate(&[2; TX], fast, now + Duration::from_millis(2)));
        assert_eq!(path.best, Some(fast));
        // An advertised direct address is never a candidate.
        path.excluded = vec![slow];
        path.candidates.clear();
        path.add_candidate(slow);
        assert!(path.candidates.is_empty());
    }

    #[tokio::test]
    async fn replayed_and_unknown_messages_are_ignored() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&directory.path().join("host")).unwrap());
        let peer = key(9);
        let peer_id = key_id(peer.verifying_key().as_bytes());
        let runtime = quinn::default_runtime().unwrap();
        let socket = runtime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let discovery = Discovery::new(&store, socket, Relays::new());
        let from = Source::Udp("127.0.0.1:9".parse().unwrap());
        let call = signed(
            &peer,
            4,
            now_ms(),
            Body::CallMeMaybe(vec!["192.0.2.44:7401".parse().unwrap()]),
        );
        let candidates = |d: &Discovery| {
            d.state
                .lock()
                .unwrap()
                .peers
                .get(&raw(&peer))
                .map(|p| p.candidates.clone())
                .unwrap_or_default()
        };
        // Unknown sender: ignored.
        discovery.receive(Source::Relay(raw(&peer)), &call);
        assert!(candidates(&discovery).is_empty());
        store
            .member_pins
            .write()
            .unwrap()
            .insert(peer_id, peer.verifying_key().as_bytes().to_vec());
        // Call-me-maybe only counts through the relay.
        discovery.receive(from, &call);
        assert!(candidates(&discovery).is_empty());
        let relayed = signed(
            &peer,
            5,
            now_ms(),
            Body::CallMeMaybe(vec!["192.0.2.44:7401".parse().unwrap()]),
        );
        discovery.receive(Source::Relay(raw(&peer)), &relayed);
        assert_eq!(
            candidates(&discovery),
            vec!["192.0.2.44:7401".parse().unwrap()]
        );
        // The same transaction again is a replay, even with other endpoints.
        discovery.state.lock().unwrap().peers.clear();
        discovery.receive(Source::Relay(raw(&peer)), &relayed);
        assert!(candidates(&discovery).is_empty());
        // A stale message is ignored.
        let stale = signed(
            &peer,
            6,
            now_ms() - 31_000,
            Body::CallMeMaybe(vec!["192.0.2.45:7401".parse().unwrap()]),
        );
        discovery.receive(Source::Relay(raw(&peer)), &stale);
        assert!(candidates(&discovery).is_empty());
        // A pong this host never asked for does not validate the endpoint.
        let pong = signed(
            &peer,
            7,
            now_ms(),
            Body::Pong {
                tx: [1; TX],
                observed: "127.0.0.1:1".parse().unwrap(),
            },
        );
        discovery.receive(from, &pong);
        assert!(discovery.host_at("127.0.0.1:9".parse().unwrap()).is_none());
        assert_eq!(discovery.path(&raw(&peer)), PathState::None);
    }
}
