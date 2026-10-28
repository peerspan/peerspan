//! `peerspan-relay/4` (wire section 14): forwards opaque QUIC datagrams
//! between registered TLS host keys. A registration grants no network access.
use super::Peer;
use crate::decentralized::mailbox::{Accounts, resource_token};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{mpsc, oneshot, watch},
};

const AUTH: u8 = 0;
const SEND: u8 = 1;
const RECEIVE: u8 = 2;
const UNREACHABLE: u8 = 3;
const PING: u8 = 4;
const AUTH_OK: u8 = 7;
const AUTH_REFUSED: u8 = 8;
const QUEUE: usize = 1024;
const QUEUED_BYTES: i64 = 64 << 20;
const WINDOW_BYTES: i64 = 32 << 20;
const REGISTRATION: Duration = Duration::from_secs(300);
const IDLE: Duration = Duration::from_secs(60);
const FIRST_AUTH: Duration = Duration::from_secs(5);
const WRITE: Duration = Duration::from_secs(5);
const PER_SOURCE: usize = 64;
const PER_ACCOUNT: usize = 64;

/// One token bucket per transport principal, with the rolling 61-second byte
/// window for datagram bytes. Counters outlive connections and reconnects.
struct Rate {
    tokens: f64,
    updated: Instant,
    seen: Instant,
    window: [(i64, i64); 61],
}
struct Rates {
    states: HashMap<String, Rate>,
    swept: Instant,
    origin: Instant,
}
impl Rates {
    fn allow(
        &mut self,
        kind: &str,
        principals: &[String],
        rate: f64,
        burst: f64,
        bytes: i64,
    ) -> bool {
        let now = Instant::now();
        if now.duration_since(self.swept) > Duration::from_secs(2) {
            self.states
                .retain(|_, s| now.duration_since(s.seen) <= Duration::from_secs(65));
            self.swept = now;
        }
        let second = now.duration_since(self.origin).as_secs() as i64;
        let mut allowed = true;
        for principal in principals {
            let name = format!("{kind}:{principal}");
            if !self.states.contains_key(&name) && self.states.len() >= 16384 {
                allowed = false;
                continue;
            }
            let state = self.states.entry(name).or_insert(Rate {
                tokens: burst,
                updated: now,
                seen: now,
                window: [(0, 0); 61],
            });
            state.tokens =
                (state.tokens + now.duration_since(state.updated).as_secs_f64() * rate).min(burst);
            state.updated = now;
            state.seen = now;
            if state.tokens < 1.0 {
                allowed = false;
            } else {
                state.tokens -= 1.0;
            }
            if bytes > 0 {
                let sum: i64 = state
                    .window
                    .iter()
                    .filter(|(s, _)| *s >= second - 60)
                    .map(|(_, b)| b)
                    .sum();
                if sum + bytes > WINDOW_BYTES {
                    allowed = false;
                } else {
                    let slot = &mut state.window[(second % 61) as usize];
                    if slot.0 != second {
                        *slot = (second, 0);
                    }
                    slot.1 += bytes;
                }
            }
        }
        allowed
    }
}
fn principals(peer: &Peer, account: &str) -> Vec<String> {
    let mut keys = vec![
        format!("key:{}", peer.key),
        format!("source:{}", peer.source),
    ];
    if !account.is_empty() {
        keys.push(format!("account:{account}"));
    }
    keys
}

struct Out {
    kind: u8,
    payload: Vec<u8>,
    ack: Option<oneshot::Sender<bool>>,
}
/// One relay connection's routing handle.
struct Conn {
    serial: u64,
    id: [u8; 32],
    peer: Peer,
    queue: mpsc::Sender<Out>,
    closed: watch::Sender<bool>,
    /// Held across an AUTH_OK write and its activation, so the reader never
    /// observes the connection between them.
    auth: tokio::sync::Mutex<()>,
}
impl Conn {
    fn close(&self) {
        self.closed.send_replace(true);
    }
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}
struct Entry {
    conn: Arc<Conn>,
    account: String,
    /// The registration deadline; `None` until the first AUTH_OK.
    expires: Option<Instant>,
    last: Instant,
    /// The account of an AUTH whose AUTH_OK is not written yet.
    pending: Option<String>,
}
impl Entry {
    fn deadline(&self) -> Instant {
        match self.expires {
            None => self.last + FIRST_AUTH,
            Some(expires) => (self.last + IDLE).min(expires),
        }
    }
}
#[derive(Default)]
struct State {
    /// Registered connections by host-ID digest.
    clients: HashMap<[u8; 32], Arc<Conn>>,
    /// Every live connection by serial.
    entries: HashMap<u64, Entry>,
}
impl State {
    fn current(&self, conn: &Conn, now: Instant) -> bool {
        self.clients
            .get(&conn.id)
            .is_some_and(|c| c.serial == conn.serial)
            && self
                .entries
                .get(&conn.serial)
                .and_then(|e| e.expires)
                .is_some_and(|e| now < e)
    }
    fn touch(&mut self, serial: u64) {
        if let Some(entry) = self.entries.get_mut(&serial) {
            entry.last = Instant::now();
        }
    }
    fn account_of(&self, conn: &Conn) -> Option<&str> {
        self.entries.get(&conn.serial).map(|e| e.account.as_str())
    }
}

pub(crate) struct Hub {
    state: Mutex<State>,
    rates: Mutex<Rates>,
    queued: Mutex<i64>,
    accounts: Option<Accounts>,
    serials: AtomicU64,
}
impl Hub {
    pub(crate) fn new(accounts: Option<Accounts>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            rates: Mutex::new(Rates {
                states: HashMap::new(),
                swept: Instant::now(),
                origin: Instant::now(),
            }),
            queued: Mutex::new(0),
            accounts,
            serials: AtomicU64::new(0),
        })
    }
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn allow(&self, kind: &str, principals: &[String], rate: f64, burst: f64, bytes: i64) -> bool {
        self.rates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allow(kind, principals, rate, burst, bytes)
    }
    fn reserve(&self, amount: i64) -> bool {
        let mut queued = self.queued.lock().unwrap_or_else(|e| e.into_inner());
        if *queued + amount > QUEUED_BYTES {
            return false;
        }
        *queued += amount;
        true
    }
    fn release(&self, amount: i64) {
        *self.queued.lock().unwrap_or_else(|e| e.into_inner()) -= amount;
    }
    /// Queues one frame without blocking; a full queue or byte budget drops it.
    fn enqueue(
        &self,
        conn: &Conn,
        kind: u8,
        payload: Vec<u8>,
        ack: Option<oneshot::Sender<bool>>,
    ) -> bool {
        if conn.is_closed() {
            return false;
        }
        let size = 3 + payload.len() as i64;
        if !self.reserve(size) {
            return false;
        }
        match conn.queue.try_send(Out { kind, payload, ack }) {
            Ok(()) => true,
            Err(_) => {
                self.release(size);
                false
            }
        }
    }
    async fn control(&self, conn: &Conn, kind: u8) -> bool {
        let (ack, done) = oneshot::channel();
        if !self.enqueue(conn, kind, Vec::new(), Some(ack)) {
            return false;
        }
        let mut closed = conn.closed.subscribe();
        tokio::select! {
            result = done => result.unwrap_or(false),
            _ = closed.wait_for(|c| *c) => false,
        }
    }
    /// Reserves registration occupancy for an AUTH before its AUTH_OK: at most
    /// 64 registered or pending connections per source and per account.
    fn reserve_auth(&self, conn: &Arc<Conn>, account: &str) -> bool {
        let mut state = self.state();
        let old = state.clients.get(&conn.id).cloned();
        if old.as_ref().is_some_and(|o| o.peer.key != conn.peer.key) {
            return false;
        }
        let (mut sources, mut accounts) = (0, 0);
        for registered in state.clients.values() {
            if old.as_ref().is_some_and(|o| o.serial == registered.serial) {
                continue;
            }
            if registered.peer.source == conn.peer.source {
                sources += 1;
            }
            if !account.is_empty() && state.account_of(registered) == Some(account) {
                accounts += 1;
            }
        }
        for entry in state.entries.values() {
            let Some(pending) = &entry.pending else {
                continue;
            };
            // A renewal or replacement reserves only occupancy its identity's
            // registration does not already hold in the same bucket.
            let registered = state.clients.get(&entry.conn.id);
            if entry.conn.peer.source == conn.peer.source
                && registered.is_none_or(|r| r.peer.source != entry.conn.peer.source)
            {
                sources += 1;
            }
            if !account.is_empty()
                && pending == account
                && registered.is_none_or(|r| state.account_of(r) != Some(pending))
            {
                accounts += 1;
            }
        }
        if sources >= PER_SOURCE || accounts >= PER_ACCOUNT {
            return false;
        }
        match state.entries.get_mut(&conn.serial) {
            Some(entry) => {
                entry.pending = Some(account.into());
                true
            }
            None => false,
        }
    }
    /// Runs under the state lock right after a successful AUTH_OK write.
    fn activate(state: &mut State, conn: &Arc<Conn>) -> bool {
        let Some(account) = state
            .entries
            .get_mut(&conn.serial)
            .and_then(|e| e.pending.take())
        else {
            return false;
        };
        if conn.is_closed() {
            return false;
        }
        if let Some(old) = state.clients.get(&conn.id)
            && old.serial != conn.serial
        {
            if old.peer.key != conn.peer.key {
                return false;
            }
            old.close();
        }
        let now = Instant::now();
        if let Some(entry) = state.entries.get_mut(&conn.serial) {
            entry.account = account;
            entry.expires = Some(now + REGISTRATION);
            entry.last = now;
        }
        state.clients.insert(conn.id, conn.clone());
        true
    }
    /// Routes one SEND; false closes the sender.
    fn send(&self, conn: &Conn, payload: &[u8]) -> bool {
        let state = self.state();
        let now = Instant::now();
        if !state.current(conn, now)
            || state
                .entries
                .get(&conn.serial)
                .is_none_or(|e| e.pending.is_some())
        {
            return false;
        }
        let destination: [u8; 32] = payload[..32].try_into().expect("checked SEND length");
        match state.clients.get(&destination) {
            Some(target) if state.current(target, now) => {
                let mut forward = Vec::with_capacity(payload.len());
                forward.extend_from_slice(&conn.id);
                forward.extend_from_slice(&payload[32..]);
                self.enqueue(target, RECEIVE, forward, None);
            }
            _ => {
                self.enqueue(conn, UNREACHABLE, destination.to_vec(), None);
            }
        }
        true
    }

    async fn writer<W: AsyncWrite + Unpin>(
        self: Arc<Self>,
        conn: Arc<Conn>,
        mut output: W,
        mut queue: mpsc::Receiver<Out>,
    ) {
        let mut closed = conn.closed.subscribe();
        loop {
            let frame = tokio::select! {
                _ = closed.wait_for(|c| *c) => break,
                frame = queue.recv() => match frame { Some(f) => f, None => break },
            };
            let size = 3 + frame.payload.len() as i64;
            let atomic = frame.kind == AUTH_OK;
            let guard = if atomic {
                Some(conn.auth.lock().await)
            } else {
                None
            };
            let allowed = {
                let state = self.state();
                let now = Instant::now();
                let entry = state.entries.get(&conn.serial);
                let control = matches!(frame.kind, AUTH_OK | AUTH_REFUSED);
                let allowed = if control {
                    entry.is_some_and(|e| e.expires.is_none_or(|x| now < x))
                } else {
                    state.current(&conn, now)
                };
                allowed && (!atomic || entry.is_some_and(|e| e.pending.is_some()))
            };
            if !allowed {
                drop(guard);
                self.release(size);
                if let Some(ack) = frame.ack {
                    let _ = ack.send(false);
                }
                break;
            }
            let mut wire = Vec::with_capacity(frame.payload.len() + 3);
            wire.push(frame.kind);
            wire.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(&frame.payload);
            let mut ok = tokio::select! {
                r = tokio::time::timeout(WRITE, async {
                    output.write_all(&wire).await?;
                    output.flush().await
                }) => matches!(r, Ok(Ok(()))),
                _ = closed.wait_for(|c| *c) => false,
            };
            if atomic {
                ok = ok && Self::activate(&mut self.state(), &conn);
            }
            drop(guard);
            self.release(size);
            if let Some(ack) = frame.ack {
                let _ = ack.send(ok);
            }
            if !ok {
                break;
            }
            self.state().touch(conn.serial);
        }
        // No producer can enqueue once the queue is closed. Release every
        // reserved byte and fail every waiting control acknowledgment.
        conn.close();
        queue.close();
        while let Ok(frame) = queue.try_recv() {
            self.release(3 + frame.payload.len() as i64);
            if let Some(ack) = frame.ack {
                let _ = ack.send(false);
            }
        }
    }

    /// Serves one TLS connection that negotiated `peerspan-relay/4`.
    pub(crate) async fn serve<S>(self: Arc<Self>, stream: S, peer: Peer)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (input, output) = tokio::io::split(stream);
        let (queue, receiver) = mpsc::channel(QUEUE);
        let (closed, _) = watch::channel(false);
        let conn = Arc::new(Conn {
            serial: self.serials.fetch_add(1, Ordering::Relaxed),
            id: Sha256::digest(&peer.raw).into(),
            peer,
            queue,
            closed,
            auth: tokio::sync::Mutex::new(()),
        });
        self.state().entries.insert(
            conn.serial,
            Entry {
                conn: conn.clone(),
                account: String::new(),
                expires: None,
                last: Instant::now(),
                pending: None,
            },
        );
        let writer = tokio::spawn(self.clone().writer(conn.clone(), output, receiver));
        let watchdog = tokio::spawn(self.clone().watchdog(conn.clone()));
        self.read(&conn, input).await;
        conn.close();
        let _ = writer.await;
        let _ = watchdog.await;
        let mut state = self.state();
        state.entries.remove(&conn.serial);
        if state
            .clients
            .get(&conn.id)
            .is_some_and(|c| c.serial == conn.serial)
        {
            state.clients.remove(&conn.id);
        }
    }
    /// Closes the connection after 5 seconds without a first AUTH, 60 seconds
    /// without any frame in either direction, or at registration expiry.
    async fn watchdog(self: Arc<Self>, conn: Arc<Conn>) {
        let mut closed = conn.closed.subscribe();
        loop {
            let Some(deadline) = self.state().entries.get(&conn.serial).map(Entry::deadline) else {
                break;
            };
            if Instant::now() >= deadline {
                conn.close();
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline.into()) => {}
                _ = closed.wait_for(|c| *c) => break,
            }
        }
    }
    async fn read<R: AsyncRead + Unpin>(self: &Arc<Self>, conn: &Arc<Conn>, input: R) {
        let mut closed = conn.closed.subscribe();
        let mut reader = BufReader::with_capacity(16 << 10, input);
        let peer = &conn.peer;
        loop {
            let mut header = [0u8; 3];
            tokio::select! {
                r = reader.read_exact(&mut header) => if r.is_err() { return },
                _ = closed.wait_for(|c| *c) => return,
            }
            let (kind, size) = (
                header[0],
                u16::from_be_bytes([header[1], header[2]]) as usize,
            );
            let (account, current, pending, ever) = {
                let _auth = conn.auth.lock().await;
                let state = self.state();
                let Some(entry) = state.entries.get(&conn.serial) else {
                    return;
                };
                (
                    entry.account.clone(),
                    state.current(conn, Instant::now()),
                    entry.pending.is_some(),
                    entry.expires.is_some(),
                )
            };
            let keys = principals(peer, &account);
            if !self.allow("relay_frames", &keys, 1024.0, 1024.0, 0)
                || (ever && !current)
                || (!ever && (kind != AUTH || pending))
                || (pending && kind != PING)
            {
                return;
            }
            let valid = match kind {
                AUTH => size <= 1024,
                SEND => (33..=1532).contains(&size),
                PING => size == 0,
                _ => false,
            };
            if !valid {
                return;
            }
            let mut payload = vec![0u8; size];
            tokio::select! {
                r = reader.read_exact(&mut payload) => if r.is_err() { return },
                _ = closed.wait_for(|c| *c) => return,
            }
            self.state().touch(conn.serial);
            match kind {
                AUTH => {
                    // Bytes read ahead with an AUTH arrived before its answer and
                    // cannot become an authenticated SEND. A renewal may pipeline
                    // only exact empty PINGs under the old registration.
                    while !reader.buffer().is_empty() {
                        let buffered = reader.buffer();
                        if !ever
                            || buffered.len() < 3
                            || buffered[..3] != [PING, 0, 0]
                            || !self.allow("relay_frames", &keys, 1024.0, 1024.0, 0)
                        {
                            return;
                        }
                        std::pin::Pin::new(&mut reader).consume(3);
                    }
                    if !resource_token(&payload) {
                        return;
                    }
                    let mut allowed = self.allow("relay_auth", &principals(peer, ""), 2.0, 8.0, 0);
                    let account = match &self.accounts {
                        None if payload.is_empty() => Some(String::new()),
                        None => None,
                        Some(accounts) => accounts.get(&payload).cloned(),
                    };
                    if let Some(account) = &account
                        && !account.is_empty()
                    {
                        allowed =
                            self.allow("relay_auth", &[format!("account:{account}")], 2.0, 8.0, 0)
                                && allowed;
                    }
                    let reserved = match &account {
                        Some(account) if allowed => self.reserve_auth(conn, account),
                        _ => false,
                    };
                    if !reserved {
                        self.control(conn, AUTH_REFUSED).await;
                        return;
                    }
                    let hub = self.clone();
                    let conn = conn.clone();
                    tokio::spawn(async move {
                        if !hub.control(&conn, AUTH_OK).await {
                            conn.close();
                        }
                    });
                }
                SEND => {
                    // Over the byte window: drop, as QUIC loss, never a fake
                    // application result.
                    if !self.allow("relay_bytes", &keys, 1e12, 1e12, size as i64 - 32) {
                        continue;
                    }
                    if !self.send(conn, &payload) {
                        return;
                    }
                }
                _ => {}
            }
        }
    }
}
