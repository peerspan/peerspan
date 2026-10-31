//! Opaque direct bootstrap storage. TLS possession identifies a resource user;
//! neither a carrier frame nor this database grants network authority.
use super::{
    bootstrap::{ALPN, Frame, MAX_FRAME_POST, Window},
    codec,
};
use anyhow::{Context, bail};
use chrono::SecondsFormat;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Deserialize;
use serde_json::{json, value::RawValue};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    future::Future,
    net::{IpAddr, Ipv6Addr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::server::TlsStream;

const GET_MAX: usize = 48 << 20;
const COMPLETION_MAX: usize = 20 << 20;
const BUFFER_MAX: usize = 64 << 20;
const RAW_MAX: i64 = 512 << 20;
const CIPHER_MAX: i64 = 256 << 20;
const BOX_MAX: i64 = 32 << 20;
const BOX_COLUMNS: &str = "locator,request_id,read_cap_hash,created_at,expires_at,expires_unix,creator_key,source_bucket,account_id,creation_identity_hash,state,ciphertext_bytes";

type Wire<T> = std::result::Result<T, Fault>;
#[derive(Debug)]
enum Fault {
    Code(&'static str),
    Internal,
}
impl From<rusqlite::Error> for Fault {
    fn from(_: rusqlite::Error) -> Self {
        Self::Internal
    }
}
impl From<codec::Error> for Fault {
    fn from(e: codec::Error) -> Self {
        Self::Code(e.code)
    }
}
fn demand(ok: bool, code: &'static str) -> Wire<()> {
    if ok { Ok(()) } else { Err(Fault::Code(code)) }
}
fn utc() -> String {
    crate::clock::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |v, (a, b)| v | (a ^ b)) == 0
}
fn source(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .map(|v| v.to_string())
            .unwrap_or_else(|| {
                let mut s = v.segments();
                s[4..].fill(0);
                format!("{}/64", Ipv6Addr::from(s))
            }),
    }
}

struct Bucket {
    tokens: f64,
    updated: Instant,
    seen: Instant,
}
#[derive(Default)]
struct Limits {
    active: usize,
    keys: HashMap<String, usize>,
    sources: HashMap<String, usize>,
    buffers: [usize; 2],
    rates: HashMap<String, Bucket>,
}
impl Limits {
    fn allow(&mut self, key: &str, source: &str, get: bool) -> bool {
        self.allow_principals(&[format!("key:{key}"), format!("source:{source}")], get)
    }
    fn allow_principals(&mut self, principals: &[String], get: bool) -> bool {
        let now = Instant::now();
        self.rates
            .retain(|_, v| now.duration_since(v.seen) <= Duration::from_secs(65));
        let (rate, burst) = if get { (1.0, 4.0) } else { (2.0, 8.0) };
        let kind = if get { "get" } else { "mutation" };
        let mut allowed = true;
        for principal in principals.iter().map(|p| format!("{kind}:{p}")) {
            if !self.rates.contains_key(&principal) && self.rates.len() >= 16384 {
                allowed = false;
                continue;
            }
            let b = self.rates.entry(principal).or_insert(Bucket {
                tokens: burst,
                updated: now,
                seen: now,
            });
            b.tokens = (b.tokens + now.duration_since(b.updated).as_secs_f64() * rate).min(burst);
            b.updated = now;
            b.seen = now;
            if b.tokens < 1.0 {
                allowed = false;
            } else {
                b.tokens -= 1.0;
            }
        }
        allowed
    }
}
struct Active {
    owner: Arc<ParticipantMailbox>,
    key: String,
    source: String,
}
impl Drop for Active {
    fn drop(&mut self) {
        if let Ok(mut l) = self.owner.limits.lock() {
            l.active -= 1;
            l.buffers[1] -= 512;
            if let Some(v) = l.keys.get_mut(&self.key) {
                *v -= 1;
                if *v == 0 {
                    l.keys.remove(&self.key);
                }
            }
            if let Some(v) = l.sources.get_mut(&self.source) {
                *v -= 1;
                if *v == 0 {
                    l.sources.remove(&self.source);
                }
            }
        }
    }
}
struct Buffer {
    owner: Arc<ParticipantMailbox>,
    index: usize,
    size: usize,
}
pub(crate) struct TransportBuffers {
    _receive: Buffer,
    _response: Buffer,
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if let Ok(mut l) = self.owner.limits.lock() {
            l.buffers[self.index] -= self.size;
        }
    }
}

/// Transport-only participant resources; no authority database, listener or key.
pub struct ParticipantMailbox {
    database: Mutex<Connection>,
    limits: Mutex<Limits>,
    unavailable: AtomicBool,
    completion: Option<Arc<dyn ParticipantCompletion>>,
    operator: Operator,
    _database_file: File,
    _directory: File,
    _lock: Option<File>,
}

/// Validated optional helper resource credentials: decoded token bytes to the
/// configured account ID.
pub type Accounts = HashMap<Vec<u8>, String>;
/// Who serves these resources. A participant host's first-contact listener
/// keeps 300-second `link_` windows and takes no resource credential; the
/// optional helper applies the request windows of spec section 9.2 and its
/// optional tokens file.
enum Operator {
    Participant,
    Helper(Option<Accounts>),
}
impl Operator {
    fn window(&self) -> Window {
        match self {
            Self::Participant => Window::Request,
            Self::Helper(_) => Window::Request,
        }
    }
}

/// Exact bounded publication bytes and the server-derived TLS host identity.
pub struct CompletionRequest {
    pub host_public_key: String,
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}
pub struct CompletionResponse {
    pub status: u16,
    pub body: Vec<u8>,
}
/// The host must verify both actual participants, full consent, current or
/// historical authority, and its final atomic adoption rules. Transport grants
/// none of these. An error closes the carrier without inventing an outcome.
pub trait ParticipantCompletion: Send + Sync + 'static {
    fn complete(
        &self,
        request: CompletionRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<CompletionResponse>> + Send + '_>>;
}
fn protected(path: &Path, create: bool) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o600 {
        bail!("invalid private participant resource file");
    }
    Ok(file)
}
impl ParticipantMailbox {
    pub fn open(state_directory: &Path) -> anyhow::Result<Arc<Self>> {
        Self::open_with_completion(state_directory, None)
    }
    pub fn open_with_completion(
        state_directory: &Path,
        completion: Option<Arc<dyn ParticipantCompletion>>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::open_as(
            state_directory,
            Some("dec-bootstrap.lock"),
            "dec-bootstrap.db",
            completion,
            Operator::Participant,
        )
    }
    /// The optional helper's resources in its private state directory. The
    /// caller already holds that directory's exclusive `helper.lock`.
    pub fn open_helper(
        state_directory: &Path,
        accounts: Option<Accounts>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::open_as(
            state_directory,
            None,
            "resources.db",
            None,
            Operator::Helper(accounts),
        )
    }
    /// Whether storage has failed; the service then refuses all requests.
    pub fn unavailable(&self) -> bool {
        self.unavailable.load(Ordering::Acquire)
    }
    fn open_as(
        state_directory: &Path,
        lock_name: Option<&str>,
        database_name: &str,
        completion: Option<Arc<dyn ParticipantCompletion>>,
        operator: Operator,
    ) -> anyhow::Result<Arc<Self>> {
        let runtime = tokio::runtime::Handle::try_current()?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state_directory)?;
        let m = directory.metadata()?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
            bail!("invalid private participant resource directory");
        }
        use std::os::fd::AsRawFd;
        let directory_path =
            std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let lock = match lock_name {
            Some(name) => {
                let lock = protected(&directory_path.join(name), true)?;
                fs2::FileExt::try_lock_exclusive(&lock)
                    .context("participant mailbox already owned")?;
                Some(lock)
            }
            None => None,
        };
        for suffix in ["-wal", "-shm", "-journal"] {
            match protected(
                &directory_path.join(format!("{database_name}{suffix}")),
                false,
            ) {
                Ok(_) => {}
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        let path = directory_path.join(database_name);
        let new = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(e.into()),
        };
        let database_file = protected(&path, false)?;
        let database_identity = database_file.metadata()?;
        // SQLite NOFOLLOW also rejects our intentional, held procfd directory
        // anchor. Validate the leaf with O_NOFOLLOW, retain that owned file,
        // and check its identity after opening instead of rejecting the anchor.
        let mut db = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let opened_identity = protected(&path, false)?.metadata()?;
        if opened_identity.dev() != database_identity.dev()
            || opened_identity.ino() != database_identity.ino()
        {
            bail!("participant resource file changed while opening");
        }
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
        if new {
            let tx = db.transaction()?;
            tx.execute_batch("CREATE TABLE helper_format(version INTEGER PRIMARY KEY CHECK(version=1));
                INSERT INTO helper_format VALUES(1);
                CREATE TABLE mailboxes(locator TEXT PRIMARY KEY,request_id TEXT NOT NULL,read_cap_hash TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,expires_unix INTEGER NOT NULL,creator_key TEXT NOT NULL,source_bucket TEXT NOT NULL,account_id TEXT NOT NULL,creation_identity_hash TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','deleted','expired')),ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes>=0));
                CREATE INDEX mailbox_expiry ON mailboxes(expires_unix);
                CREATE TABLE frames(locator TEXT NOT NULL REFERENCES mailboxes(locator) ON DELETE CASCADE,frame_id TEXT NOT NULL,role TEXT NOT NULL,writer_key TEXT NOT NULL,body BLOB NOT NULL,ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes>=16),PRIMARY KEY(locator,frame_id));")?;
            tx.commit()?;
            directory.sync_all()?;
        }
        validate(&db, &operator)
            .map_err(|_| anyhow::anyhow!("invalid participant resource storage"))?;
        db.execute_batch("PRAGMA journal_mode=WAL;")?;
        let service = Arc::new(Self {
            database: Mutex::new(db),
            limits: Mutex::new(Limits::default()),
            unavailable: AtomicBool::new(false),
            completion,
            operator,
            _database_file: database_file,
            _directory: directory,
            _lock: lock,
        });
        let weak = Arc::downgrade(&service);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Some(owner) = weak.upgrade() else { break };
                let job = owner.clone();
                let result = tokio::task::spawn_blocking(move || job.collect()).await;
                if !matches!(result, Ok(Ok(()))) {
                    owner.unavailable.store(true, Ordering::Release);
                    break;
                }
            }
        });
        Ok(service)
    }
    /// Reserve the bounded transport receive window, parser lookahead/header,
    /// and send window before a connection can advertise application credit.
    pub(crate) fn transport_buffers(self: &Arc<Self>) -> Option<TransportBuffers> {
        let receive = self.buffer(0, 64 << 10).ok()?;
        let response = self.buffer(1, 64 << 10).ok()?;
        Some(TransportBuffers {
            _receive: receive,
            _response: response,
        })
    }
    fn collect(&self) -> Wire<()> {
        let mut db = self.database.lock().map_err(|_| Fault::Internal)?;
        let tx = db.transaction()?;
        collect(&tx, crate::clock::now().timestamp())?;
        tx.commit()?;
        Ok(())
    }
    fn active(self: &Arc<Self>, key: &str, source: &str) -> Option<Active> {
        let mut l = self.limits.lock().ok()?;
        if self.unavailable.load(Ordering::Acquire)
            || l.active >= 128
            || l.keys.get(key).copied().unwrap_or(0) >= 4
            || l.sources.get(source).copied().unwrap_or(0) >= 16
            || l.buffers[1] > BUFFER_MAX - 512
        {
            return None;
        }
        l.active += 1;
        // Fixed control replies are below 512 bytes; reserve them before headers.
        l.buffers[1] += 512;
        *l.keys.entry(key.into()).or_default() += 1;
        *l.sources.entry(source.into()).or_default() += 1;
        Some(Active {
            owner: self.clone(),
            key: key.into(),
            source: source.into(),
        })
    }
    fn buffer(self: &Arc<Self>, index: usize, size: usize) -> Wire<Buffer> {
        let mut l = self.limits.lock().map_err(|_| Fault::Internal)?;
        demand(
            size <= BUFFER_MAX.saturating_sub(l.buffers[index]),
            "quota_exceeded",
        )?;
        l.buffers[index] += size;
        Ok(Buffer {
            owner: self.clone(),
            index,
            size,
        })
    }
}
fn collect(tx: &Transaction<'_>, now: i64) -> Wire<()> {
    tx.execute("DELETE FROM frames WHERE locator IN (SELECT locator FROM mailboxes WHERE state='active' AND expires_unix<=?1)",[now])?;
    tx.execute("UPDATE mailboxes SET state='expired',ciphertext_bytes=0 WHERE state='active' AND expires_unix<=?1",[now])?;
    tx.execute(
        "DELETE FROM mailboxes WHERE state!='active' AND expires_unix<=?1",
        [now - 86400],
    )?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Creation {
    format: u64,
    request_id: String,
    locator: String,
    read_cap_hash: String,
    created_at: String,
    expires_at: String,
    frame: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Append {
    frame: Box<RawValue>,
}
struct Mailbox {
    locator: String,
    request: String,
    cap: String,
    created: String,
    expires: String,
    deadline: i64,
    creator: String,
    source: String,
    account: String,
    identity: String,
    state: String,
    bytes: i64,
}
impl Mailbox {
    fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            locator: r.get(0)?,
            request: r.get(1)?,
            cap: r.get(2)?,
            created: r.get(3)?,
            expires: r.get(4)?,
            deadline: r.get(5)?,
            creator: r.get(6)?,
            source: r.get(7)?,
            account: r.get(8)?,
            identity: r.get(9)?,
            state: r.get(10)?,
            bytes: r.get(11)?,
        })
    }
}
fn identity(c: &Creation, f: &Frame) -> String {
    codec::hash(&codec::lines(&[
        "peerspan-decentralized-mailbox-create-v1",
        "1",
        &c.request_id,
        &c.locator,
        &c.read_cap_hash,
        &c.created_at,
        &c.expires_at,
        &codec::hash(&f.body),
    ]))
}
fn frame_window(f: &Frame, window: Window) -> Wire<()> {
    window
        .check_at(&f.created_at, &f.expires_at, &utc())
        .map_err(Into::into)
}
fn validate(db: &Connection, operator: &Operator) -> Wire<()> {
    let window = operator.window();
    let (count, version): (i64, i64) = db.query_row(
        "SELECT count(*),coalesce(min(version),0) FROM helper_format",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    demand(count == 1 && version == 1, "invalid")?;
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    demand(integrity == "ok", "invalid")?;
    let mut foreign_query = db.prepare("PRAGMA foreign_key_check")?;
    let mut foreign_rows = foreign_query.query([])?;
    let foreign: Option<i64> = foreign_rows.next()?.map(|r| r.get(1)).transpose()?;
    demand(foreign.is_none(), "invalid")?;
    let (count,live,bytes):(i64,i64,i64)=db.query_row("SELECT count(*),coalesce(sum(state='active'),0),coalesce(sum(ciphertext_bytes),0) FROM mailboxes",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    demand(
        count <= 4096 && live <= 1024 && (0..=CIPHER_MAX).contains(&bytes),
        "invalid",
    )?;
    let (raw,bad):(i64,i64)=db.query_row("SELECT coalesce(sum(length(body)),0),coalesce(sum(length(body)>8388608 OR ciphertext_bytes<16 OR ciphertext_bytes>4194320),0) FROM frames",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    demand(raw <= RAW_MAX && bad == 0, "invalid")?;
    for (column, total, active) in [
        ("creator_key", 64, 4),
        ("source_bucket", 256, 16),
        ("account_id", 64, 4),
    ] {
        let sql = format!(
            "SELECT count(*) FROM (SELECT {column} FROM mailboxes WHERE {column}!='' GROUP BY {column} HAVING count(*)>{total} OR sum(state='active')>{active})"
        );
        let bad: i64 = db.query_row(&sql, [], |r| r.get(0))?;
        demand(bad == 0, "invalid")?;
    }
    let mut query = db.prepare(&format!("SELECT {BOX_COLUMNS} FROM mailboxes"))?;
    let mut boxes = query.query([])?;
    while let Some(row) = boxes.next()? {
        let b = Mailbox::row(row)?;
        demand(
            window.stored(&b.request, &b.created, &b.expires)
                && codec::digest(&b.locator)
                && codec::digest(&b.cap)
                && codec::key(&b.creator)
                && codec::digest(&b.identity)
                && b.source.len() <= 64
                && match operator {
                    Operator::Participant => b.account.len() <= 128,
                    Operator::Helper(_) => b.account.is_empty() || account_id(&b.account),
                },
            "invalid",
        )?;
        let end = codec::stamp(&b.expires)?.timestamp();
        demand(
            end == b.deadline
                && matches!(b.state.as_str(), "active" | "deleted" | "expired")
                && (0..=BOX_MAX).contains(&b.bytes),
            "invalid",
        )?;
        let (count, size): (i64, i64) = db.query_row(
            "SELECT count(*),coalesce(sum(ciphertext_bytes),0) FROM frames WHERE locator=?1",
            [&b.locator],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        demand(
            count <= 64 && size == b.bytes && (b.state == "active" || count == 0),
            "invalid",
        )?;
        let mut frames = db.prepare(
            "SELECT frame_id,role,writer_key,body,ciphertext_bytes FROM frames WHERE locator=?1",
        )?;
        let mut frames = frames.query([&b.locator])?;
        let mut first = false;
        while let Some(r) = frames.next()? {
            let raw: Vec<u8> = r.get(3)?;
            let f = Frame::read_in(&raw, window)?;
            demand(
                f.frame_id == r.get::<_, String>(0)?
                    && f.role == r.get::<_, String>(1)?
                    && f.writer_host_public_key == r.get::<_, String>(2)?
                    && f.ciphertext.len() as i64 == r.get::<_, i64>(4)?
                    && f.locator == b.locator
                    && f.request_id == b.request
                    && f.created_at == b.created
                    && f.expires_at == b.expires,
                "invalid",
            )?;
            if f.role == "request" && f.writer_host_public_key == b.creator {
                let c = Creation {
                    format: 1,
                    request_id: b.request.clone(),
                    locator: b.locator.clone(),
                    read_cap_hash: b.cap.clone(),
                    created_at: b.created.clone(),
                    expires_at: b.expires.clone(),
                    frame: RawValue::from_string(
                        String::from_utf8(raw).map_err(|_| Fault::Internal)?,
                    )
                    .map_err(|_| Fault::Internal)?,
                };
                first |= identity(&c, &f) == b.identity;
            }
        }
        demand(b.state != "active" || first, "invalid")?;
    }
    Ok(())
}
fn lookup(tx: &Transaction<'_>, locator: &str, cap: &str) -> Wire<Mailbox> {
    let b = tx
        .query_row(
            &format!("SELECT {BOX_COLUMNS} FROM mailboxes WHERE locator=?1"),
            [locator],
            Mailbox::row,
        )
        .optional()?
        .ok_or(Fault::Code("not_found"))?;
    demand(same(&b.cap, &codec::hash(cap.as_bytes())), "forbidden")?;
    Ok(b)
}
fn insert_frame(tx: &Transaction<'_>, f: &Frame) -> Wire<()> {
    let (raw, cipher): (i64, i64) = tx.query_row(
        "SELECT coalesce(sum(length(body)),0),coalesce(sum(ciphertext_bytes),0) FROM frames",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    demand(
        raw + f.body.len() as i64 <= RAW_MAX && cipher + f.ciphertext.len() as i64 <= CIPHER_MAX,
        "quota_exceeded",
    )?;
    tx.execute("INSERT INTO frames(locator,frame_id,role,writer_key,body,ciphertext_bytes) VALUES(?1,?2,?3,?4,?5,?6)",params![f.locator,f.frame_id,f.role,f.writer_host_public_key,f.body,f.ciphertext.len() as i64])?;
    Ok(())
}
/// A helper resource account ID from the tokens file.
pub fn account_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn quota(tx: &Transaction<'_>, key: &str, source: &str, account: &str) -> Wire<()> {
    // Account ceilings additionally aggregate different keys; anonymous
    // resources keep both actual-key and actual-source limits.
    for (column, arg, total, live) in [
        ("creator_key", key, 64, 4),
        ("source_bucket", source, 256, 16),
        ("account_id", account, 64, 4),
    ] {
        if arg.is_empty() {
            continue;
        }
        let sql = format!(
            "SELECT count(*),coalesce(sum(state='active'),0) FROM mailboxes WHERE {column}=?1"
        );
        let (count, active): (i64, i64) =
            tx.query_row(&sql, [arg], |r| Ok((r.get(0)?, r.get(1)?)))?;
        demand(count < total && active < live, "quota_exceeded")?;
    }
    let (count, active): (i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(state='active'),0) FROM mailboxes",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    demand(count < 4096 && active < 1024, "quota_exceeded")?;
    Ok(())
}
enum Operation {
    Create(Box<Creation>, Box<Frame>, String),
    Append(Box<Frame>, String),
    Get(String, String),
    Delete(String, String),
}
struct Response {
    status: u16,
    allow: Option<&'static str>,
    body: Vec<u8>,
    limited: bool,
    _buffer: Option<Buffer>,
}
impl Response {
    fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            allow: None,
            body: serde_json::to_vec(&value).expect("JSON value"),
            limited: false,
            _buffer: None,
        }
    }
    fn fault(code: &'static str) -> Self {
        let status = match code {
            "invalid" => 400,
            "forbidden" => 403,
            "not_found" => 404,
            "expired" => 410,
            "rate_limited" => 429,
            _ => 409,
        };
        let mut r = Self::json(status, json!({"code":code,"error":code,"required_ids":[]}));
        r.limited = status == 429;
        r
    }
}
impl ParticipantMailbox {
    fn operation(self: &Arc<Self>, op: Operation, key: &str, source: &str) -> Wire<Response> {
        let window = self.operator.window();
        if self.unavailable.load(Ordering::Acquire) {
            return Err(Fault::Internal);
        }
        let mut db = self.database.lock().map_err(|_| Fault::Internal)?;
        // Expiration releases resource quotas even when the request is refused.
        let tx = db.transaction()?;
        collect(&tx, crate::clock::now().timestamp())?;
        tx.commit()?;
        let tx = db.transaction()?;
        let response = match op {
            Operation::Create(c, f, account) => {
                frame_window(&f, window)?;
                let old = tx
                    .query_row(
                        &format!("SELECT {BOX_COLUMNS} FROM mailboxes WHERE locator=?1"),
                        [&c.locator],
                        Mailbox::row,
                    )
                    .optional()?;
                let status = if let Some(b) = old {
                    demand(b.state == "active", "expired")?;
                    demand(b.identity == identity(&c, &f), "operation_conflict")?;
                    200
                } else {
                    quota(&tx, key, source, &account)?;
                    tx.execute(
                        "INSERT INTO mailboxes VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'active',?11)",
                        params![
                            c.locator,
                            c.request_id,
                            c.read_cap_hash,
                            c.created_at,
                            c.expires_at,
                            codec::stamp(&c.expires_at)?.timestamp(),
                            key,
                            source,
                            account,
                            identity(&c, &f),
                            f.ciphertext.len() as i64
                        ],
                    )?;
                    insert_frame(&tx, &f)?;
                    201
                };
                Response::json(
                    status,
                    json!({"request_id":c.request_id,"locator":c.locator}),
                )
            }
            Operation::Append(f, cap) => {
                frame_window(&f, window)?;
                let b = lookup(&tx, &f.locator, &cap)?;
                demand(b.state == "active", "expired")?;
                demand(
                    b.request == f.request_id
                        && b.created == f.created_at
                        && b.expires == f.expires_at,
                    "invalid",
                )?;
                let old: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT body FROM frames WHERE locator=?1 AND frame_id=?2",
                        params![f.locator, f.frame_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(old) = old {
                    demand(old == f.body, "state_conflict")?;
                } else {
                    let count: i64 = tx.query_row(
                        "SELECT count(*) FROM frames WHERE locator=?1",
                        [&f.locator],
                        |r| r.get(0),
                    )?;
                    demand(
                        count < 64 && b.bytes + f.ciphertext.len() as i64 <= BOX_MAX,
                        "quota_exceeded",
                    )?;
                    insert_frame(&tx, &f)?;
                    tx.execute("UPDATE mailboxes SET ciphertext_bytes=ciphertext_bytes+?1 WHERE locator=?2",params![f.ciphertext.len() as i64,f.locator])?;
                }
                Response::json(200, json!({"frame_id":f.frame_id}))
            }
            Operation::Delete(locator, cap) => {
                let b = lookup(&tx, &locator, &cap)?;
                if b.state == "active" {
                    tx.execute("DELETE FROM frames WHERE locator=?1", [&locator])?;
                    tx.execute(
                        "UPDATE mailboxes SET state='deleted',ciphertext_bytes=0 WHERE locator=?1",
                        [&locator],
                    )?;
                }
                Response {
                    status: 204,
                    allow: None,
                    body: Vec::new(),
                    limited: false,
                    _buffer: None,
                }
            }
            Operation::Get(locator, cap) => {
                let b = lookup(&tx, &locator, &cap)?;
                demand(b.state != "deleted", "not_found")?;
                demand(
                    b.state != "expired" && crate::clock::now().timestamp() < b.deadline,
                    "expired",
                )?;
                let prefix = format!(
                    "{{\"format\":1,\"request_id\":\"{}\",\"created_at\":\"{}\",\"expires_at\":\"{}\",\"frames\":[",
                    b.request, b.created, b.expires
                );
                let (raw, count): (i64, i64) = tx.query_row(
                    "SELECT coalesce(sum(length(body)),0),count(*) FROM frames WHERE locator=?1",
                    [&locator],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                demand(
                    (0..=GET_MAX as i64).contains(&raw) && (0..=64).contains(&count),
                    "quota_exceeded",
                )?;
                let size =
                    prefix.len() + raw as usize + count.saturating_sub(1).max(0) as usize + 2;
                demand(size <= GET_MAX, "quota_exceeded")?;
                let response_buffer = self.buffer(1, size.saturating_sub(512))?;
                let mut body = Vec::with_capacity(size);
                body.extend(prefix.as_bytes());
                let mut query=tx.prepare("SELECT body FROM frames WHERE locator=?1 ORDER BY role COLLATE BINARY,writer_key COLLATE BINARY,frame_id COLLATE BINARY")?;
                let mut rows = query.query([&locator])?;
                let mut first = true;
                while let Some(r) = rows.next()? {
                    let raw: Vec<u8> = r.get(0)?;
                    demand(body.len() + raw.len() + 3 <= GET_MAX, "quota_exceeded")?;
                    if !first {
                        body.push(b',');
                    }
                    first = false;
                    body.extend(raw);
                }
                body.extend(b"]}");
                Response {
                    status: 200,
                    allow: None,
                    body,
                    limited: false,
                    _buffer: Some(response_buffer),
                }
            }
        };
        tx.commit()?;
        Ok(response)
    }
}

struct Head {
    method: String,
    path: String,
    length: usize,
    cap: std::result::Result<String, &'static str>,
    /// The `X-Peerspan-Resource-Token` header: absent, its decoded token, or
    /// `invalid` for a duplicate or malformed value.
    token: Option<std::result::Result<Vec<u8>, &'static str>>,
}
fn head(raw: &[u8]) -> Wire<Head> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut r = httparse::Request::new(&mut headers);
    demand(
        r.parse(raw).is_ok_and(|s| s.is_complete()) && r.version == Some(1),
        "invalid",
    )?;
    let method = r.method.ok_or(Fault::Code("invalid"))?.to_owned();
    let path = r.path.ok_or(Fault::Code("invalid"))?.to_owned();
    let (mut length, mut lengths, mut authorization, mut tokens) =
        (0usize, 0usize, Vec::new(), Vec::new());
    // Inspect raw security values before a generic HTTP parser can trim them.
    for line in raw.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        demand(line[0] != b' ' && line[0] != b'\t', "invalid")?;
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(Fault::Code("invalid"))?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(Fault::Code("invalid"));
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            lengths += 1;
            let literal = std::str::from_utf8(value)
                .map_err(|_| Fault::Code("invalid"))?
                .trim();
            length = literal.parse().map_err(|_| Fault::Code("invalid"))?;
            demand(lengths == 1 && length.to_string() == literal, "invalid")?;
        }
        if name.eq_ignore_ascii_case(b"authorization") {
            authorization.push(value);
        }
        if name.eq_ignore_ascii_case(b"x-peerspan-resource-token") {
            tokens.push(value);
        }
    }
    demand(method != "POST" || lengths == 1, "invalid")?;
    demand(
        !matches!(method.as_str(), "GET" | "DELETE") || length == 0,
        "invalid",
    )?;
    let exact = |value: &[u8]| -> Option<String> {
        let value = value.strip_prefix(b" ").unwrap_or(value);
        let value = std::str::from_utf8(value).ok()?;
        (value.trim() == value).then(|| value.to_owned())
    };
    let cap = if authorization.is_empty() {
        Err("forbidden")
    } else if authorization.len() != 1 {
        Err("invalid")
    } else {
        exact(authorization[0])
            .and_then(|v| {
                v.strip_prefix("Bearer ")
                    .filter(|v| codec::digest(v))
                    .map(str::to_owned)
            })
            .ok_or("invalid")
    };
    let token = match tokens.as_slice() {
        [] => None,
        [token] => Some(
            exact(token)
                .and_then(|v| codec::b64(&v, 1024).ok())
                .filter(|v| !v.is_empty() && resource_token(v))
                .ok_or("invalid"),
        ),
        _ => Some(Err("invalid")),
    };
    Ok(Head {
        method,
        path,
        length,
        cap,
        token,
    })
}
/// A resource token: UTF-8 without CR, LF or NUL (relay AUTH allows empty).
pub fn resource_token(token: &[u8]) -> bool {
    std::str::from_utf8(token).is_ok() && !token.iter().any(|b| matches!(b, 0 | 10 | 13))
}
enum Route {
    Create,
    Box(String),
    Append(String),
    Completion(&'static str),
}
fn completion_route(path: &str) -> Wire<Route> {
    if path == "/bootstrap/v1/activations" {
        return Ok(Route::Completion("POST"));
    }
    if let Some(id) = path.strip_prefix("/bootstrap/v1/operations/")
        && codec::ident(id, "link_")
    {
        return Ok(Route::Completion("GET"));
    }
    Err(Fault::Code("not_found"))
}
fn route(path: &str, completion: bool) -> Wire<Route> {
    const BASE: &str = "/bootstrap/v1/mailboxes";
    demand(!path.contains('?'), "invalid")?;
    if completion && path == "/bootstrap/v1/activations" {
        return Ok(Route::Completion("POST"));
    }
    if completion && let Some(id) = path.strip_prefix("/bootstrap/v1/operations/") {
        demand(codec::ident(id, "link_"), "invalid")?;
        return Ok(Route::Completion("GET"));
    }
    if path == BASE {
        return Ok(Route::Create);
    }
    let Some(rest) = path.strip_prefix(&format!("{BASE}/")) else {
        return Err(Fault::Code("not_found"));
    };
    let (id, append) = rest
        .strip_suffix("/frames")
        .map(|v| (v, true))
        .unwrap_or((rest, false));
    demand(codec::digest(id), "invalid")?;
    if append {
        Ok(Route::Append(id.into()))
    } else {
        Ok(Route::Box(id.into()))
    }
}
fn prepare(
    r: &Head,
    kind: Route,
    body: &[u8],
    key: &str,
    window: Window,
    account: String,
) -> Wire<Operation> {
    let cap = r.cap.as_ref().map_err(|c| Fault::Code(c))?;
    match kind {
        Route::Completion(_) => Err(Fault::Internal),
        Route::Create => {
            let c: Creation = serde_json::from_slice(body).map_err(|_| Fault::Code("invalid"))?;
            demand(
                c.format == 1
                    && window.request_id(&c.request_id)
                    && codec::digest(&c.locator)
                    && codec::digest(&c.read_cap_hash),
                "invalid",
            )?;
            let f = Frame::read_in(c.frame.get().as_bytes(), window)?;
            demand(f.writer_host_public_key == key, "forbidden")?;
            demand(
                f.role == "request"
                    && f.request_id == c.request_id
                    && f.locator == c.locator
                    && f.created_at == c.created_at
                    && f.expires_at == c.expires_at,
                "invalid",
            )?;
            frame_window(&f, window)?;
            demand(
                same(&c.read_cap_hash, &codec::hash(cap.as_bytes())),
                "forbidden",
            )?;
            Ok(Operation::Create(Box::new(c), Box::new(f), account))
        }
        Route::Append(id) => {
            let a: Append = serde_json::from_slice(body).map_err(|_| Fault::Code("invalid"))?;
            let f = Frame::read_in(a.frame.get().as_bytes(), window)?;
            demand(f.writer_host_public_key == key, "forbidden")?;
            demand(f.locator == id, "invalid")?;
            frame_window(&f, window)?;
            Ok(Operation::Append(Box::new(f), cap.clone()))
        }
        Route::Box(id) => {
            demand(body.is_empty(), "invalid")?;
            if r.method == "GET" {
                Ok(Operation::Get(id, cap.clone()))
            } else {
                Ok(Operation::Delete(id, cap.clone()))
            }
        }
    }
}
impl ParticipantMailbox {
    /// The bearer read capability, then the optional resource credential: its
    /// account ID, or "" for anonymous resources.
    fn credential(&self, r: &Head) -> std::result::Result<String, &'static str> {
        match &self.operator {
            // A participant host has no operator credentials to accept.
            Operator::Participant => match &r.token {
                None => r.cap.clone().map(|_| String::new()),
                Some(Ok(_)) => Err("forbidden"),
                Some(Err(c)) => Err(c),
            },
            Operator::Helper(accounts) => {
                r.cap.clone()?;
                match (&r.token, accounts) {
                    (None, None) => Ok(String::new()),
                    (None, Some(_)) => Err("forbidden"),
                    (Some(Err(c)), _) => Err(c),
                    (Some(Ok(token)), accounts) => accounts
                        .as_ref()
                        .and_then(|a| a.get(token))
                        .cloned()
                        .ok_or("forbidden"),
                }
            }
        }
    }
    /// Takes one already authenticated TLS connection and no asserted identity.
    /// The caller owns listener admission, pre-handshake budgets and shutdown.
    pub async fn serve_connection(
        self: Arc<Self>,
        stream: TlsStream<TcpStream>,
    ) -> anyhow::Result<()> {
        let (socket, tls) = stream.get_ref();
        if tls.is_handshaking()
            || tls.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || tls.alpn_protocol() != Some(ALPN)
        {
            bail!("invalid participant transport");
        }
        let certificates = tls
            .peer_certificates()
            .filter(|c| c.len() == 1)
            .context("invalid participant transport")?;
        let peer =
            crate::peer::certificate_key(&certificates[0], rustls::pki_types::UnixTime::now())
                .map_err(|_| anyhow::anyhow!("invalid participant transport"))?;
        let key = codec::encode(&peer);
        if !codec::key(&key) {
            bail!("invalid participant transport");
        }
        let source = source(socket.peer_addr()?.ip());
        self.serve_stream(stream, key, source, false).await
    }
    pub(crate) async fn serve_completion<S>(
        self: Arc<Self>,
        stream: S,
        key: String,
        source: String,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        if !codec::key(&key) {
            bail!("invalid participant transport");
        }
        self.serve_stream(stream, key, source, true).await
    }
    async fn serve_stream<S>(
        self: Arc<Self>,
        stream: S,
        key: String,
        source: String,
        completion_only: bool,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let Some(_active) = self.active(&key, &source) else {
            return Ok(());
        };
        let mut reader = BufReader::with_capacity(16 << 10, stream);
        let header = timeout(Duration::from_secs(5), async {
            let mut header = Vec::with_capacity(1024);
            for _ in 0..(16 << 10) {
                let b = reader.read_u8().await?;
                header.push(b);
                if b == b'\n' && (header.len() < 2 || header[header.len() - 2] != b'\r') {
                    return Ok::<_, std::io::Error>(header);
                }
                if header.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Ok(header)
        })
        .await;
        let header = match header {
            Ok(Ok(h)) => h,
            _ => return Ok(()),
        };
        let get = header.starts_with(b"GET ")
            && !(self.completion.is_some() && header.starts_with(b"GET /bootstrap/v1/operations/"));
        let allowed = self
            .limits
            .lock()
            .map_err(|_| anyhow::anyhow!("participant resources unavailable"))?
            .allow(&key, &source, get);
        if !allowed {
            return respond(reader, Response::fault("rate_limited")).await;
        }
        let parsed = if header.ends_with(b"\r\n\r\n") {
            head(&header)
        } else {
            Err(Fault::Code("invalid"))
        };
        let r = match parsed {
            Ok(r) => r,
            Err(Fault::Code(c)) => return respond(reader, Response::fault(c)).await,
            Err(Fault::Internal) => bail!("participant resources unavailable"),
        };
        let selected_route = if completion_only {
            completion_route(&r.path)
        } else {
            route(&r.path, self.completion.is_some())
        };
        let kind = match selected_route {
            Ok(k) => k,
            Err(Fault::Code(c)) => return respond(reader, Response::fault(c)).await,
            Err(Fault::Internal) => bail!("participant resources unavailable"),
        };
        if completion_only && !matches!(kind, Route::Completion(_)) {
            return respond(reader, Response::fault("not_found")).await;
        }
        let allow = match &kind {
            Route::Box(_) => "GET, DELETE",
            Route::Completion(method) => method,
            _ => "POST",
        };
        if !((allow == "POST" && r.method == "POST")
            || (allow == "GET" && r.method == "GET")
            || (allow == "GET, DELETE" && matches!(r.method.as_str(), "GET" | "DELETE")))
        {
            let mut response = Response::fault("invalid");
            response.status = 405;
            response.allow = Some(allow);
            return respond(reader, response).await;
        }
        let completion = matches!(kind, Route::Completion(_));
        let mut account = String::new();
        if !completion {
            match self.credential(&r) {
                Ok(a) => account = a,
                Err(c) => return respond(reader, Response::fault(c)).await,
            }
        }
        if !account.is_empty() {
            let allowed = self
                .limits
                .lock()
                .map_err(|_| anyhow::anyhow!("participant resources unavailable"))?
                .allow_principals(&[format!("account:{account}")], get);
            if !allowed {
                return respond(reader, Response::fault("rate_limited")).await;
            }
        }
        if r.length
            > if completion {
                COMPLETION_MAX
            } else {
                MAX_FRAME_POST
            }
        {
            return respond(reader, Response::fault("quota_exceeded")).await;
        }
        if reader.buffer().len() > r.length {
            return respond(reader, Response::fault("invalid")).await;
        }
        let receive = match self.buffer(0, r.length) {
            Ok(b) => b,
            Err(Fault::Code(c)) => return respond(reader, Response::fault(c)).await,
            Err(Fault::Internal) => bail!("participant resources unavailable"),
        };
        let mut body = vec![0; r.length];
        if !matches!(
            timeout(Duration::from_secs(10), reader.read_exact(&mut body)).await,
            Ok(Ok(_))
        ) {
            return Ok(());
        }
        if !reader.buffer().is_empty() {
            return respond(reader, Response::fault("invalid")).await;
        }
        if completion {
            let callback = self
                .completion
                .clone()
                .context("participant completion unavailable")?;
            let response_buffer = match self.buffer(1, COMPLETION_MAX - 512) {
                Ok(b) => b,
                Err(Fault::Code(c)) => return respond(reader, Response::fault(c)).await,
                Err(Fault::Internal) => bail!("participant resources unavailable"),
            };
            let request = CompletionRequest {
                host_public_key: key,
                method: r.method,
                path: r.path,
                body,
            };
            // Dropping the socket's waiter does not release the processing or
            // byte slots while its owned controller future is still running.
            let result = tokio::spawn(async move {
                let result = callback.complete(request).await;
                (result, receive, response_buffer, _active)
            })
            .await
            .map_err(|_| anyhow::anyhow!("participant completion unavailable"))?;
            let (result, _receive, _response_buffer, _active) = result;
            let result =
                result.map_err(|_| anyhow::anyhow!("participant completion unavailable"))?;
            if !matches!(result.status, 200 | 400 | 403 | 404 | 409 | 410 | 429)
                || result.body.len() > COMPLETION_MAX
                || serde_json::from_slice::<Box<RawValue>>(&result.body).is_err()
            {
                bail!("invalid participant completion response");
            }
            return respond(
                reader,
                Response {
                    status: result.status,
                    limited: result.status == 429,
                    allow: None,
                    body: result.body,
                    _buffer: None,
                },
            )
            .await;
        }
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _receive = receive;
            let window = owner.operator.window();
            let result = prepare(&r, kind, &body, &key, window, account)
                .and_then(|op| owner.operation(op, &key, &source));
            if matches!(&result, Err(Fault::Internal)) {
                owner.unavailable.store(true, Ordering::Release);
            }
            // A cancelled socket task cannot release a processing slot while
            // its detached blocking worker still owns body/database work.
            (result, _active)
        })
        .await
        .map_err(|_| anyhow::anyhow!("participant resources unavailable"))?;
        let (result, _active) = result;
        match result {
            Ok(response) => respond(reader, response).await,
            Err(Fault::Code(c)) => respond(reader, Response::fault(c)).await,
            Err(Fault::Internal) => {
                self.unavailable.store(true, Ordering::Release);
                bail!("participant resources unavailable")
            }
        }
    }
}
async fn respond<S>(mut reader: BufReader<S>, r: Response) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let reason = match r.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let mut header = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        r.status,
        reason,
        r.body.len()
    );
    if let Some(allow) = r.allow {
        header.push_str(&format!("Allow: {allow}\r\n"));
    }
    if r.limited {
        header.push_str("Retry-After: 1\r\n");
    }
    header.push_str("\r\n");
    let _ = timeout(Duration::from_secs(10), async {
        reader.get_mut().write_all(header.as_bytes()).await?;
        reader.get_mut().write_all(&r.body).await?;
        reader.get_mut().shutdown().await
    })
    .await;
    Ok(())
}
