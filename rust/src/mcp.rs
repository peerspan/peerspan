//! A minimal MCP client over stdio (tools contract): the daemon starts a
//! shared server as a child process, speaks newline-delimited JSON-RPC 2.0
//! to it, and keeps one instance per agent, server, and profile for calls.
//! Snapshots use a short-lived instance of their own.
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{oneshot, watch},
};

/// The protocol version the client asks for.
pub const PROTOCOL: &str = "2025-06-18";
/// Negotiated versions this client accepts.
const SUPPORTED: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// An instance must finish `initialize` within this long.
pub const START_BOUND: Duration = Duration::from_secs(30);
/// A result larger than this, encoded, is not kept.
pub const MAX_RESULT: usize = 1_048_576;
/// Lines from a server longer than this are not parsed; only their ID is read.
const MAX_LINE: usize = 64 << 20;
/// A server's log keeps its last 1 MiB at each start.
const LOG_KEEP: u64 = 1 << 20;

/// How to start one server or profile instance.
#[derive(Clone, Debug)]
pub struct Launch {
    pub command: String,
    pub args: Vec<String>,
    /// The whole environment of the child, in order of precedence applied.
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub log: PathBuf,
}

/// A server's answer to one request.
#[derive(Debug)]
pub enum Reply {
    /// The result, and its canonical text with numbers as the server wrote
    /// them.
    Result(Value, String),
    Error {
        code: i64,
        message: String,
    },
    /// The result was larger than 1 MiB encoded.
    TooLarge,
}

type Waiters = Arc<Mutex<HashMap<u64, oneshot::Sender<Reply>>>>;

/// One running server process.
pub struct Client {
    stdin: tokio::sync::Mutex<ChildStdin>,
    pending: Waiters,
    next_id: AtomicU64,
    exited: watch::Receiver<bool>,
    child: Mutex<Option<Child>>,
    log: PathBuf,
}

/// Appends a note to a server's log.
pub fn note(log: &Path, text: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(log)
    {
        let _ = writeln!(
            file,
            "peerspan {}: {text}",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
    }
}

/// Opens a server's log for its new instance: mode 0600, truncated to its
/// last 1 MiB.
fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    use std::io::{Read, Seek, SeekFrom};
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    }
    if let Ok(mut file) = std::fs::File::open(path) {
        let len = file.metadata()?.len();
        if len > LOG_KEEP {
            file.seek(SeekFrom::Start(len - LOG_KEEP))?;
            let mut tail = Vec::new();
            file.read_to_end(&mut tail)?;
            std::fs::write(path, tail)?;
        }
    }
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(file)
}

/// One line from the server: whole, or too long to parse.
enum Line {
    Whole(Vec<u8>),
    Oversized(Vec<u8>),
}
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Line>> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(match (line.is_empty(), oversized) {
                (true, false) => None,
                (_, true) => Some(Line::Oversized(line)),
                (false, false) => Some(Line::Whole(line)),
            });
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        if !oversized {
            if line.len() + chunk.len() > MAX_LINE {
                oversized = true;
                // Keep a prefix, which holds the ID in the usual key order.
                line.truncate(4096);
                let keep = 4096usize.saturating_sub(line.len()).min(chunk.len());
                line.extend_from_slice(&chunk[..keep]);
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let consumed = newline.map_or(available.len(), |i| i + 1);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(if oversized {
                Line::Oversized(line)
            } else {
                Line::Whole(line)
            }));
        }
    }
}
/// Reads the request ID from the start of an oversized response.
fn prefix_id(prefix: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(prefix);
    let at = text.find("\"id\"")?;
    let rest = text[at + 4..].trim_start().strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

impl Client {
    /// Starts the process. It is killed when the client is dropped.
    pub fn spawn(launch: &Launch) -> anyhow::Result<Arc<Self>> {
        let log = open_log(&launch.log)?;
        let mut command = Command::new(&launch.command);
        command
            .args(&launch.args)
            .env_clear()
            .envs(launch.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&launch.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .kill_on_drop(true);
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("no stdout"))?;
        let (exit_tx, exited) = watch::channel(false);
        let pending: Waiters = Arc::default();
        let client = Arc::new(Self {
            stdin: tokio::sync::Mutex::new(stdin),
            pending: pending.clone(),
            next_id: AtomicU64::new(1),
            exited,
            child: Mutex::new(Some(child)),
            log: launch.log.clone(),
        });
        let weak = Arc::downgrade(&client);
        let log_path = launch.log.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::with_capacity(64 * 1024, stdout);
            loop {
                let line = match read_line(&mut reader).await {
                    Ok(Some(line)) => line,
                    _ => break,
                };
                let (id, reply) = match line {
                    Line::Oversized(prefix) => match prefix_id(&prefix) {
                        Some(id) => (id, Reply::TooLarge),
                        None => continue,
                    },
                    Line::Whole(bytes) => {
                        let Ok(message) = serde_json::from_slice::<Value>(&bytes) else {
                            continue;
                        };
                        if message.get("method").is_some() {
                            // A request from the server: answer pings, and
                            // refuse what this client does not offer.
                            if let (Some(id), Some(client)) =
                                (message.get("id").cloned(), weak.upgrade())
                            {
                                let answer = if message["method"] == "ping" {
                                    json!({"jsonrpc": "2.0", "id": id, "result": {}})
                                } else {
                                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}})
                                };
                                let _ = client.write(&answer).await;
                            }
                            continue;
                        }
                        let Some(id) = message.get("id").and_then(Value::as_u64) else {
                            continue;
                        };
                        let reply = if let Some(error) = message.get("error") {
                            Reply::Error {
                                code: error["code"].as_i64().unwrap_or(0),
                                message: error["message"].as_str().unwrap_or_default().to_owned(),
                            }
                        } else {
                            let result = message.get("result").cloned().unwrap_or(Value::Null);
                            match serde_json::to_vec(&result) {
                                Ok(encoded) if encoded.len() > MAX_RESULT => Reply::TooLarge,
                                _ => {
                                    let text = crate::canonical::member_text(&bytes, "result")
                                        .unwrap_or_else(|| crate::canonical::value_text(&result));
                                    Reply::Result(result, text)
                                }
                            }
                        };
                        (id, reply)
                    }
                };
                let waiter = pending.lock().ok().and_then(|mut p| p.remove(&id));
                match waiter {
                    Some(waiter) => {
                        let _ = waiter.send(reply);
                    }
                    None => note(
                        &log_path,
                        &format!(
                            "discarded a response to request {id}, which arrived after its call had ended"
                        ),
                    ),
                }
            }
            // Waiters see the instance end when their senders drop.
            if let Ok(mut p) = pending.lock() {
                p.clear();
            }
            let _ = exit_tx.send(true);
        });
        Ok(client)
    }
    async fn write(&self, message: &Value) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(message)?;
        line.push(b'\n');
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(&line).await?;
        stdin.flush().await
    }
    /// Sends a request; the receiver yields its reply, or fails when the
    /// instance ends first.
    pub async fn send(
        &self,
        method: &str,
        params: Value,
    ) -> std::io::Result<(u64, oneshot::Receiver<Reply>)> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id, tx);
        }
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        if let Err(e) = self.write(&message).await {
            self.forget(id);
            return Err(e);
        }
        Ok((id, rx))
    }
    /// Stops waiting for a request; a later response is discarded and noted.
    pub fn forget(&self, id: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&id);
        }
    }
    pub async fn notify(&self, method: &str, params: Value) -> std::io::Result<()> {
        self.write(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
            .await
    }
    /// Tells the server a request is cancelled.
    pub async fn cancel(&self, id: u64, reason: &str) {
        let _ = self
            .notify(
                "notifications/cancelled",
                json!({"requestId": id, "reason": reason}),
            )
            .await;
    }
    /// A request and its reply, or an error when the instance ends first.
    pub async fn request(&self, method: &str, params: Value) -> anyhow::Result<Reply> {
        let (_, rx) = self.send(method, params).await?;
        rx.await
            .map_err(|_| anyhow::anyhow!("the server exited before answering {method}"))
    }
    /// `initialize` and `notifications/initialized`. Returns the server's
    /// capabilities.
    pub async fn initialize(&self) -> anyhow::Result<Value> {
        let params = json!({
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "peerspan", "version": env!("CARGO_PKG_VERSION")},
        });
        let result = match self.request("initialize", params).await? {
            Reply::Result(result, _) => result,
            Reply::Error { code, message } => {
                anyhow::bail!("initialize failed: {code} {message}")
            }
            Reply::TooLarge => anyhow::bail!("initialize returned too much"),
        };
        let version = result["protocolVersion"].as_str().unwrap_or_default();
        if !SUPPORTED.contains(&version) {
            anyhow::bail!("the server negotiated unsupported protocol version {version:?}");
        }
        self.notify("notifications/initialized", json!({})).await?;
        Ok(result["capabilities"].clone())
    }
    pub fn has_exited(&self) -> bool {
        *self.exited.borrow()
    }
    /// Resolves once the process has ended.
    pub async fn wait_exit(&self) {
        let mut exited = self.exited.clone();
        let _ = exited.wait_for(|e| *e).await;
    }
    pub fn kill(&self) {
        if let Ok(mut child) = self.child.lock()
            && let Some(child) = child.as_mut()
        {
            let _ = child.start_kill();
        }
    }
    pub fn log(&self) -> &Path {
        &self.log
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Starts an instance and completes `initialize` within 30 seconds;
/// otherwise stops it.
pub async fn start(launch: &Launch) -> anyhow::Result<(Arc<Client>, Value)> {
    let client = Client::spawn(launch)?;
    match tokio::time::timeout(START_BOUND, client.initialize()).await {
        Ok(Ok(capabilities)) => Ok((client, capabilities)),
        Ok(Err(e)) => {
            client.kill();
            note(&launch.log, &format!("start failed: {e:#}"));
            Err(e)
        }
        Err(_) => {
            client.kill();
            note(
                &launch.log,
                "start failed: initialize did not finish within 30 seconds",
            );
            anyhow::bail!("initialize did not finish within 30 seconds")
        }
    }
}

/// Lists `method` (`tools/list` or `resources/list`), following
/// `nextCursor`. More than `limit` entries of `field` is the error
/// `too_many_entries`.
pub async fn list(
    client: &Client,
    method: &str,
    field: &str,
    limit: usize,
) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let result = match client.request(method, params).await? {
            Reply::Result(result, _) => result,
            Reply::Error { code, message } => anyhow::bail!("{method} failed: {code} {message}"),
            Reply::TooLarge => anyhow::bail!("{method} returned more than 1 MiB"),
        };
        for entry in result[field].as_array().into_iter().flatten() {
            if out.len() >= limit {
                anyhow::bail!("too_many_entries");
            }
            out.push(entry.clone());
        }
        match result["nextCursor"].as_str() {
            Some(next) if !next.is_empty() => cursor = Some(next.to_owned()),
            _ => return Ok(out),
        }
    }
}

/// One instance per agent, server, and profile (`""` for none).
pub type Key = (String, String, String);

/// Running instances and recent start failures.
#[derive(Default)]
pub struct Pool {
    slots: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<Option<Live>>>>>,
    failures: Mutex<HashMap<Key, Vec<Instant>>>,
}
#[derive(Clone)]
pub struct Live {
    pub client: Arc<Client>,
    pub used: Arc<Mutex<Instant>>,
    pub active: Arc<AtomicU64>,
}

/// A server that fails to start this many times within the window fails
/// its queued calls without another start.
const START_FAILURES: usize = 3;
const FAILURE_WINDOW: Duration = Duration::from_secs(600);
/// An instance with no calls for this long is stopped.
pub const IDLE_STOP: Duration = Duration::from_secs(600);

impl Pool {
    fn slot(&self, key: &Key) -> Arc<tokio::sync::Mutex<Option<Live>>> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots.entry(key.clone()).or_default().clone()
    }
    /// Whether the server has failed to start 3 times in 10 minutes.
    pub fn failing(&self, key: &Key) -> bool {
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let recent = failures.entry(key.clone()).or_default();
        recent.retain(|at| at.elapsed() < FAILURE_WINDOW);
        recent.len() >= START_FAILURES
    }
    /// The running instance, started on demand. Concurrent callers wait for
    /// one start.
    pub async fn instance(&self, key: &Key, launch: &Launch) -> anyhow::Result<Live> {
        let slot = self.slot(key);
        let mut guard = slot.lock().await;
        if let Some(live) = guard.as_ref()
            && !live.client.has_exited()
        {
            return Ok(live.clone());
        }
        *guard = None;
        match start(launch).await {
            Ok((client, _)) => {
                let live = Live {
                    client,
                    used: Arc::new(Mutex::new(Instant::now())),
                    active: Arc::default(),
                };
                *guard = Some(live.clone());
                Ok(live)
            }
            Err(e) => {
                let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
                failures
                    .entry(key.clone())
                    .or_default()
                    .push(Instant::now());
                Err(e)
            }
        }
    }
    /// Stops instances idle for 10 minutes, and forgets ended ones.
    pub fn reap(&self) {
        let slots: Vec<(Key, Arc<tokio::sync::Mutex<Option<Live>>>)> = {
            let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            slots.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (_, slot) in slots {
            let Ok(mut guard) = slot.try_lock() else {
                continue;
            };
            let stop = guard.as_ref().is_some_and(|live| {
                live.client.has_exited()
                    || (live.active.load(Ordering::Relaxed) == 0
                        && live
                            .used
                            .lock()
                            .map(|u| u.elapsed() >= IDLE_STOP)
                            .unwrap_or(false))
            });
            if stop && let Some(live) = guard.take() {
                live.client.kill();
            }
        }
    }
    /// Stops every instance of an agent's server, for example after its
    /// definition was dropped or changed.
    pub fn stop(&self, agent: &str, server: &str) {
        let slots: Vec<Arc<tokio::sync::Mutex<Option<Live>>>> = {
            let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            slots
                .iter()
                .filter(|((a, s, _), _)| a == agent && s == server)
                .map(|(_, v)| v.clone())
                .collect()
        };
        for slot in slots {
            if let Ok(mut guard) = slot.try_lock()
                && let Some(live) = guard.as_ref()
                && live.active.load(Ordering::Relaxed) == 0
            {
                live.client.kill();
                *guard = None;
            }
        }
    }
}
