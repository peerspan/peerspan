//! Streamable HTTP sessions with remote MCP servers (capabilities slice 3):
//! each JSON-RPC message is a `POST` to the server's URL, answered with JSON
//! or an event stream. The session carries the definition's headers, an
//! OAuth token when the source signed in, the negotiated protocol version,
//! and `MCP-Session-Id` once the server sets one.
use crate::{
    http_client::{self, BodyError, Failure, Url},
    mcp::{self, HttpFail, HttpKind, RemoteLaunch, Reply, TokenMode, Tokens},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{oneshot, watch};

/// Protocol versions accepted from a remote server.
pub const VERSIONS: [&str; 3] = ["2025-03-26", "2025-06-18", "2025-11-25"];
/// A body, or the part of an event stream read for one response, is read
/// up to this many bytes.
pub const BODY_LIMIT: usize = 2 << 20;

/// Definition headers the session sets itself, never sent from the
/// definition.
const RESERVED: [&str; 6] = [
    "content-type",
    "accept",
    "content-length",
    "host",
    "mcp-protocol-version",
    "mcp-session-id",
];

type Waiters = Arc<Mutex<HashMap<u64, oneshot::Sender<Reply>>>>;

pub struct Session {
    url: Url,
    headers: Vec<(String, String)>,
    tokens: Option<Tokens>,
    version: Mutex<Option<String>>,
    session: Mutex<Option<String>>,
    log: PathBuf,
    exit: watch::Sender<bool>,
    tasks: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    ended: AtomicBool,
    me: Mutex<std::sync::Weak<Session>>,
    /// The token of the latest request, for the closing `DELETE`, which
    /// never refreshes.
    last_token: Mutex<Option<String>>,
}

/// One POST's outcome.
enum Posted {
    Reply(Reply),
    /// A notification's answer, unread.
    Done,
}

impl Session {
    pub fn new(
        remote: &RemoteLaunch,
        log: PathBuf,
        exit: watch::Sender<bool>,
    ) -> anyhow::Result<Self> {
        let url = http_client::parse_url(&remote.url)
            .ok_or_else(|| anyhow::anyhow!("the server's URL is not usable"))?;
        let headers = remote
            .headers
            .iter()
            .filter(|(n, _)| !RESERVED.contains(&n.to_ascii_lowercase().as_str()))
            .cloned()
            .collect();
        Ok(Self {
            url,
            headers,
            tokens: remote.tokens.clone(),
            version: Mutex::new(None),
            session: Mutex::new(None),
            log,
            exit,
            tasks: Mutex::default(),
            ended: AtomicBool::new(false),
            me: Mutex::new(std::sync::Weak::new()),
            last_token: Mutex::new(None),
        })
    }
    fn note(&self, text: &str) {
        mcp::note(&self.log, text);
    }
    pub fn set_version(&self, version: &str) {
        if let Ok(mut v) = self.version.lock() {
            *v = Some(version.to_owned());
        }
    }
    fn session_id(&self) -> Option<String> {
        self.session.lock().ok().and_then(|s| s.clone())
    }
    /// Sends a request in its own task; its reply goes to its waiter.
    pub fn spawn_request(
        self: &Arc<Self>,
        id: u64,
        method: String,
        params: Value,
        pending: Waiters,
    ) {
        if let Ok(mut me) = self.me.lock() {
            *me = Arc::downgrade(self);
        }
        let session = self.clone();
        let task = tokio::spawn(async move {
            let reply = session.request(id, &method, params).await;
            session.forget_task(id);
            let waiter = pending.lock().ok().and_then(|mut p| p.remove(&id));
            match waiter {
                Some(waiter) => {
                    let _ = waiter.send(reply);
                }
                None => session.note(&format!(
                    "discarded a response to request {id}, which arrived after its call had ended"
                )),
            }
            // A session the server ended takes its other requests with it,
            // once this answer is delivered: their waiters see the end.
            if session.ended.load(Ordering::SeqCst)
                && let Ok(mut tasks) = session.tasks.lock()
            {
                for (_, task) in tasks.drain() {
                    task.abort();
                }
            }
        });
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.insert(id, task.abort_handle());
        }
    }
    fn forget_task(&self, id: u64) {
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.remove(&id);
        }
    }
    /// Stops reading a request's answer.
    pub fn abandon(&self, id: u64) {
        if let Ok(mut tasks) = self.tasks.lock()
            && let Some(task) = tasks.remove(&id)
        {
            task.abort();
        }
    }
    /// Ends the session: a `DELETE` with its ID, when it has one.
    pub fn end(&self) {
        if self.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.exit.send(true);
        // Outstanding requests end with the session, so none keeps holding
        // a credential's refresh lock.
        if let Ok(mut tasks) = self.tasks.lock() {
            for (_, task) in tasks.drain() {
                task.abort();
            }
        }
        let Some(id) = self.session_id() else {
            return;
        };
        let url = self.url.clone();
        let mut headers = self.base_headers();
        headers.push(("MCP-Session-Id".into(), id));
        if let Some(token) = self.last_token.lock().ok().and_then(|t| t.clone()) {
            headers.push(("Authorization".into(), format!("Bearer {token}")));
        }
        let log = self.log.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                // Bounded, as Go's: a server that never answers cannot keep
                // the task and its socket alive.
                let delete = http_client::send("DELETE", &url, &headers, None);
                match tokio::time::timeout(std::time::Duration::from_secs(5), delete).await {
                    Ok(Ok(r)) => mcp::note(&log, &format!("ended the session: HTTP {}", r.status)),
                    Ok(Err(e)) => mcp::note(&log, &format!("ending the session failed: {e}")),
                    Err(_) => mcp::note(&log, "ending the session got no answer within 5 seconds"),
                }
            });
        }
    }
    fn base_headers(&self) -> Vec<(String, String)> {
        let mut headers = self.headers.clone();
        if let Some(v) = self.version.lock().ok().and_then(|v| v.clone()) {
            headers.push(("MCP-Protocol-Version".into(), v));
        }
        headers
    }
    /// Posts a notification; its answer is not read. The whole exchange,
    /// the token included, is bounded by 10 seconds, so a server that never
    /// answers cannot hold a cancelled call's slot.
    pub async fn notify(&self, message: &Value) {
        let exchange = async {
            let token = match &self.tokens {
                Some(tokens) => match tokens(TokenMode::Use).await {
                    Ok(t) => t,
                    Err(_) => return,
                },
                None => None,
            };
            if let Err(e) = self.post(message, token.as_deref(), None).await {
                self.note(&format!("a notification failed: {}", e.detail));
            }
        };
        if tokio::time::timeout(std::time::Duration::from_secs(10), exchange)
            .await
            .is_err()
        {
            self.note("a notification got no answer within 10 seconds");
        }
    }

    /// Sends one request: refreshing the token first as needed, and for
    /// `initialize`, `tools/list`, and `resources/list` once more after a
    /// 401 with a refreshed token.
    async fn request(&self, id: u64, method: &str, params: Value) -> Reply {
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let retryable = matches!(method, "initialize" | "tools/list" | "resources/list");
        let mut mode = TokenMode::Use;
        for attempt in 0..2 {
            let token = match &self.tokens {
                Some(tokens) => match tokens(mode.clone()).await {
                    Ok(token) => token,
                    Err(_) => {
                        return Reply::Http(HttpFail {
                            kind: HttpKind::LoginRequired,
                            status: None,
                            authenticate: None,
                            detail: "the sign-in has lapsed".into(),
                        });
                    }
                },
                None => None,
            };
            match self.post(&message, token.as_deref(), Some(id)).await {
                Ok(Posted::Reply(reply)) => return reply,
                Ok(Posted::Done) => {
                    return Reply::Http(HttpFail {
                        kind: HttpKind::Failed,
                        status: None,
                        authenticate: None,
                        detail: "no response".into(),
                    });
                }
                Err(fail) if fail.kind == HttpKind::Unauthorized => {
                    if let (Some(tokens), Some(_)) = (&self.tokens, &token) {
                        if retryable && attempt == 0 {
                            self.note("the server refused the token; refreshing it once");
                            mode = TokenMode::Force(token.clone());
                            continue;
                        }
                        let _ = tokens(if retryable {
                            TokenMode::Lapse(token.clone())
                        } else {
                            TokenMode::Mark(token.clone())
                        })
                        .await;
                    }
                    return Reply::Http(fail);
                }
                Err(fail) => return Reply::Http(fail),
            }
        }
        unreachable!("the loop returns")
    }

    /// One POST of a message, and its answer.
    async fn post(
        &self,
        message: &Value,
        token: Option<&str>,
        id: Option<u64>,
    ) -> Result<Posted, HttpFail> {
        let initialize = message["method"] == "initialize";
        let mut headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            (
                "Accept".to_owned(),
                "application/json, text/event-stream".to_owned(),
            ),
        ];
        headers.extend(self.headers.iter().cloned());
        if let Some(token) = token {
            headers.push(("Authorization".into(), format!("Bearer {token}")));
            if let Ok(mut last) = self.last_token.lock() {
                *last = Some(token.to_owned());
            }
        }
        if !initialize && let Some(v) = self.version.lock().ok().and_then(|v| v.clone()) {
            headers.push(("MCP-Protocol-Version".into(), v));
        }
        let session = self.session_id();
        if let Some(sid) = &session {
            headers.push(("MCP-Session-Id".into(), sid.clone()));
        }
        let body = serde_json::to_vec(message).unwrap_or_default();
        let fail = |kind, status, authenticate, detail: String| HttpFail {
            kind,
            status,
            authenticate,
            detail,
        };
        let mut response = match http_client::send("POST", &self.url, &headers, Some(body)).await {
            Ok(r) => r,
            Err(Failure::Connect(e)) => {
                self.note(&format!("could not connect: {e}"));
                return Err(fail(
                    HttpKind::Connect,
                    None,
                    None,
                    format!("could not connect: {e}"),
                ));
            }
            Err(Failure::Lost(e)) => {
                self.note(&format!("the connection was lost: {e}"));
                return Err(fail(
                    HttpKind::Lost,
                    None,
                    None,
                    format!("the connection was lost: {e}"),
                ));
            }
        };
        let status = response.status;
        let authenticate = response.header("www-authenticate");
        if !(200..300).contains(&status) {
            self.note(&format!(
                "{} answered HTTP {status}",
                message["method"].as_str().unwrap_or("a message")
            ));
            let kind = match status {
                401 => HttpKind::Unauthorized,
                403 if authenticate
                    .as_deref()
                    .and_then(http_client::bearer_challenge)
                    .is_some_and(|p| {
                        p.iter()
                            .any(|(k, v)| k == "error" && v == "insufficient_scope")
                    }) =>
                {
                    HttpKind::InsufficientScope
                }
                404 if session.is_some() => {
                    self.note("the server ended the session");
                    if let Ok(mut s) = self.session.lock() {
                        *s = None;
                    }
                    self.ended.store(true, Ordering::SeqCst);
                    let _ = self.exit.send(true);
                    HttpKind::SessionGone
                }
                500..=599 => HttpKind::ServerError,
                _ => HttpKind::Failed,
            };
            return Err(fail(
                kind,
                Some(status),
                authenticate,
                format!("HTTP {status}"),
            ));
        }
        if initialize && let Some(sid) = response.header("mcp-session-id") {
            self.note("the server started a session");
            if let Ok(mut s) = self.session.lock() {
                *s = Some(sid);
            }
        }
        let Some(id) = id else {
            return Ok(Posted::Done);
        };
        let content_type = response
            .header("content-type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let unreadable = |detail: &str| Err(fail(HttpKind::Failed, None, None, detail.to_owned()));
        if content_type.starts_with("application/json") {
            let bytes = match http_client::read_body(&mut response.body, BODY_LIMIT).await {
                Ok(b) => b,
                Err(BodyError::TooLarge) => return Ok(Posted::Reply(Reply::TooLarge)),
                Err(BodyError::Lost(e)) => {
                    return Err(fail(
                        HttpKind::Lost,
                        None,
                        None,
                        format!("the connection was lost: {e}"),
                    ));
                }
            };
            return match response_of(&bytes, id) {
                Some(reply) => Ok(Posted::Reply(reply)),
                None => unreadable("the answer was not a JSON-RPC response"),
            };
        }
        if content_type.starts_with("text/event-stream") {
            return self.read_stream(&mut response.body, id).await;
        }
        unreadable("the answer had an unexpected content type")
    }

    /// Reads an event stream until the event holding the response to `id`.
    async fn read_stream(
        &self,
        body: &mut hyper::body::Incoming,
        id: u64,
    ) -> Result<Posted, HttpFail> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut total = 0usize;
        loop {
            // Each complete event in the buffer.
            while let Some((end, skip)) = event_end(&buffer) {
                let event: Vec<u8> = buffer.drain(..end + skip).take(end).collect();
                let data = event_data(&event);
                if data.is_empty() {
                    continue;
                }
                let Ok(message) = serde_json::from_slice::<Value>(data.as_bytes()) else {
                    self.note("dropped an event that was not JSON");
                    continue;
                };
                if message.get("method").is_some() {
                    if let Some(rid) = message.get("id").cloned().filter(|v| !v.is_null()) {
                        let answer = if message["method"] == "ping" {
                            json!({"jsonrpc": "2.0", "id": rid, "result": {}})
                        } else {
                            json!({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})
                        };
                        self.answer_server(answer);
                    } else {
                        self.note("dropped a notification from the server");
                    }
                    continue;
                }
                if message.get("id").and_then(Value::as_u64) == Some(id) {
                    return match response_of(data.as_bytes(), id) {
                        Some(reply) => Ok(Posted::Reply(reply)),
                        None => Err(HttpFail {
                            kind: HttpKind::Failed,
                            status: None,
                            authenticate: None,
                            detail: "the answer was not a JSON-RPC response".into(),
                        }),
                    };
                }
                self.note("dropped an event for another request");
            }
            match http_client::next_chunk(body).await {
                Ok(Some(chunk)) => {
                    total += chunk.len();
                    if total > BODY_LIMIT {
                        return Ok(Posted::Reply(Reply::TooLarge));
                    }
                    buffer.extend_from_slice(&chunk);
                }
                Ok(None) => {
                    return Err(HttpFail {
                        kind: HttpKind::Lost,
                        status: None,
                        authenticate: None,
                        detail: "the event stream ended before the response".into(),
                    });
                }
                Err(e) => {
                    let detail = match e {
                        BodyError::Lost(e) => e,
                        BodyError::TooLarge => "too large".into(),
                    };
                    return Err(HttpFail {
                        kind: HttpKind::Lost,
                        status: None,
                        authenticate: None,
                        detail: format!("the connection was lost: {detail}"),
                    });
                }
            }
        }
    }

    /// Answers a request the server sent on a stream, in a POST of its own.
    fn answer_server(&self, answer: Value) {
        let Some(me) = self.me.lock().ok().and_then(|m| m.upgrade()) else {
            return;
        };
        tokio::spawn(async move {
            me.notify(&answer).await;
        });
    }
}

/// Where the first event in a buffer ends: its length, and the separator's.
fn event_end(buffer: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buffer.len() {
        if buffer[i..].starts_with(b"\r\n\r\n") {
            return Some((i, 4));
        }
        if buffer[i..].starts_with(b"\n\n") || buffer[i..].starts_with(b"\r\r") {
            return Some((i, 2));
        }
        i += 1;
    }
    None
}
/// The `data:` lines of an event, joined with `\n`.
fn event_data(event: &[u8]) -> String {
    let text = String::from_utf8_lossy(event);
    text.split(['\n'])
        .map(|l| l.trim_end_matches('\r'))
        .filter_map(|l| l.strip_prefix("data:"))
        .map(|d| d.strip_prefix(' ').unwrap_or(d))
        .collect::<Vec<_>>()
        .join("\n")
}
/// A JSON-RPC response to `id` as a reply.
fn response_of(bytes: &[u8], id: u64) -> Option<Reply> {
    let message: Value = serde_json::from_slice(bytes).ok()?;
    if message.get("id").and_then(Value::as_u64) != Some(id) {
        return None;
    }
    if let Some(error) = message.get("error") {
        return Some(Reply::Error {
            code: error["code"].as_i64().unwrap_or(0),
            message: error["message"].as_str().unwrap_or_default().to_owned(),
        });
    }
    let result = message.get("result")?.clone();
    match serde_json::to_vec(&result) {
        Ok(encoded) if encoded.len() > mcp::MAX_RESULT => Some(Reply::TooLarge),
        _ => {
            let text = crate::canonical::member_text(bytes, "result")
                .unwrap_or_else(|| crate::canonical::value_text(&result));
            Some(Reply::Result(result, text))
        }
    }
}
