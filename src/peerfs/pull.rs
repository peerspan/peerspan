//! The owner's cross-host pull (PeerFS pull contract, sections 2 to 4 and 6): brings a
//! branch another host shares with this one into one of this host's registered spaces.
//!
//! The host does not import objects itself (PF-07). For one pull it serves, on a private
//! socket, the three calls a PeerFS pull makes of its source, answering them from the
//! sharing host's PF-2 peer routes, and asks the destination's own provider to pull from
//! that socket; PeerFS checks every object and signature and writes the tracking
//! reference last.
use super::{
    Deadline, Operation, Record, conflict, decode, directory, find, internal, invalid, not_found,
    provider, reader, unavailable,
};
use crate::{
    api::blocking,
    decentralized,
    model::Error,
    peer_store::{Peer, valid_id},
    policy::{PolicyRef, peerfs_branch},
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Request, State, rejection::BytesRejection},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, LazyLock, Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};

/// The bound of the sharing host's `head` answer, connecting included.
const HEAD_BOUND: Duration = Duration::from_secs(10);
/// The bound of one of the sharing host's `objects` answers: its 30 seconds, and the
/// transfer of up to 16 MiB.
const OBJECTS_BOUND: Duration = Duration::from_secs(90);
/// The bound of the checks before anything is fetched.
const CHECK_BOUND: Duration = Duration::from_secs(5);
/// A pull has no overall time bound; its operation outlives any real pull.
const NO_BOUND: Duration = Duration::from_secs(365 * 24 * 3600);
/// The default byte bound of one pull (PF-11).
const DEFAULT_MAX_BYTES: u64 = 1 << 30;
/// The most object IDs one fetch names, as PeerFS asks.
const MAX_IDS: usize = 256;
/// How often a fetch asks again after the sharing host's 429, and how long it waits.
const BUSY_ATTEMPTS: u32 = 10;
const BUSY_PAUSE: Duration = Duration::from_millis(500);
/// The largest request body the proxy reads: 256 quoted IDs and some whitespace.
const MAX_FETCH_BODY: usize = 64 << 10;
/// The longest Unix socket path.
const MAX_SOCKET_PATH: usize = 107;

/// The owner-local route of `fs pull`; never on the peer router.
pub(super) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/fs/pulls", post(pull))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PullRequest {
    peer: String,
    space: String,
    branch: String,
    into: String,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    max_bytes: Option<u64>,
}

fn message(status: u16, code: &'static str, text: impl Into<String>) -> Error {
    Error::Coded {
        status,
        code,
        message: text.into(),
        extra: Default::default(),
    }
}
fn remote(text: impl Into<String>) -> Error {
    message(502, "remote", text)
}
fn too_large() -> Error {
    message(507, "too_large", "the pull reached its byte bound")
}

/// An operation ending at `bound` from now, cancelled when the returned guard drops.
fn operation(bound: Duration) -> (Operation, super::Cancel) {
    let op = Operation(Arc::new(Deadline {
        at: Instant::now() + bound,
        cancelled: AtomicBool::new(false),
    }));
    (op.clone(), super::Cancel(op))
}

/// Pulls running, by host, destination, sharing host, space and branch.
static RUNNING: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Default::default);
/// One running pull, held until the destination's provider has answered.
struct Running(String);
impl Running {
    fn take(key: String) -> Option<Self> {
        let mut running = RUNNING.lock().ok()?;
        running.insert(key.clone()).then_some(Self(key))
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Ok(mut running) = RUNNING.lock() {
            running.remove(&self.0);
        }
    }
}

/// Owner-local `POST /v1/fs/pulls` with `{peer, space, branch, into, network?,
/// max_bytes?}`: pulls `(space, branch)` shared by `peer` into the registered space
/// `into` as `<peer>:<space>/<branch>`. Dropping the request ends the pull.
async fn pull(
    State(store): State<Arc<Store>>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: PullRequest = decode(input, super::BODY)?;
    let valid = valid_id(&request.peer, "host", 32)
        && request.peer != store.identity().id
        && valid_id(&request.space, "space", 16)
        && peerfs_branch(&request.branch)
        && valid_id(&request.into, "space", 16)
        && request
            .network
            .as_deref()
            .is_none_or(|n| decentralized::codec::ident(n, "net_"))
        && request.max_bytes.is_none_or(|n| n > 0);
    if !valid {
        return Err(invalid());
    }
    let max_bytes = request.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);

    // 1. The destination: registered here, in the share's network, its directory the
    // pinned one and its provider passing activation's identity check.
    let (check, _check_cancel) = operation(CHECK_BOUND);
    let (into, wanted) = (request.into.clone(), request.network.clone());
    let (record, dir) = blocking(store.clone(), move |store| {
        destination(store, &into, wanted.as_deref(), &check)
    })
    .await
    .map_err(|e| match e {
        Error::Coded { .. } => e,
        _ => internal(),
    })?;
    let network = record.view.network_id.clone();

    // 2. The sharing host lists the branch for this host.
    let (peer, entries) = reader::discover(&store, &request.peer, &network)
        .await
        .map_err(from_discovery)?;
    let entry = entries
        .into_iter()
        .find(|e| e.space == request.space && e.branch == request.branch)
        .ok_or_else(not_found)?;

    // 3. One pull of this shared branch into this space at a time.
    let key = format!(
        "{}/{}/{}/{}/{}",
        store.identity().id,
        request.into,
        request.peer,
        request.space,
        request.branch
    );
    let running = Running::take(key).ok_or_else(|| {
        message(
            409,
            "conflict",
            "another pull of this branch into this space is running",
        )
    })?;

    // 4. The target: the branch's head now, selected once.
    let head = select_head(&store, &peer, &request, &entry.policy).await?;
    let tracking_remote = format!("{}:{}", request.peer, request.space);

    // 5. The proxy, and the destination's provider pulling from it.
    let proxy = Proxy::start(
        &store,
        Source {
            store: store.clone(),
            peer,
            space: request.space.clone(),
            branch: request.branch.clone(),
            policy: entry.policy,
            head: head.clone(),
            remote: tracking_remote.clone(),
            max_bytes,
            state: Mutex::default(),
        },
    )?;
    let (op, _cancel) = operation(NO_BOUND);
    let (from, branch) = (proxy.socket.clone(), request.branch.clone());
    let pulled = blocking(store.clone(), move |_| {
        let _running = running;
        provider::pull(&dir, &record.view, &from, &branch, &op)
    })
    .await;
    let served = proxy.source.state.lock().map(|s| s.clone()).ok();
    drop(proxy);
    let served = served.ok_or_else(internal)?;
    if let Some(failure) = served.failure {
        return Err(failure.error());
    }
    let answer = match pulled {
        Err(error @ Error::Coded { .. }) => return Err(error),
        Err(_) => return Err(internal()),
        Ok(provider::Pulled::Refused {
            status,
            code,
            message: text,
        }) => return Err(refused(status, &code, &text)),
        Ok(provider::Pulled::Done(answer)) => answer,
    };
    if answer.remote != tracking_remote || answer.branch != request.branch || answer.head != head {
        return Err(remote(
            "the destination's provider reported another pull than the one asked",
        ));
    }
    let tracking = format!("{tracking_remote}/{}", request.branch);

    // 6. Recorded as activity.
    let subject = format!("{}/{tracking}", request.into);
    blocking(store.clone(), move |store| {
        let mut c = store.connection()?;
        let tx = c.transaction()?;
        append_event(&tx, "fs.pulled", &subject, &now())?;
        tx.commit()?;
        Ok(())
    })
    .await
    .map_err(|_| internal())?;
    Ok(Json(json!({
        "peer": request.peer,
        "space": request.space,
        "branch": request.branch,
        "into": request.into,
        "tracking": tracking,
        "head": head,
        "objects": served.objects,
        "bytes": served.bytes,
    })))
}

/// The destination's binding and its pinned directory: registered on this host (404
/// without a binding, 409 prepared or released), in `network` when one is named (409
/// otherwise), its directory the pinned one (409) and its provider passing activation's
/// identity check (503 unreachable, 409 another provider).
fn destination(
    store: &Store,
    space: &str,
    network: Option<&str>,
    op: &Operation,
) -> Result<(Record, directory::Pinned), Error> {
    let record = {
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        find(&c, space)?.ok_or_else(not_found)?
    };
    record.current(store, &record.view.binding_id)?;
    if record.view.state != "registered" || network.is_some_and(|n| n != record.view.network_id) {
        return Err(conflict());
    }
    let dir = directory::open(&record.view.directory, true, op)?;
    dir.matches(record.stamp)?;
    provider::probe(&dir, &record.view, op).map_err(|e| match e {
        Error::Coded { status: 403, .. } => unavailable(),
        other => other,
    })?;
    op.check()?;
    Ok((record, dir))
}

/// A discovery failure in section 6's terms: the sharing host unknown is 404, no answer
/// or a 503/429 refusal is 503, any other refusal or a malformed answer is 502.
fn from_discovery(error: Error) -> Error {
    match error {
        Error::Coded {
            status: 502, extra, ..
        } => match extra.get("peer_status").and_then(Value::as_u64) {
            Some(503 | 429) => unavailable(),
            _ => remote("the sharing host's discovery answer was refused or malformed"),
        },
        other => other,
    }
}

/// The sharing host's answer to a refused request, in section 6's terms.
fn peer_refusal(status: u16) -> Error {
    match status {
        404 => not_found(),
        429 | 503 => unavailable(),
        _ => remote("the sharing host refused the request"),
    }
}

/// The destination provider's refusal of its pull, in section 6's terms: a verification
/// failure (`remote`, or `forbidden` for a key the host does not recognize) is 502, the
/// host's key check or the provider unavailable 503.
fn refused(status: u16, code: &str, text: &str) -> Error {
    let text = format!("the destination's PeerFS pull failed: {text} ({code})");
    match status {
        400 | 403 | 404 | 409 | 502 => remote(text),
        _ => message(503, "unavailable", text),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadAnswer {
    host: String,
    space: String,
    branch: String,
    head: String,
}

/// The branch's current head on the sharing host, citing `policy`.
async fn select_head(
    store: &Arc<Store>,
    peer: &Peer,
    request: &PullRequest,
    policy: &PolicyRef,
) -> Result<String, Error> {
    let path = format!(
        "/peer/v1/fs/spaces/{}/branches/{}/head",
        request.space,
        provider::segment(&request.branch)
    );
    let body = serde_json::to_vec(&json!({"policy": policy})).map_err(|_| internal())?;
    let (status, data) = match tokio::time::timeout(
        HEAD_BOUND,
        crate::quic::request(store.clone(), peer, "POST", &path, &body),
    )
    .await
    {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) | Err(_) => return Err(unavailable()),
    };
    if status != 200 {
        return Err(peer_refusal(status));
    }
    let answer: HeadAnswer = serde_json::from_slice(&data)
        .map_err(|_| remote("the sharing host's head answer is malformed"))?;
    if answer.host != request.peer
        || answer.space != request.space
        || answer.branch != request.branch
        || provider::object_id(&answer.head).is_none()
    {
        return Err(remote("the sharing host's head answer is malformed"));
    }
    Ok(answer.head)
}

/// Why the proxy stopped serving: the pull's outcome, whatever the provider reports.
#[derive(Clone, Copy)]
enum Failure {
    TooLarge,
    NotFound,
    Unavailable,
    Remote,
}
impl Failure {
    fn error(self) -> Error {
        match self {
            Self::TooLarge => too_large(),
            Self::NotFound => not_found(),
            Self::Unavailable => unavailable(),
            Self::Remote => remote("the sharing host's objects answer is malformed"),
        }
    }
    fn response(self) -> Response {
        let (status, code, text) = match self {
            Self::TooLarge => (507, "too_large", "the pull reached its byte bound"),
            Self::NotFound => (
                404,
                "not_found",
                "the sharing host no longer serves these objects",
            ),
            Self::Unavailable => (503, "unavailable", "the sharing host is unavailable"),
            Self::Remote => (502, "remote", "the sharing host's answer is malformed"),
        };
        answer_error(status, code, text)
    }
}

/// A PeerFS error response.
fn answer_error(status: u16, code: &str, text: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(json!({"code": code, "error": text}))).into_response()
}

/// What the proxy served so far.
#[derive(Clone, Default)]
struct Served {
    /// Objects handed to the provider.
    objects: u64,
    /// Bytes of the sharing host's `objects` answers.
    bytes: u64,
    failure: Option<Failure>,
}

/// The shared branch a proxy serves, and what it served.
struct Source {
    store: Arc<Store>,
    peer: Peer,
    space: String,
    branch: String,
    policy: PolicyRef,
    head: String,
    remote: String,
    max_bytes: u64,
    state: Mutex<Served>,
}
impl Source {
    fn state(&self) -> std::sync::MutexGuard<'_, Served> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One pull's proxy: a private directory in the state directory holding its socket,
/// both removed, and every connection ended, when it drops.
struct Proxy {
    directory: PathBuf,
    socket: String,
    source: Arc<Source>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Proxy {
    fn start(store: &Store, source: Source) -> Result<Self, Error> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|_| internal())?;
        let directory = store
            .state_directory()
            .join(format!("pull-{}", hex::encode(random)));
        let path = directory.join("s.sock");
        let socket = path.to_str().ok_or_else(unavailable)?.to_owned();
        if socket.len() > MAX_SOCKET_PATH {
            return Err(message(
                503,
                "unavailable",
                "the state directory's path is too long for the pull's socket",
            ));
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| internal())?;
        let source = Arc::new(source);
        let bound = (|| {
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            Ok::<_, std::io::Error>(listener)
        })();
        let listener = match bound {
            Ok(listener) => listener,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&directory);
                return Err(internal());
            }
        };
        let task = tokio::spawn(accept(listener, source.clone(), directory::uid()));
        Ok(Self {
            directory,
            socket,
            source,
            task,
        })
    }
}

/// Serves connections from this account only (`SO_PEERCRED`); others are closed
/// unanswered. Aborting this task ends every connection it serves.
async fn accept(listener: tokio::net::UnixListener, source: Arc<Source>, uid: u32) {
    let router = Router::new().fallback(serve).with_state(source);
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                };
                if !stream.peer_cred().is_ok_and(|c| c.uid() == uid) {
                    continue;
                }
                let service = TowerToHyperService::new(router.clone());
                connections.spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Exactly the three calls of a PeerFS pull's source; anything else is 404.
async fn serve(State(source): State<Arc<Source>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some() {
        return answer_error(404, "not_found", "not found");
    }
    match (&parts.method, parts.uri.path()) {
        (&Method::GET, "/v1/space") => Json(json!({
            "path": format!("peerspan:{}/{}", source.peer.id, source.space),
            "host": source.remote,
            "objects": 0,
            "key": source.peer.public_key,
        }))
        .into_response(),
        (&Method::GET, "/v1/branches") => {
            Json(json!([{"name": source.branch, "head": source.head}])).into_response()
        }
        (&Method::POST, "/v1/objects/fetch") => {
            match axum::body::to_bytes(body, MAX_FETCH_BODY).await {
                Ok(body) => fetch(&source, &body).await,
                Err(_) => answer_error(400, "invalid", "invalid request"),
            }
        }
        _ => answer_error(404, "not_found", "not found"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    ids: Vec<String>,
}

/// `POST /v1/objects/fetch` with `{ids}`: every requested object, from the sharing
/// host's `objects` route, in one PeerFS object batch in the order asked. The sharing
/// host answers only the leading objects that fit 16 MiB, so the rest are asked for
/// again until all are held.
///
/// When the pull stops part way (its byte bound reached, or the sharing host failing),
/// the objects already held are still handed over, so PeerFS keeps the blobs it checks
/// before it fails on the first missing one and a later pull resumes from them; the
/// pull's outcome is the recorded failure.
async fn fetch(source: &Source, body: &[u8]) -> Response {
    let Ok(request) = serde_json::from_slice::<FetchRequest>(body) else {
        return answer_error(400, "invalid", "invalid request");
    };
    let mut seen = HashSet::new();
    let wanted: Option<Vec<[u8; provider::OBJECT_ID]>> = request
        .ids
        .iter()
        .map(|id| provider::object_id(id).filter(|_| seen.insert(id.as_str())))
        .collect();
    let Some(wanted) = wanted.filter(|w| !w.is_empty() && w.len() <= MAX_IDS) else {
        return answer_error(400, "invalid", "invalid request");
    };
    let path = format!(
        "/peer/v1/fs/spaces/{}/branches/{}/objects",
        source.space,
        provider::segment(&source.branch)
    );
    let mut answers: Vec<(Vec<u8>, Vec<std::ops::Range<usize>>)> = Vec::new();
    let mut next = 0;
    let mut stopped = None;
    while next < wanted.len() {
        {
            let state = source.state();
            if let Some(failure) = state.failure {
                stopped = Some(failure);
                break;
            }
            if state.bytes > source.max_bytes {
                stopped = Some(Failure::TooLarge);
                break;
            }
        }
        let body = match serde_json::to_vec(&json!({
            "policy": source.policy,
            "ids": &request.ids[next..],
        })) {
            Ok(body) => body,
            Err(_) => return answer_error(500, "internal", "internal error"),
        };
        let data = match ask_objects(source, &path, &body).await {
            Ok(data) => data,
            Err(failure) => {
                stopped = Some(failure);
                break;
            }
        };
        let Some(ranges) = provider::split_batch(&data, &wanted[next..]) else {
            stopped = Some(Failure::Remote);
            break;
        };
        next += ranges.len();
        answers.push((data, ranges));
        let mut state = source.state();
        state.bytes = state
            .bytes
            .saturating_add(answers.last().map_or(0, |a| a.0.len()) as u64);
        if state.bytes > source.max_bytes {
            stopped = Some(Failure::TooLarge);
            break;
        }
    }
    if let Some(failure) = stopped {
        let failure = *source.state().failure.get_or_insert(failure);
        if answers.is_empty() {
            return failure.response();
        }
    }
    let entries: Vec<&[u8]> = answers
        .iter()
        .flat_map(|(data, ranges)| ranges.iter().map(|r| &data[r.clone()]))
        .collect();
    let batch = provider::join_batch(&entries);
    source.state().objects += entries.len() as u64;
    let length = batch.len();
    let mut response = Response::new(Body::from(batch));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    response
}

/// One `objects` request to the sharing host within [`OBJECTS_BOUND`], asked again a
/// few times after a 429.
async fn ask_objects(source: &Source, path: &str, body: &[u8]) -> Result<Vec<u8>, Failure> {
    for attempt in 1..=BUSY_ATTEMPTS {
        let asked = tokio::time::timeout(
            OBJECTS_BOUND,
            crate::quic::request(source.store.clone(), &source.peer, "POST", path, body),
        )
        .await;
        let (status, data) = match asked {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => return Err(Failure::Unavailable),
        };
        match status {
            200 => return Ok(data),
            429 if attempt < BUSY_ATTEMPTS => tokio::time::sleep(BUSY_PAUSE).await,
            404 => return Err(Failure::NotFound),
            429 | 503 => return Err(Failure::Unavailable),
            _ => return Err(Failure::Remote),
        }
    }
    Err(Failure::Unavailable)
}
