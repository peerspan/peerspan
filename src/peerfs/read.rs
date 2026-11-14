//! Whole-branch reads for other hosts (PeerFS read contract, sections 3 to 5): the three
//! peer routes, served only on the authenticated peer router.
//!
//! Every `head` and `objects` request is authorized again: the cited policy must be the
//! binding owner's current one with a filesystem rule for the sender, the binding must be
//! registered with its pinned directory and provider intact, and the branch must exist.
//! A sender without a rule gets the same 404 whatever exists, and the provider is not
//! contacted for it.
use super::{
    Operation, Record, coded, directory, find, internal, invalid, not_found, provider, unavailable,
};
use crate::{
    api::blocking,
    decentralized::{self, product},
    model::Error,
    peer_store::valid_id,
    policy::{FS_READ_ACTION, FsRule, PolicyRef, peerfs_branch},
    quic::LongTransfer,
    store::Store,
};
use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{
        Path, RawQuery, State,
        rejection::{BytesRejection, PathRejection},
    },
    http::{HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use hyper::body::{Frame, SizeHint};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    pin::Pin,
    sync::{Arc, LazyLock, Mutex, atomic::AtomicBool},
    task::{Context, Poll},
    time::{Duration, Instant},
};

/// The bound of a `branches` or `head` request.
const LIST_BOUND: Duration = Duration::from_secs(5);
/// The bound of an `objects` request.
const OBJECTS_BOUND: Duration = Duration::from_secs(30);
/// The most object IDs one `objects` request names.
const MAX_IDS: usize = 256;
/// The largest `objects` answer.
pub(crate) const MAX_OBJECTS_ANSWER: usize = 16 << 20;
/// The most concurrent `objects` requests from one reader host.
const MAX_CONCURRENT: usize = 4;
/// The largest `head` or `objects` request body: 256 IDs of 66 digits, quoted, and the
/// policy, with room for whitespace.
const MAX_BODY: usize = 64 << 10;

pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/peer/v1/fs/branches", get(branches))
        .route(
            "/peer/v1/fs/spaces/{space}/branches/{branch}/head",
            post(head),
        )
        .route(
            "/peer/v1/fs/spaces/{space}/branches/{branch}/objects",
            post(objects),
        )
}

/// An operation bounded to `bound`, cancelled when the returned guard drops.
fn operation(bound: Duration) -> (Operation, super::Cancel) {
    let op = Operation(Arc::new(super::Deadline {
        at: Instant::now() + bound,
        cancelled: AtomicBool::new(false),
    }));
    (op.clone(), super::Cancel(op))
}

/// Runs `action` on a blocking worker within `op`'s deadline: past it, 503. A raw
/// database or OS error is never returned as such.
async fn within<T: Send + 'static>(
    store: Arc<Store>,
    op: Operation,
    action: impl FnOnce(&Store, &Operation) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let at = tokio::time::Instant::from_std(op.0.at);
    let worker = op.clone();
    let done = blocking(store, move |store| {
        worker.check()?;
        action(store, &worker)
    });
    match tokio::time::timeout_at(at, done).await {
        Err(_) => Err(unavailable()),
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error @ Error::Coded { .. })) => Err(error),
        Ok(Err(_)) => Err(internal()),
    }
}

/// The filesystem rules of this host's person's current policy in `network` that
/// `sender` may use (step 2 of section 3, before the cited version is compared), with
/// that policy's reference. `None` when the network is not one this host and the sender
/// share, the person has no current policy, or the sender is blocked.
fn readable(
    store: &Store,
    c: &Connection,
    network: &str,
    sender: &str,
) -> Result<Option<(PolicyRef, Vec<FsRule>)>, Error> {
    let me = store.identity().id;
    if sender == me || !product::is_decentralized(c, network)? {
        return Ok(None);
    }
    let Some(person) = store
        .product_member(c, network, &me)?
        .and_then(|m| m.person_id)
    else {
        return Ok(None);
    };
    // A sender whose membership lapsed matches only rules with `allow_disconnected`,
    // as the member it last was, as for runtime rules.
    let (sender_member, is_current) = match store.product_member(c, network, sender)? {
        Some(m) => (m, true),
        None => match store.product_lapsed_member(c, network, sender)? {
            Some(m) => (m, false),
            None => return Ok(None),
        },
    };
    let Some(key) = store.product_person_key(c, network, &person)? else {
        return Ok(None);
    };
    let Some(policy) = store.product_policy(c, network, &key)? else {
        return Ok(None);
    };
    if !policy.in_window(crate::clock::now()) {
        return Ok(None);
    }
    let groups = store.product_groups(c, network)?;
    let mut rules: Vec<FsRule> = policy
        .fs_rules()
        .iter()
        .filter(|rule| {
            rule.host == me
                && rule.actions.iter().any(|a| a == FS_READ_ACTION)
                && (is_current || rule.allow_disconnected)
                && rule
                    .principals
                    .iter()
                    .any(|p| product::principal_matches(p, &sender_member, &groups, None))
        })
        .cloned()
        .collect();
    if rules.iter().any(|rule| !rule.allow_disconnected)
        && !decentralized::peer::current_connected(c, store, sender)?
    {
        rules.retain(|rule| rule.allow_disconnected);
    }
    if rules.is_empty() || store.blocked(c, sender)? {
        return Ok(None);
    }
    Ok(Some((policy.reference(), rules)))
}

#[derive(Serialize)]
struct Entry {
    host: String,
    space: String,
    branch: String,
    policy: PolicyRef,
}

/// `GET /peer/v1/fs/branches?network=ID`: the branches the sender may read on this host
/// in that network, from the current policy and the bindings' states only.
async fn branches(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    RawQuery(query): RawQuery,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let network = match query.as_deref().and_then(|q| q.strip_prefix("network=")) {
        Some(id) if decentralized::codec::ident(id, "net_") => id.to_owned(),
        _ => return Err(invalid()),
    };
    if !input.map_err(|_| invalid())?.is_empty() {
        return Err(invalid());
    }
    let (op, _cancel) = operation(LIST_BOUND);
    let answer = network.clone();
    let entries = within(store, op, move |store, op| {
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        let Some((reference, rules)) = readable(store, &c, &network, &sender)? else {
            return Ok(Vec::new());
        };
        let host = store.identity().id;
        let mut entries = Vec::new();
        for rule in rules {
            let listed = find(&c, &rule.space)?.is_some_and(|record| {
                record.view.state == "registered" && record.view.network_id == network
            });
            if listed {
                entries.push(Entry {
                    host: host.clone(),
                    space: rule.space,
                    branch: rule.branch,
                    policy: reference.clone(),
                });
            }
        }
        entries.sort_by(|a, b| (&a.space, &a.branch).cmp(&(&b.space, &b.branch)));
        op.check()?;
        Ok(entries)
    })
    .await?;
    Ok(Json(json!({"network": answer, "branches": entries})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadRequest {
    policy: PolicyRef,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectsRequest {
    policy: PolicyRef,
    ids: Vec<String>,
}

/// A request body of exactly the stated fields; anything else is 400.
fn body<T: serde::de::DeserializeOwned>(input: Result<Bytes, BytesRejection>) -> Result<T, Error> {
    let input = input.map_err(|_| invalid())?;
    if input.len() > MAX_BODY {
        return Err(invalid());
    }
    let value = decentralized::codec::parse(&input, MAX_BODY).map_err(|_| invalid())?;
    serde_json::from_value(value).map_err(|_| invalid())
}

/// The space and branch of a route, and the cited policy, each well formed.
fn target(
    ids: Result<Path<(String, String)>, PathRejection>,
    policy: &PolicyRef,
) -> Result<(String, String), Error> {
    let Path((space, branch)) = ids.map_err(|_| invalid())?;
    if !valid_id(&space, "space", 16)
        || !peerfs_branch(&branch)
        || !crate::policy::person_id_shape(&policy.person_id)
    {
        return Err(invalid());
    }
    Ok((space, branch))
}

/// Steps 1 to 3 of section 3, up to contacting the provider: the binding, the sender's
/// rule in its owner's current policy, and the binding's state. 404 without a rule or a
/// binding; 503 for a rule whose binding is not registered or not this host's.
fn authorize(
    store: &Store,
    op: &Operation,
    sender: &str,
    space: &str,
    branch: &str,
    cited: &PolicyRef,
) -> Result<Record, Error> {
    let c = store.connection().map_err(|_| internal())?;
    op.check()?;
    let record = find(&c, space)?.ok_or_else(not_found)?;
    let allowed =
        readable(store, &c, &record.view.network_id, sender)?.is_some_and(|(reference, rules)| {
            reference == *cited
                && rules
                    .iter()
                    .any(|rule| rule.space == space && rule.branch == branch)
        });
    if !allowed {
        return Err(not_found());
    }
    if record.view.state != "registered" || record.current(store, &record.view.binding_id).is_err()
    {
        return Err(unavailable());
    }
    op.check()?;
    Ok(record)
}

/// The binding's pinned directory, unchanged; otherwise the space is not serving (503).
fn pinned(record: &Record, op: &Operation) -> Result<directory::Pinned, Error> {
    let dir = directory::open(&record.view.directory, true, op).map_err(|_| unavailable())?;
    dir.matches(record.stamp).map_err(|_| unavailable())?;
    Ok(dir)
}

/// `POST /peer/v1/fs/spaces/{space}/branches/{branch}/head`: the branch's current head.
async fn head(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    ids: Result<Path<(String, String)>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: HeadRequest = body(input)?;
    let (space, branch) = target(ids, &request.policy)?;
    let (op, _cancel) = operation(LIST_BOUND);
    within(store, op, move |store, op| {
        let record = authorize(store, op, &sender, &space, &branch, &request.policy)?;
        let dir = pinned(&record, op)?;
        let found = provider::head(&dir, &record.view, &branch, op).map_err(|_| unavailable())?;
        pinned(&record, op)?;
        let head = found.ok_or_else(not_found)?;
        Ok(Json(json!({"host": record.view.host_id, "space": space,
            "branch": branch, "head": head})))
    })
    .await
}

/// `POST /peer/v1/fs/spaces/{space}/branches/{branch}/objects`: the requested objects, if
/// the branch's current head reaches every one, as a PeerFS object batch of at most
/// 16 MiB holding the leading objects that fit.
async fn objects(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    long: Option<Extension<LongTransfer>>,
    ids: Result<Path<(String, String)>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Response, Error> {
    let request: ObjectsRequest = body(input)?;
    let (space, branch) = target(ids, &request.policy)?;
    let mut seen = HashSet::new();
    if request.ids.is_empty()
        || request.ids.len() > MAX_IDS
        || !request
            .ids
            .iter()
            .all(|id| provider::object_id(id).is_some() && seen.insert(id.as_str()))
    {
        return Err(invalid());
    }
    let slot = Slot::take(&store.identity().id, &sender).ok_or_else(|| {
        coded(
            429,
            "limit",
            "too many concurrent object requests from this host",
        )
    })?;
    // The request may outlast the transport's usual serve bound; OBJECTS_BOUND bounds
    // it here, and the transport bounds a stalled transfer of the answer.
    if let Some(Extension(long)) = long {
        long.allow();
    }
    let (op, _cancel) = operation(OBJECTS_BOUND);
    let batch = within(store, op, move |store, op| {
        let record = authorize(store, op, &sender, &space, &branch, &request.policy)?;
        let dir = pinned(&record, op)?;
        let fetched = provider::fetch(
            &dir,
            &record.view,
            &branch,
            &request.ids,
            MAX_OBJECTS_ANSWER,
            op,
        )
        .map_err(|_| unavailable())?;
        pinned(&record, op)?;
        match fetched {
            provider::Fetched::NotReached => Err(not_found()),
            provider::Fetched::Batch(batch) => Ok(batch),
        }
    })
    .await?;
    let length = batch.len();
    let mut response = Response::new(Body::new(Held {
        data: Some(Bytes::from(batch)),
        _slot: slot,
    }));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

/// Concurrent `objects` requests, by serving host and reader host.
static READERS: LazyLock<Mutex<HashMap<String, usize>>> = LazyLock::new(Default::default);
/// One of a reader host's concurrent `objects` requests, held until its answer is sent.
struct Slot(String);
impl Slot {
    fn take(host: &str, sender: &str) -> Option<Self> {
        let key = format!("{host}/{sender}");
        let mut readers = READERS.lock().ok()?;
        let count = readers.entry(key.clone()).or_default();
        if *count >= MAX_CONCURRENT {
            return None;
        }
        *count += 1;
        Some(Self(key))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Ok(mut readers) = READERS.lock()
            && let Some(count) = readers.get_mut(&self.0)
        {
            *count -= 1;
            if *count == 0 {
                readers.remove(&self.0);
            }
        }
    }
}

/// A complete answer body that keeps its request's [`Slot`] until it is sent or dropped.
struct Held {
    data: Option<Bytes>,
    _slot: Slot,
}
impl axum::body::HttpBody for Held {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
    }
    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, |d| d.len() as u64))
    }
}
