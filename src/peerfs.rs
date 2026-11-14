//! Owner-local PeerFS bindings and typed host signing (PF-1), and whole-branch reads
//! for other hosts on the peer router (PF-2, in `read`).
mod commit;
mod directory;
mod provider;
mod read;
mod reader;

pub(crate) use read::{MAX_OBJECTS_ANSWER, peer_routes};

use crate::{api::blocking, decentralized, model::Error, peer_store::valid_id, store::Store};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, Request, State,
        rejection::{BytesRejection, PathRejection},
    },
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE peerfs_bindings (
 space_id TEXT PRIMARY KEY NOT NULL,
 binding_id TEXT NOT NULL UNIQUE,
 network_id TEXT NOT NULL,
 context_id TEXT NOT NULL,
 host_id TEXT NOT NULL,
 public_key TEXT NOT NULL,
 directory TEXT NOT NULL,
 state TEXT NOT NULL CHECK (state IN ('prepared','registered','released')),
 created_at TEXT NOT NULL,
 device BLOB NOT NULL CHECK (length(device) = 8),
 inode BLOB NOT NULL CHECK (length(inode) = 8),
 uid INTEGER NOT NULL CHECK (uid BETWEEN 0 AND 4294967295)
);
CREATE UNIQUE INDEX peerfs_live_directory ON peerfs_bindings(directory) WHERE state != 'released';
CREATE UNIQUE INDEX peerfs_live_inode ON peerfs_bindings(device,inode) WHERE state != 'released';
";
const COLUMNS: &str = "space_id,binding_id,network_id,context_id,host_id,public_key,directory,state,created_at,device,inode,uid";
const BODY: usize = 8 << 10;
const SIGN_BODY: usize = 96 << 10;

fn coded(status: u16, code: &'static str, message: &'static str) -> Error {
    Error::Coded {
        status,
        code,
        message: message.into(),
        extra: Default::default(),
    }
}
fn invalid() -> Error {
    coded(400, "invalid", "invalid request")
}
fn forbidden() -> Error {
    coded(403, "forbidden", "forbidden")
}
fn not_found() -> Error {
    coded(404, "not_found", "not found")
}
fn conflict() -> Error {
    coded(409, "conflict", "conflict")
}
fn too_large() -> Error {
    coded(413, "too_large", "too large")
}
fn unavailable() -> Error {
    coded(503, "unavailable", "unavailable")
}
fn internal() -> Error {
    coded(500, "internal", "internal error")
}
fn db(error: rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            unavailable()
        }
        _ => internal(),
    }
}

// A commit must not wait in SQLite after its final cancellation/deadline
// check. The store guard isolates this temporary setting from other routes.
struct NoWait<'a> {
    connection: &'a Connection,
    prior_ms: u32,
}
impl<'a> NoWait<'a> {
    fn new(connection: &'a Connection) -> Result<Self, Error> {
        let prior_ms = connection
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .map_err(db)?;
        connection.busy_timeout(Duration::ZERO).map_err(db)?;
        Ok(Self {
            connection,
            prior_ms,
        })
    }
}
impl Drop for NoWait<'_> {
    fn drop(&mut self) {
        let _ = self
            .connection
            .busy_timeout(Duration::from_millis(u64::from(self.prior_ms)));
    }
}

#[derive(Clone)]
struct Operation(Arc<Deadline>);
struct Deadline {
    at: Instant,
    cancelled: AtomicBool,
}
impl Operation {
    fn check(&self) -> Result<(), Error> {
        if self.0.cancelled.load(Ordering::Acquire) || Instant::now() >= self.0.at {
            return Err(unavailable());
        }
        Ok(())
    }
}
struct Cancel(Operation);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.0.cancelled.store(true, Ordering::Release);
    }
}
async fn bounded(mut request: Request, next: Next) -> Response {
    let op = Operation(Arc::new(Deadline {
        at: Instant::now() + Duration::from_secs(5),
        cancelled: AtomicBool::new(false),
    }));
    let _cancel = Cancel(op.clone());
    if request.uri().query().is_some() {
        return invalid().into_response();
    }
    request.extensions_mut().insert(op.clone());
    match tokio::time::timeout_at(tokio::time::Instant::from_std(op.0.at), next.run(request)).await
    {
        Ok(response) => response,
        Err(_) => unavailable().into_response(),
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/fs/spaces", get(list).post(prepare))
        .route("/v1/fs/spaces/{space_id}", get(inspect))
        .route("/v1/fs/spaces/{space_id}/release", post(release))
        .route("/v1/fs/spaces/{space_id}/activate", post(activate))
        .route("/v1/fs/spaces/{space_id}/host-keys/check", post(host_keys))
        .route("/v1/fs/spaces/{space_id}/branches/{branch}", get(branch))
        .route("/v1/fs/shares", get(shares))
        .route(
            "/v1/fs/spaces/{space_id}/sign-commit",
            post(sign).layer(DefaultBodyLimit::max(SIGN_BODY)),
        )
        .layer(DefaultBodyLimit::max(BODY))
        .layer(middleware::from_fn(bounded))
        .merge(reader::local_routes())
}
fn body(input: Result<Bytes, BytesRejection>) -> Result<Bytes, Error> {
    input.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            too_large()
        } else {
            invalid()
        }
    })
}
fn decode<T: DeserializeOwned>(
    input: Result<Bytes, BytesRejection>,
    limit: usize,
) -> Result<T, Error> {
    let input = body(input)?;
    if input.len() > limit {
        return Err(too_large());
    }
    let value = decentralized::codec::parse(&input, limit).map_err(|_| invalid())?;
    serde_json::from_value(value).map_err(|_| invalid())
}
fn no_body(input: Result<Bytes, BytesRejection>) -> Result<(), Error> {
    if !body(input)?.is_empty() {
        return Err(invalid());
    }
    Ok(())
}
fn path(input: Result<Path<String>, PathRejection>) -> Result<String, Error> {
    let Path(id) = input.map_err(|_| invalid())?;
    if !valid_id(&id, "space", 16) {
        return Err(invalid());
    }
    Ok(id)
}
async fn run<T: Send + 'static>(
    store: Arc<Store>,
    op: Operation,
    action: impl FnOnce(&Store, &Operation) -> Result<T, Error> + Send + 'static,
) -> Result<Json<T>, Error> {
    blocking(store, move |store| {
        op.check()?;
        action(store, &op)
    })
    .await
    .map(Json)
    .map_err(|error| match error {
        Error::Coded { .. } => error,
        _ => internal(), // Never route a raw SQLite/OS exception to logging.
    })
}
#[derive(Clone, Serialize)]
struct View {
    format: u8,
    space_id: String,
    binding_id: String,
    network_id: String,
    context_id: String,
    host_id: String,
    public_key: String,
    directory: String,
    state: String,
    created_at: String,
}
struct Record {
    view: View,
    stamp: directory::Stamp,
}
impl Record {
    fn validate(&self) -> Result<(), Error> {
        let v = &self.view;
        let valid = v.format == 1
            && valid_id(&v.space_id, "space", 16)
            && valid_id(&v.binding_id, "fsbind", 16)
            && decentralized::codec::ident(&v.network_id, "net_")
            && decentralized::codec::ident(&v.context_id, "ctx_")
            && decentralized::codec::key(&v.public_key)
            && STANDARD
                .decode(&v.public_key)
                .is_ok_and(|key| crate::peer_store::key_id(&key) == v.host_id)
            && directory::syntax(&v.directory).is_ok()
            && matches!(v.state.as_str(), "prepared" | "registered" | "released")
            && decentralized::codec::stamp(&v.created_at).is_ok()
            && self.stamp.uid == directory::uid();
        if !valid {
            return Err(internal());
        }
        Ok(())
    }
    fn current(&self, store: &Store, binding: &str) -> Result<(), Error> {
        self.validate()?;
        let identity = store.identity();
        if self.view.binding_id != binding
            || self.view.state == "released"
            || self.view.host_id != identity.id
            || self.view.public_key != identity.public_key
        {
            return Err(conflict());
        }
        Ok(())
    }
}
fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    let device: Vec<u8> = row.get(9)?;
    let inode: Vec<u8> = row.get(10)?;
    Ok(Record {
        view: View {
            format: 1,
            space_id: row.get(0)?,
            binding_id: row.get(1)?,
            network_id: row.get(2)?,
            context_id: row.get(3)?,
            host_id: row.get(4)?,
            public_key: row.get(5)?,
            directory: row.get(6)?,
            state: row.get(7)?,
            created_at: row.get(8)?,
        },
        stamp: directory::Stamp {
            device: u64::from_be_bytes(
                device
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            ),
            inode: u64::from_be_bytes(
                inode
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            ),
            uid: row.get(11)?,
        },
    })
}
fn find(c: &Connection, space: &str) -> Result<Option<Record>, Error> {
    let found = c
        .query_row(
            &format!("SELECT {COLUMNS} FROM peerfs_bindings WHERE space_id=?1"),
            [space],
            row,
        )
        .optional()
        .map_err(db)?;
    if let Some(record) = &found {
        record.validate()?;
    }
    Ok(found)
}
fn load(c: &Connection, space: &str) -> Result<Record, Error> {
    find(c, space)?.ok_or_else(not_found)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    space_id: String,
    network_id: String,
    context_id: String,
    directory: String,
}
impl Prepare {
    fn validate(&self) -> Result<(), Error> {
        if !valid_id(&self.space_id, "space", 16)
            || !decentralized::codec::ident(&self.network_id, "net_")
            || !decentralized::codec::ident(&self.context_id, "ctx_")
        {
            return Err(invalid());
        }
        directory::syntax(&self.directory)
    }
    fn same(&self, record: &Record) -> Result<View, Error> {
        if self.network_id != record.view.network_id
            || self.context_id != record.view.context_id
            || self.directory != record.view.directory
        {
            return Err(conflict());
        }
        Ok(record.view.clone())
    }
}
async fn prepare(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    input: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<View>), Error> {
    let request: Prepare = decode(input, BODY)?;
    request.validate()?;
    let Json((created, view)) =
        run(store, op, move |store, op| prepare_in(store, op, request)).await?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(view),
    ))
}
fn prepare_in(store: &Store, op: &Operation, request: Prepare) -> Result<(bool, View), Error> {
    {
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        if let Some(record) = find(&c, &request.space_id)? {
            return Ok((false, request.same(&record)?));
        }
    }
    // No database guard/transaction while traversing or reading a directory.
    let directory = directory::open(&request.directory, false, op)?;
    directory.empty(op)?;
    let identity = store.identity();
    let c = store.connection().map_err(|_| internal())?;
    op.check()?;
    let _no_wait = NoWait::new(&c)?;
    let tx = c.unchecked_transaction().map_err(db)?;
    if let Some(record) = find(&tx, &request.space_id)? {
        return Ok((false, request.same(&record)?));
    }
    let used: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM peerfs_bindings WHERE state!='released' AND (directory=?1 OR (device=?2 AND inode=?3)))",
        params![request.directory, directory.stamp.device.to_be_bytes().as_slice(), directory.stamp.inode.to_be_bytes().as_slice()],
        |r| r.get(0),
    ).map_err(db)?;
    if used {
        return Err(conflict());
    }
    let count: u32 = tx
        .query_row(
            "SELECT count(*) FROM peerfs_bindings WHERE state!='released'",
            [],
            |r| r.get(0),
        )
        .map_err(db)?;
    if count >= 256 {
        let mut error = coded(429, "limit", "limit exceeded");
        if let Error::Coded { extra, .. } = &mut error {
            extra.insert("limit".into(), json!("fs_spaces"));
        }
        return Err(error);
    }
    // Only public authority is read; no signer, repair, guard write or contacts.
    let snapshot =
        decentralized::Snapshot::load_public(&tx, &request.network_id, &identity.public_key)
            .map_err(|_| forbidden())?;
    if snapshot.network.context_id != request.context_id
        || snapshot
            .migrations
            .iter()
            .any(|m| m.fenced && m.state != "adopted")
    {
        return Err(forbidden());
    }
    // Eligibility is current after waiting for the store and loading its
    // retained public authority, not at admission to the blocking worker.
    let now = decentralized::local_decision_time().map_err(|_| unavailable())?;
    let projection = snapshot.project(&now).map_err(|_| forbidden())?;
    projection
        .active(projection.root_state_id().map_err(|_| forbidden())?)
        .map_err(|_| forbidden())?;
    if !projection
        .members()
        .map_err(|_| forbidden())?
        .iter()
        .any(|m| m.host_public_key == identity.public_key)
    {
        return Err(forbidden());
    }
    let binding = crate::store::new_id("fsbind").map_err(|_| internal())?;
    let view = View {
        format: 1,
        space_id: request.space_id,
        binding_id: binding,
        network_id: request.network_id,
        context_id: request.context_id,
        host_id: identity.id,
        public_key: identity.public_key,
        directory: request.directory,
        state: "prepared".into(),
        created_at: now,
    };
    op.check()?;
    tx.execute(
        "INSERT INTO peerfs_bindings VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            view.space_id,
            view.binding_id,
            view.network_id,
            view.context_id,
            view.host_id,
            view.public_key,
            view.directory,
            view.state,
            view.created_at,
            directory.stamp.device.to_be_bytes().as_slice(),
            directory.stamp.inode.to_be_bytes().as_slice(),
            directory.stamp.uid,
        ],
    )
    .map_err(db)?;
    op.check()?;
    tx.commit().map_err(db)?;
    Ok((true, view))
}
async fn list(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Vec<View>>, Error> {
    no_body(input)?;
    run(store, op, |store, op| {
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        let mut query = c.prepare(&format!("SELECT {COLUMNS} FROM peerfs_bindings WHERE state!='released' ORDER BY space_id LIMIT 257")).map_err(db)?;
        let mut views = Vec::new();
        for record in query.query_map([], row).map_err(db)? {
            let record = record.map_err(db)?;
            record.validate()?;
            views.push(record.view);
        }
        if views.len() > 256 { return Err(internal()); }
        op.check()?;
        Ok(views)
    }).await
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    id: Result<Path<String>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<View>, Error> {
    let id = path(id)?;
    no_body(input)?;
    run(store, op, move |store, op| {
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        Ok(load(&c, &id)?.view)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    binding_id: String,
}
fn binding(id: &str) -> Result<(), Error> {
    if valid_id(id, "fsbind", 16) {
        Ok(())
    } else {
        Err(invalid())
    }
}
async fn release(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    id: Result<Path<String>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<View>, Error> {
    let id = path(id)?;
    let request: Binding = decode(input, BODY)?;
    binding(&request.binding_id)?;
    run(store, op, move |store, op| {
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        let _no_wait = NoWait::new(&c)?;
        let tx = c.unchecked_transaction().map_err(db)?;
        let mut record = load(&tx, &id)?;
        if record.view.binding_id != request.binding_id {
            return Err(conflict());
        }
        if record.view.state != "released" {
            op.check()?;
            tx.execute(
                "UPDATE peerfs_bindings SET state='released' WHERE space_id=?1",
                [&id],
            )
            .map_err(db)?;
            op.check()?;
            tx.commit().map_err(db)?;
            record.view.state = "released".into();
        }
        Ok(record.view)
    })
    .await
}
/// Verifies the space's running provider and marks a prepared binding registered. The
/// probe runs with no database transaction held; the binding and directory are checked
/// again afterwards, so a release or change meanwhile prevents the transition.
async fn activate(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    id: Result<Path<String>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let id = path(id)?;
    let request: Binding = decode(input, BODY)?;
    binding(&request.binding_id)?;
    run(store, op, move |store, op| {
        let record = {
            let c = store.connection().map_err(|_| internal())?;
            op.check()?;
            let record = load(&c, &id)?;
            record.current(store, &request.binding_id)?;
            record
        };
        let pinned = directory::open(&record.view.directory, true, op)?;
        pinned.matches(record.stamp)?;
        provider::probe(&pinned, &record.view, op)?;
        let observed_at = decentralized::local_decision_time().map_err(|_| unavailable())?;
        // The directory must still be the pinned one after the probe.
        directory::open(&record.view.directory, true, op)?.matches(record.stamp)?;
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        let _no_wait = NoWait::new(&c)?;
        let tx = c.unchecked_transaction().map_err(db)?;
        let mut current = load(&tx, &id)?;
        current.current(store, &request.binding_id)?;
        if current.stamp.device != record.stamp.device || current.stamp.inode != record.stamp.inode
        {
            return Err(conflict());
        }
        if current.view.state == "prepared" {
            op.check()?;
            tx.execute(
                "UPDATE peerfs_bindings SET state='registered' WHERE space_id=?1 AND state='prepared'",
                [&id],
            )
            .map_err(db)?;
            op.check()?;
            tx.commit().map_err(db)?;
            current.view.state = "registered".into();
        }
        Ok(json!({"registration": current.view,
            "provider": {"state": "verified", "observed_at": observed_at}}))
    })
    .await
}
/// A registered binding's branch as its running provider reports it, for `fs share`'s
/// review (PeerFS read contract, section 7). Read-only: the directory must be the pinned
/// one and the provider must pass activation's identity check; it is never started.
async fn branch(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    ids: Result<Path<(String, String)>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let Path((id, name)) = ids.map_err(|_| invalid())?;
    if !valid_id(&id, "space", 16) || !crate::policy::peerfs_branch(&name) {
        return Err(invalid());
    }
    no_body(input)?;
    run(store, op, move |store, op| {
        let record = {
            let c = store.connection().map_err(|_| internal())?;
            op.check()?;
            load(&c, &id)?
        };
        record.current(store, &record.view.binding_id)?;
        if record.view.state != "registered" {
            return Err(conflict());
        }
        let pinned = directory::open(&record.view.directory, true, op)?;
        pinned.matches(record.stamp)?;
        let found = provider::branch(&pinned, &record.view, &name, op)?.ok_or_else(not_found)?;
        directory::open(&record.view.directory, true, op)?.matches(record.stamp)?;
        Ok(
            json!({"space_id": record.view.space_id, "binding_id": record.view.binding_id,
            "network_id": record.view.network_id, "branch": name, "head": found.head,
            "commits": found.commits}),
        )
    })
    .await
}
/// This host's filesystem rules in its person's current policy of each coordinator-free
/// network, by network ID, each with `network_id` and the policy it is in.
async fn shares(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Vec<Value>>, Error> {
    no_body(input)?;
    run(store, op, |store, op| {
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        let own = store.identity().id;
        let mut out = Vec::new();
        for (network, member) in store
            .decentralized_own_members(&c)
            .map_err(|_| internal())?
        {
            let Some(person) = member.person_id else {
                continue;
            };
            let Some(key) = store
                .product_person_key(&c, &network, &person)
                .map_err(|_| internal())?
            else {
                continue;
            };
            let Some(policy) = store
                .product_policy(&c, &network, &key)
                .map_err(|_| internal())?
            else {
                continue;
            };
            for rule in policy.fs_rules().iter().filter(|r| r.host == own) {
                let mut value = serde_json::to_value(rule).map_err(|_| internal())?;
                value["network_id"] = network.clone().into();
                value["policy"] =
                    serde_json::to_value(policy.reference()).map_err(|_| internal())?;
                out.push(value);
            }
        }
        op.check()?;
        Ok(out)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyCheck {
    binding_id: String,
    host_id: String,
    public_key: String,
}
/// Whether a commit's author host and signing key are a recognized identity: the local
/// host's, or one the binding's pinned context retains a verified admission of. Identity
/// history only, offline and read-only; it says nothing about current access.
async fn host_keys(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    id: Result<Path<String>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let id = path(id)?;
    let request: KeyCheck = decode(input, BODY)?;
    binding(&request.binding_id)?;
    if !valid_id(&request.host_id, "host", 32) || !decentralized::codec::key(&request.public_key) {
        return Err(invalid());
    }
    let hashes = STANDARD
        .decode(&request.public_key)
        .is_ok_and(|key| crate::peer_store::key_id(&key) == request.host_id);
    run(store, op, move |store, op| {
        let answer = |recognized: bool| {
            json!({"host_id": request.host_id, "public_key": request.public_key,
                "recognized": recognized})
        };
        let first = {
            let c = store.connection().map_err(|_| internal())?;
            op.check()?;
            let record = load(&c, &id)?;
            record.current(store, &request.binding_id)?;
            record
        };
        // As for signing and activation, a binding whose directory was replaced or made
        // public is refused. Filesystem IO first, with no transaction held.
        directory::open(&first.view.directory, true, op)?.matches(first.stamp)?;
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        // One read view of the binding and the retained authority.
        let tx = c.unchecked_transaction().map_err(db)?;
        let record = load(&tx, &id)?;
        record.current(store, &request.binding_id)?;
        if record.stamp.device != first.stamp.device || record.stamp.inode != first.stamp.inode {
            return Err(conflict());
        }
        if !hashes {
            return Ok(answer(false));
        }
        let identity = store.identity();
        if request.public_key == identity.public_key {
            return Ok(answer(true));
        }
        let snapshot = decentralized::Snapshot::load_public(
            &tx,
            &record.view.network_id,
            &identity.public_key,
        )
        .map_err(|_| conflict())?;
        if snapshot.network.context_id != record.view.context_id {
            return Err(conflict());
        }
        let now = decentralized::local_decision_time().map_err(|_| unavailable())?;
        let projection = snapshot.project(&now).map_err(|_| conflict())?;
        op.check()?;
        let recognized = projection
            .host_key_admitted(&request.public_key)
            .map_err(|_| conflict())?;
        Ok(answer(recognized))
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sign {
    binding_id: String,
    message_base64: String,
}
async fn sign(
    State(store): State<Arc<Store>>,
    Extension(op): Extension<Operation>,
    id: Result<Path<String>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let id = path(id)?;
    let request: Sign = decode(input, SIGN_BODY)?;
    binding(&request.binding_id)?;
    run(store, op, move |store, op| {
        let record = {
            let c = store.connection().map_err(|_| internal())?;
            op.check()?;
            let record = load(&c, &id)?;
            record.current(store, &request.binding_id)?;
            record
        };
        let message = commit::message(&request.message_base64, &record.view.host_id)?;
        let directory = directory::open(&record.view.directory, true, op)?;
        directory.matches(record.stamp)?;
        let c = store.connection().map_err(|_| internal())?;
        op.check()?;
        let current = load(&c, &id)?;
        current.current(store, &request.binding_id)?;
        op.check()?;
        // The same store guard serializes the final live-binding check and
        // pure key use with release. No file/provider/agent/network callback.
        let signature = store.signing_key.sign(&message);
        op.check()?;
        Ok(
            json!({"host_id":current.view.host_id,"public_key":current.view.public_key,
            "signature":STANDARD.encode(signature.to_bytes())}),
        )
    })
    .await
}

/// Namespace/schema checks are transactional; malformed current state is not repaired.
pub(crate) fn check_namespace(c: &Connection) -> anyhow::Result<()> {
    let count: i64 = c.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'peerfs_*'",
        [],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        count == 0,
        "reserved PeerFS namespace exists before schema31"
    );
    Ok(())
}
pub(crate) fn check_schema(c: &Connection) -> anyhow::Result<()> {
    let normalize = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    for (name, expected) in [
        "peerfs_bindings",
        "peerfs_live_directory",
        "peerfs_live_inode",
    ]
    .iter()
    .zip(SCHEMA.split(';').filter(|s| !s.trim().is_empty()))
    {
        let sql: Option<String> = c
            .query_row("SELECT sql FROM sqlite_schema WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|_| anyhow::anyhow!("invalid PeerFS binding schema"))?;
        anyhow::ensure!(
            sql.is_some_and(|sql| normalize(&sql) == normalize(expected)),
            "invalid PeerFS binding schema"
        );
    }
    let objects: i64 = c.query_row("SELECT count(*) FROM sqlite_schema WHERE name GLOB 'peerfs_*' OR (tbl_name='peerfs_bindings' AND type IN ('trigger','index') AND sql IS NOT NULL)", [], |r| r.get(0))?;
    anyhow::ensure!(objects == 3, "unexpected PeerFS binding schema object");
    let mut query = c.prepare(&format!("SELECT {COLUMNS} FROM peerfs_bindings"))?;
    let mut live = 0;
    for record in query.query_map([], row)? {
        let record = record.map_err(|_| anyhow::anyhow!("invalid PeerFS binding row"))?;
        record
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid PeerFS binding row"))?;
        if record.view.state != "released" {
            live += 1;
        }
    }
    anyhow::ensure!(live <= 256, "invalid PeerFS binding count");
    Ok(())
}
pub(crate) fn check_identity(
    c: &Connection,
    identity: &crate::model::Identity,
) -> anyhow::Result<()> {
    let count: i64 = c.query_row(
        "SELECT count(*) FROM peerfs_bindings WHERE host_id!=?1 OR public_key!=?2",
        params![identity.id, identity.public_key],
        |r| r.get(0),
    )?;
    anyhow::ensure!(count == 0, "PeerFS binding host identity mismatch");
    Ok(())
}
