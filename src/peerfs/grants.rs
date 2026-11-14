//! Agents' pull grants (PeerFS pull contract, section 5; PF-10): which of this host's
//! agents may pull into which of its spaces, and each pull's byte bound.
//!
//! Grants live only on this host, in `fs-pull-grants.json` (mode 0600) in the state
//! directory: never in the database or in signed policy, so holding the person key does
//! not let another machine allow an agent here. The file is written whole (a temporary
//! file, fsync, rename) and read strictly; a file that is not a regular file owned by
//! this account with mode 0600, or whose content does not parse, holds no grants.
use super::{BODY, decode, find, internal, invalid, pull};
use crate::{
    adapter::{authority, token},
    adapter_connection::AdapterAuth,
    api::blocking,
    model::Error,
    peer_store::valid_id,
    store::{Store, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Path, State,
        rejection::{BytesRejection, PathRejection},
    },
    http::HeaderMap,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
};

/// The grants file's name in the state directory.
const FILE: &str = "fs-pull-grants.json";
/// The most grants this host holds.
const MAX_GRANTS: usize = 256;
/// The largest grants file read: 256 grants of under 300 bytes each.
const MAX_FILE: u64 = 128 << 10;
/// The grants file's format.
const FORMAT: u32 = 1;

/// Serializes the owner's changes to the file.
static WRITING: Mutex<()> = Mutex::new(());

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    agent_id: String,
    space: String,
    max_bytes: u64,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grants {
    format: u32,
    grants: Vec<Grant>,
}

fn coded(status: u16, code: &'static str, text: impl Into<String>) -> Error {
    Error::Coded {
        status,
        code,
        message: text.into(),
        extra: Default::default(),
    }
}

fn path(store: &Store) -> PathBuf {
    store.state_directory().join(FILE)
}

/// This host's grants, or why the file holds none. A missing file holds none.
fn load(store: &Store) -> Result<Vec<Grant>, String> {
    let path = path(store);
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{FILE} cannot be opened: {e}")),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("{FILE} cannot be read: {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!("{FILE} is not a regular file"));
    }
    if meta.uid() != super::directory::uid() {
        return Err(format!("{FILE} is not owned by this host's account"));
    }
    if meta.mode() & 0o7777 != 0o600 {
        return Err(format!(
            "{FILE} has mode {:o}, not 600",
            meta.mode() & 0o7777
        ));
    }
    if meta.len() > MAX_FILE {
        return Err(format!("{FILE} is larger than {MAX_FILE} bytes"));
    }
    let mut text = Vec::new();
    (&mut file)
        .take(MAX_FILE + 1)
        .read_to_end(&mut text)
        .map_err(|e| format!("{FILE} cannot be read: {e}"))?;
    let grants: Grants =
        serde_json::from_slice(&text).map_err(|e| format!("{FILE} is malformed: {e}"))?;
    let mut pairs = HashSet::new();
    let valid = grants.format == FORMAT
        && grants.grants.len() <= MAX_GRANTS
        && grants.grants.iter().all(|g| {
            valid_id(&g.agent_id, "agent", 16)
                && valid_id(&g.space, "space", 16)
                && g.max_bytes > 0
                && chrono::DateTime::parse_from_rfc3339(&g.created_at).is_ok()
                && pairs.insert((g.agent_id.clone(), g.space.clone()))
        });
    if !valid {
        return Err(format!("{FILE} is malformed"));
    }
    Ok(grants.grants)
}

/// Replaces the grants file: a fresh mode 0600 temporary file in the state directory,
/// written and synced, renamed over it, and the directory synced.
fn store_grants(store: &Store, grants: &[Grant]) -> Result<(), Error> {
    let text = serde_json::to_vec_pretty(&Grants {
        format: FORMAT,
        grants: grants.to_vec(),
    })
    .map_err(|_| internal())?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| internal())?;
    let directory = store.state_directory();
    let temporary = directory.join(format!(".{FILE}.{}", hex::encode(random)));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(&text)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path(store))?;
        sync_directory(directory)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(internal());
    }
    Ok(())
}

fn sync_directory(directory: &FsPath) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}

/// The grants file unreadable, to the owner: 409 naming why, so it is fixed rather
/// than silently replaced.
fn unreadable(reason: String) -> Error {
    coded(
        409,
        "conflict",
        format!("{reason}; no agent may pull until it is fixed or removed"),
    )
}

/// `agent`'s grant for `space`, read now: its byte bound, or `None` when it has none
/// (or the grants file holds none).
pub(super) fn bound(store: &Store, agent: &str, space: &str) -> Option<u64> {
    load(store)
        .ok()?
        .into_iter()
        .find(|g| g.agent_id == agent && g.space == space)
        .map(|g| g.max_bytes)
}

/// The owner-local grant routes; never on the peer or adapter routers.
pub(super) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/fs/pull-grants", get(list)).route(
        "/v1/fs/pull-grants/{agent_id}/{space_id}",
        put(allow).delete(deny),
    )
}

/// The agent routes of `fs_pull`, on the adapter router only.
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/fs/pull-grants", get(agent_grants))
        .route("/adapter/v1/fs/pulls", post(agent_pull))
}

fn pair(input: Result<Path<(String, String)>, PathRejection>) -> Result<(String, String), Error> {
    let Path((agent, space)) = input.map_err(|_| invalid())?;
    if !valid_id(&agent, "agent", 16) || !valid_id(&space, "space", 16) {
        return Err(invalid());
    }
    Ok((agent, space))
}

/// The agent's name, or null for an agent no longer registered.
fn named(c: &rusqlite::Connection, agent: &str) -> Result<Option<String>, Error> {
    use rusqlite::OptionalExtension;
    c.query_row("SELECT name FROM agents WHERE id = ?1", [agent], |r| {
        r.get(0)
    })
    .optional()
    .map_err(|_| internal())
}

fn view(c: &rusqlite::Connection, g: &Grant) -> Result<Value, Error> {
    Ok(json!({
        "agent_id": g.agent_id,
        "agent_name": named(c, &g.agent_id)?,
        "space": g.space,
        "max_bytes": g.max_bytes,
        "created_at": g.created_at,
    }))
}

/// `GET /v1/fs/pull-grants`: `{grants: [{agent_id, agent_name, space, max_bytes,
/// created_at}]}`, ordered by agent and space.
async fn list(State(store): State<Arc<Store>>) -> Result<Json<Value>, Error> {
    blocking(store, |store| {
        let mut grants = load(store).map_err(unreadable)?;
        grants.sort_by(|a, b| (&a.agent_id, &a.space).cmp(&(&b.agent_id, &b.space)));
        let c = store.connection().map_err(|_| internal())?;
        let grants = grants
            .iter()
            .map(|g| view(&c, g))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Json(json!({ "grants": grants })))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allow {
    #[serde(default)]
    max_bytes: Option<u64>,
}

/// `PUT /v1/fs/pull-grants/{agent_id}/{space_id}` with `{max_bytes?}`: lets a
/// registered agent of this host pull into a space with a binding on this host (404
/// otherwise; 409 released), each pull bounded to `max_bytes` (default 1 GiB),
/// replacing the pair's grant. 409 at 256 grants.
async fn allow(
    State(store): State<Arc<Store>>,
    target: Result<Path<(String, String)>, PathRejection>,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let (agent, space) = pair(target)?;
    let request: Allow = decode(input, BODY)?;
    if request.max_bytes == Some(0) {
        return Err(invalid());
    }
    let max_bytes = request.max_bytes.unwrap_or(pull::DEFAULT_MAX_BYTES);
    blocking(store, move |store| {
        let _writing = WRITING.lock().unwrap_or_else(|e| e.into_inner());
        let c = store.connection().map_err(|_| internal())?;
        if named(&c, &agent)?.is_none() {
            return Err(coded(404, "not_found", "no such agent on this host"));
        }
        let record = find(&c, &space)?.ok_or_else(|| {
            coded(
                404,
                "not_found",
                "no PeerFS space with this ID on this host",
            )
        })?;
        if record.view.state == "released" {
            return Err(coded(409, "conflict", "the space's binding is released"));
        }
        let mut grants = load(store).map_err(unreadable)?;
        grants.retain(|g| !(g.agent_id == agent && g.space == space));
        if grants.len() >= MAX_GRANTS {
            return Err(coded(
                409,
                "conflict",
                format!("this host holds at most {MAX_GRANTS} pull grants"),
            ));
        }
        let grant = Grant {
            agent_id: agent,
            space,
            max_bytes,
            created_at: now(),
        };
        grants.push(grant.clone());
        store_grants(store, &grants)?;
        Ok(Json(view(&c, &grant)?))
    })
    .await
}

/// `DELETE /v1/fs/pull-grants/{agent_id}/{space_id}`: `{removed}`. A pull already
/// running finishes; the next is refused.
async fn deny(
    State(store): State<Arc<Store>>,
    target: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<Value>, Error> {
    let (agent, space) = pair(target)?;
    blocking(store, move |store| {
        let _writing = WRITING.lock().unwrap_or_else(|e| e.into_inner());
        let mut grants = load(store).map_err(unreadable)?;
        let before = grants.len();
        grants.retain(|g| !(g.agent_id == agent && g.space == space));
        let removed = grants.len() != before;
        if removed {
            store_grants(store, &grants)?;
        }
        Ok(Json(json!({ "removed": removed })))
    })
    .await
}

/// The calling agent, from its adapter credential.
async fn agent(store: &Arc<Store>, auth: AdapterAuth) -> Result<String, Error> {
    blocking(store.clone(), move |store| {
        let c = store.connection()?;
        Ok(authority(&c, &auth)?.1.agent_id)
    })
    .await
}

/// `GET /adapter/v1/fs/pull-grants`: the calling agent's grants, `{grants: [{space,
/// max_bytes}]}`; the adapter offers `fs_pull` only while there is one.
async fn agent_grants(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    let agent = agent(&store, token(&headers)).await?;
    blocking(store, move |store| {
        let mut grants: Vec<Value> = load(store)
            .unwrap_or_default()
            .into_iter()
            .filter(|g| g.agent_id == agent)
            .map(|g| json!({"space": g.space, "max_bytes": g.max_bytes}))
            .collect();
        grants.sort_by(|a, b| a["space"].as_str().cmp(&b["space"].as_str()));
        Ok(Json(json!({ "grants": grants })))
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPull {
    peer: String,
    space: String,
    branch: String,
    into: String,
}

/// `POST /adapter/v1/fs/pulls` with `{peer, space, branch, into}`: the owner's pull,
/// for the calling agent, into a space it has a grant for (403 `forbidden` otherwise),
/// bounded to the grant's `max_bytes`. The grant is read at the call, so `deny-pull`
/// refuses the next one; dropping the request ends the pull.
async fn agent_pull(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: AgentPull = decode(input, BODY)?;
    let agent = agent(&store, token(&headers)).await?;
    let request = pull::Pull {
        peer: request.peer,
        space: request.space,
        branch: request.branch,
        into: request.into,
        network: None,
    };
    if !request.valid(&store) {
        return Err(invalid());
    }
    let (who, into) = (agent.clone(), request.into.clone());
    let max_bytes = blocking(store.clone(), move |store| Ok(bound(store, &who, &into)))
        .await?
        .ok_or_else(|| {
            coded(
                403,
                "forbidden",
                "this agent has no grant to pull into this space",
            )
        })?;
    pull::run(store, pull::Caller::Agent(agent), request, max_bytes)
        .await
        .map(Json)
}
