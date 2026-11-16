//! A runtime agent's build cache (build cache contract, Host: the profile's
//! build cache): the profile's `build_cache` field, the cache's name, the
//! refresh runs that alone write the cache, each profile's last refresh, and
//! the `cache show|refresh|clear` routes. Tasks only name the cache
//! (`peerfs_cache`), in `runtime_agent::run_body`.
//!
//! A refresh run goes straight to the runtime's local API, like a peerbox
//! gate's runs: it is not a received task. Its dispatch is recorded before
//! the start is sent, an unanswered start is sent again with the identical
//! body, and a run the runtime no longer knows ends with
//! `the runtime restarted`, as for a runtime task.
use crate::{
    api::blocking,
    model::Error,
    runtime::call,
    runtime_agent::Profile,
    store::{Store, append_event, new_id, now},
};
use axum::{
    Json, Router,
    extract::{Path as UrlPath, State},
    routing::{get, post},
};
use hyper::Method;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;

/// Each profile's last refresh. Created only if missing, so a state lowered
/// to the previous version to repair another table keeps it.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS runtime_cache_refreshes (agent_id TEXT PRIMARY KEY NOT NULL, record TEXT NOT NULL);
";
/// How often the host checks whether a refresh should start.
const CHECK: chrono::TimeDelta = chrono::TimeDelta::seconds(60);
const DEFAULT_INTERVAL: i64 = 600;
const RESTARTED: &str = "the runtime restarted";

/// A profile's `build_cache`, as stored and returned.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildCache {
    pub command: String,
    pub interval_seconds: i64,
}

/// `build_cache` in `PUT /v1/agents/{agent_id}/runtime`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildCacheRequest {
    command: String,
    #[serde(default)]
    interval_seconds: Option<i64>,
}

impl BuildCacheRequest {
    /// The request's `build_cache`, taken as JSON so that a field of the
    /// wrong shape is 400 `invalid` naming `build_cache`, then checked
    /// against the contract's ranges with its default.
    pub(crate) fn parse(value: Value) -> Result<BuildCache, Error> {
        serde_json::from_value::<Self>(value)
            .map_err(|_| Error::Invalid("build_cache".into()))?
            .build_cache()
    }
    fn build_cache(self) -> Result<BuildCache, Error> {
        let interval_seconds = self.interval_seconds.unwrap_or(DEFAULT_INTERVAL);
        if self.command.is_empty() || self.command.len() > 4096 {
            return Err(Error::Invalid("build_cache.command".into()));
        }
        if !(60..=86_400).contains(&interval_seconds) {
            return Err(Error::Invalid("build_cache.interval_seconds".into()));
        }
        Ok(BuildCache {
            command: self.command,
            interval_seconds,
        })
    }
}

/// The cache's name: `bc-` and the first 32 hex digits of the SHA-256 of
/// `from_branch`, a NUL byte, and `image` (empty when null).
pub(crate) fn cache_name(profile: &Profile) -> String {
    let mut digest = Sha256::new();
    digest.update(profile.from_branch.as_bytes());
    digest.update([0]);
    digest.update(profile.image.as_deref().unwrap_or_default().as_bytes());
    format!("bc-{}", &hex::encode(digest.finalize())[..32])
}

// ---------------------------------------------------------------------
// Storage.

/// A profile's stored refresh state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    /// `cache refresh` asked for a refresh at the next check.
    #[serde(default)]
    requested: bool,
    #[serde(default)]
    last: Option<Refresh>,
}

/// A profile's last refresh. The fields after `reason` are never shown.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Refresh {
    started_at: String,
    run_id: String,
    /// The branch's head when the refresh was dispatched.
    commit: String,
    ended_at: Option<String>,
    saved: Option<bool>,
    reason: Option<String>,
    /// The cache it writes.
    cache: String,
    /// The runtime's socket at dispatch, which the run is followed on.
    socket: PathBuf,
    /// The whole `POST /v1/runs` body, which every resend uses.
    body: Value,
    /// The last runtime event sequence stored.
    #[serde(default)]
    after: u64,
    #[serde(default)]
    started: bool,
    /// The runtime's `exited` result, once stored.
    #[serde(default)]
    exited: Option<Value>,
    /// Ended, and the runtime may still hold the run: it is deleted until
    /// the runtime answers 200 or 404.
    #[serde(default)]
    cleanup: bool,
    /// While the start is unanswered: the row as it was before this
    /// dispatch, put back if the runtime refuses with 429, since no run
    /// exists then.
    #[serde(default)]
    before: Option<Box<Row>>,
}

impl Refresh {
    /// Dispatched or running: not yet ended.
    fn active(&self) -> bool {
        self.ended_at.is_none()
    }
    fn view(&self) -> Value {
        json!({
            "started_at": self.started_at,
            "run_id": self.run_id,
            "commit": self.commit,
            "ended_at": self.ended_at,
            "saved": self.saved,
            "reason": self.reason,
        })
    }
}

fn rows(conn: &Connection) -> Result<HashMap<String, Row>, Error> {
    let mut statement = conn.prepare("SELECT agent_id, record FROM runtime_cache_refreshes")?;
    let raw = statement
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    raw.into_iter()
        .map(|(agent, record)| Ok((agent, serde_json::from_str(&record)?)))
        .collect()
}
fn row(conn: &Connection, agent: &str) -> Result<Row, Error> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT record FROM runtime_cache_refreshes WHERE agent_id = ?1",
            [agent],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw
        .map(|r| serde_json::from_str(&r))
        .transpose()?
        .unwrap_or_default())
}
fn save(conn: &Connection, agent: &str, row: &Row) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO runtime_cache_refreshes VALUES (?1, ?2) ON CONFLICT(agent_id) DO UPDATE SET record = ?2",
        params![agent, serde_json::to_string(row)?],
    )?;
    Ok(())
}
/// Whether a refresh of `cache` is dispatched or running, for any profile.
fn cache_busy(rows: &HashMap<String, Row>, cache: &str) -> bool {
    rows.values()
        .filter_map(|r| r.last.as_ref())
        .any(|r| r.active() && r.cache == cache)
}

/// Forgets a refresh asked for with `cache refresh`, once the profile has no
/// `build_cache`: removing it stops refreshes. A refresh already dispatched
/// or running finishes.
pub(crate) fn forget_request(store: &Store, agent: &str) -> Result<(), Error> {
    let conn = store.connection()?;
    let mut r = row(&conn, agent)?;
    if r.requested {
        r.requested = false;
        save(&conn, agent, &r)?;
    }
    Ok(())
}

/// Removes the agent's stored refresh with its profile. A refresh still
/// dispatched or running, or whose run is still to delete, is kept until
/// that is done (`clean_up`), without its pending request.
pub(crate) fn remove_with_profile(store: &Store, agent: &str) -> Result<(), Error> {
    let conn = store.connection()?;
    let mut r = row(&conn, agent)?;
    if r.last.as_ref().is_some_and(|l| l.active() || l.cleanup) {
        r.requested = false;
        save(&conn, agent, &r)?;
    } else {
        conn.execute(
            "DELETE FROM runtime_cache_refreshes WHERE agent_id = ?1",
            [agent],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// The runtime's peerfs space, through the runtime's local API (RUN-21).

/// A cache's current version, as `GET /v1/caches` reports it.
struct Version {
    commit: String,
    saved_at: String,
    bytes: u64,
}

/// The runtime's socket while the switch is on (503 otherwise).
fn runtime_socket(store: &Store) -> Result<PathBuf, Error> {
    store
        .runtime_switch()?
        .map(|w| w.socket)
        .ok_or_else(|| Error::Unavailable("the runtime is disabled".into()))
}

/// A path segment, percent-encoded except for unreserved bytes.
fn segment(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// One call to the runtime about its space; 503 when it cannot be asked
/// or does not answer as the contract says.
async fn ask(
    socket: &std::path::Path,
    method: Method,
    path: &str,
    accept: &[u16],
) -> Result<crate::runtime::Answer, Error> {
    let answer = call(socket, method, path, None).await.map_err(|e| {
        Error::Unavailable(format!(
            "cannot reach the runtime at {}: {e}",
            socket.display()
        ))
    })?;
    if !accept.contains(&answer.status) {
        let error = answer.body["error"].as_str().unwrap_or_default();
        return Err(Error::Unavailable(format!(
            "the runtime answered {} to {path}: {error}",
            answer.status
        )));
    }
    Ok(answer)
}
fn malformed(path: &str) -> Error {
    Error::Unavailable(format!("the runtime's answer to {path} is malformed"))
}

/// The cache's current version (`GET /v1/caches`), or None when the space
/// has no such cache.
async fn current_version(socket: &std::path::Path, cache: &str) -> Result<Option<Version>, Error> {
    let path = "/v1/caches";
    let answer = ask(socket, Method::GET, path, &[200]).await?;
    let caches = answer.body["caches"]
        .as_array()
        .ok_or_else(|| malformed(path))?;
    let Some(entry) = caches.iter().find(|c| c["name"].as_str() == Some(cache)) else {
        return Ok(None);
    };
    match (
        entry["commit"].as_str(),
        entry["saved_at"].as_str(),
        entry["bytes"].as_u64(),
    ) {
        (Some(commit), Some(saved_at), Some(bytes)) => Ok(Some(Version {
            commit: commit.into(),
            saved_at: saved_at.into(),
            bytes,
        })),
        _ => Err(malformed(path)),
    }
}

/// The branch's head (`GET /v1/branches/{name}`), or None when the space
/// has no such branch.
async fn branch_head(socket: &std::path::Path, branch: &str) -> Result<Option<String>, Error> {
    let path = format!("/v1/branches/{}", segment(branch));
    let answer = ask(socket, Method::GET, &path, &[200, 404]).await?;
    if answer.status == 404 {
        return Ok(None);
    }
    answer.body["head"]
        .as_str()
        .map(|h| Some(h.to_owned()))
        .ok_or_else(|| malformed(&path))
}

/// Removes the cache from the runtime's space (`DELETE /v1/caches/{name}`).
async fn remove_cache(socket: &std::path::Path, cache: &str) -> Result<(), Error> {
    let path = format!("/v1/caches/{}", segment(cache));
    ask(socket, Method::DELETE, &path, &[200]).await?;
    Ok(())
}

// ---------------------------------------------------------------------
// The refresh run.

/// The `POST /v1/runs` body of a refresh (The host refresh).
fn refresh_body(profile: &Profile, build: &BuildCache, run_id: &str, cache: &str) -> Value {
    let hex = run_id.strip_prefix("cache_").unwrap_or(run_id);
    let mut body = json!({
        "run_id": run_id,
        "argv": ["/bin/sh", "-c", build.command],
        "cwd": "/workspace",
        "env": {},
        "resources": {
            "cpus": profile.cpus,
            "memory_mib": profile.memory_mib,
            "timeout_seconds": profile.timeout_seconds,
        },
        "network": profile.network,
        "workspace_archive": null,
        "results": "none",
        "peerfs_workspace": format!("{cache}.refresh.{hex}"),
        "peerfs_fork_from": profile.from_branch,
        "peerfs_cache": cache,
        "peerfs_cache_save": cache,
        "peerfs_commit": false,
        "stdin": null,
    });
    if let Some(image) = &profile.image {
        body["image"] = image.as_str().into();
    }
    body
}

/// Why nothing was saved, from the runtime's `exited` result: the first of
/// `timed out`, `signal N`, `exit N` for a non-zero status, the result's
/// `error`, or `exit 0`.
fn reason(result: &Value) -> Option<String> {
    if result["cache_saved"] == Value::Bool(true) {
        return None;
    }
    let error = result["error"]
        .as_str()
        .map(|e| e.replace(['\r', '\n'], " "))
        .filter(|e| !e.is_empty());
    Some(if result["timed_out"] == Value::Bool(true) {
        "timed out".into()
    } else if let Some(signal) = result["signal"].as_i64() {
        format!("signal {signal}")
    } else if let Some(code) = result["exit_code"].as_i64().filter(|c| *c != 0) {
        format!("exit {code}")
    } else if let Some(error) = error {
        error
    } else {
        "exit 0".into()
    })
}

/// Ends the agent's refresh `run_id`, if it is still the active one, with
/// `saved` and `reason`, and records `runtime.cache_refreshed`.
fn end(
    store: &Store,
    agent: &str,
    run_id: &str,
    saved: bool,
    reason: Option<String>,
) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let mut r = row(&tx, agent)?;
    let Some(last) = r.last.as_mut().filter(|l| l.run_id == run_id && l.active()) else {
        return Ok(());
    };
    ended(&tx, agent, last, saved, reason)?;
    save(&tx, agent, &r)?;
    tx.commit()?;
    Ok(())
}

/// Marks `last` ended and records `runtime.cache_refreshed`, in the
/// caller's transaction, which also saves the row.
fn ended(
    tx: &rusqlite::Transaction<'_>,
    agent: &str,
    last: &mut Refresh,
    saved: bool,
    reason: Option<String>,
) -> Result<(), Error> {
    let at = now();
    last.ended_at = Some(at.clone());
    last.saved = Some(saved);
    last.reason = if saved { None } else { reason };
    last.cleanup = true;
    last.before = None;
    let subject = format!("{agent}/{}/{saved}", last.commit);
    append_event(tx, "runtime.cache_refreshed", &subject, &at)?;
    Ok(())
}

enum Started {
    /// 201 or 200: the run exists.
    Accepted,
    /// The refresh is over: 429 put the row back, or another refusal ended it.
    Over,
    /// No answer: the start is sent again.
    Unknown,
}

/// Sends a dispatched refresh's start and applies a definite answer.
async fn start(store: &Arc<Store>, agent: &str, refresh: &Refresh) -> Result<Started, Error> {
    let answer = match call(
        &refresh.socket,
        Method::POST,
        "/v1/runs",
        Some(&refresh.body),
    )
    .await
    {
        Ok(a) => a,
        Err(_) => return Ok(Started::Unknown),
    };
    let (agent, run_id) = (agent.to_owned(), refresh.run_id.clone());
    blocking(store.clone(), move |s| match answer.status {
        200 | 201 => {
            let mut conn = s.connection()?;
            let tx = conn.transaction()?;
            let mut r = row(&tx, &agent)?;
            if let Some(last) = r.last.as_mut().filter(|l| l.run_id == run_id) {
                last.before = None;
                save(&tx, &agent, &r)?;
            }
            tx.commit()?;
            Ok(Started::Accepted)
        }
        // Every slot is busy: no run exists, so the refresh never happened.
        429 => {
            let mut conn = s.connection()?;
            let tx = conn.transaction()?;
            let r = row(&tx, &agent)?;
            if let Some(before) = r
                .last
                .as_ref()
                .filter(|l| l.run_id == run_id && l.active())
                .and_then(|l| l.before.clone())
            {
                save(&tx, &agent, &before)?;
            }
            tx.commit()?;
            Ok(Started::Over)
        }
        400..=499 => {
            let error = answer.body["error"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| format!("status {}", answer.status));
            let reason = format!("the runtime refused the run: {error}");
            end(s, &agent, &run_id, false, Some(reason))?;
            Ok(Started::Over)
        }
        _ => Ok(Started::Unknown),
    })
    .await
}

/// The refreshes that have a follower, by run ID.
type Following = Arc<Mutex<HashSet<String>>>;

fn follow(
    store: &Arc<Store>,
    following: &Following,
    shutdown: &watch::Receiver<bool>,
    (agent, run_id): (String, String),
    answered: bool,
) {
    if !following.lock().expect("followers").insert(run_id.clone()) {
        return;
    }
    let (store, following, shutdown) = (store.clone(), following.clone(), shutdown.clone());
    tokio::spawn(async move {
        if let Err(e) = follower(&store, &agent, &run_id, answered, shutdown).await {
            eprintln!("build cache refresh {run_id} of {agent}: {e:?}");
        }
        following.lock().expect("followers").remove(&run_id);
    });
}

async fn pause(shutdown: &mut watch::Receiver<bool>, d: Duration) {
    tokio::select! {
        _ = shutdown.changed() => {}
        _ = tokio::time::sleep(d) => {}
    }
}

/// Follows the agent's refresh `run_id` to its end: sends its start again
/// while it is unanswered, and stores the runtime's events.
async fn follower(
    store: &Arc<Store>,
    agent: &str,
    run_id: &str,
    mut answered: bool,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let refresh = {
            let agent = agent.to_owned();
            blocking(store.clone(), move |s| {
                Ok(row(&*s.connection()?, &agent)?.last)
            })
            .await?
        };
        let Some(refresh) = refresh.filter(|l| l.run_id == run_id && l.active()) else {
            return Ok(());
        };
        if !refresh.started && !answered {
            match start(store, agent, &refresh).await? {
                Started::Accepted => answered = true,
                Started::Over => return Ok(()),
                Started::Unknown => {
                    pause(&mut shutdown, Duration::from_secs(1)).await;
                    continue;
                }
            }
        }
        let path = format!(
            "/v1/runs/{}/events?after={}&wait=5&limit={}",
            refresh.run_id,
            refresh.after,
            crate::task_outbound::RUNTIME_EVENT_PAGE
        );
        let answer = tokio::select! {
            a = call(&refresh.socket, Method::GET, &path, None) => a,
            _ = shutdown.changed() => return Ok(()),
        };
        let events = match answer {
            Ok(a) if a.status == 404 => {
                let (agent, run_id) = (agent.to_owned(), refresh.run_id.clone());
                blocking(store.clone(), move |s| {
                    end(s, &agent, &run_id, false, Some(RESTARTED.into()))
                })
                .await?;
                return Ok(());
            }
            Ok(a) if a.status == 200 => a.body.as_array().cloned().unwrap_or_default(),
            _ => {
                pause(&mut shutdown, Duration::from_secs(1)).await;
                continue;
            }
        };
        let (agent2, run_id) = (agent.to_owned(), refresh.run_id.clone());
        let ended = blocking(store.clone(), move |s| apply(s, &agent2, &run_id, events)).await?;
        if ended {
            return Ok(());
        }
    }
}

/// Stores a page of runtime events. `results`, the last, ends the refresh
/// with the `exited` result, in the same transaction as the cursor that
/// passes it, so a restart never finds the cursor past an unended refresh;
/// whether it ended.
fn apply(store: &Store, agent: &str, run_id: &str, events: Vec<Value>) -> Result<bool, Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let mut r = row(&tx, agent)?;
    let Some(last) = r.last.as_mut().filter(|l| l.run_id == run_id && l.active()) else {
        return Ok(true);
    };
    let mut finished = false;
    for event in events {
        let sequence = event["sequence"].as_u64().unwrap_or(0);
        if sequence <= last.after {
            continue;
        }
        last.after = sequence;
        match event["kind"].as_str().unwrap_or_default() {
            "started" => last.started = true,
            "exited" => last.exited = Some(event["result"].clone()),
            "results" => {
                let result = last.exited.clone().unwrap_or(Value::Null);
                let saved = result["cache_saved"] == Value::Bool(true);
                ended(&tx, agent, last, saved, reason(&result))?;
                finished = true;
                break;
            }
            _ => {}
        }
    }
    save(&tx, agent, &r)?;
    tx.commit()?;
    Ok(finished)
}

/// Deletes ended refreshes' runs that the runtime may still hold, and
/// forgets each once the runtime answers 200 or 404.
async fn clean_up(store: &Arc<Store>) -> Result<(), Error> {
    let pending: Vec<(String, Refresh)> = blocking(store.clone(), |s| {
        Ok(rows(&*s.connection()?)?
            .into_iter()
            .filter_map(|(agent, r)| Some((agent, r.last?)))
            .filter(|(_, l)| l.cleanup)
            .collect())
    })
    .await?;
    for (agent, refresh) in pending {
        let path = format!("/v1/runs/{}", refresh.run_id);
        if !matches!(
            call(&refresh.socket, Method::DELETE, &path, None).await,
            Ok(a) if a.status == 200 || a.status == 404
        ) {
            continue;
        }
        blocking(store.clone(), move |s| {
            let conn = s.connection()?;
            let mut r = row(&conn, &agent)?;
            if let Some(last) = r.last.as_mut().filter(|l| l.run_id == refresh.run_id) {
                last.cleanup = false;
                save(&conn, &agent, &r)?;
            }
            drop(conn);
            // The profile was removed while the refresh ran: its stored
            // refresh goes with it now.
            if s.runtime_profile(&agent)?.is_none() {
                remove_with_profile(s, &agent)?;
            }
            Ok(())
        })
        .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// The scheduler.

/// Follows dispatched refreshes, resuming them after a restart, and checks
/// every 60 seconds whether a profile's refresh should start, until
/// shutdown.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let following: Following = Default::default();
    let mut next = crate::clock::now();
    loop {
        if let Err(e) = resume(&store, &following, &shutdown).await {
            eprintln!("build cache refreshes: {e:?}");
        }
        if let Err(e) = clean_up(&store).await {
            eprintln!("build cache refreshes: {e:?}");
        }
        if crate::clock::now() >= next {
            next = crate::clock::now() + CHECK;
            if let Err(e) = check(&store, &following, &shutdown).await {
                eprintln!("build cache refreshes: {e:?}");
            }
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

/// A follower for every dispatched or running refresh.
async fn resume(
    store: &Arc<Store>,
    following: &Following,
    shutdown: &watch::Receiver<bool>,
) -> Result<(), Error> {
    let active: Vec<(String, String)> = blocking(store.clone(), |s| {
        Ok(rows(&*s.connection()?)?
            .into_iter()
            .filter_map(|(agent, r)| Some((agent, r.last.filter(Refresh::active)?.run_id)))
            .collect())
    })
    .await?;
    for key in active {
        follow(store, following, shutdown, key, false);
    }
    Ok(())
}

/// A runtime agent's tasks dispatched or running, by agent, and whether any
/// runtime agent's task is queued and not yet dispatched.
fn task_load(conn: &Connection) -> Result<(HashMap<String, i64>, bool), Error> {
    let mut statement = conn.prepare(
        "SELECT json_extract(request, '$.target_agent_id'), json_extract(record, '$.state'), COALESCE(json_extract(record, '$.runtime.dispatched'), 0) FROM received_tasks WHERE json_extract(record, '$.runtime_agent') = 1 AND json_extract(record, '$.state') IN ('queued', 'running')",
    )?;
    let tasks = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut runs: HashMap<String, i64> = HashMap::new();
    let mut queued = false;
    for (agent, state, dispatched) in tasks {
        if state == "running" || dispatched {
            *runs.entry(agent).or_default() += 1;
        } else {
            queued = true;
        }
    }
    Ok((runs, queued))
}

/// One check (The host refresh): starts a refresh for each profile with
/// `build_cache` for which every condition holds, while the runtime has a
/// free slot.
async fn check(
    store: &Arc<Store>,
    following: &Following,
    shutdown: &watch::Receiver<bool>,
) -> Result<(), Error> {
    let (profiles, mut rows, (runs, queued), switch) = blocking(store.clone(), |s| {
        let profiles: Vec<Profile> = s
            .runtime_profiles()?
            .into_iter()
            .filter(|p| p.build_cache.is_some())
            .collect();
        let conn = s.connection()?;
        let rows = rows(&conn)?;
        let load = task_load(&conn)?;
        drop(conn);
        Ok((profiles, rows, load, s.runtime_switch()?))
    })
    .await?;
    // No task of any runtime agent is queued.
    if profiles.is_empty() || queued {
        return Ok(());
    }
    let Some(switch) = switch else {
        return Ok(());
    };
    let Ok(report) = crate::runtime::report(&switch.socket).await else {
        return Ok(());
    };
    // A runtime without caches refuses every refresh.
    if report["peerfs_caches"] != Value::Bool(true) {
        return Ok(());
    }
    let mut free = report["max_concurrent_runs"].as_i64().unwrap_or(0)
        - report["running"].as_i64().unwrap_or(0);
    let now_at = crate::clock::now();
    for profile in profiles {
        if free <= 0 {
            break;
        }
        let Some(build) = profile.build_cache.clone() else {
            continue;
        };
        let cache = cache_name(&profile);
        if cache_busy(&rows, &cache) {
            continue;
        }
        let agent = profile.agent_id.clone();
        let current = rows.get(&agent).cloned().unwrap_or_default();
        let last = current.last.as_ref();
        // The profile's own refresh is still dispatched or running, perhaps
        // of the cache its branch or image named before, or its run is still
        // to delete: it is followed to its end and its run deleted, and its
        // record is never replaced until then.
        if last.is_some_and(|l| l.active() || l.cleanup) {
            continue;
        }
        // At least `interval_seconds` since the last refresh started, unless
        // `cache refresh` asked for one.
        let due = current.requested
            || last.is_none_or(
                |l| match chrono::DateTime::parse_from_rfc3339(&l.started_at) {
                    Ok(started) => {
                        now_at - started.to_utc()
                            >= chrono::TimeDelta::seconds(build.interval_seconds)
                    }
                    Err(_) => true,
                },
            );
        if !due {
            continue;
        }
        // Fewer than `max_runs` of its tasks and refreshes dispatched or
        // running; none of its refreshes is, above.
        if runs.get(&agent).copied().unwrap_or(0) >= profile.max_runs {
            continue;
        }
        let space = async {
            let head = branch_head(&switch.socket, &profile.from_branch).await?;
            let version = current_version(&switch.socket, &cache).await?;
            Ok::<_, Error>((head, version))
        };
        let (head, version) = match space.await {
            Ok(space) => space,
            Err(e) => {
                eprintln!("build cache refresh of {agent}: {e:?}");
                continue;
            }
        };
        // A branch that does not exist has nothing to build.
        let Some(head) = head else {
            continue;
        };
        if !current.requested && version.is_some_and(|v| v.commit == head) {
            continue;
        }
        let run_id = new_id("cache")?;
        let refresh = Refresh {
            started_at: crate::store::now(),
            run_id: run_id.clone(),
            commit: head,
            ended_at: None,
            saved: None,
            reason: None,
            body: refresh_body(&profile, &build, &run_id, &cache),
            cache,
            socket: switch.socket.clone(),
            after: 0,
            started: false,
            exited: None,
            cleanup: false,
            before: Some(Box::new(current.clone())),
        };
        let stored = Row {
            requested: false,
            last: Some(refresh.clone()),
        };
        // The branch and cache requests may have taken a while: the dispatch
        // is recorded only if the profile, its cache, the switch and the
        // profile's last refresh are as this check found them, and the tasks
        // still leave room for it.
        let dispatched = {
            let (agent, stored, profile) = (agent.clone(), stored.clone(), profile.clone());
            let (socket, before) = (switch.socket.clone(), current.clone());
            blocking(store.clone(), move |s| {
                let mut conn = s.connection()?;
                let tx = conn.transaction()?;
                let now = s.runtime_profile(&agent)?;
                let same_profile = now.as_ref().is_some_and(|now| {
                    now.build_cache == profile.build_cache
                        && cache_name(now) == cache_name(&profile)
                });
                let same_switch = s.runtime_switch()?.is_some_and(|w| w.socket == socket);
                let r = row(&tx, &agent)?;
                // A `cache refresh` asked for meanwhile is met by this one.
                let same_row = r.last.as_ref().map(|l| &l.run_id)
                    == before.last.as_ref().map(|l| &l.run_id)
                    && r.last.as_ref().is_none_or(|l| !l.active() && !l.cleanup);
                // Tasks may have arrived or started meanwhile: none of any
                // runtime agent is queued, and fewer than `max_runs` of this
                // profile's are dispatched or running.
                let (runs, queued) = task_load(&tx)?;
                let room =
                    now.is_some_and(|now| runs.get(&agent).copied().unwrap_or(0) < now.max_runs);
                if !(same_profile && same_switch && same_row && room) || queued {
                    return Ok(false);
                }
                save(&tx, &agent, &stored)?;
                tx.commit()?;
                Ok(true)
            })
            .await?
        };
        if !dispatched {
            continue;
        }
        rows.insert(agent.clone(), stored);
        free -= 1;
        let key = (agent.clone(), run_id);
        match start(store, &agent, &refresh).await? {
            Started::Accepted => follow(store, following, shutdown, key, true),
            Started::Unknown => follow(store, following, shutdown, key, false),
            // The runtime is full, or refused the run.
            Started::Over => break,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// The local API.

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/agents/runtime/cache", get(list))
        .route("/v1/agents/{id}/runtime/cache", get(show).delete(clear))
        .route("/v1/agents/{id}/runtime/cache/refresh", post(refresh))
}

/// The agent's profile, which must have `build_cache` (404 otherwise).
fn cached_profile(store: &Store, agent: &str) -> Result<Profile, Error> {
    store
        .runtime_profile(agent)?
        .filter(|p| p.build_cache.is_some())
        .ok_or(Error::NotFound)
}

/// A profile's cache as `cache show` reports it.
async fn shown(store: &Arc<Store>, profile: Profile) -> Result<Value, Error> {
    let cache = cache_name(&profile);
    let agent = profile.agent_id.clone();
    let (last, socket) = blocking(store.clone(), move |s| {
        let last = row(&*s.connection()?, &agent)?.last;
        Ok((last, runtime_socket(s)?))
    })
    .await?;
    let current = current_version(&socket, &cache).await?;
    Ok(json!({
        "agent_id": profile.agent_id,
        "name": cache,
        "commit": current.as_ref().map(|v| v.commit.clone()),
        "saved_at": current.as_ref().map(|v| v.saved_at.clone()),
        "bytes": current.as_ref().map(|v| v.bytes),
        "last_refresh": last.as_ref().map(Refresh::view),
    }))
}

async fn list(State(store): State<Arc<Store>>) -> Result<Json<Value>, Error> {
    let profiles = blocking(store.clone(), |s| {
        Ok(s.runtime_profiles()?
            .into_iter()
            .filter(|p| p.build_cache.is_some())
            .collect::<Vec<_>>())
    })
    .await?;
    let mut caches = Vec::new();
    for profile in profiles {
        caches.push(shown(&store, profile).await?);
    }
    Ok(Json(json!({ "caches": caches })))
}

async fn show(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Value>, Error> {
    let profile = blocking(store.clone(), move |s| cached_profile(s, &id)).await?;
    Ok(Json(shown(&store, profile).await?))
}

/// `cache refresh`: a refresh at the next check, unless one of the cache is
/// dispatched or running (409 `busy`).
async fn refresh(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Value>, Error> {
    blocking(store, move |s| {
        let profile = cached_profile(s, &id)?;
        let cache = cache_name(&profile);
        let conn = s.connection()?;
        if cache_busy(&rows(&conn)?, &cache) {
            return Err(Error::Coded {
                status: 409,
                code: "busy",
                message: format!("a refresh of {cache} is dispatched or running"),
                extra: Default::default(),
            });
        }
        let mut r = row(&conn, &profile.agent_id)?;
        r.requested = true;
        save(&conn, &profile.agent_id, &r)?;
        Ok(Json(json!({})))
    })
    .await
}

/// `cache clear`: `cache rm` on the runtime's peerfs space.
async fn clear(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Value>, Error> {
    let (profile, socket) = blocking(store, move |s| {
        let profile = cached_profile(s, &id)?;
        Ok((profile, runtime_socket(s)?))
    })
    .await?;
    remove_cache(&socket, &cache_name(&profile)).await?;
    Ok(Json(json!({})))
}
