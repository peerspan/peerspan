//! Runtime tasks (runtime task contract): the receiving host. A peer's
//! runtime task is authorized by a runtime rule in this host's owner's
//! policy and by the local switch, persisted `queued`, dispatched to the
//! runtime (`peerspan-runtime serve`) in `created_at` order, and followed
//! there: its output becomes `output` events, its exit the final event with
//! the run result and the result artifacts.
use crate::{
    artifact::{ArtifactEntry, INPUT, RECEIVED, RESULT, manifest_total},
    model::Error,
    policy::{PolicyRef, RuntimeRule},
    runtime::{Answer, call},
    store::{Store, append_event, now},
    task::{TaskRequest, TaskStatus, is_final, received, record, record_output},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::Method;
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

pub const EXECUTOR: &str = "runtime";
/// The largest `output` chunk, and the most output the host holds per
/// stream before it emits one.
const CHUNK: usize = 16_384;
/// The longest the host holds output before it emits it.
const HOLD: Duration = Duration::from_millis(250);
/// The artifact contract's limit for one file.
const MAX_FILE: i64 = 104_857_600;
const RESTARTED: &str = "the runtime restarted";

/// A runtime task's command (`run`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunSpec {
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Workspace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<String>,
}
/// `run.workspace`: an archive input artifact, or a workspace of the
/// receiving host's peerfs space.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Workspace {
    #[serde(rename = "archive")]
    Archive(String),
    #[serde(rename = "peerfs")]
    Peerfs(String),
}
impl Workspace {
    /// The peerfs workspace's name, if it is one.
    pub fn peerfs(&self) -> Option<&str> {
        match self {
            Self::Peerfs(name) => Some(name),
            Self::Archive(_) => None,
        }
    }
}
impl RunSpec {
    fn peerfs_workspace(&self) -> Option<&str> {
        self.workspace.as_ref().and_then(Workspace::peerfs)
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i64>,
}

/// An `output` event's chunk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub stream: String,
    pub data: String,
}
impl Chunk {
    pub(crate) fn well_formed(&self) -> bool {
        matches!(self.stream.as_str(), "stdout" | "stderr")
            && STANDARD
                .decode(&self.data)
                .is_ok_and(|d| (1..=CHUNK).contains(&d.len()))
    }
}

/// What the host keeps about a runtime task beside its record, never
/// served: the run, whether it was dispatched, the bounds of the rule that
/// authorized it, and how far its runtime events are stored.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Internal {
    pub run_id: String,
    pub dispatched: bool,
    /// The runtime's socket at dispatch, which the run is followed on.
    #[serde(default)]
    pub socket: Option<PathBuf>,
    pub bounds: Option<RuntimeRule>,
    /// The last runtime event sequence stored.
    pub after: u64,
    pub started: bool,
    /// Output held for the next `output` event, base64, per stream.
    #[serde(default)]
    pub held: BTreeMap<String, String>,
    pub streamed: i64,
    /// The runtime's `exited` result, once stored.
    #[serde(default)]
    pub exited: Option<Value>,
}

fn invalid(field: &str) -> Error {
    Error::Invalid(field.into())
}
fn utf8_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.contains('\0')
}

/// The `run_id` of a received task: `run_` and the hex SHA-256 of
/// `<sender host ID>/<task_id>`.
pub(crate) fn run_id(sender: &str, task_id: &str) -> String {
    format!(
        "run_{}",
        hex::encode(Sha256::digest(format!("{sender}/{task_id}")))
    )
}

/// A runtime task's fields, checked before decoding so that a refusal
/// names the field (Requests).
pub(crate) fn check_fields(body: &Value) -> Result<(), Error> {
    const TOP: [&str; 8] = [
        "task_id",
        "executor",
        "run",
        "deadline",
        "input",
        "policy",
        "origin",
        "artifacts",
    ];
    const RUN: [&str; 6] = ["argv", "cwd", "env", "workspace", "resources", "results"];
    const RESOURCES: [&str; 3] = ["cpus", "memory_mib", "timeout_seconds"];
    let Some(object) = body.as_object() else {
        return Err(invalid("request"));
    };
    if let Some(key) = object.keys().find(|k| !TOP.contains(&k.as_str())) {
        return Err(invalid(key));
    }
    let run = object.get("run").ok_or_else(|| invalid("run"))?;
    let run = run.as_object().ok_or_else(|| invalid("run"))?;
    if let Some(key) = run.keys().find(|k| !RUN.contains(&k.as_str())) {
        return Err(invalid(&format!("run.{key}")));
    }
    if let Some(res) = run.get("resources").and_then(Value::as_object)
        && let Some(key) = res.keys().find(|k| !RESOURCES.contains(&k.as_str()))
    {
        return Err(invalid(&format!("resources.{key}")));
    }
    Ok(())
}

/// The request rules of a runtime task (Requests).
pub(crate) fn validate(r: &TaskRequest) -> Result<(), Error> {
    if !crate::peer_store::valid_id(&r.task_id, "task", 16) {
        return Err(invalid("task_id"));
    }
    if !r.target_agent_id.is_empty() {
        return Err(invalid("target_agent_id"));
    }
    if r.grant_id.is_some() {
        return Err(invalid("grant_id"));
    }
    if r.delegation.is_some() {
        return Err(invalid("chain"));
    }
    if r.self_access.is_some() {
        return Err(invalid("self"));
    }
    if r.policy.is_none() {
        return Err(invalid("policy"));
    }
    if r.origin.as_ref().is_some_and(|o| !o.valid()) {
        return Err(invalid("origin"));
    }
    if r.input.is_empty() || r.input.len() > crate::task::MAX_TEXT {
        return Err(invalid("input"));
    }
    chrono::DateTime::parse_from_rfc3339(&r.deadline).map_err(|_| invalid("deadline"))?;
    if let Some(manifest) = &r.artifacts {
        crate::artifact::validate_manifest(manifest).map_err(|_| invalid("artifacts"))?;
    }
    let run = r.run.as_ref().ok_or_else(|| invalid("run"))?;
    if run.argv.is_empty()
        || run.argv.len() > 256
        || run.argv.iter().any(|a| !utf8_text(a, 4096))
        || run.argv.iter().map(String::len).sum::<usize>() > 65_536
    {
        return Err(invalid("argv"));
    }
    if let Some(cwd) = &run.cwd
        && (!cwd.starts_with('/') || !utf8_text(cwd, 4096))
    {
        return Err(invalid("cwd"));
    }
    if let Some(env) = &run.env {
        let name = |n: &str| {
            let b = n.as_bytes();
            !b.is_empty()
                && b.len() <= 256
                && (b[0].is_ascii_alphabetic() || b[0] == b'_')
                && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        };
        if env.len() > 64
            || env
                .iter()
                .any(|(n, v)| !name(n) || v.len() > 4096 || v.contains('\0'))
        {
            return Err(invalid("env"));
        }
    }
    if let Some(res) = &run.resources {
        for (name, value, lo, hi) in [
            ("cpus", res.cpus, 1, 64),
            ("memory_mib", res.memory_mib, 128, 262_144),
            ("timeout_seconds", res.timeout_seconds, 1, 86_400),
        ] {
            if value.is_some_and(|v| !(lo..=hi).contains(&v)) {
                return Err(invalid(&format!("resources.{name}")));
            }
        }
    }
    if let Some(results) = &run.results
        && !matches!(results.as_str(), "none" | "output" | "changes")
    {
        return Err(invalid("results"));
    }
    match &run.workspace {
        Some(Workspace::Archive(archive)) => {
            let listed = r.artifacts.iter().flatten().any(|e| {
                e.sha256 == *archive
                    && matches!(
                        e.media_type.as_str(),
                        "application/x-tar" | "application/gzip"
                    )
            });
            if !crate::artifact::valid_digest(archive) || !listed {
                return Err(invalid("workspace"));
            }
        }
        Some(Workspace::Peerfs(name)) => {
            if !crate::policy::peerfs_workspace(name) {
                return Err(invalid("workspace"));
            }
            // The run result names the snapshot instead (RUN-7).
            if run.results.as_deref() == Some("changes") {
                return Err(invalid("results"));
            }
        }
        None => {}
    }
    Ok(())
}

fn forbidden(code: &'static str, message: &str) -> Error {
    Error::Coded {
        status: 403,
        code,
        message: message.into(),
        extra: Default::default(),
    }
}

/// Checks 1 to 3: the local switch, the cited policy's runtime rule for
/// the sender, and the rule's bounds. Returns the rule.
fn authorize(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &TaskRequest,
) -> Result<RuntimeRule, Error> {
    if store.runtime_switch()?.is_none() {
        return Err(forbidden("runtime_disabled", "this host's runtime is off"));
    }
    let cited: &PolicyRef = r.policy.as_ref().ok_or_else(|| invalid("policy"))?;
    let me = store.identity().id;
    // A network this host and the sender share, coordinator-free, whose
    // current policy of the cited person is this host's owner's.
    let networks: Vec<String> = store
        .own_members(conn)?
        .into_iter()
        .filter(|(_, m)| m.person_id.as_deref() == Some(cited.person_id.as_str()))
        .map(|(n, _)| n)
        .collect();
    let mut unavailable = None;
    for network in networks {
        if !crate::decentralized::product::is_decentralized(conn, &network)? {
            continue;
        }
        let Some(sender_member) = store
            .product_member(conn, &network, sender)?
            .filter(|m| m.host_id != me)
        else {
            continue;
        };
        let Some(key) = store.product_person_key(conn, &network, &cited.person_id)? else {
            continue;
        };
        let Some(policy) = store.product_policy(conn, &network, &key)? else {
            unavailable = Some("this host has not yet received the cited policy");
            continue;
        };
        if policy.version < cited.version {
            unavailable = Some("this host has not yet received the cited policy version");
            continue;
        }
        if !policy.in_window(crate::clock::now())
            || crate::task::time(&r.deadline)? > crate::task::time(&policy.valid_until)?
        {
            continue;
        }
        let groups = store.product_groups(conn, &network)?;
        let Some(rule) = policy.runtime_rules().iter().find(|rule| {
            rule.host == me
                && rule.principals.iter().any(|p| {
                    crate::decentralized::product::principal_matches(
                        p,
                        &sender_member,
                        &groups,
                        r.origin.as_ref(),
                    )
                })
        }) else {
            continue;
        };
        if !rule.allow_disconnected
            && !crate::decentralized::peer::current_connected(conn, store, sender)?
        {
            continue;
        }
        if store.blocked(conn, sender)? {
            return Err(Error::Forbidden);
        }
        let run = r.run.as_ref().ok_or_else(|| invalid("run"))?;
        let res = run.resources.clone().unwrap_or_default();
        let over = |v: Option<i64>, max: i64| v.is_some_and(|v| v > max);
        if over(res.cpus, rule.max_cpus)
            || over(res.memory_mib, rule.max_memory_mib)
            || over(res.timeout_seconds, rule.max_seconds)
            || manifest_total(&r.artifacts).unwrap_or(0) > rule.max_artifact_bytes
            || run
                .peerfs_workspace()
                .is_some_and(|name| !rule.peerfs_workspaces.iter().any(|n| n == name))
        {
            return Err(forbidden(
                "forbidden",
                "the run exceeds the runtime rule's bounds",
            ));
        }
        return Ok(rule.clone());
    }
    Err(match unavailable {
        Some(m) => Error::Unavailable(m.into()),
        None => Error::Forbidden,
    })
}

fn internal(conn: &Connection, sender: &str, task_id: &str) -> Result<Internal, Error> {
    let raw: Option<String> = conn.query_row(
        "SELECT json_extract(record, '$.runtime') FROM received_tasks WHERE sender = ?1 AND task_id = ?2",
        params![sender, task_id],
        |r| r.get(0),
    )?;
    Ok(raw
        .map(|r| serde_json::from_str(&r))
        .transpose()?
        .unwrap_or_default())
}
fn save_internal(
    tx: &Transaction<'_>,
    sender: &str,
    task_id: &str,
    value: &Internal,
) -> Result<(), Error> {
    tx.execute(
        "UPDATE received_tasks SET record = json_set(record, '$.runtime', json(?1)) WHERE sender = ?2 AND task_id = ?3",
        params![serde_json::to_string(value)?, sender, task_id],
    )?;
    Ok(())
}
/// Whether a queued runtime task was dispatched, so its deadline no longer
/// applies.
pub(crate) fn dispatched(conn: &Connection, sender: &str, task_id: &str) -> Result<bool, Error> {
    Ok(internal(conn, sender, task_id)?.dispatched)
}

/// Accepts a runtime task as `queued`, idempotently by sender and task ID.
pub(crate) fn accept(store: &Store, sender: &str, r: TaskRequest) -> Result<TaskStatus, Error> {
    validate(&r)?;
    let mut connection = store.connection()?;
    let tx = connection.transaction()?;
    let rule = authorize(store, &tx, sender, &r)?;
    if let Some((old, mut status)) = received(&tx, sender, &r.task_id)? {
        if old != r {
            return Err(Error::Conflict(
                "task ID reused with different fields".into(),
            ));
        }
        if crate::task::expire(&tx, sender, &old, &mut status)? {
            tx.commit()?;
        }
        return Ok(status);
    }
    if let Some(manifest) = &r.artifacts {
        store.reserve(&tx, manifest)?;
    }
    let at = now();
    let mut status = TaskStatus {
        task_id: r.task_id.clone(),
        sender_host_id: sender.into(),
        receiver_host_id: store.identity().id,
        executor: Some(EXECUTOR.into()),
        target_agent_id: String::new(),
        state: "queued".into(),
        cancel_requested: false,
        created_at: at.clone(),
        updated_at: at,
        last_event: 0,
    };
    tx.execute(
        "INSERT INTO received_tasks VALUES (?1, ?2, ?3, ?4)",
        params![
            sender,
            r.task_id,
            serde_json::to_string(&r)?,
            serde_json::to_string(&status)?
        ],
    )?;
    save_internal(
        &tx,
        sender,
        &r.task_id,
        &Internal {
            run_id: run_id(sender, &r.task_id),
            bounds: Some(rule),
            ..Default::default()
        },
    )?;
    record(&tx, sender, &mut status, "queued", None, None, None)?;
    if let Some(manifest) = &r.artifacts {
        crate::artifact::add_artifacts(
            &tx,
            RECEIVED,
            sender,
            &r.task_id,
            INPUT,
            manifest,
            crate::artifact::PENDING,
        )?;
    }
    tx.commit()?;
    store.runtime_wake.notify_one();
    Ok(status)
}

/// A cancellation request just recorded: a queued task not yet dispatched
/// ends `cancelled` at once; a dispatched or running one is forwarded by
/// its follower.
pub(crate) fn cancel_requested(
    tx: &Transaction<'_>,
    sender: &str,
    status: &mut TaskStatus,
) -> Result<(), Error> {
    if status.state == "queued" && !internal(tx, sender, &status.task_id)?.dispatched {
        record(tx, sender, status, "cancelled", None, None, None)?;
    }
    Ok(())
}

/// The run result (The run result), with its keys in the contract's order.
#[derive(Serialize)]
struct RunResult {
    exit_code: Option<i64>,
    signal: Option<i64>,
    timed_out: bool,
    duration_ms: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    output_truncated: bool,
    results_dropped: Vec<String>,
    results_same: BTreeMap<String, String>,
    snapshot: Option<String>,
    error: Option<String>,
}
impl RunResult {
    fn never_started(error: &str) -> Self {
        Self {
            exit_code: None,
            signal: None,
            timed_out: false,
            duration_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            output_truncated: false,
            results_dropped: Vec::new(),
            results_same: BTreeMap::new(),
            snapshot: None,
            error: Some(error.into()),
        }
    }
    fn from_exited(v: &Value, streamed: i64) -> Self {
        let stdout_bytes = v["stdout_bytes"].as_u64().unwrap_or(0);
        let stderr_bytes = v["stderr_bytes"].as_u64().unwrap_or(0);
        Self {
            exit_code: v["exit_code"].as_i64(),
            signal: v["signal"].as_i64(),
            timed_out: v["timed_out"].as_bool().unwrap_or(false),
            duration_ms: v["duration_ms"].as_u64().unwrap_or(0),
            stdout_bytes,
            stderr_bytes,
            output_truncated: (streamed as u64) < stdout_bytes + stderr_bytes,
            results_dropped: Vec::new(),
            results_same: BTreeMap::new(),
            snapshot: v["snapshot"].as_str().map(str::to_owned),
            error: v["error"].as_str().map(str::to_owned),
        }
    }
}

/// One runtime task as the worker sees it.
struct Task {
    sender: String,
    request: TaskRequest,
    status: TaskStatus,
    internal: Internal,
}
fn load(conn: &Connection, sender: &str, task_id: &str) -> Result<Option<Task>, Error> {
    let Some((request, status)) = received(conn, sender, task_id)? else {
        return Ok(None);
    };
    Ok(Some(Task {
        sender: sender.into(),
        request,
        status,
        internal: internal(conn, sender, task_id)?,
    }))
}
/// Runtime tasks not yet final, in `created_at` order.
fn open_tasks(conn: &Connection) -> Result<Vec<(String, String)>, Error> {
    let mut statement = conn.prepare(
        "SELECT sender, task_id FROM received_tasks WHERE json_extract(request, '$.executor') = 'runtime' AND json_extract(record, '$.state') IN ('queued', 'running') ORDER BY json_extract(record, '$.created_at'), rowid",
    )?;
    statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}
fn inputs_stored(conn: &Connection, sender: &str, task_id: &str) -> Result<bool, Error> {
    Ok(conn.query_row(
        "SELECT NOT EXISTS (SELECT 1 FROM task_artifacts WHERE side = 'received' AND peer = ?1 AND task_id = ?2 AND direction = 'input' AND json_extract(record, '$.state') != 'stored')",
        params![sender, task_id],
        |r| r.get(0),
    )?)
}

/// Ends a task with `kind` and its output, in one transaction.
fn finish(
    store: &Store,
    sender: &str,
    task_id: &str,
    kind: &str,
    message: Option<String>,
    output: Option<String>,
    artifacts: Option<Vec<ArtifactEntry>>,
) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let Some((_, mut status)) = received(&tx, sender, task_id)? else {
        return Ok(());
    };
    if is_final(&status.state) {
        return Ok(());
    }
    if kind != "rejected" && kind != "cancelled" && status.state == "running" {
        append_event(
            &tx,
            "task.run_exited",
            &format!("{sender}/{task_id}"),
            &now(),
        )?;
    }
    record(
        &tx,
        sender,
        &mut status,
        kind,
        message,
        output,
        artifacts.clone(),
    )?;
    if let Some(results) = &artifacts {
        crate::artifact::add_artifacts(
            &tx,
            RECEIVED,
            sender,
            task_id,
            RESULT,
            results,
            crate::artifact::STORED,
        )?;
    }
    tx.commit()?;
    Ok(())
}
fn set_dispatched(
    store: &Store,
    sender: &str,
    task_id: &str,
    socket: Option<PathBuf>,
) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let mut i = internal(&tx, sender, task_id)?;
    i.dispatched = socket.is_some();
    if socket.is_some() {
        i.socket = socket;
    }
    save_internal(&tx, sender, task_id, &i)?;
    tx.commit()?;
    Ok(())
}

/// The start request for a task (`POST /v1/runs`).
fn start_body(store: &Store, t: &Task) -> Result<Value, Error> {
    let run = t.request.run.as_ref().ok_or_else(|| invalid("run"))?;
    let rule = t
        .internal
        .bounds
        .as_ref()
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("a runtime task without bounds")))?;
    let res = run.resources.clone().unwrap_or_default();
    let archive = match &run.workspace {
        Some(Workspace::Archive(sha)) => Some(
            store
                .artifact_dir()
                .join(sha)
                .to_string_lossy()
                .into_owned(),
        ),
        _ => None,
    };
    Ok(json!({
        "run_id": t.internal.run_id,
        "argv": run.argv,
        "cwd": run.cwd.clone().unwrap_or_else(|| "/workspace".into()),
        "env": run.env.clone().unwrap_or_default(),
        "resources": {
            "cpus": res.cpus.unwrap_or(rule.max_cpus),
            "memory_mib": res.memory_mib.unwrap_or(rule.max_memory_mib),
            "timeout_seconds": res.timeout_seconds.unwrap_or(rule.max_seconds),
        },
        "workspace_archive": archive,
        "peerfs_workspace": run.peerfs_workspace(),
        "results": run.results.clone().unwrap_or_else(|| "output".into()),
    }))
}

enum Started {
    /// 201 or 200: the run exists.
    Accepted,
    /// 429: no run exists, and no slot is free.
    Busy,
    /// The task ended: refused (422 or another definite refusal), or
    /// cancelled because no run exists.
    Ended,
    /// No answer: the task stays dispatched and the start is sent again.
    Unknown,
}

/// Sends a dispatched task's start and applies a definite answer.
async fn start(store: &Arc<Store>, sender: &str, task_id: &str) -> Result<Started, Error> {
    let (body, socket) = {
        let s = store.clone();
        let (sender, task_id) = (sender.to_owned(), task_id.to_owned());
        crate::api::blocking(s, move |s| {
            let conn = s.connection()?;
            let t = load(&conn, &sender, &task_id)?.ok_or(Error::NotFound)?;
            Ok((start_body(s, &t)?, t.internal.socket.clone()))
        })
        .await?
    };
    let Some(socket) = socket else {
        return Ok(Started::Unknown);
    };
    let answer = match call(&socket, Method::POST, "/v1/runs", Some(&body)).await {
        Ok(a) => a,
        Err(_) => return Ok(Started::Unknown),
    };
    let (sender, task_id) = (sender.to_owned(), task_id.to_owned());
    crate::api::blocking(store.clone(), move |s| {
        let conn = s.connection()?;
        let Some(t) = load(&conn, &sender, &task_id)? else {
            return Ok(Started::Ended);
        };
        drop(conn);
        match answer.status {
            200 | 201 => Ok(Started::Accepted),
            429 => {
                set_dispatched(s, &sender, &task_id, None)?;
                if t.status.cancel_requested {
                    finish(s, &sender, &task_id, "cancelled", None, None, None)?;
                    return Ok(Started::Ended);
                }
                Ok(Started::Busy)
            }
            400..=499 => {
                set_dispatched(s, &sender, &task_id, None)?;
                if t.status.cancel_requested {
                    finish(s, &sender, &task_id, "cancelled", None, None, None)?;
                } else {
                    let message = format!("the runtime refused the run: {}", refusal(&answer));
                    finish(s, &sender, &task_id, "rejected", Some(message), None, None)?;
                }
                Ok(Started::Ended)
            }
            _ => Ok(Started::Unknown),
        }
    })
    .await
}
fn refusal(answer: &Answer) -> String {
    answer.body["error"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("status {}", answer.status))
}

/// The worker's followers: one per dispatched or running task.
type Following = Arc<Mutex<HashSet<(String, String)>>>;

/// Dispatches queued runtime tasks and follows dispatched ones until
/// shutdown.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let following: Following = Default::default();
    loop {
        if let Err(e) = pass(&store, &following, &shutdown).await {
            eprintln!("runtime tasks: {e:?}");
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = store.runtime_wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

/// One scheduling pass: followers for dispatched and running tasks, then
/// queued tasks started in order while the runtime has free slots.
async fn pass(
    store: &Arc<Store>,
    following: &Following,
    shutdown: &watch::Receiver<bool>,
) -> Result<(), Error> {
    let tasks = crate::api::blocking(store.clone(), |s| {
        let conn = s.connection()?;
        let mut out = Vec::new();
        for (sender, id) in open_tasks(&conn)? {
            if let Some(t) = load(&conn, &sender, &id)? {
                let ready = inputs_stored(&conn, &sender, &id)?;
                out.push((t, ready));
            }
        }
        Ok(out)
    })
    .await?;
    // Runs on one peerfs workspace take turns: a queued task waits while
    // another task on its workspace is dispatched or running.
    let mut in_use: HashSet<String> = tasks
        .iter()
        .filter(|(t, _)| t.internal.dispatched || t.status.state == "running")
        .filter_map(|(t, _)| t.request.run.as_ref()?.peerfs_workspace())
        .map(str::to_owned)
        .collect();
    // Free slots, from the runtime's own report; none while it is off or
    // unreachable, so a queued task is started only into a free slot.
    let mut free: Option<i64> = None;
    for (t, ready) in tasks {
        let key = (t.sender.clone(), t.status.task_id.clone());
        if t.internal.dispatched || t.status.state == "running" {
            follow(store, following, shutdown, key, false);
            continue;
        }
        let workspace = t
            .request
            .run
            .as_ref()
            .and_then(RunSpec::peerfs_workspace)
            .map(str::to_owned);
        if t.status.cancel_requested
            || !ready
            || workspace.as_ref().is_some_and(|w| in_use.contains(w))
        {
            continue;
        }
        if free.is_none() {
            let switch = crate::api::blocking(store.clone(), |s| s.runtime_switch()).await?;
            free = Some(match switch {
                Some(switch) => match crate::runtime::report(&switch.socket).await {
                    Ok(r) => {
                        r["max_concurrent_runs"].as_i64().unwrap_or(0)
                            - r["running"].as_i64().unwrap_or(0)
                    }
                    Err(_) => 0,
                },
                // The switch off rejects at the recheck below.
                None => 1,
            });
        }
        if free.is_some_and(|f| f <= 0) {
            break;
        }
        // The rechecks before a start: a final failure rejects, and a
        // recoverable one leaves the task queued.
        let s = store.clone();
        let (sender, id) = key.clone();
        let socket = crate::api::blocking(s, move |s| {
            let mut conn = s.connection()?;
            let tx = conn.transaction()?;
            let Some((request, mut status)) = received(&tx, &sender, &id)? else {
                return Ok(None);
            };
            if status.state != "queued" || crate::task::expire(&tx, &sender, &request, &mut status)?
            {
                tx.commit()?;
                return Ok(None);
            }
            let rule = match authorize(s, &tx, &sender, &request) {
                Ok(rule) => rule,
                Err(Error::Unavailable(_)) => return Ok(None),
                Err(e) => {
                    let reason = match e {
                        Error::Coded { message, .. } => message,
                        _ => crate::task::LAPSED.into(),
                    };
                    record(
                        &tx,
                        &sender,
                        &mut status,
                        "rejected",
                        Some(reason),
                        None,
                        None,
                    )?;
                    tx.commit()?;
                    return Ok(None);
                }
            };
            let socket = s.runtime_switch()?.map(|w| w.socket);
            let mut i = internal(&tx, &sender, &id)?;
            i.bounds = Some(rule);
            i.dispatched = true;
            i.socket = socket.clone();
            save_internal(&tx, &sender, &id, &i)?;
            tx.commit()?;
            Ok(socket)
        })
        .await?;
        if socket.is_none() {
            continue;
        }
        free = free.map(|f| f - 1);
        if let Some(w) = workspace.clone() {
            in_use.insert(w);
        }
        match start(store, &key.0, &key.1).await? {
            Started::Accepted => follow(store, following, shutdown, key, true),
            Started::Unknown => follow(store, following, shutdown, key, false),
            // The runtime holds the workspace for a run of its own: later
            // tasks may still start.
            Started::Busy if workspace.is_some() => free = free.map(|f| f + 1),
            // Every slot is busy: later tasks wait their turn.
            Started::Busy => break,
            Started::Ended => {}
        }
    }
    Ok(())
}

fn follow(
    store: &Arc<Store>,
    following: &Following,
    shutdown: &watch::Receiver<bool>,
    key: (String, String),
    answered: bool,
) {
    if !following.lock().expect("followers").insert(key.clone()) {
        return;
    }
    let (store, following, shutdown) = (store.clone(), following.clone(), shutdown.clone());
    tokio::spawn(async move {
        if let Err(e) = follower(&store, &key, answered, shutdown).await {
            eprintln!("runtime task {}/{}: {e:?}", key.0, key.1);
        }
        following.lock().expect("followers").remove(&key);
        store.runtime_wake.notify_one();
    });
}

/// Follows one dispatched task to its end: sends its start again while it
/// is unanswered, forwards a cancellation once no start is outstanding,
/// and stores the runtime's events.
async fn follower(
    store: &Arc<Store>,
    key: &(String, String),
    mut answered: bool,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Error> {
    let (sender, id) = (key.0.clone(), key.1.clone());
    let mut cancel_sent = false;
    let mut first_held: Option<Instant> = None;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let t = {
            let (sender, id) = (sender.clone(), id.clone());
            crate::api::blocking(store.clone(), move |s| {
                let conn = s.connection()?;
                load(&conn, &sender, &id)
            })
            .await?
        };
        let Some(t) = t else { return Ok(()) };
        if is_final(&t.status.state) {
            return Ok(());
        }
        if t.status.state == "queued" && !t.internal.dispatched {
            return Ok(());
        }
        let Some(socket) = t.internal.socket.clone() else {
            return Ok(());
        };
        // An unanswered start is sent again, unless cancellation was
        // requested: then no start is outstanding after a restart.
        if t.status.state == "queued" && !answered && !t.status.cancel_requested {
            match start(store, &sender, &id).await? {
                Started::Accepted => answered = true,
                Started::Busy | Started::Ended => return Ok(()),
                Started::Unknown => {
                    pause(&mut shutdown, Duration::from_secs(1)).await;
                    continue;
                }
            }
        }
        let path = format!("/v1/runs/{}", t.internal.run_id);
        if t.status.cancel_requested && !cancel_sent {
            match call(
                &socket,
                Method::POST,
                &format!("{path}/cancel"),
                Some(&json!({})),
            )
            .await
            {
                Ok(a) if a.status == 404 => {
                    let (s, sender, id) = (store.clone(), sender.clone(), id.clone());
                    crate::api::blocking(s, move |s| {
                        finish(s, &sender, &id, "cancelled", None, None, None)
                    })
                    .await?;
                    return Ok(());
                }
                Ok(_) => cancel_sent = true,
                Err(_) => {
                    pause(&mut shutdown, Duration::from_secs(1)).await;
                    continue;
                }
            }
        }
        let holding = !t.internal.held.is_empty();
        // A cancellation that arrives while waiting is noticed at once, or
        // at the latest after 5 seconds.
        let wait = if holding { 0 } else { 5 };
        // Paged like a peer's events, within the 1 MiB runtime response limit.
        let events_path = format!(
            "{path}/events?after={}&wait={wait}&limit={}",
            t.internal.after,
            crate::task_outbound::RUNTIME_EVENT_PAGE
        );
        let answer = tokio::select! {
            a = call(&socket, Method::GET, &events_path, None) => a,
            _ = store.runtime_cancel.notified(), if !t.status.cancel_requested => {
                // A cancellation may have arrived: look again.
                continue;
            }
            _ = shutdown.changed() => return Ok(()),
        };
        let events = match answer {
            Ok(a) if a.status == 404 => {
                // The runtime does not know the run.
                let (s, sender, id) = (store.clone(), sender.clone(), id.clone());
                crate::api::blocking(s, move |s| lost(s, &sender, &id)).await?;
                return Ok(());
            }
            Ok(a) if a.status == 200 => a.body.as_array().cloned().unwrap_or_default(),
            _ => {
                pause(&mut shutdown, Duration::from_secs(1)).await;
                continue;
            }
        };
        if !events.is_empty() && first_held.is_none() {
            first_held = Some(Instant::now());
        }
        let flush = first_held.is_some_and(|f| f.elapsed() >= HOLD);
        let (s, sender2, id2) = (store.clone(), sender.clone(), id.clone());
        let outcome =
            crate::api::blocking(s, move |s| apply(s, &sender2, &id2, events, flush)).await?;
        match outcome {
            Applied::Holding => {}
            Applied::Empty => first_held = None,
            Applied::Results(artifacts) => {
                let (s, sender2, id2) = (store.clone(), sender.clone(), id.clone());
                crate::api::blocking(s, move |s| results(s, &sender2, &id2, artifacts)).await?;
                let _ = call(&socket, Method::DELETE, &path, None).await;
                return Ok(());
            }
        }
        if holding || first_held.is_some() {
            pause(&mut shutdown, HOLD / 5).await;
        }
    }
}
async fn pause(shutdown: &mut watch::Receiver<bool>, d: Duration) {
    tokio::select! {
        _ = shutdown.changed() => {}
        _ = tokio::time::sleep(d) => {}
    }
}

/// A run the runtime does not know (404): a cancelled task ends
/// `cancelled`; otherwise the task fails with `the runtime restarted`.
fn lost(store: &Store, sender: &str, id: &str) -> Result<(), Error> {
    let conn = store.connection()?;
    let Some(t) = load(&conn, sender, id)? else {
        return Ok(());
    };
    drop(conn);
    if t.status.cancel_requested {
        return finish(store, sender, id, "cancelled", None, None, None);
    }
    let result = RunResult::never_started(RESTARTED);
    let output = match &t.internal.exited {
        Some(v) => {
            let mut r = RunResult::from_exited(v, t.internal.streamed);
            r.error = Some(RESTARTED.into());
            r
        }
        None if t.internal.started => RunResult {
            duration_ms: 0,
            ..result
        },
        None => result,
    };
    finish(
        store,
        sender,
        id,
        "failed",
        None,
        Some(serde_json::to_string(&output)?),
        None,
    )
}

enum Applied {
    /// Output is held for the next `output` event.
    Holding,
    /// Nothing is held.
    Empty,
    /// The runtime reported its results: the artifact list.
    Results(Vec<Value>),
}

/// Stores a page of runtime events: `started` moves the task to
/// `running`, output is held and emitted as `output` events, and `exited`
/// is kept for the final event, which `results` triggers.
fn apply(
    store: &Store,
    sender: &str,
    id: &str,
    events: Vec<Value>,
    flush: bool,
) -> Result<Applied, Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let Some(mut t) = load(&tx, sender, id)? else {
        return Ok(Applied::Empty);
    };
    let max_output = t.internal.bounds.as_ref().map_or(0, |b| b.max_output_bytes);
    let mut results = None;
    for event in events {
        let sequence = event["sequence"].as_u64().unwrap_or(0);
        if sequence <= t.internal.after {
            continue;
        }
        t.internal.after = sequence;
        match event["kind"].as_str().unwrap_or_default() {
            "started" if t.status.state == "queued" => {
                t.internal.started = true;
                record(&tx, sender, &mut t.status, "accepted", None, None, None)?;
                append_event(&tx, "task.run_started", &format!("{sender}/{id}"), &now())?;
            }
            stream @ ("stdout" | "stderr") => {
                let data = STANDARD
                    .decode(event["data"].as_str().unwrap_or_default())
                    .unwrap_or_default();
                let mut held = t
                    .internal
                    .held
                    .get(stream)
                    .map(|h| STANDARD.decode(h).unwrap_or_default())
                    .unwrap_or_default();
                held.extend_from_slice(&data);
                while held.len() >= CHUNK {
                    let rest = held.split_off(CHUNK);
                    emit(&tx, sender, &mut t, stream, &held, max_output)?;
                    held = rest;
                }
                if held.is_empty() {
                    t.internal.held.remove(stream);
                } else {
                    t.internal.held.insert(stream.into(), STANDARD.encode(held));
                }
            }
            "exited" => {
                flush_held(&tx, sender, &mut t, max_output)?;
                t.internal.exited = Some(event["result"].clone());
            }
            "results" => {
                // Not acknowledged: until `results(...)` makes the task final,
                // a restarted follower fetches this last event again.
                t.internal.after = sequence - 1;
                results = Some(event["artifacts"].as_array().cloned().unwrap_or_default());
            }
            _ => {}
        }
    }
    if flush {
        flush_held(&tx, sender, &mut t, max_output)?;
    }
    save_internal(&tx, sender, id, &t.internal)?;
    tx.commit()?;
    Ok(match results {
        Some(r) => Applied::Results(r),
        None if t.internal.held.is_empty() => Applied::Empty,
        None => Applied::Holding,
    })
}
fn flush_held(
    tx: &Transaction<'_>,
    sender: &str,
    t: &mut Task,
    max_output: i64,
) -> Result<(), Error> {
    for stream in ["stdout", "stderr"] {
        if let Some(h) = t.internal.held.remove(stream) {
            let data = STANDARD.decode(h).unwrap_or_default();
            if !data.is_empty() {
                emit(tx, sender, t, stream, &data, max_output)?;
            }
        }
    }
    Ok(())
}
/// Emits one `output` event, cut at what `max_output_bytes` still allows.
fn emit(
    tx: &Transaction<'_>,
    sender: &str,
    t: &mut Task,
    stream: &str,
    data: &[u8],
    max_output: i64,
) -> Result<(), Error> {
    if t.status.state != "running" {
        return Ok(());
    }
    let room = usize::try_from(max_output - t.internal.streamed).unwrap_or(0);
    let data = &data[..data.len().min(room)];
    if data.is_empty() {
        return Ok(());
    }
    t.internal.streamed += data.len() as i64;
    record_output(
        tx,
        sender,
        &mut t.status,
        Chunk {
            stream: stream.into(),
            data: STANDARD.encode(data),
        },
    )
}

/// The final event: the run result, and the result files copied into the
/// artifact store that fit (Result artifacts).
fn results(store: &Store, sender: &str, id: &str, artifacts: Vec<Value>) -> Result<(), Error> {
    let conn = store.connection()?;
    let Some(t) = load(&conn, sender, id)? else {
        return Ok(());
    };
    drop(conn);
    if is_final(&t.status.state) {
        return Ok(());
    }
    let exited = t.internal.exited.clone().unwrap_or(Value::Null);
    let mut result = RunResult::from_exited(&exited, t.internal.streamed);
    let kind = if t.status.cancel_requested {
        "cancelled"
    } else if !t.internal.started {
        "failed"
    } else if result.exit_code == Some(0) && !result.timed_out {
        "succeeded"
    } else {
        "failed"
    };
    let mut attached: Vec<ArtifactEntry> = Vec::new();
    if kind != "cancelled" {
        let bound = t
            .internal
            .bounds
            .as_ref()
            .map_or(0, |b| b.max_artifact_bytes);
        let mut used = manifest_total(&t.request.artifacts).unwrap_or(0);
        let mut changes_dropped = false;
        for a in artifacts {
            let name = a["name"].as_str().unwrap_or_default().to_owned();
            let size = a["size"].as_i64().unwrap_or(0);
            let sha = a["sha256"].as_str().unwrap_or_default().to_owned();
            if size == 0 {
                continue;
            }
            if name == "deleted.txt" && changes_dropped {
                result.results_dropped.push(name);
                continue;
            }
            if let Some(earlier) = attached.iter().find(|e| e.sha256 == sha) {
                result.results_same.insert(name, earlier.name.clone());
                continue;
            }
            let fits = size <= MAX_FILE && used + size <= bound;
            let stored = fits
                .then(|| copy_result(store, &a, &name, size, &sha))
                .and_then(Result::ok);
            match stored {
                Some(entry) => {
                    used += size;
                    attached.push(entry);
                }
                None => {
                    if name == "changes.tar" {
                        changes_dropped = true;
                    }
                    result.results_dropped.push(name);
                }
            }
        }
    }
    let artifacts = (!attached.is_empty()).then_some(attached);
    let output = serde_json::to_string(&result)?;
    finish(store, sender, id, kind, None, Some(output), artifacts)
}

/// Copies one result file into the artifact store, verifying its size and
/// digest.
fn copy_result(
    store: &Store,
    a: &Value,
    name: &str,
    size: i64,
    sha: &str,
) -> Result<ArtifactEntry, Error> {
    let path = a["path"]
        .as_str()
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("a result without a path")))?;
    let media_type = a["media_type"]
        .as_str()
        .unwrap_or("application/octet-stream");
    let temp = store.artifact_dir().join(crate::store::new_id("partial")?);
    let copied = (|| -> std::io::Result<(i64, String)> {
        let mut from = std::fs::File::open(path)?;
        let mut to = std::fs::File::create(&temp)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0; 1 << 16];
        let mut total = 0i64;
        loop {
            let n = from.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            to.write_all(&buf[..n])?;
            total += n as i64;
        }
        to.sync_all()?;
        Ok((total, hex::encode(hasher.finalize())))
    })();
    match copied {
        Ok((total, digest)) if total == size && digest == sha => {
            store.finish_upload(temp, size, sha.into(), name.into(), media_type.into())
        }
        other => {
            let _ = std::fs::remove_file(&temp);
            Err(Error::Internal(anyhow::anyhow!(
                "result {name} did not match its report: {:?}",
                other.map(|(n, _)| n)
            )))
        }
    }
}
