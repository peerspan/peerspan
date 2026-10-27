//! Single-hop task delegation (roadmap milestone 6, slice 2): the receiving
//! host. A peer submits a task for a local agent; the host persists it as
//! `queued`, hands it to an attached session of that agent through the
//! adapter, and records the agent's lifecycle as a per-task event sequence
//! that only the submitter can read.
use crate::{
    adapter::{authority, read},
    adapter_connection::AdapterAuth,
    api::{blocking, decode},
    artifact::{
        ArtifactEntry, INPUT, RECEIVED, RESULT, manifest_total, normalized, validate_manifest,
    },
    chain::{Carried, Link, Verified},
    model::Error,
    peer_store::{Authz, Bounds, Connectivity, Origin, valid_id},
    policy::{PolicyRef, TASK_ACTION},
    store::{Store, append_event, new_id, now},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Database version 9: received and outbound tasks, their events, task
/// deliveries to sessions, and task-update notifications.
pub(crate) const SCHEMA: &str = "
CREATE TABLE received_tasks (sender TEXT NOT NULL, task_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, task_id));
CREATE TABLE task_events (sender TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, task_id, sequence));
CREATE TABLE outbound_tasks (peer TEXT NOT NULL, task_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, task_id));
CREATE TABLE outbound_task_events (peer TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, task_id, sequence));
CREATE TABLE task_deliveries (id TEXT PRIMARY KEY, sender TEXT NOT NULL, task_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, task_id));
CREATE TABLE task_update_notifications (id TEXT PRIMARY KEY, peer TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, UNIQUE(peer, task_id, sequence));
PRAGMA user_version = 9;
";

/// Task input, progress messages, rejection reasons, and outputs are text of
/// at most this many UTF-8 bytes.
pub const MAX_TEXT: usize = 65536;
/// States no further event changes.
pub const FINAL_STATES: [&str; 5] = ["rejected", "expired", "succeeded", "failed", "cancelled"];
pub(crate) fn is_final(state: &str) -> bool {
    FINAL_STATES.contains(&state)
}
const EVENT_KINDS: [&str; 9] = [
    "queued",
    "accepted",
    "rejected",
    "progress",
    "cancel_requested",
    "succeeded",
    "failed",
    "cancelled",
    "expired",
];
pub(crate) const STATES: [&str; 7] = [
    "queued",
    "running",
    "rejected",
    "expired",
    "succeeded",
    "failed",
    "cancelled",
];

/// A task as submitted on the wire, stored unchanged by the receiver.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    pub task_id: String,
    /// Exactly one of `grant_id` and `policy` names the authorization; on
    /// the wire the other is absent, never null or empty.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub grant_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub policy: Option<PolicyRef>,
    /// Self access: the sender's bound person (launch slice 3).
    #[serde(
        rename = "self",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub self_access: Option<crate::policy::SelfRef>,
    pub target_agent_id: String,
    pub deadline: String,
    pub input: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub origin: Option<Origin>,
    /// The input artifact manifest (milestone 6 slice 3).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub artifacts: Option<Vec<ArtifactEntry>>,
    /// The delegation chain (milestone 6 slice 4): 1 to 3 links, the last
    /// naming this hop.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub delegation: Option<Vec<Link>>,
}
impl TaskRequest {
    pub(crate) fn authz(&self) -> Authz<'_> {
        Authz {
            action: TASK_ACTION,
            grant_id: self.grant_id.as_deref(),
            policy: self.policy.as_ref(),
            self_access: self.self_access.as_ref(),
            target_agent_id: &self.target_agent_id,
            deadline: &self.deadline,
            size: self.input.len(),
            origin: self.origin.as_ref(),
            artifacts: manifest_total(&self.artifacts),
        }
    }
}

/// The receiver's status record, served only to the submitter.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskStatus {
    pub task_id: String,
    pub sender_host_id: String,
    pub receiver_host_id: String,
    pub target_agent_id: String,
    pub state: String,
    pub cancel_requested: bool,
    pub created_at: String,
    pub updated_at: String,
    /// The highest event sequence.
    pub last_event: i64,
}

/// One entry of a task's event sequence. Fields that do not apply are null.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskEvent {
    pub sequence: i64,
    pub kind: String,
    pub state: String,
    pub message: Option<String>,
    pub output: Option<String>,
    pub created_at: String,
    /// The result manifest on a final `succeeded` or `failed` event with
    /// results; null otherwise.
    #[serde(default)]
    pub artifacts: Option<Vec<ArtifactEntry>>,
}
impl TaskEvent {
    /// The shape a submitter accepts from a receiver.
    pub(crate) fn well_formed(&self) -> bool {
        self.artifacts.as_ref().is_none_or(|m| {
            matches!(self.kind.as_str(), "succeeded" | "failed") && validate_manifest(m).is_ok()
        }) && EVENT_KINDS.contains(&self.kind.as_str())
            && STATES.contains(&self.state.as_str())
            && self.message.as_ref().is_none_or(|m| m.len() <= MAX_TEXT)
            && self.output.as_ref().is_none_or(|o| o.len() <= MAX_TEXT)
            && DateTime::parse_from_rfc3339(&self.created_at).is_ok()
    }
}

/// A task claimed by one session. Only that session may change the task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDelivery {
    pub id: String,
    pub sender_host_id: String,
    pub task_id: String,
    pub target_agent_id: String,
    pub session_id: String,
    pub adapter_id: String,
    /// When the session claimed this task's cancellation request.
    pub cancel_claimed_at: Option<String>,
    pub created_at: String,
}
#[derive(Serialize)]
pub struct TaskHandoff {
    pub delivery: TaskDelivery,
    pub task: TaskRequest,
    pub status: TaskStatus,
    /// The person the sending host is bound to, and its label; null when
    /// the sender is unbound.
    pub sender_person_id: Option<String>,
    pub sender_person: Option<String>,
    /// The person the chain's originator host is bound to; null without a
    /// chain or when unbound.
    pub originator_person_id: Option<String>,
    /// Whether the agent may pass this task on: the authorization includes
    /// `task.delegate` and the chain allows another hop.
    pub delegable: bool,
    /// Whether this task was claimed again after its holding authorization
    /// ended before the task was accepted or rejected.
    pub redelivered: bool,
    /// Whether this session adopted the task while it was running.
    pub adopted: bool,
    /// The latest progress message, or null.
    pub progress: Option<String>,
}
#[derive(Serialize)]
pub struct CancelHandoff {
    pub delivery: TaskDelivery,
    pub status: TaskStatus,
}

/// An agent's change to a task it claimed.
pub enum Change {
    Accept,
    Reject(String),
    Progress(String),
    Complete {
        status: String,
        output: String,
        artifacts: Option<Vec<ArtifactEntry>>,
    },
    Cancelled,
}

pub(crate) fn validate_task(r: &TaskRequest) -> Result<(), Error> {
    let authorization = crate::peer_store::one_authorization(
        r.grant_id.as_deref(),
        r.policy.as_ref(),
        r.self_access.as_ref(),
    );
    if !valid_id(&r.task_id, "task", 16)
        || !authorization
        || r.origin.as_ref().is_some_and(|o| !o.valid())
        || !valid_id(&r.target_agent_id, "agent", 16)
        || r.input.is_empty()
        || r.input.len() > MAX_TEXT
    {
        return Err(Error::Invalid("invalid task".into()));
    }
    if let Some(manifest) = &r.artifacts {
        validate_manifest(manifest)?;
    }
    if let Some(chain) = &r.delegation {
        crate::chain::validate(chain)?;
    }
    DateTime::parse_from_rfc3339(&r.deadline)
        .map_err(|_| Error::Invalid("invalid deadline".into()))?;
    Ok(())
}
pub(crate) fn time(text: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| Error::Internal(e.into()))
}
/// The receiver-side activity kind for an event kind.
fn activity(kind: &str) -> &'static str {
    match kind {
        "queued" => "task.received",
        "accepted" => "task.accepted",
        "rejected" => "task.rejected",
        "progress" => "task.progress",
        "cancel_requested" => "task.cancel_requested",
        "cancelled" => "task.cancelled",
        "expired" => "task.expired",
        _ => "task.completed",
    }
}
fn text(value: &str, empty: bool) -> Result<(), Error> {
    if (!empty && value.is_empty()) || value.len() > MAX_TEXT {
        return Err(Error::Invalid(
            "text must be nonempty and at most 65536 bytes".into(),
        ));
    }
    Ok(())
}
/// The stored record of a received task: the status record plus what the
/// authorization checked at acceptance allowed, which is never served: the
/// artifact bound and whether the agent may pass the task on.
const INTERNAL_KEYS: [&str; 2] = ["max_artifact_bytes", "delegable"];
pub(crate) fn status_record(text: &str) -> Result<TaskStatus, Error> {
    let mut value: serde_json::Value = serde_json::from_str(text)?;
    if let Some(object) = value.as_object_mut() {
        for key in INTERNAL_KEYS {
            object.remove(key);
        }
    }
    Ok(serde_json::from_value(value)?)
}
/// Whether a received task's acceptance allowed `task.delegate`.
pub(crate) fn delegable(conn: &Connection, sender: &str, id: &str) -> Result<bool, Error> {
    let value: Option<bool> = conn.query_row(
        "SELECT json_extract(record, '$.delegable') FROM received_tasks WHERE sender = ?1 AND task_id = ?2",
        params![sender, id],
        |r| r.get(0),
    )?;
    Ok(value.unwrap_or(false))
}
/// Verifies a request's chain, then authorizes the request: the sender for a
/// single hop, and the originator past one link. Returns the bounds, the
/// authorized host, and what the chain established.
pub(crate) fn task_bounds(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &TaskRequest,
    require_deadline: bool,
) -> Result<(Bounds, String, Option<Verified>), Error> {
    let verified = match &r.delegation {
        Some(chain) => Some(store.verify_chain(
            conn,
            sender,
            &Carried {
                chain,
                task_id: &r.task_id,
                deadline: &r.deadline,
                origin_agent_id: r.origin.as_ref().map(|o| o.agent_id.as_str()),
            },
            require_deadline,
        )?),
        None => None,
    };
    let (subject, origin) = match &verified {
        Some(v) if v.chain_hosts.len() > 1 => (
            v.originator_host_id.clone(),
            Some(Origin {
                agent_id: v.originator_agent_id.clone(),
                session_id: None,
            }),
        ),
        _ => (sender.to_owned(), r.origin.clone()),
    };
    let mut authz = r.authz();
    authz.origin = origin.as_ref();
    let bounds = store.message_bounds(conn, &subject, &authz, require_deadline)?;
    Ok((bounds, subject, verified))
}
pub(crate) fn received(
    conn: &Connection,
    sender: &str,
    id: &str,
) -> Result<Option<(TaskRequest, TaskStatus)>, Error> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT request, record FROM received_tasks WHERE sender = ?1 AND task_id = ?2",
            params![sender, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(r, s)| Ok((serde_json::from_str(&r)?, status_record(&s)?)))
        .transpose()
}
fn last_event(conn: &Connection, sender: &str, status: &TaskStatus) -> Result<TaskEvent, Error> {
    read(
        conn,
        "SELECT record FROM task_events WHERE sender = ?1 AND task_id = ?2 AND sequence = ?3",
        params![sender, status.task_id, status.last_event],
    )
}
/// Appends one event and the state it leaves the task in, with its activity,
/// in the caller's transaction.
pub(crate) fn record(
    tx: &Transaction<'_>,
    sender: &str,
    status: &mut TaskStatus,
    kind: &str,
    message: Option<String>,
    output: Option<String>,
    artifacts: Option<Vec<ArtifactEntry>>,
) -> Result<TaskEvent, Error> {
    let at = now();
    let state = match kind {
        "accepted" | "progress" => "running",
        "cancel_requested" => status.state.as_str(),
        other => other,
    }
    .to_owned();
    let event = TaskEvent {
        sequence: status.last_event + 1,
        kind: kind.into(),
        state: state.clone(),
        message,
        output,
        created_at: at.clone(),
        artifacts,
    };
    status.state = state;
    status.last_event = event.sequence;
    status.updated_at = at.clone();
    if kind == "cancel_requested" {
        status.cancel_requested = true;
    }
    tx.execute(
        "INSERT INTO task_events VALUES (?1, ?2, ?3, ?4)",
        params![
            sender,
            status.task_id,
            event.sequence,
            serde_json::to_string(&event)?
        ],
    )?;
    // What acceptance allowed stays with the record.
    let old: String = tx.query_row(
        "SELECT record FROM received_tasks WHERE sender = ?1 AND task_id = ?2",
        params![sender, status.task_id],
        |r| r.get(0),
    )?;
    let old: serde_json::Value = serde_json::from_str(&old)?;
    let mut new = serde_json::to_value(&*status)?;
    for key in INTERNAL_KEYS {
        if let (Some(value), Some(object)) = (old.get(key), new.as_object_mut()) {
            object.insert(key.into(), value.clone());
        }
    }
    tx.execute(
        "UPDATE received_tasks SET record = ?1 WHERE sender = ?2 AND task_id = ?3",
        params![serde_json::to_string(&new)?, sender, status.task_id],
    )?;
    append_event(
        tx,
        activity(kind),
        &format!("{sender}/{}", status.task_id),
        &at,
    )?;
    Ok(event)
}
/// A task still queued at its deadline becomes `expired`. Returns whether it
/// changed.
pub(crate) fn expire(
    tx: &Transaction<'_>,
    sender: &str,
    request: &TaskRequest,
    status: &mut TaskStatus,
) -> Result<bool, Error> {
    if status.state != "queued" || time(&request.deadline)? > Utc::now() {
        return Ok(false);
    }
    record(tx, sender, status, "expired", None, None, None)?;
    Ok(true)
}
/// The rejection reason when authorization lapses before an agent accepts.
pub const LAPSED: &str = "authorization lapsed before acceptance";
/// Whether an agent may pass a task on: its authorization includes
/// `task.delegate`, and its chain allows another hop.
fn may_delegate(bounds: &Bounds, verified: Option<&Verified>) -> bool {
    bounds.delegate && verified.is_some_and(|v| v.depth >= 1)
}
/// Rechecks a queued task's authorization, chain included. `Ok(Ok(..))`
/// admits it, `Ok(Err(reason))` is a final lapse, and `Unavailable` can
/// recover.
#[allow(clippy::type_complexity)]
fn recheck(
    store: &Store,
    tx: &Transaction<'_>,
    sender: &str,
    request: &TaskRequest,
) -> Result<Result<(Bounds, Option<Verified>), String>, Error> {
    match task_bounds(store, tx, sender, request, true) {
        Ok((bounds, subject, verified)) => match store.grant_connected(tx, &subject, &bounds)? {
            Connectivity::Usable => Ok(Ok((bounds, verified))),
            Connectivity::Stale => Err(Error::Unavailable("coordination disconnected".into())),
            Connectivity::Absent => Ok(Err(LAPSED.into())),
        },
        Err(Error::Forbidden) => Ok(Err(LAPSED.into())),
        Err(e) => Err(e),
    }
}

impl Store {
    /// Accepts a submitted task as `queued`, idempotently by sender and task ID.
    pub fn accept_task(&self, sender: &str, r: TaskRequest) -> Result<TaskStatus, Error> {
        validate_task(&r)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (bounds, subject, _) = task_bounds(self, &tx, sender, &r, true)?;
        match self.grant_connected(&tx, &subject, &bounds)? {
            Connectivity::Usable => {}
            Connectivity::Stale => {
                return Err(Error::Unavailable("coordination disconnected".into()));
            }
            Connectivity::Absent => return Err(Error::Forbidden),
        }
        if let Some((old, mut status)) = received(&tx, sender, &r.task_id)? {
            if old != r {
                return Err(Error::Conflict(
                    "task ID reused with different fields".into(),
                ));
            }
            if expire(&tx, sender, &old, &mut status)? {
                tx.commit()?;
            }
            return Ok(status);
        }
        if let Some(manifest) = &r.artifacts {
            self.reserve(&tx, manifest)?;
        }
        let at = now();
        let mut status = TaskStatus {
            task_id: r.task_id.clone(),
            sender_host_id: sender.into(),
            receiver_host_id: self.identity().id,
            target_agent_id: r.target_agent_id.clone(),
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
        Ok(status)
    }
    /// A submitter's task, settled for expiry; anyone else's is not found.
    fn settled_task(&self, sender: &str, id: &str) -> Result<TaskStatus, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (request, mut status) = received(&tx, sender, id)?.ok_or(Error::NotFound)?;
        if expire(&tx, sender, &request, &mut status)? {
            tx.commit()?;
        }
        Ok(status)
    }
    pub fn task_status(&self, sender: &str, id: &str) -> Result<TaskStatus, Error> {
        self.settled_task(sender, id)
    }
    pub fn task_events(
        &self,
        sender: &str,
        id: &str,
        after: i64,
        limit: i64,
    ) -> Result<Vec<TaskEvent>, Error> {
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("invalid event page bounds".into()));
        }
        self.settled_task(sender, id)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT record FROM task_events WHERE sender = ?1 AND task_id = ?2 AND sequence > ?3 ORDER BY sequence LIMIT ?4",
        )?;
        statement
            .query_map(params![sender, id, after, limit], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }
    /// Records the submitter's cancellation request, once. The state changes
    /// only when the agent confirms or finishes.
    pub fn request_task_cancel(&self, sender: &str, id: &str) -> Result<TaskStatus, Error> {
        Ok(self.cancel_received(sender, id)?.0)
    }
    /// Records a cancellation request, and marks every task forwarded from
    /// this one for cancellation in the same transaction. Returns the
    /// status and the children `(peer, task_id)` newly marked.
    #[allow(clippy::type_complexity)]
    pub(crate) fn cancel_received(
        &self,
        sender: &str,
        id: &str,
    ) -> Result<(TaskStatus, Vec<(String, String)>), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (request, mut status) = received(&tx, sender, id)?.ok_or(Error::NotFound)?;
        expire(&tx, sender, &request, &mut status)?;
        let mut children = Vec::new();
        if !status.cancel_requested && !is_final(&status.state) {
            record(
                &tx,
                sender,
                &mut status,
                "cancel_requested",
                None,
                None,
                None,
            )?;
            children = crate::task_outbound::cancel_children(&tx, sender, id)?;
        }
        tx.commit()?;
        Ok((status, children))
    }
    /// Expires every task still queued at its deadline. Returns how many.
    pub(crate) fn expire_tasks(&self) -> Result<usize, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let queued = {
            let mut statement = tx.prepare(
                "SELECT sender, request, record FROM received_tasks WHERE json_extract(record, '$.state') = 'queued'",
            )?;
            statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut count = 0;
        for (sender, request, status) in queued {
            let request: TaskRequest = serde_json::from_str(&request)?;
            let mut status = status_record(&status)?;
            if expire(&tx, &sender, &request, &mut status)? {
                count += 1;
            }
        }
        if count > 0 {
            tx.commit()?;
        }
        Ok(count)
    }

    /// Claims the oldest queued task for this session's agent after
    /// rechecking its authorization. A final lapse records `rejected`; a
    /// recoverable connected state leaves the task queued and unclaimed.
    pub fn next_task(&self, auth: &AdapterAuth) -> Result<Option<TaskHandoff>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = crate::adapter_connection::verified_authority(&tx, auth)?;
        crate::live_delivery::return_items(&tx, &ss.agent_id)?;
        if let Some(handoff) = self.claim_returned_task(&tx, &a, &ss)? {
            tx.commit()?;
            return Ok(Some(handoff));
        }
        let pending = {
            let mut stmt = tx.prepare("SELECT t.sender, t.request, t.record FROM received_tasks t WHERE json_extract(t.request, '$.target_agent_id') = ?1 AND json_extract(t.record, '$.state') = 'queued' AND NOT EXISTS (SELECT 1 FROM task_deliveries d WHERE d.sender = t.sender AND d.task_id = t.task_id) AND NOT EXISTS (SELECT 1 FROM task_artifacts a WHERE a.side = 'received' AND a.peer = t.sender AND a.task_id = t.task_id AND a.direction = 'input' AND json_extract(a.record, '$.state') != 'stored') ORDER BY t.rowid LIMIT 100")?;
            stmt.query_map([&ss.agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let mut handoff = None;
        for (sender, request, status) in pending {
            let request: TaskRequest = serde_json::from_str(&request)?;
            let mut status = status_record(&status)?;
            if expire(&tx, &sender, &request, &mut status)? {
                continue;
            }
            let (delegable, verified) = match recheck(self, &tx, &sender, &request) {
                Ok(Ok((bounds, verified))) => (may_delegate(&bounds, verified.as_ref()), verified),
                Ok(Err(reason)) => {
                    record(
                        &tx,
                        &sender,
                        &mut status,
                        "rejected",
                        Some(reason),
                        None,
                        None,
                    )?;
                    continue;
                }
                Err(Error::Unavailable(_)) => continue,
                Err(e) => return Err(e),
            };
            let d = TaskDelivery {
                id: new_id("delivery")?,
                sender_host_id: sender,
                task_id: request.task_id.clone(),
                target_agent_id: ss.agent_id.clone(),
                session_id: ss.id.clone(),
                adapter_id: a.id.clone(),
                cancel_claimed_at: None,
                created_at: now(),
            };
            tx.execute(
                "INSERT INTO task_deliveries (id, sender, task_id, session_id, record) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    d.id,
                    d.sender_host_id,
                    d.task_id,
                    d.session_id,
                    serde_json::to_string(&d)?
                ],
            )?;
            let (sender_person_id, sender_person) =
                crate::adapter::sender_person(self, &tx, &d.sender_host_id)?;
            let verified = verified.as_ref();
            handoff = Some(TaskHandoff {
                delivery: d,
                task: request,
                status,
                sender_person_id,
                sender_person,
                originator_person_id: verified.and_then(|v| v.originator_person_id.clone()),
                delegable,
                redelivered: false,
                adopted: false,
                progress: None,
            });
            break;
        }
        tx.commit()?;
        Ok(handoff)
    }
    /// Claims the oldest task returned to this agent's queue: a running one
    /// is adopted as it stands, and a queued one is offered again after
    /// rechecking its authorization as for a new one.
    fn claim_returned_task(
        &self,
        tx: &Transaction<'_>,
        a: &crate::adapter::Adapter,
        ss: &crate::model::Session,
    ) -> Result<Option<TaskHandoff>, Error> {
        let returned = {
            let mut stmt = tx.prepare("SELECT d.record, t.request, t.record FROM task_deliveries d JOIN sessions s ON s.id = d.session_id JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE s.agent_id = ?1 AND d.returned_at IS NOT NULL AND json_extract(t.record, '$.state') IN ('queued', 'running') ORDER BY d.rowid")?;
            stmt.query_map([&ss.agent_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        for (claim, request, status) in returned {
            let mut d: TaskDelivery = serde_json::from_str(&claim)?;
            let request: TaskRequest = serde_json::from_str(&request)?;
            let mut status = status_record(&status)?;
            let sender = d.sender_host_id.clone();
            let adopting = status.state == "running";
            let (delegable, originator) = if adopting {
                // What acceptance allowed stays; the chain is as verified then.
                let originator = task_bounds(self, tx, &sender, &request, false)
                    .ok()
                    .and_then(|(_, _, v)| v.and_then(|v| v.originator_person_id));
                (delegable(tx, &sender, &request.task_id)?, originator)
            } else {
                if expire(tx, &sender, &request, &mut status)? {
                    continue;
                }
                match recheck(self, tx, &sender, &request) {
                    Ok(Ok((bounds, verified))) => (
                        may_delegate(&bounds, verified.as_ref()),
                        verified.and_then(|v| v.originator_person_id),
                    ),
                    Ok(Err(reason)) => {
                        record(
                            tx,
                            &sender,
                            &mut status,
                            "rejected",
                            Some(reason),
                            None,
                            None,
                        )?;
                        tx.execute(
                            "UPDATE task_deliveries SET returned_at = NULL WHERE id = ?1",
                            [&d.id],
                        )?;
                        continue;
                    }
                    Err(Error::Unavailable(_)) => continue,
                    Err(e) => return Err(e),
                }
            };
            d.adapter_id = a.id.clone();
            d.session_id = ss.id.clone();
            let redeliveries: i64 = if adopting {
                tx.execute(
                    "UPDATE task_deliveries SET record = ?1, session_id = ?2, returned_at = NULL, adopted_at = ?3 WHERE id = ?4",
                    params![serde_json::to_string(&d)?, d.session_id, now(), d.id],
                )?;
                tx.query_row(
                    "SELECT redeliveries FROM task_deliveries WHERE id = ?1",
                    [&d.id],
                    |r| r.get(0),
                )?
            } else {
                tx.execute(
                    "UPDATE task_deliveries SET record = ?1, session_id = ?2, returned_at = NULL, adopted_at = NULL, redeliveries = redeliveries + 1 WHERE id = ?3",
                    params![serde_json::to_string(&d)?, d.session_id, d.id],
                )?;
                1
            };
            let progress: Option<String> = if adopting {
                tx.query_row(
                    "SELECT json_extract(record, '$.message') FROM task_events WHERE sender = ?1 AND task_id = ?2 AND json_extract(record, '$.kind') = 'progress' ORDER BY sequence DESC LIMIT 1",
                    params![sender, request.task_id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten()
            } else {
                None
            };
            let (sender_person_id, sender_person) =
                crate::adapter::sender_person(self, tx, &sender)?;
            return Ok(Some(TaskHandoff {
                delivery: d,
                task: request,
                status,
                sender_person_id,
                sender_person,
                originator_person_id: originator,
                delegable,
                redelivered: redeliveries > 0,
                adopted: adopting,
                progress,
            }));
        }
        Ok(None)
    }

    /// Applies an agent's change to a task this session claimed. Each change
    /// persists the state and its event together; an identical repeat
    /// returns the record unchanged, and an invalid transition is 409.
    pub fn change_task(
        &self,
        auth: &AdapterAuth,
        id: &str,
        change: Change,
    ) -> Result<TaskStatus, Error> {
        match &change {
            Change::Reject(reason) => text(reason, true)?,
            Change::Progress(message) => text(message, false)?,
            Change::Complete {
                status,
                output,
                artifacts,
            } => {
                if status != "succeeded" && status != "failed" {
                    return Err(Error::Invalid("status is succeeded or failed".into()));
                }
                text(output, false)?;
                if let Some(manifest) = artifacts
                    && !manifest.is_empty()
                {
                    validate_manifest(manifest)?;
                }
            }
            Change::Accept | Change::Cancelled => {}
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        let claim: Option<String> = tx
            .query_row(
                "SELECT record FROM task_deliveries WHERE task_id = ?1 AND session_id = ?2 AND returned_at IS NULL AND json_extract(record, '$.adapter_id') = ?3 ORDER BY rowid LIMIT 1",
                params![id, ss.id, a.id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(d) = claim else {
            // Only the session that claimed a task may change it.
            let known: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM received_tasks WHERE task_id = ?1)",
                [id],
                |r| r.get(0),
            )?;
            return Err(if known {
                Error::Forbidden
            } else {
                Error::NotFound
            });
        };
        let d: TaskDelivery = serde_json::from_str(&d)?;
        let sender = d.sender_host_id.as_str();
        let (request, mut status) = received(&tx, sender, id)?.ok_or(Error::NotFound)?;
        // The call shows the session saw the task, if it decides it, and
        // a cancellation request it claimed.
        let at = now();
        if matches!(change, Change::Accept | Change::Reject(_)) {
            tx.execute(
                "UPDATE task_deliveries SET seen_at = COALESCE(seen_at, ?1) WHERE id = ?2",
                params![at, d.id],
            )?;
        }
        crate::live_delivery::mark_cancel(&tx, &a.id, &ss.id, id, &at)?;
        crate::live_delivery::mark_updates(&tx, &a.id, &ss.id, id, None, &at)?;
        expire(&tx, sender, &request, &mut status)?;
        let outcome = self.apply(&tx, sender, &request, &mut status, change);
        // A refused change records nothing, so what was seen or settled
        // above is kept either way.
        tx.commit()?;
        match outcome {
            Ok(None) => Ok(status),
            Ok(Some(refusal)) | Err(refusal) => Err(refusal),
        }
    }
    /// `Ok(None)` applied (or repeated) the change. `Ok(Some(e))` recorded a
    /// lapse that must be committed before refusing with `e`. `Err` changed
    /// nothing.
    fn apply(
        &self,
        tx: &Transaction<'_>,
        sender: &str,
        request: &TaskRequest,
        status: &mut TaskStatus,
        change: Change,
    ) -> Result<Option<Error>, Error> {
        let invalid = |status: &TaskStatus, what: &str| {
            Error::Conflict(format!("cannot {what} a task that is {}", status.state))
        };
        match change {
            Change::Accept => match status.state.as_str() {
                "running" => Ok(None),
                "queued" => match recheck(self, tx, sender, request)? {
                    Ok((bounds, verified)) => {
                        let delegable = may_delegate(&bounds, verified.as_ref());
                        record(tx, sender, status, "accepted", None, None, None)?;
                        // The artifact bound checked now governs the results,
                        // and `task.delegate` lets the agent pass it on.
                        tx.execute(
                            "UPDATE received_tasks SET record = json_set(record, '$.max_artifact_bytes', ?1, '$.delegable', json(?2)) WHERE sender = ?3 AND task_id = ?4",
                            params![
                                bounds.max_artifact_bytes,
                                if delegable { "true" } else { "false" },
                                sender,
                                status.task_id
                            ],
                        )?;
                        Ok(None)
                    }
                    Err(reason) => {
                        record(tx, sender, status, "rejected", Some(reason), None, None)?;
                        Ok(Some(Error::Forbidden))
                    }
                },
                _ => Err(invalid(status, "accept")),
            },
            Change::Reject(reason) => match status.state.as_str() {
                "queued" => {
                    record(tx, sender, status, "rejected", Some(reason), None, None)?;
                    Ok(None)
                }
                "rejected"
                    if last_event(tx, sender, status)?.message.as_deref()
                        == Some(reason.as_str()) =>
                {
                    Ok(None)
                }
                _ => Err(invalid(status, "reject")),
            },
            Change::Progress(message) => {
                if status.state != "running" {
                    return Err(invalid(status, "report progress on"));
                }
                let last = last_event(tx, sender, status)?;
                if last.kind != "progress" || last.message.as_deref() != Some(message.as_str()) {
                    record(tx, sender, status, "progress", Some(message), None, None)?;
                }
                Ok(None)
            }
            Change::Complete {
                status: outcome,
                output,
                artifacts,
            } => {
                let artifacts = normalized(artifacts);
                if status.state == "running" {
                    if let Some(results) = &artifacts {
                        self.check_uploads(tx, results)?;
                        // Inputs and results together stay within the bound
                        // checked at acceptance.
                        let bound: Option<i64> = tx.query_row(
                            "SELECT json_extract(record, '$.max_artifact_bytes') FROM received_tasks WHERE sender = ?1 AND task_id = ?2",
                            params![sender, status.task_id],
                            |r| r.get(0),
                        )?;
                        let total = manifest_total(&request.artifacts).unwrap_or(0)
                            + manifest_total(&artifacts).unwrap_or(0);
                        if !crate::peer_store::artifacts_fit(Some(total), bound.unwrap_or(0)) {
                            return Err(Error::Forbidden);
                        }
                    }
                    let id = status.task_id.clone();
                    record(
                        tx,
                        sender,
                        status,
                        &outcome,
                        None,
                        Some(output),
                        artifacts.clone(),
                    )?;
                    if let Some(results) = &artifacts {
                        crate::artifact::add_artifacts(
                            tx,
                            RECEIVED,
                            sender,
                            &id,
                            RESULT,
                            results,
                            crate::artifact::STORED,
                        )?;
                    }
                    return Ok(None);
                }
                let last = last_event(tx, sender, status)?;
                if status.state == outcome
                    && last.output.as_deref() == Some(output.as_str())
                    && last.artifacts == artifacts
                {
                    return Ok(None);
                }
                Err(invalid(status, "complete"))
            }
            Change::Cancelled => match status.state.as_str() {
                "cancelled" => Ok(None),
                "running" if status.cancel_requested => {
                    record(tx, sender, status, "cancelled", None, None, None)?;
                    Ok(None)
                }
                "running" => Err(Error::Conflict(
                    "cancellation was not requested for this task".into(),
                )),
                _ => Err(invalid(status, "cancel")),
            },
        }
    }

    /// Claims one unseen cancellation request for this session's running
    /// tasks.
    pub fn next_task_cancel(&self, auth: &AdapterAuth) -> Result<Option<CancelHandoff>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = crate::adapter_connection::verified_authority(&tx, auth)?;
        crate::live_delivery::return_items(&tx, &ss.agent_id)?;
        let pending: Option<(String, String)> = tx
            .query_row(
                "SELECT d.record, t.record FROM task_deliveries d JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE d.session_id = ?1 AND d.returned_at IS NULL AND json_extract(d.record, '$.adapter_id') = ?2 AND json_extract(d.record, '$.cancel_claimed_at') IS NULL AND json_extract(t.record, '$.state') = 'running' AND json_extract(t.record, '$.cancel_requested') = 1 ORDER BY d.rowid LIMIT 1",
                params![ss.id, a.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((delivery, status)) = pending else {
            tx.commit()?;
            return Ok(None);
        };
        let mut delivery: TaskDelivery = serde_json::from_str(&delivery)?;
        let status = status_record(&status)?;
        delivery.cancel_claimed_at = Some(now());
        // The first claim of a cancellation request starts it unseen.
        tx.execute(
            "UPDATE task_deliveries SET record = ?1, cancel_seen_at = NULL WHERE id = ?2",
            params![serde_json::to_string(&delivery)?, delivery.id],
        )?;
        tx.commit()?;
        Ok(Some(CancelHandoff { delivery, status }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectBody {
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressBody {
    message: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteBody {
    status: String,
    output: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    artifacts: Option<Vec<ArtifactEntry>>,
}
#[derive(Deserialize)]
pub(crate) struct EventPage {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/peer/v1/tasks", post(submit))
        .route("/peer/v1/tasks/{id}", get(status))
        .route("/peer/v1/tasks/{id}/events", get(events))
        .route("/peer/v1/tasks/{id}/cancel", post(cancel))
}
async fn submit(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskStatus>, Error> {
    let request = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.accept_task(&sender, request)).await?,
    ))
}
async fn status(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
) -> Result<Json<TaskStatus>, Error> {
    Ok(Json(
        blocking(store, move |s| s.task_status(&sender, &id)).await?,
    ))
}
async fn events(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    query: Result<Query<EventPage>, QueryRejection>,
) -> Result<Json<Vec<TaskEvent>>, Error> {
    let Query(page) = query.map_err(|_| Error::Invalid("invalid event page".into()))?;
    Ok(Json(
        blocking(store, move |s| {
            s.task_events(
                &sender,
                &id,
                page.after.unwrap_or(0),
                page.limit.unwrap_or(100),
            )
        })
        .await?,
    ))
}
async fn cancel(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskStatus>, Error> {
    let _: Empty = decode(body)?;
    let (status, children) =
        blocking(store.clone(), move |s| s.cancel_received(&sender, &id)).await?;
    // Children are sent now; the poll worker resends any uncertain one.
    if !children.is_empty() {
        tokio::spawn(crate::task_outbound::send_cancels(store, children));
    }
    Ok(Json(status))
}

pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/tasks/next", post(next))
        .route("/adapter/v1/tasks/cancels/next", post(next_cancel))
        .route("/adapter/v1/tasks/{id}/accept", post(accept))
        .route("/adapter/v1/tasks/{id}/reject", post(reject))
        .route("/adapter/v1/tasks/{id}/progress", post(progress))
        .route("/adapter/v1/tasks/{id}/complete", post(complete))
        .route("/adapter/v1/tasks/{id}/cancelled", post(cancelled))
}
async fn next(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<TaskHandoff>>, Error> {
    let _: Empty = decode(body)?;
    let auth = crate::adapter::token(&headers);
    Ok(Json(blocking(store, move |s| s.next_task(&auth)).await?))
}
async fn next_cancel(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<CancelHandoff>>, Error> {
    let _: Empty = decode(body)?;
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.next_task_cancel(&auth)).await?,
    ))
}
async fn changed(
    store: Arc<Store>,
    headers: HeaderMap,
    id: String,
    change: Change,
) -> Result<Json<TaskStatus>, Error> {
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.change_task(&auth, &id, change)).await?,
    ))
}
async fn accept(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskStatus>, Error> {
    let _: Empty = decode(body)?;
    changed(store, headers, id, Change::Accept).await
}
async fn reject(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskStatus>, Error> {
    let r: RejectBody = decode(body)?;
    changed(store, headers, id, Change::Reject(r.reason)).await
}
async fn progress(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskStatus>, Error> {
    let r: ProgressBody = decode(body)?;
    changed(store, headers, id, Change::Progress(r.message)).await
}
async fn complete(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskStatus>, Error> {
    let r: CompleteBody = decode(body)?;
    changed(
        store,
        headers,
        id,
        Change::Complete {
            status: r.status,
            output: r.output,
            artifacts: r.artifacts,
        },
    )
    .await
}
async fn cancelled(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskStatus>, Error> {
    let _: Empty = decode(body)?;
    changed(store, headers, id, Change::Cancelled).await
}

/// Expires queued tasks at their deadlines until shutdown.
pub async fn expiry_worker(store: Arc<Store>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
        }
        let _ = blocking(store.clone(), Store::expire_tasks).await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        adapter_outbound::tests::connected_adapter,
        peer_store::{CreateGrant, Grant, tests::add_test_peer},
        store::rfc3339,
    };

    pub(crate) fn task_grant(store: &Store, peer: &str, agent: &str, action: &str) -> Grant {
        store
            .create_grant(CreateGrant {
                requester_host_id: peer.into(),
                target_agent_id: agent.into(),
                expires_at: rfc3339(Utc::now() + chrono::Duration::hours(2)),
                max_message_bytes: 1000,
                max_artifact_bytes: 0,
                allow_disconnected: true,
                requester_agent_id: None,
                action: Some(action.into()),
            })
            .unwrap()
    }
    pub(crate) fn task(n: char, grant: &str, agent: &str) -> TaskRequest {
        TaskRequest {
            task_id: format!("task_{}", n.to_string().repeat(32)),
            grant_id: Some(grant.into()),
            policy: None,
            self_access: None,
            target_agent_id: agent.into(),
            deadline: rfc3339(Utc::now() + chrono::Duration::minutes(30)),
            input: "summarize the report".into(),
            origin: None,
            artifacts: None,
            delegation: None,
        }
    }
    struct Fixture {
        _dir: tempfile::TempDir,
        store: Store,
        peer: String,
        agent: String,
        grant: Grant,
        auth: AdapterAuth,
    }
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("host")).unwrap();
        let peer = add_test_peer(&store).id;
        let auth = connected_adapter(&store, "a");
        let agent = store.adapter_session(&auth).unwrap().agent_id;
        let grant = task_grant(&store, &peer, &agent, TASK_ACTION);
        Fixture {
            _dir: dir,
            store,
            peer,
            agent,
            grant,
            auth,
        }
    }
    fn kinds(store: &Store, peer: &str, id: &str) -> Vec<String> {
        store
            .task_events(peer, id, 0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }
    fn activity_kinds(store: &Store) -> Vec<String> {
        store
            .events(0, 1000)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .filter(|k| k.starts_with("task."))
            .collect()
    }

    #[test]
    fn submission_needs_a_task_grant_and_is_idempotent() {
        let f = fixture();
        let message_only = task_grant(&f.store, &f.peer, &f.agent, crate::policy::ACTION);
        assert!(matches!(
            f.store
                .accept_task(&f.peer, task('1', &message_only.id, &f.agent)),
            Err(Error::Forbidden)
        ));
        let r = task('1', &f.grant.id, &f.agent);
        let status = f.store.accept_task(&f.peer, r.clone()).unwrap();
        assert_eq!(
            (
                status.state.as_str(),
                status.last_event,
                status.cancel_requested
            ),
            ("queued", 1, false)
        );
        assert_eq!(status.sender_host_id, f.peer);
        assert_eq!(status.receiver_host_id, f.store.identity().id);
        assert_eq!(f.store.accept_task(&f.peer, r.clone()).unwrap(), status);
        let changed = TaskRequest {
            input: "something else".into(),
            ..r.clone()
        };
        assert!(matches!(
            f.store.accept_task(&f.peer, changed),
            Err(Error::Conflict(_))
        ));
        // Oversized input, a malformed ID, and a message grant all refuse.
        let big = TaskRequest {
            task_id: format!("task_{}", "2".repeat(32)),
            input: "x".repeat(1001),
            ..r.clone()
        };
        assert!(matches!(
            f.store.accept_task(&f.peer, big),
            Err(Error::Forbidden)
        ));
        let bad = TaskRequest {
            task_id: "task_x".into(),
            ..r.clone()
        };
        assert!(matches!(
            f.store.accept_task(&f.peer, bad),
            Err(Error::Invalid(_))
        ));
        assert_eq!(kinds(&f.store, &f.peer, &r.task_id), ["queued"]);
        assert_eq!(activity_kinds(&f.store), ["task.received"]);
        // Only the submitter sees the task.
        let other = add_test_peer(&f.store).id;
        assert!(matches!(
            f.store.task_status(&other, &r.task_id),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            f.store.task_events(&other, &r.task_id, 0, 10),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            f.store.request_task_cancel(&other, &r.task_id),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            f.store.task_events(&f.peer, &r.task_id, -1, 10),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            f.store.task_events(&f.peer, &r.task_id, 0, 1001),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn requests_are_strict_on_the_wire() {
        let base = serde_json::json!({
            "task_id": format!("task_{}", "0".repeat(32)),
            "grant_id": format!("grant_{}", "0".repeat(32)),
            "target_agent_id": format!("agent_{}", "0".repeat(32)),
            "deadline": "2026-10-10T00:00:00Z",
            "input": "hi",
        });
        let r: TaskRequest = serde_json::from_value(base.clone()).unwrap();
        validate_task(&r).unwrap();
        assert!(serde_json::to_value(&r).unwrap().get("origin").is_none());
        for (field, value) in [
            ("origin", serde_json::Value::Null),
            ("grant_id", serde_json::Value::Null),
            ("extra", serde_json::json!(1)),
            ("content", serde_json::json!("x")),
        ] {
            let mut v = base.clone();
            v[field] = value;
            assert!(serde_json::from_value::<TaskRequest>(v).is_err(), "{field}");
        }
        let mut both = base.clone();
        both["policy"] =
            serde_json::json!({"person_id": format!("person_{}", "1".repeat(64)), "version": 1});
        let both: TaskRequest = serde_json::from_value(both).unwrap();
        assert!(matches!(validate_task(&both), Err(Error::Invalid(_))));
        let empty = TaskRequest {
            input: String::new(),
            ..r.clone()
        };
        assert!(matches!(validate_task(&empty), Err(Error::Invalid(_))));
        let long = TaskRequest {
            input: "x".repeat(MAX_TEXT + 1),
            ..r
        };
        assert!(matches!(validate_task(&long), Err(Error::Invalid(_))));
    }

    #[test]
    fn the_claiming_session_runs_the_full_lifecycle() {
        let f = fixture();
        let r = task('1', &f.grant.id, &f.agent);
        f.store.accept_task(&f.peer, r.clone()).unwrap();
        let handoff = f.store.next_task(&f.auth).unwrap().unwrap();
        let shown = serde_json::to_value(&handoff).unwrap();
        assert_eq!(shown["task"]["input"], "summarize the report");
        assert_eq!(shown["status"]["state"], "queued");
        assert!(shown["delivery"]["cancel_claimed_at"].is_null());
        assert!(shown["sender_person_id"].is_null() && shown.get("sender_person").is_some());
        // Claimed tasks are never offered again.
        assert!(f.store.next_task(&f.auth).unwrap().is_none());
        // Another session can neither claim nor change it.
        let other = connected_adapter(&f.store, "b");
        assert!(f.store.next_task(&other).unwrap().is_none());
        assert!(matches!(
            f.store.change_task(&other, &r.task_id, Change::Accept),
            Err(Error::Forbidden)
        ));
        let unknown = format!("task_{}", "9".repeat(32));
        assert!(matches!(
            f.store.change_task(&f.auth, &unknown, Change::Accept),
            Err(Error::NotFound)
        ));
        // Progress needs a running task.
        assert!(matches!(
            f.store
                .change_task(&f.auth, &r.task_id, Change::Progress("x".into())),
            Err(Error::Conflict(_))
        ));
        let running = f
            .store
            .change_task(&f.auth, &r.task_id, Change::Accept)
            .unwrap();
        assert_eq!(running.state, "running");
        assert_eq!(
            f.store
                .change_task(&f.auth, &r.task_id, Change::Accept)
                .unwrap(),
            running
        );
        for _ in 0..2 {
            f.store
                .change_task(&f.auth, &r.task_id, Change::Progress("half way".into()))
                .unwrap();
        }
        assert!(matches!(
            f.store
                .change_task(&f.auth, &r.task_id, Change::Progress(String::new())),
            Err(Error::Invalid(_))
        ));
        let complete = |status: &str, output: &str| {
            f.store.change_task(
                &f.auth,
                &r.task_id,
                Change::Complete {
                    status: status.into(),
                    output: output.into(),
                    artifacts: None,
                },
            )
        };
        assert!(matches!(complete("done", "x"), Err(Error::Invalid(_))));
        let done = complete("succeeded", "the summary").unwrap();
        assert_eq!((done.state.as_str(), done.last_event), ("succeeded", 4));
        assert_eq!(complete("succeeded", "the summary").unwrap(), done);
        assert!(matches!(
            complete("succeeded", "another"),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            complete("failed", "the summary"),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            f.store
                .change_task(&f.auth, &r.task_id, Change::Reject("no".into())),
            Err(Error::Conflict(_))
        ));
        let events = f.store.task_events(&f.peer, &r.task_id, 0, 100).unwrap();
        type Row<'a> = (i64, &'a str, &'a str, Option<&'a str>, Option<&'a str>);
        let summary: Vec<Row> = events
            .iter()
            .map(|e| {
                (
                    e.sequence,
                    e.kind.as_str(),
                    e.state.as_str(),
                    e.message.as_deref(),
                    e.output.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (1, "queued", "queued", None, None),
                (2, "accepted", "running", None, None),
                (3, "progress", "running", Some("half way"), None),
                (4, "succeeded", "succeeded", None, Some("the summary")),
            ]
        );
        assert_eq!(
            f.store.task_events(&f.peer, &r.task_id, 2, 1).unwrap()[0].sequence,
            3
        );
        assert_eq!(
            activity_kinds(&f.store),
            [
                "task.received",
                "task.accepted",
                "task.progress",
                "task.completed"
            ]
        );
    }

    #[test]
    fn rejection_failure_and_expiry_are_final() {
        let f = fixture();
        let r = task('1', &f.grant.id, &f.agent);
        f.store.accept_task(&f.peer, r.clone()).unwrap();
        f.store.next_task(&f.auth).unwrap().unwrap();
        let rejected = f
            .store
            .change_task(&f.auth, &r.task_id, Change::Reject(String::new()))
            .unwrap();
        assert_eq!(rejected.state, "rejected");
        f.store
            .change_task(&f.auth, &r.task_id, Change::Reject(String::new()))
            .unwrap();
        assert!(matches!(
            f.store
                .change_task(&f.auth, &r.task_id, Change::Reject("busy".into())),
            Err(Error::Conflict(_))
        ));
        assert_eq!(
            f.store.task_events(&f.peer, &r.task_id, 1, 10).unwrap()[0].message,
            Some(String::new())
        );

        let failing = task('2', &f.grant.id, &f.agent);
        f.store.accept_task(&f.peer, failing.clone()).unwrap();
        f.store.next_task(&f.auth).unwrap().unwrap();
        f.store
            .change_task(&f.auth, &failing.task_id, Change::Accept)
            .unwrap();
        let failed = f
            .store
            .change_task(
                &f.auth,
                &failing.task_id,
                Change::Complete {
                    status: "failed".into(),
                    output: "it broke".into(),
                    artifacts: None,
                },
            )
            .unwrap();
        assert_eq!(failed.state, "failed");

        // A task still queued at its deadline expires, claimed or not.
        let late = task('3', &f.grant.id, &f.agent);
        let unclaimed = task('4', &f.grant.id, &f.agent);
        f.store.accept_task(&f.peer, late.clone()).unwrap();
        f.store.next_task(&f.auth).unwrap().unwrap();
        f.store.accept_task(&f.peer, unclaimed.clone()).unwrap();
        for r in [&late, &unclaimed] {
            let mut past = r.clone();
            past.deadline = rfc3339(Utc::now() - chrono::Duration::seconds(1));
            f.store
                .connection()
                .unwrap()
                .execute(
                    "UPDATE received_tasks SET request = ?1 WHERE task_id = ?2",
                    params![serde_json::to_string(&past).unwrap(), r.task_id],
                )
                .unwrap();
        }
        assert!(matches!(
            f.store.change_task(&f.auth, &late.task_id, Change::Accept),
            Err(Error::Conflict(_))
        ));
        assert_eq!(
            f.store.task_status(&f.peer, &late.task_id).unwrap().state,
            "expired"
        );
        assert_eq!(f.store.expire_tasks().unwrap(), 1);
        assert_eq!(f.store.expire_tasks().unwrap(), 0);
        assert_eq!(
            kinds(&f.store, &f.peer, &unclaimed.task_id),
            ["queued", "expired"]
        );
        assert!(f.store.next_task(&f.auth).unwrap().is_none());
    }

    #[test]
    fn cancellation_is_requested_then_confirmed_or_finished_anyway() {
        let f = fixture();
        let r = task('1', &f.grant.id, &f.agent);
        f.store.accept_task(&f.peer, r.clone()).unwrap();
        f.store.next_task(&f.auth).unwrap().unwrap();
        f.store
            .change_task(&f.auth, &r.task_id, Change::Accept)
            .unwrap();
        assert!(matches!(
            f.store.change_task(&f.auth, &r.task_id, Change::Cancelled),
            Err(Error::Conflict(_))
        ));
        assert!(f.store.next_task_cancel(&f.auth).unwrap().is_none());
        let requested = f.store.request_task_cancel(&f.peer, &r.task_id).unwrap();
        assert!(requested.cancel_requested);
        assert_eq!(requested.state, "running");
        assert_eq!(
            f.store.request_task_cancel(&f.peer, &r.task_id).unwrap(),
            requested
        );
        // Another session never sees this request.
        let other = connected_adapter(&f.store, "b");
        assert!(f.store.next_task_cancel(&other).unwrap().is_none());
        let notice = f.store.next_task_cancel(&f.auth).unwrap().unwrap();
        assert_eq!(notice.status.task_id, r.task_id);
        assert!(notice.delivery.cancel_claimed_at.is_some());
        assert!(f.store.next_task_cancel(&f.auth).unwrap().is_none());
        let cancelled = f
            .store
            .change_task(&f.auth, &r.task_id, Change::Cancelled)
            .unwrap();
        assert_eq!(cancelled.state, "cancelled");
        f.store
            .change_task(&f.auth, &r.task_id, Change::Cancelled)
            .unwrap();
        assert_eq!(
            kinds(&f.store, &f.peer, &r.task_id),
            ["queued", "accepted", "cancel_requested", "cancelled"]
        );
        // A final task ignores further requests.
        assert_eq!(
            f.store.request_task_cancel(&f.peer, &r.task_id).unwrap(),
            cancelled
        );

        // Requested while queued, then completed anyway.
        let anyway = task('2', &f.grant.id, &f.agent);
        f.store.accept_task(&f.peer, anyway.clone()).unwrap();
        let queued = f
            .store
            .request_task_cancel(&f.peer, &anyway.task_id)
            .unwrap();
        assert_eq!(
            (queued.state.as_str(), queued.cancel_requested),
            ("queued", true)
        );
        f.store.next_task(&f.auth).unwrap().unwrap();
        f.store
            .change_task(&f.auth, &anyway.task_id, Change::Accept)
            .unwrap();
        let done = f
            .store
            .change_task(
                &f.auth,
                &anyway.task_id,
                Change::Complete {
                    status: "succeeded".into(),
                    output: "done before stopping".into(),
                    artifacts: None,
                },
            )
            .unwrap();
        assert_eq!(
            (done.state.as_str(), done.cancel_requested),
            ("succeeded", true)
        );
    }

    #[test]
    fn revocation_before_acceptance_rejects_but_accepted_work_continues() {
        let f = fixture();
        let unclaimed = task('1', &f.grant.id, &f.agent);
        let claimed = task('2', &f.grant.id, &f.agent);
        let running = task('3', &f.grant.id, &f.agent);
        f.store.accept_task(&f.peer, running.clone()).unwrap();
        f.store.next_task(&f.auth).unwrap().unwrap();
        f.store
            .change_task(&f.auth, &running.task_id, Change::Accept)
            .unwrap();
        f.store.accept_task(&f.peer, claimed.clone()).unwrap();
        f.store.next_task(&f.auth).unwrap().unwrap();
        f.store.accept_task(&f.peer, unclaimed.clone()).unwrap();
        f.store.revoke_grant(&f.grant.id).unwrap();
        // At claim: rejected, never handed off.
        assert!(f.store.next_task(&f.auth).unwrap().is_none());
        let rejected = f
            .store
            .task_events(&f.peer, &unclaimed.task_id, 1, 10)
            .unwrap();
        assert_eq!(rejected[0].kind, "rejected");
        assert_eq!(rejected[0].message.as_deref(), Some(LAPSED));
        // At acceptance: rejected and refused.
        assert!(matches!(
            f.store
                .change_task(&f.auth, &claimed.task_id, Change::Accept),
            Err(Error::Forbidden)
        ));
        assert_eq!(
            f.store
                .task_status(&f.peer, &claimed.task_id)
                .unwrap()
                .state,
            "rejected"
        );
        // Accepted work belongs to the agent.
        f.store
            .change_task(
                &f.auth,
                &running.task_id,
                Change::Progress("still going".into()),
            )
            .unwrap();
        let done = f
            .store
            .change_task(
                &f.auth,
                &running.task_id,
                Change::Complete {
                    status: "succeeded".into(),
                    output: "ok".into(),
                    artifacts: None,
                },
            )
            .unwrap();
        assert_eq!(done.state, "succeeded");
        // Status remains available to the submitter after revocation.
        f.store.task_status(&f.peer, &running.task_id).unwrap();
        // New submissions are refused.
        assert!(matches!(
            f.store
                .accept_task(&f.peer, task('4', &f.grant.id, &f.agent)),
            Err(Error::Forbidden)
        ));
    }

    #[test]
    fn a_blocked_sender_cannot_submit() {
        let f = fixture();
        f.store
            .block(crate::policy::BlockRequest {
                person: None,
                host: Some(f.peer.clone()),
            })
            .unwrap();
        assert!(matches!(
            f.store
                .accept_task(&f.peer, task('1', &f.grant.id, &f.agent)),
            Err(Error::Forbidden)
        ));
    }
}
