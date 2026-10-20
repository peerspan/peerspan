//! Agent capability tools (capabilities contract, slice 2): the adapter
//! routes through which an attached agent lists and calls capabilities,
//! follows its calls, and is told when one becomes final. Calls persist as
//! outbound calls with the agent's origin and credential; `adapter_calls`
//! binds each to its session and counts it against the credential's
//! `max_calls_per_hour`.
use crate::{
    adapter::{Adapter, authority, token},
    adapter_connection::AdapterAuth,
    api::{blocking, decode},
    call_outbound::{self, OutboundCall, Viewer},
    calls::{CallRequest, call_id_shape},
    model::{Error, Session},
    peer_store::Origin,
    store::{Store, append_event, new_id, now, rfc3339},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State, rejection::BytesRejection},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

/// Database version 18.
pub(crate) const SCHEMA: &str = "
CREATE TABLE adapter_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id), adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), session_id TEXT NOT NULL REFERENCES sessions(id), called_at_ms INTEGER NOT NULL, PRIMARY KEY(peer, call_id), UNIQUE(agent_id, call_id), FOREIGN KEY(peer, call_id) REFERENCES outbound_calls(peer, call_id));
CREATE INDEX adapter_calls_rate ON adapter_calls(adapter_id, called_at_ms);
CREATE TABLE call_update_notifications (id TEXT PRIMARY KEY, peer TEXT NOT NULL, call_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, seen_at TEXT, redeliveries INTEGER NOT NULL DEFAULT 0, returned_at TEXT, UNIQUE(peer, call_id));
PRAGMA user_version = 18;
";

/// The default cap on an agent's calls in any 60 minutes.
pub const DEFAULT_CALLS_PER_HOUR: i64 = 100;
const HOUR_MS: i64 = 3_600_000;
/// The largest result text returned inline, and the largest part.
const PART: usize = 65_536;
/// Resolution and persistence must finish within this long of receipt.
const PERSIST_BOUND: Duration = Duration::from_secs(20);
/// The route returns by this long after receipt, whatever the submission.
const SUBMIT_BOUND: Duration = Duration::from_secs(25);

const NOTE_PENDING: &str = "The call has not finished. Its result arrives as a kind=call_update event; call_status reports it at any time.";
const NOTE_UNCERTAIN: &str = "The call was running when it ended without a result, so it may or may not have taken effect. Do not call it again on your own: check whether it took effect, or ask the person.";
const NOTE_NEVER_RAN: &str =
    "The call never ran, so it had no effect. Calling again makes a new call.";
const NOTE_PARTS: &str =
    "The result is in parts; call call_status with offset set to next_offset for the next part.";

/// A call-update notification, as the adapter sees it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallUpdateNotification {
    pub id: String,
    pub peer_host_id: String,
    pub call_id: String,
    pub adapter_id: String,
    pub session_id: String,
    /// `unknown` or `forwarded`.
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}
/// The stored record: the notification, and whether a session has claimed
/// it since it was created or returned.
#[derive(Serialize, Deserialize)]
struct StoredNotification {
    #[serde(flatten)]
    notification: CallUpdateNotification,
    #[serde(default)]
    claimed: bool,
}
#[derive(Serialize)]
pub struct CallUpdate {
    pub delivery: CallUpdateNotification,
    pub call: Value,
    pub redelivered: bool,
}

fn coded(status: u16, code: &'static str, message: String, extra: Value) -> Error {
    Error::Coded {
        status,
        code,
        message,
        extra: extra.as_object().cloned().unwrap_or_default(),
    }
}
fn no_calls() -> Error {
    coded(
        403,
        "no_calls",
        "this session's credential may not call capabilities; the person enables it with peerspan attach --calls".into(),
        json!({}),
    )
}
/// The credential and session of an adapter request, refused with
/// `no_calls` unless the credential may call capabilities.
fn calls_authority(conn: &Connection, auth: &AdapterAuth) -> Result<(Adapter, Session), Error> {
    let (a, ss) = authority(conn, auth)?;
    if !a.calls {
        return Err(no_calls());
    }
    Ok((a, ss))
}

/// Creates the call-update notification of an agent's call that has just
/// become final, bound to the session that made it.
pub(crate) fn notify_final(tx: &Transaction<'_>, out: &OutboundCall) -> Result<(), Error> {
    let Some(adapter) = &out.adapter_id else {
        return Ok(());
    };
    if !out.finished() {
        return Ok(());
    }
    let Some(session) = out
        .request
        .origin
        .as_ref()
        .and_then(|o| o.session_id.clone())
    else {
        return Ok(());
    };
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM call_update_notifications WHERE peer = ?1 AND call_id = ?2)",
        params![out.peer_host_id, out.request.call_id],
        |r| r.get(0),
    )?;
    if exists {
        return Ok(());
    }
    let at = now();
    let n = StoredNotification {
        notification: CallUpdateNotification {
            id: new_id("notification")?,
            peer_host_id: out.peer_host_id.clone(),
            call_id: out.request.call_id.clone(),
            adapter_id: adapter.clone(),
            session_id: session.clone(),
            state: "unknown".into(),
            created_at: at.clone(),
            updated_at: at,
        },
        claimed: false,
    };
    tx.execute(
        "INSERT INTO call_update_notifications (id, peer, call_id, session_id, record) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            n.notification.id,
            n.notification.peer_host_id,
            n.notification.call_id,
            session,
            serde_json::to_string(&n)?
        ],
    )?;
    Ok(())
}

/// The call view's `state`: `submitting` while the submission is unknown,
/// `rejected` when it was refused, and otherwise the status record's.
fn view_state(out: &OutboundCall) -> String {
    match out.submit_state.as_str() {
        "unknown" => "submitting".into(),
        "rejected" => "rejected".into(),
        _ => out
            .status
            .as_ref()
            .map(|s| s.state.clone())
            .unwrap_or_else(|| "queued".into()),
    }
}
/// The status record's error, or the refusal's text for a refused
/// submission.
fn view_error(out: &OutboundCall) -> Option<String> {
    if out.submit_state == "rejected" {
        return out.error.as_deref().map(|e| {
            // Stored as `peer returned HTTP N: TEXT`.
            match e.split_once(": ") {
                Some((head, text))
                    if head.starts_with("peer returned HTTP ") && !text.is_empty() =>
                {
                    text.to_owned()
                }
                _ => e.to_owned(),
            }
        });
    }
    out.status.as_ref().and_then(|s| s.error.clone())
}
/// The canonical encoding of the stored result: as received, or from the
/// parsed value for a record stored without it.
fn result_text(out: &OutboundCall) -> Option<String> {
    out.result.as_ref().map(|r| {
        out.result_text
            .clone()
            .unwrap_or_else(|| crate::canonical::value_text(r))
    })
}
fn created_at(called_at_ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(called_at_ms)
        .map(rfc3339)
        .unwrap_or_default()
}

/// The call view from byte `offset` of the result text.
fn view(out: &OutboundCall, called_at_ms: i64, offset: usize) -> Result<Value, Error> {
    let state = view_state(out);
    let text = result_text(out);
    let size = text.as_ref().map_or(0, String::len);
    if offset > size || text.as_ref().is_some_and(|t| !t.is_char_boundary(offset)) {
        return Err(Error::Invalid(
            "offset is past the result or inside a character".into(),
        ));
    }
    let (mut result, mut part, mut truncated, mut next) = (Value::Null, Value::Null, false, None);
    if let Some(text) = &text {
        if size <= PART && offset == 0 {
            result = out.result.clone().unwrap_or(Value::Null);
        } else {
            truncated = true;
            let mut end = (offset + PART).min(size);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            part = Value::String(text[offset..end].to_owned());
            if end < size {
                next = Some(end);
            }
        }
    }
    let note = match state.as_str() {
        "submitting" | "queued" | "running" => Some(NOTE_PENDING),
        "uncertain" => Some(NOTE_UNCERTAIN),
        "rejected" | "expired" | "cancelled" => Some(NOTE_NEVER_RAN),
        "succeeded" | "failed" if truncated => Some(NOTE_PARTS),
        _ => None,
    };
    Ok(json!({
        "call_id": out.request.call_id,
        "address": out.target,
        "peer_host_id": out.peer_host_id,
        "operation": out.request.operation,
        "submit_state": out.submit_state,
        "state": state,
        "error": view_error(out),
        "created_at": created_at(called_at_ms),
        "deadline": out.request.deadline,
        "result": result,
        "result_part": part,
        "truncated": truncated,
        "result_bytes": text.as_ref().map(String::len),
        "offset": offset,
        "next_offset": next,
        "note": note,
    }))
}

/// One of this agent's calls: its peer, and when it was persisted.
fn agent_call(conn: &Connection, agent: &str, id: &str) -> Result<(String, i64), Error> {
    conn.query_row(
        "SELECT peer, called_at_ms FROM adapter_calls WHERE agent_id = ?1 AND call_id = ?2",
        params![agent, id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or(Error::NotFound)
}
/// Marks the call-update notification this session holds for a call
/// seen. Returns whether it was newly marked.
pub(crate) fn mark_call_seen(
    conn: &Connection,
    session: &str,
    call: &str,
    at: &str,
) -> Result<bool, Error> {
    Ok(conn.execute(
        "UPDATE call_update_notifications SET seen_at = ?1 WHERE call_id = ?2 AND session_id = ?3 AND seen_at IS NULL AND returned_at IS NULL",
        params![at, call, session],
    )? > 0)
}
/// Whether a session may name a call in `mark_seen`: one of its agent's
/// calls, or one whose notification it holds.
pub(crate) fn holds_call(conn: &Connection, session: &Session, call: &str) -> Result<bool, Error> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM adapter_calls WHERE agent_id = ?1 AND call_id = ?2) OR EXISTS(SELECT 1 FROM call_update_notifications WHERE call_id = ?2 AND session_id = ?3 AND returned_at IS NULL)",
        params![session.agent_id, call, session.id],
        |r| r.get(0),
    )?)
}
/// The view of a call for its agent's session. When the view is final it
/// marks the notification this session holds seen; a late notification no
/// session holds yet is bound to this session, when it is verified
/// (`verified` is then its credential), and seen at once.
fn seen_view(
    tx: &Transaction<'_>,
    ss: &Session,
    verified: Option<&Adapter>,
    out: &OutboundCall,
    called_at_ms: i64,
    offset: usize,
) -> Result<Value, Error> {
    let value = view(out, called_at_ms, offset)?;
    if out.finished() {
        let at = now();
        if !mark_call_seen(tx, &ss.id, &out.request.call_id, &at)?
            && let Some(a) = verified
        {
            bind_late(tx, a, ss, out, &at)?;
        }
    }
    Ok(value)
}
/// Binds a late notification of the call, one never claimed whose
/// authorization has ended, to this session, seen.
fn bind_late(
    tx: &Transaction<'_>,
    a: &Adapter,
    ss: &Session,
    out: &OutboundCall,
    at: &str,
) -> Result<(), Error> {
    let record: Option<String> = tx
        .query_row(
            "SELECT record FROM call_update_notifications WHERE peer = ?1 AND call_id = ?2 AND seen_at IS NULL AND returned_at IS NULL AND COALESCE(json_extract(record, '$.claimed'), 0) = 0",
            params![out.peer_host_id, out.request.call_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(record) = record else {
        return Ok(());
    };
    let mut n: StoredNotification = serde_json::from_str(&record)?;
    if n.notification.session_id == ss.id
        || !crate::live_delivery::ended(tx, &n.notification.adapter_id)?
    {
        return Ok(());
    }
    n.notification.adapter_id = a.id.clone();
    n.notification.session_id = ss.id.clone();
    n.notification.updated_at = at.to_owned();
    tx.execute(
        "UPDATE call_update_notifications SET record = ?1, session_id = ?2, seen_at = ?3 WHERE id = ?4",
        params![serde_json::to_string(&n)?, ss.id, at, n.notification.id],
    )?;
    Ok(())
}
/// Whether a session has ended: its authorization has (detached, revoked,
/// replaced, or expired), for every credential it had.
fn session_ended(conn: &Connection, session: &str) -> Result<bool, Error> {
    let ids: Vec<String> = {
        let mut stmt = conn.prepare("SELECT id FROM adapter_credentials WHERE session_id = ?1")?;
        stmt.query_map([session], |r| r.get(0))?
            .collect::<Result<_, _>>()?
    };
    for id in ids {
        if !crate::live_delivery::ended(conn, &id)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentCall {
    call_id: String,
    address: String,
    operation: String,
    input: Value,
}

/// What a submission found before resolving: an existing call, or the
/// credential and session to make a new one with.
enum Prior {
    Existing(Value),
    New(Box<(Adapter, Session)>),
}

impl Store {
    /// Step 2 and 3: a repeat of this agent's call, or the rate limit.
    fn agent_call_prior(&self, auth: &AdapterAuth, r: &AgentCall) -> Result<Prior, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = calls_authority(&tx, auth)?;
        let verified = crate::adapter_connection::verified_authority(&tx, auth).is_ok();
        if let Some(existing) = repeat(&tx, &ss, verified.then_some(&a), r)? {
            tx.commit()?;
            return Ok(Prior::Existing(existing));
        }
        rate_check(&tx, &a)?;
        Ok(Prior::New(Box::new((a, ss))))
    }
    /// Step 7: persists the outbound record, its `adapter_calls` row, and
    /// the `call.submitted` activity in one transaction.
    fn persist_agent_call(
        &self,
        a: &Adapter,
        ss: &Session,
        r: &AgentCall,
        out: &OutboundCall,
        deadline: Instant,
    ) -> Result<Result<OutboundCall, Value>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if let Some(existing) = repeat(&tx, ss, None, r)? {
            tx.commit()?;
            return Ok(Err(existing));
        }
        rate_check(&tx, a)?;
        let taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbound_calls WHERE peer = ?1 AND call_id = ?2)",
            params![out.peer_host_id, out.request.call_id],
            |row| row.get(0),
        )?;
        if taken {
            return Err(Error::Conflict("call ID already used".into()));
        }
        tx.execute(
            "INSERT INTO outbound_calls VALUES (?1, ?2, ?3)",
            params![
                out.peer_host_id,
                out.request.call_id,
                call_outbound::encode(out)?
            ],
        )?;
        tx.execute(
            "INSERT INTO adapter_calls VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                out.peer_host_id,
                out.request.call_id,
                ss.agent_id,
                a.id,
                ss.id,
                Utc::now().timestamp_millis()
            ],
        )?;
        append_event(&tx, "call.submitted", &call_outbound::subject(out), &now())?;
        // Past the 20-second bound nothing is persisted: dropping the
        // transaction rolls it back.
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        tx.commit()?;
        Ok(Ok(out.clone()))
    }
    /// The view of one of this agent's calls after its submission's first
    /// attempt, marking the session's notification seen when final.
    fn agent_call_view(
        &self,
        auth: &AdapterAuth,
        ss: &Session,
        peer: &str,
        id: &str,
    ) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let verified = crate::adapter_connection::verified_authority(&tx, auth)
            .ok()
            .map(|(a, _)| a);
        let (_, called) = agent_call(&tx, &ss.agent_id, id)?;
        let out = call_outbound::stored(&tx, peer, id)?;
        let value = seen_view(&tx, ss, verified.as_ref(), &out, called, 0)?;
        tx.commit()?;
        Ok(value)
    }
    /// `GET /adapter/v1/calls/{call_id}`.
    pub fn agent_call_status(
        &self,
        auth: &AdapterAuth,
        id: &str,
        offset: usize,
    ) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = calls_authority(&tx, auth)?;
        let verified = crate::adapter_connection::verified_authority(&tx, auth).is_ok();
        let (peer, called) = agent_call(&tx, &ss.agent_id, id)?;
        let out = call_outbound::stored(&tx, &peer, id)?;
        let value = seen_view(&tx, &ss, verified.then_some(&a), &out, called, offset)?;
        tx.commit()?;
        Ok(value)
    }
    /// The scope check of `POST /adapter/v1/calls/{call_id}/cancel`.
    fn agent_call_scope(&self, auth: &AdapterAuth, id: &str) -> Result<(String, i64), Error> {
        let conn = self.connection()?;
        let (_, ss) = calls_authority(&conn, auth)?;
        agent_call(&conn, &ss.agent_id, id)
    }
    /// `POST /adapter/v1/call-updates/next`: the returned notification of
    /// the agent claimed first, then the oldest unclaimed one this session
    /// holds or one whose authorization has ended.
    pub fn next_call_update(&self, auth: &AdapterAuth) -> Result<Option<CallUpdate>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = calls_authority(&tx, auth)?;
        crate::adapter_connection::verified_authority(&tx, auth)?;
        crate::live_delivery::return_items(&tx, &ss.agent_id)?;
        let at = now();
        let returned: Option<String> = tx
            .query_row(
                "SELECT n.record FROM call_update_notifications n JOIN sessions s ON s.id = n.session_id WHERE s.agent_id = ?1 AND n.returned_at IS NOT NULL AND n.seen_at IS NULL ORDER BY n.rowid LIMIT 1",
                [&ss.agent_id],
                |r| r.get(0),
            )
            .optional()?;
        let (record, redelivered) = match returned {
            Some(record) => (record, true),
            None => {
                let rows: Vec<String> = {
                    let mut stmt = tx.prepare("SELECT n.record FROM call_update_notifications n JOIN sessions s ON s.id = n.session_id WHERE s.agent_id = ?1 AND n.seen_at IS NULL AND n.returned_at IS NULL AND COALESCE(json_extract(n.record, '$.claimed'), 0) = 0 ORDER BY n.rowid")?;
                    stmt.query_map([&ss.agent_id], |r| r.get(0))?
                        .collect::<Result<_, _>>()?
                };
                let mut ended = crate::live_delivery::Ended::default();
                let mut found = None;
                for record in rows {
                    let n: StoredNotification = serde_json::from_str(&record)?;
                    let own =
                        n.notification.adapter_id == a.id && n.notification.session_id == ss.id;
                    // One created after its session's authorization ended
                    // goes to the agent's next verified session.
                    if own || ended.check(&tx, &n.notification.adapter_id)? {
                        found = Some(record);
                        break;
                    }
                }
                match found {
                    Some(record) => (record, false),
                    None => {
                        tx.commit()?;
                        return Ok(None);
                    }
                }
            }
        };
        let mut n: StoredNotification = serde_json::from_str(&record)?;
        n.notification.adapter_id = a.id.clone();
        n.notification.session_id = ss.id.clone();
        n.notification.state = "unknown".into();
        n.notification.updated_at = at;
        n.claimed = true;
        tx.execute(
            "UPDATE call_update_notifications SET record = ?1, session_id = ?2, redeliveries = redeliveries + ?3, returned_at = NULL WHERE id = ?4",
            params![
                serde_json::to_string(&n)?,
                ss.id,
                i64::from(redelivered),
                n.notification.id
            ],
        )?;
        let out =
            call_outbound::stored(&tx, &n.notification.peer_host_id, &n.notification.call_id)?;
        let called: i64 = tx.query_row(
            "SELECT called_at_ms FROM adapter_calls WHERE peer = ?1 AND call_id = ?2",
            params![n.notification.peer_host_id, n.notification.call_id],
            |r| r.get(0),
        )?;
        let call = view(&out, called, 0)?;
        tx.commit()?;
        Ok(Some(CallUpdate {
            delivery: n.notification,
            call,
            redelivered,
        }))
    }
    /// `POST /adapter/v1/call-updates/{id}/forwarded`.
    pub fn call_update_forwarded(
        &self,
        auth: &AdapterAuth,
        id: &str,
    ) -> Result<CallUpdateNotification, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = calls_authority(&tx, auth)?;
        let record: String = tx
            .query_row(
                "SELECT record FROM call_update_notifications WHERE id = ?1 AND returned_at IS NULL",
                [id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let mut n: StoredNotification = serde_json::from_str(&record)?;
        if n.notification.adapter_id != a.id || n.notification.session_id != ss.id || !n.claimed {
            return Err(Error::NotFound);
        }
        if n.notification.state == "forwarded" {
            return Ok(n.notification);
        }
        n.notification.state = "forwarded".into();
        n.notification.updated_at = now();
        tx.execute(
            "UPDATE call_update_notifications SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&n)?, n.notification.id],
        )?;
        tx.commit()?;
        Ok(n.notification)
    }
}

/// An existing call of this agent under the request's call ID: its view
/// when the request is identical, and 409 when it differs.
fn repeat(
    tx: &Transaction<'_>,
    ss: &Session,
    verified: Option<&Adapter>,
    r: &AgentCall,
) -> Result<Option<Value>, Error> {
    let Ok((peer, called)) = agent_call(tx, &ss.agent_id, &r.call_id) else {
        return Ok(None);
    };
    let out = call_outbound::stored(tx, &peer, &r.call_id)?;
    if out.target != r.address
        || out.request.operation != r.operation
        || out.request.input != r.input
    {
        return Err(coded(
            409,
            "conflict",
            "this call ID was used with a different address, operation, or input".into(),
            json!({}),
        ));
    }
    Ok(Some(seen_view(tx, ss, verified, &out, called, 0)?))
}
/// Refuses a call that would make more than `max_calls_per_hour` calls
/// persisted through this credential in the preceding 60 minutes.
fn rate_check(conn: &Connection, a: &Adapter) -> Result<(), Error> {
    let cap = a.max_calls_per_hour.unwrap_or(DEFAULT_CALLS_PER_HOUR);
    let now = Utc::now().timestamp_millis();
    let (count, oldest): (i64, Option<i64>) = conn.query_row(
        "SELECT COUNT(*), MIN(called_at_ms) FROM adapter_calls WHERE adapter_id = ?1 AND called_at_ms > ?2",
        params![a.id, now - HOUR_MS],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count < cap {
        return Ok(());
    }
    let wait_ms = oldest.map_or(HOUR_MS, |t| t + HOUR_MS - now);
    let retry_after = ((wait_ms + 999) / 1000).max(1);
    Err(coded(
        429,
        "rate_limited",
        format!(
            "this session made {count} capability calls in the last hour, its limit; retry after {retry_after} seconds"
        ),
        json!({ "retry_after": retry_after }),
    ))
}

fn timeout() -> Error {
    coded(
        503,
        "timeout",
        "the call could not be resolved and recorded in time; nothing was recorded".into(),
        json!({}),
    )
}

/// `POST /adapter/v1/calls`.
async fn create(store: Arc<Store>, auth: AdapterAuth, r: AgentCall) -> Result<Value, Error> {
    let received = Instant::now();
    // 1. Shape.
    if !call_id_shape(&r.call_id)
        || r.address.len() > 256
        || r.operation.is_empty()
        || r.operation.len() > 128
        || !r.input.is_object()
    {
        return Err(Error::Invalid(
            "call_id is call_ and 32 lowercase hex digits, address at most 256 bytes, operation 1 to 128 bytes, and input an object".into(),
        ));
    }
    let r = Arc::new(r);
    // 2 and 3. Repeat, then the rate limit.
    let (request, a) = (r.clone(), auth.clone());
    let (adapter, session) =
        match blocking(store.clone(), move |s| s.agent_call_prior(&a, &request)).await? {
            Prior::Existing(view) => return Ok(view),
            Prior::New(found) => *found,
        };
    // 4. Address.
    if r.address.matches('/').count() == 2 {
        return Err(coded(
            400,
            "source",
            "sources can be called only from the peerspan CLI".into(),
            json!({}),
        ));
    }
    let resolved = tokio::time::timeout_at(
        (received + PERSIST_BOUND).into(),
        prepare(&store, &adapter, &session, &r),
    )
    .await
    .map_err(|_| timeout())??;
    if received.elapsed() >= PERSIST_BOUND {
        return Err(timeout());
    }
    // 7. Persist.
    let (request, a, ss) = (r.clone(), adapter.clone(), session.clone());
    let out = match blocking(store.clone(), move |s| {
        s.persist_agent_call(&a, &ss, &request, &resolved, received + PERSIST_BOUND)
    })
    .await?
    {
        Ok(out) => out,
        Err(existing) => return Ok(existing),
    };
    // 8. Submit: return once the first attempt ends, or 25 seconds after
    // receipt; later attempts continue in the background.
    let status_only = crate::retry::receipt_only(&out, Utc::now());
    let attempt = tokio::spawn(call_outbound::submit(
        store.clone(),
        out.clone(),
        status_only,
    ));
    let _ = tokio::time::timeout_at((received + SUBMIT_BOUND).into(), attempt).await;
    let (peer, id) = (out.peer_host_id.clone(), out.request.call_id.clone());
    blocking(store, move |s| {
        s.agent_call_view(&auth, &session, &peer, &id)
    })
    .await
}

/// Steps 4 to 6: resolves the address over what `GET
/// /adapter/v1/capabilities` would list, cites the first `via` entry that
/// applies to this agent, and sets the deadline.
async fn prepare(
    store: &Arc<Store>,
    adapter: &Adapter,
    session: &Session,
    r: &AgentCall,
) -> Result<OutboundCall, Error> {
    let address = call_outbound::parse_address(&r.address)?;
    let viewer = Viewer::Agent(session.agent_id.clone());
    let (peer, entry) = call_outbound::resolve(store, &address, None, &viewer).await?;
    let (network_id, policy, self_access) = call_outbound::cite(store, &entry, None).await?;
    let mut deadline = call_outbound::default_deadline(store, policy.as_ref()).await?;
    if let Ok(expires) = DateTime::parse_from_rfc3339(&adapter.expires_at) {
        deadline = deadline.min(expires.with_timezone(&Utc));
    }
    Ok(OutboundCall {
        peer_host_id: peer,
        request: CallRequest {
            call_id: r.call_id.clone(),
            capability: address.capability().to_owned(),
            operation: r.operation.clone(),
            input: r.input.clone(),
            deadline: rfc3339(deadline),
            origin: Some(Origin {
                agent_id: session.agent_id.clone(),
                session_id: Some(session.id.clone()),
            }),
            policy,
            self_access,
        },
        submit_state: "unknown".into(),
        status: None,
        result: None,
        cancel_state: None,
        attempts: 0,
        next_attempt_at: Some(rfc3339(Utc::now() + crate::retry::PREPARE_GUARD)),
        error: None,
        status_queries: 0,
        network_id: Some(network_id),
        target: r.address.clone(),
        adapter_id: Some(adapter.id.clone()),
        result_text: None,
    })
}

/// A call in pending work.
#[derive(Debug, Serialize)]
pub struct PendingCall {
    pub call_id: String,
    pub address: String,
    pub operation: String,
    pub state: String,
    pub error: Option<String>,
    pub result_bytes: Option<usize>,
    pub created_at: String,
    pub deadline: String,
    pub session_id: String,
    pub redelivered: bool,
    #[serde(skip)]
    called_at_ms: i64,
}

/// The calls a session still owes attention: the agent's unfinished calls
/// made by this session or by an ended authorization of the agent, and
/// the calls whose notification this session holds unseen. Oldest first.
pub(crate) fn pending_calls(conn: &Connection, session: &str) -> Result<Vec<PendingCall>, Error> {
    let agent: String = conn.query_row(
        "SELECT agent_id FROM sessions WHERE id = ?1",
        [session],
        |r| r.get(0),
    )?;
    type Row = (String, String, String, i64, Option<i64>);
    let rows: Vec<Row> = {
        let mut stmt = conn.prepare("SELECT c.peer, c.call_id, c.session_id, c.called_at_ms, (SELECT n.redeliveries FROM call_update_notifications n WHERE n.peer = c.peer AND n.call_id = c.call_id AND n.session_id = ?2 AND n.seen_at IS NULL AND n.returned_at IS NULL) FROM adapter_calls c WHERE c.agent_id = ?1 ORDER BY c.called_at_ms, c.rowid")?;
        stmt.query_map(params![agent, session], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<Result<_, _>>()?
    };
    let mut ended: HashMap<String, bool> = HashMap::new();
    let mut out = Vec::new();
    for (peer, id, maker, called, held) in rows {
        let call = call_outbound::stored(conn, &peer, &id)?;
        let listed = if call.finished() {
            held.is_some()
        } else if maker == session {
            true
        } else {
            match ended.get(&maker) {
                Some(v) => *v,
                None => {
                    let v = session_ended(conn, &maker)?;
                    ended.insert(maker.clone(), v);
                    v
                }
            }
        };
        if !listed {
            continue;
        }
        out.push(PendingCall {
            call_id: id,
            address: call.target.clone(),
            operation: call.request.operation.clone(),
            state: view_state(&call),
            error: view_error(&call),
            result_bytes: result_text(&call).map(|t| t.len()),
            created_at: created_at(called),
            deadline: call.request.deadline.clone(),
            session_id: maker,
            redelivered: held.is_some_and(|n| n > 0),
            called_at_ms: called,
        });
    }
    out.sort_by_key(|c| c.called_at_ms);
    Ok(out)
}

/// Returns to the agent's queue the claimed, unseen notifications whose
/// authorization has ended, up to the redelivery limit.
pub(crate) fn return_calls(
    tx: &Transaction<'_>,
    agent: &str,
    ended: &mut crate::live_delivery::Ended,
    at: &str,
) -> Result<(), Error> {
    let rows: Vec<(String, i64)> = {
        let mut stmt = tx.prepare("SELECT n.record, n.redeliveries FROM call_update_notifications n JOIN sessions s ON s.id = n.session_id WHERE s.agent_id = ?1 AND n.seen_at IS NULL AND n.returned_at IS NULL AND json_extract(n.record, '$.claimed') = 1 ORDER BY n.rowid")?;
        stmt.query_map([agent], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    for (record, count) in rows {
        let n: StoredNotification = serde_json::from_str(&record)?;
        if count < crate::live_delivery::MAX_REDELIVERIES
            && ended.check(tx, &n.notification.adapter_id)?
        {
            tx.execute(
                "UPDATE call_update_notifications SET returned_at = ?1 WHERE id = ?2",
                params![at, n.notification.id],
            )?;
        }
    }
    Ok(())
}

pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/capabilities", get(capabilities_route))
        .route("/adapter/v1/calls", post(create_route))
        .route("/adapter/v1/calls/{id}", get(status_route))
        .route("/adapter/v1/calls/{id}/cancel", post(cancel_route))
        .route("/adapter/v1/call-updates/next", post(next_route))
        .route(
            "/adapter/v1/call-updates/{id}/forwarded",
            post(forwarded_route),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

async fn capabilities_route(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    let auth = token(&headers);
    let (_, ss) = blocking(store.clone(), move |s| {
        calls_authority(&*s.connection()?, &auth)
    })
    .await?;
    let (capabilities, unanswered) =
        call_outbound::agent_capabilities(&store, &ss.agent_id).await?;
    Ok(Json(
        json!({"capabilities": capabilities, "unanswered": unanswered}),
    ))
}
async fn create_route(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let auth = token(&headers);
    // The credential is checked before the body.
    let a = auth.clone();
    blocking(store.clone(), move |s| {
        calls_authority(&*s.connection()?, &a).map(|_| ())
    })
    .await?;
    let r: AgentCall = decode(body)?;
    Ok(Json(create(store, auth, r).await?))
}
#[derive(Deserialize)]
struct OffsetQuery {
    #[serde(default)]
    offset: Option<String>,
}
async fn status_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<OffsetQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    let auth = token(&headers);
    let offset = match query.ok().and_then(|Query(q)| q.offset) {
        None => Some(0),
        Some(text) => text.parse::<usize>().ok(),
    };
    let a = auth.clone();
    let Some(offset) = offset else {
        blocking(store, move |s| {
            calls_authority(&*s.connection()?, &a).map(|_| ())
        })
        .await?;
        return Err(Error::Invalid("offset is a whole number of bytes".into()));
    };
    Ok(Json(
        blocking(store, move |s| s.agent_call_status(&auth, &id, offset)).await?,
    ))
}
async fn cancel_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let auth = token(&headers);
    let (a, i) = (auth.clone(), id.clone());
    let (peer, called) = blocking(store.clone(), move |s| s.agent_call_scope(&a, &i)).await?;
    let _: Empty = decode(body)?;
    let (p, i) = (peer.clone(), id.clone());
    let mut out = blocking(store.clone(), move |s| s.request_call_cancel(&p, &i)).await?;
    if out.submit_state == "accepted" && out.cancel_state.as_deref() == Some("unknown") {
        out = call_outbound::send_cancel(&store, out).await?;
    }
    Ok(Json(view(&out, called, 0)?))
}
async fn next_route(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<CallUpdate>>, Error> {
    let auth = token(&headers);
    let a = auth.clone();
    blocking(store.clone(), move |s| {
        calls_authority(&*s.connection()?, &a).map(|_| ())
    })
    .await?;
    let _: Empty = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.next_call_update(&auth)).await?,
    ))
}
async fn forwarded_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<CallUpdateNotification>, Error> {
    let auth = token(&headers);
    let a = auth.clone();
    blocking(store.clone(), move |s| {
        calls_authority(&*s.connection()?, &a).map(|_| ())
    })
    .await?;
    let _: Empty = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.call_update_forwarded(&auth, &id)).await?,
    ))
}
