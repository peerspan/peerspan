//! Live delivery slice 2: seen tracking, the return of unseen items when an
//! authorization ends, and the work a session still owes.
use crate::{
    adapter::{Adapter, Delivery, authority, read, token},
    adapter_connection::AdapterAuth,
    adapter_outbound::ReplyDelivery,
    api::{blocking, decode},
    model::Error,
    peer_store::MessageRequest,
    store::{Store, append_event, now},
    task::{TaskDelivery, TaskRequest, status_record},
    task_outbound::TaskUpdateNotification,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

/// How many times an item is claimed again after a return.
pub(crate) const MAX_REDELIVERIES: i64 = 3;
/// The error of a queued task past the redelivery limit.
pub(crate) const NEVER_SEEN: &str = "session never saw the task";
/// Characters of content in a pending item's preview.
const PREVIEW: usize = 200;

/// Schema version 15: seen, return, and redelivery columns on handed-off
/// items and the adopting claim on tasks, each added only when missing. Every
/// existing row is marked seen, so nothing from before the upgrade is
/// redelivered.
pub(crate) fn migrate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    let item = [
        ("seen_at", "TEXT"),
        ("redeliveries", "INTEGER NOT NULL DEFAULT 0"),
        ("returned_at", "TEXT"),
    ];
    let task = [
        ("seen_at", "TEXT"),
        ("redeliveries", "INTEGER NOT NULL DEFAULT 0"),
        ("returned_at", "TEXT"),
        ("cancel_seen_at", "TEXT"),
        ("adopted_at", "TEXT"),
    ];
    let reply = [
        ("reply_seen_at", "TEXT"),
        ("reply_redeliveries", "INTEGER NOT NULL DEFAULT 0"),
        ("reply_returned_at", "TEXT"),
    ];
    let tables: [(&str, &[(&str, &str)]); 4] = [
        ("deliveries", &item),
        ("task_update_notifications", &item),
        ("task_deliveries", &task),
        ("adapter_outbound", &reply),
    ];
    for (table, columns) in tables {
        let present = {
            let mut statement =
                tx.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (column, kind) in columns {
            if !present.iter().any(|c| c == column) {
                tx.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind};"))?;
            }
        }
    }
    let at = now();
    for (table, column) in [
        ("deliveries", "seen_at"),
        ("task_update_notifications", "seen_at"),
        ("task_deliveries", "seen_at"),
        ("task_deliveries", "cancel_seen_at"),
        ("adapter_outbound", "reply_seen_at"),
    ] {
        tx.execute(
            &format!("UPDATE {table} SET {column} = COALESCE({column}, ?1)"),
            [&at],
        )?;
    }
    tx.execute_batch("PRAGMA user_version = 15;")
}

fn passed(text: &str) -> bool {
    DateTime::parse_from_rfc3339(text).is_ok_and(|t| t <= Utc::now())
}

/// Whether an authorization has ended: replaced or revoked, expired, or
/// detached. A session detached only by a daemon restart, which its adapter
/// may still recover, has not ended.
pub(crate) fn ended(conn: &Connection, adapter_id: &str) -> Result<bool, Error> {
    let (record, state, recoverable): (String, String, bool) = match conn.query_row(
        "SELECT c.record, s.state, x.recoverable FROM adapter_credentials c JOIN sessions s ON s.id = c.session_id JOIN adapter_connections x ON x.adapter_id = c.id WHERE c.id = ?1",
        [adapter_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ) {
        Ok(row) => row,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(true),
        Err(e) => return Err(e.into()),
    };
    let a: Adapter = serde_json::from_str(&record)?;
    Ok(a.revoked_at.is_some() || passed(&a.expires_at) || (state == "detached" && !recoverable))
}
/// `ended`, remembered per authorization for one pass.
#[derive(Default)]
pub(crate) struct Ended(HashMap<String, bool>);
impl Ended {
    pub(crate) fn check(&mut self, conn: &Connection, adapter_id: &str) -> Result<bool, Error> {
        if let Some(value) = self.0.get(adapter_id) {
            return Ok(*value);
        }
        let value = ended(conn, adapter_id)?;
        self.0.insert(adapter_id.to_owned(), value);
        Ok(value)
    }
}

/// Returns to the agent's queue every unseen item that an ended
/// authorization of the agent holds, as a verified session of the agent
/// claims work or lists its pending work. Items past the redelivery limit
/// end instead: a message is blocked and a queued task fails.
pub(crate) fn return_items(tx: &Transaction<'_>, agent: &str) -> Result<(), Error> {
    let at = now();
    let mut ended = Ended::default();
    // Inbound deliveries, forwarded (claimed) but neither answered nor seen.
    let rows = {
        let mut stmt = tx.prepare("SELECT d.record, d.redeliveries FROM deliveries d JOIN sessions s ON s.id = d.session_id WHERE s.agent_id = ?1 AND d.seen_at IS NULL AND d.returned_at IS NULL AND json_extract(d.record, '$.state') IN ('unknown', 'forwarded') ORDER BY d.rowid")?;
        stmt.query_map([agent], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    for (record, count) in rows {
        let mut d: Delivery = serde_json::from_str(&record)?;
        if !ended.check(tx, &d.adapter_id)? {
            continue;
        }
        let request: MessageRequest = read(
            tx,
            "SELECT request FROM received_messages WHERE sender = ?1 AND request_id = ?2",
            params![d.sender_host_id, d.request_id],
        )?;
        if passed(&request.deadline) {
            continue;
        }
        if count >= MAX_REDELIVERIES {
            d.state = "blocked".into();
            d.updated_at = at.clone();
            tx.execute(
                "UPDATE deliveries SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&d)?, d.id],
            )?;
            append_event(tx, "message.blocked", &d.id, &at)?;
        } else {
            tx.execute(
                "UPDATE deliveries SET returned_at = ?1 WHERE id = ?2",
                params![at, d.id],
            )?;
        }
    }
    // Replies to the agent's sends, handed off but unseen.
    let rows = {
        let mut stmt = tx.prepare("SELECT o.reply_delivery, o.reply_redeliveries FROM adapter_outbound o JOIN sessions s ON s.id = o.session_id WHERE s.agent_id = ?1 AND o.reply_delivery IS NOT NULL AND o.reply_seen_at IS NULL AND o.reply_returned_at IS NULL ORDER BY o.rowid")?;
        stmt.query_map([agent], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    for (record, count) in rows {
        let d: ReplyDelivery = serde_json::from_str(&record)?;
        if count < MAX_REDELIVERIES && ended.check(tx, &d.adapter_id)? {
            tx.execute(
                "UPDATE adapter_outbound SET reply_returned_at = ?1 WHERE peer = ?2 AND request_id = ?3",
                params![at, d.peer_host_id, d.request_id],
            )?;
        }
    }
    // Task updates handed off but unseen.
    let rows = {
        let mut stmt = tx.prepare("SELECT n.record, n.redeliveries FROM task_update_notifications n JOIN sessions s ON s.id = json_extract(n.record, '$.session_id') WHERE s.agent_id = ?1 AND n.seen_at IS NULL AND n.returned_at IS NULL ORDER BY n.rowid")?;
        stmt.query_map([agent], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    for (record, count) in rows {
        let n: TaskUpdateNotification = serde_json::from_str(&record)?;
        if count < MAX_REDELIVERIES && ended.check(tx, &n.adapter_id)? {
            tx.execute(
                "UPDATE task_update_notifications SET returned_at = ?1 WHERE id = ?2",
                params![at, n.id],
            )?;
        }
    }
    // Tasks: queued and unseen, to redeliver, or running, to adopt.
    let rows = {
        let mut stmt = tx.prepare("SELECT d.record, d.redeliveries, d.seen_at IS NOT NULL, t.request, t.record FROM task_deliveries d JOIN sessions s ON s.id = d.session_id JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE s.agent_id = ?1 AND d.returned_at IS NULL AND json_extract(t.record, '$.state') IN ('queued', 'running') ORDER BY d.rowid")?;
        stmt.query_map([agent], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    for (record, count, seen, request, status) in rows {
        let d: TaskDelivery = serde_json::from_str(&record)?;
        if !ended.check(tx, &d.adapter_id)? {
            continue;
        }
        let request: TaskRequest = serde_json::from_str(&request)?;
        let mut status = status_record(&status)?;
        if status.state == "queued" {
            if seen || crate::task::expire(tx, &d.sender_host_id, &request, &mut status)? {
                continue;
            }
            if count >= MAX_REDELIVERIES {
                crate::task::record(
                    tx,
                    &d.sender_host_id,
                    &mut status,
                    "failed",
                    Some(NEVER_SEEN.into()),
                    None,
                    None,
                )?;
                continue;
            }
        }
        tx.execute(
            "UPDATE task_deliveries SET returned_at = ?1 WHERE id = ?2",
            params![at, d.id],
        )?;
    }
    Ok(())
}

/// The first 200 characters of some content.
fn preview(text: &str) -> String {
    text.chars().take(PREVIEW).collect()
}

#[derive(Debug, Serialize)]
pub struct PendingDelivery {
    pub delivery_id: String,
    pub request_id: String,
    pub sender_host_id: String,
    pub origin_agent_id: Option<String>,
    pub preview: String,
    pub seen: bool,
    pub deadline: Option<String>,
    pub redelivered: bool,
}
#[derive(Debug, Serialize)]
pub struct PendingReply {
    pub notification_id: String,
    pub request_id: String,
    pub peer_host_id: String,
    pub preview: String,
}
#[derive(Debug, Serialize)]
pub struct PendingTask {
    pub task_id: String,
    pub delivery_id: String,
    pub sender_host_id: String,
    pub state: String,
    pub preview: String,
    pub deadline: Option<String>,
    pub adopted: bool,
}
/// The work a session still owes, in each list in the order the items
/// first reached this host.
#[derive(Debug, Serialize)]
pub struct Pending {
    pub deliveries: Vec<PendingDelivery>,
    pub replies: Vec<PendingReply>,
    pub tasks: Vec<PendingTask>,
}

/// The items a session holds: by its session, and by its authorization
/// when given.
fn pending(conn: &Connection, session: &str, adapter: Option<&str>) -> Result<Pending, Error> {
    let holds = |adapter_id: &str| adapter.is_none_or(|a| a == adapter_id);
    let mut deliveries = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT d.record, d.seen_at IS NOT NULL, d.redeliveries, m.request FROM deliveries d JOIN received_messages m ON m.sender = d.sender AND m.request_id = d.request_id WHERE d.session_id = ?1 AND d.returned_at IS NULL AND json_extract(d.record, '$.state') IN ('unknown', 'forwarded') ORDER BY m.rowid")?;
        let rows = stmt
            .query_map([session], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (record, seen, count, request) in rows {
            let d: Delivery = serde_json::from_str(&record)?;
            if !holds(&d.adapter_id) || d.session_id != session {
                continue;
            }
            let request: MessageRequest = serde_json::from_str(&request)?;
            deliveries.push(PendingDelivery {
                delivery_id: d.id,
                request_id: d.request_id,
                sender_host_id: d.sender_host_id,
                origin_agent_id: request.origin.map(|o| o.agent_id),
                preview: preview(&request.content),
                seen,
                deadline: Some(request.deadline).filter(|d| !d.is_empty()),
                redelivered: count > 0,
            });
        }
    }
    let mut replies = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT o.reply_delivery, r.record FROM adapter_outbound o JOIN outbound_replies r ON r.peer = o.peer AND r.request_id = o.request_id WHERE o.session_id = ?1 AND o.reply_delivery IS NOT NULL AND o.reply_seen_at IS NULL AND o.reply_returned_at IS NULL ORDER BY r.rowid")?;
        let rows = stmt
            .query_map([session], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (record, reply) in rows {
            let d: ReplyDelivery = serde_json::from_str(&record)?;
            if !holds(&d.adapter_id) || d.session_id != session {
                continue;
            }
            let reply: crate::adapter::Reply = serde_json::from_str(&reply)?;
            replies.push(PendingReply {
                notification_id: d.id,
                request_id: d.request_id,
                peer_host_id: d.peer_host_id,
                preview: preview(&reply.content),
            });
        }
    }
    let mut tasks = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT d.record, d.adopted_at IS NOT NULL, t.request, t.record FROM task_deliveries d JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE d.session_id = ?1 AND d.returned_at IS NULL AND json_extract(t.record, '$.state') IN ('queued', 'running') ORDER BY t.rowid")?;
        let rows = stmt
            .query_map([session], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (record, adopted, request, status) in rows {
            let d: TaskDelivery = serde_json::from_str(&record)?;
            if !holds(&d.adapter_id) || d.session_id != session {
                continue;
            }
            let request: TaskRequest = serde_json::from_str(&request)?;
            let status = status_record(&status)?;
            tasks.push(PendingTask {
                task_id: d.task_id,
                delivery_id: d.id,
                sender_host_id: d.sender_host_id,
                state: if status.state == "running" && status.cancel_requested {
                    "cancel_requested".into()
                } else {
                    status.state
                },
                preview: preview(&request.input),
                deadline: Some(request.deadline).filter(|d| !d.is_empty()),
                adopted,
            });
        }
    }
    Ok(Pending {
        deliveries,
        replies,
        tasks,
    })
}

/// Marks what a session holds under one ID seen. Returns whether the ID is
/// held, and whether anything was newly marked.
fn mark(
    tx: &Transaction<'_>,
    a: &str,
    session: &str,
    id: &str,
    at: &str,
) -> Result<(bool, bool), Error> {
    if id.starts_with("delivery_") {
        let held: Option<(String, bool)> = rusqlite::OptionalExtension::optional(tx.query_row(
            "SELECT record, seen_at IS NOT NULL FROM deliveries WHERE id = ?1 AND session_id = ?2 AND returned_at IS NULL",
            params![id, session],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        let Some((record, seen)) = held else {
            // A task's delivery ID stands for the task's cancellation
            // request.
            let task: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_deliveries WHERE id = ?1 AND session_id = ?2 AND returned_at IS NULL AND json_extract(record, '$.adapter_id') = ?3)",
                params![id, session, a],
                |r| r.get(0),
            )?;
            if !task {
                return Ok((false, false));
            }
            let changed = tx.execute(
                "UPDATE task_deliveries SET cancel_seen_at = ?1 WHERE id = ?2 AND cancel_seen_at IS NULL AND json_extract(record, '$.cancel_claimed_at') IS NOT NULL",
                params![at, id],
            )? > 0;
            return Ok((true, changed));
        };
        let d: Delivery = serde_json::from_str(&record)?;
        if d.adapter_id != a || d.state == "blocked" {
            return Ok((false, false));
        }
        if !seen {
            tx.execute(
                "UPDATE deliveries SET seen_at = ?1 WHERE id = ?2",
                params![at, id],
            )?;
        }
        return Ok((true, !seen));
    }
    if id.starts_with("request_") {
        let own: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM adapter_outbound WHERE adapter_id = ?1 AND request_id = ?2)",
            params![a, id],
            |r| r.get(0),
        )?;
        let changed = mark_reply(tx, a, session, id, at)?;
        let held = own
            || {
                tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM adapter_outbound WHERE request_id = ?1 AND session_id = ?2 AND reply_returned_at IS NULL AND json_extract(reply_delivery, '$.adapter_id') = ?3 AND json_extract(reply_delivery, '$.session_id') = ?2)",
                params![id, session, a],
                |r| r.get(0),
            )?
            };
        return Ok((held, changed));
    }
    if id.starts_with("task_") {
        let claimed: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_deliveries WHERE task_id = ?1 AND session_id = ?2 AND returned_at IS NULL AND json_extract(record, '$.adapter_id') = ?3)",
            params![id, session, a],
            |r| r.get(0),
        )?;
        let own: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbound_tasks WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2)",
            params![id, a],
            |r| r.get(0),
        )?;
        let notified: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_update_notifications WHERE task_id = ?1 AND returned_at IS NULL AND json_extract(record, '$.adapter_id') = ?2 AND json_extract(record, '$.session_id') = ?3)",
            params![id, a, session],
            |r| r.get(0),
        )?;
        let changed =
            mark_cancel(tx, a, session, id, at)? | mark_updates(tx, a, session, id, None, at)?;
        return Ok((claimed || own || notified, changed));
    }
    Ok((false, false))
}
/// Marks the reply to a send seen, when this session holds it.
pub(crate) fn mark_reply(
    tx: &Connection,
    a: &str,
    session: &str,
    request: &str,
    at: &str,
) -> Result<bool, Error> {
    Ok(tx.execute(
        "UPDATE adapter_outbound SET reply_seen_at = ?1 WHERE request_id = ?2 AND session_id = ?3 AND reply_seen_at IS NULL AND reply_returned_at IS NULL AND json_extract(reply_delivery, '$.adapter_id') = ?4 AND json_extract(reply_delivery, '$.session_id') = ?3",
        params![at, request, session, a],
    )? > 0)
}
/// Marks the cancellation request of a task this session holds seen, once
/// the session claimed it.
pub(crate) fn mark_cancel(
    tx: &Connection,
    a: &str,
    session: &str,
    task: &str,
    at: &str,
) -> Result<bool, Error> {
    Ok(tx.execute(
        "UPDATE task_deliveries SET cancel_seen_at = ?1 WHERE task_id = ?2 AND session_id = ?3 AND returned_at IS NULL AND cancel_seen_at IS NULL AND json_extract(record, '$.adapter_id') = ?4 AND json_extract(record, '$.cancel_claimed_at') IS NOT NULL",
        params![at, task, session, a],
    )? > 0)
}
/// Marks the task updates this session holds for a task seen; `peer`
/// narrows them to one receiver.
pub(crate) fn mark_updates(
    tx: &Connection,
    a: &str,
    session: &str,
    task: &str,
    peer: Option<&str>,
    at: &str,
) -> Result<bool, Error> {
    Ok(tx.execute(
        "UPDATE task_update_notifications SET seen_at = ?1 WHERE task_id = ?2 AND (?5 IS NULL OR peer = ?5) AND seen_at IS NULL AND returned_at IS NULL AND json_extract(record, '$.adapter_id') = ?3 AND json_extract(record, '$.session_id') = ?4",
        params![at, task, a, session, peer],
    )? > 0)
}

fn valid_item(id: &str) -> bool {
    ["delivery", "request", "task"]
        .iter()
        .any(|prefix| crate::peer_store::valid_id(id, prefix, 16))
}

impl Store {
    /// `POST /adapter/v1/seen`: marks 1 to 100 items this session holds
    /// seen. An ID it does not hold changes nothing and is not found.
    pub fn mark_seen(&self, auth: &AdapterAuth, ids: &[String]) -> Result<Vec<String>, Error> {
        if ids.is_empty() || ids.len() > 100 || !ids.iter().all(|id| valid_item(id)) {
            return Err(Error::Invalid(
                "ids must be 1 to 100 delivery, request, or task IDs".into(),
            ));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        let at = now();
        let mut seen: Vec<String> = Vec::new();
        for id in ids {
            let (held, changed) = mark(&tx, &a.id, &ss.id, id, &at)?;
            if !held {
                return Err(Error::NotFound);
            }
            if changed && !seen.contains(id) {
                seen.push(id.clone());
            }
        }
        tx.commit()?;
        Ok(seen)
    }
    /// `GET /adapter/v1/pending`. A verified session first takes back what
    /// the agent's ended authorizations left unseen.
    pub fn adapter_pending(&self, auth: &AdapterAuth) -> Result<Pending, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        if crate::adapter_connection::verified_authority(&tx, auth).is_ok() {
            return_items(&tx, &ss.agent_id)?;
        }
        let result = pending(&tx, &ss.id, Some(&a.id))?;
        tx.commit()?;
        Ok(result)
    }
    /// `GET /v1/sessions/{id}/pending`: the same object for the owner.
    pub fn session_pending(&self, id: &str) -> Result<Pending, Error> {
        let conn = self.connection()?;
        crate::adapter::session(&conn, id)?;
        pending(&conn, id, None)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeenRequest {
    ids: Vec<String>,
}
#[derive(Serialize)]
struct SeenResponse {
    seen: Vec<String>,
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/seen", post(seen))
        .route("/adapter/v1/pending", get(adapter_pending))
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/sessions/{id}/pending", get(session_pending))
}
async fn seen(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<SeenResponse>, Error> {
    let r: SeenRequest = decode(body)?;
    let auth = token(&headers);
    Ok(Json(SeenResponse {
        seen: blocking(store, move |s| s.mark_seen(&auth, &r.ids)).await?,
    }))
}
async fn adapter_pending(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
) -> Result<Json<Pending>, Error> {
    let auth = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.adapter_pending(&auth)).await?,
    ))
}
async fn session_pending(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Pending>, Error> {
    Ok(Json(
        blocking(store, move |s| s.session_pending(&id)).await?,
    ))
}
