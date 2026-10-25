//! Per-call approval (capabilities contract, slice 3 item B): the owner can
//! require that calls to selected operations of a capability wait until the
//! person approves each one at a terminal on this host. This module keeps
//! the requirement's shape, the approval records and their notices, the
//! owner's local routes, and the adapter's notice routes. The call
//! transitions that go with each decision live with the calls.
use crate::{
    adapter::token,
    adapter_connection::{AdapterAuth, verified_authority},
    api::{blocking, decode},
    calls::{CallRequest, call_id_shape},
    model::Error,
    peer_store::{Origin, valid_id},
    sources::Snapshot,
    store::{Store, new_id},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

/// Database version 20. Version 19 is reserved for machine linking.
pub(crate) const SCHEMA: &str = "
CREATE TABLE call_approvals (sender TEXT NOT NULL, call_id TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id), FOREIGN KEY(sender, call_id) REFERENCES received_calls(sender, call_id));
CREATE INDEX call_approvals_state ON call_approvals(state, expires_at);
CREATE TABLE approval_notices (id TEXT PRIMARY KEY, sender TEXT NOT NULL, call_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id), session_id TEXT REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, call_id));
PRAGMA user_version = 20;
";

/// At most this many approvals are pending per pending key.
pub const MAX_PENDING: i64 = 20;
/// `approvals --all` lists decided approvals this recent.
const DECIDED_LISTED: TimeDelta = TimeDelta::days(7);
/// The longest input preview, in bytes.
const PREVIEW_BYTES: usize = 512;
/// The longest denial reason, in bytes of UTF-8.
const MAX_REASON: usize = 1024;

/// The approval requirement of a capability record. `operations` is
/// `"none"`, `"changing"`, `"all"`, or a sorted list of operation names.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Requirement {
    pub operations: Value,
    pub agent_self: bool,
}
impl Default for Requirement {
    fn default() -> Self {
        Requirement {
            operations: json!("none"),
            agent_self: true,
        }
    }
}
impl Requirement {
    /// Whether the requirement covers an operation, read against the
    /// snapshot the call runs against.
    pub fn covers(&self, operation: &str, snapshot: Option<&Snapshot>) -> bool {
        match &self.operations {
            Value::String(mode) if mode == "all" => true,
            Value::String(mode) if mode == "changing" => {
                operation != crate::capabilities::READ && changes_things(operation, snapshot)
            }
            Value::Array(list) => list.iter().any(|o| o.as_str() == Some(operation)),
            _ => false,
        }
    }
    /// `none`, `changing`, `all`, or the list joined with `,`.
    pub fn mode(&self) -> String {
        match &self.operations {
            Value::String(mode) => mode.clone(),
            Value::Array(list) => list
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
            _ => "none".into(),
        }
    }
}
/// Whether a tool operation can change things: its snapshot entry is not
/// marked read-only. `read` never does.
pub fn changes_things(operation: &str, snapshot: Option<&Snapshot>) -> bool {
    operation != crate::capabilities::READ
        && !snapshot
            .and_then(|s| s.tool(operation))
            .is_some_and(|t| t.read_only)
}

/// Checks `operations` of a requirement against a record's operations,
/// and returns its stored form: a list deduplicated and sorted by bytes.
pub fn parse_operations(value: &Value, operations: &[String], reads: bool) -> Result<Value, Error> {
    let invalid = || {
        Error::Invalid(
            "approval operations is none, changing, all, or a non-empty list of the capability's operations".into(),
        )
    };
    match value {
        Value::String(mode) if matches!(mode.as_str(), "none" | "changing" | "all") => {
            Ok(value.clone())
        }
        Value::Array(list) if !list.is_empty() => {
            let mut names = Vec::new();
            for item in list {
                let name = item.as_str().ok_or_else(invalid)?;
                let known = operations.iter().any(|o| o == name)
                    || (reads && name == crate::capabilities::READ);
                if !known {
                    return Err(Error::Invalid(format!(
                        "{name} is not an operation of the capability"
                    )));
                }
                names.push(name.to_owned());
            }
            names.sort();
            names.dedup();
            Ok(json!(names))
        }
        _ => Err(invalid()),
    }
}
/// Reads an `approval` body, `{operations, agent_self}`: `operations` is
/// required, and an absent `agent_self` is `keep`.
pub fn parse_requirement(
    body: &Value,
    operations: &[String],
    reads: bool,
    keep: bool,
) -> Result<Requirement, Error> {
    let Some(object) = body.as_object() else {
        return Err(Error::Invalid(
            "approval is {operations, agent_self}".into(),
        ));
    };
    if object
        .keys()
        .any(|k| k != "operations" && k != "agent_self")
    {
        return Err(Error::Invalid(
            "approval has only operations and agent_self".into(),
        ));
    }
    let ops = match object.get("operations") {
        None | Some(Value::Null) => {
            return Err(Error::Invalid("approval operations is required".into()));
        }
        Some(v) => parse_operations(v, operations, reads)?,
    };
    let agent_self = match object.get("agent_self") {
        None | Some(Value::Null) => keep,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(Error::Invalid("agent_self is a boolean".into())),
    };
    Ok(Requirement {
        operations: ops,
        agent_self,
    })
}

/// Who made a call, as an approval shows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Caller {
    pub person_id: Option<String>,
    pub person_label: Option<String>,
    pub host_id: String,
    /// `policy` or `self`, as cited.
    pub via: String,
}
/// The record of one received call's approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub sender_host_id: String,
    pub call_id: String,
    /// `pending`, `approved`, `denied`, `expired`, or `cancelled`.
    pub state: String,
    pub capability: String,
    pub operation: String,
    pub changes_things: bool,
    pub caller: Caller,
    pub origin: Option<Value>,
    pub input_sha256: String,
    pub requested_at: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
    pub reason: Option<String>,
}
impl ApprovalRecord {
    /// The `approval` object of the peer status record.
    pub fn status(&self) -> ApprovalStatus {
        ApprovalStatus {
            state: self.state.clone(),
            requested_at: self.requested_at.clone(),
            expires_at: self.expires_at.clone(),
            decided_at: self.decided_at.clone(),
            reason: self.reason.clone(),
        }
    }
}
/// `call_approvals.record`: the approval record and its pending key,
/// which is not shown.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stored {
    #[serde(flatten)]
    record: ApprovalRecord,
    pending_key: String,
}
/// The `approval` object of a peer status record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ApprovalStatus {
    pub state: String,
    pub requested_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub decided_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}
pub const APPROVAL_STATES: [&str; 5] = ["pending", "approved", "denied", "expired", "cancelled"];

/// The origin of a call as an approval shows it.
pub fn origin_value(origin: Option<&Origin>) -> Option<Value> {
    origin.map(|o| json!({"agent_id": o.agent_id, "session_id": o.session_id}))
}

/// A notice for the capability's source agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notice {
    pub id: String,
    pub sender_host_id: String,
    pub call_id: String,
    pub agent_id: String,
    pub session_id: Option<String>,
    /// `unknown`, `forwarded`, or `void`.
    pub state: String,
    pub created_at: String,
}
/// `approval_notices.record`: the notice, and the credential that claimed
/// it, which is not shown.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredNotice {
    #[serde(flatten)]
    notice: Notice,
    #[serde(default)]
    adapter_id: Option<String>,
}

fn load(conn: &Connection, sender: &str, id: &str) -> Result<Option<Stored>, Error> {
    conn.query_row(
        "SELECT record FROM call_approvals WHERE sender = ?1 AND call_id = ?2",
        params![sender, id],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|r| Ok(serde_json::from_str(&r)?))
    .transpose()
}
/// One call's approval record, if it has one.
pub(crate) fn approval(
    conn: &Connection,
    sender: &str,
    id: &str,
) -> Result<Option<ApprovalRecord>, Error> {
    Ok(load(conn, sender, id)?.map(|s| s.record))
}
/// Approvals pending under a pending key.
pub(crate) fn pending_under(conn: &Connection, key: &str) -> Result<i64, Error> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM call_approvals WHERE state = 'pending' AND json_extract(record, '$.pending_key') = ?1",
        [key],
        |r| r.get(0),
    )?)
}
/// Stores a new pending approval and its notice for the source agent.
pub(crate) fn create(
    tx: &Transaction<'_>,
    record: &ApprovalRecord,
    pending_key: String,
    agent_id: &str,
) -> Result<(), Error> {
    let stored = Stored {
        record: record.clone(),
        pending_key,
    };
    tx.execute(
        "INSERT INTO call_approvals VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            record.sender_host_id,
            record.call_id,
            record.state,
            record.expires_at,
            serde_json::to_string(&stored)?
        ],
    )?;
    // A built-in source has no source agent, so there is no session to
    // notify: the approval waits at the owner's CLI only.
    if crate::builtin::is_builtin(agent_id) {
        return Ok(());
    }
    let notice = StoredNotice {
        notice: Notice {
            id: new_id("notice")?,
            sender_host_id: record.sender_host_id.clone(),
            call_id: record.call_id.clone(),
            agent_id: agent_id.to_owned(),
            session_id: None,
            state: "unknown".into(),
            created_at: record.requested_at.clone(),
        },
        adapter_id: None,
    };
    tx.execute(
        "INSERT INTO approval_notices (id, sender, call_id, agent_id, session_id, record) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
        params![
            notice.notice.id,
            record.sender_host_id,
            record.call_id,
            agent_id,
            serde_json::to_string(&notice)?
        ],
    )?;
    Ok(())
}
/// Moves a pending approval to `state`, setting `decided_at` and the
/// reason, and voids its notice unless claimed. Returns the record, or
/// None when it is not pending.
pub(crate) fn decide(
    tx: &Transaction<'_>,
    sender: &str,
    id: &str,
    state: &str,
    reason: Option<String>,
    at: &str,
) -> Result<Option<ApprovalRecord>, Error> {
    let Some(mut stored) = load(tx, sender, id)? else {
        return Ok(None);
    };
    if stored.record.state != "pending" {
        return Ok(None);
    }
    stored.record.state = state.to_owned();
    stored.record.decided_at = Some(at.to_owned());
    stored.record.reason = reason;
    tx.execute(
        "UPDATE call_approvals SET state = ?1, record = ?2 WHERE sender = ?3 AND call_id = ?4",
        params![state, serde_json::to_string(&stored)?, sender, id],
    )?;
    // A notice whose approval leaves pending before it is claimed is void.
    let notices: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT record FROM approval_notices WHERE sender = ?1 AND call_id = ?2 AND session_id IS NULL",
        )?;
        stmt.query_map(params![sender, id], |r| r.get(0))?
            .collect::<Result<_, _>>()?
    };
    for record in notices {
        let mut n: StoredNotice = serde_json::from_str(&record)?;
        n.notice.state = "void".into();
        tx.execute(
            "UPDATE approval_notices SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&n)?, n.notice.id],
        )?;
    }
    Ok(Some(stored.record))
}
/// The 409 for a decision on an approval no longer pending.
pub(crate) fn not_pending(record: &ApprovalRecord) -> Error {
    Error::Coded {
        status: 409,
        code: "conflict",
        message: "the call is no longer waiting for approval".into(),
        extra: [("approval".to_owned(), json!(record))]
            .into_iter()
            .collect(),
    }
}
/// A denial reason: a string or null, an empty string reading as null,
/// at most 1,024 bytes.
pub(crate) fn reason_of(body: &Value) -> Result<Option<String>, Error> {
    let Some(object) = body.as_object() else {
        return Err(Error::Invalid("the body is {reason}".into()));
    };
    if object.keys().any(|k| k != "reason") {
        return Err(Error::Invalid("the body is {reason}".into()));
    }
    match object.get("reason") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) if s.len() <= MAX_REASON => Ok(Some(s.clone())),
        Some(Value::String(_)) => Err(Error::Invalid(
            "reason is at most 1024 bytes of UTF-8".into(),
        )),
        Some(_) => Err(Error::Invalid("reason is a string or null".into())),
    }
}

/// The input text: the input encoded as the call view encodes a result.
fn input_text(input: &Value) -> Option<String> {
    (!input.is_null()).then(|| crate::canonical::value_text(input))
}
/// Writes U+007F and U+0080 to U+009F as `\u` and four lowercase hex
/// digits.
fn escape_c1(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
/// The longest prefix of at most 512 bytes ending on a character
/// boundary, escaped.
fn preview(text: &str) -> String {
    let mut end = text.len().min(PREVIEW_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    escape_c1(&text[..end])
}
/// A call's stored input, or null once deleted.
fn stored_input(
    conn: &Connection,
    sender: &str,
    id: &str,
) -> Result<(Value, Option<String>), Error> {
    let request: Option<String> = conn
        .query_row(
            "SELECT request FROM received_calls WHERE sender = ?1 AND call_id = ?2",
            params![sender, id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match request {
        // The canonical text from the stored request text, numbers as sent.
        Some(r) => {
            let input = serde_json::from_str::<CallRequest>(&r)?.input;
            let text = (!input.is_null())
                .then(|| crate::canonical::member_text(r.as_bytes(), "input"))
                .flatten()
                .or_else(|| input_text(&input));
            (input, text)
        }
        None => (Value::Null, None),
    })
}
/// The approval record plus `input_preview` and `input_bytes`, and with
/// `full`, `input`.
fn item(conn: &Connection, record: &ApprovalRecord, full: bool) -> Result<Value, Error> {
    let (input, text) = stored_input(conn, &record.sender_host_id, &record.call_id)?;
    let mut value = json!(record);
    value["input_preview"] = json!(text.as_deref().map(preview));
    value["input_bytes"] = json!(text.as_ref().map(String::len));
    if full {
        value["input"] = input;
    }
    Ok(value)
}
fn time_of(text: &str) -> chrono::DateTime<Utc> {
    crate::membership::time(text).unwrap_or_default()
}
fn records(
    conn: &Connection,
    query: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<ApprovalRecord>, Error> {
    let mut stmt = conn.prepare(query)?;
    let rows: Vec<String> = stmt
        .query_map(args, |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|r| Ok(serde_json::from_str::<Stored>(&r)?.record))
        .collect()
}
/// Oldest first by `requested_at`, then sender, then call ID.
fn sort(list: &mut [ApprovalRecord]) {
    list.sort_by(|a, b| {
        (time_of(&a.requested_at), &a.sender_host_id, &a.call_id).cmp(&(
            time_of(&b.requested_at),
            &b.sender_host_id,
            &b.call_id,
        ))
    });
}

impl Store {
    /// The pending approvals, oldest first.
    pub(crate) fn pending_approvals(&self) -> Result<Vec<ApprovalRecord>, Error> {
        let conn = self.connection()?;
        let mut list = records(
            &conn,
            "SELECT record FROM call_approvals WHERE state = 'pending'",
            [],
        )?;
        sort(&mut list);
        Ok(list)
    }
    /// `GET /v1/approvals?state=pending|all`.
    pub fn approvals_view(&self, all: bool) -> Result<Value, Error> {
        let conn = self.connection()?;
        let mut list = records(&conn, "SELECT record FROM call_approvals", [])?;
        let since = Utc::now() - DECIDED_LISTED;
        list.retain(|r| {
            r.state == "pending"
                || (all && r.decided_at.as_deref().is_some_and(|d| time_of(d) >= since))
        });
        sort(&mut list);
        let items = list
            .iter()
            .map(|r| item(&conn, r, false))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({ "approvals": items }))
    }
    /// `GET /v1/approvals/{sender}/{call_id}`.
    pub fn approval_show(&self, sender: &str, id: &str) -> Result<Value, Error> {
        let conn = self.connection()?;
        let record = approval(&conn, sender, id)?.ok_or(Error::NotFound)?;
        item(&conn, &record, true)
    }
    /// `GET /v1/approvals/{call_id}`: the one approval with that call ID,
    /// 409 `ambiguous` when several senders used it.
    pub fn approval_resolve(&self, id: &str) -> Result<Value, Error> {
        let conn = self.connection()?;
        let mut found = records(
            &conn,
            "SELECT record FROM call_approvals WHERE call_id = ?1",
            [id],
        )?;
        match found.len() {
            0 => Err(Error::NotFound),
            1 => item(&conn, &found.remove(0), true),
            _ => {
                let mut candidates: Vec<String> = found
                    .iter()
                    .map(|r| format!("{}/{}", r.sender_host_id, r.call_id))
                    .collect();
                candidates.sort();
                Err(Error::Coded {
                    status: 409,
                    code: "ambiguous",
                    message: format!(
                        "several senders used call ID {id}; use one of {}",
                        candidates.join(", ")
                    ),
                    extra: [("candidates".to_owned(), json!(candidates))]
                        .into_iter()
                        .collect(),
                })
            }
        }
    }
    /// `POST /adapter/v1/approval-notices/next`: claims the oldest notice
    /// of this session's agent that no session holds and whose approval is
    /// still pending.
    pub fn next_approval_notice(&self, auth: &AdapterAuth) -> Result<Option<Value>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = verified_authority(&tx, auth)?;
        let rows: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT n.record FROM approval_notices n JOIN call_approvals c ON c.sender = n.sender AND c.call_id = n.call_id WHERE n.agent_id = ?1 AND n.session_id IS NULL AND c.state = 'pending'",
            )?;
            stmt.query_map([&ss.agent_id], |r| r.get(0))?
                .collect::<Result<_, _>>()?
        };
        let mut notices = rows
            .iter()
            .map(|r| serde_json::from_str::<StoredNotice>(r))
            .collect::<Result<Vec<_>, _>>()?;
        notices.retain(|n| n.notice.state != "void");
        notices.sort_by(|x, y| {
            (time_of(&x.notice.created_at), &x.notice.id)
                .cmp(&(time_of(&y.notice.created_at), &y.notice.id))
        });
        let Some(mut n) = notices.into_iter().next() else {
            tx.commit()?;
            return Ok(None);
        };
        n.notice.session_id = Some(ss.id.clone());
        n.adapter_id = Some(a.id.clone());
        tx.execute(
            "UPDATE approval_notices SET session_id = ?1, record = ?2 WHERE id = ?3",
            params![ss.id, serde_json::to_string(&n)?, n.notice.id],
        )?;
        let record =
            approval(&tx, &n.notice.sender_host_id, &n.notice.call_id)?.ok_or(Error::NotFound)?;
        tx.commit()?;
        Ok(Some(json!({"notice": n.notice, "approval": record})))
    }
    /// `POST /adapter/v1/approval-notices/{id}/forwarded`.
    pub fn approval_notice_forwarded(&self, auth: &AdapterAuth, id: &str) -> Result<Notice, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, _) = crate::adapter::authority(&tx, auth)?;
        let record: String = tx
            .query_row(
                "SELECT record FROM approval_notices WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let mut n: StoredNotice = serde_json::from_str(&record)?;
        if n.adapter_id.as_deref() != Some(a.id.as_str()) {
            return Err(Error::NotFound);
        }
        if n.notice.state != "forwarded" {
            n.notice.state = "forwarded".into();
            tx.execute(
                "UPDATE approval_notices SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&n)?, n.notice.id],
            )?;
            tx.commit()?;
        }
        Ok(n.notice)
    }
    /// Status item 18: one item while any approval is pending.
    pub(crate) fn approval_attention(&self) -> Result<Option<(String, String, String)>, Error> {
        let pending = self.pending_approvals()?;
        let Some(oldest) = pending.first() else {
            return Ok(None);
        };
        let caller = oldest
            .caller
            .person_label
            .clone()
            .unwrap_or_else(|| oldest.caller.host_id.clone());
        Ok(Some((
            pending.len().to_string(),
            format!(
                "{} call(s) wait for your approval; the oldest calls {} ({}) from {}, until {}",
                pending.len(),
                oldest.capability,
                oldest.operation,
                caller,
                oldest.expires_at
            ),
            "peerspan approvals".into(),
        )))
    }
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    state: Option<String>,
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/approvals", get(list_route))
        .route("/v1/approvals/{id}", get(resolve_route))
        .route("/v1/approvals/{sender}/{id}", get(show_route))
        .route("/v1/approvals/{sender}/{id}/approve", post(approve_route))
        .route("/v1/approvals/{sender}/{id}/deny", post(deny_route))
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/approval-notices/next", post(next_route))
        .route(
            "/adapter/v1/approval-notices/{id}/forwarded",
            post(forwarded_route),
        )
}
async fn list_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid query".into()))?;
    let all = match q.state.as_deref() {
        None | Some("pending") => false,
        Some("all") => true,
        Some(_) => return Err(Error::Invalid("state is pending or all".into())),
    };
    Ok(Json(blocking(store, move |s| s.approvals_view(all)).await?))
}
async fn resolve_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.approval_resolve(&id)).await?,
    ))
}
async fn show_route(
    State(store): State<Arc<Store>>,
    Path((sender, id)): Path<(String, String)>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.approval_show(&sender, &id)).await?,
    ))
}
fn ids_shape(sender: &str, id: &str) -> Result<(), Error> {
    if valid_id(sender, "host", 32) && call_id_shape(id) {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn approve_route(
    State(store): State<Arc<Store>>,
    Path((sender, id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<ApprovalRecord>, Error> {
    let _: Empty = decode(body)?;
    ids_shape(&sender, &id)?;
    Ok(Json(
        blocking(store, move |s| s.approve_call(&sender, &id)).await?,
    ))
}
async fn deny_route(
    State(store): State<Arc<Store>>,
    Path((sender, id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<ApprovalRecord>, Error> {
    let body: Value = decode(body)?;
    let reason = reason_of(&body)?;
    ids_shape(&sender, &id)?;
    Ok(Json(
        blocking(store, move |s| s.deny_call(&sender, &id, reason)).await?,
    ))
}
async fn next_route(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<Value>>, Error> {
    let auth = token(&headers);
    let a = auth.clone();
    blocking(store.clone(), move |s| {
        crate::adapter::authority(&*s.connection()?, &a).map(|_| ())
    })
    .await?;
    let _: Empty = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.next_approval_notice(&auth)).await?,
    ))
}
async fn forwarded_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Notice>, Error> {
    let auth = token(&headers);
    let a = auth.clone();
    blocking(store.clone(), move |s| {
        crate::adapter::authority(&*s.connection()?, &a).map(|_| ())
    })
    .await?;
    let _: Empty = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.approval_notice_forwarded(&auth, &id)).await?,
    ))
}
