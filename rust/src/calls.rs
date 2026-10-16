//! Calls to shared tools (tools contract): the receiving host. A peer lists
//! what it may call, submits a `tools/call` or `resources/read` request,
//! and polls its status. The host authorizes each call by policy or self
//! access from a trusted host, persists it, and runs it on the
//! server's instance, never twice.
use crate::{
    api::{blocking, decode},
    mcp::{self, Reply},
    model::Error,
    peer_store::{Origin, valid_id},
    policy::{
        ALL_AGENTS, MAX_INPUT_BYTES, Policy, PolicyRef, SelfRef, ToolRule, principal_matches,
    },
    store::{Store, append_event, now, rfc3339},
    tools::{Instance, Snapshot},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    routing::{get, post},
};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Notify, watch};

/// A deadline is at most this long after submission.
pub const MAX_DEADLINE: TimeDelta = TimeDelta::minutes(15);
/// Arguments and results are deleted this long after a call is final.
const RETENTION: TimeDelta = TimeDelta::days(7);
/// One instance runs at most this many calls at once.
const PER_INSTANCE: usize = 4;
/// The rejection reason when authorization lapses before a call starts.
pub const LAPSED: &str = "authorization lapsed before start";
pub const FINAL: [&str; 6] = [
    "succeeded",
    "failed",
    "rejected",
    "expired",
    "cancelled",
    "uncertain",
];
pub const STATES: [&str; 8] = [
    "queued",
    "running",
    "succeeded",
    "failed",
    "rejected",
    "expired",
    "cancelled",
    "uncertain",
];
pub fn is_final(state: &str) -> bool {
    FINAL.contains(&state)
}

/// Present, possibly null: `profile` must always be sent.
fn nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

/// A call as submitted on the wire.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CallRequest {
    pub call_id: String,
    pub target_agent_id: String,
    pub server: String,
    #[serde(deserialize_with = "nullable")]
    pub profile: Option<String>,
    pub kind: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub name: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub uri: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub arguments: Option<Value>,
    pub deadline: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub origin: Option<Origin>,
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
    #[serde(
        rename = "self",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub self_access: Option<SelfRef>,
}
impl CallRequest {
    pub fn instance(&self) -> Instance {
        Instance {
            agent_id: self.target_agent_id.clone(),
            server: self.server.clone(),
            profile: self.profile.clone(),
        }
    }
    fn tool(&self) -> bool {
        self.kind == "tool"
    }
    /// The tool name or the URI.
    fn target(&self) -> &str {
        self.name
            .as_deref()
            .or(self.uri.as_deref())
            .unwrap_or_default()
    }
    /// What `max_input_bytes` bounds: the JSON encoding of `arguments`, or
    /// the URI.
    fn input_size(&self) -> usize {
        match &self.arguments {
            Some(a) if self.tool() => serde_json::to_vec(a).map(|v| v.len()).unwrap_or(usize::MAX),
            _ => self.uri.as_deref().map_or(0, str::len),
        }
    }
    fn arguments_sha256(&self) -> String {
        let encoded = match &self.arguments {
            Some(a) => serde_json::to_vec(a).unwrap_or_default(),
            None => Vec::new(),
        };
        hex::encode(sha2::Sha256::digest(encoded))
    }
}
pub fn call_id_shape(id: &str) -> bool {
    valid_id(id, "call", 16)
}
fn validate(r: &CallRequest) -> Result<(), Error> {
    let shape = call_id_shape(&r.call_id)
        && valid_id(&r.target_agent_id, "agent", 16)
        && crate::policy::tool_name_shape(&r.server)
        && r.profile
            .as_deref()
            .is_none_or(crate::policy::tool_name_shape)
        && r.origin.as_ref().is_none_or(Origin::valid)
        && crate::peer_store::one_authorization(
            r.grant_id.as_deref(),
            r.policy.as_ref(),
            r.self_access.as_ref(),
        );
    let body = match r.kind.as_str() {
        "tool" => {
            r.name.as_deref().is_some_and(|n| !n.is_empty())
                && r.uri.is_none()
                && r.arguments.as_ref().is_some_and(Value::is_object)
        }
        "resource" => {
            r.uri.as_deref().is_some_and(|u| !u.is_empty())
                && r.name.is_none()
                && r.arguments.is_none()
        }
        _ => false,
    };
    if !shape || !body {
        return Err(Error::Invalid("invalid call".into()));
    }
    crate::membership::time(&r.deadline)?;
    Ok(())
}

/// The status record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CallStatus {
    pub call_id: String,
    pub sender_host_id: String,
    pub receiver_host_id: String,
    pub target_agent_id: String,
    pub server: String,
    pub profile: Option<String>,
    pub kind: String,
    pub name: Option<String>,
    pub uri: Option<String>,
    pub state: String,
    pub cancel_requested: bool,
    pub error: Option<String>,
    pub result_bytes: Option<i64>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}
/// `received_calls.record`: the status, the result, and what the receiver
/// keeps for itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stored {
    #[serde(flatten)]
    status: CallStatus,
    #[serde(default)]
    result: Option<Value>,
    arguments_sha256: String,
    /// The rule or grant whose hourly budget the call counted against.
    #[serde(default)]
    budget: Option<String>,
    caller: String,
    accepted_ms: i64,
    #[serde(default)]
    finished_ms: Option<i64>,
}
/// A status record, with its result once final.
#[derive(Serialize)]
pub struct CallView {
    #[serde(flatten)]
    pub status: CallStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}
fn view(s: Stored, with_result: bool) -> CallView {
    let result =
        (with_result && is_final(&s.status.state)).then(|| s.result.unwrap_or(Value::Null));
    CallView {
        status: s.status,
        result,
    }
}

fn load(conn: &Connection, sender: &str, id: &str) -> Result<Option<(CallRequest, Stored)>, Error> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT request, record FROM received_calls WHERE sender = ?1 AND call_id = ?2",
            params![sender, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(r, s)| Ok((serde_json::from_str(&r)?, serde_json::from_str(&s)?)))
        .transpose()
}
fn save(tx: &Transaction<'_>, sender: &str, s: &Stored) -> Result<(), Error> {
    tx.execute(
        "UPDATE received_calls SET record = ?1 WHERE sender = ?2 AND call_id = ?3",
        params![serde_json::to_string(s)?, sender, s.status.call_id],
    )?;
    Ok(())
}
fn subject(sender: &str, id: &str) -> String {
    format!("{sender}/{id}")
}
/// Moves a call to a final state, with `call.finished`.
fn finish(
    tx: &Transaction<'_>,
    sender: &str,
    s: &mut Stored,
    state: &str,
    error: Option<&str>,
    result: Option<Value>,
) -> Result<(), Error> {
    let at = Utc::now();
    s.status.state = state.into();
    s.status.error = error.map(str::to_owned);
    s.status.result_bytes = result
        .as_ref()
        .map(|r| serde_json::to_vec(r).map(|v| v.len() as i64).unwrap_or(0));
    s.result = result;
    s.status.finished_at = Some(rfc3339(at));
    s.finished_ms = Some(at.timestamp_millis());
    save(tx, sender, s)?;
    append_event(
        tx,
        "call.finished",
        &subject(sender, &s.status.call_id),
        &rfc3339(at),
    )?;
    Ok(())
}
/// A queued call past its deadline becomes `expired`.
fn expire(
    tx: &Transaction<'_>,
    sender: &str,
    r: &CallRequest,
    s: &mut Stored,
) -> Result<bool, Error> {
    if s.status.state != "queued" || crate::membership::time(&r.deadline)? > Utc::now() {
        return Ok(false);
    }
    finish(tx, sender, s, "expired", None, None)?;
    Ok(true)
}

/// Whether a tool rule covers a tool (by its scope) or a resource (every
/// resource of the snapshot, under `resource.read`).
fn covers(rule: &ToolRule, tool: bool, target: &str, snapshot: Option<&Snapshot>) -> bool {
    if !tool {
        return rule.reads_resources();
    }
    rule.calls_tools()
        && rule.scope.iter().any(|entry| match entry.as_str() {
            "*" => true,
            "readonly" => snapshot
                .and_then(|s| s.tool(target))
                .is_some_and(|t| t.read_only),
            name => name == target,
        })
}
/// The read-only rule: under policy or a grant, a tool of a server without
/// a profile must be read-only.
fn read_only_ok(instance: &Instance, tool: bool, target: &str, snapshot: &Snapshot) -> bool {
    !tool || instance.profile.is_some() || snapshot.tool(target).is_some_and(|t| t.read_only)
}

/// One way a call is authorized: its bounds and budget.
#[derive(Clone, Debug)]
struct Candidate {
    /// The budget key and its hourly limit; none under self access.
    budget: Option<(String, i64)>,
    max_input: i64,
    until: Option<DateTime<Utc>>,
    allow_disconnected: bool,
    caller: String,
}
/// What authorized an accepted call.
pub(crate) struct Authorized {
    budget: Option<String>,
    caller: String,
}

/// The policy of this host's person in a network, if in its window.
fn own_policy(
    store: &Store,
    conn: &Connection,
    network: &str,
    person: &str,
) -> Result<Option<Policy>, Error> {
    let Some(key) = store.person_key(conn, network, person)? else {
        return Ok(None);
    };
    store.stored_policy(conn, network, &key)
}
/// The networks in which self access from a trusted host covers `sender`:
/// both hosts are bound to the same person, and that person's newest
/// verified policy there, within its window, lists the sender as trusted.
fn trusted_networks(
    store: &Store,
    conn: &Connection,
    sender: &str,
    person: Option<&str>,
) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    if sender == store.identity().id {
        return Ok(out);
    }
    let at = Utc::now();
    for (network, own) in store.own_members(conn)? {
        let Some(p) = own.person_id.as_deref() else {
            continue;
        };
        if person.is_some_and(|x| x != p) {
            continue;
        }
        let bound = crate::chain::member(conn, &network, sender)?
            .is_some_and(|m| m.person_id.as_deref() == Some(p));
        if !bound {
            continue;
        }
        if let Some(policy) = own_policy(store, conn, &network, p)?
            && policy.in_window(at)
            && policy.trusted_hosts().iter().any(|h| h == sender)
        {
            out.push((network.clone(), p.to_owned()));
        }
    }
    Ok(out)
}
fn agent_name(conn: &Connection, id: &str) -> Result<Option<String>, Error> {
    Ok(conn
        .query_row("SELECT name FROM agents WHERE id = ?1", [id], |r| r.get(0))
        .optional()?)
}
/// Whether a tool rule applies to agent `name` and this server or profile:
/// the rule names the agent, or is a `*` rule while no tool rule names the
/// agent for it.
fn rule_applies(policy: &Policy, rule: &crate::policy::ToolRule, name: &str, server: &str) -> bool {
    if rule.server != server {
        return false;
    }
    if rule.agent == name {
        return true;
    }
    rule.agent == ALL_AGENTS
        && !policy
            .tool_rules()
            .iter()
            .any(|r| r.agent == name && r.server == server)
}
fn rule_key(network: &str, person: &str, rule: &crate::policy::ToolRule) -> String {
    let encoded = serde_json::to_vec(rule).unwrap_or_default();
    format!(
        "policy:{network}:{person}:{}",
        hex::encode(sha2::Sha256::digest(encoded))
    )
}
/// The policy, grant, or self authorizations a call cites that match it,
/// and whether it relies on self access.
fn candidates(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &CallRequest,
    snapshot: Option<&Snapshot>,
) -> Result<(Vec<Candidate>, bool), Error> {
    let instance = r.instance();
    let label = instance.label();
    let Some(name) = agent_name(conn, &r.target_agent_id)? else {
        return Err(Error::NotFound);
    };
    if let Some(cited) = &r.self_access {
        let trusted = trusted_networks(store, conn, sender, Some(&cited.person_id))?;
        if trusted.is_empty() {
            return Err(Error::Forbidden);
        }
        return Ok((
            vec![Candidate {
                budget: None,
                max_input: MAX_INPUT_BYTES,
                until: None,
                allow_disconnected: true,
                caller: cited.person_id.clone(),
            }],
            true,
        ));
    }
    let mut out = Vec::new();
    if let Some(cited) = &r.policy {
        let at = Utc::now();
        let mut behind = false;
        for (network, own) in store.own_members(conn)? {
            if own.person_id.as_deref() != Some(cited.person_id.as_str()) {
                continue;
            }
            let Some(policy) = own_policy(store, conn, &network, &cited.person_id)? else {
                behind = true;
                continue;
            };
            if policy.version < cited.version {
                behind = true;
                continue;
            }
            if !policy.in_window(at) {
                continue;
            }
            let Some(sender_member) = crate::chain::member(conn, &network, sender)?
                .filter(|m| m.host_id != store.identity().id)
            else {
                continue;
            };
            let groups = store.stored_groups(conn, &network)?;
            let caller = sender_member
                .person_id
                .clone()
                .unwrap_or_else(|| sender.to_owned());
            for rule in policy.tool_rules() {
                if rule_applies(&policy, rule, &name, &label)
                    && rule
                        .principals
                        .iter()
                        .any(|p| principal_matches(p, &sender_member, &groups, r.origin.as_ref()))
                    && covers(rule, r.tool(), r.target(), snapshot)
                {
                    out.push(Candidate {
                        budget: Some((
                            rule_key(&network, &cited.person_id, rule),
                            rule.max_calls_per_hour,
                        )),
                        max_input: rule.max_input_bytes,
                        until: crate::membership::time(&policy.valid_until).ok(),
                        allow_disconnected: rule.allow_disconnected,
                        caller: caller.clone(),
                    });
                }
            }
        }
        if out.is_empty() && behind {
            return Err(Error::Unavailable(
                "this host has not yet received the cited policy version".into(),
            ));
        }
    }
    if out.is_empty() {
        return Err(Error::Forbidden);
    }
    Ok((out, false))
}
/// Calls counted against a budget by a caller in the trailing hour.
fn used(conn: &Connection, budget: &str, caller: &str) -> Result<i64, Error> {
    let since = Utc::now().timestamp_millis() - 3_600_000;
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM received_calls WHERE json_extract(record, '$.budget') = ?1 AND json_extract(record, '$.caller') = ?2 AND json_extract(record, '$.accepted_ms') > ?3",
        params![budget, caller, since],
        |r| r.get(0),
    )?)
}

/// Authorizes a call, in the contract's order: a matching citation, then
/// blocks (except self), the snapshot (404), the read-only rule (except
/// self), the bounds (413, the deadline, the connected state), and, at
/// submission, the hourly budget (429).
fn authorize(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &CallRequest,
    budget: bool,
) -> Result<Authorized, Error> {
    let instance = r.instance();
    let snapshot = store.offered(conn, &instance)?;
    let (candidates, self_access) = candidates(store, conn, sender, r, snapshot.as_ref())?;
    if !self_access && store.blocked(conn, sender)? {
        return Err(Error::Forbidden);
    }
    let Some(snapshot) = snapshot else {
        return Err(Error::NotFound);
    };
    let present = if r.tool() {
        snapshot.tool(r.target()).is_some()
    } else {
        snapshot.resource(r.target()).is_some()
    };
    if !present {
        return Err(Error::NotFound);
    }
    if !self_access && !read_only_ok(&instance, r.tool(), r.target(), &snapshot) {
        return Err(Error::Forbidden);
    }
    let size = r.input_size() as i64;
    let fit: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| size <= c.max_input)
        .collect();
    if fit.is_empty() {
        return Err(Error::TooLarge(
            "the input is larger than the authorization's max_input_bytes".into(),
        ));
    }
    let deadline = crate::membership::time(&r.deadline)?;
    let fit: Vec<Candidate> = fit
        .into_iter()
        .filter(|c| c.until.is_none_or(|u| deadline <= u))
        .collect();
    if fit.is_empty() {
        return Err(Error::Forbidden);
    }
    let connected = store.connected(conn, sender)?;
    let fit: Vec<Candidate> = fit
        .into_iter()
        .filter(|c| c.allow_disconnected || connected)
        .collect();
    if fit.is_empty() {
        let member: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_members WHERE host_id = ?1)",
            [sender],
            |r| r.get(0),
        )?;
        return Err(if member {
            Error::Unavailable("coordination disconnected".into())
        } else {
            Error::Forbidden
        });
    }
    if !budget {
        let c = &fit[0];
        return Ok(Authorized {
            budget: c.budget.as_ref().map(|(k, _)| k.clone()),
            caller: c.caller.clone(),
        });
    }
    for c in &fit {
        match &c.budget {
            None => {
                return Ok(Authorized {
                    budget: None,
                    caller: c.caller.clone(),
                });
            }
            Some((key, limit)) if used(conn, key, &c.caller)? < *limit => {
                return Ok(Authorized {
                    budget: Some(key.clone()),
                    caller: c.caller.clone(),
                });
            }
            Some(_) => {}
        }
    }
    Err(Error::Limit {
        limit: "max_calls_per_hour".into(),
        message: "the hourly call budget of this authorization is used up".into(),
    })
}

/// In-memory state of the call runner.
#[derive(Default)]
pub struct Runner {
    /// Calls running or starting on each instance.
    claimed: Mutex<HashMap<mcp::Key, usize>>,
    /// Calls being dispatched, so each runs once.
    inflight: Mutex<HashSet<(String, String)>>,
    /// Running calls' cancellation signals.
    cancels: Mutex<HashMap<(String, String), Arc<Notify>>>,
    /// Wakes the dispatcher.
    wake: Notify,
}

#[derive(Deserialize)]
pub(crate) struct ToolsQuery {
    #[serde(default)]
    network: Option<String>,
}

impl Store {
    /// `POST /peer/v1/calls`: authorizes a call and persists it as `queued`.
    pub fn accept_call(&self, sender: &str, r: CallRequest) -> Result<CallStatus, Error> {
        validate(&r)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if let Some((old, mut s)) = load(&tx, sender, &r.call_id)? {
            let strip = |c: &CallRequest| CallRequest {
                arguments: None,
                ..c.clone()
            };
            if strip(&old) != strip(&r) || s.arguments_sha256 != r.arguments_sha256() {
                return Err(Error::Conflict(
                    "call ID reused with different fields".into(),
                ));
            }
            if expire(&tx, sender, &old, &mut s)? {
                tx.commit()?;
            }
            return Ok(s.status);
        }
        let at = Utc::now();
        let deadline = crate::membership::time(&r.deadline)?;
        if deadline <= at || deadline > at + MAX_DEADLINE {
            return Err(Error::Invalid(
                "a deadline is in the future and at most 15 minutes away".into(),
            ));
        }
        let authorized = authorize(self, &tx, sender, &r, true)?;
        let status = CallStatus {
            call_id: r.call_id.clone(),
            sender_host_id: sender.to_owned(),
            receiver_host_id: self.identity().id,
            target_agent_id: r.target_agent_id.clone(),
            server: r.server.clone(),
            profile: r.profile.clone(),
            kind: r.kind.clone(),
            name: r.name.clone(),
            uri: r.uri.clone(),
            state: "queued".into(),
            cancel_requested: false,
            error: None,
            result_bytes: None,
            created_at: rfc3339(at),
            started_at: None,
            finished_at: None,
        };
        let stored = Stored {
            status: status.clone(),
            result: None,
            arguments_sha256: r.arguments_sha256(),
            budget: authorized.budget,
            caller: authorized.caller,
            accepted_ms: at.timestamp_millis(),
            finished_ms: None,
        };
        tx.execute(
            "INSERT INTO received_calls VALUES (?1, ?2, ?3, ?4)",
            params![
                sender,
                r.call_id,
                serde_json::to_string(&r)?,
                serde_json::to_string(&stored)?
            ],
        )?;
        append_event(
            &tx,
            "call.received",
            &subject(sender, &r.call_id),
            &status.created_at,
        )?;
        tx.commit()?;
        self.call_runner.wake.notify_one();
        Ok(status)
    }
    /// The submitter's call, settled for expiry; anyone else's is not found.
    pub fn call_status(&self, sender: &str, id: &str) -> Result<CallView, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (request, mut s) = load(&tx, sender, id)?.ok_or(Error::NotFound)?;
        if expire(&tx, sender, &request, &mut s)? {
            tx.commit()?;
        }
        Ok(view(s, true))
    }
    /// Sets `cancel_requested`: a queued call becomes `cancelled`, and a
    /// running one `uncertain`, unless its result arrived first. Returns
    /// the status and whether a running call must be told.
    fn cancel_call(&self, sender: &str, id: &str) -> Result<(CallStatus, bool), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (request, mut s) = load(&tx, sender, id)?.ok_or(Error::NotFound)?;
        expire(&tx, sender, &request, &mut s)?;
        let mut running = false;
        if !s.status.cancel_requested && !is_final(&s.status.state) {
            s.status.cancel_requested = true;
            append_event(&tx, "call.cancel_requested", &subject(sender, id), &now())?;
            match s.status.state.as_str() {
                "queued" => finish(&tx, sender, &mut s, "cancelled", None, None)?,
                _ => {
                    running = true;
                    finish(
                        &tx,
                        sender,
                        &mut s,
                        "uncertain",
                        Some("cancel_requested"),
                        None,
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok((s.status, running))
    }
    /// Calls received by this host, in insertion order.
    pub fn received_calls(&self, after: i64, limit: i64) -> Result<Vec<Value>, Error> {
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("invalid page bounds".into()));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT rowid, request, record FROM received_calls WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![after, limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::new();
        let mut bytes = 2;
        for (sequence, request, record) in rows {
            let request: CallRequest = serde_json::from_str(&request)?;
            let s: Stored = serde_json::from_str(&record)?;
            let item = json!({
                "sequence": sequence,
                "request": request,
                "status": s.status,
                "arguments_sha256": s.arguments_sha256,
            });
            let size = item.to_string().len() + 1;
            if bytes + size > 900_000 {
                break;
            }
            bytes += size;
            out.push(item);
        }
        Ok(out)
    }
    /// `GET /peer/v1/tools`: what the sender may call or read here, from
    /// snapshots, filtered by authorization without budgets. With a
    /// network, only self and policy authorizations from it count.
    pub fn listing(&self, sender: &str, network: Option<&str>) -> Result<Vec<Value>, Error> {
        let conn = self.connection()?;
        let at = Utc::now();
        let in_scope = |n: &str| network.is_none_or(|x| x == n);
        let selfs: Vec<String> = trusted_networks(self, &conn, sender, None)?
            .into_iter()
            .map(|(n, _)| n)
            .filter(|n| in_scope(n))
            .collect();
        let blocked = self.blocked(&conn, sender)?;
        // This host's person's policies the sender is a member under.
        let mut policies = Vec::new();
        if !blocked {
            for (net, own) in self.own_members(&conn)? {
                if !in_scope(&net) {
                    continue;
                }
                let Some(person) = own.person_id.clone() else {
                    continue;
                };
                let Some(policy) = own_policy(self, &conn, &net, &person)? else {
                    continue;
                };
                if !policy.in_window(at) {
                    continue;
                }
                let Some(sender_member) = crate::chain::member(&conn, &net, sender)?
                    .filter(|m| m.host_id != self.identity().id)
                else {
                    continue;
                };
                let groups = self.stored_groups(&conn, &net)?;
                policies.push((net, person, policy, sender_member, groups));
            }
        }
        let names = crate::tools::agent_names(&conn)?;
        let mut out = Vec::new();
        for offered in self.offered_all(&conn)? {
            let instance = &offered.instance;
            let snapshot = &offered.snapshot;
            let Some(name) = names.get(&instance.agent_id) else {
                continue;
            };
            let label = instance.label();
            let via = |tool: bool, target: &str| -> Vec<Value> {
                let mut via: Vec<Value> = selfs
                    .iter()
                    .map(|n| json!({"kind": "self", "network_id": n}))
                    .collect();
                let read_only = read_only_ok(instance, tool, target, snapshot);
                for (net, person, policy, member, groups) in &policies {
                    let allowed = read_only
                        && policy.tool_rules().iter().any(|rule| {
                            rule_applies(policy, rule, name, &label)
                                && rule
                                    .principals
                                    .iter()
                                    .any(|p| principal_matches(p, member, groups, None))
                                && covers(rule, tool, target, Some(snapshot))
                        });
                    if allowed {
                        via.push(json!({"kind": "policy", "network_id": net, "person_id": person, "version": policy.version}));
                    }
                }
                via
            };
            let tools: Vec<Value> = snapshot
                .tools
                .iter()
                .filter_map(|t| {
                    let via = via(true, &t.name);
                    (!via.is_empty()).then(|| {
                        json!({
                            "name": t.name,
                            "description": t.description,
                            "input_schema": t.input_schema,
                            "read_only": t.read_only,
                            "via": via,
                        })
                    })
                })
                .collect();
            let resources: Vec<Value> = snapshot
                .resources
                .iter()
                .filter_map(|r| {
                    let via = via(false, &r.uri);
                    (!via.is_empty()).then(|| {
                        json!({
                            "uri": r.uri,
                            "name": r.name,
                            "description": r.description,
                            "mime_type": r.mime_type,
                            "via": via,
                        })
                    })
                })
                .collect();
            if tools.is_empty() && resources.is_empty() {
                continue;
            }
            out.push((
                (
                    name.clone(),
                    instance.server.clone(),
                    instance.profile.clone(),
                ),
                json!({
                    "agent": name,
                    "agent_id": instance.agent_id,
                    "server": instance.server,
                    "profile": instance.profile,
                    "tools": tools,
                    "resources": resources,
                }),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out.into_iter().map(|(_, v)| v).collect())
    }

    /// Expires queued calls past their deadlines.
    fn expire_calls(&self) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let rows = queued(&tx)?;
        let mut changed = false;
        for (sender, request, mut s) in rows {
            changed |= expire(&tx, &sender, &request, &mut s)?;
        }
        if changed {
            tx.commit()?;
        }
        Ok(())
    }
    /// Queued calls in order: sender, call ID, and instance.
    fn queued_calls(&self) -> Result<Vec<(String, String, Instance)>, Error> {
        let connection = self.connection()?;
        Ok(queued(&connection)?
            .into_iter()
            .map(|(sender, r, _)| (sender, r.call_id.clone(), r.instance()))
            .collect())
    }
    /// Rechecks a queued call immediately before it starts and marks it
    /// `running`. A lapse records `rejected`; a call no longer queued, or
    /// past its deadline, does not start.
    fn start_call(&self, sender: &str, id: &str) -> Result<Option<CallRequest>, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let Some((request, mut s)) = load(&tx, sender, id)? else {
            return Ok(None);
        };
        if s.status.state != "queued" {
            return Ok(None);
        }
        if expire(&tx, sender, &request, &mut s)? {
            tx.commit()?;
            return Ok(None);
        }
        if authorize(self, &tx, sender, &request, false).is_err() {
            finish(&tx, sender, &mut s, "rejected", Some(LAPSED), None)?;
            tx.commit()?;
            return Ok(None);
        }
        let at = now();
        s.status.state = "running".into();
        s.status.started_at = Some(at.clone());
        save(&tx, sender, &s)?;
        append_event(&tx, "call.started", &subject(sender, id), &at)?;
        tx.commit()?;
        Ok(Some(request))
    }
    /// Whether a call is still queued, before its instance starts.
    fn still_queued(&self, sender: &str, id: &str) -> Result<bool, Error> {
        Ok(
            load(&*self.connection()?, sender, id)?
                .is_some_and(|(_, s)| s.status.state == "queued"),
        )
    }
    /// Ends a call that was not sent: every queued call of an instance that
    /// failed to start fails with `server_start_failed`.
    fn fail_queued(&self, instance: &Instance, error: &str) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        for (sender, request, mut s) in queued(&tx)? {
            if request.instance() == *instance {
                finish(&tx, &sender, &mut s, "failed", Some(error), None)?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// Ends a running call exactly once. Returns false when it had already
    /// ended (cancelled, past its deadline, or a restart).
    fn end_call(
        &self,
        sender: &str,
        id: &str,
        state: &str,
        error: Option<&str>,
        result: Option<Value>,
    ) -> Result<bool, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let Some((_, mut s)) = load(&tx, sender, id)? else {
            return Ok(false);
        };
        if s.status.state != "running" {
            return Ok(false);
        }
        finish(&tx, sender, &mut s, state, error, result)?;
        tx.commit()?;
        Ok(true)
    }
    /// At start: every call still `running` becomes `uncertain`, never
    /// re-executed.
    pub(crate) fn settle_running_calls(tx: &Transaction<'_>) -> Result<(), Error> {
        let rows: Vec<(String, String)> = {
            let mut statement = tx.prepare(
                "SELECT sender, record FROM received_calls WHERE json_extract(record, '$.state') = 'running'",
            )?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        for (sender, record) in rows {
            let mut s: Stored = serde_json::from_str(&record)?;
            finish(
                tx,
                &sender,
                &mut s,
                "uncertain",
                Some("daemon_restarted"),
                None,
            )?;
        }
        Ok(())
    }
    /// Deletes arguments and results 7 days after their calls became final.
    fn prune_calls(&self) -> Result<(), Error> {
        let cutoff = (Utc::now() - RETENTION).timestamp_millis();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let rows: Vec<(String, String, String)> = {
            let mut statement = tx.prepare(
                "SELECT sender, request, record FROM received_calls WHERE json_extract(record, '$.finished_ms') < ?1 AND (json_extract(request, '$.arguments') IS NOT NULL OR json_extract(record, '$.result') IS NOT NULL)",
            )?;
            statement
                .query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?
        };
        for (sender, request, record) in rows {
            let mut request: Value = serde_json::from_str(&request)?;
            let mut s: Stored = serde_json::from_str(&record)?;
            if let Some(object) = request.as_object_mut() {
                object.remove("arguments");
            }
            s.result = None;
            tx.execute(
                "UPDATE received_calls SET request = ?1, record = ?2 WHERE sender = ?3 AND call_id = ?4",
                params![request.to_string(), serde_json::to_string(&s)?, sender, s.status.call_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
#[allow(clippy::type_complexity)]
fn queued(conn: &Connection) -> Result<Vec<(String, CallRequest, Stored)>, Error> {
    let mut statement = conn.prepare(
        "SELECT sender, request, record FROM received_calls WHERE json_extract(record, '$.state') = 'queued' ORDER BY rowid",
    )?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(sender, r, s)| Ok((sender, serde_json::from_str(&r)?, serde_json::from_str(&s)?)))
        .collect()
}

/// Releases a dispatched call's slot.
fn release(store: &Store, key: &mcp::Key, call: &(String, String)) {
    if let Ok(mut claimed) = store.call_runner.claimed.lock()
        && let Some(n) = claimed.get_mut(key)
    {
        *n = n.saturating_sub(1);
        if *n == 0 {
            claimed.remove(key);
        }
    }
    if let Ok(mut inflight) = store.call_runner.inflight.lock() {
        inflight.remove(call);
    }
    if let Ok(mut cancels) = store.call_runner.cancels.lock() {
        cancels.remove(call);
    }
    store.call_runner.wake.notify_one();
}

/// Runs one dispatched call: starts its instance if needed, rechecks it,
/// sends it, and records how it ends.
async fn run(store: Arc<Store>, sender: String, id: String, instance: Instance) {
    let key = instance.key();
    let call = (sender.clone(), id.clone());
    run_inner(&store, &sender, &id, &instance).await;
    release(&store, &key, &call);
}
async fn run_inner(store: &Arc<Store>, sender: &str, id: &str, instance: &Instance) {
    let key = instance.key();
    let (s, i) = (sender.to_owned(), id.to_owned());
    if !blocking(store.clone(), move |st| st.still_queued(&s, &i))
        .await
        .unwrap_or(false)
    {
        return;
    }
    if store.tool_pool.failing(&key) {
        let i = instance.clone();
        let _ = blocking(store.clone(), move |s| {
            s.fail_queued(&i, "server_start_failed")
        })
        .await;
        return;
    }
    let i = instance.clone();
    let launch = match blocking(store.clone(), move |s| s.launch(&*s.connection()?, &i)).await {
        Ok(launch) => launch,
        Err(_) => {
            // The server is gone; the recheck rejects the call.
            let (s, i) = (sender.to_owned(), id.to_owned());
            let _ = blocking(store.clone(), move |st| st.start_call(&s, &i)).await;
            return;
        }
    };
    let live = match store.tool_pool.instance(&key, &launch).await {
        Ok(live) => live,
        Err(_) => {
            let i = instance.clone();
            let _ = blocking(store.clone(), move |s| {
                s.note_health(&i, true, None)?;
                s.fail_queued(&i, "server_start_failed")
            })
            .await;
            return;
        }
    };
    let cancel = Arc::new(Notify::new());
    if let Ok(mut cancels) = store.call_runner.cancels.lock() {
        cancels.insert((sender.to_owned(), id.to_owned()), cancel.clone());
    }
    let (s, i) = (sender.to_owned(), id.to_owned());
    let Ok(Some(request)) = blocking(store.clone(), move |st| st.start_call(&s, &i)).await else {
        return;
    };
    live.active
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let outcome = send(store, &live, &request, &cancel).await;
    live.active
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut used) = live.used.lock() {
        *used = std::time::Instant::now();
    }
    let (state, error, result, auth) = outcome;
    let (s, i) = (sender.to_owned(), id.to_owned());
    let inst = instance.clone();
    let log = live.client.log().to_path_buf();
    let _ = blocking(store.clone(), move |st| {
        if let Some(message) = &auth {
            st.note_health(&inst, false, Some(message))?;
        }
        if let Some(state) = state
            && !st.end_call(&s, &i, state, error, result)?
        {
            mcp::note(
                &log,
                &format!("discarded the response to call {i}, which had already ended"),
            );
        }
        Ok(())
    })
    .await;
}
type Outcome = (
    Option<&'static str>,
    Option<&'static str>,
    Option<Value>,
    Option<String>,
);
/// Sends the call and waits for whichever comes first: the response, the
/// instance ending, a cancellation, or the deadline. A cancellation or the
/// deadline sends `notifications/cancelled`.
async fn send(store: &Arc<Store>, live: &mcp::Live, r: &CallRequest, cancel: &Notify) -> Outcome {
    let (method, params) = if r.tool() {
        (
            "tools/call",
            json!({"name": r.name, "arguments": r.arguments.clone().unwrap_or_else(|| json!({}))}),
        )
    } else {
        ("resources/read", json!({"uri": r.uri}))
    };
    let (rid, rx) = match live.client.send(method, params).await {
        Ok(sent) => sent,
        Err(_) => return (Some("failed"), Some("server_exited"), None, None),
    };
    let deadline = crate::membership::time(&r.deadline).unwrap_or_else(|_| Utc::now());
    let wait = (deadline - Utc::now()).to_std().unwrap_or(Duration::ZERO);
    tokio::select! {
        reply = rx => match reply {
            Ok(Reply::Result(result)) => {
                if r.tool() && result.get("isError") == Some(&json!(true)) {
                    (Some("failed"), Some("tool_error"), Some(result), None)
                } else {
                    (Some("succeeded"), None, Some(result), None)
                }
            }
            Ok(Reply::Error { code, message }) => {
                let auth = crate::tools::auth_like(&message).then(|| message.clone());
                (Some("failed"), Some("jsonrpc_error"), Some(json!({"code": code, "message": message})), auth)
            }
            Ok(Reply::TooLarge) => (Some("failed"), Some("result_too_large"), None, None),
            Err(_) => (Some("uncertain"), Some("server_exited"), None, None),
        },
        _ = cancel.notified() => {
            // The cancel route already made the call uncertain.
            live.client.forget(rid);
            live.client.cancel(rid, "cancel_requested").await;
            (None, None, None, None)
        }
        _ = tokio::time::sleep(wait) => {
            live.client.forget(rid);
            live.client.cancel(rid, "deadline").await;
            let _ = store;
            (Some("uncertain"), Some("deadline"), None, None)
        }
    }
}

/// Dispatches queued calls, at most 4 per instance, expires them at their
/// deadlines, stops idle instances, and prunes old arguments and results.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let mut last_prune = std::time::Instant::now() - Duration::from_secs(3600);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = store.call_runner.wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
        let _ = blocking(store.clone(), Store::expire_calls).await;
        let Ok(queued) = blocking(store.clone(), Store::queued_calls).await else {
            continue;
        };
        for (sender, id, instance) in queued {
            let key = instance.key();
            let call = (sender.clone(), id.clone());
            {
                let Ok(mut inflight) = store.call_runner.inflight.lock() else {
                    continue;
                };
                let Ok(mut claimed) = store.call_runner.claimed.lock() else {
                    continue;
                };
                let n = claimed.entry(key.clone()).or_default();
                if inflight.contains(&call) || *n >= PER_INSTANCE {
                    continue;
                }
                *n += 1;
                inflight.insert(call);
            }
            tokio::spawn(run(store.clone(), sender, id, instance));
        }
        store.tool_pool.reap();
        if last_prune.elapsed() >= Duration::from_secs(600) {
            last_prune = std::time::Instant::now();
            let _ = blocking(store.clone(), Store::prune_calls).await;
        }
    }
}

pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/peer/v1/tools", get(tools_route))
        .route("/peer/v1/calls", post(submit_route))
        .route("/peer/v1/calls/{id}", get(status_route))
        .route("/peer/v1/calls/{id}/cancel", post(cancel_route))
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/calls/received", get(received_route))
}
async fn tools_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    query: Result<Query<ToolsQuery>, QueryRejection>,
) -> Result<Json<Vec<Value>>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid query".into()))?;
    Ok(Json(
        blocking(store, move |s| s.listing(&sender, q.network.as_deref())).await?,
    ))
}
async fn submit_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<CallStatus>, Error> {
    let request: CallRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.accept_call(&sender, request)).await?,
    ))
}
async fn status_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
) -> Result<Json<CallView>, Error> {
    Ok(Json(
        blocking(store, move |s| s.call_status(&sender, &id)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn cancel_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<CallStatus>, Error> {
    let _: Empty = decode(body)?;
    let call = (sender.clone(), id.clone());
    let (status, running) = blocking(store.clone(), move |s| s.cancel_call(&sender, &id)).await?;
    if running
        && let Ok(cancels) = store.call_runner.cancels.lock()
        && let Some(signal) = cancels.get(&call)
    {
        signal.notify_one();
    }
    Ok(Json(status))
}
#[derive(Deserialize)]
struct Page {
    after: Option<i64>,
    limit: Option<i64>,
}
async fn received_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<Page>, QueryRejection>,
) -> Result<Json<Vec<Value>>, Error> {
    let Query(p) = query.map_err(|_| Error::Invalid("invalid page bounds".into()))?;
    Ok(Json(
        blocking(store, move |s| {
            s.received_calls(p.after.unwrap_or(0), p.limit.unwrap_or(100))
        })
        .await?,
    ))
}
