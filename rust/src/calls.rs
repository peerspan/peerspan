//! Calls (capabilities contract): the receiving host. A peer lists the
//! capabilities it may use, and the sources opened to it; submits a call to
//! one operation; and polls its status. The host authorizes each call by
//! policy, or by self access from a trusted host, persists it, and runs it
//! on the serving instance, never twice.
use crate::{
    api::{blocking, decode},
    capabilities::{
        CapabilityRecord, READ, capability_record, capability_records, current, present_resources,
    },
    mcp::{self, Reply},
    model::Error,
    peer_store::{Origin, valid_id},
    policy::{MAX_INPUT_BYTES, Policy, name_shape, person_id_shape, principal_matches},
    sources::{Instance, ServerRecord, Snapshot, open_to_host, server_record},
    store::{Store, append_event, now, rfc3339},
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
use chrono::{TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
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
/// Inputs and results are deleted this long after a call is final.
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

/// A policy citation: the owner, the network, and the newest version the
/// sender has verified.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyCitation {
    pub person_id: String,
    pub network_id: String,
    pub version: u64,
}
/// A self citation: the sender's person, in one network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelfCitation {
    pub person_id: String,
    pub network_id: String,
}

/// A call as submitted on the wire.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CallRequest {
    pub call_id: String,
    /// A capability name, or `AGENT/SERVER` for a source.
    pub capability: String,
    pub operation: String,
    /// The operation's input; deleted 7 days after the call is final.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
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
    pub policy: Option<PolicyCitation>,
    #[serde(
        rename = "self",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub self_access: Option<SelfCitation>,
}
impl CallRequest {
    /// `AGENT` and `SERVER` when the call is to a source.
    pub fn source(&self) -> Option<(&str, &str)> {
        self.capability.rsplit_once('/')
    }
    /// What `max_input_bytes` bounds: the JSON encoding of the input.
    fn input_size(&self) -> usize {
        serde_json::to_vec(&self.input)
            .map(|v| v.len())
            .unwrap_or(usize::MAX)
    }
    fn input_sha256(&self) -> String {
        hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&self.input).unwrap_or_default(),
        ))
    }
}
pub fn call_id_shape(id: &str) -> bool {
    valid_id(id, "call", 16)
}
fn network_shape(id: &str) -> bool {
    valid_id(id, "net", 32)
}
/// A capability name, or `AGENT/SERVER`.
pub fn capability_shape(value: &str) -> bool {
    match value.rsplit_once('/') {
        Some((agent, server)) => {
            !agent.is_empty() && crate::membership::label(agent).is_ok() && name_shape(server)
        }
        None => name_shape(value),
    }
}
fn validate(r: &CallRequest) -> Result<(), Error> {
    let citation = match (&r.policy, &r.self_access) {
        (Some(p), None) => {
            p.version >= 1 && person_id_shape(&p.person_id) && network_shape(&p.network_id)
        }
        (None, Some(s)) => person_id_shape(&s.person_id) && network_shape(&s.network_id),
        _ => false,
    };
    if !call_id_shape(&r.call_id)
        || !capability_shape(&r.capability)
        || r.operation.is_empty()
        || !r.input.is_object()
        || r.origin.as_ref().is_some_and(|o| !o.valid())
        || !citation
    {
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
    pub capability: String,
    pub operation: String,
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
#[derive(Clone, Debug, Serialize)]
struct Stored {
    #[serde(flatten)]
    status: CallStatus,
    #[serde(default)]
    result: Option<Value>,
    input_sha256: String,
    /// The rule whose hourly budget the call counted against.
    #[serde(default)]
    budget: Option<String>,
    caller: String,
    accepted_ms: i64,
    #[serde(default)]
    finished_ms: Option<i64>,
}
/// `Stored` without its status. Records are read in two passes, because a
/// flattened struct cannot read numbers that keep their text
/// (`arbitrary_precision`).
#[derive(Deserialize)]
struct StoredRest {
    #[serde(default)]
    result: Option<Value>,
    input_sha256: String,
    #[serde(default)]
    budget: Option<String>,
    caller: String,
    accepted_ms: i64,
    #[serde(default)]
    finished_ms: Option<i64>,
}
impl<'de> Deserialize<'de> for Stored {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = Value::deserialize(d)?;
        let status = CallStatus::deserialize(&value).map_err(D::Error::custom)?;
        let rest = StoredRest::deserialize(&value).map_err(D::Error::custom)?;
        Ok(Stored {
            status,
            result: rest.result,
            input_sha256: rest.input_sha256,
            budget: rest.budget,
            caller: rest.caller,
            accepted_ms: rest.accepted_ms,
            finished_ms: rest.finished_ms,
        })
    }
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

/// What a call reaches on this host.
enum Target {
    Capability(CapabilityRecord),
    /// A source called as an implicit capability `AGENT/SERVER`.
    Source {
        server: ServerRecord,
    },
}
impl Target {
    fn instance(&self) -> Instance {
        match self {
            Self::Capability(c) => c.instance(),
            Self::Source { server } => Instance {
                agent_id: server.agent_id.clone(),
                server: server.definition.name.clone(),
                capability: None,
            },
        }
    }
}
/// The agent ID of a local agent named `name`.
fn agent_id(conn: &Connection, name: &str) -> Result<Option<String>, Error> {
    Ok(conn
        .query_row("SELECT id FROM agents WHERE name = ?1", [name], |r| {
            r.get(0)
        })
        .optional()?)
}
/// The source behind `AGENT/SERVER`, when it is shareable and snapshotted.
fn open_source(
    conn: &Connection,
    agent: &str,
    server: &str,
) -> Result<Option<ServerRecord>, Error> {
    let Some(id) = agent_id(conn, agent)? else {
        return Ok(None);
    };
    Ok(server_record(conn, &id, server)?.filter(|s| s.shareable && s.snapshot.is_some()))
}

/// The operations a source offers as an implicit capability: every tool
/// but one named `read`, plus `read` when it has resources.
fn source_operations(snapshot: &Snapshot) -> Vec<String> {
    let mut ops: Vec<String> = snapshot
        .tools
        .iter()
        .filter(|t| t.name != READ)
        .map(|t| t.name.clone())
        .collect();
    if !snapshot.resources.is_empty() {
        ops.push(READ.into());
    }
    ops
}

/// One way a call is authorized: its bounds and budget.
#[derive(Clone, Debug)]
struct Candidate {
    /// The budget key and its hourly limit; none under self access.
    budget: Option<(String, i64)>,
    max_input: i64,
    allow_disconnected: bool,
    caller: String,
}
/// What authorized an accepted call.
pub(crate) struct Authorized {
    budget: Option<String>,
    caller: String,
}

/// The policy of this host's person in a network.
fn own_policy(
    store: &Store,
    conn: &Connection,
    network: &str,
    person: &str,
) -> Result<Option<Policy>, Error> {
    let Some(key) = store.person_key(conn, network, person)? else {
        return Ok(None);
    };
    // Withdrawals of this host's unsettled edits apply at once.
    store
        .stored_policy(conn, network, &key)?
        .map(|p| store.enforced(conn, network, p))
        .transpose()
}
/// Whether self access covers `sender` in `network`: both hosts are bound
/// to `person` there, and that person's newest verified policy, within its
/// window, lists the sender as trusted.
fn trusted_in(
    store: &Store,
    conn: &Connection,
    sender: &str,
    network: &str,
    person: &str,
) -> Result<bool, Error> {
    if sender == store.identity().id {
        return Ok(false);
    }
    let own = store
        .own_members(conn)?
        .into_iter()
        .any(|(n, m)| n == network && m.person_id.as_deref() == Some(person));
    let bound = crate::chain::member(conn, network, sender)?
        .is_some_and(|m| m.person_id.as_deref() == Some(person));
    if !own || !bound {
        return Ok(false);
    }
    Ok(own_policy(store, conn, network, person)?
        .is_some_and(|p| p.in_window(Utc::now()) && p.trusted_hosts().iter().any(|h| h == sender)))
}
/// The networks in which self access covers `sender`.
fn trusted_networks(store: &Store, conn: &Connection, sender: &str) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for (network, own) in store.own_members(conn)? {
        if let Some(person) = &own.person_id
            && trusted_in(store, conn, sender, &network, person)?
        {
            out.push(network);
        }
    }
    Ok(out)
}
/// A rule's budget identity: its network, owner, host, capability, and
/// bounds, but not its principals.
fn rule_key(network: &str, person: &str, rule: &crate::policy::CapabilityRule) -> String {
    format!(
        "policy:{network}:{person}:{}:{}:{} {} {}",
        rule.host,
        rule.capability,
        rule.max_input_bytes,
        rule.allow_disconnected,
        rule.max_calls_per_hour
    )
}
/// The authorization a call cites, when it matches, and whether it is
/// self access.
fn candidates(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &CallRequest,
) -> Result<(Vec<Candidate>, bool), Error> {
    let me = store.identity().id;
    if let Some(cited) = &r.self_access {
        if !trusted_in(store, conn, sender, &cited.network_id, &cited.person_id)? {
            return Err(Error::Forbidden);
        }
        // A source needs the serving host's open list as well.
        if r.source().is_some() && !open_to_host(conn, sender)? {
            return Err(Error::Forbidden);
        }
        return Ok((
            vec![Candidate {
                budget: None,
                max_input: MAX_INPUT_BYTES,
                allow_disconnected: true,
                caller: cited.person_id.clone(),
            }],
            true,
        ));
    }
    let Some(cited) = &r.policy else {
        return Err(Error::Forbidden);
    };
    // Sources are never shared through policy.
    if r.source().is_some() {
        return Err(Error::Forbidden);
    }
    let bound = store.own_members(conn)?.into_iter().any(|(n, m)| {
        n == cited.network_id && m.person_id.as_deref() == Some(cited.person_id.as_str())
    });
    if !bound {
        return Err(Error::Forbidden);
    }
    let Some(policy) = own_policy(store, conn, &cited.network_id, &cited.person_id)? else {
        return Err(Error::Unavailable(
            "this host has not yet received the cited policy".into(),
        ));
    };
    if policy.version < cited.version {
        return Err(Error::Unavailable(
            "this host has not yet received the cited policy version".into(),
        ));
    }
    if !policy.in_window(Utc::now()) {
        return Err(Error::Forbidden);
    }
    let Some(sender_member) =
        crate::chain::member(conn, &cited.network_id, sender)?.filter(|m| m.host_id != me)
    else {
        return Err(Error::Forbidden);
    };
    let groups = store.stored_groups(conn, &cited.network_id)?;
    let caller = sender_member
        .person_id
        .clone()
        .unwrap_or_else(|| sender.to_owned());
    let out: Vec<Candidate> = policy
        .capability_rules()
        .iter()
        .filter(|rule| {
            rule.host == me
                && rule.capability == r.capability
                && rule
                    .principals
                    .iter()
                    .any(|p| principal_matches(p, &sender_member, &groups, r.origin.as_ref()))
        })
        .map(|rule| Candidate {
            budget: Some((
                rule_key(&cited.network_id, &cited.person_id, rule),
                rule.max_calls_per_hour,
            )),
            max_input: rule.max_input_bytes,
            allow_disconnected: rule.allow_disconnected,
            caller: caller.clone(),
        })
        .collect();
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
fn unavailable(what: &str) -> Error {
    Error::Coded {
        status: 409,
        code: "unavailable",
        message: format!("{what} is unavailable"),
        extra: Default::default(),
    }
}
/// The target and whether the operation and its input fit it: 404 when the
/// capability, operation, or URI is not there, 409 when it is unavailable.
fn resolve_target(conn: &Connection, r: &CallRequest) -> Result<Target, Error> {
    let uri = || r.input.get("uri").and_then(Value::as_str);
    if let Some((agent, server)) = r.source() {
        let Some(id) = agent_id(conn, agent)? else {
            return Err(Error::NotFound);
        };
        let Some(source) = server_record(conn, &id, server)? else {
            return Err(unavailable(&r.capability));
        };
        let Some(snapshot) = source.snapshot.as_ref().filter(|_| source.shareable) else {
            return Err(unavailable(&r.capability));
        };
        if !source_operations(snapshot).contains(&r.operation) {
            return Err(Error::NotFound);
        }
        if r.operation == READ && uri().is_none_or(|u| snapshot.resource(u).is_none()) {
            return Err(Error::NotFound);
        }
        return Ok(Target::Source { server: source });
    }
    let Some(record) = capability_record(conn, &r.capability)? else {
        return Err(Error::NotFound);
    };
    let is_read = r.operation == READ && record.reads();
    if !is_read && !record.operations.contains(&r.operation) {
        return Err(Error::NotFound);
    }
    let now = current(conn, &record)?;
    if now.gone() {
        return Err(unavailable(&r.capability));
    }
    if now.unavailable.contains(&r.operation) {
        return Err(unavailable(&format!("{}/{}", r.capability, r.operation)));
    }
    if is_read {
        let present = present_resources(&record, now.snapshot.as_ref());
        if uri().is_none_or(|u| !present.iter().any(|p| p.uri == u)) {
            return Err(Error::NotFound);
        }
    }
    Ok(Target::Capability(record))
}

/// Authorizes a call, in the contract's order: a matching citation, then
/// blocks (except self), the capability and operation (404, or 409 when
/// unavailable), the bounds (413, the deadline at submission, the
/// connected state), and, at submission, the hourly budget (429).
fn authorize(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &CallRequest,
    submission: bool,
) -> Result<(Authorized, Target), Error> {
    let (candidates, self_access) = candidates(store, conn, sender, r)?;
    if !self_access && store.blocked(conn, sender)? {
        return Err(Error::Forbidden);
    }
    let target = resolve_target(conn, r)?;
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
    if submission {
        // One minute of clock skew beyond the 15 minutes.
        let at = Utc::now();
        let deadline = crate::membership::time(&r.deadline)?;
        if deadline <= at || deadline > at + MAX_DEADLINE + TimeDelta::minutes(1) {
            return Err(Error::Invalid(
                "a deadline is in the future and at most 15 minutes away".into(),
            ));
        }
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
    if !submission {
        let c = &fit[0];
        return Ok((
            Authorized {
                budget: c.budget.as_ref().map(|(k, _)| k.clone()),
                caller: c.caller.clone(),
            },
            target,
        ));
    }
    for c in &fit {
        match &c.budget {
            None => {
                return Ok((
                    Authorized {
                        budget: None,
                        caller: c.caller.clone(),
                    },
                    target,
                ));
            }
            Some((key, limit)) if used(conn, key, &c.caller)? < *limit => {
                return Ok((
                    Authorized {
                        budget: Some(key.clone()),
                        caller: c.caller.clone(),
                    },
                    target,
                ));
            }
            Some(_) => {}
        }
    }
    Err(Error::Limit {
        limit: "max_calls_per_hour".into(),
        message: "the hourly call budget of this authorization is used up".into(),
    })
}

/// The input schema of `read`: one of the URIs.
fn read_schema(uris: &[String]) -> Value {
    json!({
        "type": "object",
        "properties": {"uri": {"type": "string", "enum": uris}},
        "required": ["uri"],
    })
}
fn tool_operation(snapshot: Option<&Snapshot>, name: &str) -> Value {
    match snapshot.and_then(|s| s.tool(name)) {
        Some(t) => json!({
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
            "read_only": t.read_only,
        }),
        None => {
            json!({"name": name, "description": null, "input_schema": null, "read_only": false})
        }
    }
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
    /// Calls whose recheck could recover, held back until then.
    deferred: Mutex<HashMap<(String, String), std::time::Instant>>,
    /// Wakes the dispatcher.
    wake: Notify,
}
/// A queued call refused recoverably is rechecked after this long.
const RECHECK: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
pub(crate) struct ListQuery {
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
                input: Value::Null,
                ..c.clone()
            };
            if strip(&old) != strip(&r) || s.input_sha256 != r.input_sha256() {
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
        let (authorized, _) = authorize(self, &tx, sender, &r, true)?;
        let status = CallStatus {
            call_id: r.call_id.clone(),
            sender_host_id: sender.to_owned(),
            receiver_host_id: self.identity().id,
            capability: r.capability.clone(),
            operation: r.operation.clone(),
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
            input_sha256: r.input_sha256(),
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
    /// `GET /peer/v1/capabilities`: the capabilities the sender may use
    /// here, and the sources opened to it. With a network, only that
    /// network is evaluated.
    pub fn listing(&self, sender: &str, network: Option<&str>) -> Result<Vec<Value>, Error> {
        let conn = self.connection()?;
        let at = Utc::now();
        let me = self.identity().id;
        let in_scope = |n: &str| network.is_none_or(|x| x == n);
        let selfs: Vec<String> = trusted_networks(self, &conn, sender)?
            .into_iter()
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
                let Some(sender_member) =
                    crate::chain::member(&conn, &net, sender)?.filter(|m| m.host_id != me)
                else {
                    continue;
                };
                let groups = self.stored_groups(&conn, &net)?;
                policies.push((net, person, policy, sender_member, groups));
            }
        }
        let self_via: Vec<Value> = selfs
            .iter()
            .map(|n| json!({"kind": "self", "network_id": n}))
            .collect();
        let mut out = Vec::new();
        for record in capability_records(&conn)? {
            let mut via = self_via.clone();
            for (net, person, policy, member, groups) in &policies {
                // A rule matching the sender only through `agent:`
                // principals for its host is listed once per such agent;
                // any other matching principal lists it once for no agent.
                let mut anyone = false;
                let mut agents: Vec<&str> = Vec::new();
                for rule in policy.capability_rules() {
                    if rule.host != me || rule.capability != record.name {
                        continue;
                    }
                    for p in &rule.principals {
                        match crate::policy::agent_principal(p) {
                            Some((host, agent)) if host == sender => {
                                if !agents.contains(&agent) {
                                    agents.push(agent);
                                }
                            }
                            Some(_) => {}
                            None => anyone |= principal_matches(p, member, groups, None),
                        }
                    }
                }
                let entry = |from: Option<&str>| json!({"kind": "policy", "network_id": net, "person_id": person, "version": policy.version, "from_agent": from});
                if anyone {
                    via.push(entry(None));
                } else {
                    agents.sort_unstable();
                    via.extend(agents.into_iter().map(|a| entry(Some(a))));
                }
            }
            if via.is_empty() {
                continue;
            }
            let now = current(&conn, &record)?;
            let mut operations: Vec<Value> = record
                .operations
                .iter()
                .map(|op| tool_operation(now.snapshot.as_ref(), op))
                .collect();
            let resources = present_resources(&record, now.snapshot.as_ref());
            if record.reads() {
                let uris: Vec<String> = resources.iter().map(|r| r.uri.clone()).collect();
                operations.push(json!({
                    "name": READ,
                    "description": "Read one of the capability's resources",
                    "input_schema": read_schema(&uris),
                    "read_only": true,
                }));
            }
            out.push(json!({
                "kind": "capability",
                "capability": record.name,
                "operations": operations,
                "resources": resources,
                "state": now.state(),
                "unavailable": now.unavailable,
                "via": via,
            }));
        }
        // Sources opened to a trusted sender.
        if !self_via.is_empty() && open_to_host(&conn, sender)? {
            let names = crate::sources::agent_names(&conn)?;
            for source in self.snapshotted_sources(&conn)? {
                let (Some(agent), Some(snapshot)) =
                    (names.get(&source.agent_id), source.snapshot.as_ref())
                else {
                    continue;
                };
                let mut operations: Vec<Value> = snapshot
                    .tools
                    .iter()
                    .filter(|t| t.name != READ)
                    .map(|t| tool_operation(Some(snapshot), &t.name))
                    .collect();
                if !snapshot.resources.is_empty() {
                    let uris: Vec<String> =
                        snapshot.resources.iter().map(|r| r.uri.clone()).collect();
                    operations.push(json!({
                        "name": READ,
                        "description": "Read one of the source's resources",
                        "input_schema": read_schema(&uris),
                        "read_only": true,
                    }));
                }
                out.push(json!({
                    "kind": "source",
                    "capability": format!("{agent}/{}", source.definition.name),
                    "operations": operations,
                    "resources": snapshot.resources,
                    "state": "available",
                    "unavailable": [],
                    "via": self_via,
                }));
            }
        }
        out.sort_by(|a, b| a["capability"].as_str().cmp(&b["capability"].as_str()));
        Ok(out)
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
    /// Queued calls in order: sender, call ID, and the instance they run
    /// on; a call whose target is gone gets a placeholder its recheck ends.
    fn queued_calls(&self) -> Result<Vec<(String, String, Instance)>, Error> {
        let connection = self.connection()?;
        let mut out = Vec::new();
        for (sender, r, _) in queued(&connection)? {
            let instance = instance_of(&connection, &r)?.unwrap_or_else(|| Instance {
                agent_id: String::new(),
                server: r.capability.clone(),
                capability: None,
            });
            out.push((sender, r.call_id.clone(), instance));
        }
        Ok(out)
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
        match authorize(self, &tx, sender, &request, false) {
            Ok(_) => {}
            // Recoverable: the call stays queued and is rechecked.
            Err(Error::Unavailable(_)) => {
                self.defer(sender, id);
                return Ok(None);
            }
            Err(_) => {
                finish(&tx, sender, &mut s, "rejected", Some(LAPSED), None)?;
                tx.commit()?;
                return Ok(None);
            }
        }
        let at = now();
        s.status.state = "running".into();
        s.status.started_at = Some(at.clone());
        save(&tx, sender, &s)?;
        append_event(&tx, "call.started", &subject(sender, id), &at)?;
        tx.commit()?;
        Ok(Some(request))
    }
    /// Rechecks a queued call before its instance starts: whether it may
    /// start now. A final lapse records `rejected`; a recoverable one leaves
    /// it queued, rechecked shortly.
    fn precheck(&self, sender: &str, id: &str) -> Result<bool, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let Some((request, mut s)) = load(&tx, sender, id)? else {
            return Ok(false);
        };
        if s.status.state != "queued" {
            return Ok(false);
        }
        if expire(&tx, sender, &request, &mut s)? {
            tx.commit()?;
            return Ok(false);
        }
        match authorize(self, &tx, sender, &request, false) {
            Ok(_) => Ok(true),
            Err(Error::Unavailable(_)) => {
                self.defer(sender, id);
                Ok(false)
            }
            Err(_) => {
                finish(&tx, sender, &mut s, "rejected", Some(LAPSED), None)?;
                tx.commit()?;
                Ok(false)
            }
        }
    }
    /// Holds a recoverably refused call back from dispatch briefly.
    fn defer(&self, sender: &str, id: &str) {
        if let Ok(mut deferred) = self.call_runner.deferred.lock() {
            deferred.insert(
                (sender.to_owned(), id.to_owned()),
                std::time::Instant::now() + RECHECK,
            );
        }
    }
    /// Ends a call that was not sent: every queued call of an instance that
    /// failed to start fails with `server_start_failed`.
    fn fail_queued(&self, instance: &Instance, error: &str) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        for (sender, request, mut s) in queued(&tx)? {
            if instance_of(&tx, &request)?.as_ref() == Some(instance) {
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
    /// Deletes inputs and results 7 days after their calls became final.
    fn prune_calls(&self) -> Result<(), Error> {
        let cutoff = (Utc::now() - RETENTION).timestamp_millis();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let rows: Vec<(String, String, String)> = {
            let mut statement = tx.prepare(
                "SELECT sender, request, record FROM received_calls WHERE json_extract(record, '$.finished_ms') < ?1 AND (json_extract(request, '$.input') IS NOT NULL OR json_extract(record, '$.result') IS NOT NULL)",
            )?;
            statement
                .query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?
        };
        for (sender, request, record) in rows {
            let mut request: Value = serde_json::from_str(&request)?;
            let mut s: Stored = serde_json::from_str(&record)?;
            if let Some(object) = request.as_object_mut() {
                object.remove("input");
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
/// The instance a call runs on, while its target exists.
fn instance_of(conn: &Connection, r: &CallRequest) -> Result<Option<Instance>, Error> {
    if let Some((agent, server)) = r.source() {
        return Ok(open_source(conn, agent, server)?
            .map(|source| Target::Source { server: source }.instance()));
    }
    Ok(capability_record(conn, &r.capability)?.map(|c| c.instance()))
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
    if !blocking(store.clone(), move |st| st.precheck(&s, &i))
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
    let outcome = send(&live, &request, &cancel).await;
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
async fn send(live: &mcp::Live, r: &CallRequest, cancel: &Notify) -> Outcome {
    // A tool operation is `tools/call`; `read` is `resources/read`.
    let tool = r.operation != READ;
    let (method, params) = if tool {
        (
            "tools/call",
            json!({"name": r.operation, "arguments": r.input}),
        )
    } else {
        ("resources/read", json!({"uri": r.input.get("uri")}))
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
                if tool && result.get("isError") == Some(&json!(true)) {
                    (Some("failed"), Some("tool_error"), Some(result), None)
                } else {
                    (Some("succeeded"), None, Some(result), None)
                }
            }
            Ok(Reply::Error { code, message }) => {
                let auth = crate::sources::auth_like(&message).then(|| message.clone());
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
                if let Ok(mut deferred) = store.call_runner.deferred.lock() {
                    let now = std::time::Instant::now();
                    deferred.retain(|_, until| *until > now);
                    if deferred.contains_key(&call) {
                        continue;
                    }
                }
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
        .route("/peer/v1/capabilities", get(capabilities_route))
        .route("/peer/v1/calls", post(submit_route))
        .route("/peer/v1/calls/{id}", get(status_route))
        .route("/peer/v1/calls/{id}/cancel", post(cancel_route))
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/calls/received", get(received_route))
}
async fn capabilities_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    query: Result<Query<ListQuery>, QueryRejection>,
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
