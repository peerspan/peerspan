//! Single-hop task delegation (roadmap milestone 6, slice 2): the submitting
//! host. The owner CLI and adapter routes submit tasks; the daemon retries
//! uncertain submissions with the same task ID, polls each submitted task's
//! events until a final state is stored, and hands those events to the
//! originating session.
use crate::{
    adapter::{authority, read},
    adapter_connection::AdapterAuth,
    adapter_outbound::{OutboundRoute, route_used, valid_name},
    api::{blocking, decode},
    artifact::{ArtifactEntry, INPUT, LocalArtifact, RESULT, SENT, normalized, validate_manifest},
    chain::{Link, MAX_DEPTH, MAX_LINKS, NETWORK, Unsigned, covered, normalized_principals},
    model::Error,
    peer_store::{Origin, valid_id},
    retry::{Attempted, Dispatcher, due_at},
    store::{Store, append_event, new_id, now, rfc3339},
    task::{MAX_TEXT, TaskEvent, TaskRequest, TaskStatus, is_final, time, validate_task},
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
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// A task's default deadline after submission.
const DEFAULT_DEADLINE: TimeDelta = TimeDelta::hours(1);
/// Event polls back off from 1 second to 60 seconds.
const POLL_FIRST: Duration = Duration::from_secs(1);
const POLL_MAX: Duration = Duration::from_secs(60);
/// Events fetched per request while catching up.
const EVENT_PAGE: i64 = 1000;
/// Peer requests are bounded like message sends.
const REQUEST_BOUND: Duration = Duration::from_secs(8);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitTask {
    pub peer_host_id: String,
    #[serde(default)]
    pub task_id: String,
    /// Absent or null, the task cites the target owner's policy.
    #[serde(default)]
    pub grant_id: Option<String>,
    pub target_agent_id: String,
    /// Absent, null, or empty, one hour from now.
    #[serde(default)]
    pub deadline: Option<String>,
    pub input: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub origin: Option<Origin>,
    /// Stored uploads to attach as inputs.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub artifacts: Option<Vec<ArtifactEntry>>,
    /// 0 to 2; nonzero creates link 0 allowing that many further hops.
    #[serde(default)]
    pub delegation_depth: u64,
    /// Link 0's principals, default `network`.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub delegation_principals: Option<Vec<String>>,
    /// A running received task to forward instead.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub parent: Option<TaskParent>,
}
/// The received task an outbound task was forwarded from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskParent {
    pub sender_host_id: String,
    pub task_id: String,
}

/// The submitter's local record of an outbound task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboundTask {
    pub peer_host_id: String,
    #[serde(with = "crate::peer_store::recorded")]
    pub request: TaskRequest,
    /// `unknown`, `accepted`, or `rejected`, as for outbound messages.
    pub submit_state: String,
    /// The latest remote status record.
    pub status: Option<TaskStatus>,
    /// The highest locally stored event sequence.
    pub events_after: i64,
    /// Null, or `unknown` until the receiver confirms a cancellation
    /// request, then `sent`.
    pub cancel_state: Option<String>,
    /// The credential and route of an adapter-originated task.
    pub adapter_id: Option<String>,
    pub route_id: Option<String>,
    pub attempts: u32,
    pub next_attempt_at: Option<String>,
    pub error: Option<String>,
    /// Status queries made at or after the deadline.
    pub status_queries: u32,
    /// Inputs, then results, with their local state; read from the task's
    /// artifacts whenever the record is returned.
    #[serde(default)]
    pub artifacts: Vec<LocalArtifact>,
    /// The received task this one was forwarded from, or null.
    #[serde(default)]
    pub parent: Option<TaskParent>,
    /// The delegation chain this task carried, or null.
    #[serde(default)]
    pub delegation: Option<Vec<Link>>,
    /// The address the task was submitted to, as given (launch slice 4);
    /// omitted for a task to a host and agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}
impl Attempted for OutboundTask {
    fn uncertain(&self) -> bool {
        self.submit_state == "unknown"
    }
    fn deadline_text(&self) -> &str {
        &self.request.deadline
    }
    fn counters(&mut self) -> (&mut u32, &mut Option<String>, &mut u32) {
        (
            &mut self.attempts,
            &mut self.next_attempt_at,
            &mut self.status_queries,
        )
    }
}
impl OutboundTask {
    /// Whether events remain to be polled: submitted, and not yet final with
    /// all its events stored.
    fn pollable(&self) -> bool {
        self.submit_state == "accepted"
            && self
                .status
                .as_ref()
                .is_none_or(|s| !is_final(&s.state) || self.events_after < s.last_event)
    }
}
#[derive(Serialize)]
pub struct TaskItem {
    pub sequence: i64,
    pub task: OutboundTask,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegate {
    pub destination: String,
    pub task_id: String,
    pub input: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub artifacts: Option<Vec<ArtifactEntry>>,
    /// A task this session claimed, to forward.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub parent_task_id: Option<String>,
}
/// A directory session's delegation by address (launch slice 4); `to` and
/// `network` are taken from the body first.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressDelegate {
    pub task_id: String,
    pub input: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub artifacts: Option<Vec<ArtifactEntry>>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub parent_task_id: Option<String>,
}
/// Where an adapter delegation goes: through a route, or to a resolved
/// address with its chosen authorization.
struct DelegationTarget {
    peer: String,
    agent: String,
    /// The route's or, by address, the credential's expiry.
    expiry: DateTime<Utc>,
    route: Option<OutboundRoute>,
    to: Option<String>,
    choice: Option<crate::directory::Choice>,
}
/// How a new task relates to delegation: no chain, a new chain from link 0,
/// or a forward of a received task.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ChainSpec {
    None,
    Origin { depth: u64, principals: Vec<String> },
    Forward(TaskParent),
}
impl ChainSpec {
    fn of(out: &OutboundTask) -> Self {
        match (&out.parent, out.delegation.as_ref().and_then(|c| c.first())) {
            (Some(parent), _) => Self::Forward(parent.clone()),
            (None, Some(first)) => Self::Origin {
                depth: first.depth,
                principals: first.principals.clone(),
            },
            (None, None) => Self::None,
        }
    }
}
/// A running received task that may be forwarded, as checked.
struct Forwardable {
    parent: TaskParent,
    chain: Vec<Link>,
    deadline: DateTime<Utc>,
    /// The local agent the parent was submitted to.
    agent_id: String,
}
/// A task update handed to the originating session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskUpdateNotification {
    pub id: String,
    pub peer_host_id: String,
    pub task_id: String,
    pub sequence: i64,
    pub adapter_id: String,
    pub session_id: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Serialize)]
pub struct TaskUpdate {
    pub delivery: TaskUpdateNotification,
    pub event: TaskEvent,
}

fn stored(conn: &Connection, peer: &str, id: &str) -> Result<OutboundTask, Error> {
    let mut out: OutboundTask = read(
        conn,
        "SELECT record FROM outbound_tasks WHERE peer = ?1 AND task_id = ?2",
        params![peer, id],
    )?;
    fill(conn, &mut out)?;
    Ok(out)
}
/// Sets the record's artifacts from the task's stored references.
fn fill(conn: &Connection, out: &mut OutboundTask) -> Result<(), Error> {
    out.artifacts =
        crate::artifact::task_artifacts(conn, SENT, &out.peer_host_id, &out.request.task_id)?;
    Ok(())
}
/// The record as stored: without its derived artifacts.
fn persisted(out: &OutboundTask) -> Result<String, Error> {
    let mut value = serde_json::to_value(out)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("artifacts");
    }
    Ok(serde_json::to_string(&value)?)
}
fn save(tx: &Transaction<'_>, out: &OutboundTask) -> Result<(), Error> {
    tx.execute(
        "UPDATE outbound_tasks SET record = ?1 WHERE peer = ?2 AND task_id = ?3",
        params![persisted(out)?, out.peer_host_id, out.request.task_id],
    )?;
    Ok(())
}
fn subject(out: &OutboundTask) -> String {
    format!("{}/{}", out.peer_host_id, out.request.task_id)
}
fn insert(tx: &Transaction<'_>, out: &mut OutboundTask) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO outbound_tasks VALUES (?1, ?2, ?3)",
        params![out.peer_host_id, out.request.task_id, persisted(out)?],
    )?;
    if let Some(inputs) = &out.request.artifacts {
        crate::artifact::add_artifacts(
            tx,
            SENT,
            &out.peer_host_id,
            &out.request.task_id,
            INPUT,
            inputs,
            crate::artifact::STORED,
        )?;
    }
    append_event(tx, "task.submitted", &subject(out), &now())?;
    fill(tx, out)?;
    Ok(())
}
fn page(after: i64, limit: i64) -> Result<(), Error> {
    if after < 0 || !(1..=1000).contains(&limit) {
        return Err(Error::Invalid("invalid page bounds".into()));
    }
    Ok(())
}
/// Accepts a newer status record: never one behind the stored events.
fn take_status(out: &mut OutboundTask, status: TaskStatus) {
    if out
        .status
        .as_ref()
        .is_none_or(|old| status.last_event >= old.last_event)
    {
        out.status = Some(status);
    }
}

impl Store {
    pub fn outbound_task(&self, peer: &str, id: &str) -> Result<OutboundTask, Error> {
        stored(&*self.connection()?, peer, id)
    }
    pub fn outbound_tasks(&self, after: i64, limit: i64) -> Result<Vec<TaskItem>, Error> {
        page(after, limit)?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT rowid, record FROM outbound_tasks WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
        )?;
        let mut rows = statement.query(params![after, limit])?;
        let mut items = Vec::new();
        let mut page_bytes = 2;
        while let Some(row) = rows.next()? {
            let mut task: OutboundTask = serde_json::from_str(&row.get::<_, String>(1)?)?;
            fill(&connection, &mut task)?;
            let item = TaskItem {
                sequence: row.get(0)?,
                task,
            };
            // Like message pages, bounded so the CLI can read a full page.
            let encoded = serde_json::to_vec(&item)?.len() + 1;
            if page_bytes + encoded > 900000 {
                break;
            }
            page_bytes += encoded;
            items.push(item);
        }
        Ok(items)
    }
    pub fn outbound_task_events(
        &self,
        peer: &str,
        id: &str,
        after: i64,
        limit: i64,
    ) -> Result<Vec<TaskEvent>, Error> {
        page(after, limit)?;
        let connection = self.connection()?;
        stored(&connection, peer, id)?;
        let mut statement = connection.prepare(
            "SELECT record FROM outbound_task_events WHERE peer = ?1 AND task_id = ?2 AND sequence > ?3 ORDER BY sequence LIMIT ?4",
        )?;
        statement
            .query_map(params![peer, id, after, limit], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }
    /// Persists an owner-submitted task before any network attempt. A repeat
    /// with identical fields returns the stored record.
    pub fn prepare_task(&self, r: SubmitTask) -> Result<OutboundTask, Error> {
        self.prepare_task_to(r, None)
    }
    /// An addressed task's target is resolved and its authorization chosen
    /// before this; a repeat of a stored task by address has no choice.
    pub(crate) fn prepare_task_to(
        &self,
        r: SubmitTask,
        addressed: Option<crate::directory::Addressed>,
    ) -> Result<OutboundTask, Error> {
        let explicit_grant = r.grant_id.is_some();
        let choice = addressed.as_ref().and_then(|a| a.choice.clone());
        let spec = match (r.parent, r.delegation_depth, r.delegation_principals) {
            (Some(parent), 0, None) => {
                if !valid_id(&parent.sender_host_id, "host", 32)
                    || !valid_id(&parent.task_id, "task", 16)
                {
                    return Err(Error::Invalid("invalid parent task".into()));
                }
                ChainSpec::Forward(parent)
            }
            (Some(_), _, _) => {
                return Err(Error::Invalid(
                    "a forwarded task keeps its parent's chain; give no delegation depth or principals".into(),
                ));
            }
            (None, 0, None) => ChainSpec::None,
            (None, 0, Some(_)) => {
                return Err(Error::Invalid(
                    "delegation principals need a delegation depth of 1 or 2".into(),
                ));
            }
            (None, depth, principals) if depth <= MAX_DEPTH => ChainSpec::Origin {
                depth,
                principals: normalized_principals(principals)?,
            },
            _ => return Err(Error::Invalid("delegation depth is 0 to 2".into())),
        };
        let given = r.deadline.filter(|d| !d.is_empty());
        let explicit_deadline = given.is_some();
        let default_deadline = Utc::now() + DEFAULT_DEADLINE;
        let deadline = match given {
            Some(deadline) => deadline,
            None => rfc3339(default_deadline),
        };
        let mut request = TaskRequest {
            task_id: if r.task_id.is_empty() {
                new_id("task")?
            } else {
                r.task_id
            },
            policy: r.grant_id.is_none().then(|| crate::policy::PolicyRef {
                person_id: format!("person_{}", "0".repeat(64)),
                version: 1,
            }),
            grant_id: r.grant_id,
            self_access: None,
            target_agent_id: r.target_agent_id,
            deadline,
            input: r.input,
            origin: r.origin,
            artifacts: normalized(r.artifacts),
            delegation: None,
        };
        if let Some(origin) = &request.origin {
            if !origin.valid() {
                return Err(Error::Invalid("invalid origin".into()));
            }
            self.check_local_origin(&*self.connection()?, origin)?;
        }
        // A chained task's deadline is the UTC string its link signs.
        if spec != ChainSpec::None
            && let Ok(at) = DateTime::parse_from_rfc3339(&request.deadline)
        {
            request.deadline = rfc3339(at.with_timezone(&Utc));
        }
        if matches!(spec, ChainSpec::Origin { .. }) && request.origin.is_none() {
            return Err(Error::Invalid(
                "a delegation chain names its originating agent; give an origin".into(),
            ));
        }
        validate_task(&request)?;
        self.dial_target(&r.peer_host_id)?;
        let mut default_cap = default_deadline;
        // A forward cites once its parent's chain is known, below.
        let forwarding = matches!(spec, ChainSpec::Forward(_));
        if let Some(crate::directory::Choice::Grant(grant)) = &choice {
            request.grant_id = Some(grant.clone());
            request.policy = None;
        }
        let repeat = addressed.is_some() && choice.is_none();
        if request.policy.is_some() && !forwarding && !repeat {
            let conn = self.connection()?;
            let cited = match &choice {
                Some(choice) => match self.chosen(&conn, &r.peer_host_id, choice)? {
                    Err(cited) => cited,
                    Ok(_) => unreachable!("a grant was cited above"),
                },
                None => self.citation(&conn, &r.peer_host_id)?,
            };
            (request.policy, request.self_access) = cited.fields();
            // A default deadline never outlives the cited policy.
            if let Some(until) = cited.valid_until() {
                default_cap = default_cap.min(time(until)?);
            }
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if let Some(old) = tx
            .query_row(
                "SELECT record FROM outbound_tasks WHERE peer = ?1 AND task_id = ?2",
                params![r.peer_host_id, request.task_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            let mut old: OutboundTask = serde_json::from_str(&old)?;
            fill(&tx, &mut old)?;
            // A repeat cites the owner's newest version, which may have moved
            // on, and a defaulted deadline moves with the clock; the stored
            // request stands. A forward's default origin is its claimer.
            let defaulted_origin =
                matches!(spec, ChainSpec::Forward(_)) && request.origin.is_none();
            // A forward's citation is made once its chain is known, so a
            // repeat compares only whether it names a grant.
            let same_owner = |a: &TaskRequest| TaskRequest {
                policy: a
                    .policy
                    .as_ref()
                    .map(|p| crate::policy::PolicyRef {
                        person_id: p.person_id.clone(),
                        version: 0,
                    })
                    .filter(|_| !forwarding),
                self_access: a.self_access.clone().filter(|_| !forwarding),
                deadline: if explicit_deadline {
                    a.deadline.clone()
                } else {
                    String::new()
                },
                origin: if defaulted_origin {
                    None
                } else {
                    a.origin.clone()
                },
                delegation: None,
                ..a.clone()
            };
            // A repeat by address keeps the stored citation unless it names
            // a grant itself.
            let same_address = |a: &TaskRequest| TaskRequest {
                grant_id: a.grant_id.clone().filter(|_| explicit_grant),
                policy: None,
                self_access: None,
                ..same_owner(a)
            };
            let differs = match &addressed {
                None => old.to.is_some() || same_owner(&old.request) != same_owner(&request),
                Some(a) => {
                    old.to.as_deref() != Some(a.to.as_str())
                        || same_address(&old.request) != same_address(&request)
                }
            };
            if old.adapter_id.is_some() || differs || ChainSpec::of(&old) != spec {
                return Err(Error::Conflict(
                    "task ID reused with different fields".into(),
                ));
            }
            return Ok(old);
        }
        if repeat && !explicit_grant {
            return Err(Error::Conflict(
                "the stored task by address changed; retry".into(),
            ));
        }
        let forward = match &spec {
            ChainSpec::Forward(parent) => {
                let f = self.forwardable(&tx, parent, &r.peer_host_id)?;
                match &request.origin {
                    // The forwarding agent is the one the parent was for.
                    Some(o) if o.agent_id != f.agent_id => return Err(Error::Forbidden),
                    Some(_) => {}
                    None => {
                        request.origin = Some(Origin {
                            agent_id: f.agent_id.clone(),
                            session_id: None,
                        });
                    }
                }
                default_cap = default_cap.min(f.deadline);
                if request.policy.is_some() {
                    let cited = self.chain_citation(&tx, &f.chain, &r.peer_host_id)?;
                    (request.policy, request.self_access) = cited.fields();
                    if let Some(until) = cited.valid_until() {
                        default_cap = default_cap.min(time(until)?);
                    }
                }
                Some(f)
            }
            _ => None,
        };
        if !explicit_deadline {
            request.deadline = rfc3339(default_cap);
        }
        if let Some(inputs) = &request.artifacts {
            self.check_uploads(&tx, inputs)?;
        }
        let delegation = self.chain_for(&tx, &r.peer_host_id, &request, &spec, forward.as_ref())?;
        request.delegation = delegation.clone();
        let mut out = OutboundTask {
            peer_host_id: r.peer_host_id,
            request,
            submit_state: "unknown".into(),
            status: None,
            events_after: 0,
            cancel_state: None,
            adapter_id: None,
            route_id: None,
            attempts: 0,
            // Retried automatically if the inline submission never finishes.
            next_attempt_at: Some(rfc3339(Utc::now() + crate::retry::PREPARE_GUARD)),
            error: None,
            status_queries: 0,
            parent: forward.as_ref().map(|f| f.parent.clone()),
            delegation,
            artifacts: Vec::new(),
            to: addressed.map(|a| a.to),
        };
        insert(&tx, &mut out)?;
        if let Some(f) = &forward {
            record_forward(&tx, f, &out)?;
        }
        tx.commit()?;
        Ok(out)
    }
    /// Checks that a received task may be forwarded to `peer`: no
    /// cancellation was requested (409), and it is running, carried a chain
    /// allowing another hop, and its acceptance allowed `task.delegate`
    /// (403). An unknown parent is not found.
    fn forwardable(
        &self,
        conn: &Connection,
        parent: &TaskParent,
        peer: &str,
    ) -> Result<Forwardable, Error> {
        let (request, status) =
            crate::task::received(conn, &parent.sender_host_id, &parent.task_id)?
                .ok_or(Error::NotFound)?;
        if status.cancel_requested {
            return Err(Error::Conflict(
                "cancellation was requested for the parent task".into(),
            ));
        }
        let Some(chain) = request.delegation.filter(|_| status.state == "running") else {
            return Err(Error::Forbidden);
        };
        let last = chain.last().expect("validated chain").clone();
        if last.depth < 1
            || !crate::task::delegable(conn, &parent.sender_host_id, &parent.task_id)?
            || chain.len() >= MAX_LINKS
        {
            return Err(Error::Forbidden);
        }
        let bindings = self.bindings(conn, &last.network_id)?;
        if peer == self.identity().id
            || crate::chain::member(conn, &last.network_id, peer)?.is_none()
            || !covered(&last.principals, &format!("host:{peer}"), &|h| {
                bindings.get(h).cloned()
            })
        {
            return Err(Error::Forbidden);
        }
        Ok(Forwardable {
            parent: parent.clone(),
            deadline: time(&last.deadline)?,
            chain,
            agent_id: request.target_agent_id,
        })
    }
    /// The chain a new task carries: none, a new link 0, or the parent's
    /// chain plus a link to `peer`, which may not outlive the parent.
    fn chain_for(
        &self,
        conn: &Connection,
        peer: &str,
        request: &TaskRequest,
        spec: &ChainSpec,
        forward: Option<&Forwardable>,
    ) -> Result<Option<Vec<Link>>, Error> {
        match (spec, forward) {
            (ChainSpec::Origin { depth, principals }, _) => {
                let network = self.shared_network(conn, peer)?;
                let origin = request
                    .origin
                    .as_ref()
                    .ok_or_else(|| Error::Invalid("a delegation chain needs an origin".into()))?;
                Ok(Some(vec![self.sign_link(Unsigned {
                    network_id: &network,
                    previous: None,
                    audience_host_id: peer,
                    task_id: &request.task_id,
                    originator_agent_id: &origin.agent_id,
                    principals,
                    deadline: &request.deadline,
                    depth: *depth,
                })]))
            }
            (ChainSpec::Forward(_), Some(f)) => {
                if time(&request.deadline)? > f.deadline {
                    return Err(Error::Forbidden);
                }
                let last = f.chain.last().expect("validated chain");
                let mut chain = f.chain.clone();
                chain.push(self.sign_link(Unsigned {
                    network_id: &last.network_id,
                    previous: Some(last),
                    audience_host_id: peer,
                    task_id: &request.task_id,
                    originator_agent_id: &last.originator_agent_id,
                    principals: &last.principals,
                    deadline: &request.deadline,
                    depth: last.depth - 1,
                }));
                Ok(Some(chain))
            }
            _ => Ok(None),
        }
    }
    /// Persists an agent-initiated task through one of the credential's
    /// `task.submit` routes, consuming one unit of its budget.
    pub fn prepare_delegation(
        &self,
        auth: &AdapterAuth,
        r: Delegate,
    ) -> Result<OutboundTask, Error> {
        if !valid_name(&r.destination)
            || !valid_id(&r.task_id, "task", 16)
            || r.input.is_empty()
            || r.input.len() > MAX_TEXT
            || r.parent_task_id
                .as_deref()
                .is_some_and(|p| !valid_id(p, "task", 16))
        {
            return Err(Error::Invalid("invalid delegation".into()));
        }
        let artifacts = normalized(r.artifacts);
        if let Some(manifest) = &artifacts {
            validate_manifest(manifest)?;
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        let route: OutboundRoute = read(
            &tx,
            "SELECT record FROM adapter_routes WHERE adapter_id = ?1 AND name = ?2",
            params![a.id, r.destination],
        )
        .map_err(|e| match e {
            Error::NotFound => Error::Forbidden,
            other => other,
        })?;
        let expiry = time(&route.expires_at)?;
        if route.revoked_at.is_some()
            || route.action != crate::policy::TASK_ACTION
            || expiry <= Utc::now()
            || r.input.len() as i64 > route.max_message_bytes
        {
            return Err(Error::Forbidden);
        }
        let reused: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbound_tasks WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2 AND (json_extract(record, '$.route_id') IS NULL OR json_extract(record, '$.route_id') != ?3))",
            params![r.task_id, a.id, route.id],
            |row| row.get(0),
        )?;
        if reused {
            return Err(Error::Conflict(
                "task ID belongs to another destination".into(),
            ));
        }
        if let Some(old) = tx
            .query_row(
                "SELECT record FROM outbound_tasks WHERE peer = ?1 AND task_id = ?2",
                params![route.peer_host_id, r.task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let mut old: OutboundTask = serde_json::from_str(&old)?;
            fill(&tx, &mut old)?;
            let Some(owner) = &old.adapter_id else {
                return Err(Error::Conflict(
                    "task belongs to owner administration".into(),
                ));
            };
            let session = old
                .request
                .origin
                .as_ref()
                .and_then(|o| o.session_id.as_deref());
            if *owner != a.id || session != Some(ss.id.as_str()) {
                return Err(Error::Forbidden);
            }
            if old.route_id.as_deref() != Some(route.id.as_str())
                || old.request.input != r.input
                || old.request.artifacts != artifacts
                || old.parent.as_ref().map(|p| p.task_id.as_str()) != r.parent_task_id.as_deref()
            {
                return Err(Error::Conflict(
                    "task ID reused with different fields".into(),
                ));
            }
            if time(&old.request.deadline)? <= Utc::now() && old.submit_state != "accepted" {
                return Err(Error::Forbidden);
            }
            return Ok(old);
        }
        if route_used(&tx, &route.id)? >= route.max_messages {
            return Err(Error::Forbidden);
        }
        let target = DelegationTarget {
            peer: route.peer_host_id.clone(),
            agent: route.target_agent_id.clone(),
            expiry,
            route: Some(route),
            to: None,
            choice: None,
        };
        let out = self.delegate_in(
            &tx,
            &a,
            &ss,
            r.task_id,
            r.input,
            artifacts,
            r.parent_task_id,
            target,
        )?;
        tx.commit()?;
        Ok(out)
    }
    /// The task for a delegation through a route or by address: a forward
    /// of a task this session claimed, or a new one, with its deadline,
    /// citation, and chain.
    #[allow(clippy::too_many_arguments)]
    fn delegate_in(
        &self,
        tx: &Transaction<'_>,
        a: &crate::adapter::Adapter,
        ss: &crate::model::Session,
        task_id: String,
        input: String,
        artifacts: Option<Vec<ArtifactEntry>>,
        parent_task_id: Option<String>,
        target: DelegationTarget,
    ) -> Result<OutboundTask, Error> {
        // A forward names a task this session claimed.
        let forward = match &parent_task_id {
            Some(parent) => {
                let sender: Option<String> = tx
                    .query_row(
                        "SELECT sender FROM task_deliveries WHERE task_id = ?1 AND session_id = ?2 AND json_extract(record, '$.adapter_id') = ?3 ORDER BY rowid LIMIT 1",
                        params![parent, ss.id, a.id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let Some(sender) = sender else {
                    // As for task transitions: claimed elsewhere is 403.
                    let known: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM received_tasks WHERE task_id = ?1)",
                        [parent],
                        |row| row.get(0),
                    )?;
                    return Err(if known {
                        Error::Forbidden
                    } else {
                        Error::NotFound
                    });
                };
                let parent = TaskParent {
                    sender_host_id: sender,
                    task_id: parent.clone(),
                };
                Some(self.forwardable(tx, &parent, &target.peer)?)
            }
            None => None,
        };
        let mut deadline = (Utc::now() + DEFAULT_DEADLINE).min(target.expiry);
        if let Some(f) = &forward {
            deadline = deadline.min(f.deadline);
        }
        let grant = match (&target.route, &target.choice) {
            (Some(route), _) => route.grant_id.clone(),
            (None, Some(crate::directory::Choice::Grant(g))) => Some(g.clone()),
            (None, _) => None,
        };
        let (policy, self_access) = match grant {
            Some(_) => (None, None),
            None => {
                let cited = match (&forward, &target.choice) {
                    (Some(f), _) => self.chain_citation(tx, &f.chain, &target.peer)?,
                    (None, Some(choice)) => match self.chosen(tx, &target.peer, choice)? {
                        Err(cited) => cited,
                        Ok(_) => unreachable!("a grant was cited above"),
                    },
                    (None, None) => self.citation(tx, &target.peer)?,
                };
                if let Some(until) = cited.valid_until() {
                    deadline = deadline.min(time(until)?);
                }
                cited.fields()
            }
        };
        if let Some(inputs) = &artifacts {
            self.check_uploads(tx, inputs)?;
        }
        let mut request = TaskRequest {
            task_id,
            grant_id: grant,
            policy,
            self_access,
            target_agent_id: target.agent.clone(),
            deadline: rfc3339(deadline),
            input,
            // The session originates the task.
            origin: Some(Origin {
                agent_id: ss.agent_id.clone(),
                session_id: Some(ss.id.clone()),
            }),
            artifacts,
            delegation: None,
        };
        let depth = target.route.as_ref().map_or(0, |r| r.delegation_depth);
        let spec = match &forward {
            Some(f) => ChainSpec::Forward(f.parent.clone()),
            None if depth > 0 => ChainSpec::Origin {
                depth,
                principals: vec![NETWORK.into()],
            },
            None => ChainSpec::None,
        };
        let delegation = self.chain_for(tx, &target.peer, &request, &spec, forward.as_ref())?;
        request.delegation = delegation.clone();
        let mut out = OutboundTask {
            peer_host_id: target.peer,
            request,
            submit_state: "unknown".into(),
            status: None,
            events_after: 0,
            cancel_state: None,
            adapter_id: Some(a.id.clone()),
            route_id: target.route.map(|r| r.id),
            attempts: 0,
            next_attempt_at: Some(rfc3339(Utc::now() + crate::retry::PREPARE_GUARD)),
            error: None,
            status_queries: 0,
            parent: forward.as_ref().map(|f| f.parent.clone()),
            delegation,
            artifacts: Vec::new(),
            to: target.to,
        };
        insert(tx, &mut out)?;
        if let Some(f) = &forward {
            record_forward(tx, f, &out)?;
        }
        Ok(out)
    }
    /// A delegation by address this credential already made with the task
    /// ID. A task ID used with a route, or with other fields, is a conflict.
    fn known_address_delegation(
        &self,
        conn: &Connection,
        a: &crate::adapter::Adapter,
        session: &str,
        to: &str,
        r: &AddressDelegate,
    ) -> Result<Option<OutboundTask>, Error> {
        let old: Option<String> = conn
            .query_row(
                "SELECT record FROM outbound_tasks WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2 ORDER BY rowid LIMIT 1",
                params![r.task_id, a.id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(old) = old else {
            return Ok(None);
        };
        let mut old: OutboundTask = serde_json::from_str(&old)?;
        fill(conn, &mut old)?;
        if old.route_id.is_some() {
            return Err(Error::Conflict(
                "task ID belongs to another destination".into(),
            ));
        }
        let origin_session = old
            .request
            .origin
            .as_ref()
            .and_then(|o| o.session_id.as_deref());
        if origin_session != Some(session) {
            return Err(Error::Forbidden);
        }
        if old.to.as_deref() != Some(to)
            || old.request.input != r.input
            || old.request.artifacts != normalized(r.artifacts.clone())
            || old.parent.as_ref().map(|p| p.task_id.as_str()) != r.parent_task_id.as_deref()
        {
            return Err(Error::Conflict(
                "task ID reused with different fields".into(),
            ));
        }
        if time(&old.request.deadline)? <= Utc::now() && old.submit_state != "accepted" {
            return Err(Error::Forbidden);
        }
        Ok(Some(old))
    }
    /// Checks a delegation by address before it is resolved: the stored
    /// task for a repeat, or else the delegating agent, once directory
    /// access and the rate cap allow a new one.
    pub fn check_address_delegation(
        &self,
        auth: &AdapterAuth,
        to: &str,
        r: &AddressDelegate,
    ) -> Result<Result<OutboundTask, String>, Error> {
        if !valid_id(&r.task_id, "task", 16)
            || r.input.is_empty()
            || r.input.len() > MAX_TEXT
            || r.parent_task_id
                .as_deref()
                .is_some_and(|p| !valid_id(p, "task", 16))
        {
            return Err(Error::Invalid("invalid delegation".into()));
        }
        if let Some(manifest) = &normalized(r.artifacts.clone()) {
            validate_manifest(manifest)?;
        }
        let conn = self.connection()?;
        let (a, ss) = authority(&conn, auth)?;
        crate::directory::directory_access(&a)?;
        if let Some(old) = self.known_address_delegation(&conn, &a, &ss.id, to, r)? {
            return Ok(Ok(old));
        }
        crate::directory::rate_check(&conn, &a)?;
        Ok(Err(ss.agent_id))
    }
    /// Persists a delegation by address to its resolved target, citing the
    /// chosen authorization, and counts it against the credential's cap.
    pub fn prepare_address_delegation(
        &self,
        auth: &AdapterAuth,
        to: &str,
        r: AddressDelegate,
        target: &crate::directory::Candidate,
        choice: &crate::directory::Choice,
    ) -> Result<OutboundTask, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        crate::directory::directory_access(&a)?;
        if let Some(old) = self.known_address_delegation(&tx, &a, &ss.id, to, &r)? {
            return Ok(old);
        }
        crate::directory::rate_check(&tx, &a)?;
        let taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbound_tasks WHERE peer = ?1 AND task_id = ?2)",
            params![target.host_id, r.task_id],
            |row| row.get(0),
        )?;
        if taken {
            return Err(Error::Conflict("task ID belongs to another task".into()));
        }
        let destination = DelegationTarget {
            peer: target.host_id.clone(),
            agent: target.agent_id.clone(),
            expiry: time(&a.expires_at)?,
            route: None,
            to: Some(to.to_owned()),
            choice: Some(choice.clone()),
        };
        let out = self.delegate_in(
            &tx,
            &a,
            &ss,
            r.task_id,
            r.input,
            normalized(r.artifacts),
            r.parent_task_id,
            destination,
        )?;
        crate::directory::count_send(&tx, &a.id, "task", &out.peer_host_id, &out.request.task_id)?;
        tx.commit()?;
        Ok(out)
    }
    /// A task submitted with this credential; any other is not found.
    pub fn delegation(&self, auth: &AdapterAuth, task_id: &str) -> Result<OutboundTask, Error> {
        let conn = self.connection()?;
        let (a, _) = authority(&conn, auth)?;
        let mut out: OutboundTask = read(
            &conn,
            "SELECT record FROM outbound_tasks WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2 ORDER BY rowid LIMIT 1",
            params![task_id, a.id],
        )?;
        fill(&conn, &mut out)?;
        Ok(out)
    }
    /// Saves one submission attempt's outcome. An accepted submission is
    /// never downgraded by a concurrent uncertain attempt.
    pub(crate) fn finish_task_submit(&self, out: OutboundTask) -> Result<OutboundTask, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut current = stored(&tx, &out.peer_host_id, &out.request.task_id)?;
        if current.submit_state == "accepted" {
            return Ok(current);
        }
        let changed = current.submit_state != out.submit_state;
        current.submit_state = out.submit_state;
        current.error = out.error;
        current.attempts = out.attempts;
        current.next_attempt_at = out.next_attempt_at;
        current.status_queries = out.status_queries;
        if let Some(status) = out.status {
            take_status(&mut current, status);
        }
        save(&tx, &current)?;
        if changed {
            append_event(&tx, "task.updated", &subject(&current), &now())?;
        }
        tx.commit()?;
        Ok(current)
    }
    /// Stores newly polled events, which must continue the stored sequence,
    /// and the latest status. Returns the record and whether anything new
    /// was stored.
    pub(crate) fn store_task_events(
        &self,
        peer: &str,
        id: &str,
        status: Option<TaskStatus>,
        events: Vec<TaskEvent>,
    ) -> Result<(OutboundTask, bool), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut out = stored(&tx, peer, id)?;
        let before = out.status.clone();
        let mut progressed = false;
        for event in events {
            if event.sequence != out.events_after + 1 {
                continue;
            }
            tx.execute(
                "INSERT INTO outbound_task_events VALUES (?1, ?2, ?3, ?4)",
                params![peer, id, event.sequence, serde_json::to_string(&event)?],
            )?;
            append_event(&tx, "task.updated", &subject(&out), &now())?;
            // Results are fetched once the final event is stored.
            if let Some(results) = &event.artifacts {
                crate::artifact::add_artifacts(
                    &tx,
                    SENT,
                    peer,
                    id,
                    RESULT,
                    results,
                    crate::artifact::PENDING,
                )?;
            }
            out.events_after = event.sequence;
            progressed = true;
        }
        if let Some(status) = status {
            take_status(&mut out, status);
        }
        progressed |= out.status != before;
        save(&tx, &out)?;
        fill(&tx, &mut out)?;
        tx.commit()?;
        Ok((out, progressed))
    }
    /// Marks a cancellation request to send, unless the task is already
    /// rejected or final.
    fn request_outbound_cancel(&self, peer: &str, id: &str) -> Result<OutboundTask, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let (out, marked) = mark_cancel(&tx, peer, id)?;
        if marked {
            tx.commit()?;
        }
        Ok(out)
    }
    fn cancel_sent(&self, peer: &str, id: &str, status: TaskStatus) -> Result<OutboundTask, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut out = stored(&tx, peer, id)?;
        out.cancel_state = Some("sent".into());
        take_status(&mut out, status);
        save(&tx, &out)?;
        tx.commit()?;
        Ok(out)
    }
    /// Uncertain submissions due at `now`, earliest first.
    pub(crate) fn due_task_retries(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(String, String)>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT record FROM outbound_tasks WHERE json_extract(record, '$.submit_state') = 'unknown'",
        )?;
        let mut due = Vec::new();
        for record in statement.query_map([], |r| r.get::<_, String>(0))? {
            let out: OutboundTask = serde_json::from_str(&record?)?;
            if let Some(at) = due_at(&out.next_attempt_at).filter(|at| *at <= now) {
                due.push((at, out.peer_host_id, out.request.task_id));
            }
        }
        due.sort();
        Ok(due.into_iter().map(|(_, peer, id)| (peer, id)).collect())
    }
    /// At startup, spreads overdue uncertain submissions over 10 seconds.
    pub(crate) fn spread_overdue_tasks(&self, now: DateTime<Utc>) -> Result<usize, Error> {
        let due = self.due_task_retries(now)?;
        let count = due.len();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        for (index, (peer, id)) in due.iter().enumerate() {
            let mut out = stored(&tx, peer, id)?;
            let offset = crate::retry::RESTART_SPREAD_MS * index as i64 / count as i64;
            out.next_attempt_at = Some(rfc3339(now + TimeDelta::milliseconds(offset)));
            save(&tx, &out)?;
        }
        tx.commit()?;
        Ok(count)
    }
    /// Tasks whose events are still to be polled, or whose cancellation
    /// request is still to be sent.
    fn pollable_tasks(&self) -> Result<Vec<(String, String)>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT record FROM outbound_tasks WHERE json_extract(record, '$.submit_state') = 'accepted' ORDER BY rowid",
        )?;
        let mut result = Vec::new();
        for record in statement.query_map([], |r| r.get::<_, String>(0))? {
            let out: OutboundTask = serde_json::from_str(&record?)?;
            if out.pollable() || out.cancel_state.as_deref() == Some("unknown") {
                result.push((out.peer_host_id, out.request.task_id));
            }
        }
        Ok(result)
    }

    /// Hands the originating session the oldest stored event of its tasks
    /// that it has not been given.
    pub fn next_task_update(&self, auth: &AdapterAuth) -> Result<Option<TaskUpdate>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        let pending: Option<(String, String, i64, String)> = tx
            .query_row(
                "SELECT e.peer, e.task_id, e.sequence, e.record FROM outbound_task_events e JOIN outbound_tasks t ON t.peer = e.peer AND t.task_id = e.task_id WHERE json_extract(t.record, '$.adapter_id') = ?1 AND json_extract(t.record, '$.request.origin.session_id') = ?2 AND NOT EXISTS (SELECT 1 FROM task_update_notifications n WHERE n.peer = e.peer AND n.task_id = e.task_id AND n.sequence = e.sequence) ORDER BY e.rowid LIMIT 1",
                params![a.id, ss.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((peer, task_id, sequence, event)) = pending else {
            return Ok(None);
        };
        let at = now();
        let n = TaskUpdateNotification {
            id: new_id("notification")?,
            peer_host_id: peer,
            task_id,
            sequence,
            adapter_id: a.id,
            session_id: ss.id,
            state: "unknown".into(),
            created_at: at.clone(),
            updated_at: at,
        };
        tx.execute(
            "INSERT INTO task_update_notifications VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                n.id,
                n.peer_host_id,
                n.task_id,
                n.sequence,
                serde_json::to_string(&n)?
            ],
        )?;
        tx.commit()?;
        Ok(Some(TaskUpdate {
            delivery: n,
            event: serde_json::from_str(&event)?,
        }))
    }
    pub fn task_update_forwarded(
        &self,
        auth: &AdapterAuth,
        id: &str,
    ) -> Result<TaskUpdateNotification, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        let mut n: TaskUpdateNotification = read(
            &tx,
            "SELECT record FROM task_update_notifications WHERE id = ?1",
            [id],
        )?;
        if n.adapter_id != a.id || n.session_id != ss.id {
            return Err(Error::NotFound);
        }
        if n.state == "forwarded" {
            return Ok(n);
        }
        n.state = "forwarded".into();
        n.updated_at = now();
        tx.execute(
            "UPDATE task_update_notifications SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&n)?, n.id],
        )?;
        tx.commit()?;
        Ok(n)
    }
}

/// Marks a cancellation request to send, unless the task is already rejected
/// or final or one is pending. Returns the record and whether it changed.
fn mark_cancel(tx: &Transaction<'_>, peer: &str, id: &str) -> Result<(OutboundTask, bool), Error> {
    let mut out = stored(tx, peer, id)?;
    if out.submit_state == "rejected"
        || out.status.as_ref().is_some_and(|s| is_final(&s.state))
        || out.cancel_state.is_some()
    {
        return Ok((out, false));
    }
    out.cancel_state = Some("unknown".into());
    save(tx, &out)?;
    Ok((out, true))
}
/// Records a forward: the parent's child, and the `task.delegated` activity.
fn record_forward(tx: &Transaction<'_>, f: &Forwardable, out: &OutboundTask) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO task_children VALUES (?1, ?2, ?3, ?4)",
        params![
            f.parent.sender_host_id,
            f.parent.task_id,
            out.peer_host_id,
            out.request.task_id
        ],
    )?;
    append_event(tx, "task.delegated", &subject(out), &now())?;
    Ok(())
}
/// Marks every task forwarded from a received task for cancellation, in
/// the caller's transaction. Returns the children newly marked.
pub(crate) fn cancel_children(
    tx: &Transaction<'_>,
    sender: &str,
    id: &str,
) -> Result<Vec<(String, String)>, Error> {
    let children = {
        let mut statement = tx.prepare(
            "SELECT peer, child_task_id FROM task_children WHERE sender = ?1 AND task_id = ?2 ORDER BY rowid",
        )?;
        statement
            .query_map(params![sender, id], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<(String, String)>, _>>()?
    };
    let mut marked = Vec::new();
    for (peer, child) in children {
        if mark_cancel(tx, &peer, &child)?.1 {
            marked.push((peer, child));
        }
    }
    Ok(marked)
}
/// Sends the pending cancellation requests of submitted children now. An
/// uncertain one, or one whose submission is not yet accepted, is left to
/// the poll worker.
pub(crate) async fn send_cancels(store: Arc<Store>, children: Vec<(String, String)>) {
    for (peer, id) in children {
        let Ok(out) = blocking(store.clone(), move |s| s.outbound_task(&peer, &id)).await else {
            continue;
        };
        if out.submit_state == "accepted" && out.cancel_state.as_deref() == Some("unknown") {
            let _ = send_cancel(&store, out).await;
        }
    }
}

/// A status record from the receiver about one of this host's tasks.
fn valid_status(store: &Store, out: &OutboundTask, s: &TaskStatus) -> bool {
    s.sender_host_id == store.identity().id
        && s.receiver_host_id == out.peer_host_id
        && s.task_id == out.request.task_id
        && s.target_agent_id == out.request.target_agent_id
        && s.last_event >= 1
        && DateTime::parse_from_rfc3339(&s.created_at).is_ok()
        && DateTime::parse_from_rfc3339(&s.updated_at).is_ok()
        && crate::task::STATES.contains(&s.state.as_str())
}
async fn peer_request(
    store: &Arc<Store>,
    peer: &str,
    method: &'static str,
    path: String,
    body: Vec<u8>,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let peer_id = peer.to_owned();
    let target = blocking(store.clone(), move |s| s.dial_target(&peer_id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tokio::time::timeout(
        REQUEST_BOUND,
        crate::quic::request(store.clone(), &target, method, &path, &body),
    )
    .await?
}
/// Fetches the remote status record.
async fn fetch_status(store: &Arc<Store>, out: &OutboundTask) -> anyhow::Result<TaskStatus> {
    let path = format!("/peer/v1/tasks/{}", out.request.task_id);
    match peer_request(store, &out.peer_host_id, "GET", path, Vec::new()).await? {
        (200, body) => {
            let status: TaskStatus = serde_json::from_slice(&body)?;
            if !valid_status(store, out, &status) {
                anyhow::bail!("invalid peer task status");
            }
            Ok(status)
        }
        (code, _) => anyhow::bail!("peer returned HTTP {code}"),
    }
}

/// One submission attempt: before the deadline it submits the saved request;
/// after it, it only queries the status. Uncertain outcomes stay `unknown`.
pub(crate) async fn submit(
    store: Arc<Store>,
    mut out: OutboundTask,
    status_only: bool,
) -> Result<OutboundTask, Error> {
    if out.submit_state != "unknown" {
        return Ok(out);
    }
    let result: anyhow::Result<TaskStatus> = if status_only {
        fetch_status(&store, &out).await
    } else {
        let body = serde_json::to_vec(&out.request).map_err(Error::from)?;
        match peer_request(
            &store,
            &out.peer_host_id,
            "POST",
            "/peer/v1/tasks".into(),
            body,
        )
        .await
        {
            Ok((200, body)) => match serde_json::from_slice::<TaskStatus>(&body) {
                Ok(status) if valid_status(&store, &out, &status) => Ok(status),
                _ => Err(anyhow::anyhow!("invalid peer task status")),
            },
            Ok((code, _)) => {
                if matches!(code, 400 | 403 | 404 | 409) {
                    out.submit_state = "rejected".into();
                }
                Err(anyhow::anyhow!("peer returned HTTP {code}"))
            }
            Err(e) => Err(e),
        }
    };
    out.error = None;
    match result {
        Ok(status) => {
            out.submit_state = "accepted".into();
            out.status = Some(status);
        }
        Err(e) => out.error = Some(format!("{e:#}")),
    }
    crate::retry::schedule(&mut out, status_only, Utc::now(), crate::retry::jitter());
    blocking(store, move |s| s.finish_task_submit(out)).await
}

/// Sends a pending cancellation request. An uncertain result stays pending
/// for the poll worker to resend.
async fn send_cancel(store: &Arc<Store>, out: OutboundTask) -> Result<OutboundTask, Error> {
    let path = format!("/peer/v1/tasks/{}/cancel", out.request.task_id);
    let response = peer_request(store, &out.peer_host_id, "POST", path, b"{}".to_vec()).await;
    if let Ok((200, body)) = response
        && let Ok(status) = serde_json::from_slice::<TaskStatus>(&body)
        && valid_status(store, &out, &status)
    {
        let (peer, id) = (out.peer_host_id.clone(), out.request.task_id.clone());
        return blocking(store.clone(), move |s| s.cancel_sent(&peer, &id, status)).await;
    }
    Ok(out)
}

/// One poll: resends a pending cancellation, then fetches the status and any
/// events after the stored cursor. Returns whether anything new was stored.
async fn poll(store: Arc<Store>, peer: String, id: String) -> anyhow::Result<bool> {
    let (p, i) = (peer.clone(), id.clone());
    let mut out = blocking(store.clone(), move |s| s.outbound_task(&p, &i)).await?;
    if out.submit_state != "accepted" {
        return Ok(false);
    }
    if out.cancel_state.as_deref() == Some("unknown") {
        out = send_cancel(&store, out).await?;
    }
    if !out.pollable() {
        return Ok(false);
    }
    let status = fetch_status(&store, &out).await?;
    let mut after = out.events_after;
    let mut progressed = false;
    loop {
        let mut events = Vec::new();
        if status.last_event > after {
            let path = format!("/peer/v1/tasks/{id}/events?after={after}&limit={EVENT_PAGE}");
            let (code, body) = peer_request(&store, &peer, "GET", path, Vec::new()).await?;
            if code != 200 {
                anyhow::bail!("peer returned HTTP {code}");
            }
            events = serde_json::from_slice::<Vec<TaskEvent>>(&body)?;
            for (expected, event) in (after + 1..).zip(&events) {
                if event.sequence != expected || !event.well_formed() {
                    anyhow::bail!("invalid peer task events");
                }
            }
        }
        let full = events.len() as i64 == EVENT_PAGE;
        let (p, i, s) = (peer.clone(), id.clone(), status.clone());
        let (stored, changed) = blocking(store.clone(), move |st| {
            st.store_task_events(&p, &i, Some(s), events)
        })
        .await?;
        progressed |= changed;
        if !full || stored.events_after <= after {
            break;
        }
        after = stored.events_after;
    }
    Ok(progressed)
}

/// Per task: when its next poll is due, and the current backoff interval.
type PollPlan = HashMap<(String, String), (Instant, Duration)>;
/// Runs task submission retries, event polls, and cancellation resends,
/// at most 4 at once, until shutdown.
pub async fn task_worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let _ = blocking(store.clone(), |s| s.spread_overdue_tasks(Utc::now())).await;
    let dispatcher = Dispatcher::new(crate::retry::CONCURRENCY);
    // In-memory poll backoff per task: when next due, and the current interval.
    let schedule: Arc<std::sync::Mutex<PollPlan>> = Arc::default();
    // In-memory fetch backoff per artifact row, from 1 second to 60 seconds;
    // a restart retries at once.
    let fetch_plan: Arc<std::sync::Mutex<PollPlan>> = Arc::default();
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(crate::retry::POLL) => {}
        }
        let mut jobs: Vec<((String, String), bool)> = Vec::new();
        if let Ok(due) = blocking(store.clone(), |s| s.due_task_retries(Utc::now())).await {
            jobs.extend(due.into_iter().map(|k| (k, false)));
        }
        if let Ok(pollable) = blocking(store.clone(), |s| s.pollable_tasks()).await
            && let Ok(mut plan) = schedule.lock()
        {
            let now = Instant::now();
            plan.retain(|k, _| pollable.contains(k));
            for key in pollable {
                let (due, _) = *plan.entry(key.clone()).or_insert((now, POLL_FIRST));
                if due <= now {
                    jobs.push((key, true));
                }
            }
        }
        let polls: HashMap<(String, String), bool> = jobs.iter().cloned().collect();
        let mut keys: Vec<(String, String)> = jobs.into_iter().map(|(k, _)| k).collect();
        // Artifact fetches share the same 4 slots.
        let mut fetches: HashMap<(String, String), crate::artifact::RowKey> = HashMap::new();
        if let Ok(pending) = blocking(store.clone(), |s| s.pending_fetches()).await
            && let Ok(mut plan) = fetch_plan.lock()
        {
            let now = Instant::now();
            let wanted: Vec<(String, String)> = pending.iter().map(|r| r.job()).collect();
            plan.retain(|k, _| wanted.contains(k));
            for row in pending {
                let key = row.job();
                if plan.get(&key).is_none_or(|(due, _)| *due <= now) {
                    keys.push(key.clone());
                    fetches.insert(key, row);
                }
            }
        }
        for claim in dispatcher.claim(keys) {
            let store = store.clone();
            let key = claim.key().clone();
            let is_poll = polls.get(&key).copied().unwrap_or(false);
            let fetch = fetches.remove(&key);
            let schedule = schedule.clone();
            let fetch_plan = fetch_plan.clone();
            tokio::spawn(async move {
                let (peer, id) = key.clone();
                if let Some(row) = fetch {
                    let done = crate::artifact::fetch(store, row).await;
                    if let Ok(mut plan) = fetch_plan.lock() {
                        if done {
                            plan.remove(&key);
                        } else {
                            let interval = match plan.get(&key) {
                                Some((_, last)) => (*last * 2).min(POLL_MAX),
                                None => POLL_FIRST,
                            };
                            plan.insert(key, (Instant::now() + interval, interval));
                        }
                    }
                } else if is_poll {
                    let progressed = poll(store, peer, id).await.unwrap_or(false);
                    if let Ok(mut plan) = schedule.lock() {
                        let interval = match plan.get(&key) {
                            _ if progressed => POLL_FIRST,
                            Some((_, last)) => (*last * 2).min(POLL_MAX),
                            None => POLL_FIRST,
                        };
                        plan.insert(key, (Instant::now() + interval, interval));
                    }
                } else {
                    retry(store, peer, id).await;
                }
                drop(claim);
            });
        }
    }
}
async fn retry(store: Arc<Store>, peer: String, id: String) {
    let Ok(out) = blocking(store.clone(), move |s| s.outbound_task(&peer, &id)).await else {
        return;
    };
    if out.submit_state != "unknown"
        || due_at(&out.next_attempt_at).is_none_or(|at| at > Utc::now())
    {
        return;
    }
    let status_only = crate::retry::receipt_only(&out, Utc::now());
    let _ = submit(store, out, status_only).await;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
struct Page {
    after: Option<i64>,
    limit: Option<i64>,
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/tasks", get(list).post(create))
        .route("/v1/tasks/{peer}/{id}", get(inspect))
        .route("/v1/tasks/{peer}/{id}/events", get(events))
        .route("/v1/tasks/{peer}/{id}/cancel", post(cancel))
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/delegations", post(delegate))
        .route("/adapter/v1/delegations/{task_id}", get(delegation))
        .route("/adapter/v1/task-updates/next", post(next_update))
        .route(
            "/adapter/v1/task-updates/{id}/forwarded",
            post(update_forwarded),
        )
}
fn bounds(query: Result<Query<Page>, QueryRejection>) -> Result<(i64, i64), Error> {
    let Query(p) = query.map_err(|_| Error::Invalid("invalid page bounds".into()))?;
    Ok((p.after.unwrap_or(0), p.limit.unwrap_or(100)))
}
async fn list(
    State(store): State<Arc<Store>>,
    query: Result<Query<Page>, QueryRejection>,
) -> Result<Json<Vec<TaskItem>>, Error> {
    let (after, limit) = bounds(query)?;
    Ok(Json(
        blocking(store, move |s| s.outbound_tasks(after, limit)).await?,
    ))
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<OutboundTask>, Error> {
    let mut value: Value = decode(body)?;
    let addressed =
        match crate::directory::split_address(&mut value, &["peer_host_id", "target_agent_id"])? {
            None => None,
            Some((to, network)) => {
                // A forward needs `task.delegate`.
                let action = if value.get("parent").is_some_and(|p| !p.is_null()) {
                    crate::policy::DELEGATE_ACTION
                } else {
                    crate::policy::TASK_ACTION
                };
                Some(
                    crate::directory::owner_request(
                        &store, &mut value, &to, network, "task_id", action,
                    )
                    .await?,
                )
            }
        };
    let request = crate::directory::body(value)?;
    let out = blocking(store.clone(), move |s| {
        s.prepare_task_to(request, addressed)
    })
    .await?;
    let status_only = crate::retry::receipt_only(&out, Utc::now());
    Ok(Json(submit(store, out, status_only).await?))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundTask>, Error> {
    Ok(Json(
        blocking(store, move |s| s.outbound_task(&peer, &id)).await?,
    ))
}
async fn events(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
    query: Result<Query<Page>, QueryRejection>,
) -> Result<Json<Vec<TaskEvent>>, Error> {
    let (after, limit) = bounds(query)?;
    Ok(Json(
        blocking(store, move |s| {
            s.outbound_task_events(&peer, &id, after, limit)
        })
        .await?,
    ))
}
async fn cancel(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundTask>, Error> {
    let out = blocking(store.clone(), move |s| {
        s.request_outbound_cancel(&peer, &id)
    })
    .await?;
    if out.submit_state == "accepted" && out.cancel_state.as_deref() == Some("unknown") {
        return Ok(Json(send_cancel(&store, out).await?));
    }
    Ok(Json(out))
}
async fn delegate(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<OutboundTask>, Error> {
    let mut value: Value = decode(body)?;
    let auth = crate::adapter::token(&headers);
    let out = match crate::directory::split_address(&mut value, &["destination"])? {
        None => {
            let request = crate::directory::body(value)?;
            blocking(store.clone(), move |s| s.prepare_delegation(&auth, request)).await?
        }
        Some((to, network)) => {
            address_delegation(
                store.clone(),
                auth,
                to,
                network,
                crate::directory::body(value)?,
            )
            .await?
        }
    };
    let status_only = crate::retry::receipt_only(&out, Utc::now());
    Ok(Json(submit(store, out, status_only).await?))
}
/// A delegation by address: checked, resolved, authorized, then persisted.
async fn address_delegation(
    store: Arc<Store>,
    auth: AdapterAuth,
    to: String,
    network: Option<String>,
    r: AddressDelegate,
) -> Result<OutboundTask, Error> {
    let (check, address, request) = (auth.clone(), to.clone(), r.clone());
    let origin = match blocking(store.clone(), move |s| {
        s.check_address_delegation(&check, &address, &request)
    })
    .await?
    {
        Ok(old) => return Ok(old),
        Err(origin) => origin,
    };
    let target = crate::directory::resolve(&store, &to, network.as_deref()).await?;
    // A forward needs `task.delegate`.
    let action = if r.parent_task_id.is_some() {
        crate::policy::DELEGATE_ACTION
    } else {
        crate::policy::TASK_ACTION
    };
    let choice = crate::directory::authorize(&store, &to, &target, action, Some(&origin)).await?;
    blocking(store, move |s| {
        s.prepare_address_delegation(&auth, &to, r, &target, &choice)
    })
    .await
}
async fn delegation(
    State(store): State<Arc<Store>>,
    Path(task_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<OutboundTask>, Error> {
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.delegation(&auth, &task_id)).await?,
    ))
}
async fn next_update(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<TaskUpdate>>, Error> {
    let _: Empty = decode(body)?;
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.next_task_update(&auth)).await?,
    ))
}
async fn update_forwarded(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TaskUpdateNotification>, Error> {
    let _: Empty = decode(body)?;
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.task_update_forwarded(&auth, &id)).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter_outbound::{CreateOutboundRoute, tests::connected_adapter},
        peer_store::tests::{add_test_peer, local_agent},
    };

    fn submission(peer: &str, task: &str) -> SubmitTask {
        SubmitTask {
            peer_host_id: peer.into(),
            task_id: task.into(),
            grant_id: Some(format!("grant_{}", "1".repeat(32))),
            target_agent_id: format!("agent_{}", "2".repeat(32)),
            deadline: None,
            input: "review this".into(),
            origin: None,
            artifacts: None,
            delegation_depth: 0,
            delegation_principals: None,
            parent: None,
        }
    }
    fn status(store: &Store, out: &OutboundTask, state: &str, last: i64) -> TaskStatus {
        TaskStatus {
            task_id: out.request.task_id.clone(),
            sender_host_id: store.identity().id,
            receiver_host_id: out.peer_host_id.clone(),
            target_agent_id: out.request.target_agent_id.clone(),
            state: state.into(),
            cancel_requested: false,
            created_at: now(),
            updated_at: now(),
            last_event: last,
        }
    }
    fn event(sequence: i64, kind: &str, state: &str) -> TaskEvent {
        TaskEvent {
            sequence,
            kind: kind.into(),
            state: state.into(),
            message: None,
            output: None,
            created_at: now(),
            artifacts: None,
        }
    }
    fn accepted(store: &Store, out: &OutboundTask) -> OutboundTask {
        let mut done = out.clone();
        done.submit_state = "accepted".into();
        done.status = Some(status(store, out, "queued", 1));
        crate::retry::schedule(&mut done, false, Utc::now(), 0.0);
        store.finish_task_submit(done).unwrap()
    }

    #[test]
    fn owner_submissions_persist_before_sending_and_deduplicate() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("host")).unwrap();
        let peer = add_test_peer(&store).id;
        let id = format!("task_{}", "a".repeat(32));
        let unknown_agent = SubmitTask {
            origin: Some(Origin {
                agent_id: format!("agent_{}", "9".repeat(32)),
                session_id: None,
            }),
            ..submission(&peer, &id)
        };
        assert!(matches!(
            store.prepare_task(unknown_agent),
            Err(Error::NotFound)
        ));
        let out = store.prepare_task(submission(&peer, &id)).unwrap();
        assert_eq!(out.submit_state, "unknown");
        assert!(out.next_attempt_at.is_some());
        let deadline = time(&out.request.deadline).unwrap() - Utc::now();
        assert!(deadline > TimeDelta::minutes(59) && deadline <= TimeDelta::hours(1));
        let shown = serde_json::to_value(&out).unwrap();
        for field in ["status", "cancel_state", "adapter_id", "route_id", "error"] {
            assert!(
                shown[field].is_null() && shown.get(field).is_some(),
                "{field}"
            );
        }
        assert_eq!(shown["events_after"], 0);
        assert_eq!(shown["status_queries"], 0);
        assert!(shown["request"].get("policy").is_none());
        // An identical repeat, even with a later default deadline, returns it.
        let again = store.prepare_task(submission(&peer, &id)).unwrap();
        assert_eq!(again.request, out.request);
        let changed = SubmitTask {
            input: "other".into(),
            ..submission(&peer, &id)
        };
        assert!(matches!(
            store.prepare_task(changed),
            Err(Error::Conflict(_))
        ));
        let generated = store.prepare_task(submission(&peer, "")).unwrap();
        assert!(valid_id(&generated.request.task_id, "task", 16));
        let list = store.outbound_tasks(0, 10).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].task.request.task_id, id);
        assert_eq!(store.outbound_tasks(list[0].sequence, 10).unwrap().len(), 1);
        let (agent, session) = local_agent(&store, "me");
        let from = store
            .prepare_task(SubmitTask {
                origin: Some(Origin {
                    agent_id: agent.clone(),
                    session_id: Some(session),
                }),
                ..submission(&peer, "")
            })
            .unwrap();
        assert_eq!(from.request.origin.unwrap().agent_id, agent);
        let submitted = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "task.submitted")
            .count();
        assert_eq!(submitted, 3);
    }

    #[test]
    fn uncertain_submissions_retry_and_acceptance_is_never_downgraded() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("host")).unwrap();
        let peer = add_test_peer(&store).id;
        let out = store
            .prepare_task(submission(&peer, &format!("task_{}", "a".repeat(32))))
            .unwrap();
        assert!(store.due_task_retries(Utc::now()).unwrap().is_empty());
        let later = Utc::now() + TimeDelta::seconds(11);
        assert_eq!(store.due_task_retries(later).unwrap().len(), 1);
        let mut uncertain = out.clone();
        uncertain.error = Some("timeout".into());
        crate::retry::schedule(&mut uncertain, false, Utc::now(), 0.0);
        let saved = store.finish_task_submit(uncertain.clone()).unwrap();
        assert_eq!(
            (saved.attempts, saved.submit_state.as_str()),
            (1, "unknown")
        );
        let done = accepted(&store, &out);
        assert_eq!(done.submit_state, "accepted");
        assert_eq!(done.next_attempt_at, None);
        assert_eq!(
            store.finish_task_submit(uncertain).unwrap().submit_state,
            "accepted"
        );
        assert!(store.due_task_retries(later).unwrap().is_empty());
        // After the deadline only status queries count, up to ten.
        let mut late = out.clone();
        late.request.deadline = rfc3339(Utc::now() - TimeDelta::minutes(1));
        assert!(crate::retry::receipt_only(&late, Utc::now()));
        for _ in 0..10 {
            crate::retry::schedule(&mut late, true, Utc::now(), 0.0);
        }
        assert_eq!((late.status_queries, late.next_attempt_at), (10, None));
        let updated = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "task.updated")
            .count();
        assert_eq!(updated, 1);
    }

    #[test]
    fn polled_events_continue_the_sequence_until_final() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("host")).unwrap();
        let peer = add_test_peer(&store).id;
        let out = store
            .prepare_task(submission(&peer, &format!("task_{}", "a".repeat(32))))
            .unwrap();
        let id = out.request.task_id.clone();
        assert!(store.pollable_tasks().unwrap().is_empty());
        let out = accepted(&store, &out);
        assert_eq!(
            store.pollable_tasks().unwrap(),
            [(peer.clone(), id.clone())]
        );
        let (stored, progressed) = store
            .store_task_events(
                &peer,
                &id,
                Some(status(&store, &out, "running", 2)),
                vec![
                    event(1, "queued", "queued"),
                    event(3, "progress", "running"),
                ],
            )
            .unwrap();
        // A gap is not stored.
        assert!(progressed);
        assert_eq!(stored.events_after, 1);
        let (stored, _) = store
            .store_task_events(
                &peer,
                &id,
                Some(status(&store, &out, "succeeded", 3)),
                vec![
                    event(2, "accepted", "running"),
                    event(3, "succeeded", "succeeded"),
                ],
            )
            .unwrap();
        assert_eq!(stored.events_after, 3);
        assert_eq!(stored.status.as_ref().unwrap().state, "succeeded");
        // An older status never replaces a newer one.
        let (stored, progressed) = store
            .store_task_events(&peer, &id, Some(status(&store, &out, "running", 2)), vec![])
            .unwrap();
        assert!(!progressed);
        assert_eq!(stored.status.unwrap().state, "succeeded");
        assert!(store.pollable_tasks().unwrap().is_empty());
        let events = store.outbound_task_events(&peer, &id, 1, 100).unwrap();
        assert_eq!(
            events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            [2, 3]
        );
        assert!(matches!(
            store.outbound_task_events(&peer, &format!("task_{}", "b".repeat(32)), 0, 10),
            Err(Error::NotFound)
        ));
        // Cancelling a final task changes nothing.
        assert_eq!(
            store
                .request_outbound_cancel(&peer, &id)
                .unwrap()
                .cancel_state,
            None
        );
    }

    #[test]
    fn cancellation_stays_pending_until_the_receiver_confirms() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("host")).unwrap();
        let peer = add_test_peer(&store).id;
        let out = store
            .prepare_task(submission(&peer, &format!("task_{}", "a".repeat(32))))
            .unwrap();
        let id = out.request.task_id.clone();
        let pending = store.request_outbound_cancel(&peer, &id).unwrap();
        assert_eq!(pending.cancel_state.as_deref(), Some("unknown"));
        // Pending cancellations are resent once the task is accepted.
        assert!(store.pollable_tasks().unwrap().is_empty());
        let out = accepted(&store, &out);
        assert_eq!(store.pollable_tasks().unwrap().len(), 1);
        let mut confirmed = status(&store, &out, "queued", 2);
        confirmed.cancel_requested = true;
        let sent = store.cancel_sent(&peer, &id, confirmed).unwrap();
        assert_eq!(sent.cancel_state.as_deref(), Some("sent"));
        assert!(sent.status.unwrap().cancel_requested);
        assert_eq!(
            store
                .request_outbound_cancel(&peer, &id)
                .unwrap()
                .cancel_state
                .as_deref(),
            Some("sent")
        );
    }

    #[test]
    fn delegations_use_task_routes_and_return_updates_to_their_session() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("host")).unwrap();
        let peer = add_test_peer(&store).id;
        let auth = connected_adapter(&store, "a");
        let other = connected_adapter(&store, "b");
        let session = store.adapter_session(&auth).unwrap();
        let adapter_id = authority(&store.connection().unwrap(), &auth).unwrap().0.id;
        let route = |name: &str, action: Option<&str>, budget: i64| {
            store
                .create_outbound_route(CreateOutboundRoute {
                    adapter_id: adapter_id.clone(),
                    name: name.into(),
                    peer_host_id: peer.clone(),
                    target_agent_id: format!("agent_{}", "1".repeat(32)),
                    grant_id: Some(format!("grant_{}", "1".repeat(32))),
                    expires_at: Some(rfc3339(Utc::now() + TimeDelta::minutes(30))),
                    max_message_bytes: 100,
                    max_messages: budget,
                    action: action.map(Into::into),
                    delegation_depth: 0,
                    follows_credential: false,
                    authorization: None,
                })
                .unwrap()
        };
        let messages = route("chat", None, 10);
        assert_eq!(messages.action, "message.append");
        let tasks = route("worker", Some("task.submit"), 2);
        let destinations = store.destinations(&auth).unwrap();
        assert_eq!(
            destinations
                .iter()
                .map(|d| (d.name.as_str(), d.action.as_str()))
                .collect::<Vec<_>>(),
            [("chat", "message.append"), ("worker", "task.submit")]
        );
        let delegate = |destination: &str, n: char, input: &str| {
            store.prepare_delegation(
                &auth,
                Delegate {
                    destination: destination.into(),
                    task_id: format!("task_{}", n.to_string().repeat(32)),
                    input: input.into(),
                    artifacts: None,
                    parent_task_id: None,
                },
            )
        };
        assert!(matches!(delegate("chat", '1', "x"), Err(Error::Forbidden)));
        assert!(matches!(
            store.prepare_adapter_send(
                &auth,
                crate::adapter_outbound::AdapterSend {
                    destination: "worker".into(),
                    request_id: format!("request_{}", "1".repeat(32)),
                    content: "x".into(),
                }
            ),
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            delegate("worker", '1', &"x".repeat(101)),
            Err(Error::Forbidden)
        ));
        let out = delegate("worker", '1', "do the thing").unwrap();
        assert_eq!(out.adapter_id.as_deref(), Some(adapter_id.as_str()));
        assert_eq!(out.route_id.as_deref(), Some(tasks.id.as_str()));
        assert_eq!(
            out.request.origin,
            Some(Origin {
                agent_id: session.agent_id.clone(),
                session_id: Some(session.id.clone()),
            })
        );
        assert!(time(&out.request.deadline).unwrap() <= Utc::now() + DEFAULT_DEADLINE);
        // Identical repeats reuse the task; changes conflict.
        assert_eq!(
            delegate("worker", '1', "do the thing").unwrap().request,
            out.request
        );
        assert!(matches!(
            delegate("worker", '1', "else"),
            Err(Error::Conflict(_))
        ));
        // The budget counts tasks.
        delegate("worker", '2', "two").unwrap();
        assert!(matches!(
            delegate("worker", '3', "three"),
            Err(Error::Forbidden)
        ));
        assert_eq!(
            store
                .destinations(&auth)
                .unwrap()
                .into_iter()
                .find(|d| d.name == "worker")
                .unwrap()
                .messages_remaining,
            0
        );
        // Status is scoped to the submitting credential.
        assert_eq!(
            store
                .delegation(&auth, &out.request.task_id)
                .unwrap()
                .request,
            out.request
        );
        assert!(matches!(
            store.delegation(&other, &out.request.task_id),
            Err(Error::NotFound)
        ));
        // Every stored event becomes one update for the originating session.
        assert!(store.next_task_update(&auth).unwrap().is_none());
        accepted(&store, &out);
        store
            .store_task_events(
                &peer,
                &out.request.task_id,
                None,
                vec![
                    event(1, "queued", "queued"),
                    event(2, "accepted", "running"),
                ],
            )
            .unwrap();
        assert!(store.next_task_update(&other).unwrap().is_none());
        let first = store.next_task_update(&auth).unwrap().unwrap();
        assert_eq!(
            (first.event.sequence, first.delivery.state.as_str()),
            (1, "unknown")
        );
        assert_eq!(first.delivery.session_id, session.id);
        let second = store.next_task_update(&auth).unwrap().unwrap();
        assert_eq!(second.event.kind, "accepted");
        assert!(store.next_task_update(&auth).unwrap().is_none());
        assert!(matches!(
            store.task_update_forwarded(&other, &first.delivery.id),
            Err(Error::NotFound)
        ));
        let forwarded = store
            .task_update_forwarded(&auth, &first.delivery.id)
            .unwrap();
        assert_eq!(forwarded.state, "forwarded");
        assert_eq!(
            store
                .task_update_forwarded(&auth, &first.delivery.id)
                .unwrap()
                .updated_at,
            forwarded.updated_at
        );
        // An owner-submitted task with the same ID cannot be adopted.
        let owner = store
            .prepare_task(SubmitTask {
                task_id: format!("task_{}", "4".repeat(32)),
                ..submission(&peer, "")
            })
            .unwrap();
        let mut more = tasks.clone();
        more.max_messages = 10;
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE adapter_routes SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&more).unwrap(), tasks.id],
            )
            .unwrap();
        assert!(matches!(
            delegate("worker", '4', &owner.request.input),
            Err(Error::Conflict(_))
        ));
    }
}
