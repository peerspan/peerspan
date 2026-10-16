//! Calls to shared tools (tools contract): the submitting host. The owner
//! CLI names a target, `PERSON/AGENT/SERVER[@PROFILE]` or
//! `HOST_ID/AGENT/SERVER[@PROFILE]`; the daemon resolves it through the
//! network map and the peers' tool listings, cites what the listing
//! reported, persists the call, submits it with retries, and polls its
//! status until final.
use crate::{
    api::{blocking, decode},
    calls::{CallRequest, CallStatus, MAX_DEADLINE, call_id_shape, is_final},
    model::Error,
    peer_store::{read, valid_id},
    policy::{PolicyRef, SelfRef},
    retry::{Attempted, due_at},
    store::{Store, append_event, new_id, now, rfc3339},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

/// Listings are fetched at most 8 at once, 5 seconds each.
const PARALLEL: usize = 8;
const LISTING_BOUND: Duration = Duration::from_secs(5);
/// Peer requests are bounded like task requests.
const REQUEST_BOUND: Duration = Duration::from_secs(8);

/// `POST /v1/calls`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitCall {
    /// `PERSON/AGENT/SERVER[@PROFILE]` or `HOST_ID/AGENT/SERVER[@PROFILE]`.
    pub target: String,
    /// `tool` or `resource`.
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub arguments: Option<Value>,
    /// RFC3339; default 15 minutes from now, or the cited policy's end.
    #[serde(default)]
    pub deadline: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub call_id: Option<String>,
}

/// The submitter's local record of an outbound call.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboundCall {
    pub peer_host_id: String,
    #[serde(with = "crate::peer_store::recorded")]
    pub request: CallRequest,
    /// `unknown`, `accepted`, or `rejected`.
    pub submit_state: String,
    pub status: Option<CallStatus>,
    pub result: Option<Value>,
    /// Null, or `unknown` until the receiver confirms, then `sent`.
    pub cancel_state: Option<String>,
    pub attempts: u32,
    pub next_attempt_at: Option<String>,
    pub error: Option<String>,
    pub status_queries: u32,
    /// The network whose authorization the call cites.
    pub network_id: Option<String>,
    /// The target as given.
    pub target: String,
}
impl Attempted for OutboundCall {
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
impl OutboundCall {
    fn pollable(&self) -> bool {
        self.submit_state == "accepted"
            && (self.status.as_ref().is_none_or(|s| !is_final(&s.state))
                || self.cancel_state.as_deref() == Some("unknown"))
    }
    fn final_state(&self) -> bool {
        self.status.as_ref().is_some_and(|s| is_final(&s.state))
    }
}

fn stored(conn: &Connection, peer: &str, id: &str) -> Result<OutboundCall, Error> {
    read(
        conn,
        "SELECT record FROM outbound_calls WHERE peer = ?1 AND call_id = ?2",
        params![peer, id],
    )
}
fn save(tx: &Transaction<'_>, out: &OutboundCall) -> Result<(), Error> {
    tx.execute(
        "UPDATE outbound_calls SET record = ?1 WHERE peer = ?2 AND call_id = ?3",
        params![
            serde_json::to_string(out)?,
            out.peer_host_id,
            out.request.call_id
        ],
    )?;
    Ok(())
}
fn subject(out: &OutboundCall) -> String {
    format!("{}/{}", out.peer_host_id, out.request.call_id)
}
fn valid_status(store: &Store, out: &OutboundCall, s: &CallStatus) -> bool {
    s.sender_host_id == store.identity().id
        && s.receiver_host_id == out.peer_host_id
        && s.call_id == out.request.call_id
        && s.target_agent_id == out.request.target_agent_id
        && crate::calls::STATES.contains(&s.state.as_str())
}

/// A parsed target.
struct Target {
    owner: String,
    agent: String,
    server: String,
    profile: Option<String>,
}
fn parse_target(target: &str) -> Result<Target, Error> {
    let mut parts = target.rsplitn(3, '/');
    let (Some(server), Some(agent), Some(owner)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Invalid(
            "a target is PERSON/AGENT/SERVER[@PROFILE] or HOST_ID/AGENT/SERVER[@PROFILE]".into(),
        ));
    };
    let Some((server, profile)) = crate::policy::split_server(server) else {
        return Err(Error::Invalid(format!("invalid server {server:?}")));
    };
    if owner.is_empty() || agent.is_empty() {
        return Err(Error::Invalid("invalid target".into()));
    }
    Ok(Target {
        owner: owner.to_owned(),
        agent: agent.to_owned(),
        server: server.to_owned(),
        profile: profile.map(str::to_owned),
    })
}

impl Store {
    /// The hosts `owner` names: a known host ID, or the hosts bound to a
    /// person (label or ID) in each network searched.
    pub(crate) fn owner_hosts(
        &self,
        owner: &str,
        network: Option<&str>,
    ) -> Result<Vec<String>, Error> {
        let own = self.identity().id;
        if valid_id(owner, "host", 32) {
            self.dial_target(owner)?;
            return Ok(vec![owner.to_owned()]);
        }
        let conn = self.connection()?;
        let networks: Vec<String> = match network {
            Some(n) => {
                self.network_record(&conn, n)?;
                vec![n.to_owned()]
            }
            None => {
                let mut statement = conn.prepare("SELECT id FROM networks ORDER BY id")?;
                statement
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?
            }
        };
        let mut found = false;
        let mut hosts = Vec::new();
        for n in &networks {
            let persons = self.stored_persons(&conn, n)?;
            let person = match crate::admins::resolve_person(&persons, owner) {
                Ok(p) => p.person_id.clone(),
                Err(Error::NotFound) => continue,
                Err(e) => return Err(e),
            };
            found = true;
            for m in self.stored_members(&conn, n)? {
                if m.person_id.as_deref() == Some(person.as_str())
                    && m.host_id != own
                    && !hosts.contains(&m.host_id)
                {
                    hosts.push(m.host_id);
                }
            }
        }
        if !found {
            return Err(Error::Invalid(format!(
                "no person {owner:?} in the networks searched"
            )));
        }
        hosts.sort();
        Ok(hosts)
    }
    /// Every other member host of the networks searched.
    fn all_hosts(&self, network: Option<&str>) -> Result<Vec<String>, Error> {
        let own = self.identity().id;
        let mut hosts: Vec<String> = Vec::new();
        for n in self.networks()? {
            if network.is_some_and(|x| x != n.id) {
                continue;
            }
            for m in self.members(&n.id)? {
                if m.host_id != own && !hosts.contains(&m.host_id) {
                    hosts.push(m.host_id);
                }
            }
        }
        hosts.sort();
        Ok(hosts)
    }
    pub fn outbound_call(&self, peer: &str, id: &str) -> Result<OutboundCall, Error> {
        stored(&*self.connection()?, peer, id)
    }
    pub fn outbound_calls(&self, after: i64, limit: i64) -> Result<Vec<Value>, Error> {
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("invalid page bounds".into()));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT rowid, record FROM outbound_calls WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![after, limit], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::new();
        let mut bytes = 2;
        for (sequence, record) in rows {
            let call: OutboundCall = serde_json::from_str(&record)?;
            let item = json!({"sequence": sequence, "call": call});
            let size = item.to_string().len() + 1;
            if bytes + size > 900_000 {
                break;
            }
            bytes += size;
            out.push(item);
        }
        Ok(out)
    }
    /// Persists an outbound call before any attempt. A repeat with the same
    /// request returns the stored record.
    fn prepare_call(&self, out: OutboundCall) -> Result<OutboundCall, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM outbound_calls WHERE peer = ?1 AND call_id = ?2",
                params![out.peer_host_id, out.request.call_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old: OutboundCall = serde_json::from_str(&old)?;
            // A repeat keeps its stored citation and deadline.
            let same = |r: &CallRequest| CallRequest {
                grant_id: None,
                policy: None,
                self_access: None,
                deadline: String::new(),
                ..r.clone()
            };
            if same(&old.request) != same(&out.request) {
                return Err(Error::Conflict(
                    "call ID reused with different fields".into(),
                ));
            }
            return Ok(old);
        }
        tx.execute(
            "INSERT INTO outbound_calls VALUES (?1, ?2, ?3)",
            params![
                out.peer_host_id,
                out.request.call_id,
                serde_json::to_string(&out)?
            ],
        )?;
        append_event(&tx, "call.submitted", &subject(&out), &now())?;
        tx.commit()?;
        Ok(out)
    }
    /// Stores a submission attempt's outcome; an accepted call never
    /// becomes unknown again.
    fn finish_call_submit(&self, out: OutboundCall) -> Result<OutboundCall, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut current = stored(&tx, &out.peer_host_id, &out.request.call_id)?;
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
            current.status = Some(status);
        }
        if out.result.is_some() {
            current.result = out.result;
        }
        save(&tx, &current)?;
        if changed {
            append_event(&tx, "call.updated", &subject(&current), &now())?;
        }
        tx.commit()?;
        Ok(current)
    }
    /// Stores a polled status, and its result once final.
    fn store_call_status(
        &self,
        peer: &str,
        id: &str,
        status: Option<CallStatus>,
        result: Option<Value>,
        cancel_sent: bool,
    ) -> Result<OutboundCall, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut out = stored(&tx, peer, id)?;
        let Some(status) = status.filter(|_| !out.final_state()) else {
            if cancel_sent {
                out.cancel_state = Some("sent".into());
                save(&tx, &out)?;
                tx.commit()?;
            }
            return Ok(out);
        };
        let changed = out.status.as_ref().map(|s| &s.state) != Some(&status.state);
        if is_final(&status.state) {
            out.result = result;
        }
        out.status = Some(status);
        if cancel_sent {
            out.cancel_state = Some("sent".into());
        }
        save(&tx, &out)?;
        if changed {
            append_event(&tx, "call.updated", &subject(&out), &now())?;
        }
        tx.commit()?;
        Ok(out)
    }
    /// Marks a cancellation to send, unless the call was refused or is
    /// final.
    fn request_call_cancel(&self, peer: &str, id: &str) -> Result<OutboundCall, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut out = stored(&tx, peer, id)?;
        if out.submit_state == "rejected" || out.final_state() || out.cancel_state.is_some() {
            return Ok(out);
        }
        out.cancel_state = Some("unknown".into());
        save(&tx, &out)?;
        tx.commit()?;
        Ok(out)
    }
    pub(crate) fn due_call_retries(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<(String, String)>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT record FROM outbound_calls WHERE json_extract(record, '$.submit_state') = 'unknown'",
        )?;
        let mut due = Vec::new();
        for record in statement.query_map([], |r| r.get::<_, String>(0))? {
            let out: OutboundCall = serde_json::from_str(&record?)?;
            if let Some(at) = due_at(&out.next_attempt_at).filter(|at| *at <= now) {
                due.push((at, out.peer_host_id, out.request.call_id));
            }
        }
        due.sort();
        Ok(due.into_iter().map(|(_, p, i)| (p, i)).collect())
    }
    pub(crate) fn pollable_calls(&self) -> Result<Vec<(String, String)>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT record FROM outbound_calls WHERE json_extract(record, '$.submit_state') = 'accepted' ORDER BY rowid",
        )?;
        let mut out = Vec::new();
        for record in statement.query_map([], |r| r.get::<_, String>(0))? {
            let call: OutboundCall = serde_json::from_str(&record?)?;
            if call.pollable() {
                out.push((call.peer_host_id, call.request.call_id));
            }
        }
        Ok(out)
    }
    /// This host's bound person in a network.
    fn person_in(&self, network: &str) -> Result<Option<String>, Error> {
        let conn = self.connection()?;
        Ok(self
            .own_members(&conn)?
            .into_iter()
            .find(|(n, _)| n == network)
            .and_then(|(_, m)| m.person_id))
    }
    /// The end of a stored policy, which caps a default deadline.
    fn policy_end(&self, network: &str, person: &str) -> Result<Option<DateTime<Utc>>, Error> {
        let conn = self.connection()?;
        let Some(key) = self.person_key(&conn, network, person)? else {
            return Ok(None);
        };
        Ok(self
            .stored_policy(&conn, network, &key)?
            .and_then(|p| crate::membership::time(&p.valid_until).ok()))
    }
}

async fn peer_request(
    store: &Arc<Store>,
    peer: &str,
    method: &'static str,
    path: String,
    body: Vec<u8>,
    bound: Duration,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let peer_id = peer.to_owned();
    let target = blocking(store.clone(), move |s| s.dial_target(&peer_id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tokio::time::timeout(
        bound,
        crate::quic::request(store.clone(), &target, method, &path, &body),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))?
}

/// Fetches `GET /peer/v1/tools` from each host, 8 at a time, 5 seconds
/// each. Returns each host's entries, or why it did not answer.
async fn listings(
    store: &Arc<Store>,
    hosts: Vec<String>,
    network: Option<&str>,
) -> Vec<(String, Result<Vec<Value>, String>)> {
    // Network IDs are `net_` and hex, safe in a query.
    let path = match network {
        Some(n) => format!("/peer/v1/tools?network={n}"),
        None => "/peer/v1/tools".to_owned(),
    };
    let semaphore = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut set = tokio::task::JoinSet::new();
    for (index, host) in hosts.into_iter().enumerate() {
        let (store, semaphore, path) = (store.clone(), semaphore.clone(), path.clone());
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            let outcome =
                match peer_request(&store, &host, "GET", path, Vec::new(), LISTING_BOUND).await {
                    Ok((200, body)) => serde_json::from_slice::<Vec<Value>>(&body)
                        .map_err(|_| "invalid tool listing".to_owned()),
                    Ok((code, _)) => Err(format!("peer returned HTTP {code}")),
                    Err(e) => Err(format!("{e:#}")),
                };
            (index, host, outcome)
        });
    }
    let mut out = Vec::new();
    while let Some(Ok(item)) = set.join_next().await {
        out.push(item);
    }
    out.sort_by_key(|(i, _, _)| *i);
    out.into_iter().map(|(_, h, o)| (h, o)).collect()
}

fn entry_matches(
    entry: &Value,
    agent: Option<&str>,
    server: Option<&str>,
    profile: Option<&Option<String>>,
) -> bool {
    agent.is_none_or(|a| entry["agent"].as_str() == Some(a))
        && server.is_none_or(|s| entry["server"].as_str() == Some(s))
        && profile.is_none_or(|p| entry["profile"].as_str() == p.as_deref())
}

/// `GET /v1/remote-tools`: what this host may call on each matching host.
async fn remote_tools(
    store: Arc<Store>,
    target: Option<String>,
    network: Option<String>,
) -> Result<Value, Error> {
    let (owner, agent) = match target.as_deref().filter(|t| !t.is_empty()) {
        None => (None, None),
        Some(t) => match t.rsplit_once('/') {
            Some((owner, agent)) if !owner.is_empty() && !agent.is_empty() => {
                (Some(owner.to_owned()), Some(agent.to_owned()))
            }
            _ => (Some(t.to_owned()), None),
        },
    };
    let n = network.clone();
    let hosts = blocking(store.clone(), move |s| match &owner {
        Some(owner) => s.owner_hosts(owner, n.as_deref()),
        None => s.all_hosts(n.as_deref()),
    })
    .await?;
    let mut tools = Vec::new();
    let mut unanswered = Vec::new();
    for (host, outcome) in listings(&store, hosts, network.as_deref()).await {
        match outcome {
            Ok(entries) => {
                for mut e in entries {
                    if entry_matches(&e, agent.as_deref(), None, None) {
                        e["host_id"] = json!(host);
                        tools.push(e);
                    }
                }
            }
            Err(error) => unanswered.push(json!({"host_id": host, "error": error})),
        }
    }
    Ok(json!({"tools": tools, "unanswered": unanswered}))
}

/// Resolves a target to exactly one host and its listing entry.
async fn resolve(
    store: &Arc<Store>,
    t: &Target,
    network: Option<&str>,
) -> Result<(String, Value), Error> {
    let (owner, n) = (t.owner.clone(), network.map(str::to_owned));
    let hosts = blocking(store.clone(), move |s| s.owner_hosts(&owner, n.as_deref())).await?;
    let mut matches = Vec::new();
    let mut unanswered = Vec::new();
    for (host, outcome) in listings(store, hosts, network).await {
        match outcome {
            Ok(entries) => {
                if let Some(e) = entries
                    .into_iter()
                    .find(|e| entry_matches(e, Some(&t.agent), Some(&t.server), Some(&t.profile)))
                {
                    matches.push((host, e));
                }
            }
            Err(error) => unanswered.push(format!("{host} ({error})")),
        }
    }
    let label = match &t.profile {
        Some(p) => format!("{}@{p}", t.server),
        None => t.server.clone(),
    };
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(Error::Coded {
            status: 404,
            code: "not_found",
            message: if unanswered.is_empty() {
                format!("no host lists {}/{label} for this host", t.agent)
            } else {
                format!(
                    "no host lists {}/{label} for this host; these hosts did not answer: {}",
                    t.agent,
                    unanswered.join(", ")
                )
            },
            extra: [("unanswered".to_owned(), json!(unanswered))]
                .into_iter()
                .collect(),
        }),
        _ => {
            let forms: Vec<String> = matches
                .iter()
                .map(|(h, _)| format!("{h}/{}/{label}", t.agent))
                .collect();
            Err(Error::Coded {
                status: 409,
                code: "ambiguous",
                message: format!(
                    "the target matches several hosts; use one of: {}",
                    forms.join(", ")
                ),
                extra: [("candidates".to_owned(), json!(forms))]
                    .into_iter()
                    .collect(),
            })
        }
    }
}

/// `POST /v1/calls`: resolves the target, cites what its listing reported,
/// persists the call, and submits it.
async fn create_call(store: Arc<Store>, r: SubmitCall) -> Result<OutboundCall, Error> {
    let tool = match r.kind.as_str() {
        "tool" => true,
        "resource" => false,
        _ => return Err(Error::Invalid("kind is tool or resource".into())),
    };
    let (name, uri, arguments) = if tool {
        let name = r
            .name
            .filter(|n| !n.is_empty())
            .ok_or_else(|| Error::Invalid("a tool call names the tool".into()))?;
        let arguments = r.arguments.unwrap_or_else(|| json!({}));
        if !arguments.is_object() || r.uri.is_some() {
            return Err(Error::Invalid("tool arguments are a JSON object".into()));
        }
        (Some(name), None, Some(arguments))
    } else {
        let uri = r
            .uri
            .filter(|u| !u.is_empty())
            .ok_or_else(|| Error::Invalid("a read names the URI".into()))?;
        if r.name.is_some() || r.arguments.is_some() {
            return Err(Error::Invalid("a read takes only a URI".into()));
        }
        (None, Some(uri), None)
    };
    if let Some(id) = &r.call_id
        && !call_id_shape(id)
    {
        return Err(Error::Invalid("invalid call ID".into()));
    }
    let target = parse_target(&r.target)?;
    let (peer, entry) = resolve(&store, &target, r.network.as_deref()).await?;
    let wanted = name.as_deref().or(uri.as_deref()).unwrap_or_default();
    let listed = if tool {
        entry["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|t| t["name"].as_str() == Some(wanted))
    } else {
        entry["resources"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|x| x["uri"].as_str() == Some(wanted))
    };
    let Some(listed) = listed else {
        return Err(Error::Invalid(format!(
            "{} does not list {wanted} for this host",
            r.target
        )));
    };
    let via: Vec<&Value> = listed["via"].as_array().into_iter().flatten().collect();
    let chosen = match &r.network {
        Some(network) => via
            .iter()
            .find(|v| v["network_id"].as_str() == Some(network.as_str()))
            .ok_or_else(|| {
                Error::Invalid(format!("nothing in network {network} authorizes this call"))
            })?,
        None => via
            .first()
            .ok_or_else(|| Error::Invalid("the listing gives no authorization".into()))?,
    };
    let network_id = chosen["network_id"].as_str().map(str::to_owned);
    let (policy, self_access) = match chosen["kind"].as_str() {
        Some("policy") => (
            Some(PolicyRef {
                person_id: chosen["person_id"].as_str().unwrap_or_default().to_owned(),
                version: chosen["version"].as_u64().unwrap_or(0),
            }),
            None,
        ),
        Some("self") => {
            let n = network_id.clone().unwrap_or_default();
            let person = blocking(store.clone(), move |s| s.person_in(&n))
                .await?
                .ok_or_else(|| Error::Invalid("this host has no person for self access".into()))?;
            (None, Some(SelfRef { person_id: person }))
        }
        _ => {
            return Err(Error::Invalid(
                "the listing gives no usable authorization".into(),
            ));
        }
    };
    let at = Utc::now();
    let deadline = match r.deadline.filter(|d| !d.is_empty()) {
        Some(d) => d,
        None => {
            let mut end = at + MAX_DEADLINE;
            if let (Some(p), Some(n)) = (&policy, &network_id) {
                let (n, person) = (n.clone(), p.person_id.clone());
                if let Some(until) =
                    blocking(store.clone(), move |s| s.policy_end(&n, &person)).await?
                {
                    end = end.min(until);
                }
            }
            rfc3339(end)
        }
    };
    let request = CallRequest {
        call_id: match r.call_id {
            Some(id) => id,
            None => new_id("call")?,
        },
        target_agent_id: entry["agent_id"].as_str().unwrap_or_default().to_owned(),
        server: target.server.clone(),
        profile: target.profile.clone(),
        kind: r.kind.clone(),
        name,
        uri,
        arguments,
        deadline,
        origin: None,
        grant_id: None,
        policy,
        self_access,
    };
    if !valid_id(&request.target_agent_id, "agent", 16) {
        return Err(Error::Invalid("the listing names no valid agent ID".into()));
    }
    let out = OutboundCall {
        peer_host_id: peer,
        request,
        submit_state: "unknown".into(),
        status: None,
        result: None,
        cancel_state: None,
        attempts: 0,
        next_attempt_at: Some(rfc3339(Utc::now() + crate::retry::PREPARE_GUARD)),
        error: None,
        status_queries: 0,
        network_id,
        target: r.target,
    };
    let out = blocking(store.clone(), move |s| s.prepare_call(out)).await?;
    let status_only = crate::retry::receipt_only(&out, Utc::now());
    submit(store, out, status_only).await
}

/// Fetches the remote status, with the result once final.
async fn fetch_status(
    store: &Arc<Store>,
    out: &OutboundCall,
) -> anyhow::Result<(CallStatus, Option<Value>)> {
    let path = format!("/peer/v1/calls/{}", out.request.call_id);
    match peer_request(
        store,
        &out.peer_host_id,
        "GET",
        path,
        Vec::new(),
        REQUEST_BOUND,
    )
    .await?
    {
        (200, body) => {
            let mut value: Value = serde_json::from_slice(&body)?;
            let result = value.as_object_mut().and_then(|o| o.remove("result"));
            let status: CallStatus = serde_json::from_value(value)?;
            if !valid_status(store, out, &status) {
                anyhow::bail!("invalid peer call status");
            }
            Ok((status, result))
        }
        (code, _) => anyhow::bail!("peer returned HTTP {code}"),
    }
}

/// One submission attempt; after the deadline, only a status query.
pub(crate) async fn submit(
    store: Arc<Store>,
    mut out: OutboundCall,
    status_only: bool,
) -> Result<OutboundCall, Error> {
    if out.submit_state != "unknown" {
        return Ok(out);
    }
    let result: anyhow::Result<(CallStatus, Option<Value>)> = if status_only {
        fetch_status(&store, &out).await
    } else {
        let body = serde_json::to_vec(&out.request).map_err(Error::from)?;
        match peer_request(
            &store,
            &out.peer_host_id,
            "POST",
            "/peer/v1/calls".into(),
            body,
            REQUEST_BOUND,
        )
        .await
        {
            Ok((200, body)) => match serde_json::from_slice::<CallStatus>(&body) {
                Ok(status) if valid_status(&store, &out, &status) => Ok((status, None)),
                _ => Err(anyhow::anyhow!("invalid peer call status")),
            },
            Ok((code, body)) => {
                // A refusal that cannot change is final; anything else,
                // such as 503, stays unknown and is retried.
                if matches!(code, 400 | 403 | 404 | 409 | 413 | 429) {
                    out.submit_state = "rejected".into();
                }
                let message = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_owned))
                    .unwrap_or_default();
                Err(anyhow::anyhow!("peer returned HTTP {code}: {message}"))
            }
            Err(e) => Err(e),
        }
    };
    out.error = None;
    match result {
        Ok((status, result)) => {
            out.submit_state = "accepted".into();
            if is_final(&status.state) {
                out.result = result;
            }
            out.status = Some(status);
        }
        Err(e) => out.error = Some(format!("{e:#}")),
    }
    crate::retry::schedule(&mut out, status_only, Utc::now(), crate::retry::jitter());
    blocking(store, move |s| s.finish_call_submit(out)).await
}

/// Sends a pending cancellation; an uncertain result is resent by polling.
async fn send_cancel(store: &Arc<Store>, out: OutboundCall) -> Result<OutboundCall, Error> {
    let path = format!("/peer/v1/calls/{}/cancel", out.request.call_id);
    let response = peer_request(
        store,
        &out.peer_host_id,
        "POST",
        path,
        b"{}".to_vec(),
        REQUEST_BOUND,
    )
    .await;
    if let Ok((200, body)) = response
        && let Ok(status) = serde_json::from_slice::<CallStatus>(&body)
        && valid_status(store, &out, &status)
    {
        let (peer, id) = (out.peer_host_id.clone(), out.request.call_id.clone());
        // A status with a result is stored by the next poll, which fetches
        // the result too.
        let status = (!matches!(status.state.as_str(), "succeeded" | "failed")).then_some(status);
        let out = blocking(store.clone(), move |s| {
            s.store_call_status(&peer, &id, status, None, true)
        })
        .await?;
        return Ok(out);
    }
    Ok(out)
}

/// One poll: resends a pending cancellation, then fetches the status.
/// Returns whether anything changed.
pub(crate) async fn poll(store: Arc<Store>, peer: String, id: String) -> anyhow::Result<bool> {
    let (p, i) = (peer.clone(), id.clone());
    let mut out = blocking(store.clone(), move |s| s.outbound_call(&p, &i)).await?;
    if out.submit_state != "accepted" {
        return Ok(false);
    }
    if out.cancel_state.as_deref() == Some("unknown") {
        out = send_cancel(&store, out).await?;
    }
    if out.final_state() {
        return Ok(false);
    }
    let before = out.status.as_ref().map(|s| s.state.clone());
    let (status, result) = fetch_status(&store, &out).await?;
    let changed = before.as_deref() != Some(status.state.as_str());
    blocking(store, move |s| {
        s.store_call_status(&peer, &id, Some(status), result, false)
    })
    .await?;
    Ok(changed)
}
/// A retry of an uncertain submission, when due.
pub(crate) async fn retry(store: Arc<Store>, peer: String, id: String) {
    let Ok(out) = blocking(store.clone(), move |s| s.outbound_call(&peer, &id)).await else {
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
struct Page {
    after: Option<i64>,
    limit: Option<i64>,
}
#[derive(Deserialize)]
struct RemoteQuery {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    network: Option<String>,
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/calls", get(list_route).post(create_route))
        .route("/v1/calls/{peer}/{id}", get(inspect_route))
        .route("/v1/calls/{peer}/{id}/cancel", post(cancel_route))
        .route("/v1/remote-tools", get(remote_route))
}
async fn list_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<Page>, QueryRejection>,
) -> Result<Json<Vec<Value>>, Error> {
    let Query(p) = query.map_err(|_| Error::Invalid("invalid page bounds".into()))?;
    Ok(Json(
        blocking(store, move |s| {
            s.outbound_calls(p.after.unwrap_or(0), p.limit.unwrap_or(100))
        })
        .await?,
    ))
}
async fn create_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<OutboundCall>, Error> {
    let request: SubmitCall = decode(body)?;
    Ok(Json(create_call(store, request).await?))
}
async fn inspect_route(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundCall>, Error> {
    Ok(Json(
        blocking(store, move |s| s.outbound_call(&peer, &id)).await?,
    ))
}
async fn cancel_route(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundCall>, Error> {
    let out = blocking(store.clone(), move |s| s.request_call_cancel(&peer, &id)).await?;
    if out.submit_state == "accepted" && out.cancel_state.as_deref() == Some("unknown") {
        return Ok(Json(send_cancel(&store, out).await?));
    }
    Ok(Json(out))
}
async fn remote_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<RemoteQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid query".into()))?;
    Ok(Json(remote_tools(store, q.target, q.network).await?))
}

/// A peer host ID and call ID.
pub(crate) type CallKey = (String, String);
/// Uncertain call submissions due now, and accepted calls to poll, for the
/// task worker, which shares its 4 slots with them.
pub(crate) fn jobs(store: &Store, now: DateTime<Utc>) -> (Vec<CallKey>, Vec<CallKey>) {
    let due = store.due_call_retries(now).unwrap_or_default();
    let polls = store.pollable_calls().unwrap_or_default();
    (due, polls)
}
