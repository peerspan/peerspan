//! Calls (capabilities contract): the submitting host. The owner CLI
//! names an address, `PERSON/CAPABILITY`, `HOST_ID/CAPABILITY`, or for a
//! source `PERSON/AGENT/SERVER` or `HOST_ID/AGENT/SERVER`; the daemon
//! resolves it through the network map and the peers' capability listings,
//! cites what the listing reported, persists the call, submits it with
//! retries, and polls its status until final. `GET /v1/discover` lists the
//! reachable agents and usable capabilities together.
use crate::{
    api::{blocking, decode},
    calls::{
        CallRequest, CallStatus, MAX_DEADLINE, PolicyCitation, SelfCitation, call_id_shape,
        is_final,
    },
    model::Error,
    peer_store::{read, valid_id},
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
use serde_json::value::RawValue;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// Listings are fetched at most 8 at once, 5 seconds each.
const PARALLEL: usize = 8;
const LISTING_BOUND: Duration = Duration::from_secs(5);
/// Peer requests are bounded like task requests.
const REQUEST_BOUND: Duration = Duration::from_secs(8);

/// `POST /v1/calls`. A null field is treated as absent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitCall {
    pub target: String,
    pub operation: String,
    #[serde(default)]
    pub input: Option<Value>,
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
    pub request: CallRequest,
    /// `unknown`, `accepted`, or `rejected`.
    pub submit_state: String,
    pub status: Option<CallStatus>,
    /// The result exactly as the receiver sent it, so numbers keep their
    /// form.
    pub result: Option<Box<RawValue>>,
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
    /// The adapter credential that made the call, or null for owner calls.
    #[serde(default)]
    pub adapter_id: Option<String>,
}
/// A received result, exactly as sent.
type Received = Option<Box<RawValue>>;

/// The stored form of an outbound record.
pub(crate) fn encode(out: &OutboundCall) -> Result<String, Error> {
    Ok(serde_json::to_string(out)?)
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
    /// Whether the call is final: its status is final with its result, or
    /// its submission was refused.
    pub(crate) fn finished(&self) -> bool {
        self.submit_state == "rejected" || self.final_state()
    }
    fn pollable(&self) -> bool {
        self.submit_state == "accepted"
            && (self.status.as_ref().is_none_or(|s| !is_final(&s.state))
                || self.cancel_state.as_deref() == Some("unknown"))
    }
    fn final_state(&self) -> bool {
        self.status.as_ref().is_some_and(|s| is_final(&s.state))
    }
}

pub(crate) fn stored(conn: &Connection, peer: &str, id: &str) -> Result<OutboundCall, Error> {
    read(
        conn,
        "SELECT record FROM outbound_calls WHERE peer = ?1 AND call_id = ?2",
        params![peer, id],
    )
}
fn save(tx: &Transaction<'_>, out: &OutboundCall) -> Result<(), Error> {
    tx.execute(
        "UPDATE outbound_calls SET record = ?1 WHERE peer = ?2 AND call_id = ?3",
        params![encode(out)?, out.peer_host_id, out.request.call_id],
    )?;
    // An agent's call that has just become final notifies its session.
    crate::agent_calls::notify_final(tx, out)
}
pub(crate) fn subject(out: &OutboundCall) -> String {
    format!("{}/{}", out.peer_host_id, out.request.call_id)
}
fn valid_status(store: &Store, out: &OutboundCall, s: &CallStatus) -> bool {
    s.sender_host_id == store.identity().id
        && s.receiver_host_id == out.peer_host_id
        && s.call_id == out.request.call_id
        && s.capability == out.request.capability
        && crate::calls::STATES.contains(&s.state.as_str())
}

/// A parsed address: who holds it, and the capability name or the source's
/// `AGENT/SERVER`.
pub(crate) struct Address {
    owner: String,
    capability: String,
}
pub(crate) fn parse_address(target: &str) -> Result<Address, Error> {
    let parts: Vec<&str> = target.split('/').collect();
    let invalid = || {
        Error::Invalid(
            "an address is PERSON/CAPABILITY, HOST_ID/CAPABILITY, PERSON/AGENT/SERVER, or HOST_ID/AGENT/SERVER".into(),
        )
    };
    match parts.as_slice() {
        [owner, capability] if !owner.is_empty() && crate::policy::name_shape(capability) => {
            Ok(Address {
                owner: (*owner).to_owned(),
                capability: (*capability).to_owned(),
            })
        }
        [owner, agent, server]
            if !owner.is_empty() && !agent.is_empty() && crate::policy::name_shape(server) =>
        {
            Ok(Address {
                owner: (*owner).to_owned(),
                capability: format!("{agent}/{server}"),
            })
        }
        _ => Err(invalid()),
    }
}
pub(crate) fn not_found(message: String, unanswered: &[(String, String)]) -> Error {
    Error::Coded {
        status: 404,
        code: "not_found",
        message,
        extra: [(
            "unanswered".to_owned(),
            json!(
                unanswered
                    .iter()
                    .map(|(h, e)| json!({"host_id": h, "error": e}))
                    .collect::<Vec<_>>()
            ),
        )]
        .into_iter()
        .collect(),
    }
}

impl Store {
    /// The hosts `owner` names: a known host ID, or the hosts bound to a
    /// person (label or ID) in each network searched.
    pub(crate) fn owner_hosts(
        &self,
        owner: &str,
        network: Option<&str>,
    ) -> Result<Vec<String>, Error> {
        if valid_id(owner, "host", 32) {
            let own = self.identity().id;
            let conn = self.connection()?;
            // A member host of a network shared with this one.
            let member: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM network_members WHERE host_id = ?1 AND host_id != ?2)",
                params![owner, own],
                |r| r.get(0),
            )?;
            if !member {
                return Err(not_found(format!("no member host {owner}"), &[]));
            }
            return Ok(vec![owner.to_owned()]);
        }
        Ok(unique_hosts(&self.person_hosts(Some(owner), network)?))
    }
    /// The (host, network, person) bindings of hosts other than this one
    /// in each network searched: of the person `owner` (label or ID), or of
    /// every person when `owner` is `None`.
    fn person_hosts(
        &self,
        owner: Option<&str>,
        network: Option<&str>,
    ) -> Result<Vec<PersonHost>, Error> {
        let own = self.identity().id;
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
        let mut out = Vec::new();
        for n in &networks {
            let persons = self.stored_persons(&conn, n)?;
            let want = match owner {
                None => None,
                Some(owner) => match crate::admins::resolve_person(&persons, owner) {
                    Ok(p) => Some(p.person_id.clone()),
                    Err(Error::NotFound) => continue,
                    Err(e) => return Err(e),
                },
            };
            found = true;
            for m in self.stored_members(&conn, n)? {
                let Some(person) = m.person_id else { continue };
                if m.host_id == own || want.as_ref().is_some_and(|w| *w != person) {
                    continue;
                }
                let label = persons
                    .iter()
                    .find(|p| p.person_id == person)
                    .map(|p| p.member.clone())
                    .or(m.person_member)
                    .unwrap_or_else(|| person.clone());
                out.push(PersonHost {
                    host: m.host_id,
                    network: n.clone(),
                    person,
                    label,
                });
            }
        }
        if let Some(owner) = owner
            && !found
        {
            return Err(not_found(
                format!("no person {owner:?} in the networks searched"),
                &[],
            ));
        }
        out.sort_by(|a, b| (&a.host, &a.network).cmp(&(&b.host, &b.network)));
        Ok(out)
    }
    /// Who binds capability names, from the networks searched: each
    /// person's capability rules by network, as (name, host).
    fn capability_bindings(&self, network: Option<&str>) -> Result<Bindings, Error> {
        let conn = self.connection()?;
        let mut out = Bindings::default();
        let mut statement = conn.prepare("SELECT id FROM networks ORDER BY id")?;
        let networks: Vec<String> = statement
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        drop(statement);
        for n in networks {
            if network.is_some_and(|x| x != n) {
                continue;
            }
            for p in self.stored_persons(&conn, &n)? {
                if let Some(policy) = self.stored_policy(&conn, &n, &p.person_public_key)? {
                    out.rules.insert(
                        (p.person_id.clone(), n.clone()),
                        policy
                            .capability_rules()
                            .iter()
                            .map(|r| (r.capability.clone(), r.host.clone()))
                            .collect(),
                    );
                }
            }
        }
        Ok(out)
    }
    pub fn outbound_call(&self, peer: &str, id: &str) -> Result<OutboundCall, Error> {
        stored(&*self.connection()?, peer, id)
    }
    pub fn outbound_calls(&self, after: i64, limit: i64) -> Result<Vec<Box<RawValue>>, Error> {
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
            // Serialized directly, so the result keeps its numbers.
            #[derive(Serialize)]
            struct Item {
                sequence: i64,
                call: OutboundCall,
            }
            let item = serde_json::value::to_raw_value(&Item { sequence, call })?;
            let size = item.get().len() + 1;
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
            params![out.peer_host_id, out.request.call_id, encode(&out)?],
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
        result: Received,
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
    pub(crate) fn request_call_cancel(&self, peer: &str, id: &str) -> Result<OutboundCall, Error> {
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
    pub(crate) fn pollable_calls(&self) -> Result<Vec<(String, String, bool)>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT record FROM outbound_calls WHERE json_extract(record, '$.submit_state') = 'accepted' ORDER BY rowid",
        )?;
        let mut out = Vec::new();
        for record in statement.query_map([], |r| r.get::<_, String>(0))? {
            let call: OutboundCall = serde_json::from_str(&record?)?;
            if call.pollable() {
                let agent = call.adapter_id.is_some();
                out.push((call.peer_host_id, call.request.call_id, agent));
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

/// Fetches `GET /peer/v1/capabilities` from each host, 8 at a time, 5
/// seconds each. Returns each host's entries, or why it did not answer.
async fn listings(
    store: &Arc<Store>,
    hosts: Vec<String>,
    network: Option<&str>,
) -> Vec<(String, Result<Vec<Value>, String>)> {
    // Network IDs are `net_` and hex, safe in a query.
    let path = match network {
        Some(n) => format!("/peer/v1/capabilities?network={n}"),
        None => "/peer/v1/capabilities".to_owned(),
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
                        .map_err(|_| "invalid capability listing".to_owned()),
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

/// A host bound to a person in one network, with the person's label. A
/// host may be bound to different persons in different networks.
struct PersonHost {
    host: String,
    network: String,
    person: String,
    label: String,
}

/// Who a listing is for: the owner CLI, or an attached agent's adapter.
#[derive(Clone)]
pub(crate) enum Viewer {
    Owner,
    Agent(String),
}
impl Viewer {
    /// The entry as this viewer may use it: only the `via` entries that
    /// apply, and `None` when none is left. The owner ignores entries for
    /// one agent (`from_agent` not null); an agent keeps capabilities only,
    /// through self or a policy entry for no agent or for itself.
    fn visible(&self, mut entry: Value) -> Option<Value> {
        let applies = |v: &Value| match self {
            Viewer::Owner => v["from_agent"].is_null(),
            Viewer::Agent(agent) => {
                v["kind"] == "self"
                    || (v["kind"] == "policy"
                        && (v["from_agent"].is_null()
                            || v["from_agent"].as_str() == Some(agent.as_str())))
            }
        };
        if matches!(self, Viewer::Agent(_)) && entry["kind"] != "capability" {
            return None;
        }
        let via: Vec<Value> = entry["via"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| applies(v))
            .cloned()
            .collect();
        if via.is_empty() {
            return None;
        }
        entry["via"] = Value::Array(via);
        Some(entry)
    }
    fn filter(&self, entries: Vec<Value>) -> Vec<Value> {
        entries
            .into_iter()
            .filter_map(|e| self.visible(e))
            .collect()
    }
}

/// The distinct hosts of bindings, sorted.
fn unique_hosts(bindings: &[PersonHost]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for b in bindings {
        if !out.contains(&b.host) {
            out.push(b.host.clone());
        }
    }
    out.sort();
    out
}

/// The binding of an entry's host that its via networks choose: the first
/// via network in which the host is bound.
fn entry_binding<'a>(
    bindings: &'a [PersonHost],
    host: &str,
    entry: &Value,
) -> Option<&'a PersonHost> {
    entry["via"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v["network_id"].as_str())
        .find_map(|n| bindings.iter().find(|b| b.host == host && b.network == n))
}

/// The persons' policies' capability rules.
#[derive(Default)]
struct Bindings {
    /// (person ID, network ID) to the policy's (capability, host) pairs.
    rules: BTreeMap<(String, String), Vec<(String, String)>>,
}

/// How discover addresses one listed entry of a person.
struct EntryAddress<'a> {
    /// The binding the entry's via networks choose.
    binding: &'a PersonHost,
    /// Whether the address is `PERSON/CAPABILITY`.
    personal: bool,
    /// Whether the entry is a capability no policy of its person binds,
    /// which that person has on more than one host.
    unsettled: bool,
}

/// For each listed entry, the person it is addressed under, by its host's
/// binding to any person in the entry's via networks, the first such
/// network deciding (`None` when there is none, or when that binding is
/// not among `wanted`, the searched person's bindings), and whether it is `PERSON/CAPABILITY`:
/// for a capability, when that person's policy for the entry's network
/// binds the name to that host, or when none of the person's policies
/// binds the name and the person has it on only one host; for a source,
/// when the person has it on only one host.
fn entry_addresses<'a>(
    found: &[(String, Vec<Value>)],
    hosts: &'a [PersonHost],
    wanted: &[PersonHost],
    bindings: &Bindings,
) -> Vec<Vec<Option<EntryAddress<'a>>>> {
    let name = |e: &Value| e["capability"].as_str().unwrap_or_default().to_owned();
    let mut count: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (host, entries) in found {
        for e in entries {
            if let Some(b) = entry_binding(hosts, host, e) {
                *count.entry((b.person.clone(), name(e))).or_default() += 1;
            }
        }
    }
    found
        .iter()
        .map(|(host, entries)| {
            entries
                .iter()
                .map(|e| {
                    let binding = entry_binding(hosts, host, e)?;
                    if !wanted
                        .iter()
                        .any(|w| w.host == binding.host && w.network == binding.network)
                    {
                        return None;
                    }
                    let name = name(e);
                    let only = count.get(&(binding.person.clone(), name.clone())) == Some(&1);
                    // A person whose label contains `/` is never used as
                    // PERSON in an address.
                    let nameable = !binding.label.contains('/');
                    if e["kind"] == "source" {
                        return Some(EntryAddress {
                            binding,
                            personal: nameable && only,
                            unsettled: false,
                        });
                    }
                    let networks: Vec<&str> = e["via"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|v| v["network_id"].as_str())
                        .collect();
                    let mut here = false;
                    let mut bound = false;
                    for ((p, network), rules) in &bindings.rules {
                        if *p != binding.person {
                            continue;
                        }
                        for (capability, h) in rules {
                            if *capability == name {
                                bound = true;
                                here |= h == host && networks.contains(&network.as_str());
                            }
                        }
                    }
                    Some(EntryAddress {
                        binding,
                        personal: nameable && (here || (!bound && only)),
                        unsettled: nameable && !bound && !only,
                    })
                })
                .collect()
        })
        .collect()
}

/// Each host's capability entries reached in a network binding the host
/// to a person, with their addresses: `PERSON/NAME` as `entry_addresses`
/// decides, otherwise `HOST_ID/NAME`.
fn addressed(
    found: Vec<(String, Vec<Value>)>,
    hosts: &[PersonHost],
    wanted: &[PersonHost],
    bindings: &Bindings,
) -> Vec<Value> {
    let addresses = entry_addresses(&found, hosts, wanted, bindings);
    let mut out = Vec::new();
    for ((host, entries), addresses) in found.iter().zip(addresses) {
        for (e, a) in entries.iter().zip(addresses) {
            let Some(a) = a else { continue };
            let name = e["capability"].as_str().unwrap_or_default();
            let address = if a.personal {
                format!("{}/{name}", a.binding.label)
            } else {
                format!("{host}/{name}")
            };
            out.push(json!({
                "address": address,
                "host_id": host,
                "kind": e["kind"],
                "capability": e["capability"],
                "operations": e["operations"],
                "resources": e["resources"],
                "state": e["state"],
                "unavailable": e["unavailable"],
                "via": e["via"],
            }));
        }
    }
    out
}

/// The `reachable` agents of the directory, as `agents --json` shows them.
async fn reachable_agents(
    store: &Arc<Store>,
    person: Option<&str>,
    network: Option<&str>,
) -> Result<Vec<Value>, Error> {
    let networks: Vec<String> = blocking(store.clone(), |s| s.networks())
        .await?
        .into_iter()
        .map(|n| n.id)
        .filter(|n| network.is_none_or(|x| x == n))
        .collect();
    let mut out: Vec<Value> = Vec::new();
    for n in networks {
        let id = n.clone();
        let view = blocking(store.clone(), move |s| s.directory_view(Some(id))).await?;
        let members = blocking(store.clone(), move |s| s.members(&n)).await?;
        let states: BTreeMap<String, String> = view["hosts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|h| {
                Some((
                    h["host_id"].as_str()?.to_owned(),
                    h["state"].as_str()?.to_owned(),
                ))
            })
            .collect();
        for a in view["agents"].as_array().into_iter().flatten() {
            if a["address"].is_null() {
                continue;
            }
            if let Some(p) = person
                && a["person_id"].as_str() != Some(p)
                && !a["person_label"]
                    .as_str()
                    .is_some_and(|l| crate::network::labels_conflict(l, p))
                && a["host_id"].as_str() != Some(p)
            {
                continue;
            }
            let host = a["host_id"].as_str().unwrap_or_default().to_owned();
            if out
                .iter()
                .any(|x| x["host_id"] == a["host_id"] && x["agent_id"] == a["agent_id"])
            {
                continue;
            }
            let mut actions = std::collections::BTreeSet::new();
            for auth in a["authorizations"].as_array().into_iter().flatten() {
                for action in auth["actions"].as_array().into_iter().flatten() {
                    if let Some(action) = action.as_str() {
                        actions.insert(action.to_owned());
                    }
                }
            }
            let actions: Vec<&str> = crate::policy::ACTIONS
                .iter()
                .copied()
                .filter(|x| actions.contains(*x))
                .collect();
            let map = crate::directory::map_address(&members, &host);
            out.push(json!({
                "address": a["address"],
                "host_id": host,
                "agent_id": a["agent_id"],
                "connected": a["connected"],
                "host_state": states.get(&host).cloned().unwrap_or_else(|| "pending".into()),
                "actions": actions,
                "endpoint": crate::directory::endpoint(store, &host, map),
            }));
        }
    }
    out.sort_by(|a, b| {
        (a["address"].as_str(), a["host_id"].as_str())
            .cmp(&(b["address"].as_str(), b["host_id"].as_str()))
    });
    Ok(out)
}

/// `GET /v1/discover`: reachable agents and usable capabilities together.
async fn discover(
    store: Arc<Store>,
    person: Option<String>,
    network: Option<String>,
) -> Result<Value, Error> {
    let person = person.filter(|p| !p.is_empty());
    let (p, n) = (person.clone(), network.clone());
    let persons = blocking(store.clone(), move |s| {
        s.person_hosts(p.as_deref(), n.as_deref())
    })
    .await?;
    let hosts = unique_hosts(&persons);
    // Whose an entry is depends on every person's bindings, not only the
    // searched person's.
    let n = network.clone();
    let all = blocking(store.clone(), move |s| s.person_hosts(None, n.as_deref())).await?;
    let n = network.clone();
    let bindings = blocking(store.clone(), move |s| s.capability_bindings(n.as_deref())).await?;
    let mut found = Vec::new();
    let mut unanswered = Vec::new();
    for (host, outcome) in listings(&store, hosts, network.as_deref()).await {
        match outcome {
            Ok(entries) => found.push((host, Viewer::Owner.filter(entries))),
            Err(error) => unanswered.push(json!({"host_id": host, "error": error})),
        }
    }
    let agents = reachable_agents(&store, person.as_deref(), network.as_deref()).await?;
    Ok(json!({
        "agents": agents,
        "capabilities": addressed(found, &all, &persons, &bindings),
        "unanswered": unanswered,
    }))
}

/// `GET /adapter/v1/capabilities`: the capabilities an agent may call, from
/// every host bound to a person in this host's networks, addressed as
/// `discover` addresses them, sorted by address and then host ID; and the
/// hosts that did not answer.
pub(crate) async fn agent_capabilities(
    store: &Arc<Store>,
    agent: &str,
) -> Result<(Vec<Value>, Vec<Value>), Error> {
    let persons = blocking(store.clone(), |s| s.person_hosts(None, None)).await?;
    let hosts = unique_hosts(&persons);
    let bindings = blocking(store.clone(), |s| s.capability_bindings(None)).await?;
    let viewer = Viewer::Agent(agent.to_owned());
    let mut found = Vec::new();
    let mut unanswered = Vec::new();
    for (host, outcome) in listings(store, hosts, None).await {
        match outcome {
            Ok(entries) => found.push((host, viewer.filter(entries))),
            Err(error) => unanswered.push(json!({"host_id": host, "error": error})),
        }
    }
    let mut entries: Vec<Value> = addressed(found, &persons, &persons, &bindings)
        .into_iter()
        .map(|e| {
            json!({
                "address": e["address"],
                "host_id": e["host_id"],
                "capability": e["capability"],
                "operations": e["operations"],
                "resources": e["resources"],
                "state": e["state"],
                "unavailable": e["unavailable"],
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        (a["address"].as_str(), a["host_id"].as_str())
            .cmp(&(b["address"].as_str(), b["host_id"].as_str()))
    });
    Ok((entries, unanswered))
}

/// Resolves an address to exactly one host and its listing entry.
pub(crate) async fn resolve(
    store: &Arc<Store>,
    a: &Address,
    network: Option<&str>,
    viewer: &Viewer,
) -> Result<(String, Value), Error> {
    let by_host = valid_id(&a.owner, "host", 32);
    let (owner, n) = (a.owner.clone(), network.map(str::to_owned));
    let persons = if by_host {
        Vec::new()
    } else {
        blocking(store.clone(), move |s| {
            s.person_hosts(Some(&owner), n.as_deref())
        })
        .await?
    };
    let hosts = if by_host {
        let (owner, n) = (a.owner.clone(), network.map(str::to_owned));
        blocking(store.clone(), move |s| s.owner_hosts(&owner, n.as_deref())).await?
    } else {
        unique_hosts(&persons)
    };
    let mut found = Vec::new();
    let mut unanswered = Vec::new();
    for (host, outcome) in listings(store, hosts, network).await {
        match outcome {
            Ok(entries) => {
                if let Some(e) = viewer
                    .filter(entries)
                    .into_iter()
                    .find(|e| e["capability"].as_str() == Some(a.capability.as_str()))
                {
                    found.push((host, vec![e]));
                }
            }
            Err(error) => unanswered.push((host, error)),
        }
    }
    // `PERSON/CAPABILITY` matches only entries `discover` addresses that
    // way. With none, the person's copies that no policy settles are the
    // candidates.
    let mut unsettled: Vec<String> = Vec::new();
    let keep: Vec<bool> = if by_host {
        vec![true; found.len()]
    } else {
        let n = network.map(str::to_owned);
        let all = blocking(store.clone(), move |s| s.person_hosts(None, n.as_deref())).await?;
        let n = network.map(str::to_owned);
        let bindings =
            blocking(store.clone(), move |s| s.capability_bindings(n.as_deref())).await?;
        let addresses = entry_addresses(&found, &all, &persons, &bindings);
        for ((host, _), e) in found.iter().zip(&addresses) {
            if e[0].as_ref().is_some_and(|e| e.unsettled) {
                unsettled.push(format!("{host}/{}", a.capability));
            }
        }
        addresses
            .iter()
            .zip(&found)
            .map(|(e, (_, entries))| {
                e[0].as_ref().is_some_and(|e| {
                    e.personal || (entries[0]["kind"] == "source" && !e.binding.label.contains('/'))
                })
            })
            .collect()
    };
    let matches: Vec<(String, Value)> = found
        .into_iter()
        .zip(keep)
        .filter(|(_, k)| *k)
        .map(|((h, mut e), _)| (h, e.remove(0)))
        .collect();
    let mut matches = matches;
    if matches.is_empty() && unsettled.len() > 1 {
        unsettled.sort();
        return Err(ambiguous(unsettled));
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(not_found(
            format!(
                "no host of {} offers {} to this host",
                a.owner, a.capability
            ),
            &unanswered,
        )),
        _ => {
            let mut forms: Vec<String> = matches
                .iter()
                .map(|(h, _)| format!("{h}/{}", a.capability))
                .collect();
            forms.sort();
            Err(ambiguous(forms))
        }
    }
}

/// 409 `ambiguous` with the sorted `HOST_ID/CAPABILITY` candidates.
fn ambiguous(forms: Vec<String>) -> Error {
    Error::Coded {
        status: 409,
        code: "ambiguous",
        message: format!(
            "the address matches several hosts; use one of: {}",
            forms.join(", ")
        ),
        extra: [("candidates".to_owned(), json!(forms))]
            .into_iter()
            .collect(),
    }
}

/// `POST /v1/calls`: resolves the address, cites what its listing
/// reported, persists the call, and submits it.
async fn create_call(store: Arc<Store>, r: SubmitCall) -> Result<OutboundCall, Error> {
    if r.operation.is_empty() {
        return Err(Error::Invalid("give an operation".into()));
    }
    let input = r
        .input
        .filter(|i| !i.is_null())
        .unwrap_or_else(|| json!({}));
    if !input.is_object() {
        return Err(Error::Invalid("the input is a JSON object".into()));
    }
    if let Some(id) = &r.call_id
        && !call_id_shape(id)
    {
        return Err(Error::Invalid("invalid call ID".into()));
    }
    // A given deadline is checked before anything is resolved or persisted.
    if let Some(d) = r.deadline.as_deref().filter(|d| !d.is_empty()) {
        let deadline = crate::membership::time(d)?;
        let now = Utc::now();
        if deadline <= now || deadline > now + MAX_DEADLINE {
            return Err(Error::Invalid(
                "a deadline is in the future and at most 15 minutes away".into(),
            ));
        }
    }
    let address = parse_address(&r.target)?;
    let (peer, entry) = resolve(&store, &address, r.network.as_deref(), &Viewer::Owner).await?;
    let (network_id, policy, self_access) = cite(&store, &entry, r.network.as_deref()).await?;
    let deadline = match r.deadline.filter(|d| !d.is_empty()) {
        Some(d) => d,
        None => rfc3339(default_deadline(&store, policy.as_ref()).await?),
    };
    let request = CallRequest {
        call_id: match r.call_id {
            Some(id) => id,
            None => new_id("call")?,
        },
        capability: address.capability.clone(),
        operation: r.operation,
        input,
        deadline,
        origin: None,
        policy,
        self_access,
    };
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
        network_id: Some(network_id),
        target: r.target,
        adapter_id: None,
    };
    let out = blocking(store.clone(), move |s| s.prepare_call(out)).await?;
    let status_only = crate::retry::receipt_only(&out, Utc::now());
    submit(store, out, status_only).await
}

impl Address {
    pub(crate) fn capability(&self) -> &str {
        &self.capability
    }
}

/// The citation for a resolved listing entry: its first `via` entry, or
/// the first in `network` when given.
pub(crate) async fn cite(
    store: &Arc<Store>,
    entry: &Value,
    network: Option<&str>,
) -> Result<(String, Option<PolicyCitation>, Option<SelfCitation>), Error> {
    let via: Vec<&Value> = entry["via"].as_array().into_iter().flatten().collect();
    let chosen = match network {
        Some(network) => via
            .iter()
            .find(|v| v["network_id"].as_str() == Some(network))
            .ok_or_else(|| {
                Error::Invalid(format!("nothing in network {network} authorizes this call"))
            })?,
        None => via
            .first()
            .ok_or_else(|| Error::Invalid("the listing gives no authorization".into()))?,
    };
    let network_id = chosen["network_id"]
        .as_str()
        .filter(|n| valid_id(n, "net", 32))
        .ok_or_else(|| Error::Invalid("the listing gives no usable authorization".into()))?
        .to_owned();
    let (policy, self_access) = match chosen["kind"].as_str() {
        Some("policy") => (
            Some(PolicyCitation {
                person_id: chosen["person_id"].as_str().unwrap_or_default().to_owned(),
                network_id: network_id.clone(),
                version: chosen["version"].as_u64().unwrap_or(0),
            }),
            None,
        ),
        Some("self") => {
            let n = network_id.clone();
            let person = blocking(store.clone(), move |s| s.person_in(&n))
                .await?
                .ok_or_else(|| Error::Invalid("this host has no person for self access".into()))?;
            (
                None,
                Some(SelfCitation {
                    person_id: person,
                    network_id: network_id.clone(),
                }),
            )
        }
        _ => {
            return Err(Error::Invalid(
                "the listing gives no usable authorization".into(),
            ));
        }
    };
    Ok((network_id, policy, self_access))
}

/// The default deadline: 15 minutes from now, capped by the cited
/// policy's end.
pub(crate) async fn default_deadline(
    store: &Arc<Store>,
    policy: Option<&PolicyCitation>,
) -> Result<DateTime<Utc>, Error> {
    let mut end = Utc::now() + MAX_DEADLINE;
    if let Some(p) = policy {
        let (n, person) = (p.network_id.clone(), p.person_id.clone());
        if let Some(until) = blocking(store.clone(), move |s| s.policy_end(&n, &person)).await? {
            end = end.min(until);
        }
    }
    Ok(end)
}

/// Fetches the remote status, with the result once final.
async fn fetch_status(
    store: &Arc<Store>,
    out: &OutboundCall,
) -> anyhow::Result<(CallStatus, Received)> {
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
            if let Some(object) = value.as_object_mut() {
                object.remove("result");
            }
            let status: CallStatus = serde_json::from_value(value)?;
            if !valid_status(store, out, &status) {
                anyhow::bail!("invalid peer call status");
            }
            // The result exactly as sent; a null result is none.
            #[derive(Deserialize)]
            struct WithResult {
                #[serde(default)]
                result: Option<Box<RawValue>>,
            }
            let result = serde_json::from_slice::<WithResult>(&body)?.result;
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
    let result: anyhow::Result<(CallStatus, Received)> = if status_only {
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
                // An idempotent repeat may already be final; its result
                // comes only from `GET /peer/v1/calls/{id}`.
                Ok(status) if valid_status(&store, &out, &status) && is_final(&status.state) => {
                    Ok(fetch_status(&store, &out).await.unwrap_or((status, None)))
                }
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
            if !is_final(&status.state) {
                out.status = Some(status);
            } else if let Some(result) = result {
                // From a GET: the final status with its result.
                out.result = Some(result);
                out.status = Some(status);
            }
            // A final status without the GET's result stays unset, so
            // polling fetches both.
        }
        Err(e) => out.error = Some(format!("{e:#}")),
    }
    crate::retry::schedule(&mut out, status_only, Utc::now(), crate::retry::jitter());
    blocking(store, move |s| s.finish_call_submit(out)).await
}

/// Sends a pending cancellation; an uncertain result is resent by polling.
pub(crate) async fn send_cancel(
    store: &Arc<Store>,
    out: OutboundCall,
) -> Result<OutboundCall, Error> {
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
struct DiscoverQuery {
    #[serde(default)]
    person: Option<String>,
    #[serde(default)]
    network: Option<String>,
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/calls", get(list_route).post(create_route))
        .route("/v1/calls/{peer}/{id}", get(inspect_route))
        .route("/v1/calls/{peer}/{id}/cancel", post(cancel_route))
        .route("/v1/discover", get(discover_route))
}
async fn list_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<Page>, QueryRejection>,
) -> Result<Json<Vec<Box<RawValue>>>, Error> {
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
async fn discover_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<DiscoverQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid query".into()))?;
    Ok(Json(discover(store, q.person, q.network).await?))
}

/// A peer host ID and call ID.
pub(crate) type CallKey = (String, String);
/// Uncertain call submissions due now, and accepted calls to poll, each
/// with whether an agent made it, for the task worker, which shares its 4
/// slots with them.
pub(crate) fn jobs(store: &Store, now: DateTime<Utc>) -> (Vec<CallKey>, Vec<(CallKey, bool)>) {
    let due = store.due_call_retries(now).unwrap_or_default();
    let polls = store
        .pollable_calls()
        .unwrap_or_default()
        .into_iter()
        .map(|(p, i, agent)| ((p, i), agent))
        .collect();
    (due, polls)
}
