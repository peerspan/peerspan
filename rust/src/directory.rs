//! The agent directory and addressing (launch slice 4). Each daemon asks the
//! other members of its networks which of their agents it may reach and
//! keeps the answers in memory. Owners and directory sessions then address
//! agents as `PERSON/AGENT` or `HOST_ID/AGENT`; names are labels and never
//! authorize anything.
use crate::{
    adapter::Adapter,
    adapter_connection::AdapterAuth,
    api::{blocking, decode},
    model::Error,
    network::Member,
    peer_store::valid_id,
    policy::{ALL_AGENTS, Rule},
    store::{Store, rfc3339},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, Query, State, rejection::BytesRejection},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::Utc;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// Database version 13: adapter sends by address have no route, and each
/// send or delegation by address is counted for its credential's rate cap.
pub(crate) const SCHEMA: &str = "
CREATE TABLE adapter_outbound_v13 (peer TEXT NOT NULL, request_id TEXT NOT NULL, adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), session_id TEXT NOT NULL REFERENCES sessions(id), route_id TEXT REFERENCES adapter_routes(id), next_poll_at INTEGER NOT NULL, reply_delivery TEXT, PRIMARY KEY(peer, request_id), UNIQUE(adapter_id, request_id), FOREIGN KEY(peer, request_id) REFERENCES outbound_messages(peer, request_id));
INSERT INTO adapter_outbound_v13 SELECT peer, request_id, adapter_id, session_id, route_id, next_poll_at, reply_delivery FROM adapter_outbound;
DROP TABLE adapter_outbound;
ALTER TABLE adapter_outbound_v13 RENAME TO adapter_outbound;
CREATE INDEX adapter_outbound_due ON adapter_outbound(next_poll_at);
CREATE INDEX adapter_outbound_route ON adapter_outbound(route_id);
CREATE TABLE directory_sends (adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), kind TEXT NOT NULL CHECK (kind IN ('message', 'task')), peer TEXT NOT NULL, request_id TEXT NOT NULL, sent_at_ms INTEGER NOT NULL, PRIMARY KEY(kind, peer, request_id));
CREATE INDEX directory_sends_adapter ON directory_sends(adapter_id, sent_at_ms);
PRAGMA user_version = 13;
";

/// The channel of the leases of attached sessions where `column` is `id`:
/// `verified` when any is verified, `unverified` when there is a lease, else
/// none.
pub(crate) fn lease_channel(
    conn: &Connection,
    column: &str,
    id: &str,
) -> Result<Option<&'static str>, Error> {
    let mut statement = conn.prepare(&format!(
        "SELECT c.record, x.channel_verified_at IS NOT NULL FROM sessions s JOIN adapter_credentials c ON c.session_id = s.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE {column} = ?1 AND s.state = 'attached' AND x.lease_until_ms > ?2"
    ))?;
    let records = statement
        .query_map(params![id, Utc::now().timestamp_millis()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut channel = None;
    for (record, verified) in records {
        let a: Adapter = serde_json::from_str(&record)?;
        if a.revoked_at.is_none()
            && crate::membership::time(&a.expires_at).is_ok_and(|t| t > Utc::now())
        {
            if verified {
                return Ok(Some("verified"));
            }
            channel = Some("unverified");
        }
    }
    Ok(channel)
}

/// A directory session's default cap on sends and delegations per hour.
pub const DEFAULT_SENDS_PER_HOUR: i64 = 100;
/// Every network is refreshed this often, and sooner after a change.
const REFRESH_EVERY: Duration = Duration::from_secs(300);
/// How often the worker looks for map and policy changes.
const WATCH_EVERY: Duration = Duration::from_secs(2);
/// Each host query's bound, and how many run at once.
const QUERY_BOUND: Duration = Duration::from_secs(5);
const PARALLEL: usize = 8;
/// A synchronous refresh waits at most this long.
const SYNC_WAIT: Duration = Duration::from_secs(10);
/// A synchronous refresh asks a host that answered 403 again this much later.
const FORBIDDEN_RETRY: Duration = Duration::from_secs(2);
/// The rate cap's window.
const HOUR_MS: i64 = 3_600_000;

/// Whether an agent name can be addressed: 1–64 characters of lowercase
/// ASCII letters, digits, `.`, `_`, and `-`, starting with a letter or digit.
pub fn addressable(name: &str) -> bool {
    crate::adapter_outbound::valid_name(name)
}

/// One current authorization of the caller for an agent, as the receiver
/// evaluates requests: `self`, `policy`, or `grant`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Authorization {
    pub kind: String,
    #[serde(default)]
    pub grant_id: Option<String>,
    pub actions: Vec<String>,
    pub max_message_bytes: i64,
    pub max_artifact_bytes: i64,
    /// For policy and grant entries: the caller's agent the entry is limited
    /// to, or null for any.
    #[serde(default)]
    pub from_agent: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}
impl Serialize for Authorization {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut value = json!({
            "kind": self.kind,
            "actions": self.actions,
            "max_message_bytes": self.max_message_bytes,
            "max_artifact_bytes": self.max_artifact_bytes,
        });
        match self.kind.as_str() {
            "policy" => value["from_agent"] = json!(self.from_agent),
            "grant" => {
                value["grant_id"] = json!(self.grant_id);
                value["expires_at"] = json!(self.expires_at);
                value["from_agent"] = json!(self.from_agent);
            }
            _ => {}
        }
        value.serialize(s)
    }
}
impl Authorization {
    fn valid(&self) -> bool {
        let shape = match self.kind.as_str() {
            "self" => true,
            "policy" => true,
            "grant" => {
                self.grant_id
                    .as_deref()
                    .is_some_and(|g| valid_id(g, "grant", 16))
                    && self.expires_at.is_some()
            }
            _ => false,
        };
        shape
            && !self.actions.is_empty()
            && self
                .actions
                .iter()
                .all(|a| crate::policy::ACTIONS.contains(&a.as_str()))
            && self
                .from_agent
                .as_deref()
                .is_none_or(|a| valid_id(a, "agent", 16))
    }
    /// Whether it allows `action` for a request from `origin`.
    fn allows(&self, action: &str, origin: Option<&str>) -> bool {
        self.from_agent
            .as_deref()
            .is_none_or(|from| origin == Some(from))
            && self
                .actions
                .iter()
                .any(|a| crate::policy::allows(a, action))
    }
}

/// One agent the caller may reach, as a receiver lists it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAgent {
    pub name: String,
    pub agent_id: String,
    pub connected: bool,
    pub authorizations: Vec<Authorization>,
    /// `verified` when a verified session holds a lease, `unverified` when
    /// only unverified ones do, else null. `connected` means verified. Hosts
    /// before live delivery omit it.
    #[serde(default)]
    pub channel: Option<String>,
}

/// What a send or task by address cites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    SelfAccess,
    Policy,
    Grant(String),
}

/// A send or task by address: the address as given, and the authorization
/// chosen for it, or none when a grant was given or the request repeats a
/// stored one.
#[derive(Clone, Debug)]
pub struct Addressed {
    pub to: String,
    pub choice: Option<Choice>,
}

/// One host's last answer.
#[derive(Clone, Debug)]
struct HostEntry {
    /// `ok`, `error`, `unsupported`, or `pending`.
    state: &'static str,
    refreshed_at: Option<String>,
    error: Option<String>,
    agents: Vec<PeerAgent>,
}
#[derive(Clone, Debug, Default)]
struct NetworkEntry {
    refreshed_at: Option<String>,
    hosts: BTreeMap<String, HostEntry>,
}
/// The in-memory directory of every network, by network ID.
#[derive(Debug, Default)]
pub struct Cache {
    networks: BTreeMap<String, NetworkEntry>,
}

/// A directory agent, or one of this host's own, that an address may name.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub network_id: String,
    pub host_id: String,
    pub agent_id: String,
    pub name: String,
    pub local: bool,
    person_id: Option<String>,
    label: Option<String>,
    agent: Option<PeerAgent>,
}

pub(crate) fn coded(status: u16, code: &'static str, message: String, extra: Value) -> Error {
    Error::Coded {
        status,
        code,
        message,
        extra: match extra {
            Value::Object(map) => map,
            _ => Default::default(),
        },
    }
}
fn no_directory() -> Error {
    coded(
        403,
        "no_directory",
        "this session's credential has no directory access; use its destinations".into(),
        json!({}),
    )
}
fn not_authorized(to: &str) -> Error {
    coded(
        403,
        "not_authorized",
        format!("no current authorization lets this host reach {to}"),
        json!({}),
    )
}
/// Whether the credential has directory access.
pub(crate) fn directory_access(a: &Adapter) -> Result<(), Error> {
    if a.directory {
        Ok(())
    } else {
        Err(no_directory())
    }
}
/// Refuses a send or delegation by address that would exceed the
/// credential's cap in the preceding 60 minutes.
pub(crate) fn rate_check(conn: &Connection, a: &Adapter) -> Result<(), Error> {
    let cap = a.max_sends_per_hour.unwrap_or(DEFAULT_SENDS_PER_HOUR);
    let now = Utc::now().timestamp_millis();
    let (count, oldest): (i64, Option<i64>) = conn.query_row(
        "SELECT COUNT(*), MIN(sent_at_ms) FROM directory_sends WHERE adapter_id = ?1 AND sent_at_ms > ?2",
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
            "this session made {count} sends and delegations by address in the last hour, its cap; retry after {retry_after} seconds"
        ),
        json!({ "retry_after": retry_after }),
    ))
}
/// Counts a send (`message`) or delegation (`task`) by address when it is
/// first persisted.
pub(crate) fn count_send(
    conn: &Connection,
    adapter: &str,
    kind: &str,
    peer: &str,
    id: &str,
) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO directory_sends VALUES (?1, ?2, ?3, ?4, ?5)",
        params![adapter, kind, peer, id, Utc::now().timestamp_millis()],
    )?;
    Ok(())
}

/// Splits `to` and its optional `network` off a request body. The address
/// replaces the fields in `replaced`; giving both forms is invalid.
pub(crate) fn split_address(
    body: &mut Value,
    replaced: &[&str],
) -> Result<Option<(String, Option<String>)>, Error> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| Error::Invalid("invalid request".into()))?;
    let to = object.remove("to");
    let network = object.remove("network");
    let Some(to) = to else {
        if network.is_some() {
            return Err(Error::Invalid("network is only given with to".into()));
        }
        return Ok(None);
    };
    let Value::String(to) = to else {
        return Err(Error::Invalid("to must be an address".into()));
    };
    let network = match network {
        None => None,
        Some(Value::String(n)) => Some(n),
        Some(_) => return Err(Error::Invalid("network must be a network ID".into())),
    };
    if let Some(field) = replaced.iter().find(|f| object.contains_key(**f)) {
        return Err(Error::Invalid(format!(
            "give either to or {field}, not both"
        )));
    }
    Ok(Some((to, network)))
}

/// Decodes what remains of a request body.
pub(crate) fn body<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, Error> {
    serde_json::from_value(value).map_err(|_| Error::Invalid("invalid request".into()))
}

/// An address's two parts, split at its last `/`.
fn parts(to: &str) -> Result<(&str, &str), Error> {
    match to.rsplit_once('/') {
        Some((first, name)) if !first.is_empty() && !name.is_empty() => Ok((first, name)),
        _ => Err(Error::Invalid(format!(
            "invalid address {to:?}: use PERSON/AGENT or HOST_ID/AGENT"
        ))),
    }
}

impl Store {
    /// An agent in this host's cached directory entries of `host` in
    /// `network`, by name or by agent ID: its ID and name.
    pub(crate) fn cached_directory_agent(
        &self,
        network: &str,
        host: &str,
        by_name: bool,
        value: &str,
    ) -> Option<(String, String)> {
        let cache = self.directory_cache().ok()?;
        let entry = cache.networks.get(network)?.hosts.get(host)?;
        entry
            .agents
            .iter()
            .find(|a| {
                if by_name {
                    a.name == value
                } else {
                    a.agent_id == value
                }
            })
            .map(|a| (a.agent_id.clone(), a.name.clone()))
    }
    pub(crate) fn directory_cache(&self) -> Result<std::sync::MutexGuard<'_, Cache>, Error> {
        self.agent_directory
            .lock()
            .map_err(|_| Error::Internal(anyhow::anyhow!("directory lock poisoned")))
    }

    /// The channel of an agent's attached sessions whose adapters hold a
    /// valid lease: `verified` when any is verified, `unverified` when there
    /// is such a lease, else none.
    pub(crate) fn agent_channel(
        &self,
        conn: &Connection,
        agent: &str,
    ) -> Result<Option<&'static str>, Error> {
        lease_channel(conn, "s.agent_id", agent)
    }

    /// The peer route: this host's agents that `caller`, a current member
    /// of `network`, may reach now, with every current authorization.
    pub fn reachable_agents(&self, caller: &str, network: &str) -> Result<Vec<PeerAgent>, Error> {
        let conn = self.connection()?;
        let known: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id = ?1)",
            [network],
            |r| r.get(0),
        )?;
        if !known {
            return Err(Error::NotFound);
        }
        if caller == self.identity().id || self.product_member(&conn, network, caller)?.is_none() {
            return Err(Error::Forbidden);
        }
        let now = Utc::now();
        let own = self.own_members(&conn)?;
        let persons: BTreeSet<String> = own
            .iter()
            .filter_map(|(_, m)| m.person_id.clone())
            .collect();
        let mut self_access = false;
        for person in &persons {
            self_access |= self.self_bound(&conn, caller, person)?;
        }
        let blocked = self.blocked(&conn, caller)?;
        // The verified, current policy of this host's person in the queried
        // network, with the caller's member record and groups there.
        let mut policies = Vec::new();
        if !blocked {
            for (net, m) in own.iter().filter(|(n, _)| n == network) {
                let Some(person) = &m.person_id else {
                    continue;
                };
                let Some(key) = self.product_person_key(&conn, net, person)? else {
                    continue;
                };
                let Some(policy) = self.product_policy(&conn, net, &key)? else {
                    continue;
                };
                // With this host's unsettled withdrawals applied.

                if !policy.in_window(now) {
                    continue;
                }
                let Some(sender) = self.product_member(&conn, net, caller)? else {
                    continue;
                };
                let groups = self.product_groups(&conn, net)?;
                policies.push((policy, sender, groups));
            }
        }
        let grants: Vec<crate::peer_store::Grant> = if blocked {
            Vec::new()
        } else {
            crate::peer_store::records::<crate::peer_store::Grant>(
                &conn,
                "SELECT record FROM grants ORDER BY id",
            )?
            .into_iter()
            .filter(|g| {
                g.requester_host_id == caller
                    && g.revoked_at.is_none()
                    && crate::membership::time(&g.expires_at).is_ok_and(|t| t > now)
            })
            .collect()
        };
        let agents: Vec<(String, String)> = {
            let mut statement = conn.prepare("SELECT id, name FROM agents ORDER BY name, id")?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        let mut result = Vec::new();
        for (id, name) in agents {
            let mut authorizations = Vec::new();
            if self_access {
                let bounds = crate::policy::SELF_BOUNDS;
                authorizations.push(Authorization {
                    kind: "self".into(),
                    grant_id: None,
                    actions: crate::policy::ACTIONS
                        .iter()
                        .map(|a| a.to_string())
                        .collect(),
                    max_message_bytes: bounds.max_message_bytes,
                    max_artifact_bytes: bounds.max_artifact_bytes,
                    from_agent: None,
                    expires_at: None,
                });
            }
            for (policy, sender, groups) in &policies {
                let named = policy.rules.iter().any(|r| r.agent == name);
                for rule in &policy.rules {
                    let applies = if named {
                        rule.agent == name
                    } else {
                        rule.agent == ALL_AGENTS
                    };
                    if applies {
                        authorizations.extend(rule_entries(rule, sender, groups));
                    }
                }
            }
            for g in grants.iter().filter(|g| g.target_agent_id == id) {
                authorizations.push(Authorization {
                    kind: "grant".into(),
                    grant_id: Some(g.id.clone()),
                    actions: vec![g.action.clone()],
                    max_message_bytes: g.max_message_bytes,
                    max_artifact_bytes: g.max_artifact_bytes,
                    from_agent: g.requester_agent_id.clone(),
                    expires_at: Some(g.expires_at.clone()),
                });
            }
            if authorizations.is_empty() {
                continue;
            }
            let channel = self.agent_channel(&conn, &id)?;
            result.push(PeerAgent {
                connected: channel == Some("verified"),
                channel: channel.map(str::to_owned),
                name,
                agent_id: id,
                authorizations,
            });
        }
        Ok(result)
    }

    /// The network a directory request names, or this host's only network.
    pub(crate) fn directory_network(&self, given: Option<String>) -> Result<String, Error> {
        let networks = self.product_network_names(&*self.connection()?)?;
        match given {
            Some(id) => {
                if networks.iter().any(|n| n.0 == id) {
                    Ok(id)
                } else {
                    Err(Error::NotFound)
                }
            }
            None => match networks.as_slice() {
                [] => Err(Error::Invalid("not a member of any network".into())),
                [one] => Ok(one.0.clone()),
                many => Err(Error::Invalid(format!(
                    "this host is in several networks; choose one: {}",
                    many.iter()
                        .map(|n| format!("{} ({})", n.0, n.1))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))),
            },
        }
    }

    /// The members of a network other than this host.
    fn other_members(&self, conn: &Connection, network: &str) -> Result<Vec<Member>, Error> {
        let own = self.identity().id;
        let mut members: Vec<Member> = self
            .product_members(conn, network)?
            .into_iter()
            .filter(|m| m.host_id != own)
            .collect();
        members.sort_by(|a, b| a.host_id.cmp(&b.host_id));
        Ok(members)
    }

    /// Every candidate an address may name in `networks`: directory agents
    /// and this host's own, each with its displayed address.
    fn candidates(&self, networks: &[String]) -> Result<Vec<(Candidate, Option<String>)>, Error> {
        self.candidates_in(&*self.connection()?, networks)
    }
    fn candidates_in(
        &self,
        conn: &Connection,
        networks: &[String],
    ) -> Result<Vec<(Candidate, Option<String>)>, Error> {
        let own = self.identity().id;
        let local: Vec<(String, String)> = {
            let mut statement = conn.prepare("SELECT id, name FROM agents ORDER BY name, id")?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        let mut result = Vec::new();
        for network in networks {
            let members = self.product_members(conn, network)?;
            let me = members.iter().find(|m| m.host_id == own);
            let mut list = Vec::new();
            for (id, name) in &local {
                list.push(Candidate {
                    network_id: network.clone(),
                    host_id: own.clone(),
                    agent_id: id.clone(),
                    name: name.clone(),
                    local: true,
                    person_id: me.and_then(|m| m.person_id.clone()),
                    label: me.and_then(|m| m.person_member.clone()),
                    agent: None,
                });
            }
            let cache = self.directory_cache()?;
            if let Some(entry) = cache.networks.get(network) {
                for (host, h) in &entry.hosts {
                    let Some(member) = members.iter().find(|m| &m.host_id == host) else {
                        continue;
                    };
                    for agent in &h.agents {
                        list.push(Candidate {
                            network_id: network.clone(),
                            host_id: host.clone(),
                            agent_id: agent.agent_id.clone(),
                            name: agent.name.clone(),
                            local: false,
                            person_id: member.person_id.clone(),
                            label: member.person_member.clone(),
                            agent: Some(agent.clone()),
                        });
                    }
                }
            }
            drop(cache);
            // A name used by more than one agent of a person is shown by
            // host, as is any agent of a host without a person.
            let mut uses: BTreeMap<(String, String), usize> = BTreeMap::new();
            for c in &list {
                if let Some(person) = &c.person_id {
                    *uses.entry((person.clone(), c.name.clone())).or_default() += 1;
                }
            }
            for c in list {
                let address = addressable(&c.name).then(|| match (&c.person_id, &c.label) {
                    (Some(person), Some(label))
                        if uses.get(&(person.clone(), c.name.clone())) == Some(&1) =>
                    {
                        format!("{label}/{}", c.name)
                    }
                    _ => format!("{}/{}", c.host_id, c.name),
                });
                result.push((c, address));
            }
        }
        Ok(result)
    }

    /// The candidates `to` names in `networks`, once per host and agent.
    fn matching(&self, to: &str, networks: &[String]) -> Result<Vec<Candidate>, Error> {
        let (first, name) = parts(to)?;
        let by_host = valid_id(first, "host", 32);
        let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
        let mut found: Vec<Candidate> = Vec::new();
        for (c, _) in self.candidates(networks)? {
            if c.name != name || !addressable(&c.name) {
                continue;
            }
            let hit = if by_host {
                c.host_id == first
            } else {
                c.label
                    .as_deref()
                    .is_some_and(|l| crate::network::labels_conflict(l, first))
            };
            if !hit {
                continue;
            }
            // One agent listed in several networks resolves in the lowest
            // that lists an authorization for it.
            let listed = |c: &Candidate| {
                c.agent
                    .as_ref()
                    .is_some_and(|a| !a.authorizations.is_empty())
            };
            match seen.get(&(c.host_id.clone(), c.agent_id.clone())) {
                Some(&i) => {
                    if !listed(&found[i]) && listed(&c) {
                        found[i] = c;
                    }
                }
                None => {
                    seen.insert((c.host_id.clone(), c.agent_id.clone()), found.len());
                    found.push(c);
                }
            }
        }
        Ok(found)
    }

    /// The networks an address is resolved in.
    fn searched(&self, network: Option<&str>) -> Result<Vec<String>, Error> {
        let all: Vec<String> = self.product_network_ids(&*self.connection()?)?;
        match network {
            Some(id) if all.iter().any(|n| n == id) => Ok(vec![id.to_owned()]),
            Some(id) => Err(Error::Invalid(format!("this host is not in network {id}"))),
            None => Ok(all),
        }
    }

    /// A cached directory agent.
    fn cached_agent(
        &self,
        network: &str,
        host: &str,
        agent: &str,
    ) -> Result<Option<PeerAgent>, Error> {
        Ok(self
            .directory_cache()?
            .networks
            .get(network)
            .and_then(|n| n.hosts.get(host))
            .and_then(|h| h.agents.iter().find(|a| a.agent_id == agent).cloned()))
    }

    /// `GET /v1/directory`: one network's cache.
    pub fn directory_view(&self, network: Option<String>) -> Result<Value, Error> {
        let network = self.directory_network(network)?;
        let members = {
            let conn = self.connection()?;
            self.other_members(&conn, &network)?
        };
        let addresses: BTreeMap<(String, String), Option<String>> = self
            .candidates(std::slice::from_ref(&network))?
            .into_iter()
            .filter(|(c, _)| !c.local)
            .map(|(c, a)| ((c.host_id, c.agent_id), a))
            .collect();
        let cache = self.directory_cache()?;
        let entry = cache.networks.get(&network).cloned().unwrap_or_default();
        drop(cache);
        let mut hosts = Vec::new();
        let mut agents = Vec::new();
        for m in &members {
            let h = entry.hosts.get(&m.host_id);
            hosts.push(json!({
                "host_id": m.host_id,
                "person_id": m.person_id,
                "person_label": m.person_member,
                "state": h.map_or("pending", |h| h.state),
                "refreshed_at": h.and_then(|h| h.refreshed_at.clone()),
                "error": h.and_then(|h| h.error.clone()),
            }));
            for a in h.map(|h| h.agents.as_slice()).unwrap_or_default() {
                let address = addresses
                    .get(&(m.host_id.clone(), a.agent_id.clone()))
                    .cloned()
                    .flatten();
                agents.push((
                    address.clone(),
                    (m.host_id.clone(), a.agent_id.clone()),
                    json!({
                        "address": address,
                        "host_id": m.host_id,
                        "person_id": m.person_id,
                        "person_label": m.person_member,
                        "name": a.name,
                        "agent_id": a.agent_id,
                        "connected": a.connected,
                        "authorizations": a.authorizations,
                        "channel": a.channel,
                    }),
                ));
            }
        }
        // Agents without an address sort last, then by host and agent ID.
        agents.sort_by(|a, b| (a.0.is_none(), &a.0, &a.1).cmp(&(b.0.is_none(), &b.0, &b.1)));
        Ok(json!({
            "network_id": network,
            "refreshed_at": entry.refreshed_at,
            "hosts": hosts,
            "agents": agents.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>(),
        }))
    }

    /// `GET /adapter/v1/agents`: the addressable directory agents a
    /// directory session may reach, with the union of what it may do.
    /// Each entry comes with its host ID and that host's map address, for
    /// the route to add the endpoint.
    pub fn adapter_agents(
        &self,
        auth: &AdapterAuth,
    ) -> Result<Vec<(String, Option<String>, Value)>, Error> {
        let (a, session) = {
            let conn = self.connection()?;
            crate::adapter::authority(&conn, auth)?
        };
        directory_access(&a)?;
        let networks: Vec<String> = self.product_network_ids(&*self.connection()?)?;
        let mut result = Vec::new();
        for (c, address) in self.candidates(&networks)? {
            let (Some(address), Some(agent)) = (address, &c.agent) else {
                continue;
            };
            let mut actions = BTreeSet::new();
            let (mut message, mut artifact) = (0, 0);
            for entry in &agent.authorizations {
                if entry
                    .from_agent
                    .as_deref()
                    .is_some_and(|f| f != session.agent_id)
                {
                    continue;
                }
                actions.extend(entry.actions.iter().cloned());
                message = message.max(entry.max_message_bytes);
                artifact = artifact.max(entry.max_artifact_bytes);
            }
            if actions.is_empty() {
                continue;
            }
            let members = {
                let conn = self.connection()?;
                self.product_members(&conn, &c.network_id)?
            };
            result.push((
                address.clone(),
                c.network_id.clone(),
                c.host_id.clone(),
                map_address(&members, &c.host_id),
                json!({
                    "address": address,
                    "network_id": c.network_id,
                    "connected": agent.connected,
                    "actions": ordered(&actions),
                    "max_message_bytes": message,
                    "max_artifact_bytes": artifact,
                }),
            ));
        }
        result.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        Ok(result
            .into_iter()
            .map(|(_, _, host, address, v)| (host, address, v))
            .collect())
    }

    /// Status item 12: names this host's person uses for more than one
    /// agent, where this host has one of them. Returns `(network, name,
    /// integration)` sorted.
    pub(crate) fn name_conflicts(
        &self,
        conn: &Connection,
    ) -> Result<Vec<(String, String, Option<String>)>, Error> {
        let networks: Vec<String> = self.product_network_ids(conn)?;
        let mut conflicts = BTreeSet::new();
        let candidates = self.candidates_in(conn, &networks)?;
        for (c, _) in candidates
            .iter()
            .filter(|(c, _)| c.local && c.person_id.is_some())
        {
            let duplicate = candidates.iter().any(|(o, _)| {
                !o.local
                    && o.network_id == c.network_id
                    && o.person_id == c.person_id
                    && o.name == c.name
            });
            if duplicate {
                conflicts.insert((c.network_id.clone(), c.name.clone(), c.agent_id.clone()));
            }
        }
        let mut result = Vec::new();
        for (network, name, agent) in conflicts {
            let integration = self
                .sessions_in(conn, &agent)?
                .into_iter()
                .max_by(|a, b| (&a.created_at, &a.id).cmp(&(&b.created_at, &b.id)))
                .map(|s| s.integration);
            result.push((network, name, integration));
        }
        Ok(result)
    }

    /// The fingerprint of what a network's directory depends on locally: its
    /// members, their persons, and its statements, policies included.
    fn directory_fingerprint(&self, network: &str) -> Result<String, Error> {
        let conn = self.connection()?;
        let mut hash = Sha256::new();
        for m in self.other_members(&conn, network)? {
            hash.update(serde_json::to_vec(&(
                &m.host_id,
                &m.public_key,
                &m.person_id,
                &m.person_member,
            ))?);
        }
        let mut statement = conn.prepare(
            "SELECT kind, subject, record FROM network_statements WHERE network_id = ?1 ORDER BY kind, subject",
        )?;
        let rows = statement.query_map([network], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (kind, subject, record) = row?;
            hash.update(kind.as_bytes());
            hash.update(subject.as_bytes());
            hash.update(record.as_bytes());
            hash.update(b"\n");
        }
        Ok(hex::encode(hash.finalize()))
    }
}

/// Actions in the policy order.
fn ordered(actions: &BTreeSet<String>) -> Vec<&'static str> {
    crate::policy::ACTIONS
        .iter()
        .copied()
        .filter(|a| actions.contains(*a))
        .collect()
}

/// A policy rule's entries for the caller: one with a null `from_agent`
/// when a principal other than an agent of the caller matches, and
/// otherwise one per matching `agent:` principal.
fn rule_entries(
    rule: &Rule,
    sender: &Member,
    groups: &[crate::decentralized::product::Group],
) -> Vec<Authorization> {
    let entry = |from_agent: Option<String>| Authorization {
        kind: "policy".into(),
        grant_id: None,
        actions: rule.actions.clone(),
        max_message_bytes: rule.max_message_bytes,
        max_artifact_bytes: rule.max_artifact_bytes,
        from_agent,
        expires_at: None,
    };
    if rule.principals.iter().any(|p| {
        crate::policy::agent_principal(p).is_none()
            && crate::decentralized::product::principal_matches(p, sender, groups, None)
    }) {
        return vec![entry(None)];
    }
    let mut agents = BTreeSet::new();
    for p in &rule.principals {
        if let Some((host, agent)) = crate::policy::agent_principal(p)
            && host == sender.host_id
        {
            agents.insert(agent.to_owned());
        }
    }
    agents.into_iter().map(|a| entry(Some(a))).collect()
}

/// The first authorization that allows `action` for `origin`: self access,
/// then a policy entry, then the grant with the latest expiry.
pub(crate) fn choose(agent: &PeerAgent, action: &str, origin: Option<&str>) -> Option<Choice> {
    let usable: Vec<&Authorization> = agent
        .authorizations
        .iter()
        .filter(|a| a.allows(action, origin))
        .collect();
    if usable.iter().any(|a| a.kind == "self") {
        return Some(Choice::SelfAccess);
    }
    if usable.iter().any(|a| a.kind == "policy") {
        return Some(Choice::Policy);
    }
    usable
        .iter()
        .filter(|a| a.kind == "grant")
        .filter_map(|a| {
            let at = crate::membership::time(a.expires_at.as_deref()?).ok()?;
            Some((at, a.grant_id.clone()?))
        })
        .max()
        .map(|(_, id)| Choice::Grant(id))
}

/// The outcome of one host query.
enum Outcome {
    Agents(Vec<PeerAgent>),
    Unsupported,
    /// HTTP 403: the host does not know this one yet, for example right
    /// after a join it has not synced.
    Forbidden,
    /// The host refused this host's TLS authentication: it does not know
    /// this host yet either.
    Unauthenticated(String),
    Failed(String),
}

async fn query(store: Arc<Store>, network: String, host: String) -> Outcome {
    let lookup = host.clone();
    let peer = match blocking(store.clone(), move |s| s.dial_target(&lookup)).await {
        Ok(peer) => peer,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let path = format!("/peer/v1/networks/{network}/agents");
    let response = tokio::time::timeout(
        QUERY_BOUND,
        crate::quic::request(store, &peer, "GET", &path, b""),
    )
    .await;
    match response {
        Ok(Ok((200, body))) => match serde_json::from_slice::<Vec<PeerAgent>>(&body) {
            Ok(mut agents)
                if agents.iter().all(|a| {
                    valid_id(&a.agent_id, "agent", 16)
                        && !a.name.is_empty()
                        && a.name.len() <= 128
                        && a.authorizations.iter().all(Authorization::valid)
                }) =>
            {
                for a in &mut agents {
                    if !matches!(a.channel.as_deref(), Some("verified" | "unverified")) {
                        a.channel = None;
                    }
                }
                Outcome::Agents(agents)
            }
            _ => Outcome::Failed("invalid directory response".into()),
        },
        Ok(Ok((404, _))) => Outcome::Unsupported,
        Ok(Ok((403, _))) => Outcome::Forbidden,
        Ok(Ok((status, _))) => Outcome::Failed(format!("peer returned HTTP {status}")),
        Ok(Err(e)) if crate::quic::unauthenticated(&e) => {
            Outcome::Unauthenticated(format!("{e:#}"))
        }
        Ok(Err(e)) => Outcome::Failed(format!("{e:#}")),
        Err(_) => Outcome::Failed("directory query timed out".into()),
    }
}

/// Drops the query locks of hosts `keep` rejects (by network and host).
/// A lock that a query of its host (a peer agents request) still holds or
/// waits for is kept; a later pass drops it.
fn prune_queries(store: &Store, keep: impl Fn(&str, &str) -> bool) {
    if let Ok(mut locks) = store.host_queries.lock() {
        locks.retain(|(n, h), lock| keep(n, h) || Arc::strong_count(lock) > 1);
    }
}

/// Refreshes one network's directory: every other member, or only `only`.
/// A host that fails keeps its agents, marked with the error. A synchronous
/// refresh (`retry_forbidden`) asks a host that answered 403 once more,
/// 2 seconds later.
async fn refresh(store: Arc<Store>, network: String, only: Option<String>, retry_forbidden: bool) {
    let lookup = network.clone();
    let Ok((members, own_person)) = blocking(store.clone(), move |s| {
        let conn = s.connection()?;
        let own = s.identity().id;
        let own_person = s
            .product_members(&conn, &lookup)?
            .into_iter()
            .find(|m| m.host_id == own)
            .and_then(|m| m.person_id);
        Ok((s.other_members(&conn, &lookup)?, own_person))
    })
    .await
    else {
        return;
    };
    // Hosts this map shows bound to this host's own person: their answer
    // should carry `self` entries.
    let siblings: Arc<BTreeSet<String>> = Arc::new(
        members
            .iter()
            .filter(|m| own_person.is_some() && m.person_id == own_person)
            .map(|m| m.host_id.clone())
            .collect(),
    );
    let hosts: Vec<String> = members
        .iter()
        .map(|m| m.host_id.clone())
        .filter(|h| only.as_ref().is_none_or(|o| o == h))
        .collect();
    if let Ok(mut cache) = store.directory_cache() {
        let entry = cache.networks.entry(network.clone()).or_default();
        entry
            .hosts
            .retain(|h, _| members.iter().any(|m| &m.host_id == h));
        for m in &members {
            entry
                .hosts
                .entry(m.host_id.clone())
                .or_insert_with(|| HostEntry {
                    state: "pending",
                    refreshed_at: None,
                    error: None,
                    agents: Vec::new(),
                });
        }
    }
    prune_queries(&store, |n, h| {
        n != network || members.iter().any(|m| m.host_id == h)
    });
    let permits = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut queries = tokio::task::JoinSet::new();
    for host in hosts {
        let (store, network, permits, siblings) = (
            store.clone(),
            network.clone(),
            permits.clone(),
            siblings.clone(),
        );
        queries.spawn(async move {
            // Taken before a permit, so waiting for another refresh of this
            // host holds none.
            let Ok(lock) = store.host_queries.lock().map(|mut locks| {
                locks
                    .entry((network.clone(), host.clone()))
                    .or_default()
                    .clone()
            }) else {
                return;
            };
            let _query = lock.lock().await;
            let Ok(_permit) = permits.acquire_owned().await else {
                return;
            };
            let mut outcome = query(store.clone(), network.clone(), host.clone()).await;
            // A synchronous refresh asks once more, 2 seconds later, a host
            // that answered 403, or a sibling whose answer has no `self`
            // entry because it has not yet synced the binding.
            let lacks_self = |o: &Outcome| match o {
                Outcome::Agents(agents) => {
                    siblings.contains(&host)
                        && !agents
                            .iter()
                            .any(|a| a.authorizations.iter().any(|z| z.kind == "self"))
                }
                _ => false,
            };
            if retry_forbidden
                && (matches!(outcome, Outcome::Forbidden | Outcome::Unauthenticated(_))
                    || lacks_self(&outcome))
            {
                tokio::time::sleep(FORBIDDEN_RETRY).await;
                outcome = query(store.clone(), network.clone(), host.clone()).await;
            }
            let at = rfc3339(Utc::now());
            let Ok(mut cache) = store.directory_cache() else {
                return;
            };
            let Some(entry) = cache
                .networks
                .get_mut(&network)
                .and_then(|n| n.hosts.get_mut(&host))
            else {
                return;
            };
            match outcome {
                Outcome::Agents(agents) => {
                    *entry = HostEntry {
                        state: "ok",
                        refreshed_at: Some(at),
                        error: None,
                        agents,
                    }
                }
                Outcome::Unsupported => {
                    *entry = HostEntry {
                        state: "unsupported",
                        refreshed_at: Some(at),
                        error: None,
                        agents: Vec::new(),
                    }
                }
                Outcome::Forbidden => {
                    entry.state = "error";
                    entry.error = Some("peer returned HTTP 403".into());
                }
                Outcome::Failed(error) | Outcome::Unauthenticated(error) => {
                    entry.state = "error";
                    entry.error = Some(error);
                }
            }
        });
    }
    while queries.join_next().await.is_some() {}
    if only.is_none()
        && let Ok(mut cache) = store.directory_cache()
        && let Some(entry) = cache.networks.get_mut(&network)
    {
        entry.refreshed_at = Some(rfc3339(Utc::now()));
    }
}

/// On another host's `presence` (relay version 3): refreshes only that
/// host's entry, when this host is in the network and its map lists the host
/// as a current member; otherwise ignores it. At most one such refresh per
/// (network, host) is in flight, and one arriving meanwhile causes one more.
pub(crate) fn presence(store: &Arc<Store>, host: String, network: String) {
    let key = (network.clone(), host.clone());
    let Ok(mut running) = store.presence_refreshes.lock() else {
        return;
    };
    if let Some(again) = running.get_mut(&key) {
        *again = true;
        return;
    }
    running.insert(key.clone(), false);
    drop(running);
    let store = store.clone();
    tokio::spawn(async move {
        loop {
            let (lookup, member) = (network.clone(), host.clone());
            let known = blocking(store.clone(), move |s| {
                let conn = s.connection()?;
                let in_network: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM networks WHERE id = ?1)",
                    [&lookup],
                    |r| r.get(0),
                )?;
                Ok(in_network
                    && s.other_members(&conn, &lookup)?
                        .iter()
                        .any(|m| m.host_id == member))
            })
            .await
            .unwrap_or(false);
            if known {
                refresh(store.clone(), network.clone(), Some(host.clone()), false).await;
            }
            let Ok(mut running) = store.presence_refreshes.lock() else {
                return;
            };
            match running.get_mut(&key) {
                Some(again) if known && *again => *again = false,
                _ => {
                    running.remove(&key);
                    return;
                }
            }
        }
    });
}

/// Refreshes networks now and waits at most 10 seconds; an unfinished
/// refresh completes in the background.
pub(crate) async fn refresh_now(store: &Arc<Store>, networks: Vec<String>, only: Option<String>) {
    let mut running = Vec::new();
    for network in networks {
        running.push(tokio::spawn(refresh(
            store.clone(),
            network,
            only.clone(),
            true,
        )));
    }
    let _ = tokio::time::timeout(SYNC_WAIT, async {
        for task in running {
            let _ = task.await;
        }
    })
    .await;
}

/// Resolves an address in every network of this host, or only `network`,
/// refreshing the directory once when nothing matches.
pub(crate) async fn resolve(
    store: &Arc<Store>,
    to: &str,
    network: Option<&str>,
) -> Result<Candidate, Error> {
    parts(to)?;
    let (address, given) = (to.to_owned(), network.map(str::to_owned));
    let networks = {
        let given = given.clone();
        blocking(store.clone(), move |s| s.searched(given.as_deref())).await?
    };
    let lookup = |networks: Vec<String>| {
        let address = address.clone();
        blocking(store.clone(), move |s| s.matching(&address, &networks))
    };
    let mut found = lookup(networks.clone()).await?;
    if found.is_empty() {
        refresh_now(store, networks.clone(), None).await;
        found = lookup(networks).await?;
    }
    match found.as_slice() {
        [] => Err(coded(
            404,
            "unknown",
            format!("no agent in the directory has the address {to}"),
            json!({ "matches": [] }),
        )),
        [one] if one.local => Err(coded(
            400,
            "local",
            format!("{to} names an agent on this host; Peerspan has no local delivery"),
            json!({ "matches": [] }),
        )),
        [one] => Ok(one.clone()),
        many => {
            let mut matches: Vec<(String, String)> = many
                .iter()
                .map(|c| (c.network_id.clone(), format!("{}/{}", c.host_id, c.name)))
                .collect();
            matches.sort();
            Err(coded(
                409,
                "ambiguous",
                format!(
                    "{to} names several agents: {}",
                    matches
                        .iter()
                        .map(|(n, a)| format!("{a} in {n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                json!({
                    "matches": matches
                        .iter()
                        .map(|(n, a)| json!({"address": a, "network_id": n}))
                        .collect::<Vec<_>>()
                }),
            ))
        }
    }
}

/// Chooses how a request by address to `target` cites its authorization,
/// refreshing that host once before refusing with `not_authorized`. Before
/// refusing, and before citing a policy this host does not yet hold, it also
/// syncs the network once, so it cites the newest policy.
pub(crate) async fn authorize(
    store: &Arc<Store>,
    to: &str,
    target: &Candidate,
    action: &str,
    origin: Option<&str>,
) -> Result<Choice, Error> {
    let chosen = |agent: Option<PeerAgent>| agent.as_ref().and_then(|a| choose(a, action, origin));
    let recheck = || async {
        refresh_now(
            store,
            vec![target.network_id.clone()],
            Some(target.host_id.clone()),
        )
        .await;
        let (network, host, agent) = (
            target.network_id.clone(),
            target.host_id.clone(),
            target.agent_id.clone(),
        );
        blocking(store.clone(), move |s| {
            s.cached_agent(&network, &host, &agent)
        })
        .await
    };
    let sync = || async {
        let read = store.clone();
        let network = target.network_id.clone();
        let native = blocking(read, move |s| {
            let c = s.connection()?;
            crate::decentralized::product::is_decentralized(&c, &network)
        })
        .await;
        match native {
            Ok(true) => {
                let _ = crate::decentralized::peer::sync(store.clone(), &target.network_id).await;
            }
            Ok(false) if !store.decentralized_runtime() => {
                let _ =
                    crate::network::sync_network(store.clone(), target.network_id.clone()).await;
            }
            _ => {}
        }
    };
    let mut synced = false;
    let mut choice = chosen(target.agent.clone());
    if choice.is_none() {
        choice = chosen(recheck().await?);
    }
    if choice.is_none() {
        sync().await;
        synced = true;
        choice = chosen(recheck().await?);
    }
    let choice = choice.ok_or_else(|| not_authorized(to))?;
    if choice == Choice::Policy && !synced {
        let host = target.host_id.clone();
        let held = blocking(store.clone(), move |s| {
            let conn = s.connection()?;
            Ok(s.cited_policy(&conn, &host).is_ok())
        })
        .await?;
        if !held {
            sync().await;
        }
    }
    Ok(choice)
}

/// Resolves and authorizes an owner request by address; an explicit grant
/// skips the choice.
pub(crate) async fn owner_target(
    store: &Arc<Store>,
    to: &str,
    network: Option<&str>,
    action: &str,
    origin: Option<&str>,
    grant: bool,
) -> Result<(Candidate, Option<Choice>), Error> {
    let target = resolve(store, to, network).await?;
    let choice = if grant {
        None
    } else {
        Some(authorize(store, to, &target, action, origin).await?)
    };
    Ok((target, choice))
}

/// Fills an owner request by address with its target: the stored one when
/// the request repeats an ID already sent to this address, and otherwise
/// the resolved one with its chosen authorization. `id_field` names the
/// request or task ID; `action` is what the request needs.
pub(crate) async fn owner_request(
    store: &Arc<Store>,
    body: &mut Value,
    to: &str,
    network: Option<String>,
    id_field: &str,
    action: &str,
) -> Result<Addressed, Error> {
    let origin = body["origin"]["agent_id"].as_str().map(str::to_owned);
    let grant = body.get("grant_id").is_some_and(|g| !g.is_null());
    let id = body[id_field].as_str().unwrap_or_default().to_owned();
    let table = if id_field == "task_id" {
        "outbound_tasks"
    } else {
        "outbound_messages"
    };
    let stored = if id.is_empty() {
        None
    } else {
        let address = to.to_owned();
        blocking(store.clone(), move |s| {
            let conn = s.connection()?;
            let column = if table == "outbound_tasks" { "task_id" } else { "request_id" };
            let found: Option<(String, String)> = rusqlite::OptionalExtension::optional(
                conn.query_row(
                    &format!(
                        "SELECT peer, json_extract(record, '$.request.target_agent_id') FROM {table} WHERE {column} = ?1 AND json_extract(record, '$.to') = ?2 ORDER BY rowid LIMIT 1"
                    ),
                    params![id, address],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                ),
            )?;
            Ok(found)
        })
        .await?
    };
    let (host, agent, choice) = match stored {
        Some((host, agent)) => (host, agent, None),
        None => {
            let (target, choice) = owner_target(
                store,
                to,
                network.as_deref(),
                action,
                origin.as_deref(),
                grant,
            )
            .await?;
            (target.host_id, target.agent_id, choice)
        }
    };
    body["peer_host_id"] = json!(host);
    body["target_agent_id"] = json!(agent);
    Ok(Addressed {
        to: to.to_owned(),
        choice,
    })
}

/// Watches every network: refreshes each at startup, every 5 minutes, and
/// within seconds of a change to its map or stored policies.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let mut last: BTreeMap<String, (Instant, String)> = BTreeMap::new();
    loop {
        let networks = blocking(store.clone(), |s| {
            let ids: Vec<String> = s.product_network_ids(&*s.connection()?)?;
            ids.into_iter()
                .map(|id| Ok((s.directory_fingerprint(&id)?, id)))
                .collect::<Result<Vec<_>, Error>>()
        })
        .await
        .unwrap_or_default();
        for (fingerprint, id) in &networks {
            let due = last
                .get(id)
                .is_none_or(|(at, seen)| at.elapsed() >= REFRESH_EVERY || seen != fingerprint);
            if due {
                last.insert(id.clone(), (Instant::now(), fingerprint.clone()));
                tokio::spawn(refresh(store.clone(), id.clone(), None, false));
            }
        }
        last.retain(|id, _| networks.iter().any(|(_, n)| n == id));
        if let Ok(mut cache) = store.directory_cache() {
            cache
                .networks
                .retain(|id, _| networks.iter().any(|(_, n)| n == id));
        }
        prune_queries(&store, |n, _| networks.iter().any(|(_, id)| id == n));
        tokio::select! {
            _ = tokio::time::sleep(WATCH_EVERY) => {}
            // A sync after the coordinator's change notification.
            _ = store.directory_wake.notified() => {}
            _ = shutdown.changed() => return,
        }
    }
}

pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new().route("/peer/v1/networks/{network_id}/agents", get(peer_agents))
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/directory", get(view))
        .route("/v1/directory/refresh", post(refresh_route))
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new().route("/adapter/v1/agents", get(agents_route))
}
async fn peer_agents(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(network): Path<String>,
) -> Result<Json<Vec<PeerAgent>>, Error> {
    Ok(Json(
        blocking(store, move |s| s.reachable_agents(&sender, &network)).await?,
    ))
}
#[derive(Deserialize)]
struct NetworkQuery {
    network: Option<String>,
}
fn network_query(
    query: Result<Query<NetworkQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Option<String>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid request".into()))?;
    Ok(q.network.filter(|n| !n.is_empty()))
}
async fn view(
    State(store): State<Arc<Store>>,
    query: Result<Query<NetworkQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    let network = network_query(query)?;
    Ok(Json(
        blocking(store, move |s| s.directory_view(network)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn refresh_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<NetworkQuery>, axum::extract::rejection::QueryRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let network = network_query(query)?;
    let body = body.map_err(|_| Error::Invalid("invalid request".into()))?;
    if !body.is_empty() {
        let _: Empty = decode(Ok(body))?;
    }
    let network = blocking(store.clone(), move |s| s.directory_network(network)).await?;
    refresh_now(&store, vec![network.clone()], None).await;
    Ok(Json(
        blocking(store, move |s| s.directory_view(Some(network))).await?,
    ))
}
async fn agents_route(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
) -> Result<Json<Vec<Value>>, Error> {
    let auth = crate::adapter::token(&headers);
    let agents = blocking(store.clone(), move |s| s.adapter_agents(&auth)).await?;
    Ok(Json(
        agents
            .into_iter()
            .map(|(host, address, mut v)| {
                v["endpoint"] = endpoint(&store, &host, address);
                v
            })
            .collect(),
    ))
}

/// A member's advertised address in a network map, else its first
/// candidate.
pub(crate) fn map_address(members: &[crate::network::Member], host: &str) -> Option<String> {
    let m = members.iter().find(|m| m.host_id == host)?;
    if !m.address.is_empty() {
        return Some(m.address.clone());
    }
    m.candidates.first().cloned()
}

/// How this host reaches `host` now: a direct path's endpoint, otherwise
/// the map address with the path as reported, or `local` for this host.
/// It grants nothing.
pub(crate) fn endpoint(store: &Arc<Store>, host: &str, map: Option<String>) -> Value {
    if host == store.identity().id {
        return json!({"address": map, "path": "local"});
    }
    match crate::quic::path_status(store, host) {
        Ok(p) if p.path == "direct" && p.endpoint.is_some() => {
            json!({"address": p.endpoint, "path": "direct"})
        }
        Ok(p) => json!({"address": map, "path": p.path}),
        Err(_) => json!({"address": map, "path": "none"}),
    }
}
