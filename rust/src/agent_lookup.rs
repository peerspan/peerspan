//! Sharing with one agent (capabilities slice 3). An owner names another
//! person's agent as `PERSON/AGENT` or `HOST_ID/AGENT`; this host asks the
//! hosts the agent may be on, by exact name, with the peer lookup route, and
//! the share stores the existing `agent:HOST_ID/AGENT_ID` principal. Names
//! never authorize. `shares` labels agent principals by asking their hosts
//! by agent ID, and keeps the answers in memory only.
use crate::{
    api::blocking,
    directory::{addressable, coded},
    model::Error,
    peer_store::valid_id,
    store::Store,
};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, RawQuery, State, rejection::QueryRejection},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// The lookup route's query bound.
const MAX_QUERY: usize = 256;
/// The lookup route's response bound.
pub(crate) const MAX_RESPONSE: usize = 4096;
/// Hosts are asked at most 8 at once, 5 seconds each.
const PARALLEL: usize = 8;
const BOUND: Duration = Duration::from_secs(5);

/// The latest lookup answer for an agent of a host: its addressable name
/// from the latest answer that found it, and `found`, `not_found`, or
/// `unanswered`.
#[derive(Clone, Debug, Default)]
pub struct LabelEntry {
    name: Option<String>,
    state: &'static str,
}
/// Lookup answers by `HOST_ID/AGENT_ID`.
pub type LabelCache = BTreeMap<String, LabelEntry>;

/// Whether a `--with` value is an agent address, `PERSON/AGENT` or
/// `HOST_ID/AGENT`, split into its parts. A value with a `KIND:` prefix,
/// `everyone`, `network`, or no `/` is not one; two or more `/`, or an
/// agent name that is not addressable, is an error.
pub fn split_agent_address(given: &str) -> Result<Option<(&str, &str)>, String> {
    if given == "everyone"
        || given == "network"
        || ["person:", "group:", "agent:"]
            .iter()
            .any(|p| given.starts_with(p))
    {
        return Ok(None);
    }
    let invalid = || {
        format!(
            "invalid recipient {given:?}: use PERSON/AGENT, HOST_ID/AGENT, or person:LABEL for a label that contains /"
        )
    };
    match given.matches('/').count() {
        0 => Ok(None),
        1 => {
            let (left, name) = given.split_once('/').unwrap_or_default();
            if left.is_empty() {
                return Err(invalid());
            }
            if !addressable(name) {
                return Err(format!("invalid agent name {name:?}"));
            }
            Ok(Some((left, name)))
        }
        _ => Err(invalid()),
    }
}

/// The pairs of a form-encoded query string, or `None` when one does not
/// decode.
fn parse_query(raw: &str) -> Option<Vec<(String, String)>> {
    let decode = |s: &str| -> Option<String> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' => {
                    let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                    out.push(u8::from_str_radix(hex, 16).ok()?);
                    i += 2;
                }
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8(out).ok()
    };
    if raw.is_empty() {
        return Some(Vec::new());
    }
    raw.split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            Some((decode(k)?, decode(v)?))
        })
        .collect()
}

/// Percent-encodes a query value, keeping only unreserved characters.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn is_host_id(left: &str) -> bool {
    valid_id(left, "host", 32)
}

/// One host's answer: the agent (ID and name, null when not addressable),
/// or none; `Err` when it did not answer.
type Answer = Result<Option<(String, Option<String>)>, String>;

impl Store {
    /// The peer lookup route: whether this host has an agent with the
    /// query's exact addressable name, or its agent ID.
    pub fn lookup_local_agent(
        &self,
        caller: &str,
        network: &str,
        raw_query: &str,
    ) -> Result<Option<(String, Option<String>)>, Error> {
        let mut connection = self.connection()?;
        let conn = connection.transaction()?;
        let members = self.product_members(&conn, network)?;
        let member = |host: &str| members.iter().any(|m| m.host_id == host);
        if !member(&self.identity().id) {
            return Err(coded(
                404,
                "not_found",
                format!("this host is not in network {network}"),
                json!({}),
            ));
        }
        if caller == self.identity().id || !member(caller) {
            return Err(Error::Forbidden);
        }
        if raw_query.len() > MAX_QUERY {
            return Err(Error::Invalid(format!(
                "the query is longer than {MAX_QUERY} bytes"
            )));
        }
        let invalid = || Error::Invalid("give exactly one of name or agent_id".into());
        let pairs = parse_query(raw_query).ok_or_else(invalid)?;
        let [(key, value)] = pairs.as_slice() else {
            return Err(invalid());
        };
        if value.is_empty() || (key != "name" && key != "agent_id") {
            return Err(invalid());
        }
        let mut statement = conn.prepare("SELECT id, name FROM agents ORDER BY name, id")?;
        let agents = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(agents
            .into_iter()
            .find(|(id, name)| {
                (key == "name" && name == value && addressable(value))
                    || (key == "agent_id" && id == value)
            })
            .map(|(id, name)| (id, Some(name).filter(|n| addressable(n)))))
    }

    fn remember_agent(&self, host: &str, agent: &str, name: Option<String>, state: &'static str) {
        if let Ok(mut cache) = self.agent_labels.lock() {
            let entry = cache.entry(format!("{host}/{agent}")).or_default();
            if state == "found" {
                entry.name = name;
            }
            entry.state = state;
        }
    }
    fn cached_label(&self, host: &str, agent: &str) -> Option<LabelEntry> {
        self.agent_labels
            .lock()
            .ok()?
            .get(&format!("{host}/{agent}"))
            .cloned()
    }
}

/// Asks one host for an agent by `name` or `agent_id`, within 5 seconds.
/// A 404 without a JSON `code` is a host that predates the route: its
/// cached directory entries answer for it, or it is `unsupported`.
async fn ask(store: &Arc<Store>, network: &str, host: &str, key: &str, value: &str) -> Answer {
    let lookup = host.to_owned();
    let target = blocking(store.clone(), move |s| s.dial_target(&lookup))
        .await
        .map_err(|e| e.to_string())?;
    let path = format!(
        "/peer/v1/networks/{network}/agent-lookup?{key}={}",
        encode(value)
    );
    let response = tokio::time::timeout(
        BOUND,
        crate::quic::request(store.clone(), &target, "GET", &path, b""),
    )
    .await;
    let (status, body) = match response {
        Err(_) => return Err("timeout".into()),
        Ok(Err(e)) => return Err(format!("{e:#}")),
        Ok(Ok(answer)) => answer,
    };
    if status == 404 {
        let code = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v["code"].as_str().map(str::to_owned))
            .filter(|c| !c.is_empty());
        if code.is_none() {
            return match store.cached_directory_agent(network, host, key == "name", value) {
                Some((id, name)) => Ok(Some((id, Some(name).filter(|n| addressable(n))))),
                None => Err("unsupported".into()),
            };
        }
    }
    if status != 200 {
        return Err(format!("peer returned HTTP {status}"));
    }
    let invalid = || "invalid lookup answer".to_owned();
    let answer: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
    let agent = &answer["agent"];
    if agent.is_null() {
        if answer.get("agent").is_none() {
            return Err(invalid());
        }
        if key == "agent_id" {
            store.remember_agent(host, value, None, "not_found");
        }
        return Ok(None);
    }
    let id = agent["agent_id"].as_str().ok_or_else(invalid)?.to_owned();
    let name = match &agent["name"] {
        Value::Null => None,
        Value::String(n) if addressable(n) => Some(n.clone()),
        _ => return Err(invalid()),
    };
    if !valid_id(&id, "agent", 16)
        || (key == "name" && name.as_deref() != Some(value))
        || (key == "agent_id" && id != value)
    {
        return Err(invalid());
    }
    store.remember_agent(host, &id, name.clone(), "found");
    Ok(Some((id, name)))
}

/// Asks each (network, host, value) by `key`, at most 8 at once.
async fn ask_many(
    store: &Arc<Store>,
    targets: &[(String, String, String)],
    key: &'static str,
) -> Vec<Answer> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
    let mut set = tokio::task::JoinSet::new();
    for (index, (network, host, value)) in targets.iter().cloned().enumerate() {
        let (store, semaphore) = (store.clone(), semaphore.clone());
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            (index, ask(&store, &network, &host, key, &value).await)
        });
    }
    let mut out: Vec<Answer> = vec![Err("timeout".into()); targets.len()];
    while let Some(Ok((index, answer))) = set.join_next().await {
        out[index] = answer;
    }
    out
}

/// `GET /v1/agent-lookup`: turns `PERSON/AGENT` or `HOST_ID/AGENT` into the
/// agent principal, asking the hosts the agent may be on.
pub async fn resolve_agent_address(
    store: Arc<Store>,
    address: String,
    network: Option<String>,
) -> Result<Value, Error> {
    let (left, name) = match split_agent_address(&address) {
        Err(e) => return Err(Error::Invalid(e)),
        Ok(None) => {
            return Err(Error::Invalid(format!(
                "{address:?} is not an agent address; use PERSON/AGENT or HOST_ID/AGENT"
            )));
        }
        Ok(Some((l, n))) => (l.to_owned(), n.to_owned()),
    };
    let (l, n) = (left.clone(), name.clone());
    let own = store.identity().id;
    // The hosts to ask, the person's label for messages, the members, and
    // whether this host has an agent with the name.
    let (network, hosts, who, members, local) = blocking(store.clone(), move |s| {
        let network = s.directory_network(network)?;
        let mut connection = s.connection()?;
        let conn = connection.transaction()?;
        let members = s.product_members(&conn, &network)?;
        let (hosts, who) = if is_host_id(&l) {
            if !members.iter().any(|m| m.host_id == l) {
                return Err(coded(
                    404,
                    "unknown_host",
                    format!("unknown host {l} in network {network}"),
                    json!({}),
                ));
            }
            (vec![l.clone()], l.clone())
        } else {
            let persons = s.product_persons(&conn, &network)?;
            let p = match crate::decentralized::product::resolve_person(&persons, &l) {
                Ok(p) => p,
                Err(Error::NotFound) => {
                    return Err(coded(
                        404,
                        "unknown_person",
                        format!("no current person {l:?}"),
                        json!({}),
                    ));
                }
                Err(e) => return Err(e),
            };
            let hosts = members
                .iter()
                .filter(|m| m.person_id.as_deref() == Some(p.person_id.as_str()))
                .map(|m| m.host_id.clone())
                .collect();
            (hosts, p.member.clone())
        };
        let local: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE name = ?1)",
            [&n],
            |r| r.get(0),
        )?;
        Ok((network, hosts, who, members, local))
    })
    .await?;
    let mut targets = Vec::new();
    for h in hosts {
        if h != own {
            targets.push((network.clone(), h, name.clone()));
        } else if local {
            return Err(coded(
                400,
                "local",
                format!(
                    "{address} is on this host, and a host never calls itself. Share with an agent on another machine."
                ),
                json!({}),
            ));
        }
    }
    let answers = ask_many(&store, &targets, "name").await;
    let mut unanswered: Vec<(String, String)> = Vec::new();
    let mut matches = Vec::new();
    for ((_, host, _), answer) in targets.iter().zip(answers) {
        match answer {
            Err(e) => unanswered.push((host.clone(), e)),
            Ok(Some((id, _))) => matches.push((host.clone(), id)),
            Ok(None) => {}
        }
    }
    unanswered.sort();
    let unanswered_json: Vec<Value> = unanswered
        .iter()
        .map(|(h, e)| json!({"host_id": h, "error": e}))
        .collect();
    match matches.len() {
        0 => {
            let mut message = if is_host_id(&left) {
                format!("{left} has no agent named {name}.")
            } else {
                format!("{who} has no agent named {name} on the hosts that answered.")
            };
            if !unanswered.is_empty() {
                message.push_str(&format!(
                    " Not answered: {}. Try again when it is online, or use agent:HOST_ID/AGENT_ID.",
                    unanswered
                        .iter()
                        .map(|(h, e)| format!("{h} ({e})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Err(coded(
                404,
                "unknown",
                message,
                json!({"unanswered": unanswered_json}),
            ))
        }
        1 => {
            let (host, agent) = matches.remove(0);
            let m = members.iter().find(|m| m.host_id == host);
            let person = m.and_then(|m| m.person_id.clone());
            let label = m.and_then(|m| m.person_member.clone());
            let address = match (&person, &label) {
                (Some(_), Some(label)) if !label.contains('/') => format!("{label}/{name}"),
                _ => format!("{host}/{name}"),
            };
            Ok(json!({
                "principal": format!("agent:{host}/{agent}"),
                "host_id": host,
                "agent_id": agent,
                "person_id": person,
                "address": address,
                "unanswered": unanswered_json,
            }))
        }
        _ => {
            let mut found: Vec<String> =
                matches.iter().map(|(h, _)| format!("{h}/{name}")).collect();
            found.sort();
            Err(coded(
                409,
                "ambiguous",
                format!("more than one host has an agent named {name}; use one of these addresses"),
                json!({"matches": found.iter().map(|a| json!({"address": a, "network_id": network})).collect::<Vec<_>>()}),
            ))
        }
    }
}

/// Sets `label` and `agent_state` on the agent recipients
/// (`{network_id, principal, label}` objects). With `lookup`, it first asks
/// each agent's host by agent ID, skipping hosts that left the network.
pub(crate) async fn label_agent_recipients(
    store: &Arc<Store>,
    recipients: &mut [Value],
    lookup: bool,
) -> Result<(), Error> {
    let networks: Vec<String> = {
        let mut n: Vec<String> = recipients
            .iter()
            .filter_map(|r| r["network_id"].as_str().map(str::to_owned))
            .collect();
        n.sort();
        n.dedup();
        n
    };
    let members: BTreeMap<String, Vec<crate::network::Member>> =
        blocking(store.clone(), move |s| {
            let mut connection = s.connection()?;
            let conn = connection.transaction()?;
            let mut out = BTreeMap::new();
            for n in networks {
                out.insert(n.clone(), s.product_members(&conn, &n)?);
            }
            Ok(out)
        })
        .await?;
    let member = |network: &str, host: &str| {
        members
            .get(network)
            .and_then(|list| list.iter().find(|m| m.host_id == host))
    };
    if lookup {
        let mut targets: Vec<(String, String, String)> = Vec::new();
        for r in recipients.iter() {
            let (Some(network), Some(principal)) =
                (r["network_id"].as_str(), r["principal"].as_str())
            else {
                continue;
            };
            let Some((host, agent)) = crate::policy::agent_principal(principal) else {
                continue;
            };
            let target = (network.to_owned(), host.to_owned(), agent.to_owned());
            if member(network, host).is_some() && !targets.contains(&target) {
                targets.push(target);
            }
        }
        for ((_, host, agent), answer) in targets
            .iter()
            .zip(ask_many(store, &targets, "agent_id").await)
        {
            match answer {
                Err(_) => store.remember_agent(host, agent, None, "unanswered"),
                Ok(Some((_, name))) => store.remember_agent(host, agent, name, "found"),
                Ok(None) => {}
            }
        }
    }
    for r in recipients.iter_mut() {
        let (Some(network), Some(principal)) = (
            r["network_id"].as_str().map(str::to_owned),
            r["principal"].as_str().map(str::to_owned),
        ) else {
            continue;
        };
        let Some((host, agent)) = crate::policy::agent_principal(&principal) else {
            continue;
        };
        let m = member(&network, host);
        let cached = store.cached_label(host, agent);
        let state = match (&m, &cached) {
            (None, _) => "host_gone",
            (Some(m), Some(c)) if c.state == "found" && m.person_id.is_none() => "unbound",
            (_, Some(c)) => c.state,
            (_, None) => "unanswered",
        };
        let label = cached.and_then(|c| c.name).map(|name| match m {
            Some(m)
                if m.person_id.is_some()
                    && m.person_member.as_deref().is_some_and(|l| !l.contains('/')) =>
            {
                format!("{}/{name}", m.person_member.clone().unwrap_or_default())
            }
            _ => format!("{host}/{name}"),
        });
        r["label"] = json!(label);
        r["agent_state"] = json!(state);
    }
    Ok(())
}

pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new().route(
        "/peer/v1/networks/{network_id}/agent-lookup",
        get(peer_lookup),
    )
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/agent-lookup", get(local_lookup))
}
async fn peer_lookup(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(network): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, Error> {
    let query = query.unwrap_or_default();
    let agent = blocking(store, move |s| {
        s.lookup_local_agent(&sender, &network, &query)
    })
    .await?;
    Ok(Json(json!({
        "agent": agent.map(|(id, name)| json!({"agent_id": id, "name": name})),
    })))
}
#[derive(Deserialize)]
struct LookupQuery {
    address: Option<String>,
    network: Option<String>,
}
async fn local_lookup(
    State(store): State<Arc<Store>>,
    query: Result<Query<LookupQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid request".into()))?;
    let address = q
        .address
        .filter(|a| !a.is_empty())
        .ok_or_else(|| Error::Invalid("give address".into()))?;
    Ok(Json(
        resolve_agent_address(store, address, q.network.filter(|n| !n.is_empty())).await?,
    ))
}
