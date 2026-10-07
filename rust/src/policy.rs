//! Owner access policy (milestone 2b slice 3). An owner signs one policy per
//! network with their person key (`SSHSIG`); every host bound to that owner
//! enforces it for its local agents, next to manual grants. A host-local
//! block list overrides both. Daemons renew policies by asking the owner's
//! `ssh-agent` for a signature and never hold the key.
use crate::api::{blocking, decode};
use crate::{
    admins::group_name,
    membership::{check_network, invalid, time},
    model::Error,
    network::Member,
    peer_store::{Bounds, MessageRequest, json},
    persons::{PersonSigner, person_id_of, verify_sshsig},
    store::{Store, append_event, now, rfc3339},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State, rejection::BytesRejection},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;

/// Database version 8: the host-local block list.
pub(crate) const SCHEMA: &str = "
CREATE TABLE access_blocks (kind TEXT NOT NULL, subject TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(kind, subject));
PRAGMA user_version = 8;
";

pub const ACTION: &str = "message.append";
pub const DEFAULT_VALID_DAYS: i64 = 7;
const MAX_RULES: usize = 64;
const MAX_PRINCIPALS: usize = 64;
/// Clock skew allowed before `issued_at`.
const SKEW: TimeDelta = TimeDelta::minutes(5);

/// One rule: who may perform which actions on one of the owner's agents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub agent: String,
    pub principals: Vec<String>,
    pub actions: Vec<String>,
    pub max_message_bytes: i64,
    pub allow_disconnected: bool,
}

/// An owner-signed access policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub network_id: String,
    pub person_public_key: String,
    pub version: u64,
    pub issued_at: String,
    pub valid_until: String,
    pub rules: Vec<Rule>,
    pub signature: String,
}

/// The owner policy a request relies on: the owner and the newest version the
/// sender has verified.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    pub person_id: String,
    pub version: u64,
}

/// Rejects an explicit `null`; an absent field defaults to `None`.
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

pub(crate) fn person_id_shape(id: &str) -> bool {
    id.strip_prefix("person_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
/// `person:<person ID>`, `group:<name>`, or `network`.
pub fn principal(value: &str) -> Result<(), Error> {
    let ok = value == "network"
        || value.strip_prefix("person:").is_some_and(person_id_shape)
        || value
            .strip_prefix("group:")
            .is_some_and(|g| group_name(g).is_ok());
    if ok {
        Ok(())
    } else {
        Err(invalid(&format!(
            "invalid principal {value:?}: use person:<person ID>, group:<name>, or network"
        )))
    }
}
/// Agent names in rules are valid labels.
pub fn agent_name(value: &str) -> Result<(), Error> {
    crate::membership::label(value)
        .map_err(|_| invalid(&format!("invalid agent name {value:?} in a policy rule")))
}

impl Rule {
    fn check(&self) -> Result<(), Error> {
        agent_name(&self.agent)?;
        if self.principals.is_empty() || self.principals.len() > MAX_PRINCIPALS {
            return Err(invalid("a rule has 1-64 principals"));
        }
        for p in &self.principals {
            principal(p)?;
        }
        if self.actions.is_empty() || self.actions.iter().any(|a| a != ACTION) {
            return Err(invalid("the only policy action is message.append"));
        }
        if !(1..=65536).contains(&self.max_message_bytes) {
            return Err(invalid("max_message_bytes must be 1-65536"));
        }
        Ok(())
    }
}

impl Policy {
    fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            "capsule-policy-v1".to_owned(),
            self.network_id.clone(),
            self.person_public_key.clone(),
            self.version.to_string(),
            self.issued_at.clone(),
            self.valid_until.clone(),
        ];
        for r in &self.rules {
            lines.push("rule".into());
            lines.push(r.agent.clone());
            lines.push(r.principals.join(" "));
            lines.push(r.actions.join(" "));
            lines.push(format!("{} {}", r.max_message_bytes, r.allow_disconnected));
        }
        lines
    }
    fn check_shape(&self) -> Result<(), Error> {
        if self.version < 1 {
            return Err(invalid("policy versions start at 1"));
        }
        let duration = time(&self.valid_until)? - time(&self.issued_at)?;
        if duration < TimeDelta::days(1) || duration > TimeDelta::days(90) {
            return Err(invalid("a policy is valid for 1-90 days"));
        }
        if self.rules.len() > MAX_RULES {
            return Err(invalid("a policy has at most 64 rules"));
        }
        for r in &self.rules {
            r.check()?;
        }
        Ok(())
    }
    /// Signs a policy as `signer`, the owner.
    pub fn sign(
        signer: &PersonSigner,
        network: &str,
        version: u64,
        issued_at: &str,
        valid_until: &str,
        rules: Vec<Rule>,
    ) -> Result<Self, Error> {
        let mut p = Self {
            network_id: network.into(),
            person_public_key: signer.public_key_b64(),
            version,
            issued_at: issued_at.into(),
            valid_until: valid_until.into(),
            rules,
            signature: String::new(),
        };
        p.check_shape()?;
        let lines = p.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        p.signature = signer.sign(&refs)?;
        Ok(p)
    }
    /// The shape and the owner's signature; not the validity window.
    pub fn verify(&self, network: &str) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        self.check_shape()?;
        let lines = self.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        verify_sshsig(&self.person_public_key, &refs, &self.signature)
    }
    pub fn person_id(&self) -> String {
        person_id_of(&self.person_public_key).unwrap_or_default()
    }
    fn times(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        let issued = time(&self.issued_at).unwrap_or(DateTime::<Utc>::MIN_UTC);
        let until = time(&self.valid_until).unwrap_or(DateTime::<Utc>::MIN_UTC);
        (issued, until)
    }
    /// Within its validity window, allowing 5 minutes of skew before `issued_at`.
    pub fn in_window(&self, at: DateTime<Utc>) -> bool {
        let (issued, until) = self.times();
        at >= issued - SKEW && at < until
    }
    /// Less than a quarter of its validity remains.
    pub fn expires_soon(&self, at: DateTime<Utc>) -> bool {
        let (issued, until) = self.times();
        until - at < (until - issued) / 4
    }
    /// The same rules at version + 1, with the same duration from `at`.
    pub fn renewal(&self, signer: &PersonSigner, at: DateTime<Utc>) -> Result<Self, Error> {
        let (issued, until) = self.times();
        Self::sign(
            signer,
            &self.network_id,
            self.version + 1,
            &rfc3339(at),
            &rfc3339(at + (until - issued)),
            self.rules.clone(),
        )
    }
    pub fn reference(&self) -> PolicyRef {
        PolicyRef {
            person_id: self.person_id(),
            version: self.version,
        }
    }
}

/// A host-local block: a person or a host refused under both grants and
/// policy, without coordination.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessBlock {
    pub kind: String,
    pub subject: String,
    pub created_at: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockRequest {
    #[serde(default)]
    pub person: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
}

/// The newest verified policy, plus whether it needs renewal soon.
#[derive(Debug, Serialize)]
pub struct PolicyView {
    #[serde(flatten)]
    pub policy: Policy,
    pub expires_soon: bool,
}

impl Store {
    /// The newest verified policy of `person_key` in a network.
    pub(crate) fn stored_policy(
        &self,
        connection: &Connection,
        network: &str,
        person_key: &str,
    ) -> Result<Option<Policy>, Error> {
        connection
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'policy' AND subject = ?2",
                params![network, person_key],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(json)
            .transpose()
    }
    /// This host's member records, one per network.
    fn own_members(&self, connection: &Connection) -> Result<Vec<(String, Member)>, Error> {
        self.members_of(connection, &self.identity().id)
    }
    fn members_of(
        &self,
        connection: &Connection,
        host: &str,
    ) -> Result<Vec<(String, Member)>, Error> {
        let mut statement = connection.prepare(
            "SELECT network_id, record FROM network_members WHERE host_id = ?1 ORDER BY network_id",
        )?;
        let rows = statement
            .query_map([host], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(|(n, m)| Ok((n, json(m)?))).collect()
    }
    /// The key of a current person in a network.
    fn person_key(
        &self,
        connection: &Connection,
        network: &str,
        person_id: &str,
    ) -> Result<Option<String>, Error> {
        Ok(self
            .stored_persons(connection, network)?
            .into_iter()
            .find(|p| p.person_id == person_id)
            .map(|p| p.person_public_key))
    }
    /// Whether the block list refuses this sender host: blocked by host ID,
    /// or bound to a blocked person in any network.
    pub(crate) fn blocked(&self, connection: &Connection, sender: &str) -> Result<bool, Error> {
        let host: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE kind = 'host' AND subject = ?1)",
            [sender],
            |r| r.get(0),
        )?;
        if host {
            return Ok(true);
        }
        for (_, m) in self.members_of(connection, sender)? {
            if let Some(person) = &m.person_id {
                let blocked: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM access_blocks WHERE kind = 'person' AND subject = ?1)",
                    [person],
                    |r| r.get(0),
                )?;
                if blocked {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    /// Authorizes a request under the cited owner's policy. Final denials are
    /// `Forbidden`; a receiver behind the cited version is `Unavailable`.
    pub(crate) fn policy_bounds(
        &self,
        connection: &Connection,
        sender: &str,
        r: &MessageRequest,
        cited: &PolicyRef,
        require_deadline: bool,
    ) -> Result<Bounds, Error> {
        let at = Utc::now();
        let deadline = time(&r.deadline)?;
        if require_deadline && deadline <= at {
            return Err(Error::Forbidden);
        }
        let agent: Option<String> = connection
            .query_row(
                "SELECT name FROM agents WHERE id = ?1",
                [&r.target_agent_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(agent) = agent else {
            return Err(Error::Forbidden);
        };
        let mut behind = false;
        let mut allowed: Option<Bounds> = None;
        for (network, own) in self.own_members(connection)? {
            if own.person_id.as_deref() != Some(cited.person_id.as_str()) {
                continue;
            }
            let Some(key) = self.person_key(connection, &network, &cited.person_id)? else {
                continue;
            };
            let Some(policy) = self.stored_policy(connection, &network, &key)? else {
                behind = true;
                continue;
            };
            if policy.version < cited.version {
                behind = true;
                continue;
            }
            // The receiver evaluates its own newest version.
            if !policy.in_window(at) || deadline > time(&policy.valid_until)? {
                continue;
            }
            let Some(sender_member) = self
                .stored_members(connection, &network)?
                .into_iter()
                .find(|m| m.host_id == sender && m.host_id != self.identity().id)
            else {
                continue;
            };
            let groups = self.stored_groups(connection, &network)?;
            let matches = |p: &str| match p {
                "network" => true,
                _ => {
                    if let Some(id) = p.strip_prefix("person:") {
                        sender_member.person_id.as_deref() == Some(id)
                    } else if let Some(name) = p.strip_prefix("group:") {
                        sender_member.person_id.as_ref().is_some_and(|person| {
                            groups
                                .iter()
                                .any(|g| g.name == name && g.members.contains(person))
                        })
                    } else {
                        false
                    }
                }
            };
            for rule in &policy.rules {
                if rule.agent != agent
                    || !rule.actions.iter().any(|a| a == ACTION)
                    || r.content.len() as i64 > rule.max_message_bytes
                    || !rule.principals.iter().any(|p| matches(p))
                {
                    continue;
                }
                let bounds = allowed.get_or_insert(Bounds {
                    max_message_bytes: 0,
                    allow_disconnected: false,
                });
                bounds.max_message_bytes = bounds.max_message_bytes.max(rule.max_message_bytes);
                bounds.allow_disconnected |= rule.allow_disconnected;
            }
        }
        match allowed {
            Some(b) => Ok(b),
            None if behind => Err(Error::Unavailable(
                "this host has not yet received the cited policy version".into(),
            )),
            None => Err(Error::Forbidden),
        }
    }
    /// The policy a send to `peer` cites: the target host's bound person's
    /// newest verified policy.
    pub(crate) fn policy_citation(
        &self,
        connection: &Connection,
        peer: &str,
    ) -> Result<PolicyRef, Error> {
        let mut owner = None;
        for (network, m) in self.members_of(connection, peer)? {
            let Some(person) = &m.person_id else {
                continue;
            };
            owner = Some(person.clone());
            let Some(key) = self.person_key(connection, &network, person)? else {
                continue;
            };
            if let Some(p) = self.stored_policy(connection, &network, &key)? {
                return Ok(p.reference());
            }
        }
        Err(Error::Invalid(match owner {
            None => format!(
                "no grant given, and host {peer} is not bound to a person in any shared network; ask its owner for a grant"
            ),
            Some(owner) => format!(
                "no grant given, and the owner of host {peer} ({owner}) has no access policy; ask them to run access allow, or give a grant"
            ),
        }))
    }

    /// The `ssh-agent` socket the daemon asks to renew policies.
    pub fn set_person_agent(&self, socket: Option<std::path::PathBuf>) {
        if let Ok(mut agent) = self.person_agent.write() {
            *agent = socket;
        }
    }
    /// The newest verified policy of a person (this host's own person by
    /// default) in a network.
    pub fn policy(&self, network: &str, person: Option<&str>) -> Result<PolicyView, Error> {
        let connection = self.connection()?;
        self.network_record(&connection, network)?;
        let person = match person {
            Some(p) => {
                let persons = self.stored_persons(&connection, network)?;
                crate::admins::resolve_person(&persons, p)?
                    .person_id
                    .clone()
            }
            None => self
                .own_members(&connection)?
                .into_iter()
                .find(|(n, _)| n == network)
                .and_then(|(_, m)| m.person_id)
                .ok_or(Error::NotFound)?,
        };
        let key = self
            .person_key(&connection, network, &person)?
            .ok_or(Error::NotFound)?;
        let policy = self
            .stored_policy(&connection, network, &key)?
            .ok_or(Error::NotFound)?;
        let expires_soon = policy.expires_soon(Utc::now());
        Ok(PolicyView {
            policy,
            expires_soon,
        })
    }
    /// Checks a policy before submission: the owner's signature, a current
    /// owner, and a version above the newest this host has verified.
    pub fn check_policy(&self, network: &str, p: &Policy) -> Result<(), Error> {
        let connection = self.connection()?;
        self.network_record(&connection, network)?;
        p.verify(network)?;
        if !p.in_window(Utc::now()) {
            return Err(invalid("the policy is not within its validity window"));
        }
        if self
            .person_key(&connection, network, &p.person_id())?
            .as_deref()
            != Some(p.person_public_key.as_str())
        {
            return Err(Error::Forbidden);
        }
        // An identical resubmission is passed on; the coordinator accepts it
        // again.
        if let Some(old) = self.stored_policy(&connection, network, &p.person_public_key)?
            && old.version >= p.version
            && old != *p
        {
            return Err(Error::Conflict(format!(
                "policy version {} is not above the newest verified version {}",
                p.version, old.version
            )));
        }
        Ok(())
    }
    /// Records a policy the coordinator accepted, unless a newer one is held.
    pub(crate) fn record_policy(&self, network: &str, p: &Policy) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if let Some(old) = self.stored_policy(&tx, network, &p.person_public_key)?
            && old.version >= p.version
        {
            return Ok(());
        }
        tx.execute(
            "INSERT OR REPLACE INTO network_statements VALUES (?1, 'policy', ?2, ?3)",
            params![network, p.person_public_key, serde_json::to_string(p)?],
        )?;
        append_event(&tx, "network.policy_updated", &p.person_id(), &now())?;
        tx.commit()?;
        Ok(())
    }
    /// The policies this host should renew: its own person's, in networks
    /// where less than a quarter of the validity remains.
    pub(crate) fn renewable_policies(&self) -> Result<Vec<Policy>, Error> {
        let connection = self.connection()?;
        let at = Utc::now();
        let mut out = Vec::new();
        for (network, own) in self.own_members(&connection)? {
            let Some(person) = &own.person_id else {
                continue;
            };
            let Some(key) = self.person_key(&connection, &network, person)? else {
                continue;
            };
            if let Some(p) = self.stored_policy(&connection, &network, &key)?
                && p.expires_soon(at)
                && time(&p.valid_until)? > at
            {
                out.push(p);
            }
        }
        Ok(out)
    }

    pub fn access_blocks(&self) -> Result<Vec<AccessBlock>, Error> {
        crate::peer_store::records(
            &*self.connection()?,
            "SELECT record FROM access_blocks ORDER BY kind, subject",
        )
    }
    /// Resolves a block request to `(kind, subject)`: a host ID, or a person
    /// given by ID, key, or unambiguous label in any network.
    fn block_subject(&self, r: &BlockRequest) -> Result<(String, String), Error> {
        match (&r.person, &r.host) {
            (Some(person), None) => {
                let connection = self.connection()?;
                let networks: Vec<String> = {
                    let mut statement = connection.prepare("SELECT id FROM networks")?;
                    statement
                        .query_map([], |r| r.get(0))?
                        .collect::<Result<_, _>>()?
                };
                let mut persons = Vec::new();
                for n in networks {
                    persons.extend(self.stored_persons(&connection, &n)?);
                }
                persons.sort_by(|a, b| a.person_id.cmp(&b.person_id));
                persons.dedup_by(|a, b| a.person_id == b.person_id);
                let id = match crate::admins::resolve_person(&persons, person) {
                    Ok(p) => p.person_id.clone(),
                    Err(Error::NotFound) if person_id_shape(person) => person.clone(),
                    Err(e) => return Err(e),
                };
                Ok(("person".into(), id))
            }
            (None, Some(host)) => {
                if !crate::peer_store::valid_id(host, "host", 32) {
                    return Err(invalid("invalid host ID"));
                }
                Ok(("host".into(), host.clone()))
            }
            _ => Err(invalid("give exactly one of person or host")),
        }
    }
    pub fn block(&self, r: BlockRequest) -> Result<AccessBlock, Error> {
        let (kind, subject) = self.block_subject(&r)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM access_blocks WHERE kind = ?1 AND subject = ?2",
                params![kind, subject],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            return json(old);
        }
        let block = AccessBlock {
            kind: kind.clone(),
            subject: subject.clone(),
            created_at: now(),
        };
        tx.execute(
            "INSERT INTO access_blocks VALUES (?1, ?2, ?3)",
            params![kind, subject, serde_json::to_string(&block)?],
        )?;
        append_event(&tx, "access.blocked", &subject, &block.created_at)?;
        tx.commit()?;
        Ok(block)
    }
    pub fn unblock(&self, r: BlockRequest) -> Result<AccessBlock, Error> {
        let (kind, subject) = self.block_subject(&r)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM access_blocks WHERE kind = ?1 AND subject = ?2",
                params![kind, subject],
                |r| r.get(0),
            )
            .optional()?;
        let Some(old) = old else {
            return Err(Error::NotFound);
        };
        tx.execute(
            "DELETE FROM access_blocks WHERE kind = ?1 AND subject = ?2",
            params![kind, subject],
        )?;
        append_event(&tx, "access.unblocked", &subject, &now())?;
        tx.commit()?;
        json(old)
    }
}

/// Renews this host's own person's policies that are close to expiry, by
/// asking the owner's `ssh-agent` (`run --person-agent`, or the daemon's
/// `SSH_AUTH_SOCK`) for a signature. Without an agent holding the key,
/// access lapses at `valid_until`. Several of an owner's hosts may renew at
/// once; the coordinator accepts one, and the others take it at the next sync.
pub(crate) async fn renew(store: Arc<Store>) {
    let socket = match store.person_agent.read() {
        Ok(guard) => guard.clone(),
        Err(_) => None,
    };
    let Some(socket) = socket else {
        return;
    };
    let due = blocking(store.clone(), |s| s.renewable_policies())
        .await
        .unwrap_or_default();
    for policy in due {
        let Ok(key) = crate::membership::canonical(&policy.person_public_key, 32) else {
            continue;
        };
        let Ok(key) = <[u8; 32]>::try_from(key) else {
            continue;
        };
        let signer = match PersonSigner::agent_at(socket.clone(), key) {
            Ok(signer) => signer,
            Err(_) => continue,
        };
        let renewed = match policy.renewal(&signer, Utc::now()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("policy renewal signing failed: {e}");
                continue;
            }
        };
        let network = policy.network_id.clone();
        match crate::network::submit_policy(store.clone(), network.clone(), renewed).await {
            Ok(_) => {}
            Err(Error::Conflict(_)) => {
                // Another of the owner's hosts renewed first.
                let _ = crate::network::sync_network(store.clone(), network).await;
            }
            Err(e) => eprintln!("policy renewal failed: {e}"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitPolicy {
    policy: Policy,
}
#[derive(Deserialize)]
struct PolicyQuery {
    #[serde(default)]
    person: Option<String>,
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/networks/{id}/policy",
            get(show_route).post(submit_route),
        )
        .route("/v1/access-blocks", get(blocks_route).post(block_route))
        .route("/v1/access-blocks/remove", post(unblock_route))
}
async fn show_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    Query(q): Query<PolicyQuery>,
) -> Result<Json<PolicyView>, Error> {
    Ok(Json(
        blocking(store, move |s| s.policy(&id, q.person.as_deref())).await?,
    ))
}
async fn submit_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Policy>), Error> {
    let request: SubmitPolicy = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(crate::network::submit_policy(store, id, request.policy).await?),
    ))
}
async fn blocks_route(State(store): State<Arc<Store>>) -> Result<Json<Vec<AccessBlock>>, Error> {
    Ok(Json(blocking(store, |s| s.access_blocks()).await?))
}
async fn block_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<AccessBlock>), Error> {
    let request: BlockRequest = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.block(request)).await?),
    ))
}
async fn unblock_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<AccessBlock>, Error> {
    let request: BlockRequest = decode(body)?;
    Ok(Json(blocking(store, move |s| s.unblock(request)).await?))
}

/// Merges a map's offered policies into the persisted ones: for each current
/// person, the highest version whose signature verifies. A lower version
/// never replaces a higher one.
pub(crate) fn verify_policies(
    network: &str,
    persons: &[String],
    persisted: Vec<Policy>,
    offered: Vec<serde_json::Value>,
) -> Vec<Policy> {
    let mut best: std::collections::BTreeMap<String, Policy> = std::collections::BTreeMap::new();
    for p in persisted {
        best.insert(p.person_public_key.clone(), p);
    }
    for p in offered
        .into_iter()
        .filter_map(|v| serde_json::from_value::<Policy>(v).ok())
    {
        if !persons.contains(&p.person_public_key) || p.verify(network).is_err() {
            continue;
        }
        if best
            .get(&p.person_public_key)
            .is_none_or(|old| old.version < p.version)
        {
            best.insert(p.person_public_key.clone(), p);
        }
    }
    best.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    const NETWORK: &str = "net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";
    const PERSON_SEED: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";
    const SECOND_ID: &str =
        "person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2";
    const POLICY_SIG: &str = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAy54wZKMJ5nBPfB3XakG7muQtkw2rjuhFVU+oWwluflHQKmEqNNa3l4MB1x5cdPmyXJduUMs9R24za8w4kW0bDg==";

    fn owner() -> PersonSigner {
        PersonSigner::File(ed25519_dalek::SigningKey::from_bytes(
            &STANDARD.decode(PERSON_SEED).unwrap().try_into().unwrap(),
        ))
    }
    fn rules() -> Vec<Rule> {
        vec![
            Rule {
                agent: "reviewer".into(),
                principals: vec![format!("person:{SECOND_ID}"), "group:backend".into()],
                actions: vec![ACTION.into()],
                max_message_bytes: 65536,
                allow_disconnected: false,
            },
            Rule {
                agent: "triage".into(),
                principals: vec!["network".into()],
                actions: vec![ACTION.into()],
                max_message_bytes: 4096,
                allow_disconnected: true,
            },
        ]
    }
    fn vector() -> Policy {
        Policy::sign(
            &owner(),
            NETWORK,
            1,
            "2026-10-10T00:00:00Z",
            "2026-10-17T00:00:00Z",
            rules(),
        )
        .unwrap()
    }

    #[test]
    fn policy_reproduces_the_vector_and_rejects_tampering() {
        let p = vector();
        assert_eq!(p.signature, POLICY_SIG);
        p.verify(NETWORK).unwrap();
        let encoded = serde_json::to_value(&p).unwrap();
        assert_eq!(
            encoded
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "issued_at",
                "network_id",
                "person_public_key",
                "rules",
                "signature",
                "valid_until",
                "version"
            ]
        );
        let mut t = p.clone();
        t.rules[0].max_message_bytes = 65535;
        assert!(t.verify(NETWORK).is_err());
        let mut t = p.clone();
        t.rules[1].principals = vec!["group:backend".into()];
        assert!(t.verify(NETWORK).is_err());
        let mut t = p.clone();
        t.version = 2;
        assert!(t.verify(NETWORK).is_err());
        let mut t = p.clone();
        t.rules.swap(0, 1);
        assert!(t.verify(NETWORK).is_err());
        assert!(p.verify(&format!("net_{}", "0".repeat(64))).is_err());
        assert!(serde_json::from_value::<Policy>(json_extra(&encoded)).is_err());
    }
    fn json_extra(v: &serde_json::Value) -> serde_json::Value {
        let mut v = v.clone();
        v["extra"] = serde_json::json!(1);
        v
    }

    #[test]
    fn shapes_and_windows_are_checked() {
        let sign = |issued: &str, until: &str, rules: Vec<Rule>| {
            Policy::sign(&owner(), NETWORK, 1, issued, until, rules)
        };
        assert!(sign("2026-10-10T00:00:00Z", "2026-10-10T23:59:59Z", rules()).is_err());
        assert!(sign("2026-10-10T00:00:00Z", "2027-01-08T00:00:01Z", rules()).is_err());
        sign("2026-10-10T00:00:00Z", "2027-01-08T00:00:00Z", rules()).unwrap();
        sign("2026-10-10T00:00:00Z", "2026-10-11T00:00:00Z", vec![]).unwrap();
        for bad in [
            Rule {
                principals: vec![],
                ..rules()[0].clone()
            },
            Rule {
                principals: vec!["person:bob".into()],
                ..rules()[0].clone()
            },
            Rule {
                principals: vec!["group:Backend".into()],
                ..rules()[0].clone()
            },
            Rule {
                actions: vec!["shell.exec".into()],
                ..rules()[0].clone()
            },
            Rule {
                max_message_bytes: 65537,
                ..rules()[0].clone()
            },
            Rule {
                agent: "bad\nname".into(),
                ..rules()[0].clone()
            },
        ] {
            assert!(sign("2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z", vec![bad]).is_err());
        }
        let too_many = vec![rules()[1].clone(); 65];
        assert!(sign("2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z", too_many).is_err());
        let p = vector();
        let at = |s: &str| time(s).unwrap();
        assert!(!p.in_window(at("2026-10-09T23:54:59Z")));
        assert!(p.in_window(at("2026-10-09T23:55:00Z")));
        assert!(p.in_window(at("2026-10-16T23:59:59Z")));
        assert!(!p.in_window(at("2026-10-17T00:00:00Z")));
        // A quarter of seven days is 42 hours.
        assert!(!p.expires_soon(at("2026-10-15T06:00:00Z")));
        assert!(p.expires_soon(at("2026-10-15T06:00:01Z")));
        let renewed = p.renewal(&owner(), at("2026-10-15T12:00:00Z")).unwrap();
        assert_eq!(renewed.version, 2);
        assert_eq!(renewed.rules, p.rules);
        assert_eq!(renewed.issued_at, "2026-10-15T12:00:00Z");
        assert_eq!(renewed.valid_until, "2026-10-22T12:00:00Z");
        renewed.verify(NETWORK).unwrap();
    }

    #[test]
    fn offered_policies_never_roll_back() {
        let v1 = vector();
        let v2 = v1
            .renewal(&owner(), time("2026-10-12T00:00:00Z").unwrap())
            .unwrap();
        let persons = vec![v1.person_public_key.clone()];
        let kept = verify_policies(
            NETWORK,
            &persons,
            vec![v2.clone()],
            vec![serde_json::to_value(&v1).unwrap()],
        );
        assert_eq!(kept, vec![v2.clone()]);
        let kept = verify_policies(
            NETWORK,
            &persons,
            vec![v1.clone()],
            vec![serde_json::to_value(&v2).unwrap()],
        );
        assert_eq!(kept, vec![v2.clone()]);
        // A forged or non-person policy is ignored.
        let mut forged = v2.clone();
        forged.version = 3;
        assert_eq!(
            verify_policies(
                NETWORK,
                &persons,
                vec![],
                vec![serde_json::to_value(&forged).unwrap()]
            ),
            vec![]
        );
        assert_eq!(
            verify_policies(
                NETWORK,
                &[],
                vec![],
                vec![serde_json::to_value(&v2).unwrap()]
            ),
            vec![]
        );
    }

    #[test]
    fn principals_have_three_shapes() {
        principal("network").unwrap();
        principal(&format!("person:{SECOND_ID}")).unwrap();
        principal("group:backend").unwrap();
        for bad in [
            "Network",
            "person:",
            "group:",
            "group:-x",
            "host:x",
            "person:person_abc",
        ] {
            assert!(principal(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn block_list_is_idempotent_and_persisted() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("host");
        let store = Store::open(&path).unwrap();
        let host = format!("host_{}", "a".repeat(64));
        let by_host = || BlockRequest {
            person: None,
            host: Some(host.clone()),
        };
        let first = store.block(by_host()).unwrap();
        assert_eq!(first.kind, "host");
        assert_eq!(store.block(by_host()).unwrap().created_at, first.created_at);
        let person = store
            .block(BlockRequest {
                person: Some(SECOND_ID.into()),
                host: None,
            })
            .unwrap();
        assert_eq!(
            (person.kind.as_str(), person.subject.as_str()),
            ("person", SECOND_ID)
        );
        assert!(
            store
                .block(BlockRequest {
                    person: Some("nobody".into()),
                    host: None,
                })
                .is_err()
        );
        assert!(
            store
                .block(BlockRequest {
                    person: Some(SECOND_ID.into()),
                    host: Some(host.clone()),
                })
                .is_err()
        );
        assert!(store.blocked(&store.connection().unwrap(), &host).unwrap());
        drop(store);
        let store = Store::open(&path).unwrap();
        let kinds: Vec<String> = store
            .access_blocks()
            .unwrap()
            .into_iter()
            .map(|b| b.kind)
            .collect();
        assert_eq!(kinds, ["host", "person"]);
        store.unblock(by_host()).unwrap();
        assert!(matches!(store.unblock(by_host()), Err(Error::NotFound)));
        assert!(!store.blocked(&store.connection().unwrap(), &host).unwrap());
    }

    #[test]
    fn requests_carry_exactly_one_authorization() {
        use crate::peer_store::OutboundMessage;
        let base = serde_json::json!({
            "request_id": format!("request_{}", "0".repeat(32)),
            "target_agent_id": format!("agent_{}", "0".repeat(32)),
            "deadline": "2026-10-10T00:00:00Z",
            "content": "hi",
            "policy": {"person_id": SECOND_ID, "version": 1},
        });
        let request: MessageRequest = serde_json::from_value(base.clone()).unwrap();
        assert!(request.grant_id.is_none());
        let wire = serde_json::to_value(&request).unwrap();
        assert!(wire.get("grant_id").is_none());
        let mut null = base.clone();
        null["grant_id"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MessageRequest>(null).is_err());
        let mut no_policy = base.clone();
        no_policy["policy"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MessageRequest>(no_policy).is_err());
        let record = OutboundMessage {
            peer_host_id: format!("host_{}", "a".repeat(64)),
            request,
            state: "unknown".into(),
            receipt: None,
            error: None,
            attempts: 0,
            next_attempt_at: None,
            receipt_queries: 0,
        };
        let shown = serde_json::to_value(&record).unwrap();
        assert!(
            shown["request"]["grant_id"].is_null() && shown["request"].get("grant_id").is_some()
        );
        let back: OutboundMessage = serde_json::from_value(shown).unwrap();
        assert_eq!(back.request, record.request);
    }
}
