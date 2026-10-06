//! Signed enrollment and the coordination client. Coordination distributes
//! membership chains and addresses; this host verifies every chain itself and
//! persists the verified map so known members keep working during outages.
use crate::{
    api::{blocking, decode},
    membership::{
        self, Attestation, ChainRelation, HostRevocation, InviteRevocation, InviteToken, Leave,
        Membership, Rotation,
    },
    model::Error,
    peer::{https, pinned_client_config},
    peer_store::{Peer, json, key_id, read, records},
    store::{Store, append_event, now, rfc3339},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use hyper::Method;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json as json_value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE networks (id TEXT PRIMARY KEY, record TEXT NOT NULL, root_seed BLOB);
CREATE TABLE network_members (network_id TEXT NOT NULL, host_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, host_id));
PRAGMA user_version = 3;
";
/// Database version 7: every verified root rotation, current attestation, and
/// sticky revocation per network.
pub(crate) const STATEMENT_SCHEMA: &str = "
CREATE TABLE network_statements (network_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, kind, subject));
PRAGMA user_version = 7;
";

const MAX_INVITE_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::days(30);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub root_public_key: String,
    pub member: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
    pub administrator: bool,
    pub last_sync_at: Option<String>,
    pub last_sync_error: Option<String>,
    /// Epoch of the current root; 0 until the root is rotated.
    #[serde(default)]
    pub root_epoch: u64,
    /// The current root, which signs new invites, revocations, and
    /// attestations. `root_public_key` stays the genesis key that derives `id`.
    #[serde(default)]
    pub current_root_public_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub host_id: String,
    pub public_key: String,
    pub member: String,
    pub address: String,
    /// Path-discovery hints published by the member; never dial addresses.
    #[serde(default)]
    pub candidates: Vec<String>,
    pub updated_at: String,
    pub membership: Membership,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNetwork {
    pub name: String,
    pub member: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvite {
    pub member: String,
    pub expires_at: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinNetwork {
    pub token: String,
}
#[derive(Debug, Serialize)]
pub struct IssuedInvite {
    pub network_id: String,
    pub member: String,
    pub invite_public_key: String,
    pub invite_expires_at: String,
    pub token: String,
}
#[derive(Deserialize)]
struct WireMap {
    network_id: String,
    root_public_key: String,
    members: Vec<Value>,
    #[serde(default)]
    rotations: Vec<Value>,
    #[serde(default)]
    attestations: Vec<Value>,
    #[serde(default)]
    revocations: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub invite_public_key: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct Revoked {
    pub network_id: String,
    pub kind: String,
    pub subject: String,
    pub submitted: bool,
}
#[derive(Debug, Serialize)]
pub struct Left {
    pub network_id: String,
    pub submitted: bool,
}

/// A signed rotation not yet accepted by the coordinator, persisted before
/// submission as `network_statements` kind `pending_rotation` (subject: the
/// epoch). `root_seed` is the new root's seed in standard Base64; the state
/// directory protects it like `networks.root_seed`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PendingRotation {
    rotation: Rotation,
    attestations: Vec<Attestation>,
    root_seed: String,
}
#[derive(Debug)]
enum PendingOutcome {
    None,
    Committed,
    Discarded,
    Resubmit(PendingRotation),
}

/// Every verified statement this host holds for one network.
#[derive(Default)]
struct Statements {
    rotations: Vec<Rotation>,
    attestations: Vec<Attestation>,
    hosts: Vec<HostRevocation>,
    invites: Vec<InviteRevocation>,
    leaves: Vec<Leave>,
}
impl Statements {
    fn load(connection: &Connection, network: &str) -> Result<Self, Error> {
        let mut statement = connection.prepare(
            "SELECT kind, subject, record FROM network_statements WHERE network_id = ?1",
        )?;
        let rows = statement
            .query_map([network], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Self::default();
        for (kind, _, record) in rows {
            match kind.as_str() {
                "rotation" => out.rotations.push(json(record)?),
                "attestation" => out.attestations.push(json(record)?),
                "host" => out.hosts.push(json(record)?),
                "invite" => out.invites.push(json(record)?),
                "leave" => out.leaves.push(json(record)?),
                _ => {}
            }
        }
        out.rotations.sort_by_key(|r| r.epoch);
        Ok(out)
    }
}
/// A map verified against this host's persisted statements.
struct VerifiedMap {
    members: Vec<Member>,
    rotations: Vec<Rotation>,
    roots: Vec<String>,
    statements: Statements,
}
fn insert_statement(
    tx: &Connection,
    network: &str,
    kind: &str,
    subject: &str,
    record: &impl Serialize,
) -> Result<bool, Error> {
    Ok(tx.execute(
        "INSERT OR IGNORE INTO network_statements VALUES (?1, ?2, ?3, ?4)",
        params![network, kind, subject, serde_json::to_string(record)?],
    )? > 0)
}
#[derive(Deserialize)]
struct WireMember {
    host_id: String,
    membership: Membership,
    address: String,
    #[serde(default)]
    candidates: Value,
    updated_at: String,
}

/// Keeps at most `MAX_ENDPOINTS` distinct literal `IP:PORT` candidates with
/// nonzero ports; anything else is dropped rather than the member.
fn valid_candidates(value: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in value.as_array().into_iter().flatten() {
        let Some(text) = item.as_str() else {
            continue;
        };
        match text.parse::<std::net::SocketAddr>() {
            Ok(addr) if addr.port() != 0 && !out.iter().any(|c| c == text) => {
                out.push(text.to_owned())
            }
            _ => {}
        }
        if out.len() == crate::disco::MAX_ENDPOINTS {
            break;
        }
    }
    out
}

fn random_seed() -> Result<SigningKey, Error> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn load_member_pins(
    connection: &Connection,
    self_id: &str,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let members = records::<Member>(connection, "SELECT record FROM network_members")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut pins = BTreeMap::new();
    for m in members.into_iter().filter(|m| m.host_id != self_id) {
        let key = membership::canonical(&m.public_key, 32).map_err(|e| anyhow::anyhow!("{e}"))?;
        if key_id(&key) != m.host_id {
            anyhow::bail!("persisted network member key does not match its ID");
        }
        pins.insert(m.host_id, key);
    }
    Ok(pins)
}

/// Verifies a coordinator map against this host's persisted statements.
///
/// The root chain must equal or extend the persisted one; a fork or a stale
/// chain is refused. Revocations from the map are added to the persisted ones
/// (sticky) when they verify under any root in the chain. At epoch 0 a member
/// is valid by its invite chain under the genesis root; after a rotation only
/// an invite chain under the current root or a current-epoch attestation
/// counts. Entries whose chain fails, whose ID mismatches, whose key or invite
/// is revoked, or whose invite key was used by more than one host key are
/// dropped. A forged member cannot be introduced without the invite secret.
fn verify_map(
    network: &Network,
    map: WireMap,
    persisted: Statements,
) -> Result<VerifiedMap, Error> {
    if map.network_id != network.id || map.root_public_key != network.root_public_key {
        return Err(Error::Unavailable(
            "coordinator map does not match this network".into(),
        ));
    }
    let offered: Vec<Rotation> = map
        .rotations
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|_| Error::Unavailable("malformed root chain".into()))?;
    let roots = membership::verify_chain(&network.id, &network.root_public_key, &offered)
        .map_err(|_| Error::Unavailable("invalid root chain".into()))?;
    match membership::chain_relation(&persisted.rotations, &offered) {
        ChainRelation::Fork => return Err(Error::Unavailable("root chain conflict".into())),
        ChainRelation::Behind => {
            return Err(Error::Unavailable(
                "coordinator root chain is behind this host".into(),
            ));
        }
        ChainRelation::Extends => {}
    }
    let epoch = (roots.len() - 1) as u64;
    let current = roots.last().expect("chain has a genesis root").clone();
    let mut statements = persisted;
    // Attestations only count for the current epoch, under the current root.
    let mut attestations: Vec<Attestation> = Vec::new();
    for a in statements.attestations.drain(..).chain(
        map.attestations
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok()),
    ) {
        if a.verify(&network.id, epoch, &current).is_ok()
            && !attestations
                .iter()
                .any(|b| b.host_public_key == a.host_public_key)
        {
            attestations.push(a);
        }
    }
    statements.attestations = attestations;
    for entry in map.revocations {
        let kind = entry["kind"].as_str().unwrap_or_default().to_owned();
        let statement = entry["statement"].clone();
        match kind.as_str() {
            "host" => {
                if let Ok(r) = serde_json::from_value::<HostRevocation>(statement)
                    && r.verify(&network.id, &roots).is_ok()
                    && !statements
                        .hosts
                        .iter()
                        .any(|h| h.host_public_key == r.host_public_key)
                {
                    statements.hosts.push(r);
                }
            }
            "invite" => {
                if let Ok(r) = serde_json::from_value::<InviteRevocation>(statement)
                    && r.verify(&network.id, &roots).is_ok()
                    && !statements
                        .invites
                        .iter()
                        .any(|i| i.invite_public_key == r.invite_public_key)
                {
                    statements.invites.push(r);
                }
            }
            "leave" => {
                if let Ok(r) = serde_json::from_value::<Leave>(statement)
                    && r.verify(&network.id).is_ok()
                    && !statements
                        .leaves
                        .iter()
                        .any(|l| l.host_public_key == r.host_public_key)
                {
                    statements.leaves.push(r);
                }
            }
            _ => {}
        }
    }
    let revoked_hosts: BTreeSet<&str> = statements
        .hosts
        .iter()
        .map(|h| h.host_public_key.as_str())
        .chain(statements.leaves.iter().map(|l| l.host_public_key.as_str()))
        .collect();
    let revoked_invites: BTreeSet<&str> = statements
        .invites
        .iter()
        .map(|i| i.invite_public_key.as_str())
        .collect();
    let attested: BTreeSet<&str> = statements
        .attestations
        .iter()
        .map(|a| a.host_public_key.as_str())
        .collect();
    let mut candidates = Vec::new();
    for entry in map.members {
        let Ok(entry) = serde_json::from_value::<WireMember>(entry) else {
            continue;
        };
        let m = &entry.membership;
        if m.network_id != network.id
            || revoked_hosts.contains(m.host_public_key.as_str())
            || revoked_invites.contains(m.invite_public_key.as_str())
        {
            continue;
        }
        let verified = if epoch == 0 {
            m.verify(&network.root_public_key)
        } else {
            m.verify_under(&current).or_else(|error| {
                if attested.contains(m.host_public_key.as_str()) {
                    roots
                        .iter()
                        .find_map(|root| m.verify_under(root).ok())
                        .ok_or(error)
                } else {
                    Err(error)
                }
            })
        };
        let Ok(host_id) = verified else {
            continue;
        };
        if host_id != entry.host_id {
            continue;
        }
        let address = if membership::advertised(&entry.address).is_ok() {
            entry.address
        } else {
            String::new()
        };
        candidates.push(Member {
            host_id,
            public_key: entry.membership.host_public_key.clone(),
            member: entry.membership.member.clone(),
            address,
            candidates: valid_candidates(&entry.candidates),
            updated_at: entry.updated_at,
            membership: entry.membership,
        });
    }
    let mut invite_hosts: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut host_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in &candidates {
        invite_hosts
            .entry(&m.membership.invite_public_key)
            .or_default()
            .insert(&m.host_id);
        *host_counts.entry(&m.host_id).or_default() += 1;
    }
    let rejected: BTreeSet<String> = candidates
        .iter()
        .filter(|m| {
            invite_hosts[m.membership.invite_public_key.as_str()].len() > 1
                || host_counts[m.host_id.as_str()] > 1
        })
        .map(|m| m.host_id.clone())
        .collect();
    let mut members: Vec<Member> = candidates
        .into_iter()
        .filter(|m| !rejected.contains(&m.host_id))
        .collect();
    members.sort_by(|a, b| a.host_id.cmp(&b.host_id));
    Ok(VerifiedMap {
        members,
        rotations: offered,
        roots,
        statements,
    })
}

fn time_after(a: &str, b: &str) -> bool {
    match (membership::time(a), membership::time(b)) {
        (Ok(a), Ok(b)) => a > b,
        (Ok(_), Err(_)) => true,
        _ => false,
    }
}

impl Store {
    fn network_record(&self, connection: &Connection, id: &str) -> Result<Network, Error> {
        let (record, administrator): (String, bool) = connection.query_row(
            "SELECT record, root_seed IS NOT NULL FROM networks WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let mut network: Network = json(record)?;
        network.administrator = administrator;
        if network.current_root_public_key.is_empty() {
            network
                .current_root_public_key
                .clone_from(&network.root_public_key);
        }
        Ok(network)
    }
    pub fn networks(&self) -> Result<Vec<Network>, Error> {
        let connection = self.connection()?;
        let ids = {
            let mut statement = connection.prepare("SELECT id FROM networks ORDER BY id")?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.iter()
            .map(|id| self.network_record(&connection, id))
            .collect()
    }
    pub fn network(&self, id: &str) -> Result<Network, Error> {
        self.network_record(&*self.connection()?, id)
    }
    pub fn members(&self, id: &str) -> Result<Vec<Member>, Error> {
        let connection = self.connection()?;
        self.network_record(&connection, id)?;
        let mut statement = connection
            .prepare("SELECT record FROM network_members WHERE network_id = ?1 ORDER BY host_id")?;
        statement
            .query_map([id], |r| r.get::<_, String>(0))?
            .map(|r| json(r?))
            .collect()
    }
    /// True if the key belongs to a manual peer or a verified network member.
    pub(crate) fn knows(&self, key: &[u8]) -> Result<bool, Error> {
        let id = key_id(key);
        let poisoned = || Error::Internal(anyhow::anyhow!("peer pins lock poisoned"));
        let pinned =
            |pins: &BTreeMap<String, Vec<u8>>| pins.get(&id).map(Vec::as_slice) == Some(key);
        Ok(pinned(&*self.peer_pins.read().map_err(|_| poisoned())?)
            || pinned(&*self.member_pins.read().map_err(|_| poisoned())?))
    }
    pub(crate) fn known_host(&self, connection: &Connection, id: &str) -> Result<bool, Error> {
        let count: i64 = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM peers WHERE id = ?1) + (SELECT COUNT(*) FROM network_members WHERE host_id = ?1 AND host_id != ?2)",
            params![id, self.identity().id],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }
    /// Coordination counts as connected for a requester that is a member of a
    /// network this host synced within three coordination intervals.
    pub(crate) fn connected(&self, connection: &Connection, host: &str) -> Result<bool, Error> {
        if host == self.identity().id {
            return Ok(false);
        }
        let window = chrono::TimeDelta::seconds(
            3 * self.coordination_interval.load(Ordering::Relaxed) as i64,
        );
        let mut statement = connection.prepare(
            "SELECT n.record FROM networks n JOIN network_members m ON m.network_id = n.id WHERE m.host_id = ?1",
        )?;
        let networks = statement
            .query_map([host], |r| r.get::<_, String>(0))?
            .map(|r| json::<Network>(r?))
            .collect::<Result<Vec<_>, _>>()?;
        let at = chrono::Utc::now();
        Ok(networks.iter().any(|n| {
            n.last_sync_at
                .as_deref()
                .and_then(|t| membership::time(t).ok())
                .is_some_and(|t| at - t <= window)
        }))
    }
    /// A manual peer's address takes precedence; otherwise the member entry with
    /// the latest update and a nonempty address. Members without an address are
    /// returned with an empty one, so a send records an unknown outcome.
    pub fn dial_target(&self, id: &str) -> Result<Peer, Error> {
        let connection = self.connection()?;
        if let Some(record) = connection
            .query_row("SELECT record FROM peers WHERE id = ?1", [id], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
        {
            return json(record);
        }
        if id == self.identity().id {
            return Err(Error::NotFound);
        }
        let mut statement =
            connection.prepare("SELECT record FROM network_members WHERE host_id = ?1")?;
        let members = statement
            .query_map([id], |r| r.get::<_, String>(0))?
            .map(|r| json::<Member>(r?))
            .collect::<Result<Vec<_>, _>>()?;
        let best = members
            .into_iter()
            .fold(None::<Member>, |best, m| match best {
                None => Some(m),
                Some(b) => {
                    let better = (!m.address.is_empty() && b.address.is_empty())
                        || (m.address.is_empty() == b.address.is_empty()
                            && time_after(&m.updated_at, &b.updated_at));
                    Some(if better { m } else { b })
                }
            });
        let m = best.ok_or(Error::NotFound)?;
        Ok(Peer {
            id: m.host_id,
            public_key: m.public_key,
            address: m.address,
        })
    }
    /// The relay for `host`: the coordinator of the lowest-ID network that both
    /// this host and `host` belong to, or none if they share no network.
    pub(crate) fn relay_coordinator(&self, host: &str) -> Result<Option<(String, String)>, Error> {
        if host == self.identity().id {
            return Ok(None);
        }
        let record: Option<String> = self
            .connection()?
            .query_row(
                "SELECT n.record FROM networks n JOIN network_members m ON m.network_id = n.id WHERE m.host_id = ?1 ORDER BY n.id LIMIT 1",
                [host],
                |r| r.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            return Ok(None);
        };
        let value: Value = serde_json::from_str(&record).map_err(|e| Error::Internal(e.into()))?;
        let field = |name: &str| value[name].as_str().map(str::to_owned);
        Ok(field("coordinator_address").zip(field("coordinator_public_key")))
    }
    /// Every coordinator of a network this host belongs to.
    pub(crate) fn coordinators(&self) -> Result<Vec<(String, String)>, Error> {
        let mut all: Vec<_> = self
            .networks()?
            .into_iter()
            .map(|n| (n.coordinator_address, n.coordinator_public_key))
            .collect();
        all.sort();
        all.dedup();
        Ok(all)
    }
    fn refresh_member_pins(&self, connection: &Connection) -> Result<(), Error> {
        let pins = load_member_pins(connection, &self.identity().id).map_err(Error::Internal)?;
        *self
            .member_pins
            .write()
            .map_err(|_| Error::Internal(anyhow::anyhow!("member pins lock poisoned")))? = pins;
        Ok(())
    }
    pub fn set_coordination_interval(&self, seconds: u64) {
        self.coordination_interval.store(seconds, Ordering::Relaxed);
    }
    pub fn set_advertised(&self, address: String) {
        if let Ok(mut advertise) = self.advertise.write() {
            *advertise = address;
        }
    }
    fn advertised(&self) -> String {
        self.advertise.read().map(|a| a.clone()).unwrap_or_default()
    }
    /// The candidates this host most recently published.
    pub(crate) fn published_candidates(&self) -> Vec<std::net::SocketAddr> {
        self.candidates
            .read()
            .map(|c| c.clone())
            .unwrap_or_default()
    }
    /// A member's published candidates across this host's networks, and its
    /// advertised direct addresses, which path discovery never reroutes.
    pub(crate) fn member_candidates(
        &self,
        host: &str,
    ) -> Result<(Vec<std::net::SocketAddr>, Vec<std::net::SocketAddr>), Error> {
        if host == self.identity().id {
            return Ok((Vec::new(), Vec::new()));
        }
        let connection = self.connection()?;
        let manual: Option<String> = connection
            .query_row("SELECT record FROM peers WHERE id = ?1", [host], |r| {
                r.get(0)
            })
            .optional()?;
        let mut statement =
            connection.prepare("SELECT record FROM network_members WHERE host_id = ?1")?;
        let members = statement
            .query_map([host], |r| r.get::<_, String>(0))?
            .map(|r| json::<Member>(r?))
            .collect::<Result<Vec<_>, _>>()?;
        let mut candidates = Vec::new();
        let mut advertised = Vec::new();
        if let Some(record) = manual {
            let peer: Peer = json(record)?;
            if let Ok(addr) = peer.address.parse() {
                advertised.push(crate::disco::normalize(addr));
            }
        }
        for m in members {
            if let Ok(addr) = m.address.parse() {
                advertised.push(crate::disco::normalize(addr));
            }
            for c in m.candidates.iter().filter_map(|c| c.parse().ok()) {
                let c = crate::disco::normalize(c);
                if !candidates.contains(&c) {
                    candidates.push(c);
                }
            }
        }
        Ok((candidates, advertised))
    }

    pub fn create_network(&self, r: CreateNetwork) -> Result<Network, Error> {
        membership::label(&r.name)?;
        membership::label(&r.member)?;
        membership::split_host_port(&r.coordinator_address)?;
        membership::public_key(&r.coordinator_public_key)?;
        let root = random_seed()?;
        let invite = random_seed()?;
        let joined = now();
        let expires = rfc3339(chrono::Utc::now() + MAX_INVITE_LIFETIME);
        let signed = membership::sign_invite(&root, &invite, &r.member, &expires);
        let own = membership::sign_member(
            signed,
            &invite,
            self.signing_key.verifying_key().as_bytes(),
            &joined,
        );
        let network = Network {
            id: own.network_id.clone(),
            name: r.name,
            root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            member: r.member,
            coordinator_address: r.coordinator_address,
            coordinator_public_key: r.coordinator_public_key,
            administrator: true,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
        };
        let me = Member {
            host_id: self.identity().id,
            public_key: own.host_public_key.clone(),
            member: own.member.clone(),
            address: self.advertised(),
            candidates: Vec::new(),
            updated_at: joined.clone(),
            membership: own,
        };
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute(
            "INSERT INTO networks VALUES (?1, ?2, ?3)",
            params![
                network.id,
                serde_json::to_string(&network)?,
                root.to_bytes().to_vec()
            ],
        )?;
        tx.execute(
            "INSERT INTO network_members VALUES (?1, ?2, ?3)",
            params![network.id, me.host_id, serde_json::to_string(&me)?],
        )?;
        append_event(&tx, "network.created", &network.id, &joined)?;
        tx.commit()?;
        Ok(network)
    }

    pub fn issue_invite(&self, id: &str, r: CreateInvite) -> Result<IssuedInvite, Error> {
        membership::label(&r.member)?;
        let expires = membership::time(&r.expires_at)?;
        let at = chrono::Utc::now();
        if expires <= at || expires > at + MAX_INVITE_LIFETIME {
            return Err(Error::Invalid(
                "invite expiry must be in the future and at most 30 days ahead".into(),
            ));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let seed: Option<Vec<u8>> =
            tx.query_row("SELECT root_seed FROM networks WHERE id = ?1", [id], |r| {
                r.get(0)
            })?;
        let root: [u8; 32] = seed
            .ok_or(Error::Forbidden)?
            .try_into()
            .map_err(|_| Error::Internal(anyhow::anyhow!("invalid persisted root seed")))?;
        let root = SigningKey::from_bytes(&root);
        let invite = random_seed()?;
        let signed =
            membership::sign_invite_for(&network.id, &root, &invite, &r.member, &r.expires_at);
        let token = InviteToken {
            network_id: network.id.clone(),
            network_name: network.name,
            // The current root signed the invite; after a rotation it no longer
            // derives the network ID, and the joiner checks it against the chain.
            root_public_key: network.current_root_public_key,
            coordinator_address: network.coordinator_address,
            coordinator_public_key: network.coordinator_public_key,
            member: signed.member.clone(),
            invite_public_key: signed.invite_public_key.clone(),
            invite_seed: STANDARD.encode(invite.to_bytes()),
            invite_expires_at: signed.invite_expires_at.clone(),
            invite_signature: signed.invite_signature,
        };
        append_event(&tx, "network.invite_issued", &network.id, &now())?;
        tx.commit()?;
        Ok(IssuedInvite {
            network_id: network.id,
            member: signed.member,
            invite_public_key: signed.invite_public_key,
            invite_expires_at: signed.invite_expires_at,
            token: token.encode(),
        })
    }

    /// Replaces a network's verified member set with a coordinator map and
    /// persists the union of verified statements. When `joined` is set, the
    /// network itself is inserted in the same transaction.
    fn apply_map(&self, network: Network, map: WireMap, joined: bool) -> Result<Network, Error> {
        // The first accepted map (a join, or a created network's registration)
        // means the coordinator now knows this host, so its relay will accept it.
        let first = joined || network.last_sync_at.is_none();
        let own_id = self.identity().id;
        let own_key = STANDARD.encode(self.signing_key.verifying_key().as_bytes());
        let at = now();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let persisted = if joined {
            Statements::default()
        } else {
            Statements::load(&tx, &network.id)?
        };
        let verified = verify_map(&network, map, persisted)?;
        let mut members = verified.members;
        if !members.iter().any(|m| m.host_id == own_id) {
            return Err(Error::Unavailable("coordinator map omits this host".into()));
        }
        let mut network = if joined {
            let exists: i64 = tx.query_row(
                "SELECT COUNT(*) FROM networks WHERE id = ?1",
                [&network.id],
                |r| r.get(0),
            )?;
            if exists != 0 {
                return Err(Error::Conflict("network already joined".into()));
            }
            tx.execute(
                "INSERT INTO networks VALUES (?1, ?2, NULL)",
                params![network.id, serde_json::to_string(&network)?],
            )?;
            append_event(&tx, "network.joined", &network.id, &at)?;
            network
        } else {
            self.network_record(&tx, &network.id)?
        };
        let id = network.id.clone();
        for rotation in &verified.rotations {
            insert_statement(&tx, &id, "rotation", &rotation.epoch.to_string(), rotation)?;
        }
        // Only the current epoch's attestations are kept.
        tx.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'attestation'",
            [&id],
        )?;
        let statements = verified.statements;
        for a in &statements.attestations {
            insert_statement(&tx, &id, "attestation", &a.host_public_key, a)?;
        }
        for r in &statements.hosts {
            insert_statement(&tx, &id, "host", &r.host_public_key, r)?;
        }
        for r in &statements.invites {
            insert_statement(&tx, &id, "invite", &r.invite_public_key, r)?;
        }
        for r in &statements.leaves {
            if insert_statement(&tx, &id, "leave", &r.host_public_key, r)?
                && r.host_public_key != own_key
                && let Ok(key) = membership::canonical(&r.host_public_key, 32)
            {
                append_event(&tx, "network.member_left", &key_id(&key), &at)?;
            }
        }
        let old: BTreeSet<String> = {
            let mut statement =
                tx.prepare("SELECT host_id FROM network_members WHERE network_id = ?1")?;
            statement
                .query_map([&id], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?
        };
        tx.execute("DELETE FROM network_members WHERE network_id = ?1", [&id])?;
        for m in &mut members {
            if m.host_id == own_id {
                // The coordinator's address for us may lag; record our own.
                m.address = self.advertised();
                m.candidates = self
                    .published_candidates()
                    .iter()
                    .map(ToString::to_string)
                    .collect();
            }
            tx.execute(
                "INSERT INTO network_members VALUES (?1, ?2, ?3)",
                params![id, m.host_id, serde_json::to_string(&m)?],
            )?;
        }
        let new: BTreeSet<String> = members.into_iter().map(|m| m.host_id).collect();
        for added in new.difference(&old).filter(|id| **id != own_id) {
            append_event(&tx, "network.member_added", added, &at)?;
        }
        for removed in old.difference(&new).filter(|id| **id != own_id) {
            append_event(&tx, "network.member_removed", removed, &at)?;
        }
        network.root_epoch = (verified.roots.len() - 1) as u64;
        network.current_root_public_key = verified.roots.last().cloned().unwrap_or_default();
        network.last_sync_at = Some(at);
        network.last_sync_error = None;
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, id],
        )?;
        tx.commit()?;
        self.refresh_member_pins(&connection)?;
        if first {
            self.relay_wake.notify_one();
        }
        Ok(network)
    }

    /// The current root seed of a network this host administers.
    fn current_root(&self, connection: &Connection, id: &str) -> Result<SigningKey, Error> {
        let seed: Option<Vec<u8>> =
            connection.query_row("SELECT root_seed FROM networks WHERE id = ?1", [id], |r| {
                r.get(0)
            })?;
        let seed: [u8; 32] = seed
            .ok_or(Error::Forbidden)?
            .try_into()
            .map_err(|_| Error::Internal(anyhow::anyhow!("invalid persisted root seed")))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Signs and persists a revocation with the current root, enforced locally
    /// at once. Returns the response and the `{kind, statement}` to submit.
    pub fn revoke(&self, id: &str, r: Revoke) -> Result<(Revoked, Value), Error> {
        let (kind, subject) = match (r.host_id, r.invite_public_key) {
            (Some(host), None) => ("host", host),
            (None, Some(invite)) => ("invite", invite),
            _ => {
                return Err(Error::Invalid(
                    "give exactly one of host_id or invite_public_key".into(),
                ));
            }
        };
        let at = now();
        let own_id = self.identity().id;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let root = self.current_root(&tx, id)?;
        let members: Vec<Member> = {
            let mut statement =
                tx.prepare("SELECT record FROM network_members WHERE network_id = ?1")?;
            statement
                .query_map([id], |r| r.get::<_, String>(0))?
                .map(|r| json(r?))
                .collect::<Result<_, _>>()?
        };
        let (key, statement, dropped) = if kind == "host" {
            if subject == own_id {
                return Err(Error::Conflict("cannot revoke this host itself".into()));
            }
            let key = match members.iter().find(|m| m.host_id == subject) {
                Some(m) => m.public_key.clone(),
                None => Statements::load(&tx, id)?
                    .hosts
                    .into_iter()
                    .map(|h| h.host_public_key)
                    .find(|k| membership::canonical(k, 32).is_ok_and(|b| key_id(&b) == subject))
                    .ok_or(Error::NotFound)?,
            };
            let statement = HostRevocation::sign(&root, &network.id, &key, &at);
            (key, serde_json::to_value(statement)?, vec![subject.clone()])
        } else {
            membership::public_key(&subject)?;
            if members
                .iter()
                .any(|m| m.host_id == own_id && m.membership.invite_public_key == subject)
            {
                return Err(Error::Conflict(
                    "cannot revoke the invite this host joined with".into(),
                ));
            }
            let statement = InviteRevocation::sign(&root, &network.id, &subject, &at);
            let dropped = members
                .iter()
                .filter(|m| m.membership.invite_public_key == subject)
                .map(|m| m.host_id.clone())
                .collect();
            (subject.clone(), serde_json::to_value(statement)?, dropped)
        };
        let existing: Option<String> = tx
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = ?2 AND subject = ?3",
                params![id, kind, key],
                |r| r.get(0),
            )
            .optional()?;
        let statement = match existing {
            Some(record) => serde_json::from_str(&record)?,
            None => {
                tx.execute(
                    "INSERT INTO network_statements VALUES (?1, ?2, ?3, ?4)",
                    params![id, kind, key, serde_json::to_string(&statement)?],
                )?;
                let event_subject = if kind == "host" { &subject } else { &key };
                append_event(&tx, &format!("network.{kind}_revoked"), event_subject, &at)?;
                statement
            }
        };
        for host in &dropped {
            if tx.execute(
                "DELETE FROM network_members WHERE network_id = ?1 AND host_id = ?2",
                params![id, host],
            )? > 0
            {
                append_event(&tx, "network.member_removed", host, &at)?;
            }
        }
        tx.commit()?;
        self.refresh_member_pins(&connection)?;
        Ok((
            Revoked {
                network_id: network.id,
                kind: kind.into(),
                subject: key,
                submitted: false,
            },
            json_value!({"kind": kind, "statement": statement}),
        ))
    }

    /// This host's own revocations of a kind the coordinator has not yet listed.
    fn pending_revocations(
        &self,
        id: &str,
        listed: &BTreeSet<(String, String)>,
    ) -> Result<Vec<Value>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT kind, subject, record FROM network_statements WHERE network_id = ?1 AND kind IN ('host', 'invite')",
        )?;
        let rows = statement
            .query_map([id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter(|(kind, subject, _)| !listed.contains(&(kind.clone(), subject.clone())))
            .filter_map(|(kind, _, record)| {
                let statement: Value = serde_json::from_str(&record).ok()?;
                Some(json_value!({"kind": kind, "statement": statement}))
            })
            .collect())
    }

    /// Removes a network and everything learned from it, with `network.left`.
    fn forget_network(&self, id: &str) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        self.network_record(&tx, id)?;
        tx.execute("DELETE FROM network_members WHERE network_id = ?1", [id])?;
        tx.execute("DELETE FROM network_statements WHERE network_id = ?1", [id])?;
        tx.execute("DELETE FROM networks WHERE id = ?1", [id])?;
        append_event(&tx, "network.left", id, &now())?;
        tx.commit()?;
        self.refresh_member_pins(&connection)
    }

    /// The rotation this administrator has signed but not yet seen accepted.
    fn pending_rotation(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Option<PendingRotation>, Error> {
        connection
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'pending_rotation' ORDER BY CAST(subject AS INTEGER) DESC LIMIT 1",
                [id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(json)
            .transpose()
    }

    /// Returns the pending rotation, creating and persisting one first if none
    /// exists. The old root stays current locally until the coordinator
    /// accepts, so a crash after acceptance can always be completed.
    fn prepare_rotation(&self, id: &str) -> Result<(Network, PendingRotation), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let network = self.network_record(&tx, id)?;
        let root = self.current_root(&tx, id)?;
        if let Some(pending) = self.pending_rotation(&tx, id)? {
            return Ok((network, pending));
        }
        let epoch = Statements::load(&tx, id)?.rotations.len() as u64 + 1;
        let next = random_seed()?;
        let next_key = STANDARD.encode(next.verifying_key().as_bytes());
        let at = now();
        let rotation = Rotation::sign(&root, id, epoch, &next_key, &at);
        let attestations = {
            let mut statement = tx.prepare(
                "SELECT record FROM network_members WHERE network_id = ?1 ORDER BY host_id",
            )?;
            statement
                .query_map([id], |r| r.get::<_, String>(0))?
                .map(|r| json::<Member>(r?))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|m| Attestation::sign(&next, id, epoch, &m.public_key, &m.member, &at))
                .collect()
        };
        let pending = PendingRotation {
            rotation,
            attestations,
            root_seed: STANDARD.encode(next.to_bytes()),
        };
        insert_statement(&tx, id, "pending_rotation", &epoch.to_string(), &pending)?;
        tx.commit()?;
        Ok((network, pending))
    }

    /// Makes an accepted pending rotation current, atomically: the new root
    /// seed, the rotation, and the new epoch's attestations, with
    /// `network.root_rotated`. A no-op if the rotation is already current.
    fn commit_rotation(&self, id: &str, pending: &PendingRotation) -> Result<(), Error> {
        let next: [u8; 32] = membership::canonical(&pending.root_seed, 32)?
            .try_into()
            .expect("checked length");
        let rotation = &pending.rotation;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut network = self.network_record(&tx, id)?;
        tx.execute(
            "UPDATE networks SET root_seed = ?1 WHERE id = ?2",
            params![next.to_vec(), id],
        )?;
        insert_statement(&tx, id, "rotation", &rotation.epoch.to_string(), rotation)?;
        tx.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind IN ('attestation', 'pending_rotation')",
            [id],
        )?;
        for a in &pending.attestations {
            insert_statement(&tx, id, "attestation", &a.host_public_key, a)?;
        }
        network.root_epoch = rotation.epoch;
        network.current_root_public_key = rotation.root_public_key.clone();
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, id],
        )?;
        append_event(&tx, "network.root_rotated", id, &now())?;
        tx.commit()?;
        Ok(())
    }

    /// Drops a pending rotation that can no longer be accepted.
    fn discard_rotation(&self, id: &str) -> Result<(), Error> {
        self.connection()?.execute(
            "DELETE FROM network_statements WHERE network_id = ?1 AND kind = 'pending_rotation'",
            [id],
        )?;
        Ok(())
    }
    /// Drops a pending rotation the coordinator rejected for good, recording
    /// `root rotation discarded: REASON` as the network's sync error.
    fn discard_rotation_with_error(&self, id: &str, reason: &str) -> Result<Network, Error> {
        self.discard_rotation(id)?;
        self.record_sync_error(id, format!("root rotation discarded: {reason}"))
    }

    /// Decides what to do with a pending rotation given the chain a
    /// coordinator served: commit it if the chain already holds it (the
    /// coordinator accepted it before a crash), discard it if the chain has a
    /// different rotation at that epoch or has moved past it, or resubmit it.
    fn resolve_rotation(&self, id: &str, offered: &[Rotation]) -> Result<PendingOutcome, Error> {
        let Some(pending) = self.pending_rotation(&*self.connection()?, id)? else {
            return Ok(PendingOutcome::None);
        };
        let epoch = pending.rotation.epoch as usize;
        match offered.get(epoch - 1) {
            Some(r) if *r == pending.rotation => {
                self.commit_rotation(id, &pending)?;
                Ok(PendingOutcome::Committed)
            }
            Some(_) => {
                self.discard_rotation(id)?;
                Ok(PendingOutcome::Discarded)
            }
            None if offered.len() + 1 < epoch => Ok(PendingOutcome::None),
            None => Ok(PendingOutcome::Resubmit(pending)),
        }
    }

    fn record_sync_error(&self, id: &str, error: String) -> Result<Network, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut network = self.network_record(&tx, id)?;
        network.last_sync_error = Some(error);
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, id],
        )?;
        tx.commit()?;
        Ok(network)
    }

    fn own_membership(&self, id: &str) -> Result<Membership, Error> {
        let m: Member = read(
            &*self.connection()?,
            "SELECT record FROM network_members WHERE network_id = ?1 AND host_id = ?2",
            params![id, self.identity().id],
        )?;
        Ok(m.membership)
    }
}

/// Status and body of one coordinator call; transport failures are `Err`.
async fn coordinator(
    store: Arc<Store>,
    address: &str,
    key: &str,
    path: String,
    body: Value,
) -> anyhow::Result<(u16, Vec<u8>)> {
    let key = membership::canonical(key, 32).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (host, _) = membership::split_host_port(address).map_err(|e| anyhow::anyhow!("{e}"))?;
    let config = pinned_client_config(store, key, b"http/1.1")?;
    let name = rustls::pki_types::ServerName::try_from(host)?;
    tokio::time::timeout(
        Duration::from_secs(8),
        https(
            config,
            address,
            name,
            Method::POST,
            &path,
            serde_json::to_vec(&body)?,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("coordinator request timed out"))?
}
fn coordinator_error(status: u16, body: &[u8]) -> String {
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_default();
    format!("coordinator returned HTTP {status}: {message}")
}
fn parse_map(body: &[u8]) -> Result<WireMap, Error> {
    serde_json::from_slice(body).map_err(|_| Error::Unavailable("malformed coordinator map".into()))
}

/// This host's candidates for a network: its reflexive address as seen by
/// that network's coordinator, then its non-loopback interface addresses with
/// the bound peer port, at most `MAX_ENDPOINTS`. Empty unless listening.
async fn publish_candidates(store: &Arc<Store>, coordinator: &str) -> Vec<String> {
    let Some(bound) = store.peer_bound.read().ok().and_then(|b| *b) else {
        return Vec::new();
    };
    let mut out: Vec<std::net::SocketAddr> = Vec::new();
    if let Some(discovery) = crate::quic::discovery(store)
        && let Some(reflexive) = discovery.reflexive(coordinator).await
    {
        out.push(reflexive);
    }
    for ip in interface_ips(bound) {
        let candidate = std::net::SocketAddr::new(ip, bound.port());
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out.truncate(crate::disco::MAX_ENDPOINTS);
    if let Ok(mut published) = store.candidates.write() {
        published.clone_from(&out);
    }
    out.iter().map(ToString::to_string).collect()
}
/// Addresses a socket bound to `bound` receives on, excluding loopback,
/// unspecified, multicast, and IPv6 link-local addresses.
fn interface_ips(bound: std::net::SocketAddr) -> Vec<std::net::IpAddr> {
    let usable = |ip: &std::net::IpAddr| {
        !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, std::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
    };
    if !bound.ip().is_unspecified() {
        return Some(bound.ip()).filter(usable).into_iter().collect();
    }
    interface_addresses()
        .into_iter()
        .filter(|ip| bound.is_ipv6() || ip.is_ipv4())
        .filter(usable)
        .collect()
}
fn interface_addresses() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    // SAFETY: getifaddrs allocates a list that is only read here and released
    // with freeifaddrs; each address is read according to its family.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let entry = &*cursor;
            if !entry.ifa_addr.is_null() {
                match i32::from((*entry.ifa_addr).sa_family) {
                    libc::AF_INET => {
                        let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        out.push(std::net::IpAddr::from(
                            u32::from_be(sin.sin_addr.s_addr).to_be_bytes(),
                        ));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        out.push(std::net::IpAddr::from(sin6.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out.sort();
    out.dedup();
    out
}

/// Registers an unregistered administered network, or syncs any other one.
/// Failures are recorded on the network rather than returned.
pub async fn sync_network(store: Arc<Store>, id: String) -> Result<Network, Error> {
    let lookup = id.clone();
    let (network, own) = blocking(store.clone(), move |s| {
        Ok((s.network(&lookup)?, s.own_membership(&lookup)?))
    })
    .await?;
    let address = store.advertised();
    let candidates = publish_candidates(&store, &network.coordinator_address).await;
    let (path, body, accepted): (_, _, &[u16]) = if network.administrator
        && network.last_sync_at.is_none()
    {
        (
            "/coord/v1/networks".to_owned(),
            json_value!({"name": network.name, "root_public_key": network.root_public_key, "membership": own, "address": address, "candidates": candidates}),
            &[200, 201],
        )
    } else {
        (
            format!("/coord/v1/networks/{}/sync", network.id),
            json_value!({"address": address, "candidates": candidates}),
            &[200],
        )
    };
    let response = coordinator(
        store.clone(),
        &network.coordinator_address,
        &network.coordinator_public_key,
        path,
        body,
    )
    .await;
    let mut listed = None;
    let mut offered = Vec::new();
    let outcome = match response {
        Ok((status, body)) if accepted.contains(&status) => match parse_map(&body) {
            Ok(map) => {
                listed = Some(listed_revocations(&map));
                offered = map
                    .rotations
                    .iter()
                    .filter_map(|r| serde_json::from_value::<Rotation>(r.clone()).ok())
                    .collect();
                let network = network.clone();
                blocking(store.clone(), move |s| s.apply_map(network, map, false)).await
            }
            Err(error) => Err(error),
        },
        Ok((status, body)) => Err(Error::Unavailable(coordinator_error(status, &body))),
        Err(error) => Err(Error::Unavailable(format!("{error:#}"))),
    };
    match outcome {
        Ok(network) => {
            // Revocations this host made stay pending until the coordinator
            // lists them; they are resubmitted on every successful sync.
            if let Some(listed) = listed {
                let lookup = network.id.clone();
                let pending = blocking(store.clone(), move |s| {
                    s.pending_revocations(&lookup, &listed)
                })
                .await
                .unwrap_or_default();
                for body in pending {
                    let _ = submit_revocation(store.clone(), &network, body).await;
                }
            }
            // A rotation left pending, for example by a crash after the
            // coordinator accepted it, is completed or resubmitted here.
            settle_rotation(store, network, offered).await
        }
        Err(Error::Internal(error)) => Err(Error::Internal(error)),
        Err(error) => {
            let message = match error {
                Error::Unavailable(message) => message,
                other => other.to_string(),
            };
            blocking(store, move |s| s.record_sync_error(&id, message)).await
        }
    }
}

/// The `(kind, subject)` of every host and invite revocation a map lists.
fn listed_revocations(map: &WireMap) -> BTreeSet<(String, String)> {
    map.revocations
        .iter()
        .filter_map(|entry| {
            let kind = entry["kind"].as_str()?;
            let field = match kind {
                "host" => "host_public_key",
                "invite" => "invite_public_key",
                _ => return None,
            };
            Some((
                kind.to_owned(),
                entry["statement"][field].as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Submits one `{kind, statement}` revocation; true once the coordinator accepts.
async fn submit_revocation(store: Arc<Store>, network: &Network, body: Value) -> bool {
    matches!(
        coordinator(
            store,
            &network.coordinator_address,
            &network.coordinator_public_key,
            format!("/coord/v1/networks/{}/revocations", network.id),
            body,
        )
        .await,
        Ok((200, _))
    )
}

/// Maps a coordinator rejection to the matching local status.
fn coordinator_status(status: u16, body: &[u8]) -> Error {
    let message = coordinator_error(status, body);
    match status {
        400 => Error::Invalid(message),
        403 => Error::Forbidden,
        404 => Error::NotFound,
        409 => Error::Conflict(message),
        _ => Error::Unavailable(message),
    }
}

/// Revokes a host or invite: enforced locally first, then submitted now and on
/// every later sync until the coordinator lists it.
pub async fn revoke(store: Arc<Store>, id: String, request: Revoke) -> Result<Revoked, Error> {
    let lookup = id.clone();
    let (mut revoked, body) = blocking(store.clone(), move |s| s.revoke(&lookup, request)).await?;
    let network = blocking(store.clone(), move |s| s.network(&id)).await?;
    revoked.submitted = submit_revocation(store, &network, body).await;
    Ok(revoked)
}

/// Signs a leave statement, tries the coordinator once, then forgets the
/// network locally whether or not the coordinator accepted.
pub async fn leave(store: Arc<Store>, id: String) -> Result<Left, Error> {
    let lookup = id.clone();
    let network = blocking(store.clone(), move |s| s.network(&lookup)).await?;
    if network.administrator {
        return Err(Error::Conflict(
            "the administrator cannot leave its own network".into(),
        ));
    }
    let statement = Leave::sign(&store.signing_key, &network.id, &now());
    let submitted = matches!(
        coordinator(
            store.clone(),
            &network.coordinator_address,
            &network.coordinator_public_key,
            format!("/coord/v1/networks/{}/leave", network.id),
            json_value!({"statement": statement}),
        )
        .await,
        Ok((200, _))
    );
    blocking(store, move |s| s.forget_network(&id)).await?;
    Ok(Left {
        network_id: network.id,
        submitted,
    })
}

/// What submitting a pending rotation achieved.
enum Submitted {
    /// Accepted; carries the coordinator's map.
    Accepted(WireMap),
    /// Will never be accepted: the coordinator holds a different rotation at
    /// that epoch (409) or rejects the rotation as invalid (400).
    Rejected(Error),
    /// Not settled (403, 5xx, unreachable); the rotation stays pending.
    Unsettled(Error),
}
/// How a coordinator status settles a pending rotation submission.
#[derive(Debug, PartialEq, Eq)]
enum RotationResponse {
    Accept,
    Discard,
    Keep,
}
fn rotation_response(status: u16) -> RotationResponse {
    match status {
        200 => RotationResponse::Accept,
        400 | 409 => RotationResponse::Discard,
        _ => RotationResponse::Keep,
    }
}
async fn submit_rotation(
    store: Arc<Store>,
    network: &Network,
    pending: &PendingRotation,
) -> Submitted {
    let response = coordinator(
        store,
        &network.coordinator_address,
        &network.coordinator_public_key,
        format!("/coord/v1/networks/{}/rotations", network.id),
        json_value!({"rotation": pending.rotation, "attestations": pending.attestations}),
    )
    .await;
    match response {
        Ok((status, body)) => match rotation_response(status) {
            RotationResponse::Accept => match parse_map(&body) {
                Ok(map) => Submitted::Accepted(map),
                Err(error) => Submitted::Unsettled(error),
            },
            RotationResponse::Discard => Submitted::Rejected(coordinator_status(status, &body)),
            RotationResponse::Keep => Submitted::Unsettled(coordinator_status(status, &body)),
        },
        Err(error) => Submitted::Unsettled(Error::Unavailable(format!("{error:#}"))),
    }
}

/// Commits an accepted rotation and applies the coordinator's map.
async fn accept_rotation(
    store: Arc<Store>,
    id: String,
    pending: PendingRotation,
    map: WireMap,
) -> Result<Network, Error> {
    let commit = id.clone();
    blocking(store.clone(), move |s| s.commit_rotation(&commit, &pending)).await?;
    let network = blocking(store.clone(), move |s| s.network(&id)).await?;
    match blocking(store, {
        let network = network.clone();
        move |s| s.apply_map(network, map, false)
    })
    .await
    {
        Ok(network) => Ok(network),
        Err(Error::Internal(error)) => Err(Error::Internal(error)),
        Err(_) => Ok(network),
    }
}

/// Rotates the root. The signed rotation, its attestations, and the new seed
/// are persisted as pending before submission, with the old root still
/// current; they become current only once the coordinator accepts. A pending
/// rotation is resubmitted by a repeated command and on every sync.
pub async fn rotate(store: Arc<Store>, id: String) -> Result<Network, Error> {
    let lookup = id.clone();
    let (network, pending) = blocking(store.clone(), move |s| s.prepare_rotation(&lookup)).await?;
    match submit_rotation(store.clone(), &network, &pending).await {
        Submitted::Accepted(map) => accept_rotation(store, id, pending, map).await,
        Submitted::Rejected(error) => {
            let reason = error.to_string();
            blocking(store, move |s| s.discard_rotation_with_error(&id, &reason)).await?;
            Err(error)
        }
        Submitted::Unsettled(error) => Err(error),
    }
}

/// Settles a pending rotation after a successful sync against `offered`, the
/// chain the coordinator served.
async fn settle_rotation(
    store: Arc<Store>,
    network: Network,
    offered: Vec<Rotation>,
) -> Result<Network, Error> {
    let id = network.id.clone();
    let lookup = id.clone();
    let outcome = blocking(store.clone(), move |s| {
        s.resolve_rotation(&lookup, &offered)
    })
    .await?;
    match outcome {
        PendingOutcome::None => Ok(network),
        PendingOutcome::Committed => blocking(store, move |s| s.network(&id)).await,
        PendingOutcome::Discarded => {
            blocking(store, move |s| {
                s.record_sync_error(
                    &id,
                    "root rotation discarded: the chain holds a different rotation at that epoch"
                        .into(),
                )
            })
            .await
        }
        PendingOutcome::Resubmit(pending) => {
            match submit_rotation(store.clone(), &network, &pending).await {
                Submitted::Accepted(map) => accept_rotation(store, id, pending, map).await,
                Submitted::Rejected(error) => {
                    let reason = error.to_string();
                    blocking(store, move |s| s.discard_rotation_with_error(&id, &reason)).await
                }
                Submitted::Unsettled(_) => Ok(network),
            }
        }
    }
}

/// Joins only after the coordinator accepts and its map verifies; nothing is
/// persisted otherwise.
pub async fn join(store: Arc<Store>, token: String) -> Result<Network, Error> {
    let token = InviteToken::decode(&token)?;
    let id = token.network_id.clone();
    let exists = blocking(store.clone(), move |s| match s.network(&id) {
        Ok(_) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(e) => Err(e),
    })
    .await?;
    if exists {
        return Err(Error::Conflict("network already joined".into()));
    }
    let invite = membership::seed(&token.invite_seed)?;
    let own = membership::sign_member(
        token.invite(),
        &invite,
        store.signing_key.verifying_key().as_bytes(),
        &now(),
    );
    let candidates = publish_candidates(&store, &token.coordinator_address).await;
    let response = coordinator(
        store.clone(),
        &token.coordinator_address,
        &token.coordinator_public_key,
        format!("/coord/v1/networks/{}/members", token.network_id),
        json_value!({"membership": own, "address": store.advertised(), "candidates": candidates}),
    )
    .await
    .map_err(|e| Error::Unavailable(format!("{e:#}")))?;
    let map = match response {
        (200 | 201, body) => parse_map(&body)?,
        (status, body) => return Err(coordinator_status(status, &body)),
    };
    // The token carries the root that signed the invite, which is the current
    // root after a rotation. The map's genesis root must derive the network ID,
    // and this host's membership must verify under the map's verified chain,
    // so a coordinator cannot substitute another network.
    let network = Network {
        id: token.network_id,
        name: token.network_name,
        root_public_key: map.root_public_key.clone(),
        member: token.member,
        coordinator_address: token.coordinator_address,
        coordinator_public_key: token.coordinator_public_key,
        administrator: false,
        last_sync_at: None,
        last_sync_error: None,
        root_epoch: 0,
        current_root_public_key: String::new(),
    };
    blocking(store, move |s| s.apply_map(network, map, true)).await
}

/// Background registration and sync for every network until shutdown.
pub async fn coordinate(store: Arc<Store>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        let ids = blocking(store.clone(), |s| {
            Ok(s.networks()?.into_iter().map(|n| n.id).collect::<Vec<_>>())
        })
        .await
        .unwrap_or_default();
        for id in ids {
            if let Err(error) = sync_network(store.clone(), id).await {
                eprintln!("coordination sync error: {error}");
            }
        }
        let interval = store.coordination_interval.load(Ordering::Relaxed);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
            _ = shutdown.changed() => return,
        }
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/networks", get(list).post(create))
        .route("/v1/networks/join", post(join_route))
        .route("/v1/networks/{id}/members", get(members))
        .route("/v1/networks/{id}/invites", post(invite))
        .route("/v1/networks/{id}/sync", post(sync))
        .route("/v1/networks/{id}/revocations", post(revoke_route))
        .route("/v1/networks/{id}/leave", post(leave_route))
        .route("/v1/networks/{id}/rotate", post(rotate_route))
}
async fn revoke_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Revoked>), Error> {
    let request: Revoke = decode(body)?;
    Ok((StatusCode::CREATED, Json(revoke(store, id, request).await?)))
}
async fn leave_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Left>, Error> {
    Ok(Json(leave(store, id).await?))
}
async fn rotate_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Network>, Error> {
    Ok(Json(rotate(store, id).await?))
}
async fn list(State(store): State<Arc<Store>>) -> Result<Json<Vec<Network>>, Error> {
    Ok(Json(blocking(store, Store::networks).await?))
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Network>), Error> {
    let request = decode(body)?;
    let network = blocking(store.clone(), move |s| s.create_network(request)).await?;
    let network = sync_network(store, network.id).await?;
    Ok((StatusCode::CREATED, Json(network)))
}
async fn join_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Network>), Error> {
    let request: JoinNetwork = decode(body)?;
    Ok((StatusCode::CREATED, Json(join(store, request.token).await?)))
}
async fn members(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<Member>>, Error> {
    Ok(Json(blocking(store, move |s| s.members(&id)).await?))
}
async fn invite(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<IssuedInvite>), Error> {
    let request = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.issue_invite(&id, request)).await?),
    ))
}
async fn sync(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Network>, Error> {
    let check = id.clone();
    blocking(store.clone(), move |s| s.network(&check)).await?;
    Ok(Json(sync_network(store, id).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_entry(root: &SigningKey, host: &SigningKey, invite: &SigningKey) -> Value {
        let signed = membership::sign_invite(root, invite, "m", "2099-01-01T00:00:00Z");
        let m = membership::sign_member(
            signed,
            invite,
            host.verifying_key().as_bytes(),
            "2026-10-05T00:00:00Z",
        );
        json_value!({"host_id": key_id(host.verifying_key().as_bytes()), "membership": m, "address": "127.0.0.1:9", "updated_at": "2026-10-05T00:00:00Z"})
    }

    #[test]
    fn map_verification_drops_forged_and_reused_entries() {
        let root = random_seed().unwrap();
        let network = Network {
            id: membership::network_id(root.verifying_key().as_bytes()),
            name: "n".into(),
            root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            member: "m".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: String::new(),
            administrator: true,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
        };
        let hosts: Vec<SigningKey> = (0..5).map(|_| random_seed().unwrap()).collect();
        let shared = random_seed().unwrap();
        let forger = random_seed().unwrap();
        let mut forged = member_entry(&forger, &hosts[2], &random_seed().unwrap());
        forged["membership"]["network_id"] = json_value!(network.id);
        let mut wrong_id = member_entry(&root, &hosts[4], &random_seed().unwrap());
        wrong_id["host_id"] = json_value!(key_id(hosts[0].verifying_key().as_bytes()));
        let map = WireMap {
            rotations: vec![],
            attestations: vec![],
            revocations: vec![],
            network_id: network.id.clone(),
            root_public_key: network.root_public_key.clone(),
            members: vec![
                member_entry(&root, &hosts[0], &random_seed().unwrap()),
                forged,
                member_entry(&root, &hosts[1], &shared),
                member_entry(&root, &hosts[3], &shared),
                wrong_id,
                json_value!({"host_id": "junk"}),
            ],
        };
        let members = verify_map(&network, map, Statements::default())
            .unwrap()
            .members;
        let ids: Vec<_> = members.iter().map(|m| m.host_id.clone()).collect();
        assert_eq!(ids, vec![key_id(hosts[0].verifying_key().as_bytes())]);
        let other = WireMap {
            network_id: network.id.clone(),
            root_public_key: STANDARD.encode(forger.verifying_key().as_bytes()),
            members: vec![],
            rotations: vec![],
            attestations: vec![],
            revocations: vec![],
        };
        assert!(verify_map(&network, other, Statements::default()).is_err());
    }

    #[test]
    fn created_network_issues_verifiable_invites_and_persists() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("host");
        let store = Store::open(&path).unwrap();
        let coordinator = STANDARD.encode(random_seed().unwrap().verifying_key().as_bytes());
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "coord.example:7400".into(),
                coordinator_public_key: coordinator,
            })
            .unwrap();
        assert!(network.administrator);
        let members = store.members(&network.id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0]
                .membership
                .verify(&network.root_public_key)
                .unwrap(),
            store.identity().id
        );
        let expires = rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1));
        let issued = store
            .issue_invite(
                &network.id,
                CreateInvite {
                    member: "bob".into(),
                    expires_at: expires.clone(),
                },
            )
            .unwrap();
        let token = InviteToken::decode(&issued.token).unwrap();
        assert_eq!(token.member, "bob");
        assert_eq!(token.invite_expires_at, expires);
        let too_late = rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(31));
        assert!(
            store
                .issue_invite(
                    &network.id,
                    CreateInvite {
                        member: "bob".into(),
                        expires_at: too_late
                    }
                )
                .is_err()
        );
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.networks().unwrap(), vec![network]);
        let kinds: Vec<_> = reopened
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(kinds, vec!["network.created", "network.invite_issued"]);
    }

    #[test]
    fn joined_networks_reject_invites_and_members_become_known() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let root = random_seed().unwrap();
        let invite = random_seed().unwrap();
        let other = random_seed().unwrap();
        let network = Network {
            id: membership::network_id(root.verifying_key().as_bytes()),
            name: "team".into(),
            root_public_key: STANDARD.encode(root.verifying_key().as_bytes()),
            member: "bob".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: STANDARD
                .encode(random_seed().unwrap().verifying_key().as_bytes()),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
        };
        let me = membership::sign_member(
            membership::sign_invite(&root, &invite, "bob", "2099-01-01T00:00:00Z"),
            &invite,
            store.signing_key.verifying_key().as_bytes(),
            "2026-10-05T00:00:00Z",
        );
        let map = || WireMap {
            rotations: vec![],
            attestations: vec![],
            revocations: vec![],
            network_id: network.id.clone(),
            root_public_key: network.root_public_key.clone(),
            members: vec![
                json_value!({"host_id": store.identity().id, "membership": me, "address": "", "updated_at": "2026-10-05T00:00:00Z"}),
                member_entry(&root, &other, &random_seed().unwrap()),
            ],
        };
        // A map that omits this host is not applied.
        let mut missing = map();
        missing.members.remove(0);
        assert!(store.apply_map(network.clone(), missing, true).is_err());
        assert!(store.networks().unwrap().is_empty());
        let joined = store.apply_map(network.clone(), map(), true).unwrap();
        assert!(joined.last_sync_at.is_some());
        assert!(matches!(
            store.apply_map(network.clone(), map(), true),
            Err(Error::Conflict(_))
        ));
        let other_key = other.verifying_key().to_bytes();
        let other_id = key_id(&other_key);
        assert!(store.knows(&other_key).unwrap());
        assert_eq!(store.dial_target(&other_id).unwrap().address, "127.0.0.1:9");
        assert!(store.dial_target(&store.identity().id).is_err());
        let connection = store.connection().unwrap();
        assert!(store.known_host(&connection, &other_id).unwrap());
        assert!(store.connected(&connection, &other_id).unwrap());
        store.coordination_interval.store(0, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!store.connected(&connection, &other_id).unwrap());
        drop(connection);
        assert!(matches!(
            store.issue_invite(
                &network.id,
                CreateInvite {
                    member: "x".into(),
                    expires_at: rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1)),
                },
            ),
            Err(Error::Forbidden)
        ));
        // Removal from the map removes the member and its pin.
        let mut shrunk = map();
        shrunk.members.truncate(1);
        store.apply_map(network.clone(), shrunk, false).unwrap();
        assert!(!store.knows(&other_key).unwrap());
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                "network.joined",
                "network.member_added",
                "network.member_removed"
            ]
        );
    }

    /// A member entry whose invite is signed by `root`, which may be a rotated
    /// root that does not derive `network`.
    fn rooted_entry(network: &str, root: &SigningKey, host: &SigningKey) -> Value {
        use ed25519_dalek::Signer;
        let invite = random_seed().unwrap();
        let mut signed = membership::sign_invite(root, &invite, "m", "2099-01-01T00:00:00Z");
        signed.network_id = network.into();
        let statement = membership::invite_statement(
            network,
            &signed.invite_public_key,
            "m",
            "2099-01-01T00:00:00Z",
        );
        signed.invite_signature = STANDARD.encode(root.sign(statement.as_bytes()).to_bytes());
        let m = membership::sign_member(
            signed,
            &invite,
            host.verifying_key().as_bytes(),
            "2026-10-05T00:00:00Z",
        );
        json_value!({"host_id": key_id(host.verifying_key().as_bytes()), "membership": m, "address": "", "updated_at": "2026-10-05T00:00:00Z"})
    }
    fn key(k: &SigningKey) -> String {
        STANDARD.encode(k.verifying_key().as_bytes())
    }
    fn wire(
        network: &Network,
        members: Vec<Value>,
        rotations: Vec<Value>,
        attestations: Vec<Value>,
        revocations: Vec<Value>,
    ) -> WireMap {
        WireMap {
            network_id: network.id.clone(),
            root_public_key: network.root_public_key.clone(),
            members,
            rotations,
            attestations,
            revocations,
        }
    }

    #[test]
    fn revocations_are_sticky_and_rotation_requires_the_current_root() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let r0 = random_seed().unwrap();
        let id = membership::network_id(r0.verifying_key().as_bytes());
        let network = Network {
            id: id.clone(),
            name: "team".into(),
            root_public_key: key(&r0),
            member: "bob".into(),
            coordinator_address: "127.0.0.1:1".into(),
            coordinator_public_key: key(&random_seed().unwrap()),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
        };
        let me = SigningKey::from_bytes(&store.signing_key.to_bytes());
        let [carol, dave, erin, frank] = [(); 4].map(|_| random_seed().unwrap());
        let mine = rooted_entry(&id, &r0, &me);
        let carol_entry = rooted_entry(&id, &r0, &carol);
        let dave_entry = rooted_entry(&id, &r0, &dave);
        let erin_entry = rooted_entry(&id, &r0, &erin);
        let base = || {
            vec![
                mine.clone(),
                carol_entry.clone(),
                dave_entry.clone(),
                erin_entry.clone(),
            ]
        };
        let known = |k: &SigningKey| store.knows(&k.verifying_key().to_bytes()).unwrap();
        store
            .apply_map(
                network.clone(),
                wire(&network, base(), vec![], vec![], vec![]),
                true,
            )
            .unwrap();
        assert!(known(&carol) && known(&dave) && known(&erin));

        // Revoking carol's key and dave's invite drops both.
        let at = "2026-10-07T00:00:00Z";
        let revoke_carol = HostRevocation::sign(&r0, &id, &key(&carol), at);
        let dave_invite = dave_entry["membership"]["invite_public_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let revoke_dave = InviteRevocation::sign(&r0, &id, &dave_invite, at);
        let forged = HostRevocation::sign(&random_seed().unwrap(), &id, &key(&erin), at);
        let revocations = vec![
            json_value!({"kind": "host", "statement": revoke_carol}),
            json_value!({"kind": "invite", "statement": revoke_dave}),
            json_value!({"kind": "host", "statement": forged}),
        ];
        store
            .apply_map(
                network.clone(),
                wire(&network, base(), vec![], vec![], revocations),
                false,
            )
            .unwrap();
        assert!(!known(&carol) && !known(&dave));
        assert!(
            known(&erin),
            "a revocation not signed by a network root is ignored"
        );
        // Sticky: a map that omits the revocations does not restore them.
        store
            .apply_map(
                network.clone(),
                wire(&network, base(), vec![], vec![], vec![]),
                false,
            )
            .unwrap();
        assert!(!known(&carol) && !known(&dave) && known(&erin));

        // Rotation: only the current root's invites or attestations count.
        let r1 = random_seed().unwrap();
        let rotation = Rotation::sign(&r0, &id, 1, &key(&r1), at);
        let attest_me = Attestation::sign(&r1, &id, 1, &key(&me), "bob", at);
        let attest_carol = Attestation::sign(&r1, &id, 1, &key(&carol), "carol", at);
        let frank_entry = rooted_entry(&id, &r1, &frank);
        let mut members = base();
        members.push(frank_entry.clone());
        let rotated = store
            .apply_map(
                network.clone(),
                wire(
                    &network,
                    members.clone(),
                    vec![json_value!(rotation)],
                    vec![json_value!(attest_me), json_value!(attest_carol)],
                    vec![],
                ),
                false,
            )
            .unwrap();
        assert_eq!(rotated.root_epoch, 1);
        assert_eq!(rotated.current_root_public_key, key(&r1));
        assert!(known(&frank), "an invite under the current root is valid");
        assert!(!known(&erin), "an old-root chain alone no longer counts");
        assert!(!known(&carol), "an attestation does not undo a revocation");
        assert_eq!(store.network(&id).unwrap().root_epoch, 1);

        // A fork at a persisted epoch, or a stale chain, is refused.
        let r2 = random_seed().unwrap();
        let fork = Rotation::sign(&r0, &id, 1, &key(&r2), at);
        let refused = store.apply_map(
            network.clone(),
            wire(
                &network,
                members.clone(),
                vec![json_value!(fork)],
                vec![],
                vec![],
            ),
            false,
        );
        assert!(matches!(refused, Err(Error::Unavailable(m)) if m == "root chain conflict"));
        assert!(
            store
                .apply_map(
                    network.clone(),
                    wire(&network, members.clone(), vec![], vec![], vec![]),
                    false
                )
                .is_err()
        );
        assert!(known(&frank));
        assert_eq!(
            store.network(&id).unwrap().current_root_public_key,
            key(&r1)
        );

        // A leave seen in a map drops that member, with network.member_left.
        let leave = Leave::sign(&frank, &id, at);
        store
            .apply_map(
                network.clone(),
                wire(
                    &network,
                    members,
                    vec![json_value!(rotation)],
                    vec![json_value!(attest_me)],
                    vec![json_value!({"kind": "leave", "statement": leave})],
                ),
                false,
            )
            .unwrap();
        assert!(!known(&frank));
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(kinds.contains(&"network.member_left".to_owned()));
    }

    #[test]
    fn administrators_revoke_rotate_and_members_leave() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("admin")).unwrap();
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
            })
            .unwrap();
        let id = network.id.clone();
        let root = store
            .current_root(&store.connection().unwrap(), &id)
            .unwrap();
        let me = SigningKey::from_bytes(&store.signing_key.to_bytes());
        let own = json_value!({"host_id": store.identity().id, "membership": store.own_membership(&id).unwrap(), "address": "", "updated_at": "2026-10-05T00:00:00Z"});
        let [carol, dave] = [(); 2].map(|_| random_seed().unwrap());
        let carol_entry = rooted_entry(&id, &root, &carol);
        let dave_entry = rooted_entry(&id, &root, &dave);
        let map = || {
            wire(
                &network,
                vec![own.clone(), carol_entry.clone(), dave_entry.clone()],
                vec![],
                vec![],
                vec![],
            )
        };
        store.apply_map(network.clone(), map(), false).unwrap();
        let known = |k: &SigningKey| store.knows(&k.verifying_key().to_bytes()).unwrap();
        assert!(known(&carol) && known(&dave));
        let revoke = |host: Option<String>, invite: Option<String>| {
            store.revoke(
                &id,
                Revoke {
                    host_id: host,
                    invite_public_key: invite,
                },
            )
        };
        assert!(matches!(
            revoke(Some(store.identity().id), None),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            revoke(Some("host_unknown".into()), None),
            Err(Error::NotFound)
        ));
        assert!(matches!(revoke(None, None), Err(Error::Invalid(_))));
        let carol_id = key_id(carol.verifying_key().as_bytes());
        let (revoked, body) = revoke(Some(carol_id.clone()), None).unwrap();
        assert_eq!(
            (revoked.kind.as_str(), revoked.subject.clone()),
            ("host", key(&carol))
        );
        assert_eq!(body["kind"], "host");
        assert!(!known(&carol));
        // Pending until the coordinator lists it; a repeat returns the same statement.
        assert_eq!(
            store
                .pending_revocations(&id, &BTreeSet::new())
                .unwrap()
                .len(),
            1
        );
        let listed = BTreeSet::from([("host".to_owned(), key(&carol))]);
        assert!(store.pending_revocations(&id, &listed).unwrap().is_empty());
        assert_eq!(
            revoke(Some(carol_id), None).unwrap().1["statement"],
            body["statement"]
        );
        // A coordinator map that still lists carol cannot restore her.
        store.apply_map(network.clone(), map(), false).unwrap();
        assert!(!known(&carol) && known(&dave));
        // Revoking an invite drops the host that joined with it; not our own invite.
        let own_invite = store.own_membership(&id).unwrap().invite_public_key;
        assert!(matches!(
            revoke(None, Some(own_invite)),
            Err(Error::Conflict(_))
        ));
        let dave_invite = dave_entry["membership"]["invite_public_key"]
            .as_str()
            .unwrap()
            .to_owned();
        revoke(None, Some(dave_invite)).unwrap();
        assert!(!known(&dave));

        // Rotation persists the new seed, epoch, and attestations; new invites
        // are signed by the new root and still decode.
        let (_, pending) = store.prepare_rotation(&id).unwrap();
        let (rotation, attestations) = (pending.rotation.clone(), pending.attestations.clone());
        let next = membership::seed(&pending.root_seed).unwrap();
        assert_eq!(rotation.epoch, 1);
        assert_eq!(
            attestations.len(),
            1,
            "only current valid members are attested"
        );
        assert_eq!(attestations[0].host_public_key, key(&me));
        store.commit_rotation(&id, &pending).unwrap();
        let rotated = store.network(&id).unwrap();
        assert_eq!(
            (rotated.root_epoch, rotated.current_root_public_key.clone()),
            (1, key(&next))
        );
        assert_eq!(rotated.root_public_key, key(&root));
        let issued = store
            .issue_invite(
                &id,
                CreateInvite {
                    member: "erin".into(),
                    expires_at: rfc3339(chrono::Utc::now() + chrono::TimeDelta::days(1)),
                },
            )
            .unwrap();
        let token = InviteToken::decode(&issued.token).unwrap();
        assert_eq!(token.root_public_key, key(&next));
        assert_eq!(token.network_id, id);
        // The rotated chain still accepts our own attested membership.
        store
            .apply_map(
                network.clone(),
                wire(
                    &network,
                    vec![own.clone()],
                    vec![json_value!(rotation)],
                    vec![json_value!(attestations[0])],
                    vec![],
                ),
                false,
            )
            .unwrap();

        // A member leaves locally; the administrator cannot.
        store.forget_network(&id).unwrap();
        assert!(store.networks().unwrap().is_empty());
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        for kind in [
            "network.host_revoked",
            "network.invite_revoked",
            "network.root_rotated",
            "network.left",
        ] {
            assert!(kinds.contains(&kind.to_owned()), "{kind}");
        }
        let joined = Store::open(&temporary.path().join("member")).unwrap();
        let member_network = Network {
            administrator: false,
            ..network.clone()
        };
        let member_own = rooted_entry(
            &id,
            &root,
            &SigningKey::from_bytes(&joined.signing_key.to_bytes()),
        );
        joined
            .apply_map(
                member_network.clone(),
                wire(&member_network, vec![member_own], vec![], vec![], vec![]),
                true,
            )
            .unwrap();
        assert!(matches!(
            joined.revoke(
                &id,
                Revoke {
                    host_id: Some(store.identity().id),
                    invite_public_key: None
                }
            ),
            Err(Error::Forbidden)
        ));
    }

    #[test]
    fn pending_rotation_survives_a_crash_after_acceptance() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("admin");
        let store = Store::open(&path).unwrap();
        let network = store
            .create_network(CreateNetwork {
                name: "team".into(),
                member: "alice".into(),
                coordinator_address: "127.0.0.1:1".into(),
                coordinator_public_key: key(&random_seed().unwrap()),
            })
            .unwrap();
        let id = network.id.clone();
        let root = store
            .current_root(&store.connection().unwrap(), &id)
            .unwrap();
        let own = json_value!({"host_id": store.identity().id, "membership": store.own_membership(&id).unwrap(), "address": "", "updated_at": "2026-10-05T00:00:00Z"});
        store
            .apply_map(
                network.clone(),
                wire(&network, vec![own.clone()], vec![], vec![], vec![]),
                false,
            )
            .unwrap();
        // Signed and persisted as pending; the old root stays current locally.
        let (_, pending) = store.prepare_rotation(&id).unwrap();
        let (_, again) = store.prepare_rotation(&id).unwrap();
        assert_eq!(
            again.rotation, pending.rotation,
            "a repeated command resubmits the same rotation"
        );
        assert_eq!(
            store.network(&id).unwrap().current_root_public_key,
            key(&root)
        );
        assert_eq!(
            store
                .current_root(&store.connection().unwrap(), &id)
                .unwrap()
                .to_bytes(),
            root.to_bytes()
        );
        let stored: String = store
            .connection()
            .unwrap()
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'pending_rotation' AND subject = '1'",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored["root_seed"], pending.root_seed);
        // The coordinator accepted it, then this host crashed before committing.
        drop(store);
        let store = Store::open(&path).unwrap();
        let accepted = wire(
            &network,
            vec![own.clone()],
            vec![json_value!(pending.rotation)],
            pending
                .attestations
                .iter()
                .map(|a| json_value!(a))
                .collect(),
            vec![],
        );
        store.apply_map(network.clone(), accepted, false).unwrap();
        // The served chain already holds the pending rotation, so the next sync commits it.
        assert!(matches!(
            store
                .resolve_rotation(&id, std::slice::from_ref(&pending.rotation))
                .unwrap(),
            PendingOutcome::Committed
        ));
        let next = membership::seed(&pending.root_seed).unwrap();
        let rotated = store.network(&id).unwrap();
        assert_eq!(
            (rotated.root_epoch, rotated.current_root_public_key),
            (1, key(&next))
        );
        assert_eq!(
            store
                .current_root(&store.connection().unwrap(), &id)
                .unwrap()
                .to_bytes(),
            next.to_bytes()
        );
        assert!(
            store
                .pending_rotation(&store.connection().unwrap(), &id)
                .unwrap()
                .is_none()
        );
        let kinds: Vec<_> = store
            .events(0, 100)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            kinds
                .iter()
                .filter(|k| *k == "network.root_rotated")
                .count(),
            1
        );
        assert!(matches!(
            store
                .resolve_rotation(&id, std::slice::from_ref(&pending.rotation))
                .unwrap(),
            PendingOutcome::None
        ));

        // A pending rotation the coordinator has not seen is resubmitted; one
        // superseded by a different rotation at that epoch is discarded.
        let (_, second) = store.prepare_rotation(&id).unwrap();
        assert_eq!(second.rotation.epoch, 2);
        assert!(matches!(
            store.resolve_rotation(&id, std::slice::from_ref(&pending.rotation)).unwrap(),
            PendingOutcome::Resubmit(p) if p.rotation == second.rotation
        ));
        let other = Rotation::sign(
            &next,
            &id,
            2,
            &key(&random_seed().unwrap()),
            "2026-10-07T00:00:00Z",
        );
        assert!(matches!(
            store
                .resolve_rotation(&id, &[pending.rotation.clone(), other])
                .unwrap(),
            PendingOutcome::Discarded
        ));
        assert!(
            store
                .pending_rotation(&store.connection().unwrap(), &id)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.network(&id).unwrap().root_epoch, 1);

        // 400 and 409 discard for good; 403, 5xx, and unreachable keep it pending.
        assert_eq!(rotation_response(200), RotationResponse::Accept);
        for status in [400, 409] {
            assert_eq!(
                rotation_response(status),
                RotationResponse::Discard,
                "{status}"
            );
        }
        for status in [403, 404, 500, 502, 503] {
            assert_eq!(
                rotation_response(status),
                RotationResponse::Keep,
                "{status}"
            );
        }
        store.prepare_rotation(&id).unwrap();
        let discarded = store
            .discard_rotation_with_error(&id, "invalid request: bad attestation")
            .unwrap();
        assert_eq!(
            discarded.last_sync_error.as_deref(),
            Some("root rotation discarded: invalid request: bad attestation")
        );
        assert!(
            store
                .pending_rotation(&store.connection().unwrap(), &id)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.network(&id).unwrap().root_epoch, 1);
    }

    #[test]
    fn version_two_state_migrates_to_latest() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("host");
        let identity = Store::open(&path).unwrap().identity();
        let connection = Connection::open(path.join("host.db")).unwrap();
        connection
            .execute_batch(
                "DROP TABLE network_statements; DROP TABLE adapter_connections; DROP TABLE adapter_outbound; DROP TABLE adapter_routes; DROP TABLE outbound_replies; DROP TABLE received_replies; DROP TABLE deliveries; DROP TABLE adapter_credentials; DROP TABLE network_members; DROP TABLE networks; PRAGMA user_version = 2;",
            )
            .unwrap();
        drop(connection);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.identity(), identity);
        assert!(store.networks().unwrap().is_empty());
        let version: i64 = store
            .connection()
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 7);
        drop(store);
        Connection::open(path.join("host.db"))
            .unwrap()
            .execute_batch("PRAGMA user_version = 8;")
            .unwrap();
        assert!(Store::open(&path).is_err());
    }
}
