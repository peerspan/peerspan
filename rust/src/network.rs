//! Signed enrollment and the coordination client. Coordination distributes
//! membership chains and addresses; this host verifies every chain itself and
//! persists the verified map so known members keep working during outages.
use crate::{
    api::{blocking, decode},
    membership::{self, InviteToken, Membership},
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
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub host_id: String,
    pub public_key: String,
    pub member: String,
    pub address: String,
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
}
#[derive(Deserialize)]
struct WireMember {
    host_id: String,
    membership: Membership,
    address: String,
    updated_at: String,
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

/// Rejects entries whose chain fails, whose ID mismatches, or whose invite key
/// was used by more than one host key. A forged member cannot be introduced
/// without the invite secret, and a reused invite discredits all its users.
fn verified_members(network: &Network, map: WireMap) -> Result<Vec<Member>, Error> {
    if map.network_id != network.id || map.root_public_key != network.root_public_key {
        return Err(Error::Unavailable(
            "coordinator map does not match this network".into(),
        ));
    }
    let mut candidates = Vec::new();
    for entry in map.members {
        let Ok(entry) = serde_json::from_value::<WireMember>(entry) else {
            continue;
        };
        let Ok(host_id) = entry.membership.verify(&network.root_public_key) else {
            continue;
        };
        if host_id != entry.host_id || entry.membership.network_id != network.id {
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
    Ok(members)
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
        };
        let me = Member {
            host_id: self.identity().id,
            public_key: own.host_public_key.clone(),
            member: own.member.clone(),
            address: self.advertised(),
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
        let signed = membership::sign_invite(&root, &invite, &r.member, &r.expires_at);
        let token = InviteToken {
            network_id: network.id.clone(),
            network_name: network.name,
            root_public_key: network.root_public_key,
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

    /// Replaces a network's verified member set with a coordinator map. When
    /// `joined` is set, the network itself is inserted in the same transaction.
    fn apply_map(&self, network: Network, map: WireMap, joined: bool) -> Result<Network, Error> {
        let mut members = verified_members(&network, map)?;
        let own_id = self.identity().id;
        if !members.iter().any(|m| m.host_id == own_id) {
            return Err(Error::Unavailable("coordinator map omits this host".into()));
        }
        let at = now();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
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
        let old: BTreeSet<String> = {
            let mut statement =
                tx.prepare("SELECT host_id FROM network_members WHERE network_id = ?1")?;
            statement
                .query_map([&network.id], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?
        };
        tx.execute(
            "DELETE FROM network_members WHERE network_id = ?1",
            [&network.id],
        )?;
        for m in &mut members {
            if m.host_id == own_id {
                // The coordinator's address for us may lag; record our own.
                m.address = self.advertised();
            }
            tx.execute(
                "INSERT INTO network_members VALUES (?1, ?2, ?3)",
                params![network.id, m.host_id, serde_json::to_string(&m)?],
            )?;
        }
        let new: BTreeSet<String> = members.into_iter().map(|m| m.host_id).collect();
        for added in new.difference(&old).filter(|id| **id != own_id) {
            append_event(&tx, "network.member_added", added, &at)?;
        }
        for removed in old.difference(&new).filter(|id| **id != own_id) {
            append_event(&tx, "network.member_removed", removed, &at)?;
        }
        network.last_sync_at = Some(at);
        network.last_sync_error = None;
        tx.execute(
            "UPDATE networks SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&network)?, network.id],
        )?;
        tx.commit()?;
        self.refresh_member_pins(&connection)?;
        Ok(network)
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
    let config = pinned_client_config(store, key)?;
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

/// Registers an unregistered administered network, or syncs any other one.
/// Failures are recorded on the network rather than returned.
pub async fn sync_network(store: Arc<Store>, id: String) -> Result<Network, Error> {
    let lookup = id.clone();
    let (network, own) = blocking(store.clone(), move |s| {
        Ok((s.network(&lookup)?, s.own_membership(&lookup)?))
    })
    .await?;
    let address = store.advertised();
    let (path, body, accepted): (_, _, &[u16]) = if network.administrator
        && network.last_sync_at.is_none()
    {
        (
            "/coord/v1/networks".to_owned(),
            json_value!({"name": network.name, "root_public_key": network.root_public_key, "membership": own, "address": address}),
            &[200, 201],
        )
    } else {
        (
            format!("/coord/v1/networks/{}/sync", network.id),
            json_value!({"address": address}),
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
    let outcome = match response {
        Ok((status, body)) if accepted.contains(&status) => match parse_map(&body) {
            Ok(map) => {
                let network = network.clone();
                blocking(store.clone(), move |s| s.apply_map(network, map, false)).await
            }
            Err(error) => Err(error),
        },
        Ok((status, body)) => Err(Error::Unavailable(coordinator_error(status, &body))),
        Err(error) => Err(Error::Unavailable(format!("{error:#}"))),
    };
    match outcome {
        Ok(network) => Ok(network),
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
    let response = coordinator(
        store.clone(),
        &token.coordinator_address,
        &token.coordinator_public_key,
        format!("/coord/v1/networks/{}/members", token.network_id),
        json_value!({"membership": own, "address": store.advertised()}),
    )
    .await
    .map_err(|e| Error::Unavailable(format!("{e:#}")))?;
    let map = match response {
        (200 | 201, body) => parse_map(&body)?,
        (status, body) => {
            let message = coordinator_error(status, &body);
            return Err(match status {
                400 => Error::Invalid(message),
                403 => Error::Forbidden,
                404 => Error::NotFound,
                409 => Error::Conflict(message),
                _ => Error::Unavailable(message),
            });
        }
    };
    let network = Network {
        id: token.network_id,
        name: token.network_name,
        root_public_key: token.root_public_key,
        member: token.member,
        coordinator_address: token.coordinator_address,
        coordinator_public_key: token.coordinator_public_key,
        administrator: false,
        last_sync_at: None,
        last_sync_error: None,
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
        };
        let hosts: Vec<SigningKey> = (0..5).map(|_| random_seed().unwrap()).collect();
        let shared = random_seed().unwrap();
        let forger = random_seed().unwrap();
        let mut forged = member_entry(&forger, &hosts[2], &random_seed().unwrap());
        forged["membership"]["network_id"] = json_value!(network.id);
        let mut wrong_id = member_entry(&root, &hosts[4], &random_seed().unwrap());
        wrong_id["host_id"] = json_value!(key_id(hosts[0].verifying_key().as_bytes()));
        let map = WireMap {
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
        let members = verified_members(&network, map).unwrap();
        let ids: Vec<_> = members.iter().map(|m| m.host_id.clone()).collect();
        assert_eq!(ids, vec![key_id(hosts[0].verifying_key().as_bytes())]);
        let other = WireMap {
            network_id: network.id.clone(),
            root_public_key: STANDARD.encode(forger.verifying_key().as_bytes()),
            members: vec![],
        };
        assert!(verified_members(&network, other).is_err());
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
        };
        let me = membership::sign_member(
            membership::sign_invite(&root, &invite, "bob", "2099-01-01T00:00:00Z"),
            &invite,
            store.signing_key.verifying_key().as_bytes(),
            "2026-10-05T00:00:00Z",
        );
        let map = || WireMap {
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

    #[test]
    fn version_two_state_migrates_to_latest() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("host");
        let identity = Store::open(&path).unwrap().identity();
        let connection = Connection::open(path.join("host.db")).unwrap();
        connection
            .execute_batch(
                "DROP TABLE adapter_outbound; DROP TABLE adapter_routes; DROP TABLE outbound_replies; DROP TABLE received_replies; DROP TABLE deliveries; DROP TABLE adapter_credentials; DROP TABLE network_members; DROP TABLE networks; PRAGMA user_version = 2;",
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
        assert_eq!(version, 5);
        drop(store);
        Connection::open(path.join("host.db"))
            .unwrap()
            .execute_batch("PRAGMA user_version = 6;")
            .unwrap();
        assert!(Store::open(&path).is_err());
    }
}
