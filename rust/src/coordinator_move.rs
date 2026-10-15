//! Coordinator moves and repair. The network root or a current administrator
//! signs a move naming a new coordinator for one network; hosts learn it from
//! the map, a peer push, or a peer lookup, and it takes precedence over
//! coordinator successors. Any member host re-submits, through the
//! coordinator's import, the signed statements a coordinator lacks.
use crate::{
    api::{blocking, decode},
    membership::{
        self, CoordinatorPending, KeySigner, SOURCE_MOVE, check_network, invalid, verify_lines,
    },
    model::Error,
    network::{Member, Network, Statements, WireMap, coordinator, coordinator_error},
    peer_store::{Peer, json},
    store::{Store, now},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::get,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

/// The first line of a coordinator move statement.
pub const MOVE_CONTEXT: &str = "peerspan-coordinator-move-v1";
/// `signer` of a move signed by the network root.
pub const ROOT_SIGNER: &str = "root";
/// Failed syncs after which a host asks its peers for a move.
const LOOKUP_AFTER: u32 = 3;
/// Bound on one peer push or lookup.
const PEER_BOUND: Duration = Duration::from_secs(8);

/// A move of one network to another coordinator, signed by the root (raw
/// Ed25519 or `SSHSIG` for an SSH root) or a current administrator (`SSHSIG`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorMove {
    pub network_id: String,
    pub sequence: u64,
    pub address: String,
    pub public_key: String,
    pub moved_at: String,
    /// `root`, or the administrator's `person_public_key`.
    pub signer: String,
    pub signature: String,
}
impl CoordinatorMove {
    fn lines(&self) -> [String; 6] {
        [
            MOVE_CONTEXT.to_owned(),
            self.network_id.clone(),
            self.sequence.to_string(),
            self.address.clone(),
            self.public_key.clone(),
            self.moved_at.clone(),
        ]
    }
    /// Signs a move. `signer` is `root` or the administrator's person key.
    pub fn sign(
        key: &KeySigner,
        signer: &str,
        network: &str,
        sequence: u64,
        address: &str,
        public_key: &str,
        at: &str,
    ) -> Result<Self, Error> {
        let mut m = Self {
            network_id: network.into(),
            sequence,
            address: address.into(),
            public_key: public_key.into(),
            moved_at: at.into(),
            signer: signer.into(),
            signature: String::new(),
        };
        m.check_shape()?;
        let lines = m.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        m.signature = key.sign(&refs)?;
        Ok(m)
    }
    fn check_shape(&self) -> Result<(), Error> {
        if self.sequence < 1 {
            return Err(invalid("move sequences start at 1"));
        }
        membership::split_host_port(&self.address)
            .map_err(|_| invalid("move address is not a coordinator address"))?;
        membership::public_key(&self.public_key)
            .map_err(|_| invalid("move public_key is not a public key"))?;
        Ok(())
    }
    /// Verifies the move for `network` against the signers this host
    /// accepts now: the current root, or a current administrator. A valid
    /// signature by anyone else is `Forbidden`.
    pub(crate) fn verify(
        &self,
        network: &str,
        authority: &crate::admins::Authority,
    ) -> Result<(), Error> {
        check_network(&self.network_id, network)?;
        self.check_shape()?;
        let lines = self.lines();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        if self.signer == ROOT_SIGNER {
            return verify_lines(authority.current(), &refs, &self.signature);
        }
        if crate::persons::sshsig_signer(&self.signature).as_deref() != Some(self.signer.as_str()) {
            return Err(invalid("an administrator's move is signed with SSHSIG"));
        }
        crate::persons::verify_sshsig(&self.signer, &refs, &self.signature)?;
        if authority.admins.contains(&self.signer) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
}

/// Per-network move and repair bookkeeping, kept in memory.
#[derive(Debug, Default)]
pub(crate) struct Tracker {
    /// Consecutive failed syncs (pinned and pending coordinator).
    failures: u32,
    last_lookup: Option<Instant>,
    last_import: Option<Instant>,
}

fn interval(store: &Store) -> Duration {
    Duration::from_secs(store.coordination_interval.load(Ordering::Relaxed).max(1))
}
/// True at most once per network per sync interval; `stamp` picks the
/// last time of the action.
fn once_per_interval(
    store: &Store,
    id: &str,
    stamp: impl FnOnce(&mut Tracker) -> &mut Option<Instant>,
) -> bool {
    let every = interval(store);
    let Ok(mut trackers) = store.coordinator_moves.lock() else {
        return false;
    };
    let slot = stamp(trackers.entry(id.to_owned()).or_default());
    // Interval syncs are spaced by at least the interval; allow a little
    // scheduling slack so one import per interval is not skipped.
    let due = slot.is_none_or(|t| t.elapsed() + every / 10 >= every);
    if due {
        *slot = Some(Instant::now());
    }
    due
}
fn may_import(store: &Store, id: &str) -> bool {
    once_per_interval(store, id, |t| &mut t.last_import)
}
/// A sync of the network succeeded.
pub(crate) fn synced(store: &Store, id: &str) {
    if let Ok(mut trackers) = store.coordinator_moves.lock() {
        trackers.entry(id.to_owned()).or_default().failures = 0;
    }
}

impl Store {
    /// The latest valid move this host holds for a network.
    pub(crate) fn latest_move(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<Option<CoordinatorMove>, Error> {
        connection
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'move' AND subject = ''",
                [id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(json)
            .transpose()
    }
    /// One more than the higher of the latest held and the applied move.
    pub(crate) fn next_move_sequence(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<u64, Error> {
        let latest = self.latest_move(connection, id)?.map_or(0, |m| m.sequence);
        Ok(latest.max(self.applied_move(connection, id)?) + 1)
    }
    /// The sequence of the move this host last switched for, or 0.
    fn applied_move(&self, connection: &Connection, id: &str) -> Result<u64, Error> {
        Ok(connection
            .query_row(
                "SELECT record FROM network_statements WHERE network_id = ?1 AND kind = 'move_applied' AND subject = ''",
                [id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|r| serde_json::from_str::<Value>(&r).ok())
            .and_then(|v| v["sequence"].as_u64())
            .unwrap_or(0))
    }
    /// Verifies a move from a map, a peer, or the CLI against this host's
    /// current view of the network.
    fn verify_move(
        &self,
        connection: &Connection,
        network: &Network,
        value: &Value,
    ) -> Result<CoordinatorMove, Error> {
        let m: CoordinatorMove =
            serde_json::from_value(value.clone()).map_err(|_| invalid("malformed move"))?;
        m.verify(&network.id, &self.authority(connection, network)?)?;
        Ok(m)
    }
    /// Verifies and stores a move. A valid move with a sequence higher than
    /// the applied one that names a coordinator other than the pin becomes
    /// the pending coordinator, replacing a pending successor or an older
    /// pending move. Returns the network and the newly pending coordinator.
    pub(crate) fn accept_move(
        &self,
        id: &str,
        value: &Value,
    ) -> Result<(Network, Option<CoordinatorPending>), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut network = self.network_record(&tx, id)?;
        let m = self.verify_move(&tx, &network, value)?;
        let latest = self.latest_move(&tx, id)?;
        if latest.as_ref().is_none_or(|l| l.sequence < m.sequence) {
            tx.execute(
                "INSERT OR REPLACE INTO network_statements VALUES (?1, 'move', '', ?2)",
                params![id, serde_json::to_string(&m)?],
            )?;
        }
        let applied = self.applied_move(&tx, id)?;
        let mut pending = None;
        if m.sequence > applied {
            let pinned = m.address == network.coordinator_address
                && m.public_key == network.coordinator_public_key;
            let current = network.coordinator_pending.as_ref();
            if pinned {
                // Already there: the move counts as applied, and an older
                // pending move is superseded.
                record_applied(&tx, id, m.sequence)?;
                if current.is_some_and(CoordinatorPending::is_move) {
                    network.coordinator_pending = None;
                }
            } else if !current
                .is_some_and(|p| p.is_move() && p.move_sequence.unwrap_or(0) >= m.sequence)
            {
                let next = CoordinatorPending {
                    address: m.address.clone(),
                    public_key: m.public_key.clone(),
                    sequence: m.sequence,
                    source: SOURCE_MOVE.to_owned(),
                    move_sequence: Some(m.sequence),
                };
                network.coordinator_pending = Some(next.clone());
                pending = Some(next);
            }
            tx.execute(
                "UPDATE networks SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&network)?, id],
            )?;
        }
        tx.commit()?;
        Ok((network, pending))
    }
    /// Whether `host` is a current member host of a network this host
    /// belongs to; an unknown network is `NotFound`.
    fn is_member_host(&self, id: &str, host: &str) -> Result<bool, Error> {
        let connection = self.connection()?;
        self.network_record(&connection, id)?;
        if host == self.identity().id {
            return Ok(false);
        }
        Ok(connection
            .query_row(
                "SELECT 1 FROM network_members WHERE network_id = ?1 AND host_id = ?2",
                params![id, host],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
    /// The signed fields of a map, as this host holds them, in the shapes the
    /// coordinator's map serves.
    pub(crate) fn import_map(&self, id: &str) -> Result<Value, Error> {
        let connection = self.connection()?;
        let held = Statements::load(&connection, id)?;
        let bindings = self.held_bindings(&connection, id)?;
        let mut members: Vec<Member> = self.stored_members(&connection, id)?;
        members.sort_by(|a, b| a.host_id.cmp(&b.host_id));
        let members: Vec<Value> = members
            .iter()
            .map(|m| {
                json!({
                    "host_id": m.host_id,
                    "membership": m.membership,
                    "admission": m.admission,
                    "binding": bindings.get(&m.public_key),
                    "address": m.address,
                    "candidates": m.candidates,
                    "updated_at": m.updated_at,
                })
            })
            .collect();
        let persons: Vec<Value> = self
            .stored_persons(&connection, id)?
            .into_iter()
            .map(|p| {
                json!({
                    "person_id": p.person_id,
                    "person_public_key": p.person_public_key,
                    "member": p.member,
                    "admission": p.admission,
                    "membership": p.membership,
                })
            })
            .collect();
        let mut revocations = Vec::new();
        let mut revoke = |kind: &str, statement: Value| {
            revocations.push(json!({"kind": kind, "statement": statement}));
        };
        for r in &held.hosts {
            revoke("host", serde_json::to_value(r)?);
        }
        for r in &held.invites {
            revoke("invite", serde_json::to_value(r)?);
        }
        for r in &held.leaves {
            revoke("leave", serde_json::to_value(r)?);
        }
        for r in &held.person_removals {
            revoke("person", serde_json::to_value(r)?);
        }
        for r in &held.unbindings {
            revoke("unbind", serde_json::to_value(r)?);
        }
        for r in &held.admin_removals {
            revoke("admin", serde_json::to_value(r)?);
        }
        Ok(json!({
            "members": members,
            "rotations": held.rotations,
            "attestations": held.attestations,
            "revocations": revocations,
            "persons": persons,
            "admins": held.admins,
            "groups": held.groups,
            "policies": held.policies,
            "move": self.latest_move(&connection, id)?,
        }))
    }
    /// Verified bindings by host key.
    fn held_bindings(
        &self,
        connection: &Connection,
        id: &str,
    ) -> Result<BTreeMap<String, Value>, Error> {
        let mut statement = connection.prepare(
            "SELECT subject, record FROM network_statements WHERE network_id = ?1 AND kind = 'binding'",
        )?;
        let rows = statement
            .query_map([id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(host, record)| Ok((host, json(record)?)))
            .collect()
    }
    /// What this host holds before a sync: the summary repair compares and
    /// the map an import would send.
    pub(crate) fn held_snapshot(&self, id: &str) -> Result<Held, Error> {
        Ok(Held {
            summary: self.held_summary(id)?,
            map: self.import_map(id)?,
        })
    }
    /// What this host holds for a network, in the summary's terms.
    fn held_summary(&self, id: &str) -> Result<MapSummary, Error> {
        let connection = self.connection()?;
        let network = self.network_record(&connection, id)?;
        let held = Statements::load(&connection, id)?;
        let mut s = MapSummary::default();
        let members = self.stored_members(&connection, id)?;
        s.members = members
            .iter()
            .map(|m| {
                let invite = m.membership.as_ref().map(|i| i.invite_public_key.clone());
                (m.host_id.clone(), (m.public_key.clone(), invite))
            })
            .collect();
        for (host, b) in self.held_bindings(&connection, id)? {
            if let Some(person) = b["person_public_key"].as_str() {
                s.bindings.insert((person.to_owned(), host));
            }
        }
        s.rotations = held.rotations.iter().map(|r| r.epoch).collect();
        s.attestations = held
            .attestations
            .iter()
            .map(|a| (a.epoch, a.host_public_key.clone()))
            .collect();
        let mut revoked = |kind: &str, subject: String| {
            s.revocations.insert((kind.to_owned(), subject));
        };
        held.hosts
            .iter()
            .for_each(|r| revoked("host", r.host_public_key.clone()));
        held.invites
            .iter()
            .for_each(|r| revoked("invite", r.invite_public_key.clone()));
        held.leaves
            .iter()
            .for_each(|r| revoked("leave", r.host_public_key.clone()));
        held.person_removals
            .iter()
            .for_each(|r| revoked("person", r.person_public_key.clone()));
        held.unbindings.iter().for_each(|r| {
            revoked(
                "unbind",
                format!("{} {}", r.person_public_key, r.host_public_key),
            )
        });
        held.admin_removals.iter().for_each(|r| {
            revoked(
                "admin",
                format!("{} {}", r.person_public_key, r.revoke_admitted),
            )
        });
        s.persons = self
            .stored_persons(&connection, id)?
            .into_iter()
            .map(|p| p.person_public_key)
            .collect();
        for d in &held.admins {
            let epoch = s.admins.entry(d.person_public_key.clone()).or_default();
            *epoch = (*epoch).max(d.epoch);
        }
        for g in &held.groups {
            s.groups.insert(g.name.clone(), g.version);
        }
        // Policies count within their window.
        let at = now();
        for p in held
            .policies
            .iter()
            .filter(|p| crate::network::time_after(&p.valid_until, &at))
        {
            s.policies.insert(p.person_public_key.clone(), p.version);
        }
        // A held move counts while it still verifies.
        s.move_sequence = match self.latest_move(&connection, id)? {
            Some(m)
                if m.verify(id, &self.authority(&connection, &network)?)
                    .is_ok() =>
            {
                m.sequence
            }
            _ => 0,
        };
        Ok(s)
    }
}

/// Records `sequence` as the applied move of a network.
pub(crate) fn record_applied(tx: &Connection, id: &str, sequence: u64) -> Result<(), Error> {
    tx.execute(
        "INSERT OR REPLACE INTO network_statements VALUES (?1, 'move_applied', '', ?2)",
        params![id, json!({ "sequence": sequence }).to_string()],
    )?;
    Ok(())
}

/// What a host held for a network before applying a map.
pub(crate) struct Held {
    summary: MapSummary,
    map: Value,
}

/// What a coordinator map carries, reduced to what repair compares.
#[derive(Debug, Default)]
pub(crate) struct MapSummary {
    /// host ID -> (host key, invite key)
    members: BTreeMap<String, (String, Option<String>)>,
    /// (person key, host key)
    bindings: BTreeSet<(String, String)>,
    rotations: BTreeSet<u64>,
    attestations: BTreeSet<(u64, String)>,
    /// (wire kind, subject)
    revocations: BTreeSet<(String, String)>,
    persons: BTreeSet<String>,
    /// Highest delegation epoch per person key.
    admins: BTreeMap<String, u64>,
    groups: BTreeMap<String, u64>,
    policies: BTreeMap<String, u64>,
    move_sequence: u64,
}
impl MapSummary {
    pub(crate) fn of(map: &WireMap) -> Self {
        let text = |v: &Value, f: &str| v[f].as_str().map(str::to_owned);
        let mut s = Self::default();
        for m in &map.members {
            if let Some(host) = text(m, "host_id") {
                let key = text(&m["membership"], "host_public_key")
                    .or_else(|| text(&m["admission"], "host_public_key"))
                    .unwrap_or_default();
                let invite = text(&m["membership"], "invite_public_key");
                s.members.insert(host, (key, invite));
            }
            if let (Some(person), Some(host)) = (
                text(&m["binding"], "person_public_key"),
                text(&m["binding"], "host_public_key"),
            ) {
                s.bindings.insert((person, host));
            }
        }
        s.rotations = map
            .rotations
            .iter()
            .filter_map(|r| r["epoch"].as_u64())
            .collect();
        s.attestations = map
            .attestations
            .iter()
            .filter_map(|a| Some((a["epoch"].as_u64()?, text(a, "host_public_key")?)))
            .collect();
        for entry in &map.revocations {
            let statement = &entry["statement"];
            let Some(kind) = entry["kind"].as_str() else {
                continue;
            };
            let subject = match kind {
                "host" | "leave" => text(statement, "host_public_key"),
                "invite" => text(statement, "invite_public_key"),
                "person" => text(statement, "person_public_key"),
                "unbind" => text(statement, "person_public_key")
                    .zip(text(statement, "host_public_key"))
                    .map(|(p, h)| format!("{p} {h}")),
                "admin" => text(statement, "person_public_key").map(|p| {
                    format!(
                        "{p} {}",
                        statement["revoke_admitted"].as_bool().unwrap_or(false)
                    )
                }),
                _ => None,
            };
            if let Some(subject) = subject {
                s.revocations.insert((kind.to_owned(), subject));
            }
        }
        for p in &map.persons {
            let key = text(p, "person_public_key")
                .or_else(|| text(&p["admission"], "person_public_key"))
                .or_else(|| text(&p["membership"], "person_public_key"));
            if let Some(key) = key {
                s.persons.insert(key);
            }
        }
        for d in &map.admins {
            if let (Some(key), Some(epoch)) = (text(d, "person_public_key"), d["epoch"].as_u64()) {
                let e = s.admins.entry(key).or_default();
                *e = (*e).max(epoch);
            }
        }
        for g in &map.groups {
            if let (Some(name), Some(version)) = (text(g, "name"), g["version"].as_u64()) {
                let v = s.groups.entry(name).or_default();
                *v = (*v).max(version);
            }
        }
        for p in &map.policies {
            if let (Some(key), Some(version)) =
                (text(p, "person_public_key"), p["version"].as_u64())
            {
                let v = s.policies.entry(key).or_default();
                *v = (*v).max(version);
            }
        }
        s.move_sequence = map.r#move["sequence"].as_u64().unwrap_or(0);
        s
    }
    fn revoked(&self, kind: &str, subject: &str) -> bool {
        self.revocations
            .contains(&(kind.to_owned(), subject.to_owned()))
    }
    /// True when `self` (what the host held before the sync) has a statement
    /// `map` lacks. A held member, person, or binding the map revokes or
    /// removes does not count.
    fn lacking_from(&self, map: &Self) -> bool {
        let higher = |held: &BTreeMap<String, u64>, served: &BTreeMap<String, u64>| {
            held.iter()
                .any(|(k, v)| served.get(k).is_none_or(|s| s < v))
        };
        let gone = |key: &str| map.revoked("host", key) || map.revoked("leave", key);
        let members = self.members.iter().any(|(id, (key, invite))| {
            !map.members.contains_key(id)
                && !gone(key)
                && !invite.as_deref().is_some_and(|i| map.revoked("invite", i))
        });
        let persons = self
            .persons
            .iter()
            .any(|p| !map.persons.contains(p) && !map.revoked("person", p));
        let bindings = self.bindings.iter().any(|(person, host)| {
            !map.bindings.contains(&(person.clone(), host.clone()))
                && !gone(host)
                && !map.revoked("person", person)
                && !map.revoked("unbind", &format!("{person} {host}"))
        });
        let revocations = self.revocations.iter().any(|(kind, subject)| {
            !map.revocations.contains(&(kind.clone(), subject.clone()))
                && !(kind == "admin"
                    && subject
                        .strip_suffix(" false")
                        .is_some_and(|k| map.revoked("admin", &format!("{k} true"))))
        });
        members
            || persons
            || bindings
            || revocations
            || !self.rotations.is_subset(&map.rotations)
            || !self.attestations.is_subset(&map.attestations)
            || higher(&self.admins, &map.admins)
            || higher(&self.groups, &map.groups)
            || higher(&self.policies, &map.policies)
            || self.move_sequence > map.move_sequence
    }
}

/// Submits what this host holds to the coordinator at `address` with `key`.
/// `with_move` replaces the held move (the mover's new one). Returns the
/// status and body.
async fn import_to(
    store: &Arc<Store>,
    network: &Network,
    address: &str,
    key: &str,
    with_move: Option<&CoordinatorMove>,
    held: Option<Value>,
) -> Result<(u16, Value), Error> {
    let id = network.id.clone();
    let mut map = match held {
        Some(map) => map,
        None => blocking(store.clone(), move |s| s.import_map(&id)).await?,
    };
    if let Some(m) = with_move {
        map["move"] = serde_json::to_value(m)?;
    }
    let body = json!({
        "name": network.name,
        "root_public_key": network.root_public_key,
        "map": map,
    });
    let (status, body) = coordinator(
        store.clone(),
        address,
        key,
        "/coord/v1/networks/import".into(),
        body,
    )
    .await
    .map_err(|e| Error::Unavailable(format!("{e:#}")))?;
    let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if matches!(status, 200 | 201) {
        Ok((status, value))
    } else {
        Err(Error::Unavailable(coordinator_error(status, &body)))
    }
}

/// Imports a network into a coordinator that answered a sync with 403 or
/// 404, at most once per network per interval; true when it was imported.
pub(crate) async fn import_unknown(
    store: &Arc<Store>,
    network: &Network,
    address: &str,
    key: &str,
) -> bool {
    may_import(store, &network.id)
        && import_to(store, network, address, key, None, None)
            .await
            .is_ok()
}

/// After a sync: imports what this host held before it into the pinned
/// coordinator when the map lacked a statement, at most once per network per
/// interval; true when it imported.
pub(crate) async fn repair(
    store: &Arc<Store>,
    network: &Network,
    served: &MapSummary,
    held: Option<Held>,
) -> bool {
    let Some(held) = held else {
        return false;
    };
    held.summary.lacking_from(served)
        && may_import(store, &network.id)
        && import_to(
            store,
            network,
            &network.coordinator_address,
            &network.coordinator_public_key,
            None,
            Some(held.map),
        )
        .await
        .is_ok()
}

/// A sync with the pinned and any pending coordinator failed. After three
/// consecutive failures, asks every member reachable on a direct path for
/// its move, at most once per interval, and switches to a newer one.
pub(crate) async fn sync_failed(store: &Arc<Store>, network: Network) -> Result<Network, Error> {
    let lookup = {
        let Ok(mut trackers) = store.coordinator_moves.lock() else {
            return Ok(network);
        };
        let tracker = trackers.entry(network.id.clone()).or_default();
        tracker.failures = tracker.failures.saturating_add(1);
        tracker.failures >= LOOKUP_AFTER
    };
    if !lookup || !once_per_interval(store, &network.id, |t| &mut t.last_lookup) {
        return Ok(network);
    }
    let id = network.id.clone();
    let members = blocking(store.clone(), move |s| {
        let connection = s.connection()?;
        s.stored_members(&connection, &id)
    })
    .await?;
    let own = store.identity().id;
    let path = format!("/peer/v1/networks/{}/move", network.id);
    let asks = members
        .into_iter()
        .filter(|m| m.host_id != own && !m.address.is_empty())
        .map(|m| {
            let store = store.clone();
            let path = path.clone();
            async move {
                let peer = Peer {
                    id: m.host_id,
                    public_key: m.public_key,
                    address: m.address,
                };
                match tokio::time::timeout(
                    PEER_BOUND,
                    crate::quic::request_direct(store, &peer, "GET", &path, b""),
                )
                .await
                {
                    Ok(Ok((200, body))) => serde_json::from_slice::<Value>(&body)
                        .ok()
                        .map(|v| v["move"].clone())
                        .filter(|v| !v.is_null()),
                    _ => None,
                }
            }
        });
    let mut moves: Vec<Value> = join_all(asks).await.into_iter().flatten().collect();
    moves.sort_by_key(|m| std::cmp::Reverse(m["sequence"].as_u64().unwrap_or(0)));
    let mut network = network;
    let mut learned = false;
    for m in moves {
        let id = network.id.clone();
        if let Ok((n, pending)) = blocking(store.clone(), move |s| s.accept_move(&id, &m)).await {
            network = n;
            learned |= pending.is_some();
        }
    }
    if !learned {
        return Ok(network);
    }
    follow_pending_move(store, network).await
}

/// Runs the futures concurrently and returns their outputs.
async fn join_all<T: Send + 'static>(
    futures: impl IntoIterator<Item = impl std::future::Future<Output = T> + Send + 'static>,
) -> Vec<T> {
    let mut set = tokio::task::JoinSet::new();
    for future in futures {
        set.spawn(future);
    }
    let mut out = Vec::new();
    while let Some(result) = set.join_next().await {
        if let Ok(value) = result {
            out.push(value);
        }
    }
    out
}

/// Switches to a pending move now; on failure records the error.
pub(crate) async fn follow_pending_move(
    store: &Arc<Store>,
    network: Network,
) -> Result<Network, Error> {
    let Some(pending) = network.coordinator_pending.clone().filter(|p| p.is_move()) else {
        return Ok(network);
    };
    match crate::network::switch_coordinator(store, network.clone(), pending.clone()).await {
        Ok(network) => {
            synced(store, &network.id);
            Ok(network)
        }
        Err(Error::Internal(error)) => Err(Error::Internal(error)),
        Err(error) => {
            let message = crate::network::pending_error(&pending, error);
            let id = network.id;
            blocking(store.clone(), move |s| s.record_sync_error(&id, message)).await
        }
    }
}

/// `POST /v1/networks/{id}/move`: the coordinator, for the daemon to sign
/// with the root seed, or a move the CLI signed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveNetwork {
    pub coordinator_address: String,
    pub coordinator_public_key: String,
    /// Null or absent for the daemon to sign with its root seed.
    #[serde(default, rename = "move")]
    pub signed: Option<Value>,
}

/// `network move`: signs (or takes) the move, imports the network into the
/// new coordinator, submits the move to the current one, pushes it to the
/// other members, and switches to the new coordinator.
pub async fn move_network(
    store: Arc<Store>,
    id: String,
    request: MoveNetwork,
) -> Result<Value, Error> {
    let lookup = id.clone();
    let (network, m) = blocking(store.clone(), move |s| {
        let connection = s.connection()?;
        let network = s.network_record(&connection, &lookup)?;
        let latest = s.next_move_sequence(&connection, &lookup)? - 1;
        let m = match request.signed {
            Some(value) => {
                let m = s.verify_move(&connection, &network, &value)?;
                if request.coordinator_address != m.address
                    || request.coordinator_public_key != m.public_key
                {
                    return Err(invalid("the move names another coordinator"));
                }
                m
            }
            None => {
                let (address, key) = (request.coordinator_address, request.coordinator_public_key);
                if address == network.coordinator_address && key == network.coordinator_public_key {
                    return Err(invalid("the network already uses that coordinator"));
                }
                let root = s.current_root(&connection, &lookup)?;
                CoordinatorMove::sign(
                    &KeySigner::Raw(&root),
                    ROOT_SIGNER,
                    &lookup,
                    latest + 1,
                    &address,
                    &key,
                    &now(),
                )?
            }
        };
        if m.address == network.coordinator_address
            && m.public_key == network.coordinator_public_key
        {
            return Err(invalid("the network already uses that coordinator"));
        }
        if m.sequence <= latest {
            return Err(Error::Conflict(format!(
                "this host already holds move sequence {latest}"
            )));
        }
        Ok((network, m))
    })
    .await?;
    // 1-2. Import into the new coordinator; nothing changes if that fails.
    let (_, imported) = import_to(&store, &network, &m.address, &m.public_key, Some(&m), None)
        .await
        .map_err(|e| match e {
            Error::Unavailable(message) => {
                Error::Unavailable(format!("import into {}: {message}", m.address))
            }
            other => other,
        })?;
    let (lookup, value) = (id.clone(), serde_json::to_value(&m)?);
    let (network, _) = blocking(store.clone(), move |s| s.accept_move(&lookup, &value)).await?;
    // 3. The current coordinator, once.
    let previous = match coordinator(
        store.clone(),
        &network.coordinator_address,
        &network.coordinator_public_key,
        format!("/coord/v1/networks/{}/moves", network.id),
        json!({ "move": m }),
    )
    .await
    {
        Ok((200, _)) => "accepted",
        Ok((status, _)) if (400..500).contains(&status) => "refused",
        _ => "unreachable",
    };
    // 4. Every other current member host this host can reach.
    let lookup = id.clone();
    let members = blocking(store.clone(), move |s| {
        let connection = s.connection()?;
        s.stored_members(&connection, &lookup)
    })
    .await?;
    let own = store.identity().id;
    let others: Vec<Member> = members.into_iter().filter(|m| m.host_id != own).collect();
    let body = serde_json::to_vec(&json!({ "move": m }))?;
    let path = format!("/peer/v1/networks/{id}/move");
    let pushes = others.iter().map(|member| {
        let (store, body, path) = (store.clone(), body.clone(), path.clone());
        let host = member.host_id.clone();
        async move {
            let Ok(peer) = blocking(store.clone(), move |s| s.dial_target(&host)).await else {
                return false;
            };
            // The direct path first: a cached relayed connection through a
            // stopped coordinator would hold the request until it times out.
            let mut failure = String::new();
            if !peer.address.is_empty() {
                match tokio::time::timeout(
                    PEER_BOUND / 2,
                    crate::quic::request_direct(store.clone(), &peer, "POST", &path, &body),
                )
                .await
                {
                    Ok(Ok((200, _))) => return true,
                    Ok(Ok((status, _))) => failure = format!("HTTP {status}"),
                    Ok(Err(error)) => failure = format!("{error:#}"),
                    Err(_) => failure = "timed out".into(),
                }
            }
            let outcome = tokio::time::timeout(
                PEER_BOUND,
                crate::quic::request(store, &peer, "POST", &path, &body),
            )
            .await;
            if !matches!(outcome, Ok(Ok((200, _)))) {
                let last = match outcome {
                    Ok(Ok((status, _))) => format!("HTTP {status}"),
                    Ok(Err(error)) => format!("{error:#}"),
                    Err(_) => "timed out".into(),
                };
                eprintln!(
                    "coordinator move push to {}: direct: {failure}; {last}",
                    peer.id
                );
                return false;
            }
            true
        }
    });
    let pushed = join_all(pushes).await.into_iter().filter(|ok| *ok).count();
    // 5. Sync the new coordinator and switch this host's pin.
    let _ = follow_pending_move(&store, network).await?;
    Ok(json!({
        "network_id": id,
        "sequence": m.sequence,
        "coordinator": {"address": m.address, "public_key": m.public_key},
        "imported": {
            "added": imported["added"].as_u64().unwrap_or(0),
            "skipped": imported["skipped"].as_u64().unwrap_or(0),
        },
        "previous_coordinator": previous,
        "pushed": pushed,
        "members": others.len(),
    }))
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route(
        "/v1/networks/{id}/move",
        get(local_move_route).post(move_route),
    )
}
async fn local_move_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| {
            let connection = s.connection()?;
            s.network_record(&connection, &id)?;
            Ok(json!({
                "move": s.latest_move(&connection, &id)?,
                "next_sequence": s.next_move_sequence(&connection, &id)?,
            }))
        })
        .await?,
    ))
}
async fn move_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: MoveNetwork = decode(body)?;
    Ok(Json(move_network(store, id, request).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushMove {
    #[serde(rename = "move")]
    signed: Value,
}

/// Peer routes: the move this host holds, and delivering one. The caller
/// must be a current member host of the network.
pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new().route(
        "/peer/v1/networks/{id}/move",
        get(peer_move_route).post(peer_push_route),
    )
}
async fn peer_move_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| {
            if !s.is_member_host(&id, &sender)? {
                return Err(Error::Forbidden);
            }
            let connection = s.connection()?;
            let m = s.latest_move(&connection, &id)?.ok_or(Error::NotFound)?;
            Ok(json!({ "move": m }))
        })
        .await?,
    ))
}
async fn peer_push_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let lookup = (id.clone(), sender);
    let member = blocking(store.clone(), move |s| {
        s.is_member_host(&lookup.0, &lookup.1)
    })
    .await?;
    if !member {
        return Err(Error::Forbidden);
    }
    let request: PushMove = decode(body)?;
    let lookup = id.clone();
    let (network, pending) = blocking(store.clone(), move |s| {
        s.accept_move(&lookup, &request.signed)
            .map_err(|e| match e {
                Error::Internal(e) => Error::Internal(e),
                Error::Invalid(m) => Error::Invalid(m),
                _ => Error::Invalid("invalid move".into()),
            })
    })
    .await?;
    if pending.is_some() {
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(error) = follow_pending_move(&store, network).await {
                eprintln!("coordinator move error: {error}");
            }
        });
    }
    let held = blocking(store, move |s| {
        let connection = s.connection()?;
        s.latest_move(&connection, &id)
    })
    .await?;
    Ok(Json(json!({ "move": held })))
}
