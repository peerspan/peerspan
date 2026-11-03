//! Format-2 maps and atomic durable projection. Hints confer no authority.
use super::{
    catalog, crypto,
    support::{self, Failure},
};
use crate::{
    membership,
    network::{Member, Network},
    store::{Store, append_event},
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, value::RawValue};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub network_id: String,
    pub name: String,
    pub genesis_root_public_key: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hint {
    pub host_id: String,
    pub host_public_key: String,
    pub membership_proof_id: String,
    pub binding_proof_id: String,
    pub join_proof_id: String,
    pub address: String,
    pub candidates: Vec<String>,
    pub updated_at: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Map {
    pub format: u64,
    pub network: Box<RawValue>,
    pub catalog: Box<RawValue>,
    pub members: Vec<Hint>,
}
impl Map {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        ensure!(raw.len() <= 16 << 20, Failure::new("invalid", "-", "map"));
        let map: Self = crate::linking::decode_stored_json(raw, "format network catalog members")?;
        ensure!(map.format == 2, Failure::new("invalid", "-", "map"));
        Ok(map)
    }
}
fn candidates(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        if value
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|a| a.port() != 0)
            && !out.contains(value)
        {
            out.push(value.clone());
        }
        if out.len() == crate::disco::MAX_ENDPOINTS {
            break;
        }
    }
    out
}
pub fn verify(
    store: &Store,
    connection: &Connection,
    n: &Network,
    raw: &[u8],
) -> Result<(catalog::Projection, Vec<Member>)> {
    let wire = Map::decode(raw)?;
    let descriptor: Descriptor = crate::linking::decode_mutation(
        wire.network.get().as_bytes(),
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    ensure!(
        descriptor.network_id == n.id
            && descriptor.name == n.name
            && descriptor.genesis_root_public_key == n.root_public_key
            && descriptor.coordinator_address == n.coordinator_address
            && descriptor.coordinator_public_key == n.coordinator_public_key,
        Failure::new("invalid", "-", "coordinator")
    );
    let remote = catalog::decode(wire.catalog.get().as_bytes(), &n.id)?;
    let prior = catalog::read(connection, &n.id)?;
    let old = catalog::decode(&prior, &n.id)?;
    let present: BTreeSet<_> = remote.objects.iter().map(|o| o.id.as_str()).collect();
    let missing: Vec<_> = old
        .objects
        .iter()
        .filter(|o| !present.contains(o.id.as_str()))
        .map(|o| o.id.clone())
        .collect();
    ensure!(missing.is_empty(), Failure::required("-", "map", missing));
    let merged = catalog::merge(&n.id, &[&prior, wire.catalog.get().as_bytes()])?;
    let projection = catalog::verify(connection, n, &merged, support::now()?)?;
    let members = verified_hints(store, &projection, &wire)?;
    Ok((projection, members))
}
pub(crate) fn verified_hints(
    store: &Store,
    projection: &catalog::Projection,
    wire: &Map,
) -> Result<Vec<Member>> {
    let proofs: BTreeMap<_, _> = projection
        .network
        .members
        .iter()
        .map(|p| (p.host_public_key.as_str(), p))
        .collect();
    let mut members = Vec::new();
    let mut previous = "";
    for hint in &wire.members {
        ensure!(
            hint.host_id.as_str() > previous,
            Failure::new("invalid", "-", "map")
        );
        previous = &hint.host_id;
        let Some(proof) = proofs.get(hint.host_public_key.as_str()) else {
            continue;
        };
        let Ok(key) = membership::canonical(&hint.host_public_key, 32) else {
            continue;
        };
        if hint.host_id != crate::peer_store::key_id(&key)
            || hint.membership_proof_id != proof.membership_proof_id
            || hint.binding_proof_id != proof.binding_proof_id
            || hint.join_proof_id != proof.join_proof_id
            || crate::membership::time(&hint.updated_at).is_err()
        {
            continue;
        }
        let (person_id, person_member) = if proof.person_public_key == "-" {
            (None, None)
        } else {
            (
                Some(crate::persons::person_id_of(&proof.person_public_key)?),
                projection
                    .network
                    .facts
                    .person_labels
                    .get(&proof.person_public_key)
                    .cloned(),
            )
        };
        members.push(Member {
            host_id: hint.host_id.clone(),
            public_key: hint.host_public_key.clone(),
            member: proof.member.clone(),
            address: if membership::advertised(&hint.address).is_ok() {
                hint.address.clone()
            } else {
                String::new()
            },
            candidates: candidates(&hint.candidates),
            updated_at: hint.updated_at.clone(),
            membership: None,
            admission: None,
            person_id,
            person_member,
        });
    }
    ensure!(
        !projection
            .network
            .facts
            .state
            .hosts
            .get(&store.identity().public_key)
            .copied()
            .unwrap_or(false)
            || members.iter().any(|m| m.host_id == store.identity().id),
        Failure::new("proof_required", "-", "map")
    );
    Ok(members)
}
pub fn projected_members(p: &catalog::Projection, old: &[Member], at: &str) -> Result<Vec<Member>> {
    let hints: BTreeMap<_, _> = old.iter().map(|m| (m.public_key.as_str(), m)).collect();
    let mut members = Vec::new();
    for proof in &p.network.members {
        let key = membership::canonical(&proof.host_public_key, 32)?;
        let hint = hints.get(proof.host_public_key.as_str());
        let (person_id, person_member) = if proof.person_public_key == "-" {
            (None, None)
        } else {
            (
                Some(crate::persons::person_id_of(&proof.person_public_key)?),
                p.network
                    .facts
                    .person_labels
                    .get(&proof.person_public_key)
                    .cloned(),
            )
        };
        members.push(Member {
            host_id: crate::peer_store::key_id(&key),
            public_key: proof.host_public_key.clone(),
            member: proof.member.clone(),
            address: hint.map(|m| m.address.clone()).unwrap_or_default(),
            candidates: hint.map(|m| m.candidates.clone()).unwrap_or_default(),
            updated_at: hint
                .map(|m| m.updated_at.clone())
                .unwrap_or_else(|| at.into()),
            membership: None,
            admission: None,
            person_id,
            person_member,
        });
    }
    members.sort_by(|a, b| a.host_id.cmp(&b.host_id));
    Ok(members)
}
// Every source statement and completed activation was already independently
// verified by the projection. This discovers a format hint, never authority.
fn verified_root_ssh(p: &catalog::Projection) -> Result<bool> {
    let current = &p.network.root_public_key;
    for entry in &p.objects.objects {
        if !matches!(
            entry.kind.as_str(),
            "attestation"
                | "admin_delegation"
                | "person_admission"
                | "host_admission"
                | "root_record"
                | "feature"
                | "activation"
        ) {
            continue;
        }
        let raw = crypto::bytes(&entry.body_base64, crate::linking::MAX_OBJECT)?;
        let mut statement: Value = serde_json::from_slice(&raw)?;
        if entry.kind == "feature" {
            statement = statement["proposal"].clone();
        } else if entry.kind == "activation" {
            if !statement["administrator"].is_object() {
                continue;
            }
            let payload = crypto::bytes(
                statement["administrator"]["payload_base64"]
                    .as_str()
                    .unwrap_or(""),
                crate::linking::MAX_PAYLOAD,
            )?;
            let payload: Value = serde_json::from_slice(&payload)?;
            let admission = &payload["admission_record"];
            if admission.get("person_public_key").is_some() {
                continue;
            }
            statement = admission.clone();
        }
        if statement["epoch"].as_u64() == Some(p.network.epoch)
            && crate::persons::sshsig_signer(statement["signature"].as_str().unwrap_or("")).as_ref()
                == Some(current)
        {
            return Ok(true);
        }
    }
    Ok(p.groups
        .values()
        .any(|g| g.signer().as_ref() == Some(current)))
}
pub fn persist(
    store: &Store,
    tx: &Transaction<'_>,
    n: &mut Network,
    p: &catalog::Projection,
    members: &mut [Member],
    at: &str,
) -> Result<()> {
    ensure!(
        p.network.epoch <= 4096,
        Failure::new("invalid", "-", "root")
    );
    let seed: Option<Vec<u8>> = tx.query_row(
        "SELECT root_seed FROM networks WHERE id=?1",
        [&n.id],
        |row| row.get(0),
    )?;
    let owns_current_root = match seed.as_deref() {
        Some(seed) => {
            let seed: &[u8; 32] = seed
                .try_into()
                .map_err(|_| Failure::new("state_conflict", "-", "storage"))?;
            ed25519_dalek::SigningKey::from_bytes(seed)
                .verifying_key()
                .as_bytes()
                .as_slice()
                == membership::canonical(&p.network.root_public_key, 32)?
        }
        None => false,
    };
    if seed.is_some() && !owns_current_root {
        tx.execute("UPDATE networks SET root_seed=NULL WHERE id=?1", [&n.id])?;
    }
    n.administrator = owns_current_root;
    let (prior_policies, _) = super::persistence::high_water(tx, &n.id)?;
    catalog::persist(tx, n, p)?;
    for entry in p
        .objects
        .objects
        .iter()
        .filter(|p| matches!(p.kind.as_str(), "rotation" | "admin_delegation"))
    {
        let body = crypto::bytes(&entry.body_base64, crate::linking::MAX_OBJECT)?;
        let object: Value = serde_json::from_slice(&body)?;
        let (kind, subject) = if entry.kind == "rotation" {
            (
                "rotation",
                object["epoch"]
                    .as_u64()
                    .ok_or_else(|| Failure::new("invalid", "-", "root"))?
                    .to_string(),
            )
        } else {
            (
                "admin",
                object["person_public_key"]
                    .as_str()
                    .ok_or_else(|| Failure::new("invalid", "-", "root"))?
                    .to_owned(),
            )
        };
        if kind == "admin" {
            let mut q=tx.prepare("SELECT record FROM network_statements WHERE network_id=?1 AND kind='admin' AND subject=?2")?;
            let old: Vec<String> = q
                .query_map(params![n.id, subject], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            if let Some(old) = old.first() {
                let old: Value = serde_json::from_str(old)?;
                if old["epoch"].as_u64() > object["epoch"].as_u64() {
                    continue;
                }
            }
        }
        tx.execute("INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?1,?2,?3,?4) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record",params![n.id,kind,subject,String::from_utf8(body)?])?;
    }
    let old: BTreeSet<String> = {
        let mut q = tx.prepare("SELECT host_id FROM network_members WHERE network_id=?1")?;
        q.query_map([&n.id], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?
    };
    tx.execute("DELETE FROM network_members WHERE network_id=?1", [&n.id])?;
    for m in members.iter_mut() {
        if m.host_id == store.identity().id {
            m.address = store.advertised();
            m.candidates = store
                .published_candidates()
                .iter()
                .map(ToString::to_string)
                .collect();
        }
        tx.execute(
            "INSERT INTO network_members(network_id,host_id,record) VALUES(?1,?2,?3)",
            params![n.id, m.host_id, serde_json::to_string(m)?],
        )?;
    }
    let new: BTreeSet<_> = members.iter().map(|m| m.host_id.clone()).collect();
    for added in new
        .difference(&old)
        .filter(|id| **id != store.identity().id)
    {
        append_event(tx, "network.member_added", added, at)?;
    }
    for removed in old
        .difference(&new)
        .filter(|id| **id != store.identity().id)
    {
        append_event(tx, "network.member_removed", removed, at)?;
    }
    for (person, policy) in &p.policies {
        store.settle_edits(tx, &n.id, policy)?;
        if !prior_policies.iter().any(|old| {
            old.person_public_key == *person
                && p.access.policies.iter().any(|selected| {
                    selected.person_public_key == *person
                        && selected.selection.high_water == old.high_water
                })
        }) {
            append_event(tx, "network.policy_updated", &policy.person_id(), at)?;
        }
    }
    store.queue_link_policies(tx, n, p, members, &prior_policies, at)?;
    n.root_ssh = verified_root_ssh(p)?
        || n.root_ssh
            && n.root_epoch == p.network.epoch
            && n.current_root_public_key == p.network.root_public_key;
    n.root_epoch = p.network.epoch;
    n.current_root_public_key = p.network.root_public_key.clone();
    tx.execute(
        "UPDATE networks SET record=?1 WHERE id=?2",
        params![serde_json::to_string(n)?, n.id],
    )?;
    Ok(())
}
impl Store {
    pub(crate) fn apply_link_map(
        &self,
        n: Network,
        raw: &[u8],
        joined: bool,
        switch: Option<membership::CoordinatorPending>,
    ) -> Result<Network> {
        self.apply_link_map_inner(n, raw, joined, switch, None)
    }
    pub(crate) fn apply_link_map_with_edit(
        &self,
        n: Network,
        raw: &[u8],
        edit: Option<(u64, crate::policy::Policy)>,
    ) -> Result<Network> {
        self.apply_link_map_inner(n, raw, false, None, edit)
    }
    fn apply_link_map_inner(
        &self,
        mut n: Network,
        raw: &[u8],
        joined: bool,
        switch: Option<membership::CoordinatorPending>,
        edit: Option<(u64, crate::policy::Policy)>,
    ) -> Result<Network> {
        let first = joined || n.last_sync_at.is_none();
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if let Some(pending) = &switch {
            n.coordinator_address = pending.address.clone();
            n.coordinator_public_key = pending.public_key.clone();
        }
        let (p, mut members) = verify(self, &tx, &n, raw)?;
        let pending:i64=tx.query_row("SELECT count(*) FROM network_statements WHERE network_id=?1 AND kind='pending_rotation'",[&n.id],|r|r.get(0))?;
        ensure!(
            pending == 0 || p.network.epoch <= n.root_epoch,
            Failure::new("state_conflict", "-", "rotation")
        );

        let at = support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        if joined {
            tx.execute(
                "INSERT INTO networks(id,record,root_seed) VALUES(?1,?2,NULL)",
                params![n.id, serde_json::to_string(&n)?],
            )?;
            append_event(&tx, "network.joined", &n.id, &at)?;
        }
        if let Some(pending) = switch {
            if let Some(sequence) = pending.move_sequence.filter(|_| pending.is_move()) {
                crate::coordinator_move::record_applied(&tx, &n.id, sequence)?;
            }
            n.coordinator_pending = None;
        }
        n.last_sync_at = Some(at.clone());
        n.last_sync_error = None;
        persist(self, &tx, &mut n, &p, &mut members, &at)?;
        super::restrictions::acknowledge(&tx, &n.id, &p.objects)?;
        if let Some((seq, policy)) = edit
            && p.policies.get(&policy.person_public_key) == Some(&policy)
        {
            self.record_edit(&tx, &n.id, seq, &policy)?;
        }
        tx.commit()?;
        self.refresh_member_pins(&connection)?;
        if first {
            self.relay_wake.notify_one();
        }
        Ok(n)
    }
}

/// Transport evidence is interpreted only after complete catalog authority has
/// been verified and persisted. It never supplies membership or a feature pin.
pub(crate) fn transport_evidence(store: &Store, n: &Network) -> Result<(Value, Value)> {
    let c = store.connection()?;
    let p = catalog::projection(&c, n, support::now()?)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    let authority = crate::admins::Authority {
        roots: p.roots()?,
        admins: p
            .network
            .facts
            .state
            .persons
            .iter()
            .filter(|(_, v)| v.admitted && v.administrator)
            .map(|(k, _)| k.clone())
            .collect(),
        ..Default::default()
    };
    let mut moved: Option<crate::coordinator_move::CoordinatorMove> = None;
    if let Some(held) = store.latest_move(&c, &n.id)?
        && held.verify(&n.id, &authority).is_ok()
    {
        moved = Some(held);
    }
    let mut edges = BTreeMap::<(String, u64), Value>::new();
    for entry in &p.objects.objects {
        if !matches!(
            entry.kind.as_str(),
            "coordinator_move" | "coordinator_successor"
        ) {
            continue;
        }
        let raw = crypto::bytes(&entry.body_base64, crate::linking::MAX_OBJECT)?;
        if entry.kind == "coordinator_move" {
            let value: crate::coordinator_move::CoordinatorMove = serde_json::from_slice(&raw)?;
            if value.verify(&n.id, &authority).is_ok()
                && moved
                    .as_ref()
                    .is_none_or(|old| old.sequence < value.sequence)
            {
                moved = Some(value);
            }
        } else {
            let value: Value = serde_json::from_slice(&raw)?;
            let previous = value["previous_public_key"]
                .as_str()
                .ok_or_else(|| Failure::new("invalid", "-", "successor"))?;
            let seq = value["sequence"]
                .as_u64()
                .ok_or_else(|| Failure::new("invalid", "-", "successor"))?;
            edges.entry((previous.into(), seq)).or_insert(value);
        }
    }
    let mut previous = n.coordinator_public_key.clone();
    let mut sequence = None;
    let mut chain = Vec::new();
    for _ in 0..p.objects.objects.len() {
        let next = if let Some(seq) = sequence {
            edges.get(&(previous.clone(), seq))
        } else {
            edges
                .iter()
                .rfind(|((key, _), _)| key == &previous)
                .map(|(_, v)| v)
        };
        let Some(value) = next else {
            break;
        };
        let seq = value["sequence"]
            .as_u64()
            .ok_or_else(|| Failure::new("invalid", "-", "successor"))?;
        chain.push(value.clone());
        previous = value["public_key"]
            .as_str()
            .ok_or_else(|| Failure::new("invalid", "-", "successor"))?
            .into();
        sequence = seq.checked_add(1);
        if sequence.is_none() {
            break;
        }
    }
    if !chain.is_empty() {
        membership::verify_successors(&n.coordinator_public_key, &chain)?;
    }
    Ok((
        moved
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(Value::Null),
        if chain.is_empty() {
            Value::Null
        } else {
            Value::Array(chain)
        },
    ))
}

/// Resolve verified catalog/held moves before the old coordinator is contacted.
/// Recheck current authority; stale historical evidence cannot retain a pending pin.
pub(crate) fn refresh_transport(
    store: &Store,
    mut n: Network,
) -> std::result::Result<Network, crate::model::Error> {
    let active = {
        let c = store.connection()?;
        catalog::feature(&c, &n.id).map_err(support::model_error)?.0 != "-"
    };
    if !active {
        return Ok(n);
    }
    let (moved, _) = match transport_evidence(store, &n) {
        Ok(evidence) => evidence,
        Err(e)
            if e.downcast_ref::<crate::linking::PathError>()
                .is_some_and(|e| e.code == "proof_required")
                || e.downcast_ref::<Failure>()
                    .is_some_and(|e| e.code == "proof_required") =>
        {
            // A missing retention proof can be repaired at the independent pin.
            // No pending transport authority is inferred from incomplete state.
            n.coordinator_pending = None;
            return Ok(n);
        }
        Err(e) => return Err(support::model_error(e)),
    };
    if n.coordinator_pending
        .as_ref()
        .is_some_and(membership::CoordinatorPending::is_move)
    {
        let valid = n.coordinator_pending.as_ref().is_some_and(|p| {
            moved["sequence"].as_u64() == p.move_sequence
                && moved["address"].as_str() == Some(p.address.as_str())
                && moved["public_key"].as_str() == Some(p.public_key.as_str())
        });
        if !valid {
            n.coordinator_pending = None;
            store.connection()?.execute(
                "UPDATE networks SET record=?1 WHERE id=?2",
                params![serde_json::to_string(&n)?, n.id],
            )?;
        }
    }
    if !moved.is_null() {
        return store.accept_move(&n.id, &moved).map(|(n, _)| n);
    }
    Ok(n)
}
