//! Exact signed DEC claims settle only inside the capability writer's transaction.
//! A candidate supplies proof bytes, never the host's prior or selected signer.
use super::{
    actions,
    catalog::Catalog,
    codec::*,
    controls, edits,
    state::Projection,
    statement::{Statement, access_body},
    storage::{Snapshot, check_outbox_capacity},
};
use crate::{policy::PolicyBody, store::Store};
use rusqlite::{Connection, Transaction};
use serde_json::{Value, json};

struct Checked {
    snapshot: Snapshot,
    before: Projection,
    statement: Statement,
    catalog: Catalog,
    owner: String,
    time: String,
}

fn exact_preparation(
    c: &Connection,
    s: &Snapshot,
    catalog: &Catalog,
    candidate: Statement,
) -> Result<Statement> {
    let person = text(&access_body(&candidate.payload)?, "person_public_key")?.to_owned();
    let provider = if text(candidate.issuer()?, "kind")? == "device" {
        candidate
            .parents()?
            .get("issuer_device")
            .cloned()
            .ok_or_else(|| Error::new("invalid"))?
    } else {
        person
    };
    let id = actions::action_id(
        &s.descriptor.context_id(),
        "policy_claim",
        &candidate.id,
        &provider,
    );
    let intent = match actions::load(c, &s.descriptor.network_id, &id, "policy_claim") {
        Ok(intent) => intent,
        Err(e) if e.code == "not_found" => return Ok(candidate),
        Err(e) => return Err(e),
    };
    if !intent.record.completed {
        return Ok(candidate);
    }
    require(intent.record.approved, "state_conflict")?;
    let fixed = intent.assembled(&s.descriptor)?.remove(0);
    let original = fixed
        .signed(&s.descriptor)?
        .ok_or_else(|| Error::new("state_conflict"))?;
    require(
        catalog
            .proofs
            .get(&original.proof_id)
            .is_some_and(|p| p.kind == "policy" && p.body == original.body),
        "operation_conflict",
    )?;
    Ok(original)
}

fn checked(
    store: &Store,
    c: &Connection,
    network: &str,
    name: &str,
    raw: &[u8],
) -> Result<Checked> {
    check(crate::policy::name_shape(name) && name != crate::capabilities::READ)?;
    let snapshot = Snapshot::load(c, network, &store.identity().public_key)?;
    if let Some(migration) = snapshot
        .migrations
        .iter()
        .find(|m| m.fenced && m.state != "adopted")
    {
        let proposal = Statement::read(
            &snapshot.descriptor,
            &b64(&migration.proposal_base64, MAX_OBJECT)?,
        )?;
        let mut error = Error::new("migration_pending");
        error.required_ids.insert(proposal.id);
        return Err(error);
    }
    let before = snapshot.project(&controls::local_decision_time()?)?;
    let owner = snapshot.network.own_identity.person_public_key.clone();
    require(key(&owner), "forbidden")?;
    before.member_for(&store.identity().public_key, &owner)?;
    let catalog = Catalog::read(&snapshot.descriptor, raw)?;
    let maximum = before
        .streams
        .get(&vec!["policy".into(), owner.clone()])
        .map(|s| s.maximum)
        .unwrap_or(0);
    let current = before.current_statement(&["policy".into(), owner.clone()]);
    let mut newer = None;
    let mut same = None;
    for statement in catalog.statements.values().filter(|s| s.kind == "policy") {
        if text(&access_body(&statement.payload)?, "person_public_key")? != owner {
            continue;
        }
        if statement.sequence()? > maximum {
            require(
                newer
                    .as_ref()
                    .is_none_or(|s: &Statement| s.id == statement.id),
                "state_conflict",
            )?;
            newer = Some(statement.clone());
        } else if current.as_ref().is_ok_and(|(s, _)| s.id == statement.id) {
            same = Some(statement.clone());
        }
    }
    let statement = exact_preparation(
        c,
        &snapshot,
        &catalog,
        newer.or(same).ok_or_else(|| Error::new("forbidden"))?,
    )?;
    let body = access_body(&statement.payload)?;
    let me = store.identity().id;
    let mut found = false;
    for rule in array(&body, "capability_rules")? {
        let rule = object(rule)?;
        if text(rule, "capability")? == name {
            require(text(rule, "host")? == me, "invalid")?;
            found = true;
        }
    }
    require(found, "invalid")?;
    if !current.as_ref().is_ok_and(|(s, _)| s.id == statement.id) {
        let mut actor = json!({"person_public_key":owner,"host_public_key":"-","device_public_key":"-","issuer_id":"-"});
        if text(statement.issuer()?, "kind")? == "device" {
            let parents = statement.parents()?;
            let id = parents
                .get("issuer_device")
                .ok_or_else(|| Error::new("invalid"))?;
            let device = before.catalog.get(id)?;
            require(device.kind == "device_lease", "invalid")?;
            actor["host_public_key"] = Value::from(text(device.subject()?, "host_public_key")?);
            actor["device_public_key"] = Value::from(text(device.subject()?, "device_public_key")?);
            actor["issuer_id"] = Value::from(id.as_str());
        }
        before.action(object(&actor)?, "policy", &statement.payload_bytes)?;
        edits::check_policy(c, &before, &statement, &store.identity().public_key, true)?;
    }
    let projected = Projection::build(
        &snapshot.descriptor,
        &snapshot.prior.value,
        Some(raw),
        &before.decision_time,
        "fresh",
    )?;
    let (actual, _) = projected.current_statement(&["policy".into(), owner.clone()])?;
    require(actual.id == statement.id, "state_conflict")?;
    Ok(Checked {
        snapshot,
        statement,
        catalog,
        owner,
        time: before.decision_time.clone(),
        before,
    })
}

pub(crate) fn check_capability_claim(
    store: &Store,
    c: &Connection,
    network: &str,
    name: &str,
    catalog: &[u8],
) -> Result<PolicyBody> {
    let claim = checked(store, c, network, name, catalog)?;
    serde_json::from_value(Value::Object(access_body(&claim.statement.payload)?))
        .map_err(|_| Error::new("invalid"))
}

pub(crate) fn apply_capability_claim(
    store: &Store,
    tx: &mut Transaction<'_>,
    network: &str,
    name: &str,
    catalog: &[u8],
) -> Result<()> {
    let claim = checked(store, tx, network, name, catalog)?;
    let applied = claim
        .snapshot
        .apply_catalog(tx, &claim.catalog.bytes, &claim.time, "fresh")?;
    let (actual, _) = applied.current_statement(&["policy".into(), claim.owner])?;
    require(actual.id == claim.statement.id, "state_conflict")?;
    edits::settle(
        tx,
        &claim.before,
        &applied,
        &claim.statement,
        &store.identity().public_key,
    )?;
    // The caller keeps this transaction open across every network and all
    // capability/source/name changes. A later refusal rolls all of them back.
    check_outbox_capacity(tx, &[])?;
    Ok(())
}
