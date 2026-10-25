//! Capability creation rechecks exact typed policy preparations in its transaction.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
};
use crate::{linking, policy::Policy, store::Store};
use anyhow::{Result, ensure};
use rusqlite::{Connection, Transaction};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimCatalog {
    pub network_id: String,
    pub catalog: Box<RawValue>,
}
pub(crate) struct Checked {
    pub network: crate::network::Network,
    pub projection: catalog::Projection,
    pub policy: Policy,
    pub edit: Option<u64>,
}
pub(crate) fn check(
    store: &Store,
    c: &Connection,
    name: &str,
    claim: &ClaimCatalog,
) -> Result<Checked> {
    ensure!(
        crate::policy::name_shape(name) && name != crate::capabilities::READ,
        Failure::new("invalid", "-", "claim")
    );
    let n = store.network_record(c, &claim.network_id)?;
    let original = store
        .own_person(c, &n.id)?
        .ok_or_else(|| Failure::new("forbidden", "-", "claim"))?;
    let person = store
        .person_key(c, &n.id, &original)?
        .ok_or_else(|| Failure::new("proof_required", "-", "person"))?;
    if let Ok((selected, _, _)) = super::provider::selected(c, &n.id) {
        ensure!(
            selected == person,
            Failure::new("state_conflict", "-", "person")
        );
    }
    let before = catalog::projection(c, &n, support::now()?)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    let union = catalog::merge(&n.id, &[&before.catalog, claim.catalog.get().as_bytes()])?;
    let p = catalog::verify(c, &n, &union, support::now()?)?;
    linking::verify_stored_catalog_additions(
        linking::CatalogFactContext {
            network: &p.descriptor,
            epoch: p.network.epoch,
            known_feature_id: &p.network.facts.feature_id,
            now: support::now()?,
        },
        &before.catalog,
        &union,
    )?;
    let selected = p
        .access
        .policies
        .iter()
        .find(|s| s.person_public_key == person && s.selection.active)
        .ok_or_else(|| Failure::new("forbidden", "-", "claim"))?;
    let candidate = catalog::decode(claim.catalog.get().as_bytes(), &n.id)?;
    let entry = candidate
        .objects
        .iter()
        .find(|e| e.id == selected.selection.proof_id && e.kind == "person_record")
        .ok_or_else(|| Failure::new("invalid", "-", "claim"))?;
    let body = crypto::bytes(&entry.body_base64, linking::MAX_OBJECT)?;
    let envelope: Value = serde_json::from_slice(&body)?;
    ensure!(
        envelope["kind"] == "peerspan-policy-v2"
            && envelope["person_public_key"] == person
            && envelope["operation_id"] == "-",
        Failure::new("invalid", "-", "claim")
    );
    let cert = envelope["certificate_id"]
        .as_str()
        .ok_or_else(|| Failure::new("invalid", "-", "claim"))?;
    linking::verify_stored_action_authority(
        linking::ActionContext {
            network: &p.descriptor,
            epoch: p.network.epoch,
            known_feature_id: &p.network.facts.feature_id,
            person_public_key: &person,
            certificate_id: cert,
            now: support::now()?,
        },
        "person_record",
        &union,
        &body,
    )?;
    let path = linking::evaluate_path(&p.network.facts.state, &person, cert, 1, support::now()?)?;
    ensure!(
        path.host_public_keys.last() == Some(&store.identity().public_key),
        Failure::new("forbidden", "-", "claim")
    );
    let policy = p
        .policies
        .get(&person)
        .ok_or_else(|| Failure::new("forbidden", "-", "claim"))?
        .clone();
    check_name(store, name, &policy)?;
    Ok(Checked {
        network: n,
        projection: p,
        policy,
        edit: None,
    })
}
pub(crate) fn check_name(store: &Store, name: &str, p: &Policy) -> Result<()> {
    ensure!(
        crate::policy::name_shape(name)
            && name != crate::capabilities::READ
            && p.capability_rules()
                .iter()
                .any(|r| r.host == store.identity().id && r.capability == name)
            && !p
                .capability_rules()
                .iter()
                .any(|r| r.host != store.identity().id && r.capability == name),
        Failure::new("invalid", "-", "claim")
    );
    Ok(())
}
pub(crate) fn apply(
    store: &Store,
    tx: &Transaction<'_>,
    name: &str,
    claims: &[ClaimCatalog],
) -> Result<()> {
    for claim in claims {
        let mut checked = check(store, tx, name, claim)?;
        checked.edit = store.check_edit(tx, &checked.network.id, &checked.policy)?;
        let at = support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let old = store.stored_members(tx, &checked.network.id)?;
        let mut members = map::projected_members(&checked.projection, &old, &at)?;
        map::persist(
            store,
            tx,
            &mut checked.network,
            &checked.projection,
            &mut members,
            &at,
        )?;
        if let Some(seq) = checked.edit {
            store.record_edit(tx, &checked.network.id, seq, &checked.policy)?;
        }
    }
    Ok(())
}
