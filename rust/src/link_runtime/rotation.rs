//! Active rotations retain old proofs and install the accepted seed atomically.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
    transport,
};
use crate::{
    linking,
    model::Error,
    network::{Network, PendingRotation, PlannedGroup, PlannedItem, RotationPlan},
    store::{Store, append_event},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::Method;
use rusqlite::{Connection, params};
use std::sync::Arc;

pub(crate) fn plan(c: &Connection, n: &Network, epoch: u64) -> Result<Option<RotationPlan>> {
    let Some(p) = catalog::projection(c, n, support::now()?)? else {
        return Ok(None);
    };
    ensure!(
        epoch == p.network.epoch + 1,
        Failure::new("state_conflict", "-", "rotation")
    );
    let mut result = RotationPlan {
        network_id: n.id.clone(),
        epoch,
        current_root_public_key: p.network.root_public_key.clone(),
        attestations: Vec::new(),
        host_admissions: Vec::new(),
        person_admissions: Vec::new(),
        admins: Vec::new(),
        groups: Vec::new(),
    };
    for (key, admitted) in &p.network.facts.state.hosts {
        if *admitted {
            let label = p
                .network
                .facts
                .host_labels
                .get(key)
                .ok_or_else(|| Failure::new("proof_required", "-", "rotation"))?;
            result.attestations.push(PlannedItem {
                public_key: key.clone(),
                member: label.clone(),
            });
        }
    }
    for (key, state) in &p.network.facts.state.persons {
        if state.admitted {
            let label = p
                .network
                .facts
                .person_labels
                .get(key)
                .ok_or_else(|| Failure::new("proof_required", "-", "rotation"))?;
            result.person_admissions.push(PlannedItem {
                public_key: key.clone(),
                member: label.clone(),
            });
            if state.administrator {
                result.admins.push(key.clone());
            }
        }
    }
    for selected in &p.access.groups {
        if !selected.selection.active || selected.selection.record_id != "-" {
            continue;
        }
        let Some(group) = p.groups.get(&selected.name) else {
            continue;
        };
        if group
            .verify_signed_by(&n.id, &p.network.root_public_key)
            .is_ok()
        {
            let version = selected
                .selection
                .high_water
                .version
                .checked_add(1)
                .ok_or_else(|| {
                    let mut error = Failure::new("quota_exceeded", "-", "rotation");
                    error.error = "access version exhausted".into();
                    error
                })?;
            result.groups.push(PlannedGroup {
                name: group.name.clone(),
                version,
                members: group.members.clone(),
            });
        }
    }
    Ok(Some(result))
}
fn seeds(p: &PendingRotation) -> Result<Vec<linking::ProofSeed>> {
    let mut out = vec![linking::ProofSeed {
        kind: "rotation".into(),
        body: crypto::json(&p.rotation)?,
    }];
    for a in &p.attestations {
        out.push(linking::ProofSeed {
            kind: "attestation".into(),
            body: crypto::json(a)?,
        });
    }
    for a in &p.admissions {
        let kind = if a.get("delegated_at").is_some() {
            "admin_delegation"
        } else if a.get("host_public_key").is_some() {
            "host_admission"
        } else {
            "person_admission"
        };
        out.push(linking::ProofSeed {
            kind: kind.into(),
            body: crypto::json(a)?,
        });
    }
    for g in &p.groups {
        out.push(linking::ProofSeed {
            kind: "group".into(),
            body: crypto::json(g)?,
        });
    }
    Ok(out)
}
fn prepare(store: &Store, n: &Network, p: &PendingRotation) -> Result<Option<Vec<u8>>> {
    let c = store.connection()?;
    let (feature, _) = catalog::feature(&c, &n.id)?;
    if feature == "-" {
        return Ok(None);
    }
    let prior = catalog::read(&c, &n.id)?;
    let seeds = seeds(p)?;
    let added = crypto::json(&catalog::Catalog {
        format: 1,
        network_id: n.id.clone(),
        objects: seeds
            .iter()
            .map(|s| catalog::Entry {
                id: catalog::proof_id(&s.kind, &s.body),
                kind: s.kind.clone(),
                body_base64: STANDARD.encode(&s.body),
            })
            .collect(),
    })?;
    // The immutable merger requires canonical proof ordering.
    let mut added: catalog::Catalog = serde_json::from_slice(&added)?;
    added.objects.sort_by(|a, b| a.id.cmp(&b.id));
    let added = crypto::json(&added)?;
    let union = catalog::merge(&n.id, &[&prior, &added])?;
    let projection = catalog::verify(&c, n, &union, support::now()?)?;
    let ctx = linking::CatalogFactContext {
        network: &projection.descriptor,
        epoch: projection.network.epoch,
        known_feature_id: &feature,
        now: support::now()?,
    };
    linking::verify_stored_catalog_additions(ctx, &prior, &union)?;
    let selected = linking::select_stored_proof_catalog(
        linking::CatalogFactContext {
            network: &projection.descriptor,
            epoch: projection.network.epoch,
            known_feature_id: &feature,
            now: support::now()?,
        },
        &union,
        &seeds,
    )?;
    let publication = catalog::merge(&n.id, &[&selected, &added])?;
    let body = crypto::raw_object(vec![("catalog", publication)])?;
    ensure!(
        body.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "rotation")
    );
    Ok(Some(body))
}
fn accept(store: &Store, mut n: Network, pending: &PendingRotation, raw: &[u8]) -> Result<Network> {
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    // A queued sync can hold a pre-completion Network/Pending snapshot even
    // after the mutation lock becomes available. Read the authoritative state
    // in the committing transaction before touching the root seed or event.
    n = store.network_record(&tx, &n.id)?;
    if n.root_epoch >= pending.rotation.epoch {
        let retained = catalog::decode(&catalog::read(&tx, &n.id)?, &n.id)?;
        for seed in seeds(pending)? {
            let id = catalog::proof_id(&seed.kind, &seed.body);
            ensure!(
                retained.objects.iter().any(|entry| entry.id == id),
                Failure::required("-", "rotation", vec![id])
            );
        }
        return Ok(n);
    }
    let saved = store
        .pending_rotation(&tx, &n.id)?
        .ok_or_else(|| Failure::new("state_conflict", "-", "rotation"))?;
    ensure!(
        crypto::json(&saved)? == crypto::json(pending)?,
        Failure::new("state_conflict", "-", "rotation")
    );
    let (p, mut members) = map::verify(store, &tx, &n, raw)?;
    ensure!(
        p.network.epoch == pending.rotation.epoch
            && p.network.root_public_key == pending.rotation.root_public_key,
        Failure::new("state_conflict", "-", "rotation")
    );
    for seed in seeds(pending)? {
        let id = catalog::proof_id(&seed.kind, &seed.body);
        ensure!(
            p.objects.objects.iter().any(|e| e.id == id),
            Failure::required("-", "rotation", vec![id])
        );
    }
    let next = if pending.root_seed.is_empty() {
        None
    } else {
        let seed = crypto::bytes(&pending.root_seed, 32)?;
        let bytes: [u8; 32] = seed.as_slice().try_into()?;
        ensure!(
            STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&bytes)
                    .verifying_key()
                    .as_bytes()
            ) == pending.rotation.root_public_key,
            Failure::new("state_conflict", "-", "rotation")
        );
        Some(seed)
    };
    n.root_ssh = next.is_none();
    n.administrator = next.is_some();
    let at = support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    n.last_sync_at = Some(at.clone());
    n.last_sync_error = None;
    let old_epoch = n.root_epoch;
    map::persist(store, &tx, &mut n, &p, &mut members, &at)?;
    n.administrator = next.is_some();
    tx.execute(
        "UPDATE networks SET root_seed=?1,record=?2 WHERE id=?3",
        params![next, serde_json::to_string(&n)?, n.id],
    )?;
    tx.execute(
        "DELETE FROM network_statements WHERE network_id=?1 AND kind='pending_rotation'",
        [&n.id],
    )?;
    if n.root_epoch > old_epoch {
        append_event(&tx, "network.root_rotated", &n.id, &at)?;
    }
    tx.commit()?;
    store.refresh_member_pins(&c)?;
    Ok(n)
}
pub(crate) async fn complete(
    store: Arc<Store>,
    n: Network,
    pending: PendingRotation,
) -> Result<Option<Network>, Error> {
    let lock = store.clone();
    let _guard = lock.link_mutation.lock().await;
    super::restrictions::resume(store.clone(), &n.id)
        .await
        .map_err(support::model_error)?;
    complete_locked(store, n, pending).await
}
/// The caller already owns Store.link_mutation during a fresh signer decision.
pub(crate) async fn complete_locked(
    store: Arc<Store>,
    n: Network,
    pending: PendingRotation,
) -> Result<Option<Network>, Error> {
    let (run, current, p) = (store.clone(), n.clone(), pending.clone());
    let prepared = tokio::task::spawn_blocking(move || prepare(&run, &current, &p))
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(support::model_error)?;
    let Some(body) = prepared else {
        return Ok(None);
    };
    let response = transport::request(
        store.clone(),
        &n.coordinator_address,
        &n.coordinator_public_key,
        Method::POST,
        &format!("/coord/v2/networks/{}/statements", n.id),
        body,
    )
    .await;
    let raw = match response {
        Ok(raw) => raw,
        Err(error) => {
            let mut failure = Failure::cause(error, "-", "rotation");
            if failure.authenticated_response
                && matches!(
                    failure.code.as_str(),
                    "invalid" | "state_conflict" | "operation_conflict"
                )
            {
                let (run, id, refused) = (store.clone(), n.id.clone(), pending.clone());
                tokio::task::spawn_blocking(move || -> Result<()> {
                    let mut c = run.connection()?;
                    let tx = c.transaction()?;
                    if let Some(saved) = run.pending_rotation(&tx, &id)?
                        && crypto::json(&saved)? == crypto::json(&refused)?
                    {
                        tx.execute(
                            "DELETE FROM network_statements WHERE network_id=?1 AND kind='pending_rotation'",
                            [&id],
                        )?;
                    }
                    tx.commit()?;
                    Ok(())
                })
                .await
                .map_err(|e| Error::Internal(e.into()))?
                .map_err(support::model_error)?;
            } else if failure.code == "forbidden" {
                failure.details.next.push(format!(
                    "Repair current root authority for network {} and resume the pending rotation.",
                    n.id
                ));
            }
            return Err(support::model_error(failure.into()));
        }
    };
    let run = store.clone();
    tokio::task::spawn_blocking(move || accept(&run, n, &pending, &raw))
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map(Some)
        .map_err(support::model_error)
}
