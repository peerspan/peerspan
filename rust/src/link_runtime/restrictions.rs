//! Durable public restrictions repair the actual pin before strict live sync.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
    transport,
};
use crate::{linking, network::Network, store::Store};
use anyhow::{Result, ensure};
use hyper::Method;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};
const KIND: &str = "pending_link_restriction";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    format: u64,
    proof_id: String,
}
pub(crate) fn restrictive(kind: &str, body: &[u8]) -> Result<bool> {
    if matches!(
        kind,
        "host_revocation"
            | "invite_revocation"
            | "host_leave"
            | "person_removal"
            | "host_unbinding"
            | "admin_removal"
            | "device_revocation"
    ) {
        return Ok(true);
    }
    if kind == "person_record" {
        let value: Value = serde_json::from_slice(body)?;
        return Ok(matches!(
            value["kind"].as_str(),
            Some(
                "peerspan-host-unbind-v1"
                    | "peerspan-person-remove-v1"
                    | "peerspan-revoke-host-v1"
                    | "peerspan-revoke-invite-v1"
            )
        ));
    }
    Ok(false)
}
pub(crate) fn mark(c: &Connection, id: &str, kind: &str, body: &[u8]) -> Result<()> {
    if !restrictive(kind, body)? {
        return Ok(());
    }
    let proof = catalog::proof_id(kind, body);
    let marker = crypto::json(&Marker {
        format: 1,
        proof_id: proof.clone(),
    })?;
    c.execute(
        "INSERT OR REPLACE INTO network_statements VALUES(?1,?2,?3,?4)",
        params![id, KIND, proof, String::from_utf8(marker)?],
    )?;
    Ok(())
}
pub(crate) fn pending(c: &Connection, id: &str) -> Result<Vec<String>> {
    let mut q=c.prepare("SELECT subject,record FROM network_statements WHERE network_id=?1 AND kind=?2 ORDER BY subject")?;
    q.query_map(params![id, KIND], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?
    .map(|row| {
        let (subject, raw) = row?;
        let m: Marker = linking::decode_stored_json(raw.as_bytes(), "format proof_id")?;
        ensure!(
            m.format == 1 && m.proof_id == subject && crypto::id(&subject, "pf_"),
            Failure::new("state_conflict", "-", "restriction")
        );
        Ok(subject)
    })
    .collect()
}
pub(crate) fn acknowledge(c: &Connection, id: &str, objects: &catalog::Catalog) -> Result<()> {
    let present: BTreeSet<_> = objects.objects.iter().map(|e| e.id.as_str()).collect();
    for proof in pending(c, id)? {
        ensure!(
            present.contains(proof.as_str()),
            Failure::required("-", "restriction", vec![proof.clone()])
        );
        c.execute(
            "DELETE FROM network_statements WHERE network_id=?1 AND kind=?2 AND subject=?3",
            params![id, KIND, proof],
        )?;
    }
    Ok(())
}
struct Prepared {
    network: Network,
    body: Vec<u8>,
}
fn prepare(store: &Store, id: &str, target: Option<(String, String)>) -> Result<Option<Prepared>> {
    let c = store.connection()?;
    let ids = pending(&c, id)?;
    if ids.is_empty() {
        return Ok(None);
    }
    let mut n = store.network_record(&c, id)?;
    let p = catalog::projection(&c, &n, support::now()?)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "restriction"))?;
    let mut seeds = Vec::new();
    for proof in ids {
        let e = p
            .objects
            .objects
            .iter()
            .find(|e| e.id == proof)
            .ok_or_else(|| Failure::required("-", "restriction", vec![proof.clone()]))?;
        let body = crypto::bytes(&e.body_base64, linking::MAX_OBJECT)?;
        ensure!(
            restrictive(&e.kind, &body)?,
            Failure::new("state_conflict", "-", "restriction")
        );
        seeds.push(linking::ProofSeed {
            kind: e.kind.clone(),
            body,
        });
    }
    if let Some((address, key)) = target {
        n.coordinator_address = address;
        n.coordinator_public_key = key;
    }
    let descriptor = catalog::descriptor(&n)?;
    let request = |objects: Vec<u8>| {
        crypto::raw_object(vec![
            ("network", descriptor.clone()),
            ("catalog", objects),
            ("feature_authorization", crypto::json(&"-")?),
        ])
    };
    let mut body = request(p.catalog.clone())?;
    if body.len() > 1 << 20 {
        ensure!(
            seeds.iter().map(|s| s.body.len()).sum::<usize>() <= linking::MAX_ACTIVATION,
            Failure::new("quota_exceeded", "-", "restriction")
        );
        let selected = linking::select_stored_proof_catalog(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &p.network.facts.feature_id,
                now: support::now()?,
            },
            &p.catalog,
            &seeds,
        )?;
        let added = crypto::json(&catalog::Catalog {
            format: 1,
            network_id: id.into(),
            objects: seeds
                .iter()
                .map(|s| catalog::Entry {
                    id: catalog::proof_id(&s.kind, &s.body),
                    kind: s.kind.clone(),
                    body_base64: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &s.body,
                    ),
                })
                .collect(),
        })?;
        body = request(catalog::merge(id, &[&selected, &added])?)?;
    }
    ensure!(
        body.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "restriction")
    );
    Ok(Some(Prepared { network: n, body }))
}
pub(crate) async fn resume_for_sync(store: Arc<Store>, id: &str) -> Result<Option<anyhow::Error>> {
    let (run, lookup) = (store.clone(), id.to_owned());
    let Some(p) = tokio::task::spawn_blocking(move || prepare(&run, &lookup, None)).await?? else {
        return Ok(None);
    };
    let raw = match transport::request(
        store.clone(),
        &p.network.coordinator_address,
        &p.network.coordinator_public_key,
        Method::POST,
        "/coord/v2/networks/import",
        p.body,
    )
    .await
    {
        Ok(raw) => raw,
        Err(e) => return Ok(Some(e)),
    };
    let lookup = id.to_owned();
    tokio::task::spawn_blocking(move||->Result<()>{
        let mut c=store.connection()?;let tx=c.transaction()?;let mut n=store.network_record(&tx,&lookup)?;
        // Actual served pin and all currently retained PFs are checked anew.
        let (projection,mut members)=map::verify(&store,&tx,&n,&raw)?;
        acknowledge(&tx,&lookup,&projection.objects)?;
        let pending:i64=tx.query_row("SELECT count(*) FROM network_statements WHERE network_id=?1 AND kind='pending_rotation'",[&lookup],|r|r.get(0))?;
        if pending==0 {
            let at=support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();n.last_sync_at=Some(at.clone());n.last_sync_error=None;
            map::persist(&store,&tx,&mut n,&projection,&mut members,&at)?;
        }
        tx.commit()?;store.refresh_member_pins(&c)?;Ok(())
    }).await??;
    Ok(None)
}

/// Explicit rotation completion keeps remote failures as hard refusals.
pub(crate) async fn resume(store: Arc<Store>, id: &str) -> Result<()> {
    if let Some(error) = resume_for_sync(store, id).await? {
        return Err(rotation_refusal(error));
    }
    Ok(())
}
pub(crate) fn rotation_refusal(error: anyhow::Error) -> anyhow::Error {
    let mut failure = Failure::cause(error, "-", "restriction");
    failure
        .details
        .next
        .push("resume the pending root rotation before following a coordinator move".into());
    failure.into()
}
/// The returned import response is a live candidate map. The caller verifies
/// it against the final chosen pin before any acknowledgment or projection.
pub(crate) async fn repair_at(
    store: Arc<Store>,
    id: &str,
    address: &str,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let (run, lookup, target) = (
        store.clone(),
        id.to_owned(),
        Some((address.to_owned(), key.to_owned())),
    );
    let Some(p) = tokio::task::spawn_blocking(move || prepare(&run, &lookup, target)).await??
    else {
        return Ok(None);
    };
    match transport::request(
        store,
        &p.network.coordinator_address,
        &p.network.coordinator_public_key,
        Method::POST,
        "/coord/v2/networks/import",
        p.body,
    )
    .await
    {
        Ok(raw) => Ok(Some(raw)),
        Err(_) => Ok(None),
    }
}
