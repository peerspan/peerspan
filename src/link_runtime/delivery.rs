//! Exact public catalogs use the existing policy delivery retry lifecycle.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
    transport,
};
use crate::{linking, network::Network, policy_sync, store::Store};
use anyhow::{Result, ensure};
use hyper::Method;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{collections::BTreeSet, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    catalog: Box<RawValue>,
}
fn response(raw: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        raw.len() <= 16 << 20,
        Failure::new("invalid", "-", "delivery")
    );
    let r: Response = linking::decode_stored_json(raw, "catalog")?;
    Ok(r.catalog.get().as_bytes().to_vec())
}
fn receipt(store: &Store, n: &Network, target: &str, sent: &[u8], received: &[u8]) -> Result<()> {
    let sent = catalog::decode(sent, &n.id)?;
    let got = catalog::decode(received, &n.id)?;
    let retained: BTreeSet<_> = got.objects.iter().map(|p| p.id.as_str()).collect();
    let missing: Vec<_> = sent
        .objects
        .iter()
        .filter(|p| !retained.contains(p.id.as_str()))
        .map(|p| p.id.clone())
        .collect();
    ensure!(
        missing.is_empty(),
        Failure::required("-", "delivery", missing)
    );
    let c = store.connection()?;
    let descriptor = catalog::descriptor(n)?;
    let epoch = catalog::target_epoch(&got)?;
    let (feature, _) = catalog::feature(&c, &n.id)?;
    let at = support::now()?;
    linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &feature,
            now: at,
        },
        received,
    )?;
    let access = linking::verify_stored_access_state(
        linking::AccessContext {
            network: &descriptor,
            epoch,
            known_feature_id: &feature,
            now: at,
            prior_policies: &[],
            prior_groups: &[],
        },
        received,
    )?;
    for selected in access.policies.iter().filter(|p| p.selection.active) {
        let (body, _) = catalog::access_body(&selected.selection)?;
        let policy: crate::policy::Policy = serde_json::from_slice(&body)?;
        store.note_edit_ack(&n.id, target, policy.edit_seq(&store.identity().id));
    }
    Ok(())
}
pub async fn deliver(
    store: &Arc<Store>,
    n: &Network,
    target: &str,
    encoded: &str,
) -> Result<(), String> {
    let run = || async {
        let catalog = crypto::bytes(encoded, 16 << 20)?;
        catalog::decode(&catalog, &n.id)?;
        let body = crypto::raw_object(vec![("catalog", catalog.clone())])?;
        ensure!(
            body.len() <= 1 << 20,
            Failure::new("quota_exceeded", "-", "delivery")
        );
        let received = if target == policy_sync::COORDINATOR {
            let raw = transport::request(
                store.clone(),
                &n.coordinator_address,
                &n.coordinator_public_key,
                Method::POST,
                &format!("/coord/v2/networks/{}/statements", n.id),
                body,
            )
            .await?;
            map::Map::decode(&raw)?.catalog.get().as_bytes().to_vec()
        } else {
            let (status, raw) = policy_sync::peer_call(
                store,
                target,
                "POST",
                &format!("/peer/v1/networks/{}/link-catalog", n.id),
                &body,
            )
            .await
            .map_err(anyhow::Error::msg)?;
            ensure!(status == 200, Failure::new("unavailable", "-", "delivery"));
            response(&raw)?
        };
        let (run, n, target) = (store.clone(), n.clone(), target.to_owned());
        tokio::task::spawn_blocking(move || receipt(&run, &n, &target, &catalog, &received))
            .await??;
        Ok::<_, anyhow::Error>(())
    };
    run().await.map_err(|e| format!("{e:#}"))
}
pub async fn sync(store: &Arc<Store>, network: &str, sibling: &str) -> Result<bool, String> {
    let run = || async {
        let (status, raw) = policy_sync::peer_call(
            store,
            sibling,
            "GET",
            &format!("/peer/v1/networks/{network}/link-catalog"),
            b"",
        )
        .await
        .map_err(anyhow::Error::msg)?;
        ensure!(status == 200, Failure::new("unavailable", "-", "sync"));
        let received = response(&raw)?;
        let (run, id, sender) = (store.clone(), network.to_owned(), sibling.to_owned());
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut c = run.connection()?;
            let tx = c.transaction()?;
            let mut n = run.network_record(&tx, &id)?;
            let before = catalog::projection(&tx, &n, support::now()?)?
                .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
            ensure!(
                before
                    .network
                    .members
                    .iter()
                    .any(|m| crate::membership::canonical(&m.host_public_key, 32)
                        .is_ok_and(|key| crate::peer_store::key_id(&key) == sender)),
                Failure::new("forbidden", "-", "member")
            );
            let union = catalog::merge(&id, &[&before.catalog, &received])?;
            let p = catalog::verify(&tx, &n, &union, support::now()?)?;
            linking::verify_stored_catalog_repair(
                linking::CatalogFactContext {
                    network: &p.descriptor,
                    epoch: p.network.epoch,
                    known_feature_id: &p.network.facts.feature_id,
                    now: support::now()?,
                },
                &before.catalog,
                &union,
            )?;
            let old = run.stored_members(&tx, &id)?;
            let at = support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let mut members = map::projected_members(&p, &old, &at)?;
            map::persist(&run, &tx, &mut n, &p, &mut members, &at)?;
            tx.commit()?;
            run.refresh_member_pins(&c)?;
            drop(c);
            receipt(&run, &n, &sender, &received, &received)?;
            Ok(before.catalog != union)
        })
        .await?
    };
    run().await.map_err(|e| format!("{e:#}"))
}
