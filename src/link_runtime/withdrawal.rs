//! Reviewed format-2 root withdrawals keep exact eligible public grants.
use super::{
    catalog, crypto, legacy,
    support::{self, Failure},
};
use crate::{
    linking,
    membership::KeySigner,
    model::Error,
    network::{Network, Revoked},
    store::Store,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::sync::Arc;
pub(crate) fn plan(store: &Store, id: &str, person: &str) -> Result<Value> {
    let c = store.connection()?;
    let n = store.network_record(&c, id)?;
    let key = store.resolve_admin(&c, id, person)?;
    let p = catalog::projection(&c, &n, support::now()?)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    let kept = linking::build_stored_admin_removal_plan(
        linking::CatalogFactContext {
            network: &p.descriptor,
            epoch: p.network.epoch,
            known_feature_id: &p.network.facts.feature_id,
            now: support::now()?,
        },
        &p.catalog,
        &key,
    )?;
    Ok(json!({"format":2,"person_public_key":key,"kept":kept}))
}
fn prepare(
    store: &Store,
    id: &str,
    person: Option<String>,
    revoke: bool,
    signed: Option<Vec<u8>>,
) -> Result<Option<(Network, Vec<u8>)>> {
    let c = store.connection()?;
    let n = store.network_record(&c, id)?;
    let Some(p) = catalog::projection(&c, &n, support::now()?)? else {
        ensure!(
            signed.is_none(),
            Failure::new("upgrade_required", "-", "feature")
        );
        return Ok(None);
    };
    let mut external = None;
    let mut external_raw = None;
    let key = if let Some(raw) = signed {
        for entry in p
            .objects
            .objects
            .iter()
            .filter(|e| e.kind == "admin_removal")
        {
            if crypto::bytes(&entry.body_base64, linking::MAX_OBJECT)? == raw {
                return Ok(Some((n, raw)));
            }
        }

        let value: Value = linking::decode_mutation(
            &raw,
            "format network_id person_public_key revoke_admitted removed_at kept signature",
        )?;
        linking::read("admin_removal_v2", &raw, &p.network.root_public_key, "-")
            .map_err(|_| Failure::new("forbidden", "-", "admin"))?;
        ensure!(
            value["network_id"] == id,
            Failure::new("invalid", "-", "admin")
        );
        external_raw = Some(raw);
        let key = value["person_public_key"]
            .as_str()
            .ok_or_else(|| Failure::new("invalid", "-", "admin"))?
            .to_owned();
        external = Some(value);
        key
    } else {
        store.resolve_admin(
            &c,
            id,
            person
                .as_deref()
                .ok_or_else(|| Failure::new("invalid", "-", "admin"))?,
        )?
    };
    let requested = external
        .as_ref()
        .map_or(revoke, |v| v["revoke_admitted"] == true);
    let mut previous = None;
    for e in p
        .objects
        .objects
        .iter()
        .filter(|e| e.kind == "admin_removal")
    {
        let value: Value =
            serde_json::from_slice(&crypto::bytes(&e.body_base64, linking::MAX_OBJECT)?)?;
        if value["person_public_key"] == key {
            if let Some(exact) = &external {
                if value["revoke_admitted"] == exact["revoke_admitted"] {
                    ensure!(
                        &value == exact,
                        Failure::new("operation_conflict", "-", "admin")
                    );
                    let bytes = external_raw.clone().unwrap_or(crypto::json(&value)?);
                    return Ok(Some((n, bytes)));
                }
                ensure!(
                    exact["revoke_admitted"] == true,
                    Failure::new("operation_conflict", "-", "admin")
                );
            }
            if value["revoke_admitted"] == true || !requested {
                previous = Some(value);
            }
        }
    }
    if let Some(value) = previous {
        return Ok(Some((n, crypto::json(&value)?)));
    }
    if let Some(_value) = external {
        return Ok(Some((
            n,
            external_raw.ok_or_else(|| Failure::new("invalid", "-", "admin"))?,
        )));
    }
    let kept = if requested {
        Vec::new()
    } else {
        linking::build_stored_admin_removal_plan(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &p.network.facts.feature_id,
                now: support::now()?,
            },
            &p.catalog,
            &key,
        )?
    };
    let at = support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut value = json!({"format":2,"network_id":id,"person_public_key":key,"revoke_admitted":requested,"removed_at":at,"kept":kept,"signature":"-"});
    let mut lines = vec![
        "peerspan-admin-remove-v2".into(),
        id.into(),
        key,
        requested.to_string(),
        at,
        kept.len().to_string(),
    ];
    lines.extend(kept);
    let root = store.current_root(&c, id)?;
    ensure!(
        STANDARD.encode(root.verifying_key().as_bytes()) == p.network.root_public_key,
        Failure::new("forbidden", "-", "root")
    );
    value["signature"] =
        json!(KeySigner::Raw(&root).sign(&lines.iter().map(String::as_str).collect::<Vec<_>>())?);
    Ok(Some((n, crypto::json(&value)?)))
}
pub(crate) async fn submit(
    store: Arc<Store>,
    id: String,
    person: Option<String>,
    revoke: bool,
    signed: Option<Vec<u8>>,
) -> Result<Option<Revoked>, Error> {
    let lock = store.clone();
    let _guard = lock.link_mutation.lock().await;
    let (run, lookup) = (store.clone(), id.clone());
    let prepared =
        tokio::task::spawn_blocking(move || prepare(&run, &lookup, person, revoke, signed))
            .await
            .map_err(|e| Error::Internal(e.into()))?
            .map_err(support::model_error)?;
    let Some((n, value)) = prepared else {
        return Ok(None);
    };
    let shape: Value = serde_json::from_slice(&value)?;
    let subject = shape["person_public_key"]
        .as_str()
        .ok_or_else(|| Error::Invalid("invalid person".into()))?
        .to_owned();
    let result = legacy::submit_raw_locked(store, &n, "admin_removal", value, true)
        .await?
        .ok_or_else(|| Error::Invalid("active feature required".into()))?;
    Ok(Some(Revoked {
        network_id: id,
        kind: "admin".into(),
        subject,
        submitted: result.submitted,
    }))
}
