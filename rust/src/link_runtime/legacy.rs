//! Original-person/root mutations retain exact signed public catalog evidence.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
    transport,
};
use crate::{linking, model::Error, network::Network, store::Store};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::Method;
use serde_json::Value;
use std::sync::Arc;
pub struct Submission {
    pub network: Network,
    pub submitted: bool,
}
struct Prepared {
    network: Network,
    catalog: Vec<u8>,
}
fn prepare(
    store: &Store,
    n: &Network,
    kind: &str,
    body: Vec<u8>,
    local: bool,
) -> Result<Option<Prepared>> {
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let (feature, _) = catalog::feature(&tx, &n.id)?;
    if feature == "-" {
        return Ok(None);
    }
    let mut n = store.network_record(&tx, &n.id)?;
    let prior = catalog::read(&tx, &n.id)?;
    let proof = catalog::proof_id(kind, &body);
    let added = crypto::json(&catalog::Catalog {
        format: 1,
        network_id: n.id.clone(),
        objects: vec![catalog::Entry {
            id: proof.clone(),
            kind: kind.into(),
            body_base64: STANDARD.encode(&body),
        }],
    })?;
    let union = catalog::merge(&n.id, &[&prior, &added])?;
    let epoch = catalog::target_epoch(&catalog::decode(&union, &n.id)?)?;
    let descriptor = catalog::descriptor(&n)?;
    let at = support::now()?;
    linking::verify_stored_catalog_additions(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &feature,
            now: at,
        },
        &prior,
        &union,
    )?;
    let p = catalog::verify(&tx, &n, &union, at)?;
    let selected = linking::select_stored_proof_catalog(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &feature,
            now: at,
        },
        &union,
        &[linking::ProofSeed {
            kind: kind.into(),
            body: body.clone(),
        }],
    )?;
    ensure!(
        crypto::raw_object(vec![("catalog", selected.clone())])?.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "writer")
    );
    if local {
        let old = store.stored_members(&tx, &n.id)?;
        let at = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut members = map::projected_members(&p, &old, &at)?;
        map::persist(store, &tx, &mut n, &p, &mut members, &at)?;
        super::restrictions::mark(&tx, &n.id, kind, &body)?;
        if kind == "admin_removal" {
            let value: Value = serde_json::from_slice(&body)?;
            if value["format"] == 2 {
                let person = value["person_public_key"]
                    .as_str()
                    .ok_or_else(|| Failure::new("invalid", "-", "admin"))?;
                let subject = format!("{}:{}", person, value["revoke_admitted"] == true);
                let fresh=tx.execute("INSERT OR IGNORE INTO network_statements(network_id,kind,subject,record) VALUES(?1,'link_admin_removal_v2',?2,?3)",rusqlite::params![n.id,subject,String::from_utf8(body.clone())?])?>0;
                if fresh {
                    crate::store::append_event(
                        &tx,
                        "network.admin_removed",
                        &crate::persons::person_id_of(person)?,
                        &at,
                    )?;
                }
            }
        }
    }
    tx.commit()?;
    if local {
        store.refresh_member_pins(&c)?;
    }
    Ok(Some(Prepared {
        network: n,
        catalog: selected,
    }))
}
pub async fn submit(
    store: Arc<Store>,
    n: &Network,
    kind: &str,
    body: Value,
    local: bool,
) -> Result<Option<Submission>, Error> {
    submit_raw(
        store,
        n,
        kind,
        crypto::json(&body).map_err(support::model_error)?,
        local,
    )
    .await
}
pub(crate) async fn submit_raw(
    store: Arc<Store>,
    n: &Network,
    kind: &str,
    body: Vec<u8>,
    local: bool,
) -> Result<Option<Submission>, Error> {
    let run = store.clone();
    let _guard = run.link_mutation.lock().await;
    submit_raw_locked(store, n, kind, body, local).await
}
pub(crate) async fn submit_raw_locked(
    store: Arc<Store>,
    n: &Network,
    kind: &str,
    body: Vec<u8>,
    local: bool,
) -> Result<Option<Submission>, Error> {
    let (run, current, kind) = (store.clone(), n.clone(), kind.to_owned());
    let prepared = tokio::task::spawn_blocking(move || prepare(&run, &current, &kind, body, local))
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(support::model_error)?;
    let Some(p) = prepared else {
        return Ok(None);
    };
    let body = crypto::raw_object(vec![("catalog", p.catalog)]).map_err(support::model_error)?;
    let raw = match transport::request(
        store.clone(),
        &p.network.coordinator_address,
        &p.network.coordinator_public_key,
        Method::POST,
        &format!("/coord/v2/networks/{}/statements", p.network.id),
        body,
    )
    .await
    {
        Ok(raw) => raw,
        Err(_) if local => {
            return Ok(Some(Submission {
                network: p.network,
                submitted: false,
            }));
        }
        Err(e) => return Err(support::model_error(e)),
    };
    let run = store.clone();
    let n = p.network;
    let network = tokio::task::spawn_blocking(move || run.apply_link_map(n, &raw, false, None))
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(support::model_error)?;
    Ok(Some(Submission {
        network,
        submitted: true,
    }))
}
