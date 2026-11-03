//! Current member authenticated catalog replication; historical evidence only.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
};
use crate::{linking, model::Error, store::Store};
use anyhow::{Result, ensure};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRequest {
    catalog: Box<RawValue>,
}
fn response(raw: &[u8]) -> Result<Value> {
    let value = serde_json::json!({"catalog":serde_json::from_slice::<Value>(raw)?});
    ensure!(
        crypto::json(&value)?.len() <= 16 << 20,
        Failure::new("quota_exceeded", "-", "catalog")
    );
    Ok(value)
}
fn member(p: &catalog::Projection, sender: &str) -> bool {
    p.network.members.iter().any(|m| {
        crate::membership::canonical(&m.host_public_key, 32)
            .is_ok_and(|key| crate::peer_store::key_id(&key) == sender)
    })
}
pub(crate) fn routes() -> Router<Arc<Store>> {
    Router::new().route(
        "/peer/v1/networks/{id}/link-catalog",
        get(get_catalog).post(post_catalog),
    )
}
async fn get_catalog(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    uri: axum::http::Uri,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    if uri.query().is_some()
        || !body
            .map_err(|_| Failure::new("invalid", "-", "request"))?
            .is_empty()
    {
        return Err(Failure::new("invalid", "-", "request"));
    }
    let _guard = store.link_mutation.lock().await;
    let run = store.clone();
    let value = tokio::task::spawn_blocking(move || -> Result<Value> {
        let c = run.connection()?;
        let n = run.network_record(&c, &id)?;
        let p = catalog::projection(&c, &n, support::now()?)?
            .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
        ensure!(
            member(&p, &sender),
            Failure::new("forbidden", "-", "member")
        );
        response(&p.catalog)
    })
    .await
    .map_err(|_| Failure::new("internal", "-", "storage"))?
    .map_err(|e| Failure::cause(e, "-", "catalog"))?;
    Ok(Json(value))
}
async fn post_catalog(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    uri: axum::http::Uri,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    if uri.query().is_some() {
        return Err(Failure::new("invalid", "-", "request"));
    }
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let request: CatalogRequest = linking::decode_mutation(&body, "catalog")
        .map_err(|_| Failure::new("invalid", "-", "request"))?;
    let _guard = store.link_mutation.lock().await;
    let run = store.clone();
    let value = tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut c = run.connection()?;
        let tx = c.transaction()?;
        let mut n = run.network_record(&tx, &id)?;
        let (feature, _) = catalog::feature(&tx, &id)?;
        ensure!(
            feature != "-",
            Failure::new("upgrade_required", "-", "feature")
        );
        let prior = catalog::read(&tx, &id)?;
        let prior_projection = catalog::projection(&tx, &n, support::now()?)?
            .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
        ensure!(
            member(&prior_projection, &sender),
            Failure::new("forbidden", "-", "member")
        );
        let union = catalog::merge(&id, &[&prior, request.catalog.get().as_bytes()])?;
        let at = support::now()?;
        let p = catalog::verify(&tx, &n, &union, at)?;
        linking::verify_stored_catalog_repair(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &feature,
                now: at,
            },
            &prior,
            &union,
        )?;

        let result = response(&p.catalog)?;
        let old = {
            let mut q = tx.prepare(
                "SELECT record FROM network_members WHERE network_id=?1 ORDER BY host_id",
            )?;
            q.query_map([&id], |r| r.get::<_, String>(0))?
                .map(|r| Ok(serde_json::from_str(&r?)?))
                .collect::<Result<Vec<crate::network::Member>>>()?
        };
        let at = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut members = map::projected_members(&p, &old, &at)?;
        map::persist(&run, &tx, &mut n, &p, &mut members, &at)?;
        tx.commit()?;
        run.refresh_member_pins(&c)?;
        Ok(result)
    })
    .await
    .map_err(|_| Failure::new("internal", "-", "storage"))?
    .map_err(|e| Failure::cause(e, "-", "catalog"))?;
    Ok(Json(value))
}
impl Store {
    pub(crate) fn reject_legacy_link_peer(&self, id: &str) -> std::result::Result<(), Error> {
        let c = self.connection()?;
        let (feature, _) = catalog::feature(&c, id).map_err(support::model_error)?;
        if feature != "-" {
            return Err(support::model_error(
                Failure::new("upgrade_required", "-", "feature").into(),
            ));
        }
        Ok(())
    }
}
