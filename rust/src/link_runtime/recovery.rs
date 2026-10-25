//! Private reviewed current-root feature recovery. Import never switches pins.
use super::{
    catalog, crypto, map,
    model::SigningRequest,
    support::{self, Failure},
    transport,
};
use crate::{linking, network::Network, store::Store};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use hyper::Method;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
const KIND: &str = "link_feature_import_intent";
const FIELDS: &str = "format import_id approved state network_base64 catalog_base64 authorization_template_base64 signature submitted result_map_base64";
const AUTH_FIELDS: &str = "format network_id network_name epoch feature_id coordinator_address coordinator_public_key catalog_sha256 issued_at expires_at signature";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    format: u64,
    network_id: String,
    network_name: String,
    epoch: u64,
    feature_id: String,
    coordinator_address: String,
    coordinator_public_key: String,
    catalog_sha256: String,
    issued_at: String,
    expires_at: String,
    signature: String,
}
impl Authorization {
    fn message(&self) -> Vec<u8> {
        [
            "peerspan-link-feature-import-v1",
            &self.network_id,
            &self.network_name,
            &self.epoch.to_string(),
            &self.feature_id,
            &self.coordinator_address,
            &self.coordinator_public_key,
            &self.catalog_sha256,
            &self.issued_at,
            &self.expires_at,
        ]
        .join("\n")
        .into_bytes()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: u64,
    import_id: String,
    approved: bool,
    state: String,
    network_base64: String,
    catalog_base64: String,
    authorization_template_base64: String,
    signature: String,
    submitted: bool,
    result_map_base64: String,
}
impl Intent {
    fn materialize(&self, network: &str) -> Result<(Vec<u8>, Vec<u8>, Authorization)> {
        ensure!(
            self.format == 1
                && crypto::id(&self.import_id, "lfi_")
                && matches!(
                    self.state.as_str(),
                    "review"
                        | "awaiting_signature"
                        | "ready"
                        | "submitted"
                        | "complete"
                        | "expired"
                )
                && (!self.submitted || self.approved && self.signature != "-")
                && (self.signature == "-" || self.approved)
                && (self.state != "complete" || self.submitted && self.result_map_base64 != "-"),
            Failure::new("state_conflict", "-", "feature_import")
        );
        let descriptor = crypto::bytes(&self.network_base64, linking::MAX_OBJECT)?;
        let d: map::Descriptor = linking::decode_mutation(
            &descriptor,
            "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
        )?;
        let catalog = crypto::bytes(&self.catalog_base64, 16 << 20)?;
        catalog::decode(&catalog, network)?;
        let a: Authorization = linking::decode_mutation(
            &crypto::bytes(&self.authorization_template_base64, linking::MAX_OBJECT)?,
            AUTH_FIELDS,
        )?;
        ensure!(
            a.format == 1
                && a.network_id == network
                && d.network_id == network
                && a.network_name == d.name
                && a.coordinator_address == d.coordinator_address
                && a.coordinator_public_key == d.coordinator_public_key
                && crypto::id(&a.feature_id, "lf_")
                && a.signature == "-"
                && a.catalog_sha256 == crypto::hash(&catalog)
                && support::stamp(&a.expires_at)?
                    == support::stamp(&a.issued_at)? + chrono::Duration::seconds(300),
            Failure::new("state_conflict", "-", "feature_import")
        );
        let id = format!(
            "lfi_{}",
            crypto::hash(
                [
                    "peerspan-link-feature-import-intent-v1",
                    network,
                    &a.coordinator_address,
                    &a.coordinator_public_key,
                    &a.catalog_sha256,
                    &a.issued_at
                ]
                .join("\n")
                .as_bytes()
            )
        );
        ensure!(
            id == self.import_id,
            Failure::new("state_conflict", "-", "feature_import")
        );
        Ok((descriptor, catalog, a))
    }
}
fn load(c: &Connection, network: &str, id: &str) -> Result<Intent> {
    let raw: Option<String> = c
        .query_row(
            "SELECT record FROM network_statements WHERE network_id=?1 AND kind=?2 AND subject=?3",
            params![network, KIND, id],
            |r| r.get(0),
        )
        .optional()?;
    let intent: Intent = linking::decode_stored_json(
        raw.ok_or_else(|| Failure::new("not_found", "-", "feature_import"))?
            .as_bytes(),
        FIELDS,
    )
    .map_err(|_| Failure::new("state_conflict", "-", "feature_import"))?;
    ensure!(
        intent.import_id == id,
        Failure::new("state_conflict", "-", "feature_import")
    );
    intent.materialize(network)?;
    Ok(intent)
}
fn save(c: &Connection, network: &str, i: &Intent) -> Result<()> {
    i.materialize(network)?;
    c.execute("INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?1,?2,?3,?4) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record",params![network,KIND,i.import_id,String::from_utf8(crypto::json(i)?)?])?;
    Ok(())
}
fn reclaim_previews(
    c: &Connection,
    network: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let ids = c
        .prepare("SELECT subject FROM network_statements WHERE network_id=?1 AND kind=?2 ORDER BY subject")?
        .query_map(params![network, KIND], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in ids {
        let intent = load(c, network, &id)?;
        let (_, _, authorization) = intent.materialize(network)?;
        if at - support::stamp(&authorization.expires_at)? > chrono::Duration::hours(24)
            && (!intent.submitted || intent.state == "complete")
        {
            c.execute(
                "DELETE FROM network_statements WHERE network_id=?1 AND kind=?2 AND subject=?3",
                params![network, KIND, id],
            )?;
        }
    }
    Ok(())
}
fn snapshot(
    i: &Intent,
    network: &str,
) -> Result<(Vec<u8>, Vec<u8>, Authorization, linking::NetworkState)> {
    let (descriptor, catalog, a) = i.materialize(network)?;
    let state = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch: a.epoch,
            known_feature_id: &a.feature_id,
            now: support::now()?,
        },
        &catalog,
    )?;
    Ok((descriptor, catalog, a, state))
}
fn view(n: &Network, i: &Intent) -> Result<Value> {
    let (_, _, a, state) = snapshot(i, &n.id)?;
    let signing: Vec<_> = if i.approved && i.signature == "-" && i.state != "expired" {
        vec![SigningRequest {
            object_type: "feature_import".into(),
            message_base64: STANDARD.encode(a.message()),
            signer_public_key: state.root_public_key.clone(),
            signature_format: if n.root_ssh { "sshsig" } else { "ed25519" }.into(),
        }]
    } else {
        Vec::new()
    };
    Ok(
        json!({"import_id":i.import_id,"review":{"network_id":a.network_id,"network_name":a.network_name,"epoch":a.epoch,"feature_id":a.feature_id,"coordinator_address":a.coordinator_address,"coordinator_public_key":a.coordinator_public_key,"catalog_sha256":a.catalog_sha256,"expires_at":a.expires_at,"signer_public_key":state.root_public_key},"signing_requests":signing,"committed":i.state=="complete"}),
    )
}
fn check_current(store: &Store, c: &Connection, n: &Network, i: &Intent) -> Result<()> {
    if i.submitted || i.state == "complete" {
        return Ok(());
    }
    let (_, raw, a) = i.materialize(&n.id)?;
    let at = support::now()?;
    ensure!(
        support::stamp(&a.issued_at)? <= at && at < support::stamp(&a.expires_at)?,
        Failure::new("expired", "-", "feature_import")
    );
    let p = catalog::projection(c, n, at)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    ensure!(
        p.network.epoch == a.epoch
            && p.network.facts.feature_id == a.feature_id
            && crypto::hash(&p.catalog) == crypto::hash(&raw),
        Failure::new("state_conflict", "-", "feature_import")
    );
    let _ = store;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    coordinator_address: String,
    coordinator_public_key: String,
    import_id: String,
    approve: bool,
}
fn prepare(store: &Store, network: &str, r: Request) -> Result<String> {
    ensure!(
        crate::membership::split_host_port(&r.coordinator_address).is_ok()
            && crypto::public_key(&r.coordinator_public_key)
            && (r.import_id == "-" || crypto::id(&r.import_id, "lfi_"))
            && (!r.approve || r.import_id != "-"),
        Failure::new("invalid", "-", "feature_import")
    );
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let n = store.network_record(&tx, network)?;
    if r.import_id != "-" {
        let mut i = load(&tx, network, &r.import_id)?;
        let (_, _, a) = i.materialize(network)?;
        ensure!(
            a.coordinator_address == r.coordinator_address
                && a.coordinator_public_key == r.coordinator_public_key,
            Failure::new("operation_conflict", "-", "feature_import")
        );
        if r.approve {
            check_current(store, &tx, &n, &i)?;
            i.approved = true;
            if i.state == "review" {
                i.state = "awaiting_signature".into();
            }
            save(&tx, network, &i)?;
        }
        tx.commit()?;
        return Ok(i.import_id);
    }
    let at = support::now()?;
    reclaim_previews(&tx, network, at)?;
    let p = catalog::projection(&tx, &n, at)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    let mut target = n.clone();
    target.coordinator_address = r.coordinator_address;
    target.coordinator_public_key = r.coordinator_public_key;
    let descriptor = catalog::descriptor(&target)?;
    let a = Authorization {
        format: 1,
        network_id: n.id.clone(),
        network_name: n.name.clone(),
        epoch: p.network.epoch,
        feature_id: p.network.facts.feature_id,
        coordinator_address: target.coordinator_address,
        coordinator_public_key: target.coordinator_public_key,
        catalog_sha256: crypto::hash(&p.catalog),
        issued_at: at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        expires_at: (at + chrono::Duration::seconds(300))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
        signature: "-".into(),
    };
    let id = format!(
        "lfi_{}",
        crypto::hash(
            [
                "peerspan-link-feature-import-intent-v1",
                network,
                &a.coordinator_address,
                &a.coordinator_public_key,
                &a.catalog_sha256,
                &a.issued_at
            ]
            .join("\n")
            .as_bytes()
        )
    );
    if load(&tx, network, &id).is_ok() {
        tx.commit()?;
        return Ok(id);
    }
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM network_statements WHERE network_id=?1 AND kind=?2",
        params![network, KIND],
        |r| r.get(0),
    )?;
    ensure!(
        count < 8,
        Failure::new("quota_exceeded", "-", "feature_import")
    );
    let template = crypto::json(&a)?;
    let body = crypto::raw_object(vec![
        ("network", descriptor.clone()),
        ("catalog", p.catalog.clone()),
        ("feature_authorization", template.clone()),
    ])?;
    ensure!(
        body.len() + 1024 <= 1 << 20,
        Failure::new("quota_exceeded", "-", "feature_import")
    );
    let intent = Intent {
        format: 1,
        import_id: id.clone(),
        approved: false,
        state: "review".into(),
        network_base64: STANDARD.encode(descriptor),
        catalog_base64: STANDARD.encode(p.catalog),
        authorization_template_base64: STANDARD.encode(template),
        signature: "-".into(),
        submitted: false,
        result_map_base64: "-".into(),
    };
    save(&tx, network, &intent)?;
    tx.commit()?;
    Ok(id)
}
struct Submission {
    intent: Intent,
    authorization: Authorization,
    body: Vec<u8>,
}
enum Preparation {
    View(Value),
    Send(Box<Submission>),
}
fn prepare_submission(
    store: &Store,
    network: &str,
    id: &str,
    signature: Option<String>,
) -> Result<Preparation> {
    let (n, mut i) = {
        let c = store.connection()?;
        (store.network_record(&c, network)?, load(&c, network, id)?)
    };
    if let Some(sig) = &signature {
        ensure!(
            i.signature == "-" || i.signature == *sig,
            Failure::new("operation_conflict", "-", "feature_import")
        );
    }
    if !i.approved || i.state == "complete" {
        return Ok(Preparation::View(view(&n, &i)?));
    }
    let (descriptor, catalog, mut a, state) = snapshot(&i, network)?;
    {
        let c = store.connection()?;
        check_current(store, &c, &n, &i)?;
        if let Some(sig) = signature {
            i.signature = sig;
        }
        if i.signature == "-"
            && let Ok(key) = store.current_root(&c, network)
            && STANDARD.encode(key.verifying_key().as_bytes()) == state.root_public_key
        {
            i.signature = STANDARD.encode(key.sign(&a.message()).to_bytes());
        }
    }
    if i.signature == "-" {
        return Ok(Preparation::View(view(&n, &i)?));
    }
    a.signature = i.signature.clone();
    let message = a.message();
    let message = std::str::from_utf8(&message)?;
    crate::membership::verify_lines(
        &state.root_public_key,
        &message.split('\n').collect::<Vec<_>>(),
        &a.signature,
    )
    .map_err(|_| Failure::new("invalid", "-", "feature_import"))?;
    let authorization = crypto::json(&a)?;
    if !i.submitted {
        linking::verify_stored_feature_import(
            linking::CatalogFactContext {
                network: &descriptor,
                epoch: a.epoch,
                known_feature_id: &a.feature_id,
                now: support::now()?,
            },
            &catalog,
            &authorization,
        )?;
    }
    let body = crypto::raw_object(vec![
        ("network", descriptor),
        ("catalog", catalog),
        ("feature_authorization", authorization),
    ])?;
    ensure!(
        body.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "feature_import")
    );
    i.state = "submitted".into();
    i.submitted = true;
    {
        let c = store.connection()?;
        save(&c, network, &i)?;
    }
    Ok(Preparation::Send(Box::new(Submission {
        intent: i,
        authorization: a,
        body,
    })))
}
async fn advance(
    store: Arc<Store>,
    network: String,
    id: String,
    signature: Option<String>,
) -> Result<Value> {
    let (run, nid) = (store.clone(), network.clone());
    let prepared =
        tokio::task::spawn_blocking(move || prepare_submission(&run, &nid, &id, signature))
            .await??;
    let Preparation::Send(submission) = prepared else {
        let Preparation::View(value) = prepared else {
            unreachable!()
        };
        return Ok(value);
    };
    let Submission {
        intent: mut i,
        authorization: a,
        body,
    } = *submission;
    let raw = transport::request(
        store.clone(),
        &a.coordinator_address,
        &a.coordinator_public_key,
        Method::POST,
        "/coord/v2/networks/import",
        body,
    )
    .await?;
    let (run, network_for_apply) = (store.clone(), network.clone());
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut c = run.connection()?;
        let tx = c.transaction()?;
        let mut n = run.network_record(&tx, &network_for_apply)?;
        let current = load(&tx, &network_for_apply, &i.import_id)?;
        ensure!(
            current.signature == i.signature && current.submitted,
            Failure::new("operation_conflict", "-", "feature_import")
        );
        let (expected, authorized, auth) = current.materialize(&network_for_apply)?;
        let wire = map::Map::decode(&raw)?;
        let descriptor: map::Descriptor = linking::decode_mutation(
            wire.network.get().as_bytes(),
            "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
        )?;
        let original: map::Descriptor = serde_json::from_slice(&expected)?;
        ensure!(
            descriptor.network_id == original.network_id
                && descriptor.name == original.name
                && descriptor.genesis_root_public_key == original.genesis_root_public_key
                && descriptor.coordinator_address == original.coordinator_address
                && descriptor.coordinator_public_key == original.coordinator_public_key,
            Failure::new("invalid", "-", "feature_import")
        );
        let receipt = wire.catalog.get().as_bytes();
        let received = catalog::decode(receipt, &n.id)?;
        let retained: std::collections::BTreeSet<_> =
            received.objects.iter().map(|p| p.id.as_str()).collect();
        let missing: Vec<_> = catalog::decode(&authorized, &n.id)?
            .objects
            .into_iter()
            .filter(|p| !retained.contains(p.id.as_str()))
            .map(|p| p.id)
            .collect();
        ensure!(
            missing.is_empty(),
            Failure::required("-", "feature_import", missing)
        );
        let at = support::now()?;
        let epoch = catalog::target_epoch(&received)?;
        linking::verify_stored_network_state(
            linking::CatalogFactContext {
                network: &expected,
                epoch,
                known_feature_id: &auth.feature_id,
                now: at,
            },
            receipt,
        )?;
        linking::verify_stored_access_state(
            linking::AccessContext {
                network: &expected,
                epoch,
                known_feature_id: &auth.feature_id,
                now: at,
                prior_policies: &[],
                prior_groups: &[],
            },
            receipt,
        )?;
        let prior = catalog::read(&tx, &n.id)?;
        let union = catalog::merge(&n.id, &[&prior, receipt])?;
        let p = catalog::verify(&tx, &n, &union, at)?;
        linking::verify_stored_catalog_repair(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &p.network.facts.feature_id,
                now: at,
            },
            &prior,
            &union,
        )?;
        ensure!(
            p.network.epoch >= n.root_epoch,
            Failure::new("state_conflict", "-", "feature_import")
        );
        let old = run.stored_members(&tx, &n.id)?;
        let at = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut members = map::projected_members(&p, &old, &at)?;
        let freshness = (n.last_sync_at.clone(), n.last_sync_error.clone());
        map::persist(&run, &tx, &mut n, &p, &mut members, &at)?;
        (n.last_sync_at, n.last_sync_error) = freshness;
        tx.execute(
            "UPDATE networks SET record=?1 WHERE id=?2",
            params![serde_json::to_string(&n)?, n.id],
        )?;
        i.state = "complete".into();
        i.result_map_base64 = STANDARD.encode(raw);
        save(&tx, &network_for_apply, &i)?;
        tx.commit()?;
        run.refresh_member_pins(&c)?;
        view(&n, &i)
    })
    .await?
}
pub(crate) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/networks/{network}/feature-import", post(request))
        .route(
            "/v1/networks/{network}/feature-import/{id}/signed",
            post(signed),
        )
        .route(
            "/v1/networks/{network}/feature-import/{id}/resume",
            post(resume),
        )
}
async fn request(
    State(store): State<Arc<Store>>,
    Path(network): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let r: Request = linking::decode_mutation(
        &body,
        "coordinator_address coordinator_public_key import_id approve",
    )
    .map_err(|_| Failure::new("invalid", "-", "request"))?;
    let approve = r.approve;
    let _guard = store.link_mutation.lock().await;
    let (run, nid) = (store.clone(), network.clone());
    let id = tokio::task::spawn_blocking(move || prepare(&run, &nid, r))
        .await
        .map_err(|_| Failure::new("internal", "-", "storage"))?
        .map_err(|e| Failure::cause(e, "-", "feature_import"))?;
    let value = if approve {
        advance(store.clone(), network, id, None).await
    } else {
        let run = store.clone();
        tokio::task::spawn_blocking(move || -> Result<Value> {
            let c = run.connection()?;
            let n = run.network_record(&c, &network)?;
            view(&n, &load(&c, &network, &id)?)
        })
        .await
        .map_err(|_| Failure::new("internal", "-", "storage"))?
    };
    value
        .map(Json)
        .map_err(|e| Failure::cause(e, "-", "feature_import"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    object_type: String,
    signature: String,
}
async fn signed(
    State(store): State<Arc<Store>>,
    Path((network, id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let r: Signature = linking::decode_mutation(&body, "object_type signature")
        .map_err(|_| Failure::new("invalid", "-", "request"))?;
    if r.object_type != "feature_import" {
        return Err(Failure::new("invalid", "-", "request"));
    }
    let _guard = store.link_mutation.lock().await;
    advance(store.clone(), network, id, Some(r.signature))
        .await
        .map(Json)
        .map_err(|e| Failure::cause(e, "-", "feature_import"))
}
async fn resume(
    State(store): State<Arc<Store>>,
    Path((network, id)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let _: serde_json::Map<String, Value> =
        linking::decode_mutation(&body, "").map_err(|_| Failure::new("invalid", "-", "request"))?;
    let _guard = store.link_mutation.lock().await;
    advance(store.clone(), network, id, None)
        .await
        .map(Json)
        .map_err(|e| Failure::cause(e, "-", "feature_import"))
}
