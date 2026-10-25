//! Root-reviewed feature preparation and exact roster acknowledgments.
use super::{
    catalog, crypto,
    model::SigningRequest,
    provider,
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
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    format: u64,
    network_id: String,
    epoch: u64,
    version: u64,
    issued_at: String,
    host_public_keys: Vec<String>,
    signature: String,
}
impl Proposal {
    fn message(&self) -> Vec<u8> {
        let mut parts = vec![
            "peerspan-link-feature-v1".to_owned(),
            self.network_id.clone(),
            self.epoch.to_string(),
            "1".into(),
            self.issued_at.clone(),
            self.host_public_keys.len().to_string(),
        ];
        parts.extend(self.host_public_keys.clone());
        parts.join("\n").into_bytes()
    }
    fn id(&self) -> String {
        format!("lf_{}", crypto::hash(&self.message()))
    }
}
#[derive(Serialize)]
struct View {
    state: String,
    feature_id: String,
    proposal: Value,
    acknowledgments: Vec<Value>,
    pending_hosts: Vec<String>,
    signing_requests: Vec<SigningRequest>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    activate: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    proposal: Box<RawValue>,
    acknowledgments: Vec<Box<RawValue>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposals {
    proposals: Vec<Candidate>,
}
fn raw(value: &Value) -> Result<Vec<u8>> {
    crypto::json(value)
}
pub fn legacy_catalog(c: &Connection, n: &Network) -> Result<Vec<u8>> {
    let mut entries = BTreeMap::new();
    let mut add = |kind: &str, body: Vec<u8>| {
        let id = catalog::proof_id(kind, &body);
        entries.insert(
            id.clone(),
            catalog::Entry {
                id,
                kind: kind.into(),
                body_base64: STANDARD.encode(body),
            },
        );
    };
    let rows = {
        let mut q = c.prepare(
            "SELECT kind,record FROM network_statements WHERE network_id=?1 ORDER BY kind,subject",
        )?;
        q.query_map([&n.id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (kind, body) in rows {
        if kind == "person" {
            let p: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&body)?;
            for (field, kind) in [
                ("admission", "person_admission"),
                ("membership", "person_membership"),
            ] {
                if let Some(proof) = p.get(field)
                    && proof.get() != "null"
                {
                    add(kind, proof.get().as_bytes().to_vec());
                }
            }
            continue;
        }
        let public = match kind.as_str() {
            "rotation" | "attestation" | "host_admission" | "group" | "policy"
            | "admin_removal" | "person_removal" => kind.as_str(),
            "admin" => "admin_delegation",
            "binding" => "host_binding",
            "membership" => "host_membership",
            "host" => "host_revocation",
            "invite" => "invite_revocation",
            "leave" => "host_leave",
            "unbind" => "host_unbinding",
            "move" => "coordinator_move",
            _ => continue,
        };
        add(public, body.into_bytes());
    }
    let members = {
        let mut q =
            c.prepare("SELECT record FROM network_members WHERE network_id=?1 ORDER BY host_id")?;
        q.query_map([&n.id], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for body in members {
        let row: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&body)?;
        for (field, kind) in [
            ("admission", "host_admission"),
            ("membership", "host_membership"),
        ] {
            if let Some(proof) = row.get(field)
                && proof.get() != "null"
            {
                add(kind, proof.get().as_bytes().to_vec());
            }
        }
    }
    let bytes = crypto::json(&catalog::Catalog {
        format: 1,
        network_id: n.id.clone(),
        objects: entries.into_values().collect(),
    })?;
    catalog::decode(&bytes, &n.id)?;
    Ok(bytes)
}
async fn put(
    store: Arc<Store>,
    n: &Network,
    id: &str,
    record: &catalog::FeatureRecord,
) -> Result<()> {
    let (n, id, record) = (n.clone(), id.to_owned(), record.clone());
    tokio::task::spawn_blocking(move||->Result<()> {
    let c = store.connection()?;
    let (existing, _) = catalog::feature(&c, &n.id)?;
    ensure!(
        existing == "-" || existing == id,
        Failure::new("state_conflict", "-", "feature")
    );
    if existing != "-" {
        return Ok(());
    }
    c.execute("INSERT INTO link_features(network_id,feature_id,record) VALUES(?1,?2,?3) ON CONFLICT(network_id) DO UPDATE SET feature_id=excluded.feature_id,record=excluded.record",params![n.id,id,String::from_utf8(crypto::json(&record)?)?])?;
    Ok(())
    }).await?
}
fn view(record: &catalog::FeatureRecord, n: &Network) -> Result<View> {
    let p: Proposal = serde_json::from_value(record.proposal.clone())?;
    let id = p.id();
    let acked: Vec<_> = record
        .acknowledgments
        .iter()
        .filter_map(|a| a["host_public_key"].as_str())
        .collect();
    let mut requests = Vec::new();
    if record.activate && p.signature == "-" {
        requests.push(SigningRequest {
            object_type: "feature_proposal".into(),
            message_base64: STANDARD.encode(p.message()),
            signer_public_key: n.current_root_public_key.clone(),
            signature_format: if n.root_ssh { "sshsig" } else { "ed25519" }.into(),
        });
    }
    Ok(View {
        state: record.state.clone(),
        feature_id: id,
        proposal: record.proposal.clone(),
        acknowledgments: record.acknowledgments.clone(),
        pending_hosts: p
            .host_public_keys
            .into_iter()
            .filter(|h| !acked.contains(&h.as_str()))
            .collect(),
        signing_requests: requests,
    })
}
async fn proposals(store: Arc<Store>, n: &Network) -> Result<Proposals> {
    let raw = transport::request(
        store,
        &n.coordinator_address,
        &n.coordinator_public_key,
        Method::GET,
        &format!("/coord/v2/networks/{}/link-feature/proposals", n.id),
        Vec::new(),
    )
    .await?;
    linking::decode_mutation(&raw, "proposals")
}
async fn send(
    store: Arc<Store>,
    n: &Network,
    path: &str,
    fields: Vec<(&str, Vec<u8>)>,
) -> Result<Vec<u8>> {
    transport::request(
        store,
        &n.coordinator_address,
        &n.coordinator_public_key,
        Method::POST,
        path,
        crypto::raw_object(fields)?,
    )
    .await
}
async fn acknowledge(store: Arc<Store>, n: &Network, catalog: &[u8]) -> Result<()> {
    let offered = proposals(store.clone(), n).await?;
    let descriptor = catalog::descriptor(n)?;
    for candidate in offered.proposals {
        let checked = linking::verify_stored_feature_preparation(
            linking::FeatureContext {
                network: &descriptor,
                epoch: n.root_epoch,
                known_feature_id: "-",
                now: support::now()?,
            },
            catalog,
            candidate.proposal.get().as_bytes(),
        );
        let Ok(checked) = checked else { continue };
        let p: Proposal = serde_json::from_str(candidate.proposal.get())?;
        let host = store.identity().public_key;
        if !p.host_public_keys.contains(&host)
            || candidate
                .acknowledgments
                .iter()
                .any(|a| linking::read("feature_ack", a.get().as_bytes(), &host, "-").is_ok())
        {
            continue;
        }
        let message = ["peerspan-link-feature-ack-v1", &checked.feature_id, &host].join("\n");
        let ack = crypto::json(
            &json!({"format":1,"feature_id":checked.feature_id,"host_public_key":host,"signature":STANDARD.encode(store.signing_key.sign(message.as_bytes()).to_bytes())}),
        )?;
        send(
            store.clone(),
            n,
            &format!("/coord/v2/networks/{}/link-feature/acknowledgments", n.id),
            vec![("acknowledgment", ack), ("catalog", catalog.to_vec())],
        )
        .await?;
    }
    Ok(())
}
async fn publish(
    store: Arc<Store>,
    n: &Network,
    catalog: &[u8],
    record: &mut catalog::FeatureRecord,
) -> Result<()> {
    let proposal = raw(&record.proposal)?;
    let p: Proposal = serde_json::from_slice(&proposal)?;
    let id = p.id();
    send(
        store.clone(),
        n,
        &format!("/coord/v2/networks/{}/link-feature/proposals", n.id),
        vec![
            ("proposal", proposal.clone()),
            ("catalog", catalog.to_vec()),
        ],
    )
    .await?;
    acknowledge(store.clone(), n, catalog).await?;
    for candidate in proposals(store.clone(), n).await?.proposals {
        let p: Proposal = serde_json::from_str(candidate.proposal.get())?;
        if p.id() != id {
            continue;
        }
        ensure!(
            candidate.proposal.get().as_bytes() == proposal,
            Failure::new("operation_conflict", "-", "feature")
        );
        record.acknowledgments = candidate
            .acknowledgments
            .into_iter()
            .map(|a| serde_json::from_str(a.get()))
            .collect::<std::result::Result<_, _>>()?;
        break;
    }
    put(store.clone(), n, &id, record).await?;
    if !view(record, n)?.pending_hosts.is_empty() {
        return Ok(());
    }
    let feature = crypto::json(
        &json!({"proposal":record.proposal,"acknowledgments":record.acknowledgments}),
    )?;
    let descriptor = catalog::descriptor(n)?;
    linking::verify_stored_feature(
        linking::FeatureContext {
            network: &descriptor,
            epoch: n.root_epoch,
            known_feature_id: "-",
            now: support::now()?,
        },
        catalog,
        &feature,
    )?;
    send(
        store.clone(),
        n,
        &format!("/coord/v2/networks/{}/link-feature", n.id),
        vec![("feature", feature), ("catalog", catalog.to_vec())],
    )
    .await?;
    let bytes = transport::request(
        store.clone(),
        &n.coordinator_address,
        &n.coordinator_public_key,
        Method::GET,
        &format!("/coord/v2/networks/{}/map", n.id),
        Vec::new(),
    )
    .await?;
    let (run, n) = (store.clone(), n.clone());
    tokio::task::spawn_blocking(move || run.apply_link_map(n, &bytes, false, None)).await??;
    record.state = "active".into();
    Ok(())
}
async fn prepare(
    store: Arc<Store>,
    id: &str,
    activate: bool,
    signature: Option<String>,
    fresh: bool,
) -> Result<View> {
    let n = if fresh {
        provider::fresh(store.clone(), id).await?
    } else {
        let (run, lookup) = (store.clone(), id.to_owned());
        tokio::task::spawn_blocking(move || run.network(&lookup)).await??
    };
    let (run, lookup) = (store.clone(), id.to_owned());
    let has_signature = signature.is_some();
    let (mut record, catalog) = tokio::task::spawn_blocking(move || -> Result<_> {
        let c = run.connection()?;
        let (feature, record) = catalog::feature(&c, &lookup)?;
        if feature != "-" {
            return Ok((record.expect("active record"), Vec::new()));
        }
        let at = support::now()?;
        let catalog = legacy_catalog(&c, &n)?;
        let record = if let Some(record) = record {
            let p: Proposal = serde_json::from_value(record.proposal.clone())?;
            if at < support::stamp(&p.issued_at)? + chrono::Duration::hours(24) {
                Some(record)
            } else {
                None
            }
        } else {
            None
        };
        let record = if let Some(record) = record {
            record
        } else {
            ensure!(
                !has_signature,
                Failure::new("state_conflict", "-", "feature")
            );
            let mut hosts = {
                let mut q = c.prepare(
                    "SELECT record FROM network_members WHERE network_id=?1 ORDER BY host_id",
                )?;
                q.query_map([&lookup], |r| r.get::<_, String>(0))?
                    .map(|r| {
                        let m: crate::network::Member = serde_json::from_str(&r?)?;
                        Ok(m.public_key)
                    })
                    .collect::<Result<Vec<_>>>()?
            };
            hosts.sort();
            hosts.dedup();
            let p = Proposal {
                format: 1,
                network_id: lookup,
                epoch: n.root_epoch,
                version: 1,
                issued_at: at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                host_public_keys: hosts,
                signature: "-".into(),
            };
            catalog::FeatureRecord {
                state: "preparing".into(),
                proposal: serde_json::to_value(p)?,
                acknowledgments: Vec::new(),
                activate: false,
            }
        };
        Ok((record, catalog))
    })
    .await??;
    let (run, lookup) = (store.clone(), id.to_owned());
    let n = tokio::task::spawn_blocking(move || run.network(&lookup)).await??;
    if record.state == "active" {
        return view(&record, &n);
    }
    if activate {
        record.activate = true;
    }
    let mut p: Proposal = serde_json::from_value(record.proposal.clone())?;
    if let Some(signature) = signature {
        ensure!(
            record.activate && (p.signature == "-" || p.signature == signature),
            Failure::new("operation_conflict", "-", "feature")
        );
        p.signature = signature;
    } else if record.activate && p.signature == "-" {
        let (run, lookup, root, message) = (
            store.clone(),
            id.to_owned(),
            n.current_root_public_key.clone(),
            p.message(),
        );
        let signature = tokio::task::spawn_blocking(move || -> Result<Option<String>> {
            let c = run.connection()?;
            if let Ok(key) = run.current_root(&c, &lookup) {
                ensure!(
                    STANDARD.encode(key.verifying_key().as_bytes()) == root,
                    Failure::new("forbidden", "-", "root")
                );
                Ok(Some(STANDARD.encode(key.sign(&message).to_bytes())))
            } else {
                Ok(None)
            }
        })
        .await??;
        if let Some(signature) = signature {
            p.signature = signature;
        }
    }
    if p.signature != "-" {
        let bytes = crypto::json(&p)?;
        let descriptor = catalog::descriptor(&n)?;
        linking::verify_stored_feature_preparation(
            linking::FeatureContext {
                network: &descriptor,
                epoch: n.root_epoch,
                known_feature_id: "-",
                now: support::now()?,
            },
            &catalog,
            &bytes,
        )?;
        record.proposal = serde_json::to_value(&p)?;
        record.state = "collecting".into();
    }
    put(store.clone(), &n, &p.id(), &record).await?;
    if record.activate && p.signature != "-" {
        publish(store.clone(), &n, &catalog, &mut record).await?;
    }
    view(&record, &n)
}
pub async fn resume(store: Arc<Store>, n: &Network) -> Result<()> {
    let (run, current) = (store.clone(), n.clone());
    let (feature, record, catalog) = tokio::task::spawn_blocking(move || -> Result<_> {
        let c = run.connection()?;
        let (feature, record) = catalog::feature(&c, &current.id)?;
        let catalog = if feature == "-" {
            legacy_catalog(&c, &current)?
        } else {
            Vec::new()
        };
        Ok((feature, record, catalog))
    })
    .await??;
    if feature != "-" {
        return Ok(());
    }
    if let Some(mut record) = record
        && record.activate
        && record.proposal["signature"] != "-"
    {
        publish(store, n, &catalog, &mut record).await
    } else {
        acknowledge(store, n, &catalog).await
    }
}
pub(crate) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/networks/{id}/link-feature", post(enable))
        .route("/v1/networks/{id}/link-feature/signed", post(signed))
}
async fn enable(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<View>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let input: Input = linking::decode_mutation(&body, "activate")
        .map_err(|_| Failure::new("invalid", "-", "request"))?;
    let _guard = store.link_mutation.lock().await;
    prepare(store.clone(), &id, input.activate, None, true)
        .await
        .map(Json)
        .map_err(|e| Failure::cause(e, "-", "feature"))
}
async fn signed(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<View>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let input: Signed = linking::decode_mutation(&body, "signature")
        .map_err(|_| Failure::new("invalid", "-", "request"))?;
    let _guard = store.link_mutation.lock().await;
    prepare(store.clone(), &id, true, Some(input.signature), true)
        .await
        .map(Json)
        .map_err(|e| Failure::cause(e, "-", "feature"))
}
