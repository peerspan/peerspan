//! A device seed signs only validated typed actions for its original person.
use super::{
    catalog, crypto, persistence,
    support::{self, Failure},
    transport,
};
use crate::{linking, network::Network, persons::PersonSigner, store::Store};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use hyper::Method;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Serialize)]
pub struct SignerView {
    pub network_id: String,
    pub person_public_key: String,
    pub device_public_key: String,
    pub certificate_id: String,
    pub scopes: u64,
    pub not_after: String,
}
pub struct Device {
    pub person: String,
    pub certificate: String,
    pub key: SigningKey,
    pub path: linking::SigningPath,
}
pub(crate) fn selected(c: &Connection, network: &str) -> Result<(String, String, String)> {
    c.query_row(
        "SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?1",
        [network],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()?
    .ok_or_else(|| Failure::new("not_found", "-", "signer").into())
}
pub fn device(
    c: &Connection,
    p: &catalog::Projection,
    network: &str,
    certificate: &str,
    required: Option<u64>,
) -> Result<Device> {
    let (person, selected_device, selected_certificate) = selected(c, network)?;
    let certificate = if certificate == "auto" {
        selected_certificate.clone()
    } else {
        ensure!(
            crypto::id(certificate, "dc_"),
            Failure::new("invalid", "-", "signer")
        );
        certificate.into()
    };
    let raw = p
        .network
        .facts
        .state
        .certificates
        .get(&certificate)
        .ok_or_else(|| Failure::required("-", "signer", vec![certificate.clone()]))?;
    let cert: Value = serde_json::from_slice(raw)?;
    ensure!(
        cert["person_public_key"].as_str() == Some(&person),
        Failure::new("state_conflict", "-", "person")
    );
    let device = cert["device_public_key"]
        .as_str()
        .ok_or_else(|| Failure::new("invalid", "-", "signer"))?;
    if certificate == selected_certificate {
        ensure!(
            device == selected_device,
            Failure::new("state_conflict", "-", "signer")
        );
    }
    let key = persistence::device(c, device)
        .map_err(|_| Failure::required("-", "signer", vec![certificate.clone()]))?;
    ensure!(
        STANDARD.encode(key.verifying_key().as_bytes()) == device,
        Failure::new("state_conflict", "-", "signer")
    );
    let scopes = cert["scopes"]
        .as_u64()
        .ok_or_else(|| Failure::new("invalid", "-", "signer"))?;
    let required = required.unwrap_or_else(|| {
        [1, 2, 4, 8]
            .into_iter()
            .find(|mask| scopes & mask != 0)
            .unwrap_or(1)
    });
    let path = linking::evaluate_path(
        &p.network.facts.state,
        &person,
        &certificate,
        required,
        support::now()?,
    )?;
    Ok(Device {
        person,
        certificate,
        key,
        path,
    })
}
pub fn view(store: &Store, id: &str) -> Result<SignerView> {
    let c = store.connection()?;
    let n = store.network_record(&c, id)?;
    // Select first so absent row remains distinct from failed existing authority.
    selected(&c, id)?;
    let p = catalog::projection(&c, &n, support::now()?)?
        .ok_or_else(|| Failure::new("proof_required", "-", "feature"))?;
    let d = device(&c, &p, id, "auto", None)?;
    ensure!(
        d.path.host_public_keys.last() == Some(&store.identity().public_key),
        Failure::new("forbidden", "-", "signer")
    );
    Ok(SignerView {
        network_id: id.into(),
        person_public_key: d.person,
        device_public_key: STANDARD.encode(d.key.verifying_key().as_bytes()),
        certificate_id: d.certificate,
        scopes: d.path.scopes,
        not_after: d.path.not_after,
    })
}

/// Read-only eligibility shared by automatic policy generation and status.
/// The caller owns the connection and verified projection for this decision.
pub(crate) fn automatic_policy_device(
    store: &Store,
    c: &Connection,
    n: &Network,
    p: &catalog::Projection,
    person: &str,
) -> Result<Device> {
    ensure!(
        p.network.facts.state.network_id == n.id
            && p.network.epoch == n.root_epoch
            && p.network.root_public_key == n.current_root_public_key,
        Failure::new("state_conflict", "-", "signer")
    );
    let d = device(c, p, &n.id, "auto", Some(1))?;
    let own = store.identity().public_key;
    ensure!(
        d.person == person
            && d.path.host_public_keys.last() == Some(&own)
            && p.network.facts.state.hosts.get(&own) == Some(&true)
            && p.network.facts.state.bindings.get(&own).map(String::as_str) == Some(person),
        Failure::new("forbidden", "-", "person")
    );
    Ok(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    kind: String,
    payload_base64: String,
    certificate_id: String,
}
struct Prepared {
    network: Network,
    record: Vec<u8>,
    record_id: String,
    proof_id: String,
    catalog: Vec<u8>,
    invite: bool,
    retry: bool,
    edit: Option<(u64, crate::policy::Policy)>,
}
fn access_version(p: &catalog::Projection, kind: &str, payload: &Value) -> Result<()> {
    let prior = if matches!(kind, "peerspan-policy-v1" | "peerspan-policy-v2") {
        p.access
            .policies
            .iter()
            .find(|x| Some(x.person_public_key.as_str()) == payload["person_public_key"].as_str())
            .map(|x| x.selection.high_water.version)
    } else if kind == "peerspan-group-v1" {
        p.access
            .groups
            .iter()
            .find(|x| Some(x.name.as_str()) == payload["name"].as_str())
            .map(|x| x.selection.high_water.version)
    } else {
        None
    };
    if let Some(prior) = prior {
        let next = payload["version"]
            .as_u64()
            .ok_or_else(|| Failure::new("invalid", "-", "version"))?;
        if prior == u64::MAX {
            let mut error = Failure::new("quota_exceeded", "-", "version");
            error.error = "access version exhausted".into();
            return Err(error.into());
        }
        ensure!(next > prior, Failure::new("state_conflict", "-", "version"));
    }
    Ok(())
}
struct Automatic {
    stored: crate::policy::Policy,
    plan: Option<crate::policy_edit::Plan>,
}
fn prepare(store: &Store, id: &str, input: Action) -> Result<Prepared> {
    prepare_inner(store, id, input, None)
}
fn prepare_inner(
    store: &Store,
    id: &str,
    mut input: Action,
    automatic: Option<Automatic>,
) -> Result<Prepared> {
    let claim = if input.kind == "policy_claim" {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Claim {
            capability: String,
            policy_base64: String,
        }
        let wrapper = crypto::bytes(&input.payload_base64, linking::MAX_PAYLOAD)
            .map_err(|_| Failure::new("invalid", "-", "claim"))?;
        let c: Claim = linking::decode_mutation(&wrapper, "capability policy_base64")
            .map_err(|_| Failure::new("invalid", "-", "claim"))?;
        input.kind = "peerspan-policy-v2".into();
        input.payload_base64 = c.policy_base64;
        Some(c.capability)
    } else {
        None
    };
    let mut connection = store.connection()?;
    let c = connection.transaction()?;
    let n = store.network_record(&c, id)?;
    let p = catalog::projection(&c, &n, support::now()?)?
        .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
    if let Some(expected) = &automatic {
        ensure!(
            p.policies.get(&expected.stored.person_public_key) == Some(&expected.stored),
            Failure::new("state_conflict", "-", "policy")
        );
        if let Some(plan) = &expected.plan {
            ensure!(
                store.reapply_unchanged(&c, plan)?,
                Failure::new("state_conflict", "-", "edit")
            );
        }
    }
    if input.kind == "invite_feature" {
        return prepare_invite_feature(store, &c, n, p, input);
    }
    let d = device(&c, &p, id, &input.certificate_id, None)?;
    ensure!(
        d.path.host_public_keys.last() == Some(&store.identity().public_key),
        Failure::new("forbidden", "-", "signer")
    );
    let payload = crypto::bytes(&input.payload_base64, linking::MAX_PAYLOAD)
        .map_err(|_| Failure::new("invalid", "-", "action"))?;
    let typed: Value =
        serde_json::from_slice(&payload).map_err(|_| Failure::new("invalid", "-", "action"))?;
    let action_kind = if input.kind == "checkpoint" {
        "checkpoint"
    } else if input.kind == "device_revocation" {
        "device_revocation"
    } else {
        "person_record"
    };
    let intent = if action_kind == "person_record" {
        linking::validate_action_payload(&input.kind, &payload)?;
        crypto::json(&json!({"kind":input.kind,"payload_base64":input.payload_base64}))?
    } else {
        payload.clone()
    };
    let at = support::now()?;
    let ctx = || linking::ActionContext {
        network: &p.descriptor,
        epoch: p.network.epoch,
        known_feature_id: &p.network.facts.feature_id,
        person_public_key: &d.person,
        certificate_id: &d.certificate,
        now: at,
    };
    if action_kind == "checkpoint" {
        ensure!(
            typed["person_public_key"].as_str() == Some(d.person.as_str())
                && typed["issuer_certificate_id"].as_str() == Some(d.certificate.as_str()),
            Failure::new("invalid", "-", "checkpoint")
        );
        linking::verify_stored_checkpoint_intent(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &p.network.facts.feature_id,
                now: at,
            },
            &p.catalog,
            &payload,
        )?;
    } else {
        linking::verify_stored_action_intent(ctx(), action_kind, &p.catalog, &intent)?;
    }
    // Exact immutable record retries need no new signature or version reservation.
    if action_kind == "person_record" {
        for entry in p
            .objects
            .objects
            .iter()
            .filter(|e| e.kind == "person_record")
        {
            let body = crypto::bytes(&entry.body_base64, linking::MAX_OBJECT)?;
            let old: Value = serde_json::from_slice(&body)?;
            if old["kind"] == input.kind
                && old["person_public_key"] == d.person
                && old["certificate_id"] == d.certificate
                && old["operation_id"] == "-"
                && old["payload_base64"] == input.payload_base64
            {
                let record = linking::read("person_record", &body, &d.path.signer_public_key, "-")?;
                return Ok(Prepared {
                    network: n,
                    record: body.clone(),
                    record_id: record.id,
                    proof_id: entry.id.clone(),
                    catalog: linking::select_stored_proof_catalog(
                        linking::CatalogFactContext {
                            network: &p.descriptor,
                            epoch: p.network.epoch,
                            known_feature_id: &p.network.facts.feature_id,
                            now: at,
                        },
                        &p.catalog,
                        &[linking::ProofSeed {
                            kind: "person_record".into(),
                            body: body.clone(),
                        }],
                    )?,
                    invite: false,
                    retry: true,
                    edit: None,
                });
            }
        }
        access_version(&p, &input.kind, &typed)?;
    }
    let edit = if matches!(
        input.kind.as_str(),
        "peerspan-policy-v1" | "peerspan-policy-v2"
    ) {
        let mut unsigned = typed.clone();
        unsigned
            .as_object_mut()
            .ok_or_else(|| Failure::new("invalid", "-", "policy"))?
            .insert("signature".into(), json!("-"));
        let policy: crate::policy::Policy = serde_json::from_value(unsigned)?;
        if let Some(name) = &claim {
            super::claims::check_name(store, name, &policy)?;
            ensure!(
                !store.bound_elsewhere(&c, name)?,
                Failure::new("state_conflict", "-", "claim")
            );
        }

        if automatic.as_ref().is_some_and(|a| a.plan.is_some()) {
            None
        } else {
            store.check_edit(&c, id, &policy)?.map(|seq| (seq, policy))
        }
    } else {
        None
    };
    let mut record = if action_kind == "person_record" {
        json!({"format":1,"kind":input.kind,"network_id":id,"epoch":p.network.epoch,"operation_id":"-","person_public_key":d.person,"certificate_id":d.certificate,"payload_base64":input.payload_base64,"signature":"-","host_signature":"-"})
    } else {
        typed.clone()
    };
    let message = if action_kind == "checkpoint" {
        let at = typed["issued_at"]
            .as_str()
            .ok_or_else(|| Failure::new("invalid", "-", "checkpoint"))?;
        let records: Vec<String> = serde_json::from_value(typed["records"].clone())?;
        let mut parts = vec![
            "peerspan-person-checkpoint-v1".to_owned(),
            id.into(),
            d.person.clone(),
            d.certificate.clone(),
            at.into(),
            records.len().to_string(),
        ];
        parts.extend(records);
        parts.join("\n")
    } else if action_kind == "person_record" {
        [
            "peerspan-person-authorization-v1",
            &input.kind,
            id,
            &p.network.epoch.to_string(),
            "-",
            &d.person,
            &d.certificate,
            &crypto::hash(&payload),
        ]
        .join("\n")
    } else {
        [
            "peerspan-device-revoke-v1",
            id,
            &d.person,
            record["target_device_public_key"]
                .as_str()
                .ok_or_else(|| Failure::new("invalid", "-", "action"))?,
            record["target_certificate_id"]
                .as_str()
                .ok_or_else(|| Failure::new("invalid", "-", "action"))?,
            &d.certificate,
            record["revoked_at"]
                .as_str()
                .ok_or_else(|| Failure::new("invalid", "-", "action"))?,
        ]
        .join("\n")
    };
    if input.kind == "peerspan-host-bind-v1" {
        ensure!(
            typed["host_public_key"].as_str() == Some(&store.identity().public_key),
            Failure::new("forbidden", "-", "binding")
        );
        let consent = [
            "peerspan-binding-consent-v1",
            &crypto::hash(message.as_bytes()),
        ]
        .join("\n");
        record["host_signature"] =
            json!(STANDARD.encode(store.signing_key.sign(consent.as_bytes()).to_bytes()));
    }
    record["signature"] =
        json!(PersonSigner::File(d.key).sign(&message.split('\n').collect::<Vec<_>>())?);
    let raw = crypto::json(&record)?;
    let record_id = if action_kind == "checkpoint" {
        linking::verify_stored_checkpoint(
            linking::CatalogFactContext {
                network: &p.descriptor,
                epoch: p.network.epoch,
                known_feature_id: &p.network.facts.feature_id,
                now: at,
            },
            &p.catalog,
            &raw,
        )?;
        "-".to_owned()
    } else {
        linking::verify_stored_action_authority(ctx(), action_kind, &p.catalog, &raw)?.record_id
    };
    let proof = catalog::proof_id(action_kind, &raw);
    let selected = linking::select_stored_proof_catalog(
        linking::CatalogFactContext {
            network: &p.descriptor,
            epoch: p.network.epoch,
            known_feature_id: &p.network.facts.feature_id,
            now: support::now()?,
        },
        &p.catalog,
        &[linking::ProofSeed {
            kind: action_kind.into(),
            body: raw.clone(),
        }],
    )?;
    let invite = matches!(
        input.kind.as_str(),
        "peerspan-invite-v1" | "peerspan-person-invite-v1"
    );
    let catalog = if invite {
        selected
    } else {
        let additional = crypto::json(&catalog::Catalog {
            format: 1,
            network_id: id.into(),
            objects: vec![catalog::Entry {
                id: proof.clone(),
                kind: action_kind.into(),
                body_base64: STANDARD.encode(&raw),
            }],
        })?;
        catalog::merge(id, &[&selected, &additional])?
    };
    let mut n = n;
    let restrictive = super::restrictions::restrictive(action_kind, &raw)?;
    if restrictive || automatic.is_some() {
        let union = catalog::merge(id, &[&p.catalog, &catalog])?;
        if restrictive {
            linking::verify_stored_catalog_additions(
                linking::CatalogFactContext {
                    network: &p.descriptor,
                    epoch: p.network.epoch,
                    known_feature_id: &p.network.facts.feature_id,
                    now: at,
                },
                &p.catalog,
                &union,
            )?;
        }
        let projection = catalog::verify(&c, &n, &union, at)?;
        let old = store.stored_members(&c, id)?;
        let stamp = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut members = super::map::projected_members(&projection, &old, &stamp)?;
        super::map::persist(store, &c, &mut n, &projection, &mut members, &stamp)?;
        if restrictive {
            super::restrictions::mark(&c, id, action_kind, &raw)?;
        }
        if let Some(expected) = &automatic
            && let Some(plan) = &expected.plan
        {
            store.note_device_reapply(&c, plan)?;
        }
        c.commit()?;
        store.refresh_member_pins(&connection)?;
    }
    Ok(Prepared {
        network: n,
        record: raw,
        record_id,
        proof_id: proof,
        catalog,
        invite: invite || claim.is_some(),
        retry: false,
        edit,
    })
}
fn prepare_invite_feature(
    store: &Store,
    c: &Connection,
    n: Network,
    p: catalog::Projection,
    input: Action,
) -> Result<Prepared> {
    let d = device(c, &p, &n.id, &input.certificate_id, Some(8))?;
    ensure!(
        d.path.host_public_keys.last() == Some(&store.identity().public_key),
        Failure::new("forbidden", "-", "signer")
    );
    let payload = crypto::bytes(&input.payload_base64, linking::MAX_PAYLOAD)
        .map_err(|_| Failure::new("invalid", "-", "invite"))?;
    let mut unsigned: Value =
        serde_json::from_slice(&payload).map_err(|_| Failure::new("invalid", "-", "invite"))?;
    ensure!(
        unsigned["issuer_kind"] == "person"
            && unsigned["person_public_key"] == d.person
            && unsigned["certificate_id"] == d.certificate
            && unsigned["signer_public_key"] == d.path.signer_public_key,
        Failure::new("invalid", "-", "invite")
    );
    let at = support::now()?;
    let ctx = || linking::CatalogFactContext {
        network: &p.descriptor,
        epoch: p.network.epoch,
        known_feature_id: &p.network.facts.feature_id,
        now: at,
    };
    let evidence = linking::verify_stored_invite_feature_intent(ctx(), &p.catalog, &payload)?;
    let mut halves = [Vec::new(), Vec::new()];
    let mut encoded = [String::new(), String::new()];
    for (i, name) in ["host_invite_base64", "person_invite_base64"]
        .iter()
        .enumerate()
    {
        encoded[i] = unsigned[name]
            .as_str()
            .ok_or_else(|| Failure::new("invalid", "-", "invite"))?
            .into();
        if encoded[i] != "-" {
            halves[i] = crypto::bytes(&encoded[i], linking::MAX_OBJECT)?;
        }
        unsigned
            .as_object_mut()
            .ok_or_else(|| Failure::new("invalid", "-", "invite"))?
            .remove(*name);
    }
    let message = std::str::from_utf8(&evidence.message)?;
    unsigned["signature"] =
        json!(PersonSigner::File(d.key).sign(&message.split('\n').collect::<Vec<_>>())?);
    let record = crypto::json(&unsigned)?;
    linking::verify_stored_invite_feature(ctx(), &p.catalog, &record, &halves[0], &halves[1])?;
    let seed = crypto::raw_object(vec![
        ("binding", record.clone()),
        ("host_invite_base64", crypto::json(&encoded[0])?),
        ("person_invite_base64", crypto::json(&encoded[1])?),
    ])?;
    let selected = linking::select_stored_proof_catalog(
        ctx(),
        &p.catalog,
        &[linking::ProofSeed {
            kind: "invite_feature".into(),
            body: seed,
        }],
    )?;
    Ok(Prepared {
        network: n,
        record,
        record_id: "-".into(),
        proof_id: "-".into(),
        catalog: selected,
        invite: true,
        retry: false,
        edit: None,
    })
}
pub(crate) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/networks/{id}/link-signer", get(signer))
        .route("/v1/networks/{id}/link-access-versions", get(versions))
        .route("/v1/networks/{id}/link-catalog", get(local_catalog))
        .route("/v1/networks/{id}/link-actions", post(action))
}
async fn local_catalog(
    State(store): State<Arc<Store>>,
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
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let c = store.connection()?;
        let n = store.network_record(&c, &id)?;
        let p = catalog::projection(&c, &n, support::now()?)?
            .ok_or_else(|| Failure::new("upgrade_required", "-", "feature"))?;
        let value = json!({"catalog":serde_json::from_slice::<Value>(&p.catalog)?});
        ensure!(
            crypto::json(&value)?.len() <= 16 << 20,
            Failure::new("quota_exceeded", "-", "catalog")
        );
        Ok(value)
    })
    .await
    .map_err(|_| Failure::new("internal", "-", "storage"))?
    .map(Json)
    .map_err(|e| Failure::cause(e, "-", "catalog"))
}
async fn versions(
    State(store): State<Arc<Store>>,
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
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let c=store.connection()?; let n=store.network_record(&c,&id)?;
        let p=catalog::projection(&c,&n,support::now()?)?.ok_or_else(||Failure::new("upgrade_required","-","feature"))?;
        let policies: Vec<_>=p.access.policies.iter().map(|p|json!({"person_public_key":p.person_public_key,"version":p.selection.high_water.version,"message_hash":p.selection.high_water.message_hash})).collect();
        let groups: Vec<_>=p.access.groups.iter().map(|g|json!({"name":g.name,"version":g.selection.high_water.version,"message_hash":g.selection.high_water.message_hash})).collect();
        Ok(json!({"policies":policies,"groups":groups}))
    }).await.map_err(|_|Failure::new("internal","-","storage"))?.map(Json).map_err(|e|Failure::cause(e,"-","versions"))
}
async fn signer(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<SignerView>, Failure> {
    tokio::task::spawn_blocking(move || view(&store, &id))
        .await
        .map_err(|_| Failure::new("internal", "-", "storage"))?
        .map(Json)
        .map_err(|e| Failure::cause(e, "-", "signer"))
}
pub async fn fresh(store: Arc<Store>, id: &str) -> Result<Network> {
    let n = crate::network::sync_link_network(store, id.into()).await?;
    ensure!(
        n.last_sync_error.is_none() && n.last_sync_at.is_some(),
        Failure::new("unavailable", "-", "sync")
    );
    Ok(n)
}
async fn action(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let input: Action = linking::decode_mutation(&body, "kind payload_base64 certificate_id")
        .map_err(|_| Failure::new("invalid", "-", "request"))?;
    let _guard = store.link_mutation.lock().await;
    fresh(store.clone(), &id)
        .await
        .map_err(|e| Failure::cause(e, "-", "sync"))?;
    let (run, lookup) = (store.clone(), id.clone());
    let p = tokio::task::spawn_blocking(move || prepare(&run, &lookup, input))
        .await
        .map_err(|_| Failure::new("internal", "-", "storage"))?
        .map_err(|e| Failure::cause(e, "-", "action"))?;
    if !p.invite && !p.retry {
        let body = crypto::raw_object(vec![("catalog", p.catalog.clone())])
            .map_err(|e| Failure::cause(e, "-", "action"))?;
        if body.len() > 1 << 20 {
            return Err(Failure::new("quota_exceeded", "-", "action"));
        }
        let raw = transport::request(
            store.clone(),
            &p.network.coordinator_address,
            &p.network.coordinator_public_key,
            Method::POST,
            &format!("/coord/v2/networks/{id}/statements"),
            body,
        )
        .await
        .map_err(|e| Failure::cause(e, "-", "publish"))?;
        let run = store.clone();
        let n = p.network.clone();
        let edit = p.edit.clone();
        tokio::task::spawn_blocking(move || run.apply_link_map_with_edit(n, &raw, edit))
            .await
            .map_err(|_| Failure::new("internal", "-", "storage"))?
            .map_err(|e| Failure::cause(e, "-", "map"))?;
    }
    Ok(Json(
        json!({"record_id":p.record_id,"proof_id":p.proof_id,"record_base64":STANDARD.encode(p.record),"catalog":serde_json::from_slice::<Value>(&p.catalog).map_err(|_|Failure::new("internal","-","catalog"))?,"committed":!p.invite}),
    ))
}

/// Internal typed policy generation shares the public validator and signer.
pub(crate) async fn automatic_policy(
    store: Arc<Store>,
    id: String,
    stored: crate::policy::Policy,
    content: crate::policy::Content,
    edits: Vec<crate::policy::EditEntry>,
    duration: chrono::TimeDelta,
    plan: Option<crate::policy_edit::Plan>,
) -> Result<Option<bool>> {
    let (run, lookup) = (store.clone(), id.clone());
    let has = tokio::task::spawn_blocking(move || -> Result<bool> {
        let c = run.connection()?;
        Ok(c.query_row(
            "SELECT 1 FROM link_signers WHERE network_id=?1",
            [lookup],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
    })
    .await??;
    if !has {
        return Ok(None);
    }
    let _guard = store.link_mutation.lock().await;
    fresh(store.clone(), &id).await?;
    let (run, lookup) = (store.clone(), id.clone());
    let prepared=tokio::task::spawn_blocking(move||->Result<Prepared>{
        let (payload,certificate)={
            let c=run.connection()?;let n=run.network_record(&c,&lookup)?;
            let p=catalog::projection(&c,&n,support::now()?)?.ok_or_else(||Failure::new("upgrade_required","-","feature"))?;
            let d=automatic_policy_device(&run,&c,&n,&p,&stored.person_public_key)?;
            let prior=p.access.policies.iter().find(|p|p.person_public_key==d.person).map(|p|p.selection.high_water.version).unwrap_or(0);
            let version=prior.checked_add(1).ok_or_else(||{let mut f=Failure::new("quota_exceeded","-","policy");f.error="access version exhausted".into();f})?;
            let at=support::now()?;let mut until=at+duration;if d.path.not_after!="-" {until=until.min(support::stamp(&d.path.not_after)?);}
            ensure!(until>at,Failure::new("authority_expired","-","policy"));
            let unsigned=serde_json::json!({"format":2,"network_id":lookup,"person_public_key":d.person,"version":version,"issued_at":at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),"valid_until":until.format("%Y-%m-%dT%H:%M:%SZ").to_string(),"rules":content.rules,"capability_rules":content.capability_rules,"trusted_hosts":content.trusted_hosts,"edits":edits});
            (crypto::json(&unsigned)?,d.certificate)
        };
        prepare_inner(&run,&lookup,Action {kind:"peerspan-policy-v2".into(),payload_base64:STANDARD.encode(payload),certificate_id:certificate},Some(Automatic {stored,plan}))
    }).await??;
    let body = crypto::raw_object(vec![("catalog", prepared.catalog)])?;
    if let Ok(raw) = transport::request(
        store.clone(),
        &prepared.network.coordinator_address,
        &prepared.network.coordinator_public_key,
        Method::POST,
        &format!("/coord/v2/networks/{id}/statements"),
        body,
    )
    .await
    {
        let run = store.clone();
        tokio::task::spawn_blocking(move || {
            run.apply_link_map(prepared.network, &raw, false, None)
        })
        .await??;
    }
    Ok(Some(true))
}
