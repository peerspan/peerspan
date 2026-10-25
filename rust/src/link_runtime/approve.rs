//! Fixed reviewed owner/admin signing intentions; original-person keys stay external.
use super::{
    catalog, ceremony, crypto,
    map::Descriptor,
    model::{Approve, Intent, IntentValue, PendingRecord, Signature, SigningRequest},
    persistence::{self, Pending},
    provider, request,
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
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hyper::Method;
use rusqlite::{Connection, Transaction};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plain {
    request_id: String,
    role: String,
    writer_public_key: String,
    packet: Box<RawValue>,
    catalog: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    object_type: String,
    signature: String,
}
struct Choice {
    person: String,
    certificate: String,
    public: String,
    not_after: String,
    scopes: u64,
    key: Option<SigningKey>,
}
fn mode(p: &Pending) -> Result<String> {
    let packet: request::Packet = serde_json::from_slice(&crypto::bytes(
        &p.record.request_packet_base64,
        linking::MAX_OBJECT,
    )?)?;
    let payload: Value = serde_json::from_slice(&crypto::bytes(
        &packet.payload_base64,
        linking::MAX_PAYLOAD,
    )?)?;
    Ok(payload["mode"]
        .as_str()
        .ok_or_else(|| Failure::new("invalid", &p.request_id, "request"))?
        .into())
}
async fn open(store: Arc<Store>, n: &Network, code: &str) -> Result<String> {
    let secret = crypto::parse_code(code).map_err(|_| Failure::new("invalid", "-", "code"))?;
    let at = support::now()?;
    if transport::recent_poll(
        &store,
        &n.coordinator_public_key,
        &crypto::locator(&secret),
        at,
    )? {
        let (run, network) = (store.clone(), n.clone());
        let known = tokio::task::spawn_blocking(move || -> Result<Option<String>> {
            let c = run.connection()?;
            let ids = c
                .prepare("SELECT request_id FROM link_pending WHERE role='approver' AND secret=?1")?
                .query_map([secret.as_slice()], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ensure!(
                ids.len() <= 1,
                Failure::new("state_conflict", "-", "request")
            );
            let Some(id) = ids.first() else {
                return Ok(None);
            };
            let p = persistence::pending(&c, id)?
                .ok_or_else(|| Failure::new("state_conflict", id, "request"))?;
            let descriptor: Descriptor = linking::decode_mutation(
                &crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)?,
                "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
            )?;
            ensure!(
                descriptor.network_id == network.id,
                Failure::new("invalid", id, "review")
            );
            ensure!(
                p.role == "approver"
                    && p.secret == Some(secret)
                    && p.record.coordinator_address == network.coordinator_address
                    && p.record.coordinator_public_key == network.coordinator_public_key,
                Failure::new("state_conflict", id, "request")
            );
            ensure!(
                at < support::stamp(&p.deadline)?,
                Failure::new("expired", id, "request")
            );
            Ok(Some(p.request_id))
        })
        .await??;
        if let Some(id) = known {
            return Ok(id);
        }
    }
    transport::poll_slot(&store, &n.coordinator_public_key, &crypto::locator(&secret)).await?;
    let raw = transport::request(
        store.clone(),
        &n.coordinator_address,
        &n.coordinator_public_key,
        Method::GET,
        &format!(
            "/coord/v2/link-mailboxes/{}?after=0",
            crypto::locator(&secret)
        ),
        Vec::new(),
    )
    .await?;
    let mailbox = transport::decode_mailbox(&raw)?;
    let polled_at = support::now()?;
    let n = n.clone();
    let (id, retained) = tokio::task::spawn_blocking(move||->Result<(String, bool)>{
        let at=support::now()?;ensure!(mailbox.locator==crypto::locator(&secret)&&mailbox.state=="open"&&at<support::stamp(&mailbox.expires_at)?&&mailbox.frames.len()<=64,Failure::new("expired",&mailbox.request_id,"request"));
        let mut c=store.connection()?;let tx=c.transaction()?;
        if let Some(mut old)=persistence::pending(&tx,&mailbox.request_id)? {
            ensure!(old.role=="approver"&&old.secret==Some(secret)&&old.record.coordinator_address==n.coordinator_address&&old.record.coordinator_public_key==n.coordinator_public_key,Failure::new("state_conflict",&mailbox.request_id,"request"));
            let mut retained=false;for frame in mailbox.frames {retained |= persistence::store_frame(&tx,&frame.frame,&frame.frame_bytes)?;old.record.after_sequence=old.record.after_sequence.max(frame.sequence);}persistence::save_pending(&tx,&old)?;tx.commit()?;transport::record_poll(&store,&n.coordinator_public_key,&crypto::locator(&secret),polled_at)?;return Ok((old.request_id,retained));
        }
        let mut pending=None;
        for row in &mailbox.frames {
            if row.frame.role!="request"{continue;}
            let plain:Plain=linking::decode_mutation(&crypto::open(&secret,&n.coordinator_public_key,&row.frame)?,"request_id role writer_public_key packet catalog")?;
            ensure!(plain.request_id==mailbox.request_id&&plain.role=="request"&&plain.writer_public_key==row.frame.writer_public_key&&row.frame.request_id==mailbox.request_id&&plain.catalog.get()=="\"-\"",Failure::new("invalid",&mailbox.request_id,"request"));
            let packet:request::Packet=linking::decode_mutation(plain.packet.get().as_bytes(),"format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature")?;
            let payload=crypto::bytes(&packet.payload_base64,linking::MAX_PAYLOAD)?;let payload:Value=serde_json::from_slice(&payload)?;
            let get=|field:&str|payload[field].as_str().ok_or_else(||Failure::new("invalid",&mailbox.request_id,"request"));
            let(host,device,nonce)=(get("host_public_key")?,get("device_public_key")?,get("request_nonce")?);
            linking::read("packet",plain.packet.get().as_bytes(),host,device)?;
            ensure!(packet.request_id==mailbox.request_id&&packet.role=="request"&&packet.writer_public_key==plain.writer_public_key&&host!=store.identity().public_key&&get("coordinator_address")?==n.coordinator_address&&get("coordinator_public_key")?==n.coordinator_public_key&&get("expires_at")?==mailbox.expires_at&&get("created_at")?==mailbox.created_at&&(get("expected_network_id")?=="-"||get("expected_network_id")?==n.id),Failure::new("invalid",&mailbox.request_id,"request"));
            let created=support::stamp(get("created_at")?)?;ensure!(created<=at&&support::stamp(&mailbox.expires_at)?-created==chrono::Duration::seconds(300)&&mailbox.request_id==format!("link_{}",crypto::hash(["peerspan-link-request-id-v1",&n.coordinator_public_key,host,device,nonce].join("\n").as_bytes())),Failure::new("invalid",&mailbox.request_id,"request"));
            let p=Pending{request_id:mailbox.request_id.clone(),role:"approver".into(),state:"review".into(),deadline:mailbox.expires_at.clone(),secret:Some(secret),record:PendingRecord{network_base64:STANDARD.encode(catalog::descriptor(&n)?),expected_network_id:get("expected_network_id")?.into(),expected_person_public_key:get("expected_person_public_key")?.into(),coordinator_address:n.coordinator_address.clone(),coordinator_public_key:n.coordinator_public_key.clone(),host_public_key:host.into(),device_public_key:device.into(),request_nonce:nonce.into(),request_packet_base64:STANDARD.encode(plain.packet.get().as_bytes()),catalog_base64:STANDARD.encode(catalog::read(&tx,&n.id)?),..PendingRecord::default()}};
            ensure!(pending.is_none(),Failure::new("operation_conflict",&mailbox.request_id,"request"));pending=Some(p);
        }
        let mut p=pending.ok_or_else(||Failure::new("proof_required",&mailbox.request_id,"request"))?;
        let mut retained=false;for frame in mailbox.frames {retained |= persistence::store_frame(&tx,&frame.frame,&frame.frame_bytes)?;p.record.after_sequence=p.record.after_sequence.max(frame.sequence);}persistence::save_pending(&tx,&p)?;tx.commit()?;transport::record_poll(&store,&n.coordinator_public_key,&crypto::locator(&secret),polled_at)?;Ok((p.request_id,retained))
    }).await??;
    if retained {
        support::barrier("host.frame.after_commit", &id, std::future::pending()).await?;
    }
    Ok(id)
}
fn projection(store: &Store, c: &Connection, p: &mut Pending) -> Result<catalog::Projection> {
    let descriptor = crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)?;
    let d: Descriptor = linking::decode_mutation(
        &descriptor,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    let n = store.network_record(c, &d.network_id)?;
    ensure!(
        n.coordinator_address == p.record.coordinator_address
            && n.coordinator_public_key == p.record.coordinator_public_key,
        Failure::new("state_conflict", &p.request_id, "coordinator")
    );
    let old = crypto::bytes(&p.record.catalog_base64, 16 << 20)?;
    let live = catalog::read(c, &n.id)?;
    let mut all = vec![old, live];
    for frame in ceremony::frames(c, p)? {
        if let Some(catalog) = frame.catalog {
            all.push(catalog);
        }
    }
    let refs: Vec<_> = all.iter().map(Vec::as_slice).collect();
    let merged = catalog::merge(&n.id, &refs)?;
    let verified = catalog::verify(c, &n, &merged, support::now()?)?;
    p.record.catalog_base64 = STANDARD.encode(merged);
    Ok(verified)
}
fn resolve(
    store: &Store,
    c: &Connection,
    p: &catalog::Projection,
    requested: &str,
    admin: bool,
    mode: &str,
) -> Result<Choice> {
    let root = || -> Result<Choice> {
        ensure!(admin, Failure::new("forbidden", "-", "signer"));
        let key = store.current_root(c, &p.network.facts.network_id).ok();
        if let Some(key) = &key {
            ensure!(
                STANDARD.encode(key.verifying_key().as_bytes()) == p.network.root_public_key,
                Failure::new("forbidden", "-", "root")
            );
        }
        Ok(Choice {
            person: "-".into(),
            certificate: "network_root".into(),
            public: p.network.root_public_key.clone(),
            not_after: "-".into(),
            scopes: 15,
            key,
        })
    };
    if requested == "network_root" {
        return root();
    }
    let person = p
        .network
        .facts
        .state
        .bindings
        .get(&store.identity().public_key)
        .filter(|p| crypto::public_key(p));
    let Some(person) = person else {
        if admin && requested == "auto" {
            return root();
        }
        return Err(Failure::new("proof_required", "-", "person").into());
    };
    let required = if admin {
        8
    } else if mode == "renew" {
        4
    } else {
        6
    };
    if requested == "auto" || crypto::id(requested, "dc_") {
        match provider::device(c, p, &p.network.facts.network_id, requested, Some(required)) {
            Ok(device) => {
                return Ok(Choice {
                    person: device.person,
                    certificate: device.certificate,
                    public: device.path.signer_public_key,
                    not_after: device.path.not_after,
                    scopes: device.path.scopes,
                    key: Some(device.key),
                });
            }
            Err(e)
                if requested == "auto"
                    && e.downcast_ref::<Failure>()
                        .is_some_and(|f| f.code == "not_found") =>
            {
                if admin
                    && let Ok(root) = root()
                    && root.key.is_some()
                {
                    return Ok(root);
                }
            }
            Err(e) => return Err(e),
        }
    } else {
        ensure!(
            requested == "person_root",
            Failure::new("invalid", "-", "signer")
        );
    }
    let path = linking::evaluate_path(
        &p.network.facts.state,
        person,
        "root",
        required,
        support::now()?,
    )?;
    Ok(Choice {
        person: person.clone(),
        certificate: "root".into(),
        public: person.clone(),
        not_after: path.not_after,
        scopes: path.scopes,
        key: None,
    })
}
fn context<'a>(
    p: &'a Pending,
    projection: &'a catalog::Projection,
) -> linking::ActivationContext<'a> {
    linking::ActivationContext {
        network: &projection.descriptor,
        epoch: projection.network.epoch,
        known_feature_id: &projection.network.facts.feature_id,
        caller_host_public_key: &p.record.host_public_key,
        expected_person_public_key: &p.record.expected_person_public_key,
        now: support::now().expect("UTC clock"),
        verification: "first",
    }
}
fn selected_owner(
    c: &Connection,
    p: &mut Pending,
    v: &catalog::Projection,
) -> Result<linking::SelectionEvidence> {
    let req = crypto::bytes(&p.record.request_packet_base64, linking::MAX_OBJECT)?;
    if p.record.selection_packet_base64 != "-" {
        return linking::verify_stored_selection(
            context(p, v),
            &v.catalog,
            &req,
            &crypto::bytes(&p.record.owner_packet_base64, linking::MAX_OBJECT)?,
            &crypto::bytes(&p.record.selection_packet_base64, linking::MAX_OBJECT)?,
        );
    }
    let frames = ceremony::frames(c, p)?;
    let mut candidates = BTreeMap::new();
    for owner in frames
        .iter()
        .filter(|f| f.role == "owner" && !f.packet.is_empty())
    {
        for selection in frames
            .iter()
            .filter(|f| f.role == "selection" && !f.packet.is_empty())
        {
            if let Ok(e) = linking::verify_stored_selection(
                context(p, v),
                &v.catalog,
                &req,
                &owner.packet,
                &selection.packet,
            ) {
                if p.record.owner_offer_id != "-"
                    && p.record.owner_offer_id != e.owner.owner_offer_id
                {
                    continue;
                }
                candidates.insert(
                    e.selection_id.clone(),
                    (e, owner.packet.clone(), selection.packet.clone()),
                );
            }
        }
    }
    let (e, owner, selection) = candidates
        .into_values()
        .next()
        .ok_or_else(|| Failure::new("proof_required", &p.request_id, "selection"))?;
    p.record.owner_packet_base64 = STANDARD.encode(owner);
    p.record.owner_offer_id = e.owner.owner_offer_id.clone();
    p.record.selection_packet_base64 = STANDARD.encode(selection);
    p.record.selection_id = e.selection_id.clone();
    Ok(e)
}
fn pins(input: &Approve, person: &str, p: &Pending) -> Result<()> {
    let id = crate::persons::person_id_of(person)?;
    ensure!(
        (input.expected_person_id == "-" || input.expected_person_id == id)
            && (input.expected_host_key == "-"
                || input.expected_host_key == p.record.host_public_key)
            && (input.expected_device_key == "-"
                || input.expected_device_key == p.record.device_public_key),
        Failure::new("invalid", &p.request_id, "review")
    );
    ensure!(
        !input.approve
            || (input.expected_person_id == id
                && input.expected_host_key == p.record.host_public_key
                && input.expected_device_key == p.record.device_public_key),
        Failure::new("invalid", &p.request_id, "consent")
    );
    Ok(())
}
fn templates(
    p: &Pending,
    v: &catalog::Projection,
    s: &Choice,
    owner: Option<&linking::SelectionEvidence>,
    admin: bool,
) -> Result<Intent> {
    let at = support::now()?;
    let issued = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut i = Intent {
        format: 1,
        approved: false,
        epoch: v.network.epoch,
        feature_id: v.network.facts.feature_id.clone(),
        person_public_key: s.person.clone(),
        certificate_id: s.certificate.clone(),
        signer_public_key: s.public.clone(),
        scopes: s.scopes,
        issued_at: issued.clone(),
        not_after: s.not_after.clone(),
        certificate_template_base64: "-".into(),
        record_template_base64: "-".into(),
        packet_template_base64: "-".into(),
        signatures: Vec::new(),
    };
    if admin {
        let target_person = owner
            .map(|o| o.owner.person_public_key.as_str())
            .unwrap_or(&s.person);
        let target_host = owner
            .map(|o| o.owner.host_public_key.as_str())
            .unwrap_or(&p.record.host_public_key);
        let target_network = v.network.facts.network_id.as_str();
        i.scopes = 8;
        let label = v
            .network
            .facts
            .person_labels
            .get(target_person)
            .ok_or_else(|| Failure::new("proof_required", &p.request_id, "person"))?;
        let payload = crypto::json(
            &json!({"network_id":target_network,"epoch":i.epoch,"host_public_key":target_host,"member":label,"admitted_at":issued}),
        )?;
        let mut record = json!({"format":1,"kind":"peerspan-host-admit-v1","network_id":target_network,"epoch":i.epoch,"operation_id":p.request_id,"payload_base64":STANDARD.encode(payload),"signature":"-"});
        if s.certificate != "network_root" {
            record["person_public_key"] = json!(s.person);
            record["certificate_id"] = json!(s.certificate);
            record["host_signature"] = json!("-");
        }
        i.record_template_base64 = STANDARD.encode(crypto::json(&record)?);
        i.signatures = vec![
            Signature {
                object_type: "admission_authorization".into(),
                signature: "-".into(),
            },
            Signature {
                object_type: "administrator_packet".into(),
                signature: "-".into(),
            },
        ];
        return Ok(i);
    }
    ensure!(
        !v.network
            .facts
            .state
            .revoked_devices
            .contains(&linking::DeviceKey {
                person_public_key: s.person.clone(),
                device_public_key: p.record.device_public_key.clone()
            }),
        Failure::new("device_revoked", &p.request_id, "certificate")
    );
    let mode = mode(p)?;
    if mode == "new" {
        ensure!(
            !v.network
                .facts
                .state
                .hosts
                .contains_key(&p.record.host_public_key),
            Failure::new("state_conflict", &p.request_id, "host")
        );
    } else {
        ensure!(
            v.network.facts.state.hosts.get(&p.record.host_public_key) == Some(&true)
                && v.network
                    .facts
                    .state
                    .bindings
                    .get(&p.record.host_public_key)
                    == Some(&s.person),
            Failure::new("forbidden", &p.request_id, "renewal")
        );
    }
    ensure!(
        s.public != p.record.device_public_key,
        Failure::new("forbidden", &p.request_id, "certificate")
    );
    let mut until = at + chrono::Duration::days(90);
    if s.not_after != "-" {
        until = until.min(support::stamp(&s.not_after)?);
    }
    i.not_after = until.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let cert = crypto::json(
        &json!({"format":1,"network_id":v.network.facts.network_id,"person_public_key":s.person,"device_public_key":p.record.device_public_key,"host_public_key":p.record.host_public_key,"parent_id":s.certificate,"scopes":s.scopes,"issued_at":issued,"not_after":i.not_after,"request_id":p.request_id,"signature":"-"}),
    )?;
    i.certificate_template_base64 = STANDARD.encode(cert);
    i.signatures.push(Signature {
        object_type: "certificate".into(),
        signature: "-".into(),
    });
    if mode == "new" {
        let payload = crypto::json(
            &json!({"network_id":v.network.facts.network_id,"person_public_key":s.person,"host_public_key":p.record.host_public_key,"bound_at":issued}),
        )?;
        let record = crypto::json(
            &json!({"format":1,"kind":"peerspan-host-bind-v1","network_id":v.network.facts.network_id,"epoch":i.epoch,"operation_id":p.request_id,"person_public_key":s.person,"certificate_id":s.certificate,"payload_base64":STANDARD.encode(payload),"signature":"-","host_signature":"-"}),
        )?;
        i.record_template_base64 = STANDARD.encode(record);
        i.signatures.push(Signature {
            object_type: "binding_authorization".into(),
            signature: "-".into(),
        });
    }
    i.signatures.push(Signature {
        object_type: "owner_packet".into(),
        signature: "-".into(),
    });
    Ok(i)
}
fn signed_template(encoded: &str, signature: &str) -> Result<Vec<u8>> {
    let raw = crypto::bytes(encoded, linking::MAX_OBJECT)?;
    let mut fields: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(&raw)?;
    fields.insert(
        "signature".into(),
        serde_json::from_slice(&serde_json::to_vec(signature)?)?,
    );
    Ok(serde_json::to_vec(&fields)?)
}
fn slot<'a>(i: &'a Intent, kind: &str) -> &'a str {
    i.signatures
        .iter()
        .find(|s| s.object_type == kind)
        .map(|s| s.signature.as_str())
        .unwrap_or("-")
}
fn message(raw: &[u8], kind: &str) -> Result<Vec<u8>> {
    let o: Value = serde_json::from_slice(raw)?;
    let s = |name: &str| {
        o[name]
            .as_str()
            .ok_or_else(|| Failure::new("invalid", "-", "intent"))
    };
    let parts: Vec<String> = if kind == "certificate" {
        vec![
            "peerspan-device-certificate-v1".into(),
            s("network_id")?.into(),
            s("person_public_key")?.into(),
            s("device_public_key")?.into(),
            s("host_public_key")?.into(),
            s("parent_id")?.into(),
            o["scopes"]
                .as_u64()
                .ok_or_else(|| Failure::new("invalid", "-", "intent"))?
                .to_string(),
            s("issued_at")?.into(),
            s("not_after")?.into(),
            s("request_id")?.into(),
        ]
    } else if kind.ends_with("_packet") {
        vec![
            "peerspan-link-packet-v1".into(),
            s("request_id")?.into(),
            s("role")?.into(),
            s("writer_public_key")?.into(),
            s("person_public_key")?.into(),
            s("certificate_id")?.into(),
            crypto::hash(&crypto::bytes(s("payload_base64")?, linking::MAX_PAYLOAD)?),
        ]
    } else {
        let mut parts = vec![
            if o.get("person_public_key").is_some() {
                "peerspan-person-authorization-v1"
            } else {
                "peerspan-root-authorization-v1"
            }
            .into(),
            s("kind")?.into(),
            s("network_id")?.into(),
            o["epoch"]
                .as_u64()
                .ok_or_else(|| Failure::new("invalid", "-", "intent"))?
                .to_string(),
            s("operation_id")?.into(),
        ];
        if o.get("person_public_key").is_some() {
            parts.push(s("person_public_key")?.into());
            parts.push(s("certificate_id")?.into());
        }
        parts.push(crypto::hash(&crypto::bytes(
            s("payload_base64")?,
            linking::MAX_PAYLOAD,
        )?));
        parts
    };
    Ok(parts.join("\n").into_bytes())
}
fn next(
    p: &Pending,
    i: &mut Intent,
    admin: bool,
    v: &catalog::Projection,
    root_ssh: bool,
    materialize: bool,
) -> Result<Option<SigningRequest>> {
    if !i.approved || admin && p.record.selection_packet_base64 == "-" {
        return Ok(None);
    }
    let Some(kind) = i
        .signatures
        .iter()
        .find(|s| s.signature == "-")
        .map(|s| s.object_type.clone())
    else {
        return Ok(None);
    };
    let template = if kind == "certificate" {
        crypto::bytes(&i.certificate_template_base64, linking::MAX_OBJECT)?
    } else if kind.ends_with("_authorization") {
        crypto::bytes(&i.record_template_base64, linking::MAX_OBJECT)?
    } else {
        if i.packet_template_base64 == "-" {
            if !materialize {
                return Ok(None);
            }
            let payload = if admin {
                crypto::raw_object(vec![
                    (
                        "owner_offer_id",
                        serde_json::to_vec(&p.record.owner_offer_id)?,
                    ),
                    ("selection_id", serde_json::to_vec(&p.record.selection_id)?),
                    (
                        "admission_record",
                        signed_template(
                            &i.record_template_base64,
                            slot(i, "admission_authorization"),
                        )?,
                    ),
                ])?
            } else {
                let (mut membership, mut binding) = ("-".to_owned(), "-".to_owned());
                if mode(p)? == "renew" {
                    let row = v
                        .network
                        .members
                        .iter()
                        .find(|m| {
                            m.host_public_key == p.record.host_public_key
                                && m.person_public_key == i.person_public_key
                        })
                        .ok_or_else(|| Failure::new("proof_required", &p.request_id, "renewal"))?;
                    membership = row.membership_proof_id.clone();
                    binding = row.binding_proof_id.clone();
                    ensure!(
                        binding != "-",
                        Failure::new("proof_required", &p.request_id, "renewal")
                    );
                }
                let req = crypto::bytes(&p.record.request_packet_base64, linking::MAX_OBJECT)?;
                let req = linking::read(
                    "packet",
                    &req,
                    &p.record.host_public_key,
                    &p.record.device_public_key,
                )?;
                crypto::raw_object(vec![
                    ("request_packet_id", serde_json::to_vec(&req.id)?),
                    (
                        "network",
                        crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)?,
                    ),
                    ("epoch", serde_json::to_vec(&i.epoch)?),
                    ("feature_id", serde_json::to_vec(&i.feature_id)?),
                    (
                        "person_public_key",
                        serde_json::to_vec(&i.person_public_key)?,
                    ),
                    (
                        "certificate",
                        signed_template(&i.certificate_template_base64, slot(i, "certificate"))?,
                    ),
                    (
                        "binding_record",
                        if i.record_template_base64 == "-" {
                            b"\"-\"".to_vec()
                        } else {
                            signed_template(
                                &i.record_template_base64,
                                slot(i, "binding_authorization"),
                            )?
                        },
                    ),
                    ("membership_proof_id", serde_json::to_vec(&membership)?),
                    ("binding_proof_id", serde_json::to_vec(&binding)?),
                ])?
            };
            let packet = request::Packet {
                format: 1,
                request_id: p.request_id.clone(),
                role: if admin { "administrator" } else { "owner" }.into(),
                writer_public_key: i.signer_public_key.clone(),
                person_public_key: i.person_public_key.clone(),
                certificate_id: i.certificate_id.clone(),
                payload_base64: STANDARD.encode(payload),
                host_signature: "-".into(),
                device_signature: "-".into(),
                authority_signature: "-".into(),
            };
            i.packet_template_base64 = STANDARD.encode(crypto::json(&packet)?);
        }
        crypto::bytes(&i.packet_template_base64, linking::MAX_OBJECT)?
    };
    Ok(Some(SigningRequest {
        object_type: kind.clone(),
        message_base64: STANDARD.encode(message(&template, &kind)?),
        signer_public_key: i.signer_public_key.clone(),
        signature_format: if i.certificate_id == "network_root" && !root_ssh {
            "ed25519"
        } else {
            "sshsig"
        }
        .into(),
    }))
}
fn verify_signature(request: &SigningRequest, signature: &str) -> Result<()> {
    let message = crypto::bytes(&request.message_base64, linking::MAX_OBJECT)?;
    if request.signature_format == "sshsig" {
        crate::persons::verify_sshsig(
            &request.signer_public_key,
            &std::str::from_utf8(&message)?
                .split('\n')
                .collect::<Vec<_>>(),
            signature,
        )?;
    } else {
        let key: [u8; 32] = crypto::bytes(&request.signer_public_key, 32)?
            .try_into()
            .map_err(|_| Failure::new("invalid", "-", "signature"))?;
        let sig: [u8; 64] = crypto::bytes(signature, 64)?
            .try_into()
            .map_err(|_| Failure::new("invalid", "-", "signature"))?;
        VerifyingKey::from_bytes(&key)?
            .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))?;
    }
    Ok(())
}
fn live_key(
    store: &Store,
    c: &Connection,
    p: &Pending,
    i: &Intent,
    admin: bool,
    v: &catalog::Projection,
) -> Result<Option<SigningKey>> {
    ensure!(
        support::now()? < support::stamp(&p.deadline)?
            && i.epoch == v.network.epoch
            && i.feature_id == v.network.facts.feature_id,
        Failure::new("state_conflict", &p.request_id, "authority")
    );
    if i.certificate_id == "network_root" {
        ensure!(
            admin && i.signer_public_key == v.network.root_public_key,
            Failure::new("forbidden", &p.request_id, "root")
        );
        let root = store.current_root(c, &v.network.facts.network_id).ok();
        if let Some(key) = &root {
            ensure!(
                STANDARD.encode(key.verifying_key().as_bytes()) == v.network.root_public_key,
                Failure::new("forbidden", &p.request_id, "root")
            );
        }
        return Ok(root);
    }
    let mask = if admin {
        8
    } else if mode(p)? == "renew" {
        4
    } else {
        6
    };
    let path = linking::evaluate_path(
        &v.network.facts.state,
        &i.person_public_key,
        &i.certificate_id,
        mask,
        support::now()?,
    )?;
    ensure!(
        path.signer_public_key == i.signer_public_key,
        Failure::new("forbidden", &p.request_id, "signer")
    );
    if !admin {
        ensure!(
            !v.network
                .facts
                .state
                .revoked_devices
                .contains(&linking::DeviceKey {
                    person_public_key: i.person_public_key.clone(),
                    device_public_key: p.record.device_public_key.clone()
                }),
            Failure::new("device_revoked", &p.request_id, "certificate")
        );
        if mode(p)? == "new" {
            ensure!(
                !v.network
                    .facts
                    .state
                    .hosts
                    .contains_key(&p.record.host_public_key),
                Failure::new("state_conflict", &p.request_id, "host")
            );
        } else {
            ensure!(
                v.network.facts.state.hosts.get(&p.record.host_public_key) == Some(&true)
                    && v.network
                        .facts
                        .state
                        .bindings
                        .get(&p.record.host_public_key)
                        == Some(&i.person_public_key),
                Failure::new("forbidden", &p.request_id, "renewal")
            );
        }
    }
    if i.certificate_id == "root" {
        Ok(None)
    } else {
        Ok(Some(persistence::device(c, &i.signer_public_key)?))
    }
}
fn save_intent(p: &mut Pending, i: &Intent, admin: bool) {
    if admin {
        p.record.administrator_intent = IntentValue(Some(i.clone()));
    } else {
        p.record.owner_intent = IntentValue(Some(i.clone()));
    }
}
fn advance(
    store: &Store,
    tx: &Transaction<'_>,
    p: &mut Pending,
    admin: bool,
    external: Option<Signed>,
    v: &catalog::Projection,
) -> Result<()> {
    let mut i = if admin {
        p.record.administrator_intent.0.clone()
    } else {
        p.record.owner_intent.0.clone()
    }
    .ok_or_else(|| Failure::new("proof_required", &p.request_id, "intent"))?;
    ensure!(
        i.approved,
        Failure::new("forbidden", &p.request_id, "consent")
    );
    let mut external = external;
    if let Some(signed) = &external {
        let prior = i
            .signatures
            .iter()
            .find(|s| s.object_type == signed.object_type)
            .ok_or_else(|| Failure::new("invalid", &p.request_id, "signature"))?;
        if prior.signature != "-" {
            ensure!(
                prior.signature == signed.signature,
                Failure::new("operation_conflict", &p.request_id, "signature")
            );
            external = None;
        }
    }
    loop {
        let Some(request) = next(
            p,
            &mut i,
            admin,
            v,
            store
                .network_record(tx, &v.network.facts.network_id)?
                .root_ssh,
            true,
        )?
        else {
            break;
        };
        save_intent(p, &i, admin);
        persistence::save_pending(tx, p)?;
        let key = live_key(store, tx, p, &i, admin, v)?;
        let signature = if let Some(signed) = external.take() {
            ensure!(
                signed.object_type == request.object_type,
                Failure::new("operation_conflict", &p.request_id, "signature")
            );
            signed.signature
        } else if let Some(key) = key {
            let msg = crypto::bytes(&request.message_base64, linking::MAX_OBJECT)?;
            if request.signature_format == "ed25519" {
                STANDARD.encode(key.sign(&msg).to_bytes())
            } else {
                PersonSigner::File(key)
                    .sign(&std::str::from_utf8(&msg)?.split('\n').collect::<Vec<_>>())?
            }
        } else {
            break;
        };
        verify_signature(&request, &signature)
            .map_err(|_| Failure::new("invalid", &p.request_id, "signature"))?;
        i.signatures
            .iter_mut()
            .find(|s| s.object_type == request.object_type)
            .expect("ready slot")
            .signature = signature;
        save_intent(p, &i, admin);
        persistence::save_pending(tx, p)?;
    }
    if i.signatures.iter().all(|s| s.signature != "-") {
        // Completed immutable offers are replayed from their existing frames;
        // resuming status never regenerates or revalidates a past signature.
        if if admin {
            p.record.administrator_packet_base64 != "-"
        } else {
            p.record.owner_packet_base64 != "-"
        } {
            return Ok(());
        }
        let mut packet: request::Packet = serde_json::from_slice(&crypto::bytes(
            &i.packet_template_base64,
            linking::MAX_OBJECT,
        )?)?;
        packet.authority_signature = slot(
            &i,
            if admin {
                "administrator_packet"
            } else {
                "owner_packet"
            },
        )
        .into();
        let raw = crypto::json(&packet)?;
        let proof = linking::read("packet", &raw, &i.signer_public_key, "-")?;
        let req = crypto::bytes(&p.record.request_packet_base64, linking::MAX_OBJECT)?;
        if admin {
            linking::verify_stored_administrator_offer(
                context(p, v),
                &v.catalog,
                &req,
                &crypto::bytes(&p.record.owner_packet_base64, linking::MAX_OBJECT)?,
                &crypto::bytes(&p.record.selection_packet_base64, linking::MAX_OBJECT)?,
                &raw,
            )?;
            if p.record.administrator_packet_base64 == "-" {
                p.record.administrator_packet_base64 = STANDARD.encode(&raw);
                p.record.administrator_offer_id = proof.id;
                let selected = linking::select_stored_proof_catalog(
                    linking::CatalogFactContext {
                        network: &v.descriptor,
                        epoch: v.network.epoch,
                        known_feature_id: &v.network.facts.feature_id,
                        now: support::now()?,
                    },
                    &v.catalog,
                    &[linking::ProofSeed {
                        kind: "packet".into(),
                        body: raw.clone(),
                    }],
                )?;
                ceremony::outbound(tx, p, "administrator", &raw, Some(&selected))?;
            }
        } else {
            linking::verify_stored_owner_offer(context(p, v), &v.catalog, &req, &raw)?;
            if p.record.owner_packet_base64 == "-" {
                p.record.owner_packet_base64 = STANDARD.encode(&raw);
                p.record.owner_offer_id = proof.id;
                let selected = linking::select_stored_proof_catalog(
                    linking::CatalogFactContext {
                        network: &v.descriptor,
                        epoch: v.network.epoch,
                        known_feature_id: &v.network.facts.feature_id,
                        now: support::now()?,
                    },
                    &v.catalog,
                    &[linking::ProofSeed {
                        kind: "packet".into(),
                        body: raw.clone(),
                    }],
                )?;
                ceremony::outbound(tx, p, "owner", &raw, Some(&selected))?;
            }
        }
        p.state = "offer_sent".into();
        persistence::save_pending(tx, p)?;
    }
    Ok(())
}
fn result(store: &Store, p: &Pending, admin: bool, v: &catalog::Projection) -> Result<Value> {
    let mut i = if admin {
        p.record.administrator_intent.0.clone()
    } else {
        p.record.owner_intent.0.clone()
    }
    .ok_or_else(|| Failure::new("proof_required", &p.request_id, "intent"))?;
    let person = if admin {
        let owner: request::Packet = serde_json::from_slice(&crypto::bytes(
            &p.record.owner_packet_base64,
            linking::MAX_OBJECT,
        )?)?;
        owner.person_public_key
    } else {
        i.person_public_key.clone()
    };
    let requests = next(
        p,
        &mut i,
        admin,
        v,
        store.network(&v.network.facts.network_id)?.root_ssh,
        false,
    )?
    .into_iter()
    .collect::<Vec<_>>();
    Ok(
        json!({"request":request::view(store,p)?,"review":{"network_id":v.network.facts.network_id,"person_id":crate::persons::person_id_of(&person)?,"host_public_key":p.record.host_public_key,"device_public_key":p.record.device_public_key,"scopes":i.scopes,"not_after":i.not_after,"signer_public_key":i.signer_public_key,"authority_warning":if i.scopes&8!=0{"This device can manage access, trust itself and approve more machines when the person is an administrator."}else{"-"}},"signing_requests":requests}),
    )
}
fn review(
    store: &Store,
    id: &str,
    input: Approve,
    admin: bool,
    external: Option<Signed>,
) -> Result<Value> {
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let mut p =
        persistence::pending(&tx, id)?.ok_or_else(|| Failure::new("not_found", id, "request"))?;
    let v = projection(store, &tx, &mut p)?;
    ensure!(
        input.network_id == v.network.facts.network_id,
        Failure::new("invalid", id, "review")
    );
    let mode = mode(&p)?;
    let owner = if admin {
        ensure!(mode == "new", Failure::new("invalid", id, "administrator"));
        Some(selected_owner(&tx, &mut p, &v)?)
    } else {
        None
    };
    let prior = if admin {
        p.record.administrator_intent.0.as_ref()
    } else {
        p.record.owner_intent.0.as_ref()
    };
    if let Some(i) = prior {
        let person = if let Some(owner) = &owner {
            &owner.owner.person_public_key
        } else {
            &i.person_public_key
        };
        pins(&input, person, &p)?;
        ensure!(
            input.signer == "auto"
                || input.signer == i.certificate_id
                || input.signer == "person_root" && i.certificate_id == "root",
            Failure::new("state_conflict", id, "signer")
        );
    } else {
        let choice = resolve(store, &tx, &v, &input.signer, admin, &mode)?;
        let person = if let Some(owner) = &owner {
            &owner.owner.person_public_key
        } else {
            &choice.person
        };
        ensure!(
            p.record.expected_person_public_key == "-"
                || p.record.expected_person_public_key == *person,
            Failure::new("invalid", id, "person")
        );
        pins(&input, person, &p)?;
        let intent = templates(&p, &v, &choice, owner.as_ref(), admin)?;
        save_intent(&mut p, &intent, admin);
        if !admin
            && mode == "new"
            && choice.scopes & 8 != 0
            && v.network
                .facts
                .state
                .persons
                .get(&choice.person)
                .is_some_and(|person| person.administrator)
            && linking::evaluate_path(
                &v.network.facts.state,
                &choice.person,
                &choice.certificate,
                8,
                support::now()?,
            )
            .is_ok()
        {
            let same = templates(&p, &v, &choice, None, true)?;
            save_intent(&mut p, &same, true);
        }
    }
    if input.approve {
        if admin {
            p.record
                .administrator_intent
                .0
                .as_mut()
                .expect("intent")
                .approved = true;
        } else {
            p.record.owner_intent.0.as_mut().expect("intent").approved = true;
            if let (Some(owner), Some(administrator)) = (
                &p.record.owner_intent.0,
                &mut p.record.administrator_intent.0,
            ) {
                ensure!(
                    owner.person_public_key == administrator.person_public_key
                        && owner.certificate_id == administrator.certificate_id
                        && owner.signer_public_key == administrator.signer_public_key,
                    Failure::new("operation_conflict", id, "signer")
                );
                linking::evaluate_path(
                    &v.network.facts.state,
                    &owner.person_public_key,
                    &owner.certificate_id,
                    8,
                    support::now()?,
                )?;
                administrator.approved = true;
            }
        }
    }
    persistence::save_pending(&tx, &p)?;
    if (if admin {
        p.record.administrator_intent.0.as_ref()
    } else {
        p.record.owner_intent.0.as_ref()
    })
    .is_some_and(|i| i.approved)
    {
        advance(store, &tx, &mut p, admin, external, &v)?;
    }
    let saved = p.clone();
    tx.commit()?;
    drop(c);
    result(store, &saved, admin, &v)
}
pub(crate) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/link/approvals", post(owner))
        .route("/v1/link/admissions", post(admin))
        .route("/v1/link/requests/{id}/signed", post(signed))
        .route("/v1/link/requests/{id}/approval", get(approval_view))
}
async fn run(store: Arc<Store>, input: Approve, admin: bool) -> Result<Value, Failure> {
    let _guard = store.link_mutation.lock().await;
    let n = provider::fresh(store.clone(), &input.network_id)
        .await
        .map_err(|e| Failure::cause(e, "-", "sync"))?;
    let id = open(store.clone(), &n, &input.code)
        .await
        .map_err(|e| Failure::cause(e, "-", "request"))?;
    let (run, lookup) = (store.clone(), id.clone());
    let result = tokio::task::spawn_blocking(move || review(&run, &lookup, input, admin, None))
        .await
        .map_err(|_| Failure::new("internal", &id, "storage"))?
        .map_err(|e| Failure::cause(e, &id, "review"))?;
    publish_ready(store.clone(), &id)
        .await
        .map_err(|e| Failure::cause(e, &id, "publish"))?;
    Ok(result)
}
async fn owner(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let input = linking::decode_mutation(
        &body,
        "code network_id expected_person_id expected_host_key expected_device_key signer approve",
    )
    .map_err(|_| Failure::new("invalid", "-", "request"))?;
    run(store, input, false).await.map(Json)
}
async fn admin(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", "-", "request"))?;
    let input = linking::decode_mutation(
        &body,
        "code network_id expected_person_id expected_host_key expected_device_key signer approve",
    )
    .map_err(|_| Failure::new("invalid", "-", "request"))?;
    run(store, input, true).await.map(Json)
}
async fn signed(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", &id, "request"))?;
    let signed: Signed = linking::decode_mutation(&body, "object_type signature")
        .map_err(|_| Failure::new("invalid", &id, "request"))?;
    let _guard = store.link_mutation.lock().await;
    let (run, lookup) = (store.clone(), id.clone());
    let p = tokio::task::spawn_blocking(move || -> Result<Pending> {
        let c = run.connection()?;
        persistence::pending(&c, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request").into())
    })
    .await
    .map_err(|_| Failure::new("internal", &id, "storage"))?
    .map_err(|e| Failure::cause(e, &id, "storage"))?;
    let descriptor: Descriptor = linking::decode_mutation(
        &crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)
            .map_err(|e| Failure::cause(e, &id, "intent"))?,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )
    .map_err(|e| Failure::cause(e, &id, "intent"))?;
    provider::fresh(store.clone(), &descriptor.network_id)
        .await
        .map_err(|e| Failure::cause(e, &id, "sync"))?;
    let admin = signed.object_type == "admission_authorization"
        || signed.object_type == "administrator_packet";
    if !(if admin {
        p.record.administrator_intent.0.as_ref()
    } else {
        p.record.owner_intent.0.as_ref()
    })
    .is_some_and(|i| i.approved)
    {
        return Err(Failure::new("forbidden", &id, "consent"));
    }
    let person = if admin {
        let owner: request::Packet = serde_json::from_slice(
            &crypto::bytes(&p.record.owner_packet_base64, linking::MAX_OBJECT)
                .map_err(|e| Failure::cause(e, &id, "intent"))?,
        )
        .map_err(|_| Failure::new("invalid", &id, "intent"))?;
        owner.person_public_key
    } else {
        p.record
            .owner_intent
            .0
            .as_ref()
            .ok_or_else(|| Failure::new("proof_required", &id, "intent"))?
            .person_public_key
            .clone()
    };
    let input = Approve {
        code: String::new(),
        network_id: descriptor.network_id,
        expected_person_id: crate::persons::person_id_of(&person)
            .map_err(|e| Failure::cause(e.into(), &id, "person"))?,
        expected_host_key: p.record.host_public_key,
        expected_device_key: p.record.device_public_key,
        signer: "auto".into(),
        approve: true,
    };
    let (run, lookup) = (store.clone(), id.clone());
    let result =
        tokio::task::spawn_blocking(move || review(&run, &lookup, input, admin, Some(signed)))
            .await
            .map_err(|_| Failure::new("internal", &id, "storage"))?
            .map_err(|e| Failure::cause(e, &id, "signature"))?;
    publish_ready(store.clone(), &id)
        .await
        .map_err(|e| Failure::cause(e, &id, "publish"))?;
    Ok(Json(result))
}

pub async fn publish_ready(store: Arc<Store>, id: &str) -> Result<()> {
    let (run, lookup) = (store.clone(), id.to_owned());
    let network = tokio::task::spawn_blocking(move || -> Result<Option<String>> {
        let c = run.connection()?;
        let p = persistence::pending(&c, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
        if p.secret.is_none() || !p.record.outbound_frames.iter().any(|f| !f.published) {
            return Ok(None);
        }
        let descriptor: Descriptor = linking::decode_mutation(
            &crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)?,
            "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
        )?;
        Ok(Some(descriptor.network_id))
    })
    .await??;
    let Some(network) = network else {
        return Ok(());
    };
    support::barrier("host.frame.after_commit", id, std::future::pending()).await?;
    provider::fresh(store.clone(), &network).await?;
    let (run, lookup) = (store.clone(), id.to_owned());
    tokio::task::spawn_blocking(move || -> Result<()> {
        let c = run.connection()?;
        let mut p = persistence::pending(&c, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
        let v = projection(&run, &c, &mut p)?;
        for f in p.record.outbound_frames.iter().filter(|f| !f.published) {
            let admin = match f.role.as_str() {
                "owner" => false,
                "administrator" => true,
                _ => continue,
            };
            let i = if admin {
                &p.record.administrator_intent.0
            } else {
                &p.record.owner_intent.0
            };
            let i = i
                .as_ref()
                .filter(|i| i.approved)
                .ok_or_else(|| Failure::new("state_conflict", &lookup, "intent"))?;
            live_key(&run, &c, &p, i, admin, &v)?;
        }
        Ok(())
    })
    .await??;
    transport::publish(store, id).await
}
pub async fn resume_after_poll(store: Arc<Store>, id: &str) -> Result<()> {
    let (run, lookup) = (store.clone(), id.to_owned());
    let network = tokio::task::spawn_blocking(move || -> Result<String> {
        let c = run.connection()?;
        let p = persistence::pending(&c, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
        let d: Descriptor = serde_json::from_slice(&crypto::bytes(
            &p.record.network_base64,
            linking::MAX_OBJECT,
        )?)?;
        Ok(d.network_id)
    })
    .await??;
    provider::fresh(store.clone(), &network).await?;
    let (run, lookup) = (store.clone(), id.to_owned());
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut c = run.connection()?;
        let tx = c.transaction()?;
        let mut p = persistence::pending(&tx, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
        ensure!(
            p.role == "approver",
            Failure::new("state_conflict", &lookup, "intent")
        );
        let v = projection(&run, &tx, &mut p)?;
        if p.record.owner_intent.0.as_ref().is_some_and(|i| i.approved) {
            advance(&run, &tx, &mut p, false, None, &v)?;
        }
        if p.record
            .administrator_intent
            .0
            .as_ref()
            .is_some_and(|i| i.approved)
        {
            match selected_owner(&tx, &mut p, &v) {
                Ok(_) => advance(&run, &tx, &mut p, true, None, &v)?,
                Err(e)
                    if e.downcast_ref::<Failure>()
                        .is_some_and(|f| f.code == "proof_required") => {}
                Err(e) => return Err(e),
            }
        }
        persistence::save_pending(&tx, &p)?;
        tx.commit()?;
        Ok(())
    })
    .await??;
    publish_ready(store, id).await
}
async fn approval_view(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    uri: axum::http::Uri,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    if uri.query().is_some()
        || !body
            .map_err(|_| Failure::new("invalid", &id, "request"))?
            .is_empty()
    {
        return Err(Failure::new("invalid", &id, "request"));
    }
    let lookup = id.clone();
    let value = tokio::task::spawn_blocking(move || -> Result<Value> {
        let c = store.connection()?;
        let mut p = persistence::pending(&c, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
        ensure!(
            p.role == "approver"
                && (p.record.owner_intent.0.as_ref().is_some_and(|i| i.approved)
                    || p.record
                        .administrator_intent
                        .0
                        .as_ref()
                        .is_some_and(|i| i.approved)),
            Failure::new("state_conflict", &lookup, "intent")
        );
        let v = projection(&store, &c, &mut p)?;
        let admin = p
            .record
            .administrator_intent
            .0
            .as_ref()
            .is_some_and(|i| i.approved)
            && p.record.selection_packet_base64 != "-"
            && p.record.owner_packet_base64 != "-";
        let i = if admin {
            p.record.administrator_intent.0.as_ref()
        } else {
            p.record.owner_intent.0.as_ref()
        }
        .ok_or_else(|| Failure::new("state_conflict", &lookup, "intent"))?;
        if i.signatures.iter().any(|s| s.signature == "-") {
            live_key(&store, &c, &p, i, admin, &v)?;
        }
        drop(c);
        result(&store, &p, admin, &v)
    })
    .await
    .map_err(|_| Failure::new("internal", &id, "storage"))?
    .map_err(|e| Failure::cause(e, &id, "intent"))?;
    Ok(Json(value))
}
