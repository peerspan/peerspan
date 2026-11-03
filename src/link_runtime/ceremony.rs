//! Requester consent is explicit and fixes exact independently verified packets.
use super::{
    catalog, crypto,
    map::Descriptor,
    model::{Commit, OutboundFrame, Select},
    persistence::{self, Pending},
    request,
    support::{self, Failure},
};
use crate::{linking, network::Network, store::Store};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use rusqlite::{Connection, Transaction};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plaintext {
    request_id: String,
    role: String,
    writer_public_key: String,
    packet: Box<RawValue>,
    catalog: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFrame {
    frame_base64: String,
}
#[derive(Clone)]
pub(crate) struct Received {
    pub packet: Vec<u8>,
    pub catalog: Option<Vec<u8>>,
    pub role: String,
}
pub(crate) fn frames(c: &Connection, p: &Pending) -> Result<Vec<Received>> {
    let Some(secret) = p.secret else {
        return Ok(Vec::new());
    };
    let rows = {
        let mut q = c.prepare(
            "SELECT record FROM link_frames WHERE request_id=?1 ORDER BY role,writer_key,frame_id",
        )?;
        q.query_map([&p.request_id], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut received = Vec::new();
    for row in rows {
        let read = || -> Result<Received> {
            let stored: StoredFrame = linking::decode_stored_json(row.as_bytes(), "frame_base64")?;
            let raw = crypto::bytes(&stored.frame_base64, 128 << 10)?;
            let frame: crypto::Frame = linking::decode_mutation(
                &raw,
                "format request_id locator role writer_public_key frame_id ciphertext",
            )?;
            ensure!(frame.request_id == p.request_id, "wrong frame request");
            let body = crypto::open(&secret, &p.record.coordinator_public_key, &frame)?;
            let plain: Plaintext = linking::decode_mutation(
                &body,
                "request_id role writer_public_key packet catalog",
            )?;
            ensure!(
                plain.request_id == frame.request_id
                    && plain.role == frame.role
                    && plain.writer_public_key == frame.writer_public_key,
                "wrong frame metadata"
            );
            let packet = if plain.packet.get() == "\"-\"" {
                Vec::new()
            } else {
                plain.packet.get().as_bytes().to_vec()
            };
            let catalog = if plain.catalog.get() == "\"-\"" {
                None
            } else {
                Some(plain.catalog.get().as_bytes().to_vec())
            };
            ensure!(!packet.is_empty() || catalog.is_some(), "empty frame");
            if packet.is_empty() {
                let raw = catalog.as_ref().expect("catalog frame");
                let value: Value = serde_json::from_slice(raw)?;
                let network = value["network_id"]
                    .as_str()
                    .ok_or_else(|| Failure::new("invalid", &p.request_id, "catalog"))?;
                ensure!(
                    !catalog::decode(raw, network)?.objects.is_empty(),
                    "empty catalog frame"
                );
            }
            if !packet.is_empty() {
                let packet: request::Packet = serde_json::from_slice(&packet)?;
                ensure!(
                    packet.request_id == frame.request_id
                        && packet.role == frame.role
                        && packet.writer_public_key == frame.writer_public_key,
                    "wrong packet metadata"
                );
            }
            Ok(Received {
                packet,
                catalog,
                role: plain.role,
            })
        };
        if let Ok(frame) = read() {
            received.push(frame);
        }
    }
    Ok(received)
}
pub(crate) struct Candidate {
    network: Network,
    descriptor: Vec<u8>,
    catalog: Vec<u8>,
    evidence: linking::OwnerOfferEvidence,
    packet: Vec<u8>,
    epoch: u64,
    feature: String,
}
impl Candidate {
    fn context<'a>(
        &'a self,
        p: &'a Pending,
        now: chrono::DateTime<chrono::Utc>,
    ) -> linking::ActivationContext<'a> {
        linking::ActivationContext {
            network: &self.descriptor,
            epoch: self.epoch,
            known_feature_id: &self.feature,
            caller_host_public_key: &p.record.host_public_key,
            expected_person_public_key: &p.record.expected_person_public_key,
            now,
            verification: "first",
        }
    }
}
pub(crate) fn candidate(
    c: &Connection,
    p: &Pending,
    owner: &[u8],
    offered_catalog: &[u8],
) -> Result<Candidate> {
    let packet: request::Packet = linking::decode_mutation(
        owner,
        "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
    )?;
    ensure!(
        packet.role == "owner" && packet.request_id == p.request_id,
        Failure::new("invalid", &p.request_id, "owner")
    );
    let payload = crypto::bytes(&packet.payload_base64, linking::MAX_PAYLOAD)?;
    let fields: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(&payload)?;
    let descriptor = fields
        .get("network")
        .ok_or_else(|| Failure::new("invalid", &p.request_id, "owner"))?
        .get()
        .as_bytes()
        .to_vec();
    let d: Descriptor = linking::decode_mutation(
        &descriptor,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    ensure!(
        d.coordinator_address == p.record.coordinator_address
            && d.coordinator_public_key == p.record.coordinator_public_key
            && (p.record.expected_network_id == "-"
                || p.record.expected_network_id == d.network_id),
        Failure::new("invalid", &p.request_id, "coordinator")
    );
    if p.record.network_base64 != "-" {
        ensure!(
            crypto::bytes(&p.record.network_base64, linking::MAX_OBJECT)? == descriptor,
            Failure::new("operation_conflict", &p.request_id, "owner")
        );
    }
    let network = Network {
        id: d.network_id,
        name: d.name,
        root_public_key: d.genesis_root_public_key,
        member: String::new(),
        coordinator_address: d.coordinator_address,
        coordinator_public_key: d.coordinator_public_key,
        administrator: false,
        last_sync_at: None,
        last_sync_error: None,
        root_epoch: 0,
        current_root_public_key: String::new(),
        root_ssh: false,
        coordinator_pending: None,
    };
    let prior = catalog::read(c, &network.id)?;
    let supplied: Vec<Vec<u8>> = frames(c, p)?
        .into_iter()
        .filter_map(|f| f.catalog)
        .filter(|raw| catalog::decode(raw, &network.id).is_ok())
        .collect();
    let mut pieces = vec![prior.as_slice()];
    if !offered_catalog.is_empty() {
        pieces.push(offered_catalog);
    }
    pieces.extend(supplied.iter().map(Vec::as_slice));
    let retained = if p.record.catalog_base64 != "-" {
        Some(crypto::bytes(&p.record.catalog_base64, 16 << 20)?)
    } else {
        None
    };
    if let Some(raw) = &retained {
        pieces.push(raw);
    }
    let merged = catalog::merge(&network.id, &pieces)?;
    let epoch = catalog::target_epoch(&catalog::decode(&merged, &network.id)?)?;
    let (known, _) = catalog::feature(c, &network.id)?;
    let state = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: &descriptor,
            epoch,
            known_feature_id: &known,
            now: support::now()?,
        },
        &merged,
    )?;
    let feature = state.facts.feature_id;
    let request = crypto::bytes(&p.record.request_packet_base64, linking::MAX_OBJECT)?;
    let evidence = linking::verify_stored_owner_offer(
        linking::ActivationContext {
            network: &descriptor,
            epoch,
            known_feature_id: &feature,
            caller_host_public_key: &p.record.host_public_key,
            expected_person_public_key: &p.record.expected_person_public_key,
            now: support::now()?,
            verification: "first",
        },
        &merged,
        &request,
        owner,
    )?;
    catalog::verify_with_adoption(c, &network, &merged, support::now()?, Some(&feature))?;
    Ok(Candidate {
        network,
        descriptor,
        catalog: merged,
        evidence,
        packet: owner.to_vec(),
        epoch,
        feature,
    })
}
fn choose(c: &Connection, p: &Pending, requested: &str) -> Result<Candidate> {
    let mut choices = BTreeMap::new();
    if p.record.owner_packet_base64 != "-" && p.record.catalog_base64 != "-" {
        let raw = crypto::bytes(&p.record.owner_packet_base64, linking::MAX_OBJECT)?;
        let catalog = crypto::bytes(&p.record.catalog_base64, 16 << 20)?;
        if let Ok(offer) = candidate(c, p, &raw, &catalog) {
            choices.insert(offer.evidence.owner_offer_id.clone(), offer);
        }
    }
    for received in frames(c, p)?
        .into_iter()
        .filter(|f| f.role == "owner" && !f.packet.is_empty())
    {
        if let Ok(offer) = candidate(
            c,
            p,
            &received.packet,
            received.catalog.as_deref().unwrap_or_default(),
        ) {
            choices.insert(offer.evidence.owner_offer_id.clone(), offer);
        }
    }
    if p.record.selection_approved && requested != "-" && requested != p.record.owner_offer_id {
        return Err(Failure::new("operation_conflict", &p.request_id, "selection").into());
    }
    if requested != "-" {
        choices
            .remove(requested)
            .ok_or_else(|| Failure::new("proof_required", &p.request_id, "owner").into())
    } else if p.record.selection_approved {
        choices
            .remove(&p.record.owner_offer_id)
            .ok_or_else(|| Failure::new("proof_required", &p.request_id, "owner").into())
    } else {
        choices
            .into_values()
            .next()
            .ok_or_else(|| Failure::new("proof_required", &p.request_id, "owner").into())
    }
}
pub(crate) fn retain(p: &mut Pending, offer: &Candidate) {
    p.record.network_base64 = STANDARD.encode(&offer.descriptor);
    p.record.owner_packet_base64 = STANDARD.encode(&offer.packet);
    p.record.owner_offer_id = offer.evidence.owner_offer_id.clone();
    p.record.catalog_base64 = STANDARD.encode(&offer.catalog);
}
fn review(offer: &Candidate) -> Result<Value> {
    let e = &offer.evidence;
    Ok(
        json!({"owner_offer_id":e.owner_offer_id,"network_id":e.network_id,"person_id":crate::persons::person_id_of(&e.person_public_key)?,"person_public_key":e.person_public_key,"host_public_key":e.host_public_key,"device_public_key":e.device_public_key,"certificate_id":e.certificate_id,"issuer_certificate_id":e.issuer_certificate_id,"scopes":e.scopes,"not_after":e.not_after,"signer_public_key":e.signer_public_key,"authority_warning":if e.scopes&8!=0{"This device can manage access, trust itself and approve more machines when the person is an administrator."}else{"-"}}),
    )
}
fn pins(
    p: &Pending,
    offer: &Candidate,
    network: &str,
    person: &str,
    host: &str,
    device: &str,
    owner: &str,
) -> Result<()> {
    let e = &offer.evidence;
    ensure!(
        (network == "-" || network == e.network_id)
            && (person == "-" || person == e.person_public_key)
            && (host == "-" || host == e.host_public_key)
            && (device == "-" || device == e.device_public_key)
            && (owner == "-" || owner == e.owner_offer_id),
        Failure::new("invalid", &p.request_id, "consent")
    );
    Ok(())
}
pub fn outbound(
    tx: &Transaction<'_>,
    p: &mut Pending,
    role: &str,
    packet: &[u8],
    supplied: Option<&[u8]>,
) -> Result<()> {
    let secret = p
        .secret
        .ok_or_else(|| Failure::new("expired", &p.request_id, "frame"))?;
    let meta: request::Packet = serde_json::from_slice(packet)?;
    let writer = meta.writer_public_key;
    let plain = |packet: &[u8], catalog: &[u8]| {
        crypto::raw_object(vec![
            ("request_id", serde_json::to_vec(&p.request_id)?),
            ("role", serde_json::to_vec(role)?),
            ("writer_public_key", serde_json::to_vec(&writer)?),
            ("packet", packet.to_vec()),
            ("catalog", catalog.to_vec()),
        ])
    };
    let absent = b"\"-\"";
    let first = plain(packet, supplied.unwrap_or(absent))?;
    let mut bodies = Vec::new();
    if first.len() <= 64 << 10 {
        bodies.push(first);
    } else {
        let only = plain(packet, absent)?;
        ensure!(
            only.len() <= 64 << 10,
            Failure::new("quota_exceeded", &p.request_id, "frame")
        );
        bodies.push(only);
        let raw = supplied.ok_or_else(|| Failure::new("quota_exceeded", &p.request_id, "frame"))?;
        let object: Value = serde_json::from_slice(raw)?;
        let network = object["network_id"]
            .as_str()
            .ok_or_else(|| Failure::new("invalid", &p.request_id, "catalog"))?;
        let complete = catalog::decode(raw, network)?;
        let mut chunk = catalog::Catalog {
            format: 1,
            network_id: network.into(),
            objects: Vec::new(),
        };
        for entry in complete.objects {
            chunk.objects.push(entry.clone());
            let candidate = plain(absent, &crypto::json(&chunk)?)?;
            if candidate.len() <= 64 << 10 {
                continue;
            }
            chunk.objects.pop();
            ensure!(
                !chunk.objects.is_empty(),
                Failure::new("quota_exceeded", &p.request_id, "frame")
            );
            bodies.push(plain(absent, &crypto::json(&chunk)?)?);
            chunk.objects = vec![entry];
            ensure!(
                plain(absent, &crypto::json(&chunk)?)?.len() <= 64 << 10,
                Failure::new("quota_exceeded", &p.request_id, "frame")
            );
        }
        if !chunk.objects.is_empty() {
            bodies.push(plain(absent, &crypto::json(&chunk)?)?);
        }
    }
    let existing = {
        let mut q = tx.prepare("SELECT record FROM link_frames WHERE request_id=?1")?;
        q.query_map([&p.request_id], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut bytes = 0usize;
    for raw in &existing {
        let r: StoredFrame = linking::decode_stored_json(raw.as_bytes(), "frame_base64")?;
        bytes = bytes.saturating_add(crypto::bytes(&r.frame_base64, 128 << 10)?.len());
    }
    ensure!(
        existing.len() + bodies.len() <= 64,
        Failure::new("quota_exceeded", &p.request_id, "frame")
    );
    let mut sealed = Vec::new();
    for body in bodies {
        let (frame, raw) = crypto::seal(
            &secret,
            &p.record.coordinator_public_key,
            &p.request_id,
            role,
            &writer,
            &body,
        )?;
        bytes = bytes.saturating_add(raw.len());
        ensure!(
            bytes <= 512 << 10,
            Failure::new("quota_exceeded", &p.request_id, "frame")
        );
        sealed.push((frame, raw));
    }
    for (frame, raw) in sealed {
        persistence::store_frame(tx, &frame, &raw)?;
        p.record.outbound_frames.push(OutboundFrame {
            role: role.into(),
            writer_public_key: writer.clone(),
            frame_id: frame.frame_id,
            published: false,
            sequence: 0,
        });
    }
    Ok(())
}
fn valid_pins(
    id: &str,
    owner: &str,
    network: &str,
    person: &str,
    host: &str,
    device: &str,
) -> Result<()> {
    ensure!(
        (owner == "-" || crypto::id(owner, "lp_"))
            && (network == "-" || crypto::id(network, "net_"))
            && [person, host, device]
                .iter()
                .all(|s| *s == "-" || crypto::public_key(s)),
        Failure::new("invalid", id, "consent")
    );
    Ok(())
}
fn committed_review(p: &Pending) -> Result<Value> {
    let raw = crypto::bytes(&p.record.owner_packet_base64, linking::MAX_OBJECT)?;
    let packet: request::Packet = linking::decode_mutation(
        &raw,
        "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
    )?;
    linking::read("packet", &raw, &packet.writer_public_key, "-")?;
    let payload = crypto::bytes(&packet.payload_base64, linking::MAX_PAYLOAD)?;
    let fields: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(&payload)?;
    let cert = fields
        .get("certificate")
        .ok_or_else(|| Failure::new("state_conflict", &p.request_id, "storage"))?
        .get()
        .as_bytes();
    let certificate = linking::read("certificate", cert, &packet.writer_public_key, "-")?;
    let cert: Value = serde_json::from_slice(cert)?;
    let descriptor: Descriptor = serde_json::from_slice(&crypto::bytes(
        &p.record.network_base64,
        linking::MAX_OBJECT,
    )?)?;
    let mut admission_id = "-".to_owned();
    let mut admission = "-".to_owned();
    let mut administrator = "-".to_owned();
    if p.record.administrator_packet_base64 != "-" {
        let raw = crypto::bytes(&p.record.administrator_packet_base64, linking::MAX_OBJECT)?;
        let admin: request::Packet = serde_json::from_slice(&raw)?;
        linking::read("packet", &raw, &admin.writer_public_key, "-")?;
        let data = crypto::bytes(&admin.payload_base64, linking::MAX_PAYLOAD)?;
        let parts: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(&data)?;
        let record = parts
            .get("admission_record")
            .ok_or_else(|| Failure::new("state_conflict", &p.request_id, "storage"))?
            .get()
            .as_bytes();
        let object: Value = serde_json::from_slice(record)?;
        admission_id = linking::read(
            if object.get("person_public_key").is_some() {
                "person_record"
            } else {
                "root_record"
            },
            record,
            &admin.writer_public_key,
            "-",
        )?
        .id;
        admission = STANDARD.encode(record);
        administrator = admin.writer_public_key;
    }
    Ok(
        json!({"owner_offer_id":p.record.owner_offer_id,"network_id":descriptor.network_id,"person_id":crate::persons::person_id_of(&packet.person_public_key)?,"person_public_key":packet.person_public_key,"host_public_key":p.record.host_public_key,"device_public_key":p.record.device_public_key,"certificate_id":certificate.id,"issuer_certificate_id":packet.certificate_id,"scopes":cert["scopes"],"not_after":cert["not_after"],"signer_public_key":packet.writer_public_key,"authority_warning":if cert["scopes"].as_u64().unwrap_or(0)&8!=0{"This device can manage access, trust itself and approve more machines when the person is an administrator."}else{"-"},"selection_id":p.record.selection_id,"administrator_offer_id":p.record.administrator_offer_id,"admission_record_id":admission_id,"admission_record_base64":admission,"administrator_signer_public_key":administrator}),
    )
}
pub fn select(store: &Store, id: &str, input: Select) -> Result<Value> {
    valid_pins(
        id,
        &input.owner_offer_id,
        &input.network_id,
        &input.person_public_key,
        &input.host_public_key,
        &input.device_public_key,
    )?;
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let mut p =
        persistence::pending(&tx, id)?.ok_or_else(|| Failure::new("not_found", id, "selection"))?;
    ensure!(
        p.role != "approver",
        Failure::new("forbidden", id, "selection")
    );
    let offer = choose(&tx, &p, &input.owner_offer_id)?;
    pins(
        &p,
        &offer,
        &input.network_id,
        &input.person_public_key,
        &input.host_public_key,
        &input.device_public_key,
        &input.owner_offer_id,
    )?;
    if input.approve {
        ensure!(
            [
                &input.network_id,
                &input.person_public_key,
                &input.host_public_key,
                &input.device_public_key,
                &input.owner_offer_id
            ]
            .iter()
            .all(|v| v.as_str() != "-"),
            Failure::new("invalid", id, "consent")
        );
    }
    retain(&mut p, &offer);
    let reviewed = review(&offer)?;
    if input.approve && !p.record.selection_approved {
        let payload = crypto::json(
            &json!({"owner_offer_id":offer.evidence.owner_offer_id,"network_id":offer.evidence.network_id,"epoch":offer.epoch,"feature_id":offer.feature,"person_public_key":offer.evidence.person_public_key}),
        )?;
        let (raw, selection) = request::requester_packet(
            store,
            &tx,
            &p,
            "selection",
            &offer.evidence.person_public_key,
            &payload,
        )?;
        linking::verify_stored_selection(
            offer.context(&p, support::now()?),
            &offer.catalog,
            &crypto::bytes(&p.record.request_packet_base64, linking::MAX_OBJECT)?,
            &offer.packet,
            &raw,
        )?;
        p.record.selection_approved = true;
        p.record.selection_packet_base64 = STANDARD.encode(&raw);
        p.record.selection_id = selection;
        p.state = if p.role == "renew" {
            "ready_to_commit"
        } else {
            "awaiting_administrator"
        }
        .into();
        outbound(&tx, &mut p, "selection", &raw, None)?;
    } else if !p.record.selection_approved {
        p.state = "waiting_selection".into();
    }
    persistence::save_pending(&tx, &p)?;
    tx.commit()?;
    drop(c);
    Ok(json!({"request":request::view(store,&p)?,"review":reviewed}))
}
pub fn commit(store: &Store, id: &str, input: Commit) -> Result<Value> {
    valid_pins(
        id,
        &input.owner_offer_id,
        &input.network_id,
        &input.person_public_key,
        &input.host_public_key,
        &input.device_public_key,
    )?;
    ensure!(
        [&input.selection_id, &input.administrator_offer_id]
            .iter()
            .all(|s| s.as_str() == "-" || crypto::id(s, "lp_")),
        Failure::new("invalid", id, "consent")
    );
    let mut c = store.connection()?;
    let tx = c.transaction()?;
    let mut p =
        persistence::pending(&tx, id)?.ok_or_else(|| Failure::new("not_found", id, "commit"))?;
    ensure!(
        p.role != "approver" && p.record.selection_approved,
        Failure::new("proof_required", id, "selection")
    );
    if input.approve {
        ensure!(
            [
                &input.owner_offer_id,
                &input.selection_id,
                &input.network_id,
                &input.person_public_key,
                &input.host_public_key,
                &input.device_public_key
            ]
            .iter()
            .all(|v| v.as_str() != "-")
                && (p.role != "new" || input.administrator_offer_id != "-"),
            Failure::new("invalid", id, "commit")
        );
    }
    if p.record.commit_approved {
        let review = committed_review(&p)?;
        for (provided, key) in [
            (&input.owner_offer_id, "owner_offer_id"),
            (&input.selection_id, "selection_id"),
            (&input.administrator_offer_id, "administrator_offer_id"),
            (&input.network_id, "network_id"),
            (&input.person_public_key, "person_public_key"),
            (&input.host_public_key, "host_public_key"),
            (&input.device_public_key, "device_public_key"),
        ] {
            ensure!(
                (!input.approve && provided == "-")
                    || review[key].as_str() == Some(provided.as_str()),
                Failure::new("operation_conflict", id, "commit")
            );
        }
        drop(tx);
        drop(c);
        return Ok(json!({"request":request::view(store, &p)?,"review":review}));
    }
    let mut offer = choose(&tx, &p, &input.owner_offer_id)?;
    let request_raw = crypto::bytes(&p.record.request_packet_base64, linking::MAX_OBJECT)?;
    let selection = crypto::bytes(&p.record.selection_packet_base64, linking::MAX_OBJECT)?;
    linking::verify_stored_selection(
        offer.context(&p, support::now()?),
        &offer.catalog,
        &request_raw,
        &offer.packet,
        &selection,
    )?;
    let mut admin_evidence = None;
    let mut admin_packet = Vec::new();
    if p.role == "new" {
        let mut options = frames(&tx, &p)?;
        if p.record.administrator_packet_base64 != "-" {
            options.push(Received {
                packet: crypto::bytes(&p.record.administrator_packet_base64, linking::MAX_OBJECT)?,
                catalog: None,
                role: "administrator".into(),
            });
        }
        let mut candidates = BTreeMap::new();
        for received in options
            .into_iter()
            .filter(|f| f.role == "administrator" && !f.packet.is_empty())
        {
            let checked = || -> Result<_> {
                let catalog = if let Some(catalog) = &received.catalog {
                    catalog::merge(&offer.network.id, &[&offer.catalog, catalog])?
                } else {
                    offer.catalog.clone()
                };
                let e = linking::verify_stored_administrator_offer(
                    offer.context(&p, support::now()?),
                    &catalog,
                    &request_raw,
                    &offer.packet,
                    &selection,
                    &received.packet,
                )?;
                Ok((e, catalog))
            };
            if let Ok((e, catalog)) = checked() {
                candidates.insert(
                    e.administrator_offer_id.clone(),
                    (e, catalog, received.packet),
                );
            }
        }
        let selected = if input.administrator_offer_id != "-" {
            candidates.remove(&input.administrator_offer_id)
        } else {
            candidates.into_values().next()
        };
        let (e, catalog, raw) =
            selected.ok_or_else(|| Failure::new("proof_required", id, "administrator"))?;
        offer.catalog = catalog;
        admin_packet = raw;
        admin_evidence = Some(e);
    }
    let mut reviewed = review(&offer)?;
    let fields = reviewed.as_object_mut().expect("review object");
    fields.insert("selection_id".into(), json!(p.record.selection_id));
    fields.insert(
        "administrator_offer_id".into(),
        json!(
            admin_evidence
                .as_ref()
                .map(|a| a.administrator_offer_id.as_str())
                .unwrap_or("-")
        ),
    );
    fields.insert(
        "admission_record_id".into(),
        json!(
            admin_evidence
                .as_ref()
                .map(|a| a.admission_record_id.as_str())
                .unwrap_or("-")
        ),
    );
    fields.insert(
        "admission_record_base64".into(),
        json!(
            admin_evidence
                .as_ref()
                .map(|a| STANDARD.encode(&a.admission_record))
                .unwrap_or_else(|| "-".into())
        ),
    );
    fields.insert(
        "administrator_signer_public_key".into(),
        json!(
            admin_evidence
                .as_ref()
                .map(|a| a.administrator_signer_public_key.as_str())
                .unwrap_or("-")
        ),
    );
    pins(
        &p,
        &offer,
        &input.network_id,
        &input.person_public_key,
        &input.host_public_key,
        &input.device_public_key,
        &input.owner_offer_id,
    )?;
    ensure!(
        (input.selection_id == "-" || input.selection_id == p.record.selection_id)
            && (input.administrator_offer_id == "-"
                || input.administrator_offer_id
                    == admin_evidence
                        .as_ref()
                        .map(|a| a.administrator_offer_id.as_str())
                        .unwrap_or("-")),
        Failure::new("invalid", id, "consent")
    );
    if input.approve {
        ensure!(
            [
                &input.network_id,
                &input.person_public_key,
                &input.host_public_key,
                &input.device_public_key,
                &input.owner_offer_id,
                &input.selection_id
            ]
            .iter()
            .all(|s| s.as_str() != "-"),
            Failure::new("invalid", id, "consent")
        );
        pins(
            &p,
            &offer,
            &input.network_id,
            &input.person_public_key,
            &input.host_public_key,
            &input.device_public_key,
            &input.owner_offer_id,
        )?;
        ensure!(
            input.selection_id == p.record.selection_id
                && input.administrator_offer_id
                    == admin_evidence
                        .as_ref()
                        .map(|a| a.administrator_offer_id.as_str())
                        .unwrap_or("-"),
            Failure::new("invalid", id, "commit")
        );
    }
    retain(&mut p, &offer);
    if let Some(e) = &admin_evidence {
        p.record.administrator_packet_base64 = STANDARD.encode(&admin_packet);
        p.record.administrator_offer_id = e.administrator_offer_id.clone();
    }
    if input.approve && !p.record.commit_approved {
        let retained: i64 = tx.query_row(
            "SELECT count(*) FROM link_operations WHERE network_id=?1 AND request_id<>?2",
            rusqlite::params![offer.network.id, id],
            |r| r.get(0),
        )?;
        ensure!(
            retained < 4096,
            Failure::new("quota_exceeded", id, "operation")
        );

        let binding = if p.role == "new" {
            let mut b: Value = serde_json::from_slice(&offer.evidence.binding_draft)?;
            let message = [
                "peerspan-binding-consent-v1",
                &crypto::hash(&offer.evidence.binding_authorization_message),
            ]
            .join("\n");
            b["host_signature"] =
                json!(STANDARD.encode(store.signing_key.sign(message.as_bytes()).to_bytes()));
            b
        } else {
            json!("-")
        };
        let payload = crypto::json(
            &json!({"mode":p.role,"request_packet_id":offer.evidence.request_packet_id,"owner_offer_id":p.record.owner_offer_id,"selection_id":p.record.selection_id,"administrator_offer_id":p.record.administrator_offer_id,"network_id":offer.evidence.network_id,"epoch":offer.epoch,"feature_id":offer.feature,"person_public_key":offer.evidence.person_public_key,"certificate_id":offer.evidence.certificate_id,"binding_record":binding,"admission_record_id":admin_evidence.as_ref().map(|a|a.admission_record_id.as_str()).unwrap_or("-"),"expires_at":p.deadline}),
        )?;
        let (raw, manifest) = request::requester_packet(
            store,
            &tx,
            &p,
            "commit",
            &offer.evidence.person_public_key,
            &payload,
        )?;
        let activation = activation(&p, &raw)?;
        linking::verify_stored_activation(
            offer.context(&p, support::now()?),
            &offer.catalog,
            &activation,
        )?;
        p.record.commit_approved = true;
        p.record.commit_packet_base64 = STANDARD.encode(&raw);
        p.record.manifest_id = manifest;
        p.state = "finalizing".into();
        outbound(&tx, &mut p, "commit", &raw, None)?;
    } else if !p.record.commit_approved {
        p.state = "ready_to_commit".into();
    }
    persistence::save_pending(&tx, &p)?;
    tx.commit()?;
    drop(c);
    Ok(json!({"request":request::view(store,&p)?,"review":reviewed}))
}
pub fn activation(p: &Pending, commit: &[u8]) -> Result<Vec<u8>> {
    crypto::raw_object(vec![
        (
            "request",
            crypto::bytes(&p.record.request_packet_base64, linking::MAX_OBJECT)?,
        ),
        (
            "owner",
            crypto::bytes(&p.record.owner_packet_base64, linking::MAX_OBJECT)?,
        ),
        (
            "selection",
            crypto::bytes(&p.record.selection_packet_base64, linking::MAX_OBJECT)?,
        ),
        (
            "administrator",
            if p.role == "new" {
                crypto::bytes(&p.record.administrator_packet_base64, linking::MAX_OBJECT)?
            } else {
                b"\"-\"".to_vec()
            },
        ),
        ("commit", commit.to_vec()),
    ])
}

/// Processing relay hints can retain a review; it never supplies requester consent.
pub fn observe(store: &Store, id: &str) -> Result<()> {
    let p = {
        let c = store.connection()?;
        persistence::pending(&c, id)?.ok_or_else(|| Failure::new("not_found", id, "request"))?
    };
    if p.role == "approver" || p.record.commit_approved {
        return Ok(());
    }
    if !p.record.selection_approved {
        match select(
            store,
            id,
            Select {
                owner_offer_id: "-".into(),
                network_id: "-".into(),
                person_public_key: "-".into(),
                host_public_key: "-".into(),
                device_public_key: "-".into(),
                approve: false,
            },
        ) {
            Ok(_) => {}
            Err(e)
                if e.downcast_ref::<Failure>()
                    .is_some_and(|f| f.code == "proof_required") => {}
            Err(e) => return Err(e),
        }
    } else {
        match commit(
            store,
            id,
            Commit {
                owner_offer_id: p.record.owner_offer_id.clone(),
                selection_id: p.record.selection_id.clone(),
                administrator_offer_id: "-".into(),
                network_id: "-".into(),
                person_public_key: "-".into(),
                host_public_key: "-".into(),
                device_public_key: "-".into(),
                approve: false,
            },
        ) {
            Ok(_) => {}
            Err(e)
                if e.downcast_ref::<Failure>()
                    .is_some_and(|f| f.code == "proof_required") => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
