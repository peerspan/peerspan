//! Durable requester identity and exact signed request packets.
use super::{
    catalog, crypto,
    model::{CreateRequest, OutboundFrame, PendingRecord, RequestView},
    persistence::{self, Pending},
    support::{self, Failure},
};
use crate::{persons::PersonSigner, store::Store};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub format: u64,
    pub request_id: String,
    pub role: String,
    pub writer_public_key: String,
    pub person_public_key: String,
    pub certificate_id: String,
    pub payload_base64: String,
    pub host_signature: String,
    pub device_signature: String,
    pub authority_signature: String,
}

pub fn requester_packet(
    store: &Store,
    connection: &Connection,
    p: &Pending,
    role: &str,
    person: &str,
    payload: &[u8],
) -> Result<(Vec<u8>, String)> {
    ensure!(
        p.record.host_public_key == store.identity().public_key
            && matches!(role, "request" | "selection" | "commit"),
        "invalid requester packet"
    );
    let key = persistence::device(connection, &p.record.device_public_key)?;
    let mut packet = Packet {
        format: 1,
        request_id: p.request_id.clone(),
        role: role.into(),
        writer_public_key: store.identity().public_key,
        person_public_key: person.into(),
        certificate_id: "-".into(),
        payload_base64: STANDARD.encode(payload),
        host_signature: "-".into(),
        device_signature: "-".into(),
        authority_signature: "-".into(),
    };
    let message = [
        "peerspan-link-packet-v1",
        &packet.request_id,
        role,
        &packet.writer_public_key,
        person,
        "-",
        &crypto::hash(payload),
    ]
    .join("\n");
    packet.host_signature = STANDARD.encode(store.signing_key.sign(message.as_bytes()).to_bytes());
    packet.device_signature =
        PersonSigner::File(key).sign(&message.split('\n').collect::<Vec<_>>())?;
    let raw = crypto::json(&packet)?;
    let checked = crate::linking::read(
        "packet",
        &raw,
        &p.record.host_public_key,
        &p.record.device_public_key,
    )?;
    Ok((raw, checked.id))
}

pub fn create(store: &Store, mut request: CreateRequest) -> Result<(String, bool)> {
    let at = support::now()?;
    ensure!(
        matches!(request.mode.as_str(), "new" | "renew")
            && (request.network_id == "-" || crypto::id(&request.network_id, "net_"))
            && (request.person_public_key == "-" || crypto::public_key(&request.person_public_key)),
        Failure::new("invalid", "-", "request")
    );
    let mut connection = store.connection()?;
    let tx = connection.transaction()?;
    let network = if request.network_id != "-" {
        match store.network_record(&tx, &request.network_id) {
            Ok(n) => Some(n),
            Err(crate::model::Error::NotFound) => None,
            Err(e) => return Err(e.into()),
        }
    } else {
        None
    };
    if let Some(network) = &network {
        if request.coordinator_address == "-" && request.coordinator_public_key == "-" {
            request.coordinator_address = network.coordinator_address.clone();
            request.coordinator_public_key = network.coordinator_public_key.clone();
        }
        ensure!(
            request.coordinator_address == network.coordinator_address
                && request.coordinator_public_key == network.coordinator_public_key,
            Failure::new("state_conflict", "-", "coordinator")
        );
    }
    if request.coordinator_address == "-" && request.coordinator_public_key == "-" {
        let (address, key) = crate::network::default_coordinator()
            .ok_or_else(|| Failure::new("invalid", "-", "coordinator"))?;
        request.coordinator_address = address.into();
        request.coordinator_public_key = key.into();
    }
    ensure!(
        crypto::public_key(&request.coordinator_public_key),
        Failure::new("invalid", "-", "coordinator")
    );
    crate::membership::split_host_port(&request.coordinator_address)
        .map_err(|_| Failure::new("invalid", "-", "coordinator"))?;
    let mut renewed_certificate = "-".to_owned();
    let mut renewal_device = None;
    if request.mode == "renew" {
        ensure!(
            network.is_some() && request.person_public_key != "-",
            Failure::new("proof_required", "-", "signer")
        );
        let signer: Option<(String, String, String)> = tx
            .query_row(
                "SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?1",
                [&request.network_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (person, device, certificate) =
            signer.ok_or_else(|| Failure::new("proof_required", "-", "signer"))?;
        ensure!(
            person == request.person_public_key,
            Failure::new("state_conflict", "-", "person")
        );
        renewal_device = Some(persistence::device(&tx, &device)?);
        renewed_certificate = certificate;
    } else {
        ensure!(
            network.is_none(),
            Failure::new("state_conflict", "-", "request")
        );
    }
    let ids = {
        let mut statement =
            tx.prepare("SELECT request_id FROM link_pending WHERE role=?1 ORDER BY request_id")?;
        statement
            .query_map([&request.mode], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut retired_device = None;
    for id in ids {
        let p = persistence::pending(&tx, &id)?
            .ok_or_else(|| Failure::new("state_conflict", &id, "storage"))?;
        let r = &p.record;
        if p.secret.is_some()
            && !matches!(p.state.as_str(), "linked" | "cancelled" | "expired")
            && at < support::stamp(&p.deadline)?
            && r.expected_network_id == request.network_id
            && r.expected_person_public_key == request.person_public_key
            && r.coordinator_address == request.coordinator_address
            && r.coordinator_public_key == request.coordinator_public_key
        {
            tx.commit()?;
            return Ok((id, false));
        }
        if request.mode == "new"
            && !r.commit_approved
            && r.expected_network_id == request.network_id
            && r.expected_person_public_key == request.person_public_key
            && r.coordinator_address == request.coordinator_address
            && r.coordinator_public_key == request.coordinator_public_key
            && (matches!(p.state.as_str(), "cancelled" | "expired")
                || at >= support::stamp(&p.deadline)?)
        {
            let mut revoked = false;
            if r.network_base64 != "-" && r.catalog_base64 != "-" {
                let descriptor = crypto::bytes(&r.network_base64, crate::linking::MAX_OBJECT)?;
                let raw = crypto::bytes(&r.catalog_base64, 16 << 20)?;
                let d: super::map::Descriptor = serde_json::from_slice(&descriptor)?;
                let objects = catalog::decode(&raw, &d.network_id)?;
                let epoch = catalog::target_epoch(&objects)?;
                let facts = crate::linking::verify_stored_network_state(
                    crate::linking::CatalogFactContext {
                        network: &descriptor,
                        epoch,
                        known_feature_id: "-",
                        now: at,
                    },
                    &raw,
                )?;
                revoked = facts
                    .facts
                    .state
                    .revoked_devices
                    .iter()
                    .any(|key| key.device_public_key == r.device_public_key);
            }
            if !revoked {
                retired_device = Some(persistence::device(&tx, &r.device_public_key)?);
            }
        }
    }
    let key = if let Some(key) = renewal_device.or(retired_device) {
        key
    } else {
        persistence::create_device(&tx, &at.format("%Y-%m-%dT%H:%M:%SZ").to_string())?
    };
    let device = STANDARD.encode(key.verifying_key().as_bytes());
    let mut nonce = [0u8; 32];
    let mut secret = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| Failure::new("internal", "-", "request"))?;
    getrandom::fill(&mut secret).map_err(|_| Failure::new("internal", "-", "request"))?;
    let nonce = STANDARD.encode(nonce);
    let host = store.identity().public_key;
    let id = format!(
        "link_{}",
        crypto::hash(
            [
                "peerspan-link-request-id-v1",
                &request.coordinator_public_key,
                &host,
                &device,
                &nonce
            ]
            .join("\n")
            .as_bytes()
        )
    );
    let deadline = (at + chrono::Duration::seconds(300))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let mut pending = Pending {
        request_id: id.clone(),
        role: request.mode.clone(),
        state: "waiting_owner".into(),
        deadline: deadline.clone(),
        secret: Some(secret),
        record: PendingRecord {
            expected_network_id: request.network_id.clone(),
            expected_person_public_key: request.person_public_key.clone(),
            coordinator_address: request.coordinator_address.clone(),
            coordinator_public_key: request.coordinator_public_key.clone(),
            host_public_key: host.clone(),
            device_public_key: device,
            request_nonce: nonce,
            ..PendingRecord::default()
        },
    };
    let payload = crypto::json(
        &serde_json::json!({"mode":request.mode,"host_public_key":host,"device_public_key":pending.record.device_public_key,"request_nonce":pending.record.request_nonce,"coordinator_address":request.coordinator_address,"coordinator_public_key":request.coordinator_public_key,"created_at":at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),"expires_at":deadline,"expected_network_id":request.network_id,"expected_person_public_key":request.person_public_key,"renewed_certificate_id":renewed_certificate}),
    )?;
    let (raw, _) = requester_packet(store, &tx, &pending, "request", "-", &payload)?;
    pending.record.request_packet_base64 = STANDARD.encode(&raw);
    let packet: serde_json::Value = serde_json::from_slice(&raw)?;
    let plaintext = crypto::json(
        &serde_json::json!({"request_id":id,"role":"request","writer_public_key":host,"packet":packet,"catalog":"-"}),
    )?;
    let (frame, frame_raw) = crypto::seal(
        &secret,
        &pending.record.coordinator_public_key,
        &id,
        "request",
        &host,
        &plaintext,
    )?;
    persistence::store_frame(&tx, &frame, &frame_raw)?;
    pending.record.outbound_frames.push(OutboundFrame {
        role: "request".into(),
        writer_public_key: host,
        frame_id: frame.frame_id,
        published: false,
        sequence: 0,
    });
    persistence::save_pending(&tx, &pending)?;
    tx.commit()?;
    Ok((id, true))
}

pub fn view(store: &Store, p: &Pending) -> Result<RequestView> {
    let r = &p.record;
    let now = support::now()?;
    let mut person = r.expected_person_public_key.clone();
    let mut network = r.expected_network_id.clone();
    if r.owner_packet_base64 != "-" {
        let raw = crypto::bytes(&r.owner_packet_base64, crate::linking::MAX_OBJECT)?;
        let packet: Packet = crate::linking::decode_mutation(
            &raw,
            "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
        )?;
        person = packet.person_public_key;
        let offer: serde_json::Value = serde_json::from_slice(&crypto::bytes(
            &packet.payload_base64,
            crate::linking::MAX_PAYLOAD,
        )?)?;
        network = offer["network"]["network_id"]
            .as_str()
            .unwrap_or("-")
            .into();
    }
    let mut state = p.state.clone();
    if p.role != "approver"
        && !r.commit_approved
        && !matches!(state.as_str(), "linked" | "cancelled")
        && now >= support::stamp(&p.deadline)?
    {
        state = "expired".into();
    }
    let mut completed = vec!["request_created".into()];
    if r.owner_packet_base64 != "-" {
        completed.push("owner_offered".into());
    }
    if r.selection_packet_base64 != "-" {
        completed.push("owner_selected".into());
    }
    if r.administrator_packet_base64 != "-" && p.role != "renew" {
        completed.push("administrator_offered".into());
    }
    if r.commit_packet_base64 != "-" {
        completed.push("commit_persisted".into());
    }
    let applied: bool = store.connection()?.query_row(
        "SELECT EXISTS(SELECT 1 FROM link_operations WHERE request_id=?1 AND locally_applied=1)",
        [&p.request_id],
        |r| r.get(0),
    )?;
    if applied {
        completed.push("locally_applied".into());
    }
    if applied && p.role != "approver" && super::provider::view(store, &network).is_err() {
        state = "incomplete".into();
    }
    let mut attention = Vec::new();
    let mut next = Vec::new();
    match state.as_str() {
        "waiting_owner" => next.push("approve_owner_offer".into()),
        "waiting_selection" => next.push("select_owner_offer".into()),
        "awaiting_administrator" => next.push("approve_administrator_offer".into()),
        "ready_to_commit" => next.push("review_final_commit".into()),
        "finalizing" => next.push("resume_finalization".into()),
        "incomplete" => {
            attention.push("authority_requires_repair".into());
            next.push("repair_same_person".into());
        }
        "expired" => attention.push("request_expired".into()),
        _ => {}
    }
    let fingerprint = crypto::bytes(&r.device_public_key, 32)?;
    let person_id = if person == "-" {
        "-".into()
    } else {
        crate::persons::person_id_of(&person)?
    };
    Ok(RequestView {
        request_id: p.request_id.clone(),
        mode: if p.role == "approver" {
            let raw = crypto::bytes(&r.request_packet_base64, crate::linking::MAX_OBJECT)?;
            let packet: Packet = serde_json::from_slice(&raw)?;
            let payload: serde_json::Value = serde_json::from_slice(&crypto::bytes(
                &packet.payload_base64,
                crate::linking::MAX_PAYLOAD,
            )?)?;
            payload["mode"].as_str().unwrap_or("-").into()
        } else {
            p.role.clone()
        },
        state,
        network_id: network,
        person_id,
        host_id: crate::peer_store::key_id(&crypto::bytes(&r.host_public_key, 32)?),
        device_fingerprint: format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&fingerprint))
        ),
        expires_at: p.deadline.clone(),
        completed,
        attention,
        next,
    })
}
