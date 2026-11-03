//! Canonical unsigned high-water storage and immutable private frame records.
use super::{crypto, model::PendingRecord};
use crate::linking::{AccessHighWater, AccessState, GroupHighWater, PolicyHighWater};
use anyhow::{Result, ensure};
use rusqlite::{
    Connection, OptionalExtension, Transaction, params,
    types::{Value, ValueRef},
};
use std::collections::BTreeMap;

pub fn encode_version(version: u64) -> Result<Value> {
    ensure!(version != 0, "invalid high water");
    Ok(if version <= i64::MAX as u64 {
        Value::Integer(version as i64)
    } else {
        Value::Blob(version.to_be_bytes().to_vec())
    })
}

pub fn decode_version(value: ValueRef<'_>) -> Result<u64> {
    match value {
        ValueRef::Integer(n) if n > 0 => Ok(n as u64),
        ValueRef::Blob(b) if b.len() == 8 && b[0] & 128 != 0 => {
            Ok(u64::from_be_bytes(b.try_into()?))
        }
        _ => anyhow::bail!("invalid high water storage"),
    }
}

pub fn high_water(
    connection: &Connection,
    network: &str,
) -> Result<(Vec<PolicyHighWater>, Vec<GroupHighWater>)> {
    let mut statement = connection.prepare("SELECT kind,subject,version,record_hash FROM link_highwater WHERE network_id=?1 ORDER BY kind,subject")?;
    let mut rows = statement.query([network])?;
    let (mut policies, mut groups) = (Vec::new(), Vec::new());
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        let subject: String = row.get(1)?;
        let version = decode_version(row.get_ref(2)?)?;
        let message_hash: String = row.get(3)?;
        ensure!(crypto::id(&message_hash, ""), "invalid high water hash");
        let high_water = AccessHighWater {
            version,
            message_hash,
        };
        match kind.as_str() {
            "policy" => {
                ensure!(crypto::public_key(&subject), "invalid policy subject");
                policies.push(PolicyHighWater {
                    person_public_key: subject,
                    high_water,
                });
            }
            "group" => {
                crate::admins::group_name(&subject)?;
                groups.push(GroupHighWater {
                    name: subject,
                    high_water,
                });
            }
            _ => anyhow::bail!("invalid high water kind"),
        }
    }
    Ok((policies, groups))
}

pub fn persist_high_water(tx: &Transaction<'_>, state: &AccessState) -> Result<()> {
    let (policies, groups) = high_water(tx, &state.network_id)?;
    let old_policies: BTreeMap<_, _> = policies
        .into_iter()
        .map(|p| (p.person_public_key, p.high_water))
        .collect();
    let old_groups: BTreeMap<_, _> = groups.into_iter().map(|p| (p.name, p.high_water)).collect();
    let put = |kind: &str,
               subject: &str,
               w: &AccessHighWater,
               old: &BTreeMap<String, AccessHighWater>|
     -> Result<()> {
        ensure!(crypto::id(&w.message_hash, ""), "invalid high water hash");
        if let Some(previous) = old.get(subject) {
            ensure!(w.version >= previous.version, "high water rollback");
            if w.version == previous.version {
                ensure!(
                    if kind == "group" {
                        w.message_hash == previous.message_hash
                    } else {
                        w.message_hash <= previous.message_hash
                    },
                    "high water conflict"
                );
            }
        }
        tx.execute("INSERT INTO link_highwater(network_id,kind,subject,version,record_hash) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(network_id,kind,subject) DO UPDATE SET version=excluded.version,record_hash=excluded.record_hash",params![state.network_id,kind,subject,encode_version(w.version)?,w.message_hash])?;
        Ok(())
    };
    for p in &state.policies {
        put(
            "policy",
            &p.person_public_key,
            &p.selection.high_water,
            &old_policies,
        )?;
    }
    for g in &state.groups {
        put("group", &g.name, &g.selection.high_water, &old_groups)?;
    }
    Ok(())
}

#[derive(Clone)]
pub struct Pending {
    pub request_id: String,
    pub role: String,
    pub state: String,
    pub deadline: String,
    pub record: PendingRecord,
    pub secret: Option<[u8; 16]>,
}

pub fn pending(connection: &Connection, request: &str) -> Result<Option<Pending>> {
    type PendingRow = (String, String, String, String, Option<Vec<u8>>);
    let raw: Option<PendingRow> = connection
        .query_row(
            "SELECT role,state,deadline,record,secret FROM link_pending WHERE request_id=?1",
            [request],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    raw.map(|(role, state, deadline, record, secret)| {
        ensure!(
            matches!(role.as_str(), "new" | "renew" | "approver"),
            "invalid pending role"
        );
        let secret = secret
            .map(|b| {
                b.try_into()
                    .map_err(|_| anyhow::anyhow!("invalid pending secret"))
            })
            .transpose()?;
        let pending = Pending {
            request_id: request.into(),
            role,
            state,
            deadline,
            record: PendingRecord::decode(record.as_bytes())?,
            secret,
        };
        validate_pending(&pending)?;
        Ok(pending)
    })
    .transpose()
}

/// The caller's stage transaction fixes all consent/template invariants first.
pub fn save_pending(tx: &Transaction<'_>, p: &Pending) -> Result<()> {
    ensure!(
        crypto::id(&p.request_id, "link_")
            && matches!(p.role.as_str(), "new" | "renew" | "approver"),
        "invalid pending identity"
    );
    if let Some(old) = pending(tx, &p.request_id)? {
        ensure!(
            old.role == p.role && old.deadline == p.deadline,
            "pending identity conflict"
        );
        ensure!(
            old.record.coordinator_address == p.record.coordinator_address
                && old.record.coordinator_public_key == p.record.coordinator_public_key
                && old.record.host_public_key == p.record.host_public_key
                && old.record.device_public_key == p.record.device_public_key
                && old.record.request_nonce == p.record.request_nonce,
            "pending pin conflict"
        );
        ensure!(
            p.record.transition_from(&old.record, &p.role),
            "immutable pending conflict"
        );
    }
    let raw = String::from_utf8(crypto::json(&p.record)?)?;
    tx.execute("INSERT INTO link_pending(request_id,role,state,deadline,record,secret) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(request_id) DO UPDATE SET state=excluded.state,record=excluded.record,secret=excluded.secret",params![p.request_id,p.role,p.state,p.deadline,raw,p.secret.as_ref().map(|b|b.as_slice())])?;
    Ok(())
}

fn validate_pending(p: &Pending) -> Result<()> {
    ensure!(
        crypto::id(&p.request_id, "link_"),
        "invalid request identity"
    );
    super::support::stamp(&p.deadline)?;
    let r = &p.record;
    let raw = crypto::bytes(&r.request_packet_base64, crate::linking::MAX_OBJECT)?;
    let signed = crate::linking::read("packet", &raw, &r.host_public_key, &r.device_public_key)?;
    let packet: serde_json::Value = serde_json::from_slice(&raw)?;
    let payload: serde_json::Value = serde_json::from_slice(
        signed
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing request payload"))?,
    )?;
    ensure!(
        packet["request_id"] == p.request_id
            && packet["role"] == "request"
            && payload["host_public_key"] == r.host_public_key
            && payload["device_public_key"] == r.device_public_key
            && payload["request_nonce"] == r.request_nonce
            && payload["coordinator_address"] == r.coordinator_address
            && payload["coordinator_public_key"] == r.coordinator_public_key
            && payload["expires_at"] == p.deadline
            && payload["expected_network_id"] == r.expected_network_id
            && payload["expected_person_public_key"] == r.expected_person_public_key
            && (p.role == "approver" || payload["mode"] == p.role),
        "pending request mismatch"
    );
    ensure!(
        matches!(
            p.state.as_str(),
            "pending"
                | "review"
                | "request_persisted"
                | "waiting_owner"
                | "waiting_selection"
                | "awaiting_administrator"
                | "ready_to_commit"
                | "commit_persisted"
                | "finalizing"
                | "linked"
                | "offer_sent"
                | "cancelled"
                | "expired"
                | "incomplete"
        ),
        "invalid pending state"
    );
    for (encoded, expected_id, role) in [
        (&r.owner_packet_base64, &r.owner_offer_id, "owner"),
        (&r.selection_packet_base64, &r.selection_id, "selection"),
        (
            &r.administrator_packet_base64,
            &r.administrator_offer_id,
            "administrator",
        ),
        (&r.commit_packet_base64, &r.manifest_id, "commit"),
    ] {
        if encoded == "-" {
            ensure!(expected_id == "-", "pending reference without packet");
            continue;
        }
        ensure!(
            crypto::id(expected_id, "lp_"),
            "pending packet without reference"
        );
        let raw = crypto::bytes(encoded, crate::linking::MAX_OBJECT)?;
        let packet: super::request::Packet = crate::linking::decode_mutation(
            &raw,
            "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
        )?;
        ensure!(
            packet.request_id == p.request_id && packet.role == role,
            "pending packet metadata mismatch"
        );
        let actor = if matches!(role, "selection" | "commit") {
            r.host_public_key.as_str()
        } else {
            packet.writer_public_key.as_str()
        };
        let device = if matches!(role, "selection" | "commit") {
            r.device_public_key.as_str()
        } else {
            "-"
        };
        ensure!(
            crate::linking::read("packet", &raw, actor, device)?.id == *expected_id,
            "pending packet reference mismatch"
        );
    }
    ensure!(
        (!r.selection_approved || r.selection_packet_base64 != "-")
            && (!r.commit_approved || r.selection_approved && r.commit_packet_base64 != "-"),
        "pending consent mismatch"
    );
    if r.result_packet_base64 != "-" {
        ensure!(r.commit_approved, "result without consent");
        let raw = crypto::bytes(&r.result_packet_base64, crate::linking::MAX_OBJECT)?;
        let packet: super::request::Packet = crate::linking::decode_mutation(
            &raw,
            "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
        )?;
        ensure!(
            packet.request_id == p.request_id && packet.role == "result",
            "pending result mismatch"
        );
        crate::linking::read("packet", &raw, &r.coordinator_public_key, "-")?;
    }
    ensure!(
        p.state != "linked" || r.result_packet_base64 != "-" && p.secret.is_none(),
        "linked outcome mismatch"
    );
    let expected = format!(
        "link_{}",
        crypto::hash(
            [
                "peerspan-link-request-id-v1",
                &r.coordinator_public_key,
                &r.host_public_key,
                &r.device_public_key,
                &r.request_nonce
            ]
            .join("\n")
            .as_bytes()
        )
    );
    ensure!(
        expected == p.request_id,
        "pending request identity mismatch"
    );
    Ok(())
}

pub fn create_device(tx: &Transaction<'_>, at: &str) -> Result<ed25519_dalek::SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| anyhow::anyhow!("random source failed"))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        key.verifying_key().as_bytes(),
    );
    tx.execute(
        "INSERT INTO link_device_keys(public_key,seed,created_at) VALUES(?1,?2,?3)",
        params![public, seed.as_slice(), at],
    )?;
    Ok(key)
}
pub fn device(connection: &Connection, public: &str) -> Result<ed25519_dalek::SigningKey> {
    let (seed, at): (Vec<u8>, String) = connection.query_row(
        "SELECT seed,created_at FROM link_device_keys WHERE public_key=?1",
        [public],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid device seed"))?;
    super::support::stamp(&at)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    ensure!(
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            key.verifying_key().as_bytes()
        ) == public,
        "invalid device identity"
    );
    Ok(key)
}

pub fn store_frame(tx: &Transaction<'_>, frame: &crypto::Frame, raw: &[u8]) -> Result<bool> {
    let record = String::from_utf8(crypto::json(
        &serde_json::json!({"frame_base64":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,raw)}),
    )?)?;
    let previous: Option<String> = tx.query_row("SELECT record FROM link_frames WHERE request_id=?1 AND role=?2 AND writer_key=?3 AND frame_id=?4",params![frame.request_id,frame.role,frame.writer_public_key,frame.frame_id],|r|r.get(0)).optional()?;
    if let Some(previous) = previous {
        ensure!(previous == record, "immutable frame conflict");
        return Ok(false);
    } else {
        tx.execute("INSERT INTO link_frames(request_id,role,writer_key,frame_id,record) VALUES(?1,?2,?3,?4,?5)",params![frame.request_id,frame.role,frame.writer_public_key,frame.frame_id,record])?;
    }
    Ok(true)
}
