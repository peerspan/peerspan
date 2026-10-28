//! Durable requester attempts and public views. Unapproved public packets stay
//! in pending state; opening, displaying or cancelling them grants no authority.
use super::{
    bootstrap::{self, Frame, Invitation, PairingToken},
    codec::*,
    controls,
    statement::Descriptor,
    storage::Snapshot,
    transcript::Packet,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub format: u64,
    pub roles: Vec<String>,
    pub mode: String,
    pub migration_proposal_id: String,
    pub expected_network_id: String,
    pub expected_context_id: String,
    pub expected_person_public_key: String,
    pub contact_invitation_base64: String,
    pub descriptor_base64: String,
    pub host_public_key: String,
    pub device_public_key: String,
    pub request_nonce: String,
    pub request_packet_base64: String,
    pub owner_packet_base64: String,
    pub selection_packet_base64: String,
    pub administrator_packet_base64: String,
    pub owner_finalization_packet_base64: String,
    pub commit_packet_base64: String,
    pub outcome_packet_base64: String,
    pub catalog_base64: String,
    pub owner_offer_id: String,
    pub selection_id: String,
    pub administrator_offer_id: String,
    pub owner_finalization_id: String,
    pub manifest_id: String,
    pub activation_id: String,
    pub selection_approved: bool,
    pub commit_approved: bool,
    pub owner_intent_id: String,
    pub administrator_intent_id: String,
    pub selection_intent_id: String,
    pub commit_intent_id: String,
    pub terminal: String,
    pub carrier_endpoints: Vec<Value>,
    pub outbound_frames: Vec<Value>,
    /// When this host recorded the request's latest stage (spec 8.5); `-`
    /// for a record written before stage times were kept.
    #[serde(default = "empty")]
    pub stage_at: String,
}
/// Each stage times out after 10 minutes of inactivity (spec 8.5).
const STAGE_SECONDS: i64 = 600;
pub(crate) struct Pending {
    pub id: String,
    pub deadline: String,
    pub record: Record,
    pub secret: Option<[u8; 16]>,
    pub terminal_read_cap: Option<[u8; 32]>,
}
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(v: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
fn empty() -> String {
    "-".into()
}
impl Pending {
    fn stages(&self) -> usize {
        let r = &self.record;
        [
            &r.owner_packet_base64,
            &r.selection_packet_base64,
            &r.administrator_packet_base64,
            &r.owner_finalization_packet_base64,
            &r.commit_packet_base64,
        ]
        .iter()
        .filter(|raw| raw.as_str() != "-")
        .count()
    }
    /// Whether the request sat more than 600 seconds after its latest stage
    /// was recorded here, before a commit was persisted (spec 8.5).
    pub(crate) fn stage_expired(&self, now: &str) -> Result<bool> {
        if self.record.commit_packet_base64 != "-" {
            return Ok(false);
        }
        let latest = if self.record.stage_at == "-" {
            text(&self.packet()?.payload, "created_at")?.to_owned()
        } else {
            self.record.stage_at.clone()
        };
        Ok(stamp(now)? - stamp(&latest)? > chrono::TimeDelta::seconds(STAGE_SECONDS))
    }
    pub fn validate(&self) -> Result<()> {
        let r = &self.record;
        check(
            r.format == 1 && ident(&self.id, "link_") && matches!(r.mode.as_str(), "new" | "renew"),
        )?;
        check(matches!(
            r.terminal.as_str(),
            "-" | "applied"
                | "cancelled"
                | "expired"
                | "stopped"
                | "migration_prepared"
                | "migration_adopted"
        ))?;
        let order = ["requester", "owner", "administrator"];
        let indices = r
            .roles
            .iter()
            .map(|role| {
                order
                    .iter()
                    .position(|r| r == role)
                    .ok_or_else(|| Error::new("invalid"))
            })
            .collect::<Result<Vec<_>>>()?;
        check(!indices.is_empty() && indices.windows(2).all(|p| p[0] < p[1]))?;
        let request = Packet::read(&b64(&r.request_packet_base64, 8 << 10)?)?;
        let p = &request.payload;
        check(
            text(&request.object, "role")? == "request"
                && text(&request.object, "request_id")? == self.id
                && text(p, "mode")? == r.mode
                && text(p, "expires_at")? == self.deadline,
        )?;
        for (field, want) in [
            ("migration_proposal_id", r.migration_proposal_id.as_str()),
            ("expected_network_id", &r.expected_network_id),
            ("expected_context_id", &r.expected_context_id),
            ("expected_person_public_key", &r.expected_person_public_key),
            ("host_public_key", &r.host_public_key),
            ("device_public_key", &r.device_public_key),
            ("request_nonce", &r.request_nonce),
        ] {
            check(text(p, field)? == want)?;
        }
        let descriptor = if r.descriptor_base64 == "-" {
            None
        } else {
            Some(Descriptor::read(&b64(&r.descriptor_base64, MAX_OBJECT)?)?)
        };
        if let Some(d) = &descriptor {
            check(
                (r.expected_network_id == "-" || r.expected_network_id == d.network_id)
                    && (r.expected_context_id == "-" || r.expected_context_id == d.context_id()),
            )?;
        }
        if r.contact_invitation_base64 != "-" {
            let invite = Invitation::read(
                &b64(&r.contact_invitation_base64, 32 << 10)?,
                text(p, "created_at")?,
            )?;
            check(
                descriptor
                    .as_ref()
                    .is_some_and(|d| d.context_id() == invite.descriptor.context_id())
                    && r.expected_network_id == invite.descriptor.network_id
                    && r.expected_context_id == invite.descriptor.context_id()
                    && (invite.expected_person_public_key == "-"
                        || invite.expected_person_public_key == r.expected_person_public_key),
            )?;
        }
        for (role, raw, id) in [
            ("owner", &r.owner_packet_base64, &r.owner_offer_id),
            ("selection", &r.selection_packet_base64, &r.selection_id),
            (
                "administrator",
                &r.administrator_packet_base64,
                &r.administrator_offer_id,
            ),
            (
                "owner_finalization",
                &r.owner_finalization_packet_base64,
                &r.owner_finalization_id,
            ),
            ("commit", &r.commit_packet_base64, &r.manifest_id),
            ("outcome", &r.outcome_packet_base64, &r.activation_id),
        ] {
            if raw == "-" {
                if !matches!(role, "commit" | "outcome") {
                    check(id == "-")?;
                }
                continue;
            }
            let packet = Packet::read(&b64(raw, MAX_OBJECT)?)?;
            check(
                text(&packet.object, "role")? == role
                    && text(&packet.object, "request_id")? == self.id,
            )?;
            if let Some(d) = &descriptor {
                check(text(&packet.object, "context_id")? == d.context_id())?;
            }
            if !matches!(role, "commit" | "outcome") {
                check(packet.id == *id)?;
            }
            if matches!(role, "selection" | "commit") {
                check(
                    text(&packet.object, "writer_host_public_key")? == r.host_public_key
                        && text(&packet.object, "signer_public_key")? == r.device_public_key,
                )?;
            }
        }
        for id in [&r.selection_intent_id, &r.commit_intent_id] {
            check(
                id == "-"
                    || id.len() == 37
                        && id.starts_with("dint_")
                        && id[5..]
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            )?;
        }
        check(r.selection_approved == (r.selection_intent_id != "-"))?;
        check(r.commit_approved == (r.commit_intent_id != "-"))?;
        check(!r.commit_approved || r.selection_approved)?;
        if r.roles.iter().any(|role| role == "requester") {
            check(
                (r.selection_packet_base64 == "-" || r.selection_approved)
                    && (r.commit_packet_base64 == "-" || r.commit_approved),
            )?;
        }
        if matches!(r.terminal.as_str(), "cancelled" | "expired") {
            check(
                r.commit_packet_base64 == "-"
                    && self.secret.is_none()
                    && self.terminal_read_cap.is_none(),
            )?;
        }
        if self.terminal_read_cap.is_some() {
            check(
                r.terminal == "applied" && self.secret.is_none() && r.outcome_packet_base64 != "-",
            )?;
        }
        if r.terminal == "applied" {
            check(self.secret.is_none() && r.outcome_packet_base64 != "-")?;
        }
        if r.catalog_base64 != "-" {
            let d = descriptor.as_ref().ok_or_else(|| Error::new("invalid"))?;
            super::catalog::Catalog::read(d, &b64(&r.catalog_base64, MAX_CATALOG)?)?;
        }
        check(r.carrier_endpoints.len() <= 8)?;
        let mut prior = None;
        for value in &r.carrier_endpoints {
            let o = object(value)?;
            fields(o, "kind address public_key")?;
            let tuple = (
                text(o, "kind")?,
                text(o, "address")?,
                text(o, "public_key")?,
            );
            check(
                matches!(tuple.0, "helper" | "participant")
                    && key(tuple.2)
                    && prior.is_none_or(|old| old < tuple),
            )?;
            bootstrap::endpoint(tuple.1)?;
            prior = Some(tuple);
        }
        require(r.outbound_frames.len() <= 64, "quota_exceeded")?;
        let mut seen = std::collections::BTreeSet::new();
        for value in &r.outbound_frames {
            let o = object(value)?;
            fields(o, "role writer_public_key frame_id acknowledged_by")?;
            let tuple = (
                text(o, "role")?,
                text(o, "writer_public_key")?,
                text(o, "frame_id")?,
            );
            check(
                matches!(
                    tuple.0,
                    "request"
                        | "owner"
                        | "selection"
                        | "administrator"
                        | "owner_finalization"
                        | "commit"
                        | "outcome"
                        | "proofs"
                ) && key(tuple.1)
                    && digest(tuple.2)
                    && seen.insert(tuple),
            )?;
            let mut previous = None;
            for ack in array(o, "acknowledged_by")? {
                let a = object(ack)?;
                fields(a, "address public_key")?;
                let pair = (text(a, "address")?, text(a, "public_key")?);
                bootstrap::endpoint(pair.0)?;
                check(key(pair.1) && previous.is_none_or(|old| old < pair))?;
                previous = Some(pair);
            }
        }
        require(bytes(r)?.len() <= 32 << 20, "quota_exceeded")
    }
    pub fn packet(&self) -> Result<Packet> {
        Packet::read(&b64(&self.record.request_packet_base64, 8 << 10)?)
    }
    /// Whether the owner can fold the admin stage into owner finalization
    /// (spec 8.2), judged from the owner offer's own signing path: an
    /// existing person outside renew mode, whose signing device (if any) has
    /// the admin bit, and who holds an admin grant that is the head of its
    /// stream, unexpired at NOW and not withdrawn. Only the display state
    /// uses it; verification is separate.
    fn folds(&self, d: Option<&Descriptor>, now: &str) -> bool {
        let r = &self.record;
        let (Some(d), false) = (d, r.mode == "renew" || r.catalog_base64 == "-") else {
            return false;
        };
        let Ok(owner) = b64(&r.owner_packet_base64, MAX_OBJECT).and_then(|raw| Packet::read(&raw))
        else {
            return false;
        };
        let (Ok(person), Ok(lease), Ok(issuer)) = (
            text(&owner.object, "person_public_key"),
            text(&owner.payload, "person_lease_id"),
            text(&owner.object, "issuer_id"),
        ) else {
            return false;
        };
        let Ok(catalog) = b64(&r.catalog_base64, MAX_CATALOG)
            .and_then(|raw| super::catalog::Catalog::read(d, &raw))
        else {
            return false;
        };
        let statements = &catalog.statements;
        let device_admin = issuer == "-"
            || statements.get(issuer).is_some_and(|device| {
                device
                    .subject()
                    .is_ok_and(|v| num(v, "scopes").is_ok_and(|scopes| scopes & 8 == 8))
            });
        let superseded = |id: &str| {
            statements.values().any(|s| {
                s.payload
                    .get("predecessors")
                    .and_then(Value::as_array)
                    .is_some_and(|p| p.iter().any(|x| x.as_str() == Some(id)))
                    || s.kind == "admin_withdraw"
                        && s.payload
                            .get("target")
                            .and_then(|t| t.get("statement_id"))
                            .and_then(Value::as_str)
                            == Some(id)
            })
        };
        lease != "-"
            && device_admin
            && statements.values().any(|s| {
                s.kind == "admin_lease"
                    && s.subject()
                        .is_ok_and(|v| text(v, "person_public_key").is_ok_and(|k| k == person))
                    && text(&s.payload, "not_after").is_ok_and(|end| now < end)
                    && !superseded(&s.id)
            })
    }
    pub fn view(&self, now: &str) -> Result<Value> {
        let r = &self.record;
        let request = self.packet()?;
        let d = if r.descriptor_base64 == "-" {
            None
        } else {
            Some(Descriptor::read(&b64(&r.descriptor_base64, MAX_OBJECT)?)?)
        };
        let mut completed = vec!["request_created"];
        for (raw, stage) in [
            (&r.owner_packet_base64, "owner_offered"),
            (&r.selection_packet_base64, "owner_selected"),
            (&r.administrator_packet_base64, "administrator_offered"),
            (&r.owner_finalization_packet_base64, "owner_finalized"),
            (&r.commit_packet_base64, "commit_persisted"),
        ] {
            if raw != "-" {
                completed.push(stage);
            }
        }
        let state = match r.terminal.as_str() {
            "applied" => {
                completed.push("locally_applied");
                "linked"
            }
            "migration_prepared" => "migration_prepared",
            "migration_adopted" => "migration_adopted",
            "cancelled" => "cancelled",
            "expired" => "expired",
            "stopped" => "blocked",
            _ => {
                if r.commit_packet_base64 != "-" {
                    "finalizing"
                } else if stamp(now)? >= stamp(&self.deadline)? || self.stage_expired(now)? {
                    "expired"
                } else if r.owner_packet_base64 == "-" {
                    "pending"
                } else if r.selection_packet_base64 == "-" {
                    "needs_selection"
                } else if r.owner_finalization_packet_base64 == "-" {
                    if r.administrator_packet_base64 == "-" && !self.folds(d.as_ref(), now) {
                        "needs_administrator"
                    } else {
                        "needs_owner_finalization"
                    }
                } else {
                    "needs_commit"
                }
            }
        };
        let outcome = if r.outcome_packet_base64 == "-" {
            "-".into()
        } else {
            Packet::read(&b64(&r.outcome_packet_base64, MAX_OBJECT)?)?.id
        };
        let network = d
            .as_ref()
            .map(|d| d.network_id.as_str())
            .unwrap_or(&r.expected_network_id);
        let context = d
            .as_ref()
            .map(Descriptor::context_id)
            .unwrap_or_else(|| r.expected_context_id.clone());
        let person = if r.owner_packet_base64 == "-" {
            r.expected_person_public_key.clone()
        } else {
            text(
                &Packet::read(&b64(&r.owner_packet_base64, MAX_OBJECT)?)?.object,
                "person_public_key",
            )?
            .into()
        };
        let delivery_pending = r.outbound_frames.iter().any(|frame| {
            r.carrier_endpoints.iter().any(|endpoint| {
                !frame["acknowledged_by"].as_array().is_some_and(|list| {
                    list.iter().any(|a| {
                        a["address"] == endpoint["address"]
                            && a["public_key"] == endpoint["public_key"]
                    })
                })
            })
        });
        let attention = if delivery_pending && r.terminal == "-" {
            vec!["delivery_pending".to_owned()]
        } else {
            Vec::new()
        };
        Ok(
            json!({"request_id":self.id,"role":if r.roles.iter().any(|r|r=="requester"){"requester"}else{"approver"},"mode":r.mode,"state":state,"network_id":network,"context_id":context,"migration_proposal_id":r.migration_proposal_id,"person_public_key":person,"host_public_key":r.host_public_key,"device_public_key":r.device_public_key,"created_at":text(&request.payload,"created_at")?,"expires_at":self.deadline,"request_packet_id":request.id,"owner_offer_id":r.owner_offer_id,"selection_id":r.selection_id,"administrator_offer_id":r.administrator_offer_id,"owner_finalization_id":r.owner_finalization_id,"manifest_id":r.manifest_id,"activation_id":r.activation_id,"outcome_id":outcome,"selection_approved":r.selection_approved,"commit_approved":r.commit_approved,"completed":completed,"attention":attention,"next":[]}),
        )
    }
    fn code(&self, connection: &Connection, now: &str) -> Result<Option<String>> {
        if self.record.terminal != "-" || stamp(now)? >= stamp(&self.deadline)? {
            return Ok(None);
        }
        let Some(secret) = &self.secret else {
            return Ok(None);
        };
        let helpers = self
            .record
            .carrier_endpoints
            .iter()
            .filter(|v| v["kind"] == "helper")
            .map(|v| json!({"address":v["address"],"public_key":v["public_key"]}))
            .collect::<Vec<_>>();
        let first = frames(connection, self)?.into_iter().find(|frame| {
            frame.role == "request" && frame.writer_host_public_key == self.record.host_public_key
        });
        let Some(first) = first else {
            require(
                !self.record.roles.iter().any(|r| r == "requester"),
                "proof_required",
            )?;
            return Ok(None);
        };
        let plain = first.open_bytes(secret, now)?;
        let contact_array = super::catalog::raw_field(&plain, "contacts")?;
        let originals: Vec<&RawValue> =
            serde_json::from_slice(&contact_array).map_err(|_| Error::new("invalid"))?;
        let contacts = originals
            .iter()
            .map(|raw| bootstrap::Contact::read(raw.get().as_bytes()))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(PairingToken::encode(
            secret,
            &b64(&self.record.request_packet_base64, 8 << 10)?,
            &contacts,
            &helpers,
            now,
        )?))
    }
}
pub(crate) fn load(c: &Connection, id: &str) -> Result<Pending> {
    check(ident(id, "link_"))?;
    type PendingRow = (String, String, Option<Vec<u8>>, Option<Vec<u8>>);
    let row: Option<PendingRow> = c
        .query_row(
            "SELECT deadline,record,secret,terminal_read_cap FROM dec_pending WHERE request_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(db)?;
    let (deadline, raw, secret, cap) = row.ok_or_else(|| Error::new("not_found"))?;
    let record = serde_json::from_value(parse(raw.as_bytes(), 32 << 20)?)
        .map_err(|_| Error::new("invalid"))?;
    let pending = Pending {
        id: id.into(),
        deadline,
        record,
        secret: secret
            .map(|s| s.try_into().map_err(|_| Error::new("invalid")))
            .transpose()?,
        terminal_read_cap: cap
            .map(|s| s.try_into().map_err(|_| Error::new("invalid")))
            .transpose()?,
    };
    pending.validate()?;
    super::requester::validate_references(c, &pending)?;
    super::ceremony::validate_references(c, &pending)?;
    super::ceremony_admin::validate_references(c, &pending)?;
    frames(c, &pending)?;
    Ok(pending)
}
pub(crate) fn frames(c: &Connection, pending: &Pending) -> Result<Vec<Frame>> {
    let mut query=c.prepare("SELECT role,writer_key,frame_id,record FROM dec_frames WHERE request_id=?1 ORDER BY role,writer_key,frame_id").map_err(db)?;
    let rows = query
        .query_map([&pending.id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(db)?;
    let created = text(&pending.packet()?.payload, "created_at")?.to_owned();
    let mut out = Vec::new();
    let mut total = 0usize;
    for row in rows {
        require(out.len() < 64, "quota_exceeded")?;
        let (role, writer, id, raw) = row.map_err(db)?;
        let value = parse(raw.as_bytes(), 32 << 20)?;
        let record = object(&value)?;
        fields(record, "frame_base64")?;
        let frame = Frame::read(&b64(
            text(record, "frame_base64")?,
            bootstrap::MAX_FRAME_POST,
        )?)?;
        check(
            frame.request_id == pending.id
                && frame.role == role
                && frame.writer_host_public_key == writer
                && frame.frame_id == id
                && frame.created_at == created
                && frame.expires_at == pending.deadline,
        )?;
        if let Some(secret) = &pending.secret {
            check(frame.locator == bootstrap::locator(secret))?;
        }
        total = total
            .checked_add(frame.ciphertext.len())
            .ok_or_else(|| Error::new("quota_exceeded"))?;
        require(total <= 32 << 20, "quota_exceeded")?;
        out.push(frame);
    }
    Ok(out)
}
pub(crate) fn save(c: &Connection, p: &Pending) -> Result<()> {
    p.validate()?;
    // A new stage is recorded only within 600 seconds of the latest one
    // (spec 8.5); its time starts the next stage's window.
    let now = controls::local_decision_time()?;
    let mut record = p.record.clone();
    let old = match load(c, &p.id) {
        Ok(old) => Some(old),
        Err(e) if e.code == "not_found" => None,
        Err(e) => return Err(e),
    };
    match old {
        // The requester recorded its request when it signed it.
        None if p.record.roles.iter().any(|r| r == "requester") => {
            record.stage_at = text(&p.packet()?.payload, "created_at")?.to_owned()
        }
        None => record.stage_at = now,
        Some(old) if p.stages() > old.stages() => {
            require(!old.stage_expired(&now)?, "expired")?;
            record.stage_at = now;
        }
        Some(_) => {}
    }
    let record = String::from_utf8(bytes(&record)?).map_err(|_| Error::new("internal"))?;
    c.execute("INSERT INTO dec_pending(request_id,deadline,record,secret,terminal_read_cap) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(request_id) DO UPDATE SET deadline=excluded.deadline,record=excluded.record,secret=excluded.secret,terminal_read_cap=excluded.terminal_read_cap",rusqlite::params![p.id,p.deadline,record,p.secret.as_ref().map(|s|s.as_slice()),p.terminal_read_cap.as_ref().map(|s|s.as_slice())]).map_err(db)?;
    Ok(())
}
fn ids_in(c: &Connection) -> Result<Vec<String>> {
    let mut q = c
        .prepare("SELECT request_id FROM dec_pending ORDER BY request_id")
        .map_err(db)?;
    q.query_map([], |r| r.get(0))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)
}
fn cleanup(c: &Connection, now: &str) -> Result<()> {
    for id in ids_in(c)? {
        let mut p = load(c, &id)?;
        if p.record.terminal == "migration_prepared" {
            continue;
        }
        // A stage idle for more than 600 seconds ends the request early (spec 8.5).
        if stamp(now)? < stamp(&p.deadline)?
            && !(p.record.terminal == "-" && p.stage_expired(now)?)
        {
            continue;
        }
        if p.record.terminal == "-" && p.record.commit_packet_base64 == "-" {
            p.record.terminal = "expired".into();
        }
        p.secret = None;
        p.terminal_read_cap = None;
        p.record.outbound_frames.clear();
        c.execute("DELETE FROM dec_frames WHERE request_id=?1", [&id])
            .map_err(db)?;
        save(c, &p)?;
        if matches!(p.record.terminal.as_str(), "cancelled" | "expired")
            && stamp(now)? >= stamp(&p.deadline)? + chrono::TimeDelta::hours(24)
        {
            c.execute("DELETE FROM dec_pending WHERE request_id=?1", [id])
                .map_err(db)?;
        }
    }
    Ok(())
}
fn signed_request(
    host: &SigningKey,
    device: &SigningKey,
    payload: &Value,
) -> Result<(String, Vec<u8>)> {
    let raw = bytes(payload)?;
    let id = format!(
        "link_{}",
        hash(&lines(&[
            "peerspan-decentralized-request-id-v1",
            &hash(&raw)
        ]))
    );
    let host_key = encode(host.verifying_key().as_bytes());
    let device_key = encode(device.verifying_key().as_bytes());
    let message = lines(&[
        "peerspan-decentralized-packet-v1",
        "-",
        &id,
        "request",
        &host_key,
        &device_key,
        "-",
        "-",
        "-",
        &hash(&raw),
    ]);
    let packet = bytes(
        &json!({"format":1,"context_id":"-","request_id":id,"role":"request","writer_host_public_key":host_key,"signer_public_key":device_key,"person_public_key":"-","issuer_id":"-","payload_base64":encode(&raw),"host_signature":encode(&host.sign(&message).to_bytes()),"device_signature":encode(&device.sign(&message).to_bytes()),"authority_signature_format":"-","authority_signature":"-"}),
    )?;
    Packet::read(&packet)?;
    Ok((id, packet))
}
pub(crate) fn create(store: &Store, input: &Obj) -> Result<(u16, Vec<u8>)> {
    fields(
        input,
        "mode network_id person_public_key migration_proposal_id contact_invitation helpers",
    )?;
    let mode = text(input, "mode")?;
    check(matches!(mode, "new" | "renew"))?;
    let migration = text(input, "migration_proposal_id")?;
    check(migration == "-" || ident(migration, "ds_"))?;
    check(migration == "-" || mode == "new" && text(input, "contact_invitation")? == "-")?;
    let mut network = text(input, "network_id")?.to_owned();
    let mut person = text(input, "person_public_key")?.to_owned();
    check(network == "-" || ident(&network, "net_"))?;
    check(person == "-" || key(&person))?;
    let mut helpers =
        bootstrap::helpers(input.get("helpers").ok_or_else(|| Error::new("invalid"))?)?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut now = controls::local_decision_time()?;
    let mut context = empty();
    let mut descriptor = empty();
    let mut renewed = empty();
    let mut owned = None;
    let mut staged_catalog = empty();
    let present: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [&network],
            |r| r.get(0),
        )
        .map_err(db)?;
    if migration != "-" {
        let staged = super::migration_link::Owned::load(store, &tx, &network, migration)?;
        let own = &staged.context.own;
        let reviewed = text(own, "person_public_key")?;
        require(person == "-" || person == reviewed, "operation_conflict")?;
        person = reviewed.into();
        now = staged.context.source.time.clone();
        context = staged.context.source.descriptor.context_id();
        descriptor = encode(&bytes(&staged.context.source.descriptor)?);
        staged_catalog = staged.context.record.prepared_catalog_base64.clone();
        owned = Some(staged.device);
    } else if present {
        let s = Snapshot::load(&tx, &network, &store.identity().public_key)?;
        let p = s.project(&now)?;
        now = p.decision_time.clone();
        context = s.descriptor.context_id();
        descriptor = encode(&bytes(&s.descriptor)?);
        let remembered = &s.network.own_identity.person_public_key;
        require(
            person == "-" || remembered == "-" || person == *remembered,
            "forbidden",
        )?;
        if person == "-" && remembered != "-" {
            person = remembered.clone();
        }
        if mode == "renew" {
            let selected = s
                .selection
                .as_ref()
                .ok_or_else(|| Error::new("not_found"))?;
            require(
                selected.kind == "device" && selected.person_key == person,
                "forbidden",
            )?;
            p.member_for(&store.identity().public_key, &person)?;
            let prior = p.catalog.get(&selected.lease_id)?;
            require(
                prior.kind == "device_lease"
                    && text(prior.subject()?, "host_public_key")? == store.identity().public_key
                    && text(prior.subject()?, "device_public_key")? == selected.device_key,
                "forbidden",
            )?;
            for restriction in &p.restrictions {
                let r = p.catalog.get(restriction)?;
                if r.kind == "device_revoke" {
                    let target = object(
                        r.payload
                            .get("target")
                            .ok_or_else(|| Error::new("invalid"))?,
                    )?;
                    require(
                        text(target, "device_public_key")? != selected.device_key,
                        "device_revoked",
                    )?;
                }
            }
            let seed: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT seed FROM link_device_keys WHERE public_key=?1",
                    [&selected.device_key],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db)?;
            let seed: [u8; 32] = seed
                .ok_or_else(|| Error::new("signer_unavailable"))?
                .try_into()
                .map_err(|_| Error::new("signer_unavailable"))?;
            let key = SigningKey::from_bytes(&seed);
            require(
                encode(key.verifying_key().as_bytes()) == selected.device_key,
                "signer_unavailable",
            )?;
            owned = Some(key);
            renewed = selected.lease_id.clone();
        }
    } else {
        require(mode == "new", "not_found")?;
    }
    let invitation = if text(input, "contact_invitation")? == "-" {
        None
    } else {
        Some(Invitation::read_token(
            text(input, "contact_invitation")?,
            &now,
        )?)
    };
    if let Some(i) = &invitation {
        check(
            mode == "new"
                && (network == "-" || network == i.descriptor.network_id)
                && (context == "-" || context == i.descriptor.context_id())
                && (i.expected_person_public_key == "-" || person == i.expected_person_public_key),
        )?;
        network = i.descriptor.network_id.clone();
        context = i.descriptor.context_id();
        descriptor = encode(&bytes(&i.descriptor)?);
        helpers.extend(i.helpers.clone());
        helpers.sort_by_key(|v| {
            (
                v["address"].as_str().unwrap_or_default().to_owned(),
                v["public_key"].as_str().unwrap_or_default().to_owned(),
            )
        });
        helpers.dedup();
        bootstrap::helpers(&Value::Array(helpers.clone()))?;
    }
    cleanup(&tx, &now)?;
    let mut carrier_endpoints = helpers
        .iter()
        .map(|h| json!({"kind":"helper","address":h["address"],"public_key":h["public_key"]}))
        .collect::<Vec<_>>();
    let contact_invitation_base64 = invitation
        .as_ref()
        .map(|i| encode(&i.body))
        .unwrap_or_else(empty);
    for id in ids_in(&tx)? {
        let p = load(&tx, &id)?;
        let r = &p.record;
        if r.roles.iter().any(|r| r == "requester")
            && r.terminal == "-"
            && r.mode == mode
            && r.migration_proposal_id == migration
            && r.expected_network_id == network
            && r.expected_context_id == context
            && r.expected_person_public_key == person
            && r.contact_invitation_base64 == contact_invitation_base64
        {
            require(
                r.carrier_endpoints
                    .iter()
                    .filter(|e| e["kind"] == "helper")
                    .eq(carrier_endpoints.iter()),
                "operation_conflict",
            )?;
            let mut view = p.view(&now)?;
            let code = p
                .code(&tx, &now)?
                .ok_or_else(|| Error::new("recovery_required"))?;
            view["display_code"] = Value::from(code);
            tx.commit().map_err(db)?;
            return Ok((200, bytes(&view)?));
        }
    }
    let rows = ids_in(&tx)?;
    require(rows.len() < 4096, "quota_exceeded")?;
    let active = rows
        .iter()
        .map(|id| load(&tx, id))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .filter(|p| matches!(p.record.terminal.as_str(), "-" | "migration_prepared"))
        .count();
    require(active < 8, "quota_exceeded")?;
    let contact = super::bootstrap_io::own_contact(&tx, store, &now, &network, &context)?;
    for address in array(object(&contact.payload)?, "bootstrap_addresses")? {
        carrier_endpoints.push(
            json!({"kind":"participant","address":address,"public_key":contact.host_public_key}),
        );
    }
    if let Some(invitation) = &invitation {
        for contact in &invitation.contacts {
            for address in array(object(&contact.payload)?, "bootstrap_addresses")? {
                carrier_endpoints.push(json!({"kind":"participant","address":address,"public_key":contact.host_public_key}));
            }
        }
    }
    carrier_endpoints.sort_by_key(|e| {
        (
            e["kind"].as_str().unwrap_or_default().to_owned(),
            e["address"].as_str().unwrap_or_default().to_owned(),
            e["public_key"].as_str().unwrap_or_default().to_owned(),
        )
    });
    carrier_endpoints.dedup();
    require(carrier_endpoints.len() <= 8, "quota_exceeded")?;
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| Error::new("internal"))?;
    let device = owned.unwrap_or_else(|| SigningKey::from_bytes(&random));
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::new("internal"))?;
    let mut secret = [0u8; 16];
    getrandom::fill(&mut secret).map_err(|_| Error::new("internal"))?;
    let deadline = (stamp(&now)? + chrono::TimeDelta::seconds(super::bootstrap::REQUEST_WINDOW))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let host = store.identity().public_key;
    let device_public_key = encode(device.verifying_key().as_bytes());
    let payload = json!({"mode":mode,"host_public_key":host,"device_public_key":device_public_key,"request_nonce":encode(&nonce),"expected_network_id":network,"expected_context_id":context,"expected_person_public_key":person,"migration_proposal_id":migration,"renewed_device_lease_id":renewed,"created_at":now,"expires_at":deadline});
    let (id, packet) = signed_request(&store.signing_key, &device, &payload)?;
    let frame = Frame::seal(
        &secret,
        &id,
        "request",
        &store.signing_key,
        (&now, &deadline),
        &now,
        &json!({"packet_base64":encode(&packet),"catalog_base64":"-","contacts":[parse(&contact.body,8<<10)?]}),
    )?;
    let record = Record {
        format: 1,
        roles: vec!["requester".into()],
        mode: mode.into(),
        migration_proposal_id: migration.into(),
        expected_network_id: network.clone(),
        expected_context_id: context.clone(),
        expected_person_public_key: person,
        contact_invitation_base64,
        descriptor_base64: descriptor,
        host_public_key: host.clone(),
        device_public_key: device_public_key.clone(),
        request_nonce: encode(&nonce),
        request_packet_base64: encode(&packet),
        owner_packet_base64: empty(),
        selection_packet_base64: empty(),
        administrator_packet_base64: empty(),
        owner_finalization_packet_base64: empty(),
        commit_packet_base64: empty(),
        outcome_packet_base64: empty(),
        catalog_base64: staged_catalog,
        owner_offer_id: empty(),
        selection_id: empty(),
        administrator_offer_id: empty(),
        owner_finalization_id: empty(),
        manifest_id: empty(),
        activation_id: empty(),
        selection_approved: false,
        commit_approved: false,
        owner_intent_id: empty(),
        administrator_intent_id: empty(),
        selection_intent_id: empty(),
        commit_intent_id: empty(),
        terminal: empty(),
        carrier_endpoints,
        outbound_frames: vec![
            json!({"role":"request","writer_public_key":host,"frame_id":frame.frame_id,"acknowledged_by":[]}),
        ],
        stage_at: empty(),
    };
    let p = Pending {
        id: id.clone(),
        deadline,
        record,
        secret: Some(secret),
        terminal_read_cap: None,
    };
    if migration == "-" {
        tx.execute("INSERT INTO link_device_keys(public_key,seed,created_at) VALUES(?1,?2,?3) ON CONFLICT(public_key) DO NOTHING",rusqlite::params![device_public_key,device.to_bytes().as_slice(),now]).map_err(db)?;
    }
    save(&tx, &p)?;
    tx.execute("INSERT INTO dec_frames(request_id,role,writer_key,frame_id,record) VALUES(?1,'request',?2,?3,?4)",rusqlite::params![id,host,frame.frame_id,json!({"frame_base64":encode(&frame.body)}).to_string()]).map_err(db)?;
    if present {
        tx.execute(
            "UPDATE dec_clock SET record=?2 WHERE network_id=?1",
            rusqlite::params![
                network,
                json!({"format":1,"largest_local_time":now}).to_string()
            ],
        )
        .map_err(db)?;
    }
    let mut view = p.view(&now)?;
    view["display_code"] = Value::from(p.code(&tx, &now)?.ok_or_else(|| Error::new("internal"))?);
    tx.commit().map_err(db)?;
    drop(c);
    controls::barrier(store, "dec.frame.after_commit", &id)?;
    controls::barrier(store, "dec.request.after_commit", &id)?;
    Ok((201, bytes(&view)?))
}
pub(crate) fn get(store: &Store, id: Option<&str>, display: bool) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let now = controls::local_decision_time()?;
    let result = if let Some(id) = id {
        let p = load(&tx, id)?;
        let mut view = p.view(&now)?;
        if display && let Some(code) = p.code(&tx, &now)? {
            view["display_code"] = Value::from(code);
        }
        bytes(&view)
    } else {
        bytes(
            &ids_in(&tx)?
                .iter()
                .map(|id| load(&tx, id)?.view(&now))
                .collect::<Result<Vec<_>>>()?,
        )
    }?;
    tx.commit().map_err(db)?;
    Ok(result)
}
pub(crate) fn resume(store: &Store, id: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    load(&tx, id)?;
    cleanup(&tx, &controls::local_decision_time()?)?;
    tx.commit().map_err(db)?;
    drop(c);
    get(store, Some(id), true)
}
pub(crate) fn cancel(store: &Store, id: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = load(&tx, id)?;
    require(
        p.record.commit_packet_base64 == "-"
            && !matches!(
                p.record.terminal.as_str(),
                "applied" | "migration_prepared" | "migration_adopted"
            ),
        "operation_conflict",
    )?;
    p.record.terminal = "cancelled".into();
    p.secret = None;
    p.terminal_read_cap = None;
    p.record.outbound_frames.clear();
    save(&tx, &p)?;
    tx.execute("DELETE FROM dec_frames WHERE request_id=?1", [id])
        .map_err(db)?;
    let view = p.view(&controls::local_decision_time()?)?;
    tx.commit().map_err(db)?;
    bytes(&view)
}
