//! Exact shared private signing records. These bytes are never peer authority.
use super::{
    codec::*,
    statement::Descriptor,
    template::{FixedPacket, FixedStatement, StatementSigningSlot},
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provider {
    pub kind: String,
    pub signer_public_key: String,
    pub signature_format: String,
    pub lease_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Template {
    pub slot_id: u64,
    pub object_type: String,
    pub template_base64: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Filled {
    pub slot_id: u64,
    pub role: String,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub format: u64,
    pub operation_id: String,
    pub approved: bool,
    pub approved_at: String,
    pub review_base64: String,
    pub provider: Provider,
    pub root_state_id: String,
    pub person_public_key: String,
    pub host_public_key: String,
    pub device_public_key: String,
    pub scopes: u64,
    pub not_after: String,
    pub created_at: String,
    pub expires_at: String,
    pub templates: Vec<Template>,
    pub signatures: Vec<Filled>,
    pub completed: bool,
    pub terminal: String,
    pub result_base64: String,
}
pub(crate) struct Intent {
    pub id: String,
    pub network_id: String,
    pub context_id: String,
    pub kind: String,
    pub record: Record,
    pub secret: Option<Vec<u8>>,
}
pub(crate) enum FixedObject {
    Statement(FixedStatement),
    Packet(FixedPacket),
}
impl FixedObject {
    pub fn read(d: &Descriptor, kind: &str, raw: &[u8]) -> Result<Self> {
        if let Some(expected) = match kind {
            "selection_packet" => Some("selection"),
            "commit_packet" => Some("commit"),
            "owner_offer_packet" => Some("owner"),
            "administrator_packet" => Some("administrator"),
            "owner_finalization_packet" => Some("owner_finalization"),
            _ => None,
        } {
            let packet = super::transcript::Packet::read_template(raw)?;
            check(text(&packet.object, "role")? == expected)?;
            Ok(Self::Packet(FixedPacket::read(d, raw)?))
        } else {
            let statement = FixedStatement::read(d, raw)?;
            check(statement.typed().kind == kind)?;
            Ok(Self::Statement(statement))
        }
    }
    pub fn pending(&self) -> Result<Vec<StatementSigningSlot>> {
        match self {
            Self::Statement(s) => Ok(s.pending()),
            Self::Packet(p) => p.pending(),
        }
    }
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Statement(s) => s.bytes(),
            Self::Packet(p) => p.bytes(),
        }
    }
    pub fn fill(&self, d: &Descriptor, role: &str, signature: &str) -> Result<Self> {
        match self {
            Self::Statement(s) => Ok(Self::Statement(s.fill(d, role, signature)?)),
            Self::Packet(p) => Ok(Self::Packet(p.fill(d, role, signature)?)),
        }
    }
}
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
impl Intent {
    pub fn objects(&self, d: &Descriptor) -> Result<Vec<Option<FixedObject>>> {
        self.record
            .templates
            .iter()
            .map(|template| {
                if template.template_base64 == "-" {
                    check(
                        !self
                            .record
                            .signatures
                            .iter()
                            .any(|s| s.slot_id == template.slot_id),
                    )?;
                    return Ok(None);
                }
                let mut value = FixedObject::read(
                    d,
                    &template.object_type,
                    &b64(&template.template_base64, MAX_OBJECT)?,
                )?;
                let pending = value.pending()?;
                for signature in self
                    .record
                    .signatures
                    .iter()
                    .filter(|s| s.slot_id == template.slot_id)
                {
                    check(pending.iter().any(|s| s.role == signature.role))?;
                    value = value.fill(d, &signature.role, &signature.signature)?;
                }
                Ok(Some(value))
            })
            .collect()
    }
    pub fn load(connection: &Connection, id: &str) -> Result<Self> {
        type Row = (String, String, String, String, Option<Vec<u8>>);
        let row:Option<Row>=connection.query_row("SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(db)?;
        let (network_id, context_id, kind, raw, secret) =
            row.ok_or_else(|| Error::new("not_found"))?;
        let value = parse(raw.as_bytes(), 32 << 20).map_err(|_| Error::new("state_conflict"))?;
        let record: Record =
            serde_json::from_value(value).map_err(|_| Error::new("state_conflict"))?;
        let value = Self {
            id: id.into(),
            network_id,
            context_id,
            kind,
            record,
            secret,
        };
        value.shape().map_err(|_| Error::new("state_conflict"))?;
        Ok(value)
    }
    pub fn shape(&self) -> Result<()> {
        check(
            self.id.len() == 37
                && self.id.starts_with("dint_")
                && self.id[5..]
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        )?;
        check(
            ident(&self.network_id, "net_")
                && (ident(&self.context_id, "ctx_")
                    || self.kind == "migration_identity" && self.context_id == "-")
                && matches!(
                    self.kind.as_str(),
                    "owner"
                        | "administrator"
                        | "create"
                        | "action"
                        | "policy_claim"
                        | "root_transition"
                        | "migration"
                        | "migration_identity"
                        | "selection"
                        | "requester_commit"
                        | "access_review"
                ),
        )?;
        let r = &self.record;
        check(
            r.format == 1
                && matches!(
                    r.terminal.as_str(),
                    "-" | "applied" | "cancelled" | "expired"
                )
                && r.scopes <= 15,
        )?;
        stamp(&r.created_at)?;
        stamp(&r.expires_at)?;
        check(
            r.created_at < r.expires_at
                && (key(&r.host_public_key)
                    || self.kind == "migration"
                        && r.provider.kind == "root"
                        && r.host_public_key == "-"
                        && r.person_public_key == "-"
                        && r.device_public_key == "-"
                        && r.scopes == 8
                        && ident(&r.operation_id, "ds_")
                        && ident(&r.root_state_id, "ds_"))
                && (r.person_public_key == "-" || key(&r.person_public_key))
                && (r.device_public_key == "-" || key(&r.device_public_key))
                && (r.root_state_id == "-" || ident(&r.root_state_id, "ds_")),
        )?;
        if r.not_after != "-" {
            stamp(&r.not_after)?;
        }
        if r.approved {
            stamp(&r.approved_at)?;
            check(
                r.created_at <= r.approved_at
                    && match self.kind.as_str() {
                        "create" => true,
                        "action" | "policy_claim" | "root_transition" => {
                            r.approved_at <= r.expires_at
                        }
                        _ => r.approved_at < r.expires_at,
                    },
            )?;
        } else {
            check(r.approved_at == "-" && r.signatures.is_empty())?;
        }
        check(
            key(&r.provider.signer_public_key)
                && matches!(r.provider.signature_format.as_str(), "ed25519" | "sshsig"),
        )?;
        check(match r.provider.kind.as_str() {
            "original" => r.provider.signature_format == "sshsig" && r.provider.lease_id == "-",
            "device" => {
                r.provider.signature_format == "ed25519" && ident(&r.provider.lease_id, "ds_")
            }
            "root" => r.provider.lease_id == "-",
            "host" => {
                (self.kind == "migration_identity"
                    || self.kind == "migration"
                        && ident(&r.operation_id, "ds_")
                        && ident(&r.root_state_id, "ds_")
                        && r.person_public_key == "-"
                        && r.device_public_key == "-"
                        && r.scopes == 0
                        && r.templates.len() == 1
                        && matches!(
                            r.templates[0].object_type.as_str(),
                            "host_lease" | "migration_ack"
                        )
                        && r.signatures
                            .iter()
                            .all(|s| s.slot_id == 1 && s.role == "host"))
                    && r.provider.signer_public_key == r.host_public_key
                    && r.provider.signature_format == "ed25519"
                    && r.provider.lease_id == "-"
            }
            "requester" => {
                matches!(self.kind.as_str(), "selection" | "requester_commit")
                    && r.provider.signature_format == "ed25519"
                    && r.provider.lease_id == "-"
                    && r.provider.signer_public_key == r.device_public_key
                    && key(&r.person_public_key)
                    && key(&r.device_public_key)
                    && ident(&r.operation_id, "link_")
            }
            _ => false,
        })?;
        check(
            matches!(self.kind.as_str(), "selection" | "requester_commit")
                == (r.provider.kind == "requester"),
        )?;
        require(
            self.secret.is_none()
                || matches!(
                    self.kind.as_str(),
                    "create" | "root_transition" | "migration_identity"
                ) && self.secret.as_ref().is_some_and(|s| s.len() == 32),
            "state_conflict",
        )?;
        if r.review_base64 != "-" {
            parse(&b64(&r.review_base64, 1 << 20)?, 1 << 20)?;
        }
        if self.kind == "access_review" {
            check(
                ident(&r.operation_id, "arev_")
                    && r.completed
                    && r.terminal == "-"
                    && r.result_base64 == "-"
                    && r.review_base64 != "-"
                    && r.templates.is_empty()
                    && r.signatures.is_empty()
                    && self.secret.is_none()
                    && matches!(r.provider.kind.as_str(), "original" | "device")
                    && key(&r.person_public_key)
                    && key(&r.host_public_key)
                    && ident(&r.root_state_id, "ds_"),
            )?;
        }
        if self.kind == "migration_identity" {
            check(
                self.context_id == "-"
                    && r.operation_id == "-"
                    && r.root_state_id == "-"
                    && r.provider.kind == "host"
                    && r.approved
                    && r.completed
                    && matches!(r.terminal.as_str(), "-" | "applied")
                    && r.review_base64 != "-"
                    && r.result_base64 == "-"
                    && r.not_after == "-"
                    && r.templates.is_empty()
                    && r.signatures.is_empty()
                    && stamp(&r.expires_at)? - stamp(&r.created_at)?
                        == chrono::TimeDelta::seconds(300)
                    && (r.terminal != "applied" || self.secret.is_none())
                    && (r.person_public_key != "-"
                        || r.device_public_key == "-" && r.scopes == 0 && self.secret.is_none()),
            )?;
        }
        let mut previous = None;
        for (index, template) in r.templates.iter().enumerate() {
            check(
                template.slot_id == index as u64 + 1
                    && matches!(
                        template.object_type.as_str(),
                        "root_state"
                            | "selection_packet"
                            | "commit_packet"
                            | "admin_lease"
                            | "person_lease"
                            | "host_lease"
                            | "binding_lease"
                            | "device_lease"
                            | "policy"
                            | "group"
                            | "admin_withdraw"
                            | "person_remove"
                            | "host_revoke"
                            | "host_unbind"
                            | "device_revoke"
                            | "owner_offer_packet"
                            | "administrator_packet"
                            | "owner_finalization_packet"
                            | "migration_proposal"
                            | "migration_ack"
                            | "migration_commit"
                    ),
            )?;
            if template.template_base64 != "-" {
                b64(&template.template_base64, MAX_OBJECT)?;
            }
        }
        for signature in &r.signatures {
            let key = (signature.slot_id, signature.role.as_str());
            check(
                signature.slot_id > 0
                    && signature.slot_id <= r.templates.len() as u64
                    && previous.is_none_or(|old| old < key)
                    && signature.signature != "-",
            )?;
            b64(&signature.signature, 8192)?;
            previous = Some(key);
        }
        if r.result_base64 != "-" {
            check(
                r.terminal == "applied"
                    && r.completed
                    && matches!(self.kind.as_str(), "create" | "action" | "root_transition"),
            )?;
            parse(&b64(&r.result_base64, 32 << 20)?, 32 << 20)?;
        }
        if r.terminal == "applied"
            && matches!(self.kind.as_str(), "create" | "action" | "root_transition")
        {
            check(r.result_base64 != "-" && self.secret.is_none())?;
        }
        Ok(())
    }
    pub fn assembled(&self, d: &Descriptor) -> Result<Vec<FixedStatement>> {
        let mut output = Vec::new();
        for template in &self.record.templates {
            check(template.template_base64 != "-")?;
            let mut value = FixedStatement::read(d, &b64(&template.template_base64, MAX_OBJECT)?)?;
            let original = value.pending();
            check(
                original
                    .iter()
                    .all(|s| s.object_type == template.object_type),
            )?;
            let mut seen = BTreeSet::new();
            for signature in self
                .record
                .signatures
                .iter()
                .filter(|s| s.slot_id == template.slot_id)
            {
                check(
                    original.iter().any(|slot| slot.role == signature.role)
                        && seen.insert(&signature.role),
                )?;
                value = value.fill(d, &signature.role, &signature.signature)?;
            }
            output.push(value);
        }
        Ok(output)
    }
    pub fn save(&self, connection: &Connection) -> Result<()> {
        self.shape()?;
        let raw = serde_json::to_vec(&self.record).map_err(|_| Error::new("internal"))?;
        require(raw.len() <= 32 << 20, "quota_exceeded")?;
        connection.execute("INSERT INTO dec_intents(intent_id,network_id,context_id,kind,record,secret) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(intent_id) DO UPDATE SET record=excluded.record,secret=excluded.secret",rusqlite::params![self.id,self.network_id,self.context_id,self.kind,String::from_utf8(raw).map_err(|_|Error::new("invalid"))?,self.secret]).map_err(db)?;
        Ok(())
    }
}
