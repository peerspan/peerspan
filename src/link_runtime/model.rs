//! Shared schema-19 private records and Unix-only request/review shapes.
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestView {
    pub request_id: String,
    pub mode: String,
    pub state: String,
    pub network_id: String,
    pub person_id: String,
    pub host_id: String,
    pub device_fingerprint: String,
    pub expires_at: String,
    pub completed: Vec<String>,
    pub attention: Vec<String>,
    pub next: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    pub object_type: String,
    pub message_base64: String,
    pub signer_public_key: String,
    pub signature_format: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub mode: String,
    pub network_id: String,
    pub person_public_key: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approve {
    pub code: String,
    pub network_id: String,
    pub expected_person_id: String,
    pub expected_host_key: String,
    pub expected_device_key: String,
    pub signer: String,
    pub approve: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Select {
    pub owner_offer_id: String,
    pub network_id: String,
    pub person_public_key: String,
    pub host_public_key: String,
    pub device_public_key: String,
    pub approve: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub owner_offer_id: String,
    pub selection_id: String,
    pub administrator_offer_id: String,
    pub network_id: String,
    pub person_public_key: String,
    pub host_public_key: String,
    pub device_public_key: String,
    pub approve: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub object_type: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub format: u64,
    pub approved: bool,
    pub epoch: u64,
    pub feature_id: String,
    pub person_public_key: String,
    pub certificate_id: String,
    pub signer_public_key: String,
    pub scopes: u64,
    pub issued_at: String,
    pub not_after: String,
    pub certificate_template_base64: String,
    pub record_template_base64: String,
    pub packet_template_base64: String,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Default)]
pub struct IntentValue(pub Option<Intent>);

impl Serialize for IntentValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.0 {
            Some(intent) => intent.serialize(serializer),
            None => serializer.serialize_str("-"),
        }
    }
}
impl<'de> Deserialize<'de> for IntentValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        if v.as_str() == Some("-") {
            return Ok(Self(None));
        }
        let intent: Intent = serde_json::from_value(v).map_err(de::Error::custom)?;
        if intent.format != 1 {
            return Err(de::Error::custom("invalid intent format"));
        }
        Ok(Self(Some(intent)))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundFrame {
    pub role: String,
    pub writer_public_key: String,
    pub frame_id: String,
    pub published: bool,
    pub sequence: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRecord {
    pub format: u64,
    pub network_base64: String,
    pub expected_network_id: String,
    pub expected_person_public_key: String,
    pub coordinator_address: String,
    pub coordinator_public_key: String,
    pub host_public_key: String,
    pub device_public_key: String,
    pub request_nonce: String,
    pub request_packet_base64: String,
    pub owner_packet_base64: String,
    pub selection_packet_base64: String,
    pub administrator_packet_base64: String,
    pub commit_packet_base64: String,
    pub result_packet_base64: String,
    pub catalog_base64: String,
    pub owner_offer_id: String,
    pub selection_id: String,
    pub administrator_offer_id: String,
    pub manifest_id: String,
    pub after_sequence: u64,
    pub selection_approved: bool,
    pub commit_approved: bool,
    pub owner_intent: IntentValue,
    pub administrator_intent: IntentValue,
    pub outbound_frames: Vec<OutboundFrame>,
}

pub const PENDING_FIELDS: &str = "format network_base64 expected_network_id expected_person_public_key coordinator_address coordinator_public_key host_public_key device_public_key request_nonce request_packet_base64 owner_packet_base64 selection_packet_base64 administrator_packet_base64 commit_packet_base64 result_packet_base64 catalog_base64 owner_offer_id selection_id administrator_offer_id manifest_id after_sequence selection_approved commit_approved owner_intent administrator_intent outbound_frames";

impl Default for PendingRecord {
    fn default() -> Self {
        Self {
            format: 1,
            network_base64: "-".into(),
            expected_network_id: "-".into(),
            expected_person_public_key: "-".into(),
            coordinator_address: "-".into(),
            coordinator_public_key: "-".into(),
            host_public_key: "-".into(),
            device_public_key: "-".into(),
            request_nonce: "-".into(),
            request_packet_base64: "-".into(),
            owner_packet_base64: "-".into(),
            selection_packet_base64: "-".into(),
            administrator_packet_base64: "-".into(),
            commit_packet_base64: "-".into(),
            result_packet_base64: "-".into(),
            catalog_base64: "-".into(),
            owner_offer_id: "-".into(),
            selection_id: "-".into(),
            administrator_offer_id: "-".into(),
            manifest_id: "-".into(),
            after_sequence: 0,
            selection_approved: false,
            commit_approved: false,
            owner_intent: IntentValue::default(),
            administrator_intent: IntentValue::default(),
            outbound_frames: Vec::new(),
        }
    }
}

impl PendingRecord {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let record: Self = crate::linking::decode_stored_json(raw, PENDING_FIELDS)?;
        ensure!(record.format == 1, "invalid pending format");
        Ok(record)
    }

    pub fn transition_from(&self, old: &Self, role: &str) -> bool {
        let fixed = [
            (&old.expected_network_id, &self.expected_network_id),
            (
                &old.expected_person_public_key,
                &self.expected_person_public_key,
            ),
            (&old.coordinator_address, &self.coordinator_address),
            (&old.coordinator_public_key, &self.coordinator_public_key),
            (&old.host_public_key, &self.host_public_key),
            (&old.device_public_key, &self.device_public_key),
            (&old.request_nonce, &self.request_nonce),
            (&old.request_packet_base64, &self.request_packet_base64),
        ];
        let locked = [
            (&old.network_base64, &self.network_base64),
            (&old.selection_packet_base64, &self.selection_packet_base64),
            (
                &old.administrator_packet_base64,
                &self.administrator_packet_base64,
            ),
            (&old.commit_packet_base64, &self.commit_packet_base64),
            (&old.result_packet_base64, &self.result_packet_base64),
            (&old.selection_id, &self.selection_id),
            (&old.administrator_offer_id, &self.administrator_offer_id),
            (&old.manifest_id, &self.manifest_id),
        ];
        self.format == 1
            && (!self.selection_approved || self.selection_packet_base64 != "-")
            && (!self.commit_approved || self.commit_packet_base64 != "-")
            && fixed.iter().all(|(a, b)| a == b)
            && locked.iter().all(|(a, b)| a.as_str() == "-" || a == b)
            && (!(role == "approver" || old.selection_approved)
                || (old.owner_packet_base64 == "-"
                    || old.owner_packet_base64 == self.owner_packet_base64)
                    && (old.owner_offer_id == "-" || old.owner_offer_id == self.owner_offer_id))
            && self.after_sequence >= old.after_sequence
            && (!old.selection_approved || self.selection_approved)
            && (!old.commit_approved || self.commit_approved)
            && intent_transition(&old.owner_intent, &self.owner_intent)
            && intent_transition(&old.administrator_intent, &self.administrator_intent)
            && self.outbound_frames.len() >= old.outbound_frames.len()
            && self.outbound_frames.len() <= 64
            && self.outbound_frames.iter().all(|f| {
                super::crypto::public_key(&f.writer_public_key)
                    && super::crypto::id(&f.frame_id, "")
                    && f.published == (f.sequence > 0)
                    && matches!(
                        f.role.as_str(),
                        "request" | "owner" | "selection" | "administrator" | "commit" | "result"
                    )
            })
            && old
                .outbound_frames
                .iter()
                .zip(&self.outbound_frames)
                .all(|(a, b)| {
                    a.role == b.role
                        && a.writer_public_key == b.writer_public_key
                        && a.frame_id == b.frame_id
                        && (!a.published || b.published)
                        && (a.sequence == 0 || a.sequence == b.sequence)
                })
    }
}

fn intent_transition(old: &IntentValue, next: &IntentValue) -> bool {
    let Some(old) = &old.0 else {
        return next.0.as_ref().is_none_or(|n| n.format == 1);
    };
    let Some(next) = &next.0 else { return false };
    if next.format != 1
        || old.approved && !next.approved
        || old.signatures.len() != next.signatures.len()
        || old.packet_template_base64 != "-"
            && old.packet_template_base64 != next.packet_template_base64
    {
        return false;
    }
    if !old.signatures.iter().zip(&next.signatures).all(|(a, b)| {
        a.object_type == b.object_type && (a.signature == "-" || a.signature == b.signature)
    }) {
        return false;
    }
    let (mut a, mut b) = (old.clone(), next.clone());
    a.approved = false;
    b.approved = false;
    a.packet_template_base64 = "-".into();
    b.packet_template_base64 = "-".into();
    a.signatures.clear();
    b.signatures.clear();
    a == b
}
