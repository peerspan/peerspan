use super::codec::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format: u64,
    pub protocol: String,
    pub network_id: String,
    pub name: String,
    pub genesis_root_public_key: String,
}
impl Descriptor {
    pub fn read(bytes: &[u8]) -> Result<Self> {
        let value = parse(bytes, MAX_OBJECT)?;
        Self::from_value(&value)
    }
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let o = object(value)?;
        fields(o, "format protocol network_id name genesis_root_public_key")?;
        version(o)?;
        check(text(o, "protocol")? == "peerspan-decentralized-v1")?;
        let descriptor: Self =
            serde_json::from_value(value.clone()).map_err(|_| Error::new("invalid"))?;
        label(&descriptor.name)?;
        check(key(&descriptor.genesis_root_public_key))?;
        let genesis = b64(&descriptor.genesis_root_public_key, 32)?;
        check(descriptor.network_id == crate::membership::network_id(&genesis))?;
        Ok(descriptor)
    }
    pub fn context_id(&self) -> String {
        format!(
            "ctx_{}",
            hash(&lines(&[
                "peerspan-decentralized-context-v1",
                &self.protocol,
                &self.network_id,
                &self.name,
                &self.genesis_root_public_key
            ]))
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub role: String,
    pub public_key: String,
    pub format: String,
    pub signature: String,
}
#[derive(Clone, Debug)]
pub struct Statement {
    pub kind: String,
    pub context_id: String,
    pub id: String,
    pub proof_id: String,
    pub body: Vec<u8>,
    pub payload_bytes: Vec<u8>,
    pub payload: Obj,
    pub signatures: BTreeMap<String, SignatureEntry>,
}
impl Statement {
    pub fn read(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        Self::read_draft(descriptor, bytes, false)
    }
    pub(crate) fn read_draft(
        descriptor: &Descriptor,
        bytes: &[u8],
        binding_draft: bool,
    ) -> Result<Self> {
        Self::read_mode(descriptor, bytes, binding_draft, false)
    }
    pub(crate) fn read_template(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        Self::read_mode(descriptor, bytes, false, true)
    }
    fn read_mode(
        descriptor: &Descriptor,
        bytes: &[u8],
        binding_draft: bool,
        template: bool,
    ) -> Result<Self> {
        Self::read_pinned(
            Some(descriptor),
            &descriptor.context_id(),
            bytes,
            binding_draft,
            template,
        )
    }
    // Context-only inspection is confined to fixed link-ceremony lease
    // templates. It cannot decode root/access/migration authority or produce
    // an ordinary admitted catalog entry without the real descriptor.
    pub(crate) fn read_link_template(context: &str, bytes: &[u8]) -> Result<Self> {
        check(ident(context, "ctx_"))?;
        let s = Self::read_pinned(None, context, bytes, false, true)?;
        check(ident(text(&s.payload, "operation_id")?, "link_"))?;
        Ok(s)
    }
    fn read_pinned(
        descriptor: Option<&Descriptor>,
        expected_context: &str,
        bytes: &[u8],
        binding_draft: bool,
        template: bool,
    ) -> Result<Self> {
        let value = parse(bytes, MAX_OBJECT)?;
        let o = object(&value)?;
        fields(o, "format kind context_id payload_base64 signatures")?;
        version(o)?;
        let kind = text(o, "kind")?;
        let context = text(o, "context_id")?;
        check(context == expected_context)?;
        let payload_bytes = b64(text(o, "payload_base64")?, MAX_PAYLOAD)?;
        let payload = object(&parse(&payload_bytes, MAX_PAYLOAD)?)?.clone();
        validate_pinned_payload(descriptor, kind, &payload)?;
        let id = statement_id(kind, context, &payload_bytes);
        let mut signatures = BTreeMap::new();
        let mut previous = "";
        for sig in array(o, "signatures")? {
            let entry = object(sig)?;
            fields(entry, "role public_key format signature")?;
            let role = text(entry, "role")?;
            check(role > previous)?;
            previous = role;
            let public = text(entry, "public_key")?;
            let format = text(entry, "format")?;
            let message = signature_message(&id, role, public);
            let encoded = text(entry, "signature")?;
            if template && encoded == "-" {
                check(key(public) && matches!(format, "ed25519" | "sshsig"))?;
            } else if binding_draft && kind == "binding_lease" && role == "host" {
                check(encoded == "-")?;
            } else {
                signature(public, format, &message, encoded)?;
            }
            let signature: SignatureEntry =
                serde_json::from_value(sig.clone()).map_err(|_| Error::new("invalid"))?;
            signatures.insert(role.into(), signature);
        }
        let expected = signature_roles(kind, &payload)?;
        let actual = signatures.keys().cloned().collect::<Vec<_>>();
        // A deadline-only renewal of a host grant or binding carries only the
        // issuer's signature (DEC-Q28); the verifier checks it moves only the
        // deadline.
        check(actual == expected || renewal_candidate(kind, &payload)? && actual == ["issuer"])?;
        let statement = Self {
            kind: kind.into(),
            context_id: context.into(),
            id,
            proof_id: proof_id(kind, bytes),
            body: bytes.into(),
            payload_bytes,
            payload,
            signatures,
        };
        if let Some(retained) = statement.payload.get("retained_statement_ids") {
            check(
                !retained
                    .as_array()
                    .ok_or_else(|| Error::new("invalid"))?
                    .contains(&Value::from(statement.id.clone())),
            )?;
        }
        statement.intrinsic_signers(descriptor)?;
        Ok(statement)
    }
    /// Whether parent `role` does not cap this statement's deadline: the
    /// issuer device of a deadline-only binding or device renewal signed by
    /// a device (spec 4.4, 7.1; DEC-Q7, DEC-Q27).
    pub fn uncapped_parent(&self, role: &str) -> bool {
        role == "issuer_device"
            && matches!(self.kind.as_str(), "binding_lease" | "device_lease")
            && renewal_candidate(&self.kind, &self.payload).unwrap_or(false)
            && (self.kind == "device_lease" || !self.signatures.contains_key("host"))
            && self
                .issuer()
                .is_ok_and(|i| text(i, "kind").is_ok_and(|k| k == "device"))
    }
    pub fn signer(&self, role: &str) -> Result<&SignatureEntry> {
        self.signatures
            .get(role)
            .ok_or_else(|| Error::new("invalid"))
    }
    pub fn stream(&self) -> Result<Option<Vec<String>>> {
        let p = &self.payload;
        let subject = || object(p.get("subject").ok_or_else(|| Error::new("invalid"))?);
        let pair = |kind: &str, key: &str| Ok(Some(vec![kind.into(), key.into()]));
        match self.kind.as_str() {
            "root_state" => Ok(Some(vec!["root".into()])),
            "admin_lease" => pair("admin", text(subject()?, "person_public_key")?),
            "person_lease" => pair("person", text(subject()?, "person_public_key")?),
            "host_lease" => pair("host", text(subject()?, "host_public_key")?),
            "binding_lease" => pair("binding", text(subject()?, "host_public_key")?),
            "device_lease" => Ok(Some(vec![
                "device".into(),
                text(subject()?, "person_public_key")?.into(),
                text(subject()?, "device_public_key")?.into(),
            ])),
            "policy" => {
                let b = access_body(p)?;
                pair("policy", text(&b, "person_public_key")?)
            }
            "group" => {
                let b = access_body(p)?;
                pair("group", text(&b, "name")?)
            }
            _ => Ok(None),
        }
    }
    pub fn sequence(&self) -> Result<u64> {
        num(
            &self.payload,
            if self.kind == "root_state" {
                "epoch"
            } else {
                "sequence"
            },
        )
    }
    pub fn parents(&self) -> Result<BTreeMap<String, String>> {
        parents(&self.payload)
    }
    pub fn issued_at(&self) -> Result<&str> {
        text(&self.payload, "issued_at")
    }
    pub fn issuer(&self) -> Result<&Obj> {
        object(
            self.payload
                .get("issuer")
                .ok_or_else(|| Error::new("invalid"))?,
        )
    }
    pub fn subject(&self) -> Result<&Obj> {
        object(
            self.payload
                .get("subject")
                .ok_or_else(|| Error::new("invalid"))?,
        )
    }
    fn intrinsic_signers(&self, descriptor: Option<&Descriptor>) -> Result<()> {
        let p = &self.payload;
        if self.kind == "root_state" {
            if array(p, "predecessors")?.is_empty() {
                check(self.signer("issuer")?.public_key == text(p, "root_public_key")?)?;
                if text(p, "migration_proposal_id")? == "-" {
                    check(
                        text(p, "root_public_key")?
                            == descriptor
                                .ok_or_else(|| Error::new("invalid"))?
                                .genesis_root_public_key,
                    )?;
                }
            }
            if let Some(sig) = self.signatures.get("new_root") {
                check(sig.public_key == text(p, "root_public_key")?)?;
            }
        } else if matches!(self.kind.as_str(), "migration_ack") {
            check(
                self.signer("host")?.public_key == text(p, "host_public_key")?
                    && self.signer("host")?.format == "ed25519",
            )?;
            if let Some(device) = self.signatures.get("device") {
                check(
                    device.public_key == text(p, "device_public_key")?
                        && device.format == "ed25519",
                )?;
            }
        } else if self.kind == "migration_proposal" {
            check(self.signer("issuer")?.public_key == text(p, "legacy_root_public_key")?)?;
        } else if !self.kind.starts_with("migration_") {
            let issuer = self.issuer()?;
            let sig = self.signer("issuer")?;
            match text(issuer, "kind")? {
                "person" => check(
                    sig.public_key == text(issuer, "person_public_key")? && sig.format == "sshsig",
                )?,
                "device" => check(sig.format == "ed25519")?,
                "root" => {}
                _ => return Err(Error::new("invalid")),
            }
            if let Some(host) = self.signatures.get("host") {
                check(
                    host.public_key == text(self.subject()?, "host_public_key")?
                        && host.format == "ed25519",
                )?;
            }
        }
        Ok(())
    }
    pub fn response(&self) -> Value {
        json!({"ok":true,"context_id":self.context_id,"statement_kind":self.kind,"statement_id":self.id,"proof_id":self.proof_id,"payload_base64":encode(&self.payload_bytes),"signers":self.signatures.values().map(|s|json!({"role":s.role,"public_key":s.public_key,"signature_format":s.format})).collect::<Vec<_>>()})
    }
}
pub fn statement_id(kind: &str, context: &str, payload: &[u8]) -> String {
    format!(
        "ds_{}",
        hash(&lines(&[
            "peerspan-decentralized-statement-v1",
            kind,
            context,
            &hash(payload)
        ]))
    )
}
pub fn proof_id(kind: &str, body: &[u8]) -> String {
    format!(
        "dp_{}",
        hash(&lines(&[
            "peerspan-decentralized-proof-v1",
            kind,
            &hash(body)
        ]))
    )
}
pub fn signature_message(id: &str, role: &str, public: &str) -> Vec<u8> {
    lines(&["peerspan-decentralized-signature-v1", id, role, public])
}
pub fn restriction(kind: &str) -> bool {
    matches!(
        kind,
        "admin_withdraw" | "person_remove" | "host_revoke" | "host_unbind" | "device_revoke"
    )
}
pub fn lease(kind: &str) -> bool {
    matches!(
        kind,
        "admin_lease" | "person_lease" | "host_lease" | "binding_lease" | "device_lease"
    )
}
pub(crate) fn parents(p: &Obj) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut previous = "";
    for v in array(p, "parents")? {
        let o = object(v)?;
        fields(o, "role id")?;
        let role = text(o, "role")?;
        let id = text(o, "id")?;
        check(
            role > previous
                && [
                    "issuer_admin",
                    "issuer_device",
                    "issuer_person",
                    "subject_binding",
                    "subject_host",
                    "subject_person",
                ]
                .contains(&role)
                && ident(id, "ds_"),
        )?;
        previous = role;
        result.insert(role.into(), id.into());
    }
    Ok(result)
}
fn issuer(p: &Obj) -> Result<&Obj> {
    let o = object(p.get("issuer").ok_or_else(|| Error::new("invalid"))?)?;
    fields(o, "kind person_public_key")?;
    let kind = text(o, "kind")?;
    let person = text(o, "person_public_key")?;
    check(
        matches!(kind, "root" | "person" | "device")
            && if kind == "root" {
                person == "-"
            } else {
                key(person)
            },
    )?;
    parents(p)?;
    Ok(o)
}
fn reference(p: &Obj, name: &str, prefix: &str, absent: bool) -> Result<()> {
    let s = text(p, name)?;
    check(ident(s, prefix) || (absent && s == "-"))
}
fn interval(p: &Obj, max: i64) -> Result<()> {
    let issued = stamp(text(p, "issued_at")?)?;
    let start = stamp(text(p, "not_before")?)?;
    let end = stamp(text(p, "not_after")?)?;
    check(issued <= start && start < end && end.signed_duration_since(issued).num_seconds() <= max)
}
fn common_stream(p: &Obj) -> Result<()> {
    check(num(p, "sequence")? > 0)?;
    let predecessors = ids(p, "predecessors", "ds_")?;
    let resolves = ids(p, "resolves", "ds_")?;
    if predecessors.len() > 1 {
        check(predecessors.iter().all(|id| resolves.contains(id)))?;
    }

    reference(p, "root_state_id", "ds_", false)
}
/// A grant that may be a deadline-only renewal (spec 7.1, DEC-Q6, DEC-Q28):
/// `operation_id` `-` and a later generation of an existing stream.
pub(crate) fn renewal_candidate(kind: &str, p: &Obj) -> Result<bool> {
    Ok(
        matches!(kind, "host_lease" | "binding_lease" | "device_lease")
            && text(p, "operation_id")? == "-"
            && !ids(p, "predecessors", "ds_")?.is_empty(),
    )
}
fn signature_roles(kind: &str, p: &Obj) -> Result<Vec<String>> {
    let mut roles = vec!["issuer".into()];
    match kind {
        "root_state" => {
            let predecessors = ids(p, "predecessors", "ds_")?;
            if predecessors.len() >= 2 {
                roles = predecessors
                    .iter()
                    .map(|id| format!("root_branch:{id}"))
                    .collect();
                roles.push("new_root".into());
            } else if predecessors.len() == 1 {
                roles.push("new_root".into());
            }
        }
        "host_lease" => {
            if text(p, "operation_id")? == "-" || ident(text(p, "operation_id")?, "ds_") {
                roles.push("host".into());
            }
        }
        "binding_lease" => {
            roles.push("host".into());
        }
        "migration_ack" => {
            roles = vec!["host".into()];
            if text(p, "device_public_key")? != "-" {
                roles.push("device".into());
            }
        }
        _ => {}
    }
    roles.sort();
    Ok(roles)
}
pub(crate) fn access_body(p: &Obj) -> Result<Obj> {
    Ok(object(&parse(
        &b64(text(p, "body_base64")?, MAX_PAYLOAD)?,
        MAX_PAYLOAD,
    )?)?
    .clone())
}
pub(crate) fn validate_payload(d: &Descriptor, kind: &str, p: &Obj) -> Result<()> {
    validate_pinned_payload(Some(d), kind, p)
}
fn validate_pinned_payload(d: Option<&Descriptor>, kind: &str, p: &Obj) -> Result<()> {
    if d.is_none() {
        check(matches!(
            kind,
            "person_lease" | "host_lease" | "binding_lease" | "device_lease"
        ))?;
    }
    match kind {
        "root_state" => {
            fields(
                p,
                "epoch predecessors resolves migration_proposal_id root_public_key issued_at retained_statement_ids",
            )?;
            check(key(text(p, "root_public_key")?))?;
            stamp(text(p, "issued_at")?)?;
            let predecessors = ids(p, "predecessors", "ds_")?;
            let resolves = ids(p, "resolves", "ds_")?;
            let retained = ids(p, "retained_statement_ids", "ds_")?;
            reference(p, "migration_proposal_id", "ds_", true)?;
            if predecessors.is_empty() {
                check(resolves.is_empty() && retained.is_empty())?;
                if text(p, "migration_proposal_id")? == "-" {
                    check(
                        num(p, "epoch")? == 0
                            && text(p, "root_public_key")?
                                == d.ok_or_else(|| Error::new("invalid"))?
                                    .genesis_root_public_key,
                    )?;
                }
            } else {
                check(text(p, "migration_proposal_id")? == "-" && num(p, "epoch")? > 0)?;
                if predecessors.len() == 1 {
                    check(resolves.is_empty())?;
                } else {
                    check(resolves == predecessors)?;
                }
            }
        }
        k if lease(k) => {
            fields(
                p,
                "root_state_id operation_id sequence predecessors resolves retained_statement_ids subject issuer parents issued_at not_before not_after",
            )?;
            common_stream(p)?;
            ids(p, "retained_statement_ids", "ds_")?;
            let op = text(p, "operation_id")?;
            check(op == "-" || ident(op, "link_") || kind == "host_lease" && ident(op, "ds_"))?;
            if kind == "device_lease" {
                // `-` only for the creator device grant (DEC-Q21), sequence 1.
                // ... and for a deadline-only renewal (DEC-Q6), a later
                // generation.
                check(
                    ident(op, "link_")
                        || op == "-"
                            && (p.get("sequence").and_then(Value::as_u64) == Some(1)
                                && ids(p, "predecessors", "ds_")?.is_empty()
                                || !ids(p, "predecessors", "ds_")?.is_empty()),
                )?;
            }
            if kind == "admin_lease" {
                check(op == "-")?;
            }
            let subject = object(p.get("subject").ok_or_else(|| Error::new("invalid"))?)?;
            fields(
                subject,
                "person_public_key host_public_key device_public_key member scopes",
            )?;
            let person = text(subject, "person_public_key")?;
            let host = text(subject, "host_public_key")?;
            let device = text(subject, "device_public_key")?;
            let member = text(subject, "member")?;
            let scopes = num(subject, "scopes")?;
            check(if kind == "host_lease" {
                person == "-"
            } else {
                key(person)
            })?;
            check(
                if matches!(kind, "host_lease" | "binding_lease" | "device_lease") {
                    key(host)
                } else {
                    host == "-"
                },
            )?;
            check(if kind == "device_lease" {
                key(device) && device != host && device != person
            } else {
                device == "-"
            })?;
            if matches!(kind, "host_lease" | "person_lease") {
                label(member)?;
            } else {
                check(member == "-")?;
            }
            check(match kind {
                "admin_lease" => scopes == 8,
                "binding_lease" => scopes == 2,
                "device_lease" => (1..=15).contains(&scopes),
                _ => scopes == 0,
            })?;
            let issuer = issuer(p)?;
            let ik = text(issuer, "kind")?;
            check(if kind == "admin_lease" {
                ik == "root"
            } else if matches!(kind, "binding_lease" | "device_lease") {
                ik != "root" && text(issuer, "person_public_key")? == person
            } else {
                true
            })?;
            interval(p, 604800)?;
            exact_parents(kind, p)?;
        }
        "policy" | "group" => {
            fields(
                p,
                "root_state_id operation_id sequence predecessors resolves issuer parents issued_at not_before not_after body_base64",
            )?;
            common_stream(p)?;
            check(text(p, "operation_id")? == "-")?;
            interval(p, 86400)?;
            let issuer = issuer(p)?;
            check(kind != "policy" || text(issuer, "kind")? != "root")?;
            exact_parents(kind, p)?;
            let body = access_body(p)?;
            if kind == "policy" {
                fields(
                    &body,
                    "format network_id person_public_key version issued_at valid_until rules capability_rules trusted_hosts edits",
                )?;
                check(
                    num(&body, "format")? == 2
                        && text(&body, "person_public_key")? == text(issuer, "person_public_key")?,
                )?;
                let policy: crate::policy::PolicyBody =
                    serde_json::from_value(Value::Object(body.clone()))
                        .map_err(|_| Error::new("invalid"))?;
                policy
                    .check_decentralized_shape()
                    .map_err(|_| Error::new("invalid"))?;
                check(
                    text(&body, "issued_at")? == text(p, "issued_at")?
                        && text(&body, "valid_until")? == text(p, "not_after")?,
                )?;
            } else {
                fields(&body, "network_id name version defined_at members")?;
                crate::admins::group_name(text(&body, "name")?)
                    .map_err(|_| Error::new("invalid"))?;
                ids(&body, "members", "person_")?;
                check(text(&body, "defined_at")? == text(p, "issued_at")?)?;
            }
            check(
                text(&body, "network_id")? == d.ok_or_else(|| Error::new("invalid"))?.network_id
                    && num(&body, "version")? == num(p, "sequence")?,
            )?;
        }
        k if restriction(k) => {
            fields(
                p,
                "root_state_id issuer parents issued_at target kept_statement_ids ratifies",
            )?;
            reference(p, "root_state_id", "ds_", false)?;
            stamp(text(p, "issued_at")?)?;
            reference(p, "ratifies", "ds_", true)?;
            let issuer = issuer(p)?;
            let ik = text(issuer, "kind")?;
            check(if kind == "admin_withdraw" {
                ik == "root"
            } else if matches!(kind, "host_unbind" | "device_revoke") {
                ik != "root"
            } else {
                true
            })?;
            exact_parents(kind, p)?;
            let target = object(p.get("target").ok_or_else(|| Error::new("invalid"))?)?;
            fields(
                target,
                "statement_id person_public_key host_public_key device_public_key",
            )?;
            let wanted = match kind {
                "admin_withdraw" => [true, true, false, false],
                "person_remove" => [false, true, false, false],
                "host_revoke" => [false, false, true, false],
                "host_unbind" => [true, true, true, false],
                _ => [false, true, false, true],
            };
            for ((name, prefix), want) in [
                ("statement_id", "ds_"),
                ("person_public_key", ""),
                ("host_public_key", ""),
                ("device_public_key", ""),
            ]
            .iter()
            .zip(wanted)
            {
                let value = text(target, name)?;
                check(if want {
                    if prefix.is_empty() {
                        key(value)
                    } else {
                        ident(value, prefix)
                    }
                } else {
                    value == "-"
                })?;
            }
            if matches!(kind, "host_unbind" | "device_revoke") {
                check(text(target, "person_public_key")? == text(issuer, "person_public_key")?)?;
            }
            let kept = ids(p, "kept_statement_ids", "ds_")?;
            check(kind == "admin_withdraw" || kept.is_empty())?;
        }
        "migration_proposal" => {
            fields(
                p,
                "proposal_nonce legacy_descriptor_base64 legacy_feature_id legacy_epoch legacy_root_public_key source_catalog_sha256 source_state_sha256 new_descriptor roster issued_at expires_at",
            )?;
            check(
                b64(text(p, "proposal_nonce")?, 32)?.len() == 32
                    && key(text(p, "legacy_root_public_key")?),
            )?;
            b64(text(p, "legacy_descriptor_base64")?, MAX_OBJECT)?;
            num(p, "legacy_epoch")?;
            reference(p, "legacy_feature_id", "lf_", true)?;
            check(
                digest(text(p, "source_catalog_sha256")?)
                    && digest(text(p, "source_state_sha256")?),
            )?;
            let embedded = Descriptor::from_value(
                p.get("new_descriptor")
                    .ok_or_else(|| Error::new("invalid"))?,
            )?;
            check(embedded.context_id() == d.ok_or_else(|| Error::new("invalid"))?.context_id())?;
            let issued = stamp(text(p, "issued_at")?)?;
            let end = stamp(text(p, "expires_at")?)?;
            check(end.signed_duration_since(issued).num_seconds() == 86400)?;
            let mut previous = "";
            for row in array(p, "roster")? {
                let r = object(row)?;
                fields(
                    r,
                    "host_public_key member person_public_key device_public_key scopes",
                )?;
                let host = text(r, "host_public_key")?;
                let person = text(r, "person_public_key")?;
                let device = text(r, "device_public_key")?;
                check(key(host) && host > previous)?;
                previous = host;
                label(text(r, "member")?)?;
                check(if person == "-" {
                    device == "-" && num(r, "scopes")? == 0
                } else {
                    key(person) && key(device) && (1..=15).contains(&num(r, "scopes")?)
                })?;
            }
            check(!array(p, "roster")?.is_empty())?;
        }
        "migration_ack" => {
            fields(
                p,
                "proposal_id root_state_id prepared_catalog_sha256 host_public_key person_public_key device_public_key host_lease_id binding_lease_id device_lease_id activation_id acknowledged_at",
            )?;
            for name in ["proposal_id", "root_state_id", "host_lease_id"] {
                reference(p, name, "ds_", false)?;
            }
            check(digest(text(p, "prepared_catalog_sha256")?) && key(text(p, "host_public_key")?))?;
            stamp(text(p, "acknowledged_at")?)?;
            let person = text(p, "person_public_key")?;
            let device = text(p, "device_public_key")?;
            if person == "-" {
                for name in [
                    "device_public_key",
                    "binding_lease_id",
                    "device_lease_id",
                    "activation_id",
                ] {
                    check(text(p, name)? == "-")?;
                }
            } else {
                check(key(person) && key(device))?;
                reference(p, "binding_lease_id", "ds_", false)?;
                reference(p, "device_lease_id", "ds_", false)?;
                reference(p, "activation_id", "da_", false)?;
            }
        }
        "migration_commit" => {
            fields(
                p,
                "proposal_id root_state_id prepared_catalog_sha256 acknowledgment_ids committed_at",
            )?;
            reference(p, "proposal_id", "ds_", false)?;
            reference(p, "root_state_id", "ds_", false)?;
            check(digest(text(p, "prepared_catalog_sha256")?))?;
            check(!ids(p, "acknowledgment_ids", "ds_")?.is_empty())?;
            stamp(text(p, "committed_at")?)?;
        }
        _ => return Err(Error::new("invalid")),
    }
    Ok(())
}
fn exact_parents(kind: &str, p: &Obj) -> Result<()> {
    let issuer = issuer(p)?;
    let ik = text(issuer, "kind")?;
    let mut expected = Vec::new();
    if ik != "root" {
        expected.push("issuer_person");
        // A deadline-only device renewal keeps the target's issuer_device
        // parent, if any; its device signer need not be that parent (DEC-Q7,
        // DEC-Q31).
        if ik == "device"
            && (!(kind == "device_lease" && renewal_candidate(kind, p)?)
                || parents(p)?.contains_key("issuer_device"))
        {
            expected.push("issuer_device");
        }
    }
    if matches!(
        kind,
        "person_lease" | "host_lease" | "group" | "person_remove" | "host_revoke"
    ) && ik != "root"
    {
        expected.push("issuer_admin");
    }
    if matches!(kind, "binding_lease" | "device_lease") {
        expected.extend(["subject_person", "subject_host"]);
    }
    if kind == "device_lease" {
        expected.push("subject_binding");
    }
    expected.sort();
    check(parents(p)?.keys().map(String::as_str).collect::<Vec<_>>() == expected)
}
