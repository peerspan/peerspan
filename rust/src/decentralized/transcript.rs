//! Exact complete consent transcripts. Parsing retains original nested bytes;
//! live grant eligibility is evaluated by the authority engine separately.
use super::{
    catalog::{raw_field, value_field},
    codec::*,
    statement::{Descriptor, Statement},
};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(crate) struct Packet {
    pub id: String,
    pub object: Obj,
    pub payload: Obj,
    pub payload_bytes: Vec<u8>,
}
impl Packet {
    pub fn read(bytes: &[u8]) -> Result<Self> {
        Self::read_mode(bytes, false)
    }
    pub(crate) fn read_template(bytes: &[u8]) -> Result<Self> {
        Self::read_mode(bytes, true)
    }
    fn read_mode(bytes: &[u8], template: bool) -> Result<Self> {
        let value = parse(bytes, MAX_OBJECT)?;
        let o = object(&value)?;
        fields(
            o,
            "format context_id request_id role writer_host_public_key signer_public_key person_public_key issuer_id payload_base64 host_signature device_signature authority_signature_format authority_signature",
        )?;
        version(o)?;
        let role = text(o, "role")?;
        let context = text(o, "context_id")?;
        let request = text(o, "request_id")?;
        check(
            matches!(
                role,
                "request"
                    | "owner"
                    | "selection"
                    | "administrator"
                    | "owner_finalization"
                    | "commit"
                    | "outcome"
            ) && ident(request, "link_"),
        )?;
        check(if role == "request" {
            context == "-"
        } else {
            ident(context, "ctx_")
        })?;
        let payload_bytes = b64(text(o, "payload_base64")?, MAX_PAYLOAD)?;
        let payload = object(&parse(&payload_bytes, MAX_PAYLOAD)?)?.clone();
        let message = lines(&[
            "peerspan-decentralized-packet-v1",
            context,
            request,
            role,
            text(o, "writer_host_public_key")?,
            text(o, "signer_public_key")?,
            text(o, "person_public_key")?,
            text(o, "issuer_id")?,
            text(o, "authority_signature_format")?,
            &hash(&payload_bytes),
        ]);
        let raw_slot = |public: &str, encoded: &str| -> Result<()> {
            if template && encoded == "-" {
                check(key(public))
            } else {
                raw_signature(public, &message, encoded)
            }
        };
        raw_slot(
            text(o, "writer_host_public_key")?,
            text(o, "host_signature")?,
        )?;
        match role {
            "request" | "selection" | "commit" => {
                check(
                    text(o, "issuer_id")? == "-"
                        && text(o, "authority_signature")? == "-"
                        && text(o, "authority_signature_format")? == "-",
                )?;
                raw_slot(text(o, "signer_public_key")?, text(o, "device_signature")?)?;
                check(if role == "request" {
                    text(o, "person_public_key")? == "-"
                } else {
                    key(text(o, "person_public_key")?)
                })?;
            }
            "outcome" => {
                for name in [
                    "signer_public_key",
                    "person_public_key",
                    "issuer_id",
                    "device_signature",
                    "authority_signature_format",
                    "authority_signature",
                ] {
                    check(text(o, name)? == "-")?;
                }
            }
            _ => {
                check(text(o, "device_signature")? == "-")?;
                let person = text(o, "person_public_key")?;
                let issuer = text(o, "issuer_id")?;
                let format = text(o, "authority_signature_format")?;
                check(if role == "administrator" && person == "-" {
                    ident(issuer, "ds_")
                } else {
                    key(person) && (issuer == "-" || ident(issuer, "ds_"))
                })?;
                if person != "-" && issuer == "-" {
                    check(format == "sshsig" && text(o, "signer_public_key")? == person)?;
                }
                if issuer != "-" && person != "-" {
                    check(format == "ed25519")?;
                }
                let encoded = text(o, "authority_signature")?;
                if template && encoded == "-" {
                    check(
                        key(text(o, "signer_public_key")?)
                            && matches!(format, "ed25519" | "sshsig"),
                    )?;
                } else {
                    signature(text(o, "signer_public_key")?, format, &message, encoded)?;
                }
            }
        }
        match role {
            "request" => {
                require(bytes.len() <= 8 << 10, "quota_exceeded")?;
                fields(
                    &payload,
                    "mode host_public_key device_public_key request_nonce expected_network_id expected_context_id expected_person_public_key migration_proposal_id renewed_device_lease_id created_at expires_at",
                )?;
                check(matches!(text(&payload, "mode")?, "new" | "renew"))?;
                check(
                    key(text(&payload, "host_public_key")?)
                        && key(text(&payload, "device_public_key")?)
                        && text(&payload, "host_public_key")?
                            != text(&payload, "device_public_key")?,
                )?;
                check(b64(text(&payload, "request_nonce")?, 32)?.len() == 32)?;
                for (name, prefix) in [
                    ("expected_network_id", "net_"),
                    ("expected_context_id", "ctx_"),
                    ("migration_proposal_id", "ds_"),
                    ("renewed_device_lease_id", "ds_"),
                ] {
                    let id = text(&payload, name)?;
                    check(id == "-" || ident(id, prefix))?;
                }
                let person = text(&payload, "expected_person_public_key")?;
                check(person == "-" || key(person))?;
                let start = stamp(text(&payload, "created_at")?)?;
                let end = stamp(text(&payload, "expires_at")?)?;
                check(end.signed_duration_since(start).num_seconds() == 300)?;
                check(
                    request
                        == format!(
                            "link_{}",
                            hash(&lines(&[
                                "peerspan-decentralized-request-id-v1",
                                &hash(&payload_bytes)
                            ]))
                        ),
                )?;
                check(
                    text(o, "writer_host_public_key")? == text(&payload, "host_public_key")?
                        && text(o, "signer_public_key")? == text(&payload, "device_public_key")?,
                )?;
                if text(&payload, "mode")? == "renew" {
                    check(
                        ident(text(&payload, "renewed_device_lease_id")?, "ds_")
                            && person != "-"
                            && text(&payload, "expected_network_id")? != "-"
                            && text(&payload, "expected_context_id")? != "-",
                    )?;
                } else {
                    check(text(&payload, "renewed_device_lease_id")? == "-")?;
                }
            }
            "owner" => {
                fields(
                    &payload,
                    "request_packet_id descriptor root_state_id person_lease_id issuer_lease_ids mode member host_public_key device_public_key scopes not_after renewed_device_lease_id",
                )?;
                check(
                    ident(text(&payload, "request_packet_id")?, "dpk_")
                        && matches!(text(&payload, "mode")?, "new" | "renew")
                        && key(text(&payload, "host_public_key")?)
                        && key(text(&payload, "device_public_key")?)
                        && (1..=15).contains(&num(&payload, "scopes")?),
                )?;
                label(text(&payload, "member")?)?;
                stamp(text(&payload, "not_after")?)?;
                ids(&payload, "issuer_lease_ids", "ds_")?;
                for name in [
                    "root_state_id",
                    "person_lease_id",
                    "renewed_device_lease_id",
                ] {
                    let id = text(&payload, name)?;
                    check(id == "-" || ident(id, "ds_"))?;
                }
                if text(&payload, "root_state_id")? == "-" {
                    check(
                        text(&payload, "person_lease_id")? == "-"
                            && ids(&payload, "issuer_lease_ids", "ds_")?.is_empty()
                            && text(o, "issuer_id")? == "-"
                            && text(&payload, "mode")? == "new",
                    )?;
                }
            }
            "selection" => {
                fields(
                    &payload,
                    "request_packet_id owner_offer_id context_id person_public_key host_public_key device_public_key selected_at",
                )?;
                stamp(text(&payload, "selected_at")?)?;
            }
            "administrator" => {
                fields(
                    &payload,
                    "selection_id owner_offer_id root_state_id issuer_lease_ids person_lease host_lease",
                )?;
                ids(&payload, "issuer_lease_ids", "ds_")?;
            }
            "owner_finalization" => {
                fields(
                    &payload,
                    "selection_id administrator_offer_id root_state_id person_lease_id host_lease_id binding_lease device_lease",
                )?;
            }
            "commit" => {
                fields(
                    &payload,
                    "manifest_base64 binding_host_signature committed_at",
                )?;
                stamp(text(&payload, "committed_at")?)?;
            }
            "outcome" => {
                fields(
                    &payload,
                    "context_id request_id manifest_id activation_id activation_sha256 observed_root_state_id applied_at",
                )?;
                check(
                    text(&payload, "context_id")? == context
                        && text(&payload, "request_id")? == request
                        && ident(text(&payload, "manifest_id")?, "dm_")
                        && ident(text(&payload, "activation_id")?, "da_")
                        && ident(text(&payload, "observed_root_state_id")?, "ds_"),
                )?;
                check(digest(text(&payload, "activation_sha256")?))?;
                stamp(text(&payload, "applied_at")?)?;
            }
            _ => unreachable!(),
        }
        Ok(Self {
            id: format!("dpk_{}", hash(&message)),
            object: o.clone(),
            payload,
            payload_bytes,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Activation {
    pub id: String,
    pub request_id: String,
    pub manifest_id: String,
    pub manifest: Obj,
    pub packets: BTreeMap<String, Packet>,
    pub statements: Vec<Statement>,
}
impl Activation {
    pub fn read(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        let value = parse(bytes, MAX_OBJECT)?;
        let o = object(&value)?;
        fields(
            o,
            "format context_id request owner selection administrator owner_finalization commit",
        )?;
        version(o)?;
        check(text(o, "context_id")? == descriptor.context_id())?;
        let mut packets: BTreeMap<String, Packet> = BTreeMap::new();
        for role in [
            "request",
            "owner",
            "selection",
            "administrator",
            "owner_finalization",
            "commit",
        ] {
            if role == "administrator" && value_field(o, role)?.as_str() == Some("-") {
                continue;
            }
            let packet = Packet::read(&raw_field(bytes, role)?)?;
            check(text(&packet.object, "role")? == role)?;
            packets.insert(role.into(), packet);
        }
        let request = &packets["request"];
        let owner = &packets["owner"];
        let selection = &packets["selection"];
        let finalization = &packets["owner_finalization"];
        let commit = &packets["commit"];
        let request_id = text(&request.object, "request_id")?;
        let host = text(&request.payload, "host_public_key")?;
        let device = text(&request.payload, "device_public_key")?;
        let person = text(&owner.object, "person_public_key")?;
        for (role, packet) in &packets {
            check(text(&packet.object, "request_id")? == request_id)?;
            if role != "request" {
                check(text(&packet.object, "context_id")? == descriptor.context_id())?;
            }
            if matches!(role.as_str(), "selection" | "commit") {
                check(
                    text(&packet.object, "writer_host_public_key")? == host
                        && text(&packet.object, "signer_public_key")? == device
                        && text(&packet.object, "person_public_key")? == person,
                )?;
            }
        }
        let owner_descriptor = Descriptor::from_value(value_field(&owner.payload, "descriptor")?)?;
        check(owner_descriptor.context_id() == descriptor.context_id())?;
        check(
            text(&owner.payload, "request_packet_id")? == request.id
                && text(&owner.payload, "host_public_key")? == host
                && text(&owner.payload, "device_public_key")? == device
                && text(&owner.payload, "mode")? == text(&request.payload, "mode")?
                && text(&owner.payload, "renewed_device_lease_id")?
                    == text(&request.payload, "renewed_device_lease_id")?,
        )?;
        for (name, actual) in [
            ("expected_network_id", descriptor.network_id.as_str()),
            ("expected_context_id", &descriptor.context_id()),
            ("expected_person_public_key", person),
        ] {
            let expected = text(&request.payload, name)?;
            check(expected == "-" || expected == actual)?;
        }
        for (name, actual) in [
            ("request_packet_id", request.id.as_str()),
            ("owner_offer_id", &owner.id),
            ("context_id", descriptor.context_id().as_str()),
            ("person_public_key", person),
            ("host_public_key", host),
            ("device_public_key", device),
        ] {
            check(text(&selection.payload, name)? == actual)?;
        }
        check(
            text(&finalization.payload, "selection_id")? == selection.id
                && text(&finalization.object, "person_public_key")? == person
                && text(&finalization.object, "signer_public_key")?
                    == text(&owner.object, "signer_public_key")?
                && text(&finalization.object, "issuer_id")? == text(&owner.object, "issuer_id")?
                && text(&finalization.object, "writer_host_public_key")?
                    == text(&owner.object, "writer_host_public_key")?,
        )?;
        let administrator_id = packets
            .get("administrator")
            .map(|p| p.id.as_str())
            .unwrap_or("-");
        check(text(&finalization.payload, "administrator_offer_id")? == administrator_id)?;
        let root = text(&finalization.payload, "root_state_id")?;
        check(ident(root, "ds_"))?;
        check(
            text(&owner.payload, "root_state_id")? == "-"
                || text(&owner.payload, "root_state_id")? == root,
        )?;
        let mut statements = Vec::new();
        let mut person_id = text(&finalization.payload, "person_lease_id")?.to_owned();
        let mut host_id = text(&finalization.payload, "host_lease_id")?.to_owned();
        if let Some(admin) = packets.get("administrator") {
            check(
                text(&admin.payload, "selection_id")? == selection.id
                    && text(&admin.payload, "owner_offer_id")? == owner.id
                    && text(&admin.payload, "root_state_id")? == root,
            )?;
            for (name, kind, id) in [
                ("person_lease", "person_lease", &mut person_id),
                ("host_lease", "host_lease", &mut host_id),
            ] {
                match value_field(&admin.payload, name)? {
                    serde_json::Value::String(s) => check(s == id)?,
                    serde_json::Value::Object(_) => {
                        let raw = raw_field(&admin.payload_bytes, name)?;
                        let statement = Statement::read(descriptor, &raw)?;
                        check(
                            statement.kind == kind
                                && statement.id == *id
                                && text(&statement.payload, "operation_id")? == request_id,
                        )?;
                        check(text(&statement.payload, "root_state_id")? == root)?;
                        statements.push(statement);
                    }
                    _ => return Err(Error::new("invalid")),
                }
            }
        } else {
            check(text(&request.payload, "mode")? == "renew")?;
        }
        check(ident(&person_id, "ds_") && ident(&host_id, "ds_"))?;
        let binding = value_field(&finalization.payload, "binding_lease")?;
        let binding_id = if let Some(id) = binding.as_str() {
            check(text(&request.payload, "mode")? == "renew" && ident(id, "ds_"))?;
            id.to_owned()
        } else {
            let raw = raw_field(&finalization.payload_bytes, "binding_lease")?;
            let statement = Statement::read_draft(descriptor, &raw, true)?;
            check(
                statement.kind == "binding_lease"
                    && text(&statement.payload, "operation_id")? == request_id
                    && text(&statement.payload, "root_state_id")? == root,
            )?;
            statement.id
        };
        let raw = raw_field(&finalization.payload_bytes, "device_lease")?;
        let target = Statement::read(descriptor, &raw)?;
        check(
            target.kind == "device_lease"
                && text(&target.payload, "operation_id")? == request_id
                && text(&target.payload, "root_state_id")? == root,
        )?;
        check(
            text(target.subject()?, "person_public_key")? == person
                && text(target.subject()?, "host_public_key")? == host
                && text(target.subject()?, "device_public_key")? == device
                && num(target.subject()?, "scopes")? == num(&owner.payload, "scopes")?
                && text(&target.payload, "not_after")? == text(&owner.payload, "not_after")?,
        )?;
        let target_parents = target.parents()?;
        check(
            target_parents.get("subject_person") == Some(&person_id)
                && target_parents.get("subject_host") == Some(&host_id)
                && target_parents.get("subject_binding") == Some(&binding_id),
        )?;
        let manifest_bytes = b64(text(&commit.payload, "manifest_base64")?, 16 << 10)?;
        let manifest = object(&parse(&manifest_bytes, 16 << 10)?)?.clone();
        fields(
            &manifest,
            "format context_id request_id request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id binding_proof_id device_proof_id ancestor_statement_ids proof_ids",
        )?;
        version(&manifest)?;
        for (name, actual) in [
            ("context_id", descriptor.context_id().as_str()),
            ("request_id", request_id),
            ("request_packet_id", request.id.as_str()),
            ("owner_offer_id", &owner.id),
            ("selection_id", &selection.id),
            ("administrator_offer_id", administrator_id),
            ("owner_finalization_id", &finalization.id),
            ("root_state_id", root),
            ("person_lease_id", &person_id),
            ("host_lease_id", &host_id),
            ("binding_lease_id", &binding_id),
            ("device_lease_id", &target.id),
        ] {
            check(text(&manifest, name)? == actual)?;
        }
        check(
            ident(text(&manifest, "binding_proof_id")?, "dp_")
                && ident(text(&manifest, "device_proof_id")?, "dp_"),
        )?;
        ids(&manifest, "ancestor_statement_ids", "ds_")?;
        ids(&manifest, "proof_ids", "dp_")?;
        if binding.is_string() {
            check(text(&commit.payload, "binding_host_signature")? == "-")?;
        } else {
            let message = super::statement::signature_message(&binding_id, "host", host);
            raw_signature(
                host,
                &message,
                text(&commit.payload, "binding_host_signature")?,
            )?;
        }
        let manifest_id = format!(
            "dm_{}",
            hash(&lines(&[
                "peerspan-decentralized-manifest-v1",
                &hash(&manifest_bytes)
            ]))
        );
        let id = format!(
            "da_{}",
            hash(&lines(&[
                "peerspan-decentralized-activation-v1",
                &descriptor.context_id(),
                request_id,
                &manifest_id,
                &commit.id
            ]))
        );
        statements.push(target);
        Ok(Self {
            id,
            request_id: request_id.into(),
            manifest_id,
            manifest,
            packets,
            statements,
        })
    }
}
