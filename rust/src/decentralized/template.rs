//! Fixed typed statement templates. Filling a declared signature string keeps
//! every other original byte intact, including payload and outer key order.
//! This parser confers no authority, approval, adoption, or signer selection.
use super::{
    codec::*,
    statement::{Descriptor, Statement, signature_message},
    transcript::Packet,
};
use serde_json::value::RawValue;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct StatementSigningSlot {
    pub statement_id: String,
    pub object_type: String,
    pub role: String,
    pub public_key: String,
    pub signature_format: String,
    pub message_base64: String,
}
/// A typed packet has fixed top-level signature positions. It is never a
/// public proof until the ordinary strict Packet reader accepts every role.
#[derive(Clone, Debug)]
pub struct FixedPacket {
    body: Vec<u8>,
    packet: Packet,
}
impl FixedPacket {
    pub fn read(descriptor: &Descriptor, body: &[u8]) -> Result<Self> {
        Self::read_context(&descriptor.context_id(), body)
    }
    /// Inspect a fixed packet under an independently reviewed context pin.
    /// This supplies no network descriptor or ordinary authority/admission.
    pub fn read_context(context: &str, body: &[u8]) -> Result<Self> {
        check(ident(context, "ctx_"))?;
        let packet = Packet::read_template(body)?;
        check(text(&packet.object, "context_id")? == context)?;
        check(matches!(
            text(&packet.object, "role")?,
            "owner" | "administrator" | "owner_finalization" | "selection" | "commit"
        ))?;
        if text(&packet.object, "role")? == "owner" {
            check(
                Descriptor::from_value(
                    packet
                        .payload
                        .get("descriptor")
                        .ok_or_else(|| Error::new("invalid"))?,
                )?
                .context_id()
                    == context,
            )?;
        }
        Ok(Self {
            body: body.into(),
            packet,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }
    pub fn packet_id(&self) -> &str {
        &self.packet.id
    }
    pub fn check_signature(&self, role: &str, encoded: &str) -> Result<()> {
        let slot = self
            .pending()?
            .into_iter()
            .find(|s| s.role == role)
            .ok_or_else(|| Error::new("invalid"))?;
        signature(
            &slot.public_key,
            &slot.signature_format,
            &b64(&slot.message_base64, 4096)?,
            encoded,
        )
    }
    pub fn pending(&self) -> Result<Vec<StatementSigningSlot>> {
        let o = &self.packet.object;
        let packet_role = text(o, "role")?;
        let object_type = match packet_role {
            "owner" => "owner_offer_packet",
            "administrator" => "administrator_packet",
            "owner_finalization" => "owner_finalization_packet",
            "selection" => "selection_packet",
            "commit" => "commit_packet",
            _ => return Err(Error::new("invalid")),
        };
        let message = lines(&[
            "peerspan-decentralized-packet-v1",
            text(o, "context_id")?,
            text(o, "request_id")?,
            packet_role,
            text(o, "writer_host_public_key")?,
            text(o, "signer_public_key")?,
            text(o, "person_public_key")?,
            text(o, "issuer_id")?,
            text(o, "authority_signature_format")?,
            &hash(&self.packet.payload_bytes),
        ]);
        let mut result = Vec::new();
        let mut roles = vec![(
            "host",
            "host_signature",
            "writer_host_public_key",
            "ed25519",
        )];
        if matches!(packet_role, "selection" | "commit") {
            roles.push(("device", "device_signature", "signer_public_key", "ed25519"));
        } else {
            roles.push((
                "authority",
                "authority_signature",
                "signer_public_key",
                text(o, "authority_signature_format")?,
            ));
        }
        roles.sort_by_key(|role| role.0);
        for (role, field, key_field, format) in roles {
            if text(o, field)? == "-" {
                result.push(StatementSigningSlot {
                    statement_id: self.packet.id.clone(),
                    object_type: object_type.into(),
                    role: role.into(),
                    public_key: text(o, key_field)?.into(),
                    signature_format: format.into(),
                    message_base64: encode(&message),
                });
            }
        }
        Ok(result)
    }
    pub fn fill(&self, descriptor: &Descriptor, role: &str, encoded: &str) -> Result<Self> {
        let field = match role {
            "host" => "host_signature",
            "authority" => "authority_signature",
            "device" => "device_signature",
            _ => return Err(Error::new("invalid")),
        };
        let current = text(&self.packet.object, field)?;
        if current != "-" {
            require(current == encoded, "operation_conflict")?;
            return Ok(self.clone());
        }
        let slot = self
            .pending()?
            .into_iter()
            .find(|s| s.role == role)
            .ok_or_else(|| Error::new("invalid"))?;
        signature(
            &slot.public_key,
            &slot.signature_format,
            &b64(&slot.message_base64, 4096)?,
            encoded,
        )?;
        let (start, end) = field_span(&self.body, field)?;
        let mut body = self.body.clone();
        body.splice(
            start..end,
            serde_json::to_vec(encoded).map_err(|_| Error::new("internal"))?,
        );
        let filled = Self::read(descriptor, &body)?;
        check(
            filled.packet.id == self.packet.id
                && filled.packet.payload_bytes == self.packet.payload_bytes,
        )?;
        if filled.pending()?.is_empty() {
            Packet::read(&body)?;
        }
        Ok(filled)
    }
}
fn field_span(bytes: &[u8], name: &str) -> Result<(usize, usize)> {
    let object: BTreeMap<&str, &RawValue> =
        serde_json::from_slice(bytes).map_err(|_| Error::new("invalid"))?;
    let value = object.get(name).ok_or_else(|| Error::new("invalid"))?.get();
    check(value == "\"-\"")?;
    let start = (value.as_ptr() as usize)
        .checked_sub(bytes.as_ptr() as usize)
        .ok_or_else(|| Error::new("invalid"))?;
    let end = start
        .checked_add(value.len())
        .ok_or_else(|| Error::new("invalid"))?;
    check(end <= bytes.len())?;
    Ok((start, end))
}
#[derive(Clone, Debug)]
pub struct FixedStatement {
    value: Statement,
}
impl FixedStatement {
    pub fn read(descriptor: &Descriptor, bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            value: Statement::read_template(descriptor, bytes)?,
        })
    }
    /// Inspect only a link-bound lease template under its reviewed context.
    /// No descriptor, root/access statement, catalog admission or authority
    /// projection can be obtained through this constructor.
    pub fn read_link(context: &str, bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            value: Statement::read_link_template(context, bytes)?,
        })
    }
    pub fn check_signature(&self, role: &str, encoded: &str) -> Result<()> {
        let slot = self.value.signer(role)?;
        check(slot.signature == "-")?;
        signature(
            &slot.public_key,
            &slot.format,
            &signature_message(&self.value.id, role, &slot.public_key),
            encoded,
        )
    }
    pub fn bytes(&self) -> &[u8] {
        &self.value.body
    }
    pub fn statement_id(&self) -> &str {
        &self.value.id
    }
    /// Inspect the strictly parsed fixed template; this is not an admission.
    pub fn typed(&self) -> &Statement {
        &self.value
    }
    pub fn pending(&self) -> Vec<StatementSigningSlot> {
        self.value
            .signatures
            .values()
            .filter(|sig| sig.signature == "-")
            .map(|sig| StatementSigningSlot {
                statement_id: self.value.id.clone(),
                object_type: self.value.kind.clone(),
                role: sig.role.clone(),
                public_key: sig.public_key.clone(),
                signature_format: sig.format.clone(),
                message_base64: encode(&signature_message(
                    &self.value.id,
                    &sig.role,
                    &sig.public_key,
                )),
            })
            .collect()
    }
    /// No generic message is accepted. The exact declared role/key/format and
    /// signature message are derived again from the fixed validated template.
    pub fn fill(&self, descriptor: &Descriptor, role: &str, encoded: &str) -> Result<Self> {
        let slot = self.value.signer(role)?;
        if slot.signature != "-" {
            require(slot.signature == encoded, "operation_conflict")?;
            return Ok(self.clone());
        }
        signature(
            &slot.public_key,
            &slot.format,
            &signature_message(&self.value.id, role, &slot.public_key),
            encoded,
        )?;
        let (start, end) = signature_span(&self.value.body, role)?;
        let replacement = serde_json::to_vec(encoded).map_err(|_| Error::new("internal"))?;
        let mut body = self.value.body.clone();
        body.splice(start..end, replacement);
        let filled = Self::read(descriptor, &body)?;
        check(
            filled.value.kind == self.value.kind
                && filled.value.payload_bytes == self.value.payload_bytes
                && filled.value.id == self.value.id,
        )?;
        Ok(filled)
    }
    pub fn signed(&self, descriptor: &Descriptor) -> Result<Option<Statement>> {
        if !self.pending().is_empty() {
            return Ok(None);
        }
        Ok(Some(Statement::read(descriptor, &self.value.body)?))
    }
    /// Exact transport size before signing. These placeholder bytes are only
    /// consumed by quota accounting, never by a catalog/authority reader.
    pub(crate) fn budget_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = self.value.body.clone();
        for slot in self.pending() {
            let (start, end) = signature_span(&bytes, &slot.role)?;
            // Strict Ed25519 SSHSIG fixes the key, namespace, empty reserved
            // field, SHA512 and 64-byte signature: its binary size is188.
            let encoded = encode(&vec![
                0;
                if slot.signature_format == "ed25519" {
                    64
                } else {
                    188
                }
            ]);
            bytes.splice(
                start..end,
                serde_json::to_vec(&encoded).map_err(|_| Error::new("internal"))?,
            );
        }
        require(bytes.len() <= MAX_OBJECT, "quota_exceeded")?;
        Ok(bytes)
    }
}
fn signature_span(bytes: &[u8], role: &str) -> Result<(usize, usize)> {
    let object: BTreeMap<&str, &RawValue> =
        serde_json::from_slice(bytes).map_err(|_| Error::new("invalid"))?;
    let entries: Vec<&RawValue> = serde_json::from_str(
        object
            .get("signatures")
            .ok_or_else(|| Error::new("invalid"))?
            .get(),
    )
    .map_err(|_| Error::new("invalid"))?;
    for entry in entries {
        let fields: BTreeMap<&str, &RawValue> =
            serde_json::from_str(entry.get()).map_err(|_| Error::new("invalid"))?;
        let current: String = serde_json::from_str(
            fields
                .get("role")
                .ok_or_else(|| Error::new("invalid"))?
                .get(),
        )
        .map_err(|_| Error::new("invalid"))?;
        if current == role {
            let value = fields
                .get("signature")
                .ok_or_else(|| Error::new("invalid"))?
                .get();
            check(value == "\"-\"")?;
            let start = (value.as_ptr() as usize)
                .checked_sub(bytes.as_ptr() as usize)
                .ok_or_else(|| Error::new("invalid"))?;
            let end = start
                .checked_add(value.len())
                .ok_or_else(|| Error::new("invalid"))?;
            check(end <= bytes.len())?;
            return Ok((start, end));
        }
    }
    Err(Error::new("invalid"))
}
