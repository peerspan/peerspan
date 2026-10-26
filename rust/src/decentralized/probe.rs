use super::{Catalog, Descriptor, Statement, codec::*};
use serde_json::{Value, json};
pub const MAX_PROBE_LINE: usize = 64 << 20;
pub fn probe(bytes: &[u8]) -> Value {
    match run(bytes) {
        Ok(value) => value,
        Err(error) => error.response(),
    }
}
fn run(bytes: &[u8]) -> Result<Value> {
    let value = parse(bytes, MAX_PROBE_LINE)?;
    let o = object(&value)?;
    version(o)?;
    let kind = text(o, "kind")?;
    if kind == "clock" {
        fields(o, "format kind now clock_guard")?;
        let clock = decision_clock(text(o, "now")?, text(o, "clock_guard")?)?;
        return Ok(json!({"ok":true,"decision_time":clock,"next_guard":clock}));
    }
    let descriptor = Descriptor::read(&b64(text(o, "descriptor_base64")?, MAX_OBJECT)?)?;
    match kind {
        "descriptor" => {
            fields(o, "format kind descriptor_base64")?;
            Ok(
                json!({"ok":true,"context_id":descriptor.context_id(),"network_id":descriptor.network_id,"genesis_root_public_key":descriptor.genesis_root_public_key}),
            )
        }
        "statement" => {
            fields(o, "format kind descriptor_base64 statement_base64")?;
            Ok(
                Statement::read(&descriptor, &b64(text(o, "statement_base64")?, MAX_OBJECT)?)?
                    .response(),
            )
        }
        "catalog" => {
            fields(o, "format kind descriptor_base64 catalog_base64")?;
            let catalog =
                Catalog::read(&descriptor, &b64(text(o, "catalog_base64")?, MAX_CATALOG)?)?;
            Ok(
                json!({"ok":true,"context_id":catalog.context_id,"proof_ids":catalog.proofs.keys().collect::<Vec<_>>()}),
            )
        }
        "activation" => {
            fields(
                o,
                "format kind descriptor_base64 prior catalog_base64 activation_base64 now expected",
            )?;
            let activation_bytes = b64(text(o, "activation_base64")?, MAX_OBJECT)?;
            let activation = super::transcript::Activation::read(&descriptor, &activation_bytes)?;
            let catalog =
                Catalog::read(&descriptor, &b64(text(o, "catalog_base64")?, MAX_CATALOG)?)?;
            let proof = super::statement::proof_id("activation", &activation_bytes);
            let mut objects: std::collections::BTreeMap<_, _> = catalog
                .proofs
                .values()
                .map(|p| {
                    (
                        p.id.clone(),
                        json!({"id":p.id,"kind":p.kind,"body_base64":encode(&p.body)}),
                    )
                })
                .collect();
            objects.insert(
                proof.clone(),
                json!({"id":proof,"kind":"activation","body_base64":encode(&activation_bytes)}),
            );
            let combined=serde_json::to_vec(&json!({"format":1,"context_id":descriptor.context_id(),"objects":objects.into_values().collect::<Vec<_>>()})).map_err(|_|Error::new("invalid"))?;
            let projection = super::state::Projection::build(
                &descriptor,
                o.get("prior").ok_or_else(|| Error::new("invalid"))?,
                Some(&combined),
                text(o, "now")?,
                "repair",
            )?;
            projection.activation_response(
                &activation.request_id,
                o.get("expected").ok_or_else(|| Error::new("invalid"))?,
            )
        }
        "projection" => {
            fields(
                o,
                "format kind descriptor_base64 prior candidate_catalog_base64 now operation",
            )?;
            let operation = text(o, "operation")?;
            let candidate = text(o, "candidate_catalog_base64")?;
            let decoded = if candidate == "-" {
                None
            } else {
                Some(b64(candidate, MAX_CATALOG)?)
            };
            let projection = super::state::Projection::build(
                &descriptor,
                o.get("prior").ok_or_else(|| Error::new("invalid"))?,
                decoded.as_deref(),
                text(o, "now")?,
                operation,
            )?;
            projection.response(operation)
        }
        "action" => {
            fields(
                o,
                "format kind descriptor_base64 prior candidate_catalog_base64 now actor action_kind unsigned_payload_base64",
            )?;
            let candidate = text(o, "candidate_catalog_base64")?;
            let decoded = if candidate == "-" {
                None
            } else {
                Some(b64(candidate, MAX_CATALOG)?)
            };
            let operation = if decoded.is_none() { "read" } else { "fresh" };
            let projection = super::state::Projection::build(
                &descriptor,
                o.get("prior").ok_or_else(|| Error::new("invalid"))?,
                decoded.as_deref(),
                text(o, "now")?,
                operation,
            )?;
            projection.action(
                object(o.get("actor").ok_or_else(|| Error::new("invalid"))?)?,
                text(o, "action_kind")?,
                &b64(text(o, "unsigned_payload_base64")?, MAX_PAYLOAD)?,
            )
        }
        _ => Err(Error::new("invalid")),
    }
}
