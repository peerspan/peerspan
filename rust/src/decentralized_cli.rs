//! The CLI signs only typed genesis slots for its explicitly chosen original
//! person. Daemon root/host keys and approval remain separate fixed roles.
use crate::{KeyChoice, admin::Local};
use anyhow::{Context, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use peerspan_host::decentralized::{Descriptor, FixedStatement};
use serde_json::{Value, json};

fn decode(encoded: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = STANDARD.decode(encoded)?;
    ensure!(
        STANDARD.encode(&bytes) == encoded,
        "non-canonical signature template"
    );
    Ok(bytes)
}
fn text<'a>(value: &'a Value, name: &str) -> anyhow::Result<&'a str> {
    value[name]
        .as_str()
        .with_context(|| format!("invalid creation {name}"))
}
fn shape(value: &Value, fields: &str) -> anyhow::Result<()> {
    let o = value.as_object().context("invalid creation object")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(
        o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)),
        "unexpected creation fields"
    );
    Ok(())
}
fn review(
    value: &Value,
    name: &str,
    member: &str,
    person: &str,
    host: &str,
) -> anyhow::Result<Descriptor> {
    shape(
        value,
        "creation_id review signing_requests network committed",
    )?;
    let r = &value["review"];
    shape(
        r,
        "name member descriptor root_state_id person_public_key host_public_key not_after authority_warning",
    )?;
    let d = Descriptor::read(&serde_json::to_vec(&r["descriptor"])?).map_err(anyhow::Error::new)?;
    ensure!(
        d.name == name
            && text(r, "name")? == name
            && text(r, "member")? == member
            && text(r, "person_public_key")? == person
            && text(r, "host_public_key")? == host,
        "daemon creation review does not match the requested owner/host/name"
    );
    ensure!(
        text(value, "creation_id")?.starts_with("create_")
            && text(r, "root_state_id")?.starts_with("ds_"),
        "invalid creation pins"
    );
    Ok(d)
}
fn signatures(
    value: &Value,
    d: &Descriptor,
    choice: &KeyChoice,
    host: &str,
) -> anyhow::Result<Value> {
    let entries = value["signing_requests"]
        .as_array()
        .context("invalid creation signing requests")?;
    ensure!(
        !entries.is_empty() && entries.len() <= 16,
        "creation requires review or provider repair before signing"
    );
    let mut id = None;
    let mut previous = None;
    let mut output = Vec::new();
    for entry in entries {
        shape(
            entry,
            "intent_id slot_id object_type object_id role public_key format template_base64 message_base64",
        )?;
        let slot = entry["slot_id"].as_u64().context("invalid creation slot")?;
        let role = text(entry, "role")?;
        ensure!(
            previous
                .as_ref()
                .is_none_or(|old: &(u64, String)| old < &(slot, role.into())),
            "unordered creation slots"
        );
        previous = Some((slot, role.into()));
        let intent = text(entry, "intent_id")?;
        if let Some(id) = id {
            ensure!(id == intent, "mixed signing intents");
        } else {
            id = Some(intent);
        }
        ensure!(
            role == "issuer"
                && text(entry, "format")? == "sshsig"
                && text(entry, "public_key")? == choice.signer.public_key_b64(),
            "creation requested a different key or signature role"
        );
        let raw = decode(text(entry, "template_base64")?)?;
        let fixed = FixedStatement::read(d, &raw)?;
        let outer: Value = serde_json::from_slice(&raw)?;
        let kind = text(&outer, "kind")?;
        ensure!(
            (kind == "binding_lease" && slot == 5) || (kind == "policy" && slot == 6),
            "unexpected creation object"
        );
        ensure!(
            kind == text(entry, "object_type")?
                && fixed.statement_id() == text(entry, "object_id")?,
            "creation object pin mismatch"
        );
        let p: Value = serde_json::from_slice(&decode(text(&outer, "payload_base64")?)?)?;
        ensure!(
            p["root_state_id"] == value["review"]["root_state_id"]
                && p["operation_id"] == "-"
                && p["sequence"] == 1
                && p["predecessors"] == json!([])
                && p["resolves"] == json!([])
                && p["issuer"]
                    == json!({"kind":"person","person_public_key":choice.signer.public_key_b64()}),
            "creation payload differs from reviewed owner/root"
        );
        if kind == "binding_lease" {
            ensure!(
                p["subject"]
                    == json!({"person_public_key":choice.signer.public_key_b64(),"host_public_key":host,"device_public_key":"-","member":"-","scopes":2})
                    && p["retained_statement_ids"] == json!([]),
                "unexpected initial binding subject/scopes"
            );
            let host_role = outer["signatures"]
                .as_array()
                .context("invalid binding roles")?
                .iter()
                .find(|s| s["role"] == "host")
                .context("missing target host consent")?;
            ensure!(
                host_role["public_key"] == host
                    && host_role["format"] == "ed25519"
                    && host_role["signature"] != "-",
                "initial binding lacks the actual host consent"
            );
        } else {
            let body: Value = serde_json::from_slice(&decode(text(&p, "body_base64")?)?)?;
            ensure!(
                body == json!({"format":2,"network_id":d.network_id,"person_public_key":choice.signer.public_key_b64(),"version":1,"issued_at":p["issued_at"],"valid_until":p["not_after"],"rules":[],"capability_rules":[],"trusted_hosts":[],"edits":[]}),
                "creator policy contains unreviewed access grants"
            );
        }
        let pending = fixed.pending();
        let expected = pending
            .iter()
            .find(|s| s.role == role)
            .context("creation signature slot is already filled")?;
        ensure!(
            expected.public_key == choice.signer.public_key_b64()
                && expected.signature_format == "sshsig"
                && expected.message_base64 == text(entry, "message_base64")?,
            "typed creation signature message mismatch"
        );
        let message = String::from_utf8(decode(&expected.message_base64)?)?;
        let signature = choice
            .signer
            .sign(&message.split('\n').collect::<Vec<_>>())
            .map_err(anyhow::Error::new)?;
        fixed.fill(d, role, &signature)?;
        output.push(json!({"slot_id":slot,"role":role,"signature":signature}));
    }
    Ok(json!({"intent_id":id.context("no signing intent")?,"signatures":output}))
}
pub(crate) async fn create(
    local: &Local<'_>,
    name: &str,
    member: &str,
    choice: &KeyChoice,
) -> anyhow::Result<Value> {
    peerspan_host::decentralized::local_decision_time()?;
    let host = local.get("/v1/host".into()).await?;
    let host = text(&host, "public_key")?;
    let mut value=local.post("/v2/networks".into(),json!({"name":name,"member":member,"person_public_key":choice.signer.public_key_b64(),"approve":false})).await?;
    let descriptor = review(&value, name, member, &choice.signer.public_key_b64(), host)?;
    // A new protected owner-local file must survive before any signed public
    // object can become active. No key is sent to the daemon or another host.
    choice.save(member)?;
    let creation_id = text(&value, "creation_id")?.to_owned();
    if value["committed"] != true {
        value=local.post(format!("/v2/network-creations/{creation_id}/approve"),json!({"context_id":descriptor.context_id(),"root_state_id":value["review"]["root_state_id"],"person_public_key":choice.signer.public_key_b64(),"host_public_key":host,"approve":true})).await?;
    }
    for _ in 0..6 {
        let observed = review(&value, name, member, &choice.signer.public_key_b64(), host)?;
        ensure!(
            observed.context_id() == descriptor.context_id()
                && text(&value, "creation_id")? == creation_id,
            "creation changed during signing"
        );
        if value["committed"] == true {
            let network = &value["network"];
            ensure!(
                network["mode"] == "decentralized"
                    && network["id"] == descriptor.network_id
                    && network["context_id"] == descriptor.context_id()
                    && network["person_public_key"] == choice.signer.public_key_b64()
                    && network["host_public_key"] == host
                    && network["provider"]["kind"] == "original_person",
                "invalid committed creation identity/provider"
            );
            return Ok(network.clone());
        }
        if value["signing_requests"]
            .as_array()
            .is_none_or(|s| s.is_empty())
        {
            return Ok(value);
        }
        let signed = signatures(&value, &descriptor, choice, host)?;
        value = local
            .post(
                format!("/v2/network-creations/{creation_id}/signed"),
                signed,
            )
            .await?;
    }
    bail!("creation signature dependencies did not converge")
}
