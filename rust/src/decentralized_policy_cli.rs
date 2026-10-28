//! Native policy editing uses the existing unsigned body delta helpers, then
//! the fixed DEC wrapper and typed slots. It never emits a legacy signed policy.
use crate::{admin::Local, cli::encoded, integration::DaemonError};
use anyhow::{Context, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use peerspan_host::{
    decentralized::{Catalog, Descriptor, FixedStatement, Statement},
    persons::PersonSigner,
    policy::PolicyBody,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone)]
pub(crate) struct Provider {
    pub person: String,
    pub id: String,
    pub not_after: String,
    kind: String,
    lease: String,
}
/// The person's policy changed since this edit started (spec 12.1 version
/// check); the caller reloads and starts the edit again.
#[derive(Debug)]
pub(crate) struct StaleEdit;
impl std::fmt::Display for StaleEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("policy changed since the edit started (state_conflict)")
    }
}
impl std::error::Error for StaleEdit {}
impl Provider {
    /// The selected provider is the person's original key, not a device.
    pub fn is_original(&self) -> bool {
        self.kind == "original_person"
    }
}
pub(crate) struct Reservation {
    pub policy: Option<PolicyBody>,
    pub version: u64,
    pub seq: u64,
    pub decision_time: String,
}
struct Submission<'a> {
    d: &'a Descriptor,
    payload: &'a [u8],
    capability: Option<&'a str>,
    reviewed_provider: Option<&'a Value>,
}
fn text<'a>(value: &'a Value, field: &str) -> anyhow::Result<&'a str> {
    value[field]
        .as_str()
        .with_context(|| format!("invalid native policy {field}"))
}
fn decode(value: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = STANDARD.decode(value)?;
    ensure!(
        STANDARD.encode(&bytes) == value,
        "non-canonical native policy bytes"
    );
    Ok(bytes)
}
fn shape(value: &Value, fields: &str) -> anyhow::Result<()> {
    let object = value.as_object().context("invalid native policy object")?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    ensure!(
        object.len() == fields.len() && fields.iter().all(|f| object.contains_key(*f)),
        "unexpected native policy fields"
    );
    Ok(())
}
fn descriptor(network: &Value) -> anyhow::Result<Descriptor> {
    ensure!(network["mode"] == "decentralized", "not a native network");
    let d = Descriptor::read(&serde_json::to_vec(
        &json!({"format":1,"protocol":"peerspan-decentralized-v1","network_id":network["id"],"name":network["name"],"genesis_root_public_key":network["genesis_root_public_key"]}),
    )?)?;
    ensure!(
        d.context_id() == text(network, "context_id")?,
        "native context mismatch"
    );
    Ok(d)
}
fn head(plan: &Value, kind: &str, subject: &str) -> anyhow::Result<String> {
    let streams = plan["streams"]
        .as_array()
        .context("missing native streams")?;
    let stream = streams
        .iter()
        .find(|s| s["stream_kind"] == kind && s["subject"] == subject)
        .context("native authority proof required; repair this network")?;
    let heads = stream["head_ids"]
        .as_array()
        .context("invalid native heads")?;
    ensure!(
        heads.len() == 1,
        "native authority has missing or conflicting heads; repair this network"
    );
    Ok(heads[0].as_str().context("invalid native head")?.into())
}
pub(crate) async fn planning(
    local: &Local<'_>,
    network: &str,
) -> anyhow::Result<(Value, Descriptor, Catalog)> {
    let plan = local
        .get(format!("/v2/networks/{}/planning", encoded(network)))
        .await?;
    shape(
        &plan,
        "network decision_time catalog streams restriction_ids admitted_ids",
    )?;
    let d = descriptor(&plan["network"])?;
    ensure!(d.network_id == network, "native network mismatch");
    let catalog = Catalog::read(&d, &serde_json::to_vec(&plan["catalog"])?)?;
    Ok((plan, d, catalog))
}
pub(crate) async fn provider(
    local: &Local<'_>,
    network: &str,
    path: Option<&Path>,
    allow_unbound: bool,
) -> anyhow::Result<Option<Provider>> {
    let own = match local
        .get(format!("/v2/networks/{}", encoded(network)))
        .await
    {
        Ok(v) => v,
        Err(e)
            if e.downcast_ref::<DaemonError>()
                .is_some_and(|d| matches!(d.status, 404 | 426)) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    descriptor(&own)?;
    // When the selected provider is the original key itself and this machine
    // holds it (configured owner key file or ssh-agent), the CLI signs with
    // it as with an explicit file, whether or not the daemon also holds it.
    let held = if path.is_none() && own["provider"]["kind"] == "original_person" {
        own["person_public_key"]
            .as_str()
            .and_then(PersonSigner::local_original)
    } else {
        None
    };
    let actual = if path.is_some() || held.is_some() {
        let signer = match (path, held) {
            (Some(path), _) => PersonSigner::open(Some(path)).map_err(anyhow::Error::new)?,
            (None, Some(signer)) => signer,
            (None, None) => unreachable!("checked above"),
        };
        let person = signer.public_key_b64();
        ensure!(
            own["person_public_key"] == person
                || (allow_unbound && own["person_public_key"] == "-"),
            "explicit original person key must match this host's bound person"
        );
        let ceiling = if allow_unbound {
            let (plan, _, catalog) = planning(local, network).await?;
            let mut ceiling = String::from("9999-12-31T23:59:59Z");
            for (kind, subject) in [
                ("person", person.as_str()),
                ("host", text(&own, "host_public_key")?),
            ] {
                let id = head(&plan, kind, subject)?;
                let s = catalog.get(&id)?;
                ceiling = ceiling.min(text(&Value::Object(s.payload.clone()), "not_after")?.into());
            }
            ceiling
        } else {
            let preview = local.post(format!("/v2/networks/{}/provider",encoded(network)),json!({"provider_id":person,"person_public_key":person,"host_public_key":own["host_public_key"],"approve":false})).await?;
            shape(&preview, "network provider provider_state")?;
            ensure!(
                preview["provider"]["kind"] == "original_person"
                    && preview["provider"]["person_public_key"] == person
                    && preview["provider"]["host_public_key"] == own["host_public_key"],
                "external original provider review changed identity"
            );
            text(&preview["provider"], "not_after")?.into()
        };
        Provider {
            person: person.clone(),
            id: person,
            not_after: ceiling,
            kind: "original_person".into(),
            lease: "-".into(),
        }
    } else {
        let v = local
            .get(format!("/v2/networks/{}/provider", encoded(network)))
            .await?;
        shape(
            &v,
            "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after",
        )?;
        ensure!(
            matches!(text(&v, "kind")?, "original_person" | "device")
                && v["person_public_key"] == own["person_public_key"]
                && v["host_public_key"] == own["host_public_key"],
            "selected native provider identity changed"
        );
        Provider {
            person: text(&v, "person_public_key")?.into(),
            id: "auto".into(),
            not_after: text(&v, "not_after")?.into(),
            kind: text(&v, "kind")?.into(),
            lease: text(&v, "lease_id")?.into(),
        }
    };
    ensure!(
        decode(&actual.person)?.len() == 32,
        "invalid native person key"
    );
    chrono::DateTime::parse_from_rfc3339(&actual.not_after)?;
    let mut actual = actual;
    if !allow_unbound {
        // The public provider summary may also describe administrative power.
        // A policy uses its declared finite ancestry only, so an unrelated
        // administrator deadline cannot shorten an owner's policy. The
        // unbound first-policy path above keeps its exact P/H ceiling.
        let host = text(&own, "host_public_key")?.to_owned();
        actual.not_after = policy_ceiling(local, network, &actual, &host).await?;
    }
    Ok(Some(actual))
}
async fn policy_ceiling(
    local: &Local<'_>,
    network: &str,
    provider: &Provider,
    host: &str,
) -> anyhow::Result<String> {
    let (plan, _, catalog) = planning(local, network).await?;
    // The person's ancestry plus this host's membership path (H and B), as
    // in the provider summary, without the administrator lease.
    let mut pending = vec![head(&plan, "person", &provider.person)?];
    for kind in ["host", "binding"] {
        if let Ok(id) = head(&plan, kind, host) {
            pending.push(id);
        }
    }
    if provider.kind == "device" {
        pending.push(provider.lease.clone());
    }
    let mut ceiling = String::from("9999-12-31T23:59:59Z");
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        ensure!(seen.len() <= 4096, "native policy ancestry is too large");
        let s = catalog
            .get(&id)
            .map_err(|_| anyhow::anyhow!("proof_required: exact policy ancestor is missing"))?;
        if let Some(after) = s.payload.get("not_after").and_then(Value::as_str) {
            ceiling = ceiling.min(after.to_owned());
        }
        pending.extend(s.parents()?.into_values());
    }
    Ok(ceiling)
}
pub(crate) async fn reserve(
    local: &Local<'_>,
    network: &str,
    provider: &Provider,
) -> anyhow::Result<Reservation> {
    let v = local
        .post(
            format!("/v2/networks/{}/policy-edits/plan", encoded(network)),
            json!({"provider_id":provider.id}),
        )
        .await?;
    shape(
        &v,
        "context_id person_public_key policy version seq created_at",
    )?;
    ensure!(
        v["person_public_key"] == provider.person,
        "reservation changed owner"
    );
    let (_, d, catalog) = planning(local, network).await?;
    ensure!(
        v["context_id"] == d.context_id(),
        "reservation changed context"
    );
    let policy = if v["policy"] == "-" {
        None
    } else {
        let reference = &v["policy"];
        shape(
            reference,
            "statement_id proof_id statement_base64 body_base64",
        )?;
        let statement = Statement::read(&d, &decode(text(reference, "statement_base64")?)?)?;
        ensure!(
            statement.kind == "policy"
                && statement.id == text(reference, "statement_id")?
                && statement.payload.get("body_base64") == reference.get("body_base64"),
            "invalid native baseline reference"
        );
        let sources = catalog
            .statement_proofs
            .get(&statement.id)
            .context("native baseline proof missing")?;
        ensure!(
            sources.iter().any(|id| reference["proof_id"] == *id)
                && catalog
                    .aliases
                    .get(&statement.id)
                    .is_some_and(|aliases| aliases.iter().any(|s| s.body == statement.body)),
            "native baseline bytes differ from retained proof"
        );
        let body: Value = serde_json::from_slice(&decode(text(reference, "body_base64")?)?)?;
        ensure!(
            body["person_public_key"] == provider.person && body["network_id"] == network,
            "native baseline owner mismatch"
        );
        Some(serde_json::from_value(body)?)
    };
    Ok(Reservation {
        policy,
        version: v["version"].as_u64().context("invalid native version")?,
        seq: v["seq"]
            .as_u64()
            .filter(|s| *s > 0)
            .context("invalid native edit number")?,
        decision_time: text(&v, "created_at")?.into(),
    })
}
pub(crate) async fn reapply(
    local: &Local<'_>,
    network: &str,
    provider: &Provider,
    original: Option<&PersonSigner>,
) -> anyhow::Result<()> {
    let (plan, d, _) = planning(local, network).await?;
    let v = local
        .post(
            format!(
                "/v2/networks/{}/policy-edits/reapply-preview",
                encoded(network)
            ),
            json!({"provider_id":provider.id}),
        )
        .await?;
    shape(
        &v,
        "context_id person_public_key host_public_key provider payload_base64 unsettled_seqs",
    )?;
    shape(
        &v["provider"],
        "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after",
    )?;
    ensure!(
        v["context_id"] == d.context_id()
            && v["person_public_key"] == provider.person
            && v["host_public_key"] == plan["network"]["host_public_key"]
            && v["provider"]["person_public_key"] == provider.person
            && v["provider"]["host_public_key"] == v["host_public_key"]
            && v["provider"]["kind"] == provider.kind
            && v["provider"]["scopes"].as_u64().is_some_and(|s| s & 1 == 1),
        "reapplication changed provider identity"
    );
    if provider.kind == "device" {
        ensure!(
            v["provider"]["lease_id"] == provider.lease,
            "reapplication changed selected device"
        );
    }
    let mut sequences = Vec::new();
    for seq in v["unsettled_seqs"]
        .as_array()
        .context("invalid reapplication sequences")?
    {
        let seq = seq
            .as_u64()
            .filter(|n| *n > 0)
            .context("invalid reapplication sequence")?;
        ensure!(
            sequences.last().is_none_or(|previous| *previous < seq),
            "invalid reapplication sequence order"
        );
        sequences.push(seq);
    }
    ensure!(
        sequences.len() <= 65536,
        "reapplication sequence bound exceeded"
    );
    if sequences.is_empty() {
        ensure!(
            v["payload_base64"] == "-",
            "unexpected reapplication without unsettled edits"
        );
        return Ok(());
    }
    let payload = decode(text(&v, "payload_base64")?)?;
    ensure!(
        payload.len() <= 256 << 10,
        "reapplication payload bound exceeded"
    );
    let signer = if provider.kind == "device" {
        text(&v["provider"], "device_public_key")?
    } else {
        provider.person.as_str()
    };
    let raw = serde_json::to_vec(
        &json!({"format":1,"kind":"policy","context_id":d.context_id(),"payload_base64":STANDARD.encode(&payload),"signatures":[{"role":"issuer","public_key":signer,"format":if provider.kind=="device"{"ed25519"}else{"sshsig"},"signature":"-"}]}),
    )?;
    let fixed = FixedStatement::read(&d, &raw)?;
    let typed = fixed.typed();
    let body: PolicyBody = serde_json::from_slice(&decode(text(
        &Value::Object(typed.payload.clone()),
        "body_base64",
    )?)?)?;
    let own_key = decode(text(&v, "host_public_key")?)?;
    ensure!(own_key.len() == 32, "invalid reapplication host key");
    let own = format!("host_{}", hex::encode(Sha256::digest(&own_key)));
    ensure!(
        typed.kind == "policy"
            && typed.payload["root_state_id"] == v["provider"]["root_state_id"]
            && body.network_id == network
            && body.person_public_key == provider.person
            && body.edits().iter().find(|e| e.host == own).map(|e| e.seq)
                == sequences.last().copied(),
        "reapplication changed exact policy or edit pins"
    );
    let mut concrete = provider.clone();
    concrete.id = if concrete.kind == "device" {
        text(&v["provider"], "lease_id")?.into()
    } else {
        text(&v["provider"], "person_public_key")?.into()
    };
    submit_payload(
        local,
        network,
        &concrete,
        original,
        Submission {
            d: &d,
            payload: &payload,
            capability: None,
            reviewed_provider: Some(&v["provider"]),
        },
    )
    .await?;
    Ok(())
}
pub(crate) async fn submit(
    local: &Local<'_>,
    network: &str,
    provider: &Provider,
    original: Option<&PersonSigner>,
    policy: &PolicyBody,
    capability: Option<&str>,
) -> anyhow::Result<Value> {
    ensure!(
        policy.network_id == network && policy.person_public_key == provider.person,
        "unexpected native policy body"
    );
    let (plan, d, catalog) = planning(local, network).await?;
    let person = head(&plan, "person", &provider.person)?;
    let mut parents = vec![json!({"role":"issuer_person","id":person})];
    let mut issuer = "person";
    if provider.kind == "device" {
        let device = catalog.get(&provider.lease)?;
        ensure!(
            device.kind == "device_lease"
                && device
                    .subject()?
                    .get("person_public_key")
                    .and_then(Value::as_str)
                    == Some(provider.person.as_str()),
            "selected device no longer matches owner"
        );
        parents.insert(0, json!({"role":"issuer_device","id":provider.lease}));
        issuer = "device";
    }
    let stream = plan["streams"]
        .as_array()
        .context("invalid native streams")?
        .iter()
        .find(|s| s["stream_kind"] == "policy" && s["subject"] == provider.person);
    let predecessors = stream.map(|s| s["head_ids"].clone()).unwrap_or(json!([]));
    let maximum = stream
        .map(|s| s["version"].as_u64().context("invalid native maximum"))
        .transpose()?
        .unwrap_or(0);
    if maximum.checked_add(1) != Some(policy.version) {
        return Err(StaleEdit.into());
    }
    let payload = serde_json::to_vec(
        &json!({"root_state_id":plan["network"]["root_state_id"],"operation_id":"-","sequence":policy.version,"predecessors":predecessors,"resolves":[],"issuer":{"kind":issuer,"person_public_key":provider.person},"parents":parents,"issued_at":policy.issued_at,"not_before":policy.issued_at,"not_after":policy.valid_until,"body_base64":STANDARD.encode(serde_json::to_vec(policy)?)}),
    )?;
    submit_payload(
        local,
        network,
        provider,
        original,
        Submission {
            d: &d,
            payload: &payload,
            capability,
            reviewed_provider: None,
        },
    )
    .await
}
async fn submit_payload(
    local: &Local<'_>,
    network: &str,
    provider: &Provider,
    original: Option<&PersonSigner>,
    submission: Submission<'_>,
) -> anyhow::Result<Value> {
    let Submission {
        d,
        payload,
        capability,
        reviewed_provider,
    } = submission;
    let route = if capability.is_some() {
        "policy-claims"
    } else {
        "actions"
    };
    let path = format!("/v2/networks/{}/{route}", encoded(network));
    let mut request = json!({"provider_id":provider.id,"signature_format":if original.is_some(){"sshsig"}else{"auto"},"payload_base64":STANDARD.encode(payload),"approve":false});
    if let Some(name) = capability {
        request["capability"] = Value::from(name);
    } else {
        request["kind"] = Value::from("policy");
    }
    let mut value = local.post(path.clone(), request.clone()).await?;
    let id = text(&value, "action_id")?.to_owned();
    async {
        check_review(&value, &provider.person, d, payload, provider, capability)?;
        if let Some(pin) = reviewed_provider {
            ensure!(
                value["review"]["provider"] == *pin,
                "reapplication provider review changed"
            );
        }
        request["approve"] = Value::Bool(true);
        value = local.post(path, request).await?;
        for _ in 0..3 {
            check_review(&value, &provider.person, d, payload, provider, capability)?;
            if let Some(pin) = reviewed_provider {
                ensure!(
                    value["review"]["provider"] == *pin,
                    "reapplication provider review changed"
                );
            }
            ensure!(value["action_id"] == id, "policy intent changed");
            let slots = value["signing_requests"]
                .as_array()
                .context("invalid native signing slots")?;
            if slots.is_empty() {
                ensure!(
                    value["statement_base64"] != "-" && value["catalog"].is_object(),
                    "policy requires provider repair before completion"
                );
                ensure!(
                    value["committed"] == capability.is_none(),
                    "invalid native publication result"
                );
                return Ok(value);
            }
            let signer=original.context("native provider needs an explicit matching --person-key-file; no original key fallback was used")?;
            let mut signatures = Vec::new();
            let mut intent_id = None;
            for slot in slots {
                shape(
                    slot,
                    "intent_id slot_id object_type object_id role public_key format template_base64 message_base64",
                )?;
                ensure!(
                    slot["slot_id"] == 1
                        && slot["object_type"] == "policy"
                        && slot["role"] == "issuer"
                        && slot["format"] == "sshsig"
                        && slot["public_key"] == signer.public_key_b64(),
                    "unreviewed native signing role"
                );
                let fixed = FixedStatement::read(d, &decode(text(slot, "template_base64")?)?)?;
                let envelope: Value = serde_json::from_slice(fixed.bytes())?;
                ensure!(
                    decode(text(&envelope, "payload_base64")?)?.as_slice() == payload
                        && fixed.statement_id() == text(slot, "object_id")?,
                    "policy template changed"
                );
                let pending = fixed.pending();
                let typed = pending
                    .iter()
                    .find(|s| s.role == "issuer")
                    .context("missing native issuer slot")?;
                ensure!(
                    typed.message_base64 == text(slot, "message_base64")?
                        && typed.public_key == signer.public_key_b64()
                        && typed.signature_format == "sshsig",
                    "native typed message changed"
                );
                let message = String::from_utf8(decode(&typed.message_base64)?)?;
                let payload_value: Value = serde_json::from_slice(payload)?;
                let issued = text(&payload_value, "issued_at")?;
                let decision = peerspan_host::decentralized::decision_clock(
                    &peerspan_host::decentralized::local_decision_time()?,
                    issued,
                )?;
                let decision = chrono::DateTime::parse_from_rfc3339(&decision)?;
                ensure!(
                    decision - chrono::DateTime::parse_from_rfc3339(issued)?
                        <= chrono::TimeDelta::seconds(300)
                        && decision
                            < chrono::DateTime::parse_from_rfc3339(text(&payload_value, "not_after")?)?,
                    "policy signing window expired; resume the retained action {id}"
                );
                let signature = signer
                    .sign(&message.split('\n').collect::<Vec<_>>())
                    .map_err(anyhow::Error::new)?;
                fixed.fill(d, "issuer", &signature)?;
                let observed = text(slot, "intent_id")?;
                ensure!(
                    intent_id.is_none_or(|id| id == observed),
                    "mixed native policy intents"
                );
                intent_id = Some(observed);
                signatures.push(json!({"slot_id":1,"role":"issuer","signature":signature}));
            }
            value=local.post(format!("/v2/networks/{}/{route}/{id}/signed",encoded(network)),json!({"intent_id":intent_id.context("missing native intent")?,"signatures":signatures})).await?;
        }
        bail!("native policy signatures did not complete")
    }
    .await
    .with_context(|| format!("retain exact policy action {id} for resume"))
}
fn check_review(
    value: &Value,
    person: &str,
    d: &Descriptor,
    payload: &[u8],
    provider: &Provider,
    capability: Option<&str>,
) -> anyhow::Result<()> {
    shape(
        value,
        "action_id review signing_requests statement_base64 proof_id catalog committed delivery",
    )?;
    let r = &value["review"];
    shape(
        r,
        "kind statement_id provider subject sequence not_after authority_warning",
    )?;
    ensure!(
        r["kind"]
            == if capability.is_some() {
                "policy_claim"
            } else {
                "policy"
            }
            && r["provider"]["person_public_key"] == person
            && r["provider"]["kind"] == provider.kind,
        "native policy review changed provider"
    );
    if provider.kind == "device" {
        ensure!(
            r["provider"]["lease_id"] == provider.lease,
            "native policy review changed selected device"
        );
    }
    let p: Value = serde_json::from_slice(payload)?;
    ensure!(
        r["provider"]["root_state_id"] == p["root_state_id"]
            && r["sequence"] == p["sequence"]
            && r["not_after"] == p["not_after"],
        "native policy review changed payload"
    );
    if value["statement_base64"] != "-" {
        let s = Statement::read(d, &decode(text(value, "statement_base64")?)?)?;
        ensure!(
            s.kind == "policy"
                && s.payload_bytes == payload
                && r["statement_id"] == s.id
                && value["proof_id"] == s.proof_id,
            "native signed result changed policy"
        );
    }
    Ok(())
}

/// Read native state without opening a signer. Legacy rows keep their own API.
pub(crate) async fn network_view(
    local: &Local<'_>,
    network: &str,
) -> anyhow::Result<Option<Value>> {
    match local
        .get(format!("/v2/networks/{}", encoded(network)))
        .await
    {
        Ok(view) => {
            descriptor(&view)?;
            Ok(Some(view))
        }
        Err(e)
            if e.downcast_ref::<DaemonError>()
                .is_some_and(|d| matches!(d.status, 404 | 426)) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
pub(crate) async fn current_persons(
    local: &Local<'_>,
    network: &Value,
) -> anyhow::Result<Vec<Value>> {
    let d = descriptor(network)?;
    let value = local
        .get(format!("/v2/networks/{}/persons", encoded(&d.network_id)))
        .await?;
    shape(&value, "context_id persons")?;
    ensure!(
        text(&value, "context_id")? == d.context_id(),
        "native person context changed"
    );
    let rows = value["persons"]
        .as_array()
        .context("missing native persons")?;
    ensure!(rows.len() <= 4096, "too many native persons");
    let mut previous = String::new();
    for row in rows {
        shape(row, "person_public_key member person_lease_id not_after")?;
        let key = text(row, "person_public_key")?;
        let raw = decode(key)?;
        ensure!(
            raw.len() == 32 && key > previous.as_str(),
            "invalid native person key order"
        );
        previous = key.into();
        ensure!(
            text(row, "person_lease_id")?.starts_with("ds_"),
            "invalid native person lease"
        );
        chrono::DateTime::parse_from_rfc3339(text(row, "not_after")?)?;
        text(row, "member")?;
    }
    Ok(rows.clone())
}
pub(crate) async fn current_policy(
    local: &Local<'_>,
    network: &Value,
    person: &str,
) -> anyhow::Result<Option<(Statement, PolicyBody)>> {
    let d = descriptor(network)?;
    let value = match local
        .get(format!(
            "/v2/networks/{}/policy/{}",
            encoded(&d.network_id),
            encoded(person)
        ))
        .await
    {
        Ok(value) => value,
        Err(e)
            if e.downcast_ref::<DaemonError>()
                .is_some_and(|d| d.status == 404) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    shape(&value, "statement_id statement_base64")?;
    let raw = decode(text(&value, "statement_base64")?)?;
    ensure!(
        raw.len() <= 1 << 20,
        "native policy statement exceeds bound"
    );
    let statement = Statement::read(&d, &raw)?;
    ensure!(
        statement.kind == "policy" && statement.id == text(&value, "statement_id")?,
        "native policy identity mismatch"
    );
    let body = decode(text(
        &Value::Object(statement.payload.clone()),
        "body_base64",
    )?)?;
    let body: PolicyBody = serde_json::from_slice(&body)?;
    ensure!(
        body.person_public_key == person
            && body.network_id == d.network_id
            && body.version == statement.sequence()?,
        "native policy subject mismatch"
    );
    Ok(Some((statement, body)))
}
