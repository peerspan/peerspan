//! At most B/D issuer then F authority, under one exact captured inspection.
use crate::{
    admin::Local,
    cli::encoded,
    decentralized_link_cli::{check_slot, describe_shape, shape},
    onboarding_owner_sign::{self as owner, Consent, decode, hash, id, text, time},
};
use anyhow::{Result, ensure};
use peerspan_host::{
    decentralized::{FixedPacket, FixedStatement, local_decision_time},
    onboarding_adapter::AdapterContext,
    persons,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::Path, sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    SignOriginalFinalization,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    flow_id: String,
    context: AdapterContext,
    join_review_id: String,
    owner_review_id: String,
    finalization_review_id: String,
    decision: Decision,
}
fn unavailable() -> anyhow::Error {
    anyhow::anyhow!(
        "original finalization signing unavailable or outcome unknown; inspect retained original consent and request progress before another explicit decision"
    )
}
fn effects() -> Value {
    json!({"verify_original_owner":true,"verify_requester_selection":true,
        "verify_administrator_admission":true,"verify_owner_finalization_bounds":true,
        "prepare_finalization":false,"sign_original":false,"publish_finalization":false,
        "commit_request":false,"grant_membership":false,"grant_agent_access":false,
        "share_files":false,"share_conversation":false,"capability_calls":false})
}
fn same(a: &Value, b: &Value) -> Result<()> {
    owner::same_request(a, b)?;
    for k in ["owner_offer_id", "selection_id", "administrator_offer_id"] {
        ensure!(
            a["request"][k] == b["request"][k],
            "changed finalization prefix"
        );
    }
    Ok(())
}
fn live(v: &Value) -> Result<()> {
    let p = &v["request"];
    ensure!(
        p["state"] == "needs_owner_finalization"
            && p["selection_approved"] == true
            && p["commit_approved"] == false,
        "fresh finalization required"
    );
    for k in ["owner_offer_id", "selection_id", "administrator_offer_id"] {
        ensure!(id(text(p, k)?, "dpk_", 64), "missing finalization parent");
    }
    for k in [
        "owner_finalization_id",
        "manifest_id",
        "activation_id",
        "outcome_id",
    ] {
        ensure!(p[k] == "-", "later request work is separate");
    }
    let raw = time(&local_decision_time()?)?;
    let observed = time(text(v, "observed_at")?)?;
    ensure!(
        raw >= time(text(p, "created_at")?)?
            && raw.max(observed) < time(text(p, "expires_at")?)?
            && raw.max(observed) < time(text(&v["owner"]["review"], "not_after")?)?,
        "finalization expired"
    );
    Ok(())
}
fn inspected(v: &Value, original: &Value, consent: &Consent, review_id: &str) -> Result<()> {
    shape(
        v,
        "version host_id flow_id join_review_id owner_review_id context observed_at request review_id review next_action",
    )?;
    ensure!(
        v["version"].as_u64() == Some(1)
            && v["host_id"] == original["host_id"]
            && v["flow_id"] == consent.flow_id
            && v["join_review_id"] == consent.join_review_id
            && v["owner_review_id"] == consent.owner_review_id
            && v["context"] == original["context"]
            && v["review_id"] == review_id
            && v["next_action"] == "review_original_finalization",
        "changed finalization inspection"
    );
    owner::strict_request(&v["request"])?;
    for k in [
        "request_id",
        "role",
        "mode",
        "state",
        "network_id",
        "context_id",
        "migration_proposal_id",
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "created_at",
        "expires_at",
        "request_packet_id",
        "owner_offer_id",
        "selection_id",
        "administrator_offer_id",
        "owner_finalization_id",
        "manifest_id",
        "activation_id",
        "outcome_id",
        "selection_approved",
        "commit_approved",
        "completed",
    ] {
        ensure!(
            v["request"][k] == original["request"][k],
            "changed finalization observation"
        );
    }
    let r = &v["review"];
    shape(
        r,
        "version kind host_id context flow_id join_review_id owner_review_id request_id intent_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id root_state_id person_lease_id host_lease_id administrator scopes binding_scopes not_after created_at expires_at effects",
    )?;
    ensure!(
        r["version"].as_u64() == Some(1)
            && r["kind"] == "inspect_new_original_finalization"
            && hash("peerspan-original-finalization-inspection-v1", r) == review_id
            && r["scopes"].as_u64() == Some(7)
            && r["binding_scopes"].as_u64() == Some(2)
            && r["effects"] == effects(),
        "unreviewed finalization terms"
    );
    for k in [
        "host_id",
        "context",
        "flow_id",
        "join_review_id",
        "owner_review_id",
    ] {
        ensure!(r[k] == v[k], "changed finalization context");
    }
    let o = &original["owner"]["review"];
    for k in [
        "intent_id",
        "network",
        "member",
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "not_after",
    ] {
        ensure!(r[k] == o[k], "changed original finalization target");
    }
    for k in [
        "request_id",
        "request_packet_id",
        "owner_offer_id",
        "selection_id",
        "administrator_offer_id",
        "created_at",
        "expires_at",
    ] {
        ensure!(
            r[k] == original["request"][k],
            "changed finalization prefix"
        );
    }
    for k in ["root_state_id", "person_lease_id", "host_lease_id"] {
        ensure!(
            id(text(r, k)?, "ds_", 64),
            "invalid finalization authority parent"
        );
    }
    ensure!(
        r["root_state_id"] != r["person_lease_id"]
            && r["root_state_id"] != r["host_lease_id"]
            && r["person_lease_id"] != r["host_lease_id"],
        "mixed finalization parents"
    );
    shape(
        &r["administrator"],
        "signer_public_key host_public_key signature_format issuer_id",
    )?;
    for k in ["signer_public_key", "host_public_key"] {
        let key = text(&r["administrator"], k)?;
        ensure!(
            persons::normalize_person_key(key)? == key,
            "invalid administrator key"
        );
    }
    ensure!(
        matches!(
            text(&r["administrator"], "signature_format")?,
            "ed25519" | "sshsig"
        ) && id(text(&r["administrator"], "issuer_id")?, "ds_", 64),
        "invalid administrator identity"
    );
    let observed = time(text(v, "observed_at")?)?;
    ensure!(
        observed >= time(text(original, "observed_at")?)?
            && observed < time(text(r, "expires_at")?)?
            && observed < time(text(r, "not_after")?)?,
        "expired finalization inspection"
    );
    Ok(())
}
struct Fresh {
    original: Value,
    inspection: Value,
    parent: Value,
}
async fn fresh(
    local: &Local<'_>,
    consent: &Consent,
    digest: &str,
    first: &Value,
    parent: Option<&Value>,
) -> Result<Fresh> {
    let original = owner::lookup(local, consent).await?;
    same(first, &original)?;
    live(&original)?;
    let parent = owner::project_binding(local, consent, &original, parent).await?;
    let inspection = owner::http(local, format!("/v1/onboarding/join-flows/{}/owner/finalization/inspect", encoded(&consent.flow_id)),
        Some(json!({"context":consent.context,"join_review_id":consent.join_review_id,"owner_review_id":consent.owner_review_id}))).await?;
    inspected(&inspection, &original, consent, digest)?;
    live(&original)?;
    Ok(Fresh {
        original,
        inspection,
        parent,
    })
}
fn statement(
    raw: &[u8],
    kind: &str,
    r: &Value,
    verified: &Value,
    complete: bool,
) -> Result<FixedStatement> {
    let fixed = FixedStatement::read_link(text(r, "context_id")?, raw)?;
    let s = fixed.typed();
    let p = Value::Object(s.payload.clone());
    let binding = kind == "binding_lease";
    ensure!(
        s.kind == kind
            && fixed.statement_id()
                == text(
                    r,
                    if binding {
                        "binding_lease_id"
                    } else {
                        "device_lease_id"
                    }
                )?,
        "changed finalization statement"
    );
    ensure!(
        p["root_state_id"] == verified["root_state_id"]
            && p["operation_id"] == verified["request_id"]
            && p["not_after"] == verified["not_after"]
            && p["resolves"] == json!([])
            && p["retained_statement_ids"] == json!([]),
        "changed finalization statement bounds"
    );
    ensure!(
        p["subject"]
            == json!({"person_public_key":verified["person_public_key"],"host_public_key":verified["host_public_key"],
        "device_public_key":if binding {json!("-")} else {verified["device_public_key"].clone()},"member":"-","scopes":if binding {2}else{7}})
            && p["issuer"]
                == json!({"kind":"person","person_public_key":verified["person_public_key"]}),
        "changed finalization issuer/subject"
    );
    let mut parents = BTreeMap::from([
        ("issuer_person", verified["person_lease_id"].clone()),
        ("subject_host", verified["host_lease_id"].clone()),
        ("subject_person", verified["person_lease_id"].clone()),
    ]);
    if !binding {
        parents.insert("subject_binding", r["binding_lease_id"].clone());
    }
    ensure!(
        p["parents"]
            == Value::Array(
                parents
                    .into_iter()
                    .map(|(role, id)| json!({"role":role,"id":id}))
                    .collect::<Vec<_>>()
            ),
        "changed finalization statement parents"
    );
    let issued = time(text(&p, "issued_at")?)?;
    ensure!(
        p["not_before"] == p["issued_at"]
            && issued >= time(text(verified, "created_at")?)?
            && issued
                <= time(text(verified, "observation_time")?)?.max(time(&local_decision_time()?)?)
            && issued < time(text(&p, "not_after")?)?,
        "changed finalization issuance"
    );
    let issuer = s.signatures.get("issuer").ok_or_else(unavailable)?;
    ensure!(
        issuer.public_key == text(verified, "person_public_key")?
            && issuer.format == "sshsig"
            && (!complete || issuer.signature != "-"),
        "missing original finalization issuer"
    );
    Ok(fixed)
}
enum Object {
    Statement(FixedStatement),
    Packet(FixedPacket),
}
struct Work {
    slot: u64,
    role: String,
    message: Vec<u8>,
    object: Object,
}
struct Batch {
    work: Vec<Work>,
    packet_id: Option<String>,
}
fn batch(fresh: &Fresh, ordinary: &Value) -> Result<Batch> {
    describe_shape(ordinary)?;
    owner::strict_request(&ordinary["request"])?;
    for (k, v) in fresh.original["request"]
        .as_object()
        .ok_or_else(unavailable)?
    {
        if !matches!(k.as_str(), "attention" | "next") {
            ensure!(
                ordinary["request"][k] == *v,
                "changed ordinary finalization request"
            );
        }
    }
    let r = &ordinary["review"];
    let mut verified = fresh.inspection["review"].clone();
    verified["observation_time"] = fresh.inspection["observed_at"].clone();
    ensure!(
        r["stage"] == "owner_finalization"
            && r["person_id"] == persons::person_id_of(text(&verified, "person_public_key")?)?,
        "unreviewed finalization stage"
    );
    for k in ["network_id", "context_id"] {
        ensure!(
            r[k] == ordinary["request"][k],
            "changed ordinary finalization network"
        );
    }
    for k in [
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "root_state_id",
        "owner_offer_id",
        "selection_id",
        "administrator_offer_id",
        "person_lease_id",
        "host_lease_id",
        "scopes",
        "not_after",
    ] {
        ensure!(r[k] == verified[k], "changed ordinary finalization terms");
    }
    ensure!(
        r["provider"]
            == json!({"kind":"original_person","person_public_key":verified["person_public_key"],"host_public_key":verified["host_public_key"],"device_public_key":"-","lease_id":"-","root_state_id":"-","scopes":0,"not_after":"-"}),
        "changed original provider"
    );
    for k in ["binding_lease_id", "device_lease_id"] {
        ensure!(
            id(text(r, k)?, "ds_", 64),
            "missing ordinary finalization draft"
        );
    }
    ensure!(
        r["binding_lease_id"] != r["device_lease_id"],
        "mixed ordinary finalization drafts"
    );
    let entries = ordinary["signing_requests"]
        .as_array()
        .ok_or_else(unavailable)?;
    ensure!(
        !entries.is_empty() && entries.len() <= 2,
        "unbounded finalization batch"
    );
    let mut prior = None;
    let mut work = Vec::new();
    let mut phase = None;
    let mut packet_id = None;
    let mut packet_raw: Option<Vec<u8>> = None;
    for e in entries {
        shape(
            e,
            "intent_id slot_id object_type object_id role public_key format template_base64 message_base64",
        )?;
        let slot = e["slot_id"].as_u64().ok_or_else(unavailable)?;
        let role = text(e, "role")?;
        ensure!(
            e["intent_id"] == verified["intent_id"]
                && prior
                    .as_ref()
                    .is_none_or(|old: &(u64, String)| old < &(slot, role.into())),
            "changed finalization slot/order"
        );
        prior = Some((slot, role.to_owned()));
        let is_packet = slot == 4;
        ensure!(
            phase.is_none_or(|old| old == is_packet),
            "mixed finalization phases"
        );
        phase = Some(is_packet);
        let raw = decode(text(e, "template_base64")?, 1 << 20)?;
        let message = decode(text(e, "message_base64")?, 4096)?;
        if !is_packet {
            let kind = match slot {
                2 => "binding_lease",
                3 => "device_lease",
                _ => return Err(unavailable()),
            };
            ensure!(
                role == "issuer"
                    && e["object_type"] == kind
                    && e["public_key"] == verified["person_public_key"]
                    && e["format"] == "sshsig",
                "unreviewed original statement slot"
            );
            let fixed = statement(&raw, kind, r, &verified, false)?;
            let (derived, packet) = check_slot(
                e,
                r,
                &ordinary["request"],
                text(&verified, "host_public_key")?,
            )?;
            ensure!(
                !packet && decode(&derived, 4096)? == message,
                "changed original statement message"
            );
            work.push(Work {
                slot,
                role: role.into(),
                message,
                object: Object::Statement(fixed),
            });
        } else {
            ensure!(
                matches!(role, "authority" | "host")
                    && e["object_type"] == "owner_finalization_packet"
                    && packet_raw.as_ref().is_none_or(|old| old == &raw),
                "changed finalization packet entries"
            );
            packet_raw = Some(raw.clone());
            let fixed = FixedPacket::read_context(text(r, "context_id")?, &raw)?;
            let outer: Value = serde_json::from_slice(&raw)?;
            let payload: Value =
                serde_json::from_slice(&decode(text(&outer, "payload_base64")?, 1 << 20)?)?;
            shape(
                &payload,
                "selection_id administrator_offer_id root_state_id person_lease_id host_lease_id binding_lease device_lease",
            )?;
            for k in [
                "selection_id",
                "administrator_offer_id",
                "root_state_id",
                "person_lease_id",
                "host_lease_id",
            ] {
                ensure!(
                    payload[k] == verified[k],
                    "changed finalization packet parents"
                );
            }
            ensure!(
                outer["role"] == "owner_finalization"
                    && outer["request_id"] == verified["request_id"]
                    && outer["writer_host_public_key"] == verified["host_public_key"]
                    && outer["signer_public_key"] == verified["person_public_key"]
                    && outer["person_public_key"] == verified["person_public_key"]
                    && outer["issuer_id"] == "-"
                    && outer["device_signature"] == "-"
                    && outer["authority_signature_format"] == "sshsig"
                    && e["object_id"] == fixed.packet_id(),
                "changed original F packet"
            );
            for kind in ["binding_lease", "device_lease"] {
                statement(
                    &serde_json::to_vec(&payload[kind])?,
                    kind,
                    r,
                    &verified,
                    true,
                )?;
            }
            let pending = fixed.pending()?;
            let ready = pending
                .iter()
                .find(|s| s.role == role)
                .ok_or_else(unavailable)?;
            ensure!(
                e["public_key"] == ready.public_key
                    && e["format"] == ready.signature_format
                    && e["message_base64"] == ready.message_base64,
                "changed typed F slot"
            );
            packet_id = Some(fixed.packet_id().to_owned());
            if role == "authority" {
                ensure!(
                    e["public_key"] == verified["person_public_key"] && e["format"] == "sshsig",
                    "changed original F authority"
                );
                let (derived, packet) = check_slot(
                    e,
                    r,
                    &ordinary["request"],
                    text(&verified, "host_public_key")?,
                )?;
                ensure!(
                    packet && decode(&derived, 4096)? == message,
                    "changed F authority message"
                );
                work.push(Work {
                    slot,
                    role: role.into(),
                    message,
                    object: Object::Packet(fixed),
                });
            } else {
                ensure!(
                    e["public_key"] == verified["host_public_key"] && e["format"] == "ed25519",
                    "foreign F host slot"
                );
            }
        }
    }
    ensure!(!work.is_empty(), "original finalization not ready");
    Ok(Batch { work, packet_id })
}
async fn approval(local: &Local<'_>, first: &Value) -> Result<Value> {
    owner::http(
        local,
        format!(
            "/v2/link/requests/{}/approval",
            encoded(text(&first["request"], "request_id")?)
        ),
        None,
    )
    .await
}
async fn submit(
    local: &Local<'_>,
    consent: &Consent,
    digest: &str,
    first: &Value,
    parent: &Value,
    batch: Batch,
    signer: Arc<persons::PersonSigner>,
) -> Result<Option<String>> {
    let mut signatures = Vec::new();
    for w in batch.work {
        fresh(local, consent, digest, first, Some(parent)).await?;
        let selected = signer.clone();
        let signature = tokio::task::spawn_blocking(move || {
            let message = std::str::from_utf8(&w.message)?;
            selected
                .sign(&message.split('\n').collect::<Vec<_>>())
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())??;
        match w.object {
            Object::Statement(s) => s.check_signature(&w.role, &signature)?,
            Object::Packet(p) => p.check_signature(&w.role, &signature)?,
        }
        signatures.push(json!({"slot_id":w.slot,"role":w.role,"signature":signature}));
    }
    fresh(local, consent, digest, first, Some(parent)).await?;
    owner::http(
        local,
        format!(
            "/v2/link/requests/{}/signed",
            encoded(text(&first["request"], "request_id")?)
        ),
        Some(json!({"intent_id":first["owner"]["review"]["intent_id"],"signatures":signatures})),
    )
    .await?;
    Ok(batch.packet_id)
}
async fn sign(local: &Local<'_>, consent: &Consent, digest: &str) -> Result<Value> {
    let first = owner::lookup(local, consent).await?;
    // Fresh-only: completed history never reaches inspection or original IO.
    live(&first)?;
    let initial = fresh(local, consent, digest, &first, None).await?;
    let ordinary = approval(local, &first).await?;
    let first_batch = batch(&initial, &ordinary)?;
    fresh(local, consent, digest, &first, Some(&initial.parent)).await?;
    let selected = Arc::new(
        owner::signer(text(&first["owner"]["review"], "person_public_key")?.into()).await?,
    );
    let packet = if let Some(id) = submit(
        local,
        consent,
        digest,
        &first,
        &initial.parent,
        first_batch,
        selected.clone(),
    )
    .await?
    {
        id
    } else {
        let current = fresh(local, consent, digest, &first, Some(&initial.parent)).await?;
        let next = approval(local, &first).await?;
        ensure!(
            next["review"] == ordinary["review"],
            "changed dependent finalization drafts"
        );
        let last = batch(&current, &next)?;
        ensure!(
            last.packet_id.is_some(),
            "dependent F is not ready; inspect progress"
        );
        submit(
            local,
            consent,
            digest,
            &first,
            &initial.parent,
            last,
            selected,
        )
        .await?
        .ok_or_else(unavailable)?
    };
    let mut result = owner::lookup(local, consent).await?;
    same(&first, &result)?;
    ensure!(
        result["request"]["owner_finalization_id"] == packet,
        "original F outcome unknown"
    );
    result["original_finalization"] =
        json!({"state":"recorded","review_id":digest,"packet_id":packet});
    Ok(result)
}
pub(crate) async fn from_stdin(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid original finalization signing input");
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    ensure!(
        bytes.len() <= 65536,
        "invalid original finalization signing input"
    );
    let input: Input = peerspan_host::linking::decode_mutation(
        &bytes,
        "flow_id context join_review_id owner_review_id finalization_review_id decision",
    )
    .map_err(|_| invalid())?;
    let Decision::SignOriginalFinalization = input.decision;
    input.context.validate().map_err(|_| invalid())?;
    ensure!(
        id(&input.flow_id, "flow_", 32)
            && id(&input.join_review_id, "review_", 64)
            && id(&input.owner_review_id, "review_", 64)
            && id(&input.finalization_review_id, "review_", 64)
            && !owner::private(&input.context.project_root)
            && !owner::private(&input.context.native_session_id),
        "invalid original finalization signing input"
    );
    let consent = Consent {
        flow_id: input.flow_id,
        context: input.context,
        join_review_id: input.join_review_id,
        owner_review_id: input.owner_review_id,
    };
    tokio::time::timeout(
        Duration::from_secs(90),
        sign(&Local(socket), &consent, &input.finalization_review_id),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}
