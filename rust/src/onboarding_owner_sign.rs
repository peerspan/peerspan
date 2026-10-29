//! One explicit local original owner-offer signature, never a ceremony driver.
use crate::{
    admin::Local,
    cli::encoded,
    decentralized_link_cli::{check_slot, describe_shape, shape, view},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use peerspan_host::{
    canonical,
    decentralized::{Descriptor, FixedPacket, local_decision_time},
    onboarding_adapter::AdapterContext,
    persons::{self, PersonSigner},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    SignOriginalOwnerOffer,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    flow_id: String,
    context: AdapterContext,
    join_review_id: String,
    owner_review_id: String,
    decision: Decision,
}
fn unavailable() -> anyhow::Error {
    anyhow::anyhow!(
        "original owner signing unavailable; inspect the recorded owner consent before another explicit attempt"
    )
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(unavailable)
}
fn id(s: &str, prefix: &str, n: usize) -> bool {
    s.strip_prefix(prefix).is_some_and(|s| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn decode(s: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        s.len() <= max.div_ceil(3) * 4,
        "bounded original signing material required"
    );
    let raw = STANDARD.decode(s)?;
    ensure!(
        raw.len() <= max && STANDARD.encode(&raw) == s,
        "canonical original signing material required"
    );
    Ok(raw)
}
fn time(s: &str) -> Result<DateTime<Utc>> {
    let t = DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc);
    ensure!(
        t.to_rfc3339_opts(SecondsFormat::Secs, true) == s,
        "whole-second original signing time required"
    );
    Ok(t)
}
fn hash(domain: &str, v: &Value) -> String {
    format!(
        "review_{}",
        hex::encode(Sha256::digest(
            format!("{domain}\n{}", canonical::value_text(v)).as_bytes()
        ))
    )
}
fn private(s: &str) -> bool {
    let stripped:String=s.chars().filter(|c|!c.is_control() && !matches!(*c,'\u{200b}'..='\u{200f}'|'\u{2028}'..='\u{202e}'|'\u{2060}'..='\u{206f}'|'\u{feff}')).collect();
    [s, &stripped].iter().any(|s| {
        [
            "psi2-",
            "psl2-",
            "token_",
            "instance_",
            "peerspan-invite-v1.",
            "peerspan-person-invite-v1.",
            "peerspan-member-invite-v1.",
        ]
        .iter()
        .any(|p| s.contains(p))
    })
}
fn label(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 128 && !s.chars().any(char::is_control) && !private(s)
}
fn owner_body(input: &Input) -> Value {
    json!({"context":input.context,"join_review_id":input.join_review_id})
}
async fn http(local: &Local<'_>, path: String, body: Option<Value>) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        match body {
            Some(body) => local.post(path, body).await,
            None => local.get(path).await,
        }
    })
    .await
    .map_err(|_| unavailable())?
}
fn effects() -> Value {
    json!({"approve_owner_intent":true,"authorize_original_signature":true,"authorize_bounded_owner_finalization":true,"auto_select_single_offer_after_signature":true,"publish_owner_offer_after_signature":true,"grant_membership":false,"grant_agent_access":false,"approve_network_administrator":false,"commit_request":false,"share_files":false,"share_conversation":false,"capability_calls":false})
}
fn strict_request(p: &Value) -> Result<()> {
    shape(
        p,
        "request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next",
    )?;
    view(p)
}
fn checked(v: &Value, input: &Input) -> Result<()> {
    shape(
        v,
        "version host_id flow_id join_review_id context observed_at request owner",
    )?;
    ensure!(
        v["version"].as_u64() == Some(1)
            && v["flow_id"] == input.flow_id
            && v["join_review_id"] == input.join_review_id
            && v["context"] == serde_json::to_value(&input.context)?,
        "changed original signing context"
    );
    let p = &v["request"];
    strict_request(p)?;
    ensure!(
        p["role"] == "requester"
            && p["mode"] == "new"
            && p["migration_proposal_id"] == "-"
            && id(text(p, "request_id")?, "link_", 64),
        "unsupported original request"
    );
    for k in ["selection_approved", "commit_approved"] {
        ensure!(p[k].is_boolean(), "invalid original request consent");
    }
    ensure!(
        !(p["commit_approved"] == true && p["selection_approved"] != true),
        "invalid requester consent"
    );
    for k in [
        "request_packet_id",
        "owner_offer_id",
        "selection_id",
        "administrator_offer_id",
        "owner_finalization_id",
        "outcome_id",
    ] {
        ensure!(
            (k != "request_packet_id" && p[k] == "-") || id(text(p, k)?, "dpk_", 64),
            "invalid original packet reference"
        );
    }
    for (k, prefix) in [("manifest_id", "dm_"), ("activation_id", "da_")] {
        ensure!(
            p[k] == "-" || id(text(p, k)?, prefix, 64),
            "invalid original result reference"
        );
    }
    let completed = p["completed"].as_array().ok_or_else(unavailable)?;
    let stages = [
        "request_created",
        "owner_offered",
        "owner_selected",
        "administrator_offered",
        "owner_finalized",
        "commit_persisted",
        "locally_applied",
    ];
    ensure!(
        !completed.is_empty() && completed.len() <= 7 && completed[0] == "request_created",
        "invalid original stages"
    );
    let mut prior = None;
    for stage in completed {
        let n = stages
            .iter()
            .position(|s| stage == *s)
            .ok_or_else(unavailable)?;
        ensure!(prior.is_none_or(|p| p < n), "unordered original stages");
        prior = Some(n);
    }
    for (stage, k) in [
        ("owner_offered", "owner_offer_id"),
        ("owner_selected", "selection_id"),
        ("administrator_offered", "administrator_offer_id"),
        ("owner_finalized", "owner_finalization_id"),
    ] {
        ensure!(
            completed.contains(&json!(stage)) == (p[k] != "-"),
            "changed original stages"
        );
    }
    for k in ["attention", "next"] {
        let a = p[k].as_array().ok_or_else(unavailable)?;
        ensure!(
            a.len() <= 32
                && a.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty()
                    && s.len() <= 1024
                    && !s.chars().any(char::is_control)
                    && !private(s))),
            "invalid original observation"
        );
    }
    let host_key = decode(text(p, "host_public_key")?, 32)?;
    ensure!(host_key.len() == 32, "invalid original host key");
    ensure!(
        text(v, "host_id")? == format!("host_{}", hex::encode(Sha256::digest(&host_key))),
        "changed original host"
    );
    let o = &v["owner"];
    shape(o, "review_id review state next_action")?;
    ensure!(
        o["state"] == "approved" && o["review_id"] == input.owner_review_id,
        "exact approved owner consent required"
    );
    let r = &o["review"];
    shape(
        r,
        "version kind host_id context flow_id join_review_id request_id intent_id network member person_public_key host_public_key device_public_key proposed_owner_offer_id scopes not_after expires_at effects",
    )?;
    ensure!(
        r["version"].as_u64() == Some(1)
            && r["kind"] == "approve_new_original_owner"
            && r["host_id"] == v["host_id"]
            && r["context"] == v["context"]
            && r["flow_id"] == input.flow_id
            && r["join_review_id"] == input.join_review_id
            && r["request_id"] == p["request_id"]
            && id(text(r, "intent_id")?, "dint_", 32)
            && id(text(r, "proposed_owner_offer_id")?, "dpk_", 64),
        "changed approved original identity"
    );
    ensure!(
        r["scopes"].as_u64() == Some(7)
            && r["effects"] == effects()
            && hash("peerspan-onboarding-original-owner-review-v1", r) == input.owner_review_id,
        "changed approved original terms"
    );
    shape(&r["network"], "id name context_id genesis_root_public_key")?;
    let d = Descriptor::read(&serde_json::to_vec(
        &json!({"format":1,"protocol":"peerspan-decentralized-v1","network_id":r["network"]["id"],"name":r["network"]["name"],"genesis_root_public_key":r["network"]["genesis_root_public_key"]}),
    )?)?;
    ensure!(
        r["network"]["context_id"] == d.context_id()
            && r["network"]["id"] == p["network_id"]
            && r["network"]["context_id"] == p["context_id"]
            && label(&d.name)
            && label(text(r, "member")?),
        "changed original network/member"
    );
    for k in ["person_public_key", "host_public_key", "device_public_key"] {
        ensure!(
            r[k] == p[k] && persons::normalize_person_key(text(r, k)?)? == text(r, k)?,
            "changed original target key"
        );
    }
    let created = time(text(p, "created_at")?)?;
    let observed = time(text(v, "observed_at")?)?;
    ensure!(
        observed >= created
            && time(text(p, "expires_at")?)? > created
            && time(text(r, "not_after")?)? == created + TimeDelta::days(7)
            && time(text(r, "expires_at")?)? > created
            && time(text(r, "expires_at")?)? <= time(text(p, "expires_at")?)?
            && time(text(r, "expires_at")?)? <= observed + TimeDelta::minutes(15),
        "changed original finite terms"
    );
    let next = if p["owner_offer_id"] == "-" {
        "provide_original_signature"
    } else {
        "follow_join_progress"
    };
    ensure!(
        o["next_action"] == next
            && (p["owner_offer_id"] == "-" || p["owner_offer_id"] == r["proposed_owner_offer_id"]),
        "changed original offer"
    );
    Ok(())
}
async fn lookup(local: &Local<'_>, input: &Input) -> Result<Value> {
    let v = http(
        local,
        format!(
            "/v1/onboarding/join-flows/{}/owner/lookup",
            encoded(&input.flow_id)
        ),
        Some(owner_body(input)),
    )
    .await?;
    checked(&v, input)?;
    Ok(v)
}
fn same_request(a: &Value, b: &Value) -> Result<()> {
    ensure!(
        a["owner"]["review"] == b["owner"]["review"],
        "changed original review"
    );
    for k in [
        "request_id",
        "network_id",
        "context_id",
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "created_at",
        "expires_at",
        "request_packet_id",
    ] {
        ensure!(
            a["request"][k] == b["request"][k],
            "changed original request"
        );
    }
    Ok(())
}
fn recorded(mut v: Value) -> Value {
    v["original_signature"] = json!({"state":"recorded"});
    v
}
fn live(v: &Value) -> Result<()> {
    let p = &v["request"];
    let r = &v["owner"]["review"];
    ensure!(
        p["state"] == "pending"
            && p["selection_approved"] == false
            && p["commit_approved"] == false,
        "live original offer required"
    );
    for k in [
        "owner_offer_id",
        "selection_id",
        "administrator_offer_id",
        "owner_finalization_id",
        "manifest_id",
        "activation_id",
        "outcome_id",
    ] {
        ensure!(p[k] == "-", "later original work is separate");
    }
    let now = time(&local_decision_time()?)?.max(time(text(v, "observed_at")?)?);
    ensure!(
        now < time(text(p, "expires_at")?)? && now < time(text(r, "not_after")?)?,
        "original request expired"
    );
    Ok(())
}
async fn binding(
    local: &Local<'_>,
    input: &Input,
    v: &Value,
    parent: Option<&Value>,
) -> Result<Value> {
    live(v)?;
    let current = tokio::time::timeout(
        Duration::from_secs(5),
        crate::onboarding_identity_cli::parent(local, &input.context),
    )
    .await
    .map_err(|_| unavailable())??;
    ensure!(
        current.1 == text(v, "host_id")? && parent.is_none_or(|p| p == &current.0),
        "changed original parent/host"
    );
    let f = http(
        local,
        format!("/v1/onboarding/join-flows/{}", encoded(&input.flow_id)),
        None,
    )
    .await?;
    shape(
        &f,
        "version host_id flow_id review_id state review outcome next_action",
    )?;
    let r = &f["review"];
    shape(
        r,
        "version kind flow_id host_id context agent invitation_review_id invitation person_public_key expires_at effects",
    )?;
    ensure!(
        f["version"].as_u64() == Some(1)
            && f["state"] == "requested"
            && f["flow_id"] == input.flow_id
            && f["review_id"] == input.join_review_id
            && f["host_id"] == v["host_id"]
            && f["next_action"] == "await_participant_reviews"
            && r["kind"] == "create_join_request"
            && r["version"].as_u64() == Some(1)
            && r["flow_id"] == f["flow_id"]
            && r["host_id"] == f["host_id"]
            && r["context"] == v["context"]
            && r["agent"] == current.0["review"]["agent"]
            && r["person_public_key"] == v["request"]["person_public_key"]
            && hash("peerspan-join-review-v1", r) == input.join_review_id,
        "changed published original flow"
    );
    shape(
        &f["outcome"],
        "request_id network_id context_id person_public_key",
    )?;
    for k in [
        "request_id",
        "network_id",
        "context_id",
        "person_public_key",
    ] {
        ensure!(
            f["outcome"][k] == v["request"][k],
            "changed original publication outcome"
        );
    }
    ensure!(
        r["invitation"]["network"] == v["owner"]["review"]["network"]
            && r["invitation"]["invitation"]["member"] == v["owner"]["review"]["member"],
        "changed original introduction"
    );
    let networks = http(local, "/v2/networks".into(), None).await?;
    ensure!(
        !networks
            .as_array()
            .ok_or_else(unavailable)?
            .iter()
            .any(|n| n["id"] == v["request"]["network_id"]),
        "original network already adopted"
    );
    live(v)?;
    Ok(current.0)
}
struct Offer {
    packet: FixedPacket,
    message: Option<String>,
}
fn offer(v: &Value, ordinary: &Value) -> Result<Option<Offer>> {
    describe_shape(ordinary)?;
    let p = &ordinary["request"];
    strict_request(p)?;
    let r = &ordinary["review"];
    let expected = &v["owner"]["review"];
    for k in [
        "request_id",
        "role",
        "mode",
        "network_id",
        "context_id",
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "created_at",
        "expires_at",
        "request_packet_id",
    ] {
        ensure!(p[k] == v["request"][k], "changed original signing request");
    }
    ensure!(
        p["state"] == "pending"
            && p["owner_offer_id"] == "-"
            && p["selection_approved"] == false
            && p["commit_approved"] == false
            && r["stage"] == "owner"
            && r["owner_offer_id"] == expected["proposed_owner_offer_id"]
            && r["person_id"] == persons::person_id_of(text(expected, "person_public_key")?)?,
        "unreviewed original signing stage"
    );
    for k in ["network_id", "context_id"] {
        ensure!(r[k] == p[k], "changed original network");
    }
    for k in [
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "scopes",
        "not_after",
    ] {
        ensure!(r[k] == expected[k], "changed original signing target");
    }
    for k in [
        "root_state_id",
        "selection_id",
        "administrator_offer_id",
        "person_lease_id",
        "host_lease_id",
        "binding_lease_id",
        "device_lease_id",
    ] {
        ensure!(r[k] == "-", "original finalization is separate");
    }
    ensure!(
        r["provider"]
            == json!({"kind":"original_person","person_public_key":expected["person_public_key"],"host_public_key":expected["host_public_key"],"device_public_key":"-","lease_id":"-","root_state_id":"-","scopes":0,"not_after":"-"}),
        "unreviewed original provider"
    );
    for k in [
        "state",
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
        ensure!(p[k] == v["request"][k], "changed original signing stage");
    }
    let requests = ordinary["signing_requests"]
        .as_array()
        .ok_or_else(unavailable)?;
    ensure!(requests.len() <= 2, "unbounded original signing batch");
    let mut selected: Option<Offer> = None;
    let mut prior: Option<String> = None;
    let mut raw_template: Option<Vec<u8>> = None;
    for entry in requests {
        shape(
            entry,
            "intent_id slot_id object_type object_id role public_key format template_base64 message_base64",
        )?;
        let role = text(entry, "role")?;
        ensure!(
            entry["intent_id"] == expected["intent_id"]
                && entry["slot_id"].as_u64() == Some(1)
                && entry["object_type"] == "owner_offer_packet"
                && entry["object_id"] == expected["proposed_owner_offer_id"]
                && matches!(role, "authority" | "host")
                && prior.as_ref().is_none_or(|old| old.as_str() < role),
            "unreviewed original slot"
        );
        prior = Some(role.into());
        let raw = decode(text(entry, "template_base64")?, 1 << 20)?;
        ensure!(
            raw_template.as_ref().is_none_or(|old| old == &raw),
            "mixed original templates"
        );
        raw_template = Some(raw.clone());
        let packet = FixedPacket::read_context(text(p, "context_id")?, &raw)?;
        ensure!(
            packet.packet_id() == text(expected, "proposed_owner_offer_id")?,
            "changed original object ID"
        );
        let outer: Value = serde_json::from_slice(&raw)?;
        let payload: Value =
            serde_json::from_slice(&decode(text(&outer, "payload_base64")?, 1 << 20)?)?;
        let descriptor = json!({"format":1,"protocol":"peerspan-decentralized-v1","network_id":expected["network"]["id"],"name":expected["network"]["name"],"genesis_root_public_key":expected["network"]["genesis_root_public_key"]});
        ensure!(
            outer["role"] == "owner"
                && outer["request_id"] == p["request_id"]
                && outer["writer_host_public_key"] == expected["host_public_key"]
                && outer["signer_public_key"] == expected["person_public_key"]
                && outer["person_public_key"] == expected["person_public_key"]
                && outer["issuer_id"] == "-"
                && outer["authority_signature_format"] == "sshsig"
                && outer["device_signature"] == "-"
                && payload["descriptor"] == descriptor
                && payload["request_packet_id"] == p["request_packet_id"]
                && payload["mode"] == "new"
                && payload["member"] == expected["member"]
                && payload["root_state_id"] == "-"
                && payload["person_lease_id"] == "-"
                && payload["issuer_lease_ids"] == json!([])
                && payload["renewed_device_lease_id"] == "-",
            "changed original possession template"
        );
        for k in [
            "host_public_key",
            "device_public_key",
            "scopes",
            "not_after",
        ] {
            ensure!(payload[k] == expected[k], "changed original offer terms");
        }
        let pending = packet.pending()?;
        let slot = pending
            .iter()
            .find(|s| s.role == role)
            .ok_or_else(unavailable)?;
        ensure!(
            entry["public_key"] == slot.public_key
                && entry["format"] == slot.signature_format
                && entry["message_base64"] == slot.message_base64,
            "changed derived original slot"
        );
        decode(text(entry, "message_base64")?, 4096)?;
        if role == "authority" {
            let (message, is_packet) = check_slot(entry, r, p, text(expected, "host_public_key")?)?;
            ensure!(
                is_packet
                    && entry["public_key"] == expected["person_public_key"]
                    && entry["format"] == "sshsig",
                "unreviewed original authority"
            );
            selected = Some(Offer {
                packet,
                message: Some(message),
            });
        } else {
            ensure!(
                entry["public_key"] == expected["host_public_key"] && entry["format"] == "ed25519",
                "foreign host slot"
            );
            if outer["authority_signature"] != "-" {
                ensure!(selected.is_none(), "inconsistent original signature state");
                selected = Some(Offer {
                    packet,
                    message: None,
                });
            }
        }
    }
    Ok(selected)
}
async fn signer(public: String) -> Result<PersonSigner> {
    tokio::task::spawn_blocking(move || {
        if let Some(key) = crate::onboarding_identity_create::read_existing()? {
            let selected = PersonSigner::File(key);
            if selected.public_key_b64() == public {
                return Ok(selected);
            }
        }
        PersonSigner::agent_with(&public).map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())?
}
async fn sign(local: &Local<'_>, input: &Input) -> Result<Value> {
    let first = lookup(local, input).await?;
    if first["request"]["owner_offer_id"] != "-" {
        return Ok(recorded(first));
    }
    let parent = binding(local, input, &first, None).await?;
    let ordinary = http(
        local,
        format!(
            "/v2/link/requests/{}/approval",
            encoded(text(&first["request"], "request_id")?)
        ),
        None,
    )
    .await?;
    let Some(offer) = offer(&first, &ordinary)? else {
        let current = lookup(local, input).await?;
        same_request(&first, &current)?;
        ensure!(
            current["request"]["owner_offer_id"] != "-",
            "original signing not ready"
        );
        return Ok(recorded(current));
    };
    let Some(message) = offer.message else {
        let current = lookup(local, input).await?;
        same_request(&first, &current)?;
        return Ok(recorded(current));
    };
    let selected = signer(text(&first["owner"]["review"], "person_public_key")?.into()).await?;
    let current = lookup(local, input).await?;
    same_request(&first, &current)?;
    if current["request"]["owner_offer_id"] != "-" {
        return Ok(recorded(current));
    }
    binding(local, input, &current, Some(&parent)).await?;
    let bytes = decode(&message, 4096)?;
    let signature = tokio::task::spawn_blocking(move || {
        let text = std::str::from_utf8(&bytes)?;
        selected
            .sign(&text.split('\n').collect::<Vec<_>>())
            .map_err(|_| unavailable())
    })
    .await
    .map_err(|_| unavailable())??;
    offer.packet.check_signature("authority", &signature)?;
    let current = lookup(local, input).await?;
    same_request(&first, &current)?;
    if current["request"]["owner_offer_id"] != "-" {
        return Ok(recorded(current));
    }
    binding(local, input, &current, Some(&parent)).await?;
    http(local,format!("/v2/link/requests/{}/signed",encoded(text(&first["request"],"request_id")?)),Some(json!({"intent_id":first["owner"]["review"]["intent_id"],"signatures":[{"slot_id":1,"role":"authority","signature":signature}]}))).await?;
    let outcome = lookup(local, input).await?;
    same_request(&first, &outcome)?;
    ensure!(
        outcome["request"]["owner_offer_id"] == first["owner"]["review"]["proposed_owner_offer_id"],
        "original signing outcome unknown"
    );
    Ok(recorded(outcome))
}
pub(crate) async fn from_stdin(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid original owner signing input");
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    ensure!(bytes.len() <= 65536, "invalid original owner signing input");
    let input: Input = peerspan_host::linking::decode_mutation(
        &bytes,
        "flow_id context join_review_id owner_review_id decision",
    )
    .map_err(|_| invalid())?;
    let Decision::SignOriginalOwnerOffer = input.decision;
    input.context.validate().map_err(|_| invalid())?;
    ensure!(
        id(&input.flow_id, "flow_", 32)
            && id(&input.join_review_id, "review_", 64)
            && id(&input.owner_review_id, "review_", 64)
            && !private(&input.context.project_root)
            && !private(&input.context.native_session_id),
        "invalid original owner signing input"
    );
    sign(&Local(socket), &input)
        .await
        .map_err(|_| unavailable())
}
