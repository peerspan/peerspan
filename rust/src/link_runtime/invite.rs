//! Private invitation wrappers keep seeds local and public feature consent exact.
use super::{
    catalog, crypto, map,
    support::{self, Failure},
};
use crate::{linking, membership, network::Network, persons};
use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, value::RawValue};
pub const PREFIX: &str = "peerspan-feature-invite-v1.";
pub const AUTHORIZED_PREFIX: &str = "peerspan-authorized-invite-v1.";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub format: u64,
    pub network: Box<RawValue>,
    pub token: String,
    pub mode: String,
    pub host_invite_base64: String,
    pub person_invite_base64: String,
    pub feature_binding: Box<RawValue>,
    pub catalog: Box<RawValue>,
}
pub struct Decoded {
    pub token: Token,
    pub network: Network,
    pub seed: ed25519_dalek::SigningKey,
    pub member: String,
    pub expires: String,
    pub host: Vec<u8>,
    pub person: Vec<u8>,
    pub feature: String,
    pub epoch: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorized {
    format: u64,
    network: Box<RawValue>,
    mode: String,
    invite_seed: String,
    host_invite: Box<RawValue>,
    person_invite: Box<RawValue>,
    catalog: Box<RawValue>,
}
fn private_bytes(text: &str, prefix: &str) -> Result<Vec<u8>> {
    let encoded = text
        .strip_prefix(prefix)
        .ok_or_else(|| Failure::new("invalid", "-", "invite"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Failure::new("invalid", "-", "invite"))?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&raw) == encoded && raw.len() <= 16 << 20,
        Failure::new("invalid", "-", "invite")
    );
    Ok(raw)
}
pub fn encode(token: &Token) -> Result<String> {
    Ok(format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(crypto::json(token)?)
    ))
}
pub fn seed_body(token: &Token) -> Result<Vec<u8>> {
    crypto::raw_object(vec![
        ("binding", token.feature_binding.get().as_bytes().to_vec()),
        (
            "host_invite_base64",
            crypto::json(&token.host_invite_base64)?,
        ),
        (
            "person_invite_base64",
            crypto::json(&token.person_invite_base64)?,
        ),
    ])
}
#[allow(clippy::too_many_arguments)] // Fixed public binding fields.
pub fn unsigned(
    p: &catalog::Projection,
    mode: &str,
    host: &[u8],
    person: &[u8],
    issuer: &str,
    original: &str,
    cert: &str,
    signer: &str,
    expires: &str,
) -> Result<Value> {
    let d: map::Descriptor = linking::decode_mutation(
        &p.descriptor,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    Ok(
        json!({"format":1,"network_id":d.network_id,"network_name":d.name,"genesis_root_public_key":d.genesis_root_public_key,"epoch":p.network.epoch,"feature_id":p.network.facts.feature_id,"coordinator_address":d.coordinator_address,"coordinator_public_key":d.coordinator_public_key,"mode":mode,"host_invite_sha256":if host.is_empty(){"-".into()}else{crypto::hash(host)},"person_invite_sha256":if person.is_empty(){"-".into()}else{crypto::hash(person)},"issuer_kind":issuer,"person_public_key":original,"certificate_id":cert,"signer_public_key":signer,"issued_at":support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string(),"expires_at":expires,"host_invite_base64":if host.is_empty(){"-".into()}else{STANDARD.encode(host)},"person_invite_base64":if person.is_empty(){"-".into()}else{STANDARD.encode(person)}}),
    )
}
pub fn decode(text: &str, now: chrono::DateTime<chrono::Utc>, known: &str) -> Result<Decoded> {
    let token: Token = linking::decode_stored_json(
        &private_bytes(text.trim(), PREFIX)?,
        "format network token mode host_invite_base64 person_invite_base64 feature_binding catalog",
    )?;
    ensure!(token.format == 1, Failure::new("invalid", "-", "invite"));
    let d: map::Descriptor = linking::decode_mutation(
        token.network.get().as_bytes(),
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    let halves = [&token.host_invite_base64, &token.person_invite_base64].map(|v| {
        if v == "-" {
            Ok(Vec::new())
        } else {
            crypto::bytes(v, linking::MAX_OBJECT)
        }
    });
    let [host, person] = halves;
    let (host, person) = (host?, person?);
    let objects = catalog::decode(token.catalog.get().as_bytes(), &d.network_id)?;
    let epoch = catalog::target_epoch(&objects)?;
    let evidence = linking::verify_stored_invite_feature(
        linking::CatalogFactContext {
            network: token.network.get().as_bytes(),
            epoch,
            known_feature_id: known,
            now,
        },
        token.catalog.get().as_bytes(),
        token.feature_binding.get().as_bytes(),
        &host,
        &person,
    )?;
    let binding: Value = serde_json::from_str(token.feature_binding.get())?;
    ensure!(
        binding["mode"] == token.mode,
        Failure::new("invalid", "-", "invite")
    );
    let (seed, member, expires, inner_root) = if token.token.starts_with(AUTHORIZED_PREFIX) {
        let inner: Authorized = linking::decode_stored_json(
            &private_bytes(&token.token, AUTHORIZED_PREFIX)?,
            "format network mode invite_seed host_invite person_invite catalog",
        )?;
        ensure!(
            inner.format == 1
                && inner.mode == token.mode
                && serde_json::from_str::<Value>(inner.network.get())?
                    == serde_json::from_str::<Value>(token.network.get())?,
            Failure::new("invalid", "-", "invite")
        );
        catalog::decode(inner.catalog.get().as_bytes(), &d.network_id)?;
        for (raw, half) in [(&host, &inner.host_invite), (&person, &inner.person_invite)] {
            ensure!(
                if raw.is_empty() {
                    half.get() == "\"-\""
                } else {
                    raw == half.get().as_bytes()
                },
                Failure::new("invalid", "-", "invite")
            );
        }
        let grant: Value = serde_json::from_slice(if !host.is_empty() { &host } else { &person })?;
        let payload = crypto::bytes(
            grant["payload_base64"]
                .as_str()
                .ok_or_else(|| Failure::new("invalid", "-", "invite"))?,
            linking::MAX_PAYLOAD,
        )?;
        let payload: Value = serde_json::from_slice(&payload)?;
        (
            membership::seed(&inner.invite_seed)?,
            payload["member"].as_str().unwrap_or("").to_owned(),
            payload["invite_expires_at"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            None,
        )
    } else {
        let (
            network_id,
            name,
            coord,
            key,
            root,
            seed,
            member,
            expires,
            expected_host,
            expected_person,
        ) = if token.token.starts_with(persons::MEMBER_TOKEN_PREFIX) {
            let t: persons::MemberInviteToken = linking::decode_mutation(
                &private_bytes(&token.token, persons::MEMBER_TOKEN_PREFIX)?,
                "network_id network_name root_public_key coordinator_address coordinator_public_key member invite_public_key invite_seed invite_expires_at invite_signature invite_epoch person_invite_signature",
            )?;
            ensure!(
                token.mode == "member",
                Failure::new("invalid", "-", "invite")
            );
            let h = json!({"network_id":t.network_id,"invite_public_key":t.invite_public_key,"member":t.member,"invite_expires_at":t.invite_expires_at,"signature":t.invite_signature});
            let p = json!({"network_id":t.network_id,"invite_epoch":t.invite_epoch,"invite_public_key":t.invite_public_key,"member":t.member,"invite_expires_at":t.invite_expires_at,"signature":t.person_invite_signature});
            (
                t.network_id,
                t.network_name,
                t.coordinator_address,
                t.coordinator_public_key,
                t.root_public_key,
                t.invite_seed,
                t.member,
                t.invite_expires_at,
                Some(h),
                Some(p),
            )
        } else if token.token.starts_with(persons::PERSON_TOKEN_PREFIX) {
            let t: persons::PersonInviteToken = linking::decode_mutation(
                &private_bytes(&token.token, persons::PERSON_TOKEN_PREFIX)?,
                "network_id network_name root_public_key coordinator_address coordinator_public_key member invite_public_key invite_seed invite_expires_at invite_signature invite_epoch",
            )?;
            ensure!(
                token.mode == "person",
                Failure::new("invalid", "-", "invite")
            );
            let p = json!({"network_id":t.network_id,"invite_epoch":t.invite_epoch,"invite_public_key":t.invite_public_key,"member":t.member,"invite_expires_at":t.invite_expires_at,"signature":t.invite_signature});
            (
                t.network_id,
                t.network_name,
                t.coordinator_address,
                t.coordinator_public_key,
                t.root_public_key,
                t.invite_seed,
                t.member,
                t.invite_expires_at,
                None,
                Some(p),
            )
        } else {
            let t: membership::InviteToken = linking::decode_mutation(
                &private_bytes(&token.token, membership::TOKEN_PREFIX)?,
                "network_id network_name root_public_key coordinator_address coordinator_public_key member invite_public_key invite_seed invite_expires_at invite_signature",
            )?;
            ensure!(token.mode == "host", Failure::new("invalid", "-", "invite"));
            let h = json!({"network_id":t.network_id,"invite_public_key":t.invite_public_key,"member":t.member,"invite_expires_at":t.invite_expires_at,"signature":t.invite_signature});
            (
                t.network_id,
                t.network_name,
                t.coordinator_address,
                t.coordinator_public_key,
                t.root_public_key,
                t.invite_seed,
                t.member,
                t.invite_expires_at,
                Some(h),
                None,
            )
        };
        ensure!(
            network_id == d.network_id
                && name == d.name
                && coord == d.coordinator_address
                && key == d.coordinator_public_key,
            Failure::new("invalid", "-", "invite")
        );
        for (raw, expected) in [(&host, expected_host), (&person, expected_person)] {
            ensure!(
                match expected {
                    Some(value) => serde_json::from_slice::<Value>(raw)? == value,
                    None => raw.is_empty(),
                },
                Failure::new("invalid", "-", "invite")
            );
        }
        (membership::seed(&seed)?, member, expires, Some(root))
    };
    let chosen: Value = serde_json::from_slice(if !host.is_empty() { &host } else { &person })?;
    let public = if chosen.get("payload_base64").is_some() {
        serde_json::from_slice::<Value>(&crypto::bytes(
            chosen["payload_base64"].as_str().unwrap_or(""),
            linking::MAX_PAYLOAD,
        )?)?
    } else {
        chosen
    };
    ensure!(
        STANDARD.encode(seed.verifying_key().as_bytes()) == public["invite_public_key"]
            && member == public["member"]
            && expires == public["invite_expires_at"],
        Failure::new("invalid", "-", "invite")
    );
    let state = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network: token.network.get().as_bytes(),
            epoch,
            known_feature_id: &evidence.feature_id,
            now,
        },
        token.catalog.get().as_bytes(),
    )?;
    ensure!(
        inner_root.is_none_or(|r| r == state.root_public_key),
        Failure::new("invalid", "-", "invite")
    );
    membership::label(&member)?;
    let network = Network {
        id: d.network_id,
        name: d.name,
        root_public_key: d.genesis_root_public_key,
        member: member.clone(),
        coordinator_address: d.coordinator_address,
        coordinator_public_key: d.coordinator_public_key,
        administrator: false,
        last_sync_at: None,
        last_sync_error: None,
        root_epoch: epoch,
        current_root_public_key: state.root_public_key,
        root_ssh: false,
        coordinator_pending: None,
    };
    Ok(Decoded {
        token,
        network,
        seed,
        member,
        expires,
        host,
        person,
        feature: evidence.feature_id,
        epoch,
    })
}

pub(super) fn decode_private(text: &str) -> Result<Vec<u8>> {
    private_bytes(text.trim(), PREFIX)
}

pub fn legacy_parts(inner: &str) -> Result<(String, Vec<u8>, Vec<u8>, String)> {
    let (prefix, mode) = if inner.starts_with(persons::MEMBER_TOKEN_PREFIX) {
        (persons::MEMBER_TOKEN_PREFIX, "member")
    } else if inner.starts_with(persons::PERSON_TOKEN_PREFIX) {
        (persons::PERSON_TOKEN_PREFIX, "person")
    } else {
        (membership::TOKEN_PREFIX, "host")
    };
    let t: Value = serde_json::from_slice(&private_bytes(inner, prefix)?)?;
    let host = if mode != "person" {
        crypto::json(
            &json!({"network_id":t["network_id"],"invite_public_key":t["invite_public_key"],"member":t["member"],"invite_expires_at":t["invite_expires_at"],"signature":t["invite_signature"]}),
        )?
    } else {
        Vec::new()
    };
    let person = if mode != "host" {
        crypto::json(
            &json!({"network_id":t["network_id"],"invite_epoch":t["invite_epoch"],"invite_public_key":t["invite_public_key"],"member":t["member"],"invite_expires_at":t["invite_expires_at"],"signature":if mode=="member"{&t["person_invite_signature"]}else{&t["invite_signature"]}}),
        )?
    } else {
        Vec::new()
    };
    Ok((
        mode.into(),
        host,
        person,
        t["invite_expires_at"]
            .as_str()
            .ok_or_else(|| Failure::new("invalid", "-", "invite"))?
            .into(),
    ))
}
pub fn finish(
    network: &[u8],
    catalog: &[u8],
    inner: &str,
    unsigned: &Value,
    signature: String,
) -> Result<String> {
    let mut binding = unsigned.clone();
    let h = binding["host_invite_base64"]
        .as_str()
        .ok_or_else(|| Failure::new("invalid", "-", "invite"))?
        .to_owned();
    let p = binding["person_invite_base64"]
        .as_str()
        .ok_or_else(|| Failure::new("invalid", "-", "invite"))?
        .to_owned();
    let o = binding
        .as_object_mut()
        .ok_or_else(|| Failure::new("invalid", "-", "invite"))?;
    o.remove("host_invite_base64");
    o.remove("person_invite_base64");
    o.insert("signature".into(), json!(signature));
    let token = Token {
        format: 1,
        network: RawValue::from_string(String::from_utf8(network.to_vec())?)?,
        token: inner.into(),
        mode: binding["mode"].as_str().unwrap_or("").into(),
        host_invite_base64: h,
        person_invite_base64: p,
        feature_binding: RawValue::from_string(String::from_utf8(crypto::json(&binding)?)?)?,
        catalog: RawValue::from_string(String::from_utf8(catalog.to_vec())?)?,
    };
    let encoded = encode(&token)?;
    decode(
        &encoded,
        support::now()?,
        binding["feature_id"].as_str().unwrap_or("-"),
    )?;
    Ok(encoded)
}
pub(crate) fn wrap_legacy(
    c: &rusqlite::Connection,
    n: &Network,
    inner: &str,
    signer: &membership::KeySigner<'_>,
) -> Result<String> {
    let Some(p) = catalog::projection(c, n, support::now()?)? else {
        return Ok(inner.into());
    };
    let (mode, host, person, expires) = legacy_parts(inner)?;
    let key = signer.public_key_b64();
    let is_root = key == p.network.root_public_key;
    let fields = unsigned(
        &p,
        &mode,
        &host,
        &person,
        if is_root { "network_root" } else { "person" },
        if is_root { "-" } else { &key },
        if is_root { "-" } else { "root" },
        &key,
        &expires,
    )?;
    let evidence = linking::verify_stored_invite_feature_intent(
        linking::CatalogFactContext {
            network: &p.descriptor,
            epoch: p.network.epoch,
            known_feature_id: &p.network.facts.feature_id,
            now: support::now()?,
        },
        &p.catalog,
        &crypto::json(&fields)?,
    )?;
    let message = std::str::from_utf8(&evidence.message)?;
    let signature = signer.sign(&message.split('\n').collect::<Vec<_>>())?;
    let provisional = finish(&p.descriptor, &p.catalog, inner, &fields, signature.clone())?;
    let decoded = decode(&provisional, support::now()?, &p.network.facts.feature_id)?;
    let selected = linking::select_stored_proof_catalog(
        linking::CatalogFactContext {
            network: &p.descriptor,
            epoch: p.network.epoch,
            known_feature_id: &p.network.facts.feature_id,
            now: support::now()?,
        },
        &p.catalog,
        &[linking::ProofSeed {
            kind: "invite_feature".into(),
            body: seed_body(&decoded.token)?,
        }],
    )?;
    finish(&p.descriptor, &selected, inner, &fields, signature)
}

/// The caller obtains this catalog from the already verified local durable read.
#[allow(clippy::too_many_arguments)] // Fixed public binding fields.
pub fn binding_intent(
    network: &[u8],
    full: &[u8],
    mode: &str,
    host: &[u8],
    person: &[u8],
    issuer: &str,
    original: &str,
    cert: &str,
    signer: &str,
    expires: &str,
) -> Result<Value> {
    let d: map::Descriptor = linking::decode_mutation(
        network,
        "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
    )?;
    let objects = catalog::decode(full, &d.network_id)?;
    let epoch = catalog::target_epoch(&objects)?;
    let state = linking::verify_stored_network_state(
        linking::CatalogFactContext {
            network,
            epoch,
            known_feature_id: "-",
            now: support::now()?,
        },
        full,
    )?;
    Ok(
        json!({"format":1,"network_id":d.network_id,"network_name":d.name,"genesis_root_public_key":d.genesis_root_public_key,"epoch":epoch,"feature_id":state.facts.feature_id,"coordinator_address":d.coordinator_address,"coordinator_public_key":d.coordinator_public_key,"mode":mode,"host_invite_sha256":if host.is_empty(){"-".into()}else{crypto::hash(host)},"person_invite_sha256":if person.is_empty(){"-".into()}else{crypto::hash(person)},"issuer_kind":issuer,"person_public_key":original,"certificate_id":cert,"signer_public_key":signer,"issued_at":support::now()?.format("%Y-%m-%dT%H:%M:%SZ").to_string(),"expires_at":expires,"host_invite_base64":if host.is_empty(){"-".into()}else{STANDARD.encode(host)},"person_invite_base64":if person.is_empty(){"-".into()}else{STANDARD.encode(person)}}),
    )
}
