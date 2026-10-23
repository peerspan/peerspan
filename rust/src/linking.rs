//! Signed-object readers and exact certificate-path evaluation for machine linking.
//! A signature alone does not prove activation, membership, a live chain, a role,
//! or permission to mutate state. Path evaluation requires verified current state.
use anyhow::{Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signature;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt};

mod path;
pub use path::{DeviceKey, PathError, PathState, PersonState, SigningPath, evaluate_path};

pub const MAX_OBJECT: usize = 1 << 20;
pub const MAX_PAYLOAD: usize = 256 << 10;
const MAX_DEPTH: usize = 64;
type Obj = Map<String, Value>;

/// Cryptographic evidence only. Callers must separately resolve authority.
pub struct SignedObject {
    pub message: Vec<u8>,
    pub id: String,
    pub payload: Option<Vec<u8>>,
}
fn signed(message: Vec<u8>, id: String, payload: Option<Vec<u8>>) -> SignedObject {
    SignedObject {
        message,
        id,
        payload,
    }
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn lines(v: &[&str]) -> Vec<u8> {
    v.join("\n").into_bytes()
}
fn ident(s: &str, prefix: &str) -> bool {
    s.len() == prefix.len() + 64
        && s.starts_with(prefix)
        && s[prefix.len()..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn decode(s: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(s.len() <= max.div_ceil(3) * 4, "oversized Base64");
    let b = STANDARD.decode(s)?;
    ensure!(
        b.len() <= max && STANDARD.encode(&b) == s,
        "noncanonical Base64"
    );
    Ok(b)
}
fn key(s: &str) -> bool {
    let Ok(b) = decode(s, 32) else { return false };
    if b.len() != 32 {
        return false;
    }
    let mut y: [u8; 32] = b.as_slice().try_into().expect("length checked");
    y[31] &= 127;
    let mut p = [255u8; 32];
    p[0] = 237;
    p[31] = 127;
    if y.iter().rev().cmp(p.iter().rev()) != std::cmp::Ordering::Less {
        return false;
    }
    crate::membership::public_key(s).is_ok_and(|k| !k.is_weak())
}

fn stamp(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let t = chrono::DateTime::parse_from_rfc3339(s)?.to_utc();
    ensure!(
        s.len() == 20
            && t.format("%Y-%m-%dT%H:%M:%SZ").to_string() == s
            && t.timestamp_subsec_nanos() == 0,
        "noncanonical time"
    );
    Ok(t)
}
struct StrictSeed {
    depth: usize,
}
struct StrictVisitor {
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom("JSON too deep"));
        }
        d.deserialize_any(StrictVisitor { depth: self.depth })
    }
}
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("strict non-null JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = a.next_element_seed(StrictSeed {
            depth: self.depth + 1,
        })? {
            out.push(v)
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = Map::new();
        let mut seen = HashSet::new();
        while let Some(k) = a.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            let v = a.next_value_seed(StrictSeed {
                depth: self.depth + 1,
            })?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}
fn parse(b: &[u8]) -> Result<Value> {
    parse_limit(b, MAX_OBJECT)
}
fn parse_limit(b: &[u8], limit: usize) -> Result<Value> {
    ensure!(b.len() <= limit, "oversized object");
    std::str::from_utf8(b)?;
    let mut d = serde_json::Deserializer::from_slice(b);
    let v = StrictSeed { depth: 0 }.deserialize(&mut d)?;
    d.end()?;
    ensure!(v.is_object(), "object required");
    Ok(v)
}
fn object(v: &Value) -> Result<&Obj> {
    v.as_object().ok_or_else(|| anyhow!("object required"))
}
fn fields(o: &Obj, required: &str, optional: &[&str]) -> Result<()> {
    let mut allowed = HashSet::new();
    for f in required.split_whitespace() {
        ensure!(o.contains_key(f), "missing field");
        allowed.insert(f);
    }
    allowed.extend(optional.iter().copied());
    ensure!(
        o.keys().all(|k| allowed.contains(k.as_str())),
        "unknown field"
    );
    Ok(())
}
fn text<'a>(o: &'a Obj, k: &str) -> Result<&'a str> {
    let s = o
        .get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("string required"))?;
    ensure!(!s.contains(['\r', '\n', '\0']), "invalid scalar");
    Ok(s)
}
fn num(o: &Obj, k: &str) -> Result<u64> {
    o.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("unsigned integer required"))
}
fn version(o: &Obj, n: u64) -> Result<()> {
    ensure!(num(o, "format")? == n, "unknown format");
    Ok(())
}
fn string_list<'a>(o: &'a Obj, k: &str) -> Result<Vec<&'a str>> {
    let a = o
        .get(k)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("array required"))?;
    ensure!(a.len() <= 4096, "too many items");
    a.iter()
        .map(|v| v.as_str().ok_or_else(|| anyhow!("string required")))
        .collect()
}
fn sorted(a: &[&str]) -> bool {
    a.iter().all(|s| !s.contains(['\r', '\n', '\0'])) && a.windows(2).all(|p| p[0] < p[1])
}
fn ssh(k: &str, m: &[u8], sig: &str) -> Result<()> {
    ensure!(key(k), "invalid weak key");
    let s = std::str::from_utf8(m)?;
    crate::persons::verify_sshsig(k, &s.split('\n').collect::<Vec<_>>(), sig)
        .map_err(|_| anyhow!("invalid SSHSIG"))
}
fn raw(k: &str, m: &[u8], sig: &str) -> Result<()> {
    ensure!(key(k), "invalid weak key");
    let pubkey = crate::membership::public_key(k).map_err(|_| anyhow!("invalid key"))?;
    let bytes: [u8; 64] = decode(sig, 64)?
        .try_into()
        .map_err(|_| anyhow!("invalid signature size"))?;
    pubkey
        .verify_strict(m, &Signature::from_bytes(&bytes))
        .map_err(|_| anyhow!("invalid signature"))
}
fn root(k: &str, m: &[u8], sig: &str) -> Result<()> {
    if decode(sig, MAX_OBJECT)?.len() == 64 {
        raw(k, m, sig)
    } else {
        ssh(k, m, sig)
    }
}
fn root_person(p: &str, c: &str, k: &str) -> bool {
    key(p) && ((c == "root" && p == k) || ident(c, "dc_"))
}
fn payload(o: &Obj) -> Result<(Vec<u8>, Value)> {
    let b = decode(text(o, "payload_base64")?, MAX_PAYLOAD)?;
    let v = parse(&b)?;
    Ok((b, v))
}

/// Check one object's signature with independently supplied expected keys.
/// No result from this function is a live authorization decision.
pub fn read(kind: &str, data: &[u8], signer: &str, device: &str) -> Result<SignedObject> {
    let v = parse(data)?;
    let o = object(&v)?;
    ensure!(key(signer), "invalid expected key");
    ensure!(
        kind == "packet" || device == "-",
        "unexpected device context"
    );
    match kind {
        "certificate" => certificate(o, signer),
        "person_record" => record(o, signer, false),
        "root_record" => record(o, signer, true),
        "device_revocation" => revocation(o, signer),
        "checkpoint" => checkpoint(o, signer),
        "packet" => packet(o, signer, device),
        "feature_proposal" => proposal(o, signer),
        "feature_ack" => ack(o, signer),
        "feature" => feature(o, signer),
        "admin_removal_v2" => admin_removal(o, signer),
        _ => bail!("unknown object kind"),
    }
}
fn certificate(o: &Obj, k: &str) -> Result<SignedObject> {
    fields(
        o,
        "format network_id person_public_key device_public_key host_public_key parent_id scopes issued_at not_after request_id signature",
        &[],
    )?;
    version(o, 1)?;
    let net = text(o, "network_id")?;
    let person = text(o, "person_public_key")?;
    let device = text(o, "device_public_key")?;
    let host = text(o, "host_public_key")?;
    let parent = text(o, "parent_id")?;
    let scopes = num(o, "scopes")?;
    let issued = text(o, "issued_at")?;
    let expiry = text(o, "not_after")?;
    let req = text(o, "request_id")?;
    ensure!(
        ident(net, "net_")
            && key(person)
            && key(device)
            && key(host)
            && person != device
            && device != host,
        "invalid certificate keys"
    );
    ensure!(
        (parent == "root" && k == person) || ident(parent, "dc_"),
        "invalid parent"
    );
    ensure!(
        (1..=15).contains(&scopes) && ident(req, "link_"),
        "invalid scope or request"
    );
    let start = stamp(issued)?;
    let end = stamp(expiry)?;
    let delta = end.signed_duration_since(start);
    ensure!(
        delta.num_seconds() > 0 && delta <= chrono::TimeDelta::days(90),
        "invalid interval"
    );
    let m = lines(&[
        "peerspan-device-certificate-v1",
        net,
        person,
        device,
        host,
        parent,
        &scopes.to_string(),
        issued,
        expiry,
        req,
    ]);
    ssh(k, &m, text(o, "signature")?)?;
    let id = format!("dc_{}", hash(&m));
    Ok(signed(m, id, None))
}
fn public_fields(p: &Obj) -> Result<()> {
    for name in p.keys() {
        match name.as_str() {
            "network_id" => ensure!(ident(text(p, name)?, "net_"), "invalid network ID"),
            "person_public_key"
            | "host_public_key"
            | "invite_public_key"
            | "device_public_key"
            | "genesis_root_public_key"
            | "coordinator_public_key" => {
                ensure!(key(text(p, name)?), "invalid key")
            }
            "epoch" | "invite_epoch" => {
                num(p, name)?;
            }
            "version" => ensure!(num(p, name)? > 0, "invalid version"),
            "bound_at" | "unbound_at" | "admitted_at" | "removed_at" | "revoked_at"
            | "invite_expires_at" | "defined_at" | "issued_at" | "valid_until" | "created_at"
            | "expires_at" | "not_after" => {
                stamp(text(p, name)?)?;
            }
            "member" => {
                crate::membership::label(text(p, name)?).map_err(|_| anyhow!("invalid label"))?;
            }
            _ => {}
        }
    }
    Ok(())
}
fn record_payload(kind: &str, p: &Obj) -> Result<()> {
    let shape = match kind {
        "peerspan-host-bind-v1" => "network_id person_public_key host_public_key bound_at",
        "peerspan-host-unbind-v1" => "network_id person_public_key host_public_key unbound_at",
        "peerspan-host-admit-v1" => "network_id epoch host_public_key member admitted_at",
        "peerspan-person-admit-v1" => "network_id epoch person_public_key member admitted_at",
        "peerspan-person-remove-v1" => "network_id person_public_key removed_at",
        "peerspan-revoke-host-v1" => "network_id host_public_key revoked_at",
        "peerspan-revoke-invite-v1" => "network_id invite_public_key revoked_at",
        "peerspan-invite-v1" => "network_id invite_public_key member invite_expires_at",
        "peerspan-person-invite-v1" => {
            "network_id invite_epoch invite_public_key member invite_expires_at"
        }
        "peerspan-group-v1" => "network_id name version defined_at members",
        "peerspan-policy-v1" => "network_id person_public_key version issued_at valid_until rules",
        "peerspan-policy-v2" => {
            "format network_id person_public_key version issued_at valid_until rules"
        }
        _ => bail!("unknown record kind"),
    };
    if kind == "peerspan-policy-v2" {
        fields(p, shape, &["capability_rules", "trusted_hosts", "edits"])?;
        version(p, 2)?;
    } else {
        fields(p, shape, &[])?;
    }
    if kind.starts_with("peerspan-policy-") {
        for name in ["rules", "capability_rules", "trusted_hosts", "edits"] {
            if let Some(v) = p.get(name) {
                ensure!(v.is_array(), "array required");
            }
        }
    }
    if kind == "peerspan-group-v1" {
        let name = text(p, "name")?;
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name.as_bytes()[0].is_ascii_alphanumeric()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c)),
            "invalid group name"
        );
        let members = string_list(p, "members")?;
        ensure!(
            sorted(&members) && members.iter().all(|s| ident(s, "person_")),
            "invalid group members"
        );
    }
    public_fields(p)?;
    if kind.starts_with("peerspan-policy-") {
        let mut checked = p.clone();
        checked.insert("signature".into(), Value::from("-"));
        if kind == "peerspan-policy-v2" {
            for k in ["capability_rules", "trusted_hosts", "edits"] {
                checked.entry(k.to_owned()).or_insert_with(|| json!([]));
            }
        }
        let policy: crate::policy::Policy = serde_json::from_value(Value::Object(checked))?;
        policy
            .check_shape()
            .map_err(|_| anyhow!("invalid policy shape"))?;
    }
    Ok(())
}
fn record(o: &Obj, k: &str, is_root: bool) -> Result<SignedObject> {
    let shape = if is_root {
        "format kind network_id epoch operation_id payload_base64 signature"
    } else {
        "format kind network_id epoch operation_id payload_base64 signature person_public_key certificate_id host_signature"
    };
    fields(o, shape, &[])?;
    version(o, 1)?;
    let kind = text(o, "kind")?;
    let net = text(o, "network_id")?;
    let epoch = num(o, "epoch")?;
    let op = text(o, "operation_id")?;
    let sig = text(o, "signature")?;
    ensure!(
        ident(net, "net_") && (op == "-" || ident(op, "link_")),
        "invalid record context"
    );
    let (b, v) = payload(o)?;
    let p = object(&v)?;
    record_payload(kind, p)?;
    ensure!(text(p, "network_id")? == net, "network mismatch");
    for name in ["epoch", "invite_epoch"] {
        if p.contains_key(name) {
            ensure!(num(p, name)? == epoch, "epoch mismatch");
        }
    }
    if is_root {
        ensure!(
            kind == "peerspan-host-admit-v1" && op != "-",
            "invalid root record"
        );
        let m = lines(&[
            "peerspan-root-authorization-v1",
            kind,
            net,
            &epoch.to_string(),
            op,
            &hash(&b),
        ]);
        root(k, &m, sig)?;
        let id = format!(
            "rr_{}",
            hash(&lines(&[
                "peerspan-root-authorized-record-v1",
                &hash(&m),
                sig
            ]))
        );
        return Ok(signed(m, id, Some(b)));
    }
    let person = text(o, "person_public_key")?;
    let cert = text(o, "certificate_id")?;
    let consent = text(o, "host_signature")?;
    ensure!(root_person(person, cert, k), "invalid person context");
    if kind.starts_with("peerspan-policy-")
        || ["peerspan-host-bind-v1", "peerspan-host-unbind-v1"].contains(&kind)
    {
        ensure!(text(p, "person_public_key")? == person, "owner mismatch");
    }
    let m = lines(&[
        "peerspan-person-authorization-v1",
        kind,
        net,
        &epoch.to_string(),
        op,
        person,
        cert,
        &hash(&b),
    ]);
    ssh(k, &m, sig)?;
    if kind == "peerspan-host-bind-v1" {
        raw(
            text(p, "host_public_key")?,
            &lines(&["peerspan-binding-consent-v1", &hash(&m)]),
            consent,
        )?;
    } else {
        ensure!(consent == "-", "unexpected host consent");
    }
    let id = format!(
        "ar_{}",
        hash(&lines(&[
            "peerspan-authorized-record-v1",
            &hash(&m),
            sig,
            consent
        ]))
    );
    Ok(signed(m, id, Some(b)))
}
fn revocation(o: &Obj, k: &str) -> Result<SignedObject> {
    fields(
        o,
        "format network_id person_public_key target_device_public_key target_certificate_id issuer_certificate_id revoked_at signature",
        &[],
    )?;
    version(o, 1)?;
    let net = text(o, "network_id")?;
    let person = text(o, "person_public_key")?;
    let device = text(o, "target_device_public_key")?;
    let target = text(o, "target_certificate_id")?;
    let issuer = text(o, "issuer_certificate_id")?;
    let at = text(o, "revoked_at")?;
    ensure!(
        ident(net, "net_") && key(device) && ident(target, "dc_") && root_person(person, issuer, k),
        "invalid revocation context"
    );
    stamp(at)?;
    let m = lines(&[
        "peerspan-device-revoke-v1",
        net,
        person,
        device,
        target,
        issuer,
        at,
    ]);
    ssh(k, &m, text(o, "signature")?)?;
    let id = format!("dr_{}", hash(&m));
    Ok(signed(m, id, None))
}
fn checkpoint(o: &Obj, k: &str) -> Result<SignedObject> {
    fields(
        o,
        "format network_id person_public_key issuer_certificate_id issued_at records signature",
        &[],
    )?;
    version(o, 1)?;
    let net = text(o, "network_id")?;
    let person = text(o, "person_public_key")?;
    let issuer = text(o, "issuer_certificate_id")?;
    let at = text(o, "issued_at")?;
    ensure!(
        ident(net, "net_") && root_person(person, issuer, k),
        "invalid checkpoint context"
    );
    stamp(at)?;
    let records = string_list(o, "records")?;
    ensure!(
        sorted(&records)
            && records
                .iter()
                .all(|s| ident(s, "ar_") || ident(s, "dr_") || ident(s, "pf_")),
        "invalid records"
    );
    let count = records.len().to_string();
    let mut parts = vec![
        "peerspan-person-checkpoint-v1",
        net,
        person,
        issuer,
        at,
        &count,
    ];
    parts.extend(records);
    let m = lines(&parts);
    ssh(k, &m, text(o, "signature")?)?;
    Ok(signed(m, "-".into(), None))
}
fn packet_payload(role: &str, p: &Obj) -> Result<()> {
    let shape = match role {
        "request" => {
            "mode host_public_key device_public_key request_nonce coordinator_address coordinator_public_key created_at expires_at expected_network_id expected_person_public_key renewed_certificate_id"
        }
        "owner" => {
            "request_packet_id network epoch feature_id person_public_key certificate binding_record membership_proof_id binding_proof_id"
        }
        "selection" => "owner_offer_id network_id epoch feature_id person_public_key",
        "administrator" => "owner_offer_id selection_id admission_record",
        "commit" => {
            "mode request_packet_id owner_offer_id selection_id administrator_offer_id network_id epoch feature_id person_public_key certificate_id binding_record admission_record_id expires_at"
        }
        "result" => "manifest_id activation catalog",
        _ => bail!("unknown role"),
    };
    fields(p, shape, &[])?;
    public_fields(p)?;
    packet_scalars(p)?;
    match role {
        "owner" => {
            let n = object(&p["network"])?;
            fields(
                n,
                "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
                &[],
            )?;
            public_fields(n)?;
            text(n, "name")?;
            text(n, "coordinator_address")?;
            let c = object(&p["certificate"])?;
            fields(
                c,
                "format network_id person_public_key device_public_key host_public_key parent_id scopes issued_at not_after request_id signature",
                &[],
            )?;
            version(c, 1)?;
            public_fields(c)?;
            ensure!((1..=15).contains(&num(c, "scopes")?), "invalid scopes");
            text(c, "parent_id")?;
            text(c, "request_id")?;
            text(c, "signature")?;
            if p["binding_record"] != "-" {
                nested_record(&p["binding_record"])?;
            }
        }
        "administrator" => nested_record(&p["admission_record"])?,
        "commit" if p["binding_record"] != "-" => {
            nested_record(&p["binding_record"])?;
        }
        "result" => result_payload(p)?,
        _ => {}
    }
    Ok(())
}
// Check packet scalars without resolving references or granting nested authority.
fn packet_scalars(p: &Obj) -> Result<()> {
    for name in p.keys() {
        if matches!(
            name.as_str(),
            "epoch"
                | "network"
                | "certificate"
                | "binding_record"
                | "admission_record"
                | "activation"
                | "catalog"
        ) {
            continue;
        }
        let s = text(p, name)?;
        let valid = match name.as_str() {
            "mode" => matches!(s, "new" | "renew"),
            "request_nonce" => decode(s, 32).is_ok_and(|b| b.len() == 32),
            "expected_network_id" => s == "-" || ident(s, "net_"),
            "expected_person_public_key" => s == "-" || key(s),
            "renewed_certificate_id" => s == "-" || ident(s, "dc_"),
            "certificate_id" => ident(s, "dc_"),
            "request_packet_id" | "owner_offer_id" | "selection_id" | "manifest_id" => {
                ident(s, "lp_")
            }
            "administrator_offer_id" => s == "-" || ident(s, "lp_"),
            "feature_id" => ident(s, "lf_"),
            "membership_proof_id" | "binding_proof_id" => s == "-" || ident(s, "pf_"),
            "admission_record_id" => s == "-" || ident(s, "ar_") || ident(s, "rr_"),
            _ => true,
        };
        ensure!(valid, "invalid packet scalar");
    }
    Ok(())
}
fn result_payload(p: &Obj) -> Result<()> {
    let activation = object(&p["activation"])?;
    fields(
        activation,
        "request owner selection administrator commit",
        &[],
    )?;
    for (name, value) in activation {
        if name == "administrator" && value == "-" {
            continue;
        }
        object(value)?;
    }
    let catalog = object(&p["catalog"])?;
    fields(catalog, "format network_id objects", &[])?;
    version(catalog, 1)?;
    public_fields(catalog)?;
    let entries = catalog["objects"]
        .as_array()
        .ok_or_else(|| anyhow!("array required"))?;
    ensure!(entries.len() <= 4096, "too many objects");
    for value in entries {
        let entry = object(value)?;
        fields(entry, "id kind body_base64", &[])?;
        ensure!(ident(text(entry, "id")?, "pf_"), "invalid proof ID");
        text(entry, "kind")?;
        parse(&decode(text(entry, "body_base64")?, MAX_OBJECT)?)?;
    }
    Ok(())
}
fn nested_record(v: &Value) -> Result<()> {
    let o = object(v)?;
    let shape = if o.contains_key("person_public_key") {
        "format kind network_id epoch operation_id payload_base64 signature person_public_key certificate_id host_signature"
    } else {
        "format kind network_id epoch operation_id payload_base64 signature"
    };
    fields(o, shape, &[])?;
    version(o, 1)?;
    public_fields(o)?;
    text(o, "operation_id")?;
    text(o, "signature")?;
    if o.contains_key("person_public_key") {
        text(o, "certificate_id")?;
        text(o, "host_signature")?;
    }
    let (_, v) = payload(o)?;
    record_payload(text(o, "kind")?, object(&v)?)
}
fn packet(o: &Obj, k: &str, device: &str) -> Result<SignedObject> {
    fields(
        o,
        "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
        &[],
    )?;
    version(o, 1)?;
    let req = text(o, "request_id")?;
    let role = text(o, "role")?;
    let writer = text(o, "writer_public_key")?;
    let person = text(o, "person_public_key")?;
    let cert = text(o, "certificate_id")?;
    let hs = text(o, "host_signature")?;
    let ds = text(o, "device_signature")?;
    let auth = text(o, "authority_signature")?;
    ensure!(ident(req, "link_") && writer == k, "invalid packet context");
    let (b, v) = payload(o)?;
    let p = object(&v)?;
    packet_payload(role, p)?;
    let m = lines(&[
        "peerspan-link-packet-v1",
        req,
        role,
        writer,
        person,
        cert,
        &hash(&b),
    ]);
    match role {
        "request" | "selection" | "commit" => {
            ensure!(
                key(device) && cert == "-" && auth == "-",
                "invalid possession context"
            );
            if role == "request" {
                ensure!(
                    person == "-"
                        && text(p, "host_public_key")? == k
                        && text(p, "device_public_key")? == device,
                    "request key mismatch"
                );
            } else {
                ensure!(key(person), "invalid selected person");
            }
            raw(k, &m, hs)?;
            ssh(device, &m, ds)?;
        }
        "owner" | "administrator" => {
            ensure!(
                device == "-" && hs == "-" && ds == "-",
                "unexpected signatures"
            );
            if role == "administrator" && cert == "network_root" && person == "-" {
                root(k, &m, auth)?;
            } else {
                ensure!(root_person(person, cert, k), "invalid person signer");
                ssh(k, &m, auth)?;
            }
        }
        "result" => {
            ensure!(
                device == "-" && person == "-" && cert == "coordinator" && hs == "-" && ds == "-",
                "invalid result context"
            );
            raw(k, &m, auth)?;
        }
        _ => bail!("unknown role"),
    }
    let id = format!(
        "lp_{}",
        hash(&lines(&[
            "peerspan-link-packet-id-v1",
            &hash(&m),
            hs,
            ds,
            auth
        ]))
    );
    Ok(signed(m, id, Some(b)))
}
fn proposal(o: &Obj, k: &str) -> Result<SignedObject> {
    fields(
        o,
        "format network_id epoch version issued_at host_public_keys signature",
        &[],
    )?;
    version(o, 1)?;
    let net = text(o, "network_id")?;
    let epoch = num(o, "epoch")?;
    let at = text(o, "issued_at")?;
    ensure!(
        ident(net, "net_") && num(o, "version")? == 1,
        "invalid feature"
    );
    stamp(at)?;
    let hosts = string_list(o, "host_public_keys")?;
    ensure!(
        !hosts.is_empty() && sorted(&hosts) && hosts.iter().all(|s| key(s)),
        "invalid roster"
    );
    let es = epoch.to_string();
    let count = hosts.len().to_string();
    let mut parts = vec!["peerspan-link-feature-v1", net, &es, "1", at, &count];
    parts.extend(hosts);
    let m = lines(&parts);
    root(k, &m, text(o, "signature")?)?;
    let id = format!("lf_{}", hash(&m));
    Ok(signed(m, id, None))
}
fn ack(o: &Obj, k: &str) -> Result<SignedObject> {
    fields(o, "format feature_id host_public_key signature", &[])?;
    version(o, 1)?;
    let feature = text(o, "feature_id")?;
    let host = text(o, "host_public_key")?;
    ensure!(ident(feature, "lf_") && host == k, "invalid acknowledgment");
    let m = lines(&["peerspan-link-feature-ack-v1", feature, host]);
    raw(k, &m, text(o, "signature")?)?;
    Ok(signed(m, "-".into(), None))
}
fn feature(o: &Obj, k: &str) -> Result<SignedObject> {
    fields(o, "proposal acknowledgments", &[])?;
    let p = object(&o["proposal"])?;
    let r = proposal(p, k)?;
    let hosts = string_list(p, "host_public_keys")?;
    let a = o["acknowledgments"]
        .as_array()
        .ok_or_else(|| anyhow!("array required"))?;
    ensure!(a.len() == hosts.len(), "incomplete acknowledgments");
    for (v, host) in a.iter().zip(hosts) {
        let a = object(v)?;
        ensure!(text(a, "feature_id")? == r.id, "feature mismatch");
        ack(a, host)?;
    }
    Ok(r)
}
fn admin_removal(o: &Obj, k: &str) -> Result<SignedObject> {
    fields(
        o,
        "format network_id person_public_key revoke_admitted removed_at kept signature",
        &[],
    )?;
    version(o, 2)?;
    let net = text(o, "network_id")?;
    let person = text(o, "person_public_key")?;
    let at = text(o, "removed_at")?;
    ensure!(ident(net, "net_") && key(person), "invalid removal context");
    stamp(at)?;
    let revoke = o["revoke_admitted"]
        .as_bool()
        .ok_or_else(|| anyhow!("boolean required"))?;
    let kept = string_list(o, "kept")?;
    ensure!(
        sorted(&kept) && (!revoke || kept.is_empty()),
        "invalid kept list"
    );
    for s in &kept {
        let valid = if let Some(id) = s.strip_prefix("legacy:") {
            ident(id, "")
        } else if let Some(id) = s.strip_prefix("record:") {
            ident(id, "ar_")
        } else if let Some(id) = s.strip_prefix("redemption:") {
            ident(id, "pf_")
        } else {
            false
        };
        ensure!(valid, "invalid kept ID");
    }
    let rs = revoke.to_string();
    let count = kept.len().to_string();
    let mut parts = vec!["peerspan-admin-remove-v2", net, person, &rs, at, &count];
    parts.extend(kept);
    let m = lines(&parts);
    root(k, &m, text(o, "signature")?)?;
    Ok(signed(m, "-".into(), None))
}

/// State-free adapter used only by the standalone conformance executable.
pub fn probe(data: &[u8]) -> Value {
    let run = || -> Result<Value> {
        let v = parse_limit(data, 2 << 20)?;
        let o = object(&v)?;
        if text(o, "kind")? == "path" {
            return Ok(path::probe_path(o));
        }
        fields(
            o,
            "kind object_base64 signer_public_key device_public_key",
            &[],
        )?;
        let b = decode(text(o, "object_base64")?, MAX_OBJECT)?;
        let r = read(
            text(o, "kind")?,
            &b,
            text(o, "signer_public_key")?,
            text(o, "device_public_key")?,
        )?;
        Ok(
            json!({"ok":true,"message_base64":STANDARD.encode(&r.message),"id":r.id,"payload_base64":r.payload.map(|b|STANDARD.encode(b)).unwrap_or_else(||"-".into())}),
        )
    };
    run().unwrap_or_else(|_| json!({"ok":false,"code":"invalid"}))
}
