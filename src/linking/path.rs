//! Exact certificate-path evaluation against independently verified state.
use super::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Current person admission and network-root-issued role, already verified.
#[derive(Clone, Debug, Default)]
pub struct PersonState {
    pub admitted: bool,
    pub administrator: bool,
}

/// A device revocation's person scope. PathState supplies its network scope.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceKey {
    pub person_public_key: String,
    pub device_public_key: String,
}

/// A coherent snapshot from a trusted verifier, never an unsigned network map.
/// Admission, bindings, activation IDs and revocations MUST already be verified.
/// Certificate bytes are candidates; evaluate_path verifies the requested path.
/// Missing entries mean unknown proof, false host entries mean removed, and a
/// binding of "-" means known unbound.
#[derive(Default)]
pub struct PathState {
    pub network_id: String,
    pub persons: BTreeMap<String, PersonState>,
    pub hosts: BTreeMap<String, bool>,
    pub bindings: BTreeMap<String, String>,
    pub certificates: BTreeMap<String, Vec<u8>>,
    pub activated_certificates: BTreeSet<String>,
    pub revoked_devices: BTreeSet<DeviceKey>,
}

/// A usable signing path under one snapshot, not authorization of a mutation.
#[derive(Debug, Serialize)]
pub struct SigningPath {
    pub certificate_id: String,
    pub person_public_key: String,
    pub signer_public_key: String,
    /// Certificate mask, not an unconditional role grant. Evaluate each
    /// operation's actual required bits, especially administration.
    pub scopes: u64,
    pub not_after: String,
    pub certificate_ids: Vec<String>,
    pub host_public_keys: Vec<String>,
}

/// Public failure/repair details without unsigned authority claims.
#[derive(Debug)]
pub struct PathError {
    pub code: &'static str,
    pub required_ids: Vec<String>,
}
impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "linking path: {}", self.code)
    }
}
impl std::error::Error for PathError {}
impl PathError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            required_ids: Vec::new(),
        }
    }
    fn missing(id: &str) -> Self {
        Self {
            code: "proof_required",
            required_ids: vec![id.to_owned()],
        }
    }
}

struct Certificate {
    id: String,
    body: Vec<u8>,
    network: String,
    person: String,
    device: String,
    host: String,
    parent: String,
    request: String,
    issued: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
    expiry: String,
    scopes: u64,
}
impl Certificate {
    fn candidate(id: &str, body: &[u8]) -> Result<Self> {
        let value = parse(body)?;
        let o = object(&value)?;
        let parent = text(o, "parent_id")?;
        ensure!(parent == "root" || ident(parent, "dc_"), "invalid parent");
        Ok(Self {
            id: id.to_owned(),
            body: body.to_vec(),
            network: text(o, "network_id")?.to_owned(),
            person: text(o, "person_public_key")?.to_owned(),
            device: text(o, "device_public_key")?.to_owned(),
            host: text(o, "host_public_key")?.to_owned(),
            parent: parent.to_owned(),
            request: text(o, "request_id")?.to_owned(),
            issued: stamp(text(o, "issued_at")?)?,
            until: stamp(text(o, "not_after")?)?,
            expiry: text(o, "not_after")?.to_owned(),
            scopes: num(o, "scopes")?,
        })
    }
}

/// Resolve exactly the named path and expected original person. Operation
/// semantics, freshness and transaction-time revalidation remain the caller's
/// responsibility, as does verification of the snapshot's source evidence.
pub fn evaluate_path(
    state: &PathState,
    person: &str,
    certificate_id: &str,
    required: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> std::result::Result<SigningPath, PathError> {
    let invalid = || PathError::new("invalid");
    if !ident(&state.network_id, "net_")
        || !key(person)
        || !(1..=15).contains(&required)
        || (certificate_id != "root" && !ident(certificate_id, "dc_"))
    {
        return Err(invalid());
    }
    let mut chain = Vec::with_capacity(8);
    let mut seen = BTreeSet::new();
    let mut id = certificate_id.to_owned();
    while id != "root" {
        if chain.len() == 8 || !seen.insert(id.clone()) {
            return Err(invalid());
        }
        let body = state
            .certificates
            .get(&id)
            .ok_or_else(|| PathError::missing(&id))?;
        let c = Certificate::candidate(&id, body).map_err(|_| invalid())?;
        id = c.parent.clone();
        chain.push(c);
    }
    chain.reverse();
    let mut devices = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut signer = person;
    for (i, c) in chain.iter().enumerate() {
        let verified = read("certificate", &c.body, signer, "-").map_err(|_| invalid())?;
        if verified.id != c.id
            || c.network != state.network_id
            || c.person != person
            || !devices.insert(c.device.as_str())
            || !hosts.insert(c.host.as_str())
            || c.device == person
        {
            return Err(invalid());
        }
        if let Some(parent) = i.checked_sub(1).map(|i| &chain[i]) {
            if c.scopes & parent.scopes != c.scopes
                || c.issued < parent.issued
                || c.until > parent.until
            {
                return Err(invalid());
            }
            if parent.scopes & 4 == 0 {
                return Err(PathError::new("forbidden"));
            }
        }
        signer = &c.device;
    }
    if !devices.is_disjoint(&hosts) {
        return Err(invalid());
    }
    let owner = state
        .persons
        .get(person)
        .ok_or_else(|| PathError::new("proof_required"))?;
    if !owner.admitted {
        return Err(PathError::new("forbidden"));
    }
    for c in &chain {
        if state.revoked_devices.contains(&DeviceKey {
            person_public_key: person.to_owned(),
            device_public_key: c.device.clone(),
        }) {
            return Err(PathError::new("device_revoked"));
        }
        if now < c.issued || now >= c.until {
            return Err(PathError::new("authority_expired"));
        }
        match state.hosts.get(&c.host) {
            None => return Err(PathError::new("proof_required")),
            Some(false) => return Err(PathError::new("forbidden")),
            Some(true) => {}
        }
        match state.bindings.get(&c.host) {
            None => return Err(PathError::new("proof_required")),
            Some(binding) if binding != person => return Err(PathError::new("forbidden")),
            Some(_) => {}
        }
        if !state.activated_certificates.contains(&c.id) {
            return Err(PathError::missing(&c.request));
        }
    }
    let (scopes, expiry) = chain
        .last()
        .map_or((15, "-"), |c| (c.scopes, c.expiry.as_str()));
    if scopes & required != required || (required & 8 != 0 && !owner.administrator) {
        return Err(PathError::new("forbidden"));
    }
    Ok(SigningPath {
        certificate_id: certificate_id.to_owned(),
        person_public_key: person.to_owned(),
        signer_public_key: signer.to_owned(),
        scopes,
        not_after: expiry.to_owned(),
        certificate_ids: chain.iter().map(|c| c.id.clone()).collect(),
        host_public_keys: chain.iter().map(|c| c.host.clone()).collect(),
    })
}

fn entries<'a>(o: &'a Obj, name: &str) -> Result<&'a [Value]> {
    let entries = o
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("array required"))?;
    ensure!(entries.len() <= 4096, "too many entries");
    Ok(entries)
}

// Conformance bridge only. This parser MUST NOT promote untrusted network
// responses into verified state in the daemon or coordinator.
fn injected_state(bytes: &[u8]) -> Result<PathState> {
    let value = parse(bytes)?;
    let o = object(&value)?;
    fields(
        o,
        "format network_id persons hosts bindings certificates activated_certificates revoked_devices",
        &[],
    )?;
    version(o, 1)?;
    let network = text(o, "network_id")?;
    ensure!(ident(network, "net_"), "invalid network");
    let mut state = PathState {
        network_id: network.to_owned(),
        ..PathState::default()
    };
    for v in entries(o, "persons")? {
        let p = object(v)?;
        fields(p, "public_key state administrator", &[])?;
        let key_text = text(p, "public_key")?;
        let status = text(p, "state")?;
        ensure!(
            key(key_text) && matches!(status, "admitted" | "removed"),
            "invalid person"
        );
        let administrator = p["administrator"]
            .as_bool()
            .ok_or_else(|| anyhow!("boolean required"))?;
        ensure!(
            state
                .persons
                .insert(
                    key_text.to_owned(),
                    PersonState {
                        admitted: status == "admitted",
                        administrator,
                    }
                )
                .is_none(),
            "duplicate person"
        );
    }
    for v in entries(o, "hosts")? {
        let p = object(v)?;
        fields(p, "public_key state", &[])?;
        let host = text(p, "public_key")?;
        let status = text(p, "state")?;
        ensure!(
            key(host) && matches!(status, "admitted" | "removed"),
            "invalid host"
        );
        ensure!(
            state
                .hosts
                .insert(host.to_owned(), status == "admitted")
                .is_none(),
            "duplicate host"
        );
    }
    for v in entries(o, "bindings")? {
        let p = object(v)?;
        fields(p, "host_public_key person_public_key", &[])?;
        let host = text(p, "host_public_key")?;
        let person = text(p, "person_public_key")?;
        ensure!(
            key(host) && (person == "-" || key(person)),
            "invalid binding"
        );
        ensure!(
            state
                .bindings
                .insert(host.to_owned(), person.to_owned())
                .is_none(),
            "duplicate binding"
        );
    }
    for v in entries(o, "certificates")? {
        let p = object(v)?;
        fields(p, "id body_base64", &[])?;
        let id = text(p, "id")?;
        ensure!(ident(id, "dc_"), "invalid certificate ID");
        let bytes = decode(text(p, "body_base64")?, MAX_OBJECT)?;
        ensure!(
            state.certificates.insert(id.to_owned(), bytes).is_none(),
            "duplicate certificate"
        );
    }
    for id in string_list(o, "activated_certificates")? {
        ensure!(
            ident(id, "dc_") && state.activated_certificates.insert(id.to_owned()),
            "invalid activation ID"
        );
    }
    for v in entries(o, "revoked_devices")? {
        let p = object(v)?;
        fields(p, "person_public_key device_public_key", &[])?;
        let person = text(p, "person_public_key")?;
        let device = text(p, "device_public_key")?;
        ensure!(key(person) && key(device), "invalid device reference");
        ensure!(
            state.revoked_devices.insert(DeviceKey {
                person_public_key: person.to_owned(),
                device_public_key: device.to_owned(),
            }),
            "duplicate revocation"
        );
    }
    Ok(state)
}

pub(super) fn probe_path(o: &Obj) -> Value {
    let run = || -> Result<std::result::Result<SigningPath, PathError>> {
        fields(
            o,
            "kind state_base64 person_public_key certificate_id required_scopes now",
            &[],
        )?;
        let state = injected_state(&decode(text(o, "state_base64")?, MAX_OBJECT)?)?;
        Ok(evaluate_path(
            &state,
            text(o, "person_public_key")?,
            text(o, "certificate_id")?,
            num(o, "required_scopes")?,
            stamp(text(o, "now")?)?,
        ))
    };
    match run() {
        Ok(Ok(path)) => {
            let mut result =
                serde_json::to_value(path).expect("path has only JSON-compatible fields");
            result
                .as_object_mut()
                .expect("path is an object")
                .insert("ok".into(), Value::Bool(true));
            result
        }
        other => {
            let e = match other {
                Ok(Err(e)) => e,
                _ => PathError::new("invalid"),
            };
            if e.code == "proof_required" {
                json!({"ok":false,"code":e.code,"required_ids":e.required_ids})
            } else {
                json!({"ok":false,"code":e.code})
            }
        }
    }
}
