//! Derive path facts from signed genesis catalogs and complete activations.
//! This module has no storage/transport integration and cannot commit a link.
use super::*;
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ACTIVATION: usize = 512 << 10;

/// Independently pinned caller context. Only genesis epoch zero is supported.
pub struct ActivationContext<'a> {
    pub network: &'a [u8],
    pub epoch: u64,
    pub known_feature_id: &'a str,
    pub caller_host_public_key: &'a str,
    pub expected_person_public_key: &'a str,
    pub now: chrono::DateTime<chrono::Utc>,
    pub verification: &'a str,
}

/// Checked public evidence, not freshness, a committed operation or readiness.
#[derive(Serialize)]
pub struct ActivationEvidence {
    pub request_id: String,
    pub manifest_id: String,
    pub certificate_id: String,
    pub network_id: String,
    pub feature_id: String,
    pub person_public_key: String,
    pub host_public_key: String,
    pub device_public_key: String,
    pub mode: String,
    #[serde(skip)]
    pub state: PathState,
}

#[derive(Clone, Serialize)]
struct Identity {
    request_id: String,
    manifest_id: String,
    certificate_id: String,
    network_id: String,
    feature_id: String,
    person_public_key: String,
    host_public_key: String,
    device_public_key: String,
    mode: String,
}

#[derive(Clone)]
struct Proof {
    kind: String,
    body: Vec<u8>,
    object: Obj,
}
struct Verifier<'a> {
    ctx: ActivationContext<'a>,
    network: Obj,
    net: String,
    root: String,
    feature: String,
    state: PathState,
    proofs: BTreeMap<String, Proof>,
    semantics: BTreeMap<String, Obj>,
    activations: BTreeMap<String, Vec<u8>>,
    busy: BTreeSet<String>,
    done: BTreeMap<String, Identity>,
    admins: BTreeSet<String>,
    persons: BTreeMap<String, String>,
    hosts: BTreeMap<String, String>,
    active_records: BTreeSet<String>,
}

fn problem(code: &'static str) -> anyhow::Error {
    PathError {
        code,
        required_ids: Vec::new(),
    }
    .into()
}
fn missing(id: &str) -> anyhow::Error {
    PathError {
        code: "proof_required",
        required_ids: vec![id.to_owned()],
    }
    .into()
}
fn check(ok: bool, code: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(problem(code)) }
}
fn obj(b: &[u8]) -> Result<Obj> {
    Ok(object(&parse(b)?)?.clone())
}
fn s<'a>(o: &'a Obj, k: &str) -> &'a str {
    text(o, k).unwrap_or("")
}
fn epoch_zero(o: &Obj) -> bool {
    num(o, "epoch").is_ok_and(|n| n == 0)
}
fn absent_value(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str) == Some("-")
}
fn proof_id(kind: &str, body: &[u8]) -> String {
    format!(
        "pf_{}",
        hash(&lines(&["peerspan-link-proof-v1", kind, &hash(body)]))
    )
}
fn p_obj(o: &Obj) -> Result<(Vec<u8>, Obj)> {
    let (b, v) = payload(o)?;
    Ok((b, object(&v)?.clone()))
}
// Never serialize Value to recover a nested public object's content address.
// Strict parsing precedes this extraction; RawValue preserves original bytes.
fn raw_field(body: &[u8], name: &str) -> Result<Vec<u8>> {
    let o: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(body)?;
    Ok(o.get(name)
        .ok_or_else(|| problem("invalid"))?
        .get()
        .as_bytes()
        .to_vec())
}
fn certificate_id(o: &Obj) -> Result<String> {
    fields(
        o,
        "format network_id person_public_key device_public_key host_public_key parent_id scopes issued_at not_after request_id signature",
        &[],
    )?;
    version(o, 1)?;
    let scopes = num(o, "scopes")?;
    check((1..=15).contains(&scopes), "invalid")?;
    text(o, "signature")?;
    Ok(format!(
        "dc_{}",
        hash(&lines(&[
            "peerspan-device-certificate-v1",
            text(o, "network_id")?,
            text(o, "person_public_key")?,
            text(o, "device_public_key")?,
            text(o, "host_public_key")?,
            text(o, "parent_id")?,
            &scopes.to_string(),
            text(o, "issued_at")?,
            text(o, "not_after")?,
            text(o, "request_id")?
        ]))
    ))
}

struct Cert {
    id: String,
    body: Vec<u8>,
    net: String,
    person: String,
    device: String,
    host: String,
    parent: String,
    request: String,
    scopes: u64,
    issued: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
}
impl Cert {
    fn candidate(id: &str, body: &[u8]) -> Result<Self> {
        let o = obj(body)?;
        let parent = text(&o, "parent_id")?;
        check(parent == "root" || ident(parent, "dc_"), "invalid")?;
        Ok(Self {
            id: id.into(),
            body: body.to_vec(),
            net: text(&o, "network_id")?.into(),
            person: text(&o, "person_public_key")?.into(),
            device: text(&o, "device_public_key")?.into(),
            host: text(&o, "host_public_key")?.into(),
            parent: parent.into(),
            request: text(&o, "request_id")?.into(),
            scopes: num(&o, "scopes")?,
            issued: stamp(text(&o, "issued_at")?)?,
            until: stamp(text(&o, "not_after")?)?,
        })
    }
}

/// Verify eligibility using a scratch snapshot. Future callers must still
/// transactionally enforce freshness, epoch, feature high-water and persistence.
pub fn verify_activation(
    ctx: ActivationContext<'_>,
    catalog: &[u8],
    activation: &[u8],
) -> Result<ActivationEvidence> {
    let run = || -> Result<ActivationEvidence> {
        check(
            ctx.network.len() + catalog.len() + activation.len() <= MAX_ACTIVATION
                && key(ctx.caller_host_public_key)
                && (ctx.expected_person_public_key == "-" || key(ctx.expected_person_public_key))
                && (ctx.known_feature_id == "-" || ident(ctx.known_feature_id, "lf_"))
                && matches!(ctx.verification, "first" | "historical"),
            "invalid",
        )?;
        check(ctx.epoch == 0, "upgrade_required")?;
        let network = obj(ctx.network)?;
        fields(
            &network,
            "network_id name genesis_root_public_key coordinator_address coordinator_public_key",
            &[],
        )?;
        let root_key = text(&network, "genesis_root_public_key")?.to_owned();
        let net = text(&network, "network_id")?.to_owned();
        check(
            key(&root_key) && key(text(&network, "coordinator_public_key")?),
            "invalid",
        )?;
        check(
            crate::membership::network_id(crate::membership::public_key(&root_key)?.as_bytes())
                == net,
            "invalid",
        )?;
        crate::membership::label(text(&network, "name")?)?;
        crate::membership::split_host_port(text(&network, "coordinator_address")?)?;
        let state = PathState {
            network_id: net.clone(),
            ..PathState::default()
        };
        let historical = ctx.verification == "historical";
        let mut v = Verifier {
            ctx,
            network,
            net,
            root: root_key,
            feature: String::new(),
            state,
            proofs: BTreeMap::new(),
            semantics: BTreeMap::new(),
            activations: BTreeMap::new(),
            busy: BTreeSet::new(),
            done: BTreeMap::new(),
            admins: BTreeSet::new(),
            persons: BTreeMap::new(),
            hosts: BTreeMap::new(),
            active_records: BTreeSet::new(),
        };
        v.catalog(catalog)?;
        let request = v.index_activation(activation)?;
        v.bootstrap()?;
        v.revocations()?;
        let r = v.activate(&request, historical, 0)?;
        check(
            r.host_public_key == v.ctx.caller_host_public_key
                && (v.ctx.expected_person_public_key == "-"
                    || r.person_public_key == v.ctx.expected_person_public_key),
            "invalid",
        )?;
        Ok(ActivationEvidence {
            request_id: r.request_id,
            manifest_id: r.manifest_id,
            certificate_id: r.certificate_id,
            network_id: r.network_id,
            feature_id: r.feature_id,
            person_public_key: r.person_public_key,
            host_public_key: r.host_public_key,
            device_public_key: r.device_public_key,
            mode: r.mode,
            state: v.state,
        })
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

impl Verifier<'_> {
    fn semantic(&mut self, id: &str, o: &Obj) -> Result<()> {
        check(
            self.semantics.get(id).is_none_or(|old| old == o),
            "state_conflict",
        )?;
        self.semantics.insert(id.into(), o.clone());
        Ok(())
    }
    fn index(&mut self, kind: &str, body: &[u8]) -> Result<String> {
        let o = obj(body)?;
        let id = proof_id(kind, body);
        if self.proofs.contains_key(&id) {
            return Ok(id);
        }
        check(self.proofs.len() < 16384, "invalid")?;
        self.proofs.insert(
            id.clone(),
            Proof {
                kind: kind.into(),
                body: body.to_vec(),
                object: o.clone(),
            },
        );
        match kind {
            "certificate" => {
                let cid = certificate_id(&o)?;
                self.semantic(&cid, &o)?;
                if self
                    .state
                    .certificates
                    .get(&cid)
                    .is_none_or(|old| proof_id(kind, old) > id)
                {
                    self.state.certificates.insert(cid, body.to_vec());
                }
            }
            "person_record" | "root_record" => {
                nested_record(&Value::Object(o.clone()))?;
                check(s(&o, "operation_id") != "-", "upgrade_required")?;
                let (b, _) = p_obj(&o)?;
                let epoch = num(&o, "epoch")?.to_string();
                let rid = if kind == "root_record" {
                    let m = lines(&[
                        "peerspan-root-authorization-v1",
                        s(&o, "kind"),
                        s(&o, "network_id"),
                        &epoch,
                        s(&o, "operation_id"),
                        &hash(&b),
                    ]);
                    format!(
                        "rr_{}",
                        hash(&lines(&[
                            "peerspan-root-authorized-record-v1",
                            &hash(&m),
                            s(&o, "signature")
                        ]))
                    )
                } else {
                    let m = lines(&[
                        "peerspan-person-authorization-v1",
                        s(&o, "kind"),
                        s(&o, "network_id"),
                        &epoch,
                        s(&o, "operation_id"),
                        s(&o, "person_public_key"),
                        s(&o, "certificate_id"),
                        &hash(&b),
                    ]);
                    format!(
                        "ar_{}",
                        hash(&lines(&[
                            "peerspan-authorized-record-v1",
                            &hash(&m),
                            s(&o, "signature"),
                            s(&o, "host_signature")
                        ]))
                    )
                };
                self.semantic(&rid, &o)?;
            }
            "activation" => {
                self.index_activation(body)?;
            }
            _ => {}
        }
        Ok(id)
    }
    fn index_activation(&mut self, body: &[u8]) -> Result<String> {
        let a = obj(body)?;
        fields(&a, "request owner selection administrator commit", &[])?;
        let request = object(a.get("request").ok_or_else(|| problem("invalid"))?)?;
        let id = text(request, "request_id")?.to_owned();
        check(ident(&id, "link_"), "invalid")?;
        if let Some(old) = self.activations.get(&id) {
            let o = obj(old)?;
            check(o.get("commit") == a.get("commit"), "operation_conflict")?;
            check(o == a, "state_conflict")?;
            return Ok(id);
        }
        self.activations.insert(id.clone(), body.to_vec());
        let owner = object(a.get("owner").ok_or_else(|| problem("invalid"))?)?;
        let (p, _) = p_obj(owner)?;
        self.index("certificate", &raw_field(&p, "certificate")?)?;
        let commit = object(a.get("commit").ok_or_else(|| problem("invalid"))?)?;
        let (raw, c) = p_obj(commit)?;
        if !absent_value(c.get("binding_record")) {
            self.index("person_record", &raw_field(&raw, "binding_record")?)?;
        }
        if !absent_value(a.get("administrator")) {
            let admin = object(a.get("administrator").ok_or_else(|| problem("invalid"))?)?;
            let (raw, p) = p_obj(admin)?;
            let record = object(
                p.get("admission_record")
                    .ok_or_else(|| problem("invalid"))?,
            )?;
            let kind = if record.contains_key("person_public_key") {
                "person_record"
            } else {
                "root_record"
            };
            self.index(kind, &raw_field(&raw, "admission_record")?)?;
        }
        Ok(id)
    }
    fn catalog(&mut self, body: &[u8]) -> Result<()> {
        let c = obj(body)?;
        fields(&c, "format network_id objects", &[])?;
        version(&c, 1)?;
        check(text(&c, "network_id")? == self.net, "invalid")?;
        let entries = c
            .get("objects")
            .and_then(Value::as_array)
            .ok_or_else(|| problem("invalid"))?;
        check(entries.len() <= 4096, "invalid")?;
        let mut last = "";
        for entry in entries {
            let o = object(entry)?;
            fields(o, "id kind body_base64", &[])?;
            let id = text(o, "id")?;
            let kind = text(o, "kind")?;
            let b = decode(text(o, "body_base64")?, MAX_OBJECT)?;
            check(
                ident(id, "pf_") && id > last && id == proof_id(kind, &b),
                "invalid",
            )?;
            last = id;
            match kind {
                "admin_delegation" | "person_admission" | "host_admission" | "host_binding"
                | "feature" | "certificate" | "activation" | "person_record" | "root_record"
                | "device_revocation" => {}
                "rotation" | "admin_removal" | "person_membership" | "host_membership"
                | "host_unbinding" | "host_leave" | "host_revocation" | "invite_revocation"
                | "person_removal" | "group" | "policy" | "join_ack" | "checkpoint"
                | "invite_redemption" => return Err(problem("upgrade_required")),
                _ => return Err(problem("invalid")),
            }
            self.index(kind, &b)?;
        }
        Ok(())
    }
    fn admin_signature(&self, m: &[u8], sig: &str) -> Result<()> {
        if root(&self.root, m, sig).is_ok() {
            return Ok(());
        }
        // Embedded SSHSIG key is a hint into a root-verified set, never authority.
        let hint = crate::persons::sshsig_signer(sig).ok_or_else(|| problem("invalid"))?;
        check(hint != self.root, "invalid")?;
        check(self.admins.contains(&hint), "forbidden")?;
        ssh(&hint, m, sig)
    }
    fn bootstrap(&mut self) -> Result<()> {
        let proofs: Vec<_> = self.proofs.values().cloned().collect();
        for p in &proofs {
            if p.kind != "admin_delegation" {
                continue;
            }
            let o = &p.object;
            fields(
                o,
                "network_id epoch person_public_key delegated_at signature",
                &[],
            )?;
            check(
                s(o, "network_id") == self.net && key(s(o, "person_public_key")),
                "invalid",
            )?;
            check(num(o, "epoch")? == 0, "upgrade_required")?;
            stamp(text(o, "delegated_at")?)?;
            root(
                &self.root,
                &lines(&[
                    "peerspan-admin-delegate-v1",
                    &self.net,
                    "0",
                    text(o, "person_public_key")?,
                    text(o, "delegated_at")?,
                ]),
                text(o, "signature")?,
            )?;
            self.admins.insert(s(o, "person_public_key").into());
        }
        for p in &proofs {
            let o = &p.object;
            match p.kind.as_str() {
                "person_admission" | "host_admission" => {
                    let (field, domain) = if p.kind == "person_admission" {
                        ("person_public_key", "peerspan-person-admit-v1")
                    } else {
                        ("host_public_key", "peerspan-host-admit-v1")
                    };
                    fields(
                        o,
                        &format!("network_id epoch {field} member admitted_at signature"),
                        &[],
                    )?;
                    check(
                        s(o, "network_id") == self.net && key(s(o, field)),
                        "invalid",
                    )?;
                    crate::membership::label(text(o, "member")?)?;
                    check(num(o, "epoch")? == 0, "upgrade_required")?;
                    stamp(text(o, "admitted_at")?)?;
                    self.admin_signature(
                        &lines(&[
                            domain,
                            &self.net,
                            "0",
                            text(o, field)?,
                            text(o, "member")?,
                            text(o, "admitted_at")?,
                        ]),
                        text(o, "signature")?,
                    )?;
                    let (k, label) = (s(o, field).to_owned(), s(o, "member").to_owned());
                    if p.kind == "person_admission" {
                        check(
                            self.persons.get(&k).is_none_or(|old| old == &label),
                            "state_conflict",
                        )?;
                        self.persons.insert(k.clone(), label);
                        self.state.persons.insert(
                            k.clone(),
                            PersonState {
                                admitted: true,
                                administrator: self.admins.contains(&k),
                            },
                        );
                    } else {
                        check(
                            self.hosts.get(&k).is_none_or(|old| old == &label),
                            "state_conflict",
                        )?;
                        self.hosts.insert(k.clone(), label);
                        self.state.hosts.insert(k, true);
                    }
                }
                "feature" => {
                    let r = read("feature", &p.body, &self.root, "-")?;
                    let proposal = object(o.get("proposal").ok_or_else(|| problem("invalid"))?)?;
                    check(s(proposal, "network_id") == self.net, "invalid")?;
                    check(num(proposal, "epoch")? == 0, "upgrade_required")?;
                    check(
                        self.feature.is_empty() || self.feature == r.id,
                        "state_conflict",
                    )?;
                    self.semantic(&r.id, o)?;
                    self.feature = r.id;
                }
                _ => {}
            }
        }
        for p in &proofs {
            if p.kind != "host_binding" {
                continue;
            }
            let o = &p.object;
            fields(
                o,
                "network_id person_public_key host_public_key bound_at signature host_signature",
                &[],
            )?;
            let (person, host, at) = (
                text(o, "person_public_key")?,
                text(o, "host_public_key")?,
                text(o, "bound_at")?,
            );
            check(
                s(o, "network_id") == self.net && key(person) && key(host),
                "invalid",
            )?;
            stamp(at)?;
            let m = lines(&["peerspan-host-bind-v1", &self.net, person, host, at]);
            ssh(person, &m, text(o, "signature")?)?;
            raw(host, &m, text(o, "host_signature")?)?;
            check(
                self.state
                    .bindings
                    .get(host)
                    .is_none_or(|old| old == person),
                "state_conflict",
            )?;
            self.state.bindings.insert(host.into(), person.into());
        }
        check(!self.feature.is_empty(), "proof_required")?;
        check(
            self.ctx.known_feature_id == "-" || self.ctx.known_feature_id == self.feature,
            "state_conflict",
        )?;
        for p in &proofs {
            if p.kind != "feature" {
                continue;
            }
            let proposal = object(p.object.get("proposal").ok_or_else(|| problem("invalid"))?)?;
            let roster: BTreeSet<_> = string_list(proposal, "host_public_keys")?
                .into_iter()
                .collect();
            check(
                self.hosts.keys().all(|h| roster.contains(h.as_str())),
                "proof_required",
            )?;
        }
        Ok(())
    }
    fn structural(&self, id: &str, person: &str) -> Result<Cert> {
        check(ident(id, "dc_") && key(person), "invalid")?;
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut next = id.to_owned();
        while next != "root" {
            check(chain.len() < 8 && seen.insert(next.clone()), "invalid")?;
            let body = self
                .state
                .certificates
                .get(&next)
                .ok_or_else(|| missing(&next))?;
            let c = Cert::candidate(&next, body)?;
            next = c.parent.clone();
            chain.push(c);
        }
        check(!chain.is_empty(), "invalid")?;
        chain.reverse();
        let (mut devices, mut hosts) = (BTreeSet::new(), BTreeSet::new());
        let mut signer = person;
        for (i, c) in chain.iter().enumerate() {
            let r = read("certificate", &c.body, signer, "-")?;
            check(
                r.id == c.id
                    && c.net == self.net
                    && c.person == person
                    && c.device != person
                    && devices.insert(c.device.as_str())
                    && hosts.insert(c.host.as_str()),
                "invalid",
            )?;
            if let Some(p) = i.checked_sub(1).map(|i| &chain[i]) {
                check(
                    p.scopes & 4 != 0
                        && c.scopes & p.scopes == c.scopes
                        && c.issued >= p.issued
                        && c.until <= p.until,
                    "forbidden",
                )?;
            }
            signer = &c.device;
        }
        check(devices.is_disjoint(&hosts), "invalid")?;
        Ok(chain.pop().expect("nonempty chain"))
    }
    fn revocations(&mut self) -> Result<()> {
        let proofs: Vec<_> = self
            .proofs
            .values()
            .filter(|p| p.kind == "device_revocation")
            .cloned()
            .collect();
        for p in proofs {
            let o = &p.object;
            check(
                s(o, "issuer_certificate_id") == "root"
                    || ident(s(o, "issuer_certificate_id"), "dc_"),
                "invalid",
            )?;
            check(s(o, "issuer_certificate_id") == "root", "upgrade_required")?;
            let person = text(o, "person_public_key")?;
            read("device_revocation", &p.body, person, "-")?;
            check(s(o, "network_id") == self.net, "invalid")?;
            let c = self.structural(text(o, "target_certificate_id")?, person)?;
            check(c.device == s(o, "target_device_public_key"), "invalid")?;
            self.state.revoked_devices.insert(DeviceKey {
                person_public_key: person.into(),
                device_public_key: c.device,
            });
        }
        Ok(())
    }
    fn authority(
        &mut self,
        person: &str,
        cert: &str,
        scopes: u64,
        depth: usize,
    ) -> Result<SigningPath> {
        check(
            key(person) && (cert == "root" || ident(cert, "dc_")),
            "invalid",
        )?;
        if cert != "root" {
            let c = self.structural(cert, person)?;
            if !self.state.activated_certificates.contains(cert) {
                self.activate(&c.request, true, depth + 1)?;
            }
        }
        Ok(evaluate_path(
            &self.state,
            person,
            cert,
            scopes,
            self.ctx.now,
        )?)
    }
    fn packet(
        &self,
        body: &[u8],
        role: &str,
        request: &str,
        signer: &str,
        device: &str,
    ) -> Result<(Obj, Obj, String, Vec<u8>)> {
        let o = obj(body)?;
        check(
            s(&o, "role") == role && s(&o, "request_id") == request,
            "invalid",
        )?;
        let r = read("packet", body, signer, device)?;
        let b = r.payload.ok_or_else(|| problem("invalid"))?;
        let p = obj(&b)?;
        Ok((o, p, r.id, b))
    }
    fn record(
        &self,
        body: &[u8],
        kind: &str,
        operation: &str,
        person: &str,
        cert: &str,
        signer: &str,
    ) -> Result<(SignedObject, Obj)> {
        let o = obj(body)?;
        check(
            s(&o, "network_id") == self.net
                && s(&o, "kind") == kind
                && s(&o, "operation_id") == operation,
            "invalid",
        )?;
        check(epoch_zero(&o), "invalid")?;
        let typ = if person == "-" {
            "root_record"
        } else {
            check(
                s(&o, "person_public_key") == person && s(&o, "certificate_id") == cert,
                "invalid",
            )?;
            "person_record"
        };
        let r = read(typ, body, signer, "-")?;
        let p = obj(r.payload.as_ref().ok_or_else(|| problem("invalid"))?)?;
        Ok((r, p))
    }
    fn renewal_proof(
        &mut self,
        id: &str,
        kind: &str,
        person: &str,
        host: &str,
        depth: usize,
    ) -> Result<()> {
        let p = self.proofs.get(id).ok_or_else(|| missing(id))?.clone();
        if matches!(p.kind.as_str(), "person_record" | "root_record") {
            self.activate(text(&p.object, "operation_id")?, true, depth + 1)?;
            check(
                self.active_records.contains(id) && s(&p.object, "kind") == kind,
                "invalid",
            )?;
            let (_, o) = p_obj(&p.object)?;
            check(s(&o, "host_public_key") == host, "invalid")?;
            if kind == "peerspan-host-bind-v1" {
                check(s(&o, "person_public_key") == person, "invalid")?;
            }
            if kind == "peerspan-host-admit-v1" {
                check(
                    self.persons
                        .get(person)
                        .is_some_and(|label| label == s(&o, "member")),
                    "invalid",
                )?;
            }
            return Ok(());
        }
        check(
            (kind == "peerspan-host-bind-v1"
                && p.kind == "host_binding"
                && s(&p.object, "host_public_key") == host
                && s(&p.object, "person_public_key") == person)
                || (kind == "peerspan-host-admit-v1"
                    && p.kind == "host_admission"
                    && s(&p.object, "host_public_key") == host
                    && self
                        .persons
                        .get(person)
                        .is_some_and(|label| label == s(&p.object, "member"))),
            "invalid",
        )
    }

    // A separate complete activation can already admit the target host. Resolve
    // its signed facts even when it is absent from the requested issuer path.
    fn host_activations(&mut self, host: &str, depth: usize) -> Result<()> {
        let ids: Vec<_> = self.activations.keys().cloned().collect();
        for id in ids {
            if self.busy.contains(&id) {
                continue;
            }
            let a = obj(self.activations.get(&id).expect("indexed activation"))?;
            let request = object(a.get("request").ok_or_else(|| problem("invalid"))?)?;
            let (_, p) = p_obj(request)?;
            if s(&p, "host_public_key") == host && s(&p, "mode") == "new" {
                self.activate(&id, true, depth + 1)?;
            }
        }
        Ok(())
    }

    fn activate(&mut self, id: &str, historical: bool, depth: usize) -> Result<Identity> {
        if let Some(r) = self.done.get(id) {
            return Ok(r.clone());
        }
        check(depth < 8 && !self.busy.contains(id), "invalid")?;
        let body = self.activations.get(id).ok_or_else(|| missing(id))?.clone();
        self.busy.insert(id.into());
        let result = self.transcript(id, &body, historical, depth);
        self.busy.remove(id);
        if let Ok(r) = &result {
            self.done.insert(id.into(), r.clone());
        }
        result
    }

    fn transcript(
        &mut self,
        id: &str,
        body: &[u8],
        historical: bool,
        depth: usize,
    ) -> Result<Identity> {
        let a = obj(body)?;
        let request = object(a.get("request").ok_or_else(|| problem("invalid"))?)?;
        let (_, req) = p_obj(request)?;
        let host = text(&req, "host_public_key")?.to_owned();
        let device = text(&req, "device_public_key")?.to_owned();
        let (_, req, rid, _) =
            self.packet(&raw_field(body, "request")?, "request", id, &host, &device)?;
        check(
            host != device
                && s(&req, "coordinator_address") == s(&self.network, "coordinator_address")
                && s(&req, "coordinator_public_key") == s(&self.network, "coordinator_public_key"),
            "invalid",
        )?;
        let expected_id = format!(
            "link_{}",
            hash(&lines(&[
                "peerspan-link-request-id-v1",
                text(&req, "coordinator_public_key")?,
                &host,
                &device,
                text(&req, "request_nonce")?
            ]))
        );
        check(id == expected_id, "invalid")?;
        let created = stamp(text(&req, "created_at")?)?;
        let expires = stamp(text(&req, "expires_at")?)?;
        check(
            expires.signed_duration_since(created).num_seconds() == 300,
            "invalid",
        )?;
        if !historical {
            check(self.ctx.now >= created && self.ctx.now < expires, "expired")?;
        }
        let mode = text(&req, "mode")?.to_owned();
        let owner = object(a.get("owner").ok_or_else(|| problem("invalid"))?)?;
        let (_, offer) = p_obj(owner)?;
        let person = text(&offer, "person_public_key")?.to_owned();
        let issuer = text(owner, "certificate_id")?.to_owned();
        check(
            s(owner, "person_public_key") == person
                && (s(&req, "expected_network_id") == "-"
                    || s(&req, "expected_network_id") == self.net)
                && (s(&req, "expected_person_public_key") == "-"
                    || s(&req, "expected_person_public_key") == person),
            "invalid",
        )?;
        check(
            object(offer.get("network").ok_or_else(|| problem("invalid"))?)? == &self.network,
            "invalid",
        )?;
        check(epoch_zero(&offer), "invalid")?;
        check(
            s(&offer, "feature_id") == self.feature && s(&offer, "request_packet_id") == rid,
            "invalid",
        )?;
        let required = if mode == "renew" { 4 } else { 6 };
        let path = self.authority(&person, &issuer, required, depth)?;
        let (_, offer, oid, offer_raw) = self.packet(
            &raw_field(body, "owner")?,
            "owner",
            id,
            &path.signer_public_key,
            "-",
        )?;
        let cert_raw = raw_field(&offer_raw, "certificate")?;
        let cid = certificate_id(&obj(&cert_raw)?)?;
        let c = Cert::candidate(&cid, &cert_raw)?;
        check(
            c.person == person
                && c.host == host
                && c.device == device
                && c.parent == issuer
                && c.request == id
                && c.net == self.net,
            "invalid",
        )?;
        if issuer != "root" {
            let parent = Cert::candidate(
                &issuer,
                self.state
                    .certificates
                    .get(&issuer)
                    .ok_or_else(|| missing(&issuer))?,
            )?;
            check(
                c.scopes & parent.scopes == c.scopes
                    && c.issued >= parent.issued
                    && c.until <= parent.until,
                "forbidden",
            )?;
        }
        self.structural(&cid, &person)?;
        if !historical {
            check(
                !self.state.revoked_devices.contains(&DeviceKey {
                    person_public_key: person.clone(),
                    device_public_key: device.clone(),
                }),
                "device_revoked",
            )?;
            check(
                self.ctx.now >= c.issued && self.ctx.now < c.until,
                "authority_expired",
            )?;
        }
        let (selection, sel, sid, _) = self.packet(
            &raw_field(body, "selection")?,
            "selection",
            id,
            &host,
            &device,
        )?;
        check(
            s(&selection, "person_public_key") == person
                && s(&sel, "owner_offer_id") == oid
                && s(&sel, "network_id") == self.net
                && epoch_zero(&sel)
                && s(&sel, "feature_id") == self.feature
                && s(&sel, "person_public_key") == person,
            "invalid",
        )?;
        let (commit, com, mid, commit_raw) =
            self.packet(&raw_field(body, "commit")?, "commit", id, &host, &device)?;
        check(
            s(&commit, "person_public_key") == person
                && s(&com, "mode") == mode
                && s(&com, "request_packet_id") == rid
                && s(&com, "owner_offer_id") == oid
                && s(&com, "selection_id") == sid
                && s(&com, "network_id") == self.net
                && epoch_zero(&com)
                && s(&com, "feature_id") == self.feature
                && s(&com, "person_public_key") == person
                && s(&com, "certificate_id") == cid
                && s(&com, "expires_at") == s(&req, "expires_at"),
            "invalid",
        )?;
        let mut completed_records = Vec::new();
        if mode == "new" {
            check(
                s(&req, "renewed_certificate_id") == "-"
                    && s(&offer, "membership_proof_id") == "-"
                    && s(&offer, "binding_proof_id") == "-"
                    && !absent_value(a.get("administrator"))
                    && !absent_value(offer.get("binding_record"))
                    && !absent_value(com.get("binding_record")),
                "invalid",
            )?;
            let admin = object(a.get("administrator").ok_or_else(|| problem("invalid"))?)?;
            let ap = text(admin, "person_public_key")?.to_owned();
            let ac = text(admin, "certificate_id")?.to_owned();
            let signer = if ac == "network_root" {
                check(ap == "-", "invalid")?;
                self.root.clone()
            } else {
                self.authority(&ap, &ac, 8, depth)?.signer_public_key
            };
            let (_, adm, aid, adm_raw) = self.packet(
                &raw_field(body, "administrator")?,
                "administrator",
                id,
                &signer,
                "-",
            )?;
            check(
                s(&adm, "owner_offer_id") == oid
                    && s(&adm, "selection_id") == sid
                    && s(&com, "administrator_offer_id") == aid,
                "invalid",
            )?;
            let admission = raw_field(&adm_raw, "admission_record")?;
            let (ar, p) =
                self.record(&admission, "peerspan-host-admit-v1", id, &ap, &ac, &signer)?;
            check(
                s(&p, "host_public_key") == host
                    && self
                        .persons
                        .get(&person)
                        .is_some_and(|label| label == s(&p, "member"))
                    && s(&com, "admission_record_id") == ar.id,
                "invalid",
            )?;
            let binding = raw_field(&commit_raw, "binding_record")?;
            let (_, p) = self.record(
                &binding,
                "peerspan-host-bind-v1",
                id,
                &person,
                &issuer,
                &path.signer_public_key,
            )?;
            check(
                s(&p, "host_public_key") == host && s(&p, "person_public_key") == person,
                "invalid",
            )?;
            let mut draft = object(
                offer
                    .get("binding_record")
                    .ok_or_else(|| problem("invalid"))?,
            )?
            .clone();
            check(s(&draft, "host_signature") == "-", "invalid")?;
            let mut final_record = obj(&binding)?;
            draft.remove("host_signature");
            final_record.remove("host_signature");
            check(draft == final_record, "invalid")?;
            self.host_activations(&host, depth)?;
            check(
                !self.state.hosts.contains_key(&host) && !self.state.bindings.contains_key(&host),
                "state_conflict",
            )?;
            completed_records.push(binding);
            completed_records.push(admission);
        } else if mode == "renew" {
            check(
                s(&req, "expected_network_id") == self.net
                    && s(&req, "expected_person_public_key") == person
                    && s(&req, "renewed_certificate_id") != "-"
                    && ident(s(&offer, "membership_proof_id"), "pf_")
                    && ident(s(&offer, "binding_proof_id"), "pf_")
                    && absent_value(a.get("administrator"))
                    && absent_value(offer.get("binding_record"))
                    && absent_value(com.get("binding_record"))
                    && s(&com, "administrator_offer_id") == "-"
                    && s(&com, "admission_record_id") == "-",
                "invalid",
            )?;
            let old = self.structural(text(&req, "renewed_certificate_id")?, &person)?;
            check(old.host == host && old.device == device, "invalid")?;
            self.activate(&old.request, true, depth + 1)?;
            check(
                self.state.activated_certificates.contains(&old.id),
                "invalid",
            )?;
            self.renewal_proof(
                text(&offer, "membership_proof_id")?,
                "peerspan-host-admit-v1",
                &person,
                &host,
                depth,
            )?;
            self.renewal_proof(
                text(&offer, "binding_proof_id")?,
                "peerspan-host-bind-v1",
                &person,
                &host,
                depth,
            )?;
            check(
                self.state.hosts.get(&host) == Some(&true)
                    && self.state.bindings.get(&host) == Some(&person),
                "forbidden",
            )?;
        } else {
            return Err(problem("invalid"));
        }
        // Facts become visible only after all transcript checks. All recursive
        // ancestors are independently complete; errors discard the scratch state.
        if mode == "new" {
            self.state.hosts.insert(host.clone(), true);
            self.hosts.insert(
                host.clone(),
                self.persons
                    .get(&person)
                    .ok_or_else(|| problem("proof_required"))?
                    .clone(),
            );
            self.state.bindings.insert(host.clone(), person.clone());
            for raw in completed_records {
                let o = obj(&raw)?;
                let kind = if o.contains_key("person_public_key") {
                    "person_record"
                } else {
                    "root_record"
                };
                for (pf, p) in &self.proofs {
                    if p.kind == kind && p.object == o {
                        self.active_records.insert(pf.clone());
                    }
                }
            }
        }
        self.state.activated_certificates.insert(cid.clone());
        Ok(Identity {
            request_id: id.into(),
            manifest_id: mid,
            certificate_id: cid,
            network_id: self.net.clone(),
            feature_id: self.feature.clone(),
            person_public_key: person,
            host_public_key: host,
            device_public_key: device,
            mode,
        })
    }
}

pub(super) fn probe_activation(o: &Obj) -> Value {
    let run = || -> Result<Value> {
        fields(
            o,
            "kind network_base64 catalog_base64 activation_base64 epoch known_feature_id caller_host_public_key expected_person_public_key now verification",
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(text(o, "catalog_base64")?, MAX_ACTIVATION)?;
        let activation = decode(text(o, "activation_base64")?, MAX_ACTIVATION)?;
        let r = verify_activation(
            ActivationContext {
                network: &network,
                epoch: num(o, "epoch")?,
                known_feature_id: text(o, "known_feature_id")?,
                caller_host_public_key: text(o, "caller_host_public_key")?,
                expected_person_public_key: text(o, "expected_person_public_key")?,
                now: stamp(text(o, "now")?)?,
                verification: text(o, "verification")?,
            },
            &catalog,
            &activation,
        )?;
        let mut result = serde_json::to_value(r)?;
        result
            .as_object_mut()
            .expect("serialized struct")
            .insert("ok".into(), Value::Bool(true));
        Ok(result)
    };
    run().unwrap_or_else(|e| {
        let code = e.downcast_ref::<PathError>().map_or("invalid",|e|e.code);
        if code == "proof_required" {
            json!({"ok":false,"code":code,"required_ids":e.downcast_ref::<PathError>().expect("known error").required_ids})
        } else { json!({"ok":false,"code":code}) }
    })
}
