//! Conservative sufficient-proof closure over an independently verified source.
use super::*;

pub struct ProofSeed {
    pub kind: String,
    pub body: Vec<u8>,
}

#[derive(Default, Clone)]
struct Subjects {
    refs: BTreeSet<String>,
    aliases: BTreeSet<String>,
    people: BTreeSet<String>,
    hosts: BTreeSet<String>,
    devices: BTreeSet<String>,
    invites: BTreeSet<String>,
}
impl Subjects {
    fn merge(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (a, b) in [
            (&mut self.refs, &other.refs),
            (&mut self.aliases, &other.aliases),
            (&mut self.people, &other.people),
            (&mut self.hosts, &other.hosts),
            (&mut self.devices, &other.devices),
            (&mut self.invites, &other.invites),
        ] {
            let before = a.len();
            a.extend(b.iter().cloned());
            changed |= before != a.len();
        }
        changed
    }
}

fn aliases(o: &Obj) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if o.contains_key("parent_id") {
        out.push(certificate_id(o)?);
    }
    if o.contains_key("payload_base64") {
        let (b, _) = p_obj(o)?;
        if o.contains_key("role") {
            let message = lines(&[
                "peerspan-link-packet-v1",
                text(o, "request_id")?,
                text(o, "role")?,
                text(o, "writer_public_key")?,
                text(o, "person_public_key")?,
                text(o, "certificate_id")?,
                &hash(&b),
            ]);
            out.push(format!(
                "lp_{}",
                hash(&lines(&[
                    "peerspan-link-packet-id-v1",
                    &hash(&message),
                    text(o, "host_signature")?,
                    text(o, "device_signature")?,
                    text(o, "authority_signature")?
                ]))
            ));
            if s(o, "role") == "request" {
                out.push(text(o, "request_id")?.into());
            }
        } else if o.contains_key("kind") {
            let epoch = num(o, "epoch")?.to_string();
            if o.contains_key("person_public_key") {
                let message = lines(&[
                    "peerspan-person-authorization-v1",
                    text(o, "kind")?,
                    text(o, "network_id")?,
                    &epoch,
                    text(o, "operation_id")?,
                    text(o, "person_public_key")?,
                    text(o, "certificate_id")?,
                    &hash(&b),
                ]);
                out.push(format!(
                    "ar_{}",
                    hash(&lines(&[
                        "peerspan-authorized-record-v1",
                        &hash(&message),
                        text(o, "signature")?,
                        text(o, "host_signature")?
                    ]))
                ));
            } else {
                let message = lines(&[
                    "peerspan-root-authorization-v1",
                    text(o, "kind")?,
                    text(o, "network_id")?,
                    &epoch,
                    text(o, "operation_id")?,
                    &hash(&b),
                ]);
                out.push(format!(
                    "rr_{}",
                    hash(&lines(&[
                        "peerspan-root-authorized-record-v1",
                        &hash(&message),
                        text(o, "signature")?
                    ]))
                ));
            }
        }
    }
    if o.contains_key("target_device_public_key") {
        out.push(format!(
            "dr_{}",
            hash(&lines(&[
                "peerspan-device-revoke-v1",
                text(o, "network_id")?,
                text(o, "person_public_key")?,
                text(o, "target_device_public_key")?,
                text(o, "target_certificate_id")?,
                text(o, "issuer_certificate_id")?,
                text(o, "revoked_at")?
            ]))
        ));
    }
    Ok(out)
}

fn discover(o: &Obj, out: &mut Subjects, feature: bool) -> Result<()> {
    out.aliases.extend(aliases(o)?);
    if feature {
        return Ok(());
    }
    for (name, value) in o {
        match value {
            Value::String(value) => {
                if ["pf_", "dc_", "ar_", "rr_", "dr_", "lp_", "lf_", "link_"]
                    .iter()
                    .any(|p| ident(value, p))
                {
                    out.refs.insert(value.clone());
                }
                if key(value) {
                    match name.as_str() {
                        "person_public_key" | "expected_person_public_key" => {
                            out.people.insert(value.clone());
                        }
                        "host_public_key" => {
                            out.hosts.insert(value.clone());
                        }
                        "device_public_key" | "target_device_public_key" => {
                            out.devices.insert(value.clone());
                        }
                        "invite_public_key" => {
                            out.invites.insert(value.clone());
                        }
                        _ => {}
                    }
                }
                if matches!(
                    name.as_str(),
                    "signature" | "invite_signature" | "authority_signature"
                ) && let Some(key) = crate::persons::sshsig_signer(value)
                {
                    out.people.insert(key);
                }
                if name == "payload_base64"
                    || matches!(name.as_str(), "host_invite_base64" | "person_invite_base64")
                        && value != "-"
                {
                    let b = decode(value, MAX_PAYLOAD)?;
                    discover(&obj(&b)?, out, false)?;
                }
            }
            Value::Object(nested) => discover(nested, out, false)?,
            Value::Array(values) => {
                for value in values {
                    match value {
                        Value::Object(nested) => discover(nested, out, false)?,
                        Value::String(id) if ["pf_", "ar_", "dr_"].iter().any(|p| ident(id, p)) => {
                            out.refs.insert(id.clone());
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// Exact nested proof references resolve to the enclosing original activation.
// RawValue slices preserve content-addressed whitespace and key order.
fn nested_aliases(body: &[u8], out: &mut Subjects) -> Result<()> {
    let o = obj(body)?;
    for (name, value) in &o {
        match value {
            Value::Object(nested) => {
                let raw = raw_field(body, name)?;
                match name.as_str() {
                    "certificate" if nested.contains_key("parent_id") => {
                        out.aliases.insert(proof_id("certificate", &raw));
                    }
                    "binding_record"
                        if s(nested, "kind") == "peerspan-host-bind-v1"
                            && s(nested, "host_signature") != "-" =>
                    {
                        out.aliases.insert(proof_id("person_record", &raw));
                    }
                    "admission_record" if s(nested, "kind") == "peerspan-host-admit-v1" => {
                        let kind = if nested.contains_key("person_public_key") {
                            "person_record"
                        } else {
                            "root_record"
                        };
                        out.aliases.insert(proof_id(kind, &raw));
                    }
                    _ => {}
                }
                nested_aliases(&raw, out)?;
            }
            Value::String(value) if name == "payload_base64" => {
                nested_aliases(&decode(value, MAX_PAYLOAD)?, out)?;
            }
            Value::Array(_) => {
                let raw = raw_field(body, name)?;
                let values: Vec<Box<RawValue>> = serde_json::from_slice(&raw)?;
                for value in values {
                    if value.get().trim_start().starts_with('{') {
                        nested_aliases(value.get().as_bytes(), out)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

struct Node {
    id: String,
    kind: String,
    body: Vec<u8>,
    object: Obj,
    subjects: Subjects,
}
fn relevant(node: &Node, s: &Subjects) -> Result<bool> {
    let o = &node.object;
    Ok(match node.kind.as_str() {
        "rotation" | "feature" => true,
        "person_admission" | "person_membership" | "admin_delegation" | "admin_removal"
        | "person_removal" => s.people.contains(scalar(o, "person_public_key")),
        "checkpoint" => {
            s.people.contains(scalar(o, "person_public_key"))
                && ["records", "activations"].into_iter().any(|field| {
                    o.get(field).and_then(Value::as_array).is_some_and(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|id| s.refs.contains(id) || s.aliases.contains(id))
                    })
                })
        }
        "host_admission" | "host_membership" | "host_binding" | "host_unbinding" | "host_leave"
        | "host_revocation" | "attestation" | "join_ack" => {
            s.hosts.contains(scalar(o, "host_public_key"))
        }
        "invite_revocation" => s.invites.contains(scalar(o, "invite_public_key")),
        "device_revocation" => {
            s.people.contains(scalar(o, "person_public_key"))
                && s.devices.contains(scalar(o, "target_device_public_key"))
        }
        "activation" => {
            let request = object(o.get("request").ok_or_else(|| problem("invalid"))?)?;
            let (_, body) = p_obj(request)?;
            s.hosts.contains(scalar(&body, "host_public_key"))
        }
        "invite_redemption" => {
            s.hosts.contains(scalar(o, "host_public_key"))
                || scalar(o, "person_action") == "admit"
                    && s.people.contains(scalar(o, "person_public_key"))
        }
        "person_record" | "root_record" => {
            let (_, p) = p_obj(o)?;
            match scalar(o, "kind") {
                "peerspan-person-admit-v1" | "peerspan-person-remove-v1" => {
                    s.people.contains(scalar(&p, "person_public_key"))
                }
                "peerspan-host-admit-v1"
                | "peerspan-host-bind-v1"
                | "peerspan-host-unbind-v1"
                | "peerspan-revoke-host-v1" => s.hosts.contains(scalar(&p, "host_public_key")),
                "peerspan-revoke-invite-v1" => s.invites.contains(scalar(&p, "invite_public_key")),
                _ => false,
            }
        }
        _ => false,
    })
}
fn scalar<'a>(o: &'a Obj, name: &str) -> &'a str {
    s(o, name)
}
fn catalog_bytes(net: &str, nodes: &[&Node]) -> Result<Vec<u8>> {
    let entries: Vec<_> = nodes
        .iter()
        .map(|n| json!({"id":n.id,"kind":n.kind,"body_base64":STANDARD.encode(&n.body)}))
        .collect();
    Ok(serde_json::to_vec(
        &json!({"format":1,"network_id":net,"objects":entries}),
    )?)
}
fn context<'a>(ctx: &CatalogFactContext<'a>) -> CatalogFactContext<'a> {
    CatalogFactContext {
        network: ctx.network,
        epoch: ctx.epoch,
        known_feature_id: ctx.known_feature_id,
        now: ctx.now,
    }
}

fn validate_seed(
    ctx: &CatalogFactContext<'_>,
    catalog: &[u8],
    seed: &ProofSeed,
    nodes: &[Node],
) -> Result<()> {
    let o = obj(&seed.body)?;
    if seed.kind == "invite_feature" {
        fields(&o, "binding host_invite_base64 person_invite_base64", &[])?;
        let mut halves = [Vec::new(), Vec::new()];
        for (i, name) in ["host_invite_base64", "person_invite_base64"]
            .iter()
            .enumerate()
        {
            let value = text(&o, name)?;
            if value != "-" {
                halves[i] = decode(value, MAX_OBJECT)?;
            }
        }
        verify_stored_invite_feature(
            context(ctx),
            catalog,
            &raw_field(&seed.body, "binding")?,
            &halves[0],
            &halves[1],
        )?;
        return Ok(());
    }
    if seed.kind == "packet" {
        let device = if matches!(s(&o, "role"), "request" | "selection" | "commit") {
            crate::persons::sshsig_signer(text(&o, "device_signature")?)
                .ok_or_else(|| problem("invalid"))?
        } else {
            "-".into()
        };
        read(
            "packet",
            &seed.body,
            text(&o, "writer_public_key")?,
            &device,
        )?;
        if matches!(s(&o, "role"), "owner" | "administrator")
            && ident(s(&o, "certificate_id"), "dc_")
        {
            let mut v = runtime_write::stored_writer_verifier(ctx, catalog)?;
            v.actor(
                text(&o, "person_public_key")?,
                text(&o, "certificate_id")?,
                0,
                true,
                0,
            )?;
        }
        return Ok(());
    }
    if matches!(seed.kind.as_str(), "person_record" | "root_record") {
        let mut v = runtime_write::stored_writer_verifier(ctx, catalog)?;
        let (mut signer, _) = v.epoch_root(&o, "epoch")?;
        check(s(&o, "network_id") == v.net, "invalid")?;
        if seed.kind == "person_record" {
            let person = text(&o, "person_public_key")?;
            let cert = text(&o, "certificate_id")?;
            signer = if cert == "root" {
                person.into()
            } else {
                v.structural(cert, person)?.device
            };
            v.actor(person, cert, 0, true, 0)?;
        }
        read(&seed.kind, &seed.body, &signer, "-")?;
        return Ok(());
    }
    let id = proof_id(&seed.kind, &seed.body);
    let existing = nodes.iter().any(|n| n.id == id);
    if existing && !matches!(seed.kind.as_str(), "certificate" | "checkpoint") {
        return Ok(());
    }
    let candidate = Node {
        id,
        kind: seed.kind.clone(),
        body: seed.body.clone(),
        object: o.clone(),
        subjects: Subjects::default(),
    };
    let mut rows: Vec<_> = nodes.iter().collect();
    if !existing {
        rows.push(&candidate);
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let candidate = catalog_bytes(s(&obj(ctx.network)?, "network_id"), &rows)?;
    verify_stored_network_state(context(ctx), &candidate)?;
    if matches!(seed.kind.as_str(), "certificate" | "checkpoint") {
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.stored_snapshot = true;
        v.catalog(&candidate)?;
        v.bootstrap(true)?;
        let person = text(&o, "person_public_key")?;
        if seed.kind == "certificate" {
            v.structural(&certificate_id(&o)?, person)?;
            let parent = text(&o, "parent_id")?;
            if parent != "root" {
                v.actor(person, parent, 0, true, 0)?;
            }
        } else {
            let issuer = text(&o, "issuer_certificate_id")?;
            let signer = if issuer == "root" {
                person.into()
            } else {
                v.structural(issuer, person)?.device
            };
            if issuer != "root" {
                v.actor(person, issuer, 0, true, 0)?;
            }
            read("checkpoint", &seed.body, &signer, "-")?;
        }
    }
    Ok(())
}

pub fn select_stored_proof_catalog(
    ctx: CatalogFactContext<'_>,
    catalog: &[u8],
    seeds: &[ProofSeed],
) -> Result<Vec<u8>> {
    let run = || -> Result<Vec<u8>> {
        check(!seeds.is_empty() && seeds.len() <= 4096, "invalid")?;
        let state = verify_stored_network_state(context(&ctx), catalog)?;
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        v.stored_snapshot = true;
        v.catalog(catalog)?;
        let c = object(&parse_limit(catalog, MAX_STORED_CATALOG)?)?.clone();
        let entries = c
            .get("objects")
            .and_then(Value::as_array)
            .ok_or_else(|| problem("invalid"))?;
        let mut nodes = Vec::new();
        let mut providers: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for row in entries {
            let row = object(row)?;
            let id = text(row, "id")?;
            let kind = text(row, "kind")?;
            let proof = v.proofs.get(id).ok_or_else(|| problem("invalid"))?;
            let mut subjects = Subjects::default();
            discover(&proof.object, &mut subjects, kind == "feature")?;
            if kind != "feature" {
                nested_aliases(&proof.body, &mut subjects)?;
            }
            subjects.aliases.insert(id.into());
            if kind == "feature" {
                subjects.aliases.insert(state.facts.feature_id.clone());
            }
            for alias in &subjects.aliases {
                providers
                    .entry(alias.clone())
                    .or_default()
                    .push(nodes.len());
            }
            nodes.push(Node {
                id: id.into(),
                kind: kind.into(),
                body: proof.body.clone(),
                object: proof.object.clone(),
                subjects,
            });
        }
        let mut found = Subjects::default();
        let mut seed_aliases = BTreeSet::new();
        let mut seed_bytes = 0usize;
        for seed in seeds {
            seed_bytes += seed.body.len();
            check(seed_bytes <= MAX_ACTIVATION, "invalid")?;
            validate_seed(&ctx, catalog, seed, &nodes)?;
            let mut subjects = Subjects::default();
            discover(&obj(&seed.body)?, &mut subjects, seed.kind == "feature")?;
            if seed.kind != "feature" {
                nested_aliases(&seed.body, &mut subjects)?;
            }
            found.merge(&subjects);
            seed_aliases.extend(subjects.aliases);
            let id = proof_id(&seed.kind, &seed.body);
            if seed.kind != "packet" && nodes.iter().any(|n| n.id == id) {
                found.refs.insert(id);
            }
        }
        let mut picked = BTreeSet::new();
        loop {
            let mut changed = false;
            for id in &found.refs {
                for index in providers.get(id).into_iter().flatten() {
                    changed |= picked.insert(*index);
                }
            }
            for (index, node) in nodes.iter().enumerate() {
                if relevant(node, &found)? {
                    changed |= picked.insert(index);
                }
            }
            for index in &picked {
                changed |= found.merge(&nodes[*index].subjects);
            }
            if !changed {
                break;
            }
        }
        let missing: Vec<_> = found
            .refs
            .iter()
            .filter(|id| {
                !providers.contains_key(*id)
                    && !seed_aliases.contains(*id)
                    && ["pf_", "dc_", "ar_", "rr_", "dr_", "lf_"]
                        .iter()
                        .any(|p| id.starts_with(p))
            })
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(PathError {
                code: "proof_required",
                required_ids: missing,
            }
            .into());
        }
        let rows: Vec<_> = picked.iter().map(|i| &nodes[*i]).collect();
        let out = catalog_bytes(&state.facts.network_id, &rows)?;
        check(
            out.len() <= MAX_OBJECT && rows.len() <= 4096,
            "quota_exceeded",
        )?;
        verify_stored_network_state(context(&ctx), &out)?;
        for seed in seeds.iter().filter(|s| s.kind == "invite_feature") {
            validate_seed(&ctx, &out, seed, &[])?;
        }
        Ok(out)
    };
    run().map_err(|e| {
        if e.downcast_ref::<PathError>().is_some() {
            e
        } else {
            problem("invalid")
        }
    })
}

pub(super) fn probe(o: &Obj) -> Value {
    let run = || -> Result<Value> {
        fields(
            o,
            "kind network_base64 catalog_base64 seeds epoch known_feature_id now",
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(text(o, "catalog_base64")?, MAX_STORED_CATALOG)?;
        let rows = o
            .get("seeds")
            .and_then(Value::as_array)
            .ok_or_else(|| problem("invalid"))?;
        check(!rows.is_empty() && rows.len() <= 4096, "invalid")?;
        let mut seeds = Vec::new();
        for row in rows {
            let row = object(row)?;
            fields(row, "kind body_base64", &[])?;
            seeds.push(ProofSeed {
                kind: text(row, "kind")?.into(),
                body: decode(text(row, "body_base64")?, MAX_ACTIVATION)?,
            });
        }
        let out = select_stored_proof_catalog(
            CatalogFactContext {
                network: &network,
                epoch: num(o, "epoch")?,
                known_feature_id: text(o, "known_feature_id")?,
                now: stamp(text(o, "now")?)?,
            },
            &catalog,
            &seeds,
        )?;
        Ok(json!({"ok":true,"catalog_base64":STANDARD.encode(out)}))
    };
    match run() {
        Ok(value) => value,
        Err(e) => {
            if let Some(p) = e.downcast_ref::<PathError>() {
                if p.code == "proof_required" {
                    json!({"ok":false,"code":p.code,"required_ids":p.required_ids})
                } else {
                    json!({"ok":false,"code":p.code})
                }
            } else {
                json!({"ok":false,"code":"invalid"})
            }
        }
    }
}
