//! Exact signed access selection with caller-pinned monotonic high-water marks.
use super::*;

#[derive(Clone, Serialize)]
pub struct AccessHighWater {
    pub version: u64,
    pub message_hash: String,
}
#[derive(Clone, Serialize)]
pub struct PolicyHighWater {
    pub person_public_key: String,
    #[serde(flatten)]
    pub high_water: AccessHighWater,
}
#[derive(Clone, Serialize)]
pub struct GroupHighWater {
    pub name: String,
    #[serde(flatten)]
    pub high_water: AccessHighWater,
}
pub struct AccessContext<'a> {
    pub network: &'a [u8],
    pub epoch: u64,
    pub known_feature_id: &'a str,
    pub now: chrono::DateTime<chrono::Utc>,
    pub prior_policies: &'a [PolicyHighWater],
    pub prior_groups: &'a [GroupHighWater],
}
#[derive(Clone, Serialize)]
pub struct AccessSelection {
    #[serde(flatten)]
    pub high_water: AccessHighWater,
    pub proof_id: String,
    pub record_id: String,
    pub body_base64: String,
    pub active: bool,
    pub code: String,
    pub required_ids: Vec<String>,
}
#[derive(Serialize)]
pub struct PolicyAccess {
    pub person_public_key: String,
    #[serde(flatten)]
    pub selection: AccessSelection,
}
#[derive(Serialize)]
pub struct GroupAccess {
    pub name: String,
    #[serde(flatten)]
    pub selection: AccessSelection,
}
#[derive(Serialize)]
pub struct AccessState {
    pub network_id: String,
    pub feature_id: String,
    pub policies: Vec<PolicyAccess>,
    pub groups: Vec<GroupAccess>,
}
pub(super) fn access_kind(kind: &str) -> bool {
    matches!(
        kind,
        "peerspan-policy-v1" | "peerspan-policy-v2" | "peerspan-group-v1"
    )
}
struct Candidate {
    key: String,
    group: bool,
    selection: AccessSelection,
    person: String,
    cert: String,
    payload: Obj,
    root: bool,
    old_root: bool,
}
fn legacy_policy_message(p: &Obj, kind: &str) -> Result<Vec<u8>> {
    record_payload(kind, p)?;
    let mut normalized = p.clone();
    normalized.insert("signature".into(), json!("-"));
    if kind == "peerspan-policy-v2" {
        for name in ["capability_rules", "trusted_hosts", "edits"] {
            normalized.entry(name).or_insert_with(|| json!([]));
        }
    }
    let policy: crate::policy::Policy = serde_json::from_value(Value::Object(normalized))?;
    Ok(policy.statement_lines().join("\n").into_bytes())
}
impl Verifier<'_> {
    fn access_candidate(&mut self, id: &str, p: &Proof) -> Result<Candidate> {
        let o = &p.object;
        let mut c = Candidate {
            key: String::new(),
            group: false,
            selection: missing_selection(AccessHighWater {
                version: 1,
                message_hash: String::new(),
            }),
            person: String::new(),
            cert: "root".into(),
            payload: Obj::new(),
            root: false,
            old_root: false,
        };
        let m;
        let mut record_id = "-".to_owned();
        if p.kind == "person_record" {
            let kind = text(o, "kind")?;
            c.group = kind == "peerspan-group-v1";
            c.person = text(o, "person_public_key")?.into();
            c.cert = text(o, "certificate_id")?.into();
            check(
                access_kind(kind)
                    && s(o, "operation_id") == "-"
                    && key(&c.person)
                    && (c.cert == "root" || ident(&c.cert, "dc_")),
                "invalid",
            )?;
            let scope = if c.group { 8 } else { 1 };
            let mut expiry = None;
            let signer = if c.cert == "root" {
                c.person.clone()
            } else {
                let cert = self.structural(&c.cert, &c.person)?;
                check(cert.scopes & scope == scope, "forbidden")?;
                expiry = Some(cert.until);
                cert.device
            };
            let (record, payload) = self.record(&p.body, kind, "-", &c.person, &c.cert, &signer)?;
            c.payload = payload;
            m = record.message;
            record_id = record.id;
            if c.group {
                check(self.access_admin_known(&c.person), "forbidden")?;
            }
            if !c.group
                && let Some(expiry) = expiry
            {
                check(
                    stamp(text(&c.payload, "valid_until")?)? <= expiry,
                    "forbidden",
                )?;
            }
        } else {
            c.group = p.kind == "group";
            c.payload = o.clone();
            c.payload.remove("signature");
            m = if c.group {
                record_payload("peerspan-group-v1", &c.payload)?;
                let version = num(&c.payload, "version")?.to_string();
                let mut parts = vec![
                    "peerspan-group-v1",
                    self.net.as_str(),
                    text(&c.payload, "name")?,
                    &version,
                    text(&c.payload, "defined_at")?,
                ];
                parts.extend(string_list(&c.payload, "members")?);
                lines(&parts)
            } else {
                let kind = if c.payload.contains_key("format") {
                    "peerspan-policy-v2"
                } else {
                    "peerspan-policy-v1"
                };
                legacy_policy_message(&c.payload, kind)?
            };
            let sig = text(o, "signature")?;
            if c.group && self.any_root_signature(&m, sig) {
                c.root = true;
                c.old_root = root(&self.root, &m, sig).is_err();
            } else {
                c.person = if c.group {
                    let signer =
                        crate::persons::sshsig_signer(sig).ok_or_else(|| problem("invalid"))?;
                    check(self.access_admin_known(&signer), "forbidden")?;
                    signer
                } else {
                    text(&c.payload, "person_public_key")?.into()
                };
                ssh(&c.person, &m, sig)?;
            }
        }
        check(s(&c.payload, "network_id") == self.net, "invalid")?;
        if !c.root {
            self.ensure_person(&c.person)?;
            check(self.historical_admission_known(&c.person), "proof_required")?;
            if c.cert != "root" && !self.state.activated_certificates.contains(&c.cert) {
                let cert = self.structural(&c.cert, &c.person)?;
                self.activate(&cert.request, true, 0)?;
            }
        }
        c.key = if c.group {
            text(&c.payload, "name")?.into()
        } else {
            c.person.clone()
        };
        c.selection = AccessSelection {
            high_water: AccessHighWater {
                version: num(&c.payload, "version")?,
                message_hash: hash(&m),
            },
            proof_id: id.into(),
            record_id,
            body_base64: STANDARD.encode(&p.body),
            active: true,
            code: "active".into(),
            required_ids: vec![],
        };
        Ok(c)
    }
    pub(super) fn validate_access_candidates(&mut self) -> Result<()> {
        let proofs: Vec<_> = self
            .proofs
            .iter()
            .filter(|(_, p)| {
                p.kind == "policy"
                    || p.kind == "group"
                    || (p.kind == "person_record"
                        && s(&p.object, "operation_id") == "-"
                        && access_kind(s(&p.object, "kind")))
            })
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        for (id, p) in proofs {
            self.access_candidate(&id, &p)?;
        }
        Ok(())
    }

    fn access_status(&self, c: &mut Candidate) -> Result<()> {
        if c.old_root {
            c.selection.active = false;
            c.selection.code = "forbidden".into();
            return Ok(());
        }
        if !c.root {
            let scope = if c.group { 8 } else { 1 };
            if let Err(e) = evaluate_path(&self.state, &c.person, &c.cert, scope, self.ctx.now) {
                if matches!(e.code, "invalid" | "proof_required") {
                    return Err(e.into());
                }
                c.selection.active = false;
                c.selection.code = e.code.into();
                return Ok(());
            }
        }
        if !c.group {
            let issued = stamp(text(&c.payload, "issued_at")?)?;
            let until = stamp(text(&c.payload, "valid_until")?)?;
            if self.ctx.now < issued - chrono::Duration::minutes(5) || self.ctx.now >= until {
                c.selection.active = false;
                c.selection.code = "expired".into();
            }
        }
        Ok(())
    }
}
fn missing_selection(w: AccessHighWater) -> AccessSelection {
    AccessSelection {
        high_water: w,
        proof_id: "-".into(),
        record_id: "-".into(),
        body_base64: "-".into(),
        active: false,
        code: "proof_required".into(),
        required_ids: vec![],
    }
}
fn group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}
fn valid_water(w: &AccessHighWater) -> bool {
    w.version > 0 && ident(&w.message_hash, "")
}

/// Select exact candidates without granting permission or committing the marks.
pub fn verify_access_state(ctx: AccessContext<'_>, catalog: &[u8]) -> Result<AccessState> {
    let run = || -> Result<AccessState> {
        check(
            ctx.network.len() + catalog.len() <= MAX_ACTIVATION
                && ctx.prior_policies.len() + ctx.prior_groups.len() <= 16384,
            "invalid",
        )?;
        let mut policies = BTreeMap::new();
        let mut groups = BTreeMap::new();
        let mut last = "";
        for p in ctx.prior_policies {
            check(
                key(&p.person_public_key)
                    && p.person_public_key.as_str() > last
                    && valid_water(&p.high_water),
                "invalid",
            )?;
            last = &p.person_public_key;
            policies.insert(last.to_owned(), missing_selection(p.high_water.clone()));
        }
        last = "";
        for g in ctx.prior_groups {
            check(
                group_name(&g.name) && g.name.as_str() > last && valid_water(&g.high_water),
                "invalid",
            )?;
            last = &g.name;
            groups.insert(last.to_owned(), missing_selection(g.high_water.clone()));
        }
        let mut v = Verifier::new(ctx.network, ctx.epoch, ctx.known_feature_id, ctx.now)?;
        check(ctx.known_feature_id != "-", "upgrade_required")?;
        v.catalog(catalog)?;
        v.bootstrap(true)?;
        v.revocations()?;
        let proofs: Vec<_> = v
            .proofs
            .iter()
            .filter(|(_, p)| {
                p.kind == "policy"
                    || p.kind == "group"
                    || (p.kind == "person_record"
                        && s(&p.object, "operation_id") == "-"
                        && access_kind(s(&p.object, "kind")))
            })
            .map(|(id, p)| (id.clone(), p.clone()))
            .collect();
        let mut candidates = Vec::new();
        for (id, p) in proofs {
            candidates.push(v.access_candidate(&id, &p)?);
        }
        v.revocations()?;
        let mut seen_groups: BTreeMap<String, BTreeMap<u64, String>> = BTreeMap::new();
        for g in ctx.prior_groups {
            seen_groups
                .entry(g.name.clone())
                .or_default()
                .insert(g.high_water.version, g.high_water.message_hash.clone());
        }
        for mut c in candidates {
            v.access_status(&mut c)?;
            let selected = if c.group {
                let versions = seen_groups.entry(c.key.clone()).or_default();
                check(
                    versions
                        .get(&c.selection.high_water.version)
                        .is_none_or(|h| h == &c.selection.high_water.message_hash),
                    "state_conflict",
                )?;
                versions.insert(
                    c.selection.high_water.version,
                    c.selection.high_water.message_hash.clone(),
                );
                &mut groups
            } else {
                &mut policies
            };
            let n = &c.selection;
            let replace = selected.get(&c.key).is_none_or(|old| {
                n.high_water.version > old.high_water.version
                    || (n.high_water.version == old.high_water.version
                        && (n.high_water.message_hash < old.high_water.message_hash
                            || (n.high_water.message_hash == old.high_water.message_hash
                                && (old.proof_id == "-" || n.proof_id < old.proof_id))))
            });
            if replace {
                selected.insert(c.key, c.selection);
            }
        }
        Ok(AccessState {
            network_id: v.net,
            feature_id: v.feature,
            policies: policies
                .into_iter()
                .map(|(person_public_key, selection)| PolicyAccess {
                    person_public_key,
                    selection,
                })
                .collect(),
            groups: groups
                .into_iter()
                .map(|(name, selection)| GroupAccess { name, selection })
                .collect(),
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
pub(super) fn probe_access(o: &Obj) -> Value {
    let run = || -> Result<Value> {
        fields(
            o,
            "kind network_base64 catalog_base64 epoch known_feature_id now prior_policies prior_groups",
            &[],
        )?;
        let network = decode(text(o, "network_base64")?, MAX_ACTIVATION)?;
        let catalog = decode(text(o, "catalog_base64")?, MAX_ACTIVATION)?;
        let mut policies = Vec::new();
        let mut groups = Vec::new();
        for field in ["prior_policies", "prior_groups"] {
            for value in o
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| problem("invalid"))?
            {
                let row = object(value)?;
                let subject = if field == "prior_policies" {
                    "person_public_key"
                } else {
                    "name"
                };
                fields(row, &format!("{subject} version message_hash"), &[])?;
                let w = AccessHighWater {
                    version: num(row, "version")?,
                    message_hash: text(row, "message_hash")?.into(),
                };
                if field == "prior_policies" {
                    policies.push(PolicyHighWater {
                        person_public_key: text(row, subject)?.into(),
                        high_water: w,
                    });
                } else {
                    groups.push(GroupHighWater {
                        name: text(row, subject)?.into(),
                        high_water: w,
                    });
                }
            }
        }
        let ctx = AccessContext {
            network: &network,
            epoch: num(o, "epoch")?,
            known_feature_id: text(o, "known_feature_id")?,
            now: stamp(text(o, "now")?)?,
            prior_policies: &policies,
            prior_groups: &groups,
        };
        let mut result = serde_json::to_value(verify_access_state(ctx, &catalog)?)?;
        result["ok"] = json!(true);
        Ok(result)
    };
    match run() {
        Ok(r) => r,
        Err(e) => {
            let p = e.downcast_ref::<PathError>();
            let code = p.map(|p| p.code).unwrap_or("invalid");
            if code == "proof_required" {
                json!({"ok":false,"code":code,"required_ids":p.unwrap().required_ids})
            } else {
                json!({"ok":false,"code":code})
            }
        }
    }
}
