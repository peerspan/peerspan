//! Owner-local legacy source inspection and separately approved roster identity.
//! Source bytes/floors/markers come from one held transaction, without polling.
use super::{
    codec::*,
    controls, creation,
    intents::{Intent, Provider, Record},
    migration::{self, SourceContext},
    statement::Descriptor,
};
use crate::{
    link_runtime::{catalog, feature, persistence, restrictions},
    store::Store,
};
use ed25519_dalek::SigningKey;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
pub(super) fn legacy(e: anyhow::Error) -> Error {
    if let Some(p) = e.downcast_ref::<crate::linking::PathError>() {
        Error {
            code: p.code,
            required_ids: p.required_ids.iter().cloned().collect(),
            stage: None,
            retry_after: None,
        }
    } else if let Some(f) = e.downcast_ref::<crate::link_runtime::support::Failure>() {
        let code = match f.code.as_str() {
            "proof_required" => "proof_required",
            "forbidden" => "forbidden",
            "state_conflict" => "state_conflict",
            "quota_exceeded" => "quota_exceeded",
            "version_exhausted" => "version_exhausted",
            _ => "invalid",
        };
        Error {
            code,
            required_ids: f.details.required_ids.iter().cloned().collect(),
            stage: None,
            retry_after: None,
        }
    } else {
        Error::new("state_conflict")
    }
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
pub(super) struct Source {
    pub descriptor: Descriptor,
    pub legacy_descriptor: Vec<u8>,
    pub feature: String,
    pub catalog: Vec<u8>,
    pub state_bytes: Vec<u8>,
    pub facts: crate::linking::NetworkState,
    pub time: String,
}
impl Source {
    pub(super) fn load(store: &Store, c: &Connection, network: &str) -> Result<Self> {
        check(ident(network, "net_"))?;
        let raw: Option<String> = c
            .query_row("SELECT record FROM networks WHERE id=?1", [network], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)?;
        let raw = raw.ok_or_else(|| Error::new("not_found"))?;
        // This is an existing legacy private row, whose original reader
        // permits nullable sync/pending fields. The DEC no-null parser is not
        // its schema. This tag inspection grants nothing: the unchanged legacy
        // row and exact signed source are independently verified below.
        require(raw.len() <= 32 << 20, "quota_exceeded")?;
        let value: Value = serde_json::from_str(&raw).map_err(|_| Error::new("state_conflict"))?;
        require(
            value.get("mode").and_then(Value::as_str) != Some("decentralized"),
            "upgrade_required",
        )?;
        let n = store
            .network_record(c, network)
            .map_err(|_| Error::new("state_conflict"))?;
        let time = creation::decision(c, network, &controls::local_decision_time()?)?;
        let d = Descriptor::read(&bytes(
            &json!({"format":1,"protocol":"peerspan-decentralized-v1","network_id":network,"name":n.name,"genesis_root_public_key":n.root_public_key}),
        )?)?;
        let old = catalog::read(c, network).map_err(legacy)?;
        let local = feature::legacy_catalog(c, &n).map_err(legacy)?;
        let all = catalog::merge(network, &[&old, &local]).map_err(legacy)?;
        require(all.len() <= 512 << 10, "quota_exceeded")?;
        let objects = catalog::decode(&all, network).map_err(legacy)?;
        let epoch = catalog::target_epoch(&objects).map_err(legacy)?;
        require(n.root_epoch <= epoch, "state_conflict")?;
        let (feature, _) = catalog::feature(c, network).map_err(legacy)?;
        let descriptor = catalog::descriptor(&n).map_err(legacy)?;
        let facts = crate::linking::verify_stored_migration_source(
            crate::linking::CatalogFactContext {
                network: &descriptor,
                epoch,
                known_feature_id: &feature,
                now: stamp(&time)?,
            },
            &all,
        )
        .map_err(legacy)?;
        require(
            facts.epoch == epoch && facts.root_public_key == n.current_root_public_key,
            "state_conflict",
        )?;
        let (policies, groups) = persistence::high_water(c, network).map_err(legacy)?;
        let access = crate::linking::verify_stored_migration_access(
            crate::linking::AccessContext {
                network: &descriptor,
                epoch,
                known_feature_id: &feature,
                now: stamp(&time)?,
                prior_policies: &policies,
                prior_groups: &groups,
            },
            &all,
        )
        .map_err(legacy)?;
        let mut maxima = BTreeMap::<(String, String), (u64, String)>::new();
        for p in access.policies {
            maxima.insert(
                ("policy".into(), p.person_public_key),
                (
                    p.selection.high_water.version,
                    p.selection.high_water.message_hash,
                ),
            );
        }
        for g in access.groups {
            maxima.insert(
                ("group".into(), g.name),
                (
                    g.selection.high_water.version,
                    g.selection.high_water.message_hash,
                ),
            );
        }
        let mut remember = |kind: &str, subject: &str, version: u64, hash: &str| -> Result<()> {
            let k = (kind.into(), subject.into());
            if let Some((v, h)) = maxima.get(&k) {
                require(
                    *v >= version && (*v != version || h == hash),
                    "state_conflict",
                )?;
            } else {
                maxima.insert(k, (version, hash.into()));
            }
            Ok(())
        };
        for p in &policies {
            remember(
                "policy",
                &p.person_public_key,
                p.high_water.version,
                &p.high_water.message_hash,
            )?;
        }
        for g in &groups {
            remember(
                "group",
                &g.name,
                g.high_water.version,
                &g.high_water.message_hash,
            )?;
        }
        let mut sticky: BTreeSet<_> = restrictions::pending(c, network)
            .map_err(legacy)?
            .into_iter()
            .collect();
        for p in catalog::decode(&local, network).map_err(legacy)?.objects {
            if migration::source_restriction(&p.id, &p.kind, &b64(&p.body_base64, MAX_OBJECT)?)?
                .is_some()
            {
                sticky.insert(p.id);
            }
        }
        let mut admitted = Vec::new();
        let mut seen = BTreeSet::new();
        let mut removed = BTreeSet::new();
        for p in &objects.objects {
            if !facts.applicable_restrictions.contains(&p.id) && !sticky.contains(&p.id) {
                continue;
            }
            let raw = b64(&p.body_base64, MAX_OBJECT)?;
            if let Some(row) = migration::source_restriction(&p.id, &p.kind, &raw)? {
                let outer = parse(&raw, MAX_OBJECT)?;
                let domain = if matches!(p.kind.as_str(), "person_record" | "root_record") {
                    text(object(&outer)?, "kind")?
                } else {
                    p.kind.as_str()
                };
                if matches!(
                    domain,
                    "host_revocation" | "host_leave" | "peerspan-revoke-host-v1"
                ) {
                    removed.insert(text(&row, "host_public_key")?.to_owned());
                }
                seen.insert(p.id.clone());
                admitted.push(Value::Object(row));
            }
        }
        for id in sticky {
            require(seen.contains(&id), "proof_required").map_err(|_| Error::missing(&id))?;
        }
        let hosts: BTreeSet<_> = facts
            .members
            .iter()
            .filter(|m| !removed.contains(&m.host_public_key))
            .map(|m| m.host_public_key.clone())
            .collect();
        let state_bytes = bytes(
            &json!({"format":1,"network_id":network,"legacy_root_highwater":epoch,"known_admitted_hosts":hosts,"access_maxima":maxima.into_iter().map(|((kind,subject),(version,message_hash))|json!({"kind":kind,"subject":subject,"version":version,"message_hash":message_hash})).collect::<Vec<_>>(),"admitted_restrictions":admitted}),
        )?;
        require(state_bytes.len() <= MAX_PAYLOAD, "quota_exceeded")?;
        let (_, facts) = migration::source_snapshot(
            SourceContext {
                descriptor: &d,
                legacy_descriptor: &descriptor,
                epoch,
                feature: &feature,
                root: &facts.root_public_key,
                now: &time,
            },
            &all,
            &state_bytes,
        )?;
        Ok(Self {
            descriptor: d,
            legacy_descriptor: descriptor,
            feature,
            catalog: all,
            state_bytes,
            facts,
            time,
        })
    }
}
pub(super) fn empty_view(network: &str) -> Value {
    json!({"network_id":network,"proposal_id":"-","context_id":"-","state":"needs_approvals","source_catalog_sha256":"-","source_state_sha256":"-","prepared_catalog_sha256":"-","root_state_id":"-","local_acknowledgment_id":"-","root_commit_id":"-","missing_host_keys":[],"required_proof_ids":[],"approved":false,"fenced":false,"expires_at":"-"})
}
fn no_proposal(c: &Connection, network: &str) -> Result<()> {
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM dec_migrations WHERE network_id=?1)",
            [network],
            |r| r.get(0),
        )
        .map_err(db)?;
    // A preproposal read never hides a real staged/fenced transition. The
    // proposal controller will supply its exact view instead of this prefix.
    require(!exists, "recovery_required")
}
pub(crate) fn status(store: &Store, network: &str) -> Result<Vec<u8>> {
    super::migration_evidence::status(store, network)
}
fn identity_review(s: &Source, identity: &Value) -> Value {
    json!({"stage":"identity","network_id":s.descriptor.network_id,"proposal_id":"-","legacy_root_public_key":s.facts.root_public_key,"legacy_epoch":s.facts.epoch,"new_context_id":"-","roster":[identity],"source_catalog_sha256":hash(&s.catalog),"source_state_sha256":hash(&s.state_bytes),"prepared_catalog_sha256":"-","authority_warning":"Whole-network migration requires the current root, every known host and each original person's exact consent. This identity review creates no membership, acknowledgment, fence or device power; finite deadlines and no coordinated timeout abort remain."})
}
pub(super) fn validate_identity(i: &Intent, host: &str) -> Result<Value> {
    i.shape()?;
    let r = &i.record;
    check(
        i.kind == "migration_identity"
            && r.host_public_key == host
            && r.provider.signer_public_key == host,
    )?;
    let v = parse(&b64(&r.review_base64, MAX_OBJECT)?, MAX_OBJECT)?;
    let o = object(&v)?;
    fields(
        o,
        "stage network_id proposal_id legacy_root_public_key legacy_epoch new_context_id roster source_catalog_sha256 source_state_sha256 prepared_catalog_sha256 authority_warning",
    )?;
    check(
        text(o, "stage")? == "identity"
            && text(o, "network_id")? == i.network_id
            && text(o, "proposal_id")? == "-"
            && text(o, "new_context_id")? == "-"
            && text(o, "prepared_catalog_sha256")? == "-"
            && key(text(o, "legacy_root_public_key")?)
            && digest(text(o, "source_catalog_sha256")?)
            && digest(text(o, "source_state_sha256")?)
            && !text(o, "authority_warning")?.is_empty()
            && text(o, "authority_warning")?.len() <= 1024,
    )?;
    num(o, "legacy_epoch")?;
    let roster = array(o, "roster")?;
    check(roster.len() == 1)?;
    let row = object(&roster[0])?;
    fields(
        row,
        "host_public_key member person_public_key device_public_key scopes",
    )?;
    label(text(row, "member")?)?;
    check(
        text(row, "host_public_key")? == host
            && text(row, "person_public_key")? == r.person_public_key
            && text(row, "device_public_key")? == r.device_public_key
            && num(row, "scopes")? == r.scopes,
    )?;
    if r.person_public_key == "-" {
        check(r.device_public_key == "-" && r.scopes == 0 && i.secret.is_none())?;
    } else {
        check(key(&r.person_public_key) && key(&r.device_public_key) && r.scopes > 0)?;
    }
    if let Some(seed) = &i.secret {
        let seed: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::new("state_conflict"))?;
        check(
            encode(SigningKey::from_bytes(seed).verifying_key().as_bytes()) == r.device_public_key,
        )?;
    }
    Ok(roster[0].clone())
}
pub(super) fn approved_identity(
    c: &Connection,
    network: &str,
    host: &str,
) -> Result<Option<Intent>> {
    let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE network_id=?1 AND kind='migration_identity' ORDER BY intent_id").map_err(db)?;
    let rows = q
        .query_map([network], |r| r.get::<_, String>(0))
        .map_err(db)?;
    let mut found = None;
    for id in rows {
        let i = Intent::load(c, &id.map_err(db)?)?;
        validate_identity(&i, host).map_err(|_| Error::new("state_conflict"))?;
        if i.record.terminal == "-" {
            require(found.is_none(), "state_conflict")?;
            found = Some(i);
        }
    }
    Ok(found)
}
pub(super) fn own_identity(c: &Connection, s: &Source, host: &str, scopes: u64) -> Result<Value> {
    let member = s
        .facts
        .members
        .iter()
        .find(|m| m.host_public_key == host)
        .ok_or_else(|| Error::new("forbidden"))?;
    let person = &member.person_public_key;
    if person == "-" {
        require(scopes == 0, "operation_conflict")?;
        return Ok(
            json!({"host_public_key":host,"member":member.member,"person_public_key":"-","device_public_key":"-","scopes":0}),
        );
    }
    require(scopes > 0 && scopes <= 15, "invalid")?;
    type Selected = (String, String, String);
    let selected: Option<Selected> = c
        .query_row(
            "SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?1",
            [&s.descriptor.network_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(db)?;
    let device = if let Some((owner, device, id)) = selected {
        require(owner == *person, "operation_conflict")?;
        let raw = s
            .facts
            .facts
            .state
            .certificates
            .get(&id)
            .ok_or_else(|| Error::missing(&id))?;
        require(
            s.facts.facts.state.activated_certificates.contains(&id),
            "proof_required",
        )?;
        let v = parse(raw, MAX_OBJECT)?;
        let p = object(&v)?;
        check(
            text(p, "person_public_key")? == person
                && text(p, "host_public_key")? == host
                && text(p, "device_public_key")? == device,
        )?;
        require(num(p, "scopes")? == scopes, "operation_conflict")?;
        persistence::device(c, &device).map_err(|_| Error::new("signer_unavailable"))?;
        device
    } else {
        "-".into()
    };
    Ok(
        json!({"host_public_key":host,"member":member.member,"person_public_key":person,"device_public_key":device,"scopes":scopes}),
    )
}
pub(crate) fn identity(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "scopes approve")?;
    let scopes = num(input, "scopes")?;
    check(scopes <= 15)?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let host = store.identity().public_key;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let source = Source::load(store, &tx, network)?;
    no_proposal(&tx, network)?;
    let mut identity = own_identity(&tx, &source, &host, scopes)?;
    if let Some(i) = approved_identity(&tx, network, &host)? {
        let old = validate_identity(&i, &host).map_err(|_| Error::new("state_conflict"))?;
        if identity["device_public_key"] == "-"
            && identity["person_public_key"] != "-"
            && i.secret.is_some()
        {
            identity["device_public_key"] = old["device_public_key"].clone();
        }
        require(identity == old, "operation_conflict")?;
        let review = parse(&b64(&i.record.review_base64, MAX_OBJECT)?, MAX_OBJECT)?;
        return bytes(
            &json!({"migration":empty_view(network),"identity":old,"review":review,"signing_requests":[]}),
        );
    }
    if !approve {
        return bytes(
            &json!({"migration":empty_view(network),"identity":identity,"review":identity_review(&source,&identity),"signing_requests":[]}),
        );
    }
    let total: i64 = tx
        .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
        .map_err(db)?;
    require(total < 4096, "quota_exceeded")?;
    let secret = if identity["person_public_key"] != "-" && identity["device_public_key"] == "-" {
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).map_err(|_| Error::new("internal"))?;
        identity["device_public_key"] = Value::from(encode(
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        ));
        Some(seed.to_vec())
    } else {
        None
    };
    let review = identity_review(&source, &identity);
    let i = Intent {
        id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
        network_id: network.into(),
        context_id: "-".into(),
        kind: "migration_identity".into(),
        secret,
        record: Record {
            format: 1,
            operation_id: "-".into(),
            approved: true,
            approved_at: source.time.clone(),
            review_base64: encode(&bytes(&review)?),
            provider: Provider {
                kind: "host".into(),
                signer_public_key: host.clone(),
                signature_format: "ed25519".into(),
                lease_id: "-".into(),
            },
            root_state_id: "-".into(),
            person_public_key: text(object(&identity)?, "person_public_key")?.into(),
            host_public_key: host.clone(),
            device_public_key: text(object(&identity)?, "device_public_key")?.into(),
            scopes,
            not_after: "-".into(),
            created_at: source.time.clone(),
            expires_at: super::actions::at(&source.time, 300)?,
            templates: Vec::new(),
            signatures: Vec::new(),
            completed: true,
            terminal: "-".into(),
            result_base64: "-".into(),
        },
    };
    validate_identity(&i, &host)?;
    i.save(&tx)?;
    creation::remember_clock(&tx, network, &source.time)?;
    tx.commit().map_err(db)?;
    drop(c);
    controls::barrier(store, "dec.intent.after_commit", &i.id)?;
    bytes(
        &json!({"migration":empty_view(network),"identity":identity,"review":review,"signing_requests":[]}),
    )
}
