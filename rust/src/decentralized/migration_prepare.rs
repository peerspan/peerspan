//! Root-endorsed migration preparation. The exact source and unsigned templates
//! are durable before approval; approval is durable before any root signature.
//! This module creates no active context, provider, host fence or admission.
use super::{
    actions,
    catalog::Catalog,
    codec::*,
    controls, creation,
    intents::{Filled, Intent, Provider, Record, Template},
    migration::{self, SourceContext},
    migration_local::{self, Source},
    statement::{Descriptor, Statement, proof_id},
    storage::MigrationRecord,
    template::FixedStatement,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    actions::bytes(v)
}

pub(super) fn load(c: &Connection, network: &str) -> Result<Option<(String, MigrationRecord)>> {
    let mut q=c.prepare("SELECT proposal_id,record FROM dec_migrations WHERE network_id=?1 ORDER BY proposal_id").map_err(db)?;
    let rows = q
        .query_map([network], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(db)?;
    let mut found = None;
    for row in rows {
        let (id, raw) = row.map_err(db)?;
        require(found.is_none(), "state_conflict")?;
        let v = parse(raw.as_bytes(), 32 << 20).map_err(|_| Error::new("state_conflict"))?;
        let r: MigrationRecord =
            serde_json::from_value(v).map_err(|_| Error::new("state_conflict"))?;
        require(
            r.format == 1
                && ident(&id, "ds_")
                && ident(&r.context_id, "ctx_")
                && matches!(
                    r.state.as_str(),
                    "needs_approvals" | "prepared" | "acknowledged" | "adopted" | "conflict"
                )
                && r.acknowledgments_base64.len() <= 4096
                && r.root_intent_ids.len() <= 4096,
            "state_conflict",
        )?;
        let mut seen = BTreeSet::new();
        require(
            r.root_intent_ids.iter().all(|s| seen.insert(s)),
            "state_conflict",
        )?;
        for intent_id in r
            .root_intent_ids
            .iter()
            .chain((r.local_ack_intent_id != "-").then_some(&r.local_ack_intent_id))
        {
            let i = Intent::load(c, intent_id)?;
            require(
                i.kind == "migration" && i.network_id == network && i.context_id == r.context_id,
                "state_conflict",
            )?;
        }
        found = Some((id, r));
    }
    Ok(found)
}
pub(super) fn save(c: &Connection, network: &str, id: &str, r: &MigrationRecord) -> Result<()> {
    let raw = serde_json::to_vec(r).map_err(|_| Error::new("internal"))?;
    require(raw.len() <= 32 << 20, "quota_exceeded")?;
    c.execute("INSERT INTO dec_migrations(network_id,proposal_id,record) VALUES(?1,?2,?3) ON CONFLICT(network_id,proposal_id) DO UPDATE SET record=excluded.record",rusqlite::params![network,id,String::from_utf8(raw).map_err(|_|Error::new("internal"))?]).map_err(db)?;
    Ok(())
}
fn people(s: &crate::linking::NetworkState) -> Result<BTreeMap<String, String>> {
    s.facts
        .state
        .persons
        .iter()
        .filter(|(_, p)| p.admitted)
        .map(|(key, _)| {
            let label = s
                .facts
                .person_labels
                .get(key)
                .ok_or_else(|| Error::new("state_conflict"))?;
            Ok((key.clone(), label.clone()))
        })
        .collect()
}
fn roster(c: &Connection, s: &Source, host: &str, rows: &[Value]) -> Result<()> {
    require(
        rows.len() == s.facts.members.len() && rows.len() <= 4096,
        "operation_conflict",
    )?;
    let mut previous = "";
    for row in rows {
        let r = object(row)?;
        fields(
            r,
            "host_public_key member person_public_key device_public_key scopes",
        )?;
        let h = text(r, "host_public_key")?;
        check(key(h) && h > previous)?;
        previous = h;
        let old = s
            .facts
            .members
            .iter()
            .find(|m| m.host_public_key == h)
            .ok_or_else(|| Error::new("operation_conflict"))?;
        require(
            text(r, "member")? == old.member
                && text(r, "person_public_key")? == old.person_public_key,
            "operation_conflict",
        )?;
        if old.person_public_key == "-" {
            check(text(r, "device_public_key")? == "-" && num(r, "scopes")? == 0)?;
        } else {
            check(key(text(r, "device_public_key")?) && (1..=15).contains(&num(r, "scopes")?))?;
        }
    }
    own_roster(c, s, host, rows)
}
pub(super) fn own_roster(c: &Connection, s: &Source, host: &str, rows: &[Value]) -> Result<()> {
    let own = rows
        .iter()
        .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(host))
        .ok_or_else(|| Error::new("forbidden"))?;
    let i = migration_local::approved_identity(c, &s.descriptor.network_id, host)?
        .ok_or_else(|| Error::new("review_required"))?;
    let reviewed =
        migration_local::validate_identity(&i, host).map_err(|_| Error::new("state_conflict"))?;
    let mut actual = migration_local::own_identity(c, s, host, num(object(own)?, "scopes")?)?;
    if actual["person_public_key"] != "-" && actual["device_public_key"] == "-" {
        require(i.secret.is_some(), "signer_unavailable")?;
        actual["device_public_key"] = reviewed["device_public_key"].clone();
    }
    require(*own == reviewed && *own == actual, "operation_conflict")
}
fn fixed(
    d: &Descriptor,
    kind: &str,
    payload: &Value,
    root: &str,
    format: &str,
) -> Result<FixedStatement> {
    FixedStatement::read(
        d,
        &bytes(
            &json!({"format":1,"kind":kind,"context_id":d.context_id(),"payload_base64":encode(&bytes(payload)?),"signatures":[{"role":"issuer","public_key":root,"format":format,"signature":"-"}]}),
        )?,
    )
}
fn templates(
    d: &Descriptor,
    p: &Value,
    format: &str,
    persons: &BTreeMap<String, String>,
    bans: &BTreeMap<migration::BanTarget, BTreeSet<String>>,
    pins: Option<(&str, &str)>,
) -> Result<Vec<FixedStatement>> {
    require(persons.len() + 2 <= 4096, "quota_exceeded")?;
    let o = object(p)?;
    let root = text(o, "legacy_root_public_key")?;
    let issued = text(o, "issued_at")?;
    let proposal = fixed(d, "migration_proposal", p, root, format)?;
    let proposal_id = pins.map_or(proposal.statement_id(), |p| p.0).to_owned();
    let initial = fixed(
        d,
        "root_state",
        &json!({"epoch":num(o,"legacy_epoch")?,"predecessors":[],"resolves":[],"migration_proposal_id":proposal_id,"root_public_key":root,"issued_at":issued,"retained_statement_ids":[]}),
        root,
        format,
    )?;
    let root_id = pins.map_or(initial.statement_id(), |p| p.1).to_owned();
    let mut values = vec![proposal, initial];
    for (person, member) in persons {
        values.push(fixed(d,"person_lease",&json!({"root_state_id":root_id,"operation_id":"-","sequence":1,"predecessors":[],"resolves":[],"retained_statement_ids":[],"subject":{"person_public_key":person,"host_public_key":"-","device_public_key":"-","member":member,"scopes":0},"issuer":{"kind":"root","person_public_key":"-"},"parents":[],"issued_at":issued,"not_before":issued,"not_after":actions::at(issued,7*86400)?}),root,format)?);
    }
    for row in array(o, "roster")? {
        let row = object(row)?;
        if text(row, "person_public_key")? != "-" {
            continue;
        }
        let host = text(row, "host_public_key")?;
        let payload = json!({"root_state_id":root_id,"operation_id":proposal_id,"sequence":1,"predecessors":[],"resolves":[],"retained_statement_ids":[],"subject":{"person_public_key":"-","host_public_key":host,"device_public_key":"-","member":text(row,"member")?,"scopes":0},"issuer":{"kind":"root","person_public_key":"-"},"parents":[],"issued_at":issued,"not_before":issued,"not_after":actions::at(issued,7*86400)?});
        values.push(FixedStatement::read(d,&bytes(&json!({"format":1,"kind":"host_lease","context_id":d.context_id(),"payload_base64":encode(&bytes(&payload)?),"signatures":[{"role":"host","public_key":host,"format":"ed25519","signature":"-"},{"role":"issuer","public_key":root,"format":format,"signature":"-"}]}))?)?);
    }
    // Shared persisted order: proposal, root, sorted P, sorted unbound H,
    // then sorted root bans. The other runtime reopens these exact slot IDs.
    // Device bans still require their original person on the separate path.
    for (kind, person, host, device) in bans.keys() {
        if !matches!(kind.as_str(), "person_remove" | "host_revoke") {
            continue;
        }
        let payload = json!({
            "root_state_id":root_id,
            "issuer":{"kind":"root","person_public_key":"-"},
            "parents":[],"issued_at":issued,
            "target":{"person_public_key":person,"host_public_key":host,
                "device_public_key":device,"statement_id":"-"},
            "kept_statement_ids":[],"ratifies":"-"
        });
        values.push(fixed(d, kind, &payload, root, format)?);
    }
    require(values.len() <= 4096, "quota_exceeded")?;
    Ok(values)
}
pub(super) fn root_seed(c: &Connection, network: &str, key: &str) -> Result<Option<[u8; 32]>> {
    let raw: Option<Vec<u8>> = c
        .query_row(
            "SELECT root_seed FROM networks WHERE id=?1",
            [network],
            |r| r.get(0),
        )
        .map_err(db)?;
    let Some(raw) = raw else { return Ok(None) };
    let seed: [u8; 32] = raw.try_into().map_err(|_| Error::new("state_conflict"))?;
    Ok((encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes()) == key).then_some(seed))
}
fn review(s: &Source, p: &Statement) -> Result<Value> {
    let o = &p.payload;
    Ok(
        json!({"stage":"proposal","network_id":s.descriptor.network_id,"proposal_id":p.id,"legacy_root_public_key":text(o,"legacy_root_public_key")?,"legacy_epoch":num(o,"legacy_epoch")?,"new_context_id":s.descriptor.context_id(),"roster":array(o,"roster")?,"source_catalog_sha256":text(o,"source_catalog_sha256")?,"source_state_sha256":text(o,"source_state_sha256")?,"prepared_catalog_sha256":"-","authority_warning":"Whole-network migration requires the current root, every known host and each original person's exact consent. Finite management parents expire within seven days. A later acknowledgment creates a durable fence with no timeout abort; this proposal creates no acknowledgment, admission or adoption."}),
    )
}
fn new(s: &Source, rows: &[Value], format: &str) -> Result<(Intent, MigrationRecord)> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::new("internal"))?;
    let p = json!({"proposal_nonce":encode(&nonce),"legacy_descriptor_base64":encode(&s.legacy_descriptor),"legacy_feature_id":s.feature,"legacy_epoch":s.facts.epoch,"legacy_root_public_key":s.facts.root_public_key,"source_catalog_sha256":hash(&s.catalog),"source_state_sha256":hash(&s.state_bytes),"new_descriptor":parse(&serde_json::to_vec(&s.descriptor).map_err(|_|Error::new("internal"))?,MAX_OBJECT)?,"roster":rows,"issued_at":s.time,"expires_at":actions::at(&s.time,86400)?});
    let source = migration::SourceState::read(&s.descriptor.network_id, &s.state_bytes)?;
    let bans = migration::inherited_bans(&source, &s.catalog, &s.facts)?;
    let ts = templates(&s.descriptor, &p, format, &people(&s.facts)?, &bans, None)?;
    let i = Intent {
        id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
        network_id: s.descriptor.network_id.clone(),
        context_id: s.descriptor.context_id(),
        kind: "migration".into(),
        secret: None,
        record: Record {
            format: 1,
            operation_id: ts[0].statement_id().into(),
            approved: false,
            approved_at: "-".into(),
            review_base64: encode(&bytes(&review(s, ts[0].typed())?)?),
            provider: Provider {
                kind: "root".into(),
                signer_public_key: s.facts.root_public_key.clone(),
                signature_format: format.into(),
                lease_id: "-".into(),
            },
            root_state_id: ts[1].statement_id().into(),
            person_public_key: "-".into(),
            host_public_key: "-".into(),
            device_public_key: "-".into(),
            scopes: 8,
            not_after: "-".into(),
            created_at: s.time.clone(),
            expires_at: actions::at(&s.time, 86400)?,
            templates: ts
                .iter()
                .enumerate()
                .map(|(n, t)| Template {
                    slot_id: n as u64 + 1,
                    object_type: t.typed().kind.clone(),
                    template_base64: encode(t.bytes()),
                })
                .collect(),
            signatures: Vec::new(),
            completed: false,
            terminal: "-".into(),
            result_base64: "-".into(),
        },
    };
    let r = MigrationRecord {
        format: 1,
        context_id: i.context_id.clone(),
        state: "needs_approvals".into(),
        proposal_base64: "-".into(),
        source_catalog_base64: encode(&s.catalog),
        source_state_base64: encode(&s.state_bytes),
        prepared_catalog_base64: "-".into(),
        initial_root_state_base64: "-".into(),
        acknowledgments_base64: Vec::new(),
        commit_base64: "-".into(),
        migration_base64: "-".into(),
        local_acknowledgment_base64: "-".into(),
        root_intent_ids: vec![i.id.clone()],
        local_ack_intent_id: "-".into(),
        approved: false,
        fenced: false,
        publication_started: false,
    };
    Ok((i, r))
}
fn descriptor(i: &Intent) -> Result<Descriptor> {
    let t = i
        .record
        .templates
        .first()
        .ok_or_else(|| Error::new("state_conflict"))?;
    let outer = parse(&b64(&t.template_base64, MAX_OBJECT)?, MAX_OBJECT)?;
    let payload = parse(
        &b64(text(object(&outer)?, "payload_base64")?, MAX_PAYLOAD)?,
        MAX_PAYLOAD,
    )?;
    Descriptor::from_value(
        payload
            .get("new_descriptor")
            .ok_or_else(|| Error::new("invalid"))?,
    )
}
fn validate(i: &Intent, r: &MigrationRecord) -> Result<(Descriptor, Vec<FixedStatement>, Value)> {
    i.shape()?;
    let d = descriptor(i)?;
    let record = &i.record;
    check(
        i.kind == "migration"
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && r.context_id == i.context_id
            && record.provider.kind == "root"
            && record.provider.lease_id == "-"
            && record.person_public_key == "-"
            && record.host_public_key == "-"
            && record.device_public_key == "-"
            && record.scopes == 8
            && record.not_after == "-"
            && i.secret.is_none()
            && record.terminal == "-"
            && record.result_base64 == "-"
            && record.templates.len() >= 2,
    )?;
    let ts = i.assembled(&d)?;
    let p = &ts[0].typed().payload;
    check(
        ts[0].typed().kind == "migration_proposal"
            && ts[0].statement_id() == record.operation_id
            && record.root_state_id == ts[1].statement_id()
            && record.created_at == text(p, "issued_at")?
            && record.expires_at == text(p, "expires_at")?
            && record.provider.signer_public_key == text(p, "legacy_root_public_key")?,
    )?;
    let source = b64(&r.source_catalog_base64, 512 << 10)?;
    let state = b64(&r.source_state_base64, MAX_PAYLOAD)?;
    check(
        hash(&source) == text(p, "source_catalog_sha256")?
            && hash(&state) == text(p, "source_state_sha256")?,
    )?;
    let (source_state, facts) = migration::source_snapshot(
        SourceContext {
            descriptor: &d,
            legacy_descriptor: &b64(text(p, "legacy_descriptor_base64")?, MAX_OBJECT)?,
            epoch: num(p, "legacy_epoch")?,
            feature: text(p, "legacy_feature_id")?,
            root: text(p, "legacy_root_public_key")?,
            now: text(p, "issued_at")?,
        },
        &source,
        &state,
    )?;
    let bans = migration::inherited_bans(&source_state, &source, &facts)?;
    let expected = templates(
        &d,
        &Value::Object(p.clone()),
        &record.provider.signature_format,
        &people(&facts)?,
        &bans,
        Some((ts[0].statement_id(), ts[1].statement_id())),
    )?;
    check(ts.len() == expected.len())?;
    for (n, (a, b)) in ts.iter().zip(expected.iter()).enumerate() {
        check(
            a.typed().kind == b.typed().kind
                && a.typed().payload == b.typed().payload
                && record.templates[n].object_type == a.typed().kind
                && a.typed().signatures.len() == b.typed().signatures.len(),
        )?;
        let sig = a.typed().signer("issuer")?;
        check(
            sig.public_key == record.provider.signer_public_key
                && sig.format == record.provider.signature_format,
        )?;
        for (role, sig) in &a.typed().signatures {
            let expected = b.typed().signer(role)?;
            check(sig.public_key == expected.public_key && sig.format == expected.format)?;
        }
    }
    check(record.completed == ts.iter().all(|t| t.pending().is_empty()))?;
    for (n, encoded) in [&r.proposal_base64, &r.initial_root_state_base64]
        .iter()
        .enumerate()
    {
        if *encoded != "-" {
            check(ts[n].pending().is_empty() && b64(encoded, MAX_OBJECT)? == ts[n].bytes())?;
        }
    }
    let v = parse(&b64(&record.review_base64, MAX_OBJECT)?, MAX_OBJECT)?;
    let o = object(&v)?;
    fields(
        o,
        "stage network_id proposal_id legacy_root_public_key legacy_epoch new_context_id roster source_catalog_sha256 source_state_sha256 prepared_catalog_sha256 authority_warning",
    )?;
    check(
        text(o, "stage")? == "proposal"
            && text(o, "network_id")? == i.network_id
            && text(o, "proposal_id")? == record.operation_id
            && text(o, "legacy_root_public_key")? == record.provider.signer_public_key
            && num(o, "legacy_epoch")? == num(p, "legacy_epoch")?
            && text(o, "new_context_id")? == i.context_id
            && array(o, "roster")? == array(p, "roster")?
            && text(o, "source_catalog_sha256")? == hash(&source)
            && text(o, "source_state_sha256")? == hash(&state)
            && text(o, "prepared_catalog_sha256")? == "-"
            && !text(o, "authority_warning")?.is_empty()
            && text(o, "authority_warning")?.len() <= 1024,
    )?;
    Ok((d, ts, v))
}
fn current(
    c: &Connection,
    s: &Source,
    host: &str,
    i: &Intent,
    r: &MigrationRecord,
) -> Result<Vec<FixedStatement>> {
    let (d, ts, _) = validate(i, r).map_err(|_| Error::new("state_conflict"))?;
    let p = &ts[0].typed().payload;
    require(
        d.context_id() == s.descriptor.context_id()
            && s.facts.root_public_key == text(p, "legacy_root_public_key")?
            && s.facts.epoch == num(p, "legacy_epoch")?
            && s.feature == text(p, "legacy_feature_id")?
            && migration::legacy_descriptor(&s.legacy_descriptor)?
                == migration::legacy_descriptor(&b64(
                    text(p, "legacy_descriptor_base64")?,
                    MAX_OBJECT,
                )?)?
            && migration::legacy_objects(&d.network_id, &s.catalog)?
                == migration::legacy_objects(
                    &d.network_id,
                    &b64(&r.source_catalog_base64, 512 << 10)?,
                )?
            && migration::SourceState::read(&d.network_id, &s.state_bytes)?
                == migration::SourceState::read(
                    &d.network_id,
                    &b64(&r.source_state_base64, MAX_PAYLOAD)?,
                )?,
        "state_conflict",
    )?;
    require(s.time >= i.record.created_at, "clock_rollback")?;
    require(s.time < i.record.expires_at, "expired")?;
    roster(c, s, host, array(p, "roster")?)?;
    Ok(ts)
}
fn group(c: &Connection, network: &str, r: &MigrationRecord) -> Result<Intent> {
    let mut found = None;
    for id in &r.root_intent_ids {
        let i = Intent::load(c, id)?;
        require(
            i.network_id == network && i.context_id == r.context_id,
            "state_conflict",
        )?;
        if i.record
            .templates
            .first()
            .is_some_and(|t| t.object_type == "migration_proposal")
        {
            require(found.is_none(), "state_conflict")?;
            found = Some(i);
        }
    }
    found.ok_or_else(|| Error::new("recovery_required"))
}
fn catalog(d: &Descriptor, ts: &[FixedStatement], budget: bool) -> Result<Vec<u8>> {
    let mut objects = BTreeMap::new();
    for t in ts {
        if !budget && !t.pending().is_empty() {
            continue;
        }
        let raw = if budget {
            t.budget_bytes()?
        } else {
            t.bytes().to_vec()
        };
        let kind = &t.typed().kind;
        let id = proof_id(kind, &raw);
        objects.insert(
            id.clone(),
            json!({"id":id,"kind":kind,"body_base64":encode(&raw)}),
        );
    }
    let raw = bytes(
        &json!({"format":1,"context_id":d.context_id(),"objects":objects.into_values().collect::<Vec<_>>()}),
    )?;
    require(raw.len() <= MAX_CATALOG, "quota_exceeded")?;
    if !budget {
        Catalog::read(d, &raw)?;
    }
    Ok(raw)
}
fn budget(r: &MigrationRecord, proposal: &[u8], prepared: &[u8]) -> Result<()> {
    let mut candidate = r.clone();
    candidate.proposal_base64 = encode(proposal);
    candidate.prepared_catalog_base64 = encode(prepared);
    super::migration_prefix::Prefix::complete_body(&candidate)?;
    Ok(())
}
fn signing(i: &Intent, ts: &[FixedStatement]) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    if !i.record.approved {
        return Ok(result);
    }
    for (n, t) in ts.iter().enumerate() {
        for s in t.pending() {
            if s.role == "host" && t.typed().signer("issuer")?.signature == "-" {
                continue;
            }
            result.push(json!({"intent_id":i.id,"slot_id":n+1,"object_type":s.object_type,"object_id":s.statement_id,"role":s.role,"public_key":s.public_key,"format":s.signature_format,"template_base64":encode(t.bytes()),"message_base64":s.message_base64}));
            if result.len() == 16 {
                return Ok(result);
            }
        }
    }
    Ok(result)
}
fn view(id: &str, r: &MigrationRecord, ts: &[FixedStatement]) -> Result<Value> {
    if r.proposal_base64 != "-" {
        let d = Descriptor::from_value(
            ts[0]
                .typed()
                .payload
                .get("new_descriptor")
                .ok_or_else(|| Error::new("state_conflict"))?,
        )?;
        let prefix = super::migration_prefix::Prefix::read(&d, r)?;
        require(prefix.proposal.id == id, "state_conflict")?;
        return prefix.view(&d, r);
    }
    // Never turn a partially supported later migration phase into a positive
    // preparation view. Its own controller will validate those exact records.
    require(
        r.state == "needs_approvals"
            && !r.fenced
            && !r.approved
            && r.acknowledgments_base64.is_empty()
            && r.local_acknowledgment_base64 == "-"
            && r.local_ack_intent_id == "-"
            && r.commit_base64 == "-"
            && r.migration_base64 == "-",
        "recovery_required",
    )?;
    let p = &ts[0].typed().payload;
    let prepared = if r.prepared_catalog_base64 == "-" {
        "-".into()
    } else {
        let raw = b64(&r.prepared_catalog_base64, MAX_CATALOG)?;
        let d = Descriptor::from_value(
            p.get("new_descriptor")
                .ok_or_else(|| Error::new("state_conflict"))?,
        )?;
        let c = Catalog::read(&d, &raw)?;
        for t in ts.iter().filter(|t| t.pending().is_empty()) {
            require(
                c.proofs
                    .get(&proof_id(&t.typed().kind, t.bytes()))
                    .is_some_and(|p| p.body == t.bytes()),
                "state_conflict",
            )?;
        }
        hash(&raw)
    };
    let root = if r.initial_root_state_base64 == "-" {
        "-"
    } else {
        ts[1].statement_id()
    };
    let missing = array(p, "roster")?
        .iter()
        .map(|v| text(object(v)?, "host_public_key").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"network_id":Descriptor::from_value(p.get("new_descriptor").ok_or_else(||Error::new("state_conflict"))?)?.network_id,"proposal_id":id,"context_id":r.context_id,"state":r.state,"source_catalog_sha256":text(p,"source_catalog_sha256")?,"source_state_sha256":text(p,"source_state_sha256")?,"prepared_catalog_sha256":prepared,"root_state_id":root,"local_acknowledgment_id":"-","root_commit_id":"-","missing_host_keys":missing,"required_proof_ids":[],"approved":r.approved,"fenced":r.fenced,"expires_at":text(p,"expires_at")?}),
    )
}
pub(super) fn status(c: &Connection, s: &Source) -> Result<Vec<u8>> {
    let Some((id, r)) = load(c, &s.descriptor.network_id)? else {
        return bytes(&migration_local::empty_view(&s.descriptor.network_id));
    };
    let i = group(c, &s.descriptor.network_id, &r)?;
    let (d, ts, _) = validate(&i, &r).map_err(|_| Error::new("state_conflict"))?;
    require(
        d.context_id() == s.descriptor.context_id() && id == i.record.operation_id,
        "state_conflict",
    )?;
    if r.proposal_base64 != "-" {
        super::migration_prefix::Prefix::read(&d, &r)?.known(s, &r)?;
    }
    bytes(&view(&id, &r, &ts)?)
}
fn result(store: &Store, network: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let (id, r) = load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
    let i = group(&tx, network, &r)?;
    let (_, ts, review) = validate(&i, &r).map_err(|_| Error::new("state_conflict"))?;
    require(id == i.record.operation_id, "state_conflict")?;
    bytes(
        &json!({"migration":view(&id,&r,&ts)?,"review":review,"signing_requests":signing(&i,&ts)?}),
    )
}
fn capacity(c: &Connection) -> Result<()> {
    let total: i64 = c
        .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
        .map_err(db)?;
    let open:i64=c.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
    require(total < 4096 && open < 64, "quota_exceeded")
}
pub(crate) fn prepare(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "roster signature_format approve")?;
    let rows = array(input, "roster")?;
    let format = text(input, "signature_format")?;
    check(matches!(format, "auto" | "ed25519" | "sshsig"))?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let host = store.identity().public_key;
    let (operation, fresh, approval) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let s = Source::load(store, &tx, network)?;
        roster(&tx, &s, &host, rows)?;
        let format = if format == "auto" || format == "ed25519" {
            require(
                root_seed(&tx, network, &s.facts.root_public_key)?.is_some(),
                "signer_unavailable",
            )?;
            "ed25519"
        } else {
            format
        };
        let old = load(&tx, network)?;
        let fresh = old.is_none();
        let (mut i, r) = if let Some((id, r)) = old {
            require(!r.fenced && r.state != "adopted", "operation_conflict")?;
            let i = group(&tx, network, &r)?;
            let (_, ts, _) = validate(&i, &r).map_err(|_| Error::new("state_conflict"))?;
            require(
                id == i.record.operation_id
                    && array(&ts[0].typed().payload, "roster")? == rows
                    && i.record.provider.signature_format == format,
                "operation_conflict",
            )?;
            (i, r)
        } else {
            capacity(&tx)?;
            new(&s, rows, format)?
        };
        let ts = current(&tx, &s, &host, &i, &r)?;
        budget(
            &r,
            &ts[0].budget_bytes()?,
            &catalog(&s.descriptor, &ts, true)?,
        )?;
        let approval = approve && !i.record.approved;
        let latest = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        require(latest < i.record.expires_at, "expired")?;
        decision_clock(&latest, &s.time)?;
        if approval {
            i.record.approved = true;
            i.record.approved_at = latest.clone();
        }
        i.save(&tx)?;
        save(&tx, network, &i.record.operation_id, &r)?;
        creation::remember_clock(&tx, network, &latest)?;
        let operation = i.record.operation_id.clone();
        tx.commit().map_err(db)?;
        (operation, fresh, approval)
    };
    if fresh {
        controls::barrier(store, "dec.intent.after_commit", &operation)?;
        controls::barrier(store, "dec.migration_proposal.after_commit", &operation)?;
    }
    if approval {
        controls::barrier(store, "dec.approval.after_commit", &operation)?;
    }
    if approve {
        advance(store, network, None)
    } else {
        result(store, network)
    }
}
fn add(i: &mut Intent, slot: u64, role: &str, signature: &str) -> Result<bool> {
    if let Some(old) = i
        .record
        .signatures
        .iter()
        .find(|s| s.slot_id == slot && s.role == role)
    {
        require(old.signature == signature, "operation_conflict")?;
        return Ok(false);
    }
    i.record.signatures.push(Filled {
        slot_id: slot,
        role: role.into(),
        signature: signature.into(),
    });
    i.record
        .signatures
        .sort_by(|a, b| (a.slot_id, &a.role).cmp(&(b.slot_id, &b.role)));
    Ok(true)
}
fn advance(store: &Store, network: &str, batch: Option<&Obj>) -> Result<Vec<u8>> {
    let host = store.identity().public_key;
    let (operation, changed) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let s = Source::load(store, &tx, network)?;
        let (id, mut r) = load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
        let mut i = group(&tx, network, &r)?;
        require(
            id == i.record.operation_id && !r.fenced,
            "operation_conflict",
        )?;
        let ts = current(&tx, &s, &host, &i, &r)?;
        require(i.record.approved, "review_required")?;
        budget(
            &r,
            &ts[0].budget_bytes()?,
            &catalog(&s.descriptor, &ts, true)?,
        )?;
        let mut changed = false;
        if let Some(batch) = batch {
            fields(batch, "intent_id signatures")?;
            require(text(batch, "intent_id")? == i.id, "operation_conflict")?;
            let entries = array(batch, "signatures")?;
            check(!entries.is_empty() && entries.len() <= 16)?;
            let mut previous = None;
            for entry in entries {
                let e = object(entry)?;
                fields(e, "slot_id role signature")?;
                let slot = num(e, "slot_id")?;
                let role = text(e, "role")?;
                let sig = text(e, "signature")?;
                check(
                    slot > 0
                        && slot <= ts.len() as u64
                        && matches!(role, "issuer" | "host")
                        && sig != "-"
                        && previous.is_none_or(|p| p < (slot, role)),
                )?;
                previous = Some((slot, role));
                if role == "host" {
                    require(
                        ts[slot as usize - 1].typed().signer("issuer")?.signature != "-",
                        "review_required",
                    )?;
                }
                ts[slot as usize - 1].fill(&s.descriptor, role, sig)?;
                changed |= add(&mut i, slot, role, sig)?;
            }
        }
        // Only an actually held root seed matching the fixed role can sign.
        // Explicit external SSH slots remain usable without daemon key access.
        if let Some(seed) = root_seed(&tx, network, &i.record.provider.signer_public_key)? {
            for (n, t) in ts.iter().enumerate() {
                for slot in t.pending() {
                    if slot.role != "issuer"
                        || slot.public_key != i.record.provider.signer_public_key
                    {
                        continue;
                    }
                    if i.record
                        .signatures
                        .iter()
                        .any(|s| s.slot_id == n as u64 + 1 && s.role == slot.role)
                    {
                        continue;
                    }
                    let message = b64(&slot.message_base64, 4096)?;
                    let sig = if slot.signature_format == "ed25519" {
                        encode(&SigningKey::from_bytes(&seed).sign(&message).to_bytes())
                    } else {
                        crate::persons::PersonSigner::File(SigningKey::from_bytes(&seed))
                            .sign(
                                &std::str::from_utf8(&message)
                                    .map_err(|_| Error::new("invalid"))?
                                    .split('\n')
                                    .collect::<Vec<_>>(),
                            )
                            .map_err(|_| Error::new("signer_unavailable"))?
                    };
                    t.fill(&s.descriptor, &slot.role, &sig)?;
                    changed |= add(&mut i, n as u64 + 1, &slot.role, &sig)?;
                }
            }
        }
        // A target's exact complete H can return through the public evidence
        // handoff. Only fill our fixed template when the original enclosing
        // bytes match; an arbitrary alias never rewrites a typed template.
        if r.prepared_catalog_base64 != "-" {
            let prepared = Catalog::read_prepared(
                &s.descriptor,
                &b64(&r.prepared_catalog_base64, MAX_OBJECT)?,
            )?;
            for (n, t) in i.assembled(&s.descriptor)?.iter().enumerate() {
                if t.typed().kind != "host_lease"
                    || t.typed().signer("host")?.signature != "-"
                    || t.typed().signer("issuer")?.signature == "-"
                {
                    continue;
                }
                if let Some(aliases) = prepared.aliases.get(t.statement_id()) {
                    for alias in aliases {
                        let signature = &alias.signer("host")?.signature;
                        let filled = t.fill(&s.descriptor, "host", signature)?;
                        if filled.bytes() == alias.body {
                            changed |= add(&mut i, n as u64 + 1, "host", signature)?;
                            break;
                        }
                    }
                }
            }
        }
        let ts = i.assembled(&s.descriptor)?;
        i.record.completed = ts.iter().all(|t| t.pending().is_empty());
        if ts[0].pending().is_empty() {
            r.proposal_base64 = encode(ts[0].bytes());
        }
        if ts[1].pending().is_empty() {
            r.initial_root_state_base64 = encode(ts[1].bytes());
        }
        if ts[0].pending().is_empty() && ts[1].pending().is_empty() {
            let own = Catalog::read(&s.descriptor, &catalog(&s.descriptor, &ts, false)?)?;
            let raw = if r.prepared_catalog_base64 == "-" {
                own.bytes
            } else {
                let old = Catalog::read(
                    &s.descriptor,
                    &b64(&r.prepared_catalog_base64, MAX_CATALOG)?,
                )?;
                // Keep the existing exact wrapper when it already contains
                // our completed objects. Any ACK binds those original bytes,
                // including a wrapper first written by the other runtime.
                if own.proofs.iter().all(|(id, p)| {
                    old.proofs
                        .get(id)
                        .is_some_and(|o| o.kind == p.kind && o.body == p.body)
                }) {
                    old.bytes
                } else {
                    require(
                        r.acknowledgments_base64.is_empty()
                            && r.local_acknowledgment_base64 == "-"
                            && r.commit_base64 == "-"
                            && r.migration_base64 == "-",
                        "operation_conflict",
                    )?;
                    Catalog::union(&s.descriptor, &old, &own)?.bytes
                }
            };
            budget(&r, ts[0].bytes(), &raw)?;
            r.prepared_catalog_base64 = encode(&raw);
        }
        let latest = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        require(latest < i.record.expires_at, "expired")?;
        decision_clock(&latest, &s.time)?;
        i.save(&tx)?;
        save(&tx, network, &id, &r)?;
        creation::remember_clock(&tx, network, &latest)?;
        tx.commit().map_err(db)?;
        (id, changed)
    };
    if changed {
        controls::barrier(store, "dec.signature.after_commit", &operation)?;
    }
    result(store, network)
}
pub(crate) fn signed(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    let copies = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        super::migration_device_bans::owns(&c, network, text(input, "intent_id")?)?
    };
    if copies {
        return super::migration_device_bans::signed(store, network, input);
    }
    let owned = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        super::migration_commit::owns(&c, network, text(input, "intent_id")?)?
    };
    if owned {
        return super::migration_commit::signed(store, network, input);
    }
    advance(store, network, Some(input))
}
pub(crate) fn resume(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "")?;
    if let Some(copies) = super::migration_device_bans::resume(store, network)? {
        return Ok(copies);
    }
    advance(store, network, None)
}
pub(crate) fn evidence(store: &Store, network: &str) -> Result<Vec<u8>> {
    super::migration_evidence::export(store, network)
}
