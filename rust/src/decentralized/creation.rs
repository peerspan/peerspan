//! Durable owner-local genesis. Approval and fixed bytes precede owned signing;
//! external original keys enter only through verified typed signature slots.
use super::{
    codec::*,
    controls,
    intents::{Filled, Intent, Provider, Record, Template},
    statement::{Descriptor, signature_message},
    storage::{OwnIdentity, Snapshot, check_outbox_capacity},
    template::FixedStatement,
    views,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const KINDS: [&str; 6] = [
    "root_state",
    "admin_lease",
    "person_lease",
    "host_lease",
    "binding_lease",
    "policy",
];
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
fn at(time: &str, seconds: i64) -> Result<String> {
    Ok((stamp(time)? + chrono::TimeDelta::seconds(seconds))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string())
}
fn random(prefix: &str, len: usize) -> Result<String> {
    let mut b = vec![0; len];
    getrandom::fill(&mut b).map_err(|_| Error::new("internal"))?;
    Ok(format!("{prefix}{}", hex::encode(b)))
}
fn review(intent: &Intent) -> Result<Value> {
    parse(&b64(&intent.record.review_base64, 1 << 20)?, 1 << 20)
}
pub(super) fn decision(connection: &Connection, network: &str, now: &str) -> Result<String> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT record FROM dec_clock WHERE network_id=?1",
            [network],
            |r| r.get(0),
        )
        .optional()
        .map_err(db)?;
    let guard = raw
        .map(|raw| -> Result<String> {
            let v = parse(raw.as_bytes(), 32 << 20)?;
            let o = object(&v)?;
            fields(o, "format largest_local_time")?;
            version(o)?;
            Ok(text(o, "largest_local_time")?.into())
        })
        .transpose()?;
    decision_clock(now, guard.as_deref().unwrap_or("-"))
}
pub(super) fn remember_clock(connection: &Connection, network: &str, time: &str) -> Result<()> {
    let record = json!({"format":1,"largest_local_time":time});
    connection.execute("INSERT INTO dec_clock(network_id,record) VALUES(?1,?2) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record",rusqlite::params![network,record.to_string()]).map_err(db)?;
    Ok(())
}
fn payload(
    index: usize,
    d: &Descriptor,
    identity: (&str, &str),
    member: &str,
    time: &str,
    ids: &[String],
    body: Option<&str>,
) -> Result<Value> {
    let (person, host) = identity;
    if index == 0 {
        return Ok(
            json!({"epoch":0,"predecessors":[],"resolves":[],"migration_proposal_id":"-","root_public_key":d.genesis_root_public_key,"issued_at":time,"retained_statement_ids":[]}),
        );
    }
    let person_issuer = index >= 4;
    let parents = match index {
        4 => {
            json!([{"role":"issuer_person","id":ids[2]},{"role":"subject_host","id":ids[3]},{"role":"subject_person","id":ids[2]}])
        }
        5 => json!([{"role":"issuer_person","id":ids[2]}]),
        _ => json!([]),
    };
    let mut value = json!({"root_state_id":ids[0],"operation_id":"-","sequence":1,"predecessors":[],"resolves":[],"issuer":{"kind":if person_issuer {"person"} else {"root"},"person_public_key":if person_issuer {person} else {"-"}},"parents":parents,"issued_at":time,"not_before":time,"not_after":at(time,if index==5 {86400} else {604800})?});
    if index == 5 {
        let expected = json!({"format":2,"network_id":d.network_id,"person_public_key":person,"version":1,"issued_at":time,"valid_until":at(time,86400)?,"rules":[],"capability_rules":[],"trusted_hosts":[],"edits":[]});
        let actual = if let Some(encoded) = body {
            check(parse(&b64(encoded, MAX_PAYLOAD)?, MAX_PAYLOAD)? == expected)?;
            encoded.to_owned()
        } else {
            encode(&bytes(&expected)?)
        };
        value["body_base64"] = Value::from(actual);
    } else {
        value["retained_statement_ids"] = json!([]);
        value["subject"] = json!({"person_public_key":if index==3 {"-"} else {person},"host_public_key":if index>=3 {host} else {"-"},"device_public_key":"-","member":if index==1 || index==4 {"-"} else {member},"scopes":match index {1=>8,4=>2,_=>0}});
    }
    Ok(value)
}
fn signers(index: usize, d: &Descriptor, person: &str, host: &str) -> Value {
    let issuer = if index >= 4 {
        person
    } else {
        &d.genesis_root_public_key
    };
    let format = if index >= 4 { "sshsig" } else { "ed25519" };
    let mut entries = Vec::new();
    if index == 3 || index == 4 {
        entries.push(json!({"role":"host","public_key":host,"format":"ed25519","signature":"-"}));
    }
    entries.push(json!({"role":"issuer","public_key":issuer,"format":format,"signature":"-"}));
    Value::Array(entries)
}
fn templates(
    d: &Descriptor,
    person: &str,
    host: &str,
    member: &str,
    time: &str,
) -> Result<Vec<Template>> {
    let mut output = Vec::new();
    let mut ids = Vec::new();
    for (index, kind) in KINDS.iter().enumerate() {
        let p = payload(index, d, (person, host), member, time, &ids, None)?;
        let raw = bytes(
            &json!({"format":1,"kind":kind,"context_id":d.context_id(),"payload_base64":encode(&bytes(&p)?),"signatures":signers(index,d,person,host)}),
        )?;
        let fixed = FixedStatement::read(d, &raw)?;
        ids.push(fixed.statement_id().into());
        output.push(Template {
            slot_id: index as u64 + 1,
            object_type: (*kind).into(),
            template_base64: encode(&raw),
        });
    }
    Ok(output)
}
fn validate(intent: &Intent, host: &str) -> Result<Descriptor> {
    let r = &intent.record;
    let value = review(intent)?;
    let view = object(&value)?;
    fields(
        view,
        "name member descriptor root_state_id person_public_key host_public_key not_after authority_warning",
    )?;
    let d = Descriptor::from_value(
        view.get("descriptor")
            .ok_or_else(|| Error::new("invalid"))?,
    )?;
    let name = text(view, "name")?;
    let member = text(view, "member")?;
    label(member)?;
    check(
        d.name == name
            && intent.kind == "create"
            && intent.network_id == d.network_id
            && intent.context_id == d.context_id()
            && ident(&r.operation_id, "create_")
            && r.host_public_key == host
            && key(&r.person_public_key)
            && r.device_public_key == "-"
            && r.scopes == 15
            && r.templates.len() == 6,
    )?;
    check(
        text(view, "person_public_key")? == r.person_public_key
            && text(view, "host_public_key")? == host
            && text(view, "not_after")? == r.not_after
            && r.not_after == at(&r.created_at, 604800)?
            && r.expires_at == at(&r.created_at, 300)?,
    )?;
    check(
        text(view, "authority_warning")?.len() <= 1024
            && r.provider.kind == "original"
            && r.provider.signer_public_key == r.person_public_key
            && r.provider.signature_format == "sshsig"
            && r.provider.lease_id == "-",
    )?;
    let mut ids = Vec::new();
    for (index, template) in r.templates.iter().enumerate() {
        check(template.object_type == KINDS[index])?;
        let fixed = FixedStatement::read(&d, &b64(&template.template_base64, MAX_OBJECT)?)?;
        let s = fixed.typed();
        let body = s.payload.get("body_base64").and_then(Value::as_str);
        check(
            Value::Object(s.payload.clone())
                == payload(
                    index,
                    &d,
                    (&r.person_public_key, host),
                    member,
                    &r.created_at,
                    &ids,
                    body,
                )?,
        )?;
        let expected: Vec<super::SignatureEntry> =
            serde_json::from_value(signers(index, &d, &r.person_public_key, host))
                .map_err(|_| Error::new("invalid"))?;
        check(
            s.signatures.len() == expected.len()
                && expected.iter().all(|entry| {
                    s.signatures.get(&entry.role).is_some_and(|actual| {
                        actual.role == entry.role
                            && actual.public_key == entry.public_key
                            && actual.format == entry.format
                            && actual.signature == "-"
                    })
                }),
        )?;
        ids.push(s.id.clone());
    }
    check(r.root_state_id == ids[0] && text(view, "root_state_id")? == ids[0])?;
    let assembled = intent.assembled(&d)?;
    check(r.completed == assembled.iter().all(|t| t.pending().is_empty()))?;
    if r.terminal == "applied" {
        validate_result(intent, &d, &value)?;
    } else {
        check(r.terminal == "-" && r.result_base64 == "-")?;
        let seed: &[u8; 32] = intent
            .secret
            .as_deref()
            .ok_or_else(|| Error::new("state_conflict"))?
            .try_into()
            .map_err(|_| Error::new("state_conflict"))?;
        check(
            encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
                == d.genesis_root_public_key,
        )?;
    }
    Ok(d)
}
fn validate_result(intent: &Intent, d: &Descriptor, review: &Value) -> Result<()> {
    let value = parse(&b64(&intent.record.result_base64, 32 << 20)?, 32 << 20)?;
    let o = object(&value)?;
    fields(o, "creation_id review signing_requests network committed")?;
    check(
        text(o, "creation_id")? == intent.record.operation_id
            && o.get("review") == Some(review)
            && array(o, "signing_requests")?.is_empty()
            && o.get("committed").and_then(Value::as_bool) == Some(true),
    )?;
    let n = object(o.get("network").ok_or_else(|| Error::new("invalid"))?)?;
    fields(
        n,
        "id name mode context_id genesis_root_public_key root_state_id root_public_key root_epoch member host_public_key person_public_key provider provider_state authority delivery created_at",
    )?;
    let r = object(review)?;
    check(
        text(n, "id")? == d.network_id
            && text(n, "name")? == d.name
            && text(n, "mode")? == "decentralized"
            && text(n, "context_id")? == d.context_id()
            && text(n, "genesis_root_public_key")? == d.genesis_root_public_key
            && text(n, "root_state_id")? == intent.record.root_state_id
            && text(n, "root_public_key")? == d.genesis_root_public_key
            && num(n, "root_epoch")? == 0
            && text(n, "member")? == text(r, "member")?
            && text(n, "host_public_key")? == intent.record.host_public_key
            && text(n, "person_public_key")? == intent.record.person_public_key,
    )?;
    let applied = text(n, "created_at")?;
    stamp(applied)?;
    check(
        intent.record.created_at.as_str() <= applied
            && intent.record.approved_at.as_str() <= applied,
    )?;
    // Validate this historical response at its retained application time,
    // never at today's time or the earlier unsigned preview deadline.
    let projected = super::state::Projection::genesis(
        d,
        &completed_catalog(intent, d)?,
        applied,
        &intent.record.person_public_key,
        &intent.record.host_public_key,
    )?;
    let provider = projected.provider_potential(
        &intent.record.person_public_key,
        &intent.record.host_public_key,
        None,
    )?;
    check(n.get("provider") == Some(&provider))?;
    let member = projected.member_for(
        &intent.record.host_public_key,
        &intent.record.person_public_key,
    )?;
    check(
        n.get("authority")
            == Some(
                &json!({"state":"usable","not_after":member.not_after,"required_ids":[],"conflict_ids":[]}),
            ),
    )?;
    check(n.get("delivery") == Some(&json!({"pending_proof_ids":[],"peer_errors":[]})))?;
    let state = object(
        n.get("provider_state")
            .ok_or_else(|| Error::new("invalid"))?,
    )?;
    fields(state, "state code error required_ids")?;
    check(array(state, "required_ids")?.is_empty())?;
    match text(state, "state")? {
        "available" => check(text(state, "code")? == "-" && text(state, "error")? == "-")?,
        "unavailable" => check(
            text(state, "code")? == "signer_unavailable"
                && !text(state, "error")?.is_empty()
                && text(state, "error")?.len() <= 1024,
        )?,
        _ => return Err(Error::new("invalid")),
    }
    check(intent.secret.is_none())
}
fn completed_catalog(intent: &Intent, d: &Descriptor) -> Result<Vec<u8>> {
    let mut objects = BTreeMap::new();
    for template in intent.assembled(d)? {
        let statement = template
            .signed(d)?
            .ok_or_else(|| Error::new("state_conflict"))?;
        objects.insert(statement.proof_id.clone(),json!({"id":statement.proof_id,"kind":statement.kind,"body_base64":encode(&statement.body)}));
    }
    bytes(
        &json!({"format":1,"context_id":d.context_id(),"objects":objects.into_values().collect::<Vec<_>>()}),
    )
}
fn load_operation(connection: &Connection, id: &str, host: &str) -> Result<(Intent, Descriptor)> {
    check(ident(id, "create_"))?;
    let mut query = connection
        .prepare("SELECT intent_id FROM dec_intents WHERE kind='create' ORDER BY intent_id")
        .map_err(db)?;
    let rows = query.query_map([], |r| r.get::<_, String>(0)).map_err(db)?;
    let mut found = None;
    for row in rows {
        let value = Intent::load(connection, &row.map_err(db)?)?;
        if value.record.operation_id == id {
            require(found.is_none(), "state_conflict")?;
            let d = validate(&value, host).map_err(|_| Error::new("state_conflict"))?;
            found = Some((value, d));
        }
    }
    found.ok_or_else(|| Error::new("not_found"))
}
fn ready(templates: &[FixedStatement], index: usize) -> Result<bool> {
    let s = templates[index].typed();
    let mut deps: BTreeSet<String> = if s.payload.contains_key("parents") {
        s.parents()?.into_values().collect()
    } else {
        BTreeSet::new()
    };
    if let Some(root) = s.payload.get("root_state_id").and_then(Value::as_str) {
        deps.insert(root.into());
    }
    for dep in deps {
        if let Some(template) = templates.iter().find(|t| t.statement_id() == dep) {
            if !template.pending().is_empty() {
                return Ok(false);
            }
        } else {
            return Err(Error::missing(&dep));
        }
    }
    Ok(true)
}
fn signing_requests(intent: &Intent, d: &Descriptor) -> Result<Vec<Value>> {
    if !intent.record.approved || intent.record.terminal != "-" {
        return Ok(Vec::new());
    }
    let templates = intent.assembled(d)?;
    let mut requests = Vec::new();
    for (index, t) in templates.iter().enumerate() {
        if !ready(&templates, index)? {
            continue;
        }
        for slot in t.pending() {
            require(requests.len() < 16, "quota_exceeded")?;
            requests.push(json!({"intent_id":intent.id,"slot_id":index+1,"object_type":slot.object_type,"object_id":slot.statement_id,"role":slot.role,"public_key":slot.public_key,"format":slot.signature_format,"template_base64":encode(t.bytes()),"message_base64":slot.message_base64}));
        }
    }
    Ok(requests)
}
fn current_templates(intent: &Intent, d: &Descriptor, time: &str) -> Result<()> {
    for fixed in intent.assembled(d)? {
        let s = fixed.typed();
        require(s.issued_at()? <= time, "not_yet_valid")?;
        if let Some(begin) = s.payload.get("not_before").and_then(Value::as_str) {
            require(begin <= time, "not_yet_valid")?;
        }
        if let Some(end) = s.payload.get("not_after").and_then(Value::as_str) {
            require(time < end, "authority_expired")?;
        }
    }
    Ok(())
}
fn response(intent: &Intent, d: &Descriptor) -> Result<Vec<u8>> {
    if intent.record.terminal == "applied" {
        return b64(&intent.record.result_base64, 32 << 20);
    }
    bytes(
        &json!({"creation_id":intent.record.operation_id,"review":review(intent)?,"signing_requests":signing_requests(intent,d)?,"network":Value::Null,"committed":false}),
    )
}
fn stored_signature(intent: &mut Intent, slot: u64, role: &str, signature: String) -> Result<()> {
    if let Some(old) = intent
        .record
        .signatures
        .iter()
        .find(|s| s.slot_id == slot && s.role == role)
    {
        require(old.signature == signature, "operation_conflict")?;
        return Ok(());
    }
    intent.record.signatures.push(Filled {
        slot_id: slot,
        role: role.into(),
        signature,
    });
    intent
        .record
        .signatures
        .sort_by(|a, b| (a.slot_id, &a.role).cmp(&(b.slot_id, &b.role)));
    Ok(())
}
fn available(store: &Store, person: &str) -> Result<()> {
    let raw: [u8; 32] = b64(person, 32)?
        .try_into()
        .map_err(|_| Error::new("invalid"))?;
    store
        .renewal_signer(raw)
        .map(|_| ())
        .map_err(|_| Error::new("signer_unavailable"))
}
fn finish(store: &Store, id: &str) -> Result<Vec<u8>> {
    // Availability discovery may contact the local SSH agent; no database
    // guard or transaction survives that external operation.
    let (person, complete) = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let (i, _) = load_operation(&c, id, &store.identity().public_key)?;
        if i.record.terminal == "applied" {
            return b64(&i.record.result_base64, 32 << 20);
        }
        if !i.record.approved {
            let d = validate(&i, &store.identity().public_key)?;
            return response(&i, &d);
        }
        (i.record.person_public_key, i.record.completed)
    };
    let availability = if complete {
        available(store, &person)
    } else {
        Err(Error::new("signer_unavailable"))
    };
    if complete {
        controls::barrier(store, "dec.apply.before_transaction", id)?;
    }
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut tx = c.transaction().map_err(db)?;
    let (mut intent, d) = load_operation(&tx, id, &store.identity().public_key)?;
    if intent.record.terminal == "applied" {
        return b64(&intent.record.result_base64, 32 << 20);
    }
    let actual_now = controls::local_decision_time()?;
    let decision = decision(&tx, &d.network_id, &actual_now)?;
    if !intent.record.approved {
        return response(&intent, &d);
    }
    if !intent.record.completed {
        require(
            stamp(&decision)? - stamp(&intent.record.approved_at)?
                <= chrono::TimeDelta::seconds(300),
            "review_required",
        )?;
    }
    require(decision < intent.record.not_after, "authority_expired")?;
    current_templates(&intent, &d, &decision)?;
    check_outbox_capacity(&tx, &[])?;
    remember_clock(&tx, &d.network_id, &decision)?;
    let seed: [u8; 32] = intent
        .secret
        .as_deref()
        .ok_or_else(|| Error::new("state_conflict"))?
        .try_into()
        .map_err(|_| Error::new("state_conflict"))?;
    let root = SigningKey::from_bytes(&seed);
    let mut signed_batch = false;
    loop {
        let assembled = intent.assembled(&d)?;
        let mut changed = false;
        for (index, t) in assembled.iter().enumerate() {
            if !ready(&assembled, index)? {
                continue;
            }
            for slot in t.pending() {
                if slot.signature_format != "ed25519" {
                    continue;
                }
                let signer = if slot.public_key == d.genesis_root_public_key {
                    &root
                } else if slot.public_key == store.identity().public_key {
                    &store.signing_key
                } else {
                    return Err(Error::new("forbidden"));
                };
                let sig = encode(
                    &signer
                        .sign(&signature_message(
                            t.statement_id(),
                            &slot.role,
                            &slot.public_key,
                        ))
                        .to_bytes(),
                );
                t.fill(&d, &slot.role, &sig)?;
                stored_signature(&mut intent, index as u64 + 1, &slot.role, sig)?;
                changed = true;
                signed_batch = true;
            }
        }
        if !changed {
            break;
        }
    }
    let assembled = intent.assembled(&d)?;
    intent.record.completed = assembled.iter().all(|t| t.pending().is_empty());
    if signed_batch {
        let complete = intent.record.completed;
        intent.save(&tx)?;
        tx.commit().map_err(db)?;
        drop(c);
        controls::barrier(store, "dec.signature.after_commit", id)?;
        return if complete {
            finish(store, id)
        } else {
            get(store, id)
        };
    }
    if !intent.record.completed {
        return response(&intent, &d);
    }
    let catalog = completed_catalog(&intent, &d)?;
    let v = review(&intent)?;
    let identity = OwnIdentity {
        member: text(object(&v)?, "member")?.into(),
        person_public_key: intent.record.person_public_key.clone(),
        host_public_key: intent.record.host_public_key.clone(),
    };
    let snapshot = Snapshot::install_genesis(
        &mut tx,
        &bytes(&serde_json::to_value(&d).map_err(|_| Error::new("internal"))?)?,
        &catalog,
        &decision,
        &identity,
        &seed,
    )?;
    let projection = snapshot.project(&decision)?;
    let delivery = views::delivery(&tx, &d.network_id, &d.context_id())?;
    let network = views::network(&snapshot, &projection, availability, delivery)?;
    let result = bytes(
        &json!({"creation_id":id,"review":v,"signing_requests":[],"network":network,"committed":true}),
    )?;
    intent.record.result_base64 = encode(&result);
    intent.record.terminal = "applied".into();
    intent.secret = None;
    validate(&intent, &store.identity().public_key)?;
    intent.save(&tx)?;
    tx.commit().map_err(db)?;
    drop(c);
    controls::barrier(store, "dec.apply.after_commit", id)?;
    Ok(result)
}
pub(crate) fn create(store: &Store, request: &Obj, _now: &str) -> Result<Vec<u8>> {
    fields(request, "name member person_public_key approve")?;
    let name = text(request, "name")?;
    let member = text(request, "member")?;
    let person = text(request, "person_public_key")?;
    label(name)?;
    label(member)?;
    check(key(person))?;
    let approve = request
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let host = store.identity().public_key;
    let (id, prepared, newly_approved) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let actual_now = controls::local_decision_time()?;
        let now = actual_now.as_str();
        let mut q = tx
            .prepare("SELECT intent_id FROM dec_intents ORDER BY intent_id")
            .map_err(db)?;
        let ids = q
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        drop(q);
        let total = ids.len();
        let mut existing = None;
        let mut unresolved = 0;
        let mut unfinished = 0;
        for id in ids {
            let i = Intent::load(&tx, &id)?;
            if !i.record.completed && i.record.terminal == "-" {
                unfinished += 1;
            }
            if i.kind != "create" {
                continue;
            }
            let d = validate(&i, &host).map_err(|_| Error::new("state_conflict"))?;
            if i.record.terminal == "-" {
                unresolved += 1;
            }
            if d.name == name {
                require(
                    i.record.person_public_key == person
                        && text(object(&review(&i)?)?, "member")? == member,
                    "state_conflict",
                )?;
                require(existing.is_none(), "state_conflict")?;
                existing = Some(i);
            }
        }
        let prepared = existing.is_none();
        let mut i = if let Some(i) = existing {
            i
        } else {
            require(
                total < 4096 && unresolved < 8 && unfinished < 64,
                "quota_exceeded",
            )?;
            let mut q = tx
                .prepare("SELECT record FROM networks ORDER BY id")
                .map_err(db)?;
            let rows = q.query_map([], |r| r.get::<_, String>(0)).map_err(db)?;
            for row in rows {
                let existing = super::storage::network_name(&row.map_err(db)?)?;
                require(existing != name, "state_conflict")?;
            }
            drop(q);
            check_outbox_capacity(&tx, &[])?;
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| Error::new("internal"))?;
            let root = SigningKey::from_bytes(&seed);
            let public = encode(root.verifying_key().as_bytes());
            let d = Descriptor {
                format: 1,
                protocol: "peerspan-decentralized-v1".into(),
                network_id: crate::membership::network_id(root.verifying_key().as_bytes()),
                name: name.into(),
                genesis_root_public_key: public,
            };
            let created = decision(&tx, &d.network_id, now)?;
            let templates = templates(&d, person, &host, member, &created)?;
            let root_id =
                FixedStatement::read(&d, &b64(&templates[0].template_base64, MAX_OBJECT)?)?
                    .statement_id()
                    .to_owned();
            let not_after = at(&created, 604800)?;
            let review = json!({"name":name,"member":member,"descriptor":d,"root_state_id":root_id,"person_public_key":person,"host_public_key":host,"not_after":not_after,"authority_warning":"Finite authority can remain usable during an unseen revocation until its signed deadline; refresh before expiry."});
            Intent {
                id: random("dint_", 16)?,
                network_id: d.network_id.clone(),
                context_id: d.context_id(),
                kind: "create".into(),
                record: Record {
                    format: 1,
                    operation_id: random("create_", 32)?,
                    approved: false,
                    approved_at: "-".into(),
                    review_base64: encode(&bytes(&review)?),
                    provider: Provider {
                        kind: "original".into(),
                        signer_public_key: person.into(),
                        signature_format: "sshsig".into(),
                        lease_id: "-".into(),
                    },
                    root_state_id: root_id,
                    person_public_key: person.into(),
                    host_public_key: host.clone(),
                    device_public_key: "-".into(),
                    scopes: 15,
                    not_after,
                    created_at: created.clone(),
                    expires_at: at(&created, 300)?,
                    templates,
                    signatures: Vec::new(),
                    completed: false,
                    terminal: "-".into(),
                    result_base64: "-".into(),
                },
                secret: Some(seed.to_vec()),
            }
        };
        if i.record.terminal == "applied" {
            let d = validate(&i, &host)?;
            return response(&i, &d);
        }
        let newly_approved = approve && i.record.terminal == "-" && !i.record.approved;
        if newly_approved {
            let decision = decision(&tx, &i.network_id, now)?;
            require(decision < i.record.expires_at, "review_required")?;
            i.record.approved = true;
            i.record.approved_at = decision;
            remember_clock(&tx, &i.network_id, &i.record.approved_at)?;
        }
        validate(&i, &host)?;
        let id = i.record.operation_id.clone();
        i.save(&tx)?;
        tx.commit().map_err(db)?;
        (id, prepared, newly_approved)
    };
    if prepared {
        controls::barrier(store, "dec.intent.after_commit", &id)?;
    }
    if newly_approved {
        controls::barrier(store, "dec.approval.after_commit", &id)?;
    }
    if approve {
        finish(store, &id)
    } else {
        get(store, &id)
    }
}
pub(crate) fn get(store: &Store, id: &str) -> Result<Vec<u8>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let (i, d) = load_operation(&c, id, &store.identity().public_key)?;
    response(&i, &d)
}
pub(crate) fn approve(store: &Store, id: &str, request: &Obj, _now: &str) -> Result<Vec<u8>> {
    fields(
        request,
        "context_id root_state_id person_public_key host_public_key approve",
    )?;
    check(
        ident(text(request, "context_id")?, "ctx_")
            && ident(text(request, "root_state_id")?, "ds_")
            && key(text(request, "person_public_key")?)
            && key(text(request, "host_public_key")?),
    )?;
    let approve = request
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let newly_approved = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let actual_now = controls::local_decision_time()?;
        let now = actual_now.as_str();
        let (mut i, d) = load_operation(&tx, id, &store.identity().public_key)?;
        require(
            text(request, "context_id")? == i.context_id
                && text(request, "root_state_id")? == i.record.root_state_id
                && text(request, "person_public_key")? == i.record.person_public_key
                && text(request, "host_public_key")? == i.record.host_public_key,
            if i.record.terminal == "applied" {
                "operation_conflict"
            } else {
                "invalid"
            },
        )?;
        if i.record.terminal == "applied" || !approve {
            return response(&i, &d);
        }
        let decision = decision(&tx, &i.network_id, now)?;
        current_templates(&i, &d, &decision)?;
        let changed = !i.record.completed
            && (!i.record.approved
                || stamp(&decision)? - stamp(&i.record.approved_at)?
                    > chrono::TimeDelta::seconds(300));
        if changed {
            i.record.approved = true;
            i.record.approved_at = decision;
            remember_clock(&tx, &i.network_id, &i.record.approved_at)?;
            i.save(&tx)?;
        }
        tx.commit().map_err(db)?;
        changed
    };
    if newly_approved {
        controls::barrier(store, "dec.approval.after_commit", id)?;
    }
    finish(store, id)
}
pub(crate) fn signed(store: &Store, id: &str, request: &Obj, _now: &str) -> Result<Vec<u8>> {
    fields(request, "intent_id signatures")?;
    let intent_id = text(request, "intent_id")?;
    let entries = array(request, "signatures")?;
    check(!entries.is_empty() && entries.len() <= 16)?;
    let signed_batch = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let (mut i, d) = load_operation(&tx, id, &store.identity().public_key)?;
        check(intent_id == i.id)?;
        require(i.record.approved, "state_conflict")?;
        if i.record.terminal != "applied" && !i.record.completed {
            let actual_now = controls::local_decision_time()?;
            let now = decision(&tx, &i.network_id, &actual_now)?;
            require(
                stamp(&now)? - stamp(&i.record.approved_at)? <= chrono::TimeDelta::seconds(300),
                "review_required",
            )?;
            current_templates(&i, &d, &now)?;
        }
        let ready = signing_requests(&i, &d)?;
        let mut previous = None;
        let mut changed = false;
        for entry in entries {
            let e = object(entry)?;
            fields(e, "slot_id role signature")?;
            let slot = num(e, "slot_id")?;
            let role = text(e, "role")?;
            let sig = text(e, "signature")?;
            b64(sig, 8192)?;
            check(
                previous
                    .as_ref()
                    .is_none_or(|p: &(u64, String)| p < &(slot, role.into())),
            )?;
            previous = Some((slot, role.into()));
            if let Some(old) = i
                .record
                .signatures
                .iter()
                .find(|s| s.slot_id == slot && s.role == role)
            {
                require(old.signature == sig, "operation_conflict")?;
                continue;
            }
            require(i.record.terminal != "applied", "operation_conflict")?;
            check(ready.iter().any(|r| {
                r.get("slot_id").and_then(Value::as_u64) == Some(slot)
                    && r.get("role").and_then(Value::as_str) == Some(role)
            }))?;
            let t = i
                .assembled(&d)?
                .get(slot.checked_sub(1).ok_or_else(|| Error::new("invalid"))? as usize)
                .cloned()
                .ok_or_else(|| Error::new("invalid"))?;
            let pending = t.pending();
            check(pending.iter().any(|s| {
                s.role == role
                    && s.signature_format == "sshsig"
                    && s.public_key == i.record.person_public_key
            }))?;
            t.fill(&d, role, sig)?;
            stored_signature(&mut i, slot, role, sig.into())?;
            changed = true;
        }
        if i.record.terminal == "applied" {
            return response(&i, &d);
        }
        i.record.completed = i.assembled(&d)?.iter().all(|t| t.pending().is_empty());
        i.save(&tx)?;
        tx.commit().map_err(db)?;
        changed
    };
    if signed_batch {
        controls::barrier(store, "dec.signature.after_commit", id)?;
    }
    finish(store, id)
}
