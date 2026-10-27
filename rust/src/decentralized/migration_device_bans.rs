//! Copy only independently verified inherited device bans under the exact
//! original person. Pending P/root facts confer no ordinary signer authority.
use super::{
    actions,
    catalog::Catalog,
    codec::*,
    controls,
    intents::{Filled, Intent, Provider, Record, Template},
    migration::{self, SourceContext},
    migration_host::Context,
    migration_prefix::Prefix,
    migration_prepare,
    statement::{Descriptor, proof_id},
    storage::MigrationRecord,
    template::FixedStatement,
};
use crate::store::Store;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
struct Plan {
    root: String,
    person_lease: String,
    copies: Vec<(String, Vec<String>)>,
    maxima: Vec<Value>,
}
fn plan(d: &Descriptor, p: &Prefix, r: &MigrationRecord, person: &str) -> Result<Plan> {
    check(key(person))?;
    let root = p
        .root
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let catalog = p
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let proposal = &p.proposal.payload;
    let source_catalog = b64(&r.source_catalog_base64, 512 << 10)?;
    let state = b64(&r.source_state_base64, MAX_PAYLOAD)?;
    let (source, legacy) = migration::source_snapshot(
        SourceContext {
            descriptor: d,
            legacy_descriptor: &b64(text(proposal, "legacy_descriptor_base64")?, MAX_OBJECT)?,
            epoch: num(proposal, "legacy_epoch")?,
            feature: text(proposal, "legacy_feature_id")?,
            root: text(proposal, "legacy_root_public_key")?,
            now: text(proposal, "issued_at")?,
        },
        &source_catalog,
        &state,
    )?;
    require(
        legacy
            .facts
            .state
            .persons
            .get(person)
            .is_some_and(|p| p.admitted),
        "forbidden",
    )?;
    let shared: Vec<_> = catalog
        .statements
        .values()
        .filter(|s| {
            s.kind == "person_lease"
                && s.subject()
                    .is_ok_and(|o| text(o, "person_public_key").is_ok_and(|k| k == person))
        })
        .collect();
    require(shared.len() == 1, "proof_required").map_err(|_| Error::missing(&p.proposal.id))?;
    let lease = shared[0];
    check(
        text(&lease.payload, "root_state_id")? == root.id
            && text(&lease.payload, "operation_id")? == "-"
            && text(lease.issuer()?, "kind")? == "root"
            && lease.signer("issuer")?.public_key == legacy.root_public_key,
    )?;
    let copies = migration::inherited_bans(&source, &source_catalog, &legacy)?
        .into_iter()
        .filter(|((kind, owner, _, _), _)| kind == "device_revoke" && owner == person)
        .map(|((_, _, _, device), proofs)| (device, proofs.into_iter().collect()))
        .collect();
    let maxima=source.maxima.into_iter().map(|((kind,subject),(version,message_hash))|
        json!({"kind":kind,"subject":subject,"version":version,"message_hash":message_hash})).collect();
    Ok(Plan {
        root: root.id.clone(),
        person_lease: lease.id.clone(),
        copies,
        maxima,
    })
}
fn templates(d: &Descriptor, person: &str, plan: &Plan, at: &str) -> Result<Vec<FixedStatement>> {
    plan.copies.iter().map(|(device,_)|{
        let payload=json!({"root_state_id":plan.root,"issuer":{"kind":"person","person_public_key":person},
            "parents":[{"role":"issuer_person","id":plan.person_lease}],"issued_at":at,
            "target":{"person_public_key":person,"host_public_key":"-","device_public_key":device,"statement_id":"-"},
            "kept_statement_ids":[],"ratifies":"-"});
        FixedStatement::read(d,&actions::bytes(&json!({"format":1,"kind":"device_revoke","context_id":d.context_id(),
            "payload_base64":encode(&actions::bytes(&payload)?),"signatures":[{"role":"issuer","public_key":person,"format":"sshsig","signature":"-"}]}))?)
    }).collect()
}
fn review(
    d: &Descriptor,
    p: &Prefix,
    person: &str,
    plan: &Plan,
    ts: Option<&[FixedStatement]>,
) -> Result<Value> {
    Ok(
        json!({"stage":"inherited_device_bans","network_id":d.network_id,"proposal_id":p.proposal.id,"new_context_id":d.context_id(),
        "person_public_key":person,"root_state_id":plan.root,"person_lease_id":plan.person_lease,
        "source_catalog_sha256":text(&p.proposal.payload,"source_catalog_sha256")?,"source_state_sha256":text(&p.proposal.payload,"source_state_sha256")?,
        "copies":plan.copies.iter().enumerate().map(|(n,(device,proofs))|json!({"device_public_key":device,"source_proof_ids":proofs,"statement_id":ts.map_or("-",|ts|ts[n].statement_id())})).collect::<Vec<_>>(),
        "access_maxima":plan.maxima,"authority_warning":"Approve only these exact irreversible inherited device bans. The original person signs restrictive copies under inert migration facts; this creates no provider, active restriction, acknowledgment, fence or adoption."}),
    )
}
fn find(c: &Connection, network: &str, proposal: &str, person: &str) -> Result<Option<Intent>> {
    let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE network_id=?1 AND kind='migration' ORDER BY intent_id").map_err(db)?;
    let mut found = None;
    for id in q
        .query_map([network], |r| r.get::<_, String>(0))
        .map_err(db)?
    {
        let i = Intent::load(c, &id.map_err(db)?)?;
        if i.record.operation_id != proposal
            || i.record.provider.kind != "original"
            || i.record.person_public_key != person
        {
            continue;
        }
        require(found.is_none(), "state_conflict")?;
        found = Some(i);
    }
    Ok(found)
}
fn validated(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    i: &Intent,
    host: &str,
) -> Result<(Plan, Vec<FixedStatement>)> {
    i.shape()?;
    let rec = &i.record;
    check(
        i.kind == "migration"
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && i.secret.is_none()
            && rec.operation_id == p.proposal.id
            && rec.approved
            && rec.provider.kind == "original"
            && rec.provider.signer_public_key == rec.person_public_key
            && rec.provider.signature_format == "sshsig"
            && rec.provider.lease_id == "-"
            && rec.host_public_key == host
            && rec.device_public_key == "-"
            && rec.scopes == 0
            && rec.not_after == "-"
            && rec.terminal == "-"
            && rec.result_base64 == "-"
            && rec.expires_at == text(&p.proposal.payload, "expires_at")?
            && rec.created_at == rec.approved_at
            && rec.created_at.as_str() >= text(&p.proposal.payload, "issued_at")?,
    )?;
    let plan = plan(d, p, r, &rec.person_public_key)?;
    require(!plan.copies.is_empty(), "operation_conflict")?;
    let derived = templates(d, &rec.person_public_key, &plan, &rec.created_at)?;
    check(rec.root_state_id == plan.root && derived.len() == rec.templates.len())?;
    let mut expected = Vec::new();
    for (n, (derived, stored)) in derived.iter().zip(&rec.templates).enumerate() {
        let original = FixedStatement::read(d, &b64(&stored.template_base64, MAX_OBJECT)?)?;
        check(
            stored.slot_id == n as u64 + 1
                && stored.object_type == "device_revoke"
                && original.typed().kind == "device_revoke"
                && original.typed().payload == derived.typed().payload
                && original.typed().signatures.len() == 1
                && original.typed().signer("issuer")?.public_key == rec.person_public_key
                && original.typed().signer("issuer")?.format == "sshsig"
                && original.typed().signer("issuer")?.signature == "-",
        )?;
        expected.push(original);
    }
    let actual = i.assembled(d)?;
    check(rec.completed == actual.iter().all(|t| t.pending().is_empty()))?;
    let mut saved = object(&parse(&b64(&rec.review_base64, MAX_OBJECT)?, MAX_OBJECT)?)?.clone();
    let mut expected_review = object(&review(
        d,
        p,
        &rec.person_public_key,
        &plan,
        Some(&expected),
    )?)?
    .clone();
    let warning = text(&saved, "authority_warning")?;
    check(!warning.is_empty() && warning.len() <= 1024)?;
    saved.remove("authority_warning");
    expected_review.remove("authority_warning");
    check(saved == expected_review)?;
    Ok((plan, actual))
}
fn current(context: &Context, plan: &Plan, person: &str, at: &str) -> Result<()> {
    require(at >= context.source.time.as_str(), "clock_rollback")?;
    require(
        at < text(&context.prefix.proposal.payload, "expires_at")?,
        "expired",
    )?;
    let p = super::state::Projection::stage_migration(
        &context.source.descriptor,
        &context
            .prefix
            .catalog
            .as_ref()
            .ok_or_else(|| Error::missing(&context.prefix.proposal.id))?
            .bytes,
        at,
        &context.prefix.proposal.id,
        &plan.root,
        &context.prefix.source.maxima,
    )?;
    let (shared, _) = p.current_statement(&["person".into(), person.into()])?;
    require(shared.id == plan.person_lease, "state_conflict")
}
fn candidate(d: &Descriptor, p: &Prefix, ts: &[FixedStatement], budget: bool) -> Result<Vec<u8>> {
    let old = p
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let mut rows = old
        .proofs
        .iter()
        .map(|(id, p)| {
            (
                id.clone(),
                json!({"id":id,"kind":p.kind,"body_base64":encode(&p.body)}),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for t in ts {
        if !budget && !t.pending().is_empty() {
            continue;
        }
        let raw = if budget {
            t.budget_bytes()?
        } else {
            t.bytes().to_vec()
        };
        let id = proof_id("device_revoke", &raw);
        rows.insert(
            id.clone(),
            json!({"id":id,"kind":"device_revoke","body_base64":encode(&raw)}),
        );
    }
    require(rows.len() <= 4096, "quota_exceeded")?;
    let raw = actions::bytes(
        &json!({"format":1,"context_id":d.context_id(),"objects":rows.into_values().collect::<Vec<_>>()}),
    )?;
    require(raw.len() <= MAX_OBJECT, "quota_exceeded")?;
    if !budget {
        Catalog::read(d, &raw)?;
    }
    Ok(raw)
}
fn wrapper(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    review: Value,
    i: Option<&Intent>,
    ts: &[FixedStatement],
) -> Result<Vec<u8>> {
    let mut slots = Vec::new();
    if let Some(i) = i {
        for (n, t) in ts.iter().enumerate() {
            for slot in t.pending() {
                check(
                    slot.role == "issuer"
                        && slot.public_key == i.record.person_public_key
                        && slot.signature_format == "sshsig",
                )?;
                if slots.len() < 16 {
                    slots.push(json!({"intent_id":i.id,"slot_id":n+1,"object_type":"device_revoke","object_id":slot.statement_id,"role":slot.role,"public_key":slot.public_key,"format":slot.signature_format,"template_base64":encode(t.bytes()),"message_base64":slot.message_base64}));
                }
            }
        }
    }
    actions::bytes(&json!({"migration":p.view(d,r)?,"review":review,"signing_requests":slots}))
}
pub(crate) fn prepare(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "proposal_id person_public_key approve")?;
    let proposal = text(input, "proposal_id")?;
    let person = text(input, "person_public_key")?;
    check(ident(network, "net_") && ident(proposal, "ds_") && key(person))?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    if let Some(i) = find(&tx, network, proposal, person)? {
        let (id, r) =
            migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("state_conflict"))?;
        require(id == proposal, "operation_conflict")?;
        let d = super::migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        let (plan, ts) = validated(&d, &p, &r, &i, &store.identity().public_key)?;
        if !i.record.completed {
            let context = Context::load(store, &tx, network, proposal)?;
            current(&context, &plan, person, &context.source.time)?;
        }
        return wrapper(
            &d,
            &p,
            &r,
            parse(&b64(&i.record.review_base64, MAX_OBJECT)?, MAX_OBJECT)?,
            Some(&i),
            &ts,
        );
    }
    let context = Context::load(store, &tx, network, proposal)?;
    let d = &context.source.descriptor;
    let p = &context.prefix;
    let r = &context.record;
    let plan = plan(d, p, r, person)?;
    let ts = templates(d, person, &plan, &context.source.time)?;
    current(&context, &plan, person, &context.source.time)?;
    super::migration_link::byte_budget(
        &context,
        &candidate(d, p, &ts, true)?,
        &context.source.time,
    )?;
    if !approve || ts.is_empty() {
        return wrapper(d, p, r, review(d, p, person, &plan, None)?, None, &[]);
    }
    let total: i64 = tx
        .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
        .map_err(db)?;
    let active:i64=tx.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
    require(total < 4096 && active < 64, "quota_exceeded")?;
    let reviewed = review(d, p, person, &plan, Some(&ts))?;
    let i = Intent {
        id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
        network_id: network.into(),
        context_id: d.context_id(),
        kind: "migration".into(),
        secret: None,
        record: Record {
            format: 1,
            operation_id: proposal.into(),
            approved: true,
            approved_at: context.source.time.clone(),
            review_base64: encode(&actions::bytes(&reviewed)?),
            provider: Provider {
                kind: "original".into(),
                signer_public_key: person.into(),
                signature_format: "sshsig".into(),
                lease_id: "-".into(),
            },
            root_state_id: plan.root.clone(),
            person_public_key: person.into(),
            host_public_key: store.identity().public_key,
            device_public_key: "-".into(),
            scopes: 0,
            not_after: "-".into(),
            created_at: context.source.time.clone(),
            expires_at: text(&p.proposal.payload, "expires_at")?.into(),
            templates: ts
                .iter()
                .enumerate()
                .map(|(n, t)| Template {
                    slot_id: n as u64 + 1,
                    object_type: "device_revoke".into(),
                    template_base64: encode(t.bytes()),
                })
                .collect(),
            signatures: vec![],
            completed: false,
            terminal: "-".into(),
            result_base64: "-".into(),
        },
    };
    validated(d, p, r, &i, &store.identity().public_key)?;
    i.save(&tx)?;
    controls::remember_decision(&tx, network, &context.source.time)?;
    let out = wrapper(d, p, r, reviewed, Some(&i), &ts)?;
    tx.commit().map_err(db)?;
    drop(c);
    controls::barrier(store, "dec.intent.after_commit", proposal)?;
    controls::barrier(store, "dec.approval.after_commit", proposal)?;
    Ok(out)
}
pub(super) fn owns(c: &Connection, network: &str, id: &str) -> Result<bool> {
    let i = Intent::load(c, id)?;
    Ok(i.network_id == network && i.kind == "migration" && i.record.provider.kind == "original")
}
pub(crate) fn signed(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "intent_id signatures")?;
    let entries = array(input, "signatures")?;
    check(!entries.is_empty() && entries.len() <= 16)?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut i = Intent::load(&tx, text(input, "intent_id")?)?;
    require(i.network_id == network, "operation_conflict")?;
    if i.record.completed {
        let (proposal, r) =
            migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("state_conflict"))?;
        require(proposal == i.record.operation_id, "operation_conflict")?;
        let d = super::migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        let (_, ts) = validated(&d, &p, &r, &i, &store.identity().public_key)?;
        let mut previous = None;
        for entry in entries {
            let e = object(entry)?;
            fields(e, "slot_id role signature")?;
            let slot = num(e, "slot_id")?;
            let role = text(e, "role")?;
            check(
                slot > 0
                    && slot <= ts.len() as u64
                    && role == "issuer"
                    && previous.is_none_or(|p| p < slot),
            )?;
            previous = Some(slot);
            let signature = text(e, "signature")?;
            require(
                i.record
                    .signatures
                    .iter()
                    .any(|s| s.slot_id == slot && s.role == role && s.signature == signature),
                "operation_conflict",
            )?;
        }
        return wrapper(
            &d,
            &p,
            &r,
            parse(&b64(&i.record.review_base64, MAX_OBJECT)?, MAX_OBJECT)?,
            Some(&i),
            &ts,
        );
    }
    let context = Context::load(store, &tx, network, &i.record.operation_id)?;
    let d = &context.source.descriptor;
    let (plan, ts) = validated(
        d,
        &context.prefix,
        &context.record,
        &i,
        &store.identity().public_key,
    )?;
    current(
        &context,
        &plan,
        &i.record.person_public_key,
        &context.source.time,
    )?;
    require(context.source.time >= i.record.created_at, "clock_rollback")?;
    let mut previous = None;
    let mut changed = false;
    for entry in entries {
        let e = object(entry)?;
        fields(e, "slot_id role signature")?;
        let slot = num(e, "slot_id")?;
        let role = text(e, "role")?;
        let signature = text(e, "signature")?;
        check(
            slot > 0
                && slot <= ts.len() as u64
                && role == "issuer"
                && signature != "-"
                && previous.is_none_or(|v| v < slot),
        )?;
        previous = Some(slot);
        if let Some(old) = i
            .record
            .signatures
            .iter()
            .find(|s| s.slot_id == slot && s.role == role)
        {
            require(old.signature == signature, "operation_conflict")?;
            continue;
        }
        ts[slot as usize - 1].fill(d, role, signature)?;
        i.record.signatures.push(Filled {
            slot_id: slot,
            role: role.into(),
            signature: signature.into(),
        });
        changed = true;
    }
    i.record
        .signatures
        .sort_by(|a, b| (a.slot_id, &a.role).cmp(&(b.slot_id, &b.role)));
    let ts = i.assembled(d)?;
    i.record.completed = ts.iter().all(|t| t.pending().is_empty());
    let prepared = candidate(d, &context.prefix, &ts, false)?;
    super::migration_link::byte_budget(&context, &prepared, &context.source.time)?;
    let mut r = context.record.clone();
    require(
        r.acknowledgments_base64.is_empty() && r.commit_base64 == "-" && r.migration_base64 == "-",
        "operation_conflict",
    )?;
    r.prepared_catalog_base64 = encode(&prepared);
    let p = Prefix::read(d, &r)?;
    validated(d, &p, &r, &i, &store.identity().public_key)?;
    let out = wrapper(
        d,
        &p,
        &r,
        parse(&b64(&i.record.review_base64, MAX_OBJECT)?, MAX_OBJECT)?,
        Some(&i),
        &ts,
    )?;
    if changed {
        i.save(&tx)?;
        migration_prepare::save(&tx, network, &p.proposal.id, &r)?;
        controls::remember_decision(&tx, network, &context.source.time)?;
    }
    let proposal = p.proposal.id.clone();
    tx.commit().map_err(db)?;
    drop(c);
    if changed {
        controls::barrier(store, "dec.signature.after_commit", &proposal)?;
    }
    Ok(out)
}

/// Read only: ready external original slots remain explicit local work.
pub(super) fn resume(store: &Store, network: &str) -> Result<Option<Vec<u8>>> {
    let selected = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let Some((proposal, _)) = migration_prepare::load(&c, network)? else {
            return Ok(None);
        };
        let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE network_id=?1 AND kind='migration' ORDER BY intent_id").map_err(db)?;
        let mut pending = BTreeMap::new();
        for id in q
            .query_map([network], |r| r.get::<_, String>(0))
            .map_err(db)?
        {
            let i = Intent::load(&c, &id.map_err(db)?)?;
            if i.record.operation_id == proposal
                && i.record.provider.kind == "original"
                && i.record.approved
                && !i.record.completed
            {
                require(
                    pending
                        .insert(i.record.person_public_key.clone(), ())
                        .is_none(),
                    "state_conflict",
                )?;
            }
        }
        pending.into_keys().next().map(|person| (proposal, person))
    };
    selected
        .map(|(proposal, person)| {
            prepare(
                store,
                network,
                object(
                    &json!({"proposal_id":proposal,"person_public_key":person,"approve":false}),
                )?,
            )
        })
        .transpose()
}
