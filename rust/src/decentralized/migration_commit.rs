//! Exact current-legacy-root final approval after every prepared host ACK.
//! It publishes only the fixed complete transition, never an active context.
use super::{
    actions,
    codec::*,
    controls, creation,
    intents::{Filled, Intent, Provider, Record, Template},
    migration_ack, migration_evidence,
    migration_host::Context,
    migration_prefix::Prefix,
    migration_prepare,
    statement::Descriptor,
    storage::MigrationRecord,
    template::FixedStatement,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn find(c: &Connection, r: &MigrationRecord) -> Result<Option<Intent>> {
    let mut found = None;
    for id in &r.root_intent_ids {
        let i = Intent::load(c, id)?;
        if i.record
            .templates
            .first()
            .is_some_and(|t| t.object_type == "migration_commit")
        {
            require(found.is_none(), "state_conflict")?;
            found = Some(i);
        }
    }
    Ok(found)
}
fn acknowledgment_ids(p: &Prefix) -> Result<Vec<String>> {
    let roster = array(&p.proposal.payload, "roster")?;
    require(p.acknowledgments.len() == roster.len(), "proof_required")
        .map_err(|_| Error::missing(&p.proposal.id))?;
    for row in roster {
        require(
            p.acknowledgments
                .contains_key(text(object(row)?, "host_public_key")?),
            "proof_required",
        )
        .map_err(|_| Error::missing(&p.proposal.id))?;
    }
    let mut ids: Vec<_> = p.acknowledgments.values().map(|a| a.id.clone()).collect();
    ids.sort();
    Ok(ids)
}
fn payload(p: &Prefix, at: &str) -> Result<Value> {
    Ok(
        json!({"proposal_id":p.proposal.id,"root_state_id":p.root.as_ref().ok_or_else(||Error::missing(&p.proposal.id))?.id,
        "prepared_catalog_sha256":hash(&p.catalog.as_ref().ok_or_else(||Error::missing(&p.proposal.id))?.bytes),
        "acknowledgment_ids":acknowledgment_ids(p)?,"committed_at":at}),
    )
}
fn fixed(d: &Descriptor, p: &Prefix, at: &str, format: &str) -> Result<FixedStatement> {
    FixedStatement::read(
        d,
        &actions::bytes(
            &json!({"format":1,"kind":"migration_commit","context_id":d.context_id(),
        "payload_base64":encode(&actions::bytes(&payload(p,at)?)?),"signatures":[{"role":"issuer",
            "public_key":text(&p.proposal.payload,"legacy_root_public_key")?,"format":format,"signature":"-"}]}),
        )?,
    )
}
fn validated(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    i: &Intent,
) -> Result<FixedStatement> {
    i.shape()?;
    let rec = &i.record;
    check(
        i.kind == "migration"
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && i.secret.is_none()
            && rec.approved
            && rec.provider.kind == "root"
            && rec.provider.lease_id == "-"
            && rec.provider.signer_public_key
                == text(&p.proposal.payload, "legacy_root_public_key")?
            && rec.operation_id == p.proposal.id
            && rec.host_public_key == "-"
            && rec.person_public_key == "-"
            && rec.device_public_key == "-"
            && rec.scopes == 8
            && rec.root_state_id
                == p.root
                    .as_ref()
                    .ok_or_else(|| Error::missing(&p.proposal.id))?
                    .id
            && rec.not_after == "-"
            && rec.expires_at == text(&p.proposal.payload, "expires_at")?
            && rec.templates.len() == 1
            && rec.templates[0].object_type == "migration_commit"
            && rec.terminal == "-"
            && rec.result_base64 == "-",
    )?;
    let t = i
        .assembled(d)?
        .pop()
        .ok_or_else(|| Error::new("state_conflict"))?;
    check(
        t.typed().payload == object(&payload(p, &rec.created_at)?)?.clone()
            && t.typed().signer("issuer")?.public_key == rec.provider.signer_public_key
            && t.typed().signer("issuer")?.format == rec.provider.signature_format
            && rec.completed == t.pending().is_empty(),
    )?;
    let mut saved = object(&parse(&b64(&rec.review_base64, MAX_OBJECT)?, MAX_OBJECT)?)?.clone();
    let mut expected = object(&migration_evidence::review(d, p, r, "root_commit")?)?.clone();
    let warning = text(&saved, "authority_warning")?;
    check(!warning.is_empty() && warning.len() <= 2048)?;
    saved.remove("authority_warning");
    expected.remove("authority_warning");
    check(saved == expected)?;
    Ok(t)
}
fn current(store: &Store, c: &Connection, network: &str, proposal: &str) -> Result<Context> {
    let context = Context::load_fenced(store, c, network, proposal)?;
    require(
        context.record.fenced && context.record.local_acknowledgment_base64 != "-",
        "review_required",
    )?;
    acknowledgment_ids(&context.prefix)?;
    migration_ack::prepared(
        &context.source.descriptor,
        &context.prefix,
        &context.record,
        &context.source.time,
    )?;
    Ok(context)
}
fn wrapper(d: &Descriptor, p: &Prefix, r: &MigrationRecord, i: Option<&Intent>) -> Result<Vec<u8>> {
    let Some(i) = i else {
        return migration_evidence::wrapper(d, p, r, "root_commit");
    };
    let t = validated(d, p, r, i)?;
    let slots=t.pending().into_iter().map(|s|json!({"intent_id":i.id,"slot_id":1,"object_id":s.statement_id,
        "object_type":s.object_type,"role":s.role,"public_key":s.public_key,"format":s.signature_format,
        "message_base64":s.message_base64,"template_base64":encode(t.bytes())})).collect::<Vec<_>>();
    actions::bytes(
        &json!({"migration":p.view(d,r)?,"review":parse(&b64(&i.record.review_base64,MAX_OBJECT)?,MAX_OBJECT)?,"signing_requests":slots}),
    )
}
fn result(store: &Store, network: &str) -> Result<Vec<u8>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let (_, r) = migration_prepare::load(&c, network)?.ok_or_else(|| Error::new("not_found"))?;
    let d = migration_evidence::descriptor(&r)?;
    let p = Prefix::read(&d, &r)?;
    let i = find(&c, &r)?;
    wrapper(&d, &p, &r, i.as_ref())
}
pub(crate) fn prepare(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(
        input,
        "proposal_id prepared_catalog_sha256 acknowledgment_ids signature_format approve",
    )?;
    let proposal = text(input, "proposal_id")?;
    let hash = text(input, "prepared_catalog_sha256")?;
    check(ident(proposal, "ds_") && digest(hash))?;
    let supplied = ids(input, "acknowledgment_ids", "ds_")?;
    let format = text(input, "signature_format")?;
    check(matches!(format, "auto" | "ed25519" | "sshsig"))?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let fresh = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let (id, mut r) =
            migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
        require(id == proposal, "operation_conflict")?;
        let d = migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        require(
            p.catalog
                .as_ref()
                .is_some_and(|c| super::codec::hash(&c.bytes) == hash)
                && acknowledgment_ids(&p)? == supplied,
            "operation_conflict",
        )?;
        let old = find(&tx, &r)?;
        if let Some(i) = old {
            validated(&d, &p, &r, &i)?;
            require(
                format == "auto" || i.record.provider.signature_format == format,
                "operation_conflict",
            )?;
            if r.commit_base64 != "-" || !approve {
                return wrapper(&d, &p, &r, Some(&i));
            }
            false
        } else {
            let context = current(store, &tx, network, proposal)?;
            let root = text(&p.proposal.payload, "legacy_root_public_key")?;
            let format = if format == "auto" || format == "ed25519" {
                require(
                    migration_prepare::root_seed(&tx, network, root)?.is_some(),
                    "signer_unavailable",
                )?;
                "ed25519"
            } else {
                format
            };
            let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
            decision_clock(&now, &context.source.time)?;
            require(
                now.as_str() < text(&p.proposal.payload, "expires_at")?,
                "expired",
            )?;
            migration_ack::prepared(&d, &p, &r, &now)?;
            let t = fixed(&d, &p, &now, format)?;
            let mut budget = r.clone();
            budget.commit_base64 = encode(&t.budget_bytes()?);
            Prefix::complete_body(&budget)?;
            if !approve {
                return wrapper(&d, &p, &r, None);
            }
            let total: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
                .map_err(db)?;
            let open:i64=tx.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
            require(total < 4096 && open < 64, "quota_exceeded")?;
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
                    approved_at: now.clone(),
                    review_base64: encode(&actions::bytes(&migration_evidence::review(
                        &d,
                        &p,
                        &r,
                        "root_commit",
                    )?)?),
                    provider: Provider {
                        kind: "root".into(),
                        signer_public_key: root.into(),
                        signature_format: format.into(),
                        lease_id: "-".into(),
                    },
                    root_state_id: context
                        .prefix
                        .root
                        .as_ref()
                        .ok_or_else(|| Error::missing(proposal))?
                        .id
                        .clone(),
                    person_public_key: "-".into(),
                    host_public_key: "-".into(),
                    device_public_key: "-".into(),
                    scopes: 8,
                    not_after: "-".into(),
                    created_at: now.clone(),
                    expires_at: text(&p.proposal.payload, "expires_at")?.into(),
                    templates: vec![Template {
                        slot_id: 1,
                        object_type: "migration_commit".into(),
                        template_base64: encode(t.bytes()),
                    }],
                    signatures: vec![],
                    completed: false,
                    terminal: "-".into(),
                    result_base64: "-".into(),
                },
            };
            validated(&d, &p, &r, &i)?;
            r.root_intent_ids.push(i.id.clone());
            i.save(&tx)?;
            migration_prepare::save(&tx, network, proposal, &r)?;
            creation::remember_clock(&tx, network, &now)?;
            tx.commit().map_err(db)?;
            true
        }
    };
    if fresh {
        controls::barrier(store, "dec.intent.after_commit", proposal)?;
        controls::barrier(store, "dec.approval.after_commit", proposal)?;
    }
    advance(store, network, None)?;
    result(store, network)
}
pub(super) fn advance(store: &Store, network: &str, batch: Option<&Obj>) -> Result<bool> {
    let (proposal, changed) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let Some((proposal, r)) = migration_prepare::load(&tx, network)? else {
            return Ok(false);
        };
        let Some(mut i) = find(&tx, &r)? else {
            return Ok(false);
        };
        let d = migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        let t = validated(&d, &p, &r, &i)?;
        if r.commit_base64 != "-" {
            if let Some(batch) = batch {
                check_batch(&d, &t, &mut i, batch)?;
            }
            return Ok(true);
        }
        let context = current(store, &tx, network, &proposal)?;
        let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        decision_clock(&now, &context.source.time)?;
        require(
            now.as_str() < text(&p.proposal.payload, "expires_at")?,
            "expired",
        )?;
        migration_ack::prepared(&d, &p, &r, &now)?;
        let mut changed = if let Some(batch) = batch {
            check_batch(&d, &t, &mut i, batch)?
        } else {
            false
        };
        if let Some(seed) =
            migration_prepare::root_seed(&tx, network, &i.record.provider.signer_public_key)?
        {
            for slot in i.assembled(&d)?[0].pending() {
                check(
                    slot.role == "issuer" && slot.public_key == i.record.provider.signer_public_key,
                )?;
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
                i.assembled(&d)?[0].fill(&d, &slot.role, &sig)?;
                i.record.signatures.push(Filled {
                    slot_id: 1,
                    role: slot.role,
                    signature: sig,
                });
                changed = true;
            }
        }
        i.record.completed = i.assembled(&d)?[0].pending().is_empty();
        validated(&d, &p, &r, &i)?;
        if changed {
            i.save(&tx)?;
            creation::remember_clock(&tx, network, &now)?;
            tx.commit().map_err(db)?;
        }
        (proposal, changed)
    };
    if changed {
        controls::barrier(store, "dec.signature.after_commit", &proposal)?;
    }
    let committed = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let (_, mut r) =
            migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
        let d = migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        let i = find(&tx, &r)?.ok_or_else(|| Error::new("not_found"))?;
        let t = validated(&d, &p, &r, &i)?;
        if !t.pending().is_empty() {
            return Ok(true);
        }
        let context = current(store, &tx, network, &proposal)?;
        let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        decision_clock(&now, &context.source.time)?;
        require(
            now.as_str() < text(&p.proposal.payload, "expires_at")?,
            "expired",
        )?;
        migration_ack::prepared(&d, &p, &r, &now)?;
        r.commit_base64 = encode(t.bytes());
        r.migration_base64 = encode(&Prefix::complete_body(&r)?);
        Prefix::read(&d, &r)?;
        migration_prepare::save(&tx, network, &proposal, &r)?;
        creation::remember_clock(&tx, network, &now)?;
        tx.commit().map_err(db)?;
        true
    };
    if committed {
        controls::barrier(store, "dec.migration_commit.after_commit", &proposal)?;
    }
    Ok(true)
}
fn check_batch(d: &Descriptor, t: &FixedStatement, i: &mut Intent, batch: &Obj) -> Result<bool> {
    fields(batch, "intent_id signatures")?;
    require(text(batch, "intent_id")? == i.id, "operation_conflict")?;
    let entries = array(batch, "signatures")?;
    check(entries.len() == 1)?;
    let e = object(&entries[0])?;
    fields(e, "slot_id role signature")?;
    check(num(e, "slot_id")? == 1 && text(e, "role")? == "issuer")?;
    let sig = text(e, "signature")?;
    if let Some(old) = i.record.signatures.first() {
        require(
            old.role == "issuer" && old.signature == sig,
            "operation_conflict",
        )?;
        return Ok(false);
    }
    t.fill(d, "issuer", sig)?;
    i.record.signatures.push(Filled {
        slot_id: 1,
        role: "issuer".into(),
        signature: sig.into(),
    });
    Ok(true)
}
pub(crate) fn signed(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    require(advance(store, network, Some(input))?, "not_found")?;
    result(store, network)
}
pub(super) fn owns(c: &Connection, network: &str, id: &str) -> Result<bool> {
    let Some((_, r)) = migration_prepare::load(c, network)? else {
        return Ok(false);
    };
    Ok(find(c, &r)?.is_some_and(|i| i.id == id))
}
