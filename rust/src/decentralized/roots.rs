//! Owner-local reviewed next-root intents. Fork branches are cosignature slots,
//! never a selected provider or an exception to ordinary authority checks.
use super::{
    actions,
    codec::*,
    controls,
    intents::{Intent, Provider, Record, Template},
    state::Projection,
    storage::Snapshot,
    template::FixedStatement,
    views,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn owned(c: &Connection, network: &str) -> Result<Option<[u8; 32]>> {
    let seed: Option<Vec<u8>> = c
        .query_row(
            "SELECT root_seed FROM networks WHERE id=?1",
            [network],
            |r| r.get(0),
        )
        .map_err(db)?;
    seed.map(|s| s.try_into().map_err(|_| Error::new("state_conflict")))
        .transpose()
}
fn public(seed: &[u8; 32]) -> String {
    encode(SigningKey::from_bytes(seed).verifying_key().as_bytes())
}
fn actor(first: &str) -> Obj {
    object(&json!({"person_public_key":"-","host_public_key":"-","device_public_key":"-","issuer_id":first})).expect("fixed actor object").clone()
}
fn predecessors(fixed: &FixedStatement) -> Result<Vec<String>> {
    ids(&fixed.typed().payload, "predecessors", "ds_")
}
fn validate(i: &Intent, d: &super::Descriptor) -> Result<()> {
    actions::validate(i, d)?;
    check(
        i.kind == "root_transition"
            && i.record.provider.kind == "root"
            && i.record.templates.len() == 1,
    )?;
    let fixed = i.assembled(d)?.remove(0);
    let s = fixed.typed();
    let old = predecessors(&fixed)?;
    check(
        s.kind == "root_state"
            && !old.is_empty()
            && i.record.person_public_key == "-"
            && i.record.device_public_key == "-"
            && i.record.not_after == "-",
    )?;
    let role = if old.len() == 1 {
        "issuer".into()
    } else {
        format!("root_branch:{}", old[0])
    };
    check(
        s.signer(&role)?.public_key == i.record.provider.signer_public_key
            && i.record.root_state_id == if old.len() == 1 { old[0].as_str() } else { "-" }
            && i.record.scopes == if old.len() == 1 { 8 } else { 0 },
    )?;
    for sig in s.signatures.values().filter(|s| s.role != "new_root") {
        check(sig.format == i.record.provider.signature_format)?;
    }
    if let Some(seed) = &i.secret {
        let seed: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::new("state_conflict"))?;
        check(
            s.signer("new_root")?.format == "ed25519"
                && public(seed) == text(&s.payload, "root_public_key")?,
        )?;
    }
    Ok(())
}
fn load(c: &Connection, network: &str, id: &str) -> Result<Intent> {
    let i = actions::load(c, network, id, "root_transition")?;
    validate(&i, &actions::descriptor(c, network)?).map_err(|_| Error::new("state_conflict"))?;
    Ok(i)
}
pub(crate) fn contains(store: &Store, network: &str, id: &str) -> Result<bool> {
    check(ident(network, "net_") && ident(id, "act_"))?;
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    c.query_row("SELECT EXISTS(SELECT 1 FROM dec_intents WHERE network_id=?1 AND kind='root_transition' AND json_extract(record,'$.operation_id')=?2)",rusqlite::params![network,id],|r|r.get(0)).map_err(db)
}
fn current(s: &Snapshot, p: &Projection, i: &Intent) -> Result<FixedStatement> {
    validate(i, &s.descriptor)?;
    require(
        i.context_id == s.network.context_id
            && i.record.host_public_key == s.network.own_identity.host_public_key,
        "state_conflict",
    )?;
    let fixed = i.assembled(&s.descriptor)?.remove(0);
    let old = predecessors(&fixed)?;
    p.action(&actor(&old[0]), "root_state", &fixed.typed().payload_bytes)?;
    for id in &old {
        let root = p.catalog.get(id)?;
        let role = if old.len() == 1 {
            "issuer".into()
        } else {
            format!("root_branch:{id}")
        };
        check(fixed.typed().signer(&role)?.public_key == text(&root.payload, "root_public_key")?)?;
    }
    Ok(fixed)
}
fn pending(c: &Connection, network: &str, d: &super::Descriptor) -> Result<Option<Intent>> {
    let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE network_id=?1 AND kind='root_transition' ORDER BY intent_id").map_err(db)?;
    let rows = q
        .query_map([network], |r| r.get::<_, String>(0))
        .map_err(db)?;
    let mut found = None;
    for row in rows {
        let i = Intent::load(c, &row.map_err(db)?)?;
        validate(&i, d).map_err(|_| Error::new("state_conflict"))?;
        if i.record.terminal == "-" {
            require(found.is_none(), "state_conflict")?;
            found = Some(i);
        }
    }
    Ok(found)
}
fn matches_request(i: &Intent, d: &super::Descriptor, r: &Obj) -> Result<()> {
    let fixed = i.assembled(d)?.remove(0);
    let s = fixed.typed();
    let target = text(r, "new_root_public_key")?;
    require(
        if target == "-" {
            i.secret.is_some()
        } else {
            target == text(&s.payload, "root_public_key")? && i.secret.is_none()
        },
        "operation_conflict",
    )?;
    require(
        text(r, "new_root_signature_format")? == s.signer("new_root")?.format
            && (text(r, "signature_format")? == "auto"
                || text(r, "signature_format")? == i.record.provider.signature_format)
            && ids(r, "retained_statement_ids", "ds_")?
                == ids(&s.payload, "retained_statement_ids", "ds_")?,
        "operation_conflict",
    )
}
fn template(
    p: &Projection,
    old: &[String],
    payload: &Value,
    format: &str,
    next_format: &str,
) -> Result<FixedStatement> {
    let mut roles = BTreeMap::new();
    for id in old {
        let root = p.catalog.get(id)?;
        let role = if old.len() == 1 {
            "issuer".into()
        } else {
            format!("root_branch:{id}")
        };
        roles.insert(
            role,
            (
                text(&root.payload, "root_public_key")?.to_owned(),
                format.to_owned(),
            ),
        );
    }
    roles.insert(
        "new_root".into(),
        (
            text(object(payload)?, "root_public_key")?.to_owned(),
            next_format.into(),
        ),
    );
    let raw = actions::bytes(
        &json!({"format":1,"kind":"root_state","context_id":p.descriptor.context_id(),"payload_base64":encode(&actions::bytes(payload)?),"signatures":roles.into_iter().map(|(role,(public_key,format))|json!({"role":role,"public_key":public_key,"format":format,"signature":"-"})).collect::<Vec<_>>()}),
    )?;
    FixedStatement::read(&p.descriptor, &raw)
}
pub(crate) fn prepare(store: &Store, network: &str, r: &Obj) -> Result<Vec<u8>> {
    fields(
        r,
        "new_root_public_key new_root_signature_format signature_format retained_statement_ids approve",
    )?;
    check(ident(network, "net_"))?;
    let target = text(r, "new_root_public_key")?;
    check(target == "-" || key(target))?;
    let next_format = text(r, "new_root_signature_format")?;
    check(
        matches!(next_format, "ed25519" | "sshsig") && (target != "-" || next_format == "ed25519"),
    )?;
    let requested_format = text(r, "signature_format")?;
    check(matches!(requested_format, "auto" | "ed25519" | "sshsig"))?;
    let retained = ids(r, "retained_statement_ids", "ds_")?;
    let approve = r
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let (id, new, approval) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        let mut i;
        let new;
        let mut existing = pending(&tx, network, &s.descriptor)?;
        // An unapproved earlier preview that no longer matches a new preview
        // request or the current root (a renewal or sync landed during its
        // review) signed nothing; the new review replaces it. An approval
        // never replaces what was reviewed.
        if let Some(old) = &existing
            && !approve
            && !old.record.approved
            && (matches_request(old, &s.descriptor, r).is_err() || current(&s, &p, old).is_err())
        {
            tx.execute("DELETE FROM dec_intents WHERE intent_id=?1", [&old.id])
                .map_err(db)?;
            existing = None;
        }
        if let Some(existing) = existing {
            matches_request(&existing, &s.descriptor, r)?;
            let fixed = current(&s, &p, &existing)?;
            actions::preflight(&tx, &p, &s, &fixed)?;
            i = existing;
            new = false;
        } else {
            let roots = p
                .streams
                .get(&vec!["root".into()])
                .ok_or_else(|| Error::new("proof_required"))?;
            require(!roots.heads.is_empty(), "proof_required")?;
            let old: Vec<_> = roots.heads.iter().cloned().collect();
            let epoch = roots
                .maximum
                .checked_add(1)
                .ok_or_else(|| Error::new("state_conflict"))?;
            let first = text(&p.catalog.get(&old[0])?.payload, "root_public_key")?.to_owned();
            let held = owned(&tx, network)?;
            let any_owned = held.as_ref().is_some_and(|seed| {
                old.iter().any(|id| {
                    p.catalog.get(id).is_ok_and(|root| {
                        text(&root.payload, "root_public_key").is_ok_and(|key| key == public(seed))
                    })
                })
            });
            let format = if requested_format == "auto" {
                if any_owned {
                    "ed25519"
                } else if old.len() == 1 {
                    "sshsig"
                } else {
                    return Err(Error::new("signer_unavailable"));
                }
            } else {
                requested_format
            };
            let mut payload = json!({"epoch":epoch,"predecessors":old,"resolves":if old.len()>1{old.clone()}else{Vec::<String>::new()},"migration_proposal_id":"-","root_public_key":if target=="-"{first.as_str()}else{target},"issued_at":p.decision_time,"retained_statement_ids":retained});
            // Validate exact roots, overflow, preservation and full fanout quota
            // before generating any new owned key.
            p.action(&actor(&old[0]), "root_state", &actions::bytes(&payload)?)?;
            let provisional = template(&p, &old, &payload, format, next_format)?;
            actions::preflight(&tx, &p, &s, &provisional)?;
            let total: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
                .map_err(db)?;
            let unsigned:i64=tx.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
            require(total < 4096 && unsigned < 64, "quota_exceeded")?;
            let secret = if target == "-" {
                let mut seed = [0; 32];
                getrandom::fill(&mut seed).map_err(|_| Error::new("internal"))?;
                payload["root_public_key"] = Value::from(public(&seed));
                Some(seed.to_vec())
            } else {
                None
            };
            let fixed = template(&p, &old, &payload, format, next_format)?;
            let operation = actions::action_id(
                &s.network.context_id,
                "root_state",
                fixed.statement_id(),
                "network_root",
            );
            require(
                matches!(actions::load(&tx,network,&operation,"action"),Err(e) if e.code=="not_found"),
                "operation_conflict",
            )?;
            let root_id = if old.len() == 1 {
                old[0].clone()
            } else {
                "-".into()
            };
            let scopes = if old.len() == 1 { 8 } else { 0 };
            let provider = json!({"kind":"network_root","person_public_key":"-","host_public_key":"-","device_public_key":"-","lease_id":"-","root_state_id":root_id,"scopes":scopes,"not_after":"-"});
            let review = json!({"kind":"root_state","statement_id":fixed.statement_id(),"provider":provider,"subject":{"root_public_key":payload["root_public_key"],"epoch":epoch},"sequence":epoch,"not_after":"-","authority_warning":"preserve only the exact reviewed finite authority; bounded proofs cannot establish that no unseen revocation exists"});
            i = Intent {
                id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
                network_id: network.into(),
                context_id: s.network.context_id.clone(),
                kind: "root_transition".into(),
                secret,
                record: Record {
                    format: 1,
                    operation_id: operation,
                    approved: false,
                    approved_at: "-".into(),
                    review_base64: encode(&actions::bytes(&review)?),
                    provider: Provider {
                        kind: "root".into(),
                        signer_public_key: first,
                        signature_format: format.into(),
                        lease_id: "-".into(),
                    },
                    root_state_id: root_id,
                    person_public_key: "-".into(),
                    host_public_key: store.identity().public_key,
                    device_public_key: "-".into(),
                    scopes,
                    not_after: "-".into(),
                    created_at: p.decision_time.clone(),
                    expires_at: actions::at(&p.decision_time, 300)?,
                    templates: vec![Template {
                        slot_id: 1,
                        object_type: "root_state".into(),
                        template_base64: encode(fixed.bytes()),
                    }],
                    signatures: Vec::new(),
                    completed: false,
                    terminal: "-".into(),
                    result_base64: "-".into(),
                },
            };
            validate(&i, &s.descriptor)?;
            new = true;
        }
        let approval = approve && !i.record.approved;
        if approval {
            i.record.approved = true;
            i.record.approved_at = p.decision_time.clone();
            actions::remember_clock(&tx, network, &p.decision_time)?;
        }
        let id = i.record.operation_id.clone();
        i.save(&tx)?;
        tx.commit().map_err(db)?;
        (id, new, approval)
    };
    if new {
        controls::barrier(store, "dec.intent.after_commit", &id)?;
    }
    if approval {
        controls::barrier(store, "dec.approval.after_commit", &id)?;
    }
    if approve {
        finish(store, network, &id)
    } else {
        get(store, network, &id)
    }
}
pub(crate) fn get(store: &Store, network: &str, id: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let i = load(&tx, network, id)?;
    if i.record.terminal == "applied" {
        return b64(&i.record.result_base64, 32 << 20);
    }
    let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let p = s.project(&controls::local_decision_time()?)?;
    current(&s, &p, &i)?;
    actions::response(&tx, &s, &p, &i)
}
fn finish(store: &Store, network: &str, id: &str) -> Result<Vec<u8>> {
    let changed = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut i = load(&tx, network, id)?;
        if i.record.terminal == "applied" {
            return b64(&i.record.result_base64, 32 << 20);
        }
        require(i.record.approved, "state_conflict")?;
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        let fixed = current(&s, &p, &i)?;
        actions::preflight(&tx, &p, &s, &fixed)?;
        let mut seeds = Vec::new();
        if let Some(seed) = owned(&tx, network)? {
            seeds.push(seed);
        }
        if let Some(seed) = &i.secret {
            seeds.push(
                seed.as_slice()
                    .try_into()
                    .map_err(|_| Error::new("state_conflict"))?,
            );
        }
        let mut changed = false;
        for slot in fixed.pending() {
            if let Some(seed) = seeds.iter().find(|seed| public(seed) == slot.public_key) {
                let message = b64(&slot.message_base64, 4096)?;
                let signature = match slot.signature_format.as_str() {
                    "ed25519" => encode(&SigningKey::from_bytes(seed).sign(&message).to_bytes()),
                    // An externally held sibling may need an SSH agent. The
                    // exact owned old-root role can use the same frozen SSHSIG
                    // format without exporting its seed or skipping a branch.
                    "sshsig" if slot.role != "new_root" => {
                        crate::persons::PersonSigner::File(SigningKey::from_bytes(seed))
                            .sign(
                                &std::str::from_utf8(&message)
                                    .map_err(|_| Error::new("invalid"))?
                                    .split('\n')
                                    .collect::<Vec<_>>(),
                            )
                            .map_err(|_| Error::new("signer_unavailable"))?
                    }
                    _ => continue,
                };
                fixed.fill(&s.descriptor, &slot.role, &signature)?;
                changed |= actions::add_signature(&mut i, &slot.role, &signature)?;
            }
        }
        if changed {
            i.record.completed = i.assembled(&s.descriptor)?[0].pending().is_empty();
            actions::remember_clock(&tx, network, &p.decision_time)?;
            i.save(&tx)?;
        }
        tx.commit().map_err(db)?;
        changed
    };
    if changed {
        controls::barrier(store, "dec.signature.after_commit", id)?;
    }
    controls::barrier(store, "dec.apply.before_transaction", id)?;
    let result = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let mut tx = c.transaction().map_err(db)?;
        let mut i = load(&tx, network, id)?;
        if i.record.terminal == "applied" {
            return b64(&i.record.result_base64, 32 << 20);
        }
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        let fixed = current(&s, &p, &i)?;
        actions::preflight(&tx, &p, &s, &fixed)?;
        let Some(signed) = fixed.signed(&s.descriptor)? else {
            return actions::response(&tx, &s, &p, &i);
        };
        let catalog = actions::candidate(&p, "root_state", &signed.body)?;
        let applied = s.apply_catalog(&mut tx, &catalog, &p.decision_time, "fresh")?;
        require(applied.root_state_id()? == signed.id, "state_conflict")?;
        tx.execute(
            "UPDATE networks SET root_seed=?2 WHERE id=?1",
            rusqlite::params![network, i.secret],
        )
        .map_err(db)?;
        let delivery = views::delivery(&tx, network, &s.network.context_id)?;
        let result = actions::bytes(
            &json!({"action_id":id,"review":actions::review(&i)?,"signing_requests":[],"statement_base64":encode(&signed.body),"proof_id":signed.proof_id,"catalog":parse(&applied.catalog.bytes,MAX_CATALOG)?,"committed":true,"delivery":delivery}),
        )?;
        i.secret = None;
        i.record.completed = true;
        i.record.terminal = "applied".into();
        i.record.result_base64 = encode(&result);
        i.save(&tx)?;
        crate::store::append_event(&tx, "network.root_rotated", network, &p.decision_time)
            .map_err(db)?;
        tx.commit().map_err(db)?;
        store
            .refresh_member_pins(&c)
            .map_err(|_| Error::new("internal"))?;
        result
    };
    controls::barrier(store, "dec.apply.after_commit", id)?;
    Ok(result)
}
pub(crate) fn signed(store: &Store, network: &str, id: &str, r: &Obj) -> Result<Vec<u8>> {
    fields(r, "intent_id signatures")?;
    let entries = array(r, "signatures")?;
    check(!entries.is_empty() && entries.len() <= 16)?;
    let changed = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut i = load(&tx, network, id)?;
        require(text(r, "intent_id")? == i.id, "invalid")?;
        require(i.record.approved, "state_conflict")?;
        let d = actions::descriptor(&tx, network)?;
        let applied = i.record.terminal == "applied";
        if !applied {
            let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
            let p = s.project(&controls::local_decision_time()?)?;
            let fixed = current(&s, &p, &i)?;
            actions::preflight(&tx, &p, &s, &fixed)?;
        }
        let mut previous = None;
        let mut changed = false;
        for entry in entries {
            let e = object(entry)?;
            fields(e, "slot_id role signature")?;
            let role = text(e, "role")?;
            let signature = text(e, "signature")?;
            check(num(e, "slot_id")? == 1 && previous.is_none_or(|old: &str| old < role))?;
            previous = Some(role);
            if applied {
                require(
                    i.record
                        .signatures
                        .iter()
                        .any(|s| s.slot_id == 1 && s.role == role && s.signature == signature),
                    "operation_conflict",
                )?;
            } else {
                i.assembled(&d)?[0].fill(&d, role, signature)?;
                changed |= actions::add_signature(&mut i, role, signature)?;
            }
        }
        if applied {
            return b64(&i.record.result_base64, 32 << 20);
        }
        i.record.completed = i.assembled(&d)?[0].pending().is_empty();
        let s = Snapshot::load(&tx, network, &store.identity().public_key)?;
        let p = s.project(&controls::local_decision_time()?)?;
        current(&s, &p, &i)?;
        actions::remember_clock(&tx, network, &p.decision_time)?;
        i.save(&tx)?;
        tx.commit().map_err(db)?;
        changed
    };
    if changed {
        controls::barrier(store, "dec.signature.after_commit", id)?;
    }
    finish(store, network, id)
}
