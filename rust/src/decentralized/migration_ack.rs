//! Own exact all-host cutover consent. Approval, owned signatures and the
//! irreversible fence are separate durable steps; none installs authority.
use super::{
    actions,
    codec::*,
    controls, creation,
    intents::{Filled, Intent, Provider, Record, Template},
    migration::{self, SourceContext},
    migration_evidence,
    migration_host::Context,
    migration_local,
    migration_prefix::Prefix,
    migration_prepare,
    statement::{Descriptor, Statement},
    storage::MigrationRecord,
    template::FixedStatement,
    transcript::Activation,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}

pub(super) fn prepared(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    at: &str,
) -> Result<BTreeMap<String, Activation>> {
    let root = p
        .root
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let catalog = p
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let proposal = &p.proposal.payload;
    let (_, facts) = migration::source_snapshot(
        SourceContext {
            descriptor: d,
            legacy_descriptor: &b64(text(proposal, "legacy_descriptor_base64")?, MAX_OBJECT)?,
            epoch: num(proposal, "legacy_epoch")?,
            feature: text(proposal, "legacy_feature_id")?,
            root: text(proposal, "legacy_root_public_key")?,
            now: text(proposal, "issued_at")?,
        },
        &b64(&r.source_catalog_base64, 512 << 10)?,
        &b64(&r.source_state_base64, MAX_PAYLOAD)?,
    )?;
    let components = migration::prepared_components(
        &p.proposal,
        &p.source,
        &b64(&r.source_catalog_base64, 512 << 10)?,
        &facts,
        catalog,
        &root.id,
    )?;
    let projection = super::state::Projection::stage_migration(
        d,
        &catalog.bytes,
        at,
        &p.proposal.id,
        &root.id,
        &p.source.maxima,
    )?;
    for row in array(proposal, "roster")? {
        let row = object(row)?;
        let host = text(row, "host_public_key")?;
        let h = catalog
            .statements
            .values()
            .find(|s| {
                s.kind == "host_lease"
                    && s.subject()
                        .is_ok_and(|v| text(v, "host_public_key").is_ok_and(|h| h == host))
            })
            .ok_or_else(|| Error::missing(&p.proposal.id))?;
        projection.active(&h.id)?;
        if let Some(a) = components.get(host) {
            for name in [
                "person_lease_id",
                "host_lease_id",
                "binding_lease_id",
                "device_lease_id",
            ] {
                projection.active(text(&a.manifest, name)?)?;
            }
        }
    }
    Ok(components)
}
pub(super) fn device_seed(
    c: &Connection,
    network: &str,
    host: &str,
    own: &Obj,
) -> Result<SigningKey> {
    let i = migration_local::approved_identity(c, network, host)?
        .ok_or_else(|| Error::new("review_required"))?;
    let reviewed = migration_local::validate_identity(&i, host)?;
    require(object(&reviewed)? == own, "operation_conflict")?;
    let public = text(own, "device_public_key")?;
    let key = if let Some(seed) = i.secret {
        let seed: [u8; 32] = seed.try_into().map_err(|_| Error::new("state_conflict"))?;
        SigningKey::from_bytes(&seed)
    } else {
        crate::link_runtime::persistence::device(c, public)
            .map_err(|_| Error::new("signer_unavailable"))?
    };
    require(
        encode(key.verifying_key().as_bytes()) == public,
        "signer_unavailable",
    )?;
    Ok(key)
}
fn payload(
    p: &Prefix,
    own: &Obj,
    components: &BTreeMap<String, Activation>,
    at: &str,
) -> Result<Value> {
    let catalog = p
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let host = text(own, "host_public_key")?;
    let h = catalog
        .statements
        .values()
        .find(|s| {
            s.kind == "host_lease"
                && s.subject()
                    .is_ok_and(|v| text(v, "host_public_key").is_ok_and(|h| h == host))
        })
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let a = components.get(host);
    check((text(own, "person_public_key")? == "-") == a.is_none())?;
    Ok(
        json!({"proposal_id":p.proposal.id,"root_state_id":p.root.as_ref().ok_or_else(||Error::missing(&p.proposal.id))?.id,
        "prepared_catalog_sha256":hash(&catalog.bytes),"host_public_key":host,
        "person_public_key":text(own,"person_public_key")?,"device_public_key":text(own,"device_public_key")?,
        "host_lease_id":h.id,"binding_lease_id":a.map_or(Ok("-"),|a|text(&a.manifest,"binding_lease_id"))?,
        "device_lease_id":a.map_or(Ok("-"),|a|text(&a.manifest,"device_lease_id"))?,
        "activation_id":a.map_or("-",|a|a.id.as_str()),"acknowledged_at":at}),
    )
}
fn template(d: &Descriptor, payload: &Value) -> Result<FixedStatement> {
    let p = object(payload)?;
    let host = text(p, "host_public_key")?;
    let device = text(p, "device_public_key")?;
    let mut signatures = Vec::new();
    if device != "-" {
        signatures
            .push(json!({"role":"device","public_key":device,"format":"ed25519","signature":"-"}));
    }
    signatures.push(json!({"role":"host","public_key":host,"format":"ed25519","signature":"-"}));
    FixedStatement::read(
        d,
        &actions::bytes(
            &json!({"format":1,"kind":"migration_ack","context_id":d.context_id(),
        "payload_base64":encode(&actions::bytes(payload)?),"signatures":signatures}),
        )?,
    )
}
// Count every still-missing ACK and a full root commit before any irreversible
// approval. Placeholder signatures are used only to bound bytes, never as proof.
pub(super) fn budget(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    components: &BTreeMap<String, Activation>,
    at: &str,
) -> Result<()> {
    let mut candidate = r.clone();
    let mut acks = BTreeMap::new();
    let mut ids = Vec::new();
    for row in array(&p.proposal.payload, "roster")? {
        let row = object(row)?;
        let host = text(row, "host_public_key")?;
        let body = if let Some(a) = p.acknowledgments.get(host) {
            ids.push(a.id.clone());
            a.body.clone()
        } else {
            let t = template(d, &payload(p, row, components, at)?)?;
            ids.push(t.statement_id().to_owned());
            t.budget_bytes()?
        };
        acks.insert(host.to_owned(), encode(&body));
    }
    candidate.acknowledgments_base64 = acks.into_values().collect();
    ids.sort();
    let root = text(&p.proposal.payload, "legacy_root_public_key")?;
    let commit = json!({"proposal_id":p.proposal.id,"root_state_id":p.root.as_ref().ok_or_else(||Error::missing(&p.proposal.id))?.id,
        "prepared_catalog_sha256":hash(&p.catalog.as_ref().ok_or_else(||Error::missing(&p.proposal.id))?.bytes),
        "acknowledgment_ids":ids,"committed_at":at});
    let fixed = FixedStatement::read(
        d,
        &actions::bytes(
            &json!({"format":1,"kind":"migration_commit","context_id":d.context_id(),
        "payload_base64":encode(&actions::bytes(&commit)?),"signatures":[{"role":"issuer","public_key":root,"format":"sshsig","signature":"-"}]}),
        )?,
    )?;
    candidate.commit_base64 = encode(&fixed.budget_bytes()?);
    Prefix::complete_body(&candidate)?;
    Ok(())
}
fn validated(
    d: &Descriptor,
    p: &Prefix,
    r: &MigrationRecord,
    i: &Intent,
    host: &str,
) -> Result<FixedStatement> {
    i.shape()?;
    let own = object(
        array(&p.proposal.payload, "roster")?
            .iter()
            .find(|r| r.get("host_public_key").and_then(Value::as_str) == Some(host))
            .ok_or_else(|| Error::new("forbidden"))?,
    )?;
    let rec = &i.record;
    check(
        i.kind == "migration"
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && i.secret.is_none()
            && rec.approved
            && rec.operation_id == p.proposal.id
            && rec.host_public_key == host
            && rec.person_public_key == text(own, "person_public_key")?
            && rec.device_public_key == text(own, "device_public_key")?
            && rec.templates.len() == 1
            && rec.templates[0].object_type == "migration_ack"
            && rec.terminal == "-"
            && rec.result_base64 == "-"
            && rec.expires_at == text(&p.proposal.payload, "expires_at")?,
    )?;
    let t = i
        .assembled(d)?
        .pop()
        .ok_or_else(|| Error::new("state_conflict"))?;
    let ack = t.typed();
    check(
        ack.kind == "migration_ack"
            && text(&ack.payload, "host_public_key")? == host
            && text(&ack.payload, "proposal_id")? == p.proposal.id
            && rec.created_at == text(&ack.payload, "acknowledged_at")?
            && rec.root_state_id == text(&ack.payload, "root_state_id")?
            && rec.completed == t.pending().is_empty(),
    )?;
    let components = prepared(d, p, r, &rec.created_at)?;
    check(ack.payload == object(&payload(p, own, &components, &rec.created_at)?)?.clone())?;
    if text(own, "person_public_key")? == "-" {
        check(
            rec.provider.kind == "host"
                && rec.provider.signer_public_key == host
                && rec.provider.lease_id == "-"
                && rec.scopes == 0,
        )?;
    } else {
        check(
            rec.provider.kind == "device"
                && rec.provider.signer_public_key == text(own, "device_public_key")?
                && rec.provider.lease_id == text(&ack.payload, "device_lease_id")?
                && rec.scopes == num(own, "scopes")?,
        )?;
    }
    let mut saved = object(&parse(&b64(&rec.review_base64, MAX_OBJECT)?, MAX_OBJECT)?)?.clone();
    let mut expected = object(&migration_evidence::review(d, p, r, "acknowledgment")?)?.clone();
    let warning = text(&saved, "authority_warning")?;
    check(!warning.is_empty() && warning.len() <= 2048)?;
    saved.remove("authority_warning");
    expected.remove("authority_warning");
    check(saved == expected)?;
    Ok(t)
}
fn wrapper(d: &Descriptor, p: &Prefix, r: &MigrationRecord, i: &Intent) -> Result<Vec<u8>> {
    actions::bytes(
        &json!({"migration":p.view(d,r)?,"review":parse(&b64(&i.record.review_base64,MAX_OBJECT)?,MAX_OBJECT)?,"signing_requests":[]}),
    )
}
fn result(store: &Store, network: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let (_, r) = migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
    let d = migration_evidence::descriptor(&r)?;
    let p = Prefix::read(&d, &r)?;
    let i = Intent::load(&tx, &r.local_ack_intent_id)?;
    validated(&d, &p, &r, &i, &store.identity().public_key)?;
    wrapper(&d, &p, &r, &i)
}
pub(crate) fn acknowledge(store: &Store, network: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "proposal_id prepared_catalog_sha256 approve")?;
    let proposal = text(input, "proposal_id")?;
    let digest = text(input, "prepared_catalog_sha256")?;
    check(ident(proposal, "ds_") && super::codec::digest(digest))?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let host = store.identity().public_key;
    let fresh = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let (id, r) =
            migration_prepare::load(&tx, network)?.ok_or_else(|| Error::new("not_found"))?;
        require(id == proposal, "operation_conflict")?;
        let d = migration_evidence::descriptor(&r)?;
        let p = Prefix::read(&d, &r)?;
        require(
            p.catalog.as_ref().is_some_and(|c| hash(&c.bytes) == digest),
            "operation_conflict",
        )?;
        if r.local_ack_intent_id != "-" {
            let i = Intent::load(&tx, &r.local_ack_intent_id)?;
            validated(&d, &p, &r, &i, &host)?;
            if r.fenced || !approve {
                return wrapper(&d, &p, &r, &i);
            }
            false
        } else {
            let mut context = Context::load(store, &tx, network, proposal)?;
            let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
            decision_clock(&now, &context.source.time)?;
            require(
                now.as_str() < text(&p.proposal.payload, "expires_at")?,
                "expired",
            )?;
            let components = prepared(&d, &p, &r, &now)?;
            if text(&context.own, "person_public_key")? != "-" {
                device_seed(&tx, network, &host, &context.own)?;
            }
            budget(&d, &p, &r, &components, &now)?;
            let t = template(&d, &payload(&p, &context.own, &components, &now)?)?;
            if !approve {
                return migration_evidence::wrapper(&d, &p, &r, "acknowledgment");
            }
            let total: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
                .map_err(db)?;
            let open:i64=tx.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
            require(total < 4096 && open < 64, "quota_exceeded")?;
            let person = text(&context.own, "person_public_key")?;
            let device = text(&context.own, "device_public_key")?;
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
                        "acknowledgment",
                    )?)?),
                    provider: Provider {
                        kind: if person == "-" { "host" } else { "device" }.into(),
                        signer_public_key: if person == "-" {
                            host.clone()
                        } else {
                            device.into()
                        },
                        signature_format: "ed25519".into(),
                        lease_id: text(&t.typed().payload, "device_lease_id")?.into(),
                    },
                    root_state_id: text(&t.typed().payload, "root_state_id")?.into(),
                    person_public_key: person.into(),
                    host_public_key: host.clone(),
                    device_public_key: device.into(),
                    scopes: num(&context.own, "scopes")?,
                    not_after: "-".into(),
                    created_at: now.clone(),
                    expires_at: text(&p.proposal.payload, "expires_at")?.into(),
                    templates: vec![Template {
                        slot_id: 1,
                        object_type: "migration_ack".into(),
                        template_base64: encode(t.bytes()),
                    }],
                    signatures: vec![],
                    completed: false,
                    terminal: "-".into(),
                    result_base64: "-".into(),
                },
            };
            validated(&d, &p, &r, &i, &host)?;
            context.record.local_ack_intent_id = i.id.clone();
            i.save(&tx)?;
            migration_prepare::save(&tx, network, proposal, &context.record)?;
            creation::remember_clock(&tx, network, &now)?;
            tx.commit().map_err(db)?;
            true
        }
    };
    if fresh {
        controls::barrier(store, "dec.intent.after_commit", proposal)?;
        controls::barrier(store, "dec.approval.after_commit", proposal)?;
    }
    advance(store, network)?;
    result(store, network)
}
pub(super) fn advance(store: &Store, network: &str) -> Result<()> {
    let host = store.identity().public_key;
    let (proposal, changed) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let Some((proposal, r)) = migration_prepare::load(&tx, network)? else {
            return Ok(());
        };
        if r.local_ack_intent_id == "-" || r.fenced {
            return Ok(());
        }
        let mut i = Intent::load(&tx, &r.local_ack_intent_id)?;
        let context = Context::load(store, &tx, network, &proposal)?;
        let d = &context.source.descriptor;
        let t = validated(d, &context.prefix, &r, &i, &host)?;
        let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        require(
            now.as_str() < text(&context.prefix.proposal.payload, "expires_at")?,
            "expired",
        )?;
        prepared(d, &context.prefix, &r, &now)?;
        let device = if i.record.device_public_key != "-" {
            Some(device_seed(&tx, network, &host, &context.own)?)
        } else {
            None
        };
        let mut changed = false;
        for slot in t.pending() {
            let key = match slot.role.as_str() {
                "host" => &store.signing_key,
                "device" => device
                    .as_ref()
                    .ok_or_else(|| Error::new("signer_unavailable"))?,
                _ => return Err(Error::new("invalid")),
            };
            check(encode(key.verifying_key().as_bytes()) == slot.public_key)?;
            let sig = encode(&key.sign(&b64(&slot.message_base64, 4096)?).to_bytes());
            t.fill(d, &slot.role, &sig)?;
            i.record.signatures.push(Filled {
                slot_id: 1,
                role: slot.role,
                signature: sig,
            });
            changed = true;
        }
        i.record
            .signatures
            .sort_by(|a, b| (a.slot_id, &a.role).cmp(&(b.slot_id, &b.role)));
        i.record.completed = i.assembled(d)?[0].pending().is_empty();
        require(i.record.completed, "state_conflict")?;
        validated(d, &context.prefix, &r, &i, &host)?;
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
    let changed = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let context = Context::load(store, &tx, network, &proposal)?;
        let mut r = context.record;
        let d = &context.source.descriptor;
        let i = Intent::load(&tx, &r.local_ack_intent_id)?;
        let t = validated(d, &context.prefix, &r, &i, &host)?;
        require(t.pending().is_empty(), "review_required")?;
        let now = creation::decision(&tx, network, &controls::local_decision_time()?)?;
        require(
            now.as_str() < text(&context.prefix.proposal.payload, "expires_at")?,
            "expired",
        )?;
        prepared(d, &context.prefix, &r, &now)?;
        let ack = Statement::read(d, t.bytes())?;
        let mut acks = context.prefix.acknowledgments;
        if let Some(old) = acks.get(&host) {
            require(old.body == ack.body, "operation_conflict")?;
        }
        acks.insert(host, ack.clone());
        r.local_acknowledgment_base64 = encode(&ack.body);
        r.acknowledgments_base64 = acks.into_values().map(|a| encode(&a.body)).collect();
        r.fenced = true;
        r.state = "acknowledged".into();
        Prefix::complete_body(&r)?;
        Prefix::read(d, &r)?;
        migration_prepare::save(&tx, network, &proposal, &r)?;
        creation::remember_clock(&tx, network, &now)?;
        tx.commit().map_err(db)?;
        true
    };
    if changed {
        controls::barrier(store, "dec.migration_fence.after_commit", &proposal)?;
    }
    Ok(())
}
