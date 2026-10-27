//! Final requester consent is fixed before binding/packet signing and framing.
use super::{bytes, db, retain_outbound};
use crate::{
    decentralized::{
        catalog::{Catalog, raw_field},
        codec::*,
        controls,
        intents::{Filled, Intent, Provider, Record, Template},
        observer::{self, Offer},
        requests::{self, Pending},
        state::{CeremonyPrefix, PreparedFinalization, Projection},
        statement::{Descriptor, Statement},
        storage::Snapshot,
        template::FixedStatement,
        transcript::{Activation, Packet},
    },
    store::Store,
};
use ed25519_dalek::Signer;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;

struct Context {
    offer: Offer,
    prepared: PreparedFinalization,
    now: String,
}
fn context(c: &Connection, store: &Store, p: &Pending) -> Result<Context> {
    require(
        p.record.selection_approved && p.record.selection_packet_base64 != "-",
        "state_conflict",
    )?;
    require(
        p.record.owner_finalization_packet_base64 != "-",
        "proof_required",
    )?;
    let (offer, now) = super::approval::commit_context(c, store, p, &p.record.owner_offer_id)?;
    let request = p.packet()?;
    let selection = Packet::read(&b64(&p.record.selection_packet_base64, MAX_OBJECT)?)?;
    let finalization = Packet::read(&b64(
        &p.record.owner_finalization_packet_base64,
        MAX_OBJECT,
    )?)?;
    let administrator = if p.record.administrator_packet_base64 == "-" {
        None
    } else {
        Some(Packet::read(&b64(
            &p.record.administrator_packet_base64,
            MAX_OBJECT,
        )?)?)
    };
    let present: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [&offer.descriptor.network_id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let prior = if present && offer.staging.is_none() {
        Snapshot::load(
            c,
            &offer.descriptor.network_id,
            &store.identity().public_key,
        )?
        .prior
        .value
    } else {
        Value::from("-")
    };
    let catalog = offer
        .catalog
        .as_ref()
        .ok_or_else(|| Error::new("proof_required"))?;
    let prepared = Projection::prepare_finalization(
        CeremonyPrefix {
            descriptor: &offer.descriptor,
            prior: &prior,
            catalog,
            request: &request,
            owner: &offer.owner,
            selection: &selection,
            administrator: administrator.as_ref(),
            now: &now,
            staging: offer.staging.as_ref(),
        },
        &finalization,
    )?;
    Ok(Context {
        offer,
        prepared,
        now,
    })
}
fn review(p: &Pending, stage: &Context) -> Result<Value> {
    let mut review = stage.offer.review(p, "commit")?;
    review["root_state_id"] = json!(stage.prepared.admissions.root);
    review["person_lease_id"] = json!(stage.prepared.admissions.person.id);
    review["host_lease_id"] = json!(stage.prepared.admissions.host.id);
    review["binding_lease_id"] = json!(stage.prepared.binding.id);
    review["device_lease_id"] = json!(stage.prepared.device.id);
    Ok(review)
}
pub(super) fn check_reference(
    p: &Pending,
    i: &Intent,
    d: &Descriptor,
    owner: &Packet,
) -> Result<()> {
    let r = &i.record;
    check(
        i.kind == "requester_commit"
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && r.operation_id == p.id
            && i.secret.is_none()
            && r.provider.kind == "requester"
            && r.provider.signer_public_key == p.record.device_public_key
            && r.person_public_key == text(&owner.object, "person_public_key")?
            && r.host_public_key == p.record.host_public_key
            && r.device_public_key == p.record.device_public_key
            && r.scopes == num(&owner.payload, "scopes")?
            && r.not_after == text(&owner.payload, "not_after")?
            && r.expires_at == p.deadline
            && r.created_at.as_str() >= text(&p.packet()?.payload, "created_at")?,
    )?;
    let f = Packet::read(&b64(
        &p.record.owner_finalization_packet_base64,
        MAX_OBJECT,
    )?)?;
    check(r.root_state_id == text(&f.payload, "root_state_id")?)?;
    let new_binding = f.payload["binding_lease"].is_object();
    check(r.templates.len() == if new_binding { 2 } else { 1 })?;
    if new_binding {
        check(
            r.templates[0].object_type == "binding_lease"
                && b64(&r.templates[0].template_base64, MAX_OBJECT)?
                    == raw_field(&f.payload_bytes, "binding_lease")?,
        )?;
    }
    let template = r
        .templates
        .last()
        .ok_or_else(|| Error::new("state_conflict"))?;
    check(template.object_type == "commit_packet")?;
    let objects = i.objects(d)?;
    let complete = objects.iter().all(|o| {
        o.as_ref()
            .is_some_and(|o| o.pending().is_ok_and(|s| s.is_empty()))
    });
    check(r.completed == complete)?;
    let review = parse(&b64(&r.review_base64, MAX_OBJECT)?, MAX_OBJECT)?;
    let review = object(&review)?;
    fields(
        review,
        "stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning",
    )?;
    for (field, want) in [
        ("stage", "commit"),
        ("network_id", d.network_id.as_str()),
        ("context_id", d.context_id().as_str()),
        ("person_public_key", r.person_public_key.as_str()),
        ("host_public_key", r.host_public_key.as_str()),
        ("device_public_key", r.device_public_key.as_str()),
        ("root_state_id", r.root_state_id.as_str()),
        ("owner_offer_id", p.record.owner_offer_id.as_str()),
        ("selection_id", p.record.selection_id.as_str()),
        (
            "administrator_offer_id",
            p.record.administrator_offer_id.as_str(),
        ),
        ("person_lease_id", text(&f.payload, "person_lease_id")?),
        ("host_lease_id", text(&f.payload, "host_lease_id")?),
    ] {
        check(text(review, field)? == want)?
    }
    let device = Statement::read(d, &raw_field(&f.payload_bytes, "device_lease")?)?;
    let binding_id = if new_binding {
        Statement::read_draft(d, &raw_field(&f.payload_bytes, "binding_lease")?, true)?.id
    } else {
        text(&f.payload, "binding_lease")?.into()
    };
    check(
        text(review, "binding_lease_id")? == binding_id
            && text(review, "device_lease_id")? == device.id
            && num(review, "scopes")? == r.scopes
            && text(review, "not_after")? == r.not_after,
    )?;
    if let Some(value) = objects.last().and_then(Option::as_ref) {
        let packet = Packet::read_template(value.bytes())?;
        check(
            text(&packet.object, "role")? == "commit"
                && text(&packet.object, "request_id")? == p.id
                && text(&packet.object, "writer_host_public_key")? == r.host_public_key
                && text(&packet.object, "signer_public_key")? == r.device_public_key
                && text(&packet.object, "person_public_key")? == r.person_public_key,
        )?;
        let manifest = parse(
            &b64(text(&packet.payload, "manifest_base64")?, 16 << 10)?,
            16 << 10,
        )?;
        let m = object(&manifest)?;
        for (field, want) in [
            ("context_id", i.context_id.as_str()),
            ("request_id", p.id.as_str()),
            ("request_packet_id", p.packet()?.id.as_str()),
            ("owner_offer_id", p.record.owner_offer_id.as_str()),
            ("selection_id", p.record.selection_id.as_str()),
            (
                "administrator_offer_id",
                p.record.administrator_offer_id.as_str(),
            ),
            (
                "owner_finalization_id",
                p.record.owner_finalization_id.as_str(),
            ),
            ("root_state_id", r.root_state_id.as_str()),
            ("person_lease_id", text(&f.payload, "person_lease_id")?),
            ("host_lease_id", text(&f.payload, "host_lease_id")?),
            ("binding_lease_id", binding_id.as_str()),
            ("device_lease_id", device.id.as_str()),
            ("device_proof_id", device.proof_id.as_str()),
        ] {
            check(text(m, field)? == want)?
        }
        let binding_signature = if new_binding {
            let b = Statement::read(
                d,
                objects[0]
                    .as_ref()
                    .ok_or_else(|| Error::new("state_conflict"))?
                    .bytes(),
            )?;
            check(text(m, "binding_proof_id")? == b.proof_id)?;
            b.signer("host")?.signature.clone()
        } else {
            "-".into()
        };
        check(text(&packet.payload, "binding_host_signature")? == binding_signature)?;
        let at = stamp(text(&packet.payload, "committed_at")?)?;
        check(at >= stamp(&r.created_at)? && at < stamp(&p.deadline)?)?;
        if p.record.commit_packet_base64 != "-" {
            check(r.completed && b64(&p.record.commit_packet_base64, MAX_OBJECT)? == value.bytes())?
        }
    } else {
        check(p.record.commit_packet_base64 == "-")?
    }
    Ok(())
}
fn check_current(p: &Pending, i: &Intent, stage: &Context) -> Result<()> {
    check_reference(p, i, &stage.offer.descriptor, &stage.offer.owner)?;
    check(parse(&b64(&i.record.review_base64, MAX_OBJECT)?, MAX_OBJECT)? == review(p, stage)?)
}
fn new_intent(c: &Connection, p: &Pending, stage: &Context) -> Result<Intent> {
    let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE kind='requester_commit' AND json_extract(record,'$.operation_id')=?1 ORDER BY intent_id").map_err(db)?;
    let ids = q
        .query_map([&p.id], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    check(ids.len() <= 1)?;
    if let Some(id) = ids.first() {
        let i = Intent::load(c, id)?;
        check_current(p, &i, stage)?;
        return Ok(i);
    }
    let total: i64 = c
        .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
        .map_err(db)?;
    let active:i64=c.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
    require(total < 4096 && active < 64, "quota_exceeded")?;
    let mut templates = Vec::new();
    if !stage.prepared.reused_binding {
        templates.push(Template {
            slot_id: 1,
            object_type: "binding_lease".into(),
            template_base64: encode(&stage.prepared.binding.body),
        })
    }
    templates.push(Template {
        slot_id: templates.len() as u64 + 1,
        object_type: "commit_packet".into(),
        template_base64: "-".into(),
    });
    Ok(Intent {
        id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
        network_id: stage.offer.descriptor.network_id.clone(),
        context_id: stage.offer.descriptor.context_id(),
        kind: "requester_commit".into(),
        secret: None,
        record: Record {
            format: 1,
            operation_id: p.id.clone(),
            approved: false,
            approved_at: "-".into(),
            review_base64: encode(&bytes(&review(p, stage)?)?),
            provider: Provider {
                kind: "requester".into(),
                signer_public_key: p.record.device_public_key.clone(),
                signature_format: "ed25519".into(),
                lease_id: "-".into(),
            },
            root_state_id: stage.prepared.admissions.root.clone(),
            person_public_key: text(&stage.offer.owner.object, "person_public_key")?.into(),
            host_public_key: p.record.host_public_key.clone(),
            device_public_key: p.record.device_public_key.clone(),
            scopes: num(&stage.offer.owner.payload, "scopes")?,
            not_after: text(&stage.offer.owner.payload, "not_after")?.into(),
            created_at: stage.now.clone(),
            expires_at: p.deadline.clone(),
            templates,
            signatures: Vec::new(),
            completed: false,
            terminal: "-".into(),
            result_base64: "-".into(),
        },
    })
}
fn budget(c: &Connection, store: &Store, p: &Pending, stage: &Context) -> Result<()> {
    let frames = requests::frames(c, p)?;
    // Placeholder signature bytes are size accounting only, never proofs.
    let mut proofs = stage.prepared.admissions.catalog.proofs.clone();
    let binding = if stage.prepared.reused_binding {
        stage.prepared.binding.body.clone()
    } else {
        FixedStatement::read(&stage.offer.descriptor, &stage.prepared.binding.body)?
            .budget_bytes()?
    };
    let binding_proof = crate::decentralized::statement::proof_id("binding_lease", &binding);
    for s in [
        &stage.prepared.admissions.person,
        &stage.prepared.admissions.host,
        &stage.prepared.device,
    ] {
        proofs.insert(
            s.proof_id.clone(),
            crate::decentralized::catalog::Proof {
                id: s.proof_id.clone(),
                kind: s.kind.clone(),
                body: s.body.clone(),
            },
        );
    }
    proofs.insert(
        binding_proof.clone(),
        crate::decentralized::catalog::Proof {
            id: binding_proof.clone(),
            kind: "binding_lease".into(),
            body: binding,
        },
    );
    require(
        proofs.len() <= 4096 && proofs.values().map(|p| p.body.len()).sum::<usize>() <= MAX_DECODED,
        "quota_exceeded",
    )?;
    let mut rows = Vec::new();
    for proof in proofs.values() {
        require(proof.body.len() <= MAX_OBJECT, "quota_exceeded")?;
        rows.push(json!({"id":proof.id,"kind":proof.kind,"body_base64":encode(&proof.body)}))
    }
    let whole = bytes(
        &json!({"format":1,"context_id":stage.offer.descriptor.context_id(),"objects":rows}),
    )?;
    require(whole.len() <= MAX_CATALOG, "quota_exceeded")?;
    if stage.offer.staging.is_some() {
        let m = manifest(p, stage, &binding_proof, proofs.keys().cloned().collect())?;
        let signature = encode(&[0u8; 64]);
        let payload = bytes(
            &json!({"manifest_base64":encode(&m),"binding_host_signature":if stage.prepared.reused_binding {"-"}else{signature.as_str()},"committed_at":stage.now}),
        )?;
        let packet = bytes(
            &json!({"format":1,"context_id":stage.offer.descriptor.context_id(),"request_id":p.id,"role":"commit","writer_host_public_key":p.record.host_public_key,"signer_public_key":p.record.device_public_key,"person_public_key":text(&stage.offer.owner.object,"person_public_key")?,"issuer_id":"-","payload_base64":encode(&payload),"host_signature":signature,"device_signature":signature,"authority_signature_format":"-","authority_signature":"-"}),
        )?;
        let activation = activation_bytes(p, &packet)?;
        let proof = crate::decentralized::statement::proof_id("activation", &activation);
        let mut prepared_rows = rows.clone();
        prepared_rows
            .push(json!({"id":proof,"kind":"activation","body_base64":encode(&activation)}));
        prepared_rows.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        require(prepared_rows.len() <= 4096, "quota_exceeded")?;
        let prepared = bytes(
            &json!({"format":1,"context_id":stage.offer.descriptor.context_id(),"objects":prepared_rows}),
        )?;
        crate::decentralized::migration_link::pending_budget(store, c, p, &prepared, &stage.now)?;
    }
    require(
        manifest(p, stage, &binding_proof, proofs.keys().cloned().collect())?.len() <= 16 << 10,
        "quota_exceeded",
    )?;
    let components = components(&stage.offer.descriptor.context_id(), rows)?;
    let mut required = 0usize;
    for raw in &components {
        required +=
            bytes(&json!({"packet_base64":"-","catalog_base64":encode(raw),"contacts":[]}))?.len()
                + 16;
    }
    // One packet's maximum is independent of the catalog-component budget.
    required += bytes(
        &json!({"packet_base64":encode(&vec![0;MAX_OBJECT]),"catalog_base64":"-","contacts":[]}),
    )?
    .len()
        + 16;
    require(
        frames.len() + components.len() < 64
            && frames.iter().map(|f| f.ciphertext.len()).sum::<usize>() + required <= 32 << 20,
        "quota_exceeded",
    )
}
pub(super) fn approve(store: &Store, id: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(
        input,
        "owner_offer_id selection_id administrator_offer_id owner_finalization_id network_id context_id person_public_key host_public_key device_public_key approve",
    )?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    if p.record.terminal == "applied" {
        return super::approval::historical(
            &p,
            &Intent::load(&tx, &p.record.commit_intent_id)?,
            input,
            true,
        );
    }
    let stage = context(&tx, store, &p)?;
    super::approval::pins(input, &p, &stage.offer)?;
    for (name, want) in [
        ("owner_offer_id", p.record.owner_offer_id.as_str()),
        ("selection_id", p.record.selection_id.as_str()),
        (
            "administrator_offer_id",
            p.record.administrator_offer_id.as_str(),
        ),
        (
            "owner_finalization_id",
            p.record.owner_finalization_id.as_str(),
        ),
    ] {
        let actual = text(input, name)?;
        check(actual == want || !approve && actual == "-")?
    }
    let mut i = if p.record.commit_intent_id == "-" {
        new_intent(&tx, &p, &stage)?
    } else {
        Intent::load(&tx, &p.record.commit_intent_id)?
    };
    check_current(&p, &i, &stage)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM dec_intents WHERE intent_id=?1)",
            [&i.id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let changed = approve && !p.record.commit_approved;
    if changed {
        observer::owned_device(store, &tx, &p)?;
        budget(&tx, store, &p, &stage)?;
        i.record.approved = true;
        i.record.approved_at = stage.now.clone();
        p.record.commit_approved = true;
        p.record.commit_intent_id = i.id.clone()
    }
    i.save(&tx)?;
    requests::save(&tx, &p)?;
    controls::remember_decision(&tx, &i.network_id, &stage.now)?;
    let response = bytes(
        &json!({"request":p.view(&stage.now)?,"review":parse(&b64(&i.record.review_base64,MAX_OBJECT)?,MAX_OBJECT)?}),
    )?;
    tx.commit().map_err(db)?;
    drop(c);
    if !exists {
        controls::barrier(store, "dec.intent.after_commit", id)?
    }
    if changed {
        controls::barrier(store, "dec.approval.after_commit", id)?
    }
    if approve {
        resume(store, id)?;
        return response_now(store, id);
    }
    Ok(response)
}
fn response_now(store: &Store, id: &str) -> Result<Vec<u8>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let p = requests::load(&c, id)?;
    let i = Intent::load(&c, &p.record.commit_intent_id)?;
    bytes(
        &json!({"request":p.view(&controls::local_decision_time()?)?,"review":parse(&b64(&i.record.review_base64,MAX_OBJECT)?,MAX_OBJECT)?}),
    )
}

fn public_catalog(p: &Pending, i: &Intent, stage: &Context) -> Result<(Catalog, Statement)> {
    let d = &stage.offer.descriptor;
    let binding = if stage.prepared.reused_binding {
        stage.prepared.binding.clone()
    } else {
        Statement::read(
            d,
            i.objects(d)?[0]
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?
                .bytes(),
        )?
    };
    let mut objects = BTreeMap::new();
    for s in [
        &stage.prepared.admissions.person,
        &stage.prepared.admissions.host,
        &binding,
        &stage.prepared.device,
    ] {
        // The actual raw envelope is independently signed and retained before
        // publication. No fake standalone serialization is manufactured.
        Statement::read(d, &s.body)?;
        objects.insert(
            s.proof_id.clone(),
            json!({"id":s.proof_id,"kind":s.kind,"body_base64":encode(&s.body)}),
        );
    }
    let addition = Catalog::read(
        d,
        &bytes(
            &json!({"format":1,"context_id":d.context_id(),"objects":objects.into_values().collect::<Vec<_>>()}),
        )?,
    )?;
    let mut catalog = Catalog::union(d, &stage.prepared.admissions.catalog, &addition)?;
    if stage.offer.staging.is_some() && p.record.commit_packet_base64 != "-" {
        let commit = Packet::read(&b64(&p.record.commit_packet_base64, MAX_OBJECT)?)?;
        let manifest = parse(
            &b64(text(&commit.payload, "manifest_base64")?, 16 << 10)?,
            16 << 10,
        )?;
        let mut rows = Vec::new();
        for id in ids(object(&manifest)?, "proof_ids", "dp_")? {
            let proof = catalog.proof(&id)?;
            rows.push(json!({"id":id,"kind":proof.kind,"body_base64":encode(&proof.body)}));
        }
        catalog = Catalog::read(
            d,
            &bytes(&json!({"format":1,"context_id":d.context_id(),"objects":rows}))?,
        )?;
    }
    // A current activation cannot be an input to its own manifest.
    for (proof, _) in catalog.activation_proofs() {
        check(Activation::read(d, &proof.body)?.request_id != p.id)?
    }
    Ok((catalog, binding))
}
fn manifest(
    p: &Pending,
    stage: &Context,
    binding_proof: &str,
    proofs: Vec<String>,
) -> Result<Vec<u8>> {
    bytes(
        &json!({"format":1,"context_id":stage.offer.descriptor.context_id(),"request_id":p.id,"request_packet_id":p.packet()?.id,"owner_offer_id":p.record.owner_offer_id,"selection_id":p.record.selection_id,"administrator_offer_id":p.record.administrator_offer_id,"owner_finalization_id":p.record.owner_finalization_id,"root_state_id":stage.prepared.admissions.root,"person_lease_id":stage.prepared.admissions.person.id,"host_lease_id":stage.prepared.admissions.host.id,"binding_lease_id":stage.prepared.binding.id,"device_lease_id":stage.prepared.device.id,"binding_proof_id":binding_proof,"device_proof_id":stage.prepared.device.proof_id,"ancestor_statement_ids":stage.prepared.ancestor_statement_ids,"proof_ids":proofs}),
    )
}
fn materialize(p: &Pending, i: &Intent, stage: &Context) -> Result<Vec<u8>> {
    let (catalog, binding) = public_catalog(p, i, stage)?;
    let d = &stage.offer.descriptor;
    let m = manifest(
        p,
        stage,
        &binding.proof_id,
        catalog.proofs.keys().cloned().collect(),
    )?;
    require(m.len() <= 16 << 10, "quota_exceeded")?;
    let payload = bytes(
        &json!({"manifest_base64":encode(&m),"binding_host_signature":if stage.prepared.reused_binding {"-"} else {binding.signer("host")?.signature.as_str()},"committed_at":stage.now}),
    )?;
    let raw = bytes(
        &json!({"format":1,"context_id":d.context_id(),"request_id":p.id,"role":"commit","writer_host_public_key":p.record.host_public_key,"signer_public_key":p.record.device_public_key,"person_public_key":i.record.person_public_key,"issuer_id":"-","payload_base64":encode(&payload),"host_signature":"-","device_signature":"-","authority_signature_format":"-","authority_signature":"-"}),
    )?;
    Packet::read_template(&raw)?;
    Ok(raw)
}
pub(crate) fn activation_bytes(p: &Pending, commit: &[u8]) -> Result<Vec<u8>> {
    let mut fields: BTreeMap<&str, Box<serde_json::value::RawValue>> = BTreeMap::new();
    fields.insert(
        "format",
        serde_json::value::to_raw_value(&1).map_err(|_| Error::new("internal"))?,
    );
    fields.insert(
        "context_id",
        serde_json::value::to_raw_value(
            &Descriptor::read(&b64(&p.record.descriptor_base64, MAX_OBJECT)?)?.context_id(),
        )
        .map_err(|_| Error::new("internal"))?,
    );
    for (field, raw) in [
        ("request", b64(&p.record.request_packet_base64, MAX_OBJECT)?),
        ("owner", b64(&p.record.owner_packet_base64, MAX_OBJECT)?),
        (
            "selection",
            b64(&p.record.selection_packet_base64, MAX_OBJECT)?,
        ),
        (
            "administrator",
            if p.record.administrator_packet_base64 == "-" {
                b"\"-\"".to_vec()
            } else {
                b64(&p.record.administrator_packet_base64, MAX_OBJECT)?
            },
        ),
        (
            "owner_finalization",
            b64(&p.record.owner_finalization_packet_base64, MAX_OBJECT)?,
        ),
        ("commit", commit.to_vec()),
    ] {
        fields.insert(
            field,
            serde_json::from_slice(&raw).map_err(|_| Error::new("invalid"))?,
        );
    }
    let raw = bytes(&fields)?;
    require(raw.len() <= MAX_OBJECT, "quota_exceeded")?;
    Ok(raw)
}
pub(super) fn resume(store: &Store, id: &str) -> Result<()> {
    // Each pass commits exactly one dependency/signature/frame phase, releases
    // the writer guard, then exposes that real durable boundary.
    loop {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut p = requests::load(&tx, id)?;
        if !p.record.commit_approved
            || (p.record.terminal != "-" && p.record.terminal != "migration_prepared")
            || (p.record.terminal == "migration_prepared"
                && stamp(&controls::local_decision_time()?)? >= stamp(&p.deadline)?)
            || super::approval::framed(&p, "commit")
        {
            return Ok(());
        }
        let stage = context(&tx, store, &p)?;
        let d = &stage.offer.descriptor;
        let mut i = Intent::load(&tx, &p.record.commit_intent_id)?;
        check_current(&p, &i, &stage)?;
        let objects = i.objects(d)?;
        let binding_missing = !stage.prepared.reused_binding
            && !objects[0]
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?
                .pending()?
                .is_empty();
        let barrier = if binding_missing {
            budget(&tx, store, &p, &stage)?;
            let value = objects[0]
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?;
            for slot in value.pending()? {
                check(
                    slot.role == "host"
                        && slot.public_key == p.record.host_public_key
                        && slot.signature_format == "ed25519",
                )?;
                i.record.signatures.push(Filled {
                    slot_id: 1,
                    role: slot.role,
                    signature: encode(
                        &store
                            .signing_key
                            .sign(&b64(&slot.message_base64, 4096)?)
                            .to_bytes(),
                    ),
                })
            }
            i.save(&tx)?;
            "dec.signature.after_commit"
        } else if i
            .record
            .templates
            .last()
            .ok_or_else(|| Error::new("state_conflict"))?
            .template_base64
            == "-"
        {
            let raw = materialize(&p, &i, &stage)?;
            i.record
                .templates
                .last_mut()
                .ok_or_else(|| Error::new("state_conflict"))?
                .template_base64 = encode(&raw);
            i.save(&tx)?;
            requests::save(&tx, &p)?;
            "dec.intent.after_commit"
        } else if !i.record.completed {
            budget(&tx, store, &p, &stage)?;
            let device = observer::owned_device(store, &tx, &p)?;
            let index = i.record.templates.len() - 1;
            for slot in objects[index]
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?
                .pending()?
            {
                let key = match slot.role.as_str() {
                    "host" if slot.public_key == p.record.host_public_key => &store.signing_key,
                    "device" if slot.public_key == p.record.device_public_key => &device,
                    _ => return Err(Error::new("state_conflict")),
                };
                i.record.signatures.push(Filled {
                    slot_id: index as u64 + 1,
                    role: slot.role,
                    signature: encode(&key.sign(&b64(&slot.message_base64, 4096)?).to_bytes()),
                });
            }
            i.record
                .signatures
                .sort_by(|a, b| (&a.slot_id, &a.role).cmp(&(&b.slot_id, &b.role)));
            i.record.completed = true;
            let assembled = i.objects(d)?;
            let raw = assembled[index]
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?
                .bytes();
            let a = Activation::read(d, &activation_bytes(&p, raw)?)?;
            let full = verify_complete(&tx, store, &p, &i, &stage, raw)?;
            p.record.commit_packet_base64 = encode(raw);
            p.record.manifest_id = a.manifest_id;
            p.record.activation_id = a.id;
            check_current(&p, &i, &stage)?;
            i.save(&tx)?;
            if p.record.migration_proposal_id != "-" {
                p.record.catalog_base64 = encode(&full.bytes);
                crate::decentralized::migration_link::retain_prepared(store, &tx, &mut p)?;
            }
            requests::save(&tx, &p)?;
            "dec.signature.after_commit"
        } else {
            let (catalog, _) = public_catalog(&p, &i, &stage)?;
            let raw = b64(&p.record.commit_packet_base64, MAX_OBJECT)?;
            let full = verify_complete(&tx, store, &p, &i, &stage, &raw)?;
            // Proof-only frames retain exact whole objects; packet frame refers
            // to the same fixed closure without crossing the2MiB component cap.
            retain_catalog(&tx, store, &mut p, &catalog, &stage.now)?;
            retain_outbound(&tx, store, &mut p, "commit", &raw, "-", &stage.now)?;
            p.record.catalog_base64 = encode(&full.bytes);
            requests::save(&tx, &p)?;
            "dec.frame.after_commit"
        };
        controls::remember_decision(&tx, &i.network_id, &stage.now)?;
        tx.commit().map_err(db)?;
        drop(c);
        controls::barrier(store, barrier, id)?;
        if barrier == "dec.signature.after_commit" && i.record.completed {
            controls::barrier(store, "dec.requester_commit.after_commit", id)?;
        }
    }
}
fn verify_complete(
    c: &Connection,
    store: &Store,
    p: &Pending,
    i: &Intent,
    stage: &Context,
    raw: &[u8],
) -> Result<Catalog> {
    let d = &stage.offer.descriptor;
    let (catalog, _) = public_catalog(p, i, stage)?;
    let activation = activation_bytes(p, raw)?;
    let proof_id = crate::decentralized::statement::proof_id("activation", &activation);
    let addition = Catalog::read(
        d,
        &bytes(
            &json!({"format":1,"context_id":d.context_id(),"objects":[{"id":proof_id,"kind":"activation","body_base64":encode(&activation)}]}),
        )?,
    )?;
    let full = Catalog::union(d, &catalog, &addition)?;
    let present: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [&d.network_id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let projection = if let Some(staged) = &stage.offer.staging {
        staged.migration_owner_prefix(&full.bytes, &stage.offer.owner, &stage.now)?
    } else {
        let prior = if present {
            Snapshot::load(c, &d.network_id, &store.identity().public_key)?
                .prior
                .value
        } else {
            Value::from("-")
        };
        Projection::build(d, &prior, Some(&full.bytes), &stage.now, "repair")?
    };
    projection.activation_response(&p.id, &Value::from("-"))?;
    Ok(full)
}
fn components(context: &str, rows: Vec<Value>) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    let mut objects = Vec::new();
    for value in rows {
        let mut next = objects.clone();
        next.push(value.clone());
        if bytes(&json!({"format":1,"context_id":context,"objects":next}))?.len() > 2 << 20 {
            require(!objects.is_empty(), "quota_exceeded")?;
            result.push(bytes(
                &json!({"format":1,"context_id":context,"objects":objects}),
            )?);
            objects = Vec::new();
        }
        objects.push(value);
    }
    if !objects.is_empty() {
        let raw = bytes(&json!({"format":1,"context_id":context,"objects":objects}))?;
        require(raw.len() <= 2 << 20, "quota_exceeded")?;
        result.push(raw)
    }
    Ok(result)
}
pub(crate) fn catalog_delta_components(
    c: &Connection,
    p: &Pending,
    catalog: &Catalog,
    writer: &str,
    now: &str,
) -> Result<Vec<Vec<u8>>> {
    let secret = p.secret.ok_or_else(|| Error::new("recovery_required"))?;
    let mut present = std::collections::BTreeSet::new();
    for frame in requests::frames(c, p)?
        .iter()
        .filter(|f| f.role == "proofs" && f.writer_host_public_key == writer)
    {
        let plain = frame.open(&secret, now)?;
        let value = text(object(&plain)?, "catalog_base64")?;
        if value == "-" {
            continue;
        }
        let raw = b64(value, 2 << 20)?;
        let v = parse(&raw, 2 << 20)?;
        if text(object(&v)?, "context_id")? != catalog.context_id {
            continue;
        }
        for row in array(object(&v)?, "objects")? {
            present.insert(text(object(row)?, "id")?.to_owned());
        }
    }
    let rows = catalog
        .proofs
        .values()
        .filter(|proof| !present.contains(&proof.id))
        .map(|proof| json!({"id":proof.id,"kind":proof.kind,"body_base64":encode(&proof.body)}))
        .collect();
    components(&catalog.context_id, rows)
}
pub(crate) fn retain_catalog(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    catalog: &Catalog,
    now: &str,
) -> Result<()> {
    for raw in catalog_delta_components(c, p, catalog, &store.identity().public_key, now)? {
        retain_outbound(c, store, p, "proofs", b"-", &encode(&raw), now)?
    }
    Ok(())
}
