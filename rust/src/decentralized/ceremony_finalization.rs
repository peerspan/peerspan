//! Owner finalization fixes only the selected request and reviewed finite terms.
//! Unsigned drafts, real signatures and ciphertext have separate durable phases.
use super::{
    ceremony::*,
    codec::*,
    controls,
    intents::{Filled, FixedObject, Intent},
    observer::{Evidence, Offer},
    provider::Resolved,
    requests::{self, Pending},
    state::{CeremonyPrefix, PreparedAdmissions, Projection},
    statement::{Descriptor, Statement},
    storage::Snapshot,
    template::FixedStatement,
    transcript::Packet,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;
const INPUT: &str = "owner_offer_id selection_id administrator_offer_id network_id context_id person_public_key host_public_key device_public_key approve";
struct Base {
    descriptor: Descriptor,
    prior: Value,
    request: Packet,
    offer: Offer,
    selection: Packet,
    selection_raw: Vec<u8>,
    administrator: Option<Packet>,
    administrator_raw: Option<Vec<u8>>,
    admissions: PreparedAdmissions,
    projection: Projection,
    now: String,
    seed: Option<[u8; 32]>,
    folded: Option<Statement>,
}
impl Base {
    fn prefix(&self) -> CeremonyPrefix<'_> {
        CeremonyPrefix {
            descriptor: &self.descriptor,
            prior: &self.prior,
            catalog: &self.admissions.catalog,
            request: &self.request,
            owner: &self.offer.owner,
            selection: &self.selection,
            administrator: self.administrator.as_ref(),
            now: &self.now,
            staging: self.offer.staging.as_ref(),
            folded_host: self.folded.as_ref(),
        }
    }
}
fn base(c: &Connection, store: &Store, p: &Pending, i: &Intent) -> Result<Base> {
    require(
        i.record.approved && p.record.terminal == "-",
        "state_conflict",
    )?;
    let descriptor = descriptor(p)?;
    let now =
        controls::guarded_decision(c, &descriptor.network_id, &controls::local_decision_time()?)?;
    require(stamp(&now)? < stamp(&p.deadline)?, "expired")?;
    let evidence = Evidence::read(c, p, &now)?;
    let offer = evidence.offer(c, store, p, &p.record.owner_offer_id, &now)?;
    require(
        offer.owner_bytes == b64(&p.record.owner_packet_base64, MAX_OBJECT)?,
        "operation_conflict",
    )?;
    let selected = evidence
        .packets
        .get(&p.record.selection_id)
        .ok_or_else(|| Error::missing(&p.record.selection_id))?;
    let selection = selected.packet.clone();
    let selection_raw = selected.bytes.clone();
    super::state::check_requester_selection(&p.packet()?, &offer.owner, &selection, &descriptor)?;
    // A folded admin stage uses no administrator packet (spec 8.2).
    let folded = folded(i, &descriptor)?;
    let administrator = if folded.is_some() {
        None
    } else if p.record.administrator_offer_id != "-" {
        Some(
            evidence
                .packets
                .get(&p.record.administrator_offer_id)
                .ok_or_else(|| Error::missing(&p.record.administrator_offer_id))?
                .packet
                .clone(),
        )
    } else {
        require(p.record.mode == "renew", "proof_required")?;
        None
    };
    let administrator_raw = administrator
        .as_ref()
        .map(|a| evidence.packets[&a.id].bytes.clone());
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [&descriptor.network_id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let snapshot = if exists && offer.staging.is_none() {
        Some(Snapshot::load(
            c,
            &descriptor.network_id,
            &store.identity().public_key,
        )?)
    } else {
        None
    };
    let prior = snapshot
        .as_ref()
        .map(|s| s.prior.value.clone())
        .unwrap_or(Value::from("-"));
    let catalog = offer
        .catalog
        .as_ref()
        .ok_or_else(|| Error::new("proof_required"))?;
    let request = p.packet()?;
    let prefix = CeremonyPrefix {
        descriptor: &descriptor,
        prior: &prior,
        catalog,
        request: &request,
        owner: &offer.owner,
        selection: &selection,
        administrator: administrator.as_ref(),
        now: &now,
        staging: offer.staging.as_ref(),
        folded_host: folded.as_ref(),
    };
    let admissions = Projection::prepare_administrator(prefix)?;
    let projection = Projection::owner_preparation(prefix)?;
    let now = projection.decision_time.clone();
    let mut seed = None;
    if let Some(snapshot) = snapshot {
        let provider = if i.record.provider.kind == "device" {
            &i.record.provider.lease_id
        } else {
            &i.record.provider.signer_public_key
        };
        let resolved = Resolved::resolve(
            c,
            &snapshot,
            &projection,
            provider,
            &i.record.provider.signature_format,
            "device_lease",
        )?;
        require(
            resolved.provider.kind == i.record.provider.kind
                && resolved.provider.signer_public_key == i.record.provider.signer_public_key
                && resolved.provider.lease_id == i.record.provider.lease_id,
            "operation_conflict",
        )?;
        seed = resolved.seed;
        let public = resolved.public(&projection, &store.identity().public_key, false)?;
        require(
            i.record.scopes & !num(object(&public)?, "scopes")? == 0,
            "forbidden",
        )?;
        require(
            i.record.not_after.as_str() <= field(&public, "not_after")?,
            "forbidden",
        )?;
    } else if offer.staging.is_some() {
        // In-place migration is removed (DEC-OWN3).
        return Err(Error::new("not_found"));
    } else {
        // Only the reviewed original-key possession path can exist without an
        // adopted context. Pending self P does not become an ordinary provider.
        check(
            text(&offer.owner.payload, "root_state_id")? == "-"
                && i.record.provider.kind == "original"
                && i.record.provider.signer_public_key == i.record.person_public_key
                && num(object(&offer.provider)?, "scopes")? == 0,
        )?;
    }
    Ok(Base {
        descriptor,
        prior,
        request,
        offer,
        selection,
        selection_raw,
        administrator,
        administrator_raw,
        admissions,
        projection,
        now,
        seed,
        folded,
    })
}
fn generation(b: &Base, kind: &str, p: &Pending) -> Result<(u64, Vec<String>)> {
    let stream = if kind == "binding_lease" {
        vec!["binding".into(), p.record.host_public_key.clone()]
    } else {
        vec![
            "device".into(),
            text(&b.offer.owner.object, "person_public_key")?.into(),
            p.record.device_public_key.clone(),
        ]
    };
    let row = b.projection.streams.get(&stream);
    require(row.is_none_or(|r| r.heads.len() <= 1), "state_conflict")?;
    Ok((
        row.map_or(0, |r| r.maximum)
            .checked_add(1)
            .ok_or_else(|| Error::new("version_exhausted"))?,
        row.map(|r| r.heads.clone())
            .unwrap_or_default()
            .into_iter()
            .collect(),
    ))
}
fn draft(
    b: &Base,
    p: &Pending,
    i: &Intent,
    kind: &str,
    binding: &str,
    time: &str,
) -> Result<Vec<u8>> {
    let (sequence, predecessors) = generation(b, kind, p)?;
    let mut parents = BTreeMap::from([
        ("subject_person", b.admissions.person.id.clone()),
        ("subject_host", b.admissions.host.id.clone()),
    ]);
    let original = text(&b.offer.owner.payload, "person_lease_id")? == "-";
    if original {
        parents.insert("issuer_person", b.admissions.person.id.clone());
    } else {
        for id in ids(&b.offer.owner.payload, "issuer_lease_ids", "ds_")? {
            let s = b.projection.catalog.get(&id)?;
            let role = match s.kind.as_str() {
                "person_lease" => "issuer_person",
                "device_lease" => "issuer_device",
                _ => return Err(Error::new("invalid")),
            };
            check(parents.insert(role, id).is_none())?;
        }
    }
    if kind == "device_lease" {
        parents.insert("subject_binding", binding.into());
    }
    let payload = json!({"root_state_id":b.admissions.root,"operation_id":p.id,"sequence":sequence,"predecessors":predecessors,"resolves":[],"retained_statement_ids":[],
        "subject":{"person_public_key":i.record.person_public_key,"host_public_key":p.record.host_public_key,"device_public_key":if kind=="device_lease"{p.record.device_public_key.as_str()}else{"-"},"member":"-","scopes":if kind=="device_lease"{i.record.scopes}else{2}},
        "issuer":{"kind":if i.record.provider.kind=="device"{"device"}else{"person"},"person_public_key":i.record.person_public_key},
        "parents":parents.into_iter().map(|(role,id)|json!({"role":role,"id":id})).collect::<Vec<_>>(),"issued_at":time,"not_before":time,"not_after":i.record.not_after});
    let mut signatures = vec![
        json!({"role":"issuer","public_key":i.record.provider.signer_public_key,"format":i.record.provider.signature_format,"signature":"-"}),
    ];
    if kind == "binding_lease" {
        signatures.insert(0,json!({"role":"host","public_key":p.record.host_public_key,"format":"ed25519","signature":"-"}));
    }
    let raw = bytes(
        &json!({"format":1,"kind":kind,"context_id":b.descriptor.context_id(),"payload_base64":encode(&bytes(&payload)?),"signatures":signatures}),
    )?;
    FixedStatement::read(&b.descriptor, &raw)?;
    Ok(raw)
}
fn reuse(b: &Base, p: &Pending, i: &Intent) -> Result<Statement> {
    check(p.record.mode == "renew")?;
    let stream = b
        .projection
        .streams
        .get(&vec!["binding".into(), p.record.host_public_key.clone()])
        .ok_or_else(|| Error::new("proof_required"))?;
    require(stream.heads.len() == 1, "state_conflict")?;
    let id = stream
        .heads
        .first()
        .ok_or_else(|| Error::new("proof_required"))?;
    let s = b.projection.catalog.get(id)?.clone();
    b.projection.active(&s.id)?;
    require(
        text(s.subject()?, "person_public_key")? == i.record.person_public_key
            && text(s.subject()?, "host_public_key")? == p.record.host_public_key
            && text(&s.payload, "not_after")? >= i.record.not_after.as_str(),
        "forbidden",
    )?;
    Ok(s)
}
fn components(b: &Base, p: &Pending, i: &Intent) -> Result<(Statement, Statement, bool)> {
    let objects = i.objects(&b.descriptor)?;
    let read = |kind: &str| -> Result<Option<Statement>> {
        let index = i
            .record
            .templates
            .iter()
            .position(|t| t.object_type == kind);
        if let Some(index) = index
            && let Some(FixedObject::Statement(s)) = &objects[index]
        {
            return Ok(Some(s.typed().clone()));
        }
        Ok(None)
    };
    let reused = !i
        .record
        .templates
        .iter()
        .any(|t| t.object_type == "binding_lease");
    let binding = if reused {
        reuse(b, p, i)?
    } else {
        read("binding_lease")?.ok_or_else(|| Error::new("state_conflict"))?
    };
    let device = read("device_lease")?.ok_or_else(|| Error::new("state_conflict"))?;
    Ok((binding, device, reused))
}
fn packet(
    b: &Base,
    p: &Pending,
    binding: &Statement,
    device: &Statement,
    reused: bool,
) -> Result<Vec<u8>> {
    let mut payload=object(&json!({"selection_id":b.selection.id,"administrator_offer_id":b.administrator.as_ref().map(|a|a.id.as_str()).unwrap_or("-"),"root_state_id":b.admissions.root,"person_lease_id":b.admissions.person.id,"host_lease_id":b.admissions.host.id}))?.clone();
    payload.insert(
        "binding_lease".into(),
        if reused {
            Value::from(binding.id.clone())
        } else {
            parse(&binding.body, MAX_OBJECT)?
        },
    );
    payload.insert("device_lease".into(), parse(&device.body, MAX_OBJECT)?);
    // Preserve the exact nested original statement bytes, including aliases.
    let mut raw_payload = BTreeMap::new();
    for (key, value) in payload {
        raw_payload.insert(key, bytes(&value)?);
    }
    if !reused {
        raw_payload.insert("binding_lease".into(), binding.body.clone());
    }
    raw_payload.insert("device_lease".into(), device.body.clone());
    let raw_payload: BTreeMap<String, Box<serde_json::value::RawValue>> = raw_payload
        .into_iter()
        .map(|(k, v)| {
            Ok((
                k,
                serde_json::value::RawValue::from_string(
                    String::from_utf8(v).map_err(|_| Error::new("invalid"))?,
                )
                .map_err(|_| Error::new("invalid"))?,
            ))
        })
        .collect::<Result<_>>()?;
    let owner = &b.offer.owner.object;
    let raw = bytes(
        &json!({"format":1,"context_id":b.descriptor.context_id(),"request_id":p.id,"role":"owner_finalization","writer_host_public_key":text(owner,"writer_host_public_key")?,"signer_public_key":text(owner,"signer_public_key")?,"person_public_key":text(owner,"person_public_key")?,"issuer_id":text(owner,"issuer_id")?,"payload_base64":encode(&bytes(&raw_payload)?),"host_signature":"-","device_signature":"-","authority_signature_format":text(owner,"authority_signature_format")?,"authority_signature":"-"}),
    )?;
    Packet::read_template(&raw)?;
    Ok(raw)
}
fn review(b: &Base, p: &Pending, binding: &Statement, device: &Statement) -> Result<Value> {
    let mut r = b.offer.review(p, "owner_finalization")?;
    r["root_state_id"] = Value::from(b.admissions.root.clone());
    r["selection_id"] = Value::from(b.selection.id.clone());
    r["administrator_offer_id"] = Value::from(
        b.administrator
            .as_ref()
            .map(|a| a.id.as_str())
            .unwrap_or("-"),
    );
    for (field, id) in [
        ("person_lease_id", &b.admissions.person.id),
        ("host_lease_id", &b.admissions.host.id),
        ("binding_lease_id", &binding.id),
        ("device_lease_id", &device.id),
    ] {
        r[field] = Value::from(id.clone());
    }
    if b.folded.as_ref().is_some_and(|host| {
        host.issuer()
            .is_ok_and(|issuer| text(issuer, "kind").is_ok_and(|kind| kind == "root"))
    }) {
        r["authority_warning"] = json!(ROOT_FOLD_WARNING);
    }
    Ok(r)
}
fn materialize(c: &Connection, store: &Store, b: &Base, p: &Pending, i: &mut Intent) -> Result<()> {
    let reused = !i
        .record
        .templates
        .iter()
        .any(|t| t.object_type == "binding_lease");
    let binding = if reused {
        reuse(b, p, i)?
    } else {
        let raw = draft(b, p, i, "binding_lease", "-", &b.now)?;
        FixedStatement::read(&b.descriptor, &raw)?.typed().clone()
    };
    let raw = draft(b, p, i, "device_lease", &binding.id, &b.now)?;
    let device = FixedStatement::read(&b.descriptor, &raw)?.typed().clone();
    let f = Packet::read_template(&packet(b, p, &binding, &device, reused)?)?;
    Projection::check_owner_drafts(b.prefix(), &f, &binding, &device, reused)?;
    frame_budget(
        c,
        store,
        p,
        Some(&b.admissions.catalog),
        binding.body.len() + device.body.len() + (64 << 10),
        &b.now,
    )?;
    for t in &mut i.record.templates {
        if t.object_type == "binding_lease" {
            check(t.template_base64 == "-")?;
            t.template_base64 = encode(&binding.body);
        }
        if t.object_type == "device_lease" {
            check(t.template_base64 == "-")?;
            t.template_base64 = encode(&device.body);
        }
    }
    i.record.root_state_id = b.admissions.root.clone();
    i.record.review_base64 = encode(&bytes(&review(b, p, &binding, &device)?)?);
    i.record.completed = false;
    Ok(())
}
fn check_current(c: &Connection, store: &Store, p: &Pending, i: &Intent) -> Result<Base> {
    let b = base(c, store, p, i)?;
    let (binding, device, reused) = components(&b, p, i)?;
    let raw = packet(&b, p, &binding, &device, reused)?;
    let f = Packet::read_template(&raw)?;
    Projection::check_owner_drafts(b.prefix(), &f, &binding, &device, reused)?;
    let saved_review = read_review(i)?;
    let mut expected_review = review(&b, p, &binding, &device)?;
    expected_review["authority_warning"] = saved_review["authority_warning"].clone();
    require(expected_review == saved_review, "operation_conflict")?;
    if let Some(last) = i.objects(&b.descriptor)?.last().and_then(Option::as_ref) {
        let saved = Packet::read_template(last.bytes())?;
        require(
            saved.id == f.id && saved.payload_bytes == f.payload_bytes,
            "operation_conflict",
        )?;
    }
    frame_budget(
        c,
        store,
        p,
        Some(&b.admissions.catalog),
        binding.body.len() + device.body.len() + (64 << 10),
        &b.now,
    )?;
    Ok(b)
}
pub(crate) fn prepare(store: &Store, id: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, INPUT)?;
    let approved = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    let mut i = owner_intent(&tx, &p)?;
    let b = base(&tx, store, &p, &i)?;
    for (field, want) in [
        ("owner_offer_id", b.offer.owner.id.as_str()),
        ("selection_id", b.selection.id.as_str()),
        (
            "administrator_offer_id",
            b.administrator
                .as_ref()
                .map(|a| a.id.as_str())
                .unwrap_or("-"),
        ),
        ("network_id", b.descriptor.network_id.as_str()),
        ("context_id", i.context_id.as_str()),
        ("person_public_key", i.record.person_public_key.as_str()),
        ("host_public_key", p.record.host_public_key.as_str()),
        ("device_public_key", p.record.device_public_key.as_str()),
    ] {
        check(text(input, field)? == want)?;
    }
    let new = field(&read_review(&i)?, "stage")? == "owner";
    if new {
        materialize(&tx, store, &b, &p, &mut i)?;
    } else {
        check_current(&tx, store, &p, &i)?;
    }
    let mut review = read_review(&i)?;
    if !approved && new {
        // This preview has not fixed its dependent templates. The next
        // explicit approval materializes their actual timestamp and IDs.
        review["binding_lease_id"] = Value::from("-");
        review["device_lease_id"] = Value::from("-");
    }
    let raw = bytes(
        &json!({"request":p.view(&b.now)?,"review":review,"signing_requests":if approved{signing_requests(&i,&b.descriptor)?}else{Vec::new()}}),
    )?;
    if !approved {
        return Ok(raw);
    }
    b.offer.remember(&mut p)?;
    p.record.selection_id = b.selection.id.clone();
    p.record.selection_packet_base64 = encode(&b.selection_raw);
    if let Some(a) = &b.administrator {
        p.record.administrator_offer_id = a.id.clone();
        p.record.administrator_packet_base64 = encode(
            b.administrator_raw
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?,
        );
    }
    i.save(&tx)?;
    requests::save(&tx, &p)?;
    controls::remember_decision(&tx, &i.network_id, &b.now)?;
    tx.commit().map_err(db)?;
    drop(c);
    if new {
        controls::barrier(store, "dec.intent.after_commit", id)?;
    }
    resume(store, id)?;
    get(store, id)
}
pub(crate) fn get(store: &Store, id: &str) -> Result<Vec<u8>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let p = requests::load(&c, id)?;
    let i = owner_intent(&c, &p)?;
    if p.record.terminal == "-" && !i.record.completed {
        check_current(&c, store, &p, &i)?;
    }
    bytes(
        &json!({"request":p.view(&controls::local_decision_time()?)?,"review":read_review(&i)?,"signing_requests":signing_requests(&i,&descriptor(&p)?)?}),
    )
}
fn completed(i: &mut Intent, p: &mut Pending, b: &Base) -> Result<()> {
    let objects = i.objects(&b.descriptor)?;
    i.record.completed = objects.iter().all(|o| {
        o.as_ref().is_some_and(|o| {
            o.pending().is_ok_and(|slots| {
                slots
                    .iter()
                    .all(|s| s.object_type == "binding_lease" && s.role == "host")
            })
        })
    });
    if i.record.completed {
        let f = objects
            .last()
            .and_then(Option::as_ref)
            .ok_or_else(|| Error::new("state_conflict"))?;
        let packet = Packet::read(f.bytes())?;
        Projection::prepare_finalization(b.prefix(), &packet)?;
        require(
            p.record.owner_finalization_packet_base64 == "-"
                || p.record.owner_finalization_packet_base64 == encode(f.bytes()),
            "operation_conflict",
        )?;
        p.record.owner_finalization_id = packet.id;
        p.record.owner_finalization_packet_base64 = encode(f.bytes());
    }
    Ok(())
}
pub(crate) fn signed(store: &Store, id: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "intent_id signatures")?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    let mut i = owner_intent(&tx, &p)?;
    check(text(input, "intent_id")? == i.id)?;
    let b = check_current(&tx, store, &p, &i)?;
    let entries = array(input, "signatures")?;
    check(!entries.is_empty() && entries.len() <= 16)?;
    let before = i.record.signatures.len();
    let mut previous = None;
    for entry in entries {
        let o = object(entry)?;
        fields(o, "slot_id role signature")?;
        let slot = num(o, "slot_id")?;
        let role = text(o, "role")?;
        check(
            previous
                .as_ref()
                .is_none_or(|old: &(u64, String)| old < &(slot, role.into())),
        )?;
        previous = Some((slot, role.into()));
        if let Some(old) = i
            .record
            .signatures
            .iter()
            .find(|s| s.slot_id == slot && s.role == role)
        {
            require(old.signature == text(o, "signature")?, "operation_conflict")?;
            continue;
        }
        let objects = i.objects(&b.descriptor)?;
        let value = objects
            .get(slot.checked_sub(1).ok_or_else(|| Error::new("invalid"))? as usize)
            .and_then(Option::as_ref)
            .ok_or_else(|| Error::new("invalid"))?;
        check(
            i.record.provider.kind == "original"
                && i.record.provider.signature_format == "sshsig"
                && value.pending()?.iter().any(|s| {
                    s.role == role
                        && s.public_key == i.record.provider.signer_public_key
                        && s.signature_format == "sshsig"
                        && !(s.object_type == "binding_lease" && s.role == "host")
                }),
        )?;
        value.fill(&b.descriptor, role, text(o, "signature")?)?;
        add(&mut i, slot, role, text(o, "signature")?)?;
    }
    completed(&mut i, &mut p, &b)?;
    i.save(&tx)?;
    requests::save(&tx, &p)?;
    controls::remember_decision(&tx, &i.network_id, &b.now)?;
    tx.commit().map_err(db)?;
    drop(c);
    if i.record.signatures.len() > before {
        controls::barrier(store, "dec.signature.after_commit", id)?;
    }
    resume(store, id)?;
    get(store, id)
}
fn generate(store: &Store, b: &Base, i: &Intent) -> Result<Vec<Filled>> {
    let mut generated = Vec::new();
    for (index, object) in i.objects(&b.descriptor)?.iter().enumerate() {
        let Some(object) = object else { continue };
        for slot in object.pending()? {
            if slot.object_type == "binding_lease" && slot.role == "host" {
                continue;
            }
            let message = b64(&slot.message_base64, 4096)?;
            let sig = if slot.role == "host"
                && slot.signature_format == "ed25519"
                && slot.public_key == store.identity().public_key
            {
                Some(encode(&store.signing_key.sign(&message).to_bytes()))
            } else if slot.public_key == i.record.provider.signer_public_key
                && slot.signature_format == i.record.provider.signature_format
            {
                if slot.signature_format == "ed25519" {
                    Some(encode(
                        &SigningKey::from_bytes(
                            &b.seed.ok_or_else(|| Error::new("signer_unavailable"))?,
                        )
                        .sign(&message)
                        .to_bytes(),
                    ))
                } else {
                    let key = b64(&slot.public_key, 32)?
                        .try_into()
                        .map_err(|_| Error::new("invalid"))?;
                    if let Ok(signer) = store.renewal_signer(key) {
                        Some(
                            signer
                                .sign(
                                    &std::str::from_utf8(&message)
                                        .map_err(|_| Error::new("invalid"))?
                                        .split('\n')
                                        .collect::<Vec<_>>(),
                                )
                                .map_err(|_| Error::new("signer_unavailable"))?,
                        )
                    } else {
                        None
                    }
                }
            } else {
                return Err(Error::new("state_conflict"));
            };
            if let Some(signature) = sig {
                generated.push(Filled {
                    slot_id: index as u64 + 1,
                    role: slot.role,
                    signature,
                });
            }
        }
    }
    Ok(generated)
}
/// Accept only durable forward progress of the same approved owner intent.
/// Its existing templates/signatures and every reviewed security field remain
/// fixed; a newly materialized dependency is checked again on the next pass.
fn advanced(before: &Intent, after: &Intent, pending: &Pending) -> Result<bool> {
    if before.id != after.id
        || before.network_id != after.network_id
        || before.context_id != after.context_id
        || before.kind != after.kind
        || before.secret != after.secret
        || before.record.templates.len() != after.record.templates.len()
        || before.record.completed && !after.record.completed
    {
        return Ok(false);
    }
    for (old, current) in before.record.templates.iter().zip(&after.record.templates) {
        if old.slot_id != current.slot_id
            || old.object_type != current.object_type
            || old.template_base64 != "-" && old.template_base64 != current.template_base64
        {
            return Ok(false);
        }
    }
    for old in &before.record.signatures {
        if !after.record.signatures.iter().any(|current| {
            old.slot_id == current.slot_id
                && old.role == current.role
                && old.signature == current.signature
        }) {
            return Ok(false);
        }
    }
    let mut expected = before.record.clone();
    let old_review = read_review(before)?;
    let current_review = read_review(after)?;
    if field(&old_review, "stage")? == "owner"
        && field(&current_review, "stage")? == "owner_finalization"
    {
        let mut review = old_review;
        for name in [
            "stage",
            "root_state_id",
            "selection_id",
            "administrator_offer_id",
            "person_lease_id",
            "host_lease_id",
            "binding_lease_id",
            "device_lease_id",
            "authority_warning",
        ] {
            review[name] = current_review[name].clone();
        }
        if review != current_review
            || field(&current_review, "selection_id")? != pending.record.selection_id
            || field(&current_review, "administrator_offer_id")?
                != pending.record.administrator_offer_id
            || field(&current_review, "owner_offer_id")? != pending.record.owner_offer_id
        {
            return Ok(false);
        }
        // Only the possession-only offer starts without a root pin. A root
        // which was already fixed cannot change as a concurrency retry.
        if expected.root_state_id == "-" {
            expected.root_state_id = after.record.root_state_id.clone();
        }
        expected.review_base64 = after.record.review_base64.clone();
    }
    expected.templates = after.record.templates.clone();
    expected.signatures = after.record.signatures.clone();
    expected.completed = after.record.completed;
    Ok(bytes(&expected)? == bytes(&after.record)?)
}
pub(crate) fn resume(store: &Store, id: &str) -> Result<()> {
    loop {
        let (b, i) = {
            let c = store.connection().map_err(|_| Error::new("internal"))?;
            let p = requests::load(&c, id)?;
            if p.record.owner_intent_id == "-"
                || p.record.terminal != "-"
                || p.record
                    .outbound_frames
                    .iter()
                    .any(|f| f["role"] == "owner_finalization")
            {
                return Ok(());
            }
            let i = owner_intent(&c, &p)?;
            if !i.record.approved
                || p.record.owner_packet_base64 == "-"
                || p.record.selection_id == "-"
                || (p.record.mode != "renew"
                    && p.record.administrator_offer_id == "-"
                    && !i
                        .record
                        .templates
                        .iter()
                        .any(|t| t.object_type == "host_lease"))
            {
                return Ok(());
            }
            let stage = field(&read_review(&i)?, "stage")?.to_owned();
            let b = if stage == "owner_finalization" {
                check_current(&c, store, &p, &i)?
            } else {
                base(&c, store, &p, &i)?
            };
            (b, i)
        };
        let stage = field(&read_review(&i)?, "stage")?.to_owned();
        let generated = if stage == "owner_finalization" {
            generate(store, &b, &i)?
        } else {
            Vec::new()
        };
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut p = requests::load(&tx, id)?;
        if p.record.terminal != "-"
            || p.record
                .outbound_frames
                .iter()
                .any(|f| f["role"] == "owner_finalization")
        {
            return Ok(());
        }
        let mut current = owner_intent(&tx, &p)?;
        if bytes(&current.record)? != bytes(&i.record)? {
            require(advanced(&i, &current, &p)?, "state_conflict")?;
            // Another approved resume committed this exact intent's next
            // dependency/signature phase while generation held no writer lock.
            // Discard this stale batch and reload; all current path, clock and
            // fixed-template checks run again before any signature is stored.
            drop(tx);
            drop(c);
            continue;
        }
        let b = if stage == "owner_finalization" {
            check_current(&tx, store, &p, &current)?
        } else {
            base(&tx, store, &p, &current)?
        };
        let barrier = if stage == "owner" {
            materialize(&tx, store, &b, &p, &mut current)?;
            current.save(&tx)?;
            "dec.intent.after_commit"
        } else if !generated.is_empty() {
            for sig in generated {
                let object = current
                    .objects(&b.descriptor)?
                    .remove(sig.slot_id as usize - 1)
                    .ok_or_else(|| Error::new("state_conflict"))?;
                object.fill(&b.descriptor, &sig.role, &sig.signature)?;
                add(&mut current, sig.slot_id, &sig.role, &sig.signature)?;
            }
            completed(&mut current, &mut p, &b)?;
            current.save(&tx)?;
            requests::save(&tx, &p)?;
            "dec.signature.after_commit"
        } else if current
            .record
            .templates
            .last()
            .ok_or_else(|| Error::new("invalid"))?
            .template_base64
            == "-"
        {
            let objects = current.objects(&b.descriptor)?;
            if !objects[..objects.len() - 1].iter().all(|o| {
                o.as_ref().is_some_and(|o| {
                    o.pending().is_ok_and(|slots| {
                        slots
                            .iter()
                            .all(|s| s.object_type == "binding_lease" && s.role == "host")
                    })
                })
            }) {
                return Ok(());
            }
            let (binding, device, reused) = components(&b, &p, &current)?;
            let raw = packet(&b, &p, &binding, &device, reused)?;
            current
                .record
                .templates
                .last_mut()
                .ok_or_else(|| Error::new("invalid"))?
                .template_base64 = encode(&raw);
            current.save(&tx)?;
            "dec.intent.after_commit"
        } else if current.record.completed {
            let raw = b64(&p.record.owner_finalization_packet_base64, MAX_OBJECT)?;
            let f = Packet::read(&raw)?;
            let prepared = Projection::prepare_finalization(b.prefix(), &f)?;
            super::requester::retain_catalog(
                &tx,
                store,
                &mut p,
                &prepared.admissions.catalog,
                &b.now,
            )?;
            retain_packet(&tx, store, &mut p, "owner_finalization", &raw, &b.now)?;
            p.record.catalog_base64 = encode(&prepared.admissions.catalog.bytes);
            requests::save(&tx, &p)?;
            "dec.frame.after_commit"
        } else {
            return Ok(());
        };
        controls::remember_decision(&tx, &current.network_id, &b.now)?;
        tx.commit().map_err(db)?;
        drop(c);
        controls::barrier(store, barrier, id)?;
        if barrier == "dec.signature.after_commit" && current.record.completed {
            controls::barrier(store, "dec.owner_finalization.after_commit", id)?;
        }
    }
}
/// A folded host grant (spec 8.2): this request's new host grant, signed by
/// the owner's provider, named by the review.
fn folded_template(p: &Pending, i: &Intent, d: &Descriptor, r: &Value) -> Result<()> {
    let Some(index) = i
        .record
        .templates
        .iter()
        .position(|t| t.object_type == "host_lease")
    else {
        return Ok(());
    };
    check(index == 1 && p.record.mode != "renew")?;
    let Some(FixedObject::Statement(s)) = &i.objects(d)?[index] else {
        return Err(Error::new("state_conflict"));
    };
    let s = s.typed();
    check(
        s.kind == "host_lease"
            && s.id == field(r, "host_lease_id")?
            && text(&s.payload, "operation_id")? == p.id
            && text(&s.payload, "not_after")? == i.record.not_after
            && text(s.subject()?, "host_public_key")? == i.record.host_public_key
            && if text(s.issuer()?, "kind")? == "root" {
                text(s.issuer()?, "person_public_key")? == "-"
                    && s.parents()?.is_empty()
                    && s.signer("issuer")?.format == "ed25519"
                    && field(r, "authority_warning")?.contains("also uses network_root")
            } else {
                text(s.issuer()?, "person_public_key")? == i.record.person_public_key
                    && s.signer("issuer")?.public_key == i.record.provider.signer_public_key
                    && s.signer("issuer")?.format == i.record.provider.signature_format
            },
    )
}
/// The signed folded host grant of this owner intent, if it folds.
fn folded(i: &Intent, d: &Descriptor) -> Result<Option<Statement>> {
    let Some(index) = i
        .record
        .templates
        .iter()
        .position(|t| t.object_type == "host_lease")
    else {
        return Ok(None);
    };
    let object = i
        .objects(d)?
        .remove(index)
        .ok_or_else(|| Error::new("state_conflict"))?;
    require(object.pending()?.is_empty(), "signer_unavailable")?;
    Ok(Some(Statement::read(d, object.bytes())?))
}
/// Validate shared private rows without requiring current signing authority.
/// Live signing rechecks the complete current prefix separately.
pub(super) fn validate_templates(
    p: &Pending,
    i: &Intent,
    d: &Descriptor,
    offer: &Packet,
) -> Result<()> {
    let r = read_review(i)?;
    let objects = i.objects(d)?;
    if field(&r, "stage")? == "owner" {
        check(
            i.record
                .templates
                .iter()
                .skip(1)
                .all(|t| t.template_base64 == "-" || t.object_type == "host_lease"),
        )?;
        folded_template(p, i, d, &r)?;
        return Ok(());
    }
    folded_template(p, i, d, &r)?;
    check(field(&r, "stage")? == "owner_finalization" && i.record.approved)?;
    for (index, t) in i.record.templates.iter().enumerate().skip(1) {
        if !matches!(t.object_type.as_str(), "binding_lease" | "device_lease") {
            continue;
        }
        let Some(FixedObject::Statement(s)) = &objects[index] else {
            return Err(Error::new("state_conflict"));
        };
        let s = s.typed();
        let device = t.object_type == "device_lease";
        check(
            s.kind == t.object_type
                && s.id
                    == field(
                        &r,
                        if device {
                            "device_lease_id"
                        } else {
                            "binding_lease_id"
                        },
                    )?
                && text(&s.payload, "root_state_id")? == i.record.root_state_id
                && text(&s.payload, "operation_id")? == p.id
                && text(&s.payload, "not_after")? == i.record.not_after
                && text(s.subject()?, "person_public_key")? == i.record.person_public_key
                && text(s.subject()?, "host_public_key")? == i.record.host_public_key
                && s.signer("issuer")?.public_key == i.record.provider.signer_public_key
                && s.signer("issuer")?.format == i.record.provider.signature_format
                && s.parents()?.get("subject_person").map(String::as_str)
                    == Some(field(&r, "person_lease_id")?)
                && s.parents()?.get("subject_host").map(String::as_str)
                    == Some(field(&r, "host_lease_id")?),
        )?;
        if device {
            check(
                text(s.subject()?, "device_public_key")? == i.record.device_public_key
                    && num(s.subject()?, "scopes")? == i.record.scopes
                    && s.parents()?.get("subject_binding").map(String::as_str)
                        == Some(field(&r, "binding_lease_id")?),
            )?;
        } else {
            check(s.signer("host")?.signature == "-")?;
        }
    }
    if let Some(f) = objects.last().and_then(Option::as_ref) {
        let packet = Packet::read_template(f.bytes())?;
        for name in [
            "writer_host_public_key",
            "signer_public_key",
            "person_public_key",
            "issuer_id",
            "authority_signature_format",
        ] {
            check(text(&packet.object, name)? == text(&offer.object, name)?)?;
        }
        check(
            text(&packet.object, "role")? == "owner_finalization"
                && text(&packet.object, "request_id")? == p.id,
        )?;
        for name in [
            "selection_id",
            "administrator_offer_id",
            "root_state_id",
            "person_lease_id",
            "host_lease_id",
        ] {
            check(text(&packet.payload, name)? == field(&r, name)?)?;
        }
        for (kind, name) in [
            ("binding_lease", "binding_lease"),
            ("device_lease", "device_lease"),
        ] {
            if let Some(index) = i
                .record
                .templates
                .iter()
                .position(|t| t.object_type == kind)
            {
                let object = objects[index]
                    .as_ref()
                    .ok_or_else(|| Error::new("state_conflict"))?;
                check(super::catalog::raw_field(&packet.payload_bytes, name)? == object.bytes())?;
            } else {
                check(
                    kind == "binding_lease"
                        && text(&packet.payload, name)? == field(&r, "binding_lease_id")?,
                )?;
            }
        }
        if p.record.owner_finalization_packet_base64 != "-" {
            check(
                i.record.completed
                    && f.pending()?.is_empty()
                    && b64(&p.record.owner_finalization_packet_base64, MAX_OBJECT)? == f.bytes()
                    && p.record.owner_finalization_id == packet.id,
            )?;
        }
    } else {
        check(p.record.owner_finalization_packet_base64 == "-")?;
    }
    Ok(())
}
