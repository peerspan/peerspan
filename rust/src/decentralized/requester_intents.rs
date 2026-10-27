//! Requester approval, typed signatures and ciphertext are separate commits.
//! The requester selector is private possession, never device authority.
use super::{bytes, db, retain_outbound};
use crate::{
    decentralized::{
        codec::*,
        controls,
        intents::{Filled, Intent, Provider, Record, Template},
        observer::{self, Evidence, Offer},
        requests::{self, Pending},
        statement::Descriptor,
        transcript::Packet,
    },
    store::Store,
};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};

fn selection_packet(p: &Pending, offer: &Offer, now: &str) -> Result<Vec<u8>> {
    let person = text(&offer.owner.object, "person_public_key")?;
    let payload = json!({"request_packet_id":p.packet()?.id,"owner_offer_id":offer.owner.id,"context_id":offer.descriptor.context_id(),"person_public_key":person,"host_public_key":p.record.host_public_key,"device_public_key":p.record.device_public_key,"selected_at":now});
    let raw = bytes(
        &json!({"format":1,"context_id":offer.descriptor.context_id(),"request_id":p.id,"role":"selection","writer_host_public_key":p.record.host_public_key,"signer_public_key":p.record.device_public_key,"person_public_key":person,"issuer_id":"-","payload_base64":encode(&bytes(&payload)?),"host_signature":"-","device_signature":"-","authority_signature_format":"-","authority_signature":"-"}),
    )?;
    Packet::read_template(&raw)?;
    Ok(raw)
}
fn check_intent(p: &Pending, i: &Intent, d: &Descriptor, owner: &Packet) -> Result<()> {
    let r = &i.record;
    check(
        i.kind == "selection"
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && i.secret.is_none()
            && r.operation_id == p.id
            && r.provider.kind == "requester"
            && r.provider.signer_public_key == p.record.device_public_key
            && r.person_public_key == text(&owner.object, "person_public_key")?
            && r.host_public_key == p.record.host_public_key
            && r.device_public_key == p.record.device_public_key
            && r.root_state_id == text(&owner.payload, "root_state_id")?
            && r.scopes == num(&owner.payload, "scopes")?
            && r.not_after == text(&owner.payload, "not_after")?
            && r.expires_at == p.deadline
            && r.created_at.as_str() >= text(&p.packet()?.payload, "created_at")?
            && r.templates.len() == 1
            && r.templates[0].object_type == "selection_packet",
    )?;
    let raw = b64(&r.templates[0].template_base64, MAX_OBJECT)?;
    let template = Packet::read_template(&raw)?;
    check(
        text(&template.object, "host_signature")? == "-"
            && text(&template.object, "device_signature")? == "-",
    )?;
    crate::decentralized::state::check_requester_selection(&p.packet()?, owner, &template, d)?;
    let selected = stamp(text(&template.payload, "selected_at")?)?;
    check(text(&template.payload, "selected_at")? == r.created_at)?;
    check(
        selected >= stamp(text(&p.packet()?.payload, "created_at")?)?
            && selected < stamp(&p.deadline)?,
    )?;
    let review = parse(&b64(&r.review_base64, 1 << 20)?, 1 << 20)?;
    let review = object(&review)?;
    fields(
        review,
        "stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning",
    )?;
    check(
        text(review, "stage")? == "selection"
            && text(review, "network_id")? == d.network_id
            && text(review, "context_id")? == d.context_id()
            && text(review, "owner_offer_id")? == owner.id
            && text(review, "selection_id")? == template.id
            && text(review, "person_public_key")? == r.person_public_key
            && text(review, "host_public_key")? == r.host_public_key
            && text(review, "device_public_key")? == r.device_public_key
            && text(review, "root_state_id")? == r.root_state_id
            && num(review, "scopes")? == r.scopes
            && text(review, "not_after")? == r.not_after,
    )?;
    let objects = i.objects(d)?;
    let value = objects[0]
        .as_ref()
        .ok_or_else(|| Error::new("state_conflict"))?;
    check(r.completed == value.pending()?.is_empty())?;
    if p.record.selection_packet_base64 != "-" {
        check(r.completed && b64(&p.record.selection_packet_base64, MAX_OBJECT)? == value.bytes())?;
    }
    Ok(())
}
pub(crate) fn validate_references(c: &Connection, p: &Pending) -> Result<()> {
    for (reference, kind, approved) in [
        (
            &p.record.selection_intent_id,
            "selection",
            p.record.selection_approved,
        ),
        (
            &p.record.commit_intent_id,
            "requester_commit",
            p.record.commit_approved,
        ),
    ] {
        if reference == "-" {
            check(!approved)?;
            continue;
        }
        let i = Intent::load(c, reference).map_err(|_| Error::new("state_conflict"))?;
        let d = Descriptor::read(&b64(&p.record.descriptor_base64, MAX_OBJECT)?)?;
        let owner = Packet::read(&b64(&p.record.owner_packet_base64, MAX_OBJECT)?)?;
        check(
            approved
                && i.kind == kind
                && i.record.approved
                && i.record.operation_id == p.id
                && i.network_id == d.network_id
                && i.context_id == d.context_id()
                && i.record.provider.kind == "requester"
                && i.secret.is_none()
                && i.record.host_public_key == p.record.host_public_key
                && i.record.device_public_key == p.record.device_public_key
                && i.record.person_public_key == text(&owner.object, "person_public_key")?,
        )?;
        let actual: Vec<u8> = c
            .query_row(
                "SELECT private_key FROM identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        let key = SigningKey::from_keypair_bytes(
            actual
                .as_slice()
                .try_into()
                .map_err(|_| Error::new("state_conflict"))?,
        )
        .map_err(|_| Error::new("state_conflict"))?;
        check(encode(key.verifying_key().as_bytes()) == i.record.host_public_key)?;
        if kind == "selection" {
            check_intent(p, &i, &d, &owner).map_err(|_| Error::new("state_conflict"))?
        } else {
            super::commitment::check_reference(p, &i, &d, &owner)
                .map_err(|_| Error::new("state_conflict"))?
        }
    }
    Ok(())
}
pub(super) fn context(
    c: &Connection,
    store: &Store,
    p: &Pending,
    owner_id: &str,
) -> Result<(Offer, String)> {
    context_mode(c, store, p, owner_id, false)
}
pub(super) fn commit_context(
    c: &Connection,
    store: &Store,
    p: &Pending,
    owner_id: &str,
) -> Result<(Offer, String)> {
    context_mode(c, store, p, owner_id, true)
}
fn context_mode(
    c: &Connection,
    store: &Store,
    p: &Pending,
    owner_id: &str,
    complete_staged: bool,
) -> Result<(Offer, String)> {
    require(p.record.roles.iter().any(|r| r == "requester"), "forbidden")?;
    check(store.identity().public_key == p.record.host_public_key)?;
    let now = controls::local_decision_time()?;
    require(
        p.record.terminal == "-"
            || complete_staged
                && p.record.terminal == "migration_prepared"
                && p.record.migration_proposal_id != "-"
                && p.record.commit_approved
                && p.record.commit_packet_base64 != "-",
        "operation_conflict",
    )?;
    require(stamp(&now)? < stamp(&p.deadline)?, "expired")?;
    let evidence = Evidence::read(c, p, &now)?;
    let mut offer = evidence.offer(c, store, p, owner_id, &now)?;
    let decision = decision_clock(
        &offer.decision_time,
        text(&p.packet()?.payload, "created_at")?,
    )?;
    let decision = controls::guarded_decision(c, &offer.descriptor.network_id, &decision)?;
    if decision != offer.decision_time {
        offer = evidence.offer(c, store, p, owner_id, &decision)?;
    }
    require(stamp(&decision)? < stamp(&p.deadline)?, "expired")?;
    Ok((offer, decision))
}
pub(super) fn pins(input: &Obj, p: &Pending, offer: &Offer) -> Result<()> {
    let ctx = offer.descriptor.context_id();
    let preview = input.get("approve").and_then(Value::as_bool) == Some(false);
    for (field, want) in [
        ("network_id", offer.descriptor.network_id.as_str()),
        ("context_id", ctx.as_str()),
        (
            "person_public_key",
            text(&offer.owner.object, "person_public_key")?,
        ),
        ("host_public_key", p.record.host_public_key.as_str()),
        ("device_public_key", p.record.device_public_key.as_str()),
    ] {
        let actual = text(input, field)?;
        check(actual == want || preview && actual == "-")?
    }
    Ok(())
}
pub(super) fn historical(p: &Pending, i: &Intent, input: &Obj, commit: bool) -> Result<Vec<u8>> {
    require(
        p.record.terminal == "applied" && i.record.approved && i.record.completed,
        "operation_conflict",
    )?;
    let d = Descriptor::read(&b64(&p.record.descriptor_base64, MAX_OBJECT)?)?;
    for (field, want) in [
        ("network_id", d.network_id.as_str()),
        ("context_id", d.context_id().as_str()),
        ("owner_offer_id", p.record.owner_offer_id.as_str()),
        ("person_public_key", i.record.person_public_key.as_str()),
        ("host_public_key", p.record.host_public_key.as_str()),
        ("device_public_key", p.record.device_public_key.as_str()),
    ] {
        require(text(input, field)? == want, "operation_conflict")?
    }
    if commit {
        for (field, want) in [
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
            require(text(input, field)? == want, "operation_conflict")?
        }
    }
    bytes(
        &json!({"request":p.view("-")?,"review":parse(&b64(&i.record.review_base64,MAX_OBJECT)?,MAX_OBJECT)?}),
    )
}
fn preflight(c: &Connection, p: &Pending, i: &Intent) -> Result<()> {
    let frames = requests::frames(c, p)?;
    // Both raw Ed25519 signature strings have fixed canonical lengths. Budget
    // the exact final packet/plaintext length before generating either one.
    let raw = b64(&i.record.templates[0].template_base64, MAX_OBJECT)?;
    let packet_length = raw
        .len()
        .checked_add(174)
        .ok_or_else(|| Error::new("quota_exceeded"))?;
    let plaintext = bytes(
        &json!({"packet_base64":encode(&vec![0;packet_length]),"catalog_base64":"-","contacts":[]}),
    )?;
    require(
        frames.len() < 64
            && frames.iter().map(|f| f.ciphertext.len()).sum::<usize>() + plaintext.len() + 16
                <= 32 << 20,
        "quota_exceeded",
    )
}
fn new_intent(c: &Connection, p: &Pending, offer: &Offer, now: &str) -> Result<Intent> {
    let mut q=c.prepare("SELECT intent_id FROM dec_intents WHERE network_id=?1 AND context_id=?2 AND kind='selection' AND json_extract(record,'$.operation_id')=?3 ORDER BY intent_id").map_err(db)?;
    for row in q
        .query_map(
            rusqlite::params![
                offer.descriptor.network_id,
                offer.descriptor.context_id(),
                p.id
            ],
            |r| r.get::<_, String>(0),
        )
        .map_err(db)?
    {
        let i = Intent::load(c, &row.map_err(db)?)?;
        let review = parse(&b64(&i.record.review_base64, 1 << 20)?, 1 << 20)?;
        if review.get("owner_offer_id").and_then(Value::as_str) == Some(offer.owner.id.as_str()) {
            check_intent(p, &i, &offer.descriptor, &offer.owner)?;
            return Ok(i);
        }
    }
    let total: i64 = c
        .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
        .map_err(db)?;
    let active:i64=c.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
    require(total < 4096 && active < 64, "quota_exceeded")?;
    let raw = selection_packet(p, offer, now)?;
    let packet = Packet::read_template(&raw)?;
    let mut review = offer.review(p, "selection")?;
    review["selection_id"] = json!(packet.id);
    Ok(Intent {
        id: crate::store::new_id("dint").map_err(|_| Error::new("internal"))?,
        network_id: offer.descriptor.network_id.clone(),
        context_id: offer.descriptor.context_id(),
        kind: "selection".into(),
        secret: None,
        record: Record {
            format: 1,
            operation_id: p.id.clone(),
            approved: false,
            approved_at: "-".into(),
            review_base64: encode(&bytes(&review)?),
            provider: Provider {
                kind: "requester".into(),
                signer_public_key: p.record.device_public_key.clone(),
                signature_format: "ed25519".into(),
                lease_id: "-".into(),
            },
            root_state_id: text(&offer.owner.payload, "root_state_id")?.into(),
            person_public_key: text(&offer.owner.object, "person_public_key")?.into(),
            host_public_key: p.record.host_public_key.clone(),
            device_public_key: p.record.device_public_key.clone(),
            scopes: num(&offer.owner.payload, "scopes")?,
            not_after: text(&offer.owner.payload, "not_after")?.into(),
            created_at: now.into(),
            expires_at: p.deadline.clone(),
            templates: vec![Template {
                slot_id: 1,
                object_type: "selection_packet".into(),
                template_base64: encode(&raw),
            }],
            signatures: Vec::new(),
            completed: false,
            terminal: "-".into(),
            result_base64: "-".into(),
        },
    })
}
pub(crate) fn select(store: &Store, id: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(
        input,
        "owner_offer_id network_id context_id person_public_key host_public_key device_public_key approve",
    )?;
    let approve = input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let requested_owner = text(input, "owner_offer_id")?;
    check(ident(requested_owner, "dpk_") || !approve && requested_owner == "-")?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    if p.record.terminal == "applied" {
        return historical(
            &p,
            &Intent::load(&tx, &p.record.selection_intent_id)?,
            input,
            false,
        );
    }
    let owner_id = if requested_owner != "-" {
        requested_owner.to_owned()
    } else if p.record.selection_approved {
        p.record.owner_offer_id.clone()
    } else {
        let evidence = Evidence::read(&tx, &p, &controls::local_decision_time()?)?;
        let owners = evidence
            .packets
            .values()
            .filter(|o| o.packet.object.get("role").and_then(Value::as_str) == Some("owner"))
            .map(|o| o.packet.id.clone())
            .collect::<Vec<_>>();
        require(owners.len() <= 1, "state_conflict")?;
        owners
            .into_iter()
            .next()
            .ok_or_else(|| Error::new("review_required"))?
    };
    if p.record.selection_approved {
        check(p.record.owner_offer_id == owner_id)?
    }
    let (offer, now) = context(&tx, store, &p, &owner_id)?;
    pins(input, &p, &offer)?;
    let mut i = if p.record.selection_intent_id != "-" {
        Intent::load(&tx, &p.record.selection_intent_id)?
    } else {
        new_intent(&tx, &p, &offer, &now)?
    };
    check_intent(&p, &i, &offer.descriptor, &offer.owner)?;
    let existed: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM dec_intents WHERE intent_id=?1)",
            [&i.id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let mut approved = false;
    if approve && !p.record.selection_approved {
        observer::owned_device(store, &tx, &p)?;
        preflight(&tx, &p, &i)?;
        i.record.approved = true;
        i.record.approved_at = now.clone();
        offer.remember(&mut p)?;
        p.record.selection_intent_id = i.id.clone();
        p.record.selection_approved = true;
        approved = true;
    }
    i.save(&tx)?;
    requests::save(&tx, &p)?;
    controls::remember_decision(&tx, &i.network_id, &now)?;
    let response = bytes(
        &json!({"request":p.view(&now)?,"review":parse(&b64(&i.record.review_base64,1<<20)?,1<<20)?}),
    )?;
    tx.commit().map_err(db)?;
    drop(c);
    if !existed {
        controls::barrier(store, "dec.intent.after_commit", id)?
    }
    if approved {
        controls::barrier(store, "dec.approval.after_commit", id)?
    }
    if approve {
        resume_approved(store, id)?;
        return response_now(store, id);
    }
    Ok(response)
}
fn response_now(store: &Store, id: &str) -> Result<Vec<u8>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let p = requests::load(&c, id)?;
    let i = Intent::load(&c, &p.record.selection_intent_id)?;
    bytes(
        &json!({"request":p.view(&controls::local_decision_time()?)?,"review":parse(&b64(&i.record.review_base64,1<<20)?,1<<20)?}),
    )
}
pub(super) fn framed(p: &Pending, role: &str) -> bool {
    p.record
        .outbound_frames
        .iter()
        .any(|f| f["role"] == role && f["writer_public_key"] == p.record.host_public_key)
}
pub(crate) fn resume_approved(store: &Store, id: &str) -> Result<()> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    if !p.record.selection_approved || framed(&p, "selection") || p.record.terminal != "-" {
        return Ok(());
    }
    let (offer, now) = context(&tx, store, &p, &p.record.owner_offer_id)?;
    let mut i = Intent::load(&tx, &p.record.selection_intent_id)?;
    check_intent(&p, &i, &offer.descriptor, &offer.owner)?;
    let mut changed = false;
    if !i.record.completed {
        preflight(&tx, &p, &i)?;
        let device = observer::owned_device(store, &tx, &p)?;
        for (index, value) in i.objects(&offer.descriptor)?.into_iter().enumerate() {
            let value = value.ok_or_else(|| Error::new("state_conflict"))?;
            for slot in value.pending()? {
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
        }
        i.record
            .signatures
            .sort_by(|a, b| (&a.slot_id, &a.role).cmp(&(&b.slot_id, &b.role)));
        i.record.completed = i.objects(&offer.descriptor)?.iter().all(|o| {
            o.as_ref()
                .is_some_and(|o| o.pending().is_ok_and(|p| p.is_empty()))
        });
        check_intent(&p, &i, &offer.descriptor, &offer.owner)?;
        i.save(&tx)?;
        let assembled = i.objects(&offer.descriptor)?;
        let raw = assembled[0]
            .as_ref()
            .ok_or_else(|| Error::new("state_conflict"))?
            .bytes();
        let packet = Packet::read(raw)?;
        p.record.selection_packet_base64 = encode(raw);
        p.record.selection_id = packet.id;
        requests::save(&tx, &p)?;
        controls::remember_decision(&tx, &i.network_id, &now)?;
        changed = true;
    }
    tx.commit().map_err(db)?;
    drop(c);
    if changed {
        controls::barrier(store, "dec.signature.after_commit", id)?;
        controls::barrier(store, "dec.selection.after_commit", id)?;
    }
    // Reopen after the signature commit: ciphertext is never made from a
    // signature batch that can still disappear with an uncommitted TX.
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    if framed(&p, "selection") {
        return Ok(());
    }
    let (offer, now) = context(&tx, store, &p, &p.record.owner_offer_id)?;
    let i = Intent::load(&tx, &p.record.selection_intent_id)?;
    check_intent(&p, &i, &offer.descriptor, &offer.owner)?;
    require(i.record.completed, "state_conflict")?;
    let objects = i.objects(&offer.descriptor)?;
    let raw = objects[0]
        .as_ref()
        .ok_or_else(|| Error::new("state_conflict"))?
        .bytes();
    let packet = Packet::read(raw)?;
    retain_outbound(&tx, store, &mut p, "selection", raw, "-", &now)?;
    p.record.selection_packet_base64 = encode(raw);
    p.record.selection_id = packet.id;
    requests::save(&tx, &p)?;
    controls::remember_decision(&tx, &i.network_id, &now)?;
    tx.commit().map_err(db)?;
    drop(c);
    controls::barrier(store, "dec.frame.after_commit", id)
}
