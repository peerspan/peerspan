//! An administrator signs only one exact selected request. Pending P/H proofs
//! and the packet remain preparation evidence until full requester consent.
use super::{
    bootstrap::PairingToken,
    catalog::Catalog,
    ceremony::*,
    codec::*,
    controls,
    intents::{self, Filled, FixedObject, Intent, Template},
    observer::{Evidence, Offer},
    provider::Resolved,
    requests::{self, Pending},
    state::{CeremonyPrefix, Projection},
    statement::Statement,
    storage::Snapshot,
    template::FixedStatement,
    transcript::Packet,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;
const INPUT: &str = "code network_id person_public_key provider_id signature_format owner_offer_id selection_id expected_host_public_key expected_device_public_key approve";

pub(crate) fn open(store: &Store, input: &Obj) -> Result<String> {
    fields(input, INPUT)?;
    input
        .get("approve")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("invalid"))?;
    let now = controls::local_decision_time()?;
    let code = PairingToken::read(text(input, "code")?, &now)?;
    let request = Packet::read(&code.request_packet)?;
    let network = text(input, "network_id")?;
    let person = text(input, "person_public_key")?;
    check(
        ident(network, "net_")
            && key(person)
            && ident(text(input, "owner_offer_id")?, "dpk_")
            && ident(text(input, "selection_id")?, "dpk_")
            && text(input, "expected_host_public_key")?
                == text(&request.payload, "host_public_key")?
            && text(input, "expected_device_public_key")?
                == text(&request.payload, "device_public_key")?,
    )?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    // In-place migration is removed (DEC-OWN3).
    require(
        text(&request.payload, "migration_proposal_id")? == "-",
        "not_found",
    )?;
    let snapshot = Some(Snapshot::load(&tx, network, &store.identity().public_key)?);
    let known_descriptor = &snapshot
        .as_ref()
        .ok_or_else(|| Error::new("state_conflict"))?
        .descriptor;
    let base_catalog = &snapshot
        .as_ref()
        .ok_or_else(|| Error::new("state_conflict"))?
        .prior
        .catalog;
    for (field, want) in [
        ("expected_network_id", network),
        (
            "expected_context_id",
            known_descriptor.context_id().as_str(),
        ),
        ("expected_person_public_key", person),
    ] {
        check(text(&request.payload, field)? == "-" || text(&request.payload, field)? == want)?;
    }
    let mut p = match requests::load(&tx, &code.request_id) {
        Ok(p) => p,
        Err(e) if e.code == "not_found" => {
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_pending", [], |r| r.get(0))
                .map_err(db)?;
            let active:i64=tx.query_row("SELECT COUNT(*) FROM dec_pending WHERE request_id GLOB 'link_*' AND json_extract(record,'$.terminal') IN ('-','migration_prepared')",[],|r|r.get(0)).map_err(db)?;
            require(count < 4096 && active < 8, "quota_exceeded")?;
            let mut p = from_code(&code, known_descriptor)?;
            p.record.roles = vec!["administrator".into()];
            p
        }
        Err(e) => return Err(e),
    };
    require(
        p.secret == Some(code.secret)
            && p.record.request_packet_base64 == encode(&code.request_packet),
        "operation_conflict",
    )?;
    if p.record.descriptor_base64 != "-" {
        check(descriptor(&p)?.context_id() == known_descriptor.context_id())?;
    }
    if p.record.owner_intent_id != "-" {
        let owner = Intent::load(&tx, &p.record.owner_intent_id)?;
        let review = read_review(&owner)?;
        // An owner provider with scope8 may also admit under its own reviewed
        // terms. An explicit network_root admission is a separate independent
        // administrator choice and is never pinned to the owner's provider.
        if owner.record.approved
            && num(object(&review["provider"])?, "scopes")? & 8 == 8
            && text(input, "provider_id")? != "network_root"
        {
            let requested = if text(input, "provider_id")? == "auto" {
                let snapshot = snapshot.as_ref().ok_or_else(|| Error::new("forbidden"))?;
                let projection = snapshot.project(&now)?;
                Resolved::resolve(
                    &tx,
                    snapshot,
                    &projection,
                    "auto",
                    text(input, "signature_format")?,
                    "host_lease",
                )?
                .provider
            } else {
                let expected = if owner.record.provider.kind == "device" {
                    &owner.record.provider.lease_id
                } else {
                    &owner.record.provider.signer_public_key
                };
                require(text(input, "provider_id")? == expected, "state_conflict")?;
                owner.record.provider.clone()
            };
            require(
                requested.kind == owner.record.provider.kind
                    && requested.signer_public_key == owner.record.provider.signer_public_key
                    && requested.lease_id == owner.record.provider.lease_id,
                "state_conflict",
            )?;
        }
    }
    if p.record.administrator_intent_id != "-" {
        let i = Intent::load(&tx, &p.record.administrator_intent_id)?;
        let concrete = if i.record.provider.kind == "root" {
            "network_root"
        } else if i.record.provider.kind == "device" {
            &i.record.provider.lease_id
        } else {
            &i.record.provider.signer_public_key
        };
        require(
            text(input, "provider_id")? == "auto" || text(input, "provider_id")? == concrete,
            "state_conflict",
        )?;
    }
    p.record.descriptor_base64 = encode(&bytes(known_descriptor)?);
    if p.record.catalog_base64 == "-" {
        p.record.catalog_base64 = encode(&base_catalog.bytes);
    }
    requests::save(&tx, &p)?;
    tx.commit().map_err(db)?;
    Ok(p.id)
}
struct Base {
    snapshot: Option<Snapshot>,
    descriptor: super::statement::Descriptor,
    host: String,
    prior: Value,
    projection: Projection,
    offer: Offer,
    selection: Packet,
    now: String,
}
fn base(
    c: &Connection,
    store: &Store,
    p: &Pending,
    owner_id: &str,
    selection_id: &str,
) -> Result<Base> {
    require(
        p.record.terminal == "-" && p.record.commit_packet_base64 == "-",
        "operation_conflict",
    )?;
    let d = descriptor(p)?;
    let now = controls::guarded_decision(c, &d.network_id, &controls::local_decision_time()?)?;
    require(stamp(&now)? < stamp(&p.deadline)?, "expired")?;
    let evidence = Evidence::read(c, p, &now)?;
    let offer = evidence.offer(c, store, p, owner_id, &now)?;
    let selected = evidence
        .packets
        .get(selection_id)
        .ok_or_else(|| Error::missing(selection_id))?
        .packet
        .clone();
    super::state::check_requester_selection(&p.packet()?, &offer.owner, &selected, &d)?;
    let snapshot = if offer.staging.is_none() {
        Some(Snapshot::load(
            c,
            &d.network_id,
            &store.identity().public_key,
        )?)
    } else {
        None
    };
    let prior = snapshot
        .as_ref()
        .map(|s| s.prior.value.clone())
        .unwrap_or(Value::from("-"));
    let projection = if let Some(stage) = &offer.staging {
        check(stage.descriptor.context_id() == d.context_id())?;
        stage.clone()
    } else {
        let snapshot = snapshot
            .as_ref()
            .ok_or_else(|| Error::new("state_conflict"))?;
        check(snapshot.descriptor.context_id() == d.context_id())?;
        let catalog = if let Some(catalog) = &offer.catalog {
            Catalog::union(&d, &snapshot.prior.catalog, catalog)?
        } else {
            snapshot.prior.catalog.clone()
        };
        Projection::read_with_proofs(&d, &prior, &catalog.bytes, &now)?
    };
    let now = projection.decision_time.clone();
    Ok(Base {
        snapshot,
        descriptor: d,
        host: store.identity().public_key,
        prior,
        projection,
        offer,
        selection: selected,
        now,
    })
}
fn resolve(c: &Connection, b: &Base, provider: &str, format: &str) -> Result<Resolved> {
    if let Some(snapshot) = &b.snapshot {
        return Resolved::resolve(c, snapshot, &b.projection, provider, format, "host_lease");
    }
    // Without an adopted network there is no administrator path; in-place
    // migration is removed (DEC-OWN3).
    let _ = (c, provider, format);
    Err(Error::new("forbidden"))
}
/// Verify a retained incoming prefix without opening/preparing an admission,
/// resolving a signer, updating a clock or importing anything from transport.
pub(crate) fn inspect_original(c: &Connection, store: &Store, p: &Pending) -> Result<Value> {
    require(
        p.record.roles.iter().any(|r| r == "administrator")
            && !p.record.roles.iter().any(|r| r == "requester")
            && p.record.mode == "new"
            && p.record.migration_proposal_id == "-"
            && p.record.owner_offer_id != "-"
            && p.record.selection_id != "-"
            && p.record.administrator_offer_id == "-"
            && p.record.owner_finalization_id == "-"
            && p.record.commit_packet_base64 == "-"
            && p.record.manifest_id == "-"
            && p.record.activation_id == "-"
            && p.record.outcome_packet_base64 == "-",
        "state_conflict",
    )?;
    let b = base(
        c,
        store,
        p,
        &p.record.owner_offer_id,
        &p.record.selection_id,
    )?;
    let request = p.view(&b.now)?;
    require(
        request["state"] == "needs_administrator"
            && stamp(&b.now)? >= stamp(field(&request, "created_at")?)?
            && (p.record.stage_at == "-" || stamp(&b.now)? >= stamp(&p.record.stage_at)?),
        "state_conflict",
    )?;
    let owner = &b.offer.owner;
    let payload = &owner.payload;
    let signed_request = p.packet()?;
    let fixed_end = (stamp(text(&signed_request.payload, "created_at")?)?
        + chrono::TimeDelta::days(7))
    .format("%Y-%m-%dT%H:%M:%SZ")
    .to_string();
    check(
        b.offer.provider["kind"] == "original_person"
            && text(payload, "root_state_id")? == "-"
            && text(payload, "person_lease_id")? == "-"
            && ids(payload, "issuer_lease_ids", "ds_")?.is_empty()
            && text(payload, "renewed_device_lease_id")? == "-"
            && num(payload, "scopes")? == 7
            && text(payload, "not_after")? == fixed_end
            && text(&owner.object, "authority_signature_format")? == "sshsig"
            && text(&owner.object, "writer_host_public_key")? == p.record.host_public_key
            && p.record.expected_network_id == b.descriptor.network_id
            && p.record.expected_context_id == b.descriptor.context_id()
            && p.record.expected_person_public_key == text(&owner.object, "person_public_key")?,
    )?;
    Ok(json!({"observed_at":b.now,"request":request,
        "network":{"id":b.descriptor.network_id,"name":b.descriptor.name,
            "context_id":b.descriptor.context_id(),"genesis_root_public_key":b.descriptor.genesis_root_public_key},
        "root_state_id":b.projection.root_state_id()?,"member":payload["member"],
        "scopes":7,"not_after":fixed_end}))
}
fn issuer(base: &Base, r: &Resolved) -> Result<(Value, BTreeMap<String, String>)> {
    if r.provider.kind == "root" {
        return Ok((
            json!({"kind":"root","person_public_key":"-"}),
            BTreeMap::new(),
        ));
    }
    let person = text(&r.actor, "person_public_key")?;
    let member = base.projection.member_for(&base.host, person)?;
    let a = base
        .projection
        .streams
        .get(&vec!["admin".into(), person.into()])
        .ok_or_else(|| Error::new("forbidden"))?;
    require(a.heads.len() == 1, "state_conflict")?;
    let admin = a
        .heads
        .first()
        .ok_or_else(|| Error::new("proof_required"))?;
    base.projection.active(admin)?;
    let mut parents = BTreeMap::from([
        ("issuer_person".into(), member.person_lease_id),
        ("issuer_admin".into(), admin.clone()),
    ]);
    if r.provider.kind == "device" {
        parents.insert("issuer_device".into(), r.provider.lease_id.clone());
    }
    Ok((
        json!({"kind":if r.provider.kind=="device" {"device"}else{"person"},"person_public_key":person}),
        parents,
    ))
}
fn draft(base: &Base, p: &Pending, r: &Resolved, kind: &str, time: &str) -> Result<Vec<u8>> {
    let person = text(&base.offer.owner.object, "person_public_key")?;
    let (actor, parents) = issuer(base, r)?;
    let stream = vec![
        if kind == "person_lease" {
            "person"
        } else {
            "host"
        }
        .to_owned(),
        if kind == "person_lease" {
            person.to_owned()
        } else {
            p.record.host_public_key.clone()
        },
    ];
    let old = base.projection.streams.get(&stream);
    require(old.is_none_or(|s| s.heads.len() <= 1), "state_conflict")?;
    let sequence = old
        .map_or(0, |s| s.maximum)
        .checked_add(1)
        .ok_or_else(|| Error::new("version_exhausted"))?;
    let payload = json!({"root_state_id":base.projection.root_state_id()?,"operation_id":p.id,"sequence":sequence,"predecessors":old.map(|s|s.heads.clone()).unwrap_or_default(),"resolves":[],"retained_statement_ids":[],"subject":{"person_public_key":if kind=="person_lease"{person}else{"-"},"host_public_key":if kind=="host_lease"{p.record.host_public_key.as_str()}else{"-"},"device_public_key":"-","member":text(&base.offer.owner.payload,"member")?,"scopes":0},"issuer":actor,"parents":parents.into_iter().map(|(role,id)|json!({"role":role,"id":id})).collect::<Vec<_>>(),"issued_at":time,"not_before":time,"not_after":text(&base.offer.owner.payload,"not_after")?});
    let raw = bytes(
        &json!({"format":1,"kind":kind,"context_id":base.descriptor.context_id(),"payload_base64":encode(&bytes(&payload)?),"signatures":[{"role":"issuer","public_key":r.provider.signer_public_key,"format":r.provider.signature_format,"signature":"-"}]}),
    )?;
    FixedStatement::read(&base.descriptor, &raw)?;
    Ok(raw)
}
fn existing(base: &Base, p: &Pending, kind: &str) -> Result<Option<Statement>> {
    let person = text(&base.offer.owner.object, "person_public_key")?;
    let stream = vec![
        if kind == "person_lease" {
            "person"
        } else {
            "host"
        }
        .to_owned(),
        if kind == "person_lease" {
            person.to_owned()
        } else {
            p.record.host_public_key.clone()
        },
    ];
    let Some(row) = base.projection.streams.get(&stream) else {
        return Ok(None);
    };
    require(row.heads.len() == 1, "state_conflict")?;
    let id = row
        .heads
        .first()
        .ok_or_else(|| Error::new("proof_required"))?;
    let s = base.projection.catalog.get(id)?;
    base.projection.active(id)?;
    require(
        text(s.subject()?, "member")? == text(&base.offer.owner.payload, "member")?
            && text(&s.payload, "not_after")? >= text(&base.offer.owner.payload, "not_after")?,
        "forbidden",
    )?;
    Ok(Some(s.clone()))
}
fn public_review(p: &Pending, b: &Base, r: &Resolved, person: &str, host: &str) -> Result<Value> {
    let mut review = b.offer.review(p, "administrator")?;
    review["selection_id"] = Value::from(b.selection.id.clone());
    review["root_state_id"] = Value::from(b.projection.root_state_id()?);
    review["person_lease_id"] = Value::from(person);
    review["host_lease_id"] = Value::from(host);
    review["provider"] = r.public(&b.projection, &b.host, false)?;
    require(
        num(object(&review["provider"])?, "scopes")? & 8 == 8,
        "forbidden",
    )?;
    Ok(review)
}
fn new_intent(
    c: &Connection,
    _store: &Store,
    p: &Pending,
    b: &Base,
    input: &Obj,
) -> Result<Intent> {
    let r = resolve(
        c,
        b,
        text(input, "provider_id")?,
        text(input, "signature_format")?,
    )?;
    let mut templates = Vec::new();
    let mut selected = BTreeMap::new();
    for kind in ["person_lease", "host_lease"] {
        let s = if let Some(s) = existing(b, p, kind)? {
            s
        } else {
            let raw = draft(b, p, &r, kind, &b.now)?;
            let s = FixedStatement::read(&b.descriptor, &raw)?.typed().clone();
            templates.push(Template {
                slot_id: templates.len() as u64 + 1,
                object_type: kind.into(),
                template_base64: encode(&raw),
            });
            s
        };
        selected.insert(kind, s);
    }
    let review = public_review(
        p,
        b,
        &r,
        &selected["person_lease"].id,
        &selected["host_lease"].id,
    )?;
    templates.push(Template {
        slot_id: templates.len() as u64 + 1,
        object_type: "administrator_packet".into(),
        template_base64: "-".into(),
    });
    let count: i64 = c
        .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
        .map_err(db)?;
    let active:i64=c.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
    require(count < 4096 && active < 64, "quota_exceeded")?;
    Ok(Intent {
        id: id()?,
        network_id: b.descriptor.network_id.clone(),
        context_id: b.descriptor.context_id(),
        kind: "administrator".into(),
        secret: None,
        record: intents::Record {
            format: 1,
            operation_id: p.id.clone(),
            approved: false,
            approved_at: "-".into(),
            review_base64: encode(&bytes(&review)?),
            provider: r.provider,
            root_state_id: b.projection.root_state_id()?.into(),
            person_public_key: text(&b.offer.owner.object, "person_public_key")?.into(),
            host_public_key: p.record.host_public_key.clone(),
            device_public_key: p.record.device_public_key.clone(),
            scopes: num(&b.offer.owner.payload, "scopes")?,
            not_after: text(&b.offer.owner.payload, "not_after")?.into(),
            created_at: b.now.clone(),
            expires_at: p.deadline.clone(),
            templates,
            signatures: Vec::new(),
            completed: false,
            terminal: "-".into(),
            result_base64: "-".into(),
        },
    })
}
fn load(c: &Connection, p: &Pending) -> Result<Intent> {
    let i = Intent::load(c, &p.record.administrator_intent_id)?;
    let d = descriptor(p)?;
    let review = read_review(&i)?;
    fields(
        object(&review)?,
        "stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning",
    )?;
    check(
        field(&review, "stage")? == "administrator"
            && field(&review, "network_id")? == i.network_id
            && field(&review, "context_id")? == i.context_id
            && field(&review, "person_public_key")? == i.record.person_public_key
            && field(&review, "host_public_key")? == i.record.host_public_key
            && field(&review, "device_public_key")? == i.record.device_public_key
            && field(&review, "root_state_id")? == i.record.root_state_id
            && num(object(&review)?, "scopes")? == i.record.scopes
            && field(&review, "not_after")? == i.record.not_after
            && i.record.created_at.as_str() >= text(&p.packet()?.payload, "created_at")?,
    )?;
    require(
        i.kind == "administrator"
            && i.secret.is_none()
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && i.record.operation_id == p.id
            && i.record.host_public_key == p.record.host_public_key
            && i.record.device_public_key == p.record.device_public_key
            && i.record.expires_at == p.deadline,
        "state_conflict",
    )?;
    let kinds = i
        .record
        .templates
        .iter()
        .map(|t| t.object_type.as_str())
        .collect::<Vec<_>>();
    check(matches!(
        kinds.as_slice(),
        ["administrator_packet"]
            | ["person_lease", "administrator_packet"]
            | ["host_lease", "administrator_packet"]
            | ["person_lease", "host_lease", "administrator_packet"]
    ))?;
    let objects = i.objects(&d)?;
    check(
        i.record.completed
            == objects.iter().all(|o| {
                o.as_ref()
                    .is_some_and(|o| o.pending().is_ok_and(|s| s.is_empty()))
            }),
    )?;
    if p.record.administrator_packet_base64 != "-" {
        let object = objects
            .last()
            .and_then(Option::as_ref)
            .ok_or_else(|| Error::new("state_conflict"))?;
        check(
            i.record.completed
                && object.bytes() == b64(&p.record.administrator_packet_base64, MAX_OBJECT)?
                && Packet::read(object.bytes())?.id == p.record.administrator_offer_id,
        )?;
    }
    Ok(i)
}
pub(crate) fn validate_references(c: &Connection, p: &Pending) -> Result<()> {
    if p.record.administrator_intent_id != "-" {
        load(c, p).map_err(|_| Error::new("state_conflict"))?;
    }
    Ok(())
}
/// The already approved owner review may authorize this exact administrator
/// phase only when its frozen provider actually included administrator power.
/// The new row fixes the current dependencies before any owned signature.
pub(crate) fn resume_owned(store: &Store, id: &str) -> Result<()> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, id)?;
    if p.record.terminal != "-"
        || p.record.owner_intent_id == "-"
        || p.record.administrator_intent_id != "-"
        || p.record.administrator_offer_id != "-"
        || p.record.owner_packet_base64 == "-"
        || p.record.selection_id == "-"
    {
        return Ok(());
    }
    let owner = owner_intent(&tx, &p)?;
    let frozen = read_review(&owner)?;
    if !owner.record.approved || num(object(&frozen["provider"])?, "scopes")? & 8 != 8 {
        return Ok(());
    }
    // A folded owner intent mints the host grant itself; it has no
    // administrator stage (spec 8.2, DEC-S7).
    if owner
        .record
        .templates
        .iter()
        .any(|t| t.object_type == "host_lease")
    {
        return Ok(());
    }
    let b = base(
        &tx,
        store,
        &p,
        &p.record.owner_offer_id,
        &p.record.selection_id,
    )?;
    // Exact current P/H renewal has no administrator phase to preapprove.
    if p.record.mode == "renew"
        && existing(&b, &p, "person_lease")?.is_some()
        && existing(&b, &p, "host_lease")?.is_some()
    {
        return Ok(());
    }
    let provider = if owner.record.provider.kind == "device" {
        owner.record.provider.lease_id.as_str()
    } else {
        owner.record.provider.signer_public_key.as_str()
    };
    let input = object(
        &json!({"provider_id":provider,"signature_format":owner.record.provider.signature_format}),
    )?
    .clone();
    let mut i = new_intent(&tx, store, &p, &b, &input)?;
    require(
        i.record.provider.kind == owner.record.provider.kind
            && i.record.provider.signer_public_key == owner.record.provider.signer_public_key
            && i.record.provider.lease_id == owner.record.provider.lease_id,
        "operation_conflict",
    )?;
    check_current(&tx, store, &p, &i)?;
    i.record.approved = true;
    i.record.approved_at = b.now.clone();
    if !p.record.roles.iter().any(|r| r == "administrator") {
        p.record.roles.push("administrator".into());
    }
    p.record.administrator_intent_id = i.id.clone();
    i.save(&tx)?;
    requests::save(&tx, &p)?;
    controls::remember_decision(&tx, &i.network_id, &b.now)?;
    tx.commit().map_err(db)?;
    drop(c);
    controls::barrier(store, "dec.intent.after_commit", id)?;
    controls::barrier(store, "dec.approval.after_commit", id)?;
    resume(store, id)
}
fn selected(b: &Base, i: &Intent) -> Result<(Statement, Statement)> {
    let review = read_review(i)?;
    let objects = i.objects(&b.descriptor)?;
    let mut result = Vec::new();
    for (kind, name) in [
        ("person_lease", "person_lease_id"),
        ("host_lease", "host_lease_id"),
    ] {
        let s = if let Some(index) = i
            .record
            .templates
            .iter()
            .position(|t| t.object_type == kind)
        {
            match objects[index]
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?
            {
                FixedObject::Statement(s) => s.typed().clone(),
                _ => return Err(Error::new("invalid")),
            }
        } else {
            b.projection.catalog.get(field(&review, name)?)?.clone()
        };
        check(s.kind == kind && s.id == field(&review, name)?)?;
        result.push(s);
    }
    Ok((result.remove(0), result.remove(0)))
}
fn packet(p: &Pending, b: &Base, i: &Intent, r: &Resolved) -> Result<Vec<u8>> {
    let (person, host) = selected(b, i)?;
    let (_, parents) = issuer(b, r)?;
    let mut refs = parents.into_values().collect::<Vec<_>>();
    refs.sort();
    refs.dedup();
    let part = |kind: &str, s: &Statement| -> Result<Box<serde_json::value::RawValue>> {
        if i.record.templates.iter().any(|t| t.object_type == kind) {
            Statement::read(&b.descriptor, &s.body)?;
            serde_json::from_slice(&s.body).map_err(|_| Error::new("invalid"))
        } else {
            serde_json::value::to_raw_value(&s.id).map_err(|_| Error::new("internal"))
        }
    };
    let mut payload = BTreeMap::new();
    for (name, value) in [
        ("selection_id", json!(b.selection.id)),
        ("owner_offer_id", json!(b.offer.owner.id)),
        ("root_state_id", json!(b.projection.root_state_id()?)),
        ("issuer_lease_ids", json!(refs)),
    ] {
        payload.insert(
            name,
            serde_json::value::to_raw_value(&value).map_err(|_| Error::new("internal"))?,
        );
    }
    payload.insert("person_lease", part("person_lease", &person)?);
    payload.insert("host_lease", part("host_lease", &host)?);
    unsigned_packet(store_host(b)?, p, b, r, &bytes(&payload)?)
}
fn store_host(b: &Base) -> Result<&str> {
    Ok(&b.host)
}
fn unsigned_packet(
    host: &str,
    p: &Pending,
    b: &Base,
    r: &Resolved,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let root = r.provider.kind == "root";
    let raw = bytes(
        &json!({"format":1,"context_id":b.descriptor.context_id(),"request_id":p.id,"role":"administrator","writer_host_public_key":host,"signer_public_key":r.provider.signer_public_key,"person_public_key":if root{"-"}else{text(&r.actor,"person_public_key")?},"issuer_id":if root {b.projection.root_state_id()?}else{r.provider.lease_id.as_str()},"payload_base64":encode(payload),"host_signature":"-","device_signature":"-","authority_signature_format":r.provider.signature_format,"authority_signature":"-"}),
    )?;
    Packet::read_template(&raw)?;
    Ok(raw)
}
fn check_current(
    c: &Connection,
    store: &Store,
    p: &Pending,
    i: &Intent,
) -> Result<(Base, Resolved)> {
    let review = read_review(i)?;
    let b = base(
        c,
        store,
        p,
        field(&review, "owner_offer_id")?,
        field(&review, "selection_id")?,
    )?;
    let provider = if i.record.provider.kind == "root" {
        "network_root"
    } else if i.record.provider.kind == "device" {
        &i.record.provider.lease_id
    } else {
        &i.record.provider.signer_public_key
    };
    let r = resolve(c, &b, provider, &i.record.provider.signature_format)?;
    let (person, host) = selected(&b, i)?;
    let mut expected_review = public_review(p, &b, &r, &person.id, &host.id)?;
    expected_review["authority_warning"] = review["authority_warning"].clone();
    expected_review["administrator_offer_id"] = review["administrator_offer_id"].clone();
    check(
        i.record.root_state_id == b.projection.root_state_id()?
            && i.record.person_public_key == text(&b.offer.owner.object, "person_public_key")?
            && i.record.scopes == num(&b.offer.owner.payload, "scopes")?
            && i.record.not_after == text(&b.offer.owner.payload, "not_after")?
            && expected_review == review,
    )?;
    let (_, parents) = issuer(&b, &r)?;
    let mut refs = parents.into_values().collect::<Vec<_>>();
    refs.sort();
    refs.dedup();
    let payload = bytes(
        &json!({"selection_id":b.selection.id,"owner_offer_id":b.offer.owner.id,"root_state_id":b.projection.root_state_id()?,"issuer_lease_ids":refs,"person_lease":person.id,"host_lease":host.id}),
    )?;
    let draft_packet = Packet::read_template(&unsigned_packet(
        &store.identity().public_key,
        p,
        &b,
        &r,
        &payload,
    )?)?;
    let drafts = [person, host]
        .into_iter()
        .filter(|s| text(&s.payload, "operation_id").is_ok_and(|op| op == p.id))
        .collect::<Vec<_>>();
    let objects = i.objects(&b.descriptor)?;
    if let Some(actual) = objects.last().and_then(Option::as_ref) {
        let actual = Packet::read_template(actual.bytes())?;
        check(field(&review, "administrator_offer_id")? == actual.id)?;
        let expected = Packet::read_template(&packet(p, &b, i, &r)?)?;
        for name in [
            "context_id",
            "request_id",
            "role",
            "writer_host_public_key",
            "signer_public_key",
            "person_public_key",
            "issuer_id",
            "authority_signature_format",
        ] {
            check(text(&actual.object, name)? == text(&expected.object, name)?)?;
        }
        check(actual.payload == expected.payload)?;
        for name in ["person_lease", "host_lease"] {
            check(
                super::catalog::raw_field(&actual.payload_bytes, name)?
                    == super::catalog::raw_field(&expected.payload_bytes, name)?,
            )?;
        }
    } else {
        check(field(&review, "administrator_offer_id")? == "-")?;
    }
    b.projection.check_administrator_drafts(
        &p.packet()?,
        &b.offer.owner,
        &b.selection,
        &draft_packet,
        &drafts,
    )?;
    let typed_bytes = i
        .record
        .templates
        .iter()
        .filter(|t| t.template_base64 != "-")
        .map(|t| b64(&t.template_base64, MAX_OBJECT).map(|b| b.len()))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    frame_budget(
        c,
        store,
        p,
        Some(&b.projection.catalog),
        typed_bytes + (64 << 10),
        &b.now,
    )?;
    Ok((b, r))
}
pub(crate) fn prepare(store: &Store, input: &Obj) -> Result<Vec<u8>> {
    fields(input, INPUT)?;
    let now = controls::local_decision_time()?;
    let code = PairingToken::read(text(input, "code")?, &now)?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let mut p = requests::load(&tx, &code.request_id)?;
    let b = base(
        &tx,
        store,
        &p,
        text(input, "owner_offer_id")?,
        text(input, "selection_id")?,
    )?;
    check(
        text(input, "network_id")? == b.descriptor.network_id
            && text(input, "person_public_key")?
                == text(&b.offer.owner.object, "person_public_key")?,
    )?;
    let new = p.record.administrator_intent_id == "-";
    let mut i = if new {
        new_intent(&tx, store, &p, &b, input)?
    } else {
        load(&tx, &p)?
    };
    check_current(&tx, store, &p, &i)?;
    let approved = input["approve"]
        .as_bool()
        .ok_or_else(|| Error::new("invalid"))?;
    let changed = approved && !i.record.approved;
    if changed {
        i.record.approved = true;
        i.record.approved_at = b.now.clone();
    }
    if !p.record.roles.iter().any(|r| r == "administrator") {
        p.record.roles.push("administrator".into());
    }
    b.offer.remember(&mut p)?;
    p.record.selection_id = b.selection.id.clone();
    p.record.selection_packet_base64 =
        encode(&Evidence::read(&tx, &p, &b.now)?.packets[&b.selection.id].bytes);
    p.record.administrator_intent_id = i.id.clone();
    i.save(&tx)?;
    requests::save(&tx, &p)?;
    controls::remember_decision(&tx, &i.network_id, &b.now)?;
    tx.commit().map_err(db)?;
    drop(c);
    if new {
        controls::barrier(store, "dec.intent.after_commit", &p.id)?;
    }
    if changed {
        controls::barrier(store, "dec.approval.after_commit", &p.id)?;
    }
    if approved {
        resume(store, &p.id)?;
    }
    get(store, &p.id)
}
pub(crate) fn get(store: &Store, id: &str) -> Result<Vec<u8>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let p = requests::load(&c, id)?;
    let i = load(&c, &p)?;
    if i.record.approved && !i.record.completed && p.record.terminal == "-" {
        check_current(&c, store, &p, &i)?;
    }
    bytes(
        &json!({"request":p.view(&controls::local_decision_time()?)?,"review":read_review(&i)?,"signing_requests":signing_requests(&i,&descriptor(&p)?)?}),
    )
}
pub(crate) fn signed(store: &Store, id: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "intent_id signatures")?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let p = requests::load(&tx, id)?;
    let mut i = load(&tx, &p)?;
    check(text(input, "intent_id")? == i.id)?;
    require(i.record.approved, "state_conflict")?;
    let (b, _) = check_current(&tx, store, &p, &i)?;
    let entries = array(input, "signatures")?;
    check(!entries.is_empty() && entries.len() <= 16)?;
    let old_signatures = i.record.signatures.len();
    let mut previous = None;
    for value in entries {
        let o = object(value)?;
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
        let object = objects
            .get(slot.checked_sub(1).ok_or_else(|| Error::new("invalid"))? as usize)
            .and_then(Option::as_ref)
            .ok_or_else(|| Error::new("invalid"))?;
        check(
            i.record.provider.signature_format == "sshsig"
                && object.pending()?.iter().any(|s| {
                    s.role == role
                        && s.public_key == i.record.provider.signer_public_key
                        && s.signature_format == "sshsig"
                }),
        )?;
        object.fill(&b.descriptor, role, text(o, "signature")?)?;
        add(&mut i, slot, role, text(o, "signature")?)?;
    }
    let mut p = p;
    complete_packet(store, &mut i, &mut p, &b)?;
    i.save(&tx)?;
    requests::save(&tx, &p)?;
    tx.commit().map_err(db)?;
    drop(c);
    if i.record.signatures.len() > old_signatures {
        controls::barrier(store, "dec.signature.after_commit", id)?;
    }
    resume(store, id)?;
    get(store, id)
}
fn complete_packet(store: &Store, i: &mut Intent, p: &mut Pending, b: &Base) -> Result<()> {
    let objects = i.objects(&b.descriptor)?;
    i.record.completed = objects.iter().all(|o| {
        o.as_ref()
            .is_some_and(|o| o.pending().is_ok_and(|s| s.is_empty()))
    });
    if i.record.completed {
        let raw = objects
            .last()
            .and_then(Option::as_ref)
            .ok_or_else(|| Error::new("state_conflict"))?
            .bytes();
        let a = Packet::read(raw)?;
        Projection::prepare_administrator(CeremonyPrefix {
            descriptor: &b.descriptor,
            prior: &b.prior,
            catalog: &b.projection.catalog,
            request: &p.packet()?,
            owner: &b.offer.owner,
            selection: &b.selection,
            administrator: Some(&a),
            now: &b.now,
            staging: b.offer.staging.as_ref(),
            folded_host: None,
        })?;
        p.record.administrator_offer_id = a.id;
        p.record.administrator_packet_base64 = encode(raw);
    }
    let _ = store;
    Ok(())
}
pub(crate) fn resume(store: &Store, id: &str) -> Result<()> {
    loop {
        let (b, r, i, objects) = {
            let c = store.connection().map_err(|_| Error::new("internal"))?;
            let p = requests::load(&c, id)?;
            if p.record.administrator_intent_id == "-"
                || p.record.terminal != "-"
                || p.record
                    .outbound_frames
                    .iter()
                    .any(|f| f["role"] == "administrator")
            {
                return Ok(());
            }
            let i = load(&c, &p)?;
            if !i.record.approved {
                return Ok(());
            }
            let (b, r) = check_current(&c, store, &p, &i)?;
            let objects = i.objects(&b.descriptor)?;
            (b, r, i, objects)
        };
        let mut generated = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            let Some(object) = object else { continue };
            for slot in object.pending()? {
                let msg = b64(&slot.message_base64, 4096)?;
                let signature = if slot.role == "host"
                    && slot.public_key == store.identity().public_key
                    && slot.signature_format == "ed25519"
                {
                    Some(encode(&store.signing_key.sign(&msg).to_bytes()))
                } else if slot.public_key == r.provider.signer_public_key {
                    if slot.signature_format == "ed25519" {
                        Some(encode(
                            &SigningKey::from_bytes(
                                &r.seed.ok_or_else(|| Error::new("signer_unavailable"))?,
                            )
                            .sign(&msg)
                            .to_bytes(),
                        ))
                    } else {
                        let key = b64(&r.provider.signer_public_key, 32)?
                            .try_into()
                            .map_err(|_| Error::new("invalid"))?;
                        if let Ok(signer) = store.renewal_signer(key) {
                            Some(
                                signer
                                    .sign(
                                        &std::str::from_utf8(&msg)
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
                if let Some(signature) = signature {
                    generated.push(Filled {
                        slot_id: index as u64 + 1,
                        role: slot.role,
                        signature,
                    });
                }
            }
        }
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut p = requests::load(&tx, id)?;
        let mut current = load(&tx, &p)?;
        let (b2, r2) = check_current(&tx, store, &p, &current)?;
        require(
            current
                .record
                .signatures
                .iter()
                .map(|s| (&s.slot_id, &s.role, &s.signature))
                .eq(i
                    .record
                    .signatures
                    .iter()
                    .map(|s| (&s.slot_id, &s.role, &s.signature))),
            "state_conflict",
        )?;
        let barrier = if !generated.is_empty() {
            for sig in generated {
                let object = current
                    .objects(&b2.descriptor)?
                    .remove(sig.slot_id as usize - 1)
                    .ok_or_else(|| Error::new("state_conflict"))?;
                object.fill(&b2.descriptor, &sig.role, &sig.signature)?;
                add(&mut current, sig.slot_id, &sig.role, &sig.signature)?;
            }
            complete_packet(store, &mut current, &mut p, &b2)?;
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
            && objects[..objects.len() - 1].iter().all(|o| {
                o.as_ref()
                    .is_some_and(|o| o.pending().is_ok_and(|s| s.is_empty()))
            })
        {
            let raw = packet(&p, &b2, &current, &r2)?;
            let mut review = read_review(&current)?;
            review["administrator_offer_id"] = Value::from(Packet::read_template(&raw)?.id);
            current.record.review_base64 = encode(&bytes(&review)?);
            current
                .record
                .templates
                .last_mut()
                .ok_or_else(|| Error::new("invalid"))?
                .template_base64 = encode(&raw);
            current.save(&tx)?;
            "dec.intent.after_commit"
        } else if current.record.completed {
            let raw = b64(&p.record.administrator_packet_base64, MAX_OBJECT)?;
            let admin = Packet::read(&raw)?;
            let prepared = Projection::prepare_administrator(CeremonyPrefix {
                descriptor: &b2.descriptor,
                prior: &b2.prior,
                catalog: &b2.projection.catalog,
                request: &p.packet()?,
                owner: &b2.offer.owner,
                selection: &b2.selection,
                administrator: Some(&admin),
                now: &b2.now,
                staging: b2.offer.staging.as_ref(),
                folded_host: None,
            })?;
            super::requester::retain_catalog(&tx, store, &mut p, &prepared.catalog, &b2.now)?;
            retain_packet(&tx, store, &mut p, "administrator", &raw, &b2.now)?;
            p.record.catalog_base64 = encode(&prepared.catalog.bytes);
            requests::save(&tx, &p)?;
            "dec.frame.after_commit"
        } else {
            return Ok(());
        };
        controls::remember_decision(&tx, &current.network_id, &b2.now)?;
        tx.commit().map_err(db)?;
        drop(c);
        controls::barrier(store, barrier, id)?;
        if barrier == "dec.signature.after_commit" && current.record.completed {
            controls::barrier(store, "dec.administrator.after_commit", id)?;
        }
        let _ = b;
    }
}
