//! Reviewed ceremony signing. Typed drafts and local approvals are kept apart
//! from public grant admission, requester consent and final application.
use super::{
    bootstrap::{Invitation, PairingToken},
    codec::*,
    controls,
    intents::{self, FixedObject, Intent},
    provider::Resolved,
    requests::{self, Pending},
    statement::Descriptor,
    storage::Snapshot,
    transcript::Packet,
};
use crate::store::Store;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};

pub(super) fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
pub(super) fn bytes(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::new("internal"))
}
pub(super) fn id() -> Result<String> {
    let mut value = [0; 16];
    getrandom::fill(&mut value).map_err(|_| Error::new("internal"))?;
    Ok(format!("dint_{}", hex::encode(value)))
}
pub(super) fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    text(object(value)?, key)
}
pub(super) fn read_review(intent: &Intent) -> Result<Value> {
    let review = parse(&b64(&intent.record.review_base64, 1 << 20)?, 1 << 20)?;
    let warning = field(&review, "authority_warning")?;
    check(!warning.is_empty() && warning.len() <= 1024)?;
    Ok(review)
}
pub(super) fn endpoint_list(code: &PairingToken) -> Result<Vec<Value>> {
    let mut endpoints = code
        .helpers
        .iter()
        .map(|h| json!({"kind":"helper","address":h["address"],"public_key":h["public_key"]}))
        .collect::<Vec<_>>();
    for contact in &code.contacts {
        for address in array(object(&contact.payload)?, "bootstrap_addresses")? {
            endpoints.push(json!({"kind":"participant","address":address,"public_key":contact.host_public_key}));
        }
    }
    endpoints.sort_by_key(|e| {
        (
            e["kind"].as_str().unwrap_or_default().to_owned(),
            e["address"].as_str().unwrap_or_default().to_owned(),
            e["public_key"].as_str().unwrap_or_default().to_owned(),
        )
    });
    endpoints.dedup();
    require(endpoints.len() <= 8, "quota_exceeded")?;
    Ok(endpoints)
}
pub(super) fn from_code(code: &PairingToken, d: &Descriptor) -> Result<Pending> {
    let request = Packet::read(&code.request_packet)?;
    let p = &request.payload;
    let dash = || "-".to_owned();
    Ok(Pending {
        id: code.request_id.clone(),
        deadline: text(p, "expires_at")?.into(),
        secret: Some(code.secret),
        terminal_read_cap: None,
        record: requests::Record {
            format: 1,
            roles: vec!["owner".into()],
            mode: text(p, "mode")?.into(),
            migration_proposal_id: text(p, "migration_proposal_id")?.into(),
            expected_network_id: text(p, "expected_network_id")?.into(),
            expected_context_id: text(p, "expected_context_id")?.into(),
            expected_person_public_key: text(p, "expected_person_public_key")?.into(),
            contact_invitation_base64: dash(),
            descriptor_base64: encode(&bytes(d)?),
            host_public_key: text(p, "host_public_key")?.into(),
            device_public_key: text(p, "device_public_key")?.into(),
            request_nonce: text(p, "request_nonce")?.into(),
            request_packet_base64: encode(&code.request_packet),
            owner_packet_base64: dash(),
            selection_packet_base64: dash(),
            administrator_packet_base64: dash(),
            owner_finalization_packet_base64: dash(),
            commit_packet_base64: dash(),
            outcome_packet_base64: dash(),
            catalog_base64: dash(),
            owner_offer_id: dash(),
            selection_id: dash(),
            administrator_offer_id: dash(),
            owner_finalization_id: dash(),
            manifest_id: dash(),
            activation_id: dash(),
            selection_approved: false,
            commit_approved: false,
            selection_intent_id: dash(),
            commit_intent_id: dash(),
            owner_intent_id: dash(),
            administrator_intent_id: dash(),
            terminal: dash(),
            carrier_endpoints: endpoint_list(code)?,
            outbound_frames: Vec::new(),
        },
    })
}
struct OwnerTerms {
    descriptor: Descriptor,
    review: Value,
    provider: intents::Provider,
    seed: Option<[u8; 32]>,
    catalog: Option<Vec<u8>>,
    time: String,
    member: String,
    person_lease: String,
    issuer_ids: Vec<String>,
    /// The unsigned host grant of a folded admin stage (spec 8.2).
    folded_host: Option<Vec<u8>>,
}
#[allow(clippy::too_many_arguments)]
fn terms(
    c: &Connection,
    store: &Store,
    pending: &Pending,
    network: &str,
    person: &str,
    provider: &str,
    format: &str,
    scopes: u64,
    not_after: &str,
) -> Result<OwnerTerms> {
    let request = pending.packet()?;
    let r = &request.payload;
    check(
        key(person)
            && scopes > 0
            && scopes <= 15
            && matches!(format, "auto" | "sshsig" | "ed25519"),
    )?;
    for (name, actual) in [
        ("expected_network_id", network),
        ("expected_person_public_key", person),
    ] {
        let expected = text(r, name)?;
        check(expected == "-" || expected == actual)?;
    }
    require(
        pending.record.terminal == "-" && pending.record.commit_packet_base64 == "-",
        "operation_conflict",
    )?;
    let mut time = controls::guarded_decision(c, network, &controls::local_decision_time()?)?;
    require(stamp(&time)? < stamp(&pending.deadline)?, "expired")?;
    require(
        stamp(not_after)? > stamp(&time)?
            && stamp(not_after)? <= stamp(&time)? + chrono::TimeDelta::days(7),
        "forbidden",
    )?;
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [network],
            |r| r.get(0),
        )
        .map_err(db)?;
    let mut folded_host = None;
    let (descriptor, public, private, seed, catalog, member, person_lease, issuer_ids, root) =
        if text(r, "migration_proposal_id")? != "-" {
            let plan = super::migration_link::owner_plan(
                store,
                c,
                pending,
                super::migration_link::OwnerProfile {
                    person,
                    provider,
                    format,
                    scopes,
                    not_after,
                },
            )?;
            time = plan.time;
            (
                plan.descriptor,
                plan.provider,
                intents::Provider {
                    kind: "original".into(),
                    signer_public_key: person.into(),
                    signature_format: "sshsig".into(),
                    lease_id: "-".into(),
                },
                None,
                Some(plan.catalog.bytes),
                plan.member,
                plan.person_lease.clone(),
                vec![plan.person_lease],
                plan.root,
            )
        } else if exists {
            let snapshot = Snapshot::load(c, network, &store.identity().public_key)?;
            let p = snapshot.project(&time)?;
            time = p.decision_time.clone();
            let resolved = Resolved::resolve(c, &snapshot, &p, provider, format, "device_lease")?;
            require(
                resolved.provider.kind != "root"
                    && text(&resolved.actor, "person_public_key")? == person,
                "forbidden",
            )?;
            if resolved.provider.kind == "device" {
                require(
                    resolved.provider.signer_public_key != pending.record.device_public_key,
                    "forbidden",
                )?;
            }
            let public = resolved.public(&p, &store.identity().public_key, false)?;
            require(scopes & !num(object(&public)?, "scopes")? == 0, "forbidden")?;
            require(not_after <= field(&public, "not_after")?, "forbidden")?;
            let stream = p
                .streams
                .get(&vec!["person".into(), person.into()])
                .ok_or_else(|| Error::new("proof_required"))?;
            require(stream.heads.len() == 1, "state_conflict")?;
            let person_lease = stream
                .heads
                .first()
                .ok_or_else(|| Error::new("proof_required"))?
                .clone();
            let member = text(p.catalog.get(&person_lease)?.subject()?, "member")?.to_owned();
            if let Some(host) = p
                .members()?
                .into_iter()
                .find(|m| m.host_public_key == pending.record.host_public_key)
            {
                require(
                    host.person_public_key == "-" || host.person_public_key == person,
                    "forbidden",
                )?;
            }
            let mut ids = vec![person_lease.clone()];
            if resolved.provider.kind == "device" {
                ids.push(resolved.provider.lease_id.clone())
            }
            ids.sort();
            // Fold (spec 8.2, DEC-S7, DEC-Q4): an owner whose path also has
            // the admin role signs the new host grant under this approval.
            if pending.record.mode != "renew"
                && num(object(&public)?, "scopes")? & 8 == 8
                && let Ok(admin) = p.head(&["admin".into(), person.into()])
                && p.active(&admin.id).is_ok()
            {
                let mut parents = std::collections::BTreeMap::from([
                    ("issuer_person", person_lease.clone()),
                    ("issuer_admin", admin.id.clone()),
                ]);
                if resolved.provider.kind == "device" {
                    parents.insert("issuer_device", resolved.provider.lease_id.clone());
                }
                let stream = p
                    .streams
                    .get(&vec!["host".into(), pending.record.host_public_key.clone()]);
                require(stream.is_none_or(|s| s.heads.len() <= 1), "state_conflict")?;
                let sequence = stream
                    .map_or(0, |s| s.maximum)
                    .checked_add(1)
                    .ok_or_else(|| Error::new("version_exhausted"))?;
                let payload = json!({"root_state_id":p.root_state_id()?,"operation_id":pending.id,"sequence":sequence,"predecessors":stream.map(|s|s.heads.clone()).unwrap_or_default(),"resolves":[],"retained_statement_ids":[],"subject":{"person_public_key":"-","host_public_key":pending.record.host_public_key,"device_public_key":"-","member":member,"scopes":0},"issuer":{"kind":if resolved.provider.kind=="device" {"device"} else {"person"},"person_public_key":person},"parents":parents.into_iter().map(|(role,id)|json!({"role":role,"id":id})).collect::<Vec<_>>(),"issued_at":time,"not_before":time,"not_after":not_after});
                let raw = bytes(
                    &json!({"format":1,"kind":"host_lease","context_id":snapshot.descriptor.context_id(),"payload_base64":encode(&bytes(&payload)?),"signatures":[{"role":"issuer","public_key":resolved.provider.signer_public_key,"format":resolved.provider.signature_format,"signature":"-"}]}),
                )?;
                super::template::FixedStatement::read(&snapshot.descriptor, &raw)?;
                folded_host = Some(raw);
            }
            (
                snapshot.descriptor,
                public,
                resolved.provider,
                resolved.seed,
                Some(p.catalog.bytes.clone()),
                member,
                person_lease,
                ids,
                p.root_state_id()?.to_owned(),
            )
        } else {
            // Possession-only offers belong on this requester's original machine
            // and require its independently retained, reviewed introduction.
            require(
                pending.record.roles.iter().any(|r| r == "requester")
                    && pending.record.host_public_key == store.identity().public_key
                    && pending.record.contact_invitation_base64 != "-",
                "proof_required",
            )?;
            check(provider == person && matches!(format, "auto" | "sshsig"))?;
            require(scopes & !7 == 0, "forbidden")?;
            let intro = Invitation::read(
                &b64(&pending.record.contact_invitation_base64, 32 << 10)?,
                text(r, "created_at")?,
            )?;
            check(
                intro.descriptor.network_id == network
                    && (intro.expected_person_public_key == "-"
                        || intro.expected_person_public_key == person),
            )?;
            let private = intents::Provider {
                kind: "original".into(),
                signer_public_key: person.into(),
                signature_format: "sshsig".into(),
                lease_id: "-".into(),
            };
            (
                intro.descriptor,
                json!({"kind":"original_person","person_public_key":person,"host_public_key":store.identity().public_key,"device_public_key":"-","lease_id":"-","root_state_id":"-","scopes":0,"not_after":"-"}),
                private,
                None,
                None,
                intro.member,
                "-".into(),
                Vec::new(),
                "-".to_owned(),
            )
        };
    check(
        text(r, "expected_context_id")? == "-"
            || text(r, "expected_context_id")? == descriptor.context_id(),
    )?;
    if pending.record.descriptor_base64 != "-" {
        check(
            Descriptor::read(&b64(&pending.record.descriptor_base64, MAX_OBJECT)?)?.context_id()
                == descriptor.context_id(),
        )?;
    }
    require(
        stamp(&time)? < stamp(&pending.deadline)? && time.as_str() < not_after,
        "expired",
    )?;
    let folded_id = match &folded_host {
        Some(raw) => super::template::FixedStatement::read(&descriptor, raw)?
            .statement_id()
            .to_owned(),
        None => "-".into(),
    };
    let review = json!({"stage":"owner","network_id":network,"context_id":descriptor.context_id(),"person_id":crate::persons::person_id_of(person).map_err(|_|Error::new("invalid"))?,"person_public_key":person,"host_public_key":pending.record.host_public_key,"device_public_key":pending.record.device_public_key,"root_state_id":root,"provider":public,"owner_offer_id":"-","selection_id":"-","administrator_offer_id":"-","person_lease_id":person_lease,"host_lease_id":folded_id,"binding_lease_id":"-","device_lease_id":"-","scopes":scopes,"not_after":not_after,"authority_warning":"Profile scopes are finite. Administration bit8 also requires an active administrator role; this review does not grant access or commit the machine."});
    let mut t = OwnerTerms {
        descriptor,
        review,
        provider: private,
        seed,
        catalog,
        time,
        member,
        person_lease,
        issuer_ids,
        folded_host,
    };
    t.review["owner_offer_id"] = Value::from(Packet::read_template(&offer(pending, &t)?)?.id);
    Ok(t)
}
fn offer(pending: &Pending, t: &OwnerTerms) -> Result<Vec<u8>> {
    let request = pending.packet()?;
    let review = object(&t.review)?;
    let payload = json!({"request_packet_id":request.id,"descriptor":t.descriptor,"root_state_id":text(review,"root_state_id")?,"person_lease_id":t.person_lease,"issuer_lease_ids":t.issuer_ids,"mode":pending.record.mode,"member":t.member,"host_public_key":pending.record.host_public_key,"device_public_key":pending.record.device_public_key,"scopes":num(review,"scopes")?,"not_after":text(review,"not_after")?,"renewed_device_lease_id":text(&request.payload,"renewed_device_lease_id")?});
    bytes(
        &json!({"format":1,"context_id":t.descriptor.context_id(),"request_id":pending.id,"role":"owner","writer_host_public_key":field(&t.review["provider"],"host_public_key")?,"signer_public_key":t.provider.signer_public_key,"person_public_key":text(review,"person_public_key")?,"issuer_id":t.provider.lease_id,"payload_base64":encode(&bytes(&payload)?),"host_signature":"-","device_signature":"-","authority_signature_format":t.provider.signature_format,"authority_signature":"-"}),
    )
}
pub(super) fn descriptor(p: &Pending) -> Result<Descriptor> {
    Descriptor::read(&b64(&p.record.descriptor_base64, MAX_OBJECT)?)
}
pub(super) fn owner_intent(c: &Connection, p: &Pending) -> Result<Intent> {
    require(p.record.owner_intent_id != "-", "state_conflict")?;
    let i = Intent::load(c, &p.record.owner_intent_id)?;
    let d = descriptor(p)?;
    let r = &i.record;
    let review = read_review(&i)?;
    fields(
        object(&review)?,
        "stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning",
    )?;
    check(
        i.kind == "owner"
            && i.secret.is_none()
            && r.operation_id == p.id
            && i.network_id == d.network_id
            && i.context_id == d.context_id()
            && r.host_public_key == p.record.host_public_key
            && r.device_public_key == p.record.device_public_key
            && r.person_public_key == field(&review, "person_public_key")?
            && matches!(r.provider.kind.as_str(), "original" | "device")
            && r.expires_at == p.deadline,
    )?;
    let kinds = r
        .templates
        .iter()
        .map(|t| t.object_type.as_str())
        .collect::<Vec<_>>();
    check(
        kinds
            == [
                "owner_offer_packet",
                "device_lease",
                "owner_finalization_packet",
            ]
            || kinds
                == [
                    "owner_offer_packet",
                    "host_lease",
                    "binding_lease",
                    "device_lease",
                    "owner_finalization_packet",
                ]
            || kinds
                == [
                    "owner_offer_packet",
                    "binding_lease",
                    "device_lease",
                    "owner_finalization_packet",
                ],
    )?;
    check(
        matches!(field(&review, "stage")?, "owner" | "owner_finalization")
            && field(&review, "network_id")? == i.network_id
            && field(&review, "context_id")? == i.context_id
            && field(&review, "person_id")?
                == crate::persons::person_id_of(&r.person_public_key)
                    .map_err(|_| Error::new("invalid"))?
            && field(&review, "host_public_key")? == r.host_public_key
            && field(&review, "device_public_key")? == r.device_public_key
            && field(&review, "root_state_id")? == r.root_state_id
            && num(object(&review)?, "scopes")? == r.scopes
            && field(&review, "not_after")? == r.not_after,
    )?;
    let objects = i.objects(&d)?;
    let offer = objects[0]
        .as_ref()
        .ok_or_else(|| Error::new("state_conflict"))?;
    let packet = Packet::read_template(offer.bytes())?;
    check(
        text(&packet.object, "request_id")? == p.id
            && text(&packet.object, "context_id")? == i.context_id
            && text(&packet.object, "person_public_key")? == r.person_public_key
            && text(&packet.object, "signer_public_key")? == r.provider.signer_public_key
            && text(&packet.object, "issuer_id")? == r.provider.lease_id
            && text(&packet.object, "authority_signature_format")? == r.provider.signature_format
            && text(&packet.payload, "request_packet_id")? == p.packet()?.id
            && text(&packet.payload, "host_public_key")? == r.host_public_key
            && text(&packet.payload, "device_public_key")? == r.device_public_key
            && num(&packet.payload, "scopes")? == r.scopes
            && text(&packet.payload, "not_after")? == r.not_after,
    )?;
    let actual: Vec<u8> = c
        .query_row(
            "SELECT private_key FROM identity WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(db)?;
    let own = SigningKey::from_keypair_bytes(
        actual
            .as_slice()
            .try_into()
            .map_err(|_| Error::new("state_conflict"))?,
    )
    .map_err(|_| Error::new("state_conflict"))?;
    check(
        text(&packet.object, "writer_host_public_key")? == encode(own.verifying_key().as_bytes()),
    )?;
    let complete = objects
        .iter()
        .enumerate()
        .map(|(index, o)| -> Result<bool> {
            let Some(o) = o else { return Ok(false) };
            Ok(o.pending()?.iter().all(|slot| {
                index > 0 && slot.object_type == "binding_lease" && slot.role == "host"
            }))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .all(|done| done);
    check(r.completed == complete)?;
    if p.record.owner_packet_base64 != "-" {
        check(
            offer.pending()?.is_empty()
                && p.record.owner_offer_id == packet.id
                && b64(&p.record.owner_packet_base64, MAX_OBJECT)? == offer.bytes(),
        )?;
    }
    super::ceremony_finalization::validate_templates(p, &i, &d, &packet)?;
    Ok(i)
}
pub(crate) fn validate_references(c: &Connection, p: &Pending) -> Result<()> {
    if p.record.owner_intent_id != "-" {
        owner_intent(c, p).map_err(|_| Error::new("state_conflict"))?;
    }
    Ok(())
}
fn initial_templates(
    c: &Connection,
    store: &Store,
    p: &Pending,
    t: &OwnerTerms,
    offer: &[u8],
) -> Result<Vec<intents::Template>> {
    let mut kinds = vec![("owner_offer_packet", encode(offer))];
    if let Some(host) = &t.folded_host {
        kinds.push(("host_lease", encode(host)));
    }
    let reuse = if p.record.mode == "renew" && t.catalog.is_some() {
        let snapshot = Snapshot::load(c, &t.descriptor.network_id, &store.identity().public_key)?;
        let projection = snapshot.project(&t.time)?;
        projection
            .member_for(
                &p.record.host_public_key,
                field(&t.review, "person_public_key")?,
            )
            .is_ok_and(|m| {
                m.person_lease_id == t.person_lease
                    && m.binding_lease_id != "-"
                    && projection.catalog.get(&m.binding_lease_id).is_ok_and(|b| {
                        b.payload
                            .get("not_after")
                            .and_then(Value::as_str)
                            .is_some_and(|end| end >= field(&t.review, "not_after").unwrap_or("~"))
                    })
            })
    } else {
        false
    };
    if !reuse {
        kinds.push(("binding_lease", "-".into()));
    }
    kinds.push(("device_lease", "-".into()));
    kinds.push(("owner_finalization_packet", "-".into()));
    Ok(kinds
        .into_iter()
        .enumerate()
        .map(|(index, (kind, raw))| intents::Template {
            slot_id: index as u64 + 1,
            object_type: kind.into(),
            template_base64: raw,
        })
        .collect())
}
pub(super) fn signing_requests(i: &Intent, d: &Descriptor) -> Result<Vec<Value>> {
    if !i.record.approved || i.record.terminal != "-" {
        return Ok(Vec::new());
    }
    let objects = i.objects(d)?;
    let mut ready = Vec::new();
    for (index, value) in objects.iter().enumerate() {
        let Some(value) = value else { continue };
        for slot in value.pending()? {
            if i.kind == "owner" && slot.object_type == "binding_lease" && slot.role == "host" {
                continue;
            }
            ready.push(json!({"intent_id":i.id,"slot_id":index as u64+1,"object_type":slot.object_type,"object_id":slot.statement_id,"role":slot.role,"public_key":slot.public_key,"format":slot.signature_format,"template_base64":encode(value.bytes()),"message_base64":slot.message_base64}));
        }
    }
    Ok(ready)
}
fn response(p: &Pending, i: &Intent, now: &str) -> Result<Vec<u8>> {
    bytes(
        &json!({"request":p.view(now)?,"review":read_review(i)?,"signing_requests":signing_requests(i,&descriptor(p)?)?}),
    )
}
pub(super) fn endpoints_with_self(store: &Store, p: &Pending) -> Result<Vec<Value>> {
    let addresses = store
        .bootstrap_settings
        .read()
        .map_err(|_| Error::new("internal"))?
        .bootstrap
        .clone();
    let mut endpoints = p.record.carrier_endpoints.clone();
    for address in addresses {
        endpoints.push(json!({"kind":"participant","address":address,"public_key":store.identity().public_key}));
    }
    endpoints.sort_by_key(|e| {
        (
            e["kind"].as_str().unwrap_or_default().to_owned(),
            e["address"].as_str().unwrap_or_default().to_owned(),
            e["public_key"].as_str().unwrap_or_default().to_owned(),
        )
    });
    endpoints.dedup();
    require(endpoints.len() <= 8, "quota_exceeded")?;
    Ok(endpoints)
}
pub(super) fn retain_packet(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    role: &str,
    raw: &[u8],
    now: &str,
) -> Result<()> {
    let endpoints = endpoints_with_self(store, p)?;
    let d = descriptor(p)?;
    let contact = super::bootstrap_io::own_contact(c, store, now, &d.network_id, &d.context_id())?;
    super::requester::retain_with_contacts(
        c,
        store,
        p,
        role,
        raw,
        "-",
        now,
        vec![parse(&contact.body, 8 << 10)?],
    )?;
    p.record.carrier_endpoints = endpoints;
    Ok(())
}
pub(super) fn frame_budget(
    c: &Connection,
    store: &Store,
    p: &Pending,
    catalog: Option<&super::catalog::Catalog>,
    packet_bytes: usize,
    now: &str,
) -> Result<()> {
    endpoints_with_self(store, p)?;
    let frames = requests::frames(c, p)?;
    let components = if let Some(catalog) = catalog {
        super::requester::catalog_delta_components(
            c,
            p,
            catalog,
            &store.identity().public_key,
            now,
        )?
    } else {
        Vec::new()
    };
    let estimate = components
        .iter()
        .map(|raw| raw.len().div_ceil(3) * 4 + (16 << 10))
        .sum::<usize>()
        + packet_bytes.div_ceil(3) * 4
        + (64 << 10);
    require(
        frames.len() + components.len() < 64
            && frames.iter().map(|f| f.ciphertext.len()).sum::<usize>() + estimate <= 32 << 20,
        "quota_exceeded",
    )
}
fn revalidate(c: &Connection, store: &Store, p: &Pending, i: &Intent) -> Result<OwnerTerms> {
    let r = &i.record;
    let provider = if r.provider.kind == "device" {
        &r.provider.lease_id
    } else {
        &r.provider.signer_public_key
    };
    let terms = terms(
        c,
        store,
        p,
        &i.network_id,
        &r.person_public_key,
        provider,
        &r.provider.signature_format,
        r.scopes,
        &r.not_after,
    )?;
    let saved = read_review(i)?;
    require(
        saved["provider"] == terms.review["provider"]
            && terms.provider.kind == r.provider.kind
            && terms.provider.signer_public_key == r.provider.signer_public_key
            && terms.provider.lease_id == r.provider.lease_id,
        "operation_conflict",
    )?;
    let catalog = if p.record.catalog_base64 == "-" {
        None
    } else {
        Some(super::catalog::Catalog::read(
            &terms.descriptor,
            &b64(&p.record.catalog_base64, MAX_CATALOG)?,
        )?)
    };
    frame_budget(
        c,
        store,
        p,
        catalog.as_ref(),
        b64(&i.record.templates[0].template_base64, MAX_OBJECT)?.len(),
        &terms.time,
    )?;
    let objects = i.objects(&terms.descriptor)?;
    let first = objects
        .first()
        .and_then(Option::as_ref)
        .ok_or_else(|| Error::new("state_conflict"))?;
    let actual = Packet::read_template(first.bytes())?;
    let expected = Packet::read_template(&offer(p, &terms)?)?;
    check(
        actual.id == expected.id
            && field(&saved, "root_state_id")? == text(&actual.payload, "root_state_id")?
            && field(&saved, "person_lease_id")? == text(&actual.payload, "person_lease_id")?
            && field(&saved, "owner_offer_id")? == actual.id,
    )?;
    Ok(terms)
}
pub(crate) fn owner(store: &Store, input: &Obj) -> Result<Vec<u8>> {
    fields(
        input,
        "code network_id person_public_key provider_id signature_format scopes not_after expected_host_public_key expected_device_public_key approve",
    )?;
    let now = controls::local_decision_time()?;
    let code = PairingToken::read(text(input, "code")?, &now)?;
    let packet = Packet::read(&code.request_packet)?;
    check(
        text(input, "expected_host_public_key")? == text(&packet.payload, "host_public_key")?
            && text(input, "expected_device_public_key")?
                == text(&packet.payload, "device_public_key")?,
    )?;
    let network = text(input, "network_id")?;
    check(ident(network, "net_"))?;
    let person = text(input, "person_public_key")?;
    check(key(person))?;
    for (field, actual) in [
        ("expected_network_id", network),
        ("expected_person_public_key", person),
    ] {
        let expected = text(&packet.payload, field)?;
        check(expected == "-" || expected == actual)?;
    }
    let approved = input["approve"]
        .as_bool()
        .ok_or_else(|| Error::new("invalid"))?;
    let (request_id, new, approval) = {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let existing = match requests::load(&tx, &code.request_id) {
            Ok(p) => Some(p),
            Err(e) if e.code == "not_found" => None,
            Err(e) => return Err(e),
        };
        let mut pending = if let Some(p) = existing {
            require(
                p.record.request_packet_base64 == encode(&code.request_packet)
                    && p.secret == Some(code.secret),
                "operation_conflict",
            )?;
            p
        } else {
            let snapshot = Snapshot::load(&tx, network, &store.identity().public_key)?;
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_pending", [], |r| r.get(0))
                .map_err(db)?;
            require(count < 4096, "quota_exceeded")?;
            let mut q = tx
                .prepare("SELECT request_id FROM dec_pending")
                .map_err(db)?;
            let ids = q
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(db)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(db)?;
            drop(q);
            let active = ids
                .iter()
                .map(|id| requests::load(&tx, id))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|p| matches!(p.record.terminal.as_str(), "-" | "migration_prepared"))
                .count();
            require(active < 8, "quota_exceeded")?;
            from_code(&code, &snapshot.descriptor)?
        };
        let t = terms(
            &tx,
            store,
            &pending,
            network,
            person,
            text(input, "provider_id")?,
            text(input, "signature_format")?,
            num(input, "scopes")?,
            text(input, "not_after")?,
        )?;
        let mut new = false;
        let mut i = if pending.record.owner_intent_id != "-" {
            let i = owner_intent(&tx, &pending)?;
            // Later dependency materialization changes the public stage/review,
            // while the original offer and reviewed terms remain immutable.
            let first = i
                .objects(&t.descriptor)?
                .remove(0)
                .ok_or_else(|| Error::new("state_conflict"))?;
            require(
                Packet::read_template(first.bytes())?.id
                    == Packet::read_template(&offer(&pending, &t)?)?.id
                    && i.record.provider.kind == t.provider.kind
                    && i.record.provider.signer_public_key == t.provider.signer_public_key
                    && i.record.provider.lease_id == t.provider.lease_id,
                "operation_conflict",
            )?;
            i
        } else {
            new = true;
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM dec_intents", [], |r| r.get(0))
                .map_err(db)?;
            let active:i64=tx.query_row("SELECT COUNT(*) FROM dec_intents WHERE json_extract(record,'$.terminal')='-' AND json_extract(record,'$.completed')=0",[],|r|r.get(0)).map_err(db)?;
            require(count < 4096 && active < 64, "quota_exceeded")?;
            let now = t.time.clone();
            let template = offer(&pending, &t)?;
            FixedObject::read(&t.descriptor, "owner_offer_packet", &template)?;
            Intent {
                id: id()?,
                network_id: network.into(),
                context_id: t.descriptor.context_id(),
                kind: "owner".into(),
                secret: None,
                record: intents::Record {
                    format: 1,
                    operation_id: pending.id.clone(),
                    approved: false,
                    approved_at: "-".into(),
                    review_base64: encode(&bytes(&t.review)?),
                    provider: t.provider.clone(),
                    root_state_id: field(&t.review, "root_state_id")?.into(),
                    person_public_key: person.into(),
                    host_public_key: pending.record.host_public_key.clone(),
                    device_public_key: pending.record.device_public_key.clone(),
                    scopes: num(input, "scopes")?,
                    not_after: text(input, "not_after")?.into(),
                    created_at: now,
                    expires_at: pending.deadline.clone(),
                    templates: initial_templates(&tx, store, &pending, &t, &template)?,
                    signatures: Vec::new(),
                    completed: false,
                    terminal: "-".into(),
                    result_base64: "-".into(),
                },
            }
        };
        let approval = approved && !i.record.approved;
        if approval {
            i.record.approved = true;
            i.record.approved_at = t.time.clone();
        }
        if !pending.record.roles.iter().any(|r| r == "owner") {
            pending.record.roles.push("owner".into());
            pending.record.roles.sort_by_key(|r| match r.as_str() {
                "requester" => 0,
                "owner" => 1,
                _ => 2,
            });
        }
        pending.record.descriptor_base64 = encode(&bytes(&t.descriptor)?);
        pending.record.owner_intent_id = i.id.clone();
        if let Some(catalog) = t.catalog {
            pending.record.catalog_base64 = encode(&catalog);
        }
        i.save(&tx)?;
        requests::save(&tx, &pending)?;
        controls::remember_decision(&tx, network, &t.time)?;
        tx.commit().map_err(db)?;
        (pending.id, new, approval)
    };
    if new {
        controls::barrier(store, "dec.intent.after_commit", &request_id)?;
    }
    if approval {
        controls::barrier(store, "dec.approval.after_commit", &request_id)?;
    }
    if approved {
        resume(store, &request_id)?;
    }
    get(store, &request_id)
}
pub(crate) fn get(store: &Store, request: &str) -> Result<Vec<u8>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let p = requests::load(&tx, request)?;
    if p.record.administrator_intent_id != "-"
        && (p.record.owner_intent_id == "-" || p.record.administrator_packet_base64 == "-")
    {
        drop(tx);
        drop(c);
        return super::ceremony_admin::get(store, request);
    }

    let i = owner_intent(&tx, &p)?;
    if field(&read_review(&i)?, "stage")? == "owner_finalization" {
        drop(tx);
        drop(c);
        return super::ceremony_finalization::get(store, request);
    }
    let result = response(&p, &i, &controls::local_decision_time()?)?;
    tx.commit().map_err(db)?;
    Ok(result)
}
pub(super) fn add(i: &mut Intent, slot: u64, role: &str, signature: &str) -> Result<()> {
    if let Some(old) = i
        .record
        .signatures
        .iter()
        .find(|s| s.slot_id == slot && s.role == role)
    {
        return require(old.signature == signature, "operation_conflict");
    }
    i.record.signatures.push(intents::Filled {
        slot_id: slot,
        role: role.into(),
        signature: signature.into(),
    });
    i.record
        .signatures
        .sort_by(|a, b| (a.slot_id, &a.role).cmp(&(b.slot_id, &b.role)));
    Ok(())
}
pub(crate) fn signed(store: &Store, request: &str, input: &Obj) -> Result<Vec<u8>> {
    fields(input, "intent_id signatures")?;
    {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let p = requests::load(&c, request)?;
        let is_admin = p.record.administrator_intent_id != "-"
            && text(input, "intent_id")? == p.record.administrator_intent_id;
        drop(c);
        if is_admin {
            return super::ceremony_admin::signed(store, request, input);
        }
        if p.record.owner_intent_id != "-" {
            let c = store.connection().map_err(|_| Error::new("internal"))?;
            let i = owner_intent(&c, &p)?;
            let finalization = field(&read_review(&i)?, "stage")? == "owner_finalization";
            drop(c);
            if finalization {
                return super::ceremony_finalization::signed(store, request, input);
            }
        }
    }
    let entries = array(input, "signatures")?;
    check(!entries.is_empty() && entries.len() <= 16)?;
    {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let p = requests::load(&tx, request)?;
        let mut i = owner_intent(&tx, &p)?;
        check(text(input, "intent_id")? == i.id)?;
        require(i.record.approved, "state_conflict")?;
        let t = revalidate(&tx, store, &p, &i)?;
        let mut previous = None;
        for entry in entries {
            let o = object(entry)?;
            fields(o, "slot_id role signature")?;
            let slot = num(o, "slot_id")?;
            let role = text(o, "role")?;
            let folded =
                slot == 2 && role == "issuer" && i.record.templates[1].object_type == "host_lease";
            check((role == "authority" || folded) && i.record.provider.kind == "original")?;
            check(
                (slot == 1 || folded)
                    && previous
                        .as_ref()
                        .is_none_or(|old: &(u64, String)| old < &(slot, role.into())),
            )?;
            previous = Some((slot, role.into()));
            if let Some(saved) = i
                .record
                .signatures
                .iter()
                .find(|s| s.slot_id == slot && s.role == role)
            {
                require(
                    saved.signature == text(o, "signature")?,
                    "operation_conflict",
                )?;
                continue;
            }
            let object = i
                .objects(&t.descriptor)?
                .remove(slot as usize - 1)
                .ok_or_else(|| Error::new("invalid"))?;
            object.fill(&t.descriptor, role, text(o, "signature")?)?;
            add(&mut i, slot, role, text(o, "signature")?)?;
        }
        let object = i
            .objects(&t.descriptor)?
            .remove(0)
            .ok_or_else(|| Error::new("state_conflict"))?;
        let mut p = p;
        if object.pending()?.is_empty() {
            let packet = Packet::read(object.bytes())?;
            require(
                p.record.owner_packet_base64 == "-"
                    || p.record.owner_packet_base64 == encode(object.bytes()),
                "operation_conflict",
            )?;
            p.record.owner_packet_base64 = encode(object.bytes());
            p.record.owner_offer_id = packet.id;
        }
        i.save(&tx)?;
        requests::save(&tx, &p)?;
        controls::remember_decision(&tx, &i.network_id, &t.time)?;
        tx.commit().map_err(db)?;
    }
    controls::barrier(store, "dec.signature.after_commit", request)?;
    resume(store, request)?;
    get(store, request)
}
pub(crate) fn resume(store: &Store, request: &str) -> Result<()> {
    resume_offer(store, request)?;
    super::ceremony_finalization::resume(store, request)
}
/// The combined resume runs F after any administrator progress. Direct owner
/// entry points retain the wrapper above so their F progression is unchanged.
pub(super) fn resume_offer(store: &Store, request: &str) -> Result<()> {
    loop {
        let prepared = {
            let c = store.connection().map_err(|_| Error::new("internal"))?;
            let p = requests::load(&c, request)?;
            if p.record.owner_intent_id == "-" || p.record.terminal != "-" {
                return Ok(());
            }
            let i = owner_intent(&c, &p)?;
            if field(&read_review(&i)?, "stage")? == "owner_finalization"
                || p.record
                    .outbound_frames
                    .iter()
                    .any(|f| f["role"] == "owner")
            {
                return Ok(());
            }
            if !i.record.approved {
                return Ok(());
            }
            let t = revalidate(&c, store, &p, &i)?;
            let objects = i.objects(&t.descriptor)?;
            let first = objects[0]
                .as_ref()
                .ok_or_else(|| Error::new("state_conflict"))?;
            let mut slots: Vec<_> = first.pending()?.into_iter().map(|s| (1, s)).collect();
            // A folded host grant is signed under the same approval.
            if i.record.templates[1].object_type == "host_lease" {
                let host = objects[1]
                    .as_ref()
                    .ok_or_else(|| Error::new("state_conflict"))?;
                slots.extend(host.pending()?.into_iter().map(|s| (2, s)));
            }
            (t, slots)
        };
        let (t, slots) = prepared;
        let mut generated = Vec::new();
        for (index, slot) in slots {
            let issuer = index == 2 && slot.role == "issuer";
            let message = b64(&slot.message_base64, 4096)?;
            if slot.role == "host"
                && slot.public_key == store.identity().public_key
                && slot.signature_format == "ed25519"
            {
                generated.push((
                    index,
                    slot.role,
                    encode(&store.signing_key.sign(&message).to_bytes()),
                ));
            } else if (slot.role == "authority" || issuer)
                && slot.public_key == t.provider.signer_public_key
            {
                if slot.signature_format == "ed25519" {
                    let seed = t.seed.ok_or_else(|| Error::new("signer_unavailable"))?;
                    generated.push((
                        index,
                        slot.role,
                        encode(&SigningKey::from_bytes(&seed).sign(&message).to_bytes()),
                    ));
                } else if slot.signature_format == "sshsig" {
                    let key = b64(&t.provider.signer_public_key, 32)?
                        .try_into()
                        .map_err(|_| Error::new("invalid"))?;
                    if let Ok(signer) = store.renewal_signer(key) {
                        let message =
                            std::str::from_utf8(&message).map_err(|_| Error::new("invalid"))?;
                        generated.push((
                            index,
                            slot.role,
                            signer
                                .sign(&message.split('\n').collect::<Vec<_>>())
                                .map_err(|_| Error::new("signer_unavailable"))?,
                        ));
                    }
                }
            } else {
                return Err(Error::new("state_conflict"));
            }
        }
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let mut p = requests::load(&tx, request)?;
        let mut i = owner_intent(&tx, &p)?;
        let t = revalidate(&tx, store, &p, &i)?;
        let barrier = if !generated.is_empty() {
            for (slot, role, signature) in generated {
                let object = i
                    .objects(&t.descriptor)?
                    .remove(slot as usize - 1)
                    .ok_or_else(|| Error::new("state_conflict"))?;
                object.fill(&t.descriptor, &role, &signature)?;
                add(&mut i, slot, &role, &signature)?;
            }
            let first = i
                .objects(&t.descriptor)?
                .remove(0)
                .ok_or_else(|| Error::new("state_conflict"))?;
            if first.pending()?.is_empty() {
                let packet = Packet::read(first.bytes())?;
                require(
                    p.record.owner_packet_base64 == "-"
                        || p.record.owner_packet_base64 == encode(first.bytes()),
                    "operation_conflict",
                )?;
                p.record.owner_packet_base64 = encode(first.bytes());
                p.record.owner_offer_id = packet.id;
            }
            i.save(&tx)?;
            requests::save(&tx, &p)?;
            "dec.signature.after_commit"
        } else {
            let first = i
                .objects(&t.descriptor)?
                .remove(0)
                .ok_or_else(|| Error::new("state_conflict"))?;
            if !first.pending()?.is_empty()
                || p.record
                    .outbound_frames
                    .iter()
                    .any(|f| f["role"] == "owner")
            {
                return Ok(());
            }
            require(
                p.record.owner_packet_base64 == encode(first.bytes()),
                "state_conflict",
            )?;
            // The complete signed packet was committed in the earlier phase.
            // Its ciphertext is a separate durable commit before publication.
            let raw = first.bytes().to_vec();
            if p.record.catalog_base64 != "-" {
                let catalog = super::catalog::Catalog::read(
                    &t.descriptor,
                    &b64(&p.record.catalog_base64, MAX_CATALOG)?,
                )?;
                super::requester::retain_catalog(&tx, store, &mut p, &catalog, &t.time)?;
            }
            retain_packet(&tx, store, &mut p, "owner", &raw, &t.time)?;
            requests::save(&tx, &p)?;
            "dec.frame.after_commit"
        };
        controls::remember_decision(&tx, &i.network_id, &t.time)?;
        tx.commit().map_err(db)?;
        drop(c);
        controls::barrier(store, barrier, request)?;
        if barrier == "dec.signature.after_commit" {
            let c = store.connection().map_err(|_| Error::new("internal"))?;
            let p = requests::load(&c, request)?;
            let done = p.record.owner_packet_base64 != "-";
            drop(c);
            if done {
                controls::barrier(store, "dec.owner.after_commit", request)?;
            }
        }
    }
}
