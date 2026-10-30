//! Guided consent reuses ordinary administrator templates and validation.
use super::*;

pub(crate) fn proposal(c: &Connection, p: &Pending) -> Result<Value> {
    let i = load(c, p)?;
    public(p, &i)
}
fn public(p: &Pending, i: &Intent) -> Result<Value> {
    let r = &i.record;
    let review = read_review(i)?;
    let d = descriptor(p)?;
    let request = p.packet()?;
    let owner = Packet::read(&b64(&p.record.owner_packet_base64, MAX_OBJECT)?)?;
    let selection = Packet::read(&b64(&p.record.selection_packet_base64, MAX_OBJECT)?)?;
    super::super::state::check_requester_selection(&request, &owner, &selection, &d)?;
    check(
        p.record.roles.iter().any(|r| r == "administrator")
            && !p.record.roles.iter().any(|r| r == "requester")
            && p.record.mode == "new"
            && p.record.migration_proposal_id == "-"
            && r.provider.kind == "root"
            && r.provider.signature_format == "ed25519"
            && r.scopes == 7
            && num(&owner.payload, "scopes")? == 7
            && text(&owner.payload, "root_state_id")? == "-"
            && text(&owner.payload, "person_lease_id")? == "-"
            && array(&owner.payload, "issuer_lease_ids")?.is_empty()
            && text(&owner.payload, "renewed_device_lease_id")? == "-"
            && text(&owner.object, "authority_signature_format")? == "sshsig"
            && text(&owner.object, "writer_host_public_key")? == p.record.host_public_key
            && text(&owner.object, "person_public_key")? == r.person_public_key
            && owner.id == field(&review, "owner_offer_id")?
            && owner.id == p.record.owner_offer_id
            && selection.id == field(&review, "selection_id")?
            && selection.id == p.record.selection_id
            && p.record.expected_network_id == i.network_id
            && p.record.expected_context_id == i.context_id
            && p.record.expected_person_public_key == r.person_public_key
            && r.not_after == text(&owner.payload, "not_after")?
            && stamp(&r.not_after)?
                == stamp(text(&request.payload, "created_at")?)? + chrono::TimeDelta::days(7),
    )?;
    let objects = i.objects(&d)?;
    check(
        i.record
            .templates
            .iter()
            .map(|t| t.object_type.as_str())
            .collect::<Vec<_>>()
            == ["person_lease", "host_lease", "administrator_packet"],
    )?;
    for (index, kind, id_field, person, host) in [
        (
            0,
            "person_lease",
            "person_lease_id",
            r.person_public_key.as_str(),
            "-",
        ),
        (
            1,
            "host_lease",
            "host_lease_id",
            "-",
            r.host_public_key.as_str(),
        ),
    ] {
        let Some(FixedObject::Statement(fixed)) = &objects[index] else {
            return Err(Error::new("state_conflict"));
        };
        let s = fixed.typed();
        check(
            s.kind == kind
                && s.id == field(&review, id_field)?
                && text(&s.payload, "operation_id")? == p.id
                && text(&s.payload, "root_state_id")? == r.root_state_id
                && text(&s.payload, "issued_at")? == r.created_at
                && text(&s.payload, "not_after")? == r.not_after
                && text(s.subject()?, "person_public_key")? == person
                && text(s.subject()?, "host_public_key")? == host
                && text(s.subject()?, "member")? == text(&owner.payload, "member")?,
        )?;
    }
    Ok(
        json!({"intent_id":i.id,"approved":r.approved,"terminal":r.terminal,
        "created_at":r.created_at,"expires_at":r.expires_at,
        "root_state_id":r.root_state_id,"root_public_key":r.provider.signer_public_key,
        "person_lease_id":review["person_lease_id"],"host_lease_id":review["host_lease_id"],
        "member":owner.payload["member"],"owner_offer_id":owner.id,"selection_id":selection.id,
        "network":{"id":d.network_id,"name":d.name,"context_id":d.context_id(),
            "genesis_root_public_key":d.genesis_root_public_key},
        "person_public_key":r.person_public_key,"host_public_key":r.host_public_key,
        "device_public_key":r.device_public_key,"scopes":7,"not_after":r.not_after}),
    )
}
pub(crate) fn live(c: &Connection, store: &Store, p: &Pending) -> Result<String> {
    check_live_time(c, p)?;
    inspect_original(c, store, p)?;
    let i = load(c, p)?;
    let (b, r) = check_current(c, store, p, &i)?;
    require(
        stamp(&b.now)? >= stamp(&i.record.created_at)?
            && r.provider.kind == "root"
            && r.provider.signature_format == "ed25519"
            && r.provider.signer_public_key == i.record.provider.signer_public_key,
        "state_conflict",
    )?;
    Ok(b.now)
}
/// Caller owns the transaction and validates its exact project/public digest.
pub(crate) fn apply(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    approve: bool,
    mut validate: impl FnMut(&Value, &str) -> Result<()>,
) -> Result<(bool, bool)> {
    check_live_time(c, p)?;
    inspect_original(c, store, p)?;
    let b = base(
        c,
        store,
        p,
        &p.record.owner_offer_id,
        &p.record.selection_id,
    )?;
    let fresh = p.record.administrator_intent_id == "-";
    let mut i = if fresh {
        new_intent(
            c,
            store,
            p,
            &b,
            object(&json!({"provider_id":"network_root","signature_format":"ed25519"}))?,
        )?
    } else {
        load(c, p)?
    };
    let (checked, _) = check_current(c, store, p, &i)?;
    let public = public(p, &i)?;
    validate(&public, &checked.now)?;
    let changed = approve && !i.record.approved;
    if changed {
        i.record.approved = true;
        i.record.approved_at = checked.now;
    }
    p.record.administrator_intent_id = i.id.clone();
    i.save(c)?;
    requests::save(c, p)?;
    let now = live(c, store, p)?;
    validate(&public, &now)?;
    Ok((fresh, changed))
}

fn check_live_time(c: &Connection, p: &Pending) -> Result<()> {
    let now = controls::guarded_decision(
        c,
        &p.record.expected_network_id,
        &controls::local_decision_time()?,
    )?;
    require(p.view(&now)?["state"] != "expired", "review_expired")
}
