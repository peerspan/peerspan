//! Exact guided consent over the existing requester intent, never signing.
use super::*;

fn find(c: &Connection, p: &Pending) -> Result<Option<Intent>> {
    let mut q = c.prepare("SELECT intent_id FROM dec_intents WHERE kind='requester_commit' AND json_extract(record,'$.operation_id')=?1 ORDER BY intent_id").map_err(db)?;
    let ids = q
        .query_map([&p.id], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    check(ids.len() <= 1)?;
    let found = ids.first().map(|id| Intent::load(c, id)).transpose()?;
    if p.record.commit_intent_id != "-" {
        check(
            found
                .as_ref()
                .is_some_and(|i| i.id == p.record.commit_intent_id),
        )?;
    }
    Ok(found)
}

fn public(p: &Pending, i: &Intent) -> Result<Value> {
    let d = Descriptor::read(&b64(&p.record.descriptor_base64, MAX_OBJECT)?)?;
    let owner = Packet::read(&b64(&p.record.owner_packet_base64, MAX_OBJECT)?)?;
    check_reference(p, i, &d, &owner)?;
    let r = &i.record;
    check(
        p.record.roles.iter().any(|s| s == "requester")
            && p.record.mode == "new"
            && p.record.migration_proposal_id == "-"
            && p.record.selection_approved
            && r.provider.signature_format == "ed25519"
            && r.provider.lease_id == "-"
            && r.scopes == 7
            && num(&owner.payload, "scopes")? == 7
            && text(&owner.payload, "root_state_id")? == "-"
            && text(&owner.payload, "person_lease_id")? == "-"
            && array(&owner.payload, "issuer_lease_ids")?.is_empty()
            && text(&owner.payload, "renewed_device_lease_id")? == "-"
            && text(&owner.object, "signer_public_key")? == r.person_public_key
            && text(&owner.object, "writer_host_public_key")? == r.host_public_key
            && text(&owner.object, "authority_signature_format")? == "sshsig"
            && stamp(&r.not_after)?
                == stamp(text(&p.packet()?.payload, "created_at")?)? + chrono::TimeDelta::days(7)
            && r.approved == p.record.commit_approved
            && (if r.approved {
                p.record.commit_intent_id == i.id
            } else {
                p.record.commit_intent_id == "-"
            }),
    )?;
    let review = parse(&b64(&r.review_base64, MAX_OBJECT)?, MAX_OBJECT)?;
    let f = Packet::read(&b64(
        &p.record.owner_finalization_packet_base64,
        MAX_OBJECT,
    )?)?;
    check(f.payload["binding_lease"].is_object())?;
    let binding = Statement::read_draft(&d, &raw_field(&f.payload_bytes, "binding_lease")?, true)?;
    let device = Statement::read(&d, &raw_field(&f.payload_bytes, "device_lease")?)?;
    for (s, kind, scopes, device_key) in [
        (&binding, "binding_lease", 2, "-"),
        (&device, "device_lease", 7, r.device_public_key.as_str()),
    ] {
        check(
            s.kind == kind
                && text(&s.payload, "operation_id")? == p.id
                && text(&s.payload, "root_state_id")? == r.root_state_id
                && text(&s.payload, "not_after")? == r.not_after
                && text(s.subject()?, "person_public_key")? == r.person_public_key
                && text(s.subject()?, "host_public_key")? == r.host_public_key
                && text(s.subject()?, "device_public_key")? == device_key
                && text(s.subject()?, "member")? == "-"
                && num(s.subject()?, "scopes")? == scopes,
        )?;
    }
    let ids = [
        r.root_state_id.as_str(),
        text(object(&review)?, "person_lease_id")?,
        text(object(&review)?, "host_lease_id")?,
        binding.id.as_str(),
        device.id.as_str(),
    ];
    check(
        ids.iter().all(|s| ident(s, "ds_"))
            && ids.iter().collect::<std::collections::BTreeSet<_>>().len() == ids.len(),
    )?;
    Ok(
        json!({"intent_id":i.id,"approved":r.approved,"terminal":r.terminal,
        "created_at":r.created_at,"expires_at":r.expires_at,"network":{"id":d.network_id,"name":d.name,
        "context_id":d.context_id(),"genesis_root_public_key":d.genesis_root_public_key},
        "member":owner.payload["member"],"person_public_key":r.person_public_key,"host_public_key":r.host_public_key,
        "device_public_key":r.device_public_key,"owner_offer_id":p.record.owner_offer_id,"selection_id":p.record.selection_id,
        "administrator_offer_id":p.record.administrator_offer_id,"owner_finalization_id":p.record.owner_finalization_id,
        "root_state_id":r.root_state_id,"person_lease_id":review["person_lease_id"],"host_lease_id":review["host_lease_id"],
        "binding_lease_id":binding.id,"device_lease_id":device.id,"scopes":7,"not_after":r.not_after}),
    )
}

pub(crate) fn proposal(c: &Connection, p: &Pending) -> Result<Option<Value>> {
    find(c, p)?.as_ref().map(|i| public(p, i)).transpose()
}

fn check_time(
    c: &Connection,
    p: &Pending,
    i: Option<&Intent>,
    effective: Option<&str>,
) -> Result<()> {
    let raw = controls::local_decision_time()?;
    let local = stamp(&raw)?;
    let after_intent = match i {
        Some(i) => local >= stamp(&i.record.created_at)?,
        None => true,
    };
    require(
        local >= stamp(text(&p.packet()?.payload, "created_at")?)?
            && (p.record.stage_at == "-" || local >= stamp(&p.record.stage_at)?)
            && after_intent,
        "commit_review_unavailable",
    )?;
    let guarded = controls::guarded_decision(c, &p.record.expected_network_id, &raw)?;
    let now = local
        .max(stamp(&guarded)?)
        .max(stamp(effective.unwrap_or(&guarded))?);
    require(
        now < stamp(&p.deadline)?
            && !p.stage_expired(&now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))?,
        "review_expired",
    )?;
    if let Some(i) = i {
        require(
            now < stamp(&i.record.not_after)?
                && now < stamp(&i.record.expires_at)?
                && now < stamp(&i.record.created_at)? + chrono::TimeDelta::minutes(15),
            "review_expired",
        )?;
    }
    Ok(())
}

fn fresh(c: &Connection, store: &Store, p: &Pending) -> Result<Context> {
    check_time(c, p, None, None)?;
    check(
        p.record.terminal == "-"
            && p.record.mode == "new"
            && p.record.migration_proposal_id == "-"
            && p.record.commit_packet_base64 == "-"
            && p.record.manifest_id == "-"
            && p.record.activation_id == "-",
    )?;
    let stage = context(c, store, p)?;
    require(
        p.view(&stage.now)?["state"] == "needs_commit",
        "state_conflict",
    )?;
    Ok(stage)
}

pub(crate) fn live(c: &Connection, store: &Store, p: &Pending) -> Result<String> {
    let stage = fresh(c, store, p)?;
    let i = find(c, p)?.ok_or_else(|| Error::new("state_conflict"))?;
    check_current(p, &i, &stage)?;
    public(p, &i)?;
    check_time(c, p, Some(&i), Some(&stage.now))?;
    Ok(stage.now)
}

/// Caller owns the transaction and validates the exact parent/public digest.
pub(crate) fn apply(
    c: &Connection,
    store: &Store,
    p: &mut Pending,
    approve: bool,
    mut validate: impl FnMut(&Value, &str) -> Result<()>,
) -> Result<(bool, bool)> {
    let stage = fresh(c, store, p)?;
    let exists = find(c, p)?.is_some();
    let mut i = new_intent(c, p, &stage)?;
    check_current(p, &i, &stage)?;
    check_time(c, p, Some(&i), Some(&stage.now))?;
    validate(&public(p, &i)?, &stage.now)?;
    let changed = approve && !i.record.approved;
    if changed {
        observer::owned_device(store, c, p)?;
        budget(c, store, p, &stage)?;
        i.record.approved = true;
        i.record.approved_at = stage.now.clone();
        p.record.commit_approved = true;
        p.record.commit_intent_id = i.id.clone();
    }
    i.save(c)?;
    if changed {
        requests::save(c, p)?;
    }
    let now = live(c, store, p)?;
    validate(&public(p, &i)?, &now)?;
    Ok((!exists, changed))
}
