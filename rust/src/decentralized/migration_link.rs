//! Private owned-host staging under one locally approved legacy transition.
//! This never constructs an adopted Snapshot, trusted prior or reusable signer.
use super::{
    catalog::Catalog, codec::*, migration_ack, migration_host::Context, requests,
    state::Projection, statement::Descriptor, transcript::Packet,
};
use super::{
    controls, migration_prefix::Prefix, migration_prepare, template::FixedStatement,
    transcript::Activation,
};
use crate::store::Store;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) struct Owned {
    pub context: Context,
    pub device: SigningKey,
    pub projection: Projection,
}
impl Owned {
    pub(super) fn load(
        store: &Store,
        c: &Connection,
        network: &str,
        proposal: &str,
    ) -> Result<Self> {
        let context = Context::load(store, c, network, proposal)?;
        require(text(&context.own, "person_public_key")? != "-", "forbidden")?;
        require(context.record.commit_base64 == "-", "operation_conflict")?;
        let root = context
            .prefix
            .root
            .as_ref()
            .ok_or_else(|| Error::missing(proposal))?;
        let catalog = context
            .prefix
            .catalog
            .as_ref()
            .ok_or_else(|| Error::missing(proposal))?;
        let person = text(&context.own, "person_public_key")?;
        let projection = super::state::Projection::stage_migration(
            &context.source.descriptor,
            &catalog.bytes,
            &context.source.time,
            proposal,
            &root.id,
            &context.prefix.source.maxima,
        )?;
        projection.current_statement(&["person".into(), person.into()])?;
        let device =
            migration_ack::device_seed(c, network, &store.identity().public_key, &context.own)?;
        Ok(Self {
            context,
            device,
            projection,
        })
    }
    pub(super) fn matches(&self, p: &requests::Pending) -> Result<()> {
        let d = &self.context.source.descriptor;
        require(
            p.record.mode == "new"
                && p.record.migration_proposal_id == self.context.prefix.proposal.id
                && p.record.expected_network_id == d.network_id
                && p.record.expected_context_id == d.context_id()
                && p.record.expected_person_public_key
                    == text(&self.context.own, "person_public_key")?
                && p.record.host_public_key == text(&self.context.own, "host_public_key")?
                && p.record.device_public_key == text(&self.context.own, "device_public_key")?,
            "operation_conflict",
        )
    }
}

pub(super) struct OwnerProfile<'a> {
    pub person: &'a str,
    pub provider: &'a str,
    pub format: &'a str,
    pub scopes: u64,
    pub not_after: &'a str,
}
pub(super) struct OwnerPlan {
    pub descriptor: Descriptor,
    pub provider: Value,
    pub catalog: Catalog,
    pub person_lease: String,
    pub member: String,
    pub root: String,
    pub time: String,
    pub staging: Projection,
}

fn target(context: &Context, p: &requests::Pending) -> Result<Obj> {
    let d = &context.source.descriptor;
    require(
        p.record.mode == "new"
            && p.record.migration_proposal_id == context.prefix.proposal.id
            && p.record.expected_network_id == d.network_id
            && p.record.expected_context_id == d.context_id(),
        "operation_conflict",
    )?;
    let row = array(&context.prefix.proposal.payload, "roster")?
        .iter()
        .find(|r| {
            r.get("host_public_key").and_then(Value::as_str) == Some(&p.record.host_public_key)
        })
        .ok_or_else(|| Error::new("forbidden"))?;
    let row = object(row)?;
    require(
        text(row, "person_public_key")? != "-"
            && text(row, "person_public_key")? == p.record.expected_person_public_key
            && text(row, "device_public_key")? == p.record.device_public_key,
        "forbidden",
    )?;
    let request = p.packet()?;
    require(
        context.source.time.as_str() >= text(&request.payload, "created_at")?,
        "not_yet_valid",
    )?;
    require(
        text(&request.payload, "created_at")?
            >= text(&context.prefix.proposal.payload, "issued_at")?
            && text(&request.payload, "created_at")?
                < text(&context.prefix.proposal.payload, "expires_at")?,
        "forbidden",
    )?;
    Ok(row.clone())
}

fn profile(context: &Context, p: &requests::Pending, scopes: u64) -> Result<()> {
    let row = target(context, p)?;
    require(scopes == num(&row, "scopes")?, "forbidden")?;
    if scopes & 8 == 0 {
        return Ok(());
    }
    // Conditional nominal8 carries only the selected preexisting exact device
    // profile. Neither a new device nor this original acquires an admin role.
    for id in &context.source.facts.facts.state.activated_certificates {
        let raw = context
            .source
            .facts
            .facts
            .state
            .certificates
            .get(id)
            .ok_or_else(|| Error::missing(id))?;
        let value = parse(raw, MAX_OBJECT)?;
        let certificate = object(&value)?;
        if text(certificate, "person_public_key")? == p.record.expected_person_public_key
            && text(certificate, "host_public_key")? == p.record.host_public_key
            && text(certificate, "device_public_key")? == p.record.device_public_key
            && scopes & !num(certificate, "scopes")? == 0
        {
            return Ok(());
        }
    }
    Err(Error::new("forbidden"))
}

fn plan(
    context: &Context,
    projection: &Projection,
    p: &requests::Pending,
    not_after: &str,
) -> Result<OwnerPlan> {
    let person_key = &p.record.expected_person_public_key;
    let (person, deadline) =
        projection.current_statement(&["person".into(), person_key.clone()])?;
    let root = context
        .prefix
        .root
        .as_ref()
        .ok_or_else(|| Error::missing(&context.prefix.proposal.id))?;
    let prepared = context
        .prefix
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&context.prefix.proposal.id))?;
    let shared: Vec<_> = prepared
        .statements
        .values()
        .filter(|s| {
            s.kind == "person_lease"
                && s.subject()
                    .is_ok_and(|o| text(o, "person_public_key").is_ok_and(|k| k == person_key))
        })
        .collect();
    require(
        shared.len() == 1
            && shared[0].id == person.id
            && projection.root_state_id()? == root.id
            && context
                .source
                .facts
                .facts
                .state
                .persons
                .get(person_key)
                .is_some_and(|p| p.admitted),
        "forbidden",
    )?;
    let member = context
        .source
        .facts
        .facts
        .person_labels
        .get(person_key)
        .ok_or_else(|| Error::new("state_conflict"))?;
    require(
        text(person.subject()?, "member")? == member && not_after <= deadline.as_str(),
        "forbidden",
    )?;
    let provider = json!({"kind":"original_person","person_public_key":person_key,
        "host_public_key":p.record.host_public_key,"device_public_key":"-",
        "lease_id":person.id,"root_state_id":root.id,"scopes":7,"not_after":deadline});
    Ok(OwnerPlan {
        descriptor: context.source.descriptor.clone(),
        provider,
        catalog: projection.catalog.clone(),
        person_lease: person.id.clone(),
        member: member.clone(),
        root: root.id.clone(),
        time: projection.decision_time.clone(),
        staging: projection.clone(),
    })
}

pub(super) fn observed_owner(
    store: &Store,
    c: &Connection,
    p: &requests::Pending,
    owner: &Packet,
    catalog: &Catalog,
) -> Result<OwnerPlan> {
    let context = Context::load(
        store,
        c,
        &p.record.expected_network_id,
        &p.record.migration_proposal_id,
    )?;
    let person = &p.record.expected_person_public_key;
    target(&context, p)?;
    check(
        text(&owner.object, "writer_host_public_key")? == p.record.host_public_key
            && text(&owner.object, "person_public_key")? == person
            && text(&owner.object, "signer_public_key")? == person
            && text(&owner.object, "issuer_id")? == "-"
            && text(&owner.object, "authority_signature_format")? == "sshsig",
    )?;
    profile(&context, p, num(&owner.payload, "scopes")?)?;
    let root = context
        .prefix
        .root
        .as_ref()
        .ok_or_else(|| Error::missing(&context.prefix.proposal.id))?;
    let base = context
        .prefix
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&context.prefix.proposal.id))?;
    let union = Catalog::union(&context.source.descriptor, base, catalog)?;
    let base = Projection::stage_migration(
        &context.source.descriptor,
        &base.bytes,
        &context.source.time,
        &context.prefix.proposal.id,
        &root.id,
        &context.prefix.source.maxima,
    )?;
    let projection = base.migration_owner_prefix(&union.bytes, owner, &context.source.time)?;
    let plan = plan(&context, &projection, p, text(&owner.payload, "not_after")?)?;
    check(
        text(&owner.payload, "root_state_id")? == plan.root
            && text(&owner.payload, "person_lease_id")? == plan.person_lease
            && ids(&owner.payload, "issuer_lease_ids", "ds_")? == vec![plan.person_lease.clone()]
            && text(&owner.payload, "member")? == plan.member,
    )?;
    Ok(plan)
}
/// Original-self consent is confined to the exact approved migration tuple.
/// Its scratch P/root facts never become an ordinary selected provider.
pub(super) fn owner_plan(
    store: &Store,
    c: &Connection,
    p: &requests::Pending,
    profile: OwnerProfile<'_>,
) -> Result<OwnerPlan> {
    let owned = Owned::load(
        store,
        c,
        &p.record.expected_network_id,
        &p.record.migration_proposal_id,
    )?;
    owned.matches(p)?;
    let context = &owned.context;
    require(
        p.record.host_public_key == store.identity().public_key
            && profile.person == text(&context.own, "person_public_key")?
            && profile.provider == profile.person
            && matches!(profile.format, "auto" | "sshsig")
            && profile.scopes == num(&context.own, "scopes")?,
        "forbidden",
    )?;
    self::profile(context, p, profile.scopes)?;
    plan(context, &owned.projection, p, profile.not_after)
}
// Future signatures below are byte-accounting placeholders only. They never
// pass to a proof parser, source verifier, signing routine or persistent record.
pub(super) fn byte_budget(context: &Context, prepared: &[u8], at: &str) -> Result<()> {
    require(prepared.len() <= MAX_OBJECT, "quota_exceeded")?;
    let d = &context.source.descriptor;
    let p = &context.prefix;
    let root = p
        .root
        .as_ref()
        .ok_or_else(|| Error::missing(&p.proposal.id))?;
    let ds = format!("ds_{}", "0".repeat(64));
    let da = format!("da_{}", "0".repeat(64));
    let mut candidate = context.record.clone();
    candidate.prepared_catalog_base64 = encode(prepared);
    let mut acknowledgments = BTreeMap::new();
    let mut ids = Vec::new();
    for row in array(&p.proposal.payload, "roster")? {
        let row = object(row)?;
        let host = text(row, "host_public_key")?;
        let body = if let Some(ack) = p.acknowledgments.get(host) {
            ids.push(ack.id.clone());
            ack.body.clone()
        } else {
            let owned = text(row, "person_public_key")? != "-";
            let payload = json!({"proposal_id":p.proposal.id,"root_state_id":root.id,
                "prepared_catalog_sha256":hash(prepared),"host_public_key":host,
                "person_public_key":text(row,"person_public_key")?,"device_public_key":text(row,"device_public_key")?,
                "host_lease_id":ds,"binding_lease_id":if owned {ds.as_str()}else{"-"},
                "device_lease_id":if owned {ds.as_str()}else{"-"},"activation_id":if owned {da.as_str()}else{"-"},"acknowledged_at":at});
            let mut signatures = Vec::new();
            if owned {
                signatures.push(json!({"role":"device","public_key":text(row,"device_public_key")?,"format":"ed25519","signature":"-"}));
            }
            signatures
                .push(json!({"role":"host","public_key":host,"format":"ed25519","signature":"-"}));
            let t = FixedStatement::read(
                d,
                &super::actions::bytes(
                    &json!({"format":1,"kind":"migration_ack","context_id":d.context_id(),"payload_base64":encode(&super::actions::bytes(&payload)?),"signatures":signatures}),
                )?,
            )?;
            ids.push(t.statement_id().to_owned());
            t.budget_bytes()?
        };
        acknowledgments.insert(host.to_owned(), encode(&body));
    }
    candidate.acknowledgments_base64 = acknowledgments.into_values().collect();
    ids.sort();
    let payload = json!({"proposal_id":p.proposal.id,"root_state_id":root.id,
        "prepared_catalog_sha256":hash(prepared),"acknowledgment_ids":ids,"committed_at":at});
    let t = FixedStatement::read(
        d,
        &super::actions::bytes(
            &json!({"format":1,"kind":"migration_commit","context_id":d.context_id(),"payload_base64":encode(&super::actions::bytes(&payload)?),"signatures":[{"role":"issuer","public_key":text(&p.proposal.payload,"legacy_root_public_key")?,"format":"sshsig","signature":"-"}]}),
        )?,
    )?;
    candidate.commit_base64 = encode(&t.budget_bytes()?);
    Prefix::complete_body(&candidate)?;
    Ok(())
}
pub(super) fn pending_budget(
    store: &Store,
    c: &Connection,
    p: &requests::Pending,
    prepared: &[u8],
    at: &str,
) -> Result<()> {
    let context = Context::load(
        store,
        c,
        &p.record.expected_network_id,
        &p.record.migration_proposal_id,
    )?;
    target(&context, p)?;
    byte_budget(&context, prepared, at)
}
/// Retain a complete, consented staged activation as private migration evidence.
/// It creates no DEC admission, selected provider, outcome, ACK or fence.
pub(super) fn retain_complete(store: &Store, c: &mut Connection, id: &str) -> Result<()> {
    let tx = c.transaction().map_err(|_| Error::new("internal"))?;
    let mut pending = requests::load(&tx, id)?;
    retain_prepared(store, &tx, &mut pending)?;
    tx.commit().map_err(|_| Error::new("internal"))?;
    Ok(())
}
pub(super) fn retain_prepared(
    store: &Store,
    c: &Connection,
    pending: &mut requests::Pending,
) -> Result<()> {
    if matches!(
        pending.record.terminal.as_str(),
        "migration_prepared" | "migration_adopted"
    ) {
        return Ok(());
    }
    require(
        pending.record.terminal == "-" && pending.record.migration_proposal_id != "-",
        "operation_conflict",
    )?;
    if pending.record.commit_packet_base64 == "-" {
        return Ok(());
    }
    let context = Context::load(
        store,
        c,
        &pending.record.expected_network_id,
        &pending.record.migration_proposal_id,
    )?;
    target(&context, pending)?;
    let evidence = super::observer::Evidence::read(c, pending, &context.source.time)?;
    let offer = evidence.offer(
        c,
        store,
        pending,
        &pending.record.owner_offer_id,
        &context.source.time,
    )?;
    let stage = offer
        .staging
        .as_ref()
        .ok_or_else(|| Error::new("forbidden"))?;
    if pending.record.roles.iter().any(|r| r == "requester") {
        require(
            pending.record.selection_approved && pending.record.commit_approved,
            "review_required",
        )?;
        super::requester::validate_references(c, pending)?;
        let owned = Owned::load(
            store,
            c,
            &pending.record.expected_network_id,
            &pending.record.migration_proposal_id,
        )?;
        owned.matches(pending)?;
    }
    let raw = super::requester::activation_bytes(
        pending,
        &b64(&pending.record.commit_packet_base64, MAX_OBJECT)?,
    )?;
    let activation = Activation::read(&offer.descriptor, &raw)?;
    check(
        activation.request_id == pending.id
            && activation.id == pending.record.activation_id
            && activation.manifest_id == pending.record.manifest_id,
    )?;
    let me = store.identity().public_key;
    require(
        ["request", "owner", "administrator"]
            .into_iter()
            .filter_map(|role| activation.packets.get(role))
            .any(|p| {
                p.object
                    .get("writer_host_public_key")
                    .and_then(Value::as_str)
                    == Some(&me)
            }),
        "forbidden",
    )?;
    let catalog = evidence
        .catalogs
        .get(&offer.descriptor.context_id())
        .ok_or_else(|| Error::missing(&activation.id))?;
    let proof = super::statement::proof_id("activation", &raw);
    let addition = Catalog::read(
        &offer.descriptor,
        &super::actions::bytes(
            &json!({"format":1,"context_id":offer.descriptor.context_id(),"objects":[{"id":proof,"kind":"activation","body_base64":encode(&raw)}]}),
        )?,
    )?;
    let full = Catalog::union(&offer.descriptor, catalog, &addition)?;
    let checked = stage.migration_owner_prefix(&full.bytes, &offer.owner, &context.source.time)?;
    checked.activation_response(&pending.id, &Value::from("-"))?;
    let base = context
        .prefix
        .catalog
        .as_ref()
        .ok_or_else(|| Error::missing(&context.prefix.proposal.id))?;
    let prepared = Catalog::union(&offer.descriptor, base, &full)?;
    let mut record = context.record.clone();
    if !context.prefix.acknowledgments.is_empty() {
        require(base.bytes == prepared.bytes, "operation_conflict")?;
    }
    byte_budget(&context, &prepared.bytes, &context.source.time)?;
    record.prepared_catalog_base64 = encode(&prepared.bytes);
    let prefix = Prefix::read(&offer.descriptor, &record)?;
    check(prefix.proposal.id == pending.record.migration_proposal_id)?;
    pending.record.catalog_base64 = encode(&prepared.bytes);
    pending.record.terminal = "migration_prepared".into();
    migration_prepare::save(
        c,
        &offer.descriptor.network_id,
        &prefix.proposal.id,
        &record,
    )?;
    requests::save(c, pending)?;
    controls::remember_decision(c, &offer.descriptor.network_id, &context.source.time)?;
    Ok(())
}
pub(crate) fn create(store: &Store, network: &str, input: &Obj) -> Result<(u16, Vec<u8>)> {
    fields(input, "proposal_id")?;
    let proposal = text(input, "proposal_id")?;
    check(ident(network, "net_") && ident(proposal, "ds_"))?;
    let helpers = store
        .bootstrap_settings
        .read()
        .map_err(|_| Error::new("internal"))?
        .rendezvous
        .clone();
    requests::create(
        store,
        object(
            &json!({"mode":"new","network_id":network,"person_public_key":"-",
        "migration_proposal_id":proposal,"contact_invitation":"-","helpers":Value::Array(helpers)}),
        )?,
    )
}
