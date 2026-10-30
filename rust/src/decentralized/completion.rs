//! Participant application is one guarded transaction. A transport identity
//! only selects the participant boundary; complete consent supplies authority.
use super::{
    catalog::{Catalog, raw_field},
    codec::*,
    controls,
    mailbox::{CompletionRequest, CompletionResponse, ParticipantCompletion},
    requests,
    statement::Descriptor,
    storage::{OwnIdentity, Snapshot},
    transcript::{Activation, Packet},
};
use crate::store::Store;
use ed25519_dalek::Signer;
use rusqlite::Connection;
use serde_json::{Value, json, value::RawValue};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};
fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn bytes(v: &impl serde::Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| Error::new("internal"))
}
pub(crate) fn handler(store: Arc<Store>) -> Arc<dyn ParticipantCompletion> {
    Arc::new(Handler { store })
}
struct Handler {
    store: Arc<Store>,
}
impl ParticipantCompletion for Handler {
    fn complete(
        &self,
        request: CompletionRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<CompletionResponse>> + Send + '_>> {
        let store = self.store.clone();
        Box::pin(async move {
            let result = tokio::task::spawn_blocking(move || dispatch(&store, &request)).await?;
            Ok(match result {
                Ok(body) => CompletionResponse { status: 200, body },
                Err(e) => {
                    let status = match e.code {
                        "invalid" => 400,
                        "forbidden"
                        | "authority_expired"
                        | "device_revoked"
                        | "not_yet_valid"
                        | "authority_would_be_invalidated" => 403,
                        "not_found" => 404,
                        "expired" => 410,
                        "rate_limited" => 429,
                        "upgrade_required" => 426,
                        "internal" => 500,
                        _ => 409,
                    };
                    CompletionResponse {
                        status,
                        body: bytes(
                            &json!({"code":e.code,"error":e.code.replace('_'," "),"details":{"network_id":"-","context_id":"-","request_id":"-","stage":"application","required_ids":e.required_ids,"conflict_ids":[],"next":[]}}),
                        )?,
                    }
                }
            })
        })
    }
}
struct Evidence {
    descriptor: Descriptor,
    activation: Activation,
    activation_raw: Vec<u8>,
    catalog: Catalog,
}
impl Evidence {
    fn read(activation: Vec<u8>, catalog: Vec<u8>) -> Result<Self> {
        let owner = Packet::read(&raw_field(&activation, "owner")?)?;
        let descriptor = Descriptor::from_value(
            owner
                .payload
                .get("descriptor")
                .ok_or_else(|| Error::new("invalid"))?,
        )?;
        let activation_parsed = Activation::read(&descriptor, &activation)?;
        require(
            text(
                &activation_parsed.packets["request"].payload,
                "migration_proposal_id",
            )? == "-",
            "operation_conflict",
        )?;
        let catalog = Catalog::read(&descriptor, &catalog)?;
        let id = crate::decentralized::statement::proof_id("activation", &activation);
        let addition = Catalog::read(
            &descriptor,
            &bytes(
                &json!({"format":1,"context_id":descriptor.context_id(),"objects":[{"id":id,"kind":"activation","body_base64":encode(&activation)}]}),
            )?,
        )?;
        let catalog = Catalog::union(&descriptor, &catalog, &addition)?;
        Ok(Self {
            descriptor,
            activation: activation_parsed,
            activation_raw: activation,
            catalog,
        })
    }
    fn participants(&self) -> Result<BTreeSet<String>> {
        ["request", "owner", "administrator"]
            .into_iter()
            .filter_map(|r| self.activation.packets.get(r))
            .map(|p| Ok(text(&p.object, "writer_host_public_key")?.into()))
            .collect()
    }
    fn boundary(&self, store: &Store, caller: &str) -> Result<()> {
        let participants = self.participants()?;
        require(
            participants.contains(caller) && participants.contains(&store.identity().public_key),
            "forbidden",
        )
    }
}
fn response(activation: &[u8], catalog: &[u8], outcome: &[u8]) -> Result<Vec<u8>> {
    let mut fields: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
    for (field, raw) in [
        ("activation", activation),
        ("catalog", catalog),
        ("outcome", outcome),
    ] {
        fields.insert(
            field,
            serde_json::from_slice(raw).map_err(|_| Error::new("invalid"))?,
        );
    }
    let result = bytes(&fields)?;
    require(result.len() <= 20 << 20, "quota_exceeded")?;
    Ok(result)
}
fn retained(
    c: &Connection,
    store: &Store,
    id: &str,
    caller: &str,
    expected: Option<&Evidence>,
) -> Result<Option<Vec<u8>>> {
    let mut q=c.prepare("SELECT network_id,context_id,record,locally_applied,activation_id,manifest_id FROM dec_operations WHERE request_id=?1 ORDER BY network_id,context_id").map_err(db)?;
    let rows = q
        .query_map([id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    require(rows.len() <= 1, "operation_conflict")?;
    let Some((network, context, record, applied, activation_id, manifest_id)) = rows.first() else {
        return Ok(None);
    };
    require(*applied == 1, "state_conflict")?;
    let value = parse(record.as_bytes(), 32 << 20)?;
    let r = object(&value)?;
    fields(
        r,
        "format activation_base64 catalog_base64 outcome_packet_base64 applied_at",
    )?;
    version(r)?;
    let evidence = Evidence::read(
        b64(text(r, "activation_base64")?, MAX_OBJECT)?,
        b64(text(r, "catalog_base64")?, MAX_CATALOG)?,
    )?;
    require(
        evidence.descriptor.network_id == *network
            && evidence.descriptor.context_id() == *context
            && evidence.activation.request_id == id,
        "state_conflict",
    )?;
    require(
        evidence.activation.id == *activation_id && evidence.activation.manifest_id == *manifest_id,
        "state_conflict",
    )?;
    evidence.boundary(store, caller)?;
    if let Some(expected) = expected {
        require(
            evidence.activation.id == expected.activation.id
                && evidence.activation.manifest_id == expected.activation.manifest_id
                && raw_field(&evidence.activation_raw, "request")?
                    == raw_field(&expected.activation_raw, "request")?,
            "operation_conflict",
        )?
    }
    let outcome_raw = b64(text(r, "outcome_packet_base64")?, MAX_OBJECT)?;
    let outcome = Packet::read(&outcome_raw)?;
    require(
        text(&outcome.object, "writer_host_public_key")? == store.identity().public_key
            && text(&outcome.object, "role")? == "outcome"
            && text(&outcome.object, "request_id")? == id
            && text(&outcome.payload, "context_id")? == *context
            && text(&outcome.payload, "manifest_id")? == evidence.activation.manifest_id
            && text(&outcome.payload, "activation_id")? == evidence.activation.id
            && text(&outcome.payload, "activation_sha256")? == hash(&evidence.activation_raw)
            && text(&outcome.payload, "applied_at")? == text(r, "applied_at")?,
        "state_conflict",
    )?;
    stamp(text(r, "applied_at")?)?;
    // Recheck the immutable retained consent/catalog at the actual saved
    // application decision; neither current authority nor a new signer is used.
    let projection = super::state::Projection::build(
        &evidence.descriptor,
        &Value::from("-"),
        Some(&evidence.catalog.bytes),
        text(r, "applied_at")?,
        "repair",
    )?;
    projection.activation_response(id, &Value::from("-"))?;
    if let Some(expected) = expected {
        // Unsigned outer framing may alias the same fixed operation. Every
        // manifest-pinned original must nevertheless be supplied unchanged.
        for id in ids(&expected.activation.manifest, "proof_ids", "dp_")? {
            let original = evidence.catalog.proof(&id)?;
            let supplied = expected.catalog.proof(&id)?;
            require(
                original.kind == supplied.kind && original.body == supplied.body,
                "operation_conflict",
            )?;
        }
        // Validate all supplied consent/aliases against the immutable saved
        // application snapshot. READ admits no new candidate, advances no
        // clock/head, and makes no claim about present authority.
        let alias = super::state::Projection::read_with_proofs(
            &evidence.descriptor,
            &projection.next_prior(),
            &expected.catalog.bytes,
            text(r, "applied_at")?,
        )?;
        alias.activation_response(id, &Value::from("-"))?;
    }
    require(
        text(&outcome.payload, "observed_root_state_id")? == projection.root_state_id()?,
        "state_conflict",
    )?;
    response(
        &evidence.activation_raw,
        &b64(text(r, "catalog_base64")?, MAX_CATALOG)?,
        &outcome_raw,
    )
    .map(Some)
}
fn dispatch(store: &Store, request: &CompletionRequest) -> Result<Vec<u8>> {
    if request.method == "GET" {
        check(request.body.is_empty())?;
        let id = request
            .path
            .strip_prefix("/bootstrap/v1/operations/")
            .ok_or_else(|| Error::new("not_found"))?;
        check(ident(id, "link_"))?;
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        return retained(&c, store, id, &request.host_public_key, None)?
            .ok_or_else(|| Error::new("not_found"));
    }
    check(request.method == "POST" && request.path == "/bootstrap/v1/activations")?;
    let value = parse(&request.body, 20 << 20)?;
    fields(object(&value)?, "activation catalog")?;
    let evidence = Evidence::read(
        raw_field(&request.body, "activation")?,
        raw_field(&request.body, "catalog")?,
    )?;
    apply(store, evidence, &request.host_public_key)
}
fn local_pending(c: &Connection, store: &Store, e: &Evidence) -> Result<Option<requests::Pending>> {
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM dec_pending WHERE request_id=?1)",
            [&e.activation.request_id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let p = if exists {
        Some(requests::load(c, &e.activation.request_id)?)
    } else {
        None
    };
    if let Some(p) = &p {
        require(
            b64(&p.record.request_packet_base64, MAX_OBJECT)?
                == raw_field(&e.activation_raw, "request")?,
            "operation_conflict",
        )?;
        for (role, reference, saved) in [
            (
                "owner",
                &p.record.owner_intent_id,
                &p.record.owner_packet_base64,
            ),
            (
                "administrator",
                &p.record.administrator_intent_id,
                &p.record.administrator_packet_base64,
            ),
        ] {
            if reference != "-" {
                let intent = super::intents::Intent::load(c, reference)?;
                require(
                    intent.record.approved
                        && saved != "-"
                        && b64(saved, MAX_OBJECT)? == raw_field(&e.activation_raw, role)?,
                    "operation_conflict",
                )?;
            }
        }
        if p.record.owner_intent_id != "-" && p.record.owner_finalization_packet_base64 != "-" {
            require(
                b64(&p.record.owner_finalization_packet_base64, MAX_OBJECT)?
                    == raw_field(&e.activation_raw, "owner_finalization")?,
                "operation_conflict",
            )?;
        }
    }
    if text(&e.activation.packets["request"].payload, "host_public_key")?
        == store.identity().public_key
    {
        let p = p.as_ref().ok_or_else(|| Error::new("forbidden"))?;
        require(
            p.record.roles.iter().any(|r| r == "requester")
                && p.record.selection_approved
                && p.record.commit_approved
                && p.record.commit_packet_base64 != "-",
            "forbidden",
        )?;
        require(
            e.activation.id == p.record.activation_id
                && e.activation.manifest_id == p.record.manifest_id
                && raw_field(&e.activation_raw, "commit")?
                    == b64(&p.record.commit_packet_base64, MAX_OBJECT)?
                && raw_field(&e.activation_raw, "request")?
                    == b64(&p.record.request_packet_base64, MAX_OBJECT)?,
            "operation_conflict",
        )?;
        super::observer::owned_device(store, c, p)?;
    }
    Ok(p)
}
fn outcome(store: &Store, e: &Evidence, root: &str, at: &str) -> Result<Vec<u8>> {
    let payload = bytes(
        &json!({"context_id":e.descriptor.context_id(),"request_id":e.activation.request_id,"manifest_id":e.activation.manifest_id,"activation_id":e.activation.id,"activation_sha256":hash(&e.activation_raw),"observed_root_state_id":root,"applied_at":at}),
    )?;
    let host = store.identity().public_key;
    let msg = lines(&[
        "peerspan-decentralized-packet-v1",
        &e.descriptor.context_id(),
        &e.activation.request_id,
        "outcome",
        &host,
        "-",
        "-",
        "-",
        "-",
        &hash(&payload),
    ]);
    let raw = bytes(
        &json!({"format":1,"context_id":e.descriptor.context_id(),"request_id":e.activation.request_id,"role":"outcome","writer_host_public_key":host,"signer_public_key":"-","person_public_key":"-","issuer_id":"-","payload_base64":encode(&payload),"host_signature":encode(&store.signing_key.sign(&msg).to_bytes()),"device_signature":"-","authority_signature_format":"-","authority_signature":"-"}),
    )?;
    Packet::read(&raw)?;
    Ok(raw)
}
fn verify(
    c: &Connection,
    store: &Store,
    e: &Evidence,
    now: &str,
) -> Result<(Option<Snapshot>, super::state::Projection)> {
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [&e.descriptor.network_id],
            |r| r.get(0),
        )
        .map_err(db)?;
    let snapshot = if exists {
        Some(Snapshot::load(
            c,
            &e.descriptor.network_id,
            &store.identity().public_key,
        )?)
    } else {
        None
    };
    if let Some(snapshot) = &snapshot {
        require(
            snapshot.network.context_id == e.descriptor.context_id(),
            "state_conflict",
        )?;
        require(
            !snapshot
                .migrations
                .iter()
                .any(|m| m.fenced && m.state != "adopted"),
            "operation_conflict",
        )?;
    }
    let prior = snapshot
        .as_ref()
        .map(|s| &s.prior.value)
        .unwrap_or(&Value::Null);
    let empty = Value::from("-");
    let prior = if prior.is_null() { &empty } else { prior };
    let decision = controls::guarded_decision(c, &e.descriptor.network_id, now)?;
    let projection = super::state::Projection::build(
        &e.descriptor,
        prior,
        Some(&e.catalog.bytes),
        &decision,
        "repair",
    )?;
    projection.activation_response(&e.activation.request_id, &Value::from("-"))?;
    let count: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM dec_operations WHERE network_id=?1",
            [&e.descriptor.network_id],
            |r| r.get(0),
        )
        .map_err(db)?;
    require(count < 4096, "quota_exceeded")?;
    let mut new_proofs: BTreeSet<_> = projection
        .catalog
        .proofs
        .keys()
        .filter(|p| {
            snapshot
                .as_ref()
                .is_none_or(|s| !s.prior.catalog.proofs.contains_key(*p))
        })
        .cloned()
        .collect();
    for id in projection
        .admitted
        .iter()
        .filter(|id| {
            snapshot
                .as_ref()
                .is_none_or(|s| !s.prior.admitted.contains(*id))
        })
        .chain(projection.restrictions.iter().filter(|id| {
            snapshot
                .as_ref()
                .is_none_or(|s| !s.prior.restrictions.contains(*id))
        }))
    {
        if let Some(proof) = projection
            .catalog
            .statement_proofs
            .get(id)
            .and_then(|p| p.first())
        {
            new_proofs.insert(proof.clone());
        }
    }
    if !new_proofs.is_empty() {
        let mut targets: BTreeSet<_> = projection
            .members()?
            .into_iter()
            .map(|m| m.host_public_key)
            .collect();
        if let Some(old) = &snapshot
            && let Ok(prior) = old.project(&projection.decision_time)
        {
            targets.extend(prior.members()?.into_iter().map(|m| m.host_public_key));
        }
        targets.remove(&store.identity().public_key);
        let body = bytes(&json!({"catalog":parse(&projection.catalog.bytes,MAX_CATALOG)?}))?;
        let record = json!({"format":1,"kind":"proofs","body_base64":encode(&body),"proof_ids":new_proofs,"created_at":projection.decision_time,"attempts":0,"next_attempt_at":projection.decision_time,"last_error_code":"-","last_error_detail":"-"});
        super::storage::check_outbox_capacity(c, &vec![&record; targets.len()])?;
    } else {
        super::storage::check_outbox_capacity(c, &[])?;
    }
    Ok((snapshot, projection))
}
fn apply(store: &Store, e: Evidence, caller: &str) -> Result<Vec<u8>> {
    apply_guarded(store, e, caller, |_, _, _| Ok(()))
}
fn apply_guarded(
    store: &Store,
    e: Evidence,
    caller: &str,
    mut guard: impl FnMut(&Connection, &requests::Pending, bool) -> Result<()>,
) -> Result<Vec<u8>> {
    e.boundary(store, caller)?;
    {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        if let Some(result) = retained(&c, store, &e.activation.request_id, caller, Some(&e))? {
            return Ok(result);
        }
        local_pending(&c, store, &e)?;
        verify(&c, store, &e, &controls::local_decision_time()?)?;
    }
    controls::barrier(
        store,
        "dec.apply.before_transaction",
        &e.activation.request_id,
    )?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut tx = c.transaction().map_err(db)?;
    if let Some(result) = retained(&tx, store, &e.activation.request_id, caller, Some(&e))? {
        return Ok(result);
    }
    let mut pending = local_pending(&tx, store, &e)?;
    if let Some(p) = &pending {
        guard(&tx, p, false)?;
    }
    let (snapshot, projection) = verify(&tx, store, &e, &controls::local_decision_time()?)?;
    let now = projection.decision_time.clone();
    let root = projection.root_state_id()?.to_owned();
    let target_host = text(&e.activation.packets["request"].payload, "host_public_key")?;
    let target_person = text(&e.activation.packets["owner"].object, "person_public_key")?;
    let target_device = text(
        &e.activation.packets["request"].payload,
        "device_public_key",
    )?;
    let lease = text(&e.activation.manifest, "device_lease_id")?;
    let is_requester = target_host == store.identity().public_key;
    if let Some(snapshot) = snapshot {
        snapshot.apply_catalog(&mut tx, &e.catalog.bytes, &now, "repair")?;
        if is_requester {
            require(
                snapshot.network.own_identity.person_public_key == target_person,
                "forbidden",
            )?;
            tx.execute("INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?1,?2,'device',?3,?4,?5) ON CONFLICT(network_id,context_id) DO UPDATE SET provider_kind=excluded.provider_kind,person_key=excluded.person_key,device_key=excluded.device_key,lease_id=excluded.lease_id",rusqlite::params![e.descriptor.network_id,e.descriptor.context_id(),target_person,target_device,lease]).map_err(db)?;
        }
    } else {
        require(is_requester, "forbidden")?;
        Snapshot::install_activation(
            &mut tx,
            &bytes(&e.descriptor)?,
            &e.catalog.bytes,
            &now,
            &OwnIdentity {
                member: text(&e.activation.packets["owner"].payload, "member")?.into(),
                person_public_key: target_person.into(),
                host_public_key: target_host.into(),
            },
            &e.activation.request_id,
        )?;
    }
    // The owned outcome signature and optional sealed frame belong to this
    // final decision, together with state/event/provider and secret retirement.
    if let Some(p) = &pending {
        guard(&tx, p, true)?;
    }
    let outcome = outcome(store, &e, &root, &now)?;
    if let Some(p) = pending.as_mut() {
        if p.secret.is_some()
            && !p.record.carrier_endpoints.is_empty()
            && stamp(&now)? < stamp(&p.deadline)?
        {
            // Only the new already-sealed outcome remains after erasure.
            tx.execute("DELETE FROM dec_frames WHERE request_id=?1", [&p.id])
                .map_err(db)?;
            p.record.outbound_frames.clear();
            let secret = p.secret.ok_or_else(|| Error::new("state_conflict"))?;
            super::requester::retain_outbound(&tx, store, p, "outcome", &outcome, "-", &now)?;
            if !p.record.carrier_endpoints.is_empty() {
                p.terminal_read_cap = Some(
                    hex::decode(super::bootstrap::read_cap(&secret))
                        .map_err(|_| Error::new("internal"))?
                        .try_into()
                        .map_err(|_| Error::new("internal"))?,
                )
            }
        } else {
            tx.execute("DELETE FROM dec_frames WHERE request_id=?1", [&p.id])
                .map_err(db)?;
            p.record.outbound_frames.clear();
            p.terminal_read_cap = None;
        }
        // A participant's retained public view describes the complete exact
        // operation it actually applied; received consent never sets local
        // requester approval booleans or invents owned signing intents.
        p.record.descriptor_base64 = encode(&bytes(&e.descriptor)?);
        for (role, raw, id) in [
            (
                "owner",
                &mut p.record.owner_packet_base64,
                &mut p.record.owner_offer_id,
            ),
            (
                "selection",
                &mut p.record.selection_packet_base64,
                &mut p.record.selection_id,
            ),
            (
                "administrator",
                &mut p.record.administrator_packet_base64,
                &mut p.record.administrator_offer_id,
            ),
            (
                "owner_finalization",
                &mut p.record.owner_finalization_packet_base64,
                &mut p.record.owner_finalization_id,
            ),
        ] {
            if let Some(packet) = e.activation.packets.get(role) {
                *raw = encode(&raw_field(&e.activation_raw, role)?);
                *id = packet.id.clone();
            } else {
                *raw = "-".into();
                *id = "-".into();
            }
        }
        p.record.commit_packet_base64 = encode(&raw_field(&e.activation_raw, "commit")?);
        p.record.catalog_base64 = encode(&projection.catalog.bytes);
        p.record.outcome_packet_base64 = encode(&outcome);
        p.record.activation_id = e.activation.id.clone();
        p.record.manifest_id = e.activation.manifest_id.clone();
        p.record.terminal = "applied".into();
        p.secret = None;
        for reference in [&p.record.selection_intent_id, &p.record.commit_intent_id] {
            if reference != "-" {
                let mut intent = super::intents::Intent::load(&tx, reference)?;
                require(
                    intent.record.approved && intent.record.completed,
                    "state_conflict",
                )?;
                intent.record.terminal = "applied".into();
                intent.save(&tx)?;
            }
        }
        requests::save(&tx, p)?;
    }
    let record = json!({"format":1,"activation_base64":encode(&e.activation_raw),"catalog_base64":encode(&projection.catalog.bytes),"outcome_packet_base64":encode(&outcome),"applied_at":now});
    tx.execute("INSERT INTO dec_operations(network_id,context_id,request_id,activation_id,manifest_id,record,locally_applied) VALUES(?1,?2,?3,?4,?5,?6,1)",rusqlite::params![e.descriptor.network_id,e.descriptor.context_id(),e.activation.request_id,e.activation.id,e.activation.manifest_id,record.to_string()]).map_err(db)?;
    crate::store::append_event(&tx, "network.link_applied", &e.activation.request_id, &now)
        .map_err(db)?;
    let result = response(&e.activation_raw, &projection.catalog.bytes, &outcome)?;
    if let Some(p) = &pending {
        guard(&tx, p, true)?;
    }
    tx.commit().map_err(db)?;
    store
        .refresh_member_pins(&c)
        .map_err(|_| Error::new("internal"))?;
    drop(c);
    if pending
        .as_ref()
        .is_some_and(|p| p.terminal_read_cap.is_some())
    {
        controls::barrier(store, "dec.frame.after_commit", &e.activation.request_id)?;
    }
    controls::barrier(store, "dec.apply.after_commit", &e.activation.request_id)?;
    Ok(result)
}
pub(crate) fn apply_local(store: &Store, id: &str) -> Result<bool> {
    let evidence = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let p = requests::load(&c, id)?;
        if p.record.terminal != "-" || p.record.commit_packet_base64 == "-" {
            return Ok(false);
        }
        require(p.record.migration_proposal_id == "-", "not_found")?;
        Evidence::read(
            super::requester::activation_bytes(
                &p,
                &b64(&p.record.commit_packet_base64, MAX_OBJECT)?,
            )?,
            b64(&p.record.catalog_base64, MAX_CATALOG)?,
        )?
    };
    apply(store, evidence, &store.identity().public_key)?;
    Ok(true)
}

/// Pure exact saved application verification, at its saved decision time.
pub(crate) fn local_recorded(c: &Connection, store: &Store, p: &requests::Pending) -> Result<bool> {
    if p.record.terminal != "applied" {
        return Ok(false);
    }
    let raw = retained(c, store, &p.id, &store.identity().public_key, None)?
        .ok_or_else(|| Error::new("state_conflict"))?;
    let activation = raw_field(&raw, "activation")?;
    let e = Evidence::read(activation, raw_field(&raw, "catalog")?)?;
    let outcome = Packet::read(&raw_field(&raw, "outcome")?)?;
    check(
        e.activation.id == p.record.activation_id
            && e.activation.manifest_id == p.record.manifest_id
            && outcome.id == Packet::read(&b64(&p.record.outcome_packet_base64, MAX_OBJECT)?)?.id
            && raw_field(&e.activation_raw, "commit")?
                == b64(&p.record.commit_packet_base64, MAX_OBJECT)?,
    )?;
    Ok(true)
}
/// Current ordinary complete projection before guided publication/application.
pub(crate) fn local_current(
    c: &Connection,
    store: &Store,
    p: &requests::Pending,
) -> Result<String> {
    let e = Evidence::read(
        super::requester::activation_bytes(p, &b64(&p.record.commit_packet_base64, MAX_OBJECT)?)?,
        b64(&p.record.catalog_base64, MAX_CATALOG)?,
    )?;
    e.boundary(store, &store.identity().public_key)?;
    local_pending(c, store, &e)?;
    let (_, projection) = verify(c, store, &e, &controls::local_decision_time()?)?;
    Ok(projection.root_state_id()?.into())
}
pub(crate) fn apply_local_guarded(
    store: &Store,
    id: &str,
    guard: impl FnMut(&Connection, &requests::Pending, bool) -> Result<()>,
) -> Result<()> {
    let e = {
        let c = store.connection().map_err(|_| Error::new("internal"))?;
        let p = requests::load(&c, id)?;
        Evidence::read(
            super::requester::activation_bytes(
                &p,
                &b64(&p.record.commit_packet_base64, MAX_OBJECT)?,
            )?,
            b64(&p.record.catalog_base64, MAX_CATALOG)?,
        )?
    };
    apply_guarded(store, e, &store.identity().public_key, guard)?;
    Ok(())
}

struct PublicationTarget {
    tcp: Vec<Value>,
    quic: Vec<String>,
}
struct Publication {
    targets: BTreeMap<String, PublicationTarget>,
    body: bytes::Bytes,
}
fn publication(store: &Store, id: &str) -> Result<Option<Publication>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let p = requests::load(&c, id)?;
    if p.record.terminal != "applied" {
        return Ok(None);
    }
    // This validates only the immutable saved application, at its saved time.
    // Publishing it again cannot select a provider or advance the local clock.
    let saved = retained(&c, store, id, &store.identity().public_key, None)?
        .ok_or_else(|| Error::new("state_conflict"))?;
    let activation = raw_field(&saved, "activation")?;
    let catalog = raw_field(&saved, "catalog")?;
    let evidence = Evidence::read(activation.clone(), catalog.clone())?;
    let participants = evidence.participants()?;
    let now = controls::local_decision_time()?;
    let mut targets = BTreeMap::new();
    for key in participants {
        if key == store.identity().public_key {
            continue;
        }
        let tcp = p
            .record
            .carrier_endpoints
            .iter()
            .filter(|e| e["kind"] == "participant" && e["public_key"] == key)
            .cloned()
            .collect();
        // The durable transcript supplies this pin. A signed contact supplies
        // only a replaceable address, never membership or authority.
        let quic = super::peer::product_addresses(
            &c,
            &evidence.descriptor.network_id,
            &evidence.descriptor.context_id(),
            &key,
            &now,
        )?;
        targets.insert(key, PublicationTarget { tcp, quic });
    }
    if targets.is_empty() {
        return Ok(None);
    }
    let body = bytes(&BTreeMap::from([
        (
            "activation",
            serde_json::from_slice::<Box<RawValue>>(&activation)
                .map_err(|_| Error::new("invalid"))?,
        ),
        (
            "catalog",
            serde_json::from_slice::<Box<RawValue>>(&catalog).map_err(|_| Error::new("invalid"))?,
        ),
    ]))?;
    require(body.len() <= 20 << 20, "quota_exceeded")?;
    Ok(Some(Publication {
        targets,
        body: body.into(),
    }))
}
fn verify_publication(store: &Store, id: &str, host: &str, raw: &[u8]) -> Result<()> {
    let v = parse(raw, 20 << 20)?;
    fields(object(&v)?, "activation catalog outcome")?;
    let evidence = Evidence::read(raw_field(raw, "activation")?, raw_field(raw, "catalog")?)?;
    require(evidence.activation.request_id == id, "operation_conflict")?;
    let outcome = Packet::read(&raw_field(raw, "outcome")?)?;
    require(
        text(&outcome.object, "role")? == "outcome"
            && text(&outcome.object, "writer_host_public_key")? == host
            && text(&outcome.object, "request_id")? == id
            && text(&outcome.object, "context_id")? == evidence.descriptor.context_id()
            && text(&outcome.payload, "request_id")? == id
            && text(&outcome.payload, "context_id")? == evidence.descriptor.context_id()
            && text(&outcome.payload, "manifest_id")? == evidence.activation.manifest_id
            && text(&outcome.payload, "activation_id")? == evidence.activation.id
            && text(&outcome.payload, "activation_sha256")? == hash(&evidence.activation_raw),
        "operation_conflict",
    )?;
    // The peer's signed outcome is its own local observation, not our state,
    // freshness or a globally ordered receipt. Validate all original pins and
    // exact consent aliases against our retained operation without reapplying.
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    retained(&c, store, id, host, Some(&evidence))?.ok_or_else(|| Error::new("state_conflict"))?;
    Ok(())
}
pub(crate) async fn publish(store: Arc<Store>, id: &str) -> Result<bool> {
    // At most three maximum-size public request plans can occupy the send
    // queue. Responses share bootstrap_io's separately bounded receive queue.
    static BUDGET: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    let permit = Arc::new(
        BUDGET
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(64 << 20)))
            .clone()
            .try_acquire_many_owned(20 << 20)
            .map_err(|_| Error::new("quota_exceeded"))?,
    );
    let target = store.clone();
    let request_id = id.to_owned();
    let planning_permit = permit.clone();
    let Some(plan) = tokio::task::spawn_blocking(move || {
        let _permit = planning_permit;
        publication(&target, &request_id)
    })
    .await
    .map_err(|_| Error::new("internal"))??
    else {
        return Ok(false);
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut succeeded = BTreeSet::new();
        let mut failed = BTreeMap::new();
        for (host, target) in plan.targets {
            let verify = |response: super::bootstrap_io::Response| {
                let target = store.clone();
                let id = id.to_owned();
                let host = host.clone();
                let verification_permit = permit.clone();
                async move {
                    let raw = super::bootstrap_io::success(response)?;
                    tokio::task::spawn_blocking(move || {
                        let _permit = verification_permit;
                        verify_publication(&target, &id, &host, &raw)
                    })
                    .await
                    .map_err(|_| Error::new("internal"))?
                }
            };
            for endpoint in target.tcp {
                let result = async {
                    verify(
                        super::bootstrap_io::complete(store.clone(), &endpoint, plan.body.clone())
                            .await?,
                    )
                    .await
                }
                .await;
                match result {
                    Ok(()) => {
                        succeeded.insert(host.clone());
                        failed.remove(&host);
                        break;
                    }
                    Err(mut e) => {
                        e.stage = Some("transport");
                        failed.insert(host.clone(), e);
                    }
                }
            }
            if succeeded.contains(&host) {
                continue;
            }
            // An empty direct address still permits explicitly selected relay4
            // resources. Their registration is never an application predicate.
            for address in target
                .quic
                .into_iter()
                .chain(std::iter::once(String::new()))
            {
                let peer = crate::peer_store::Peer {
                    id: crate::peer_store::key_id(&b64(&host, 32)?),
                    public_key: host.clone(),
                    address,
                };
                let result = async {
                    verify(
                        crate::quic::completion_request(
                            store.clone(),
                            &peer,
                            hyper::Method::POST,
                            "/bootstrap/v1/activations".into(),
                            plan.body.clone(),
                        )
                        .await?,
                    )
                    .await
                }
                .await;
                match result {
                    Ok(()) => {
                        succeeded.insert(host.clone());
                        failed.remove(&host);
                        break;
                    }
                    Err(mut e) => {
                        e.stage = Some("transport");
                        failed.insert(host.clone(), e);
                    }
                }
            }
        }
        if let Some((_, error)) = failed.into_iter().next() {
            return Err(error);
        }
        Ok(!succeeded.is_empty())
    })
    .await
    .map_err(|_| {
        let mut error = Error::new("recovery_required");
        error.stage = Some("transport");
        error
    })?
}
