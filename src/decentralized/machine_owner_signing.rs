//! Bounded initial typed owner/fold signatures under exact durable project consent.
use super::{
    ceremony,
    codec::*,
    controls,
    intents::FixedObject,
    machine_owner_consent as consent,
    provider::Resolved,
    requests::{self, Pending},
    storage::Snapshot,
    transcript::Packet,
};
use crate::{
    model::Error as HostError,
    onboarding_machine::Inspect,
    onboarding_machine_consent::Input,
    onboarding_machine_signing::{dec, unavailable},
    persons::PersonSigner,
    store::Store,
};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Instant};

type HostResult<T> = std::result::Result<T, HostError>;
#[derive(Clone, PartialEq, Eq)]
struct Slot {
    id: u64,
    role: String,
    object_type: String,
    object_id: String,
    key: String,
    format: String,
    message: Vec<u8>,
}
struct Plan {
    slots: Vec<Slot>,
    needed: Vec<usize>,
    provider_kind: String,
    provider_key: String,
    device_seed: Option<[u8; 32]>,
}
impl Plan {
    fn same(&self, other: &Self) -> bool {
        self.slots == other.slots
            && self.provider_kind == other.provider_kind
            && self.provider_key == other.provider_key
            && self.device_seed == other.device_seed
    }
}
struct Produced {
    slot: usize,
    signature: String,
}
enum Attempt {
    Done(Value),
    Work(Plan),
}
fn budget(until: Instant) -> HostResult<()> {
    if Instant::now() >= until {
        Err(unavailable())
    } else {
        Ok(())
    }
}
fn safe(v: Value) -> HostResult<Value> {
    if !crate::onboarding_admission::safe(&v)
        || serde_json::to_vec(&v).map_err(|_| unavailable())?.len() > 2 << 20
    {
        Err(unavailable())
    } else {
        Ok(v)
    }
}
struct Slots {
    all: Vec<Slot>,
    needed: Vec<usize>,
}
// Only initially unsigned typed templates declare work. The ordinary loader
// verifies all existing signatures, including later history; none is inferred
// from a receipt flag, nor does this plan include later B/D/F slots.
fn slots(store: &Store, p: &Pending, r: &consent::Receipt) -> Result<Slots> {
    let identity = store.identity();
    let d = ceremony::descriptor(p)?;
    let i = &r.owner;
    let objects = i.objects(&d)?;
    let fold = r.review["effects"]["authorize_host_admission_if_folded"] == true;
    let count = if fold { 2 } else { 1 };
    let mut all = Vec::new();
    let mut needed = Vec::new();
    for (index, t) in i.record.templates.iter().enumerate().take(count) {
        require(
            t.slot_id == index as u64 + 1
                && t.object_type
                    == if index == 0 {
                        "owner_offer_packet"
                    } else {
                        "host_lease"
                    },
            "state_conflict",
        )?;
        let fixed = FixedObject::read(&d, &t.object_type, &b64(&t.template_base64, MAX_OBJECT)?)?;
        let baseline = fixed.pending()?;
        require(
            baseline.len() == if index == 0 { 2 } else { 1 },
            "state_conflict",
        )?;
        let actual = objects
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(|| Error::new("state_conflict"))?;
        let pending = actual.pending()?;
        for s in baseline {
            let host = index == 0 && s.role == "host";
            require(
                (host || s.role == if index == 0 { "authority" } else { "issuer" })
                    && s.object_type == t.object_type
                    && s.public_key
                        == if host {
                            identity.public_key.as_str()
                        } else {
                            i.record.provider.signer_public_key.as_str()
                        }
                    && s.signature_format
                        == if host {
                            "ed25519"
                        } else {
                            i.record.provider.signature_format.as_str()
                        },
                "state_conflict",
            )?;
            let item = Slot {
                id: t.slot_id,
                role: s.role.clone(),
                object_type: s.object_type.clone(),
                object_id: s.statement_id.clone(),
                key: s.public_key.clone(),
                format: s.signature_format.clone(),
                message: b64(&s.message_base64, 4096)?,
            };
            if pending.iter().any(|v| v.role == s.role) {
                needed.push(all.len());
            }
            all.push(item);
        }
        if index == 0 {
            let packet = Packet::read_template(fixed.bytes())?;
            require(
                packet.id == r.review["proposed_owner_offer_id"],
                "state_conflict",
            )?;
            if pending.is_empty() {
                Packet::read(actual.bytes())?;
                require(
                    p.record.owner_packet_base64 == encode(actual.bytes())
                        && p.record.owner_offer_id == packet.id,
                    "state_conflict",
                )?;
            } else {
                require(
                    p.record.owner_packet_base64 == "-" && p.record.owner_offer_id == "-",
                    "state_conflict",
                )?;
            }
        }
    }
    require(all.len() == if fold { 3 } else { 2 }, "state_conflict")?;
    Ok(Slots { all, needed })
}
fn deadlines(p: &Pending, r: &consent::Receipt, now: &str) -> Result<()> {
    require(now >= r.meta.record.created_at.as_str(), "review_changed")?;
    require(
        now < r.meta.record.expires_at.as_str()
            && now < text(object(&r.review)?, "request_stage_deadline")?
            && now < p.deadline.as_str()
            && now < r.owner.record.not_after.as_str(),
        "review_expired",
    )?;
    Ok(())
}
fn public_live(
    c: &Connection,
    store: &Store,
    input: &Input,
    p: &Pending,
    r: &consent::Receipt,
    now: &str,
) -> Result<()> {
    require(
        r.meta.record.approved
            && r.owner.record.approved
            && r.meta.record.approved_at == r.owner.record.approved_at,
        "machine_owner_signing_unavailable",
    )?;
    require(
        consent::latest(c, store, p)?.as_deref() == Some(r.meta.id.as_str()),
        "review_changed",
    )?;
    deadlines(p, r, now)?;
    require(
        r.owner.record.terminal == "-"
            && !r.owner.record.completed
            && ceremony::read_review(&r.owner)?["stage"] == "owner",
        "review_changed",
    )?;
    let v = crate::onboarding_machine::inspect_signing_in(
        c,
        store,
        &Inspect {
            context: input.context.clone(),
            request_id: p.id.clone(),
        },
        p,
        now,
    )
    .map_err(|_| Error::new("review_changed"))?;
    require(
        v["review_id"] == r.review["inspection_review_id"]
            && v["review"] == r.review["inspection"]
            && ceremony::read_review(&r.owner)?["provider"] == r.review["inspection"]["provider"],
        "review_changed",
    )?;
    Ok(())
}
fn marker(
    c: &Connection,
    store: &Store,
    input: &Input,
    p: &Pending,
    r: &consent::Receipt,
    now: &str,
    slots: &Slots,
) -> Result<Value> {
    if !r.meta.record.approved {
        return Ok(Value::Null);
    }
    let count = slots.all.len() - slots.needed.len();
    let signed = slots.needed.is_empty();
    let can_sign = !signed && public_live(c, store, input, p, r, now).is_ok();
    Ok(
        json!({"state":if signed {"signed"}else if count==0 {"unsigned"}else{"partial"},
        "intent_id":r.owner.id,"proposed_owner_offer_id":r.review["proposed_owner_offer_id"],
        "signature_count":count,"required_signatures":slots.all.len(),"can_sign":can_sign,
        "next_action":if can_sign {"sign_machine_owner_offer"}else if signed {"follow_machine_link"}else{"inspect_machine_link"},
        "owner_offer_publication":"not_verified","host_admission":"not_verified","machine_powers":"not_verified",
        "requester_selection":"not_verified","request_commit":"not_verified","agent_access":"not_verified","connection_readiness":"not_verified"}),
    )
}
fn response(
    c: &Connection,
    store: &Store,
    input: &Input,
    p: &Pending,
    r: &consent::Receipt,
    now: &str,
    slots: &Slots,
) -> HostResult<Value> {
    let latest = consent::latest(c, store, p).map_err(dec)?;
    let mut v =
        consent::wrapper(c, store, input, p, Some(r), latest.as_deref(), now).map_err(dec)?;
    v["signing"] = marker(c, store, input, p, r, now, slots).map_err(dec)?;
    safe(v)
}
fn attempt(
    store: &Store,
    input: &Input,
    until: Option<Instant>,
    produced: Option<(&Plan, &[Produced])>,
) -> HostResult<Attempt> {
    let mut c = store.connection().map_err(|_| unavailable())?;
    let tx = c.transaction().map_err(|_| unavailable())?;
    let mut p = requests::load(&tx, &input.request_id).map_err(dec)?;
    let raw = controls::local_decision_time().map_err(dec)?;
    let now = controls::guarded_decision(&tx, &p.record.expected_network_id, &raw).map_err(dec)?;
    let id = input.consent_id.as_deref().ok_or_else(unavailable)?;
    let mut r = consent::load(&tx, store, &p, id, &now).map_err(dec)?;
    require(
        input.consent_review_id.as_deref() == Some(consent::review_id(&r.review).as_str())
            && r.review["context"] == json!(input.context),
        "review_changed",
    )
    .map_err(dec)?;
    let observed = slots(store, &p, &r).map_err(dec)?;
    let result = response(&tx, store, input, &p, &r, &now, &observed)?;
    // Complete typed history and status observation have no key-resolution or
    // live-authority work, no clock save and no commit.
    if until.is_none() || r.meta.record.approved && observed.needed.is_empty() {
        return Ok(Attempt::Done(result));
    }
    let until = until.ok_or_else(unavailable)?;
    budget(until)?;
    public_live(&tx, store, input, &p, &r, &now).map_err(dec)?;
    ceremony::validate_owner_live(&tx, store, &p, &r.owner)
        .map_err(|_| dec(Error::new("review_changed")))?;
    let snapshot =
        Snapshot::load(&tx, &r.owner.network_id, &store.identity().public_key).map_err(dec)?;
    let projection = snapshot.project(&now).map_err(dec)?;
    let provider = &r.owner.record.provider;
    let resolved = Resolved::resolve(
        &tx,
        &snapshot,
        &projection,
        if provider.kind == "device" {
            &provider.lease_id
        } else {
            &provider.signer_public_key
        },
        &provider.signature_format,
        "device_lease",
    )
    .map_err(|_| unavailable())?;
    let actual_provider = serde_json::to_value(&resolved.provider).map_err(|_| unavailable())?;
    let recorded_provider = serde_json::to_value(provider).map_err(|_| unavailable())?;
    let public_provider = resolved
        .public(&projection, &store.identity().public_key, false)
        .map_err(dec)?;
    require(
        actual_provider == recorded_provider
            && public_provider == r.review["inspection"]["provider"],
        "review_changed",
    )
    .map_err(dec)?;
    let plan = Plan {
        slots: observed.all,
        needed: observed.needed,
        provider_kind: provider.kind.clone(),
        provider_key: provider.signer_public_key.clone(),
        device_seed: resolved.seed,
    };
    let Some((previous, signatures)) = produced else {
        return Ok(Attempt::Work(plan));
    };
    require(previous.same(&plan), "review_changed").map_err(dec)?;
    let mut seen = BTreeSet::new();
    for v in signatures {
        require(
            v.slot < plan.slots.len() && seen.insert(v.slot),
            "machine_owner_signing_unavailable",
        )
        .map_err(dec)?;
    }
    require(
        plan.needed.iter().all(|index| seen.contains(index)),
        "machine_owner_signing_unavailable",
    )
    .map_err(dec)?;
    for index in &plan.needed {
        let s = &plan.slots[*index];
        let signature = &signatures
            .iter()
            .find(|v| v.slot == *index)
            .ok_or_else(unavailable)?
            .signature;
        let object = r
            .owner
            .objects(&snapshot.descriptor)
            .map_err(dec)?
            .remove(s.id as usize - 1)
            .ok_or_else(unavailable)?;
        object
            .fill(&snapshot.descriptor, &s.role, signature)
            .map_err(|_| unavailable())?;
        ceremony::add(&mut r.owner, s.id, &s.role, signature).map_err(dec)?;
    }
    let first = r
        .owner
        .objects(&snapshot.descriptor)
        .map_err(dec)?
        .remove(0)
        .ok_or_else(unavailable)?;
    require(
        first.pending().map_err(dec)?.is_empty(),
        "machine_owner_signing_unavailable",
    )
    .map_err(dec)?;
    let packet = Packet::read(first.bytes()).map_err(dec)?;
    p.record.owner_packet_base64 = encode(first.bytes());
    p.record.owner_offer_id = packet.id;
    p.record.catalog_base64 = encode(&projection.catalog.bytes);
    let final_slots = slots(store, &p, &r).map_err(dec)?;
    require(
        final_slots.needed.is_empty(),
        "machine_owner_signing_unavailable",
    )
    .map_err(dec)?;
    budget(until)?;
    r.owner.save(&tx).map_err(dec)?;
    requests::save(&tx, &p).map_err(dec)?;
    let result = response(&tx, store, input, &p, &r, &now, &final_slots)?;
    // Assembly, verification and response construction may cross a fixed wall
    // deadline even while the separate action budget remains live. Refresh it
    // after that work; expiry rolls back the whole new batch and packet pins.
    let commit_raw = controls::local_decision_time().map_err(dec)?;
    let commit_now =
        controls::guarded_decision(&tx, &r.owner.network_id, &commit_raw).map_err(dec)?;
    deadlines(&p, &r, &commit_now).map_err(dec)?;
    controls::remember_decision(&tx, &r.owner.network_id, &commit_now).map_err(dec)?;
    budget(until)?;
    tx.commit().map_err(|_| unavailable())?;
    Ok(Attempt::Done(result))
}
fn produce(
    store: &Store,
    plan: &Plan,
    signer: Option<&PersonSigner>,
    index: usize,
    until: Instant,
) -> HostResult<Produced> {
    budget(until)?;
    let s = &plan.slots[index];
    let signature = if s.id == 1 && s.role == "host" {
        encode(&store.signing_key.sign(&s.message).to_bytes())
    } else if plan.provider_kind == "device" && s.format == "ed25519" && s.key == plan.provider_key
    {
        let seed = plan.device_seed.ok_or_else(unavailable)?;
        encode(&SigningKey::from_bytes(&seed).sign(&s.message).to_bytes())
    } else if plan.provider_kind == "original" && s.format == "sshsig" && s.key == plan.provider_key
    {
        let text = std::str::from_utf8(&s.message).map_err(|_| unavailable())?;
        signer
            .ok_or_else(unavailable)?
            .sign(&text.split('\n').collect::<Vec<_>>())
            .map_err(|_| unavailable())?
    } else {
        return Err(unavailable());
    };
    budget(until)?;
    Ok(Produced {
        slot: index,
        signature,
    })
}
pub(crate) fn run(store: &Store, input: &Input, until: Option<Instant>) -> HostResult<Value> {
    let first = match attempt(store, input, until, None)? {
        Attempt::Done(v) => return Ok(v),
        Attempt::Work(p) => p,
    };
    let until = until.ok_or_else(unavailable)?;
    budget(until)?;
    let needs_original = first
        .needed
        .iter()
        .any(|i| first.slots[*i].format == "sshsig");
    let signer = if needs_original {
        let key = b64(&first.provider_key, 32)
            .map_err(dec)?
            .try_into()
            .map_err(|_| unavailable())?;
        Some(
            super::project_access_signing::original_signer(store, key, until)
                .map_err(|_| unavailable())?,
        )
    } else {
        None
    };
    // Identity lookup/key-source validation ran outside SQLite. Observe current
    // consent/authority and exact unchanged messages before any signing call.
    let current = match attempt(store, input, Some(until), None)? {
        Attempt::Done(v) => return Ok(v),
        Attempt::Work(p) => p,
    };
    require(
        first.same(&current) && current.needed.iter().all(|i| first.needed.contains(i)),
        "review_changed",
    )
    .map_err(dec)?;
    let mut signatures = Vec::new();
    for index in &current.needed {
        // A previous agent call may have blocked while public authority or the
        // project changed. Recheck the entire immutable plan before every key
        // dispatch, retaining roles another approved worker already completed.
        let fresh = match attempt(store, input, Some(until), None)? {
            Attempt::Done(v) => return Ok(v),
            Attempt::Work(p) => p,
        };
        require(
            current.same(&fresh) && fresh.needed.iter().all(|i| current.needed.contains(i)),
            "review_changed",
        )
        .map_err(dec)?;
        if fresh.needed.contains(index) {
            signatures.push(produce(store, &fresh, signer.as_ref(), *index, until)?);
        }
    }
    match attempt(store, input, Some(until), Some((&current, &signatures)))? {
        Attempt::Done(v) => Ok(v),
        Attempt::Work(_) => Err(unavailable()),
    }
}
