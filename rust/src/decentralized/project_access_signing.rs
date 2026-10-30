//! Store only the fixed issuer signature authorized by both consent records.
use super::{
    actions, codec::*, controls, project_access_consent as consent, provider::Resolved,
    storage::Snapshot, template::FixedStatement,
};
use crate::{
    model::Error as HostError,
    onboarding_access_consent::Input,
    onboarding_access_signing::{dec, unavailable},
    persons::PersonSigner,
    store::Store,
};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    time::Instant,
};

type HostResult<T> = std::result::Result<T, HostError>;
#[derive(PartialEq, Eq)]
struct Plan {
    key: [u8; 32],
    message: Vec<u8>,
}
enum Attempt {
    Done(Value),
    External(Plan),
}
fn budget(until: Instant) -> HostResult<()> {
    if Instant::now() >= until {
        Err(unavailable())
    } else {
        Ok(())
    }
}
fn safe(value: Value) -> HostResult<Value> {
    if !crate::onboarding_admission::safe(&value)
        || serde_json::to_vec(&value).map_err(|_| unavailable())?.len() > 1 << 20
    {
        return Err(unavailable());
    }
    Ok(value)
}
fn marker(c: &Connection, input: &Input, r: &consent::Receipt) -> Result<Value> {
    if !r.meta.record.approved {
        return Ok(Value::Null);
    }
    let d = actions::descriptor(c, &input.network_id)?;
    let fixed = FixedStatement::read(
        &d,
        &b64(&r.action.record.templates[0].template_base64, MAX_OBJECT)?,
    )?;
    let slots = fixed.pending();
    require(slots.len() == 1, "access_signing_unavailable")?;
    let slot = &slots[0];
    let provider = &r.action.record.provider;
    require(
        slot.role == "issuer"
            && slot.object_type == "policy"
            && slot.public_key == provider.signer_public_key
            && slot.signature_format == provider.signature_format,
        "access_signing_unavailable",
    )?;
    let assembled = r.action.assembled(&d)?.remove(0);
    let count = r.action.record.signatures.len();
    require(
        count <= 1
            && r.action.record.completed == assembled.pending().is_empty()
            && r.action.record.completed == (count == 1),
        "access_signing_unavailable",
    )?;
    Ok(json!({"state":if count == 1 {"signed"} else {"unsigned"},
        "action_id":r.action.record.operation_id,"intent_id":r.action.id,
        "statement_id":fixed.statement_id(),"signature_count":count,"required_signatures":1,
        "policy_application":"not_verified","peer_delivery":"not_verified",
        "connection_readiness":"not_verified"}))
}
fn response(
    store: &Store,
    input: &Input,
    now: &str,
    access: &Value,
    signing: Value,
) -> HostResult<Value> {
    safe(
        json!({"version":1,"host_id":store.identity().id,"context":input.context,
        "observed_at":now,"access":access,"signing":signing}),
    )
}

/// Every phase captures its own coherent time and authority snapshot. External
/// key lookup and signing happen only after this function drops the transaction.
fn attempt(
    store: &Store,
    input: &Input,
    until: Option<Instant>,
    signature: Option<&str>,
) -> HostResult<Attempt> {
    let mut c = store.connection().map_err(|_| unavailable())?;
    let tx = c.transaction().map_err(|_| unavailable())?;
    // Resolve a genuinely missing requested network separately from damaged
    // references inside an otherwise retained receipt.
    actions::descriptor(&tx, &input.network_id).map_err(dec)?;
    let raw = controls::local_decision_time().map_err(dec)?;
    let now = controls::guarded_decision(&tx, &input.network_id, &raw).map_err(dec)?;
    let time = chrono::DateTime::parse_from_rfc3339(&now)
        .map_err(|_| unavailable())?
        .with_timezone(&chrono::Utc);
    let (parent, attached) = input.context.project(&tx, time)?;
    let id = input.access_id.as_deref().ok_or_else(unavailable)?;
    let mut r = consent::load(&tx, store, input, &parent, id, &raw).map_err(dec)?;
    require(
        input.access_review_id.as_deref() == Some(consent::review_id(&r.review).as_str()),
        "review_changed",
    )
    .map_err(dec)?;
    let access = consent::view(&tx, store, input, &r, &parent, attached, &now).map_err(dec)?;
    let signing = marker(&tx, input, &r).map_err(dec)?;
    let result = response(store, input, &now, &access, signing.clone())?;
    // Verified history is pure: no key lookup, eligibility refresh or clock write.
    if until.is_none() || signing["state"] == "signed" {
        return Ok(Attempt::Done(result));
    }
    let until = until.ok_or_else(unavailable)?;
    budget(until)?;
    require(r.meta.record.approved, "access_signing_unavailable").map_err(dec)?;
    require(
        consent::latest(&tx, input).map_err(dec)?.as_deref() == Some(id),
        "review_changed",
    )
    .map_err(dec)?;
    consent::live(&tx, store, input, &r, &parent, attached, &now).map_err(|e| {
        if matches!(e.code, "review_changed" | "review_expired") {
            dec(e)
        } else {
            unavailable()
        }
    })?;
    let s = Snapshot::load(&tx, &input.network_id, &store.identity().public_key).map_err(dec)?;
    let p = s.project(&now).map_err(dec)?;
    let resolved =
        Resolved::resolve(&tx, &s, &p, "auto", "auto", "policy").map_err(|_| unavailable())?;
    let fixed = FixedStatement::read(
        &s.descriptor,
        &b64(&r.action.record.templates[0].template_base64, MAX_OBJECT).map_err(dec)?,
    )
    .map_err(dec)?;
    let slots = fixed.pending();
    let slot = slots
        .first()
        .filter(|_| slots.len() == 1)
        .ok_or_else(unavailable)?;
    let message = b64(&slot.message_base64, 4096).map_err(dec)?;
    budget(until)?;
    let sig = if let Some(sig) = signature {
        require(
            resolved.provider.kind == "original",
            "access_signing_unavailable",
        )
        .map_err(dec)?;
        sig.to_owned()
    } else if resolved.provider.kind == "device" {
        let seed = resolved.seed.ok_or_else(unavailable)?;
        encode(&SigningKey::from_bytes(&seed).sign(&message).to_bytes())
    } else {
        require(
            resolved.provider.kind == "original" && slot.signature_format == "sshsig",
            "access_signing_unavailable",
        )
        .map_err(dec)?;
        let key = b64(&slot.public_key, 32)
            .map_err(dec)?
            .try_into()
            .map_err(|_| unavailable())?;
        return Ok(Attempt::External(Plan { key, message }));
    };
    let filled = fixed
        .fill(&s.descriptor, "issuer", &sig)
        .map_err(|_| unavailable())?;
    require(filled.pending().is_empty(), "access_signing_unavailable").map_err(dec)?;
    actions::add_signature(&mut r.action, "issuer", &sig).map_err(dec)?;
    r.action.record.completed = true;
    let result = response(
        store,
        input,
        &now,
        &access,
        marker(&tx, input, &r).map_err(dec)?,
    )?;
    budget(until)?;
    actions::remember_clock(&tx, &input.network_id, &now).map_err(dec)?;
    r.action.save(&tx).map_err(dec)?;
    budget(until)?;
    tx.commit().map_err(|_| unavailable())?;
    Ok(Attempt::Done(result))
}

/// Only the daemon's configured exact original key is eligible. A device seed
/// failure never reaches this fallback, and no global agent discovery is used.
fn original_signer(store: &Store, key: [u8; 32], until: Instant) -> HostResult<PersonSigner> {
    budget(until)?;
    let socket = store
        .person_agent
        .read()
        .map_err(|_| unavailable())?
        .clone();
    if let Some(socket) = socket {
        let signer = PersonSigner::agent_at(socket, key);
        budget(until)?;
        if let Ok(signer) = signer {
            return Ok(signer);
        }
    }
    let path = store
        .person_key_file
        .read()
        .map_err(|_| unavailable())?
        .clone()
        .ok_or_else(unavailable)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| unavailable())?;
    let meta = file.metadata().map_err(|_| unavailable())?;
    // O_NONBLOCK prevents a configured FIFO from blocking before fstat.
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() > 16384
    {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > 16384 {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| unavailable())?;
    let signer = PersonSigner::File(
        crate::persons::parse_openssh_private_key(text).map_err(|_| unavailable())?,
    );
    if signer.public_key() != key {
        return Err(unavailable());
    }
    budget(until)?;
    Ok(signer)
}
pub(crate) fn run(store: &Store, input: &Input, until: Option<Instant>) -> HostResult<Value> {
    let plan = match attempt(store, input, until, None)? {
        Attempt::Done(v) => return Ok(v),
        Attempt::External(plan) => plan,
    };
    let until = until.ok_or_else(unavailable)?;
    let signer = original_signer(store, plan.key, until)?;
    // Recheck all fresh guards after external identity lookup and before asking
    // an SSH agent to sign. Neither phase holds the database connection over IO.
    match attempt(store, input, Some(until), None)? {
        Attempt::Done(v) => return Ok(v),
        Attempt::External(current) if current == plan => {}
        _ => return Err(unavailable()),
    }
    budget(until)?;
    let text = std::str::from_utf8(&plan.message).map_err(|_| unavailable())?;
    let sig = signer
        .sign(&text.split('\n').collect::<Vec<_>>())
        .map_err(|_| unavailable())?;
    budget(until)?;
    match attempt(store, input, Some(until), Some(&sig))? {
        Attempt::Done(v) => Ok(v),
        Attempt::External(_) => Err(unavailable()),
    }
}
