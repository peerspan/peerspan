//! Exact guided policy application in one ordinary local transaction.
use super::{
    actions,
    codec::*,
    controls, edits, project_access_consent as consent,
    storage::{self, Snapshot},
    views,
};
use crate::{
    model::Error as HostError,
    onboarding_access_application::{dec, unavailable},
    onboarding_access_consent::Input,
    store::Store,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::time::Instant;

type HostResult<T> = std::result::Result<T, HostError>;
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
    let fixed = r.action.assembled(&d)?.remove(0);
    let signed = fixed.signed(&d)?;
    require(
        r.action.record.completed == signed.is_some()
            && r.action.record.signatures.len() == usize::from(signed.is_some()),
        "access_application_unavailable",
    )?;
    if r.action.record.terminal == "applied" {
        let signed = signed
            .as_ref()
            .ok_or_else(|| Error::new("access_application_unavailable"))?;
        // The action loader verified its exact normal result and historical
        // signature closure. Require its actual retained local evidence too;
        // a result alone cannot recreate a removed admission or proof.
        let (kind, body): (String, Vec<u8>) = c.query_row(
            "SELECT kind,body FROM dec_objects WHERE network_id=?1 AND context_id=?2 AND proof_id=?3",
            rusqlite::params![input.network_id, d.context_id(), signed.proof_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|_| Error::new("access_application_unavailable"))?;
        let record: String = c.query_row(
            "SELECT record FROM dec_admissions WHERE network_id=?1 AND context_id=?2 AND statement_id=?3",
            rusqlite::params![input.network_id, d.context_id(), signed.id], |row| row.get(0),
        ).map_err(|_| Error::new("access_application_unavailable"))?;
        let admission = storage::marker(&record, false)?;
        let basis = object(
            admission
                .get("basis")
                .ok_or_else(|| Error::new("access_application_unavailable"))?,
        )?;
        let evidence = array(basis, "evidence_ids")?;
        let mut required: Vec<_> = signed.parents()?.into_values().collect();
        required.extend([
            signed.id.clone(),
            text(&signed.payload, "root_state_id")?.to_owned(),
        ]);
        require(
            kind == "policy"
                && signed.kind == kind
                && body == signed.body
                && text(&admission, "kind")? == "policy"
                && text(&admission, "proof_id")? == signed.proof_id
                && text(&admission, "admitted_at")? >= r.action.record.created_at.as_str()
                && required.iter().all(|id| {
                    evidence
                        .iter()
                        .any(|value| value.as_str() == Some(id.as_str()))
                }),
            "access_application_unavailable",
        )?;
    }
    Ok(
        json!({"state":if r.action.record.terminal == "applied" {"locally_applied"} else if signed.is_some() {"signed"} else {"unsigned"},
        "action_id":r.action.record.operation_id,"intent_id":r.action.id,
        "statement_id":fixed.statement_id(),"proof_id":signed.as_ref().map(|s|s.proof_id.as_str()).unwrap_or("-"),
        "peer_delivery":"not_verified","connection_readiness":"not_verified"}),
    )
}
fn response(
    store: &Store,
    input: &Input,
    now: &str,
    access: &Value,
    application: Value,
) -> HostResult<Value> {
    safe(
        json!({"version":1,"host_id":store.identity().id,"context":input.context,
        "observed_at":now,"access":access,"application":application}),
    )
}
pub(crate) fn run(store: &Store, input: &Input, until: Option<Instant>) -> HostResult<Value> {
    let mut c = store.connection().map_err(|_| unavailable())?;
    let mut tx = c.transaction().map_err(|_| unavailable())?;
    actions::descriptor(&tx, &input.network_id).map_err(dec)?;
    let raw = controls::local_decision_time().map_err(dec)?;
    let now = controls::guarded_decision(&tx, &input.network_id, &raw).map_err(dec)?;
    let time = chrono::DateTime::parse_from_rfc3339(&now)
        .map_err(|_| unavailable())?
        .with_timezone(&chrono::Utc);
    let (parent, attached) = input.context.project(&tx, time).map_err(|e| match e {
        HostError::NotFound
        | HostError::Coded {
            code: "review_changed",
            ..
        } => e,
        _ => unavailable(),
    })?;
    let id = input.access_id.as_deref().ok_or_else(unavailable)?;
    let mut r = consent::load(&tx, store, input, &parent, id, &raw).map_err(dec)?;
    require(
        input.access_review_id.as_deref() == Some(consent::review_id(&r.review).as_str()),
        "review_changed",
    )
    .map_err(dec)?;
    let access = consent::view(&tx, store, input, &r, &parent, attached, &now).map_err(dec)?;
    let application = marker(&tx, input, &r).map_err(dec)?;
    if until.is_none() || application["state"] == "locally_applied" {
        return response(store, input, &now, &access, application);
    }
    let until = until.ok_or_else(unavailable)?;
    budget(until)?;
    require(r.meta.record.approved, "review_changed").map_err(dec)?;
    require(
        consent::latest(&tx, input).map_err(dec)?.as_deref() == Some(id),
        "review_changed",
    )
    .map_err(dec)?;
    require(
        application["state"] == "signed",
        "access_application_unavailable",
    )
    .map_err(dec)?;
    consent::live_application(&tx, store, input, &r, &parent, attached, &now).map_err(dec)?;
    let s = Snapshot::load(&tx, &input.network_id, &store.identity().public_key).map_err(dec)?;
    let p = s.project(&now).map_err(dec)?;
    let fixed = r.action.assembled(&s.descriptor).map_err(dec)?.remove(0);
    let signed = fixed
        .signed(&s.descriptor)
        .map_err(dec)?
        .ok_or_else(unavailable)?;
    let catalog = actions::candidate(&p, &signed.kind, &signed.body).map_err(dec)?;
    budget(until)?;
    let applied = s
        .apply_catalog(&mut tx, &catalog, &now, "fresh")
        .map_err(dec)?;
    require(
        applied.admitted.contains(&signed.id),
        "access_application_unavailable",
    )
    .map_err(dec)?;
    edits::settle(&tx, &p, &applied, &signed, &store.identity().public_key).map_err(dec)?;
    let delivery = views::delivery(&tx, &input.network_id, &s.network.context_id).map_err(dec)?;
    let result = actions::bytes(&json!({"action_id":r.action.record.operation_id,"review":actions::review(&r.action).map_err(dec)?,
        "signing_requests":[],"statement_base64":encode(&signed.body),"proof_id":signed.proof_id,
        "catalog":parse(&applied.catalog.bytes,MAX_CATALOG).map_err(dec)?,"committed":true,"delivery":delivery})).map_err(dec)?;
    r.action.record.terminal = "applied".into();
    r.action.record.result_base64 = encode(&result);
    r.action.save(&tx).map_err(dec)?;
    crate::store::append_event(&tx, "network.action_applied", &input.network_id, &now)
        .map_err(|_| unavailable())?;
    // Validate our normal retained result before committing any policy/queue
    // change. A failure below drops the entire ordinary transaction.
    actions::validate(&r.action, &s.descriptor).map_err(dec)?;
    let result = response(
        store,
        input,
        &now,
        &access,
        marker(&tx, input, &r).map_err(dec)?,
    )?;
    budget(until)?;
    tx.commit().map_err(|_| unavailable())?;
    Ok(result)
}
