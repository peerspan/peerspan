//! One explicit GET pass, then atomic pending-only owner/selection retention.
use crate::{
    api::blocking,
    decentralized::{self as dec, bootstrap::Frame, codec, controls, requests, storage::Snapshot},
    model::Error,
    onboarding_admission::{Inspect, safe},
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    routing::post,
};
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

fn coded(code: &'static str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
fn unavailable() -> Error {
    coded("incoming_progress_unavailable")
}
fn time(s: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| unavailable())
}
fn record(p: &requests::Pending) -> Result<String, Error> {
    serde_json::to_string(&p.record).map_err(|_| unavailable())
}
fn load(c: &Connection, id: &str) -> Result<requests::Pending, Error> {
    requests::load(c, id).map_err(|e| {
        if e.code == "not_found" {
            Error::NotFound
        } else {
            unavailable()
        }
    })
}
struct Current {
    now: String,
    parent: Value,
    root: String,
}
fn current(
    store: &Store,
    c: &Connection,
    input: &Inspect,
    p: &requests::Pending,
) -> Result<Current, Error> {
    let raw = controls::local_decision_time().map_err(|_| unavailable())?;
    let packet = p.packet().map_err(|_| unavailable())?;
    let created = codec::text(&packet.payload, "created_at").map_err(|_| unavailable())?;
    if time(&raw)? < time(created)?
        || p.record.stage_at != "-" && time(&raw)? < time(&p.record.stage_at)?
    {
        return Err(unavailable());
    }
    let guarded = controls::guarded_decision(c, &p.record.expected_network_id, &raw)
        .map_err(|_| unavailable())?;
    let (parent, attached) = input.context.project(c, time(&guarded)?)?;
    if !attached {
        return Err(coded("review_changed"));
    }
    let r = &p.record;
    if !r.roles.iter().any(|s| s == "administrator")
        || r.roles.iter().any(|s| s == "requester")
        || r.mode != "new"
        || r.migration_proposal_id != "-"
        || r.terminal != "-"
        || r.host_public_key == store.identity().public_key
        || r.selection_approved
        || r.commit_approved
        || [
            &r.owner_intent_id,
            &r.administrator_intent_id,
            &r.selection_intent_id,
            &r.commit_intent_id,
            &r.administrator_offer_id,
            &r.administrator_packet_base64,
            &r.owner_finalization_id,
            &r.owner_finalization_packet_base64,
            &r.commit_packet_base64,
            &r.manifest_id,
            &r.activation_id,
            &r.outcome_packet_base64,
        ]
        .iter()
        .any(|v| v.as_str() != "-")
    {
        return Err(unavailable());
    }
    let snapshot = Snapshot::load(c, &r.expected_network_id, &store.identity().public_key)
        .map_err(|_| unavailable())?;
    if snapshot.descriptor.context_id() != r.expected_context_id
        || !codec::key(&r.expected_person_public_key)
        || snapshot
            .prior
            .maxima
            .contains_key(&vec!["person".into(), r.expected_person_public_key.clone()])
    {
        return Err(unavailable());
    }
    let projection = snapshot.project(&guarded).map_err(|_| unavailable())?;
    let now = projection.decision_time.clone();
    if !input.context.project(c, time(&now)?)?.1 {
        return Err(coded("review_changed"));
    }
    let view = p.view(&now).map_err(|_| unavailable())?;
    if !matches!(
        view["state"].as_str(),
        Some("pending" | "needs_selection" | "needs_administrator")
    ) {
        return Err(unavailable());
    }
    if !requests::frames(c, p)
        .map_err(|_| unavailable())?
        .iter()
        .all(|f| dec::incoming_role(&f.role))
    {
        return Err(unavailable());
    }
    Ok(Current {
        now,
        parent,
        root: projection
            .root_state_id()
            .map_err(|_| unavailable())?
            .into(),
    })
}
fn public(
    store: &Store,
    c: &Connection,
    input: &Inspect,
    p: &requests::Pending,
    state: &Current,
) -> Result<Value, Error> {
    let (now, request, next) = if p.record.owner_offer_id != "-" && p.record.selection_id != "-" {
        let verified = dec::inspect_original_admission(c, store, p).map_err(|_| unavailable())?;
        if !safe(
            &json!({"context":input.context,"agent":state.parent["agent"],"evidence":verified}),
        ) {
            return Err(unavailable());
        }
        (
            verified["observed_at"].clone(),
            verified["request"].clone(),
            "review_administrator_consent",
        )
    } else {
        (
            Value::from(state.now.clone()),
            p.view(&state.now).map_err(|_| unavailable())?,
            if p.record.owner_offer_id == "-" {
                "wait_for_original_owner"
            } else {
                "wait_for_requester_selection"
            },
        )
    };
    let result = json!({"version":1,"host_id":store.identity().id,"context":input.context,
        "observed_at":now,"request":request,"next_action":next});
    if !safe(&result) {
        return Err(unavailable());
    }
    Ok(result)
}
struct Prepared {
    plan: Option<dec::IncomingPlan>,
    cached: Option<Value>,
    record: String,
    root: String,
    agent: Value,
    deadline: String,
    secret: Option<[u8; 16]>,
}
fn prepare(store: &Store, input: &Inspect) -> Result<Prepared, Error> {
    let mut c = store.connection().map_err(|_| unavailable())?;
    let tx = c.transaction().map_err(|_| unavailable())?;
    let p = load(&tx, &input.request_id)?;
    let state = current(store, &tx, input, &p)?;
    // Validate any already cached partial evidence without changing its record.
    let mut shadow = requests::Pending {
        id: p.id.clone(),
        deadline: p.deadline.clone(),
        record: p.record.clone(),
        secret: p.secret,
        terminal_read_cap: p.terminal_read_cap,
    };
    dec::incoming_prefix(&tx, store, &mut shadow, &state.now).map_err(|_| unavailable())?;
    let result = public(store, &tx, input, &p, &state)?;
    let complete = p.record.owner_offer_id != "-" && p.record.selection_id != "-";
    Ok(Prepared {
        plan: if complete {
            None
        } else {
            Some(dec::incoming_plan(&tx, &p).map_err(|_| unavailable())?)
        },
        cached: complete.then_some(result),
        record: record(&p)?,
        root: state.root,
        agent: state.parent["agent"].clone(),
        deadline: p.deadline,
        secret: p.secret,
    })
}
fn retain(
    store: &Store,
    input: Inspect,
    original: Prepared,
    incoming: Vec<Frame>,
    until: Instant,
) -> Result<Value, Error> {
    controls::barrier(
        store,
        "dec.incoming_progress.before_retain",
        &input.request_id,
    )
    .map_err(|_| unavailable())?;
    if Instant::now() >= until {
        return Err(unavailable());
    }
    let mut c = store.connection().map_err(|_| unavailable())?;
    let tx = c.transaction().map_err(|_| unavailable())?;
    let mut p = load(&tx, &input.request_id)?;
    let raw = controls::local_decision_time().map_err(|_| unavailable())?;
    // Parent replacement is checked before operation pins. Actual expiry takes
    // precedence over a cleanup-induced changed record.
    if !input.context.project(&tx, time(&raw)?)?.1 {
        return Err(coded("review_changed"));
    }
    let guarded = controls::guarded_decision(&tx, &p.record.expected_network_id, &raw)
        .map_err(|_| unavailable())?;
    if p.view(&guarded).map_err(|_| unavailable())?["state"] == "expired" {
        return Err(unavailable());
    }
    if record(&p)? != original.record
        || p.deadline != original.deadline
        || p.secret != original.secret
    {
        return Err(coded("review_changed"));
    }
    let state = current(store, &tx, &input, &p)?;
    if state.root != original.root || state.parent["agent"] != original.agent {
        return Err(coded("review_changed"));
    }
    let secret = p.secret.ok_or_else(unavailable)?;
    let mut all = BTreeMap::<(String, String, String), Frame>::new();
    for frame in requests::frames(&tx, &p)
        .map_err(|_| unavailable())?
        .into_iter()
        .chain(incoming)
    {
        if !dec::incoming_role(&frame.role) {
            return Err(unavailable());
        }
        frame.valid_at(&state.now).map_err(|_| unavailable())?;
        frame
            .open_bytes(&secret, &state.now)
            .map_err(|_| unavailable())?;
        let key = (
            frame.role.clone(),
            frame.writer_host_public_key.clone(),
            frame.frame_id.clone(),
        );
        if let Some(old) = all.get(&key) {
            if old.body != frame.body {
                return Err(unavailable());
            }
        } else {
            all.insert(key, frame);
        }
    }
    if all.len() > 64 || all.values().map(|f| f.ciphertext.len()).sum::<usize>() > 32 << 20 {
        return Err(unavailable());
    }
    let mut inserted = 0;
    if Instant::now() >= until {
        return Err(unavailable());
    }
    for frame in all.values() {
        inserted += tx.execute("INSERT INTO dec_frames(request_id,role,writer_key,frame_id,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(request_id,role,writer_key,frame_id) DO NOTHING",
            rusqlite::params![p.id,frame.role,frame.writer_host_public_key,frame.frame_id,json!({"frame_base64":codec::encode(&frame.body)}).to_string()]).map_err(|_|unavailable())?;
    }
    dec::incoming_prefix(&tx, store, &mut p, &state.now).map_err(|_| unavailable())?;
    if inserted > 0 || record(&p)? != original.record {
        requests::save(&tx, &p).map_err(|_| unavailable())?;
    }
    let p = load(&tx, &p.id)?;
    let final_state = current(store, &tx, &input, &p)?;
    if final_state.root != original.root || final_state.parent["agent"] != original.agent {
        return Err(coded("review_changed"));
    }
    let result = public(store, &tx, &input, &p, &final_state)?;
    if Instant::now() >= until {
        return Err(unavailable());
    }
    tx.commit().map_err(|_| unavailable())?;
    Ok(result)
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/onboarding/incoming-progress", post(progress))
}
async fn progress(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let invalid = || Error::Invalid("invalid incoming progress input".into());
    let input = crate::onboarding_admission::decode_input(&body.map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let until = Instant::now() + Duration::from_secs(4);
    let copy = Inspect {
        context: input.context.clone(),
        request_id: input.request_id.clone(),
    };
    let mut prepared = blocking(store.clone(), move |s| prepare(s, &copy)).await?;
    if let Some(result) = prepared.cached.take() {
        return Ok(Json(result));
    }
    if Instant::now() >= until {
        return Err(unavailable());
    }
    let frames = dec::fetch_incoming(store.clone(), prepared.plan.take().ok_or_else(unavailable)?)
        .await
        .map_err(|_| unavailable())?;
    Ok(Json(
        blocking(store, move |s| retain(s, input, prepared, frames, until)).await?,
    ))
}
