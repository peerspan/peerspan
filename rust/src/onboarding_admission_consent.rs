//! Exact public approval of one retained ordinary root administrator intent.
use crate::{
    api::blocking,
    canonical,
    decentralized::{codec, consent_in, consent_live, consent_proposal, controls, requests},
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
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    context: crate::onboarding_adapter::AdapterContext,
    request_id: String,
    admission_review_id: String,
}
fn invalid() -> Error {
    Error::Invalid("invalid administrator admission consent input".into())
}
fn coded(code: &'static str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
fn unavailable() -> Error {
    coded("admission_review_unavailable")
}
fn dec_error(e: codec::Error) -> Error {
    match e.code {
        "review_changed" | "review_expired" => coded(e.code),
        _ => unavailable(),
    }
}
pub fn decode_input(bytes: &[u8], operation: &str) -> Result<Value, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let fields = match operation {
        "lookup" | "prepare" => "context request_id",
        "approve" => "context request_id admission_review_id",
        _ => return Err(invalid()),
    };
    let value: Value = crate::linking::decode_mutation(bytes, fields).map_err(|_| invalid())?;
    if operation == "approve" {
        let a: Approval = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        Inspect {
            context: a.context,
            request_id: a.request_id,
        }
        .validate()
        .map_err(|_| invalid())?;
        if !crate::peer_store::valid_id(&a.admission_review_id, "review", 32) {
            return Err(invalid());
        }
    } else {
        let input: Inspect = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        input.validate().map_err(|_| invalid())?;
    }
    Ok(value)
}
fn time(s: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| unavailable())
}
fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v[key].as_str().ok_or_else(unavailable)
}
fn observed(c: &Connection, p: &requests::Pending) -> Result<DateTime<Utc>, Error> {
    time(
        &controls::guarded_decision(
            c,
            &p.record.expected_network_id,
            &controls::local_decision_time().map_err(dec_error)?,
        )
        .map_err(dec_error)?,
    )
}
fn digest(review: &Value) -> String {
    format!(
        "review_{}",
        hex::encode(Sha256::digest(format!(
            "peerspan-onboarding-original-admission-review-v1\n{}",
            canonical::value_text(review)
        )))
    )
}
fn review(
    store: &Store,
    input: &Inspect,
    parent: &Value,
    request: &Value,
    proposal: &Value,
) -> Result<Value, Error> {
    let expires = time(field(proposal, "expires_at")?)?
        .min(time(field(proposal, "created_at")?)? + TimeDelta::minutes(15));
    Ok(
        json!({"version":1,"kind":"approve_new_original_admission","host_id":store.identity().id,
        "context":input.context,"agent":parent["agent"],"network":proposal["network"],
        "request_id":input.request_id,"request_packet_id":request["request_packet_id"],
        "owner_offer_id":proposal["owner_offer_id"],"selection_id":proposal["selection_id"],
        "intent_id":proposal["intent_id"],"root_state_id":proposal["root_state_id"],
        "root_public_key":proposal["root_public_key"],"person_lease_id":proposal["person_lease_id"],
        "host_lease_id":proposal["host_lease_id"],"member":proposal["member"],
        "person_public_key":proposal["person_public_key"],"host_public_key":proposal["host_public_key"],
        "device_public_key":proposal["device_public_key"],"scopes":7,"not_after":proposal["not_after"],
        "request_created_at":request["created_at"],"request_expires_at":request["expires_at"],
        "created_at":proposal["created_at"],"expires_at":stamp(expires),
        "effects":{"approve_administrator_intent":true,"authorize_network_root_signature":true,
        "authorize_host_packet_signature":true,"publish_administrator_offer_after_signatures":true,
        "grant_membership":false,"grant_agent_access":false,"authorize_original_finalization":false,
        "commit_request":false,"share_files":false,"share_conversation":false,"capability_calls":false}}),
    )
}
fn response(
    store: &Store,
    c: &Connection,
    input: &Inspect,
    p: &requests::Pending,
    now: DateTime<Utc>,
) -> Result<Value, Error> {
    let (parent, attached) = input.context.project(c, now)?;
    let request = p.view(&stamp(now)).map_err(dec_error)?;
    if now < time(field(&request, "created_at")?)? {
        return Err(unavailable());
    }
    let admission = if p.record.administrator_intent_id == "-" {
        Value::Null
    } else {
        let proposal = consent_proposal(c, p).map_err(dec_error)?;
        if now < time(field(&proposal, "created_at")?)? {
            return Err(unavailable());
        }
        let review = review(store, input, &parent, &request, &proposal)?;
        let state = if proposal["approved"] == true {
            "approved"
        } else if request["state"] == "cancelled" || proposal["terminal"] == "cancelled" {
            "cancelled"
        } else if request["state"] == "expired"
            || proposal["terminal"] == "expired"
            || now >= time(field(&review, "expires_at")?)?
        {
            "expired"
        } else if !attached || consent_live(c, store, p).is_err() {
            "invalidated"
        } else {
            "review"
        };
        let next = match state {
            "approved" => "follow_link_progress",
            "review" => "approve_administrator_intent",
            _ => "inspect_link_progress",
        };
        json!({"review_id":digest(&review),"review":review,"state":state,"next_action":next})
    };
    let result = json!({"version":1,"host_id":store.identity().id,"context":input.context,
        "observed_at":stamp(now),"request":request,"admission":admission});
    if !safe(&result) {
        return Err(unavailable());
    }
    Ok(result)
}
impl Store {
    pub fn admission_consent(&self, operation: &str, value: Value) -> Result<Value, Error> {
        let expected = value["admission_review_id"].as_str().map(str::to_owned);
        let input: Inspect = serde_json::from_value(
            json!({"context":value["context"],"request_id":value["request_id"]}),
        )
        .map_err(|_| invalid())?;
        input.validate().map_err(|_| invalid())?;
        if !matches!(operation, "lookup" | "prepare" | "approve")
            || operation == "approve"
                && !expected
                    .as_deref()
                    .is_some_and(|s| crate::peer_store::valid_id(s, "review", 32))
        {
            return Err(invalid());
        }
        let mut c = self.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        let mut p = requests::load(&tx, &input.request_id).map_err(|e| {
            if e.code == "not_found" {
                Error::NotFound
            } else {
                unavailable()
            }
        })?;
        if !p.record.roles.iter().any(|r| r == "administrator")
            || p.record.roles.iter().any(|r| r == "requester")
            || p.record.mode != "new"
            || p.record.migration_proposal_id != "-"
        {
            return Err(unavailable());
        }
        let now = observed(&tx, &p)?;
        let current = response(self, &tx, &input, &p, now)?;
        if operation == "lookup" {
            return Ok(current);
        }
        if operation == "approve" {
            if current["admission"].is_null() {
                return Err(unavailable());
            }
            if current["admission"]["review_id"].as_str() != expected.as_deref() {
                return Err(coded("review_changed"));
            }
        }
        if !current["admission"].is_null()
            && (operation == "prepare" || current["admission"]["state"] == "approved")
        {
            return Ok(current);
        }
        let (_, attached) = input.context.project(&tx, now)?;
        if !attached {
            return Err(coded("review_changed"));
        }
        if current["request"]["state"] == "expired" || current["admission"]["state"] == "expired" {
            return Err(coded("review_expired"));
        }
        let original = requests::load(&tx, &p.id).map_err(dec_error)?;
        let (fresh, approved) = consent_in(
            &tx,
            self,
            &mut p,
            operation == "approve",
            |proposal, effective| {
                let check = || -> Result<(), Error> {
                    let at = time(effective)?;
                    let (parent, attached) = input.context.project(&tx, at)?;
                    if !attached {
                        return Err(coded("review_changed"));
                    }
                    let request = original.view(effective).map_err(dec_error)?;
                    let actual = review(self, &input, &parent, &request, proposal)?;
                    if expected.as_deref().is_some_and(|s| s != digest(&actual)) {
                        return Err(coded("review_changed"));
                    }
                    if at < time(field(&actual, "created_at")?)? {
                        return Err(unavailable());
                    }
                    if at >= time(field(&actual, "expires_at")?)? {
                        return Err(coded("review_expired"));
                    }
                    if !safe(&actual) {
                        return Err(unavailable());
                    }
                    Ok(())
                };
                check().map_err(|e| match e {
                    Error::Coded {
                        code: "review_changed",
                        ..
                    } => codec::Error::new("review_changed"),
                    Error::Coded {
                        code: "review_expired",
                        ..
                    } => codec::Error::new("review_expired"),
                    _ => codec::Error::new("admission_review_unavailable"),
                })
            },
        )
        .map_err(dec_error)?;
        let now = time(&consent_live(&tx, self, &p).map_err(dec_error)?)?;
        if !input.context.project(&tx, now)?.1 {
            return Err(coded("review_changed"));
        }
        let public = response(self, &tx, &input, &p, now)?;
        if now >= time(field(&public["admission"]["review"], "expires_at")?)? {
            return Err(coded("review_expired"));
        }
        controls::remember_decision(&tx, &p.record.expected_network_id, &stamp(now))
            .map_err(dec_error)?;
        tx.commit().map_err(|_| unavailable())?;
        drop(c);
        if fresh {
            controls::barrier(self, "dec.intent.after_commit", &p.id).map_err(dec_error)?;
        }
        if approved {
            controls::barrier(self, "dec.approval.after_commit", &p.id).map_err(dec_error)?;
        }
        Ok(public)
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/admission-consent/lookup", post(lookup))
        .route("/v1/onboarding/admission-consent/prepare", post(prepare))
        .route("/v1/onboarding/admission-consent/approve", post(approve))
}
async fn execute(
    store: Arc<Store>,
    body: Result<Bytes, BytesRejection>,
    operation: &'static str,
) -> Result<Json<Value>, Error> {
    let value = decode_input(&body.map_err(|_| invalid())?, operation)?;
    Ok(Json(
        blocking(store, move |s| s.admission_consent(operation, value)).await?,
    ))
}
async fn lookup(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    execute(store, body, "lookup").await
}
async fn prepare(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    execute(store, body, "prepare").await
}
async fn approve(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    execute(store, body, "approve").await
}
