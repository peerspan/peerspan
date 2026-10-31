//! One project-bound, pure incoming existing-person machine-owner review.
use crate::{
    api::blocking,
    decentralized::{inspect_machine_owner, requests},
    model::Error,
    onboarding_adapter::AdapterContext,
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspect {
    pub context: AdapterContext,
    pub request_id: String,
}
fn invalid() -> Error {
    Error::Invalid("invalid machine owner inspection input".into())
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
    coded("machine_owner_inspection_unavailable")
}
impl Inspect {
    fn validate(&self) -> Result<(), Error> {
        self.context.validate().map_err(|_| invalid())?;
        if !crate::peer_store::valid_id(&self.request_id, "link", 32) {
            return Err(invalid());
        }
        Ok(())
    }
}
pub fn decode_input(bytes: &[u8]) -> Result<Inspect, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let input: Inspect =
        crate::linking::decode_mutation(bytes, "context request_id").map_err(|_| invalid())?;
    input.validate()?;
    Ok(input)
}
impl Store {
    pub fn inspect_machine_owner(&self, input: Inspect) -> Result<Value, Error> {
        input.validate()?;
        let mut c = self.connection().map_err(|_| unavailable())?;
        let tx = c.transaction().map_err(|_| unavailable())?;
        let p = requests::load(&tx, &input.request_id).map_err(|e| {
            if e.code == "not_found" {
                Error::NotFound
            } else {
                unavailable()
            }
        })?;
        // Verify the exact attached parent before projecting network authority.
        let raw = crate::decentralized::local_decision_time().map_err(|_| unavailable())?;
        let time = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|t| t.with_timezone(&chrono::Utc))
                .map_err(|_| unavailable())
        };
        if !input
            .context
            .project(&tx, time(&raw)?)
            .map_err(|_| coded("review_changed"))?
            .1
        {
            return Err(coded("review_changed"));
        }
        let e = inspect_machine_owner(&tx, self, &p).map_err(|_| unavailable())?;
        let observed = e["observed_at"].as_str().ok_or_else(unavailable)?;
        let (parent, attached) = input
            .context
            .project(&tx, time(observed)?)
            .map_err(|_| coded("review_changed"))?;
        if !attached {
            return Err(coded("review_changed"));
        }
        let r = &e["request"];
        let review = json!({"version":1,"kind":"inspect_existing_person_machine",
            "host_id":self.identity().id,"context":input.context,"agent":parent["agent"],
            "network":e["network"],"root_state_id":e["root_state_id"],
            "request_id":input.request_id,"request_packet_id":r["request_packet_id"],
            "person_public_key":r["person_public_key"],"host_public_key":r["host_public_key"],
            "device_public_key":r["device_public_key"],"member":e["member"],
            "person_lease_id":e["person_lease_id"],"local_host":e["local_host"],
            "provider":e["provider"],"provider_id":e["provider_id"],"signature_format":e["signature_format"],
            "scopes":7,"not_after":e["not_after"],"host_admission":e["host_admission"],
            "created_at":r["created_at"],"expires_at":r["expires_at"],
            "effects":{"verify_request_signature":true,"inspect_current_owner_authority":true,
                "prepare_owner_intent":false,"approve_owner_intent":false,"sign_owner_offer":false,
                "publish_owner_offer":false,"grant_membership":false,"grant_machine_powers":false,
                "grant_agent_access":false,"commit_request":false,"share_files":false,
                "share_conversation":false,"capability_calls":false}});
        let digest = format!(
            "review_{}",
            hex::encode(Sha256::digest(format!(
                "peerspan-machine-owner-inspection-v1\n{}",
                crate::canonical::value_text(&review)
            )))
        );
        let result = json!({"version":1,"host_id":self.identity().id,"context":input.context,
            "observed_at":observed,"request":r,"review_id":digest,"review":review,
            "next_action":"review_machine_owner_consent"});
        if !crate::onboarding_admission::safe(&result)
            || serde_json::to_vec(&result)
                .map_err(|_| unavailable())?
                .len()
                > 2 << 20
        {
            return Err(unavailable());
        }
        // Drop the held read. No clock save, intent, key probe, cleanup or IO.
        Ok(result)
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/onboarding/machine-owner-inspection", post(inspect))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let input = decode_input(&body.map_err(|_| invalid())?)?;
    Ok(Json(
        blocking(store, move |s| s.inspect_machine_owner(input)).await?,
    ))
}
