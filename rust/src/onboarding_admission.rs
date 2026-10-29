//! Read-only public evidence before administrator consent. No signer choice.
use crate::{
    api::blocking,
    canonical,
    decentralized::{inspect_original_admission, requests},
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
use chrono::{DateTime, Utc};
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
    Error::Invalid("invalid administrator admission inspection input".into())
}
fn coded(code: &'static str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
impl Inspect {
    pub fn validate(&self) -> Result<(), Error> {
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
fn safe(v: &Value) -> bool {
    match v {
        Value::String(s) => {
            if s.chars().any(char::is_control) {
                return false;
            }
            let plain: String = s
                .chars()
                .filter(|c| {
                    !matches!(*c,
                '\u{200b}'..='\u{200f}'|'\u{2028}'..='\u{202e}'|'\u{2060}'..='\u{206f}'|'\u{feff}')
                })
                .collect();
            ![
                "psi2-",
                "psl2-",
                "token_",
                "instance_",
                "peerspan-invite-v1.",
                "peerspan-person-invite-v1.",
                "peerspan-member-invite-v1.",
            ]
            .iter()
            .any(|p| s.contains(p) || plain.contains(p))
        }
        Value::Array(a) => a.iter().all(safe),
        Value::Object(o) => o.values().all(safe),
        _ => true,
    }
}
impl Store {
    pub fn inspect_admission(&self, input: Inspect) -> Result<Value, Error> {
        input.validate()?;
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let p = requests::load(&tx, &input.request_id).map_err(|e| {
            if e.code == "not_found" {
                Error::NotFound
            } else {
                coded("admission_inspection_unavailable")
            }
        })?;
        let evidence = inspect_original_admission(&tx, self, &p)
            .map_err(|_| coded("admission_inspection_unavailable"))?;
        let observed = evidence["observed_at"]
            .as_str()
            .ok_or_else(|| coded("admission_inspection_unavailable"))?;
        let now: DateTime<Utc> = DateTime::parse_from_rfc3339(observed)
            .map_err(|_| coded("admission_inspection_unavailable"))?
            .with_timezone(&Utc);
        let (parent, attached) = input.context.project(&tx, now)?;
        if !attached {
            return Err(coded("review_changed"));
        }
        let r = &evidence["request"];
        let review = json!({"version":1,"kind":"inspect_new_original_admission",
            "host_id":self.identity().id,"context":input.context,"agent":parent["agent"],
            "network":evidence["network"],"root_state_id":evidence["root_state_id"],
            "request_id":input.request_id,"request_packet_id":r["request_packet_id"],
            "owner_offer_id":r["owner_offer_id"],"selection_id":r["selection_id"],
            "member":evidence["member"],"person_public_key":r["person_public_key"],
            "host_public_key":r["host_public_key"],"device_public_key":r["device_public_key"],
            "scopes":7,"not_after":evidence["not_after"],"created_at":r["created_at"],"expires_at":r["expires_at"],
            "effects":{"verify_request_signature":true,"verify_original_owner_signature":true,
                "verify_requester_selection":true,"prepare_administrator_intent":false,
                "approve_administrator_intent":false,"sign_admission":false,"grant_membership":false,
                "grant_agent_access":false,"commit_request":false,"share_files":false,
                "share_conversation":false,"capability_calls":false}});
        let review_id = format!(
            "review_{}",
            hex::encode(Sha256::digest(format!(
                "peerspan-admission-inspection-v1\n{}",
                canonical::value_text(&review)
            )))
        );
        let result = json!({"version":1,"host_id":self.identity().id,"context":input.context,
            "observed_at":observed,"request":r,"review_id":review_id,"review":review,
            "next_action":"review_administrator_consent"});
        if !safe(&result) {
            return Err(coded("admission_inspection_unavailable"));
        }
        // Drop a read transaction. No save, cleanup, clock or event mutation.
        Ok(result)
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/onboarding/admission-inspection", post(inspect))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let body = body.map_err(|_| invalid())?;
    let input = decode_input(&body)?;
    Ok(Json(
        blocking(store, move |s| s.inspect_admission(input)).await?,
    ))
}
