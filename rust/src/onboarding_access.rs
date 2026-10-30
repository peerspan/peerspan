//! Exact project binding over current public membership and policy evidence.
use crate::{
    api::blocking,
    decentralized::{codec, inspect_project_access},
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
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspect {
    pub context: AdapterContext,
    pub network_id: String,
    pub person_public_key: String,
}
fn invalid() -> Error {
    Error::Invalid("invalid project access inspection input".into())
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
    fn validate(&self) -> Result<(), Error> {
        self.context.validate().map_err(|_| invalid())?;
        if !codec::ident(&self.network_id, "net_") || !codec::key(&self.person_public_key) {
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
        crate::linking::decode_mutation(bytes, "context network_id person_public_key")
            .map_err(|_| invalid())?;
    input.validate()?;
    Ok(input)
}
impl Store {
    pub fn inspect_project_access(&self, input: Inspect) -> Result<Value, Error> {
        input.validate()?;
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let unavailable = || coded("access_inspection_unavailable");
        let e = inspect_project_access(&tx, self, &input.network_id, &input.person_public_key)
            .map_err(|e| {
                if e.code == "not_found" {
                    // Only the network's absence is a 404. An unknown person or
                    // missing current policy ancestry is unavailable evidence.
                    let exists: bool = tx
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
                            [&input.network_id],
                            |r| r.get(0),
                        )
                        .unwrap_or(true);
                    if exists {
                        unavailable()
                    } else {
                        Error::NotFound
                    }
                } else {
                    unavailable()
                }
            })?;
        let observed = e["observed_at"].as_str().ok_or_else(unavailable)?;
        let now = chrono::DateTime::parse_from_rfc3339(observed)
            .map_err(|_| unavailable())?
            .with_timezone(&chrono::Utc);
        let (parent, attached) = input.context.project(&tx, now)?;
        if !attached {
            return Err(coded("review_changed"));
        }
        let review = json!({"version":1,"kind":"inspect_project_agent_access",
            "host_id":self.identity().id,"context":input.context,"agent":parent["agent"],
            "network":e["network"],"root_state_id":e["root_state_id"],"owner":e["owner"],
            "participant":e["participant"],"policy":e["policy"],
            "effects":{"inspect_current_membership":true,"inspect_current_policy":true,
                "prepare_access":false,"approve_access":false,"sign_policy":false,
                "publish_policy":false,"grant_agent_access":false,"share_files":false,
                "share_conversation":false,"capability_calls":false}});
        let digest = format!(
            "review_{}",
            codec::hash(
                format!(
                    "peerspan-project-access-inspection-v1\n{}",
                    crate::canonical::value_text(&review),
                )
                .as_bytes()
            )
        );
        let result = json!({"version":1,"host_id":self.identity().id,"context":input.context,
            "observed_at":observed,"review_id":digest,"review":review,
            "next_action":"review_agent_access"});
        if !crate::onboarding_admission::safe(&result)
            || serde_json::to_vec(&result)?.len() > 2 << 20
        {
            return Err(unavailable());
        }
        // Drop the read transaction: no intent, cleanup, clock or event save.
        Ok(result)
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/onboarding/access-inspection", post(inspect))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let input = decode_input(&body.map_err(|_| invalid())?)?;
    Ok(Json(
        blocking(store, move |s| s.inspect_project_access(input)).await?,
    ))
}
