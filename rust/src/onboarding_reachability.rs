//! One explicit pinned peer read; never permission or incoming-delivery proof.
use crate::{
    api::blocking, decentralized::codec, model::Error, onboarding_access::Inspect,
    onboarding_adapter::AdapterContext, peer_store::Peer, store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub context: AdapterContext,
    pub network_id: String,
    pub person_public_key: String,
    pub peer_host_id: String,
}
impl Input {
    fn inspection(&self) -> Inspect {
        Inspect {
            context: self.context.clone(),
            network_id: self.network_id.clone(),
            person_public_key: self.person_public_key.clone(),
        }
    }
}
fn invalid() -> Error {
    Error::Invalid("invalid project reachability input".into())
}
fn unavailable() -> Error {
    Error::Coded {
        status: 409,
        code: "reachability_unavailable",
        message: "project reachability unavailable".into(),
        extra: Default::default(),
    }
}
pub fn decode_input(bytes: &[u8]) -> Result<Input, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let input: Input =
        crate::linking::decode_mutation(bytes, "context network_id person_public_key peer_host_id")
            .map_err(|_| invalid())?;
    input.inspection().validate().map_err(|_| invalid())?;
    if !codec::ident(&input.peer_host_id, "host_") {
        return Err(invalid());
    }
    Ok(input)
}

// Only owned public pins and the resolved private dial target cross an await.
struct Plan {
    input: Input,
    inspection: Value,
    peer: Peer,
}
fn prepare(store: &Store, input: Input) -> Result<Plan, Error> {
    let inspection = store.inspect_project_access(input.inspection())?;
    let selected = inspection["review"]["participant"]["hosts"]
        .as_array()
        .ok_or_else(unavailable)?
        .iter()
        .find_map(|host| {
            let key = host["host_public_key"].as_str()?;
            let bytes = crate::membership::canonical(key, 32).ok()?;
            (crate::peer_store::key_id(&bytes) == input.peer_host_id).then_some(key)
        })
        .ok_or_else(unavailable)?;
    if input.peer_host_id == store.identity().id {
        return Err(unavailable());
    }
    let peer = store
        .dial_target(&input.peer_host_id)
        .map_err(|_| unavailable())?;
    if peer.id != input.peer_host_id || peer.public_key != selected {
        return Err(unavailable());
    }
    Ok(Plan {
        input,
        inspection,
        peer,
    })
}
fn finish(store: &Store, plan: Plan, status: Option<u16>) -> Result<Value, Error> {
    let current = store
        .inspect_project_access(plan.input.inspection())
        .map_err(|_| unavailable())?;
    if current["host_id"] != plan.inspection["host_id"]
        || current["context"] != plan.inspection["context"]
        || current["review_id"] != plan.inspection["review_id"]
        || current["review"] != plan.inspection["review"]
        || current["observed_at"].as_str() < plan.inspection["observed_at"].as_str()
    {
        return Err(unavailable());
    }
    let result = json!({"version":1,"host_id":current["host_id"],"context":plan.input.context,
        "observed_at":current["observed_at"],
        "inspection":{"review_id":current["review_id"],"review":current["review"]},
        "reachability":{"direction":"project_host_to_participant_host",
            "peer_host_id":plan.peer.id,"peer_host_public_key":plan.peer.public_key,
            "result":if status.is_some() {"authenticated_response"} else {"not_verified"},
            "http_status":status,"incoming_delivery":"not_verified","model_receipt":"not_verified",
            "connection_readiness":"not_verified"}});
    if !crate::onboarding_admission::safe(&result) || serde_json::to_vec(&result)?.len() > 2 << 20 {
        return Err(unavailable());
    }
    Ok(result)
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/onboarding/reachability", post(check))
}
async fn check(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let input = decode_input(&body.map_err(|_| invalid())?)?;
    tokio::time::timeout(Duration::from_secs(12), async move {
        let plan = blocking(store.clone(), move |s| prepare(s, input)).await?;
        let path = format!("/peer/v1/networks/{}/agents", plan.input.network_id);
        let status = tokio::time::timeout(
            Duration::from_secs(8),
            crate::quic::request_current_routes(store.clone(), &plan.peer, "GET", &path, b""),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .map(|(status, _)| status)
        .filter(|status| (200..=599).contains(status));
        blocking(store, move |s| finish(s, plan, status))
            .await
            .map(Json)
    })
    .await
    .map_err(|_| unavailable())?
}
