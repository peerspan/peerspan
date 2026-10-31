//! Current receiver advertisements and exact-session evidence, never a probe.
use crate::{
    adapter::Adapter,
    api::blocking,
    model::Error,
    onboarding_access::{Inspect, decode_input, inspect_in},
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    routing::post,
};
use chrono::Utc;
use serde_json::{Value, json};
use std::sync::Arc;

fn unavailable() -> Error {
    Error::Coded {
        status: 409,
        code: "readiness_unavailable",
        message: "project readiness unavailable".into(),
        extra: Default::default(),
    }
}

impl Store {
    pub fn project_readiness(&self, input: Inspect) -> Result<Value, Error> {
        input.validate()?;
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let at = crate::decentralized::local_decision_time().map_err(|_| unavailable())?;
        crate::decentralized::product::with_read_time(&at, || {
            let inspection = inspect_in(&tx, self, &input, &at)?;
            let now = chrono::DateTime::parse_from_rfc3339(
                inspection["observed_at"].as_str().ok_or_else(unavailable)?,
            )
            .map_err(|_| unavailable())?
            .with_timezone(&Utc);
            let (project, attached) = input.context.project(&tx, now)?;
            if !attached {
                return Err(unavailable());
            }
            let agent_id = project["agent"]["id"].as_str().ok_or_else(unavailable)?;
            let agent_name = project["agent"]["name"].as_str().ok_or_else(unavailable)?;
            let session_id = project["session_id"].as_str().ok_or_else(unavailable)?;
            let mut peers = Vec::new();
            for host in inspection["review"]["participant"]["hosts"]
                .as_array()
                .ok_or_else(unavailable)?
            {
                let key = host["host_public_key"].as_str().ok_or_else(unavailable)?;
                let bytes = crate::membership::canonical(key, 32).map_err(|_| unavailable())?;
                let id = crate::peer_store::key_id(&bytes);
                if id == self.identity().id {
                    continue;
                }
                let advertised = self.reachable_agents_in(&tx, &id, &input.network_id)?;
                let authorizations = advertised
                    .into_iter()
                    .find(|a| a.agent_id == agent_id && a.name == agent_name)
                    .map(|a| a.authorizations)
                    .unwrap_or_default();
                peers.push(
                    json!({"host_id":id,"host_public_key":key,"authorizations":authorizations}),
                );
            }
            peers.sort_by(|a, b| a["host_id"].as_str().cmp(&b["host_id"].as_str()));
            let credentials = {
                let mut q = tx.prepare(
                    "SELECT record FROM adapter_credentials WHERE session_id=?1 ORDER BY id",
                )?;
                q.query_map([session_id], |r| r.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let mut connections = Vec::new();
            for raw in credentials {
                let credential: Adapter = serde_json::from_str(&raw)?;
                if credential.revoked_at.is_none()
                    && crate::membership::time(&credential.expires_at)? > crate::clock::now()
                {
                    connections.push(self.adapter_connection_in(&tx, &credential.id)?);
                }
            }
            let result = json!({"version":1,"host_id":inspection["host_id"],"context":input.context,
                "observed_at":inspection["observed_at"],
                "inspection":{"review_id":inspection["review_id"],"review":inspection["review"]},
                "readiness":{"direction":"participant_hosts_to_project_agent","session_id":session_id,
                    "adapter_connections":connections,"peers":peers,"peer_reachability":"not_verified",
                    "model_receipt":"not_verified","connection_readiness":"not_verified"}});
            if !crate::onboarding_admission::safe(&result)
                || serde_json::to_vec(&result)?.len() > 2 << 20
            {
                return Err(unavailable());
            }
            // Dropping this read transaction commits no guard, cleanup or event.
            Ok(result)
        })
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route("/v1/onboarding/readiness", post(readiness))
}
async fn readiness(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let input = decode_input(&body.map_err(|_| Error::Invalid("invalid readiness input".into()))?)?;
    Ok(Json(
        blocking(store, move |s| s.project_readiness(input)).await?,
    ))
}
