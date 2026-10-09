//! Owner-local transactional session and route setup. No schema extension.
use crate::{
    adapter::{AdapterCredential, CreateAdapter},
    adapter_outbound::{CreateOutboundRoute, OutboundRoute},
    api::{blocking, decode},
    model::{AttachSession, Error, Session},
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::StatusCode,
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterSetupRequest {
    pub agent_id: String,
    pub session_id: String,
    pub integration: String,
    /// Absent, the credential is renewable.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub routes: Vec<SetupRoute>,
    /// Directory access (launch slice 4), default false.
    #[serde(default)]
    pub directory: bool,
    /// 1 to 10,000, default 100; only with `directory`.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub max_sends_per_hour: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRoute {
    pub name: String,
    pub peer_host_id: String,
    pub target_agent_id: String,
    #[serde(default)]
    pub grant_id: Option<String>,
    /// Absent, the route follows the renewable credential.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub expires_at: Option<String>,
    pub max_message_bytes: i64,
    pub max_messages: i64,
    /// Absent, the route sends messages.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub action: Option<String>,
}
#[derive(Serialize)]
pub struct AdapterSetup {
    pub session: Session,
    pub credential: AdapterCredential,
    pub routes: Vec<OutboundRoute>,
}
impl Store {
    pub fn route_status(&self, id: &str) -> Result<Vec<serde_json::Value>, Error> {
        self.adapter(id)?;
        let conn = self.connection()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT r.record,{} FROM adapter_routes r WHERE adapter_id = ?1 ORDER BY name",
            crate::adapter_outbound::ROUTE_USED
        ))?;
        let mut result = Vec::new();
        for row in stmt.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (encoded, used) = row?;
            let route: OutboundRoute = serde_json::from_str(&encoded)?;
            result.push(
                serde_json::json!({"messages_remaining":route.max_messages-used,"route":route}),
            );
        }
        Ok(result)
    }
    pub fn verify_adapter_credential(&self, id: &str, token: &str) -> Result<bool, Error> {
        if !crate::peer_store::valid_id(token, "token", 32) {
            return Err(Error::Invalid("invalid credential".into()));
        }
        let digest: String = self.connection()?.query_row(
            "SELECT token_hash FROM adapter_credentials WHERE id = ?1",
            [id],
            |r| r.get(0),
        )?;
        Ok(digest == crate::adapter::token_hash(token))
    }
    pub fn setup_adapter(&self, r: AdapterSetupRequest) -> Result<AdapterSetup, Error> {
        if !crate::peer_store::valid_id(&r.session_id, "session", 16) || r.routes.len() > 100 {
            return Err(Error::Invalid("invalid setup".into()));
        }
        let directory = match (r.directory, r.max_sends_per_hour) {
            (false, None) => None,
            (false, Some(_)) => {
                return Err(Error::Invalid(
                    "max_sends_per_hour requires directory access".into(),
                ));
            }
            (true, None) => Some(crate::directory::DEFAULT_SENDS_PER_HOUR),
            (true, Some(n)) if (1..=10000).contains(&n) => Some(n),
            (true, Some(_)) => {
                return Err(Error::Invalid(
                    "max_sends_per_hour must be 1 to 10000".into(),
                ));
            }
        };
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let session = Self::attach_session_in(
            &tx,
            AttachSession {
                agent_id: r.agent_id,
                integration: r.integration,
            },
            Some(r.session_id),
        )?;
        let credential = self.create_adapter_in(
            &tx,
            CreateAdapter {
                session_id: session.id.clone(),
                expires_at: r.expires_at,
            },
            directory,
        )?;
        let mut routes = Vec::new();
        for route in r.routes {
            routes.push(self.create_outbound_route_in(
                &tx,
                CreateOutboundRoute {
                    adapter_id: credential.adapter.id.clone(),
                    name: route.name,
                    peer_host_id: route.peer_host_id,
                    target_agent_id: route.target_agent_id,
                    grant_id: route.grant_id,
                    expires_at: route.expires_at,
                    max_message_bytes: route.max_message_bytes,
                    max_messages: route.max_messages,
                    action: route.action,
                    delegation_depth: 0,
                    follows_credential: false,
                    authorization: None,
                },
            )?);
        }
        tx.commit()?;
        Ok(AdapterSetup {
            session,
            credential,
            routes,
        })
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/adapters/setup", post(setup))
        .route("/v1/adapters/{id}/verify-credential", post(verify))
        .route(
            "/v1/adapters/{id}/route-status",
            axum::routing::get(route_status),
        )
}
async fn route_status(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<serde_json::Value>>, Error> {
    Ok(Json(blocking(store, move |s| s.route_status(&id)).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckCredential {
    token: String,
}
async fn verify(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<serde_json::Value>, Error> {
    let request: CheckCredential = decode(body)?;
    let matches = blocking(store, move |s| {
        s.verify_adapter_credential(&id, &request.token)
    })
    .await?;
    Ok(Json(serde_json::json!({"matches":matches})))
}
async fn setup(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<AdapterSetup>), Error> {
    let request: AdapterSetupRequest = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.setup_adapter(request)).await?),
    ))
}
