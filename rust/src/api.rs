use crate::{
    model::{Agent, AttachSession, Error, Event, RegisterAgent, Session},
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, de::DeserializeOwned};
use std::sync::Arc;

/// Owner-local administration only. Never serve this router as a peer API.
pub fn router(store: Arc<Store>) -> Router {
    let history = store.clone();
    Router::new()
        .route("/v1/host", get(identity))
        .route("/v1/agents", get(agents).post(register))
        .route("/v1/agents/{id}", get(agent))
        .route("/v1/sessions", get(sessions).post(attach))
        .route("/v1/sessions/{id}", get(session))
        .route("/v1/sessions/{id}/detach", post(detach))
        .route("/v1/activity", get(activity))
        .merge(crate::peer::local_routes())
        .merge(crate::network::local_routes())
        .merge(crate::link_runtime::local_routes())
        .merge(crate::decentralized::runtime::local_routes())
        .merge(crate::decentralized::peer::local_routes())
        .merge(crate::coordinator_move::local_routes())
        .merge(crate::policy::local_routes())
        .merge(crate::adapter::local_routes())
        .merge(crate::adapter_setup::local_routes())
        .merge(crate::task_outbound::local_routes())
        .merge(crate::artifact::local_routes())
        .merge(crate::status::local_routes())
        .merge(crate::onboarding::local_routes())
        .merge(crate::onboarding_access::local_routes())
        .merge(crate::onboarding_readiness::local_routes())
        .merge(crate::onboarding_reachability::local_routes())
        .merge(crate::onboarding_access_consent::local_routes())
        .merge(crate::onboarding_access_signing::local_routes())
        .merge(crate::onboarding_access_application::local_routes())
        .merge(crate::onboarding_machine::local_routes())
        .merge(crate::onboarding_machine_consent::local_routes())
        .merge(crate::onboarding_admission::local_routes())
        .merge(crate::onboarding_admission_consent::local_routes())
        .merge(crate::onboarding_incoming::local_routes())
        .merge(crate::onboarding_adapter::local_routes())
        .merge(crate::onboarding_invitation::local_routes())
        .merge(crate::onboarding_join::local_routes())
        .merge(crate::directory::local_routes())
        .merge(crate::agent_lookup::local_routes())
        .merge(crate::live_delivery::local_routes())
        .merge(crate::sources::local_routes())
        .merge(crate::oauth::local_routes())
        .merge(crate::builtin::local_routes())
        .merge(crate::capabilities::local_routes())
        .merge(crate::calls::local_routes())
        .merge(crate::approvals::local_routes())
        .merge(crate::call_outbound::local_routes())
        .layer(DefaultBodyLimit::max(1 << 20))
        .with_state(store)
        .layer(axum::middleware::from_fn_with_state(
            history,
            crate::decentralized::history::gate,
        ))
        .layer(axum::middleware::from_fn(crate::timing::layer))
}

pub(crate) async fn blocking<T: Send + 'static>(
    store: Arc<Store>,
    f: impl FnOnce(&Store) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let request = crate::timing::current();
    tokio::task::spawn_blocking(move || {
        let _request = crate::timing::within(request);
        f(&store)
    })
    .await
    .map_err(|e| Error::Internal(e.into()))?
}

pub(crate) fn decode<T: DeserializeOwned>(body: Result<Bytes, BytesRejection>) -> Result<T, Error> {
    let body = body.map_err(|_| Error::Invalid("invalid request".into()))?;
    serde_json::from_slice(&body).map_err(|_| Error::Invalid("invalid request".into()))
}

/// This host's public identity, and the coordinator `network create` uses
/// when given none.
async fn identity(State(store): State<Arc<Store>>) -> Json<serde_json::Value> {
    let identity = store.identity();
    Json(serde_json::json!({
        "id": identity.id,
        "public_key": identity.public_key,
        "created_at": identity.created_at,
        "default_coordinator": serde_json::Value::Null,
        "network_protocols":["peerspan-decentralized-v1"],
    }))
}
async fn register(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Agent>), Error> {
    let request: RegisterAgent = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.register_agent(request)).await?),
    ))
}
async fn agents(State(store): State<Arc<Store>>) -> Result<Json<Vec<Agent>>, Error> {
    Ok(Json(blocking(store, Store::agents).await?))
}
async fn agent(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Agent>, Error> {
    Ok(Json(blocking(store, move |s| s.agent(&id)).await?))
}
async fn attach(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Session>), Error> {
    let request: AttachSession = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.attach_session(request)).await?),
    ))
}

#[derive(Default, Deserialize)]
struct SessionQuery {
    #[serde(default)]
    agent_id: String,
}
async fn sessions(
    State(store): State<Arc<Store>>,
    query: Result<Query<SessionQuery>, QueryRejection>,
) -> Result<Json<Vec<Session>>, Error> {
    let Query(query) = query.map_err(|_| Error::Invalid("invalid request".into()))?;
    Ok(Json(
        blocking(store, move |s| s.sessions(&query.agent_id)).await?,
    ))
}
async fn session(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Session>, Error> {
    Ok(Json(blocking(store, move |s| s.session(&id)).await?))
}
async fn detach(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Session>, Error> {
    Ok(Json(blocking(store, move |s| s.detach_session(&id)).await?))
}

#[derive(Default, Deserialize)]
struct EventQuery {
    after: Option<String>,
    limit: Option<String>,
}
async fn activity(
    State(store): State<Arc<Store>>,
    query: Result<Query<EventQuery>, QueryRejection>,
) -> Result<Json<Vec<Event>>, Error> {
    let Query(query) = query.map_err(|_| Error::Invalid("invalid request".into()))?;
    let after = number(query.after, 0)?;
    let limit = number(query.limit, 100)?;
    Ok(Json(
        blocking(store, move |s| s.events(after, limit)).await?,
    ))
}
fn number(value: Option<String>, default: i64) -> Result<i64, Error> {
    match value.filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(value) => value
            .parse()
            .map_err(|_| Error::Invalid("invalid request".into())),
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut limit = None;
        let mut extra = serde_json::Map::new();
        let (status, code, message) = match self {
            Self::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                "invalid",
                format!("invalid request: {message}"),
            ),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "forbidden".into()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".into()),
            Self::Conflict(message) => (
                StatusCode::CONFLICT,
                "conflict",
                format!("conflict: {message}"),
            ),
            Self::Unavailable(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                format!("unavailable: {message}"),
            ),
            Self::TooLarge(message) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                format!("too large: {message}"),
            ),
            Self::InsufficientStorage(message) => (
                StatusCode::INSUFFICIENT_STORAGE,
                "insufficient_storage",
                format!("insufficient storage: {message}"),
            ),
            Self::Limit {
                limit: name,
                message,
            } => {
                limit = Some(name);
                (StatusCode::TOO_MANY_REQUESTS, "limit", message)
            }
            Self::Coded {
                status,
                code,
                message,
                extra: fields,
            } => {
                extra = fields;
                (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                    code,
                    message,
                )
            }
            Self::Internal(error) => {
                eprintln!("host store error: {error}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".into(),
                )
            }
        };
        let mut body = serde_json::json!({"code": code, "error": message});
        if let Some(limit) = limit {
            body["limit"] = limit.into();
        }
        if let Some(object) = body.as_object_mut() {
            object.extend(extra);
        }
        (status, Json(body)).into_response()
    }
}
