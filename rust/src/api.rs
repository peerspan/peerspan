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
    Router::new()
        .route("/v1/host", get(identity))
        .route("/v1/agents", get(agents).post(register))
        .route("/v1/agents/{id}", get(agent))
        .route("/v1/sessions", get(sessions).post(attach))
        .route("/v1/sessions/{id}", get(session))
        .route("/v1/sessions/{id}/detach", post(detach))
        .route("/v1/activity", get(activity))
        .merge(crate::peer::local_routes())
        .layer(DefaultBodyLimit::max(1 << 20))
        .with_state(store)
}

pub(crate) async fn blocking<T: Send + 'static>(
    store: Arc<Store>,
    f: impl FnOnce(&Store) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|e| Error::Internal(e.into()))?
}

pub(crate) fn decode<T: DeserializeOwned>(body: Result<Bytes, BytesRejection>) -> Result<T, Error> {
    let body = body.map_err(|_| Error::Invalid("invalid request".into()))?;
    serde_json::from_slice(&body).map_err(|_| Error::Invalid("invalid request".into()))
}

async fn identity(State(store): State<Arc<Store>>) -> Json<crate::model::Identity> {
    Json(store.identity())
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
            Self::Internal(error) => {
                eprintln!("host store error: {error}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".into(),
                )
            }
        };
        (
            status,
            Json(serde_json::json!({"code": code, "error": message})),
        )
            .into_response()
    }
}
