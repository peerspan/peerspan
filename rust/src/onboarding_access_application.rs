//! Explicit local publication of an exact, already approved and signed policy.
use crate::{
    api::blocking,
    decentralized::{codec, project_access_application},
    model::Error,
    onboarding_access_consent::{Input, decode_input, invalid},
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    routing::post,
};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) fn unavailable() -> Error {
    coded("access_application_unavailable")
}
fn coded(code: &'static str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
pub(crate) fn dec(e: codec::Error) -> Error {
    match e.code {
        "not_found" => Error::NotFound,
        "review_changed" | "review_expired" => coded(e.code),
        _ => unavailable(),
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/onboarding/access-consent/application",
            post(application),
        )
        .route("/v1/onboarding/access-consent/apply", post(apply))
}
async fn run(
    store: Arc<Store>,
    body: Result<Bytes, BytesRejection>,
    operation: &'static str,
) -> Result<Json<Value>, Error> {
    let input: Input =
        serde_json::from_value(decode_input(&body.map_err(|_| invalid())?, operation)?)
            .map_err(|_| invalid())?;
    let until = (operation == "apply").then(|| Instant::now() + Duration::from_secs(90));
    let task = blocking(store, move |s| {
        project_access_application::run(s, &input, until)
    });
    let value = if let Some(until) = until {
        tokio::time::timeout_at(tokio::time::Instant::from_std(until), task)
            .await
            .map_err(|_| unavailable())??
    } else {
        task.await?
    };
    Ok(Json(value))
}
async fn application(
    State(s): State<Arc<Store>>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, b, "application").await
}
async fn apply(
    State(s): State<Arc<Store>>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, b, "apply").await
}
