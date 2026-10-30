//! Private bounded signature storage. No policy publication or application.
use crate::{
    api::blocking,
    decentralized::{codec, project_access_signing},
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
    coded("access_signing_unavailable")
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
        .route("/v1/onboarding/access-consent/signing", post(signing))
        .route("/v1/onboarding/access-consent/sign", post(sign))
}
async fn run(
    store: Arc<Store>,
    body: Result<Bytes, BytesRejection>,
    operation: &'static str,
) -> Result<Json<Value>, Error> {
    let input: Input =
        serde_json::from_value(decode_input(&body.map_err(|_| invalid())?, operation)?)
            .map_err(|_| invalid())?;
    let deadline = (operation == "sign").then(|| Instant::now() + Duration::from_secs(90));
    let task = blocking(store, move |s| {
        project_access_signing::run(s, &input, deadline)
    });
    let result = if let Some(until) = deadline {
        tokio::time::timeout_at(tokio::time::Instant::from_std(until), task)
            .await
            .map_err(|_| unavailable())??
    } else {
        task.await?
    };
    Ok(Json(result))
}
async fn signing(
    State(s): State<Arc<Store>>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, b, "signing").await
}
async fn sign(
    State(s): State<Arc<Store>>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, b, "sign").await
}
