//! Bounded owner-local initial machine-owner signature storage.
use crate::{
    api::blocking,
    decentralized::{codec, machine_owner_signing},
    model::Error,
    onboarding_machine_consent::{Input, decode_input},
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
    coded("machine_owner_signing_unavailable")
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
fn invalid() -> Error {
    Error::Invalid("invalid machine owner signing input".into())
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/onboarding/machine-owner-consent/signing",
            post(signing),
        )
        .route("/v1/onboarding/machine-owner-consent/sign", post(sign))
}
async fn run(
    s: Arc<Store>,
    b: Result<Bytes, BytesRejection>,
    op: &'static str,
) -> Result<Json<Value>, Error> {
    let input: Input = serde_json::from_value(decode_input(&b.map_err(|_| invalid())?, op)?)
        .map_err(|_| invalid())?;
    let until = (op == "sign").then(|| Instant::now() + Duration::from_secs(90));
    let task = blocking(s, move |s| machine_owner_signing::run(s, &input, until));
    let v = if let Some(until) = until {
        tokio::time::timeout_at(tokio::time::Instant::from_std(until), task)
            .await
            .map_err(|_| unavailable())??
    } else {
        task.await?
    };
    Ok(Json(v))
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
