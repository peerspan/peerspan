//! Owner-local exact project attribution over the ordinary machine owner intent.
use crate::{
    api::blocking,
    decentralized::{self, codec},
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
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub context: AdapterContext,
    pub request_id: String,
    #[serde(default, deserialize_with = "non_null")]
    pub consent_id: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub consent_review_id: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub inspection_review_id: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub replace_consent_id: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub decision: Option<String>,
}
fn non_null<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn invalid() -> Error {
    Error::Invalid("invalid machine owner consent input".into())
}
fn dec(e: codec::Error) -> Error {
    if e.code == "not_found" {
        return Error::NotFound;
    }
    let code = match e.code {
        "review_changed" | "review_expired" => e.code,
        _ => "machine_owner_consent_unavailable",
    };
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
pub fn decode_input(bytes: &[u8], operation: &str) -> Result<Value, Error> {
    let v = codec::parse(bytes, 65536).map_err(|_| invalid())?;
    let shape = match operation {
        "lookup" if v.get("consent_id").is_some() => "context request_id consent_id",
        "lookup" => "context request_id",
        "prepare" if v.get("replace_consent_id").is_some() => {
            "context request_id inspection_review_id replace_consent_id"
        }
        "prepare" => "context request_id inspection_review_id",
        "approve" | "signing" => "context request_id consent_id consent_review_id",
        "sign" => "context request_id consent_id consent_review_id decision",
        _ => return Err(invalid()),
    };
    codec::fields(codec::object(&v).map_err(|_| invalid())?, shape).map_err(|_| invalid())?;
    let i: Input = serde_json::from_value(v.clone()).map_err(|_| invalid())?;
    i.context.validate().map_err(|_| invalid())?;
    if operation == "sign" && i.decision.as_deref() != Some("sign_machine_owner_offer")
        || !codec::ident(&i.request_id, "link_")
        || [&i.consent_id, &i.replace_consent_id].iter().any(|v| {
            v.as_deref()
                .is_some_and(|s| !crate::peer_store::valid_id(s, "dint", 16))
        })
        || [&i.consent_review_id, &i.inspection_review_id]
            .iter()
            .any(|v| v.as_deref().is_some_and(|s| !codec::ident(s, "review_")))
    {
        return Err(invalid());
    }
    Ok(v)
}
impl Store {
    pub fn machine_owner_consent(&self, operation: &str, value: Value) -> Result<Value, Error> {
        let v = decode_input(
            &serde_json::to_vec(&value).map_err(|_| invalid())?,
            operation,
        )?;
        let i: Input = serde_json::from_value(v).map_err(|_| invalid())?;
        let mut c = self
            .connection()
            .map_err(|_| dec(codec::Error::new("internal")))?;
        let tx = c
            .transaction()
            .map_err(|_| dec(codec::Error::new("internal")))?;
        let (result, changed) =
            decentralized::machine_owner_consent_in(&tx, self, operation, &i).map_err(dec)?;
        if changed {
            tx.commit()
                .map_err(|_| dec(codec::Error::new("internal")))?;
        }
        Ok(result)
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/machine-owner-consent/lookup", post(lookup))
        .route(
            "/v1/onboarding/machine-owner-consent/prepare",
            post(prepare),
        )
        .route(
            "/v1/onboarding/machine-owner-consent/approve",
            post(approve),
        )
}
async fn run(
    s: Arc<Store>,
    b: Result<Bytes, BytesRejection>,
    op: &'static str,
) -> Result<Json<Value>, Error> {
    let v = decode_input(&b.map_err(|_| invalid())?, op)?;
    Ok(Json(
        blocking(s, move |s| s.machine_owner_consent(op, v)).await?,
    ))
}
async fn lookup(
    State(s): State<Arc<Store>>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, b, "lookup").await
}
async fn prepare(
    State(s): State<Arc<Store>>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, b, "prepare").await
}
async fn approve(
    State(s): State<Arc<Store>>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, b, "approve").await
}
