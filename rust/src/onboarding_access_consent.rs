//! Exact human consent over an ordinary policy action; no signing or publication.
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
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub context: AdapterContext,
    pub network_id: String,
    pub person_public_key: String,
    #[serde(default, deserialize_with = "non_null")]
    pub inspection_review_id: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub replace_access_id: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub access_id: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub access_review_id: Option<String>,
}
fn non_null<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
pub(crate) fn invalid() -> Error {
    Error::Invalid("invalid project access consent input".into())
}
fn coded(code: &'static str) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: code.replace('_', " "),
        extra: Default::default(),
    }
}
fn dec(e: codec::Error) -> Error {
    match e.code {
        "not_found" => Error::NotFound,
        "review_changed" | "review_expired" => coded(e.code),
        _ => coded("access_review_unavailable"),
    }
}
impl Input {
    pub(crate) fn selection(&self) -> Value {
        json!({"context":self.context,"network_id":self.network_id,"person_public_key":self.person_public_key})
    }
    pub(crate) fn inspection(&self) -> crate::onboarding_access::Inspect {
        crate::onboarding_access::Inspect {
            context: self.context.clone(),
            network_id: self.network_id.clone(),
            person_public_key: self.person_public_key.clone(),
        }
    }
}
pub fn decode_input(bytes: &[u8], operation: &str) -> Result<Value, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let value = codec::parse(bytes, 65536).map_err(|_| invalid())?;
    let fields = match operation {
        "lookup" => "context network_id person_public_key",
        "prepare" if value.get("replace_access_id").is_some() => {
            "context network_id person_public_key inspection_review_id replace_access_id"
        }
        "prepare" => "context network_id person_public_key inspection_review_id",
        "approve" => "context network_id person_public_key access_id access_review_id",
        _ => return Err(invalid()),
    };
    codec::fields(codec::object(&value).map_err(|_| invalid())?, fields).map_err(|_| invalid())?;
    let input: Input = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    input.context.validate().map_err(|_| invalid())?;
    if !codec::ident(&input.network_id, "net_") || !codec::key(&input.person_public_key) {
        return Err(invalid());
    }
    let id = |v: &Option<String>| {
        v.as_deref()
            .is_some_and(|s| crate::peer_store::valid_id(s, "dint", 16))
    };
    let review = |v: &Option<String>| v.as_deref().is_some_and(|s| codec::ident(s, "review_"));
    if (operation == "prepare" && !review(&input.inspection_review_id))
        || (operation == "approve" && (!id(&input.access_id) || !review(&input.access_review_id)))
        || (input.replace_access_id.is_some() && !id(&input.replace_access_id))
    {
        return Err(invalid());
    }
    Ok(value)
}
impl Store {
    pub fn access_consent(&self, operation: &str, value: Value) -> Result<Value, Error> {
        let value = decode_input(&serde_json::to_vec(&value)?, operation)?;
        let input: Input = serde_json::from_value(value).map_err(|_| invalid())?;
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        let raw = decentralized::controls::local_decision_time().map_err(dec)?;
        let now =
            decentralized::controls::guarded_decision(&tx, &input.network_id, &raw).map_err(dec)?;
        let time = chrono::DateTime::parse_from_rfc3339(&now)
            .map_err(|_| coded("access_review_unavailable"))?
            .with_timezone(&chrono::Utc);
        let (parent, attached) = input.context.project(&tx, time)?;
        let access =
            decentralized::access_consent_in(&tx, self, operation, &input, &parent, attached, &now)
                .map_err(dec)?;
        if !access.is_null()
            && access["review"]["created_at"]
                .as_str()
                .is_none_or(|created| raw.as_str() < created)
        {
            return Err(coded("access_review_unavailable"));
        }
        let result = json!({"version":1,"host_id":self.identity().id,"context":input.context,
            "observed_at":now,"access":access});
        if !crate::onboarding_admission::safe(&result)
            || serde_json::to_vec(&result)?.len() > 1 << 20
        {
            return Err(coded("access_review_unavailable"));
        }
        if operation != "lookup" {
            tx.commit()?;
        }
        Ok(result)
    }
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/access-consent/lookup", post(lookup))
        .route("/v1/onboarding/access-consent/prepare", post(prepare))
        .route("/v1/onboarding/access-consent/approve", post(approve))
}
async fn run(
    store: Arc<Store>,
    body: Result<Bytes, BytesRejection>,
    operation: &'static str,
) -> Result<Json<Value>, Error> {
    let value = decode_input(&body.map_err(|_| invalid())?, operation)?;
    Ok(Json(
        blocking(store, move |s| s.access_consent(operation, value)).await?,
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
