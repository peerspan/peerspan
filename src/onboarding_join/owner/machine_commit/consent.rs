//! Owner-local strict private actions; no protocol signing or continuation.
use super::*;

pub fn decode_input(bytes: &[u8], op: &str, cli: bool) -> Result<Value, Error> {
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    let shape = match op {
        "lookup" => "context join_review_id",
        "prepare" => "context join_review_id inspection_review_id",
        "approve" => "context join_review_id consent_review_id",
        "complete" => "context join_review_id consent_review_id decision",
        _ => return Err(invalid()),
    };
    let shape = if cli {
        format!("flow_id {shape}")
    } else {
        shape.into()
    };
    let v: Value = crate::linking::decode_mutation(bytes, &shape).map_err(|_| invalid())?;
    let context: AdapterContext =
        serde_json::from_value(v["context"].clone()).map_err(|_| invalid())?;
    context.validate().map_err(|_| invalid())?;
    for k in [
        "join_review_id",
        "inspection_review_id",
        "consent_review_id",
    ] {
        if (k == "join_review_id" || v.get(k).is_some())
            && !v[k]
                .as_str()
                .is_some_and(|s| crate::peer_store::valid_id(s, "review", 32))
        {
            return Err(invalid());
        }
    }
    if op == "complete" && v["decision"] != "complete_machine_requester_commit" {
        return Err(invalid());
    }
    if cli
        && !v["flow_id"]
            .as_str()
            .is_some_and(|s| crate::peer_store::valid_id(s, "flow", 16))
        || !crate::onboarding_admission::safe(&v)
    {
        return Err(invalid());
    }
    Ok(v)
}
fn domain(e: codec::Error) -> Error {
    match e.code {
        "review_changed" => coded("review_changed"),
        "expired" | "review_expired" | "authority_expired" => coded("review_expired"),
        _ => coded("machine_requester_consent_unavailable"),
    }
}
impl Store {
    pub fn machine_requester_consent(
        &self,
        id: &str,
        op: &str,
        value: Value,
    ) -> Result<Value, Error> {
        if !crate::peer_store::valid_id(id, "flow", 16) {
            return Err(invalid());
        }
        let value = decode_input(
            &serde_json::to_vec(&value).map_err(|_| invalid())?,
            op,
            false,
        )?;
        let input = OwnerContext {
            context: serde_json::from_value(value["context"].clone()).map_err(|_| invalid())?,
            join_review_id: field(&value, "join_review_id")?.into(),
        };
        let mut c = self
            .connection()
            .map_err(|_| domain(codec::Error::new("internal")))?;
        let tx = c
            .transaction()
            .map_err(|_| domain(codec::Error::new("internal")))?;
        let (f, mut p, _, _) = bind_history(self, &tx, id, &input).map_err(|e| match e {
            Error::NotFound | Error::Invalid(_) => e,
            Error::Coded {
                code: "review_changed" | "request_unavailable",
                ..
            } => e,
            _ => domain(codec::Error::new("state_conflict")),
        })?;
        let expected = value[if op == "prepare" {
            "inspection_review_id"
        } else {
            "consent_review_id"
        }]
        .as_str();
        let scope = json!({"context":f.proposal.context,"agent":f.review["agent"],"flow_id":f.id,"join_review_id":f.review_id});
        let (result, changed) = crate::decentralized::machine_requester_consent_in(
            &tx,
            self,
            &mut p,
            &scope,
            op,
            expected,
            |p, prepared| {
                inspection_in(&tx, self, &f, p, &input, prepared).map_err(|e| match e {
                    Error::Coded {
                        code: "review_expired",
                        ..
                    } => codec::Error::new("review_expired"),
                    Error::Coded {
                        code: "review_changed",
                        ..
                    } => codec::Error::new("review_changed"),
                    _ => codec::Error::new("machine_requester_consent_unavailable"),
                })
            },
        )
        .map_err(domain)?;
        if changed {
            tx.commit()
                .map_err(|_| domain(codec::Error::new("internal")))?;
        }
        Ok(result)
    }
}
async fn run(
    s: Arc<Store>,
    id: String,
    b: Result<Bytes, BytesRejection>,
    op: &'static str,
) -> Result<Json<Value>, Error> {
    let value = decode_input(&b.map_err(|_| invalid())?, op, false)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        blocking(s, move |s| s.machine_requester_consent(&id, op, value)),
    )
    .await
    .map_err(|_| coded("machine_requester_consent_unavailable"))?
    .map(Json)
}
async fn lookup(
    State(s): State<Arc<Store>>,
    Path(id): Path<String>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, id, b, "lookup").await
}
async fn prepare(
    State(s): State<Arc<Store>>,
    Path(id): Path<String>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, id, b, "prepare").await
}
async fn approve(
    State(s): State<Arc<Store>>,
    Path(id): Path<String>,
    b: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    run(s, id, b, "approve").await
}
pub(super) fn routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/onboarding/join-flows/{id}/machine-commit/lookup",
            post(lookup),
        )
        .route(
            "/v1/onboarding/join-flows/{id}/machine-commit/prepare",
            post(prepare),
        )
        .route(
            "/v1/onboarding/join-flows/{id}/machine-commit/approve",
            post(approve),
        )
}
