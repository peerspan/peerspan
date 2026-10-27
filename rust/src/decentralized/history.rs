//! Public launch retains old protocol reads and exact signed-result settlement.
//! New legacy management never starts through the owner-local router.
use crate::store::Store;
use axum::{
    Json,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::sync::Arc;
pub(crate) fn legacy(
    store: &Store,
    c: &rusqlite::Connection,
    network: &str,
) -> Result<bool, crate::model::Error> {
    if !store.decentralized_runtime() {
        return Ok(false);
    }
    let mode: Option<String> = c.query_row(
        "SELECT json_extract(record,'$.mode') FROM networks WHERE id=?1",
        [network],
        |r| r.get(0),
    )?;
    Ok(mode.as_deref() != Some("decentralized"))
}
pub(crate) async fn gate(
    State(store): State<Arc<Store>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let legacy = path == "/v1/networks"
        || path.starts_with("/v1/networks/")
        || path == "/v1/link"
        || path.starts_with("/v1/link/")
        || path.starts_with("/peer/v1/networks/");
    if store.decentralized_runtime() && request.method() != Method::GET && legacy {
        let parts = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        let settlement = request.method() == Method::POST
            && matches!(
                parts.as_slice(),
                ["v1", "link", "requests", _, "resume" | "cancel"]
            );
        if !settlement {
            return (StatusCode::UPGRADE_REQUIRED,Json(json!({"code":"upgrade_required","error":"legacy network authority is retained for history and explicit migration only","details":{"network_id":"-","context_id":"-","request_id":"-","stage":"migration","required_ids":[],"conflict_ids":[],"next":[]}}))).into_response();
        }
    }
    next.run(request).await
}
