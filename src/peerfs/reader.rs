//! The reader side of discovery (PeerFS read contract, section 7): the owner-local route
//! `fs branches --peer HOST` uses to ask another host what it shares with this one, and
//! that `fs pull` checks before it fetches anything.
use super::{coded, invalid, not_found, unavailable};
use crate::{
    api::blocking,
    decentralized,
    model::Error,
    peer_store::{Peer, valid_id},
    policy::{PolicyRef, peerfs_branch},
    store::Store,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Path, RawQuery, State,
        rejection::{BytesRejection, PathRejection},
    },
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

/// The most entries one discovery answer has (one policy's filesystem rules).
const MAX_ENTRIES: usize = 64;
/// How long a reader waits for another host's discovery answer, connecting included.
const ASK_BOUND: Duration = Duration::from_secs(10);

/// The owner-local route of `fs branches --peer HOST --network ID`.
pub(super) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route(
        "/v1/fs/peers/{host}/networks/{network}/branches",
        get(ask_branches),
    )
}

/// The discovery answer of another host, exactly as section 5 states it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answer {
    network: String,
    branches: Vec<AnswerEntry>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AnswerEntry {
    pub host: String,
    pub space: String,
    pub branch: String,
    pub policy: PolicyRef,
}

fn bad_gateway(message: &'static str) -> Error {
    coded(502, "bad_gateway", message)
}

/// Owner-local `GET /v1/fs/peers/{host}/networks/{network}/branches`: asks `host` what it
/// shares with this host in `network` (`GET /peer/v1/fs/branches`). A transport failure
/// or refusal is an error, never an empty list.
async fn ask_branches(
    State(store): State<Arc<Store>>,
    ids: Result<Path<(String, String)>, PathRejection>,
    RawQuery(query): RawQuery,
    input: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let Path((host, network)) = ids.map_err(|_| invalid())?;
    if !valid_id(&host, "host", 32)
        || !decentralized::codec::ident(&network, "net_")
        || query.is_some()
        || !input.map_err(|_| invalid())?.is_empty()
    {
        return Err(invalid());
    }
    let (_, branches) = discover(&store, &host, &network).await?;
    Ok(Json(
        json!({"host": host, "network": network, "branches": branches}),
    ))
}

/// Asks `host` what it shares with this host in `network` and checks the answer's exact
/// shape: the host's dial target and its entries. 400 for this host itself, 404 for an
/// unknown host, 503 without an answer, 502 for a refusal (with `peer_status`) or a
/// malformed answer.
pub(super) async fn discover(
    store: &Arc<Store>,
    host: &str,
    network: &str,
) -> Result<(Peer, Vec<AnswerEntry>), Error> {
    if host == store.identity().id {
        return Err(invalid());
    }
    let lookup = host.to_owned();
    let target = blocking(store.clone(), move |s| s.dial_target(&lookup))
        .await
        .map_err(|e| match e {
            Error::NotFound => not_found(),
            _ => unavailable(),
        })?;
    let path = format!("/peer/v1/fs/branches?network={network}");
    let (status, data) = match tokio::time::timeout(
        ASK_BOUND,
        crate::quic::request(store.clone(), &target, "GET", &path, b""),
    )
    .await
    {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) | Err(_) => return Err(unavailable()),
    };
    if status != 200 {
        let mut error = bad_gateway("the host refused the request");
        if let Error::Coded { extra, .. } = &mut error {
            extra.insert("peer_status".into(), json!(status));
        }
        return Err(error);
    }
    let answer: Answer = serde_json::from_slice(&data)
        .map_err(|_| bad_gateway("the host's answer is not a branch listing"))?;
    let sorted = answer
        .branches
        .windows(2)
        .all(|w| (&w[0].space, &w[0].branch) < (&w[1].space, &w[1].branch));
    let valid = answer.network == network
        && answer.branches.len() <= MAX_ENTRIES
        && sorted
        && answer.branches.iter().all(|e| {
            e.host == host
                && valid_id(&e.space, "space", 16)
                && peerfs_branch(&e.branch)
                && crate::policy::person_id_shape(&e.policy.person_id)
        });
    if !valid {
        return Err(bad_gateway("the host's answer is not a branch listing"));
    }
    Ok((target, answer.branches))
}
