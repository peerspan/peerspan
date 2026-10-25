//! Unix-only linking routes. The peer router never mounts these handlers.
use super::{
    approve, ceremony, crypto, finalize,
    model::{Commit, CreateRequest, Select},
    persistence, request,
    support::{self, Failure},
    transport,
};
use crate::store::Store;
use anyhow::Result;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::StatusCode,
    routing::{get, post},
};
use serde_json::Value;
use std::sync::Arc;

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .merge(super::provider::routes())
        .merge(super::feature::routes())
        .merge(super::recovery::routes())
        .merge(super::approve::routes())
        .route("/v1/link/requests", get(list).post(create))
        .route("/v1/link/requests/{id}", get(status))
        .route("/v1/link/requests/{id}/resume", post(resume))
        .route("/v1/link/requests/{id}/cancel", post(cancel))
        .route("/v1/link/requests/{id}/selection", post(select))
        .route("/v1/link/requests/{id}/commit", post(commit))
}

fn decode<T: serde::de::DeserializeOwned>(
    body: Result<Bytes, BytesRejection>,
    fields: &str,
    id: &str,
) -> Result<T, Failure> {
    let body = body.map_err(|_| Failure::new("invalid", id, "request"))?;
    crate::linking::decode_mutation(&body, fields)
        .map_err(|_| Failure::new("invalid", id, "request"))
}
async fn blocking<T: Send + 'static>(
    store: Arc<Store>,
    id: &str,
    f: impl FnOnce(&Store) -> Result<T> + Send + 'static,
) -> Result<T, Failure> {
    tokio::task::spawn_blocking(move || f(&store))
        .await
        .map_err(|_| Failure::new("internal", id, "storage"))?
        .map_err(|e| Failure::cause(e, id, "storage"))
}
async fn public(store: Arc<Store>, id: &str, code: bool) -> Result<Value, Failure> {
    let lookup = id.to_owned();
    blocking(store, id, move |s| {
        let p = {
            let c = s.connection()?;
            persistence::pending(&c, &lookup)?
                .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?
        };
        let mut view = serde_json::to_value(request::view(s, &p)?)?;
        if code
            && !matches!(p.state.as_str(), "linked" | "cancelled" | "expired")
            && support::now()? < support::stamp(&p.deadline)?
            && let Some(secret) = p.secret
        {
            view.as_object_mut()
                .ok_or_else(|| Failure::new("internal", &lookup, "view"))?
                .insert(
                    "display_code".into(),
                    Value::String(crypto::display_code(&secret)),
                );
        }
        Ok(view)
    })
    .await
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Failure> {
    let request: CreateRequest = decode(
        body,
        "mode network_id person_public_key coordinator_address coordinator_public_key",
        "-",
    )?;
    let _guard = store.link_mutation.lock().await;
    let (id, fresh) = blocking(store.clone(), "-", move |s| request::create(s, request)).await?;
    if fresh {
        support::barrier("host.request.after_commit", &id, std::future::pending()).await?;
        support::barrier("host.frame.after_commit", &id, std::future::pending()).await?;
    }
    transport::publish(store.clone(), &id)
        .await
        .map_err(|e| Failure::cause(e, &id, "publish"))?;
    Ok((
        StatusCode::CREATED,
        Json(public(store.clone(), &id, true).await?),
    ))
}
async fn list(State(store): State<Arc<Store>>) -> Result<Json<Value>, Failure> {
    let ids = blocking(store.clone(), "-", |s| {
        let c = s.connection()?;
        let mut q = c.prepare("SELECT request_id FROM link_pending ORDER BY request_id")?;
        Ok(q.query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    })
    .await?;
    let mut views = Vec::new();
    for id in ids {
        views.push(public(store.clone(), &id, false).await?);
    }
    Ok(Json(Value::Array(views)))
}
async fn status(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Failure> {
    if !crypto::id(&id, "link_") {
        return Err(Failure::new("invalid", &id, "request"));
    }
    Ok(Json(public(store, &id, false).await?))
}
pub(crate) async fn resume(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let _: serde_json::Map<String, Value> = decode(body, "", &id)?;
    let _guard = store.link_mutation.lock().await;
    let lookup = id.clone();
    let pending = blocking(store.clone(), &id, move |s| {
        let c = s.connection()?;
        persistence::pending(&c, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request").into())
    })
    .await?;
    if pending.record.commit_approved {
        finalize::finish(store.clone(), &id)
            .await
            .map_err(|e| Failure::cause(e, &id, "finalize"))?;
        return Ok(Json(public(store.clone(), &id, false).await?));
    }
    if support::now()?
        >= support::stamp(&pending.deadline)
            .map_err(|_| Failure::new("internal", &id, "storage"))?
        && !matches!(pending.state.as_str(), "linked" | "cancelled" | "expired")
    {
        let lookup = id.clone();
        blocking(store.clone(), &id, move |s| {
            let mut c = s.connection()?;
            let tx = c.transaction()?;
            let mut p = persistence::pending(&tx, &lookup)?
                .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
            p.state = "expired".into();
            p.secret = None;
            tx.execute("DELETE FROM link_frames WHERE request_id=?1", [&lookup])?;
            persistence::save_pending(&tx, &p)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
        return Ok(Json(public(store.clone(), &id, false).await?));
    }
    if matches!(pending.state.as_str(), "linked" | "cancelled" | "expired") {
        return Ok(Json(public(store.clone(), &id, false).await?));
    }
    if pending.role != "approver" {
        transport::publish(store.clone(), &id)
            .await
            .map_err(|e| Failure::cause(e, &id, "publish"))?;
    }
    let mailbox = transport::poll(store.clone(), &id)
        .await
        .map_err(|e| Failure::cause(e, &id, "poll"))?;
    if let Some((mailbox, polled_at)) = mailbox {
        let lookup = id.clone();
        let retained = blocking(store.clone(), &id, move |s| {
            let mut c = s.connection()?;
            let tx = c.transaction()?;
            let mut p = persistence::pending(&tx, &lookup)?
                .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
            let locator = p.secret.map(|secret| crypto::locator(&secret));
            let mut retained = false;
            for frame in mailbox.frames {
                retained |= persistence::store_frame(&tx, &frame.frame, &frame.frame_bytes)?;
                p.record.after_sequence = p.record.after_sequence.max(frame.sequence);
            }
            if mailbox.state != "open" && !p.record.commit_approved {
                p.state = if mailbox.state == "deleted" {
                    "cancelled"
                } else {
                    "expired"
                }
                .into();
                p.secret = None;
                tx.execute("DELETE FROM link_frames WHERE request_id=?1", [&lookup])?;
                retained = false;
            }
            persistence::save_pending(&tx, &p)?;
            tx.commit()?;
            if let Some(locator) = locator {
                transport::record_poll(s, &p.record.coordinator_public_key, &locator, polled_at)?;
            }
            Ok(retained)
        })
        .await?;
        if retained {
            support::barrier("host.frame.after_commit", &id, std::future::pending()).await?;
        }
    }
    if pending.role == "approver" {
        approve::resume_after_poll(store.clone(), &id)
            .await
            .map_err(|e| Failure::cause(e, &id, "intent"))?;
    } else {
        let lookup = id.clone();
        blocking(store.clone(), &id, move |s| ceremony::observe(s, &lookup)).await?;
    }
    Ok(Json(public(store.clone(), &id, true).await?))
}
async fn cancel(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let _: serde_json::Map<String, Value> = decode(body, "", &id)?;
    let _guard = store.link_mutation.lock().await;
    let lookup = id.clone();
    let p = blocking(store.clone(), &id, move |s| {
        let c = s.connection()?;
        persistence::pending(&c, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request").into())
    })
    .await?;
    if p.record.commit_approved || p.state == "linked" {
        return Ok(Json(public(store.clone(), &id, false).await?));
    }
    if p.role != "approver" && p.secret.is_some() {
        transport::delete(store.clone(), &id)
            .await
            .map_err(|e| Failure::cause(e, &id, "cancel"))?;
    }
    let lookup = id.clone();
    blocking(store.clone(), &id, move |s| {
        let mut c = s.connection()?;
        let tx = c.transaction()?;
        let mut p = persistence::pending(&tx, &lookup)?
            .ok_or_else(|| Failure::new("not_found", &lookup, "request"))?;
        p.state = if p.role == "approver"
            && (p.record.owner_packet_base64 != "-" || p.record.administrator_packet_base64 != "-")
        {
            "offer_sent"
        } else {
            "cancelled"
        }
        .into();
        p.secret = None;
        tx.execute("DELETE FROM link_frames WHERE request_id=?1", [&lookup])?;
        persistence::save_pending(&tx, &p)?;
        tx.commit()?;
        Ok(())
    })
    .await?;
    Ok(Json(public(store.clone(), &id, false).await?))
}

async fn select(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let request: Select = decode(
        body,
        "owner_offer_id network_id person_public_key host_public_key device_public_key approve",
        &id,
    )?;
    let approve = request.approve;
    let _guard = store.link_mutation.lock().await;
    let lookup = id.clone();
    let result = blocking(store.clone(), &id, move |s| {
        ceremony::select(s, &lookup, request)
    })
    .await?;
    if approve {
        support::barrier("host.selection.after_commit", &id, std::future::pending()).await?;
        support::barrier("host.frame.after_commit", &id, std::future::pending()).await?;
        transport::publish(store.clone(), &id)
            .await
            .map_err(|e| Failure::cause(e, &id, "publish"))?;
    }
    Ok(Json(result))
}
async fn commit(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Failure> {
    let request: Commit = decode(
        body,
        "owner_offer_id selection_id administrator_offer_id network_id person_public_key host_public_key device_public_key approve",
        &id,
    )?;
    let approve = request.approve;
    let _guard = store.link_mutation.lock().await;
    let lookup = id.clone();
    let mut result = blocking(store.clone(), &id, move |s| {
        ceremony::commit(s, &lookup, request)
    })
    .await?;
    if approve && result["request"]["state"] != "linked" {
        support::barrier("host.finalize.after_commit", &id, std::future::pending()).await?;
        support::barrier("host.frame.after_commit", &id, std::future::pending()).await?;
        transport::publish(store.clone(), &id)
            .await
            .map_err(|e| Failure::cause(e, &id, "publish"))?;
        finalize::finish(store.clone(), &id)
            .await
            .map_err(|e| Failure::cause(e, &id, "finalize"))?;
        result["request"] = public(store.clone(), &id, false).await?;
    }
    Ok(Json(result))
}
