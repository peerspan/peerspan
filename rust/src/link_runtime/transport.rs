//! Pinned mailbox transport. Ciphertext metadata is never signing authority.
use super::{crypto, model::OutboundFrame, persistence, support::Failure};
use crate::{
    peer::{https_link, pinned_client_config},
    store::Store,
};
use anyhow::{Result, ensure};
use hyper::Method;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequencedFrame {
    pub sequence: u64,
    pub frame: crypto::Frame,
    #[serde(skip)]
    pub frame_bytes: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mailbox {
    pub request_id: String,
    pub locator: String,
    pub created_at: String,
    pub expires_at: String,
    pub next_sequence: u64,
    pub state: String,
    pub frames: Vec<SequencedFrame>,
}

pub(crate) fn decode_mailbox(raw: &[u8]) -> Result<Mailbox> {
    let mut mailbox: Mailbox = crate::linking::decode_mutation(
        raw,
        "request_id locator created_at expires_at next_sequence state frames",
    )?;
    type RawObject = std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>;
    let fields: RawObject = serde_json::from_slice(raw)?;
    let frames: Vec<RawObject> = serde_json::from_str(
        fields
            .get("frames")
            .ok_or_else(|| Failure::new("invalid", "-", "mailbox"))?
            .get(),
    )?;
    let created = super::support::stamp(&mailbox.created_at)?;
    let expires = super::support::stamp(&mailbox.expires_at)?;
    ensure!(
        crypto::id(&mailbox.request_id, "link_")
            && crypto::id(&mailbox.locator, "")
            && expires == created + chrono::Duration::seconds(300)
            && mailbox.frames.len() <= 64
            && (1..=65).contains(&mailbox.next_sequence)
            && matches!(mailbox.state.as_str(), "open" | "expired" | "deleted"),
        Failure::new("invalid", &mailbox.request_id, "mailbox")
    );
    let mut total = 0usize;
    let mut previous = 0;
    for (frame, fields) in mailbox.frames.iter_mut().zip(frames) {
        frame.frame_bytes = fields
            .get("frame")
            .ok_or_else(|| Failure::new("invalid", "-", "mailbox"))?
            .get()
            .as_bytes()
            .to_vec();
        total += frame.frame_bytes.len();
        ensure!(
            frame.sequence > previous
                && frame.sequence < mailbox.next_sequence
                && frame.frame.request_id == mailbox.request_id
                && frame.frame.locator == mailbox.locator
                && total <= 512 << 10,
            Failure::new("invalid", &mailbox.request_id, "mailbox")
        );
        previous = frame.sequence;
    }
    Ok(mailbox)
}

pub async fn request(
    store: Arc<Store>,
    address: &str,
    key: &str,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>> {
    ensure!(
        body.len() <= 1 << 20,
        Failure::new("quota_exceeded", "-", "transport")
    );
    let raw_key = crate::membership::canonical(key, 32)?;
    let (host, _) = crate::membership::split_host_port(address)?;
    let config = pinned_client_config(store, raw_key, b"http/1.1")?;
    let name = rustls::pki_types::ServerName::try_from(host)?;
    let (status, headers, body) = tokio::time::timeout(
        Duration::from_secs(8),
        https_link(config, address, name, method, path, body),
    )
    .await
    .map_err(|_| Failure::new("unavailable", "-", "transport"))??;
    ensure!(
        body.len() <= 16 << 20,
        Failure::new("invalid", "-", "transport")
    );
    if !(200..=299).contains(&status) {
        let decoded = crate::linking::decode_mutation::<Failure>(&body, "code error details");
        let authenticated_response = decoded
            .as_ref()
            .is_ok_and(|failure| status < 500 && failure.status().as_u16() == status);
        let mut error = decoded.unwrap_or_else(|_| {
            Failure::new(
                if status == 404 {
                    "not_found"
                } else if status == 410 {
                    "expired"
                } else if status == 429 {
                    "rate_limited"
                } else {
                    "unavailable"
                },
                "-",
                "transport",
            )
        });
        error.authenticated_response = authenticated_response;
        error.retry_after = headers
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        return Err(error.into());
    }
    Ok(body)
}

async fn load(store: Arc<Store>, id: String) -> Result<persistence::Pending> {
    tokio::task::spawn_blocking(move || {
        let c = store.connection()?;
        persistence::pending(&c, &id)?
            .ok_or_else(|| Failure::new("not_found", &id, "request").into())
    })
    .await?
}

fn frame_bytes(store: &Store, id: &str, reference: &OutboundFrame) -> Result<Vec<u8>> {
    let connection = store.connection()?;
    let raw:String=connection.query_row("SELECT record FROM link_frames WHERE request_id=?1 AND role=?2 AND writer_key=?3 AND frame_id=?4",rusqlite::params![id,reference.role,reference.writer_public_key,reference.frame_id],|r|r.get(0))?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Record {
        frame_base64: String,
    }
    let record: Record = crate::linking::decode_stored_json(raw.as_bytes(), "frame_base64")?;
    let bytes = crypto::bytes(&record.frame_base64, 1 << 20)?;
    let frame: crypto::Frame = crate::linking::decode_mutation(
        &bytes,
        "format request_id locator role writer_public_key frame_id ciphertext",
    )?;
    ensure!(
        frame.request_id == id
            && frame.role == reference.role
            && frame.writer_public_key == reference.writer_public_key
            && frame.frame_id == reference.frame_id,
        Failure::new("state_conflict", id, "storage")
    );
    Ok(bytes)
}

/// Replays persisted exact frames; no call here generates a frame ID or nonce.
pub async fn publish(store: Arc<Store>, id: &str) -> Result<()> {
    let pending = load(store.clone(), id.into()).await?;
    let secret = pending
        .secret
        .ok_or_else(|| Failure::new("expired", id, "transport"))?;
    for reference in pending
        .record
        .outbound_frames
        .iter()
        .filter(|f| !f.published)
    {
        let lookup = id.to_owned();
        let reference_copy = reference.clone();
        let reader = store.clone();
        let raw =
            tokio::task::spawn_blocking(move || frame_bytes(&reader, &lookup, &reference_copy))
                .await??;
        let path = if reference.role == "request" {
            "/coord/v2/link-mailboxes".into()
        } else {
            format!(
                "/coord/v2/link-mailboxes/{}/frames",
                crypto::locator(&secret)
            )
        };
        let mut body = b"{\"frame\":".to_vec();
        body.extend_from_slice(&raw);
        if reference.role == "request" {
            let request = crypto::bytes(
                &pending.record.request_packet_base64,
                crate::linking::MAX_OBJECT,
            )?;
            let packet: super::request::Packet = crate::linking::decode_mutation(
                &request,
                "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature",
            )?;
            let payload: serde_json::Value = serde_json::from_slice(&crypto::bytes(
                &packet.payload_base64,
                crate::linking::MAX_PAYLOAD,
            )?)?;
            body.extend_from_slice(b",\"created_at\":");
            body.extend_from_slice(&serde_json::to_vec(&payload["created_at"])?);
            body.extend_from_slice(b",\"expires_at\":");
            body.extend_from_slice(&serde_json::to_vec(&pending.deadline)?);
        }
        body.push(b'}');
        let response = request(
            store.clone(),
            &pending.record.coordinator_address,
            &pending.record.coordinator_public_key,
            Method::POST,
            &path,
            body,
        )
        .await?;
        let sequence = if reference.role == "request" {
            let mailbox = decode_mailbox(&response)?;
            ensure!(
                mailbox.request_id == id
                    && mailbox.locator == crypto::locator(&secret)
                    && mailbox.expires_at == pending.deadline,
                Failure::new("invalid", id, "mailbox")
            );
            mailbox
                .frames
                .iter()
                .find(|f| {
                    f.frame.frame_id == reference.frame_id
                        && f.frame.role == reference.role
                        && f.frame.writer_public_key == reference.writer_public_key
                })
                .map(|f| f.sequence)
                .ok_or_else(|| Failure::new("invalid", id, "mailbox"))?
        } else {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Sequence {
                sequence: u64,
            }
            let response: Sequence = crate::linking::decode_mutation(&response, "sequence")?;
            response.sequence
        };
        ensure!(sequence > 0, Failure::new("invalid", id, "mailbox"));
        let writer = store.clone();
        let id = id.to_owned();
        let role = reference.role.clone();
        let frame_id = reference.frame_id.clone();
        let writer_key = reference.writer_public_key.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut c = writer.connection()?;
            let tx = c.transaction()?;
            let mut p = persistence::pending(&tx, &id)?
                .ok_or_else(|| Failure::new("state_conflict", &id, "storage"))?;
            let f = p
                .record
                .outbound_frames
                .iter_mut()
                .find(|f| {
                    f.role == role && f.frame_id == frame_id && f.writer_public_key == writer_key
                })
                .ok_or_else(|| Failure::new("state_conflict", &id, "storage"))?;
            ensure!(
                f.sequence == 0 || f.sequence == sequence,
                Failure::new("operation_conflict", &id, "frame")
            );
            f.published = true;
            f.sequence = sequence;
            persistence::save_pending(&tx, &p)?;
            tx.commit()?;
            Ok(())
        })
        .await??;
    }
    Ok(())
}

pub async fn poll(
    store: Arc<Store>,
    id: &str,
) -> Result<Option<(Mailbox, chrono::DateTime<chrono::Utc>)>> {
    let p = load(store.clone(), id.into()).await?;
    let secret = p
        .secret
        .ok_or_else(|| Failure::new("expired", id, "transport"))?;
    let at = super::support::now()?;
    if recent_poll(
        &store,
        &p.record.coordinator_public_key,
        &crypto::locator(&secret),
        at,
    )? {
        return Ok(None);
    }
    let path = format!(
        "/coord/v2/link-mailboxes/{}?after={}",
        crypto::locator(&secret),
        p.record.after_sequence
    );
    poll_slot(
        &store,
        &p.record.coordinator_public_key,
        &crypto::locator(&secret),
    )
    .await?;
    let raw = request(
        store,
        &p.record.coordinator_address,
        &p.record.coordinator_public_key,
        Method::GET,
        &path,
        Vec::new(),
    )
    .await?;
    let mailbox = decode_mailbox(&raw)?;
    ensure!(
        mailbox.request_id == id
            && mailbox.locator == crypto::locator(&secret)
            && mailbox.expires_at == p.deadline
            && matches!(mailbox.state.as_str(), "open" | "expired" | "deleted")
            && mailbox.next_sequence > p.record.after_sequence,
        Failure::new("invalid", id, "mailbox")
    );
    let mut previous = p.record.after_sequence;
    for f in &mailbox.frames {
        ensure!(
            f.sequence > previous
                && f.sequence < mailbox.next_sequence
                && f.frame.request_id == id
                && f.frame.locator == mailbox.locator,
            Failure::new("invalid", id, "mailbox")
        );
        previous = f.sequence;
    }
    Ok(Some((mailbox, at)))
}

pub fn recent_poll(
    store: &Store,
    coordinator: &str,
    locator: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    Ok(store
        .link_successful_polls
        .lock()
        .map_err(|_| Failure::new("internal", "-", "poll"))?
        .get(&format!("{coordinator}:{locator}"))
        .is_some_and(|last| at >= *last && at - *last < chrono::Duration::seconds(2)))
}

pub fn record_poll(
    store: &Store,
    coordinator: &str,
    locator: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    store
        .link_successful_polls
        .lock()
        .map_err(|_| Failure::new("internal", "-", "poll"))?
        .insert(format!("{coordinator}:{locator}"), at);
    Ok(())
}

pub async fn delete(store: Arc<Store>, id: &str) -> Result<()> {
    let p = load(store.clone(), id.into()).await?;
    let Some(secret) = p.secret else {
        return Ok(());
    };
    request(
        store,
        &p.record.coordinator_address,
        &p.record.coordinator_public_key,
        Method::DELETE,
        &format!("/coord/v2/link-mailboxes/{}", crypto::locator(&secret)),
        Vec::new(),
    )
    .await?;
    Ok(())
}

pub async fn poll_slot(store: &Store, coordinator: &str, locator: &str) -> Result<()> {
    let now = std::time::Instant::now();
    let due = {
        let mut polls = store
            .link_polls
            .lock()
            .map_err(|_| Failure::new("internal", "-", "transport"))?;
        let key = format!("{coordinator}:{locator}");
        let due = polls
            .get(&key)
            .map(|last| (*last + Duration::from_secs(2)).max(now))
            .unwrap_or(now);
        polls.insert(key, due);
        due
    };
    tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
    Ok(())
}
