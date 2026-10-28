//! The invite's automatic return path (spec 8.1 step 4, DEC-Q3, DEC-Q26,
//! DEC-Q32; wire section 10.1). The inviter keeps the invite's return secret
//! in a `dec_pending` row keyed by the invitation ID until the invite
//! expires; such rows are not join requests and do not count toward the 8
//! active requests. The joiner seals its request code as one `request` frame
//! under keys derived from that secret and the invitation ID and posts it to
//! the mailbox at the derived locator, on the inviter's first-contact address
//! and on each helper in the invite. The inviter reads those mailboxes and
//! records the request, as if its code had been entered there, so it waits
//! for `link approve` / `link admit` with no hand-carried code.
use super::{
    bootstrap::{self, Frame, Invitation, PairingToken},
    bootstrap_io,
    codec::*,
    controls, requests,
};
use crate::store::Store;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::Method;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::Arc;

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
/// Keep the return secret of a new invite until it expires (DEC-Q26).
pub(crate) fn remember(c: &Connection, invite: &Invitation, secret: &[u8; 16]) -> Result<()> {
    cleanup(c, &controls::local_decision_time()?)?;
    total_below_limit(c)?;
    let record = json!({"format":1,"kind":"invite_return","network_id":invite.descriptor.network_id,"invitation_base64":encode(&invite.body)});
    c.execute(
        "INSERT INTO dec_pending(request_id,deadline,record,secret,terminal_read_cap) VALUES(?1,?2,?3,?4,NULL)",
        rusqlite::params![invite.id, invite.expires_at, record.to_string(), secret.as_slice()],
    )
    .map_err(db)?;
    Ok(())
}
/// At most 4096 pending rows of any kind (spec 8.7, DEC-Q32).
fn total_below_limit(c: &Connection) -> Result<()> {
    let total: i64 = c
        .query_row("SELECT COUNT(*) FROM dec_pending", [], |r| r.get(0))
        .map_err(db)?;
    require(total < 4096, "quota_exceeded")
}
/// Forget return secrets of expired invites.
pub(crate) fn cleanup(c: &Connection, now: &str) -> Result<()> {
    c.execute(
        "DELETE FROM dec_pending WHERE request_id GLOB 'di_*' AND deadline<=?1",
        [now],
    )
    .map_err(db)?;
    Ok(())
}
/// The inviter's first-contact addresses and the invite's helpers.
fn endpoints(invite: &Invitation) -> Result<Vec<Value>> {
    let mut endpoints = invite
        .helpers
        .iter()
        .map(|h| json!({"kind":"helper","address":h["address"],"public_key":h["public_key"]}))
        .collect::<Vec<_>>();
    for contact in &invite.contacts {
        for address in array(object(&contact.payload)?, "bootstrap_addresses")? {
            endpoints.push(json!({"kind":"participant","address":address,"public_key":contact.host_public_key}));
        }
    }
    endpoints.dedup();
    endpoints.truncate(8);
    Ok(endpoints)
}
/// The joiner's side: post the request code through the invite's return
/// path. `Ok(true)` when at least one mailbox took it.
pub(crate) async fn send(store: Arc<Store>, request: &str) -> Result<bool> {
    let capture = store.clone();
    let id = request.to_owned();
    let prepared =
        tokio::task::spawn_blocking(move || -> Result<Option<(Frame, String, Vec<Value>)>> {
            let c = capture.connection().map_err(|_| Error::new("internal"))?;
            let p = requests::load(&c, &id)?;
            if p.record.contact_invitation_base64 == "-"
                || !p.record.roles.iter().any(|r| r == "requester")
            {
                return Ok(None);
            }
            let created = text(&p.packet()?.payload, "created_at")?.to_owned();
            let invite = Invitation::read(
                &b64(&p.record.contact_invitation_base64, 32 << 10)?,
                &created,
            )?;
            let Some(secret) = invite.return_secret else {
                return Ok(None);
            };
            let now = controls::local_decision_time()?;
            let Some(code) = p.code(&c, &now)? else {
                return Ok(None);
            };
            let raw = URL_SAFE_NO_PAD
                .decode(
                    code.strip_prefix("psl2-")
                        .ok_or_else(|| Error::new("internal"))?,
                )
                .map_err(|_| Error::new("internal"))?;
            let frame = Frame::seal(
                &secret,
                &invite.id,
                "request",
                &capture.signing_key,
                (&invite.issued_at, &invite.expires_at),
                &now,
                &json!({"packet_base64":encode(&raw),"catalog_base64":"-","contacts":[]}),
            )?;
            Ok(Some((
                frame,
                bootstrap::read_cap(&secret),
                endpoints(&invite)?,
            )))
        })
        .await
        .map_err(|_| Error::new("internal"))??;
    let Some((frame, cap, endpoints)) = prepared else {
        return Ok(false);
    };
    let mut tasks = tokio::task::JoinSet::new();
    for endpoint in endpoints {
        let store = store.clone();
        let frame = frame.clone();
        let cap = cap.clone();
        tasks.spawn(async move {
            let created = bootstrap_io::exchange(
                store.clone(),
                &endpoint,
                Method::POST,
                "/bootstrap/v1/mailboxes".into(),
                &cap,
                bootstrap_io::creation_body(&frame, &cap)?,
            )
            .await
            .and_then(bootstrap_io::success);
            if created.is_ok() {
                return Ok(());
            }
            // The invite's mailbox may already exist (another joiner used
            // the same invite): append to it.
            bootstrap_io::exchange(
                store,
                &endpoint,
                Method::POST,
                format!("/bootstrap/v1/mailboxes/{}/frames", frame.locator),
                &cap,
                bootstrap_io::append_body(&frame)?,
            )
            .await
            .and_then(bootstrap_io::success)
            .map(|_| ())
        });
    }
    let mut sent = false;
    while let Some(result) = tasks.join_next().await {
        sent |= matches!(result, Ok(Ok(())));
    }
    Ok(sent)
}
struct Waiting {
    invite: Invitation,
    secret: [u8; 16],
}
fn waiting(store: &Store) -> Result<Vec<Waiting>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let now = controls::local_decision_time()?;
    cleanup(&c, &now)?;
    let mut q = c
        .prepare("SELECT record,secret FROM dec_pending WHERE request_id GLOB 'di_*' AND deadline>?1 ORDER BY request_id")
        .map_err(db)?;
    let rows = q
        .query_map([&now], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
        })
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    let mut out = Vec::new();
    for (record, secret) in rows {
        let v = parse(record.as_bytes(), 64 << 10)?;
        let Some(Ok(secret)) = secret.map(<[u8; 16]>::try_from) else {
            continue;
        };
        let raw = b64(text(object(&v)?, "invitation_base64")?, 32 << 10)?;
        let Ok(invite) = Invitation::read(&raw, &now) else {
            continue;
        };
        out.push(Waiting { invite, secret });
    }
    Ok(out)
}
/// Record a returned request as waiting for approval here, unless it is
/// already known.
fn import(store: &Store, invite: &Invitation, code: &PairingToken) -> Result<bool> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    match requests::load(&tx, &code.request_id) {
        Ok(_) => return Ok(false),
        Err(e) if e.code == "not_found" => {}
        Err(e) => return Err(e),
    }
    let packet = super::transcript::Packet::read(&code.request_packet)?;
    let p = &packet.payload;
    let network = text(p, "expected_network_id")?;
    let person = text(p, "expected_person_public_key")?;
    check(
        text(p, "mode")? == "new"
            && (network == "-" || network == invite.descriptor.network_id)
            && (invite.expected_person_public_key == "-"
                || person == invite.expected_person_public_key),
    )?;
    // Expired requests release their active slots first.
    requests::cleanup(&tx, &controls::local_decision_time()?)?;
    let active: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM dec_pending WHERE request_id GLOB 'link_*' AND json_extract(record,'$.terminal') IN ('-','migration_prepared')",
            [],
            |r| r.get(0),
        )
        .map_err(db)?;
    require(active < 8, "quota_exceeded")?;
    total_below_limit(&tx)?;
    let mut pending = super::ceremony::from_code(code, &invite.descriptor)?;
    pending.record.roles = vec!["administrator".into()];
    // The requester also posted its request to the invite's mailboxes; read
    // them too, for a requester this host cannot reach.
    for endpoint in endpoints(invite)? {
        if !pending.record.carrier_endpoints.contains(&endpoint)
            && pending.record.carrier_endpoints.len() < 8
        {
            pending.record.carrier_endpoints.push(endpoint);
        }
    }
    pending.record.carrier_endpoints.sort_by_key(|e| {
        (
            e["kind"].as_str().unwrap_or_default().to_owned(),
            e["address"].as_str().unwrap_or_default().to_owned(),
            e["public_key"].as_str().unwrap_or_default().to_owned(),
        )
    });
    requests::save(&tx, &pending)?;
    tx.commit().map_err(db)?;
    Ok(true)
}
/// The inviter's side: read each live invite's return mailboxes and record
/// the requests found there.
pub(crate) async fn receive(store: Arc<Store>) {
    let capture = store.clone();
    let Ok(Ok(list)) = tokio::task::spawn_blocking(move || waiting(&capture)).await else {
        return;
    };
    // Rotate the starting invite each pass and stop reading an endpoint for
    // this pass once it rate-limits (one GET per second, burst 4), so every
    // live invite is read in turn.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let mut list = list;
    if !list.is_empty() {
        let start = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % list.len();
        list.rotate_left(start);
    }
    let mut limited = std::collections::BTreeSet::new();
    for w in list {
        let Ok(endpoints) = endpoints(&w.invite) else {
            continue;
        };
        let cap = bootstrap::read_cap(&w.secret);
        let locator = bootstrap::locator(&w.secret);
        for endpoint in endpoints {
            let target = (
                endpoint["address"].to_string(),
                endpoint["public_key"].to_string(),
            );
            if limited.contains(&target) {
                continue;
            }
            let body = match bootstrap_io::exchange(
                store.clone(),
                &endpoint,
                Method::GET,
                format!("/bootstrap/v1/mailboxes/{locator}"),
                &cap,
                Vec::new(),
            )
            .await
            .and_then(bootstrap_io::success)
            {
                Ok(body) => body,
                Err(e) => {
                    if e.code == "rate_limited" {
                        limited.insert(target);
                    }
                    continue;
                }
            };
            let Ok(now) = controls::local_decision_time() else {
                continue;
            };
            let Ok(value) = parse(&body, 64 << 20) else {
                continue;
            };
            let frames = value
                .get("frames")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for raw in frames {
                let Some(code) = (|| -> Result<PairingToken> {
                    let frame =
                        Frame::read(&serde_json::to_vec(&raw).map_err(|_| Error::new("invalid"))?)?;
                    check(frame.request_id == w.invite.id && frame.role == "request")?;
                    let plain = frame.open(&w.secret, &now)?;
                    let code = b64(text(object(&plain)?, "packet_base64")?, 32 << 10)?;
                    PairingToken::read(&format!("psl2-{}", URL_SAFE_NO_PAD.encode(&code)), &now)
                })()
                .ok() else {
                    continue;
                };
                let target = store.clone();
                let invite = w.invite.clone();
                let id = code.request_id.clone();
                let imported =
                    tokio::task::spawn_blocking(move || import(&target, &invite, &code)).await;
                if matches!(imported, Ok(Ok(true))) {
                    // Read the request's own mailbox at once, so its frames
                    // (and the code) are here for `link admit REQUEST_ID`.
                    let _ = super::requests_io::poll(store.clone(), &id).await;
                    // This read must not count as a recent poll: the next
                    // command on the request reads the mailbox again.
                    if let Ok(mut polls) = store.bootstrap_polls.lock() {
                        polls.retain(|key, _| key.0 != id);
                    }
                }
            }
        }
    }
}
/// Reads the return mailboxes of live invites every second.
pub(crate) async fn worker(store: Arc<Store>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    tick.tick().await;
    loop {
        tokio::select! {_ = shutdown.changed()=>break,_=tick.tick()=>{}}
        receive(store.clone()).await;
    }
}
/// `link_request_waiting` (spec 8.1 step 5, 16): join requests for this
/// network that this host holds as approver and has not approved yet.
pub(crate) fn waiting_items(
    c: &Connection,
    network: &str,
) -> Result<Vec<(String, String, String, String)>> {
    let now = controls::local_decision_time()?;
    let mut q = c
        .prepare("SELECT request_id FROM dec_pending WHERE request_id GLOB 'link_*' AND deadline>?1 ORDER BY request_id")
        .map_err(db)?;
    let ids = q
        .query_map([&now], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    let mut out = Vec::new();
    for id in ids {
        let Ok(p) = requests::load(c, &id) else {
            continue;
        };
        let r = &p.record;
        if r.terminal != "-"
            || r.roles.iter().any(|role| role == "requester")
            || r.owner_intent_id != "-"
            || r.administrator_intent_id != "-"
            || !(r.expected_network_id == network || r.expected_network_id == "-")
        {
            continue;
        }
        // The owner reviews first (spec 8.3); the administrator admits
        // after the owner offer and the requester's selection.
        let command = if r.owner_offer_id != "-" && r.selection_id != "-" {
            format!(
                "peerspan link admit {id} --network {network} --owner-offer {} --selection {}",
                r.owner_offer_id, r.selection_id
            )
        } else {
            format!("peerspan link approve {id} --network {network}")
        };
        out.push((
            "link_request_waiting".into(),
            network.into(),
            format!("join request {id} waits for approval on this host"),
            command,
        ));
    }
    Ok(out)
}
