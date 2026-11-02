//! Exact-frame delivery after local durable commits. Carrier acknowledgements
//! update only delivery metadata, never consent, authority or the frame bytes.
use super::{
    bootstrap::{self, Frame},
    bootstrap_io,
    codec::*,
    controls, observer, requests,
};
use crate::store::Store;
use hyper::Method;
use serde_json::{Value, json, value::RawValue};
use std::{collections::BTreeMap, sync::Arc};

struct Plan {
    id: String,
    locator: String,
    created_at: String,
    expires_at: String,
    cap: String,
    endpoints: Vec<Value>,
    frames: Vec<Frame>,
    outbound: Vec<Value>,
    terminal: bool,
}

/// Opaque immutable private GET plan, prepared under the guided caller's
/// preflight snapshot. This path never acknowledges, publishes or learns contacts.
pub(crate) struct IncomingPlan(Plan, [u8; 16]);
pub(crate) fn incoming_plan(
    c: &rusqlite::Connection,
    p: &requests::Pending,
) -> Result<IncomingPlan> {
    let secret = p.secret.ok_or_else(|| Error::new("recovery_required"))?;
    require(
        !p.record.carrier_endpoints.is_empty() && p.record.carrier_endpoints.len() <= 8,
        "recovery_required",
    )?;
    // Check existing frames without doing cleanup or changing poll metadata.
    require(
        requests::frames(c, p)?
            .iter()
            .all(|f| incoming_role(&f.role)),
        "state_conflict",
    )?;
    Ok(IncomingPlan(
        Plan {
            id: p.id.clone(),
            locator: bootstrap::locator(&secret),
            created_at: text(&p.packet()?.payload, "created_at")?.into(),
            expires_at: p.deadline.clone(),
            cap: bootstrap::read_cap(&secret),
            endpoints: p.record.carrier_endpoints.clone(),
            frames: Vec::new(),
            outbound: Vec::new(),
            terminal: false,
        },
        secret,
    ))
}
pub(crate) fn incoming_role(role: &str) -> bool {
    matches!(role, "request" | "owner" | "selection" | "proofs")
}
pub(crate) async fn fetch_incoming(store: Arc<Store>, plan: IncomingPlan) -> Result<Vec<Frame>> {
    let secret = plan.1;
    let plan = Arc::new(plan.0);
    let mut tasks = tokio::task::JoinSet::new();
    for endpoint in plan.endpoints.clone() {
        let store = store.clone();
        let plan = plan.clone();
        tasks.spawn(async move {
            let response = bootstrap_io::exchange(
                store,
                &endpoint,
                Method::GET,
                format!("/bootstrap/v1/mailboxes/{}", plan.locator),
                &plan.cap,
                Vec::new(),
            )
            .await?;
            let raw = bootstrap_io::success(response)?;
            let now = controls::local_decision_time()?;
            let frames = received(&raw, &plan, &now)?;
            require(
                frames.iter().all(|f| incoming_role(&f.role)),
                "state_conflict",
            )?;
            // Reject this endpoint as a unit before it can poison another
            // carrier's valid response. Retention revalidates the merged prefix
            // and all context/operation pins under its atomic transaction.
            for frame in &frames {
                frame.open_bytes(&secret, &now)?;
            }
            Ok::<_, Error>(frames)
        });
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut frames = BTreeMap::new();
    let mut success = false;
    while let Ok(Some(result)) = tokio::time::timeout_at(deadline, tasks.join_next()).await {
        if let Ok(Ok(incoming)) = result {
            success = true;
            for frame in incoming {
                let tuple = (
                    frame.role.clone(),
                    frame.writer_host_public_key.clone(),
                    frame.frame_id.clone(),
                );
                if let Some(old) = frames.get(&tuple) {
                    let old: &Frame = old;
                    require(old.body == frame.body, "operation_conflict")?;
                } else {
                    frames.insert(tuple, frame);
                }
            }
            require(
                frames.len() <= 64
                    && frames.values().map(|f| f.ciphertext.len()).sum::<usize>() <= 32 << 20,
                "quota_exceeded",
            )?;
        }
    }
    // Dropping JoinSet aborts outstanding GETs. No task can retain local state.
    require(success, "recovery_required")?;
    Ok(frames.into_values().collect())
}
fn plan(store: &Store, id: &str) -> Result<Option<Plan>> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(|_| Error::new("internal"))?;
    let p = requests::load(&tx, id)?;
    let now = controls::local_decision_time()?;
    if !matches!(
        p.record.terminal.as_str(),
        "-" | "applied" | "migration_prepared"
    ) || stamp(&now)? >= stamp(&p.deadline)?
    {
        return Ok(None);
    }
    let terminal = p.record.terminal == "applied";
    let frames = requests::frames(&tx, &p)?;
    let (locator, cap) = if terminal {
        let Some(cap) = p.terminal_read_cap else {
            return Ok(None);
        };
        let Some(frame) = frames.first() else {
            return Err(Error::new("state_conflict"));
        };
        check(frames.iter().all(|f| {
            f.role == "outcome"
                && f.locator == frame.locator
                && f.writer_host_public_key == store.identity().public_key
        }))?;
        (frame.locator.clone(), hex::encode(cap))
    } else {
        let Some(secret) = p.secret else {
            return Ok(None);
        };
        (bootstrap::locator(&secret), bootstrap::read_cap(&secret))
    };
    let plan = Plan {
        id: id.into(),
        locator,
        created_at: text(&p.packet()?.payload, "created_at")?.into(),
        expires_at: p.deadline.clone(),
        cap,
        endpoints: p.record.carrier_endpoints.clone(),
        frames,
        outbound: p.record.outbound_frames.clone(),
        terminal,
    };
    tx.commit().map_err(|_| Error::new("internal"))?;
    Ok(Some(plan))
}
fn ack(store: &Store, id: &str, endpoint: &Value, frame: &Frame) -> Result<()> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(|_| Error::new("internal"))?;
    let mut p = requests::load(&tx, id)?;
    let entry = p
        .record
        .outbound_frames
        .iter_mut()
        .find(|v| {
            v["role"] == frame.role
                && v["writer_public_key"] == frame.writer_host_public_key
                && v["frame_id"] == frame.frame_id
        })
        .ok_or_else(|| Error::new("operation_conflict"))?;
    let ack = json!({"address":endpoint["address"],"public_key":endpoint["public_key"]});
    let list = entry["acknowledged_by"]
        .as_array_mut()
        .ok_or_else(|| Error::new("state_conflict"))?;
    if !list.contains(&ack) {
        list.push(ack);
        list.sort_by_key(|v| {
            (
                v["address"].as_str().unwrap_or_default().to_owned(),
                v["public_key"].as_str().unwrap_or_default().to_owned(),
            )
        });
    }
    if p.record.terminal == "applied"
        && p.record.outbound_frames.iter().all(|f| {
            p.record.carrier_endpoints.iter().all(|e| {
                f["acknowledged_by"].as_array().is_some_and(|acks| {
                    acks.iter()
                        .any(|a| a["address"] == e["address"] && a["public_key"] == e["public_key"])
                })
            })
        })
    {
        p.terminal_read_cap = None;
        p.record.outbound_frames.clear();
        tx.execute("DELETE FROM dec_frames WHERE request_id=?1", [id])
            .map_err(|_| Error::new("internal"))?;
    }
    requests::save(&tx, &p)?;
    tx.commit().map_err(|_| Error::new("internal"))?;
    Ok(())
}
fn unacknowledged(frame: &Frame, plan: &Plan, endpoint: &Value) -> bool {
    plan.outbound.iter().any(|v| {
        v["role"] == frame.role
            && v["writer_public_key"] == frame.writer_host_public_key
            && v["frame_id"] == frame.frame_id
            && !v["acknowledged_by"].as_array().is_some_and(|list| {
                list.iter().any(|v| {
                    v["address"] == endpoint["address"] && v["public_key"] == endpoint["public_key"]
                })
            })
    })
}
async fn acknowledge(store: Arc<Store>, id: String, endpoint: Value, frame: Frame) -> Result<()> {
    tokio::task::spawn_blocking(move || ack(&store, &id, &endpoint, &frame))
        .await
        .map_err(|_| Error::new("internal"))?
}
async fn publish_to(store: Arc<Store>, plan: &Plan, endpoint: &Value) -> Result<()> {
    let first = plan.frames.iter().find(|f| f.role == "request");
    // Only the actual outer writer can create/append a resource frame. Foreign
    // received frames are retained locally and learned through GET instead.
    let own = store.identity().public_key;
    if let Some(first) = first
        && first.writer_host_public_key == own
        && unacknowledged(first, plan, endpoint)
    {
        let response = bootstrap_io::exchange(
            store.clone(),
            endpoint,
            Method::POST,
            "/bootstrap/v1/mailboxes".into(),
            &plan.cap,
            bootstrap_io::creation_body(first, &plan.cap)?,
        )
        .await?;
        let body = bootstrap_io::success(response)?;
        let v = parse(&body, 1 << 20)?;
        let o = object(&v)?;
        fields(o, "request_id locator")?;
        check(text(o, "request_id")? == plan.id && text(o, "locator")? == first.locator)?;
        acknowledge(
            store.clone(),
            plan.id.clone(),
            endpoint.clone(),
            first.clone(),
        )
        .await?;
    }
    // Proof frames go first: a stage packet needs the proofs that travel
    // beside it, and a reader takes each mailbox as one snapshot. Posting a
    // packet before its proofs let a reader see the packet alone and answer
    // proof_required (stored frames are listed by role, so `administrator`
    // came before `proofs`).
    let ordered = plan
        .frames
        .iter()
        .filter(|f| f.role == "proofs")
        .chain(plan.frames.iter().filter(|f| f.role != "proofs"));
    for frame in ordered {
        if frame.role == "request"
            || frame.writer_host_public_key != own
            || !unacknowledged(frame, plan, endpoint)
        {
            continue;
        }
        let response = bootstrap_io::exchange(
            store.clone(),
            endpoint,
            Method::POST,
            format!("/bootstrap/v1/mailboxes/{}/frames", frame.locator),
            &plan.cap,
            bootstrap_io::append_body(frame)?,
        )
        .await?;
        let body = bootstrap_io::success(response)?;
        let v = parse(&body, 1 << 20)?;
        let o = object(&v)?;
        fields(o, "frame_id")?;
        check(text(o, "frame_id")? == frame.frame_id)?;
        acknowledge(
            store.clone(),
            plan.id.clone(),
            endpoint.clone(),
            frame.clone(),
        )
        .await?;
    }
    Ok(())
}
pub(crate) async fn publish(store: Arc<Store>, id: &str) -> Result<()> {
    let complete = super::completion::publish(store.clone(), id).await;
    let frames = publish_frames(store, id).await;
    match complete {
        Ok(true) => Ok(()),
        Ok(false) => frames,
        Err(error) => Err(error),
    }
}
async fn publish_frames(store: Arc<Store>, id: &str) -> Result<()> {
    let lookup = id.to_owned();
    let capture = store.clone();
    let Some(plan) = tokio::task::spawn_blocking(move || plan(&capture, &lookup))
        .await
        .map_err(|_| Error::new("internal"))??
    else {
        return Ok(());
    };
    let mut first_error = None;
    let mut succeeded = false;
    let plan = Arc::new(plan);
    let mut tasks = tokio::task::JoinSet::new();
    for endpoint in plan.endpoints.clone() {
        let store = store.clone();
        let plan = plan.clone();
        tasks.spawn(async move { publish_to(store, &plan, &endpoint).await });
    }
    while let Some(result) = tasks.join_next().await {
        match result.map_err(|_| Error::new("internal"))? {
            Ok(()) => succeeded = true,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e)
                }
            }
        }
    }
    if succeeded || plan.endpoints.is_empty() {
        Ok(())
    } else {
        Err(first_error.unwrap_or_else(|| Error::new("recovery_required")))
    }
}
pub(crate) fn transport_attention(raw: &[u8], error: &Error) -> Result<Vec<u8>> {
    let mut v = parse(raw, 32 << 20)?;
    let id = v
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new("internal"))?
        .to_owned();
    v["attention"] = json!([format!(
        "transport_{}: request is durable; retry its exact saved frames",
        error.code
    )]);
    v["next"] = json!([format!("peerspan link resume {id}")]);
    serde_json::to_vec(&v).map_err(|_| Error::new("internal"))
}
// Parsing a carrier reply retains exact signed frame slices. The observer will
// validate/decrypt their inner stage before any authority/application effect.
fn received(raw: &[u8], plan: &Plan, now: &str) -> Result<Vec<Frame>> {
    let value = parse(raw, 48 << 20)?;
    let o = object(&value)?;
    fields(o, "format request_id created_at expires_at frames")?;
    version(o)?;
    check(
        text(o, "request_id")? == plan.id
            && text(o, "created_at")? == plan.created_at
            && text(o, "expires_at")? == plan.expires_at,
    )?;
    let field = super::catalog::raw_field(raw, "frames")?;
    let raws: Vec<&RawValue> = serde_json::from_slice(&field).map_err(|_| Error::new("invalid"))?;
    require(raws.len() <= 64, "quota_exceeded")?;
    let mut frames = Vec::new();
    let mut bytes = 0;
    let mut previous = None;
    for raw in raws {
        let frame = Frame::read(raw.get().as_bytes())?;
        frame.valid_at(now)?;
        check(
            frame.request_id == plan.id
                && frame.locator == plan.locator
                && frame.created_at == plan.created_at
                && frame.expires_at == plan.expires_at,
        )?;
        let tuple = (
            frame.role.clone(),
            frame.writer_host_public_key.clone(),
            frame.frame_id.clone(),
        );
        check(previous.as_ref().is_none_or(|p| p < &tuple))?;
        previous = Some(tuple);
        bytes += frame.ciphertext.len();
        require(bytes <= 32 << 20, "quota_exceeded")?;
        frames.push(frame);
    }
    Ok(frames)
}
fn retain(store: &Store, id: &str, incoming: Vec<Frame>) -> Result<()> {
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(|_| Error::new("internal"))?;
    let mut p = requests::load(&tx, id)?;
    let now = controls::local_decision_time()?;
    require(
        matches!(p.record.terminal.as_str(), "-" | "migration_prepared")
            && stamp(&now)? < stamp(&p.deadline)?,
        "expired",
    )?;
    let secret = p.secret.ok_or_else(|| Error::new("recovery_required"))?;
    let mut all = requests::frames(&tx, &p)?
        .into_iter()
        .map(|f| {
            (
                (
                    f.role.clone(),
                    f.writer_host_public_key.clone(),
                    f.frame_id.clone(),
                ),
                f,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for frame in incoming {
        frame.valid_at(&now)?;
        let plain = frame.open_bytes(&secret, &now)?;
        let contacts = super::catalog::raw_field(&plain, "contacts")?;
        let contacts: Vec<Box<RawValue>> =
            serde_json::from_slice(&contacts).map_err(|_| Error::new("invalid"))?;
        for contact in contacts {
            let raw = contact.get().as_bytes();
            let contact = bootstrap::Contact::read(raw)?;
            contact.valid_at(&now)?;
            if contact.host_public_key != frame.writer_host_public_key {
                continue;
            }
            let descriptor = if p.record.descriptor_base64 != "-" {
                Some(super::Descriptor::read(&b64(
                    &p.record.descriptor_base64,
                    MAX_OBJECT,
                )?)?)
            } else if frame.role == "owner" {
                let plain_value = parse(&plain, bootstrap::MAX_FRAME_PLAIN)?;
                let packet = super::transcript::Packet::read(&b64(
                    text(object(&plain_value)?, "packet_base64")?,
                    MAX_OBJECT,
                )?)?;
                Some(super::Descriptor::from_value(
                    packet
                        .payload
                        .get("descriptor")
                        .ok_or_else(|| Error::new("invalid"))?,
                )?)
            } else {
                None
            };
            if let Some(descriptor) = descriptor {
                super::peer::remember_pairing_contact(
                    &tx,
                    &descriptor.network_id,
                    &descriptor.context_id(),
                    &frame.writer_host_public_key,
                    raw,
                    &now,
                )?;
            } else if contact.context_id == "-" {
                super::peer::remember_pairing_contact(
                    &tx,
                    "-",
                    "-",
                    &frame.writer_host_public_key,
                    raw,
                    &now,
                )?;
            }
            // A writer's signed contact changes only this private operation's
            // transport hints. It supplies no membership or provider pin.
            for address in array(object(&contact.payload)?, "bootstrap_addresses")? {
                p.record.carrier_endpoints.push(json!({"kind":"participant","address":address,"public_key":contact.host_public_key}));
            }
        }
        let tuple = (
            frame.role.clone(),
            frame.writer_host_public_key.clone(),
            frame.frame_id.clone(),
        );
        if let Some(old) = all.get(&tuple) {
            require(old.body == frame.body, "operation_conflict")?;
        } else {
            all.insert(tuple, frame);
        }
    }
    require(
        all.len() <= 64 && all.values().map(|f| f.ciphertext.len()).sum::<usize>() <= 32 << 20,
        "quota_exceeded",
    )?;
    p.record.carrier_endpoints.sort_by_key(|e| {
        (
            e["kind"].as_str().unwrap_or_default().to_owned(),
            e["address"].as_str().unwrap_or_default().to_owned(),
            e["public_key"].as_str().unwrap_or_default().to_owned(),
        )
    });
    p.record.carrier_endpoints.dedup();
    if p.record.carrier_endpoints.len() > 8 {
        return Err(Error::quota("more than 8 carrier endpoints"));
    }
    let mut inserted = 0;
    for frame in all.values() {
        inserted+=tx.execute("INSERT INTO dec_frames(request_id,role,writer_key,frame_id,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(request_id,role,writer_key,frame_id) DO NOTHING",rusqlite::params![id,frame.role,frame.writer_host_public_key,frame.frame_id,json!({"frame_base64":encode(&frame.body)}).to_string()]).map_err(|_|Error::new("internal"))?;
    }
    requests::save(&tx, &p)?;
    tx.commit().map_err(|_| Error::new("internal"))?;
    drop(c);
    if inserted > 0 {
        controls::barrier(store, "dec.frame.after_commit", id)?;
    }
    Ok(())
}
pub(crate) async fn poll(store: Arc<Store>, id: &str) -> Result<()> {
    let capture = store.clone();
    let lookup = id.to_owned();
    let Some(plan) = tokio::task::spawn_blocking(move || plan(&capture, &lookup))
        .await
        .map_err(|_| Error::new("internal"))??
    else {
        return Ok(());
    };
    if plan.terminal {
        return Ok(());
    }
    let mut success = false;
    let mut error = None;
    for endpoint in &plan.endpoints {
        let now = controls::local_decision_time()?;
        let key = (
            id.to_owned(),
            endpoint["address"]
                .as_str()
                .ok_or_else(|| Error::new("invalid"))?
                .to_owned(),
            endpoint["public_key"]
                .as_str()
                .ok_or_else(|| Error::new("invalid"))?
                .to_owned(),
        );
        let recent = store
            .bootstrap_polls
            .lock()
            .map_err(|_| Error::new("internal"))?
            .get(&key)
            .map(|last| -> Result<bool> {
                Ok(stamp(&now)? >= stamp(&last.decision_time)?
                    && last.read_at.elapsed() < std::time::Duration::from_secs(2))
            })
            .transpose()?
            .unwrap_or(false);
        if recent {
            success = true;
            continue;
        }
        let result = async {
            let response = bootstrap_io::exchange(
                store.clone(),
                endpoint,
                Method::GET,
                format!("/bootstrap/v1/mailboxes/{}", plan.locator),
                &plan.cap,
                Vec::new(),
            )
            .await?;
            let raw = bootstrap_io::success(response)?;
            let incoming = received(&raw, &plan, &now)?;
            let target = store.clone();
            let id = id.to_owned();
            tokio::task::spawn_blocking(move || retain(&target, &id, incoming))
                .await
                .map_err(|_| Error::new("internal"))??;
            let completed = controls::local_decision_time()?;
            let mut polls = store
                .bootstrap_polls
                .lock()
                .map_err(|_| Error::new("internal"))?;
            if !polls.contains_key(&key) && polls.len() >= 4096 {
                polls.retain(|_, last| last.read_at.elapsed() < std::time::Duration::from_secs(2));
            }
            if stamp(&completed)? >= stamp(&now)?
                && (polls.len() < 4096 || polls.contains_key(&key))
            {
                polls.insert(
                    key,
                    crate::store::BootstrapPoll {
                        decision_time: completed,
                        read_at: std::time::Instant::now(),
                    },
                );
            }
            Ok::<_, Error>(())
        }
        .await;
        match result {
            Ok(()) => success = true,
            Err(e) => {
                if error.is_none() {
                    error = Some(e)
                }
            }
        }
    }
    if success || plan.endpoints.is_empty() {
        let target = store.clone();
        let id = id.to_owned();
        tokio::task::spawn_blocking(move || observer::observe(&target, &id))
            .await
            .map_err(|_| Error::new("internal"))?
    } else {
        Err(error.unwrap_or_else(|| Error::new("recovery_required")))
    }
}
/// Approved owner work proceeds without `link resume` on the approving host
/// (spec 8.2 preapproval and fold, 8.7): every 2 seconds, an approving host
/// reads the mailboxes of its approved, unfinished requests, signs the stages
/// its approval already covers, and publishes them.
pub(crate) async fn approver_worker(
    store: Arc<Store>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    tick.tick().await;
    loop {
        tokio::select! {_ = shutdown.changed()=>break,_=tick.tick()=>{}}
        let capture = store.clone();
        let ids = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let c = capture.connection().map_err(|_| Error::new("internal"))?;
            let now = controls::local_decision_time()?;
            let mut q = c
                .prepare("SELECT request_id FROM dec_pending WHERE request_id GLOB 'link_*' ORDER BY request_id")
                .map_err(|_| Error::new("internal"))?;
            let ids = q
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|_| Error::new("internal"))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::new("internal"))?;
            let mut due = Vec::new();
            for id in ids {
                let Ok(p) = requests::load(&c, &id) else {
                    continue;
                };
                // Kept until the request ends, so a finalization whose frame
                // was not yet retained or published is retried after a crash.
                // Approved work on an approving host, and every unfinished
                // request of this machine as requester: its stages arrive by
                // mailbox and advance without `link resume` (spec 8.4, 9.5).
                let requester = p.record.roles.iter().any(|r| r == "requester");
                let approved_owner = p.record.owner_intent_id != "-"
                    && super::ceremony::owner_intent(&c, &p)
                        .is_ok_and(|intent| intent.record.approved && intent.record.terminal == "-");
                let approved_administrator = p.record.administrator_intent_id != "-"
                    && super::intents::Intent::load(&c, &p.record.administrator_intent_id)
                        .is_ok_and(|intent| {
                            intent.kind == "administrator"
                                && intent.record.approved
                                && intent.record.terminal == "-"
                        });
                if p.record.terminal == "-"
                    && (approved_owner
                        || approved_administrator
                        || requester && p.record.commit_packet_base64 == "-")
                    && stamp(&now)? < stamp(&p.deadline)?
                {
                    due.push(id);
                }
            }
            Ok(due)
        })
        .await;
        let Ok(Ok(ids)) = ids else { continue };
        for id in ids.into_iter().take(8) {
            if *shutdown.borrow() {
                return;
            }
            if poll(store.clone(), &id).await.is_err() {
                continue;
            }
            let target = store.clone();
            let resume_id = id.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = super::ceremony::resume(&target, &resume_id);
                super::requester::resume_approved(&target, &resume_id)
            })
            .await;
            let _ = publish(store.clone(), &id).await;
        }
    }
}
