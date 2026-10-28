//! Exact durable publication retries use real transport time. A peer's verified
//! catalog acknowledges only its local observation of these fixed proof bytes.
use super::*;
use tokio::sync::watch;

/// Set when deliveries are queued, so they go out at once rather than on the
/// next 2-second pass.
pub(super) static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[derive(Clone)]
struct Delivery {
    id: String,
    network: String,
    context: String,
    host: String,
    raw: String,
    record: Value,
    body: Vec<u8>,
}
fn due(
    store: &Store,
    excluded: &std::collections::BTreeSet<String>,
    capacity: usize,
) -> Result<Vec<Delivery>> {
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let real = crate::clock::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut q = c.prepare("SELECT delivery_id,network_id,context_id,target_key,record FROM dec_outbox WHERE json_extract(record,'$.attempts')=0 OR json_extract(record,'$.next_attempt_at')<=?1 ORDER BY (json_extract(record,'$.attempts')=0) DESC,json_extract(record,'$.next_attempt_at'),delivery_id").map_err(db)?;
    let rows = q
        .query_map([real], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .map_err(db)?;
    let mut output = Vec::new();
    for row in rows {
        let (id, network, context, host, raw) = row.map_err(db)?;
        if excluded.contains(&id) {
            continue;
        }
        let record = parse(raw.as_bytes(), 32 << 20)?;
        let o = object(&record)?;
        fields(
            o,
            "format kind body_base64 proof_ids created_at attempts next_attempt_at last_error_code last_error_detail",
        )?;
        version(o)?;
        check(ident(&network, "net_") && ident(&context, "ctx_") && key(&host))?;
        check(matches!(
            text(o, "kind")?,
            "proofs" | "activation" | "migration"
        ))?;
        ids(o, "proof_ids", "dp_")?;
        stamp(text(o, "created_at")?)?;
        stamp(text(o, "next_attempt_at")?)?;
        num(o, "attempts")?;
        let body = b64(text(o, "body_base64")?, WHOLE)?;
        output.push(Delivery {
            id,
            network,
            context,
            host,
            raw,
            record,
            body,
        });
        if output.len() >= capacity {
            break;
        }
    }
    Ok(output)
}
fn prepare(store: &Store, delivery: &Delivery) -> Result<DialTarget> {
    let plan = sync_plan(store, &delivery.network)?;
    require(plan.current, "forbidden")?;
    let c = store.connection().map_err(|_| Error::new("internal"))?;
    let snapshot = Snapshot::load(&c, &delivery.network, &store.identity().public_key)?;
    require(
        snapshot.network.context_id == delivery.context,
        "state_conflict",
    )?;
    let value = parse(&delivery.body, WHOLE)?;
    let input = object(&value)?;
    fields(input, "catalog")?;
    let catalog =
        super::super::Catalog::read(&snapshot.descriptor, &encode_json(&input["catalog"])?)?;
    for id in ids(object(&delivery.record)?, "proof_ids", "dp_")? {
        require(catalog.proofs.contains_key(&id), "state_conflict")?;
    }
    plan.targets
        .into_iter()
        .find(|t| t.host == delivery.host)
        .ok_or_else(|| Error::new("transport_unavailable"))
}
async fn send(store: Arc<Store>, delivery: &Delivery, target: DialTarget) -> Result<Vec<u8>> {
    let path = format!("/peer/v2/networks/{}/catalog", delivery.network);
    for endpoint in target.quic {
        let Ok(Ok(addresses)) =
            tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(endpoint)).await
        else {
            continue;
        };
        for address in addresses.take(8) {
            let peer = crate::peer_store::Peer {
                id: key_id(&b64(&target.host, 32)?),
                public_key: target.host.clone(),
                address: address.to_string(),
            };
            match tokio::time::timeout(
                Duration::from_secs(5),
                crate::quic::request(store.clone(), &peer, "POST", &path, &delivery.body),
            )
            .await
            {
                Ok(Ok((200, body))) => return Ok(body),
                Ok(Ok((status, body))) => {
                    // Preserve only a known public code, never remote text or
                    // credentials. The exact delivery remains pending.
                    if let Ok(value) = parse(&body, 1 << 20)
                        && let Some(code) = value.get("code").and_then(Value::as_str)
                    {
                        let code = match code {
                            "forbidden" => "forbidden",
                            "authority_expired" => "authority_expired",
                            "proof_required" => "proof_required",
                            "state_conflict" => "state_conflict",
                            "quota_exceeded" => "quota_exceeded",
                            "rate_limited" => "rate_limited",
                            _ => "transport_unavailable",
                        };
                        if status != 200 {
                            return Err(Error::new(code));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Err(Error::new("transport_unavailable"))
}
fn acknowledge(store: &Store, delivery: &Delivery, response: &[u8]) -> Result<()> {
    let value = parse(response, WHOLE)?;
    let input = object(&value)?;
    fields(input, "catalog")?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut tx = c.transaction().map_err(db)?;
    let snapshot = Snapshot::load(&tx, &delivery.network, &store.identity().public_key)?;
    require(
        snapshot.network.context_id == delivery.context,
        "state_conflict",
    )?;
    let incoming = encode_json(&input["catalog"])?;
    let catalog = super::super::Catalog::read(&snapshot.descriptor, &incoming)?;
    let sent = parse(&delivery.body, WHOLE)?;
    let sent = super::super::Catalog::read(
        &snapshot.descriptor,
        &encode_json(&object(&sent)?["catalog"])?,
    )?;
    for (id, proof) in &sent.proofs {
        require(
            catalog
                .proofs
                .get(id)
                .is_some_and(|p| p.kind == proof.kind && p.body == proof.body),
            "state_conflict",
        )?;
    }
    remembered(&snapshot, &delivery.host)?;
    // First-admission/current checks use the latest local guard and ALL local
    // facts. Nothing from this response authorizes the already sent request.
    snapshot.apply_catalog(
        &mut tx,
        &incoming,
        &super::super::controls::local_decision_time()?,
        "repair",
    )?;
    tx.execute(
        "DELETE FROM dec_outbox WHERE delivery_id=?1 AND record=?2",
        params![delivery.id, delivery.raw],
    )
    .map_err(db)?;
    tx.commit().map_err(db)?;
    store
        .refresh_member_pins(&c)
        .map_err(|_| Error::new("internal"))?;
    Ok(())
}
fn failed(store: &Store, delivery: &Delivery, error: Error) -> Result<()> {
    let mut record = object(&delivery.record)?.clone();
    let attempts = num(&record, "attempts")?.saturating_add(1);
    let delay = (1u64 << attempts.min(6)).min(60);
    let next = (crate::clock::now() + chrono::TimeDelta::seconds(delay as i64))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    record.insert("attempts".into(), json!(attempts));
    record.insert("next_attempt_at".into(), json!(next));
    record.insert("last_error_code".into(), json!(error.code));
    record.insert(
        "last_error_detail".into(),
        json!(error.code.replace('_', " ")),
    );
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let changed = tx
        .execute(
            "UPDATE dec_outbox SET record=?3 WHERE delivery_id=?1 AND record=?2",
            params![delivery.id, delivery.raw, Value::Object(record).to_string()],
        )
        .map_err(db)?;
    if changed > 0 {
        super::super::storage::check_outbox_capacity(&tx, &[])?;
    }
    tx.commit().map_err(db)?;
    Ok(())
}
async fn deliver(store: Arc<Store>, delivery: Arc<Delivery>) {
    let owner = store.clone();
    let row = delivery.clone();
    let target = tokio::task::spawn_blocking(move || prepare(&owner, &row))
        .await
        .unwrap_or_else(|_| Err(Error::new("internal")));
    let result = match target {
        Ok(target) => {
            match tokio::time::timeout(
                Duration::from_secs(30),
                send(store.clone(), &delivery, target),
            )
            .await
            {
                Ok(Ok(response)) => {
                    let owner = store.clone();
                    let row = delivery.clone();
                    tokio::task::spawn_blocking(move || acknowledge(&owner, &row, &response))
                        .await
                        .unwrap_or_else(|_| Err(Error::new("internal")))
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(Error::new("transport_unavailable")),
            }
        }
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        let _ = tokio::task::spawn_blocking(move || failed(&store, &delivery, error)).await;
    }
}
async fn reconcile(store: Arc<Store>) {
    let owner = store.clone();
    let Ok(Ok(ids)) = tokio::task::spawn_blocking(move || {
        let c = owner.connection().map_err(|_| Error::new("internal"))?;
        network_ids(&c)
    })
    .await
    else {
        return;
    };
    for network in ids {
        let _ = sync(store.clone(), &network).await;
    }
}
/// No heartbeat grants authority or renews a lease. Only exact pending public
/// bytes retry here; ordinary anti-entropy has a separate real monotonic timer.
pub(super) async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let mut pending = tokio::time::interval(Duration::from_secs(2));
    pending.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut anti = Box::pin(tokio::time::sleep(Duration::from_secs(60 + jitter())));
    let mut active = tokio::task::JoinSet::new();
    let mut inflight = std::collections::BTreeSet::new();
    let mut syncing = false;
    loop {
        let pass = tokio::select! {
            _=shutdown.changed()=>break,
            _=pending.tick()=>true,
            _=WAKE.notified()=>true,
            _=&mut anti,if !syncing=>{syncing=true;let owner=store.clone();active.spawn(async move{reconcile(owner).await;None});false},
            Some(result)=active.join_next(),if !active.is_empty()=>{match result {
                Ok(Some(id))=>{inflight.remove(&id);},
                Ok(None)=>{syncing=false;anti.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(60+jitter()));},
                Err(_)=>{
                    active.abort_all();while active.join_next().await.is_some(){}
                    inflight.clear();syncing=false;
                    anti.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(60+jitter()));
                }
            };false},
        };
        if pass {
            let capacity = 4usize.saturating_sub(inflight.len());
            if capacity > 0 {
                let owner = store.clone();
                let excluded = inflight.clone();
                if let Ok(Ok(rows)) =
                    tokio::task::spawn_blocking(move || due(&owner, &excluded, capacity)).await
                {
                    for row in rows {
                        let id = row.id.clone();
                        inflight.insert(id.clone());
                        let owner = store.clone();
                        let row = Arc::new(row);
                        active.spawn(async move {
                            deliver(owner, row).await;
                            Some(id)
                        });
                    }
                }
            }
        }
    }
    active.abort_all();
    while active.join_next().await.is_some() {}
}
fn jitter() -> u64 {
    let mut byte = [0];
    getrandom::fill(&mut byte)
        .map(|_| u64::from(byte[0]) % 11)
        .unwrap_or(0)
}
