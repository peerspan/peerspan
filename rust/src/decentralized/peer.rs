//! Public proof exchange authenticates the prior local graph before considering
//! incoming evidence. Remembered pins permit TLS possession checks, not work.
mod contact_refresh;
mod delivery;
mod repair;
use super::{bootstrap::Contact, codec::*, storage::Snapshot};
use crate::{peer_store::key_id, store::Store};
use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State, rejection::BytesRejection},
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(crate) const REPAIR_ALPN: &[u8] = b"peerspan-state-repair/1";
/// Wakes the publication worker after new deliveries are queued; it reads them
/// once the queuing transaction commits, as they share the store's connection.
pub(crate) fn wake_delivery() {
    delivery::WAKE.notify_one();
}
pub async fn state_worker(store: Arc<Store>, shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::join!(
        delivery::worker(store.clone(), shutdown.clone()),
        super::renewal::worker(store.clone(), shutdown.clone()),
        super::requests_io::approver_worker(store.clone(), shutdown.clone()),
        crate::quic::helper_worker(store, shutdown)
    );
}
#[derive(Default)]
pub(crate) struct RepairLimits(Mutex<RepairBudget>);
#[derive(Default)]
struct RepairBudget {
    active: usize,
    wire: usize,
    hosts: BTreeMap<String, usize>,
    sources: BTreeMap<IpAddr, usize>,
    rates: BTreeMap<String, (f64, Instant)>,
}
pub(crate) struct RepairPermit {
    owner: Arc<RepairLimits>,
    host: String,
    source: IpAddr,
}
impl Drop for RepairPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.owner.0.lock() {
            state.active -= 1;
            state.wire -= WHOLE + (64 << 10);
            if let Some(count) = state.hosts.get_mut(&self.host) {
                *count -= 1;
                if *count == 0 {
                    state.hosts.remove(&self.host);
                }
            }
            if let Some(count) = state.sources.get_mut(&self.source) {
                *count -= 1;
                if *count == 0 {
                    state.sources.remove(&self.source);
                }
            }
        }
    }
}
fn source_bucket(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or_else(|| {
            let mut s = v.segments();
            s[4..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(s))
        }),
        v => v,
    }
}
impl RepairLimits {
    pub(crate) fn admit(self: &Arc<Self>, host: &str, source: IpAddr) -> Result<RepairPermit> {
        let source = source_bucket(source);
        let mut state = self.0.lock().map_err(|_| Error::new("internal"))?;
        // Reserve the entire possible response plus header/control space until
        // the transport finishes writing it; never truncate a public catalog.
        require(
            state.wire + WHOLE + (64 << 10) <= 64 << 20
                && state.active < 128
                && state.hosts.get(host).copied().unwrap_or(0) < 4
                && state.sources.get(&source).copied().unwrap_or(0) < 16,
            // Concurrent reservations are transient: retry, not a fixed quota.
            "rate_limited",
        )?;
        let now = Instant::now();
        state
            .rates
            .retain(|_, (_, last)| now.duration_since(*last) <= Duration::from_secs(65));
        for principal in [format!("host:{host}"), format!("source:{source}")] {
            require(
                state.rates.contains_key(&principal) || state.rates.len() < 16384,
                "quota_exceeded",
            )?;
            let (tokens, last) = state.rates.entry(principal).or_insert((4.0, now));
            *tokens = (*tokens + now.duration_since(*last).as_secs_f64()).min(4.0);
            *last = now;
            require(*tokens >= 1.0, "rate_limited")?;
            *tokens -= 1.0;
        }
        state.active += 1;
        state.wire += WHOLE + (64 << 10);
        *state.hosts.entry(host.into()).or_default() += 1;
        *state.sources.entry(source).or_default() += 1;
        Ok(RepairPermit {
            owner: self.clone(),
            host: host.into(),
            source,
        })
    }
}

/// Transport identity memory is narrower than a manual peer pin. Only an
/// exact independently admitted H may reach even the repair HTTP parser.
/// Permanent bans remain recognizable here so the exact repair route can
/// return its existing forbidden result without disclosing a catalog.
pub(crate) async fn repair_transport_known(store: Arc<Store>, key: Vec<u8>) -> bool {
    if !store
        .member_pins
        .read()
        .is_ok_and(|pins| pins.get(&key_id(&key)).is_some_and(|stored| stored == &key))
    {
        return false;
    }
    tokio::task::spawn_blocking(move || -> Result<bool> {
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let host = encode(&key);
        let own = store.identity().public_key;
        for network in network_ids(&tx)? {
            let view = repair::View::load(&tx, &network, &own)?;
            if view.hosts.contains(&host) {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .await
    .is_ok_and(|result| result.unwrap_or(false))
}
/// Called only after TLS negotiated the separate repair ALPN. It never serves
/// the ordinary peer or owner-local router, and never applies candidate bytes.
pub(crate) async fn serve_repair(
    store: Arc<Store>,
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<()> {
    let (socket, tls) = stream.get_ref();
    anyhow::ensure!(
        tls.alpn_protocol() == Some(REPAIR_ALPN)
            && tls.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3),
        "invalid repair transport"
    );
    let certificates = tls
        .peer_certificates()
        .filter(|c| c.len() == 1)
        .ok_or_else(|| anyhow::anyhow!("invalid repair identity"))?;
    let key = crate::peer::certificate_key(&certificates[0], rustls::pki_types::UnixTime::now())
        .map_err(|_| anyhow::anyhow!("invalid repair identity"))?;
    anyhow::ensure!(
        repair_transport_known(store.clone(), key.clone()).await,
        "unknown repair identity"
    );
    let host = encode(&key);
    let permit = store
        .dec_repair_limits
        .admit(&host, socket.peer_addr()?.ip());
    let denied = permit.as_ref().err().cloned();
    let router = repair_router(store, host, denied);
    let service = hyper_util::service::TowerToHyperService::new(router);
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_buf_size(16 << 10)
        .max_headers(64)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5));
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service),
    )
    .await;
    drop(permit);
    result??;
    Ok(())
}
pub(crate) fn repair_router(store: Arc<Store>, host: String, denied: Option<Error>) -> Router {
    if let Some(error) = denied {
        Router::new().fallback(move || {
            let e = error.clone();
            async move { failure(e, "-", "repair", None) }
        })
    } else {
        Router::new()
            .route(
                "/repair/v1/networks/{network}/catalog",
                any(repair_dispatch),
            )
            .fallback(|| async { failure(Error::new("not_found"), "-", "repair", None) })
            .layer(Extension(host))
            .layer(DefaultBodyLimit::max(0))
            .with_state(store)
    }
}
async fn repair_dispatch(
    State(store): State<Arc<Store>>,
    Extension(host): Extension<String>,
    Path(network): Path<String>,
    method: Method,
    uri: Uri,
    body: std::result::Result<Bytes, BytesRejection>,
) -> Response {
    if method != Method::GET {
        return failure(Error::new("invalid"), &network, "repair", Some("GET"));
    }
    if uri.query().is_some()
        || uri.path() != format!("/repair/v1/networks/{network}/catalog")
        || !body.is_ok_and(|b| b.is_empty())
    {
        return failure(Error::new("invalid"), &network, "repair", None);
    }
    let error_network = network.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        check(ident(&network, "net_"))?;
        let mut c = store.connection().map_err(|_| Error::new("internal"))?;
        let tx = c.transaction().map_err(db)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
                [&network],
                |r| r.get(0),
            )
            .map_err(db)?;
        require(exists, "not_found")?;
        let view = repair::View::load(&tx, &network, &store.identity().public_key)?;
        view.remembered(&host)?;
        let response = catalog_body(&view.catalog.bytes)?;
        tx.commit().map_err(db)?;
        Ok(response)
    })
    .await
    .unwrap_or_else(|_| Err(Error::new("internal")));
    match result {
        Ok(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(error) => failure(error, &error_network, "repair", None),
    }
}

const WHOLE: usize = 20 << 20;

#[derive(Clone)]
struct DialTarget {
    host: String,
    quic: Vec<String>,
    bootstrap: Vec<String>,
}
struct SyncPlan {
    targets: Vec<DialTarget>,
    catalog: Arc<Vec<u8>>,
    current: bool,
    own_contact: Option<Arc<Vec<u8>>>,
}
fn sync_plan(store: &Store, network: &str) -> Result<SyncPlan> {
    check(ident(network, "net_"))?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let tx = c.transaction().map_err(db)?;
    let view = repair::View::load(&tx, network, &store.identity().public_key)?;
    let now = decision_clock(&super::controls::local_decision_time()?, &view.guard)?;
    // Validate the persisted local guard even when membership needs repair.
    let current = Snapshot::load(&tx, network, &store.identity().public_key)
        .and_then(|snapshot| snapshot.project(&now))
        .and_then(|projection| {
            projection.member_for(
                &view.network.own_identity.host_public_key,
                &view.network.own_identity.person_public_key,
            )
        })
        .is_ok();
    let own_contact = contact_refresh::own(&tx, store, &view, &now, current)?;
    let mut q = tx.prepare("SELECT context_id,host_key,sequence,record FROM dec_contacts WHERE (network_id=?1 AND context_id=?2) OR (network_id='-' AND context_id='-') ORDER BY host_key,context_id").map_err(db)?;
    let rows = q
        .query_map(params![network, view.network.context_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, rusqlite::types::Value>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(db)?;
    let mut targets: BTreeMap<String, DialTarget> = BTreeMap::new();
    for row in rows {
        let (context, host, sequence, raw) = row.map_err(db)?;
        if host == view.network.own_identity.host_public_key || view.remembered(&host).is_err() {
            continue;
        }
        let record = contact_record(sequence, &raw, &context, &host)?;
        if record.conflicted {
            continue;
        }
        for contact in record.contacts {
            if contact.valid_at(&now).is_err() {
                continue;
            }
            let payload = object(&contact.payload)?;
            let endpoints = |field| -> Result<Vec<String>> {
                array(payload, field)?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| Error::new("state_conflict"))
                    })
                    .collect()
            };
            let target = targets.entry(host.clone()).or_insert_with(|| DialTarget {
                host: host.clone(),
                quic: Vec::new(),
                bootstrap: Vec::new(),
            });
            target.quic.extend(endpoints("quic_addresses")?);
            target.bootstrap.extend(endpoints("bootstrap_addresses")?);
        }
    }
    drop(q);
    let catalog = Arc::new(catalog_body(&view.catalog.bytes)?);
    tx.commit().map_err(db)?;
    Ok(SyncPlan {
        targets: targets
            .into_values()
            .map(|mut target| {
                target.quic.sort();
                target.quic.dedup();
                target.bootstrap.sort();
                target.bootstrap.dedup();
                target
            })
            .collect(),
        catalog,
        current,
        own_contact,
    })
}

async fn fetch_target(
    store: Arc<Store>,
    network: String,
    target: DialTarget,
    catalog: Arc<Vec<u8>>,
    current: bool,
    own_contact: Option<Arc<Vec<u8>>>,
) -> Result<Vec<u8>> {
    let normal = format!("/peer/v2/networks/{network}/catalog");
    let repair = format!("/repair/v1/networks/{network}/catalog");
    for endpoint in &target.quic {
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
            if current
                && let Ok(Ok((200, body))) = tokio::time::timeout(
                    Duration::from_secs(5),
                    crate::quic::request(store.clone(), &peer, "GET", &normal, b""),
                )
                .await
            {
                // Exact original local evidence is the only outbound batch;
                // incoming grants cannot authorize a fresh send in this pass.
                let _ = tokio::time::timeout(
                    Duration::from_secs(5),
                    crate::quic::request(store.clone(), &peer, "POST", &normal, catalog.as_slice()),
                )
                .await;
                contact_refresh::exchange(
                    store.clone(),
                    &network,
                    &peer,
                    own_contact.as_deref().map(Vec::as_slice),
                )
                .await;
                return Ok(body);
            }
            if let Ok(Ok((200, body))) = tokio::time::timeout(
                Duration::from_secs(5),
                crate::quic::request_repair(store.clone(), &peer, &repair),
            )
            .await
            {
                return Ok(body);
            }
        }
    }
    for endpoint in &target.bootstrap {
        let config =
            crate::peer::pinned_client_config(store.clone(), b64(&target.host, 32)?, REPAIR_ALPN)
                .map_err(|_| Error::new("transport_unavailable"))?;
        let name = rustls::pki_types::ServerName::try_from("peerspan-peer")
            .map_err(|_| Error::new("internal"))?;
        if let Ok(Ok((200, _, body))) = tokio::time::timeout(
            Duration::from_secs(5),
            crate::peer::https_bounded(
                config,
                endpoint,
                name,
                Method::GET,
                &repair,
                Vec::new(),
                WHOLE,
            ),
        )
        .await
        {
            return Ok(body);
        }
    }
    Err(Error::new("transport_unavailable"))
}
fn learn_catalog(store: &Store, network: &str, host: &str, body: &[u8]) -> Result<Vec<String>> {
    let value = parse(body, WHOLE)?;
    let object = object(&value)?;
    fields(object, "catalog")?;
    let candidate = encode_json(object.get("catalog").ok_or_else(|| Error::new("invalid"))?)?;
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut tx = c.transaction().map_err(db)?;
    let before = repair::View::load(&tx, network, &store.identity().public_key)?;
    before.remembered(host)?;
    before.restore(&tx, &candidate)?;
    let latest = Snapshot::load(&tx, network, &store.identity().public_key)?;
    remembered(&latest, host)?;
    let projection = latest.apply_catalog(
        &mut tx,
        &candidate,
        &super::controls::local_decision_time()?,
        "repair",
    )?;
    let learned = projection
        .catalog
        .proofs
        .keys()
        .filter(|id| !before.catalog.proofs.contains_key(*id))
        .cloned()
        .collect();
    tx.commit().map_err(db)?;
    store
        .refresh_member_pins(&c)
        .map_err(|_| Error::new("internal"))?;
    Ok(learned)
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v2/networks/{network}/sync", any(sync_dispatch))
        .layer(DefaultBodyLimit::max(1 << 20))
}
async fn sync_dispatch(
    State(store): State<Arc<Store>>,
    Path(network): Path<String>,
    method: Method,
    uri: Uri,
    body: std::result::Result<Bytes, BytesRejection>,
) -> Response {
    if method != Method::POST {
        return failure(Error::new("invalid"), &network, "repair", Some("POST"));
    }
    let valid = body
        .ok()
        .and_then(|b| parse(&b, 1 << 20).ok())
        .is_some_and(|v| v.as_object().is_some_and(|o| o.is_empty()));
    if !valid || uri.query().is_some() || uri.path() != format!("/v2/networks/{network}/sync") {
        return failure(Error::new("invalid"), &network, "repair", None);
    }
    let result = sync(store, &network).await;
    match result {
        Ok(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Err(error) => failure(error, &network, "repair", None),
    }
}
pub(crate) async fn sync(store: Arc<Store>, network: &str) -> Result<Value> {
    let setup = store.clone();
    let id = network.to_owned();
    let plan = tokio::task::spawn_blocking(move || sync_plan(&setup, &id))
        .await
        .map_err(|_| Error::new("internal"))??;
    let mut pending: std::collections::VecDeque<_> = plan.targets.into();
    let mut attempted = std::collections::BTreeSet::new();
    let mut remaining = std::collections::BTreeSet::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut learned = std::collections::BTreeSet::new();
    let mut unavailable = BTreeMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        while tasks.len() < 4 {
            let Some(target) = pending.pop_front() else {
                break;
            };
            attempted.insert(target.host.clone());
            remaining.insert(target.host.clone());
            let worker = store.clone();
            let id = network.to_owned();
            let body = plan.catalog.clone();
            let hint = plan.own_contact.clone();
            tasks.spawn(async move {
                let host = target.host.clone();
                (
                    host,
                    fetch_target(worker, id, target, body, plan.current, hint).await,
                )
            });
        }
        if tasks.is_empty() {
            break;
        }
        let Ok(Some(result)) = tokio::time::timeout_at(deadline, tasks.join_next()).await else {
            break;
        };
        let Ok((host, result)) = result else {
            continue;
        };
        remaining.remove(&host);
        let result = match result {
            Ok(body) => {
                let worker = store.clone();
                let id = network.to_owned();
                let source = host.clone();
                tokio::task::spawn_blocking(move || learn_catalog(&worker, &id, &source, &body))
                    .await
                    .unwrap_or_else(|_| Err(Error::new("internal")))
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(ids) => learned.extend(ids),
            Err(e) => {
                unavailable.insert(host, e.code);
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    for host in remaining {
        unavailable.insert(host, "transport_unavailable");
    }
    let reader = store.clone();
    let id = network.to_owned();
    let view = tokio::task::spawn_blocking(move || {
        super::runtime::read_network(&reader, &id, "", &super::controls::local_decision_time()?)
    })
    .await
    .map_err(|_| Error::new("internal"))??;
    let view = parse(&view, 32 << 20)?;
    let state = view
        .get("authority")
        .and_then(|a| a.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("state_conflict");
    if !matches!(state, "usable" | "unbound") {
        let code = match state {
            "authority_expired" => "authority_expired",
            "not_yet_valid" => "not_yet_valid",
            "proof_required" => "proof_required",
            "clock_rollback" => "clock_rollback",
            "forbidden" => "forbidden",
            _ => "state_conflict",
        };
        let mut error = Error::new(code);
        if let Some(ids) = view
            .get("authority")
            .and_then(|a| a.get("required_ids"))
            .and_then(Value::as_array)
        {
            error.required_ids = ids
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        return Err(error);
    }
    Ok(
        json!({"network":view,"attempted":attempted,"learned_proof_ids":learned,"unavailable":unavailable.into_iter().map(|(host,code)|json!({"host_public_key":host,"code":code})).collect::<Vec<_>>()}),
    )
}

fn db(_: rusqlite::Error) -> Error {
    Error::new("internal")
}
fn encode_json(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::new("internal"))
}
fn network_ids(c: &Connection) -> Result<Vec<String>> {
    let mut q = c.prepare("SELECT id FROM networks WHERE json_extract(record,'$.mode')='decentralized' ORDER BY id").map_err(db)?;
    q.query_map([], |r| r.get(0))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)
}
fn host_key(snapshot: &Snapshot, sender: &str) -> Result<String> {
    for id in &snapshot.prior.admitted {
        let Some(statement) = snapshot.prior.catalog.statements.get(id) else {
            continue;
        };
        if statement.kind == "host_lease" {
            let key = text(statement.subject()?, "host_public_key")?;
            if key_id(&b64(key, 32)?) == sender {
                return Ok(key.into());
            }
        }
    }
    Err(Error::new("forbidden"))
}
fn remembered(snapshot: &Snapshot, host: &str) -> Result<()> {
    require(
        snapshot.prior.admitted.iter().any(|id| {
            snapshot.prior.catalog.get(id).is_ok_and(|s| {
                s.kind == "host_lease"
                    && s.subject()
                        .and_then(|o| text(o, "host_public_key"))
                        .is_ok_and(|key| key == host)
            })
        }),
        "forbidden",
    )?;
    for id in &snapshot.prior.restrictions {
        let restriction = snapshot.prior.catalog.get(id)?;
        if restriction.kind == "host_revoke" {
            let target = object(
                restriction
                    .payload
                    .get("target")
                    .ok_or_else(|| Error::new("state_conflict"))?,
            )?;
            require(text(target, "host_public_key")? != host, "forbidden")?;
        }
    }
    Ok(())
}
fn authorize(snapshot: &Snapshot, host: &str, now: &str) -> Result<()> {
    remembered(snapshot, host)?;
    let projection = snapshot.project(now)?;
    projection.member_for(&snapshot.network.own_identity.host_public_key, "-")?;
    projection.member_for(host, "-")?;
    Ok(())
}

/// Cache exact previously admitted host keys. Neither a contact nor a manual
/// peer can create this admission; every request separately checks authority.
pub(crate) fn remembered_pins(
    c: &Connection,
    self_id: &str,
) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let own: Vec<u8> = c.query_row(
        "SELECT private_key FROM identity WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let seed: &[u8; 64] = own
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid host identity"))?;
    let own_key = encode(
        ed25519_dalek::SigningKey::from_keypair_bytes(seed)?
            .verifying_key()
            .as_bytes(),
    );
    let mut pins = BTreeMap::new();
    for network in network_ids(c)? {
        let view = repair::View::load(c, &network, &own_key)?;
        for key in &view.hosts {
            let raw = b64(key, 32)?;
            let id = key_id(&raw);
            if id != self_id {
                pins.insert(id, raw);
            }
        }
    }
    Ok(pins)
}

/// Explicit manual allow_disconnected grants bypass this predicate at their
/// existing call site. Other work requires a current common authority path.
pub(crate) fn current_connected(
    c: &Connection,
    store: &Store,
    sender: &str,
) -> std::result::Result<bool, crate::model::Error> {
    let check = || -> Result<bool> {
        let now = super::controls::local_decision_time()?;
        for network in network_ids(c)? {
            let snapshot = Snapshot::load(c, &network, &store.identity().public_key)?;
            let Ok(host) = host_key(&snapshot, sender) else {
                continue;
            };
            if authorize(
                &snapshot,
                &snapshot.network.own_identity.host_public_key,
                &now,
            )
            .is_ok()
                && authorize(&snapshot, &host, &now).is_ok()
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    check().map_err(|e| crate::model::Error::Unavailable(e.code.into()))
}

struct WirePermit {
    owner: Arc<RepairLimits>,
    size: usize,
}
impl Drop for WirePermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.owner.0.lock() {
            state.wire -= self.size;
        }
    }
}
#[derive(Clone)]
pub(crate) struct WireBudget {
    _permit: Arc<WirePermit>,
}
impl RepairLimits {
    pub(crate) fn transport_budget(self: &Arc<Self>, size: usize) -> Result<WireBudget> {
        let mut limits = self.0.lock().map_err(|_| Error::new("internal"))?;
        // Concurrent reservations are transient: retry, not a fixed quota.
        require(size <= (64 << 20) - limits.wire, "rate_limited")?;
        limits.wire += size;
        Ok(WireBudget {
            _permit: Arc::new(WirePermit {
                owner: self.clone(),
                size,
            }),
        })
    }
}
struct BudgetedBody {
    body: axum::body::Body,
    _budget: WireBudget,
}
impl hyper::body::Body for BudgetedBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
async fn reserve_wire(
    State(store): State<Arc<Store>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Reserve the whole possible response plus the actual declared request
    // body (the transport enforces Content-Length); an undeclared body
    // reserves the whole request bound.
    let size = if request.method() == Method::GET {
        WHOLE + (64 << 10)
    } else {
        let declared = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n <= WHOLE)
            .unwrap_or(WHOLE);
        WHOLE + declared + (64 << 10)
    };
    let reserve = || -> Result<WireBudget> {
        let mut limits = store
            .dec_repair_limits
            .0
            .lock()
            .map_err(|_| Error::new("internal"))?;
        // Concurrent reservations are transient: retry, not a fixed quota.
        require(limits.wire + size <= 64 << 20, "rate_limited")?;
        limits.wire += size;
        Ok(WireBudget {
            _permit: Arc::new(WirePermit {
                owner: store.dec_repair_limits.clone(),
                size,
            }),
        })
    };
    let budget = match reserve() {
        Ok(budget) => budget,
        Err(error) => return failure(error, "-", "transport", None),
    };
    request.extensions_mut().insert(budget.clone());
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        axum::body::Body::new(BudgetedBody {
            body,
            _budget: budget,
        }),
    )
}
pub(crate) fn routes(store: Arc<Store>) -> Router<Arc<Store>> {
    Router::new()
        .route("/peer/v2/networks/{network}/{resource}", any(dispatch))
        .route_layer(axum::middleware::from_fn_with_state(store, reserve_wire))
        .layer(DefaultBodyLimit::max(WHOLE))
}
async fn dispatch(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Extension(budget): Extension<WireBudget>,
    Path((network, resource)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    body: std::result::Result<Bytes, BytesRejection>,
) -> Response {
    if uri.path() != format!("/peer/v2/networks/{network}/{resource}") {
        return failure(Error::new("invalid"), &network, "transport", None);
    }
    let allow = match resource.as_str() {
        "catalog" | "migration" => Some("GET, POST"),
        "contacts" => Some("GET"),
        "contact" => Some("POST"),
        _ => None,
    };
    let permitted = (matches!(resource.as_str(), "catalog" | "migration")
        && matches!(method, Method::GET | Method::POST))
        || (resource == "contacts" && method == Method::GET)
        || (resource == "contact" && method == Method::POST);
    if allow.is_some() && !permitted {
        return failure(Error::new("invalid"), &network, "transport", allow);
    }
    let error_network = network.clone();
    let result = match body {
        Ok(body) => {
            let query = uri.query().is_some();
            tokio::task::spawn_blocking(move || {
                // Keep capacity owned by work which survives an HTTP caller's
                // cancellation; the response body independently retains it.
                let _budget = budget;
                exchange(&store, &sender, &network, &resource, &method, query, &body)
            })
            .await
            .unwrap_or_else(|_| Err(Error::new("internal")))
        }
        Err(_) => Err(Error::new("invalid")),
    };
    match result {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(error) => failure(error, &error_network, "transport", None),
    }
}
fn failure(error: Error, network: &str, stage: &str, allow: Option<&str>) -> Response {
    let status = if allow.is_some() {
        StatusCode::METHOD_NOT_ALLOWED
    } else {
        match error.code {
            "invalid" => StatusCode::BAD_REQUEST,
            "forbidden" | "authority_expired" | "not_yet_valid" | "device_revoked" => {
                StatusCode::FORBIDDEN
            }
            "not_found" => StatusCode::NOT_FOUND,
            "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
            "upgrade_required" => StatusCode::UPGRADE_REQUIRED,
            "internal" => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::CONFLICT,
        }
    };
    let message = if error.code == "internal" {
        "internal error".into()
    } else {
        error.code.replace('_', " ")
    };
    let mut response = (status, axum::Json(json!({"code":error.code,"error":message,"details":{"network_id":if ident(network,"net_"){network}else{"-"},"context_id":"-","request_id":"-","stage":stage,"required_ids":error.required_ids,"conflict_ids":[],"next":[]}}))).into_response();
    if let Some(allow) = allow
        && let Ok(header) = allow.parse()
    {
        response.headers_mut().insert(header::ALLOW, header);
    }
    if error.code == "rate_limited" {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
    }
    response
}
fn catalog_body(raw: &[u8]) -> Result<Vec<u8>> {
    let mut body = b"{\"catalog\":".to_vec();
    body.extend_from_slice(raw);
    body.push(b'}');
    require(body.len() <= WHOLE, "quota_exceeded")?;
    Ok(body)
}
fn exchange(
    store: &Store,
    sender: &str,
    network: &str,
    resource: &str,
    method: &Method,
    query: bool,
    body: &[u8],
) -> Result<Vec<u8>> {
    check(ident(network, "net_") && !query)?;
    require(
        matches!(resource, "catalog" | "contacts" | "contact" | "migration"),
        "not_found",
    )?;
    require(
        (matches!(resource, "catalog" | "migration")
            && matches!(*method, Method::GET | Method::POST))
            || (resource == "contacts" && *method == Method::GET)
            || (resource == "contact" && *method == Method::POST),
        "method_not_allowed",
    )?;
    if *method == Method::GET {
        check(body.is_empty())?;
    }
    if resource == "contact" {
        require(body.len() <= 16 << 10, "invalid")?;
    }
    if resource == "migration" {
        if *method == Method::POST {
            let value = parse(body, WHOLE)?;
            super::migration_evidence::peer_receive(store, network, sender, object(&value)?)?;
        }
        let output = super::migration_evidence::peer_export(store, network, sender)?;
        require(output.len() <= WHOLE, "quota_exceeded")?;
        return Ok(output);
    }
    let mut c = store.connection().map_err(|_| Error::new("internal"))?;
    let mut tx = c.transaction().map_err(db)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM networks WHERE id=?1)",
            [network],
            |r| r.get(0),
        )
        .map_err(db)?;
    require(exists, "not_found")?;
    let snapshot = Snapshot::load(&tx, network, &store.identity().public_key)?;
    let host = host_key(&snapshot, sender)?;
    authorize(&snapshot, &host, &super::controls::local_decision_time()?)?;
    let response = match resource {
        "catalog" if *method == Method::POST => {
            let value = parse(body, WHOLE)?;
            let object = object(&value)?;
            fields(object, "catalog")?;
            let candidate =
                encode_json(object.get("catalog").ok_or_else(|| Error::new("invalid"))?)?;
            // Incoming grants never supply the route's own authorization.
            let projection = snapshot.apply_catalog(
                &mut tx,
                &candidate,
                &super::controls::local_decision_time()?,
                "fresh",
            )?;
            catalog_body(&projection.catalog.bytes)?
        }
        "catalog" => catalog_body(&snapshot.prior.catalog.bytes)?,
        "contacts" => contacts(&tx, &snapshot, &super::controls::local_decision_time()?)?,
        "contact" => save_contact(
            &tx,
            &snapshot,
            &host,
            body,
            &super::controls::local_decision_time()?,
        )?,
        _ => return Err(Error::new("not_found")),
    };
    // Keep a withdrawal ingestible while rechecking the original caller path
    // against the actual final clock, never against a grant in the candidate.
    authorize(&snapshot, &host, &super::controls::local_decision_time()?)?;
    tx.commit().map_err(db)?;
    store
        .refresh_member_pins(&c)
        .map_err(|_| Error::new("internal"))?;
    Ok(response)
}

#[derive(Clone)]
struct ContactRecord {
    sequence: u64,
    hashes: Vec<String>,
    conflicted: bool,
    contacts: Vec<Contact>,
}
fn message_hash(contact: &Contact) -> Result<String> {
    let value = parse(&contact.body, 8 << 10)?;
    let object = object(&value)?;
    Ok(hash(&lines(&[
        "peerspan-decentralized-contact-v1",
        &contact.context_id,
        &contact.host_public_key,
        &contact.sequence.to_string(),
        &contact.issued_at,
        &contact.expires_at,
        &hash(&b64(text(object, "payload_base64")?, 8 << 10)?),
    ])))
}
fn contact_record(
    sequence: rusqlite::types::Value,
    raw: &str,
    context: &str,
    host: &str,
) -> Result<ContactRecord> {
    let sequence = super::storage::decode_u64(&sequence, false)?;
    let value = parse(raw.as_bytes(), 32 << 10)?;
    let object = object(&value)?;
    fields(object, "format message_hashes conflicted contacts_base64")?;
    version(object)?;
    let hashes: Vec<String> = array(object, "message_hashes")?
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| ident(s, ""))
                .map(str::to_owned)
                .ok_or_else(|| Error::new("state_conflict"))
        })
        .collect::<Result<_>>()?;
    let conflicted = object
        .get("conflicted")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::new("state_conflict"))?;
    check(hashes.len() == if conflicted { 2 } else { 1 })?;
    check(hashes.windows(2).all(|w| w[0] < w[1]))?;
    let mut contacts = Vec::new();
    let mut previous = None;
    for encoded in array(object, "contacts_base64")? {
        let contact = Contact::read(&b64(
            encoded
                .as_str()
                .ok_or_else(|| Error::new("state_conflict"))?,
            8 << 10,
        )?)?;
        check(
            contact.sequence == sequence
                && contact.context_id == context
                && contact.host_public_key == host
                && hashes.contains(&message_hash(&contact)?),
        )?;
        let body_hash = hash(&contact.body);
        check(previous.as_ref().is_none_or(|old| old < &body_hash))?;
        previous = Some(body_hash);
        contacts.push(contact);
    }
    check(contacts.len() <= hashes.len())?;
    Ok(ContactRecord {
        sequence,
        hashes,
        conflicted,
        contacts,
    })
}
fn contacts(c: &Connection, snapshot: &Snapshot, now: &str) -> Result<Vec<u8>> {
    let mut q = c.prepare("SELECT host_key,sequence,record FROM dec_contacts WHERE network_id=?1 AND context_id=?2 ORDER BY host_key").map_err(db)?;
    let rows = q
        .query_map(
            params![snapshot.descriptor.network_id, snapshot.network.context_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, rusqlite::types::Value>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(db)?;
    let mut output = Vec::new();
    for row in rows {
        let (host, sequence, raw) = row.map_err(db)?;
        let record = contact_record(sequence, &raw, &snapshot.network.context_id, &host)?;
        if !record.conflicted {
            for contact in record.contacts {
                if contact.valid_at(now).is_ok() {
                    output.push(contact.body);
                }
            }
        }
    }
    let mut body = b"{\"contacts\":[".to_vec();
    for (index, contact) in output.iter().enumerate() {
        if index != 0 {
            body.push(b',');
        }
        body.extend_from_slice(contact);
    }
    body.extend_from_slice(b"]}");
    require(body.len() <= 1 << 20, "quota_exceeded")?;
    Ok(body)
}
fn save_contact(
    c: &Connection,
    snapshot: &Snapshot,
    host: &str,
    body: &[u8],
    now: &str,
) -> Result<Vec<u8>> {
    let value = parse(body, 16 << 10)?;
    let object = object(&value)?;
    fields(object, "contact")?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        contact: Box<serde_json::value::RawValue>,
    }
    let input: Input = serde_json::from_slice(body).map_err(|_| Error::new("invalid"))?;
    let raw = input.contact.get().as_bytes().to_vec();
    let contact = Contact::read(&raw)?;
    check(contact.context_id == snapshot.network.context_id)?;
    require(contact.host_public_key == host, "forbidden")?;
    contact.valid_at(now)?;
    retain_contact(
        c,
        &snapshot.descriptor.network_id,
        &snapshot.network.context_id,
        &contact,
    )?;
    contact_body(&contact.body)
}
fn contact_body(raw: &[u8]) -> Result<Vec<u8>> {
    let mut response = b"{\"contact\":".to_vec();
    response.extend_from_slice(raw);
    response.push(b'}');
    require(response.len() <= 16 << 10, "quota_exceeded")?;
    Ok(response)
}
fn retain_contact(c: &Connection, network: &str, context: &str, contact: &Contact) -> Result<()> {
    let host = &contact.host_public_key;
    let incoming_hash = message_hash(contact)?;
    let old: Option<(rusqlite::types::Value, String)> = c.query_row("SELECT sequence,record FROM dec_contacts WHERE network_id=?1 AND context_id=?2 AND host_key=?3", params![network, context, host], |r| Ok((r.get(0)?, r.get(1)?))).optional().map_err(db)?;
    let old = old
        .map(|(sequence, raw)| contact_record(sequence, &raw, context, host))
        .transpose()?;
    let mut record = ContactRecord {
        sequence: contact.sequence,
        hashes: vec![incoming_hash.clone()],
        conflicted: false,
        contacts: vec![contact.clone()],
    };
    if let Some(previous) = old {
        require(contact.sequence >= previous.sequence, "state_conflict")?;
        if contact.sequence == previous.sequence {
            record = previous;
            if !record.hashes.contains(&incoming_hash) {
                record.hashes.push(incoming_hash);
                record.hashes.sort();
                record.hashes.truncate(2);
                record.conflicted = true;
                record.contacts.push(contact.clone());
                let hashes = record.hashes.clone();
                record
                    .contacts
                    .retain(|c| message_hash(c).is_ok_and(|h| hashes.contains(&h)));
            } else if !record
                .contacts
                .iter()
                .any(|c| message_hash(c).is_ok_and(|h| h == incoming_hash))
            {
                record.contacts.push(contact.clone());
            }
        }
    }
    record.contacts.sort_by_key(|c| hash(&c.body));
    let mut messages = std::collections::BTreeSet::new();
    record
        .contacts
        .retain(|c| message_hash(c).is_ok_and(|h| messages.insert(h)));
    let record_json = json!({"format":1,"message_hashes":record.hashes,"conflicted":record.conflicted,"contacts_base64":record.contacts.iter().map(|c| encode(&c.body)).collect::<Vec<_>>()});
    c.execute("INSERT INTO dec_contacts(network_id,context_id,host_key,sequence,record) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(network_id,context_id,host_key) DO UPDATE SET sequence=excluded.sequence,record=excluded.record",params![network,context,host,super::storage::encode_u64(record.sequence,false)?,record_json.to_string()]).map_err(db)?;
    Ok(())
}
/// Private pairing input is a signed transport hint only. Ordinary peer
/// permission and repair identity still require their independent H admission.
pub(crate) fn remember_pairing_contact(
    c: &Connection,
    network: &str,
    context: &str,
    writer: &str,
    raw: &[u8],
    now: &str,
) -> Result<()> {
    let contact = Contact::read(raw)?;
    check(
        contact.host_public_key == writer
            && (contact.context_id == "-" || contact.context_id == context),
    )?;
    contact.valid_at(now)?;
    let (network, context) = if contact.context_id == "-" {
        ("-", "-")
    } else {
        check(ident(network, "net_") && ident(context, "ctx_"))?;
        (network, context)
    };
    let previous:Option<(rusqlite::types::Value,String)>=c.query_row("SELECT sequence,record FROM dec_contacts WHERE network_id=?1 AND context_id=?2 AND host_key=?3",params![network,context,writer],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
    if let Some((sequence, raw)) = previous {
        let previous = contact_record(sequence, &raw, context, writer)?;
        if contact.sequence < previous.sequence {
            return Ok(());
        }
    }
    retain_contact(c, network, context, &contact)
}

/// Signed transport hints only. The caller must already have independently
/// verified this host; no returned address establishes a pin or permission.
pub(crate) fn product_addresses(
    c: &Connection,
    network: &str,
    context: &str,
    host: &str,
    now: &str,
) -> Result<Vec<String>> {
    for (network, context) in [(network, context), ("-", "-")] {
        let row:Option<(rusqlite::types::Value,String)>=c.query_row("SELECT sequence,record FROM dec_contacts WHERE network_id=?1 AND context_id=?2 AND host_key=?3",params![network,context,host],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db)?;
        let Some((sequence, raw)) = row else { continue };
        let record = contact_record(sequence, &raw, context, host)?;
        if record.conflicted {
            return Ok(Vec::new());
        }
        let mut addresses = std::collections::BTreeSet::new();
        for contact in record.contacts {
            if contact.valid_at(now).is_ok() {
                for address in array(object(&contact.payload)?, "quic_addresses")? {
                    addresses.insert(
                        address
                            .as_str()
                            .ok_or_else(|| Error::new("state_conflict"))?
                            .to_owned(),
                    );
                }
            }
        }
        return Ok(addresses.into_iter().collect());
    }
    Ok(Vec::new())
}
