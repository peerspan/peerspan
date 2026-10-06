//! Credential-scoped session handoff and bounded replies. This router never
//! exposes owner administration or arbitrary outbound messaging.
use crate::{
    adapter_connection::AdapterAuth,
    api::{blocking, decode},
    model::{Error, Session},
    peer_store::{Connectivity, MessageRequest, Peer, grant_bounds, valid_id},
    store::{Store, append_event, new_id, now},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) const SCHEMA: &str = "
CREATE TABLE adapter_credentials (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id), token_hash TEXT NOT NULL UNIQUE, record TEXT NOT NULL);
CREATE TABLE deliveries (id TEXT PRIMARY KEY, sender TEXT NOT NULL, request_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, request_id));
CREATE TABLE received_replies (sender TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, request_id));
CREATE TABLE outbound_replies (peer TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, request_id));
PRAGMA user_version = 4;
";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Adapter {
    pub id: String,
    pub session_id: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAdapter {
    pub session_id: String,
    pub expires_at: String,
}
#[derive(Serialize)]
pub struct AdapterCredential {
    pub adapter: Adapter,
    pub token: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub replaced_adapter_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delivery {
    pub id: String,
    pub sender_host_id: String,
    pub request_id: String,
    pub target_agent_id: String,
    pub session_id: String,
    pub adapter_id: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Serialize)]
pub struct DeliveryRecord {
    pub sequence: i64,
    pub delivery: Delivery,
}
#[derive(Serialize)]
pub struct Handoff {
    pub delivery: Delivery,
    pub request: MessageRequest,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub sender_host_id: String,
    pub request_id: String,
    pub receiver_host_id: String,
    pub target_agent_id: String,
    pub session_id: String,
    pub delivery_id: String,
    pub content: String,
    pub replied_at: String,
}
#[derive(Serialize)]
pub struct ReplyStatus {
    pub state: String,
    pub reply: Option<Reply>,
    pub error: Option<String>,
}

pub(crate) fn read<T: DeserializeOwned>(
    conn: &Connection,
    query: &str,
    args: impl rusqlite::Params,
) -> Result<T, Error> {
    let text: String = conn.query_row(query, args, |row| row.get(0))?;
    Ok(serde_json::from_str(&text)?)
}
fn rows<T: DeserializeOwned>(conn: &Connection, query: &str) -> Result<Vec<T>, Error> {
    let mut statement = conn.prepare(query)?;
    statement
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|r| Ok(serde_json::from_str(&r?)?))
        .collect()
}
fn expires(value: &str) -> Result<DateTime<chrono::FixedOffset>, Error> {
    DateTime::parse_from_rfc3339(value).map_err(|e| Error::Internal(e.into()))
}
pub(crate) fn session(conn: &Connection, id: &str) -> Result<Session, Error> {
    Ok(conn.query_row(
        "SELECT id,agent_id,integration,state,created_at,updated_at FROM sessions WHERE id = ?1",
        [id],
        |r| {
            Ok(Session {
                id: r.get(0)?,
                agent_id: r.get(1)?,
                integration: r.get(2)?,
                state: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
            })
        },
    )?)
}
pub(crate) fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
pub(crate) fn credential_authority(
    conn: &Connection,
    token: &str,
) -> Result<(Adapter, Session), Error> {
    if !valid_id(token, "token", 32) {
        return Err(Error::Forbidden);
    }
    let a: Adapter = read(
        conn,
        "SELECT record FROM adapter_credentials WHERE token_hash = ?1",
        [token_hash(token)],
    )
    .map_err(|e| match e {
        Error::NotFound => Error::Forbidden,
        other => other,
    })?;
    if a.revoked_at.is_some() || expires(&a.expires_at)? <= Utc::now() {
        return Err(Error::Forbidden);
    }
    let ss = session(conn, &a.session_id)?;
    Ok((a, ss))
}
pub(crate) fn authority(
    conn: &Connection,
    auth: &AdapterAuth,
) -> Result<(Adapter, Session), Error> {
    crate::adapter_connection::authority(conn, auth)
}
fn owned(conn: &Connection, token: &AdapterAuth, id: &str) -> Result<Delivery, Error> {
    let (a, ss) = authority(conn, token)?;
    let d: Delivery = read(conn, "SELECT record FROM deliveries WHERE id = ?1", [id])?;
    if d.adapter_id != a.id || d.session_id != ss.id || d.state == "blocked" {
        return Err(Error::Forbidden);
    }
    Ok(d)
}
fn update(tx: &Transaction<'_>, d: &Delivery, kind: &str) -> Result<(), Error> {
    tx.execute(
        "UPDATE deliveries SET record = ?1 WHERE id = ?2",
        params![serde_json::to_string(d)?, d.id],
    )?;
    Ok(append_event(tx, kind, &d.id, &d.updated_at)?)
}
impl Store {
    pub fn create_adapter(&self, r: CreateAdapter) -> Result<AdapterCredential, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let credential = self.create_adapter_in(&tx, r)?;
        tx.commit()?;
        Ok(credential)
    }
    pub(crate) fn create_adapter_in(
        &self,
        tx: &Transaction<'_>,
        r: CreateAdapter,
    ) -> Result<AdapterCredential, Error> {
        let expiration = DateTime::parse_from_rfc3339(&r.expires_at)
            .map_err(|_| Error::Invalid("invalid expiration".into()))?;
        if expiration <= Utc::now() {
            return Err(Error::Invalid("invalid expiration".into()));
        }
        let ss = session(tx, &r.session_id)?;
        if ss.state != "attached" {
            return Err(Error::Forbidden);
        }
        let active = {
            let mut stmt = tx.prepare("SELECT c.record,x.instance_hash,x.lease_until_ms FROM adapter_credentials c JOIN sessions s ON c.session_id = s.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE s.agent_id = ?1 AND (s.state = 'attached' OR x.recoverable = 1) ORDER BY c.id")?;
            stmt.query_map([&ss.agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let current = Utc::now();
        let at = now();
        let mut stale = Vec::new();
        for (data, hash, until) in active {
            let old: Adapter = serde_json::from_str(&data)?;
            if old.revoked_at.is_some() || expires(&old.expires_at)? <= current {
                continue;
            }
            // A fresh owner-authorized session replaces only a bound offline
            // adapter. Preserve unbound setups, live leases, and the startup
            // reconnect window for previously bound instances.
            if old.session_id == r.session_id {
                return Err(Error::Conflict(
                    "replacement requires a fresh session attachment".into(),
                ));
            }
            if hash.is_none() {
                return Err(Error::Conflict(format!(
                    "adapter {} has not connected; revoke it or detach its session to cancel that setup",
                    old.id
                )));
            }
            if until > current.timestamp_millis() {
                let lease = crate::store::rfc3339(
                    DateTime::from_timestamp_millis(until)
                        .ok_or_else(|| Error::Internal(anyhow::anyhow!("invalid lease")))?,
                );
                return Err(Error::Conflict(format!(
                    "adapter {} has a live lease until {}; retry after it expires or explicitly detach its session",
                    old.id, lease
                )));
            }
            if let Some(deadline) = self.adapter_recovery_until.get(&old.id)
                && let Some(remaining) = deadline.checked_duration_since(Instant::now())
                && !remaining.is_zero()
            {
                let until = crate::store::rfc3339(
                    Utc::now()
                        + chrono::Duration::from_std(remaining)
                            .map_err(|e| Error::Internal(e.into()))?,
                );
                return Err(Error::Conflict(format!(
                    "adapter {} has a restart reconnect window until {}; retry after it expires or explicitly detach its session",
                    old.id, until
                )));
            }
            stale.push(old);
        }
        if expiration <= current {
            return Err(Error::Invalid("invalid expiration".into()));
        }
        let mut replaced_adapter_ids = Vec::new();
        for mut old in stale {
            old.revoked_at = Some(at.clone());
            tx.execute(
                "UPDATE adapter_credentials SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&old)?, old.id],
            )?;
            tx.execute("UPDATE adapter_connections SET recoverable = 0,lease_until_ms = 0 WHERE adapter_id = ?1",[&old.id])?;
            tx.execute(
                "UPDATE sessions SET state = 'detached',updated_at = ?1 WHERE id = ?2",
                params![at, old.session_id],
            )?;
            append_event(tx, "adapter.replaced", &old.id, &at)?;
            append_event(tx, "session.detached", &old.session_id, &at)?;
            replaced_adapter_ids.push(old.id);
        }
        let a = Adapter {
            id: new_id("adapter")?,
            session_id: r.session_id,
            expires_at: r.expires_at,
            revoked_at: None,
        };
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
        let token = format!("token_{}", hex::encode(random));
        tx.execute(
            "INSERT INTO adapter_credentials VALUES (?1,?2,?3,?4)",
            params![
                a.id,
                a.session_id,
                token_hash(&token),
                serde_json::to_string(&a)?
            ],
        )?;
        tx.execute(
            "INSERT INTO adapter_connections(adapter_id) VALUES (?1)",
            [&a.id],
        )?;
        append_event(tx, "adapter.created", &a.id, &now())?;
        Ok(AdapterCredential {
            adapter: a,
            token,
            replaced_adapter_ids,
        })
    }
    pub fn adapter(&self, id: &str) -> Result<Adapter, Error> {
        read(
            &*self.connection()?,
            "SELECT record FROM adapter_credentials WHERE id = ?1",
            [id],
        )
    }
    pub fn adapters(&self) -> Result<Vec<Adapter>, Error> {
        rows(
            &*self.connection()?,
            "SELECT record FROM adapter_credentials ORDER BY id",
        )
    }
    pub fn revoke_adapter(&self, id: &str) -> Result<Adapter, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut a: Adapter = read(
            &tx,
            "SELECT record FROM adapter_credentials WHERE id = ?1",
            [id],
        )?;
        if a.revoked_at.is_some() {
            return Ok(a);
        }
        let at = now();
        a.revoked_at = Some(at.clone());
        tx.execute(
            "UPDATE adapter_credentials SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&a)?, id],
        )?;
        append_event(&tx, "adapter.revoked", id, &at)?;
        tx.commit()?;
        Ok(a)
    }
    pub fn adapter_session(&self, token: &AdapterAuth) -> Result<Session, Error> {
        Ok(authority(&*self.connection()?, token)?.1)
    }
    pub fn next_delivery(&self, token: &AdapterAuth) -> Result<Option<Handoff>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, token)?;
        let pending = {
            let mut stmt = tx.prepare("SELECT m.sender,m.request FROM received_messages m WHERE json_extract(m.request,'$.target_agent_id') = ?1 AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.sender = m.sender AND d.request_id = m.request_id) ORDER BY m.rowid LIMIT 100")?;
            stmt.query_map([&ss.agent_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|row| {
                let (sender, text) = row?;
                Ok((sender, serde_json::from_str::<MessageRequest>(&text)?))
            })
            .collect::<Result<Vec<_>, Error>>()?
        };
        let mut handoff = None;
        for (sender, request) in pending {
            let state = match grant_bounds(&tx, &sender, &request, true) {
                Ok(g) => match self.grant_connected(&tx, &sender, &g)? {
                    Connectivity::Usable => "unknown",
                    // A recoverable connected state is not final: leave the
                    // message unclaimed, without a delivery record, until
                    // syncing resumes or its deadline passes.
                    Connectivity::Stale => continue,
                    Connectivity::Absent => "blocked",
                },
                Err(Error::Forbidden) => "blocked",
                Err(e) => return Err(e),
            };
            let at = now();
            let d = Delivery {
                id: new_id("delivery")?,
                sender_host_id: sender,
                request_id: request.request_id.clone(),
                target_agent_id: ss.agent_id.clone(),
                session_id: ss.id.clone(),
                adapter_id: a.id.clone(),
                state: state.into(),
                created_at: at.clone(),
                updated_at: at,
            };
            tx.execute(
                "INSERT INTO deliveries VALUES (?1,?2,?3,?4,?5)",
                params![
                    d.id,
                    d.sender_host_id,
                    d.request_id,
                    d.session_id,
                    serde_json::to_string(&d)?
                ],
            )?;
            append_event(
                &tx,
                if state == "blocked" {
                    "message.blocked"
                } else {
                    "message.handoff"
                },
                &d.id,
                &d.created_at,
            )?;
            if state == "unknown" {
                handoff = Some(Handoff {
                    delivery: d,
                    request,
                });
                break;
            }
        }
        tx.commit()?;
        Ok(handoff)
    }
    pub fn delivery(&self, id: &str) -> Result<Delivery, Error> {
        read(
            &*self.connection()?,
            "SELECT record FROM deliveries WHERE id = ?1",
            [id],
        )
    }
    pub fn deliveries(&self, after: i64, limit: i64) -> Result<Vec<DeliveryRecord>, Error> {
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("invalid page bounds".into()));
        }
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT rowid,record FROM deliveries WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
        )?;
        stmt.query_map(params![after, limit], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?
        .map(|r| {
            let (sequence, text) = r?;
            Ok(DeliveryRecord {
                sequence,
                delivery: serde_json::from_str(&text)?,
            })
        })
        .collect()
    }
    pub fn forwarded(&self, token: &AdapterAuth, id: &str) -> Result<Delivery, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut d = owned(&tx, token, id)?;
        if d.state != "unknown" {
            return Ok(d);
        }
        d.state = "forwarded".into();
        d.updated_at = now();
        update(&tx, &d, "message.forwarded")?;
        tx.commit()?;
        Ok(d)
    }
    pub fn reply(&self, token: &AdapterAuth, id: &str, content: String) -> Result<Reply, Error> {
        if content.is_empty() || content.len() > 65536 {
            return Err(Error::Invalid("invalid reply content".into()));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut d = owned(&tx, token, id)?;
        let request: MessageRequest = read(
            &tx,
            "SELECT request FROM received_messages WHERE sender = ?1 AND request_id = ?2",
            params![d.sender_host_id, d.request_id],
        )?;
        // A reply answers content this host already delivered, so only final
        // bounds apply; a lapsed connected state does not strand it.
        let g = grant_bounds(&tx, &d.sender_host_id, &request, false)?;
        if content.len() as i64 > g.max_message_bytes {
            return Err(Error::Forbidden);
        }
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM received_replies WHERE sender = ?1 AND request_id = ?2",
                params![d.sender_host_id, d.request_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old: Reply = serde_json::from_str(&old)?;
            if old.content != content {
                return Err(Error::Conflict(
                    "reply already exists with different content".into(),
                ));
            }
            return Ok(old);
        }
        let at = now();
        let r = Reply {
            sender_host_id: d.sender_host_id.clone(),
            request_id: d.request_id.clone(),
            receiver_host_id: self.identity().id,
            target_agent_id: d.target_agent_id.clone(),
            session_id: d.session_id.clone(),
            delivery_id: d.id.clone(),
            content,
            replied_at: at.clone(),
        };
        tx.execute(
            "INSERT INTO received_replies VALUES (?1,?2,?3)",
            params![d.sender_host_id, d.request_id, serde_json::to_string(&r)?],
        )?;
        d.state = "replied".into();
        d.updated_at = at;
        update(&tx, &d, "message.replied")?;
        tx.commit()?;
        Ok(r)
    }
    pub fn received_reply(&self, sender: &str, id: &str) -> Result<Reply, Error> {
        read(
            &*self.connection()?,
            "SELECT record FROM received_replies WHERE sender = ?1 AND request_id = ?2",
            params![sender, id],
        )
    }
    pub fn outbound_reply(&self, peer: &str, id: &str) -> Result<Reply, Error> {
        read(
            &*self.connection()?,
            "SELECT record FROM outbound_replies WHERE peer = ?1 AND request_id = ?2",
            params![peer, id],
        )
    }
    pub fn save_outbound_reply(&self, peer: &str, r: Reply) -> Result<Reply, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM outbound_replies WHERE peer = ?1 AND request_id = ?2",
                params![peer, r.request_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old: Reply = serde_json::from_str(&old)?;
            if old != r {
                return Err(Error::Conflict("reply changed".into()));
            }
            return Ok(old);
        }
        tx.execute(
            "INSERT INTO outbound_replies VALUES (?1,?2,?3)",
            params![peer, r.request_id, serde_json::to_string(&r)?],
        )?;
        append_event(
            &tx,
            "reply.received",
            &format!("{peer}/{}", r.request_id),
            &now(),
        )?;
        tx.commit()?;
        Ok(r)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyRequest {
    content: String,
}
pub(crate) fn token(headers: &HeaderMap) -> AdapterAuth {
    let value = bearer(headers);
    let instance = if headers.get_all("X-Capsule-Instance").iter().count() == 1 {
        headers
            .get("X-Capsule-Instance")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    } else {
        String::new()
    };
    AdapterAuth {
        token: value,
        instance,
    }
}
fn bearer(headers: &HeaderMap) -> String {
    if headers.get_all("Authorization").iter().count() != 1 {
        return String::new();
    }
    headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("")
        .into()
}
pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .merge(crate::adapter_connection::adapter_routes())
        .merge(crate::adapter_outbound::adapter_routes())
        .route("/adapter/v1/session", get(adapter_session))
        .route("/adapter/v1/next", post(next))
        .route("/adapter/v1/deliveries/{id}/forwarded", post(forwarded))
        .route("/adapter/v1/deliveries/{id}/reply", post(reply))
        .layer(DefaultBodyLimit::max(1 << 20))
        .with_state(store)
}
async fn adapter_session(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
) -> Result<Json<Session>, Error> {
    let token = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.adapter_session(&token)).await?,
    ))
}
async fn next(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<Handoff>>, Error> {
    let _: Empty = decode(body)?;
    let token = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.next_delivery(&token)).await?,
    ))
}
async fn forwarded(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Delivery>, Error> {
    let _: Empty = decode(body)?;
    let token = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.forwarded(&token, &id)).await?,
    ))
}
async fn reply(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Reply>, Error> {
    let r: ReplyRequest = decode(body)?;
    let token = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.reply(&token, &id, r.content)).await?,
    ))
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .merge(crate::adapter_connection::local_routes())
        .merge(crate::adapter_outbound::local_routes())
        .route("/v1/adapters", get(adapters).post(create))
        .route("/v1/adapters/{id}", get(adapter))
        .route("/v1/adapters/{id}/revoke", post(revoke))
        .route("/v1/deliveries", get(deliveries))
        .route("/v1/deliveries/{id}", get(delivery))
        .route("/v1/outbound/{peer}/{id}/reply", post(fetch_reply))
}
async fn adapters(State(store): State<Arc<Store>>) -> Result<Json<Vec<Adapter>>, Error> {
    Ok(Json(blocking(store, Store::adapters).await?))
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<AdapterCredential>), Error> {
    let r = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.create_adapter(r)).await?),
    ))
}
async fn adapter(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Adapter>, Error> {
    Ok(Json(blocking(store, move |s| s.adapter(&id)).await?))
}
async fn revoke(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Adapter>, Error> {
    Ok(Json(blocking(store, move |s| s.revoke_adapter(&id)).await?))
}
async fn delivery(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Delivery>, Error> {
    Ok(Json(blocking(store, move |s| s.delivery(&id)).await?))
}
#[derive(Deserialize)]
struct Page {
    after: Option<i64>,
    limit: Option<i64>,
}
async fn deliveries(
    State(store): State<Arc<Store>>,
    query: Result<Query<Page>, QueryRejection>,
) -> Result<Json<Vec<DeliveryRecord>>, Error> {
    let Query(p) = query.map_err(|_| Error::Invalid("invalid page bounds".into()))?;
    Ok(Json(
        blocking(store, move |s| {
            s.deliveries(p.after.unwrap_or(0), p.limit.unwrap_or(100))
        })
        .await?,
    ))
}
pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new().route("/peer/v1/replies/{id}", get(peer_reply))
}
async fn peer_reply(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
) -> Result<Json<Reply>, Error> {
    Ok(Json(
        blocking(store, move |s| s.received_reply(&sender, &id)).await?,
    ))
}
async fn lookup(store: Arc<Store>, peer: Peer, id: &str) -> anyhow::Result<(u16, Vec<u8>)> {
    crate::quic::request(store, &peer, "GET", &format!("/peer/v1/replies/{id}"), b"").await
}
async fn fetch_reply(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<ReplyStatus>, Error> {
    Ok(Json(fetch_reply_status(store, peer, id).await?))
}

pub(crate) async fn fetch_reply_status(
    store: Arc<Store>,
    peer: String,
    id: String,
) -> Result<ReplyStatus, Error> {
    let p = peer.clone();
    let rid = id.clone();
    let out = blocking(store.clone(), move |s| s.outbound(&p, &rid)).await?;
    let p = peer.clone();
    let rid = id.clone();
    match blocking(store.clone(), move |s| s.outbound_reply(&p, &rid)).await {
        Ok(r) => {
            return Ok(ReplyStatus {
                state: "replied".into(),
                reply: Some(r),
                error: None,
            });
        }
        Err(Error::NotFound) => {}
        Err(e) => return Err(e),
    }
    let p = peer.clone();
    let target = blocking(store.clone(), move |s| s.dial_target(&p)).await?;
    let response =
        tokio::time::timeout(Duration::from_secs(8), lookup(store.clone(), target, &id)).await;
    let mut status = ReplyStatus {
        state: "unknown".into(),
        reply: None,
        error: Some("peer reply could not be confirmed".into()),
    };
    match response {
        Ok(Ok((404, _))) => {
            status.state = "pending".into();
            status.error = None;
        }
        Ok(Ok((200, body))) => {
            if let Ok(r) = serde_json::from_slice::<Reply>(&body)
                && r.sender_host_id == store.identity().id
                && r.receiver_host_id == peer
                && r.request_id == out.request.request_id
                && r.target_agent_id == out.request.target_agent_id
                && valid_id(&r.session_id, "session", 16)
                && valid_id(&r.delivery_id, "delivery", 16)
                && !r.content.is_empty()
                && r.content.len() <= 65536
                && DateTime::parse_from_rfc3339(&r.replied_at).is_ok()
            {
                let r = blocking(store, move |s| s.save_outbound_reply(&peer, r)).await?;
                status = ReplyStatus {
                    state: "replied".into(),
                    reply: Some(r),
                    error: None,
                };
            }
        }
        _ => {}
    }
    Ok(status)
}
