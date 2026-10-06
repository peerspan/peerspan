//! Live adapter leases, recovery by the original instance, and token rotation.
use crate::{
    adapter::{Adapter, AdapterCredential, credential_authority, read, session, token, token_hash},
    api::{blocking, decode},
    model::{Error, Session},
    peer_store::valid_id,
    store::{Store, append_event, now, rfc3339},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection as DB, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(crate) const SCHEMA:&str="
CREATE TABLE adapter_connections (adapter_id TEXT PRIMARY KEY REFERENCES adapter_credentials(id), instance_hash TEXT, lease_until_ms INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT, recoverable INTEGER NOT NULL DEFAULT 0 CHECK(recoverable IN (0,1)));
INSERT INTO adapter_connections(adapter_id) SELECT id FROM adapter_credentials;
PRAGMA user_version = 6;
";
pub struct AdapterAuth {
    pub token: String,
    pub instance: String,
}
#[derive(Serialize)]
pub struct Connection {
    pub adapter_id: String,
    pub session_id: String,
    pub state: String,
    pub recoverable: bool,
    pub lease_expires_at: Option<String>,
    pub last_seen_at: Option<String>,
}
type Binding = (Option<String>, i64, Option<String>, bool);
fn binding(conn: &DB, id: &str) -> Result<Binding, Error> {
    Ok(conn.query_row("SELECT instance_hash,lease_until_ms,last_seen_at,recoverable FROM adapter_connections WHERE adapter_id = ?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?)
}
pub(crate) fn authority(conn: &DB, auth: &AdapterAuth) -> Result<(Adapter, Session), Error> {
    let (a, ss) = credential_authority(conn, &auth.token)?;
    let (hash, until, _, recoverable) = binding(conn, &a.id)?;
    if !valid_id(&auth.instance, "instance", 32)
        || hash.as_deref() != Some(token_hash(&auth.instance).as_str())
    {
        return Err(Error::Forbidden);
    }
    if ss.state == "detached" && !recoverable {
        return Err(Error::Forbidden);
    }
    if ss.state != "attached" || until <= Utc::now().timestamp_millis() {
        return Err(Error::Unavailable("adapter connection is not ready".into()));
    }
    Ok((a, ss))
}
fn status(conn: &DB, a: &Adapter, ss: &Session) -> Result<Connection, Error> {
    let (hash, until, last, recoverable) = binding(conn, &a.id)?;
    let expiry =
        DateTime::parse_from_rfc3339(&a.expires_at).map_err(|e| Error::Internal(e.into()))?;
    let state = if a.revoked_at.is_some() {
        "revoked"
    } else if expiry <= Utc::now() {
        "expired"
    } else if ss.state == "detached" && !recoverable {
        "detached"
    } else if hash.is_none() {
        "registered"
    } else if ss.state == "attached" && until > Utc::now().timestamp_millis() {
        "ready"
    } else {
        "offline"
    };
    Ok(Connection {
        adapter_id: a.id.clone(),
        session_id: ss.id.clone(),
        state: state.into(),
        recoverable: recoverable && hash.is_some() && a.revoked_at.is_none() && expiry > Utc::now(),
        lease_expires_at: if until > 0 {
            Some(rfc3339(DateTime::from_timestamp_millis(until).ok_or_else(
                || Error::Internal(anyhow::anyhow!("invalid lease")),
            )?))
        } else {
            None
        },
        last_seen_at: last,
    })
}
impl Store {
    pub fn adapter_connection(&self, id: &str) -> Result<Connection, Error> {
        let conn = self.connection()?;
        let a: Adapter = read(
            &conn,
            "SELECT record FROM adapter_credentials WHERE id = ?1",
            [id],
        )?;
        let ss = session(&conn, &a.session_id)?;
        status(&conn, &a, &ss)
    }
    pub fn connect_adapter(
        &self,
        token: &str,
        instance: &str,
        adapter_id: &str,
        session_id: &str,
    ) -> Result<Connection, Error> {
        if !valid_id(instance, "instance", 32)
            || !valid_id(adapter_id, "adapter", 16)
            || !valid_id(session_id, "session", 16)
        {
            return Err(Error::Invalid("invalid instance".into()));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, mut ss) = credential_authority(&tx, token)?;
        if a.id != adapter_id || ss.id != session_id {
            return Err(Error::Forbidden);
        }
        let (hash, until, _, recoverable) = binding(&tx, &a.id)?;
        if ss.state == "detached" && (hash.is_none() || !recoverable) {
            return Err(Error::Forbidden);
        }
        if hash.as_ref().is_some_and(|h| h != &token_hash(instance)) {
            return Err(Error::Conflict(
                "authorization belongs to another adapter instance".into(),
            ));
        }
        let current = Utc::now();
        let expiry = DateTime::parse_from_rfc3339(&a.expires_at)
            .map_err(|e| Error::Internal(e.into()))?
            .with_timezone(&Utc);
        let lease = (current + chrono::Duration::seconds(15)).min(expiry);
        let at = now();
        if ss.state == "detached" {
            tx.execute(
                "UPDATE sessions SET state = 'attached',updated_at = ?1 WHERE id = ?2",
                params![at, ss.id],
            )?;
            append_event(&tx, "session.reconnected", &ss.id, &at)?;
            ss.state = "attached".into();
        }
        tx.execute("UPDATE adapter_connections SET instance_hash = ?1,lease_until_ms = ?2,last_seen_at = ?3,recoverable = 1 WHERE adapter_id = ?4",params![token_hash(instance),lease.timestamp_millis(),at,a.id])?;
        if hash.is_none() || until <= current.timestamp_millis() {
            append_event(&tx, "adapter.connected", &a.id, &at)?;
        }
        let c = status(&tx, &a, &ss)?;
        tx.commit()?;
        Ok(c)
    }
    pub fn rotate_adapter(&self, id: &str) -> Result<AdapterCredential, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let a: Adapter = read(
            &tx,
            "SELECT record FROM adapter_credentials WHERE id = ?1",
            [id],
        )?;
        let ss = session(&tx, &a.session_id)?;
        let c = status(&tx, &a, &ss)?;
        if matches!(c.state.as_str(), "expired" | "revoked" | "detached") {
            return Err(Error::Forbidden);
        }
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
        let token = format!("token_{}", hex::encode(random));
        tx.execute(
            "UPDATE adapter_credentials SET token_hash = ?1 WHERE id = ?2",
            params![token_hash(&token), a.id],
        )?;
        append_event(&tx, "adapter.credential_rotated", &a.id, &now())?;
        tx.commit()?;
        Ok(AdapterCredential { adapter: a, token })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connect {
    instance_id: String,
    adapter_id: String,
    session_id: String,
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new().route("/adapter/v1/connect", post(connect))
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/adapters/{id}/connection", get(inspect))
        .route("/v1/adapters/{id}/rotate", post(rotate))
}
async fn connect(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Connection>, Error> {
    let req: Connect = decode(body)?;
    let auth = token(&headers);
    Ok(Json(
        blocking(store, move |s| {
            s.connect_adapter(
                &auth.token,
                &req.instance_id,
                &req.adapter_id,
                &req.session_id,
            )
        })
        .await?,
    ))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Connection>, Error> {
    Ok(Json(
        blocking(store, move |s| s.adapter_connection(&id)).await?,
    ))
}
async fn rotate(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<AdapterCredential>, Error> {
    Ok(Json(blocking(store, move |s| s.rotate_adapter(&id)).await?))
}
