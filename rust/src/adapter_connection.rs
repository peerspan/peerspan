//! Live adapter leases, recovery by the original instance, and token rotation.
use crate::{
    adapter::{
        Adapter, AdapterCredential, credential_authority, read, renewed_expiry, session, token,
        token_hash,
    },
    adapter_outbound::OutboundRoute,
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
use rusqlite::{Connection as DB, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(crate) const SCHEMA:&str="
CREATE TABLE adapter_connections (adapter_id TEXT PRIMARY KEY REFERENCES adapter_credentials(id), instance_hash TEXT, lease_until_ms INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT, recoverable INTEGER NOT NULL DEFAULT 0 CHECK(recoverable IN (0,1)));
INSERT INTO adapter_connections(adapter_id) SELECT id FROM adapter_credentials;
PRAGMA user_version = 6;
";
pub(crate) const LEASE_SECONDS: u64 = 15;
#[derive(Clone)]
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
/// Moves a live renewable credential's expiry to a day ahead, with the routes
/// that follow it, when that gains at least a minute. The first renewal, and
/// then at most one an hour, is recorded.
fn renew(tx: &Transaction<'_>, a: &mut Adapter) -> Result<(), Error> {
    let old = DateTime::parse_from_rfc3339(&a.expires_at).map_err(|e| Error::Internal(e.into()))?;
    let next = renewed_expiry();
    let parsed = DateTime::parse_from_rfc3339(&next).map_err(|e| Error::Internal(e.into()))?;
    if parsed - old < chrono::TimeDelta::seconds(60) {
        return Ok(());
    }
    a.expires_at = next;
    tx.execute(
        "UPDATE adapter_credentials SET record = ?1 WHERE id = ?2",
        params![serde_json::to_string(&a)?, a.id],
    )?;
    let routes = {
        let mut stmt = tx.prepare("SELECT record FROM adapter_routes WHERE adapter_id = ?1")?;
        stmt.query_map([&a.id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for record in routes {
        let mut route: OutboundRoute = serde_json::from_str(&record)?;
        if route.follows_credential && route.revoked_at.is_none() {
            route.expires_at = a.expires_at.clone();
            tx.execute(
                "UPDATE adapter_routes SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&route)?, route.id],
            )?;
        }
    }
    let last: Option<String> = tx
        .query_row(
            "SELECT created_at FROM events WHERE kind = 'adapter.renewed' AND subject_id = ?1 ORDER BY sequence DESC LIMIT 1",
            [&a.id],
            |r| r.get(0),
        )
        .optional()?;
    let due = match last {
        None => true,
        Some(at) => DateTime::parse_from_rfc3339(&at).map_or(true, |at| {
            Utc::now() - at.with_timezone(&Utc) >= chrono::TimeDelta::hours(1)
        }),
    };
    if due {
        append_event(tx, "adapter.renewed", &a.id, &now())?;
    }
    Ok(())
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
        let mut a = a;
        if a.renewable {
            renew(&tx, &mut a)?;
        }
        let current = Utc::now();
        let expiry = DateTime::parse_from_rfc3339(&a.expires_at)
            .map_err(|e| Error::Internal(e.into()))?
            .with_timezone(&Utc);
        let lease = (current + chrono::Duration::seconds(LEASE_SECONDS as i64)).min(expiry);
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
        Ok(AdapterCredential {
            adapter: a,
            token,
            replaced_adapter_ids: Vec::new(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter::CreateAdapter,
        adapter_outbound::CreateOutboundRoute,
        model::{AttachSession, RegisterAgent},
        peer_store::tests::add_test_peer,
    };

    fn route(
        adapter: &str,
        peer: &str,
        name: &str,
        expires_at: Option<String>,
    ) -> CreateOutboundRoute {
        CreateOutboundRoute {
            adapter_id: adapter.into(),
            name: name.into(),
            peer_host_id: peer.into(),
            target_agent_id: format!("agent_{}", "1".repeat(32)),
            grant_id: None,
            expires_at,
            max_message_bytes: 100,
            max_messages: 10,
            action: None,
            delegation_depth: 0,
            follows_credential: false,
        }
    }
    /// Moves a stored expiry back, as if the credential were an hour from
    /// its end.
    fn age(store: &Store, a: &Adapter, routes: &[&OutboundRoute]) -> String {
        let earlier = rfc3339(Utc::now() + chrono::TimeDelta::hours(1));
        let conn = store.connection().unwrap();
        let mut a = a.clone();
        a.expires_at = earlier.clone();
        conn.execute(
            "UPDATE adapter_credentials SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&a).unwrap(), a.id],
        )
        .unwrap();
        for r in routes {
            let mut r = (*r).clone();
            r.expires_at = earlier.clone();
            conn.execute(
                "UPDATE adapter_routes SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&r).unwrap(), r.id],
            )
            .unwrap();
        }
        earlier
    }

    #[test]
    fn renewable_credentials_and_following_routes_move_on_connect() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let peer = add_test_peer(&store);
        let agent = store
            .register_agent(RegisterAgent {
                name: "a".into(),
                owner: "a".into(),
                capabilities: vec![],
            })
            .unwrap();
        let session = store
            .attach_session(AttachSession {
                agent_id: agent.id.clone(),
                integration: "test".into(),
            })
            .unwrap();
        let credential = store
            .create_adapter(CreateAdapter {
                session_id: session.id.clone(),
                expires_at: None,
            })
            .unwrap();
        let a = credential.adapter.clone();
        assert!(a.renewable);
        let expiry = DateTime::parse_from_rfc3339(&a.expires_at).unwrap();
        assert!(expiry > Utc::now() + chrono::TimeDelta::hours(23));
        let following = store
            .create_outbound_route(route(&a.id, &peer.id, "follow", None))
            .unwrap();
        assert!(following.follows_credential);
        assert_eq!(following.expires_at, a.expires_at);
        let fixed_expiry = rfc3339(Utc::now() + chrono::TimeDelta::minutes(30));
        let fixed = store
            .create_outbound_route(route(&a.id, &peer.id, "fixed", Some(fixed_expiry.clone())))
            .unwrap();
        assert!(!fixed.follows_credential);
        let renewals = || {
            store
                .events(0, 1000)
                .unwrap()
                .iter()
                .filter(|e| e.kind == "adapter.renewed" && e.subject_id == a.id)
                .count()
        };
        let instance = format!("instance_{}", "7".repeat(64));
        let connect = || {
            store
                .connect_adapter(&credential.token, &instance, &a.id, &session.id)
                .unwrap()
        };
        // Within a minute of a full day: unchanged and not recorded.
        connect();
        assert_eq!(store.adapter(&a.id).unwrap().expires_at, a.expires_at);
        assert_eq!(renewals(), 0);
        // An hour from its end, a lease renewal moves it a day ahead.
        let earlier = age(&store, &a, &[&following]);
        connect();
        let renewed = store.adapter(&a.id).unwrap().expires_at;
        assert!(renewed > earlier);
        let routes = store.outbound_routes(&a.id).unwrap();
        let by_name = |name: &str| routes.iter().find(|r| r.name == name).unwrap().clone();
        assert_eq!(by_name("follow").expires_at, renewed);
        assert_eq!(by_name("fixed").expires_at, fixed_expiry);
        assert_eq!(renewals(), 1);
        // Renewed again within the hour: moved, recorded once.
        age(&store, &a, &[&following]);
        connect();
        assert!(store.adapter(&a.id).unwrap().expires_at > earlier);
        assert_eq!(renewals(), 1);
        // A revoked following route keeps its expiry.
        store.revoke_outbound_route(&following.id).unwrap();
        let earlier = age(&store, &a, &[]);
        connect();
        assert_ne!(store.adapter(&a.id).unwrap().expires_at, earlier);
        assert_ne!(
            store.outbound_routes(&a.id).unwrap()[1].expires_at,
            store.adapter(&a.id).unwrap().expires_at
        );
    }

    #[test]
    fn fixed_credentials_never_move_and_refuse_following_routes() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let peer = add_test_peer(&store);
        let agent = store
            .register_agent(RegisterAgent {
                name: "a".into(),
                owner: "a".into(),
                capabilities: vec![],
            })
            .unwrap();
        let session = store
            .attach_session(AttachSession {
                agent_id: agent.id,
                integration: "test".into(),
            })
            .unwrap();
        let expiry = rfc3339(Utc::now() + chrono::TimeDelta::hours(1));
        let credential = store
            .create_adapter(CreateAdapter {
                session_id: session.id.clone(),
                expires_at: Some(expiry.clone()),
            })
            .unwrap();
        assert!(!credential.adapter.renewable);
        assert!(matches!(
            store.create_outbound_route(route(&credential.adapter.id, &peer.id, "r", None)),
            Err(Error::Invalid(_))
        ));
        let instance = format!("instance_{}", "7".repeat(64));
        store
            .connect_adapter(
                &credential.token,
                &instance,
                &credential.adapter.id,
                &session.id,
            )
            .unwrap();
        assert_eq!(
            store.adapter(&credential.adapter.id).unwrap().expires_at,
            expiry
        );
    }
}
