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
/// Schema version 14 (live delivery slice 1): adds the channel verification
/// time and the MCP protocol revision of each authorization, each only when
/// missing, since a state rewound to an older version may keep them.
/// Existing authorizations migrate as unverified.
pub(crate) fn migrate_channel(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    let present = {
        let mut statement =
            tx.prepare("SELECT name FROM pragma_table_info('adapter_connections')")?;
        statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for column in ["channel_verified_at", "protocol_version"] {
        if !present.iter().any(|c| c == column) {
            tx.execute_batch(&format!(
                "ALTER TABLE adapter_connections ADD COLUMN {column} TEXT;"
            ))?;
        }
    }
    tx.execute_batch("PRAGMA user_version = 14;")
}
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
    /// `verified` or `unverified` while the adapter holds a lease, else
    /// null.
    pub channel: Option<&'static str>,
    pub channel_verified_at: Option<String>,
    /// The MCP protocol revision the adapter last reported on connect.
    pub protocol_version: Option<String>,
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
    if ss.state != "attached" || until <= crate::clock::now().timestamp_millis() {
        return Err(Error::Unavailable("adapter connection is not ready".into()));
    }
    Ok((a, ss))
}
/// Like `authority`, for the work routes that claim deliveries, tasks,
/// cancellations, replies, and task updates: the authorization must also have verified
/// its channel through `POST /adapter/v1/ready`.
pub(crate) fn verified_authority(
    conn: &DB,
    auth: &AdapterAuth,
) -> Result<(Adapter, Session), Error> {
    let (a, ss) = authority(conn, auth)?;
    if channel_columns(conn, &a.id)?.0.is_none() {
        return Err(Error::Coded {
            status: 409,
            code: "conflict",
            message: "channel not verified".into(),
            extra: Default::default(),
        });
    }
    Ok((a, ss))
}
/// The verification time and the reported MCP protocol revision.
fn channel_columns(conn: &DB, id: &str) -> Result<(Option<String>, Option<String>), Error> {
    Ok(conn.query_row(
        "SELECT channel_verified_at, protocol_version FROM adapter_connections WHERE adapter_id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}
/// A readiness nonce: 128 bits as 32 hex digits.
fn valid_nonce(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
/// An MCP protocol revision as an adapter reports it: 1 to 64 letters,
/// digits, `.`, `_`, or `-`, starting with a letter or digit.
fn valid_protocol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
fn status(conn: &DB, a: &Adapter, ss: &Session) -> Result<Connection, Error> {
    let (hash, until, last, recoverable) = binding(conn, &a.id)?;
    let (verified, protocol) = channel_columns(conn, &a.id)?;
    let expiry =
        DateTime::parse_from_rfc3339(&a.expires_at).map_err(|e| Error::Internal(e.into()))?;
    let state = if a.revoked_at.is_some() {
        "revoked"
    } else if expiry <= crate::clock::now() {
        "expired"
    } else if ss.state == "detached" && !recoverable {
        "detached"
    } else if hash.is_none() {
        "registered"
    } else if ss.state == "attached" && until > crate::clock::now().timestamp_millis() {
        "ready"
    } else {
        "offline"
    };
    Ok(Connection {
        adapter_id: a.id.clone(),
        session_id: ss.id.clone(),
        state: state.into(),
        recoverable: recoverable
            && hash.is_some()
            && a.revoked_at.is_none()
            && expiry > crate::clock::now(),
        lease_expires_at: if until > 0 {
            Some(rfc3339(DateTime::from_timestamp_millis(until).ok_or_else(
                || Error::Internal(anyhow::anyhow!("invalid lease")),
            )?))
        } else {
            None
        },
        last_seen_at: last,
        channel: (state == "ready").then_some(if verified.is_some() {
            "verified"
        } else {
            "unverified"
        }),
        channel_verified_at: verified,
        protocol_version: protocol,
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
            crate::clock::now() - at.with_timezone(&Utc) >= chrono::TimeDelta::hours(1)
        }),
    };
    if due {
        append_event(tx, "adapter.renewed", &a.id, &now())?;
    }
    Ok(())
}
impl Store {
    pub fn adapter_connection(&self, id: &str) -> Result<Connection, Error> {
        self.adapter_connection_in(&*self.connection()?, id)
    }
    pub(crate) fn adapter_connection_in(&self, conn: &DB, id: &str) -> Result<Connection, Error> {
        let a: Adapter = read(
            conn,
            "SELECT record FROM adapter_credentials WHERE id = ?1",
            [id],
        )?;
        let ss = session(conn, &a.session_id)?;
        status(conn, &a, &ss)
    }
    pub fn connect_adapter(
        &self,
        token: &str,
        instance: &str,
        adapter_id: &str,
        session_id: &str,
    ) -> Result<Connection, Error> {
        self.connect_adapter_reporting(token, instance, adapter_id, session_id, None)
    }
    /// Connects or renews the lease, recording the MCP protocol revision
    /// the adapter negotiated when it reports one.
    pub fn connect_adapter_reporting(
        &self,
        token: &str,
        instance: &str,
        adapter_id: &str,
        session_id: &str,
        protocol_version: Option<&str>,
    ) -> Result<Connection, Error> {
        if protocol_version.is_some_and(|v| !valid_protocol(v)) {
            return Err(Error::Invalid("invalid protocol version".into()));
        }
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
        let current = crate::clock::now();
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
        if let Some(version) = protocol_version {
            tx.execute(
                "UPDATE adapter_connections SET protocol_version = ?1 WHERE adapter_id = ?2",
                params![version, a.id],
            )?;
        }
        if hash.is_none() || until <= current.timestamp_millis() {
            append_event(&tx, "adapter.connected", &a.id, &at)?;
        }
        let c = status(&tx, &a, &ss)?;
        tx.commit()?;
        self.presence_changed();
        Ok(c)
    }
    /// `POST /adapter/v1/ready`: records that this authorization's session
    /// received the hello event. Idempotent: the first time is kept.
    pub fn adapter_ready(&self, auth: &AdapterAuth, nonce: &str) -> Result<Connection, Error> {
        if !valid_nonce(nonce) {
            return Err(Error::Invalid("invalid nonce".into()));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, auth)?;
        tx.execute(
            "UPDATE adapter_connections SET channel_verified_at = COALESCE(channel_verified_at, ?1) WHERE adapter_id = ?2",
            params![now(), a.id],
        )?;
        let c = status(&tx, &a, &ss)?;
        tx.commit()?;
        self.presence_changed();
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
    #[serde(default)]
    protocol_version: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyRequest {
    nonce: String,
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/connect", post(connect))
        .route("/adapter/v1/ready", post(ready))
}
async fn ready(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Connection>, Error> {
    let req: ReadyRequest = decode(body)?;
    let auth = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.adapter_ready(&auth, &req.nonce)).await?,
    ))
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
            s.connect_adapter_reporting(
                &auth.token,
                &req.instance_id,
                &req.adapter_id,
                &req.session_id,
                req.protocol_version.as_deref(),
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
            authorization: None,
        }
    }
    /// Moves a stored expiry back, as if the credential were an hour from
    /// its end.
    fn age(store: &Store, a: &Adapter, routes: &[&OutboundRoute]) -> String {
        let earlier = rfc3339(crate::clock::now() + chrono::TimeDelta::hours(1));
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
        assert!(expiry > crate::clock::now() + chrono::TimeDelta::hours(23));
        let following = store
            .create_outbound_route(route(&a.id, &peer.id, "follow", None))
            .unwrap();
        assert!(following.follows_credential);
        assert_eq!(following.expires_at, a.expires_at);
        let fixed_expiry = rfc3339(crate::clock::now() + chrono::TimeDelta::minutes(30));
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
        let expiry = rfc3339(crate::clock::now() + chrono::TimeDelta::hours(1));
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
