//! Owner-defined outbound destinations and automatic, session-bound replies.
use crate::{
    adapter::{Reply, authority, read, token},
    adapter_connection::AdapterAuth,
    api::{blocking, decode},
    model::Error,
    peer_store::{MessageRequest, OutboundMessage, valid_id},
    store::{Store, append_event, new_id, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

pub(crate) const SCHEMA:&str="
CREATE TABLE adapter_routes (id TEXT PRIMARY KEY, adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), name TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(adapter_id, name));
CREATE TABLE adapter_outbound (peer TEXT NOT NULL, request_id TEXT NOT NULL, adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), session_id TEXT NOT NULL REFERENCES sessions(id), route_id TEXT NOT NULL REFERENCES adapter_routes(id), next_poll_at INTEGER NOT NULL, reply_delivery TEXT, PRIMARY KEY(peer, request_id), UNIQUE(adapter_id, request_id), FOREIGN KEY(peer, request_id) REFERENCES outbound_messages(peer, request_id));
CREATE INDEX adapter_outbound_due ON adapter_outbound(next_poll_at);
CREATE INDEX adapter_outbound_route ON adapter_outbound(route_id);
PRAGMA user_version = 5;
";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "StoredRoute")]
pub struct OutboundRoute {
    pub id: String,
    pub adapter_id: String,
    pub name: String,
    pub peer_host_id: String,
    pub target_agent_id: String,
    /// `message.append` (sends) or `task.submit` (delegations). Routes from
    /// before tasks send messages.
    #[serde(default = "message_action")]
    pub action: String,
    /// Null when the route sends under the target owner's policy.
    #[serde(default)]
    pub grant_id: Option<String>,
    pub expires_at: String,
    pub max_message_bytes: i64,
    pub max_messages: i64,
    pub revoked_at: Option<String>,
    /// Created without an expiry on a renewable credential: `expires_at`
    /// moves with the credential's. Older routes read as fixed.
    #[serde(default)]
    pub follows_credential: bool,
    /// For `task.submit` routes, 0 to 2: tasks carry link 0 allowing that
    /// many further hops. Older routes read as 0.
    #[serde(default)]
    pub delegation_depth: u64,
    /// `grant`, `policy`, or `self`: what the route cited when created.
    pub authorization: String,
}
/// A stored route; older records lack `authorization`, which then follows
/// from `grant_id`.
#[derive(Deserialize)]
struct StoredRoute {
    id: String,
    adapter_id: String,
    name: String,
    peer_host_id: String,
    target_agent_id: String,
    #[serde(default = "message_action")]
    action: String,
    #[serde(default)]
    grant_id: Option<String>,
    expires_at: String,
    max_message_bytes: i64,
    max_messages: i64,
    revoked_at: Option<String>,
    #[serde(default)]
    follows_credential: bool,
    #[serde(default)]
    delegation_depth: u64,
    #[serde(default)]
    authorization: Option<String>,
}
impl From<StoredRoute> for OutboundRoute {
    fn from(r: StoredRoute) -> Self {
        let authorization = r.authorization.unwrap_or_else(|| {
            if r.grant_id.is_some() {
                "grant"
            } else {
                "policy"
            }
            .into()
        });
        Self {
            id: r.id,
            adapter_id: r.adapter_id,
            name: r.name,
            peer_host_id: r.peer_host_id,
            target_agent_id: r.target_agent_id,
            action: r.action,
            grant_id: r.grant_id,
            expires_at: r.expires_at,
            max_message_bytes: r.max_message_bytes,
            max_messages: r.max_messages,
            revoked_at: r.revoked_at,
            follows_credential: r.follows_credential,
            delegation_depth: r.delegation_depth,
            authorization,
        }
    }
}
fn message_action() -> String {
    crate::policy::ACTION.into()
}
/// SQL for a route `r`'s consumed budget: its messages and its tasks.
pub(crate) const ROUTE_USED: &str = "((SELECT COUNT(*) FROM adapter_outbound o WHERE o.route_id = r.id) + (SELECT COUNT(*) FROM outbound_tasks t WHERE json_extract(t.record, '$.route_id') = r.id))";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOutboundRoute {
    pub adapter_id: String,
    pub name: String,
    pub peer_host_id: String,
    pub target_agent_id: String,
    #[serde(default)]
    pub grant_id: Option<String>,
    /// Absent, the route follows its renewable credential's expiry.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub expires_at: Option<String>,
    pub max_message_bytes: i64,
    pub max_messages: i64,
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub action: Option<String>,
    /// 0 (the default) to 2; nonzero only for `task.submit`.
    #[serde(default)]
    pub delegation_depth: u64,
    /// True is the same as omitting `expires_at`, so a route record can be
    /// posted back as a request.
    #[serde(default)]
    pub follows_credential: bool,
    /// Accepted so a route record can be posted back; the daemon decides it.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub authorization: Option<String>,
}
#[derive(Serialize)]
pub struct Destination {
    pub name: String,
    pub action: String,
    pub expires_at: String,
    pub max_message_bytes: i64,
    pub messages_remaining: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterSend {
    pub destination: String,
    pub request_id: String,
    pub content: String,
}
/// An agent's view of one of its own sends, including automatic retry progress.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SendStatus {
    pub request_id: String,
    pub destination: String,
    pub state: String,
    pub attempts: u32,
    pub next_attempt_at: Option<String>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplyDelivery {
    pub id: String,
    pub peer_host_id: String,
    pub request_id: String,
    pub adapter_id: String,
    pub session_id: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Serialize)]
pub struct ReplyHandoff {
    pub delivery: ReplyDelivery,
    pub reply: Reply,
}

#[derive(Serialize)]
pub struct OutboundOrigin {
    pub peer_host_id: String,
    pub request_id: String,
    pub adapter_id: String,
    pub session_id: String,
    pub route_id: String,
    pub reply_delivery: Option<ReplyDelivery>,
}
fn expiration(text: &str) -> Result<DateTime<chrono::FixedOffset>, Error> {
    DateTime::parse_from_rfc3339(text).map_err(|e| Error::Internal(e.into()))
}
/// A route's consumed budget: messages and tasks sent through it.
pub(crate) fn route_used(conn: &rusqlite::Connection, route: &str) -> Result<i64, Error> {
    Ok(conn.query_row(
        &format!("SELECT {ROUTE_USED} FROM adapter_routes r WHERE r.id = ?1"),
        [route],
        |row| row.get(0),
    )?)
}
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || (i > 0 && matches!(b, b'.' | b'_' | b'-'))
        })
}
impl Store {
    pub fn outbound_origin(&self, peer: &str, id: &str) -> Result<OutboundOrigin, Error> {
        let conn = self.connection()?;
        let (adapter_id,session_id,route_id,delivery):(String,String,String,Option<String>)=conn.query_row("SELECT adapter_id,session_id,route_id,reply_delivery FROM adapter_outbound WHERE peer = ?1 AND request_id = ?2",params![peer,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        Ok(OutboundOrigin {
            peer_host_id: peer.to_owned(),
            request_id: id.to_owned(),
            adapter_id,
            session_id,
            route_id,
            reply_delivery: delivery.map(|s| serde_json::from_str(&s)).transpose()?,
        })
    }
    pub fn create_outbound_route(&self, r: CreateOutboundRoute) -> Result<OutboundRoute, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let route = self.create_outbound_route_in(&tx, r)?;
        tx.commit()?;
        Ok(route)
    }
    pub(crate) fn create_outbound_route_in(
        &self,
        tx: &rusqlite::Transaction<'_>,
        mut r: CreateOutboundRoute,
    ) -> Result<OutboundRoute, Error> {
        if r.follows_credential {
            r.expires_at = None;
        }
        let exp = r
            .expires_at
            .as_deref()
            .map(DateTime::parse_from_rfc3339)
            .transpose()
            .map_err(|_| Error::Invalid("invalid expiration".into()))?;
        if exp.is_some_and(|exp| exp <= Utc::now())
            || !valid_name(&r.name)
            || !valid_id(&r.target_agent_id, "agent", 16)
            || !r
                .grant_id
                .as_deref()
                .is_none_or(|g| valid_id(g, "grant", 16))
            || !(1..=65536).contains(&r.max_message_bytes)
            || !(1..=10000).contains(&r.max_messages)
            || r.action
                .as_deref()
                .is_some_and(|a| !crate::policy::ROUTE_ACTIONS.contains(&a))
            || r.authorization
                .as_deref()
                .is_some_and(|a| !["grant", "policy", "self"].contains(&a))
            || r.delegation_depth > crate::chain::MAX_DEPTH
            || (r.delegation_depth > 0 && r.action.as_deref() != Some(crate::policy::TASK_ACTION))
        {
            return Err(Error::Invalid("invalid route bounds".into()));
        }
        if !self.known_host(tx, &r.peer_host_id)? {
            return Err(Error::NotFound);
        }
        let a: crate::adapter::Adapter = read(
            tx,
            "SELECT record FROM adapter_credentials WHERE id = ?1",
            [&r.adapter_id],
        )?;
        let state: String = tx.query_row(
            "SELECT state FROM sessions WHERE id = ?1",
            [&a.session_id],
            |row| row.get(0),
        )?;
        let ae = expiration(&a.expires_at)?;
        if a.revoked_at.is_some() || state != "attached" || ae <= Utc::now() {
            return Err(Error::Forbidden);
        }
        let follows_credential = exp.is_none();
        match exp {
            Some(exp) if exp > ae => {
                return Err(Error::Invalid("route outlives credential".into()));
            }
            None if !a.renewable => {
                return Err(Error::Invalid(
                    "a route without expires_at needs a renewable credential".into(),
                ));
            }
            _ => {}
        }
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM adapter_routes WHERE adapter_id = ?1 AND name = ?2",
            params![r.adapter_id, r.name],
            |row| row.get(0),
        )?;
        if count != 0 {
            return Err(Error::Conflict("destination name already exists".into()));
        }
        let authorization = if r.grant_id.is_some() {
            "grant"
        } else if self.self_citation(tx, &r.peer_host_id)?.is_some() {
            "self"
        } else {
            "policy"
        };
        let route = OutboundRoute {
            authorization: authorization.into(),
            id: new_id("route")?,
            adapter_id: r.adapter_id,
            name: r.name,
            peer_host_id: r.peer_host_id,
            target_agent_id: r.target_agent_id,
            action: r.action.unwrap_or_else(message_action),
            grant_id: r.grant_id,
            expires_at: r.expires_at.unwrap_or_else(|| a.expires_at.clone()),
            max_message_bytes: r.max_message_bytes,
            max_messages: r.max_messages,
            revoked_at: None,
            follows_credential,
            delegation_depth: r.delegation_depth,
        };
        tx.execute(
            "INSERT INTO adapter_routes VALUES (?1,?2,?3,?4)",
            params![
                route.id,
                route.adapter_id,
                route.name,
                serde_json::to_string(&route)?
            ],
        )?;
        append_event(tx, "adapter.route_created", &route.id, &now())?;
        Ok(route)
    }
    pub fn outbound_routes(&self, adapter_id: &str) -> Result<Vec<OutboundRoute>, Error> {
        self.adapter(adapter_id)?;
        let conn = self.connection()?;
        let mut stmt =
            conn.prepare("SELECT record FROM adapter_routes WHERE adapter_id = ?1 ORDER BY name")?;
        stmt.query_map([adapter_id], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }
    pub fn revoke_outbound_route(&self, id: &str) -> Result<OutboundRoute, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut r: OutboundRoute =
            read(&tx, "SELECT record FROM adapter_routes WHERE id = ?1", [id])?;
        if r.revoked_at.is_some() {
            return Ok(r);
        }
        let at = now();
        r.revoked_at = Some(at.clone());
        tx.execute(
            "UPDATE adapter_routes SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&r)?, id],
        )?;
        append_event(&tx, "adapter.route_revoked", id, &at)?;
        tx.commit()?;
        Ok(r)
    }
    pub fn destinations(&self, token: &AdapterAuth) -> Result<Vec<Destination>, Error> {
        let conn = self.connection()?;
        let (a, _) = authority(&conn, token)?;
        let mut stmt = conn.prepare(&format!(
            "SELECT r.record,{ROUTE_USED} FROM adapter_routes r WHERE adapter_id = ?1 ORDER BY name"
        ))?;
        let rows = stmt.query_map([a.id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (data, used) = row?;
            let r: OutboundRoute = serde_json::from_str(&data)?;
            if r.revoked_at.is_none() && expiration(&r.expires_at)? > Utc::now() {
                result.push(Destination {
                    name: r.name,
                    action: r.action,
                    expires_at: r.expires_at,
                    max_message_bytes: r.max_message_bytes,
                    messages_remaining: r.max_messages - used,
                });
            }
        }
        Ok(result)
    }
    pub fn prepare_adapter_send(
        &self,
        token: &AdapterAuth,
        r: AdapterSend,
    ) -> Result<OutboundMessage, Error> {
        if !valid_name(&r.destination)
            || !valid_id(&r.request_id, "request", 16)
            || r.content.is_empty()
            || r.content.len() > 65536
        {
            return Err(Error::Invalid("invalid send".into()));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, token)?;
        let route: OutboundRoute = read(
            &tx,
            "SELECT record FROM adapter_routes WHERE adapter_id = ?1 AND name = ?2",
            params![a.id, r.destination],
        )
        .map_err(|e| match e {
            Error::NotFound => Error::Forbidden,
            other => other,
        })?;
        let exp = expiration(&route.expires_at)?;
        if route.revoked_at.is_some()
            || route.action != crate::policy::ACTION
            || exp <= Utc::now()
            || r.content.len() as i64 > route.max_message_bytes
        {
            return Err(Error::Forbidden);
        }
        let reused: i64 = tx.query_row(
            "SELECT COUNT(*) FROM adapter_outbound WHERE adapter_id = ?1 AND request_id = ?2 AND route_id != ?3",
            params![a.id, r.request_id, route.id],
            |row| row.get(0),
        )?;
        if reused != 0 {
            return Err(Error::Conflict(
                "request ID belongs to another destination".into(),
            ));
        }
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM outbound_messages WHERE peer = ?1 AND request_id = ?2",
                params![route.peer_host_id, r.request_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old: OutboundMessage = serde_json::from_str(&old)?;
            let binding:Option<(String,String,String)>=tx.query_row("SELECT adapter_id,session_id,route_id FROM adapter_outbound WHERE peer = ?1 AND request_id = ?2",params![route.peer_host_id,r.request_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
            let Some((aid, sid, rid)) = binding else {
                return Err(Error::Conflict(
                    "request belongs to owner administration".into(),
                ));
            };
            if aid != a.id || sid != ss.id {
                return Err(Error::Forbidden);
            }
            if rid != route.id || old.request.content != r.content {
                return Err(Error::Conflict(
                    "request ID reused with different fields".into(),
                ));
            }
            if expiration(&old.request.deadline)? <= Utc::now() && old.state != "accepted" {
                return Err(Error::Forbidden);
            }
            return Ok(old);
        }
        if route_used(&tx, &route.id)? >= route.max_messages {
            return Err(Error::Forbidden);
        }
        let deadline = (Utc::now() + chrono::Duration::minutes(5))
            .fixed_offset()
            .min(exp);
        let (policy, self_access) = if route.grant_id.is_none() {
            self.citation(&tx, &route.peer_host_id)?.fields()
        } else {
            (None, None)
        };
        let out = OutboundMessage {
            peer_host_id: route.peer_host_id,
            request: MessageRequest {
                request_id: r.request_id,
                grant_id: route.grant_id,
                policy,
                self_access,
                target_agent_id: route.target_agent_id,
                deadline: crate::store::rfc3339(deadline.with_timezone(&Utc)),
                content: r.content,
                // The route's session originates the send.
                origin: Some(crate::peer_store::Origin {
                    agent_id: ss.agent_id.clone(),
                    session_id: Some(ss.id.clone()),
                }),
            },
            state: "unknown".into(),
            receipt: None,
            error: None,
            attempts: 0,
            // Retried automatically if the inline send never finishes.
            next_attempt_at: Some(crate::store::rfc3339(
                Utc::now() + crate::retry::PREPARE_GUARD,
            )),
            receipt_queries: 0,
        };
        tx.execute(
            "INSERT INTO outbound_messages VALUES (?1,?2,?3)",
            params![
                out.peer_host_id,
                out.request.request_id,
                serde_json::to_string(&out)?
            ],
        )?;
        append_event(
            &tx,
            "message.queued",
            &format!("{}/{}", out.peer_host_id, out.request.request_id),
            &now(),
        )?;
        tx.execute(
            "INSERT INTO adapter_outbound VALUES (?1,?2,?3,?4,?5,0,NULL)",
            params![
                out.peer_host_id,
                out.request.request_id,
                a.id,
                ss.id,
                route.id
            ],
        )?;
        append_event(
            &tx,
            "adapter.message_queued",
            &format!("{}/{}", out.peer_host_id, out.request.request_id),
            &now(),
        )?;
        tx.commit()?;
        Ok(out)
    }
    /// A send made with this credential; any other request is not found.
    pub fn send_status(&self, token: &AdapterAuth, request_id: &str) -> Result<SendStatus, Error> {
        if !valid_id(request_id, "request", 16) {
            return Err(Error::NotFound);
        }
        let conn = self.connection()?;
        let (a, _) = authority(&conn, token)?;
        let (peer, route_id): (String, String) = conn
            .query_row(
                "SELECT peer, route_id FROM adapter_outbound WHERE adapter_id = ?1 AND request_id = ?2",
                params![a.id, request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let route: OutboundRoute = read(
            &conn,
            "SELECT record FROM adapter_routes WHERE id = ?1",
            [&route_id],
        )?;
        let out: OutboundMessage = read(
            &conn,
            "SELECT record FROM outbound_messages WHERE peer = ?1 AND request_id = ?2",
            params![peer, request_id],
        )?;
        Ok(SendStatus {
            request_id: out.request.request_id,
            destination: route.name,
            state: out.state,
            attempts: out.attempts,
            next_attempt_at: out.next_attempt_at,
            error: out.error,
        })
    }
    pub fn next_reply(&self, token: &AdapterAuth) -> Result<Option<ReplyHandoff>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, token)?;
        let pending:Option<(String,String,String)>=tx.query_row("SELECT o.peer,o.request_id,r.record FROM adapter_outbound o JOIN outbound_replies r ON r.peer = o.peer AND r.request_id = o.request_id WHERE o.adapter_id = ?1 AND o.session_id = ?2 AND o.reply_delivery IS NULL ORDER BY o.rowid LIMIT 1",params![a.id,ss.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((peer, id, data)) = pending else {
            return Ok(None);
        };
        let reply: Reply = serde_json::from_str(&data)?;
        let at = now();
        let d = ReplyDelivery {
            id: new_id("notification")?,
            peer_host_id: peer,
            request_id: id,
            adapter_id: a.id,
            session_id: ss.id,
            state: "unknown".into(),
            created_at: at.clone(),
            updated_at: at,
        };
        tx.execute(
            "UPDATE adapter_outbound SET reply_delivery = ?1 WHERE peer = ?2 AND request_id = ?3",
            params![serde_json::to_string(&d)?, d.peer_host_id, d.request_id],
        )?;
        append_event(&tx, "reply.handoff", &d.id, &d.created_at)?;
        tx.commit()?;
        Ok(Some(ReplyHandoff { delivery: d, reply }))
    }
    pub fn reply_forwarded(&self, token: &AdapterAuth, id: &str) -> Result<ReplyDelivery, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = authority(&tx, token)?;
        let mut d: ReplyDelivery = read(
            &tx,
            "SELECT reply_delivery FROM adapter_outbound WHERE json_extract(reply_delivery,'$.id') = ?1 AND adapter_id = ?2 AND session_id = ?3",
            params![id, a.id, ss.id],
        )?;
        if d.state == "forwarded" {
            return Ok(d);
        }
        d.state = "forwarded".into();
        d.updated_at = now();
        tx.execute(
            "UPDATE adapter_outbound SET reply_delivery = ?1 WHERE peer = ?2 AND request_id = ?3",
            params![serde_json::to_string(&d)?, d.peer_host_id, d.request_id],
        )?;
        append_event(&tx, "reply.forwarded", id, &d.updated_at)?;
        tx.commit()?;
        Ok(d)
    }
    fn next_reply_job(&self) -> Result<Option<(String, String)>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let candidates = {
            let mut stmt=tx.prepare("SELECT o.peer,o.request_id,c.record FROM adapter_outbound o JOIN adapter_credentials c ON c.id = o.adapter_id JOIN sessions ss ON ss.id = o.session_id JOIN adapter_connections ac ON ac.adapter_id = o.adapter_id WHERE ac.lease_until_ms > ?1 AND ss.state = 'attached' AND o.next_poll_at <= ?1 AND NOT EXISTS (SELECT 1 FROM outbound_replies r WHERE r.peer = o.peer AND r.request_id = o.request_id) ORDER BY o.next_poll_at,o.rowid LIMIT 100")?;
            stmt.query_map([Utc::now().timestamp_millis()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        };
        let mut result = None;
        for (peer, id, data) in candidates {
            let a: crate::adapter::Adapter = serde_json::from_str(&data)?;
            if a.revoked_at.is_none() && expiration(&a.expires_at)? > Utc::now() {
                result = Some((peer, id));
                break;
            } else {
                tx.execute("UPDATE adapter_outbound SET next_poll_at = ?1 WHERE peer = ?2 AND request_id = ?3",params![i64::MAX,peer,id])?;
            }
        }
        if let Some((peer, id)) = &result {
            tx.execute(
                "UPDATE adapter_outbound SET next_poll_at = ?1 WHERE peer = ?2 AND request_id = ?3",
                params![
                    (Utc::now() + chrono::Duration::seconds(10)).timestamp_millis(),
                    peer,
                    id
                ],
            )?;
        }
        tx.commit()?;
        Ok(result)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/destinations", get(destinations))
        .route("/adapter/v1/send", post(send))
        .route("/adapter/v1/sends/{request_id}", get(send_status))
        .route("/adapter/v1/replies/next", post(next))
        .route("/adapter/v1/replies/{id}/forwarded", post(forwarded))
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/outbound/{peer}/{id}/origin", get(origin))
        .route("/v1/adapter-routes", post(create))
        .route("/v1/adapters/{id}/routes", get(routes))
        .route("/v1/adapter-routes/{id}/revoke", post(revoke))
}
async fn origin(
    State(store): State<Arc<Store>>,
    Path((peer, id)): Path<(String, String)>,
) -> Result<Json<OutboundOrigin>, Error> {
    Ok(Json(
        blocking(store, move |s| s.outbound_origin(&peer, &id)).await?,
    ))
}
async fn destinations(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
) -> Result<Json<Vec<Destination>>, Error> {
    let t = token(&headers);
    Ok(Json(blocking(store, move |s| s.destinations(&t)).await?))
}
async fn send(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<OutboundMessage>, Error> {
    let req = decode(body)?;
    let t = token(&headers);
    let out = blocking(store.clone(), move |s| s.prepare_adapter_send(&t, req)).await?;
    Ok(Json(crate::peer::exchange(store, out, false).await?))
}
async fn send_status(
    State(store): State<Arc<Store>>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SendStatus>, Error> {
    let t = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.send_status(&t, &request_id)).await?,
    ))
}
async fn next(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<ReplyHandoff>>, Error> {
    let _: Empty = decode(body)?;
    let t = token(&headers);
    Ok(Json(blocking(store, move |s| s.next_reply(&t)).await?))
}
async fn forwarded(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<ReplyDelivery>, Error> {
    let _: Empty = decode(body)?;
    let t = token(&headers);
    Ok(Json(
        blocking(store, move |s| s.reply_forwarded(&t, &id)).await?,
    ))
}
async fn create(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<OutboundRoute>), Error> {
    let req = decode(body)?;
    Ok((
        StatusCode::CREATED,
        Json(blocking(store, move |s| s.create_outbound_route(req)).await?),
    ))
}
async fn routes(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Vec<OutboundRoute>>, Error> {
    Ok(Json(
        blocking(store, move |s| s.outbound_routes(&id)).await?,
    ))
}
async fn revoke(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<OutboundRoute>, Error> {
    Ok(Json(
        blocking(store, move |s| s.revoke_outbound_route(&id)).await?,
    ))
}

async fn reply_loop(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {_=shutdown.changed()=>return,_=tokio::time::sleep(Duration::from_millis(250))=>{}}
        let Ok(Some((peer, id))) = blocking(store.clone(), Store::next_reply_job).await else {
            continue;
        };
        tokio::select! {_=shutdown.changed()=>return,_=crate::adapter::fetch_reply_status(store.clone(),peer.clone(),id.clone())=>{}}
        let _ = blocking(store.clone(), move |s| {
            s.connection()?.execute(
                "UPDATE adapter_outbound SET next_poll_at = ?1 WHERE peer = ?2 AND request_id = ?3",
                params![
                    (Utc::now() + chrono::Duration::seconds(2)).timestamp_millis(),
                    peer,
                    id
                ],
            )?;
            Ok(())
        })
        .await;
    }
}
pub async fn reply_workers(store: Arc<Store>, shutdown: watch::Receiver<bool>) {
    tokio::join!(
        reply_loop(store.clone(), shutdown.clone()),
        reply_loop(store.clone(), shutdown.clone()),
        reply_loop(store.clone(), shutdown.clone()),
        reply_loop(store, shutdown)
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        adapter::CreateAdapter,
        model::{AttachSession, RegisterAgent},
        peer_store::{Peer, key_id},
    };
    use base64::{Engine, engine::general_purpose::STANDARD};

    pub(crate) fn connected_adapter(store: &Store, name: &str) -> AdapterAuth {
        let agent = store
            .register_agent(RegisterAgent {
                name: name.into(),
                owner: name.into(),
                capabilities: vec![],
            })
            .unwrap();
        let session = store
            .attach_session(AttachSession {
                agent_id: agent.id,
                integration: "test".into(),
            })
            .unwrap();
        let credential = store
            .create_adapter(CreateAdapter {
                session_id: session.id.clone(),
                expires_at: Some(crate::store::rfc3339(
                    Utc::now() + chrono::Duration::hours(1),
                )),
            })
            .unwrap();
        let instance = format!(
            "instance_{}",
            hex::encode(name.repeat(32).as_bytes())[..64].to_owned()
        );
        store
            .connect_adapter(
                &credential.token,
                &instance,
                &credential.adapter.id,
                &session.id,
            )
            .unwrap();
        AdapterAuth {
            token: credential.token,
            instance,
        }
    }

    #[test]
    fn send_status_is_scoped_to_the_sending_credential() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let peer = store
            .add_peer(Peer {
                id: key_id(&key),
                public_key: STANDARD.encode(key),
                address: "127.0.0.1:9".into(),
            })
            .unwrap();
        let alice = connected_adapter(&store, "a");
        let bob = connected_adapter(&store, "b");
        let alice_id = crate::adapter::authority(&store.connection().unwrap(), &alice)
            .unwrap()
            .0
            .id;
        store
            .create_outbound_route(CreateOutboundRoute {
                adapter_id: alice_id,
                name: "reviewer".into(),
                peer_host_id: peer.id,
                target_agent_id: format!("agent_{}", "1".repeat(32)),
                grant_id: Some(format!("grant_{}", "1".repeat(32))),
                expires_at: Some(crate::store::rfc3339(
                    Utc::now() + chrono::Duration::minutes(30),
                )),
                max_message_bytes: 100,
                max_messages: 10,
                action: None,
                delegation_depth: 0,
                follows_credential: false,
                authorization: None,
            })
            .unwrap();
        let request_id = format!("request_{}", "2".repeat(32));
        let out = store
            .prepare_adapter_send(
                &alice,
                AdapterSend {
                    destination: "reviewer".into(),
                    request_id: request_id.clone(),
                    content: "hello".into(),
                },
            )
            .unwrap();
        // The route's session originates the send.
        let session = store.adapter_session(&alice).unwrap();
        assert_eq!(
            serde_json::to_value(&out.request).unwrap()["origin"],
            serde_json::json!({"agent_id": session.agent_id, "session_id": session.id})
        );
        let status = store.send_status(&alice, &request_id).unwrap();
        assert_eq!(
            (
                status.destination.as_str(),
                status.state.as_str(),
                status.attempts
            ),
            ("reviewer", "unknown", 0)
        );
        // A prepared send is due after the inline send's bound.
        assert!(status.next_attempt_at.is_some());
        assert!(matches!(
            store.send_status(&bob, &request_id),
            Err(Error::NotFound)
        ));
        let other = format!("request_{}", "3".repeat(32));
        assert!(matches!(
            store.send_status(&alice, &other),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            store.send_status(&alice, "bad"),
            Err(Error::NotFound)
        ));
    }
}
