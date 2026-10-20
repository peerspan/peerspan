//! Credential-scoped session handoff and bounded replies. This router never
//! exposes owner administration or arbitrary outbound messaging.
use crate::{
    adapter_connection::AdapterAuth,
    api::{blocking, decode},
    model::{Error, Session},
    peer_store::{Connectivity, MessageRequest, Origin, Peer, valid_id},
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
    /// Created without an expiry: connecting or renewing the lease moves
    /// `expires_at` to a day ahead. Older records read as fixed.
    #[serde(default)]
    pub renewable: bool,
    /// Directory access (launch slice 4): the adapter may send and delegate
    /// by address to any agent in the directory. Older records read as
    /// false.
    #[serde(default)]
    pub directory: bool,
    /// The cap on sends and delegations by address in any 60 minutes; null
    /// without directory access.
    #[serde(default)]
    pub max_sends_per_hour: Option<i64>,
    /// Capability calls (capabilities slice 2): the adapter may call
    /// capabilities. Older records read as false.
    #[serde(default)]
    pub calls: bool,
    /// The cap on capability calls in any 60 minutes; null without `calls`.
    #[serde(default)]
    pub max_calls_per_hour: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAdapter {
    pub session_id: String,
    /// Absent, the credential is renewable.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub expires_at: Option<String>,
}
/// How far ahead a renewable credential's expiry is set.
pub(crate) const RENEWAL_WINDOW: chrono::TimeDelta = chrono::TimeDelta::hours(24);
/// A renewable credential's expiry a day from now.
pub(crate) fn renewed_expiry() -> String {
    crate::store::rfc3339(Utc::now() + RENEWAL_WINDOW)
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
    /// The person the sending host is bound to, and its label, in the first
    /// network by ID that binds it; null for an unbound host.
    pub sender_person_id: Option<String>,
    pub sender_person: Option<String>,
    /// Whether this delivery was claimed again after its holding
    /// authorization ended unseen.
    pub redelivered: bool,
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
    /// The agent and session that replied, as the replying host asserts it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub origin: Option<Origin>,
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
                channel: None,
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
    let (record, returned): (String, bool) = conn.query_row(
        "SELECT record, returned_at IS NOT NULL FROM deliveries WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let d: Delivery = serde_json::from_str(&record)?;
    // A returned delivery belongs to no session until it is claimed again.
    if returned || d.adapter_id != a.id || d.session_id != ss.id || d.state == "blocked" {
        return Err(Error::Forbidden);
    }
    Ok(d)
}
/// The person a host is bound to, and its label, in the first network by ID
/// that binds it; both are `None` for an unbound host.
pub(crate) fn sender_person(
    conn: &Connection,
    host: &str,
) -> Result<(Option<String>, Option<String>), Error> {
    let mut stmt =
        conn.prepare("SELECT record FROM network_members WHERE host_id = ?1 ORDER BY network_id")?;
    let records = stmt
        .query_map([host], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for record in records {
        let member: crate::network::Member = serde_json::from_str(&record)?;
        if member.person_id.is_some() {
            return Ok((member.person_id, member.person_member));
        }
    }
    Ok((None, None))
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
        let credential = self.create_adapter_in(&tx, r, None, None)?;
        tx.commit()?;
        Ok(credential)
    }
    /// `directory` is the rate cap of a credential with directory access,
    /// and `calls` that of one that may call capabilities.
    pub(crate) fn create_adapter_in(
        &self,
        tx: &Transaction<'_>,
        r: CreateAdapter,
        directory: Option<i64>,
        calls: Option<i64>,
    ) -> Result<AdapterCredential, Error> {
        let renewable = r.expires_at.is_none();
        let expires_at = r.expires_at.unwrap_or_else(renewed_expiry);
        let expiration = DateTime::parse_from_rfc3339(&expires_at)
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
            expires_at,
            revoked_at: None,
            renewable,
            directory: directory.is_some(),
            max_sends_per_hour: directory,
            calls: calls.is_some(),
            max_calls_per_hour: calls,
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
        // Replacing an authorization ends its lease. The worker reads once
        // the caller's transaction has released the connection.
        self.presence_changed();
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
        self.presence_changed();
        Ok(a)
    }
    pub fn adapter_session(&self, token: &AdapterAuth) -> Result<Session, Error> {
        let conn = self.connection()?;
        let mut session = authority(&conn, token)?.1;
        session.channel = crate::store::session_channel(&conn, &session.id)?;
        Ok(session)
    }
    pub fn next_delivery(&self, token: &AdapterAuth) -> Result<Option<Handoff>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = crate::adapter_connection::verified_authority(&tx, token)?;
        crate::live_delivery::return_items(&tx, &ss.agent_id)?;
        if let Some(handoff) = self.claim_returned_delivery(&tx, &a, &ss)? {
            tx.commit()?;
            return Ok(Some(handoff));
        }
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
            let state = match self.message_bounds(&tx, &sender, &request.authz(), true) {
                Ok(g) => match self.grant_connected(&tx, &sender, &g)? {
                    Connectivity::Usable => "unknown",
                    // A recoverable connected state is not final: leave the
                    // message unclaimed, without a delivery record, until
                    // syncing resumes or its deadline passes.
                    Connectivity::Stale => continue,
                    Connectivity::Absent => "blocked",
                },
                Err(Error::Forbidden) => "blocked",
                // Behind the cited policy version: recoverable, like a stale
                // connected state.
                Err(Error::Unavailable(_)) => continue,
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
                "INSERT INTO deliveries (id, sender, request_id, session_id, record) VALUES (?1,?2,?3,?4,?5)",
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
                let (sender_person_id, sender_person) = sender_person(&tx, &d.sender_host_id)?;
                handoff = Some(Handoff {
                    delivery: d,
                    request,
                    sender_person_id,
                    sender_person,
                    redelivered: false,
                });
                break;
            }
        }
        tx.commit()?;
        Ok(handoff)
    }
    /// Claims the oldest delivery returned to this agent's queue, after
    /// rechecking its authorization and deadline as for a new one: a final
    /// lapse blocks it, and a recoverable one leaves it returned.
    fn claim_returned_delivery(
        &self,
        tx: &Transaction<'_>,
        a: &Adapter,
        ss: &Session,
    ) -> Result<Option<Handoff>, Error> {
        let returned = {
            let mut stmt = tx.prepare("SELECT d.record FROM deliveries d JOIN sessions s ON s.id = d.session_id WHERE s.agent_id = ?1 AND d.returned_at IS NOT NULL ORDER BY d.rowid")?;
            stmt.query_map([&ss.agent_id], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for record in returned {
            let mut d: Delivery = serde_json::from_str(&record)?;
            let request: MessageRequest = read(
                tx,
                "SELECT request FROM received_messages WHERE sender = ?1 AND request_id = ?2",
                params![d.sender_host_id, d.request_id],
            )?;
            let usable = match self.message_bounds(tx, &d.sender_host_id, &request.authz(), true) {
                Ok(g) => match self.grant_connected(tx, &d.sender_host_id, &g)? {
                    Connectivity::Usable => true,
                    Connectivity::Stale => continue,
                    Connectivity::Absent => false,
                },
                Err(Error::Forbidden) => false,
                Err(Error::Unavailable(_)) => continue,
                Err(e) => return Err(e),
            };
            let at = now();
            d.updated_at = at.clone();
            if !usable {
                d.state = "blocked".into();
                tx.execute(
                    "UPDATE deliveries SET record = ?1, returned_at = NULL WHERE id = ?2",
                    params![serde_json::to_string(&d)?, d.id],
                )?;
                append_event(tx, "message.blocked", &d.id, &at)?;
                continue;
            }
            d.adapter_id = a.id.clone();
            d.session_id = ss.id.clone();
            d.state = "unknown".into();
            tx.execute(
                "UPDATE deliveries SET record = ?1, session_id = ?2, redeliveries = redeliveries + 1, returned_at = NULL WHERE id = ?3",
                params![serde_json::to_string(&d)?, d.session_id, d.id],
            )?;
            append_event(tx, "message.handoff", &d.id, &at)?;
            let (sender_person_id, sender_person) = sender_person(tx, &d.sender_host_id)?;
            return Ok(Some(Handoff {
                delivery: d,
                request,
                sender_person_id,
                sender_person,
                redelivered: true,
            }));
        }
        Ok(None)
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
        let r = self.answer(&tx, &mut d, content)?;
        // A recorded reply reports the delivery seen; a refused one does not.
        tx.execute(
            "UPDATE deliveries SET seen_at = COALESCE(seen_at, ?1) WHERE id = ?2",
            params![now(), d.id],
        )?;
        tx.commit()?;
        Ok(r)
    }
    /// Records the reply to a delivery, or returns the identical one
    /// already recorded.
    fn answer(
        &self,
        tx: &Transaction<'_>,
        d: &mut Delivery,
        content: String,
    ) -> Result<Reply, Error> {
        let request: MessageRequest = read(
            tx,
            "SELECT request FROM received_messages WHERE sender = ?1 AND request_id = ?2",
            params![d.sender_host_id, d.request_id],
        )?;
        // A reply answers content this host already delivered, so only final
        // bounds apply; a lapsed connected state does not strand it.
        let g = self.message_bounds(tx, &d.sender_host_id, &request.authz(), false)?;
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
            origin: Some(Origin {
                agent_id: d.target_agent_id.clone(),
                session_id: Some(d.session_id.clone()),
            }),
        };
        tx.execute(
            "INSERT INTO received_replies VALUES (?1,?2,?3)",
            params![d.sender_host_id, d.request_id, serde_json::to_string(&r)?],
        )?;
        d.state = "replied".into();
        d.updated_at = at;
        update(tx, d, "message.replied")?;
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
    let instance = if headers.get_all("X-Peerspan-Instance").iter().count() == 1 {
        headers
            .get("X-Peerspan-Instance")
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
        .merge(crate::task::adapter_routes())
        .merge(crate::task_outbound::adapter_routes())
        .merge(crate::artifact::adapter_routes())
        .merge(crate::directory::adapter_routes())
        .merge(crate::live_delivery::adapter_routes())
        .merge(crate::agent_calls::adapter_routes())
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

/// A reply's origin, when present, names the replying agent and session.
fn reply_origin_consistent(r: &Reply) -> bool {
    r.origin.as_ref().is_none_or(|o| {
        o.valid() && o.agent_id == r.target_agent_id && o.session_id.as_ref() == Some(&r.session_id)
    })
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
                && reply_origin_consistent(&r)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter_outbound::tests::connected_adapter,
        peer_store::tests::{add_test_peer, grant_for, request},
    };

    fn received(store: &Store, sender: &str, r: &MessageRequest) {
        store.accept_message(sender, r.clone()).unwrap();
    }

    #[test]
    fn handoffs_and_replies_carry_origin_and_the_sender_person() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let peer = add_test_peer(&store);
        let auth = connected_adapter(&store, "a");
        let session = store.adapter_session(&auth).unwrap();
        let remote = Origin {
            agent_id: format!("agent_{}", "c".repeat(32)),
            session_id: Some(format!("session_{}", "d".repeat(32))),
        };
        let g = grant_for(&store, &peer.id, &session.agent_id, Some(&remote.agent_id));
        received(
            &store,
            &peer.id,
            &request(&g.id, &session.agent_id, Some(remote.clone())),
        );
        let handoff = store.next_delivery(&auth).unwrap().unwrap();
        let shown = serde_json::to_value(&handoff).unwrap();
        assert_eq!(
            shown["request"]["origin"],
            serde_json::to_value(&remote).unwrap()
        );
        // An unbound sender has no person, shown as null.
        assert!(shown["sender_person_id"].is_null() && shown.get("sender_person_id").is_some());
        assert!(shown["sender_person"].is_null() && shown.get("sender_person").is_some());
        let reply = store
            .reply(&auth, &handoff.delivery.id, "done".into())
            .unwrap();
        assert_eq!(
            reply.origin,
            Some(Origin {
                agent_id: session.agent_id.clone(),
                session_id: Some(session.id.clone()),
            })
        );
        assert_eq!(
            store.received_reply(&peer.id, &reply.request_id).unwrap(),
            reply
        );
    }

    #[test]
    fn fetched_reply_origins_name_the_replying_session() {
        let agent = format!("agent_{}", "a".repeat(32));
        let session = format!("session_{}", "b".repeat(32));
        let wire = serde_json::json!({
            "sender_host_id": "h", "request_id": "r", "receiver_host_id": "h",
            "target_agent_id": agent, "session_id": session, "delivery_id": "d",
            "content": "c", "replied_at": "t",
        });
        let with = |origin: Option<serde_json::Value>| {
            let mut v = wire.clone();
            if let Some(o) = origin {
                v["origin"] = o;
            }
            serde_json::from_value::<Reply>(v)
        };
        assert!(reply_origin_consistent(&with(None).unwrap()));
        assert!(reply_origin_consistent(
            &with(Some(
                serde_json::json!({"agent_id": agent, "session_id": session})
            ))
            .unwrap()
        ));
        let other = format!("agent_{}", "c".repeat(32));
        for bad in [
            serde_json::json!({"agent_id": agent}),
            serde_json::json!({"agent_id": other, "session_id": session}),
        ] {
            assert!(!reply_origin_consistent(&with(Some(bad)).unwrap()));
        }
        assert!(with(Some(serde_json::Value::Null)).is_err());
        assert!(with(Some(serde_json::json!({"agent_id": agent, "x": 1}))).is_err());
    }

    #[test]
    fn a_bound_sender_names_its_person_in_the_first_network() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let conn = store.connection().unwrap();
        let host = format!("host_{}", "a".repeat(64));
        let member = |person: Option<&str>, label: Option<&str>| {
            serde_json::json!({
                "host_id": host, "public_key": "", "member": "m", "address": "",
                "updated_at": "", "person_id": person, "person_member": label,
            })
            .to_string()
        };
        assert_eq!(sender_person(&conn, &host).unwrap(), (None, None));
        let person = format!("person_{}", "b".repeat(64));
        for (network, record) in [
            ("network_1", member(None, None)),
            ("network_2", member(Some(&person), Some("pat"))),
            ("network_3", member(Some("person_other"), Some("other"))),
        ] {
            conn.execute(
                "INSERT INTO network_members VALUES (?1, ?2, ?3)",
                params![network, host, record],
            )
            .unwrap();
        }
        assert_eq!(
            sender_person(&conn, &host).unwrap(),
            (Some(person), Some("pat".into()))
        );
    }

    #[test]
    fn agent_grants_are_rechecked_at_handoff_and_reply() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let peer = add_test_peer(&store);
        let auth = connected_adapter(&store, "a");
        let agent = store.adapter_session(&auth).unwrap().agent_id;
        let remote = format!("agent_{}", "c".repeat(32));
        let origin = Some(Origin {
            agent_id: remote.clone(),
            session_id: None,
        });
        let g = grant_for(&store, &peer.id, &agent, Some(&remote));
        let set_requester = |agent: &str| {
            let mut changed = g.clone();
            changed.requester_agent_id = Some(agent.into());
            store
                .connection()
                .unwrap()
                .execute(
                    "UPDATE grants SET record = ?1 WHERE id = ?2",
                    params![serde_json::to_string(&changed).unwrap(), g.id],
                )
                .unwrap();
        };
        // Accepted, then the grant names another requester agent: blocked.
        let first = request(&g.id, &agent, origin.clone());
        received(&store, &peer.id, &first);
        let other = format!("agent_{}", "d".repeat(32));
        set_requester(&other);
        assert!(store.next_delivery(&auth).unwrap().is_none());
        let blocked = store.deliveries(0, 10).unwrap();
        assert_eq!(blocked[0].delivery.state, "blocked");
        // Handed off, then the grant changes before the reply: refused.
        set_requester(&remote);
        let mut second = request(&g.id, &agent, origin);
        second.request_id = format!("request_{}", "2".repeat(32));
        received(&store, &peer.id, &second);
        let handoff = store.next_delivery(&auth).unwrap().unwrap();
        set_requester(&other);
        assert!(matches!(
            store.reply(&auth, &handoff.delivery.id, "done".into()),
            Err(Error::Forbidden)
        ));
        set_requester(&remote);
        store
            .reply(&auth, &handoff.delivery.id, "done".into())
            .unwrap();
    }
}
