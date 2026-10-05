use crate::{
    model::Error,
    store::{Store, append_event, new_id, now},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::SocketAddr};

pub(crate) const SCHEMA: &str = "
CREATE TABLE peers (id TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE grants (id TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE received_messages (sender TEXT NOT NULL, request_id TEXT NOT NULL, request TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY(sender, request_id));
CREATE TABLE outbound_messages (peer TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, request_id));
PRAGMA user_version = 2;
";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub id: String,
    pub public_key: String,
    pub address: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub requester_host_id: String,
    pub target_agent_id: String,
    pub action: String,
    pub expires_at: String,
    pub max_message_bytes: i64,
    pub allow_disconnected: bool,
    pub revoked_at: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGrant {
    pub requester_host_id: String,
    pub target_agent_id: String,
    pub expires_at: String,
    pub max_message_bytes: i64,
    #[serde(default)]
    pub allow_disconnected: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageRequest {
    pub request_id: String,
    pub grant_id: String,
    pub target_agent_id: String,
    pub deadline: String,
    pub content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendMessage {
    pub peer_host_id: String,
    #[serde(default)]
    pub request_id: String,
    pub grant_id: String,
    pub target_agent_id: String,
    pub deadline: String,
    pub content: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub sender_host_id: String,
    pub request_id: String,
    pub receiver_host_id: String,
    pub target_agent_id: String,
    pub accepted_at: String,
}
#[derive(Serialize)]
pub struct ReceivedMessage {
    pub sequence: i64,
    pub request: MessageRequest,
    pub receipt: Receipt,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub peer_host_id: String,
    pub request: MessageRequest,
    pub state: String,
    pub receipt: Option<Receipt>,
    pub error: Option<String>,
}

pub(crate) fn key_id(key: &[u8]) -> String {
    format!("host_{}", hex::encode(Sha256::digest(key)))
}
pub(crate) fn peer_key(p: &Peer) -> Result<Vec<u8>, Error> {
    let key = STANDARD
        .decode(&p.public_key)
        .map_err(|_| Error::Invalid("invalid peer public key".into()))?;
    if key.len() != 32 || STANDARD.encode(&key) != p.public_key || key_id(&key) != p.id {
        return Err(Error::Invalid("peer ID and public key must match".into()));
    }
    Ok(key)
}
pub(crate) fn load_pins(connection: &Connection) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let peers = records::<Peer>(connection, "SELECT record FROM peers ORDER BY id")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    peers
        .into_iter()
        .map(|p| {
            Ok((
                p.id.clone(),
                peer_key(&p).map_err(|e| anyhow::anyhow!("{e}"))?,
            ))
        })
        .collect()
}
pub(crate) fn json<T: DeserializeOwned>(encoded: String) -> Result<T, Error> {
    Ok(serde_json::from_str(&encoded)?)
}
pub(crate) fn read<T: DeserializeOwned>(
    connection: &Connection,
    query: &str,
    args: impl rusqlite::Params,
) -> Result<T, Error> {
    json(connection.query_row(query, args, |row| row.get(0))?)
}
pub(crate) fn records<T: DeserializeOwned>(
    connection: &Connection,
    query: &str,
) -> Result<Vec<T>, Error> {
    let mut statement = connection.prepare(query)?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .map(|r| json(r?))
        .collect()
}
pub(crate) fn valid_id(id: &str, prefix: &str, bytes: usize) -> bool {
    id.strip_prefix(&format!("{prefix}_")).is_some_and(|v| {
        v.len() == bytes * 2
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn validate_message(r: &MessageRequest) -> Result<(), Error> {
    if !valid_id(&r.request_id, "request", 16)
        || !valid_id(&r.grant_id, "grant", 16)
        || !valid_id(&r.target_agent_id, "agent", 16)
        || r.content.is_empty()
        || r.content.len() > 65536
    {
        return Err(Error::Invalid("invalid message".into()));
    }
    chrono::DateTime::parse_from_rfc3339(&r.deadline)
        .map_err(|_| Error::Invalid("invalid deadline".into()))?;
    Ok(())
}
impl Store {
    pub(crate) fn message_authority(
        &self,
        conn: &Connection,
        sender: &str,
        r: &MessageRequest,
        require_deadline: bool,
    ) -> Result<Grant, Error> {
        let g: Grant = read(
            conn,
            "SELECT record FROM grants WHERE id = ?1",
            [&r.grant_id],
        )
        .map_err(|e| match e {
            Error::NotFound => Error::Forbidden,
            other => other,
        })?;
        let expiration = chrono::DateTime::parse_from_rfc3339(&g.expires_at)
            .map_err(|e| Error::Internal(e.into()))?;
        let deadline = chrono::DateTime::parse_from_rfc3339(&r.deadline)
            .map_err(|e| Error::Internal(e.into()))?;
        let at = Utc::now();
        if g.requester_host_id != sender
            || g.target_agent_id != r.target_agent_id
            || g.action != "message.append"
            || g.revoked_at.is_some()
            || expiration <= at
            || deadline > expiration
            || (require_deadline && deadline <= at)
            || r.content.len() as i64 > g.max_message_bytes
            // Without coordination, only a grant that opts in permits new work.
            // This is rechecked at handoff and reply, not only at wire acceptance.
            || (!g.allow_disconnected && !self.connected(conn, sender)?)
        {
            return Err(Error::Forbidden);
        }
        Ok(g)
    }

    pub fn peers(&self) -> Result<Vec<Peer>, Error> {
        records(&*self.connection()?, "SELECT record FROM peers ORDER BY id")
    }
    pub fn peer(&self, id: &str) -> Result<Peer, Error> {
        read(
            &*self.connection()?,
            "SELECT record FROM peers WHERE id = ?1",
            [id],
        )
    }
    pub fn add_peer(&self, p: Peer) -> Result<Peer, Error> {
        let key = peer_key(&p)?;
        let address = p
            .address
            .parse::<SocketAddr>()
            .map_err(|_| Error::Invalid("address must be IP:port".into()))?;
        if address.port() == 0 {
            return Err(Error::Invalid("peer port must be nonzero".into()));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: Option<String> = tx
            .query_row("SELECT record FROM peers WHERE id = ?1", [&p.id], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(old) = old
            && json::<Peer>(old)? == p
        {
            return Ok(p);
        }
        tx.execute("INSERT INTO peers VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET record = excluded.record",params![p.id,serde_json::to_string(&p)?])?;
        append_event(&tx, "peer.configured", &p.id, &now())?;
        tx.commit()?;
        self.peer_pins
            .write()
            .map_err(|_| Error::Internal(anyhow::anyhow!("peer pins lock poisoned")))?
            .insert(p.id.clone(), key);
        Ok(p)
    }
    pub fn grants(&self) -> Result<Vec<Grant>, Error> {
        records(
            &*self.connection()?,
            "SELECT record FROM grants ORDER BY id",
        )
    }
    pub fn create_grant(&self, r: CreateGrant) -> Result<Grant, Error> {
        let expires = chrono::DateTime::parse_from_rfc3339(&r.expires_at)
            .map_err(|_| Error::Invalid("invalid expiration".into()))?;
        if expires <= Utc::now() || !(1..=65536).contains(&r.max_message_bytes) {
            return Err(Error::Invalid("invalid grant bounds".into()));
        }
        let g = Grant {
            id: new_id("grant")?,
            requester_host_id: r.requester_host_id,
            target_agent_id: r.target_agent_id,
            action: "message.append".into(),
            expires_at: r.expires_at,
            max_message_bytes: r.max_message_bytes,
            allow_disconnected: r.allow_disconnected,
            revoked_at: None,
        };
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if !self.known_host(&tx, &g.requester_host_id)? {
            return Err(Error::NotFound);
        }
        let agents: i64 = tx.query_row(
            "SELECT COUNT(*) FROM agents WHERE id = ?1",
            [&g.target_agent_id],
            |r| r.get(0),
        )?;
        if agents == 0 {
            return Err(Error::NotFound);
        }
        tx.execute(
            "INSERT INTO grants VALUES (?1, ?2)",
            params![g.id, serde_json::to_string(&g)?],
        )?;
        append_event(&tx, "grant.created", &g.id, &now())?;
        tx.commit()?;
        Ok(g)
    }
    pub fn revoke_grant(&self, id: &str) -> Result<Grant, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let mut g: Grant = read(&tx, "SELECT record FROM grants WHERE id = ?1", [id])?;
        if g.revoked_at.is_some() {
            return Ok(g);
        }
        let at = now();
        g.revoked_at = Some(at.clone());
        tx.execute(
            "UPDATE grants SET record = ?1 WHERE id = ?2",
            params![serde_json::to_string(&g)?, id],
        )?;
        append_event(&tx, "grant.revoked", id, &at)?;
        tx.commit()?;
        Ok(g)
    }
    pub fn accept_message(&self, sender: &str, r: MessageRequest) -> Result<Receipt, Error> {
        validate_message(&r)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        self.message_authority(&tx, sender, &r, true)?;
        let old:Option<(String,String)>=tx.query_row("SELECT request,receipt FROM received_messages WHERE sender = ?1 AND request_id = ?2",params![sender,r.request_id],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((old, receipt)) = old {
            if json::<MessageRequest>(old)? != r {
                return Err(Error::Conflict(
                    "request ID reused with different fields".into(),
                ));
            }
            return json(receipt);
        }
        let receipt = Receipt {
            sender_host_id: sender.into(),
            request_id: r.request_id.clone(),
            receiver_host_id: self.identity().id,
            target_agent_id: r.target_agent_id.clone(),
            accepted_at: now(),
        };
        tx.execute(
            "INSERT INTO received_messages VALUES (?1, ?2, ?3, ?4)",
            params![
                sender,
                r.request_id,
                serde_json::to_string(&r)?,
                serde_json::to_string(&receipt)?
            ],
        )?;
        append_event(
            &tx,
            "message.accepted",
            &format!("{sender}/{}", r.request_id),
            &receipt.accepted_at,
        )?;
        tx.commit()?;
        Ok(receipt)
    }
    pub fn message_receipt(&self, sender: &str, id: &str) -> Result<Receipt, Error> {
        read(
            &*self.connection()?,
            "SELECT receipt FROM received_messages WHERE sender = ?1 AND request_id = ?2",
            params![sender, id],
        )
    }
    pub fn messages(&self, after: i64, limit: i64) -> Result<Vec<ReceivedMessage>, Error> {
        if after < 0 || !(1..=1000).contains(&limit) {
            return Err(Error::Invalid("invalid page bounds".into()));
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT rowid,request,receipt FROM received_messages WHERE rowid > ?1 ORDER BY rowid LIMIT ?2")?;
        let mut rows = statement.query(params![after, limit])?;
        let mut items = Vec::new();
        let mut page_bytes = 2;
        while let Some(row) = rows.next()? {
            let item = ReceivedMessage {
                sequence: row.get(0)?,
                request: json(row.get(1)?)?,
                receipt: json(row.get(2)?)?,
            };
            let encoded = serde_json::to_vec(&item)?;
            if page_bytes + encoded.len() + 1 > 900000 {
                break;
            }
            page_bytes += encoded.len() + 1;
            items.push(item);
        }
        Ok(items)
    }

    pub fn outbound(&self, peer: &str, id: &str) -> Result<OutboundMessage, Error> {
        read(
            &*self.connection()?,
            "SELECT record FROM outbound_messages WHERE peer = ?1 AND request_id = ?2",
            params![peer, id],
        )
    }
    pub fn prepare_outbound(&self, r: SendMessage) -> Result<OutboundMessage, Error> {
        let request = MessageRequest {
            request_id: if r.request_id.is_empty() {
                new_id("request")?
            } else {
                r.request_id
            },
            grant_id: r.grant_id,
            target_agent_id: r.target_agent_id,
            deadline: r.deadline,
            content: r.content,
        };
        validate_message(&request)?;
        self.dial_target(&r.peer_host_id)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: Option<String> = tx
            .query_row(
                "SELECT record FROM outbound_messages WHERE peer = ?1 AND request_id = ?2",
                params![r.peer_host_id, request.request_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            let old: OutboundMessage = json(old)?;
            if old.request != request {
                return Err(Error::Conflict(
                    "request ID reused with different fields".into(),
                ));
            }
            return Ok(old);
        }
        let out = OutboundMessage {
            peer_host_id: r.peer_host_id,
            request,
            state: "unknown".into(),
            receipt: None,
            error: None,
        };
        tx.execute(
            "INSERT INTO outbound_messages VALUES (?1, ?2, ?3)",
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
        tx.commit()?;
        Ok(out)
    }
    pub fn finish_outbound(&self, out: OutboundMessage) -> Result<OutboundMessage, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let old: OutboundMessage = read(
            &tx,
            "SELECT record FROM outbound_messages WHERE peer = ?1 AND request_id = ?2",
            params![out.peer_host_id, out.request.request_id],
        )?;
        if old.state == "accepted" {
            return Ok(old);
        }
        tx.execute(
            "UPDATE outbound_messages SET record = ?1 WHERE peer = ?2 AND request_id = ?3",
            params![
                serde_json::to_string(&out)?,
                out.peer_host_id,
                out.request.request_id
            ],
        )?;
        if out.state != old.state {
            append_event(
                &tx,
                &format!("message.{}", out.state),
                &format!("{}/{}", out.peer_host_id, out.request.request_id),
                &now(),
            )?;
        }
        tx.commit()?;
        Ok(out)
    }
}
