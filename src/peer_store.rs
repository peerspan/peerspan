use crate::{
    model::Error,
    policy::PolicyRef,
    store::{Store, append_event, new_id, now, rfc3339},
};
use base64::{Engine, engine::general_purpose::STANDARD};
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
    /// The total input and result artifact bytes a task may carry; 0 allows
    /// none. Older records read as 0.
    #[serde(default)]
    pub max_artifact_bytes: i64,
    pub allow_disconnected: bool,
    pub revoked_at: Option<String>,
    /// When set, only requests whose asserted `origin.agent_id` equals it.
    #[serde(default)]
    pub requester_agent_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGrant {
    pub requester_host_id: String,
    pub target_agent_id: String,
    pub expires_at: String,
    pub max_message_bytes: i64,
    /// 0 (the default) through 1 GiB; nonzero only for `task.submit`.
    #[serde(default)]
    pub max_artifact_bytes: i64,
    #[serde(default)]
    pub allow_disconnected: bool,
    #[serde(default)]
    pub requester_agent_id: Option<String>,
    /// `message.append` (the default) or `task.submit`; never null.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub action: Option<String>,
}
/// The local agent, and optionally session, that originated a request,
/// asserted by the authenticated sending host.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub agent_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub session_id: Option<String>,
}
impl Origin {
    pub(crate) fn valid(&self) -> bool {
        valid_id(&self.agent_id, "agent", 16)
            && self
                .session_id
                .as_deref()
                .is_none_or(|s| valid_id(s, "session", 16))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageRequest {
    pub request_id: String,
    /// Exactly one of `grant_id` and `policy` names the authorization; on
    /// the wire the other is absent, never null or empty.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub grant_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub policy: Option<crate::policy::PolicyRef>,
    /// Self access: the sender's bound person (launch slice 3).
    #[serde(
        rename = "self",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub self_access: Option<crate::policy::SelfRef>,
    pub target_agent_id: String,
    pub deadline: String,
    pub content: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub origin: Option<Origin>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendMessage {
    pub peer_host_id: String,
    #[serde(default)]
    pub request_id: String,
    /// Absent or null, the send cites the target owner's policy.
    #[serde(default)]
    pub grant_id: Option<String>,
    pub target_agent_id: String,
    pub deadline: String,
    pub content: String,
    /// Owner sends may name a registered local agent, and optionally one of
    /// its sessions, as the origin; absent otherwise, never null.
    #[serde(default, deserialize_with = "crate::policy::present")]
    pub origin: Option<Origin>,
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
    #[serde(with = "recorded")]
    pub request: MessageRequest,
    pub state: String,
    pub receipt: Option<Receipt>,
    pub error: Option<String>,
    /// Transmissions so far (submissions and receipt queries).
    #[serde(default)]
    pub attempts: u32,
    /// When the daemon next retries an `unknown` record; null once final or
    /// given up. Records from before automatic retry lack it and are due now.
    #[serde(default)]
    pub next_attempt_at: Option<String>,
    /// Receipt queries made after the deadline; written only when nonzero.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub receipt_queries: u32,
    /// The address the send was made to, as given (launch slice 4);
    /// omitted for a send to a host and agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}
fn is_zero(n: &u32) -> bool {
    *n == 0
}

pub fn key_id(key: &[u8]) -> String {
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
/// An outbound record shows a request without a grant as `grant_id: null`;
/// the wire omits it.
pub(crate) mod recorded {
    use serde::{
        Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned, de::Error as _,
        ser::Error as _,
    };
    use serde_json::Value;
    pub fn serialize<T: Serialize, S: Serializer>(r: &T, s: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_json::to_value(r).map_err(S::Error::custom)?;
        if let Some(object) = value.as_object_mut() {
            object.entry("grant_id").or_insert(Value::Null);
        }
        value.serialize(s)
    }
    pub fn deserialize<'de, T: DeserializeOwned, D: Deserializer<'de>>(
        d: D,
    ) -> Result<T, D::Error> {
        let mut value = Value::deserialize(d)?;
        if let Some(object) = value.as_object_mut()
            && object.get("grant_id").is_some_and(Value::is_null)
        {
            object.remove("grant_id");
        }
        serde_json::from_value(value).map_err(D::Error::custom)
    }
}
pub(crate) fn valid_id(id: &str, prefix: &str, bytes: usize) -> bool {
    id.strip_prefix(&format!("{prefix}_")).is_some_and(|v| {
        v.len() == bytes * 2
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
/// Exactly one of `grant_id`, `policy`, and `self`, each well formed.
pub(crate) fn one_authorization(
    grant: Option<&str>,
    policy: Option<&PolicyRef>,
    self_access: Option<&crate::policy::SelfRef>,
) -> bool {
    match (grant, policy, self_access) {
        (Some(grant), None, None) => valid_id(grant, "grant", 16),
        (None, Some(p), None) => p.version >= 1 && crate::policy::person_id_shape(&p.person_id),
        (None, None, Some(s)) => crate::policy::person_id_shape(&s.person_id),
        _ => false,
    }
}
fn validate_message(r: &MessageRequest) -> Result<(), Error> {
    let authorization = one_authorization(
        r.grant_id.as_deref(),
        r.policy.as_ref(),
        r.self_access.as_ref(),
    );
    if !valid_id(&r.request_id, "request", 16)
        || !authorization
        || r.origin.as_ref().is_some_and(|o| !o.valid())
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
/// The authorization message and task requests share: who may perform which
/// action on which local agent, until when, and with how large a body.
#[derive(Clone, Copy)]
pub(crate) struct Authz<'a> {
    pub action: &'a str,
    pub grant_id: Option<&'a str>,
    pub policy: Option<&'a PolicyRef>,
    pub self_access: Option<&'a crate::policy::SelfRef>,
    pub target_agent_id: &'a str,
    pub deadline: &'a str,
    /// Bytes bounded by `max_message_bytes`: message content or task input.
    pub size: usize,
    pub origin: Option<&'a Origin>,
    /// A task's input artifact total, when it carries any; bounded by
    /// `max_artifact_bytes`, where 0 refuses artifacts altogether.
    pub artifacts: Option<i64>,
}
/// Whether an artifact bound admits a total (none at all under 0).
pub(crate) fn artifacts_fit(total: Option<i64>, bound: i64) -> bool {
    total.is_none_or(|t| bound > 0 && t <= bound)
}
impl MessageRequest {
    pub(crate) fn authz(&self) -> Authz<'_> {
        Authz {
            action: crate::policy::ACTION,
            grant_id: self.grant_id.as_deref(),
            policy: self.policy.as_ref(),
            self_access: self.self_access.as_ref(),
            target_agent_id: &self.target_agent_id,
            deadline: &self.deadline,
            size: self.content.len(),
            origin: self.origin.as_ref(),
            artifacts: None,
        }
    }
}
/// Checks everything except coordination connectivity. Its denials are final:
/// revocation, expiry, a passed deadline, and size never recover.
pub(crate) fn grant_bounds(
    conn: &Connection,
    sender: &str,
    r: &Authz<'_>,
    require_deadline: bool,
) -> Result<Grant, Error> {
    let g: Grant = read(
        conn,
        "SELECT record FROM grants WHERE id = ?1",
        [r.grant_id.unwrap_or_default()],
    )
    .map_err(|e| match e {
        Error::NotFound => Error::Forbidden,
        other => other,
    })?;
    let expiration = chrono::DateTime::parse_from_rfc3339(&g.expires_at)
        .map_err(|e| Error::Internal(e.into()))?;
    let deadline =
        chrono::DateTime::parse_from_rfc3339(r.deadline).map_err(|e| Error::Internal(e.into()))?;
    let at = crate::clock::now();
    if g.requester_host_id != sender
        || g.target_agent_id != r.target_agent_id
        || !crate::policy::allows(&g.action, r.action)
        || g.revoked_at.is_some()
        || expiration <= at
        || deadline > expiration
        || (require_deadline && deadline <= at)
        || r.size as i64 > g.max_message_bytes
        || !artifacts_fit(r.artifacts, g.max_artifact_bytes)
        || g.requester_agent_id
            .as_deref()
            .is_some_and(|agent| r.origin.map(|o| o.agent_id.as_str()) != Some(agent))
    {
        return Err(Error::Forbidden);
    }
    Ok(g)
}
/// What an authorization allows: a grant's or a policy rule's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bounds {
    pub max_message_bytes: i64,
    pub max_artifact_bytes: i64,
    pub allow_disconnected: bool,
    /// Whether the authorization includes `task.delegate`.
    pub delegate: bool,
}
/// Whether a grant's connected-state requirement is met.
pub(crate) enum Connectivity {
    Usable,
    /// The requester is a verified member of a network this host has not
    /// synced recently; resumed syncing can restore it.
    Stale,
    /// The requester is not a member of any network; this does not recover.
    Absent,
}
impl Store {
    /// Every final check: the block list, then a grant or the cited owner
    /// policy and its bounds. A receiver behind a cited policy version is
    /// `Unavailable` (recoverable); everything else denied is `Forbidden`.
    pub(crate) fn message_bounds(
        &self,
        conn: &Connection,
        sender: &str,
        r: &Authz<'_>,
        require_deadline: bool,
    ) -> Result<Bounds, Error> {
        // Self access needs no grant or policy, and blocks do not apply.
        if let Some(cited) = r.self_access {
            return self.self_bounds(conn, sender, r, cited, require_deadline);
        }
        if self.blocked(conn, sender)? {
            return Err(Error::Forbidden);
        }
        match r.policy {
            Some(cited) => self.policy_bounds(conn, sender, r, cited, require_deadline),
            None => {
                let g = grant_bounds(conn, sender, r, require_deadline)?;
                Ok(Bounds {
                    max_message_bytes: g.max_message_bytes,
                    max_artifact_bytes: g.max_artifact_bytes,
                    allow_disconnected: g.allow_disconnected,
                    delegate: g.action == crate::policy::DELEGATE_ACTION,
                })
            }
        }
    }
    pub(crate) fn message_authority(
        &self,
        conn: &Connection,
        sender: &str,
        r: &Authz<'_>,
        require_deadline: bool,
    ) -> Result<Bounds, Error> {
        let g = self.message_bounds(conn, sender, r, require_deadline)?;
        match self.grant_connected(conn, sender, &g)? {
            Connectivity::Usable => Ok(g),
            // Retryable (503), unlike final denials.
            Connectivity::Stale => Err(Error::Unavailable("coordination disconnected".into())),
            Connectivity::Absent => Err(Error::Forbidden),
        }
    }

    /// Whether the grant may be used now. Without coordination, only a grant
    /// that opts in permits new work.
    pub(crate) fn grant_connected(
        &self,
        conn: &Connection,
        sender: &str,
        g: &Bounds,
    ) -> Result<Connectivity, Error> {
        if g.allow_disconnected || self.connected(conn, sender)? {
            return Ok(Connectivity::Usable);
        }
        let member: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_members WHERE host_id = ?1)",
            [sender],
            |r| r.get(0),
        )?;
        Ok(if member {
            Connectivity::Stale
        } else {
            Connectivity::Absent
        })
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
        if expires <= crate::clock::now() || !(1..=65536).contains(&r.max_message_bytes) {
            return Err(Error::Invalid("invalid grant bounds".into()));
        }
        let g = Grant {
            id: new_id("grant")?,
            requester_host_id: r.requester_host_id,
            target_agent_id: r.target_agent_id,
            action: r.action.unwrap_or_else(|| crate::policy::ACTION.to_owned()),
            expires_at: r.expires_at,
            max_message_bytes: r.max_message_bytes,
            max_artifact_bytes: r.max_artifact_bytes,
            allow_disconnected: r.allow_disconnected,
            revoked_at: None,
            requester_agent_id: r.requester_agent_id,
        };
        if g.requester_agent_id
            .as_deref()
            .is_some_and(|a| !valid_id(a, "agent", 16))
        {
            return Err(Error::Invalid("invalid requester agent ID".into()));
        }
        if !crate::policy::ACTIONS.contains(&g.action.as_str()) {
            return Err(Error::Invalid(
                "action must be message.append, task.submit, or task.delegate".into(),
            ));
        }
        crate::artifact::check_bound(
            g.max_artifact_bytes,
            crate::policy::task_actions(std::iter::once(g.action.as_str())),
        )?;
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
        self.message_authority(&tx, sender, &r.authz(), true)?;
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
        self.prepare_outbound_to(r, None)
    }
    /// An addressed send's target is resolved and its authorization chosen
    /// before this; a repeat of a stored send by address has no choice and
    /// returns the stored record without citing anything anew.
    pub(crate) fn prepare_outbound_to(
        &self,
        r: SendMessage,
        addressed: Option<crate::directory::Addressed>,
    ) -> Result<OutboundMessage, Error> {
        let explicit_grant = r.grant_id.is_some();
        let policy = r.grant_id.is_none().then(|| PolicyRef {
            person_id: format!("person_{}", "0".repeat(64)),
            version: 1,
        });
        let mut request = MessageRequest {
            request_id: if r.request_id.is_empty() {
                new_id("request")?
            } else {
                r.request_id
            },
            grant_id: r.grant_id,
            policy,
            self_access: None,
            target_agent_id: r.target_agent_id,
            deadline: r.deadline,
            content: r.content,
            origin: r.origin,
        };
        if let Some(origin) = &request.origin {
            if !origin.valid() {
                return Err(Error::Invalid("invalid origin".into()));
            }
            self.check_local_origin(&*self.connection()?, origin)?;
        }
        validate_message(&request)?;
        self.dial_target(&r.peer_host_id)?;
        if request.policy.is_some() {
            // Cite self access, or else the target owner's newest verified
            // policy; with neither, the send is refused before anything is
            // persisted. A send by address cites what was chosen for it.
            let conn = self.connection()?;
            match addressed.as_ref().map(|a| &a.choice) {
                None => {
                    (request.policy, request.self_access) =
                        self.citation(&conn, &r.peer_host_id)?.fields();
                }
                Some(Some(choice)) => {
                    (request.grant_id, request.policy, request.self_access) =
                        self.chosen_citation(&conn, &r.peer_host_id, choice)?;
                }
                Some(None) => {}
            }
        }
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
            // A repeated send cites the owner's newest version, which may have
            // moved on; the stored request with its original citation stands.
            let same_owner = |a: &MessageRequest| MessageRequest {
                policy: a.policy.as_ref().map(|p| crate::policy::PolicyRef {
                    person_id: p.person_id.clone(),
                    version: 0,
                }),
                ..a.clone()
            };
            // A repeat by address keeps the stored citation, whatever it
            // cites, unless it names a grant itself.
            let same_address = |a: &MessageRequest| MessageRequest {
                grant_id: a.grant_id.clone().filter(|_| explicit_grant),
                policy: None,
                self_access: None,
                ..a.clone()
            };
            let differs = match &addressed {
                None => old.to.is_some() || same_owner(&old.request) != same_owner(&request),
                Some(a) => {
                    old.to.as_deref() != Some(a.to.as_str())
                        || same_address(&old.request) != same_address(&request)
                }
            };
            if differs {
                return Err(Error::Conflict(
                    "request ID reused with different fields".into(),
                ));
            }
            return Ok(old);
        }
        if addressed.as_ref().is_some_and(|a| a.choice.is_none()) && !explicit_grant {
            return Err(Error::Conflict(
                "the stored send by address changed; retry".into(),
            ));
        }
        let out = OutboundMessage {
            peer_host_id: r.peer_host_id,
            request,
            state: "unknown".into(),
            receipt: None,
            error: None,
            attempts: 0,
            // Retried automatically if the inline send never finishes.
            next_attempt_at: Some(rfc3339(crate::clock::now() + crate::retry::PREPARE_GUARD)),
            receipt_queries: 0,
            to: addressed.map(|a| a.to),
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
    /// An owner-asserted origin names a registered local agent and, if given,
    /// one of that agent's sessions.
    pub(crate) fn check_local_origin(&self, conn: &Connection, o: &Origin) -> Result<(), Error> {
        let agents: i64 = conn.query_row(
            "SELECT COUNT(*) FROM agents WHERE id = ?1",
            [&o.agent_id],
            |r| r.get(0),
        )?;
        if agents == 0 {
            return Err(Error::NotFound);
        }
        if let Some(session) = &o.session_id {
            let sessions: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE id = ?1 AND agent_id = ?2",
                params![session, o.agent_id],
                |r| r.get(0),
            )?;
            if sessions == 0 {
                return Err(Error::NotFound);
            }
        }
        Ok(())
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{AttachSession, RegisterAgent};

    pub(crate) fn add_test_peer(store: &Store) -> Peer {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        store
            .add_peer(Peer {
                id: key_id(&key),
                public_key: STANDARD.encode(key),
                address: "127.0.0.1:9".into(),
            })
            .unwrap()
    }
    pub(crate) fn local_agent(store: &Store, name: &str) -> (String, String) {
        let agent = store
            .register_agent(RegisterAgent {
                name: name.into(),
                owner: name.into(),
                capabilities: vec![],
            })
            .unwrap();
        let session = store
            .attach_session(AttachSession {
                agent_id: agent.id.clone(),
                integration: "test".into(),
            })
            .unwrap();
        (agent.id, session.id)
    }
    pub(crate) fn grant_for(store: &Store, peer: &str, agent: &str, from: Option<&str>) -> Grant {
        store
            .create_grant(CreateGrant {
                requester_host_id: peer.into(),
                target_agent_id: agent.into(),
                expires_at: rfc3339(crate::clock::now() + chrono::Duration::hours(1)),
                max_message_bytes: 1000,
                max_artifact_bytes: 0,
                allow_disconnected: true,
                requester_agent_id: from.map(Into::into),
                action: None,
            })
            .unwrap()
    }
    pub(crate) fn request(grant: &str, agent: &str, origin: Option<Origin>) -> MessageRequest {
        MessageRequest {
            request_id: format!("request_{}", "1".repeat(32)),
            grant_id: Some(grant.into()),
            policy: None,
            self_access: None,
            target_agent_id: agent.into(),
            deadline: rfc3339(crate::clock::now() + chrono::Duration::minutes(5)),
            content: "hello".into(),
            origin,
        }
    }
    fn origin(agent: &str, session: Option<&str>) -> Option<Origin> {
        Some(Origin {
            agent_id: agent.into(),
            session_id: session.map(Into::into),
        })
    }

    #[test]
    fn origin_is_strictly_shaped() {
        let agent = format!("agent_{}", "a".repeat(32));
        let session = format!("session_{}", "b".repeat(32));
        let base = serde_json::json!({
            "request_id": format!("request_{}", "0".repeat(32)),
            "grant_id": format!("grant_{}", "0".repeat(32)),
            "target_agent_id": agent,
            "deadline": "2026-10-10T00:00:00Z",
            "content": "hi",
        });
        let with = |o: serde_json::Value| {
            let mut v = base.clone();
            v["origin"] = o;
            serde_json::from_value::<MessageRequest>(v)
        };
        let r = with(serde_json::json!({"agent_id": agent, "session_id": session})).unwrap();
        validate_message(&r).unwrap();
        assert_eq!(
            serde_json::to_value(&r).unwrap()["origin"],
            serde_json::json!({"agent_id": agent, "session_id": session})
        );
        let r = with(serde_json::json!({"agent_id": agent})).unwrap();
        validate_message(&r).unwrap();
        assert!(
            serde_json::to_value(&r).unwrap()["origin"]
                .get("session_id")
                .is_none()
        );
        let absent: MessageRequest = serde_json::from_value(base.clone()).unwrap();
        assert!(
            serde_json::to_value(&absent)
                .unwrap()
                .get("origin")
                .is_none()
        );
        for bad in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"session_id": session}),
            serde_json::json!({"agent_id": null}),
            serde_json::json!({"agent_id": agent, "session_id": null}),
            serde_json::json!({"agent_id": agent, "host_id": "x"}),
            serde_json::json!("agent"),
        ] {
            assert!(with(bad.clone()).is_err(), "{bad}");
        }
        for bad in [
            serde_json::json!({"agent_id": "agent_x"}),
            serde_json::json!({"agent_id": session}),
            serde_json::json!({"agent_id": agent, "session_id": agent}),
            serde_json::json!({"agent_id": agent.to_uppercase()}),
        ] {
            assert!(
                matches!(
                    validate_message(&with(bad.clone()).unwrap()),
                    Err(Error::Invalid(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn agent_grants_admit_only_their_requester_agent_and_origin_is_deduplicated() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let peer = add_test_peer(&store);
        let (target, _) = local_agent(&store, "target");
        let remote = format!("agent_{}", "c".repeat(32));
        let bad = store.create_grant(CreateGrant {
            requester_host_id: peer.id.clone(),
            target_agent_id: target.clone(),
            expires_at: rfc3339(crate::clock::now() + chrono::Duration::hours(1)),
            max_message_bytes: 1000,
            max_artifact_bytes: 0,
            allow_disconnected: true,
            requester_agent_id: Some("agent_bad".into()),
            action: None,
        });
        assert!(matches!(bad, Err(Error::Invalid(_))));
        let g = grant_for(&store, &peer.id, &target, Some(&remote));
        assert_eq!(
            serde_json::to_value(&g).unwrap()["requester_agent_id"],
            serde_json::json!(remote)
        );
        let other = format!("agent_{}", "d".repeat(32));
        for denied in [None, origin(&other, None)] {
            assert!(matches!(
                store.accept_message(&peer.id, request(&g.id, &target, denied)),
                Err(Error::Forbidden)
            ));
        }
        let session = format!("session_{}", "e".repeat(32));
        let first = request(&g.id, &target, origin(&remote, Some(&session)));
        let receipt = store.accept_message(&peer.id, first.clone()).unwrap();
        let again = store.accept_message(&peer.id, first.clone()).unwrap();
        assert_eq!(receipt.accepted_at, again.accepted_at);
        let changed = MessageRequest {
            origin: origin(&remote, None),
            ..first
        };
        assert!(matches!(
            store.accept_message(&peer.id, changed),
            Err(Error::Conflict(_))
        ));
        let stored = store.messages(0, 10).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].request.origin, origin(&remote, Some(&session)));
        // A grant without a requester agent ignores origin.
        let open = grant_for(&store, &peer.id, &target, None);
        let mut plain = request(&open.id, &target, None);
        plain.request_id = format!("request_{}", "2".repeat(32));
        store.accept_message(&peer.id, plain).unwrap();
    }

    #[test]
    fn owner_sends_name_only_registered_local_origins() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let peer = add_test_peer(&store);
        let (agent, session) = local_agent(&store, "sender");
        let (_, foreign_session) = local_agent(&store, "other");
        let send = |o: Option<Origin>| {
            store.prepare_outbound(SendMessage {
                peer_host_id: peer.id.clone(),
                request_id: String::new(),
                grant_id: Some(format!("grant_{}", "1".repeat(32))),
                target_agent_id: format!("agent_{}", "2".repeat(32)),
                deadline: rfc3339(crate::clock::now() + chrono::Duration::minutes(5)),
                content: "hello".into(),
                origin: o,
            })
        };
        let unknown = format!("agent_{}", "9".repeat(32));
        let unknown_session = format!("session_{}", "9".repeat(32));
        for missing in [
            origin(&unknown, None),
            origin(&agent, Some(&unknown_session)),
            origin(&agent, Some(&foreign_session)),
        ] {
            assert!(matches!(send(missing), Err(Error::NotFound)));
        }
        assert!(matches!(
            send(origin("agent_bad", None)),
            Err(Error::Invalid(_))
        ));
        let count = || -> i64 {
            store
                .connection()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM outbound_messages", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(), 0);
        let out = send(origin(&agent, Some(&session))).unwrap();
        assert_eq!(out.request.origin, origin(&agent, Some(&session)));
        assert_eq!(
            store
                .outbound(&peer.id, &out.request.request_id)
                .unwrap()
                .request
                .origin,
            origin(&agent, Some(&session))
        );
        assert!(send(None).unwrap().request.origin.is_none());
        assert_eq!(count(), 2);
    }

    #[test]
    fn local_send_bodies_reject_a_null_origin() {
        let body = serde_json::json!({
            "peer_host_id": "host_x",
            "target_agent_id": "agent_y",
            "deadline": "d",
            "content": "c",
            "origin": null,
        });
        assert!(serde_json::from_value::<SendMessage>(body).is_err());
    }
}
