//! Conversations, PR C1 (docs/conversations-contract.md): a person on the
//! home host starts a conversation with one remote agent, and both send.
//!
//! Each host keeps the messages it authored and those it accepted. The home
//! host orders roster versions; messages go directly from the author's host
//! to each target's host, with one durable target record per recipient.
use crate::{
    adapter_connection::{authority, verified_authority},
    api::{blocking, decode},
    directory::coded,
    model::Error,
    peer_store::{Authz, Origin, json, one_authorization, valid_id},
    policy::{PolicyRef, RequestAuthorization, SelfRef},
    retry::{Dispatcher, backoff, due_at, jitter},
    store::{Store, new_id, now, rfc3339},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::watch;

/// Every table of feature slice 1 (proposal, Persistence), added at once.
pub(crate) const SCHEMA: &str = r#"
CREATE TABLE conversations (id TEXT PRIMARY KEY, home_host TEXT NOT NULL, roster_version INTEGER NOT NULL, state TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE conversation_messages (conversation_id TEXT NOT NULL REFERENCES conversations(id), message_id TEXT NOT NULL, author TEXT NOT NULL, seq INTEGER NOT NULL, clock INTEGER NOT NULL, local_seq INTEGER NOT NULL UNIQUE, record TEXT NOT NULL, PRIMARY KEY(conversation_id, message_id), UNIQUE(conversation_id, author, seq));
CREATE INDEX conversation_messages_order ON conversation_messages(conversation_id, clock, author, seq);
CREATE TABLE conversation_targets (conversation_id TEXT NOT NULL, message_id TEXT NOT NULL, target TEXT NOT NULL, direction TEXT NOT NULL, peer TEXT NOT NULL, prev_seq INTEGER, state TEXT NOT NULL, next_attempt_at TEXT, record TEXT NOT NULL, PRIMARY KEY(conversation_id, message_id, target, direction));
CREATE TABLE conversation_invites (conversation_id TEXT NOT NULL, person_id TEXT NOT NULL, home_host TEXT NOT NULL, expires_at TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(conversation_id, person_id));
CREATE TABLE conversation_roster_outbound (conversation_id TEXT NOT NULL, peer TEXT NOT NULL, kind TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(conversation_id, peer, kind));
CREATE TABLE conversation_notifications (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, kind TEXT NOT NULL, message_id TEXT, agent_id TEXT NOT NULL REFERENCES agents(id), session_id TEXT REFERENCES sessions(id), record TEXT NOT NULL, seen_at TEXT, redeliveries INTEGER NOT NULL DEFAULT 0, returned_at TEXT);
CREATE TABLE conversation_reads (conversation_id TEXT NOT NULL, participant TEXT NOT NULL, read_through INTEGER NOT NULL, PRIMARY KEY(conversation_id, participant));
CREATE TABLE conversation_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, record TEXT NOT NULL);
PRAGMA user_version = 24;
"#;

const MAX_CONTENT: usize = 65_536;
const MAX_TITLE: usize = 200;
const MAX_NOTE: usize = 4_096;
const START_WAIT: Duration = Duration::from_secs(15);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
const WINDOW_MESSAGES: usize = 10;
const WINDOW_BYTES: usize = 16_384;
const WINDOW_CUT: usize = 2_048;

// ---------------------------------------------------------------- shapes

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub id: Option<String>,
    pub kind: String,
    pub host_id: Option<String>,
    pub person_id: Option<String>,
    pub agent_id: Option<String>,
    pub name: Option<String>,
    pub state: String,
    pub added_by: Option<String>,
    pub added_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Roster {
    pub conversation_id: String,
    pub home_host_id: String,
    pub version: i64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub title: Option<String>,
    pub state: String,
    pub created_by: String,
    pub created_at: String,
    pub participants: Vec<Participant>,
    pub departed: Vec<Value>,
}
impl Roster {
    fn joined(&self, id: &str) -> Option<&Participant> {
        self.participants
            .iter()
            .find(|p| p.id.as_deref() == Some(id) && p.state == "joined")
    }
    fn ever(&self, id: &str) -> bool {
        self.participants
            .iter()
            .any(|p| p.id.as_deref() == Some(id))
            || self.departed.iter().any(|d| d["id"].as_str() == Some(id))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub message_id: String,
    pub conversation_id: String,
    pub author: String,
    pub seq: i64,
    pub clock: i64,
    pub roster_version: i64,
    pub sent_at: String,
    pub content: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub addressed_to: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub origin: Option<Origin>,
}

/// A message as this host holds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stored {
    message: Message,
    received_at: String,
    sender_host: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InviteTarget {
    pub kind: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub agent_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub person_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    pub conversation_id: String,
    pub roster: Roster,
    pub target: InviteTarget,
    pub adder: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub note: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub origin: Option<Origin>,
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
    pub policy: Option<PolicyRef>,
    #[serde(
        rename = "self",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub self_access: Option<SelfRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MessageRequest {
    pub message: Message,
    pub target: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub prev_seq: Option<i64>,
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
    pub policy: Option<PolicyRef>,
    #[serde(
        rename = "self",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::policy::present"
    )]
    pub self_access: Option<SelfRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub message_id: String,
    pub target: String,
    pub receiver_host_id: String,
    pub accepted_at: String,
}

/// An inbound target record: what was accepted, for deduplication.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Inbound {
    message: Message,
    target: String,
    prev_seq: Option<i64>,
    receipt: Receipt,
}

/// An outbound target record: one recipient's delivery state.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Outbound {
    participant: String,
    state: String,
    code: Option<String>,
    error: Option<String>,
    attempts: u32,
    next_attempt_at: Option<String>,
}

/// An invite the home host sends until it has a final answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Invite {
    target: String,
    participant: String,
    agent_id: String,
    adder: String,
    state: String,
    code: Option<String>,
    error: Option<String>,
    attempts: u32,
    next_attempt_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Notification {
    id: String,
    kind: String,
    conversation_id: String,
    message_id: Option<String>,
    session_id: Option<String>,
    created_at: String,
    claimed_at: Option<String>,
    forwarded_at: Option<String>,
}

// ---------------------------------------------------------------- helpers

fn coded_error(status: u16, code: &'static str, message: &str) -> Error {
    coded(status, code, message.into(), json!({}))
}
fn not_participant() -> Error {
    coded_error(
        403,
        "not_participant",
        "This participant is not in that conversation.",
    )
}
fn not_bound() -> Error {
    coded_error(
        409,
        "not_bound",
        "This host is not bound to a person; conversations need one (peerspan join).",
    )
}
fn unavailable(message: &str) -> Error {
    Error::Unavailable(message.into())
}
fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}
pub(crate) fn valid_conversation_id(id: &str) -> bool {
    valid_id(id, "conv", 16)
}
pub(crate) fn valid_message_id(id: &str) -> bool {
    valid_id(id, "cmsg", 16)
}
fn valid_title(title: &str) -> bool {
    title.len() <= MAX_TITLE && !title.chars().any(char::is_control)
}
/// A participant ID's kind and host: `agent:HOST/AGENT` or `person:HOST/PERSON`.
fn participant_parts(id: &str) -> Option<(&'static str, &str, &str)> {
    let (kind, rest) = match id.strip_prefix("agent:") {
        Some(rest) => ("agent", rest),
        None => ("person", id.strip_prefix("person:")?),
    };
    let (host, local) = rest.split_once('/')?;
    let local_ok = if kind == "agent" {
        valid_id(local, "agent", 16)
    } else {
        crate::policy::person_id_shape(local)
    };
    (valid_id(host, "host", 32) && local_ok).then_some((kind, host, local))
}
/// Whether every participant's fields agree with its ID, and IDs are unique.
fn consistent(roster: &Roster) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    roster.participants.iter().all(|p| {
        let Some(id) = p.id.as_deref() else {
            return false;
        };
        let Some((kind, host, local)) = participant_parts(id) else {
            return false;
        };
        let fields = if kind == "agent" {
            p.agent_id.as_deref() == Some(local) && p.name.is_some()
        } else {
            p.agent_id.is_none() && p.person_id.as_deref() == Some(local)
        };
        seen.insert(id)
            && p.kind == kind
            && p.host_id.as_deref() == Some(host)
            && fields
            && matches!(&p.state[..], "inviting" | "joined")
    })
}
fn valid_content(content: &str) -> bool {
    !content.is_empty() && content.len() <= MAX_CONTENT
}
fn table_roster(conn: &Connection, id: &str) -> Result<Option<Roster>, Error> {
    let record: Option<String> = conn
        .query_row(
            "SELECT record FROM conversations WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    record.map(json).transpose()
}
fn save_roster(conn: &Connection, roster: &Roster) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO conversations (id, home_host, roster_version, state, record) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO UPDATE SET roster_version = excluded.roster_version, state = excluded.state, record = excluded.record",
        params![
            roster.conversation_id,
            roster.home_host_id,
            roster.version,
            roster.state,
            serde_json::to_string(roster)?
        ],
    )?;
    Ok(())
}
fn cut(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
fn later(seconds: i64) -> String {
    rfc3339(crate::clock::now() + chrono::TimeDelta::seconds(seconds))
}

/// One attempt's outcome, as the sender classifies a peer answer.
enum Outcome {
    /// A 200 answer, with its body.
    Answer(Vec<u8>),
    /// A final refusal: state, code and text.
    Final(&'static str, &'static str, String),
    /// Not final: retried.
    Retry(String),
}
fn classify(status: u16, body: &[u8], peer: &str) -> Outcome {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["code"].as_str().map(str::to_owned))
        .unwrap_or_default();
    match status {
        200 => Outcome::Answer(body.to_vec()),
        400 => Outcome::Final(
            "refused",
            "invalid",
            format!("{peer} refused it as invalid"),
        ),
        403 if code == "not_participant" => Outcome::Final(
            "refused",
            "not_participant",
            format!("{peer} holds that participant as not in the conversation"),
        ),
        403 => Outcome::Final(
            "refused",
            "not_authorized",
            format!("{peer} did not authorize it"),
        ),
        409 => Outcome::Final(
            "refused",
            "conflict",
            format!("{peer} holds a different message with that ID"),
        ),
        404 => Outcome::Final(
            "unsupported",
            "unsupported",
            format!("{peer} is running a Peerspan without conversations"),
        ),
        other => Outcome::Retry(format!("peer returned HTTP {other}")),
    }
}

// ---------------------------------------------------------------- store

impl Store {
    /// This host's bound person, from the first network that binds it.
    fn conversation_person(&self, conn: &Connection) -> Result<Option<String>, Error> {
        Ok(self
            .own_members(conn)?
            .into_iter()
            .find_map(|(_, m)| m.person_id))
    }
    fn person_participant(&self, conn: &Connection) -> Result<String, Error> {
        let person = self.conversation_person(conn)?.ok_or_else(not_bound)?;
        Ok(format!("person:{}/{person}", self.identity().id))
    }
    /// A participant's label, derived from this host's verified records.
    fn label(&self, conn: &Connection, p: &Participant) -> Result<String, Error> {
        // The host comes from the participant ID, which messages are
        // checked against, never from the roster's other fields.
        let host = match p.id.as_deref().and_then(participant_parts) {
            Some((_, host, _)) => host.to_owned(),
            None => p.host_id.clone().unwrap_or_default(),
        };
        let person = crate::adapter::sender_person(self, conn, &host)?.1;
        let base = person.unwrap_or(host);
        Ok(match (&p.kind[..], &p.name) {
            ("agent", Some(name)) => format!("{base}/{name}"),
            ("agent", None) => format!("{base}/{}", p.agent_id.clone().unwrap_or_default()),
            _ => base,
        })
    }
    fn label_of(&self, conn: &Connection, roster: &Roster, id: &str) -> Result<String, Error> {
        if let Some(p) = roster
            .participants
            .iter()
            .find(|p| p.id.as_deref() == Some(id))
        {
            return self.label(conn, p);
        }
        let Some((kind, host, local)) = participant_parts(id) else {
            return Ok(id.to_owned());
        };
        let p = Participant {
            id: Some(id.into()),
            kind: kind.into(),
            host_id: Some(host.into()),
            person_id: None,
            agent_id: (kind == "agent").then(|| local.to_owned()),
            name: None,
            state: "joined".into(),
            added_by: None,
            added_at: String::new(),
        };
        self.label(conn, &p)
    }
    fn local_participant(&self, id: &str) -> bool {
        participant_parts(id).is_some_and(|(_, host, _)| host == self.identity().id)
    }
    fn roster(&self, conn: &Connection, id: &str) -> Result<Roster, Error> {
        table_roster(conn, id)?.ok_or(Error::NotFound)
    }
    /// The participant a local read is for: the given one, which must be on
    /// this host and in the roster, or this host's person.
    fn reader(
        &self,
        conn: &Connection,
        roster: &Roster,
        participant: Option<String>,
    ) -> Result<String, Error> {
        let reader = match participant {
            Some(p) => {
                if !self.local_participant(&p) {
                    return Err(invalid("participant must be a local participant ID"));
                }
                p
            }
            None => self.person_participant(conn)?,
        };
        if !roster.ever(&reader) {
            return Err(not_participant());
        }
        Ok(reader)
    }

    /// The messages `reader` may see, in display order.
    fn visible(&self, conn: &Connection, id: &str, reader: &str) -> Result<Vec<Stored>, Error> {
        let mut statement = conn.prepare(
            "SELECT m.record FROM conversation_messages m WHERE m.conversation_id = ?1 AND (m.author = ?2 OR EXISTS (SELECT 1 FROM conversation_targets t WHERE t.conversation_id = m.conversation_id AND t.message_id = m.message_id AND t.direction = 'in' AND t.target = ?2)) ORDER BY m.clock, m.author, m.seq",
        )?;
        let rows = statement
            .query_map(params![id, reader], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(json).collect()
    }
    fn targets(
        &self,
        conn: &Connection,
        roster: &Roster,
        message: &str,
    ) -> Result<Vec<Value>, Error> {
        let mut statement = conn.prepare(
            "SELECT record FROM conversation_targets WHERE conversation_id = ?1 AND message_id = ?2 AND direction = 'out' ORDER BY rowid",
        )?;
        let rows = statement
            .query_map(params![roster.conversation_id, message], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|text| {
                let o: Outbound = json(text)?;
                Ok(json!({
                    "participant": o.participant,
                    "label": self.label_of(conn, roster, &o.participant)?,
                    "state": o.state,
                    "code": o.code,
                    "error": o.error,
                    "attempts": o.attempts,
                }))
            })
            .collect()
    }
    fn author_kind(author: &str) -> &'static str {
        if author.starts_with("agent:") {
            "agent"
        } else {
            "person"
        }
    }
    fn message_view(
        &self,
        conn: &Connection,
        roster: &Roster,
        stored: &Stored,
        reader: &str,
    ) -> Result<Value, Error> {
        let m = &stored.message;
        let mine = m.author == reader;
        Ok(json!({
            "message_id": m.message_id,
            "conversation_id": m.conversation_id,
            "author": m.author,
            "author_label": self.label_of(conn, roster, &m.author)?,
            "author_kind": Self::author_kind(&m.author),
            "seq": m.seq,
            "clock": m.clock,
            "roster_version": m.roster_version,
            "sent_at": m.sent_at,
            "received_at": stored.received_at,
            "content": m.content,
            "addressed_to": m.addressed_to.clone().unwrap_or_default(),
            "mine": mine,
            "targets": if mine { Value::from(self.targets(conn, roster, &m.message_id)?) } else { Value::Null },
        }))
    }
    fn participant_views(&self, conn: &Connection, roster: &Roster) -> Result<Vec<Value>, Error> {
        roster
            .participants
            .iter()
            .map(|p| {
                let mut v = serde_json::to_value(p)?;
                v["label"] = json!(self.label(conn, p)?);
                v["local"] = json!(p.host_id.as_deref() == Some(self.identity().id.as_str()));
                Ok(v)
            })
            .collect()
    }
    fn last_message_at(messages: &[Stored]) -> Value {
        messages
            .iter()
            .map(|s| s.message.sent_at.clone())
            .max()
            .map(Value::from)
            .unwrap_or(Value::Null)
    }
    fn conversation_view(
        &self,
        conn: &Connection,
        roster: &Roster,
        reader: &str,
    ) -> Result<Value, Error> {
        let messages = self.visible(conn, &roster.conversation_id, reader)?;
        Ok(json!({
            "conversation_id": roster.conversation_id,
            "title": roster.title,
            "state": roster.state,
            "home_host_id": roster.home_host_id,
            "roster_version": roster.version,
            "created_by": roster.created_by,
            "created_at": roster.created_at,
            "participants": self.participant_views(conn, roster)?,
            "last_message_at": Self::last_message_at(&messages),
        }))
    }

    /// `GET /v1/conversations`.
    pub fn conversations(&self, all: bool) -> Result<Value, Error> {
        let conn = self.connection()?;
        let own = self.identity().id;
        let rosters: Vec<Roster> = {
            let mut statement = conn.prepare("SELECT record FROM conversations")?;
            let rows = statement
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().map(json).collect::<Result<_, _>>()?
        };
        let mut items = Vec::new();
        for roster in rosters {
            if !all && roster.state != "open" {
                continue;
            }
            if !roster
                .participants
                .iter()
                .any(|p| p.host_id.as_deref() == Some(own.as_str()) && p.state == "joined")
            {
                continue;
            }
            let last: Option<String> = conn.query_row(
                "SELECT MAX(json_extract(record, '$.message.sent_at')) FROM conversation_messages WHERE conversation_id = ?1",
                [&roster.conversation_id],
                |r| r.get(0),
            )?;
            let participants = roster
                .participants
                .iter()
                .map(|p| {
                    Ok(json!({
                        "id": p.id,
                        "label": self.label(&conn, p)?,
                        "kind": p.kind,
                        "state": p.state,
                        "local": p.host_id.as_deref() == Some(own.as_str()),
                    }))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let activity = last.clone().unwrap_or_else(|| roster.created_at.clone());
            items.push((
                activity,
                json!({
                    "conversation_id": roster.conversation_id,
                    "title": roster.title,
                    "state": roster.state,
                    "home_host_id": roster.home_host_id,
                    "participants": participants,
                    "created_at": roster.created_at,
                    "last_message_at": last,
                }),
            ));
        }
        items.sort_by(|a, b| {
            crate::membership::time(&b.0)
                .ok()
                .cmp(&crate::membership::time(&a.0).ok())
        });
        Ok(json!({ "conversations": items.into_iter().map(|(_, v)| v).collect::<Vec<_>>() }))
    }
    /// `GET /v1/conversations/{id}`.
    pub fn conversation(&self, id: &str, participant: Option<String>) -> Result<Value, Error> {
        let conn = self.connection()?;
        let roster = self.roster(&conn, id)?;
        let reader = self.reader(&conn, &roster, participant)?;
        self.conversation_view(&conn, &roster, &reader)
    }
    /// `GET /v1/conversations/{id}/messages`.
    pub fn conversation_messages(
        &self,
        id: &str,
        participant: Option<String>,
        before: Option<String>,
        limit: Option<i64>,
    ) -> Result<Value, Error> {
        let limit = limit.unwrap_or(20);
        if !(1..=100).contains(&limit) {
            return Err(invalid("limit must be 1 to 100"));
        }
        let conn = self.connection()?;
        let roster = self.roster(&conn, id)?;
        let reader = self.reader(&conn, &roster, participant)?;
        let messages = self.visible(&conn, id, &reader)?;
        let end = match &before {
            None => messages.len(),
            Some(before) => messages
                .iter()
                .position(|s| &s.message.message_id == before)
                .ok_or_else(|| invalid("unknown before message"))?,
        };
        let start = end.saturating_sub(limit as usize);
        let page = messages[start..end]
            .iter()
            .map(|s| self.message_view(&conn, &roster, s, &reader))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "messages": page,
            "next_before_message_id": if start > 0 { Value::from(messages[start].message.message_id.clone()) } else { Value::Null },
        }))
    }

    /// Persists a new conversation with the person as creator and the
    /// target agent `inviting`, and the invite to send.
    fn create_conversation(
        &self,
        target: &crate::directory::Candidate,
        given: &str,
        title: Option<String>,
    ) -> Result<(String, String), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let creator = self.person_participant(&tx)?;
        let own = self.identity().id;
        let id = new_id("conv")?;
        let at = now();
        let person = self.conversation_person(&tx)?;
        let target_person = crate::adapter::sender_person(self, &tx, &target.host_id)?.0;
        let participant = format!("agent:{}/{}", target.host_id, target.agent_id);
        let roster = Roster {
            conversation_id: id.clone(),
            home_host_id: own.clone(),
            version: 1,
            title,
            state: "open".into(),
            created_by: creator.clone(),
            created_at: at.clone(),
            participants: vec![
                Participant {
                    id: Some(creator.clone()),
                    kind: "person".into(),
                    host_id: Some(own),
                    person_id: person,
                    agent_id: None,
                    name: None,
                    state: "joined".into(),
                    added_by: None,
                    added_at: at.clone(),
                },
                Participant {
                    id: Some(participant.clone()),
                    kind: "agent".into(),
                    host_id: Some(target.host_id.clone()),
                    person_id: target_person,
                    agent_id: Some(target.agent_id.clone()),
                    name: Some(target.name.clone()),
                    state: "inviting".into(),
                    added_by: Some(creator.clone()),
                    added_at: at.clone(),
                },
            ],
            departed: vec![],
        };
        save_roster(&tx, &roster)?;
        let invite = Invite {
            target: given.into(),
            participant: participant.clone(),
            agent_id: target.agent_id.clone(),
            adder: creator,
            state: "sending".into(),
            code: None,
            error: None,
            attempts: 0,
            next_attempt_at: Some(later(10)),
        };
        tx.execute(
            "INSERT INTO conversation_roster_outbound (conversation_id, peer, kind, record) VALUES (?1, ?2, ?3, ?4)",
            params![id, target.host_id, format!("invite:{}", target.agent_id), serde_json::to_string(&invite)?],
        )?;
        tx.commit()?;
        Ok((id, participant))
    }
    fn invite_record(
        &self,
        conn: &Connection,
        id: &str,
        participant: &str,
    ) -> Result<Invite, Error> {
        let (_, host, agent) = participant_parts(participant).ok_or(Error::NotFound)?;
        let text: String = conn.query_row(
            "SELECT record FROM conversation_roster_outbound WHERE conversation_id = ?1 AND peer = ?2 AND kind = ?3",
            params![id, host, format!("invite:{agent}")],
            |r| r.get(0),
        )?;
        json(text)
    }
    fn invite_outcome(
        &self,
        conn: &Connection,
        roster: &Roster,
        invite: &Invite,
    ) -> Result<Value, Error> {
        let state = match &invite.state[..] {
            "sending" => "inviting",
            other => other,
        };
        Ok(json!({
            "target": invite.target,
            "participant": invite.participant,
            "label": self.label_of(conn, roster, &invite.participant)?,
            "state": state,
            "code": invite.code,
            "error": invite.error,
        }))
    }

    /// The citation a request for `agent` on `peer` carries, chosen now:
    /// the directory's choice, else self access or the owner's newest
    /// policy; `None` when this host holds nothing to cite.
    fn conversation_citation(
        &self,
        conn: &Connection,
        peer: &str,
        agent: &str,
        origin: Option<&str>,
    ) -> Result<Option<RequestAuthorization>, Error> {
        if let Some(choice) = self.cached_choice(peer, agent, crate::policy::ACTION, origin)?
            && let Ok(cited) = self.chosen_citation(conn, peer, &choice)
        {
            return Ok(Some(cited));
        }
        match self.citation(conn, peer) {
            Ok(cited) => {
                let (policy, self_access) = cited.fields();
                Ok(Some((None, policy, self_access)))
            }
            Err(Error::Invalid(_) | Error::NotFound | Error::Forbidden) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The invite request for its next attempt, or `None` when it is no
    /// longer due; a target this host cannot cite anything for is refused.
    fn prepare_invite(
        &self,
        id: &str,
        participant: &str,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let invite = self.invite_record(&tx, id, participant)?;
        if invite.state != "sending" {
            return Ok(None);
        }
        let roster = self.roster(&tx, id)?;
        let (_, host, _) = participant_parts(participant).ok_or(Error::NotFound)?;
        let host = host.to_owned();
        let origin = participant_parts(&invite.adder)
            .filter(|(kind, _, _)| *kind == "agent")
            .map(|(_, _, agent)| agent.to_owned());
        let Some((grant_id, policy, self_access)) =
            self.conversation_citation(&tx, &host, &invite.agent_id, origin.as_deref())?
        else {
            self.settle_invite(
                &tx,
                id,
                participant,
                Err((
                    "refused",
                    "not_authorized",
                    "no current authorization lets this host reach it".into(),
                )),
            )?;
            tx.commit()?;
            return Ok(None);
        };
        let mut next = roster.clone();
        next.version += 1;
        for p in &mut next.participants {
            if p.id.as_deref() == Some(participant) {
                p.state = "joined".into();
            }
        }
        let request = InviteRequest {
            conversation_id: id.into(),
            roster: next,
            target: InviteTarget {
                kind: "agent".into(),
                agent_id: Some(invite.agent_id.clone()),
                person_id: None,
            },
            adder: invite.adder.clone(),
            note: None,
            origin: origin.map(|agent_id| Origin {
                agent_id,
                session_id: None,
            }),
            grant_id,
            policy,
            self_access,
        };
        Ok(Some((host, serde_json::to_vec(&request)?)))
    }
    /// Records an invite's outcome: `Ok(name)` joins the target with that
    /// name; a final refusal removes it; anything else schedules a retry.
    fn settle_invite(
        &self,
        tx: &Transaction<'_>,
        id: &str,
        participant: &str,
        outcome: Result<String, (&'static str, &'static str, String)>,
    ) -> Result<(), Error> {
        let mut invite = self.invite_record(tx, id, participant)?;
        if invite.state != "sending" {
            return Ok(());
        }
        let mut roster = self.roster(tx, id)?;
        match outcome {
            Ok(name) => {
                invite.state = "joined".into();
                invite.next_attempt_at = None;
                invite.code = None;
                invite.error = None;
                roster.version += 1;
                for p in &mut roster.participants {
                    if p.id.as_deref() == Some(participant) {
                        p.state = "joined".into();
                        p.name = Some(name.clone());
                    }
                }
                save_roster(tx, &roster)?;
            }
            Err((state @ ("refused" | "unsupported"), code, error)) => {
                invite.state = state.into();
                invite.code = Some(code.into());
                invite.error = Some(error);
                invite.next_attempt_at = None;
                roster.version += 1;
                roster
                    .participants
                    .retain(|p| p.id.as_deref() != Some(participant));
                save_roster(tx, &roster)?;
            }
            Err((_, _, error)) => {
                invite.error = Some(error);
                invite.next_attempt_at = Some(rfc3339(
                    crate::clock::now() + backoff(invite.attempts.max(1), jitter()),
                ));
            }
        }
        let (_, host, agent) = participant_parts(participant).ok_or(Error::NotFound)?;
        tx.execute(
            "UPDATE conversation_roster_outbound SET record = ?1 WHERE conversation_id = ?2 AND peer = ?3 AND kind = ?4",
            params![serde_json::to_string(&invite)?, id, host, format!("invite:{agent}")],
        )?;
        Ok(())
    }
    fn finish_invite(&self, id: &str, participant: &str, outcome: Outcome) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        {
            let mut invite = self.invite_record(&tx, id, participant)?;
            invite.attempts += 1;
            let (_, host, agent) = participant_parts(participant).ok_or(Error::NotFound)?;
            tx.execute(
                "UPDATE conversation_roster_outbound SET record = ?1 WHERE conversation_id = ?2 AND peer = ?3 AND kind = ?4",
                params![serde_json::to_string(&invite)?, id, host, format!("invite:{agent}")],
            )?;
        }
        let settled = match outcome {
            Outcome::Answer(body) => match serde_json::from_slice::<Value>(&body) {
                Ok(v) if v["state"] == "joined" && v["name"].is_string() => {
                    Ok(v["name"].as_str().unwrap_or_default().to_owned())
                }
                _ => Err(("sending", "", "invalid invite answer".to_owned())),
            },
            Outcome::Final(state, code, error) => Err((state, code, error)),
            Outcome::Retry(error) => Err(("sending", "", error)),
        };
        self.settle_invite(&tx, id, participant, settled)?;
        tx.commit()?;
        Ok(())
    }

    /// Authors a message as `author` (a joined local participant), or
    /// returns the stored one for an identical repeat. Returns the message
    /// view and its targets, and the keys of new target records.
    fn author_message(
        &self,
        id: &str,
        author: &str,
        origin: Option<Origin>,
        message_id: Option<String>,
        content: String,
    ) -> Result<(Value, Vec<String>), Error> {
        if !valid_content(&content) {
            return Err(invalid("content must be 1 to 65,536 bytes of UTF-8"));
        }
        let message_id = match message_id {
            Some(m) if valid_message_id(&m) => m,
            Some(_) => return Err(invalid("invalid message_id")),
            None => new_id("cmsg")?,
        };
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let roster = self.roster(&tx, id)?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT conversation_id, record FROM conversation_messages WHERE message_id = ?1",
                [&message_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((conversation, record)) = existing {
            let stored: Stored = json(record)?;
            if conversation != id
                || stored.message.author != author
                || stored.message.content != content
            {
                return Err(coded_error(
                    409,
                    "conflict",
                    "This message_id was already used with different content.",
                ));
            }
            let view = self.message_view(&tx, &roster, &stored, author)?;
            let targets = view["targets"].clone();
            return Ok((json!({"message": view, "targets": targets}), vec![]));
        }
        if roster.joined(author).is_none() {
            return Err(not_participant());
        }
        let (seq, clock, local_seq): (i64, i64, i64) = tx.query_row(
            "SELECT (SELECT COALESCE(MAX(seq), 0) + 1 FROM conversation_messages WHERE conversation_id = ?1 AND author = ?2), (SELECT COALESCE(MAX(clock), 0) + 1 FROM conversation_messages WHERE conversation_id = ?1), (SELECT COALESCE(MAX(local_seq), 0) + 1 FROM conversation_messages)",
            params![id, author],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let at = now();
        let message = Message {
            message_id: message_id.clone(),
            conversation_id: id.into(),
            author: author.into(),
            seq,
            clock,
            roster_version: roster.version,
            sent_at: at.clone(),
            content,
            addressed_to: None,
            origin,
        };
        let stored = Stored {
            message,
            received_at: at,
            sender_host: self.identity().id,
        };
        tx.execute(
            "INSERT INTO conversation_messages (conversation_id, message_id, author, seq, clock, local_seq, record) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, message_id, author, seq, clock, local_seq, serde_json::to_string(&stored)?],
        )?;
        let mut keys = Vec::new();
        for p in &roster.participants {
            let Some(target) = p.id.as_deref() else {
                continue;
            };
            if p.state != "joined" || target == author {
                continue;
            }
            let peer = p.host_id.clone().unwrap_or_default();
            let prev: Option<i64> = tx.query_row(
                "SELECT MAX(m.seq) FROM conversation_messages m JOIN conversation_targets t ON t.conversation_id = m.conversation_id AND t.message_id = m.message_id WHERE m.conversation_id = ?1 AND m.author = ?2 AND t.direction = 'out' AND t.target = ?3 AND m.seq < ?4",
                params![id, author, target, seq],
                |r| r.get(0),
            )?;
            let record = Outbound {
                participant: target.into(),
                state: "sending".into(),
                code: None,
                error: None,
                attempts: 0,
                next_attempt_at: Some(later(10)),
            };
            tx.execute(
                "INSERT INTO conversation_targets (conversation_id, message_id, target, direction, peer, prev_seq, state, next_attempt_at, record) VALUES (?1, ?2, ?3, 'out', ?4, ?5, 'sending', ?6, ?7)",
                params![id, message_id, target, peer, prev, record.next_attempt_at, serde_json::to_string(&record)?],
            )?;
            keys.push(format!("{id} {message_id} {target}"));
        }
        let view = self.message_view(&tx, &roster, &stored, author)?;
        tx.commit()?;
        let targets = view["targets"].clone();
        Ok((json!({"message": view, "targets": targets}), keys))
    }
    fn outbound_record(
        &self,
        conn: &Connection,
        id: &str,
        message: &str,
        target: &str,
    ) -> Result<(Outbound, Option<i64>), Error> {
        let (record, prev): (String, Option<i64>) = conn.query_row(
            "SELECT record, prev_seq FROM conversation_targets WHERE conversation_id = ?1 AND message_id = ?2 AND target = ?3 AND direction = 'out'",
            params![id, message, target],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((json(record)?, prev))
    }
    fn save_outbound(
        &self,
        conn: &Connection,
        id: &str,
        message: &str,
        o: &Outbound,
    ) -> Result<(), Error> {
        conn.execute(
            "UPDATE conversation_targets SET state = ?1, next_attempt_at = ?2, record = ?3 WHERE conversation_id = ?4 AND message_id = ?5 AND target = ?6 AND direction = 'out'",
            params![o.state, o.next_attempt_at, serde_json::to_string(o)?, id, message, o.participant],
        )?;
        Ok(())
    }
    /// The request for a target's next attempt, or `None` when it is no
    /// longer due or was refused here for lack of anything to cite.
    fn prepare_target(
        &self,
        id: &str,
        message: &str,
        target: &str,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (mut out, prev_seq) = self.outbound_record(&tx, id, message, target)?;
        if out.state != "sending" {
            return Ok(None);
        }
        let stored: Stored = json(tx.query_row(
            "SELECT record FROM conversation_messages WHERE conversation_id = ?1 AND message_id = ?2",
            params![id, message],
            |r| r.get::<_, String>(0),
        )?)?;
        let (kind, host, local) = participant_parts(target).ok_or(Error::NotFound)?;
        let host = host.to_owned();
        let (grant_id, policy, self_access) = if kind == "agent" {
            let origin = stored.message.origin.as_ref().map(|o| o.agent_id.clone());
            match self.conversation_citation(&tx, &host, local, origin.as_deref())? {
                Some(cited) => cited,
                None => {
                    out.state = "refused".into();
                    out.code = Some("not_authorized".into());
                    out.error = Some("no current authorization lets this host reach it".into());
                    out.next_attempt_at = None;
                    self.save_outbound(&tx, id, message, &out)?;
                    tx.commit()?;
                    return Ok(None);
                }
            }
        } else {
            (None, None, None)
        };
        let request = MessageRequest {
            message: stored.message,
            target: target.into(),
            prev_seq,
            grant_id,
            policy,
            self_access,
        };
        Ok(Some((host, serde_json::to_vec(&request)?)))
    }
    fn finish_target(
        &self,
        id: &str,
        message: &str,
        target: &str,
        peer: &str,
        outcome: Outcome,
    ) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (mut out, _) = self.outbound_record(&tx, id, message, target)?;
        if out.state != "sending" {
            return Ok(());
        }
        out.attempts += 1;
        let result = match outcome {
            Outcome::Answer(body) => match serde_json::from_slice::<Receipt>(&body) {
                Ok(r)
                    if r.message_id == message
                        && r.target == target
                        && r.receiver_host_id == peer =>
                {
                    Ok(())
                }
                _ => Err(Outcome::Retry("invalid peer receipt".into())),
            },
            other => Err(other),
        };
        match result {
            Ok(()) => {
                out.state = "delivered".into();
                out.code = None;
                out.error = None;
                out.next_attempt_at = None;
            }
            Err(Outcome::Final(state, code, error)) => {
                out.state = state.into();
                out.code = Some(code.into());
                out.error = Some(error);
                out.next_attempt_at = None;
            }
            Err(Outcome::Retry(error)) => {
                out.error = Some(error);
                out.next_attempt_at = Some(rfc3339(
                    crate::clock::now() + backoff(out.attempts, jitter()),
                ));
            }
            Err(Outcome::Answer(_)) => {
                out.error = Some("invalid peer answer".into());
                out.next_attempt_at = Some(rfc3339(
                    crate::clock::now() + backoff(out.attempts, jitter()),
                ));
            }
        }
        self.save_outbound(&tx, id, message, &out)?;
        tx.commit()?;
        Ok(())
    }

    /// `POST /peer/v1/conversations/invites`.
    pub fn accept_invite(&self, sender: &str, r: InviteRequest) -> Result<Value, Error> {
        let own = self.identity().id;
        let agent = match (&r.target.kind[..], &r.target.agent_id, &r.target.person_id) {
            ("agent", Some(agent), None) if valid_id(agent, "agent", 16) => agent.clone(),
            _ => return Err(invalid("invalid invite target")),
        };
        let participant = format!("agent:{own}/{agent}");
        let cited = one_authorization(
            r.grant_id.as_deref(),
            r.policy.as_ref(),
            r.self_access.as_ref(),
        );
        if !valid_conversation_id(&r.conversation_id)
            || r.roster.conversation_id != r.conversation_id
            || r.roster.home_host_id != sender
            || r.roster.version < 1
            || !consistent(&r.roster)
            || r.roster.joined(&participant).is_none()
            || !cited
            || r.note.as_ref().is_some_and(|n| n.len() > MAX_NOTE)
            || r.roster.title.as_deref().is_some_and(|t| !valid_title(t))
            || participant_parts(&r.adder).is_none()
            || r.origin.as_ref().is_some_and(|o| !o.valid())
        {
            return Err(invalid("invalid invite"));
        }
        let (adder_kind, adder_host, adder_local) =
            participant_parts(&r.adder).ok_or_else(|| invalid("invalid adder"))?;
        let origin_ok = match (&r.origin, adder_kind) {
            (Some(o), "agent") => o.agent_id == adder_local,
            (None, "person") => true,
            _ => false,
        };
        if !origin_ok {
            return Err(invalid("origin must name an agent adder"));
        }
        if adder_host != sender || r.roster.joined(&r.adder).is_none() {
            return Err(Error::Forbidden);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let name: Option<String> = tx
            .query_row("SELECT name FROM agents WHERE id = ?1", [&agent], |row| {
                row.get(0)
            })
            .optional()?;
        let Some(name) = name else {
            return Err(Error::Forbidden);
        };
        self.conversation_authorize(
            &tx,
            sender,
            (
                r.grant_id.as_deref(),
                r.policy.as_ref(),
                r.self_access.as_ref(),
            ),
            &agent,
            0,
            r.origin.as_ref(),
        )?;
        let held = table_roster(&tx, &r.conversation_id)?;
        if let Some(held) = &held
            && held.home_host_id != sender
        {
            return Err(Error::Forbidden);
        }
        if held.as_ref().is_none_or(|h| h.version < r.roster.version) {
            save_roster(&tx, &r.roster)?;
        }
        tx.commit()?;
        Ok(json!({"state": "joined", "name": name}))
    }

    /// Accepts when the cited authorization, self access, or this host's
    /// owner's current policy allows `message.append`; 503 only when the
    /// cited policy is newer than this host holds.
    fn conversation_authorize(
        &self,
        conn: &Connection,
        sender: &str,
        cited: (Option<&str>, Option<&PolicyRef>, Option<&SelfRef>),
        agent: &str,
        size: usize,
        origin: Option<&Origin>,
    ) -> Result<(), Error> {
        let deadline = now();
        let check =
            |grant_id: Option<&str>, policy: Option<&PolicyRef>, self_access: Option<&SelfRef>| {
                let authz = Authz {
                    action: crate::policy::ACTION,
                    grant_id,
                    policy,
                    self_access,
                    target_agent_id: agent,
                    deadline: &deadline,
                    size,
                    origin,
                    artifacts: None,
                };
                self.message_authority(conn, sender, &authz, false)
            };
        // A receiver behind the cited policy version answers 503 before
        // anything else, so an older version never decides.
        match check(cited.0, cited.1, cited.2) {
            Ok(_) => return Ok(()),
            Err(Error::Forbidden) => {}
            Err(e) => return Err(e),
        }
        if let (Some(person), _) = crate::adapter::sender_person(self, conn, sender)? {
            let s = SelfRef { person_id: person };
            if check(None, None, Some(&s)).is_ok() {
                return Ok(());
            }
        }
        if let Some(own) = self.conversation_person(conn)? {
            let p = PolicyRef {
                person_id: own,
                version: 1,
            };
            if check(None, Some(&p), None).is_ok() {
                return Ok(());
            }
        }
        let grants: Vec<String> = {
            let mut statement = conn.prepare(
                "SELECT id FROM grants WHERE json_extract(record, '$.requester_host_id') = ?1 AND json_extract(record, '$.target_agent_id') = ?2 ORDER BY id",
            )?;
            statement
                .query_map(params![sender, agent], |r| r.get::<_, String>(0))?
                .collect::<Result<_, _>>()?
        };
        if grants
            .iter()
            .any(|g| check(Some(g.as_str()), None, None).is_ok())
        {
            return Ok(());
        }
        Err(Error::Forbidden)
    }

    /// `POST /peer/v1/conversations/{id}/messages`.
    pub fn accept_conversation_message(
        &self,
        sender: &str,
        id: &str,
        r: MessageRequest,
    ) -> Result<Receipt, Error> {
        let own = self.identity().id;
        let m = &r.message;
        let target = participant_parts(&r.target);
        let author = participant_parts(&m.author);
        let cited = (
            r.grant_id.as_deref(),
            r.policy.as_ref(),
            r.self_access.as_ref(),
        );
        let citation_ok = match target {
            Some(("agent", _, _)) => one_authorization(cited.0, cited.1, cited.2),
            Some(_) => cited == (None, None, None),
            None => false,
        };
        let origin_ok = match (author, &m.origin) {
            (Some(("agent", _, agent)), Some(o)) => o.valid() && o.agent_id == agent,
            (Some(("person", _, _)), None) => true,
            _ => false,
        };
        if m.conversation_id != id
            || !valid_conversation_id(id)
            || !valid_message_id(&m.message_id)
            || author.is_none()
            || !citation_ok
            || !origin_ok
            || m.seq < 1
            || m.clock < 1
            || m.roster_version < 1
            || r.prev_seq.is_some_and(|p| p < 1 || p >= m.seq)
            || !valid_content(&m.content)
            || chrono::DateTime::parse_from_rfc3339(&m.sent_at).is_err()
            || m.addressed_to.as_ref().is_some_and(|a| {
                a.is_empty() || a.len() > 16 || a.iter().any(|p| participant_parts(p).is_none())
            })
        {
            return Err(invalid("invalid conversation message"));
        }
        // Both parse: the shape check above refuses either missing.
        let (Some((_, author_host, _)), Some((target_kind, target_host, target_local))) =
            (author, target)
        else {
            return Err(invalid("invalid conversation message"));
        };
        if author_host != sender {
            return Err(Error::Forbidden);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT record FROM conversation_targets WHERE conversation_id = ?1 AND message_id = ?2 AND target = ?3 AND direction = 'in' AND peer = ?4",
                params![id, m.message_id, r.target, sender],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            let previous: Inbound = json(previous)?;
            if previous.message == *m
                && previous.target == r.target
                && previous.prev_seq == r.prev_seq
            {
                return Ok(previous.receipt);
            }
            return Err(Error::Conflict(
                "message ID reused with different fields".into(),
            ));
        }
        let Some(roster) = table_roster(&tx, id)? else {
            return Err(unavailable(
                "this host does not hold that conversation's roster",
            ));
        };
        if m.roster_version > roster.version {
            return Err(unavailable("this host holds an older roster"));
        }
        if target_host != own
            || roster.joined(&r.target).is_none()
            || roster.joined(&m.author).is_none()
        {
            return Err(not_participant());
        }
        if target_kind == "agent" {
            self.conversation_authorize(
                &tx,
                sender,
                cited,
                target_local,
                m.content.len(),
                m.origin.as_ref(),
            )?;
        } else {
            let person = self.conversation_person(&tx)?;
            if person.as_deref() != Some(target_local)
                || self.product_members_of(&tx, sender)?.is_empty()
                || self.blocked(&tx, sender)?
            {
                return Err(Error::Forbidden);
            }
        }
        let held: Option<String> = tx
            .query_row(
                "SELECT record FROM conversation_messages WHERE message_id = ?1",
                [&m.message_id],
                |row| row.get(0),
            )
            .optional()?;
        let at = now();
        match held {
            Some(held) => {
                let held: Stored = json(held)?;
                if held.message != *m || held.sender_host != sender {
                    return Err(Error::Conflict(
                        "message ID reused with different fields".into(),
                    ));
                }
            }
            None => {
                let local_seq: i64 = tx.query_row(
                    "SELECT COALESCE(MAX(local_seq), 0) + 1 FROM conversation_messages",
                    [],
                    |row| row.get(0),
                )?;
                let stored = Stored {
                    message: m.clone(),
                    received_at: at.clone(),
                    sender_host: sender.into(),
                };
                let inserted = tx.execute(
                    "INSERT INTO conversation_messages (conversation_id, message_id, author, seq, clock, local_seq, record) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id, m.message_id, m.author, m.seq, m.clock, local_seq, serde_json::to_string(&stored)?],
                );
                match inserted {
                    Ok(_) => {}
                    Err(rusqlite::Error::SqliteFailure(e, _))
                        if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        return Err(Error::Conflict("author sequence number reused".into()));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let receipt = Receipt {
            message_id: m.message_id.clone(),
            target: r.target.clone(),
            receiver_host_id: own,
            accepted_at: at.clone(),
        };
        let inbound = Inbound {
            message: m.clone(),
            target: r.target.clone(),
            prev_seq: r.prev_seq,
            receipt: receipt.clone(),
        };
        tx.execute(
            "INSERT INTO conversation_targets (conversation_id, message_id, target, direction, peer, prev_seq, state, next_attempt_at, record) VALUES (?1, ?2, ?3, 'in', ?4, ?5, 'accepted', NULL, ?6)",
            params![id, m.message_id, r.target, sender, r.prev_seq, serde_json::to_string(&inbound)?],
        )?;
        if target_kind == "agent" {
            let notification = Notification {
                id: new_id("cnot")?,
                kind: "message".into(),
                conversation_id: id.into(),
                message_id: Some(m.message_id.clone()),
                session_id: None,
                created_at: at,
                claimed_at: None,
                forwarded_at: None,
            };
            tx.execute(
                "INSERT INTO conversation_notifications (id, conversation_id, kind, message_id, agent_id, session_id, record) VALUES (?1, ?2, 'message', ?3, ?4, NULL, ?5)",
                params![notification.id, id, m.message_id, target_local, serde_json::to_string(&notification)?],
            )?;
        }
        tx.commit()?;
        Ok(receipt)
    }

    /// `POST /adapter/v1/conversation-notifications/next`.
    pub fn claim_conversation_notification(
        &self,
        auth: &crate::adapter_connection::AdapterAuth,
    ) -> Result<Option<Value>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = verified_authority(&tx, auth)?;
        if !a.directory {
            return Ok(None);
        }
        let next: Option<(String, String)> = tx
            .query_row(
                "SELECT id, record FROM conversation_notifications WHERE agent_id = ?1 AND session_id IS NULL ORDER BY rowid LIMIT 1",
                [&ss.agent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((nid, record)) = next else {
            return Ok(None);
        };
        let mut n: Notification = json(record)?;
        let at = now();
        n.session_id = Some(ss.id.clone());
        n.claimed_at = Some(at);
        tx.execute(
            "UPDATE conversation_notifications SET session_id = ?1, record = ?2 WHERE id = ?3",
            params![ss.id, serde_json::to_string(&n)?, nid],
        )?;
        let roster = self.roster(&tx, &n.conversation_id)?;
        let me = format!("agent:{}/{}", self.identity().id, ss.agent_id);
        let visible = self.visible(&tx, &n.conversation_id, &me)?;
        let position = visible
            .iter()
            .position(|s| Some(&s.message.message_id) == n.message_id.as_ref());
        let first: bool = !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversation_notifications WHERE conversation_id = ?1 AND session_id = ?2 AND id != ?3)",
            params![n.conversation_id, ss.id, nid],
            |r| r.get::<_, bool>(0),
        )?;
        let mut messages = Vec::new();
        let mut window = Vec::new();
        let mut window_total = 0;
        if let Some(position) = position {
            messages.push(self.adapter_message(&tx, &roster, &visible[position], &me, None)?);
            if first {
                window_total = position;
                let mut bytes = 0;
                for s in visible[..position].iter().rev() {
                    let length = cut(&s.message.content, WINDOW_CUT).len();
                    if window.len() == WINDOW_MESSAGES || bytes + length > WINDOW_BYTES {
                        break;
                    }
                    bytes += length;
                    window.push(self.adapter_message(&tx, &roster, s, &me, Some(WINDOW_CUT))?);
                }
                window.reverse();
            }
        }
        let summary = self.agent_summary(&tx, &roster, &me)?;
        tx.commit()?;
        Ok(Some(json!({
            "notification": n,
            "conversation": summary,
            "messages": messages,
            "window": window,
            "window_total": window_total,
            "redelivered": false,
        })))
    }
    fn adapter_message(
        &self,
        conn: &Connection,
        roster: &Roster,
        stored: &Stored,
        me: &str,
        limit: Option<usize>,
    ) -> Result<Value, Error> {
        let m = &stored.message;
        let host = participant_parts(&m.author)
            .map(|p| p.1)
            .unwrap_or_default();
        let (person_id, person) = crate::adapter::sender_person(self, conn, host)?;
        let addressed_to = m.addressed_to.clone().unwrap_or_default();
        let mut view = json!({
            "message_id": m.message_id,
            "author": m.author,
            "author_label": self.label_of(conn, roster, &m.author)?,
            "author_kind": Self::author_kind(&m.author),
            "origin_agent_id": m.origin.as_ref().map(|o| o.agent_id.clone()),
            "sender_person_id": person_id,
            "sender_person": person,
            "seq": m.seq,
            "clock": m.clock,
            "sent_at": m.sent_at,
            "received_at": stored.received_at,
            "content": m.content,
            "addressed": addressed_to.is_empty() || addressed_to.iter().any(|a| a == me),
            "addressed_to": addressed_to,
            "mine": m.author == me,
        });
        if let Some(limit) = limit {
            let short = cut(&m.content, limit);
            view["truncated"] = json!(short.len() < m.content.len());
            if short.len() < m.content.len() {
                view["content_bytes"] = json!(m.content.len());
                view["content"] = json!(short);
            }
        }
        Ok(view)
    }
    fn agent_summary(&self, conn: &Connection, roster: &Roster, me: &str) -> Result<Value, Error> {
        let agent = participant_parts(me).map(|p| p.2).unwrap_or_default();
        let unseen: i64 = conn.query_row(
            "SELECT COUNT(*) FROM conversation_notifications WHERE conversation_id = ?1 AND agent_id = ?2 AND kind = 'message' AND json_extract(record, '$.forwarded_at') IS NULL",
            params![roster.conversation_id, agent],
            |r| r.get(0),
        )?;
        let visible = self.visible(conn, &roster.conversation_id, me)?;
        let participants = roster
            .participants
            .iter()
            .map(|p| {
                Ok(json!({
                    "id": p.id,
                    "label": self.label(conn, p)?,
                    "kind": p.kind,
                    "state": p.state,
                    "you": p.id.as_deref() == Some(me),
                }))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(json!({
            "conversation_id": roster.conversation_id,
            "title": roster.title,
            "state": roster.state,
            "home_host_id": roster.home_host_id,
            "participants": participants,
            "unseen": unseen,
            "last_message_at": Self::last_message_at(&visible),
            "creator": roster.created_by == me,
        }))
    }
    /// `POST /adapter/v1/conversation-notifications/{id}/forwarded`.
    pub fn conversation_forwarded(
        &self,
        auth: &crate::adapter_connection::AdapterAuth,
        id: &str,
    ) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (_, ss) = authority(&tx, auth)?;
        let record: Option<String> = tx
            .query_row(
                "SELECT record FROM conversation_notifications WHERE id = ?1 AND agent_id = ?2",
                params![id, ss.agent_id],
                |r| r.get(0),
            )
            .optional()?;
        let mut n: Notification = json(record.ok_or(Error::NotFound)?)?;
        if n.forwarded_at.is_none() {
            n.forwarded_at = Some(now());
            tx.execute(
                "UPDATE conversation_notifications SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&n)?, id],
            )?;
        }
        tx.commit()?;
        Ok(json!({ "notification": n }))
    }
    /// The adapter's author participant and origin, once directory access
    /// is established.
    fn adapter_author(
        &self,
        auth: &crate::adapter_connection::AdapterAuth,
    ) -> Result<(String, Origin), Error> {
        let conn = self.connection()?;
        let (a, ss) = authority(&conn, auth)?;
        crate::directory::directory_access(&a)?;
        Ok((
            format!("agent:{}/{}", self.identity().id, ss.agent_id),
            Origin {
                agent_id: ss.agent_id.clone(),
                session_id: Some(ss.id.clone()),
            },
        ))
    }

    fn due_conversation_attempts(
        &self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(String, String)>, Error> {
        let conn = self.connection()?;
        let mut due = Vec::new();
        {
            let mut statement = conn.prepare(
                "SELECT conversation_id, message_id, target, next_attempt_at FROM conversation_targets WHERE direction = 'out' AND state = 'sending'",
            )?;
            let rows = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (c, m, t, next) in rows {
                if let Some(when) = due_at(&next).filter(|w| *w <= at) {
                    due.push((when, "target".to_owned(), format!("{c} {m} {t}")));
                }
            }
        }
        {
            let mut statement = conn.prepare(
                "SELECT conversation_id, record FROM conversation_roster_outbound WHERE kind LIKE 'invite:%'",
            )?;
            let rows = statement
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            for (c, record) in rows {
                let invite: Invite = json(record)?;
                if invite.state != "sending" {
                    continue;
                }
                if let Some(when) = due_at(&invite.next_attempt_at).filter(|w| *w <= at) {
                    due.push((
                        when,
                        "invite".to_owned(),
                        format!("{c} {}", invite.participant),
                    ));
                }
            }
        }
        due.sort();
        Ok(due.into_iter().map(|(_, kind, key)| (kind, key)).collect())
    }
    /// At startup, spreads overdue attempts over the next 10 seconds.
    fn spread_conversation_attempts(&self, at: chrono::DateTime<chrono::Utc>) -> Result<(), Error> {
        let due = self.due_conversation_attempts(at)?;
        let count = due.len() as i64;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        for (index, (kind, key)) in due.iter().enumerate() {
            let when = rfc3339(
                at + chrono::TimeDelta::milliseconds(
                    crate::retry::RESTART_SPREAD_MS * index as i64 / count,
                ),
            );
            let parts: Vec<&str> = key.split(' ').collect();
            if kind == "target" {
                let (mut out, _) = self.outbound_record(&tx, parts[0], parts[1], parts[2])?;
                out.next_attempt_at = Some(when);
                self.save_outbound(&tx, parts[0], parts[1], &out)?;
            } else {
                let mut invite = self.invite_record(&tx, parts[0], parts[1])?;
                invite.next_attempt_at = Some(when);
                let (_, host, agent) = participant_parts(parts[1]).ok_or(Error::NotFound)?;
                tx.execute(
                    "UPDATE conversation_roster_outbound SET record = ?1 WHERE conversation_id = ?2 AND peer = ?3 AND kind = ?4",
                    params![serde_json::to_string(&invite)?, parts[0], host, format!("invite:{agent}")],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

// ---------------------------------------------------------------- attempts

fn dispatcher() -> &'static Dispatcher {
    static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();
    DISPATCHER.get_or_init(|| Dispatcher::new(crate::retry::CONCURRENCY))
}

async fn send(store: &Arc<Store>, peer: &str, path: &str, body: &[u8]) -> Outcome {
    let id = peer.to_owned();
    let target = match blocking(store.clone(), move |s| s.dial_target(&id)).await {
        Ok(t) => t,
        Err(e) => return Outcome::Retry(format!("{e:?}")),
    };
    match tokio::time::timeout(
        ATTEMPT_TIMEOUT,
        crate::quic::request(store.clone(), &target, "POST", path, body),
    )
    .await
    {
        Ok(Ok((status, body))) => classify(status, &body, peer),
        Ok(Err(e)) => Outcome::Retry(format!("{e:#}")),
        Err(_) => Outcome::Retry("timed out".into()),
    }
}

async fn attempt(store: Arc<Store>, kind: String, key: String) {
    let parts: Vec<String> = key.split(' ').map(str::to_owned).collect();
    if kind == "target" {
        let [id, message, target] = &parts[..] else {
            return;
        };
        let (i, m, t) = (id.clone(), message.clone(), target.clone());
        let Ok(Some((peer, body))) =
            blocking(store.clone(), move |s| s.prepare_target(&i, &m, &t)).await
        else {
            return;
        };
        let outcome = send(
            &store,
            &peer,
            &format!("/peer/v1/conversations/{id}/messages"),
            &body,
        )
        .await;
        let (i, m, t) = (id.clone(), message.clone(), target.clone());
        let _ = blocking(store, move |s| s.finish_target(&i, &m, &t, &peer, outcome)).await;
    } else {
        let [id, participant] = &parts[..] else {
            return;
        };
        let (i, p) = (id.clone(), participant.clone());
        let Ok(Some((peer, body))) =
            blocking(store.clone(), move |s| s.prepare_invite(&i, &p)).await
        else {
            return;
        };
        let outcome = send(&store, &peer, "/peer/v1/conversations/invites", &body).await;
        let (i, p) = (id.clone(), participant.clone());
        let _ = blocking(store, move |s| s.finish_invite(&i, &p, outcome)).await;
    }
}

/// Starts attempts for these keys now, within the shared concurrency bound;
/// one that finds no free slot is left to the worker.
fn dispatch(store: &Arc<Store>, keys: Vec<(String, String)>) -> Vec<tokio::task::JoinHandle<()>> {
    dispatcher()
        .claim(keys)
        .into_iter()
        .map(|claim| {
            let store = store.clone();
            let (kind, key) = claim.key().clone();
            tokio::spawn(async move {
                attempt(store, kind, key).await;
                drop(claim);
            })
        })
        .collect()
}

/// Runs conversation attempts (invites and message targets) until shutdown.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let _ = blocking(store.clone(), |s| {
        s.spread_conversation_attempts(crate::clock::now())
    })
    .await;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(crate::retry::POLL) => {}
        }
        let Ok(due) = blocking(store.clone(), |s| {
            s.due_conversation_attempts(crate::clock::now())
        })
        .await
        else {
            continue;
        };
        dispatch(&store, due);
    }
}

// ---------------------------------------------------------------- routes

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRequest {
    participants: Vec<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    title: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    content: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    message_id: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    network: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
    content: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    message_id: Option<String>,
}
#[derive(Deserialize)]
struct ListQuery {
    state: Option<String>,
}
#[derive(Deserialize)]
struct ReadQuery {
    participant: Option<String>,
}
#[derive(Deserialize)]
struct PageQuery {
    participant: Option<String>,
    before: Option<String>,
    limit: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/conversations", get(list).post(start))
        .route("/v1/conversations/{id}", get(show))
        .route("/v1/conversations/{id}/messages", get(page).post(say))
}
pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/peer/v1/conversations/invites", post(peer_invite))
        .route("/peer/v1/conversations/{id}/messages", post(peer_message))
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/conversations/{id}/messages", post(adapter_say))
        .route(
            "/adapter/v1/conversation-notifications/next",
            post(adapter_next),
        )
        .route(
            "/adapter/v1/conversation-notifications/{id}/forwarded",
            post(adapter_forwarded),
        )
}

async fn list(
    State(store): State<Arc<Store>>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| invalid("invalid query"))?;
    let all = match q.state.as_deref() {
        None | Some("open") => false,
        Some("all") => true,
        Some(_) => return Err(invalid("state must be open or all")),
    };
    Ok(Json(blocking(store, move |s| s.conversations(all)).await?))
}
async fn show(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    query: Result<Query<ReadQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| invalid("invalid query"))?;
    Ok(Json(
        blocking(store, move |s| s.conversation(&id, q.participant)).await?,
    ))
}
async fn page(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| invalid("invalid query"))?;
    Ok(Json(
        blocking(store, move |s| {
            s.conversation_messages(&id, q.participant, q.before, q.limit)
        })
        .await?,
    ))
}
fn target_keys(keys: Vec<String>) -> Vec<(String, String)> {
    keys.into_iter().map(|k| ("target".to_owned(), k)).collect()
}
async fn say(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: SendRequest = decode(body)?;
    let (value, keys) = blocking(store.clone(), move |s| {
        let author = s.person_participant(&*s.connection()?)?;
        s.author_message(&id, &author, None, r.message_id, r.content)
    })
    .await?;
    dispatch(&store, target_keys(keys));
    Ok(Json(value))
}
async fn start(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let r: StartRequest = decode(body)?;
    let [to] = &r.participants[..] else {
        return Err(invalid("give exactly one participant"));
    };
    if to.len() > 256 {
        return Err(invalid("participant is longer than 256 characters"));
    }
    if to.starts_with("person:") || !to.contains('/') {
        return Err(invalid("person participants are not supported yet"));
    }
    if r.title.as_deref().is_some_and(|t| !valid_title(t)) {
        return Err(invalid(
            "title must be at most 200 bytes without control characters",
        ));
    }
    if r.content.as_deref().is_some_and(|c| !valid_content(c)) {
        return Err(invalid("content must be 1 to 65,536 bytes of UTF-8"));
    }
    if let Some(m) = &r.message_id
        && (r.content.is_none() || !valid_message_id(m))
    {
        return Err(invalid("invalid message_id"));
    }
    blocking(store.clone(), |s| s.person_participant(&*s.connection()?)).await?;
    let (target, _) = crate::directory::owner_target(
        &store,
        to,
        r.network.as_deref(),
        crate::policy::ACTION,
        None,
        false,
    )
    .await?;
    let given = to.clone();
    let title = r.title.clone();
    let (id, participant) = blocking(store.clone(), move |s| {
        s.create_conversation(&target, &given, title)
    })
    .await?;
    let began = tokio::time::Instant::now();
    for handle in dispatch(
        &store,
        vec![("invite".into(), format!("{id} {participant}"))],
    ) {
        let _ = tokio::time::timeout(START_WAIT, handle).await;
    }
    loop {
        let (i, p) = (id.clone(), participant.clone());
        let state = blocking(store.clone(), move |s| {
            Ok(s.invite_record(&*s.connection()?, &i, &p)?.state)
        })
        .await?;
        if state != "sending" || began.elapsed() >= START_WAIT {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let message = match r.content {
        Some(content) => {
            let i = id.clone();
            let message_id = r.message_id.clone();
            let (value, keys) = blocking(store.clone(), move |s| {
                let author = s.person_participant(&*s.connection()?)?;
                s.author_message(&i, &author, None, message_id, content)
            })
            .await?;
            dispatch(&store, target_keys(keys));
            value["message"].clone()
        }
        None => Value::Null,
    };
    let answer = blocking(store, move |s| {
        let conn = s.connection()?;
        let roster = s.roster(&conn, &id)?;
        let reader = s.person_participant(&conn)?;
        let invite = s.invite_record(&conn, &id, &participant)?;
        let mut message = message;
        if let Some(id) = message["message_id"].as_str().map(str::to_owned) {
            message["targets"] = Value::from(s.targets(&conn, &roster, &id)?);
        }
        Ok(json!({
            "conversation": s.conversation_view(&conn, &roster, &reader)?,
            "invites": [s.invite_outcome(&conn, &roster, &invite)?],
            "message": message,
        }))
    })
    .await?;
    Ok((StatusCode::CREATED, Json(answer)))
}

async fn peer_invite(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: InviteRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.accept_invite(&sender, r)).await?,
    ))
}
async fn peer_message(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Receipt>, Error> {
    let r: MessageRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| {
            s.accept_conversation_message(&sender, &id, r)
        })
        .await?,
    ))
}

async fn adapter_say(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let auth = crate::adapter::token(&headers);
    let r: SendRequest = decode(body)?;
    let (value, keys) = blocking(store.clone(), move |s| {
        let (author, origin) = s.adapter_author(&auth)?;
        if !valid_conversation_id(&id) {
            return Err(Error::NotFound);
        }
        s.author_message(&id, &author, Some(origin), r.message_id, r.content)
    })
    .await?;
    dispatch(&store, target_keys(keys));
    Ok(Json(value))
}
async fn adapter_next(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<Value>>, Error> {
    let _: Empty = decode(body)?;
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.claim_conversation_notification(&auth)).await?,
    ))
}
async fn adapter_forwarded(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let _: Empty = decode(body)?;
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.conversation_forwarded(&auth, &id)).await?,
    ))
}
