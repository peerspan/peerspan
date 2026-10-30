//! Conversations, PRs C1 and C2 (docs/conversations-contract.md): people
//! and agents start conversations, send, and change membership.
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
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock},
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
/// The largest `seq`, `clock` or `roster_version` accepted: 2^53 - 1, exact
/// in every JSON reader.
const MAX_COUNTER: i64 = (1 << 53) - 1;
/// How far a received clock may run ahead of the highest one held.
const MAX_CLOCK_JUMP: i64 = 1 << 20;
/// Participants `inviting` or `joined` in one conversation, the creator included.
const MAX_PARTICIPANTS: usize = 16;
/// Open conversations one local participant may be joined in.
const MAX_OPEN: usize = 200;
/// How long an invite may stay unanswered before home drops it.
const INVITE_LIMIT_SECONDS: i64 = 600;
const CLOSED: &str = "This conversation is closed.";
const NOT_CREATOR: &str = "Only the conversation's creator can add, remove, or close.";
const FULL: &str = "A conversation has at most 16 participants.";
const OPEN_LIMIT: &str = "A participant can be in at most 200 open conversations.";

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
    #[serde(default)]
    note: Option<String>,
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
    /// For `roster` notifications: `{change, by, by_label, note, roster_version}`.
    #[serde(default)]
    change: Option<Value>,
}

/// Which local participants this host admitted itself (contract C2,
/// Admission). A peer's roster never makes a local participant joined.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LocalState {
    /// Admitted local participants, with the `added_at` of the admission.
    #[serde(default)]
    admitted: BTreeMap<String, String>,
    /// Ended admissions (left, removed, or dropped), with their `added_at`.
    #[serde(default)]
    ended: BTreeMap<String, String>,
    /// Local participants that left on this host, with when.
    #[serde(default)]
    left: BTreeMap<String, String>,
}

/// A conversation as this host holds it: home's roster and the local state.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Held {
    roster: Roster,
    #[serde(default)]
    local: LocalState,
}
impl Held {
    fn joined_here(&self, id: &str) -> bool {
        self.local.admitted.contains_key(id) && !self.local.left.contains_key(id)
    }
    /// Joined: a local participant joined here, a remote one per the roster.
    fn joined(&self, own: &str, id: &str) -> bool {
        match participant_parts(id) {
            Some((_, host, _)) if host == own => self.joined_here(id),
            Some(_) => self.roster.joined(id).is_some(),
            None => false,
        }
    }
    fn admit(&mut self, id: &str, added_at: &str) {
        self.local.admitted.insert(id.into(), added_at.into());
        self.local.ended.remove(id);
        self.local.left.remove(id);
    }
    fn end(&mut self, id: &str) {
        if let Some(at) = self.local.admitted.remove(id) {
            self.local.ended.insert(id.into(), at);
        }
    }
    /// Participants `inviting` or `joined`.
    fn count(&self) -> usize {
        self.roster.participants.len()
    }
}

/// A roster push home sends to one host until it holds that version.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Push {
    version: i64,
    state: String,
    attempts: u32,
    error: Option<String>,
    next_attempt_at: Option<String>,
}

/// A leave a participant's host sends to home until home answers.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Leave {
    participant: String,
    state: String,
    attempts: u32,
    error: Option<String>,
    next_attempt_at: Option<String>,
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
/// Whether every participant's fields agree with its ID, IDs are unique
/// across `participants` and `departed`, and the states are known.
fn consistent(roster: &Roster) -> bool {
    let mut seen = BTreeSet::new();
    let departed_ok = roster.departed.iter().all(|d| {
        let Some(object) = d.as_object() else {
            return false;
        };
        let text = |k: &str| object.get(k).and_then(Value::as_str);
        let (Some(id), Some(kind), Some(reason), Some(at)) =
            (text("id"), text("kind"), text("reason"), text("at"))
        else {
            return false;
        };
        object.len() == 4
            && participant_parts(id).is_some_and(|(k, _, _)| k == kind)
            && matches!(reason, "left" | "removed" | "unanswered")
            && chrono::DateTime::parse_from_rfc3339(at).is_ok()
            && seen.insert(id.to_owned())
    });
    departed_ok
        && matches!(&roster.state[..], "open" | "closed")
        && participant_parts(&roster.created_by).is_some()
        && roster.participants.iter().all(|p| {
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
            seen.insert(id.to_owned())
                && p.kind == kind
                && p.host_id.as_deref() == Some(host)
                && fields
                && matches!(&p.state[..], "inviting" | "joined")
        })
}
fn valid_content(content: &str) -> bool {
    !content.is_empty() && content.len() <= MAX_CONTENT
}
/// A stored conversation record: `{roster, local}`, or a bare roster as C1
/// stored it, whose joined local participants this host had admitted.
fn parse_held(text: String, own: &str) -> Result<Held, Error> {
    let value: Value = serde_json::from_str(&text)?;
    if value.get("roster").is_some() {
        return Ok(serde_json::from_value(value)?);
    }
    let roster: Roster = serde_json::from_value(value)?;
    let mut local = LocalState::default();
    for p in &roster.participants {
        if let Some(id) = &p.id
            && p.host_id.as_deref() == Some(own)
            && p.state == "joined"
        {
            local.admitted.insert(id.clone(), p.added_at.clone());
        }
    }
    Ok(Held { roster, local })
}
fn save_held(conn: &Connection, held: &Held) -> Result<(), Error> {
    let roster = &held.roster;
    conn.execute(
        "INSERT INTO conversations (id, home_host, roster_version, state, record) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO UPDATE SET roster_version = excluded.roster_version, state = excluded.state, record = excluded.record",
        params![
            roster.conversation_id,
            roster.home_host_id,
            roster.version,
            roster.state,
            serde_json::to_string(held)?
        ],
    )?;
    Ok(())
}
fn closed() -> Error {
    coded_error(409, "closed", CLOSED)
}
fn not_creator() -> Error {
    coded_error(403, "not_creator", NOT_CREATOR)
}
fn departed_entry(id: &str, reason: &str) -> Value {
    let kind = participant_parts(id).map(|p| p.0).unwrap_or("agent");
    json!({"id": id, "kind": kind, "reason": reason, "at": now()})
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
        409 if code == "closed" => Outcome::Final(
            "refused",
            "closed",
            format!("{peer} holds the conversation as closed"),
        ),
        429 => Outcome::Final(
            "refused",
            "limit",
            format!("{peer} refused it over a limit"),
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
    fn held_opt(&self, conn: &Connection, id: &str) -> Result<Option<Held>, Error> {
        let record: Option<String> = conn
            .query_row(
                "SELECT record FROM conversations WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        let own = self.identity().id;
        record.map(|r| parse_held(r, &own)).transpose()
    }
    fn held(&self, conn: &Connection, id: &str) -> Result<Held, Error> {
        self.held_opt(conn, id)?.ok_or(Error::NotFound)
    }
    fn roster(&self, conn: &Connection, id: &str) -> Result<Roster, Error> {
        Ok(self.held(conn, id)?.roster)
    }
    /// Every conversation this host holds.
    fn all_held(&self, conn: &Connection) -> Result<Vec<Held>, Error> {
        let own = self.identity().id;
        let mut statement = conn.prepare("SELECT record FROM conversations ORDER BY rowid")?;
        let rows = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(|r| parse_held(r, &own)).collect()
    }
    /// Open conversations a local participant is joined in here.
    fn open_count(&self, conn: &Connection, participant: &str) -> Result<usize, Error> {
        Ok(self
            .all_held(conn)?
            .iter()
            .filter(|h| h.roster.state == "open" && h.joined_here(participant))
            .count())
    }
    /// The participants and departures this host shows: home's roster, with
    /// its own participants as it holds them (contract C2, Admission).
    fn shown(&self, held: &Held) -> (Vec<Participant>, Vec<Value>) {
        let mut participants = Vec::new();
        let mut departed = held.roster.departed.clone();
        for p in &held.roster.participants {
            let id = p.id.clone().unwrap_or_default();
            if !self.local_participant(&id) {
                participants.push(p.clone());
            } else if held.joined_here(&id) {
                let mut p = p.clone();
                p.state = "joined".into();
                participants.push(p);
            } else if let Some(at) = held.local.left.get(&id) {
                let mut d = departed_entry(&id, "left");
                d["at"] = json!(at);
                departed.push(d);
            } else if held.local.ended.contains_key(&id) {
                departed.push(departed_entry(&id, "removed"));
            } else {
                participants.push(p.clone());
            }
        }
        (participants, departed)
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
    fn participant_views(
        &self,
        conn: &Connection,
        participants: &[Participant],
    ) -> Result<Vec<Value>, Error> {
        participants
            .iter()
            .map(|p| {
                let mut v = serde_json::to_value(p)?;
                v["label"] = json!(self.label(conn, p)?);
                v["local"] = json!(p.host_id.as_deref() == Some(self.identity().id.as_str()));
                Ok(v)
            })
            .collect()
    }
    fn departed_views(
        &self,
        conn: &Connection,
        roster: &Roster,
        departed: &[Value],
    ) -> Result<Vec<Value>, Error> {
        departed
            .iter()
            .map(|d| {
                let id = d["id"].as_str().unwrap_or_default();
                Ok(json!({
                    "id": id,
                    "kind": d["kind"],
                    "label": self.label_of(conn, roster, id)?,
                    "reason": d["reason"],
                    "at": d["at"],
                }))
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
        held: &Held,
        reader: &str,
    ) -> Result<Value, Error> {
        let roster = &held.roster;
        let messages = self.visible(conn, &roster.conversation_id, reader)?;
        let (participants, departed) = self.shown(held);
        Ok(json!({
            "conversation_id": roster.conversation_id,
            "title": roster.title,
            "state": roster.state,
            "home_host_id": roster.home_host_id,
            "roster_version": roster.version,
            "created_by": roster.created_by,
            "created_at": roster.created_at,
            "participants": self.participant_views(conn, &participants)?,
            "departed": self.departed_views(conn, roster, &departed)?,
            "last_message_at": Self::last_message_at(&messages),
        }))
    }

    /// `GET /v1/conversations`.
    pub fn conversations(&self, all: bool) -> Result<Value, Error> {
        let conn = self.connection()?;
        let own = self.identity().id;
        let mut items = Vec::new();
        for held in self.all_held(&conn)? {
            let roster = &held.roster;
            let active =
                roster.state == "open" && held.local.admitted.keys().any(|p| held.joined_here(p));
            if !all && !active {
                continue;
            }
            let last: Option<String> = conn.query_row(
                "SELECT MAX(json_extract(record, '$.message.sent_at')) FROM conversation_messages WHERE conversation_id = ?1",
                [&roster.conversation_id],
                |r| r.get(0),
            )?;
            let participants = self
                .shown(&held)
                .0
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
        let held = self.held(&conn, id)?;
        let reader = self.reader(&conn, &held.roster, participant)?;
        self.conversation_view(&conn, &held, &reader)
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

    /// Creates a conversation as `creator` (a local person or agent
    /// participant): local agent targets are joined at once, remote ones are
    /// `inviting` with an invite to send. Returns the ID and, per target,
    /// `(given, participant, local outcome)`, the outcome `None` for remote.
    #[allow(clippy::type_complexity)]
    fn create_conversation(
        &self,
        creator: &str,
        targets: &[(String, crate::directory::Candidate)],
        title: Option<String>,
        note: Option<String>,
    ) -> Result<(String, Vec<(String, String, Option<&'static str>)>), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if self.open_count(&tx, creator)? >= MAX_OPEN {
            return Err(coded_error(429, "limit", OPEN_LIMIT));
        }
        let own = self.identity().id;
        let id = new_id("conv")?;
        let at = now();
        let person = self.conversation_person(&tx)?;
        let (kind, _, local) =
            participant_parts(creator).ok_or_else(|| invalid("invalid creator"))?;
        let name: Option<String> = if kind == "agent" {
            Some(
                tx.query_row("SELECT name FROM agents WHERE id = ?1", [local], |r| {
                    r.get(0)
                })
                .optional()?
                .ok_or(Error::NotFound)?,
            )
        } else {
            None
        };
        let mut held = Held {
            roster: Roster {
                conversation_id: id.clone(),
                home_host_id: own.clone(),
                version: 1,
                title,
                state: "open".into(),
                created_by: creator.into(),
                created_at: at.clone(),
                participants: vec![Participant {
                    id: Some(creator.into()),
                    kind: kind.into(),
                    host_id: Some(own.clone()),
                    person_id: person.clone(),
                    agent_id: (kind == "agent").then(|| local.to_owned()),
                    name,
                    state: "joined".into(),
                    added_by: None,
                    added_at: at.clone(),
                }],
                departed: vec![],
            },
            local: LocalState::default(),
        };
        held.admit(creator, &at);
        let mut outcomes = Vec::new();
        let mut added = Vec::new();
        for (given, target) in targets {
            let participant = format!("agent:{}/{}", target.host_id, target.agent_id);
            if target.local {
                if self.open_count(&tx, &participant)? >= MAX_OPEN {
                    outcomes.push((given.clone(), participant, Some("limit")));
                    continue;
                }
                held.roster.participants.push(Participant {
                    id: Some(participant.clone()),
                    kind: "agent".into(),
                    host_id: Some(own.clone()),
                    person_id: person.clone(),
                    agent_id: Some(target.agent_id.clone()),
                    name: Some(target.name.clone()),
                    state: "joined".into(),
                    added_by: Some(creator.into()),
                    added_at: at.clone(),
                });
                held.admit(&participant, &at);
                added.push(target.agent_id.clone());
                outcomes.push((given.clone(), participant, Some("joined")));
            } else {
                let target_person = crate::adapter::sender_person(self, &tx, &target.host_id)?.0;
                held.roster.participants.push(Participant {
                    id: Some(participant.clone()),
                    kind: "agent".into(),
                    host_id: Some(target.host_id.clone()),
                    person_id: target_person,
                    agent_id: Some(target.agent_id.clone()),
                    name: Some(target.name.clone()),
                    state: "inviting".into(),
                    added_by: Some(creator.into()),
                    added_at: at.clone(),
                });
                self.save_invite(
                    &tx,
                    &id,
                    &Invite {
                        target: given.clone(),
                        participant: participant.clone(),
                        agent_id: target.agent_id.clone(),
                        adder: creator.into(),
                        state: "sending".into(),
                        code: None,
                        error: None,
                        attempts: 0,
                        next_attempt_at: Some(later(10)),
                        note: note.clone(),
                    },
                )?;
                outcomes.push((given.clone(), participant, None));
            }
        }
        save_held(&tx, &held)?;
        for agent in added {
            let change =
                self.roster_change(&tx, &held.roster, "added", creator, note.as_deref())?;
            self.notify(&tx, &id, &agent, "roster", None, Some(change))?;
        }
        tx.commit()?;
        Ok((id, outcomes))
    }
    fn save_invite(&self, conn: &Connection, id: &str, invite: &Invite) -> Result<(), Error> {
        let (_, host, agent) = participant_parts(&invite.participant).ok_or(Error::NotFound)?;
        conn.execute(
            "INSERT INTO conversation_roster_outbound (conversation_id, peer, kind, record) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(conversation_id, peer, kind) DO UPDATE SET record = excluded.record",
            params![id, host, format!("invite:{agent}"), serde_json::to_string(invite)?],
        )?;
        Ok(())
    }
    fn invite_opt(
        &self,
        conn: &Connection,
        id: &str,
        participant: &str,
    ) -> Result<Option<Invite>, Error> {
        let Some((_, host, agent)) = participant_parts(participant) else {
            return Ok(None);
        };
        let text: Option<String> = conn
            .query_row(
                "SELECT record FROM conversation_roster_outbound WHERE conversation_id = ?1 AND peer = ?2 AND kind = ?3",
                params![id, host, format!("invite:{agent}")],
                |r| r.get(0),
            )
            .optional()?;
        text.map(json).transpose()
    }
    /// Stops an invite that is still being sent, recording why.
    fn stop_invite(
        &self,
        conn: &Connection,
        id: &str,
        participant: &str,
        state: &str,
    ) -> Result<(), Error> {
        if let Some(mut invite) = self.invite_opt(conn, id, participant)?
            && invite.state == "sending"
        {
            invite.state = state.into();
            invite.next_attempt_at = None;
            self.save_invite(conn, id, &invite)?;
        }
        Ok(())
    }
    fn roster_change(
        &self,
        conn: &Connection,
        roster: &Roster,
        change: &str,
        by: &str,
        note: Option<&str>,
    ) -> Result<Value, Error> {
        Ok(json!({
            "change": change,
            "by": by,
            "by_label": self.label_of(conn, roster, by)?,
            "note": note,
            "roster_version": roster.version,
        }))
    }
    fn notify(
        &self,
        conn: &Connection,
        conversation: &str,
        agent: &str,
        kind: &str,
        message_id: Option<&str>,
        change: Option<Value>,
    ) -> Result<(), Error> {
        let n = Notification {
            id: new_id("cnot")?,
            kind: kind.into(),
            conversation_id: conversation.into(),
            message_id: message_id.map(str::to_owned),
            session_id: None,
            created_at: now(),
            claimed_at: None,
            forwarded_at: None,
            change,
        };
        conn.execute(
            "INSERT INTO conversation_notifications (id, conversation_id, kind, message_id, agent_id, session_id, record) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
            params![n.id, conversation, kind, message_id, agent, serde_json::to_string(&n)?],
        )?;
        Ok(())
    }
    /// Withdraws a departed agent's unclaimed message notifications.
    fn withdraw(&self, conn: &Connection, conversation: &str, agent: &str) -> Result<(), Error> {
        conn.execute(
            "DELETE FROM conversation_notifications WHERE conversation_id = ?1 AND agent_id = ?2 AND kind = 'message' AND session_id IS NULL",
            params![conversation, agent],
        )?;
        Ok(())
    }
    /// Takes `new` as the held roster: admitted local participants it lists
    /// as departed or omits stop being joined here, and local agents get
    /// `removed` and `closed` notifications (never the `actor`).
    fn apply_roster(
        &self,
        conn: &Connection,
        held: &mut Held,
        new: Roster,
        actor: Option<&str>,
    ) -> Result<(), Error> {
        let id = new.conversation_id.clone();
        let was_closed = held.roster.state == "closed";
        let admitted: Vec<String> = held.local.admitted.keys().cloned().collect();
        for p in &admitted {
            if new.participants.iter().any(|x| x.id.as_deref() == Some(p)) {
                continue;
            }
            let reason = new
                .departed
                .iter()
                .find(|d| d["id"].as_str() == Some(p))
                .and_then(|d| d["reason"].as_str())
                .map(str::to_owned);
            let was_joined = held.joined_here(p);
            held.end(p);
            if let Some(("agent", _, agent)) = participant_parts(p) {
                self.withdraw(conn, &id, agent)?;
                if was_joined && reason.as_deref() == Some("removed") && actor != Some(p.as_str()) {
                    let change =
                        self.roster_change(conn, &new, "removed", &new.created_by, None)?;
                    self.notify(conn, &id, agent, "roster", None, Some(change))?;
                }
            }
        }
        if new.state == "closed" && !was_closed {
            let joined: Vec<String> = held
                .local
                .admitted
                .keys()
                .filter(|p| held.joined_here(p))
                .cloned()
                .collect();
            for p in joined {
                if actor == Some(p.as_str()) {
                    continue;
                }
                if let Some(("agent", _, agent)) = participant_parts(&p) {
                    let change = self.roster_change(conn, &new, "closed", &new.created_by, None)?;
                    self.notify(conn, &id, agent, "roster", None, Some(change))?;
                }
            }
        }
        held.roster = new;
        Ok(())
    }
    /// Home commits `new` as its next roster version and schedules pushes
    /// to every other host with a participant in it, or one it just moved
    /// to `departed`.
    fn commit(
        &self,
        conn: &Connection,
        held: &mut Held,
        mut new: Roster,
        actor: Option<&str>,
    ) -> Result<(), Error> {
        let old = held.roster.clone();
        new.version = old.version + 1;
        self.apply_roster(conn, held, new, actor)?;
        save_held(conn, held)?;
        let own = self.identity().id;
        let mut hosts = BTreeSet::new();
        for p in &held.roster.participants {
            if let Some(h) = &p.host_id {
                hosts.insert(h.clone());
            }
        }
        for d in &held.roster.departed {
            if !old.departed.contains(d)
                && let Some((_, h, _)) = d["id"].as_str().and_then(participant_parts)
            {
                hosts.insert(h.to_owned());
            }
        }
        hosts.remove(&own);
        let push = Push {
            version: held.roster.version,
            state: "sending".into(),
            attempts: 0,
            error: None,
            next_attempt_at: Some(now()),
        };
        for host in hosts {
            conn.execute(
                "INSERT INTO conversation_roster_outbound (conversation_id, peer, kind, record) VALUES (?1, ?2, 'roster', ?3) ON CONFLICT(conversation_id, peer, kind) DO UPDATE SET record = excluded.record",
                params![held.roster.conversation_id, host, serde_json::to_string(&push)?],
            )?;
        }
        Ok(())
    }
    /// Whether participant `x` may send to `y`, as far as this host knows
    /// (contract C2, Invite outcome).
    fn reaches(&self, conn: &Connection, roster: &Roster, x: &str, y: &str) -> Result<bool, Error> {
        let own = self.identity().id;
        let (Some((xk, xh, xl)), Some((yk, yh, yl))) = (participant_parts(x), participant_parts(y))
        else {
            return Ok(false);
        };
        if x == y {
            return Ok(false);
        }
        if yk == "person" {
            return Ok(yh != own || xh == own || !self.blocked(conn, xh)?);
        }
        if xh == yh {
            return Ok(true);
        }
        let person = |host: &str| -> Result<Option<String>, Error> {
            Ok(crate::adapter::sender_person(self, conn, host)?.0)
        };
        let (xp, yp) = (person(xh)?, person(yh)?);
        if xp.is_some() && xp == yp {
            return Ok(true);
        }
        let origin = (xk == "agent").then(|| Origin {
            agent_id: xl.to_owned(),
            session_id: None,
        });
        if yh == own {
            return Ok(self
                .conversation_authorize(conn, xh, (None, None, None), yl, 0, origin.as_ref())
                .is_ok());
        }
        if xh == own {
            return Ok(self
                .cached_choice(
                    yh,
                    yl,
                    crate::policy::ACTION,
                    origin.as_ref().map(|o| o.agent_id.as_str()),
                )?
                .is_some());
        }
        let Some(yp) = yp else {
            return Ok(false);
        };
        let name = roster
            .participants
            .iter()
            .find(|p| p.id.as_deref() == Some(y))
            .and_then(|p| p.name.clone())
            .unwrap_or_default();
        let at = crate::clock::now();
        for network in self.product_network_ids(conn)? {
            let members = self.product_members(conn, &network)?;
            let (Some(xm), true, true) = (
                members.iter().find(|m| m.host_id == xh),
                members.iter().any(|m| m.host_id == yh),
                members.iter().any(|m| m.host_id == own),
            ) else {
                continue;
            };
            let Some(key) = self.product_person_key(conn, &network, &yp)? else {
                continue;
            };
            let Some(policy) = self.product_policy(conn, &network, &key)? else {
                continue;
            };
            if !policy.in_window(at) {
                continue;
            }
            let groups = self.product_groups(conn, &network)?;
            let named = policy.rules.iter().any(|r| r.agent == name);
            let allowed = policy.rules.iter().any(|rule| {
                let applies = if named {
                    rule.agent == name
                } else {
                    rule.agent == crate::policy::ALL_AGENTS
                };
                applies
                    && rule
                        .actions
                        .iter()
                        .any(|a| crate::policy::allows(a, crate::policy::ACTION))
                    && rule.principals.iter().any(|p| {
                        crate::decentralized::product::principal_matches(
                            p,
                            xm,
                            &groups,
                            origin.as_ref(),
                        )
                    })
            });
            if allowed {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// An invite outcome for `participant`, with reachability.
    fn outcome_view(
        &self,
        conn: &Connection,
        held: &Held,
        given: &str,
        participant: &str,
        local: Option<&str>,
    ) -> Result<Value, Error> {
        let id = &held.roster.conversation_id;
        let (state, code, error): (String, Option<String>, Option<String>) = match local {
            Some("joined") => ("joined".into(), None, None),
            Some(_) => (
                "refused".into(),
                Some("limit".into()),
                Some(OPEN_LIMIT.into()),
            ),
            None => match self.invite_opt(conn, id, participant)? {
                Some(invite) => match &invite.state[..] {
                    "joined" | "refused" | "unsupported" => {
                        (invite.state.clone(), invite.code, invite.error)
                    }
                    _ => ("inviting".into(), None, invite.error),
                },
                None => ("joined".into(), None, None),
            },
        };
        let listed = held
            .roster
            .participants
            .iter()
            .any(|p| p.id.as_deref() == Some(participant));
        let mut reachable_from = Vec::new();
        let mut reaches = Vec::new();
        if listed && matches!(&state[..], "joined" | "inviting") {
            for p in &held.roster.participants {
                let Some(other) = p.id.as_deref() else {
                    continue;
                };
                if other == participant {
                    continue;
                }
                if self.reaches(conn, &held.roster, other, participant)? {
                    reachable_from.push(other.to_owned());
                }
                if self.reaches(conn, &held.roster, participant, other)? {
                    reaches.push(other.to_owned());
                }
            }
        }
        Ok(json!({
            "target": given,
            "participant": participant,
            "label": self.label_of(conn, &held.roster, participant)?,
            "state": state,
            "code": code,
            "error": error,
            "reachable_from": reachable_from,
            "reaches": reaches,
        }))
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
        let inviting = roster
            .participants
            .iter()
            .any(|p| p.id.as_deref() == Some(participant) && p.state == "inviting");
        if roster.state != "open" || !inviting {
            self.stop_invite(&tx, id, participant, "stopped")?;
            tx.commit()?;
            return Ok(None);
        }
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
            note: invite.note.clone(),
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
    /// name; a final refusal drops it; anything else schedules a retry. An
    /// answer for a target no longer `inviting` (removed, dropped, closed)
    /// changes nothing.
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
        let mut held = self.held(tx, id)?;
        let inviting = held.roster.state == "open"
            && held
                .roster
                .participants
                .iter()
                .any(|p| p.id.as_deref() == Some(participant) && p.state == "inviting");
        match outcome {
            Ok(name) => {
                invite.state = "joined".into();
                invite.next_attempt_at = None;
                invite.code = None;
                invite.error = None;
                if inviting {
                    let mut next = held.roster.clone();
                    for p in &mut next.participants {
                        if p.id.as_deref() == Some(participant) {
                            p.state = "joined".into();
                            p.name = Some(name.clone());
                        }
                    }
                    self.commit(tx, &mut held, next, None)?;
                }
            }
            Err((state @ ("refused" | "unsupported"), code, error)) => {
                invite.state = state.into();
                invite.code = Some(code.into());
                invite.error = Some(error);
                invite.next_attempt_at = None;
                if inviting {
                    let mut next = held.roster.clone();
                    next.participants
                        .retain(|p| p.id.as_deref() != Some(participant));
                    self.commit(tx, &mut held, next, None)?;
                }
            }
            Err((_, _, error)) => {
                invite.error = Some(error);
                invite.next_attempt_at = Some(rfc3339(
                    crate::clock::now() + backoff(invite.attempts.max(1), jitter()),
                ));
            }
        }
        self.save_invite(tx, id, &invite)
    }
    fn finish_invite(&self, id: &str, participant: &str, outcome: Outcome) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        {
            let mut invite = self.invite_record(&tx, id, participant)?;
            invite.attempts += 1;
            self.save_invite(&tx, id, &invite)?;
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
        let held = self.held(&tx, id)?;
        let roster = held.roster.clone();
        let own = self.identity().id;
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
        if roster.state == "closed" {
            return Err(closed());
        }
        if !held.joined(&own, author) {
            return Err(not_participant());
        }
        let (seq, clock, local_seq): (i64, i64, i64) = tx.query_row(
            "SELECT (SELECT COALESCE(MAX(seq), 0) + 1 FROM conversation_messages WHERE conversation_id = ?1 AND author = ?2), (SELECT COALESCE(MAX(clock), 0) + 1 FROM conversation_messages WHERE conversation_id = ?1), (SELECT COALESCE(MAX(local_seq), 0) + 1 FROM conversation_messages)",
            params![id, author],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if seq > MAX_COUNTER || clock > MAX_COUNTER {
            return Err(invalid("this conversation's counters are exhausted"));
        }
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
            if target == author || !held.joined(&own, target) {
                continue;
            }
            let peer = p.host_id.clone().unwrap_or_default();
            let prev: Option<i64> = tx.query_row(
                "SELECT MAX(m.seq) FROM conversation_messages m JOIN conversation_targets t ON t.conversation_id = m.conversation_id AND t.message_id = m.message_id WHERE m.conversation_id = ?1 AND m.author = ?2 AND t.direction = 'out' AND t.target = ?3 AND m.seq < ?4",
                params![id, author, target, seq],
                |r| r.get(0),
            )?;
            if peer == own {
                // Decision 18: a local target is delivered in this
                // transaction, under self access, with no peer request.
                let record = Outbound {
                    participant: target.into(),
                    state: "delivered".into(),
                    code: None,
                    error: None,
                    attempts: 0,
                    next_attempt_at: None,
                };
                tx.execute(
                    "INSERT INTO conversation_targets (conversation_id, message_id, target, direction, peer, prev_seq, state, next_attempt_at, record) VALUES (?1, ?2, ?3, 'out', ?4, ?5, 'delivered', NULL, ?6)",
                    params![id, message_id, target, peer, prev, serde_json::to_string(&record)?],
                )?;
                let receipt = Receipt {
                    message_id: message_id.clone(),
                    target: target.into(),
                    receiver_host_id: own.clone(),
                    accepted_at: stored.received_at.clone(),
                };
                let inbound = Inbound {
                    message: stored.message.clone(),
                    target: target.into(),
                    prev_seq: prev,
                    receipt,
                };
                tx.execute(
                    "INSERT INTO conversation_targets (conversation_id, message_id, target, direction, peer, prev_seq, state, next_attempt_at, record) VALUES (?1, ?2, ?3, 'in', ?4, ?5, 'accepted', NULL, ?6)",
                    params![id, message_id, target, own, prev, serde_json::to_string(&inbound)?],
                )?;
                if let Some(("agent", _, agent)) = participant_parts(target) {
                    self.notify(&tx, id, agent, "message", Some(&message_id), None)?;
                }
                continue;
            }
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
            // A person on this host joins only here, never by a peer's roster.
            || r.roster.participants.iter().any(|p| {
                p.kind == "person" && p.host_id.as_deref() == Some(own.as_str())
            })
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
        let held = self.held_opt(&tx, &r.conversation_id)?;
        if let Some(held) = &held
            && held.roster.home_host_id != sender
        {
            return Err(Error::Forbidden);
        }
        // Another local agent may be listed `inviting`, or `joined` only if
        // this host already holds it joined: an invite joins its own target
        // and nothing else.
        let stray = r.roster.participants.iter().any(|p| {
            let id = p.id.as_deref().unwrap_or_default();
            p.host_id.as_deref() == Some(own.as_str())
                && id != participant
                && p.state == "joined"
                && held.as_ref().is_none_or(|h| !h.joined_here(id))
        });
        if stray || r.roster.state != "open" {
            return Err(invalid(
                "an invite cannot join another participant on this host",
            ));
        }
        let added_at = r
            .roster
            .participants
            .iter()
            .find(|p| p.id.as_deref() == Some(participant.as_str()))
            .map(|p| p.added_at.clone())
            .unwrap_or_default();
        let mut held = match held {
            Some(h) => h,
            None => Held {
                roster: r.roster.clone(),
                local: LocalState::default(),
            },
        };
        if held.local.admitted.get(&participant) == Some(&added_at)
            && held.joined_here(&participant)
        {
            return Ok(json!({"state": "joined", "name": name}));
        }
        if held.local.ended.get(&participant) == Some(&added_at) {
            return Err(not_participant());
        }
        if self.open_count(&tx, &participant)? >= MAX_OPEN {
            return Err(coded_error(429, "limit", OPEN_LIMIT));
        }
        if held.roster.version < r.roster.version || held.roster == r.roster {
            let mut roster = r.roster.clone();
            for p in &mut roster.participants {
                if p.id.as_deref() == Some(participant.as_str()) {
                    p.name = Some(name.clone());
                }
            }
            self.apply_roster(&tx, &mut held, roster, None)?;
        }
        held.admit(&participant, &added_at);
        save_held(&tx, &held)?;
        let change = self.roster_change(&tx, &r.roster, "added", &r.adder, r.note.as_deref())?;
        self.notify(
            &tx,
            &r.conversation_id,
            &agent,
            "roster",
            None,
            Some(change),
        )?;
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
            || !(1..=MAX_COUNTER).contains(&m.seq)
            || !(1..=MAX_COUNTER).contains(&m.clock)
            || !(1..=MAX_COUNTER).contains(&m.roster_version)
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
        let Some(held) = self.held_opt(&tx, id)? else {
            return Err(unavailable(
                "this host does not hold that conversation's roster",
            ));
        };
        let roster = &held.roster;
        if m.roster_version > roster.version {
            return Err(unavailable("this host holds an older roster"));
        }
        // A clock far ahead of everything held would leave nothing to count
        // up to; honest clocks advance by one per message.
        let highest: i64 = tx.query_row(
            "SELECT COALESCE(MAX(clock), 0) FROM conversation_messages WHERE conversation_id = ?1",
            [id],
            |row| row.get(0),
        )?;
        if m.clock > highest.saturating_add(MAX_CLOCK_JUMP) {
            return Err(invalid("clock too far ahead"));
        }
        // A local participant counts as joined only when this host admitted
        // it (contract C2, Admission), never by a peer's roster.
        if target_host != own || !held.joined_here(&r.target) || roster.joined(&m.author).is_none()
        {
            return Err(not_participant());
        }
        // A message authored before its author's host knew of the close is
        // still accepted.
        if roster.state == "closed" && m.roster_version >= roster.version {
            return Err(closed());
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
            self.notify(&tx, id, target_local, "message", Some(&m.message_id), None)?;
        }
        tx.commit()?;
        Ok(receipt)
    }

    /// A local agent's participant ID, by agent ID or name.
    fn agent_participant(&self, conn: &Connection, agent: &str) -> Result<String, Error> {
        let id: Option<String> = conn
            .query_row(
                "SELECT id FROM agents WHERE id = ?1 OR name = ?1 ORDER BY id = ?1 DESC LIMIT 1",
                [agent],
                |r| r.get(0),
            )
            .optional()?;
        let id = id.ok_or(Error::NotFound)?;
        Ok(format!("agent:{}/{id}", self.identity().id))
    }
    /// The creator checks of `add`, `remove` and `close`: 404, then
    /// `not_creator` and `not_participant`. Returns the held conversation.
    fn creator_check(&self, conn: &Connection, id: &str, actor: &str) -> Result<Held, Error> {
        let held = self.held(conn, id)?;
        if held.roster.created_by != actor || held.roster.home_host_id != self.identity().id {
            return Err(not_creator());
        }
        if !held.joined_here(actor) {
            return Err(not_participant());
        }
        Ok(held)
    }
    /// Whether `participant` is already `inviting` or `joined`.
    fn listed(held: &Held, participant: &str) -> bool {
        held.roster
            .participants
            .iter()
            .any(|p| p.id.as_deref() == Some(participant))
    }
    /// `add` once resolved: a local agent is joined at once (or refused
    /// over its limit), a remote one is committed `inviting` and invited.
    /// Returns the local outcome (`None` for remote) and whether a new
    /// invite was created.
    fn add_participant(
        &self,
        id: &str,
        actor: &str,
        target: &crate::directory::Candidate,
        given: &str,
    ) -> Result<(Option<&'static str>, bool), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut held = self.creator_check(&tx, id, actor)?;
        if held.roster.state == "closed" {
            return Err(closed());
        }
        let participant = format!("agent:{}/{}", target.host_id, target.agent_id);
        if Self::listed(&held, &participant) {
            return Ok((target.local.then_some("joined"), false));
        }
        if held.count() >= MAX_PARTICIPANTS {
            return Err(coded_error(409, "full", FULL));
        }
        if target.local && self.open_count(&tx, &participant)? >= MAX_OPEN {
            return Ok((Some("limit"), false));
        }
        let at = now();
        let person = if target.local {
            self.conversation_person(&tx)?
        } else {
            crate::adapter::sender_person(self, &tx, &target.host_id)?.0
        };
        let mut next = held.roster.clone();
        next.departed
            .retain(|d| d["id"].as_str() != Some(participant.as_str()));
        next.participants.push(Participant {
            id: Some(participant.clone()),
            kind: "agent".into(),
            host_id: Some(target.host_id.clone()),
            person_id: person,
            agent_id: Some(target.agent_id.clone()),
            name: Some(target.name.clone()),
            state: if target.local { "joined" } else { "inviting" }.into(),
            added_by: Some(actor.into()),
            added_at: at.clone(),
        });
        self.commit(&tx, &mut held, next, Some(actor))?;
        if target.local {
            held.admit(&participant, &at);
            save_held(&tx, &held)?;
            let change = self.roster_change(&tx, &held.roster, "added", actor, None)?;
            self.notify(&tx, id, &target.agent_id, "roster", None, Some(change))?;
        } else {
            self.save_invite(
                &tx,
                id,
                &Invite {
                    target: given.into(),
                    participant: participant.clone(),
                    agent_id: target.agent_id.clone(),
                    adder: actor.into(),
                    state: "sending".into(),
                    code: None,
                    error: None,
                    attempts: 0,
                    next_attempt_at: Some(later(10)),
                    note: None,
                },
            )?;
        }
        tx.commit()?;
        Ok((target.local.then_some("joined"), !target.local))
    }
    /// `remove`: a participant ID, or a label matching exactly one.
    fn remove_participant(&self, id: &str, actor: &str, which: &str) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut held = self.creator_check(&tx, id, actor)?;
        if held.roster.state == "closed" {
            return Err(closed());
        }
        let mut matches = Vec::new();
        for p in &held.roster.participants {
            let pid = p.id.clone().unwrap_or_default();
            if pid == which || self.label(&tx, p)? == which {
                matches.push(pid);
            }
        }
        let participant = match matches.as_slice() {
            [] => {
                return Err(coded_error(
                    404,
                    "not_found",
                    "No such participant in that conversation.",
                ));
            }
            [one] => one.clone(),
            many => {
                return Err(coded(
                    409,
                    "ambiguous",
                    format!("{which} names several participants: {}", many.join(", ")),
                    json!({ "matches": many }),
                ));
            }
        };
        if participant == held.roster.created_by {
            return Err(invalid("the creator cannot be removed; it can leave"));
        }
        let mut next = held.roster.clone();
        next.participants
            .retain(|p| p.id.as_deref() != Some(participant.as_str()));
        next.departed.push(departed_entry(&participant, "removed"));
        self.commit(&tx, &mut held, next, Some(actor))?;
        self.stop_invite(&tx, id, &participant, "removed")?;
        tx.commit()?;
        Ok(())
    }
    /// `close`: idempotent; pending invites stop.
    fn close_conversation(&self, id: &str, actor: &str) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut held = self.creator_check(&tx, id, actor)?;
        if held.roster.state == "closed" {
            return Ok(());
        }
        let mut next = held.roster.clone();
        next.state = "closed".into();
        self.commit(&tx, &mut held, next, Some(actor))?;
        let inviting: Vec<String> = held
            .roster
            .participants
            .iter()
            .filter(|p| p.state == "inviting")
            .filter_map(|p| p.id.clone())
            .collect();
        for p in inviting {
            self.stop_invite(&tx, id, &p, "closed")?;
        }
        tx.commit()?;
        Ok(())
    }
    /// A local participant leaves: at once here, then at home.
    fn leave_conversation(&self, id: &str, participant: &str) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut held = self.held(&tx, id)?;
        if !held.joined_here(participant) {
            return Err(not_participant());
        }
        if held.roster.state == "closed" {
            return Err(closed());
        }
        held.end(participant);
        held.local.left.insert(participant.into(), now());
        if let Some(("agent", _, agent)) = participant_parts(participant) {
            self.withdraw(&tx, id, agent)?;
        }
        let own = self.identity().id;
        if held.roster.home_host_id == own {
            let mut next = held.roster.clone();
            next.participants
                .retain(|p| p.id.as_deref() != Some(participant));
            next.departed.push(departed_entry(participant, "left"));
            self.commit(&tx, &mut held, next, Some(participant))?;
        } else {
            save_held(&tx, &held)?;
            let leave = Leave {
                participant: participant.into(),
                state: "sending".into(),
                attempts: 0,
                error: None,
                next_attempt_at: Some(now()),
            };
            tx.execute(
                "INSERT INTO conversation_roster_outbound (conversation_id, peer, kind, record) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(conversation_id, peer, kind) DO UPDATE SET record = excluded.record",
                params![id, held.roster.home_host_id, format!("leave:{participant}"), serde_json::to_string(&leave)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    fn current_member(&self, conn: &Connection, sender: &str) -> Result<(), Error> {
        if self.product_members_of(conn, sender)?.is_empty() {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    /// `POST /peer/v1/conversations/{id}/leave` at home.
    pub fn accept_leave(&self, sender: &str, id: &str, participant: &str) -> Result<Value, Error> {
        match participant_parts(participant) {
            Some(("agent", host, _)) if valid_conversation_id(id) => {
                if host != sender {
                    return Err(Error::Forbidden);
                }
            }
            _ => return Err(invalid("participant must be an agent participant ID")),
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        self.current_member(&tx, sender)?;
        let Some(mut held) = self.held_opt(&tx, id)? else {
            return Err(Error::NotFound);
        };
        if held.roster.home_host_id != self.identity().id {
            return Err(Error::NotFound);
        }
        if held.roster.state == "open" && Self::listed(&held, participant) {
            let mut next = held.roster.clone();
            next.participants
                .retain(|p| p.id.as_deref() != Some(participant));
            next.departed.push(departed_entry(participant, "left"));
            self.commit(&tx, &mut held, next, None)?;
            self.stop_invite(&tx, id, participant, "left")?;
        }
        tx.commit()?;
        Ok(json!({ "roster": held.roster }))
    }
    /// `GET /peer/v1/conversations/{id}/roster` at home.
    pub fn serve_roster(&self, sender: &str, id: &str) -> Result<Value, Error> {
        let conn = self.connection()?;
        self.current_member(&conn, sender)?;
        let Some(held) = self.held_opt(&conn, id)? else {
            return Err(Error::NotFound);
        };
        let on_sender = |pid: &str| participant_parts(pid).is_some_and(|(_, h, _)| h == sender);
        let holds = held
            .roster
            .participants
            .iter()
            .any(|p| p.id.as_deref().is_some_and(on_sender))
            || held
                .roster
                .departed
                .iter()
                .any(|d| d["id"].as_str().is_some_and(on_sender));
        if held.roster.home_host_id != self.identity().id || !holds {
            return Err(Error::NotFound);
        }
        Ok(json!({ "roster": held.roster }))
    }
    /// `POST /peer/v1/conversations/{id}/roster`, and a roster fetched from
    /// home: steps 1 to 6 of the contract.
    pub fn accept_roster(&self, sender: &str, id: &str, roster: Roster) -> Result<Value, Error> {
        if !valid_conversation_id(id)
            || roster.conversation_id != id
            || !(1..=MAX_COUNTER).contains(&roster.version)
            || !consistent(&roster)
            || roster.title.as_deref().is_some_and(|t| !valid_title(t))
        {
            return Err(invalid("invalid roster"));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        self.current_member(&tx, sender)?;
        let Some(mut held) = self.held_opt(&tx, id)? else {
            return Err(Error::NotFound);
        };
        if held.roster.home_host_id != sender || roster.home_host_id != sender {
            return Err(Error::Forbidden);
        }
        if roster.version <= held.roster.version {
            return Ok(json!({ "version": held.roster.version }));
        }
        let own = self.identity().id;
        let claims = roster.participants.iter().any(|p| {
            let pid = p.id.as_deref().unwrap_or_default();
            p.host_id.as_deref() == Some(own.as_str())
                && p.state == "joined"
                && !held.joined_here(pid)
                && !held.local.left.contains_key(pid)
        });
        if claims {
            return Err(invalid("a roster cannot join a participant on this host"));
        }
        self.apply_roster(&tx, &mut held, roster, None)?;
        save_held(&tx, &held)?;
        tx.commit()?;
        Ok(json!({ "version": held.roster.version }))
    }
    /// Home drops invites still unanswered 10 minutes after `added_at`.
    fn expire_invites(&self) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let rows: Vec<(String, String)> = {
            let mut statement = tx.prepare(
                "SELECT conversation_id, record FROM conversation_roster_outbound WHERE kind LIKE 'invite:%'",
            )?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        let at = crate::clock::now();
        for (id, record) in rows {
            let mut invite: Invite = json(record)?;
            if invite.state != "sending" {
                continue;
            }
            let Some(mut held) = self.held_opt(&tx, &id)? else {
                continue;
            };
            let due = held.roster.participants.iter().any(|p| {
                p.id.as_deref() == Some(invite.participant.as_str())
                    && p.state == "inviting"
                    && crate::membership::time(&p.added_at)
                        .is_ok_and(|t| t + chrono::TimeDelta::seconds(INVITE_LIMIT_SECONDS) <= at)
            });
            if !due || held.roster.state != "open" {
                continue;
            }
            invite.state = "unanswered".into();
            invite.next_attempt_at = None;
            let mut next = held.roster.clone();
            next.participants
                .retain(|p| p.id.as_deref() != Some(invite.participant.as_str()));
            next.departed
                .push(departed_entry(&invite.participant, "unanswered"));
            self.commit(&tx, &mut held, next, None)?;
            self.save_invite(&tx, &id, &invite)?;
        }
        tx.commit()?;
        Ok(())
    }
    fn outbound_row<T: serde::de::DeserializeOwned>(
        &self,
        conn: &Connection,
        id: &str,
        peer: &str,
        kind: &str,
    ) -> Result<Option<T>, Error> {
        let text: Option<String> = conn
            .query_row(
                "SELECT record FROM conversation_roster_outbound WHERE conversation_id = ?1 AND peer = ?2 AND kind = ?3",
                params![id, peer, kind],
                |r| r.get(0),
            )
            .optional()?;
        text.map(json).transpose()
    }
    fn save_row<T: Serialize>(
        &self,
        conn: &Connection,
        id: &str,
        peer: &str,
        kind: &str,
        record: &T,
    ) -> Result<(), Error> {
        conn.execute(
            "UPDATE conversation_roster_outbound SET record = ?1 WHERE conversation_id = ?2 AND peer = ?3 AND kind = ?4",
            params![serde_json::to_string(record)?, id, peer, kind],
        )?;
        Ok(())
    }
    /// The roster push for its next attempt: the newest roster.
    fn prepare_push(&self, id: &str, peer: &str) -> Result<Option<(Vec<u8>, i64)>, Error> {
        let conn = self.connection()?;
        let Some(push) = self.outbound_row::<Push>(&conn, id, peer, "roster")? else {
            return Ok(None);
        };
        if push.state != "sending" {
            return Ok(None);
        }
        let held = self.held(&conn, id)?;
        Ok(Some((
            serde_json::to_vec(&json!({ "roster": held.roster }))?,
            held.roster.version,
        )))
    }
    fn finish_push(
        &self,
        id: &str,
        peer: &str,
        version: i64,
        outcome: Outcome,
    ) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let Some(mut push) = self.outbound_row::<Push>(&tx, id, peer, "roster")? else {
            return Ok(());
        };
        if push.state != "sending" {
            return Ok(());
        }
        push.attempts += 1;
        let retry = |push: &mut Push, error: String| {
            push.error = Some(error);
            push.next_attempt_at = Some(rfc3339(
                crate::clock::now() + backoff(push.attempts, jitter()),
            ));
        };
        match outcome {
            Outcome::Answer(body) => {
                let held = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|v| v["version"].as_i64());
                match held {
                    Some(v) if v >= push.version => {
                        push.state = "done".into();
                        push.error = None;
                        push.next_attempt_at = None;
                    }
                    _ => retry(&mut push, "the host did not take the roster yet".into()),
                }
            }
            Outcome::Final(_, _, error) => {
                if version >= push.version {
                    push.state = "stopped".into();
                    push.next_attempt_at = None;
                    push.error = Some(error);
                } else {
                    push.next_attempt_at = Some(now());
                }
            }
            Outcome::Retry(error) => retry(&mut push, error),
        }
        self.save_row(&tx, id, peer, "roster", &push)?;
        tx.commit()?;
        Ok(())
    }
    fn prepare_leave(
        &self,
        id: &str,
        peer: &str,
        participant: &str,
    ) -> Result<Option<Vec<u8>>, Error> {
        let conn = self.connection()?;
        let kind = format!("leave:{participant}");
        match self.outbound_row::<Leave>(&conn, id, peer, &kind)? {
            Some(leave) if leave.state == "sending" => Ok(Some(serde_json::to_vec(
                &json!({ "participant": participant }),
            )?)),
            _ => Ok(None),
        }
    }
    fn finish_leave(
        &self,
        id: &str,
        peer: &str,
        participant: &str,
        outcome: Outcome,
    ) -> Result<(), Error> {
        let kind = format!("leave:{participant}");
        let roster = {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let Some(mut leave) = self.outbound_row::<Leave>(&tx, id, peer, &kind)? else {
                return Ok(());
            };
            leave.attempts += 1;
            let mut roster = None;
            match outcome {
                Outcome::Answer(body) => {
                    leave.state = "done".into();
                    leave.next_attempt_at = None;
                    roster = serde_json::from_slice::<Value>(&body)
                        .ok()
                        .and_then(|v| serde_json::from_value::<Roster>(v["roster"].clone()).ok());
                }
                Outcome::Final(_, _, error) => {
                    leave.state = "stopped".into();
                    leave.next_attempt_at = None;
                    leave.error = Some(error);
                }
                Outcome::Retry(error) => {
                    leave.error = Some(error);
                    leave.next_attempt_at = Some(rfc3339(
                        crate::clock::now() + backoff(leave.attempts, jitter()),
                    ));
                }
            }
            self.save_row(&tx, id, peer, &kind, &leave)?;
            tx.commit()?;
            roster
        };
        if let Some(roster) = roster {
            let _ = self.accept_roster(peer, id, roster);
        }
        Ok(())
    }
    /// The home host of a conversation this host holds at a lower roster
    /// version than `version`.
    fn behind(&self, id: &str, version: i64) -> Option<String> {
        let conn = self.connection().ok()?;
        let held = self.held_opt(&conn, id).ok()??;
        (held.roster.version < version && held.roster.home_host_id != self.identity().id)
            .then_some(held.roster.home_host_id)
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
        let held = self.held(&tx, &n.conversation_id)?;
        let roster = held.roster.clone();
        let me = format!("agent:{}/{}", self.identity().id, ss.agent_id);
        let visible = self.visible(&tx, &n.conversation_id, &me)?;
        let position = visible
            .iter()
            .position(|s| Some(&s.message.message_id) == n.message_id.as_ref());
        let first: bool = !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversation_notifications WHERE conversation_id = ?1 AND session_id = ?2 AND id != ?3 AND kind = 'message')",
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
        let summary = self.agent_summary(&tx, &held, &me)?;
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
    fn agent_summary(&self, conn: &Connection, held: &Held, me: &str) -> Result<Value, Error> {
        let roster = &held.roster;
        let agent = participant_parts(me).map(|p| p.2).unwrap_or_default();
        let unseen: i64 = conn.query_row(
            "SELECT COUNT(*) FROM conversation_notifications WHERE conversation_id = ?1 AND agent_id = ?2 AND kind = 'message' AND json_extract(record, '$.forwarded_at') IS NULL",
            params![roster.conversation_id, agent],
            |r| r.get(0),
        )?;
        let visible = self.visible(conn, &roster.conversation_id, me)?;
        let participants = self
            .shown(held)
            .0
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
    /// `GET /adapter/v1/conversations`: open conversations the agent is
    /// joined in, and closed ones it was in with unseen messages.
    pub fn agent_conversations(
        &self,
        auth: &crate::adapter_connection::AdapterAuth,
    ) -> Result<Value, Error> {
        let conn = self.connection()?;
        let (a, ss) = authority(&conn, auth)?;
        crate::directory::directory_access(&a)?;
        let me = format!("agent:{}/{}", self.identity().id, ss.agent_id);
        let mut items = Vec::new();
        for held in self.all_held(&conn)? {
            if !held.joined_here(&me) {
                continue;
            }
            let summary = self.agent_summary(&conn, &held, &me)?;
            if held.roster.state != "open" && summary["unseen"].as_i64().unwrap_or(0) == 0 {
                continue;
            }
            let activity = summary["last_message_at"]
                .as_str()
                .unwrap_or(&held.roster.created_at)
                .to_owned();
            items.push((activity, summary));
        }
        items.sort_by(|a, b| {
            crate::membership::time(&b.0)
                .ok()
                .cmp(&crate::membership::time(&a.0).ok())
        });
        Ok(json!({ "conversations": items.into_iter().map(|(_, v)| v).collect::<Vec<_>>() }))
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
                "SELECT conversation_id, peer, kind, record FROM conversation_roster_outbound",
            )?;
            let rows = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (c, peer, kind, record) in rows {
                let value: Value = serde_json::from_str(&record)?;
                if value["state"] != "sending" {
                    continue;
                }
                let next = value["next_attempt_at"].as_str().map(str::to_owned);
                let Some(when) = due_at(&next).filter(|w| *w <= at) else {
                    continue;
                };
                if kind.starts_with("invite:") {
                    let participant = value["participant"].as_str().unwrap_or_default();
                    due.push((when, "invite".to_owned(), format!("{c} {participant}")));
                } else if kind == "roster" {
                    due.push((when, "push".to_owned(), format!("{c} {peer}")));
                } else if let Some(participant) = kind.strip_prefix("leave:") {
                    due.push((
                        when,
                        "leave".to_owned(),
                        format!("{c} {peer} {participant}"),
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
            match &kind[..] {
                "target" => {
                    let (mut out, _) = self.outbound_record(&tx, parts[0], parts[1], parts[2])?;
                    out.next_attempt_at = Some(when);
                    self.save_outbound(&tx, parts[0], parts[1], &out)?;
                }
                "invite" => {
                    let mut invite = self.invite_record(&tx, parts[0], parts[1])?;
                    invite.next_attempt_at = Some(when);
                    self.save_invite(&tx, parts[0], &invite)?;
                }
                "push" => {
                    if let Some(mut push) =
                        self.outbound_row::<Push>(&tx, parts[0], parts[1], "roster")?
                    {
                        push.next_attempt_at = Some(when);
                        self.save_row(&tx, parts[0], parts[1], "roster", &push)?;
                    }
                }
                _ => {
                    let kind = format!("leave:{}", parts[2]);
                    if let Some(mut leave) =
                        self.outbound_row::<Leave>(&tx, parts[0], parts[1], &kind)?
                    {
                        leave.next_attempt_at = Some(when);
                        self.save_row(&tx, parts[0], parts[1], &kind, &leave)?;
                    }
                }
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
    request(store, peer, "POST", path, body).await
}
async fn request(store: &Arc<Store>, peer: &str, method: &str, path: &str, body: &[u8]) -> Outcome {
    let id = peer.to_owned();
    let target = match blocking(store.clone(), move |s| s.dial_target(&id)).await {
        Ok(t) => t,
        Err(e) => return Outcome::Retry(format!("{e:?}")),
    };
    match tokio::time::timeout(
        ATTEMPT_TIMEOUT,
        crate::quic::request(store.clone(), &target, method, path, body),
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
    } else if kind == "push" {
        let [id, peer] = &parts[..] else {
            return;
        };
        let (i, p) = (id.clone(), peer.clone());
        let Ok(Some((body, version))) =
            blocking(store.clone(), move |s| s.prepare_push(&i, &p)).await
        else {
            return;
        };
        let outcome = send(
            &store,
            peer,
            &format!("/peer/v1/conversations/{id}/roster"),
            &body,
        )
        .await;
        let (i, p) = (id.clone(), peer.clone());
        let _ = blocking(store, move |s| s.finish_push(&i, &p, version, outcome)).await;
    } else if kind == "leave" {
        let [id, peer, participant] = &parts[..] else {
            return;
        };
        let (i, h, p) = (id.clone(), peer.clone(), participant.clone());
        let Ok(Some(body)) = blocking(store.clone(), move |s| s.prepare_leave(&i, &h, &p)).await
        else {
            return;
        };
        let outcome = send(
            &store,
            peer,
            &format!("/peer/v1/conversations/{id}/leave"),
            &body,
        )
        .await;
        let (i, h, p) = (id.clone(), peer.clone(), participant.clone());
        let _ = blocking(store, move |s| s.finish_leave(&i, &h, &p, outcome)).await;
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

fn fetching() -> &'static Mutex<BTreeSet<String>> {
    static FETCHING: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    FETCHING.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// Fetches a conversation's roster from home, at most one at a time per
/// conversation, and stores it as a push.
async fn fetch_roster(store: Arc<Store>, id: String, home: String) {
    if !fetching()
        .lock()
        .map(|mut f| f.insert(id.clone()))
        .unwrap_or(false)
    {
        return;
    }
    let path = format!("/peer/v1/conversations/{id}/roster");
    if let Outcome::Answer(body) = request(&store, &home, "GET", &path, &[]).await
        && let Some(roster) = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| serde_json::from_value::<Roster>(v["roster"].clone()).ok())
    {
        let (i, h) = (id.clone(), home.clone());
        let _ = blocking(store, move |s| s.accept_roster(&h, &i, roster)).await;
    }
    if let Ok(mut f) = fetching().lock() {
        f.remove(&id);
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
    let mut ticks: u32 = 0;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(crate::retry::POLL) => {}
        }
        ticks = ticks.wrapping_add(1);
        if ticks.is_multiple_of(8) {
            let _ = blocking(store.clone(), |s| s.expire_invites()).await;
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
    note: Option<String>,
    #[serde(rename = "as", default, deserialize_with = "crate::policy::present")]
    as_agent: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    network: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterStartRequest {
    participants: Vec<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    title: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    content: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    note: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    message_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
    content: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    message_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManageRequest {
    action: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    participant: Option<String>,
    #[serde(rename = "as", default, deserialize_with = "crate::policy::present")]
    as_agent: Option<String>,
    #[serde(default, deserialize_with = "crate::policy::present")]
    network: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterManageRequest {
    action: String,
    #[serde(default, deserialize_with = "crate::policy::present")]
    participant: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaveRequest {
    #[serde(default, deserialize_with = "crate::policy::present")]
    agent: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterRequest {
    roster: Roster,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerLeaveRequest {
    participant: String,
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
        .route("/v1/conversations/{id}/manage", post(manage))
        .route("/v1/conversations/{id}/leave", post(leave))
}
pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/peer/v1/conversations/invites", post(peer_invite))
        .route("/peer/v1/conversations/{id}/messages", post(peer_message))
        .route(
            "/peer/v1/conversations/{id}/roster",
            get(peer_get_roster).post(peer_roster),
        )
        .route("/peer/v1/conversations/{id}/leave", post(peer_leave))
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/adapter/v1/conversations",
            get(adapter_list).post(adapter_start),
        )
        .route("/adapter/v1/conversations/{id}/messages", post(adapter_say))
        .route(
            "/adapter/v1/conversations/{id}/manage",
            post(adapter_manage),
        )
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

/// Who starts or manages: this host's person, or a local agent with the
/// origin its messages carry.
#[derive(Clone)]
struct Actor {
    participant: String,
    origin: Option<Origin>,
}
impl Actor {
    fn agent(&self) -> Option<String> {
        self.origin.as_ref().map(|o| o.agent_id.clone())
    }
}
/// The actor of an owner request: the agent named by `as`, or the person.
async fn owner_actor(store: &Arc<Store>, agent: Option<String>) -> Result<Actor, Error> {
    blocking(store.clone(), move |s| {
        let conn = s.connection()?;
        match agent {
            Some(agent) => {
                let participant = s.agent_participant(&conn, &agent)?;
                let id = participant_parts(&participant)
                    .map(|p| p.2.to_owned())
                    .unwrap_or_default();
                Ok(Actor {
                    participant,
                    origin: Some(Origin {
                        agent_id: id,
                        session_id: None,
                    }),
                })
            }
            None => Ok(Actor {
                participant: s.person_participant(&conn)?,
                origin: None,
            }),
        }
    })
    .await
}
/// The adapter's agent as actor, once directory access is established.
async fn adapter_actor(store: &Arc<Store>, headers: &HeaderMap) -> Result<Actor, Error> {
    let auth = crate::adapter::token(headers);
    let (participant, origin) = blocking(store.clone(), move |s| s.adapter_author(&auth)).await?;
    Ok(Actor {
        participant,
        origin: Some(origin),
    })
}

/// An agent address only: person forms are C3.
fn agent_address(to: &str) -> Result<(), Error> {
    if to.len() > 256 {
        return Err(invalid("participant is longer than 256 characters"));
    }
    if to.starts_with("person:") || !to.contains('/') {
        return Err(invalid("person participants are not supported yet"));
    }
    Ok(())
}

/// Waits at most 15 seconds for these invites to settle.
async fn wait_invites(
    store: &Arc<Store>,
    id: &str,
    participants: Vec<String>,
) -> Result<(), Error> {
    if participants.is_empty() {
        return Ok(());
    }
    let began = tokio::time::Instant::now();
    let keys = participants
        .iter()
        .map(|p| ("invite".to_owned(), format!("{id} {p}")))
        .collect();
    let handles = dispatch(store, keys);
    for handle in handles {
        let left = START_WAIT.saturating_sub(began.elapsed());
        let _ = tokio::time::timeout(left, handle).await;
    }
    loop {
        let (i, ps) = (id.to_owned(), participants.clone());
        let pending = blocking(store.clone(), move |s| {
            let conn = s.connection()?;
            let mut pending = false;
            for p in &ps {
                if s.invite_opt(&conn, &i, p)?
                    .is_some_and(|v| v.state == "sending")
                {
                    pending = true;
                }
            }
            Ok(pending)
        })
        .await?;
        if !pending || began.elapsed() >= START_WAIT {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

struct Started {
    id: String,
    outcomes: Vec<(String, String, Option<&'static str>)>,
    message: Value,
}

/// Starts a conversation (contract C2, Starting).
#[allow(clippy::too_many_arguments)]
async fn start_conversation(
    store: &Arc<Store>,
    actor: &Actor,
    participants: Vec<String>,
    title: Option<String>,
    content: Option<String>,
    message_id: Option<String>,
    note: Option<String>,
    network: Option<String>,
) -> Result<Started, Error> {
    if participants.is_empty() || participants.len() > MAX_PARTICIPANTS - 1 {
        return Err(invalid("give 1 to 15 participants"));
    }
    let mut seen = BTreeSet::new();
    for to in &participants {
        agent_address(to)?;
        if !seen.insert(to.clone()) {
            return Err(invalid("a participant is given twice"));
        }
    }
    if title.as_deref().is_some_and(|t| !valid_title(t)) {
        return Err(invalid(
            "title must be at most 200 bytes without control characters",
        ));
    }
    if content.as_deref().is_some_and(|c| !valid_content(c)) {
        return Err(invalid("content must be 1 to 65,536 bytes of UTF-8"));
    }
    if note.as_deref().is_some_and(|n| n.len() > MAX_NOTE) {
        return Err(invalid("note must be at most 4,096 bytes"));
    }
    if let Some(m) = &message_id
        && (content.is_none() || !valid_message_id(m))
    {
        return Err(invalid("invalid message_id"));
    }
    let mut targets = Vec::new();
    let mut ids = BTreeSet::from([actor.participant.clone()]);
    for to in &participants {
        let target = crate::directory::resolve_participant(store, to, network.as_deref()).await?;
        if !ids.insert(format!("agent:{}/{}", target.host_id, target.agent_id)) {
            return Err(invalid(
                "two targets name the same participant, or the creator",
            ));
        }
        targets.push((to.clone(), target));
    }
    let origin = actor.agent();
    for (to, target) in &targets {
        if !target.local {
            crate::directory::authorize(
                store,
                to,
                target,
                crate::policy::ACTION,
                origin.as_deref(),
            )
            .await?;
        }
    }
    let creator = actor.participant.clone();
    let (id, outcomes) = blocking(store.clone(), move |s| {
        s.create_conversation(&creator, &targets, title, note)
    })
    .await?;
    let remote: Vec<String> = outcomes
        .iter()
        .filter(|o| o.2.is_none())
        .map(|o| o.1.clone())
        .collect();
    wait_invites(store, &id, remote).await?;
    let message = match content {
        Some(content) => {
            let (i, author, origin) = (id.clone(), actor.participant.clone(), actor.origin.clone());
            let (value, keys) = blocking(store.clone(), move |s| {
                s.author_message(&i, &author, origin, message_id, content)
            })
            .await?;
            dispatch(store, target_keys(keys));
            value["message"].clone()
        }
        None => Value::Null,
    };
    Ok(Started {
        id,
        outcomes,
        message,
    })
}

/// The answer of a start: the creator's view, outcomes, the first message.
async fn started_answer(
    store: &Arc<Store>,
    actor: &Actor,
    started: Started,
    adapter: bool,
) -> Result<Value, Error> {
    let reader = actor.participant.clone();
    blocking(store.clone(), move |s| {
        let conn = s.connection()?;
        let held = s.held(&conn, &started.id)?;
        let mut message = started.message;
        if let Some(mid) = message["message_id"].as_str().map(str::to_owned) {
            message["targets"] = Value::from(s.targets(&conn, &held.roster, &mid)?);
        }
        let invites = started
            .outcomes
            .iter()
            .map(|(given, participant, local)| {
                s.outcome_view(&conn, &held, given, participant, *local)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let conversation = if adapter {
            s.agent_summary(&conn, &held, &reader)?
        } else {
            s.conversation_view(&conn, &held, &reader)?
        };
        Ok(json!({
            "conversation": conversation,
            "invites": invites,
            "message": message,
        }))
    })
    .await
}

async fn start(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let r: StartRequest = decode(body)?;
    if r.participants.is_empty() || r.participants.len() > MAX_PARTICIPANTS - 1 {
        return Err(invalid("give 1 to 15 participants"));
    }
    let actor = owner_actor(&store, r.as_agent).await?;
    let started = start_conversation(
        &store,
        &actor,
        r.participants,
        r.title,
        r.content,
        r.message_id,
        r.note,
        r.network,
    )
    .await?;
    let answer = started_answer(&store, &actor, started, false).await?;
    Ok((StatusCode::CREATED, Json(answer)))
}

/// `add`, `remove`, `close`, and the adapter's `leave`: returns the add's
/// invite outcome, or null.
async fn manage_as(
    store: &Arc<Store>,
    id: String,
    actor: &Actor,
    action: &str,
    participant: Option<String>,
    network: Option<String>,
) -> Result<Value, Error> {
    match (action, &participant) {
        ("add" | "remove", Some(_)) | ("close" | "leave", None) => {}
        ("add" | "remove", None) => return Err(invalid("participant is required")),
        ("close" | "leave", Some(_)) => {
            return Err(invalid("participant is not allowed for this action"));
        }
        _ => return Err(invalid("action must be add, remove, leave or close")),
    }
    if network.is_some() && action != "add" {
        return Err(invalid("network is only for add"));
    }
    let who = actor.participant.clone();
    match action {
        "leave" => {
            blocking(store.clone(), move |s| s.leave_conversation(&id, &who)).await?;
            Ok(Value::Null)
        }
        "close" => {
            blocking(store.clone(), move |s| s.close_conversation(&id, &who)).await?;
            Ok(Value::Null)
        }
        "remove" => {
            let which = participant.unwrap_or_default();
            blocking(store.clone(), move |s| {
                s.remove_participant(&id, &who, &which)
            })
            .await?;
            Ok(Value::Null)
        }
        _ => {
            let to = participant.unwrap_or_default();
            {
                let (i, w) = (id.clone(), who.clone());
                blocking(store.clone(), move |s| {
                    let held = s.creator_check(&*s.connection()?, &i, &w)?;
                    if held.roster.state == "closed" {
                        return Err(closed());
                    }
                    Ok(())
                })
                .await?;
            }
            agent_address(&to)?;
            let target =
                crate::directory::resolve_participant(store, &to, network.as_deref()).await?;
            let participant = format!("agent:{}/{}", target.host_id, target.agent_id);
            let listed = {
                let (i, p) = (id.clone(), participant.clone());
                blocking(store.clone(), move |s| {
                    Ok(Store::listed(&s.held(&*s.connection()?, &i)?, &p))
                })
                .await?
            };
            if !listed && !target.local {
                crate::directory::authorize(
                    store,
                    &to,
                    &target,
                    crate::policy::ACTION,
                    actor.agent().as_deref(),
                )
                .await?;
            }
            let (i, w, t, g) = (id.clone(), who.clone(), target.clone(), to.clone());
            let (local, invited) =
                blocking(store.clone(), move |s| s.add_participant(&i, &w, &t, &g)).await?;
            if invited {
                wait_invites(store, &id, vec![participant.clone()]).await?;
            }
            blocking(store.clone(), move |s| {
                let conn = s.connection()?;
                let held = s.held(&conn, &id)?;
                s.outcome_view(&conn, &held, &to, &participant, local)
            })
            .await
        }
    }
}

async fn manage(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: ManageRequest = decode(body)?;
    if r.action == "leave" {
        return Err(invalid("action must be add, remove or close"));
    }
    if !valid_conversation_id(&id) {
        return Err(Error::NotFound);
    }
    {
        let i = id.clone();
        blocking(store.clone(), move |s| {
            s.held(&*s.connection()?, &i).map(|_| ())
        })
        .await?;
    }
    let actor = owner_actor(&store, r.as_agent).await?;
    let action = r.action.clone();
    let invite = manage_as(
        &store,
        id.clone(),
        &actor,
        &r.action,
        r.participant,
        r.network,
    )
    .await?;
    let reader = actor.participant.clone();
    let view = blocking(store, move |s| {
        let conn = s.connection()?;
        let held = s.held(&conn, &id)?;
        s.conversation_view(&conn, &held, &reader)
    })
    .await?;
    Ok(Json(if action == "add" {
        json!({"conversation": view, "invite": invite})
    } else {
        json!({"conversation": view})
    }))
}

async fn leave(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: LeaveRequest = decode(body)?;
    let participant = blocking(store.clone(), move |s| {
        let conn = s.connection()?;
        match r.agent {
            Some(agent) => s.agent_participant(&conn, &agent),
            None => s.person_participant(&conn),
        }
    })
    .await?;
    let (i, p) = (id.clone(), participant.clone());
    blocking(store.clone(), move |s| s.leave_conversation(&i, &p)).await?;
    let view = blocking(store, move |s| {
        let conn = s.connection()?;
        let held = s.held(&conn, &id)?;
        s.conversation_view(&conn, &held, &participant)
    })
    .await?;
    Ok(Json(json!({ "conversation": view })))
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
    let version = r.message.roster_version;
    let (s2, i) = (sender.clone(), id.clone());
    let result = blocking(store.clone(), move |s| {
        s.accept_conversation_message(&s2, &i, r)
    })
    .await;
    if let Err(Error::Unavailable(_)) = &result {
        let i = id.clone();
        if let Ok(Some(home)) = blocking(store.clone(), move |s| Ok(s.behind(&i, version))).await {
            tokio::spawn(fetch_roster(store, id, home));
        }
    }
    Ok(Json(result?))
}
async fn peer_roster(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: RosterRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.accept_roster(&sender, &id, r.roster)).await?,
    ))
}
async fn peer_get_roster(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.serve_roster(&sender, &id)).await?,
    ))
}
async fn peer_leave(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: PeerLeaveRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.accept_leave(&sender, &id, &r.participant)).await?,
    ))
}

async fn adapter_list(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    let auth = crate::adapter::token(&headers);
    Ok(Json(
        blocking(store, move |s| s.agent_conversations(&auth)).await?,
    ))
}
async fn adapter_start(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let actor = adapter_actor(&store, &headers).await?;
    let r: AdapterStartRequest = decode(body)?;
    let started = start_conversation(
        &store,
        &actor,
        r.participants,
        r.title,
        r.content,
        r.message_id,
        r.note,
        None,
    )
    .await?;
    let answer = started_answer(&store, &actor, started, true).await?;
    Ok((StatusCode::CREATED, Json(answer)))
}
async fn adapter_manage(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let actor = adapter_actor(&store, &headers).await?;
    let r: AdapterManageRequest = decode(body)?;
    if !valid_conversation_id(&id) {
        return Err(Error::NotFound);
    }
    {
        let i = id.clone();
        blocking(store.clone(), move |s| {
            s.held(&*s.connection()?, &i).map(|_| ())
        })
        .await?;
    }
    let invite = manage_as(&store, id.clone(), &actor, &r.action, r.participant, None).await?;
    let me = actor.participant.clone();
    let summary = blocking(store, move |s| {
        let conn = s.connection()?;
        let held = s.held(&conn, &id)?;
        s.agent_summary(&conn, &held, &me)
    })
    .await?;
    Ok(Json(json!({"conversation": summary, "invite": invite})))
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
