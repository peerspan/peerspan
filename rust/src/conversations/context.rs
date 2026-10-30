//! Session context, contract C5: the handoff recheck, what an agent's
//! session may see, seen tracking, returning and redelivering notifications,
//! coalesced catch-up, `pending_work.conversations`, `conversation_history`,
//! and `conversation_undelivered` notifications.
use super::{
    Empty, Notification, Outbound, PageQueryAdapter, Stored, WINDOW_BYTES, WINDOW_CUT,
    WINDOW_MESSAGES, cut, invalid, not_participant, participant_parts, valid_conversation_id,
    valid_message_id,
};
use crate::{
    adapter_connection::{AdapterAuth, authority, verified_authority},
    api::{blocking, decode},
    live_delivery::{Ended, MAX_REDELIVERIES},
    model::Error,
    peer_store::json,
    store::{Store, new_id, now},
};
use axum::{
    Json,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    http::HeaderMap,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

const HISTORY_BYTES: usize = 262_144;
const HISTORY_LIMIT: i64 = 50;
const PREVIEW: usize = 200;

/// The outcome of the handoff recheck (contract C5).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Recheck {
    Pass,
    Fail,
    Wait,
}

/// One row of `conversation_notifications`.
struct Row {
    id: String,
    kind: String,
    conversation_id: String,
    message_id: Option<String>,
    session_id: Option<String>,
    seen: bool,
    returned: bool,
    redeliveries: i64,
    n: Notification,
}
impl Row {
    fn open(&self) -> bool {
        !self.seen && self.n.blocked_at.is_none() && self.n.exhausted_at.is_none()
    }
    fn claimable(&self) -> bool {
        self.open() && (self.session_id.is_none() || self.returned)
    }
    fn holds(&self, session: &str) -> bool {
        !self.returned && self.session_id.as_deref() == Some(session)
    }
}
const ROW: &str = "SELECT id, kind, conversation_id, message_id, session_id, seen_at IS NOT NULL, returned_at IS NOT NULL, redeliveries, record FROM conversation_notifications";
fn rows(conn: &Connection, filter: &str, values: &[&str]) -> Result<Vec<Row>, Error> {
    let mut statement = conn.prepare(&format!("{ROW} WHERE {filter} ORDER BY rowid"))?;
    let found = statement
        .query_map(rusqlite::params_from_iter(values), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, bool>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    found
        .into_iter()
        .map(|x| {
            Ok(Row {
                id: x.0,
                kind: x.1,
                conversation_id: x.2,
                message_id: x.3,
                session_id: x.4,
                seen: x.5,
                returned: x.6,
                redeliveries: x.7,
                n: json(x.8)?,
            })
        })
        .collect()
}
fn save(conn: &Connection, row: &Row) -> Result<(), Error> {
    conn.execute(
        "UPDATE conversation_notifications SET record = ?1 WHERE id = ?2",
        params![serde_json::to_string(&row.n)?, row.id],
    )?;
    Ok(())
}
/// Whether the authorization holding a notification has ended. A
/// notification claimed before this version names only its session.
fn holder_ended(conn: &Connection, row: &Row, ended: &mut Ended) -> Result<bool, Error> {
    let adapter = match &row.n.adapter_id {
        Some(a) => Some(a.clone()),
        None => conn
            .query_row(
                "SELECT id FROM adapter_credentials WHERE session_id = ?1 ORDER BY rowid DESC LIMIT 1",
                [&row.session_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?,
    };
    match adapter {
        Some(a) => ended.check(conn, &a),
        None => Ok(true),
    }
}
/// Held by a session that has not ended.
fn held_live(conn: &Connection, row: &Row, ended: &mut Ended) -> Result<bool, Error> {
    Ok(row.session_id.is_some() && !row.returned && !holder_ended(conn, row, ended)?)
}

/// The notification object of the adapter routes.
pub(super) fn notification_view(conn: &Connection, n: &Notification) -> Result<Value, Error> {
    let (seen_at, redeliveries): (Option<String>, i64) = conn.query_row(
        "SELECT seen_at, redeliveries FROM conversation_notifications WHERE id = ?1",
        [&n.id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(json!({
        "id": n.id,
        "kind": n.kind,
        "conversation_id": n.conversation_id,
        "message_id": n.message_id,
        "session_id": n.session_id,
        "created_at": n.created_at,
        "claimed_at": n.claimed_at,
        "forwarded_at": n.forwarded_at,
        "change": n.change,
        "undelivered": n.undelivered,
        "seen_at": seen_at,
        "redeliveries": redeliveries,
    }))
}

/// Returns what an agent's ended authorizations left unseen, as a verified
/// session of the agent claims work or lists its pending work.
pub(crate) fn return_notifications(
    store: &Store,
    tx: &Transaction<'_>,
    agent: &str,
    ended: &mut Ended,
    at: &str,
) -> Result<(), Error> {
    let me = format!("agent:{}/{agent}", store.identity().id);
    for mut row in rows(
        tx,
        "agent_id = ?1 AND session_id IS NOT NULL AND seen_at IS NULL AND returned_at IS NULL",
        &[agent],
    )? {
        if !row.open() || !holder_ended(tx, &row, ended)? {
            continue;
        }
        if row.kind == "message"
            && !store
                .held_opt(tx, &row.conversation_id)?
                .is_some_and(|h| h.joined_here(&me))
        {
            tx.execute(
                "DELETE FROM conversation_notifications WHERE id = ?1",
                [&row.id],
            )?;
        } else if row.redeliveries < MAX_REDELIVERIES {
            tx.execute(
                "UPDATE conversation_notifications SET returned_at = ?1 WHERE id = ?2",
                params![at, row.id],
            )?;
        } else {
            row.n.exhausted_at = Some(at.to_owned());
            save(tx, &row)?;
        }
    }
    Ok(())
}

/// `POST /adapter/v1/seen` for a `conv_` or `cmsg_` ID: whether this session
/// holds it, and whether anything became seen.
pub(crate) fn mark_seen_id(
    tx: &Transaction<'_>,
    session: &str,
    id: &str,
    at: &str,
) -> Result<(bool, bool), Error> {
    let column = if id.starts_with("conv_") {
        "conversation_id"
    } else {
        "message_id"
    };
    let held: Vec<Row> = rows(
        tx,
        &format!(
            "{column} = ?1 AND session_id = ?2 AND returned_at IS NULL AND json_extract(record, '$.blocked_at') IS NULL"
        ),
        &[id, session],
    )?;
    if held.is_empty() {
        return Ok((false, false));
    }
    let mut changed = 0;
    for row in &held {
        for target in std::iter::once(&row.id).chain(row.n.coalesced.iter()) {
            changed += tx.execute(
                "UPDATE conversation_notifications SET seen_at = ?1 WHERE id = ?2 AND session_id = ?3 AND seen_at IS NULL AND returned_at IS NULL",
                params![at, target, session],
            )?;
        }
    }
    Ok((true, changed > 0))
}

impl Store {
    /// The handoff recheck of `message` for local agent `agent`: C4's
    /// fetched-message step 6, evaluated now.
    pub(super) fn recheck(
        &self,
        conn: &Connection,
        stored: &Stored,
        agent: &str,
    ) -> Result<Recheck, Error> {
        let m = &stored.message;
        let Some((_, host, _)) = participant_parts(&m.author) else {
            return Ok(Recheck::Fail);
        };
        if host == self.identity().id {
            return Ok(Recheck::Pass);
        }
        let authorized = self.conversation_authorize(
            conn,
            host,
            (None, None, None),
            agent,
            m.content.len(),
            m.origin.as_ref(),
        );
        match authorized {
            Ok(()) => Ok(Recheck::Pass),
            Err(Error::Forbidden) if self.own_policy_current(conn, host)? => Ok(Recheck::Fail),
            Err(Error::Forbidden | Error::Unavailable(_)) => Ok(Recheck::Wait),
            Err(e) => Err(e),
        }
    }
    fn stored_message(
        &self,
        conn: &Connection,
        conversation: &str,
        message: &str,
    ) -> Result<Option<Stored>, Error> {
        let record: Option<String> = conn
            .query_row(
                "SELECT record FROM conversation_messages WHERE conversation_id = ?1 AND message_id = ?2",
                params![conversation, message],
                |r| r.get(0),
            )
            .optional()?;
        record.map(json).transpose()
    }
    fn recheck_row(&self, conn: &Connection, row: &Row, agent: &str) -> Result<Recheck, Error> {
        let Some(message) = &row.message_id else {
            return Ok(Recheck::Fail);
        };
        match self.stored_message(conn, &row.conversation_id, message)? {
            Some(stored) => self.recheck(conn, &stored, agent),
            None => Ok(Recheck::Fail),
        }
    }
    /// Keeps of `messages` those visible to local agent `agent` (contract
    /// C5, What an agent may see).
    pub(super) fn visible_to_agent(
        &self,
        conn: &Connection,
        conversation: &str,
        reader: &str,
        agent: &str,
        messages: Vec<Stored>,
    ) -> Result<Vec<Stored>, Error> {
        let notifications: HashMap<String, Row> = rows(
            conn,
            "conversation_id = ?1 AND agent_id = ?2 AND kind = 'message'",
            &[conversation, agent],
        )?
        .into_iter()
        .filter_map(|r| r.message_id.clone().map(|m| (m, r)))
        .collect();
        let mut ended = Ended::default();
        let mut kept = Vec::with_capacity(messages.len());
        for stored in messages {
            let show = stored.message.author == reader
                || match notifications.get(&stored.message.message_id) {
                    Some(row) if row.n.blocked_at.is_none() => {
                        row.seen
                            || held_live(conn, row, &mut ended)?
                            || self.recheck(conn, &stored, agent)? == Recheck::Pass
                    }
                    _ => false,
                };
            if show {
                kept.push(stored);
            }
        }
        Ok(kept)
    }
    /// Whether a message notification counts in `unseen`.
    fn counted(
        &self,
        conn: &Connection,
        row: &Row,
        agent: &str,
        ended: &mut Ended,
    ) -> Result<bool, Error> {
        if row.kind != "message" || !row.open() {
            return Ok(false);
        }
        if held_live(conn, row, ended)? {
            return Ok(true);
        }
        if row.session_id.is_some() && !row.returned && row.redeliveries >= MAX_REDELIVERIES {
            return Ok(false);
        }
        Ok(self.recheck_row(conn, row, agent)? == Recheck::Pass)
    }
    /// `unseen` of the agent summary.
    pub(super) fn unseen(
        &self,
        conn: &Connection,
        conversation: &str,
        agent: &str,
    ) -> Result<i64, Error> {
        let mut ended = Ended::default();
        let mut count = 0;
        for row in rows(
            conn,
            "conversation_id = ?1 AND agent_id = ?2 AND kind = 'message' AND seen_at IS NULL",
            &[conversation, agent],
        )? {
            if self.counted(conn, &row, agent, &mut ended)? {
                count += 1;
            }
        }
        Ok(count)
    }
    /// The session's notifications become seen, after a successful
    /// conversation tool call.
    pub(super) fn conversation_seen(
        &self,
        auth: &AdapterAuth,
        conversation: &str,
    ) -> Result<(), Error> {
        let conn = self.connection()?;
        let (_, ss) = authority(&conn, auth)?;
        conn.execute(
            "UPDATE conversation_notifications SET seen_at = ?1 WHERE conversation_id = ?2 AND session_id = ?3 AND seen_at IS NULL AND returned_at IS NULL AND json_extract(record, '$.blocked_at') IS NULL",
            params![now(), conversation, ss.id],
        )?;
        Ok(())
    }
    fn block_notification(&self, tx: &Transaction<'_>, row: &mut Row) -> Result<(), Error> {
        row.n.blocked_at = Some(now());
        tx.execute(
            "UPDATE conversation_notifications SET returned_at = NULL WHERE id = ?1",
            [&row.id],
        )?;
        save(tx, row)
    }
    fn bind(
        &self,
        tx: &Transaction<'_>,
        row: &mut Row,
        session: &str,
        adapter: &str,
        at: &str,
    ) -> Result<(), Error> {
        let again = row.returned;
        row.n.session_id = Some(session.to_owned());
        row.n.adapter_id = Some(adapter.to_owned());
        row.n.claimed_at = Some(at.to_owned());
        tx.execute(
            "UPDATE conversation_notifications SET session_id = ?1, returned_at = NULL, redeliveries = redeliveries + ?2 WHERE id = ?3",
            params![session, i64::from(again), row.id],
        )?;
        save(tx, row)
    }
    /// `POST /adapter/v1/conversation-notifications/next`.
    pub fn claim_conversation_notification(
        &self,
        auth: &AdapterAuth,
    ) -> Result<Option<Value>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = verified_authority(&tx, auth)?;
        if !a.directory {
            return Ok(None);
        }
        crate::live_delivery::return_items(self, &tx, &ss.agent_id)?;
        let at = now();
        let mut claim = None;
        for mut row in rows(&tx, "agent_id = ?1", &[&ss.agent_id])? {
            if !row.claimable() {
                continue;
            }
            if row.kind == "message" {
                match self.recheck_row(&tx, &row, &ss.agent_id)? {
                    Recheck::Pass => {}
                    Recheck::Wait => continue,
                    Recheck::Fail => {
                        self.block_notification(&tx, &mut row)?;
                        continue;
                    }
                }
            }
            let catch_up = row.kind == "message" && row.returned;
            let redelivered = row.returned;
            self.bind(&tx, &mut row, &ss.id, &a.id, &at)?;
            let mut bound = Vec::new();
            if catch_up {
                for mut other in rows(
                    &tx,
                    "agent_id = ?1 AND conversation_id = ?2 AND kind = 'message' AND returned_at IS NOT NULL AND seen_at IS NULL",
                    &[&ss.agent_id, &row.conversation_id],
                )? {
                    if !other.claimable() {
                        continue;
                    }
                    match self.recheck_row(&tx, &other, &ss.agent_id)? {
                        Recheck::Pass => {
                            self.bind(&tx, &mut other, &ss.id, &a.id, &at)?;
                            bound.push(other);
                        }
                        Recheck::Wait => {}
                        Recheck::Fail => self.block_notification(&tx, &mut other)?,
                    }
                }
            }
            claim = Some(self.claim_answer(&tx, &ss, row, bound, catch_up, redelivered)?);
            break;
        }
        tx.commit()?;
        Ok(claim)
    }
    fn claim_answer(
        &self,
        tx: &Transaction<'_>,
        ss: &crate::model::Session,
        first_row: Row,
        others: Vec<Row>,
        catch_up: bool,
        redelivered: bool,
    ) -> Result<Value, Error> {
        let conversation = first_row.conversation_id.clone();
        let held = self.held(tx, &conversation)?;
        let roster = held.roster.clone();
        let me = format!("agent:{}/{}", self.identity().id, ss.agent_id);
        let visible = self.visible(tx, &conversation, &me)?;
        // The newest claimed message in display order is the new message.
        let mut claimed: Vec<Row> = std::iter::once(first_row).chain(others).collect();
        let place = |row: &Row| {
            visible
                .iter()
                .position(|s| Some(&s.message.message_id) == row.message_id.as_ref())
        };
        claimed.sort_by_key(place);
        let mut newest = claimed.pop().ok_or(Error::NotFound)?;
        let coalesced: Vec<String> = claimed.iter().map(|r| r.id.clone()).collect();
        if !coalesced.is_empty() {
            newest.n.coalesced = coalesced.clone();
            save(tx, &newest)?;
        }
        let first: bool = !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversation_notifications WHERE conversation_id = ?1 AND session_id = ?2 AND id != ?3 AND kind = 'message' AND returned_at IS NULL)",
            params![conversation, ss.id, newest.id],
            |r| r.get::<_, bool>(0),
        )?;
        let mut messages = Vec::new();
        let mut window = Vec::new();
        let mut window_total = 0;
        if newest.kind == "message"
            && let Some(position) = place(&newest)
        {
            messages.push(self.adapter_message(tx, &roster, &visible[position], &me, None)?);
            if first || catch_up {
                window_total = position;
                let mut bytes = 0;
                for s in visible[..position].iter().rev() {
                    let length = cut(&s.message.content, WINDOW_CUT).len();
                    if window.len() == WINDOW_MESSAGES || bytes + length > WINDOW_BYTES {
                        break;
                    }
                    bytes += length;
                    window.push(self.adapter_message(tx, &roster, s, &me, Some(WINDOW_CUT))?);
                }
                window.reverse();
            }
        }
        let summary = self.agent_summary(tx, &held, &me)?;
        Ok(json!({
            "notification": notification_view(tx, &newest.n)?,
            "conversation": summary,
            "messages": messages,
            "window": window,
            "window_total": window_total,
            "catch_up": catch_up,
            "coalesced": coalesced,
            "redelivered": redelivered,
        }))
    }
    /// `POST .../forwarded` also marks what the catch-up coalesced.
    pub(super) fn forward_coalesced(
        &self,
        conn: &Connection,
        n: &Notification,
        agent: &str,
    ) -> Result<(), Error> {
        for id in &n.coalesced {
            for mut row in rows(conn, "id = ?1 AND agent_id = ?2", &[id, agent])? {
                if row.n.forwarded_at.is_none() {
                    row.n.forwarded_at = n.forwarded_at.clone();
                    save(conn, &row)?;
                }
            }
        }
        Ok(())
    }
    /// One `undelivered` notification per (message, target), for a message
    /// of a local agent still joined here.
    pub(super) fn note_undelivered(
        &self,
        conn: &Connection,
        conversation: &str,
        message: &str,
        o: &Outbound,
    ) -> Result<(), Error> {
        if !matches!(&o.state[..], "refused" | "unsupported" | "stopped") {
            return Ok(());
        }
        let Some(stored) = self.stored_message(conn, conversation, message)? else {
            return Ok(());
        };
        let author = &stored.message.author;
        let own = self.identity().id;
        let agent = match participant_parts(author) {
            Some(("agent", host, agent)) if host == own => agent,
            _ => return Ok(()),
        };
        let held = self.held(conn, conversation)?;
        let noted: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversation_notifications WHERE conversation_id = ?1 AND message_id = ?2 AND kind = 'undelivered' AND json_extract(record, '$.undelivered.participant') = ?3)",
            params![conversation, message, o.participant],
            |r| r.get(0),
        )?;
        if noted || !held.joined_here(author) {
            return Ok(());
        }
        let n = Notification {
            id: new_id("cnot")?,
            kind: "undelivered".into(),
            conversation_id: conversation.into(),
            message_id: Some(message.into()),
            session_id: None,
            created_at: now(),
            claimed_at: None,
            forwarded_at: None,
            change: None,
            undelivered: Some(json!({
                "participant": o.participant,
                "label": self.label_of(conn, &held.roster, &o.participant)?,
                "state": o.state,
                "code": o.code,
                "error": o.error,
                "preview": stored.message.content.chars().take(PREVIEW).collect::<String>(),
            })),
            adapter_id: None,
            blocked_at: None,
            exhausted_at: None,
            coalesced: Vec::new(),
        };
        conn.execute(
            "INSERT INTO conversation_notifications (id, conversation_id, kind, message_id, agent_id, session_id, record) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
            params![n.id, conversation, n.kind, message, agent, serde_json::to_string(&n)?],
        )?;
        Ok(())
    }
    /// `pending_work.conversations` for a session of `agent`.
    pub(crate) fn pending_conversations(
        &self,
        conn: &Connection,
        session: &str,
        agent: &str,
        directory: bool,
    ) -> Result<Vec<Value>, Error> {
        if !directory {
            return Ok(Vec::new());
        }
        let me = format!("agent:{}/{agent}", self.identity().id);
        let mut ended = Ended::default();
        let mut per: Vec<(String, Vec<String>)> = Vec::new();
        for row in rows(
            conn,
            "agent_id = ?1 AND kind = 'message' AND seen_at IS NULL",
            &[agent],
        )? {
            let listed = if row.holds(session) {
                row.open()
            } else if held_live(conn, &row, &mut ended)? {
                false
            } else {
                self.counted(conn, &row, agent, &mut ended)?
            };
            let Some(message) = row.message_id.clone().filter(|_| listed) else {
                continue;
            };
            match per.iter_mut().find(|(c, _)| *c == row.conversation_id) {
                Some((_, list)) => list.push(message),
                None => per.push((row.conversation_id.clone(), vec![message])),
            }
        }
        let mut items = Vec::new();
        for (conversation, ids) in per {
            let Some(held) = self.held_opt(conn, &conversation)? else {
                continue;
            };
            if !held.joined_here(&me) {
                continue;
            }
            let mut messages = Vec::new();
            for id in &ids {
                if let Some(stored) = self.stored_message(conn, &conversation, id)? {
                    let local: i64 = conn.query_row(
                        "SELECT local_seq FROM conversation_messages WHERE conversation_id = ?1 AND message_id = ?2",
                        params![conversation, id],
                        |r| r.get(0),
                    )?;
                    messages.push((local, stored));
                }
            }
            let earliest = messages.iter().map(|m| m.0).min().unwrap_or(i64::MAX);
            let addressed = messages.iter().any(|(_, s)| {
                s.message
                    .addressed_to
                    .as_ref()
                    .is_none_or(|t| t.is_empty() || t.contains(&me))
            });
            let Some((_, latest)) = messages.iter().max_by(|x, y| {
                let key = |s: &Stored| {
                    (
                        s.message.clock,
                        s.message.author.clone().into_bytes(),
                        s.message.seq,
                    )
                };
                key(&x.1).cmp(&key(&y.1))
            }) else {
                continue;
            };
            items.push((
                earliest,
                json!({
                    "conversation_id": conversation,
                    "title": held.roster.title,
                    "unseen": messages.len(),
                    "addressed": addressed,
                    "latest": {
                        "message_id": latest.message.message_id,
                        "author_label": self.label_of(conn, &held.roster, &latest.message.author)?,
                        "preview": latest.message.content.chars().take(PREVIEW).collect::<String>(),
                    },
                }),
            ));
        }
        items.sort_by_key(|x| x.0);
        Ok(items.into_iter().map(|x| x.1).collect())
    }
    /// `GET /adapter/v1/conversations/{id}/messages`.
    fn adapter_history(
        &self,
        auth: &AdapterAuth,
        id: &str,
        query: Result<PageQueryAdapter, Error>,
    ) -> Result<Value, Error> {
        let conn = self.connection()?;
        let (a, ss) = authority(&conn, auth)?;
        crate::directory::directory_access(&a)?;
        let q = query?;
        let limit = q.limit.unwrap_or(20);
        if !valid_conversation_id(id)
            || !(1..=HISTORY_LIMIT).contains(&limit)
            || q.before.as_deref().is_some_and(|b| !valid_message_id(b))
        {
            return Err(invalid("invalid conversation history request"));
        }
        let held = self.held(&conn, id)?;
        let me = format!("agent:{}/{}", self.identity().id, ss.agent_id);
        if !held.joined_here(&me) {
            return Err(not_participant());
        }
        let visible = self.visible(&conn, id, &me)?;
        let end = match &q.before {
            None => visible.len(),
            Some(before) => visible
                .iter()
                .position(|s| &s.message.message_id == before)
                .ok_or_else(|| invalid("unknown before message"))?,
        };
        let mut start = end;
        let mut bytes = 0;
        while start > 0 && end - start < limit as usize {
            let length = visible[start - 1].message.content.len();
            if start < end && bytes + length > HISTORY_BYTES {
                break;
            }
            bytes += length;
            start -= 1;
        }
        let messages = visible[start..end]
            .iter()
            .map(|s| {
                let mut view =
                    self.adapter_message(&conn, &held.roster, s, &me, Some(HISTORY_BYTES))?;
                view["targets"] = if s.message.author == me {
                    Value::from(self.targets(&conn, &held.roster, &s.message.message_id)?)
                } else {
                    Value::Null
                };
                Ok(view)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let summary = self.agent_summary(&conn, &held, &me)?;
        Ok(json!({
            "messages": messages,
            "next_before_message_id": if start > 0 { Value::from(visible[start].message.message_id.clone()) } else { Value::Null },
            "participants": summary["participants"],
        }))
    }
}

pub(super) async fn adapter_history(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<PageQueryAdapter>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let auth = crate::adapter::token(&headers);
    let query = query
        .map(|Query(q)| q)
        .map_err(|_| invalid("invalid query"));
    Ok(Json(
        blocking(store, move |s| {
            let value = s.adapter_history(&auth, &id, query)?;
            s.conversation_seen(&auth, &id)?;
            Ok(value)
        })
        .await?,
    ))
}
pub(super) async fn adapter_next(
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
