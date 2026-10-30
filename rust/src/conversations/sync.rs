//! Catch-up, contract C4: the 24-hour push window and `stopped`, gap
//! detection through `prev_seq`, the `heads`, `messages` and `acks` peer
//! routes, and the conversation sync (roster first) at startup, every 10
//! minutes, after a roster change, on request, and after close until every
//! host is complete or 30 days pass.
use super::{
    Held, Inbound, Message, MessageRequest, Outbound, Outcome, Push, Roster, Stored, classify,
    invalid, participant_parts, unavailable, valid_conversation_id,
};
use crate::{
    api::{blocking, decode},
    model::Error,
    peer_store::json,
    store::{Store, now},
};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

/// How long the author's host pushes a message, and home a roster version.
const PUSH_WINDOW_SECONDS: i64 = 24 * 3600;
/// How often each conversation is synced.
const SYNC_EVERY_SECONDS: i64 = 600;
/// How long after close a host keeps syncing with an unanswering host.
const CLOSED_SYNC_SECONDS: i64 = 30 * 24 * 3600;
/// Each peer request of a sync.
const SYNC_REQUEST: Duration = Duration::from_secs(5);
/// Conversation syncs at once per daemon.
const SYNCS: usize = 4;
/// The largest page of fetched messages, in encoded bytes.
const PAGE_BYTES: usize = 900_000;
const PAGE_LIMIT: i64 = 100;
/// Pages one fetch takes; the rest waits for the next sync.
const FETCH_PAGES: usize = 100;
const MAX_COUNTER: i64 = (1 << 53) - 1;
const STOPPED: &str =
    "retries stopped 24 hours after sending; the recipient's host fetches it when it syncs";

fn time(text: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    crate::membership::time(text).ok()
}
fn passed(since: &str, seconds: i64) -> bool {
    time(since).is_some_and(|t| t + chrono::TimeDelta::seconds(seconds) <= crate::clock::now())
}
/// Whether a message sent at `sent_at` is past its 24-hour push window.
pub(super) fn push_window_over(sent_at: &str) -> bool {
    passed(sent_at, PUSH_WINDOW_SECONDS)
}
pub(super) fn stop(out: &mut Outbound) {
    out.state = "stopped".into();
    out.code = None;
    out.error = Some(STOPPED.into());
    out.next_attempt_at = None;
}

/// A fetched message this host refused for a target with a final code: it
/// resolves that `seq` of the chain and is reported in the next `acks`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Refused {
    author: String,
    seq: i64,
    prev_seq: Option<i64>,
    code: String,
    refused_at: String,
    #[serde(default)]
    acked: bool,
}

/// The answer to a push of a message already refused at a fetch.
pub(super) fn saved_refusal(record: String) -> Result<Error, Error> {
    let refused: Refused = json(record)?;
    Ok(match &refused.code[..] {
        "not_participant" => super::not_participant(),
        "closed" => super::closed(),
        "conflict" => Error::Conflict("message ID reused with different fields".into()),
        "invalid" => invalid("refused as invalid at a fetch"),
        _ => Error::Forbidden,
    })
}

/// This host's sync with one other participant host, in
/// `conversation_roster_outbound` with `kind` `sync` (never `sending`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SyncPeer {
    /// `pending`, `complete` or `unsynced`.
    state: String,
    /// The `through_seq` of the last answered ack, per `AUTHOR TARGET`.
    #[serde(default)]
    acked: BTreeMap<String, i64>,
}

// ---------------------------------------------------------------- in-memory schedule

struct Schedule {
    /// When each conversation's last sync started (this host's clock).
    last: BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    /// Conversations to sync at the next pass (a roster change).
    now: BTreeSet<String>,
    /// Gap fetches running: `CONVERSATION PEER AUTHOR TARGET`.
    gaps: BTreeSet<String>,
}
fn schedule_state() -> &'static Mutex<Schedule> {
    static S: OnceLock<Mutex<Schedule>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(Schedule {
            last: BTreeMap::new(),
            now: BTreeSet::new(),
            gaps: BTreeSet::new(),
        })
    })
}
fn permits() -> &'static Arc<tokio::sync::Semaphore> {
    static P: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    P.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(SYNCS)))
}
/// One lock per conversation: at most one sync of it at a time.
fn lock_of(id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static L: OnceLock<Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let map = L.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut map = map.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(id.to_owned()).or_default().clone()
}
/// Syncs this conversation at the next pass (a newer roster was stored).
pub(super) fn due_now(id: &str) {
    if let Ok(mut s) = schedule_state().lock() {
        s.now.insert(id.to_owned());
    }
}

// ---------------------------------------------------------------- store

/// What a page of fetched messages did.
struct Page {
    accepted: usize,
    /// Processing stopped early: the rest waits for the next sync.
    stopped: bool,
}

/// One conversation's sync plan: the roster held, the local targets, and
/// for each other participant host whether to ask it.
struct Plan {
    roster: Roster,
    targets: Vec<String>,
    /// Host, and its state when not to be asked (`complete`, `unsynced`).
    hosts: Vec<(String, Option<String>)>,
}

impl Store {
    /// Whether this host holds a current `policy` statement of its own
    /// person in a network it shares with `sender`.
    pub(super) fn own_policy_current(
        &self,
        conn: &Connection,
        sender: &str,
    ) -> Result<bool, Error> {
        let shared: BTreeSet<String> = self
            .product_members_of(conn, sender)?
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        for (network, own) in self.own_members(conn)? {
            let Some(person) = own.person_id else {
                continue;
            };
            if !shared.contains(&network) {
                continue;
            }
            let Some(key) = self.product_person_key(conn, &network, &person)? else {
                continue;
            };
            if self.product_policy(conn, &network, &key)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Marks overdue message targets and roster pushes `stopped`.
    pub(super) fn stop_overdue(&self) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let rows: Vec<(String, String, String, String)> = {
            let mut q = tx.prepare(
                "SELECT t.conversation_id, t.message_id, t.record, m.record FROM conversation_targets t JOIN conversation_messages m ON m.conversation_id = t.conversation_id AND m.message_id = t.message_id WHERE t.direction = 'out' AND t.state = 'sending'",
            )?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?
        };
        for (id, message, out, stored) in rows {
            let stored: Stored = json(stored)?;
            if !push_window_over(&stored.message.sent_at) {
                continue;
            }
            let mut out: Outbound = json(out)?;
            stop(&mut out);
            self.save_outbound(&tx, &id, &message, &out)?;
        }
        let pushes: Vec<(String, String, String)> = {
            let mut q = tx.prepare(
                "SELECT conversation_id, peer, record FROM conversation_roster_outbound WHERE kind = 'roster'",
            )?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?
        };
        for (id, peer, record) in pushes {
            let mut push: Push = json(record)?;
            if push.state != "sending"
                || !push
                    .created_at
                    .as_deref()
                    .is_some_and(|at| passed(at, PUSH_WINDOW_SECONDS))
            {
                continue;
            }
            push.state = "stopped".into();
            push.next_attempt_at = None;
            push.error = Some(
                "pushes stop 24 hours after the version; the host fetches it when it syncs".into(),
            );
            self.save_row(&tx, &id, &peer, "roster", &push)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The `seq`s this host resolved for `target` from `author` (accepted
    /// or refused at a fetch), with their `prev_seq`, and the unacked
    /// refusals.
    fn chain(
        &self,
        conn: &Connection,
        id: &str,
        author: &str,
        target: &str,
    ) -> Result<(i64, Vec<(i64, String)>), Error> {
        let host = participant_parts(author).map(|p| p.1).unwrap_or_default();
        let rows: Vec<(String, String)> = {
            let mut q = conn.prepare(
                "SELECT state, record FROM conversation_targets WHERE conversation_id = ?1 AND target = ?2 AND direction = 'in' AND peer = ?3",
            )?;
            q.query_map(params![id, target, host], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        let mut next: BTreeMap<Option<i64>, i64> = BTreeMap::new();
        let mut starts = Vec::new();
        let mut refused = Vec::new();
        for (state, record) in rows {
            let (from, seq, prev) = if state == "refused" {
                let r: Refused = json(record)?;
                if r.author == author && !r.acked {
                    refused.push((r.seq, r.code.clone()));
                }
                (r.author, r.seq, r.prev_seq)
            } else {
                let r: Inbound = json(record)?;
                (r.message.author, r.message.seq, r.prev_seq)
            };
            if from != author {
                continue;
            }
            match prev {
                None => starts.push(seq),
                Some(p) => {
                    let e = next.entry(Some(p)).or_insert(seq);
                    *e = (*e).min(seq);
                }
            }
        }
        let mut head = starts.into_iter().max().unwrap_or(0);
        while let Some(&n) = next.get(&Some(head)) {
            if n <= head {
                break;
            }
            head = n;
        }
        refused.sort();
        Ok((head, refused))
    }
    fn chain_head(&self, id: &str, author: &str, target: &str) -> Result<i64, Error> {
        Ok(self.chain(&*self.connection()?, id, author, target)?.0)
    }

    /// Applies message acceptance to a page fetched from `peer`.
    fn accept_fetched(
        &self,
        peer: &str,
        id: &str,
        author: &str,
        target: &str,
        after: i64,
        entries: Vec<Entry>,
    ) -> Result<Page, Error> {
        let mut page = Page {
            accepted: 0,
            stopped: false,
        };
        let mut last = after;
        for entry in entries {
            let seq = entry.seq();
            if seq <= last {
                page.stopped = true;
                return Ok(page);
            }
            last = seq;
            let prev_seq = entry.prev_seq;
            let (message, message_id) = match (entry.message, entry.message_id, entry.refused) {
                (Some(m), None, None) if m.author == author => {
                    let id = m.message_id.clone();
                    (Some(m), id)
                }
                (None, Some(i), Some(_)) if super::valid_message_id(&i) => (None, i),
                _ => {
                    page.stopped = true;
                    return Ok(page);
                }
            };
            // Accepted or refused already: never overwritten.
            let resolved: bool = self.connection()?.query_row(
                "SELECT EXISTS(SELECT 1 FROM conversation_targets WHERE conversation_id = ?1 AND message_id = ?2 AND target = ?3 AND direction = 'in' AND peer = ?4)",
                params![id, message_id, target, peer],
                |r| r.get(0),
            )?;
            if resolved {
                continue;
            }
            // The author's host already holds it as refused for this target.
            let Some(message) = message else {
                let refused = Refused {
                    author: author.to_owned(),
                    seq,
                    prev_seq,
                    code: String::new(),
                    refused_at: now(),
                    acked: true,
                };
                self.connection()?.execute(
                    "INSERT OR IGNORE INTO conversation_targets (conversation_id, message_id, target, direction, peer, prev_seq, state, next_attempt_at, record) VALUES (?1, ?2, ?3, 'in', ?4, ?5, 'refused', NULL, ?6)",
                    params![id, message_id, target, peer, prev_seq, serde_json::to_string(&refused)?],
                )?;
                continue;
            };
            let request = MessageRequest {
                message: message.clone(),
                target: target.to_owned(),
                prev_seq,
                grant_id: None,
                policy: None,
                self_access: None,
            };
            let code = match self.accept_inbound(peer, id, request, true) {
                Ok(_) => {
                    page.accepted += 1;
                    continue;
                }
                Err(Error::Invalid(_)) => "invalid",
                Err(Error::Forbidden) => "not_authorized",
                Err(Error::Conflict(_)) => "conflict",
                Err(Error::Coded {
                    code: "not_participant",
                    ..
                }) => "not_participant",
                Err(Error::Coded { code: "closed", .. }) => "closed",
                Err(Error::Coded {
                    code: "conflict", ..
                }) => "conflict",
                Err(Error::Internal(e)) => return Err(Error::Internal(e)),
                Err(_) => {
                    page.stopped = true;
                    return Ok(page);
                }
            };
            let refused = Refused {
                author: message.author.clone(),
                seq: message.seq,
                prev_seq,
                code: code.into(),
                refused_at: now(),
                acked: false,
            };
            self.connection()?.execute(
                "INSERT OR IGNORE INTO conversation_targets (conversation_id, message_id, target, direction, peer, prev_seq, state, next_attempt_at, record) VALUES (?1, ?2, ?3, 'in', ?4, ?5, 'refused', NULL, ?6)",
                params![id, message.message_id, target, peer, prev_seq, serde_json::to_string(&refused)?],
            )?;
        }
        Ok(page)
    }

    fn sync_peer(&self, conn: &Connection, id: &str, peer: &str) -> Result<SyncPeer, Error> {
        Ok(self
            .outbound_row::<SyncPeer>(conn, id, peer, "sync")?
            .unwrap_or_else(|| SyncPeer {
                state: "pending".into(),
                ..Default::default()
            }))
    }
    fn save_sync_peer(
        &self,
        conn: &Connection,
        id: &str,
        peer: &str,
        s: &SyncPeer,
    ) -> Result<(), Error> {
        conn.execute(
            "INSERT INTO conversation_roster_outbound (conversation_id, peer, kind, record) VALUES (?1, ?2, 'sync', ?3) ON CONFLICT(conversation_id, peer, kind) DO UPDATE SET record = excluded.record",
            params![id, peer, serde_json::to_string(s)?],
        )?;
        Ok(())
    }
    /// The hosts in `unsynced` for the conversation view.
    pub(super) fn unsynced(&self, conn: &Connection, id: &str) -> Result<Vec<String>, Error> {
        let mut q = conn.prepare(
            "SELECT peer FROM conversation_roster_outbound WHERE conversation_id = ?1 AND kind = 'sync' AND json_extract(record, '$.state') = 'unsynced' ORDER BY peer",
        )?;
        let rows = q
            .query_map([id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The acks to send `peer` for local `target`: one entry per author
    /// whose chain head moved past the last answered ack, or with unacked
    /// refusals.
    fn acks_due(
        &self,
        id: &str,
        peer: &str,
        target: &str,
        authors: &[String],
    ) -> Result<Vec<Value>, Error> {
        let conn = self.connection()?;
        let state = self.sync_peer(&conn, id, peer)?;
        let mut entries = Vec::new();
        for author in authors {
            let (head, mut refused) = self.chain(&conn, id, author, target)?;
            refused.retain(|(seq, _)| *seq <= head);
            let mut through = head;
            if refused.len() > 100 {
                through = refused[100].0 - 1;
                refused.truncate(100);
            }
            let acked = state
                .acked
                .get(&format!("{author} {target}"))
                .copied()
                .unwrap_or(0);
            if through < 1 || (through <= acked && refused.is_empty()) {
                continue;
            }
            entries.push(json!({
                "author": author,
                "through_seq": through,
                "refused": refused.iter().map(|(seq, code)| json!({"seq": seq, "code": code})).collect::<Vec<_>>(),
            }));
        }
        Ok(entries)
    }
    /// Records an answered ack: its `through_seq`s and refusals.
    fn acked(&self, id: &str, peer: &str, target: &str, entries: &[Value]) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut state = self.sync_peer(&tx, id, peer)?;
        for e in entries {
            let author = e["author"].as_str().unwrap_or_default();
            let through = e["through_seq"].as_i64().unwrap_or(0);
            let key = format!("{author} {target}");
            let old = state.acked.get(&key).copied().unwrap_or(0);
            state.acked.insert(key, old.max(through));
            for r in e["refused"].as_array().into_iter().flatten() {
                let seq = r["seq"].as_i64().unwrap_or(0);
                let rows: Vec<(String, String)> = {
                    let mut q = tx.prepare(
                        "SELECT message_id, record FROM conversation_targets WHERE conversation_id = ?1 AND target = ?2 AND direction = 'in' AND state = 'refused' AND peer = ?3",
                    )?;
                    q.query_map(params![id, target, peer], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<Result<_, _>>()?
                };
                for (message, record) in rows {
                    let mut refused: Refused = json(record)?;
                    if refused.author == author && refused.seq == seq {
                        refused.acked = true;
                        tx.execute(
                            "UPDATE conversation_targets SET record = ?1 WHERE conversation_id = ?2 AND message_id = ?3 AND target = ?4 AND direction = 'in'",
                            params![serde_json::to_string(&refused)?, id, message, target],
                        )?;
                    }
                }
            }
        }
        self.save_sync_peer(&tx, id, peer, &state)?;
        tx.commit()?;
        Ok(())
    }

    /// What one sync of the conversation covers.
    fn plan(&self, id: &str) -> Result<Plan, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let held = self.held(&tx, id)?;
        let own = self.identity().id;
        let roster = held.roster.clone();
        let targets: Vec<String> = held
            .local
            .admitted
            .keys()
            .filter(|p| held.joined_here(p))
            .cloned()
            .collect();
        let mut peers = BTreeSet::new();
        for p in &roster.participants {
            if p.state == "joined"
                && let Some(host) = &p.host_id
                && *host != own
            {
                peers.insert(host.clone());
            }
        }
        let closed = roster.state == "closed";
        let mut hosts = Vec::new();
        for host in peers {
            let mut state = self.sync_peer(&tx, id, &host)?;
            let skip = if !closed {
                None
            } else if matches!(&state.state[..], "complete" | "unsynced") {
                Some(state.state.clone())
            } else if held
                .local
                .closed_at
                .as_deref()
                .is_some_and(|at| passed(at, CLOSED_SYNC_SECONDS))
            {
                state.state = "unsynced".into();
                self.save_sync_peer(&tx, id, &host, &state)?;
                Some(state.state.clone())
            } else {
                None
            };
            hosts.push((host, skip));
        }
        tx.commit()?;
        Ok(Plan {
            roster,
            targets,
            hosts,
        })
    }
    /// A closed conversation's host answered completely at or above the
    /// closing version: it is not asked again.
    fn mark_complete(&self, id: &str, peer: &str) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut state = self.sync_peer(&tx, id, peer)?;
        state.state = "complete".into();
        self.save_sync_peer(&tx, id, peer, &state)?;
        tx.commit()?;
        Ok(())
    }
    /// The conversations the schedule syncs: open ones with a local
    /// participant joined here, and closed ones with a host still pending.
    fn sync_candidates(&self) -> Result<Vec<String>, Error> {
        let conn = self.connection()?;
        let own = self.identity().id;
        let mut ids = Vec::new();
        for held in self.all_held(&conn)? {
            let local = held.local.admitted.keys().any(|p| held.joined_here(p));
            let roster = &held.roster;
            let wanted = if roster.state == "open" {
                local
            } else {
                let mut pending = false;
                for p in &roster.participants {
                    if p.state == "joined"
                        && let Some(host) = &p.host_id
                        && *host != own
                        && !matches!(
                            &self.sync_peer(&conn, &roster.conversation_id, host)?.state[..],
                            "complete" | "unsynced"
                        )
                    {
                        pending = true;
                    }
                }
                pending
            };
            if wanted {
                ids.push(roster.conversation_id.clone());
            }
        }
        Ok(ids)
    }

    /// `GET /peer/v1/conversations/{id}/heads` and `.../messages`: whether
    /// this host serves `target` to `sender`.
    fn serves(
        &self,
        conn: &Connection,
        sender: &str,
        id: &str,
        target: &str,
    ) -> Result<Held, Error> {
        self.current_member(conn, sender)?;
        let held = self.held_opt(conn, id)?.ok_or(Error::NotFound)?;
        let (_, host, _) = participant_parts(target).ok_or_else(|| invalid("invalid target"))?;
        if host != sender {
            return Err(Error::Forbidden);
        }
        if held.roster.joined(target).is_none() {
            return Err(Error::NotFound);
        }
        Ok(held)
    }
    /// After a close, whether nothing is left to fetch for `target`: every
    /// outbound record is final, or 30 days passed.
    fn serving_ended(&self, conn: &Connection, held: &Held, target: &str) -> Result<bool, Error> {
        if held.roster.state != "closed" {
            return Ok(false);
        }
        let window_over = held
            .local
            .closed_at
            .as_deref()
            .is_none_or(|at| passed(at, CLOSED_SYNC_SECONDS));
        let outstanding: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM conversation_targets WHERE conversation_id = ?1 AND target = ?2 AND direction = 'out' AND state NOT IN ('delivered', 'refused'))",
            params![held.roster.conversation_id, target],
            |r| r.get(0),
        )?;
        Ok(window_over || !outstanding)
    }
    pub(super) fn serve_heads(&self, sender: &str, id: &str, target: &str) -> Result<Value, Error> {
        let conn = self.connection()?;
        let held = self.serves(&conn, sender, id, target)?;
        let mut q = conn.prepare(
            "SELECT m.author, MAX(m.seq) FROM conversation_messages m JOIN conversation_targets t ON t.conversation_id = m.conversation_id AND t.message_id = m.message_id WHERE m.conversation_id = ?1 AND t.direction = 'out' AND t.target = ?2 GROUP BY m.author ORDER BY m.author",
        )?;
        let authors = q
            .query_map(params![id, target], |r| {
                Ok(json!({"author": r.get::<_, String>(0)?, "last_seq": r.get::<_, i64>(1)?}))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        // Heads advertise only what `messages` would still serve.
        let authors = if self.serving_ended(&conn, &held, target)? {
            Vec::new()
        } else {
            authors
        };
        Ok(json!({"roster_version": held.roster.version, "authors": authors}))
    }
    pub(super) fn serve_messages(
        &self,
        sender: &str,
        id: &str,
        author: &str,
        target: &str,
        after: i64,
        limit: i64,
    ) -> Result<Value, Error> {
        let conn = self.connection()?;
        let own = self.identity().id;
        if !participant_parts(author).is_some_and(|(_, h, _)| h == own) {
            return Err(invalid("author must be a participant on this host"));
        }
        let held = self.serves(&conn, sender, id, target)?;
        if self.serving_ended(&conn, &held, target)? {
            return Err(Error::NotFound);
        }
        let mut q = conn.prepare(
            "SELECT m.record, t.prev_seq, t.record FROM conversation_messages m JOIN conversation_targets t ON t.conversation_id = m.conversation_id AND t.message_id = m.message_id WHERE m.conversation_id = ?1 AND m.author = ?2 AND t.direction = 'out' AND t.target = ?3 AND m.seq > ?4 ORDER BY m.seq LIMIT ?5",
        )?;
        let rows = q
            .query_map(params![id, author, target, after, limit + 1], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut messages = Vec::new();
        let mut bytes = 0;
        let mut more = false;
        for (index, (record, prev, out)) in rows.into_iter().enumerate() {
            if index as i64 == limit {
                more = true;
                break;
            }
            let stored: Stored = json(record)?;
            let out: Outbound = json(out)?;
            // A final refusal stays final: it is named, never served again.
            let mut entry = if out.state == "refused" {
                json!({
                    "message_id": stored.message.message_id,
                    "seq": stored.message.seq,
                    "refused": out.code,
                })
            } else {
                json!({ "message": stored.message })
            };
            if let Some(prev) = prev {
                entry["prev_seq"] = json!(prev);
            }
            let size = serde_json::to_vec(&entry)?.len();
            if !messages.is_empty() && bytes + size > PAGE_BYTES {
                more = true;
                break;
            }
            bytes += size;
            messages.push(entry);
        }
        Ok(json!({"messages": messages, "more": more}))
    }
    pub(super) fn accept_acks(
        &self,
        sender: &str,
        id: &str,
        r: AcksRequest,
    ) -> Result<Value, Error> {
        let own = self.identity().id;
        let codes = [
            "not_authorized",
            "not_participant",
            "closed",
            "invalid",
            "conflict",
        ];
        let mut authors = BTreeSet::new();
        let shape = !r.acks.is_empty()
            && r.acks.len() <= 16
            && participant_parts(&r.target).is_some()
            && r.acks.iter().all(|a| {
                participant_parts(&a.author).is_some_and(|(_, h, _)| h == own)
                    && authors.insert(a.author.clone())
                    && (1..=MAX_COUNTER).contains(&a.through_seq)
                    && a.refused.len() <= 100
                    && a.refused.iter().all(|x| {
                        (1..=a.through_seq).contains(&x.seq) && codes.contains(&x.code.as_str())
                    })
            });
        if !valid_conversation_id(id) || !shape {
            return Err(invalid("invalid acks"));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        self.current_member(&tx, sender)?;
        if self.held_opt(&tx, id)?.is_none() {
            return Err(Error::NotFound);
        }
        if participant_parts(&r.target).map(|p| p.1) != Some(sender) {
            return Err(Error::Forbidden);
        }
        let mut changed = 0;
        for a in &r.acks {
            let refused: BTreeMap<i64, &str> =
                a.refused.iter().map(|x| (x.seq, x.code.as_str())).collect();
            let rows: Vec<(String, i64, String)> = {
                let mut q = tx.prepare(
                    "SELECT m.message_id, m.seq, t.record FROM conversation_messages m JOIN conversation_targets t ON t.conversation_id = m.conversation_id AND t.message_id = m.message_id WHERE m.conversation_id = ?1 AND m.author = ?2 AND t.direction = 'out' AND t.target = ?3 AND m.seq <= ?4",
                )?;
                q.query_map(params![id, a.author, r.target, a.through_seq], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<Result<_, _>>()?
            };
            for (message, seq, record) in rows {
                let mut out: Outbound = json(record)?;
                if let Some(code) = refused.get(&seq) {
                    if out.state == "delivered" || out.code.as_deref() == Some(code) {
                        continue;
                    }
                    out.state = "refused".into();
                    out.code = Some((*code).into());
                    out.error = Some(format!("{sender} refused it when it fetched it"));
                } else if matches!(&out.state[..], "sending" | "stopped") {
                    out.state = "delivered".into();
                    out.code = None;
                    out.error = None;
                } else {
                    continue;
                }
                out.next_attempt_at = None;
                self.save_outbound(&tx, id, &message, &out)?;
                changed += 1;
            }
        }
        tx.commit()?;
        Ok(json!({ "acked": changed }))
    }
}

// ---------------------------------------------------------------- requests

fn encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
async fn request(store: &Arc<Store>, peer: &str, method: &str, path: &str, body: &[u8]) -> Outcome {
    let id = peer.to_owned();
    let target = match blocking(store.clone(), move |s| s.dial_target(&id)).await {
        Ok(t) => t,
        Err(e) => return Outcome::Retry(format!("{e:?}")),
    };
    match tokio::time::timeout(
        SYNC_REQUEST,
        crate::quic::request(store.clone(), &target, method, path, body),
    )
    .await
    {
        Ok(Ok((status, body))) => classify(status, &body, peer),
        Ok(Err(e)) => Outcome::Retry(format!("{e:#}")),
        Err(_) => Outcome::Retry("timed out".into()),
    }
}
fn failure(outcome: Outcome) -> String {
    match outcome {
        Outcome::Answer(_) => "invalid answer".into(),
        Outcome::Final(_, _, e) | Outcome::Retry(e) => e,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heads {
    roster_version: i64,
    authors: Vec<Head>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    author: String,
    last_seq: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fetched {
    messages: Vec<Entry>,
    more: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    seq: Option<i64>,
    #[serde(default)]
    refused: Option<String>,
    #[serde(default)]
    prev_seq: Option<i64>,
}
impl Entry {
    fn seq(&self) -> i64 {
        self.message
            .as_ref()
            .map(|m| m.seq)
            .or(self.seq)
            .unwrap_or(0)
    }
}

/// Fetches `author`'s messages to `target` past this host's chain head
/// from `peer`, page by page; returns the number accepted, or why it ended.
async fn fetch_missing(
    store: &Arc<Store>,
    id: &str,
    peer: &str,
    author: &str,
    target: &str,
    last_seq: Option<i64>,
) -> Result<usize, String> {
    let mut accepted = 0;
    let (i, a, t) = (id.to_owned(), author.to_owned(), target.to_owned());
    let mut after = blocking(store.clone(), move |s| s.chain_head(&i, &a, &t))
        .await
        .map_err(|e| format!("{e:?}"))?;
    if last_seq.is_some_and(|l| l <= after) {
        return Ok(accepted);
    }
    for _ in 0..FETCH_PAGES {
        let path = format!(
            "/peer/v1/conversations/{id}/messages?author={}&target={}&after={after}&limit={PAGE_LIMIT}",
            encode(author),
            encode(target)
        );
        let body = match request(store, peer, "GET", &path, &[]).await {
            Outcome::Answer(body) => body,
            other => return Err(failure(other)),
        };
        let page: Fetched =
            serde_json::from_slice(&body).map_err(|_| "invalid messages answer".to_owned())?;
        let Some(highest) = page.messages.last().map(Entry::seq) else {
            break;
        };
        let entries = page.messages;
        let (i, p, a, t) = (
            id.to_owned(),
            peer.to_owned(),
            author.to_owned(),
            target.to_owned(),
        );
        let result = blocking(store.clone(), move |s| {
            s.accept_fetched(&p, &i, &a, &t, after, entries)
        })
        .await
        .map_err(|e| format!("{e:?}"))?;
        accepted += result.accepted;
        if result.stopped {
            return Err("some messages wait for the next sync".into());
        }
        after = highest;
        if !page.more {
            break;
        }
    }
    let (i, a, t) = (id.to_owned(), author.to_owned(), target.to_owned());
    let head = blocking(store.clone(), move |s| s.chain_head(&i, &a, &t))
        .await
        .map_err(|e| format!("{e:?}"))?;
    match last_seq {
        Some(l) if head < l => Err("messages still missing".into()),
        _ => Ok(accepted),
    }
}

/// Sends `peer` the acks due for local `target` from `authors`.
async fn send_acks(
    store: &Arc<Store>,
    id: &str,
    peer: &str,
    target: &str,
    authors: Vec<String>,
) -> Result<(), String> {
    // More than 100 refusals in one chain take several rounds.
    loop {
        let (i, p, t, a) = (
            id.to_owned(),
            peer.to_owned(),
            target.to_owned(),
            authors.clone(),
        );
        let entries = blocking(store.clone(), move |s| s.acks_due(&i, &p, &t, &a))
            .await
            .map_err(|e| format!("{e:?}"))?;
        if entries.is_empty() {
            return Ok(());
        }
        for chunk in entries.chunks(16) {
            let body = serde_json::to_vec(&json!({"target": target, "acks": chunk}))
                .map_err(|e| e.to_string())?;
            match request(
                store,
                peer,
                "POST",
                &format!("/peer/v1/conversations/{id}/acks"),
                &body,
            )
            .await
            {
                Outcome::Answer(_) => {
                    let (i, p, t, c) = (
                        id.to_owned(),
                        peer.to_owned(),
                        target.to_owned(),
                        chunk.to_vec(),
                    );
                    blocking(store.clone(), move |s| s.acked(&i, &p, &t, &c))
                        .await
                        .map_err(|e| format!("{e:?}"))?;
                }
                other => return Err(failure(other)),
            }
        }
    }
}

/// One sync with one participant host: heads for every local target,
/// fetches of what is missing, and acks.
async fn sync_host(
    store: &Arc<Store>,
    id: &str,
    peer: &str,
    targets: &[String],
) -> (Result<i64, String>, usize) {
    let mut fetched = 0;
    let mut error = None;
    let mut version = i64::MAX;
    for target in targets {
        let path = format!(
            "/peer/v1/conversations/{id}/heads?target={}",
            encode(target)
        );
        let heads: Heads = match request(store, peer, "GET", &path, &[]).await {
            Outcome::Answer(body) => match serde_json::from_slice(&body) {
                Ok(h) => h,
                Err(_) => {
                    error.get_or_insert_with(|| "invalid heads answer".to_owned());
                    continue;
                }
            },
            other => {
                error.get_or_insert(failure(other));
                continue;
            }
        };
        version = version.min(heads.roster_version);
        let mut authors = Vec::new();
        for head in heads.authors {
            if !participant_parts(&head.author).is_some_and(|(_, h, _)| h == peer) {
                continue;
            }
            match fetch_missing(store, id, peer, &head.author, target, Some(head.last_seq)).await {
                Ok(n) => fetched += n,
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
            authors.push(head.author);
        }
        if let Err(e) = send_acks(store, id, peer, target, authors).await {
            error.get_or_insert(e);
        }
    }
    match error {
        Some(e) => (Err(e), fetched),
        None => (Ok(version), fetched),
    }
}

/// Runs one sync of the conversation; the caller holds its lock.
async fn run_sync(store: &Arc<Store>, id: &str) -> Result<Value, Error> {
    if let Ok(mut s) = schedule_state().lock() {
        s.last.insert(id.to_owned(), crate::clock::now());
        s.now.remove(id);
    }
    let i = id.to_owned();
    let plan = blocking(store.clone(), move |s| s.plan(&i)).await?;
    let own = store.identity().id;
    // Roster first.
    if plan.roster.home_host_id != own {
        let home = plan.roster.home_host_id.clone();
        let path = format!("/peer/v1/conversations/{id}/roster");
        if let Outcome::Answer(body) = request(store, &home, "GET", &path, &[]).await
            && let Some(roster) = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|v| serde_json::from_value::<Roster>(v["roster"].clone()).ok())
        {
            let i = id.to_owned();
            let _ = blocking(store.clone(), move |s| s.accept_roster(&home, &i, roster)).await;
        }
    }
    let i = id.to_owned();
    let plan = blocking(store.clone(), move |s| s.plan(&i)).await?;
    let closing = (plan.roster.state == "closed").then_some(plan.roster.version);
    let mut tasks = Vec::new();
    for (host, skip) in plan.hosts {
        if let Some(state) = skip {
            tasks.push((host, None, Some(state)));
            continue;
        }
        let (store, id, peer, targets) = (
            store.clone(),
            id.to_owned(),
            host.clone(),
            plan.targets.clone(),
        );
        let task = tokio::spawn(async move { sync_host(&store, &id, &peer, &targets).await });
        tasks.push((host, Some(task), None));
    }
    let mut hosts = Vec::new();
    for (host, task, skip) in tasks {
        if let Some(state) = skip {
            hosts.push(json!({"host_id": host, "state": state, "fetched": 0, "error": null}));
            continue;
        }
        let Some(task) = task else { continue };
        let (result, fetched) = task
            .await
            .unwrap_or_else(|_| (Err("sync failed".into()), 0));
        match result {
            Ok(version) => {
                if let Some(v) = closing
                    && (version >= v || plan.targets.is_empty())
                {
                    let (i, h) = (id.to_owned(), host.clone());
                    let _ = blocking(store.clone(), move |s| s.mark_complete(&i, &h)).await;
                }
                hosts.push(
                    json!({"host_id": host, "state": "synced", "fetched": fetched, "error": null}),
                );
            }
            Err(e) => {
                hosts.push(
                    json!({"host_id": host, "state": "failed", "fetched": fetched, "error": e}),
                );
            }
        }
    }
    Ok(json!({
        "conversation_id": id,
        "roster_version": plan.roster.version,
        "hosts": hosts,
    }))
}

/// Starts the syncs that are due, within the bound of 4 at once.
pub(super) async fn schedule(store: &Arc<Store>) {
    let Ok(candidates) = blocking(store.clone(), |s| s.sync_candidates()).await else {
        return;
    };
    let at = crate::clock::now();
    let due: Vec<String> = {
        let Ok(s) = schedule_state().lock() else {
            return;
        };
        candidates
            .into_iter()
            .filter(|id| {
                s.now.contains(id)
                    || s.last.get(id).is_none_or(|last| {
                        *last + chrono::TimeDelta::seconds(SYNC_EVERY_SECONDS) <= at
                    })
            })
            .collect()
    };
    for id in due {
        let Ok(permit) = permits().clone().try_acquire_owned() else {
            return;
        };
        let lock = lock_of(&id);
        let Ok(guard) = lock.try_lock_owned() else {
            continue;
        };
        let store = store.clone();
        tokio::spawn(async move {
            let _ = run_sync(&store, &id).await;
            drop(guard);
            drop(permit);
        });
    }
}

/// After an accepted push: a `prev_seq` past the chain head is a gap, which
/// is fetched at once from the author's host.
pub(super) fn after_push(
    store: Arc<Store>,
    id: String,
    sender: String,
    (author, target, prev_seq): (String, String, Option<i64>),
) {
    let Some(prev) = prev_seq else {
        return;
    };
    tokio::spawn(async move {
        let (i, a, t) = (id.clone(), author.clone(), target.clone());
        let Ok(head) = blocking(store.clone(), move |s| s.chain_head(&i, &a, &t)).await else {
            return;
        };
        if prev <= head {
            return;
        }
        let key = format!("{id} {sender} {author} {target}");
        if !schedule_state()
            .lock()
            .map(|mut s| s.gaps.insert(key.clone()))
            .unwrap_or(false)
        {
            return;
        }
        let _ = fetch_missing(&store, &id, &sender, &author, &target, None).await;
        let _ = send_acks(&store, &id, &sender, &target, vec![author]).await;
        if let Ok(mut s) = schedule_state().lock() {
            s.gaps.remove(&key);
        }
    });
}

// ---------------------------------------------------------------- routes

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

/// `POST /v1/conversations/{id}/sync`.
pub(super) async fn local_sync(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let _: Empty = decode(body)?;
    let i = id.clone();
    let held = blocking(store.clone(), move |s| {
        if !valid_conversation_id(&i) {
            return Ok(false);
        }
        Ok(s.held_opt(&*s.connection()?, &i)?.is_some())
    })
    .await?;
    if !held {
        return Err(Error::NotFound);
    }
    let lock = lock_of(&id);
    let _guard = lock.lock().await;
    let _permit = permits()
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| unavailable("shutting down"))?;
    Ok(Json(run_sync(&store, &id).await?))
}

fn query(
    q: Result<Query<BTreeMap<String, String>>, QueryRejection>,
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, Error> {
    let Query(q) = q.map_err(|_| invalid("invalid query"))?;
    if q.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(invalid("unknown query parameter"));
    }
    Ok(q)
}
fn number(
    text: Option<&String>,
    default: i64,
    range: std::ops::RangeInclusive<i64>,
) -> Result<i64, Error> {
    match text {
        None => Ok(default),
        Some(t) => t
            .parse::<i64>()
            .ok()
            .filter(|n| range.contains(n) && t.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| invalid("invalid number")),
    }
}

/// `GET /peer/v1/conversations/{id}/heads?target=T`.
pub(super) async fn peer_heads(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    q: Result<Query<BTreeMap<String, String>>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let q = query(q, &["target"])?;
    let target = q
        .get("target")
        .cloned()
        .ok_or_else(|| invalid("target is required"))?;
    if !valid_conversation_id(&id) || participant_parts(&target).is_none() {
        return Err(invalid("invalid heads request"));
    }
    Ok(Json(
        blocking(store, move |s| s.serve_heads(&sender, &id, &target)).await?,
    ))
}

/// `GET /peer/v1/conversations/{id}/messages?author=A&target=T&after=N&limit=M`.
pub(super) async fn peer_fetch(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    q: Result<Query<BTreeMap<String, String>>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let q = query(q, &["author", "target", "after", "limit"])?;
    let author = q
        .get("author")
        .cloned()
        .ok_or_else(|| invalid("author is required"))?;
    let target = q
        .get("target")
        .cloned()
        .ok_or_else(|| invalid("target is required"))?;
    let after = number(q.get("after"), -1, 0..=MAX_COUNTER)?;
    if after < 0 {
        return Err(invalid("after is required"));
    }
    let limit = number(q.get("limit"), 50, 1..=PAGE_LIMIT)?;
    if !valid_conversation_id(&id)
        || participant_parts(&author).is_none()
        || participant_parts(&target).is_none()
    {
        return Err(invalid("invalid messages request"));
    }
    Ok(Json(
        blocking(store, move |s| {
            s.serve_messages(&sender, &id, &author, &target, after, limit)
        })
        .await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcksRequest {
    target: String,
    acks: Vec<Ack>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    author: String,
    through_seq: i64,
    refused: Vec<AckRefused>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRefused {
    seq: i64,
    code: String,
}

/// `POST /peer/v1/conversations/{id}/acks`.
pub(super) async fn peer_acks(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: AcksRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.accept_acks(&sender, &id, r)).await?,
    ))
}
