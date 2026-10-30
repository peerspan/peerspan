//! The person's tools, contract C6: the rate limit's count, `addressed_to`,
//! the read cursor, the local event log, `conversation forget`, and
//! `home_unavailable`.
use super::{
    Error, Held, Participant, Roster, Stored, coded_error, invalid, not_participant,
    participant_parts, save_held, valid_conversation_id, valid_message_id,
};
use crate::{
    api::{blocking, decode},
    directory::coded,
    store::{Store, now},
};
use axum::{
    Json,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

/// Messages one author may have per conversation in any trailing hour.
const RATE_LIMIT: usize = 60;
const RATE_WINDOW_SECONDS: i64 = 3_600;
const EVENT_KEEP: i64 = 10_000;
const EVENT_KEEP_SECONDS: i64 = 30 * 24 * 3_600;
const MAX_ADDRESSED: usize = 16;
const MAX_ADDRESS_CHARS: usize = 256;
const MAX_READ_IDS: usize = 100;
const MAX_WAIT_SECONDS: i64 = 25;
const NO_SUCH_PARTICIPANT: &str = "No such participant in that conversation.";

pub(super) fn author_limit() -> Error {
    coded_error(
        429,
        "limit",
        "This participant reached its limit of 60 messages per hour in this conversation.",
    )
}
pub(super) fn recipient_limit() -> Error {
    coded_error(
        429,
        "limit",
        "This author reached its limit of 60 messages per hour in this conversation.",
    )
}

/// Whether `author` already has the full allowance in the hour ending at
/// `at`. A message's time is the lesser of its `sent_at` and when this host
/// stored it, so retries and catch-up keep the times the author's host
/// limited, and a future `sent_at` gains nothing.
pub(super) fn rate_full(
    conn: &Connection,
    id: &str,
    author: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error> {
    let mut statement = conn.prepare(
        "SELECT json_extract(record, '$.message.sent_at'), json_extract(record, '$.received_at') FROM conversation_messages WHERE conversation_id = ?1 AND author = ?2",
    )?;
    let rows = statement
        .query_map(params![id, author], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let from = at - chrono::TimeDelta::seconds(RATE_WINDOW_SECONDS);
    let parse = |t: &str| crate::membership::time(t).ok();
    let count = rows
        .iter()
        .filter_map(|(sent, received)| Some(parse(sent)?.min(parse(received)?)))
        .filter(|time| *time > from && *time <= at)
        .count();
    Ok(count >= RATE_LIMIT)
}

/// One entry of the local event log, in the caller's transaction. It never
/// holds content.
pub(super) fn log_event(
    conn: &Connection,
    kind: &str,
    conversation: &str,
    message: Option<&str>,
    participant: Option<&str>,
) -> Result<(), Error> {
    let at = now();
    let record = json!({
        "kind": kind,
        "conversation_id": conversation,
        "message_id": message,
        "participant": participant,
        "at": at,
    });
    conn.execute(
        "INSERT INTO conversation_events (created_at, record) VALUES (?1, ?2)",
        params![at, record.to_string()],
    )?;
    conn.execute(
        "DELETE FROM conversation_events WHERE sequence <= (SELECT sequence FROM conversation_events ORDER BY sequence DESC LIMIT 1 OFFSET ?1)",
        [EVENT_KEEP],
    )?;
    prune_old_events(conn, Some(100))
}
/// Deletes entries past 30 days, among the oldest `scan` when given.
fn prune_old_events(conn: &Connection, scan: Option<i64>) -> Result<(), Error> {
    let cutoff = crate::clock::now() - chrono::TimeDelta::seconds(EVENT_KEEP_SECONDS);
    let mut statement = conn.prepare(
        "SELECT sequence, created_at FROM conversation_events ORDER BY sequence LIMIT ?1",
    )?;
    let rows = statement
        .query_map([scan.unwrap_or(-1)], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (sequence, at) in rows {
        if crate::membership::time(&at).is_ok_and(|t| t < cutoff) {
            conn.execute(
                "DELETE FROM conversation_events WHERE sequence = ?1",
                [sequence],
            )?;
        }
    }
    Ok(())
}
/// One activity record, in the caller's transaction. Never holds content.
pub(super) fn activity(conn: &Connection, kind: &str, subject: &str) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO events (kind, subject_id, created_at) VALUES (?1, ?2, ?3)",
        params![kind, subject, now()],
    )?;
    Ok(())
}

/// Validates the optional `about` link's shape.
pub(super) fn valid_about(about: &super::About) -> bool {
    crate::peer_store::valid_id(&about.peer_host_id, "host", 32)
        && crate::peer_store::valid_id(&about.task_id, "task", 16)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadRequest {
    #[serde(default, deserialize_with = "crate::policy::present")]
    message_ids: Option<Vec<String>>,
}
#[derive(Deserialize)]
pub(super) struct OneQuery {
    participant: Option<String>,
}

impl Store {
    /// A conversation a local route may use: held, and not forgotten here.
    pub(super) fn not_forgotten(&self, id: &str) -> Result<(), Error> {
        let conn = self.connection()?;
        match self.held_opt(&conn, id)? {
            Some(held) if !held.local.forgotten => Ok(()),
            _ => Err(Error::NotFound),
        }
    }
    /// `addressed_to` as given, resolved to participant IDs in roster order.
    pub(super) fn resolve_addressed(
        &self,
        conn: &Connection,
        held: &Held,
        given: &[String],
    ) -> Result<Vec<String>, Error> {
        check_addressed(given)?;
        let (shown, _) = self.shown(held);
        let candidates: Vec<(&Participant, String)> = shown
            .iter()
            .filter(|p| p.id.is_some() && matches!(&p.state[..], "joined" | "inviting"))
            .map(|p| Ok((p, self.label(conn, p)?)))
            .collect::<Result<_, Error>>()?;
        let mut chosen = BTreeSet::new();
        for entry in given {
            let matches: Vec<&str> = candidates
                .iter()
                .filter(|(p, label)| p.id.as_deref() == Some(entry) || label == entry)
                .filter_map(|(p, _)| p.id.as_deref())
                .collect();
            match matches.as_slice() {
                [] => return Err(coded_error(404, "not_found", NO_SUCH_PARTICIPANT)),
                [one] => {
                    chosen.insert(one.to_string());
                }
                many => {
                    return Err(coded(
                        409,
                        "ambiguous",
                        format!("{entry} names several participants: {}", many.join(", ")),
                        json!({ "matches": many }),
                    ));
                }
            }
        }
        Ok(candidates
            .iter()
            .filter_map(|(p, _)| p.id.clone())
            .filter(|id| chosen.contains(id))
            .collect())
    }
    /// Whether a repeat's `addressed_to` names exactly the stored set,
    /// against the stored IDs and their current labels.
    pub(super) fn same_addressed(
        &self,
        conn: &Connection,
        roster: &Roster,
        stored: &[String],
        given: &[String],
    ) -> Result<bool, Error> {
        let mut named = BTreeSet::new();
        for entry in given {
            let mut found = false;
            for id in stored {
                if id == entry || self.label_of(conn, roster, id)? == *entry {
                    named.insert(id);
                    found = true;
                }
            }
            if !found {
                return Ok(false);
            }
        }
        Ok(named.len() == stored.len())
    }
    /// The labels of `addressed_to`, in the same order.
    pub(super) fn addressed_labels(
        &self,
        conn: &Connection,
        roster: &Roster,
        ids: &[String],
    ) -> Result<Vec<String>, Error> {
        ids.iter()
            .map(|id| self.label_of(conn, roster, id))
            .collect()
    }
    /// True while home is not a current member of a network shared with this
    /// host (CONV-23); never on home.
    pub(super) fn home_unavailable(
        &self,
        conn: &Connection,
        roster: &Roster,
    ) -> Result<bool, Error> {
        if roster.home_host_id == self.identity().id {
            return Ok(false);
        }
        Ok(self
            .product_members_of(conn, &roster.home_host_id)?
            .is_empty())
    }

    /// The person's unread count in a conversation.
    pub(super) fn unread(&self, conn: &Connection, id: &str, person: &str) -> Result<i64, Error> {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM conversation_messages m WHERE m.conversation_id = ?1 AND m.author != ?2 AND m.local_seq > COALESCE((SELECT read_through FROM conversation_reads r WHERE r.conversation_id = ?1 AND r.participant = ?2), 0) AND EXISTS (SELECT 1 FROM conversation_targets t WHERE t.conversation_id = m.conversation_id AND t.message_id = m.message_id AND t.direction = 'in' AND t.state = 'accepted' AND t.target = ?2)",
            params![id, person],
            |r| r.get(0),
        )?)
    }
    /// The unread count of this host's person, 0 without one.
    pub(super) fn own_unread(&self, conn: &Connection, id: &str) -> Result<i64, Error> {
        match self.conversation_person(conn)? {
            Some(person) => {
                let me = format!("person:{}/{person}", self.identity().id);
                self.unread(conn, id, &me)
            }
            None => Ok(0),
        }
    }
    /// `POST /v1/conversations/{id}/read`.
    fn read_conversation(&self, id: &str, ids: Option<Vec<String>>) -> Result<Value, Error> {
        if ids.as_ref().is_some_and(|i| {
            i.is_empty() || i.len() > MAX_READ_IDS || i.iter().any(|m| !valid_message_id(m))
        }) {
            return Err(invalid("message_ids must be 1 to 100 message IDs"));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let held = self.held(&tx, id)?;
        if held.local.forgotten {
            return Err(Error::NotFound);
        }
        let person = self.person_participant(&tx)?;
        if !held.roster.ever(&person) {
            return Err(not_participant());
        }
        let visible = self.visible(&tx, id, &person)?;
        let chosen: Vec<String> = match ids {
            Some(ids) => {
                let known: BTreeSet<&str> = visible
                    .iter()
                    .map(|s| s.message.message_id.as_str())
                    .collect();
                if ids.iter().any(|m| !known.contains(m.as_str())) {
                    return Err(invalid("a message ID is not visible to this person"));
                }
                ids
            }
            None => visible
                .iter()
                .map(|s| s.message.message_id.clone())
                .collect(),
        };
        let mut through = 0i64;
        for m in &chosen {
            let seq: i64 = tx.query_row(
                "SELECT local_seq FROM conversation_messages WHERE conversation_id = ?1 AND message_id = ?2",
                params![id, m],
                |r| r.get(0),
            )?;
            through = through.max(seq);
        }
        let cursor: i64 = tx
            .query_row(
                "SELECT read_through FROM conversation_reads WHERE conversation_id = ?1 AND participant = ?2",
                params![id, person],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if through > cursor {
            tx.execute(
                "INSERT INTO conversation_reads (conversation_id, participant, read_through) VALUES (?1, ?2, ?3) ON CONFLICT(conversation_id, participant) DO UPDATE SET read_through = excluded.read_through",
                params![id, person, through],
            )?;
            log_event(&tx, "read_changed", id, None, Some(&person))?;
        }
        let unread = self.unread(&tx, id, &person)?;
        tx.commit()?;
        Ok(json!({"conversation_id": id, "participant": person, "unread": unread}))
    }
    /// `GET /v1/conversations/{id}/messages/{message_id}`.
    fn one_message(
        &self,
        id: &str,
        message: &str,
        participant: Option<String>,
    ) -> Result<Value, Error> {
        let conn = self.connection()?;
        let held = self.held(&conn, id)?;
        if held.local.forgotten {
            return Err(Error::NotFound);
        }
        let reader = self.reader(&conn, &held.roster, participant)?;
        let stored = self
            .visible(&conn, id, &reader)?
            .into_iter()
            .find(|s| s.message.message_id == message)
            .ok_or(Error::NotFound)?;
        Ok(json!({"message": self.message_view(&conn, &held.roster, &stored, &reader)?}))
    }
    /// One read of the event log: entries for the reader after `after`.
    fn read_events(
        &self,
        after: i64,
        limit: i64,
        participant: Option<String>,
        conversation: Option<String>,
    ) -> Result<Value, Error> {
        let conn = self.connection()?;
        prune_old_events(&conn, None)?;
        let reader = match participant {
            Some(p) if self.local_participant(&p) => p,
            Some(_) => return Err(invalid("participant must be a local participant ID")),
            None => self.person_participant(&conn)?,
        };
        if let Some(id) = &conversation {
            if !valid_conversation_id(id) {
                return Err(invalid("invalid conversation ID"));
            }
            // The connection is exclusive: read through the one held here.
            if self.held_opt(&conn, id)?.is_none_or(|h| h.local.forgotten) {
                return Err(Error::NotFound);
            }
        }
        let latest: i64 = conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'conversation_events'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let own_person = match participant_parts(&reader) {
            Some(("person", _, person)) => Some(format!("person:{person}")),
            _ => None,
        };
        // Per conversation: whether the reader is in its roster, and what it
        // may see now.
        let mut known: BTreeMap<String, (bool, BTreeSet<String>)> = BTreeMap::new();
        let mut events = Vec::new();
        let mut cursor = after;
        let mut last_returned = None;
        'scan: loop {
            let mut statement = conn.prepare(
                "SELECT sequence, record FROM conversation_events WHERE sequence > ?1 ORDER BY sequence LIMIT 500",
            )?;
            let rows = statement
                .query_map([cursor], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if rows.is_empty() {
                break;
            }
            for (sequence, record) in rows {
                cursor = sequence;
                let mut entry: Value = serde_json::from_str(&record)?;
                let id = entry["conversation_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if conversation.as_ref().is_some_and(|c| *c != id) {
                    continue;
                }
                let kind = entry["kind"].as_str().unwrap_or_default().to_owned();
                let named = entry["participant"].as_str();
                let keep = match &kind[..] {
                    "invited" => named.is_some() && named == own_person.as_deref(),
                    "read_changed" => named == Some(reader.as_str()),
                    "roster_changed" => self.seen_of(&conn, &mut known, &id, &reader)?.0,
                    _ => {
                        named == Some(reader.as_str())
                            && entry["message_id"].as_str().is_some_and(|m| {
                                known_visible(self, &conn, &mut known, &id, &reader, m)
                            })
                    }
                };
                if keep {
                    entry["sequence"] = json!(sequence);
                    events.push(entry);
                    last_returned = Some(sequence);
                    if events.len() as i64 >= limit {
                        break 'scan;
                    }
                }
            }
        }
        let next_after = match last_returned {
            Some(last) if events.len() as i64 >= limit => last,
            _ => latest.max(after),
        };
        Ok(json!({"events": events, "next_after": next_after, "latest": latest}))
    }
    fn seen_of<'a>(
        &self,
        conn: &Connection,
        known: &'a mut BTreeMap<String, (bool, BTreeSet<String>)>,
        id: &str,
        reader: &str,
    ) -> Result<&'a (bool, BTreeSet<String>), Error> {
        if !known.contains_key(id) {
            let held = self.held_opt(conn, id)?;
            let value = match held {
                Some(held) if !held.local.forgotten => (
                    held.roster.ever(reader),
                    self.visible(conn, id, reader)?
                        .into_iter()
                        .map(|s: Stored| s.message.message_id)
                        .collect(),
                ),
                _ => (false, BTreeSet::new()),
            };
            known.insert(id.to_owned(), value);
        }
        Ok(&known[id])
    }
    /// The highest `seq` an author used before this host forgot the
    /// conversation, or 0.
    pub(super) fn forgotten_seq(
        &self,
        conn: &Connection,
        id: &str,
        author: &str,
    ) -> Result<i64, Error> {
        let record: Option<String> = conn
            .query_row(
                "SELECT record FROM conversation_roster_outbound WHERE conversation_id = ?1 AND kind = ?2",
                params![id, format!("seq:{author}")],
                |r| r.get(0),
            )
            .optional()?;
        Ok(record
            .and_then(|r| serde_json::from_str::<Value>(&r).ok())
            .and_then(|v| v["seq"].as_i64())
            .unwrap_or(0))
    }
    /// `DELETE /v1/conversations/{id}`.
    fn forget_conversation(&self, id: &str) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut held = self.held(&tx, id)?;
        if held.local.forgotten {
            return Err(Error::NotFound);
        }
        let joined =
            held.roster.state == "open" && held.local.admitted.keys().any(|p| held.joined_here(p));
        let pending = self.pending_rows(&tx, id)?.iter().any(|(_, p)| p.current());
        if joined || pending {
            return Err(coded_error(
                409,
                "in_use",
                "Someone on this host is still in that conversation; leave it first.",
            ));
        }
        // A later re-invite must not reuse an author's `seq`: other hosts
        // still hold the earlier ones.
        let heads: Vec<(String, i64)> = {
            let mut q = tx.prepare(
                "SELECT author, MAX(seq) FROM conversation_messages WHERE conversation_id = ?1 GROUP BY author",
            )?;
            q.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        let own = self.identity().id;
        for (author, seq) in heads {
            if participant_parts(&author).is_some_and(|(_, host, _)| host == own) {
                tx.execute(
                    "INSERT INTO conversation_roster_outbound (conversation_id, peer, kind, record) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(conversation_id, peer, kind) DO UPDATE SET record = excluded.record",
                    params![id, own, format!("seq:{author}"), json!({"seq": seq}).to_string()],
                )?;
            }
        }
        for table in [
            "conversation_notifications",
            "conversation_targets",
            "conversation_reads",
            "conversation_messages",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE conversation_id = ?1"),
                [id],
            )?;
        }
        tx.execute(
            "DELETE FROM conversation_events WHERE json_extract(record, '$.conversation_id') = ?1",
            [id],
        )?;
        let home = held.roster.home_host_id == self.identity().id;
        if home {
            // The roster and its pushes stay: others still rely on them.
            for p in held.local.admitted.keys().cloned().collect::<Vec<_>>() {
                held.end(&p);
            }
            held.local.forgotten = true;
            save_held(&tx, &held)?;
        } else {
            // An unconfirmed leave or decline is still sent.
            tx.execute(
                "DELETE FROM conversation_roster_outbound WHERE conversation_id = ?1 AND kind NOT LIKE 'leave:%' AND kind NOT LIKE 'seq:%'",
                [id],
            )?;
            tx.execute("DELETE FROM conversations WHERE id = ?1", [id])?;
        }
        tx.commit()?;
        Ok(json!({"conversation_id": id, "state": "forgotten", "roster_kept": home}))
    }
}
fn known_visible(
    store: &Store,
    conn: &Connection,
    known: &mut BTreeMap<String, (bool, BTreeSet<String>)>,
    id: &str,
    reader: &str,
    message: &str,
) -> bool {
    store
        .seen_of(conn, known, id, reader)
        .is_ok_and(|(_, visible)| visible.contains(message))
}
pub(super) fn check_addressed(given: &[String]) -> Result<(), Error> {
    if given.len() > MAX_ADDRESSED || given.iter().any(|a| a.chars().count() > MAX_ADDRESS_CHARS) {
        return Err(invalid(
            "addressed_to must be at most 16 strings of at most 256 characters",
        ));
    }
    Ok(())
}

pub(super) async fn read(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let r: ReadRequest = decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.read_conversation(&id, r.message_ids)).await?,
    ))
}
pub(super) async fn one(
    State(store): State<Arc<Store>>,
    Path((id, message)): Path<(String, String)>,
    query: Result<Query<OneQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| invalid("invalid query"))?;
    Ok(Json(
        blocking(store, move |s| s.one_message(&id, &message, q.participant)).await?,
    ))
}
pub(super) async fn forget(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| s.forget_conversation(&id)).await?,
    ))
}
/// `GET /v1/conversations/events`: holds up to `wait` seconds for an entry.
pub(super) async fn events(
    State(store): State<Arc<Store>>,
    query: Result<Query<BTreeMap<String, String>>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let q = super::sync::query(
        query,
        &["after", "limit", "wait", "participant", "conversation"],
    )?;
    let mut after = super::sync::number(q.get("after"), 0, 0..=i64::MAX)?;
    let limit = super::sync::number(q.get("limit"), 100, 1..=1_000)?;
    let wait = super::sync::number(q.get("wait"), 0, 0..=MAX_WAIT_SECONDS)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait as u64);
    loop {
        let (participant, conversation) = (
            q.get("participant").cloned(),
            q.get("conversation").cloned(),
        );
        let answer = blocking(store.clone(), move |s| {
            s.read_events(after, limit, participant, conversation)
        })
        .await?;
        let empty = answer["events"].as_array().is_none_or(|e| e.is_empty());
        if !empty || tokio::time::Instant::now() >= deadline {
            return Ok(Json(answer));
        }
        // Entries passed over in this scan stay passed over in the next.
        after = answer["next_after"].as_i64().unwrap_or(after);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "conv_00000000000000000000000000000000";
    const AUTHOR: &str = "person:host_a/person_a";

    fn setup(temporary: &tempfile::TempDir) -> Store {
        Store::open(&temporary.path().join("host")).unwrap()
    }
    fn stored(
        conn: &Connection,
        n: i64,
        sent: chrono::DateTime<chrono::Utc>,
        received: chrono::DateTime<chrono::Utc>,
    ) {
        let record = json!({
            "message": {"sent_at": crate::store::rfc3339(sent)},
            "received_at": crate::store::rfc3339(received),
        });
        conn.execute("PRAGMA foreign_keys = OFF", []).unwrap();
        conn.execute(
            "INSERT INTO conversation_messages (conversation_id, message_id, author, seq, clock, local_seq, record) VALUES (?1, ?2, ?3, ?4, ?4, ?4, ?5)",
            params![ID, format!("m{n}"), AUTHOR, n, record.to_string()],
        )
        .unwrap();
    }

    #[test]
    fn the_limit_counts_a_messages_own_time() {
        let temporary = tempfile::tempdir().unwrap();
        let store = setup(&temporary);
        let conn = store.connection().unwrap();
        let at = crate::clock::now();
        for n in 1..=59 {
            stored(&conn, n, at, at);
        }
        assert!(!rate_full(&conn, ID, AUTHOR, at).unwrap());
        // A future `sent_at` counts at its storing time.
        stored(&conn, 60, at + chrono::TimeDelta::days(30), at);
        assert!(rate_full(&conn, ID, AUTHOR, at).unwrap());
        // Another hour's allowance is untouched.
        let earlier = at - chrono::TimeDelta::hours(2);
        assert!(!rate_full(&conn, ID, AUTHOR, earlier).unwrap());
        assert!(!rate_full(&conn, ID, AUTHOR, at + chrono::TimeDelta::seconds(3_601)).unwrap());
    }

    #[test]
    fn a_saved_limit_refusal_answers_a_later_push() {
        let record = json!({"author": AUTHOR, "seq": 1, "prev_seq": null, "code": "limit", "refused_at": "2026-10-30T00:00:00Z", "acked": false});
        let error = super::super::sync::saved_refusal(record.to_string()).unwrap();
        assert!(matches!(error, Error::Coded { code: "limit", .. }));
    }

    #[test]
    fn the_event_log_keeps_30_days_and_10000_entries() {
        let temporary = tempfile::tempdir().unwrap();
        let store = setup(&temporary);
        let conn = store.connection().unwrap();
        conn.execute(
            "INSERT INTO conversation_events (created_at, record) VALUES (?1, '{}')",
            [crate::store::rfc3339(
                crate::clock::now() - chrono::TimeDelta::days(31),
            )],
        )
        .unwrap();
        log_event(&conn, "roster_changed", ID, None, None).unwrap();
        let count = |conn: &Connection| -> i64 {
            conn.query_row("SELECT COUNT(*) FROM conversation_events", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(&conn), 1);
        for _ in 0..10_005 {
            conn.execute(
                "INSERT INTO conversation_events (created_at, record) VALUES (?1, '{}')",
                [now()],
            )
            .unwrap();
        }
        log_event(&conn, "roster_changed", ID, None, None).unwrap();
        assert_eq!(count(&conn), EVENT_KEEP);
    }
}
