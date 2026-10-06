//! Automatic retry of uncertain outbound sends (roadmap milestone 5).
//!
//! The daemon retries every `unknown` outbound record with the saved request
//! and request ID. Before the deadline it resubmits; afterwards it only queries
//! the receipt. Receivers deduplicate by sender and request ID, so a retry never
//! creates a second message or consumes another route budget unit.
use crate::{
    api::blocking,
    model::Error,
    peer_store::OutboundMessage,
    store::{Store, rfc3339},
};
use chrono::{DateTime, Utc};
use rusqlite::params;
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

const FIRST_DELAY_MS: i64 = 1_000;
const MAX_DELAY_MS: i64 = 60_000;
/// Receipt-only queries after the deadline before giving up.
const MAX_RECEIPT_QUERIES: u32 = 10;
/// Stop querying receipts this long after the deadline.
const GIVE_UP_AFTER_DEADLINE: chrono::TimeDelta = chrono::TimeDelta::hours(24);
/// A freshly prepared record is due after the inline send's 8 s bound, so a
/// request interrupted before transmission is still retried.
pub(crate) const PREPARE_GUARD: chrono::TimeDelta = chrono::TimeDelta::seconds(10);
/// At most this many automatic attempts run at once per daemon.
pub(crate) const CONCURRENCY: usize = 4;
/// Overdue records at startup are spread over this window instead of sent at once.
const RESTART_SPREAD_MS: i64 = 10_000;
const POLL: Duration = Duration::from_millis(250);

/// The backoff after `attempts` transmissions: 1 s, doubling to 60 s, scaled
/// by `1 + jitter`, where `jitter` is within ±0.2.
pub(crate) fn backoff(attempts: u32, jitter: f64) -> chrono::TimeDelta {
    let exponent = attempts.saturating_sub(1).min(16);
    let base = (FIRST_DELAY_MS << exponent).min(MAX_DELAY_MS) as f64;
    chrono::TimeDelta::milliseconds((base * (1.0 + jitter)).round() as i64)
}

/// A uniformly random jitter factor in [-0.2, 0.2].
pub(crate) fn jitter() -> f64 {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return 0.0;
    }
    (u32::from_le_bytes(bytes) as f64 / u32::MAX as f64) * 0.4 - 0.2
}

fn deadline(out: &OutboundMessage) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&out.request.deadline)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Whether an attempt at `now` may only query the receipt: the receiver
/// refuses resubmission once the deadline has passed.
pub(crate) fn receipt_only(out: &OutboundMessage, now: DateTime<Utc>) -> bool {
    deadline(out).is_none_or(|d| now >= d)
}

/// Records one attempt's outcome: counts it, counts receipt queries made after
/// the deadline, and sets `next_attempt_at`, or clears it when the outcome is
/// final or the post-deadline limits are reached.
pub(crate) fn schedule(
    out: &mut OutboundMessage,
    receipt_only: bool,
    now: DateTime<Utc>,
    jitter: f64,
) {
    out.attempts = out.attempts.saturating_add(1);
    if out.state != "unknown" {
        out.next_attempt_at = None;
        return;
    }
    if let Some(deadline) = deadline(out)
        && now >= deadline
    {
        if receipt_only {
            out.receipt_queries = out.receipt_queries.saturating_add(1);
        }
        if out.receipt_queries >= MAX_RECEIPT_QUERIES || now >= deadline + GIVE_UP_AFTER_DEADLINE {
            out.next_attempt_at = None;
            return;
        }
    }
    out.next_attempt_at = Some(rfc3339(now + backoff(out.attempts, jitter)));
}

fn due_at(out: &OutboundMessage) -> Option<DateTime<Utc>> {
    out.next_attempt_at
        .as_deref()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
}

impl Store {
    /// Unknown records due at `now`, earliest first. A record written before
    /// this milestone has no schedule fields and is due immediately.
    pub(crate) fn due_retries(&self, now: DateTime<Utc>) -> Result<Vec<(String, String)>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT peer, request_id, record, json_type(record, '$.attempts') IS NULL FROM outbound_messages WHERE json_extract(record, '$.state') = 'unknown'",
        )?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut due = Vec::new();
        for (peer, id, record, legacy) in rows {
            let out: OutboundMessage = serde_json::from_str(&record)?;
            let at = if legacy {
                Some(DateTime::<Utc>::MIN_UTC)
            } else {
                due_at(&out)
            };
            if let Some(at) = at.filter(|at| *at <= now) {
                due.push((at, peer, id));
            }
        }
        due.sort();
        Ok(due.into_iter().map(|(_, peer, id)| (peer, id)).collect())
    }

    /// At startup, spreads every overdue unknown record evenly over the next
    /// 10 seconds, so a restart does not send a burst. Returns how many moved.
    pub(crate) fn spread_overdue(&self, now: DateTime<Utc>) -> Result<usize, Error> {
        let due = self.due_retries(now)?;
        let count = due.len();
        if count == 0 {
            return Ok(0);
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        for (index, (peer, id)) in due.iter().enumerate() {
            let record: String = tx.query_row(
                "SELECT record FROM outbound_messages WHERE peer = ?1 AND request_id = ?2",
                params![peer, id],
                |r| r.get(0),
            )?;
            let mut out: OutboundMessage = serde_json::from_str(&record)?;
            let offset = RESTART_SPREAD_MS * index as i64 / count as i64;
            out.next_attempt_at = Some(rfc3339(now + chrono::TimeDelta::milliseconds(offset)));
            tx.execute(
                "UPDATE outbound_messages SET record = ?1 WHERE peer = ?2 AND request_id = ?3",
                params![serde_json::to_string(&out)?, peer, id],
            )?;
        }
        tx.commit()?;
        Ok(count)
    }
}

/// Bounds concurrent automatic attempts and keeps one attempt per record.
#[derive(Clone)]
pub(crate) struct Dispatcher {
    permits: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashSet<(String, String)>>>,
}

pub(crate) struct Claim {
    key: (String, String),
    in_flight: Arc<Mutex<HashSet<(String, String)>>>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Claim {
    fn drop(&mut self) {
        if let Ok(mut set) = self.in_flight.lock() {
            set.remove(&self.key);
        }
    }
}

impl Dispatcher {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit)),
            in_flight: Arc::default(),
        }
    }
    /// Claims due records not already in flight, up to the free permits.
    pub(crate) fn claim(&self, due: Vec<(String, String)>) -> Vec<Claim> {
        let mut claims = Vec::new();
        let Ok(mut set) = self.in_flight.lock() else {
            return claims;
        };
        for key in due {
            if set.contains(&key) {
                continue;
            }
            let Ok(permit) = self.permits.clone().try_acquire_owned() else {
                break;
            };
            set.insert(key.clone());
            claims.push(Claim {
                key,
                in_flight: self.in_flight.clone(),
                _permit: permit,
            });
        }
        claims
    }
}

async fn attempt(store: Arc<Store>, peer: String, id: String) {
    let Ok(out) = blocking(store.clone(), move |s| s.outbound(&peer, &id)).await else {
        return;
    };
    // An explicit retry or refresh may have finished it or moved its schedule.
    if out.state != "unknown" || due_at(&out).is_none_or(|at| at > Utc::now()) {
        return;
    }
    let receipt_only = receipt_only(&out, Utc::now());
    let _ = crate::peer::exchange(store, out, receipt_only).await;
}

/// Runs automatic retries until shutdown.
pub async fn retry_worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let _ = blocking(store.clone(), |s| s.spread_overdue(Utc::now())).await;
    let dispatcher = Dispatcher::new(CONCURRENCY);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
        let Ok(due) = blocking(store.clone(), |s| s.due_retries(Utc::now())).await else {
            continue;
        };
        for claim in dispatcher.claim(due) {
            let store = store.clone();
            let (peer, id) = claim.key.clone();
            tokio::spawn(async move {
                attempt(store, peer, id).await;
                drop(claim);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_store::MessageRequest;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }
    fn record(state: &str, deadline: &str) -> OutboundMessage {
        OutboundMessage {
            peer_host_id: format!("host_{}", "a".repeat(64)),
            request: MessageRequest {
                request_id: format!("request_{}", "0".repeat(32)),
                grant_id: format!("grant_{}", "0".repeat(32)),
                target_agent_id: format!("agent_{}", "0".repeat(32)),
                deadline: deadline.into(),
                content: "hello".into(),
            },
            state: state.into(),
            receipt: None,
            error: None,
            attempts: 0,
            next_attempt_at: None,
            receipt_queries: 0,
        }
    }

    #[test]
    fn backoff_doubles_to_a_minute_within_jitter() {
        let seconds = |n| backoff(n, 0.0).num_milliseconds();
        assert_eq!(
            [1, 2, 3, 4, 5, 6, 7, 30].map(seconds),
            [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000]
        );
        assert_eq!(backoff(1, 0.2).num_milliseconds(), 1_200);
        assert_eq!(backoff(1, -0.2).num_milliseconds(), 800);
        assert_eq!(backoff(9, 0.2).num_milliseconds(), 72_000);
        for _ in 0..1000 {
            let j = jitter();
            assert!((-0.2..=0.2).contains(&j), "{j}");
        }
    }

    #[test]
    fn unknown_outcomes_schedule_and_final_outcomes_stop() {
        let now = at("2026-10-07T00:00:00Z");
        let mut out = record("unknown", "2026-10-07T01:00:00Z");
        schedule(&mut out, false, now, 0.0);
        assert_eq!(out.attempts, 1);
        assert_eq!(out.next_attempt_at.as_deref(), Some("2026-10-07T00:00:01Z"));
        schedule(&mut out, false, now, 0.0);
        assert_eq!(out.next_attempt_at.as_deref(), Some("2026-10-07T00:00:02Z"));
        for state in ["accepted", "rejected"] {
            let mut done = record(state, "2026-10-07T01:00:00Z");
            done.next_attempt_at = Some("2026-10-07T00:00:05Z".into());
            schedule(&mut done, false, now, 0.0);
            assert_eq!(done.next_attempt_at, None, "{state}");
        }
    }

    #[test]
    fn deadline_switches_to_receipt_queries_and_limits_them() {
        let deadline = "2026-10-07T00:00:00Z";
        let mut out = record("unknown", deadline);
        assert!(!receipt_only(&out, at("2026-10-06T23:59:59Z")));
        assert!(receipt_only(&out, at(deadline)));
        // Before the deadline, refreshes do not count toward the limit.
        schedule(&mut out, true, at("2026-10-06T23:00:00Z"), 0.0);
        assert_eq!(out.receipt_queries, 0);
        for n in 1..=9 {
            schedule(&mut out, true, at("2026-10-07T00:10:00Z"), 0.0);
            assert_eq!(out.receipt_queries, n);
            assert!(out.next_attempt_at.is_some(), "query {n}");
        }
        schedule(&mut out, true, at("2026-10-07T00:10:00Z"), 0.0);
        assert_eq!(out.receipt_queries, 10);
        assert_eq!(out.next_attempt_at, None);

        let mut late = record("unknown", deadline);
        schedule(&mut late, true, at("2026-10-08T00:00:00Z"), 0.0);
        assert_eq!(late.next_attempt_at, None, "24 hours past the deadline");
    }

    fn insert(store: &Store, peer: &str, id: &str, record: &str) {
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO outbound_messages VALUES (?1, ?2, ?3)",
                params![peer, id, record],
            )
            .unwrap();
    }
    fn stored(out: &OutboundMessage) -> String {
        serde_json::to_string(out).unwrap()
    }

    #[test]
    fn due_records_include_legacy_and_exclude_final_or_stopped() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let now = at("2026-10-07T00:00:00Z");
        let mut due = record("unknown", "2026-10-07T01:00:00Z");
        due.next_attempt_at = Some("2026-10-06T23:59:59Z".into());
        insert(&store, "p", "due", &stored(&due));
        let mut later = due.clone();
        later.next_attempt_at = Some("2026-10-07T00:00:01Z".into());
        insert(&store, "p", "later", &stored(&later));
        let stopped = record("unknown", "2026-10-07T01:00:00Z");
        insert(&store, "p", "stopped", &stored(&stopped));
        let mut accepted = record("accepted", "2026-10-07T01:00:00Z");
        accepted.next_attempt_at = Some("2026-10-06T00:00:00Z".into());
        insert(&store, "p", "accepted", &stored(&accepted));
        // A record from before this milestone has no schedule fields at all.
        let mut legacy: serde_json::Value =
            serde_json::to_value(record("unknown", "2026-10-07T01:00:00Z")).unwrap();
        let map = legacy.as_object_mut().unwrap();
        map.remove("attempts");
        map.remove("next_attempt_at");
        insert(&store, "p", "legacy", &legacy.to_string());
        let ids: Vec<String> = store
            .due_retries(now)
            .unwrap()
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        assert_eq!(ids, ["legacy", "due"]);
        let read: OutboundMessage = serde_json::from_str(&legacy.to_string()).unwrap();
        assert_eq!((read.attempts, read.next_attempt_at), (0, None));
    }

    #[test]
    fn restart_spreads_overdue_records_over_ten_seconds() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("host")).unwrap();
        let now = at("2026-10-07T00:00:00Z");
        for n in 0..5 {
            let mut out = record("unknown", "2026-10-07T01:00:00Z");
            out.next_attempt_at = Some(format!("2026-10-06T23:00:0{n}Z"));
            insert(&store, "p", &format!("r{n}"), &stored(&out));
        }
        let mut future = record("unknown", "2026-10-07T01:00:00Z");
        future.next_attempt_at = Some("2026-10-07T00:05:00Z".into());
        insert(&store, "p", "future", &stored(&future));
        assert_eq!(store.spread_overdue(now).unwrap(), 5);
        let mut times: Vec<String> = (0..5)
            .map(|n| {
                store
                    .outbound("p", &format!("r{n}"))
                    .unwrap()
                    .next_attempt_at
                    .unwrap()
            })
            .collect();
        times.sort();
        assert_eq!(
            times,
            [
                "2026-10-07T00:00:00Z",
                "2026-10-07T00:00:02Z",
                "2026-10-07T00:00:04Z",
                "2026-10-07T00:00:06Z",
                "2026-10-07T00:00:08Z"
            ]
        );
        assert_eq!(
            store
                .outbound("p", "future")
                .unwrap()
                .next_attempt_at
                .as_deref(),
            Some("2026-10-07T00:05:00Z")
        );
        // Only the first is due immediately; the rest follow over the window.
        assert_eq!(store.due_retries(now).unwrap().len(), 1);
        assert_eq!(
            store.due_retries(at("2026-10-07T00:00:10Z")).unwrap().len(),
            5
        );
    }

    #[test]
    fn dispatcher_caps_concurrency_and_never_doubles_a_record() {
        let dispatcher = Dispatcher::new(CONCURRENCY);
        let keys = |n: usize| {
            (0..n)
                .map(|i| ("p".to_string(), format!("r{i}")))
                .collect::<Vec<_>>()
        };
        let mut first = dispatcher.claim(keys(10));
        assert_eq!(first.len(), 4);
        // Records already in flight are skipped, and no permits remain.
        assert!(dispatcher.claim(keys(10)).is_empty());
        drop(first.remove(0));
        let second = dispatcher.claim(keys(10));
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].key, ("p".to_string(), "r0".to_string()));
    }
}
