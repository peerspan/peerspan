//! Presence notifications (launch slice 6), sending side. A host's presence
//! is what its peer route would serve for its agents, ignoring
//! authorizations: the agents, with each one's `connected` and `channel`. It
//! is the same in every network, so a change is announced in all of them,
//! each on its coordinator's relay connection when that runs version 3.
//!
//! The worker keeps a fingerprint of the presence and recomputes it when a
//! store change may have altered it (`Store::presence_changed`), when the
//! earliest live lease lapses (nothing else runs then), and every 30 seconds
//! as a fallback. Sends are at most one per network per 250 milliseconds;
//! a change within that window is sent when it ends.
use crate::{
    api::blocking,
    membership,
    model::Error,
    relay::{Coordinator, Presence},
    store::Store,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// The least time between two `presence` frames for one network.
const WINDOW: Duration = Duration::from_millis(250);
/// Recomputes the presence at least this often, in case a change was not
/// signalled.
const FALLBACK: Duration = Duration::from_secs(30);
/// How soon to retry a `presence` that found its relay queue full.
const BUSY_RETRY: Duration = Duration::from_millis(50);

/// Networks with a `presence` still to send, and when each was last sent.
#[derive(Default)]
pub(crate) struct State {
    pending: BTreeSet<String>,
    sent: BTreeMap<String, Instant>,
}

impl Store {
    /// Signals that this host's presence may have changed. Cheap and safe
    /// inside a transaction: the worker reads after the connection is free.
    pub(crate) fn presence_changed(&self) {
        self.presence_wake.notify_one();
    }

    /// The presence fingerprint, and when the earliest live lease lapses (in
    /// Unix milliseconds). Leases never outlast their credential's expiry,
    /// so the lease time also covers an authorization expiring.
    fn presence_view(&self) -> Result<(String, Option<i64>), Error> {
        let conn = self.connection()?;
        let agents: Vec<(String, String)> = {
            let mut statement = conn.prepare("SELECT id, name FROM agents ORDER BY name, id")?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        let mut hash = Sha256::new();
        for (id, name) in agents {
            let channel = self.agent_channel(&conn, &id)?;
            hash.update(serde_json::to_vec(&(&id, &name, channel))?);
        }
        let lapse: Option<i64> = conn.query_row(
            "SELECT MIN(x.lease_until_ms) FROM sessions s JOIN adapter_credentials c ON c.session_id = s.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE s.state = 'attached' AND x.lease_until_ms > ?1",
            [Utc::now().timestamp_millis()],
            |r| r.get(0),
        )?;
        Ok((hex::encode(hash.finalize()), lapse))
    }

    /// Each network of this host with its coordinator.
    fn presence_networks(&self) -> Result<Vec<(String, Coordinator)>, Error> {
        Ok(self
            .networks()?
            .into_iter()
            .filter_map(|n| {
                let key = membership::canonical(&n.coordinator_public_key, 32).ok()?;
                Some((
                    n.id,
                    Coordinator {
                        address: n.coordinator_address,
                        key,
                    },
                ))
            })
            .collect())
    }

    fn presence_state(&self) -> Option<std::sync::MutexGuard<'_, State>> {
        self.presence.lock().ok()
    }
}

/// Queues `presence` for the given networks, or all of them.
fn mark(store: &Store, networks: impl IntoIterator<Item = String>) {
    if let Some(mut state) = store.presence_state() {
        state.pending.extend(networks);
    }
    store.presence_changed();
}

/// After a version 3 relay connection to `coordinator` is established:
/// announces every network of this host on it.
pub(crate) fn reconnected(store: &Arc<Store>, coordinator: &Coordinator) {
    let (store, coordinator) = (store.clone(), coordinator.clone());
    tokio::spawn(async move {
        let Ok(networks) = blocking(store.clone(), |s| s.presence_networks()).await else {
            return;
        };
        mark(
            &store,
            networks
                .into_iter()
                .filter(|(_, c)| *c == coordinator)
                .map(|(id, _)| id),
        );
    });
}

/// Sends what is due and returns when the next deferred send is due.
async fn flush(store: &Arc<Store>) -> Option<Instant> {
    if store.presence_state()?.pending.is_empty() {
        return None;
    }
    let networks: BTreeMap<String, Coordinator> =
        blocking(store.clone(), |s| s.presence_networks())
            .await
            .ok()?
            .into_iter()
            .collect();
    let relays = crate::quic::relays(store);
    let mut state = store.presence_state()?;
    let State { pending, sent } = &mut *state;
    sent.retain(|id, _| networks.contains_key(id));
    let now = Instant::now();
    let mut next: Option<Instant> = None;
    pending.retain(|id| {
        let Some(coordinator) = networks.get(id) else {
            return false;
        };
        if let Some(at) = sent.get(id)
            && now.saturating_duration_since(*at) < WINDOW
        {
            let due = *at + WINDOW;
            next = Some(next.map_or(due, |n| n.min(due)));
            return true;
        }
        // Without a version 3 connection there is nobody to tell; the
        // announcement on (re)connection covers it. A full queue keeps the
        // network pending, since nothing else would announce it again.
        match relays.as_ref().map(|r| r.presence(coordinator, id)) {
            Some(Presence::Queued) => {
                sent.insert(id.clone(), now);
                false
            }
            Some(Presence::Busy) => {
                let due = now + BUSY_RETRY;
                next = Some(next.map_or(due, |n| n.min(due)));
                true
            }
            Some(Presence::Unsent) | None => false,
        }
    });
    next
}

/// Announces this host's presence changes until shutdown.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let mut seen: Option<String> = None;
    let all = |store: Arc<Store>| async move {
        if let Ok(networks) = blocking(store.clone(), |s| s.presence_networks()).await {
            mark(&store, networks.into_iter().map(|(id, _)| id));
        }
    };
    // One after startup, whatever the view.
    all(store.clone()).await;
    loop {
        let mut wait = FALLBACK;
        if let Ok((fingerprint, lapse)) = blocking(store.clone(), |s| s.presence_view()).await {
            if seen.as_ref().is_some_and(|s| *s != fingerprint) {
                all(store.clone()).await;
            }
            seen = Some(fingerprint);
            if let Some(until) = lapse {
                // A lease is live while its time is ahead; look just after.
                let ms = until.saturating_sub(Utc::now().timestamp_millis()) + 5;
                wait = wait.min(Duration::from_millis(ms.max(1) as u64));
            }
        }
        if let Some(due) = flush(&store).await {
            wait = wait.min(due.saturating_duration_since(Instant::now()));
        }
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = store.presence_wake.notified() => {}
            _ = shutdown.changed() => return,
        }
    }
}
