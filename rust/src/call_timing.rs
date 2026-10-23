//! Call timing (owner decision 15): an agent's `POST /adapter/v1/calls` is
//! held at this daemon until the call is final or its wait ends, and for a
//! call's first 60 seconds after acceptance this daemon holds a status
//! request open at the serving host, so a result arrives as soon as it
//! exists. As the serving host, `GET /peer/v1/calls/{id}?wait=N&state=S`
//! is held until the call's state differs from `S`.
use crate::{
    api::blocking,
    call_outbound::CallKey,
    calls::{CallView, STATES, is_final},
    model::Error,
    store::Store,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// How long `POST /adapter/v1/calls` holds its response at most, and the
/// bound on its steps 4 to 7. It must stay at or below 45 seconds, within
/// the adapter's 50-second request timeout.
pub(crate) const WAIT_LIMIT: Duration = Duration::from_secs(15);
/// The longest wait `GET /peer/v1/calls/{id}` accepts, and the wait this
/// daemon asks for.
pub(crate) const PEER_WAIT_MAX: u64 = 10;
/// How long after acceptance held status requests replace polling.
const HELD_WINDOW: Duration = Duration::from_secs(60);
/// The pause after a quick answer that did not change the state, as from a
/// host that predates `wait`, or after a failed request.
const QUICK_PAUSE: Duration = Duration::from_secs(1);
/// How often a held peer status request rechecks the call.
const RECEIVER_CHECK: Duration = Duration::from_millis(50);

/// The in-memory state of held requests.
#[derive(Default)]
pub(crate) struct Timing {
    /// Bumped after an outbound call's final status is stored, waking the
    /// agent requests held on calls.
    finals: watch::Sender<u64>,
    /// When each outbound call was accepted, while in its held window.
    accepted: Mutex<HashMap<CallKey, Instant>>,
    /// Outbound calls with held status requests in progress.
    following: Mutex<HashSet<CallKey>>,
    /// Outbound calls an agent's POST is holding, with how many.
    held: Mutex<HashMap<CallKey, usize>>,
    /// Set on shutdown: held requests answer at once.
    closing: watch::Sender<bool>,
}

impl Timing {
    /// Wakes the requests held on calls; sent after a final status commits.
    pub(crate) fn signal_final(&self) {
        self.finals.send_modify(|n| *n = n.wrapping_add(1));
    }
    /// Answers every held request at once, and holds no more; for shutdown.
    pub(crate) fn close(&self) {
        self.closing.send_replace(true);
    }
    /// Whether held status requests are in progress for a call, so the poll
    /// workers leave it alone.
    pub(crate) fn following(&self, key: &CallKey) -> bool {
        self.following.lock().is_ok_and(|f| f.contains(key))
    }
    /// Whether an agent's POST is holding a call, so its call-update
    /// notification is not claimed.
    pub(crate) fn held(&self, peer: &str, id: &str) -> bool {
        self.held
            .lock()
            .is_ok_and(|h| h.contains_key(&(peer.to_owned(), id.to_owned())))
    }
}

/// Marks a call held by an agent's POST until dropped.
struct Hold<'a> {
    timing: &'a Timing,
    key: CallKey,
}
impl<'a> Hold<'a> {
    fn new(timing: &'a Timing, key: CallKey) -> Self {
        if let Ok(mut held) = timing.held.lock() {
            *held.entry(key.clone()).or_default() += 1;
        }
        Hold { timing, key }
    }
}
impl Drop for Hold<'_> {
    fn drop(&mut self) {
        if let Ok(mut held) = self.timing.held.lock()
            && let Some(n) = held.get_mut(&self.key)
        {
            *n -= 1;
            if *n == 0 {
                held.remove(&self.key);
            }
        }
    }
}

/// Holds an agent's call request until the view `fetch` returns is final or
/// `until` passes, and answers with the latest view. The call's
/// notification is not claimed meanwhile; the final view marks it seen.
pub(crate) async fn hold<V, F>(
    store: &Arc<Store>,
    key: CallKey,
    until: Instant,
    state: impl Fn(&V) -> &str,
    fetch: F,
) -> Result<V, Error>
where
    V: Send + 'static,
    F: Fn(&Store) -> Result<V, Error> + Clone + Send + 'static,
{
    let _hold = Hold::new(&store.call_timing, key);
    let mut finals = store.call_timing.finals.subscribe();
    let mut closing = store.call_timing.closing.subscribe();
    loop {
        finals.borrow_and_update();
        let view = blocking(store.clone(), fetch.clone()).await?;
        if is_final(state(&view)) || Instant::now() >= until || *closing.borrow_and_update() {
            return Ok(view);
        }
        tokio::select! {
            _ = finals.changed() => {}
            _ = closing.changed() => {}
            _ = tokio::time::sleep_until(until.into()) => {}
        }
    }
}

/// Starts an accepted call's held window, unless it has one, and the held
/// status requests for it unless they are in progress.
pub(crate) fn accepted(store: &Arc<Store>, key: CallKey) {
    let now = Instant::now();
    let Ok(mut accepted) = store.call_timing.accepted.lock() else {
        return;
    };
    accepted.retain(|_, at| now.duration_since(*at) < HELD_WINDOW);
    let at = *accepted.entry(key.clone()).or_insert(now);
    drop(accepted);
    if now.duration_since(at) >= HELD_WINDOW {
        return;
    }
    let Ok(mut following) = store.call_timing.following.lock() else {
        return;
    };
    if following.insert(key.clone()) {
        tokio::spawn(follow(store.clone(), key, at));
    }
}

/// Sends held status requests one at a time, each as soon as the previous
/// answers, until the call is final or its held window passes; the poll
/// workers then back off as usual. Held requests do not use the task
/// polling slots.
async fn follow(store: Arc<Store>, key: CallKey, accepted: Instant) {
    while accepted.elapsed() < HELD_WINDOW {
        let sent = Instant::now();
        match crate::call_outbound::poll_held(store.clone(), &key.0, &key.1).await {
            // Final, or no longer accepted.
            Ok(None) => break,
            // A new state is followed at once.
            Ok(Some(true)) => continue,
            // The same state: at once after a held answer, and a second
            // later after a quick one.
            Ok(Some(false)) if sent.elapsed() >= QUICK_PAUSE => continue,
            Ok(Some(false)) | Err(_) => tokio::time::sleep(QUICK_PAUSE).await,
        }
    }
    if let Ok(mut following) = store.call_timing.following.lock() {
        following.remove(&key);
    }
}

/// Parses `wait` and `state` of `GET /peer/v1/calls/{id}`: an absent wait
/// is 0, and a wait is an integer from 0 to 10; a state is a call state.
pub(crate) fn peer_wait(
    wait: Option<String>,
    state: Option<String>,
) -> Result<(u64, Option<String>), Error> {
    if let Some(state) = &state
        && !STATES.contains(&state.as_str())
    {
        return Err(Error::Invalid("state is a call state".into()));
    }
    let wait = match wait {
        None => 0,
        Some(text) => text
            .parse::<u64>()
            .ok()
            .filter(|n| *n <= PEER_WAIT_MAX)
            .ok_or_else(|| {
                Error::Invalid(format!("wait is an integer from 0 to {PEER_WAIT_MAX}"))
            })?,
    };
    Ok((wait, state))
}

/// The submitter's call, held until its state differs from `known` (or,
/// without it, from the state on arrival), it is final, or `wait` seconds
/// pass.
pub(crate) async fn held_status(
    store: Arc<Store>,
    sender: String,
    id: String,
    wait: u64,
    mut known: Option<String>,
) -> Result<CallView, Error> {
    let until = Instant::now() + Duration::from_secs(wait);
    let mut closing = store.call_timing.closing.subscribe();
    loop {
        let (s, i) = (sender.clone(), id.clone());
        let view = blocking(store.clone(), move |st| st.call_status(&s, &i)).await?;
        let state = &view.status.state;
        let known = known.get_or_insert_with(|| state.clone());
        let now = Instant::now();
        if is_final(state) || state != known || now >= until || *closing.borrow_and_update() {
            return Ok(view);
        }
        tokio::select! {
            _ = closing.changed() => {}
            _ = tokio::time::sleep(RECEIVER_CHECK.min(until - now)) => {}
        }
    }
}
