//! Direct policy propagation among an owner's hosts (roadmap 2c). A host
//! bound to person P pushes P's policies to its siblings (the other current
//! member hosts bound to P in its membership view) and to the coordinator,
//! retrying with backoff, and syncs with each sibling on start, periodically,
//! and when a sibling appears. Withholding a withdrawal then also requires
//! partitioning the owner's hosts from one another. Block lists stay local.
use crate::{
    api::blocking,
    membership::invalid,
    model::Error,
    peer_store::json,
    policy::{Accepted, Policy},
    store::{Store, append_event, now, rfc3339},
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::{get, post},
};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// Database version 12: queued policy deliveries per owner and target.
pub(crate) const SCHEMA: &str = "
CREATE TABLE policy_deliveries (network_id TEXT NOT NULL, person_id TEXT NOT NULL, target TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, person_id, target));
PRAGMA user_version = 12;
";

/// The delivery target that stands for the network's coordinator.
pub const COORDINATOR: &str = "coordinator";
/// Seconds between periodic syncs with every sibling.
pub const SYNC_INTERVAL_SECONDS: u64 = 300;
const FIRST_DELAY_MS: i64 = 1_000;
const MAX_DELAY_MS: i64 = 300_000;
const POLL: Duration = Duration::from_millis(250);
const REQUEST_BOUND: Duration = Duration::from_secs(8);

/// One queued delivery of the owner's stored policy to a sibling host or
/// the coordinator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDelivery {
    pub target: String,
    pub version: u64,
    /// `pending` or `delivered`.
    pub state: String,
    pub attempts: u32,
    pub next_attempt_at: Option<String>,
    pub error: Option<String>,
    pub delivered_at: Option<String>,
}

/// `access sync` status: this host's person's stored policy and its
/// deliveries.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncStatus {
    pub person_id: String,
    pub version: Option<u64>,
    pub sha256: Option<String>,
    pub deliveries: Vec<PolicyDelivery>,
}

/// What a sibling reports holding after a push.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredPolicy {
    pub person_id: String,
    pub version: u64,
    pub sha256: String,
}
impl StoredPolicy {
    fn of(p: &Policy) -> Self {
        Self {
            person_id: p.person_id(),
            version: p.version,
            sha256: p.sha256(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushPolicy {
    policy: Policy,
}

/// The backoff after `attempts` failed attempts: 1 second, doubling to 5
/// minutes, scaled by `1 + jitter` with `jitter` within ±0.2.
pub(crate) fn backoff(attempts: u32, jitter: f64) -> TimeDelta {
    let exponent = attempts.saturating_sub(1).min(20);
    let base = (FIRST_DELAY_MS << exponent).min(MAX_DELAY_MS) as f64;
    TimeDelta::milliseconds((base * (1.0 + jitter)).round() as i64)
}

/// A stored delivery row: the status fields plus the policy it carries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DeliveryRecord {
    #[serde(flatten)]
    delivery: PolicyDelivery,
    policy: Policy,
}
impl DeliveryRecord {
    fn pending(target: &str, policy: &Policy, at: &str) -> Self {
        Self {
            delivery: PolicyDelivery {
                target: target.into(),
                version: policy.version,
                state: "pending".into(),
                attempts: 0,
                next_attempt_at: Some(at.into()),
                error: None,
                delivered_at: None,
            },
            policy: policy.clone(),
        }
    }
    /// Whether two rows carry the same policy.
    fn same_policy(&self, other: &Self) -> bool {
        self.policy.version == other.policy.version
            && self.policy.signature == other.policy.signature
    }
}

impl Store {
    /// The person this host is bound to in a network.
    pub(crate) fn own_person(
        &self,
        connection: &Connection,
        network: &str,
    ) -> Result<Option<String>, Error> {
        Ok(self
            .own_members(connection)?
            .into_iter()
            .find(|(n, _)| n == network)
            .and_then(|(_, m)| m.person_id))
    }
    /// The other current member hosts bound to `person` in this host's
    /// membership view.
    pub(crate) fn siblings(
        &self,
        connection: &Connection,
        network: &str,
        person: &str,
    ) -> Result<Vec<String>, Error> {
        let own = self.identity().id;
        Ok(self
            .stored_members(connection, network)?
            .into_iter()
            .filter(|m| m.host_id != own && m.person_id.as_deref() == Some(person))
            .map(|m| m.host_id)
            .collect())
    }
    /// Whether `host` and this host are both bound to `person` in a network.
    fn sibling_of(
        &self,
        connection: &Connection,
        network: &str,
        person: &str,
        host: &str,
    ) -> Result<bool, Error> {
        if self.network_record(connection, network).is_err() {
            return Ok(false);
        }
        Ok(
            self.own_person(connection, network)?.as_deref() == Some(person)
                && self
                    .siblings(connection, network, person)?
                    .iter()
                    .any(|s| s == host),
        )
    }
    fn delivery_record(
        &self,
        connection: &Connection,
        network: &str,
        person: &str,
        target: &str,
    ) -> Result<Option<DeliveryRecord>, Error> {
        connection
            .query_row(
                "SELECT record FROM policy_deliveries WHERE network_id = ?1 AND person_id = ?2 AND target = ?3",
                params![network, person, target],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(json)
            .transpose()
    }
    fn put_delivery_record(
        &self,
        connection: &Connection,
        network: &str,
        person: &str,
        d: &DeliveryRecord,
    ) -> Result<(), Error> {
        connection.execute(
            "INSERT OR REPLACE INTO policy_deliveries VALUES (?1, ?2, ?3, ?4)",
            params![
                network,
                person,
                d.delivery.target,
                serde_json::to_string(d)?
            ],
        )?;
        Ok(())
    }
    /// Queues a stored policy of this host's own person for delivery to each
    /// sibling and to the coordinator, replacing every older row of that
    /// person. Policies of other persons are not propagated.
    pub(crate) fn queue_policy_deliveries(
        &self,
        tx: &Transaction<'_>,
        network: &str,
        p: &Policy,
    ) -> Result<(), Error> {
        let person = p.person_id();
        if self.own_person(tx, network)?.as_deref() != Some(person.as_str()) {
            return Ok(());
        }
        let mut targets = self.siblings(tx, network, &person)?;
        targets.push(COORDINATOR.into());
        tx.execute(
            "DELETE FROM policy_deliveries WHERE network_id = ?1 AND person_id = ?2",
            params![network, person],
        )?;
        let at = now();
        for target in &targets {
            self.put_delivery_record(
                tx,
                network,
                &person,
                &DeliveryRecord::pending(target, p, &at),
            )?;
        }
        Ok(())
    }
    /// Queues a delivery to the coordinator alone, for a policy the owner
    /// submitted on a host that is not bound to them.
    fn queue_coordinator_delivery(
        &self,
        tx: &Transaction<'_>,
        network: &str,
        p: &Policy,
    ) -> Result<(), Error> {
        self.put_delivery_record(
            tx,
            network,
            &p.person_id(),
            &DeliveryRecord::pending(COORDINATOR, p, &now()),
        )
    }
    /// Deletes rows to hosts that are no longer siblings: for a person this
    /// host is not bound to, only a coordinator row remains. Returns the rows
    /// kept.
    fn prune_deliveries(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<Vec<(String, String, DeliveryRecord)>, Error> {
        let rows: Vec<(String, String, String)> = {
            let mut statement = tx.prepare(
                "SELECT network_id, person_id, record FROM policy_deliveries ORDER BY network_id, person_id, target",
            )?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?
        };
        let mut siblings: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        let mut kept = Vec::new();
        for (network, person, record) in rows {
            let record: DeliveryRecord = json(record)?;
            let target = record.delivery.target.clone();
            let keep = target == COORDINATOR || {
                let key = (network.clone(), person.clone());
                if !siblings.contains_key(&key) {
                    let current = if self.network_record(tx, &network).is_ok()
                        && self.own_person(tx, &network)?.as_deref() == Some(person.as_str())
                    {
                        self.siblings(tx, &network, &person)?
                    } else {
                        Vec::new()
                    };
                    siblings.insert(key.clone(), current);
                }
                siblings[&key].contains(&target)
            };
            if keep {
                kept.push((network, person, record));
            } else {
                tx.execute(
                    "DELETE FROM policy_deliveries WHERE network_id = ?1 AND person_id = ?2 AND target = ?3",
                    params![network, person, target],
                )?;
            }
        }
        Ok(kept)
    }
    /// Drops rows to hosts that are no longer siblings, then lists the pending
    /// ones due at `at`, or, when `at` is `None`, every pending row of this
    /// host's own person in `network`.
    pub(crate) fn due_policy_deliveries(
        &self,
        network: Option<&str>,
        at: Option<DateTime<Utc>>,
    ) -> Result<Vec<(String, String, String)>, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let kept = self.prune_deliveries(&tx)?;
        let own = match network {
            Some(n) => self.own_person(&tx, n)?,
            None => None,
        };
        let due = kept
            .into_iter()
            .filter(|(n, p, r)| {
                r.delivery.state == "pending"
                    && match (network, at) {
                        (Some(wanted), None) => wanted == n && own.as_deref() == Some(p.as_str()),
                        (wanted, Some(at)) => {
                            wanted.is_none_or(|w| w == n)
                                && crate::retry::due_at(&r.delivery.next_attempt_at)
                                    .is_none_or(|t| t <= at)
                        }
                        (None, None) => true,
                    }
            })
            .map(|(n, p, r)| (n, p, r.delivery.target))
            .collect();
        tx.commit()?;
        Ok(due)
    }
    /// A pending delivery and the network it belongs to.
    fn delivery_job(
        &self,
        network: &str,
        person: &str,
        target: &str,
    ) -> Result<Option<(DeliveryRecord, crate::network::Network)>, Error> {
        let connection = self.connection()?;
        let Ok(record) = self.network_record(&connection, network) else {
            return Ok(None);
        };
        let Some(d) = self.delivery_record(&connection, network, person, target)? else {
            return Ok(None);
        };
        if d.delivery.state != "pending" {
            return Ok(None);
        }
        if target != COORDINATOR && !self.sibling_of(&connection, network, person, target)? {
            connection.execute(
                "DELETE FROM policy_deliveries WHERE network_id = ?1 AND person_id = ?2 AND target = ?3",
                params![network, person, target],
            )?;
            return Ok(None);
        }
        Ok(Some((d, record)))
    }
    /// Records an attempt's outcome, unless a newer policy superseded the
    /// row meanwhile.
    fn finish_delivery(
        &self,
        network: &str,
        person: &str,
        attempted: &DeliveryRecord,
        outcome: Result<(), String>,
        jitter: f64,
    ) -> Result<bool, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let target = &attempted.delivery.target;
        let Some(mut r) = self.delivery_record(&tx, network, person, target)? else {
            return Ok(false);
        };
        if !r.same_policy(attempted) || r.delivery.state != "pending" {
            return Ok(false);
        }
        let at = Utc::now();
        let d = &mut r.delivery;
        d.attempts = d.attempts.saturating_add(1);
        let delivered = outcome.is_ok();
        match outcome {
            Ok(()) => {
                d.state = "delivered".into();
                d.delivered_at = Some(rfc3339(at));
                d.next_attempt_at = None;
                d.error = None;
                append_event(
                    &tx,
                    "network.policy_delivered",
                    &format!("{person}/{target}"),
                    &rfc3339(at),
                )?;
            }
            Err(error) => {
                d.error = Some(error);
                d.next_attempt_at = Some(rfc3339(at + backoff(d.attempts, jitter)));
            }
        }
        self.put_delivery_record(&tx, network, person, &r)?;
        tx.commit()?;
        Ok(delivered)
    }
    /// Whether the coordinator row holds `p` as delivered.
    fn delivered_to_coordinator(
        &self,
        network: &str,
        person: &str,
        p: &Policy,
    ) -> Result<bool, Error> {
        let connection = self.connection()?;
        Ok(self
            .delivery_record(&connection, network, person, COORDINATOR)?
            .is_some_and(|r| {
                r.delivery.state == "delivered"
                    && r.policy.version == p.version
                    && r.policy.signature == p.signature
            }))
    }
    /// Applies the acceptance rule to a policy the owner's CLI or the renewal
    /// task signed. An identical policy is accepted again; a lower version, or
    /// an equal one that loses the tie-break, is a conflict.
    fn submit_local_policy(&self, network: &str, p: &Policy) -> Result<Accepted, Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        self.network_record(&tx, network)?;
        let outcome = self.accept_policy(&tx, network, p, Utc::now())?;
        match &outcome {
            Accepted::Kept(old) => {
                return Err(Error::Conflict(format!(
                    "policy version {} does not supersede the stored version {}",
                    p.version, old.version
                )));
            }
            Accepted::Stored
                if self.own_person(&tx, network)?.as_deref() != Some(p.person_id().as_str()) =>
            {
                self.queue_coordinator_delivery(&tx, network, p)?;
            }
            _ => {}
        }
        tx.commit()?;
        Ok(outcome)
    }
    /// A sibling's push: both hosts must be bound to the policy's owner.
    fn accept_pushed_policy(
        &self,
        sender: &str,
        network: &str,
        p: &Policy,
    ) -> Result<StoredPolicy, Error> {
        crate::membership::check_network(&p.network_id, network)?;
        let person = crate::persons::person_id_of(&p.person_public_key)
            .map_err(|_| invalid("invalid policy owner key"))?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if !self.sibling_of(&tx, network, &person, sender)? {
            return Err(Error::Forbidden);
        }
        // A sibling's policy whose owner is not current is invalid.
        self.accept_policy(&tx, network, p, Utc::now())
            .map_err(|e| match e {
                Error::Forbidden => invalid("the policy owner is not a current person"),
                other => other,
            })?;
        let stored = self
            .stored_policy(&tx, network, &p.person_public_key)?
            .ok_or(Error::NotFound)?;
        tx.commit()?;
        self.policy_wake.notify_one();
        Ok(StoredPolicy::of(&stored))
    }
    /// The stored policy of `person`, for a sibling of that person only.
    fn sibling_policy(&self, sender: &str, network: &str, person: &str) -> Result<Policy, Error> {
        let connection = self.connection()?;
        if !self.sibling_of(&connection, network, person, sender)? {
            return Err(Error::Forbidden);
        }
        let key = self
            .person_key(&connection, network, person)?
            .ok_or(Error::NotFound)?;
        self.stored_policy(&connection, network, &key)?
            .ok_or(Error::NotFound)
    }
    /// Applies the acceptance rule to a sibling's answer; whether it stored a
    /// newer policy.
    fn accept_synced_policy(
        &self,
        network: &str,
        person: &str,
        sibling: &str,
        p: &Policy,
    ) -> Result<bool, Error> {
        if p.person_id() != person {
            return Err(invalid("the sibling returned another person's policy"));
        }
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let stored = self.accept_policy(&tx, network, p, Utc::now())? == Accepted::Stored;
        if stored {
            append_event(
                &tx,
                "network.policy_synced",
                &format!("{person}/{sibling}"),
                &now(),
            )?;
        }
        tx.commit()?;
        if stored {
            self.policy_wake.notify_one();
        }
        Ok(stored)
    }
    /// Every network where this host is bound, with its person and siblings.
    fn all_siblings(&self) -> Result<Vec<(String, String, Vec<String>)>, Error> {
        let connection = self.connection()?;
        let mut out = Vec::new();
        for (network, own) in self.own_members(&connection)? {
            if let Some(person) = own.person_id {
                let siblings = self.siblings(&connection, &network, &person)?;
                out.push((network, person, siblings));
            }
        }
        Ok(out)
    }
    /// This host's person and siblings in one network.
    fn network_siblings(&self, network: &str) -> Result<(String, Vec<String>), Error> {
        let connection = self.connection()?;
        self.network_record(&connection, network)?;
        let person = self
            .own_person(&connection, network)?
            .ok_or(Error::NotFound)?;
        let siblings = self.siblings(&connection, network, &person)?;
        Ok((person, siblings))
    }
    /// `access sync --status`.
    pub fn policy_sync_status(&self, network: &str) -> Result<SyncStatus, Error> {
        let (person, _) = self.network_siblings(network)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let policy = match self.person_key(&tx, network, &person)? {
            Some(key) => self.stored_policy(&tx, network, &key)?,
            None => None,
        };
        let deliveries = self
            .prune_deliveries(&tx)?
            .into_iter()
            .filter(|(n, p, _)| *n == network && *p == person)
            .map(|(_, _, r)| r.delivery)
            .collect();
        tx.commit()?;
        Ok(SyncStatus {
            person_id: person,
            version: policy.as_ref().map(|p| p.version),
            sha256: policy.as_ref().map(Policy::sha256),
            deliveries,
        })
    }
}

/// Claims a unit of work so it runs once at a time; released on drop.
struct Claim {
    store: Arc<Store>,
    key: String,
}
impl Claim {
    fn take(store: &Arc<Store>, key: String) -> Option<Self> {
        let mut inflight = store.policy_inflight.lock().ok()?;
        inflight.insert(key.clone()).then(|| Self {
            store: store.clone(),
            key,
        })
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        if let Ok(mut inflight) = self.store.policy_inflight.lock() {
            inflight.remove(&self.key);
        }
    }
}

async fn peer_call(
    store: &Arc<Store>,
    host: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let id = host.to_owned();
    let peer = blocking(store.clone(), move |s| s.dial_target(&id))
        .await
        .map_err(|e| e.to_string())?;
    tokio::time::timeout(
        REQUEST_BOUND,
        crate::quic::request(store.clone(), &peer, method, path, body),
    )
    .await
    .map_err(|_| "sibling request timed out".to_owned())?
    .map_err(|e| format!("{e:#}"))
}

/// Pushes a policy to a sibling; done when it reports the same or a higher
/// version.
async fn push_to_sibling(store: &Arc<Store>, sibling: &str, p: &Policy) -> Result<(), String> {
    let body = serde_json::to_vec(&json!({ "policy": p })).map_err(|e| e.to_string())?;
    let path = format!("/peer/v1/networks/{}/policies", p.network_id);
    match peer_call(store, sibling, "POST", &path, &body).await? {
        (200, body) => {
            let reported: StoredPolicy = serde_json::from_slice(&body)
                .map_err(|_| "invalid sibling policy report".to_owned())?;
            if reported.person_id == p.person_id() && reported.version >= p.version {
                Ok(())
            } else {
                Err(format!("sibling holds version {}", reported.version))
            }
        }
        (status, _) => Err(format!("sibling returned HTTP {status}")),
    }
}

/// Submits a policy to the coordinator; done on 200 or 201, whose map is
/// applied, or on 409, which means it holds an equal or higher version.
async fn push_to_coordinator(
    store: &Arc<Store>,
    network: crate::network::Network,
    p: &Policy,
) -> Result<(), String> {
    let response = crate::network::coordinator(
        store.clone(),
        &network.coordinator_address,
        &network.coordinator_public_key,
        format!("/coord/v1/networks/{}/policies", network.id),
        json!({ "policy": p }),
    )
    .await
    .map_err(|e| format!("{e:#}"))?;
    match response {
        (200 | 201, body) => {
            let _ = crate::network::apply_returned_map(store.clone(), network, &body).await;
            Ok(())
        }
        (409, _) => Ok(()),
        (status, body) => Err(crate::network::coordinator_error(status, &body)),
    }
}

/// Attempts one queued delivery; whether it completed, or `None` when
/// another attempt is already in progress.
pub(crate) async fn deliver(
    store: Arc<Store>,
    network: String,
    person: String,
    target: String,
) -> Option<bool> {
    let _claim = Claim::take(&store, format!("deliver {network} {person} {target}"))?;
    Some(attempt(store, network, person, target).await)
}
async fn attempt(store: Arc<Store>, network: String, person: String, target: String) -> bool {
    let (n, p, t) = (network.clone(), person.clone(), target.clone());
    let Ok(Some((attempted, record))) =
        blocking(store.clone(), move |s| s.delivery_job(&n, &p, &t)).await
    else {
        return false;
    };
    let outcome = if target == COORDINATOR {
        push_to_coordinator(&store, record, &attempted.policy).await
    } else {
        push_to_sibling(&store, &target, &attempted.policy).await
    };
    let jitter = crate::retry::jitter();
    match blocking(store, move |s| {
        s.finish_delivery(&network, &person, &attempted, outcome, jitter)
    })
    .await
    {
        Ok(delivered) => delivered,
        Err(e) => {
            eprintln!("policy delivery error: {e}");
            false
        }
    }
}

/// Asks a sibling for its stored policy of their person and applies the
/// acceptance rule to the answer; whether a newer policy was stored.
pub(crate) async fn sync_sibling(
    store: Arc<Store>,
    network: String,
    person: String,
    sibling: String,
) -> Result<bool, String> {
    let Some(_claim) = Claim::take(&store, format!("sync {network} {sibling}")) else {
        return Ok(false);
    };
    let path = format!("/peer/v1/networks/{network}/policies/{person}");
    let policy: Policy = match peer_call(&store, &sibling, "GET", &path, b"").await? {
        (200, body) => {
            serde_json::from_slice(&body).map_err(|_| "invalid sibling policy".to_owned())?
        }
        (404, _) => return Ok(false),
        (status, _) => return Err(format!("sibling returned HTTP {status}")),
    };
    blocking(store, move |s| {
        s.accept_synced_policy(&network, &person, &sibling, &policy)
    })
    .await
    .map_err(|e| e.to_string())
}

/// Records an owner-signed policy from the CLI or the renewal task before
/// submitting it, then submits it to the coordinator and the siblings. The
/// result does not depend on the coordinator being reachable.
pub async fn submit(store: Arc<Store>, network: String, policy: Policy) -> Result<Policy, Error> {
    let (lookup, checked) = (network.clone(), policy.clone());
    blocking(store.clone(), move |s| {
        s.submit_local_policy(&lookup, &checked)
    })
    .await?;
    let checked_policy = policy.clone();
    // Siblings may be slow or offline; the worker pushes to them in the
    // background, while the coordinator is tried once before returning, and
    // synced after it accepts.
    store.policy_wake.notify_one();
    let person = policy.person_id();
    let started = Instant::now();
    let delivered = loop {
        // The worker may hold this delivery already; wait for its attempt.
        match deliver(
            store.clone(),
            network.clone(),
            person.clone(),
            COORDINATOR.into(),
        )
        .await
        {
            Some(done) => break done,
            None if started.elapsed() < REQUEST_BOUND + Duration::from_secs(2) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            None => break false,
        }
    };
    let delivered = delivered || {
        let (n, p) = (network.clone(), person.clone());
        blocking(store.clone(), move |s| {
            s.delivered_to_coordinator(&n, &p, &checked_policy)
        })
        .await
        .unwrap_or(false)
    };
    if delivered {
        let _ = crate::network::sync_network(store, network).await;
    }
    Ok(policy)
}

/// `access sync`: one sync with every sibling now, then every pending
/// delivery of the network retried at once.
pub async fn sync_now(store: Arc<Store>, network: String) -> Result<SyncStatus, Error> {
    let lookup = network.clone();
    let (person, siblings) = blocking(store.clone(), move |s| s.network_siblings(&lookup)).await?;
    let handles: Vec<_> = siblings
        .into_iter()
        .map(|sibling| {
            tokio::spawn(sync_sibling(
                store.clone(),
                network.clone(),
                person.clone(),
                sibling,
            ))
        })
        .collect();
    for h in handles {
        let _ = h.await;
    }
    let lookup = network.clone();
    let due = blocking(store.clone(), move |s| {
        s.due_policy_deliveries(Some(&lookup), None)
    })
    .await?;
    // A delivery the worker is attempting is awaited, so the status reports
    // that attempt's outcome.
    let handles: Vec<_> = due
        .into_iter()
        .map(|(n, p, t)| {
            let store = store.clone();
            tokio::spawn(async move {
                let started = Instant::now();
                while deliver(store.clone(), n.clone(), p.clone(), t.clone())
                    .await
                    .is_none()
                    && started.elapsed() < REQUEST_BOUND + Duration::from_secs(2)
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.await;
    }
    blocking(store, move |s| s.policy_sync_status(&network)).await
}

/// Background propagation until shutdown: syncs with every sibling on start
/// and every interval, and with each sibling as it appears in the membership
/// view, and attempts deliveries as they come due.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    let mut known: BTreeSet<(String, String)> = BTreeSet::new();
    let mut last_full: Option<Instant> = None;
    loop {
        let interval = Duration::from_secs(store.policy_sync_interval.load(Ordering::Relaxed));
        let full = last_full.is_none_or(|t| t.elapsed() >= interval);
        if full {
            last_full = Some(Instant::now());
        }
        if let Ok(all) = blocking(store.clone(), |s| s.all_siblings()).await {
            let mut seen = BTreeSet::new();
            for (network, person, siblings) in all {
                for sibling in siblings {
                    let key = (network.clone(), sibling.clone());
                    if full || !known.contains(&key) {
                        let job = sync_sibling(
                            store.clone(),
                            network.clone(),
                            person.clone(),
                            sibling.clone(),
                        );
                        tokio::spawn(async move {
                            if let Err(e) = job.await {
                                eprintln!("policy sync with {sibling}: {e}");
                            }
                        });
                    }
                    seen.insert(key);
                }
            }
            known = seen;
        }
        if let Ok(due) = blocking(store.clone(), |s| {
            s.due_policy_deliveries(None, Some(Utc::now()))
        })
        .await
        {
            for (n, p, t) in due {
                tokio::spawn(deliver(store.clone(), n, p, t));
            }
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = store.policy_wake.notified() => {}
            _ = tokio::time::sleep(POLL) => {}
        }
    }
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new().route(
        "/v1/networks/{id}/policy/sync",
        get(status_route).post(sync_route),
    )
}
async fn status_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<SyncStatus>, Error> {
    Ok(Json(
        blocking(store, move |s| s.policy_sync_status(&id)).await?,
    ))
}
async fn sync_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<SyncStatus>, Error> {
    Ok(Json(sync_now(store, id).await?))
}

pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/peer/v1/networks/{id}/policies", post(push_route))
        .route("/peer/v1/networks/{id}/policies/{person}", get(fetch_route))
}
async fn push_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<StoredPolicy>, Error> {
    let request: PushPolicy = crate::api::decode(body)?;
    Ok(Json(
        blocking(store, move |s| {
            s.accept_pushed_policy(&sender, &id, &request.policy)
        })
        .await?,
    ))
}
async fn fetch_route(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    Path((id, person)): Path<(String, String)>,
) -> Result<Json<Policy>, Error> {
    Ok(Json(
        blocking(store, move |s| s.sibling_policy(&sender, &id, &person)).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        network::{Member, Network},
        persons::PersonSigner,
        policy::{ACTION, Rule},
    };
    use chrono::SecondsFormat;

    const NETWORK: &str = "net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";

    fn signer(seed: u8) -> PersonSigner {
        PersonSigner::File(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }
    fn host(c: char) -> String {
        format!("host_{}", c.to_string().repeat(64))
    }
    fn stamp(t: DateTime<Utc>) -> String {
        t.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
    fn sign(owner: &PersonSigner, version: u64, offset: i64, principal: &str) -> Policy {
        let issued = Utc::now() - TimeDelta::minutes(1) + TimeDelta::seconds(offset);
        Policy::sign(
            owner,
            NETWORK,
            version,
            &stamp(issued),
            &stamp(issued + TimeDelta::days(7)),
            vec![Rule {
                agent: "reviewer".into(),
                principals: vec![principal.into()],
                actions: vec![ACTION.into()],
                max_message_bytes: 4096,
                max_artifact_bytes: 0,
                allow_disconnected: false,
            }],
        )
        .unwrap()
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        store: Store,
        owner: PersonSigner,
        other: PersonSigner,
        owner_id: String,
        other_id: String,
    }
    /// This host and host A are bound to the owner, host B to another
    /// person, and host C to nobody.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("host")).unwrap();
        let (owner, other) = (signer(5), signer(6));
        let owner_id = crate::persons::person_id(&owner.public_key());
        let other_id = crate::persons::person_id(&other.public_key());
        let network = Network {
            id: NETWORK.into(),
            name: "n".into(),
            root_public_key: String::new(),
            member: "m".into(),
            coordinator_address: "127.0.0.1:9".into(),
            coordinator_public_key: String::new(),
            administrator: false,
            last_sync_at: None,
            last_sync_error: None,
            root_epoch: 0,
            current_root_public_key: String::new(),
            root_ssh: false,
        };
        {
            let connection = store.connection().unwrap();
            connection
                .execute(
                    "INSERT INTO networks VALUES (?1, ?2, NULL)",
                    params![NETWORK, serde_json::to_string(&network).unwrap()],
                )
                .unwrap();
            for p in [&owner, &other] {
                let key = p.public_key_b64();
                let proof = json!({"admission": {"network_id": NETWORK, "epoch": 0,
                    "person_public_key": key, "member": "p", "admitted_at": "2026-10-01T00:00:00Z",
                    "signature": ""}});
                connection
                    .execute(
                        "INSERT INTO network_statements VALUES (?1, 'person', ?2, ?3)",
                        params![NETWORK, key, proof.to_string()],
                    )
                    .unwrap();
            }
        }
        let f = Fixture {
            _dir: dir,
            owner,
            other,
            owner_id: owner_id.clone(),
            other_id: other_id.clone(),
            store,
        };
        let own = f.store.identity().id;
        bind(&f.store, &own, Some(&owner_id));
        bind(&f.store, &host('a'), Some(&owner_id));
        bind(&f.store, &host('b'), Some(&other_id));
        bind(&f.store, &host('c'), None);
        f
    }
    fn bind(store: &Store, host_id: &str, person: Option<&str>) {
        let member = Member {
            host_id: host_id.into(),
            public_key: String::new(),
            member: "m".into(),
            address: String::new(),
            candidates: vec![],
            updated_at: String::new(),
            membership: None,
            admission: None,
            person_id: person.map(Into::into),
            person_member: None,
        };
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO network_members VALUES (?1, ?2, ?3)",
                params![NETWORK, host_id, serde_json::to_string(&member).unwrap()],
            )
            .unwrap();
    }
    fn events(store: &Store) -> Vec<(String, String)> {
        store
            .events(0, 1000)
            .unwrap()
            .into_iter()
            .map(|e| (e.kind, e.subject_id))
            .filter(|(k, _)| k.starts_with("network.policy"))
            .collect()
    }
    fn targets(status: &SyncStatus) -> Vec<(String, u64, String, u32)> {
        status
            .deliveries
            .iter()
            .map(|d| (d.target.clone(), d.version, d.state.clone(), d.attempts))
            .collect()
    }
    fn record(store: &Store, person: &str, target: &str) -> DeliveryRecord {
        store
            .delivery_record(&store.connection().unwrap(), NETWORK, person, target)
            .unwrap()
            .unwrap()
    }

    #[test]
    fn version_eleven_migrates_to_twelve_and_thirteen_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host");
        drop(Store::open(&path).unwrap());
        Connection::open(path.join("host.db"))
            .unwrap()
            .execute_batch("DROP TABLE policy_deliveries; PRAGMA user_version = 11;")
            .unwrap();
        let store = Store::open(&path).unwrap();
        let connection = store.connection().unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 12);
        let sql: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'policy_deliveries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            sql,
            "CREATE TABLE policy_deliveries (network_id TEXT NOT NULL, person_id TEXT NOT NULL, target TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, person_id, target))"
        );
        drop(connection);
        drop(store);
        Connection::open(path.join("host.db"))
            .unwrap()
            .execute_batch("PRAGMA user_version = 13;")
            .unwrap();
        assert!(Store::open(&path).is_err());
    }

    #[test]
    fn backoff_runs_from_one_second_to_five_minutes() {
        assert_eq!(backoff(1, 0.0), TimeDelta::seconds(1));
        assert_eq!(backoff(2, 0.0), TimeDelta::seconds(2));
        assert_eq!(backoff(9, 0.0), TimeDelta::seconds(256));
        assert_eq!(backoff(10, 0.0), TimeDelta::seconds(300));
        assert_eq!(backoff(500, 0.0), TimeDelta::seconds(300));
        assert_eq!(backoff(1, 0.2), TimeDelta::milliseconds(1200));
        assert_eq!(backoff(40, -0.2), TimeDelta::seconds(240));
    }

    #[test]
    fn local_submission_stores_first_and_queues_siblings_and_the_coordinator() {
        let f = fixture();
        let s = &f.store;
        let v1 = sign(&f.owner, 1, 0, "network");
        assert_eq!(
            s.submit_local_policy(NETWORK, &v1).unwrap(),
            Accepted::Stored
        );
        let status = s.policy_sync_status(NETWORK).unwrap();
        assert_eq!(status.person_id, f.owner_id);
        assert_eq!(status.version, Some(1));
        assert_eq!(status.sha256.as_deref(), Some(v1.sha256().as_str()));
        // Siblings only: not the other person's host or the unbound one.
        assert_eq!(
            targets(&status),
            [
                (COORDINATOR.into(), 1, "pending".into(), 0),
                (host('a'), 1, "pending".into(), 0)
            ]
        );
        let d = &status.deliveries[0];
        assert!(d.next_attempt_at.is_some() && d.error.is_none() && d.delivered_at.is_none());
        assert_eq!(record(s, &f.owner_id, &host('a')).policy, v1);
        // Identical resubmission changes nothing.
        assert_eq!(
            s.submit_local_policy(NETWORK, &v1).unwrap(),
            Accepted::Identical
        );
        // A newer version supersedes the queued deliveries.
        let v2 = sign(&f.owner, 2, 0, "network");
        assert_eq!(
            s.submit_local_policy(NETWORK, &v2).unwrap(),
            Accepted::Stored
        );
        let status = s.policy_sync_status(NETWORK).unwrap();
        assert_eq!(status.version, Some(2));
        assert!(status.deliveries.iter().all(|d| d.version == 2));
        assert_eq!(record(s, &f.owner_id, COORDINATOR).policy, v2);
        // A lower version conflicts.
        assert!(matches!(
            s.submit_local_policy(NETWORK, &v1),
            Err(Error::Conflict(_))
        ));
        // An equal version wins only with a lower statement hash.
        let (a, b) = (
            sign(&f.owner, 3, 0, "network"),
            sign(&f.owner, 3, 1, "network"),
        );
        let (low, high) = if a.sha256() < b.sha256() {
            (a, b)
        } else {
            (b, a)
        };
        assert_eq!(
            s.submit_local_policy(NETWORK, &high).unwrap(),
            Accepted::Stored
        );
        assert_eq!(
            s.submit_local_policy(NETWORK, &low).unwrap(),
            Accepted::Stored
        );
        assert!(matches!(
            s.submit_local_policy(NETWORK, &high),
            Err(Error::Conflict(_))
        ));
        assert_eq!(record(s, &f.owner_id, &host('a')).policy, low);
        let updated = events(s)
            .into_iter()
            .filter(|(k, _)| k == "network.policy_updated")
            .count();
        assert_eq!(updated, 4);
        // Outside its window, or by a non-person, it is refused.
        let late = Policy::sign(
            &f.owner,
            NETWORK,
            9,
            "2020-01-01T00:00:00Z",
            "2020-01-08T00:00:00Z",
            vec![],
        )
        .unwrap();
        assert!(matches!(
            s.submit_local_policy(NETWORK, &late),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            s.submit_local_policy(NETWORK, &sign(&signer(7), 1, 0, "network")),
            Err(Error::Forbidden)
        ));
    }

    #[test]
    fn deliveries_complete_retry_and_drop_non_siblings() {
        let f = fixture();
        let s = &f.store;
        let v1 = sign(&f.owner, 1, 0, "network");
        s.submit_local_policy(NETWORK, &v1).unwrap();
        let due = s.due_policy_deliveries(None, Some(Utc::now())).unwrap();
        assert_eq!(due.len(), 2);
        let attempted = record(s, &f.owner_id, &host('a'));
        let before = Utc::now();
        assert!(
            !s.finish_delivery(NETWORK, &f.owner_id, &attempted, Err("down".into()), 0.0)
                .unwrap()
        );
        let failed = record(s, &f.owner_id, &host('a')).delivery;
        assert_eq!(
            (
                failed.state.as_str(),
                failed.attempts,
                failed.error.as_deref()
            ),
            ("pending", 1, Some("down"))
        );
        let next = crate::retry::due_at(&failed.next_attempt_at).unwrap();
        assert!(next >= before + TimeDelta::milliseconds(900));
        assert!(next <= Utc::now() + TimeDelta::milliseconds(1100));
        // Not due until then, but `access sync` retries pending ones at once.
        let due = s.due_policy_deliveries(None, Some(Utc::now())).unwrap();
        assert_eq!(
            due,
            [(NETWORK.into(), f.owner_id.clone(), COORDINATOR.into())]
        );
        assert_eq!(
            s.due_policy_deliveries(Some(NETWORK), None).unwrap().len(),
            2
        );
        let attempted = record(s, &f.owner_id, &host('a'));
        assert!(
            s.finish_delivery(NETWORK, &f.owner_id, &attempted, Ok(()), 0.0)
                .unwrap()
        );
        let done = record(s, &f.owner_id, &host('a')).delivery;
        assert_eq!((done.state.as_str(), done.attempts), ("delivered", 2));
        assert!(done.next_attempt_at.is_none() && done.error.is_none());
        assert!(done.delivered_at.is_some());
        assert!(events(s).contains(&(
            "network.policy_delivered".into(),
            format!("{}/{}", f.owner_id, host('a'))
        )));
        // An attempt superseded by a newer policy is not recorded.
        let stale = record(s, &f.owner_id, COORDINATOR);
        s.submit_local_policy(NETWORK, &sign(&f.owner, 2, 0, "network"))
            .unwrap();
        assert!(
            !s.finish_delivery(NETWORK, &f.owner_id, &stale, Ok(()), 0.0)
                .unwrap()
        );
        let fresh = record(s, &f.owner_id, COORDINATOR).delivery;
        assert_eq!((fresh.version, fresh.state.as_str()), (2, "pending"));
        // A host that is no longer a sibling loses its delivery.
        bind(s, &host('a'), None);
        let status = s.policy_sync_status(NETWORK).unwrap();
        assert_eq!(
            targets(&status),
            [(COORDINATOR.into(), 2, "pending".into(), 0)]
        );
        // A new sibling is queued with the next stored policy.
        bind(s, &host('d'), Some(&f.owner_id));
        s.submit_local_policy(NETWORK, &sign(&f.owner, 3, 0, "network"))
            .unwrap();
        let status = s.policy_sync_status(NETWORK).unwrap();
        assert_eq!(status.deliveries.len(), 2);
        assert_eq!(status.deliveries[1].target, host('d'));
    }

    #[test]
    fn other_persons_policies_go_only_to_the_coordinator() {
        let f = fixture();
        let s = &f.store;
        let theirs = sign(&f.other, 1, 0, "network");
        assert_eq!(
            s.submit_local_policy(NETWORK, &theirs).unwrap(),
            Accepted::Stored
        );
        assert_eq!(
            s.due_policy_deliveries(None, Some(Utc::now())).unwrap(),
            [(NETWORK.into(), f.other_id.clone(), COORDINATOR.into())]
        );
        let status = s.policy_sync_status(NETWORK).unwrap();
        assert!(status.deliveries.is_empty() && status.version.is_none());
        // A policy of another person stored from a peer or a map is not
        // propagated at all.
        let mut connection = s.connection().unwrap();
        let tx = connection.transaction().unwrap();
        s.accept_policy(&tx, NETWORK, &sign(&f.other, 2, 0, "network"), Utc::now())
            .unwrap();
        tx.commit().unwrap();
        drop(connection);
        assert_eq!(record(s, &f.other_id, COORDINATOR).delivery.version, 1);
    }

    #[test]
    fn peer_pushes_and_fetches_require_siblings() {
        let f = fixture();
        let s = &f.store;
        assert!(matches!(
            s.sibling_policy(&host('a'), NETWORK, &f.owner_id),
            Err(Error::NotFound)
        ));
        let v2 = sign(&f.owner, 2, 0, "network");
        let stored = s.accept_pushed_policy(&host('a'), NETWORK, &v2).unwrap();
        assert_eq!(
            stored,
            StoredPolicy {
                person_id: f.owner_id.clone(),
                version: 2,
                sha256: v2.sha256()
            }
        );
        // The push is stored first and then propagated onward.
        assert_eq!(s.policy_sync_status(NETWORK).unwrap().deliveries.len(), 2);
        // A lower version leaves the stored one, which is reported.
        let v1 = sign(&f.owner, 1, 0, "network");
        assert_eq!(
            s.accept_pushed_policy(&host('a'), NETWORK, &v1)
                .unwrap()
                .version,
            2
        );
        for sender in [host('b'), host('c'), host('e')] {
            assert!(matches!(
                s.accept_pushed_policy(&sender, NETWORK, &v2),
                Err(Error::Forbidden)
            ));
            assert!(matches!(
                s.sibling_policy(&sender, NETWORK, &f.owner_id),
                Err(Error::Forbidden)
            ));
        }
        // The receiver must be bound to the owner too.
        let theirs = sign(&f.other, 1, 0, "network");
        assert!(matches!(
            s.accept_pushed_policy(&host('b'), NETWORK, &theirs),
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            s.sibling_policy(&host('b'), NETWORK, &f.other_id),
            Err(Error::Forbidden)
        ));
        let elsewhere = format!("net_{}", "0".repeat(64));
        assert!(matches!(
            s.accept_pushed_policy(&host('a'), &elsewhere, &v2),
            Err(Error::Invalid(_))
        ));
        let mut forged = sign(&f.owner, 5, 0, "network");
        forged.version = 6;
        assert!(matches!(
            s.accept_pushed_policy(&host('a'), NETWORK, &forged),
            Err(Error::Invalid(_))
        ));
        assert_eq!(
            s.sibling_policy(&host('a'), NETWORK, &f.owner_id).unwrap(),
            v2
        );
    }

    #[test]
    fn synced_policies_record_their_sibling() {
        let f = fixture();
        let s = &f.store;
        let v1 = sign(&f.owner, 1, 0, "network");
        assert!(
            s.accept_synced_policy(NETWORK, &f.owner_id, &host('a'), &v1)
                .unwrap()
        );
        assert!(
            !s.accept_synced_policy(NETWORK, &f.owner_id, &host('a'), &v1)
                .unwrap()
        );
        assert!(
            s.accept_synced_policy(NETWORK, &f.other_id, &host('a'), &v1)
                .is_err()
        );
        assert_eq!(
            events(s),
            [
                ("network.policy_updated".into(), f.owner_id.clone()),
                (
                    "network.policy_synced".into(),
                    format!("{}/{}", f.owner_id, host('a'))
                ),
            ]
        );
    }

    #[test]
    fn status_and_records_have_the_shared_shape() {
        let f = fixture();
        let s = &f.store;
        let v1 = sign(&f.owner, 1, 0, "network");
        s.submit_local_policy(NETWORK, &v1).unwrap();
        let status = serde_json::to_value(s.policy_sync_status(NETWORK).unwrap()).unwrap();
        let keys = |v: &serde_json::Value| {
            v.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<String>>()
        };
        assert_eq!(
            keys(&status),
            ["deliveries", "person_id", "sha256", "version"]
        );
        assert_eq!(
            keys(&status["deliveries"][0]),
            [
                "attempts",
                "delivered_at",
                "error",
                "next_attempt_at",
                "state",
                "target",
                "version"
            ]
        );
        let stored: String = s
            .connection()
            .unwrap()
            .query_row(
                "SELECT record FROM policy_deliveries WHERE target = 'coordinator'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored["policy"], serde_json::to_value(&v1).unwrap());
        assert!(stored["error"].is_null() && stored["delivered_at"].is_null());
        // Unknown networks and unbound hosts have no status.
        assert!(matches!(
            s.policy_sync_status(&format!("net_{}", "0".repeat(64))),
            Err(Error::NotFound)
        ));
        bind(s, &s.identity().id, None);
        assert!(matches!(
            s.policy_sync_status(NETWORK),
            Err(Error::NotFound)
        ));
    }
}
