//! Agent access granted with the invite (guided session contract section55):
//! an approved invitation review with `agent_access` records a pending grant
//! keyed by the invitation ID. As for a peerbox pending share, it notes whose
//! join requests came through the invitation, binds only to the person whose
//! exact request an administrator admitted as a new person, and then adds that
//! person to the ordinary owner policy of the invitation's agent with section
//! 31's profile: automatically when the owner's provider signs without the
//! owner, otherwise after one explicit owner press (`complete`).
//!
//! Every outcome is kept as a terminal record for 7 days, so a lookup can tell
//! a granted grant from a cancelled, expired or stopped one.
use crate::{
    api::blocking,
    decentralized::peerbox_share::{ContentSigning, sign_content},
    model::Error,
    peerbox_invite::{Admitted, Came},
    policy::Rule,
    store::{Store, append_event},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

/// Created at every start: an additive table no earlier version reads.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS invitation_grants (invitation_id TEXT PRIMARY KEY, flow_id TEXT NOT NULL, record TEXT NOT NULL);
";

/// A pending grant ends at most this long after it was created.
const CAP: TimeDelta = TimeDelta::days(7);
/// A request that came through the invitation counts as abandoned this long
/// after it arrived.
const REQUEST_WINDOW: TimeDelta = TimeDelta::hours(1);
/// The most requests noted per invitation.
const MAX_REQUESTS: usize = 16;
/// How long a terminal record is kept.
const KEEP: TimeDelta = TimeDelta::days(7);
/// Section31's profile.
const ACTIONS: [&str; 2] = ["message.append", "task.submit"];
const MAX_MESSAGE_BYTES: i64 = 65536;

/// The terminal outcome of a grant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// `granted`, `cancelled`, `expired` or `stopped`.
    pub state: String,
    pub at: String,
    /// For `granted`: the policy version that holds the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
    /// For `expired`: the ending rule; for `stopped`: the recheck reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A grant, keyed by its invitation's ID.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub invitation_id: String,
    pub flow_id: String,
    pub network_id: String,
    pub member: String,
    pub agent_id: String,
    pub agent_name: String,
    /// The invitation's pinned person key, or `-`.
    pub expected_person_public_key: String,
    pub created_at: String,
    /// The invitation's expiry.
    pub expires_at: String,
    #[serde(default)]
    pub requests: Vec<Came>,
    #[serde(default)]
    pub person: Option<Admitted>,
    /// Automatic signing needed the owner.
    #[serde(default)]
    pub waiting: bool,
    #[serde(default)]
    pub outcome: Option<Outcome>,
}

fn time(s: &str, fallback: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or(fallback)
}
fn stamp(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

impl Grant {
    /// The grant's current state.
    pub fn state(&self) -> &str {
        if let Some(o) = &self.outcome {
            return &o.state;
        }
        if self.person.is_some() && self.waiting {
            "waiting_for_owner"
        } else if self.requests.is_empty() {
            "waiting_for_request"
        } else {
            "waiting_for_admission"
        }
    }
    /// Which ending rule ended a pending grant at `at`, if any.
    fn ended(&self, at: DateTime<Utc>) -> Option<&'static str> {
        if at >= time(&self.created_at, at) + CAP {
            return Some("seven_days");
        }
        if self.person.is_some() {
            return None;
        }
        let expires = time(&self.expires_at, at);
        if self.requests.is_empty() {
            return (at >= expires).then_some("invitation_expired");
        }
        let last = self
            .requests
            .iter()
            .map(|r| time(&r.at, at) + REQUEST_WINDOW)
            .max()
            .unwrap_or(expires)
            .max(expires);
        (at >= last).then_some("request_window")
    }
    fn principal(&self) -> Option<String> {
        Some(format!("person:{}", self.person.as_ref()?.person_id))
    }
    fn view(&self) -> Value {
        json!({
            "invitation_id": self.invitation_id,
            "flow_id": self.flow_id,
            "network_id": self.network_id,
            "member": self.member,
            "agent": {"id": self.agent_id, "name": self.agent_name},
            "state": self.state(),
            "requests": self.requests.iter().map(|r| json!({
                "request_id": r.request_id,
                "person_id": crate::decentralized::codec::b64(&r.person_public_key, 32)
                    .map(|k| crate::persons::person_id(&k)).ok(),
                "at": r.at,
            })).collect::<Vec<_>>(),
            "person_id": self.person.as_ref().map(|p| &p.person_id),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "outcome": self.outcome,
        })
    }
}

fn read(conn: &Connection, id: &str) -> Result<Option<Grant>, Error> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT record FROM invitation_grants WHERE invitation_id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|r| Ok(serde_json::from_str(&r)?)).transpose()
}
fn all(conn: &Connection) -> Result<Vec<Grant>, Error> {
    let mut statement =
        conn.prepare("SELECT record FROM invitation_grants ORDER BY invitation_id")?;
    let rows = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .collect()
}
fn save(conn: &Connection, grant: &Grant) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO invitation_grants VALUES (?1, ?2, ?3) ON CONFLICT(invitation_id) DO UPDATE SET record = excluded.record",
        params![
            grant.invitation_id,
            grant.flow_id,
            serde_json::to_string(grant)?
        ],
    )?;
    Ok(())
}
/// Ends a pending grant with `state`, recording when.
fn finish(
    conn: &rusqlite::Transaction<'_>,
    grant: &mut Grant,
    state: &str,
    policy_version: Option<u64>,
    reason: Option<&str>,
) -> Result<(), Error> {
    grant.outcome = Some(Outcome {
        state: state.into(),
        at: stamp(crate::clock::now()),
        policy_version,
        reason: reason.map(Into::into),
    });
    grant.waiting = false;
    save(conn, grant)?;
    append_event(
        conn,
        &format!("invitation_grant.{state}"),
        &grant.invitation_id,
        &stamp(crate::clock::now()),
    )?;
    Ok(())
}

/// Records the pending grant of an invitation just minted from an approved
/// review with `agent_access`, in the caller's transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record(
    tx: &rusqlite::Transaction<'_>,
    invitation_id: &str,
    flow_id: &str,
    network_id: &str,
    member: &str,
    agent: &Value,
    expected_person_public_key: &str,
    expires_at: &str,
) -> Result<(), Error> {
    let field = |key: &str| {
        agent[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::Internal(anyhow::anyhow!("invalid retained invitation review")))
    };
    let grant = Grant {
        invitation_id: invitation_id.into(),
        flow_id: flow_id.into(),
        network_id: network_id.into(),
        member: member.into(),
        agent_id: field("id")?,
        agent_name: field("name")?,
        expected_person_public_key: expected_person_public_key.into(),
        created_at: stamp(crate::clock::now()),
        expires_at: expires_at.into(),
        requests: Vec::new(),
        person: None,
        waiting: false,
        outcome: None,
    };
    if read(tx, invitation_id)?.is_some() {
        return Err(Error::Conflict("a grant exists for this invitation".into()));
    }
    save(tx, &grant)?;
    append_event(
        tx,
        "invitation_grant.recorded",
        invitation_id,
        &grant.created_at,
    )?;
    Ok(())
}

/// A join request came through invitation `id` on its return path: its
/// person is noted, unless already in the network or not the pinned person.
/// Noting grants nothing.
pub(crate) fn came_through(
    store: &Store,
    conn: &Connection,
    id: &str,
    request_id: &str,
    network_id: &str,
    person_public_key: &str,
) -> Result<(), Error> {
    let Some(mut grant) = read(conn, id)? else {
        return Ok(());
    };
    if grant.outcome.is_some()
        || grant.person.is_some()
        || grant.requests.len() >= MAX_REQUESTS
        || grant.requests.iter().any(|r| r.request_id == request_id)
        || (network_id != "-" && network_id != grant.network_id)
        || (grant.expected_person_public_key != "-"
            && grant.expected_person_public_key != person_public_key)
    {
        return Ok(());
    }
    if store
        .product_persons(conn, &grant.network_id)?
        .iter()
        .any(|p| p.person_public_key == person_public_key)
    {
        return Ok(());
    }
    grant.requests.push(Came {
        request_id: request_id.into(),
        person_public_key: person_public_key.into(),
        at: stamp(crate::clock::now()),
    });
    save(conn, &grant)
}

/// Ends pending grants by their ending rules and removes terminal records
/// kept long enough.
fn sweep(conn: &rusqlite::Transaction<'_>) -> Result<(), Error> {
    let at = crate::clock::now();
    for mut grant in all(conn)? {
        if let Some(o) = &grant.outcome {
            if at >= time(&o.at, at) + KEEP {
                conn.execute(
                    "DELETE FROM invitation_grants WHERE invitation_id = ?1",
                    [&grant.invitation_id],
                )?;
            }
            continue;
        }
        if let Some(rule) = grant.ended(at) {
            finish(conn, &mut grant, "expired", None, Some(rule))?;
        }
    }
    Ok(())
}

/// Binds pending grants whose request an administrator admitted.
fn bind(store: &Store, conn: &Connection) -> Result<(), Error> {
    for mut grant in all(conn)? {
        if grant.outcome.is_some() || grant.person.is_some() || grant.requests.is_empty() {
            continue;
        }
        let evidenced: Vec<&Came> = grant
            .requests
            .iter()
            .filter(|r| crate::peerbox_invite::admitted(store, conn, &grant.network_id, r))
            .collect();
        if evidenced.is_empty() {
            continue;
        }
        let persons = store.product_persons(conn, &grant.network_id)?;
        let found = evidenced.iter().find_map(|r| {
            persons
                .iter()
                .find(|p| p.person_public_key == r.person_public_key)
        });
        if let Some(p) = found {
            grant.person = Some(Admitted {
                person_id: p.person_id.clone(),
                person_public_key: p.person_public_key.clone(),
            });
            save(conn, &grant)?;
        }
    }
    Ok(())
}

/// Why a bound grant may no longer be signed: its agent changed, or its
/// person is no longer a member.
fn recheck(store: &Store, conn: &Connection, grant: &Grant) -> Result<Option<&'static str>, Error> {
    let agent: Option<String> = conn
        .query_row(
            "SELECT name FROM agents WHERE id=?1",
            [&grant.agent_id],
            |r| r.get(0),
        )
        .optional()?;
    if agent.as_deref() != Some(grant.agent_name.as_str()) {
        return Ok(Some("agent_changed"));
    }
    let Some(person) = &grant.person else {
        return Ok(None);
    };
    if !store
        .product_persons(conn, &grant.network_id)?
        .iter()
        .any(|p| p.person_id == person.person_id && p.person_public_key == person.person_public_key)
    {
        return Ok(Some("person_removed"));
    }
    Ok(None)
}

/// Section31's same-key merge of the grant's profile rule. Returns whether
/// the profile rule was appended rather than merged into a same-key rule.
fn merge(grant: &Grant, content: &mut crate::policy::Content) -> bool {
    let Some(principal) = grant.principal() else {
        return false;
    };
    let rule = Rule {
        agent: grant.agent_name.clone(),
        principals: vec![principal.clone()],
        actions: ACTIONS.iter().map(|a| (*a).to_owned()).collect(),
        max_message_bytes: MAX_MESSAGE_BYTES,
        max_artifact_bytes: 0,
        allow_disconnected: false,
    };
    if let Some(same) = content.rules.iter_mut().find(|r| r.same_key(&rule)) {
        if !same.principals.contains(&principal) {
            same.principals.push(principal);
        }
        false
    } else {
        content.rules.push(rule);
        true
    }
}

/// Held from a signing's check that the grant is pending to its outcome, and
/// by a cancellation.
static SIGNING: std::sync::Mutex<()> = std::sync::Mutex::new(());
static RETRY: std::sync::Mutex<std::collections::BTreeMap<String, std::time::Instant>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
const RETRY_AFTER: Duration = Duration::from_secs(30);
fn due(id: &str) -> bool {
    RETRY
        .lock()
        .map(|m| m.get(id).is_none_or(|at| std::time::Instant::now() >= *at))
        .unwrap_or(true)
}
fn retry_later(id: &str) {
    if let Ok(mut m) = RETRY.lock() {
        m.insert(id.to_owned(), std::time::Instant::now() + RETRY_AFTER);
    }
}

/// What one signing attempt came to.
enum Attempt {
    Granted,
    NeedsOwner,
    NotPending(Box<Grant>),
}

/// Signs one bound pending grant, holding the signing lock: automatically,
/// or with the daemon's ssh-agent or key file when `explicit`.
fn sign(store: &Store, id: &str, explicit: bool) -> Result<Attempt, Error> {
    let _signing = SIGNING.lock().unwrap_or_else(|e| e.into_inner());
    let grant = {
        let mut conn = store.connection()?;
        let tx = conn.transaction()?;
        sweep(&tx)?;
        let Some(mut grant) = read(&tx, id)? else {
            return Err(Error::NotFound);
        };
        if grant.outcome.is_some() || grant.person.is_none() {
            tx.commit()?;
            return Ok(Attempt::NotPending(Box::new(grant)));
        }
        if let Some(reason) = recheck(store, &tx, &grant)? {
            finish(&tx, &mut grant, "stopped", None, Some(reason))?;
            tx.commit()?;
            return Ok(Attempt::NotPending(Box::new(grant)));
        }
        tx.commit()?;
        grant
    };
    // A newly appended profile rule, the last one, keeps section31's
    // explicit raw `max_artifact_bytes:0`.
    let appended = std::cell::Cell::new(false);
    // Retained rules keep the explicit field presence of the stored body
    // (section31); merging only appends a principal or a last rule, so the
    // retained rules keep their positions.
    let adjust = |raw: &mut Value, baseline: Option<&Value>| {
        let Some(rules) = raw["rules"].as_array_mut() else {
            return;
        };
        let before = baseline
            .and_then(|b| b["rules"].as_array())
            .map_or(0, Vec::len);
        if let Some(old) = baseline.and_then(|b| b["rules"].as_array()) {
            for (rule, old) in rules.iter_mut().zip(old) {
                if let Some(bound) = old.get("max_artifact_bytes")
                    && rule.get("max_artifact_bytes").is_none()
                {
                    rule["max_artifact_bytes"] = bound.clone();
                }
            }
        }
        if appended.get()
            && rules.len() > before
            && let Some(rule) = rules.last_mut()
            && rule.get("max_artifact_bytes").is_none()
        {
            rule["max_artifact_bytes"] = json!(0);
        }
    };
    let outcome = sign_content(
        store,
        &grant.network_id,
        explicit,
        Some(&adjust),
        |_, content| appended.set(merge(&grant, content)),
    )
    .map_err(crate::decentralized::product::model)?;
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let Some(mut current) = read(&tx, id)? else {
        return Err(Error::NotFound);
    };
    let attempt = match outcome {
        ContentSigning::Signed(v) | ContentSigning::Unchanged(v) => {
            finish(&tx, &mut current, "granted", Some(v), None)?;
            Attempt::Granted
        }
        ContentSigning::NeedsOwner => {
            if !current.waiting {
                current.waiting = true;
                save(&tx, &current)?;
            }
            Attempt::NeedsOwner
        }
    };
    tx.commit()?;
    Ok(attempt)
}

/// One pass: end, bind, then sign automatically what may be.
fn pass(store: &Store) -> Result<(), Error> {
    let grants = {
        let mut conn = store.connection()?;
        let tx = conn.transaction()?;
        sweep(&tx)?;
        bind(store, &tx)?;
        let grants = all(&tx)?;
        tx.commit()?;
        grants
    };
    for grant in grants {
        if grant.outcome.is_some() || grant.person.is_none() || grant.waiting {
            continue;
        }
        if !due(&grant.invitation_id) {
            continue;
        }
        if sign(store, &grant.invitation_id, false).is_err() {
            retry_later(&grant.invitation_id);
        }
    }
    Ok(())
}

/// Binds and signs pending grants until shutdown.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if let Err(e) = blocking(store.clone(), pass).await {
            eprintln!("invitation grants: {e:?}");
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

/// `agent_access_waiting` items: (subject, detail, command).
pub(crate) fn attention(conn: &Connection) -> Result<Vec<(String, String, String)>, Error> {
    let at = crate::clock::now();
    Ok(all(conn)?
        .into_iter()
        .filter(|g| g.outcome.is_none() && g.waiting && g.person.is_some() && g.ended(at).is_none())
        .map(|g| {
            let id = g.invitation_id;
            (
                id.clone(),
                format!(
                    "agent access for {} to {} through invitation {id} waits for the owner's signature",
                    g.member, g.agent_name
                ),
                format!("peerspan onboarding invitation grant complete {id}"),
            )
        })
        .collect())
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/onboarding/invitation-grants", get(list))
        .route(
            "/v1/onboarding/invitation-grants/{id}",
            get(inspect).delete(cancel),
        )
        .route(
            "/v1/onboarding/invitation-grants/{id}/complete",
            post(complete),
        )
}
fn valid(id: &str) -> Result<(), Error> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::Invalid("invitation_id".into()));
    }
    Ok(())
}
fn coded(state: &str) -> Error {
    Error::Coded {
        status: 409,
        code: "state_conflict",
        message: format!("the grant is {state}"),
        extra: [("state".to_owned(), json!(state))].into_iter().collect(),
    }
}
async fn list(State(store): State<Arc<Store>>) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, |s| {
            let conn = s.connection()?;
            let grants = all(&conn)?;
            Ok(json!({"version": 1, "grants": grants.iter().map(Grant::view).collect::<Vec<_>>()}))
        })
        .await?,
    ))
}
async fn inspect(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    valid(&id)?;
    Ok(Json(
        blocking(store, move |s| {
            let conn = s.connection()?;
            Ok(read(&conn, &id)?.ok_or(Error::NotFound)?.view())
        })
        .await?,
    ))
}
/// Cancels a grant that is not terminal; a terminal one is returned as it is.
async fn cancel(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    valid(&id)?;
    Ok(Json(
        blocking(store, move |s| {
            let _signing = SIGNING.lock().unwrap_or_else(|e| e.into_inner());
            let mut conn = s.connection()?;
            let tx = conn.transaction()?;
            let mut grant = read(&tx, &id)?.ok_or(Error::NotFound)?;
            if grant.outcome.is_none() {
                finish(&tx, &mut grant, "cancelled", None, None)?;
            }
            tx.commit()?;
            Ok(grant.view())
        })
        .await?,
    ))
}
/// The owner's explicit press: signs and applies a grant waiting for the
/// owner; a granted grant is returned unchanged.
async fn complete(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    valid(&id)?;
    Ok(Json(
        blocking(store, move |s| {
            let before = read(&*s.connection()?, &id)?.ok_or(Error::NotFound)?;
            if before.state() == "granted" {
                return Ok(before.view());
            }
            if before.state() != "waiting_for_owner" {
                return Err(coded(before.state()));
            }
            match sign(s, &id, true)? {
                Attempt::Granted => {
                    Ok(read(&*s.connection()?, &id)?.ok_or(Error::NotFound)?.view())
                }
                Attempt::NeedsOwner => Err(Error::Coded {
                    status: 409,
                    code: "signer_unavailable",
                    message: "the owner's signer is not reachable from this host".into(),
                    extra: Default::default(),
                }),
                Attempt::NotPending(g) if g.state() == "granted" => Ok(g.view()),
                Attempt::NotPending(g) => Err(coded(g.state())),
            }
        })
        .await?,
    ))
}
