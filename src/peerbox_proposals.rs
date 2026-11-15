//! Agent proposals (peerbox contract, Agent proposals; PBX-16 to PBX-21): an
//! agent whose credential has `peerbox_proposals` prepares a `peerbox
//! create`, `share` or `invite` on this host, the person approves it once
//! at a terminal with `approve`, and only then does the host carry it out,
//! exactly as prepared. This module keeps the proposal records, their
//! proposal-update notifications, the adapter's and the owner's routes, and
//! the worker that expires, settles and removes proposals.
use crate::{
    adapter::{Adapter, authority, token},
    adapter_connection::AdapterAuth,
    api::blocking,
    decentralized::peerbox_share::{ProposalSigner, ProposalSigning, sign_proposal_share},
    model::{Error, Session},
    peerbox::{Failure, Git},
    peerbox_invite::PendingShare,
    persons::PersonSigner,
    policy::{MAX_BUNDLE_BYTES, MAX_PENDING, PeerboxRule},
    store::{Store, append_event, new_id},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{BytesRejection, QueryRejection},
    },
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// A proposal waits this long for the person (PBX-19).
const LIFETIME: TimeDelta = TimeDelta::hours(1);
/// Pending proposals per credential and per host.
const PENDING_PER_CREDENTIAL: i64 = 5;
const PENDING_PER_HOST: i64 = 20;
/// Proposals made through one credential in any 60 minutes.
const PER_HOUR: usize = 20;
/// `approvals --all` lists proposals decided this recently.
const DECIDED_LISTED: TimeDelta = TimeDelta::days(7);
/// Final proposals are kept this long after `decided_at`.
const KEPT: TimeDelta = TimeDelta::days(30);
/// How many times a share is tried again after a concurrent policy edit.
const SHARE_ATTEMPTS: usize = 3;
/// The longest repository path, in bytes.
const MAX_PATH: usize = 4096;

const NOTE_PENDING: &str = "The person must approve this in a terminal on this machine (peerspan approve PROPOSAL_ID); it has not been done, and you cannot approve it. Tell the person what you prepared and why. Its outcome arrives as a kind=peerbox_proposal_update event; peerbox_proposal_status reports it at any time. Do not propose it again.";
const NOTE_APPROVED: &str = "The person approved this; it is being carried out.";
const NOTE_INVITE: &str = "The invite was created. Give the code only to the person it is for, privately: whoever holds it can ask to join the network and receive this access once an administrator admits them.";
const NOTE_FAILED: &str =
    "The person approved this, but it could not be carried out (see error). Nothing was changed.";
const NOTE_NOT_DONE: &str =
    "This was not done, and nothing was changed. Proposing again makes a new proposal.";

/// The proposing session.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalOrigin {
    pub adapter_id: String,
    pub agent_id: String,
    pub session_id: String,
}
/// A proposal record (peerbox contract, The proposal record).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    /// `create`, `share` or `invite`.
    pub op: String,
    pub args: Value,
    pub review: Value,
    pub request_sha256: String,
    pub proposal_sha256: String,
    pub origin: ProposalOrigin,
    /// `pending`, `approved`, `executed`, `failed`, `denied`, `expired` or
    /// `cancelled`.
    pub state: String,
    pub requested_at: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
    pub reason: Option<String>,
    pub result: Option<Value>,
    pub error: Option<Value>,
}
impl Proposal {
    fn is_final(&self) -> bool {
        matches!(
            self.state.as_str(),
            "executed" | "failed" | "denied" | "expired" | "cancelled"
        )
    }
    /// The proposal view: the record without `origin` and `request_sha256`,
    /// with `note`.
    pub fn view(&self) -> Value {
        let mut value = json!(self);
        if let Some(object) = value.as_object_mut() {
            object.remove("origin");
            object.remove("request_sha256");
        }
        let note = match self.state.as_str() {
            "pending" => Some(NOTE_PENDING.replace("PROPOSAL_ID", &self.proposal_id)),
            "approved" => Some(NOTE_APPROVED.into()),
            "executed" if self.op == "invite" => Some(NOTE_INVITE.into()),
            "executed" => None,
            "failed" => Some(NOTE_FAILED.into()),
            _ => Some(NOTE_NOT_DONE.into()),
        };
        value["note"] = json!(note);
        value
    }
    fn due(&self, at: DateTime<Utc>) -> bool {
        self.state == "pending" && time(&self.expires_at) <= at
    }
}

/// A proposal-update notification: a call-update notification in all but
/// name (peerbox contract, Telling the agent).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalUpdate {
    pub id: String,
    pub proposal_id: String,
    pub adapter_id: String,
    pub session_id: String,
    /// `unknown` or `forwarded`.
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Serialize, Deserialize)]
struct StoredUpdate {
    #[serde(flatten)]
    notification: ProposalUpdate,
    #[serde(default)]
    claimed: bool,
}

/// Proposals being carried out by this process. A proposal found
/// `approved` and not listed here was interrupted by a restart.
static IN_FLIGHT: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

fn time(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_default()
}
fn stamp(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn digest(value: &Value) -> String {
    hex::encode(Sha256::digest(
        crate::canonical::value_text(value).as_bytes(),
    ))
}
/// Whether `id` is a proposal ID: `pbp_` and 32 lowercase hex digits.
pub fn proposal_id_shape(id: &str) -> bool {
    crate::peer_store::valid_id(id, "pbp", 16)
}
/// Untrusted text as the approval display writes it (What the person
/// sees): `"`, the text with `\` as `\\`, `"` as `\"`, and each character
/// below U+0020, U+007F and U+0080 to U+009F as `\u` and four lowercase
/// hex digits, then `"`.
pub fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if (c as u32) < 0x20 || c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn coded(status: u16, code: &'static str, message: impl Into<String>, extra: Value) -> Error {
    Error::Coded {
        status,
        code,
        message: message.into(),
        extra: extra.as_object().cloned().unwrap_or_default(),
    }
}
fn invalid(field: &str) -> Error {
    coded(
        400,
        "invalid",
        format!("invalid request: {field}"),
        json!({ "field": field }),
    )
}
fn no_flag() -> Error {
    coded(
        403,
        "no_peerbox_proposals",
        "this session's credential may not prepare peerbox changes; the person enables it with peerspan attach --peerbox-proposals",
        json!({}),
    )
}
fn unknown() -> Error {
    coded(404, "unknown", "no such peerbox on this host", json!({}))
}
fn not_pending(value: Value) -> Error {
    coded(
        409,
        "conflict",
        "the proposal is no longer pending",
        json!({ "proposal": value }),
    )
}
/// A Git failure while proposing, as a refusal.
fn git_refusal(f: Failure) -> Error {
    match f.code {
        "invalid" => coded(400, "invalid", f.message, json!({"field": "repository"})),
        _ => crate::peerbox::coded(f),
    }
}

/// The credential and session of an adapter request, refused with
/// `no_peerbox_proposals` unless the credential may propose.
fn proposals_authority(conn: &Connection, auth: &AdapterAuth) -> Result<(Adapter, Session), Error> {
    let (a, ss) = authority(conn, auth)?;
    if !a.peerbox_proposals {
        return Err(no_flag());
    }
    Ok((a, ss))
}

fn load(conn: &Connection, id: &str) -> Result<Option<Proposal>, Error> {
    if !proposal_id_shape(id) {
        return Ok(None);
    }
    conn.query_row(
        "SELECT record FROM peerbox_proposals WHERE proposal_id = ?1",
        [id],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|r| Ok(serde_json::from_str(&r)?))
    .transpose()
}
fn save(conn: &Connection, p: &Proposal) -> Result<(), Error> {
    conn.execute(
        "UPDATE peerbox_proposals SET state = ?1, expires_at = ?2, record = ?3 WHERE proposal_id = ?4",
        params![p.state, p.expires_at, serde_json::to_string(p)?, p.proposal_id],
    )?;
    Ok(())
}
fn all(
    conn: &Connection,
    query: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<Proposal>, Error> {
    let mut stmt = conn.prepare(query)?;
    let rows: Vec<String> = stmt
        .query_map(args, |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .collect()
}
/// Oldest first by `requested_at`, then proposal ID.
fn sort(list: &mut [Proposal]) {
    list.sort_by(|a, b| {
        (time(&a.requested_at), &a.proposal_id).cmp(&(time(&b.requested_at), &b.proposal_id))
    });
}

/// Moves a proposal to a final or the approved state, with its activity
/// and, for `executed`, `failed`, `denied` and `expired`, its
/// proposal-update notification, in the caller's transaction.
fn decide(tx: &Transaction<'_>, p: &mut Proposal, state: &str) -> Result<(), Error> {
    let at = stamp(crate::clock::now());
    if p.decided_at.is_none() {
        p.decided_at = Some(at.clone());
    }
    p.state = state.to_owned();
    save(tx, p)?;
    let kind = match state {
        "approved" => "peerbox.proposal_approved",
        "executed" => "peerbox.proposal_executed",
        "failed" => "peerbox.proposal_failed",
        "denied" => "peerbox.proposal_denied",
        "expired" => "peerbox.proposal_expired",
        _ => "peerbox.proposal_cancelled",
    };
    append_event(tx, kind, &p.proposal_id, &at)?;
    if matches!(state, "executed" | "failed" | "denied" | "expired") {
        notify(tx, p, &at)?;
    }
    Ok(())
}
/// Creates the proposal-update notification, bound to the proposing
/// session.
fn notify(tx: &Transaction<'_>, p: &Proposal, at: &str) -> Result<(), Error> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM peerbox_proposal_notifications WHERE proposal_id = ?1)",
        [&p.proposal_id],
        |r| r.get(0),
    )?;
    if exists {
        return Ok(());
    }
    let n = StoredUpdate {
        notification: ProposalUpdate {
            id: new_id("notification")?,
            proposal_id: p.proposal_id.clone(),
            adapter_id: p.origin.adapter_id.clone(),
            session_id: p.origin.session_id.clone(),
            state: "unknown".into(),
            created_at: at.to_owned(),
            updated_at: at.to_owned(),
        },
        claimed: false,
    };
    tx.execute(
        "INSERT INTO peerbox_proposal_notifications (id, proposal_id, session_id, record) VALUES (?1, ?2, ?3, ?4)",
        params![
            n.notification.id,
            p.proposal_id,
            p.origin.session_id,
            serde_json::to_string(&n)?
        ],
    )?;
    Ok(())
}
/// Expires a pending proposal past `expires_at`; returns whether it did.
fn expire_if_due(tx: &Transaction<'_>, p: &mut Proposal) -> Result<bool, Error> {
    if !p.due(crate::clock::now()) {
        return Ok(false);
    }
    decide(tx, p, "expired")?;
    Ok(true)
}

// ---------------------------------------------------------------------
// Proposing (peerbox contract, Adapter routes).

/// A value of `args` other than null.
fn given<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    args.get(key).filter(|v| !v.is_null())
}
fn string<'a>(args: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, Error> {
    match given(args, key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(invalid(key)),
    }
}
fn required<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    string(args, key)?.ok_or_else(|| invalid(key))
}
fn integer(args: &Map<String, Value>, key: &str) -> Result<Option<i64>, Error> {
    match given(args, key) {
        None => Ok(None),
        Some(v) if v.is_i64() || v.is_u64() => v.as_i64().map(Some).ok_or_else(|| invalid(key)),
        Some(_) => Err(invalid(key)),
    }
}
fn peerbox_id(args: &Map<String, Value>) -> Result<String, Error> {
    let id = required(args, "peerbox_id")?;
    if !crate::peer_store::valid_id(id, "pbx", 16) {
        return Err(invalid("peerbox_id"));
    }
    Ok(id.to_owned())
}
/// `actions` in short names, distinct, written read, submit, run; submit
/// and run need read; the default is read.
fn actions(args: &Map<String, Value>) -> Result<Vec<&'static str>, Error> {
    let Some(value) = given(args, "actions") else {
        return Ok(vec!["read"]);
    };
    let list = value.as_array().ok_or_else(|| invalid("actions"))?;
    let mut seen = BTreeSet::new();
    for item in list {
        let position = ["read", "submit", "run"]
            .iter()
            .position(|a| item.as_str() == Some(*a))
            .ok_or_else(|| invalid("actions"))?;
        if !seen.insert(position) {
            return Err(invalid("actions"));
        }
    }
    if !seen.contains(&0) {
        return Err(invalid("actions"));
    }
    Ok(seen
        .into_iter()
        .map(|i| ["read", "submit", "run"][i])
        .collect())
}
/// The bounds of `share` and `invite`, as their flags take them.
fn bounds(args: &Map<String, Value>, actions: &[&str]) -> Result<(i64, i64), Error> {
    let bytes = integer(args, "max_bundle_bytes")?.unwrap_or(MAX_BUNDLE_BYTES);
    if !(1..=MAX_BUNDLE_BYTES).contains(&bytes) {
        return Err(invalid("max_bundle_bytes"));
    }
    let submit = actions.contains(&"submit");
    let pending = match (submit, integer(args, "max_pending")?) {
        (true, None) => 4,
        (true, Some(n)) if (1..=MAX_PENDING).contains(&n) => n,
        (false, None | Some(0)) => 0,
        _ => return Err(invalid("max_pending")),
    };
    Ok((bytes, pending))
}
/// A label as `peerspan invite` takes it.
fn label_ok(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text.trim() == text
        && !text.chars().any(char::is_control)
}
/// The host's coordinator-free networks.
fn networks(conn: &Connection) -> Result<Vec<String>, Error> {
    let mut stmt = conn.prepare(
        "SELECT id FROM networks WHERE json_extract(record,'$.mode')='decentralized' ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Proposing step 1: checks `op` and `args` and returns `args` normalized,
/// every default filled in.
fn normalize(conn: &Connection, op: &str, args: &Map<String, Value>) -> Result<Value, Error> {
    let keys: &[&str] = match op {
        "create" => &["repository", "branch", "title", "network_id"],
        "share" => &[
            "peerbox_id",
            "principals",
            "actions",
            "max_bundle_bytes",
            "max_pending",
            "allow_disconnected",
        ],
        _ => &[
            "peerbox_id",
            "label",
            "actions",
            "max_bundle_bytes",
            "max_pending",
            "expires_in_seconds",
        ],
    };
    if let Some(key) = args.keys().find(|k| !keys.contains(&k.as_str())) {
        return Err(invalid(key));
    }
    match op {
        "create" => {
            let given_path = required(args, "repository")?;
            if given_path.is_empty() || given_path.len() > MAX_PATH {
                return Err(invalid("repository"));
            }
            let resolved = std::fs::canonicalize(given_path).map_err(|_| invalid("repository"))?;
            let repository = resolved
                .to_str()
                .filter(|p| p.len() <= MAX_PATH)
                .ok_or_else(|| invalid("repository"))?
                .to_owned();
            let branch = required(args, "branch")?;
            if !crate::peerbox::valid_branch(branch) {
                return Err(invalid("branch"));
            }
            let title = match string(args, "title")? {
                Some(t) => t.to_owned(),
                None => resolved
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_owned(),
            };
            if title.is_empty() || title.len() > 200 {
                return Err(invalid("title"));
            }
            let held = networks(conn)?;
            let network = match string(args, "network_id")? {
                Some(id) if held.iter().any(|n| n == id) => id.to_owned(),
                Some(_) => return Err(invalid("network_id")),
                None => match held.as_slice() {
                    [only] => only.clone(),
                    _ => return Err(invalid("network_id")),
                },
            };
            Ok(json!({
                "repository": repository,
                "branch": branch,
                "title": title,
                "network_id": network,
            }))
        }
        "share" => {
            let pbx = peerbox_id(args)?;
            let list = given(args, "principals")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("principals"))?;
            if list.is_empty() || list.len() > 64 {
                return Err(invalid("principals"));
            }
            let mut principals = BTreeSet::new();
            for item in list {
                let ok = item
                    .as_str()
                    .and_then(|p| p.strip_prefix("person:"))
                    .is_some_and(|id| crate::peer_store::valid_id(id, "person", 32));
                if !ok || !principals.insert(item.as_str().unwrap_or_default().to_owned()) {
                    return Err(invalid("principals"));
                }
            }
            let actions = actions(args)?;
            let (bytes, pending) = bounds(args, &actions)?;
            let disconnected = match given(args, "allow_disconnected") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err(invalid("allow_disconnected")),
            };
            Ok(json!({
                "peerbox_id": pbx,
                "principals": principals.into_iter().collect::<Vec<_>>(),
                "actions": actions,
                "max_bundle_bytes": bytes,
                "max_pending": pending,
                "allow_disconnected": disconnected,
            }))
        }
        _ => {
            let pbx = peerbox_id(args)?;
            let label = required(args, "label")?;
            if !label_ok(label) {
                return Err(invalid("label"));
            }
            let actions = actions(args)?;
            let (bytes, pending) = bounds(args, &actions)?;
            let seconds = integer(args, "expires_in_seconds")?.unwrap_or(3600);
            if !(60..=86_400).contains(&seconds) {
                return Err(invalid("expires_in_seconds"));
            }
            Ok(json!({
                "peerbox_id": pbx,
                "label": label,
                "actions": actions,
                "max_bundle_bytes": bytes,
                "max_pending": pending,
                "expires_in_seconds": seconds,
            }))
        }
    }
}

/// Proposing step 3: the pending and hourly limits, the pending limit
/// answering when both apply.
fn limits(conn: &Connection, adapter: &str) -> Result<(), Error> {
    let (mine, host): (i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(adapter_id = ?1), 0), COUNT(*) FROM peerbox_proposals WHERE state = 'pending'",
        [adapter],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if mine >= PENDING_PER_CREDENTIAL || host >= PENDING_PER_HOST {
        return Err(Error::Limit {
            limit: "max_pending_proposals".into(),
            message: "too many proposals are waiting for approval".into(),
        });
    }
    let now = crate::clock::now();
    let mut recent: Vec<DateTime<Utc>> = all(
        conn,
        "SELECT record FROM peerbox_proposals WHERE adapter_id = ?1",
        [adapter],
    )?
    .iter()
    .map(|p| time(&p.requested_at))
    .filter(|at| *at > now - TimeDelta::hours(1))
    .collect();
    if recent.len() < PER_HOUR {
        return Ok(());
    }
    recent.sort();
    let wait = (recent[0] + TimeDelta::hours(1) - now).num_milliseconds();
    let retry_after = ((wait + 999) / 1000).max(1);
    Err(coded(
        429,
        "rate_limited",
        format!(
            "this session made {} peerbox proposals in the last hour, its limit; retry after {retry_after} seconds",
            recent.len()
        ),
        json!({ "retry_after": retry_after }),
    ))
}

/// The peerbox rules of this host in its owner's current policy in
/// `network`.
fn current_rules(
    store: &Store,
    conn: &Connection,
    network: &str,
) -> Result<Vec<PeerboxRule>, Error> {
    let own = store.identity().id;
    let mut rules = Vec::new();
    for (id, member) in store.decentralized_own_members(conn)? {
        if id != network {
            continue;
        }
        let Some(person) = member.person_id else {
            continue;
        };
        let Some(key) = store.product_person_key(conn, &id, &person)? else {
            continue;
        };
        if let Some(policy) = store.product_policy(conn, &id, &key)? {
            rules.extend(
                policy
                    .peerbox_rules()
                    .iter()
                    .filter(|r| r.host == own)
                    .cloned(),
            );
        }
    }
    Ok(rules)
}
/// The access each principal holds on a peerbox in `rules`, in short
/// action names, or null.
fn before(rules: &[PeerboxRule], host: &str, peerbox: &str, principals: &[String]) -> Value {
    Value::Array(
        principals
            .iter()
            .map(|p| {
                rules
                    .iter()
                    .find(|r| r.host == host && r.peerbox == peerbox && r.principals.contains(p))
                    .map(|r| {
                        json!({
                            "actions": r.actions.iter().map(|a| a.trim_start_matches("peerbox.")).collect::<Vec<_>>(),
                            "max_bundle_bytes": r.max_bundle_bytes,
                            "max_pending": r.max_pending,
                            "allow_disconnected": r.allow_disconnected,
                        })
                    })
                    .unwrap_or(Value::Null)
            })
            .collect(),
    )
}
fn principals_of(args: &Value) -> Vec<String> {
    args["principals"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect()
}
/// The share review's `people`, or the first principal that is no person
/// of the network's current signed membership.
fn people(
    store: &Store,
    conn: &Connection,
    network: &str,
    principals: &[String],
) -> Result<Result<Value, String>, Error> {
    let persons = store.product_persons(conn, network)?;
    let mut out = Vec::new();
    for p in principals {
        let id = p.trim_start_matches("person:");
        match persons.iter().find(|x| x.person_id == id) {
            Some(x) => {
                out.push(json!({"principal": p, "person_id": x.person_id, "label": x.member}))
            }
            None => return Ok(Err(p.clone())),
        }
    }
    Ok(Ok(Value::Array(out)))
}

/// Proposing steps 4 and 5 for `share` and `invite`: the target and the
/// review, from this host's records and its owner's policy.
fn review_record(store: &Store, op: &str, args: &Value) -> Result<Value, Error> {
    let conn = store.connection()?;
    let pbx = args["peerbox_id"].as_str().unwrap_or_default();
    let record = crate::peerbox::record(&conn, pbx)?.ok_or_else(unknown)?;
    if op == "invite" {
        return Ok(json!({"title": record.title, "network_id": record.network_id}));
    }
    let principals = principals_of(args);
    let people = match people(store, &conn, &record.network_id, &principals)? {
        Ok(v) => v,
        Err(principal) => {
            return Err(coded(
                400,
                "unknown_principal",
                format!("{principal} is no member of the peerbox's network"),
                json!({ "principal": principal }),
            ));
        }
    };
    let rules = current_rules(store, &conn, &record.network_id)?;
    Ok(json!({
        "title": record.title,
        "network_id": record.network_id,
        "people": people,
        "before": before(&rules, &store.identity().id, pbx, &principals),
    }))
}
/// The `create` review: Git's disclosure of the branch, read without the
/// store's lock.
fn review_create(store: &Store, args: &Value) -> Result<Value, Failure> {
    let git = Git::new(store.state_directory())?;
    crate::peerbox::create_review(
        &git,
        &PathBuf::from(args["repository"].as_str().unwrap_or_default()),
        args["branch"].as_str().unwrap_or_default(),
        &store.state_directory().join("peerbox-tmp"),
    )
}

/// What a submission found before the target and review.
enum Prior {
    Existing(Value),
    New(Box<(String, Value, String)>),
}

impl Store {
    /// Proposing steps 1 to 3: a repeat, or the normalized request within
    /// the limits.
    fn proposal_prior(&self, auth: &AdapterAuth, body: &Value) -> Result<Prior, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = proposals_authority(&tx, auth)?;
        let object = body.as_object().ok_or_else(|| invalid("proposal_id"))?;
        let id = object
            .get("proposal_id")
            .and_then(Value::as_str)
            .filter(|id| proposal_id_shape(id))
            .ok_or_else(|| invalid("proposal_id"))?;
        let request_sha256 = digest(body);
        // 2. Repeat, before any other step.
        if let Some(existing) = load(&tx, id)? {
            if existing.origin.agent_id != ss.agent_id || existing.request_sha256 != request_sha256
            {
                return Err(coded(
                    409,
                    "conflict",
                    "this proposal ID was used with a different request",
                    json!({}),
                ));
            }
            let verified = crate::adapter_connection::verified_authority(&tx, auth).is_ok();
            let view = seen_view(&tx, &a, &ss, verified, &existing)?;
            tx.commit()?;
            return Ok(Prior::Existing(view));
        }
        // 1. Shape.
        if let Some(key) = object
            .keys()
            .find(|k| !matches!(k.as_str(), "proposal_id" | "op" | "args"))
        {
            return Err(invalid(key));
        }
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .filter(|op| matches!(*op, "create" | "share" | "invite"))
            .ok_or_else(|| invalid("op"))?
            .to_owned();
        let args = object
            .get("args")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("args"))?;
        let args = normalize(&tx, &op, args)?;
        // 3. Limits.
        limits(&tx, &a.id)?;
        Ok(Prior::New(Box::new((op, args, request_sha256))))
    }
    /// Proposing steps 6 and 7: the duplicate check and the record.
    fn persist_proposal(
        &self,
        auth: &AdapterAuth,
        body: &Value,
        op: String,
        args: Value,
        review: Value,
        request_sha256: String,
    ) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = proposals_authority(&tx, auth)?;
        let id = body["proposal_id"].as_str().unwrap_or_default().to_owned();
        // A concurrent request with the same ID got there first.
        if let Some(existing) = load(&tx, &id)? {
            if existing.origin.agent_id != ss.agent_id || existing.request_sha256 != request_sha256
            {
                return Err(coded(
                    409,
                    "conflict",
                    "this proposal ID was used with a different request",
                    json!({}),
                ));
            }
            return Ok(existing.view());
        }
        let proposal_sha256 = digest(&json!({"op": op, "args": args, "review": review}));
        let duplicate = all(
            &tx,
            "SELECT record FROM peerbox_proposals WHERE agent_id = ?1 AND state = 'pending'",
            [&ss.agent_id],
        )?
        .into_iter()
        .find(|p| p.proposal_sha256 == proposal_sha256);
        if let Some(d) = duplicate {
            return Err(coded(
                409,
                "duplicate",
                "the same change is already waiting for the person's approval",
                json!({ "proposal_id": d.proposal_id }),
            ));
        }
        limits(&tx, &a.id)?;
        let now = crate::clock::now();
        let p = Proposal {
            proposal_id: id,
            op,
            args,
            review,
            request_sha256,
            proposal_sha256,
            origin: ProposalOrigin {
                adapter_id: a.id.clone(),
                agent_id: ss.agent_id.clone(),
                session_id: ss.id.clone(),
            },
            state: "pending".into(),
            requested_at: stamp(now),
            expires_at: stamp(now + LIFETIME),
            decided_at: None,
            reason: None,
            result: None,
            error: None,
        };
        tx.execute(
            "INSERT INTO peerbox_proposals VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                p.proposal_id,
                a.id,
                ss.agent_id,
                ss.id,
                p.op,
                p.state,
                p.expires_at,
                serde_json::to_string(&p)?
            ],
        )?;
        append_event(&tx, "peerbox.proposed", &p.proposal_id, &p.requested_at)?;
        tx.commit()?;
        Ok(p.view())
    }
    /// `GET /adapter/v1/peerbox/proposals/{id}`.
    fn adapter_proposal(&self, auth: &AdapterAuth, id: &str) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = proposals_authority(&tx, auth)?;
        let p = load(&tx, id)?
            .filter(|p| p.origin.agent_id == ss.agent_id)
            .ok_or(Error::NotFound)?;
        let verified = crate::adapter_connection::verified_authority(&tx, auth).is_ok();
        let view = seen_view(&tx, &a, &ss, verified, &p)?;
        tx.commit()?;
        Ok(view)
    }
    /// `POST /adapter/v1/peerbox/proposals/{id}/cancel`.
    fn cancel_proposal(&self, auth: &AdapterAuth, id: &str) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (_, ss) = proposals_authority(&tx, auth)?;
        let mut p = load(&tx, id)?
            .filter(|p| p.origin.agent_id == ss.agent_id)
            .ok_or(Error::NotFound)?;
        if expire_if_due(&tx, &mut p)? {
            tx.commit()?;
            return Err(not_pending(p.view()));
        }
        if p.state != "pending" {
            return Err(not_pending(p.view()));
        }
        decide(&tx, &mut p, "cancelled")?;
        tx.commit()?;
        Ok(p.view())
    }
}

/// A proposal's view for its agent's session. A final view marks the
/// notification this session holds seen; a late one no session holds yet
/// is bound to this session, when verified, and seen at once.
fn seen_view(
    tx: &Transaction<'_>,
    a: &Adapter,
    ss: &Session,
    verified: bool,
    p: &Proposal,
) -> Result<Value, Error> {
    if p.is_final() {
        let at = crate::store::now();
        if !mark_seen(tx, &ss.id, &p.proposal_id, &at)? && verified {
            bind_late(tx, a, ss, &p.proposal_id, &at)?;
        }
    }
    Ok(p.view())
}
fn bind_late(
    tx: &Transaction<'_>,
    a: &Adapter,
    ss: &Session,
    id: &str,
    at: &str,
) -> Result<(), Error> {
    let record: Option<String> = tx
        .query_row(
            "SELECT record FROM peerbox_proposal_notifications WHERE proposal_id = ?1 AND seen_at IS NULL AND returned_at IS NULL AND COALESCE(json_extract(record, '$.claimed'), 0) = 0",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(record) = record else {
        return Ok(());
    };
    let mut n: StoredUpdate = serde_json::from_str(&record)?;
    if n.notification.session_id == ss.id
        || !crate::live_delivery::ended(tx, &n.notification.adapter_id)?
    {
        return Ok(());
    }
    n.notification.adapter_id = a.id.clone();
    n.notification.session_id = ss.id.clone();
    n.notification.updated_at = at.to_owned();
    tx.execute(
        "UPDATE peerbox_proposal_notifications SET record = ?1, session_id = ?2, seen_at = ?3 WHERE id = ?4",
        params![serde_json::to_string(&n)?, ss.id, at, n.notification.id],
    )?;
    Ok(())
}
/// Marks the proposal-update notification this session holds seen.
/// Returns whether it was newly marked.
pub(crate) fn mark_seen(
    conn: &Connection,
    session: &str,
    id: &str,
    at: &str,
) -> Result<bool, Error> {
    Ok(conn.execute(
        "UPDATE peerbox_proposal_notifications SET seen_at = ?1 WHERE proposal_id = ?2 AND session_id = ?3 AND seen_at IS NULL AND returned_at IS NULL",
        params![at, id, session],
    )? > 0)
}
/// Whether a session may name a proposal in `mark_seen`: one of its
/// agent's, or one whose notification it holds.
pub(crate) fn holds(conn: &Connection, session: &Session, id: &str) -> Result<bool, Error> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM peerbox_proposals WHERE agent_id = ?1 AND proposal_id = ?2) OR EXISTS(SELECT 1 FROM peerbox_proposal_notifications WHERE proposal_id = ?2 AND session_id = ?3 AND returned_at IS NULL)",
        params![session.agent_id, id, session.id],
        |r| r.get(0),
    )?)
}
/// Whether a session has ended: its authorization has, for every
/// credential it had.
fn session_ended(conn: &Connection, session: &str) -> Result<bool, Error> {
    let ids: Vec<String> = {
        let mut stmt = conn.prepare("SELECT id FROM adapter_credentials WHERE session_id = ?1")?;
        stmt.query_map([session], |r| r.get(0))?
            .collect::<Result<_, _>>()?
    };
    for id in ids {
        if !crate::live_delivery::ended(conn, &id)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The proposals a session still owes attention (pending work): its
/// agent's proposals not final, made by this session or an ended one of
/// the agent, and those whose notification this session holds unseen.
/// Oldest first.
pub(crate) fn pending(conn: &Connection, session: &str) -> Result<Vec<Value>, Error> {
    let agent: String = conn.query_row(
        "SELECT agent_id FROM sessions WHERE id = ?1",
        [session],
        |r| r.get(0),
    )?;
    let rows: Vec<(String, Option<i64>)> = {
        let mut stmt = conn.prepare("SELECT p.record, (SELECT n.redeliveries FROM peerbox_proposal_notifications n WHERE n.proposal_id = p.proposal_id AND n.session_id = ?2 AND n.seen_at IS NULL AND n.returned_at IS NULL) FROM peerbox_proposals p WHERE p.agent_id = ?1 ORDER BY p.rowid")?;
        stmt.query_map(params![agent, session], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    let mut ended: HashMap<String, bool> = HashMap::new();
    let mut out = Vec::new();
    for (record, held) in rows {
        let p: Proposal = serde_json::from_str(&record)?;
        let maker = p.origin.session_id.clone();
        let listed = if p.is_final() {
            held.is_some()
        } else if maker == session {
            true
        } else {
            match ended.get(&maker) {
                Some(v) => *v,
                None => {
                    let v = session_ended(conn, &maker)?;
                    ended.insert(maker.clone(), v);
                    v
                }
            }
        };
        if listed {
            out.push((
                time(&p.requested_at),
                json!({
                    "proposal_id": p.proposal_id,
                    "op": p.op,
                    "state": p.state,
                    "expires_at": p.expires_at,
                    "session_id": maker,
                    "redelivered": held.is_some_and(|n| n > 0),
                }),
            ));
        }
    }
    out.sort_by_key(|(at, _)| *at);
    Ok(out.into_iter().map(|(_, v)| v).collect())
}
/// Returns to the agent's queue the claimed, unseen notifications whose
/// authorization has ended, up to the redelivery limit.
pub(crate) fn return_updates(
    tx: &Transaction<'_>,
    agent: &str,
    ended: &mut crate::live_delivery::Ended,
    at: &str,
) -> Result<(), Error> {
    let rows: Vec<(String, i64)> = {
        let mut stmt = tx.prepare("SELECT n.record, n.redeliveries FROM peerbox_proposal_notifications n JOIN sessions s ON s.id = n.session_id WHERE s.agent_id = ?1 AND n.seen_at IS NULL AND n.returned_at IS NULL AND json_extract(n.record, '$.claimed') = 1 ORDER BY n.rowid")?;
        stmt.query_map([agent], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    for (record, count) in rows {
        let n: StoredUpdate = serde_json::from_str(&record)?;
        if count < crate::live_delivery::MAX_REDELIVERIES
            && ended.check(tx, &n.notification.adapter_id)?
        {
            tx.execute(
                "UPDATE peerbox_proposal_notifications SET returned_at = ?1 WHERE id = ?2",
                params![at, n.notification.id],
            )?;
        }
    }
    Ok(())
}

impl Store {
    /// `POST /adapter/v1/peerbox/proposal-updates/next`: the returned
    /// notification of the agent claimed first, then the oldest unclaimed
    /// one this session holds or one whose authorization has ended.
    fn next_proposal_update(&self, auth: &AdapterAuth) -> Result<Option<Value>, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = proposals_authority(&tx, auth)?;
        crate::adapter_connection::verified_authority(&tx, auth)?;
        crate::live_delivery::return_items(self, &tx, &ss.agent_id)?;
        let at = crate::store::now();
        let returned: Option<String> = tx
            .query_row(
                "SELECT n.record FROM peerbox_proposal_notifications n JOIN sessions s ON s.id = n.session_id WHERE s.agent_id = ?1 AND n.returned_at IS NOT NULL AND n.seen_at IS NULL ORDER BY n.rowid",
                [&ss.agent_id],
                |r| r.get(0),
            )
            .optional()?;
        let (record, redelivered) = match returned {
            Some(record) => (record, true),
            None => {
                let rows: Vec<String> = {
                    let mut stmt = tx.prepare("SELECT n.record FROM peerbox_proposal_notifications n JOIN sessions s ON s.id = n.session_id WHERE s.agent_id = ?1 AND n.seen_at IS NULL AND n.returned_at IS NULL AND COALESCE(json_extract(n.record, '$.claimed'), 0) = 0 ORDER BY n.rowid")?;
                    stmt.query_map([&ss.agent_id], |r| r.get(0))?
                        .collect::<Result<_, _>>()?
                };
                let mut ended = crate::live_delivery::Ended::default();
                let mut found = None;
                for record in rows {
                    let n: StoredUpdate = serde_json::from_str(&record)?;
                    let own =
                        n.notification.adapter_id == a.id && n.notification.session_id == ss.id;
                    if own || ended.check(&tx, &n.notification.adapter_id)? {
                        found = Some(record);
                        break;
                    }
                }
                match found {
                    Some(record) => (record, false),
                    None => {
                        tx.commit()?;
                        return Ok(None);
                    }
                }
            }
        };
        let mut n: StoredUpdate = serde_json::from_str(&record)?;
        n.notification.adapter_id = a.id.clone();
        n.notification.session_id = ss.id.clone();
        n.notification.state = "unknown".into();
        n.notification.updated_at = at;
        n.claimed = true;
        tx.execute(
            "UPDATE peerbox_proposal_notifications SET record = ?1, session_id = ?2, redeliveries = redeliveries + ?3, returned_at = NULL WHERE id = ?4",
            params![
                serde_json::to_string(&n)?,
                ss.id,
                i64::from(redelivered),
                n.notification.id
            ],
        )?;
        let p = load(&tx, &n.notification.proposal_id)?.ok_or(Error::NotFound)?;
        tx.commit()?;
        Ok(Some(json!({
            "delivery": n.notification,
            "proposal": p.view(),
            "redelivered": redelivered,
        })))
    }
    /// `POST /adapter/v1/peerbox/proposal-updates/{id}/forwarded`.
    fn proposal_update_forwarded(
        &self,
        auth: &AdapterAuth,
        id: &str,
    ) -> Result<ProposalUpdate, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (a, ss) = proposals_authority(&tx, auth)?;
        let record: String = tx
            .query_row(
                "SELECT record FROM peerbox_proposal_notifications WHERE id = ?1 AND returned_at IS NULL",
                [id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::NotFound)?;
        let mut n: StoredUpdate = serde_json::from_str(&record)?;
        if n.notification.adapter_id != a.id || n.notification.session_id != ss.id || !n.claimed {
            return Err(Error::NotFound);
        }
        if n.notification.state != "forwarded" {
            n.notification.state = "forwarded".into();
            n.notification.updated_at = crate::store::now();
            tx.execute(
                "UPDATE peerbox_proposal_notifications SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&n)?, n.notification.id],
            )?;
            tx.commit()?;
        }
        Ok(n.notification)
    }
}

// ---------------------------------------------------------------------
// The person (peerbox contract, Approving).

impl Store {
    /// `GET /v1/peerbox-proposals?state=pending|all`.
    pub fn peerbox_proposals_view(&self, every: bool) -> Result<Value, Error> {
        let conn = self.connection()?;
        let since = crate::clock::now() - DECIDED_LISTED;
        let mut list = all(&conn, "SELECT record FROM peerbox_proposals", [])?;
        list.retain(|p| {
            p.state == "pending"
                || (every && p.decided_at.as_deref().is_some_and(|d| time(d) >= since))
        });
        sort(&mut list);
        Ok(json!({ "peerbox_proposals": list }))
    }
    /// `GET /v1/peerbox-proposals/{id}`.
    pub fn peerbox_proposal(&self, id: &str) -> Result<Proposal, Error> {
        load(&*self.connection()?, id)?.ok_or(Error::NotFound)
    }
    /// `POST /v1/peerbox-proposals/{id}/deny`.
    pub fn deny_proposal(&self, id: &str, reason: Option<String>) -> Result<Proposal, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut p = load(&tx, id)?.ok_or(Error::NotFound)?;
        if expire_if_due(&tx, &mut p)? {
            tx.commit()?;
            return Err(not_pending(json!(p)));
        }
        if p.state != "pending" {
            return Err(not_pending(json!(p)));
        }
        p.reason = reason;
        decide(&tx, &mut p, "denied")?;
        tx.commit()?;
        Ok(p)
    }
    /// `POST /v1/peerbox-proposals/{id}/approve`: checks the proposal and
    /// the digest, moves it to `approved`, and carries out exactly its
    /// `args`. Returns the record, `executed` or `failed`.
    pub fn approve_proposal(
        &self,
        id: &str,
        sha256: &str,
        person_key: Option<String>,
    ) -> Result<Proposal, Error> {
        let signer = match person_key {
            None => None,
            Some(path) => {
                if !std::path::Path::new(&path).is_absolute() {
                    return Err(invalid("person_key"));
                }
                Some(
                    PersonSigner::open(Some(std::path::Path::new(&path))).map_err(|e| {
                        coded(
                            400,
                            "invalid",
                            format!("person_key: {e}"),
                            json!({"field": "person_key"}),
                        )
                    })?,
                )
            }
        };
        let p = self.approvable(id, sha256)?;
        if p.op == "share" {
            self.share_signer_ready(&p, signer.as_ref())?;
        }
        // Pending to approved, once, in one transaction; listed as being
        // carried out before it commits.
        let mut p = {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let mut current = load(&tx, id)?.ok_or(Error::NotFound)?;
            if current.state != "pending" || current.due(crate::clock::now()) {
                return Err(not_pending(json!(current)));
            }
            if current.proposal_sha256 != sha256 {
                return Err(coded(
                    409,
                    "proposal_changed",
                    "the proposal is not the one displayed",
                    json!({}),
                ));
            }
            IN_FLIGHT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id.to_owned());
            if let Err(e) = decide(&tx, &mut current, "approved").and_then(|_| Ok(tx.commit()?)) {
                IN_FLIGHT
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(id);
                return Err(e);
            }
            current
        };
        let outcome = self.execute_proposal(&mut p, signer);
        IN_FLIGHT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        outcome?;
        Ok(p)
    }
    /// The route refusals checked before anything changes.
    fn approvable(&self, id: &str, sha256: &str) -> Result<Proposal, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut p = load(&tx, id)?.ok_or(Error::NotFound)?;
        if expire_if_due(&tx, &mut p)? {
            tx.commit()?;
            return Err(not_pending(json!(p)));
        }
        if p.state != "pending" {
            return Err(not_pending(json!(p)));
        }
        if p.proposal_sha256 != sha256 {
            return Err(coded(
                409,
                "proposal_changed",
                "the proposal is not the one displayed",
                json!({}),
            ));
        }
        Ok(p)
    }
    /// `person_key_needed` for a share whose signing would need the
    /// person's interaction without the key; a key that is not this
    /// network's person key is refused.
    fn share_signer_ready(&self, p: &Proposal, signer: Option<&PersonSigner>) -> Result<(), Error> {
        let network = {
            let conn = self.connection()?;
            let pbx = p.args["peerbox_id"].as_str().unwrap_or_default();
            match crate::peerbox::record(&conn, pbx)? {
                Some(r) => r.network_id,
                // Execution fails it with `unknown`.
                None => return Ok(()),
            }
        };
        match signer {
            Some(key) => {
                let person = crate::persons::person_id(&key.public_key());
                let own = self
                    .decentralized_own_members(&*self.connection()?)?
                    .into_iter()
                    .any(|(n, m)| n == network && m.person_id.as_deref() == Some(person.as_str()));
                if !own {
                    return Err(coded(
                        400,
                        "invalid",
                        "person_key is not this network's person key on this host",
                        json!({"field": "person_key"}),
                    ));
                }
                Ok(())
            }
            None => {
                let ready = crate::decentralized::peerbox_share::provider_signs(self, &network)
                    .unwrap_or(false);
                if ready {
                    Ok(())
                } else {
                    Err(coded(
                        409,
                        "person_key_needed",
                        "signing this policy needs your person key; run approve again with --person-key",
                        json!({}),
                    ))
                }
            }
        }
    }
    /// Carries out an approved proposal and records `executed` or `failed`.
    fn execute_proposal(
        &self,
        p: &mut Proposal,
        signer: Option<PersonSigner>,
    ) -> Result<(), Error> {
        let outcome = match p.op.as_str() {
            "create" => self.execute_create(p),
            "invite" => self.execute_invite(p),
            _ => self.execute_share(p, signer),
        };
        match outcome {
            Ok(Done::Stored) => Ok(()),
            Ok(Done::Result(result)) => {
                let mut conn = self.connection()?;
                let tx = conn.transaction()?;
                p.result = Some(result);
                decide(&tx, p, "executed")?;
                tx.commit()?;
                Ok(())
            }
            Err((code, message)) => {
                let mut conn = self.connection()?;
                let tx = conn.transaction()?;
                p.error = Some(json!({"code": code, "message": message}));
                p.result = None;
                decide(&tx, p, "failed")?;
                tx.commit()?;
                Ok(())
            }
        }
    }
    /// `create`: the disclosure again, then the record, in one transaction
    /// with the proposal's `executed`.
    fn execute_create(&self, p: &mut Proposal) -> Result<Done, (String, String)> {
        let review = review_create(self, &p.args).map_err(|f| (f.code.to_owned(), f.message))?;
        if review != p.review {
            return Err(changed());
        }
        let mut run = || -> Result<Result<(), (String, String)>, Error> {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let network = p.args["network_id"].as_str().unwrap_or_default().to_owned();
            if !crate::decentralized::product::is_decentralized(&tx, &network)? {
                return Ok(Err((
                    "invalid".into(),
                    "the network is no longer one this host is in".into(),
                )));
            }
            let r = crate::peerbox::Record {
                peerbox_id: new_id("pbx")?,
                network_id: network,
                title: p.args["title"].as_str().unwrap_or_default().to_owned(),
                repository: p.args["repository"].as_str().unwrap_or_default().to_owned(),
                branch: p.args["branch"].as_str().unwrap_or_default().to_owned(),
                created_at: crate::store::now(),
                proposal_id: Some(p.proposal_id.clone()),
            };
            tx.execute(
                "INSERT INTO peerboxes VALUES (?1, ?2, ?3)",
                params![r.peerbox_id, r.network_id, serde_json::to_string(&r)?],
            )?;
            append_event(&tx, "peerbox.created", &r.peerbox_id, &r.created_at)?;
            p.result = Some(json!({"peerbox_id": r.peerbox_id}));
            decide(&tx, p, "executed")?;
            tx.commit()?;
            Ok(Ok(()))
        };
        match run() {
            Ok(Ok(())) => Ok(Done::Stored),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(internal(e)),
        }
    }
    /// `invite`: the network invite and its pending share, in one
    /// transaction with the proposal's `executed` and the `psb1-` code.
    fn execute_invite(&self, p: &mut Proposal) -> Result<Done, (String, String)> {
        let mut run = || -> Result<Result<(), (String, String)>, Error> {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let pbx = p.args["peerbox_id"].as_str().unwrap_or_default();
            let Some(record) = crate::peerbox::record(&tx, pbx)? else {
                return Ok(Err((
                    "unknown".into(),
                    "the peerbox was removed before execution".into(),
                )));
            };
            let label = p.args["label"].as_str().unwrap_or_default();
            let seconds = p.args["expires_in_seconds"].as_i64().unwrap_or(3600);
            let minted = match crate::decentralized::runtime::mint_invite_for(
                self,
                &tx,
                &record.network_id,
                label,
                seconds,
            ) {
                Ok(v) => v,
                Err(e) => return Ok(Err((e.code.into(), format!("the invite: {}", e.code)))),
            };
            let text = |k: &str| minted[k].as_str().unwrap_or_default().to_owned();
            let actions: Vec<String> = p.args["actions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|a| format!("peerbox.{a}"))
                .collect();
            let share = PendingShare {
                invitation_id: text("invitation_id"),
                peerbox_id: record.peerbox_id.clone(),
                network_id: record.network_id.clone(),
                label: label.to_owned(),
                actions: actions.clone(),
                max_bundle_bytes: p.args["max_bundle_bytes"]
                    .as_i64()
                    .unwrap_or(MAX_BUNDLE_BYTES),
                max_pending: p.args["max_pending"].as_i64().unwrap_or(0),
                created_at: crate::store::now(),
                expires_at: text("expires_at"),
                requests: Vec::new(),
                person: None,
                waiting: false,
                proposal_id: Some(p.proposal_id.clone()),
            };
            crate::peerbox_invite::insert_pending_share(&tx, &share)?;
            // The `psb1-` code, as `peerbox invite` prints it.
            let code = json!({
                "invite": text("invitation"),
                "peerbox_id": record.peerbox_id,
                "title": record.title,
                "home_host_id": self.identity().id,
                "actions": actions,
            });
            use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
            let code = format!(
                "psb1-{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&code)?)
            );
            p.result = Some(json!({
                "code": code,
                "invitation_id": share.invitation_id,
                "expires_at": share.expires_at,
            }));
            decide(&tx, p, "executed")?;
            tx.commit()?;
            Ok(Ok(()))
        };
        match run() {
            Ok(Ok(())) => Ok(Done::Stored),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(internal(e)),
        }
    }
    /// `share`: the review again from the policy the signature builds on,
    /// then the signature, tried again after a concurrent edit.
    fn execute_share(
        &self,
        p: &Proposal,
        signer: Option<PersonSigner>,
    ) -> Result<Done, (String, String)> {
        let signer = match signer {
            Some(key) => ProposalSigner::Key(Box::new(key)),
            None => ProposalSigner::Provider,
        };
        let pbx = p.args["peerbox_id"].as_str().unwrap_or_default().to_owned();
        let principals = principals_of(&p.args);
        let host = self.identity().id;
        let actions: Vec<String> = p.args["actions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|a| format!("peerbox.{a}"))
            .collect();
        let unit = PeerboxRule {
            host: String::new(),
            peerbox: pbx.clone(),
            principals: Vec::new(),
            actions,
            max_bundle_bytes: p.args["max_bundle_bytes"]
                .as_i64()
                .unwrap_or(MAX_BUNDLE_BYTES),
            max_pending: p.args["max_pending"].as_i64().unwrap_or(0),
            allow_disconnected: p.args["allow_disconnected"].as_bool().unwrap_or(false),
        };
        let mut last = None;
        for _ in 0..SHARE_ATTEMPTS {
            let network = {
                let conn = self.connection().map_err(internal)?;
                let Some(record) = crate::peerbox::record(&conn, &pbx).map_err(internal)? else {
                    return Err((
                        "unknown".into(),
                        "the peerbox was removed before execution".into(),
                    ));
                };
                let people =
                    people(self, &conn, &record.network_id, &principals).map_err(internal)?;
                let Ok(people) = people else {
                    return Err(changed());
                };
                if p.review["title"] != json!(record.title)
                    || p.review["network_id"] != json!(record.network_id)
                    || p.review["people"] != people
                {
                    return Err(changed());
                }
                record.network_id
            };
            let reviewed = p.review["before"].clone();
            let check = |rules: &[PeerboxRule]| before(rules, &host, &pbx, &principals) == reviewed;
            let outcome = sign_proposal_share(self, &network, &signer, &check, |host, rules| {
                for principal in &principals {
                    crate::policy::peerbox_put(
                        rules,
                        &PeerboxRule {
                            host: host.into(),
                            principals: vec![principal.clone()],
                            ..unit.clone()
                        },
                    );
                }
            });
            match outcome {
                Ok(ProposalSigning::Signed(v) | ProposalSigning::Unchanged(v)) => {
                    return Ok(Done::Result(json!({"policy_version": v})));
                }
                Ok(ProposalSigning::Changed) => return Err(changed()),
                Ok(ProposalSigning::NeedsOwner) => {
                    return Err((
                        "person_key_needed".into(),
                        "signing needed the person's interaction".into(),
                    ));
                }
                Err(e) if e.code == "state_conflict" => last = Some(e),
                Err(e) => return Err((e.code.into(), format!("signing: {}", e.code))),
            }
        }
        let code = last.map_or("state_conflict", |e| e.code);
        Err((
            code.into(),
            "the policy kept changing during signing".into(),
        ))
    }
}

/// What execution came to.
enum Done {
    /// The change and `executed` were written together.
    Stored,
    /// A result to record as `executed`.
    Result(Value),
}
fn changed() -> (String, String) {
    (
        "review_changed".into(),
        "what the review showed changed before execution".into(),
    )
}
fn internal(e: Error) -> (String, String) {
    eprintln!("peerbox proposal: {e:?}");
    ("internal".into(), "an internal error".into())
}

/// One pass: expires pending proposals past `expires_at`, fails approved
/// ones no execution holds (a restart interrupted them), clears an
/// executed invite's code at its expiry, and deletes final proposals 30
/// days after their decision.
fn pass(store: &Store) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let now = crate::clock::now();
    for mut p in all(
        &tx,
        "SELECT record FROM peerbox_proposals WHERE state IN ('pending', 'approved', 'executed')",
        [],
    )? {
        if p.due(now) {
            decide(&tx, &mut p, "expired")?;
        } else if p.state == "approved" {
            let running = IN_FLIGHT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&p.proposal_id);
            if !running {
                p.error = Some(
                    json!({"code": "interrupted", "message": "the daemon stopped while carrying it out; nothing was stored"}),
                );
                decide(&tx, &mut p, "failed")?;
            }
        } else if p.state == "executed"
            && p.op == "invite"
            && let Some(result) = p.result.as_mut()
            && !result["code"].is_null()
            && time(result["expires_at"].as_str().unwrap_or_default()) <= now
        {
            result["code"] = Value::Null;
            save(&tx, &p)?;
        }
    }
    for p in all(
        &tx,
        "SELECT record FROM peerbox_proposals WHERE state NOT IN ('pending', 'approved')",
        [],
    )? {
        if p.decided_at
            .as_deref()
            .is_some_and(|d| time(d) + KEPT <= now)
        {
            tx.execute(
                "DELETE FROM peerbox_proposal_notifications WHERE proposal_id = ?1",
                [&p.proposal_id],
            )?;
            tx.execute(
                "DELETE FROM peerbox_proposals WHERE proposal_id = ?1",
                [&p.proposal_id],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Settles proposals until shutdown, at least every 5 seconds.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if let Err(e) = blocking(store.clone(), pass).await {
            eprintln!("peerbox proposals: {e:?}");
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

/// An attention item: subject, detail and command.
type Item = (String, String, String);
/// `GET /v1/status`: the number of pending proposals and the
/// `peerbox_proposal_pending` item (subject, detail, command).
pub(crate) fn status(conn: &Connection) -> Result<(usize, Option<Item>), Error> {
    let mut list = all(
        conn,
        "SELECT record FROM peerbox_proposals WHERE state = 'pending'",
        [],
    )?;
    sort(&mut list);
    let Some(oldest) = list.first() else {
        return Ok((0, None));
    };
    let target = match oldest.op.as_str() {
        "create" => format!(
            "repository {}",
            quoted(oldest.args["repository"].as_str().unwrap_or_default())
        ),
        _ => format!(
            "peerbox {}",
            oldest.args["peerbox_id"].as_str().unwrap_or_default()
        ),
    };
    Ok((
        list.len(),
        Some((
            list.len().to_string(),
            format!(
                "{} peerbox proposal(s) wait for your approval; the oldest is {} of {}, until {}",
                list.len(),
                oldest.op,
                target,
                oldest.expires_at
            ),
            "peerspan approvals".into(),
        )),
    ))
}

// ---------------------------------------------------------------------
// Routes.

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/peerbox-proposals", get(list_route))
        .route("/v1/peerbox-proposals/{id}", get(show_route))
        .route("/v1/peerbox-proposals/{id}/approve", post(approve_route))
        .route("/v1/peerbox-proposals/{id}/deny", post(deny_route))
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/peerbox/proposals", post(propose_route))
        .route("/adapter/v1/peerbox/proposals/{id}", get(view_route))
        .route(
            "/adapter/v1/peerbox/proposals/{id}/cancel",
            post(cancel_route),
        )
        .route(
            "/adapter/v1/peerbox/proposal-updates/next",
            post(next_route),
        )
        .route(
            "/adapter/v1/peerbox/proposal-updates/{id}/forwarded",
            post(forwarded_route),
        )
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    state: Option<String>,
}
async fn list_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid query".into()))?;
    let every = match q.state.as_deref() {
        None | Some("pending") => false,
        Some("all") => true,
        Some(_) => return Err(Error::Invalid("state is pending or all".into())),
    };
    Ok(Json(
        blocking(store, move |s| s.peerbox_proposals_view(every)).await?,
    ))
}
async fn show_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Proposal>, Error> {
    Ok(Json(
        blocking(store, move |s| s.peerbox_proposal(&id)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    proposal_sha256: String,
    #[serde(default)]
    person_key: Option<String>,
}
async fn approve_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Proposal>, Error> {
    let body: ApproveBody = crate::api::decode(body)?;
    // Execution runs to its end in one blocking task, so a closed request
    // never leaves an approval without its execution.
    Ok(Json(
        blocking(store, move |s| {
            s.approve_proposal(&id, &body.proposal_sha256, body.person_key)
        })
        .await?,
    ))
}
async fn deny_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Proposal>, Error> {
    let body: Value = crate::api::decode(body)?;
    let reason = crate::approvals::reason_of(&body)?;
    Ok(Json(
        blocking(store, move |s| s.deny_proposal(&id, reason)).await?,
    ))
}

/// Checks the credential, and its `peerbox_proposals`, before the body.
async fn flagged(store: &Arc<Store>, auth: &AdapterAuth) -> Result<(), Error> {
    let a = auth.clone();
    blocking(store.clone(), move |s| {
        proposals_authority(&*s.connection()?, &a).map(|_| ())
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn propose_route(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let received = Instant::now();
    let auth = token(&headers);
    flagged(&store, &auth).await?;
    let bytes = body.map_err(|_| invalid("proposal_id"))?;
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| invalid("proposal_id"))?;
    let body = Arc::new(body);
    let (a, b) = (auth.clone(), body.clone());
    let (op, args, request_sha256) =
        match blocking(store.clone(), move |s| s.proposal_prior(&a, &b)).await? {
            Prior::Existing(view) => return Ok(Json(view)),
            Prior::New(found) => *found,
        };
    // 4 and 5. The target and the review, within the wait limit of
    // receipt; Git runs without the store's lock.
    let (o, g) = (op.clone(), args.clone());
    let reviewing = blocking(store.clone(), move |s| {
        if o == "create" {
            review_create(s, &g).map_err(git_refusal)
        } else {
            review_record(s, &o, &g)
        }
    });
    let review = tokio::time::timeout_at(
        (received + crate::call_timing::WAIT_LIMIT).into(),
        reviewing,
    )
    .await
    .map_err(|_| {
        coded(
            503,
            "timeout",
            "the review could not be computed in time; nothing was recorded. The person creates such a peerbox with peerbox create",
            json!({}),
        )
    })??;
    let (a, b) = (auth.clone(), body.clone());
    Ok(Json(
        blocking(store, move |s| {
            s.persist_proposal(&a, &b, op, args, review, request_sha256)
        })
        .await?,
    ))
}
async fn view_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, Error> {
    let auth = token(&headers);
    flagged(&store, &auth).await?;
    Ok(Json(
        blocking(store, move |s| s.adapter_proposal(&auth, &id)).await?,
    ))
}
async fn cancel_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let auth = token(&headers);
    flagged(&store, &auth).await?;
    let _: Empty = crate::api::decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.cancel_proposal(&auth, &id)).await?,
    ))
}
async fn next_route(
    State(store): State<Arc<Store>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Option<Value>>, Error> {
    let auth = token(&headers);
    flagged(&store, &auth).await?;
    let _: Empty = crate::api::decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.next_proposal_update(&auth)).await?,
    ))
}
async fn forwarded_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<ProposalUpdate>, Error> {
    let auth = token(&headers);
    flagged(&store, &auth).await?;
    let _: Empty = crate::api::decode(body)?;
    Ok(Json(
        blocking(store, move |s| s.proposal_update_forwarded(&auth, &id)).await?,
    ))
}
