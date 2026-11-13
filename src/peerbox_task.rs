//! Peerbox tasks (peerbox contract, Requests to Operations): the home
//! host. A peer's peerbox task is authorized by a peerbox rule in this
//! host's owner's policy, persisted `queued`, and served by the worker,
//! which checks it again before it runs the operation. The result is the
//! final `output`; an operation's error is a final `failed` outcome.
use crate::{
    artifact::{ArtifactEntry, RECEIVED, RESULT, STORED},
    model::Error,
    network::Member,
    peerbox::{BUNDLE_TYPE, Failure, Git, MAX_FILE, Record, commit_id, valid_branch},
    policy::{PEERBOX_ACTIONS, PEERBOX_READ, PEERBOX_RUN, PEERBOX_SUBMIT, PolicyRef, peerbox_id},
    store::{Store, append_event, now},
    task::{TaskRequest, TaskStatus, is_final, received, record},
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

pub const EXECUTOR: &str = "peerbox";
/// The task contract's limit for one final output.
const OUTPUT_LIMIT: usize = 65_536;
const MAX_HAVE: usize = 32;
/// The operations of slices not yet implemented here.
const NOT_IMPLEMENTED: &str = "not_implemented";

/// A peerbox task's `peerbox` object: the operation and its fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerboxOp {
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peerbox_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub have: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<crate::runtime_task::RunSpec>,
}

const OPS: [&str; 6] = ["list", "fetch", "submit", "status", "run", "withdraw"];

/// An operation's fields beside `op`: (required, optional).
fn shape(op: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match op {
        "list" => (&[], &["after"]),
        "fetch" => (&["peerbox_id"], &["have"]),
        "submit" => (&["peerbox_id", "base", "branch", "bundle"], &[]),
        "status" => (&["peerbox_id"], &["contribution_id", "before"]),
        "run" => (&["peerbox_id", "commit", "run"], &[]),
        "withdraw" => (&["peerbox_id", "contribution_id"], &[]),
        _ => (&[], &[]),
    }
}

fn invalid(field: &str) -> Error {
    Error::Invalid(field.into())
}
fn unknown() -> Error {
    Error::Coded {
        status: 404,
        code: "unknown",
        message: "unknown peerbox".into(),
        extra: Default::default(),
    }
}
fn contribution_id(id: &str) -> bool {
    crate::peer_store::valid_id(id, "pbc", 16)
}

/// A peerbox task's fields, checked before decoding so that a refusal
/// names the field (Requests).
pub(crate) fn check_fields(body: &Value) -> Result<(), Error> {
    const TOP: [&str; 8] = [
        "task_id",
        "executor",
        "peerbox",
        "deadline",
        "input",
        "policy",
        "origin",
        "artifacts",
    ];
    const RUN: [&str; 5] = ["argv", "cwd", "env", "resources", "results"];
    const RESOURCES: [&str; 3] = ["cpus", "memory_mib", "timeout_seconds"];
    let Some(object) = body.as_object() else {
        return Err(invalid("request"));
    };
    if let Some(key) = object.keys().find(|k| !TOP.contains(&k.as_str())) {
        return Err(invalid(key));
    }
    let op = object
        .get("peerbox")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("peerbox"))?;
    let name = op
        .get("op")
        .and_then(Value::as_str)
        .filter(|o| OPS.contains(o))
        .ok_or_else(|| invalid("op"))?;
    let (required, optional) = shape(name);
    for key in op.keys() {
        if key != "op" && !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(invalid(key));
        }
    }
    if let Some(key) = required.iter().find(|k| !op.contains_key(**k)) {
        return Err(invalid(key));
    }
    for (key, value) in op {
        let ok = match key.as_str() {
            "have" => value
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string)),
            "run" => value.is_object(),
            _ => value.is_string(),
        };
        if !ok {
            return Err(invalid(key));
        }
    }
    if let Some(run) = op.get("run").and_then(Value::as_object) {
        // A peerbox run's workspace is the commit's tree (Runs).
        if run.contains_key("workspace") {
            return Err(invalid("workspace"));
        }
        if let Some(key) = run.keys().find(|k| !RUN.contains(&k.as_str())) {
            return Err(invalid(&format!("run.{key}")));
        }
        if let Some(res) = run.get("resources").and_then(Value::as_object)
            && let Some(key) = res.keys().find(|k| !RESOURCES.contains(&k.as_str()))
        {
            return Err(invalid(&format!("resources.{key}")));
        }
    }
    Ok(())
}

/// The request rules of a peerbox task (Requests).
pub(crate) fn validate(r: &TaskRequest) -> Result<(), Error> {
    if !crate::peer_store::valid_id(&r.task_id, "task", 16) {
        return Err(invalid("task_id"));
    }
    if !r.target_agent_id.is_empty() {
        return Err(invalid("target_agent_id"));
    }
    if r.grant_id.is_some() {
        return Err(invalid("grant_id"));
    }
    if r.delegation.is_some() {
        return Err(invalid("delegation"));
    }
    if r.self_access.is_some() {
        return Err(invalid("self"));
    }
    if r.run.is_some() {
        return Err(invalid("run"));
    }
    if r.policy.is_none() {
        return Err(invalid("policy"));
    }
    if r.origin.as_ref().is_some_and(|o| !o.valid()) {
        return Err(invalid("origin"));
    }
    if r.input.is_empty() || r.input.len() > crate::task::MAX_TEXT {
        return Err(invalid("input"));
    }
    chrono::DateTime::parse_from_rfc3339(&r.deadline).map_err(|_| invalid("deadline"))?;
    if let Some(manifest) = &r.artifacts {
        crate::artifact::validate_manifest(manifest).map_err(|_| invalid("artifacts"))?;
    }
    let p = r.peerbox.as_ref().ok_or_else(|| invalid("peerbox"))?;
    if !OPS.contains(&p.op.as_str()) {
        return Err(invalid("op"));
    }
    let (required, optional) = shape(&p.op);
    let present = [
        ("peerbox_id", p.peerbox_id.is_some()),
        ("after", p.after.is_some()),
        ("have", p.have.is_some()),
        ("base", p.base.is_some()),
        ("branch", p.branch.is_some()),
        ("bundle", p.bundle.is_some()),
        ("contribution_id", p.contribution_id.is_some()),
        ("before", p.before.is_some()),
        ("commit", p.commit.is_some()),
        ("run", p.run.is_some()),
    ];
    for (name, given) in present {
        let allowed = required.contains(&name) || optional.contains(&name);
        if given != required.contains(&name) && !(given && allowed) {
            return Err(invalid(name));
        }
    }
    if p.peerbox_id.as_deref().is_some_and(|id| !peerbox_id(id)) {
        return Err(invalid("peerbox_id"));
    }
    if p.after.as_deref().is_some_and(|id| !peerbox_id(id)) {
        return Err(invalid("after"));
    }
    if let Some(have) = &p.have {
        let mut sorted: Vec<&String> = have.iter().collect();
        sorted.sort();
        if have.len() > MAX_HAVE
            || have.iter().any(|c| !commit_id(c))
            || sorted.windows(2).any(|w| w[0] == w[1])
        {
            return Err(invalid("have"));
        }
    }
    for (name, value) in [("base", &p.base), ("commit", &p.commit)] {
        if value.as_deref().is_some_and(|c| !commit_id(c)) {
            return Err(invalid(name));
        }
    }
    if p.branch.as_deref().is_some_and(|b| !valid_branch(b)) {
        return Err(invalid("branch"));
    }
    if let Some(bundle) = &p.bundle {
        let listed = r
            .artifacts
            .iter()
            .flatten()
            .any(|e| e.sha256 == *bundle && e.media_type == BUNDLE_TYPE);
        if !crate::artifact::valid_digest(bundle) || !listed {
            return Err(invalid("bundle"));
        }
    }
    if p.contribution_id.is_some() && p.before.is_some() {
        return Err(invalid("before"));
    }
    for (name, value) in [
        ("contribution_id", &p.contribution_id),
        ("before", &p.before),
    ] {
        if value.as_deref().is_some_and(|c| !contribution_id(c)) {
            return Err(invalid(name));
        }
    }
    if let Some(run) = &p.run {
        if run.workspace.is_some() {
            return Err(invalid("workspace"));
        }
        crate::runtime_task::validate_run(run, &r.artifacts)?;
    }
    Ok(())
}

/// What a sender may do on one peerbox: the union of the actions of the
/// rules it matches, and for each action the largest bound among the
/// matching rules that grant it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Access {
    actions: Vec<&'static str>,
    read_bytes: i64,
    submit_bytes: i64,
    max_pending: i64,
}
impl Access {
    fn has(&self, action: &str) -> bool {
        self.actions.contains(&action)
    }
    fn add(&mut self, rule: &crate::policy::PeerboxRule) {
        for action in PEERBOX_ACTIONS {
            if rule.has(action) && !self.actions.contains(&action) {
                self.actions.push(action);
            }
        }
        self.actions
            .sort_by_key(|a| PEERBOX_ACTIONS.iter().position(|k| k == a));
        if rule.has(PEERBOX_READ) {
            self.read_bytes = self.read_bytes.max(rule.max_bundle_bytes);
        }
        if rule.has(PEERBOX_SUBMIT) {
            self.submit_bytes = self.submit_bytes.max(rule.max_bundle_bytes);
            self.max_pending = self.max_pending.max(rule.max_pending);
        }
    }
}

/// The sender's access to this host's peerboxes under the cited policy,
/// keyed by (network, peerbox), and its membership per network.
#[derive(Default)]
struct Grants {
    access: BTreeMap<(String, String), Access>,
    members: BTreeMap<String, Member>,
    unavailable: Option<&'static str>,
}

/// Matches the sender against the peerbox rules of the cited policy, as
/// runtime rules are matched: the cited person is this host's owner in a
/// coordinator-free network both hosts share, the deadline is within the
/// policy's `valid_until`, and membership is current unless the rule
/// allows disconnected senders (Checks 1).
fn grants(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &TaskRequest,
) -> Result<Grants, Error> {
    let mut out = Grants::default();
    let cited: &PolicyRef = r.policy.as_ref().ok_or_else(|| invalid("policy"))?;
    let me = store.identity().id;
    if store.blocked(conn, sender)? {
        return Ok(out);
    }
    let networks: Vec<String> = store
        .own_members(conn)?
        .into_iter()
        .filter(|(_, m)| m.person_id.as_deref() == Some(cited.person_id.as_str()))
        .map(|(n, _)| n)
        .collect();
    let mut connected: Option<bool> = None;
    for network in networks {
        if !crate::decentralized::product::is_decentralized(conn, &network)? {
            continue;
        }
        let current = store
            .product_member(conn, &network, sender)?
            .filter(|m| m.host_id != me);
        let is_current = current.is_some();
        let sender_member = match current {
            Some(m) => m,
            None => match store
                .product_lapsed_member(conn, &network, sender)?
                .filter(|m| m.host_id != me)
            {
                Some(m) => m,
                None => continue,
            },
        };
        out.members.insert(network.clone(), sender_member.clone());
        let Some(key) = store.product_person_key(conn, &network, &cited.person_id)? else {
            continue;
        };
        let Some(policy) = store.product_policy(conn, &network, &key)? else {
            out.unavailable = Some("this host has not yet received the cited policy");
            continue;
        };
        if policy.version < cited.version {
            out.unavailable = Some("this host has not yet received the cited policy version");
            continue;
        }
        if !policy.in_window(crate::clock::now())
            || crate::task::time(&r.deadline)? > crate::task::time(&policy.valid_until)?
        {
            continue;
        }
        let groups = store.product_groups(conn, &network)?;
        for rule in policy.peerbox_rules() {
            if rule.host != me
                || !(is_current || rule.allow_disconnected)
                || !rule.principals.iter().any(|p| {
                    crate::decentralized::product::principal_matches(
                        p,
                        &sender_member,
                        &groups,
                        r.origin.as_ref(),
                    )
                })
            {
                continue;
            }
            if !rule.allow_disconnected {
                let now_connected = match connected {
                    Some(c) => c,
                    None => {
                        let c = crate::decentralized::peer::current_connected(conn, store, sender)?;
                        connected = Some(c);
                        c
                    }
                };
                if !now_connected {
                    continue;
                }
            }
            out.access
                .entry((network.clone(), rule.peerbox.clone()))
                .or_default()
                .add(rule);
        }
    }
    Ok(out)
}

/// Whether the sender's person submitted contributions to a peerbox (the
/// `status` exception of Checks 1).
fn contributed(conn: &Connection, peerbox: &str, member: &Member) -> Result<bool, Error> {
    let Some(person) = &member.person_id else {
        return Ok(false);
    };
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM peerbox_contributions WHERE peerbox_id = ?1 AND json_extract(record, '$.contributor.person_id') = ?2)",
        params![peerbox, person],
        |r| r.get(0),
    )?)
}

/// What the checks found for one operation.
struct Checked {
    /// The peerbox, for every operation but `list`.
    record: Option<Record>,
    access: Access,
    grants: Grants,
}

/// Checks 1 to 3 (Checks), in order: 404 `unknown`, then 403.
fn check(
    store: &Store,
    conn: &Connection,
    sender: &str,
    r: &TaskRequest,
) -> Result<Checked, Error> {
    let p = r.peerbox.as_ref().ok_or_else(|| invalid("peerbox"))?;
    let grants = grants(store, conn, sender, r)?;
    let Some(id) = p.peerbox_id.as_deref() else {
        return Ok(Checked {
            record: None,
            access: Access::default(),
            grants,
        });
    };
    let found = crate::peerbox::record(conn, id)?;
    let access = found
        .as_ref()
        .and_then(|rec| grants.access.get(&(rec.network_id.clone(), id.to_owned())))
        .filter(|a| a.has(PEERBOX_READ))
        .cloned();
    let exception = match (&found, &access) {
        (Some(rec), None) if p.op == "status" => match grants.members.get(&rec.network_id) {
            Some(member) => contributed(conn, id, member)?,
            None => false,
        },
        _ => false,
    };
    let Some(rec) = found.filter(|_| access.is_some() || exception) else {
        return Err(match grants.unavailable {
            Some(m) => Error::Unavailable(m.into()),
            None => unknown(),
        });
    };
    let access = access.unwrap_or_default();
    let needed = match p.op.as_str() {
        "submit" | "withdraw" => Some(PEERBOX_SUBMIT),
        "run" => Some(PEERBOX_RUN),
        _ => None,
    };
    if needed.is_some_and(|a| !access.has(a)) {
        return Err(Error::Forbidden);
    }
    if p.op == "submit" {
        let size = r
            .artifacts
            .iter()
            .flatten()
            .find(|e| Some(&e.sha256) == p.bundle.as_ref())
            .map_or(0, |e| e.size);
        if size > access.submit_bytes {
            return Err(Error::Forbidden);
        }
    }
    Ok(Checked {
        record: Some(rec),
        access,
        grants,
    })
}

/// A commit ID of the other object format is 400 (Peerboxes and
/// contributions), known once the peerbox is.
fn check_lengths(store: &Store, rec: &Record, p: &PeerboxOp) -> Result<(), Error> {
    let mut ids: Vec<(&str, &String)> = Vec::new();
    for c in p.have.iter().flatten() {
        ids.push(("have", c));
    }
    for (name, value) in [("base", &p.base), ("commit", &p.commit)] {
        if let Some(c) = value {
            ids.push((name, c));
        }
    }
    if ids.is_empty() {
        return Ok(());
    }
    let Ok(git) = Git::new(store.state_directory()) else {
        return Ok(());
    };
    let Ok(length) = git.id_length(Path::new(&rec.repository)) else {
        return Ok(());
    };
    match ids.iter().find(|(_, c)| c.len() != length) {
        Some((name, _)) => Err(invalid(name)),
        None => Ok(()),
    }
}

/// Accepts a peerbox task as `queued`, idempotently by sender and task ID.
pub(crate) fn accept(store: &Store, sender: &str, r: TaskRequest) -> Result<TaskStatus, Error> {
    validate(&r)?;
    let mut connection = store.connection()?;
    let tx = connection.transaction()?;
    let checked = check(store, &tx, sender, &r)?;
    if let (Some(rec), Some(p)) = (&checked.record, &r.peerbox) {
        check_lengths(store, rec, p)?;
    }
    // Checks 4: a run is also everything a runtime task's checks are, with
    // the request's `run` in place of a runtime task's.
    let runtime_rule = match r.peerbox.as_ref().and_then(|p| p.run.as_ref()) {
        Some(run) if r.is_peerbox_run() => Some(crate::runtime_task::authorize_run(
            store, &tx, sender, &r, run,
        )?),
        _ => None,
    };
    if let Some((old, mut status)) = received(&tx, sender, &r.task_id)? {
        if old != r {
            return Err(Error::Conflict(
                "task ID reused with different fields".into(),
            ));
        }
        if crate::task::expire(&tx, sender, &old, &mut status)? {
            tx.commit()?;
        }
        return Ok(status);
    }
    // A new task's deadline is in the future at the receiver, refused as
    // the task routes refuse it for agent tasks.
    if crate::task::time(&r.deadline)? <= crate::clock::now() {
        return Err(Error::Forbidden);
    }
    if let Some(manifest) = &r.artifacts {
        store.reserve(&tx, manifest)?;
    }
    let at = now();
    let mut status = TaskStatus {
        task_id: r.task_id.clone(),
        sender_host_id: sender.into(),
        receiver_host_id: store.identity().id,
        executor: Some(EXECUTOR.into()),
        target_agent_id: String::new(),
        state: "queued".into(),
        cancel_requested: false,
        created_at: at.clone(),
        updated_at: at,
        last_event: 0,
    };
    tx.execute(
        "INSERT INTO received_tasks VALUES (?1, ?2, ?3, ?4)",
        params![
            sender,
            r.task_id,
            serde_json::to_string(&r)?,
            serde_json::to_string(&status)?
        ],
    )?;
    if let Some(rule) = runtime_rule {
        crate::runtime_task::mark_peerbox_run(&tx, sender, &r.task_id, rule)?;
    }
    record(&tx, sender, &mut status, "queued", None, None, None)?;
    if let Some(manifest) = &r.artifacts {
        crate::artifact::add_artifacts(
            &tx,
            RECEIVED,
            sender,
            &r.task_id,
            crate::artifact::INPUT,
            manifest,
            crate::artifact::PENDING,
        )?;
    }
    tx.commit()?;
    store.peerbox_wake.notify_one();
    Ok(status)
}

/// A cancellation request just recorded: a queued peerbox operation ends
/// `cancelled` at once.
pub(crate) fn cancel_requested(
    tx: &rusqlite::Transaction<'_>,
    sender: &str,
    status: &mut TaskStatus,
) -> Result<(), Error> {
    if status.state == "queued" {
        record(tx, sender, status, "cancelled", None, None, None)?;
    }
    Ok(())
}

/// Queued peerbox tasks, in `created_at` order.
fn queued(conn: &Connection) -> Result<Vec<(String, String)>, Error> {
    let mut statement = conn.prepare(
        "SELECT sender, task_id FROM received_tasks WHERE json_extract(request, '$.executor') = 'peerbox' AND json_extract(record, '$.state') = 'queued' AND COALESCE(json_extract(record, '$.peerbox_run'), 0) = 0 ORDER BY json_extract(record, '$.created_at'), rowid",
    )?;
    statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

/// Serves queued peerbox tasks until shutdown.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if let Err(e) = pass(&store).await {
            eprintln!("peerbox tasks: {e:?}");
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = store.peerbox_wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

async fn pass(store: &Arc<Store>) -> Result<(), Error> {
    crate::api::blocking(store.clone(), sweep_archives).await?;
    let tasks = crate::api::blocking(store.clone(), |s| queued(&*s.connection()?)).await?;
    for (sender, id) in tasks {
        crate::api::blocking(store.clone(), move |s| serve(s, &sender, &id)).await?;
    }
    Ok(())
}

/// What an operation ends with.
enum Outcome {
    Succeeded {
        output: Value,
        artifact: Option<ArtifactEntry>,
        activity: Option<(&'static str, String)>,
    },
    Failed(Failure),
}

/// Rechecks one queued task and runs its operation (Checks: again before
/// a bundle is served).
fn serve(store: &Store, sender: &str, id: &str) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let Some((request, mut status)) = received(&tx, sender, id)? else {
        return Ok(());
    };
    // A task still queued at its deadline ends `expired` and serves
    // nothing (task contract).
    if crate::task::expire(&tx, sender, &request, &mut status)? {
        tx.commit()?;
        return Ok(());
    }
    drop(tx);
    if status.state != "queued" || status.cancel_requested {
        return Ok(());
    }
    let checked = match check(store, &conn, sender, &request) {
        Ok(c) => c,
        // Recoverable: left queued.
        Err(Error::Unavailable(_)) => return Ok(()),
        Err(e) => {
            drop(conn);
            let reason = match e {
                Error::Forbidden => "the peerbox rule no longer allows this operation".to_owned(),
                _ => "the sender may no longer read this peerbox".to_owned(),
            };
            return finish(
                store,
                sender,
                id,
                "rejected",
                Some(reason),
                None,
                None,
                None,
            );
        }
    };
    drop(conn);
    let Some(p) = request.peerbox.clone() else {
        return Ok(());
    };
    let outcome = match p.op.as_str() {
        "list" => list(store, &checked, p.after.as_deref()),
        "fetch" => fetch(store, &checked, &p, sender),
        "run" => match prepare_run(store, &checked, &request, sender) {
            Ok(()) => return Ok(()),
            Err(Prepared::Failed(f)) => Outcome::Failed(f),
            Err(Prepared::Error(e)) => return Err(e),
            Err(Prepared::Rejected(reason)) => {
                return finish(
                    store,
                    sender,
                    id,
                    "rejected",
                    Some(reason),
                    None,
                    None,
                    None,
                );
            }
        },
        other => Outcome::Failed(Failure::new(
            NOT_IMPLEMENTED,
            format!("peerbox {other} is not implemented on this host yet"),
        )),
    };
    match outcome {
        Outcome::Succeeded {
            output,
            artifact,
            activity,
        } => finish(
            store,
            sender,
            id,
            "succeeded",
            None,
            Some(output.to_string()),
            artifact.map(|a| vec![a]),
            activity,
        ),
        Outcome::Failed(f) => finish(
            store,
            sender,
            id,
            "failed",
            None,
            Some(f.output()),
            None,
            None,
        ),
    }
}

/// Ends a task with `kind`, its output and result artifacts, unless it is
/// final already.
#[allow(clippy::too_many_arguments)]
fn finish(
    store: &Store,
    sender: &str,
    id: &str,
    kind: &str,
    message: Option<String>,
    output: Option<String>,
    artifacts: Option<Vec<ArtifactEntry>>,
    activity: Option<(&'static str, String)>,
) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let Some((_, mut status)) = received(&tx, sender, id)? else {
        return Ok(());
    };
    if is_final(&status.state) {
        return Ok(());
    }
    let kind = if status.cancel_requested {
        "cancelled"
    } else {
        kind
    };
    let (output, artifacts) = if kind == "cancelled" {
        (None, None)
    } else {
        (output, artifacts)
    };
    record(
        &tx,
        sender,
        &mut status,
        kind,
        message,
        output,
        artifacts.clone(),
    )?;
    if let Some(results) = &artifacts {
        crate::artifact::add_artifacts(&tx, RECEIVED, sender, id, RESULT, results, STORED)?;
    }
    if kind != "cancelled"
        && let Some((activity, subject)) = activity
    {
        append_event(&tx, activity, &subject, &now())?;
    }
    tx.commit()?;
    Ok(())
}

/// One `peerboxes` entry (Results), with its keys in the contract's order.
#[derive(Serialize)]
struct Entry {
    peerbox_id: String,
    title: String,
    branch: String,
    head: Option<String>,
    actions: Vec<&'static str>,
}

/// `list`: the peerboxes the sender may read, in ascending ID order after
/// `after`, as many whole entries as fit one output.
fn list(store: &Store, checked: &Checked, after: Option<&str>) -> Outcome {
    let records = match store
        .connection()
        .map_err(|e| e.to_string())
        .and_then(|c| crate::peerbox::records(&c).map_err(|e| e.to_string()))
    {
        Ok(r) => r,
        Err(e) => return Outcome::Failed(Failure::new("internal", e)),
    };
    let readable: Vec<(Record, &Access)> = records
        .into_iter()
        .filter(|r| after.is_none_or(|a| r.peerbox_id.as_str() > a))
        .filter_map(|r| {
            let a = checked
                .grants
                .access
                .get(&(r.network_id.clone(), r.peerbox_id.clone()))
                .filter(|a| a.has(PEERBOX_READ))?;
            Some((r, a))
        })
        .collect();
    let git = Git::new(store.state_directory()).ok();
    let mut heads: BTreeMap<(String, String), Option<String>> = BTreeMap::new();
    // `{"peerboxes":[` ... `],"next":` NEXT `}`
    let frame = r#"{"peerboxes":[],"next":}"#.len();
    let mut used = frame;
    let mut entries: Vec<String> = Vec::new();
    let mut next = None;
    for (i, (r, access)) in readable.iter().enumerate() {
        let head = heads
            .entry((r.repository.clone(), r.branch.clone()))
            .or_insert_with(|| {
                git.as_ref()
                    .and_then(|g| g.head(Path::new(&r.repository), &r.branch).ok().flatten())
            })
            .clone();
        let entry = Entry {
            peerbox_id: r.peerbox_id.clone(),
            title: r.title.clone(),
            branch: r.branch.clone(),
            head,
            actions: access.actions.clone(),
        };
        let text = match serde_json::to_string(&entry) {
            Ok(t) => t,
            Err(e) => return Outcome::Failed(Failure::new("internal", e.to_string())),
        };
        let more = i + 1 < readable.len();
        let comma = usize::from(!entries.is_empty());
        // With more to come, `next` names this entry: its ID and quotes.
        let tail = if more { r.peerbox_id.len() + 2 } else { 4 };
        if used + comma + text.len() + tail > OUTPUT_LIMIT {
            next = entries.last().map(|_| readable[i - 1].0.peerbox_id.clone());
            break;
        }
        used += comma + text.len();
        entries.push(text);
    }
    let output = format!(
        r#"{{"peerboxes":[{}],"next":{}}}"#,
        entries.join(","),
        serde_json::to_string(&next).unwrap_or_else(|_| "null".into())
    );
    match serde_json::from_str(&output) {
        Ok(value) => Outcome::Succeeded {
            output: value,
            artifact: None,
            activity: None,
        },
        Err(e) => Outcome::Failed(Failure::new("internal", e.to_string())),
    }
}

/// The fetch result (Results), with its keys in the contract's order.
#[derive(Serialize)]
struct Fetched {
    head: String,
    bundle_sha256: Option<String>,
    size: i64,
}

/// `fetch` (Fetch): a bundle of the protected branch at its head, without
/// the history of the `have` commits reachable from it.
fn fetch(store: &Store, checked: &Checked, p: &PeerboxOp, sender: &str) -> Outcome {
    match fetch_inner(store, checked, p, sender) {
        Ok(o) => o,
        Err(f) => Outcome::Failed(f),
    }
}
fn fetch_inner(
    store: &Store,
    checked: &Checked,
    p: &PeerboxOp,
    sender: &str,
) -> Result<Outcome, Failure> {
    let rec = checked
        .record
        .as_ref()
        .ok_or_else(|| Failure::new("unknown", "unknown peerbox"))?;
    let git = Git::new(store.state_directory())?;
    let repo = PathBuf::from(&rec.repository);
    let head = git.head(&repo, &rec.branch)?.ok_or_else(|| {
        Failure::new(
            "unavailable",
            format!("the protected branch {} has no head", rec.branch),
        )
    })?;
    let have = p.have.clone().unwrap_or_default();
    let fetched = |head: String, sha: Option<String>, size: i64| -> Result<Value, Failure> {
        serde_json::to_value(Fetched {
            head,
            bundle_sha256: sha,
            size,
        })
        .map_err(|e| Failure::new("internal", e.to_string()))
    };
    let activity = Some(("peerbox.fetched", format!("{}/{sender}", rec.peerbox_id)));
    if have.contains(&head) {
        return Ok(Outcome::Succeeded {
            output: fetched(head, None, 0)?,
            artifact: None,
            activity,
        });
    }
    // Only `have` commits reachable from the head shorten the bundle; any
    // other ID is ignored, so the bundle reveals nothing outside the branch.
    let mut keep = Vec::new();
    for c in &have {
        if git.reachable(&repo, c, &head)? {
            keep.push(c.clone());
        }
    }
    let dir = store.artifact_dir();
    let temp = dir.join(
        crate::store::new_id("partial").map_err(|e| Failure::new("internal", e.to_string()))?,
    );
    let result = (|| {
        let bundled = git.bundle(&repo, &rec.branch, &keep, &temp)?;
        let (sha, size) = crate::peerbox::digest_file(&temp)
            .map_err(|e| Failure::new("internal", e.to_string()))?;
        let bound = checked.access.read_bytes.min(MAX_FILE);
        if size > bound {
            return Err(Failure::new(
                "too_large",
                format!("the bundle is {size} bytes, over the bound of {bound} bytes"),
            ));
        }
        Ok((bundled, sha, size))
    })();
    let (bundled, sha, size) = match result {
        Ok(v) => v,
        Err(f) => {
            let _ = std::fs::remove_file(&temp);
            return Err(f);
        }
    };
    let entry = store
        .finish_upload(
            temp,
            size,
            sha.clone(),
            "peerbox.bundle".into(),
            BUNDLE_TYPE.into(),
        )
        .map_err(|e| Failure::new("unavailable", e.to_string()))?;
    Ok(Outcome::Succeeded {
        output: fetched(bundled, Some(sha), size)?,
        artifact: Some(entry),
        activity,
    })
}

// ---------------------------------------------------------------------
// Runs (Runs; Withdrawal).

/// Why a run was not handed to the runtime.
enum Prepared {
    /// A final `failed` outcome before any run.
    Failed(Failure),
    /// The recheck failed for good.
    Rejected(String),
    /// Left as it is: recoverable, or a host error.
    Error(Error),
}
impl From<Error> for Prepared {
    fn from(e: Error) -> Self {
        Self::Error(e)
    }
}
impl From<rusqlite::Error> for Prepared {
    fn from(e: rusqlite::Error) -> Self {
        Self::Error(e.into())
    }
}

/// The directory of the workspace archives of peerbox runs.
fn archive_dir(store: &Store) -> PathBuf {
    store.state_directory().join("peerbox-runs")
}

/// `run` before the runtime (Runs): the runtime rule's current bounds, the
/// runnable-commit rule, and the workspace archive built from the commit's
/// tree within `max_artifact_bytes`. Then the task is the runtime
/// worker's, which follows the runtime task contract from its queue on.
fn prepare_run(
    store: &Store,
    checked: &Checked,
    request: &TaskRequest,
    sender: &str,
) -> Result<(), Prepared> {
    let rec = checked
        .record
        .as_ref()
        .ok_or_else(|| Prepared::Failed(Failure::new("unknown", "unknown peerbox")))?;
    let commit = request
        .peerbox
        .as_ref()
        .and_then(|p| p.commit.clone())
        .ok_or_else(|| Prepared::Error(invalid("commit")))?;
    // A run still queued at its deadline ends `expired` before any
    // workspace is built or start sent, as a runtime task does.
    {
        let mut conn = store.connection()?;
        let tx = conn.transaction()?;
        let Some((stored, mut status)) = received(&tx, sender, &request.task_id)? else {
            return Ok(());
        };
        if crate::task::expire(&tx, sender, &stored, &mut status)? {
            tx.commit()?;
            return Ok(());
        }
    }
    let rule = {
        let conn = store.connection()?;
        match recheck_run(store, &conn, sender, request) {
            Ok((rule, _)) => rule,
            Err(Error::Unavailable(_)) => return Ok(()),
            Err(Error::Coded { message, .. }) => return Err(Prepared::Rejected(message)),
            Err(e) => return Err(Prepared::Error(e)),
        }
    };
    let git = Git::new(store.state_directory()).map_err(Prepared::Failed)?;
    let person = checked
        .grants
        .members
        .get(&rec.network_id)
        .and_then(|m| m.person_id.clone());
    {
        let conn = store.connection()?;
        crate::peerbox::runnable_commit(&git, &conn, rec, person.as_deref(), &commit)
            .map_err(Prepared::Failed)?;
    }
    use std::os::unix::fs::DirBuilderExt;
    let dir = archive_dir(store);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Prepared::Error(Error::Internal(e.into())))?;
    let path = dir.join(format!("{sender}-{}.tar", request.task_id));
    let _ = std::fs::remove_file(&path);
    if let Err(f) = crate::peerbox::workspace_archive(
        &git,
        Path::new(&rec.repository),
        &commit,
        &path,
        rule.max_artifact_bytes,
    ) {
        let _ = std::fs::remove_file(&path);
        return Err(Prepared::Failed(f));
    }
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let still = received(&tx, sender, &request.task_id)?
        .is_some_and(|(_, status)| status.state == "queued" && !status.cancel_requested);
    if !still {
        drop(tx);
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let created_at = received(&tx, sender, &request.task_id)?
        .map(|(_, status)| status.created_at)
        .unwrap_or_else(now);
    crate::peerbox::record_run(&tx, &rec.peerbox_id, &commit, &request.task_id, &created_at)?;
    crate::runtime_task::peerbox_run_ready(&tx, sender, &request.task_id, path)?;
    tx.commit()?;
    store.runtime_wake.notify_one();
    Ok(())
}

/// The checks before a peerbox run starts: Checks 1 and 2 again, then the
/// runtime task contract's (Checks 4). Returns the runtime rule and the
/// owner's policy version it holds under. A final failure is a coded
/// refusal whose message is the reason; `Unavailable` can recover.
pub(crate) fn recheck_run(
    store: &Store,
    conn: &Connection,
    sender: &str,
    request: &TaskRequest,
) -> Result<(crate::policy::RuntimeRule, u64), Error> {
    let refused = |message: &str| Error::Coded {
        status: 403,
        code: "forbidden",
        message: message.into(),
        extra: Default::default(),
    };
    let checked = match check(store, conn, sender, request) {
        Ok(c) => c,
        Err(Error::Unavailable(m)) => return Err(Error::Unavailable(m)),
        Err(Error::Forbidden) => {
            return Err(refused("the peerbox rule no longer allows this operation"));
        }
        Err(_) => return Err(refused("the sender may no longer read this peerbox")),
    };
    let run = request
        .peerbox
        .as_ref()
        .and_then(|p| p.run.as_ref())
        .ok_or_else(|| invalid("run"))?;
    let rule = match crate::runtime_task::authorize_run(store, conn, sender, request, run) {
        Ok(rule) => rule,
        Err(Error::Unavailable(m)) => return Err(Error::Unavailable(m)),
        Err(Error::Coded { message, .. }) => return Err(refused(&message)),
        Err(_) => return Err(refused(crate::task::LAPSED)),
    };
    let version = match &checked.record {
        Some(rec) => owner_policy(store, conn, &rec.network_id, request)?.map_or(0, |p| p.version),
        None => 0,
    };
    Ok((rule, version))
}

/// The home host's stored policy of the cited person in `network`.
fn owner_policy(
    store: &Store,
    conn: &Connection,
    network: &str,
    request: &TaskRequest,
) -> Result<Option<crate::decentralized::product::Policy>, Error> {
    let Some(cited) = &request.policy else {
        return Ok(None);
    };
    let Some(key) = store.product_person_key(conn, network, &cited.person_id)? else {
        return Ok(None);
    };
    Ok(store.product_policy(conn, network, &key)?)
}

/// Whether a started peerbox run's sender no longer matches `peerbox.run`
/// under a policy version the home host stored since the run was
/// dispatched (Withdrawal, PBX-4). Only the rule counts: a policy lapsing,
/// a ban, a lapsed membership or a runtime rule's withdrawal does not.
pub(crate) fn run_withdrawn(store: &Store, sender: &str, id: &str) -> Result<bool, Error> {
    let conn = store.connection()?;
    let Some(dispatched) = crate::runtime_task::dispatched_policy_version(&conn, sender, id)?
    else {
        return Ok(false);
    };
    let Some((request, _)) = received(&conn, sender, id)? else {
        return Ok(false);
    };
    let Some(pbx) = request.peerbox.as_ref().and_then(|p| p.peerbox_id.clone()) else {
        return Ok(false);
    };
    let Some(rec) = crate::peerbox::record(&conn, &pbx)? else {
        // A deleted peerbox has no rules left.
        return Ok(true);
    };
    let Some(policy) = owner_policy(store, &conn, &rec.network_id, &request)? else {
        return Ok(false);
    };
    if policy.version <= dispatched {
        return Ok(false);
    }
    let me = store.identity().id;
    let member = match store.product_member(&conn, &rec.network_id, sender)? {
        Some(m) => m,
        None => match store.product_lapsed_member(&conn, &rec.network_id, sender)? {
            Some(m) => m,
            None => return Ok(false),
        },
    };
    let groups = store.product_groups(&conn, &rec.network_id)?;
    let matches = policy.peerbox_rules().iter().any(|rule| {
        rule.host == me
            && rule.peerbox == pbx
            && rule.has(PEERBOX_RUN)
            && rule.principals.iter().any(|p| {
                crate::decentralized::product::principal_matches(
                    p,
                    &member,
                    &groups,
                    request.origin.as_ref(),
                )
            })
    });
    Ok(!matches)
}

/// Removes the archives of runs that are final or unknown.
fn sweep_archives(store: &Store) -> Result<(), Error> {
    let Ok(entries) = std::fs::read_dir(archive_dir(store)) else {
        return Ok(());
    };
    let conn = store.connection()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((sender, id)) = name.strip_suffix(".tar").and_then(|n| n.split_once('-')) else {
            continue;
        };
        let keep = received(&conn, sender, id)?.is_some_and(|(_, status)| !is_final(&status.state));
        if !keep {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}
