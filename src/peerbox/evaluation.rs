//! Gate evaluations (peerbox contract, Gates: Evaluation, Fresh episodes,
//! Result line, Verdict): the home host's queue, one evaluation at a time,
//! each measurement a linked pair on its own runtime (runtime task
//! contract, Linked runs), the verdict and the gate's decision.
use super::{
    Git, Record,
    contribution::{self, Contribution, PENDING},
    gate::{self, Frontier, Gate, number},
};
use crate::{
    model::Error,
    runtime::call,
    store::{Store, append_event, new_id, now},
};
use base64::Engine;
use hyper::Method;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// A result line's bound (Result line).
const MAX_LINE: usize = 262_144;
/// The stdout tail kept of an environment or check run.
const TAIL: usize = MAX_LINE + 4096;
/// How long after a pair's timeout the host waits for its runs to end.
const GRACE: Duration = Duration::from_secs(15);

/// One run of an evaluation (What `gate show` returns: `runs`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunEntry {
    pub task_id: String,
    pub side: String,
    pub kind: String,
    pub outcome: String,
    /// The runtime's run ID and socket, never shown.
    pub run_id: String,
    pub socket: PathBuf,
}

/// An evaluation as stored.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub evaluation_id: String,
    pub peerbox_id: String,
    pub contribution_id: String,
    pub gate_version: i64,
    pub secret: String,
    pub secret_sha256: String,
    pub frontier: String,
    pub started_at: String,
    pub decided_at: Option<String>,
    pub result: Option<Value>,
    pub runs: Vec<RunEntry>,
    /// `running` until it decides (`decided`) or ends without a decision
    /// (`ended`); never shown.
    pub state: String,
    /// Runs still to cancel and delete on the runtime.
    #[serde(default)]
    pub cleanup: bool,
}

impl Evaluation {
    fn view(&self) -> Value {
        json!({
            "evaluation_id": self.evaluation_id,
            "contribution_id": self.contribution_id,
            "gate_version": self.gate_version,
            "secret": self.secret,
            "secret_sha256": self.secret_sha256,
            "frontier": self.frontier,
            "started_at": self.started_at,
            "decided_at": self.decided_at,
            "result": self.result,
            "runs": self.runs.iter().map(|r| json!({
                "task_id": r.task_id, "side": r.side, "kind": r.kind, "outcome": r.outcome,
            })).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------
// Storage.

fn all(conn: &Connection, sql: &str, p: impl rusqlite::Params) -> Result<Vec<Evaluation>, Error> {
    let mut s = conn.prepare(sql)?;
    let rows = s
        .query_map(p, |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .collect()
}
fn save(conn: &Connection, e: &Evaluation) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO peerbox_gate_evaluations VALUES (?1, ?2, ?3) ON CONFLICT(evaluation_id) DO UPDATE SET record = ?3",
        params![e.evaluation_id, e.peerbox_id, serde_json::to_string(e)?],
    )?;
    Ok(())
}
fn load(conn: &Connection, id: &str) -> Result<Option<Evaluation>, Error> {
    Ok(all(
        conn,
        "SELECT record FROM peerbox_gate_evaluations WHERE evaluation_id = ?1",
        [id],
    )?
    .pop())
}
/// The running evaluation of a peerbox, if any.
pub(crate) fn running(conn: &Connection, peerbox: &str) -> Result<Option<Evaluation>, Error> {
    Ok(all(
        conn,
        "SELECT record FROM peerbox_gate_evaluations WHERE peerbox_id = ?1 AND json_extract(record, '$.state') = 'running'",
        [peerbox],
    )?
    .pop())
}
/// The latest evaluations, newest first, as `gate show` lists them.
pub(crate) fn shown(conn: &Connection, peerbox: &str) -> Result<Vec<Value>, Error> {
    Ok(all(
        conn,
        "SELECT record FROM peerbox_gate_evaluations WHERE peerbox_id = ?1 ORDER BY rowid DESC LIMIT ?2",
        params![peerbox, gate::EVALUATIONS_KEPT as i64],
    )?
    .iter()
    .map(Evaluation::view)
    .collect())
}
/// Keeps a peerbox's latest evaluations and those with runs to clean up.
fn prune(conn: &Connection, peerbox: &str) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM peerbox_gate_evaluations WHERE peerbox_id = ?1 AND json_extract(record, '$.state') != 'running' AND COALESCE(json_extract(record, '$.cleanup'), 0) = 0 AND rowid NOT IN (SELECT rowid FROM peerbox_gate_evaluations WHERE peerbox_id = ?1 ORDER BY rowid DESC LIMIT ?2)",
        params![peerbox, gate::EVALUATIONS_KEPT as i64],
    )?;
    Ok(())
}
fn update(store: &Store, id: &str, f: impl FnOnce(&mut Evaluation)) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    if let Some(mut e) = load(&tx, id)? {
        f(&mut e);
        save(&tx, &e)?;
    }
    tx.commit()?;
    Ok(())
}

async fn run_blocking<T: Send + 'static>(
    store: &Arc<Store>,
    f: impl FnOnce(&Store) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    crate::api::blocking(store.clone(), f).await
}

