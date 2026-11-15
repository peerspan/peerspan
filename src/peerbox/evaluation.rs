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
    io::{Read, Write},
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
            // A pair the runtime refused never started; its runs stay
            // stored only until their cancellation is confirmed.
            "runs": self.runs.iter().filter(|r| r.outcome != "refused").map(|r| json!({
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
/// Ends a peerbox's running evaluation at once, for a cleared gate or, with
/// `contribution`, a decision by hand on the contribution it evaluates
/// (Evaluation; Gate CLI: clear): it ends undecided, its live runs are
/// marked cancelled and returned for the caller to cancel on the runtime,
/// and its own loop stops when it next looks. Takes the store's connection,
/// so the caller must not hold it.
pub(crate) fn stop_running(
    store: &Store,
    peerbox: &str,
    contribution: Option<&str>,
) -> Result<Vec<RunEntry>, Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    let Some(mut e) = running(&tx, peerbox)? else {
        return Ok(Vec::new());
    };
    if contribution.is_some_and(|c| c != e.contribution_id) {
        return Ok(Vec::new());
    }
    let live: Vec<RunEntry> = e
        .runs
        .iter()
        .filter(|r| r.outcome == "running" || r.outcome == "starting")
        .cloned()
        .collect();
    for r in &mut e.runs {
        if r.outcome == "running" || r.outcome == "starting" {
            r.outcome = "cancelled".into();
        }
    }
    e.state = "ended".into();
    e.cleanup = true;
    save(&tx, &e)?;
    tx.commit()?;
    Ok(live)
}

/// Asks the runtime to cancel each run; the worker deletes them later.
pub(crate) async fn cancel_runs(runs: &[RunEntry]) {
    for r in runs {
        let _ = call(
            &r.socket,
            Method::POST,
            &format!("/v1/runs/{}/cancel", r.run_id),
            Some(&json!({})),
        )
        .await;
    }
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

// ---------------------------------------------------------------------
// The worker.

/// Evaluates queued contributions one at a time until shutdown. At start,
/// an evaluation a restart interrupted ends undecided, and each run it had
/// started is cancelled before any new run starts.
pub async fn worker(store: Arc<Store>, mut shutdown: watch::Receiver<bool>) {
    if let Err(e) = run_blocking(&store, interrupted).await {
        eprintln!("peerbox gates: {e:?}");
    }
    loop {
        match clean_up(&store).await {
            Ok(true) => match run_blocking(&store, next).await {
                Ok(Some(job)) => {
                    if let Err(e) = evaluate(&store, job, &mut shutdown).await {
                        eprintln!("peerbox gate evaluation: {e:?}");
                    }
                }
                Ok(None) => {}
                Err(e) => eprintln!("peerbox gates: {e:?}"),
            },
            Ok(false) => {}
            Err(e) => eprintln!("peerbox gates: {e:?}"),
        }
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
}

fn interrupted(store: &Store) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    for mut e in all(
        &tx,
        "SELECT record FROM peerbox_gate_evaluations WHERE json_extract(record, '$.state') = 'running'",
        [],
    )? {
        e.state = "ended".into();
        e.cleanup = true;
        for r in &mut e.runs {
            if r.outcome == "running" || r.outcome == "starting" {
                r.outcome = "cancelled".into();
            }
        }
        save(&tx, &e)?;
    }
    tx.commit()?;
    Ok(())
}

/// Cancels and deletes the runs of evaluations marked for clean-up;
/// whether none is left.
async fn clean_up(store: &Arc<Store>) -> Result<bool, Error> {
    let pending = run_blocking(store, |s| {
        all(
            &*s.connection()?,
            "SELECT record FROM peerbox_gate_evaluations WHERE COALESCE(json_extract(record, '$.cleanup'), 0) = 1",
            [],
        )
    })
    .await?;
    let mut clean = true;
    for e in pending {
        let mut done = true;
        for r in &e.runs {
            if !remove_run(r).await {
                done = false;
            }
        }
        if done {
            let (id, peerbox) = (e.evaluation_id.clone(), e.peerbox_id.clone());
            run_blocking(store, move |s| {
                update(s, &id, |e| e.cleanup = false)?;
                // A deleted peerbox's evaluation was kept only for this.
                let conn = s.connection()?;
                if super::record(&conn, &peerbox)?.is_none() {
                    conn.execute(
                        "DELETE FROM peerbox_gate_evaluations WHERE evaluation_id = ?1",
                        [&id],
                    )?;
                }
                Ok(())
            })
            .await?;
        } else {
            clean = false;
        }
    }
    Ok(clean)
}

/// Cancels a run and deletes it; whether the runtime answered.
async fn remove_run(r: &RunEntry) -> bool {
    let path = format!("/v1/runs/{}", r.run_id);
    let cancelled = matches!(
        call(&r.socket, Method::POST, &format!("{path}/cancel"), Some(&json!({}))).await,
        Ok(a) if a.status == 200 || a.status == 404
    );
    let deleted = matches!(
        call(&r.socket, Method::DELETE, &path, None).await,
        Ok(a) if a.status == 200 || a.status == 404
    );
    cancelled && deleted
}

/// The next evaluation to start: the oldest queued contribution of the
/// first gated peerbox that is active, while the runtime's switch is on.
struct Job {
    peerbox: String,
    contribution: String,
}
fn next(store: &Store) -> Result<Option<Job>, Error> {
    if store.runtime_switch()?.is_none() {
        return Ok(None);
    }
    let conn = store.connection()?;
    for peerbox in gate::gated(&conn)? {
        let Some((_, g)) = gate::gated_record(&conn, &peerbox)? else {
            continue;
        };
        if g.paused_reason.is_some() || running(&conn, &peerbox)?.is_some() {
            continue;
        }
        if let Some(first) = gate::queue(&conn, &peerbox)?.into_iter().next() {
            return Ok(Some(Job {
                peerbox,
                contribution: first,
            }));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------
// One evaluation.

/// What a measurement found.
#[derive(Clone, Debug)]
enum Measured {
    Scored {
        score: f64,
        samples: Option<Vec<f64>>,
        reason: String,
    },
    Failed {
        code: &'static str,
        reason: Option<String>,
    },
}
/// Why an evaluation stopped before its verdict.
enum Stop {
    /// The contribution is no longer pending, or the gate was cleared or
    /// set again: its runs are cancelled and nothing is recorded.
    Cancelled,
    Shutdown,
    Error(Error),
}
impl From<Error> for Stop {
    fn from(e: Error) -> Self {
        Stop::Error(e)
    }
}

struct Context {
    store: Arc<Store>,
    rec: Record,
    gate: Gate,
    contribution: Contribution,
    evaluation: String,
    secret: String,
    secret_sha256: String,
    frontier: String,
    own: String,
    work: PathBuf,
}

fn random_bytes() -> Result<[u8; 32], Error> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
    Ok(b)
}

async fn evaluate(
    store: &Arc<Store>,
    job: Job,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), Error> {
    let store2 = store.clone();
    let started = run_blocking(store, move |s| begin(s, job, store2)).await?;
    let Some(ctx) = started else { return Ok(()) };
    let id = ctx.evaluation.clone();
    let outcome = measure_all(&ctx, shutdown).await;
    let _ = std::fs::remove_dir_all(&ctx.work);
    match outcome {
        // Every run of the evaluation is cancelled and deleted again
        // before the next one starts, so none is left on the runtime.
        Ok(()) => run_blocking(store, move |s| update(s, &id, |e| e.cleanup = true)).await,
        Err(Stop::Shutdown) => Ok(()),
        Err(Stop::Cancelled) => {
            let (peerbox, gate) = (ctx.rec.peerbox_id.clone(), ctx.gate.clone());
            run_blocking(store, move |s| {
                update(s, &id, |e| {
                    e.state = "ended".into();
                    e.cleanup = true;
                })?;
                // A gate cleared during the evaluation leaves its snapshots
                // to it.
                if gate::load(&*s.connection()?, &peerbox)?
                    .is_none_or(|g| g.version != gate.version)
                {
                    let (a, b) = gate.parts(s, &peerbox);
                    let _ = std::fs::remove_file(a);
                    let _ = std::fs::remove_file(b);
                }
                Ok(())
            })
            .await
        }
        Err(Stop::Error(err)) => {
            run_blocking(store, move |s| {
                update(s, &id, |e| {
                    e.state = "ended".into();
                    e.cleanup = true;
                })
            })
            .await?;
            Err(err)
        }
    }
}

/// Starts an evaluation of the job's contribution against the protected
/// head, with a new secret.
fn begin(store: &Store, job: Job, shared: Arc<Store>) -> Result<Option<Context>, Error> {
    let conn = store.connection()?;
    let Some((rec, g)) = gate::gated_record(&conn, &job.peerbox)? else {
        return Ok(None);
    };
    let Some(c) = contribution::load(&conn, &job.contribution)? else {
        return Ok(None);
    };
    if c.state != PENDING {
        return Ok(None);
    }
    drop(conn);
    let git = Git::new(store.state_directory()).map_err(super::coded)?;
    let Some(frontier) = git
        .head(Path::new(&rec.repository), &rec.branch)
        .map_err(super::coded)?
    else {
        return Ok(None);
    };
    let secret = random_bytes()?;
    let e = Evaluation {
        evaluation_id: new_id("pbe")?,
        peerbox_id: job.peerbox.clone(),
        contribution_id: c.contribution_id.clone(),
        gate_version: g.version,
        secret: hex::encode(secret),
        secret_sha256: hex::encode(Sha256::digest(secret)),
        frontier,
        started_at: now(),
        decided_at: None,
        result: None,
        runs: Vec::new(),
        state: "running".into(),
        cleanup: false,
    };
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    if running(&tx, &job.peerbox)?.is_some() {
        return Ok(None);
    }
    save(&tx, &e)?;
    prune(&tx, &job.peerbox)?;
    tx.commit()?;
    let work = store
        .state_directory()
        .join("peerbox-gate-runs")
        .join(&e.evaluation_id);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&work)
            .map_err(|e| Error::Internal(e.into()))?;
    }
    Ok(Some(Context {
        store: shared,
        rec,
        gate: g,
        contribution: c,
        evaluation: e.evaluation_id,
        secret: e.secret,
        secret_sha256: e.secret_sha256,
        frontier: e.frontier,
        own: store.identity().id,
        work,
    }))
}

/// Whether the evaluation may go on: its contribution still pending and
/// its gate version still set.
async fn going_on(ctx: &Context) -> Result<(), Stop> {
    let (peerbox, cid, version) = (
        ctx.rec.peerbox_id.clone(),
        ctx.contribution.contribution_id.clone(),
        ctx.gate.version,
    );
    let ok = run_blocking(&ctx.store, move |s| {
        let conn = s.connection()?;
        let pending = contribution::load(&conn, &cid)?.is_some_and(|c| c.state == PENDING);
        let same = gate::load(&conn, &peerbox)?.is_some_and(|g| g.version == version);
        Ok(pending && same)
    })
    .await?;
    if ok { Ok(()) } else { Err(Stop::Cancelled) }
}

/// The archive of a measured commit's tree, without `.peerbox-gate/`,
/// with an inputs part under `.peerbox-gate/inputs/`: the inputs snapshot,
/// or what the evaluation's generator made (Generator).
async fn tree_archive(
    ctx: &Context,
    commit: &str,
    name: &str,
    inputs: &Path,
) -> Result<Option<PathBuf>, Error> {
    let inputs = inputs.to_path_buf();
    let out = ctx.work.join(name);
    let (repo, commit) = (PathBuf::from(&ctx.rec.repository), commit.to_owned());
    run_blocking(&ctx.store, move |s| {
        let git = Git::new(s.state_directory()).map_err(super::coded)?;
        let _ = std::fs::remove_file(&out);
        match super::workspace_archive_with(
            &git,
            &repo,
            &commit,
            &out,
            super::MAX_FILE,
            Some(&inputs),
        ) {
            Ok(_) => Ok(Some(out)),
            Err(_) => {
                let _ = std::fs::remove_file(&out);
                Ok(None)
            }
        }
    })
    .await
}

/// The environment's archive: the checker snapshot and the secret.
fn environment_archive(checker: &Path, out: PathBuf, secret: &str) -> Result<PathBuf, Error> {
    let io = |e: std::io::Error| Error::Internal(e.into());
    let mut file = std::io::BufWriter::new(std::fs::File::create(&out).map_err(io)?);
    std::io::copy(&mut std::fs::File::open(checker).map_err(io)?, &mut file).map_err(io)?;
    let secret = format!("{secret}\n");
    crate::tar::entry(
        &mut file,
        b".peerbox-gate/",
        crate::tar::DIRECTORY,
        0o755,
        0,
        b"",
    )
    .map_err(io)?;
    crate::tar::entry(
        &mut file,
        b".peerbox-gate/secret",
        crate::tar::FILE,
        0o644,
        secret.len() as u64,
        b"",
    )
    .map_err(io)?;
    file.write_all(secret.as_bytes()).map_err(io)?;
    crate::tar::pad(&mut file, secret.len() as u64).map_err(io)?;
    crate::tar::end(&mut file).map_err(io)?;
    file.flush().map_err(io)?;
    file.get_ref().sync_all().map_err(io)?;
    Ok(out)
}

async fn measure_all(ctx: &Context, shutdown: &mut watch::Receiver<bool>) -> Result<(), Stop> {
    let g = &ctx.gate;
    let (repo, frontier, head) = (
        PathBuf::from(&ctx.rec.repository),
        ctx.frontier.clone(),
        ctx.contribution.head.clone(),
    );
    let descends = run_blocking(&ctx.store, move |s| {
        let git = Git::new(s.state_directory()).map_err(super::coded)?;
        git.reachable(&repo, &frontier, &head).map_err(super::coded)
    })
    .await?;
    if !descends {
        return decide(
            ctx,
            Verdict {
                promoted: false,
                code: "not_fast_forward",
                checker_reason: None,
                frontier: Vec::new(),
                candidate: Vec::new(),
                paired: None,
            },
        )
        .await;
    }
    let (inputs, checker) = ctx.gate.parts(&ctx.store, &ctx.rec.peerbox_id);
    // Episode mode: the environment's archive. Outputs mode: what check
    // runs start from, and the generator's inputs when there is one.
    let mut environment = PathBuf::new();
    let mut checks = Checks {
        checker: checker.clone(),
        generated: None,
    };
    let mut inputs = inputs;
    if g.mode == "episode" {
        let (out, secret) = (ctx.work.join("environment.tar"), ctx.secret.clone());
        environment = run_blocking(&ctx.store, move |_| {
            environment_archive(&checker, out, &secret)
        })
        .await?;
    } else if g.generator.is_some() {
        match generate(ctx, shutdown).await? {
            Some(made) => {
                inputs = made.inputs;
                checks.generated = Some(made.files);
            }
            None => {
                let (id, v, e) = (
                    ctx.rec.peerbox_id.clone(),
                    g.version,
                    ctx.evaluation.clone(),
                );
                run_blocking(&ctx.store, move |s| {
                    gate::pause_with(s, &id, v, "generator_failed")?;
                    update(s, &e, |e| e.state = "ended".into())
                })
                .await?;
                return Ok(());
            }
        }
    }
    let frontier_tree = tree_archive(ctx, &ctx.frontier, "frontier.tar", &inputs).await?;
    let candidate_tree =
        tree_archive(ctx, &ctx.contribution.head, "candidate.tar", &inputs).await?;
    let mut f: Vec<Option<f64>> = Vec::new();
    let mut c: Vec<Option<f64>> = Vec::new();
    let mut f_samples: Vec<Vec<f64>> = Vec::new();
    let mut c_samples: Vec<Vec<f64>> = Vec::new();
    let mut first_count: Option<usize> = None;
    let mut last_reason: Option<String> = None;
    for _ in 0..g.repeats {
        for side in ["frontier", "candidate"] {
            let tree = if side == "frontier" {
                &frontier_tree
            } else {
                &candidate_tree
            };
            let measured = match tree {
                Some(tree) if g.mode == "episode" => {
                    measure(ctx, side, &environment, tree, shutdown).await?
                }
                Some(tree) => measure_outputs(ctx, side, tree, &checks, shutdown).await?,
                None => Measured::Failed {
                    code: "run_failed",
                    reason: None,
                },
            };
            let measured = check_samples(measured, g, side, &mut first_count);
            match measured {
                Measured::Scored {
                    score,
                    samples,
                    reason,
                } => {
                    if side == "frontier" {
                        f.push(Some(score));
                        f_samples.extend(samples);
                    } else {
                        c.push(Some(score));
                        c_samples.extend(samples);
                        last_reason = Some(reason);
                    }
                }
                Measured::Failed { code, reason } => {
                    if side == "frontier" {
                        // A broken frontier is the owner's to fix.
                        let (id, v, e) = (
                            ctx.rec.peerbox_id.clone(),
                            g.version,
                            ctx.evaluation.clone(),
                        );
                        run_blocking(&ctx.store, move |s| {
                            gate::pause_with(s, &id, v, "frontier_failed")?;
                            update(s, &e, |e| e.state = "ended".into())
                        })
                        .await?;
                        return Ok(());
                    }
                    c.push(None);
                    return decide(
                        ctx,
                        Verdict {
                            promoted: false,
                            code,
                            checker_reason: reason,
                            frontier: f,
                            candidate: c,
                            paired: None,
                        },
                    )
                    .await;
                }
            }
        }
    }
    let fs: Vec<f64> = f.iter().flatten().copied().collect();
    let cs: Vec<f64> = c.iter().flatten().copied().collect();
    let k = g.min_gain / 100.0;
    let (promoted, paired) = if g.compare == "worst_best" {
        let pass = if g.direction == "lower" {
            let worst = cs.iter().copied().fold(f64::MIN, f64::max);
            let best = fs.iter().copied().fold(f64::MAX, f64::min);
            worst <= best * (1.0 - k)
        } else {
            let worst = cs.iter().copied().fold(f64::MAX, f64::min);
            let best = fs.iter().copied().fold(f64::MIN, f64::max);
            worst >= best * (1.0 + k)
        };
        (pass, None)
    } else {
        let (pass, value) = paired_bound(g, &f_samples, &c_samples);
        (pass, Some(value))
    };
    decide(
        ctx,
        Verdict {
            promoted,
            code: if promoted { "promoted" } else { "below_margin" },
            checker_reason: last_reason,
            frontier: f,
            candidate: c,
            paired,
        },
    )
    .await
}

/// A paired comparison (Verdict): whether the candidate passes, and the
/// public `paired`.
fn paired_bound(g: &Gate, frontier: &[Vec<f64>], candidate: &[Vec<f64>]) -> (bool, Value) {
    let n = frontier.first().map_or(0, Vec::len);
    let mean_of =
        |side: &[Vec<f64>], i: usize| side.iter().map(|m| m[i]).sum::<f64>() / side.len() as f64;
    let f: Vec<f64> = (0..n).map(|i| mean_of(frontier, i)).collect();
    let c: Vec<f64> = (0..n).map(|i| mean_of(candidate, i)).collect();
    let lower = g.direction == "lower";
    let d: Vec<f64> = f
        .iter()
        .zip(&c)
        .map(|(fi, ci)| if lower { fi - ci } else { ci - fi })
        .collect();
    let k = g.min_gain / 100.0;
    let e: Vec<f64> = d.iter().zip(&f).map(|(di, fi)| di - k * fi).collect();
    let nf = n as f64;
    let mean_e = e.iter().sum::<f64>() / nf;
    let sd = (e.iter().map(|x| (x - mean_e).powi(2)).sum::<f64>() / (nf - 1.0)).sqrt();
    let left = if g.compare == "paired_normal" {
        mean_e - 1.645 * sd / nf.sqrt()
    } else {
        let [lo, hi] = g.score_range.unwrap_or([0.0, 0.0]);
        let l = 40f64.ln();
        let r = (2.0 + k) * (hi - lo);
        mean_e - (2.0 * sd * sd * l / nf).sqrt() - 7.0 * r * l / (3.0 * (nf - 1.0))
    };
    let mean_f = f.iter().sum::<f64>() / nf;
    let mean_d = d.iter().sum::<f64>() / nf;
    let round = |x: f64| number((x * 100.0).round() / 100.0);
    (
        left >= 0.0,
        json!({
            "episodes": n,
            "mean_gain_percent": round(100.0 * mean_d / mean_f),
            "margin_bound_percent": round(left * 100.0 / mean_f),
        }),
    )
}

/// The sample checks that need the evaluation (Result line): the count
/// of its first frontier measurement, and `score_range`.
fn check_samples(m: Measured, g: &Gate, side: &str, first: &mut Option<usize>) -> Measured {
    let Measured::Scored {
        samples: Some(samples),
        reason,
        ..
    } = &m
    else {
        return m;
    };
    let failed = Measured::Failed {
        code: "check_failed",
        reason: Some(reason.clone()),
    };
    if let Some([lo, hi]) = g.score_range
        && g.compare == "paired_bounded"
        && samples.iter().any(|x| *x < lo || *x > hi)
    {
        return failed;
    }
    match first {
        Some(n) if *n != samples.len() => return failed,
        None if side == "frontier" => *first = Some(samples.len()),
        _ => {}
    }
    m
}

struct Verdict {
    promoted: bool,
    code: &'static str,
    checker_reason: Option<String>,
    frontier: Vec<Option<f64>>,
    candidate: Vec<Option<f64>>,
    paired: Option<Value>,
}

/// Records the gate's decision, atomically with the pending check, and the
/// evaluation's result and the gate's frontier.
async fn decide(ctx: &Context, v: Verdict) -> Result<(), Stop> {
    let g = &ctx.gate;
    let scores = |s: &[Option<f64>]| {
        s.iter()
            .map(|x| x.map_or(Value::Null, number))
            .collect::<Vec<_>>()
    };
    let public = json!({
        "gate_version": g.version,
        "verdict": if v.promoted { "promoted" } else { "rejected" },
        "code": v.code,
        "checker_reason": v.checker_reason,
        "score": g.score,
        "direction": g.direction,
        "min_gain": number(g.min_gain),
        "compare": g.compare,
        "frontier_scores": scores(&v.frontier),
        "candidate_scores": scores(&v.candidate),
        "secret_sha256": ctx.secret_sha256,
        "paired": v.paired,
    });
    let reason = match v.checker_reason.as_deref() {
        Some(r) if !r.is_empty() => format!("{}: {r}", v.code),
        _ => v.code.to_owned(),
    };
    let (cid, frontier, promoted) = (
        ctx.contribution.contribution_id.clone(),
        ctx.frontier.clone(),
        v.promoted,
    );
    let (peerbox, version, eval) = (
        ctx.rec.peerbox_id.clone(),
        g.version,
        ctx.evaluation.clone(),
    );
    let new_frontier = if v.promoted {
        Some((
            ctx.contribution.head.clone(),
            v.candidate.iter().flatten().copied().collect::<Vec<_>>(),
        ))
    } else if v.frontier.is_empty() {
        None
    } else {
        Some((
            ctx.frontier.clone(),
            v.frontier.iter().flatten().copied().collect::<Vec<_>>(),
        ))
    };
    run_blocking(&ctx.store, move |s| {
        let outcome = s.gate_decide(&cid, version, &frontier, promoted, reason, public.clone())?;
        let mut conn = s.connection()?;
        let tx = conn.transaction()?;
        let at = now();
        if let Some(mut e) = load(&tx, &eval)? {
            e.state = if outcome == contribution::GateOutcome::Recorded {
                "decided"
            } else {
                "ended"
            }
            .into();
            if outcome == contribution::GateOutcome::Recorded {
                e.decided_at = Some(at.clone());
                e.result = Some(public);
            }
            save(&tx, &e)?;
        }
        match outcome {
            contribution::GateOutcome::Recorded => {
                if let Some(mut gate) = gate::load(&tx, &peerbox)?
                    && gate.version == version
                    && let Some((commit, scores)) = new_frontier
                {
                    gate.frontier = Some(Frontier {
                        commit,
                        scores,
                        measured_at: at.clone(),
                    });
                    gate::save(&tx, &peerbox, &gate)?;
                }
                append_event(
                    &tx,
                    "peerbox.gate_evaluated",
                    &format!("{peerbox}/{cid}"),
                    &at,
                )?;
            }
            contribution::GateOutcome::DirtyWorktree => {
                tx.commit()?;
                // `conn` is the store's only connection; pause_with takes it.
                drop(conn);
                return gate::pause_with(s, &peerbox, version, "dirty_worktree");
            }
            _ => {}
        }
        tx.commit()?;
        Ok(())
    })
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------
// One measurement in episode mode: a linked pair.

/// One run of a pair as the host follows it.
struct Followed {
    entry: RunEntry,
    after: i64,
    tail: Vec<u8>,
    cut: bool,
    exited: Option<Value>,
    done: bool,
}

fn run_body(ctx: &Context, entry: &RunEntry, archive: &Path, link: &Value, role: &str) -> Value {
    let g = &ctx.gate;
    let environment = role == "listen";
    let (argv, cpus, memory, image) = if environment {
        (
            &g.checker,
            g.checker_cpus,
            g.checker_memory_mib,
            &g.checker_image,
        )
    } else {
        (&g.command, g.cpus, g.memory_mib, &g.image)
    };
    let mut link = link.clone();
    link["role"] = json!(role);
    let mut body = json!({
        "run_id": entry.run_id,
        "argv": argv,
        "cwd": "/workspace",
        "env": {},
        "resources": {"cpus": cpus, "memory_mib": memory, "timeout_seconds": g.timeout_seconds},
        "workspace_archive": archive.to_string_lossy(),
        "peerfs_workspace": null,
        "results": "output",
        "link": link,
    });
    if let Some(image) = image {
        body["image"] = json!(image);
    }
    body
}

/// Cancels and deletes the stored runs of refused pairs; whether none is
/// left.
async fn retry_refused(ctx: &Context) -> Result<bool, Error> {
    let eval = ctx.evaluation.clone();
    let refused: Vec<RunEntry> = run_blocking(&ctx.store, move |s| {
        Ok(load(&*s.connection()?, &eval)?
            .map(|e| {
                e.runs
                    .into_iter()
                    .filter(|r| r.outcome == "refused")
                    .collect()
            })
            .unwrap_or_default())
    })
    .await?;
    let mut removed = Vec::new();
    for r in &refused {
        if remove_run(r).await {
            removed.push(r.task_id.clone());
        }
    }
    let all = removed.len() == refused.len();
    if !removed.is_empty() {
        let eval = ctx.evaluation.clone();
        run_blocking(&ctx.store, move |s| {
            update(s, &eval, |e| {
                e.runs.retain(|r| !removed.contains(&r.task_id))
            })
        })
        .await?;
    }
    Ok(all)
}

/// Records a run's outcome, except over `cancelled`: a run cancelled by
/// a cleared gate or a decision by hand stays so, though it then exits.
fn set_outcome(store: &Store, eval: &str, task: &str, outcome: &str) -> Result<(), Error> {
    update(store, eval, |e| {
        for r in e
            .runs
            .iter_mut()
            .filter(|r| r.task_id == task && r.outcome != "cancelled")
        {
            r.outcome = outcome.into();
        }
    })
}

async fn measure(
    ctx: &Context,
    side: &str,
    environment: &Path,
    tree: &Path,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Measured, Stop> {
    let g = &ctx.gate;
    let link = g.link.clone().ok_or_else(|| {
        Stop::Error(Error::Internal(anyhow::anyhow!(
            "an episode gate without a link"
        )))
    })?;
    // Start the pair, listen first; a refusal cancels the other and
    // starts the pair again later.
    let (env_entry, bot_entry) = loop {
        going_on(ctx).await?;
        if *shutdown.borrow() {
            return Err(Stop::Shutdown);
        }
        // Evaluations wait while the runtime's switch is off or the gate
        // is paused.
        let (peerbox, version) = (ctx.rec.peerbox_id.clone(), g.version);
        let (switch, paused) = run_blocking(&ctx.store, move |s| {
            let paused = gate::load(&*s.connection()?, &peerbox)?
                .is_some_and(|g| g.version == version && g.paused_reason.is_some());
            Ok((s.runtime_switch()?, paused))
        })
        .await?;
        let Some(switch) = switch.filter(|_| !paused) else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        // The runs of a refused pair whose cancellation was not confirmed
        // are cancelled first, so none holds a slot of the next pair.
        if !retry_refused(ctx).await? {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)
            .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
        let link_value = json!({
            "id": format!("lnk_{}", hex::encode(id)),
            "port": link.port,
            "max_connections": link.connections,
            "max_bytes": link.bytes,
        });
        let entry = |kind: &str| -> Result<RunEntry, Error> {
            let task_id = new_id("task")?;
            Ok(RunEntry {
                run_id: crate::runtime_task::run_id(&ctx.own, &task_id),
                task_id,
                side: side.into(),
                kind: kind.into(),
                outcome: "starting".into(),
                socket: switch.socket.clone(),
            })
        };
        let (env_entry, bot_entry) = (entry("environment")?, entry("candidate")?);
        {
            let (a, b, eval) = (env_entry.clone(), bot_entry.clone(), ctx.evaluation.clone());
            run_blocking(&ctx.store, move |s| {
                update(s, &eval, |e| {
                    e.runs.push(a);
                    e.runs.push(b);
                })
            })
            .await?;
        }
        let started = |entry: &RunEntry, archive: &Path, role: &str| {
            let body = run_body(ctx, entry, archive, &link_value, role);
            let socket = switch.socket.clone();
            async move {
                matches!(call(&socket, Method::POST, "/v1/runs", Some(&body)).await,
                    Ok(a) if a.status == 200 || a.status == 201)
            }
        };
        // A refused pair's runs are forgotten once their cancellation is
        // confirmed; until then they stay stored as refused.
        let forget = |entries: Vec<(RunEntry, bool)>| {
            let eval = ctx.evaluation.clone();
            run_blocking(&ctx.store, move |s| {
                update(s, &eval, |e| {
                    for (entry, removed) in &entries {
                        if *removed {
                            e.runs.retain(|r| r.task_id != entry.task_id);
                        } else {
                            for r in e.runs.iter_mut().filter(|r| r.task_id == entry.task_id) {
                                r.outcome = "refused".into();
                            }
                        }
                    }
                })
            })
        };
        if !started(&env_entry, environment, "listen").await {
            let removed = remove_run(&env_entry).await;
            forget(vec![(env_entry, removed), (bot_entry, true)]).await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        if !started(&bot_entry, tree, "connect").await {
            let a = remove_run(&env_entry).await;
            let b = remove_run(&bot_entry).await;
            forget(vec![(env_entry, a), (bot_entry, b)]).await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        break (env_entry, bot_entry);
    };
    {
        let (eval, a, b) = (
            ctx.evaluation.clone(),
            env_entry.task_id.clone(),
            bot_entry.task_id.clone(),
        );
        run_blocking(&ctx.store, move |s| {
            set_outcome(s, &eval, &a, "running")?;
            set_outcome(s, &eval, &b, "running")
        })
        .await?;
    }
    let mut runs = [env_entry, bot_entry].map(|entry| Followed {
        entry,
        after: 0,
        tail: Vec::new(),
        cut: false,
        exited: None,
        done: false,
    });
    // The pair as a whole is bounded by the gate's timeout.
    let deadline = Instant::now() + Duration::from_secs(g.timeout_seconds as u64);
    let mut timed_out = false;
    let mut checked = Instant::now();
    while runs.iter().any(|r| !r.done) {
        if *shutdown.borrow() {
            return Err(Stop::Shutdown);
        }
        if checked.elapsed() >= Duration::from_secs(1) {
            checked = Instant::now();
            if let Err(stop) = going_on(ctx).await {
                for r in &runs {
                    remove_run(&r.entry).await;
                }
                let eval = ctx.evaluation.clone();
                let ids: Vec<String> = runs.iter().map(|r| r.entry.task_id.clone()).collect();
                run_blocking(&ctx.store, move |s| {
                    for id in ids {
                        set_outcome(s, &eval, &id, "cancelled")?;
                    }
                    Ok(())
                })
                .await?;
                return Err(stop);
            }
        }
        let now = Instant::now();
        if now >= deadline && !timed_out {
            timed_out = true;
            for r in &runs {
                let _ = call(
                    &r.entry.socket,
                    Method::POST,
                    &format!("/v1/runs/{}/cancel", r.entry.run_id),
                    Some(&json!({})),
                )
                .await;
            }
        }
        if now >= deadline + GRACE {
            break;
        }
        let mut progressed = false;
        for r in runs.iter_mut().filter(|r| !r.done) {
            // Paged within the runtime client's 1 MiB response limit, as
            // the runtime task follower pages.
            let path = format!(
                "/v1/runs/{}/events?after={}&wait=0&limit={}",
                r.entry.run_id,
                r.after,
                crate::task_outbound::RUNTIME_EVENT_PAGE
            );
            match call(&r.entry.socket, Method::GET, &path, None).await {
                Ok(a) if a.status == 404 => r.done = true,
                Ok(a) if a.status == 200 => {
                    for event in a.body.as_array().cloned().unwrap_or_default() {
                        progressed = true;
                        r.after = event["sequence"].as_i64().unwrap_or(r.after).max(r.after);
                        match event["kind"].as_str() {
                            Some("stdout") => {
                                let data = base64::engine::general_purpose::STANDARD
                                    .decode(event["data"].as_str().unwrap_or_default())
                                    .unwrap_or_default();
                                r.tail.extend_from_slice(&data);
                                if r.tail.len() > TAIL {
                                    let cut = r.tail.len() - TAIL;
                                    r.tail.drain(..cut);
                                    r.cut = true;
                                }
                            }
                            Some("exited") => r.exited = Some(event["result"].clone()),
                            Some("results") => r.done = true,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        if !progressed {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    for r in &runs {
        remove_run(&r.entry).await;
    }
    let outcome = |r: &Followed| -> &'static str {
        match &r.exited {
            None => "failed",
            // A timeout is `failed` (gate show: outcome).
            Some(x) if x["timed_out"] == json!(true) => "failed",
            Some(x) if x["error"].is_string() => "failed",
            Some(_) if timed_out => "failed",
            Some(x) if x["exit_code"] == json!(0) => "succeeded",
            Some(_) => "failed",
        }
    };
    let outcomes: Vec<(String, &'static str)> = runs
        .iter()
        .map(|r| (r.entry.task_id.clone(), outcome(r)))
        .collect();
    {
        let eval = ctx.evaluation.clone();
        run_blocking(&ctx.store, move |s| {
            for (id, o) in outcomes {
                set_outcome(s, &eval, &id, o)?;
            }
            Ok(())
        })
        .await?;
    }
    let env = &runs[0];
    let line = result_line(&env.tail, env.cut, g);
    // A line is read only from a run that exited 0 (Result line).
    Ok(match (outcome(env), line) {
        ("succeeded", Some(l)) if l.pass => Measured::Scored {
            score: l.score.unwrap_or(0.0),
            samples: l.samples,
            reason: l.reason,
        },
        ("succeeded", Some(l)) => Measured::Failed {
            code: "check_failed",
            reason: Some(l.reason),
        },
        _ => Measured::Failed {
            code: "check_failed",
            reason: None,
        },
    })
}

// ---------------------------------------------------------------------
// Outputs mode: a candidate run, then a check run on its outputs, and the
// generator once per evaluation (Evaluation; Generator).

/// Where check runs start from: the checker snapshot, and the generator's
/// other files when it made any.
struct Checks {
    checker: PathBuf,
    generated: Option<PathBuf>,
}

/// What an evaluation's generator made, as parts: the candidate runs'
/// inputs, and the check runs' files under `.peerbox-gate/generated/`.
struct Made {
    inputs: PathBuf,
    files: PathBuf,
}

/// One run that is not part of a pair, as the host followed it.
struct Single {
    entry: RunEntry,
    tail: Vec<u8>,
    cut: bool,
    exited: Option<Value>,
    artifacts: Vec<Value>,
    timed_out: bool,
}

/// A run's outcome as `gate show` reports it: a timeout is `failed`.
fn single_outcome(r: &Single) -> &'static str {
    match &r.exited {
        None => "failed",
        Some(x) if x["timed_out"] == json!(true) => "failed",
        Some(x) if x["error"].is_string() => "failed",
        Some(_) if r.timed_out => "failed",
        Some(x) if x["exit_code"] == json!(0) => "succeeded",
        Some(_) => "failed",
    }
}

/// What a run of `kind` executes, and under which bounds and image.
fn single_body(ctx: &Context, entry: &RunEntry, kind: &str, archive: &Path) -> Value {
    let g = &ctx.gate;
    let (argv, cpus, memory, image, results): (&[String], _, _, _, _) = match kind {
        "candidate" => (&g.command, g.cpus, g.memory_mib, &g.image, "changes"),
        "generator" => (
            g.generator.as_deref().unwrap_or_default(),
            g.checker_cpus,
            g.checker_memory_mib,
            &g.checker_image,
            "changes",
        ),
        _ => (
            &g.checker,
            g.checker_cpus,
            g.checker_memory_mib,
            &g.checker_image,
            "output",
        ),
    };
    let mut body = json!({
        "run_id": entry.run_id,
        "argv": argv,
        "cwd": "/workspace",
        "env": {},
        "resources": {"cpus": cpus, "memory_mib": memory, "timeout_seconds": g.timeout_seconds},
        "workspace_archive": archive.to_string_lossy(),
        "peerfs_workspace": null,
        "results": results,
    });
    if let Some(image) = image {
        body["image"] = json!(image);
    }
    body
}

/// Starts one run of `kind` on the home host's runtime, waiting while the
/// switch is off or the gate is paused and starting again after a
/// refusal, and follows it until its results. The run stays on the runtime
/// for the caller to read its result files.
async fn run_single(
    ctx: &Context,
    side: &str,
    kind: &str,
    archive: &Path,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Single, Stop> {
    let g = &ctx.gate;
    let entry = loop {
        going_on(ctx).await?;
        if *shutdown.borrow() {
            return Err(Stop::Shutdown);
        }
        let (peerbox, version) = (ctx.rec.peerbox_id.clone(), g.version);
        let (switch, paused) = run_blocking(&ctx.store, move |s| {
            let paused = gate::load(&*s.connection()?, &peerbox)?
                .is_some_and(|g| g.version == version && g.paused_reason.is_some());
            Ok((s.runtime_switch()?, paused))
        })
        .await?;
        let Some(switch) = switch.filter(|_| !paused) else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        if !retry_refused(ctx).await? {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let task_id = new_id("task")?;
        let entry = RunEntry {
            run_id: crate::runtime_task::run_id(&ctx.own, &task_id),
            task_id,
            side: side.into(),
            kind: kind.into(),
            outcome: "starting".into(),
            socket: switch.socket.clone(),
        };
        {
            let (a, eval) = (entry.clone(), ctx.evaluation.clone());
            run_blocking(&ctx.store, move |s| update(s, &eval, |e| e.runs.push(a))).await?;
        }
        let body = single_body(ctx, &entry, kind, archive);
        let started = matches!(call(&switch.socket, Method::POST, "/v1/runs", Some(&body)).await,
            Ok(a) if a.status == 200 || a.status == 201);
        if started {
            break entry;
        }
        // A refused run is forgotten once its cancellation is confirmed.
        let removed = remove_run(&entry).await;
        let (eval, id) = (ctx.evaluation.clone(), entry.task_id.clone());
        run_blocking(&ctx.store, move |s| {
            update(s, &eval, |e| {
                if removed {
                    e.runs.retain(|r| r.task_id != id);
                } else {
                    for r in e.runs.iter_mut().filter(|r| r.task_id == id) {
                        r.outcome = "refused".into();
                    }
                }
            })
        })
        .await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    {
        let (eval, id) = (ctx.evaluation.clone(), entry.task_id.clone());
        run_blocking(&ctx.store, move |s| set_outcome(s, &eval, &id, "running")).await?;
    }
    let mut r = Single {
        entry,
        tail: Vec::new(),
        cut: false,
        exited: None,
        artifacts: Vec::new(),
        timed_out: false,
    };
    let deadline = Instant::now() + Duration::from_secs(g.timeout_seconds as u64);
    let (mut after, mut checked) = (0i64, Instant::now());
    loop {
        if *shutdown.borrow() {
            return Err(Stop::Shutdown);
        }
        if checked.elapsed() >= Duration::from_secs(1) {
            checked = Instant::now();
            if let Err(stop) = going_on(ctx).await {
                remove_run(&r.entry).await;
                let (eval, id) = (ctx.evaluation.clone(), r.entry.task_id.clone());
                run_blocking(&ctx.store, move |s| set_outcome(s, &eval, &id, "cancelled")).await?;
                return Err(stop);
            }
        }
        let now = Instant::now();
        if now >= deadline && !r.timed_out {
            r.timed_out = true;
            let _ = call(
                &r.entry.socket,
                Method::POST,
                &format!("/v1/runs/{}/cancel", r.entry.run_id),
                Some(&json!({})),
            )
            .await;
        }
        if now >= deadline + GRACE {
            break;
        }
        let path = format!(
            "/v1/runs/{}/events?after={after}&wait=0&limit={}",
            r.entry.run_id,
            crate::task_outbound::RUNTIME_EVENT_PAGE
        );
        let mut progressed = false;
        let mut done = false;
        match call(&r.entry.socket, Method::GET, &path, None).await {
            Ok(a) if a.status == 404 => done = true,
            Ok(a) if a.status == 200 => {
                for event in a.body.as_array().cloned().unwrap_or_default() {
                    progressed = true;
                    after = event["sequence"].as_i64().unwrap_or(after).max(after);
                    match event["kind"].as_str() {
                        Some("stdout") => {
                            let data = base64::engine::general_purpose::STANDARD
                                .decode(event["data"].as_str().unwrap_or_default())
                                .unwrap_or_default();
                            r.tail.extend_from_slice(&data);
                            if r.tail.len() > TAIL {
                                let cut = r.tail.len() - TAIL;
                                r.tail.drain(..cut);
                                r.cut = true;
                            }
                        }
                        Some("exited") => r.exited = Some(event["result"].clone()),
                        Some("results") => {
                            r.artifacts =
                                event["artifacts"].as_array().cloned().unwrap_or_default();
                            done = true;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        if done {
            break;
        }
        if !progressed {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let (eval, id, outcome) = (
        ctx.evaluation.clone(),
        r.entry.task_id.clone(),
        single_outcome(&r),
    );
    run_blocking(&ctx.store, move |s| set_outcome(s, &eval, &id, outcome)).await?;
    // A run that ended because the evaluation was stopped (a cleared gate,
    // a decision by hand) is not a measurement: the evaluation stops.
    if let Err(stop) = going_on(ctx).await {
        remove_run(&r.entry).await;
        return Err(stop);
    }
    Ok(r)
}

/// The run's `changes.tar`, when it came back within `max_changes_bytes`
/// (The gate record: the changes size is its size).
fn changes_within(r: &Single, bound: i64) -> Option<PathBuf> {
    let a = r.artifacts.iter().find(|a| a["name"] == "changes.tar")?;
    let size = a["size"].as_i64()?;
    if size > bound {
        return None;
    }
    a["path"].as_str().map(PathBuf::from)
}

/// The directories leading to `path`, each written once to `out`.
fn parents(out: &mut impl Write, path: &[u8], written: &mut Vec<Vec<u8>>) -> std::io::Result<()> {
    let mut at = 0;
    while let Some(i) = path[at..].iter().position(|b| *b == b'/') {
        at += i + 1;
        let dir = &path[..at];
        if !written.iter().any(|w| w == dir) {
            written.push(dir.to_vec());
            crate::tar::entry(out, dir, crate::tar::DIRECTORY, 0o755, 0, b"")?;
        }
    }
    Ok(())
}

/// Copies the regular files of a run's `changes.tar` that `rename` maps,
/// under their new paths and with the directories leading to them. A path
/// that is absolute or climbs out with `..` is left out.
fn copy_changes(
    changes: &Path,
    out: &mut impl Write,
    written: &mut Vec<Vec<u8>>,
    rename: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> std::io::Result<()> {
    let mut archive = tar::Archive::new(std::io::BufReader::new(std::fs::File::open(changes)?));
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let raw = entry.path_bytes().into_owned();
        let path = raw.strip_prefix(b"./").unwrap_or(&raw).to_vec();
        if path.is_empty()
            || path.starts_with(b"/")
            || path.split(|b| *b == b'/').any(|c| c == b"..")
        {
            continue;
        }
        let Some(to) = rename(&path) else { continue };
        let mode = entry.header().mode().unwrap_or(0o644) & 0o7777;
        let size = entry.size();
        parents(out, &to, written)?;
        crate::tar::entry(out, &to, crate::tar::FILE, mode, size, b"")?;
        let copied = std::io::copy(&mut (&mut entry).take(size), out)?;
        if copied != size {
            return Err(std::io::Error::other("a changes.tar entry ended early"));
        }
        crate::tar::pad(out, size)?;
    }
    Ok(())
}

/// A check run's archive: the checker snapshot, the secret, the
/// generator's other files, and the candidate's outputs, the regular files
/// its changes hold under `.peerbox-gate/out/`.
fn check_archive(
    checks: &Checks,
    secret: &str,
    changes: &Path,
    out: PathBuf,
) -> Result<PathBuf, Error> {
    let io = |e: std::io::Error| Error::Internal(e.into());
    let mut file = std::io::BufWriter::new(std::fs::File::create(&out).map_err(io)?);
    std::io::copy(
        &mut std::fs::File::open(&checks.checker).map_err(io)?,
        &mut file,
    )
    .map_err(io)?;
    let secret = format!("{secret}\n");
    let mut written = vec![b".peerbox-gate/".to_vec()];
    crate::tar::entry(
        &mut file,
        b".peerbox-gate/",
        crate::tar::DIRECTORY,
        0o755,
        0,
        b"",
    )
    .map_err(io)?;
    crate::tar::entry(
        &mut file,
        b".peerbox-gate/secret",
        crate::tar::FILE,
        0o644,
        secret.len() as u64,
        b"",
    )
    .map_err(io)?;
    file.write_all(secret.as_bytes()).map_err(io)?;
    crate::tar::pad(&mut file, secret.len() as u64).map_err(io)?;
    if let Some(generated) = &checks.generated {
        std::io::copy(&mut std::fs::File::open(generated).map_err(io)?, &mut file).map_err(io)?;
        written.push(b".peerbox-gate/generated/".to_vec());
    }
    copy_changes(changes, &mut file, &mut written, |p| {
        p.starts_with(b".peerbox-gate/out/").then(|| p.to_vec())
    })
    .map_err(io)?;
    crate::tar::end(&mut file).map_err(io)?;
    file.flush().map_err(io)?;
    file.get_ref().sync_all().map_err(io)?;
    Ok(out)
}

/// Splits a generator's changes into the parts it makes (Generator): its
/// files under `.peerbox-gate/inputs/`, which replace the inputs snapshot
/// in candidate runs, and the rest, at their paths under
/// `.peerbox-gate/generated/`, for check runs.
fn split_generated(changes: &Path, work: &Path) -> Result<Made, Error> {
    let io = |e: std::io::Error| Error::Internal(e.into());
    let (inputs, files) = (
        work.join("generated-inputs.part"),
        work.join("generated-files.part"),
    );
    let mut a = std::io::BufWriter::new(std::fs::File::create(&inputs).map_err(io)?);
    let mut written = Vec::new();
    parents(&mut a, b".peerbox-gate/inputs/", &mut written).map_err(io)?;
    copy_changes(changes, &mut a, &mut written, |p| {
        p.starts_with(b".peerbox-gate/inputs/").then(|| p.to_vec())
    })
    .map_err(io)?;
    a.flush().map_err(io)?;
    let mut b = std::io::BufWriter::new(std::fs::File::create(&files).map_err(io)?);
    // `.peerbox-gate/` itself is the check archive's.
    let mut written = vec![b".peerbox-gate/".to_vec()];
    parents(&mut b, b".peerbox-gate/generated/", &mut written).map_err(io)?;
    copy_changes(changes, &mut b, &mut written, |p| {
        (!p.starts_with(b".peerbox-gate/inputs/")).then(|| {
            let mut to = b".peerbox-gate/generated/".to_vec();
            to.extend_from_slice(p);
            to
        })
    })
    .map_err(io)?;
    b.flush().map_err(io)?;
    Ok(Made { inputs, files })
}

/// Runs the generator once, before the first measurement; None when it
/// failed, timed out, or its changes were over the bound or dropped.
async fn generate(
    ctx: &Context,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<Made>, Stop> {
    let (_, checker) = ctx.gate.parts(&ctx.store, &ctx.rec.peerbox_id);
    let (out, secret) = (ctx.work.join("generator.tar"), ctx.secret.clone());
    let archive = run_blocking(&ctx.store, move |_| {
        environment_archive(&checker, out, &secret)
    })
    .await?;
    let r = run_single(ctx, "evaluation", "generator", &archive, shutdown).await?;
    let changes = (single_outcome(&r) == "succeeded")
        .then(|| changes_within(&r, ctx.gate.max_changes_bytes))
        .flatten();
    let made = match changes {
        Some(changes) => {
            let work = ctx.work.clone();
            Some(run_blocking(&ctx.store, move |_| split_generated(&changes, &work)).await?)
        }
        None => None,
    };
    remove_run(&r.entry).await;
    Ok(made)
}

/// One measurement in outputs mode: the candidate run, then, when it
/// succeeded within the bound, a check run on its outputs.
async fn measure_outputs(
    ctx: &Context,
    side: &str,
    tree: &Path,
    checks: &Checks,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Measured, Stop> {
    let g = &ctx.gate;
    let candidate = run_single(ctx, side, "candidate", tree, shutdown).await?;
    // A run that both fails and exceeds the bound is `run_failed`.
    if single_outcome(&candidate) != "succeeded" {
        remove_run(&candidate.entry).await;
        return Ok(Measured::Failed {
            code: "run_failed",
            reason: None,
        });
    }
    let Some(changes) = changes_within(&candidate, g.max_changes_bytes) else {
        remove_run(&candidate.entry).await;
        return Ok(Measured::Failed {
            code: "outputs_too_large",
            reason: None,
        });
    };
    let time = candidate
        .exited
        .as_ref()
        .and_then(|x| x["duration_ms"].as_f64())
        .unwrap_or(0.0)
        .max(1.0);
    let archive = {
        let (checker, generated) = (checks.checker.clone(), checks.generated.clone());
        let (secret, out) = (
            ctx.secret.clone(),
            ctx.work
                .join(format!("check-{}.tar", candidate.entry.task_id)),
        );
        run_blocking(&ctx.store, move |_| {
            check_archive(&Checks { checker, generated }, &secret, &changes, out)
        })
        .await
    };
    remove_run(&candidate.entry).await;
    let archive = archive?;
    let check = run_single(ctx, side, "check", &archive, shutdown).await?;
    remove_run(&check.entry).await;
    let _ = std::fs::remove_file(&archive);
    let line = result_line(&check.tail, check.cut, g);
    // A line is read only from a run that exited 0 (Result line).
    Ok(match (single_outcome(&check), line) {
        ("succeeded", Some(l)) if l.pass => Measured::Scored {
            score: if g.score == "time" {
                time
            } else {
                l.score.unwrap_or(0.0)
            },
            samples: l.samples,
            reason: l.reason,
        },
        ("succeeded", Some(l)) => Measured::Failed {
            code: "check_failed",
            reason: Some(l.reason),
        },
        _ => Measured::Failed {
            code: "check_failed",
            reason: None,
        },
    })
}

struct Line {
    pass: bool,
    score: Option<f64>,
    reason: String,
    samples: Option<Vec<f64>>,
}

/// A check or environment run's result line (Result line): its last
/// non-empty stdout line, `PEERBOX-GATE ` and a JSON object. None when
/// there is none or it is malformed: a malformed line is not read, even
/// when part of it parses.
fn result_line(tail: &[u8], cut: bool, g: &Gate) -> Option<Line> {
    let mut end = tail.len();
    let (start, stop) = loop {
        let start = tail[..end]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |i| i + 1);
        let line = &tail[start..end];
        if !line.iter().all(u8::is_ascii_whitespace) {
            break (start, end);
        }
        if start == 0 {
            return None;
        }
        end = start - 1;
    };
    if (start == 0 && cut) || stop - start > MAX_LINE {
        return None;
    }
    let line = std::str::from_utf8(&tail[start..stop]).ok()?;
    let line = line.strip_suffix('\r').unwrap_or(line);
    let json = line.strip_prefix("PEERBOX-GATE ")?;
    let v: Value = serde_json::from_str(json).ok()?;
    let o = v.as_object()?;
    let paired = g.compare != "worst_best";
    let mut keys = vec!["pass", "reason", "score"];
    if paired {
        keys.push("samples");
    }
    keys.sort_unstable();
    let mut have: Vec<&str> = o.keys().map(String::as_str).collect();
    have.sort_unstable();
    if have != keys {
        return None;
    }
    let pass = o["pass"].as_bool()?;
    let reason = o["reason"].as_str()?;
    if reason.len() > 200 {
        return None;
    }
    let positive = |x: &Value| x.as_f64().filter(|f| f.is_finite() && *f > 0.0);
    let score = if g.score == "time" {
        if !o["score"].is_null() {
            return None;
        }
        None
    } else {
        Some(positive(&o["score"])?)
    };
    let samples = if paired {
        let list = o["samples"].as_array()?;
        if !(30..=10_000).contains(&list.len()) {
            return None;
        }
        Some(list.iter().map(positive).collect::<Option<Vec<_>>>()?)
    } else {
        None
    };
    Some(Line {
        pass,
        score,
        reason: reason.to_owned(),
        samples,
    })
}
