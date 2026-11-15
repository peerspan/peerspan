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
            let id = e.evaluation_id.clone();
            run_blocking(store, move |s| update(s, &id, |e| e.cleanup = false)).await?;
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
    socket: PathBuf,
}
fn next(store: &Store) -> Result<Option<Job>, Error> {
    let Some(switch) = store.runtime_switch()? else {
        return Ok(None);
    };
    let conn = store.connection()?;
    for peerbox in gate::gated(&conn)? {
        let Some((_, g)) = gate::gated_record(&conn, &peerbox)? else {
            continue;
        };
        // Only episode gates are evaluated; gate set refuses the others.
        if g.mode != "episode" || g.paused_reason.is_some() || running(&conn, &peerbox)?.is_some() {
            continue;
        }
        if let Some(first) = gate::queue(&conn, &peerbox)?.into_iter().next() {
            return Ok(Some(Job {
                peerbox,
                contribution: first,
                socket: switch.socket,
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
    socket: PathBuf,
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
        Ok(()) => Ok(()),
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
        socket: job.socket,
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
/// with the inputs snapshot under `.peerbox-gate/inputs/`.
async fn tree_archive(ctx: &Context, commit: &str, name: &str) -> Result<Option<PathBuf>, Error> {
    let (inputs, _) = ctx.gate.parts(&ctx.store, &ctx.rec.peerbox_id);
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
    let environment = {
        let (_, checker) = ctx.gate.parts(&ctx.store, &ctx.rec.peerbox_id);
        let (out, secret) = (ctx.work.join("environment.tar"), ctx.secret.clone());
        run_blocking(&ctx.store, move |_| {
            environment_archive(&checker, out, &secret)
        })
        .await?
    };
    let frontier_tree = tree_archive(ctx, &ctx.frontier, "frontier.tar").await?;
    let candidate_tree = tree_archive(ctx, &ctx.contribution.head, "candidate.tar").await?;
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
                Some(tree) => measure(ctx, side, &environment, tree, shutdown).await?,
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
        let outcome = s.gate_decide(&cid, &frontier, promoted, reason, public.clone())?;
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

fn set_outcome(store: &Store, eval: &str, task: &str, outcome: &str) -> Result<(), Error> {
    update(store, eval, |e| {
        for r in e.runs.iter_mut().filter(|r| r.task_id == task) {
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
                socket: ctx.socket.clone(),
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
            let socket = ctx.socket.clone();
            async move {
                matches!(call(&socket, Method::POST, "/v1/runs", Some(&body)).await,
                    Ok(a) if a.status == 200 || a.status == 201)
            }
        };
        let forget = |a: RunEntry, b: RunEntry| {
            let eval = ctx.evaluation.clone();
            run_blocking(&ctx.store, move |s| {
                update(s, &eval, |e| {
                    e.runs
                        .retain(|r| r.task_id != a.task_id && r.task_id != b.task_id)
                })
            })
        };
        if !started(&env_entry, environment, "listen").await {
            remove_run(&env_entry).await;
            forget(env_entry, bot_entry).await?;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        if !started(&bot_entry, tree, "connect").await {
            remove_run(&env_entry).await;
            remove_run(&bot_entry).await;
            forget(env_entry, bot_entry).await?;
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
            let path = format!(
                "/v1/runs/{}/events?after={}&wait=0&limit=1000",
                r.entry.run_id, r.after
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
            Some(x) if x["timed_out"] == json!(true) => "timed_out",
            Some(x) if x["error"].is_string() => "failed",
            Some(_) if timed_out => "timed_out",
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
    Ok(match (outcome(env), line) {
        ("succeeded", Ok(l)) if l.pass => Measured::Scored {
            score: l.score.unwrap_or(0.0),
            samples: l.samples,
            reason: l.reason,
        },
        (_, Ok(l)) => Measured::Failed {
            code: "check_failed",
            reason: Some(l.reason),
        },
        (_, Err(())) => Measured::Failed {
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
/// non-empty stdout line, `PEERBOX-GATE ` and a JSON object.
fn result_line(tail: &[u8], cut: bool, g: &Gate) -> Result<Line, ()> {
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
            return Err(());
        }
        end = start - 1;
    };
    if (start == 0 && cut) || stop - start > MAX_LINE {
        return Err(());
    }
    let line = std::str::from_utf8(&tail[start..stop]).map_err(|_| ())?;
    let line = line.strip_suffix('\r').unwrap_or(line);
    let json = line.strip_prefix("PEERBOX-GATE ").ok_or(())?;
    let v: Value = serde_json::from_str(json).map_err(|_| ())?;
    let o = v.as_object().ok_or(())?;
    let paired = g.compare != "worst_best";
    let mut keys = vec!["pass", "reason", "score"];
    if paired {
        keys.push("samples");
    }
    keys.sort_unstable();
    let mut have: Vec<&str> = o.keys().map(String::as_str).collect();
    have.sort_unstable();
    if have != keys {
        return Err(());
    }
    let pass = o["pass"].as_bool().ok_or(())?;
    let reason = o["reason"].as_str().ok_or(())?;
    if reason.len() > 200 {
        return Err(());
    }
    let positive = |x: &Value| x.as_f64().filter(|f| f.is_finite() && *f > 0.0);
    let score = if g.score == "time" {
        if !o["score"].is_null() {
            return Err(());
        }
        None
    } else {
        Some(positive(&o["score"]).ok_or(())?)
    };
    let samples = if paired {
        let list = o["samples"].as_array().ok_or(())?;
        if !(30..=10_000).contains(&list.len()) {
            return Err(());
        }
        Some(
            list.iter()
                .map(|x| positive(x).ok_or(()))
                .collect::<Result<Vec<_>, _>>()?,
        )
    } else {
        None
    };
    Ok(Line {
        pass,
        score,
        reason: reason.to_owned(),
        samples,
    })
}
