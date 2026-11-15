//! Peerbox gates (peerbox contract, Gates): the gate record, its
//! snapshots and commitment, `gate set|pause|resume|clear|show` on the
//! local API, and the public summary `list` carries. Evaluations are
//! `evaluation`.
use super::{Record, contribution, record};
use crate::{
    api::{blocking, decode},
    model::Error,
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State, rejection::BytesRejection},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
};

/// Database version 34: gates and their evaluations. A gate's row stays
/// after `gate clear` with a null record, so the next `gate set` takes the
/// next version.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS peerbox_gates (peerbox_id TEXT PRIMARY KEY, version INTEGER NOT NULL, record TEXT);
CREATE TABLE IF NOT EXISTS peerbox_gate_evaluations (evaluation_id TEXT PRIMARY KEY, peerbox_id TEXT NOT NULL, record TEXT NOT NULL);
";

/// The latest evaluations `gate show` lists and the host keeps.
pub const EVALUATIONS_KEPT: usize = 20;
/// A snapshot's bound: the artifact contract's limit for one file, which
/// bounds a workspace archive (PBX-37).
const SNAPSHOT_LIMIT: u64 = 104_857_600;
/// The prefix of the inputs in a candidate run's workspace.
pub const INPUTS_PREFIX: &[u8] = b".peerbox-gate/inputs/";

/// The link of an `episode` gate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub port: i64,
    pub connections: i64,
    pub bytes: i64,
}

/// The gate's frontier from its latest evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Frontier {
    pub commit: String,
    pub scores: Vec<f64>,
    pub measured_at: String,
}

/// A gate as stored: the gate record, with the paused reason the host
/// stores (`runtime_disabled` is derived, never stored; PBX-36).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub version: i64,
    pub paused_reason: Option<String>,
    pub mode: String,
    pub command: Vec<String>,
    pub inputs_sha256: String,
    pub checker: Vec<String>,
    pub checker_sha256: String,
    pub generator: Option<Vec<String>>,
    pub score: String,
    pub direction: String,
    pub min_gain: f64,
    pub repeats: i64,
    pub compare: String,
    pub score_range: Option<[f64; 2]>,
    pub image: Option<String>,
    pub checker_image: Option<String>,
    pub link: Option<Link>,
    pub cpus: i64,
    pub memory_mib: i64,
    pub timeout_seconds: i64,
    pub checker_cpus: i64,
    pub checker_memory_mib: i64,
    pub max_changes_bytes: i64,
    pub salt: String,
    pub commitment: String,
    pub frontier: Option<Frontier>,
}

impl Gate {
    /// The state and paused reason shown: a stored reason, else
    /// `runtime_disabled` while the runtime's switch is off (PBX-36).
    pub fn shown_state(&self, switch_on: bool) -> (&'static str, Option<String>) {
        match (&self.paused_reason, switch_on) {
            (Some(r), _) => ("paused", Some(r.clone())),
            (None, false) => ("paused", Some("runtime_disabled".into())),
            (None, true) => ("active", None),
        }
    }
    /// The gate record as `gate show` and `gate set` return it.
    pub fn view(&self, switch_on: bool) -> Value {
        let (state, reason) = self.shown_state(switch_on);
        let mut v = serde_json::to_value(self).unwrap_or(Value::Null);
        v["state"] = json!(state);
        v["paused_reason"] = json!(reason);
        v["min_gain"] = number(self.min_gain);
        if let Some([lo, hi]) = self.score_range {
            v["score_range"] = json!([number(lo), number(hi)]);
        }
        if let Some(f) = &self.frontier {
            v["frontier"]["scores"] = f.scores.iter().map(|s| number(*s)).collect();
        }
        v
    }
    /// The best of a list of scores, by the gate's direction.
    pub fn best(&self, scores: &[f64]) -> Option<f64> {
        let lower = self.direction == "lower";
        scores
            .iter()
            .copied()
            .reduce(|a, b| if (b < a) == lower { b } else { a })
    }
    /// The public summary (What readers see).
    pub fn summary(&self, switch_on: bool) -> Value {
        let (state, _) = self.shown_state(switch_on);
        json!({
            "version": self.version,
            "state": state,
            "mode": self.mode,
            "command": self.command,
            "score": self.score,
            "direction": self.direction,
            "min_gain": number(self.min_gain),
            "compare": self.compare,
            "score_range": self.score_range.map(|[lo, hi]| json!([number(lo), number(hi)])),
            "image": self.image,
            "link_port": self.link.as_ref().map(|l| l.port),
            "commitment": self.commitment,
            "frontier": self.frontier.as_ref().map(|f| json!({
                "commit": f.commit,
                "score": self.best(&f.scores).map(number),
            })),
        })
    }
    /// The snapshot parts of this version in the state directory.
    pub fn parts(&self, store: &Store, peerbox: &str) -> (PathBuf, PathBuf) {
        let dir = gates_dir(store).join(peerbox);
        (
            dir.join(format!("v{}-inputs.part", self.version)),
            dir.join(format!("v{}-checker.part", self.version)),
        )
    }
}

/// A number as JSON: an integer when it is one.
pub fn number(x: f64) -> Value {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 9.0e15 {
        json!(x as i64)
    } else {
        json!(x)
    }
}

fn gates_dir(store: &Store) -> PathBuf {
    store.state_directory().join("peerbox-gates")
}

// ---------------------------------------------------------------------
// Storage.

pub(crate) fn load(conn: &Connection, peerbox: &str) -> Result<Option<Gate>, Error> {
    let raw: Option<Option<String>> = conn
        .query_row(
            "SELECT record FROM peerbox_gates WHERE peerbox_id = ?1",
            [peerbox],
            |r| r.get(0),
        )
        .optional()?;
    raw.flatten()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .transpose()
}
pub(crate) fn save(conn: &Connection, peerbox: &str, gate: &Gate) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO peerbox_gates VALUES (?1, ?2, ?3) ON CONFLICT(peerbox_id) DO UPDATE SET version = ?2, record = ?3",
        params![peerbox, gate.version, serde_json::to_string(gate)?],
    )?;
    Ok(())
}
/// Every gated peerbox's ID, in ascending order.
pub(crate) fn gated(conn: &Connection) -> Result<Vec<String>, Error> {
    let mut s = conn.prepare(
        "SELECT peerbox_id FROM peerbox_gates WHERE record IS NOT NULL ORDER BY peerbox_id",
    )?;
    let rows = s
        .query_map([], |r| r.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(rows)
}
/// The public summary of a peerbox's gate, or null.
pub fn summary_of(store: &Store, conn: &Connection, peerbox: &str) -> Value {
    let switch_on = store.runtime_switch().ok().flatten().is_some();
    load(conn, peerbox)
        .ok()
        .flatten()
        .map_or(Value::Null, |g| g.summary(switch_on))
}
/// The queued contributions, in evaluation order (PBX-14, PBX-35): every
/// pending contribution, oldest first by `(submitted_at,
/// contribution_id)`, except the one under evaluation.
pub(crate) fn queue(conn: &Connection, peerbox: &str) -> Result<Vec<String>, Error> {
    let running = super::evaluation::running(conn, peerbox)?.map(|e| e.contribution_id);
    let mut pending: Vec<(String, String)> = contribution::of_peerbox(conn, peerbox)?
        .into_iter()
        .filter(|c| c.state == contribution::PENDING)
        .map(|c| (c.submitted_at, c.contribution_id))
        .collect();
    pending.sort();
    Ok(pending
        .into_iter()
        .map(|(_, id)| id)
        .filter(|id| Some(id) != running.as_ref())
        .collect())
}

// ---------------------------------------------------------------------
// The commitment (PBX-32): RFC 8785 canonical JSON.

/// RFC 8785 canonical JSON of a value whose object keys are ASCII.
fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            out.push_str(&serde_json::to_string(v).unwrap_or_default())
        }
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => out.push_str(&i.to_string()),
            (_, Some(u), _) => out.push_str(&u.to_string()),
            (_, _, Some(f)) => out.push_str(&es_number(f)),
            _ => out.push_str("null"),
        },
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                canonical(&map[k], out);
            }
            out.push('}');
        }
    }
}
/// A finite number as ECMAScript's Number::toString prints it.
fn es_number(x: f64) -> String {
    if x == 0.0 {
        return "0".into();
    }
    let sign = if x < 0.0 { "-" } else { "" };
    let text = format!("{:e}", x.abs());
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exponent + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let m = if k == 1 {
            digits.clone()
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!("{m}e{}{}", if e > 0 { "+" } else { "-" }, e.abs())
    };
    format!("{sign}{body}")
}
/// The commitment of a gate's settings under its salt.
pub fn commitment(g: &Gate) -> String {
    let mut body = Map::new();
    let full = serde_json::to_value(g).unwrap_or(Value::Null);
    for key in [
        "mode",
        "command",
        "inputs_sha256",
        "checker",
        "checker_sha256",
        "generator",
        "score",
        "direction",
        "min_gain",
        "repeats",
        "compare",
        "score_range",
        "image",
        "checker_image",
        "link",
        "cpus",
        "memory_mib",
        "checker_cpus",
        "checker_memory_mib",
        "timeout_seconds",
        "max_changes_bytes",
    ] {
        body.insert(key.into(), full[key].clone());
    }
    body.insert("min_gain".into(), number(g.min_gain));
    if let Some([lo, hi]) = g.score_range {
        body.insert("score_range".into(), json!([number(lo), number(hi)]));
    }
    body.insert("salt".into(), json!(g.salt));
    let mut text = String::new();
    canonical(&Value::Object(body), &mut text);
    let mut h = Sha256::new();
    h.update(b"peerbox-gate-commitment-v1\n");
    h.update(text.as_bytes());
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------
// Snapshots (The gate record, Snapshots; PBX-37).

/// A writer that counts and refuses to pass the snapshot bound.
struct Bounded<W> {
    inner: W,
    written: u64,
}
impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written + buf.len() as u64 > SNAPSHOT_LIMIT {
            return Err(std::io::Error::other("over"));
        }
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn walk(root: &FsPath, rel: &FsPath, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root.join(rel))? {
        let entry = entry?;
        let path = rel.join(entry.file_name());
        let kind = entry.file_type()?;
        out.push(path.clone());
        if kind.is_dir() {
            walk(root, &path, out)?;
        }
    }
    Ok(())
}

/// Copies `dir` into `out` as workspace archive entries under `prefix`
/// (no end marker), and returns its snapshot digest. Refuses, naming
/// `field`, anything a workspace cannot hold and a snapshot over the
/// bound.
pub(crate) fn snapshot(
    dir: &FsPath,
    field: &'static str,
    prefix: &[u8],
    out: &FsPath,
) -> Result<String, Error> {
    let invalid = |m: String| Error::Invalid(format!("{field} {m}"));
    if !dir.is_absolute() {
        return Err(invalid("must be an absolute path".into()));
    }
    if !std::fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
        return Err(invalid(format!("{} is not a directory", dir.display())));
    }
    let mut paths = Vec::new();
    walk(dir, FsPath::new(""), &mut paths).map_err(|e| invalid(format!("cannot be read: {e}")))?;
    paths.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out)
        .map_err(|e| Error::Internal(e.into()))?;
    let _ = std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600));
    let mut tar = Bounded {
        inner: std::io::BufWriter::new(file),
        written: 0,
    };
    let over = || {
        invalid(format!(
            "is over {SNAPSHOT_LIMIT} bytes as a workspace archive"
        ))
    };
    let io = |e: std::io::Error| {
        if e.to_string() == "over" {
            over()
        } else {
            invalid(format!("cannot be read: {e}"))
        }
    };
    // The prefix's own directories.
    let mut at = 0;
    while let Some(i) = prefix[at..].iter().position(|b| *b == b'/') {
        at += i + 1;
        crate::tar::entry(
            &mut tar,
            &prefix[..at],
            crate::tar::DIRECTORY,
            0o755,
            0,
            b"",
        )
        .map_err(io)?;
    }
    let mut digest = Sha256::new();
    for rel in paths {
        let name = rel.as_os_str().as_bytes();
        let full = dir.join(&rel);
        let meta = std::fs::symlink_metadata(&full).map_err(io)?;
        let kind = meta.file_type();
        let mut path = prefix.to_vec();
        path.extend_from_slice(name);
        if kind.is_dir() {
            digest.update(b"d");
            digest.update(name);
            digest.update([0]);
            path.push(b'/');
            crate::tar::entry(
                &mut tar,
                &path,
                crate::tar::DIRECTORY,
                meta.mode() & 0o7777,
                0,
                b"",
            )
            .map_err(io)?;
        } else if kind.is_symlink() {
            let target = std::fs::read_link(&full).map_err(io)?;
            if target.components().any(|c| c == Component::ParentDir) {
                return Err(invalid(format!(
                    "holds {}, a symbolic link whose target contains ..",
                    rel.display()
                )));
            }
            let target = target.as_os_str().as_bytes();
            digest.update(b"l");
            digest.update(name);
            digest.update([0]);
            digest.update(target);
            digest.update([0]);
            crate::tar::entry(&mut tar, &path, crate::tar::SYMLINK, 0o777, 0, target)
                .map_err(io)?;
        } else if kind.is_file() {
            let mode = meta.mode() & 0o7777;
            let size = meta.len();
            crate::tar::entry(&mut tar, &path, crate::tar::FILE, mode, size, b"").map_err(io)?;
            let mut content = Sha256::new();
            let mut reader = std::fs::File::open(&full).map_err(io)?;
            let mut buf = vec![0u8; 65536];
            let mut copied = 0u64;
            loop {
                let n = std::io::Read::read(&mut reader, &mut buf).map_err(io)?;
                if n == 0 {
                    break;
                }
                copied += n as u64;
                if copied > size {
                    break;
                }
                content.update(&buf[..n]);
                tar.write_all(&buf[..n]).map_err(io)?;
            }
            if copied != size {
                return Err(invalid(format!("{} changed while read", rel.display())));
            }
            crate::tar::pad(&mut tar, size).map_err(io)?;
            digest.update(b"f");
            digest.update(name);
            digest.update([0]);
            digest.update(format!("{mode:04o}").as_bytes());
            digest.update(content.finalize());
        } else {
            return Err(invalid(format!(
                "holds {}, which is not a directory, regular file or symbolic link",
                rel.display()
            )));
        }
    }
    // Room for the archive's end marker.
    if tar.written + 1024 > SNAPSHOT_LIMIT {
        return Err(over());
    }
    tar.flush().map_err(io)?;
    tar.inner
        .get_ref()
        .sync_all()
        .map_err(|e| Error::Internal(e.into()))?;
    Ok(hex::encode(digest.finalize()))
}

// ---------------------------------------------------------------------
// gate set (Gate CLI and local API).

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkRequest {
    #[serde(default)]
    port: Option<i64>,
    #[serde(default)]
    connections: Option<i64>,
    #[serde(default)]
    bytes: Option<i64>,
}

/// `PUT /v1/peerboxes/{id}/gate`.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetRequest {
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    inputs_dir: Option<String>,
    #[serde(default)]
    command: Option<Vec<String>>,
    #[serde(default)]
    checker_dir: Option<String>,
    #[serde(default)]
    checker: Option<Vec<String>>,
    #[serde(default)]
    generator: Option<Vec<String>>,
    #[serde(default)]
    score: Option<String>,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    min_gain: Option<f64>,
    #[serde(default)]
    compare: Option<String>,
    #[serde(default)]
    score_range: Option<Vec<f64>>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    checker_image: Option<String>,
    #[serde(default)]
    link: Option<LinkRequest>,
    #[serde(default)]
    repeats: Option<i64>,
    #[serde(default)]
    cpus: Option<i64>,
    #[serde(default)]
    memory_mib: Option<i64>,
    #[serde(default)]
    checker_cpus: Option<i64>,
    #[serde(default)]
    checker_memory_mib: Option<i64>,
    #[serde(default)]
    timeout_seconds: Option<i64>,
    #[serde(default)]
    max_changes_bytes: Option<i64>,
}

fn field(name: &str, message: &str) -> Error {
    Error::Invalid(format!("{name} {message}"))
}
fn argv(name: &str, v: &[String]) -> Result<(), Error> {
    let total: usize = v.iter().map(String::len).sum();
    if v.is_empty() || v.len() > 64 || total > 4096 || v.iter().any(|s| s.contains('\0')) {
        return Err(field(
            name,
            "is 1 to 64 strings of at most 4,096 bytes summed, without NUL",
        ));
    }
    Ok(())
}
/// Whether `r` is an OCI reference with a digest (PBX-28).
fn pinned(r: &str) -> bool {
    let Some((name, hex)) = r.rsplit_once("@sha256:") else {
        return false;
    };
    (1..=1024).contains(&r.len())
        && !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_graphic())
        && hex.len() == 64
        && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn within(name: &str, v: i64, lo: i64, hi: i64) -> Result<i64, Error> {
    if (lo..=hi).contains(&v) {
        Ok(v)
    } else {
        Err(field(name, &format!("is {lo} to {hi}")))
    }
}

/// A gate's settings after the checks that need no runtime, without the
/// snapshot digests, salt and version.
struct Checked {
    gate: Gate,
    inputs_dir: PathBuf,
    checker_dir: PathBuf,
}

fn check_request(r: SetRequest) -> Result<Checked, Error> {
    let missing = |name: &str| field(name, "is required");
    let inputs_dir = r.inputs_dir.ok_or_else(|| missing("inputs_dir"))?;
    let command = r.command.ok_or_else(|| missing("command"))?;
    let checker_dir = r.checker_dir.ok_or_else(|| missing("checker_dir"))?;
    let checker = r.checker.ok_or_else(|| missing("checker"))?;
    let score = r.score.ok_or_else(|| missing("score"))?;
    let direction = r.direction.ok_or_else(|| missing("direction"))?;
    let min_gain = r.min_gain.ok_or_else(|| missing("min_gain"))?;
    let mode = r.mode.unwrap_or_else(|| "outputs".into());
    let compare = r.compare.unwrap_or_else(|| "worst_best".into());
    if !matches!(mode.as_str(), "outputs" | "episode") {
        return Err(field("mode", "is outputs or episode"));
    }
    if !matches!(score.as_str(), "time" | "checker") {
        return Err(field("score", "is time or checker"));
    }
    if !matches!(direction.as_str(), "lower" | "higher") {
        return Err(field("direction", "is lower or higher"));
    }
    if !matches!(
        compare.as_str(),
        "worst_best" | "paired_normal" | "paired_bounded"
    ) {
        return Err(field(
            "compare",
            "is worst_best, paired_normal or paired_bounded",
        ));
    }
    let episode = mode == "episode";
    let paired = compare != "worst_best";
    if score == "time" && episode {
        return Err(field("score", "time is refused in episode mode (PBX-29)"));
    }
    if score == "time" && paired {
        return Err(field("score", "time is refused with a paired compare"));
    }
    if episode && r.generator.is_some() {
        return Err(field("generator", "is only for outputs mode"));
    }
    if !episode && r.link.is_some() {
        return Err(field("link", "is only for episode mode"));
    }
    let link = match (episode, r.link) {
        (
            true,
            Some(LinkRequest {
                port: Some(p),
                connections,
                bytes,
            }),
        ) => Some(Link {
            port: p,
            connections: connections.unwrap_or(16),
            bytes: bytes.unwrap_or(268_435_456),
        }),
        (true, _) => return Err(field("link", "port is required in episode mode")),
        (false, _) => None,
    };
    if compare == "paired_bounded" && r.score_range.is_none() {
        return Err(field("score_range", "is required with paired_bounded"));
    }
    if compare != "paired_bounded" && r.score_range.is_some() {
        return Err(field("score_range", "is only for paired_bounded"));
    }
    if r.image.as_deref().is_some_and(|i| !pinned(i)) {
        return Err(field(
            "image",
            "is a reference with a digest, NAME@sha256: and 64 lowercase hex digits",
        ));
    }
    if r.checker_image.as_deref().is_some_and(|i| !pinned(i)) {
        return Err(field(
            "checker_image",
            "is a reference with a digest, NAME@sha256: and 64 lowercase hex digits",
        ));
    }
    argv("command", &command)?;
    argv("checker", &checker)?;
    if let Some(g) = &r.generator {
        argv("generator", g)?;
    }
    let cents = min_gain * 100.0;
    if !(0.0..=1000.0).contains(&min_gain) || (cents - cents.round()).abs() > 1e-6 {
        return Err(field("min_gain", "is 0 to 1,000 with at most two decimals"));
    }
    let score_range = match r.score_range {
        Some(v) => match v[..] {
            [lo, hi] if lo.is_finite() && hi.is_finite() && 0.0 < lo && lo < hi => Some([lo, hi]),
            _ => {
                return Err(field(
                    "score_range",
                    "is two finite numbers with 0 < LO < HI",
                ));
            }
        },
        None => None,
    };
    if let Some(l) = &link {
        within("link", l.port, 1, 65_535)?;
        within("link", l.connections, 1, 64)?;
        within("link", l.bytes, 1, 1_073_741_824)?;
    }
    let repeats = within("repeats", r.repeats.unwrap_or(1), 1, 5)?;
    let cpus = within("cpus", r.cpus.unwrap_or(2), 1, 64)?;
    let memory_mib = within("memory_mib", r.memory_mib.unwrap_or(2048), 128, 262_144)?;
    let checker_cpus = within("checker_cpus", r.checker_cpus.unwrap_or(cpus), 1, 64)?;
    let checker_memory_mib = within(
        "checker_memory_mib",
        r.checker_memory_mib.unwrap_or(memory_mib),
        128,
        262_144,
    )?;
    let timeout_seconds = within(
        "timeout_seconds",
        r.timeout_seconds.unwrap_or(900),
        1,
        86_400,
    )?;
    let max_changes_bytes = within(
        "max_changes_bytes",
        r.max_changes_bytes.unwrap_or(104_857_600),
        1,
        104_857_600,
    )?;
    let (inputs_dir, checker_dir) = (PathBuf::from(inputs_dir), PathBuf::from(checker_dir));
    if !inputs_dir.is_absolute() {
        return Err(field("inputs_dir", "must be an absolute path"));
    }
    if !checker_dir.is_absolute() {
        return Err(field("checker_dir", "must be an absolute path"));
    }
    Ok(Checked {
        gate: Gate {
            version: 0,
            paused_reason: None,
            mode,
            command,
            inputs_sha256: String::new(),
            checker,
            checker_sha256: String::new(),
            generator: r.generator,
            score,
            direction,
            min_gain,
            repeats,
            compare,
            score_range,
            image: r.image,
            checker_image: r.checker_image,
            link,
            cpus,
            memory_mib,
            timeout_seconds,
            checker_cpus,
            checker_memory_mib,
            max_changes_bytes,
            salt: String::new(),
            commitment: String::new(),
            frontier: None,
        },
        inputs_dir,
        checker_dir,
    })
}

fn conflict(code: &'static str, message: impl Into<String>) -> Error {
    Error::Coded {
        status: 409,
        code,
        message: message.into(),
        extra: Default::default(),
    }
}

/// The runtime's checks of `gate set`: its report through the switch
/// (503 without one, PBX-34), images, links and two slots, and each bound
/// at most what it reports.
async fn check_runtime(store: &Arc<Store>, g: &Gate) -> Result<(), Error> {
    let switch = blocking(store.clone(), |s| s.runtime_switch()).await?;
    let Some(switch) = switch else {
        return Err(Error::Unavailable(
            "the runtime's local switch is off; turn it on with runtime enable".into(),
        ));
    };
    let report = crate::runtime::report(&switch.socket)
        .await
        .map_err(Error::Unavailable)?;
    if (g.image.is_some() || g.checker_image.is_some()) && report["images"] != json!(true) {
        return Err(conflict(
            "runtime_unsupported",
            "the runtime does not report images, so a gate cannot name an image",
        ));
    }
    if g.mode == "episode"
        && (report["links"] != json!(true)
            || report["max_concurrent_runs"].as_i64().unwrap_or(0) < 2)
    {
        return Err(conflict(
            "runtime_unsupported",
            "an episode gate needs a runtime that reports links and at least 2 concurrent runs",
        ));
    }
    let max = |k: &str| report[k].as_i64().unwrap_or(i64::MAX);
    for (name, value, limit) in [
        ("cpus", g.cpus, max("max_cpus")),
        ("memory_mib", g.memory_mib, max("max_memory_mib")),
        ("timeout_seconds", g.timeout_seconds, max("max_seconds")),
        ("checker_cpus", g.checker_cpus, max("max_cpus")),
        (
            "checker_memory_mib",
            g.checker_memory_mib,
            max("max_memory_mib"),
        ),
    ] {
        if value > limit {
            return Err(field(
                name,
                &format!("is at most what the runtime reports, {limit}"),
            ));
        }
    }
    Ok(())
}

fn random_hex() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::Internal(anyhow::anyhow!("random source: {e}")))?;
    Ok(hex::encode(bytes))
}

async fn set_gate(store: Arc<Store>, id: String, request: SetRequest) -> Result<Value, Error> {
    let checked = check_request(request)?;
    if checked.gate.mode != "episode" {
        // Outputs mode (candidate runs with check runs, and the generator)
        // is not evaluated by this host yet.
        return Err(conflict(
            "not_implemented",
            "mode outputs is not implemented on this host yet; use --mode episode",
        ));
    }
    {
        let id = id.clone();
        blocking(store.clone(), move |s| {
            let conn = s.connection()?;
            record(&conn, &id)?.ok_or(Error::NotFound)?;
            busy(&conn, &id)
        })
        .await?;
    }
    if checked.gate.compare != "worst_best" {
        // Paired comparison is the next slice.
        return Err(conflict(
            "not_implemented",
            "paired comparison is not implemented on this host yet",
        ));
    }
    check_runtime(&store, &checked.gate).await?;
    blocking(store, move |s| {
        contribution::with_lock(&id, || set_locked(s, &id, checked))
    })
    .await
}
fn busy(conn: &Connection, id: &str) -> Result<(), Error> {
    if super::evaluation::running(conn, id)?.is_some() {
        return Err(conflict(
            "gate_busy",
            "an evaluation is running; try again once it has decided",
        ));
    }
    Ok(())
}
fn set_locked(store: &Store, id: &str, checked: Checked) -> Result<Value, Error> {
    let conn = store.connection()?;
    record(&conn, id)?.ok_or(Error::NotFound)?;
    busy(&conn, id)?;
    let previous: Option<i64> = conn
        .query_row(
            "SELECT version FROM peerbox_gates WHERE peerbox_id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    let old = load(&conn, id)?;
    drop(conn);
    let mut gate = checked.gate;
    gate.version = previous.unwrap_or(0) + 1;
    let dir = gates_dir(store).join(id);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| Error::Internal(e.into()))?;
    }
    let (inputs, checker) = gate.parts(store, id);
    let made = (|| -> Result<(), Error> {
        gate.inputs_sha256 = snapshot(&checked.inputs_dir, "inputs_dir", INPUTS_PREFIX, &inputs)?;
        gate.checker_sha256 = snapshot(&checked.checker_dir, "checker_dir", b"", &checker)?;
        Ok(())
    })();
    if let Err(e) = made {
        let _ = std::fs::remove_file(&inputs);
        let _ = std::fs::remove_file(&checker);
        return Err(e);
    }
    gate.salt = random_hex()?;
    gate.commitment = commitment(&gate);
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    save(&tx, id, &gate)?;
    append_event(&tx, "peerbox.gate_set", id, &now())?;
    tx.commit()?;
    if let Some(old) = old {
        let (a, b) = old.parts(store, id);
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }
    let switch_on = store.runtime_switch()?.is_some();
    Ok(gate.view(switch_on))
}

fn change(store: &Store, id: &str, pause: bool) -> Result<Value, Error> {
    contribution::with_lock(id, || {
        let mut conn = store.connection()?;
        let tx = conn.transaction()?;
        let mut gate = load(&tx, id)?.ok_or(Error::NotFound)?;
        if pause {
            gate.paused_reason = Some("owner".into());
            append_event(&tx, "peerbox.gate_paused", id, &now())?;
        } else {
            gate.paused_reason = None;
        }
        save(&tx, id, &gate)?;
        tx.commit()?;
        Ok(gate.view(store.runtime_switch()?.is_some()))
    })
}

/// Pauses a gate with `reason` (an evaluation's outcome), unless it was
/// cleared or set again meanwhile.
pub(crate) fn pause_with(store: &Store, id: &str, version: i64, reason: &str) -> Result<(), Error> {
    let mut conn = store.connection()?;
    let tx = conn.transaction()?;
    if let Some(mut gate) = load(&tx, id)?
        && gate.version == version
    {
        gate.paused_reason = Some(reason.into());
        save(&tx, id, &gate)?;
        append_event(&tx, "peerbox.gate_paused", id, &now())?;
    }
    tx.commit()?;
    Ok(())
}

fn clear(store: &Store, id: &str) -> Result<Value, Error> {
    contribution::with_lock(id, || {
        let mut conn = store.connection()?;
        let tx = conn.transaction()?;
        let gate = load(&tx, id)?.ok_or(Error::NotFound)?;
        tx.execute(
            "UPDATE peerbox_gates SET record = NULL WHERE peerbox_id = ?1",
            [id],
        )?;
        tx.commit()?;
        // A running evaluation sees the gate gone and cancels its runs; its
        // snapshot parts go once it has.
        if super::evaluation::running(&*store.connection()?, id)?.is_none() {
            let (a, b) = gate.parts(store, id);
            let _ = std::fs::remove_file(a);
            let _ = std::fs::remove_file(b);
        }
        Ok(json!({"peerbox_id": id, "gate": null}))
    })
}

fn show(store: &Store, id: &str) -> Result<Value, Error> {
    let conn = store.connection()?;
    record(&conn, id)?.ok_or(Error::NotFound)?;
    let gate = load(&conn, id)?.ok_or(Error::NotFound)?;
    let switch_on = store.runtime_switch()?.is_some();
    Ok(json!({
        "gate": gate.view(switch_on),
        "queue": queue(&conn, id)?,
        "evaluations": super::evaluation::shown(&conn, id)?,
    }))
}

/// Deletes a peerbox's gate and evaluations with the peerbox.
pub(crate) fn delete_with(conn: &Connection, id: &str) -> Result<(), Error> {
    conn.execute("DELETE FROM peerbox_gates WHERE peerbox_id = ?1", [id])?;
    conn.execute(
        "DELETE FROM peerbox_gate_evaluations WHERE peerbox_id = ?1",
        [id],
    )?;
    Ok(())
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route(
            "/v1/peerboxes/{id}/gate",
            get(show_route).put(set_route).delete(clear_route),
        )
        .route("/v1/peerboxes/{id}/gate/pause", post(pause_route))
        .route("/v1/peerboxes/{id}/gate/resume", post(resume_route))
}
async fn set_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let raw: Value = decode(body)?;
    let request: SetRequest = serde_json::from_value(raw).map_err(|e| {
        let text = e.to_string();
        // Name the key serde could not read, as the first word.
        let key = text
            .split('`')
            .nth(1)
            .filter(|_| text.starts_with("unknown field"))
            .unwrap_or("request");
        Error::Invalid(format!("{key} is not valid: {text}"))
    })?;
    Ok(Json(set_gate(store, id, request).await?))
}
async fn show_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| show(s, &id)).await?))
}
async fn clear_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| clear(s, &id)).await?))
}
async fn pause_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| change(s, &id, true)).await?))
}
async fn resume_route(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| change(s, &id, false)).await?))
}

/// The record a gated peerbox's gate is on, for the evaluator.
pub(crate) fn gated_record(conn: &Connection, id: &str) -> Result<Option<(Record, Gate)>, Error> {
    Ok(match (record(conn, id)?, load(conn, id)?) {
        (Some(r), Some(g)) => Some((r, g)),
        _ => None,
    })
}
