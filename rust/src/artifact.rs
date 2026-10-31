//! Task artifacts (roadmap milestone 6, slice 3): files attached to tasks as
//! inputs by the submitter or results by the receiving agent. The host that
//! holds a file advertises it in a manifest; the other party of that task
//! pulls it over the peer connection, verifies its size and SHA-256 digest,
//! and stores it under its digest. Coordination never carries artifacts.
use crate::{
    adapter::{authority, read},
    adapter_connection::AdapterAuth,
    api::blocking,
    model::Error,
    quic::LongTransfer,
    store::{Store, append_event, new_id, now, rfc3339},
    task::{is_final, time},
};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use chrono::TimeDelta;
use http_body_util::BodyExt;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

/// Database version 10: stored artifact files and each task's artifacts.
pub(crate) const SCHEMA: &str = "
CREATE TABLE artifact_files (sha256 TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE task_artifacts (side TEXT NOT NULL, peer TEXT NOT NULL, task_id TEXT NOT NULL, direction TEXT NOT NULL, sha256 TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(side, peer, task_id, direction, sha256));
PRAGMA user_version = 10;
";

/// Entries in one manifest.
pub const MAX_ENTRIES: usize = 64;
/// One artifact's size limit (100 MiB).
pub const MAX_SIZE: i64 = 104_857_600;
/// The largest `max_artifact_bytes` a grant or rule may carry (1 GiB).
pub const MAX_BOUND: i64 = 1_073_741_824;
/// The default per-host artifact quota (10 GiB).
pub const DEFAULT_QUOTA: i64 = 10 * 1024 * 1024 * 1024;
pub const DEFAULT_MEDIA_TYPE: &str = "application/octet-stream";
/// Uploads not yet referenced by a task are kept this long.
const UPLOAD_HOLD: TimeDelta = TimeDelta::hours(24);
/// A task keeps its artifacts this long after it reaches a final state.
const TASK_HOLD: TimeDelta = TimeDelta::days(7);
/// Retention sweeps run at startup and this often.
const SWEEP: Duration = Duration::from_secs(60);
/// Bytes buffered before each blocking write.
const WRITE_BATCH: usize = 1 << 20;
const READ_CHUNK: usize = 64 * 1024;

pub const SENT: &str = "sent";
pub const RECEIVED: &str = "received";
pub const INPUT: &str = "input";
pub const RESULT: &str = "result";
pub const STORED: &str = "stored";
pub const PENDING: &str = "pending";
pub const PRUNED: &str = "pruned";

/// One manifest entry: exactly these four fields, none null.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEntry {
    pub name: String,
    pub size: i64,
    pub sha256: String,
    pub media_type: String,
}

/// A task's artifact as the submitter's local record shows it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalArtifact {
    pub direction: String,
    pub name: String,
    pub size: i64,
    pub sha256: String,
    pub media_type: String,
    /// `stored`, `pending`, or `pruned`.
    pub state: String,
}

/// A `task_artifacts` record: one task's reference to an artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Row {
    pub side: String,
    pub peer_host_id: String,
    pub task_id: String,
    pub direction: String,
    pub name: String,
    pub size: i64,
    pub sha256: String,
    pub media_type: String,
    pub state: String,
}
impl Row {
    pub(crate) fn key(&self) -> RowKey {
        RowKey {
            side: self.side.clone(),
            peer: self.peer_host_id.clone(),
            task_id: self.task_id.clone(),
            direction: self.direction.clone(),
            sha256: self.sha256.clone(),
        }
    }
    /// Whether this host fetches the content from the other party.
    fn fetched_here(&self) -> bool {
        (self.side.as_str(), self.direction.as_str()) == (RECEIVED, INPUT)
            || (self.side.as_str(), self.direction.as_str()) == (SENT, RESULT)
    }
}

/// An `artifact_files` record; a row exists while the file is stored.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredFile {
    pub sha256: String,
    pub size: i64,
    pub created_at: String,
    /// 24 hours after the latest upload of this content; null once released.
    pub upload_until: Option<String>,
}

/// One stored file in `artifact list`.
#[derive(Debug, Serialize)]
pub struct FileView {
    pub sha256: String,
    pub size: i64,
    pub created_at: String,
    pub upload_until: Option<String>,
    /// Stored task references to this content.
    pub tasks: i64,
}
#[derive(Debug, Serialize)]
pub struct ArtifactList {
    pub quota: i64,
    pub stored_bytes: i64,
    pub pending_bytes: i64,
    pub files: Vec<FileView>,
}
#[derive(Debug, Default, Serialize)]
pub struct PruneResult {
    pub files_deleted: i64,
    pub bytes_freed: i64,
}

/// Identifies one task's reference to an artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct RowKey {
    pub side: String,
    pub peer: String,
    pub task_id: String,
    pub direction: String,
    pub sha256: String,
}
impl RowKey {
    /// The task worker's job key; distinct from task polls and retries.
    pub(crate) fn job(&self) -> (String, String) {
        (
            format!("artifact:{}:{}", self.side, self.peer),
            format!("{}/{}/{}", self.task_id, self.direction, self.sha256),
        )
    }
}

/// A grant's or rule's `max_artifact_bytes`: 0 to 1 GiB, and nonzero only
/// with the action `task.submit`.
pub(crate) fn check_bound(bound: i64, task_action: bool) -> Result<(), Error> {
    if !(0..=MAX_BOUND).contains(&bound) {
        return Err(Error::Invalid(
            "max_artifact_bytes must be 0 to 1073741824".into(),
        ));
    }
    if bound != 0 && !task_action {
        return Err(Error::Invalid(
            "max_artifact_bytes needs the action task.submit".into(),
        ));
    }
    Ok(())
}
pub(crate) fn valid_name(name: &str) -> bool {
    (1..=255).contains(&name.len())
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}
pub(crate) fn valid_media_type(value: &str) -> bool {
    (1..=255).contains(&value.len()) && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// 1 to 64 well-formed entries with unique names and digests.
pub(crate) fn validate_manifest(entries: &[ArtifactEntry]) -> Result<(), Error> {
    if entries.is_empty() || entries.len() > MAX_ENTRIES {
        return Err(Error::Invalid("a manifest has 1 to 64 artifacts".into()));
    }
    let mut names = std::collections::HashSet::new();
    let mut digests = std::collections::HashSet::new();
    for e in entries {
        if !valid_name(&e.name)
            || !(0..=MAX_SIZE).contains(&e.size)
            || !valid_digest(&e.sha256)
            || !valid_media_type(&e.media_type)
        {
            return Err(Error::Invalid(format!("invalid artifact {:?}", e.name)));
        }
        if !names.insert(e.name.as_str()) || !digests.insert(e.sha256.as_str()) {
            return Err(Error::Invalid(
                "artifact names and digests are unique within a manifest".into(),
            ));
        }
    }
    Ok(())
}
/// A manifest's total size, or `None` without artifacts.
pub(crate) fn manifest_total(manifest: &Option<Vec<ArtifactEntry>>) -> Option<i64> {
    manifest
        .as_ref()
        .filter(|m| !m.is_empty())
        .map(|m| m.iter().map(|e| e.size).sum())
}
/// Locally, an empty manifest is no manifest.
pub(crate) fn normalized(manifest: Option<Vec<ArtifactEntry>>) -> Option<Vec<ArtifactEntry>> {
    manifest.filter(|m| !m.is_empty())
}

fn stored_file(conn: &Connection, sha: &str) -> Result<Option<StoredFile>, Error> {
    conn.query_row(
        "SELECT record FROM artifact_files WHERE sha256 = ?1",
        [sha],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|r| Ok(serde_json::from_str(&r)?))
    .transpose()
}
fn put_file(tx: &Transaction<'_>, file: &StoredFile) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO artifact_files VALUES (?1, ?2) ON CONFLICT(sha256) DO UPDATE SET record = excluded.record",
        params![file.sha256, serde_json::to_string(file)?],
    )?;
    Ok(())
}
fn row(conn: &Connection, k: &RowKey) -> Result<Row, Error> {
    read(
        conn,
        "SELECT record FROM task_artifacts WHERE side = ?1 AND peer = ?2 AND task_id = ?3 AND direction = ?4 AND sha256 = ?5",
        params![k.side, k.peer, k.task_id, k.direction, k.sha256],
    )
}
fn put_row(tx: &Transaction<'_>, r: &Row) -> Result<(), Error> {
    tx.execute(
        "UPDATE task_artifacts SET record = ?1 WHERE side = ?2 AND peer = ?3 AND task_id = ?4 AND direction = ?5 AND sha256 = ?6",
        params![
            serde_json::to_string(r)?,
            r.side,
            r.peer_host_id,
            r.task_id,
            r.direction,
            r.sha256
        ],
    )?;
    Ok(())
}
/// Rows in one state, in insertion order.
fn rows_in(conn: &Connection, state: &str) -> Result<Vec<Row>, Error> {
    let mut statement = conn.prepare(
        "SELECT record FROM task_artifacts WHERE json_extract(record, '$.state') = ?1 ORDER BY rowid",
    )?;
    statement
        .query_map([state], |r| r.get::<_, String>(0))?
        .map(|r| Ok(serde_json::from_str(&r?)?))
        .collect()
}
/// Bytes of stored files, and of pending fetches whose content is not yet
/// stored (each digest once).
pub(crate) fn usage(conn: &Connection) -> Result<(i64, i64), Error> {
    Ok(conn.query_row(
        "SELECT (SELECT COALESCE(SUM(json_extract(record, '$.size')), 0) FROM artifact_files), (SELECT COALESCE(SUM(size), 0) FROM (SELECT MAX(json_extract(record, '$.size')) AS size FROM task_artifacts WHERE json_extract(record, '$.state') = 'pending' AND sha256 NOT IN (SELECT sha256 FROM artifact_files) GROUP BY sha256))",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}
/// One task's artifacts on one side, in manifest order: inputs, then
/// results.
pub(crate) fn task_artifacts(
    conn: &Connection,
    side: &str,
    peer: &str,
    task_id: &str,
) -> Result<Vec<LocalArtifact>, Error> {
    let mut statement = conn.prepare(
        "SELECT record FROM task_artifacts WHERE side = ?1 AND peer = ?2 AND task_id = ?3 ORDER BY rowid",
    )?;
    let rows = statement
        .query_map(params![side, peer, task_id], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|r| {
            let r: Row = serde_json::from_str(&r)?;
            Ok(LocalArtifact {
                direction: r.direction,
                name: r.name,
                size: r.size,
                sha256: r.sha256,
                media_type: r.media_type,
                state: r.state,
            })
        })
        .collect()
}

/// Records one task's manifest in order. Content already stored is
/// stored at once; otherwise the entry has the given state.
pub(crate) fn add_artifacts(
    tx: &Transaction<'_>,
    side: &str,
    peer: &str,
    task_id: &str,
    direction: &str,
    entries: &[ArtifactEntry],
    state: &str,
) -> Result<(), Error> {
    for e in entries {
        let stored = state == STORED || stored_file(tx, &e.sha256)?.is_some();
        let r = Row {
            side: side.into(),
            peer_host_id: peer.into(),
            task_id: task_id.into(),
            direction: direction.into(),
            name: e.name.clone(),
            size: e.size,
            sha256: e.sha256.clone(),
            media_type: e.media_type.clone(),
            state: if stored { STORED } else { state }.into(),
        };
        tx.execute(
            "INSERT OR IGNORE INTO task_artifacts VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                side,
                peer,
                task_id,
                direction,
                e.sha256,
                serde_json::to_string(&r)?
            ],
        )?;
    }
    Ok(())
}

impl Store {
    pub(crate) fn artifact_dir(&self) -> PathBuf {
        self.state_directory().join("artifacts")
    }
    fn artifact_path(&self, sha: &str) -> PathBuf {
        self.artifact_dir().join(sha)
    }
    /// A temporary name beside the stored files, never a digest.
    fn temporary_path(&self) -> Result<PathBuf, Error> {
        Ok(self.artifact_dir().join(new_id("partial")?))
    }
    pub fn set_artifact_quota(&self, bytes: i64) {
        self.artifact_quota
            .store(bytes.max(1), std::sync::atomic::Ordering::Relaxed);
    }
    pub(crate) fn artifact_quota(&self) -> i64 {
        self.artifact_quota
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Creates the private artifact directory and removes every entry that
    /// is not a recorded digest, such as a download a crash interrupted
    /// before its rename.
    pub(crate) fn prepare_artifacts(&self, conn: &Connection) -> anyhow::Result<()> {
        let dir = self.artifact_dir();
        DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        let metadata = fs::symlink_metadata(&dir)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("artifact directory must be a private directory (mode 0700)");
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let recorded: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM artifact_files WHERE sha256 = ?1)",
                [&name],
                |r| r.get(0),
            )?;
            if !recorded {
                let path = entry.path();
                if entry.file_type()?.is_dir() {
                    fs::remove_dir_all(path)?;
                } else {
                    fs::remove_file(path)?;
                }
            }
        }
        Ok(())
    }

    /// Every entry must name a stored file of that size and digest.
    pub(crate) fn check_uploads(
        &self,
        conn: &Connection,
        entries: &[ArtifactEntry],
    ) -> Result<(), Error> {
        for e in entries {
            if stored_file(conn, &e.sha256)?.is_none_or(|f| f.size != e.size) {
                return Err(Error::Invalid(format!(
                    "artifact {} is not a stored upload of {} bytes",
                    e.name, e.size
                )));
            }
        }
        Ok(())
    }
    /// Refuses a manifest whose content not yet stored would exceed the
    /// quota together with stored files and pending fetches (507).
    pub(crate) fn reserve(
        &self,
        conn: &Connection,
        entries: &[ArtifactEntry],
    ) -> Result<(), Error> {
        let mut need = 0;
        for e in entries {
            if stored_file(conn, &e.sha256)?.is_none() {
                need += e.size;
            }
        }
        if need == 0 {
            return Ok(());
        }
        let (stored, pending) = usage(conn)?;
        if stored + pending + need > self.artifact_quota() {
            return Err(Error::InsufficientStorage(
                "the artifact quota is exhausted".into(),
            ));
        }
        Ok(())
    }
    /// Stores a completed upload under its digest, holding it for 24 hours.
    /// New content over the quota is refused (507).
    pub(crate) fn finish_upload(
        &self,
        temp: PathBuf,
        size: i64,
        sha: String,
        name: String,
        media_type: String,
    ) -> Result<ArtifactEntry, Error> {
        let result = (|| {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let at = crate::clock::now();
            let until = Some(rfc3339(at + UPLOAD_HOLD));
            let file = match stored_file(&tx, &sha)? {
                Some(mut file) => {
                    file.upload_until = until;
                    file
                }
                None => {
                    let (stored, pending) = usage(&tx)?;
                    if stored + pending + size > self.artifact_quota() {
                        return Err(Error::InsufficientStorage(
                            "the artifact quota is exhausted".into(),
                        ));
                    }
                    fs::rename(&temp, self.artifact_path(&sha))
                        .map_err(|e| Error::Internal(e.into()))?;
                    StoredFile {
                        sha256: sha.clone(),
                        size,
                        created_at: rfc3339(at),
                        upload_until: until,
                    }
                }
            };
            put_file(&tx, &file)?;
            tx.commit()?;
            Ok(ArtifactEntry {
                name,
                size,
                sha256: sha,
                media_type,
            })
        })();
        // Removes the temporary file unless it was renamed.
        let _ = fs::remove_file(&temp);
        result
    }

    /// Pending fetches: inputs of received tasks still queued, and results
    /// of sent tasks.
    pub(crate) fn pending_fetches(&self) -> Result<Vec<RowKey>, Error> {
        let conn = self.connection()?;
        let mut due = Vec::new();
        for r in rows_in(&conn, PENDING)? {
            if !r.fetched_here() {
                continue;
            }
            if r.side == RECEIVED {
                let queued: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM received_tasks WHERE sender = ?1 AND task_id = ?2 AND json_extract(record, '$.state') = 'queued')",
                    params![r.peer_host_id, r.task_id],
                    |q| q.get(0),
                )?;
                if !queued {
                    continue;
                }
            }
            due.push(r.key());
        }
        Ok(due)
    }
    /// The size to fetch, or `None` when the row no longer needs a fetch
    /// (content stored meanwhile completes it here). A fetch starts only
    /// while stored files and it fit the quota.
    fn fetch_plan(&self, k: &RowKey) -> Result<Option<i64>, Error> {
        let r = row(&*self.connection()?, k)?;
        if r.state != PENDING {
            return Ok(None);
        }
        if stored_file(&*self.connection()?, &k.sha256)?.is_some() {
            self.fetched(k, None)?;
            return Ok(None);
        }
        let (stored, _) = usage(&*self.connection()?)?;
        if stored + r.size > self.artifact_quota() {
            return Err(Error::InsufficientStorage(
                "the artifact quota is exhausted; waiting".into(),
            ));
        }
        Ok(Some(r.size))
    }
    /// Stores verified content under its digest and marks every pending
    /// reference to it stored, each with `task.artifact_fetched`.
    pub(crate) fn fetched(&self, k: &RowKey, temp: Option<PathBuf>) -> Result<(), Error> {
        let result = (|| {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let at = now();
            if stored_file(&tx, &k.sha256)?.is_none() {
                let Some(temp) = &temp else {
                    return Ok(());
                };
                let size = row(&tx, k)?.size;
                fs::rename(temp, self.artifact_path(&k.sha256))
                    .map_err(|e| Error::Internal(e.into()))?;
                put_file(
                    &tx,
                    &StoredFile {
                        sha256: k.sha256.clone(),
                        size,
                        created_at: at.clone(),
                        upload_until: None,
                    },
                )?;
            }
            for mut r in rows_in(&tx, PENDING)? {
                if r.sha256 != k.sha256 {
                    continue;
                }
                r.state = STORED.into();
                put_row(&tx, &r)?;
                append_event(
                    &tx,
                    "task.artifact_fetched",
                    &format!("{}/{}/{}", r.peer_host_id, r.task_id, r.sha256),
                    &at,
                )?;
            }
            tx.commit()?;
            Ok(())
        })();
        if let Some(temp) = temp {
            let _ = fs::remove_file(temp);
        }
        result
    }

    /// Whether a task has released its artifacts: 7 days after it reached a
    /// final state, or at once for `prune`; an outbound task never accepted
    /// 7 days after its deadline.
    fn released(&self, conn: &Connection, r: &Row, all: bool) -> Result<bool, Error> {
        let at = crate::clock::now();
        let after = |final_at: &serde_json::Value| -> Result<bool, Error> {
            Ok(all || time(final_at.as_str().unwrap_or_default())? + TASK_HOLD <= at)
        };
        if r.side == RECEIVED {
            let record: Option<String> = conn
                .query_row(
                    "SELECT record FROM received_tasks WHERE sender = ?1 AND task_id = ?2",
                    params![r.peer_host_id, r.task_id],
                    |q| q.get(0),
                )
                .optional()?;
            let Some(record) = record else {
                return Ok(true);
            };
            let v: serde_json::Value = serde_json::from_str(&record)?;
            if !is_final(v["state"].as_str().unwrap_or_default()) {
                return Ok(false);
            }
            return after(&v["updated_at"]);
        }
        let record: Option<String> = conn
            .query_row(
                "SELECT record FROM outbound_tasks WHERE peer = ?1 AND task_id = ?2",
                params![r.peer_host_id, r.task_id],
                |q| q.get(0),
            )
            .optional()?;
        let Some(record) = record else {
            return Ok(true);
        };
        let v: serde_json::Value = serde_json::from_str(&record)?;
        let status = &v["status"];
        if is_final(status["state"].as_str().unwrap_or_default()) {
            return after(&status["updated_at"]);
        }
        match v["submit_state"].as_str().unwrap_or_default() {
            "accepted" => Ok(false),
            state => Ok((all && state == "rejected")
                || time(v["request"]["deadline"].as_str().unwrap_or_default())? + TASK_HOLD <= at),
        }
    }
    /// Releases the artifacts of tasks that no longer keep them (with `all`,
    /// every final task's and every upload hold), then deletes each file
    /// nothing keeps, with `artifact.pruned`.
    pub fn prune_artifacts(&self, all: bool) -> Result<PruneResult, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let at = crate::clock::now();
        let stamp = rfc3339(at);
        for state in [STORED, PENDING] {
            for mut r in rows_in(&tx, state)? {
                if self.released(&tx, &r, all)? {
                    r.state = PRUNED.into();
                    put_row(&tx, &r)?;
                }
            }
        }
        let files: Vec<StoredFile> = {
            let mut statement = tx.prepare("SELECT record FROM artifact_files ORDER BY sha256")?;
            statement
                .query_map([], |r| r.get::<_, String>(0))?
                .map(|r| Ok(serde_json::from_str(&r?)?))
                .collect::<Result<_, Error>>()?
        };
        let mut result = PruneResult::default();
        let mut deleted = Vec::new();
        for mut file in files {
            if let Some(until) = &file.upload_until
                && (all || time(until)? <= at)
            {
                file.upload_until = None;
                put_file(&tx, &file)?;
            }
            let referenced: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE sha256 = ?1 AND json_extract(record, '$.state') = 'stored')",
                [&file.sha256],
                |r| r.get(0),
            )?;
            if file.upload_until.is_some() || referenced {
                continue;
            }
            tx.execute(
                "DELETE FROM artifact_files WHERE sha256 = ?1",
                [&file.sha256],
            )?;
            append_event(&tx, "artifact.pruned", &file.sha256, &stamp)?;
            result.files_deleted += 1;
            result.bytes_freed += file.size;
            deleted.push(file.sha256);
        }
        tx.commit()?;
        drop(conn);
        for sha in deleted {
            let _ = fs::remove_file(self.artifact_path(&sha));
        }
        Ok(result)
    }
    pub fn artifact_list(&self) -> Result<ArtifactList, Error> {
        let conn = self.connection()?;
        let mut statement = conn.prepare(
            "SELECT f.record, (SELECT COUNT(*) FROM task_artifacts t WHERE t.sha256 = f.sha256 AND json_extract(t.record, '$.state') = 'stored') FROM artifact_files f ORDER BY f.sha256",
        )?;
        let files = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(record, tasks)| {
                let f: StoredFile = serde_json::from_str(&record)?;
                Ok(FileView {
                    sha256: f.sha256,
                    size: f.size,
                    created_at: f.created_at,
                    upload_until: f.upload_until,
                    tasks,
                })
            })
            .collect::<Result<_, Error>>()?;
        let (stored_bytes, pending_bytes) = usage(&conn)?;
        Ok(ArtifactList {
            quota: self.artifact_quota(),
            stored_bytes,
            pending_bytes,
            files,
        })
    }

    /// Opens the stored artifact one of a task's rows names: a stored row
    /// serves, a pending one is 409, and anything else is not found.
    fn open_listed(&self, conn: &Connection, rows: &[Row]) -> Result<(File, u64), Error> {
        let Some(r) = rows.iter().find(|r| r.state == STORED) else {
            if rows.iter().any(|r| r.state == PENDING) {
                return Err(Error::Conflict("the artifact is not yet fetched".into()));
            }
            return Err(Error::NotFound);
        };
        if stored_file(conn, &r.sha256)?.is_none() {
            return Err(Error::NotFound);
        }
        let file = File::open(self.artifact_path(&r.sha256)).map_err(|_| Error::NotFound)?;
        let len = file
            .metadata()
            .map_err(|e| Error::Internal(e.into()))?
            .len();
        Ok((file, len))
    }
    fn rows_of(
        &self,
        conn: &Connection,
        side: &str,
        peer: &str,
        task_id: &str,
        sha: &str,
        directions: &[&str],
    ) -> Result<Vec<Row>, Error> {
        let mut found = Vec::new();
        for direction in directions {
            let k = RowKey {
                side: side.into(),
                peer: peer.into(),
                task_id: task_id.into(),
                direction: (*direction).into(),
                sha256: sha.into(),
            };
            match row(conn, &k) {
                Ok(r) => found.push(r),
                Err(Error::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(found)
    }
    /// What a peer may fetch: an input of a task this host submitted to it,
    /// or a result of a task it submitted here. Nothing is reauthorized.
    pub(crate) fn peer_artifact(
        &self,
        requester: &str,
        task_id: &str,
        sha: &str,
    ) -> Result<(File, u64), Error> {
        let conn = self.connection()?;
        let mut rows = self.rows_of(&conn, SENT, requester, task_id, sha, &[INPUT])?;
        rows.extend(self.rows_of(&conn, RECEIVED, requester, task_id, sha, &[RESULT])?);
        rows.retain(|r| r.state == STORED);
        self.open_listed(&conn, &rows)
    }
    /// An input or fetched result of an outbound task.
    pub(crate) fn outbound_artifact(
        &self,
        peer: &str,
        task_id: &str,
        sha: &str,
    ) -> Result<(File, u64), Error> {
        let conn = self.connection()?;
        let rows = self.rows_of(&conn, SENT, peer, task_id, sha, &[INPUT, RESULT])?;
        self.open_listed(&conn, &rows)
    }
    /// An input or fetched result of a task this credential submitted.
    pub(crate) fn delegation_artifact(
        &self,
        auth: &AdapterAuth,
        task_id: &str,
        sha: &str,
    ) -> Result<(File, u64), Error> {
        let conn = self.connection()?;
        let (a, _) = authority(&conn, auth)?;
        let peer: Option<String> = conn
            .query_row(
                "SELECT peer FROM outbound_tasks WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2 ORDER BY rowid LIMIT 1",
                params![task_id, a.id],
                |r| r.get(0),
            )
            .optional()?;
        let peer = peer.ok_or(Error::NotFound)?;
        let rows = self.rows_of(&conn, SENT, &peer, task_id, sha, &[INPUT, RESULT])?;
        self.open_listed(&conn, &rows)
    }
    /// An input or result of a task this session claimed; a task claimed by
    /// another session or credential is forbidden.
    pub(crate) fn claimed_artifact(
        &self,
        auth: &AdapterAuth,
        task_id: &str,
        sha: &str,
    ) -> Result<(File, u64), Error> {
        let conn = self.connection()?;
        let (a, ss) = authority(&conn, auth)?;
        let sender: Option<String> = conn
            .query_row(
                "SELECT sender FROM task_deliveries WHERE task_id = ?1 AND session_id = ?2 AND json_extract(record, '$.adapter_id') = ?3 ORDER BY rowid LIMIT 1",
                params![task_id, ss.id, a.id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(sender) = sender else {
            let known: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM received_tasks WHERE task_id = ?1)",
                [task_id],
                |r| r.get(0),
            )?;
            return Err(if known {
                Error::Forbidden
            } else {
                Error::NotFound
            });
        };
        let rows = self.rows_of(&conn, RECEIVED, &sender, task_id, sha, &[INPUT, RESULT])?;
        self.open_listed(&conn, &rows)
    }
}

/// Writes a stream to a private temporary file while counting and hashing
/// it. Writes happen on blocking workers in batches.
pub(crate) struct Sink {
    file: Option<File>,
    path: PathBuf,
    hasher: Sha256,
    buffer: Vec<u8>,
    size: u64,
    limit: u64,
}
impl Sink {
    pub(crate) async fn create(store: &Arc<Store>, limit: u64) -> Result<Self, Error> {
        let path = store.temporary_path()?;
        let at = path.clone();
        let file = tokio::task::spawn_blocking(move || {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(at)
        })
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(|e| Error::Internal(e.into()))?;
        Ok(Self {
            file: Some(file),
            path,
            hasher: Sha256::new(),
            buffer: Vec::with_capacity(WRITE_BATCH),
            size: 0,
            limit,
        })
    }
    /// Appends data; more than the limit is `TooLarge`.
    pub(crate) async fn push(&mut self, data: &[u8]) -> Result<(), Error> {
        self.size += data.len() as u64;
        if self.size > self.limit {
            return Err(Error::TooLarge(
                "the artifact exceeds its size limit".into(),
            ));
        }
        self.hasher.update(data);
        self.buffer.extend_from_slice(data);
        if self.buffer.len() >= WRITE_BATCH {
            self.flush(false).await?;
        }
        Ok(())
    }
    async fn flush(&mut self, sync: bool) -> Result<(), Error> {
        let mut file = self
            .file
            .take()
            .ok_or_else(|| Error::Internal(anyhow::anyhow!("artifact file closed")))?;
        let buffer = std::mem::take(&mut self.buffer);
        let (file, buffer) = tokio::task::spawn_blocking(move || {
            file.write_all(&buffer)?;
            if sync {
                file.sync_all()?;
            }
            Ok::<_, std::io::Error>((file, buffer))
        })
        .await
        .map_err(|e| Error::Internal(e.into()))?
        .map_err(|e| Error::Internal(e.into()))?;
        self.file = Some(file);
        self.buffer = buffer;
        self.buffer.clear();
        Ok(())
    }
    /// Flushes and syncs the file; returns its path, size, and digest.
    pub(crate) async fn finish(mut self) -> Result<(PathBuf, u64, String), Error> {
        self.flush(true).await?;
        self.file = None;
        let path = std::mem::take(&mut self.path);
        let digest = hex::encode(std::mem::take(&mut self.hasher).finalize());
        Ok((path, self.size, digest))
    }
    pub(crate) async fn discard(mut self) {
        self.file = None;
        let path = std::mem::take(&mut self.path);
        let _ = tokio::task::spawn_blocking(move || fs::remove_file(path)).await;
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        // Only an abandoned sink still owns its file.
        if !self.path.as_os_str().is_empty() {
            let path = std::mem::take(&mut self.path);
            tokio::task::spawn_blocking(move || fs::remove_file(path));
        }
    }
}

/// A file's bytes as a response or request body, read on a blocking worker.
pub struct FileBody {
    receiver: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>,
    len: u64,
}
impl FileBody {
    pub fn new(mut file: File, len: u64) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::task::spawn_blocking(move || {
            let mut remaining = len;
            while remaining > 0 {
                let mut chunk = vec![0u8; READ_CHUNK.min(remaining as usize)];
                match file.read(&mut chunk) {
                    Ok(0) => {
                        let _ = sender.blocking_send(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "artifact file truncated",
                        )));
                        return;
                    }
                    Ok(n) => {
                        chunk.truncate(n);
                        remaining -= n as u64;
                        if sender.blocking_send(Ok(Bytes::from(chunk))).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = sender.blocking_send(Err(e));
                        return;
                    }
                }
            }
        });
        Self { receiver, len }
    }
}
impl hyper::body::Body for FileBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
        self.receiver
            .poll_recv(cx)
            .map(|chunk| chunk.map(|c| c.map(hyper::body::Frame::data)))
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.len)
    }
}
fn file_response(file: File, len: u64) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        Body::new(FileBody::new(file, len)),
    )
        .into_response()
}

/// Receives an upload into a temporary file and stores it.
async fn upload(
    store: Arc<Store>,
    query: Result<Query<UploadQuery>, QueryRejection>,
    headers: &HeaderMap,
    body: Body,
) -> Result<ArtifactEntry, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid upload query".into()))?;
    let name = q.name.unwrap_or_default();
    let media_type = q.media_type.unwrap_or_else(|| DEFAULT_MEDIA_TYPE.into());
    if !valid_name(&name) {
        return Err(Error::Invalid("invalid artifact name".into()));
    }
    if !valid_media_type(&media_type) {
        return Err(Error::Invalid("invalid media type".into()));
    }
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let mut body = body;
    let too_large = || Error::TooLarge("an artifact is at most 104857600 bytes".into());
    if declared.is_some_and(|n| n > MAX_SIZE as u64) {
        drain(&mut body).await;
        return Err(too_large());
    }
    let mut sink = Sink::create(&store, MAX_SIZE as u64).await?;
    loop {
        match body.frame().await {
            None => break,
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data()
                    && let Err(e) = sink.push(&data).await
                {
                    sink.discard().await;
                    if matches!(e, Error::TooLarge(_)) {
                        drain(&mut body).await;
                    }
                    return Err(e);
                }
            }
            Some(Err(_)) => {
                sink.discard().await;
                return Err(Error::Invalid("upload interrupted".into()));
            }
        }
    }
    let (temp, size, sha) = sink.finish().await?;
    blocking(store, move |s| {
        s.finish_upload(temp, size as i64, sha, name, media_type)
    })
    .await
}

/// Reads and discards the rest of a refused upload, so the client sees the
/// response instead of a reset; bounded, since the client could send forever.
async fn drain(body: &mut Body) {
    let mut drained: u64 = 0;
    while drained <= 2 * MAX_SIZE as u64 {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    drained += data.len() as u64;
                }
            }
            _ => return,
        }
    }
}

/// One fetch attempt for a pending artifact. Returns whether the row needs
/// no further attempt; a failure, including a mismatched size or digest or
/// a full quota, is retried with backoff.
pub(crate) async fn fetch(store: Arc<Store>, k: RowKey) -> bool {
    let key = k.clone();
    let size = match blocking(store.clone(), move |s| s.fetch_plan(&key)).await {
        Ok(Some(size)) => size,
        Ok(None) => return true,
        Err(_) => return false,
    };
    match download(&store, &k, size).await {
        Ok(temp) => {
            let key = k.clone();
            blocking(store, move |s| s.fetched(&key, Some(temp)))
                .await
                .is_ok()
        }
        Err(_) => false,
    }
}
async fn download(store: &Arc<Store>, k: &RowKey, size: i64) -> anyhow::Result<PathBuf> {
    let peer_id = k.peer.clone();
    let peer = blocking(store.clone(), move |s| s.dial_target(&peer_id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = format!("/peer/v1/tasks/{}/artifacts/{}", k.task_id, k.sha256);
    let mut response = crate::quic::download(store.clone(), &peer, &path).await?;
    if response.status != 200 {
        anyhow::bail!("peer returned HTTP {}", response.status);
    }
    if response.length != Some(size as u64) {
        anyhow::bail!("peer artifact length does not match the manifest");
    }
    let mut sink = Sink::create(store, size as u64)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    loop {
        match response.chunk().await {
            Ok(Some(data)) => {
                if let Err(e) = sink.push(&data).await {
                    sink.discard().await;
                    anyhow::bail!("{e}");
                }
            }
            Ok(None) => break,
            Err(e) => {
                sink.discard().await;
                return Err(e);
            }
        }
    }
    let (temp, written, digest) = sink.finish().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    if written != size as u64 || digest != k.sha256 {
        let _ = tokio::task::spawn_blocking(move || fs::remove_file(temp)).await;
        anyhow::bail!("fetched artifact failed size or digest verification");
    }
    Ok(temp)
}

/// Releases expired artifacts until shutdown.
pub async fn retention_worker(store: Arc<Store>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        let _ = blocking(store.clone(), |s| s.prune_artifacts(false)).await;
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = tokio::time::sleep(SWEEP) => {}
        }
    }
}

#[derive(Deserialize)]
struct UploadQuery {
    name: Option<String>,
    media_type: Option<String>,
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/artifacts", get(list).post(local_upload))
        .route("/v1/artifacts/prune", post(prune))
        .route("/v1/tasks/{peer}/{id}/artifacts/{sha}", get(local_download))
}
pub(crate) fn adapter_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/adapter/v1/artifacts", post(adapter_upload))
        .route(
            "/adapter/v1/delegations/{task_id}/artifacts/{sha}",
            get(delegation_download),
        )
        .route(
            "/adapter/v1/tasks/{task_id}/artifacts/{sha}",
            get(claimed_download),
        )
}
pub(crate) fn peer_routes() -> Router<Arc<Store>> {
    Router::new().route("/peer/v1/tasks/{id}/artifacts/{sha}", get(peer_download))
}

async fn list(State(store): State<Arc<Store>>) -> Result<Json<ArtifactList>, Error> {
    Ok(Json(blocking(store, |s| s.artifact_list()).await?))
}
async fn prune(State(store): State<Arc<Store>>) -> Result<Json<PruneResult>, Error> {
    Ok(Json(blocking(store, |s| s.prune_artifacts(true)).await?))
}
async fn local_upload(
    State(store): State<Arc<Store>>,
    query: Result<Query<UploadQuery>, QueryRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<ArtifactEntry>, Error> {
    Ok(Json(upload(store, query, &headers, body).await?))
}
async fn adapter_upload(
    State(store): State<Arc<Store>>,
    query: Result<Query<UploadQuery>, QueryRejection>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<ArtifactEntry>, Error> {
    let auth = crate::adapter::token(&headers);
    blocking(store.clone(), move |s| {
        authority(&*s.connection()?, &auth).map(|_| ())
    })
    .await?;
    Ok(Json(upload(store, query, &headers, body).await?))
}
fn checked(task_id: &str, sha: &str) -> Result<(), Error> {
    if !crate::peer_store::valid_id(task_id, "task", 16) || !valid_digest(sha) {
        return Err(Error::NotFound);
    }
    Ok(())
}
async fn local_download(
    State(store): State<Arc<Store>>,
    Path((peer, id, sha)): Path<(String, String, String)>,
) -> Result<Response, Error> {
    checked(&id, &sha)?;
    let (file, len) = blocking(store, move |s| s.outbound_artifact(&peer, &id, &sha)).await?;
    Ok(file_response(file, len))
}
async fn delegation_download(
    State(store): State<Arc<Store>>,
    Path((id, sha)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let auth = crate::adapter::token(&headers);
    blocking(store.clone(), {
        let auth = auth.clone();
        move |s| authority(&*s.connection()?, &auth).map(|_| ())
    })
    .await?;
    checked(&id, &sha)?;
    let (file, len) = blocking(store, move |s| s.delegation_artifact(&auth, &id, &sha)).await?;
    Ok(file_response(file, len))
}
async fn claimed_download(
    State(store): State<Arc<Store>>,
    Path((id, sha)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let auth = crate::adapter::token(&headers);
    blocking(store.clone(), {
        let auth = auth.clone();
        move |s| authority(&*s.connection()?, &auth).map(|_| ())
    })
    .await?;
    checked(&id, &sha)?;
    let (file, len) = blocking(store, move |s| s.claimed_artifact(&auth, &id, &sha)).await?;
    Ok(file_response(file, len))
}
async fn peer_download(
    State(store): State<Arc<Store>>,
    Extension(sender): Extension<String>,
    long: Option<Extension<LongTransfer>>,
    Path((id, sha)): Path<(String, String)>,
) -> Result<Response, Error> {
    checked(&id, &sha)?;
    let (file, len) = blocking(store, move |s| s.peer_artifact(&sender, &id, &sha)).await?;
    if let Some(Extension(long)) = long {
        long.allow();
    }
    Ok(file_response(file, len))
}

#[cfg(test)]
mod tests;
