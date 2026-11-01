//! Explicit local fixture controls. Never consult these for TLS, QUIC, helper
//! resource expiry/rate or I/O timeouts, and never accept them from a peer.
use super::codec::*;
use crate::store::Store;
use rusqlite::{Connection, OptionalExtension};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};
fn failure(stage: &'static str) -> Error {
    let mut error = Error::new("internal");
    error.stage = Some(stage);
    error
}
fn enabled() -> bool {
    std::env::var("PEERSPAN_DEC_TEST_MODE").as_deref() == Ok("1")
}
/// A network's local guard also applies while its reviewed ceremony is still
/// private pending state. Peers and helpers never supply this anchor.
fn retained_clock(c: &Connection, network: &str) -> Result<Option<String>> {
    check(ident(network, "net_"))?;
    let record: Option<String> = c
        .query_row(
            "SELECT record FROM dec_clock WHERE network_id=?1",
            [network],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| Error::new("internal"))?;
    let guard = record
        .map(|raw| -> Result<String> {
            let value = parse(raw.as_bytes(), 32 << 20)?;
            let o = object(&value)?;
            fields(o, "format largest_local_time")?;
            version(o)?;
            let time = text(o, "largest_local_time")?;
            stamp(time)?;
            Ok(time.into())
        })
        .transpose()
        .map_err(|_| Error::new("state_conflict"))?;
    Ok(guard)
}
pub(crate) fn guarded_decision(c: &Connection, network: &str, local: &str) -> Result<String> {
    decision_clock(local, retained_clock(c, network)?.as_deref().unwrap_or("-"))
}
/// Observation of retained history is not a new authorization decision. Keep
/// its last known clock without making recovery depend on live rollback limits.
/// Callers must still use guarded_decision before any fresh authorized work.
pub(crate) fn historical_decision(c: &Connection, network: &str, local: &str) -> Result<String> {
    let raw = stamp(local)?;
    match retained_clock(c, network)? {
        Some(saved) if stamp(&saved)? > raw => Ok(saved),
        _ => Ok(local.into()),
    }
}
pub(crate) fn remember_decision(c: &Connection, network: &str, decision: &str) -> Result<()> {
    let actual = guarded_decision(c, network, decision)?;
    check(actual == decision)?;
    let record = serde_json::json!({"format":1,"largest_local_time":decision});
    c.execute("INSERT INTO dec_clock(network_id,record) VALUES(?1,?2) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record",rusqlite::params![network,record.to_string()]).map_err(|_|Error::new("internal"))?;
    Ok(())
}
fn regular(path: &Path, write: bool, create: bool, stage: &'static str) -> Result<File> {
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| failure(stage))?;
    require(
        file.metadata()
            .map_err(|_| failure(stage))?
            .file_type()
            .is_file(),
        "internal",
    )
    .map_err(|_| failure(stage))?;
    Ok(file)
}
/// Actual owner-local whole-second UTC, with the separately opted-in DEC test
/// clock. Call again inside the final authoritative transaction after a wait.
pub fn local_decision_time() -> Result<String> {
    if enabled()
        && let Some(path) = std::env::var_os("PEERSPAN_DEC_TEST_CLOCK_FILE")
    {
        if path.is_empty() {
            return Err(failure("clock"));
        }
        let file = regular(Path::new(&path), false, false, "clock")?;
        let mut bytes = Vec::new();
        file.take(22)
            .read_to_end(&mut bytes)
            .map_err(|_| failure("clock"))?;
        let value = std::str::from_utf8(&bytes).map_err(|_| failure("clock"))?;
        let value = value.strip_suffix('\n').unwrap_or(value);
        stamp(value).map_err(|_| failure("clock"))?;
        return Ok(value.into());
    }
    Ok(crate::clock::now().format("%Y-%m-%dT%H:%M:%SZ").to_string())
}
fn barrier_file(path: &Path, write: bool, create: bool) -> Result<File> {
    let file = regular(path, write, create, "apply")?;
    let metadata = file.metadata().map_err(|_| failure("apply"))?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let uid = unsafe { libc::geteuid() };
    require(
        metadata.mode() & 0o777 == 0o600 && metadata.uid() == uid && metadata.nlink() == 1,
        "internal",
    )
    .map_err(|_| failure("apply"))?;
    Ok(file)
}
/// Called only on a blocking worker, after dropping all connection guards and
/// writer transactions. Cancellation is the daemon's normal shutdown context.
pub(crate) fn barrier(store: &Store, name: &str, operation: &str) -> Result<()> {
    if !enabled() {
        return Ok(());
    }
    let Some(path) = std::env::var_os("PEERSPAN_DEC_TEST_BARRIER_DIR") else {
        return Ok(());
    };
    if path.is_empty() {
        return Err(failure("apply"));
    }
    let directory = PathBuf::from(path);
    let d = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(&directory)
        .map_err(|_| failure("apply"))?;
    let m = d.metadata().map_err(|_| failure("apply"))?;
    // SAFETY: geteuid has no preconditions.
    require(
        m.is_dir() && m.mode() & 0o777 == 0o700 && m.uid() == unsafe { libc::geteuid() },
        "internal",
    )
    .map_err(|_| failure("apply"))?;
    let armed = directory.join(format!("{name}.arm"));
    match std::fs::symlink_metadata(&armed) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(failure("apply")),
        Ok(_) => {}
    }
    let file = barrier_file(&armed, false, false)?;
    let mut raw = String::new();
    file.take(130)
        .read_to_string(&mut raw)
        .map_err(|_| failure("apply"))?;
    let target = raw.strip_suffix('\n').unwrap_or(&raw);
    require(
        target == "-"
            || ["create_", "act_", "link_", "ds_"]
                .iter()
                .any(|prefix| ident(target, prefix)),
        "internal",
    )
    .map_err(|_| failure("apply"))?;
    if target != "-" && target != operation {
        return Ok(());
    }
    require(
        ["create_", "act_", "link_", "ds_"]
            .iter()
            .any(|prefix| ident(operation, prefix)),
        "internal",
    )
    .map_err(|_| failure("apply"))?;
    let entered = directory.join(format!("{name}.entered"));
    let mut file = barrier_file(&entered, true, true)?;
    file.set_len(0).map_err(|_| failure("apply"))?;
    file.write_all(operation.as_bytes())
        .map_err(|_| failure("apply"))?;
    file.sync_all().map_err(|_| failure("apply"))?;
    let continued = directory.join(format!("{name}.continue"));
    loop {
        if store.dec_cancelled.load(Ordering::Acquire) {
            return Err(failure("apply"));
        }
        match std::fs::symlink_metadata(&continued) {
            Ok(_) => {
                barrier_file(&continued, false, false)?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failure("apply")),
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
