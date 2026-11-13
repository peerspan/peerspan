//! `task run` (runtime task contract, CLI): packs the workspace, uploads
//! it, submits a runtime task, follows its events, writing each output
//! chunk to this process's own stdout or stderr, saves result artifacts,
//! and exits with the command's status.
use crate::{
    admin::Local,
    cli::{Command, TaskCommand, encoded},
};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use peerspan_host::tar;
use serde_json::{Map, Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const MAX_INPUT: usize = 65_536;
/// The exit status when the task ended other than by the command's own exit.
const OTHER: i32 = 125;

/// The names a run's result artifacts may have (runtime task contract).
const RESULT_NAMES: [&str; 4] = ["stdout.log", "stderr.log", "changes.tar", "deleted.txt"];

pub async fn run(command: &Command, directory: &Path) -> anyhow::Result<i32> {
    let Command::Task(TaskCommand::Run {
        peer,
        workspace,
        peerfs_workspace,
        results,
        cpus,
        memory_mib,
        timeout,
        env,
        cwd,
        input,
        deadline,
        detach,
        command,
    }) = command
    else {
        unreachable!("not task run");
    };
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    if let Some(results) = results
        && peerfs_workspace.is_some()
        && results == "changes"
    {
        bail!(
            "--results changes is not available with --peerfs-workspace: the workspace's history holds them"
        );
    }
    let mut run = run_object(command, cwd, env, cpus, memory_mib, timeout, results)?;
    if let Some(name) = peerfs_workspace {
        run.insert("workspace".into(), json!({ "peerfs": name }));
    }
    let mut body = json!({
        "peer_host_id": peer,
        "executor": "runtime",
        "input": input.clone().unwrap_or_else(|| default_input(command)),
    });
    if let Some(deadline) = deadline {
        body["deadline"] = json!(deadline);
    }
    if let Some(dir) = workspace {
        let packed = pack_to_temp(dir)?;
        let entry =
            crate::upload(&socket, packed.path(), "workspace.tar", "application/x-tar").await;
        drop(packed);
        let entry = entry?;
        run.insert(
            "workspace".into(),
            json!({ "archive": entry["sha256"].clone() }),
        );
        body["artifacts"] = json!([entry]);
    }
    body["run"] = Value::Object(run);
    submit_and_follow(
        &local,
        &socket,
        peer,
        body,
        *detach,
        results.as_deref() == Some("changes"),
    )
    .await
}

/// The default `input`: the command line joined with spaces, cut at
/// 65,536 bytes.
pub(crate) fn default_input(command: &[String]) -> String {
    cut(&command.join(" "), MAX_INPUT)
}

/// Submits a task through `POST /v1/tasks` and, unless `detach`, follows
/// it to its final event (`task run`'s exit status).
pub(crate) async fn submit_and_follow(
    local: &Local<'_>,
    socket: &Path,
    peer: &str,
    body: Value,
    detach: bool,
    save: bool,
) -> anyhow::Result<i32> {
    let record = local.post("/v1/tasks".into(), body).await?;
    if detach {
        crate::output::emit(&record)?;
        return Ok(0);
    }
    let id = record["request"]["task_id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    follow(local, socket, peer, &id, save).await
}

/// A run's `argv`, `cwd`, `env`, `resources` and `results` from `task
/// run`'s flags.
pub(crate) fn run_object(
    command: &[String],
    cwd: &Option<String>,
    env: &[String],
    cpus: &Option<i64>,
    memory_mib: &Option<i64>,
    timeout: &Option<String>,
    results: &Option<String>,
) -> anyhow::Result<Map<String, Value>> {
    let mut run = Map::new();
    run.insert("argv".into(), json!(command));
    if let Some(cwd) = cwd {
        run.insert("cwd".into(), json!(cwd));
    }
    if !env.is_empty() {
        let mut vars = Map::new();
        for pair in env {
            let (name, value) = pair
                .split_once('=')
                .with_context(|| format!("--env {pair:?} is not NAME=VALUE"))?;
            vars.insert(name.into(), json!(value));
        }
        run.insert("env".into(), Value::Object(vars));
    }
    let mut resources = Map::new();
    if let Some(n) = cpus {
        resources.insert("cpus".into(), json!(n));
    }
    if let Some(n) = memory_mib {
        resources.insert("memory_mib".into(), json!(n));
    }
    if let Some(t) = timeout {
        resources.insert("timeout_seconds".into(), json!(seconds(t)?));
    }
    if !resources.is_empty() {
        run.insert("resources".into(), Value::Object(resources));
    }
    if let Some(results) = results {
        run.insert("results".into(), json!(results));
    }
    Ok(run)
}

/// Follows the local events to the final one, writing output as it comes.
async fn follow(
    local: &Local<'_>,
    socket: &Path,
    peer: &str,
    id: &str,
    save: bool,
) -> anyhow::Result<i32> {
    let mut after = 0;
    let record = format!("/v1/tasks/{}/{}", encoded(peer), encoded(id));
    loop {
        // A refused submission has no event: only its record says so.
        let task = local.get(record.clone()).await?;
        if task["submit_state"] == "rejected" {
            match task["error"].as_str() {
                Some(error) => eprintln!("task rejected: {error}"),
                None => eprintln!("task rejected"),
            }
            return Ok(OTHER);
        }
        let events = local
            .get(format!(
                "/v1/tasks/{}/{}/events?after={after}&limit={}",
                encoded(peer),
                encoded(id),
                peerspan_host::task_outbound::RUNTIME_EVENT_PAGE
            ))
            .await?;
        let events = events.as_array().cloned().unwrap_or_default();
        for event in &events {
            after = event["sequence"].as_i64().unwrap_or(after);
            if let Some(chunk) = event["chunk"].as_object() {
                let data = STANDARD.decode(chunk["data"].as_str().unwrap_or_default())?;
                if chunk["stream"] == "stderr" {
                    std::io::stderr().write_all(&data)?;
                } else {
                    let mut out = std::io::stdout();
                    out.write_all(&data)?;
                    out.flush()?;
                }
            }
            let state = event["state"].as_str().unwrap_or_default();
            if matches!(
                state,
                "succeeded" | "failed" | "cancelled" | "rejected" | "expired"
            ) {
                return finish(local, socket, peer, id, event, save).await;
            }
        }
        if events.is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// The exit status of a final event, after saving its results.
async fn finish(
    local: &Local<'_>,
    socket: &Path,
    peer: &str,
    id: &str,
    event: &Value,
    save: bool,
) -> anyhow::Result<i32> {
    let state = event["state"].as_str().unwrap_or_default();
    if matches!(state, "rejected" | "expired") {
        if let Some(message) = event["message"].as_str() {
            eprintln!("task {state}: {message}");
        } else {
            eprintln!("task {state}");
        }
    }
    let result: Value = event["output"]
        .as_str()
        .and_then(|o| serde_json::from_str(o).ok())
        .unwrap_or(Value::Null);
    // A peerbox run that failed before it started has no run result, only
    // `{"error", "message"}` (peerbox contract, Results).
    if state == "failed"
        && result.get("exit_code").is_none()
        && let Some(code) = result["error"].as_str()
    {
        eprintln!("{code}: {}", result["message"].as_str().unwrap_or_default());
    }
    if save && let Some(artifacts) = event["artifacts"].as_array() {
        let dir = PathBuf::from("peerspan-results").join(id);
        fs::create_dir_all(&dir)?;
        let mut saved = Vec::new();
        for a in artifacts {
            let name = a["name"]
                .as_str()
                .filter(|n| RESULT_NAMES.contains(n))
                .context("invalid result artifact")?;
            let sha = a["sha256"].as_str().context("invalid result artifact")?;
            save_result(local, socket, peer, id, sha, &dir.join(name)).await?;
            saved.push(name);
        }
        if let Some(same) = result["results_same"].as_object() {
            for (name, earlier) in same {
                // Both names come from the peer: only a result name, copied
                // from one saved above.
                let earlier = earlier
                    .as_str()
                    .filter(|e| saved.contains(e) && RESULT_NAMES.contains(&name.as_str()))
                    .context("invalid results_same")?;
                fs::copy(dir.join(earlier), dir.join(name))?;
            }
        }
    }
    if !matches!(state, "succeeded" | "failed") {
        return Ok(OTHER);
    }
    Ok(if result["timed_out"] == true {
        124
    } else if let Some(signal) = result["signal"].as_i64() {
        128 + signal as i32
    } else if let Some(code) = result["exit_code"].as_i64() {
        code as i32
    } else {
        OTHER
    })
}

/// Saves one result once this host has fetched it.
async fn save_result(
    local: &Local<'_>,
    socket: &Path,
    peer: &str,
    id: &str,
    sha: &str,
    out: &Path,
) -> anyhow::Result<()> {
    let path = format!(
        "/v1/tasks/{}/{}/artifacts/{}",
        encoded(peer),
        encoded(id),
        encoded(sha)
    );
    let until = std::time::Instant::now() + Duration::from_secs(600);
    loop {
        match crate::download(socket, path.clone(), out).await {
            Ok(_) => return Ok(()),
            Err(e) if std::time::Instant::now() < until => {
                let _ = local;
                // download removes only what it wrote; a file already there
                // is someone else's and stays.
                let exists = e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
                });
                if exists {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// `90`, `90s`, `10m` or `2h`, as whole seconds.
pub(crate) fn seconds(value: &str) -> anyhow::Result<i64> {
    let (number, unit) = match value.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&value[..i], c),
        _ => (value, 's'),
    };
    let n: i64 = number
        .parse()
        .with_context(|| format!("--timeout {value:?} is not a duration such as 90s, 10m or 2h"))?;
    Ok(match unit {
        's' => n,
        'm' => n * 60,
        'h' => n * 3600,
        _ => bail!("--timeout {value:?} is not a duration such as 90s, 10m or 2h"),
    })
}
fn cut(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// A packed workspace, removed when dropped.
struct Packed(PathBuf);
impl Packed {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Packed {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn pack_to_temp(dir: &Path) -> anyhow::Result<Packed> {
    let path = std::env::temp_dir().join(format!(
        "peerspan-workspace-{}-{}.tar",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let packed = Packed(path);
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(packed.path())?;
    fs::set_permissions(packed.path(), fs::Permissions::from_mode(0o600))?;
    let mut out = std::io::BufWriter::new(file);
    pack(dir, &mut out)?;
    out.flush()?;
    Ok(packed)
}

/// Packs `dir` as an uncompressed pax tar (Packing): directories, regular
/// files with their mode, and symbolic links. Inside a git working tree the
/// paths are git's tracked and unignored files.
pub(crate) fn pack(dir: &Path, out: &mut impl Write) -> anyhow::Result<()> {
    let mut paths = match git_paths(dir)? {
        Some(files) => {
            let mut all = std::collections::BTreeSet::new();
            for file in files {
                let mut parent = file.parent();
                while let Some(p) = parent.filter(|p| !p.as_os_str().is_empty()) {
                    all.insert(p.to_path_buf());
                    parent = p.parent();
                }
                all.insert(file);
            }
            all.into_iter().collect::<Vec<_>>()
        }
        None => {
            let mut all = Vec::new();
            walk(dir, Path::new(""), &mut all)?;
            all
        }
    };
    paths.sort();
    for relative in paths {
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            continue;
        }
        // git still lists the tracked files under a directory replaced by a
        // symbolic link: only paths whose every ancestor is a directory are
        // packed, so the link is archived and never followed.
        let real_parents = relative
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
            .all(|p| fs::symlink_metadata(dir.join(p)).is_ok_and(|m| m.is_dir()));
        if !real_parents {
            continue;
        }
        let full = dir.join(&relative);
        let Ok(meta) = fs::symlink_metadata(&full) else {
            continue;
        };
        let name = relative
            .to_str()
            .with_context(|| format!("{} is not a UTF-8 path", relative.display()))?;
        let kind = meta.file_type();
        if kind.is_dir() {
            tar::entry(
                out,
                format!("{name}/").as_bytes(),
                tar::DIRECTORY,
                meta.mode() & 0o7777,
                0,
                b"",
            )?;
        } else if kind.is_symlink() {
            let target = fs::read_link(&full)?;
            let target = target
                .to_str()
                .with_context(|| format!("{} links to a non-UTF-8 path", relative.display()))?;
            tar::entry(
                out,
                name.as_bytes(),
                tar::SYMLINK,
                0o777,
                0,
                target.as_bytes(),
            )?;
        } else if kind.is_file() {
            tar::entry(
                out,
                name.as_bytes(),
                tar::FILE,
                meta.mode() & 0o7777,
                meta.len(),
                b"",
            )?;
            let copied = std::io::copy(&mut fs::File::open(&full)?, out)?;
            if copied != meta.len() {
                bail!("{} changed while it was packed", relative.display());
            }
            tar::pad(out, copied)?;
        }
    }
    tar::end(out)?;
    Ok(())
}
fn walk(root: &Path, relative: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for item in fs::read_dir(root.join(relative))? {
        let item = item?;
        let path = relative.join(item.file_name());
        let kind = item.file_type()?;
        out.push(path.clone());
        if kind.is_dir() {
            walk(root, &path, out)?;
        }
    }
    Ok(())
}
/// The paths of `git ls-files --cached --others --exclude-standard`, or
/// None outside a git working tree.
fn git_paths(dir: &Path) -> anyhow::Result<Option<Vec<PathBuf>>> {
    let inside = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--is-inside-work-tree"])
        .stderr(std::process::Stdio::null())
        .output();
    match inside {
        Ok(o) if o.status.success() && o.stdout.starts_with(b"true") => {}
        _ => return Ok(None),
    }
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()?;
    if !listed.status.success() {
        bail!("git ls-files failed in {}", dir.display());
    }
    Ok(Some(
        listed
            .stdout
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| PathBuf::from(String::from_utf8_lossy(p).into_owned()))
            .collect(),
    ))
}
