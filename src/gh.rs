//! The built-in `gh` source (capabilities contract, slice 3): a stdio MCP
//! server inside this binary, `builtin-source gh --gh PATH --state DIR`,
//! offering a fixed set of GitHub operations that run the GitHub CLI with
//! an argument vector, never a shell, under fixed limits. The daemon also
//! runs `gh` directly to check a credential's reach and, at capability
//! creation, whether bound repositories are visible.
use crate::bounds::repo_shape;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, mpsc},
};

/// The JSON-RPC error code for output over the limit; a daemon maps it to
/// `result_too_large` for built-in sources.
pub const TOO_LARGE_CODE: i64 = -32002;
/// Standard output kept from one `gh` run.
const STDOUT_LIMIT: usize = 1_000_000;
/// The tail of standard error kept.
const STDERR_KEEP: usize = 65_536;
/// The tail of standard error shown in `gh failed`.
const STDERR_SHOWN: usize = 2_048;
/// A call's `gh` run may take this long.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Reach checks and visibility warnings may take this long.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// After `SIGTERM`, `SIGKILL` follows this long later.
const KILL_GRACE: Duration = Duration::from_secs(2);
const MAX_BODY: usize = 65_536;

const ISSUE_LIST_FIELDS: &str =
    "number,title,state,author,labels,assignees,milestone,createdAt,updatedAt,url";
const ISSUE_VIEW_FIELDS: &str = "number,title,state,stateReason,body,author,labels,assignees,milestone,createdAt,updatedAt,closedAt,url";
const PR_LIST_FIELDS: &str =
    "number,title,state,isDraft,author,baseRefName,headRefName,labels,createdAt,updatedAt,url";
const PR_VIEW_FIELDS: &str = "number,title,state,isDraft,body,author,baseRefName,headRefName,mergeable,reviewDecision,additions,deletions,changedFiles,files,labels,createdAt,updatedAt,mergedAt,url";
const PR_CHECKS_FIELDS: &str = "name,state,bucket,workflow,link,startedAt,completedAt";
pub const REPO_VIEW_FIELDS: &str = "nameWithOwner,description,url,visibility,isArchived,defaultBranchRef,homepageUrl,primaryLanguage,stargazerCount,forkCount,pushedAt,updatedAt";

/// The operations, in `tools/list` order.
pub const OPERATIONS: [&str; 10] = [
    "issue_list",
    "issue_view",
    "pr_list",
    "pr_view",
    "pr_diff",
    "pr_checks",
    "repo_view",
    "issue_create",
    "issue_comment",
    "pr_comment",
];

fn read_only(op: &str) -> bool {
    !matches!(op, "issue_create" | "issue_comment" | "pr_comment")
}

fn string_property(description: &str) -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": 256, "description": description})
}
fn array_property(description: &str) -> Value {
    json!({"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 256}, "maxItems": 10, "description": description})
}
fn property(op: &str, name: &str) -> Value {
    let list = op.ends_with("_list");
    match name {
        "repo" => json!({
            "type": "string",
            "pattern": "^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$",
            "description": "The repository, as OWNER/REPO.",
        }),
        "number" => {
            json!({"type": "integer", "minimum": 1, "maximum": 2147483647, "description": "The issue or pull request number."})
        }
        "state" => {
            let values: &[&str] = if op == "pr_list" {
                &["open", "closed", "merged", "all"]
            } else {
                &["open", "closed", "all"]
            };
            json!({"type": "string", "enum": values, "default": "open", "description": "Which items to list."})
        }
        "limit" => {
            json!({"type": "integer", "minimum": 1, "maximum": 100, "default": 30, "description": "At most this many items."})
        }
        "label" if list => array_property("Only items with all of these labels."),
        "label" => array_property("Labels to add."),
        "assignee" if list => string_property("Only items assigned to this login."),
        "assignee" => array_property("Logins to assign."),
        "author" => string_property("Only items opened by this login."),
        "milestone" => string_property("Only issues in this milestone."),
        "base" => string_property("Only pull requests into this base branch."),
        "head" => string_property("Only pull requests from this head branch."),
        "draft" => json!({"type": "boolean", "description": "Only draft pull requests."}),
        "comments" => json!({
            "type": "boolean",
            "default": false,
            "description": if op == "pr_view" { "Include comments and reviews." } else { "Include comments." },
        }),
        "name_only" => {
            json!({"type": "boolean", "default": false, "description": "Return only the names of the changed files."})
        }
        "title" => string_property("The issue title."),
        "body" => {
            json!({"type": "string", "maxLength": 65536, "description": "The text, in Markdown."})
        }
        _ => json!({}),
    }
}
/// An operation's properties in order, and the required ones.
fn shape(op: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match op {
        "issue_list" => (
            &[
                "repo",
                "state",
                "limit",
                "label",
                "assignee",
                "author",
                "milestone",
            ],
            &["repo"],
        ),
        "issue_view" | "pr_view" => (&["repo", "number", "comments"], &["repo", "number"]),
        "pr_list" => (
            &[
                "repo", "state", "limit", "base", "head", "label", "author", "draft",
            ],
            &["repo"],
        ),
        "pr_diff" => (&["repo", "number", "name_only"], &["repo", "number"]),
        "pr_checks" => (&["repo", "number"], &["repo", "number"]),
        "repo_view" => (&["repo"], &["repo"]),
        "issue_create" => (
            &["repo", "title", "body", "label", "assignee"],
            &["repo", "title"],
        ),
        "issue_comment" | "pr_comment" => {
            (&["repo", "number", "body"], &["repo", "number", "body"])
        }
        _ => (&[], &[]),
    }
}
fn description(op: &str) -> &'static str {
    match op {
        "issue_list" => "List issues in a GitHub repository.",
        "issue_view" => {
            "Show one issue of a GitHub repository, with its comments when comments is true."
        }
        "pr_list" => "List pull requests in a GitHub repository.",
        "pr_view" => {
            "Show one pull request of a GitHub repository, with its comments and reviews when comments is true."
        }
        "pr_diff" => {
            "Show the diff of a pull request, or with name_only the names of the changed files."
        }
        "pr_checks" => "Show the status checks of a pull request.",
        "repo_view" => "Show a GitHub repository.",
        "issue_create" => "Create an issue in a GitHub repository.",
        "issue_comment" => "Add a comment to an issue.",
        "pr_comment" => "Add a comment to a pull request.",
        _ => "",
    }
}
/// The input schema of an operation.
pub fn input_schema(op: &str) -> Value {
    let (properties, required) = shape(op);
    let mut p = Map::new();
    for name in properties {
        p.insert((*name).to_owned(), property(op, name));
    }
    json!({"type": "object", "properties": p, "required": required, "additionalProperties": false})
}
/// The `tools/list` entries.
pub fn tools() -> Vec<Value> {
    OPERATIONS
        .iter()
        .map(|op| {
            let annotations = if read_only(op) {
                json!({"readOnlyHint": true})
            } else {
                json!({"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false})
            };
            json!({
                "name": op,
                "description": description(op),
                "inputSchema": input_schema(op),
                "annotations": annotations,
            })
        })
        .collect()
}

/// A plain string: 1 to 256 bytes, no character below U+0020 or U+007F.
fn plain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(|c| c < ' ' || c == '\u{7f}')
}
/// A whole JSON number in a range.
fn whole(value: &Value, max: i64) -> Option<i64> {
    let n = value.as_number()?;
    let v = if let Some(i) = n.as_i64() {
        i
    } else {
        let f = n.as_f64()?;
        if f.fract() != 0.0 || !f.is_finite() || f < 1.0 || f > max as f64 {
            return None;
        }
        f as i64
    };
    (1..=max).contains(&v).then_some(v)
}

/// Checks arguments against an operation's schema and rules.
pub fn validate(op: &str, args: &Map<String, Value>) -> Result<(), String> {
    let (properties, required) = shape(op);
    for name in args.keys() {
        if !properties.contains(&name.as_str()) {
            return Err(format!("unknown argument {name}"));
        }
    }
    for name in required {
        if !args.contains_key(*name) {
            return Err(format!("{name} is required"));
        }
    }
    for (name, value) in args {
        let ok = match name.as_str() {
            "repo" => value.as_str().is_some_and(|s| plain(s) && repo_shape(s)),
            "number" => whole(value, 2_147_483_647).is_some(),
            "limit" => whole(value, 100).is_some(),
            "state" => value.as_str().is_some_and(|s| {
                matches!(s, "open" | "closed" | "all") || (op == "pr_list" && s == "merged")
            }),
            "label" => strings(value).is_some(),
            "assignee" if op == "issue_create" => strings(value).is_some(),
            "assignee" | "author" | "milestone" | "base" | "head" | "title" => {
                value.as_str().is_some_and(plain)
            }
            "draft" | "comments" | "name_only" => value.is_boolean(),
            "body" => value
                .as_str()
                .is_some_and(|s| s.len() <= MAX_BODY && !s.contains('\0')),
            _ => false,
        };
        if !ok {
            return Err(format!("{name} is not valid"));
        }
    }
    Ok(())
}
fn strings(value: &Value) -> Option<Vec<String>> {
    let list = value.as_array()?;
    if list.len() > 10 {
        return None;
    }
    list.iter()
        .map(|v| v.as_str().filter(|s| plain(s)).map(str::to_owned))
        .collect()
}

/// The `gh` arguments of a validated call, and its standard input.
pub fn argv(op: &str, args: &Map<String, Value>) -> (Vec<String>, Option<String>) {
    let s = |k: &str| args.get(k).and_then(Value::as_str).map(str::to_owned);
    let flag = |k: &str| args.get(k) == Some(&Value::Bool(true));
    let number = || {
        args.get("number")
            .and_then(|v| whole(v, 2_147_483_647))
            .unwrap_or(0)
            .to_string()
    };
    let repo = s("repo").unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    let mut push = |v: String| out.push(v);
    let mut stdin = None;
    let list_head = |out: &mut Vec<String>, kind: &str| {
        out.push(kind.into());
        out.push("list".into());
        out.push(format!("--repo={repo}"));
        out.push(format!(
            "--state={}",
            s("state").unwrap_or_else(|| "open".into())
        ));
        out.push(format!(
            "--limit={}",
            args.get("limit").and_then(|v| whole(v, 100)).unwrap_or(30)
        ));
    };
    let labels = strings(args.get("label").unwrap_or(&Value::Null)).unwrap_or_default();
    match op {
        "issue_list" => {
            list_head(&mut out, "issue");
            for l in &labels {
                out.push(format!("--label={l}"));
            }
            for k in ["assignee", "author", "milestone"] {
                if let Some(v) = s(k) {
                    out.push(format!("--{k}={v}"));
                }
            }
            out.push(format!("--json={ISSUE_LIST_FIELDS}"));
        }
        "pr_list" => {
            list_head(&mut out, "pr");
            for k in ["base", "head"] {
                if let Some(v) = s(k) {
                    out.push(format!("--{k}={v}"));
                }
            }
            for l in &labels {
                out.push(format!("--label={l}"));
            }
            if let Some(v) = s("author") {
                out.push(format!("--author={v}"));
            }
            if flag("draft") {
                out.push("--draft".into());
            }
            out.push(format!("--json={PR_LIST_FIELDS}"));
        }
        "issue_view" | "pr_view" => {
            let (kind, fields, extra) = if op == "issue_view" {
                ("issue", ISSUE_VIEW_FIELDS, ",comments")
            } else {
                ("pr", PR_VIEW_FIELDS, ",comments,reviews")
            };
            for v in [
                kind.to_owned(),
                "view".into(),
                number(),
                format!("--repo={repo}"),
            ] {
                push(v);
            }
            if flag("comments") {
                push("--comments".into());
                push(format!("--json={fields}{extra}"));
            } else {
                push(format!("--json={fields}"));
            }
        }
        "pr_diff" => {
            for v in [
                "pr".into(),
                "diff".into(),
                number(),
                format!("--repo={repo}"),
                "--color=never".into(),
            ] {
                push(v);
            }
            if flag("name_only") {
                push("--name-only".into());
            }
        }
        "pr_checks" => {
            for v in [
                "pr".into(),
                "checks".into(),
                number(),
                format!("--repo={repo}"),
                format!("--json={PR_CHECKS_FIELDS}"),
            ] {
                push(v);
            }
        }
        "repo_view" => out = repo_view_argv(&repo),
        "issue_create" => {
            for v in [
                "issue".into(),
                "create".into(),
                format!("--repo={repo}"),
                format!("--title={}", s("title").unwrap_or_default()),
                "--body-file=-".into(),
            ] {
                push(v);
            }
            for l in &labels {
                push(format!("--label={l}"));
            }
            for a in strings(args.get("assignee").unwrap_or(&Value::Null)).unwrap_or_default() {
                push(format!("--assignee={a}"));
            }
            stdin = Some(s("body").unwrap_or_default());
        }
        "issue_comment" | "pr_comment" => {
            let kind = if op == "issue_comment" { "issue" } else { "pr" };
            for v in [
                kind.into(),
                "comment".into(),
                number(),
                format!("--repo={repo}"),
                "--body-file=-".into(),
            ] {
                push(v);
            }
            stdin = Some(s("body").unwrap_or_default());
        }
        _ => {}
    }
    (out, stdin)
}
/// `repo view R --json=F`.
pub fn repo_view_argv(repo: &str) -> Vec<String> {
    vec![
        "repo".into(),
        "view".into(),
        repo.to_owned(),
        format!("--json={REPO_VIEW_FIELDS}"),
    ]
}

/// The environment of a `gh` process, from the instance's environment.
pub fn gh_env(instance: &[(String, String)], state: &Path) -> Vec<(String, String)> {
    let get = |name: &str| {
        instance
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    let mut env = Vec::new();
    for name in ["PATH", "HOME"] {
        if let Some(v) = get(name) {
            env.push((name.to_owned(), v));
        }
    }
    if let Some(token) = get("GH_TOKEN").filter(|t| !t.is_empty()) {
        env.push(("GH_TOKEN".into(), token));
    }
    let config = state.join("builtin").join("gh").join("config");
    for (k, v) in [
        ("GH_HOST", "github.com".to_owned()),
        ("GH_CONFIG_DIR", config.display().to_string()),
        ("GH_PROMPT_DISABLED", "1".into()),
        ("GH_NO_UPDATE_NOTIFIER", "1".into()),
        ("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1".into()),
        ("GH_SPINNER_DISABLED", "1".into()),
        ("NO_COLOR", "1".into()),
        ("GH_PAGER", "cat".into()),
        ("GH_TELEMETRY", "0".into()),
    ] {
        env.push((k.to_owned(), v));
    }
    env
}
/// `STATE/builtin/gh/work`, created empty with mode 0700, and the config
/// directory beside it.
pub fn work_dir(state: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let base = state.join("builtin").join("gh");
    for dir in [base.join("work"), base.join("config")] {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let _ = std::fs::set_permissions(
        state.join("builtin"),
        std::fs::Permissions::from_mode(0o700),
    );
    let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
    base.join("work")
}

/// How one `gh` run ended.
pub enum Run {
    NotStarted,
    TooLarge,
    Timeout,
    Cancelled,
    Exited {
        code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

/// Sends `SIGTERM` to the process group, then `SIGKILL` 2 seconds later if
/// the process is still running.
async fn kill(child: &mut tokio::process::Child, pid: Option<u32>) {
    let Some(pid) = pid else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return;
    };
    let group = -(pid as libc::pid_t);
    // SAFETY: signalling a process group this process started.
    unsafe {
        libc::kill(group, libc::SIGTERM);
    }
    if tokio::time::timeout(KILL_GRACE, child.wait())
        .await
        .is_err()
    {
        // SAFETY: as above.
        unsafe {
            libc::kill(group, libc::SIGKILL);
        }
        let _ = child.wait().await;
    } else {
        // Anything left in the group goes too.
        // SAFETY: as above.
        unsafe {
            libc::kill(group, libc::SIGKILL);
        }
    }
}

/// Runs `gh` once: never through a shell, with the given environment only,
/// standard output up to 1,000,000 bytes, the last 64 KiB of standard
/// error, a timeout, and an optional cancellation.
pub async fn run(
    gh: &Path,
    args: &[String],
    env: &[(String, String)],
    cwd: &Path,
    stdin: Option<String>,
    timeout: Duration,
    cancel: Option<Arc<Notify>>,
) -> Run {
    let mut command = tokio::process::Command::new(gh);
    command
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let Ok(mut child) = command.spawn() else {
        return Run::NotStarted;
    };
    let pid = child.id();
    if let Some(mut input) = child.stdin.take() {
        tokio::spawn(async move {
            if let Some(text) = stdin {
                let _ = input.write_all(text.as_bytes()).await;
            }
            let _ = input.shutdown().await;
        });
    }
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut out_task = tokio::spawn(async move {
        let mut kept = Vec::new();
        let Some(out) = stdout.as_mut() else {
            return Some(kept);
        };
        let mut buffer = [0u8; 8192];
        loop {
            match out.read(&mut buffer).await {
                Ok(0) | Err(_) => return Some(kept),
                Ok(n) => {
                    kept.extend_from_slice(&buffer[..n]);
                    if kept.len() > STDOUT_LIMIT {
                        return None;
                    }
                }
            }
        }
    });
    let err_task = tokio::spawn(async move {
        let mut kept: Vec<u8> = Vec::new();
        let Some(err) = stderr.as_mut() else {
            return kept;
        };
        let mut buffer = [0u8; 8192];
        loop {
            match err.read(&mut buffer).await {
                Ok(0) | Err(_) => return kept,
                Ok(n) => {
                    kept.extend_from_slice(&buffer[..n]);
                    if kept.len() > STDERR_KEEP {
                        kept.drain(..kept.len() - STDERR_KEEP);
                    }
                }
            }
        }
    });
    let deadline = tokio::time::Instant::now() + timeout;
    let cancelled = || {
        let cancel = cancel.clone();
        async move {
            match cancel {
                Some(c) => c.notified().await,
                None => std::future::pending().await,
            }
        }
    };
    let out = tokio::select! {
        r = &mut out_task => match r {
            Ok(Some(bytes)) => bytes,
            _ => {
                kill(&mut child, pid).await;
                return Run::TooLarge;
            }
        },
        _ = tokio::time::sleep_until(deadline) => {
            out_task.abort();
            kill(&mut child, pid).await;
            return Run::Timeout;
        }
        _ = cancelled() => {
            out_task.abort();
            kill(&mut child, pid).await;
            return Run::Cancelled;
        }
    };
    let status = tokio::select! {
        s = child.wait() => s,
        _ = tokio::time::sleep_until(deadline) => {
            kill(&mut child, pid).await;
            return Run::Timeout;
        }
        _ = cancelled() => {
            kill(&mut child, pid).await;
            return Run::Cancelled;
        }
    };
    let stderr = tokio::time::timeout(Duration::from_secs(1), err_task)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    Run::Exited {
        code: status.ok().and_then(|s| s.code()).unwrap_or(-1),
        stdout: out,
        stderr,
    }
}

/// Text from bytes, one U+FFFD per byte that is not part of valid UTF-8.
pub fn lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                // SAFETY-free: the prefix is valid UTF-8.
                out.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or_default());
                out.push('\u{fffd}');
                rest = &rest[valid + 1..];
            }
        }
    }
    out
}
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}
/// Removes leading and trailing space, tab, newline, and carriage return.
pub fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !is_space(*b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_space(*b))
        .map_or(start, |i| i + 1);
    &bytes[start..end.max(start)]
}
fn trim_str(text: &str) -> &str {
    text.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

/// A tool result.
fn text_result(text: String, error: bool) -> Value {
    let mut v = json!({"content": [{"type": "text", "text": text}]});
    if error {
        v["isError"] = json!(true);
    }
    v
}
const UNREADABLE: &str = "gh returned output Peerspan could not read.";

/// What a call answers: a result, a JSON-RPC error, or nothing (cancelled).
pub enum Answer {
    Result(Value),
    Error(i64, String),
    None,
}

/// Runs one validated operation and builds its answer.
pub async fn execute(
    gh: &Path,
    state: &Path,
    op: &str,
    args: &Map<String, Value>,
    cancel: Arc<Notify>,
    log: impl Fn(&str),
) -> Answer {
    let (argv, stdin) = argv(op, args);
    let env: Vec<(String, String)> = std::env::vars().collect();
    let env = gh_env(&env, state);
    let cwd = work_dir(state);
    let started = Instant::now();
    let outcome = run(gh, &argv, &env, &cwd, stdin, CALL_TIMEOUT, Some(cancel)).await;
    let elapsed = started.elapsed().as_millis();
    let exit = match &outcome {
        Run::NotStarted => "not_started".to_owned(),
        Run::TooLarge => "too_large".to_owned(),
        Run::Timeout => "timeout".to_owned(),
        Run::Cancelled => "cancelled".to_owned(),
        Run::Exited { code, .. } => code.to_string(),
    };
    log(&format!("{op} exit={exit} duration_ms={elapsed}"));
    let (code, stdout, stderr) = match outcome {
        Run::NotStarted => {
            return Answer::Result(text_result("gh could not be started.".into(), true));
        }
        Run::TooLarge => {
            return Answer::Error(
                TOO_LARGE_CODE,
                format!("gh output exceeded {STDOUT_LIMIT} bytes."),
            );
        }
        Run::Timeout => {
            return Answer::Result(text_result(
                format!(
                    "gh did not finish within {} seconds.",
                    CALL_TIMEOUT.as_secs()
                ),
                true,
            ));
        }
        Run::Cancelled => return Answer::None,
        Run::Exited {
            code,
            stdout,
            stderr,
        } => (code, stdout, stderr),
    };
    if code == 4 {
        return Answer::Error(
            -32001,
            "gh is not authenticated for github.com. The owner runs gh auth login, then peerspan sources refresh.".into(),
        );
    }
    let out = trim(&stdout);
    let is_array = |b: &[u8]| matches!(serde_json::from_slice::<Value>(b), Ok(Value::Array(_)));
    if op == "pr_checks" && matches!(code, 0 | 1 | 8) && is_array(out) {
        return Answer::Result(text_result(wrapped("checks", out), false));
    }
    if code != 0 {
        let tail = &stderr[stderr.len().saturating_sub(STDERR_SHOWN)..];
        let start = tail
            .iter()
            .position(|b| !(0x80..=0xbf).contains(b))
            .unwrap_or(tail.len());
        let text = lossy(&tail[start..]);
        let text = text.trim_end_matches([' ', '\t', '\n', '\r']);
        return Answer::Result(text_result(
            if text.is_empty() {
                format!("gh failed with exit status {code}.")
            } else {
                format!("gh failed: {text}")
            },
            true,
        ));
    }
    match result_text(op, args, out, &stdout) {
        Some(text) => Answer::Result(text_result(text, false)),
        None => Answer::Result(text_result(UNREADABLE.into(), true)),
    }
}
/// `{"KEY":OUT}`, with OUT copied byte for byte.
fn wrapped(key: &str, out: &[u8]) -> String {
    format!("{{\"{key}\":{}}}", String::from_utf8_lossy(out))
}
fn result_text(op: &str, args: &Map<String, Value>, out: &[u8], raw: &[u8]) -> Option<String> {
    let parsed = || serde_json::from_slice::<Value>(out).ok();
    match op {
        "issue_list" | "pr_list" => {
            let key = if op == "issue_list" {
                "issues"
            } else {
                "pull_requests"
            };
            parsed()?.is_array().then(|| wrapped(key, out))
        }
        "issue_view" | "pr_view" | "repo_view" => {
            let key = match op {
                "issue_view" => "issue",
                "pr_view" => "pull_request",
                _ => "repository",
            };
            parsed()?.is_object().then(|| wrapped(key, out))
        }
        "pr_diff" => {
            let text = lossy(raw);
            if args.get("name_only") == Some(&Value::Bool(true)) {
                let files: Vec<&str> = text
                    .split('\n')
                    .map(|l| l.strip_suffix('\r').unwrap_or(l))
                    .filter(|l| !l.is_empty())
                    .collect();
                Some(crate::canonical::value_text(&json!({"files": files})))
            } else {
                Some(crate::canonical::value_text(&json!({"diff": text})))
            }
        }
        "issue_create" | "issue_comment" | "pr_comment" => {
            let text = lossy(raw);
            let url = text
                .split('\n')
                .map(trim_str)
                .rfind(|l| l.starts_with("https://"))?
                .to_owned();
            if op == "issue_create" {
                let path = url.split('#').next().unwrap_or_default();
                let last = path.rsplit('/').next().unwrap_or_default();
                if last.is_empty() || !last.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let number: u64 = last.parse().ok()?;
                Some(crate::canonical::value_text(
                    &json!({"number": number, "url": url}),
                ))
            } else {
                Some(crate::canonical::value_text(&json!({"url": url})))
            }
        }
        _ => None,
    }
}

/// A credential's reach, stored with a built-in source's snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reach {
    pub account: Option<String>,
    pub host: String,
    pub token_type: String,
    pub scopes: Option<Vec<String>>,
    pub checked_at: String,
    pub error: Option<String>,
}
/// The token type from a token's prefix.
pub fn token_type(token: Option<&str>) -> &'static str {
    match token {
        Some(t) if t.starts_with("gho_") => "oauth",
        Some(t) if t.starts_with("ghp_") => "classic",
        Some(t) if t.starts_with("github_pat_") => "fine_grained",
        Some(t) if t.starts_with("ghu_") || t.starts_with("ghs_") => "app",
        _ => "unknown",
    }
}
/// Runs `gh api --include --hostname github.com user` with the gh
/// environment built from an instance's environment.
pub async fn check_reach(gh: &Path, state: &Path, instance_env: &[(String, String)]) -> Reach {
    let env = gh_env(instance_env, state);
    let token = env
        .iter()
        .find(|(k, _)| k == "GH_TOKEN")
        .map(|(_, v)| v.as_str());
    let mut reach = Reach {
        account: None,
        host: "github.com".into(),
        token_type: token_type(token).into(),
        scopes: None,
        checked_at: crate::store::now(),
        error: None,
    };
    let cwd = work_dir(state);
    let args: Vec<String> = ["api", "--include", "--hostname", "github.com", "user"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let error = match run(gh, &args, &env, &cwd, None, CHECK_TIMEOUT, None).await {
        Run::NotStarted => "gh could not be started".to_owned(),
        Run::Timeout | Run::Cancelled => format!(
            "gh did not finish within {} seconds",
            CHECK_TIMEOUT.as_secs()
        ),
        Run::TooLarge => "gh returned output Peerspan could not read".to_owned(),
        Run::Exited { code, .. } if code != 0 => format!("gh exited with status {code}"),
        Run::Exited { stdout, .. } => match parse_include(&stdout) {
            Some((login, scopes)) => {
                reach.account = Some(login);
                reach.scopes = scopes;
                return reach;
            }
            None => "gh returned output Peerspan could not read".to_owned(),
        },
    };
    reach.error = Some(error);
    reach
}
/// The login and `X-OAuth-Scopes` of `gh api --include` output.
fn parse_include(out: &[u8]) -> Option<(String, Option<Vec<String>>)> {
    let text = std::str::from_utf8(out).ok()?;
    let mut lines = text.split('\n');
    let status = lines.next()?.trim_end_matches('\r');
    if !status.starts_with("HTTP") {
        return None;
    }
    let mut scopes = None;
    let mut consumed = status.len() + 1;
    let mut ended = false;
    for line in lines.by_ref() {
        consumed += line.len() + 1;
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            ended = true;
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("x-oauth-scopes") {
            scopes = Some(
                value
                    .split(',')
                    .map(trim_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
            );
        }
    }
    if !ended {
        return None;
    }
    let body: Value = serde_json::from_str(text.get(consumed.min(text.len())..)?).ok()?;
    let login = body.as_object()?.get("login")?.as_str()?.to_owned();
    Some((login, scopes))
}

/// Whether `repo view` of a repository succeeds with an instance's
/// credential, within 10 seconds.
pub async fn repo_visible(
    gh: &Path,
    state: &Path,
    instance_env: &[(String, String)],
    repo: &str,
    timeout: Duration,
) -> bool {
    let env = gh_env(instance_env, state);
    let cwd = work_dir(state);
    matches!(
        run(
            gh,
            &repo_view_argv(repo),
            &env,
            &cwd,
            None,
            timeout.min(CHECK_TIMEOUT),
            None
        )
        .await,
        Run::Exited { code: 0, .. }
    )
}

/// The reach sentence (capabilities contract, slice 3).
pub fn sentence(reach: Option<&Value>, definition_account: Option<&str>) -> String {
    let reach = reach.filter(|r| r.is_object());
    let login = reach
        .and_then(|r| r["account"].as_str())
        .or(definition_account)
        .unwrap_or("unknown");
    let host = "github.com";
    let Some(r) = reach else {
        return format!(
            "Peerspan could not check the reach of the gh account {login} on {host} (not checked yet). Assume everything the account can reach."
        );
    };
    if let Some(e) = r["error"].as_str() {
        return format!(
            "Peerspan could not check the reach of the gh account {login} on {host} ({e}). Assume everything the account can reach."
        );
    }
    let scopes: Option<Vec<&str>> = r["scopes"]
        .as_array()
        .map(|l| l.iter().filter_map(Value::as_str).collect());
    if let Some(list) = &scopes {
        let joined = list.join(", ");
        if list.contains(&"repo") {
            return format!(
                "The gh account {login} on {host} (token scopes: {joined}) can read and change every repository {login} can, public and private."
            );
        }
        if list.contains(&"public_repo") {
            return format!(
                "The gh account {login} on {host} (token scopes: {joined}) can read public repositories and change public repositories {login} can."
            );
        }
        if matches!(r["token_type"].as_str(), Some("oauth" | "classic")) {
            let shown = if joined.is_empty() {
                "none".to_owned()
            } else {
                joined
            };
            return format!(
                "The gh account {login} on {host} (token scopes: {shown}) can read public repositories only."
            );
        }
    }
    format!(
        "The gh account {login} on {host} uses a token that states no scopes, so Peerspan cannot tell which repositories it reaches. Assume every repository it was granted."
    )
}

/// The argument vector the daemon starts a built-in source with.
pub fn server_args(gh: &str, state: &Path) -> Vec<String> {
    vec![
        "builtin-source".into(),
        "gh".into(),
        "--gh".into(),
        gh.to_owned(),
        "--state".into(),
        state.display().to_string(),
    ]
}
/// The `gh` path and state directory of a built-in source's launch.
pub fn launch_target(command_args: &[String]) -> Option<(PathBuf, PathBuf)> {
    match command_args {
        [a, b, c, gh, d, state]
            if a == "builtin-source" && b == "gh" && c == "--gh" && d == "--state" =>
        {
            Some((PathBuf::from(gh), PathBuf::from(state)))
        }
        _ => None,
    }
}

/// `builtin-source gh --gh PATH --state DIR`: serves MCP on stdio until
/// standard input closes.
pub async fn serve(args: &[String]) -> anyhow::Result<()> {
    let mut full = vec!["builtin-source".to_owned()];
    full.extend(args.iter().cloned());
    let Some((gh, state)) = launch_target(&full) else {
        anyhow::bail!("usage: builtin-source gh --gh PATH --state DIR");
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    // Standard input and output are read and written on their own threads.
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        while let Some(line) = rx.blocking_recv() {
            if out.write_all(line.as_bytes()).is_err()
                || out.write_all(b"\n").is_err()
                || out.flush().is_err()
            {
                break;
            }
        }
    });
    let (lines_tx, mut lines) = mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });
    let calls: Arc<Mutex<HashMap<String, Arc<Notify>>>> = Arc::default();
    let gh = Arc::new(gh);
    let state = Arc::new(state);
    while let Some(line) = lines.recv().await {
        let Ok(message) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        let method = message["method"].as_str().unwrap_or_default().to_owned();
        let id = message.get("id").cloned();
        let reply = |result: Result<Value, (i64, String)>| -> String {
            let id = id.clone().unwrap_or(Value::Null);
            match result {
                Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}).to_string(),
                Err((code, m)) => {
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}})
                        .to_string()
                }
            }
        };
        match (method.as_str(), &id) {
            ("notifications/cancelled", _) => {
                let key = message["params"]["requestId"].to_string();
                if let Some(c) = calls.lock().ok().and_then(|c| c.get(&key).cloned()) {
                    c.notify_one();
                }
            }
            (_, None) => {}
            ("initialize", Some(_)) => {
                let asked = message["params"]["protocolVersion"].as_str();
                let version = match asked {
                    Some(v) if ["2025-06-18", "2025-03-26", "2024-11-05"].contains(&v) => v,
                    _ => "2025-06-18",
                };
                let _ = tx.send(reply(Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "peerspan-gh", "version": env!("CARGO_PKG_VERSION")},
                }))));
            }
            ("ping", Some(_)) => {
                let _ = tx.send(reply(Ok(json!({}))));
            }
            ("tools/list", Some(_)) => {
                let _ = tx.send(reply(Ok(json!({"tools": tools()}))));
            }
            ("tools/call", Some(request_id)) => {
                let name = message["params"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                if !OPERATIONS.contains(&name.as_str()) {
                    let _ = tx.send(reply(Err((-32602, format!("Unknown tool: {name}")))));
                    continue;
                }
                let arguments = match &message["params"]["arguments"] {
                    Value::Null => Some(Map::new()),
                    Value::Object(o) => Some(o.clone()),
                    _ => None,
                };
                let checked = match arguments {
                    Some(a) => validate(&name, &a).map(|_| a),
                    None => Err("arguments is an object".into()),
                };
                let args = match checked {
                    Ok(a) => a,
                    Err(detail) => {
                        let _ = tx.send(reply(Ok(text_result(
                            format!("Invalid arguments for {name}: {detail}"),
                            true,
                        ))));
                        continue;
                    }
                };
                let key = request_id.to_string();
                let cancel = Arc::new(Notify::new());
                if let Ok(mut c) = calls.lock() {
                    c.insert(key.clone(), cancel.clone());
                }
                let (tx, calls, gh, state, id) = (
                    tx.clone(),
                    calls.clone(),
                    gh.clone(),
                    state.clone(),
                    request_id.clone(),
                );
                tokio::spawn(async move {
                    let answer =
                        execute(&gh, &state, &name, &args, cancel, |l| eprintln!("{l}")).await;
                    if let Ok(mut c) = calls.lock() {
                        c.remove(&key);
                    }
                    let line = match answer {
                        Answer::Result(r) => {
                            json!({"jsonrpc": "2.0", "id": id, "result": r}).to_string()
                        }
                        Answer::Error(code, m) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": m}}).to_string(),
                        Answer::None => return,
                    };
                    let _ = tx.send(line);
                });
            }
            (other, Some(_)) => {
                let _ = tx.send(reply(Err((-32601, format!("Method not found: {other}")))));
            }
        }
    }
    drop(tx);
    let _ = tokio::task::spawn_blocking(move || writer.join()).await;
    Ok(())
}
