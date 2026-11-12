//! Runtime agents (runtime agent contract): registered agents of this host
//! whose tasks the host runs itself, each in its own microVM on a peerfs
//! fork. This module holds the owner's launch profiles
//! (`runtime-agents.json`), the agents' credentials (`credentials/`), their
//! local API, the `POST /v1/runs` body a task is dispatched with, and the
//! text a finished task returns. Dispatching and following the run are
//! the runtime task worker's (`runtime_task`).
use crate::{
    api::{blocking, decode},
    model::Error,
    store::{Store, append_event, now},
    task::TaskRequest,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as UrlPath, State, rejection::BytesRejection},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const PROFILES_FILE: &str = "runtime-agents.json";
const CREDENTIALS: &str = "credentials";
/// The most a final event's `output` holds (task contract).
const MAX_OUTPUT: usize = crate::task::MAX_TEXT;
/// The longest error a `not committed:` trailer carries.
const MAX_ERROR: usize = 1024;
/// Serializes changes to the profiles file.
static PROFILES: Mutex<()> = Mutex::new(());

/// The Codex harness command's script: the prompt arrives on stdin, Codex's
/// event stream and logs go to stderr, and its final message to stdout.
const CODEX_SCRIPT: &str = r#"export HOME=/root CODEX_HOME=/root/.codex
mkdir -p "$CODEX_HOME" || exit 1
CODEX_API_KEY=$(cat /run/secrets/openai_api_key) || exit 1
export CODEX_API_KEY
last="$CODEX_HOME/peerspan-last-message"
rm -f "$last"
cd /workspace || exit 1
/opt/peerspan/harness/codex exec --json --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox --output-last-message "$last" - >&2
status=$?
cat "$last" 2>/dev/null
exit $status
"#;

/// The Claude harness command's script (RUN-13): it runs as root with
/// `IS_SANDBOX=1`, the prompt arrives on stdin, Claude's final message goes
/// to stdout and its logs to stderr. Claude Code needs glibc, so an image
/// without it gets a message saying so rather than a loader error.
const CLAUDE_SCRIPT: &str = r#"if [ ! -e /lib64/ld-linux-x86-64.so.2 ]; then
  echo 'the image has no glibc, which Claude Code needs'
  exit 127
fi
export HOME=/root IS_SANDBOX=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
ANTHROPIC_API_KEY=$(cat /run/secrets/anthropic_api_key) || exit 1
export ANTHROPIC_API_KEY
cd /workspace || exit 1
exec /opt/peerspan/harness/claude -p --dangerously-skip-permissions --output-format text --no-session-persistence
"#;

/// The harness command's script and the run's secret name, at
/// `/run/secrets/NAME`, for a profile's `harness`.
fn harness_command(harness: &str) -> (&'static str, &'static str) {
    match harness {
        "claude" => (CLAUDE_SCRIPT, "anthropic_api_key"),
        _ => (CODEX_SCRIPT, "openai_api_key"),
    }
}

/// A launch profile, as stored and returned (without `credential`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub agent_id: String,
    pub harness: String,
    pub harness_dir: String,
    /// The OCI image each run boots, or null for the runtime's own. Older
    /// profiles have none stored.
    #[serde(default)]
    pub image: Option<String>,
    pub from_branch: String,
    pub network: String,
    pub cpus: i64,
    pub memory_mib: i64,
    pub timeout_seconds: i64,
    pub max_runs: i64,
}

/// `PUT /v1/agents/{agent_id}/runtime`: the profile's fields but
/// `agent_id`; an omitted one takes its default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRequest {
    #[serde(default)]
    harness: Option<String>,
    harness_dir: String,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    from_branch: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    cpus: Option<i64>,
    #[serde(default)]
    memory_mib: Option<i64>,
    #[serde(default)]
    timeout_seconds: Option<i64>,
    #[serde(default)]
    max_runs: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    value: String,
}

fn invalid(field: &str) -> Error {
    Error::Invalid(field.into())
}
fn coded(status: u16, code: &'static str, message: &str) -> Error {
    Error::Coded {
        status,
        code,
        message: message.into(),
        extra: Default::default(),
    }
}

impl ProfileRequest {
    /// The profile for `agent_id`, with defaults, checked against the
    /// contract's ranges.
    fn profile(self, agent_id: &str) -> Result<Profile, Error> {
        let profile = Profile {
            agent_id: agent_id.into(),
            harness: self.harness.unwrap_or_else(|| "codex".into()),
            harness_dir: self.harness_dir,
            image: self.image,
            from_branch: self.from_branch.unwrap_or_else(|| "main".into()),
            network: self.network.unwrap_or_else(|| "internet".into()),
            cpus: self.cpus.unwrap_or(2),
            memory_mib: self.memory_mib.unwrap_or(2048),
            timeout_seconds: self.timeout_seconds.unwrap_or(3600),
            max_runs: self.max_runs.unwrap_or(3),
        };
        if !matches!(profile.harness.as_str(), "codex" | "claude") {
            return Err(invalid("harness"));
        }
        if profile.image.as_ref().is_some_and(|image| {
            image.is_empty() || image.len() > 1024 || !image.bytes().all(|b| b.is_ascii_graphic())
        }) {
            return Err(invalid("image"));
        }
        if !profile.harness_dir.starts_with('/')
            || profile.harness_dir.len() > 4096
            || profile.harness_dir.contains('\0')
        {
            return Err(invalid("harness_dir"));
        }
        if !crate::policy::peerfs_workspace(&profile.from_branch) {
            return Err(invalid("from_branch"));
        }
        if !matches!(profile.network.as_str(), "none" | "internet") {
            return Err(invalid("network"));
        }
        for (name, value, lo, hi) in [
            ("cpus", profile.cpus, 1, 64),
            ("memory_mib", profile.memory_mib, 128, 262_144),
            ("timeout_seconds", profile.timeout_seconds, 1, 86_400),
            ("max_runs", profile.max_runs, 1, 64),
        ] {
            if !(lo..=hi).contains(&value) {
                return Err(invalid(name));
            }
        }
        Ok(profile)
    }
}

/// A credential's text: 1 to 4,096 bytes of printable ASCII without
/// whitespace, after dropping one trailing newline.
fn credential_text(value: &str) -> Result<&str, Error> {
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    if value.is_empty() || value.len() > 4096 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid("value"));
    }
    Ok(value)
}

/// Writes a private (0600) file atomically, through a temporary file of this write's own, so
/// concurrent writes of one path never share a temporary file: the last rename wins whole.
fn write_private(path: &Path, raw: &[u8]) -> Result<(), Error> {
    use std::{
        io::Write,
        os::unix::fs::OpenOptionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let mut partial = path.as_os_str().to_owned();
    partial.push(format!(
        ".partial-{}-{}",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    let partial = PathBuf::from(partial);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial)
        .and_then(|mut file| file.write_all(raw).and_then(|()| file.sync_all()))
        .and_then(|()| std::fs::rename(&partial, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&partial);
        return Err(Error::Internal(e.into()));
    }
    Ok(())
}
fn remove(path: &Path) -> Result<bool, Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Internal(e.into())),
    }
}

impl Store {
    /// Every launch profile, in agent ID order.
    pub(crate) fn runtime_profiles(&self) -> Result<Vec<Profile>, Error> {
        match std::fs::read(self.state_directory().join(PROFILES_FILE)) {
            Ok(raw) => {
                let mut profiles: Vec<Profile> = serde_json::from_slice(&raw)?;
                profiles.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
                Ok(profiles)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(Error::Internal(e.into())),
        }
    }
    /// The agent's launch profile, if it has one.
    pub(crate) fn runtime_profile(&self, agent_id: &str) -> Result<Option<Profile>, Error> {
        Ok(self
            .runtime_profiles()?
            .into_iter()
            .find(|p| p.agent_id == agent_id))
    }
    /// Replaces the agent's profile with `profile`, or removes it with
    /// None. Returns whether a profile was there before.
    fn store_profile(&self, agent_id: &str, profile: Option<Profile>) -> Result<bool, Error> {
        let _guard = PROFILES
            .lock()
            .map_err(|_| Error::Internal(anyhow::anyhow!("profiles lock poisoned")))?;
        let mut profiles = self.runtime_profiles()?;
        let before = profiles.len();
        profiles.retain(|p| p.agent_id != agent_id);
        let existed = profiles.len() != before;
        if let Some(profile) = profile {
            profiles.push(profile);
        }
        profiles.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        write_private(
            &self.state_directory().join(PROFILES_FILE),
            &serde_json::to_vec_pretty(&profiles)?,
        )?;
        Ok(existed)
    }
    /// The absolute path of the agent's credential file, which the runtime
    /// reads at each start.
    pub(crate) fn credential_path(&self, agent_id: &str) -> Result<PathBuf, Error> {
        let directory = std::path::absolute(self.state_directory().join(CREDENTIALS))
            .map_err(|e| Error::Internal(e.into()))?;
        Ok(directory.join(agent_id))
    }
    pub(crate) fn has_credential(&self, agent_id: &str) -> Result<bool, Error> {
        Ok(self.credential_path(agent_id)?.is_file())
    }
    fn set_credential(&self, agent_id: &str, value: Option<&str>) -> Result<(), Error> {
        let path = self.credential_path(agent_id)?;
        let Some(value) = value else {
            remove(&path)?;
            return Ok(());
        };
        if let Some(directory) = path.parent() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .map_err(|e| Error::Internal(e.into()))?;
        }
        write_private(&path, value.as_bytes())
    }
    fn activity(&self, kind: &str, agent_id: &str) -> Result<(), Error> {
        let mut c = self.connection()?;
        let tx = c.transaction()?;
        append_event(&tx, kind, agent_id, &now())?;
        tx.commit()?;
        Ok(())
    }
}

/// The `POST /v1/runs` body for a runtime agent's task, built from the
/// profile as it is now. It names the credential's path, never the key.
pub(crate) fn run_body(
    store: &Store,
    profile: &Profile,
    agent_name: &str,
    run_id: &str,
    sender: &str,
    request: &TaskRequest,
) -> Result<Value, Error> {
    let secret = store.credential_path(&profile.agent_id)?;
    let (script, name) = harness_command(&profile.harness);
    let mut body = json!({
        "run_id": run_id,
        "argv": ["/bin/sh", "-c", script],
        "cwd": "/workspace",
        "env": {},
        "resources": {
            "cpus": profile.cpus,
            "memory_mib": profile.memory_mib,
            "timeout_seconds": profile.timeout_seconds,
        },
        "network": profile.network,
        "workspace_archive": null,
        "results": "none",
        "peerfs_workspace": format!("{agent_name}.{}", request.task_id),
        "peerfs_fork_from": profile.from_branch,
        "peerfs_agent": agent_name,
        "peerfs_commit": true,
        "peerfs_commit_message": format!("{} from {sender}", request.task_id),
        "stdin": STANDARD.encode(request.input.as_bytes()),
        "harness": profile.harness_dir,
        "secrets": { name: secret },
    });
    if let Some(image) = &profile.image {
        body["image"] = image.as_str().into();
    }
    Ok(body)
}

/// How a runtime agent's run ended, for its output text.
pub(crate) struct Ending<'a> {
    /// The run's stdout as collected, at most the output bound.
    pub stdout: &'a [u8],
    /// The run wrote more than `stdout` holds, not all whitespace.
    pub stdout_more: bool,
    pub started: bool,
    pub cancelled: bool,
    pub exit_code: Option<i64>,
    pub signal: Option<i64>,
    pub timed_out: bool,
    pub error: Option<String>,
    pub commit: Option<String>,
    /// The stored request's fork name and its `from_branch`.
    pub fork: &'a str,
    pub from: &'a str,
}

/// Cuts `text` to at most `max` bytes at a character boundary.
fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The final event's output (The output): the message, a blank line, and
/// the branch line, within 65,536 bytes.
pub(crate) fn output(e: &Ending<'_>) -> String {
    let decoded = String::from_utf8_lossy(e.stdout);
    let mut message = if e.stdout_more {
        decoded.into_owned()
    } else {
        decoded.trim_end().to_owned()
    };
    let error = e
        .error
        .as_ref()
        .map(|err| err.replace(['\r', '\n'], " "))
        .filter(|err| !err.is_empty());
    if message.is_empty() {
        message = if e.cancelled {
            "cancelled".into()
        } else if e.timed_out {
            "timed out".into()
        } else if let Some(signal) = e.signal {
            format!("signal {signal}")
        } else if let Some(code) = e.exit_code.filter(|c| *c != 0) {
            format!("exit {code}")
        } else if let Some(error) = &error {
            error.clone()
        } else if let Some(code) = e.exit_code {
            format!("exit {code}")
        } else {
            "the run did not start".into()
        };
    }
    let trailer = if !e.started {
        "Branch: none".to_owned()
    } else if let Some(error) = &error {
        format!(
            "Branch: {}, not committed: {}",
            e.fork,
            cut(error, MAX_ERROR)
        )
    } else if let Some(commit) = &e.commit {
        format!("Branch: {} at commit {commit}", e.fork)
    } else {
        format!("Branch: {}, unchanged from {}", e.fork, e.from)
    };
    let budget = MAX_OUTPUT.saturating_sub(trailer.len() + 2);
    if message.len() > budget {
        let ellipsis = "…";
        message = format!(
            "{}{ellipsis}",
            cut(&message, budget.saturating_sub(ellipsis.len()))
        );
    }
    format!("{message}\n\n{trailer}")
}

pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/agents/runtime", get(list))
        .route("/v1/agents/{id}/runtime", get(show).put(set).delete(clear))
        .route(
            "/v1/agents/{id}/credential",
            axum::routing::put(set_credential).delete(clear_credential),
        )
}

/// A profile as shown, with `credential` added.
fn shown(store: &Store, profile: &Profile) -> Result<Value, Error> {
    let mut value = serde_json::to_value(profile)?;
    value["credential"] = store.has_credential(&profile.agent_id)?.into();
    Ok(value)
}

async fn list(State(store): State<Arc<Store>>) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, |s| {
            let profiles = s.runtime_profiles()?;
            Ok(Value::Array(
                profiles
                    .iter()
                    .map(|p| shown(s, p))
                    .collect::<Result<_, _>>()?,
            ))
        })
        .await?,
    ))
}

async fn show(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(
        blocking(store, move |s| {
            let profile = s.runtime_profile(&id)?.ok_or(Error::NotFound)?;
            shown(s, &profile)
        })
        .await?,
    ))
}

async fn set(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Profile>, Error> {
    let request: ProfileRequest = decode(body)?;
    let (agent, switch) = {
        let id = id.clone();
        blocking(store.clone(), move |s| {
            Ok((s.agent(&id)?, s.runtime_switch()?))
        })
        .await?
    };
    if !crate::directory::addressable(&agent.name) {
        return Err(invalid("the agent's name is not addressable"));
    }
    let profile = request.profile(&agent.id)?;
    let unavailable = || {
        coded(
            409,
            "runtime_unavailable",
            "a launch profile needs the runtime switch on and a runtime that serves a peerfs space",
        )
    };
    let switch = switch.ok_or_else(unavailable)?;
    let report = crate::runtime::report(&switch.socket)
        .await
        .map_err(|_| unavailable())?;
    if report["peerfs"] != Value::Bool(true) {
        return Err(unavailable());
    }
    if profile.image.is_some() && report["images"] != Value::Bool(true) {
        return Err(coded(
            409,
            "runtime_unavailable",
            "an image needs a runtime that reports images true",
        ));
    }
    for (field, value, most) in [
        ("cpus", profile.cpus, "max_cpus"),
        ("memory_mib", profile.memory_mib, "max_memory_mib"),
        ("timeout_seconds", profile.timeout_seconds, "max_seconds"),
    ] {
        if report[most].as_i64().is_none_or(|m| value > m) {
            return Err(coded(
                422,
                "too_large",
                &format!("{field} {value} exceeds the runtime's {most}"),
            ));
        }
    }
    if profile.network == "internet" && report["max_network"].as_str() != Some("internet") {
        return Err(coded(
            422,
            "too_large",
            "network internet exceeds the runtime's max_network",
        ));
    }
    blocking(store, move |s| {
        s.store_profile(&profile.agent_id, Some(profile.clone()))?;
        s.activity("runtime.agent_set", &profile.agent_id)?;
        Ok(Json(profile))
    })
    .await
}

async fn clear(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Value>, Error> {
    blocking(store, move |s| {
        let agent = s.agent(&id)?;
        if s.store_profile(&agent.id, None)? {
            s.activity("runtime.agent_cleared", &agent.id)?;
        }
        Ok(Json(json!({})))
    })
    .await
}

async fn set_credential(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: CredentialRequest = decode(body)?;
    blocking(store, move |s| {
        let agent = s.agent(&id)?;
        s.set_credential(&agent.id, Some(credential_text(&request.value)?))?;
        s.activity("runtime.credential_set", &agent.id)?;
        Ok(Json(json!({ "agent_id": agent.id, "credential": true })))
    })
    .await
}

async fn clear_credential(
    State(store): State<Arc<Store>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Value>, Error> {
    blocking(store, move |s| {
        let agent = s.agent(&id)?;
        s.set_credential(&agent.id, None)?;
        s.activity("runtime.credential_cleared", &agent.id)?;
        Ok(Json(json!({ "agent_id": agent.id, "credential": false })))
    })
    .await
}
