//! Native owner session lifecycle, independent of a harness or its runtime.
use crate::cli::SessionCommand;
use anyhow::{Context, bail};
use chrono::{DateTime, SecondsFormat, TimeDelta};
use hyper::Method;
use peerspan_host::membership;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: u64 = 1 << 20;
#[derive(Debug)]
pub struct DaemonError {
    pub status: u16,
    pub message: String,
    /// The error body's `code`, or empty.
    pub code: String,
}
impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "host daemon: {}", self.message)
    }
}
impl std::error::Error for DaemonError {}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    id: String,
    command: Vec<String>,
    operations: Vec<String>,
}
impl Manifest {
    fn supports(&self, op: &str) -> bool {
        self.operations.iter().any(|value| value == op)
    }
    fn validate(&self) -> anyhow::Result<()> {
        let mut seen = BTreeSet::new();
        if self.version != 1
            || !name(&self.id)
            || self.command.is_empty()
            || self.command.len() > 64
            || !self.supports("prepare")
            || !self.supports("check")
            || self.command.iter().any(|arg| arg.contains('\0'))
        {
            bail!("invalid integration manifest")
        }
        for op in &self.operations {
            if !["prepare", "check", "launch"].contains(&op.as_str()) || !seen.insert(op) {
                bail!("invalid integration operations")
            }
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    name: String,
    status: String,
    detail: String,
}
impl Check {
    fn new(name: &str, ok: bool, detail: &str) -> Self {
        Self {
            name: name.into(),
            status: if ok { "ok" } else { "error" }.into(),
            detail: scrub(detail),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    program: String,
    args: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderResult {
    version: u32,
    checks: Vec<Check>,
    #[serde(default = "empty_object")]
    state: Value,
    #[serde(default)]
    files: BTreeMap<String, String>,
    #[serde(default)]
    launch: Option<Launch>,
}
fn empty_object() -> Value {
    json!({})
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    version: u32,
    phase: String,
    directory: String,
    state: String,
    host_id: String,
    agent_id: String,
    session_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    adapter_id: String,
    harness: Manifest,
    options: BTreeMap<String, String>,
    provider_state: Value,
    files: BTreeMap<String, String>,
    request: Value,
    /// The project's real path, in profiles made by `attach`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    workspace: String,
}
struct SetupOptions {
    directory: PathBuf,
    state: Option<PathBuf>,
    harness: String,
    agent: String,
    /// None for a renewable credential.
    expiry: Option<String>,
    integrations: Option<PathBuf>,
    runner: Option<PathBuf>,
    routes: Option<PathBuf>,
    options: Vec<String>,
    /// Directory access with this rate cap, for `attach`.
    max_sends_per_hour: Option<i64>,
    /// Capability calls with this rate cap, for `attach`.
    max_calls_per_hour: Option<i64>,
    /// The project an `attach` profile records.
    workspace: Option<String>,
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
fn artifact(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        && name != "profile.json"
        && name != "credential.json"
}
fn valid_id(value: &str, prefix: &str, length: usize) -> bool {
    value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(|text| {
            text.len() == length * 2
                && text
                    .bytes()
                    .all(|c| c.is_ascii_digit() || b"abcdef".contains(&c))
        })
}
fn future(value: &str) -> bool {
    DateTime::parse_from_rfc3339(value).is_ok_and(|at| at > peerspan_host::clock::now())
}
fn scrub(value: &str) -> String {
    let mut text = value.to_owned();
    for prefix in ["token_", "instance_"] {
        let mut offset = 0;
        while let Some(at) = text[offset..].find(prefix) {
            let start = offset + at;
            let end = start + prefix.len() + 64;
            if text.get(start + prefix.len()..end).is_some_and(|s| {
                s.bytes()
                    .all(|c| c.is_ascii_digit() || b"abcdef".contains(&c))
            }) {
                text.replace_range(start..end, "[redacted]");
                offset = start + 10;
            } else {
                offset = start + prefix.len();
            }
        }
    }
    text.chars().take(600).collect()
}
fn absolute(path: &Path) -> anyhow::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    // Lexically clean paths without requiring a future setup directory to exist.
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    Ok(result)
}
fn executable(program: &str) -> anyhow::Result<String> {
    let paths = if program.contains('/') {
        vec![absolute(Path::new(program))?]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(program))
            .collect()
    };
    for path in paths {
        if fs::metadata(&path).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0) {
            return Ok(fs::canonicalize(path)?.to_string_lossy().into_owned());
        }
    }
    bail!("integration executable is missing or not executable")
}
fn read_file(path: &Path, private: bool) -> anyhow::Result<Vec<u8>> {
    let flags = libc::O_NONBLOCK | if private { libc::O_NOFOLLOW } else { 0 };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    let stat = file.metadata()?;
    if !stat.is_file() || stat.len() > LIMIT {
        bail!("configuration must be a regular file of at most 1 MiB")
    }
    if private && (stat.mode() & 0o077 != 0 || stat.uid() != unsafe { libc::getuid() }) {
        bail!("setup files must be private and owned by this account")
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT as usize {
        bail!("configuration exceeds 1 MiB")
    }
    Ok(bytes)
}
fn read_json<T: DeserializeOwned>(path: &Path, private: bool) -> anyhow::Result<T> {
    serde_json::from_slice(&read_file(path, private)?)
        .map_err(|_| anyhow::anyhow!("invalid JSON configuration"))
}
fn private_directory(path: &Path) -> anyhow::Result<()> {
    let stat = fs::symlink_metadata(path).context("private setup directory is missing")?;
    if !stat.is_dir() || stat.mode() & 0o077 != 0 || stat.uid() != unsafe { libc::getuid() } {
        bail!("setup directory must be private and owned by this account")
    }
    Ok(())
}
fn random_id(prefix: &str) -> anyhow::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}
fn write_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if bytes.len() > LIMIT as usize {
        bail!("configuration exceeds 1 MiB")
    }
    let parent = path.parent().context("invalid setup path")?;
    let temporary = parent.join(random_id(".integration")?);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}
fn write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_file(path, &bytes)
}
fn load_manifest(
    root: Option<PathBuf>,
    id: &str,
    runner: Option<PathBuf>,
) -> anyhow::Result<Manifest> {
    if !name(id) {
        bail!("use a valid --harness ID")
    }
    let root = root
        .or_else(|| {
            std::env::var_os("PEERSPAN_INTEGRATIONS_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap_or_default()
                .parent()
                .unwrap_or(Path::new("."))
                .join("../share/peerspan/integrations")
        });
    let entries = fs::read_dir(&root)
        .context("integration directory is missing; specify --integrations DIR")?;
    let mut selected = None;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path().join("integration.json");
        if !path.exists() {
            continue;
        }
        let Ok(identity) = read_json::<Value>(&path, false) else {
            continue;
        };
        if identity["id"] != id {
            continue;
        }
        let mut m: Manifest =
            read_json(&path, false).context("invalid installed integration manifest")?;
        m.validate()?;
        if m.id != id {
            continue;
        }
        if selected.is_some() {
            bail!("duplicate harness ID in integration directory")
        }
        for arg in &mut m.command {
            if arg.starts_with("./") || arg.starts_with("../") {
                *arg = absolute(&entry.path().join(&*arg))?
                    .to_string_lossy()
                    .into_owned()
            }
        }
        selected = Some(m);
    }
    let mut m = selected.context("harness is not installed in the integration directory")?;
    if let Some(runner) = runner {
        m.command[0] = runner.to_string_lossy().into_owned()
    }
    m.command[0] = executable(&m.command[0])?;
    Ok(m)
}
struct HelperGroup(u32);
impl Drop for HelperGroup {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}
async fn provider(
    p: &Profile,
    op: &str,
    workspace: &str,
    args: &[String],
) -> anyhow::Result<ProviderResult> {
    if !p.harness.supports(op) {
        bail!("this integration does not support {op}")
    }
    let mut input = json!({"version":1,"operation":op,"context":{
        "directory":p.directory,"state":p.state,"agent_id":p.agent_id,"session_id":p.session_id,
        "adapter_socket":Path::new(&p.state).join("adapter.sock"),"credential_file":Path::new(&p.directory).join("credential.json"),
        "options":p.options,"provider_state":p.provider_state,"workspace":workspace,"arguments":args,
    }});
    // A launch names this executable, for the session's hook that runs
    // `session pending`.
    if op == "launch" {
        let executable = absolute(&std::env::current_exe()?)?;
        input["context"]["peerspan_executable"] = json!(executable);
    }
    let bytes = serde_json::to_vec(&input)?;
    if bytes.len() > LIMIT as usize {
        bail!("integration request exceeds 1 MiB")
    }
    let mut command = tokio::process::Command::new(&p.harness.command[0]);
    command
        .args(&p.harness.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command
        .spawn()
        .context("integration helper executable failed")?;
    let _group = HelperGroup(child.id().context("integration helper did not start")?);
    let output = tokio::time::timeout(Duration::from_secs(30), async {
        let mut stdin = child
            .stdin
            .take()
            .context("integration input unavailable")?;
        stdin.write_all(&bytes).await?;
        drop(stdin);
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .context("integration output unavailable")?
            .take(LIMIT + 1)
            .read_to_end(&mut output)
            .await?;
        if output.len() > LIMIT as usize || !child.wait().await?.success() {
            bail!("integration helper failed")
        }
        Ok::<_, anyhow::Error>(output)
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "integration helper failed or timed out; check its installation and runtime"
        )
    })?
    .map_err(|_| {
        anyhow::anyhow!(
            "integration helper failed or timed out; check its installation and runtime"
        )
    })?;
    let mut result: ProviderResult = serde_json::from_slice(&output)
        .map_err(|_| anyhow::anyhow!("invalid integration response"))?;
    if result.version != 1 {
        bail!("invalid integration response")
    }
    for check in &mut result.checks {
        if check.name.is_empty()
            || check.name.len() > 64
            || !check
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || !["ok", "error"].contains(&check.status.as_str())
        {
            bail!("invalid integration check")
        }
        check.name = format!("harness/{}", check.name);
        check.detail = scrub(&check.detail);
    }
    if result.files.keys().any(|name| !artifact(name)) {
        bail!("integration returned an invalid artifact filename")
    }
    Ok(result)
}
fn failed(checks: &[Check]) -> bool {
    checks.iter().any(|c| c.status != "ok")
}
fn check_errors(checks: &[Check]) -> String {
    checks
        .iter()
        .filter(|c| c.status == "error")
        .map(|c| c.detail.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}
async fn call(
    p: &Profile,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    tokio::time::timeout(
        Duration::from_secs(10),
        crate::call(
            Path::new(&p.state).join("admin.sock"),
            method,
            path.into(),
            body,
        ),
    )
    .await
    .context("host daemon request timed out")?
}
fn load_profile(directory: &Path, state: &Option<PathBuf>) -> anyhow::Result<Profile> {
    let directory = absolute(directory)?;
    private_directory(&directory)?;
    let p: Profile = read_json(&directory.join("profile.json"), true)?;
    if p.version != 2 {
        bail!("unsupported setup profile; use a fresh session setup directory")
    }
    p.harness.validate()?;
    if !Path::new(&p.harness.command[0]).is_absolute()
        || Path::new(&p.directory) != directory
        || !Path::new(&p.state).is_absolute()
        || !valid_id(&p.agent_id, "agent", 16)
        || !valid_id(&p.session_id, "session", 16)
        || p.request["agent_id"] != p.agent_id
        || p.request["session_id"] != p.session_id
        || p.request["integration"] != p.harness.id
        || !["configured", "preparing"].contains(&p.phase.as_str())
        || p.phase == "configured" && !valid_id(&p.adapter_id, "adapter", 16)
        || !p.request["routes"].is_array()
        || p.files.keys().any(|name| !artifact(name))
    {
        bail!("invalid setup profile")
    }
    if let Some(state) = state
        && absolute(state)? != Path::new(&p.state)
    {
        bail!("this setup belongs to another state directory")
    }
    Ok(p)
}
async fn same_host(p: &Profile) -> anyhow::Result<()> {
    if call(p, Method::GET, "/v1/host", None).await?["id"] != p.host_id {
        bail!(
            "host_changed: daemon identity differs from the setup; prepare a fresh setup for this host"
        )
    }
    Ok(())
}
fn credential(p: &Profile) -> anyhow::Result<Value> {
    let value: Value = read_json(&Path::new(&p.directory).join("credential.json"), true)?;
    if !valid_id(value["token"].as_str().unwrap_or(""), "token", 32)
        || value["adapter"]["id"] != p.adapter_id
        || value["adapter"]["session_id"] != p.session_id
    {
        bail!("credential file does not belong to this attachment")
    }
    Ok(value)
}
async fn verify(p: &Profile, token: &Value) -> anyhow::Result<bool> {
    Ok(call(
        p,
        Method::POST,
        &format!("/v1/adapters/{}/verify-credential", p.adapter_id),
        Some(json!({"token":token})),
    )
    .await?["matches"]
        == true)
}
fn finish(p: &mut Profile, result: Value) -> anyhow::Result<()> {
    if result["session"]["id"] != p.session_id
        || result["session"]["agent_id"] != p.agent_id
        || result["session"]["integration"] != p.harness.id
        || result["credential"]["adapter"]["session_id"] != p.session_id
        || !valid_id(
            result["credential"]["adapter"]["id"].as_str().unwrap_or(""),
            "adapter",
            16,
        )
        || !valid_id(
            result["credential"]["token"].as_str().unwrap_or(""),
            "token",
            32,
        )
    {
        bail!("daemon response does not match the prepared attachment")
    }
    p.adapter_id = result["credential"]["adapter"]["id"]
        .as_str()
        .unwrap()
        .into();
    write_json(
        &Path::new(&p.directory).join("credential.json"),
        &result["credential"],
    )?;
    p.phase = "configured".into();
    write_json(&Path::new(&p.directory).join("profile.json"), p)
}
fn ensure_artifacts(p: &Profile) -> anyhow::Result<()> {
    for (name, content) in &p.files {
        let path = Path::new(&p.directory).join(name);
        match read_file(&path, true) {
            Ok(data) if data == content.as_bytes() => {}
            Ok(_) => {
                bail!("preparing integration configuration changed; inspect it before resuming")
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                write_file(&path, content.as_bytes())?
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn shape(route: &Value) -> Value {
    let mut map = serde_json::Map::new();
    for key in [
        "name",
        "peer_host_id",
        "target_agent_id",
        "grant_id",
        "expires_at",
        "max_message_bytes",
        "max_messages",
    ] {
        map.insert(key.into(), route[key].clone());
    }
    // A route that follows a renewable credential compares as if it had been
    // requested without an expiry.
    if route["follows_credential"] == true {
        map.insert("expires_at".into(), Value::Null);
    }
    // A destination without an action sends messages.
    map.insert(
        "action".into(),
        match &route["action"] {
            Value::Null => json!("message.append"),
            action => action.clone(),
        },
    );
    Value::Object(map)
}
async fn recover(p: &mut Profile) -> anyhow::Result<()> {
    same_host(p).await?;
    let session = match call(
        p,
        Method::GET,
        &format!("/v1/sessions/{}", p.session_id),
        None,
    )
    .await
    {
        Ok(session) => session,
        Err(error)
            if error
                .downcast_ref::<DaemonError>()
                .is_some_and(|e| e.status == 404) =>
        {
            let result = call(
                p,
                Method::POST,
                "/v1/adapters/setup",
                Some(p.request.clone()),
            )
            .await?;
            return finish(p, result);
        }
        Err(error) => return Err(error),
    };
    if session["agent_id"] != p.agent_id
        || session["integration"] != p.harness.id
        || session["state"] != "attached"
    {
        bail!("recovery refused: original session changed or was detached")
    }
    let all = call(p, Method::GET, "/v1/adapters", None).await?;
    let matches = all
        .as_array()
        .context("invalid daemon response")?
        .iter()
        .filter(|a| a["session_id"] == p.session_id)
        .collect::<Vec<_>>();
    let same_expiry = match p.request.get("expires_at") {
        Some(expiry) => matches.first().is_some_and(|m| m["expires_at"] == *expiry),
        None => matches.first().is_some_and(|m| m["renewable"] == true),
    };
    if matches.len() != 1
        || !matches[0]["revoked_at"].is_null()
        || !same_expiry
        || !future(matches[0]["expires_at"].as_str().unwrap_or(""))
    {
        bail!("recovery refused: preparing authorization is missing, changed, revoked, or expired")
    }
    p.adapter_id = matches[0]["id"]
        .as_str()
        .context("invalid daemon response")?
        .into();
    if call(
        p,
        Method::GET,
        &format!("/v1/adapters/{}/connection", p.adapter_id),
        None,
    )
    .await?["state"]
        != "registered"
    {
        bail!("recovery refused: preparing attachment has already connected; it cannot be adopted")
    }
    let routes = call(
        p,
        Method::GET,
        &format!("/v1/adapters/{}/routes", p.adapter_id),
        None,
    )
    .await?;
    let routes = routes.as_array().context("invalid daemon response")?;
    if routes.iter().any(|r| !r["revoked_at"].is_null()) {
        bail!("recovery refused: preparing destinations were withdrawn")
    }
    let mut actual = routes.iter().map(shape).collect::<Vec<_>>();
    let mut wanted = p.request["routes"]
        .as_array()
        .context("invalid preparing destinations")?
        .iter()
        .map(shape)
        .collect::<Vec<_>>();
    actual.sort_by_key(|v| v["name"].as_str().unwrap_or("").to_owned());
    wanted.sort_by_key(|v| v["name"].as_str().unwrap_or("").to_owned());
    if actual != wanted {
        bail!("recovery refused: destinations differ from the original request")
    }
    let mut secret = credential(p).ok();
    if let Some(value) = &secret
        && !verify(p, &value["token"]).await?
    {
        secret = None
    }
    let secret = match secret {
        Some(value) => value,
        None => {
            call(
                p,
                Method::POST,
                &format!("/v1/adapters/{}/rotate", p.adapter_id),
                None,
            )
            .await?
        }
    };
    finish(p, json!({"session":session,"credential":secret}))
}
pub(crate) fn parse_options(values: Vec<String>) -> anyhow::Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for value in values {
        let (key, text) = value
            .split_once('=')
            .context("integration options use KEY=VALUE")?;
        if key.is_empty()
            || key.len() > 64
            || !key.as_bytes()[0].is_ascii_alphabetic()
            || !key
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || text.contains('\0')
        {
            bail!("integration options use KEY=VALUE")
        }
        if result.insert(key.into(), text.into()).is_some() {
            bail!("duplicate integration option")
        }
    }
    Ok(result)
}
/// Destinations from a routes file. Without an expiry of their own they take
/// a fixed credential's, or follow a renewable one.
fn routes(path: Option<PathBuf>, expiry: Option<&str>) -> anyhow::Result<Value> {
    let Some(path) = path else {
        return Ok(json!([]));
    };
    let value: Value = read_json(&path, false)?;
    let rows = value.as_array().context("destinations must be an array")?;
    if rows.len() > 100 {
        bail!("destinations must contain at most 100 routes")
    }
    let mut result = Vec::new();
    for row in rows {
        let mut row = row.as_object().context("invalid destination")?.clone();
        if row.iter().any(|(key, v)| {
            (v.is_null() && key != "grant_id")
                || ![
                    "name",
                    "peer_host_id",
                    "target_agent_id",
                    "grant_id",
                    "expires_at",
                    "max_message_bytes",
                    "max_messages",
                    "action",
                ]
                .contains(&key.as_str())
        }) {
            bail!("unknown or null destination field")
        }
        if let Some(expiry) = expiry {
            row.entry("expires_at").or_insert(json!(expiry));
        }
        row.entry("max_message_bytes").or_insert(json!(65536));
        row.entry("max_messages").or_insert(json!(100));
        for key in ["name", "peer_host_id", "target_agent_id"] {
            if !row.get(key).is_some_and(Value::is_string) {
                bail!("invalid destination")
            }
        }
        if row.get("expires_at").is_some_and(|v| !v.is_string()) {
            bail!("invalid destination")
        }
        if row.get("action").is_some_and(|v| !v.is_string()) {
            bail!("invalid destination")
        }
        for key in ["max_message_bytes", "max_messages"] {
            if !row.get(key).is_some_and(|v| v.as_i64().is_some()) {
                bail!("invalid destination")
            }
        }
        // Without a grant, sends cite the target owner's policy.
        if row
            .get("grant_id")
            .is_some_and(|v| !v.is_null() && !v.is_string())
        {
            bail!("invalid destination")
        }
        result.push(Value::Object(row));
    }
    Ok(Value::Array(result))
}
async fn prepare(o: SetupOptions) -> anyhow::Result<Profile> {
    let directory = absolute(&o.directory)?;
    if fs::symlink_metadata(&directory).is_ok() {
        bail!("setup directory already exists; start or diagnose it, or choose a fresh directory")
    }
    if !valid_id(&o.agent, "agent", 16) || o.expiry.as_deref().is_some_and(|e| !future(e)) {
        bail!("use a registered agent ID and a future RFC3339 expiry")
    }
    let harness = load_manifest(o.integrations, &o.harness, o.runner)?;
    let state = absolute(&match o.state {
        Some(value) => value,
        None => crate::default_directory()?,
    })?;
    let mut p = Profile {
        version: 2,
        phase: "preparing".into(),
        directory: directory.to_string_lossy().into_owned(),
        state: state.to_string_lossy().into_owned(),
        host_id: String::new(),
        agent_id: o.agent.clone(),
        session_id: random_id("session")?,
        adapter_id: String::new(),
        harness,
        options: parse_options(o.options)?,
        provider_state: json!({}),
        files: BTreeMap::new(),
        request: Value::Null,
        workspace: o.workspace.unwrap_or_default(),
    };
    p.request = json!({"agent_id":o.agent,"session_id":p.session_id,"integration":p.harness.id,"routes":routes(o.routes,o.expiry.as_deref())?});
    if let Some(cap) = o.max_sends_per_hour {
        p.request["directory"] = json!(true);
        p.request["max_sends_per_hour"] = json!(cap);
    }
    if let Some(cap) = o.max_calls_per_hour {
        p.request["calls"] = json!(true);
        p.request["max_calls_per_hour"] = json!(cap);
    }
    // Without an expiry the credential is renewable.
    if let Some(expiry) = &o.expiry {
        p.request["expires_at"] = json!(expiry);
    }
    let result = provider(&p, "prepare", "", &[]).await?;
    if failed(&result.checks) {
        bail!("{}", check_errors(&result.checks))
    }
    p.provider_state = result.state;
    p.files = result.files;
    p.host_id = call(&p, Method::GET, "/v1/host", None).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .into();
    call(&p, Method::GET, &format!("/v1/agents/{}", p.agent_id), None).await?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory.parent().context("invalid setup directory")?)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .context("choose a fresh writable setup directory")?;
    write_json(&directory.join("profile.json"), &p)?;
    ensure_artifacts(&p)?;
    let result = match call(
        &p,
        Method::POST,
        "/v1/adapters/setup",
        Some(p.request.clone()),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            if error
                .downcast_ref::<DaemonError>()
                .is_some_and(|e| e.status >= 400 && e.status < 500)
            {
                for name in p.files.keys() {
                    let _ = fs::remove_file(directory.join(name));
                }
                let _ = fs::remove_file(directory.join("profile.json"));
                let _ = fs::remove_dir(&directory);
            }
            return Err(error);
        }
    };
    finish(&mut p, result)?;
    Ok(p)
}
async fn provider_checks(p: &Profile) -> Vec<Check> {
    let mut checks = Vec::new();
    for name in p.files.keys() {
        if let Err(error) = read_file(&Path::new(&p.directory).join(name), true) {
            checks.push(Check::new("private_file", false, &error.to_string()))
        }
    }
    match provider(p, "check", "", &[]).await {
        Ok(result) => checks.extend(result.checks),
        Err(error) => checks.push(Check::new("integration", false, &error.to_string())),
    }
    checks
}
async fn inspect(p: &Profile, mut checks: Vec<Check>) -> Value {
    let mut connection = Value::Null;
    let mut destinations = Vec::new();
    checks.push(Check::new(
        "setup",
        p.phase == "configured",
        "Interrupted setup can be resumed with session start --directory DIR.",
    ));
    let result: anyhow::Result<()>=async{
        if let Err(error)=same_host(p).await{checks.push(Check::new("host_changed",false,&error.to_string()));return Ok(())}
        checks.push(Check::new("daemon",true,"The original host daemon is reachable."));
        if p.phase!="configured"{return Ok(())}
        let secret=match credential(p){Ok(value)=>value,Err(error)=>{checks.push(Check::new("credential",false,&error.to_string()));return Ok(())}};
        let matched=verify(p,&secret["token"]).await?;
        checks.push(Check::new("credential",matched,"Credential file must match the daemon; save adapter rotate output atomically when rotating."));
        let adapter=call(p,Method::GET,&format!("/v1/adapters/{}",p.adapter_id),None).await?;
        let session=call(p,Method::GET,&format!("/v1/sessions/{}",p.session_id),None).await?;
        checks.push(Check::new("authorization",adapter["revoked_at"].is_null() && future(adapter["expires_at"].as_str().unwrap_or("")) && adapter["session_id"]==p.session_id && session["agent_id"]==p.agent_id,"Authorization must belong to this session and remain valid; rotation does not extend expiry."));
        connection=call(p,Method::GET,&format!("/v1/adapters/{}/connection",p.adapter_id),None).await?;
        let detail=match connection["state"].as_str().unwrap_or(""){
            "registered"=>"Configuration is prepared but no adapter has connected. Launch or connect through this integration.",
            "ready"=>"The original adapter has a valid lease; model availability and message consumption remain unverified.",
            "offline"=>"Adapter lease expired. Check the original harness process, daemon availability, and rotated credential file.",
            "detached"=>"Owner detached this session. Prepare a fresh setup.","revoked"=>"Owner revoked this authorization. Prepare a fresh setup.","expired"=>"Authorization expired. Prepare a fresh setup.",_=>"Adapter state is unknown.",
        };
        checks.push(Check::new("adapter_connection",connection["state"]=="ready",detail));
        match connection["channel"].as_str() {
            None => checks.push(Check::new("channel", true, "not running")),
            Some("verified") => checks.push(Check::new("channel", true, "verified")),
            Some(_) => {
                let agent = call(p, Method::GET, &format!("/v1/agents/{}", p.agent_id), None).await.ok();
                let name = agent.as_ref().and_then(|a| a["name"].as_str()).filter(|n| !n.is_empty()).unwrap_or(&p.agent_id);
                checks.push(Check::new("channel", false, &format!("unverified: {}", peerspan_host::status::channel_unverified_detail(name))))
            }
        }
        // Only Claude Code's channel delivery depends on the revision; a
        // missing value is never a failure.
        checks.push(match connection["protocol_version"].as_str() {
            None => Check::new("mcp_protocol", true, "The adapter has not reported a protocol revision yet."),
            Some(version) if p.harness.id == "claude-code" && protocol_too_new(version) => Check::new("mcp_protocol", false, &format!("The adapter negotiated MCP protocol revision {version}; revisions from {MCP_PROTOCOL_LIMIT} do not deliver channel events. Launch Claude Code with MCP_PROTOCOL_NEGOTIATION=legacy.")),
            Some(version) => Check::new("mcp_protocol", true, &format!("The adapter reported protocol revision {version}.")),
        });
        let routes=call(p,Method::GET,&format!("/v1/adapters/{}/route-status",p.adapter_id),None).await?;
        for entry in routes.as_array().context("invalid daemon response")?{
            let route=&entry["route"];let remaining=entry["messages_remaining"].as_i64().context("invalid route budget")?;
            let status=if !route["revoked_at"].is_null(){"revoked"}else if !future(route["expires_at"].as_str().unwrap_or("")){"expired"}else if remaining<=0{"budget_exhausted"}else{"configured"};
            destinations.push(json!({"name":route["name"],"status":status,"expires_at":route["expires_at"],"messages_remaining":remaining,"remote_acceptance":"unverified"}));
        }
        Ok(())
    }.await;
    if let Err(error) = result {
        checks.push(Check::new("inspection", false, &error.to_string()))
    }
    json!({"checked_at":peerspan_host::clock::now().to_rfc3339(),"directory":p.directory,"harness":p.harness.id,"agent_id":p.agent_id,"session_id":p.session_id,"adapter_id":p.adapter_id,"adapter_ready":connection["state"]=="ready" && connection["channel"]=="verified" && !failed(&checks),"channel":connection["channel"],"model_availability":"unknown","message_consumption":"unverified","connection":connection,"checks":checks,"destinations":destinations})
}
/// The first MCP protocol revision under which Claude Code drops channel
/// events.
const MCP_PROTOCOL_LIMIT: &str = "2026-07-28";
/// Whether a dated MCP protocol revision is at or after the limit.
/// Revisions that are not dates are not compared.
fn protocol_too_new(revision: &str) -> bool {
    let date = |text: &str| {
        (text.len() == 10)
            .then(|| chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").ok())
            .flatten()
    };
    match (date(revision), date(MCP_PROTOCOL_LIMIT)) {
        (Some(at), Some(limit)) => at >= limit,
        _ => false,
    }
}
pub async fn run(command: SessionCommand, state: Option<PathBuf>) -> anyhow::Result<()> {
    let (directory, workspace, args) = match command {
        SessionCommand::Setup {
            directory,
            harness,
            agent,
            expires_at,
            expires_in,
            integrations,
            runner,
            routes,
            options,
        } => {
            let p = if let Some(agent) = agent {
                let expiry = match (expires_at, expires_in) {
                    (Some(expiry), None) => Some(expiry),
                    (None, Some(duration)) => Some(relative_expiry(&duration)?),
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        bail!("--expires-at and --expires-in are mutually exclusive")
                    }
                };
                prepare(SetupOptions {
                    directory,
                    state,
                    harness: harness.context("--harness is required")?,
                    agent,
                    expiry,
                    integrations,
                    runner,
                    routes,
                    options,
                    max_sends_per_hour: None,
                    max_calls_per_hour: None,
                    workspace: None,
                })
                .await?
            } else {
                let mut p = load_profile(&directory, &state)?;
                if p.phase != "preparing" {
                    bail!("setup is already configured; use session start or session doctor")
                }
                ensure_artifacts(&p)?;
                let checks = provider_checks(&p).await;
                if failed(&checks) {
                    bail!("{}", check_errors(&checks))
                }
                recover(&mut p).await?;
                p
            };
            let adapter = credential(&p)?["adapter"].take();
            let value = json!({"state":"configured","adapter_ready":false,"directory":p.directory,"harness":p.harness.id,"agent_id":p.agent_id,"session_id":p.session_id,"adapter_id":p.adapter_id,"expires_at":adapter["expires_at"],"renewable":adapter["renewable"]==true,"destinations":p.request["routes"].as_array().unwrap().iter().map(|r|r["name"].clone()).collect::<Vec<_>>(),"launch_supported":p.harness.supports("launch"),"next":[crate::program(),"session",if p.harness.supports("launch"){ "start" }else{ "doctor" },"--directory",p.directory]});
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(());
        }
        SessionCommand::Doctor { directory } => {
            let directory = match directory {
                Some(directory) => directory,
                None => attached_profile(&state)?,
            };
            let p = load_profile(&directory, &state)?;
            let report = inspect(&p, provider_checks(&p).await).await;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["adapter_ready"] != true {
                bail!("session is not ready; inspect the diagnostic checks")
            };
            return Ok(());
        }
        SessionCommand::Start {
            directory,
            workspace,
            harness_args,
        } => (directory, workspace, harness_args),
        SessionCommand::Pending { json, hook } => return pending(&state, json, hook).await,
        _ => bail!("unknown session integration operation"),
    };
    let directory = match directory {
        Some(directory) => directory,
        None => attached_profile(&state)?,
    };
    start(&directory, &state, workspace, args).await
}

/// `session start`: recovers a preparing session if needed, then replaces
/// this process with the harness in the workspace. It returns only on error.
pub(crate) async fn start(
    directory: &Path,
    state: &Option<PathBuf>,
    workspace: Option<PathBuf>,
    args: Vec<String>,
) -> anyhow::Result<()> {
    let mut p = load_profile(directory, state)?;
    if !p.harness.supports("launch") {
        bail!(
            "this integration does not support launch; connect its consumer using the prepared configuration"
        )
    }
    let workspace = absolute(&workspace.unwrap_or(std::env::current_dir()?))?;
    if !workspace.is_dir() {
        bail!("workspace must be an existing directory")
    }
    if args.iter().any(|arg| arg.contains('\0')) {
        bail!("invalid harness argument")
    }
    if p.phase == "preparing" {
        ensure_artifacts(&p)?
    }
    let checks = provider_checks(&p).await;
    if failed(&checks) {
        bail!("{}", check_errors(&checks))
    }
    let plan = provider(&p, "launch", &workspace.to_string_lossy(), &args).await?;
    if failed(&plan.checks) {
        bail!("{}", check_errors(&plan.checks))
    }
    let plan = plan
        .launch
        .context("integration returned an invalid launch plan")?;
    if !Path::new(&plan.program).is_absolute() || plan.args.iter().any(|a| a.contains('\0')) {
        bail!("integration returned an invalid launch plan")
    }
    let program = executable(&plan.program)?;
    if p.phase == "preparing" {
        recover(&mut p).await?
    }
    let report = inspect(&p, checks).await;
    let blocked: Vec<Check> = serde_json::from_value::<Vec<Check>>(report["checks"].clone())?
        .into_iter()
        .filter(|c| c.status == "error" && c.name != "adapter_connection")
        .collect();
    if failed(&blocked) {
        bail!("{}", check_errors(&blocked))
    }
    if report["connection"]["state"] != "registered" {
        bail!(
            "attachment has already connected or was withdrawn; keep its original process or prepare a fresh owner-authorized setup"
        )
    }
    std::env::set_current_dir(workspace)?;
    Err(Command::new(program).args(plan.args).exec()).context("harness launch failed")
}

/// `$XDG_CONFIG_HOME/peerspan/sessions`, where `attach` keeps its profiles.
pub(crate) fn sessions_root() -> anyhow::Result<PathBuf> {
    let key = peerspan_host::persons::generated_key_path().context(
        "cannot locate the configuration directory: neither XDG_CONFIG_HOME nor HOME is set",
    )?;
    Ok(key
        .parent()
        .context("invalid configuration directory")?
        .join("sessions"))
}
/// The state directory a command uses, as an absolute path.
fn state_directory(state: &Option<PathBuf>) -> anyhow::Result<PathBuf> {
    absolute(&match state {
        Some(value) => value.clone(),
        None => crate::default_directory()?,
    })
}
/// Every `attach` profile under `root/HOST/AGENT`, with its directory;
/// unreadable ones are skipped.
fn attach_profiles(root: &Path, host: Option<&str>) -> Vec<(PathBuf, Profile)> {
    let mut found = Vec::new();
    let hosts = match host {
        Some(host) => vec![root.join(host)],
        None => fs::read_dir(root)
            .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
            .unwrap_or_default(),
    };
    for host in hosts {
        let Ok(entries) = fs::read_dir(&host) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !entry.path().is_dir() {
                continue;
            }
            if let Ok(p) = load_profile(&entry.path(), &None)
                && !p.workspace.is_empty()
            {
                found.push((entry.path(), p));
            }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}
/// Each `attach` profile of a host: its agent ID, integration, and
/// workspace.
pub(crate) fn attach_agents(host: &str) -> anyhow::Result<Vec<(String, String, PathBuf)>> {
    Ok(attach_profiles(&sessions_root()?, Some(host))
        .into_iter()
        .map(|(_, p)| (p.agent_id, p.harness.id, PathBuf::from(p.workspace)))
        .collect())
}

pub(crate) fn up_profile(state: &Path, workspace: &Path) -> anyhow::Result<Option<Value>> {
    let found: Vec<_> = attach_profiles(&sessions_root()?, None)
        .into_iter()
        .filter(|(_, p)| Path::new(&p.state) == state && Path::new(&p.workspace) == workspace)
        .collect();
    if found.len() > 1 {
        bail!(
            "several attach profiles record this project; use peerspan session doctor --directory PROFILE"
        )
    }
    found
        .into_iter()
        .next()
        .map(|(_, p)| serde_json::to_value(p).map_err(Into::into))
        .transpose()
}

/// Run the provider's read-only prepare operation without saving its returned
/// artifacts or issuing any daemon request or credential.
pub(crate) struct UpPreflight<'a> {
    pub state: &'a Path,
    pub workspace: &'a Path,
    pub harness: &'a str,
    pub profile: Option<&'a Value>,
    pub integrations: Option<PathBuf>,
    pub runner: Option<PathBuf>,
    pub options: BTreeMap<String, String>,
    pub arguments: &'a [String],
}

pub(crate) async fn up_preflight(input: UpPreflight<'_>) -> anyhow::Result<()> {
    let UpPreflight {
        state,
        workspace,
        harness,
        profile,
        integrations,
        runner,
        options,
        arguments,
    } = input;
    let manifest = if let Some(p) = profile.filter(|_| integrations.is_none() && runner.is_none()) {
        serde_json::from_value(p["harness"].clone())?
    } else {
        load_manifest(integrations, harness, runner)?
    };
    if let Some(profile) = profile
        && serde_json::to_value(&manifest)? != profile["harness"]
    {
        bail!("requested integration conflicts with this project's attachment")
    }
    let directory = profile
        .and_then(|p| p["directory"].as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| state.join("up-preflight"));
    let p = Profile {
        version: 2,
        phase: "preparing".into(),
        directory: directory.to_string_lossy().into_owned(),
        state: state.to_string_lossy().into_owned(),
        host_id: String::new(),
        agent_id: "agent_00000000000000000000000000000000".into(),
        session_id: "session_00000000000000000000000000000000".into(),
        adapter_id: String::new(),
        harness: manifest,
        options,
        provider_state: json!({}),
        files: BTreeMap::new(),
        request: json!({}),
        workspace: workspace.to_string_lossy().into_owned(),
    };
    let result = provider(&p, "prepare", &workspace.to_string_lossy(), arguments).await?;
    if failed(&result.checks) {
        bail!("{}", check_errors(&result.checks))
    }
    Ok(())
}
/// The `attach` profiles whose workspace is the current directory.
fn attached_profiles(state: &Option<PathBuf>) -> anyhow::Result<Vec<PathBuf>> {
    workspace_profiles(Some(state_directory(state)?))
}
/// The `attach` profiles whose workspace is the current directory, of one
/// state directory or of any.
fn workspace_profiles(state: Option<PathBuf>) -> anyhow::Result<Vec<PathBuf>> {
    let workspace = fs::canonicalize(std::env::current_dir()?)?;
    Ok(attach_profiles(&sessions_root()?, None)
        .into_iter()
        .filter(|(_, p)| {
            Path::new(&p.workspace) == workspace
                && state.as_ref().is_none_or(|s| Path::new(&p.state) == s)
        })
        .map(|(directory, _)| directory)
        .collect())
}
/// Introduces the pending work in the session start hook's context.
const PENDING_HOOK_LEAD: &str = "Peerspan work this session still owes, listed after /clear, compaction, or resume. Finish each task with the task_* tools, answer each delivery with reply, check each call with call_status, and follow each conversation with conversation_history; call pending_work for the current list. ";

/// The `SessionStart` hook's output for a pending object, `None` when every
/// list is empty.
fn pending_hook(value: &Value) -> Option<String> {
    let empty = ["deliveries", "replies", "tasks", "calls", "conversations"]
        .iter()
        .all(|k| value[k].as_array().is_none_or(|a| a.is_empty()));
    (!empty).then(|| {
        let context = format!("{PENDING_HOOK_LEAD}{value}");
        json!({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context}})
            .to_string()
    })
}

/// `session pending`: the work the current directory's attached session
/// still owes. Without an attachment it prints nothing, so a session start
/// hook never fails.
async fn pending(state: &Option<PathBuf>, json: bool, hook: bool) -> anyhow::Result<()> {
    // The session start hook runs without --state: any state's attachment
    // of this directory then counts, read through its own daemon.
    let found = match state {
        Some(_) => attached_profiles(state).unwrap_or_default(),
        None => workspace_profiles(None).unwrap_or_default(),
    };
    let directory = match found.as_slice() {
        [] => return Ok(()),
        [one] => one.clone(),
        many => bail!(
            "several attach profiles record this directory: {}",
            many.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let Ok(p) = load_profile(&directory, state) else {
        return Ok(());
    };
    let value = call(
        &p,
        Method::GET,
        &format!("/v1/sessions/{}/pending", p.session_id),
        None,
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string(&value)?);
        return Ok(());
    }
    if hook {
        // Claude Code reads a hook's JSON output as hook output, so the list
        // reaches the model only as additionalContext.
        if let Some(output) = pending_hook(&value) {
            println!("{output}");
        }
        return Ok(());
    }
    let text = |v: &Value| {
        v.as_str()
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let marks = |set: &[(bool, &str)]| {
        let on: Vec<&str> = set.iter().filter(|(v, _)| *v).map(|(_, m)| *m).collect();
        if on.is_empty() {
            String::new()
        } else {
            format!(" ({})", on.join(", "))
        }
    };
    for d in value["deliveries"].as_array().into_iter().flatten() {
        println!(
            "message {} request {} from {}{}: {}",
            text(&d["delivery_id"]),
            text(&d["request_id"]),
            text(&d["sender_host_id"]),
            marks(&[
                (d["seen"] == true, "seen"),
                (d["redelivered"] == true, "redelivered")
            ]),
            text(&d["preview"])
        );
    }
    for r in value["replies"].as_array().into_iter().flatten() {
        println!(
            "reply {} to request {} from {}: {}",
            text(&r["notification_id"]),
            text(&r["request_id"]),
            text(&r["peer_host_id"]),
            text(&r["preview"])
        );
    }
    for t in value["tasks"].as_array().into_iter().flatten() {
        println!(
            "task {} {} from {}{}: {}",
            text(&t["task_id"]),
            text(&t["state"]),
            text(&t["sender_host_id"]),
            marks(&[(t["adopted"] == true, "adopted")]),
            text(&t["preview"])
        );
    }
    for c in value["conversations"].as_array().into_iter().flatten() {
        println!(
            "conversation {} {} unseen, latest from {}: {}",
            text(&c["conversation_id"]),
            c["unseen"],
            text(&c["latest"]["author_label"]),
            text(&c["latest"]["preview"])
        );
    }
    for c in value["calls"].as_array().into_iter().flatten() {
        println!(
            "call {} {} {} {}{}",
            text(&c["call_id"]),
            text(&c["state"]),
            text(&c["address"]),
            text(&c["operation"]),
            marks(&[(c["redelivered"] == true, "redelivered")]),
        );
    }
    Ok(())
}
/// The `attach` profile whose workspace is the current directory, for
/// `session start` and `doctor` without `--directory`.
fn attached_profile(state: &Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let matches = attached_profiles(state)?;
    match matches.as_slice() {
        [] => bail!(
            "no attach profile for this directory; run peerspan attach HARNESS, or give --directory"
        ),
        [one] => Ok(one.clone()),
        many => bail!(
            "several attach profiles record this directory; choose one with --directory: {}",
            many.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}
pub(crate) async fn admin(
    state: &Path,
    method: Method,
    path: String,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    tokio::time::timeout(
        Duration::from_secs(20),
        crate::call(state.join("admin.sock"), method, path, body),
    )
    .await
    .context("host daemon request timed out")?
}
/// Lowercases a name suffix and replaces characters outside the
/// addressable set with `-`.
fn suffix(text: &str) -> String {
    text.chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}
/// `suffix`, or `fallback` when that leaves no letter or digit.
fn suffix_or(text: &str, fallback: &str) -> String {
    let part = suffix(text);
    if part.chars().any(|c| c.is_ascii_alphanumeric()) {
        part
    } else {
        fallback.to_owned()
    }
}
/// `parts` joined with `-` and `tail` appended, cutting the parts from the
/// end so the name fits in 64 characters: the host name (`parts[1]`)
/// first, then the project (`parts[2]`), then the base (`parts[0]`), each
/// down to 1 character before the next. The tail is never cut.
fn fitted(parts: &[String], tail: &str) -> String {
    let mut cut = parts.to_vec();
    for i in [1, 2, 0] {
        let Some(part) = cut.get(i) else { continue };
        let over = (cut.join("-").len() + tail.len()).saturating_sub(64);
        let keep = part.len().saturating_sub(over).max(1);
        cut[i].truncate(keep);
    }
    format!("{}{tail}", cut.join("-"))
}

/// The first free default name: `BASE-HOSTNAME`, else
/// `BASE-HOSTNAME-PROJECT` when that is used on this host, or
/// `BASE-HOSTNAME-HHHH` with a growing prefix of the host ID when it is
/// used only on another host, then the last of these with `-2`, `-3`, and
/// so on.
fn default_name(
    base: &str,
    hostname: &str,
    project: &str,
    host_id: &str,
    local: &BTreeSet<String>,
    remote: &BTreeMap<String, String>,
) -> String {
    let free = |name: &str| !local.contains(name) && !remote.contains_key(name);
    let mut parts = vec![
        base.to_owned(),
        suffix_or(hostname.split('.').next().unwrap_or_default(), "host"),
    ];
    let first = fitted(&parts, "");
    if free(&first) {
        return first;
    }
    let mut tail = String::new();
    if local.contains(&first) {
        parts.push(suffix_or(project, "project"));
    } else {
        let hex = host_id.strip_prefix("host_").unwrap_or(host_id);
        for digits in (4..=hex.len().min(32)).step_by(2) {
            tail = format!("-{}", &hex[..digits]);
            if free(&fitted(&parts, &tail)) {
                break;
            }
        }
    }
    let name = fitted(&parts, &tail);
    if free(&name) {
        return name;
    }
    (2u64..)
        .map(|n| fitted(&parts, &format!("{tail}-{n}")))
        .find(|name| free(name))
        .expect("an unused suffix exists")
}

/// Polls an adapter's connection until the lease in `seen` has expired, at
/// most 16 seconds, and refuses when the lease is renewed meanwhile.
async fn wait_for_lease(
    state: &Path,
    adapter_id: &str,
    seen: &Value,
    workspace: &str,
) -> anyhow::Result<()> {
    let lease = |c: &Value| {
        c["lease_expires_at"]
            .as_str()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
    };
    let first = lease(seen);
    let running = || {
        anyhow::anyhow!(
            "the session for {workspace} is already running (adapter {adapter_id} has a live lease)"
        )
    };
    eprintln!(
        "peerspan: the session for {workspace} is connected; waiting up to 16 seconds for its lease to expire"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(16);
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let connection = admin(
            state,
            Method::GET,
            format!("/v1/adapters/{adapter_id}/connection"),
            None,
        )
        .await?;
        if connection["state"] != "ready" {
            return Ok(());
        }
        if lease(&connection) > first {
            return Err(running());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(running());
        }
    }
}

/// `attach HARNESS`: registers the agent if needed and sets up a directory
/// session for the project, recorded in an attach profile.
pub(crate) struct PreparedAttachment {
    pub value: Value,
    pub directory: PathBuf,
    pub launchable: bool,
}

pub async fn attach(command: crate::cli::Command, state: Option<PathBuf>) -> anyhow::Result<()> {
    let (no_start, args) = match &command {
        crate::cli::Command::Attach {
            no_start,
            harness_args,
            ..
        } => (*no_start, harness_args.clone()),
        _ => bail!("not an attach command"),
    };
    let prepared = prepare_attach(command, state.clone()).await?;
    let text = serde_json::to_string_pretty(&prepared.value)?;
    if !no_start && prepared.launchable {
        eprintln!("{text}");
        let workspace = prepared.value["workspace"].as_str().map(PathBuf::from);
        start(&prepared.directory, &state, workspace, args).await
    } else {
        println!("{text}");
        if !args.is_empty() {
            bail!("this integration does not support launch")
        }
        Ok(())
    }
}

pub(crate) async fn prepare_attach(
    command: crate::cli::Command,
    state: Option<PathBuf>,
) -> anyhow::Result<PreparedAttachment> {
    prepare_attach_inner(command, state, None, None).await
}

pub(crate) async fn prepare_up_attach(
    command: crate::cli::Command,
    state: Option<PathBuf>,
    profile: Option<Value>,
    send_limit: Option<i64>,
) -> anyhow::Result<PreparedAttachment> {
    prepare_attach_inner(command, state, profile, send_limit).await
}

async fn prepare_attach_inner(
    command: crate::cli::Command,
    state: Option<PathBuf>,
    up_profile: Option<Value>,
    requested_send_limit: Option<i64>,
) -> anyhow::Result<PreparedAttachment> {
    let crate::cli::Command::Attach {
        harness,
        name: wanted,
        directory,
        expires_at,
        expires_in: _,
        max_sends_per_hour,
        calls,
        no_calls,
        max_calls_per_hour,
        options,
        integrations,
        runner,
        no_start,
        harness_args,
    } = command
    else {
        bail!("not an attach command")
    };
    // `builtin` is the agent position of built-in sources.
    if wanted.as_deref() == Some(peerspan_host::builtin::AGENT) {
        bail!("the agent name builtin is reserved for built-in sources; choose another --name")
    }
    // The capability call flags are checked before anything changes.
    if calls && no_calls {
        bail!("--calls and --no-calls are mutually exclusive")
    }
    if no_calls && max_calls_per_hour.is_some() {
        bail!("--max-calls-per-hour requires calls; omit --no-calls")
    }
    let max_calls_per_hour = match max_calls_per_hour {
        None => None,
        Some(text) => match text.parse::<i64>() {
            Ok(n) if (1..=10000).contains(&n) => Some(n),
            _ => bail!("--max-calls-per-hour must be a whole number from 1 to 10000"),
        },
    };
    let integration = if harness == "claude" {
        "claude-code".to_owned()
    } else {
        harness
    };
    let base = if integration == "claude-code" {
        "claude".to_owned()
    } else {
        integration.clone()
    };
    if !name(&integration) {
        bail!("use a valid integration ID")
    }
    if no_start && !harness_args.is_empty() {
        bail!("harness arguments require a launch; omit --no-start")
    }
    if let Some(expiry) = &expires_at
        && !future(expiry)
    {
        bail!("use a future RFC3339 expiry")
    }
    let project = match directory {
        Some(directory) => directory,
        None => std::env::current_dir()?,
    };
    let workspace = fs::canonicalize(&project)
        .with_context(|| format!("{} is not an existing directory", project.display()))?;
    if !workspace.is_dir() {
        bail!("{} is not a directory", workspace.display())
    }
    let workspace_text = workspace.to_string_lossy().into_owned();
    let state = state_directory(&state)?;
    let host = admin(&state, Method::GET, "/v1/host".into(), None).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    // Refresh every network's directory first: names are checked against
    // the person's other hosts, and unreachable ones are reported.
    let status = admin(&state, Method::GET, "/v1/status".into(), None).await?;
    let mut persons = BTreeMap::new();
    let mut label = None;
    for network in status["networks"].as_array().into_iter().flatten() {
        if let (Some(id), Some(person)) = (network["id"].as_str(), network["person"]["id"].as_str())
        {
            persons.insert(id.to_owned(), person.to_owned());
            if label.is_none() {
                label = network["person"]["label"].as_str().map(str::to_owned);
            }
        } else if network["mode"] == "decentralized"
            && let Some(id) = network["id"].as_str()
        {
            // A coordinator-free network's entry is its network view: the
            // bound person and label come from the verified current members.
            let members = admin(
                &state,
                Method::GET,
                format!("/v1/networks/{}/members", crate::cli::encoded(id)),
                None,
            )
            .await?;
            if let Some(own) = members.as_array().into_iter().flatten().find(|m| {
                m["public_key"] == network["host_public_key"] && m["person_id"].is_string()
            }) {
                persons.insert(
                    id.to_owned(),
                    own["person_id"].as_str().unwrap_or_default().to_owned(),
                );
                if label.is_none() {
                    label = own["person_member"].as_str().map(str::to_owned);
                }
            }
        }
    }
    let mut unchecked = BTreeSet::new();
    let mut remote: BTreeMap<String, String> = BTreeMap::new();
    for network in status["networks"].as_array().into_iter().flatten() {
        let Some(id) = network["id"].as_str() else {
            continue;
        };
        let directory = admin(
            &state,
            Method::POST,
            format!("/v1/directory/refresh?network={}", crate::cli::encoded(id)),
            Some(json!({})),
        )
        .await?;
        let Some(person) = persons.get(id) else {
            continue;
        };
        for h in directory["hosts"].as_array().into_iter().flatten() {
            if h["person_id"].as_str() == Some(person) && h["state"] != "ok" {
                unchecked.insert(h["host_id"].as_str().unwrap_or_default().to_owned());
            }
        }
        for a in directory["agents"].as_array().into_iter().flatten() {
            if a["person_id"].as_str() == Some(person)
                && let (Some(name), Some(on)) = (a["name"].as_str(), a["host_id"].as_str())
            {
                remote
                    .entry(name.to_owned())
                    .or_insert_with(|| on.to_owned());
            }
        }
    }
    let agents = admin(&state, Method::GET, "/v1/agents".into(), None).await?;
    let local: BTreeMap<String, String> = agents
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| Some((a["name"].as_str()?.to_owned(), a["id"].as_str()?.to_owned())))
        .collect();
    let root = sessions_root()?.join(&host);
    let profiles = attach_profiles(&sessions_root()?, Some(&host));
    let address = |name: &str| match &label {
        Some(label) => format!("{label}/{name}"),
        None => format!("{host}/{name}"),
    };
    let unchecked: Vec<String> = unchecked.into_iter().collect();
    let socket = state.join("admin.sock");
    let discovered = |agent_id: String| {
        let (socket, integration, workspace) =
            (socket.clone(), integration.clone(), workspace.clone());
        async move {
            let mut tools =
                match crate::discovery::refresh(&socket, &agent_id, &integration, &workspace).await
                {
                    Ok(tools) => tools,
                    Err(e) => json!({"servers": [], "errors": [{"error": format!("{e:#}")}]}),
                };
            // Built-in discovery follows; its failures land in errors.
            let builtin = crate::builtin_discovery::refresh(&socket).await;
            if let (Some(errors), Some(more)) =
                (tools["errors"].as_array_mut(), builtin["errors"].as_array())
            {
                errors.extend(more.iter().cloned());
            }
            tools["builtin"] = builtin["servers"].clone();
            tools
        }
    };
    let build = |agent_id: &str,
                 agent_name: &str,
                 p: &Profile,
                 profile: &Path,
                 reused: bool,
                 adapter: &Value,
                 tools: Value| {
        let next = if p.harness.supports("launch") {
            "peerspan session start"
        } else {
            "peerspan session doctor"
        };
        let value = json!({
            "agent": {"id": agent_id, "name": agent_name, "address": address(agent_name)},
            "session_id": p.session_id,
            "adapter_id": p.adapter_id,
            "profile": profile,
            "workspace": workspace_text,
            "reused": reused,
            "unchecked_hosts": unchecked,
            "next": next,
            "calls": adapter["calls"] == true,
            "max_calls_per_hour": adapter["max_calls_per_hour"],
            "sources": tools,
        });
        eprintln!("{}", crate::discovery::summary_line(&value["sources"]));
        PreparedAttachment {
            value,
            directory: profile.to_owned(),
            launchable: p.harness.supports("launch"),
        }
    };
    let existing = profiles
        .iter()
        .find(|(_, p)| p.workspace == workspace_text && p.host_id == host);
    if up_profile.is_some() && existing.is_none() {
        bail!("the project's attachment changed; inspect its original session")
    }
    let (agent_id, agent_name) = match existing {
        Some((directory, p)) => {
            if let Some(expected) = &up_profile
                && serde_json::to_value(p)? != *expected
            {
                bail!("the project's attachment changed; inspect its original session")
            }
            if p.phase == "configured" {
                let adapter = admin(
                    &state,
                    Method::GET,
                    format!("/v1/adapters/{}", p.adapter_id),
                    None,
                )
                .await?;
                let connection = admin(
                    &state,
                    Method::GET,
                    format!("/v1/adapters/{}/connection", p.adapter_id),
                    None,
                )
                .await?;
                if up_profile.is_some()
                    && matches!(connection["state"].as_str(), Some("ready" | "offline"))
                {
                    same_host(p).await?;
                    let secret = credential(p)?;
                    if !verify(p, &secret["token"]).await? {
                        bail!(
                            "the original attachment credential no longer matches; inspect session doctor"
                        )
                    }
                    let session = admin(
                        &state,
                        Method::GET,
                        format!("/v1/sessions/{}", p.session_id),
                        None,
                    )
                    .await?;
                    let agent_name = directory
                        .file_name()
                        .and_then(|name| name.to_str())
                        .context("invalid attachment directory")?;
                    let same_expiry = match p.request["expires_at"].as_str() {
                        Some(expiry) => {
                            adapter["renewable"] != true
                                && membership::time(expiry)?
                                    == membership::time(
                                        adapter["expires_at"].as_str().unwrap_or(""),
                                    )?
                        }
                        None => adapter["renewable"] == true,
                    };
                    let same_options = parse_options(options.clone())? == p.options;
                    if adapter["id"] != p.adapter_id
                        || adapter["session_id"] != p.session_id
                        || !adapter["revoked_at"].is_null()
                        || !future(adapter["expires_at"].as_str().unwrap_or(""))
                        || !same_expiry
                        || session["id"] != p.session_id
                        || session["agent_id"] != p.agent_id
                        || session["integration"] != p.harness.id
                        || p.harness.id != integration
                        || local.get(agent_name) != Some(&p.agent_id)
                        || wanted.as_deref().is_some_and(|name| name != agent_name)
                        || !same_options
                        || adapter["directory"].as_bool().unwrap_or(false)
                            != (p.request["directory"] == true)
                        || adapter["max_sends_per_hour"] != p.request["max_sends_per_hour"]
                        || adapter["calls"].as_bool().unwrap_or(false)
                            != (p.request["calls"] == true)
                        || adapter["max_calls_per_hour"] != p.request["max_calls_per_hour"]
                        || (calls && adapter["calls"] != true)
                        || (no_calls && adapter["calls"] == true)
                        || max_calls_per_hour
                            .is_some_and(|n| adapter["max_calls_per_hour"].as_i64() != Some(n))
                        || requested_send_limit
                            .is_some_and(|n| adapter["max_sends_per_hour"].as_i64() != Some(n))
                        || connection["adapter_id"] != p.adapter_id
                        || connection["session_id"] != p.session_id
                    {
                        bail!(
                            "the original attachment or its settings no longer match; inspect session doctor"
                        )
                    }
                    let ready = connection["state"] == "ready" && session["state"] == "attached";
                    let recoverable = connection["state"] == "offline"
                        && connection["recoverable"] == true
                        && matches!(session["state"].as_str(), Some("attached" | "detached"));
                    if ready || recoverable {
                        if !harness_args.is_empty() {
                            bail!(
                                "harness arguments require a new launch; the original integration is retained without launching a duplicate"
                            )
                        }
                        let tools = discovered(p.agent_id.clone()).await;
                        let mut prepared =
                            build(&p.agent_id, agent_name, p, directory, true, &adapter, tools);
                        prepared.value["connection"] = connection;
                        prepared.value["adapter_ready"] = json!(ready);
                        return Ok(prepared);
                    }
                }
                // A live lease may belong to an adapter that has just exited:
                // wait for the lease seen here to run out, and refuse only if
                // it is renewed meanwhile. A valid credential that never
                // connected is reused unchanged; anything else lapsed and
                // gets a new setup for the same agent.
                if connection["state"] == "ready" {
                    wait_for_lease(&state, &p.adapter_id, &connection, &workspace_text).await?;
                }
                if connection["state"] == "registered"
                    && adapter["revoked_at"].is_null()
                    && future(adapter["expires_at"].as_str().unwrap_or(""))
                {
                    // The stored call setting stands; a flag that differs
                    // is refused before anything changes.
                    let stored = adapter["calls"] == true;
                    let stored_max = adapter["max_calls_per_hour"].as_i64();
                    if (calls && !stored)
                        || (no_calls && stored)
                        || max_calls_per_hour.is_some_and(|n| stored_max != Some(n))
                    {
                        bail!(
                            "this agent's credential, never connected, is reused with its stored setting calls: {stored}, max_calls_per_hour: {}; give matching flags or none",
                            stored_max.map_or("null".to_owned(), |n| n.to_string())
                        )
                    }
                    let agent_name = directory
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let tools = discovered(p.agent_id.clone()).await;
                    return Ok(build(
                        &p.agent_id,
                        &agent_name,
                        p,
                        directory,
                        true,
                        &adapter,
                        tools,
                    ));
                }
            }
            let agent = admin(
                &state,
                Method::GET,
                format!("/v1/agents/{}", p.agent_id),
                None,
            )
            .await?;
            (
                p.agent_id.clone(),
                agent["name"]
                    .as_str()
                    .context("invalid daemon response")?
                    .to_owned(),
            )
        }
        None => {
            let recorded = |id: &str| profiles.iter().any(|(_, p)| p.agent_id == id);
            let reuse = match &wanted {
                Some(wanted) => {
                    if !peerspan_host::directory::addressable(wanted) {
                        bail!(
                            "invalid agent name {wanted:?}: use 1-64 lowercase letters, digits, '.', '_', or '-', starting with a letter or digit"
                        )
                    }
                    if let Some(on) = remote.get(wanted) {
                        bail!("name {wanted} is taken by an agent on host {on} (409)")
                    }
                    match local.get(wanted) {
                        Some(id) if recorded(id) => {
                            bail!("name {wanted} is taken by agent {id} on host {host} (409)")
                        }
                        Some(id) => Some((id.clone(), wanted.clone())),
                        None => None,
                    }
                }
                None => None,
            };
            match reuse {
                Some(found) => found,
                None => {
                    let agent_name = match wanted {
                        Some(wanted) => wanted,
                        None => {
                            let project = workspace
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            let names = local.keys().cloned().collect();
                            default_name(
                                &base,
                                &crate::hostname(),
                                &project,
                                &host,
                                &names,
                                &remote,
                            )
                        }
                    };
                    let owner = label
                        .clone()
                        .or_else(crate::login_name)
                        .unwrap_or_else(|| "owner".into());
                    let agent = admin(
                        &state,
                        Method::POST,
                        "/v1/agents".into(),
                        Some(json!({"name": agent_name, "owner": owner, "capabilities": []})),
                    )
                    .await?;
                    (
                        agent["id"]
                            .as_str()
                            .context("invalid daemon response")?
                            .to_owned(),
                        agent_name,
                    )
                }
            }
        }
    };
    use std::io::IsTerminal;
    // Capability calls: the flags decide, or else the prompt at a terminal;
    // without a terminal the answer is no.
    let call_cap = if calls {
        Some(max_calls_per_hour.unwrap_or(peerspan_host::agent_calls::DEFAULT_CALLS_PER_HOUR))
    } else if no_calls {
        None
    } else if std::io::stdin().is_terminal()
        && crate::capability_cli::ask(
            "Let this agent call capabilities shared with you, and yours on your other trusted machines? [y/N] ",
        )?
    {
        Some(max_calls_per_hour.unwrap_or(peerspan_host::agent_calls::DEFAULT_CALLS_PER_HOUR))
    } else {
        None
    };
    // A new setup replaces an old profile only once it succeeds.
    let directory = root.join(&agent_name);
    let aside = root.join(format!(".{agent_name}.old"));
    let moved = if fs::symlink_metadata(&directory).is_ok() {
        let _ = fs::remove_dir_all(&aside);
        fs::rename(&directory, &aside).context("cannot move the old attach profile aside")?;
        true
    } else {
        false
    };
    let result = prepare(SetupOptions {
        directory: directory.clone(),
        state: Some(state.clone()),
        harness: integration.clone(),
        agent: agent_id.clone(),
        expiry: expires_at,
        integrations,
        runner,
        routes: None,
        options,
        max_sends_per_hour: Some(max_sends_per_hour),
        max_calls_per_hour: call_cap,
        workspace: Some(workspace_text.clone()),
    })
    .await;
    match result {
        Ok(p) => {
            if moved {
                let _ = fs::remove_dir_all(&aside);
            }
            let adapter = admin(
                &state,
                Method::GET,
                format!("/v1/adapters/{}", p.adapter_id),
                None,
            )
            .await?;
            let tools = discovered(agent_id.clone()).await;
            Ok(build(
                &agent_id,
                &agent_name,
                &p,
                &directory,
                false,
                &adapter,
                tools,
            ))
        }
        Err(error) => {
            if moved && fs::symlink_metadata(&directory).is_err() {
                let _ = fs::rename(&aside, &directory);
            }
            Err(error)
        }
    }
}

pub(crate) fn relative_expiry(value: &str) -> anyhow::Result<String> {
    let (number, unit) = if let Some(number) = value.strip_suffix('m') {
        (number, "m")
    } else if let Some(number) = value.strip_suffix('h') {
        (number, "h")
    } else {
        bail!("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")
    };
    let amount: i64 = number.parse().with_context(
        || "--expires-in must be a whole-minute or whole-hour duration from 1m to 720h",
    )?;
    let duration = match unit {
        "m" => TimeDelta::try_minutes(amount),
        "h" => TimeDelta::try_hours(amount),
        _ => None,
    }
    .filter(|duration| *duration >= TimeDelta::minutes(1) && *duration <= TimeDelta::days(30))
    .context("--expires-in must be a whole-minute or whole-hour duration from 1m to 720h")?;
    Ok((peerspan_host::clock::now() + duration).to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_hook_names_conversations() {
        let empty =
            json!({"deliveries": [], "replies": [], "tasks": [], "calls": [], "conversations": []});
        assert_eq!(pending_hook(&empty), None);
        let mut only = empty;
        only["conversations"] = json!([{"conversation_id": "conv_x"}]);
        let output = pending_hook(&only).unwrap();
        assert!(output.contains(
            "check each call with call_status, and follow each conversation with conversation_history; call pending_work for the current list. "
        ));
        assert!(output.contains("conv_x"));
    }

    #[test]
    fn relative_expiry_is_bounded_and_uses_whole_minutes_or_hours() {
        let before = peerspan_host::clock::now() + TimeDelta::minutes(59);
        let expiry = DateTime::parse_from_rfc3339(&relative_expiry("1h").unwrap()).unwrap();
        let after = peerspan_host::clock::now() + TimeDelta::minutes(61);
        assert!(expiry > before && expiry < after);
        for invalid in [
            "",
            "0m",
            "30s",
            "1h30m",
            "721h",
            "999999999999999999999h",
            "1é",
            "1💥",
        ] {
            assert!(relative_expiry(invalid).is_err(), "{invalid}");
        }
    }
}
