//! Native owner session lifecycle, independent of a harness or its runtime.
use crate::cli::SessionCommand;
use anyhow::{Context, bail};
use chrono::{DateTime, Utc};
use hyper::Method;
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
}
struct SetupOptions {
    directory: PathBuf,
    state: Option<PathBuf>,
    harness: String,
    agent: String,
    expiry: String,
    integrations: Option<PathBuf>,
    runner: Option<PathBuf>,
    routes: Option<PathBuf>,
    options: Vec<String>,
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
    DateTime::parse_from_rfc3339(value).is_ok_and(|at| at > Utc::now())
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
            std::env::var_os("CAPSULE_INTEGRATIONS_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap_or_default()
                .parent()
                .unwrap_or(Path::new("."))
                .join("../share/capsule/integrations")
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
    let input = json!({"version":1,"operation":op,"context":{
        "directory":p.directory,"state":p.state,"agent_id":p.agent_id,"session_id":p.session_id,
        "adapter_socket":Path::new(&p.state).join("adapter.sock"),"credential_file":Path::new(&p.directory).join("credential.json"),
        "options":p.options,"provider_state":p.provider_state,"workspace":workspace,"arguments":args,
    }});
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
    if matches.len() != 1
        || !matches[0]["revoked_at"].is_null()
        || matches[0]["expires_at"] != p.request["expires_at"]
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
fn parse_options(values: Vec<String>) -> anyhow::Result<BTreeMap<String, String>> {
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
fn routes(path: Option<PathBuf>, expiry: &str) -> anyhow::Result<Value> {
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
                ]
                .contains(&key.as_str())
        }) {
            bail!("unknown or null destination field")
        }
        row.entry("expires_at").or_insert(json!(expiry));
        row.entry("max_message_bytes").or_insert(json!(65536));
        row.entry("max_messages").or_insert(json!(100));
        for key in ["name", "peer_host_id", "target_agent_id", "expires_at"] {
            if !row.get(key).is_some_and(Value::is_string) {
                bail!("invalid destination")
            }
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
    if !valid_id(&o.agent, "agent", 16) || !future(&o.expiry) {
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
    };
    p.request = json!({"agent_id":o.agent,"session_id":p.session_id,"integration":p.harness.id,"expires_at":o.expiry,"routes":routes(o.routes,&o.expiry)?});
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
    json!({"checked_at":Utc::now().to_rfc3339(),"directory":p.directory,"harness":p.harness.id,"agent_id":p.agent_id,"session_id":p.session_id,"adapter_id":p.adapter_id,"adapter_ready":connection["state"]=="ready" && !failed(&checks),"model_availability":"unknown","message_consumption":"unverified","connection":connection,"checks":checks,"destinations":destinations})
}
pub async fn run(command: SessionCommand, state: Option<PathBuf>) -> anyhow::Result<()> {
    let (directory, workspace, args) = match command {
        SessionCommand::Setup {
            directory,
            harness,
            agent,
            expires_at,
            integrations,
            runner,
            routes,
            options,
        } => {
            let p = if let Some(agent) = agent {
                prepare(SetupOptions {
                    directory,
                    state,
                    harness: harness.context("--harness is required")?,
                    agent,
                    expiry: expires_at.context("--expires-at is required")?,
                    integrations,
                    runner,
                    routes,
                    options,
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
            let value = json!({"state":"configured","adapter_ready":false,"directory":p.directory,"harness":p.harness.id,"agent_id":p.agent_id,"session_id":p.session_id,"adapter_id":p.adapter_id,"expires_at":p.request["expires_at"],"destinations":p.request["routes"].as_array().unwrap().iter().map(|r|r["name"].clone()).collect::<Vec<_>>(),"launch_supported":p.harness.supports("launch"),"next":["capsule-host","session",if p.harness.supports("launch"){ "start" }else{ "doctor" },"--directory",p.directory]});
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(());
        }
        SessionCommand::Doctor { directory } => {
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
        _ => bail!("unknown session integration operation"),
    };
    let mut p = load_profile(&directory, &state)?;
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
