//! Sources (capabilities contract, milestone 10 slice 1): the MCP servers
//! the CLI discovered in an agent's harness configuration, the values their
//! references resolved to, snapshots of what each offers, and the local open
//! list that lets this person's trusted machines call sources directly.
//! Values never leave this host.
use crate::{
    api::{blocking, decode},
    capabilities::{CapabilityRecord, capability_record, capability_records},
    mcp::{self, Launch},
    model::Error,
    peer_store::json,
    policy::name_shape,
    store::{Store, append_event, now},
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State, rejection::BytesRejection},
    http::StatusCode,
    routing::{delete, get, post, put},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

/// Database version 16: sources, their values, capabilities, the open list,
/// and calls in both directions.
pub(crate) const SCHEMA: &str = "
CREATE TABLE tool_servers (agent_id TEXT NOT NULL REFERENCES agents(id), name TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, name));
CREATE TABLE tool_values (agent_id TEXT NOT NULL, server TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(agent_id, server, field));
CREATE TABLE capabilities (name TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE source_access (host_id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE received_calls (sender TEXT NOT NULL, call_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id));
CREATE TABLE outbound_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, call_id));
PRAGMA user_version = 16;
";

/// A snapshot lists at most this many tools and resources each.
const LIST_LIMIT: usize = 1000;
/// A whole snapshot must finish within this long.
const SNAPSHOT_BOUND: Duration = Duration::from_secs(30);
/// A snapshot larger than this, as JSON, is an error.
const SNAPSHOT_MAX: usize = 1 << 20;
/// Snapshots after a `PUT` run this many at once.
const SNAPSHOT_PARALLEL: usize = 8;

/// How an `env` value is obtained: `literal`, `captured`, or `missing`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvSource {
    pub source: String,
    /// For `missing`: the referenced variables that could not be resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<String>>,
}

/// A discovered server, as the CLI normalizes it, with `disabled` when its
/// harness disables it. The daemon computes `shareable` and `reason`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub name: String,
    pub transport: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, EnvSource>,
    #[serde(default)]
    pub url: Option<String>,
    pub source: String,
    /// Disabled in its harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ToolEntry {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    pub read_only: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResourceEntry {
    pub uri: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub mime_type: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Snapshot {
    pub tools: Vec<ToolEntry>,
    pub resources: Vec<ResourceEntry>,
    pub taken_at: String,
}
impl Snapshot {
    pub fn tool(&self, name: &str) -> Option<&ToolEntry> {
        self.tools.iter().find(|t| t.name == name)
    }
    pub fn resource(&self, uri: &str) -> Option<&ResourceEntry> {
        self.resources.iter().find(|r| r.uri == uri)
    }
}

/// Failures `status` reports for a source or a capability's own instance.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Health {
    /// The last time an instance failed to start.
    #[serde(default)]
    pub start_failed_at: Option<String>,
    /// The last JSON-RPC error whose message suggests authentication.
    #[serde(default)]
    pub auth_error_at: Option<String>,
    #[serde(default)]
    pub auth_error: Option<String>,
}

/// `tool_servers.record`: the definition and its snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServerRecord {
    pub agent_id: String,
    pub definition: Definition,
    pub workspace: String,
    pub shareable: bool,
    pub reason: Option<String>,
    #[serde(default)]
    pub missing_env: Vec<String>,
    pub snapshot: Option<Snapshot>,
    pub snapshot_error: Option<String>,
    #[serde(default)]
    pub health: Health,
    pub updated_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutServers {
    pub workspace: String,
    pub servers: Vec<Definition>,
    #[serde(default)]
    pub values: BTreeMap<String, BTreeMap<String, String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTo {
    pub host_id: String,
}

/// One instance: a source, or a capability with its own credential.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instance {
    pub agent_id: String,
    pub server: String,
    /// The capability whose own credential the instance runs with.
    pub capability: Option<String>,
}
impl Instance {
    pub fn key(&self) -> mcp::Key {
        (
            self.agent_id.clone(),
            self.server.clone(),
            self.capability.clone().unwrap_or_default(),
        )
    }
    /// `SERVER`, or `SERVER@CAPABILITY` for a capability's own instance.
    pub fn label(&self) -> String {
        match &self.capability {
            Some(c) => format!("{}@{c}", self.server),
            None => self.server.clone(),
        }
    }
}

/// The per-user environment file, `$XDG_CONFIG_HOME/peerspan/env` (default
/// `~/.config/peerspan/env`).
pub fn env_file_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").filter(|v| !v.is_empty())?).join(".config"),
    };
    Some(base.join("peerspan").join("env"))
}
/// `NAME=VALUE` lines, with `#` comments and blank lines.
fn parse_env(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (name, value) = trimmed.split_once('=')?;
            let name = name.trim();
            (!name.is_empty()).then(|| (name.to_owned(), value.trim_end_matches('\r').to_owned()))
        })
        .collect()
}
/// The environment file's state: absent, too open (not mode 0600 or
/// stricter), or its variables.
pub enum EnvFile {
    Absent,
    TooOpen(PathBuf),
    Values(Vec<(String, String)>),
}
pub fn read_env_file() -> EnvFile {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = env_file_path() else {
        return EnvFile::Absent;
    };
    let Ok(metadata) = std::fs::metadata(&path) else {
        return EnvFile::Absent;
    };
    if metadata.permissions().mode() & 0o177 != 0 {
        return EnvFile::TooOpen(path);
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => EnvFile::Values(parse_env(&text)),
        Err(_) => EnvFile::Absent,
    }
}

/// Whether a JSON-RPC error message suggests an authentication failure.
pub fn auth_like(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    ["auth", "401", "403", "token"]
        .iter()
        .any(|w| lower.contains(w))
}

/// The variables `${NAME}` or `${NAME:-D}` references in a text.
fn references(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let Some(len) = rest[start..].find('}') else {
            break;
        };
        let inner = &rest[start + 2..start + len];
        let name = inner.split_once(":-").map_or(inner, |(n, _)| n);
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            out.push(name.to_owned());
        }
        rest = &rest[start + len + 1..];
    }
    out
}
/// Whether a server is shareable, why not (`name`, `remote`, `disabled`,
/// or `missing_env`, in that order), and its unresolved variables: those a
/// `command` or `args` element references without a stored value, and the
/// `variables` of each `missing` env entry.
fn reason_for(
    d: &Definition,
    values: Option<&BTreeMap<String, String>>,
) -> (bool, Option<String>, Vec<String>) {
    let has = |field: &str| values.is_some_and(|v| v.contains_key(field));
    let mut missing: Vec<String> = Vec::new();
    if let Some(c) = &d.command
        && !has("command")
    {
        missing.extend(references(c));
    }
    for (i, a) in d.args.iter().enumerate() {
        if !has(&format!("args.{i}")) {
            missing.extend(references(a));
        }
    }
    missing.extend(
        d.env
            .iter()
            .filter(|(_, s)| s.source == "missing")
            .flat_map(|(_, s)| s.variables.clone().unwrap_or_default()),
    );
    missing.sort();
    missing.dedup();
    let reason = if !name_shape(&d.name) {
        Some("name")
    } else if d.transport == "remote" {
        Some("remote")
    } else if d.disabled == Some(true) {
        Some("disabled")
    } else if !missing.is_empty() {
        Some("missing_env")
    } else {
        None
    };
    (reason.is_none(), reason.map(str::to_owned), missing)
}

fn valid_definition(d: &Definition) -> Result<(), Error> {
    let bad = |m: &str| Err(Error::Invalid(format!("server {:?}: {m}", d.name)));
    if d.name.is_empty() || d.name.len() > 256 || d.name.chars().any(char::is_control) {
        return bad("invalid name");
    }
    match d.transport.as_str() {
        "stdio" => {
            if d.command.as_deref().is_none_or(str::is_empty) {
                return bad("a stdio server needs a command");
            }
        }
        "remote" => {}
        _ => return bad("transport is stdio or remote"),
    }
    // A missing entry names its unresolved variables; no other does.
    let variables_ok = |s: &EnvSource| match (s.source.as_str(), &s.variables) {
        ("missing", Some(v)) => !v.is_empty() && v.iter().all(|n| !n.is_empty()),
        ("literal" | "captured", None) => true,
        _ => false,
    };
    if d.env.values().any(|s| !variables_ok(s)) {
        return bad("env sources are literal, captured, or missing");
    }
    if d.env
        .keys()
        .any(|k| k.is_empty() || k.contains('=') || k.contains('\0'))
    {
        return bad("invalid env name");
    }
    let (integration, scope) = d.source.split_once(':').unwrap_or_default();
    if integration.is_empty() || scope.is_empty() {
        return bad("source is INTEGRATION:SCOPE");
    }
    Ok(())
}
fn valid_field(d: &Definition, field: &str) -> bool {
    if field == "command" {
        return true;
    }
    if let Some(name) = field.strip_prefix("env.") {
        return d
            .env
            .get(name)
            .is_some_and(|s| s.source == "literal" || s.source == "captured");
    }
    field
        .strip_prefix("args.")
        .and_then(|n| n.parse::<usize>().ok())
        .is_some_and(|n| n < d.args.len() && field == format!("args.{n}"))
}

pub(crate) fn server_record(
    conn: &Connection,
    agent: &str,
    name: &str,
) -> Result<Option<ServerRecord>, Error> {
    conn.query_row(
        "SELECT record FROM tool_servers WHERE agent_id = ?1 AND name = ?2",
        params![agent, name],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(json)
    .transpose()
}
pub(crate) fn server_records(conn: &Connection, agent: &str) -> Result<Vec<ServerRecord>, Error> {
    let mut statement =
        conn.prepare("SELECT record FROM tool_servers WHERE agent_id = ?1 ORDER BY name")?;
    statement
        .query_map([agent], |r| r.get::<_, String>(0))?
        .map(|r| json(r?))
        .collect()
}
fn values(conn: &Connection, agent: &str, server: &str) -> Result<BTreeMap<String, String>, Error> {
    let mut statement =
        conn.prepare("SELECT field, value FROM tool_values WHERE agent_id = ?1 AND server = ?2")?;
    let rows = statement
        .query_map(params![agent, server], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<BTreeMap<String, String>, _>>()?;
    Ok(rows)
}
/// Agent names by ID, read on a connection already held (the store's
/// connection lock is not reentrant).
pub(crate) fn agent_names(conn: &Connection) -> Result<BTreeMap<String, String>, Error> {
    let mut statement = conn.prepare("SELECT id, name FROM agents")?;
    let rows = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<BTreeMap<String, String>, _>>()?;
    Ok(rows)
}

impl Store {
    fn agent_exists(&self, conn: &Connection, id: &str) -> Result<bool, Error> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?1)",
            [id],
            |r| r.get(0),
        )?)
    }
    /// Every shareable source with a snapshot.
    pub(crate) fn snapshotted_sources(
        &self,
        conn: &Connection,
    ) -> Result<Vec<ServerRecord>, Error> {
        let mut statement =
            conn.prepare("SELECT record FROM tool_servers ORDER BY agent_id, name")?;
        let servers: Vec<ServerRecord> = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .map(|r| json(r?))
            .collect::<Result<_, Error>>()?;
        Ok(servers
            .into_iter()
            .filter(|s| s.shareable && s.snapshot.is_some())
            .collect())
    }
    /// How to start an instance: the definition's command and arguments (a
    /// capability's `args` replacing them) with stored values substituted;
    /// an environment of the daemon's `PATH` and `HOME`, the definition's
    /// `env` with its values, the environment file (for those names), then
    /// a capability's whole `env_file`; and the workspace as directory.
    pub(crate) fn launch(&self, conn: &Connection, instance: &Instance) -> Result<Launch, Error> {
        let capability = match &instance.capability {
            Some(c) => Some(capability_record(conn, c)?.ok_or(Error::NotFound)?),
            None => None,
        };
        self.launch_with(conn, instance, capability.as_ref())
    }
    /// `launch`, with the capability whose own credential applies given,
    /// possibly before it is stored.
    pub(crate) fn launch_with(
        &self,
        conn: &Connection,
        instance: &Instance,
        capability: Option<&CapabilityRecord>,
    ) -> Result<Launch, Error> {
        let server =
            server_record(conn, &instance.agent_id, &instance.server)?.ok_or(Error::NotFound)?;
        let d = &server.definition;
        let stored = values(conn, &instance.agent_id, &instance.server)?;
        let command = stored
            .get("command")
            .cloned()
            .or_else(|| d.command.clone())
            .ok_or(Error::NotFound)?;
        let mut args: Vec<String> = d
            .args
            .iter()
            .enumerate()
            .map(|(i, a)| {
                stored
                    .get(&format!("args.{i}"))
                    .cloned()
                    .unwrap_or_else(|| a.clone())
            })
            .collect();
        let mut env: Vec<(String, String)> = Vec::new();
        for name in ["PATH", "HOME"] {
            if let Some(v) = std::env::var_os(name) {
                env.push((name.into(), v.to_string_lossy().into_owned()));
            }
        }
        let set = |env: &mut Vec<(String, String)>, name: &str, value: String| {
            env.retain(|(n, _)| n != name);
            env.push((name.to_owned(), value));
        };
        for name in d.env.keys() {
            if let Some(v) = stored.get(&format!("env.{name}")) {
                set(&mut env, name, v.clone());
            }
        }
        // The environment file overrides values of the same names; a file
        // that is too open is not read at all.
        if let EnvFile::Values(file) = read_env_file() {
            for (name, value) in file {
                if d.env.contains_key(&name) {
                    set(&mut env, &name, value);
                }
            }
        }
        if let Some(capability) = capability {
            apply_credential(capability, &mut args, &mut env, set);
        }
        Ok(Launch {
            command,
            args,
            env,
            cwd: PathBuf::from(&server.workspace),
            log: self.tool_log(instance),
        })
    }
    /// `STATE/tool-logs/AGENT_ID/SERVER[@CAPABILITY].log`.
    pub(crate) fn tool_log(&self, instance: &Instance) -> PathBuf {
        self.state_directory()
            .join("tool-logs")
            .join(&instance.agent_id)
            .join(format!("{}.log", instance.label()))
    }

    /// Replaces an agent's definitions and values in one transaction.
    /// Returns the instances to snapshot and the servers to stop.
    fn replace_servers(
        &self,
        agent: &str,
        r: PutServers,
    ) -> Result<(Vec<Instance>, Vec<String>), Error> {
        if !std::path::Path::new(&r.workspace).is_absolute() {
            return Err(Error::Invalid("workspace must be an absolute path".into()));
        }
        let mut names = BTreeSet::new();
        for d in &r.servers {
            valid_definition(d)?;
            if !names.insert(d.name.clone()) {
                return Err(Error::Invalid(format!(
                    "server {:?} is listed twice",
                    d.name
                )));
            }
        }
        for (server, fields) in &r.values {
            let Some(d) = r.servers.iter().find(|d| &d.name == server) else {
                return Err(Error::Invalid(format!(
                    "values name unknown server {server:?}"
                )));
            };
            if let Some(field) = fields.keys().find(|f| !valid_field(d, f)) {
                return Err(Error::Invalid(format!(
                    "invalid value field {field:?} of server {server:?}"
                )));
            }
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if !self.agent_exists(&tx, agent)? {
            return Err(Error::NotFound);
        }
        let old: BTreeMap<String, ServerRecord> = server_records(&tx, agent)?
            .into_iter()
            .map(|s| (s.definition.name.clone(), s))
            .collect();
        let mut stop = Vec::new();
        for name in old.keys().filter(|n| !names.contains(*n)) {
            // Capabilities built on it remain, and become unavailable.
            for table in ["tool_servers", "tool_values"] {
                let column = if table == "tool_servers" {
                    "name"
                } else {
                    "server"
                };
                tx.execute(
                    &format!("DELETE FROM {table} WHERE agent_id = ?1 AND {column} = ?2"),
                    params![agent, name],
                )?;
            }
            stop.push(name.clone());
        }
        tx.execute("DELETE FROM tool_values WHERE agent_id = ?1", [agent])?;
        let at = now();
        let mut snapshot = Vec::new();
        for d in r.servers {
            let (shareable, reason, missing_env) = reason_for(&d, r.values.get(&d.name));
            let previous = old.get(&d.name);
            if previous.is_some_and(|p| p.definition != d || p.workspace != r.workspace) {
                stop.push(d.name.clone());
            }
            let record = ServerRecord {
                agent_id: agent.to_owned(),
                workspace: r.workspace.clone(),
                shareable,
                reason,
                missing_env,
                snapshot: previous.and_then(|p| p.snapshot.clone()),
                snapshot_error: previous.and_then(|p| p.snapshot_error.clone()),
                health: previous.map(|p| p.health.clone()).unwrap_or_default(),
                updated_at: at.clone(),
                definition: d.clone(),
            };
            tx.execute(
                "INSERT OR REPLACE INTO tool_servers VALUES (?1, ?2, ?3)",
                params![agent, d.name, serde_json::to_string(&record)?],
            )?;
            if let Some(fields) = r.values.get(&d.name) {
                for (field, value) in fields {
                    tx.execute(
                        "INSERT INTO tool_values VALUES (?1, ?2, ?3, ?4)",
                        params![agent, d.name, field, value],
                    )?;
                }
            }
            if shareable {
                snapshot.push(Instance {
                    agent_id: agent.to_owned(),
                    server: d.name.clone(),
                    capability: None,
                });
            }
        }
        // Capabilities with their own credential, built on this agent's
        // shareable sources, are snapshotted again with that credential; a
        // failure keeps their previous snapshot.
        for c in capability_records(&tx)? {
            if c.agent_id == agent
                && c.credential.own()
                && snapshot
                    .iter()
                    .any(|i| i.capability.is_none() && i.server == c.source.server)
            {
                snapshot.push(c.instance());
            }
        }
        append_event(&tx, "sources.discovered", agent, &at)?;
        tx.commit()?;
        Ok((snapshot, stop))
    }
    /// Stores a snapshot's outcome: a new snapshot, or an error that keeps
    /// the previous one.
    pub(crate) fn store_snapshot(
        &self,
        instance: &Instance,
        outcome: Result<Snapshot, String>,
    ) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let at = now();
        let failed = outcome.is_err();
        match &instance.capability {
            None => {
                let Some(mut r) = server_record(&tx, &instance.agent_id, &instance.server)? else {
                    return Ok(());
                };
                match outcome {
                    Ok(s) => {
                        r.snapshot = Some(s);
                        r.snapshot_error = None;
                    }
                    Err(e) => r.snapshot_error = Some(e),
                }
                tx.execute(
                    "UPDATE tool_servers SET record = ?1 WHERE agent_id = ?2 AND name = ?3",
                    params![
                        serde_json::to_string(&r)?,
                        instance.agent_id,
                        instance.server
                    ],
                )?;
            }
            Some(c) => {
                let Some(mut r) = capability_record(&tx, c)? else {
                    return Ok(());
                };
                match outcome {
                    Ok(s) => {
                        r.snapshot = Some(s);
                        r.snapshot_error = None;
                    }
                    Err(e) => r.snapshot_error = Some(e),
                }
                crate::capabilities::save(&tx, &r)?;
            }
        }
        if failed {
            append_event(
                &tx,
                "sources.snapshot_failed",
                &format!("{}/{}", instance.agent_id, instance.label()),
                &at,
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Records a failed start, or a JSON-RPC error suggesting
    /// authentication, for `status`.
    pub(crate) fn note_health(
        &self,
        instance: &Instance,
        start_failed: bool,
        auth_error: Option<&str>,
    ) -> Result<(), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let at = now();
        let update = |h: &mut Health| {
            if start_failed {
                h.start_failed_at = Some(at.clone());
            }
            if let Some(message) = auth_error {
                h.auth_error_at = Some(at.clone());
                h.auth_error = Some(message.chars().take(200).collect());
            }
        };
        match &instance.capability {
            None => {
                if let Some(mut r) = server_record(&tx, &instance.agent_id, &instance.server)? {
                    update(&mut r.health);
                    tx.execute(
                        "UPDATE tool_servers SET record = ?1 WHERE agent_id = ?2 AND name = ?3",
                        params![
                            serde_json::to_string(&r)?,
                            instance.agent_id,
                            instance.server
                        ],
                    )?;
                }
            }
            Some(c) => {
                if let Some(mut r) = capability_record(&tx, c)? {
                    update(&mut r.health);
                    crate::capabilities::save(&tx, &r)?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// `GET /v1/sources`: every agent (or one, by name or ID) with its
    /// sources, their snapshots, and the capabilities built on them, plus
    /// the open list. Values never appear.
    pub fn sources_view(&self, agent: Option<&str>) -> Result<Value, Error> {
        let agents = self.agents()?;
        let conn = self.connection()?;
        let mut out = Vec::new();
        let mut matched = false;
        let mut sorted = agents;
        sorted.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        for a in sorted {
            if agent.is_some_and(|x| x != a.name && x != a.id) {
                continue;
            }
            matched = true;
            let mut servers = Vec::new();
            let built = capability_records(&conn)?;
            for s in server_records(&conn, &a.id)? {
                let name = s.definition.name.clone();
                let capabilities: Vec<&str> = built
                    .iter()
                    .filter(|c| c.agent_id == a.id && c.source.server == name)
                    .map(|c| c.name.as_str())
                    .collect();
                let d = &s.definition;
                servers.push(json!({
                    "name": name,
                    "transport": d.transport,
                    "command": d.command,
                    "args": d.args,
                    "env": d.env,
                    "url": d.url,
                    "source": d.source,
                    "disabled": d.disabled.unwrap_or(false),
                    "shareable": s.shareable,
                    "reason": s.reason,
                    "missing_env": s.missing_env,
                    "tools": s.snapshot.as_ref().map(|s| s.tools.clone()).unwrap_or_default(),
                    "resources": s.snapshot.as_ref().map(|s| s.resources.clone()).unwrap_or_default(),
                    "snapshot_at": s.snapshot.as_ref().map(|s| s.taken_at.clone()),
                    "snapshot_error": s.snapshot_error,
                    "start_failed_at": s.health.start_failed_at,
                    "auth_error_at": s.health.auth_error_at,
                    "capabilities": capabilities,
                }));
            }
            out.push(json!({
                "agent": {"id": a.id, "name": a.name},
                "workspace": server_records(&conn, &a.id)?.first().map(|s| s.workspace.clone()),
                "servers": servers,
            }));
        }
        if agent.is_some() && !matched {
            return Err(Error::NotFound);
        }
        Ok(json!({"agents": out, "open_to": open_list(&conn)?}))
    }
    /// One agent with its stored servers and their snapshots.
    fn agent_servers(&self, agent: &str) -> Result<Value, Error> {
        let view = self.sources_view(Some(agent))?;
        Ok(view["agents"][0].clone())
    }
    /// `sources open-to`: adds a host bound to this host's person in some
    /// network map, or `*`. Returns the entry and whether it is new.
    fn open_to(&self, host: &str) -> Result<(Value, bool), Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if host != "*" {
            if !crate::peer_store::valid_id(host, "host", 32) || host == self.identity().id {
                return Err(Error::Invalid("give another host's ID, or --all".into()));
            }
            let mut bound = false;
            for (network, own) in self.own_members(&tx)? {
                if let Some(person) = &own.person_id {
                    bound |= crate::chain::member(&tx, &network, host)?
                        .is_some_and(|m| m.person_id.as_deref() == Some(person.as_str()));
                }
            }
            if !bound {
                return Err(Error::Invalid(format!(
                    "host {host} is not bound to this host's person in any network"
                )));
            }
        }
        let old: Option<String> = tx
            .query_row(
                "SELECT created_at FROM source_access WHERE host_id = ?1",
                [host],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(at) = old {
            return Ok((json!({"host_id": host, "created_at": at}), false));
        }
        let at = now();
        tx.execute(
            "INSERT INTO source_access VALUES (?1, ?2)",
            params![host, at],
        )?;
        append_event(&tx, "sources.opened", host, &at)?;
        tx.commit()?;
        Ok((json!({"host_id": host, "created_at": at}), true))
    }
    /// `sources close-to`: removes the host, or `*`.
    fn close_to(&self, host: &str) -> Result<Value, Error> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let removed = tx.execute("DELETE FROM source_access WHERE host_id = ?1", [host])?;
        if removed > 0 {
            append_event(&tx, "sources.closed", host, &now())?;
        }
        tx.commit()?;
        Ok(json!({"host_id": host, "removed": removed}))
    }
    /// Status item 14 for sources: `(subject, detail, command)` for each
    /// failing snapshot, recent start failure, recent authentication-like
    /// error, and an environment file that is too open.
    pub(crate) fn failing_sources(&self) -> Result<Vec<(String, String, String)>, Error> {
        let conn = self.connection()?;
        let names: BTreeMap<String, String> = agent_names(&conn)?;
        let day = chrono::Utc::now() - chrono::TimeDelta::hours(24);
        let recent = |at: &Option<String>| {
            at.as_deref()
                .and_then(|t| crate::membership::time(t).ok())
                .is_some_and(|t| t > day)
        };
        let mut out = Vec::new();
        let mut statement =
            conn.prepare("SELECT record FROM tool_servers ORDER BY agent_id, name")?;
        let servers: Vec<ServerRecord> = statement
            .query_map([], |r| r.get::<_, String>(0))?
            .map(|r| json(r?))
            .collect::<Result<_, Error>>()?;
        let mut check = |agent: &str, label: String, error: &Option<String>, h: &Health| {
            let name = names
                .get(agent)
                .cloned()
                .unwrap_or_else(|| agent.to_owned());
            let mut causes = Vec::new();
            if let Some(e) = error {
                causes.push(format!("its latest snapshot failed: {e}"));
            }
            if recent(&h.start_failed_at) {
                causes.push("an instance failed to start in the last 24 hours".to_owned());
            }
            if recent(&h.auth_error_at) {
                causes.push(format!(
                    "it answered with an error suggesting authentication in the last 24 hours ({}); its captured credentials may be stale",
                    h.auth_error.clone().unwrap_or_default()
                ));
            }
            if !causes.is_empty() {
                out.push((
                    format!("{name}/{label}"),
                    causes.join("; "),
                    format!("peerspan sources refresh --agent {name}"),
                ));
            }
        };
        for s in &servers {
            check(
                &s.agent_id,
                s.definition.name.clone(),
                &s.snapshot_error,
                &s.health,
            );
        }
        if let EnvFile::TooOpen(path) = read_env_file() {
            out.push((
                "env".into(),
                format!(
                    "the environment file {} is not mode 0600 or stricter, so servers start without it",
                    path.display()
                ),
                format!("chmod 600 {}", path.display()),
            ));
        }
        Ok(out)
    }
}

/// Lists a server's tools and resources once, within 30 seconds, from a
/// short-lived instance.
pub(crate) async fn take_snapshot(launch: Launch) -> Result<Snapshot, String> {
    let work = async {
        let (client, capabilities) = mcp::start(&launch).await.map_err(|e| format!("{e:#}"))?;
        // Each list is asked for when the server declares its capability
        // key, whatever the value.
        let tools = if capabilities.get("tools").is_some() {
            mcp::list(&client, "tools/list", "tools", LIST_LIMIT)
                .await
                .map_err(|e| format!("{e:#}"))?
        } else {
            Vec::new()
        };
        let resources = if capabilities.get("resources").is_some() {
            mcp::list(&client, "resources/list", "resources", LIST_LIMIT)
                .await
                .map_err(|e| format!("{e:#}"))?
        } else {
            Vec::new()
        };
        client.kill();
        let text = |v: &Value| v.as_str().map(str::to_owned);
        let tools = tools
            .iter()
            .filter_map(|t| {
                Some(ToolEntry {
                    name: t["name"].as_str()?.to_owned(),
                    description: text(&t["description"]),
                    input_schema: t
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object"})),
                    read_only: t["annotations"]["readOnlyHint"] == json!(true),
                })
            })
            .collect();
        let resources = resources
            .iter()
            .filter_map(|r| {
                Some(ResourceEntry {
                    uri: r["uri"].as_str()?.to_owned(),
                    name: text(&r["name"]),
                    description: text(&r["description"]),
                    mime_type: text(&r["mimeType"]),
                })
            })
            .collect();
        Ok::<_, String>(Snapshot {
            tools,
            resources,
            taken_at: now(),
        })
    };
    let snapshot = tokio::time::timeout(SNAPSHOT_BOUND, work)
        .await
        .map_err(|_| "the snapshot did not finish within 30 seconds".to_owned())??;
    match serde_json::to_vec(&snapshot) {
        Ok(encoded) if encoded.len() <= SNAPSHOT_MAX => Ok(snapshot),
        _ => Err("the snapshot is larger than 1 MiB".into()),
    }
}

/// Snapshots instances, 8 at a time, and stores each outcome.
async fn snapshot_all(store: Arc<Store>, instances: Vec<Instance>) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(SNAPSHOT_PARALLEL));
    let mut set = tokio::task::JoinSet::new();
    for instance in instances {
        let store = store.clone();
        let semaphore = semaphore.clone();
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            let i = instance.clone();
            let outcome =
                match blocking(store.clone(), move |s| s.launch(&*s.connection()?, &i)).await {
                    Ok(launch) => take_snapshot(launch).await,
                    Err(e) => Err(e.to_string()),
                };
            let _ = blocking(store, move |s| s.store_snapshot(&instance, outcome)).await;
        });
    }
    while set.join_next().await.is_some() {}
}

#[derive(Deserialize)]
struct SourcesQuery {
    #[serde(default)]
    agent: Option<String>,
}
pub(crate) fn local_routes() -> Router<Arc<Store>> {
    Router::new()
        .route("/v1/sources", get(list_route))
        .route("/v1/agents/{agent}/tool-servers", put(put_route))
        .route("/v1/sources/open-to", post(open_route))
        .route("/v1/sources/open-to/{host}", delete(close_route))
}
async fn list_route(
    State(store): State<Arc<Store>>,
    query: Result<Query<SourcesQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Value>, Error> {
    let Query(q) = query.map_err(|_| Error::Invalid("invalid query".into()))?;
    Ok(Json(
        blocking(store, move |s| s.sources_view(q.agent.as_deref())).await?,
    ))
}
async fn put_route(
    State(store): State<Arc<Store>>,
    Path(agent): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, Error> {
    let request: PutServers = decode(body)?;
    let id = agent.clone();
    let (instances, stop) =
        blocking(store.clone(), move |s| s.replace_servers(&id, request)).await?;
    for server in &stop {
        store.tool_pool.stop(&agent, server);
    }
    snapshot_all(store.clone(), instances).await;
    Ok(Json(
        blocking(store, move |s| s.agent_servers(&agent)).await?,
    ))
}
async fn open_route(
    State(store): State<Arc<Store>>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let request: OpenTo = decode(body)?;
    let (entry, new) = blocking(store, move |s| s.open_to(&request.host_id)).await?;
    Ok((
        if new {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(entry),
    ))
}
async fn close_route(
    State(store): State<Arc<Store>>,
    Path(host): Path<String>,
) -> Result<Json<Value>, Error> {
    Ok(Json(blocking(store, move |s| s.close_to(&host)).await?))
}

/// The open list, sorted, with `*` first.
pub(crate) fn open_list(conn: &Connection) -> Result<Vec<String>, Error> {
    let mut statement = conn.prepare("SELECT host_id FROM source_access ORDER BY host_id")?;
    let mut hosts: Vec<String> = statement
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    hosts.sort_by_key(|h| (h != "*", h.clone()));
    Ok(hosts)
}
/// Whether the open list lets `host` call this host's sources.
pub(crate) fn open_to_host(conn: &Connection, host: &str) -> Result<bool, Error> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM source_access WHERE host_id = ?1 OR host_id = '*')",
        [host],
        |r| r.get(0),
    )?)
}
/// Applies a capability's own credential: its `args` replace the source's,
/// and its whole `env_file` is applied last.
pub(crate) fn apply_credential(
    capability: &CapabilityRecord,
    args: &mut Vec<String>,
    env: &mut Vec<(String, String)>,
    set: impl Fn(&mut Vec<(String, String)>, &str, String),
) {
    if let Some(a) = &capability.credential.args {
        *args = a.clone();
    }
    if let Some(path) = &capability.credential.env_file
        && let Ok(text) = std::fs::read_to_string(path)
    {
        for (name, value) in parse_env(&text) {
            set(env, &name, value);
        }
    }
}
