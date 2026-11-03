//! Discovery of the MCP servers an attached agent's harness already uses
//! (tools contract). It runs in the CLI, which has the user's environment
//! and the project directory, and sends the result to the daemon.
use anyhow::Context;
use hyper::Method;
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// What discovery found: normalized definitions, the values of their
/// literals and references, and the sources that did not parse.
#[derive(Default)]
pub struct Discovered {
    pub servers: Vec<Value>,
    pub values: Map<String, Value>,
    pub errors: Vec<Value>,
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}
fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".config")))
}

/// Resolves `${NAME}` and `${NAME:-DEFAULT}` from the environment. Returns
/// the text, whether it held a reference, and the variables without a value
/// or default.
fn resolve(text: &str) -> (String, bool, Vec<String>) {
    let mut out = String::new();
    let mut missing = Vec::new();
    let mut referenced = false;
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let Some(len) = rest[start..].find('}') else {
            break;
        };
        let inner = &rest[start + 2..start + len];
        let (name, default) = match inner.split_once(":-") {
            Some((n, d)) => (n, Some(d)),
            None => (inner, None),
        };
        let valid = !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit());
        out.push_str(&rest[..start]);
        if !valid {
            out.push_str(&rest[start..start + len + 1]);
        } else {
            referenced = true;
            match std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty() || default.is_none())
            {
                Some(v) => out.push_str(&v),
                None => match default {
                    Some(d) => out.push_str(d),
                    None => missing.push(name.to_owned()),
                },
            }
        }
        rest = &rest[start + len + 1..];
    }
    out.push_str(rest);
    (out, referenced, missing)
}

/// The valid variable names a text references, in order.
fn reference_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let Some(len) = rest[start..].find('}') else {
            break;
        };
        let inner = &rest[start + 2..start + len];
        let name = inner.split_once(":-").map_or(inner, |(n, _)| n);
        if !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
        {
            out.push(name.to_owned());
        }
        rest = &rest[start + len + 1..];
    }
    out
}
/// Names without repeats, in order of first appearance.
fn dedupe(names: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// A raw harness entry, before normalization.
struct Raw {
    remote: bool,
    disabled: bool,
    command: Option<String>,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    url: Option<String>,
    /// For a remote entry: `remote.protocol`, `remote.oauth`, and
    /// `remote.headers_helper`, and its headers.
    protocol: &'static str,
    oauth: Value,
    headers_helper: bool,
    headers: Vec<(String, Header)>,
}
/// How a remote header's value is written in the configuration.
enum Header {
    /// Literal text, never resolved (Codex `http_headers`).
    Literal(String),
    /// Text that may hold `${NAME}` or `${NAME:-D}` references.
    Template(String),
}
/// A header value that is not a string is its JSON text.
fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
/// Adds a header, replacing an earlier one of the same name, compared
/// case-insensitively.
fn put_header(headers: &mut Vec<(String, Header)>, name: &str, value: Header) {
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    headers.push((name.to_owned(), value));
}
/// `scopes` as a string, or an array joined with spaces.
fn scopes_of(v: &Value) -> Value {
    match v {
        Value::String(s) => json!(s),
        Value::Array(items) => json!(
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        ),
        _ => Value::Null,
    }
}
/// A callback port from 1 to 65535, else null.
fn port_of(v: &Value) -> Value {
    match v.as_u64() {
        Some(p) if (1..=65535).contains(&p) => json!(p),
        _ => Value::Null,
    }
}
fn hints(client_id: &Value, scopes: Value, port: Value) -> Value {
    json!({
        "client_id": client_id.as_str(),
        "scopes": scopes,
        "callback_port": port,
    })
}
/// OpenCode's `{env:VAR}` written as `${VAR}`.
fn opencode_refs(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("{env:") {
        let Some(len) = rest[start..].find('}') else {
            break;
        };
        out.push_str(&rest[..start]);
        out.push_str("${");
        out.push_str(&rest[start + 5..start + len]);
        out.push('}');
        rest = &rest[start + len + 1..];
    }
    out.push_str(rest);
    out
}
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}
fn string_map(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
        .collect()
}
fn claude_entry(v: &Value) -> Raw {
    let kind = v["type"].as_str().unwrap_or_default();
    let mut headers = Vec::new();
    for (name, value) in v["headers"].as_object().into_iter().flatten() {
        put_header(&mut headers, name, Header::Template(text_of(value)));
    }
    let oauth = &v["oauth"];
    Raw {
        remote: matches!(kind, "http" | "streamable-http" | "sse")
            || (v["url"].is_string() && kind != "stdio"),
        disabled: false,
        command: v["command"].as_str().map(str::to_owned),
        args: strings(&v["args"]),
        env: string_map(&v["env"]),
        url: v["url"].as_str().map(str::to_owned),
        protocol: if kind == "sse" { "sse" } else { "http" },
        oauth: hints(
            &oauth["clientId"],
            scopes_of(&oauth["scopes"]),
            port_of(&oauth["callbackPort"]),
        ),
        headers_helper: v.get("headersHelper").is_some_and(|h| !h.is_null()),
        headers,
    }
}
/// The Codex root's `mcp_oauth_callback_port`, carried into each entry.
const CODEX_GLOBAL_PORT: &str = "\u{0}mcp_oauth_callback_port";
fn codex_entry(v: &Value) -> Raw {
    let mut headers = Vec::new();
    for (name, value) in v["http_headers"].as_object().into_iter().flatten() {
        put_header(&mut headers, name, Header::Literal(text_of(value)));
    }
    for (name, var) in v["env_http_headers"].as_object().into_iter().flatten() {
        put_header(
            &mut headers,
            name,
            Header::Template(format!("${{{}}}", text_of(var))),
        );
    }
    if let Some(var) = v["bearer_token_env_var"].as_str() {
        put_header(
            &mut headers,
            "Authorization",
            Header::Template(format!("Bearer ${{{var}}}")),
        );
    }
    let port = match port_of(&v["oauth"]["callback_port"]) {
        Value::Null => port_of(&v[CODEX_GLOBAL_PORT]),
        port => port,
    };
    Raw {
        remote: v["url"].is_string(),
        disabled: v["enabled"] == json!(false),
        command: v["command"].as_str().map(str::to_owned),
        args: strings(&v["args"]),
        env: string_map(&v["env"]),
        url: v["url"].as_str().map(str::to_owned),
        protocol: "http",
        oauth: hints(&Value::Null, scopes_of(&v["scopes"]), port),
        headers_helper: false,
        headers,
    }
}
fn opencode_entry(v: &Value) -> Raw {
    let command = strings(&v["command"]);
    let kind = v["type"].as_str().unwrap_or_default();
    let mut headers = Vec::new();
    for (name, value) in v["headers"].as_object().into_iter().flatten() {
        put_header(
            &mut headers,
            name,
            Header::Template(opencode_refs(&text_of(value))),
        );
    }
    let oauth = &v["oauth"];
    Raw {
        remote: kind == "remote" || (v["url"].is_string() && kind != "local"),
        disabled: v["enabled"] == json!(false),
        command: command.first().cloned(),
        args: command.into_iter().skip(1).collect(),
        env: if v["environment"].is_object() {
            string_map(&v["environment"])
        } else {
            string_map(&v["env"])
        },
        url: v["url"].as_str().map(opencode_refs),
        protocol: "http",
        oauth: if *oauth == json!(false) {
            Value::Null
        } else {
            hints(&oauth["clientId"], scopes_of(&oauth["scope"]), Value::Null)
        },
        headers_helper: false,
        headers,
    }
}

/// One configuration source: its label, path, and how to read it.
struct Source {
    label: &'static str,
    path: PathBuf,
    format: Format,
}
enum Format {
    /// A JSON file and the pointer to its server map.
    Json(Vec<String>),
    /// Codex's TOML `[mcp_servers.NAME]` tables.
    CodexToml,
}

fn sources(integration: &str, workspace: &Path) -> Vec<Source> {
    let ws = workspace.to_string_lossy().into_owned();
    match integration {
        "claude-code" => {
            let Some(home) = home() else {
                return vec![Source {
                    label: "claude-code:project",
                    path: workspace.join(".mcp.json"),
                    format: Format::Json(vec!["mcpServers".into()]),
                }];
            };
            vec![
                Source {
                    label: "claude-code:user",
                    path: home.join(".claude.json"),
                    format: Format::Json(vec!["mcpServers".into()]),
                },
                Source {
                    label: "claude-code:project",
                    path: workspace.join(".mcp.json"),
                    format: Format::Json(vec!["mcpServers".into()]),
                },
                Source {
                    label: "claude-code:local",
                    path: home.join(".claude.json"),
                    format: Format::Json(vec!["projects".into(), ws, "mcpServers".into()]),
                },
            ]
        }
        "codex" => {
            let dir = std::env::var_os("CODEX_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .or_else(|| home().map(|h| h.join(".codex")));
            dir.map(|d| Source {
                label: "codex:user",
                path: d.join("config.toml"),
                format: Format::CodexToml,
            })
            .into_iter()
            .collect()
        }
        "opencode" => {
            let mut out = Vec::new();
            if let Some(config) = config_home() {
                out.push(Source {
                    label: "opencode:global",
                    path: config.join("opencode").join("opencode.json"),
                    format: Format::Json(vec!["mcp".into()]),
                });
            }
            out.push(Source {
                label: "opencode:project",
                path: workspace.join("opencode.json"),
                format: Format::Json(vec!["mcp".into()]),
            });
            out
        }
        _ => Vec::new(),
    }
}

/// The server map of one source, or why it could not be read. A missing
/// file contributes nothing.
fn read_source(s: &Source) -> Result<Map<String, Value>, String> {
    let text = match std::fs::read_to_string(&s.path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Map::new()),
        Err(e) => return Err(e.to_string()),
    };
    let root: Value = match &s.format {
        Format::Json(_) => serde_json::from_str(&text).map_err(|e| e.to_string())?,
        Format::CodexToml => {
            let table: toml::Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
            let mut value = serde_json::to_value(table).map_err(|e| e.to_string())?;
            let port = value["mcp_oauth_callback_port"].clone();
            let mut servers = value
                .as_object_mut()
                .and_then(|o| o.remove("mcp_servers"))
                .unwrap_or_default();
            if !port.is_null() {
                for entry in servers
                    .as_object_mut()
                    .into_iter()
                    .flat_map(|o| o.values_mut())
                {
                    if let Some(entry) = entry.as_object_mut() {
                        entry.insert(CODEX_GLOBAL_PORT.into(), port.clone());
                    }
                }
            }
            servers
        }
    };
    let mut node = &root;
    if let Format::Json(pointer) = &s.format {
        for key in pointer {
            node = &node[key.as_str()];
        }
    }
    Ok(node.as_object().cloned().unwrap_or_default())
}

/// Whether an entry is the integration's own Peerspan server: Codex's
/// `peerspan_` plus 32 hex digits, or an entry named `peerspan`.
fn own_entry(name: &str) -> bool {
    name == "peerspan"
        || name
            .strip_prefix("peerspan_")
            .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Discovers an integration's servers for a workspace.
pub fn discover(integration: &str, workspace: &Path) -> Discovered {
    let mut found: BTreeMap<String, (&'static str, Raw)> = BTreeMap::new();
    let mut errors = Vec::new();
    let read: Vec<Source> = sources(integration, workspace);
    for source in &read {
        match read_source(source) {
            Err(error) => errors.push(json!({
                "source": source.label,
                "path": source.path.display().to_string(),
                "server": Value::Null,
                "error": error,
            })),
            Ok(map) => {
                for (name, entry) in map {
                    if own_entry(&name) || !entry.is_object() {
                        continue;
                    }
                    let raw = match integration {
                        "claude-code" => claude_entry(&entry),
                        "codex" => codex_entry(&entry),
                        _ => opencode_entry(&entry),
                    };
                    // The highest-precedence definition wins whole.
                    found.insert(name, (source.label, raw));
                }
            }
        }
    }
    let mut out = Discovered {
        errors,
        ..Default::default()
    };
    for (name, (source, raw)) in found {
        let mut values = Map::new();
        let mut missing = Vec::new();
        let mut env = Map::new();
        let command = raw.command.as_ref().map(|c| {
            let (text, referenced, gone) = resolve(c);
            if referenced && gone.is_empty() {
                values.insert("command".into(), json!(text));
            }
            missing.extend(gone);
            c.clone()
        });
        for (i, a) in raw.args.iter().enumerate() {
            let (text, referenced, gone) = resolve(a);
            if referenced && gone.is_empty() {
                values.insert(format!("args.{i}"), json!(text));
            }
            missing.extend(gone);
        }
        for (key, value) in &raw.env {
            let (text, referenced, gone) = resolve(value);
            let source = if !gone.is_empty() {
                "missing"
            } else if referenced {
                "captured"
            } else {
                "literal"
            };
            let entry = if gone.is_empty() {
                values.insert(format!("env.{key}"), json!(text));
                json!({"source": source})
            } else {
                json!({"source": source, "variables": gone})
            };
            missing.extend(gone);
            env.insert(key.clone(), entry);
        }
        let stdio_without_command = !raw.remote && command.as_deref().is_none_or(str::is_empty);
        if stdio_without_command {
            out.errors.push(json!({
                "source": source,
                "path": Value::Null,
                "server": name,
                "error": "a local server without a command",
            }));
            continue;
        }
        let mut server = if raw.remote {
            // A remote entry: no command, args, or env; its URL, remote
            // hints, and headers.
            values.clear();
            missing.clear();
            env.clear();
            if let Some(url) = &raw.url {
                let (text, referenced, gone) = resolve(url);
                if referenced && gone.is_empty() {
                    values.insert("url".into(), json!(text));
                }
                missing.extend(gone);
            }
            let mut headers = Map::new();
            for (header, spec) in &raw.headers {
                let entry = match spec {
                    Header::Literal(text) => {
                        values.insert(format!("headers.{header}"), json!(text));
                        json!({"source": "literal"})
                    }
                    Header::Template(template) => {
                        let (text, referenced, gone) = resolve(template);
                        if !gone.is_empty() {
                            missing.extend(gone.clone());
                            json!({"source": "missing", "variables": dedupe(gone)})
                        } else if referenced {
                            values.insert(format!("headers.{header}"), json!(text));
                            values.insert(format!("header_templates.{header}"), json!(template));
                            json!({"source": "captured", "variables": dedupe(reference_names(template))})
                        } else {
                            values.insert(format!("headers.{header}"), json!(text));
                            json!({"source": "literal"})
                        }
                    }
                };
                headers.insert(header.clone(), entry);
            }
            json!({
                "name": name,
                "transport": "remote",
                "command": Value::Null,
                "args": [],
                "env": {},
                "url": raw.url,
                "remote": {
                    "protocol": raw.protocol,
                    "oauth": raw.oauth,
                    "headers_helper": raw.headers_helper,
                },
                "headers": headers,
                "source": source,
            })
        } else {
            json!({
                "name": name,
                "transport": "stdio",
                "command": json!(command),
                "args": json!(raw.args),
                "env": env,
                "url": raw.url,
                "source": source,
            })
        };
        if raw.disabled {
            server["disabled"] = json!(true);
        }
        // Kept for the attach output; never sent.
        missing.sort();
        missing.dedup();
        server["missing"] = json!(missing);
        out.servers.push(server);
        if !values.is_empty() {
            out.values.insert(name, Value::Object(values));
        }
    }
    out
}

/// Runs discovery for an agent and sends it to the daemon. Returns the
/// `tools` output of `attach`: `{servers, errors}`.
pub async fn refresh(
    socket: &Path,
    agent_id: &str,
    integration: &str,
    workspace: &Path,
) -> anyhow::Result<Value> {
    let found = discover(integration, workspace);
    let missing: BTreeMap<String, Value> = found
        .servers
        .iter()
        .filter_map(|s| Some((s["name"].as_str()?.to_owned(), s.get("missing")?.clone())))
        .collect();
    let servers: Vec<Value> = found
        .servers
        .into_iter()
        .map(|mut s| {
            if let Some(o) = s.as_object_mut() {
                o.remove("missing");
            }
            s
        })
        .collect();
    let body = json!({
        "workspace": workspace.to_string_lossy(),
        "servers": servers,
        "values": found.values,
    });
    let stored = tokio::time::timeout(
        crate::LOCAL_TIMEOUT,
        crate::call(
            socket.to_path_buf(),
            Method::PUT,
            format!("/v1/agents/{}/tool-servers", crate::cli::encoded(agent_id)),
            Some(body),
        ),
    )
    .await
    .context("local host daemon request timed out")??;
    let servers: Vec<Value> = stored["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| {
            let tools = s["tools"].as_array().map_or(0, Vec::len);
            let read_only = s["tools"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|t| t["read_only"] == json!(true))
                .count();
            let entry = json!({
                "name": s["name"],
                "transport": s["transport"],
                "shareable": s["shareable"],
                "reason": s["reason"],
                "missing_env": s["name"]
                    .as_str()
                    .and_then(|n| missing.get(n))
                    .cloned()
                    .unwrap_or_else(|| s["missing_env"].clone()),
                "tools": tools,
                "read_only_tools": read_only,
                "snapshot_error": s["snapshot_error"],
            });
            entry
        })
        .collect();
    Ok(json!({"servers": servers, "errors": found.errors}))
}

/// The readable line `attach` adds, for example `MCP servers found: github,
/// linear (remote, not shareable yet). None are shared.`
pub fn summary_line(tools: &Value) -> String {
    let servers: Vec<String> = tools["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| {
            let name = s["name"].as_str().unwrap_or_default();
            match s["reason"].as_str() {
                None => name.to_owned(),
                Some("remote") => format!("{name} (remote, not shareable yet)"),
                Some("login") => format!("{name} (needs a sign-in: peerspan sources login)"),
                Some("missing_env") => format!(
                    "{name} (not shareable: missing {})",
                    strings(&s["missing_env"]).join(", ")
                ),
                Some(reason) => format!("{name} (not shareable: {reason})"),
            }
        })
        .collect();
    if servers.is_empty() {
        "Sources found: none.".into()
    } else {
        format!(
            "MCP servers found: {}. None are shared.",
            servers.join(", ")
        )
    }
}
