//! Built-in source discovery in the CLI (capabilities contract, slice 3):
//! finds `gh` on the user's `PATH`, reads its version and `github.com`
//! accounts, captures each account's token, and sends the definitions to
//! the daemon. Tokens appear only in the request's `values`.
use anyhow::Context;
use hyper::Method;
use peerspan_host::builtin::{MIN_GH, version_of};
use serde_json::{Map, Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

/// Each discovery command may take this long.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// Token variables removed from the commands' environment.
const TOKEN_VARIABLES: [&str; 4] = [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
];

/// The first regular, executable `gh` on the CLI's `PATH`, skipping empty
/// and relative entries.
pub fn find_gh() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() || !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join("gh");
        if let Ok(m) = std::fs::metadata(&candidate)
            && m.is_file()
            && m.permissions().mode() & 0o111 != 0
        {
            return Some(candidate);
        }
    }
    None
}

/// Runs one discovery command: exit code and standard output, or None on a
/// failure to start or a timeout. Output is never printed.
async fn run(gh: &Path, args: &[&str]) -> Option<(i32, Vec<u8>)> {
    let mut command = tokio::process::Command::new(gh);
    command
        .args(args)
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for name in TOKEN_VARIABLES {
        command.env_remove(name);
    }
    let child = command.spawn().ok()?;
    let output = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    Some((output.status.code().unwrap_or(-1), output.stdout))
}

fn trim(text: &str) -> &str {
    text.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

/// `gh-LOGIN`: lowercased, other characters replaced by `-`, cut to 63.
fn account_name(login: &str) -> String {
    let mut name: String = format!("gh-{login}")
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if name.len() > 63 {
        let mut cut = 63;
        while !name.is_char_boundary(cut) {
            cut -= 1;
        }
        name.truncate(cut);
    }
    name
}

/// The definitions and values `PUT /v1/builtin-sources` takes.
pub async fn discover() -> (Vec<Value>, Map<String, Value>) {
    let mut values = Map::new();
    let Some(gh) = find_gh() else {
        return (Vec::new(), values);
    };
    let command = gh.display().to_string();
    let definition = |name: &str,
                      version: Option<&str>,
                      account: Option<&str>,
                      authenticated: bool,
                      captured: bool| {
        let env = if captured {
            json!({"GH_TOKEN": {"source": "captured"}})
        } else {
            json!({"GH_TOKEN": {"source": "missing", "variables": ["GH_TOKEN"]}})
        };
        json!({
            "name": name,
            "adapter": "gh",
            "command": command,
            "version": version,
            "host": "github.com",
            "account": account,
            "authenticated": authenticated,
            "env": env,
            "disabled": false,
        })
    };
    let version = run(&gh, &["--version"]).await.and_then(|(code, out)| {
        if code != 0 {
            return None;
        }
        let text = String::from_utf8_lossy(&out);
        let first = text.lines().next()?;
        let rest = first.strip_prefix("gh version ")?;
        let word: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let mut parts = word.splitn(4, '.');
        let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
        if [a, b, c].iter().any(|p| p.is_empty()) {
            return None;
        }
        let v = format!("{a}.{b}.{c}");
        version_of(&v).map(|_| v)
    });
    if version
        .as_deref()
        .and_then(version_of)
        .is_none_or(|v| v < MIN_GH)
    {
        return (
            vec![definition("gh", version.as_deref(), None, false, false)],
            values,
        );
    }
    let version = version.as_deref();
    let accounts: Vec<Value> = run(&gh, &["auth", "status", "--json", "hosts"])
        .await
        .filter(|(code, _)| *code == 0)
        .and_then(|(_, out)| serde_json::from_slice::<Value>(&out).ok())
        .and_then(|v| v["hosts"]["github.com"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|a| {
            !matches!(a["tokenSource"].as_str(), Some("GH_TOKEN" | "GITHUB_TOKEN"))
                && a["login"].as_str().is_some()
        })
        .collect();
    if accounts.is_empty() {
        return (vec![definition("gh", version, None, false, false)], values);
    }
    let active = accounts
        .iter()
        .position(|a| a["active"] == json!(true))
        .unwrap_or(0);
    let mut out: Vec<Value> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for (i, a) in accounts.iter().enumerate() {
        let login = a["login"].as_str().unwrap_or_default();
        let name = if i == active {
            "gh".to_owned()
        } else {
            account_name(login)
        };
        if names.contains(&name) {
            continue;
        }
        names.push(name.clone());
        let authenticated = a["state"].as_str() == Some("success");
        let token = if authenticated {
            run(
                &gh,
                &["auth", "token", "--hostname", "github.com", "--user", login],
            )
            .await
            .filter(|(code, _)| *code == 0)
            .map(|(_, out)| trim(&String::from_utf8_lossy(&out)).to_owned())
            .filter(|t| !t.is_empty())
        } else {
            None
        };
        if let Some(token) = &token {
            values.insert(name.clone(), json!({"env.GH_TOKEN": token}));
        }
        out.push(definition(
            &name,
            version,
            Some(login),
            authenticated,
            token.is_some(),
        ));
    }
    (out, values)
}

/// Runs built-in discovery and stores it. Returns `{servers, errors}` with
/// entries shaped as `attach`'s.
pub async fn refresh(socket: &Path) -> Value {
    let (sources, values) = discover().await;
    let body = json!({"sources": sources, "values": values});
    let stored = tokio::time::timeout(
        crate::LOCAL_TIMEOUT,
        crate::call(
            socket.to_path_buf(),
            Method::PUT,
            "/v1/builtin-sources".into(),
            Some(body),
        ),
    )
    .await
    .context("local host daemon request timed out");
    let stored = match stored {
        Ok(Ok(v)) => v,
        Ok(Err(e)) | Err(e) => {
            return json!({"servers": [], "errors": [{"source": "builtin", "path": null, "server": null, "error": format!("storing the built-in sources failed: {e:#}")}]});
        }
    };
    let servers: Vec<Value> = stored["builtin"]
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
            json!({
                "name": s["name"],
                "transport": s["transport"],
                "shareable": s["shareable"],
                "reason": s["reason"],
                "missing_env": s["missing_env"],
                "tools": tools,
                "read_only_tools": read_only,
                "snapshot_error": s["snapshot_error"],
            })
        })
        .collect();
    json!({"servers": servers, "errors": []})
}
