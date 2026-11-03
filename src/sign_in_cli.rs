//! `sources login` and `logout`, and `capability login` and `logout`
//! (capabilities slice 3): the CLI starts a sign-in at the daemon, opens or
//! prints the authorization link, receives the redirect on a loopback port
//! or as a pasted address, and hands it to the daemon. The PKCE verifier
//! and the tokens stay in the daemon.
use crate::{admin::Local, cli::encoded};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::io::{BufRead, IsTerminal};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

/// The flags of a sign-in.
pub struct SignIn<'a> {
    pub scopes: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub client_secret_file: Option<&'a std::path::Path>,
    pub port: Option<u16>,
    pub no_browser: bool,
    pub account: Option<&'a str>,
}

/// `AGENT/SERVER`, or `SERVER` when exactly one agent here has it.
pub async fn resolve_source(local: &Local<'_>, given: &str) -> anyhow::Result<(String, String)> {
    if let Some((agent, server)) = given.split_once('/') {
        return Ok((agent.to_owned(), server.to_owned()));
    }
    let view = local.get("/v1/sources".into()).await?;
    let mut found = Vec::new();
    for a in view["agents"].as_array().into_iter().flatten() {
        for s in a["servers"].as_array().into_iter().flatten() {
            if s["name"].as_str() == Some(given) {
                found.push(a["agent"]["name"].as_str().unwrap_or_default().to_owned());
            }
        }
    }
    match found.len() {
        0 => bail!("No source {given} on this host. Run peerspan sources."),
        1 => Ok((found.remove(0), given.to_owned())),
        _ => bail!(
            "several agents have a source named {given}; give AGENT/SERVER: {}",
            found
                .iter()
                .map(|a| format!("{a}/{given}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The source of a capability, `(agent, server)`, and its view.
async fn capability_source(
    local: &Local<'_>,
    name: &str,
) -> anyhow::Result<(String, String, Value)> {
    match local
        .get(format!("/v1/capabilities/{}", encoded(name)))
        .await
    {
        Ok(c) => Ok((
            c["source"]["agent"].as_str().unwrap_or_default().to_owned(),
            c["source"]["server"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            c,
        )),
        Err(e)
            if e.downcast_ref::<crate::integration::DaemonError>()
                .is_some_and(|d| d.status == 404) =>
        {
            bail!("No capability {name} on this host. Run peerspan capability list.")
        }
        Err(e) => Err(e),
    }
}

/// Whether to print the link rather than open a browser.
fn print_mode(no_browser: bool) -> bool {
    let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    no_browser
        || set("SSH_CONNECTION")
        || (cfg!(target_os = "linux") && !set("DISPLAY") && !set("WAYLAND_DISPLAY"))
}

/// What the waiting ends with.
enum Got {
    /// A request to the listener: its target, and the stream to answer.
    Listener(String, tokio::net::TcpStream),
    Pasted(String),
}

/// Reads one HTTP request's head; its target when it is `GET`.
async fn request_target(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut buffer = [0u8; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 65536 {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buffer))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buffer[..n]);
    }
    let text = String::from_utf8_lossy(&head);
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    parts.next().map(str::to_owned)
}
async fn answer(stream: &mut tokio::net::TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Signs in to a source, or for a capability its own sign-in.
pub async fn sign_in(
    local: &Local<'_>,
    agent: &str,
    server: &str,
    capability: Option<&str>,
    flags: &SignIn<'_>,
) -> anyhow::Result<Value> {
    let command = if capability.is_some() {
        "capability login"
    } else {
        "sources login"
    };
    if !std::io::stdin().is_terminal() && !flags.no_browser {
        bail!(
            "{command} needs a terminal, or --no-browser to print the link and read the pasted address from stdin."
        );
    }
    if flags.client_secret_file.is_some() && flags.client_id.is_none() {
        bail!("--client-secret-file needs --client-id.");
    }
    let secret = match flags.client_secret_file {
        Some(path) => {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .with_context(|| format!("read {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                bail!("{} must have mode 0600 or stricter.", path.display());
            }
            Some(
                std::fs::read_to_string(path)
                    .with_context(|| format!("read {}", path.display()))?
                    .trim_end()
                    .to_owned(),
            )
        }
        None => None,
    };
    let started = local
        .post(
            format!("/v1/sources/{}/{}/login", encoded(agent), encoded(server)),
            json!({
                "capability": capability,
                "scopes": flags.scopes,
                "client_id": flags.client_id,
                "client_secret": secret,
                "redirect_port": flags.port,
                "account": flags.account,
            }),
        )
        .await?;
    let login_id = started["login_id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let link = started["authorization_url"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let redirect = started["redirect_uri"].as_str().unwrap_or_default();
    let port = peerspan_host::http_client::parse_url(redirect)
        .map(|u| u.port)
        .unwrap_or_default();
    let expires = started["expires_at"]
        .as_str()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| peerspan_host::clock::now() + chrono::TimeDelta::minutes(10));
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => Some(l),
        Err(_) => {
            eprintln!(
                "Port {port} on 127.0.0.1 is in use, so Peerspan cannot receive the redirect; paste the address instead."
            );
            None
        }
    };
    let mut opened = false;
    if !print_mode(flags.no_browser) {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        opened = match std::process::Command::new(opener)
            .arg(&link)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                // The opener runs before the link is printed: wait for it,
                // at most 5 seconds.
                let started = std::time::Instant::now();
                while started.elapsed() < std::time::Duration::from_secs(5) {
                    if !matches!(child.try_wait(), Ok(None)) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                true
            }
            Err(_) => false,
        };
    }
    if opened {
        eprintln!("Opening your browser to approve Peerspan. If it does not open, use this link:");
    } else {
        eprintln!("Open this link in a browser on any machine and approve Peerspan:");
    }
    eprintln!("  {link}");
    eprintln!("If the browser then shows a page that cannot be reached, copy the full address");
    eprintln!("from its address bar and paste it here:");
    // Pasted lines arrive from a thread; end of input is None.
    let (lines_tx, mut lines) = mpsc::unbounded_channel::<Option<String>>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if lines_tx.send(Some(line)).is_err() {
                return;
            }
        }
        let _ = lines_tx.send(None);
    });
    let wait = (expires - peerspan_host::clock::now())
        .to_std()
        .unwrap_or_default();
    let deadline = tokio::time::Instant::now() + wait;
    let mut stdin_open = true;
    let got = loop {
        if !stdin_open && listener.is_none() {
            bail!("The sign-in was not completed.");
        }
        tokio::select! {
            accepted = async {
                match &listener {
                    Some(l) => l.accept().await.ok(),
                    None => std::future::pending().await,
                }
            } => {
                let Some((mut stream, _)) = accepted else { continue };
                match request_target(&mut stream).await {
                    Some(target) if target.split('?').next() == Some("/callback") => {
                        break Got::Listener(target, stream);
                    }
                    _ => answer(&mut stream, "404 Not Found", "Not found.").await,
                }
            }
            line = lines.recv(), if stdin_open => match line {
                Some(Some(line)) => {
                    let line = line.trim().to_owned();
                    if !line.is_empty() {
                        break Got::Pasted(line);
                    }
                }
                _ => stdin_open = false,
            },
            _ = tokio::time::sleep_until(deadline) => {
                let source = format!("{agent}/{server}");
                bail!("This sign-in link is no longer valid. Run peerspan sources login {source} again.");
            }
        }
    };
    let (callback_url, mut stream) = match got {
        Got::Listener(target, stream) => (format!("http://127.0.0.1:{port}{target}"), Some(stream)),
        Got::Pasted(line) => (line, None),
    };
    let result = local
        .post(
            format!("/v1/oauth/logins/{}/complete", encoded(&login_id)),
            json!({"callback_url": callback_url}),
        )
        .await;
    if let Some(stream) = stream.as_mut() {
        match &result {
            Ok(_) => {
                answer(
                    stream,
                    "200 OK",
                    "<!doctype html><title>Peerspan</title><p>Peerspan sign-in complete. You can close this tab.</p>",
                )
                .await
            }
            Err(e) => {
                let text = match e.downcast_ref::<crate::integration::DaemonError>() {
                    Some(d) => d.message.clone(),
                    None => e.to_string(),
                };
                answer(
                    stream,
                    "400 Bad Request",
                    &format!(
                        "<!doctype html><title>Peerspan</title><p>Peerspan sign-in failed. {} See the terminal.</p>",
                        html_escape(&text)
                    ),
                )
                .await
            }
        }
    }
    let done = result?;
    eprintln!(
        "Signed in to {} for {} (scopes: {}).",
        peerspan_host::http_client::display_host(done["issuer"].as_str().unwrap_or_default()),
        done["source"].as_str().unwrap_or_default(),
        done["scopes"].as_str().unwrap_or("none")
    );
    Ok(done)
}

/// `sources login SOURCE`.
pub async fn sources_login(
    local: &Local<'_>,
    source: &str,
    flags: &SignIn<'_>,
) -> anyhow::Result<Value> {
    let (agent, server) = resolve_source(local, source).await?;
    sign_in(local, &agent, &server, None, flags).await
}
/// `capability login NAME`.
pub async fn capability_login(
    local: &Local<'_>,
    name: &str,
    flags: &SignIn<'_>,
) -> anyhow::Result<Value> {
    let (agent, server, _) = capability_source(local, name).await?;
    sign_in(local, &agent, &server, Some(name), flags).await
}

/// The revocation hint for a credential deleted without revocation.
fn not_revoked(issuer: &str) {
    let label = peerspan_host::oauth::client_name();
    eprintln!(
        "{issuer} has no revocation endpoint Peerspan could use. To revoke access there, remove \"{label}\" from the connected apps of your account."
    );
}

/// `sources logout SOURCE [--yes]`.
pub async fn sources_logout(local: &Local<'_>, source: &str, yes: bool) -> anyhow::Result<Value> {
    let (agent, server) = resolve_source(local, source).await?;
    let shown = format!("{agent}/{server}");
    let view = local
        .get(format!("/v1/sources?agent={}", encoded(&agent)))
        .await
        .unwrap_or(Value::Null);
    let issuer = view["agents"][0]["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["name"].as_str() == Some(server.as_str()))
        .and_then(|s| s["auth"]["issuer"].as_str())
        .unwrap_or_default()
        .to_owned();
    let capabilities = local
        .get("/v1/capabilities".into())
        .await
        .unwrap_or(Value::Null);
    let users: Vec<String> = capabilities["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| {
            c["source"]["agent"].as_str() == Some(agent.as_str())
                && c["source"]["server"].as_str() == Some(server.as_str())
                && c["auth"]["own"] != true
        })
        .filter_map(|c| c["name"].as_str().map(str::to_owned))
        .collect();
    if !users.is_empty() {
        eprintln!("These capabilities use the sign-in of {shown}:");
        for u in &users {
            eprintln!("  {u}");
        }
        if !yes {
            if !std::io::stdin().is_terminal() {
                bail!("confirm this sign-out at a terminal, or pass --yes");
            }
            if !crate::capability_cli::ask(
                "Sign out? Calls to these capabilities will fail until the next sign-in. [y/N] ",
            )? {
                bail!("not signed out");
            }
        }
    }
    let out = local
        .post(
            format!(
                "/v1/sources/{}/{}/logout",
                encoded(&agent),
                encoded(&server)
            ),
            json!({"capability": null}),
        )
        .await?;
    if out["deleted"] == false {
        eprintln!(
            "{} has no sign-in on this host.",
            out["source"].as_str().unwrap_or(&shown)
        );
    } else if out["revoked"] == false {
        not_revoked(&issuer);
    }
    Ok(out)
}
/// `capability logout NAME`.
pub async fn capability_logout(local: &Local<'_>, name: &str) -> anyhow::Result<Value> {
    let (agent, server, view) = capability_source(local, name).await?;
    let issuer = view["auth"]["issuer"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let out = local
        .post(
            format!(
                "/v1/sources/{}/{}/logout",
                encoded(&agent),
                encoded(&server)
            ),
            json!({"capability": name}),
        )
        .await?;
    if out["deleted"] == false {
        eprintln!("{name} has no sign-in of its own on this host.");
    } else if out["revoked"] == false {
        not_revoked(&issuer);
    }
    Ok(out)
}

/// The review's and `shares`' `Credential:` text for a capability on a
/// remote source, without the `Credential: ` prefix; None for other
/// sources. `auth` is the capability's (or, for a draft, the source's)
/// auth; `name` the capability.
pub fn credential_text(
    source: &Value,
    auth: &Value,
    own: bool,
    env_file: Option<&str>,
    agent: &str,
    name: &str,
) -> Option<String> {
    if source["transport"].as_str() != Some("remote") {
        return None;
    }
    let server = source["name"].as_str().unwrap_or_default();
    let address = format!("{agent}/{server}");
    Some(match auth["mode"].as_str() {
        Some("none") => format!(
            "none. {address} ({}) asks for no sign-in, so it serves anyone who can reach it. Sharing it lets the people you share with use the selected operations through this host, including when the server is only reachable from here (a local, home, VPN, or company network).",
            peerspan_host::http_client::display_host(source["url"].as_str().unwrap_or_default())
        ),
        Some("headers") => {
            let names: Vec<&str> = source["headers"]
                .as_object()
                .map(|h| h.keys().map(String::as_str).collect())
                .unwrap_or_default();
            let from = source["source"].as_str().unwrap_or_default();
            let mut text = if names.len() == 1 {
                format!(
                    "the token in the {} header of {address} (from {from}).",
                    names[0]
                )
            } else {
                format!(
                    "the tokens in the {} headers of {address} (from {from}).",
                    names.join(", ")
                )
            };
            if let Some(file) = env_file {
                text.push_str(&format!(
                    " Values from the capability's environment file {file} override the variables those headers reference."
                ));
            }
            text
        }
        Some("oauth") if matches!(auth["state"].as_str(), Some("ok" | "refresh_failed")) => {
            let account = match auth["account"].as_str() {
                Some(a) => format!("account {a}"),
                None => "account not labelled; Peerspan cannot see which account approved".into(),
            };
            let date: String = auth["obtained_at"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .take(10)
                .collect();
            format!(
                "{} to {}, scopes {}, {account}, signed in on {date}.",
                if own {
                    "this capability's own sign-in"
                } else {
                    "Peerspan's own sign-in"
                },
                peerspan_host::http_client::display_host(
                    auth["issuer"].as_str().unwrap_or_default()
                ),
                auth["scope"].as_str().unwrap_or("none")
            )
        }
        Some("oauth") => format!(
            "the sign-in to {address} has lapsed; run {}",
            if own {
                format!("peerspan capability login {name}")
            } else {
                format!("peerspan sources login {address}")
            }
        ),
        _ => format!("unknown; Peerspan has not reached {address} yet."),
    })
}

/// The `url:` and `auth:` lines of a remote source in `sources`.
pub fn remote_lines(agent: &str, s: &Value) -> String {
    let name = s["name"].as_str().unwrap_or_default();
    let mut out = format!("    url: {}\n", s["url"].as_str().unwrap_or_default());
    let auth = &s["auth"];
    let line = match auth["mode"].as_str() {
        None => "not reached yet".to_owned(),
        Some("none") => "none (the server asks for no sign-in)".to_owned(),
        Some("headers") => format!(
            "headers {}",
            s["headers"]
                .as_object()
                .map(|h| h.keys().cloned().collect::<Vec<_>>().join(", "))
                .unwrap_or_default()
        ),
        Some("oauth")
            if matches!(auth["state"].as_str(), Some("ok" | "refresh_failed"))
                && auth["issuer"].is_string() =>
        {
            format!(
                "signed in to {}, scopes {}, account {}, {}",
                peerspan_host::http_client::display_host(
                    auth["issuer"].as_str().unwrap_or_default()
                ),
                auth["scope"].as_str().unwrap_or("none"),
                auth["account"].as_str().unwrap_or("not labelled"),
                auth["state"].as_str().unwrap_or_default()
            )
        }
        Some(_) => format!("needs a sign-in: peerspan sources login {agent}/{name}"),
    };
    out.push_str(&format!("    auth: {line}\n"));
    out
}
