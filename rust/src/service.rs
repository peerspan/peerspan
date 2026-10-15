//! `install`, `uninstall`, and the `service` part of `status`: the daemon as
//! a user service under systemd or launchd. The CLI runs the service tools it
//! finds on `PATH`; which tools are present selects the manager.
use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::{
    env, fs,
    net::{SocketAddr, UdpSocket},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const SYSTEMD_UNIT: &str = "peerspan.service";
const LAUNCHD_LABEL: &str = "dev.peerspan.host";
const DEFAULT_PORTS: std::ops::RangeInclusive<u16> = 7401..=7499;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Manager {
    Systemd,
    Launchd,
}

impl Manager {
    /// `systemctl` on `PATH` selects systemd, otherwise `launchctl` selects
    /// launchd.
    fn find() -> Option<Self> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return None;
        }
        if on_path("systemctl") {
            Some(Self::Systemd)
        } else if on_path("launchctl") {
            Some(Self::Launchd)
        } else {
            None
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
        }
    }
    fn unit(self) -> anyhow::Result<PathBuf> {
        let home = || {
            env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from)
                .context("HOME is not set")
        };
        Ok(match self {
            Self::Systemd => {
                let config = match env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
                    Some(directory) => PathBuf::from(directory),
                    None => home()?.join(".config"),
                };
                config.join("systemd/user").join(SYSTEMD_UNIT)
            }
            Self::Launchd => home()?
                .join("Library/LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist")),
        })
    }
}

fn on_path(tool: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|directory| {
            fs::metadata(directory.join(tool))
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
    })
}

/// Runs a service tool, returning whether it succeeded and its output.
fn tool(program: &str, args: &[&str]) -> (bool, String) {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text += &String::from_utf8_lossy(&output.stderr);
            (output.status.success(), text.trim().to_owned())
        }
        Err(error) => (false, error.to_string()),
    }
}
fn required(program: &str, args: &[&str]) -> anyhow::Result<()> {
    match tool(program, args) {
        (true, _) => Ok(()),
        (false, output) => bail!("{program} {} failed: {output}", args.join(" ")),
    }
}
fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    required("systemctl", &[&["--user"], args].concat())
}
fn gui() -> String {
    // SAFETY: getuid has no preconditions and cannot fail.
    format!("gui/{}", unsafe { libc::getuid() })
}
fn launchd_target() -> String {
    format!("{}/{LAUNCHD_LABEL}", gui())
}

/// The current user's name, for `loginctl show-user`.
fn user_name() -> Option<String> {
    // SAFETY: getpwuid returns null or a pointer to a static record that is
    // read here before any other call could overwrite it.
    let name = unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() || (*entry).pw_name.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr((*entry).pw_name)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    };
    name.or_else(|| env::var("USER").ok().filter(|u| !u.is_empty()))
}
/// Whether lingering is enabled; false when `loginctl` cannot tell.
fn linger() -> bool {
    let Some(user) = user_name() else {
        return false;
    };
    match tool("loginctl", &["show-user", &user, "--property=Linger"]) {
        (true, output) => output.lines().any(|l| l.trim() == "Linger=yes"),
        _ => false,
    }
}

/// An absolute, lexically cleaned path; symbolic links are kept.
fn absolute(path: &Path) -> anyhow::Result<PathBuf> {
    let path = std::path::absolute(path)?;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Ok(out)
}

/// One unit-file argument: bare when it has only safe characters, otherwise
/// double-quoted with `\\` and `"` escaped; `%` and `$` are always doubled.
fn unit_word(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._:@+=,-".contains(c));
    if safe {
        return word.to_owned();
    }
    let escaped = word
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    format!("\"{escaped}\"")
}
fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The unit or plist. Only the systemd unit carries `SSH_AUTH_SOCK`.
fn unit_text(manager: Manager, arguments: &[String], agent: Option<&str>) -> String {
    match manager {
        Manager::Systemd => {
            let exec = arguments
                .iter()
                .map(|a| unit_word(a))
                .collect::<Vec<_>>()
                .join(" ");
            let environment = agent
                .map(|a| format!("Environment={}\n", unit_word(&format!("SSH_AUTH_SOCK={a}"))))
                .unwrap_or_default();
            format!(
                "[Unit]\nDescription=Peerspan host daemon\n\n[Service]\nExecStart={exec}\n{environment}Restart=on-failure\n\n[Install]\nWantedBy=default.target\n"
            )
        }
        Manager::Launchd => {
            let program = arguments
                .iter()
                .map(|a| format!("\t\t<string>{}</string>\n", xml(a)))
                .collect::<String>();
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>{LAUNCHD_LABEL}</string>\n\t<key>ProgramArguments</key>\n\t<array>\n{program}\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n</dict>\n</plist>\n"
            )
        }
    }
}

/// The program arguments of an existing unit.
fn unit_arguments(manager: Manager, text: &str) -> Vec<String> {
    match manager {
        Manager::Systemd => text
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .map(split_words)
            .unwrap_or_default(),
        Manager::Launchd => {
            let Some(start) = text.find("<array>") else {
                return Vec::new();
            };
            let end = text[start..]
                .find("</array>")
                .map_or(text.len(), |e| start + e);
            text[start..end]
                .split("<string>")
                .skip(1)
                .filter_map(|s| s.split("</string>").next())
                .map(|s| {
                    s.replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&quot;", "\"")
                        .replace("&apos;", "'")
                        .replace("&amp;", "&")
                })
                .collect()
        }
    }
}
fn split_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            break;
        };
        let mut word = String::new();
        if first == '"' {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => word.extend(chars.next()),
                    c => word.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                word.push(c);
                chars.next();
            }
        }
        words.push(word.replace("%%", "%").replace("$$", "$"));
    }
    words
}

fn free_port() -> anyhow::Result<SocketAddr> {
    for port in DEFAULT_PORTS {
        if let Ok(socket) = UdpSocket::bind(("0.0.0.0", port)) {
            drop(socket);
            return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
        }
    }
    bail!(
        "no free UDP port from {} to {}; pass --peer-listen",
        DEFAULT_PORTS.start(),
        DEFAULT_PORTS.end()
    )
}

/// Whether the state directory's admin socket accepts a connection.
async fn listening(directory: &Path) -> bool {
    tokio::net::UnixStream::connect(directory.join("admin.sock"))
        .await
        .is_ok()
}
/// Whether the service is running, from its manager.
fn active(manager: Manager) -> bool {
    match manager {
        Manager::Systemd => {
            let (_, output) = tool("systemctl", &["--user", "is-active", SYSTEMD_UNIT]);
            output.lines().next().map(str::trim) == Some("active")
        }
        Manager::Launchd => tool("launchctl", &["print", &launchd_target()]).0,
    }
}

/// `install`: writes the unit, enables (and starts) the service, and enables
/// lingering on systemd.
pub(crate) async fn install(
    directory: &Path,
    peer_listen: Option<SocketAddr>,
    no_start: bool,
) -> anyhow::Result<Value> {
    let manager = Manager::find().context("no supported service manager")?;
    let unit = manager.unit()?;
    let state = absolute(directory)?;
    let binary = fs::canonicalize(env::current_exe()?)?;
    if listening(&state).await && !active(manager) {
        bail!(
            "a daemon is already running on {} outside the service; stop it first",
            state.display()
        );
    }
    let existing = fs::read_to_string(&unit).ok();
    let previous = existing
        .as_deref()
        .map(|text| unit_arguments(manager, text))
        .unwrap_or_default();
    let listen = match peer_listen {
        Some(address) => address.to_string(),
        None => match previous
            .iter()
            .position(|a| a == "--peer-listen")
            .and_then(|i| previous.get(i + 1))
        {
            Some(address) => address.clone(),
            None => free_port()?.to_string(),
        },
    };
    let arguments = [
        binary.to_string_lossy().into_owned(),
        "--state".into(),
        state.to_string_lossy().into_owned(),
        "run".into(),
        "--peer-listen".into(),
        listen.clone(),
    ];
    let agent = env::var("SSH_AUTH_SOCK").ok().filter(|a| !a.is_empty());
    let text = unit_text(manager, &arguments, agent.as_deref());
    let changed = existing.as_deref() != Some(text.as_str());
    if changed {
        fs::create_dir_all(unit.parent().context("unit path has no parent")?)?;
        fs::write(&unit, &text)?;
    }
    let mut linger_value = Value::Null;
    match manager {
        Manager::Systemd => {
            if changed {
                systemctl(&["daemon-reload"])?;
            }
            if no_start {
                systemctl(&["enable", SYSTEMD_UNIT])?;
            } else {
                systemctl(&["enable", "--now", SYSTEMD_UNIT])?;
                if changed && existing.is_some() {
                    systemctl(&["restart", SYSTEMD_UNIT])?;
                }
            }
            linger_value = json!(tool("loginctl", &["enable-linger"]).0);
        }
        Manager::Launchd if !no_start => {
            let plist = unit.to_string_lossy().into_owned();
            if changed && existing.is_some() {
                let _ = tool("launchctl", &["bootout", &launchd_target()]);
            }
            if changed {
                required("launchctl", &["bootstrap", &gui(), &plist])?;
            } else {
                // Already loaded unless it was booted out since.
                let _ = tool("launchctl", &["bootstrap", &gui(), &plist]);
            }
        }
        Manager::Launchd => {}
    }
    let mut started = false;
    if !no_start {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if listening(&state).await {
                started = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    Ok(json!({
        "service": manager.name(),
        "unit": unit,
        "state": state,
        "peer_listen": listen,
        "linger": linger_value,
        "started": started,
    }))
}

/// `uninstall`: stops and disables the service and removes its unit. The
/// state directory and lingering stay.
pub(crate) fn uninstall() -> anyhow::Result<Value> {
    let manager = Manager::find().context("no supported service manager")?;
    let unit = manager.unit()?;
    let removed = unit.exists();
    if removed {
        match manager {
            Manager::Systemd => systemctl(&["disable", "--now", SYSTEMD_UNIT])?,
            Manager::Launchd => {
                let _ = tool("launchctl", &["bootout", &launchd_target()]);
            }
        }
        fs::remove_file(&unit)?;
    }
    Ok(json!({"service": manager.name(), "unit": unit, "removed": removed}))
}

/// The `service` object of `status`.
pub(crate) fn status() -> Value {
    let Some(manager) = Manager::find() else {
        return json!({"manager": null, "unit": null, "installed": false, "active": false, "linger": null});
    };
    let unit = manager.unit().ok();
    let installed = unit.as_deref().is_some_and(Path::exists);
    let active = installed && active(manager);
    let linger = match manager {
        Manager::Systemd => Some(linger()),
        Manager::Launchd => None,
    };
    json!({
        "manager": manager.name(),
        "unit": unit,
        "installed": installed,
        "active": active,
        "linger": linger,
    })
}

/// Attention items 8 and 9, which only the CLI can see, for a daemon that
/// answered.
pub(crate) fn attention(service: &Value) -> Vec<Value> {
    let mut items = Vec::new();
    if service["installed"] == false {
        items.push(json!({
            "kind": "service_not_installed",
            "subject": "service",
            "detail": "the host daemon runs outside a user service and will not start at login",
            "command": "peerspan install",
        }));
    }
    if service["manager"] == "systemd" && service["installed"] == true && service["linger"] == false
    {
        items.push(json!({
            "kind": "linger_disabled",
            "subject": "service",
            "detail": "systemd lingering is disabled, so the service stops when you log out",
            "command": "loginctl enable-linger",
        }));
    }
    items
}
