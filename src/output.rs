//! What commands print: a readable summary by default, the full object with
//! `--json` (docs/cli-output-contract.md, OUT-1 and OUT-2).
use crate::cli::{self, Command};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};

static JSON: AtomicBool = AtomicBool::new(false);

/// Records the global `--json` flag.
pub(crate) fn set_json(on: bool) {
    JSON.store(on, Ordering::Relaxed);
}

/// Whether `--json` was given anywhere on the command line.
pub(crate) fn json() -> bool {
    JSON.load(Ordering::Relaxed)
}

/// The object as pretty JSON.
fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// `value` as `--json` prints it, or otherwise in the generic layout.
pub(crate) fn render(value: &Value) -> String {
    if json() {
        pretty(value)
    } else {
        generic(value)
    }
}

/// Prints `value` on stdout: JSON with `--json`, otherwise the generic layout.
pub(crate) fn emit(value: &Value) -> anyhow::Result<()> {
    println!("{}", render(value));
    Ok(())
}

/// Prints the result of `command`: JSON with `--json`, otherwise the
/// command's summary, or the generic layout when it has none.
pub(crate) fn emit_for(summary: &Summary, value: &Value) -> anyhow::Result<()> {
    if json() {
        println!("{}", pretty(value));
    } else {
        println!("{}", summary.render(value));
    }
    Ok(())
}

/// Text with control characters written as `\u00XX`, safe for a terminal.
pub(crate) fn safe(text: &str) -> String {
    crate::capability_cli::escaped(text)
}

fn s(value: &Value) -> String {
    safe(value.as_str().unwrap_or("-"))
}

/// A byte count as `N KB`, `N MB` or `N GB` when exact, else `N bytes`.
pub(crate) fn size(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "KB")];
    for (unit, name) in UNITS {
        if bytes >= unit && bytes.is_multiple_of(unit) {
            return format!("{} {name}", bytes / unit);
        }
    }
    format!("{bytes} bytes")
}

fn scalar(value: &Value) -> Option<String> {
    Some(match value {
        Value::Null => "none".into(),
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        Value::Number(n) => n.to_string(),
        Value::String(text) => safe(text),
        _ => return None,
    })
}

/// The generic readable layout (contract section 1.2).
pub(crate) fn generic(value: &Value) -> String {
    let mut lines = Vec::new();
    match value {
        Value::Object(_) => object(value, 0, &mut lines),
        Value::Array(items) if items.is_empty() => lines.push("none".into()),
        Value::Array(items) => list(items, 0, &mut lines),
        other => lines.push(scalar(other).unwrap_or_default()),
    }
    if lines.is_empty() {
        lines.push("none".into());
    }
    lines.join("\n")
}

fn pad(depth: usize) -> String {
    "  ".repeat(depth)
}

fn object(value: &Value, depth: usize, lines: &mut Vec<String>) {
    let Some(fields) = value.as_object() else {
        return;
    };
    for (key, field) in fields {
        let key = safe(key);
        let indent = pad(depth);
        match field {
            Value::Object(inner) if inner.is_empty() => lines.push(format!("{indent}{key}: none")),
            Value::Object(_) => {
                lines.push(format!("{indent}{key}:"));
                object(field, depth + 1, lines);
            }
            Value::Array(items) if items.iter().all(|item| scalar(item).is_some()) => {
                let joined = items.iter().filter_map(scalar).collect::<Vec<_>>();
                let joined = if joined.is_empty() {
                    "none".into()
                } else {
                    joined.join(", ")
                };
                lines.push(format!("{indent}{key}: {joined}"));
            }
            Value::Array(items) => {
                lines.push(format!("{indent}{key}:"));
                list(items, depth + 1, lines);
            }
            other => lines.push(format!(
                "{indent}{key}: {}",
                scalar(other).unwrap_or_default()
            )),
        }
    }
}

fn list(items: &[Value], depth: usize, lines: &mut Vec<String>) {
    let indent = pad(depth);
    for item in items {
        if let Some(text) = scalar(item) {
            lines.push(format!("{indent}- {text}"));
            continue;
        }
        let mut inner = Vec::new();
        match item {
            Value::Array(nested) => list(nested, depth + 1, &mut inner),
            _ => object(item, depth + 1, &mut inner),
        }
        if inner.is_empty() {
            lines.push(format!("{indent}- none"));
            continue;
        }
        // The first field shares the item's `- ` line.
        let deeper = pad(depth + 1);
        let first = inner.remove(0);
        lines.push(format!(
            "{indent}- {}",
            first.strip_prefix(&deeper).unwrap_or(&first)
        ));
        lines.extend(inner);
    }
}

/// Commands with a summary of their own (contract section 2).
pub(crate) enum Summary {
    Generic,
    NetworkCreate,
    NetworkList,
    NetworkMembers,
    Allow { principal: String, agent: String },
    Deny { principal: String },
    Block { target: String, blocked: bool },
    Send,
    TaskSubmit,
    RuntimeShow,
}

impl Summary {
    /// The summary for `command`'s result, chosen before it runs.
    pub(crate) fn of(command: &Command) -> Self {
        use cli::{AccessCommand, MessageCommand, NetworkCommand, RuntimeCommand, TaskCommand};
        match command {
            Command::Network(NetworkCommand::Create { .. }) => Self::NetworkCreate,
            Command::Network(NetworkCommand::List) => Self::NetworkList,
            Command::Network(NetworkCommand::Members { .. }) => Self::NetworkMembers,
            Command::Allow {
                principal, agent, ..
            } => Self::Allow {
                principal: principal.clone(),
                agent: agent.clone(),
            },
            Command::Deny { principal, .. } if !cli::approval_id(principal) => Self::Deny {
                principal: principal.clone(),
            },
            Command::Block { target, .. } => Self::Block {
                target: target.clone(),
                blocked: true,
            },
            Command::Unblock { target, .. } => Self::Block {
                target: target.clone(),
                blocked: false,
            },
            Command::Access(AccessCommand::Block { person, host }) => Self::Block {
                target: person.clone().or_else(|| host.clone()).unwrap_or_default(),
                blocked: true,
            },
            Command::Access(AccessCommand::Unblock { person, host }) => Self::Block {
                target: person.clone().or_else(|| host.clone()).unwrap_or_default(),
                blocked: false,
            },
            Command::Send { .. }
            | Command::Message(MessageCommand::Send { .. } | MessageCommand::Retry { .. }) => {
                Self::Send
            }
            Command::Task(TaskCommand::Submit { .. } | TaskCommand::To(_)) => Self::TaskSubmit,
            Command::Runtime(RuntimeCommand::Show { .. }) => Self::RuntimeShow,
            _ => Self::Generic,
        }
    }

    fn render(&self, value: &Value) -> String {
        let text = match self {
            Self::Generic => None,
            Self::NetworkCreate => network_create(value),
            Self::NetworkList => network_list(value),
            Self::NetworkMembers => network_members(value),
            Self::Allow { principal, agent } => allow(value, principal, agent),
            Self::Deny { principal } => deny(value, principal),
            Self::Block { target, blocked } => block(value, target, *blocked),
            Self::Send => send(value),
            Self::TaskSubmit => task_submit(value),
            Self::RuntimeShow => runtime_show(value),
        };
        // An unexpected shape still prints every field.
        text.unwrap_or_else(|| generic(value))
    }
}

fn network_create(v: &Value) -> Option<String> {
    v.get("id")?;
    Some(format!(
        "Created network {} ({}); this machine is member {}.",
        s(&v["name"]),
        s(&v["id"]),
        s(&v["member"])
    ))
}

fn network_list(v: &Value) -> Option<String> {
    let networks = v.as_array()?;
    if networks.is_empty() {
        return Some(
            "No networks. Create one with `peerspan network create NAME --as LABEL`, or join one with `peerspan join`."
                .into(),
        );
    }
    let lines: Vec<String> = networks
        .iter()
        .map(|n| {
            let mut line = format!("{}  {}  as {}", s(&n["id"]), s(&n["name"]), s(&n["member"]));
            match n["authority"]["state"].as_str() {
                Some("usable") | None => {}
                Some(state) => line.push_str(&format!("  (authority {})", safe(state))),
            }
            line
        })
        .collect();
    Some(lines.join("\n"))
}

fn network_members(v: &Value) -> Option<String> {
    let members = v["members"].as_array().or_else(|| v.as_array())?;
    if members.is_empty() {
        return Some("No members.".into());
    }
    let lines: Option<Vec<String>> = members
        .iter()
        .map(|m| {
            let label = m.get("member").or_else(|| m.get("label"))?;
            let host = match m.get("host_id").and_then(Value::as_str) {
                Some(id) => safe(id),
                None => host_id(m.get("host_public_key")?.as_str()?)?,
            };
            Some(format!("{}  {host}", s(label)))
        })
        .collect();
    Some(lines?.join("\n"))
}

/// A host ID from its Base64 public key: `host_` and the key's SHA-256.
fn host_id(key: &str) -> Option<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};
    let raw = STANDARD.decode(key).ok()?;
    Some(format!("host_{}", hex::encode(Sha256::digest(raw))))
}

fn who(principal: &str) -> String {
    match principal {
        "everyone" | "network" => "everyone".into(),
        other => safe(other),
    }
}

fn policy_line(policy: &Value) -> String {
    format!(
        "Policy version {}, valid until {}.",
        policy["version"],
        s(&policy["valid_until"])
    )
}

fn allow(v: &Value, principal: &str, agent: &str) -> Option<String> {
    let actions: Vec<&str> = v["actions"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let target = if agent == "*" {
        "all your agents".to_string()
    } else {
        format!("your agent {}", safe(agent))
    };
    let tasks = actions.contains(&"task.submit");
    let mut sentence = format!(
        "{} can now send {target} messages{}",
        who(principal),
        if tasks { " and tasks" } else { "" }
    );
    match v["max_artifact_bytes"].as_u64() {
        Some(bytes) if tasks && bytes > 0 => {
            sentence.push_str(&format!(", with files up to {}", size(bytes)))
        }
        _ if tasks => sentence.push_str(", with no files"),
        _ => {}
    }
    if actions.contains(&"task.delegate") {
        sentence.push_str(", and your agents may delegate those tasks onward");
    }
    Some(format!("{sentence}. {}", policy_line(&v["policy"])))
}

fn deny(v: &Value, principal: &str) -> Option<String> {
    let removed = v["removed"].as_u64()?;
    if removed == 0 {
        let note = s(&v["note"]);
        let stop = if note.ends_with('.') { "" } else { "." };
        return Some(format!("{note}{stop} No new policy version was signed."));
    }
    Some(format!(
        "Removed {} from {removed} rule{} of your policy. {}",
        who(principal),
        if removed == 1 { "" } else { "s" },
        policy_line(&v["policy"])
    ))
}

fn block(v: &Value, target: &str, blocked: bool) -> Option<String> {
    let verb = if blocked { "Blocked" } else { "Unblocked" };
    let subject = v["subject"].as_str().unwrap_or(target);
    let mut line = format!("{verb} {} {}", s(&v["kind"]), safe(target));
    if subject != target {
        line.push_str(&format!(" ({})", safe(subject)));
    }
    line.push('.');
    Some(line)
}

/// The target of an outbound record: its address, else agent on peer host.
fn target(v: &Value) -> String {
    match v["to"].as_str() {
        Some(to) => safe(to),
        None => format!(
            "agent {} on {}",
            s(&v["request"]["target_agent_id"]),
            s(&v["peer_host_id"])
        ),
    }
}

fn outcome(v: &Value, state: &str, what: &str, id: &str) -> String {
    let to = target(v);
    let error = v["error"].as_str().map(safe);
    match state {
        "accepted" => format!("Delivered {what} {id} to {to}."),
        "rejected" => format!(
            "{to} refused {what} {id}: {}.",
            error.unwrap_or_else(|| "no reason given".into())
        ),
        _ => {
            let mut line = format!("{what} {id} is not delivered to {to} yet");
            if let Some(at) = v["next_attempt_at"].as_str() {
                line.push_str(&format!("; the next attempt is at {}", safe(at)));
            }
            if let Some(error) = error {
                line.push_str(&format!(" (last error: {error})"));
            }
            line.push('.');
            capitalized(&line)
        }
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn send(v: &Value) -> Option<String> {
    let state = v["state"].as_str()?;
    let id = v["request"]["request_id"].as_str()?;
    Some(outcome(v, state, "message", &safe(id)))
}

fn task_submit(v: &Value) -> Option<String> {
    let state = v["submit_state"].as_str()?;
    let id = safe(v["request"]["task_id"].as_str()?);
    let mut text = outcome(v, state, "task", &id);
    if state != "rejected" {
        text.push_str(&format!(
            "\nFollow it with: peerspan task inspect --peer {} {id}",
            s(&v["peer_host_id"])
        ));
    }
    Some(text)
}

fn runtime_show(v: &Value) -> Option<String> {
    let enabled = v["enabled"].as_bool()?;
    let mut lines = vec![format!(
        "Runtime tasks: {}",
        if enabled { "enabled" } else { "disabled" }
    )];
    lines.push(format!(
        "socket: {}",
        scalar(&v["socket"]).unwrap_or_default()
    ));
    for key in ["runtime", "rule"] {
        match &v[key] {
            Value::Null => lines.push(format!("{key}: none")),
            Value::Object(_) => {
                lines.push(format!("{key}:"));
                object(&v[key], 1, &mut lines);
            }
            other => lines.push(format!("{key}: {}", scalar(other).unwrap_or_default())),
        }
    }
    Some(lines.join("\n"))
}

/// `install`'s summary (contract section 2).
pub(crate) fn install(v: &Value) -> String {
    let mut lines = vec![format!(
        "Peerspan service {} ({}): {}.",
        s(&v["unit"]),
        s(&v["service"]),
        if v["started"] == true {
            "installed and running"
        } else {
            "installed, not started"
        }
    )];
    if let Some(listen) = v["peer_listen"].as_str() {
        lines.push(format!("Peer listen address: {}", safe(listen)));
    }
    if let Some(linger) = v["linger"].as_bool() {
        lines.push(format!(
            "Lingering: {}",
            if linger {
                "enabled; the service keeps running after you log out"
            } else {
                "disabled; the service stops when you log out"
            }
        ));
    }
    lines.join("\n")
}

/// `uninstall`'s summary (contract section 2).
pub(crate) fn uninstall(v: &Value) -> String {
    if v["removed"] == true {
        format!(
            "Removed the Peerspan service {}. The state directory was kept.",
            s(&v["unit"])
        )
    } else {
        format!(
            "No Peerspan service was installed ({}). The state directory was kept.",
            s(&v["unit"])
        )
    }
}

/// `invite`'s summary: the member, expiry and introduction on its own line.
pub(crate) fn invite(v: &Value, member: &str) -> String {
    format!(
        "Invite for {} in network {}, expires {}.\nSend this introduction privately; the joiner enters it at `peerspan up --join` or `peerspan join`:\n{}",
        safe(member),
        s(&v["network_id"]),
        s(&v["expires_at"]),
        v["invitation"].as_str().unwrap_or("-")
    )
}

/// `up`'s setup report (contract section 2): stages, attention and `next`.
pub(crate) fn setup(v: &Value) -> String {
    let mut lines = vec![format!("Setup: {}", s(&v["setup"]["state"]))];
    for stage in v["setup"]["stages"].as_array().into_iter().flatten() {
        lines.push(format!("  {}: {}", s(&stage["stage"]), s(&stage["state"])));
    }
    let attention = v["attention"]
        .as_array()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if !attention.is_empty() {
        lines.push("Needs attention:".into());
        for item in attention {
            lines.push(format!("  {}: {}", s(&item["stage"]), s(&item["detail"])));
        }
    }
    if v["setup"]["state"] == "incomplete" {
        match &v["next"] {
            Value::String(next) => lines.push(format!("Next: {}", safe(next))),
            Value::Array(parts) => lines.push(format!(
                "Next: {}",
                parts.iter().map(s).collect::<Vec<_>>().join(" ")
            )),
            _ => {}
        }
    }
    lines.join("\n")
}

/// The linking request view (contract section 2, linking views).
pub(crate) fn link_view(v: &Value) -> String {
    let mut lines = vec![format!(
        "Request {} in network {}: {}",
        s(&v["request_id"]),
        s(&v["network_id"]),
        s(&v["state"])
    )];
    if let Some(mode) = v["mode"].as_str() {
        lines.push(format!("  mode: {}", safe(mode)));
    }
    if let Some(code) = v["display_code"].as_str() {
        lines.push("  reply code (send it privately to the other machine):".into());
        lines.push(code.to_owned());
    }
    if let Some(trusted) = v["trusted"].as_bool() {
        lines.push(format!(
            "  trusted for your capabilities: {}",
            if trusted { "yes" } else { "no" }
        ));
    }
    if let Some(error) = v["trusted_error"].as_str() {
        lines.push(format!("  trust not set: {}", safe(error)));
    }
    for item in v["attention"].as_array().into_iter().flatten() {
        lines.push(format!(
            "  attention: {}",
            item.as_str().map(safe).unwrap_or_else(|| generic(item))
        ));
    }
    lines.join("\n")
}

/// A list of linking request views.
pub(crate) fn link_views(items: &[Value]) -> String {
    if items.is_empty() {
        return "No linking requests.".into();
    }
    items.iter().map(link_view).collect::<Vec<_>>().join("\n\n")
}

/// The scopes bit mask as names (spec glossary, "Scope").
pub(crate) fn scopes(mask: u64) -> String {
    let names: Vec<&str> = [
        (1, "edit policy"),
        (2, "bind hosts"),
        (4, "approve devices"),
        (8, "network admin"),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, name)| name)
    .collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// A Base64 Ed25519 key as its OpenSSH `SHA256:` fingerprint.
pub(crate) fn fingerprint(key: &Value) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    key.as_str()
        .and_then(|k| STANDARD.decode(k).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(|raw| peerspan_host::persons::fingerprint(&raw))
        .unwrap_or_else(|| "-".into())
}

/// The review before "Approve/Commit this exact machine?" (section 2.1).
pub(crate) fn review(v: &Value, network_name: Option<&str>) -> String {
    let network = match network_name {
        Some(name) => format!("{} ({})", safe(name), s(&v["network_id"])),
        None => s(&v["network_id"]),
    };
    let mut lines = vec![
        format!("Review ({}):", s(&v["stage"])),
        format!("  network:     {network}"),
        format!("  person key:  {}", fingerprint(&v["person_public_key"])),
        format!("  host key:    {}", fingerprint(&v["host_public_key"])),
        format!("  device key:  {}", fingerprint(&v["device_public_key"])),
        format!(
            "  scopes:      {}",
            scopes(v["scopes"].as_u64().unwrap_or(0))
        ),
        format!("  expires:     {}", s(&v["not_after"])),
    ];
    match &v["authority_warning"] {
        Value::String(w) if !w.is_empty() && w != "-" => {
            lines.push(format!("Warning: {}", safe(w)))
        }
        _ => {}
    }
    lines.join("\n")
}
