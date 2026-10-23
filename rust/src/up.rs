//! Guided setup composes the existing owner-local operations. Its result tracks
//! completed stages so a partial enrollment is never mistaken for a ready agent.
use crate::{
    cli::{Command, NetworkCommand, UpArgs},
    integration, service,
};
use anyhow::{Context, bail};
use hyper::Method;
use peerspan_host::{membership, persons};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{IsTerminal, Write},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
};

struct TerminalMode {
    flags: i32,
    termios: libc::termios,
}
impl Drop for TerminalMode {
    fn drop(&mut self) {
        // SAFETY: these are the flags and terminal settings read from stdin.
        unsafe {
            libc::fcntl(0, libc::F_SETFL, self.flags);
            libc::tcsetattr(0, libc::TCSANOW, &self.termios);
        }
    }
}

async fn prompt(question: &str, fallback: &str, secret: bool) -> anyhow::Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("without a terminal, supply the missing setup choices as flags")
    }
    eprint!("{question}");
    if !fallback.is_empty() {
        eprint!(" [{fallback}]");
    }
    eprint!(": ");
    std::io::stderr().flush()?;
    // SAFETY: tcgetattr initializes the supplied record; duplicate stdin is
    // owned below, and the guard restores its shared flags on every exit.
    let (flags, termios, fd) = unsafe {
        let flags = libc::fcntl(0, libc::F_GETFL);
        let mut termios = std::mem::zeroed();
        if flags < 0 || libc::tcgetattr(0, &mut termios) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        (flags, termios, OwnedFd::from_raw_fd(fd))
    };
    let _restore = TerminalMode { flags, termios };
    // SAFETY: the descriptor remains valid for the lifetime of the guard.
    unsafe {
        if libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if secret {
            let mut quiet = termios;
            quiet.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(0, libc::TCSANOW, &quiet) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    let input = tokio::io::unix::AsyncFd::new(fd)?;
    let mut line = Vec::new();
    loop {
        let mut ready = input.readable().await?;
        let read = ready.try_io(|fd| {
            let mut byte = [0u8; 1];
            // SAFETY: byte is a writable one-byte buffer and fd is live.
            let n = unsafe { libc::read(fd.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok((n, byte[0]))
        });
        let (n, byte) = match read {
            Ok(r) => r?,
            Err(_) => continue,
        };
        if n == 0 {
            bail!("setup input ended; completed stages were kept")
        }
        if byte == b'\n' {
            break;
        }
        line.push(byte);
        if line.len() > 16384 {
            bail!("setup answer is too long")
        }
    }
    if secret {
        eprintln!()
    }
    let line = String::from_utf8(line)?.trim().to_owned();
    let line = if line.is_empty() {
        fallback.to_owned()
    } else {
        line
    };
    if line.is_empty() {
        bail!("a setup choice is required; run up again to continue")
    }
    Ok(line)
}

fn redact(text: &str) -> String {
    let mut text = text.to_owned();
    for prefix in [
        "peerspan-member-invite-v1.",
        "peerspan-invite-v1.",
        "token_",
        "instance_",
    ] {
        let mut offset = 0;
        while let Some(start) = text[offset..].find(prefix).map(|n| n + offset) {
            let end = start
                + text[start..]
                    .bytes()
                    .take_while(|c| c.is_ascii_alphanumeric() || b"_-.".contains(c))
                    .count();
            if end <= start + prefix.len() {
                offset = start + prefix.len();
                continue;
            }
            text.replace_range(start..end, "[redacted]");
            offset = start + 10;
        }
    }
    text
}

struct Setup {
    result: Value,
    stage: usize,
}
impl Setup {
    fn new() -> Self {
        Self {
            result: json!({"setup":{"state":"incomplete","stages": (["preflight","service","membership","trust","attachment"].map(|stage|json!({"stage":stage,"state":"pending"})))},"service":null,"network":null,"attachment":null,"attention":[],"next":"peerspan up"}),
            stage: 0,
        }
    }
    fn done(&mut self, reused: bool) {
        let value = if reused { "reused" } else { "completed" };
        self.result["setup"]["stages"][self.stage]["state"] = json!(value);
        eprintln!(
            "{}: {value}",
            self.result["setup"]["stages"][self.stage]["stage"]
                .as_str()
                .unwrap_or_default()
        );
        self.stage += 1;
    }
    fn fail(&mut self, error: &str) {
        let stage = self.stage.min(4);
        self.result["setup"]["state"] = json!("incomplete");
        self.result["setup"]["stages"][stage]["state"] = json!("failed");
        let name = self.result["setup"]["stages"][stage]["stage"].clone();
        self.result["attention"]
            .as_array_mut()
            .unwrap()
            .push(json!({"stage":name,"detail":redact(error)}));
    }

    async fn prepare(
        &mut self,
        args: &mut UpArgs,
        state: Option<PathBuf>,
    ) -> anyhow::Result<(integration::PreparedAttachment, PathBuf)> {
        if !cfg!(target_os = "linux") {
            bail!("guided up currently supports validated Linux installs")
        }
        if args.no_start && !args.harness_args.is_empty() {
            bail!("harness arguments require a launch; omit --no-start")
        }
        if args.join.is_some() && (args.person.is_some() || args.coordinator.is_some()) {
            bail!("--as and coordinator flags are for creation; joining uses its invite")
        }
        if let Some(name) = &args.create {
            membership::label(name)?;
        }
        if let Some(label) = &args.person {
            membership::label(label)?;
        }
        if let Some(address) = &args.coordinator {
            membership::split_host_port(address)?;
            membership::public_key(
                args.coordinator_key
                    .as_deref()
                    .context("give both coordinator flags")?,
            )?;
        }
        if args.calls && args.no_calls || args.no_calls && args.max_calls_per_hour.is_some() {
            bail!("invalid capability call flags; see peerspan up --help")
        }
        if let Some(n) = &args.max_calls_per_hour {
            let n = n
                .parse::<i64>()
                .context("--max-calls-per-hour must be a whole number from 1 to 10000")?;
            if !(1..=10000).contains(&n) {
                bail!("--max-calls-per-hour must be 1 to 10000")
            }
        }
        if args.expires_at.is_some() && args.expires_in.is_some() {
            bail!("--expires-at and --expires-in are mutually exclusive")
        }
        if let Some(relative) = args.expires_in.take() {
            args.expires_at = Some(integration::relative_expiry(&relative)?)
        }
        if let Some(at) = &args.expires_at
            && membership::time(at)? <= chrono::Utc::now()
        {
            bail!("use a future RFC3339 expiry")
        }
        let state = std::path::absolute(match state {
            Some(state) => state,
            None => crate::default_directory()?,
        })?;
        self.result["next"] = json!(format!(
            "peerspan --state {} up",
            quote(&state.to_string_lossy())
        ));
        let project = match &args.directory {
            Some(directory) => directory.clone(),
            None => std::env::current_dir()?,
        };
        let workspace = fs::canonicalize(&project)
            .with_context(|| format!("{} is not an existing directory", project.display()))?;
        if !workspace.is_dir() {
            bail!("--directory must be an existing project directory")
        }
        args.directory = Some(workspace.clone());
        let profile = integration::up_profile(&state, &workspace)?;
        if args.harness.as_deref() == Some("claude") {
            args.harness = Some("claude-code".into())
        }
        if args.harness.is_none() {
            args.harness = profile
                .as_ref()
                .and_then(|p| p["harness"]["id"].as_str().map(str::to_owned));
        }
        let mut harness = match &args.harness {
            Some(h) => h.clone(),
            None => prompt("Agent (claude, codex, or opencode)", "", false)
                .await
                .context("choose HARNESS, for example peerspan up claude")?,
        };
        if harness == "claude" {
            harness = "claude-code".into()
        }
        args.harness = Some(harness.clone());
        if let Some(name) = &args.name
            && !peerspan_host::directory::addressable(name)
        {
            bail!("--name must be an addressable agent name")
        }
        let mut options = integration::parse_options(args.options.clone())?;
        if let Some(p) = &profile {
            let recorded = Path::new(p["directory"].as_str().unwrap_or_default())
                .file_name()
                .and_then(|n| n.to_str());
            if p["harness"]["id"] != harness
                || args.name.as_deref().is_some_and(|n| Some(n) != recorded)
            {
                bail!(
                    "this project already has another agent or integration; use its existing attachment or explicit session commands"
                )
            }
            let stored: BTreeMap<String, String> = serde_json::from_value(p["options"].clone())?;
            for (key, value) in stored {
                if options.get(&key).is_some_and(|v| v != &value) {
                    bail!(
                        "--option {key} conflicts with this project's attachment; use its existing conversation"
                    )
                }
                options.insert(key, value);
            }
            if !args.calls && !args.no_calls {
                args.calls = p["request"]["calls"] == true;
                args.no_calls = !args.calls;
                if args.calls && args.max_calls_per_hour.is_none() {
                    args.max_calls_per_hour = p["request"]["max_calls_per_hour"]
                        .as_i64()
                        .map(|n| n.to_string());
                }
            }
        }
        for (name, question) in required_options(&harness) {
            if options.get(*name).is_none_or(String::is_empty) {
                if !std::io::stdin().is_terminal() {
                    bail!("{harness} needs --option {name}=VALUE; {question}")
                }
                options.insert((*name).into(), prompt(question, "", false).await?);
            }
        }
        args.options = options.iter().map(|(k, v)| format!("{k}={v}")).collect();
        integration::up_preflight(integration::UpPreflight {
            state: &state,
            workspace: &workspace,
            harness: &harness,
            profile: profile.as_ref(),
            integrations: args.integrations.clone(),
            runner: args.runner.clone(),
            options,
            arguments: &args.harness_args,
        })
        .await?;
        if let Some(token) = &args.join {
            invite(token, chrono::DateTime::<chrono::Utc>::MIN_UTC)?;
        }
        self.done(profile.is_some());
        let (service, reused) = service::ensure_up(&state).await?;
        self.result["service"] = service;
        self.done(reused);
        let mut networks = get(&state, "/v1/networks")
            .await?
            .as_array()
            .context("invalid network list")?
            .clone();
        if networks.len() > 1 {
            bail!(
                "guided up supports one network; found {}; use network and attach commands",
                networks
                    .iter()
                    .map(|n| format!("{} ({})", text(&n["name"]), text(&n["id"])))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        if networks.is_empty() && args.create.is_none() && args.join.is_none() {
            let choice = prompt(
                "Create a network or join with an invite (create/join)",
                "",
                false,
            )
            .await
            .context("choose --create NAME or --join TOKEN")?;
            match choice.as_str() {
                "create" => args.create = Some(prompt("Network name", "personal", false).await?),
                "join" => args.join = Some(prompt("Invite (hidden)", "", true).await?),
                _ => bail!("choose create or join"),
            }
        }
        let existing = networks.len() == 1;
        let mut outcome = None;
        if let Some(n) = networks.first() {
            if args
                .create
                .as_deref()
                .is_some_and(|v| v != text(&n["name"]))
                || args.coordinator.as_deref().is_some_and(|v| {
                    v != text(&n["coordinator_address"])
                        || args.coordinator_key.as_deref() != n["coordinator_public_key"].as_str()
                })
            {
                bail!(
                    "creation inputs conflict with the existing network; use explicit network commands"
                )
            }
            if let Some(token) = &args.join
                && invite(token, chrono::DateTime::<chrono::Utc>::MIN_UTC)?.network_id
                    != text(&n["id"])
            {
                bail!("invite names a different network; use explicit network commands")
            }
        } else {
            let (name, label, address, coordinator_key) = if let Some(token) = &args.join {
                let invite = invite(token, chrono::Utc::now())?;
                (
                    invite.network_name,
                    invite.member,
                    invite.coordinator_address,
                    invite.coordinator_public_key,
                )
            } else {
                let name = args
                    .create
                    .clone()
                    .context("choose --create NAME or --join TOKEN")?;
                let label = args
                    .person
                    .clone()
                    .or_else(crate::login_name)
                    .context("cannot determine the login name; give --as LABEL")?;
                membership::label(&name)?;
                membership::label(&label)?;
                let (address, key) = if let Some(address) = &args.coordinator {
                    (
                        address.clone(),
                        args.coordinator_key.clone().unwrap_or_default(),
                    )
                } else {
                    let info = get(&state, "/v1/host").await?;
                    if info["default_coordinator"].is_null() {
                        bail!(
                            "this build has no default coordinator; pass --coordinator and --coordinator-key"
                        )
                    }
                    (
                        text(&info["default_coordinator"]["address"]).to_owned(),
                        text(&info["default_coordinator"]["public_key"]).to_owned(),
                    )
                };
                (name, label, address, key)
            };
            eprintln!(
                "Network: {name}; person: {label}; coordinator: {address} (pinned key {coordinator_key})"
            );
            let key = crate::choose_key(&args.person_key)?;
            eprintln!("Person key: {}", key.source);
            drop(key);
            eprintln!(
                "A machine holding your person private key can sign a policy that marks itself trusted."
            );
            if args.join.is_some() {
                eprintln!(
                    "To join as the same person on another machine, make that person's existing key available through ssh-agent or the documented key-file copy."
                );
            }
            if !args.trusted && !args.untrusted {
                if std::io::stdin().is_terminal() {
                    let answer=prompt("Let this machine use your capabilities on other machines, and source tools those hosts allow? (y/N)","no",false).await?;
                    args.trusted = matches!(answer.to_lowercase().as_str(), "y" | "yes");
                }
                args.untrusted = !args.trusted;
            }
            let command = if let Some(token) = &args.join {
                invite(token, chrono::Utc::now())?;
                Command::Network(NetworkCommand::Join {
                    token: Some(token.clone()),
                    descriptor: None,
                    person_key: args.person_key.clone(),
                    no_person: false,
                    trusted: args.trusted,
                    untrusted: args.untrusted,
                })
            } else {
                Command::Network(NetworkCommand::Create {
                    name_arg: args.create.clone(),
                    name: None,
                    member: args.person.clone(),
                    coordinator: args.coordinator.clone(),
                    coordinator_key: args.coordinator_key.clone(),
                    person_key: args.person_key.clone(),
                    no_person: false,
                    trusted: args.trusted,
                    untrusted: args.untrusted,
                })
            };
            let value = crate::dispatch(command, &state).await?;
            self.result["network"] = json!({"id":value["id"],"name":value["name"],"coordinator_address":value["coordinator_address"],"coordinator_public_key":value["coordinator_public_key"],"person":value["person"]});
            if let Some(error) = value["last_sync_error"].as_str() {
                self.result["next"] =
                    json!(format!("peerspan network sync {}", text(&value["id"])));
                bail!("pinned coordinator check failed: {error}")
            }
            if value["person"]["admitted"] != true || value["person"]["bound"] != true {
                self.result["next"] = value["person"]["next"].clone();
                bail!(
                    "host joined, but person identity is incomplete; {}",
                    text(&value["person"]["next"])
                )
            }
            if let Some(next) = value["person"]["next"].as_str() {
                eprintln!("{}", redact(next))
            }
            outcome = Some(value);
            networks = get(&state, "/v1/networks")
                .await?
                .as_array()
                .context("invalid network list")?
                .clone();
        }
        if networks.len() != 1 {
            bail!("membership changed during setup; inspect peerspan status before retrying")
        }
        let n = &networks[0];
        let network = text(&n["id"]);
        let mut status = get(&state, "/v1/status").await?;
        let person = status["networks"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["id"] == network)
            .map(|s| s["person"].clone())
            .unwrap_or(Value::Null);
        self.result["network"] = json!({"id":n["id"],"name":n["name"],"coordinator_address":n["coordinator_address"],"coordinator_public_key":n["coordinator_public_key"],"person":person});
        if person.is_null() {
            self.result["next"] = json!(format!("peerspan network bind --network {network}"));
            bail!(
                "this host's person is unbound; use the original person key and {}",
                text(&self.result["next"])
            )
        }
        let signer = persons::PersonSigner::open(args.person_key.as_deref())
            .context("recover the original person key before continuing")?;
        if persons::person_id(&signer.public_key()) != text(&person["id"]) {
            bail!(
                "selected person key differs from this host's bound person; recover the original key"
            )
        }
        if args
            .person
            .as_deref()
            .is_some_and(|p| Some(p) != person["label"].as_str())
        {
            bail!("--as differs from the existing bound person")
        }
        if existing {
            self.result["next"] = json!(format!("peerspan network sync {network}"));
            let synced = integration::admin(
                &state,
                Method::POST,
                format!("/v1/networks/{}/sync", crate::cli::encoded(network)),
                Some(json!({})),
            )
            .await
            .context("pinned coordinator check failed")?;
            if let Some(error) = synced["last_sync_error"].as_str() {
                bail!("pinned coordinator check failed: {error}")
            }
            self.result["network"]["coordinator_address"] = synced["coordinator_address"].clone();
            self.result["network"]["coordinator_public_key"] =
                synced["coordinator_public_key"].clone();
            status = get(&state, "/v1/status").await?;
            let current = status["networks"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|n| n["id"] == network && n["person"]["id"] == person["id"]);
            if current.is_none() {
                bail!(
                    "person binding changed during coordination; inspect peerspan status before retrying"
                )
            }
        }
        eprintln!(
            "Network: {} ({network}); person: {}",
            text(&n["name"]),
            text(&person["id"])
        );
        self.done(existing);
        self.result["next"] = json!(format!(
            "peerspan --state {} up",
            quote(&state.to_string_lossy())
        ));
        if existing && (args.trusted || args.untrusted) {
            let command = if args.trusted {
                Command::Trust {
                    host: None,
                    network: Some(network.into()),
                    person_key: args.person_key.clone(),
                }
            } else {
                Command::Untrust {
                    host: text(&status["host_id"]).into(),
                    network: Some(network.into()),
                    person_key: args.person_key.clone(),
                }
            };
            self.result["next"] = json!(format!(
                "peerspan {} --network {network}",
                if args.trusted { "trust" } else { "untrust" }
            ));
            crate::dispatch(command, &state).await?;
        }
        if let Some(outcome) = &outcome
            && !outcome["trusted_error"].is_null()
        {
            self.result["next"] = json!(format!("peerspan trust --network {network}"));
            bail!("requested trust failed: {}", outcome["trusted_error"])
        }
        self.done(existing && !args.trusted && !args.untrusted);
        self.result["next"] = if let Some(p) = &profile {
            json!(format!(
                "peerspan session doctor --directory {}",
                quote(text(&p["directory"]))
            ))
        } else {
            json!(format!(
                "peerspan --state {} up",
                quote(&state.to_string_lossy())
            ))
        };
        let policy = match get(
            &state,
            &format!("/v1/networks/{}/policy", crate::cli::encoded(network)),
        )
        .await
        {
            Ok(p) => p,
            Err(e)
                if e.downcast_ref::<integration::DaemonError>()
                    .is_some_and(|e| e.status == 404) =>
            {
                Value::Null
            }
            Err(e) => return Err(e),
        };
        self.result["network"]["access"] = policy;
        self.result["attention"] = status["attention"].clone();
        if !args.calls && !args.no_calls {
            if std::io::stdin().is_terminal() {
                let answer=prompt("Let this agent call capabilities shared with you, and yours on your other trusted machines? (y/N)","no",false).await?;
                args.calls = matches!(answer.to_lowercase().as_str(), "y" | "yes");
            }
            args.no_calls = !args.calls;
        }
        let mut command = Command::Attach {
            harness,
            name: args.name.clone(),
            directory: Some(workspace),
            expires_at: args.expires_at.clone(),
            expires_in: None,
            max_sends_per_hour: args.max_sends_per_hour,
            calls: args.calls,
            no_calls: args.no_calls,
            max_calls_per_hour: args.max_calls_per_hour.clone(),
            options: args.options.clone(),
            integrations: args.integrations.clone(),
            runner: args.runner.clone(),
            no_start: args.no_start,
            harness_args: args.harness_args.clone(),
        };
        command.resolve_expiries()?;
        let prepared = integration::prepare_attach(command, Some(state.clone())).await?;
        self.result["attachment"] = prepared.value.clone();
        self.result["next"] = json!(format!(
            "peerspan session start --directory '{}'",
            prepared.directory.to_string_lossy().replace('\'', "'\\''")
        ));
        self.done(prepared.value["reused"] == true);
        self.result["setup"]["state"] = json!("prepared");
        Ok((prepared, state))
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
async fn get(state: &Path, path: &str) -> anyhow::Result<Value> {
    integration::admin(state, Method::GET, path.into(), None).await
}
fn invite(
    token: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<membership::InviteToken> {
    if token.starts_with(persons::MEMBER_TOKEN_PREFIX) {
        Ok(persons::MemberInviteToken::decode_at(token, now)?.host())
    } else {
        Ok(membership::InviteToken::decode_at(token, now)?)
    }
}
fn required_options(harness: &str) -> &'static [(&'static str, &'static str)] {
    match harness {
        "codex" => &[
            (
                "socket",
                "Existing Codex backend socket (codex app-server daemon version)",
            ),
            (
                "thread",
                "Existing loaded conversation UUID (/status in Codex)",
            ),
        ],
        "opencode" => &[
            ("server", "Existing OpenCode loopback server URL"),
            (
                "session",
                "Existing conversation ID (opencode session list in the project)",
            ),
            ("directory", "Existing OpenCode project directory"),
            (
                "bindings",
                "Private binding directory from the installed Peerspan plugin configuration",
            ),
        ],
        _ => &[],
    }
}

pub(crate) async fn run(mut args: UpArgs, state: Option<PathBuf>) -> anyhow::Result<()> {
    let mut setup = Setup::new();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let prepared = tokio::select! {value=setup.prepare(&mut args,state)=>value,_=interrupt.recv()=>Err(anyhow::anyhow!("setup cancelled; completed stages were kept")),_=terminate.recv()=>Err(anyhow::anyhow!("setup cancelled; completed stages were kept"))};
    if let Err(error) = &prepared {
        setup.fail(&format!("{error:#}"));
    }
    let output = redact(&serde_json::to_string_pretty(&setup.result)?);
    if args.no_start {
        println!("{output}")
    } else {
        eprintln!("{output}")
    }
    let (prepared, state) = prepared.map_err(|e| anyhow::anyhow!(redact(&format!("{e:#}"))))?;
    if args.no_start {
        return Ok(());
    }
    eprintln!(
        "Prepared; starting the integration. Check peerspan status for its connection and delivery readiness."
    );
    let workspace = prepared.value["workspace"].as_str().map(PathBuf::from);
    let state = Some(state);
    let launch = tokio::select! {value=integration::start(&prepared.directory,&state,workspace,args.harness_args)=>value,_=interrupt.recv()=>Err(anyhow::anyhow!("setup cancelled; completed stages were kept")),_=terminate.recv()=>Err(anyhow::anyhow!("setup cancelled; completed stages were kept"))};
    if let Err(error) = &launch {
        setup.result["setup"]["state"] = json!("incomplete");
        setup.result["setup"]["stages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"stage":"launch","state":"failed"}));
        setup.result["attention"]
            .as_array_mut()
            .unwrap()
            .push(json!({"stage":"launch","detail":redact(&format!("{error:#}"))}));
        eprintln!("{}", redact(&serde_json::to_string_pretty(&setup.result)?));
    }
    launch.map_err(|e| anyhow::anyhow!(redact(&format!("{e:#}"))))
}
