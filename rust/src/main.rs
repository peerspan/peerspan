mod access;
mod addressing;
mod admin;
mod builtin_discovery;
mod capability_cli;
mod cli;
mod conversation_cli;
mod decentralized_action_cli;
mod decentralized_admin_cli;
mod decentralized_cli;
mod decentralized_groups_cli;
mod decentralized_link_cli;
mod decentralized_onboarding_cli;
mod decentralized_policy_cli;
mod decentralized_root_cli;
mod decentralized_up;
mod discovery;
mod integration;
mod link_cli;
mod service;
mod sign_in_cli;
mod up;

use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use clap::FromArgMatches;
use cli::Cli;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use peerspan_host::{api, membership, model, persons, status::ATTENTION_ORDER, store::Store};
use serde_json::{Value, json};
use std::{
    env, fs,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
};

static PROGRAM: OnceLock<&'static str> = OnceLock::new();
/// When this process started, for the debug timing log.
static STARTED: OnceLock<std::time::Instant> = OnceLock::new();

/// The debug timing log's line for the whole command.
fn log_total() {
    if let Some(began) = STARTED.get() {
        let args: Vec<String> = env::args()
            .skip(1)
            .filter(|a| !a.starts_with('/'))
            .take(4)
            .collect();
        peerspan_host::timing::log("total", &args.join(" "), *began);
    }
}

/// The base name this binary was invoked as, `peerspan` or `peerspan-host`;
/// help and hints name it.
pub(crate) fn program() -> &'static str {
    PROGRAM.get().copied().unwrap_or("peerspan-host")
}

#[tokio::main]
async fn main() {
    STARTED.get_or_init(std::time::Instant::now);
    // The hidden built-in source server, started by the daemon.
    let raw: Vec<String> = env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if raw.get(1).map(String::as_str) == Some("builtin-source") {
        if let Err(error) = peerspan_host::gh::serve(&raw[2..]).await {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    let name = env::args_os()
        .next()
        .and_then(|arg| {
            Path::new(&arg)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "peerspan-host".into());
    PROGRAM.get_or_init(|| Box::leak(name.into_boxed_str()));
    let cli = cli::command_line(program())
        .try_get_matches()
        .and_then(|matches| Cli::from_arg_matches(&matches))
        .unwrap_or_else(|e| e.exit());
    let outcome = run(cli).await;
    log_total();
    if let Err(error) = outcome {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    if cli.help_advanced {
        print!("{}", cli::advanced_help(program()));
        return Ok(());
    }
    let Some(mut command) = cli.command else {
        cli::command_line(program()).print_help()?;
        return Ok(());
    };
    if let cli::Command::Help { topic } = &command {
        return help(topic);
    }
    if let cli::Command::Up(args) = command {
        return up::run(args, cli.state).await;
    }
    if let cli::Command::Link(args) = command {
        return link_cli::run(args, cli.state).await;
    }
    if let cli::Command::Network(cli::NetworkCommand::Repair(args)) = command {
        return link_cli::repair(args, cli.state).await;
    }
    if let cli::Command::Network(cli::NetworkCommand::EnableLinking { network, root_key }) = command
    {
        return link_cli::enable(network, root_key, cli.state).await;
    }
    if decentralized_onboarding_cli::run(&command, cli.state.as_deref()).await? {
        return Ok(());
    }
    command.resolve_expiries()?;
    if matches!(
        &command,
        cli::Command::Session(
            cli::SessionCommand::Setup { .. }
                | cli::SessionCommand::Start { .. }
                | cli::SessionCommand::Doctor { .. }
                | cli::SessionCommand::Pending { .. }
        )
    ) {
        let cli::Command::Session(operation) = command else {
            unreachable!()
        };
        return integration::run(operation, cli.state).await;
    }
    if let cli::Command::Attach { .. } = command {
        return integration::attach(command, cli.state).await;
    }
    if let cli::Command::Uninstall = command {
        println!("{}", serde_json::to_string_pretty(&service::uninstall()?)?);
        return Ok(());
    }
    if let cli::Command::Install {
        state,
        peer_listen,
        no_start,
    } = command
    {
        let directory = match state.or(cli.state) {
            Some(directory) => directory,
            None => default_directory()?,
        };
        let value = service::install(&directory, peer_listen, no_start).await?;
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let directory = match cli.state {
        Some(directory) => directory,
        None => default_directory()?,
    };
    if let cli::Command::Status { json } = command {
        return status(&directory, json).await;
    }
    if conversation_cli::handles(&command) {
        return conversation_cli::run(command, &directory.join("admin.sock")).await;
    }
    if let Some(network) = command.network_mut()
        && network.is_none()
    {
        *network = Some(only_network(&directory.join("admin.sock")).await?);
    }
    if let cli::Command::Agents {
        network,
        refresh,
        json,
    } = &command
    {
        return addressing::agents(
            &directory.join("admin.sock"),
            cli::resolved(network),
            *refresh,
            *json,
        )
        .await;
    }
    // this binary currently either starts a host daemon or a local admin client
    // the daemon serves admin requests, peer-listeners etc
    if let cli::Command::Run {
        bootstrap_listen,
        transport_config,
        peer_listen,
        advertise,
        coordination_interval,
        person_agent,
        artifact_quota,
        person_key_file,
    } = command
    {
        let person_agent = person_agent.or_else(|| {
            env::var_os("SSH_AUTH_SOCK")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        });
        let person_key_file = person_key_file.or_else(persons::generated_key_path);
        return run_daemon(
            directory,
            ListenerOptions {
                bootstrap_listen,
                transport_config,
                peer_listen,
                advertise,
            },
            coordination_interval,
            person_agent,
            person_key_file,
            artifact_quota,
        )
        .await;
    }
    let value = dispatch(command, &directory).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    if value.get("creation_id").is_some() && value["committed"] == false {
        bail!("network creation requires review or signing repair");
    }
    Ok(())
}

/// Runs a command through the local daemon and returns what it prints.
async fn dispatch(command: cli::Command, directory: &Path) -> anyhow::Result<Value> {
    let socket = directory.join("admin.sock");
    if let cli::Command::Task(cli::TaskCommand::To(args)) = command {
        return addressing::task_to(&socket, args).await;
    }
    if let Some(value) = artifact_command(&command, &socket).await? {
        return Ok(value);
    }
    if let cli::Command::Access(access) = &command
        && let Some(value) = access::command(access, &socket).await?
    {
        return Ok(value);
    }
    if let Some(value) = capability_cli::command(&command, directory).await? {
        return Ok(value);
    }
    if let Some(value) = access::top_command(&command, &socket).await? {
        return Ok(value);
    }
    if let Some(value) = decentralized_admin_cli::command(&command, &socket).await? {
        return Ok(value);
    }
    if let Some(value) = person_command(&command, directory).await? {
        return Ok(value);
    }
    if let Some(value) = decentralized_root_cli::command(&command, &socket).await? {
        return Ok(value);
    }
    if let Some(value) = decentralized_groups_cli::command(&command, &socket).await? {
        return Ok(value);
    }
    if let Some(value) = admin::command(&command, &socket).await? {
        return Ok(value);
    }
    let request = command.request().expect("local control command");
    tokio::time::timeout(
        LOCAL_TIMEOUT,
        call(socket, request.method, request.path, request.body),
    )
    .await
    .context("local host daemon request timed out")?
}

/// `help`, `help advanced`, or `help COMMAND...`, which prints that
/// command's own help.
fn help(topic: &[String]) -> anyhow::Result<()> {
    match topic {
        [] => cli::command_line(program()).print_help()?,
        [advanced] if advanced == "advanced" => print!("{}", cli::advanced_help(program())),
        path => {
            let args = std::iter::once(program())
                .chain(path.iter().map(String::as_str))
                .chain(["--help"]);
            if let Err(e) = cli::command_line(program()).try_get_matches_from(args) {
                e.exit()
            }
        }
    }
    Ok(())
}

/// The one network this host is in, for a command that omits it. Never
/// chosen by name.
async fn only_network(socket: &Path) -> anyhow::Result<String> {
    let networks = admin::Local(socket).get("/v2/networks".into()).await?;
    let networks = networks.as_array().context("invalid daemon response")?;
    match networks.as_slice() {
        [] => bail!("not a member of any network"),
        [one] => Ok(one["id"].as_str().unwrap_or_default().to_owned()),
        many => bail!(
            "this host is in several networks; choose one with --network: {}",
            many.iter()
                .map(|n| format!(
                    "{} ({})",
                    n["id"].as_str().unwrap_or_default(),
                    n["name"].as_str().unwrap_or_default()
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The bound on a local daemon request. Requests may submit to a coordinator,
/// sync, or refresh the directory first, so this matches the daemon's own
/// 65-second write bound on the admin socket.
pub(crate) const LOCAL_TIMEOUT: Duration = Duration::from_secs(65);

/// `status`: exits 0 when nothing needs attention, 1 when something does,
/// and 2 when the daemon cannot be reached.
async fn status(directory: &Path, json: bool) -> anyhow::Result<()> {
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        call(
            directory.join("admin.sock"),
            Method::GET,
            "/v2/status".into(),
            None,
        ),
    )
    .await;
    let service = service::status();
    let mut value = match result {
        Ok(Ok(value)) => value,
        Ok(Err(e)) if e.downcast_ref::<integration::DaemonError>().is_some() => return Err(e),
        // Not listening, or not answering.
        Ok(Err(_)) | Err(_) => {
            let state = fs::canonicalize(directory).or_else(|_| std::path::absolute(directory))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"daemon": "not running", "state": state, "service": service})
                    )?
                );
            } else {
                println!(
                    "The host daemon is not running for state {}; start it with: {} run",
                    state.display(),
                    program()
                );
            }
            exit(2);
        }
    };
    // Items 8 and 9 come from the CLI; all kinds are then ordered together.
    if let Some(items) = value["attention"].as_array_mut() {
        items.extend(service::attention(&service));
        let rank = |item: &Value| {
            let kind = item["kind"].as_str().unwrap_or_default();
            ATTENTION_ORDER
                .iter()
                .position(|k| *k == kind)
                .unwrap_or(ATTENTION_ORDER.len())
        };
        items.sort_by(|a, b| {
            rank(a)
                .cmp(&rank(b))
                .then_with(|| a["subject"].as_str().cmp(&b["subject"].as_str()))
        });
    }
    value["service"] = service;
    if json {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        print!("{}", summary(&value));
    }
    if value["attention"].as_array().is_some_and(|a| !a.is_empty()) {
        exit(1);
    }
    Ok(())
}
fn exit(code: i32) -> ! {
    use std::io::Write;
    log_total();
    let _ = std::io::stdout().flush();
    std::process::exit(code)
}

/// The readable `status` layout; not a shared format.
fn summary(value: &Value) -> String {
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    };
    let mut out = format!(
        "Host {} (version {})\n",
        text(&value["host_id"]),
        text(&value["version"])
    );
    let networks = value["networks"].as_array().cloned().unwrap_or_default();
    if networks.is_empty() {
        out += "Networks: none\n";
    } else {
        out += "Networks:\n";
    }
    for n in &networks {
        if n["mode"] == "decentralized" {
            out += &format!(
                "  {} {}: authority {}, deadline {}, provider {} ({})\n",
                text(&n["id"]),
                text(&n["name"]),
                text(&n["authority"]["state"]),
                text(&n["authority"]["not_after"]),
                text(&n["provider"]["kind"]),
                text(&n["provider_state"]["state"])
            );
            continue;
        }
        out += &format!(
            "  {} {}: {} members, coordinator {}, last sync {}\n",
            text(&n["id"]),
            text(&n["name"]),
            text(&n["members"]),
            text(&n["coordinator"]),
            text(&n["last_sync_at"]),
        );
        if !n["person"].is_null() {
            out += &format!(
                "    person {} ({}), policy version {} valid until {}, {} deliveries pending\n",
                text(&n["person"]["label"]),
                text(&n["person"]["id"]),
                text(&n["policy"]["version"]),
                text(&n["policy"]["valid_until"]),
                text(&n["policy_deliveries_pending"]),
            );
        }
    }
    let agents = value["agents"].as_array().cloned().unwrap_or_default();
    out += if agents.is_empty() {
        "Agents: none\n"
    } else {
        "Agents:\n"
    };
    for a in &agents {
        out += &format!("  {} ({})\n", text(&a["name"]), text(&a["id"]));
        for s in a["sessions"].as_array().into_iter().flatten() {
            out += &format!(
                "    session {} {}: {}, expires {}{}\n",
                text(&s["id"]),
                text(&s["integration"]),
                text(&s["connection"]),
                text(&s["expires_at"]),
                if s["renewable"] == true {
                    " (renewable)"
                } else {
                    ""
                },
            );
        }
    }
    out += &format!(
        "Blocks: {}\nArtifacts: {} stored, {} pending of {} bytes\n",
        text(&value["blocks"]),
        text(&value["artifacts"]["stored_bytes"]),
        text(&value["artifacts"]["pending_bytes"]),
        text(&value["artifacts"]["quota"]),
    );
    let service = &value["service"];
    out += &match service["manager"].as_str() {
        None => "Service: no supported service manager\n".into(),
        Some(manager) if service["installed"] == true => format!(
            "Service: {manager} unit {}, {}{}\n",
            text(&service["unit"]),
            if service["active"] == true {
                "active"
            } else {
                "inactive"
            },
            if service["linger"] == false {
                ", lingering disabled"
            } else {
                ""
            },
        ),
        Some(manager) => format!("Service: not installed ({manager})\n"),
    };
    let attention = value["attention"].as_array().cloned().unwrap_or_default();
    if attention.is_empty() {
        out += "Nothing needs attention.\n";
    } else {
        out += "Needs attention:\n";
    }
    for item in &attention {
        out += &format!(
            "  {} {}: {}\n",
            text(&item["kind"]),
            text(&item["subject"]),
            text(&item["detail"]),
        );
        if let Some(command) = item["command"].as_str().filter(|c| !c.is_empty()) {
            out += &format!("    run: {command}\n");
        }
    }
    out
}

/// Commands that sign with a person key. The key stays with the CLI (an
/// ssh-agent identity or a key file); the daemon only receives the signed
/// statement. `person show` needs no daemon at all.
async fn person_command(command: &cli::Command, directory: &Path) -> anyhow::Result<Option<Value>> {
    use cli::{Command, NetworkCommand, PersonCommand, encoded};
    let socket = directory.join("admin.sock");
    let signer = |path: &Option<PathBuf>| {
        persons::PersonSigner::open(path.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))
    };
    let at = || peerspan_host::clock::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let local = |method: Method, path: String, body: Option<Value>| {
        let socket = socket.clone();
        async move {
            tokio::time::timeout(LOCAL_TIMEOUT, call(socket, method, path, body))
                .await
                .context("local host daemon request timed out")?
        }
    };
    let value = match command {
        Command::Person(PersonCommand::Show { person_key }) => {
            let signer = signer(person_key)?;
            let key = signer.public_key();
            json!({
                "person_id": persons::person_id(&key),
                "public_key": signer.public_key_b64(),
                "ssh_public_key": persons::ssh_public_line(&key),
            })
        }
        Command::Network(NetworkCommand::Create {
            name_arg,
            name,
            member,
            coordinator,
            coordinator_key,
            person_key,
            no_person,
            trusted,
            untrusted,
        }) => {
            let name = match (name_arg, name) {
                (Some(_), Some(_)) => bail!("give the network name once: as NAME or with --name"),
                (Some(name), None) | (None, Some(name)) => name.clone(),
                (None, None) => bail!("network create needs a NAME"),
            };
            let member = match member {
                Some(label) => label.clone(),
                None => login_name().context("cannot determine the login name; give --as LABEL")?,
            };
            if coordinator.is_some() || coordinator_key.is_some() {
                bail!(
                    "coordinator-based creation is no longer supported; create locally without coordinator flags"
                );
            }
            if *no_person {
                bail!("local genesis requires an original-person owner; omit --no-person");
            }
            let choice = choose_key(person_key)?;
            let mut value =
                decentralized_cli::create(&admin::Local(&socket), &name, &member, &choice).await?;
            // Only a committed creation returns the network view.
            if value["mode"] == "decentralized"
                && let Some(id) = value["id"].as_str().map(str::to_owned)
            {
                // The creation key signs the trust change: an explicit file,
                // else the configured owner key or the agent identity.
                let path = choice.path.clone();
                capability_cli::dec_trust_outcome(
                    &mut value,
                    &socket,
                    &id,
                    path.as_deref(),
                    *trusted,
                    *untrusted,
                    true,
                )
                .await;
            }
            value
        }
        Command::Network(NetworkCommand::Join {
            token,
            invitation: _,
            descriptor,
            person_key,
            no_person,
            trusted,
            untrusted,
        }) => {
            let choice = match no_person {
                true => None,
                false => Some(choose_key(person_key)?),
            };
            let mut body = match (token, descriptor) {
                (Some(token), _) => json!({"token": token}),
                (None, descriptor) => json!({"descriptor": descriptor}),
            };
            let network = token.as_deref().and_then(token_network).or_else(|| {
                descriptor
                    .as_deref()
                    .and_then(|d| persons::Descriptor::decode(d).ok())
                    .map(|d| d.network_id)
            });
            if let Some(choice) = &choice {
                let signer = &choice.signer;
                body["person_public_key"] = json!(signer.public_key_b64());
                // Sign the binding before joining: the token or descriptor names
                // the network, and the daemon names this host. If either is
                // unavailable, the daemon reports the missing binding.
                if let Some(network) = &network
                    && let Ok(host) = local(Method::GET, "/v1/host".into(), None).await
                    && let Some(key) = host["public_key"].as_str()
                {
                    let bound = if token.as_deref().is_some_and(|t| {
                        t.trim()
                            .starts_with(peerspan_host::link_runtime::invite::PREFIX)
                    }) {
                        let people = local(
                            Method::GET,
                            format!("/v1/networks/{}/persons", encoded(network)),
                            None,
                        )
                        .await;
                        match people {
                            Ok(people) => {
                                let people = people
                                    .as_array()
                                    .context("invalid local persons response")?;
                                let existing = people.iter().find(|person| {
                                    person["hosts"].as_array().is_some_and(|hosts| {
                                        hosts.iter().any(|id| id == &host["id"])
                                    })
                                });
                                if let Some(person) = existing {
                                    anyhow::ensure!(
                                        person["public_key"] == signer.public_key_b64(),
                                        "this host is already bound to a different person; use its existing person identity"
                                    );
                                }
                                existing.is_some()
                            }
                            Err(error)
                                if error
                                    .downcast_ref::<integration::DaemonError>()
                                    .is_some_and(|e| e.status == 404) =>
                            {
                                false
                            }
                            Err(error) => return Err(error),
                        }
                    } else {
                        false
                    };
                    if !bound
                        && let Ok(binding) = persons::HostBinding::sign(signer, network, key, &at())
                    {
                        body["binding"] = json!(binding);
                    }
                }
            }
            let mut value = local(Method::POST, "/v1/networks/join".into(), Some(body)).await?;
            match &choice {
                Some(choice) => {
                    let label = token
                        .as_deref()
                        .and_then(token_member)
                        .or_else(login_name)
                        .unwrap_or_default();
                    choice.save(&label)?;
                    let member_token = token
                        .as_deref()
                        .is_some_and(|t| t.trim().starts_with(persons::MEMBER_TOKEN_PREFIX));
                    if value["person"].is_null() {
                        value["person"] = skipped("no person key reached the daemon".into(), None);
                    }
                    choice.describe(&mut value, member_token);
                    let bound = value["person"]["bound"] == json!(true);
                    let id = value["id"].as_str().unwrap_or_default().to_owned();
                    value["trusted"] = json!(false);
                    if bound {
                        capability_cli::trust_outcome(
                            &mut value,
                            &socket,
                            &id,
                            &choice.signer,
                            *trusted,
                            *untrusted,
                        )
                        .await;
                    }
                }
                None => {
                    let id = value["id"].as_str().unwrap_or_default().to_owned();
                    let next = match token {
                        Some(token) if token.trim().starts_with(persons::MEMBER_TOKEN_PREFIX) => {
                            format!(
                                "{} network redeem-person --token {token} --person-key PATH; then: {} --person-key PATH",
                                program(),
                                bind_next(&id)
                            )
                        }
                        _ => format!(
                            "after an administrator admits your person: {} --person-key PATH",
                            bind_next(&id)
                        ),
                    };
                    value["person"] =
                        skipped("person step disabled with --no-person".into(), Some(next));
                    value["trusted"] = json!(false);
                }
            }
            value
        }
        Command::Network(NetworkCommand::RedeemPerson { token, person_key }) => {
            let signer = signer(person_key)?;
            local(
                Method::POST,
                "/v1/networks/redeem-person".into(),
                Some(json!({"token": token, "person_public_key": signer.public_key_b64()})),
            )
            .await?
        }
        Command::Network(NetworkCommand::Bind {
            network,
            person_key,
        }) => {
            let network = cli::resolved(network);
            let provider = access::PolicySigner::for_binding(
                &admin::Local(&socket),
                network,
                person_key.as_deref(),
            )
            .await?;
            if let Some((certificate, _)) = access::PolicySigning::device(&provider) {
                let own = local(Method::GET, "/v1/host".into(), None).await?;
                let payload = json!({"network_id":network,"person_public_key":access::PolicySigning::public_key_b64(&provider),"host_public_key":own["public_key"],"bound_at":at()});
                return Ok(Some(local(Method::POST,format!("/v1/networks/{}/link-actions",encoded(network)),Some(json!({"kind":"peerspan-host-bind-v1","certificate_id":certificate,"payload_base64":STANDARD.encode(serde_json::to_vec(&payload)?)}))).await?));
            }
            let signer = signer(person_key)?;
            let host = local(Method::GET, "/v1/host".into(), None).await?;
            let key = host["public_key"]
                .as_str()
                .context("host daemon returned no public key")?;
            let binding = persons::HostBinding::sign(&signer, network, key, &at())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            local(
                Method::POST,
                format!("/v1/networks/{}/bindings", encoded(network)),
                Some(json!({"binding": binding})),
            )
            .await?
        }
        Command::Network(NetworkCommand::Unbind {
            network,
            host,
            person_key,
            ..
        }) => {
            let network = cli::resolved(network);
            let provider =
                access::PolicySigner::open(&admin::Local(&socket), network, person_key.as_deref())
                    .await?;

            let members = local(
                Method::GET,
                format!("/v1/networks/{}/members", encoded(network)),
                None,
            )
            .await?;
            let key = members
                .as_array()
                .into_iter()
                .flatten()
                .find(|m| m["host_id"].as_str() == Some(host.as_str()))
                .and_then(|m| m["public_key"].as_str())
                .context("that host is not a member of this network")?
                .to_owned();
            if let Some((certificate, _)) = access::PolicySigning::device(&provider) {
                let payload = json!({"network_id":network,"person_public_key":access::PolicySigning::public_key_b64(&provider),"host_public_key":key,"unbound_at":at()});
                return Ok(Some(local(Method::POST,format!("/v1/networks/{}/link-actions",encoded(network)),Some(json!({"kind":"peerspan-host-unbind-v1","certificate_id":certificate,"payload_base64":STANDARD.encode(serde_json::to_vec(&payload)?)}))).await?));
            }
            let signer = signer(person_key)?;
            let unbinding = persons::HostUnbinding::sign(&signer, network, &key, &at())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            local(
                Method::POST,
                format!("/v1/networks/{}/unbindings", encoded(network)),
                Some(json!({"unbinding": unbinding})),
            )
            .await?
        }
        _ => return Ok(None),
    };
    Ok(Some(value))
}

/// The person key `network create` and `join` use, and where it came from:
/// `option` (--person-key), `generated` (the generated key file), `agent`
/// (the only ssh-ed25519 identity in ssh-agent), or `new`. A new key exists
/// only in memory until `save`.
struct KeyChoice {
    signer: persons::PersonSigner,
    source: &'static str,
    path: Option<PathBuf>,
    new: Option<ed25519_dalek::SigningKey>,
}
fn choose_key(option: &Option<PathBuf>) -> anyhow::Result<KeyChoice> {
    if let Some(path) = option {
        let signer = persons::PersonSigner::open(Some(path)).map_err(|e| {
            let reason = match e {
                model::Error::Invalid(message) => message,
                other => other.to_string(),
            };
            anyhow::anyhow!("--person-key {}: {reason}", path.display())
        })?;
        return Ok(KeyChoice {
            signer,
            source: "option",
            path: Some(std::path::absolute(path)?),
            new: None,
        });
    }
    match persons::PersonSigner::discover().map_err(|e| anyhow::anyhow!("{e}"))? {
        Some((signer, Some(path))) => {
            return Ok(KeyChoice {
                signer,
                source: "generated",
                path: Some(path),
                new: None,
            });
        }
        Some((signer, None)) => {
            return Ok(KeyChoice {
                signer,
                source: "agent",
                path: None,
                new: None,
            });
        }
        None => {}
    }
    let generated = persons::generated_key_path().context(
        "cannot locate the generated person key: neither XDG_CONFIG_HOME nor HOME is set",
    )?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("random source: {e}"))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(KeyChoice {
        signer: persons::PersonSigner::File(key.clone()),
        source: "new",
        path: Some(generated),
        new: Some(key),
    })
}
impl KeyChoice {
    /// Writes a new key, once the network request has succeeded: the private
    /// key mode 0600 and the public key beside it mode 0644, in a 0700
    /// directory. It never overwrites. Other sources have nothing to save.
    fn save(&self, label: &str) -> anyhow::Result<()> {
        let (Some(key), Some(path)) = (&self.new, &self.path) else {
            return Ok(());
        };
        let result = (|| -> anyhow::Result<()> {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let comment = format!("peerspan {label}@{}", hostname());
            let dir = path.parent().context("invalid key path")?;
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            let text = persons::encode_openssh_private_key(key, &comment)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            if let Err(e) = file
                .write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
            {
                let _ = fs::remove_file(path);
                return Err(e.into());
            }
            let public = path.with_file_name("person_ed25519.pub");
            let line = format!(
                "{} {comment}\n",
                persons::ssh_public_line(&key.verifying_key().to_bytes())
            );
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&public)?
                .write_all(line.as_bytes())?;
            fs::set_permissions(&public, fs::Permissions::from_mode(0o644))?;
            Ok(())
        })();
        result.with_context(|| {
            format!(
                "the host joined, but the new person key could not be saved to {}",
                path.display()
            )
        })
    }
    /// Adds `person.key`, and the follow-up a key needs: backing up a new
    /// key, or, when a member join's person part failed with a generated or
    /// new key, copying the first machine's key.
    fn describe(&self, value: &mut Value, member_join: bool) {
        let id = value["id"].as_str().unwrap_or_default().to_owned();
        let Some(outcome) = value.get_mut("person").and_then(Value::as_object_mut) else {
            return;
        };
        let path = match self.source {
            "agent" => Value::Null,
            _ => json!(self.path.as_ref().map(|p| p.display().to_string())),
        };
        outcome.insert(
            "key".into(),
            json!({"source": self.source, "public_key": self.signer.public_key_b64(), "path": path}),
        );
        let mut next = outcome
            .get("next")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let shown = self
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        if member_join
            && outcome.get("admitted") != Some(&json!(true))
            && matches!(self.source, "new" | "generated")
        {
            next = format!(
                "to use the same person as on your first machine, copy its person_ed25519 (and .pub) to {shown}, then run {} network bind --network {id}",
                program()
            );
        }
        if self.source == "new" {
            let backup = format!(
                "back up the new person key {shown}; copy it to your other machines to use the same identity there"
            );
            next = if next.is_empty() {
                backup
            } else {
                format!("{next}; {backup}")
            };
        }
        if !next.is_empty() {
            outcome.insert("next".into(), json!(next));
        }
    }
}
/// The login name: the user name of the effective user ID, else `$USER`.
fn login_name() -> Option<String> {
    // SAFETY: getpwuid returns null or a pointer to a static record that is
    // read here before any other call could overwrite it.
    let name = unsafe {
        let entry = libc::getpwuid(libc::geteuid());
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
    name.filter(|n| !n.is_empty())
        .or_else(|| env::var("USER").ok().filter(|u| !u.is_empty()))
}
fn hostname() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname writes at most
    // that many bytes.
    let ok = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } == 0;
    if !ok {
        return String::new();
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}
/// An invite token's member label.
fn token_member(token: &str) -> Option<String> {
    if token
        .trim()
        .starts_with(peerspan_host::link_runtime::invite::PREFIX)
    {
        return peerspan_host::link_runtime::invite::decode(
            token,
            peerspan_host::link_runtime::support::now().ok()?,
            "-",
        )
        .ok()
        .map(|t| t.member);
    }
    persons::MemberInviteToken::decode(token)
        .map(|t| t.member)
        .or_else(|_| membership::InviteToken::decode(token).map(|t| t.member))
        .ok()
}
/// The network a token names, read locally so the CLI can sign a binding
/// before joining. The daemon verifies the token itself.
fn token_network(token: &str) -> Option<String> {
    if token
        .trim()
        .starts_with(peerspan_host::link_runtime::invite::PREFIX)
    {
        return peerspan_host::link_runtime::invite::decode(
            token,
            peerspan_host::link_runtime::support::now().ok()?,
            "-",
        )
        .ok()
        .map(|t| t.network.id);
    }
    persons::MemberInviteToken::decode(token)
        .map(|t| t.network_id)
        .or_else(|_| membership::InviteToken::decode(token).map(|t| t.network_id))
        .ok()
}
fn bind_next(network: &str) -> String {
    format!("{} network bind --network {network}", program())
}
fn skipped(reason: String, next: Option<String>) -> Value {
    json!({
        "person_id": Value::Null,
        "admitted": false,
        "bound": false,
        "skipped": reason,
        "next": next,
    })
}

fn default_directory() -> anyhow::Result<PathBuf> {
    if let Some(directory) = env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            bail!("XDG_STATE_HOME must be an absolute path");
        }
        return Ok(directory.join("peerspan/host"));
    }
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/state/peerspan/host"))
}

/// Removes the socket on orderly shutdown. A crash leaves a stale socket that
/// the next owner of the exclusive state lock can remove.
struct SocketCleanup(PathBuf);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct ListenerOptions {
    bootstrap_listen: Option<std::net::SocketAddr>,
    transport_config: Option<PathBuf>,
    peer_listen: Option<std::net::SocketAddr>,
    advertise: Option<std::net::SocketAddr>,
}
async fn run_daemon(
    directory: PathBuf,
    listeners: ListenerOptions,
    coordination_interval: u64,
    person_agent: Option<PathBuf>,
    person_key_file: Option<PathBuf>,
    artifact_quota: i64,
) -> anyhow::Result<()> {
    let ListenerOptions {
        bootstrap_listen,
        transport_config,
        peer_listen,
        advertise,
    } = listeners;
    let store = Arc::new(Store::open(&directory)?);
    store.set_artifact_quota(artifact_quota);
    store.set_coordination_interval(coordination_interval);
    store.set_person_agent(person_agent);
    store.set_person_key_file(person_key_file);
    let path = store.socket_path();
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                bail!("admin socket path contains a non-socket file");
            }
            fs::remove_file(&path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(&path)?;
    let _cleanup = SocketCleanup(path.clone());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let adapter_path = directory.join("adapter.sock");
    match fs::symlink_metadata(&adapter_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                bail!("adapter socket path contains a non-socket file");
            }
            fs::remove_file(&adapter_path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let adapter_listener = UnixListener::bind(&adapter_path)?;
    let _adapter_cleanup = SocketCleanup(adapter_path.clone());
    fs::set_permissions(&adapter_path, fs::Permissions::from_mode(0o600))?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    eprintln!(
        "host daemon {} listening on local control socket {}",
        store.identity().id,
        path.display()
    );
    let listening = match peer_listen {
        Some(address) => {
            let bound = peerspan_host::quic::listen(&store, address)?;
            let advertised = match advertise {
                Some(address) => address.to_string(),
                None if !bound.ip().is_unspecified() => bound.to_string(),
                None => String::new(),
            };
            eprintln!("peer listener udp {bound} (advertising {advertised:?})");
            store.set_advertised(advertised);
            true
        }
        None => false,
    };
    let (shutdown, peer_shutdown) = tokio::sync::watch::channel(false);
    let bootstrap_address = bootstrap_listen.unwrap_or_else(|| {
        std::net::SocketAddr::new(
            peer_listen
                .map(|p| p.ip())
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            0,
        )
    });
    let bootstrap = peerspan_host::decentralized::bootstrap_io::Listener::bind(
        store.clone(),
        bootstrap_address,
        transport_config,
    )
    .await?;
    eprintln!("bootstrap listener tcp {}", bootstrap.local_addr()?);
    store.enable_decentralized_runtime();
    let bootstrap = bootstrap.serve(peer_shutdown.clone());
    let mut adapter_shutdown = peer_shutdown.clone();
    let adapter = axum::serve(
        adapter_listener,
        peerspan_host::adapter::router(store.clone()),
    )
    .with_graceful_shutdown(async move {
        let _ = adapter_shutdown.changed().await;
    })
    .into_future();
    let closing = store.clone();
    let admin = axum::serve(listener, api::router(store.clone()))
        .with_graceful_shutdown(async move {
            tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
            // Held requests answer at once, so the servers drain promptly.
            closing.close_held_requests();
            let _ = shutdown.send(true);
        })
        .into_future();
    // Legacy coordinator histories remain available for explicit migration
    // and exact committed-operation recovery. Launch never starts their
    // enrollment, policy publication, signing or automatic renewal workers.
    let reply_workers =
        peerspan_host::adapter_outbound::reply_workers(store.clone(), peer_shutdown.clone());
    let retries = peerspan_host::retry::retry_worker(store.clone(), peer_shutdown.clone());
    let conversations = peerspan_host::conversations::worker(store.clone(), peer_shutdown.clone());
    let tasks = peerspan_host::task_outbound::task_worker(store.clone(), peer_shutdown.clone());
    let expiry = peerspan_host::task::expiry_worker(store.clone(), peer_shutdown.clone());
    let retention = peerspan_host::artifact::retention_worker(store.clone(), peer_shutdown.clone());
    let directory = peerspan_host::directory::worker(store.clone(), peer_shutdown.clone());
    let presence = peerspan_host::presence::worker(store.clone(), peer_shutdown.clone());
    let calls = peerspan_host::calls::worker(store.clone(), peer_shutdown.clone());
    let decentralized_state =
        peerspan_host::decentralized::state_worker(store.clone(), peer_shutdown.clone());
    let peers = async {
        if listening {
            peerspan_host::quic::serve(store, peer_shutdown).await?;
        } else {
            peerspan_host::quic::keep_without_listener(store, peer_shutdown).await;
        }
        Ok::<_, anyhow::Error>(())
    };
    use std::future::IntoFuture;
    tokio::try_join!(
        bootstrap,
        async { admin.await.map_err(anyhow::Error::from) },
        async { adapter.await.map_err(anyhow::Error::from) },
        peers,
        async {
            reply_workers.await;
            Ok(())
        },
        async {
            retries.await;
            Ok(())
        },
        async {
            conversations.await;
            Ok(())
        },
        async {
            tasks.await;
            Ok(())
        },
        async {
            expiry.await;
            Ok(())
        },
        async {
            retention.await;
            Ok(())
        },
        async {
            directory.await;
            Ok(())
        },
        async {
            presence.await;
            Ok(())
        },
        async {
            calls.await;
            Ok(())
        },
        async {
            decentralized_state.await;
            Ok(())
        },
    )?;
    Ok(())
}

/// Local responses may carry a call's result of up to 1 MiB with its
/// record.
const RESPONSE_LIMIT: usize = 32 << 20;

/// A `DELETE` on the local socket.
pub(crate) async fn delete(socket: &Path, path: String) -> anyhow::Result<Value> {
    tokio::time::timeout(
        LOCAL_TIMEOUT,
        call(socket.to_path_buf(), Method::DELETE, path, None),
    )
    .await
    .context("local host daemon request timed out")?
}

async fn call(
    socket: PathBuf,
    method: Method,
    path: String,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    if !peerspan_host::timing::enabled() {
        return call_inner(socket, method, path, body).await;
    }
    let began = std::time::Instant::now();
    let what = format!("{method} {path}");
    let out = call_inner(socket, method, path, body).await;
    peerspan_host::timing::log("cli", &what, began);
    out
}

async fn call_inner(
    socket: PathBuf,
    method: Method,
    path: String,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect to local host daemon")?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let encoded = match body {
        Some(body) => serde_json::to_vec(&body)?,
        None => Vec::new(),
    };
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "localhost")
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(encoded)))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let bytes = http_body_util::Limited::new(response.into_body(), RESPONSE_LIMIT)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read host response: {e}"))?
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes)?;
    if status.is_client_error() || status.is_server_error() {
        return Err(integration::DaemonError {
            status: status.as_u16(),
            message: value["error"]
                .as_str()
                .unwrap_or("request failed")
                .to_owned(),
            code: value["code"].as_str().unwrap_or_default().to_owned(),
        }
        .into());
    }
    Ok(value)
}

/// Artifact transfers through the local socket are bounded generously.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1800);

/// `task submit` with artifacts uploads each file first, and `task artifact`
/// saves one to a new file; both stream through the local socket.
async fn artifact_command(command: &cli::Command, socket: &Path) -> anyhow::Result<Option<Value>> {
    use cli::{Command, TaskCommand};
    match command {
        Command::Task(TaskCommand::Submit {
            artifacts,
            artifact_types,
            ..
        }) if !artifacts.is_empty() || !artifact_types.is_empty() => {
            if artifact_types.len() > artifacts.len() {
                bail!("more --artifact-type values than --artifact files");
            }
            let mut entries = Vec::new();
            for (index, path) in artifacts.iter().enumerate() {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .with_context(|| format!("{} has no UTF-8 file name", path.display()))?
                    .to_owned();
                let media_type = artifact_types
                    .get(index)
                    .map(String::as_str)
                    .unwrap_or(peerspan_host::artifact::DEFAULT_MEDIA_TYPE);
                let entry =
                    tokio::time::timeout(TRANSFER_TIMEOUT, upload(socket, path, &name, media_type))
                        .await
                        .context("artifact upload timed out")??;
                entries.push(entry);
            }
            let request = cli::Command::Task(clone_submit(command))
                .request()
                .expect("task submit is a local request");
            let mut body = request.body.unwrap_or_default();
            body["artifacts"] = Value::Array(entries);
            let value = tokio::time::timeout(
                LOCAL_TIMEOUT,
                call(
                    socket.to_path_buf(),
                    request.method,
                    request.path,
                    Some(body),
                ),
            )
            .await
            .context("local host daemon request timed out")??;
            Ok(Some(value))
        }
        Command::Task(TaskCommand::Artifact {
            peer,
            id,
            sha256,
            out,
        }) => {
            let path = format!(
                "/v1/tasks/{}/{}/artifacts/{}",
                cli::encoded(peer),
                cli::encoded(id),
                cli::encoded(sha256)
            );
            let value = tokio::time::timeout(TRANSFER_TIMEOUT, download(socket, path, out))
                .await
                .context("artifact download timed out")??;
            Ok(Some(value))
        }
        _ => Ok(None),
    }
}
fn clone_submit(command: &cli::Command) -> cli::TaskCommand {
    let cli::Command::Task(cli::TaskCommand::Submit {
        peer,
        agent,
        input,
        deadline,
        grant,
        from_agent,
        from_session,
        task,
        delegation_depth,
        delegate_to,
        parent_sender,
        parent_task,
        ..
    }) = command
    else {
        unreachable!("not a task submission")
    };
    cli::TaskCommand::Submit {
        peer: peer.clone(),
        agent: agent.clone(),
        input: input.clone(),
        deadline: deadline.clone(),
        grant: grant.clone(),
        from_agent: from_agent.clone(),
        from_session: from_session.clone(),
        task: task.clone(),
        artifacts: Vec::new(),
        artifact_types: Vec::new(),
        delegation_depth: *delegation_depth,
        delegate_to: delegate_to.clone(),
        parent_sender: parent_sender.clone(),
        parent_task: parent_task.clone(),
    }
}

/// The daemon's JSON error for a failed response.
async fn failure(response: hyper::Response<hyper::body::Incoming>) -> anyhow::Error {
    let status = response.status();
    let bytes = http_body_util::Limited::new(response.into_body(), 1 << 20)
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    integration::DaemonError {
        status: status.as_u16(),
        message: value["error"]
            .as_str()
            .unwrap_or("request failed")
            .to_owned(),
        code: value["code"].as_str().unwrap_or_default().to_owned(),
    }
    .into()
}

/// Streams a file to `POST /v1/artifacts` and returns its manifest entry.
async fn upload(socket: &Path, path: &Path, name: &str, media_type: &str) -> anyhow::Result<Value> {
    let source = path.to_path_buf();
    let (file, len) = tokio::task::spawn_blocking(move || {
        let file = fs::File::open(&source)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            anyhow::bail!("{} is not a regular file", source.display());
        }
        Ok((file, metadata.len()))
    })
    .await??;
    let stream = UnixStream::connect(socket)
        .await
        .context("connect to local host daemon")?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/v1/artifacts?name={}&media_type={}",
            cli::encoded(name),
            cli::encoded(media_type)
        ))
        .header("Host", "localhost")
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", len)
        .body(peerspan_host::artifact::FileBody::new(file, len))?;
    let response = sender.send_request(request).await?;
    if !response.status().is_success() {
        return Err(failure(response).await);
    }
    let bytes = http_body_util::Limited::new(response.into_body(), 1 << 20)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("read host response: {e}"))?
        .to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

/// Saves an artifact to a new private file at `out`.
async fn download(socket: &Path, path: String, out: &Path) -> anyhow::Result<Value> {
    use sha2::Digest;
    let stream = UnixStream::connect(socket)
        .await
        .context("connect to local host daemon")?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("Host", "localhost")
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    if !response.status().is_success() {
        return Err(failure(response).await);
    }
    let target = out.to_path_buf();
    let mut file = Some(
        tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&target)
                .with_context(|| format!("create {}", target.display()))
        })
        .await??,
    );
    let mut body = response.into_body();
    let mut hasher = sha2::Sha256::new();
    let mut size: u64 = 0;
    let result: anyhow::Result<()> = async {
        while let Some(frame) = body.frame().await {
            let Ok(data) = frame?.into_data() else {
                continue;
            };
            hasher.update(&data);
            size += data.len() as u64;
            let mut writer = file.take().context("output closed")?;
            writer = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                writer.write_all(&data).map(|_| writer)
            })
            .await??;
            file = Some(writer);
        }
        let writer = file.take().context("output closed")?;
        tokio::task::spawn_blocking(move || writer.sync_all()).await??;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        let target = out.to_path_buf();
        let _ = tokio::task::spawn_blocking(move || fs::remove_file(target)).await;
        return Err(error);
    }
    Ok(json!({
        "path": out.display().to_string(),
        "sha256": hex::encode(hasher.finalize()),
        "size": size,
    }))
}
