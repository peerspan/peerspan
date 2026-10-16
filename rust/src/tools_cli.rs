//! The owner CLI for shared tools (tools contract): `tools`, `call`,
//! `read`, the tool forms of `allow` and `deny`, `trust` and `untrust`, and
//! the trust question of `join` and `network create`.
use crate::{
    access::{at, duration_of, failed, strip_view, top_principal},
    admin::Local,
    cli::{CallOptions, Command, ProfileCommand, ToolsArgs, ToolsCommand, encoded, resolved},
    integration::DaemonError,
};
use anyhow::{Context, bail};
use chrono::{TimeDelta, Utc};
use peerspan_host::{
    persons::{self, PersonSigner},
    policy::{ALL_AGENTS, Content, Policy, RESOURCE_ACTION, TOOL_ACTION, ToolRule, split_server},
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, IsTerminal, Write},
    path::Path,
    time::Duration,
};

/// Runs a tools command; None for any other command, and for `allow` and
/// `deny` without `--tools`.
pub async fn command(command: &Command, directory: &Path) -> anyhow::Result<Option<Value>> {
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    Ok(Some(match command {
        Command::Tools(args) => return tools(&local, &socket, args).await,
        Command::Call {
            target,
            tool,
            arguments,
            options,
        } => {
            let arguments: Value = match arguments {
                Some(text) => serde_json::from_str(text).context("--arguments is not JSON")?,
                None => json!({}),
            };
            if !arguments.is_object() {
                bail!("--arguments must be a JSON object");
            }
            let body =
                json!({"target": target, "kind": "tool", "name": tool, "arguments": arguments});
            return call(&local, body, options).await;
        }
        Command::Read {
            target,
            uri,
            options,
        } => {
            let body = json!({"target": target, "kind": "resource", "uri": uri});
            return call(&local, body, options).await;
        }
        Command::Allow {
            principal,
            agent,
            tools,
            yes,
            calls_per_hour,
            network,
            person_key,
            no_tasks,
            files,
            delegate,
        } if !tools.is_empty() => {
            if *no_tasks || files.is_some() || *delegate {
                bail!(
                    "--tools shares tools only; give --no-tasks, --files, and --delegate without it"
                );
            }
            let share = Share {
                principal,
                agent: agent.as_deref(),
                specs: tools,
                yes: *yes,
                calls_per_hour: calls_per_hour.unwrap_or(100),
            };
            allow_tools(&local, resolved(network), person_key.as_deref(), share).await?
        }
        Command::Deny {
            principal,
            agent,
            tools,
            network,
            person_key,
        } if !tools.is_empty() => {
            deny_tools(
                &local,
                resolved(network),
                person_key.as_deref(),
                principal,
                agent.as_deref(),
                tools,
            )
            .await?
        }
        Command::Trust {
            host,
            network,
            person_key,
        } => {
            trust(
                &local,
                resolved(network),
                person_key.as_deref(),
                host.as_deref(),
                true,
            )
            .await?
        }
        Command::Untrust {
            host,
            network,
            person_key,
        } => {
            trust(
                &local,
                resolved(network),
                person_key.as_deref(),
                Some(host),
                false,
            )
            .await?
        }
        _ => return Ok(None),
    }))
}

/// The newest stored policy of the signer's person in a network.
async fn current(
    local: &Local<'_>,
    network: &str,
    signer: &PersonSigner,
) -> anyhow::Result<Option<Policy>> {
    let me = persons::person_id(&signer.public_key());
    let path = format!(
        "/v1/networks/{}/policy?person={}",
        encoded(network),
        encoded(&me)
    );
    match local.get(path).await {
        Ok(value) => Ok(Some(serde_json::from_value(strip_view(value))?)),
        Err(e)
            if e.downcast_ref::<DaemonError>()
                .is_some_and(|d| d.status == 404) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}
/// Signs the next version of the signer's policy with `content`, valid for
/// `duration` or the current policy's duration, and submits it.
async fn sign_next(
    local: &Local<'_>,
    network: &str,
    signer: &PersonSigner,
    current: &Option<Policy>,
    content: Content,
    duration: Option<TimeDelta>,
) -> anyhow::Result<Value> {
    let duration = match (duration, current) {
        (Some(d), _) => d,
        (None, Some(c)) => duration_of(c)?,
        (None, None) => TimeDelta::days(peerspan_host::policy::DEFAULT_VALID_DAYS),
    };
    let now = Utc::now();
    let version = current.as_ref().map_or(0, |p| p.version) + 1;
    let policy = Policy::sign_v2(
        signer,
        network,
        version,
        &at(now),
        &at(now + duration),
        content,
    )
    .map_err(failed)?;
    local
        .post(
            format!("/v1/networks/{}/policy", encoded(network)),
            json!({ "policy": policy }),
        )
        .await
}

/// `trust [HOST]` and `untrust HOST`.
async fn trust(
    local: &Local<'_>,
    network: &str,
    person_key: Option<&Path>,
    host: Option<&str>,
    add: bool,
) -> anyhow::Result<Value> {
    let signer = PersonSigner::open(person_key).map_err(failed)?;
    let host = match host {
        Some(h) => h.to_owned(),
        None => local.get("/v1/host".into()).await?["id"]
            .as_str()
            .context("invalid daemon response")?
            .to_owned(),
    };
    if add {
        let me = persons::person_id(&signer.public_key());
        let members = local
            .get(format!("/v1/networks/{}/members", encoded(network)))
            .await?;
        let bound = members.as_array().into_iter().flatten().any(|m| {
            m["host_id"].as_str() == Some(host.as_str())
                && m["person_id"].as_str() == Some(me.as_str())
        });
        if !bound {
            bail!("host {host} is not bound to your person in network {network}");
        }
    }
    let current = current(local, network, &signer).await?;
    let mut content = current.as_ref().map(Policy::content).unwrap_or_default();
    let present = content.trusted_hosts.contains(&host);
    if add == present {
        return Ok(json!({"policy": current, "host": host, "trusted": add, "changed": false}));
    }
    if add {
        content.trusted_hosts.push(host.clone());
    } else {
        content.trusted_hosts.retain(|h| *h != host);
    }
    let policy = sign_next(local, network, &signer, &current, content, None).await?;
    Ok(json!({"policy": policy, "host": host, "trusted": add, "changed": true}))
}

/// After `join` or `network create` bound this host: asks whether it may
/// use tools shared from the person's other machines, unless a flag
/// answered, and adds it to the trusted hosts on yes. Returns the answer.
/// `trusted`, and `trusted_error` when signing the trust change failed, for
/// the output of `join` and `network create`.
pub async fn trust_outcome(
    value: &mut Value,
    socket: &Path,
    network: &str,
    signer: &PersonSigner,
    trusted: bool,
    untrusted: bool,
) {
    match trust_after_join(socket, network, signer, trusted, untrusted).await {
        Ok(answer) => value["trusted"] = json!(answer),
        Err(e) => {
            value["trusted"] = json!(false);
            value["trusted_error"] = json!(format!("{e:#}"));
        }
    }
}
async fn trust_after_join(
    socket: &Path,
    network: &str,
    signer: &PersonSigner,
    trusted: bool,
    untrusted: bool,
) -> anyhow::Result<bool> {
    let yes = if trusted {
        true
    } else if untrusted {
        false
    } else if std::io::stdin().is_terminal() {
        ask("Let this machine use tools shared from your other machines? [y/N] ")?
    } else {
        false
    };
    if !yes {
        eprintln!(
            "This machine is not trusted for tools shared from your other machines. Note that any host holding your person key can sign a policy that marks itself trusted; untrusted marking protects only against hosts without the key."
        );
        return Ok(false);
    }
    let local = Local(socket);
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let current = current(&local, network, signer).await?;
    let mut content = current.as_ref().map(Policy::content).unwrap_or_default();
    if !content.trusted_hosts.contains(&host) {
        content.trusted_hosts.push(host);
        sign_next(&local, network, signer, &current, content, None).await?;
    }
    Ok(true)
}

fn ask(prompt: &str) -> anyhow::Result<bool> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// One `--tools` occurrence.
struct Spec {
    server: String,
    profile: Option<String>,
    /// `readonly`, `*`, or tool names.
    scope: Vec<String>,
    actions: Vec<String>,
}
impl Spec {
    fn label(&self) -> String {
        match &self.profile {
            Some(p) => format!("{}@{p}", self.server),
            None => self.server.clone(),
        }
    }
}
/// `SERVER[@PROFILE]` (read-only tools and resources),
/// `SERVER[@PROFILE]:TOOL[,TOOL...]` (those tools), or `SERVER@PROFILE:*`
/// (every tool and resource).
fn parse_spec(text: &str) -> anyhow::Result<Spec> {
    let (server, tools) = match text.split_once(':') {
        Some((s, t)) => (s, Some(t)),
        None => (text, None),
    };
    let Some((name, profile)) = split_server(server) else {
        bail!("invalid server {server:?}: use SERVER or SERVER@PROFILE");
    };
    let both = vec![TOOL_ACTION.to_owned(), RESOURCE_ACTION.to_owned()];
    let (scope, action) = match tools {
        None => (vec!["readonly".to_owned()], both),
        Some("*") => {
            if profile.is_none() {
                bail!(
                    "SERVER:* would share write tools with the server's own credentials; use a profile, SERVER@PROFILE:*"
                );
            }
            (vec!["*".to_owned()], both)
        }
        Some(list) => {
            let names: Vec<String> = list.split(',').map(str::to_owned).collect();
            if names
                .iter()
                .any(|n| n.is_empty() || n == "*" || n == "readonly")
            {
                bail!("invalid tool list {list:?}");
            }
            (names, vec![TOOL_ACTION.to_owned()])
        }
    };
    Ok(Spec {
        server: name.to_owned(),
        profile: profile.map(str::to_owned),
        scope,
        actions: action,
    })
}

struct Share<'a> {
    principal: &'a str,
    agent: Option<&'a str>,
    specs: &'a [String],
    yes: bool,
    calls_per_hour: i64,
}

/// The server entry of a local agent in `GET /v1/tools`.
fn server_of<'a>(agent: &'a Value, server: &str) -> Option<&'a Value> {
    agent["servers"]
        .as_array()?
        .iter()
        .find(|s| s["name"].as_str() == Some(server))
}
fn names(values: &Value) -> Vec<String> {
    values
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect()
}

/// `allow PRINCIPAL --tools SPEC ...`: checks each share against this
/// host's snapshots, asks to confirm each credential's reach once, and
/// signs the next policy version.
async fn allow_tools(
    local: &Local<'_>,
    network: &str,
    person_key: Option<&Path>,
    share: Share<'_>,
) -> anyhow::Result<Value> {
    let specs: Vec<Spec> = share
        .specs
        .iter()
        .map(|s| parse_spec(s))
        .collect::<anyhow::Result<_>>()?;
    let view = local.get("/v1/tools".into()).await?;
    let agents: Vec<&Value> = view["agents"].as_array().into_iter().flatten().collect();
    let signer = PersonSigner::open(person_key).map_err(failed)?;
    let principal = top_principal(local, network, share.principal).await?;
    let all = share.agent == Some(ALL_AGENTS);
    if all && !share.yes {
        bail!(
            "--agent '*' shares the server under that name on every machine of yours, including servers whose credentials were not confirmed here; give --yes to confirm"
        );
    }
    if let Some(agent) = share.agent
        && agent != ALL_AGENTS
        && peerspan_host::policy::agent_name(agent).is_err()
    {
        bail!("invalid agent name {agent:?}");
    }
    // Each rule to set: (agent name, spec), and the local instances whose
    // reach needs confirming: (agent ID, agent name, server, profile, tools).
    let mut rules: Vec<(String, &Spec)> = Vec::new();
    let mut confirm: Vec<(String, String, &Spec, Vec<String>)> = Vec::new();
    for spec in &specs {
        let label = spec.label();
        let candidates: Vec<&Value> = match share.agent {
            Some(name) if name != ALL_AGENTS => {
                let Some(a) = agents
                    .iter()
                    .find(|a| a["agent"]["name"].as_str() == Some(name))
                else {
                    bail!("no agent {name} on this host");
                };
                vec![*a]
            }
            _ => agents
                .iter()
                .filter(|a| {
                    server_of(a, &spec.server).is_some_and(|s| s["shareable"] == json!(true))
                })
                .copied()
                .collect(),
        };
        if candidates.is_empty() && !all {
            bail!(
                "no agent on this host has a shareable server {}; run allow on the machine whose server you share",
                spec.server
            );
        }
        for a in &candidates {
            let name = a["agent"]["name"].as_str().unwrap_or_default().to_owned();
            let id = a["agent"]["id"].as_str().unwrap_or_default().to_owned();
            let Some(server) = server_of(a, &spec.server) else {
                bail!("agent {name} has no server {}", spec.server);
            };
            if server["shareable"] != json!(true) {
                bail!(
                    "server {} of agent {name} is not shareable: {}",
                    spec.server,
                    server["reason"].as_str().unwrap_or("unknown")
                );
            }
            let instance = match &spec.profile {
                None => server,
                Some(p) => server["profiles"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|x| x["name"].as_str() == Some(p.as_str()))
                    .with_context(|| format!("agent {name} has no profile {label}"))?,
            };
            let tools = &instance["tools"];
            let covered: Vec<String> = match spec.scope[0].as_str() {
                "readonly" => tools
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|t| t["read_only"] == json!(true))
                    .filter_map(|t| t["name"].as_str().map(str::to_owned))
                    .collect(),
                "*" => names(tools),
                _ => {
                    if spec.profile.is_none() {
                        let writes: Vec<&String> = spec
                            .scope
                            .iter()
                            .filter(|n| {
                                !tools.as_array().into_iter().flatten().any(|t| {
                                    t["name"].as_str() == Some(n.as_str())
                                        && t["read_only"] == json!(true)
                                })
                            })
                            .collect();
                        if !writes.is_empty() {
                            bail!(
                                "{} of {} on {name} are not read-only tools; add a profile with a narrower credential (peerspan tools profile add), or wait for approval of each call",
                                writes
                                    .iter()
                                    .map(|s| s.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                spec.server
                            );
                        }
                    }
                    spec.scope.clone()
                }
            };
            if instance["confirmed"] != json!(true) || all {
                confirm.push((id, name.clone(), spec, covered));
            }
            if !all {
                rules.push((name, spec));
            }
        }
        if all {
            rules.push((ALL_AGENTS.to_owned(), spec));
        }
    }
    // The reach is confirmed once per agent, server, and profile.
    let shown = share.principal;
    for (_, name, spec, covered) in confirm.iter().filter(|_| !all) {
        let mut text = format!(
            "{shown} can call these tools of {} on {name} with the credentials it runs with there: {}. Anything those credentials can reach through these tools, {shown} can too.",
            spec.label(),
            if covered.is_empty() {
                "(none yet)".to_owned()
            } else {
                covered.join(", ")
            }
        );
        if spec.actions.iter().any(|a| a == RESOURCE_ACTION) {
            text.push_str(&format!(" {shown} can also read every resource it offers."));
        }
        eprintln!("{text}");
    }
    if all {
        eprintln!(
            "Warning: the * rule covers servers of these names on every machine of yours, including servers whose credentials were not confirmed on this host."
        );
    }
    if !confirm.is_empty() && !share.yes {
        if !std::io::stdin().is_terminal() {
            bail!("confirm the reach above at a terminal, or give --yes");
        }
        if !ask("Share? [y/N] ")? {
            bail!("not shared");
        }
    }
    for (id, _, spec, _) in &confirm {
        if all {
            continue;
        }
        local
            .post(
                format!(
                    "/v1/agents/{}/tool-servers/{}/confirmations",
                    encoded(id),
                    encoded(&spec.server)
                ),
                json!({"profile": spec.profile}),
            )
            .await?;
    }
    let current = current(local, network, &signer).await?;
    let mut content = current.as_ref().map(Policy::content).unwrap_or_default();
    // Set semantics, once per invocation: the principal leaves every tool
    // rule of each agent and server or profile named, then each occurrence
    // joins the first remaining rule with the same settings, actions, and
    // scope, or a new rule.
    for (agent, spec) in &rules {
        let label = spec.label();
        for r in content.tool_rules.iter_mut() {
            if r.agent == *agent && r.server == label {
                r.principals.retain(|p| *p != principal);
            }
        }
    }
    let mut set = Vec::new();
    for (agent, spec) in &rules {
        let rule = ToolRule {
            agent: agent.clone(),
            server: spec.label(),
            principals: vec![principal.clone()],
            actions: spec.actions.clone(),
            scope: spec.scope.clone(),
            max_input_bytes: 65536,
            allow_disconnected: false,
            max_calls_per_hour: share.calls_per_hour,
        };
        let same_scope = |r: &ToolRule| {
            r.scope.len() == rule.scope.len() && rule.scope.iter().all(|s| r.scope.contains(s))
        };
        match content.tool_rules.iter_mut().find(|r| {
            r.agent == rule.agent
                && r.server == rule.server
                && r.actions == rule.actions
                && r.max_input_bytes == rule.max_input_bytes
                && r.allow_disconnected == rule.allow_disconnected
                && r.max_calls_per_hour == rule.max_calls_per_hour
                && same_scope(r)
        }) {
            Some(existing) => {
                if !existing.principals.contains(&principal) {
                    existing.principals.push(principal.clone());
                }
            }
            None => content.tool_rules.push(rule.clone()),
        }
        set.push(json!({"agent": rule.agent, "server": rule.server, "actions": rule.actions, "scope": rule.scope}));
    }
    content.tool_rules.retain(|r| !r.principals.is_empty());
    let policy = sign_next(
        local,
        network,
        &signer,
        &current,
        content,
        Some(TimeDelta::days(peerspan_host::policy::DEFAULT_VALID_DAYS)),
    )
    .await?;
    Ok(json!({"policy": policy, "principal": principal, "rules": set}))
}

/// `deny PRINCIPAL --tools SERVER[@PROFILE]`: removes the principal from
/// every tool rule of that server (and, for a bare server, its profiles),
/// under both actions, within the agent scope.
async fn deny_tools(
    local: &Local<'_>,
    network: &str,
    person_key: Option<&Path>,
    given: &str,
    agent: Option<&str>,
    servers: &[String],
) -> anyhow::Result<Value> {
    for s in servers {
        if split_server(s).is_none() {
            bail!("invalid server {s:?}: use SERVER or SERVER@PROFILE");
        }
    }
    let signer = PersonSigner::open(person_key).map_err(failed)?;
    let principal = top_principal(local, network, given).await?;
    let current = current(local, network, &signer).await?;
    let mut content = current.as_ref().map(Policy::content).unwrap_or_default();
    let mut removed = 0;
    let mut actions: Vec<String> = Vec::new();
    for r in content.tool_rules.iter_mut() {
        let named = servers.iter().any(|s| {
            r.server == *s
                || (!s.contains('@')
                    && r.server
                        .strip_prefix(s.as_str())
                        .is_some_and(|rest| rest.starts_with('@')))
        });
        if named && agent.is_none_or(|a| r.agent == a) && r.principals.contains(&principal) {
            r.principals.retain(|p| *p != principal);
            removed += 1;
            for a in &r.actions {
                if !actions.contains(a) {
                    actions.push(a.clone());
                }
            }
        }
    }
    actions.sort();
    if removed == 0 {
        return Ok(json!({
            "policy": current,
            "removed": 0,
            "actions": actions,
            "note": format!("no tool rule of your policy for those servers names {principal}; access through a group or everyone is unaffected, and block stops a person at once"),
        }));
    }
    content.tool_rules.retain(|r| !r.principals.is_empty());
    let policy = sign_next(local, network, &signer, &current, content, None).await?;
    Ok(json!({"policy": policy, "removed": removed, "actions": actions}))
}

/// `call` and `read`: submits, then waits up to `--wait` for a final
/// state. Exits 0 for `succeeded`, 1 for other final states, 3 if pending.
async fn call(
    local: &Local<'_>,
    mut body: Value,
    options: &CallOptions,
) -> anyhow::Result<Option<Value>> {
    let wait = match options.wait.as_deref() {
        None => Duration::from_secs(60),
        Some(text) => parse_wait(text)?,
    };
    if let Some(d) = &options.deadline {
        body["deadline"] = json!(deadline_of(d)?);
    }
    if let Some(n) = &options.network {
        body["network"] = json!(n);
    }
    let mut record = local.post("/v1/calls".into(), body).await?;
    let peer = record["peer_host_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let id = record["request"]["call_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let until = std::time::Instant::now() + wait;
    let finished = |r: &Value| {
        r["submit_state"] == "rejected"
            || r["status"]["state"]
                .as_str()
                .is_some_and(peerspan_host::calls::is_final)
    };
    while !finished(&record) && std::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(250)).await;
        record = local
            .get(format!("/v1/calls/{}/{}", encoded(&peer), encoded(&id)))
            .await?;
    }
    println!("{}", serde_json::to_string_pretty(&record)?);
    let code = if record["status"]["state"] == "succeeded" {
        0
    } else if finished(&record) {
        1
    } else {
        3
    };
    crate::exit(code)
}
/// `--deadline`: RFC3339, or a duration from now (`N`, `Ns`, or `Nm`).
fn deadline_of(text: &str) -> anyhow::Result<String> {
    if chrono::DateTime::parse_from_rfc3339(text).is_ok() {
        return Ok(text.to_owned());
    }
    let after = parse_wait(text)
        .map_err(|_| anyhow::anyhow!("--deadline is RFC3339, or N, Ns, or Nm from now"))?;
    Ok(at(Utc::now() + TimeDelta::from_std(after)?))
}
fn parse_wait(text: &str) -> anyhow::Result<Duration> {
    let invalid = || anyhow::anyhow!("--wait is seconds, or Ns or Nm, at most 15m");
    let (digits, unit) = if let Some(d) = text.strip_suffix('m') {
        (d, 60)
    } else if let Some(d) = text.strip_suffix('s') {
        (d, 1)
    } else {
        (text, 1)
    };
    let n: u64 = digits.parse().map_err(|_| invalid())?;
    let seconds = n.checked_mul(unit).ok_or_else(invalid)?;
    if seconds > 900 {
        return Err(invalid());
    }
    Ok(Duration::from_secs(seconds))
}

/// The agent a profile command names: `--agent`, or the only agent with the
/// server.
fn profile_agent(view: &Value, server: &str, agent: Option<&str>) -> anyhow::Result<String> {
    let matches: Vec<&Value> = view["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| {
            agent.is_none_or(|n| {
                a["agent"]["name"].as_str() == Some(n) || a["agent"]["id"].as_str() == Some(n)
            })
        })
        .filter(|a| server_of(a, server).is_some())
        .collect();
    match matches.as_slice() {
        [one] => Ok(one["agent"]["id"].as_str().unwrap_or_default().to_owned()),
        [] => bail!("no agent on this host has a server {server}"),
        many => bail!(
            "several agents have a server {server}; choose one with --agent: {}",
            many.iter()
                .filter_map(|a| a["agent"]["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

async fn tools(
    local: &Local<'_>,
    socket: &Path,
    args: &ToolsArgs,
) -> anyhow::Result<Option<Value>> {
    match &args.command {
        None => {
            let path = match &args.agent {
                Some(a) => format!("/v1/tools?agent={}", encoded(a)),
                None => "/v1/tools".to_owned(),
            };
            let view = local.get(path).await?;
            if args.json {
                return Ok(Some(view));
            }
            print!("{}", readable(&view));
            crate::exit(0)
        }
        Some(ToolsCommand::Refresh { agent }) => {
            let host = local.get("/v1/host".into()).await?["id"]
                .as_str()
                .context("invalid daemon response")?
                .to_owned();
            let agents = local.get("/v1/agents".into()).await?;
            let mut out = Vec::new();
            for (id, integration, workspace) in crate::integration::attach_agents(&host)? {
                let name = agents
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|a| a["id"].as_str() == Some(id.as_str()))
                    .and_then(|a| a["name"].as_str())
                    .unwrap_or_default()
                    .to_owned();
                if agent.as_deref().is_some_and(|a| a != name && a != id) {
                    continue;
                }
                let tools =
                    crate::discovery::refresh(socket, &id, &integration, &workspace).await?;
                out.push(json!({"agent": {"id": id, "name": name}, "tools": tools}));
            }
            if out.is_empty()
                && let Some(a) = agent
            {
                bail!("no attach profile on this host for agent {a}");
            }
            Ok(Some(Value::Array(out)))
        }
        Some(ToolsCommand::Remote {
            target,
            network,
            json,
        }) => {
            let mut path = "/v1/remote-tools?".to_owned();
            if let Some(t) = target {
                path.push_str(&format!("target={}&", encoded(t)));
            }
            if let Some(n) = network {
                path.push_str(&format!("network={}", encoded(n)));
            }
            let value = local.get(path).await?;
            if *json {
                return Ok(Some(value));
            }
            for e in value["entries"].as_array().into_iter().flatten() {
                let server = match e["profile"].as_str() {
                    Some(p) => format!("{}@{p}", e["server"].as_str().unwrap_or_default()),
                    None => e["server"].as_str().unwrap_or_default().to_owned(),
                };
                println!(
                    "{}/{}/{server}",
                    e["host_id"].as_str().unwrap_or_default(),
                    e["agent"].as_str().unwrap_or_default()
                );
                for t in e["tools"].as_array().into_iter().flatten() {
                    println!(
                        "  tool {}{}",
                        t["name"].as_str().unwrap_or_default(),
                        if t["read_only"] == true {
                            " (read-only)"
                        } else {
                            ""
                        }
                    );
                }
                for r in e["resources"].as_array().into_iter().flatten() {
                    println!("  resource {}", r["uri"].as_str().unwrap_or_default());
                }
            }
            for u in value["unanswered"].as_array().into_iter().flatten() {
                println!(
                    "{} did not answer: {}",
                    u["host_id"].as_str().unwrap_or_default(),
                    u["error"].as_str().unwrap_or_default()
                );
            }
            crate::exit(0)
        }
        Some(ToolsCommand::Profile(ProfileCommand::Add {
            server,
            profile,
            env_file,
            args,
            agent,
        })) => {
            let view = local.get("/v1/tools".into()).await?;
            let id = profile_agent(&view, server, agent.as_deref())?;
            let env_file = std::path::absolute(env_file)?;
            let mut body = json!({"name": profile, "env_file": env_file.display().to_string()});
            if !args.is_empty() {
                body["args"] = json!(args);
            }
            Ok(Some(
                local
                    .post(
                        format!(
                            "/v1/agents/{}/tool-servers/{}/profiles",
                            encoded(&id),
                            encoded(server)
                        ),
                        body,
                    )
                    .await?,
            ))
        }
        Some(ToolsCommand::Profile(ProfileCommand::Remove { spec, agent })) => {
            let Some((server, Some(profile))) = split_server(spec) else {
                bail!("give SERVER@PROFILE");
            };
            let view = local.get("/v1/tools".into()).await?;
            let id = profile_agent(&view, server, agent.as_deref())?;
            Ok(Some(
                crate::delete(
                    socket,
                    format!(
                        "/v1/agents/{}/tool-servers/{}/profiles/{}",
                        encoded(&id),
                        encoded(server),
                        encoded(profile)
                    ),
                )
                .await?,
            ))
        }
    }
}

/// The readable `tools` layout; not a shared format.
fn readable(view: &Value) -> String {
    let mut out = String::new();
    for a in view["agents"].as_array().into_iter().flatten() {
        out += &format!("{}\n", a["agent"]["name"].as_str().unwrap_or_default());
        let servers = a["servers"].as_array().cloned().unwrap_or_default();
        if servers.is_empty() {
            out += "  no MCP servers found\n";
        }
        for s in servers {
            let name = s["name"].as_str().unwrap_or_default();
            match s["reason"].as_str() {
                Some(reason) => out += &format!("  {name}: not shareable ({reason})\n"),
                None => out += &format!("  {name}\n"),
            }
            if let Some(e) = s["snapshot_error"].as_str() {
                out += &format!("    snapshot failed: {e}\n");
            }
            for t in s["tools"].as_array().into_iter().flatten() {
                out += &format!(
                    "    tool {} ({})\n",
                    t["name"].as_str().unwrap_or_default(),
                    if t["read_only"] == true {
                        "read-only"
                    } else {
                        "write"
                    }
                );
            }
            for r in s["resources"].as_array().into_iter().flatten() {
                out += &format!("    resource {}\n", r["uri"].as_str().unwrap_or_default());
            }
            for p in s["profiles"].as_array().into_iter().flatten() {
                out += &format!(
                    "    profile {name}@{}\n",
                    p["name"].as_str().unwrap_or_default()
                );
            }
            for r in s["shares"].as_array().into_iter().flatten() {
                out += &format!(
                    "    shared in {} with {}: {} {} ({})\n",
                    r["network_id"].as_str().unwrap_or_default(),
                    names_of(&r["principals"]),
                    r["server"].as_str().unwrap_or_default(),
                    names_of(&r["scope"]),
                    names_of(&r["actions"]),
                );
            }
        }
    }
    out
}
fn names_of(v: &Value) -> String {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}
