//! The owner CLI for capabilities (capabilities contract): `sources`,
//! `capability`, `share`, `shares`, `unshare`, `trust` and `untrust`,
//! `discover`, `call`, and the trust question of `join` and `network
//! create`. Signing stays here; the daemon never sees the person key.
use crate::{
    access::{EDIT_ATTEMPTS, Editor, at, edit_conflict, failed, top_principal},
    admin::Local,
    cli::{CapabilityCommand, Command, SourcesArgs, SourcesCommand, encoded, resolved},
};
use anyhow::{Context, bail};
use chrono::{TimeDelta, Utc};
use peerspan_host::{
    persons::{self, PersonSigner},
    policy::{CapabilityRule, Content, Policy},
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, IsTerminal, Write},
    path::Path,
    time::Duration,
};

/// Runs a capabilities command; None for any other command.
pub async fn command(command: &Command, directory: &Path) -> anyhow::Result<Option<Value>> {
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    Ok(Some(match command {
        Command::Sources(args) => return sources(&local, &socket, args).await,
        Command::Capability(c) => return capability(&local, c).await,
        Command::Share {
            name,
            with,
            calls_per_hour,
            yes,
            from,
            operations,
            resources,
            capability_name,
            env_file,
            args,
            network,
            person_key,
        } => {
            let guided = Guided {
                from: from.clone(),
                operations: operations.clone(),
                resources: resources.clone(),
                name: capability_name.clone(),
                env_file: env_file
                    .as_ref()
                    .map(std::path::absolute)
                    .transpose()?
                    .map(|p| p.display().to_string()),
                args: args.clone(),
            };
            share(
                &local,
                resolved(network),
                person_key.as_deref(),
                name.as_deref(),
                with,
                *calls_per_hour,
                *yes,
                guided,
            )
            .await?
        }
        Command::Shares { json, network } => {
            let value = shares(&local, network.as_deref()).await?;
            if *json {
                value
            } else {
                print!("{}", readable_shares(&value));
                crate::exit(0)
            }
        }
        Command::Unshare {
            name,
            with,
            network,
            person_key,
        } => unshare(&local, resolved(network), person_key.as_deref(), name, with).await?,
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
        Command::Discover {
            person,
            network,
            json,
        } => {
            let value = discover(&local, person.as_deref(), network.as_deref()).await?;
            if *json {
                value
            } else {
                print!("{}", readable_discover(&value));
                crate::exit(0)
            }
        }
        Command::Call {
            address,
            operation,
            options,
        } => return call(&local, address, operation, options).await,
        _ => return Ok(None),
    }))
}

/// One policy edit: applies `change` to the starting content, signs, and
/// submits, starting again from the edit route on an edit conflict.
/// `change` returns false to sign nothing. Returns the starting policy and
/// the stored policy, if one was signed.
async fn edit_policy<F>(
    local: &Local<'_>,
    network: &str,
    signer: &PersonSigner,
    mut change: F,
) -> anyhow::Result<(Option<Policy>, Option<Value>)>
where
    F: FnMut(&mut Content) -> anyhow::Result<bool>,
{
    let editor = Editor::new(local, network, signer).await?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let start = editor.start(local).await?;
        let mut content = start
            .policy
            .as_ref()
            .map(Policy::content)
            .unwrap_or_default();
        if !change(&mut content)? {
            return Ok((start.policy, None));
        }
        let policy = editor.sign(signer, &start, content, None, true)?;
        match editor.submit(local, &policy).await {
            Err(e) if edit_conflict(&e) && attempt < EDIT_ATTEMPTS => continue,
            outcome => return Ok((start.policy, Some(outcome?))),
        }
    }
}

/// The networks in which this host is bound to a person, with that
/// person's ID.
async fn bound_networks(local: &Local<'_>) -> anyhow::Result<Vec<(String, String)>> {
    let status = local.get("/v1/status".into()).await?;
    Ok(status["networks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| {
            Some((
                n["id"].as_str()?.to_owned(),
                n["person"]["id"].as_str()?.to_owned(),
            ))
        })
        .collect())
}

/// The share a guided first share signs in its network.
struct FirstShare<'a> {
    network: &'a str,
    principal: &'a str,
    calls_per_hour: Option<i64>,
}

/// Creates a capability and claims its name (capabilities contract,
/// claims): one signed policy for each network in which this host is bound
/// to its person, each an edit adding this host's rule for `name` with no
/// principals, or in the guided share's network with its principal.
/// Refuses a name bound to another host before signing.
async fn create_claimed(
    local: &Local<'_>,
    person_key: Option<&Path>,
    mut body: Value,
    first: Option<FirstShare<'_>>,
) -> anyhow::Result<(Value, bool)> {
    let name = body["name"].as_str().unwrap_or_default().to_owned();
    // An identical repeat signs nothing; another record under the name is
    // refused by the daemon.
    let exists = local
        .get(format!("/v1/capabilities/{}", encoded(&name)))
        .await
        .is_ok();
    let bound = if exists {
        Vec::new()
    } else {
        bound_networks(local).await?
    };
    let signer = if bound.is_empty() {
        None
    } else {
        Some(PersonSigner::open(person_key).map_err(failed)?)
    };
    // Claims are signed in the networks where this host is bound to the
    // signing person; the others gain theirs at the first share there.
    let networks: Vec<String> = match &signer {
        Some(signer) => {
            let me = persons::person_id(&signer.public_key());
            bound
                .into_iter()
                .filter(|(_, p)| *p == me)
                .map(|(n, _)| n)
                .collect()
        }
        None => Vec::new(),
    };
    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut policies = Vec::new();
        for network in &networks {
            let signer = signer.as_ref().expect("opened for bound networks");
            let editor = Editor::new(local, network, signer).await?;
            let start = editor.start(local).await?;
            let mut content = start
                .policy
                .as_ref()
                .map(Policy::content)
                .unwrap_or_default();
            if content
                .capability_rules
                .iter()
                .any(|r| r.capability == name && r.host != editor.host)
            {
                bail!("a capability rule of yours binds {name} to another host (409)");
            }
            let share = first.as_ref().filter(|f| f.network == network.as_str());
            match content
                .capability_rules
                .iter_mut()
                .find(|r| r.capability == name)
            {
                Some(r) => {
                    if let Some(f) = share {
                        if !r.principals.iter().any(|p| p == f.principal) {
                            r.principals.push(f.principal.to_owned());
                        }
                        if let Some(n) = f.calls_per_hour {
                            r.max_calls_per_hour = n;
                        }
                    }
                }
                None => {
                    let mut rule = CapabilityRule::claim(&editor.host, &name);
                    if let Some(f) = share {
                        rule.principals.push(f.principal.to_owned());
                        rule.max_calls_per_hour = f.calls_per_hour.unwrap_or(100);
                    }
                    content.capability_rules.push(rule);
                }
            }
            policies.push(editor.sign(signer, &start, content, None, true)?);
        }
        body["policies"] = json!(policies);
        match local.post("/v1/capabilities".into(), body.clone()).await {
            Err(e) if edit_conflict(&e) && attempt < EDIT_ATTEMPTS => continue,
            outcome => {
                let shared = first
                    .as_ref()
                    .is_some_and(|f| networks.iter().any(|n| n == f.network));
                return Ok((outcome?, shared));
            }
        }
    }
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
    let (current, policy) = edit_policy(local, network, &signer, |content| {
        let present = content.trusted_hosts.contains(&host);
        if add == present {
            return Ok(false);
        }
        if add {
            content.trusted_hosts.push(host.clone());
        } else {
            content.trusted_hosts.retain(|h| *h != host);
        }
        Ok(true)
    })
    .await?;
    Ok(match policy {
        None => json!({"policy": current, "host": host, "trusted": add, "changed": false}),
        Some(policy) => json!({"policy": policy, "host": host, "trusted": add, "changed": true}),
    })
}

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
/// After `join` or `network create` bound this host: asks whether it may
/// use the person's capabilities on their other machines, unless a flag
/// answered, and adds it to the trusted hosts on yes. Returns the answer.
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
        ask(
            "Let this machine use your capabilities on your other machines, and the tools of those that allow it? [y/N] ",
        )?
    } else {
        false
    };
    if !yes {
        eprintln!(
            "This machine is not trusted to use your capabilities on your other machines. Note that any host holding your person key can mark itself trusted; untrusted marking protects only against hosts without the key."
        );
        return Ok(false);
    }
    let local = Local(socket);
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    edit_policy(&local, network, signer, |content| {
        if content.trusted_hosts.contains(&host) {
            return Ok(false);
        }
        content.trusted_hosts.push(host.clone());
        Ok(true)
    })
    .await?;
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

/// The sources view.
async fn sources_view(local: &Local<'_>) -> anyhow::Result<Value> {
    local.get("/v1/sources".into()).await
}
/// `AGENT/SERVER`, or `SERVER` when exactly one agent here has it.
async fn source_of(local: &Local<'_>, given: &str) -> anyhow::Result<(String, String, Value)> {
    let view = sources_view(local).await?;
    let mut found = Vec::new();
    for a in view["agents"].as_array().into_iter().flatten() {
        let agent = a["agent"]["name"].as_str().unwrap_or_default();
        for s in a["servers"].as_array().into_iter().flatten() {
            let server = s["name"].as_str().unwrap_or_default();
            let matches = match given.rsplit_once('/') {
                Some((ga, gs)) => ga == agent && gs == server,
                None => given == server,
            };
            if matches {
                found.push((agent.to_owned(), server.to_owned(), s.clone()));
            }
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => bail!("no source {given} on this host; see peerspan sources"),
        _ => bail!(
            "several agents have {given}; give AGENT/SERVER: {}",
            found
                .iter()
                .map(|(a, s, _)| format!("{a}/{s}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

async fn sources(
    local: &Local<'_>,
    socket: &Path,
    args: &SourcesArgs,
) -> anyhow::Result<Option<Value>> {
    match &args.command {
        None => {
            let path = match &args.agent {
                Some(a) => format!("/v1/sources?agent={}", encoded(a)),
                None => "/v1/sources".to_owned(),
            };
            let view = local.get(path).await?;
            if args.json {
                return Ok(Some(view));
            }
            print!("{}", readable_sources(&view));
            crate::exit(0)
        }
        Some(SourcesCommand::Refresh { agent }) => {
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
                let found =
                    crate::discovery::refresh(socket, &id, &integration, &workspace).await?;
                out.push(json!({"agent": {"id": id, "name": name}, "sources": found}));
            }
            if out.is_empty()
                && let Some(a) = agent
            {
                bail!("no attach profile on this host for agent {a}");
            }
            Ok(Some(Value::Array(out)))
        }
        Some(SourcesCommand::OpenTo { host, all }) => {
            let host = if *all {
                "*".to_owned()
            } else {
                host.clone().unwrap_or_default()
            };
            Ok(Some(
                local
                    .post("/v1/sources/open-to".into(), json!({"host_id": host}))
                    .await?,
            ))
        }
        Some(SourcesCommand::CloseTo { host, all }) => {
            let host = if *all {
                "*".to_owned()
            } else {
                host.clone().unwrap_or_default()
            };
            Ok(Some(
                crate::delete(local.0, format!("/v1/sources/open-to/{}", encoded(&host))).await?,
            ))
        }
    }
}

/// `OP[,OP...]`.
fn list_of(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
/// `all`, or `URI[,URI...]`.
fn resources_of(text: Option<&str>) -> Value {
    match text {
        None => Value::Null,
        Some("all") => json!("all"),
        Some(list) => json!(list_of(list)),
    }
}

/// What the guided share asks for, or takes from flags.
struct Guided {
    from: Option<String>,
    operations: Option<String>,
    resources: Option<String>,
    name: Option<String>,
    env_file: Option<String>,
    args: Vec<String>,
}

/// The body of `POST /v1/capabilities`.
fn create_body(
    name: &str,
    agent: &str,
    server: &str,
    operations: Option<&str>,
    resources: Option<&str>,
    env_file: Option<String>,
    args: &[String],
) -> Value {
    let mut body = json!({
        "name": name,
        "source": {"agent": agent, "server": server},
        "operations": operations.map(list_of).unwrap_or_default(),
        "resources": resources_of(resources),
        "env_file": env_file,
    });
    if !args.is_empty() {
        body["args"] = json!(args);
    }
    body
}

async fn capability(local: &Local<'_>, c: &CapabilityCommand) -> anyhow::Result<Option<Value>> {
    Ok(Some(match c {
        CapabilityCommand::Create {
            name,
            from,
            operations,
            resources,
            env_file,
            args,
            person_key,
        } => {
            let (agent, server, _) = source_of(local, from).await?;
            let env_file = env_file
                .as_ref()
                .map(std::path::absolute)
                .transpose()?
                .map(|p| p.display().to_string());
            let body = create_body(
                name,
                &agent,
                &server,
                operations.as_deref(),
                resources.as_deref(),
                env_file,
                args,
            );
            create_claimed(local, person_key.as_deref(), body, None)
                .await?
                .0
        }
        CapabilityCommand::List { json } => {
            let value = local.get("/v1/capabilities".into()).await?;
            if !*json {
                for c in value["capabilities"].as_array().into_iter().flatten() {
                    println!("{}", readable_capability(c));
                }
                crate::exit(0)
            }
            value
        }
        CapabilityCommand::Show { name } => {
            local
                .get(format!("/v1/capabilities/{}", encoded(name)))
                .await?
        }
        CapabilityCommand::Remove {
            name,
            yes,
            person_key,
        } => remove(local, name, *yes, person_key.as_deref()).await?,
    }))
}

/// `capability remove`: after confirmation when shared, removes this host's
/// rule for the capability from every network's policy, then the record.
async fn remove(
    local: &Local<'_>,
    name: &str,
    yes: bool,
    person_key: Option<&Path>,
) -> anyhow::Result<Value> {
    let record = local
        .get(format!("/v1/capabilities/{}", encoded(name)))
        .await?;
    let recipients = record["recipients"].as_array().cloned().unwrap_or_default();
    if !recipients.is_empty() {
        eprintln!("{name} is shared with:");
        for r in &recipients {
            eprintln!(
                "  {} in {}",
                r["label"]
                    .as_str()
                    .or(r["principal"].as_str())
                    .unwrap_or_default(),
                r["network_id"].as_str().unwrap_or_default()
            );
        }
        eprintln!("Removing it withdraws these shares.");
        if !yes {
            if !std::io::stdin().is_terminal() {
                bail!("confirm at a terminal, or give --yes");
            }
            if !ask("Remove? [y/N] ")? {
                bail!("not removed");
            }
        }
    }
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    // Every stored policy of the signing person with this host's rule,
    // claim included, also in networks where this host is no longer bound;
    // any failure keeps the record.
    let holders = local
        .get(format!("/v1/capabilities/{}/rules", encoded(name)))
        .await?;
    let holders: Vec<(String, String)> = holders
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|h| {
            Some((
                h["network_id"].as_str()?.to_owned(),
                h["person_id"].as_str()?.to_owned(),
            ))
        })
        .collect();
    let mut signed = Vec::new();
    if !holders.is_empty() {
        let signer = PersonSigner::open(person_key).map_err(failed)?;
        let me = persons::person_id(&signer.public_key());
        for (network, _) in holders.iter().filter(|(_, p)| *p == me) {
            let (_, stored) = edit_policy(local, network, &signer, |content| {
                let before = content.capability_rules.len();
                content
                    .capability_rules
                    .retain(|r| !(r.host == host && r.capability == name));
                Ok(content.capability_rules.len() != before)
            })
            .await?;
            if let Some(stored) = stored {
                signed.push(json!({"network_id": network, "version": stored["version"]}));
            }
        }
    }
    let removed = crate::delete(local.0, format!("/v1/capabilities/{}", encoded(name))).await?;
    Ok(json!({"capability": removed, "policies": signed}))
}

/// This host's person label and ID in a network.
async fn me_in(local: &Local<'_>, network: &str) -> anyhow::Result<(String, String)> {
    let status = local.get("/v1/status".into()).await?;
    let person = status["networks"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|n| n["id"].as_str() == Some(network))
        .map(|n| n["person"].clone())
        .unwrap_or(Value::Null);
    Ok((
        person["label"].as_str().unwrap_or_default().to_owned(),
        person["id"].as_str().unwrap_or_default().to_owned(),
    ))
}

/// Asks for one line at the terminal, offering a default.
fn prompt(question: &str, default: Option<&str>) -> anyhow::Result<String> {
    match default {
        Some(d) => eprint!("{question} [{d}]: "),
        None => eprint!("{question}: "),
    }
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let line = line.trim().to_owned();
    Ok(match (line.is_empty(), default) {
        (true, Some(d)) => d.to_owned(),
        _ => line,
    })
}

/// `share`: the review, the confirmation, and the next signed version.
#[allow(clippy::too_many_arguments)]
async fn share(
    local: &Local<'_>,
    network: &str,
    person_key: Option<&Path>,
    name: Option<&str>,
    with: &str,
    calls_per_hour: Option<i64>,
    yes: bool,
    guided: Guided,
) -> anyhow::Result<Value> {
    let terminal = std::io::stdin().is_terminal();
    let signer = PersonSigner::open(person_key).map_err(failed)?;
    let principal = top_principal(local, network, with).await?;
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    // The capability: an existing one, or the guided share's draft.
    let (record, draft): (Value, Option<Value>) = match name {
        Some(name) => (
            local
                .get(format!("/v1/capabilities/{}", encoded(name)))
                .await?,
            None,
        ),
        None => {
            if !terminal && (guided.from.is_none() || !yes) {
                bail!(
                    "without a terminal, the guided share needs --from, --operations or --resources, and --yes"
                );
            }
            let from = match guided.from.clone() {
                Some(f) => f,
                None => {
                    let view = sources_view(local).await?;
                    for a in view["agents"].as_array().into_iter().flatten() {
                        for s in a["servers"].as_array().into_iter().flatten() {
                            if s["shareable"] == true {
                                eprintln!(
                                    "  {}/{}",
                                    a["agent"]["name"].as_str().unwrap_or_default(),
                                    s["name"].as_str().unwrap_or_default()
                                );
                            }
                        }
                    }
                    prompt("Source (AGENT/SERVER)", None)?
                }
            };
            let (agent, server, source) = source_of(local, &from).await?;
            let (operations, resources) =
                if guided.operations.is_some() || guided.resources.is_some() || !terminal {
                    (guided.operations.clone(), guided.resources.clone())
                } else {
                    for t in source["tools"].as_array().into_iter().flatten() {
                        eprintln!(
                            "  {}{}",
                            t["name"].as_str().unwrap_or_default(),
                            if t["read_only"] == true {
                                ""
                            } else {
                                " (can change things)"
                            }
                        );
                    }
                    let ops = prompt("Operations (OP,OP...)", None)?;
                    let include =
                        prompt("Include resources? (all, URI,URI..., or no)", Some("no"))?;
                    (
                        (!ops.is_empty()).then_some(ops),
                        (!matches!(include.to_ascii_lowercase().as_str(), "" | "n" | "no"))
                            .then_some(include),
                    )
                };
            let cap_name = match guided.name.clone() {
                Some(n) => n,
                None if terminal => prompt("Capability name", Some(&server))?,
                None => server.clone(),
            };
            let body = create_body(
                &cap_name,
                &agent,
                &server,
                operations.as_deref(),
                resources.as_deref(),
                guided.env_file.clone(),
                &guided.args,
            );
            let preview = json!({
                "name": cap_name,
                "source": {"agent": agent, "server": server},
                "operations": body["operations"],
                "resources": body["resources"],
                "credential": {"env_file": body["env_file"], "args": body.get("args")},
            });
            (preview, Some(body))
        }
    };
    let cap = record["name"].as_str().unwrap_or_default().to_owned();
    // The review reads the stored policy; the edit starts from the edit
    // route after confirmation.
    let me = persons::person_id(&signer.public_key());
    let current: Option<Policy> = local
        .get(format!(
            "/v1/networks/{}/policy?person={}",
            encoded(network),
            encoded(&me)
        ))
        .await
        .ok()
        .map(|v| serde_json::from_value(crate::access::strip_view(v)))
        .transpose()?;
    let content = current.as_ref().map(Policy::content).unwrap_or_default();
    if content
        .capability_rules
        .iter()
        .any(|r| r.capability == cap && r.host != host)
    {
        bail!("a capability rule of yours binds {cap} to another host (409)");
    }
    let existing = content
        .capability_rules
        .iter()
        .find(|r| r.capability == cap && r.host == host)
        .cloned();
    let limit_change = match (&existing, calls_per_hour) {
        (Some(r), Some(n)) if r.max_calls_per_hour != n => Some((r.max_calls_per_hour, n)),
        _ => None,
    };
    // Every share shows the review and asks, even one that changes nothing.
    let unchanged = existing.as_ref().is_some_and(|r| {
        r.principals.contains(&principal) && limit_change.is_none() && draft.is_none()
    });
    // The review, on stderr.
    let (label, _) = me_in(local, network).await?;
    let source_view = source_of(
        local,
        &format!(
            "{}/{}",
            record["source"]["agent"].as_str().unwrap_or_default(),
            record["source"]["server"].as_str().unwrap_or_default()
        ),
    )
    .await
    .map(|(_, _, s)| s)
    .unwrap_or(Value::Null);
    let read_only = |op: &str| {
        source_view["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|t| t["name"].as_str() == Some(op) && t["read_only"] == true)
    };
    eprintln!(
        "Capability: {}/{cap}",
        if label.is_empty() {
            host.as_str()
        } else {
            label.as_str()
        }
    );
    eprintln!(
        "Source: {}/{} ({})",
        record["source"]["agent"].as_str().unwrap_or_default(),
        record["source"]["server"].as_str().unwrap_or_default(),
        source_view["source"].as_str().unwrap_or("unknown origin")
    );
    eprintln!("Operations:");
    for op in record["operations"].as_array().into_iter().flatten() {
        let op = op.as_str().unwrap_or_default();
        eprintln!(
            "  {op}{}",
            if read_only(op) {
                ""
            } else {
                " (can change things)"
            }
        );
    }
    match &record["resources"] {
        Value::Null => {}
        Value::String(all) => eprintln!("Resources: {all} (read)"),
        list => eprintln!("Resources: {} (read)", list_text(list)),
    }
    match record["credential"]["env_file"].as_str() {
        Some(file) => eprintln!("Credentials: the capability's environment file {file}"),
        None => eprintln!("Credentials: the source's own environment on this host"),
    }
    eprintln!("Recipient: {with} ({principal})");
    if let (Some((old, new)), Some(r)) = (limit_change, &existing) {
        // Recipients by label where the principal resolves to one, as in
        // `shares`, falling back to the principal.
        let persons = local
            .get(format!("/v1/networks/{}/persons", encoded(network)))
            .await
            .unwrap_or(Value::Null);
        let label = |p: &String| {
            p.strip_prefix("person:")
                .and_then(|id| {
                    persons
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|x| x["person_id"].as_str() == Some(id))
                        .and_then(|x| x["member"].as_str())
                })
                .map(str::to_owned)
                .unwrap_or_else(|| p.clone())
        };
        eprintln!(
            "Calls per hour: {old} becomes {new} for every recipient: {}",
            r.principals
                .iter()
                .map(label)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    eprintln!(
        "{with} can use these operations with the credentials they run with on this host. Anything those credentials can reach through them, {with} can too."
    );
    if !yes {
        if !terminal {
            bail!("confirm the review above at a terminal, or give --yes");
        }
        if !ask("Share? [y/N] ")? {
            bail!("not shared");
        }
    }
    if unchanged {
        // Already shared this way: nothing is signed.
        return Ok(
            json!({"policy": current, "capability": cap, "principal": principal, "created": false}),
        );
    }
    let mut created_now = false;
    if let Some(body) = draft {
        // The guided share creates the capability with its claims: the
        // share in this network, the claim in the others.
        let (_, shared) = create_claimed(
            local,
            person_key,
            body,
            Some(FirstShare {
                network,
                principal: &principal,
                calls_per_hour,
            }),
        )
        .await?;
        let policy = local
            .get(format!(
                "/v1/networks/{}/policy?person={}",
                encoded(network),
                encoded(&me)
            ))
            .await
            .map(crate::access::strip_view)
            .unwrap_or(Value::Null);
        if shared {
            return Ok(
                json!({"policy": policy, "capability": cap, "principal": principal, "created": true}),
            );
        }
        // An identical capability existed already, or this host has no
        // person here: it is shared as usual.
        created_now = true;
    }
    let (start, policy) = edit_policy(local, network, &signer, |content| {
        if content
            .capability_rules
            .iter()
            .any(|r| r.capability == cap && r.host != host)
        {
            bail!("a capability rule of yours binds {cap} to another host (409)");
        }
        match content
            .capability_rules
            .iter_mut()
            .find(|r| r.capability == cap && r.host == host)
        {
            Some(r) => {
                let limit = calls_per_hour.filter(|n| *n != r.max_calls_per_hour);
                if r.principals.contains(&principal) && limit.is_none() {
                    return Ok(false);
                }
                if !r.principals.contains(&principal) {
                    r.principals.push(principal.clone());
                }
                if let Some(n) = limit {
                    r.max_calls_per_hour = n;
                }
            }
            None => content.capability_rules.push(CapabilityRule {
                host: host.clone(),
                capability: cap.clone(),
                principals: vec![principal.clone()],
                max_input_bytes: 65536,
                allow_disconnected: false,
                max_calls_per_hour: calls_per_hour.unwrap_or(100),
            }),
        }
        Ok(true)
    })
    .await?;
    let policy = match policy {
        Some(p) => p,
        None => json!(start),
    };
    Ok(json!({"policy": policy, "capability": cap, "principal": principal, "created": created_now}))
}
fn list_text(v: &Value) -> String {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `unshare`: removes PRINCIPAL from this host's rule for the capability.
async fn unshare(
    local: &Local<'_>,
    network: &str,
    person_key: Option<&Path>,
    name: &str,
    with: &str,
) -> anyhow::Result<Value> {
    let signer = PersonSigner::open(person_key).map_err(failed)?;
    let principal = top_principal(local, network, with).await?;
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let mut removed = 0;
    let (current, policy) = edit_policy(local, network, &signer, |content| {
        removed = 0;
        for r in content.capability_rules.iter_mut() {
            if r.host == host && r.capability == name && r.principals.contains(&principal) {
                r.principals.retain(|p| *p != principal);
                removed += 1;
            }
        }
        // A rule left without principals stays as the name's claim.
        Ok(removed > 0)
    })
    .await?;
    let Some(policy) = policy else {
        return Ok(json!({
            "policy": current,
            "capability": name,
            "principal": principal,
            "removed": 0,
            "note": format!("{principal} is not in the share of {name}; access through a group or everyone is unaffected, and block stops a person at once"),
        }));
    };
    eprintln!(
        "{principal}'s future calls to {name} are denied. Calls already running finish; queued calls are refused when they would start."
    );
    Ok(json!({"policy": policy, "capability": name, "principal": principal, "removed": removed}))
}

/// `shares`: every capability here and every capability rule in this
/// person's stored policies.
async fn shares(local: &Local<'_>, network: Option<&str>) -> anyhow::Result<Value> {
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let capabilities = local.get("/v1/capabilities".into()).await?;
    let status = local.get("/v1/status".into()).await?;
    let mut entries = Vec::new();
    for c in capabilities["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let name = c["name"].as_str().unwrap_or_default();
        let recipients: Vec<Value> = c["recipients"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| network.is_none_or(|n| r["network_id"].as_str() == Some(n)))
            .map(|r| {
                let mut r = r.clone();
                r["unshare"] = json!(format!(
                    "peerspan unshare {name} --with {} --network {}",
                    r["principal"].as_str().unwrap_or_default(),
                    r["network_id"].as_str().unwrap_or_default()
                ));
                r
            })
            .collect();
        entries.push(json!({
            "capability": name,
            "host": host,
            "source": c["source"],
            "operations": c["operations"],
            "resources": c["resources"],
            "credential": c["credential"],
            "state": c["state"],
            "unavailable": c["unavailable"],
            "recipients": recipients,
        }));
    }
    // Rules of this person for capabilities on other hosts.
    for n in status["networks"].as_array().into_iter().flatten() {
        let Some(id) = n["id"].as_str() else { continue };
        if network.is_some_and(|x| x != id) {
            continue;
        }
        let Some(person) = n["person"]["id"].as_str() else {
            continue;
        };
        let policy = match local
            .get(format!(
                "/v1/networks/{}/policy?person={}",
                encoded(id),
                encoded(person)
            ))
            .await
        {
            Ok(p) => p,
            Err(_) => continue,
        };
        for r in policy["capability_rules"].as_array().into_iter().flatten() {
            if r["host"].as_str() == Some(host.as_str()) {
                continue;
            }
            entries.push(json!({
                "capability": r["capability"],
                "host": r["host"],
                "network_id": id,
                "source": null,
                "operations": null,
                "credential": null,
                "state": null,
                "recipients": r["principals"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| json!({"network_id": id, "principal": p, "label": null}))
                    .collect::<Vec<_>>(),
            }));
        }
    }
    Ok(json!({"shares": entries}))
}

async fn discover(
    local: &Local<'_>,
    person: Option<&str>,
    network: Option<&str>,
) -> anyhow::Result<Value> {
    let mut path = "/v1/discover?".to_owned();
    if let Some(p) = person {
        path.push_str(&format!("person={}&", encoded(p)));
    }
    if let Some(n) = network {
        path.push_str(&format!("network={}", encoded(n)));
    }
    local.get(path).await
}

/// `call ADDRESS OPERATION [--input JSON] [--KEY VALUE ...] [--deadline T]
/// [--wait D] [--network ID]`. `call`'s own flags always win; each other
/// `--KEY VALUE` fills a scalar top-level property of the operation's
/// input schema. Exits 0 for `succeeded`, 1 for other final states, and 3
/// if pending.
async fn call(
    local: &Local<'_>,
    address: &str,
    operation: &str,
    options: &[String],
) -> anyhow::Result<Option<Value>> {
    let mut input: Option<serde_json::Map<String, Value>> = None;
    let (mut deadline, mut wait, mut network) = (None, None, None);
    let mut keys: Vec<(String, String)> = Vec::new();
    let mut rest = options.iter();
    while let Some(flag) = rest.next() {
        let Some(name) = flag.strip_prefix("--").filter(|n| !n.is_empty()) else {
            bail!("unexpected argument {flag:?}; options are --KEY VALUE");
        };
        let (name, inline) = match name.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (name, None),
        };
        let value = match inline {
            Some(v) => v,
            None => rest
                .next()
                .cloned()
                .with_context(|| format!("--{name} needs a value"))?,
        };
        match name {
            "input" => {
                let parsed: Value = serde_json::from_str(&value).context("--input is not JSON")?;
                let Value::Object(map) = parsed else {
                    bail!("--input must be a JSON object");
                };
                input = Some(map);
            }
            "deadline" => deadline = Some(deadline_of(&value)?),
            "wait" => wait = Some(parse_wait(&value)?),
            "network" => network = Some(value),
            key => keys.push((key.to_owned(), value)),
        }
    }
    let mut body_input = input.clone().unwrap_or_default();
    if !keys.is_empty() {
        // The schema comes from the capability listing.
        let owner = address.split('/').next().unwrap_or_default();
        let capability = address.split_once('/').map(|(_, c)| c).unwrap_or_default();
        let listing = discover(local, Some(owner), network.as_deref()).await?;
        // The entry at this address: by address, else by host, else the
        // only one with that capability.
        let entries: Vec<&Value> = listing["capabilities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| e["capability"].as_str() == Some(capability))
            .collect();
        let entry = entries
            .iter()
            .find(|e| e["address"].as_str() == Some(address))
            .or_else(|| {
                entries
                    .iter()
                    .find(|e| e["host_id"].as_str() == Some(owner))
            })
            .or_else(|| (entries.len() == 1).then(|| &entries[0]))
            .with_context(|| format!("no single capability at {address}"))?;
        let schema = entry["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|o| o["name"].as_str() == Some(operation))
            .map(|o| o["input_schema"].clone())
            .with_context(|| format!("{address} has no operation {operation}"))?;
        for (key, value) in keys {
            if input.as_ref().is_some_and(|i| i.contains_key(&key)) {
                bail!("--{key} is also in --input");
            }
            let kind = schema["properties"][&key]["type"]
                .as_str()
                .unwrap_or_default();
            let parsed = match kind {
                "string" => json!(value),
                "integer" => json!(
                    value
                        .parse::<i64>()
                        .with_context(|| format!("--{key} is an integer"))?
                ),
                "number" => json!(
                    value
                        .parse::<f64>()
                        .with_context(|| format!("--{key} is a number"))?
                ),
                "boolean" => match value.as_str() {
                    "true" => json!(true),
                    "false" => json!(false),
                    _ => bail!("--{key} is true or false"),
                },
                _ => bail!(
                    "the input schema of {operation} declares no string, integer, number, or boolean property {key}"
                ),
            };
            body_input.insert(key, parsed);
        }
    }
    let mut body = json!({"target": address, "operation": operation, "input": body_input});
    if let Some(d) = &deadline {
        body["deadline"] = json!(d);
    }
    if let Some(n) = &network {
        body["network"] = json!(n);
    }
    let wait = wait.unwrap_or(Duration::from_secs(60));
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

/// The readable layouts; not shared formats.
fn readable_sources(view: &Value) -> String {
    let mut out = String::new();
    for a in view["agents"].as_array().into_iter().flatten() {
        let agent = a["agent"]["name"].as_str().unwrap_or_default();
        let servers = a["servers"].as_array().cloned().unwrap_or_default();
        if servers.is_empty() {
            out += &format!("{agent}: no sources found\n");
        }
        for s in servers {
            let name = s["name"].as_str().unwrap_or_default();
            out += &format!(
                "{agent}/{name} ({}){}\n",
                s["source"].as_str().unwrap_or_default(),
                match s["reason"].as_str() {
                    Some(r) => format!(": not shareable ({r})"),
                    None => String::new(),
                }
            );
            if let Some(e) = s["snapshot_error"].as_str() {
                out += &format!("  snapshot failed: {e}\n");
            }
            for t in s["tools"].as_array().into_iter().flatten() {
                out += &format!(
                    "  tool {}{}\n",
                    t["name"].as_str().unwrap_or_default(),
                    if t["read_only"] == true {
                        " (read-only)"
                    } else {
                        " (can change things)"
                    }
                );
            }
            for r in s["resources"].as_array().into_iter().flatten() {
                out += &format!("  resource {}\n", r["uri"].as_str().unwrap_or_default());
            }
            let caps = list_text(&s["capabilities"]);
            if !caps.is_empty() {
                out += &format!("  capabilities: {caps}\n");
            }
        }
    }
    let open = list_text(&view["open_to"]);
    out += &format!(
        "Open to: {}\n",
        if open.is_empty() {
            "nobody"
        } else {
            open.as_str()
        }
    );
    out
}
fn readable_capability(c: &Value) -> String {
    format!(
        "{} from {}/{}: {}{} ({})",
        c["name"].as_str().unwrap_or_default(),
        c["source"]["agent"].as_str().unwrap_or_default(),
        c["source"]["server"].as_str().unwrap_or_default(),
        list_text(&c["operations"]),
        if c["resources"].is_null() {
            ""
        } else {
            ", read"
        },
        c["state"].as_str().unwrap_or_default()
    )
}
fn readable_shares(value: &Value) -> String {
    let mut out = String::new();
    for e in value["shares"].as_array().into_iter().flatten() {
        out += &format!(
            "{} on {}{}\n",
            e["capability"].as_str().unwrap_or_default(),
            e["host"].as_str().unwrap_or_default(),
            e["state"]
                .as_str()
                .map(|s| format!(" ({s})"))
                .unwrap_or_default()
        );
        for r in e["recipients"].as_array().into_iter().flatten() {
            out += &format!(
                "  {}{}\n",
                r["label"]
                    .as_str()
                    .or(r["principal"].as_str())
                    .unwrap_or_default(),
                r["unshare"]
                    .as_str()
                    .map(|u| format!(": {u}"))
                    .unwrap_or_default()
            );
        }
    }
    out
}
fn readable_discover(value: &Value) -> String {
    let mut out = String::new();
    for a in value["agents"].as_array().into_iter().flatten() {
        out += &format!("agent {}\n", a["address"].as_str().unwrap_or_default());
    }
    for c in value["capabilities"].as_array().into_iter().flatten() {
        let ops: Vec<&str> = c["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|o| o["name"].as_str())
            .collect();
        out += &format!(
            "{} {}: {}\n",
            c["kind"].as_str().unwrap_or_default(),
            c["address"].as_str().unwrap_or_default(),
            ops.join(", ")
        );
    }
    for u in value["unanswered"].as_array().into_iter().flatten() {
        out += &format!(
            "{} did not answer: {}\n",
            u["host_id"].as_str().unwrap_or_default(),
            u["error"].as_str().unwrap_or_default()
        );
    }
    out
}
