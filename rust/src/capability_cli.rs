//! The owner CLI for capabilities (capabilities contract): `sources`,
//! `capability`, `share`, `shares`, `unshare`, `trust` and `untrust`,
//! `discover`, `call`, and the trust question of `join` and `network
//! create`. Signing stays here; the daemon never sees the person key.
use crate::{
    access::{
        EDIT_ATTEMPTS, Editor, PolicySigner, PolicySigning, PolicyValue, at, edit_conflict,
        recipient,
    },
    admin::Local,
    cli::{
        ApprovalsArgs, ApprovalsCommand, CapabilityCommand, Command, SourcesArgs, SourcesCommand,
        approval_id, encoded, resolved,
    },
};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::TimeDelta;
use peerspan_host::{
    persons::{self, PersonSigner},
    policy::{CapabilityRule, Content, Policy, PolicyBody},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
            approval,
            no_agent_self_approval,
            bound,
            network,
            person_key,
        } => {
            // `share NAME` never changes an existing capability's
            // requirement.
            if name.is_some() && (approval.is_some() || *no_agent_self_approval) {
                bail!(
                    "--approval and --no-agent-self-approval apply only to the guided share; use peerspan capability approval NAME MODE"
                );
            }
            let guided = Guided {
                approval: approval.clone(),
                no_agent_self: *no_agent_self_approval,
                bound: bound.clone(),
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
            from_agent: Some(agent),
        } => {
            let id = local_agent_id(&local, agent).await?;
            let value = discover_as(&local, &id, person.as_deref(), network.as_deref()).await?;
            if *json {
                value
            } else {
                println!("Capabilities {agent} may call:");
                print!("{}", readable_discover(&value));
                crate::exit(0)
            }
        }
        Command::Discover {
            person,
            network,
            json,
            from_agent: None,
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
        Command::Approvals(args) => return approvals(&local, args).await,
        Command::Approve { id } => approve(&local, id).await?,
        Command::Deny {
            principal,
            reason,
            agent,
            network,
            ..
        } if approval_id(principal) => {
            if agent.is_some() || network.is_some() {
                bail!("--agent and --network apply to access rules, not to denying a call");
            }
            let (sender, id) = resolve_approval(&local, principal).await?;
            local
                .post(
                    format!("/v1/approvals/{}/{}/deny", encoded(&sender), encoded(&id)),
                    json!({ "reason": reason }),
                )
                .await?
        }
        Command::Deny {
            reason: Some(_), ..
        } => bail!("--reason applies only to denying a call: peerspan deny CALL_ID --reason TEXT"),
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
    signer: &dyn PolicySigning,
    mut change: F,
) -> anyhow::Result<(Option<PolicyValue>, Option<Value>)>
where
    F: FnMut(&mut Content) -> anyhow::Result<bool>,
{
    let editor = Editor::new(local, network, signer).await?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let start = editor.start(local, signer.original()).await?;
        let mut content = start
            .policy
            .as_ref()
            .map(|p| p.content())
            .unwrap_or_default();
        if !change(&mut content)? {
            return Ok((start.policy, None));
        }
        let policy = editor.sign(signer, &start, content, None, true)?;
        match editor.submit(local, signer, &policy).await {
            Err(e) if edit_conflict(&e) && attempt < EDIT_ATTEMPTS => continue,
            outcome => return Ok((start.policy, Some(outcome?))),
        }
    }
}

fn not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<crate::integration::DaemonError>()
        .is_some_and(|d| d.status == 404)
}
async fn current_networks(local: &Local<'_>) -> anyhow::Result<Vec<Value>> {
    let status = local.get("/v2/status".into()).await?;
    let rows = status["networks"]
        .as_array()
        .context("invalid current network list")?;
    let mut result = Vec::new();
    for row in rows.iter().filter(|n| n["mode"] != "legacy_history") {
        let mut row = row.clone();
        if row["mode"] == "decentralized" {
            let key = row["person_public_key"]
                .as_str()
                .context("invalid current own person")?;
            row["person"] = if key == "-" {
                Value::Null
            } else {
                let raw = STANDARD.decode(key)?;
                anyhow::ensure!(
                    raw.len() == 32 && STANDARD.encode(&raw) == key,
                    "invalid current own person key"
                );
                json!({"id":persons::person_id(&raw)})
            };
        }
        result.push(row);
    }
    Ok(result)
}
async fn current_people(local: &Local<'_>, network: &str) -> anyhow::Result<Value> {
    if let Some(view) = crate::decentralized_policy_cli::network_view(local, network).await? {
        let people = crate::decentralized_policy_cli::current_persons(local, &view).await?;
        let members = local
            .get(format!("/v2/networks/{}/members", encoded(network)))
            .await?;
        let members = members["members"]
            .as_array()
            .context("invalid current member list")?;
        let mut out = Vec::new();
        for p in people {
            let key = p["person_public_key"]
                .as_str()
                .context("invalid current person")?;
            let raw = STANDARD.decode(key)?;
            anyhow::ensure!(
                raw.len() == 32 && STANDARD.encode(&raw) == key,
                "invalid current person key"
            );
            let hosts: Vec<String> = members
                .iter()
                .filter(|m| m["person_public_key"] == key)
                .map(|m| {
                    let key = m["host_public_key"]
                        .as_str()
                        .context("invalid current host")?;
                    let raw = STANDARD.decode(key)?;
                    anyhow::ensure!(
                        raw.len() == 32 && STANDARD.encode(&raw) == key,
                        "invalid current host key"
                    );
                    Ok(format!("host_{}", hex::encode(Sha256::digest(&raw))))
                })
                .collect::<anyhow::Result<_>>()?;
            out.push(json!({"person_id":persons::person_id(&raw),"person_public_key":key,"member":p["member"],"hosts":hosts}));
        }
        return Ok(json!(out));
    }
    local
        .get(format!("/v1/networks/{}/persons", encoded(network)))
        .await
}
// Native output is the signed policy-v2 body (the policy's fields, as the
// commands' contracts print them); it never gains a legacy `signature`.
async fn read_policy(
    local: &Local<'_>,
    network: &str,
    person: &str,
    key: &str,
) -> anyhow::Result<Option<(Value, PolicyBody)>> {
    if let Some(view) = crate::decentralized_policy_cli::network_view(local, network).await? {
        return Ok(
            crate::decentralized_policy_cli::current_policy(local, &view, key)
                .await?
                .map(|(_, b)| (serde_json::to_value(&b).unwrap_or(Value::Null), b)),
        );
    }
    let value = match local
        .get(format!(
            "/v1/networks/{}/policy?person={}",
            encoded(network),
            encoded(person)
        ))
        .await
    {
        Ok(v) => crate::access::strip_view(v),
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let policy: Policy = serde_json::from_value(value.clone())?;
    Ok(Some((value, policy.unsigned_body())))
}
/// The networks in which this host is bound to a person, with that
/// person's ID.
async fn bound_networks(local: &Local<'_>) -> anyhow::Result<Vec<(String, String)>> {
    Ok(current_networks(local)
        .await?
        .iter()
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
    let exists = match local
        .get(format!("/v1/capabilities/{}", encoded(&name)))
        .await
    {
        Ok(_) => true,
        Err(e) if not_found(&e) => false,
        Err(e) => return Err(e),
    };
    let bound = if exists {
        Vec::new()
    } else {
        bound_networks(local).await?
    };
    let mut signers = std::collections::BTreeMap::new();
    let mut selected_person = if let Some(first) = first
        .as_ref()
        .filter(|_| person_key.is_none() && !bound.is_empty())
    {
        let signer = PolicySigner::open(local, first.network, None).await?;
        Some(persons::person_id(&signer.public_key()))
    } else if bound.is_empty() {
        None
    } else {
        person_key
            .map(|path| PersonSigner::open(Some(path)))
            .transpose()?
            .map(|signer| persons::person_id(&signer.public_key()))
    };
    for (network, bound_person) in bound {
        if selected_person.as_ref().is_some_and(|p| p != &bound_person) {
            continue;
        }
        let signer = PolicySigner::open(local, &network, person_key).await?;
        let me = persons::person_id(&signer.public_key());
        if me != bound_person {
            continue;
        }
        if selected_person.as_ref().is_some_and(|p| p != &me) {
            continue;
        }
        selected_person = Some(me);
        signers.insert(network, signer);
    }
    let networks: Vec<String> = signers.keys().cloned().collect();
    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut policies = Vec::new();
        let mut catalogs = Vec::new();
        for network in &networks {
            let signer = signers.get(network).expect("selected provider");
            let editor = Editor::new(local, network, signer).await?;
            let start = editor.start(local, signer.original()).await?;
            let mut content = start
                .policy
                .as_ref()
                .map(|p| p.content())
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
            let signed = editor.sign(signer, &start, content, None, true)?;
            if let Some(prepared) = editor.prepare_claim(local, signer, &signed, &name).await? {
                anyhow::ensure!(
                    prepared["committed"] == false,
                    "claim preparation unexpectedly published"
                );
                catalogs.push(json!({"network_id":network,"catalog":prepared["catalog"]}));
            } else if let Some((certificate, _)) = signer.device() {
                let mut payload = serde_json::to_value(&signed)?;
                payload
                    .as_object_mut()
                    .context("invalid claim policy")?
                    .remove("signature");
                let prepared=local.post(format!("/v1/networks/{}/link-actions",encoded(network)),json!({"kind":"policy_claim","certificate_id":certificate,"payload_base64":STANDARD.encode(serde_json::to_vec(&json!({"capability":name,"policy_base64":STANDARD.encode(serde_json::to_vec(&payload)?)}))?)})).await?;
                anyhow::ensure!(
                    prepared["committed"] == false,
                    "claim preparation unexpectedly published"
                );
                catalogs.push(json!({"network_id":network,"catalog":prepared["catalog"]}));
            } else {
                policies.push(signed);
            }
        }
        body["policies"] = json!(policies);
        if !catalogs.is_empty() {
            body["catalogs"] = json!(catalogs);
        } else {
            body.as_object_mut()
                .context("invalid create request")?
                .remove("catalogs");
        }
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
    let signer = PolicySigner::open(local, network, person_key).await?;
    let host = match host {
        Some(h) => h.to_owned(),
        None => local.get("/v1/host".into()).await?["id"]
            .as_str()
            .context("invalid daemon response")?
            .to_owned(),
    };
    if add {
        let me = persons::person_id(&signer.public_key());
        let bound = if signer.decentralized().is_some() {
            let response = local
                .get(format!("/v2/networks/{}/members", encoded(network)))
                .await?;
            let members = response["members"]
                .as_array()
                .context("invalid current member list")?;
            let mut bound = false;
            for member in members {
                let key = member["host_public_key"]
                    .as_str()
                    .context("invalid current host key")?;
                let raw = STANDARD.decode(key)?;
                anyhow::ensure!(
                    raw.len() == 32 && STANDARD.encode(&raw) == key,
                    "invalid current host key"
                );
                let id = format!("host_{}", hex::encode(Sha256::digest(&raw)));
                if id == host && member["person_public_key"] == signer.public_key_b64() {
                    bound = true;
                }
            }
            bound
        } else {
            let members = local
                .get(format!("/v1/networks/{}/members", encoded(network)))
                .await?;
            members.as_array().into_iter().flatten().any(|m| {
                m["host_id"].as_str() == Some(host.as_str())
                    && m["person_id"].as_str() == Some(me.as_str())
            })
        };
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
            content.trusted_hosts.sort();
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
        content.trusted_hosts.sort();
        Ok(true)
    })
    .await?;
    Ok(true)
}

pub(crate) fn ask(prompt: &str) -> anyhow::Result<bool> {
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
    Ok(at(peerspan_host::clock::now() + TimeDelta::from_std(after)?))
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
    let builtin = json!({"agent": {"name": "builtin"}, "servers": view["builtin"]});
    for a in view["agents"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(std::iter::once(&builtin))
    {
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
            "several sources are named {given}; give AGENT/SERVER: {}",
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
            if crate::builtin_discovery::find_gh().is_none() {
                println!(
                    "GitHub CLI (gh) not found on PATH; install gh 2.81.0 or later and run peerspan sources refresh to use it as a source."
                );
            }
            crate::exit(0)
        }
        Some(SourcesCommand::Refresh { agent, builtin }) => {
            if *builtin && agent.is_some() {
                bail!("sources refresh takes --builtin or --agent, not both");
            }
            let mut out = Vec::new();
            if !*builtin {
                out = agents_refresh(local, socket, agent.as_deref()).await?;
            }
            if agent.is_none() {
                let found = crate::builtin_discovery::refresh(socket).await;
                out.push(json!({"agent_id": null, "agent": "builtin", "workspace": null, "sources": found}));
            }
            Ok(Some(Value::Array(out)))
        }
        Some(SourcesCommand::Login {
            source,
            scopes,
            client_id,
            client_secret_file,
            port,
            no_browser,
            account,
        }) => {
            let flags = crate::sign_in_cli::SignIn {
                scopes: scopes.as_deref(),
                client_id: client_id.as_deref(),
                client_secret_file: client_secret_file.as_deref(),
                port: *port,
                no_browser: *no_browser,
                account: account.as_deref().filter(|a| !a.is_empty()),
            };
            Ok(Some(
                crate::sign_in_cli::sources_login(local, source, &flags).await?,
            ))
        }
        Some(SourcesCommand::Logout { source, yes }) => Ok(Some(
            crate::sign_in_cli::sources_logout(local, source, *yes).await?,
        )),
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

/// `sources refresh` for each attached agent, or one.
async fn agents_refresh(
    local: &Local<'_>,
    socket: &Path,
    agent: Option<&str>,
) -> anyhow::Result<Vec<Value>> {
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
        if agent.is_some_and(|a| a != name && a != id) {
            continue;
        }
        let found = crate::discovery::refresh(socket, &id, &integration, &workspace).await?;
        out.push(json!({"agent": {"id": id, "name": name}, "sources": found}));
    }
    if out.is_empty()
        && let Some(a) = agent
    {
        bail!("no attach profile on this host for agent {a}");
    }
    Ok(out)
}

/// `OP[,OP...]`.
fn list_of(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
/// `--bound` values: each `KEY=VALUE[,KEY=VALUE...]` is one combination.
fn bounds_of(flags: &[String]) -> anyhow::Result<Option<Value>> {
    if flags.is_empty() {
        return Ok(None);
    }
    let mut combinations = Vec::new();
    for flag in flags {
        let mut c = serde_json::Map::new();
        for part in flag.split(',') {
            let Some((key, value)) = part.split_once('=') else {
                bail!("--bound {flag:?}: each part is KEY=VALUE");
            };
            if key.is_empty() {
                bail!("--bound {flag:?}: a name is empty");
            }
            if c.insert(key.to_owned(), json!(value)).is_some() {
                bail!("--bound {flag:?}: {key} is given twice");
            }
        }
        combinations.push(Value::Object(c));
    }
    Ok(Some(json!({"arguments": combinations})))
}
/// Prints a create response's warnings to stderr.
fn print_warnings(created: &Value) {
    for w in created["warnings"].as_array().into_iter().flatten() {
        eprintln!("warning: {}", w.as_str().unwrap_or_default());
    }
}
/// The reach statement of the review and `shares`.
fn reach_statement(principal: &str, gh: bool, bounds: &Value, sentence: &str) -> String {
    let combinations = peerspan_host::bounds::of_record(bounds);
    if combinations.is_empty() {
        if gh {
            return format!(
                "{principal} can use these operations with the credentials they run with on this host. {sentence} No resource bound."
            );
        }
        return format!(
            "{principal} can use these operations with the credentials they run with on this host. Anything those credentials can reach through them, {principal} can too. No resource bound."
        );
    }
    let allowed = peerspan_host::bounds::allowed(&combinations);
    if gh {
        format!(
            "{principal} can use these operations only where {allowed}; Peerspan refuses other calls. The credential reaches more than the bound. {sentence}"
        )
    } else {
        format!(
            "{principal} can use these operations only where {allowed}; Peerspan refuses other calls. Arguments Peerspan does not check can still reach anything the credentials they run with on this host can reach."
        )
    }
}
/// The review's bounds block, when the capability has a bound.
fn bounds_block(record: &Value, source: &Value, gh: bool) -> Vec<String> {
    let combinations = peerspan_host::bounds::of_record(&record["bounds"]);
    if combinations.is_empty() {
        return Vec::new();
    }
    let mut out = vec![format!(
        "Bounds: {}",
        peerspan_host::bounds::allowed(&combinations)
    )];
    if gh && combinations.iter().all(|c| c.contains_key("repo")) {
        out.push(
            "  Every gh operation names its repository in repo, so Peerspan checks every call."
                .into(),
        );
    } else {
        let names = peerspan_host::bounds::names(&combinations);
        let mut parts = Vec::new();
        for op in record["operations"].as_array().into_iter().flatten() {
            let op = op.as_str().unwrap_or_default();
            let schema = source["tools"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|t| t["name"].as_str() == Some(op))
                .map(|t| t["input_schema"]["properties"].clone())
                .unwrap_or(Value::Null);
            let mut others: Vec<&String> = schema
                .as_object()
                .into_iter()
                .flat_map(|m| m.keys())
                .filter(|k| !names.contains(k))
                .collect();
            others.sort();
            if !others.is_empty() {
                parts.push(format!(
                    "{op}: {}",
                    others
                        .iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        if parts.is_empty() {
            out.push("  Peerspan checks every argument of these operations.".into());
        } else {
            out.push(format!("  Not checked by Peerspan: {}.", parts.join("; ")));
        }
    }
    if !record["resources"].is_null() {
        out.push(
            "  The bound does not apply to read, which is limited to the capability's resources."
                .into(),
        );
    }
    out
}
/// Asks one question exactly as given and reads a line.
fn ask_line(question: &str) -> anyhow::Result<String> {
    eprint!("{question}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
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
    approval: Option<String>,
    no_agent_self: bool,
    bound: Vec<String>,
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
            bound,
            person_key,
            approval,
            no_agent_self_approval,
        } => {
            let bounds = bounds_of(bound)?;
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
            let mut body = body;
            if approval.is_some() || *no_agent_self_approval {
                body["approval"] = json!({
                    "operations": approval_operations(approval.as_deref().unwrap_or("none")),
                    "agent_self": !no_agent_self_approval,
                });
            }
            if let Some(b) = bounds {
                body["bounds"] = b;
            }
            let created = create_claimed(local, person_key.as_deref(), body, None)
                .await?
                .0;
            print_warnings(&created);
            created
        }
        CapabilityCommand::Approval {
            name,
            mode,
            agent_self,
            no_agent_self,
        } => {
            if *agent_self && *no_agent_self {
                bail!("--agent-self and --no-agent-self cannot be given together");
            }
            let mut body = json!({ "operations": approval_operations(mode) });
            if *agent_self || *no_agent_self {
                body["agent_self"] = json!(*agent_self);
            }
            local
                .put(format!("/v1/capabilities/{}/approval", encoded(name)), body)
                .await?
        }
        CapabilityCommand::Login {
            name,
            scopes,
            client_id,
            client_secret_file,
            port,
            no_browser,
            account,
        } => {
            let flags = crate::sign_in_cli::SignIn {
                scopes: scopes.as_deref(),
                client_id: client_id.as_deref(),
                client_secret_file: client_secret_file.as_deref(),
                port: *port,
                no_browser: *no_browser,
                account: account.as_deref().filter(|a| !a.is_empty()),
            };
            crate::sign_in_cli::capability_login(local, name, &flags).await?
        }
        CapabilityCommand::Logout { name } => {
            crate::sign_in_cli::capability_logout(local, name).await?
        }
        CapabilityCommand::List { json } => {
            let value = local.get("/v1/capabilities?lookup=true".into()).await?;
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
                .get(format!("/v1/capabilities/{}?lookup=true", encoded(name)))
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
    // Every stored policy holding this host's rule, claim included, of any
    // person and in every network, also where this host is no longer
    // bound. Any failure keeps the record.
    let networks = current_networks(local).await?;
    let mut holders: Vec<(String, String, String)> = Vec::new();
    for n in networks {
        let network = n["id"].as_str().context("invalid current network")?;
        let people = current_people(local, network).await?;
        for p in people.as_array().context("invalid current persons")? {
            let person = p["person_id"]
                .as_str()
                .context("invalid current person ID")?;
            let key = p["person_public_key"]
                .as_str()
                .context("invalid current person key")?;
            if read_policy(local, network, person, key)
                .await?
                .is_some_and(|(_, b)| {
                    b.capability_rules
                        .as_ref()
                        .into_iter()
                        .flatten()
                        .any(|r| r.host == host && r.capability == name)
                })
            {
                holders.push((
                    network.into(),
                    person.into(),
                    p["member"].as_str().unwrap_or(person).into(),
                ));
            }
        }
    }
    let mut signed = Vec::new();
    let mut other_holders = Vec::new();
    if !holders.is_empty() {
        let explicit_person = person_key
            .map(|path| PersonSigner::open(Some(path)))
            .transpose()?
            .map(|signer| persons::person_id(&signer.public_key()));
        for (network, person, label) in &holders {
            if explicit_person.as_ref().is_some_and(|p| p != person) {
                other_holders.push(format!("{label} ({person}) in network {network}"));
                continue;
            }
            if explicit_person.is_none() && me_in(local, network).await?.1 != *person {
                other_holders.push(format!("{label} ({person}) in network {network}"));
                continue;
            }
            let signer = PolicySigner::open(local, network, person_key).await?;
            let me = persons::person_id(&signer.public_key());
            if *person != me {
                other_holders.push(format!("{label} ({person}) in network {network}"));
                continue;
            }
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
    if !other_holders.is_empty() {
        bail!(
            "the policies of {} hold this host's rule for {name}; run capability remove again with those persons' keys (--person-key)",
            other_holders.join(", ")
        );
    }
    let removed = crate::delete(local.0, format!("/v1/capabilities/{}", encoded(name))).await?;
    Ok(json!({"capability": removed, "policies": signed}))
}

/// This host's person label and ID in a network.
async fn me_in(local: &Local<'_>, network: &str) -> anyhow::Result<(String, String)> {
    if let Some(view) = crate::decentralized_policy_cli::network_view(local, network).await? {
        let key = view["person_public_key"]
            .as_str()
            .context("invalid current own person")?;
        if key == "-" {
            return Ok((String::new(), String::new()));
        }
        let people = crate::decentralized_policy_cli::current_persons(local, &view).await?;
        let p = people
            .iter()
            .find(|p| p["person_public_key"] == key)
            .context("current own person proof required")?;
        return Ok((
            p["member"]
                .as_str()
                .context("invalid current label")?
                .into(),
            persons::person_id(&STANDARD.decode(key)?),
        ));
    }
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
    let signer = PolicySigner::open(local, network, person_key).await?;
    let (principal, found) = recipient(local, network, with).await?;
    let recipient_view = recipient_object(found.as_ref());
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
            // The guided share creates the capability with its claims, so
            // its network must be one where this host is bound to the
            // signing person; it checks before creating anything.
            let me = persons::person_id(&signer.public_key());
            if !bound_networks(local)
                .await?
                .iter()
                .any(|(n, p)| n == network && *p == me)
            {
                bail!(
                    "this host is not bound to the person of that key ({me}) in network {network}; the guided share needs that binding"
                );
            }
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
                            if s["shareable"] == true || s["reason"] == "login" {
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
            let (agent, server, mut source) = source_of(local, &from).await?;
            // A source that needs a sign-in gets it first, at a terminal.
            if source["reason"] == "login" {
                if !terminal {
                    bail!(
                        "{agent}/{server} needs a sign-in first: run peerspan sources login {agent}/{server}"
                    );
                }
                let flags = crate::sign_in_cli::SignIn {
                    scopes: None,
                    client_id: None,
                    client_secret_file: None,
                    port: None,
                    no_browser: false,
                    account: None,
                };
                crate::sign_in_cli::sign_in(local, &agent, &server, None, &flags).await?;
                source = source_of(local, &format!("{agent}/{server}")).await?.2;
            }
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
            // Right after the operations: whether calls to tools that can
            // change things wait for the person's approval.
            let changing_selected = operations
                .as_deref()
                .map(list_of)
                .unwrap_or_default()
                .iter()
                .any(|op| {
                    source["tools"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|t| t["name"].as_str() == Some(op) && t["read_only"] != true)
                });
            let approval_ops = match &guided.approval {
                Some(mode) => approval_operations(mode),
                None if terminal && changing_selected => {
                    eprint!(
                        "Require your approval for each call to tools that can change things? [Y/n] "
                    );
                    std::io::stderr().flush()?;
                    let mut line = String::new();
                    std::io::stdin().lock().read_line(&mut line)?;
                    if matches!(line.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes") {
                        json!("changing")
                    } else {
                        json!("none")
                    }
                }
                None => json!("none"),
            };
            let requirement =
                json!({"operations": approval_ops, "agent_self": !guided.no_agent_self});
            let cap_name = match guided.name.clone() {
                Some(n) => n,
                None if terminal => prompt("Capability name", Some(&server))?,
                None => server.clone(),
            };
            let mut bounds = bounds_of(&guided.bound)?;
            if bounds.is_none() && terminal {
                let words: Vec<String> = if source["adapter"].as_str() == Some("gh") {
                    ask_line("Limit which repositories? Enter OWNER/REPO, several separated by spaces, or leave empty for no limit: ")?
                        .split_whitespace()
                        .map(|w| format!("repo={w}"))
                        .collect()
                } else {
                    ask_line("Limit by argument values? Enter KEY=VALUE[,KEY=VALUE] combinations separated by spaces, or leave empty for no limit: ")?
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect()
                };
                bounds = bounds_of(&words)?;
            }
            let mut body = create_body(
                &cap_name,
                &agent,
                &server,
                operations.as_deref(),
                resources.as_deref(),
                guided.env_file.clone(),
                &guided.args,
            );
            body["approval"] = requirement.clone();
            if let Some(b) = &bounds {
                body["bounds"] = b.clone();
            }
            let preview = json!({
                "approval": requirement,
                "name": cap_name,
                "source": {"agent": agent, "server": server},
                "operations": body["operations"],
                "resources": body["resources"],
                "credential": {"env_file": body["env_file"], "args": body.get("args")},
                "bounds": bounds.clone().unwrap_or_else(|| json!({})),
                "draft": true,
            });
            (preview, Some(body))
        }
    };
    let cap = record["name"].as_str().unwrap_or_default().to_owned();
    // The review reads the stored policy; the edit starts from the edit
    // route after confirmation.
    let me = persons::person_id(&signer.public_key());
    let current = read_policy(local, network, &me, &signer.public_key_b64()).await?;
    let content = current
        .as_ref()
        .map(|(_, p)| p.content())
        .unwrap_or_default();
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
    let gh = source_view["adapter"].as_str() == Some("gh");
    for line in bounds_block(&record, &source_view, gh) {
        eprintln!("{line}");
    }
    for line in approval_review(&record, &cap, &read_only) {
        eprintln!("{line}");
    }
    let (auth, own) = if record["draft"] == true {
        (source_view["auth"].clone(), false)
    } else {
        (record["auth"].clone(), record["auth"]["own"] == true)
    };
    match crate::sign_in_cli::credential_text(
        &source_view,
        &auth,
        own,
        record["credential"]["env_file"].as_str(),
        record["source"]["agent"].as_str().unwrap_or_default(),
        &cap,
    ) {
        Some(text) => eprintln!("Credential: {text}"),
        None => match record["credential"]["env_file"].as_str() {
            Some(file) => eprintln!("Credentials: the capability's environment file {file}"),
            None => eprintln!("Credentials: the source's own environment on this host"),
        },
    }
    let persons = current_people(local, network).await?;
    let shown = match &found {
        Some(f) => f["address"].as_str().unwrap_or(with).to_owned(),
        None => with.to_owned(),
    };
    match &found {
        Some(f) => {
            eprintln!("Recipient: {shown}");
            recipient_lines(f, &persons);
        }
        None => eprintln!("Recipient: {shown} ({principal})"),
    }
    if let (Some((old, new)), Some(r)) = (limit_change, &existing) {
        // Recipients by label where the principal resolves to one, as in
        // `shares`, falling back to the principal.
        let persons = current_people(local, network).await?;
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
    // A draft with its own credential has not been checked yet.
    let reach = if record["draft"] == true {
        if record["credential"]["env_file"].is_string() {
            Value::Null
        } else {
            source_view["reach"].clone()
        }
    } else {
        record["credential_reach"].clone()
    };
    let sentence = peerspan_host::gh::sentence(Some(&reach), source_view["account"].as_str());
    eprintln!(
        "{}",
        reach_statement(&shown, gh, &record["bounds"], &sentence)
    );
    agent_review(&principal, &persons, &me, &content);
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
            json!({"policy": current.as_ref().map(|(v,_)|v), "capability": cap, "principal": principal, "recipient": recipient_view, "created": false}),
        );
    }
    let mut created_now = false;
    if let Some(body) = draft {
        // The guided share creates the capability with its claims: the
        // share in this network, the claim in the others.
        let (created, shared) = create_claimed(
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
        print_warnings(&created);
        let policy = read_policy(local, network, &me, &signer.public_key_b64())
            .await?
            .map(|(v, _)| v)
            .unwrap_or(Value::Null);
        if shared {
            return Ok(
                json!({"policy": policy, "capability": cap, "principal": principal, "recipient": recipient_view, "created": true}),
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
    Ok(
        json!({"policy": policy, "capability": cap, "principal": principal, "recipient": recipient_view, "created": created_now}),
    )
}

/// The `HOST_ID/NAME` address that removes a found agent recipient, from
/// its principal and label (`PERSON/NAME` or `HOST_ID/NAME`), or `None`
/// when the label names no agent.
fn removal_address(principal: &str, label: Option<&str>) -> Option<String> {
    let (host, _) = principal.strip_prefix("agent:")?.split_once('/')?;
    let name = label?.rsplit('/').next()?;
    peerspan_host::directory::addressable(name).then(|| format!("{host}/{name}"))
}

/// The `recipient` object of `share` and `unshare` output: from the lookup
/// for an agent address, null otherwise.
fn recipient_object(found: Option<&Value>) -> Value {
    match found {
        Some(f) => json!({
            "address": f["address"],
            "host_id": f["host_id"],
            "agent_id": f["agent_id"],
            "person_id": f["person_id"],
        }),
        None => Value::Null,
    }
}

/// The person (`person_id`, `member`) a host is bound to among a network's
/// persons, if any.
fn host_person<'a>(persons: &'a Value, host: &str) -> Option<&'a Value> {
    persons.as_array().into_iter().flatten().find(|p| {
        p["hosts"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|h| h.as_str() == Some(host))
    })
}

/// The review's lines under the recipient for an agent address.
fn recipient_lines(found: &Value, persons: &Value) {
    let host = found["host_id"].as_str().unwrap_or_default();
    let agent = found["agent_id"].as_str().unwrap_or_default();
    match host_person(persons, host).filter(|_| !found["person_id"].is_null()) {
        Some(p) => eprintln!(
            "  agent {agent} on host {host}, bound to {}",
            p["member"].as_str().unwrap_or_default()
        ),
        None => eprintln!("  agent {agent} on host {host}, not bound to a person"),
    }
    let unanswered: Vec<String> = found["unanswered"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|u| {
            format!(
                "{} ({})",
                u["host_id"].as_str().unwrap_or_default(),
                u["error"].as_str().unwrap_or_default()
            )
        })
        .collect();
    if !unanswered.is_empty() {
        eprintln!("Not checked: {}", unanswered.join(", "));
    }
}

/// The review's agent paragraph for an `agent:` principal, and the note
/// for the signer's own agent on a trusted host.
fn agent_review(principal: &str, persons: &Value, me: &str, content: &Content) {
    let Some((host, _)) = principal
        .strip_prefix("agent:")
        .and_then(|p| p.split_once('/'))
    else {
        return;
    };
    eprintln!("Only calls that {host} says come from this agent are allowed.");
    let person = host_person(persons, host);
    match person.and_then(|p| p["member"].as_str()) {
        Some(label) => eprintln!(
            "That host makes the claim itself: {label}, and any program that can run peerspan as {label} on that machine, can call as this agent. {label}'s other machines and other agents, and other people, cannot."
        ),
        None => eprintln!(
            "That host makes the claim itself: anyone, and any program, that can run peerspan as that host's owner can call as this agent. Other machines, other agents, and other people cannot."
        ),
    }
    eprintln!(
        "The share stays with this agent on this machine. If the agent is set up again on another machine, share it again."
    );
    if person.is_some_and(|p| p["person_id"].as_str() == Some(me))
        && content.trusted_hosts.iter().any(|h| h == host)
    {
        eprintln!(
            "This machine is trusted, so this agent already reaches all your capabilities through self access. This share matters only if you untrust it."
        );
    }
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
    let signer = PolicySigner::open(local, network, person_key).await?;
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let persons = current_people(local, network).await?;
    let (principal, found) = match recipient(local, network, with).await {
        Ok(r) => r,
        Err(e)
            if e.downcast_ref::<crate::integration::DaemonError>()
                .is_some_and(|d| d.code == "unknown" || d.code == "unknown_host") =>
        {
            // A gone agent can always be removed by its principal.
            eprintln!("error: {e}");
            agent_fallback(local, network, &persons, &host, name, with, &signer).await;
            std::process::exit(1);
        }
        Err(e) => return Err(e),
    };
    let recipient_view = recipient_object(found.as_ref());
    let mut removed = 0;
    let mut left: Vec<String> = Vec::new();
    let (current, policy) = edit_policy(local, network, &signer, |content| {
        removed = 0;
        for r in content.capability_rules.iter_mut() {
            if r.host == host && r.capability == name && r.principals.contains(&principal) {
                r.principals.retain(|p| *p != principal);
                left = r.principals.clone();
                removed += 1;
            }
        }
        // A rule left without principals stays as the name's claim.
        Ok(removed > 0)
    })
    .await?;
    let Some(policy) = policy else {
        let note = match &found {
            None => format!(
                "{principal} is not in the share of {name}; access through a group or everyone is unaffected, and block stops a person at once"
            ),
            Some(f) => {
                let person = host_person(&persons, f["host_id"].as_str().unwrap_or_default())
                    .filter(|_| !f["person_id"].is_null())
                    .and_then(|p| p["member"].as_str());
                match person {
                    Some(label) => format!(
                        "the rule for {name} on this host does not name {principal}. Access through person:{label}, a group, or everyone is unaffected."
                    ),
                    None => format!(
                        "the rule for {name} on this host does not name {principal}. Access through a group or everyone is unaffected."
                    ),
                }
            }
        };
        return Ok(json!({
            "policy": current,
            "capability": name,
            "principal": principal,
            "recipient": recipient_view,
            "removed": 0,
            "note": note,
        }));
    };
    eprintln!(
        "{principal}'s future calls to {name} are denied. Calls already running finish; queued calls are refused when they would start."
    );
    let mut out = json!({"policy": policy, "capability": name, "principal": principal, "recipient": recipient_view, "removed": removed});
    if let Some(person) = principal.strip_prefix("person:") {
        let note = agents_left_note(local, network, &persons, person, &left, name).await;
        if !note.is_empty() {
            out["note"] = json!(note);
        }
    }
    Ok(out)
}

/// After a failed agent resolution in `unshare`: the rule's agent
/// principals on the address's hosts, each with its command.
async fn agent_fallback(
    local: &Local<'_>,
    network: &str,
    persons: &Value,
    host: &str,
    name: &str,
    with: &str,
    signer: &impl PolicySigning,
) {
    let Ok(Some((left, _))) = peerspan_host::agent_lookup::split_agent_address(with) else {
        return;
    };
    let hosts: Vec<String> = if left.starts_with("host_") {
        vec![left.to_owned()]
    } else {
        persons
            .as_array()
            .into_iter()
            .flatten()
            .find(|p| {
                p["person_id"].as_str() == Some(left)
                    || p["member"]
                        .as_str()
                        .is_some_and(|m| m.eq_ignore_ascii_case(left))
            })
            .map(|p| {
                p["hosts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|h| h.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    // A host no longer in the network may have been the person's: its
    // binding is gone with it.
    let members: Vec<String> = local
        .get(format!("/v1/networks/{}/members", encoded(network)))
        .await
        .ok()
        .and_then(|m| m.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|m| m["host_id"].as_str().map(str::to_owned))
        .collect();
    let by_person = !left.starts_with("host_");
    let me = persons::person_id(&signer.public_key());
    let Ok(policy) = local
        .get(format!(
            "/v1/networks/{}/policy?person={}",
            encoded(network),
            encoded(&me)
        ))
        .await
    else {
        return;
    };
    let mut lines = Vec::new();
    for r in policy["capability_rules"].as_array().into_iter().flatten() {
        if r["host"].as_str() != Some(host) || r["capability"].as_str() != Some(name) {
            continue;
        }
        for p in r["principals"].as_array().into_iter().flatten() {
            let Some(p) = p.as_str() else { continue };
            if let Some((h, _)) = p.strip_prefix("agent:").and_then(|x| x.split_once('/'))
                && (hosts.iter().any(|x| x == h) || (by_person && !members.iter().any(|x| x == h)))
            {
                lines.push(format!(
                    "  {p}: peerspan unshare {name} --with {p} --network {network}"
                ));
            }
        }
    }
    if !lines.is_empty() {
        eprintln!(
            "Agent shares of {name} on those hosts:\n{}",
            lines.join("\n")
        );
    }
}

/// `unshare --with PERSON`'s note for the agents on that person's hosts
/// that still have their own share.
async fn agents_left_note(
    local: &Local<'_>,
    network: &str,
    persons: &Value,
    person: &str,
    left: &[String],
    name: &str,
) -> String {
    let Some(p) = persons
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["person_id"].as_str() == Some(person))
    else {
        return String::new();
    };
    let hosts: Vec<&str> = p["hosts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let agents: Vec<&String> = left
        .iter()
        .filter(|x| {
            x.strip_prefix("agent:")
                .and_then(|x| x.split_once('/'))
                .is_some_and(|(h, _)| hosts.contains(&h))
        })
        .collect();
    if agents.is_empty() {
        return String::new();
    }
    let view = local
        .get(format!("/v1/capabilities/{}?lookup=true", encoded(name)))
        .await
        .unwrap_or(Value::Null);
    agents
        .iter()
        .map(|principal| {
            let found = view["recipients"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| {
                    r["network_id"].as_str() == Some(network)
                        && r["principal"].as_str() == Some(principal.as_str())
                        && r["agent_state"] == "found"
                })
                .and_then(|r| {
                    let label = r["label"].as_str()?;
                    Some((label.to_owned(), removal_address(principal, Some(label))?))
                });
            let (label, address) =
                found.unwrap_or_else(|| (principal.to_string(), principal.to_string()));
            format!(
                "{label} still has its own share. Run peerspan unshare {name} --with {address} --network {network} to remove it."
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `shares`: every capability here and every capability rule in this
/// person's stored policies.
async fn shares(local: &Local<'_>, network: Option<&str>) -> anyhow::Result<Value> {
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let capabilities = local.get("/v1/capabilities?lookup=true".into()).await?;
    let networks = current_networks(local).await?;
    let sources = sources_view(local).await.unwrap_or(Value::Null);
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
                // An agent found on its host is removed by its host's
                // address, HOST_ID/NAME, which names exactly that agent.
                let principal = r["principal"].as_str().unwrap_or_default().to_owned();
                let with = match r["agent_state"].as_str() {
                    Some("found") => removal_address(&principal, r["label"].as_str())
                        .unwrap_or_else(|| principal.clone()),
                    _ => principal.clone(),
                };
                r["unshare"] = json!(format!(
                    "peerspan unshare {name} --with {with} --network {}",
                    r["network_id"].as_str().unwrap_or_default()
                ));
                r
            })
            .collect();
        let builtin = (c["source"]["agent"].as_str() == Some("builtin"))
            .then(|| {
                sources["builtin"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|s| s["name"] == c["source"]["server"])
                    .cloned()
            })
            .flatten();
        let gh = builtin
            .as_ref()
            .is_some_and(|b| b["adapter"].as_str() == Some("gh"));
        let sentence = peerspan_host::gh::sentence(
            Some(&c["credential_reach"]),
            builtin.as_ref().and_then(|b| b["account"].as_str()),
        );
        let remote_source = sources["agents"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["agent"]["name"] == c["source"]["agent"])
            .flat_map(|a| a["servers"].as_array().cloned().unwrap_or_default())
            .find(|s| s["name"] == c["source"]["server"])
            .unwrap_or(Value::Null);
        let credential_text = crate::sign_in_cli::credential_text(
            &remote_source,
            &c["auth"],
            c["auth"]["own"] == true,
            c["credential"]["env_file"].as_str(),
            c["source"]["agent"].as_str().unwrap_or_default(),
            name,
        );
        entries.push(json!({
            "auth": c["auth"],
            "credential_text": credential_text,
            "bounds": c["bounds"],
            "reach": reach_statement("Recipients", gh, &c["bounds"], &sentence),
            "capability": name,
            "host": host,
            "source": c["source"],
            "operations": c["operations"],
            "resources": c["resources"],
            "credential": c["credential"],
            "state": c["state"],
            "unavailable": c["unavailable"],
            "approval": c["approval"],
            "recipients": recipients,
        }));
    }
    // Rules of this person for capabilities on other hosts.
    for n in &networks {
        let Some(id) = n["id"].as_str() else { continue };
        if network.is_some_and(|x| x != id) {
            continue;
        }
        let Some(person) = n["person"]["id"].as_str() else {
            continue;
        };
        let key =
            if let Some(view) = crate::decentralized_policy_cli::network_view(local, id).await? {
                view["person_public_key"]
                    .as_str()
                    .context("invalid current own person")?
                    .to_owned()
            } else {
                String::new()
            };
        let Some((_, policy)) = read_policy(local, id, person, &key).await? else {
            continue;
        };
        for r in policy.capability_rules.as_ref().into_iter().flatten() {
            let r = serde_json::to_value(r)?;

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
                "approval": null,
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

/// `discover --from-agent`: what that agent's `list_capabilities` shows.
async fn discover_as(
    local: &Local<'_>,
    agent: &str,
    person: Option<&str>,
    network: Option<&str>,
) -> anyhow::Result<Value> {
    let mut path = format!("/v1/discover?from_agent={}", encoded(agent));
    if let Some(p) = person {
        path.push_str(&format!("&person={}", encoded(p)));
    }
    if let Some(n) = network {
        path.push_str(&format!("&network={}", encoded(n)));
    }
    local.get(path).await
}

/// `--from-agent`: an agent ID registered on this host, or else the exact
/// name of one.
async fn local_agent_id(local: &Local<'_>, given: &str) -> anyhow::Result<String> {
    let agents = local.get("/v1/agents".into()).await?;
    let list = agents.as_array().cloned().unwrap_or_default();
    if list.iter().any(|a| a["id"].as_str() == Some(given)) {
        return Ok(given.to_owned());
    }
    let named: Vec<&str> = list
        .iter()
        .filter(|a| a["name"].as_str() == Some(given))
        .filter_map(|a| a["id"].as_str())
        .collect();
    match named.as_slice() {
        [] => bail!("no agent {given} on this host"),
        [one] => Ok((*one).to_owned()),
        _ => bail!("several agents on this host are named {given}; give the agent ID"),
    }
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
    let (mut from_agent, mut from_session): (Option<String>, Option<String>) = (None, None);
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
            "from-agent" => from_agent = Some(value),
            "from-session" => from_session = Some(value),
            key => keys.push((key.to_owned(), value)),
        }
    }
    if from_session.is_some() && from_agent.is_none() {
        bail!("--from-session needs --from-agent");
    }
    let origin = match &from_agent {
        Some(agent) => {
            let id = local_agent_id(local, agent).await?;
            let mut o = json!({"agent_id": id});
            if let Some(s) = &from_session {
                o["session_id"] = json!(s);
            }
            Some(o)
        }
        None => None,
    };
    let mut body_input = input.clone().unwrap_or_default();
    if !keys.is_empty() {
        // The schema comes from the capability listing.
        let owner = address.split('/').next().unwrap_or_default();
        let capability = address.split_once('/').map(|(_, c)| c).unwrap_or_default();
        // A call as an agent takes the schema from that agent's view.
        let listing = match &origin {
            Some(o) => {
                discover_as(
                    local,
                    o["agent_id"].as_str().unwrap_or_default(),
                    (!owner.starts_with("host_")).then_some(owner),
                    network.as_deref(),
                )
                .await?
            }
            None => {
                // A host ID is not a person: list every entry and match by host.
                discover(
                    local,
                    (!owner.starts_with("host_")).then_some(owner),
                    network.as_deref(),
                )
                .await?
            }
        };
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
    if let Some(o) = origin {
        body["origin"] = o;
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
    if code == 3 && record["status"]["approval"]["state"] == "pending" {
        // The PERSON of a PERSON/CAPABILITY address, otherwise the host ID.
        let owner = address.split('/').next().unwrap_or(&peer);
        eprintln!(
            "Waiting for {owner} to approve this call (until {}). Check it later with peerspan calls inspect --peer {peer} {id}.",
            record["status"]["approval"]["expires_at"]
                .as_str()
                .unwrap_or_default()
        );
    }
    crate::exit(code)
}

/// The readable layouts; not shared formats.
fn readable_sources(view: &Value) -> String {
    let mut out = String::new();
    for a in view["agents"].as_array().into_iter().flatten() {
        let agent = a["agent"]["name"].as_str().unwrap_or_default();
        out += &format!(
            "{agent} ({})\n",
            a["agent"]["id"].as_str().unwrap_or_default()
        );
        let servers = a["servers"].as_array().cloned().unwrap_or_default();
        if servers.is_empty() {
            out += "  no sources discovered\n";
        }
        for s in servers {
            let name = s["name"].as_str().unwrap_or_default();
            let state = match s["reason"].as_str() {
                None => "usable".to_owned(),
                Some(r) => {
                    let missing = list_text(&s["missing_env"]);
                    if missing.is_empty() {
                        format!("not usable: {r}")
                    } else {
                        format!("not usable: {r} ({missing})")
                    }
                }
            };
            out += &format!(
                "  {agent}/{name}  {}  from {}  {state}\n",
                s["transport"].as_str().unwrap_or_default(),
                s["source"].as_str().unwrap_or_default(),
            );
            if s["transport"] == "remote" {
                out += &crate::sign_in_cli::remote_lines(agent, &s);
            }
            if let Some(e) = s["snapshot_error"].as_str() {
                out += &format!("    snapshot failed: {e}\n");
            }
            for t in s["tools"].as_array().into_iter().flatten() {
                out += &format!(
                    "    tool {}{}\n",
                    t["name"].as_str().unwrap_or_default(),
                    if t["read_only"] == true {
                        " (read-only)"
                    } else {
                        " (can change things)"
                    }
                );
            }
            for r in s["resources"].as_array().into_iter().flatten() {
                out += &format!("    resource {}\n", r["uri"].as_str().unwrap_or_default());
            }
            let caps = list_text(&s["capabilities"]);
            if !caps.is_empty() {
                out += &format!("    capabilities: {caps}\n");
            }
        }
    }
    let builtin = view["builtin"].as_array().cloned().unwrap_or_default();
    if !builtin.is_empty() {
        out += "builtin\n";
    }
    for s in builtin {
        out += &format!(
            "  builtin/{}  gh {}  account {}  {}\n",
            s["name"].as_str().unwrap_or_default(),
            s["version"].as_str().unwrap_or("unknown"),
            s["account"].as_str().unwrap_or("unknown"),
            match s["reason"].as_str() {
                Some(r) => format!("not usable: {r}"),
                None => "usable".into(),
            }
        );
        if let Some(e) = s["snapshot_error"].as_str() {
            out += &format!("    snapshot failed: {e}\n");
        }
        for t in s["tools"].as_array().into_iter().flatten() {
            out += &format!(
                "    tool {}{}\n",
                t["name"].as_str().unwrap_or_default(),
                if t["read_only"] == true {
                    " (read-only)"
                } else {
                    " (can change things)"
                }
            );
        }
        let caps = list_text(&s["capabilities"]);
        if !caps.is_empty() {
            out += &format!("    capabilities: {caps}\n");
        }
        out += &format!(
            "    reach: {}\n",
            peerspan_host::gh::sentence(Some(&s["reach"]), s["account"].as_str())
        );
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
    let combinations = peerspan_host::bounds::of_record(&c["bounds"]);
    let bounds = if combinations.is_empty() {
        String::new()
    } else {
        format!(
            "  bounds: {}",
            peerspan_host::bounds::allowed(&combinations)
        )
    };
    format!(
        "{} from {}/{}: {}{} ({}) approval: {} {}{bounds}",
        c["name"].as_str().unwrap_or_default(),
        c["source"]["agent"].as_str().unwrap_or_default(),
        c["source"]["server"].as_str().unwrap_or_default(),
        list_text(&c["operations"]),
        if c["resources"].is_null() {
            ""
        } else {
            ", read"
        },
        c["state"].as_str().unwrap_or_default(),
        approval_mode(&c["approval"]["operations"]),
        if c["approval"]["agent_self"] == false {
            "-agent_self"
        } else {
            "+agent_self"
        }
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
        if let Some(text) = e["credential_text"].as_str() {
            out += &format!("  credential: {text}\n");
        }
        if let Some(reach) = e["reach"].as_str() {
            let combinations = peerspan_host::bounds::of_record(&e["bounds"]);
            out += &format!(
                "  bounds: {}\n  reach: {reach}\n",
                if combinations.is_empty() {
                    "none".to_owned()
                } else {
                    peerspan_host::bounds::allowed(&combinations)
                }
            );
        }
        for r in e["recipients"].as_array().into_iter().flatten() {
            let mark = match r["agent_state"].as_str() {
                None => "",
                Some("found") => " (agent)",
                Some(_) => " (agent, gone)",
            };
            out += &format!(
                "  {}{mark}{}\n",
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
        let ops: Vec<String> = c["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|o| {
                o["name"].as_str().map(|name| {
                    if o["approval"] == true {
                        format!("{name} (needs approval)")
                    } else {
                        name.to_owned()
                    }
                })
            })
            .collect();
        let only = match c["for_agents"].as_array() {
            Some(agents) => {
                let names: Vec<&str> = agents
                    .iter()
                    .filter_map(|a| a["name"].as_str().or(a["agent_id"].as_str()))
                    .collect();
                format!(
                    "   only for your {} {}",
                    if names.len() > 1 { "agents" } else { "agent" },
                    names.join(", ")
                )
            }
            None => String::new(),
        };
        out += &format!(
            "{} {}: {}{only}\n",
            c["kind"].as_str().unwrap_or_default(),
            c["address"].as_str().unwrap_or_default(),
            ops.join(", ")
        );
        let combinations = peerspan_host::bounds::of_record(&c["bounds"]);
        if !combinations.is_empty() {
            out += &format!(
                "    limited to {}\n",
                peerspan_host::bounds::allowed(&combinations)
            );
        }
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

/// `--approval MODE` and `capability approval NAME MODE`: `none`,
/// `changing`, `all`, or `OP[,OP...]` as a list.
fn approval_operations(mode: &str) -> Value {
    match mode {
        "none" | "changing" | "all" => json!(mode),
        list => json!(list_of(list)),
    }
}
/// `none`, `changing`, `all`, or the list joined with `,`.
fn approval_mode(operations: &Value) -> String {
    match operations {
        Value::String(mode) => mode.clone(),
        Value::Array(_) => list_text(operations).replace(", ", ","),
        _ => "none".into(),
    }
}
/// The review's approval lines, in the order of the record's operations
/// followed by `read`.
fn approval_review(record: &Value, name: &str, read_only: &dyn Fn(&str) -> bool) -> Vec<String> {
    let tools: Vec<&str> = record["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut every = tools.clone();
    if !record["resources"].is_null() {
        every.push("read");
    }
    let operations = &record["approval"]["operations"];
    let changing = operations == "changing";
    let covered: Vec<&str> = match operations {
        Value::String(mode) if mode == "all" => every.clone(),
        Value::String(mode) if mode == "changing" => {
            tools.iter().copied().filter(|op| !read_only(op)).collect()
        }
        Value::Array(list) => every
            .iter()
            .copied()
            .filter(|op| list.iter().any(|l| l.as_str() == Some(op)))
            .collect(),
        _ => Vec::new(),
    };
    let mut out = Vec::new();
    if operations == "all" {
        out.push("Every call waits for your approval at this machine (peerspan approvals).".into());
    } else if !covered.is_empty() {
        out.push(format!(
            "Calls to {} wait for your approval at this machine (peerspan approvals).",
            covered.join(", ")
        ));
    } else if tools.iter().any(|op| !read_only(op)) {
        out.push(format!(
            "No call waits for your approval. To require it: peerspan capability approval {name} changing"
        ));
    }
    if changing {
        out.push(
            "Tools are marked by the server itself; a tool it wrongly marks read-only runs without approval."
                .into(),
        );
    }
    out
}

/// Writes every character below U+0020, U+007F, and U+0080 to U+009F as
/// `\u` and four lowercase hex digits, so caller-supplied text carries no
/// terminal escape sequence.
fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if (c as u32) < 0x20 || c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
/// The input pretty-printed as JSON, its strings escaped as `escaped`
/// does, and `"` and `\` as in JSON.
fn pretty_input(value: &Value, indent: usize, out: &mut String) {
    let pad = |n: usize| "  ".repeat(n);
    let string = |s: &str| {
        let mut text = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => text.push_str("\\\""),
                '\\' => text.push_str("\\\\"),
                c => text.push_str(&escaped(&c.to_string())),
            }
        }
        text.push('"');
        text
    };
    match value {
        Value::Object(map) if !map.is_empty() => {
            out.push_str("{\n");
            for (i, (k, v)) in map.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                out.push_str(&string(k));
                out.push_str(": ");
                pretty_input(v, indent + 1, out);
                if i + 1 < map.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad(indent));
            out.push('}');
        }
        Value::Array(list) if !list.is_empty() => {
            out.push_str("[\n");
            for (i, v) in list.iter().enumerate() {
                out.push_str(&pad(indent + 1));
                pretty_input(v, indent + 1, out);
                if i + 1 < list.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad(indent));
            out.push(']');
        }
        Value::String(s) => out.push_str(&string(s)),
        other => out.push_str(&other.to_string()),
    }
}
/// The caller as the readable output names it, escaped.
fn caller_text(a: &Value) -> String {
    let caller = &a["caller"];
    let mut text = match caller["person_label"].as_str() {
        Some(label) => format!(
            "{} ({})",
            escaped(label),
            caller["host_id"].as_str().unwrap_or_default()
        ),
        None => caller["host_id"].as_str().unwrap_or_default().to_owned(),
    };
    if let Some(agent) = a["origin"]["agent_id"].as_str() {
        text.push_str(&format!(", agent {}", escaped(agent)));
    }
    text
}
/// One readable line per approval.
fn readable_approval(a: &Value) -> String {
    format!(
        "{}/{} {} {} {}{} from {} until {}{}",
        escaped(a["sender_host_id"].as_str().unwrap_or_default()),
        escaped(a["call_id"].as_str().unwrap_or_default()),
        a["state"].as_str().unwrap_or_default(),
        escaped(a["capability"].as_str().unwrap_or_default()),
        escaped(a["operation"].as_str().unwrap_or_default()),
        if a["changes_things"] == true {
            " (can change things)"
        } else {
            ""
        },
        caller_text(a),
        escaped(a["expires_at"].as_str().unwrap_or_default()),
        match a["input_preview"].as_str() {
            Some(p) => format!(" input {}", escaped(p)),
            None => String::new(),
        }
    )
}
/// `approvals show` and `approve`: the approval, the capability's source
/// and credential context while it exists, and the whole input.
async fn readable_approval_show(local: &Local<'_>, a: &Value) -> String {
    let mut out = format!(
        "Call {}/{}: {}\n",
        escaped(a["sender_host_id"].as_str().unwrap_or_default()),
        escaped(a["call_id"].as_str().unwrap_or_default()),
        a["state"].as_str().unwrap_or_default()
    );
    let capability = a["capability"].as_str().unwrap_or_default();
    out += &format!(
        "A call to {} ({}){} from {}, via {}\n",
        escaped(capability),
        escaped(a["operation"].as_str().unwrap_or_default()),
        if a["changes_things"] == true {
            ", which can change things,"
        } else {
            ""
        },
        caller_text(a),
        escaped(a["caller"]["via"].as_str().unwrap_or_default())
    );
    if let Some(person) = a["caller"]["person_id"].as_str() {
        out += &format!("Caller person: {}\n", escaped(person));
    }
    if let Some(session) = a["origin"]["session_id"].as_str() {
        out += &format!("Caller session: {}\n", escaped(session));
    }
    out += &format!(
        "Requested at {}, expires at {}\n",
        escaped(a["requested_at"].as_str().unwrap_or_default()),
        escaped(a["expires_at"].as_str().unwrap_or_default())
    );
    if let Some(decided) = a["decided_at"].as_str() {
        out += &format!("Decided at {}\n", escaped(decided));
    }
    if let Some(reason) = a["reason"].as_str() {
        out += &format!("Reason: {}\n", escaped(reason));
    }
    if let Ok(c) = local
        .get(format!("/v1/capabilities/{}", encoded(capability)))
        .await
    {
        out += &format!(
            "Source: {}/{}\n",
            c["source"]["agent"].as_str().unwrap_or_default(),
            c["source"]["server"].as_str().unwrap_or_default()
        );
        let env_file = c["credential"]["env_file"].as_str();
        let args = c["credential"]["args"].as_array();
        if env_file.is_some() || args.is_some() {
            out += &format!(
                "Credentials: the capability's own environment file {}",
                escaped(env_file.unwrap_or_default())
            );
            if let Some(args) = args {
                let args: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
                out += &format!(", with arguments {}", escaped(&args.join(" ")));
            }
            out.push('\n');
        } else {
            out += "Credentials: the source's own environment on this host\n";
        }
    }
    match &a["input"] {
        Value::Null => out += "Input: deleted\n",
        input => {
            out += &format!(
                "Input ({} bytes):\n",
                a["input_bytes"].as_u64().unwrap_or_default()
            );
            let mut text = String::new();
            pretty_input(input, 0, &mut text);
            out += &text;
            out.push('\n');
        }
    }
    out
}

/// An approval ID as `(SENDER_HOST_ID, CALL_ID)`: the full form as given,
/// or a bare call ID resolved by the daemon.
async fn resolve_approval(local: &Local<'_>, id: &str) -> anyhow::Result<(String, String)> {
    if !approval_id(id) {
        bail!(
            "an approval ID is a call ID (call_ and 32 lowercase hex digits) or SENDER_HOST_ID/CALL_ID"
        );
    }
    if let Some((sender, call)) = id.split_once('/') {
        return Ok((sender.to_owned(), call.to_owned()));
    }
    let found = local.get(format!("/v1/approvals/{}", encoded(id))).await?;
    Ok((
        found["sender_host_id"]
            .as_str()
            .context("invalid daemon response")?
            .to_owned(),
        found["call_id"]
            .as_str()
            .context("invalid daemon response")?
            .to_owned(),
    ))
}
fn approval_path(sender: &str, id: &str) -> String {
    format!("/v1/approvals/{}/{}", encoded(sender), encoded(id))
}

/// `approvals [--all] [--json]` and `approvals show ID [--json]`.
async fn approvals(local: &Local<'_>, args: &ApprovalsArgs) -> anyhow::Result<Option<Value>> {
    if let Some(ApprovalsCommand::Show { id, json }) = &args.command {
        let (sender, call) = resolve_approval(local, id).await?;
        let value = local.get(approval_path(&sender, &call)).await?;
        if *json {
            return Ok(Some(value));
        }
        print!("{}", readable_approval_show(local, &value).await);
        crate::exit(0)
    }
    let state = if args.all { "all" } else { "pending" };
    let value = local.get(format!("/v1/approvals?state={state}")).await?;
    if args.json {
        return Ok(Some(value));
    }
    let list = value["approvals"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("No calls are waiting for your approval.");
    }
    for a in &list {
        println!("{}", readable_approval(a));
    }
    crate::exit(0)
}

/// `approve ID`: at a terminal only, after showing the call and asking.
async fn approve(local: &Local<'_>, id: &str) -> anyhow::Result<Value> {
    if !std::io::stdin().is_terminal() {
        bail!("peerspan approve needs a terminal: approval must come from the person.");
    }
    let (sender, call) = resolve_approval(local, id).await?;
    let path = approval_path(&sender, &call);
    let shown = local.get(path.clone()).await?;
    eprint!("{}", readable_approval_show(local, &shown).await);
    // An approval no longer pending is sent as is; its 409 exits 1.
    if shown["state"] == "pending"
        && !ask(
            "Approve this call? It runs once, with the credentials it runs with on this machine. [y/N] ",
        )?
    {
        bail!("not approved; nothing changed");
    }
    local.post(format!("{path}/approve"), json!({})).await
}
