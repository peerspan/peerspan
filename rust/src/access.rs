//! Owner access policy commands that sign. The CLI fetches the owner's
//! current policy from the daemon, edits its rules, and signs the next
//! version with the person key; the daemon verifies and submits it and never
//! sees the key.
use crate::{
    admin::{Local, person_key},
    cli::{AccessCommand, Command, encoded, resolved},
    integration::DaemonError,
};
use anyhow::{Context, bail};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use peerspan_host::{
    persons::{self, PersonSigner},
    policy::{ACTION, ALL_AGENTS, DELEGATE_ACTION, Policy, Rule, TASK_ACTION},
};
use serde_json::{Value, json};
use std::path::Path;

fn failed(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

pub async fn command(command: &AccessCommand, socket: &Path) -> anyhow::Result<Option<Value>> {
    let (network, person_key_path) = match command {
        AccessCommand::Allow {
            network,
            person_key,
            ..
        }
        | AccessCommand::Deny {
            network,
            person_key,
            ..
        }
        | AccessCommand::Renew {
            network,
            person_key,
        } => (network, person_key),
        _ => return Ok(None),
    };
    let network = resolved(network);
    let local = Local(socket);
    let signer = PersonSigner::open(person_key_path.as_deref()).map_err(failed)?;
    let me = persons::person_id(&signer.public_key());
    let path = format!("/v1/networks/{}/policy", encoded(network));
    let current: Option<Policy> = match local.get(format!("{path}?person={}", encoded(&me))).await {
        Ok(value) => Some(serde_json::from_value(strip_view(value))?),
        Err(e)
            if e.downcast_ref::<DaemonError>()
                .is_some_and(|d| d.status == 404) =>
        {
            None
        }
        Err(e) => return Err(e),
    };
    let now = Utc::now();
    // A new version keeps the current duration unless --valid-days is given.
    let mut duration = current
        .as_ref()
        .map(duration_of)
        .transpose()?
        .unwrap_or(TimeDelta::days(peerspan_host::policy::DEFAULT_VALID_DAYS));
    let mut rules = current
        .as_ref()
        .map(|p| p.rules.clone())
        .unwrap_or_default();
    match command {
        AccessCommand::Allow {
            agent,
            principal,
            max_message_bytes,
            allow_disconnected,
            valid_days,
            actions,
            max_artifact_bytes,
            ..
        } => {
            let mut principals = Vec::new();
            for given in principal {
                let resolved = resolve(&local, network, given).await?;
                if !principals.contains(&resolved) {
                    principals.push(resolved);
                }
            }
            let rule = Rule {
                agent: agent.clone(),
                principals,
                actions: if actions.is_empty() {
                    vec![ACTION.into()]
                } else {
                    let mut unique = Vec::new();
                    for a in actions {
                        if !unique.contains(a) {
                            unique.push(a.clone());
                        }
                    }
                    unique
                },
                max_message_bytes: *max_message_bytes,
                allow_disconnected: *allow_disconnected,
                max_artifact_bytes: *max_artifact_bytes,
            };
            // Several rules for the agent become one, at the first's place.
            match rules.iter().position(|r| r.agent == *agent) {
                Some(first) => {
                    rules[first] = rule;
                    let mut index = 0;
                    rules.retain(|r| {
                        index += 1;
                        index - 1 == first || r.agent != *agent
                    });
                }
                None => rules.push(rule),
            }
            duration = TimeDelta::days(*valid_days);
        }
        AccessCommand::Deny {
            agent, principal, ..
        } => {
            if current.is_none() {
                bail!("you have no policy in this network");
            }
            if !rules.iter().any(|r| r.agent == *agent) {
                bail!("your policy has no rule for agent {agent:?}");
            }
            if principal.is_empty() {
                rules.retain(|r| r.agent != *agent);
            } else {
                let mut removed = Vec::new();
                for given in principal {
                    removed.push(resolve(&local, network, given).await?);
                }
                for rule in rules.iter_mut().filter(|r| r.agent == *agent) {
                    rule.principals.retain(|p| !removed.contains(p));
                }
                rules.retain(|r| r.agent != *agent || !r.principals.is_empty());
            }
        }
        AccessCommand::Renew { .. } => {
            if current.is_none() {
                bail!("you have no policy in this network");
            }
        }
        _ => unreachable!("not a signing access command"),
    }
    let version = current.as_ref().map_or(0, |p| p.version) + 1;
    let policy = Policy::sign(
        &signer,
        network,
        version,
        &at(now),
        &at(now + duration),
        rules,
    )
    .map_err(failed)?;
    Ok(Some(local.post(path, json!({ "policy": policy })).await?))
}

fn at(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// `access show` adds `expires_soon` beside the policy fields.
fn strip_view(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("expires_soon");
    }
    value
}

fn duration_of(p: &Policy) -> anyhow::Result<TimeDelta> {
    let issued = DateTime::parse_from_rfc3339(&p.issued_at)?;
    let until = DateTime::parse_from_rfc3339(&p.valid_until)?;
    Ok(until - issued)
}

/// Resolves `person:LABEL` (or a public key) to `person:<ID>`, erroring on an
/// ambiguous label. Other principals pass through for the daemon to check.
async fn resolve(local: &Local<'_>, network: &str, given: &str) -> anyhow::Result<String> {
    let Some(person) = given.strip_prefix("person:") else {
        return Ok(given.to_owned());
    };
    if is_person_id(person) {
        return Ok(given.to_owned());
    }
    let key = synced_person_key(local, network, person).await?;
    Ok(format!(
        "person:{}",
        persons::person_id_of(&key).map_err(failed)?
    ))
}

/// Resolves a person as `person_key` does, but when it is not a current
/// person, syncs the network once and resolves again before failing: a
/// person admitted moments ago elsewhere may not have reached this host yet.
async fn synced_person_key(
    local: &Local<'_>,
    network: &str,
    given: &str,
) -> anyhow::Result<String> {
    let first = person_key(local, network, given).await;
    match &first {
        Err(e) if e.to_string().starts_with("no current person") => {
            // A failed sync leaves the first answer.
            if local
                .post(format!("/v1/networks/{}/sync", encoded(network)), json!({}))
                .await
                .is_err()
            {
                return first;
            }
            person_key(local, network, given).await
        }
        _ => first,
    }
}

fn is_person_id(value: &str) -> bool {
    value.strip_prefix("person_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The largest `--files` bound: 1 GiB.
const SIZE_LIMIT: i64 = peerspan_host::artifact::MAX_BOUND;

/// A byte count with an optional `K`, `M`, or `G` suffix (powers of 1024),
/// from 1 byte to 1 GiB.
pub fn parse_size(value: &str) -> anyhow::Result<i64> {
    let invalid = || {
        anyhow::anyhow!(
            "invalid size {value:?}: give 1 to {SIZE_LIMIT} bytes, with an optional K, M, or G suffix"
        )
    };
    let (digits, unit) = match value.as_bytes().last() {
        Some(b'K') => (&value[..value.len() - 1], 1i64 << 10),
        Some(b'M') => (&value[..value.len() - 1], 1 << 20),
        Some(b'G') => (&value[..value.len() - 1], 1 << 30),
        _ => (value, 1),
    };
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let n: i64 = digits.parse().map_err(|_| invalid())?;
    if n < 1 || n > SIZE_LIMIT / unit {
        return Err(invalid());
    }
    Ok(n * unit)
}

/// The PRINCIPAL of `allow` and `deny`: `everyone` or `network`,
/// `group:NAME`, `agent:HOST/AGENT`, or `person:PERSON` or a bare PERSON,
/// resolved among the network's current persons.
async fn top_principal(local: &Local<'_>, network: &str, given: &str) -> anyhow::Result<String> {
    if given == "everyone" || given == "network" {
        return Ok("network".into());
    }
    if given.starts_with("group:") || given.starts_with("agent:") {
        return Ok(given.to_owned());
    }
    let person = given.strip_prefix("person:").unwrap_or(given);
    let key = synced_person_key(local, network, person).await?;
    Ok(format!(
        "person:{}",
        persons::person_id_of(&key).map_err(failed)?
    ))
}

/// Whether two rules have the same actions, as sets, and the same bounds.
fn same_settings(a: &Rule, b: &Rule) -> bool {
    a.max_message_bytes == b.max_message_bytes
        && a.max_artifact_bytes == b.max_artifact_bytes
        && a.allow_disconnected == b.allow_disconnected
        && a.actions.len() == b.actions.len()
        && b.actions.iter().all(|x| a.actions.contains(x))
}

/// The top-level `allow` and `deny`. `allow` sets a principal's access for
/// one agent scope (`--agent`, default `*`): it removes the principal from
/// every rule of that scope, adds it to the first rule of the scope with
/// identical settings or appends a new rule, drops rules left without
/// principals, and signs the next version, valid for 7 days. `deny` removes
/// the principal from every rule of the scope, or of every scope without
/// `--agent`.
pub async fn top_command(command: &Command, socket: &Path) -> anyhow::Result<Option<Value>> {
    let (given, agent, network, person_key_path, allow) = match command {
        Command::Allow {
            principal,
            agent,
            network,
            person_key,
            ..
        } => (principal, Some(agent), network, person_key, true),
        Command::Deny {
            principal,
            agent,
            network,
            person_key,
        } => (principal, agent.as_ref(), network, person_key, false),
        _ => return Ok(None),
    };
    let network = resolved(network);
    let scope = agent.cloned().unwrap_or_else(|| ALL_AGENTS.to_owned());
    if peerspan_host::membership::label(&scope).is_err() {
        bail!("invalid agent name {scope:?}");
    }
    let mut rule = Rule {
        agent: scope.clone(),
        principals: Vec::new(),
        actions: vec![ACTION.into()],
        max_message_bytes: 65536,
        max_artifact_bytes: 0,
        allow_disconnected: false,
    };
    if let Command::Allow {
        no_tasks,
        files,
        delegate,
        ..
    } = command
    {
        if *no_tasks && (*delegate || files.is_some()) {
            bail!("--delegate and --files need tasks; drop --no-tasks");
        }
        if !*no_tasks {
            rule.actions.push(TASK_ACTION.into());
        }
        if *delegate {
            rule.actions.push(DELEGATE_ACTION.into());
        }
        if let Some(files) = files {
            rule.max_artifact_bytes = parse_size(files)?;
        }
    }
    let local = Local(socket);
    let signer = PersonSigner::open(person_key_path.as_deref()).map_err(failed)?;
    let owner = signer.public_key_b64();
    let persons = local
        .get(format!("/v1/networks/{}/persons", encoded(network)))
        .await?;
    let me = persons
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["public_key"].as_str() == Some(owner.as_str()))
        .and_then(|p| p["person_id"].as_str())
        .map(str::to_owned)
        .with_context(|| {
            format!(
                "the person key {} is not a current person of that network",
                persons::person_id(&signer.public_key())
            )
        })?;
    let principal = top_principal(&local, network, given).await?;
    let path = format!("/v1/networks/{}/policy", encoded(network));
    let current: Option<Policy> = match local.get(format!("{path}?person={}", encoded(&me))).await {
        Ok(value) => Some(serde_json::from_value(strip_view(value))?),
        Err(e)
            if e.downcast_ref::<DaemonError>()
                .is_some_and(|d| d.status == 404) =>
        {
            None
        }
        Err(e) => return Err(e),
    };
    let scoped = allow || agent.is_some();
    let mut removed = 0;
    let mut rules: Vec<Rule> = current
        .as_ref()
        .map(|p| p.rules.clone())
        .unwrap_or_default();
    for r in &mut rules {
        if (!scoped || r.agent == scope) && r.principals.contains(&principal) {
            r.principals.retain(|p| *p != principal);
            removed += 1;
        }
    }
    if allow {
        match rules
            .iter_mut()
            .find(|r| r.agent == scope && same_settings(r, &rule))
        {
            Some(existing) => existing.principals.push(principal.clone()),
            None => {
                let mut new = rule.clone();
                new.principals = vec![principal.clone()];
                rules.push(new);
            }
        }
    }
    rules.retain(|r| !r.principals.is_empty());
    let mut duration = TimeDelta::days(peerspan_host::policy::DEFAULT_VALID_DAYS);
    if !allow {
        if removed == 0 {
            return Ok(Some(json!({
                "policy": current,
                "removed": 0,
                "note": format!("no rule of your policy names {principal}; access through a group or everyone is unaffected, and block stops a person at once"),
            })));
        }
        if let Some(current) = &current {
            duration = duration_of(current)?;
        }
    }
    let now = Utc::now();
    let version = current.as_ref().map_or(0, |p| p.version) + 1;
    let policy = Policy::sign(
        &signer,
        network,
        version,
        &at(now),
        &at(now + duration),
        rules,
    )
    .map_err(failed)?;
    let stored = local.post(path, json!({ "policy": policy })).await?;
    Ok(Some(if allow {
        json!({
            "policy": stored,
            "principal": principal,
            "agent": scope,
            "actions": rule.actions,
            "max_artifact_bytes": rule.max_artifact_bytes,
        })
    } else {
        json!({"policy": stored, "removed": removed})
    }))
}
