//! Owner access policy commands that sign. The CLI fetches the owner's
//! current policy from the daemon, edits its rules, and signs the next
//! version with the person key; the daemon verifies and submits it and never
//! sees the key.
use crate::{
    admin::{Local, person_key},
    cli::{AccessCommand, encoded},
    integration::DaemonError,
};
use anyhow::{Context, bail};
use capsule_host::{
    persons::{self, PersonSigner},
    policy::{ACTION, Policy, Rule},
};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
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
        .unwrap_or(TimeDelta::days(capsule_host::policy::DEFAULT_VALID_DAYS));
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
            match rules.iter_mut().find(|r| r.agent == *agent) {
                Some(existing) => *existing = rule,
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
            let index = rules
                .iter()
                .position(|r| r.agent == *agent)
                .with_context(|| format!("your policy has no rule for agent {agent:?}"))?;
            if principal.is_empty() {
                rules.remove(index);
            } else {
                let mut removed = Vec::new();
                for given in principal {
                    removed.push(resolve(&local, network, given).await?);
                }
                let rule = &mut rules[index];
                rule.principals.retain(|p| !removed.contains(p));
                if rule.principals.is_empty() {
                    rules.remove(index);
                }
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
    let key = person_key(local, network, person).await?;
    Ok(format!(
        "person:{}",
        persons::person_id_of(&key).map_err(failed)?
    ))
}

fn is_person_id(value: &str) -> bool {
    value.strip_prefix("person_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
