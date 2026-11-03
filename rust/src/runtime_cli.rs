//! `runtime enable` and `runtime disable` (runtime task contract): the
//! local switch, then this host's runtime rule in the person's policy,
//! signed through the network's provider as a policy edit.
use crate::{
    access::{EDIT_ATTEMPTS, Editor, PolicySigner, PolicySigning, edit_conflict, top_principal},
    admin::Local,
    cli::{Command, RuntimeCommand, resolved},
};
use anyhow::{Context, bail};
use chrono::TimeDelta;
use peerspan_host::policy::{DEFAULT_VALID_DAYS, RuntimeRule};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Hosts on software without runtime rules refuse a policy that has them
/// (RUN-5).
const OLDER_HOSTS: &str = "note: hosts on software without runtime rules, v0.1.0 included, will stop accepting this person's policy; add a runtime rule only once every host in the network is upgraded";

pub async fn command(command: &Command, socket: &Path) -> anyhow::Result<Option<Value>> {
    let local = Local(socket);
    match command {
        Command::Runtime(RuntimeCommand::Enable {
            socket: runtime,
            principals,
            max_cpus,
            max_memory_mib,
            max_seconds,
            max_output_bytes,
            max_artifact_bytes,
            peerfs_workspaces,
            allow_disconnected,
            network,
            person_key,
        }) => {
            let runtime = std::path::absolute(runtime)?;
            let report = peerspan_host::runtime::report(&runtime)
                .await
                .map_err(anyhow::Error::msg)?;
            let mut rule = RuntimeRule {
                host: String::new(),
                principals: Vec::new(),
                max_cpus: max_cpus.unwrap_or(2),
                max_memory_mib: max_memory_mib.unwrap_or(2048),
                max_seconds: max_seconds.unwrap_or(3600),
                max_output_bytes: max_output_bytes.unwrap_or(1_048_576),
                max_artifact_bytes: max_artifact_bytes.unwrap_or(104_857_600),
                peerfs_workspaces: peerfs_workspaces
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                allow_disconnected: *allow_disconnected,
            };
            if let Some(name) = rule
                .peerfs_workspaces
                .iter()
                .find(|n| !peerspan_host::policy::peerfs_workspace(n))
            {
                bail!("--peerfs-workspace {name:?} is not a workspace name");
            }
            if !rule.peerfs_workspaces.is_empty() && report["peerfs"] != Value::Bool(true) {
                bail!("--peerfs-workspace needs a runtime that serves a peerfs space");
            }
            for (name, value, field) in [
                ("--max-cpus", rule.max_cpus, "max_cpus"),
                ("--max-memory-mib", rule.max_memory_mib, "max_memory_mib"),
                ("--max-seconds", rule.max_seconds, "max_seconds"),
            ] {
                let most = report[field].as_i64().context("invalid runtime report")?;
                if value > most {
                    bail!("{name} {value} exceeds the runtime's {field} of {most}");
                }
            }
            let network = resolved(network);
            for given in principals {
                rule.principals
                    .push(top_principal(&local, network, given).await?);
            }
            local
                .put("/v1/runtime".into(), json!({ "socket": runtime }))
                .await?;
            eprintln!("{OLDER_HOSTS}");
            let policy = edit(&local, network, person_key, |host, person, rules| {
                rule.host = host.into();
                if rule.principals.is_empty() {
                    rule.principals = vec![format!("person:{person}")];
                }
                rules.retain(|r| r.host != host);
                rules.push(rule.clone());
            })
            .await?;
            Ok(Some(json!({ "runtime": report, "policy": policy })))
        }
        Command::Runtime(RuntimeCommand::Disable {
            network,
            person_key,
        }) => {
            local.delete("/v1/runtime".into()).await?;
            let policy = edit(&local, resolved(network), person_key, |host, _, rules| {
                rules.retain(|r| r.host != host);
            })
            .await?;
            Ok(Some(json!({ "enabled": false, "policy": policy })))
        }
        _ => Ok(None),
    }
}

/// Signs the next policy version with `change` applied to its runtime
/// rules, starting again when a concurrent edit wins the version check.
/// Nothing is signed when the rules are unchanged.
async fn edit(
    local: &Local<'_>,
    network: &str,
    person_key: &Option<PathBuf>,
    mut change: impl FnMut(&str, &str, &mut Vec<RuntimeRule>),
) -> anyhow::Result<Value> {
    let signer = PolicySigner::open(local, network, person_key.as_deref()).await?;
    let editor = Editor::new(local, network, &signer).await?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let start = editor.start(local, signer.original()).await?;
        let mut content = start
            .policy
            .as_ref()
            .map(|p| p.content())
            .unwrap_or_default();
        let before = content.runtime_rules.clone();
        change(&editor.host, &editor.person_id, &mut content.runtime_rules);
        if content.runtime_rules == before {
            return Ok(serde_json::to_value(&start.policy)?);
        }
        let policy = editor.sign(
            &signer,
            &start,
            content,
            Some(TimeDelta::days(DEFAULT_VALID_DAYS)),
            true,
        )?;
        match editor.submit(local, &signer, &policy).await {
            Err(e) if edit_conflict(&e) && attempt < EDIT_ATTEMPTS => continue,
            outcome => return outcome,
        }
    }
}
