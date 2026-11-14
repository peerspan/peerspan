//! `fs share`, `fs unshare` and `fs shares` (PeerFS read contract, section 7): this
//! host's filesystem rules in the person's policy, signed through the network's provider
//! as a policy edit, as `runtime enable` signs runtime rules. `fs branches --peer` asks
//! another host what it shares with this one.
use crate::{
    access::{EDIT_ATTEMPTS, Editor, PolicySigner, PolicySigning, edit_conflict, top_principal},
    admin::Local,
    capability_cli::ask,
    cli::{FsCommand, encoded, resolved},
    integration::DaemonError,
};
use anyhow::{Context, bail};
use chrono::TimeDelta;
use peerspan_host::policy::{DEFAULT_VALID_DAYS, FS_READ_ACTION, FsRule, peerfs_branch, principal};
use serde_json::{Value, json};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
};

/// Hosts on software without filesystem rules refuse a policy that has them (PeerFS
/// read contract, section 2).
const OLDER_HOSTS: &str = "note: hosts on software without filesystem rules (fs_rules) will stop accepting this person's policy; share a branch only once every host in the network is upgraded";
/// The most filesystem rules one policy holds.
const MAX_FS_RULES: usize = 64;

pub async fn command(command: &FsCommand, socket: &Path) -> anyhow::Result<Value> {
    let local = Local(socket);
    match command {
        FsCommand::Share {
            space,
            branch,
            with,
            network,
            allow_disconnected,
            yes,
            person_key,
        } => {
            let network = resolved(network);
            if !peerfs_branch(branch) {
                bail!(
                    "{branch:?} is not a PeerFS branch name: 1 to 255 bytes, not . or .., without / or NUL"
                );
            }
            let binding = registered(&local, space, network).await?;
            let state = branch_state(&local, space, branch, &binding).await?;
            let mut principals = Vec::new();
            for given in with {
                let resolved = top_principal(&local, network, given).await?;
                principal(&resolved).map_err(|e| anyhow::anyhow!("{e}"))?;
                principals.push(resolved);
            }
            principals.sort();
            principals.dedup();
            if principals.len() > 64 {
                bail!("a share names at most 64 principals");
            }
            eprintln!(
                "Share branch {branch:?} of space {space} on this host, in network {network}, for reading:"
            );
            eprintln!("  head: {}", state["head"].as_str().unwrap_or_default());
            eprintln!(
                "  history: {} commits",
                state["commits"].as_u64().unwrap_or_default()
            );
            for p in &principals {
                eprintln!("  reader: {p}");
            }
            if *allow_disconnected {
                eprintln!(
                    "  readers whose membership lapsed still read while the policy is current"
                );
            }
            eprintln!(
                "Each reader can read the branch's whole history: every commit its head reaches and every file in each, not only the current files. Bytes a reader fetches stay with it after you unshare."
            );
            eprintln!("{OLDER_HOSTS}");
            confirm(*yes, "Share? [y/N] ")?;
            let mut rule = FsRule {
                host: String::new(),
                space: space.clone(),
                branch: branch.clone(),
                principals,
                actions: vec![FS_READ_ACTION.into()],
                allow_disconnected: *allow_disconnected,
            };
            let policy = edit(&local, network, person_key, |host, rules| {
                rule.host = host.into();
                let others = rules.iter().filter(|r| r.key() != rule.key()).count();
                if others >= MAX_FS_RULES {
                    bail!("a policy holds at most {MAX_FS_RULES} filesystem rules");
                }
                rules.retain(|r| r.key() != rule.key());
                rules.push(rule.clone());
                Ok(())
            })
            .await?;
            Ok(
                json!({ "share": rule, "head": state["head"], "commits": state["commits"],
                "policy": policy }),
            )
        }
        FsCommand::Unshare {
            space,
            branch,
            network,
            yes,
            person_key,
        } => {
            let network = resolved(network);
            let shared = shares(&local, Some(network))
                .await?
                .into_iter()
                .any(|r| r["space"] == space.as_str() && r["branch"] == branch.as_str());
            if shared {
                eprintln!(
                    "Stop sharing branch {branch:?} of space {space} on this host, in network {network}. Bytes readers already fetched stay with them."
                );
                confirm(*yes, "Unshare? [y/N] ")?;
            }
            let policy = edit(&local, network, person_key, |host, rules| {
                rules.retain(|r| r.key() != (host, space.as_str(), branch.as_str()));
                Ok(())
            })
            .await?;
            Ok(json!({ "removed": shared, "policy": policy }))
        }
        FsCommand::Shares { network, .. } => {
            Ok(Value::Array(shares(&local, network.as_deref()).await?))
        }
        FsCommand::Branches { peer, network, .. } => {
            let network = resolved(network);
            let path = format!(
                "/v1/fs/peers/{}/networks/{}/branches",
                encoded(peer),
                encoded(network)
            );
            match local.get(path).await {
                Err(e) if status(&e) == Some(400) => {
                    bail!(
                        "{peer:?} is not another host's ID (host_...), or {network:?} is not a network ID"
                    )
                }
                Err(e) if status(&e) == Some(404) => {
                    bail!("host {peer} is not known to this host")
                }
                Err(e) if status(&e) == Some(503) => {
                    bail!("host {peer} did not answer; nothing is known about what it shares")
                }
                outcome => outcome,
            }
        }
    }
}

fn confirm(yes: bool, prompt: &str) -> anyhow::Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("confirm at a terminal, or give --yes");
    }
    if !ask(prompt)? {
        bail!("nothing changed");
    }
    Ok(())
}

fn status(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<DaemonError>().map(|d| d.status)
}

/// The space's binding, which must be registered on this host in `network`.
async fn registered(local: &Local<'_>, space: &str, network: &str) -> anyhow::Result<Value> {
    let binding = match local.get(format!("/v1/fs/spaces/{}", encoded(space))).await {
        Ok(binding) => binding,
        Err(e) if status(&e) == Some(404) => {
            bail!("no PeerFS space {space} on this host; prepare and activate it first")
        }
        Err(e) if status(&e) == Some(400) => bail!("{space:?} is not a space ID (space_...)"),
        Err(e) => return Err(e),
    };
    let state = binding["state"]
        .as_str()
        .context("invalid daemon response")?;
    if state != "registered" {
        bail!("space {space} is {state} on this host; only a registered space can be shared");
    }
    let bound = binding["network_id"]
        .as_str()
        .context("invalid daemon response")?;
    if bound != network {
        bail!("space {space} is bound to network {bound}, not {network}; choose it with --network");
    }
    Ok(binding)
}

/// The branch's head and history length, from the space's running provider.
async fn branch_state(
    local: &Local<'_>,
    space: &str,
    branch: &str,
    binding: &Value,
) -> anyhow::Result<Value> {
    let path = format!(
        "/v1/fs/spaces/{}/branches/{}",
        encoded(space),
        encoded(branch)
    );
    let directory = binding["directory"].as_str().unwrap_or_default();
    match local.get(path).await {
        Ok(state) => Ok(state),
        Err(e) if status(&e) == Some(404) => bail!("space {space} has no branch {branch:?}"),
        Err(e) if status(&e) == Some(503) => bail!(
            "the PeerFS provider of space {space} is not reachable; start `peerfs serve` for {directory} and try again"
        ),
        Err(e) if status(&e) == Some(409) => bail!(
            "space {space}'s directory or provider is not the registered one ({directory}); nothing was shared"
        ),
        Err(e) => Err(e),
    }
}

/// This host's filesystem rules from the current policies, of one network or all.
async fn shares(local: &Local<'_>, network: Option<&str>) -> anyhow::Result<Vec<Value>> {
    let all = local.get("/v1/fs/shares".into()).await?;
    Ok(all
        .as_array()
        .context("invalid daemon response")?
        .iter()
        .filter(|r| network.is_none_or(|n| r["network_id"] == n))
        .cloned()
        .collect())
}

/// Signs the next policy version with `change` applied to its filesystem rules,
/// starting again when a concurrent edit wins the version check. Nothing is signed
/// when the rules are unchanged.
async fn edit(
    local: &Local<'_>,
    network: &str,
    person_key: &Option<PathBuf>,
    mut change: impl FnMut(&str, &mut Vec<FsRule>) -> anyhow::Result<()>,
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
        let before = content.fs_rules.clone();
        change(&editor.host, &mut content.fs_rules)?;
        content.fs_rules.sort_by(|a, b| a.key().cmp(&b.key()));
        if content.fs_rules == before {
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
