//! `peerbox` (peerbox contract, CLI and local API): the owner's commands,
//! which sign peerbox rules as `runtime enable` signs its rule, and the
//! peer side's, which submit peerbox tasks and wait for their outcome.
use crate::{
    access::{EDIT_ATTEMPTS, Editor, PolicySigner, PolicySigning, edit_conflict, top_principal},
    admin::Local,
    cli::{Command, PeerboxAction, PeerboxCommand, encoded},
};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::TimeDelta;
use peerspan_host::{
    peerbox::{BUNDLE_TYPE, Failure, Git, Scratch, valid_branch},
    policy::{DEFAULT_VALID_DAYS, MAX_BUNDLE_BYTES, MAX_PENDING, PeerboxRule},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    time::Duration,
};

/// Hosts on software without peerbox rules refuse a policy that has them
/// (peerbox contract, Compatibility).
const OLDER_HOSTS: &str = "note: hosts on software without peerbox rules, every Go host included, will stop accepting this person's policy; add a peerbox rule only once every host in the network runs software that implements peerboxes";

fn failure(f: Failure) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", f.code, f.message)
}

pub async fn command(command: &Command, directory: &Path) -> anyhow::Result<Option<Value>> {
    let Command::Peerbox(command) = command else {
        return Ok(None);
    };
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    match command {
        PeerboxCommand::Create {
            repository,
            branch,
            title,
            network,
            yes,
        } => create(&local, directory, repository, branch, title, network, *yes)
            .await
            .map(Some),
        PeerboxCommand::Share {
            pending: Some(id),
            person_key,
            ..
        } => share_pending(&local, id, person_key).await.map(Some),
        PeerboxCommand::Share {
            peerbox,
            principals,
            actions,
            max_bundle_bytes,
            max_pending,
            allow_disconnected,
            person_key,
            pending: None,
        } => {
            let peerbox = peerbox.as_ref().context("give the peerbox")?;
            let record = local
                .get(format!("/v1/peerboxes/{}", encoded(peerbox)))
                .await?;
            let network = record["network_id"]
                .as_str()
                .context("invalid daemon response")?
                .to_owned();
            let (actions, max_bundle_bytes, max_pending) =
                bounds(actions, *max_bundle_bytes, *max_pending)?;
            let mut resolved = Vec::new();
            for given in principals {
                resolved.push(top_principal(&local, &network, given).await?);
            }
            eprintln!("{OLDER_HOSTS}");
            let unit = PeerboxRule {
                host: String::new(),
                peerbox: peerbox.clone(),
                principals: Vec::new(),
                actions,
                max_bundle_bytes,
                max_pending,
                allow_disconnected: *allow_disconnected,
            };
            let policy = edit(&local, &network, person_key, |host, rules| {
                for p in &resolved {
                    let unit = PeerboxRule {
                        host: host.into(),
                        principals: vec![p.clone()],
                        ..unit.clone()
                    };
                    peerspan_host::policy::peerbox_put(rules, &unit);
                }
            })
            .await?;
            Ok(Some(json!({"peerbox_id": peerbox, "policy": policy})))
        }
        PeerboxCommand::Unshare {
            peerbox,
            principals,
            person_key,
        } => {
            let record = local
                .get(format!("/v1/peerboxes/{}", encoded(peerbox)))
                .await?;
            let network = record["network_id"]
                .as_str()
                .context("invalid daemon response")?
                .to_owned();
            let mut resolved = Vec::new();
            for given in principals {
                resolved.push(top_principal(&local, &network, given).await?);
            }
            let policy = edit(&local, &network, person_key, |host, rules| {
                if resolved.is_empty() {
                    rules.retain(|r| !(r.host == host && r.peerbox == *peerbox));
                }
                for p in &resolved {
                    peerspan_host::policy::peerbox_remove(rules, host, peerbox, p);
                }
            })
            .await?;
            Ok(Some(json!({"peerbox_id": peerbox, "policy": policy})))
        }
        PeerboxCommand::Delete {
            peerbox,
            person_key,
        } => {
            let path = format!("/v1/peerboxes/{}", encoded(peerbox));
            let record = local.get(path.clone()).await?;
            let network = record["network_id"]
                .as_str()
                .context("invalid daemon response")?
                .to_owned();
            if record["rules"].as_array().is_some_and(|r| !r.is_empty()) {
                edit(&local, &network, person_key, |host, rules| {
                    rules.retain(|r| !(r.host == host && r.peerbox == *peerbox));
                })
                .await?;
            }
            local.delete(path).await.map(Some)
        }
        PeerboxCommand::Show { peerbox, .. } => match peerbox {
            None => local.get("/v1/peerboxes".into()).await.map(Some),
            Some(id) => {
                let record = local.get(format!("/v1/peerboxes/{}", encoded(id))).await?;
                Ok(Some(json!([record])))
            }
        },
        PeerboxCommand::List { peer, .. } => {
            let all = list_all(&local, peer).await?;
            Ok(Some(json!({"peerboxes": all, "next": null})))
        }
        PeerboxCommand::Fetch {
            peer,
            peerbox,
            repository,
        } => fetch(&local, directory, peer, peerbox, repository)
            .await
            .map(Some),
        PeerboxCommand::Invite { list: true, .. } => {
            local.get("/v1/peerbox-invites".into()).await.map(Some)
        }
        PeerboxCommand::Invite {
            cancel: Some(id), ..
        } => local
            .delete(format!("/v1/peerbox-invites/{}", encoded(id)))
            .await
            .map(Some),
        PeerboxCommand::Invite {
            peerbox,
            label,
            actions,
            max_bundle_bytes,
            max_pending,
            expires_in,
            expires_at,
            ..
        } => {
            let peerbox = peerbox.as_ref().context("give the peerbox")?;
            let label = label.as_ref().context("give the new member's label")?;
            invite(
                &local,
                peerbox,
                label,
                bounds(actions, *max_bundle_bytes, *max_pending)?,
                expires_in,
                expires_at,
            )
            .await
            .map(Some)
        }
        PeerboxCommand::Join {
            code,
            invitation,
            repository,
            label,
            person_key,
        } => {
            anyhow::ensure!(
                code.is_none(),
                "keep peerbox codes out of argv; use --invite-stdin, --invite-file or the hidden prompt"
            );
            join(&local, directory, invitation, repository, label, person_key)
                .await
                .map(Some)
        }
        PeerboxCommand::Run { .. } => unreachable!("peerbox run exits with its own status"),
    }
}

/// The actions in rule order and the bounds of `share` and `invite`:
/// `--action` defaults to read; submit and run need read; 104,857,600
/// bytes per bundle by default; `--max-pending` 4 by default with submit
/// and 0 without it, where any other value is refused.
fn bounds(
    actions: &[PeerboxAction],
    max_bundle_bytes: Option<i64>,
    max_pending: Option<i64>,
) -> anyhow::Result<(Vec<String>, i64, i64)> {
    let mut actions = if actions.is_empty() {
        vec![PeerboxAction::Read]
    } else {
        actions.to_vec()
    };
    actions.sort();
    actions.dedup();
    if !actions.contains(&PeerboxAction::Read) {
        bail!("--action submit and --action run need --action read");
    }
    let submit = actions.contains(&PeerboxAction::Submit);
    let max_bundle_bytes = max_bundle_bytes.unwrap_or(MAX_BUNDLE_BYTES);
    if !(1..=MAX_BUNDLE_BYTES).contains(&max_bundle_bytes) {
        bail!("--max-bundle-bytes is 1 to {MAX_BUNDLE_BYTES}");
    }
    let max_pending = match (submit, max_pending) {
        (true, None) => 4,
        (true, Some(n)) if (1..=MAX_PENDING).contains(&n) => n,
        (true, Some(_)) => bail!("--max-pending is 1 to {MAX_PENDING} with submit"),
        (false, None | Some(0)) => 0,
        (false, Some(_)) => bail!("--max-pending is 0 without --action submit"),
    };
    Ok((
        actions.iter().map(|a| a.name().to_owned()).collect(),
        max_bundle_bytes,
        max_pending,
    ))
}

/// Submits `list` to `peer`, following `next` until null.
async fn list_all(local: &Local<'_>, peer: &str) -> anyhow::Result<Vec<Value>> {
    let mut all = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let mut op = json!({"op": "list"});
        if let Some(a) = &after {
            op["after"] = json!(a);
        }
        let (value, _, _) = operation(local, peer, op).await?;
        all.extend(value["peerboxes"].as_array().cloned().unwrap_or_default());
        match value["next"].as_str() {
            Some(next) if after.as_deref() != Some(next) => after = Some(next.to_owned()),
            _ => break,
        }
    }
    Ok(all)
}

/// The JSON of a `psb1-` code (Invitations for new participants 1), its
/// keys in this order. Everything beside `invite` is a display hint.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerboxCode {
    pub invite: String,
    pub peerbox_id: String,
    pub title: String,
    pub home_host_id: String,
    pub actions: Vec<String>,
}
const PSB1: &str = "psb1-";
fn encode_code(code: &PeerboxCode) -> anyhow::Result<String> {
    Ok(format!(
        "{PSB1}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(code)?)
    ))
}
/// The network invite inside a `psb1-` code, with the code's hints; any
/// other token as it is.
pub(crate) fn unwrap_code(token: &str) -> anyhow::Result<(String, Option<PeerboxCode>)> {
    let Some(body) = token.strip_prefix(PSB1) else {
        return Ok((token.to_owned(), None));
    };
    let code: PeerboxCode = URL_SAFE_NO_PAD
        .decode(body)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .context("the psb1- peerbox code is malformed")?;
    anyhow::ensure!(
        code.invite.starts_with("psi2-"),
        "the psb1- peerbox code holds no network invite"
    );
    Ok((code.invite.clone(), Some(code)))
}
/// Shows a peerbox code's peerbox beside the invite's review, and refuses
/// it on a machine already in that network (Invitations 2).
pub(crate) async fn review_code(
    local: &Local<'_>,
    code: &PeerboxCode,
    network: &str,
) -> anyhow::Result<()> {
    eprintln!(
        "Peerbox: {:?} ({}) on home host {}; offered actions: {}. Only the rule its owner signs after you are admitted grants access.",
        code.title,
        code.peerbox_id,
        code.home_host_id,
        code.actions.join(", ")
    );
    let networks = local.get("/v2/networks".into()).await?;
    if networks
        .as_array()
        .into_iter()
        .flatten()
        .any(|n| n["id"] == network)
    {
        bail!(
            "this machine is already in network {network}; ask the peerbox's owner to give you access with `peerbox share`"
        );
    }
    Ok(())
}

/// `peerbox invite` (Invitations 1): a network invite as `invite` creates
/// it, the pending share keyed by its invitation ID, and the `psb1-` code.
async fn invite(
    local: &Local<'_>,
    peerbox: &str,
    label: &str,
    (actions, max_bundle_bytes, max_pending): (Vec<String>, i64, i64),
    expires_in: &Option<String>,
    expires_at: &Option<String>,
) -> anyhow::Result<Value> {
    let record = local
        .get(format!("/v1/peerboxes/{}", encoded(peerbox)))
        .await?;
    let network = record["network_id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let title = record["title"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let host = local.get("/v1/host".into()).await?["id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    eprintln!(
        "Peerbox invite for {label}: peerbox {title:?} ({peerbox}) in network {network}, actions {}, max_bundle_bytes {max_bundle_bytes}, max_pending {max_pending}. They join as an ordinary member once a network administrator admits them; this host then signs their peerbox rule.",
        actions.join(", ")
    );
    let v = crate::decentralized_onboarding_cli::mint_invite(
        local,
        &Some(network),
        label,
        expires_at,
        expires_in,
    )
    .await?;
    let invitation_id = v["invitation_id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    local
        .post(
            "/v1/peerbox-invites".into(),
            json!({
                "invitation_id": invitation_id,
                "peerbox_id": peerbox,
                "label": label,
                "actions": actions,
                "max_bundle_bytes": max_bundle_bytes,
                "max_pending": max_pending,
            }),
        )
        .await?;
    let code = encode_code(&PeerboxCode {
        invite: v["invitation"]
            .as_str()
            .context("invalid daemon response")?
            .to_owned(),
        peerbox_id: peerbox.to_owned(),
        title,
        home_host_id: host,
        actions,
    })?;
    eprintln!(
        "Send this private code to {label} privately; it lasts until {}.",
        v["expires_at"].as_str().unwrap_or("-")
    );
    Ok(json!({"code": code, "invitation_id": invitation_id, "expires_at": v["expires_at"]}))
}

/// `peerbox share --pending` (CLI): signs the rule of a pending share whose
/// person was admitted, as `share --for` would.
async fn share_pending(
    local: &Local<'_>,
    id: &str,
    person_key: &Option<PathBuf>,
) -> anyhow::Result<Value> {
    let shares = local.get("/v1/peerbox-invites".into()).await?;
    let share = shares
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["invitation_id"] == id)
        .cloned()
        .with_context(|| format!("no pending share for invite {id}"))?;
    let person = share["person"]["person_id"]
        .as_str()
        .with_context(|| format!("the person of invite {id} has not been admitted yet"))?
        .to_owned();
    let text = |name: &str| -> anyhow::Result<String> {
        Ok(share[name]
            .as_str()
            .context("invalid daemon response")?
            .to_owned())
    };
    let (peerbox, network) = (text("peerbox_id")?, text("network_id")?);
    let unit = PeerboxRule {
        host: String::new(),
        peerbox: peerbox.clone(),
        principals: vec![format!("person:{person}")],
        actions: serde_json::from_value(share["actions"].clone())?,
        max_bundle_bytes: share["max_bundle_bytes"]
            .as_i64()
            .context("invalid daemon response")?,
        max_pending: share["max_pending"]
            .as_i64()
            .context("invalid daemon response")?,
        allow_disconnected: false,
    };
    eprintln!("{OLDER_HOSTS}");
    let policy = edit(local, &network, person_key, |host, rules| {
        peerspan_host::policy::peerbox_put(
            rules,
            &PeerboxRule {
                host: host.into(),
                ..unit.clone()
            },
        );
    })
    .await?;
    local
        .post(
            format!("/v1/peerbox-invites/{}/complete", encoded(id)),
            json!({}),
        )
        .await?;
    Ok(json!({"peerbox_id": peerbox, "invitation_id": id, "policy": policy}))
}

/// `peerbox join` (Invitations 2 and 5): the join from a `psb1-` code;
/// after the commit, `list` on the home host until the peerbox appears or
/// 10 minutes pass, then the fetch with `--repository`.
async fn join(
    local: &Local<'_>,
    directory: &Path,
    invitation: &crate::decentralized_onboarding_cli::InvitationInput,
    repository: &Option<PathBuf>,
    label: &Option<String>,
    person_key: &Option<PathBuf>,
) -> anyhow::Result<Value> {
    let token = invitation.read().await?;
    let (_, code) = unwrap_code(&token)?;
    let code =
        code.context("peerbox join takes a psb1- peerbox code; use join for a psi2- invite")?;
    let v = crate::decentralized_onboarding_cli::join_view(
        local.0,
        &token,
        person_key,
        label.as_deref(),
    )
    .await?;
    if v["state"] != "linked" {
        for line in v["next"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            eprintln!("Next: {line}");
        }
        bail!(
            "the join is not complete ({}); once it is, run peerbox list --peer {}",
            v["state"].as_str().unwrap_or("-"),
            code.home_host_id
        );
    }
    let network = v["network_id"].as_str().unwrap_or_default().to_owned();
    eprintln!(
        "Joined. Waiting for the peerbox {} to be shared with you...",
        code.peerbox_id
    );
    let until = std::time::Instant::now() + Duration::from_secs(600);
    let entry = loop {
        // One `list` never outlasts the 10 minutes.
        let left = until.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left, list_all(local, &code.home_host_id))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out")))
        {
            Ok(all) => {
                if let Some(entry) = all.into_iter().find(|e| e["peerbox_id"] == code.peerbox_id) {
                    break entry;
                }
            }
            // Not yet reachable, or no policy of the owner known yet.
            Err(_) if !network.is_empty() => {
                let _ = local
                    .post(
                        format!("/v2/networks/{}/sync", encoded(&network)),
                        json!({}),
                    )
                    .await;
            }
            Err(_) => {}
        }
        if std::time::Instant::now() >= until {
            bail!(
                "the peerbox {} did not appear within 10 minutes; ask its owner, then run peerbox list --peer {}",
                code.peerbox_id,
                code.home_host_id
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let mut out = json!({"network_id": network, "peerbox": entry});
    if let Some(dir) = repository {
        out["fetched"] = fetch(local, directory, &code.home_host_id, &code.peerbox_id, dir).await?;
    }
    Ok(out)
}

/// `peerbox run` (CLI): submits `run` with `task run`'s flags and follows
/// it as `task run` does, with its exit status.
pub async fn run(command: &Command, directory: &Path) -> anyhow::Result<i32> {
    let Command::Peerbox(PeerboxCommand::Run {
        peer,
        peerbox,
        commit,
        results,
        cpus,
        memory_mib,
        timeout,
        env,
        cwd,
        input,
        deadline,
        detach,
        command,
    }) = command
    else {
        unreachable!("not peerbox run");
    };
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    let run = crate::task_run::run_object(command, cwd, env, cpus, memory_mib, timeout, results)?;
    let mut body = json!({
        "peer_host_id": peer,
        "executor": "peerbox",
        "input": input.clone().unwrap_or_else(|| crate::task_run::default_input(command)),
        "peerbox": {"op": "run", "peerbox_id": peerbox, "commit": commit, "run": run},
    });
    if let Some(deadline) = deadline {
        body["deadline"] = json!(deadline);
    }
    crate::task_run::submit_and_follow(
        &local,
        &socket,
        peer,
        body,
        *detach,
        results.as_deref() == Some("changes"),
    )
    .await
}

/// `peerbox create`: the disclosure, the confirmation, then the record.
async fn create(
    local: &Local<'_>,
    directory: &Path,
    repository: &Path,
    branch: &str,
    title: &Option<String>,
    network: &Option<String>,
    yes: bool,
) -> anyhow::Result<Value> {
    let repository = std::path::absolute(repository)?;
    if !valid_branch(branch) {
        bail!("--branch {branch:?} is not a branch name a peerbox accepts");
    }
    let git = Git::new(directory).map_err(failure)?;
    let shown = peerspan_host::peerbox::disclosure(
        &git,
        &repository,
        branch,
        &directory.join("peerbox-tmp"),
    )
    .map_err(failure)?;
    eprint!("{}", shown.text());
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("confirm the disclosure above at a terminal, or give --yes");
        }
        eprint!("Create this peerbox? [y/N] ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            bail!("not created");
        }
    }
    let network = network.as_deref().context("--network is required")?;
    let mut body = json!({
        "repository": repository,
        "branch": branch,
        "network_id": network,
    });
    if let Some(title) = title {
        body["title"] = json!(title);
    }
    local.post("/v1/peerboxes".into(), body).await
}

/// Signs the next policy version with `change` applied to this host's
/// peerbox rules, starting again when a concurrent edit wins the version
/// check. Nothing is signed when the rules are unchanged.
async fn edit(
    local: &Local<'_>,
    network: &str,
    person_key: &Option<PathBuf>,
    mut change: impl FnMut(&str, &mut Vec<PeerboxRule>),
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
        let before = content.peerbox_rules.clone();
        change(&editor.host, &mut content.peerbox_rules);
        if content.peerbox_rules == before {
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

/// Submits one peerbox operation to `peer` and waits for its final event:
/// the result object and the event, or the operation's code and message.
async fn operation(
    local: &Local<'_>,
    peer: &str,
    op: Value,
) -> anyhow::Result<(Value, Value, String)> {
    let name = op["op"].as_str().unwrap_or_default().to_owned();
    let record = local
        .post(
            "/v1/tasks".into(),
            json!({
                "peer_host_id": peer,
                "executor": "peerbox",
                "peerbox": op,
                "input": format!("peerbox {name}"),
            }),
        )
        .await?;
    let id = record["request"]["task_id"]
        .as_str()
        .context("invalid daemon response")?
        .to_owned();
    let path = format!("/v1/tasks/{}/{}", encoded(peer), encoded(&id));
    let mut after = 0;
    loop {
        let task = local.get(path.clone()).await?;
        if task["submit_state"] == "rejected" {
            bail!(
                "rejected: {}",
                task["error"]
                    .as_str()
                    .unwrap_or("the peer refused the task")
            );
        }
        let events = local
            .get(format!("{path}/events?after={after}&limit=100"))
            .await?;
        let events = events.as_array().cloned().unwrap_or_default();
        for event in events {
            after = event["sequence"].as_i64().unwrap_or(after);
            match event["state"].as_str().unwrap_or_default() {
                "succeeded" => {
                    let value: Value = event["output"]
                        .as_str()
                        .and_then(|o| serde_json::from_str(o).ok())
                        .context("the peer's result is not a JSON object")?;
                    return Ok((value, event, id));
                }
                "failed" => {
                    let value: Value = event["output"]
                        .as_str()
                        .and_then(|o| serde_json::from_str(o).ok())
                        .unwrap_or(Value::Null);
                    bail!(
                        "{}: {}",
                        value["error"].as_str().unwrap_or("failed"),
                        value["message"].as_str().unwrap_or_default()
                    );
                }
                state @ ("rejected" | "expired" | "cancelled") => {
                    bail!("{state}: {}", event["message"].as_str().unwrap_or_default());
                }
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// `peerbox fetch` (Fetch): `have` from DIR's refs for the peerbox; the
/// bundle verified by digest, by `git bundle verify`, and fetched into a
/// quarantine repository with `transfer.fsckObjects` before any ref of DIR
/// changes.
async fn fetch(
    local: &Local<'_>,
    directory: &Path,
    peer: &str,
    peerbox: &str,
    repository: &Path,
) -> anyhow::Result<Value> {
    if !peerspan_host::policy::peerbox_id(peerbox) {
        bail!("{peerbox:?} is not a peerbox ID");
    }
    let dir = std::path::absolute(repository)?;
    let git = Git::new(directory).map_err(failure)?;
    let mut have: Vec<String> = Vec::new();
    if dir.exists() {
        let listed = git
            .text(
                &dir,
                &[
                    "for-each-ref",
                    "--format=%(objectname)",
                    &format!("refs/peerbox/{peerbox}/"),
                ],
                "invalid",
            )
            .map_err(failure)?;
        for line in listed.lines() {
            if !have.iter().any(|h| h == line) && have.len() < 32 {
                have.push(line.to_owned());
            }
        }
    }
    let mut op = json!({"op": "fetch", "peerbox_id": peerbox});
    if !have.is_empty() {
        op["have"] = json!(have);
    }
    let (value, event, task_id) = operation(local, peer, op).await?;
    let Some(sha) = value["bundle_sha256"].as_str() else {
        // The caller has the head: nothing is new and no ref changes.
        return Ok(value);
    };
    let head = value["head"].as_str().context("invalid fetch result")?;
    let size = value["size"].as_i64().context("invalid fetch result")?;
    let listed = event["artifacts"].as_array().cloned().unwrap_or_default();
    let found = listed.iter().any(|a| {
        a["name"] == "peerbox.bundle"
            && a["media_type"] == BUNDLE_TYPE
            && a["sha256"] == sha
            && a["size"] == size
    });
    if !found {
        bail!("bundle_invalid: the fetch result names no peerbox.bundle artifact");
    }
    let scratch = Scratch::new(&directory.join("peerbox-tmp")).map_err(failure)?;
    let file = scratch.path().join("peerbox.bundle");
    let socket = directory.join("admin.sock");
    let path = format!(
        "/v1/tasks/{}/{}/artifacts/{}",
        encoded(peer),
        encoded(&task_id),
        encoded(sha)
    );
    let until = std::time::Instant::now() + Duration::from_secs(600);
    loop {
        match crate::download(&socket, path.clone(), &file).await {
            Ok(_) => break,
            Err(_) if std::time::Instant::now() < until => {
                let _ = std::fs::remove_file(&file);
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => return Err(e),
        }
    }
    let (digest, length) = peerspan_host::peerbox::digest_file(&file)?;
    if digest != sha || length != size {
        bail!("bundle_invalid: the bundle does not match its digest");
    }
    let heads = git
        .text(
            scratch.path(),
            &["bundle", "list-heads", &file.to_string_lossy()],
            "bundle_invalid",
        )
        .map_err(failure)?;
    let branch = match heads.lines().collect::<Vec<_>>().as_slice() {
        [line] => match line.split_once(' ') {
            Some((tip, name)) if tip == head => name
                .strip_prefix("refs/heads/")
                .filter(|b| valid_branch(b))
                .map(str::to_owned),
            _ => None,
        },
        _ => None,
    }
    .context("bundle_invalid: the bundle's single ref is not refs/heads/BRANCH at the head")?;
    // DIR and the quarantine hold the bundle's object format.
    let format = peerspan_host::peerbox::bundle_object_format(&file).map_err(failure)?;
    let format_arg = format!("--object-format={format}");
    if dir.exists() {
        let found = git
            .text(&dir, &["rev-parse", "--show-object-format"], "invalid")
            .map_err(failure)?;
        if found != format {
            bail!(
                "invalid: {} uses the {found} object format and the peerbox uses {format}; fetch it into another directory",
                dir.display()
            );
        }
    } else {
        git.text(
            scratch.path(),
            &["init", "-q", &format_arg, &dir.to_string_lossy()],
            "invalid",
        )
        .map_err(failure)?;
    }
    let file_text = file.to_string_lossy().into_owned();
    git.text(
        &dir,
        &["bundle", "verify", "-q", &file_text],
        "bundle_invalid",
    )
    .map_err(failure)?;
    // The quarantine borrows DIR's objects for the bundle's prerequisites.
    let quarantine = scratch.path().join("quarantine");
    git.text(
        scratch.path(),
        &[
            "init",
            "-q",
            "--bare",
            &format_arg,
            &quarantine.to_string_lossy(),
        ],
        "invalid",
    )
    .map_err(failure)?;
    let objects = git
        .text(&dir, &["rev-parse", "--git-path", "objects"], "invalid")
        .map_err(failure)?;
    let objects = std::path::absolute(dir.join(objects))?;
    std::fs::write(
        quarantine.join("objects/info/alternates"),
        format!("{}\n", objects.display()),
    )?;
    let reference = format!("+refs/heads/{branch}:refs/quarantine/head");
    git.text(
        &quarantine,
        &[
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "-q",
            "--no-write-fetch-head",
            &file_text,
            &reference,
        ],
        "bundle_invalid",
    )
    .map_err(failure)?;
    let target = format!("+refs/quarantine/head:refs/peerbox/{peerbox}/{branch}");
    git.text(
        &dir,
        &[
            "-c",
            "transfer.fsckObjects=true",
            "fetch",
            "-q",
            "--no-write-fetch-head",
            &quarantine.to_string_lossy(),
            &target,
        ],
        "bundle_invalid",
    )
    .map_err(failure)?;
    Ok(value)
}
