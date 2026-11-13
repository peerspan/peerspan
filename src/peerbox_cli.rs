//! `peerbox` (peerbox contract, CLI and local API): the owner's commands,
//! which sign peerbox rules as `runtime enable` signs its rule, and the
//! peer side's, which submit peerbox tasks and wait for their outcome.
use crate::{
    access::{EDIT_ATTEMPTS, Editor, PolicySigner, PolicySigning, edit_conflict, top_principal},
    admin::Local,
    cli::{Command, PeerboxAction, PeerboxCommand, encoded},
};
use anyhow::{Context, bail};
use chrono::TimeDelta;
use peerspan_host::{
    peerbox::{BUNDLE_TYPE, Failure, Git, Scratch, valid_branch},
    policy::{DEFAULT_VALID_DAYS, MAX_BUNDLE_BYTES, MAX_PENDING, PeerboxRule},
};
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
            peerbox,
            principals,
            actions,
            max_bundle_bytes,
            max_pending,
            allow_disconnected,
            person_key,
        } => {
            let record = local
                .get(format!("/v1/peerboxes/{}", encoded(peerbox)))
                .await?;
            let network = record["network_id"]
                .as_str()
                .context("invalid daemon response")?
                .to_owned();
            let mut actions = if actions.is_empty() {
                vec![PeerboxAction::Read]
            } else {
                actions.clone()
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
            let max_pending = match (submit, *max_pending) {
                (true, None) => 4,
                (true, Some(n)) if (1..=MAX_PENDING).contains(&n) => n,
                (true, Some(_)) => bail!("--max-pending is 1 to {MAX_PENDING} with submit"),
                (false, None | Some(0)) => 0,
                (false, Some(_)) => bail!("--max-pending is 0 without --action submit"),
            };
            let mut resolved = Vec::new();
            for given in principals {
                resolved.push(top_principal(&local, &network, given).await?);
            }
            eprintln!("{OLDER_HOSTS}");
            let unit = PeerboxRule {
                host: String::new(),
                peerbox: peerbox.clone(),
                principals: Vec::new(),
                actions: actions.iter().map(|a| a.name().to_owned()).collect(),
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
            let mut all = Vec::new();
            let mut after: Option<String> = None;
            loop {
                let mut op = json!({"op": "list"});
                if let Some(a) = &after {
                    op["after"] = json!(a);
                }
                let (value, _, _) = operation(&local, peer, op).await?;
                all.extend(value["peerboxes"].as_array().cloned().unwrap_or_default());
                match value["next"].as_str() {
                    Some(next) if after.as_deref() != Some(next) => after = Some(next.to_owned()),
                    _ => break,
                }
            }
            Ok(Some(json!({"peerboxes": all, "next": null})))
        }
        PeerboxCommand::Fetch {
            peer,
            peerbox,
            repository,
        } => fetch(&local, directory, peer, peerbox, repository)
            .await
            .map(Some),
        PeerboxCommand::Submit {
            peer,
            peerbox,
            repository,
            branch,
            base,
        } => submit(&local, directory, peer, peerbox, repository, branch, base)
            .await
            .map(Some),
        PeerboxCommand::Status {
            peer,
            peerbox,
            contribution,
            before,
            limit,
            ..
        } => {
            let mut op = json!({"op": "status", "peerbox_id": peerbox});
            if let Some(id) = contribution {
                if before.is_some() {
                    bail!("give a contribution or --before, not both");
                }
                op["contribution_id"] = json!(id);
                let (value, _, _) = operation(&local, peer, op).await?;
                return Ok(Some(value));
            }
            let mut all: Vec<Value> = Vec::new();
            let mut before = before.clone();
            let mut next = Value::Null;
            while all.len() < *limit {
                let mut op = op.clone();
                if let Some(b) = &before {
                    op["before"] = json!(b);
                }
                let (value, _, _) = operation(&local, peer, op).await?;
                all.extend(value["contributions"].as_array().cloned().unwrap_or_default());
                next = value["next"].clone();
                match next.as_str() {
                    Some(n) if before.as_deref() != Some(n) => before = Some(n.to_owned()),
                    _ => break,
                }
            }
            if all.len() > *limit {
                all.truncate(*limit);
            }
            // `next` names the last printed record when more remain.
            let more = all.len() == *limit && !next.is_null();
            let next = if more {
                all.last()
                    .map(|r| r["contribution_id"].clone())
                    .unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            Ok(Some(json!({"contributions": all, "next": next})))
        }
        PeerboxCommand::Withdraw {
            peer,
            peerbox,
            contribution,
        } => {
            let op = json!({"op": "withdraw", "peerbox_id": peerbox, "contribution_id": contribution});
            let (value, _, _) = operation(&local, peer, op).await?;
            Ok(Some(value))
        }
        PeerboxCommand::Review {
            target,
            accept,
            reject,
            reason,
            ..
        } => review(&local, directory, target.as_deref(), *accept, *reject, reason)
            .await
            .map(Some),
    }
}

/// A 409 from the daemon as its code and message, so the command exits 1
/// printing the code.
fn with_code(e: anyhow::Error) -> anyhow::Error {
    match e.downcast_ref::<crate::integration::DaemonError>() {
        Some(d) if !d.code.is_empty() => anyhow::anyhow!("{}: {}", d.code, d.message),
        _ => e,
    }
}

/// `peerbox review`: the pending contributions with `git diff --stat`, or
/// the owner's decision on one.
async fn review(
    local: &Local<'_>,
    directory: &Path,
    target: Option<&str>,
    accept: bool,
    reject: bool,
    reason: &Option<String>,
) -> anyhow::Result<Value> {
    if accept || reject {
        let id = target.context("give the contribution to accept or reject")?;
        let mut body = json!({"decision": if accept { "accepted" } else { "rejected" }});
        if let Some(reason) = reason {
            body["reason"] = json!(reason);
        }
        return local
            .post(
                format!("/v1/peerboxes/contributions/{}/decision", encoded(id)),
                body,
            )
            .await
            .map_err(with_code);
    }
    if reason.is_some() {
        bail!("--reason goes with --accept or --reject");
    }
    let records: Vec<Value> = match target {
        Some(id) => vec![local.get(format!("/v1/peerboxes/{}", encoded(id))).await?],
        None => local
            .get("/v1/peerboxes".into())
            .await?
            .as_array()
            .cloned()
            .unwrap_or_default(),
    };
    let git = Git::new(directory).map_err(failure)?;
    let mut out = Vec::new();
    for record in records {
        let id = record["peerbox_id"].as_str().context("invalid daemon response")?;
        let repo = PathBuf::from(record["repository"].as_str().unwrap_or_default());
        let listed = local
            .get(format!("/v1/peerboxes/{}/contributions", encoded(id)))
            .await?;
        for mut c in listed.as_array().cloned().unwrap_or_default() {
            if c["state"] != "pending" {
                continue;
            }
            let (base, head) = (
                c["base"].as_str().unwrap_or_default().to_owned(),
                c["head"].as_str().unwrap_or_default().to_owned(),
            );
            c["diff_stat"] = json!(
                git.text(&repo, &["diff", "--stat", &base, &head, "--"], "unavailable")
                    .unwrap_or_default()
            );
            out.push(c);
        }
    }
    Ok(Value::Array(out))
}

/// `peerbox submit` (CLI): bundles NAME in DIR without the history of the
/// base, uploads it and submits it.
async fn submit(
    local: &Local<'_>,
    directory: &Path,
    peer: &str,
    peerbox: &str,
    repository: &Path,
    branch: &str,
    base: &Option<String>,
) -> anyhow::Result<Value> {
    if !peerspan_host::policy::peerbox_id(peerbox) {
        bail!("{peerbox:?} is not a peerbox ID");
    }
    if !valid_branch(branch) {
        bail!("--branch {branch:?} is not a branch name a peerbox accepts");
    }
    let dir = std::path::absolute(repository)?;
    let git = Git::new(directory).map_err(failure)?;
    let tip = git
        .head(&dir, branch)
        .map_err(failure)?
        .with_context(|| format!("{} has no branch {branch:?}", dir.display()))?;
    let base = match base {
        Some(b) => git
            .text(
                &dir,
                &["rev-parse", "--verify", "-q", "--end-of-options", &format!("{b}^{{commit}}")],
                "invalid",
            )
            .map_err(|_| anyhow::anyhow!("--base {b:?} names no commit in {}", dir.display()))?,
        None => {
            let fetched = git
                .text(
                    &dir,
                    &[
                        "for-each-ref",
                        "--format=%(refname)",
                        &format!("refs/peerbox/{peerbox}/"),
                    ],
                    "invalid",
                )
                .map_err(failure)?;
            let fetched: Vec<&str> = fetched
                .lines()
                .filter(|r| r.matches('/').count() == 3)
                .collect();
            let [fetched] = fetched.as_slice() else {
                bail!("fetch the peerbox into {} first, or give --base", dir.display());
            };
            git.text(&dir, &["merge-base", &tip, fetched], "invalid")
                .map_err(|_| anyhow::anyhow!("{branch} has no merge base with {fetched}; give --base"))?
        }
    };
    let scratch = Scratch::new(&directory.join("peerbox-tmp")).map_err(failure)?;
    let file = scratch.path().join("contribution.bundle");
    git.bundle(&dir, branch, std::slice::from_ref(&base), &file)
        .map_err(failure)?;
    let socket = directory.join("admin.sock");
    let entry = crate::upload(&socket, &file, "contribution.bundle", BUNDLE_TYPE).await?;
    let op = json!({
        "op": "submit",
        "peerbox_id": peerbox,
        "base": base,
        "branch": branch,
        "bundle": entry["sha256"],
    });
    let (value, _, _) = operation_with(local, peer, op, Some(json!([entry]))).await?;
    Ok(value)
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
    operation_with(local, peer, op, None).await
}
/// [`operation`] with input artifacts.
async fn operation_with(
    local: &Local<'_>,
    peer: &str,
    op: Value,
    artifacts: Option<Value>,
) -> anyhow::Result<(Value, Value, String)> {
    let name = op["op"].as_str().unwrap_or_default().to_owned();
    let mut body = json!({
        "peer_host_id": peer,
        "executor": "peerbox",
        "peerbox": op,
        "input": format!("peerbox {name}"),
    });
    if let Some(artifacts) = artifacts {
        body["artifacts"] = artifacts;
    }
    let record = local.post("/v1/tasks".into(), body).await?;
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
    if !dir.exists() {
        git.text(
            scratch.path(),
            &["init", "-q", &dir.to_string_lossy()],
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
        &["init", "-q", "--bare", &quarantine.to_string_lossy()],
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
