//! Native finite group/administrator mutations use fixed owner-local v2 actions.
use crate::{
    admin::Local,
    cli::{Command, GroupCommand, NetworkCommand, encoded, resolved},
    decentralized_action_cli::{self as action, Authority, Plan, decode, ident, stamp, text},
    decentralized_policy_cli::{current_persons, network_view},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use peerspan_host::persons;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

async fn target_person(local: &Local<'_>, p: &Plan, given: &str) -> Result<String> {
    if decode(given).is_ok_and(|b| b.len() == 32) {
        return Ok(given.into());
    }
    let people = current_persons(local, p.network()).await?;
    let matches: Vec<_> = people
        .iter()
        .filter(|row| {
            let key = row["person_public_key"].as_str().unwrap_or("");
            given == row["member"].as_str().unwrap_or("")
                || decode(key).is_ok_and(|key| persons::person_id(&key) == given)
        })
        .collect();
    ensure!(
        matches.len() == 1,
        "person is missing or ambiguous; give its exact stable key"
    );
    Ok(text(matches[0], "person_public_key")?.into())
}
async fn target_host(local: &Local<'_>, p: &Plan, given: &str) -> Result<String> {
    if decode(given).is_ok_and(|b| b.len() == 32) {
        return Ok(given.into());
    }
    let v = local
        .get(format!(
            "/v2/networks/{}/members",
            encoded(&p.descriptor.network_id)
        ))
        .await?;
    ensure!(
        v["context_id"] == p.descriptor.context_id(),
        "member context changed"
    );
    let mut found = BTreeSet::new();
    for m in v["members"].as_array().context("invalid current members")? {
        let key = text(m, "host_public_key")?;
        let raw = decode(key)?;
        ensure!(raw.len() == 32, "invalid current host key");
        if given == format!("host_{}", hex::encode(Sha256::digest(raw))) || m["member"] == given {
            found.insert(key.to_owned());
        }
    }
    ensure!(
        found.len() == 1,
        "host is missing or ambiguous; inactive target needs its exact stable key"
    );
    Ok(found.into_iter().next().expect("one target"))
}
fn ids(values: &[String]) -> Result<Vec<String>> {
    let mut ids = values.to_vec();
    ids.sort();
    ensure!(
        ids.iter().all(|s| ident(s, "ds_")) && ids.windows(2).all(|x| x[0] != x[1]),
        "expected unique exact ds_ references"
    );
    Ok(ids)
}
fn deadline(a: &Authority, explicit: Option<&str>) -> Result<String> {
    let until = explicit.map(stamp).transpose()?.unwrap_or(a.until);
    ensure!(
        until > a.now && until <= a.until,
        "not-after exceeds current finite path ceiling"
    );
    Ok(until.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}
#[allow(clippy::too_many_arguments)]
async fn group(
    local: &Local<'_>,
    p: &Plan,
    name: &str,
    members: &[String],
    selector: &str,
    original: Option<&Path>,
    root: Option<&Path>,
    after: Option<&str>,
) -> Result<Value> {
    peerspan_host::admins::group_name(name)?;
    let mut selected = BTreeSet::new();
    for given in members {
        let key = target_person(local, p, given).await?;
        selected.insert(persons::person_id(&decode(&key)?));
    }
    let (version, heads) = p.stream("group", name)?;
    ensure!(
        heads.len() <= 1,
        "resolve all exact group heads before defining a fresh group"
    );
    let seq = version.checked_add(1).context("version exhausted")?;
    let a = Authority::read(local, p, selector, original, root, 8, true, 1).await?;
    let now = a.now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let body = json!({"network_id":p.descriptor.network_id,"name":name,"version":seq,"defined_at":now,"members":selected});
    let payload = json!({"root_state_id":p.network()["root_state_id"],"operation_id":"-","sequence":seq,"predecessors":heads,"resolves":[],"issuer":a.issuer,"parents":a.parents,"issued_at":now,"not_before":now,"not_after":deadline(&a,after)?,"body_base64":STANDARD.encode(serde_json::to_vec(&body)?)});
    action::run(
        local,
        p,
        &a,
        "group",
        payload,
        "Approve this exact finite group definition?",
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn mutation(
    local: &Local<'_>,
    p: &Plan,
    kind: &str,
    given: &str,
    selector: &str,
    original: Option<&Path>,
    root: Option<&Path>,
    after: Option<&str>,
    keep: &[String],
    revoke: bool,
    resolves: &[String],
    exact_role: Option<&str>,
) -> Result<Value> {
    let root_only = matches!(kind, "admin_lease" | "admin_withdraw");
    if root_only {
        ensure!(
            selector == "network_root" || root.is_some(),
            "root-only action requires explicit --signer network_root or --root-key"
        );
    }
    let a = Authority::read(
        local,
        p,
        selector,
        original,
        root,
        if kind == "host_unbind" { 2 } else { 8 },
        kind != "host_unbind",
        7,
    )
    .await?;
    if root_only {
        ensure!(
            a.issuer["kind"] == "root",
            "only the exact current root grants/withdraws administrator roles"
        );
    }
    let now = a.now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut target = json!({"person_public_key":"-","host_public_key":"-","device_public_key":"-","statement_id":"-"});
    if matches!(kind, "admin_lease" | "admin_withdraw" | "person_remove") {
        target["person_public_key"] = json!(target_person(local, p, given).await?);
    } else {
        target["host_public_key"] = json!(target_host(local, p, given).await?);
    }
    let mut kept = Vec::new();
    if kind == "admin_lease" {
        let (version, heads) = p.stream("admin", text(&target, "person_public_key")?)?;
        let mut resolve_set: BTreeSet<String> = resolves.iter().cloned().collect();
        if heads.len() > 1 {
            resolve_set.extend(heads.iter().cloned());
        }
        let resolves = ids(&resolve_set.into_iter().collect::<Vec<_>>())?;
        let seq = version.checked_add(1).context("version exhausted")?;
        let subject = json!({"person_public_key":target["person_public_key"],"host_public_key":"-","device_public_key":"-","member":"-","scopes":8});
        let payload = json!({"root_state_id":p.network()["root_state_id"],"operation_id":"-","sequence":seq,"predecessors":heads,"resolves":resolves,"retained_statement_ids":[],"subject":subject,"issuer":a.issuer,"parents":a.parents,"issued_at":now,"not_before":now,"not_after":deadline(&a,after)?});
        return action::run(
            local,
            p,
            &a,
            kind,
            payload,
            "Approve this exact finite administrator role?",
        )
        .await;
    }
    if kind == "admin_withdraw" {
        ensure!(
            revoke || !keep.is_empty(),
            "give every exact --keep admission or explicitly --revoke-admitted; no role retention default is inferred from raw heads"
        );
        ensure!(
            !revoke || keep.is_empty(),
            "keep and revoke-admitted conflict"
        );
        let role = match exact_role {
            Some(id) => {
                ensure!(ident(id, "ds_"), "invalid exact administrator role ID");
                id.to_owned()
            }
            None => p.head("admin", text(&target, "person_public_key")?)?,
        };
        let s = p.catalog.get(&role)?;
        let v = Value::Object(s.payload.clone());
        ensure!(
            s.kind == "admin_lease"
                && v["subject"]["person_public_key"] == target["person_public_key"],
            "administrator target differs from exact role"
        );
        target["statement_id"] = json!(role);
        kept = ids(keep)?;
        for id in &kept {
            let s = p.catalog.get(id)?;
            let v = Value::Object(s.payload.clone());
            ensure!(
                matches!(s.kind.as_str(), "person_lease" | "host_lease")
                    && v["parents"].as_array().is_some_and(|ps| ps
                        .iter()
                        .any(|x| x["role"] == "issuer_admin" && x["id"] == role)),
                "kept admission must have this exact issuer_admin role"
            );
        }
    } else if kind == "host_unbind" {
        let binding = p.head("binding", text(&target, "host_public_key")?)?;
        let s = p.catalog.get(&binding)?;
        let v = Value::Object(s.payload.clone());
        ensure!(
            s.kind == "binding_lease"
                && v["subject"]["host_public_key"] == target["host_public_key"]
                && v["subject"]["person_public_key"] == a.issuer["person_public_key"],
            "unbind needs the exact original owner or same-person bound device2"
        );
        target["person_public_key"] = v["subject"]["person_public_key"].clone();
        target["statement_id"] = json!(binding);
    }
    let payload = json!({"root_state_id":p.network()["root_state_id"],"issuer":a.issuer,"parents":a.parents,"issued_at":now,"target":target,"kept_statement_ids":kept,"ratifies":"-"});
    action::run(
        local,
        p,
        &a,
        kind,
        payload,
        if matches!(kind, "person_remove" | "host_revoke") {
            "Approve this irreversible stable-key network ban?"
        } else {
            "Approve this exact role or binding withdrawal?"
        },
    )
    .await
}
pub(crate) async fn command(command: &Command, socket: &Path) -> Result<Option<Value>> {
    let Command::Network(command) = command else {
        return Ok(None);
    };
    let id = match command {
        NetworkCommand::Group(GroupCommand::Set { network, .. })
        | NetworkCommand::DelegateAdmin { network, .. }
        | NetworkCommand::RemovePerson { network, .. }
        | NetworkCommand::Unbind { network, .. } => resolved(network),
        NetworkCommand::RemoveAdmin { network, .. } | NetworkCommand::Revoke { network, .. } => {
            network
        }
        _ => return Ok(None),
    };
    let local = Local(socket);
    let Some(network) = network_view(&local, id).await? else {
        return Ok(None);
    };
    let approve = match command {
        NetworkCommand::Group(GroupCommand::Set { approve, .. })
        | NetworkCommand::DelegateAdmin { approve, .. }
        | NetworkCommand::RemoveAdmin { approve, .. }
        | NetworkCommand::RemovePerson { approve, .. }
        | NetworkCommand::Revoke { approve, .. }
        | NetworkCommand::Unbind { approve, .. } => *approve,
        _ => false,
    };
    action::APPROVED.store(approve, std::sync::atomic::Ordering::Relaxed);
    let p = Plan::read(&local, &network).await?;
    Ok(Some(match command {
        NetworkCommand::Group(GroupCommand::Set {
            group: name,
            person,
            signer,
            person_key,
            root_key,
            not_after,
            ..
        }) => {
            group(
                &local,
                &p,
                name,
                person,
                signer,
                person_key.as_deref(),
                root_key.as_deref(),
                not_after.as_deref(),
            )
            .await?
        }
        NetworkCommand::DelegateAdmin {
            person,
            signer,
            root_key,
            not_after,
            resolve,
            ..
        } => {
            mutation(
                &local,
                &p,
                "admin_lease",
                person,
                signer,
                None,
                root_key.as_deref(),
                not_after.as_deref(),
                &[],
                false,
                resolve,
                None,
            )
            .await?
        }
        NetworkCommand::RemoveAdmin {
            person,
            signer,
            root_key,
            keep,
            revoke_admitted,
            statement,
            ..
        } => {
            mutation(
                &local,
                &p,
                "admin_withdraw",
                person,
                signer,
                None,
                root_key.as_deref(),
                None,
                keep,
                *revoke_admitted,
                &[],
                statement.as_deref(),
            )
            .await?
        }
        NetworkCommand::RemovePerson {
            person,
            signer,
            person_key,
            root_key,
            ..
        } => {
            mutation(
                &local,
                &p,
                "person_remove",
                person,
                signer,
                person_key.as_deref(),
                root_key.as_deref(),
                None,
                &[],
                false,
                &[],
                None,
            )
            .await?
        }
        NetworkCommand::Revoke {
            host,
            signer,
            person_key,
            root_key,
            ..
        } => {
            mutation(
                &local,
                &p,
                "host_revoke",
                host,
                signer,
                person_key.as_deref(),
                root_key.as_deref(),
                None,
                &[],
                false,
                &[],
                None,
            )
            .await?
        }
        NetworkCommand::Unbind {
            host,
            signer,
            person_key,
            ..
        } => {
            mutation(
                &local,
                &p,
                "host_unbind",
                host,
                signer,
                person_key.as_deref(),
                None,
                None,
                &[],
                false,
                &[],
                None,
            )
            .await?
        }
        _ => unreachable!("selected administration command"),
    }))
}
