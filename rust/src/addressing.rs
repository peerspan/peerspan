//! The directory commands (launch slice 4): `agents`, which shows what this
//! host can reach and who can reach its agents, and `task TARGET TEXT`.
use crate::{
    admin::Local,
    call,
    cli::{TaskTo, encoded},
    integration::DaemonError,
};
use anyhow::Context;
use hyper::Method;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, time::Duration};

/// The policy order of actions.
const ACTIONS: [&str; 3] = ["message.append", "task.submit", "task.delegate"];

fn union(authorizations: &Value) -> Vec<&'static str> {
    let mut found = BTreeSet::new();
    for a in authorizations.as_array().into_iter().flatten() {
        for action in a["actions"].as_array().into_iter().flatten() {
            if let Some(action) = action.as_str() {
                found.insert(action.to_owned());
            }
        }
    }
    ACTIONS
        .iter()
        .copied()
        .filter(|a| found.contains(*a))
        .collect()
}
fn by_address(a: &Value, b: &Value) -> std::cmp::Ordering {
    let key = |v: &Value| {
        (
            v["address"].is_null(),
            v["address"].as_str().unwrap_or_default().to_owned(),
            v["host_id"].as_str().unwrap_or_default().to_owned(),
            v["agent_id"].as_str().unwrap_or_default().to_owned(),
        )
    };
    key(a).cmp(&key(b))
}

/// `agents`: the directory of one network, with this person's agents and
/// the access their policy gives others.
pub async fn agents(
    socket: &Path,
    network: &str,
    refresh: bool,
    as_json: bool,
) -> anyhow::Result<()> {
    let local = Local(socket);
    let query = format!("network={}", encoded(network));
    let directory = if refresh {
        // A refresh waits up to 10 seconds in the daemon.
        tokio::time::timeout(
            Duration::from_secs(20),
            call(
                socket.to_path_buf(),
                Method::POST,
                format!("/v1/directory/refresh?{query}"),
                Some(json!({})),
            ),
        )
        .await
        .context("local host daemon request timed out")??
    } else {
        local.get(format!("/v1/directory?{query}")).await?
    };
    let status = local.get("/v1/status".into()).await?;
    let host = status["host_id"].as_str().unwrap_or_default().to_owned();
    let me = status["networks"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|n| n["id"].as_str() == Some(network))
        .map(|n| n["person"].clone())
        .unwrap_or(Value::Null);
    let person = me["id"].as_str();
    let label = me["label"].as_str();
    let states: std::collections::BTreeMap<String, String> = directory["hosts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|h| {
            Some((
                h["host_id"].as_str()?.to_owned(),
                h["state"].as_str()?.to_owned(),
            ))
        })
        .collect();
    let listed = directory["agents"].as_array().cloned().unwrap_or_default();
    let mut reachable: Vec<Value> = listed
        .iter()
        .filter(|a| !a["address"].is_null())
        .map(|a| {
            let host = a["host_id"].as_str().unwrap_or_default();
            json!({
                "address": a["address"],
                "host_id": a["host_id"],
                "agent_id": a["agent_id"],
                "connected": a["connected"],
                "host_state": states.get(host).cloned().unwrap_or_else(|| "pending".into()),
                "actions": union(&a["authorizations"]),
            })
        })
        .collect();
    reachable.sort_by(by_address);
    // Each session's channel; a daemon that reports none predates channel
    // verification, and a lease alone counts there, as in the directory.
    let sessions = local.get("/v1/sessions".into()).await?;
    let channels: std::collections::BTreeMap<String, Value> = sessions
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s["id"].as_str()?.to_owned(), s.get("channel")?.clone())))
        .collect();
    let mut mine = Vec::new();
    for agent in status["agents"].as_array().into_iter().flatten() {
        let name = agent["name"].as_str().unwrap_or_default();
        if !peerspan_host::directory::addressable(name) {
            continue;
        }
        let duplicate = person.is_some()
            && listed
                .iter()
                .any(|a| a["person_id"].as_str() == person && a["name"].as_str() == Some(name));
        let address = match label {
            Some(label) if !duplicate => format!("{label}/{name}"),
            _ => format!("{host}/{name}"),
        };
        let connected = agent["sessions"].as_array().into_iter().flatten().any(|s| {
            s["connection"] == "ready"
                && s["id"]
                    .as_str()
                    .and_then(|id| channels.get(id))
                    .is_none_or(|c| c == "verified")
        });
        mine.push(json!({
            "address": address,
            "host_id": host,
            "agent_id": agent["id"],
            "connected": connected,
        }));
    }
    if person.is_some() {
        for a in listed.iter().filter(|a| a["person_id"].as_str() == person) {
            mine.push(json!({
                "address": a["address"],
                "host_id": a["host_id"],
                "agent_id": a["agent_id"],
                "connected": a["connected"],
            }));
        }
    }
    mine.sort_by(by_address);
    let mut inbound = Vec::new();
    let mut labels = std::collections::BTreeMap::new();
    if person.is_some() {
        match local
            .get(format!("/v1/networks/{}/policy", encoded(network)))
            .await
        {
            Ok(policy) => {
                for rule in policy["rules"].as_array().into_iter().flatten() {
                    inbound.push(json!({
                        "agent": rule["agent"],
                        "principals": rule["principals"],
                        "actions": rule["actions"],
                        "max_artifact_bytes": rule["max_artifact_bytes"].as_i64().unwrap_or(0),
                    }));
                }
            }
            Err(error)
                if error
                    .downcast_ref::<DaemonError>()
                    .is_some_and(|e| e.status == 404) => {}
            Err(error) => return Err(error),
        }
        if let Ok(persons) = local
            .get(format!("/v1/networks/{}/persons", encoded(network)))
            .await
        {
            for p in persons.as_array().into_iter().flatten() {
                if let (Some(id), Some(member)) = (p["person_id"].as_str(), p["member"].as_str()) {
                    labels.insert(format!("person:{id}"), member.to_owned());
                }
            }
        }
    }
    if as_json {
        let value = json!({
            "network_id": directory["network_id"],
            "refreshed_at": directory["refreshed_at"],
            "reachable": reachable,
            "mine": mine,
            "inbound": inbound,
            "hosts": directory["hosts"],
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let text = |v: &Value| v.as_str().unwrap_or("-").to_owned();
    let list = |v: &Value| {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "Network {} (refreshed {})",
        text(&directory["network_id"]),
        directory["refreshed_at"].as_str().unwrap_or("never")
    );
    println!("\nReachable:");
    if reachable.is_empty() {
        println!("  none");
    }
    for a in &reachable {
        let answered = if a["host_state"] == "ok" {
            String::new()
        } else {
            format!(", host {}", text(&a["host_state"]))
        };
        println!(
            "  {}  {}  {}{answered}",
            text(&a["address"]),
            list(&a["actions"]),
            if a["connected"] == true {
                "connected"
            } else {
                "not connected"
            },
        );
    }
    println!("\nMine:");
    if mine.is_empty() {
        println!("  none");
    }
    for a in &mine {
        println!(
            "  {}  {}",
            a["address"]
                .as_str()
                .unwrap_or(a["agent_id"].as_str().unwrap_or("-")),
            if a["connected"] == true {
                "connected"
            } else {
                "not connected"
            },
        );
    }
    println!("\nInbound:");
    for rule in &inbound {
        let principals = rule["principals"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|p| labels.get(p).cloned().unwrap_or_else(|| p.to_owned()))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {}: {}  {}  files up to {} bytes",
            text(&rule["agent"]),
            principals,
            list(&rule["actions"]),
            rule["max_artifact_bytes"]
        );
    }
    if person.is_some() {
        println!("  Your own hosts reach all of your agents.");
    } else {
        println!("  This host is not bound to a person in this network.");
    }
    Ok(())
}

/// `task TARGET TEXT`: uploads any files, then submits by address.
pub async fn task_to(socket: &Path, args: Vec<String>) -> anyhow::Result<Value> {
    let parsed = match <TaskTo as clap::Parser>::try_parse_from(
        std::iter::once(format!("{} task", crate::program())).chain(args),
    ) {
        Ok(parsed) => parsed,
        Err(error) => error.exit(),
    };
    let mut body = json!({"to": parsed.target, "input": parsed.text});
    if let Some(network) = parsed.network {
        body["network"] = json!(network);
    }
    if let Some(grant) = parsed.grant {
        body["grant_id"] = json!(grant);
    }
    if let Some(agent) = parsed.from_agent {
        body["origin"] = json!({ "agent_id": agent });
    }
    if let Some(deadline) = parsed.deadline {
        body["deadline"] = json!(deadline);
    }
    if !parsed.files.is_empty() {
        let mut entries = Vec::new();
        for path in &parsed.files {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .with_context(|| format!("{} has no UTF-8 file name", path.display()))?
                .to_owned();
            let entry = tokio::time::timeout(
                crate::TRANSFER_TIMEOUT,
                crate::upload(
                    socket,
                    path,
                    &name,
                    peerspan_host::artifact::DEFAULT_MEDIA_TYPE,
                ),
            )
            .await
            .context("artifact upload timed out")??;
            entries.push(entry);
        }
        body["artifacts"] = Value::Array(entries);
    }
    tokio::time::timeout(
        Duration::from_secs(40),
        call(
            socket.to_path_buf(),
            Method::POST,
            "/v1/tasks".into(),
            Some(body),
        ),
    )
    .await
    .context("local host daemon request timed out")?
}
