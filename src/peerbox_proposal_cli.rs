//! The person's side of peerbox agent proposals (peerbox contract, Agent
//! proposals, Approving): `approvals` lists them after the calls, `approvals
//! show pbp_...` and `approve pbp_...` show what will happen, `approve`
//! asks at a terminal and sends the digest it displayed, and `deny pbp_...`
//! denies. Every value the host did not choose is written quoted.
use crate::{admin::Local, cli::encoded, integration::DaemonError};
use anyhow::bail;
use peerspan_host::peerbox_proposals::quoted;
use serde_json::{Value, json};
use std::{io::IsTerminal, path::PathBuf};

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}
fn q(value: &Value, key: &str) -> String {
    quoted(text(value, key))
}
fn path(id: &str) -> String {
    format!("/v1/peerbox-proposals/{}", encoded(id))
}
/// An access as the display writes it: actions and bounds, or none.
fn access(value: &Value) -> String {
    if value.is_null() {
        return "none".into();
    }
    let actions: Vec<&str> = value["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    format!(
        "{}, max_bundle_bytes {}, max_pending {}{}",
        actions.join(" "),
        value["max_bundle_bytes"],
        value["max_pending"],
        if value["allow_disconnected"] == true {
            ", allow_disconnected"
        } else {
            ""
        }
    )
}
fn actions(args: &Value) -> String {
    args["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The question `approve` asks for an operation.
fn question(op: &str) -> &'static str {
    match op {
        "create" => "Create this peerbox? [y/N] ",
        "share" => "Sign a policy giving these people this access? [y/N] ",
        _ => "Create this invite? Your agent will receive the code and choose who gets it. [y/N] ",
    }
}

/// What `approvals show` and `approve` print (What the person sees).
pub(crate) fn display(p: &Value) -> String {
    let args = &p["args"];
    let review = &p["review"];
    let mut out = format!(
        "Prepared by agent {} in session {}. It may be acting on what other people told it; only the lines below are what will happen.\n",
        text(&p["origin"], "agent_id"),
        text(&p["origin"], "session_id")
    );
    out += &format!(
        "Proposal {} ({}): {}; requested at {}, expires at {}\n",
        text(p, "proposal_id"),
        text(p, "op"),
        text(p, "state"),
        text(p, "requested_at"),
        text(p, "expires_at")
    );
    match text(p, "op") {
        "create" => {
            out += &format!(
                "Create a peerbox of the repository {}, branch {}, titled {}, in network {}.\n",
                q(args, "repository"),
                q(args, "branch"),
                q(args, "title"),
                text(args, "network_id")
            );
            out += "A read of this peerbox discloses:\n";
            out += &format!("  head: {}\n", text(review, "head"));
            out += &format!("  commits reachable from it: {}\n", review["commits"]);
            out += &format!(
                "  authors and committers ({}):\n",
                review["identities_total"]
            );
            let identities = review["identities"].as_array().cloned().unwrap_or_default();
            for i in &identities {
                out += &format!("    name {} email {}\n", q(i, "name"), q(i, "email"));
            }
            let total = review["identities_total"].as_u64().unwrap_or(0);
            if total > identities.len() as u64 {
                out += &format!("    and {} more\n", total - identities.len() as u64);
            }
            out += &format!("  bundle size: {} bytes\n", review["bundle_bytes"]);
        }
        "share" => {
            out += &format!(
                "Share the peerbox {} ({}) in network {}:\n",
                q(review, "title"),
                text(args, "peerbox_id"),
                text(review, "network_id")
            );
            let after = json!({
                "actions": args["actions"],
                "max_bundle_bytes": args["max_bundle_bytes"],
                "max_pending": args["max_pending"],
                "allow_disconnected": args["allow_disconnected"],
            });
            let people = review["people"].as_array().cloned().unwrap_or_default();
            let before = review["before"].as_array().cloned().unwrap_or_default();
            for (i, person) in people.iter().enumerate() {
                out += &format!(
                    "  {} ({}): before: {}; after: {}\n",
                    q(person, "label"),
                    text(person, "person_id"),
                    access(before.get(i).unwrap_or(&Value::Null)),
                    access(&after)
                );
            }
            out += &format!("{}\n", crate::peerbox_cli::OLDER_HOSTS);
        }
        _ => {
            out += &format!(
                "Create an invite to network {} for {}, giving access to the peerbox {} ({}): {}, max_bundle_bytes {}, max_pending {}. The code works for {} seconds from approval.\n",
                text(review, "network_id"),
                q(args, "label"),
                q(review, "title"),
                text(args, "peerbox_id"),
                actions(args),
                args["max_bundle_bytes"],
                args["max_pending"],
                args["expires_in_seconds"]
            );
        }
    }
    if let Some(at) = p["decided_at"].as_str() {
        out += &format!("Decided at {at}\n");
    }
    if p["reason"].is_string() {
        out += &format!("Reason: {}\n", q(p, "reason"));
    }
    if !p["error"].is_null() {
        out += &format!(
            "Error: {}: {}\n",
            quoted(text(&p["error"], "code")),
            q(&p["error"], "message")
        );
    }
    if !p["result"].is_null() {
        out += &format!(
            "Result: {}\n",
            quoted(&peerspan_host::canonical::value_text(&p["result"]))
        );
    }
    out
}

/// One readable line of `approvals`.
fn line(p: &Value) -> String {
    let args = &p["args"];
    let review = &p["review"];
    let now = peerspan_host::clock::now();
    let at = |key: &str| {
        chrono::DateTime::parse_from_rfc3339(text(p, key))
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or(now)
    };
    let target = match text(p, "op") {
        "create" => format!("repository {}", q(args, "repository")),
        _ => format!(
            "peerbox {} ({})",
            q(review, "title"),
            text(args, "peerbox_id")
        ),
    };
    let who = match text(p, "op") {
        "share" => format!(
            " for {}",
            review["people"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|person| q(person, "label"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "invite" => format!(" for {}", q(args, "label")),
        _ => String::new(),
    };
    let actions = match text(p, "op") {
        "create" => String::new(),
        _ => format!(" actions {}", actions(args)),
    };
    format!(
        "{} {} {} {}{}{} by agent {}, {} min old, {} min left",
        text(p, "proposal_id"),
        text(p, "op"),
        text(p, "state"),
        target,
        who,
        actions,
        text(&p["origin"], "agent_id"),
        (now - at("requested_at")).num_minutes().max(0),
        (at("expires_at") - now).num_minutes().max(0)
    )
}

/// The proposal list beside the calls: `approvals [--all]`.
pub(crate) async fn list(local: &Local<'_>, every: bool) -> anyhow::Result<Value> {
    let state = if every { "all" } else { "pending" };
    let value = local
        .get(format!("/v1/peerbox-proposals?state={state}"))
        .await?;
    Ok(value["peerbox_proposals"].clone())
}
/// The readable proposal block of `approvals`.
pub(crate) fn print_list(list: &Value) {
    let list = list.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("No peerbox proposals are waiting for your approval.");
        return;
    }
    println!("Peerbox proposals:");
    for p in &list {
        println!("{}", line(p));
    }
}

/// `approvals show pbp_... [--json]`.
pub(crate) async fn show(local: &Local<'_>, id: &str, json: bool) -> anyhow::Result<Option<Value>> {
    let record = local.get(path(id)).await?;
    if json {
        return Ok(Some(record));
    }
    print!("{}", display(&record));
    crate::exit(0)
}

/// `approve pbp_... [--person-key PATH]`: at a terminal only, after
/// showing the proposal and asking; prints the record as JSON and exits 0
/// for `executed`, 1 for `failed`.
pub(crate) async fn approve(
    local: &Local<'_>,
    id: &str,
    person_key: &Option<PathBuf>,
) -> anyhow::Result<Value> {
    if !std::io::stdin().is_terminal() {
        bail!("peerspan approve needs a terminal: approval must come from the person.");
    }
    let record = local.get(path(id)).await?;
    eprint!("{}", display(&record));
    // A proposal no longer pending is sent as is; its 409 exits 1.
    if record["state"] == "pending" && !crate::capability_cli::ask(question(text(&record, "op")))? {
        bail!("not approved; nothing changed");
    }
    let key = person_key
        .as_ref()
        .map(std::path::absolute)
        .transpose()?
        .map(|p| p.to_string_lossy().into_owned());
    let outcome = local
        .post(
            format!("{}/approve", path(id)),
            json!({"proposal_sha256": record["proposal_sha256"], "person_key": key}),
        )
        .await;
    let done = match outcome {
        Ok(done) => done,
        Err(e)
            if e.downcast_ref::<DaemonError>()
                .is_some_and(|d| d.code == "person_key_needed") =>
        {
            bail!(
                "signing this policy needs your person key; nothing changed and the proposal is still pending: run peerspan approve {id} --person-key PATH"
            )
        }
        Err(e) => return Err(e),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&done).unwrap_or_else(|_| done.to_string())
    );
    if done["state"] == "executed" {
        crate::exit(0)
    }
    crate::exit(1)
}

/// `deny pbp_... [--reason TEXT]`.
pub(crate) async fn deny(
    local: &Local<'_>,
    id: &str,
    reason: &Option<String>,
) -> anyhow::Result<Value> {
    local
        .post(format!("{}/deny", path(id)), json!({ "reason": reason }))
        .await
}
