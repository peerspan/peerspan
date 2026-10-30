//! `conversations` and `conversation start|say|show` (conversations
//! contract, C1). Unlisted in the root help until C6 (CONV-24).
use crate::{
    admin::Local,
    cli::{Command, ConversationCommand},
};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn handles(command: &Command) -> bool {
    matches!(
        command,
        Command::Conversations { .. } | Command::Conversation(_)
    )
}

/// Runs a conversation command; daemon refusals print as `CODE: TEXT`.
pub(crate) async fn run(command: Command, socket: &Path) -> anyhow::Result<()> {
    match execute(command, socket).await {
        Err(error) => match error.downcast::<crate::integration::DaemonError>() {
            Ok(d) if !d.code.is_empty() => bail!("{}: {}", d.code, d.message),
            Ok(d) => Err(d.into()),
            Err(other) => Err(other),
        },
        ok => ok,
    }
}

fn print(value: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
use crate::cli::encoded;

async fn execute(command: Command, socket: &Path) -> anyhow::Result<()> {
    let local = Local(socket);
    match command {
        Command::Conversations { all, json } => {
            let state = if all { "all" } else { "open" };
            let value = local
                .get(format!("/v1/conversations?state={state}"))
                .await?;
            if json {
                return print(&value);
            }
            for c in value["conversations"].as_array().into_iter().flatten() {
                let id = text(&c["conversation_id"]);
                let mut line = id.chars().take(13).collect::<String>();
                if let Some(title) = c["title"].as_str() {
                    line.push_str(&format!("  \"{title}\""));
                }
                let labels: Vec<&str> = c["participants"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| text(&p["label"]))
                    .collect();
                line.push_str(&format!("  {}", labels.join(", ")));
                let last = c["last_message_at"]
                    .as_str()
                    .unwrap_or_else(|| text(&c["created_at"]));
                line.push_str(&format!("  {last}"));
                println!("{line}");
            }
            Ok(())
        }
        Command::Conversation(ConversationCommand::Start {
            target,
            title,
            message,
            message_id,
            network,
        }) => {
            let mut body = json!({ "participants": [target] });
            if let Some(title) = title {
                body["title"] = json!(title);
            }
            if let Some(message) = message {
                body["content"] = json!(message);
            }
            if let Some(id) = message_id {
                body["message_id"] = json!(id);
            }
            if let Some(network) = network {
                body["network"] = json!(network);
            }
            print(&local.post("/v1/conversations".into(), body).await?)
        }
        Command::Conversation(ConversationCommand::Say {
            id,
            text: content,
            message_id,
        }) => {
            let id = resolve(&local, &id).await?;
            let mut body = json!({ "content": content });
            if let Some(m) = message_id {
                body["message_id"] = json!(m);
            }
            print(
                &local
                    .post(format!("/v1/conversations/{id}/messages"), body)
                    .await?,
            )
        }
        Command::Conversation(ConversationCommand::Show {
            id,
            limit,
            before,
            as_agent,
            json,
        }) => {
            let id = resolve(&local, &id).await?;
            let mut query = String::new();
            let mut reader = None;
            if let Some(agent) = as_agent {
                let host = local.get("/v1/host".into()).await?;
                let agents = local.get("/v1/agents".into()).await?;
                let found = agents
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|a| text(&a["id"]) == agent || text(&a["name"]) == agent)
                    .with_context(|| format!("no agent {agent} on this host"))?;
                let participant = format!("agent:{}/{}", text(&host["id"]), text(&found["id"]));
                query = format!("participant={}", encoded(&participant));
                reader = Some(participant);
            }
            let conversation = local.get(format!("/v1/conversations/{id}?{query}")).await?;
            let mut page = format!("/v1/conversations/{id}/messages?limit={limit}");
            if !query.is_empty() {
                page.push_str(&format!("&{query}"));
            }
            if let Some(before) = before {
                page.push_str(&format!("&before={}", encoded(&before)));
            }
            let messages = local.get(page).await?;
            if json {
                return print(&json!({
                    "conversation": conversation,
                    "messages": messages["messages"],
                    "next_before_message_id": messages["next_before_message_id"],
                }));
            }
            readable(&conversation, &messages, reader.as_deref());
            Ok(())
        }
        _ => unreachable!("not a conversation command"),
    }
}

/// A full ID, or `conv_` and at least 6 hex digits naming exactly one.
async fn resolve(local: &Local<'_>, id: &str) -> anyhow::Result<String> {
    let hex = id.strip_prefix("conv_").unwrap_or_default();
    if hex.len() == 32 {
        return Ok(id.to_owned());
    }
    if hex.len() < 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("not_found: no conversation {id}");
    }
    let all = local.get("/v1/conversations?state=all".into()).await?;
    let matches: Vec<String> = all["conversations"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| text(&c["conversation_id"]).to_owned())
        .filter(|c| c.starts_with(id))
        .collect();
    match matches.as_slice() {
        [] => bail!("not_found: no conversation {id}"),
        [one] => Ok(one.clone()),
        many => bail!("ambiguous: {id} matches {}", many.join(", ")),
    }
}

fn hhmm(time: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(time)
        .map(|t| t.with_timezone(&chrono::Utc).format("%H:%M").to_string())
        .unwrap_or_default()
}

fn readable(conversation: &Value, messages: &Value, reader: Option<&str>) {
    let participants = conversation["participants"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let you = |p: &Value| match reader {
        Some(r) => text(&p["id"]) == r,
        None => p["local"] == true && p["kind"] == "person",
    };
    let mut header = format!(
        "{}…",
        text(&conversation["conversation_id"])
            .chars()
            .take(13)
            .collect::<String>()
    );
    if let Some(title) = conversation["title"].as_str() {
        header.push_str(&format!(" \"{title}\""));
    }
    println!(
        "{header}   {}   {} participants",
        text(&conversation["state"]),
        participants.len()
    );
    let labels: Vec<String> = participants
        .iter()
        .map(|p| {
            let mut label = text(&p["label"]).to_owned();
            if you(p) {
                label.push_str(" (you)");
            } else if p["state"] != "joined" {
                label.push_str(&format!(" ({})", text(&p["state"])));
            }
            label
        })
        .collect();
    println!("  {}", labels.join("   "));
    println!();
    let list = messages["messages"].as_array().cloned().unwrap_or_default();
    let width = list
        .iter()
        .map(|m| text(&m["author_label"]).len())
        .max()
        .unwrap_or(0);
    for m in &list {
        println!(
            "{}  {:width$}  {}",
            hhmm(text(&m["sent_at"])),
            text(&m["author_label"]),
            text(&m["content"])
        );
        for t in m["targets"].as_array().into_iter().flatten() {
            match text(&t["state"]) {
                "delivered" => {}
                "sending" => println!(
                    "         not yet received by {} (sending)",
                    text(&t["label"])
                ),
                state => println!(
                    "         not received by {} ({state}: {})",
                    text(&t["label"]),
                    text(&t["code"])
                ),
            }
        }
    }
}
