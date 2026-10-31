//! `conversations` and `conversation start|say|show|watch|add|remove|close|leave|join|decline|read|forget|sync`
//! (conversations contract, C1 to C6). Peer-supplied text is escaped in all output.
use crate::{
    admin::Local,
    capability_cli::escaped,
    cli::{Command, ConversationCommand},
};
use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{IsTerminal, Write},
    path::Path,
    time::Duration,
};

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
            Ok(d) if !d.code.is_empty() => bail!("{}: {}", d.code, escaped(&d.message)),
            Ok(d) => bail!("{}", escaped(&d.to_string())),
            Err(other) => bail!("{}", escaped(&format!("{other:#}"))),
        },
        ok => ok,
    }
}

/// JSON text with U+007F and U+0080 to U+009F written as `\\u00XX`: they can
/// only be inside strings, and parsing returns the original text.
pub(crate) fn json_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
fn print(value: &Value) -> anyhow::Result<()> {
    println!("{}", json_text(&serde_json::to_string_pretty(value)?));
    Ok(())
}
/// A value's text, escaped for a terminal.
fn safe(value: &Value) -> String {
    escaped(text(value))
}
fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
use crate::cli::encoded;

async fn execute(command: Command, socket: &Path) -> anyhow::Result<()> {
    let local = Local(socket);
    match command {
        Command::Conversations {
            invites: true,
            json,
            ..
        } => {
            let value = local.get("/v1/conversations/invites".into()).await?;
            if json {
                return print(&value);
            }
            let list = value["invites"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                println!("No pending conversation invites.");
            }
            for i in &list {
                let mut line = text(&i["conversation_id"])
                    .chars()
                    .take(13)
                    .collect::<String>();
                if let Some(title) = i["title"].as_str() {
                    line.push_str(&format!("  \"{}\"", escaped(title)));
                }
                line.push_str(&format!(
                    "  from {}  expires {}",
                    safe(&i["added_by_label"]),
                    safe(&i["expires_at"])
                ));
                println!("{line}");
            }
            Ok(())
        }
        Command::Conversations { all, json, .. } => {
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
                    line.push_str(&format!("  \"{}\"", escaped(title)));
                }
                let labels: Vec<String> = c["participants"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| safe(&p["label"]))
                    .collect();
                line.push_str(&format!("  {}", labels.join(", ")));
                let last = c["last_message_at"]
                    .as_str()
                    .unwrap_or_else(|| text(&c["created_at"]));
                line.push_str(&format!("  {}", escaped(last)));
                if let Some(n) = c["unread"].as_i64().filter(|n| *n > 0) {
                    line.push_str(&format!("  {n} unread"));
                }
                println!("{line}");
            }
            Ok(())
        }
        Command::Conversation(ConversationCommand::Start {
            targets,
            title,
            message,
            message_id,
            note,
            as_agent,
            network,
            about,
        }) => {
            let mut body = json!({ "participants": targets });
            if let Some(about) = about {
                let (host, task) = about
                    .split_once('/')
                    .context("--about takes HOST_ID/TASK_ID")?;
                body["about"] = json!({"peer_host_id": host, "task_id": task});
            }
            if let Some(title) = title {
                body["title"] = json!(title);
            }
            if let Some(message) = message {
                body["content"] = json!(message);
            }
            if let Some(id) = message_id {
                body["message_id"] = json!(id);
            }
            if let Some(note) = note {
                body["note"] = json!(note);
            }
            if let Some(agent) = as_agent {
                body["as"] = json!(agent);
            }
            if let Some(network) = network {
                body["network"] = json!(network);
            }
            print(&local.post("/v1/conversations".into(), body).await?)
        }
        Command::Conversation(ConversationCommand::Add {
            id,
            target,
            as_agent,
            network,
        }) => {
            let id = resolve(&local, &id).await?;
            let mut body = json!({ "action": "add", "participant": target });
            if let Some(agent) = as_agent {
                body["as"] = json!(agent);
            }
            if let Some(network) = network {
                body["network"] = json!(network);
            }
            manage(&local, &id, body).await
        }
        Command::Conversation(ConversationCommand::Remove {
            id,
            participant,
            as_agent,
        }) => {
            let id = resolve(&local, &id).await?;
            let mut body = json!({ "action": "remove", "participant": participant });
            if let Some(agent) = as_agent {
                body["as"] = json!(agent);
            }
            manage(&local, &id, body).await
        }
        Command::Conversation(ConversationCommand::Close { id, as_agent }) => {
            let id = resolve(&local, &id).await?;
            let mut body = json!({ "action": "close" });
            if let Some(agent) = as_agent {
                body["as"] = json!(agent);
            }
            manage(&local, &id, body).await
        }
        Command::Conversation(ConversationCommand::Leave { id, agent }) => {
            let id = resolve(&local, &id).await?;
            let mut body = json!({});
            if let Some(agent) = agent {
                body["agent"] = json!(agent);
            }
            print(
                &local
                    .post(format!("/v1/conversations/{id}/leave"), body)
                    .await?,
            )
        }
        Command::Conversation(ConversationCommand::Join { id }) => {
            let id = resolve_invite(&local, &id).await?;
            print(
                &local
                    .post(format!("/v1/conversations/{id}/join"), json!({}))
                    .await?,
            )
        }
        Command::Conversation(ConversationCommand::Decline { id }) => {
            let id = resolve_invite(&local, &id).await?;
            print(
                &local
                    .post(format!("/v1/conversations/{id}/decline"), json!({}))
                    .await?,
            )
        }
        Command::Conversation(ConversationCommand::Sync { id }) => {
            let id = resolve(&local, &id).await?;
            print(
                &local
                    .post(format!("/v1/conversations/{id}/sync"), json!({}))
                    .await?,
            )
        }
        Command::Conversation(ConversationCommand::Say {
            id,
            text: content,
            message_id,
            to,
        }) => {
            let id = resolve(&local, &id).await?;
            let mut body = json!({ "content": content });
            if !to.is_empty() {
                body["addressed_to"] = json!(to);
            }
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
                let participant = agent_participant(&local, &agent).await?;
                query = format!("participant={}", encoded(&participant));
                reader = Some(participant);
            }
            let conversation = local.get(format!("/v1/conversations/{id}?{query}")).await;
            let conversation = match (conversation, &reader) {
                (Err(error), None) => return Err(point_to_as(&local, &id, error).await),
                (conversation, _) => conversation?,
            };
            let mut page = format!("/v1/conversations/{id}/messages?limit={limit}");
            if !query.is_empty() {
                page.push_str(&format!("&{query}"));
            }
            if let Some(before) = before {
                page.push_str(&format!("&before={}", encoded(&before)));
            }
            let messages = local.get(page).await?;
            if json {
                print(&json!({
                    "conversation": conversation,
                    "messages": messages["messages"],
                    "next_before_message_id": messages["next_before_message_id"],
                }))?;
            } else {
                readable(&conversation, &messages, reader.as_deref());
            }
            if reader.is_none() {
                let ids: Vec<String> = messages["messages"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|m| text(&m["message_id"]).to_owned())
                    .collect();
                advance(&local, &id, ids).await;
            }
            Ok(())
        }
        Command::Conversation(ConversationCommand::Read { id }) => {
            let id = resolve(&local, &id).await?;
            print(
                &local
                    .post(format!("/v1/conversations/{id}/read"), json!({}))
                    .await?,
            )
        }
        Command::Conversation(ConversationCommand::Forget { id, yes }) => {
            let id = resolve(&local, &id).await?;
            if !yes {
                if !std::io::stdin().is_terminal() {
                    bail!("confirm: conversation forget needs --yes when not at a terminal.");
                }
                eprint!("Delete this host's copy of {id}? [y/N] ");
                std::io::stderr().flush()?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let answer = answer.trim().to_ascii_lowercase();
                if answer != "y" && answer != "yes" {
                    println!("Not forgotten.");
                    return Ok(());
                }
            }
            print(&local.delete(format!("/v1/conversations/{id}")).await?)
        }
        Command::Conversation(ConversationCommand::Watch { id, as_agent }) => {
            let mut query = String::new();
            let mut reader = None;
            if let Some(agent) = as_agent {
                let participant = agent_participant(&local, &agent).await?;
                query.push_str(&format!("&participant={}", encoded(&participant)));
                reader = Some(participant);
            }
            let whole_host = id.is_none();
            if let Some(id) = id {
                let id = resolve(&local, &id).await?;
                let read = local
                    .get(format!(
                        "/v1/conversations/{id}?{}",
                        &query[query.len().min(1)..]
                    ))
                    .await;
                match (read, &reader) {
                    (Err(error), None) => return Err(point_to_as(&local, &id, error).await),
                    (read, _) => {
                        read?;
                    }
                }
                query.push_str(&format!("&conversation={id}"));
            }
            use tokio::signal::unix::{SignalKind, signal};
            let mut interrupt = signal(SignalKind::interrupt())?;
            let mut terminate = signal(SignalKind::terminate())?;
            tokio::select! {
                result = watch(&local, &query, reader.as_deref(), whole_host) => result,
                _ = interrupt.recv() => Ok(()),
                _ = terminate.recv() => Ok(()),
            }
        }
        _ => unreachable!("not a conversation command"),
    }
}

async fn manage(local: &Local<'_>, id: &str, body: Value) -> anyhow::Result<()> {
    print(
        &local
            .post(format!("/v1/conversations/{id}/manage"), body)
            .await?,
    )
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

/// A full ID, or `conv_` and at least 6 hex digits naming exactly one
/// current pending invite on this host.
async fn resolve_invite(local: &Local<'_>, id: &str) -> anyhow::Result<String> {
    const NONE: &str = "not_found: No pending invite to that conversation on this host.";
    let hex = id.strip_prefix("conv_").unwrap_or_default();
    if hex.len() == 32 {
        return Ok(id.to_owned());
    }
    if hex.len() < 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(NONE);
    }
    let all = local.get("/v1/conversations/invites".into()).await?;
    let mut matches: Vec<String> = all["invites"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| text(&c["conversation_id"]).to_owned())
        .filter(|c| c.starts_with(id))
        .collect();
    matches.dedup();
    match matches.as_slice() {
        [] => bail!(NONE),
        [one] => Ok(one.clone()),
        many => bail!("ambiguous: {id} matches {}", many.join(", ")),
    }
}

/// The participant ID of a local agent, by name or ID.
async fn agent_participant(local: &Local<'_>, agent: &str) -> anyhow::Result<String> {
    let host = local.get("/v1/host".into()).await?;
    let agents = local.get("/v1/agents".into()).await?;
    let found = agents
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| text(&a["id"]) == agent || text(&a["name"]) == agent)
        .with_context(|| format!("no agent {agent} on this host"))?;
    Ok(format!(
        "agent:{}/{}",
        text(&host["id"]),
        text(&found["id"])
    ))
}
/// The names of this host's agents joined in a conversation listed in
/// `summary`, sorted and joined by `, `; empty when there are none.
async fn joined_agents(local: &Local<'_>, summary: &Value) -> anyhow::Result<String> {
    let ids: Vec<&str> = summary["participants"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["kind"] == "agent" && p["local"] == true && p["state"] == "joined")
        .filter_map(|p| p["id"].as_str()?.rsplit('/').next())
        .collect();
    if ids.is_empty() {
        return Ok(String::new());
    }
    let agents = local.get("/v1/agents".into()).await?;
    let mut names: Vec<String> = ids
        .iter()
        .map(|id| {
            agents
                .as_array()
                .into_iter()
                .flatten()
                .find(|a| text(&a["id"]) == *id)
                .map_or(id.to_string(), |a| text(&a["name"]).to_owned())
        })
        .collect();
    names.sort();
    Ok(escaped(&names.join(", ")))
}
/// A refused person's read, with what to do when agents here are in it.
async fn point_to_as(local: &Local<'_>, id: &str, error: anyhow::Error) -> anyhow::Error {
    let error = match error.downcast::<crate::integration::DaemonError>() {
        Ok(d) => d,
        Err(other) => return other,
    };
    if error.code != "not_participant" && error.code != "not_bound" {
        return error.into();
    }
    let Ok(all) = local.get("/v1/conversations?state=all".into()).await else {
        return error.into();
    };
    let summary = all["conversations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|c| text(&c["conversation_id"]) == id);
    let Some(Ok(names)) = (match summary {
        Some(summary) => Some(joined_agents(local, summary).await),
        None => None,
    }) else {
        return error.into();
    };
    if names.is_empty() {
        return error.into();
    }
    crate::integration::DaemonError {
        status: error.status,
        message: format!(
            "{} Agents on this host that are: {names}. Use --as NAME.",
            error.message
        ),
        code: error.code,
    }
    .into()
}
/// Says once per conversation why it is not being shown, for the open ones
/// where agents here take part and this host's person does not.
async fn note_agent_only(local: &Local<'_>, noted: &mut BTreeSet<String>) {
    let Ok(open) = local.get("/v1/conversations?state=open".into()).await else {
        return;
    };
    for c in open["conversations"].as_array().into_iter().flatten() {
        let id = text(&c["conversation_id"]);
        let person_here = c["participants"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|p| p["kind"] == "person" && p["local"] == true && p["state"] == "joined");
        if person_here || noted.contains(id) {
            continue;
        }
        let Ok(names) = joined_agents(local, c).await else {
            continue;
        };
        if names.is_empty() {
            continue;
        }
        noted.insert(id.to_owned());
        let short: String = id.chars().take(13).collect();
        eprintln!(
            "Not showing {}: this host's person is not in it. Agents on this host that are: {names}. Use conversation watch --as NAME.",
            escaped(&short)
        );
    }
}
/// Moves the person's read cursor past messages just shown. Printing already
/// happened; a failure leaves them unread.
async fn advance(local: &Local<'_>, id: &str, ids: Vec<String>) {
    for chunk in ids.chunks(100) {
        let _ = local
            .post(
                format!("/v1/conversations/{id}/read"),
                json!({ "message_ids": chunk }),
            )
            .await;
    }
}
/// The longest `conversation watch` holds a message past a gap.
const HOLD: Duration = Duration::from_secs(5);
/// A message past a gap, waiting for the earlier ones.
struct Held {
    conversation: String,
    message: String,
    author: String,
    seq: i64,
    since: std::time::Instant,
}
/// A message's place in display order, per conversation.
fn display_key(conversation: &str, m: &Value) -> (String, i64, String, i64) {
    (
        conversation.to_owned(),
        m["clock"].as_i64().unwrap_or(0),
        text(&m["author"]).to_owned(),
        m["seq"].as_i64().unwrap_or(0),
    )
}
/// `conversation watch`: long-polls the event log from where it is now.
async fn watch(
    local: &Local<'_>,
    query: &str,
    reader: Option<&str>,
    whole_host: bool,
) -> anyhow::Result<()> {
    let first = local
        .get(format!("/v1/conversations/events?wait=0&limit=1{query}"))
        .await?;
    let mut after = first["latest"].as_i64().unwrap_or(0);
    eprintln!("Watching; press Ctrl-C to stop.");
    let participant = reader
        .map(|r| format!("?participant={}", encoded(r)))
        .unwrap_or_default();
    let mut said = BTreeSet::new();
    let mut noted = BTreeSet::new();
    let mut held: Vec<Held> = Vec::new();
    // Printed and not yet posted to the read cursor.
    let mut shown: Vec<(String, String)> = Vec::new();
    // Past their hold, waiting to print with this round's events.
    let mut released: Vec<(String, Value)> = Vec::new();
    loop {
        if whole_host && reader.is_none() {
            note_agent_only(local, &mut noted).await;
        }
        // Before the event read, so what closed a gap prints with what it released.
        let mut waiting = Vec::new();
        for h in held {
            let path = format!(
                "/v1/conversations/{}/messages/{}{participant}",
                h.conversation, h.message
            );
            match local.get(path).await {
                Ok(view) if view["earlier_missing"] == true && h.since.elapsed() < HOLD => {
                    waiting.push(h);
                }
                Ok(view) => released.push((h.conversation, view["message"].clone())),
                // Not reachable now: read again, and print by the limit if it can be read.
                Err(e)
                    if e.downcast_ref::<crate::integration::DaemonError>()
                        .is_none() =>
                {
                    waiting.push(h);
                }
                Err(_) => {}
            }
        }
        held = waiting;
        // A held message is read again at least once a second.
        let wait = match (held.is_empty(), released.is_empty()) {
            (false, _) => 1,
            (true, false) => 0,
            (true, true) => 25,
        };
        let path = format!("/v1/conversations/events?after={after}&wait={wait}&limit=100{query}");
        let answer = match local.get(path).await {
            Ok(answer) => answer,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        after = answer["next_after"].as_i64().unwrap_or(after);
        let mut ready: Vec<(String, Value)> = Vec::new();
        let events_read = answer["events"].as_array().map_or(0, Vec::len);
        for event in answer["events"].as_array().into_iter().flatten() {
            let id = text(&event["conversation_id"]);
            let short: String = id.chars().take(13).collect();
            let kind = text(&event["kind"]);
            let message = text(&event["message_id"]);
            match kind {
                "message_sent" | "message_received" | "target_changed" => {
                    let path = format!("/v1/conversations/{id}/messages/{message}{participant}");
                    let Ok(view) = local.get(path).await else {
                        continue;
                    };
                    let m = &view["message"];
                    if kind == "target_changed" {
                        for t in m["targets"].as_array().into_iter().flatten() {
                            let state = text(&t["state"]);
                            let key = (
                                message.to_owned(),
                                text(&t["participant"]).to_owned(),
                                state.to_owned(),
                            );
                            if state != "delivered" && state != "sending" && said.insert(key) {
                                println!("{short}  {}", target_line(t));
                            }
                        }
                    } else if view["earlier_missing"] == true {
                        held.push(Held {
                            conversation: id.to_owned(),
                            message: message.to_owned(),
                            author: text(&m["author"]).to_owned(),
                            seq: m["seq"].as_i64().unwrap_or(0),
                            since: std::time::Instant::now(),
                        });
                    } else {
                        ready.push((id.to_owned(), m.clone()));
                    }
                }
                "roster_changed" => println!("{short}  participants or state changed"),
                "invited" => println!("{short}  you were invited"),
                _ => {}
            }
        }
        // Whatever closed a gap committed its event first, so the read above
        // sees it. A full page may leave more: wait for the rest.
        released.append(&mut ready);
        if events_read < 100 {
            ready = std::mem::take(&mut released);
        }
        // A later message of an author with an earlier one held waits behind it.
        let (later, mut ready): (Vec<_>, Vec<_>) = ready.into_iter().partition(|(id, m)| {
            held.iter().any(|h| {
                h.conversation == *id
                    && h.author == text(&m["author"])
                    && h.seq < m["seq"].as_i64().unwrap_or(0)
            })
        });
        released.extend(later);
        ready.sort_by_cached_key(|(id, m)| display_key(id, m));
        for (id, m) in &ready {
            let short: String = id.chars().take(13).collect();
            println!("{short}  {}", message_line(m, 0));
            if reader.is_none() {
                shown.push((id.clone(), text(&m["message_id"]).to_owned()));
            }
        }
        std::io::stdout().flush()?;
        if reader.is_none() {
            // The cursor is one high-water mark, so a later arrival's ID would
            // also pass a held message: wait until the conversation holds none.
            let conversations: BTreeSet<String> = shown
                .iter()
                .map(|s| s.0.clone())
                .filter(|id| !held.iter().any(|h| h.conversation == *id))
                .collect();
            for id in conversations {
                let (ids, rest): (Vec<_>, Vec<_>) = shown.drain(..).partition(|s| s.0 == id);
                shown = rest;
                advance(local, &id, ids.into_iter().map(|s| s.1).collect()).await;
            }
        }
    }
}
/// One message's line, the author label padded to `width`.
fn message_line(m: &Value, width: usize) -> String {
    let labels: Vec<String> = m["addressed_to_labels"]
        .as_array()
        .into_iter()
        .flatten()
        .map(safe)
        .collect();
    let to = if labels.is_empty() {
        String::new()
    } else {
        format!("  to {}", labels.join(", "))
    };
    format!(
        "{}  {:width$}{to}  {}",
        hhmm(text(&m["sent_at"])),
        safe(&m["author_label"]),
        safe(&m["content"])
    )
}
/// The line for a target not `delivered`.
fn target_line(t: &Value) -> String {
    match text(&t["state"]) {
        state @ ("sending" | "stopped") => {
            format!("not yet received by {} ({state})", safe(&t["label"]))
        }
        state => format!(
            "not received by {} ({}: {})",
            safe(&t["label"]),
            escaped(state),
            safe(&t["code"])
        ),
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
        header.push_str(&format!(" \"{}\"", escaped(title)));
    }
    println!(
        "{header}   {}   {} participants{}",
        safe(&conversation["state"]),
        participants.len(),
        if conversation["home_unavailable"] == true {
            "   home unavailable"
        } else {
            ""
        }
    );
    if let Some(about) = conversation["about"].as_object() {
        println!(
            "  about task {} on {}",
            about.get("task_id").map(safe).unwrap_or_default(),
            about.get("peer_host_id").map(safe).unwrap_or_default()
        );
    }
    let labels: Vec<String> = participants
        .iter()
        .map(|p| {
            let mut label = safe(&p["label"]);
            if you(p) {
                label.push_str(" (you)");
            } else if p["state"] != "joined" {
                label.push_str(&format!(" ({})", safe(&p["state"])));
            }
            label
        })
        .collect();
    println!("  {}", labels.join("   "));
    println!();
    let list = messages["messages"].as_array().cloned().unwrap_or_default();
    let width = list
        .iter()
        .map(|m| safe(&m["author_label"]).chars().count())
        .max()
        .unwrap_or(0);
    for m in &list {
        println!("{}", message_line(m, width));
        for t in m["targets"].as_array().into_iter().flatten() {
            if t["state"] != "delivered" {
                println!("         {}", target_line(t));
            }
        }
    }
}
