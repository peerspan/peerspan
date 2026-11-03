//! Display exact verified public group bodies without opening a signer.
use crate::{
    admin::Local,
    cli::{Command, NetworkCommand, encoded, resolved},
    decentralized_policy_cli::network_view,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use peerspan_host::decentralized::{Descriptor, Statement};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Groups {
    context_id: String,
    groups: Vec<Group>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    name: String,
    statement_id: String,
    statement_base64: String,
}

pub(crate) async fn command(command: &Command, socket: &Path) -> Result<Option<Value>> {
    let Command::Network(NetworkCommand::Groups { id }) = command else {
        return Ok(None);
    };
    let id = resolved(id);
    let local = Local(socket);
    let Some(network) = network_view(&local, id).await? else {
        return Ok(None);
    };
    ensure!(network["id"] == id, "group network changed during display");
    let descriptor = Descriptor::read(&serde_json::to_vec(&json!({
        "format":1,"protocol":"peerspan-decentralized-v1","network_id":id,
        "name":network["name"],"genesis_root_public_key":network["genesis_root_public_key"]
    }))?)?;
    let response: Groups = serde_json::from_value(
        local
            .get(format!("/v2/networks/{}/groups", encoded(id)))
            .await?,
    )?;
    ensure!(
        response.context_id == descriptor.context_id() && response.groups.len() <= 4096,
        "group response changes context or exceeds its bound"
    );
    let mut groups = Vec::new();
    let mut previous = None;
    for entry in response.groups {
        ensure!(
            previous
                .as_ref()
                .is_none_or(|name: &String| name < &entry.name),
            "group names must be sorted and unique"
        );
        peerspan_host::admins::group_name(&entry.name)?;
        ensure!(
            entry.statement_base64.len() <= 4 * ((1 << 20_usize) + 2) / 3,
            "group statement exceeds its bound"
        );
        let raw = STANDARD.decode(&entry.statement_base64)?;
        ensure!(
            raw.len() <= 1 << 20 && STANDARD.encode(&raw) == entry.statement_base64,
            "group statement is not bounded canonical Base64"
        );
        let statement = Statement::read(&descriptor, &raw)?;
        ensure!(
            statement.kind == "group" && statement.id == entry.statement_id,
            "group response changes exact signed statement"
        );
        let body = statement
            .payload
            .get("body_base64")
            .and_then(Value::as_str)
            .context("missing signed group body")?;
        let body: Value = serde_json::from_slice(&STANDARD.decode(body)?)?;
        ensure!(
            body["name"] == entry.name && body["network_id"] == id,
            "group response changes the exact signed name/network"
        );
        groups.push(json!({"name":entry.name,"members":body["members"],
            "version":body["version"],"statement_id":statement.id}));
        previous = Some(entry.name);
    }
    Ok(Some(json!(groups)))
}
