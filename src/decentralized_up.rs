//! Guided enrollment uses the same explicit coordinator-free ceremonies as the
//! native commands. Unfinished work retains its identity and blocks attachment.
use crate::{
    admin::Local,
    cli::{UpArgs, encoded},
};
use anyhow::{Context, Result, bail, ensure};
use peerspan_host::{
    decentralized::{Invitation, local_decision_time},
    persons,
};
use serde_json::{Value, json};
use std::{
    io::{self, IsTerminal},
    path::Path,
};

fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("invalid setup {k}"))
}
async fn list(local: &Local<'_>) -> Result<Vec<Value>> {
    local
        .get("/v2/networks".into())
        .await?
        .as_array()
        .cloned()
        .context("invalid network list")
}
fn migration_pending(result: &mut Value, v: &Value) -> Result<()> {
    if v["state"] == "migration_prepared" {
        let request = text(v, "request_id")?;
        result["network"] = json!({"link_request":v});
        result["next"] = json!(format!("peerspan link cancel {request}"));
        bail!(
            "this host was prepared for an in-place migration, which is no longer supported; cancel request {request}, then join the new network with a fresh invite"
        );
    }
    Ok(())
}
fn incomplete(result: &mut Value, v: &Value) -> Result<()> {
    migration_pending(result, v)?;
    let id = text(v, "request_id")?;
    let mut public = v.clone();
    if let Some(o) = public.as_object_mut() {
        o.remove("display_code");
    }
    result["network"] = json!({"link_request":public});
    result["next"] = json!(format!("peerspan link resume {id}"));
    ensure!(
        v["state"] == "linked",
        "machine linking is incomplete; resume the same request {id}"
    );
    Ok(())
}
async fn guide(socket: &Path, mut v: Value) -> Result<Value> {
    let terminal = io::stdin().is_terminal();
    if !terminal && let Some(o) = v.as_object_mut() {
        o.remove("display_code");
    }
    let mut v = crate::link_cli::guide(socket, v, terminal).await?;
    if let Some(o) = v.as_object_mut() {
        o.remove("display_code");
    }
    Ok(v)
}
pub(crate) async fn network(
    state: &Path,
    args: &mut UpArgs,
    mut intro: Option<String>,
    result: &mut Value,
) -> Result<(Value, bool)> {
    let socket = state.join("admin.sock");
    let local = Local(&socket);
    let mut all = list(&local).await?;
    ensure!(
        all.len() <= 1,
        "guided up supports one network; use explicit network and attach commands"
    );
    let was_existing = !all.is_empty();
    let pending = local.get("/v2/link/requests".into()).await?;
    let pending = pending.as_array().context("invalid linking requests")?;
    let pending: Vec<_> = pending
        .iter()
        .filter(|v| {
            v["role"] == "requester"
                && !matches!(
                    v["state"].as_str(),
                    Some("linked" | "cancelled" | "migration_adopted")
                )
        })
        .collect();
    ensure!(
        pending.len() <= 1,
        "multiple machine links need review; inspect peerspan link status"
    );
    if let Some(v) = pending.first() {
        migration_pending(result, v)?;
        let id = text(v, "request_id")?;
        result["network"] = json!({"link_request":v});
        result["next"] = json!(format!("peerspan link resume {id}"));
        ensure!(
            args.create.is_none() && args.join.is_none() && !args.link,
            "an existing machine link requires explicit resume or cancellation before another setup choice"
        );
        let v = crate::link_cli::resume(
            &socket,
            id,
            args.person_key.as_deref(),
            None,
            io::stdin().is_terminal(),
            false,
        )
        .await?;
        incomplete(result, &v)?;
        all = list(&local).await?;
    }
    if all.is_empty() && args.create.is_none() && args.join.is_none() && !args.link {
        let choice = crate::up::prompt("Create a network, link this machine, or join through a private introduction (create/link/join)", "", false)
            .await.context("choose --create NAME, --link or --join with private input")?;
        match choice.as_str() {
            "create" => {
                args.create = Some(crate::up::prompt("Network name", "personal", false).await?)
            }
            "link" => args.link = true,
            "join" => {
                args.join = Some("-".into());
                let token = args.invitation.read().await?;
                Invitation::read_token(&token, &local_decision_time()?)?;
                intro = Some(token);
            }
            _ => bail!("choose create, link or join"),
        }
    }
    if all.is_empty() {
        if args.link {
            ensure!(
                args.person_key.is_none() && args.person.is_none(),
                "same-person linking keeps the original key on its original machine"
            );
            let v = local
                .post(
                    "/v2/link/requests".into(),
                    json!({"mode":"new",
                "network_id":"-","person_public_key":"-","migration_proposal_id":"-",
                "contact_invitation":"-","helpers":[]}),
                )
                .await?;
            let v = guide(&socket, v).await?;
            incomplete(result, &v)?;
        } else if let Some(token) = &intro {
            let v =
                crate::decentralized_onboarding_cli::create_join(&local, token, &args.person_key)
                    .await?;
            let v = guide(&socket, v).await?;
            incomplete(result, &v)?;
        } else {
            let name = args
                .create
                .as_deref()
                .context("choose --create NAME, --link or --join")?;
            let member = args
                .person
                .clone()
                .or_else(crate::login_name)
                .context("cannot determine the login name; give --as LABEL")?;
            let choice = crate::choose_key(&args.person_key)?;
            let v = crate::decentralized_cli::create(&local, name, &member, &choice).await?;
            result["network"] = v.clone();
            ensure!(
                v["mode"] == "decentralized",
                "network creation is incomplete; retain its exact pending identity and review"
            );
        }
        all = list(&local).await?;
    }
    ensure!(
        all.len() == 1,
        "membership changed during setup; inspect peerspan status"
    );
    let n = all.remove(0);
    result["network"] = n.clone();
    let id = text(&n, "id")?;
    result["next"] = json!(format!("peerspan network sync {id}"));
    ensure!(
        n["mode"] == "decentralized",
        "this legacy network needs explicit whole-network migration"
    );
    ensure!(
        args.create.as_deref().is_none_or(|name| n["name"] == name),
        "creation inputs conflict with the existing network; use explicit network commands"
    );
    if let Some(token) = &intro {
        let i = Invitation::read_token(token, &local_decision_time()?)?;
        ensure!(
            n["id"] == i.descriptor.network_id && n["context_id"] == i.descriptor.context_id(),
            "the introduction names a different network"
        );
    }
    ensure!(
        n["authority"]["state"] == "usable",
        "network authority needs repair: {}; required_ids {}",
        n["authority"]["state"],
        n["authority"]["required_ids"]
    );
    ensure!(
        n["person_public_key"] != "-",
        "this host remains unbound; retain its existing identity and review binding"
    );
    ensure!(
        args.person
            .as_deref()
            .is_none_or(|member| n["member"] == member),
        "--as differs from the existing bound person"
    );
    if let Some(path) = args.person_key.as_deref() {
        let key = persons::PersonSigner::open(Some(path))?;
        ensure!(
            n["person_public_key"] == key.public_key_b64(),
            "the original key differs from this host's remembered person"
        );
    }
    // A present but broken selected device never falls back to an original key.
    let provider = local
        .get(format!("/v2/networks/{}/provider", encoded(id)))
        .await?;
    ensure!(
        provider["person_public_key"] == n["person_public_key"]
            && provider["host_public_key"] == n["host_public_key"]
            && matches!(
                provider["kind"].as_str(),
                Some("original_person" | "device")
            ),
        "repair this host's exact selected owner provider before attachment"
    );
    ensure!(
        provider["scopes"].as_u64().is_some_and(|s| s & 1 != 0),
        "the selected owner provider lacks policy scope1 for setup and renewal"
    );
    Ok((n, was_existing))
}
