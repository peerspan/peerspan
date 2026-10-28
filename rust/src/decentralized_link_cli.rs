//! Native coordinator-free linking: typed reviews, exact key roles and two
//! independent requester confirmations. Original keys remain on this machine.
use crate::{admin::Local, cli::encoded};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Subcommand};
use ed25519_dalek::Signer;
use peerspan_host::{
    decentralized::{
        Catalog, Descriptor, FixedPacket, FixedStatement, PairingToken, Statement,
        local_decision_time, migration_person_labels,
    },
    persons::PersonSigner,
};
use serde_json::{Value, json};
use std::{
    io::{self, IsTerminal, Read},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Args)]
pub struct LinkArgs {
    #[arg(long)]
    renew: bool,
    #[arg(long)]
    network: Option<String>,
    #[arg(long)]
    expect_person: Option<String>,
    #[command(subcommand)]
    command: Option<LinkCommand>,
}
#[derive(Debug, Args)]
struct Keys {
    #[arg(long, alias = "person-key-file")]
    person_key: Option<PathBuf>,
    #[arg(long)]
    root_key: Option<PathBuf>,
}
#[derive(Debug, Args)]
struct Approval {
    /// A link request ID already on this machine, for example one returned
    /// through an invite; its code is read from the daemon, not the prompt.
    request: Option<String>,
    #[arg(long)]
    network: String,
    #[arg(long, alias = "expect-person")]
    person: Option<String>,
    #[arg(long)]
    expect_host_key: Option<String>,
    #[arg(long)]
    expect_device_key: Option<String>,
    /// Signing provider: defaults to network_root for admit and auto for approve.
    #[arg(long, alias = "provider")]
    signer: Option<String>,
    #[arg(long, default_value = "auto")]
    signature_format: String,
    #[arg(long)]
    scopes: Option<u64>,
    #[arg(long)]
    not_after: Option<String>,
    #[arg(long)]
    owner_offer: Option<String>,
    #[arg(long)]
    selection: Option<String>,
    #[arg(long)]
    code_stdin: bool,
    #[arg(long)]
    approve: bool,
    #[command(flatten)]
    keys: Keys,
}
#[derive(Debug, Args)]
struct Consent {
    request_id: String,
    #[arg(long)]
    owner_offer: Option<String>,
    #[arg(long)]
    network: Option<String>,
    #[arg(long)]
    context: Option<String>,
    #[arg(long)]
    expect_person: Option<String>,
    #[arg(long)]
    expect_host_key: Option<String>,
    #[arg(long)]
    expect_device_key: Option<String>,
    #[arg(long)]
    selection: Option<String>,
    #[arg(long)]
    administrator_offer: Option<String>,
    #[arg(long)]
    owner_finalization: Option<String>,
    #[arg(long)]
    approve: bool,
}
#[derive(Debug, Subcommand)]
enum LinkCommand {
    Approve(Approval),
    Admit(Approval),
    Finalize {
        #[command(flatten)]
        consent: Consent,
        #[command(flatten)]
        keys: Keys,
    },
    Status {
        request_id: Option<String>,
    },
    Resume {
        request_id: String,
        #[command(flatten)]
        keys: Keys,
    },
    Cancel {
        request_id: String,
    },
    Select(Consent),
    Commit(Consent),
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("invalid linking {k}"))
}
fn shape(v: &Value, names: &str) -> Result<()> {
    let o = v.as_object().context("invalid linking object")?;
    let names: Vec<_> = names.split_whitespace().collect();
    ensure!(
        o.len() == names.len() && names.iter().all(|k| o.contains_key(*k)),
        "unexpected linking fields"
    );
    Ok(())
}
fn ident(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 64
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode(value: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(value)?;
    ensure!(
        STANDARD.encode(&bytes) == value,
        "noncanonical linking template"
    );
    Ok(bytes)
}
fn key(value: &str) -> bool {
    decode(value).is_ok_and(|v| v.len() == 32)
}
fn arg(v: Option<String>) -> String {
    v.unwrap_or_else(|| "-".into())
}
fn base(id: &str) -> Result<String> {
    ensure!(ident(id, "link_"), "invalid link request ID");
    Ok(format!("/v2/link/requests/{}", encoded(id)))
}
fn view(v: &Value) -> Result<()> {
    let mut fields = v.clone();
    if let Some(o) = fields.as_object_mut() {
        o.remove("display_code");
    }
    shape(
        &fields,
        "request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next",
    )?;
    ensure!(
        ident(text(v, "request_id")?, "link_")
            && matches!(text(v, "role")?, "requester" | "approver"),
        "invalid linking identity/role"
    );
    ensure!(
        matches!(
            text(v, "state")?,
            "pending"
                | "needs_selection"
                | "needs_administrator"
                | "needs_owner_finalization"
                | "needs_commit"
                | "finalizing"
                | "linked"
                | "migration_prepared"
                | "migration_adopted"
                | "cancelled"
                | "expired"
                | "blocked"
        ),
        "invalid linking state"
    );
    ensure!(
        key(text(v, "host_public_key")?) && key(text(v, "device_public_key")?),
        "invalid requester keys"
    );
    Ok(())
}
fn request(wrapper: &Value) -> Result<Value> {
    view(&wrapper["request"])?;
    Ok(wrapper["request"].clone())
}
pub(crate) fn output(mut v: Value, display: bool) -> Result<()> {
    if !display && let Some(o) = v.as_object_mut() {
        o.remove("display_code");
    }
    if v.is_array() {
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    // `join` adds its trust answer (CLI output, not part of the daemon view).
    let mut checked = v.clone();
    if let Some(o) = checked.as_object_mut() {
        o.remove("trusted");
        o.remove("trusted_error");
    }
    view(&checked)?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    if v["state"] != "linked" {
        bail!("linking is incomplete; follow the returned next step");
    }
    Ok(())
}
async fn confirm(question: &str) -> Result<bool> {
    Ok(matches!(
        crate::up::prompt(question, "no", false)
            .await?
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "y" | "yes"
    ))
}
async fn private_code(stdin: bool) -> Result<String> {
    let value = if stdin {
        let mut s = String::new();
        io::stdin()
            .lock()
            .take((32 << 10) + 1)
            .read_to_string(&mut s)?;
        s.trim_end_matches(['\r', '\n']).into()
    } else {
        crate::up::prompt_bounded("Private linking code (hidden)", "", true, 32 << 10).await?
    };
    ensure!(
        value.len() <= 32 << 10 && !value.contains(['\n', '\r']),
        "invalid private linking code"
    );
    Ok(value)
}
fn describe(review: &Value) -> Result<()> {
    shape(
        review,
        "stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning",
    )?;
    eprintln!("{}", serde_json::to_string_pretty(review)?);
    Ok(())
}
fn pins(r: &Value, approve: bool) -> Value {
    json!({"owner_offer_id":r["owner_offer_id"],"network_id":r["network_id"],"context_id":r["context_id"],"person_public_key":r["person_public_key"],"host_public_key":r["host_public_key"],"device_public_key":r["device_public_key"],"approve":approve})
}
async fn network(local: &Local<'_>, name: &str) -> Result<Value> {
    let all = local.get("/v2/networks".into()).await?;
    let networks = all.as_array().context("invalid networks")?;
    let n = networks
        .iter()
        .find(|n| n["id"] == name || n["name"] == name || (name == "-" && networks.len() == 1))
        .context("choose the exact existing coordinator-free network with --network")?;
    ensure!(
        n["mode"] == "decentralized",
        "this network needs explicit migration"
    );
    Ok(n.clone())
}
fn same_target(a: &Value, b: &Value) -> Result<()> {
    for k in [
        "network_id",
        "context_id",
        "person_public_key",
        "host_public_key",
        "device_public_key",
        "scopes",
        "not_after",
    ] {
        ensure!(a[k] == b[k], "link signing changed reviewed {k}");
    }
    for k in [
        "root_state_id",
        "owner_offer_id",
        "selection_id",
        "administrator_offer_id",
        "person_lease_id",
        "host_lease_id",
        "binding_lease_id",
        "device_lease_id",
    ] {
        if a[k] != "-" {
            ensure!(a[k] == b[k], "link signing changed the fixed {k}");
        }
    }
    let prior = &a["provider"];
    let next = &b["provider"];
    if prior["kind"] == "original_person" && prior["scopes"] == 0 {
        // A new original person's exact pending self-consent can learn its
        // administrator's concrete P/root later, without choosing another key.
        for k in [
            "kind",
            "person_public_key",
            "host_public_key",
            "device_public_key",
        ] {
            ensure!(
                prior[k] == next[k],
                "pending self-consent changed provider {k}"
            );
        }
    } else {
        ensure!(
            prior == next && a["root_state_id"] == b["root_state_id"],
            "link signing changed the approved provider/root"
        );
    }
    Ok(())
}
fn check_slot(entry: &Value, r: &Value, v: &Value, local_host: &str) -> Result<(String, bool)> {
    shape(
        entry,
        "intent_id slot_id object_type object_id role public_key format template_base64 message_base64",
    )?;
    ensure!(
        text(entry, "intent_id")?.starts_with("dint_")
            && entry["slot_id"].as_u64().is_some_and(|n| n > 0),
        "invalid signing intent/slot"
    );
    let context = text(r, "context_id")?;
    ensure!(
        ident(context, "ctx_")
            && r["network_id"] == v["network_id"]
            && r["context_id"] == v["context_id"],
        "linking context changed"
    );
    let kind = text(entry, "object_type")?;
    let role = text(entry, "role")?;
    let public = text(entry, "public_key")?;
    let format = text(entry, "format")?;
    let provider = &r["provider"];
    ensure!(
        matches!(text(provider, "kind")?, "original_person" | "network_root"),
        "owned device roles are never external signing slots"
    );
    if provider["kind"] == "original_person" {
        ensure!(
            provider["person_public_key"] == public && format == "sshsig",
            "original signing key/format changed"
        );
    }
    let raw = decode(text(entry, "template_base64")?)?;
    let outer: Value = serde_json::from_slice(&raw)?;
    let payload: Value = serde_json::from_slice(&decode(text(&outer, "payload_base64")?)?)?;
    let (slots, object, packet) = if kind.ends_with("_packet") {
        let fixed = FixedPacket::read_context(context, &raw)?;
        let expected = match kind {
            "owner_offer_packet" => "owner",
            "administrator_packet" => "administrator",
            "owner_finalization_packet" => "owner_finalization",
            _ => bail!("unreviewed packet signing role"),
        };
        ensure!(
            role == "authority"
                && outer["role"] == expected
                && outer["request_id"] == v["request_id"]
                && outer["writer_host_public_key"] == local_host
                && outer["signer_public_key"] == public
                && outer["authority_signature_format"] == format,
            "packet changes reviewed ceremony/key/role"
        );
        if provider["kind"] == "network_root" {
            ensure!(
                outer["person_public_key"] == "-" && outer["issuer_id"] == r["root_state_id"],
                "root packet changes reviewed issuer"
            );
        } else {
            ensure!(
                outer["person_public_key"] == provider["person_public_key"],
                "packet changes original signer"
            );
        }
        for field in match expected {
            "owner" => &[
                "request_packet_id",
                "root_state_id",
                "person_lease_id",
                "host_public_key",
                "device_public_key",
                "scopes",
                "not_after",
            ][..],
            "administrator" => &["owner_offer_id", "selection_id", "root_state_id"][..],
            _ => &[
                "selection_id",
                "administrator_offer_id",
                "root_state_id",
                "person_lease_id",
                "host_lease_id",
            ][..],
        } {
            let expected = if *field == "request_packet_id" {
                &v[*field]
            } else {
                &r[*field]
            };
            ensure!(
                &payload[*field] == expected,
                "packet changes reviewed {field}"
            );
        }
        (fixed.pending()?, fixed.packet_id().to_owned(), true)
    } else {
        ensure!(
            matches!(
                kind,
                "person_lease" | "host_lease" | "binding_lease" | "device_lease"
            ) && role == "issuer",
            "unreviewed grant signing role"
        );
        let fixed = FixedStatement::read_link(context, &raw)?;
        let reference = match kind {
            "person_lease" => "person_lease_id",
            "host_lease" => "host_lease_id",
            "binding_lease" => "binding_lease_id",
            _ => "device_lease_id",
        };
        ensure!(
            r[reference] == fixed.statement_id(),
            "grant differs from the concrete reviewed {reference}"
        );
        for parent in payload["parents"]
            .as_array()
            .context("invalid typed grant parents")?
        {
            let reference = match text(parent, "role")? {
                "subject_person" => Some("person_lease_id"),
                "subject_host" => Some("host_lease_id"),
                "subject_binding" => Some("binding_lease_id"),
                _ => None,
            };
            if let Some(reference) = reference {
                ensure!(
                    parent["id"] == r[reference],
                    "grant changes reviewed parent {reference}"
                );
            }
        }
        ensure!(
            outer["kind"] == kind
                && payload["operation_id"] == v["request_id"]
                && payload["root_state_id"] == r["root_state_id"]
                && payload["not_after"] == r["not_after"],
            "grant changes reviewed operation/finite terms"
        );
        let subject = &payload["subject"];
        if kind != "host_lease" {
            ensure!(
                subject["person_public_key"] == r["person_public_key"],
                "grant changes target person"
            );
        }
        if kind != "person_lease" {
            ensure!(
                subject["host_public_key"] == r["host_public_key"],
                "grant changes target host"
            );
        }
        if kind == "device_lease" {
            ensure!(
                subject["device_public_key"] == r["device_public_key"]
                    && subject["scopes"] == r["scopes"],
                "grant changes reviewed device/powers"
            );
        }
        (fixed.pending(), fixed.statement_id().to_owned(), false)
    };
    ensure!(entry["object_id"] == object, "typed object ID changed");
    let slot = slots
        .iter()
        .find(|s| s.role == role)
        .context("typed signature role is not ready")?;
    ensure!(
        slot.public_key == public
            && slot.signature_format == format
            && entry["message_base64"] == slot.message_base64,
        "typed signature message/key/format differs"
    );
    let now = local_decision_time()?;
    ensure!(
        now.as_str() < text(v, "expires_at")?,
        "link signing window expired; retain and inspect this request"
    );
    Ok((slot.message_base64.clone(), packet))
}
async fn signatures(
    socket: &Path,
    mut response: Value,
    person_key: Option<&Path>,
    root_key: Option<&Path>,
) -> Result<Value> {
    let local = Local(socket);
    let identity = local.get("/v1/host".into()).await?;
    let host = text(&identity, "public_key")?;
    let mut pinned = response["review"].clone();
    for _ in 0..257 {
        describe_shape(&response)?;
        same_target(&pinned, &response["review"])?;
        pinned = response["review"].clone();
        let requests = response["signing_requests"]
            .as_array()
            .context("invalid signing batch")?;
        if requests.is_empty() {
            return Ok(response);
        }
        ensure!(requests.len() <= 16, "too many ready signature slots");
        let mut id = None;
        let mut previous = None;
        let mut batch = Vec::new();
        for entry in requests {
            let (message, packet) =
                check_slot(entry, &response["review"], &response["request"], host)?;
            let pair = (
                entry["slot_id"].as_u64().context("invalid slot")?,
                text(entry, "role")?.to_owned(),
            );
            ensure!(
                previous.as_ref().is_none_or(|old| old < &pair),
                "unordered/duplicate signature slots"
            );
            previous = Some(pair);
            let intent = text(entry, "intent_id")?;
            ensure!(
                id.is_none_or(|old| old == intent),
                "mixed signing intentions"
            );
            id = Some(intent);
            let public = text(entry, "public_key")?;
            let provider = &response["review"]["provider"];
            let path = if provider["kind"] == "network_root" {
                root_key
            } else {
                person_key
            };
            let signer = if let Some(path) = path {
                PersonSigner::open(Some(path))?
            } else if provider["kind"] == "original_person" {
                // A fresh original join may have saved its key locally without
                // an ssh-agent. Select only the exact reviewed original key.
                let generated = peerspan_host::persons::generated_key_path()
                    .filter(|p| p.exists())
                    .map(|p| PersonSigner::open(Some(&p)))
                    .transpose()?;
                match generated {
                    Some(signer) if signer.public_key_b64() == public => signer,
                    _ => PersonSigner::agent_with(public)?,
                }
            } else {
                PersonSigner::agent_with(public)?
            };
            ensure!(
                signer.public_key_b64() == public,
                "keep the exact reviewed original/root key on its own machine"
            );
            if provider["kind"] == "network_root" {
                let n = network(&local, text(&response["review"], "network_id")?).await?;
                ensure!(
                    n["root_public_key"] == public
                        && n["root_state_id"] == response["review"]["root_state_id"],
                    "root signer differs from independently reviewed current root"
                );
            }
            let bytes = decode(&message)?;
            let signature = match text(entry, "format")? {
                "sshsig" => {
                    signer.sign(&std::str::from_utf8(&bytes)?.split('\n').collect::<Vec<_>>())?
                }
                "ed25519" => {
                    let PersonSigner::File(key) = signer else {
                        bail!("raw root signing needs its explicitly supplied private key file")
                    };
                    STANDARD.encode(key.sign(&bytes).to_bytes())
                }
                _ => bail!("invalid signature format"),
            };
            let raw = decode(text(entry, "template_base64")?)?;
            if packet {
                FixedPacket::read_context(text(&response["review"], "context_id")?, &raw)?
                    .check_signature(text(entry, "role")?, &signature)?;
            } else {
                FixedStatement::read_link(text(&response["review"], "context_id")?, &raw)?
                    .check_signature(text(entry, "role")?, &signature)?;
            }
            batch.push(
                json!({"slot_id":entry["slot_id"],"role":entry["role"],"signature":signature}),
            );
        }
        let path = format!(
            "{}/signed",
            base(text(&response["request"], "request_id")?)?
        );
        let next = local
            .post(
                path,
                json!({"intent_id":id.context("missing intent")?,"signatures":batch}),
            )
            .await?;
        ensure!(
            next["request"]["request_id"] == response["request"]["request_id"],
            "signing response changes request"
        );
        response = next;
    }
    bail!("too many dependency signature batches; resume the exact retained request")
}
fn describe_shape(response: &Value) -> Result<()> {
    shape(response, "request review signing_requests")?;
    view(&response["request"])?;
    shape(
        &response["review"],
        "stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning",
    )
}
pub async fn resume(
    socket: &Path,
    id: &str,
    person_key: Option<&Path>,
    root_key: Option<&Path>,
    interactive: bool,
    display_code: bool,
) -> Result<Value> {
    let local = Local(socket);
    let mut v = local
        .post(format!("{}/resume", base(id)?), json!({}))
        .await?;
    view(&v)?;
    // A completed result must never reopen approval or use retired secrets.
    if matches!(
        v["state"].as_str(),
        Some("linked" | "migration_prepared" | "migration_adopted")
    ) {
        return Ok(v);
    }
    if v["role"] == "approver" {
        let approval = local.get(format!("{}/approval", base(id)?)).await?;
        v = request(&signatures(socket, approval, person_key, root_key).await?)?;
    }
    if !display_code && let Some(o) = v.as_object_mut() {
        o.remove("display_code");
    }
    guide(socket, v, interactive).await
}
pub(crate) async fn guide(socket: &Path, mut v: Value, interactive: bool) -> Result<Value> {
    view(&v)?;
    let code = v.get("display_code").cloned();
    if let Some(code) = code.as_ref().and_then(Value::as_str) {
        eprintln!("Approve this private code on an existing machine: {code}");
    }
    if !interactive || v["role"] != "requester" {
        return Ok(v);
    }
    let local = Local(socket);
    loop {
        let path = base(text(&v, "request_id")?)?;
        match text(&v, "state")? {
            "linked" | "cancelled" | "expired" | "blocked" | "migration_prepared"
            | "migration_adopted" => return Ok(v),
            "needs_selection" | "needs_commit" => {
                let commit = v["state"] == "needs_commit";
                let mut body = pins(&v, false);
                if commit {
                    for k in [
                        "selection_id",
                        "administrator_offer_id",
                        "owner_finalization_id",
                    ] {
                        body[k] = v[k].clone();
                    }
                }
                let route = format!("{path}/{}", if commit { "commit" } else { "selection" });
                let preview = local.post(route.clone(), body).await?;
                describe(&preview["review"])?;
                if !confirm(if commit {
                    "Commit this exact machine link? [y/N]"
                } else {
                    "Select this exact owner offer? (y/N)"
                })
                .await?
                {
                    let mut pending = request(&preview)?;
                    if let Some(code) = code.clone() {
                        pending["display_code"] = code;
                    }
                    return Ok(pending);
                }
                let mut body = pins(&preview["review"], true);
                if commit {
                    for k in ["selection_id", "administrator_offer_id"] {
                        body[k] = preview["review"][k].clone();
                    }
                    body["owner_finalization_id"] =
                        preview["request"]["owner_finalization_id"].clone();
                }
                v = request(&local.post(route, body).await?)?;
            }
            _ => {
                eprintln!("Linking: {}; next: {}", text(&v, "state")?, v["next"]);
                tokio::time::sleep(Duration::from_secs(2)).await;
                v = local.post(format!("{path}/resume"), json!({})).await?;
                view(&v)?;
            }
        }
    }
}
struct MigrationOwner {
    network: Value,
    scopes: u64,
}
async fn migration_owner(
    local: &Local<'_>,
    network: &str,
    token: &PairingToken,
    terms: &Value,
    admin: bool,
) -> Result<MigrationOwner> {
    let route = format!("/v2/networks/{}/migration", encoded(network));
    let status = local.get(route.clone()).await?;
    ensure!(
        status["approved"] == true
            && status["fenced"] == false
            && status["state"] != "adopted"
            && status["network_id"] == network
            && status["proposal_id"] == terms["migration_proposal_id"]
            && status["context_id"] == terms["expected_context_id"],
        "review and approve this exact local migration proposal before machine consent"
    );
    let carrier = local.get(format!("{route}/evidence")).await?;
    shape(
        &carrier,
        "proposal_base64 source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments_base64 commit_base64",
    )?;
    let proposal_bytes = decode(text(&carrier, "proposal_base64")?)?;
    let envelope: Value = serde_json::from_slice(&proposal_bytes)?;
    let payload: Value = serde_json::from_slice(&decode(text(&envelope, "payload_base64")?)?)?;
    let descriptor = Descriptor::read(&serde_json::to_vec(&payload["new_descriptor"])?)?;
    let proposal = Statement::read(&descriptor, &proposal_bytes)?;
    let people = migration_person_labels(&descriptor, &carrier)?;
    ensure!(
        proposal.kind == "migration_proposal"
            && proposal.id == status["proposal_id"]
            && descriptor.network_id == network
            && descriptor.context_id() == terms["expected_context_id"]
            && terms["expected_network_id"] == network,
        "migration source/proposal/context changed"
    );
    let row = payload["roster"]
        .as_array()
        .context("invalid migration roster")?
        .iter()
        .find(|r| r["host_public_key"] == terms["host_public_key"])
        .context("request host is absent from the exact migration roster")?;
    let person = text(row, "person_public_key")?;
    ensure!(
        key(person)
            && people.contains_key(person)
            && row["person_public_key"] == terms["expected_person_public_key"]
            && row["device_public_key"] == terms["device_public_key"],
        "migration request changes the exact original/host/device tuple"
    );
    let host = local.get("/v1/host".into()).await?;
    if !admin {
        let own = local.get(base(&token.request_id)?).await?;
        view(&own)?;
        ensure!(
            own["role"] == "requester"
                && own["mode"] == "new"
                && own["migration_proposal_id"] == proposal.id
                && own["network_id"] == network
                && own["context_id"] == descriptor.context_id()
                && own["host_public_key"] == host["public_key"]
                && own["host_public_key"] == terms["host_public_key"]
                && own["device_public_key"] == terms["device_public_key"]
                && own["person_public_key"] == person
                && own["request_packet_id"] == token.request_packet_id()?,
            "migration original consent belongs on this exact requesting machine"
        );
    }
    let catalog = Catalog::read(
        &descriptor,
        &decode(text(&carrier, "prepared_catalog_base64")?)?,
    )?;
    let leases: Vec<_> = catalog
        .statements
        .values()
        .filter(|s| {
            s.kind == "person_lease"
                && s.subject().is_ok_and(|v| {
                    v.get("person_public_key").and_then(Value::as_str) == Some(person)
                })
        })
        .collect();
    ensure!(
        leases.len() == 1
            && leases[0].payload.get("root_state_id") == Some(&status["root_state_id"]),
        "migration needs its exact shared prepared person lease"
    );
    let lease = leases[0];
    let scopes = row["scopes"]
        .as_u64()
        .context("invalid migration device profile")?;
    ensure!(
        scopes != 0,
        "an unbound migration host has no owned-machine ceremony"
    );
    // These facts are a private proposal review, never an adopted provider.
    // Nominal conditional8 remains only the exact source-selected device profile.
    let provider = json!({"kind":"original_person","person_public_key":person,
        "host_public_key":terms["host_public_key"],"device_public_key":"-","lease_id":lease.id,
        "root_state_id":status["root_state_id"],"scopes":7,"not_after":lease.payload["not_after"]});
    Ok(MigrationOwner {
        network: json!({"id":network,"name":descriptor.name,
        "person_public_key":person,"host_public_key":host["public_key"],"provider":provider}),
        scopes,
    })
}
async fn approval(socket: &Path, input: Approval, admin: bool, interactive: bool) -> Result<Value> {
    let local = Local(socket);
    let signer = input
        .signer
        .as_deref()
        .unwrap_or(if admin { "network_root" } else { "auto" });
    let private = match (&input.request, input.code_stdin) {
        (Some(id), false) => {
            let view = local
                .post(format!("{}/resume", base(id)?), json!({}))
                .await?;
            view["display_code"]
                .as_str()
                .context("this request's code is not here yet; enter it with --code-stdin")?
                .to_owned()
        }
        _ => private_code(input.code_stdin).await?,
    };
    let now = local_decision_time()?;
    let token = PairingToken::read(&private, &now)?;
    let packet: Value = serde_json::from_slice(&token.request_packet)?;
    let terms: Value = serde_json::from_slice(&decode(text(&packet, "payload_base64")?)?)?;
    let all = local.get("/v2/networks".into()).await?;
    let all = all.as_array().context("invalid networks")?;
    let known = all
        .iter()
        .find(|n| n["id"] == input.network || n["name"] == input.network);
    let staged = if terms["migration_proposal_id"] != "-" {
        let n =
            known.context("migration consent requires this machine's existing source network")?;
        ensure!(
            n["mode"] != "decentralized",
            "use completed migration history after adoption"
        );
        Some(migration_owner(&local, text(n, "id")?, &token, &terms, admin).await?)
    } else {
        None
    };
    // New-person consent is on the original machine before context adoption.
    // Pin its exact locally retained requester, never fabricate an active view.
    let (n, pending) = if let Some(stage) = &staged {
        (stage.network.clone(), false)
    } else if let Some(n) = known {
        ensure!(
            n["mode"] == "decentralized",
            "this network needs explicit migration"
        );
        (n.clone(), false)
    } else {
        ensure!(
            !admin && input.network == terms["expected_network_id"],
            "choose the exact reviewed introduction network ID"
        );
        let own = local.get(base(&token.request_id)?).await?;
        view(&own)?;
        let host = local.get("/v1/host".into()).await?;
        ensure!(
            own["role"] == "requester"
                && own["mode"] == "new"
                && own["migration_proposal_id"] == "-"
                && own["network_id"] == input.network
                && own["context_id"] == terms["expected_context_id"]
                && own["host_public_key"] == host["public_key"]
                && own["host_public_key"] == terms["host_public_key"]
                && own["device_public_key"] == terms["device_public_key"]
                && own["person_public_key"] == terms["expected_person_public_key"]
                && own["request_packet_id"] == token.request_packet_id()?
                && own["created_at"] == terms["created_at"]
                && own["expires_at"] == terms["expires_at"],
            "new-original consent requires this machine's exact pending introduction request"
        );
        let choice = crate::choose_key(&input.keys.person_key)?;
        ensure!(
            choice.new.is_none() && own["person_public_key"] == choice.signer.public_key_b64(),
            "retain this original key on its original machine; approval cannot generate a replacement"
        );
        (
            json!({"id":own["network_id"],"person_public_key":own["person_public_key"]}),
            true,
        )
    };
    let person = input
        .person
        .as_deref()
        .unwrap_or(text(&n, "person_public_key")?);
    ensure!(
        key(person),
        "supply the exact target original person with --person"
    );
    if staged.is_some() {
        ensure!(
            n["person_public_key"] == person,
            "migration consent changes its reviewed roster person"
        );
        ensure!(
            if admin {
                signer == "network_root"
            } else {
                signer == "auto" || signer == "person_root" || signer == person
            },
            "migration uses only its reviewed original owner or explicit network root administrator"
        );
        if let Some(stage) = &staged {
            ensure!(
                input.scopes.is_none_or(|scopes| scopes == stage.scopes),
                "migration consent must preserve the exact reviewed roster device profile"
            );
        }
    }
    if pending {
        ensure!(
            n["person_public_key"] == person
                && (signer == "auto" || signer == "person_root" || signer == person),
            "new-original possession uses only this exact original key"
        );
    }
    let provider = if pending || staged.is_some() && !admin || signer == "person_root" {
        person
    } else {
        signer
    };
    let format = if input.signature_format != "auto" {
        input.signature_format.clone()
    } else if provider == "network_root" {
        if input.keys.root_key.is_some() {
            "sshsig"
        } else {
            "ed25519"
        }
        .into()
    } else if key(provider) {
        "sshsig".into()
    } else {
        "auto".into()
    };
    let mut body = json!({"code":private,"network_id":n["id"],"person_public_key":person,"provider_id":provider,"signature_format":format,"expected_host_public_key":input.expect_host_key.as_deref().unwrap_or(text(&terms,"host_public_key")?),"expected_device_public_key":input.expect_device_key.as_deref().unwrap_or(text(&terms,"device_public_key")?),"approve":false});
    let path = if admin {
        "/v2/link/admissions"
    } else {
        "/v2/link/approvals"
    };
    if admin {
        ensure!(
            input.owner_offer.is_some() && input.selection.is_some(),
            "administrator review needs --owner-offer and --selection"
        );
        body["owner_offer_id"] = json!(input.owner_offer);
        body["selection_id"] = json!(input.selection);
    } else {
        let mut provider = if pending {
            json!({"kind":"original_person","person_public_key":person,"scopes":0,"not_after":"-"})
        } else {
            n["provider"].clone()
        };
        if !pending && staged.is_none() && body["provider_id"] != "auto" {
            let p=local.post(format!("/v2/networks/{}/provider",encoded(text(&n,"id")?)),json!({"provider_id":body["provider_id"],"person_public_key":person,"host_public_key":n["host_public_key"],"approve":false})).await?;
            provider = p["provider"].clone();
        }
        ensure!(
            provider.is_object() && provider["person_public_key"] == person,
            "the selected provider differs from the target owner"
        );
        let scopes = input.scopes.unwrap_or(if let Some(stage) = &staged {
            stage.scopes
        } else if pending {
            7
        } else {
            15 & provider["scopes"]
                .as_u64()
                .context("invalid provider scopes")?
        });
        let mut deadline = (chrono::DateTime::parse_from_rfc3339(text(&terms, "created_at")?)?
            + chrono::Duration::days(7))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
        if let Some(end) = provider["not_after"].as_str().filter(|v| *v != "-")
            && end < deadline.as_str()
        {
            deadline = end.into();
        }
        body["scopes"] = json!(scopes);
        body["not_after"] = json!(input.not_after.unwrap_or(deadline));
    }
    let mut result = local.post(path.into(), body.clone()).await?;
    describe_shape(&result)?;
    describe(&result["review"])?;
    if input.approve || interactive && confirm("Approve this exact machine? (y/N)").await? {
        let prior = result["review"].clone();
        body["approve"] = json!(true);
        body["expected_host_public_key"] = prior["host_public_key"].clone();
        body["expected_device_public_key"] = prior["device_public_key"].clone();
        result = local.post(path.into(), body).await?;
        same_target(&prior, &result["review"])?;
        result = signatures(
            socket,
            result,
            input.keys.person_key.as_deref(),
            input.keys.root_key.as_deref(),
        )
        .await?;
    }
    request(&result)
}
async fn consent(socket: &Path, input: Consent, kind: &str, keys: Option<Keys>) -> Result<Value> {
    let local = Local(socket);
    let v = local.get(base(&input.request_id)?).await?;
    view(&v)?;
    let mut body = json!({"owner_offer_id":input.owner_offer.unwrap_or_else(||v["owner_offer_id"].as_str().unwrap_or("-").into()),"network_id":input.network.unwrap_or_else(||v["network_id"].as_str().unwrap_or("-").into()),"context_id":input.context.unwrap_or_else(||v["context_id"].as_str().unwrap_or("-").into()),"person_public_key":input.expect_person.unwrap_or_else(||v["person_public_key"].as_str().unwrap_or("-").into()),"host_public_key":input.expect_host_key.unwrap_or_else(||v["host_public_key"].as_str().unwrap_or("-").into()),"device_public_key":input.expect_device_key.unwrap_or_else(||v["device_public_key"].as_str().unwrap_or("-").into()),"approve":input.approve});
    if kind != "selection" {
        body["selection_id"] = json!(
            input
                .selection
                .unwrap_or_else(|| v["selection_id"].as_str().unwrap_or("-").into())
        );
        body["administrator_offer_id"] = json!(
            input
                .administrator_offer
                .unwrap_or_else(|| v["administrator_offer_id"].as_str().unwrap_or("-").into())
        );
    }
    if kind == "commit" {
        body["owner_finalization_id"] = json!(
            input
                .owner_finalization
                .unwrap_or_else(|| v["owner_finalization_id"].as_str().unwrap_or("-").into())
        );
    }
    body["approve"] = json!(false);
    let route = format!("{}/{kind}", base(&input.request_id)?);
    let mut result = local.post(route.clone(), body).await?;
    describe(&result["review"])?;
    if input.approve {
        let reviewed = result["review"].clone();
        let mut fixed = pins(&reviewed, true);
        if kind != "selection" {
            for k in ["selection_id", "administrator_offer_id"] {
                fixed[k] = reviewed[k].clone();
            }
        }
        if kind == "commit" {
            fixed["owner_finalization_id"] = result["request"]["owner_finalization_id"].clone();
        }
        result = local.post(route, fixed).await?;
        same_target(&reviewed, &result["review"])?;
    }
    if input.approve
        && let Some(keys) = keys
    {
        result = signatures(
            socket,
            result,
            keys.person_key.as_deref(),
            keys.root_key.as_deref(),
        )
        .await?;
    }
    request(&result)
}
pub async fn run(args: LinkArgs, state: Option<PathBuf>) -> Result<()> {
    let directory = state.map(Ok).unwrap_or_else(crate::default_directory)?;
    let socket = directory.join("admin.sock");
    let local = Local(&socket);
    let interactive = io::stdin().is_terminal();
    let mut display = false;
    let v = match args.command {
        Some(LinkCommand::Approve(input)) => approval(&socket, input, false, interactive).await?,
        Some(LinkCommand::Admit(input)) => approval(&socket, input, true, interactive).await?,
        Some(LinkCommand::Finalize {
            consent: input,
            keys,
        }) => consent(&socket, input, "finalization", Some(keys)).await?,
        Some(LinkCommand::Select(input)) => consent(&socket, input, "selection", None).await?,
        Some(LinkCommand::Commit(input)) => consent(&socket, input, "commit", None).await?,
        Some(LinkCommand::Status { request_id }) => {
            local
                .get(
                    request_id
                        .as_deref()
                        .map(base)
                        .transpose()?
                        .unwrap_or_else(|| "/v2/link/requests".into()),
                )
                .await?
        }
        Some(LinkCommand::Cancel { request_id }) => {
            local
                .post(format!("{}/cancel", base(&request_id)?), json!({}))
                .await?
        }
        Some(LinkCommand::Resume { request_id, keys }) => {
            display = true;
            resume(
                &socket,
                &request_id,
                keys.person_key.as_deref(),
                keys.root_key.as_deref(),
                interactive,
                true,
            )
            .await?
        }
        None => {
            ensure!(
                !args.renew || args.network.is_some() && args.expect_person.is_some(),
                "renew needs the existing network and original person"
            );
            let network = if let Some(name) = args.network {
                if ident(&name, "net_") {
                    name
                } else {
                    text(&network(&local, &name).await?, "id")?.into()
                }
            } else {
                "-".into()
            };
            let v=local.post("/v2/link/requests".into(),json!({"mode":if args.renew{"renew"}else{"new"},"network_id":network,"person_public_key":arg(args.expect_person),"migration_proposal_id":"-","contact_invitation":"-","helpers":[]})).await?;
            display = true;
            guide(&socket, v, interactive).await?
        }
    };
    output(v, display)
}
