//! Typed local linking commands. Private codes are read from terminal or stdin.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Subcommand};
use ed25519_dalek::Signer;
use hyper::Method;
use peerspan_host::{link_runtime::model::SigningRequest, persons::PersonSigner};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, IsTerminal},
    path::{Path, PathBuf},
};

#[derive(Debug, Args)]
pub struct LinkArgs {
    #[arg(long)]
    pub renew: bool,
    #[arg(long)]
    pub network: Option<String>,
    #[arg(long)]
    pub expect_person: Option<String>,
    #[arg(long, requires = "coordinator_key")]
    pub coordinator: Option<String>,
    #[arg(long, requires = "coordinator")]
    pub coordinator_key: Option<String>,
    #[command(subcommand)]
    pub command: Option<LinkCommand>,
}
#[derive(Debug, Args)]
pub struct Approval {
    #[arg(long)]
    network: String,
    #[arg(long)]
    person: Option<String>,
    #[arg(long)]
    expect_host_key: Option<String>,
    #[arg(long)]
    expect_device_key: Option<String>,
    #[arg(long, default_value = "auto")]
    signer: String,
    #[arg(long)]
    code_stdin: bool,
    #[arg(long)]
    approve: bool,
    #[arg(long)]
    person_key: Option<PathBuf>,
    #[arg(long)]
    root_key: Option<PathBuf>,
}
#[derive(Debug, Args)]
pub struct Consent {
    request_id: String,
    #[arg(long)]
    owner_offer: Option<String>,
    #[arg(long)]
    network: Option<String>,
    #[arg(long)]
    expect_person: Option<String>,
    #[arg(long)]
    expect_host_key: Option<String>,
    #[arg(long)]
    expect_device_key: Option<String>,
    #[arg(long)]
    approve: bool,
}
#[derive(Debug, Subcommand)]
pub enum LinkCommand {
    Approve(Approval),
    Admit(Approval),
    Status {
        request_id: Option<String>,
    },
    Resume {
        request_id: String,
        #[arg(long)]
        person_key: Option<PathBuf>,
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    Cancel {
        request_id: String,
    },
    Select(Consent),
    Commit {
        #[command(flatten)]
        consent: Consent,
        #[arg(long)]
        selection: Option<String>,
        #[arg(long)]
        administrator_offer: Option<String>,
    },
}
fn arg(v: Option<String>) -> String {
    v.filter(|s| !s.is_empty()).unwrap_or_else(|| "-".into())
}
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("-")
}
fn output(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}
async fn call(socket: &Path, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
    crate::integration::admin(
        socket.parent().context("invalid daemon socket")?,
        method,
        path.into(),
        body,
    )
    .await
}
async fn confirm(question: &str) -> Result<bool> {
    Ok(matches!(
        crate::up::prompt(question, "no", false)
            .await?
            .to_ascii_lowercase()
            .as_str(),
        "y" | "yes"
    ))
}
async fn code(stdin: bool) -> Result<String> {
    if stdin {
        let mut value = String::new();
        io::stdin().lock().read_line(&mut value)?;
        ensure!(value.len() <= 1024, "invalid private code");
        Ok(value.trim_end_matches(['\r', '\n']).into())
    } else {
        crate::up::prompt("Private linking code (hidden)", "", true).await
    }
}
fn describe(review: &Value, final_commit: bool) {
    eprintln!(
        "Network: {}; person: {}; host: {}; device: {}; scopes: {}; expires: {}; signer: {}",
        text(review, "network_id"),
        text(review, "person_id"),
        text(review, "host_public_key"),
        text(review, "device_public_key"),
        review["scopes"],
        text(review, "not_after"),
        text(review, "signer_public_key")
    );
    if final_commit {
        eprintln!(
            "Owner: {}; selection: {}; administrator: {}; admission: {}; administrator signer: {}",
            text(review, "owner_offer_id"),
            text(review, "selection_id"),
            text(review, "administrator_offer_id"),
            text(review, "admission_record_id"),
            text(review, "administrator_signer_public_key")
        );
    }
    if text(review, "authority_warning") != "-" {
        eprintln!("{}", text(review, "authority_warning"));
    }
}
async fn signatures(
    socket: &Path,
    mut response: Value,
    person_key: Option<&Path>,
    root_key: Option<&Path>,
) -> Result<Value> {
    for _ in 0..8 {
        let Some(value) = response["signing_requests"]
            .as_array()
            .and_then(|r| r.first())
        else {
            return Ok(response);
        };
        let request: SigningRequest = serde_json::from_value(value.clone())?;
        let signer = PersonSigner::open(root_key.or(person_key))?;
        ensure!(
            signer.public_key_b64() == request.signer_public_key,
            "the original key does not match the reviewed signer; keep the same person"
        );
        let bytes = STANDARD.decode(&request.message_base64)?;
        ensure!(
            STANDARD.encode(&bytes) == request.message_base64 && bytes.len() <= 1 << 20,
            "invalid typed signing request"
        );
        let message = std::str::from_utf8(&bytes)?;
        let parts: Vec<_> = message.split('\n').collect();
        let valid = match request.object_type.as_str() {
            "certificate" => {
                parts.len() == 10
                    && parts[0] == "peerspan-device-certificate-v1"
                    && parts[9] == text(&response["request"], "request_id")
            }
            "binding_authorization" => {
                parts.len() == 8
                    && parts[0] == "peerspan-person-authorization-v1"
                    && parts[1] == "peerspan-host-bind-v1"
                    && parts[4] == text(&response["request"], "request_id")
            }
            "admission_authorization" => {
                matches!(parts.len(), 6 | 8)
                    && matches!(
                        parts[0],
                        "peerspan-person-authorization-v1" | "peerspan-root-authorization-v1"
                    )
                    && parts[1] == "peerspan-host-admit-v1"
                    && parts[4] == text(&response["request"], "request_id")
            }
            "owner_packet" | "administrator_packet" => {
                parts.len() == 7
                    && parts[0] == "peerspan-link-packet-v1"
                    && parts[1] == text(&response["request"], "request_id")
                    && parts[2]
                        == if request.object_type == "owner_packet" {
                            "owner"
                        } else {
                            "administrator"
                        }
            }
            _ => false,
        };
        ensure!(valid, "invalid typed signing request");
        let signature = if request.signature_format == "sshsig" {
            signer.sign(&parts)?
        } else if request.signature_format == "ed25519" {
            let PersonSigner::File(key) = signer else {
                bail!("this reviewed raw root signature requires its original key file")
            };
            STANDARD.encode(key.sign(&bytes).to_bytes())
        } else {
            bail!("invalid signature format")
        };
        response = call(
            socket,
            Method::POST,
            &format!(
                "/v1/link/requests/{}/signed",
                crate::cli::encoded(text(&response["request"], "request_id"))
            ),
            Some(json!({"object_type":request.object_type,"signature":signature})),
        )
        .await?;
    }
    bail!("too many dependency signing requests")
}
fn pins(review: &Value, approve: bool) -> Value {
    json!({"owner_offer_id":review["owner_offer_id"],"network_id":review["network_id"],"person_public_key":review["person_public_key"],"host_public_key":review["host_public_key"],"device_public_key":review["device_public_key"],"approve":approve})
}
fn unknown() -> Value {
    json!({"owner_offer_id":"-","network_id":"-","person_public_key":"-","host_public_key":"-","device_public_key":"-","approve":false})
}
pub async fn resume(
    socket: &Path,
    id: &str,
    person_key: Option<&Path>,
    root_key: Option<&Path>,
    interactive: bool,
    display_code: bool,
) -> Result<Value> {
    let mut value = call(
        socket,
        Method::POST,
        &format!("/v1/link/requests/{}/resume", crate::cli::encoded(id)),
        Some(json!({})),
    )
    .await?;
    match call(
        socket,
        Method::GET,
        &format!("/v1/link/requests/{}/approval", crate::cli::encoded(id)),
        None,
    )
    .await
    {
        Ok(approval) => {
            let signed = signatures(socket, approval, person_key, root_key).await?;
            value = signed["request"].clone();
        }
        Err(e)
            if e.downcast_ref::<crate::integration::DaemonError>()
                .is_some_and(|e| e.status == 409) => {}
        Err(e) => return Err(e),
    }
    if !display_code && let Some(fields) = value.as_object_mut() {
        fields.remove("display_code");
    }
    guide(socket, value, interactive).await
}
pub(crate) async fn guide(socket: &Path, mut value: Value, interactive: bool) -> Result<Value> {
    if let Some(code) = value["display_code"].as_str() {
        eprintln!("Approve this private code on an existing machine: {code}");
    }
    if !interactive {
        return Ok(value);
    }
    loop {
        let id = text(&value, "request_id");
        let base = format!("/v1/link/requests/{}", crate::cli::encoded(id));
        match text(&value, "state") {
            "linked" => return Ok(value),
            "cancelled" | "expired" | "incomplete" => return Ok(value),
            "waiting_selection" => {
                let preview = call(
                    socket,
                    Method::POST,
                    &format!("{base}/selection"),
                    Some(unknown()),
                )
                .await?;
                let review = &preview["review"];
                describe(review, false);
                if !confirm("Select this exact owner offer? (y/N)").await? {
                    return Ok(preview);
                }
                let selected = call(
                    socket,
                    Method::POST,
                    &format!("{base}/selection"),
                    Some(pins(review, true)),
                )
                .await?;
                value = selected["request"].clone();
            }
            "ready_to_commit" => {
                let mut body = unknown();
                body["selection_id"] = json!("-");
                body["administrator_offer_id"] = json!("-");
                let preview =
                    call(socket, Method::POST, &format!("{base}/commit"), Some(body)).await?;
                let review = &preview["review"];
                describe(review, true);
                if !confirm("Commit this exact machine link? (y/N)").await? {
                    return Ok(preview);
                }
                let mut body = pins(review, true);
                body["selection_id"] = review["selection_id"].clone();
                body["administrator_offer_id"] = review["administrator_offer_id"].clone();
                let result =
                    call(socket, Method::POST, &format!("{base}/commit"), Some(body)).await?;
                value = result["request"].clone();
            }
            _ => {
                eprintln!(
                    "Linking: {}; next: {}",
                    text(&value, "state"),
                    value["next"]
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                value = call(
                    socket,
                    Method::POST,
                    &format!("{base}/resume"),
                    Some(json!({})),
                )
                .await?;
            }
        }
    }
}
pub async fn run(args: LinkArgs, state: Option<PathBuf>) -> Result<()> {
    let directory = state.map(Ok).unwrap_or_else(crate::default_directory)?;
    let socket = directory.join("admin.sock");
    let interactive = io::stdin().is_terminal();
    let mut incomplete = false;
    let value = match args.command {
        Some(LinkCommand::Approve(input)) => approval(&socket, input, false, interactive).await?,
        Some(LinkCommand::Admit(input)) => approval(&socket, input, true, interactive).await?,
        Some(LinkCommand::Status { request_id }) => {
            call(
                &socket,
                Method::GET,
                &request_id
                    .map(|id| format!("/v1/link/requests/{}", crate::cli::encoded(&id)))
                    .unwrap_or_else(|| "/v1/link/requests".into()),
                None,
            )
            .await?
        }
        Some(LinkCommand::Cancel { request_id }) => {
            call(
                &socket,
                Method::POST,
                &format!(
                    "/v1/link/requests/{}/cancel",
                    crate::cli::encoded(&request_id)
                ),
                Some(json!({})),
            )
            .await?
        }
        Some(LinkCommand::Select(input)) => consent(&socket, input, None, None).await?,
        Some(LinkCommand::Commit {
            consent: input,
            selection,
            administrator_offer,
        }) => {
            consent(
                &socket,
                input,
                Some(arg(selection)),
                Some(arg(administrator_offer)),
            )
            .await?
        }
        Some(LinkCommand::Resume {
            request_id,
            person_key,
            root_key,
        }) => {
            let v = resume(
                &socket,
                &request_id,
                person_key.as_deref(),
                root_key.as_deref(),
                interactive,
                true,
            )
            .await?;
            incomplete = v["state"] != "linked";
            v
        }
        None => {
            ensure!(
                !args.renew || (args.network.is_some() && args.expect_person.is_some()),
                "renew requires the existing network and original person"
            );
            let result=call(&socket,Method::POST,"/v1/link/requests",Some(json!({"mode":if args.renew{"renew"}else{"new"},"network_id":arg(args.network),"person_public_key":arg(args.expect_person),"coordinator_address":arg(args.coordinator),"coordinator_public_key":arg(args.coordinator_key)}))).await?;
            let v = guide(&socket, result, interactive).await?;
            incomplete = v["state"] != "linked";
            v
        }
    };
    output(&value)?;
    if incomplete {
        bail!("linking is incomplete; follow the returned next step");
    }
    Ok(())
}
async fn approval(
    socket: &Path,
    mut input: Approval,
    admin: bool,
    interactive: bool,
) -> Result<Value> {
    let private = code(input.code_stdin).await?;
    let path = if admin {
        "/v1/link/admissions"
    } else {
        "/v1/link/approvals"
    };
    let mut body = json!({"code":private,"network_id":input.network,"expected_person_id":arg(input.person.take()),"expected_host_key":arg(input.expect_host_key.take()),"expected_device_key":arg(input.expect_device_key.take()),"signer":input.signer,"approve":input.approve});
    let mut result = call(socket, Method::POST, path, Some(body.clone())).await?;
    if !input.approve && interactive {
        describe(&result["review"], false);
        if confirm("Approve this exact machine? (y/N)").await? {
            body["approve"] = json!(true);
            body["expected_person_id"] = result["review"]["person_id"].clone();
            body["expected_host_key"] = result["review"]["host_public_key"].clone();
            body["expected_device_key"] = result["review"]["device_public_key"].clone();
            result = call(socket, Method::POST, path, Some(body)).await?;
            input.approve = true;
        }
    }
    if input.approve {
        result = signatures(
            socket,
            result,
            input.person_key.as_deref(),
            input.root_key.as_deref(),
        )
        .await?;
    }
    Ok(result)
}
async fn consent(
    socket: &Path,
    input: Consent,
    selection: Option<String>,
    administrator: Option<String>,
) -> Result<Value> {
    let mut body = json!({"owner_offer_id":arg(input.owner_offer),"network_id":arg(input.network),"person_public_key":arg(input.expect_person),"host_public_key":arg(input.expect_host_key),"device_public_key":arg(input.expect_device_key),"approve":input.approve});
    let stage = if let Some(selection) = selection {
        body["selection_id"] = json!(selection);
        body["administrator_offer_id"] = json!(administrator.unwrap_or_else(|| "-".into()));
        "commit"
    } else {
        "selection"
    };
    call(
        socket,
        Method::POST,
        &format!(
            "/v1/link/requests/{}/{stage}",
            crate::cli::encoded(&input.request_id)
        ),
        Some(body),
    )
    .await
}
pub async fn enable(
    network: Option<String>,
    root_key: Option<PathBuf>,
    state: Option<PathBuf>,
) -> Result<()> {
    let directory = state.map(Ok).unwrap_or_else(crate::default_directory)?;
    let socket = directory.join("admin.sock");
    let network = match network {
        Some(n) => n,
        None => crate::only_network(&socket).await?,
    };
    let path = format!(
        "/v1/networks/{}/link-feature",
        crate::cli::encoded(&network)
    );
    let preview = call(
        &socket,
        Method::POST,
        &path,
        Some(json!({"activate":false})),
    )
    .await?;
    eprintln!(
        "Feature: {}; network: {}; hosts: {}",
        preview["feature_id"], network, preview["proposal"]["host_public_keys"]
    );
    let mut result = call(&socket, Method::POST, &path, Some(json!({"activate":true}))).await?;
    if let Some(request) = result["signing_requests"]
        .as_array()
        .and_then(|r| r.first())
    {
        let request: SigningRequest = serde_json::from_value(request.clone())?;
        ensure!(
            request.object_type == "feature_proposal",
            "invalid feature signing request"
        );
        let signer = PersonSigner::open(root_key.as_deref())?;
        ensure!(
            signer.public_key_b64() == request.signer_public_key,
            "original root key does not match the reviewed root"
        );
        let bytes = STANDARD.decode(&request.message_base64)?;
        let message = std::str::from_utf8(&bytes)?;
        ensure!(
            message.starts_with(&format!("peerspan-link-feature-v1\n{network}\n")),
            "invalid typed feature message"
        );
        let signature = if request.signature_format == "sshsig" {
            signer.sign(&message.split('\n').collect::<Vec<_>>())?
        } else {
            let PersonSigner::File(key) = signer else {
                bail!("this raw root signature requires its original key file")
            };
            STANDARD.encode(key.sign(&bytes).to_bytes())
        };
        result = call(
            &socket,
            Method::POST,
            &format!("{path}/signed"),
            Some(json!({"signature":signature})),
        )
        .await?;
    }
    output(&result)?;
    if result["state"] != "active" {
        bail!("waiting for the listed hosts to acknowledge linking support");
    }
    Ok(())
}

#[derive(Debug, Args)]
pub struct RepairArgs {
    pub network: Option<String>,
    #[arg(long, requires = "coordinator_key")]
    pub coordinator: String,
    #[arg(long, requires = "coordinator")]
    pub coordinator_key: String,
    #[arg(long)]
    pub approve: bool,
    #[arg(long)]
    pub import_id: Option<String>,
    #[arg(long)]
    pub root_key: Option<PathBuf>,
}
pub async fn repair(args: RepairArgs, state: Option<PathBuf>) -> Result<()> {
    let directory = state.map(Ok).unwrap_or_else(crate::default_directory)?;
    let socket = directory.join("admin.sock");
    let network = match args.network {
        Some(n) => n,
        None => crate::only_network(&socket).await?,
    };
    let path = format!(
        "/v1/networks/{}/feature-import",
        crate::cli::encoded(&network)
    );
    let mut body = json!({"coordinator_address":args.coordinator,"coordinator_public_key":args.coordinator_key,"import_id":args.import_id.as_deref().unwrap_or("-"),"approve":false});
    let mut result = call(&socket, Method::POST, &path, Some(body.clone())).await?;
    let review = &result["review"];
    eprintln!(
        "Root recovery: network {} ({}); feature {}; target {} ({}); snapshot {}; expires {}; root {}",
        text(review, "network_name"),
        text(review, "network_id"),
        text(review, "feature_id"),
        text(review, "coordinator_address"),
        text(review, "coordinator_public_key"),
        text(review, "catalog_sha256"),
        text(review, "expires_at"),
        text(review, "signer_public_key")
    );
    let interactive = io::stdin().is_terminal();
    if args.approve && !interactive && args.import_id.is_none() {
        output(&result)?;
        bail!("noninteractive approval requires the exact reviewed --import-id");
    }
    let approve = args.approve
        || interactive
            && confirm("Authorize this exact root recovery snapshot and target? (y/N)").await?;
    if approve {
        body["import_id"] = result["import_id"].clone();
        body["approve"] = json!(true);
        result = call(&socket, Method::POST, &path, Some(body)).await?;
    } else if let Some(id) = args.import_id {
        result = call(
            &socket,
            Method::POST,
            &format!("{path}/{}/resume", crate::cli::encoded(&id)),
            Some(json!({})),
        )
        .await?;
    }
    if let Some(value) = result["signing_requests"]
        .as_array()
        .and_then(|r| r.first())
    {
        let request: SigningRequest = serde_json::from_value(value.clone())?;
        let bytes = STANDARD.decode(&request.message_base64)?;
        ensure!(
            STANDARD.encode(&bytes) == request.message_base64 && bytes.len() <= 1 << 20,
            "invalid typed root recovery request"
        );
        let message = std::str::from_utf8(&bytes)?;
        let parts: Vec<_> = message.split('\n').collect();
        let r = &result["review"];
        ensure!(
            request.object_type == "feature_import"
                && parts.len() == 10
                && parts[0] == "peerspan-link-feature-import-v1"
                && parts[1] == network
                && parts[2] == text(r, "network_name")
                && parts[3]
                    == r["epoch"]
                        .as_u64()
                        .context("invalid reviewed epoch")?
                        .to_string()
                && parts[4] == text(r, "feature_id")
                && parts[5] == text(r, "coordinator_address")
                && parts[6] == text(r, "coordinator_public_key")
                && parts[7] == text(r, "catalog_sha256")
                && parts[9] == text(r, "expires_at")
                && request.signer_public_key == text(r, "signer_public_key"),
            "invalid typed root recovery request"
        );
        let signer = PersonSigner::open(args.root_key.as_deref())?;
        ensure!(
            signer.public_key_b64() == request.signer_public_key,
            "original root key differs from the reviewed root"
        );
        let signature = if request.signature_format == "sshsig" {
            signer.sign(&parts)?
        } else if request.signature_format == "ed25519" {
            let PersonSigner::File(key) = signer else {
                bail!("this raw root recovery requires its original key file")
            };
            STANDARD.encode(key.sign(&bytes).to_bytes())
        } else {
            bail!("invalid root signature format")
        };
        result = call(
            &socket,
            Method::POST,
            &format!(
                "{path}/{}/signed",
                crate::cli::encoded(text(&result, "import_id"))
            ),
            Some(json!({"object_type":"feature_import","signature":signature})),
        )
        .await?;
    }
    output(&result)?;
    if result["committed"] != true {
        bail!("root recovery is not committed; resume the same reviewed import ID");
    }
    Ok(())
}
