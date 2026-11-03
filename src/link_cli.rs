//! Legacy feature/history recovery remains separate from normal v2 linking.
pub(crate) use crate::decentralized_link_cli::guide;
pub use crate::decentralized_link_cli::{LinkArgs, resume, run};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;
use ed25519_dalek::Signer;
use hyper::Method;
use peerspan_host::{link_runtime::model::SigningRequest, persons::PersonSigner};
use serde_json::{Value, json};
use std::{
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};
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
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "y" | "yes"
    ))
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
