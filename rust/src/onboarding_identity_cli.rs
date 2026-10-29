//! Local original-identity choices and explicit creation for the private UI.
use crate::{admin::Local, cli::encoded};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use peerspan_host::{onboarding_adapter::AdapterContext, persons};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

async fn parent(local: &Local<'_>, context: &AdapterContext) -> Result<(Value, String)> {
    let flow = local
        .get(format!(
            "/v1/onboarding/project-flows/{}",
            encoded(&context.project_flow_id)
        ))
        .await?;
    let host = local.get("/v1/host".into()).await?;
    let r = &flow["review"];
    let host = host["id"]
        .as_str()
        .filter(|s| {
            s.strip_prefix("host_").is_some_and(|v| {
                v.len() == 64
                    && v.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        })
        .ok_or_else(|| anyhow::anyhow!("join identity inventory unavailable"))?;
    ensure!(
        flow["state"] == "attached"
            && flow["flow_id"] == context.project_flow_id
            && flow["review_id"] == context.project_review_id
            && r["host_id"] == host
            && r["project_root"] == context.project_root
            && r["native_session_id"] == context.native_session_id
            && r["integration"] == context.integration,
        "join identity parent unavailable"
    );
    Ok((flow, host.into()))
}
fn inventory() -> Result<Vec<Value>> {
    let mut keys: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    if let Some(path) = persons::generated_key_path() {
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path);
        match opened {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => anyhow::bail!("local person identity unavailable"),
            Ok(file) => {
                let m = file
                    .metadata()
                    .map_err(|_| anyhow::anyhow!("local person identity unavailable"))?;
                // SAFETY: geteuid has no preconditions.
                ensure!(
                    m.is_file()
                        && m.uid() == unsafe { libc::geteuid() }
                        && m.mode() & 0o077 == 0
                        && m.len() <= 65536,
                    "local person identity unavailable"
                );
                let mut bytes = Vec::new();
                file.take(65537)
                    .read_to_end(&mut bytes)
                    .map_err(|_| anyhow::anyhow!("local person identity unavailable"))?;
                ensure!(bytes.len() <= 65536, "local person identity unavailable");
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| anyhow::anyhow!("local person identity unavailable"))?;
                let key = persons::parse_openssh_private_key(text)
                    .map_err(|_| anyhow::anyhow!("local person identity unavailable"))?;
                keys.insert(
                    STANDARD.encode(key.verifying_key().to_bytes()),
                    vec!["generated"],
                );
            }
        }
    }
    for (key, _) in persons::agent_keys() {
        if ed25519_dalek::VerifyingKey::from_bytes(&key).is_ok() {
            keys.entry(STANDARD.encode(key))
                .or_default()
                .push("ssh_agent");
        }
    }
    ensure!(keys.len() <= 64, "too many local person identities");
    Ok(keys
        .into_iter()
        .map(|(public_key, sources)| json!({"public_key":public_key,"sources":sources}))
        .collect())
}
pub async fn identities(socket: &Path, context: AdapterContext) -> Result<Value> {
    let local = Local(socket);
    let before = parent(&local, &context)
        .await
        .map_err(|_| anyhow::anyhow!("join identity parent unavailable"))?;
    let identities = tokio::task::spawn_blocking(inventory)
        .await
        .map_err(|_| anyhow::anyhow!("local person identity unavailable"))??;
    ensure!(
        parent(&local, &context)
            .await
            .map_err(|_| anyhow::anyhow!("join identity parent unavailable"))?
            == before,
        "join identity parent changed"
    );
    Ok(json!({"version":1,"host_id":before.1,"context":context,"identities":identities}))
}

pub async fn create_from_stdin(socket: &Path) -> Result<Value> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Decision {
        CreateNewIdentity,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        context: AdapterContext,
        decision: Decision,
    }
    let invalid = || anyhow::anyhow!("invalid identity creation input");
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    ensure!(bytes.len() <= 65536, "invalid identity creation input");
    let request: Request = peerspan_host::linking::decode_mutation(&bytes, "context decision")
        .map_err(|_| invalid())?;
    let Decision::CreateNewIdentity = request.decision;
    let local = Local(socket);
    let before = parent(&local, &request.context)
        .await
        .map_err(|_| anyhow::anyhow!("identity creation parent unavailable"))?;
    let available = tokio::task::spawn_blocking(inventory)
        .await
        .map_err(|_| anyhow::anyhow!("local person identity unavailable"))??;
    ensure!(
        available.is_empty(),
        "a local person identity already exists"
    );
    ensure!(
        parent(&local, &request.context)
            .await
            .map_err(|_| anyhow::anyhow!("identity creation parent unavailable"))?
            == before,
        "identity creation parent changed"
    );
    // Persistence is not a transaction with the daemon. Once published, the
    // approved original survives a lost response or a changed project view.
    let public_key = tokio::task::spawn_blocking(crate::onboarding_identity_create::persist)
        .await
        .map_err(|_| anyhow::anyhow!("identity creation outcome unavailable"))?
        .map_err(|_| anyhow::anyhow!("identity creation outcome unavailable"))?;
    ensure!(
        parent(&local, &request.context)
            .await
            .map_err(|_| anyhow::anyhow!("identity creation outcome unavailable"))?
            == before,
        "identity creation outcome unavailable"
    );
    Ok(
        json!({"version":1,"host_id":before.1,"context":request.context,
        "identity":{"public_key":public_key,"sources":["generated"]}}),
    )
}
