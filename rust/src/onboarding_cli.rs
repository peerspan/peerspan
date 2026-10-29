//! Private project review payloads cross stdin, never command arguments.
use crate::{
    admin::Local,
    cli::{Command, encoded},
};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use peerspan_host::onboarding::{Decision, Prepare, ProjectContext};
use serde::Deserialize;
use serde_json::Value;
use std::{
    io::{self, Read},
    path::Path,
};

#[derive(Debug, Args)]
pub struct OnboardingArgs {
    #[command(subcommand)]
    pub command: Option<OnboardingCommand>,
}
#[derive(Debug, Subcommand)]
pub enum OnboardingCommand {
    /// Prepare, inspect or decide an exact local project attachment review
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Review a scoped credential for an already attached guided project
    Adapter {
        #[command(subcommand)]
        command: AdapterCommand,
    },
}
#[derive(Debug, Subcommand)]
pub enum AdapterCommand {
    /// Read the current attempt for an exact project binding from stdin
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare or resume an exact credential review from stdin
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Inspect retained terms without retrieving any secret
    Inspect { flow_id: String },
    /// Submit an exact owner decision from stdin
    Decide {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Privately retrieve an approved credential; output contains a secret
    Credential {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Read the current flow and local agent choices for one private context
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare or resume exact terms from JSON on standard input
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Inspect a retained flow without changing it
    Inspect { flow_id: String },
    /// Submit an exact owner-local decision from JSON on standard input
    Decide {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputDecision {
    flow_id: String,
    review_id: String,
    project_root: String,
    native_session_id: String,
    integration: String,
    decision: String,
}
fn input() -> Result<Value> {
    let mut bytes = Vec::new();
    io::stdin().lock().take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "project review input exceeds 64 KiB");
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid project review input"))
}
pub async fn command(command: &Command, socket: &Path) -> Result<Option<Value>> {
    if let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Adapter { command }),
    }) = command
    {
        return adapter_command(command, socket).await.map(Some);
    }
    let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Project { command }),
    }) = command
    else {
        return Ok(None);
    };
    let local = Local(socket);
    let base = "/v1/onboarding/project-flows";
    let result = match command {
        ProjectCommand::Lookup { .. } => {
            let value = input()?;
            let _: ProjectContext = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("invalid project review input"))?;
            local.post(format!("{base}/lookup"), value).await?
        }
        ProjectCommand::Prepare { .. } => {
            let value = input()?;
            let _: Prepare = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("invalid project review input"))?;
            local.post(base.into(), value).await?
        }
        ProjectCommand::Inspect { flow_id } => {
            local.get(format!("{base}/{}", encoded(flow_id))).await?
        }
        ProjectCommand::Decide { .. } => {
            let value = input()?;
            let request: InputDecision = serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("invalid project review input"))?;
            let body = serde_json::json!({"review_id":request.review_id,"project_root":request.project_root,
                "native_session_id":request.native_session_id,"integration":request.integration,"decision":request.decision});
            let _: Decision = serde_json::from_value(body.clone())
                .map_err(|_| anyhow::anyhow!("invalid project review input"))?;
            local
                .post(
                    format!("{base}/{}/decision", encoded(&request.flow_id)),
                    body,
                )
                .await?
        }
    };
    Ok(Some(result))
}

async fn adapter_command(command: &AdapterCommand, socket: &Path) -> Result<Value> {
    use peerspan_host::onboarding_adapter::{AdapterContext, CredentialRequest, Decision, Prepare};
    let local = Local(socket);
    let base = "/v1/onboarding/adapter-flows";
    match command {
        AdapterCommand::Lookup { .. } => {
            let value = input()?;
            let _: AdapterContext = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("invalid adapter review input"))?;
            local.post(format!("{base}/lookup"), value).await
        }
        AdapterCommand::Prepare { .. } => {
            let value = input()?;
            let _: Prepare = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("invalid adapter review input"))?;
            local.post(base.into(), value).await
        }
        AdapterCommand::Inspect { flow_id } => {
            local.get(format!("{base}/{}", encoded(flow_id))).await
        }
        AdapterCommand::Decide { .. } | AdapterCommand::Credential { .. } => {
            let mut value = input()?;
            let flow_id = value
                .as_object_mut()
                .and_then(|v| v.remove("flow_id"))
                .and_then(|id| id.as_str().map(str::to_owned))
                .filter(|id| {
                    id.strip_prefix("flow_").is_some_and(|suffix| {
                        suffix.len() == 32
                            && suffix
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    })
                })
                .ok_or_else(|| anyhow::anyhow!("invalid adapter review input"))?;
            let operation = if matches!(command, AdapterCommand::Decide { .. }) {
                let _: Decision = serde_json::from_value(value.clone())
                    .map_err(|_| anyhow::anyhow!("invalid adapter review input"))?;
                "decision"
            } else {
                let _: CredentialRequest = serde_json::from_value(value.clone())
                    .map_err(|_| anyhow::anyhow!("invalid adapter review input"))?;
                "credential"
            };
            local
                .post(format!("{base}/{}/{operation}", encoded(&flow_id)), value)
                .await
        }
    }
}
