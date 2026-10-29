//! Private project review payloads cross stdin, never command arguments.
use crate::{
    admin::Local,
    cli::{Command, encoded},
};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use peerspan_host::onboarding::{Decision, Prepare};
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
}
#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
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
    let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Project { command }),
    }) = command
    else {
        return Ok(None);
    };
    let local = Local(socket);
    let base = "/v1/onboarding/project-flows";
    let result = match command {
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
