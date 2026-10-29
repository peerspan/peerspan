//! Private onboarding payloads cross stdin, never command arguments.
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
    /// Review and explicitly publish a join request for a selected person public key
    Join {
        #[command(subcommand)]
        command: JoinCommand,
    },
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
    /// Review a contact-only teammate invitation and retrieve its private handoff
    Invitation {
        #[command(subcommand)]
        command: InvitationCommand,
    },
}
#[derive(Debug, Subcommand)]
pub enum JoinCommand {
    /// List existing local original public identities without creating or signing
    Identities {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare or resume public join terms; creates no person key or request
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read the current exact project's join review or recorded outcome
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Inspect public terms without retrieving pairing material
    Inspect { flow_id: String },
    /// Approve request publication or decline the exact retained review
    Decide {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum InvitationCommand {
    /// Privately verify incoming contact terms without creating an identity or request
    Preview {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read the current invitation attempt for an exact project context
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare or resume exact invitation terms from stdin without signing
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Inspect a retained invitation review without retrieving its code
    Inspect { flow_id: String },
    /// Submit an exact owner-local decision from stdin
    Decide {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Explicitly retrieve an approved private invitation; output contains a secret
    Handoff {
        #[arg(long, required = true)]
        stdin: bool,
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
    /// Privately retrieve approved native transport material; output contains secrets
    Transport {
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
        command: Some(OnboardingCommand::Join { command }),
    }) = command
    {
        return join_command(command, socket).await.map(Some);
    }
    if let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Invitation { command }),
    }) = command
    {
        return invitation_command(command, socket).await.map(Some);
    }
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

async fn join_command(command: &JoinCommand, socket: &Path) -> Result<Value> {
    use peerspan_host::onboarding_join::{Decision, Lookup, Prepare, decode_input};
    let local = Local(socket);
    let base = "/v1/onboarding/join-flows";
    if let JoinCommand::Inspect { flow_id } = command {
        return local.get(format!("{base}/{}", encoded(flow_id))).await;
    }
    let operation = match command {
        JoinCommand::Prepare { .. } => "prepare",
        JoinCommand::Lookup { .. } | JoinCommand::Identities { .. } => "lookup",
        JoinCommand::Decide { .. } => "decision",
        JoinCommand::Inspect { .. } => unreachable!(),
    };
    let invalid = || anyhow::anyhow!("invalid join review input");
    let mut bytes = Vec::new();
    io::stdin().lock().take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "join review input exceeds 64 KiB");
    let mut value: Value = decode_input(&bytes, operation, true).map_err(|_| invalid())?;
    match command {
        JoinCommand::Identities { .. } => {
            let request: Lookup = serde_json::from_value(value).map_err(|_| invalid())?;
            crate::onboarding_identity_cli::identities(socket, request.context).await
        }
        JoinCommand::Prepare { .. } => {
            let _: Prepare = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            local.post(base.into(), value).await
        }
        JoinCommand::Lookup { .. } => {
            let _: Lookup = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            local.post(format!("{base}/lookup"), value).await
        }
        JoinCommand::Decide { .. } => {
            let id = value
                .as_object_mut()
                .and_then(|v| v.remove("flow_id"))
                .and_then(|v| v.as_str().map(str::to_owned))
                .filter(|id| {
                    id.strip_prefix("flow_").is_some_and(|v| {
                        v.len() == 32
                            && v.bytes()
                                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                    })
                })
                .ok_or_else(invalid)?;
            let request: Decision = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            ensure!(
                matches!(
                    (&request.decision, &request.invitation),
                    (peerspan_host::onboarding::DecisionKind::Approve, Some(_))
                        | (peerspan_host::onboarding::DecisionKind::Decline, None)
                ),
                "invalid join review input"
            );
            local
                .post(format!("{base}/{}/decision", encoded(&id)), value)
                .await
        }
        JoinCommand::Inspect { .. } => unreachable!(),
    }
}

async fn invitation_command(command: &InvitationCommand, socket: &Path) -> Result<Value> {
    use peerspan_host::onboarding_invitation::{Decision, Handoff, Lookup, Prepare, Preview};
    let local = Local(socket);
    let base = "/v1/onboarding/invitation-flows";
    if let InvitationCommand::Inspect { flow_id } = command {
        return local.get(format!("{base}/{}", encoded(flow_id))).await;
    }
    let mut value = invitation_input(command)?;
    let invalid = |_| anyhow::anyhow!("invalid invitation review input");
    match command {
        InvitationCommand::Preview { .. } => {
            let _: Preview = serde_json::from_value(value.clone()).map_err(invalid)?;
            local
                .post("/v1/onboarding/invitation-preview".into(), value)
                .await
        }
        InvitationCommand::Lookup { .. } => {
            let _: Lookup = serde_json::from_value(value.clone()).map_err(invalid)?;
            local.post(format!("{base}/lookup"), value).await
        }
        InvitationCommand::Prepare { .. } => {
            let _: Prepare = serde_json::from_value(value.clone()).map_err(invalid)?;
            local.post(base.into(), value).await
        }
        InvitationCommand::Decide { .. } | InvitationCommand::Handoff { .. } => {
            let id = value
                .as_object_mut()
                .and_then(|v| v.remove("flow_id"))
                .and_then(|id| id.as_str().map(str::to_owned))
                .filter(|id| {
                    id.strip_prefix("flow_").is_some_and(|v| {
                        v.len() == 32
                            && v.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                })
                .ok_or_else(|| anyhow::anyhow!("invalid invitation review input"))?;
            let operation = if matches!(command, InvitationCommand::Decide { .. }) {
                let _: Decision = serde_json::from_value(value.clone()).map_err(invalid)?;
                "decision"
            } else {
                let _: Handoff = serde_json::from_value(value.clone()).map_err(invalid)?;
                "handoff"
            };
            local
                .post(format!("{base}/{}/{operation}", encoded(&id)), value)
                .await
        }
        InvitationCommand::Inspect { .. } => unreachable!(),
    }
}

fn invitation_input(command: &InvitationCommand) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid invitation review input");
    let mut bytes = Vec::new();
    io::stdin().lock().take(65537).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 65536,
        "invitation review input exceeds 64 KiB"
    );
    let fields = match command {
        InvitationCommand::Preview { .. } => "context invitation",
        InvitationCommand::Lookup { .. } => "context",
        InvitationCommand::Prepare { .. } => {
            // This preliminary value chooses only the optional field set. The
            // original bytes still cross the strict duplicate-key decoder.
            let shape: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if shape.get("replace_flow_id").is_some() {
                "context network_id member expected_person_public_key replace_flow_id"
            } else {
                "context network_id member expected_person_public_key"
            }
        }
        InvitationCommand::Decide { .. } => "flow_id context review_id decision",
        InvitationCommand::Handoff { .. } => "flow_id context review_id",
        InvitationCommand::Inspect { .. } => return Err(invalid()),
    };
    peerspan_host::linking::decode_mutation(&bytes, fields).map_err(|_| invalid())
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
        AdapterCommand::Decide { .. }
        | AdapterCommand::Credential { .. }
        | AdapterCommand::Transport { .. } => {
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
            let review_id = value["review_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid adapter review input"))?
                .to_owned();
            let result = local
                .post(format!("{base}/{}/{operation}", encoded(&flow_id)), value)
                .await?;
            if matches!(command, AdapterCommand::Transport { .. }) {
                transport(result, socket, &flow_id, &review_id)
            } else {
                Ok(result)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportCredential {
    version: u8,
    adapter_id: String,
    session_id: String,
    token: String,
}
fn transport(value: Value, socket: &Path, flow_id: &str, review_id: &str) -> Result<Value> {
    let credential: TransportCredential = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("invalid private transport response"))?;
    let valid_id = |value: &str, prefix: &str, size: usize| {
        value.strip_prefix(prefix).is_some_and(|suffix| {
            suffix.len() == size
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    };
    ensure!(
        credential.version == 1
            && valid_id(&credential.adapter_id, "adapter_", 32)
            && valid_id(&credential.session_id, "session_", 32)
            && valid_id(&credential.token, "token_", 64),
        "invalid private transport response"
    );
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        &hex::decode(&credential.token[6..])
            .map_err(|_| anyhow::anyhow!("invalid private transport response"))?,
    );
    let input = format!("peerspan-guided-adapter-instance-v1\n{flow_id}\n{review_id}");
    let instance_id = format!(
        "instance_{}",
        hex::encode(ring::hmac::sign(&key, input.as_bytes()).as_ref())
    );
    let adapter_socket = std::path::absolute(socket.with_file_name("adapter.sock"))?
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("adapter socket path is not UTF-8"))?;
    Ok(
        serde_json::json!({"version":1,"adapter_id":credential.adapter_id,"session_id":credential.session_id,
        "token":credential.token,"instance_id":instance_id,"adapter_socket":adapter_socket}),
    )
}
