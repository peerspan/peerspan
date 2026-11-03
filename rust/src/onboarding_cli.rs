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
    /// Inspect an incoming same-person machine request on the existing computer
    Machine {
        #[command(subcommand)]
        command: MachineCommand,
    },
    /// Explicitly check the pinned outbound peer transport to one selected machine
    Reachability {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read current project-bound membership, advertised access and session evidence
    Readiness {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Inspect current project-bound membership and policy before an access grant
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Inspect retained incoming admission evidence before administrator consent
    Admission {
        #[command(subcommand)]
        command: AdmissionCommand,
    },
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
pub enum MachineCommand {
    /// Read exact retained initial machine-owner signature status
    Signing {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Sign only the exact approved initial owner packet and reviewed fold
    Sign {
        #[arg(long, required = true)]
        stdin: bool,
    },

    /// Recover exact project machine-owner consent
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare the exact unsigned ordinary machine-owner intent
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Approve the exact reviewed owner intent and its ordinary continuation
    Approve {
        #[arg(long, required = true)]
        stdin: bool,
    },

    /// Read current public owner terms without consent, signing or publication
    Inspect {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Read verified historical local policy application without publishing
    Application {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Apply only the exact approved and already signed project policy
    Apply {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read retained exact policy signature progress without signing
    Signing {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Sign only the exact already approved project policy action
    Sign {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Recover exact project agent-access consent
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare one exact unsigned project policy action
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Approve the exact retained policy action without signing
    Approve {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read current public access terms without granting or signing
    Inspect {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum AdmissionCommand {
    /// Explicitly fetch missing incoming original/selection evidence
    Progress {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read retained exact administrator consent without preparing or signing
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare one unapproved current-root administrator intent
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Approve the exact retained administrator review from private stdin
    Approve {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Verify public incoming original/selection evidence without mutation
    Inspect {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum JoinCommand {
    /// Inspect received existing-person finalization without requester consent
    MachineCommit {
        #[command(subcommand)]
        command: MachineCommitCommand,
    },
    /// Review and approve the separate exact requester final-commit consent
    Commit {
        #[command(subcommand)]
        command: CommitCommand,
    },
    /// Prepare or explicitly approve exact new-original owner terms
    Owner {
        #[command(subcommand)]
        command: OwnerCommand,
    },
    /// Explicitly create and save a new original when no local identity is available
    CreateIdentity {
        #[arg(long, required = true)]
        stdin: bool,
    },
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
    /// Observe the exact published request without advancing or retrieving a code
    Progress {
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
pub enum MachineCommitCommand {
    /// Complete only an already approved exact machine requester consent
    Complete {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read the retained exact machine requester consent without preparing work
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Freeze the verified inspection in an unsigned requester consent
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Approve only the exact retained machine requester consent
    Approve {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read exact verified remote owner and target machine commit terms
    Inspect {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum CommitCommand {
    /// Complete only the exact already approved requester consent
    Complete {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Pure lookup of retained requester commit consent
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare exact public final-commit terms without signing or applying
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Atomically approve only the exact retained final-commit review
    Approve {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum OwnerCommand {
    /// Inspect verified administrator parents before original finalization
    Finalization {
        #[command(subcommand)]
        command: OwnerFinalizationCommand,
    },
    /// Explicitly sign only the exact approved original owner offer
    Sign {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Prepare fixed public owner terms without signing
    Prepare {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read exact retained owner terms and global approval
    Lookup {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Approve the exact retained owner review without signing
    Approve {
        #[arg(long, required = true)]
        stdin: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum OwnerFinalizationCommand {
    /// Sign only the exact reviewed original B/D/F finalization
    Sign {
        #[arg(long, required = true)]
        stdin: bool,
    },
    /// Read exact original consent and retained administrator evidence only
    Inspect {
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
        command: Some(OnboardingCommand::Machine { command }),
    }) = command
    {
        let op = match command {
            MachineCommand::Signing { .. } => Some("signing"),
            MachineCommand::Sign { .. } => Some("sign"),
            MachineCommand::Lookup { .. } => Some("lookup"),
            MachineCommand::Prepare { .. } => Some("prepare"),
            MachineCommand::Approve { .. } => Some("approve"),
            _ => None,
        };
        if let Some(op) = op {
            return machine_consent(socket, op).await.map(Some);
        }
    }
    if let Command::Onboarding(OnboardingArgs {
        command:
            Some(OnboardingCommand::Machine {
                command: MachineCommand::Inspect { .. },
            }),
    }) = command
    {
        return machine_inspection(socket).await.map(Some);
    }
    if let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Reachability { .. }),
    }) = command
    {
        return reachability(socket).await.map(Some);
    }
    if let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Readiness { .. }),
    }) = command
    {
        return readiness(socket).await.map(Some);
    }
    if let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Access { command }),
    }) = command
    {
        return match command {
            AccessCommand::Inspect { .. } => access_inspection(socket).await,
            AccessCommand::Lookup { .. } => access_consent(socket, "lookup").await,
            AccessCommand::Prepare { .. } => access_consent(socket, "prepare").await,
            AccessCommand::Approve { .. } => access_consent(socket, "approve").await,
            AccessCommand::Signing { .. } => access_consent(socket, "signing").await,
            AccessCommand::Sign { .. } => access_consent(socket, "sign").await,
            AccessCommand::Application { .. } => access_consent(socket, "application").await,
            AccessCommand::Apply { .. } => access_consent(socket, "apply").await,
        }
        .map(Some);
    }
    if let Command::Onboarding(OnboardingArgs {
        command: Some(OnboardingCommand::Admission { command }),
    }) = command
    {
        return match command {
            AdmissionCommand::Progress { .. } => incoming_progress(socket).await,
            AdmissionCommand::Inspect { .. } => admission_inspection(socket).await,
            AdmissionCommand::Lookup { .. } => admission_consent(socket, "lookup").await,
            AdmissionCommand::Prepare { .. } => admission_consent(socket, "prepare").await,
            AdmissionCommand::Approve { .. } => admission_consent(socket, "approve").await,
        }
        .map(Some);
    }
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
async fn access_consent(socket: &Path, operation: &str) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid project access consent input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let input = peerspan_host::onboarding_access_consent::decode_input(&bytes, operation)
        .map_err(|_| invalid())?;
    let unavailable = || anyhow::anyhow!("project access consent unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(if matches!(operation, "sign" | "apply") {
            95
        } else {
            5
        }),
        Local(socket).post(format!("/v1/onboarding/access-consent/{operation}"), input),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}
async fn reachability(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid project reachability input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let input =
        peerspan_host::onboarding_reachability::decode_input(&bytes).map_err(|_| invalid())?;
    let payload = serde_json::to_value(input).map_err(|_| invalid())?;
    let unavailable = || anyhow::anyhow!("project reachability unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        Local(socket).post("/v1/onboarding/reachability".into(), payload),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn readiness(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid project readiness input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let input = peerspan_host::onboarding_access::decode_input(&bytes).map_err(|_| invalid())?;
    let payload = serde_json::json!({"context":input.context,"network_id":input.network_id,
        "person_public_key":input.person_public_key});
    let unavailable = || anyhow::anyhow!("project readiness unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post("/v1/onboarding/readiness".into(), payload),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn access_inspection(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid project access inspection input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let input = peerspan_host::onboarding_access::decode_input(&bytes).map_err(|_| invalid())?;
    let payload = serde_json::json!({"context":input.context,"network_id":input.network_id,
        "person_public_key":input.person_public_key});
    let unavailable = || anyhow::anyhow!("project access inspection unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post("/v1/onboarding/access-inspection".into(), payload),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}
async fn admission_inspection(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid administrator admission inspection input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let input = peerspan_host::onboarding_admission::decode_input(&bytes).map_err(|_| invalid())?;
    let payload = serde_json::json!({"context":input.context,"request_id":input.request_id});
    let unavailable = || anyhow::anyhow!("administrator admission inspection unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post("/v1/onboarding/admission-inspection".into(), payload),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn incoming_progress(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid incoming progress input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let input = peerspan_host::onboarding_admission::decode_input(&bytes).map_err(|_| invalid())?;
    let payload = serde_json::json!({"context":input.context,"request_id":input.request_id});
    let unavailable = || anyhow::anyhow!("incoming progress unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post("/v1/onboarding/incoming-progress".into(), payload),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn admission_consent(socket: &Path, operation: &str) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid administrator admission consent input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let payload = peerspan_host::onboarding_admission_consent::decode_input(&bytes, operation)
        .map_err(|_| invalid())?;
    let unavailable = || anyhow::anyhow!("administrator admission consent unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post(
            format!("/v1/onboarding/admission-consent/{operation}"),
            payload,
        ),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn join_command(command: &JoinCommand, socket: &Path) -> Result<Value> {
    use peerspan_host::onboarding_join::{Decision, Lookup, Prepare, Progress, decode_input};
    let local = Local(socket);
    let base = "/v1/onboarding/join-flows";
    if let JoinCommand::MachineCommit { command } = command {
        return machine_commit_command(command, socket).await;
    }
    if let JoinCommand::Commit { command } = command {
        return commit_command(command, socket).await;
    }
    if let JoinCommand::Owner { command } = command {
        return owner_command(command, socket).await;
    }
    if let JoinCommand::Inspect { flow_id } = command {
        return local.get(format!("{base}/{}", encoded(flow_id))).await;
    }
    if let JoinCommand::CreateIdentity { .. } = command {
        return crate::onboarding_identity_cli::create_from_stdin(socket).await;
    }
    let operation = match command {
        JoinCommand::Prepare { .. } => "prepare",
        JoinCommand::Lookup { .. } | JoinCommand::Identities { .. } => "lookup",
        JoinCommand::Decide { .. } => "decision",
        JoinCommand::Progress { .. } => "progress",
        JoinCommand::Inspect { .. }
        | JoinCommand::CreateIdentity { .. }
        | JoinCommand::Owner { .. }
        | JoinCommand::Commit { .. }
        | JoinCommand::MachineCommit { .. } => unreachable!(),
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
        JoinCommand::Decide { .. } | JoinCommand::Progress { .. } => {
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
            if let JoinCommand::Progress { .. } = command {
                let _: Progress = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
                return local.post(format!("{base}/{id}/progress"), value).await;
            }
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
        JoinCommand::Inspect { .. }
        | JoinCommand::CreateIdentity { .. }
        | JoinCommand::Owner { .. }
        | JoinCommand::Commit { .. }
        | JoinCommand::MachineCommit { .. } => unreachable!(),
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

async fn machine_commit_command(command: &MachineCommitCommand, socket: &Path) -> Result<Value> {
    let op = match command {
        MachineCommitCommand::Inspect { .. } => return machine_commit_inspection(socket).await,
        MachineCommitCommand::Lookup { .. } => "lookup",
        MachineCommitCommand::Prepare { .. } => "prepare",
        MachineCommitCommand::Approve { .. } => "approve",
        MachineCommitCommand::Complete { .. } => "complete",
    };
    let invalid = || anyhow::anyhow!("invalid machine requester consent input");
    let unavailable = || {
        anyhow::anyhow!(
            "machine requester consent unavailable or outcome unknown; look up the retained review before another explicit action"
        )
    };
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let mut value = peerspan_host::onboarding_join::decode_machine_commit_input(&bytes, op, true)
        .map_err(|_| invalid())?;
    let id = value
        .as_object_mut()
        .and_then(|v| v.remove("flow_id"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(invalid)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(if op == "complete" { 95 } else { 5 }),
        Local(socket).post(
            format!("/v1/onboarding/join-flows/{id}/machine-commit/{op}"),
            value,
        ),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn machine_commit_inspection(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid machine requester inspection input");
    let unavailable = || anyhow::anyhow!("machine requester inspection unavailable");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let mut value = peerspan_host::onboarding_join::decode_commit_input(&bytes, "lookup", true)
        .map_err(|_| invalid())?;
    let id = value
        .as_object_mut()
        .and_then(|v| v.remove("flow_id"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(invalid)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post(
            format!("/v1/onboarding/join-flows/{id}/machine-commit/inspect"),
            value,
        ),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn commit_command(command: &CommitCommand, socket: &Path) -> Result<Value> {
    let operation = match command {
        CommitCommand::Complete { .. } => "complete",
        CommitCommand::Lookup { .. } => "lookup",
        CommitCommand::Prepare { .. } => "prepare",
        CommitCommand::Approve { .. } => "approve",
    };
    let invalid = || anyhow::anyhow!("invalid requester commit consent input");
    let unavailable = || {
        if operation == "complete" {
            anyhow::anyhow!(
                "requester commit completion unavailable or outcome unknown; inspect retained consent and progress before another explicit action"
            )
        } else {
            anyhow::anyhow!(
                "requester commit consent unavailable or outcome unknown; inspect the retained exact review before another explicit action"
            )
        }
    };
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    ensure!(
        bytes.len() <= 65536,
        "invalid requester commit consent input"
    );
    let mut value = peerspan_host::onboarding_join::decode_commit_input(&bytes, operation, true)
        .map_err(|_| invalid())?;
    let id = value
        .as_object_mut()
        .and_then(|v| v.remove("flow_id"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(invalid)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(if operation == "complete" { 95 } else { 5 }),
        Local(socket).post(
            format!("/v1/onboarding/join-flows/{id}/commit/{operation}"),
            value,
        ),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}
async fn owner_command(command: &OwnerCommand, socket: &Path) -> Result<Value> {
    if let OwnerCommand::Finalization { command } = command {
        return match command {
            OwnerFinalizationCommand::Inspect { .. } => finalization_inspect(socket).await,
            OwnerFinalizationCommand::Sign { .. } => {
                crate::onboarding_owner_finalization_sign::from_stdin(socket).await
            }
        };
    }
    if let OwnerCommand::Sign { .. } = command {
        return crate::onboarding_owner_sign::from_stdin(socket).await;
    }
    use peerspan_host::onboarding_join::{OwnerApproval, OwnerContext, decode_owner_input};
    let operation = match command {
        OwnerCommand::Prepare { .. } => "prepare",
        OwnerCommand::Lookup { .. } => "lookup",
        OwnerCommand::Approve { .. } => "approve",
        OwnerCommand::Sign { .. } | OwnerCommand::Finalization { .. } => unreachable!(),
    };
    let invalid = || anyhow::anyhow!("invalid owner review input");
    let mut bytes = Vec::new();
    io::stdin().lock().take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "owner review input exceeds 64 KiB");
    let mut value: Value = decode_owner_input(&bytes, operation, true).map_err(|_| invalid())?;
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
        .ok_or_else(invalid)?;
    if operation == "approve" {
        let _: OwnerApproval = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    } else {
        let _: OwnerContext = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    }
    Local(socket)
        .post(
            format!("/v1/onboarding/join-flows/{id}/owner/{operation}"),
            value,
        )
        .await
}

async fn finalization_inspect(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid original finalization inspection input");
    let unavailable = || {
        anyhow::anyhow!(
            "original finalization inspection unavailable; inspect the exact original consent and retained admission evidence"
        )
    };
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    ensure!(
        bytes.len() <= 65536,
        "invalid original finalization inspection input"
    );
    let mut value: Value =
        peerspan_host::onboarding_join::decode_owner_input(&bytes, "inspect-finalization", true)
            .map_err(|_| invalid())?;
    let id = value
        .as_object_mut()
        .and_then(|v| v.remove("flow_id"))
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|s| {
            s.strip_prefix("flow_").is_some_and(|v| {
                v.len() == 32
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
        .ok_or_else(invalid)?;
    let input: peerspan_host::onboarding_join::OwnerApproval =
        serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    input.context.validate().map_err(|_| invalid())?;
    for review in [&input.join_review_id, &input.owner_review_id] {
        ensure!(
            review.strip_prefix("review_").is_some_and(|v| v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "invalid original finalization inspection input"
        );
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post(
            format!("/v1/onboarding/join-flows/{id}/owner/finalization/inspect"),
            value,
        ),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn machine_inspection(socket: &Path) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid machine owner inspection input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let input = peerspan_host::onboarding_machine::decode_input(&bytes).map_err(|_| invalid())?;
    let payload = serde_json::json!({"context":input.context,"request_id":input.request_id});
    let unavailable = || anyhow::anyhow!("machine owner inspection unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Local(socket).post("/v1/onboarding/machine-owner-inspection".into(), payload),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

async fn machine_consent(socket: &Path, operation: &str) -> Result<Value> {
    let invalid = || anyhow::anyhow!("invalid machine owner consent input");
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let payload = peerspan_host::onboarding_machine_consent::decode_input(&bytes, operation)
        .map_err(|_| invalid())?;
    let unavailable = || anyhow::anyhow!("machine owner consent unavailable");
    tokio::time::timeout(
        std::time::Duration::from_secs(if operation == "sign" { 95 } else { 5 }),
        Local(socket).post(
            format!("/v1/onboarding/machine-owner-consent/{operation}"),
            payload,
        ),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}
