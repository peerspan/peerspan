use clap::{Parser, Subcommand};
use hyper::Method;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "capsule-host",
    about = "Run and control a local Capsule host daemon",
    after_help = "Session attachment records metadata only; agent integration is a later milestone."
)]
pub struct Cli {
    /// Private state directory; otherwise use XDG_STATE_HOME or HOME
    #[arg(long, value_name = "DIR")]
    pub state: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the host daemon in the foreground
    #[command(visible_alias = "serve")]
    Run,
    /// Show the local daemon's public identity
    Info,
    /// Manage local agent registrations
    #[command(subcommand)]
    Agent(AgentCommand),
    /// Manage local session attachment records
    #[command(subcommand)]
    Session(SessionCommand),
    /// Read the local activity log
    Activity {
        /// Read events after this sequence
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
        /// Maximum number of events
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=1000))]
        limit: i64,
    },
}

#[derive(Debug, Subcommand)]
pub enum AgentCommand {
    /// Register an agent owned by this host
    Register {
        #[arg(long)]
        name: String,
        /// Local owner label, not a network identity
        #[arg(long)]
        owner: String,
        /// Advertised capability; repeat for multiple capabilities
        #[arg(long = "capability", value_name = "NAME")]
        capabilities: Vec<String>,
    },
    /// List registered agents
    List,
    /// Inspect a registered agent
    Inspect { id: String },
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Record an attachment to a registered agent
    Attach {
        #[arg(long, value_name = "ID")]
        agent: String,
        #[arg(long, value_name = "NAME")]
        integration: String,
    },
    /// List session records, optionally filtered by agent
    List {
        #[arg(long, value_name = "ID")]
        agent: Option<String>,
    },
    /// Inspect a session record
    Inspect { id: String },
    /// Detach a session record
    Detach { id: String },
}

pub struct AdminRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
}

impl Command {
    /// Run starts the daemon; every other command uses its local control socket.
    pub fn request(self) -> Option<AdminRequest> {
        let (method, path, body) = match self {
            Self::Run => return None,
            Self::Info => (Method::GET, "/v1/host".into(), None),
            Self::Agent(AgentCommand::List) => (Method::GET, "/v1/agents".into(), None),
            Self::Agent(AgentCommand::Inspect { id }) => {
                (Method::GET, format!("/v1/agents/{}", encoded(&id)), None)
            }
            Self::Agent(AgentCommand::Register {
                name,
                owner,
                capabilities,
            }) => (
                Method::POST,
                "/v1/agents".into(),
                Some(json!({"name": name, "owner": owner, "capabilities": capabilities})),
            ),
            Self::Session(SessionCommand::Attach { agent, integration }) => (
                Method::POST,
                "/v1/sessions".into(),
                Some(json!({"agent_id": agent, "integration": integration})),
            ),
            Self::Session(SessionCommand::List { agent }) => (
                Method::GET,
                format!(
                    "/v1/sessions?agent_id={}",
                    encoded(&agent.unwrap_or_default())
                ),
                None,
            ),
            Self::Session(SessionCommand::Inspect { id }) => {
                (Method::GET, format!("/v1/sessions/{}", encoded(&id)), None)
            }
            Self::Session(SessionCommand::Detach { id }) => (
                Method::POST,
                format!("/v1/sessions/{}/detach", encoded(&id)),
                None,
            ),
            Self::Activity { after, limit } => (
                Method::GET,
                format!("/v1/activity?after={after}&limit={limit}"),
                None,
            ),
        };
        Some(AdminRequest { method, path, body })
    }
}

fn encoded(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
