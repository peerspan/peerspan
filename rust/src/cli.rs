use crate::integration::relative_expiry;
use anyhow::bail;
use chrono::{SecondsFormat, TimeDelta};
use clap::{Parser, Subcommand};
use hyper::Method;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "peerspan-host",
    about = "Run and control a local Peerspan host daemon",
    after_help = "Session attachment records metadata; a scoped adapter connects an opted-in session.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Private state directory; otherwise use XDG_STATE_HOME or HOME
    #[arg(long, value_name = "DIR")]
    pub state: Option<PathBuf>,
    /// Print help listing every command
    #[arg(long, hide = true)]
    pub help_advanced: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Link or renew this machine without copying an original person key
    Link(crate::link_cli::LinkArgs),
    /// Guide service, network, and project setup
    Up(UpArgs),
    /// Show this host's networks, sessions, and what needs attention
    Status {
        /// Print the daemon's status object
        #[arg(long)]
        json: bool,
    },
    /// Run the host daemon in the foreground
    #[command(visible_alias = "serve")]
    Run {
        /// Isolated bootstrap TCP bind address; defaults to the peer interface, or loopback
        #[arg(long, value_name = "IP:PORT")]
        bootstrap_listen: Option<std::net::SocketAddr>,
        /// Protected optional transport configuration file
        #[arg(long, value_name = "PATH")]
        transport_config: Option<PathBuf>,
        /// Opt-in peer bind address
        #[arg(long, value_name = "IP:PORT")]
        peer_listen: Option<std::net::SocketAddr>,
        /// Peer address advertised to coordination; defaults to a specific bind address
        #[arg(long, value_name = "IP:PORT", requires = "peer_listen")]
        advertise: Option<std::net::SocketAddr>,
        /// Seconds between coordination syncs
        #[arg(long, value_name = "SECONDS", default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
        coordination_interval: u64,
        /// ssh-agent socket used to renew this host's person's access
        /// policy; defaults to SSH_AUTH_SOCK
        #[arg(long, value_name = "SOCKET")]
        person_agent: Option<PathBuf>,
        /// Bytes of storage for task artifacts: stored files plus pending fetches
        #[arg(long, value_name = "BYTES", default_value_t = peerspan_host::artifact::DEFAULT_QUOTA, value_parser = clap::value_parser!(i64).range(1..))]
        artifact_quota: i64,
        /// CLI-generated person key file for renewing access policies when
        /// the ssh-agent lacks the key; defaults to
        /// $XDG_CONFIG_HOME/peerspan/person_ed25519, used while it exists
        #[arg(long, value_name = "PATH")]
        person_key_file: Option<PathBuf>,
    },
    /// Join through a private contact introduction and explicit machine approval
    Join {
        /// Historical argv tokens are refused; use a private input below
        #[arg(value_name = "TOKEN", hide = true)]
        token: Option<String>,
        #[command(flatten)]
        invitation: crate::decentralized_onboarding_cli::InvitationInput,
        /// Person key: an OpenSSH public key (select an ssh-agent identity) or
        /// unencrypted private key file
        #[arg(long, value_name = "PATH", conflicts_with = "no_person")]
        person_key: Option<PathBuf>,
        /// Host-only membership: do not admit or bind a person
        #[arg(long)]
        no_person: bool,
        /// Let this machine use your capabilities on your other machines
        #[arg(long, conflicts_with = "untrusted")]
        trusted: bool,
        /// Do not let this machine use your capabilities on your other machines
        #[arg(long)]
        untrusted: bool,
    },
    /// Print a private invite code (psi2-) for a new member; it lasts 1 hour
    /// by default and grants no membership by itself
    Invite {
        /// The new member's label
        #[arg(value_name = "LABEL")]
        label: String,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// When the invite expires (RFC 3339), 60 seconds to 24 hours ahead
        #[arg(long, value_name = "TIME", conflicts_with = "expires_in")]
        expires_at: Option<String>,
        /// How long the invite lasts, 60 seconds to 24 hours (for example 2h); default 1h
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
        /// Unsupported introduction signer override; use explicit machine approval
        #[arg(long, value_name = "PATH", hide = true)]
        person_key: Option<PathBuf>,
    },
    /// Set a principal's access to your agents
    Allow {
        /// everyone, network, group:NAME, person:PERSON or PERSON, or
        /// agent:HOST/AGENT
        #[arg(value_name = "PRINCIPAL")]
        principal: String,
        /// Agent name the access covers; * means every agent of yours
        #[arg(long, value_name = "NAME", default_value = "*")]
        agent: String,
        /// Allow messages only, not task.submit
        #[arg(long)]
        no_tasks: bool,
        /// Task artifact bound: a byte count with an optional K, M, or G suffix
        #[arg(long, value_name = "SIZE")]
        files: Option<String>,
        /// Also allow task.delegate, so your agent may pass tasks on
        #[arg(long)]
        delegate: bool,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Remove a principal's access to your agents; deny ID [--reason TEXT] denies a call waiting for your approval
    Deny {
        /// A principal, or the ID of a call waiting for your approval
        #[arg(value_name = "PRINCIPAL")]
        principal: String,
        /// With a call ID: the reason given to the caller
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
        /// Only from this agent's rules (* names the * rules); default every rule
        #[arg(long, value_name = "NAME")]
        agent: Option<String>,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Block a person or host locally
    Block {
        /// A host ID, or a person ID or label
        #[arg(value_name = "TARGET")]
        target: String,
        /// Accepted like the other person commands; blocks are host-local and
        /// sign nothing
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Remove a local block
    Unblock {
        /// A host ID, or a person ID or label
        #[arg(value_name = "TARGET")]
        target: String,
        /// Accepted like the other person commands; blocks are host-local and
        /// sign nothing
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Register an agent for a project, set up its directory session, and launch it
    Attach {
        /// Integration ID, or claude for claude-code
        #[arg(value_name = "HARNESS")]
        harness: String,
        /// Agent name; default claude (for claude-code) or the integration ID,
        /// suffixed when taken
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Project directory; default the current directory
        #[arg(long, value_name = "DIR")]
        directory: Option<PathBuf>,
        /// Authorization expiry; without it or --expires-in, renewable
        #[arg(long, value_name = "TIME")]
        expires_at: Option<String>,
        /// Relative authorization lifetime, from 1m to 720h
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
        /// Cap on the session's sends and delegations by address per hour
        #[arg(long, value_name = "N", default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=10000))]
        max_sends_per_hour: i64,
        /// Let the agent call capabilities shared with you, and yours on your
        /// other trusted machines, without asking
        #[arg(long)]
        calls: bool,
        /// Do not let the agent call capabilities, without asking
        #[arg(long)]
        no_calls: bool,
        /// Cap on the agent's capability calls per hour, 1 to 10000; default 100
        #[arg(long, value_name = "N")]
        max_calls_per_hour: Option<String>,
        #[arg(long = "option", value_name = "KEY=VALUE")]
        options: Vec<String>,
        #[arg(long, value_name = "DIR")]
        integrations: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        runner: Option<PathBuf>,
        /// Stop after setup and print the result instead of launching the harness
        #[arg(long)]
        no_start: bool,
        /// Arguments passed to the harness at launch
        #[arg(last = true, allow_hyphen_values = true, value_name = "HARNESS_ARGS")]
        harness_args: Vec<String>,
    },
    /// Show the agents you can reach, your own, and who can reach yours
    Agents {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// Refresh the directory first
        #[arg(long)]
        refresh: bool,
        /// Print the directory as JSON
        #[arg(long)]
        json: bool,
    },
    /// Send a message to an agent by address, PERSON/AGENT or HOST_ID/AGENT
    Send {
        #[arg(value_name = "TARGET")]
        target: String,
        #[arg(value_name = "TEXT")]
        text: String,
        /// Resolve the address only in this network
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// Grant ID; otherwise the daemon chooses an authorization
        #[arg(long, value_name = "ID")]
        grant: Option<String>,
        /// Send as this registered local agent
        #[arg(long, value_name = "AGENT_ID")]
        from_agent: Option<String>,
        /// RFC3339 deadline; default one hour
        #[arg(long, value_name = "TIME")]
        deadline: Option<String>,
    },
    /// Show the sources this host can operate, from attached agents' harnesses
    Sources(SourcesArgs),
    /// List the calls waiting for your approval; approvals show ID for one
    Approvals(ApprovalsArgs),
    /// Approve one call waiting for your approval, at a terminal
    Approve {
        /// CALL_ID, or SENDER_HOST_ID/CALL_ID
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Create, list, show, and remove capabilities on this host
    #[command(subcommand)]
    Capability(CapabilityCommand),
    /// Share a capability: share NAME --with PRINCIPAL, or the guided share --with PRINCIPAL
    Share {
        /// The existing capability; omit for the guided share
        #[arg(value_name = "NAME")]
        name: Option<String>,
        #[arg(long = "with", value_name = "PRINCIPAL")]
        with: String,
        /// Calls per hour each caller may make; on an existing share it changes the limit for every recipient
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(i64).range(1..=10000))]
        calls_per_hour: Option<i64>,
        /// Confirm without asking
        #[arg(long)]
        yes: bool,
        /// Guided share: the source, AGENT/SERVER or SERVER
        #[arg(long, value_name = "SOURCE")]
        from: Option<String>,
        /// Guided share: the operations, OP[,OP...]
        #[arg(long, value_name = "OPS")]
        operations: Option<String>,
        /// Guided share: all, or URI[,URI...]
        #[arg(long, value_name = "RESOURCES")]
        resources: Option<String>,
        /// Guided share: the capability's name; default the server's
        #[arg(long = "name", value_name = "NAME")]
        capability_name: Option<String>,
        /// Guided share: the capability's own environment file
        #[arg(long, value_name = "PATH")]
        env_file: Option<PathBuf>,
        /// Guided share: arguments replacing the source's; repeat for each
        #[arg(long = "arg", value_name = "A", allow_hyphen_values = true)]
        args: Vec<String>,
        /// Guided share: which calls wait for your approval: none, changing, all, or OP[,OP...]
        #[arg(long, value_name = "MODE")]
        approval: Option<String>,
        /// Guided share: self-access calls from your agents need no approval
        #[arg(long)]
        no_agent_self_approval: bool,
        /// Guided share: a resource bound, KEY=VALUE[,KEY=VALUE...]; repeat for alternatives
        #[arg(long = "bound", value_name = "KEY=VALUE")]
        bound: Vec<String>,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Show every capability here and every share in your policies
    Shares {
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
    },
    /// Stop sharing a capability with a principal
    Unshare {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long = "with", value_name = "PRINCIPAL")]
        with: String,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Show reachable agents and usable capabilities together
    Discover {
        /// Only this person's
        #[arg(value_name = "PERSON")]
        person: Option<String>,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long)]
        json: bool,
        /// Show what this local agent (ID or name) may call
        #[arg(long, value_name = "AGENT")]
        from_agent: Option<String>,
    },
    /// Call an operation: call ADDRESS OPERATION [--input JSON] [--KEY VALUE ...] [--deadline T] [--wait D] [--network ID] [--from-agent AGENT [--from-session ID]]
    Call {
        /// PERSON/CAPABILITY, HOST_ID/CAPABILITY, PERSON/AGENT/SERVER, or HOST_ID/AGENT/SERVER
        #[arg(value_name = "ADDRESS")]
        address: String,
        #[arg(value_name = "OPERATION")]
        operation: String,
        /// --input JSON, --KEY VALUE, --deadline T, --wait D, --network ID
        #[arg(
            value_name = "OPTIONS",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        options: Vec<String>,
    },
    /// List and inspect calls
    #[command(subcommand)]
    Calls(CallsCommand),
    /// Let one of your machines use your capabilities on your other machines
    Trust {
        /// Host ID; default this host
        #[arg(value_name = "HOST")]
        host: Option<String>,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Stop letting a machine use your capabilities on your other machines
    Untrust {
        #[arg(value_name = "HOST")]
        host: String,
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Install the daemon as a user service and start it
    Install {
        /// Private state directory; otherwise use XDG_STATE_HOME or HOME
        #[arg(long, value_name = "DIR")]
        state: Option<PathBuf>,
        /// Peer bind address; defaults to the installed unit's, then 0.0.0.0:7401
        /// or the next free UDP port up to 7499
        #[arg(long, value_name = "IP:PORT")]
        peer_listen: Option<std::net::SocketAddr>,
        /// Enable the service without starting it
        #[arg(long)]
        no_start: bool,
    },
    /// Stop and remove the user service; the state directory stays
    Uninstall,
    /// Show the local daemon's public identity
    Info,
    /// Manage local agent registrations
    #[command(subcommand)]
    Agent(AgentCommand),
    /// Manage local session attachment records
    #[command(subcommand)]
    Session(SessionCommand),
    /// Configure owner-verified peer identities
    #[command(subcommand)]
    Peer(PeerCommand),
    /// Manage receiver-owned message grants
    #[command(subcommand)]
    Grant(GrantCommand),
    /// Manage the owner access policy and this host's block list
    #[command(subcommand)]
    Access(AccessCommand),
    /// Submit messages and inspect durable host receipts
    #[command(subcommand)]
    Message(MessageCommand),
    /// Delegate a task to an agent by address: task TARGET TEXT
    #[command(subcommand)]
    Task(TaskCommand),
    /// Inspect and prune stored task artifacts
    #[command(subcommand)]
    Artifact(ArtifactCommand),
    /// Create, join, and inspect coordinated networks
    #[command(subcommand)]
    Network(NetworkCommand),
    /// Inspect the person key used to sign person statements (no daemon)
    #[command(subcommand)]
    Person(PersonCommand),
    /// Issue or revoke credentials for one local session
    #[command(subcommand)]
    Adapter(AdapterCommand),
    /// Inspect durable adapter handoffs
    #[command(subcommand)]
    Delivery(DeliveryCommand),
    /// Read the local activity log
    Activity {
        /// Read events after this sequence
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
        /// Maximum number of events
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=1000))]
        limit: i64,
    },
    /// Print help for a command; `help advanced` lists every command
    Help {
        #[arg(value_name = "COMMAND")]
        topic: Vec<String>,
    },
}

#[derive(Debug, clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ApprovalsArgs {
    #[command(subcommand)]
    pub command: Option<ApprovalsCommand>,
    /// Also the approvals decided in the last 7 days
    #[arg(long)]
    pub all: bool,
    /// Print JSON
    #[arg(long)]
    pub json: bool,
}
#[derive(Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// Show one approval, with the call's input
    Show {
        /// CALL_ID, or SENDER_HOST_ID/CALL_ID
        #[arg(value_name = "ID")]
        id: String,
        #[arg(long)]
        json: bool,
    },
}
/// Whether text is an approval ID: a call ID, or SENDER_HOST_ID/CALL_ID.
pub fn approval_id(text: &str) -> bool {
    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let call = |s: &str| s.strip_prefix("call_").is_some_and(|h| hex(h, 32));
    match text.split_once('/') {
        Some((host, id)) => host.strip_prefix("host_").is_some_and(|h| hex(h, 64)) && call(id),
        None => call(text),
    }
}

#[derive(Debug, clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SourcesArgs {
    #[command(subcommand)]
    pub command: Option<SourcesCommand>,
    /// Only this agent
    #[arg(long, value_name = "NAME")]
    pub agent: Option<String>,
    /// Print JSON
    #[arg(long)]
    pub json: bool,
}
#[derive(Debug, Subcommand)]
pub enum SourcesCommand {
    /// Discover the sources of each attached agent again
    Refresh {
        #[arg(long, value_name = "NAME")]
        agent: Option<String>,
        /// Only the built-in sources, such as gh
        #[arg(long)]
        builtin: bool,
    },
    /// Let one of your trusted machines call this host's sources directly
    OpenTo {
        #[arg(
            value_name = "HOST",
            required_unless_present = "all",
            conflicts_with = "all"
        )]
        host: Option<String>,
        /// Every machine of yours that passes self access
        #[arg(long)]
        all: bool,
    },
    /// Sign Peerspan in to a remote source's server (OAuth)
    Login {
        #[arg(value_name = "SOURCE")]
        source: String,
        /// Scopes to ask for, space-separated
        #[arg(long, value_name = "SCOPES")]
        scopes: Option<String>,
        /// A client ID registered with the provider
        #[arg(long, value_name = "ID")]
        client_id: Option<String>,
        /// A file holding that client's secret (mode 0600 or stricter)
        #[arg(long, value_name = "PATH")]
        client_secret_file: Option<PathBuf>,
        /// The loopback port of the redirect
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
        /// Print the link, and read the pasted address from stdin
        #[arg(long)]
        no_browser: bool,
        /// Your own label for the provider account that approves
        #[arg(long, value_name = "LABEL")]
        account: Option<String>,
    },
    /// Revoke and delete this host's sign-in for a remote source
    Logout {
        #[arg(value_name = "SOURCE")]
        source: String,
        #[arg(long)]
        yes: bool,
    },
    /// Stop letting a machine call this host's sources directly
    CloseTo {
        #[arg(
            value_name = "HOST",
            required_unless_present = "all",
            conflicts_with = "all"
        )]
        host: Option<String>,
        #[arg(long)]
        all: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum CapabilityCommand {
    /// Create a capability from a source, without sharing it
    Create {
        #[arg(value_name = "NAME")]
        name: String,
        /// AGENT/SERVER, or SERVER when one agent here has it
        #[arg(long, value_name = "SOURCE")]
        from: String,
        /// OP[,OP...]
        #[arg(long, value_name = "OPS")]
        operations: Option<String>,
        /// all, or URI[,URI...]
        #[arg(long, value_name = "RESOURCES")]
        resources: Option<String>,
        /// The capability's own environment file
        #[arg(long, value_name = "PATH")]
        env_file: Option<PathBuf>,
        /// Arguments replacing the source's; repeat for each
        #[arg(long = "arg", value_name = "A", allow_hyphen_values = true)]
        args: Vec<String>,
        /// A resource bound, KEY=VALUE[,KEY=VALUE...]; repeat for alternatives
        #[arg(long = "bound", value_name = "KEY=VALUE")]
        bound: Vec<String>,
        /// The person key that signs the name's claims
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
        /// Which calls wait for your approval: none, changing, all, or OP[,OP...]
        #[arg(long, value_name = "MODE")]
        approval: Option<String>,
        /// Self-access calls from your agents need no approval
        #[arg(long)]
        no_agent_self_approval: bool,
    },
    /// Set which calls wait for your approval: none, changing, all, or OP[,OP...]
    Approval {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(value_name = "MODE")]
        mode: String,
        /// Self-access calls from your agents need approval too
        #[arg(long)]
        agent_self: bool,
        /// Self-access calls from your agents need no approval
        #[arg(long)]
        no_agent_self: bool,
    },
    /// Give a capability its own sign-in to its remote source (OAuth)
    Login {
        #[arg(value_name = "NAME")]
        name: String,
        /// Scopes to ask for, space-separated
        #[arg(long, value_name = "SCOPES")]
        scopes: Option<String>,
        /// A client ID registered with the provider
        #[arg(long, value_name = "ID")]
        client_id: Option<String>,
        /// A file holding that client's secret (mode 0600 or stricter)
        #[arg(long, value_name = "PATH")]
        client_secret_file: Option<PathBuf>,
        /// The loopback port of the redirect
        #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
        /// Print the link, and read the pasted address from stdin
        #[arg(long)]
        no_browser: bool,
        /// Your own label for the provider account that approves
        #[arg(long, value_name = "LABEL")]
        account: Option<String>,
    },
    /// Revoke and delete a capability's own sign-in
    Logout {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// List this host's capabilities
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one capability
    Show {
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Remove a capability, withdrawing its shares first
    Remove {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long)]
        yes: bool,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
}
#[derive(Debug, Subcommand)]
pub enum CallsCommand {
    /// Calls this host made, in local order
    List {
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=1000))]
        limit: i64,
    },
    /// Calls this host received
    Received {
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=1000))]
        limit: i64,
    },
    /// Show a call's local record
    Inspect {
        #[arg(long)]
        peer: String,
        id: String,
    },
    /// Ask the receiver to cancel a call
    Cancel {
        #[arg(long)]
        peer: String,
        id: String,
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
        /// Descriptive label, stored in the capabilities field; repeat for
        /// several. It confers nothing. `--capability` is an alias.
        #[arg(long = "label", visible_alias = "capability", value_name = "NAME")]
        capabilities: Vec<String>,
    },
    /// List registered agents
    List,
    /// Inspect a registered agent
    Inspect { id: String },
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Prepare an opted-in session using an installed harness integration
    Setup {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, requires = "agent")]
        harness: Option<String>,
        #[arg(long, requires = "harness")]
        agent: Option<String>,
        /// Authorization expiry; without it or --expires-in, renewable
        #[arg(long, requires_all=["agent","harness"])]
        expires_at: Option<String>,
        /// Relative authorization lifetime, from 1m to 720h
        #[arg(long, requires_all=["agent","harness"])]
        expires_in: Option<String>,
        #[arg(long, requires = "agent")]
        integrations: Option<PathBuf>,
        #[arg(long, requires = "agent")]
        runner: Option<PathBuf>,
        #[arg(long, requires = "agent")]
        routes: Option<PathBuf>,
        #[arg(long = "option", value_name = "KEY=VALUE", requires = "agent")]
        options: Vec<String>,
    },
    /// Launch a prepared session if its integration supports launch
    Start {
        /// Setup directory; default the attach profile of the current directory
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(last = true, allow_hyphen_values = true)]
        harness_args: Vec<String>,
    },
    /// Inspect session and integration readiness without changing state
    Doctor {
        /// Setup directory; default the attach profile of the current directory
        #[arg(long)]
        directory: Option<PathBuf>,
    },
    /// Show the work the current directory's attached session still owes
    Pending {
        /// Print the pending work object as JSON
        #[arg(long)]
        json: bool,
        /// Print the pending work as Claude Code SessionStart hook output
        #[arg(long)]
        hook: bool,
    },

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

#[derive(Debug, Subcommand)]
pub enum PeerCommand {
    Add {
        #[arg(long)]
        id: String,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        address: std::net::SocketAddr,
    },
    List,
    /// Show whether traffic to a peer goes direct or through the relay
    Path {
        id: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum PersonCommand {
    /// Show the person ID and key from ssh-agent or --person-key
    Show {
        /// OpenSSH public key (select an ssh-agent identity) or unencrypted private key file
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
}

/// `network reinvite OLD NEW` (spec 14.2).
#[derive(Debug, clap::Args)]
pub struct ReinviteArgs {
    /// The legacy or root-split network
    pub old: String,
    /// A coordinator-free network this host is a current member of
    pub new: String,
    /// When the invites expire (RFC 3339), 60 seconds to 24 hours ahead
    #[arg(long, value_name = "TIME", conflicts_with = "expires_in")]
    pub expires_at: Option<String>,
    /// How long the invites last, 60 seconds to 24 hours; default 24h
    #[arg(long, value_name = "DURATION")]
    pub expires_in: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum NetworkCommand {
    /// Review an exact current-root feature recovery snapshot and target
    Repair(crate::link_cli::RepairArgs),
    /// Review and enable approved machine linking with the current root
    EnableLinking {
        #[arg(long)]
        network: Option<String>,
        #[arg(long)]
        root_key: Option<PathBuf>,
    },
    /// Create a network whose root key stays on this host
    Create {
        /// Network name; or give --name
        #[arg(value_name = "NAME")]
        name_arg: Option<String>,
        #[arg(long)]
        name: Option<String>,
        /// Your person and member label; defaults to the login name
        #[arg(long = "as", alias = "member", value_name = "LABEL")]
        member: Option<String>,
        /// Unsupported legacy coordinator option (creation is local)
        #[arg(long, value_name = "HOST:PORT", hide = true)]
        coordinator: Option<String>,
        /// Unsupported legacy coordinator key
        #[arg(long, value_name = "BASE64", hide = true)]
        coordinator_key: Option<String>,
        /// Person key: an OpenSSH public key (select an ssh-agent identity) or
        /// unencrypted private key file; default is the agent's only ssh-ed25519 key
        #[arg(
            long,
            alias = "person-key-file",
            value_name = "PATH",
            conflicts_with = "no_person"
        )]
        person_key: Option<PathBuf>,
        /// Unsupported legacy creation without an original-person owner
        #[arg(long, hide = true)]
        no_person: bool,
        /// Unsupported creation-time trust; review trust after creation
        #[arg(long, hide = true, conflicts_with = "untrusted")]
        trusted: bool,
        /// Do not let this machine use your capabilities on your other machines
        #[arg(long)]
        untrusted: bool,
    },
    /// Print a private invite code (psi2-) for a new member; it lasts 1 hour
    /// by default and grants no membership by itself
    Invite {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// The new member's label
        #[arg(long)]
        member: String,
        /// When the invite expires (RFC 3339), 60 seconds to 24 hours ahead
        #[arg(long, value_name = "TIME", conflicts_with = "expires_in")]
        expires_at: Option<String>,
        /// How long the invite lasts, 60 seconds to 24 hours (for example 2h); default 1h
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
        /// Unsupported host-only introduction
        #[arg(long, hide = true)]
        host_only: bool,
        /// Unsupported introduction signer override; use explicit machine approval
        #[arg(long, value_name = "PATH", hide = true)]
        person_key: Option<PathBuf>,
    },
    /// Join through a private contact introduction and explicit machine approval
    Join {
        /// Historical tokens and descriptors are refused
        #[arg(long, conflicts_with = "descriptor", hide = true)]
        token: Option<String>,
        #[command(flatten)]
        invitation: crate::decentralized_onboarding_cli::InvitationInput,
        #[arg(long)]
        descriptor: Option<String>,
        /// Person key: an OpenSSH public key (select an ssh-agent identity) or
        /// unencrypted private key file; default is the agent's only ssh-ed25519 key
        #[arg(long, value_name = "PATH", conflicts_with = "no_person")]
        person_key: Option<PathBuf>,
        /// Do not admit or bind a person
        #[arg(long)]
        no_person: bool,
        /// Let this machine use your capabilities on your other machines
        #[arg(long, conflicts_with = "untrusted")]
        trusted: bool,
        /// Do not let this machine use your capabilities on your other machines
        #[arg(long)]
        untrusted: bool,
    },
    /// Admit a person or a host by public key (administrator only)
    Admit {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// ssh-ed25519 public key line, or a path to one
        #[arg(
            long,
            value_name = "SSH_PUBLIC_KEY",
            required_unless_present = "host",
            conflicts_with = "host"
        )]
        person: Option<String>,
        /// Host public key (standard Base64), as `info` prints it
        #[arg(long, value_name = "HOST_PUBLIC_KEY")]
        host: Option<String>,
        #[arg(long)]
        member: String,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Issue a one-time person invite token (administrator only)
    InvitePerson {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long)]
        member: String,
        #[arg(long, value_name = "TIME")]
        expires_at: Option<String>,
        /// Relative lifetime, from 1m to 720h
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Redeem a person invite for your person key, on a member host
    RedeemPerson {
        #[arg(long)]
        token: String,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Bind this host to your person; signed with your person key
    Bind {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Unbind one of your hosts with its current owner authority
    Unbind {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "HOST_ID")]
        host: String,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
        /// Exact owner provider; auto uses only this host's selected provider
        #[arg(long, default_value = "auto")]
        signer: String,
        /// Approve the exact displayed typed action without a prompt
        #[arg(long)]
        approve: bool,
    },
    /// Remove a person and end its bindings (administrator only)
    RemovePerson {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PERSON_ID")]
        person: String,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
        /// Exact administrator provider; auto uses only the selected provider
        #[arg(long, default_value = "auto")]
        signer: String,
        /// The external root key, used only when explicitly selected
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
        /// Approve the exact displayed typed action without a prompt
        #[arg(long)]
        approve: bool,
    },
    /// List a network's persons and the hosts bound to them
    Persons { id: Option<String> },
    /// List networks
    List,
    /// List a network's verified members
    Members { id: Option<String> },
    /// Register or sync a network now
    Sync { id: Option<String> },
    /// Revoke a member host's membership (administrator only)
    Revoke {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long, value_name = "HOST_ID")]
        host: String,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
        /// Exact administrator provider; auto uses only the selected provider
        #[arg(long, default_value = "auto")]
        signer: String,
        /// The external root key, used only when explicitly selected
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
        /// Approve the exact displayed typed action without a prompt
        #[arg(long)]
        approve: bool,
    },
    /// Revoke an invite, and any host that joined with it (administrator only)
    RevokeInvite {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "INVITE_PUBLIC_KEY")]
        invite: String,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Leave a network; takes effect locally even if coordination is down
    Leave { id: String },
    /// Print an invite into NEW for each member machine of OLD, a legacy
    /// network or one frozen by a root split; invites last 24 hours by default
    Reinvite(ReinviteArgs),
    /// Rotate the root after reviewing the exact finite authority to retain
    RotateRoot {
        id: String,
        /// Rotate to the SSH key named by --root-key; this host then deletes its root seed
        #[arg(long, requires = "root_key")]
        to_ssh: bool,
        /// The root's SSH key: an OpenSSH public key (select an ssh-agent
        /// identity) or unencrypted private key file
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
    },
    /// Make a person an administrator (root only)
    DelegateAdmin {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// Person ID or label
        #[arg(long)]
        person: String,
        /// The SSH root key, when this host does not hold the root seed
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
        /// Select network_root explicitly for an already-owned daemon root
        #[arg(long, default_value = "auto")]
        signer: String,
        /// Exact finite authority deadline
        #[arg(long, value_name = "TIME")]
        not_after: Option<String>,
        /// Resolve exactly these remembered authority barriers or fork heads
        #[arg(long, value_name = "DS")]
        resolve: Vec<String>,
        /// Approve the exact displayed typed action without a prompt
        #[arg(long)]
        approve: bool,
    },
    /// Remove an administrator, permanently (root only)
    RemoveAdmin {
        #[arg(long, value_name = "ID")]
        network: String,
        /// Person ID or label
        #[arg(long)]
        person: String,
        /// Also invalidate everything that administrator signed
        #[arg(long, conflicts_with = "keep")]
        revoke_admitted: bool,
        /// The SSH root key, when this host does not hold the root seed
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
        /// Select network_root explicitly for an already-owned daemon root
        #[arg(long, default_value = "auto")]
        signer: String,
        /// Retain exactly these signed contributions; repeat for every ID
        #[arg(long, value_name = "DS", conflicts_with = "revoke_admitted")]
        keep: Vec<String>,
        /// Exact administrator statement to withdraw when more than one is known
        #[arg(long, value_name = "DS")]
        statement: Option<String>,
        /// Approve the exact displayed typed action without a prompt
        #[arg(long)]
        approve: bool,
    },
    /// Define groups of persons (administrator or root)
    #[command(subcommand)]
    Group(GroupCommand),
    /// Move a network to another coordinator (administrator or root)
    Move {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// The new coordinator's address
        #[arg(long, value_name = "HOST:PORT")]
        coordinator: String,
        /// The new coordinator's public key (standard Base64)
        #[arg(long, value_name = "KEY")]
        coordinator_key: String,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// List a network's current groups
    Groups { id: Option<String> },
}
#[derive(Debug, Subcommand)]
pub enum GroupCommand {
    /// Set a group's current membership; an empty membership is permitted
    Set {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "NAME")]
        group: String,
        /// Person ID or label; repeat for each member
        #[arg(long)]
        person: Vec<String>,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
        /// Exact administrator provider; auto uses only the selected provider
        #[arg(long, default_value = "auto")]
        signer: String,
        /// The external root key, used only when explicitly selected
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
        /// Exact finite authority deadline
        #[arg(long, value_name = "TIME")]
        not_after: Option<String>,
        /// Approve the exact displayed typed action without a prompt
        #[arg(long)]
        approve: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum GrantCommand {
    Create {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        agent: String,
        /// Grant expiry; default 30 days
        #[arg(long, value_name = "TIME")]
        expires_at: Option<String>,
        /// Relative lifetime, from 1m to 720h
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
        #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(i64).range(1..=65536))]
        max_message_bytes: i64,
        #[arg(long)]
        allow_disconnected: bool,
        /// Authorize only requests whose origin is this agent of the peer
        #[arg(long, value_name = "AGENT_ID")]
        from_agent: Option<String>,
        /// What the grant authorizes
        #[arg(long, value_parser = ["message.append", "task.submit", "task.delegate"], default_value = "message.append")]
        action: String,
        /// Total input and result artifact bytes a task may carry (task.submit only)
        #[arg(long, value_name = "N", default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..=peerspan_host::artifact::MAX_BOUND))]
        max_artifact_bytes: i64,
    },
    List,
    Revoke {
        id: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Add or replace the rule for an agent in your policy
    Allow {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "NAME")]
        agent: String,
        /// person:ID, person:LABEL, group:NAME, network, or
        /// agent:HOST_ID/AGENT_ID; repeat for each
        #[arg(long, required = true)]
        principal: Vec<String>,
        #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(i64).range(1..=65536))]
        max_message_bytes: i64,
        #[arg(long)]
        allow_disconnected: bool,
        #[arg(long, default_value_t = 7, value_parser = clap::value_parser!(i64).range(1..=90))]
        valid_days: i64,
        /// Action the rule allows; repeat for each (default message.append)
        #[arg(long = "action", value_name = "ACTION", value_parser = ["message.append", "task.submit", "task.delegate"])]
        actions: Vec<String>,
        /// Total input and result artifact bytes a task may carry (task.submit only)
        #[arg(long, value_name = "N", default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..=peerspan_host::artifact::MAX_BOUND))]
        max_artifact_bytes: i64,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Remove principals from an agent's rule, or the whole rule
    Deny {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "NAME")]
        agent: String,
        #[arg(long)]
        principal: Vec<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Re-sign your current rules now
    Renew {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Show a person's newest verified policy (yours by default)
    Show {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        #[arg(long)]
        person: Option<String>,
    },
    /// Sync your policy with your other hosts now and retry its deliveries,
    /// or show its delivery status
    Sync {
        #[arg(long, value_name = "ID")]
        network: Option<String>,
        /// Show the status without syncing
        #[arg(long)]
        status: bool,
    },
    /// Refuse messages from a person or host on this host
    Block {
        #[arg(long, conflicts_with = "host", required_unless_present = "host")]
        person: Option<String>,
        #[arg(long, value_name = "HOST_ID")]
        host: Option<String>,
    },
    /// Remove a block
    Unblock {
        #[arg(long, conflicts_with = "host", required_unless_present = "host")]
        person: Option<String>,
        #[arg(long, value_name = "HOST_ID")]
        host: Option<String>,
    },
    /// List this host's blocks
    Blocks,
}
#[derive(Debug, Subcommand)]
pub enum MessageCommand {
    Origin {
        #[arg(long)]
        peer: String,
        id: String,
    },
    /// Send a message to an agent on a peer host
    Send {
        #[arg(long)]
        peer: String,
        /// Grant ID; otherwise cite the target owner's policy
        #[arg(long)]
        grant: Option<String>,
        #[arg(long)]
        agent: String,
        /// RFC3339 deadline; default one hour
        #[arg(long)]
        deadline: Option<String>,
        #[arg(long)]
        content: String,
        #[arg(long, default_value = "")]
        request: String,
        /// Send as this registered local agent
        #[arg(long, value_name = "AGENT_ID")]
        from_agent: Option<String>,
        /// Send as this session of the --from-agent agent
        #[arg(long, value_name = "SESSION_ID", requires = "from_agent")]
        from_session: Option<String>,
    },
    List {
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=1000))]
        limit: i64,
    },
    Inspect {
        #[arg(long)]
        peer: String,
        id: String,
    },
    Retry {
        #[arg(long)]
        peer: String,
        id: String,
    },
    Refresh {
        #[arg(long)]
        peer: String,
        id: String,
    },
    Reply {
        #[arg(long)]
        peer: String,
        id: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum TaskCommand {
    /// Submit a task to an agent on a peer host
    Submit {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        input: String,
        /// RFC3339 deadline for an agent to accept it; default one hour
        #[arg(long)]
        deadline: Option<String>,
        /// Grant ID; otherwise cite the target owner's policy
        #[arg(long)]
        grant: Option<String>,
        /// Submit as this registered local agent
        #[arg(long, value_name = "AGENT_ID")]
        from_agent: Option<String>,
        /// Submit as this session of the --from-agent agent
        #[arg(long, value_name = "SESSION_ID", requires = "from_agent")]
        from_session: Option<String>,
        /// Task ID; generated when omitted
        #[arg(long = "task", value_name = "ID")]
        task: Option<String>,
        /// File to attach as an input artifact; repeat for each
        #[arg(long = "artifact", value_name = "PATH")]
        artifacts: Vec<PathBuf>,
        /// Media type of the artifact in the same position; repeat for each
        #[arg(long = "artifact-type", value_name = "TYPE")]
        artifact_types: Vec<String>,
        /// Let the receiver pass the task on this many further hops (0 to 2)
        #[arg(long, value_name = "N", default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=2))]
        delegation_depth: u64,
        /// Who the receiver may pass it on to: network, person:ID, or
        /// host:ID; repeat for each (default network)
        #[arg(long = "delegate-to", value_name = "PRINCIPAL")]
        delegate_to: Vec<String>,
        /// Forward the running task received from this host instead
        #[arg(long, value_name = "HOST", requires = "parent_task", conflicts_with_all = ["delegation_depth", "delegate_to"])]
        parent_sender: Option<String>,
        /// The received task to forward
        #[arg(long, value_name = "ID", requires = "parent_sender")]
        parent_task: Option<String>,
    },
    /// Save an input or fetched result of a submitted task to a new file
    Artifact {
        #[arg(long)]
        peer: String,
        id: String,
        sha256: String,
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// List submitted tasks in local order
    List {
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=1000))]
        limit: i64,
    },
    /// Show a submitted task's local record
    Inspect {
        #[arg(long)]
        peer: String,
        id: String,
    },
    /// Show a submitted task's locally stored events
    Events {
        #[arg(long)]
        peer: String,
        id: String,
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
    },
    /// Ask the receiver to cancel a submitted task
    Cancel {
        #[arg(long)]
        peer: String,
        id: String,
    },
    /// `task TARGET TEXT [OPTIONS]`, parsed as `TaskTo`.
    #[command(external_subcommand)]
    To(Vec<String>),
}

/// `task TARGET TEXT`: a task submission by address.
#[derive(Debug, Parser)]
#[command(about = "Delegate a task to an agent by address, PERSON/AGENT or HOST_ID/AGENT")]
pub struct TaskTo {
    #[arg(value_name = "TARGET")]
    pub target: String,
    #[arg(value_name = "TEXT")]
    pub text: String,
    /// File to attach as an input artifact; repeat for each
    #[arg(long = "file", value_name = "PATH")]
    pub files: Vec<PathBuf>,
    /// Resolve the address only in this network
    #[arg(long, value_name = "ID")]
    pub network: Option<String>,
    /// Grant ID; otherwise the daemon chooses an authorization
    #[arg(long, value_name = "ID")]
    pub grant: Option<String>,
    /// Submit as this registered local agent
    #[arg(long, value_name = "AGENT_ID")]
    pub from_agent: Option<String>,
    /// RFC3339 deadline for an agent to accept it; default one hour
    #[arg(long, value_name = "TIME")]
    pub deadline: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    /// Show stored artifact files, their sizes, and the quota
    List,
    /// Release the artifacts of every final task and of uploads now
    Prune,
}

#[derive(Debug, Subcommand)]
pub enum AdapterCommand {
    Rotate {
        id: String,
    },
    Connection {
        id: String,
    },
    #[command(subcommand)]
    Route(RouteCommand),

    Create {
        #[arg(long)]
        session: String,
        /// Credential expiry; without it or --expires-in, renewable
        #[arg(long, value_name = "TIME")]
        expires_at: Option<String>,
        /// Relative lifetime, from 1m to 720h
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
    },
    List,
    Inspect {
        id: String,
    },
    Revoke {
        id: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum RouteCommand {
    Add {
        #[arg(long)]
        adapter: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        agent: String,
        /// Grant ID; otherwise cite the target owner's policy
        #[arg(long)]
        grant: Option<String>,
        /// Route expiry; without it or --expires-in, follows the credential
        #[arg(long, value_name = "TIME")]
        expires_at: Option<String>,
        /// Relative lifetime, from 1m to 720h
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
        #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(i64).range(1..=65536))]
        max_message_bytes: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=10000))]
        max_messages: i64,
        /// What the route sends: messages or tasks
        #[arg(long, value_parser = ["message.append", "task.submit"], default_value = "message.append")]
        action: String,
        /// Let receivers of tasks sent through it pass them on this many
        /// further hops (0 to 2; task.submit only)
        #[arg(long, value_name = "N", default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=2))]
        delegation_depth: u64,
    },
    List {
        #[arg(long)]
        adapter: String,
    },
    Revoke {
        id: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum DeliveryCommand {
    List {
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i64).range(0..))]
        after: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=1000))]
        limit: i64,
    },
    Inspect {
        id: String,
    },
}

#[derive(Debug, clap::Args)]
pub struct UpArgs {
    /// Integration ID, or claude for claude-code
    #[arg(value_name = "HARNESS")]
    pub harness: Option<String>,
    /// Agent name; default claude (for claude-code) or the integration ID,
    /// suffixed when taken
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Project directory; default the current directory
    #[arg(long, value_name = "DIR")]
    pub directory: Option<PathBuf>,
    /// Authorization expiry; without it or --expires-in, renewable
    #[arg(long, value_name = "TIME")]
    pub expires_at: Option<String>,
    /// Relative authorization lifetime, from 1m to 720h
    #[arg(long, value_name = "DURATION")]
    pub expires_in: Option<String>,
    /// Cap on sends and delegations per hour; default 100 for a new attachment
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(i64).range(1..=10000))]
    pub max_sends_per_hour: Option<i64>,
    /// Let the agent call capabilities shared with you, and yours on your
    /// other trusted machines, without asking
    #[arg(long)]
    pub calls: bool,
    /// Do not let the agent call capabilities, without asking
    #[arg(long)]
    pub no_calls: bool,
    /// Cap on the agent's capability calls per hour, 1 to 10000; default 100
    #[arg(long, value_name = "N")]
    pub max_calls_per_hour: Option<String>,
    #[arg(long = "option", value_name = "KEY=VALUE")]
    pub options: Vec<String>,
    #[arg(long, value_name = "DIR")]
    pub integrations: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub runner: Option<PathBuf>,
    /// Stop after setup and print the result instead of launching the harness
    #[arg(long)]
    pub no_start: bool,
    /// Arguments passed to the harness at launch
    #[arg(last = true, allow_hyphen_values = true, value_name = "HARNESS_ARGS")]
    pub harness_args: Vec<String>,

    /// Create or resume a network by name
    #[arg(long, conflicts_with = "join")]
    pub create: Option<String>,
    /// Join through a private introduction (hidden prompt or --invite-stdin/file)
    #[arg(long, num_args = 0..=1, default_missing_value = "-", conflicts_with = "create")]
    pub join: Option<String>,
    /// Request same-person linking without an original key on this machine
    #[arg(long, conflicts_with_all = ["create", "join"])]
    pub link: bool,
    #[command(flatten)]
    pub invitation: crate::decentralized_onboarding_cli::InvitationInput,
    /// Person label when creating a network
    #[arg(long = "as")]
    pub person: Option<String>,
    #[arg(long)]
    pub person_key: Option<PathBuf>,
    #[arg(long, requires = "coordinator_key")]
    pub coordinator: Option<String>,
    #[arg(long, requires = "coordinator")]
    pub coordinator_key: Option<String>,
    #[arg(long, conflicts_with = "untrusted")]
    pub trusted: bool,
    #[arg(long, conflicts_with = "trusted")]
    pub untrusted: bool,
}

pub struct AdminRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
}

/// The commands the root help lists, in order; `help advanced` lists all.
pub const MAIN_COMMANDS: [&str; 20] = [
    "status",
    "up",
    "install",
    "run",
    "network create",
    "join",
    "invite",
    "attach",
    "agents",
    "send",
    "task",
    "allow",
    "deny",
    "block",
    "unblock",
    "network list",
    "network members",
    "access show",
    "session start",
    "session doctor",
];

/// The command line under `name`, the base name the binary was invoked as.
/// The root help lists only the main commands.
pub fn command_line(name: &'static str) -> clap::Command {
    let command = <Cli as clap::CommandFactory>::command()
        .name(name)
        .bin_name(name);
    let entries = MAIN_COMMANDS
        .iter()
        .map(|path| (path.to_string(), about(&command, path)))
        .collect::<Vec<_>>();
    let help = format!(
        "{}\n\nCommands:\n{}\n{}Run '{name} help advanced' to list every command.\n",
        heading(&command, name),
        listing(&entries),
        OPTIONS,
    );
    command.override_help(help)
}

/// `help advanced`: every command, as the root help listed them before.
pub fn advanced_help(name: &str) -> String {
    let mut command = <Cli as clap::CommandFactory>::command();
    command.build();
    let mut entries = Vec::new();
    leaves(&command, "", &mut entries);
    format!(
        "{}\n\nCommands:\n{}\n{}{}\nRun '{name} help COMMAND' for a command's options.\n",
        heading(&command, name),
        listing(&entries),
        OPTIONS,
        command
            .get_after_help()
            .map(|text| format!("{text}\n"))
            .unwrap_or_default(),
    )
}

const OPTIONS: &str = "Options:\n      --state <DIR>  Private state directory; otherwise use XDG_STATE_HOME or HOME\n  -h, --help         Print help\n\n";

fn heading(command: &clap::Command, name: &str) -> String {
    format!(
        "{}\n\nUsage: {name} [--state <DIR>] <COMMAND>",
        command
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default()
    )
}
fn about(command: &clap::Command, path: &str) -> String {
    let mut found = command;
    for word in path.split(' ') {
        found = found
            .find_subcommand(word)
            .expect("a listed command exists");
    }
    found
        .get_about()
        .map(ToString::to_string)
        .unwrap_or_default()
}
fn leaves(command: &clap::Command, prefix: &str, entries: &mut Vec<(String, String)>) {
    for sub in command.get_subcommands().filter(|s| s.get_name() != "help") {
        let path = format!("{prefix}{}", sub.get_name());
        if sub.has_subcommands() {
            // A group that also runs by itself, like `task TARGET TEXT`.
            if sub.is_allow_external_subcommands_set() {
                let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
                entries.push((path.clone(), about));
            }
            leaves(sub, &format!("{path} "), entries);
        } else {
            let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
            entries.push((path, about));
        }
    }
}
fn listing(entries: &[(String, String)]) -> String {
    let width = entries
        .iter()
        .map(|(path, _)| path.len())
        .max()
        .unwrap_or(0);
    entries
        .iter()
        .map(|(path, about)| format!("  {path:width$}  {about}").trim_end().to_owned() + "\n")
        .collect()
}

impl Command {
    /// The network of a command that may omit it, for the CLI to fill in
    /// when this host is in exactly one.
    pub fn network_mut(&mut self) -> Option<&mut Option<String>> {
        match self {
            // Denying a call waiting for approval names no network.
            Self::Deny { principal, .. } if approval_id(principal) => None,
            Self::Network(
                NetworkCommand::Invite { network, .. }
                | NetworkCommand::InvitePerson { network, .. }
                | NetworkCommand::Admit { network, .. }
                | NetworkCommand::Bind { network, .. }
                | NetworkCommand::Unbind { network, .. }
                | NetworkCommand::RemovePerson { network, .. }
                | NetworkCommand::RevokeInvite { network, .. }
                | NetworkCommand::DelegateAdmin { network, .. }
                | NetworkCommand::Move { network, .. }
                | NetworkCommand::Group(GroupCommand::Set { network, .. }),
            )
            | Self::Invite { network, .. }
            | Self::Agents { network, .. }
            | Self::Allow { network, .. }
            | Self::Deny { network, .. }
            | Self::Trust { network, .. }
            | Self::Untrust { network, .. }
            | Self::Share { network, .. }
            | Self::Unshare { network, .. }
            | Self::Access(
                AccessCommand::Allow { network, .. }
                | AccessCommand::Deny { network, .. }
                | AccessCommand::Renew { network, .. }
                | AccessCommand::Show { network, .. }
                | AccessCommand::Sync { network, .. },
            ) => Some(network),
            Self::Network(
                NetworkCommand::Persons { id }
                | NetworkCommand::Members { id }
                | NetworkCommand::Sync { id }
                | NetworkCommand::Groups { id },
            ) => Some(id),
            _ => None,
        }
    }

    /// Resolves `--expires-in` and fixed default expiries to RFC3339 times,
    /// so the daemon APIs are unchanged. Without an expiry, an adapter
    /// credential is renewable and a route follows its credential.
    pub fn resolve_expiries(&mut self) -> anyhow::Result<()> {
        let (expires_at, expires_in, default) = match self {
            Self::Grant(GrantCommand::Create {
                expires_at,
                expires_in,
                ..
            }) => (expires_at, expires_in, Some(TimeDelta::days(30))),
            Self::Invite {
                expires_at,
                expires_in,
                ..
            }
            | Self::Network(
                NetworkCommand::Invite {
                    expires_at,
                    expires_in,
                    ..
                }
                | NetworkCommand::InvitePerson {
                    expires_at,
                    expires_in,
                    ..
                },
            ) => (expires_at, expires_in, Some(TimeDelta::days(7))),
            Self::Adapter(
                AdapterCommand::Create {
                    expires_at,
                    expires_in,
                    ..
                }
                | AdapterCommand::Route(RouteCommand::Add {
                    expires_at,
                    expires_in,
                    ..
                }),
            )
            | Self::Session(SessionCommand::Setup {
                expires_at,
                expires_in,
                ..
            }) => (expires_at, expires_in, None),
            Self::Attach {
                expires_at,
                expires_in,
                ..
            } => (expires_at, expires_in, None),
            Self::Message(MessageCommand::Send { deadline, .. }) | Self::Send { deadline, .. } => {
                deadline.get_or_insert_with(|| after(TimeDelta::hours(1)));
                return Ok(());
            }
            _ => return Ok(()),
        };
        match (expires_at.is_some(), expires_in.take()) {
            (true, Some(_)) => bail!("--expires-at and --expires-in are mutually exclusive"),
            (false, Some(duration)) => *expires_at = Some(relative_expiry(&duration)?),
            (false, None) => *expires_at = default.map(after),
            (true, None) => {}
        }
        Ok(())
    }

    /// Run starts the daemon; every other command uses its local control socket.
    pub fn request(self) -> Option<AdminRequest> {
        let (method, path, body) = match self {
            Self::Up(_)
            | Self::Link(_)
            | Self::Network(NetworkCommand::EnableLinking { .. })
            | Self::Network(NetworkCommand::Repair(_))
            | Self::Network(NetworkCommand::RotateRoot { .. })
            | Self::Run { .. }
            | Self::Status { .. }
            | Self::Install { .. }
            | Self::Uninstall
            | Self::Help { .. }
            | Self::Session(
                SessionCommand::Setup { .. }
                | SessionCommand::Start { .. }
                | SessionCommand::Doctor { .. }
                | SessionCommand::Pending { .. },
            )
            | Self::Person(_)
            | Self::Join { .. }
            | Self::Invite { .. }
            | Self::Network(NetworkCommand::Reinvite(_))
            | Self::Allow { .. }
            | Self::Deny { .. }
            | Self::Sources(_)
            | Self::Approvals(_)
            | Self::Approve { .. }
            | Self::Capability(_)
            | Self::Share { .. }
            | Self::Shares { .. }
            | Self::Unshare { .. }
            | Self::Discover { .. }
            | Self::Call { .. }
            | Self::Trust { .. }
            | Self::Untrust { .. }
            | Self::Task(TaskCommand::Artifact { .. } | TaskCommand::To(_))
            | Self::Attach { .. }
            | Self::Agents { .. }
            | Self::Access(
                AccessCommand::Allow { .. }
                | AccessCommand::Deny { .. }
                | AccessCommand::Renew { .. },
            )
            | Self::Network(
                NetworkCommand::RedeemPerson { .. }
                | NetworkCommand::Bind { .. }
                | NetworkCommand::Unbind { .. },
            ) => return None,
            Self::Info => (Method::GET, "/v1/host".into(), None),
            Self::Calls(CallsCommand::List { after, limit }) => (
                Method::GET,
                format!("/v1/calls?after={after}&limit={limit}"),
                None,
            ),
            Self::Calls(CallsCommand::Received { after, limit }) => (
                Method::GET,
                format!("/v1/calls/received?after={after}&limit={limit}"),
                None,
            ),
            Self::Calls(CallsCommand::Inspect { peer, id }) => (
                Method::GET,
                format!("/v1/calls/{}/{}", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Calls(CallsCommand::Cancel { peer, id }) => (
                Method::POST,
                format!("/v1/calls/{}/{}/cancel", encoded(&peer), encoded(&id)),
                None,
            ),
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
            Self::Peer(PeerCommand::Add {
                id,
                public_key,
                address,
            }) => (
                Method::POST,
                "/v1/peers".into(),
                Some(json!({"id":id,"public_key":public_key,"address":address.to_string()})),
            ),
            Self::Peer(PeerCommand::List) => (Method::GET, "/v1/peers".into(), None),
            Self::Peer(PeerCommand::Path { id }) => (
                Method::GET,
                format!("/v1/peers/{}/path", encoded(&id)),
                None,
            ),
            Self::Grant(GrantCommand::Create {
                peer,
                agent,
                expires_at,
                expires_in: _,
                max_message_bytes,
                allow_disconnected,
                from_agent,
                action,
                max_artifact_bytes,
            }) => {
                let mut body = json!({"requester_host_id":peer,"target_agent_id":agent,"expires_at":expires_at,"max_message_bytes":max_message_bytes,"allow_disconnected":allow_disconnected,"action":action,"max_artifact_bytes":max_artifact_bytes});
                if let Some(agent) = from_agent {
                    body["requester_agent_id"] = json!(agent);
                }
                (Method::POST, "/v1/grants".into(), Some(body))
            }
            Self::Grant(GrantCommand::List) => (Method::GET, "/v1/grants".into(), None),
            Self::Grant(GrantCommand::Revoke { id }) => (
                Method::POST,
                format!("/v1/grants/{}/revoke", encoded(&id)),
                None,
            ),
            Self::Message(MessageCommand::Send {
                peer,
                grant,
                agent,
                deadline,
                content,
                request,
                from_agent,
                from_session,
            }) => {
                let mut body = with_grant(
                    json!({"peer_host_id":peer,"target_agent_id":agent,"deadline":deadline,"content":content,"request_id":request}),
                    grant,
                );
                if let Some(agent) = from_agent {
                    let mut origin = json!({ "agent_id": agent });
                    if let Some(session) = from_session {
                        origin["session_id"] = json!(session);
                    }
                    body["origin"] = origin;
                }
                (Method::POST, "/v1/outbound".into(), Some(body))
            }
            Self::Send {
                target,
                text,
                network,
                grant,
                from_agent,
                deadline,
            } => {
                let mut body = with_grant(
                    json!({"to": target, "content": text, "deadline": deadline, "request_id": ""}),
                    grant,
                );
                if let Some(network) = network {
                    body["network"] = json!(network);
                }
                if let Some(agent) = from_agent {
                    body["origin"] = json!({ "agent_id": agent });
                }
                (Method::POST, "/v1/outbound".into(), Some(body))
            }
            Self::Task(TaskCommand::Submit {
                peer,
                agent,
                input,
                deadline,
                grant,
                from_agent,
                from_session,
                task,
                artifacts: _,
                artifact_types: _,
                delegation_depth,
                delegate_to,
                parent_sender,
                parent_task,
            }) => {
                // Artifacts are uploaded first; see `task_submit` in main.
                let mut body = with_grant(
                    json!({"peer_host_id":peer,"target_agent_id":agent,"input":input}),
                    grant,
                );
                if let Some(deadline) = deadline {
                    body["deadline"] = json!(deadline);
                }
                if let Some(task) = task {
                    body["task_id"] = json!(task);
                }
                if let Some(agent) = from_agent {
                    let mut origin = json!({ "agent_id": agent });
                    if let Some(session) = from_session {
                        origin["session_id"] = json!(session);
                    }
                    body["origin"] = origin;
                }
                if delegation_depth > 0 {
                    body["delegation_depth"] = json!(delegation_depth);
                }
                if !delegate_to.is_empty() {
                    body["delegation_principals"] = json!(delegate_to);
                }
                if let (Some(sender), Some(task)) = (parent_sender, parent_task) {
                    body["parent"] = json!({"sender_host_id": sender, "task_id": task});
                }
                (Method::POST, "/v1/tasks".into(), Some(body))
            }
            Self::Artifact(ArtifactCommand::List) => (Method::GET, "/v1/artifacts".into(), None),
            Self::Artifact(ArtifactCommand::Prune) => {
                (Method::POST, "/v1/artifacts/prune".into(), Some(json!({})))
            }
            Self::Task(TaskCommand::List { after, limit }) => (
                Method::GET,
                format!("/v1/tasks?after={after}&limit={limit}"),
                None,
            ),
            Self::Task(TaskCommand::Inspect { peer, id }) => (
                Method::GET,
                format!("/v1/tasks/{}/{}", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Task(TaskCommand::Events { peer, id, after }) => (
                Method::GET,
                format!(
                    "/v1/tasks/{}/{}/events?after={after}&limit=1000",
                    encoded(&peer),
                    encoded(&id)
                ),
                None,
            ),
            Self::Task(TaskCommand::Cancel { peer, id }) => (
                Method::POST,
                format!("/v1/tasks/{}/{}/cancel", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Message(MessageCommand::List { after, limit }) => (
                Method::GET,
                format!("/v1/messages?after={after}&limit={limit}"),
                None,
            ),
            Self::Message(MessageCommand::Origin { peer, id }) => (
                Method::GET,
                format!("/v1/outbound/{}/{}/origin", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Message(MessageCommand::Inspect { peer, id }) => (
                Method::GET,
                format!("/v1/outbound/{}/{}", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Message(MessageCommand::Retry { peer, id }) => (
                Method::POST,
                format!("/v1/outbound/{}/{}/retry", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Message(MessageCommand::Refresh { peer, id }) => (
                Method::POST,
                format!("/v1/outbound/{}/{}/refresh", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Network(NetworkCommand::Create {
                name,
                member,
                coordinator,
                coordinator_key,
                ..
            }) => (
                Method::POST,
                "/v1/networks".into(),
                Some(
                    json!({"name":name,"member":member,"coordinator_address":coordinator,"coordinator_public_key":coordinator_key}),
                ),
            ),
            Self::Network(NetworkCommand::Invite {
                network,
                member,
                expires_at,
                host_only,
                ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/invites", encoded(resolved(&network))),
                Some(json!({"member":member,"expires_at":expires_at,"host_only":host_only})),
            ),
            Self::Network(NetworkCommand::Join {
                token, descriptor, ..
            }) => (
                Method::POST,
                "/v1/networks/join".into(),
                Some(match (token, descriptor) {
                    (Some(token), _) => json!({"token": token}),
                    (None, descriptor) => json!({"descriptor": descriptor}),
                }),
            ),
            Self::Network(NetworkCommand::Admit {
                network,
                person,
                host,
                member,
                ..
            }) => match (person, host) {
                (Some(person), _) => {
                    // A path to an OpenSSH public key file is read here; a
                    // key line is passed through for the daemon to check.
                    let key = std::fs::read_to_string(&person)
                        .map(|text| text.trim().to_owned())
                        .unwrap_or(person);
                    (
                        Method::POST,
                        format!("/v1/networks/{}/persons", encoded(resolved(&network))),
                        Some(json!({"person_public_key": key, "member": member})),
                    )
                }
                (None, host) => (
                    Method::POST,
                    format!("/v1/networks/{}/hosts", encoded(resolved(&network))),
                    Some(json!({"host_public_key": host.unwrap_or_default(), "member": member})),
                ),
            },
            Self::Network(NetworkCommand::InvitePerson {
                network,
                member,
                expires_at,
                ..
            }) => (
                Method::POST,
                format!(
                    "/v1/networks/{}/person-invites",
                    encoded(resolved(&network))
                ),
                Some(json!({"member": member, "expires_at": expires_at})),
            ),
            Self::Network(NetworkCommand::RemovePerson {
                network, person, ..
            }) => (
                Method::POST,
                format!(
                    "/v1/networks/{}/person-removals",
                    encoded(resolved(&network))
                ),
                Some(json!({"person_id": person})),
            ),
            Self::Network(NetworkCommand::Persons { id }) => (
                Method::GET,
                format!("/v1/networks/{}/persons", encoded(resolved(&id))),
                None,
            ),

            Self::Network(NetworkCommand::List) => (Method::GET, "/v2/networks".into(), None),
            Self::Network(NetworkCommand::Members { id }) => (
                Method::GET,
                format!("/v2/networks/{}/members", encoded(resolved(&id))),
                None,
            ),
            Self::Network(NetworkCommand::Sync { id }) => (
                Method::POST,
                format!("/v2/networks/{}/sync", encoded(resolved(&id))),
                Some(json!({})),
            ),
            Self::Network(NetworkCommand::Revoke { network, host, .. }) => (
                Method::POST,
                format!("/v1/networks/{}/revocations", encoded(&network)),
                Some(json!({"host_id": host})),
            ),
            Self::Network(NetworkCommand::RevokeInvite {
                network, invite, ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/revocations", encoded(resolved(&network))),
                Some(json!({"invite_public_key": invite})),
            ),
            Self::Network(NetworkCommand::Leave { id }) => (
                Method::POST,
                format!("/v1/networks/{}/leave", encoded(&id)),
                None,
            ),
            Self::Network(NetworkCommand::DelegateAdmin {
                network, person, ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/admins", encoded(resolved(&network))),
                Some(json!({"person": person})),
            ),
            Self::Network(NetworkCommand::RemoveAdmin {
                network,
                person,
                revoke_admitted,
                ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/admin-removals", encoded(&network)),
                Some(json!({"person": person, "revoke_admitted": revoke_admitted})),
            ),
            Self::Network(NetworkCommand::Group(GroupCommand::Set {
                network,
                group,
                person,
                ..
            })) => (
                Method::POST,
                format!("/v1/networks/{}/groups", encoded(resolved(&network))),
                Some(json!({"name": group, "members": person})),
            ),
            Self::Network(NetworkCommand::Move {
                network,
                coordinator,
                coordinator_key,
                ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/move", encoded(resolved(&network))),
                Some(json!({
                    "coordinator_address": coordinator,
                    "coordinator_public_key": coordinator_key,
                })),
            ),
            Self::Network(NetworkCommand::Groups { id }) => (
                Method::GET,
                format!("/v1/networks/{}/groups", encoded(resolved(&id))),
                None,
            ),
            Self::Adapter(AdapterCommand::Rotate { id }) => (
                Method::POST,
                format!("/v1/adapters/{}/rotate", encoded(&id)),
                None,
            ),
            Self::Adapter(AdapterCommand::Connection { id }) => (
                Method::GET,
                format!("/v1/adapters/{}/connection", encoded(&id)),
                None,
            ),
            Self::Adapter(AdapterCommand::Route(RouteCommand::Add {
                adapter,
                name,
                peer,
                agent,
                grant,
                expires_at,
                max_message_bytes,
                max_messages,
                action,
                delegation_depth,
                ..
            })) => (
                Method::POST,
                "/v1/adapter-routes".into(),
                Some(with_expiry(
                    with_grant(
                        json!({"adapter_id":adapter,"name":name,"peer_host_id":peer,"target_agent_id":agent,"max_message_bytes":max_message_bytes,"max_messages":max_messages,"action":action,"delegation_depth":delegation_depth}),
                        grant,
                    ),
                    expires_at,
                )),
            ),
            Self::Adapter(AdapterCommand::Route(RouteCommand::List { adapter })) => (
                Method::GET,
                format!("/v1/adapters/{}/routes", encoded(&adapter)),
                None,
            ),
            Self::Adapter(AdapterCommand::Route(RouteCommand::Revoke { id })) => (
                Method::POST,
                format!("/v1/adapter-routes/{}/revoke", encoded(&id)),
                None,
            ),
            Self::Adapter(AdapterCommand::Create {
                session,
                expires_at,
                ..
            }) => (
                Method::POST,
                "/v1/adapters".into(),
                Some(with_expiry(json!({ "session_id": session }), expires_at)),
            ),
            Self::Adapter(AdapterCommand::List) => (Method::GET, "/v1/adapters".into(), None),
            Self::Adapter(AdapterCommand::Inspect { id }) => {
                (Method::GET, format!("/v1/adapters/{}", encoded(&id)), None)
            }
            Self::Adapter(AdapterCommand::Revoke { id }) => (
                Method::POST,
                format!("/v1/adapters/{}/revoke", encoded(&id)),
                None,
            ),
            Self::Delivery(DeliveryCommand::List { after, limit }) => (
                Method::GET,
                format!("/v1/deliveries?after={after}&limit={limit}"),
                None,
            ),
            Self::Delivery(DeliveryCommand::Inspect { id }) => (
                Method::GET,
                format!("/v1/deliveries/{}", encoded(&id)),
                None,
            ),
            Self::Message(MessageCommand::Reply { peer, id }) => (
                Method::POST,
                format!("/v1/outbound/{}/{}/reply", encoded(&peer), encoded(&id)),
                None,
            ),
            Self::Access(AccessCommand::Show { network, person }) => (
                Method::GET,
                match person {
                    Some(p) => format!(
                        "/v1/networks/{}/policy?person={}",
                        encoded(resolved(&network)),
                        encoded(&p)
                    ),
                    None => format!("/v1/networks/{}/policy", encoded(resolved(&network))),
                },
                None,
            ),
            Self::Access(AccessCommand::Sync { network, status }) => (
                if status { Method::GET } else { Method::POST },
                format!("/v1/networks/{}/policy/sync", encoded(resolved(&network))),
                None,
            ),
            Self::Access(AccessCommand::Block { person, host }) => (
                Method::POST,
                "/v1/access-blocks".into(),
                Some(block_body(person, host)),
            ),
            Self::Access(AccessCommand::Unblock { person, host }) => (
                Method::POST,
                "/v1/access-blocks/remove".into(),
                Some(block_body(person, host)),
            ),
            Self::Block { target, .. } => (
                Method::POST,
                "/v1/access-blocks".into(),
                Some(target_body(&target)),
            ),
            Self::Unblock { target, .. } => (
                Method::POST,
                "/v1/access-blocks/remove".into(),
                Some(target_body(&target)),
            ),
            Self::Access(AccessCommand::Blocks) => (Method::GET, "/v1/access-blocks".into(), None),
            Self::Activity { after, limit } => (
                Method::GET,
                format!("/v1/activity?after={after}&limit={limit}"),
                None,
            ),
        };
        Some(AdminRequest { method, path, body })
    }
}

/// Sends an expiry only when one is given; otherwise the credential is
/// renewable, or the route follows it.
fn with_expiry(mut body: Value, expires_at: Option<String>) -> Value {
    if let Some(expires_at) = expires_at {
        body["expires_at"] = json!(expires_at);
    }
    body
}
fn after(duration: TimeDelta) -> String {
    (peerspan_host::clock::now() + duration).to_rfc3339_opts(SecondsFormat::Secs, true)
}
/// A network ID the CLI filled in before the request; see `network_mut`.
pub fn resolved(network: &Option<String>) -> &str {
    network.as_deref().unwrap_or_default()
}

/// Names a grant only when one is given; otherwise the daemon cites a policy.
fn with_grant(mut body: Value, grant: Option<String>) -> Value {
    if let Some(grant) = grant {
        body["grant_id"] = json!(grant);
    }
    body
}
/// `block`/`unblock TARGET`: a host ID, or else a person ID or label.
fn target_body(target: &str) -> Value {
    if target.starts_with("host_") {
        json!({ "host": target })
    } else {
        json!({ "person": target.strip_prefix("person:").unwrap_or(target) })
    }
}
fn block_body(person: Option<String>, host: Option<String>) -> Value {
    match (person, host) {
        (Some(person), _) => json!({ "person": person }),
        (None, host) => json!({ "host": host.unwrap_or_default() }),
    }
}

pub fn encoded(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn body(args: &[&str]) -> Value {
        let cli = Cli::try_parse_from([&["peerspan-host"], args].concat()).unwrap();
        cli.command.unwrap().request().unwrap().body.unwrap()
    }

    #[test]
    fn access_sync_posts_or_reads_the_status() {
        let request = |args: &[&str]| {
            let cli =
                Cli::try_parse_from([&["peerspan-host", "access", "sync"], args].concat()).unwrap();
            let r = cli.command.unwrap().request().unwrap();
            (r.method, r.path, r.body)
        };
        assert_eq!(
            request(&["--network", "net_x"]),
            (Method::POST, "/v1/networks/net_x/policy/sync".into(), None)
        );
        assert_eq!(
            request(&["--network", "net_x", "--status"]),
            (Method::GET, "/v1/networks/net_x/policy/sync".into(), None)
        );
        // Without --network the CLI fills in the only network first.
        let mut omitted = Cli::try_parse_from(["peerspan-host", "access", "sync"])
            .unwrap()
            .command
            .unwrap();
        assert_eq!(omitted.network_mut(), Some(&mut None));
    }

    #[test]
    fn networks_may_be_omitted_except_where_explicit() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["peerspan-host"], args].concat());
        for args in [
            &["network", "members"][..],
            &["network", "sync"],
            &["network", "persons"],
            &["network", "groups"],
            &["network", "invite", "--member", "m"],
            &["network", "bind"],
            &["access", "show"],
        ] {
            let mut command = parse(args).unwrap().command.unwrap();
            assert_eq!(command.network_mut(), Some(&mut None), "{args:?}");
        }
        let mut named = parse(&["network", "members", "net_x"])
            .unwrap()
            .command
            .unwrap();
        assert_eq!(named.network_mut(), Some(&mut Some("net_x".into())));
        for args in [
            &["network", "leave"][..],
            &["network", "rotate-root"],
            &["network", "revoke", "--host", "h"],
            &["network", "remove-admin", "--person", "p"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn expiries_resolve_before_requests() {
        let resolved = |args: &[&str]| {
            let mut command = Cli::try_parse_from([&["peerspan-host"], args].concat())
                .unwrap()
                .command
                .unwrap();
            command.resolve_expiries().map(|_| command)
        };
        let within = |value: &Value, key: &str, expected: TimeDelta| {
            let at = chrono::DateTime::parse_from_rfc3339(value[key].as_str().unwrap()).unwrap();
            let off = at.with_timezone(&chrono::Utc) - (peerspan_host::clock::now() + expected);
            assert!(off.abs() < TimeDelta::seconds(5), "{key}: {value}");
        };
        let grant = ["grant", "create", "--peer", "host_x", "--agent", "agent_y"];
        let body = |command: Command| command.request().unwrap().body.unwrap();
        within(
            &body(resolved(&grant).unwrap()),
            "expires_at",
            TimeDelta::days(30),
        );
        within(
            &body(resolved(&[&grant[..], &["--expires-in", "2h"]].concat()).unwrap()),
            "expires_at",
            TimeDelta::hours(2),
        );
        assert!(
            resolved(&[&grant[..], &["--expires-in", "2h", "--expires-at", "t"]].concat()).is_err()
        );
        assert!(resolved(&[&grant[..], &["--expires-in", "721h"]].concat()).is_err());
        let invite = [
            "network",
            "invite-person",
            "--network",
            "n",
            "--member",
            "m",
        ];
        within(
            &body(resolved(&invite).unwrap()),
            "expires_at",
            TimeDelta::days(7),
        );
        let send = [
            "message",
            "send",
            "--peer",
            "host_x",
            "--agent",
            "agent_y",
            "--content",
            "c",
        ];
        within(
            &body(resolved(&send).unwrap()),
            "deadline",
            TimeDelta::hours(1),
        );
        // Without an expiry, a credential is renewable and a route follows it.
        let create = body(resolved(&["adapter", "create", "--session", "s"]).unwrap());
        assert_eq!(create, json!({"session_id": "s"}));
        let route = body(
            resolved(&[
                "adapter",
                "route",
                "add",
                "--adapter",
                "a",
                "--name",
                "r",
                "--peer",
                "h",
                "--agent",
                "g",
            ])
            .unwrap(),
        );
        assert!(route.get("expires_at").is_none());
    }

    #[test]
    fn root_help_lists_the_main_commands() {
        fn listed(help: &str) -> Vec<String> {
            help.lines()
                .skip_while(|l| *l != "Commands:")
                .skip(1)
                .take_while(|l| !l.is_empty())
                .map(|l| l.trim().split("  ").next().unwrap().to_owned())
                .collect()
        }
        let help = command_line("peerspan").render_help().to_string();
        assert_eq!(listed(&help), MAIN_COMMANDS);
        assert!(!help.contains("peerspan-host"));
        assert!(
            help.trim_end()
                .lines()
                .last()
                .unwrap()
                .contains("help advanced")
        );
        let advanced = listed(&advanced_help("peerspan"));
        for path in
            MAIN_COMMANDS
                .iter()
                .chain(&["grant create", "network group set", "activity", "info"])
        {
            assert!(advanced.iter().any(|p| p == path), "{path}");
        }
    }

    #[test]
    fn message_send_carries_origin_only_when_named() {
        let send = [
            "message",
            "send",
            "--peer",
            "host_x",
            "--agent",
            "agent_y",
            "--deadline",
            "d",
            "--content",
            "c",
        ];
        assert!(body(&send).get("origin").is_none());
        let with_agent = body(&[&send[..], &["--from-agent", "agent_a"]].concat());
        assert_eq!(with_agent["origin"], json!({"agent_id": "agent_a"}));
        let with_session = body(
            &[
                &send[..],
                &["--from-agent", "agent_a", "--from-session", "session_s"],
            ]
            .concat(),
        );
        assert_eq!(
            with_session["origin"],
            json!({"agent_id": "agent_a", "session_id": "session_s"})
        );
        // A session alone names no agent.
        assert!(
            Cli::try_parse_from(
                [
                    &["peerspan-host"],
                    &send[..],
                    &["--from-session", "session_s"]
                ]
                .concat()
            )
            .is_err()
        );
    }

    #[test]
    fn grant_create_names_a_requester_agent_only_when_given() {
        let create = [
            "grant",
            "create",
            "--peer",
            "host_x",
            "--agent",
            "agent_y",
            "--expires-at",
            "e",
        ];
        assert!(body(&create).get("requester_agent_id").is_none());
        assert_eq!(body(&create)["action"], "message.append");
        assert_eq!(
            body(&[&create[..], &["--action", "task.submit"]].concat())["action"],
            "task.submit"
        );
        assert!(
            Cli::try_parse_from(
                [&["peerspan-host"], &create[..], &["--action", "shell.exec"]].concat()
            )
            .is_err()
        );
        assert_eq!(
            body(&[&create[..], &["--from-agent", "agent_a"]].concat())["requester_agent_id"],
            "agent_a"
        );
    }

    #[test]
    fn artifact_flags_map_to_the_local_api() {
        let create = [
            "grant",
            "create",
            "--peer",
            "host_x",
            "--agent",
            "agent_y",
            "--expires-at",
            "e",
            "--action",
            "task.submit",
        ];
        assert_eq!(body(&create)["max_artifact_bytes"], 0);
        assert_eq!(
            body(&[&create[..], &["--max-artifact-bytes", "1048576"]].concat())["max_artifact_bytes"],
            1048576
        );
        for bad in ["-1", "1073741825"] {
            assert!(
                Cli::try_parse_from(
                    [
                        &["peerspan-host"],
                        &create[..],
                        &["--max-artifact-bytes", bad]
                    ]
                    .concat()
                )
                .is_err()
            );
        }
        let path = |args: &[&str]| {
            let cli = Cli::try_parse_from([&["peerspan-host"], args].concat()).unwrap();
            let request = cli.command.unwrap().request().unwrap();
            (request.method, request.path)
        };
        assert_eq!(
            path(&["artifact", "list"]),
            (Method::GET, "/v1/artifacts".into())
        );
        assert_eq!(
            path(&["artifact", "prune"]),
            (Method::POST, "/v1/artifacts/prune".into())
        );
        let submit = Cli::try_parse_from([
            "peerspan-host",
            "task",
            "submit",
            "--peer",
            "host_x",
            "--agent",
            "agent_y",
            "--input",
            "i",
            "--artifact",
            "a.txt",
            "--artifact",
            "b.bin",
            "--artifact-type",
            "text/plain",
        ])
        .unwrap();
        let Some(Command::Task(TaskCommand::Submit {
            artifacts,
            artifact_types,
            ..
        })) = submit.command
        else {
            panic!("not a submission")
        };
        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifact_types, ["text/plain"]);
        let saved = Cli::try_parse_from([
            "peerspan-host",
            "task",
            "artifact",
            "--peer",
            "host_x",
            "task_t",
            "abc",
            "--out",
            "out.bin",
        ])
        .unwrap();
        assert!(saved.command.unwrap().request().is_none());
        let run =
            Cli::try_parse_from(["peerspan-host", "run", "--artifact-quota", "1024"]).unwrap();
        assert!(matches!(
            run.command,
            Some(Command::Run {
                artifact_quota: 1024,
                ..
            })
        ));
        assert!(Cli::try_parse_from(["peerspan-host", "run", "--artifact-quota", "0"]).is_err());
    }

    #[test]
    fn task_commands_map_to_the_local_api() {
        let submit = [
            "task", "submit", "--peer", "host_x", "--agent", "agent_y", "--input", "do it",
        ];
        let cli = Cli::try_parse_from([&["peerspan-host"], &submit[..]].concat()).unwrap();
        let request = cli.command.unwrap().request().unwrap();
        assert_eq!(request.path, "/v1/tasks");
        let plain = request.body.unwrap();
        assert_eq!(
            plain,
            json!({"peer_host_id": "host_x", "target_agent_id": "agent_y", "input": "do it"})
        );
        let full = body(
            &[
                &submit[..],
                &[
                    "--deadline",
                    "2026-10-10T00:00:00Z",
                    "--grant",
                    "grant_g",
                    "--from-agent",
                    "agent_a",
                    "--from-session",
                    "session_s",
                    "--task",
                    "task_t",
                ],
            ]
            .concat(),
        );
        assert_eq!(full["deadline"], "2026-10-10T00:00:00Z");
        assert_eq!(full["grant_id"], "grant_g");
        assert_eq!(full["task_id"], "task_t");
        assert_eq!(
            full["origin"],
            json!({"agent_id": "agent_a", "session_id": "session_s"})
        );
        let path = |args: &[&str]| {
            let cli = Cli::try_parse_from([&["peerspan-host"], args].concat()).unwrap();
            let r = cli.command.unwrap().request().unwrap();
            (r.method, r.path)
        };
        assert_eq!(
            path(&["task", "inspect", "--peer", "host_x", "task_t"]),
            (Method::GET, "/v1/tasks/host_x/task_t".into())
        );
        assert_eq!(
            path(&[
                "task", "events", "--peer", "host_x", "task_t", "--after", "3"
            ]),
            (
                Method::GET,
                "/v1/tasks/host_x/task_t/events?after=3&limit=1000".into()
            )
        );
        assert_eq!(
            path(&["task", "cancel", "--peer", "host_x", "task_t"]),
            (Method::POST, "/v1/tasks/host_x/task_t/cancel".into())
        );
        assert_eq!(
            path(&["task", "list"]),
            (Method::GET, "/v1/tasks?after=0&limit=100".into())
        );
        let route = [
            "adapter",
            "route",
            "add",
            "--adapter",
            "adapter_a",
            "--name",
            "r",
            "--peer",
            "host_x",
            "--agent",
            "agent_y",
            "--expires-at",
            "e",
        ];
        assert_eq!(body(&route)["action"], "message.append");
        assert_eq!(
            body(&[&route[..], &["--action", "task.submit"]].concat())["action"],
            "task.submit"
        );
        assert_eq!(body(&route)["delegation_depth"], 0);
        assert_eq!(
            body(&[&route[..], &["--delegation-depth", "2"]].concat())["delegation_depth"],
            2
        );
        let parse = |args: &[&str]| Cli::try_parse_from([&["peerspan-host"], args].concat());
        assert!(parse(&[&route[..], &["--delegation-depth", "3"]].concat()).is_err());
        assert!(parse(&[&route[..], &["--action", "task.delegate"]].concat()).is_err());
    }

    #[test]
    fn delegation_flags_map_to_the_local_api() {
        let submit = [
            "task", "submit", "--peer", "host_x", "--agent", "agent_y", "--input", "do it",
        ];
        let plain = body(&submit);
        for key in ["delegation_depth", "delegation_principals", "parent"] {
            assert!(plain.get(key).is_none(), "{key}");
        }
        let chained = body(
            &[
                &submit[..],
                &[
                    "--delegation-depth",
                    "2",
                    "--delegate-to",
                    "network",
                    "--delegate-to",
                    "host:host_z",
                ],
            ]
            .concat(),
        );
        assert_eq!(chained["delegation_depth"], 2);
        assert_eq!(
            chained["delegation_principals"],
            json!(["network", "host:host_z"])
        );
        let forward = body(
            &[
                &submit[..],
                &["--parent-sender", "host_p", "--parent-task", "task_p"],
            ]
            .concat(),
        );
        assert_eq!(
            forward["parent"],
            json!({"sender_host_id": "host_p", "task_id": "task_p"})
        );
        let parse =
            |args: &[&str]| Cli::try_parse_from([&["peerspan-host"], &submit[..], args].concat());
        assert!(parse(&["--delegation-depth", "3"]).is_err());
        assert!(parse(&["--parent-sender", "host_p"]).is_err());
        assert!(parse(&["--parent-task", "task_p"]).is_err());
        assert!(
            parse(&[
                "--parent-sender",
                "host_p",
                "--parent-task",
                "task_p",
                "--delegation-depth",
                "1"
            ])
            .is_err()
        );
        let grant = [
            "grant",
            "create",
            "--peer",
            "host_x",
            "--agent",
            "agent_y",
            "--expires-at",
            "e",
        ];
        assert_eq!(
            body(&[&grant[..], &["--action", "task.delegate"]].concat())["action"],
            "task.delegate"
        );
        assert!(
            Cli::try_parse_from(
                [
                    &["peerspan-host"][..],
                    &[
                        "access",
                        "allow",
                        "--network",
                        "net_x",
                        "--agent",
                        "a",
                        "--principal",
                        "network",
                        "--action",
                        "task.delegate"
                    ]
                ]
                .concat()
            )
            .is_ok()
        );
    }
}
