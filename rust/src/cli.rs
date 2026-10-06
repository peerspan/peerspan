use clap::{Parser, Subcommand};
use hyper::Method;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "capsule-host",
    about = "Run and control a local Capsule host daemon",
    after_help = "Session attachment records metadata; a scoped adapter connects an opted-in session."
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
    Run {
        /// Opt-in peer bind address
        #[arg(long, value_name = "IP:PORT")]
        peer_listen: Option<std::net::SocketAddr>,
        /// Peer address advertised to coordination; defaults to a specific bind address
        #[arg(long, value_name = "IP:PORT", requires = "peer_listen")]
        advertise: Option<std::net::SocketAddr>,
        /// Seconds between coordination syncs
        #[arg(long, value_name = "SECONDS", default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
        coordination_interval: u64,
    },
    /// Show the local daemon's public identity
    Info,
    /// Prepare, launch, or diagnose an opted-in Claude Code session
    #[command(subcommand)]
    Claude(ClaudeCommand),
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
    /// Submit messages and inspect durable host receipts
    #[command(subcommand)]
    Message(MessageCommand),
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
}

#[derive(Debug, Subcommand)]
pub enum ClaudeCommand {
    /// Create private MCP configuration and an owner-authorized attachment
    Setup {
        #[command(flatten)]
        runtime: ClaudeRuntime,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        channel: PathBuf,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        routes: Option<PathBuf>,
    },
    /// Launch a prepared session, or prepare and launch one with --agent
    Start {
        #[command(flatten)]
        runtime: ClaudeRuntime,
        #[arg(long, requires_all = ["channel", "expires_at"])]
        agent: Option<String>,
        #[arg(long, requires = "agent")]
        channel: Option<PathBuf>,
        #[arg(long, requires = "agent")]
        expires_at: Option<String>,
        #[arg(long, requires = "agent")]
        routes: Option<PathBuf>,
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// Additional Claude arguments after --; Capsule channel options cannot be overridden
        #[arg(last = true, allow_hyphen_values = true)]
        claude_args: Vec<String>,
    },
    /// Inspect setup and adapter readiness without establishing a lease
    Doctor {
        #[command(flatten)]
        runtime: ClaudeRuntime,
    },
}

#[derive(Debug, clap::Args)]
pub struct ClaudeRuntime {
    /// Private setup directory
    #[arg(long)]
    pub directory: PathBuf,
    /// Node 22+ executable
    #[arg(long)]
    pub node: Option<PathBuf>,
    /// Claude Code executable
    #[arg(long)]
    pub claude: Option<PathBuf>,
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

#[derive(Debug, Subcommand)]
pub enum NetworkCommand {
    /// Create a network whose root key stays on this host
    Create {
        #[arg(long)]
        name: String,
        /// Member label for this host's own membership
        #[arg(long)]
        member: String,
        /// Coordinator HOST:PORT
        #[arg(long, value_name = "HOST:PORT")]
        coordinator: String,
        /// Independently verified coordinator public key
        #[arg(long, value_name = "BASE64")]
        coordinator_key: String,
        /// Person key: an OpenSSH public key (select an ssh-agent identity) or
        /// unencrypted private key file; default is the agent's only ssh-ed25519 key
        #[arg(long, value_name = "PATH", conflicts_with = "no_person")]
        person_key: Option<PathBuf>,
        /// Do not admit or bind a person
        #[arg(long)]
        no_person: bool,
    },
    /// Issue a one-time invite token (administrator only). By default a member
    /// invite, which also admits the joiner's person and binds the host.
    Invite {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long)]
        member: String,
        #[arg(long, value_name = "TIME")]
        expires_at: String,
        /// Issue a host-only invite
        #[arg(long)]
        host_only: bool,
    },
    /// Join a network with an invite token or, if an administrator admitted
    /// this host's key, a network descriptor
    Join {
        #[arg(
            long,
            required_unless_present = "descriptor",
            conflicts_with = "descriptor"
        )]
        token: Option<String>,
        #[arg(long)]
        descriptor: Option<String>,
        /// Person key: an OpenSSH public key (select an ssh-agent identity) or
        /// unencrypted private key file; default is the agent's only ssh-ed25519 key
        #[arg(long, value_name = "PATH", conflicts_with = "no_person")]
        person_key: Option<PathBuf>,
        /// Do not admit or bind a person
        #[arg(long)]
        no_person: bool,
    },
    /// Admit a person or a host by public key (administrator only)
    Admit {
        #[arg(long, value_name = "ID")]
        network: String,
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
    },
    /// Issue a one-time person invite token (administrator only)
    InvitePerson {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long)]
        member: String,
        #[arg(long, value_name = "TIME")]
        expires_at: String,
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
        network: String,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Unbind one of your hosts; signed with your person key
    Unbind {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long, value_name = "HOST_ID")]
        host: String,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Remove a person and end its bindings (administrator only)
    RemovePerson {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long, value_name = "PERSON_ID")]
        person: String,
    },
    /// List a network's persons and the hosts bound to them
    Persons { id: String },
    /// List networks
    List,
    /// List a network's verified members
    Members { id: String },
    /// Register or sync a network now
    Sync { id: String },
    /// Revoke a member host's membership (administrator only)
    Revoke {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long, value_name = "HOST_ID")]
        host: String,
    },
    /// Revoke an invite, and any host that joined with it (administrator only)
    RevokeInvite {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long, value_name = "INVITE_PUBLIC_KEY")]
        invite: String,
    },
    /// Leave a network; takes effect locally even if coordination is down
    Leave { id: String },
    /// Rotate the network root key and re-attest current members (administrator only)
    RotateRoot { id: String },
}
#[derive(Debug, Subcommand)]
pub enum GrantCommand {
    Create {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(i64).range(1..=65536))]
        max_message_bytes: i64,
        #[arg(long)]
        allow_disconnected: bool,
    },
    List,
    Revoke {
        id: String,
    },
}
#[derive(Debug, Subcommand)]
pub enum MessageCommand {
    Origin {
        #[arg(long)]
        peer: String,
        id: String,
    },
    Send {
        #[arg(long)]
        peer: String,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        deadline: String,
        #[arg(long)]
        content: String,
        #[arg(long, default_value = "")]
        request: String,
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
        #[arg(long)]
        expires_at: String,
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
        #[arg(long)]
        grant: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(i64).range(1..=65536))]
        max_message_bytes: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=10000))]
        max_messages: i64,
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

pub struct AdminRequest {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
}

impl Command {
    /// Run starts the daemon; every other command uses its local control socket.
    pub fn request(self) -> Option<AdminRequest> {
        let (method, path, body) = match self {
            Self::Run { .. }
            | Self::Claude(_)
            | Self::Person(_)
            | Self::Network(
                NetworkCommand::RedeemPerson { .. }
                | NetworkCommand::Bind { .. }
                | NetworkCommand::Unbind { .. },
            ) => return None,
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
                max_message_bytes,
                allow_disconnected,
            }) => (
                Method::POST,
                "/v1/grants".into(),
                Some(
                    json!({"requester_host_id":peer,"target_agent_id":agent,"expires_at":expires_at,"max_message_bytes":max_message_bytes,"allow_disconnected":allow_disconnected}),
                ),
            ),
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
            }) => (
                Method::POST,
                "/v1/outbound".into(),
                Some(
                    json!({"peer_host_id":peer,"grant_id":grant,"target_agent_id":agent,"deadline":deadline,"content":content,"request_id":request}),
                ),
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
            }) => (
                Method::POST,
                format!("/v1/networks/{}/invites", encoded(&network)),
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
            }) => match (person, host) {
                (Some(person), _) => {
                    // A path to an OpenSSH public key file is read here; a
                    // key line is passed through for the daemon to check.
                    let key = std::fs::read_to_string(&person)
                        .map(|text| text.trim().to_owned())
                        .unwrap_or(person);
                    (
                        Method::POST,
                        format!("/v1/networks/{}/persons", encoded(&network)),
                        Some(json!({"person_public_key": key, "member": member})),
                    )
                }
                (None, host) => (
                    Method::POST,
                    format!("/v1/networks/{}/hosts", encoded(&network)),
                    Some(json!({"host_public_key": host.unwrap_or_default(), "member": member})),
                ),
            },
            Self::Network(NetworkCommand::InvitePerson {
                network,
                member,
                expires_at,
            }) => (
                Method::POST,
                format!("/v1/networks/{}/person-invites", encoded(&network)),
                Some(json!({"member": member, "expires_at": expires_at})),
            ),
            Self::Network(NetworkCommand::RemovePerson { network, person }) => (
                Method::POST,
                format!("/v1/networks/{}/person-removals", encoded(&network)),
                Some(json!({"person_id": person})),
            ),
            Self::Network(NetworkCommand::Persons { id }) => (
                Method::GET,
                format!("/v1/networks/{}/persons", encoded(&id)),
                None,
            ),

            Self::Network(NetworkCommand::List) => (Method::GET, "/v1/networks".into(), None),
            Self::Network(NetworkCommand::Members { id }) => (
                Method::GET,
                format!("/v1/networks/{}/members", encoded(&id)),
                None,
            ),
            Self::Network(NetworkCommand::Sync { id }) => (
                Method::POST,
                format!("/v1/networks/{}/sync", encoded(&id)),
                None,
            ),
            Self::Network(NetworkCommand::Revoke { network, host }) => (
                Method::POST,
                format!("/v1/networks/{}/revocations", encoded(&network)),
                Some(json!({"host_id": host})),
            ),
            Self::Network(NetworkCommand::RevokeInvite { network, invite }) => (
                Method::POST,
                format!("/v1/networks/{}/revocations", encoded(&network)),
                Some(json!({"invite_public_key": invite})),
            ),
            Self::Network(NetworkCommand::Leave { id }) => (
                Method::POST,
                format!("/v1/networks/{}/leave", encoded(&id)),
                None,
            ),
            Self::Network(NetworkCommand::RotateRoot { id }) => (
                Method::POST,
                format!("/v1/networks/{}/rotate", encoded(&id)),
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
            })) => (
                Method::POST,
                "/v1/adapter-routes".into(),
                Some(
                    json!({"adapter_id":adapter,"name":name,"peer_host_id":peer,"target_agent_id":agent,"grant_id":grant,"expires_at":expires_at,"max_message_bytes":max_message_bytes,"max_messages":max_messages}),
                ),
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
            }) => (
                Method::POST,
                "/v1/adapters".into(),
                Some(json!({"session_id":session,"expires_at":expires_at})),
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
            Self::Activity { after, limit } => (
                Method::GET,
                format!("/v1/activity?after={after}&limit={limit}"),
                None,
            ),
        };
        Some(AdminRequest { method, path, body })
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
