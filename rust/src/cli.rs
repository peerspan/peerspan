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
        /// ssh-agent socket used to renew this host's person's access
        /// policy; defaults to SSH_AUTH_SOCK
        #[arg(long, value_name = "SOCKET")]
        person_agent: Option<PathBuf>,
    },
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
    /// Delegate tasks to remote agents and follow their progress
    #[command(subcommand)]
    Task(TaskCommand),
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
    /// Prepare an opted-in session using an installed harness integration
    Setup {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long, requires_all=["agent","expires_at"])]
        harness: Option<String>,
        #[arg(long, requires_all=["harness","expires_at"])]
        agent: Option<String>,
        #[arg(long, requires_all=["agent","harness"])]
        expires_at: Option<String>,
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
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(last = true, allow_hyphen_values = true)]
        harness_args: Vec<String>,
    },
    /// Inspect session and integration readiness without changing state
    Doctor {
        #[arg(long)]
        directory: PathBuf,
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
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
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
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Issue a one-time person invite token (administrator only)
    InvitePerson {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long)]
        member: String,
        #[arg(long, value_name = "TIME")]
        expires_at: String,
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
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
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
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Revoke an invite, and any host that joined with it (administrator only)
    RevokeInvite {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long, value_name = "INVITE_PUBLIC_KEY")]
        invite: String,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Leave a network; takes effect locally even if coordination is down
    Leave { id: String },
    /// Rotate the network root key and re-attest current members (root only)
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
        network: String,
        /// Person ID or label
        #[arg(long)]
        person: String,
        /// The SSH root key, when this host does not hold the root seed
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
    },
    /// Remove an administrator, permanently (root only)
    RemoveAdmin {
        #[arg(long, value_name = "ID")]
        network: String,
        /// Person ID or label
        #[arg(long)]
        person: String,
        /// Also invalidate everything that administrator signed
        #[arg(long)]
        revoke_admitted: bool,
        /// The SSH root key, when this host does not hold the root seed
        #[arg(long, value_name = "PATH")]
        root_key: Option<PathBuf>,
    },
    /// Define groups of persons (administrator or root)
    #[command(subcommand)]
    Group(GroupCommand),
    /// List a network's current groups
    Groups { id: String },
}
#[derive(Debug, Subcommand)]
pub enum GroupCommand {
    /// Set a group's persons; with no --person, delete the group
    Set {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long, value_name = "NAME")]
        group: String,
        /// Person ID or label; repeat for each member
        #[arg(long)]
        person: Vec<String>,
        /// Person key for signing as an administrator, when this host does
        /// not hold the root seed and the agent holds several keys
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
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
        /// Authorize only requests whose origin is this agent of the peer
        #[arg(long, value_name = "AGENT_ID")]
        from_agent: Option<String>,
        /// What the grant authorizes
        #[arg(long, value_parser = ["message.append", "task.submit"], default_value = "message.append")]
        action: String,
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
        network: String,
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
        #[arg(long = "action", value_name = "ACTION", value_parser = ["message.append", "task.submit"])]
        actions: Vec<String>,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Remove principals from an agent's rule, or the whole rule
    Deny {
        #[arg(long, value_name = "ID")]
        network: String,
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
        network: String,
        #[arg(long, value_name = "PATH")]
        person_key: Option<PathBuf>,
    },
    /// Show a person's newest verified policy (yours by default)
    Show {
        #[arg(long, value_name = "ID")]
        network: String,
        #[arg(long)]
        person: Option<String>,
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
    Send {
        #[arg(long)]
        peer: String,
        /// Grant ID; otherwise cite the target owner's policy
        #[arg(long)]
        grant: Option<String>,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        deadline: String,
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
        /// Grant ID; otherwise cite the target owner's policy
        #[arg(long)]
        grant: Option<String>,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(i64).range(1..=65536))]
        max_message_bytes: i64,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(i64).range(1..=10000))]
        max_messages: i64,
        /// What the route sends: messages or tasks
        #[arg(long, value_parser = ["message.append", "task.submit"], default_value = "message.append")]
        action: String,
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
            | Self::Session(
                SessionCommand::Setup { .. }
                | SessionCommand::Start { .. }
                | SessionCommand::Doctor { .. },
            )
            | Self::Person(_)
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
                from_agent,
                action,
            }) => {
                let mut body = json!({"requester_host_id":peer,"target_agent_id":agent,"expires_at":expires_at,"max_message_bytes":max_message_bytes,"allow_disconnected":allow_disconnected,"action":action});
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
            Self::Task(TaskCommand::Submit {
                peer,
                agent,
                input,
                deadline,
                grant,
                from_agent,
                from_session,
                task,
            }) => {
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
                (Method::POST, "/v1/tasks".into(), Some(body))
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
                ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/person-invites", encoded(&network)),
                Some(json!({"member": member, "expires_at": expires_at})),
            ),
            Self::Network(NetworkCommand::RemovePerson {
                network, person, ..
            }) => (
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
            Self::Network(NetworkCommand::Revoke { network, host, .. }) => (
                Method::POST,
                format!("/v1/networks/{}/revocations", encoded(&network)),
                Some(json!({"host_id": host})),
            ),
            Self::Network(NetworkCommand::RevokeInvite {
                network, invite, ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/revocations", encoded(&network)),
                Some(json!({"invite_public_key": invite})),
            ),
            Self::Network(NetworkCommand::Leave { id }) => (
                Method::POST,
                format!("/v1/networks/{}/leave", encoded(&id)),
                None,
            ),
            Self::Network(NetworkCommand::RotateRoot { id, .. }) => (
                Method::POST,
                format!("/v1/networks/{}/rotate", encoded(&id)),
                None,
            ),
            Self::Network(NetworkCommand::DelegateAdmin {
                network, person, ..
            }) => (
                Method::POST,
                format!("/v1/networks/{}/admins", encoded(&network)),
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
                format!("/v1/networks/{}/groups", encoded(&network)),
                Some(json!({"name": group, "members": person})),
            ),
            Self::Network(NetworkCommand::Groups { id }) => (
                Method::GET,
                format!("/v1/networks/{}/groups", encoded(&id)),
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
            })) => (
                Method::POST,
                "/v1/adapter-routes".into(),
                Some(with_grant(
                    json!({"adapter_id":adapter,"name":name,"peer_host_id":peer,"target_agent_id":agent,"expires_at":expires_at,"max_message_bytes":max_message_bytes,"max_messages":max_messages,"action":action}),
                    grant,
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
            Self::Access(AccessCommand::Show { network, person }) => (
                Method::GET,
                match person {
                    Some(p) => format!(
                        "/v1/networks/{}/policy?person={}",
                        encoded(&network),
                        encoded(&p)
                    ),
                    None => format!("/v1/networks/{}/policy", encoded(&network)),
                },
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

/// Names a grant only when one is given; otherwise the daemon cites a policy.
fn with_grant(mut body: Value, grant: Option<String>) -> Value {
    if let Some(grant) = grant {
        body["grant_id"] = json!(grant);
    }
    body
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
        let cli = Cli::try_parse_from([&["capsule-host"], args].concat()).unwrap();
        cli.command.unwrap().request().unwrap().body.unwrap()
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
                    &["capsule-host"],
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
                [&["capsule-host"], &create[..], &["--action", "shell.exec"]].concat()
            )
            .is_err()
        );
        assert_eq!(
            body(&[&create[..], &["--from-agent", "agent_a"]].concat())["requester_agent_id"],
            "agent_a"
        );
    }

    #[test]
    fn task_commands_map_to_the_local_api() {
        let submit = [
            "task", "submit", "--peer", "host_x", "--agent", "agent_y", "--input", "do it",
        ];
        let cli = Cli::try_parse_from([&["capsule-host"], &submit[..]].concat()).unwrap();
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
            let cli = Cli::try_parse_from([&["capsule-host"], args].concat()).unwrap();
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
    }
}
