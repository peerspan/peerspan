package main

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/spf13/cobra"
)

func newCommand(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use: "capsule-host", Short: "Run and control a local Capsule host daemon",
		Long: `Run and control a local Capsule host daemon.

Person keys are ssh-ed25519 keys in ssh-agent (SSH_AUTH_SOCK), or --person-key
PATH naming a public key in the agent or an unencrypted OpenSSH private key file.
A host holding the network's root seed signs administration as the root;
otherwise the CLI signs with the person key in ssh-agent, which must be a
current administrator. Root-only commands without the seed use --root-key PATH.
PERSON is a person ID or label. An access policy, signed by the agents' owner,
lets principals (person:PERSON, group:NAME, or network) message the owner's
agents by name without a grant; the daemon renews it through the ssh-agent at
--person-agent. Blocks are host-local and override grants and policies.
Without --grant, message send, task submit, and adapter routes cite the receiver
owner's policy. Grants, policy rules, and routes carry an action: message.append
(the default) or task.submit. Task submissions are retried and their events
polled automatically; task inspect and task events read the local record.
Task artifacts are off unless the receiver's grant or policy rule for
task.submit sets --max-artifact-bytes, which bounds a task's input and result
files together. --artifact uploads a file named after its base name; the
i-th --artifact-type is the i-th file's media type. Received files count
toward the daemon's --artifact-quota (default 10 GiB) and are kept 7 days
after their task finishes; artifact prune releases finished tasks now.
The serve command is a compatibility alias for run.
Session attachment records metadata; a scoped adapter connects an opted-in session.
`,
		SilenceUsage: true, SilenceErrors: true,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	root.SetOut(out)
	root.SetErr(errOut)
	root.CompletionOptions.DisableDefaultCmd = true
	var state string
	root.PersistentFlags().StringVar(&state, "state", "", "private state directory; defaults to XDG_STATE_HOME or HOME")
	groups := map[string]*cobra.Command{"": root}
	add := func(path, use, short string, count int) *cobra.Command {
		parts := strings.Split(path, " ")
		parent := root
		for i, name := range parts[:len(parts)-1] {
			key := strings.Join(parts[:i+1], " ")
			group := groups[key]
			if group == nil {
				group = &cobra.Command{Use: name, Short: "Manage " + key, Args: cobra.NoArgs,
					RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() }}
				groups[key] = group
				parent.AddCommand(group)
			}
			parent = group
		}
		cmd := &cobra.Command{Use: use, Short: short, Args: cobra.ExactArgs(count)}
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			return execute(cmd.Context(), append(append([]string{}, parts...), args...), cmd.Flags(), state, cmd.OutOrStdout(), cmd.ErrOrStderr())
		}
		configureFlags(cmd, parts)
		parent.AddCommand(cmd)
		return cmd
	}
	add("run", "run", "Run the host daemon in the foreground", 0).Aliases = []string{"serve"}
	add("info", "info", "Show the local daemon's public identity", 0)
	add("agent register", "register", "Register a local agent", 0)
	add("agent list", "list", "List registered agents", 0)
	add("agent inspect", "inspect ID", "Inspect an agent", 1)
	add("session setup", "setup", "Prepare or recover an opted-in session", 0)
	start := add("session start", "start [-- HARNESS_ARGS...]", "Launch a prepared session", 0)
	start.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && cmd.Flags().ArgsLenAtDash() != 0 {
			return errors.New("harness arguments require session start and a -- separator")
		}
		return nil
	}
	add("session doctor", "doctor", "Inspect session readiness", 0)
	add("session attach", "attach", "Record a session attachment", 0)
	add("session list", "list", "List session records", 0)
	add("session inspect", "inspect ID", "Inspect a session", 1)
	add("session detach", "detach ID", "Detach a session", 1)
	add("peer add", "add", "Configure an owner-verified peer", 0)
	add("peer list", "list", "List peers", 0)
	add("peer path", "path HOST", "Show a peer's active network path", 1)
	add("grant create", "create", "Issue a receiver-owned grant", 0)
	add("grant list", "list", "List grants", 0)
	add("grant revoke", "revoke ID", "Revoke a grant", 1)
	add("message send", "send", "Send a message to a remote agent", 0)
	add("message list", "list", "List durable message receipts", 0)
	add("message inspect", "inspect ID", "Inspect a message receipt", 1)
	add("message retry", "retry ID", "Retry an outbound message", 1)
	add("message refresh", "refresh ID", "Refresh a remote message receipt", 1)
	add("message reply", "reply ID", "Fetch a remote reply", 1)
	add("message origin", "origin ID", "Inspect a message's origin", 1)
	add("task submit", "submit", "Delegate a task to a remote agent", 0)
	add("task list", "list", "List task records", 0)
	add("task inspect", "inspect ID", "Inspect a task", 1)
	add("task cancel", "cancel ID", "Cancel a task", 1)
	add("task events", "events ID", "Read task events", 1)
	add("task artifact", "artifact ID SHA256", "Download a task artifact", 2)
	add("artifact list", "list", "List stored artifacts", 0)
	add("artifact prune", "prune", "Release artifacts of finished tasks", 0)
	add("network create", "create", "Create a coordinated network", 0)
	add("network join", "join", "Join a coordinated network", 0)
	add("network invite", "invite", "Issue a member or host invite", 0)
	add("network list", "list", "List joined networks", 0)
	add("network members", "members ID", "List network members", 1)
	add("network sync", "sync ID", "Sync a network with coordination", 1)
	add("network revoke", "revoke", "Revoke a host membership", 0)
	add("network revoke-invite", "revoke-invite", "Revoke an invite", 0)
	add("network leave", "leave ID", "Leave a network", 1)
	add("network rotate-root", "rotate-root ID", "Rotate the network root key", 1)
	add("network admit", "admit", "Admit a person or host", 0)
	add("network invite-person", "invite-person", "Issue a person invite", 0)
	add("network redeem-person", "redeem-person", "Redeem a person invite", 0)
	add("network bind", "bind", "Bind this host to a person", 0)
	add("network unbind", "unbind", "Unbind a host from a person", 0)
	add("network remove-person", "remove-person", "Remove a person", 0)
	add("network persons", "persons ID", "List network persons", 1)
	add("network delegate-admin", "delegate-admin", "Delegate network administration", 0)
	add("network remove-admin", "remove-admin", "Remove an administrator", 0)
	add("network group set", "set", "Set or delete a group", 0)
	add("network groups", "groups ID", "List network groups", 1)
	add("access allow", "allow", "Allow access to an owner's agent", 0)
	add("access deny", "deny", "Withdraw access to an owner's agent", 0)
	add("access renew", "renew", "Renew the owner access policy", 0)
	add("access show", "show", "Show an owner access policy", 0)
	add("access block", "block", "Block a person or host locally", 0)
	add("access unblock", "unblock", "Remove a local access block", 0)
	add("access blocks", "blocks", "List local access blocks", 0)
	add("person show", "show", "Show the signing person identity", 0)
	add("adapter create", "create", "Issue a session credential", 0)
	add("adapter list", "list", "List session credentials", 0)
	add("adapter inspect", "inspect ID", "Inspect a credential", 1)
	add("adapter revoke", "revoke ID", "Revoke a credential", 1)
	add("adapter rotate", "rotate ID", "Rotate a credential token", 1)
	add("adapter connection", "connection ID", "Inspect an adapter connection", 1)
	add("adapter route add", "add", "Configure an outbound destination", 0)
	add("adapter route list", "list", "List adapter destinations", 0)
	add("adapter route revoke", "revoke ID", "Revoke an outbound destination", 1)
	add("delivery list", "list", "List durable adapter handoffs", 0)
	add("delivery inspect", "inspect ID", "Inspect an adapter handoff", 1)
	add("activity", "activity", "Read the local activity log", 0)
	return root
}

func configureFlags(cmd *cobra.Command, args []string) {
	fs := cmd.Flags()
	command := args[len(args)-1]
	if args[0] == "network" {
		switch command {
		case "create", "join", "redeem-person", "bind", "unbind", "set":
			fs.String("person-key", "", "ssh-ed25519 public key in ssh-agent, or an unencrypted OpenSSH private key file")
		default:
			if administeredCommands[command] {
				fs.String("person-key", "", "ssh-ed25519 public key in ssh-agent, or an unencrypted OpenSSH private key file")
			}
		}
	} else if args[0] == "person" {
		fs.String("person-key", "", "ssh-ed25519 public key in ssh-agent, or an unencrypted OpenSSH private key file")
	}

	switch strings.Join(args, " ") {
	case "agent register":
		fs.String("name", "", "agent name")
		fs.String("owner", "", "local owner label")
		fs.StringArray("capability", nil, "advertised capability; repeatable")
	case "session attach":
		fs.String("agent", "", "registered agent ID")
		fs.String("integration", "", "integration label")
	case "session list":
		fs.String("agent", "", "filter by registered agent ID")
	case "peer add":
		fs.String("id", "", "expected host ID")
		fs.String("public-key", "", "owner-verified public key")
		fs.String("address", "", "peer IP:port")
	case "grant create":
		fs.String("from-agent", "", "limit the grant to requests whose asserted origin is this agent of the requester host")
		fs.String("peer", "", "requester host ID")
		fs.String("agent", "", "target local agent ID")
		fs.String("expires-at", "", "UTC grant expiration")
		fs.Int64("max-message-bytes", 65536, "content byte limit")
		fs.Int64("max-artifact-bytes", 0, "bound on a task's input and result artifacts together; 0 refuses artifacts; needs --action task.submit or task.delegate")
		fs.Bool("allow-disconnected", false, "permit work without coordination")
		fs.String("action", "message.append", "authorized action: message.append, task.submit, or task.delegate (task.submit, and the receiving agent may pass the task on)")
	case "message list":
		fs.Int64("after", 0, "read messages after sequence")
		fs.Int64("limit", 100, "maximum records, 1 to 1000")
	case "message send":
		fs.String("peer", "", "receiving host ID")
		fs.String("request", "", "stable request ID; generated if omitted")
		fs.String("grant", "", "receiver grant ID; without it, the send cites the receiver owner's access policy")
		fs.String("agent", "", "receiver agent ID")
		fs.String("deadline", "", "UTC request deadline")
		fs.String("content", "", "message text")
		fs.String("from-agent", "", "local agent this send originates from")
		fs.String("from-session", "", "one of that agent's sessions; needs --from-agent")
	case "task submit":
		fs.Int64("delegation-depth", 0, "let the receiving agent pass the task on through up to N further hosts, 0 to 2; needs --from-agent")
		fs.StringArray("delegate-to", nil, "principal the task may be passed on to: network, person:<person ID>, or host:<host ID>; repeatable, default network; needs --delegation-depth")
		fs.String("parent-sender", "", "sender host of a running received task to pass on; needs --parent-task")
		fs.String("parent-task", "", "ID of that received task; needs --parent-sender")
		fs.StringArray("artifact", nil, "file to upload and attach as an input artifact; repeatable")
		fs.StringArray("artifact-type", nil, "media type of the corresponding --artifact; repeatable, default application/octet-stream")
		fs.String("peer", "", "receiving host ID")
		fs.String("agent", "", "receiver agent ID")
		fs.String("input", "", "task input text")
		fs.String("deadline", "", "UTC time by which an agent must accept; default 1 hour")
		fs.String("grant", "", "receiver grant ID for task.submit; without it, the task cites the receiver owner's access policy")
		fs.String("from-agent", "", "local agent this task originates from")
		fs.String("from-session", "", "one of that agent's sessions; needs --from-agent")
		fs.String("task", "", "stable task ID; generated if omitted")
	case "task list":
		fs.Int64("after", 0, "read tasks after sequence")
		fs.Int64("limit", 100, "maximum records, 1 to 1000")
	case "network invite":
		fs.String("network", "", "network ID")
		fs.String("member", "", "invitee member label")
		fs.String("expires-at", "", "UTC invite expiration, at most 30 days ahead")
		fs.Bool("host-only", false, "issue a host-only invite instead of a member invite")
	case "network invite-person":
		fs.String("network", "", "network ID")
		fs.String("member", "", "invitee member label")
		fs.String("expires-at", "", "UTC invite expiration, at most 30 days ahead")
	case "network remove-person":
		fs.String("network", "", "network ID")
		fs.String("person", "", "person ID to remove")
	case "adapter route add":
		fs.String("adapter", "", "local adapter credential ID")
		fs.String("name", "", "destination name")
		fs.String("peer", "", "receiving host ID")
		fs.String("agent", "", "remote agent ID")
		fs.String("grant", "", "receiver's grant ID; without it, sends cite the receiver owner's access policy")
		fs.String("expires-at", "", "route expiration")
		fs.Int64("max-message-bytes", 65536, "maximum content bytes")
		fs.Int64("max-messages", 100, "lifetime message and task budget")
		fs.String("action", "message.append", "route action: message.append (send) or task.submit (delegate_task)")
		fs.Int64("delegation-depth", 0, "tasks through this route may be passed on through up to N further hosts, 0 to 2; needs --action task.submit")
	case "adapter route list":
		fs.String("adapter", "", "adapter credential ID")
	case "adapter create":
		fs.String("session", "", "one attached session ID")
		fs.String("expires-at", "", "credential expiration")
	case "delivery list":
		fs.Int64("after", 0, "read after this sequence")
		fs.Int64("limit", 100, "maximum records")
	case "activity":
		fs.Int64("after", 0, "read events after this sequence")
		fs.Int("limit", 100, "maximum events, 1 to 1000")
	case "network group set":
		fs.String("network", "", "network ID")
		fs.String("group", "", "group name")
		fs.StringArray("person", nil, "member person ID or label (repeatable; none deletes the group)")
	case "network rotate-root":
		fs.Bool("to-ssh", false, "rotate to the SSH key named by --root-key")
		fs.String("root-key", "", "the new SSH root: a .pub file selecting an ssh-agent identity, or an OpenSSH private key file")
	case "network admit":
		fs.String("network", "", "network ID")
		fs.String("person", "", "person ssh-ed25519 public key line, or a path to one")
		fs.String("host", "", "host public key (Base64, from the host's info)")
		fs.String("member", "", "member label")
	case "network redeem-person":
		fs.String("token", "", "person invite token")
	case "network create", "network join":
		fs.Bool("no-person", false, "do not admit or bind a person")
		if command == "create" {
			fs.String("name", "", "network name")
			fs.String("member", "", "this host's member label")
			fs.String("coordinator", "", "coordinator HOST:PORT")
			fs.String("coordinator-key", "", "pinned coordinator public key")
		} else {
			fs.String("token", "", "invite token")
			fs.String("descriptor", "", "network descriptor, for a host admitted by public key")
		}
	case "run":
		fs.String("peer-listen", "", "opt-in peer bind address, UDP IP:port")
		fs.String("advertise", "", "peer address advertised to coordination; defaults to a specific bind address")
		fs.Int("coordination-interval", 30, "seconds between coordination syncs, 1 to 3600")
		fs.String("person-agent", os.Getenv("SSH_AUTH_SOCK"), "ssh-agent socket for renewing access policies; defaults to SSH_AUTH_SOCK")
		fs.Int64("artifact-quota", host.DefaultArtifactQuota, "bytes of task artifacts this host stores, including pending fetches")
	case "session setup", "session start", "session doctor":
		fs.String("directory", "", "private session setup directory")
		if command == "setup" {
			fs.String("harness", "", "installed harness integration ID")
			fs.String("integrations", "", "integration bundle directory; defaults to CAPSULE_INTEGRATIONS_DIR or installation")
			fs.String("runner", "", "integration helper executable override")
			fs.String("agent", "", "registered agent ID")
			fs.String("expires-at", "", "future RFC3339 authorization expiry")
			fs.String("expires-in", "", "relative authorization lifetime (1m to 720h)")
			fs.String("routes", "", "owner destination JSON array")
			fs.StringArray("option", nil, "integration-specific KEY=VALUE; repeatable")
		}
		if command == "start" {
			fs.String("workspace", "", "harness working directory; defaults to this directory")
		}
	case "message inspect", "message retry", "message refresh", "message reply", "message origin", "task inspect", "task cancel", "task events", "task artifact":
		fs.String("peer", "", "receiving host ID")
		if command == "events" {
			fs.Int64("after", 0, "read events after this sequence")
			fs.Int64("limit", 100, "maximum events, 1 to 1000")
		}
		if command == "artifact" {
			fs.String("out", "", "new file to write the artifact to")
		}
	case "network revoke", "network revoke-invite":
		fs.String("network", "", "network ID")
		if command == "revoke" {
			fs.String("host", "", "host ID to revoke")
		} else {
			fs.String("invite", "", "invite public key to revoke")
		}
	case "network delegate-admin", "network remove-admin":
		fs.String("network", "", "network ID")
		fs.String("person", "", "person ID or label")
		fs.String("root-key", "", "the current SSH root key in ssh-agent or an OpenSSH private key file")
		if command == "remove-admin" {
			fs.Bool("revoke-admitted", false, "also invalidate everything the administrator signed")
		}
	case "network bind", "network unbind":
		fs.String("network", "", "network ID")
		if command == "unbind" {
			fs.String("host", "", "host ID to unbind")
		}
	case "access allow", "access deny", "access renew":
		fs.String("network", "", "network ID")
		fs.String("person-key", "", "ssh-ed25519 public key in ssh-agent, or an unencrypted OpenSSH private key file")
		if command != "renew" {
			fs.String("agent", "", "local agent name the rule covers")
			fs.StringArray("principal", nil, "person:PERSON, group:NAME, network, or agent:HOST_ID/AGENT_ID; repeatable")
		}
		if command == "allow" {
			fs.Int64("max-message-bytes", 65536, "content byte limit, 1 to 65536")
			fs.Int64("max-artifact-bytes", 0, "bound on input and result artifacts together; 0 refuses artifacts")
			fs.Bool("allow-disconnected", false, "permit messages while the receiver is out of sync")
			fs.Int("valid-days", 7, "policy validity, 1 to 90 days")
			fs.StringArray("action", nil, "message.append (the default), task.submit, or task.delegate; repeatable")
		}
	case "access show":
		fs.String("network", "", "network ID")
		fs.String("person", "", "person ID or label; this host's person by default")
	case "access block", "access unblock":
		fs.String("person", "", "person ID or label to block")
		fs.String("host", "", "host ID to block")
	}
}
