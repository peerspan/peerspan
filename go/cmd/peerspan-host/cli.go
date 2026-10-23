package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/spf13/cobra"
)

func newCommand(out, errOut io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use: programName, Short: "Run and control a local Peerspan host daemon",
		Long: `Run and control a local Peerspan host daemon.

Person keys are ssh-ed25519 keys in ssh-agent (SSH_AUTH_SOCK), or --person-key
PATH naming a public key in the agent or an unencrypted OpenSSH private key file.
A host holding the network's root seed signs administration as the root;
otherwise the CLI signs with the person key in ssh-agent, which must be a
current administrator. Root-only commands without the seed use --root-key PATH.
PERSON is a person ID or label. An access policy, signed by the agents' owner,
lets principals (person:PERSON, group:NAME, or network) message the owner's
agents by name without a grant; the daemon renews it through the ssh-agent at
--person-agent. The owner's hosts in a network push their policies to one
another and to the coordinator, and sync with each other at start, every 5
minutes, and when another of the owner's hosts appears; access sync runs a sync
now, and --status shows the deliveries. Blocks are host-local and override
grants and policies.
A policy rule for agent * covers every agent of the owner that no rule names.
Hosts bound to the same person reach each other's agents without a grant or
policy (self access), even out of sync with coordination; blocks do not apply.
Without --grant, message send, task submit, and adapter routes cite self access
when the receiver is bound to this host's person, and otherwise the receiver
owner's policy. Grants, policy rules, and routes carry an action: message.append
(the default) or task.submit. Task submissions are retried and their events
polled automatically; task inspect and task events read the local record.
Task artifacts are off unless the receiver's grant or policy rule for
task.submit sets --max-artifact-bytes, which bounds a task's input and result
files together. --artifact uploads a file named after its base name; the
i-th --artifact-type is the i-th file's media type. Received files count
toward the daemon's --artifact-quota (default 10 GiB) and are kept 7 days
after their task finishes; artifact prune releases finished tasks now.
Agents are addressed as PERSON/AGENT or HOST_ID/AGENT. Each daemon keeps a
directory of the agents its networks' other hosts let it reach; agents shows
it, and send and task address an agent there, citing self access, a policy
rule, or the grant with the latest expiry unless --grant is given. attach
registers an agent for a project and sets up a session with directory access:
its agent may send and delegate by address to anyone in the directory, at most
--max-sends-per-hour times in an hour. With --calls, its agent may also call
capabilities shared with you, and yours on your other trusted machines, at
most --max-calls-per-hour times in an hour; without --calls or --no-calls,
attach asks at a terminal. For a harness that supports launch,
attach then starts it in the project as session start does, printing its
result on stderr first; --no-start only sets up, and arguments after -- go to
the harness.
The serve command is a compatibility alias for run.
Session attachment records metadata; a scoped adapter connects an opted-in session.
`,
		SilenceUsage: true, SilenceErrors: true,
		Args: cobra.NoArgs,
	}
	var leaves []*cobra.Command
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if advanced, _ := cmd.Flags().GetBool("help-advanced"); advanced {
			return printHelp(root, leaves, true)
		}
		return cmd.Help()
	}
	root.Flags().Bool("help-advanced", false, "list every command")
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
		leaves = append(leaves, cmd)
		return cmd
	}
	add("status", "status", "Show this host and what needs attention", 0)
	up := add("up", "up [HARNESS] [-- HARNESS_ARGS...]", "Guide service, network, and project setup", 0)
	up.Args = func(cmd *cobra.Command, args []string) error {
		n := cmd.Flags().ArgsLenAtDash()
		if n < 0 {
			n = len(args)
		}
		if n > 1 {
			return errors.New("up takes at most one HARNESS before --")
		}
		return nil
	}
	up.RunE = func(cmd *cobra.Command, args []string) error {
		n := cmd.Flags().ArgsLenAtDash()
		if n < 0 {
			n = len(args)
		}
		harness := ""
		if n == 1 {
			harness = args[0]
		}
		return runUp(cmd.Context(), harness, args[n:], cmd.Flags(), state, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}
	add("run", "run", "Run the host daemon in the foreground", 0).Aliases = []string{"serve"}
	add("install", "install", "Install and start the daemon as a user service", 0)
	add("uninstall", "uninstall", "Stop and remove the daemon's user service", 0)
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
	add("session pending", "pending", "List the work the current directory's session still owes", 0)
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
	// task TARGET TEXT is the task group itself, run with an address.
	task := groups["task"]
	task.Use, task.Short, task.Args = "task TARGET TEXT", "Delegate a task to an agent by address", cobra.ExactArgs(2)
	task.RunE = func(cmd *cobra.Command, args []string) error {
		return execute(cmd.Context(), append([]string{taskByAddress}, args...), cmd.Flags(), state, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}
	configureFlags(task, []string{taskByAddress})
	leaves = append(leaves, task)
	attach := add("attach", "attach HARNESS [-- HARNESS_ARGS...]", "Attach a harness in this project to the directory and start it", 1)
	attach.Args = func(cmd *cobra.Command, args []string) error {
		if dash := cmd.Flags().ArgsLenAtDash(); (dash == -1 && len(args) != 1) || (dash != -1 && dash != 1) {
			return errors.New("attach takes one HARNESS; harness arguments follow a -- separator")
		}
		return nil
	}
	add("agents", "agents", "Show the agents you can reach and who can reach yours", 0)
	add("send", "send TARGET TEXT", "Send a message to an agent by address", 2)
	add("sources refresh", "refresh", "Discover the sources of attached agents again", 0)
	add("sources open-to", "open-to HOST", "Let a trusted machine of yours call this host's sources", 0).Args = cobra.RangeArgs(0, 1)
	add("sources close-to", "close-to HOST", "Stop a machine calling this host's sources", 0).Args = cobra.RangeArgs(0, 1)
	// sources is the sources group itself, listing this host's sources.
	sourcesGroup := groups["sources"]
	sourcesGroup.Use, sourcesGroup.Short, sourcesGroup.Args = "sources", "List this host's sources and the capabilities built on them", cobra.NoArgs
	sourcesGroup.RunE = func(cmd *cobra.Command, args []string) error {
		return execute(cmd.Context(), []string{"sources"}, cmd.Flags(), state, cmd.OutOrStdout(), cmd.ErrOrStderr())
	}
	configureFlags(sourcesGroup, []string{"sources"})
	leaves = append(leaves, sourcesGroup)
	add("capability create", "create NAME", "Create a capability from a source", 1)
	add("capability list", "list", "List this host's capabilities", 0)
	add("capability show", "show NAME", "Show a capability and its recipients", 1)
	add("capability remove", "remove NAME", "Remove a capability, withdrawing its shares", 1)
	add("share", "share [NAME]", "Share a capability with a principal", 0).Args = cobra.RangeArgs(0, 1)
	add("shares", "shares", "List capabilities and their shares", 0)
	add("unshare", "unshare NAME", "Withdraw a principal's access to a capability", 1)
	add("discover", "discover [PERSON]", "List reachable agents and usable capabilities", 0).Args = cobra.RangeArgs(0, 1)
	// call ADDRESS OPERATION reads its own arguments: --KEY VALUE options
	// name the operation's input properties.
	callCommand := &cobra.Command{Use: "call ADDRESS OPERATION [--input JSON] [--KEY VALUE ...] [--deadline T] [--wait D] [--network ID]", Short: "Call an operation of a capability", DisableFlagParsing: true}
	callCommand.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := parseCallArgs(args)
		if err != nil {
			return err
		}
		if c.help {
			return cmd.Help()
		}
		if c.state == "" {
			c.state = state
		}
		return executeCall(cmd.Context(), c, cmd.OutOrStdout())
	}
	root.AddCommand(callCommand)
	leaves = append(leaves, callCommand)
	add("calls list", "list", "List outbound calls", 0)
	add("calls received", "received", "List calls received by this host", 0)
	add("calls inspect", "inspect ID", "Inspect an outbound call", 1)
	add("calls cancel", "cancel ID", "Cancel an outbound call", 1)
	add("trust", "trust [HOST]", "Let a machine of yours use your capabilities", 0).Args = cobra.RangeArgs(0, 1)
	add("untrust", "untrust HOST", "Stop a machine of yours using your capabilities", 1)
	add("artifact list", "list", "List stored artifacts", 0)
	add("artifact prune", "prune", "Release artifacts of finished tasks", 0)
	add("network create", "create [NAME]", "Create a coordinated network", 0).Args = cobra.RangeArgs(0, 1)
	add("join", "join TOKEN", "Join a network with an invite", 1)
	add("invite", "invite LABEL", "Invite a person to a network", 1)
	add("allow", "allow PRINCIPAL", "Set a principal's access to your agents", 1)
	add("deny", "deny PRINCIPAL", "Remove a principal's access to your agents", 1)
	add("block", "block TARGET", "Block a person or host locally", 1)
	add("unblock", "unblock TARGET", "Remove a local block", 1)
	add("network join", "join", "Join a coordinated network", 0)
	add("network invite", "invite", "Issue a member or host invite", 0)
	add("network list", "list", "List joined networks", 0)
	add("network members", "members [ID]", "List network members", 0).Args = cobra.RangeArgs(0, 1)
	add("network sync", "sync [ID]", "Sync a network with coordination", 0).Args = cobra.RangeArgs(0, 1)
	add("network revoke", "revoke", "Revoke a host membership", 0)
	add("network revoke-invite", "revoke-invite", "Revoke an invite", 0)
	add("network leave", "leave ID", "Leave a network", 1)
	add("network rotate-root", "rotate-root ID", "Rotate the network root key", 1)
	add("network move", "move", "Move a network to another coordinator", 0)
	add("network admit", "admit", "Admit a person or host", 0)
	add("network invite-person", "invite-person", "Issue a person invite", 0)
	add("network redeem-person", "redeem-person", "Redeem a person invite", 0)
	add("network bind", "bind", "Bind this host to a person", 0)
	add("network unbind", "unbind", "Unbind a host from a person", 0)
	add("network remove-person", "remove-person", "Remove a person", 0)
	add("network persons", "persons [ID]", "List network persons", 0).Args = cobra.RangeArgs(0, 1)
	add("network delegate-admin", "delegate-admin", "Delegate network administration", 0)
	add("network remove-admin", "remove-admin", "Remove an administrator", 0)
	add("network group set", "set", "Set or delete a group", 0)
	add("network groups", "groups [ID]", "List network groups", 0).Args = cobra.RangeArgs(0, 1)
	add("access allow", "allow", "Allow access to an owner's agent", 0)
	add("access deny", "deny", "Withdraw access to an owner's agent", 0)
	add("access renew", "renew", "Renew the owner access policy", 0)
	add("access show", "show", "Show an owner access policy", 0)
	add("access sync", "sync", "Sync the owner's policies with sibling hosts now", 0)
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
	shapeHelp(root, leaves)
	return root
}

// rootCommands are the commands the root help lists, in order; the others
// are hidden and listed by help advanced.
var rootCommands = []string{
	"status", "up", "install", "run",
	"network create", "join", "invite",
	"attach", "agents", "send", "task",
	"allow", "deny", "block", "unblock",
	"network list", "network members",
	"access show",
	"session start", "session doctor",
}

// taskByAddress is the command path execute receives for task TARGET TEXT.
const taskByAddress = "task-by-address"

// shapeHelp hides every command outside rootCommands, and groups left with
// no visible command, and installs the root and advanced help.
func shapeHelp(root *cobra.Command, leaves []*cobra.Command) {
	shown := map[string]bool{}
	for _, path := range rootCommands {
		shown[path] = true
	}
	leaf := map[*cobra.Command]bool{}
	for _, l := range leaves {
		l.Hidden = !shown[commandPath(l)]
		leaf[l] = true
	}
	var hideGroups func(*cobra.Command) bool
	hideGroups = func(cmd *cobra.Command) bool {
		if !cmd.HasSubCommands() {
			return !cmd.Hidden
		}
		// A runnable group, such as task, stays visible when listed.
		visible := leaf[cmd] && !cmd.Hidden
		for _, child := range cmd.Commands() {
			if hideGroups(child) {
				visible = true
			}
		}
		if cmd != root {
			cmd.Hidden = !visible
		}
		return visible
	}
	hideGroups(root)
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd != root {
			defaultHelp(cmd, args)
			return
		}
		_ = printHelp(root, leaves, false)
	})
	root.SetHelpCommand(&cobra.Command{
		Use: "help [advanced | COMMAND]", Short: "Help about any command",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && args[0] == "advanced" {
				return printHelp(root, leaves, true)
			}
			target, _, err := root.Find(args)
			if err != nil || target == nil {
				return fmt.Errorf("unknown help topic %q; see %s help advanced", strings.Join(args, " "), programName)
			}
			return target.Help()
		},
	})
}

// commandPath is a command's path without the program name.
func commandPath(cmd *cobra.Command) string {
	_, path, _ := strings.Cut(cmd.CommandPath(), " ")
	return path
}

// printHelp prints the root help, or with advanced the full description and
// every command. The Commands section is parsed by conformance/launch_cli.py:
// one "  PATH  description" line per command.
func printHelp(root *cobra.Command, leaves []*cobra.Command, advanced bool) error {
	out := root.OutOrStdout()
	root.InitDefaultHelpFlag()
	paths := rootCommands
	if advanced {
		paths = nil
		for _, leaf := range leaves {
			paths = append(paths, commandPath(leaf))
		}
		fmt.Fprint(out, root.Long)
	} else {
		fmt.Fprintln(out, root.Short+".")
	}
	fmt.Fprintf(out, "\nUsage:\n  %s COMMAND [flags]\n\nCommands:\n", programName)
	width := 0
	for _, path := range paths {
		width = max(width, len(path))
	}
	for _, path := range paths {
		cmd, _, err := root.Find(strings.Fields(path))
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "  %-*s  %s\n", width, path, cmd.Short)
	}
	fmt.Fprintf(out, "\nFlags:\n%s\n", root.LocalFlags().FlagUsages())
	if advanced {
		fmt.Fprintf(out, "Run '%s COMMAND --help' for a command's flags.\n", programName)
	} else {
		fmt.Fprintf(out, "Run '%s help advanced' for every command.\n", programName)
	}
	return nil
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
	} else if args[0] == "person" || args[0] == "join" || args[0] == "invite" || args[0] == "allow" || args[0] == "deny" || args[0] == "trust" || args[0] == "untrust" || args[0] == "share" || args[0] == "unshare" || (args[0] == "capability" && (command == "remove" || command == "create")) {
		fs.String("person-key", "", "ssh-ed25519 public key in ssh-agent, or an unencrypted OpenSSH private key file")
	}

	switch strings.Join(args, " ") {
	case "sources":
		fs.String("agent", "", "only this local agent")
		fs.Bool("json", false, "print the daemon's listing")
	case "sources refresh":
		fs.String("agent", "", "only this local agent")
	case "sources open-to", "sources close-to":
		fs.Bool("all", false, "every machine of yours that passes self access, including ones trusted later")
	case "capability create":
		fs.String("from", "", "the source: AGENT/SERVER, or SERVER when one agent here has it")
		fs.String("operations", "", "tool names, comma-separated")
		fs.String("resources", "", "all, or URIs, comma-separated; adds the read operation")
		fs.String("env-file", "", "the capability's own environment file, applied whole to its own instance")
		fs.StringArray("arg", nil, "argument replacing the source's args in its own instance; repeatable")
	case "capability list":
		fs.Bool("json", false, "print the daemon's listing")
	case "capability remove":
		fs.Bool("yes", false, "withdraw its shares without asking")
	case "share":
		fs.String("with", "", "the principal: PERSON, person:PERSON, group:NAME, everyone, network, or agent:HOST/AGENT")
		fs.Int64("calls-per-hour", shareMaxCallsPerHour, "calls each caller may make in an hour, 1 to 10000; on an existing rule, for every recipient")
		fs.Bool("yes", false, "share without asking for confirmation")
		fs.String("network", "", "network ID; defaults to the only network")
		fs.String("from", "", "guided share: the source, AGENT/SERVER or SERVER")
		fs.String("operations", "", "guided share: tool names, comma-separated")
		fs.String("resources", "", "guided share: all, or URIs, comma-separated")
		fs.String("name", "", "guided share: the capability name")
		fs.String("env-file", "", "guided share: the capability's own environment file")
		fs.StringArray("arg", nil, "guided share: argument replacing the source's args; repeatable")
	case "unshare":
		fs.String("with", "", "the principal to remove")
		fs.String("network", "", "network ID; defaults to the only network")
	case "shares":
		fs.Bool("json", false, "print the shares object")
		fs.String("network", "", "only this network's rules")
	case "discover":
		fs.String("network", "", "only this network")
		fs.Bool("json", false, "print the discover object")
	case "calls list", "calls received":
		fs.Int64("after", 0, "read calls after sequence")
		fs.Int64("limit", 100, "maximum records, 1 to 1000")
	case "calls inspect", "calls cancel":
		fs.String("peer", "", "receiving host ID")
	case "trust", "untrust":
		fs.String("network", "", "network ID; defaults to the only network")
	case "join":
		fs.Bool("trusted", false, "let this machine use your capabilities on your other machines")
		fs.Bool("untrusted", false, "do not let this machine use your capabilities on your other machines")
		fs.Bool("no-person", false, "join as a host-only membership, without admitting or binding a person")
		// network join's flags, filled in from TOKEN.
		fs.String("token", "", "")
		fs.String("descriptor", "", "")
		_ = fs.MarkHidden("token")
		_ = fs.MarkHidden("descriptor")
	case "invite":
		fs.String("network", "", "network ID; defaults to the only network")
		fs.String("expires-at", "", "UTC invite expiration, at most 30 days ahead; default 7 days")
		fs.String("expires-in", "", "relative lifetime (1m to 720h); excludes --expires-at")
		fs.String("member", "", "")
		fs.Bool("host-only", false, "")
		_ = fs.MarkHidden("member")
		_ = fs.MarkHidden("host-only")
	case "allow", "deny":
		fs.String("network", "", "network ID; defaults to the only network")
		fs.String("agent", membership.PolicyAgentAll, "agent name the access covers; * means every agent of yours")
		if command == "allow" {
			fs.Bool("no-tasks", false, "allow messages only, not task.submit")
			fs.String("files", "", "task artifact bound, a byte count with an optional K, M, or G suffix; default none")
			fs.Bool("delegate", false, "also allow task.delegate, so your agent may pass tasks on")
		}
	case "block", "unblock":
	case "attach", "up":
		if command == "up" {
			fs.String("create", "", "create or resume a network by name")
			fs.String("join", "", "join or resume the network in an invite")
			fs.String("as", "", "person label for a new network; defaults to your login")
			fs.String("person-key", "", "person signing key")
			fs.String("coordinator", "", "explicit coordinator HOST:PORT for creation")
			fs.String("coordinator-key", "", "pinned coordinator public key")
			fs.Bool("trusted", false, "trust this machine for capability calls")
			fs.Bool("untrusted", false, "keep this machine untrusted for capability calls")
		}
		fs.String("name", "", "agent name; by default the harness name, suffixed when taken")
		fs.String("directory", "", "project directory; defaults to the current directory")
		fs.String("expires-at", "", "credential expiration; by default the credential is renewable")
		fs.String("expires-in", "", "relative credential lifetime (1m to 720h); excludes --expires-at")
		fs.Int64("max-sends-per-hour", 100, "sends and delegations by address the session may make in any 60 minutes, 1 to 10000")
		fs.Bool("calls", false, "let the agent call capabilities shared with you, and yours on your other trusted machines")
		fs.Bool("no-calls", false, "do not let the agent call capabilities")
		fs.Int64("max-calls-per-hour", 100, "capability calls the session may make in any 60 minutes, 1 to 10000; requires calls")
		fs.StringArray("option", nil, "integration-specific KEY=VALUE; repeatable")
		fs.String("integrations", "", "integration bundle directory; defaults to PEERSPAN_INTEGRATIONS_DIR or installation")
		fs.String("runner", "", "integration helper executable override")
		fs.Bool("no-start", false, "set up only, print the result, and do not start the harness")
	case "agents":
		fs.String("network", "", "network ID; defaults to the only network")
		fs.Bool("refresh", false, "refresh the directory first")
		fs.Bool("json", false, "print the directory object")
	case "send", taskByAddress:
		fs.String("network", "", "network to resolve TARGET in; by default every network")
		fs.String("grant", "", "receiver grant ID; without it, the daemon chooses self access, a policy rule, or a grant")
		fs.String("from-agent", "", "local agent this originates from")
		fs.String("deadline", "", "UTC deadline; default 1 hour")
		if command == taskByAddress {
			fs.StringArray("file", nil, "file to attach as an input artifact; repeatable")
		}
	case "status":
		fs.Bool("json", false, "print the daemon's status object")
	case "install":
		fs.String("peer-listen", "", "peer listen address, UDP IP:PORT; default the installed unit's, else 0.0.0.0:7401 or the next free port to 7499")
		fs.Bool("no-start", false, "install and enable the service without starting it")
	case "agent register":
		fs.String("name", "", "agent name")
		fs.String("owner", "", "local owner label")
		fs.StringArray("label", nil, "descriptive label; repeatable; confers nothing")
		fs.StringArray("capability", nil, "alias of --label")
	case "session attach":
		fs.String("agent", "", "registered agent ID")
		fs.String("integration", "", "integration label")
	case "session list":
		fs.String("agent", "", "filter by registered agent ID")
	case "session pending":
		fs.Bool("json", false, "print the pending work object")
		fs.Bool("hook", false, "print the pending work as Claude Code SessionStart hook output")
	case "peer add":
		fs.String("id", "", "expected host ID")
		fs.String("public-key", "", "owner-verified public key")
		fs.String("address", "", "peer IP:port")
	case "grant create":
		fs.String("from-agent", "", "limit the grant to requests whose asserted origin is this agent of the requester host")
		fs.String("peer", "", "requester host ID")
		fs.String("agent", "", "target local agent ID")
		fs.String("expires-at", "", "UTC grant expiration; default 30 days")
		fs.String("expires-in", "", "relative lifetime (1m to 720h); excludes --expires-at")
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
		fs.String("deadline", "", "UTC request deadline; default 1 hour")
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
		fs.String("expires-at", "", "UTC invite expiration, at most 30 days ahead; default 7 days")
		fs.String("expires-in", "", "relative lifetime (1m to 720h); excludes --expires-at")
		fs.Bool("host-only", false, "issue a host-only invite instead of a member invite")
	case "network invite-person":
		fs.String("network", "", "network ID")
		fs.String("member", "", "invitee member label")
		fs.String("expires-at", "", "UTC invite expiration, at most 30 days ahead; default 7 days")
		fs.String("expires-in", "", "relative lifetime (1m to 720h); excludes --expires-at")
	case "network remove-person":
		fs.String("network", "", "network ID")
		fs.String("person", "", "person ID to remove")
	case "adapter route add":
		fs.String("adapter", "", "local adapter credential ID")
		fs.String("name", "", "destination name")
		fs.String("peer", "", "receiving host ID")
		fs.String("agent", "", "remote agent ID")
		fs.String("grant", "", "receiver's grant ID; without it, sends cite the receiver owner's access policy")
		fs.String("expires-at", "", "route expiration; by default the route follows its renewable credential")
		fs.String("expires-in", "", "relative lifetime (1m to 720h); excludes --expires-at")
		fs.Int64("max-message-bytes", 65536, "maximum content bytes")
		fs.Int64("max-messages", 100, "lifetime message and task budget")
		fs.String("action", "message.append", "route action: message.append (send) or task.submit (delegate_task)")
		fs.Int64("delegation-depth", 0, "tasks through this route may be passed on through up to N further hosts, 0 to 2; needs --action task.submit")
	case "adapter route list":
		fs.String("adapter", "", "adapter credential ID")
	case "adapter create":
		fs.String("session", "", "one attached session ID")
		fs.String("expires-at", "", "credential expiration; by default the credential is renewable, extended to 24 hours ahead whenever its adapter connects")
		fs.String("expires-in", "", "relative lifetime (1m to 720h); excludes --expires-at")
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
	case "network move":
		fs.String("network", "", "network ID; defaults to the only network")
		fs.String("coordinator", "", "the new coordinator's HOST:PORT")
		fs.String("coordinator-key", "", "the new coordinator's public key")
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
		fs.Bool("trusted", false, "let this machine use your capabilities on your other machines")
		fs.Bool("untrusted", false, "do not let this machine use your capabilities on your other machines")
		fs.Bool("no-person", false, "host-only membership: do not admit or bind a person")
		if command == "create" {
			fs.String("name", "", "network name; or give NAME")
			fs.String("as", "", "your person and member label; defaults to the login name")
			fs.String("member", "", "alias of --as")
			fs.String("coordinator", "", "coordinator HOST:PORT; with --coordinator-key, overrides the build's default coordinator")
			fs.String("coordinator-key", "", "pinned coordinator public key; given together with --coordinator")
		} else {
			fs.String("token", "", "invite token")
			fs.String("descriptor", "", "network descriptor, for a host admitted by public key")
		}
	case "run":
		fs.String("peer-listen", "", "opt-in peer bind address, UDP IP:port")
		fs.String("advertise", "", "peer address advertised to coordination; defaults to a specific bind address")
		fs.Int("coordination-interval", 30, "seconds between coordination syncs, 1 to 3600")
		fs.String("person-agent", os.Getenv("SSH_AUTH_SOCK"), "ssh-agent socket for renewing access policies; defaults to SSH_AUTH_SOCK")
		fs.String("person-key-file", "", "CLI-generated person key file for renewing access policies when the ssh-agent lacks the key; defaults to $XDG_CONFIG_HOME/peerspan/person_ed25519, used while it exists")
		fs.Int64("artifact-quota", host.DefaultArtifactQuota, "bytes of task artifacts this host stores, including pending fetches")
	case "session setup", "session start", "session doctor":
		if command == "setup" {
			fs.String("directory", "", "private session setup directory")
		} else {
			fs.String("directory", "", "private session setup directory; defaults to the attach profile of the current directory")
		}
		if command == "setup" {
			fs.String("harness", "", "installed harness integration ID")
			fs.String("integrations", "", "integration bundle directory; defaults to PEERSPAN_INTEGRATIONS_DIR or installation")
			fs.String("runner", "", "integration helper executable override")
			fs.String("agent", "", "registered agent ID")
			fs.String("expires-at", "", "future RFC3339 authorization expiry; by default the authorization is renewable")
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
	case "access sync":
		fs.String("network", "", "network ID")
		fs.Bool("status", false, "show the delivery status without syncing")
	case "access block", "access unblock":
		fs.String("person", "", "person ID or label to block")
		fs.String("host", "", "host ID to block")
	}
}
