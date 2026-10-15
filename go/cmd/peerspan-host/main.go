package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/person"
	"github.com/spf13/pflag"
)

// programName is the base name the CLI was invoked as, peerspan or
// peerspan-host; help and diagnostics use it.
var programName = "peerspan-host"

// exitStatus ends the CLI with a status code and no error message.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func invalidCommand() error {
	return errors.New("invalid command; see " + programName + " --help")
}

func main() {
	if name := filepath.Base(os.Args[0]); name != "" && name != "." && name != string(filepath.Separator) {
		programName = name
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var code exitStatus
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	cmd := newCommand(out, errOut)
	cmd.SetArgs(args)
	return cmd.ExecuteContext(ctx)
}

func execute(ctx context.Context, args []string, fs *pflag.FlagSet, state string, out, errOut io.Writer) error {
	if args[0] == "person" {
		return personShow(fs, out)
	}
	// send and task TARGET TEXT name their target by address.
	addressed := args[0] == "send" || args[0] == taskByAddress
	if args[0] == taskByAddress {
		args = append([]string{"task"}, args[1:]...)
	}
	if args[0] == "session" && args[1] == "pending" {
		return runSessionPending(ctx, fs, state, out)
	}
	if args[0] == "session" && (args[1] == "setup" || args[1] == "start" || args[1] == "doctor") {
		return runSessionSetup(ctx, args[1:], fs, state, out)
	}
	// The top-level invite and join are network invite and network join.
	topInvite := args[0] == "invite"
	switch args[0] {
	case "invite":
		if err := fs.Set("member", args[1]); err != nil {
			return err
		}
		args = []string{"network", "invite"}
	case "join":
		if err := fs.Set("token", args[1]); err != nil {
			return err
		}
		args = []string{"network", "join"}
	}
	if err := resolveExpiry(args, fs); err != nil {
		return err
	}
	explicitState := state
	if state == "" {
		var err error
		state, err = host.DefaultStateDir()
		if err != nil {
			return err
		}
	}
	if args[0] == "run" {
		return runDaemon(ctx, fs, state, errOut)
	}
	if args[0] == "install" {
		return runInstall(ctx, fs, state, out)
	}
	if args[0] == "uninstall" {
		return runUninstall(ctx, out)
	}

	client := host.Client{SocketPath: filepath.Join(state, "admin.sock")}
	if args[0] == "status" {
		return runStatus(ctx, client, fs, state, out)
	}
	if args[0] == "attach" {
		return runAttach(ctx, client, args[1], args[2:], fs, state, out, errOut)
	}
	if args[0] == "agents" {
		return runAgents(ctx, client, fs, out)
	}
	args, err := defaultNetwork(ctx, client, args, fs)
	if err != nil {
		return err
	}
	if len(args) >= 2 && args[0] == "network" && (args[1] == "create" || args[1] == "join") {
		return networkCreateOrJoin(ctx, client, args[1], args[2:], fs, explicitState, out, errOut)
	}
	if args[0] == "allow" || args[0] == "deny" {
		return allowOrDeny(ctx, client, args[0], args[1], fs, out)
	}
	var method, path string
	var body any
	if addressed {
		method, path, body, err = addressedRequest(args, fs)
	} else if args[0] == "access" {
		method, path, body, err = accessRequest(ctx, client, args, fs)
	} else {
		method, path, body, err = buildRequest(args, fs)
	}
	if errors.Is(err, errPersonCommand) {
		method, path, body, err = personRequest(ctx, client, args, fs)
	}
	if errors.Is(err, errAdminCommand) {
		method, path, body, err = adminRequest(ctx, client, args, fs)
	}
	if err == nil && args[0] == "network" && administeredCommands[args[1]] {
		body, err = signAsAdministrator(ctx, client, path, body, personKey(fs))
	}
	if err != nil {
		return err
	}
	var result json.RawMessage
	switch b := body.(type) {
	case taskSubmission:
		if b.SubmitTask.Artifacts, err = uploadArtifacts(ctx, client, b.files, b.types); err != nil {
			return err
		}
		result, err = client.Call(ctx, method, path, b.SubmitTask)
	case addressedTask:
		if len(b.files) > 0 {
			if b.body["artifacts"], err = uploadArtifacts(ctx, client, b.files, nil); err != nil {
				return err
			}
		}
		result, err = client.Call(ctx, method, path, b.body)
	case artifactDownload:
		result, err = downloadArtifact(ctx, client, path, b.out)
	default:
		result, err = client.Call(ctx, method, path, body)
	}
	if err != nil {
		return err
	}
	if topInvite {
		result, err = inviteOutput(result)
		if err != nil {
			return err
		}
	}
	var value any
	if err := json.Unmarshal(result, &value); err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func buildRequest(args []string, fs *pflag.FlagSet) (string, string, any, error) {
	invalid := func() (string, string, any, error) {
		return "", "", nil, invalidCommand()
	}
	switch args[0] {
	case "block", "unblock":
		// TARGET is a host ID, or else a person ID or label.
		target := args[1]
		req := host.BlockAccess{Person: strings.TrimPrefix(target, "person:")}
		if strings.HasPrefix(target, "host_") {
			req = host.BlockAccess{Host: target}
		}
		if args[0] == "unblock" {
			return "POST", "/v1/access-blocks/remove", req, nil
		}
		return "POST", "/v1/access-blocks", req, nil
	case "info":
		if len(args) != 1 {
			return invalid()
		}
		return "GET", "/v1/host", nil, nil
	case "agent":
		if len(args) < 2 {
			return invalid()
		}
		switch args[1] {
		case "register":
			var req host.RegisterAgent
			var caps []string
			req.Name, _ = fs.GetString("name")
			req.Owner, _ = fs.GetString("owner")
			caps, _ = fs.GetStringArray("capability")
			req.Capabilities = caps
			return "POST", "/v1/agents", req, nil
		case "list":
			if len(args) != 2 {
				return invalid()
			}
			return "GET", "/v1/agents", nil, nil
		case "inspect":
			if len(args) != 3 {
				return invalid()
			}
			return "GET", "/v1/agents/" + url.PathEscape(args[2]), nil, nil
		}
	case "session":
		if len(args) < 2 {
			return invalid()
		}
		switch args[1] {
		case "attach":
			var req host.AttachSession
			req.AgentID, _ = fs.GetString("agent")
			req.Integration, _ = fs.GetString("integration")
			return "POST", "/v1/sessions", req, nil
		case "list":
			var agentID string
			agentID, _ = fs.GetString("agent")
			return "GET", "/v1/sessions?" + (url.Values{"agent_id": {agentID}}).Encode(), nil, nil
		case "inspect", "detach":
			if len(args) != 3 {
				return invalid()
			}
			path := "/v1/sessions/" + url.PathEscape(args[2])
			if args[1] == "detach" {
				return "POST", path + "/detach", nil, nil
			}
			return "GET", path, nil, nil
		}
	case "peer":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "list" && len(args) == 2 {
			return "GET", "/v1/peers", nil, nil
		}
		if args[1] == "path" && len(args) == 3 {
			return "GET", "/v1/peers/" + url.PathEscape(args[2]) + "/path", nil, nil
		}
		if args[1] == "add" {
			var p host.Peer
			p.ID, _ = fs.GetString("id")
			p.PublicKey, _ = fs.GetString("public-key")
			p.Address, _ = fs.GetString("address")
			return "POST", "/v1/peers", p, nil
		}
	case "grant":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "list" && len(args) == 2 {
			return "GET", "/v1/grants", nil, nil
		}
		if args[1] == "revoke" && len(args) == 3 {
			return "POST", "/v1/grants/" + url.PathEscape(args[2]) + "/revoke", nil, nil
		}
		if args[1] == "create" {
			var g host.CreateGrant
			var fromAgent string
			fromAgent, _ = fs.GetString("from-agent")
			g.RequesterHostID, _ = fs.GetString("peer")
			g.TargetAgentID, _ = fs.GetString("agent")
			g.ExpiresAt, _ = fs.GetString("expires-at")
			g.MaxMessageBytes, _ = fs.GetInt64("max-message-bytes")
			g.MaxArtifactBytes, _ = fs.GetInt64("max-artifact-bytes")
			g.AllowDisconnected, _ = fs.GetBool("allow-disconnected")
			g.Action, _ = fs.GetString("action")
			g.RequesterAgentID = optional(fromAgent)
			g.Action = defaultAction(g.Action)
			return "POST", "/v1/grants", g, nil
		}
	case "message":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "list" {
			var after, limit int64
			after, _ = fs.GetInt64("after")
			limit, _ = fs.GetInt64("limit")
			return "GET", fmt.Sprintf("/v1/messages?after=%d&limit=%d", after, limit), nil, nil
		}
		if args[1] == "send" {
			var m host.SendMessage
			var grant, fromAgent, fromSession string
			var err error
			m.PeerHostID, _ = fs.GetString("peer")
			m.RequestID, _ = fs.GetString("request")
			grant, _ = fs.GetString("grant")
			m.TargetAgentID, _ = fs.GetString("agent")
			m.Deadline, _ = fs.GetString("deadline")
			if m.Deadline == "" {
				m.Deadline = expiryIn(messageDefaultDeadline)
			}
			m.Content, _ = fs.GetString("content")
			fromAgent, _ = fs.GetString("from-agent")
			fromSession, _ = fs.GetString("from-session")
			m.GrantID = optional(grant)
			if fromSession != "" && fromAgent == "" {
				err = errors.New("--from-session needs --from-agent")
			}
			if fromAgent != "" {
				m.Origin = &host.Origin{AgentID: fromAgent, SessionID: fromSession}
			}
			return "POST", "/v1/outbound", m, err
		}
		if args[1] == "inspect" || args[1] == "retry" || args[1] == "refresh" || args[1] == "reply" || args[1] == "origin" {
			peer, _ := fs.GetString("peer")
			if peer == "" || len(args) != 3 {
				return invalid()
			}
			path := "/v1/outbound/" + url.PathEscape(peer) + "/" + url.PathEscape(args[2])
			if args[1] == "inspect" {
				return "GET", path, nil, nil
			}
			if args[1] == "origin" {
				return "GET", path + "/origin", nil, nil
			}
			return "POST", path + "/" + args[1], nil, nil
		}
	case "task":
		if len(args) < 2 {
			return invalid()
		}
		switch args[1] {
		case "submit":
			var t host.SubmitTask
			var grant, fromAgent, fromSession, parentSender, parentTask string
			var files, types, delegateTo []string
			var err error
			t.DelegationDepth, _ = fs.GetInt64("delegation-depth")
			delegateTo, _ = fs.GetStringArray("delegate-to")
			parentSender, _ = fs.GetString("parent-sender")
			parentTask, _ = fs.GetString("parent-task")
			files, _ = fs.GetStringArray("artifact")
			types, _ = fs.GetStringArray("artifact-type")
			t.PeerHostID, _ = fs.GetString("peer")
			t.TargetAgentID, _ = fs.GetString("agent")
			t.Input, _ = fs.GetString("input")
			t.Deadline, _ = fs.GetString("deadline")
			grant, _ = fs.GetString("grant")
			fromAgent, _ = fs.GetString("from-agent")
			fromSession, _ = fs.GetString("from-session")
			t.TaskID, _ = fs.GetString("task")
			t.GrantID = optional(grant)
			if fromSession != "" && fromAgent == "" {
				err = errors.New("--from-session needs --from-agent")
			}
			if fromAgent != "" {
				t.Origin = &host.Origin{AgentID: fromAgent, SessionID: fromSession}
			}
			if len(types) > len(files) {
				err = errors.New("each --artifact-type needs a corresponding --artifact")
			}
			if len(delegateTo) > 0 {
				t.DelegationPrincipals = delegateTo
			}
			if (parentSender == "") != (parentTask == "") {
				err = errors.New("--parent-sender and --parent-task go together")
			}
			if parentSender != "" {
				t.Parent = &host.TaskParent{SenderHostID: parentSender, TaskID: parentTask}
			}
			if len(files) > 0 {
				return "POST", "/v1/tasks", taskSubmission{t, files, types}, err
			}
			return "POST", "/v1/tasks", t, err
		case "list":
			var after, limit int64
			after, _ = fs.GetInt64("after")
			limit, _ = fs.GetInt64("limit")
			return "GET", fmt.Sprintf("/v1/tasks?after=%d&limit=%d", after, limit), nil, nil
		case "inspect", "cancel", "events", "artifact":
			peer, _ := fs.GetString("peer")
			out := ""
			if args[1] == "artifact" {
				out, _ = fs.GetString("out")
			}
			var after, limit int64
			if args[1] == "events" {
				after, _ = fs.GetInt64("after")
				limit, _ = fs.GetInt64("limit")
			}
			positional := args[2:]

			if args[1] == "artifact" {
				if peer == "" || len(positional) != 2 || out == "" {
					return invalid()
				}
				return "GET", "/v1/tasks/" + url.PathEscape(peer) + "/" + url.PathEscape(positional[0]) + "/artifacts/" + url.PathEscape(positional[1]), artifactDownload{out}, nil
			}
			if peer == "" || len(positional) != 1 || out != "" {
				return invalid()
			}
			path := "/v1/tasks/" + url.PathEscape(peer) + "/" + url.PathEscape(positional[0])
			switch args[1] {
			case "inspect":
				return "GET", path, nil, nil
			case "cancel":
				return "POST", path + "/cancel", nil, nil
			}
			return "GET", fmt.Sprintf("%s/events?after=%d&limit=%d", path, after, limit), nil, nil
		}
	case "network":
		if len(args) < 2 {
			return invalid()
		}
		switch args[1] {
		case "invite":
			var network string
			var i host.CreateInvite
			network, _ = fs.GetString("network")
			i.Member, _ = fs.GetString("member")
			i.ExpiresAt, _ = fs.GetString("expires-at")
			i.HostOnly, _ = fs.GetBool("host-only")
			if network == "" {
				return invalid()
			}
			return "POST", "/v1/networks/" + url.PathEscape(network) + "/invites", i, nil
		case "move":
			var network string
			var req host.MoveNetwork
			network, _ = fs.GetString("network")
			req.CoordinatorAddress, _ = fs.GetString("coordinator")
			req.CoordinatorPublicKey, _ = fs.GetString("coordinator-key")
			if network == "" || req.CoordinatorAddress == "" || req.CoordinatorPublicKey == "" {
				return invalid()
			}
			return "POST", "/v1/networks/" + url.PathEscape(network) + "/move", req, nil
		case "admit", "redeem-person", "bind", "unbind":
			return "", "", nil, errPersonCommand
		case "delegate-admin", "remove-admin", "group", "groups":
			return "", "", nil, errAdminCommand
		case "invite-person":
			var network string
			var i host.CreateInvite
			network, _ = fs.GetString("network")
			i.Member, _ = fs.GetString("member")
			i.ExpiresAt, _ = fs.GetString("expires-at")
			if network == "" {
				return invalid()
			}
			return "POST", "/v1/networks/" + url.PathEscape(network) + "/person-invites", i, nil
		case "remove-person":
			var network string
			var req host.RemovePerson
			network, _ = fs.GetString("network")
			req.PersonID, _ = fs.GetString("person")
			if network == "" || req.PersonID == "" {
				return invalid()
			}
			return "POST", "/v1/networks/" + url.PathEscape(network) + "/person-removals", req, nil
		case "persons":
			if len(args) != 3 {
				return invalid()
			}
			return "GET", "/v1/networks/" + url.PathEscape(args[2]) + "/persons", nil, nil
		case "list":
			if len(args) != 2 {
				return invalid()
			}
			return "GET", "/v1/networks", nil, nil
		case "members", "sync", "leave", "rotate-root":
			if args[1] == "rotate-root" && (fs.Changed("to-ssh") || fs.Changed("root-key")) {
				return "", "", nil, errAdminCommand
			}
			if len(args) != 3 {
				return invalid()
			}
			path := "/v1/networks/" + url.PathEscape(args[2])
			switch args[1] {
			case "sync":
				return "POST", path + "/sync", nil, nil
			case "leave":
				return "POST", path + "/leave", nil, nil
			case "rotate-root":
				return "POST", path + "/rotate", nil, nil
			}
			return "GET", path + "/members", nil, nil
		case "revoke", "revoke-invite":
			var network string
			var req host.RevokeMembership
			network, _ = fs.GetString("network")
			if args[1] == "revoke" {
				req.HostID, _ = fs.GetString("host")
			} else {
				req.InvitePublicKey, _ = fs.GetString("invite")
			}
			if network == "" || req.HostID+req.InvitePublicKey == "" {
				return invalid()
			}
			return "POST", "/v1/networks/" + url.PathEscape(network) + "/revocations", req, nil
		}
	case "adapter":
		if len(args) < 2 {
			return invalid()
		}
		if len(args) == 3 && (args[1] == "rotate" || args[1] == "connection") {
			method := "GET"
			if args[1] == "rotate" {
				method = "POST"
			}
			return method, "/v1/adapters/" + url.PathEscape(args[2]) + "/" + args[1], nil, nil
		}
		if args[1] == "route" {
			if len(args) < 3 {
				return invalid()
			}
			if args[2] == "add" {
				var req host.CreateOutboundRoute
				var grant string
				req.AdapterID, _ = fs.GetString("adapter")
				req.Name, _ = fs.GetString("name")
				req.PeerHostID, _ = fs.GetString("peer")
				req.TargetAgentID, _ = fs.GetString("agent")
				grant, _ = fs.GetString("grant")
				req.ExpiresAt, _ = fs.GetString("expires-at")
				req.MaxMessageBytes, _ = fs.GetInt64("max-message-bytes")
				req.MaxMessages, _ = fs.GetInt64("max-messages")
				req.Action, _ = fs.GetString("action")
				req.DelegationDepth, _ = fs.GetInt64("delegation-depth")
				req.GrantID = optional(grant)
				req.Action = defaultAction(req.Action)
				return "POST", "/v1/adapter-routes", req, nil
			}
			if args[2] == "list" {
				var id string
				id, _ = fs.GetString("adapter")
				if id == "" {
					return invalid()
				}
				return "GET", "/v1/adapters/" + url.PathEscape(id) + "/routes", nil, nil
			}
			if args[2] == "revoke" && len(args) == 4 {
				return "POST", "/v1/adapter-routes/" + url.PathEscape(args[3]) + "/revoke", nil, nil
			}
			return invalid()
		}
		if args[1] == "create" {
			var req host.CreateAdapter
			req.SessionID, _ = fs.GetString("session")
			req.ExpiresAt, _ = fs.GetString("expires-at")
			return "POST", "/v1/adapters", req, nil
		}
		if args[1] == "list" && len(args) == 2 {
			return "GET", "/v1/adapters", nil, nil
		}
		if len(args) == 3 && (args[1] == "inspect" || args[1] == "revoke") {
			path := "/v1/adapters/" + url.PathEscape(args[2])
			if args[1] == "revoke" {
				return "POST", path + "/revoke", nil, nil
			}
			return "GET", path, nil, nil
		}
	case "delivery":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "inspect" && len(args) == 3 {
			return "GET", "/v1/deliveries/" + url.PathEscape(args[2]), nil, nil
		}
		if args[1] == "list" {
			var after, limit int64
			after, _ = fs.GetInt64("after")
			limit, _ = fs.GetInt64("limit")
			return "GET", fmt.Sprintf("/v1/deliveries?after=%d&limit=%d", after, limit), nil, nil
		}
	case "artifact":
		if len(args) == 2 && args[1] == "list" {
			return "GET", "/v1/artifacts", nil, nil
		}
		if len(args) == 2 && args[1] == "prune" {
			return "POST", "/v1/artifacts/prune", nil, nil
		}
	case "activity":
		var after int64
		var limit int
		after, _ = fs.GetInt64("after")
		limit, _ = fs.GetInt("limit")
		return "GET", fmt.Sprintf("/v1/activity?after=%d&limit=%d", after, limit), nil, nil
	}
	return invalid()
}

// defaultAction omits the default action, message.append, from a request.
func defaultAction(action string) string {
	if action == "message.append" {
		return ""
	}
	return action
}

// optional is nil for an empty flag value: the field is then omitted.
func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// taskSubmission is a task submit whose files are uploaded first.
type taskSubmission struct {
	host.SubmitTask
	files, types []string
}

// artifactDownload writes an artifact to a new file.
type artifactDownload struct{ out string }

// uploadArtifacts uploads each file, named after its base name, and returns
// the input manifest.
func uploadArtifacts(ctx context.Context, client host.Client, files, types []string) ([]host.ArtifactEntry, error) {
	var manifest []host.ArtifactEntry
	for i, path := range files {
		query := url.Values{"name": {filepath.Base(path)}}
		if i < len(types) {
			query.Set("media_type", types[i])
		}
		entry, err := uploadFile(ctx, client, path, query)
		if err != nil {
			return nil, fmt.Errorf("upload %s: %w", path, err)
		}
		manifest = append(manifest, entry)
	}
	return manifest, nil
}

func uploadFile(ctx context.Context, client host.Client, path string, query url.Values) (host.ArtifactEntry, error) {
	var entry host.ArtifactEntry
	f, err := os.Open(path)
	if err != nil {
		return entry, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return entry, err
	}
	if !info.Mode().IsRegular() {
		return entry, errors.New("an artifact must be a regular file")
	}
	data, err := client.Upload(ctx, "/v1/artifacts?"+query.Encode(), f, info.Size())
	if err != nil {
		return entry, err
	}
	err = json.Unmarshal(data, &entry)
	return entry, err
}

// downloadArtifact writes an artifact to a new private file at out; a
// failed download removes the partial file.
func downloadArtifact(ctx context.Context, client host.Client, path, out string) (json.RawMessage, error) {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	n, err := client.Download(ctx, path, io.MultiWriter(f, hash))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(out)
		return nil, err
	}
	return json.Marshal(map[string]any{"path": out, "sha256": hex.EncodeToString(hash.Sum(nil)), "size": n})
}

func runDaemon(ctx context.Context, fs *pflag.FlagSet, state string, errOut io.Writer) error {
	peerListen, _ := fs.GetString("peer-listen")
	advertise, _ := fs.GetString("advertise")
	interval, _ := fs.GetInt("coordination-interval")
	personAgent, _ := fs.GetString("person-agent")
	personKeyFile, _ := fs.GetString("person-key-file")
	artifactQuota, _ := fs.GetInt64("artifact-quota")
	if advertise != "" && peerListen == "" {
		return errors.New("--advertise requires --peer-listen")
	}
	if interval < 1 || interval > 3600 {
		return errors.New("--coordination-interval must be 1 to 3600 seconds")
	}
	if artifactQuota < 1 {
		return errors.New("--artifact-quota must be at least 1 byte")
	}
	store, err := host.Open(ctx, state)
	if err != nil {
		return err
	}
	defer store.Close()
	listener, err := store.Listen()
	if err != nil {
		return err
	}
	defer listener.Close()
	fmt.Fprintf(errOut, "host daemon %s listening on local control socket %s\n", store.Identity().ID, store.SocketPath())
	daemonCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var peerListener net.Listener
	if peerListen != "" {
		peerListener, err = store.ListenPeer(daemonCtx, peerListen)
		if err != nil {
			return err
		}
		defer peerListener.Close()
		if advertise == "" {
			if bound, err := netip.ParseAddrPort(peerListener.Addr().String()); err == nil && !bound.Addr().IsUnspecified() {
				advertise = bound.String()
			}
		}
		fmt.Fprintf(errOut, "peer listener %s (advertised %q)\n", peerListener.Addr(), advertise)
	}
	// Every member host keeps its coordinators' relay connections, which
	// carry change notifications; a listening host is also reachable there.
	go store.RunRelays(daemonCtx)
	if err = store.ConfigureCoordination(advertise, time.Duration(interval)*time.Second); err != nil {
		return err
	}
	store.ConfigurePersonAgent(personAgent)
	if !fs.Changed("person-key-file") {
		personKeyFile, _ = person.GeneratedKeyPath()
	}
	store.ConfigurePersonKeyFile(personKeyFile)
	if err = store.ConfigureArtifacts(artifactQuota); err != nil {
		return err
	}
	coordinationDone := make(chan struct{})
	go func() {
		defer close(coordinationDone)
		store.RunCoordination(daemonCtx, func(format string, args ...any) { fmt.Fprintf(errOut, format+"\n", args...) })
	}()
	defer func() { cancel(); <-coordinationDone }()
	repliesDone := make(chan struct{})
	go func() { defer close(repliesDone); store.RunReplyWorkers(daemonCtx) }()
	policiesDone := make(chan struct{})
	go func() {
		defer close(policiesDone)
		store.RunPolicySync(daemonCtx, func(format string, args ...any) { fmt.Fprintf(errOut, format+"\n", args...) })
	}()
	defer func() { cancel(); <-policiesDone }()
	directoryDone := make(chan struct{})
	go func() { defer close(directoryDone); store.RunDirectory(daemonCtx) }()
	defer func() { cancel(); <-directoryDone }()
	retriesDone := make(chan struct{})
	go func() { defer close(retriesDone); store.RunOutboundRetries(daemonCtx) }()
	defer func() { cancel(); <-retriesDone }()
	tasksDone := make(chan struct{})
	go func() {
		defer close(tasksDone)
		go store.RunTaskExpiry(daemonCtx)
		go store.RunArtifactRetention(daemonCtx)
		store.RunTaskWorkers(daemonCtx)
	}()
	defer func() { cancel(); <-tasksDone }()
	defer func() { cancel(); <-repliesDone }()
	adapterListener, err := store.ListenAdapter()
	if err != nil {
		return err
	}
	defer adapterListener.Close()
	results := make(chan error, 3)
	go func() { results <- host.ServeLocal(daemonCtx, listener, host.Handler(store)) }()
	go func() { results <- host.ServeLocal(daemonCtx, adapterListener, host.AdapterHandler(store)) }()
	count := 2
	if peerListener != nil {
		count++
		go func() { results <- host.Serve(daemonCtx, peerListener, host.PeerHandler(store)) }()
	}
	first := <-results
	cancel()
	for range count - 1 {
		first = errors.Join(first, <-results)
	}
	return first
}
