package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

// Sources, capabilities, and calls on the owner's CLI: discovery for attach
// and sources refresh, owner calls, and trusted hosts. Capability commands
// and sharing are in capabilities_cli.go.

// sourcesAgent is AGENT of GET /v1/sources, as the CLI reads it.
type sourcesAgent struct {
	Agent struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"agent"`
	Workspace *string        `json:"workspace"`
	Servers   []sourceServer `json:"servers"`
	// AgentID and AgentName mirror Agent.
	AgentID, AgentName string `json:"-"`
}

type sourceServer struct {
	Name          string                  `json:"name"`
	Transport     string                  `json:"transport"`
	Source        string                  `json:"source"`
	Shareable     bool                    `json:"shareable"`
	Reason        *string                 `json:"reason"`
	MissingEnv    []string                `json:"missing_env"`
	Tools         []host.SnapshotTool     `json:"tools"`
	Resources     []host.SnapshotResource `json:"resources"`
	SnapshotError *string                 `json:"snapshot_error"`
	Capabilities  []string                `json:"capabilities"`
	URL           *string                 `json:"url"`
	Headers       map[string]host.ToolEnv `json:"headers"`
	Auth          *host.AuthView          `json:"auth"`
}

// sourcesListing is GET /v1/sources.
type sourcesListing struct {
	Agents  []sourcesAgent       `json:"agents"`
	Builtin []builtinSourcesView `json:"builtin"`
	OpenTo  []string             `json:"open_to"`
}

// readSources reads GET /v1/sources.
func readSources(ctx context.Context, client host.Client, path string) (sourcesListing, error) {
	listing, err := call[sourcesListing](ctx, client, "GET", path)
	for i := range listing.Agents {
		listing.Agents[i].fill()
	}
	return listing, err
}

func (a *sourcesAgent) fill() { a.AgentID, a.AgentName = a.Agent.ID, a.Agent.Name }

func (a sourcesAgent) server(name string) *sourceServer {
	for i := range a.Servers {
		if a.Servers[i].Name == name {
			return &a.Servers[i]
		}
	}
	return nil
}

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// stdin reads stdin a line at a time, shared by every prompt of a command.
var stdin = bufio.NewReader(os.Stdin)

// stdinLine is one line read from stdin, or its end.
type stdinLine struct {
	text string
	err  error
}

var (
	stdinOnce  sync.Once
	stdinLines chan stdinLine
)

// lineSource delivers stdin's lines, read by one goroutine, so a prompt
// and a wait that also listens elsewhere never compete for a line. The
// channel closes at the end of stdin.
func lineSource() chan stdinLine {
	stdinOnce.Do(func() {
		stdinLines = make(chan stdinLine)
		go func() {
			for {
				line, err := stdin.ReadString('\n')
				stdinLines <- stdinLine{line, err}
				if err != nil {
					close(stdinLines)
					return
				}
			}
		}()
	})
	return stdinLines
}

// readLine reads one answer from stdin.
func readLine() string {
	line := <-lineSource()
	return strings.TrimSpace(line.text)
}

// askYes prompts at a terminal and reads one answer; only y or yes agrees.
func askYes(errOut io.Writer, prompt string) bool {
	fmt.Fprint(errOut, prompt+" [y/N] ")
	answer := strings.ToLower(readLine())
	return answer == "y" || answer == "yes"
}

// attachSummary is attach's sources: {servers, errors}.
type attachSummary struct {
	Servers []attachServer   `json:"servers"`
	Errors  []discoveryError `json:"errors"`
	// Builtin lists the built-in sources, in attach's output only.
	Builtin *[]attachServer `json:"builtin,omitempty"`
}

type attachServer struct {
	Name          string   `json:"name"`
	Transport     string   `json:"transport"`
	Shareable     bool     `json:"shareable"`
	Reason        *string  `json:"reason"`
	MissingEnv    []string `json:"missing_env"`
	Tools         int      `json:"tools"`
	ReadOnlyTools int      `json:"read_only_tools"`
	SnapshotError *string  `json:"snapshot_error"`
}

// discoverAndStore runs discovery for one agent and stores the result.
func discoverAndStore(ctx context.Context, client host.Client, agentID, integrationID, workspace string) (sourcesAgent, []discoveryError, error) {
	d := discoverServers(integrationID, workspace)
	errs := d.errors
	if errs == nil {
		errs = []discoveryError{}
	}
	data, err := client.Call(ctx, "PUT", "/v1/agents/"+url.PathEscape(agentID)+"/tool-servers", d.put)
	if err != nil {
		return sourcesAgent{}, errs, err
	}
	var stored sourcesAgent
	err = json.Unmarshal(data, &stored)
	stored.fill()
	return stored, errs, err
}

// summarize is attach's sources output and its readable line.
func summarize(stored sourcesAgent, errs []discoveryError) (attachSummary, string) {
	summary := attachSummary{Servers: []attachServer{}, Errors: errs}
	var names []string
	for _, s := range stored.Servers {
		readOnly := 0
		for _, t := range s.Tools {
			if t.ReadOnly {
				readOnly++
			}
		}
		missing := s.MissingEnv
		if missing == nil {
			missing = []string{}
		}
		summary.Servers = append(summary.Servers, attachServer{s.Name, s.Transport, s.Shareable, s.Reason, missing, len(s.Tools), readOnly, s.SnapshotError})
		name := s.Name
		switch {
		case s.Shareable:
		case deref(s.Reason) == "remote":
			name += " (remote, not usable yet)"
		case deref(s.Reason) == "login":
			name += " (needs a sign-in: peerspan sources login " + stored.AgentName + "/" + s.Name + ")"
		case deref(s.Reason) == "insecure_url" || deref(s.Reason) == "sse" || deref(s.Reason) == "headers_helper":
			name += " (" + deref(s.Reason) + ")"
		case deref(s.Reason) == "missing_env":
			name += " (missing " + strings.Join(s.MissingEnv, ", ") + ")"
		case deref(s.Reason) == "disabled":
			name += " (disabled)"
		default:
			name += " (invalid name)"
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return summary, "No MCP sources found."
	}
	return summary, "Sources found: " + strings.Join(names, ", ") + ". Share one with: peerspan share --with PERSON"
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// attachSources runs attach's discovery after its setup succeeded; failures
// are reported in errors, not as a failed attach.
func attachSources(ctx context.Context, client host.Client, agentID, integrationID, workspace string, errOut io.Writer) attachSummary {
	stored, errs, err := discoverAndStore(ctx, client, agentID, integrationID, workspace)
	if err != nil {
		errs = append(errs, discoveryError{Source: integrationID, Error: "storing the discovered sources failed: " + err.Error()})
	}
	summary, line := summarize(stored, errs)
	fmt.Fprintln(errOut, line)
	// Built-in discovery follows; a failure is reported, not fatal.
	entries := []attachServer{}
	summary.Builtin = &entries
	if builtin, err := storeBuiltin(ctx, client); err != nil {
		summary.Errors = append(summary.Errors, discoveryError{Source: "builtin", Error: "storing the built-in sources failed: " + err.Error()})
	} else {
		entries = summarizeBuiltin(builtin)
		summary.Builtin = &entries
		if len(builtin) > 0 {
			var names []string
			for _, b := range builtin {
				names = append(names, "builtin/"+b.Name)
			}
			fmt.Fprintln(errOut, "Built-in sources: "+strings.Join(names, ", ")+".")
		}
	}
	return summary
}

// parseWait reads N, Ns, or Nm, from 0 to 15 minutes.
func parseWait(value string) (time.Duration, error) {
	digits, unit := value, time.Second
	switch {
	case strings.HasSuffix(value, "s"):
		digits = strings.TrimSuffix(value, "s")
	case strings.HasSuffix(value, "m"):
		digits, unit = strings.TrimSuffix(value, "m"), time.Minute
	}
	n, err := strconv.Atoi(digits)
	if err != nil || digits == "" || strings.ContainsAny(digits, "+-") || n > 900 {
		return 0, fmt.Errorf("invalid duration %q; give N, Ns, or Nm, at most 15 minutes", value)
	}
	d := time.Duration(n) * unit
	if d > 15*time.Minute {
		return 0, errors.New("the duration must be 0 to 15 minutes")
	}
	return d, nil
}

// callOutcome is the exit code for a local call record: 0 succeeded, 1
// another final state, 3 still pending.
func callOutcome(out host.OutboundCall) int {
	switch {
	case out.SubmitState == "rejected":
		return 1
	case out.Status != nil && out.Status.State == host.CallSucceeded:
		return 0
	case out.Status != nil && (out.Status.State == host.CallFailed || out.Status.State == host.CallRejected || out.Status.State == host.CallExpired || out.Status.State == host.CallCancelled || out.Status.State == host.CallUncertain):
		return 1
	}
	return 3
}

// callArgs is call's command line: its own flags, the --KEY VALUE options,
// and ADDRESS OPERATION.
type callArgs struct {
	state, input, deadline, wait, network string
	fromAgent, fromSession                string
	inputGiven                            bool
	options                               [][2]string
	positional                            []string
	help                                  bool
}

// parseCallArgs reads call's arguments by hand, because --KEY VALUE options
// name the operation's input properties. --input, --deadline, --wait,
// --network, and --state are always call's own.
func parseCallArgs(args []string) (callArgs, error) {
	c := callArgs{wait: "60s"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			c.positional = append(c.positional, args[i+1:]...)
			break
		}
		if arg == "-h" || arg == "--help" {
			c.help = true
			continue
		}
		if !strings.HasPrefix(arg, "--") || len(arg) == 2 {
			c.positional = append(c.positional, arg)
			continue
		}
		key, value, inline := strings.Cut(arg[2:], "=")
		if !inline {
			if i+1 >= len(args) {
				return c, fmt.Errorf("--%s needs a value", key)
			}
			i++
			value = args[i]
		}
		switch key {
		case "state":
			c.state = value
		case "input":
			c.input, c.inputGiven = value, true
		case "deadline":
			c.deadline = value
		case "wait":
			c.wait = value
		case "network":
			c.network = value
		case "from-agent":
			c.fromAgent = value
		case "from-session":
			c.fromSession = value
		default:
			if key == "" {
				return c, errors.New("an option needs a name")
			}
			c.options = append(c.options, [2]string{key, value})
		}
	}
	return c, nil
}

// buildInput is the input object: --input, with each --KEY VALUE filling a
// top-level scalar property of the operation's input schema.
func buildInput(input string, options [][2]string, schema json.RawMessage) (json.RawMessage, error) {
	object := map[string]json.RawMessage{}
	if input != "" {
		if err := json.Unmarshal([]byte(input), &object); err != nil || object == nil {
			return nil, errors.New("--input must be a JSON object")
		}
	}
	var properties struct {
		Properties map[string]struct {
			Type any `json:"type"`
		} `json:"properties"`
	}
	_ = json.Unmarshal(schema, &properties)
	for _, option := range options {
		key, value := option[0], option[1]
		if _, ok := object[key]; ok {
			return nil, fmt.Errorf("--%s is also given in --input", key)
		}
		property, ok := properties.Properties[key]
		kind, _ := property.Type.(string)
		if !ok {
			return nil, fmt.Errorf("--%s: the operation's input has no property %s", key, key)
		}
		var encoded any
		switch kind {
		case "string":
			encoded = value
		case "integer":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("--%s takes an integer", key)
			}
			encoded = n
		case "number":
			f, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return nil, fmt.Errorf("--%s takes a number", key)
			}
			encoded = f
		case "boolean":
			switch value {
			case "true":
				encoded = true
			case "false":
				encoded = false
			default:
				return nil, fmt.Errorf("--%s takes true or false", key)
			}
		default:
			return nil, fmt.Errorf("--%s: property %s is not a string, integer, number, or boolean; give it in --input", key, key)
		}
		data, _ := json.Marshal(encoded)
		object[key] = data
	}
	data, err := json.Marshal(object)
	return data, err
}

// operationSchema finds an operation's input schema in the listing of the
// address's host or person.
func operationSchema(ctx context.Context, client host.Client, address, operation, network string, origin *host.Origin) (json.RawMessage, error) {
	left, capability, found := strings.Cut(address, "/")
	if !found {
		return nil, fmt.Errorf("invalid address %q", address)
	}
	query := url.Values{}
	if network != "" {
		query.Set("network", network)
	}
	byHost := strings.HasPrefix(left, "host_")
	if !byHost {
		query.Set("person", left)
	}
	if origin != nil {
		// A call as an agent takes the schema from that agent's view.
		query.Set("from_agent", origin.AgentID)
		list, err := call[host.AdapterCapabilities](ctx, client, "GET", "/v1/discover?"+query.Encode())
		if err != nil {
			return nil, err
		}
		var found []host.AdapterCapability
		for _, e := range list.Capabilities {
			if (byHost && e.Capability == capability && e.HostID == left) || (!byHost && e.Address == address) {
				found = append(found, e)
			}
		}
		if len(found) != 1 {
			return nil, fmt.Errorf("%s does not name exactly one capability; --KEY options need its input schema", address)
		}
		for _, op := range found[0].Operations {
			if op.Name == operation {
				return op.InputSchema, nil
			}
		}
		return nil, fmt.Errorf("%s has no operation %s", address, operation)
	}
	d, err := call[host.Discovery](ctx, client, "GET", "/v1/discover?"+query.Encode())
	if err != nil {
		return nil, err
	}
	var matches []host.DiscoveredCapability
	for _, e := range d.Capabilities {
		// A person's entry matches by its discover address, which is by
		// host ID for a person whose label contains '/'.
		if (byHost && e.Capability == capability && e.HostID == left) || (!byHost && e.Address == address) {
			matches = append(matches, e)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("%s does not name exactly one capability; --KEY options need its input schema", address)
	}
	for _, op := range matches[0].Operations {
		if op.Name == operation {
			return op.InputSchema, nil
		}
	}
	return nil, fmt.Errorf("%s has no operation %s", address, operation)
}

// runCall runs call ADDRESS OPERATION: it submits the call, waits for a
// final state, and prints the local record.
func runCall(ctx context.Context, client host.Client, c callArgs, out, errOut io.Writer) error {
	if len(c.positional) != 2 {
		return errors.New("call takes ADDRESS OPERATION")
	}
	address, operation := c.positional[0], c.positional[1]
	if c.fromSession != "" && c.fromAgent == "" {
		return errors.New("--from-session needs --from-agent")
	}
	var origin *host.Origin
	if c.fromAgent != "" {
		agent, err := localAgentID(ctx, client, c.fromAgent)
		if err != nil {
			return err
		}
		origin = &host.Origin{AgentID: agent, SessionID: c.fromSession}
	}
	wait, err := parseWait(c.wait)
	if err != nil {
		return fmt.Errorf("--wait: %w", err)
	}
	deadline := c.deadline
	if deadline != "" {
		if _, err := time.Parse(time.RFC3339, deadline); err != nil {
			d, err := parseWait(deadline)
			if err != nil {
				return fmt.Errorf("--deadline takes RFC3339 or N, Ns, or Nm")
			}
			deadline = time.Now().Add(d).UTC().Format(time.RFC3339Nano)
		}
	}
	input := json.RawMessage("{}")
	if c.inputGiven || len(c.options) > 0 {
		var schema json.RawMessage
		if len(c.options) > 0 {
			if schema, err = operationSchema(ctx, client, address, operation, c.network, origin); err != nil {
				return err
			}
		}
		if input, err = buildInput(c.input, c.options, schema); err != nil {
			return err
		}
	}
	body := host.SubmitCall{Target: address, Operation: operation, Input: input, Deadline: deadline, Network: c.network, Origin: origin}
	data, err := client.Call(ctx, "POST", "/v1/calls", body)
	if err != nil {
		return err
	}
	var record host.OutboundCall
	if err = json.Unmarshal(data, &record); err != nil {
		return err
	}
	until := time.Now().Add(wait)
	// A final status from the submit response carries no result; the
	// daemon's poll fetches it, so wait for that too.
	resultPending := func() bool {
		st := record.Status
		return record.SubmitState == "accepted" && st != nil && record.Result == nil && st.ResultBytes != nil && deref(st.Error) != "result_too_large"
	}
	for (callOutcome(record) == 3 || resultPending()) && time.Now().Before(until) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(time.Second, time.Until(until))):
		}
		data, err = client.Call(ctx, "GET", "/v1/calls/"+url.PathEscape(record.PeerHostID)+"/"+url.PathEscape(record.Request.CallID), nil)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(data, &record); err != nil {
			return err
		}
	}
	if err = printJSON(out, json.RawMessage(data)); err != nil {
		return err
	}
	code := callOutcome(record)
	if st := record.Status; code == 3 && st != nil && st.Approval != nil && st.Approval.State == host.ApprovalPending {
		// OWNER is the PERSON of a PERSON/CAPABILITY address, and otherwise
		// the host ID.
		owner := record.PeerHostID
		if left, _, ok := strings.Cut(address, "/"); ok && !strings.HasPrefix(left, "host_") {
			owner = left
		}
		fmt.Fprintf(errOut, "Waiting for %s to approve this call (until %s). Check it later with peerspan calls inspect --peer %s %s.\n", owner, st.Approval.ExpiresAt, record.PeerHostID, record.Request.CallID)
	}
	if code != 0 {
		return exitStatus(code)
	}
	return nil
}

// executeCall runs call against the daemon of the state directory.
func executeCall(ctx context.Context, c callArgs, out, errOut io.Writer) error {
	state := c.state
	if state == "" {
		var err error
		if state, err = host.DefaultStateDir(); err != nil {
			return err
		}
	}
	return runCall(ctx, host.Client{SocketPath: filepath.Join(state, "admin.sock")}, c, out, errOut)
}

// callsRequest builds calls list, received, inspect, and cancel.
func callsRequest(args []string, fs *pflag.FlagSet) (string, string, error) {
	if len(args) < 2 {
		return "", "", invalidCommand()
	}
	switch args[1] {
	case "list", "received":
		after, _ := fs.GetInt64("after")
		limit, _ := fs.GetInt64("limit")
		path := "/v1/calls"
		if args[1] == "received" {
			path += "/received"
		}
		return "GET", fmt.Sprintf("%s?after=%d&limit=%d", path, after, limit), nil
	case "inspect", "cancel":
		peer, _ := fs.GetString("peer")
		if peer == "" || len(args) != 3 {
			return "", "", errors.New("calls " + args[1] + " needs --peer HOST and a call ID")
		}
		path := "/v1/calls/" + url.PathEscape(peer) + "/" + url.PathEscape(args[2])
		if args[1] == "cancel" {
			return "POST", path + "/cancel", nil
		}
		return "GET", path, nil
	}
	return "", "", invalidCommand()
}

// ownerContext loads the signing person key and this network's view of the
// owner: the current persons, the owner's person ID, and the starting point
// of an edit, from the daemon's edit route (Concurrent edits).
type ownerContext struct {
	signer   person.Signer
	device   *host.LinkSignerView
	ownerKey string
	persons  []host.Person
	ownerID  string
	network  string
	hostID   string
	// current is the edit's starting point; version is the stored version
	// and seq the reserved edit number, 0 when the signer is not this
	// host's person and the edit route does not apply.
	current *membership.Policy
	version uint64
	seq     int64
	// validFor, when set, is the signed duration instead.
	validFor time.Duration
}

func loadOwner(ctx context.Context, client host.Client, network, keyPath string) (*ownerContext, error) {
	var selected *host.LinkSignerView
	if keyPath == "" {
		view, err := call[host.LinkSignerView](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/link-signer")
		var failure *host.ClientError
		if err == nil {
			selected = &view
		} else if !errors.As(err, &failure) || failure.Status != 404 {
			return nil, err
		}
	}
	if selected != nil {
		o := &ownerContext{device: selected, ownerKey: selected.PersonPublicKey, network: network}
		var err error
		if o.persons, err = personsOf(ctx, client, network); err != nil {
			return nil, err
		}
		for _, p := range o.persons {
			if p.PublicKey == o.ownerKey {
				o.ownerID = p.PersonID
			}
		}
		if o.ownerID == "" {
			return nil, errors.New("the selected device's stable person requires repair")
		}
		if err = o.start(ctx, client); err != nil {
			return nil, err
		}
		return o, nil
	}
	signer, err := person.Load(keyPath)
	if err != nil {
		return nil, err
	}
	o := &ownerContext{signer: signer, network: network, ownerKey: membership.EncodeKey(signer.PublicKey())}
	if o.persons, err = personsOf(ctx, client, network); err != nil {
		signer.Close()
		return nil, err
	}
	owner := membership.EncodeKey(signer.PublicKey())
	activeFeature := false
	if keyPath != "" {
		_, e := call[host.LinkAccessVersions](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/link-access-versions")
		if e == nil {
			activeFeature = true
		} else {
			var failure *host.ClientError
			if !errors.As(e, &failure) || failure.Status != http.StatusUpgradeRequired || failure.Code != "upgrade_required" {
				signer.Close()
				return nil, e
			}
		}
	}
	if activeFeature {
		identity, e := call[host.Identity](ctx, client, "GET", "/v1/host")
		if e != nil {
			signer.Close()
			return nil, e
		}
		members, e := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/members")
		if e != nil {
			signer.Close()
			return nil, e
		}
		for _, member := range members {
			if member.HostID == identity.ID && member.PersonID != nil && *member.PersonID != membership.PersonID(signer.PublicKey()) {
				signer.Close()
				return nil, errors.New("the explicit original key does not match this machine's bound person")
			}
		}
	}
	for _, p := range o.persons {
		if p.PublicKey == owner {
			o.ownerID = p.PersonID
		}
	}
	if o.ownerID == "" {
		signer.Close()
		return nil, fmt.Errorf("the person key %s is not a current person of that network", membership.PersonID(signer.PublicKey()))
	}
	if err = o.start(ctx, client); err != nil {
		signer.Close()
		return nil, err
	}
	return o, nil
}

func (o *ownerContext) close() {
	if o.signer != nil {
		_ = o.signer.Close()
	}
}

// editStart is the edit route's answer.
type editStart struct {
	Policy  json.RawMessage `json:"policy"`
	Version uint64          `json:"version"`
	Seq     int64           `json:"seq"`
}

// start gets the edit's starting point from GET .../policy/edit, reserving
// an edit number. When this host is not bound to the signing person, it
// starts from that person's stored policy instead, without an edit number.
func (o *ownerContext) start(ctx context.Context, client host.Client) error {
	if o.hostID == "" {
		identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
		if err != nil {
			return err
		}
		o.hostID = identity.ID
	}
	bound := false
	if members, err := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(o.network)+"/members"); err == nil {
		for _, m := range members {
			if m.HostID == o.hostID && m.PersonID != nil && *m.PersonID == o.ownerID {
				bound = true
			}
		}
	}
	if bound {
		start, err := call[editStart](ctx, client, "GET", policyPath(o.network)+"/edit")
		if err != nil {
			return err
		}
		o.current, o.version, o.seq = nil, start.Version, start.Seq
		if len(start.Policy) > 0 && string(start.Policy) != "null" {
			p, err := membership.DecodePolicy(start.Policy)
			if err != nil {
				return err
			}
			o.current = &p
		}
		return nil
	}
	current, err := currentPolicy(ctx, client, o.network, o.ownerID)
	if err != nil {
		return err
	}
	o.current, o.version, o.seq = current, 0, 0
	if current != nil {
		o.version = current.Version
	}
	versions, versionErr := call[host.LinkAccessVersions](ctx, client, "GET", "/v1/networks/"+url.PathEscape(o.network)+"/link-access-versions")
	if versionErr == nil {
		for _, policy := range versions.Policies {
			if policy.PersonPublicKey == o.ownerKey {
				o.version = max(o.version, policy.Version)
			}
		}
	} else {
		var failure *host.ClientError
		if !errors.As(versionErr, &failure) || failure.Status != 426 && failure.Status != 404 {
			return versionErr
		}
	}
	return nil
}

// next signs the owner's next policy version with body, as an edit with
// this host's reserved number; keep keeps the starting point's duration,
// otherwise it is valid for 7 days.
func (o *ownerContext) next(network string, body membership.PolicyBody, keep bool) (membership.Policy, error) {
	version, err := membership.NextAccessVersion(o.version)
	if err != nil {
		return membership.Policy{}, err
	}
	validFor := 7 * 24 * time.Hour
	if o.current != nil && keep {
		issued, _ := membership.ParseTime(o.current.IssuedAt)
		until, _ := membership.ParseTime(o.current.ValidUntil)
		validFor = until.Sub(issued)
	}
	if o.validFor > 0 {
		validFor = o.validFor
	}
	if o.seq > 0 {
		body.Edits = membership.WithEdit(body.Edits, o.hostID, o.seq)
	}
	if o.device != nil {
		issued := time.Now().UTC().Truncate(time.Second)
		until := issued.Add(validFor)
		if limit, err := membership.ParseTime(o.device.NotAfter); err == nil && until.After(limit) {
			until = limit
		}
		p := membership.Policy{Format: 2, NetworkID: network, PersonPublicKey: o.ownerKey, Version: version, IssuedAt: issued.Format(time.RFC3339), ValidUntil: until.Format(time.RFC3339), Rules: body.Rules, CapabilityRules: body.CapabilityRules, TrustedHosts: body.TrustedHosts, Edits: body.Edits, Signature: "-"}
		return p, membership.CheckPolicy(network, p)
	}
	return membership.SignPolicyV2(o.signer, network, version, time.Now().Truncate(time.Second), validFor, body)
}

func (o *ownerContext) submit(ctx context.Context, client host.Client, policy membership.Policy) (json.RawMessage, error) {
	if o.device == nil {
		return client.Call(ctx, "POST", policyPath(o.network), host.SubmitPolicy{Policy: &policy})
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "signature")
	raw, err = json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	_, err = client.Call(ctx, "POST", "/v1/networks/"+url.PathEscape(o.network)+"/link-actions", host.LinkActionRequest{Kind: "peerspan-policy-v2", PayloadBase64: base64.StdEncoding.EncodeToString(raw), CertificateID: o.device.CertificateID})
	if err != nil {
		return nil, err
	}
	return client.Call(ctx, "GET", policyPath(o.network)+"?"+url.Values{"person": {o.ownerID}}.Encode(), nil)
}

func (o *ownerContext) body() membership.PolicyBody {
	if o.current == nil {
		return membership.PolicyBody{Rules: []membership.PolicyRule{}, CapabilityRules: []membership.CapabilityRule{}, TrustedHosts: []string{}, Edits: []membership.PolicyEdit{}}
	}
	// Rules of one agent with identical settings combine as v2.
	return membership.CombineDuplicateRules(o.current.Body())
}

// editRetries is how many times an edit refused as edit_conflict starts
// again from the edit route.
const editRetries = 3

func isEditConflict(err error) bool {
	var failure *host.ClientError
	return errors.As(err, &failure) && failure.Status == 409 && failure.Code == "edit_conflict"
}

// edit applies change to the starting point, signs, and submits it,
// starting again from the edit route after an edit_conflict, at most 3
// times. change reports whether anything changed; when nothing does,
// nothing is signed and the starting point is returned.
func (o *ownerContext) edit(ctx context.Context, client host.Client, keep bool, change func(body *membership.PolicyBody) (bool, error)) (json.RawMessage, bool, error) {
	for attempt := 0; ; attempt++ {
		body := o.body()
		changed, err := change(&body)
		if err != nil {
			return nil, false, err
		}
		if !changed {
			data, err := json.Marshal(o.current)
			return data, false, err
		}
		p, err := o.next(o.network, body, keep)
		if err != nil {
			return nil, false, err
		}
		data, err := o.submit(ctx, client, p)
		if isEditConflict(err) && attempt < editRetries {
			if err = o.start(ctx, client); err != nil {
				return nil, false, err
			}
			continue
		}
		return data, err == nil, err
	}
}

func contains(list []string, value string) bool {
	for _, x := range list {
		if x == value {
			return true
		}
	}
	return false
}

func dedupe(list []string) []string {
	var out []string
	for _, x := range list {
		if !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// runTrust runs trust [HOST] and untrust HOST: it adds the host to, or
// removes it from, trusted_hosts of this person's policy in the network.
func runTrust(ctx context.Context, client host.Client, command string, args []string, fs *pflag.FlagSet, out io.Writer) error {
	network, _ := fs.GetString("network")
	keyPath, _ := fs.GetString("person-key")
	target := ""
	if len(args) > 1 {
		target = args[1]
	}
	if target == "" {
		identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
		if err != nil {
			return err
		}
		target = identity.ID
	}
	if !membership.ValidHostID(target) {
		return fmt.Errorf("invalid host ID %q", target)
	}
	o, err := loadOwner(ctx, client, network, keyPath)
	if err != nil {
		return err
	}
	defer o.close()
	if command == "trust" {
		members, err := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/members")
		if err != nil {
			return err
		}
		bound := false
		for _, m := range members {
			if m.HostID == target && m.PersonID != nil && *m.PersonID == o.ownerID {
				bound = true
			}
		}
		if !bound {
			return fmt.Errorf("host %s is not bound to you (%s) in network %s", target, o.ownerID, network)
		}
	}
	trusted := command == "trust"
	if contains(o.body().TrustedHosts, target) == trusted {
		// Nothing changes, so nothing is signed.
		var policy any
		if o.current != nil {
			policy = o.current
		}
		return printJSON(out, map[string]any{"policy": policy, "host": target, "trusted": trusted, "changed": false})
	}
	data, changed, err := setTrusted(ctx, client, o, target, trusted)
	if err != nil {
		return err
	}
	return printJSON(out, map[string]any{"policy": json.RawMessage(data), "host": target, "trusted": trusted, "changed": changed})
}

// setTrusted signs and submits the next policy version with host added to
// or removed from trusted_hosts.
func setTrusted(ctx context.Context, client host.Client, o *ownerContext, target string, trusted bool) (json.RawMessage, bool, error) {
	return o.edit(ctx, client, true, func(body *membership.PolicyBody) (bool, error) {
		if contains(body.TrustedHosts, target) == trusted {
			return false, nil
		}
		hosts := []string{}
		for _, h := range body.TrustedHosts {
			if h != target {
				hosts = append(hosts, h)
			}
		}
		if trusted {
			hosts = append(hosts, target)
		}
		body.TrustedHosts = hosts
		return true, nil
	})
}

// joinTrust applies join's and network create's --trusted and --untrusted:
// when this host was bound to a person, it asks at a terminal unless a flag
// answers, and a yes adds the host to trusted_hosts in the network's policy.
func joinTrust(ctx context.Context, client host.Client, fs *pflag.FlagSet, signer person.Signer, result map[string]any, errOut io.Writer) {
	result["trusted"] = false
	outcome, _ := result["person"].(map[string]any)
	if signer == nil || outcome == nil || outcome["bound"] != true {
		return
	}
	network, _ := result["id"].(string)
	trusted, _ := fs.GetBool("trusted")
	untrusted, _ := fs.GetBool("untrusted")
	yes := trusted
	if !trusted && !untrusted && isTerminal(os.Stdin) {
		yes = askYes(errOut, "Let this machine use your capabilities on your other machines, and the tools of those that allow it?")
	}
	if !yes {
		fmt.Fprintln(errOut, "This machine is not trusted for your capabilities on your other machines. Note that any host holding your person key can sign a policy that marks itself trusted; untrusted marking protects only against hosts without the key, such as hosts bound through ssh-agent forwarding.")
		return
	}
	identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
	if err == nil {
		o := &ownerContext{signer: signer, ownerID: membership.PersonID(signer.PublicKey()), network: network, hostID: identity.ID}
		if err = o.start(ctx, client); err == nil {
			_, _, err = setTrusted(ctx, client, o, identity.ID, true)
		}
	}
	if err != nil {
		result["trusted_error"] = err.Error()
		return
	}
	result["trusted"] = true
}
