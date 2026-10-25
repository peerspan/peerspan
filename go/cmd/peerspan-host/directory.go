package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/integration"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/spf13/pflag"
)

// Directory and addressing (milestone 7, slice 4): attach, agents, and
// sending by address.

// directoryOf reads, or with refresh first refreshes, one network's
// directory.
func directoryOf(ctx context.Context, client host.Client, network string, refresh bool) (host.Directory, error) {
	var d host.Directory
	path := "/v1/directory?" + url.Values{"network": {network}}.Encode()
	var data json.RawMessage
	var err error
	if refresh {
		data, err = client.Call(ctx, "POST", "/v1/directory/refresh?"+url.Values{"network": {network}}.Encode(), map[string]any{})
	} else {
		data, err = client.Call(ctx, "GET", path, nil)
	}
	if err == nil {
		err = json.Unmarshal(data, &d)
	}
	return d, err
}

// hostPersons is this host's bound person per network, from status.
type hostPersons struct {
	ids    map[string]string
	labels map[string]string
	// label is the person label in the first network by ID that binds this
	// host, or "".
	label string
}

func readHostPersons(ctx context.Context, client host.Client) (host.Status, hostPersons, error) {
	st, err := call[host.Status](ctx, client, "GET", "/v1/status")
	p := hostPersons{ids: map[string]string{}, labels: map[string]string{}}
	if err != nil {
		return st, p, err
	}
	for _, n := range st.Networks {
		if n.Person == nil {
			continue
		}
		p.ids[n.ID] = n.Person.ID
		if n.Person.Label != nil {
			p.labels[n.ID] = *n.Person.Label
			if p.label == "" {
				p.label = *n.Person.Label
			}
		}
	}
	return st, p, nil
}

// namePart lowercases a name part and replaces characters outside the
// addressable set with '-'.
func namePart(text string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(text) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// fittedName joins parts with '-' and appends tail, cutting the parts from
// the end so the name fits in 64 characters: the host name (parts[1])
// first, then the project (parts[2]), then the base (parts[0]), each down
// to 1 character before the next. The tail is never cut.
func fittedName(parts []string, tail string) string {
	cut := slices.Clone(parts)
	length := func() int { return len(strings.Join(cut, "-")) + len(tail) }
	for _, i := range []int{1, 2, 0} {
		if i >= len(cut) {
			continue
		}
		if over := length() - 64; over > 0 {
			cut[i] = cut[i][:max(1, len(cut[i])-over)]
		}
	}
	return strings.Join(cut, "-") + tail
}

// namePartOr is namePart, or fallback when that leaves no letter or digit.
func namePartOr(text, fallback string) string {
	part := namePart(text)
	if strings.IndexFunc(part, func(c rune) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }) < 0 {
		return fallback
	}
	return part
}

// defaultAgentName is the first free default name for attach:
// BASE-HOSTNAME, else BASE-HOSTNAME-PROJECT when that is used on this
// host, or BASE-HOSTNAME-HHHH with a growing prefix of the host ID when it
// is used only on another host, then the last of these with -2, -3, and so
// on.
func defaultAgentName(base, hostname, project, hostID string, usedHere, free func(string) bool) string {
	hostname, _, _ = strings.Cut(hostname, ".")
	parts := []string{base, namePartOr(hostname, "host")}
	first := fittedName(parts, "")
	if free(first) {
		return first
	}
	tail := ""
	if usedHere(first) {
		parts = append(parts, namePartOr(project, "project"))
	} else {
		hex := strings.TrimPrefix(hostID, "host_")
		for digits := 4; digits <= min(32, len(hex)); digits += 2 {
			tail = "-" + hex[:digits]
			if free(fittedName(parts, tail)) {
				break
			}
		}
	}
	name := fittedName(parts, tail)
	for n := 2; !free(name); n++ {
		name = fittedName(parts, fmt.Sprintf("%s-%d", tail, n))
	}
	return name
}

type attachAgent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

// runAttach registers an agent if needed and sets up a directory session
// for a project, recording it in an attach profile. For an integration that
// supports launch it then starts the session as session start does, unless
// --no-start is given, printing its output on errOut first.
func runAttach(ctx context.Context, client host.Client, harness string, harnessArgs []string, fs *pflag.FlagSet, state string, out, errOut io.Writer) error {
	return attachPrepared(ctx, client, harness, harnessArgs, fs, state, errOut, func(p *integration.Profile, result map[string]any) error {
		noStart, _ := fs.GetBool("no-start")
		if !p.Launchable() || noStart {
			if err := printJSON(out, result); err != nil {
				return err
			}
			if len(harnessArgs) > 0 {
				return errors.New("this integration does not support launch; harness arguments were not used")
			}
			return nil
		}
		if err := printJSON(errOut, result); err != nil {
			return err
		}
		return integration.Run(ctx, integration.Options{Action: "start", Directory: p.Directory, State: state, Workspace: p.Workspace, Args: harnessArgs, Program: programName}, out)
	})
}

func attachPrepared(ctx context.Context, client host.Client, harness string, harnessArgs []string, fs *pflag.FlagSet, state string, errOut io.Writer, complete func(*integration.Profile, map[string]any) error, guidedReuse ...bool) error {
	upReuse := len(guidedReuse) == 1 && guidedReuse[0]
	noStart, _ := fs.GetBool("no-start")
	if noStart && len(harnessArgs) > 0 {
		return errors.New("harness arguments require a launch; omit --no-start")
	}
	name, _ := fs.GetString("name")
	project, _ := fs.GetString("directory")
	expiresAt, _ := fs.GetString("expires-at")
	maxSends, _ := fs.GetInt64("max-sends-per-hour")
	values, _ := fs.GetStringArray("option")
	integrations, _ := fs.GetString("integrations")
	runner, _ := fs.GetString("runner")
	if harness == "claude" {
		harness = "claude-code"
	}
	base := harness
	if harness == "claude-code" {
		base = "claude"
	}
	if maxSends < 1 || maxSends > 10000 {
		return errors.New("--max-sends-per-hour must be 1 to 10000")
	}
	callsFlag, _ := fs.GetBool("calls")
	noCalls, _ := fs.GetBool("no-calls")
	maxCalls, _ := fs.GetInt64("max-calls-per-hour")
	maxCallsGiven := fs.Changed("max-calls-per-hour")
	switch {
	case callsFlag && noCalls:
		return errors.New("--calls and --no-calls exclude each other")
	case maxCallsGiven && noCalls:
		return errors.New("--max-calls-per-hour requires calls; omit --no-calls")
	case maxCallsGiven && (maxCalls < 1 || maxCalls > 10000):
		return errors.New("--max-calls-per-hour must be 1 to 10000")
	}
	if name == "builtin" {
		return errors.New("the agent name builtin is reserved for built-in sources; choose another --name")
	}
	if name != "" && !host.AddressableName(name) {
		return errors.New("--name must be 1 to 64 lowercase letters, digits, '.', '_', or '-', starting with a letter or digit")
	}
	options, err := integration.ParseOptions(values)
	if err != nil {
		return err
	}
	if project == "" {
		if project, err = os.Getwd(); err != nil {
			return err
		}
	}
	workspace, err := filepath.Abs(project)
	if err == nil {
		workspace, err = filepath.EvalSymlinks(workspace)
	}
	if err != nil {
		return err
	}
	if info, err := os.Stat(workspace); err != nil || !info.IsDir() {
		return errors.New("--directory must be an existing project directory")
	}
	identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
	if err != nil {
		return err
	}
	_, persons, err := readHostPersons(ctx, client)
	if err != nil {
		return err
	}
	networks, err := call[[]host.Network](ctx, client, "GET", "/v1/networks")
	if err != nil {
		return err
	}
	// Names are free only after a synchronous refresh of every directory.
	var directories []host.Directory
	for _, n := range networks {
		d, err := directoryOf(ctx, client, n.ID, true)
		if err != nil {
			return err
		}
		directories = append(directories, d)
	}
	unchecked := []string{}
	for _, d := range directories {
		mine := persons.ids[d.NetworkID]
		for _, h := range d.Hosts {
			if mine != "" && h.PersonID != nil && *h.PersonID == mine && h.State != "ok" && !slices.Contains(unchecked, h.HostID) {
				unchecked = append(unchecked, h.HostID)
			}
		}
	}
	sort.Strings(unchecked)
	// remote is the host of this person that has a name, or "".
	remote := func(name string) string {
		for _, d := range directories {
			mine := persons.ids[d.NetworkID]
			for _, a := range d.Agents {
				if mine != "" && a.PersonID != nil && *a.PersonID == mine && a.Name == name {
					return a.HostID
				}
			}
		}
		return ""
	}
	profiles, err := integration.HostProfiles(identity.ID)
	if err != nil {
		return err
	}
	locals, err := call[[]host.Agent](ctx, client, "GET", "/v1/agents")
	if err != nil {
		return err
	}
	local := func(name string) *host.Agent {
		for i := range locals {
			if locals[i].Name == name {
				return &locals[i]
			}
		}
		return nil
	}
	var agent *host.Agent
	var reusedProfile *integration.Profile
	for _, p := range profiles {
		if p.Workspace == workspace {
			reusedProfile = p
			for i := range locals {
				if locals[i].ID == p.AgentID {
					agent = &locals[i]
				}
			}
		}
	}
	if reusedProfile != nil && agent == nil {
		return fmt.Errorf("the attach profile %s names agent %s, which this host does not have", reusedProfile.Directory, reusedProfile.AgentID)
	}
	address := func(name string) string {
		if persons.label != "" {
			return persons.label + "/" + name
		}
		return identity.ID + "/" + name
	}
	var reusedConnection *host.Connection
	print := func(p *integration.Profile, reused bool) error {
		next := "peerspan session doctor"
		if p.Launchable() {
			next = "peerspan session start"
		}
		credential, err := call[host.Adapter](ctx, client, "GET", "/v1/adapters/"+url.PathEscape(p.AdapterID))
		if err != nil {
			return err
		}
		result := map[string]any{
			"agent": attachAgent{agent.ID, agent.Name, address(agent.Name)}, "session_id": p.SessionID, "adapter_id": p.AdapterID,
			"profile": p.Directory, "workspace": workspace, "reused": reused, "unchecked_hosts": unchecked, "next": next,
			"calls": credential.Calls, "max_calls_per_hour": credential.MaxCallsPerHour,
		}
		if reusedConnection != nil {
			result["next"] = "peerspan session doctor"
			result["connection"] = *reusedConnection
			result["adapter_ready"] = reusedConnection.State == "ready"
		}
		// Discovery follows a successful setup.
		result["sources"] = attachSources(ctx, client, agent.ID, p.Harness.ID, workspace, errOut)
		return complete(p, result)
	}
	if reusedProfile != nil && reusedProfile.Phase == "configured" {
		// A valid credential that never connected is reused unchanged; one
		// connected now is refused; any other is replaced by a new setup.
		adapter, err := call[host.Adapter](ctx, client, "GET", "/v1/adapters/"+url.PathEscape(reusedProfile.AdapterID))
		if err != nil {
			return err
		}
		conn, err := call[host.Connection](ctx, client, "GET", "/v1/adapters/"+url.PathEscape(reusedProfile.AdapterID)+"/connection")
		if err != nil {
			return err
		}
		valid := false
		if expires, err := time.Parse(time.RFC3339Nano, adapter.ExpiresAt); err == nil && adapter.RevokedAt == nil && expires.After(time.Now()) {
			valid = true
		}

		if upReuse && valid && (conn.State == "ready" || conn.State == "offline" && conn.Recoverable) {
			current, err := integration.ValidateAttachment(ctx, reusedProfile)
			if err != nil {
				return err
			}
			adapter, conn = current.Adapter, current.Connection
			eligible := conn.State == "ready" && current.Session.State == host.SessionAttached || conn.State == "offline" && conn.Recoverable && (current.Session.State == host.SessionAttached || current.Session.State == host.SessionDetached)
			if !eligible {
				return errors.New("the existing attachment changed; inspect session doctor before retrying")
			}
			if reusedProfile.State != state || reusedProfile.Harness.ID != harness || (name != "" && name != agent.Name) || len(harnessArgs) != 0 {
				return errors.New("the requested integration or launch inputs differ from this project's existing attachment")
			}
			if len(options) != len(reusedProfile.Options) {
				return errors.New("the requested options differ from this project's existing attachment")
			}
			for key, value := range options {
				if reusedProfile.Options[key] != value {
					return errors.New("the requested options differ from this project's existing attachment")
				}
			}
			if (expiresAt != "" && expiresAt != adapter.ExpiresAt) || (callsFlag && !adapter.Calls) || (noCalls && adapter.Calls) || (maxCallsGiven && (adapter.MaxCallsPerHour == nil || *adapter.MaxCallsPerHour != maxCalls)) || (fs.Changed("max-sends-per-hour") && (adapter.MaxSendsPerHour == nil || *adapter.MaxSendsPerHour != maxSends)) {
				return errors.New("the requested expiry, calls or rate budgets differ from this project's existing attachment; nothing was changed")
			}
			reusedConnection = &conn
			return print(reusedProfile, true)
		}
		switch {
		case valid && conn.State == "registered":
			// The stored call settings stand; a flag that differs is
			// refused before anything changes.
			if (callsFlag && !adapter.Calls) || (noCalls && adapter.Calls) || (maxCallsGiven && (adapter.MaxCallsPerHour == nil || *adapter.MaxCallsPerHour != maxCalls)) {
				stored := "null"
				if adapter.MaxCallsPerHour != nil {
					stored = strconv.FormatInt(*adapter.MaxCallsPerHour, 10)
				}
				return fmt.Errorf("the reused credential %s of agent %s has calls %t and max_calls_per_hour %s; the given call settings differ, so nothing was changed; give matching flags, or revoke the credential (peerspan adapter revoke %s) to set up a new one", adapter.ID, agent.Name, adapter.Calls, stored, adapter.ID)
			}
			return print(reusedProfile, true)
		case conn.State == "ready":
			// An adapter that has just exited keeps its lease for up to 15
			// seconds: wait until the lease seen has expired, at most 16
			// seconds, and refuse if it was renewed meanwhile.
			running := fmt.Errorf("the session of agent %s in this project is already running (adapter %s is connected)", agent.Name, reusedProfile.AdapterID)
			seen := time.Now()
			if conn.LeaseExpiresAt != nil {
				if at, err := time.Parse(time.RFC3339Nano, *conn.LeaseExpiresAt); err == nil {
					seen = at
				}
			}
			fmt.Fprintf(errOut, "waiting for the previous session of agent %s to release its lease (until %s)\n", agent.Name, seen.UTC().Format(time.RFC3339))
			limit := time.Now().Add(16 * time.Second)
			for {
				wait := time.Until(seen) + 200*time.Millisecond
				if wait > time.Second {
					wait = time.Second
				}
				if until := time.Until(limit); wait > until {
					wait = until
				}
				if wait > 0 {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(wait):
					}
				}
				conn, err = call[host.Connection](ctx, client, "GET", "/v1/adapters/"+url.PathEscape(reusedProfile.AdapterID)+"/connection")
				if err != nil {
					return err
				}
				if conn.LeaseExpiresAt != nil {
					if at, err := time.Parse(time.RFC3339Nano, *conn.LeaseExpiresAt); err == nil && at.After(seen) {
						return running
					}
				}
				if conn.State != "ready" {
					break
				}
				if !time.Now().Before(limit) {
					return running
				}
			}
		}
	}
	if agent == nil {
		attached := func(id string) bool {
			for _, p := range profiles {
				if p.AgentID == id {
					return true
				}
			}
			return false
		}
		if name != "" {
			// A taken name is refused before any registration; an agent of
			// this host that no attach profile records is attached.
			if a := local(name); a != nil {
				if attached(a.ID) {
					return fmt.Errorf("name %s is taken by %s on host %s, this host (409)", name, a.ID, identity.ID)
				}
				agent = a
			} else if other := remote(name); other != "" {
				return fmt.Errorf("name %s is taken by another of your agents on host %s (409)", name, other)
			}
		} else {
			free := func(name string) bool { return local(name) == nil && remote(name) == "" }
			hostname, _ := os.Hostname()
			usedHere := func(name string) bool { return local(name) != nil }
			name = defaultAgentName(base, hostname, filepath.Base(workspace), identity.ID, usedHere, free)
		}
		if agent == nil {
			owner := persons.label
			if owner == "" {
				owner = loginName()
			}
			data, err := client.Call(ctx, "POST", "/v1/agents", host.RegisterAgent{Name: name, Owner: owner})
			if err != nil {
				return err
			}
			agent = new(host.Agent)
			if err = json.Unmarshal(data, agent); err != nil {
				return err
			}
		}
	}
	// A new setup decides calls again: the flags, or the prompt at a
	// terminal, where no terminal answers no.
	callsLimit := int64(0)
	allow := callsFlag
	if !callsFlag && !noCalls && isTerminal(os.Stdin) {
		allow = askYes(errOut, "Let this agent call capabilities shared with you, and yours on your other trusted machines?")
	}
	if allow {
		callsLimit = 100
		if maxCallsGiven {
			callsLimit = maxCalls
		}
	}
	root, err := integration.SessionsDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(root, identity.ID, agent.Name)
	if reusedProfile != nil {
		dir = reusedProfile.Directory
	}
	// An existing profile is replaced only once the new setup succeeds.
	backup := filepath.Join(filepath.Dir(dir), "."+filepath.Base(dir)+".old")
	if _, err := os.Lstat(dir); err == nil {
		if err = os.RemoveAll(backup); err != nil {
			return err
		}
		if err = os.Rename(dir, backup); err != nil {
			return err
		}
	} else {
		backup = ""
	}
	p, err := integration.Setup(ctx, integration.Options{Action: "setup", Directory: dir, State: state, Harness: harness, Integrations: integrations, Runner: runner, Agent: agent.ID, ExpiresAt: expiresAt, ProviderOptions: options, Program: programName, AttachWorkspace: workspace, MaxSendsPerHour: maxSends, MaxCallsPerHour: callsLimit})
	if err != nil {
		if backup != "" {
			_ = os.RemoveAll(dir)
			_ = os.Rename(backup, dir)
		}
		return err
	}
	if backup != "" {
		_ = os.RemoveAll(backup)
	}
	return print(p, false)
}

// singleNetwork applies network defaulting to an omitted --network.
func singleNetwork(ctx context.Context, client host.Client, network string) (string, error) {
	if network != "" {
		return network, nil
	}
	networks, err := call[[]host.Network](ctx, client, "GET", "/v1/networks")
	if err != nil {
		return "", err
	}
	switch len(networks) {
	case 0:
		return "", errors.New("not a member of any network")
	case 1:
		return networks[0].ID, nil
	}
	listed := make([]string, len(networks))
	for i, n := range networks {
		listed[i] = fmt.Sprintf("%s (%s)", n.ID, n.Name)
	}
	return "", errors.New("this host is in several networks; choose one with --network: " + strings.Join(listed, ", "))
}

type reachableAgent struct {
	Address   string        `json:"address"`
	HostID    string        `json:"host_id"`
	AgentID   string        `json:"agent_id"`
	Connected bool          `json:"connected"`
	HostState string        `json:"host_state"`
	Actions   []string      `json:"actions"`
	Endpoint  host.Endpoint `json:"endpoint"`
}

type mineAgent struct {
	Address   string        `json:"address"`
	HostID    string        `json:"host_id"`
	AgentID   string        `json:"agent_id"`
	Connected bool          `json:"connected"`
	Endpoint  host.Endpoint `json:"endpoint"`
}

// endpoints reports each host's endpoint as agents shows it, from the
// network map and the peer paths.
func endpoints(ctx context.Context, client host.Client, network, self string) (func(string) host.Endpoint, error) {
	members, err := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/members")
	if err != nil {
		return nil, err
	}
	seen := map[string]host.Endpoint{}
	return func(id string) host.Endpoint {
		if e, ok := seen[id]; ok {
			return e
		}
		e := host.Endpoint{Address: host.MapAddress(members, id), Path: "local"}
		if id != self {
			path, err := call[host.PeerPath](ctx, client, "GET", "/v1/peers/"+url.PathEscape(id)+"/path")
			if err != nil {
				path = host.PeerPath{HostID: id, Path: "none"}
			}
			e = host.EndpointFrom(path, members, id)
		}
		seen[id] = e
		return e
	}, nil
}

// endpointText is an endpoint in the readable layout.
func endpointText(e host.Endpoint) string {
	switch {
	case e.Address == nil:
		return e.Path
	case e.Path == "direct" || e.Path == "local":
		return *e.Address
	}
	return *e.Address + " (" + e.Path + ")"
}

type inboundRule struct {
	Agent            string   `json:"agent"`
	Principals       []string `json:"principals"`
	Actions          []string `json:"actions"`
	MaxArtifactBytes int64    `json:"max_artifact_bytes"`
}

// runAgents shows a network's directory: agents this host may reach, this
// person's agents, and who may reach them.
func runAgents(ctx context.Context, client host.Client, fs *pflag.FlagSet, out io.Writer) error {
	network, _ := fs.GetString("network")
	refresh, _ := fs.GetBool("refresh")
	asJSON, _ := fs.GetBool("json")
	network, err := singleNetwork(ctx, client, network)
	if err != nil {
		return err
	}
	d, err := directoryOf(ctx, client, network, refresh)
	if err != nil {
		return err
	}
	st, persons, err := readHostPersons(ctx, client)
	if err != nil {
		return err
	}
	endpoint, err := endpoints(ctx, client, network, st.HostID)
	if err != nil {
		return err
	}
	states := map[string]string{}
	for _, h := range d.Hosts {
		states[h.HostID] = h.State
	}
	reachable := []reachableAgent{}
	mine := []mineAgent{}
	person := persons.ids[network]
	for _, a := range d.Agents {
		if a.Address == nil {
			continue
		}
		have := map[string]bool{}
		for _, auth := range a.Authorizations {
			for _, action := range auth.Actions {
				have[action] = true
			}
		}
		actions := []string{}
		for _, action := range []string{membership.PolicyActionMessage, membership.PolicyActionTask, membership.PolicyActionDelegate} {
			if have[action] {
				actions = append(actions, action)
			}
		}
		reachable = append(reachable, reachableAgent{*a.Address, a.HostID, a.AgentID, a.Connected, states[a.HostID], actions, endpoint(a.HostID)})
		if person != "" && a.PersonID != nil && *a.PersonID == person {
			mine = append(mine, mineAgent{*a.Address, a.HostID, a.AgentID, a.Connected, endpoint(a.HostID)})
		}
	}
	// This host's own agents, addressed as the directory would address them.
	sessions, err := call[[]map[string]*string](ctx, client, "GET", "/v1/sessions")
	if err != nil {
		return err
	}
	channels := map[string]*string{}
	for _, s := range sessions {
		if id := s["id"]; id != nil {
			if channel, ok := s["channel"]; ok {
				channels[*id] = channel
			}
		}
	}
	label := persons.labels[network]
	for _, a := range st.Agents {
		if !host.AddressableName(a.Name) {
			continue
		}
		address := st.HostID + "/" + a.Name
		if person != "" && label != "" {
			address = label + "/" + a.Name
			for _, other := range d.Agents {
				if other.PersonID != nil && *other.PersonID == person && other.Name == a.Name {
					address = st.HostID + "/" + a.Name
				}
			}
		}
		// Connected means a session with a lease and a verified channel,
		// as in the directory; a daemon that reports no channel predates
		// verification, and a lease alone counts there.
		connected := false
		for _, s := range a.Sessions {
			if s.Connection != nil && *s.Connection == "ready" {
				channel, reported := channels[s.ID]
				connected = connected || !reported || (channel != nil && *channel == host.ChannelVerified)
			}
		}
		mine = append(mine, mineAgent{address, st.HostID, a.ID, connected, endpoint(st.HostID)})
	}
	sort.SliceStable(mine, func(i, j int) bool {
		if mine[i].Address != mine[j].Address {
			return mine[i].Address < mine[j].Address
		}
		return mine[i].HostID < mine[j].HostID
	})
	inbound := []inboundRule{}
	var policy struct {
		Rules []inboundRule `json:"rules"`
	}
	if person != "" {
		policy, err = call[struct {
			Rules []inboundRule `json:"rules"`
		}](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/policy")
		var failure *host.ClientError
		if errors.As(err, &failure) && failure.Status == 404 {
			err = nil
		}
		if err != nil {
			return err
		}
		inbound = append(inbound, policy.Rules...)
	}
	if asJSON {
		return printJSON(out, map[string]any{"network_id": d.NetworkID, "refreshed_at": d.RefreshedAt, "reachable": reachable, "mine": mine, "inbound": inbound, "hosts": d.Hosts})
	}
	refreshed := "never refreshed"
	if d.RefreshedAt != nil {
		refreshed = "refreshed " + *d.RefreshedAt
	}
	fmt.Fprintf(out, "Network %s, %s\n\nReachable:\n", d.NetworkID, refreshed)
	if len(reachable) == 0 {
		fmt.Fprintln(out, "  none")
	}
	for _, a := range reachable {
		connected := "not connected"
		if a.Connected {
			connected = "connected"
		}
		answered := "answered the last refresh"
		if a.HostState != "ok" {
			answered = "host " + a.HostState + " at the last refresh"
		}
		fmt.Fprintf(out, "  %s  %s; %s; %s; %s\n", a.Address, strings.Join(a.Actions, ", "), connected, answered, endpointText(a.Endpoint))
	}
	fmt.Fprintln(out, "\nMine:")
	if len(mine) == 0 {
		fmt.Fprintln(out, "  none")
	}
	for _, a := range mine {
		connected := "not connected"
		if a.Connected {
			connected = "connected"
		}
		fmt.Fprintf(out, "  %s  %s  %s\n", a.Address, connected, endpointText(a.Endpoint))
	}
	fmt.Fprintln(out, "\nInbound:")
	labels := map[string]string{}
	if len(inbound) > 0 {
		if list, err := call[[]host.Person](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/persons"); err == nil {
			for _, p := range list {
				labels["person:"+p.PersonID] = p.Member
			}
		}
	}
	for _, rule := range inbound {
		names := make([]string, len(rule.Principals))
		for i, p := range rule.Principals {
			names[i] = p
			if label, ok := labels[p]; ok {
				names[i] = label
			} else if p == membership.PrincipalNetwork {
				names[i] = "everyone"
			}
		}
		files := ""
		if rule.MaxArtifactBytes > 0 {
			files = fmt.Sprintf(", files up to %d bytes", rule.MaxArtifactBytes)
		}
		fmt.Fprintf(out, "  %s: %s may %s%s\n", rule.Agent, strings.Join(names, ", "), strings.Join(rule.Actions, ", "), files)
	}
	fmt.Fprintln(out, "  Your own hosts reach all of your agents.")
	return nil
}

// addressedTask is a task by address whose files are uploaded first.
type addressedTask struct {
	body  map[string]any
	files []string
}

// addressedRequest builds send and task, which name their target by
// address. The bodies carry only the fields given, so neither form of
// target is sent alongside the other.
func addressedRequest(args []string, fs *pflag.FlagSet) (string, string, any, error) {
	network, _ := fs.GetString("network")
	grant, _ := fs.GetString("grant")
	fromAgent, _ := fs.GetString("from-agent")
	deadline, _ := fs.GetString("deadline")
	body := map[string]any{"to": args[1]}
	if network != "" {
		body["network"] = network
	}
	if grant != "" {
		body["grant_id"] = grant
	}
	if fromAgent != "" {
		body["origin"] = host.Origin{AgentID: fromAgent}
	}
	if args[0] == "send" {
		if deadline == "" {
			deadline = expiryIn(messageDefaultDeadline)
		}
		body["content"], body["deadline"] = args[2], deadline
		return "POST", "/v1/outbound", body, nil
	}
	body["input"] = args[2]
	if deadline != "" {
		body["deadline"] = deadline
	}
	files, _ := fs.GetStringArray("file")
	return "POST", "/v1/tasks", addressedTask{body, files}, nil
}
