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
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/integration"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
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

// suffixed is base-suffix with the suffix lowercased, characters outside
// the addressable set replaced by '-', and cut to fit 64 characters.
func suffixed(base, suffix string) string {
	clean := []byte(strings.ToLower(suffix))
	for i, c := range clean {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			clean[i] = '-'
		}
	}
	name := base + "-" + string(clean)
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// numbered is name with -N appended, cutting name to fit 64 characters.
func numbered(name string, n int) string {
	suffix := fmt.Sprintf("-%d", n)
	if len(name)+len(suffix) > 64 {
		name = name[:64-len(suffix)]
	}
	return name + suffix
}

type attachAgent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
}

// runAttach registers an agent if needed and sets up a directory session
// for a project, recording it in an attach profile.
func runAttach(ctx context.Context, client host.Client, harness string, fs *pflag.FlagSet, state string, out io.Writer) error {
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
	print := func(p *integration.Profile, reused bool) error {
		next := "capsule session doctor"
		if p.Launchable() {
			next = "capsule session start"
		}
		return printJSON(out, map[string]any{
			"agent": attachAgent{agent.ID, agent.Name, address(agent.Name)}, "session_id": p.SessionID, "adapter_id": p.AdapterID,
			"profile": p.Directory, "workspace": workspace, "reused": reused, "unchecked_hosts": unchecked, "next": next,
		})
	}
	if reusedProfile != nil && reusedProfile.Phase == "configured" {
		adapter, err := call[host.Adapter](ctx, client, "GET", "/v1/adapters/"+url.PathEscape(reusedProfile.AdapterID))
		if err != nil {
			return err
		}
		if expires, err := time.Parse(time.RFC3339Nano, adapter.ExpiresAt); err == nil && adapter.RevokedAt == nil && expires.After(time.Now()) {
			return print(reusedProfile, true)
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
			name = base
			if !free(name) {
				stem := ""
				if local(base) != nil {
					stem = suffixed(base, filepath.Base(workspace))
				} else {
					hostname, _ := os.Hostname()
					hostname, _, _ = strings.Cut(hostname, ".")
					stem = suffixed(base, hostname)
				}
				name = stem
				for n := 2; !free(name); n++ {
					name = numbered(stem, n)
				}
			}
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
	p, err := integration.Setup(ctx, integration.Options{Action: "setup", Directory: dir, State: state, Harness: harness, Integrations: integrations, Runner: runner, Agent: agent.ID, ExpiresAt: expiresAt, ProviderOptions: options, Program: programName, AttachWorkspace: workspace, MaxSendsPerHour: maxSends})
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
	Address   string   `json:"address"`
	HostID    string   `json:"host_id"`
	AgentID   string   `json:"agent_id"`
	Connected bool     `json:"connected"`
	HostState string   `json:"host_state"`
	Actions   []string `json:"actions"`
}

type mineAgent struct {
	Address   string `json:"address"`
	HostID    string `json:"host_id"`
	AgentID   string `json:"agent_id"`
	Connected bool   `json:"connected"`
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
		reachable = append(reachable, reachableAgent{*a.Address, a.HostID, a.AgentID, a.Connected, states[a.HostID], actions})
		if person != "" && a.PersonID != nil && *a.PersonID == person {
			mine = append(mine, mineAgent{*a.Address, a.HostID, a.AgentID, a.Connected})
		}
	}
	// This host's own agents, addressed as the directory would address them.
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
		connected := false
		for _, s := range a.Sessions {
			if s.Connection != nil && *s.Connection == "ready" {
				connected = true
			}
		}
		mine = append(mine, mineAgent{address, st.HostID, a.ID, connected})
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
		fmt.Fprintf(out, "  %s  %s; %s; %s\n", a.Address, strings.Join(a.Actions, ", "), connected, answered)
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
		fmt.Fprintf(out, "  %s  %s\n", a.Address, connected)
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
