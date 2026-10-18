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
	"sort"
	"strconv"
	"strings"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/integration"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

// Capabilities on the owner's CLI: sources, capability records, sharing
// them through capability rules, the open list, and discover.

// Capability rule settings for a new share.
const (
	shareMaxInputBytes   = 65536
	shareMaxCallsPerHour = 100
)

// runSources runs sources, sources refresh, sources open-to, and sources
// close-to.
func runSources(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	agentName := ""
	if fs.Lookup("agent") != nil {
		agentName, _ = fs.GetString("agent")
	}
	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}
	switch sub {
	case "":
		asJSON, _ := fs.GetBool("json")
		path := "/v1/sources"
		if agentName != "" {
			path += "?" + url.Values{"agent": {agentName}}.Encode()
		}
		data, err := client.Call(ctx, "GET", path, nil)
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(out, json.RawMessage(data))
		}
		var listing sourcesListing
		if err = json.Unmarshal(data, &listing); err != nil {
			return err
		}
		printSources(out, listing)
		return nil
	case "refresh":
		identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
		if err != nil {
			return err
		}
		profiles, err := integration.HostProfiles(identity.ID)
		if err != nil {
			return err
		}
		locals, err := call[[]host.Agent](ctx, client, "GET", "/v1/agents")
		if err != nil {
			return err
		}
		names := map[string]string{}
		for _, a := range locals {
			names[a.ID] = a.Name
		}
		results := []map[string]any{}
		for _, p := range profiles {
			if p.Workspace == "" || names[p.AgentID] == "" || (agentName != "" && names[p.AgentID] != agentName && p.AgentID != agentName) {
				continue
			}
			stored, errs, err := discoverAndStore(ctx, client, p.AgentID, p.Harness.ID, p.Workspace)
			if err != nil {
				return err
			}
			summary, line := summarize(stored, errs)
			fmt.Fprintf(errOut, "%s: %s\n", names[p.AgentID], line)
			results = append(results, map[string]any{"agent_id": p.AgentID, "agent": names[p.AgentID], "workspace": p.Workspace, "sources": summary})
		}
		if agentName != "" && len(results) == 0 {
			return fmt.Errorf("no attach profile on this host records agent %s", agentName)
		}
		return printJSON(out, results)
	case "open-to", "close-to":
		all, _ := fs.GetBool("all")
		target := ""
		if len(args) > 2 {
			target = args[2]
		}
		if all == (target != "") {
			return fmt.Errorf("sources %s takes HOST or --all", sub)
		}
		if all {
			target = "*"
		}
		var data json.RawMessage
		var err error
		if sub == "open-to" {
			data, err = client.Call(ctx, "POST", "/v1/sources/open-to", map[string]string{"host_id": target})
		} else {
			data, err = client.Call(ctx, "DELETE", "/v1/sources/open-to/"+url.PathEscape(target), nil)
		}
		if err != nil {
			return err
		}
		return printJSON(out, data)
	}
	return invalidCommand()
}

func printSources(out io.Writer, listing sourcesListing) {
	for _, a := range listing.Agents {
		fmt.Fprintf(out, "%s (%s)\n", a.Agent.Name, a.Agent.ID)
		if len(a.Servers) == 0 {
			fmt.Fprintln(out, "  no sources discovered")
		}
		for _, s := range a.Servers {
			state := "usable"
			if !s.Shareable {
				state = "not usable: " + deref(s.Reason)
				if len(s.MissingEnv) > 0 {
					state += " (" + strings.Join(s.MissingEnv, ", ") + ")"
				}
			}
			fmt.Fprintf(out, "  %s/%s  %s  from %s  %s\n", a.Agent.Name, s.Name, s.Transport, s.Source, state)
			if s.SnapshotError != nil {
				fmt.Fprintf(out, "    snapshot failed: %s\n", *s.SnapshotError)
			}
			for _, t := range s.Tools {
				mark := "can change things"
				if t.ReadOnly {
					mark = "read-only"
				}
				fmt.Fprintf(out, "    tool %s (%s)\n", t.Name, mark)
			}
			for _, r := range s.Resources {
				fmt.Fprintf(out, "    resource %s\n", r.URI)
			}
			if len(s.Capabilities) > 0 {
				fmt.Fprintf(out, "    capabilities: %s\n", strings.Join(s.Capabilities, ", "))
			}
		}
	}
	if len(listing.OpenTo) > 0 {
		fmt.Fprintf(out, "Open to: %s\n", strings.Join(listing.OpenTo, ", "))
	}
}

// capabilityRecord is a capability as the CLI reads it.
type capabilityRecord struct {
	Name   string `json:"name"`
	Source struct {
		Agent  string `json:"agent"`
		Server string `json:"server"`
	} `json:"source"`
	Operations []string        `json:"operations"`
	Resources  json.RawMessage `json:"resources"`
	Credential struct {
		EnvFile *string  `json:"env_file"`
		Args    []string `json:"args"`
	} `json:"credential"`
	State       string   `json:"state"`
	Unavailable []string `json:"unavailable"`
	Recipients  []struct {
		NetworkID string  `json:"network_id"`
		Principal string  `json:"principal"`
		Label     *string `json:"label"`
	} `json:"recipients"`
}

// resolveSource reads SOURCE, AGENT/SERVER or a SERVER exactly one agent
// on this host has.
func resolveSource(listing sourcesListing, given string) (sourcesAgent, sourceServer, error) {
	agent, server, qualified := strings.Cut(given, "/")
	if !qualified {
		agent, server = "", given
	}
	var matches []sourcesAgent
	for _, a := range listing.Agents {
		if (agent == "" || a.Agent.Name == agent) && a.server(server) != nil {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return sourcesAgent{}, sourceServer{}, fmt.Errorf("no source %s on this host", given)
	case 1:
		return matches[0], *matches[0].server(server), nil
	}
	var names []string
	for _, m := range matches {
		names = append(names, m.Agent.Name+"/"+server)
	}
	return sourcesAgent{}, sourceServer{}, fmt.Errorf("several agents have %s: %s; give AGENT/SERVER", server, strings.Join(names, ", "))
}

// capabilitySpec is what capability create and the guided share collect.
type capabilitySpec struct {
	name, source string
	operations   []string
	resources    string // "", "all", or comma-separated URIs
	envFile      string
	args         []string
	argsGiven    bool
}

// createBody is the POST /v1/capabilities body for a spec.
func createBody(listing sourcesListing, spec capabilitySpec) (map[string]any, error) {
	agent, server, err := resolveSource(listing, spec.source)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"name": spec.name, "source": map[string]string{"agent": agent.Agent.Name, "server": server.Name}, "operations": nil, "resources": nil, "env_file": nil}
	if len(spec.operations) > 0 {
		body["operations"] = spec.operations
	}
	switch spec.resources {
	case "":
	case "all":
		body["resources"] = "all"
	default:
		body["resources"] = strings.Split(spec.resources, ",")
	}
	if spec.envFile != "" {
		path, err := filepath.Abs(spec.envFile)
		if err != nil {
			return nil, err
		}
		body["env_file"] = path
	}
	if spec.argsGiven {
		body["args"] = spec.args
	}
	return body, nil
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// runCapability runs capability create, list, show, and remove.
func runCapability(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	if len(args) < 2 {
		return invalidCommand()
	}
	switch args[1] {
	case "create":
		spec := capabilitySpec{name: args[2]}
		spec.source, _ = fs.GetString("from")
		operations, _ := fs.GetString("operations")
		spec.operations = splitList(operations)
		spec.resources, _ = fs.GetString("resources")
		spec.envFile, _ = fs.GetString("env-file")
		spec.args, _ = fs.GetStringArray("arg")
		spec.argsGiven = fs.Changed("arg")
		if spec.source == "" {
			return errors.New("capability create needs --from SOURCE")
		}
		listing, err := readSources(ctx, client, "/v1/sources")
		if err != nil {
			return err
		}
		body, err := createBody(listing, spec)
		if err != nil {
			return err
		}
		keyPath, _ := fs.GetString("person-key")
		data, _, err := createWithClaims(ctx, client, keyPath, spec.name, body, "", "", 0)
		if err != nil {
			return err
		}
		return printJSON(out, data)
	case "list":
		asJSON, _ := fs.GetBool("json")
		data, err := client.Call(ctx, "GET", "/v1/capabilities", nil)
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(out, data)
		}
		var list struct {
			Capabilities []capabilityRecord `json:"capabilities"`
		}
		if err = json.Unmarshal(data, &list); err != nil {
			return err
		}
		if len(list.Capabilities) == 0 {
			fmt.Fprintln(out, "No capabilities on this host.")
		}
		for _, c := range list.Capabilities {
			fmt.Fprintf(out, "%s  from %s/%s  %s  operations: %s", c.Name, c.Source.Agent, c.Source.Server, c.State, strings.Join(c.Operations, ", "))
			if string(c.Resources) != "null" {
				fmt.Fprintf(out, "  resources: %s", c.Resources)
			}
			fmt.Fprintf(out, "  recipients: %d\n", len(c.Recipients))
		}
		return nil
	case "show":
		data, err := client.Call(ctx, "GET", "/v1/capabilities/"+url.PathEscape(args[2]), nil)
		if err != nil {
			return err
		}
		return printJSON(out, data)
	case "remove":
		return removeCapability(ctx, client, args[2], fs, out, errOut)
	}
	return invalidCommand()
}

// removeCapability withdraws a capability's shares from every network's
// policy, after confirmation, and deletes the record only once every
// withdrawal is stored. A failed signing keeps the record; repeating the
// command finishes the removal.
func removeCapability(ctx context.Context, client host.Client, name string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	yes, _ := fs.GetBool("yes")
	keyPath, _ := fs.GetString("person-key")
	c, err := call[capabilityRecord](ctx, client, "GET", "/v1/capabilities/"+url.PathEscape(name))
	if err != nil {
		return err
	}
	if len(c.Recipients) > 0 {
		fmt.Fprintf(errOut, "%s is shared with:\n", name)
		for _, r := range c.Recipients {
			label := r.Principal
			if r.Label != nil {
				label = *r.Label + " (" + r.Principal + ")"
			}
			fmt.Fprintf(errOut, "  %s in %s\n", label, r.NetworkID)
		}
		fmt.Fprintln(errOut, "Removing it withdraws these shares.")
		switch {
		case yes:
		case isTerminal(os.Stdin):
			if !askYes(errOut, "Remove?") {
				fmt.Fprintln(errOut, "Not removed.")
				return exitStatus(1)
			}
		default:
			fmt.Fprintln(errOut, "error: confirm at a terminal, or pass --yes")
			return exitStatus(1)
		}
	}
	identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
	if err != nil {
		return err
	}
	// Every network whose policy has this host's rule for the name, claim
	// included.
	networks := []string{}
	for _, r := range c.Recipients {
		if !contains(networks, r.NetworkID) {
			networks = append(networks, r.NetworkID)
		}
	}
	// The stored policies of this host's persons, and of the signing key's
	// person when it loads, in every network of this host, bound there or
	// not: a claim left in a network where this host is no longer bound
	// would come back on rebinding.
	candidates := []string{}
	if _, persons, err := readHostPersons(ctx, client); err == nil {
		for _, n := range sortedNetworks(persons.ids) {
			if !contains(candidates, persons.ids[n]) {
				candidates = append(candidates, persons.ids[n])
			}
		}
	}
	if signer, err := person.Load(keyPath); err == nil {
		if id := membership.PersonID(signer.PublicKey()); !contains(candidates, id) {
			candidates = append(candidates, id)
		}
		signer.Close()
	}
	holders := map[string][]string{} // network: persons whose policy holds the rule
	for _, n := range ownNetworks(ctx, client) {
		for _, id := range candidates {
			if p, err := currentPolicy(ctx, client, n, id); err == nil && p != nil && hostRule(p.CapabilityRules, identity.ID, name) >= 0 {
				holders[n] = append(holders[n], id)
				if !contains(networks, n) {
					networks = append(networks, n)
				}
			}
		}
	}
	signed := []json.RawMessage{}
	for _, network := range networks {
		o, err := loadOwner(ctx, client, network, keyPath)
		if err != nil {
			return fmt.Errorf("withdrawing %s from %s failed; the capability is kept, and repeating the command finishes the removal: %w", name, network, err)
		}
		data, changed, err := o.edit(ctx, client, true, func(body *membership.PolicyBody) (bool, error) {
			i := hostRule(body.CapabilityRules, identity.ID, name)
			if i < 0 {
				return false, nil
			}
			body.CapabilityRules = append(body.CapabilityRules[:i:i], body.CapabilityRules[i+1:]...)
			return true, nil
		})
		o.signer.Close()
		if changed {
			signed = append(signed, data)
		}
		if err == nil {
			for _, id := range holders[network] {
				if id != o.ownerID {
					err = fmt.Errorf("the policy of %s still has this host's rule for %s; sign with that person's key", id, name)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("withdrawing %s from %s failed; the capability is kept, and repeating the command finishes the removal: %w", name, network, err)
		}
	}
	data, err := client.Call(ctx, "DELETE", "/v1/capabilities/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	return printJSON(out, map[string]any{"capability": json.RawMessage(data), "policies": signed})
}

// review is what share prints before asking for confirmation.
func printReview(errOut io.Writer, address string, c capabilityRecord, server sourceServer, principal string, limitChange string) {
	fmt.Fprintf(errOut, "Capability: %s\n", address)
	fmt.Fprintf(errOut, "Source: %s/%s, from %s\n", c.Source.Agent, c.Source.Server, server.Source)
	fmt.Fprintln(errOut, "Operations:")
	for _, op := range c.Operations {
		mark := " (can change things)"
		for _, t := range server.Tools {
			if t.Name == op && t.ReadOnly {
				mark = ""
			}
		}
		fmt.Fprintf(errOut, "  %s%s\n", op, mark)
	}
	if string(c.Resources) != "" && string(c.Resources) != "null" {
		fmt.Fprintf(errOut, "  read, over resources: %s\n", c.Resources)
	}
	if c.Credential.EnvFile != nil || c.Credential.Args != nil {
		fmt.Fprintf(errOut, "Credentials: the capability's own environment file %s", deref(c.Credential.EnvFile))
		if c.Credential.Args != nil {
			fmt.Fprintf(errOut, ", with arguments %s", strings.Join(c.Credential.Args, " "))
		}
		fmt.Fprintln(errOut)
	} else {
		fmt.Fprintf(errOut, "Credentials: the source's own environment on this host\n")
	}
	fmt.Fprintf(errOut, "Recipient: %s\n", principal)
	if limitChange != "" {
		fmt.Fprint(errOut, limitChange)
	}
	fmt.Fprintf(errOut, "%s can use these operations with the credentials they run with on this host. Anything those credentials can reach through them, %s can too.\n", principal, principal)
}

// confirmShare asks Share? at a terminal, or takes --yes; otherwise it
// refuses with exit 1.
func confirmShare(errOut io.Writer, yes bool) error {
	switch {
	case yes:
		return nil
	case isTerminal(os.Stdin):
		if askYes(errOut, "Share?") {
			return nil
		}
		fmt.Fprintln(errOut, "Not shared.")
		return exitStatus(1)
	}
	fmt.Fprintln(errOut, "error: confirm this share at a terminal, or pass --yes")
	return exitStatus(1)
}

// guidedSpec asks at a terminal for every selection not given as a flag:
// the source, the operations, whether to include resources, and the name.
func guidedSpec(ctx context.Context, client host.Client, fs *pflag.FlagSet, errOut io.Writer) (capabilitySpec, sourcesListing, error) {
	var spec capabilitySpec
	spec.source, _ = fs.GetString("from")
	operations, _ := fs.GetString("operations")
	spec.operations = splitList(operations)
	spec.resources, _ = fs.GetString("resources")
	spec.name, _ = fs.GetString("name")
	spec.envFile, _ = fs.GetString("env-file")
	spec.args, _ = fs.GetStringArray("arg")
	spec.argsGiven = fs.Changed("arg")
	yes, _ := fs.GetBool("yes")
	listing, err := readSources(ctx, client, "/v1/sources")
	if err != nil {
		return spec, listing, err
	}
	terminal := isTerminal(os.Stdin)
	if !terminal {
		if spec.source == "" || spec.name == "" || (!fs.Changed("operations") && !fs.Changed("resources")) || !yes {
			return spec, listing, errors.New("without a terminal, share --with needs --from, --operations or --resources, --name, and --yes; nothing was created")
		}
		return spec, listing, nil
	}
	if spec.source == "" {
		var choices []string
		for _, a := range listing.Agents {
			for _, s := range a.Servers {
				if s.Shareable {
					choices = append(choices, a.Agent.Name+"/"+s.Name)
				}
			}
		}
		if len(choices) == 0 {
			return spec, listing, errors.New("no usable source on this host; run sources refresh")
		}
		fmt.Fprintln(errOut, "Sources:")
		for i, c := range choices {
			fmt.Fprintf(errOut, "  %d. %s\n", i+1, c)
		}
		fmt.Fprint(errOut, "Source (number or AGENT/SERVER): ")
		answer := readLine()
		if n, err := strconv.Atoi(answer); err == nil && n >= 1 && n <= len(choices) {
			answer = choices[n-1]
		}
		spec.source = answer
	}
	agent, server, err := resolveSource(listing, spec.source)
	if err != nil {
		return spec, listing, err
	}
	spec.source = agent.Agent.Name + "/" + server.Name
	if !fs.Changed("operations") {
		fmt.Fprintln(errOut, "Tools:")
		for _, t := range server.Tools {
			mark := " (can change things)"
			if t.ReadOnly {
				mark = ""
			}
			fmt.Fprintf(errOut, "  %s%s\n", t.Name, mark)
		}
		fmt.Fprint(errOut, "Operations (comma-separated tool names): ")
		spec.operations = splitList(readLine())
	}
	if !fs.Changed("resources") && len(server.Resources) > 0 {
		if askYes(errOut, fmt.Sprintf("Include its %d resources?", len(server.Resources))) {
			spec.resources = "all"
		}
	}
	if spec.name == "" {
		fmt.Fprintf(errOut, "Capability name [%s]: ", server.Name)
		if spec.name = readLine(); spec.name == "" {
			spec.name = server.Name
		}
	}
	return spec, listing, nil
}

// runShare runs share NAME --with PRINCIPAL and the guided share --with.
func runShare(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	network, _ := fs.GetString("network")
	given, _ := fs.GetString("with")
	keyPath, _ := fs.GetString("person-key")
	yes, _ := fs.GetBool("yes")
	if given == "" {
		return errors.New("share needs --with PRINCIPAL")
	}
	var calls int64
	if fs.Changed("calls-per-hour") {
		calls, _ = fs.GetInt64("calls-per-hour")
		if calls < 1 || calls > membership.PolicyMaxCallsPerHour {
			return fmt.Errorf("--calls-per-hour must be 1 to %d", membership.PolicyMaxCallsPerHour)
		}
	}
	identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
	if err != nil {
		return err
	}
	o, err := loadOwner(ctx, client, network, keyPath)
	if err != nil {
		return err
	}
	defer o.signer.Close()
	principal, err := resolveTopPrincipal(o.persons, given)
	if errors.Is(err, host.ErrNotFound) {
		if _, err = client.Call(ctx, "POST", "/v1/networks/"+url.PathEscape(network)+"/sync", nil); err != nil {
			return err
		}
		if o.persons, err = personsOf(ctx, client, network); err != nil {
			return err
		}
		principal, err = resolveTopPrincipal(o.persons, given)
	}
	if err != nil {
		return err
	}
	guided := len(args) < 2
	var name string
	var listing sourcesListing
	var c capabilityRecord
	var spec capabilitySpec
	if guided {
		if spec, listing, err = guidedSpec(ctx, client, fs, errOut); err != nil {
			return err
		}
		name = spec.name
		agent, server, err := resolveSource(listing, spec.source)
		if err != nil {
			return err
		}
		c.Name, c.Operations = name, spec.operations
		c.Source.Agent, c.Source.Server = agent.Agent.Name, server.Name
		switch spec.resources {
		case "":
			c.Resources = json.RawMessage("null")
		case "all":
			c.Resources = json.RawMessage(`"all"`)
		default:
			c.Resources, _ = json.Marshal(strings.Split(spec.resources, ","))
		}
		if spec.envFile != "" {
			c.Credential.EnvFile = &spec.envFile
		}
		if spec.argsGiven {
			c.Credential.Args = spec.args
		}
	} else {
		name = args[1]
		if c, err = call[capabilityRecord](ctx, client, "GET", "/v1/capabilities/"+url.PathEscape(name)); err != nil {
			return err
		}
		if listing, err = readSources(ctx, client, "/v1/sources"); err != nil {
			return err
		}
	}
	if !membership.ValidCapabilityName(name) {
		return fmt.Errorf("invalid capability name %q", name)
	}
	// A name bound to another host by any stored rule of this person is
	// refused, in every network.
	for _, n := range ownNetworks(ctx, client) {
		if p, err := currentPolicy(ctx, client, n, o.ownerID); err == nil && p != nil {
			for _, r := range p.CapabilityRules {
				if r.Capability == name && r.Host != identity.ID {
					return fmt.Errorf("a capability rule of yours binds %s to host %s (409); choose another name", name, r.Host)
				}
			}
		}
	}
	var server sourceServer
	if agent, s, err := resolveSource(listing, c.Source.Agent+"/"+c.Source.Server); err == nil {
		_ = agent
		server = s
	}
	body := o.body()
	index := -1
	for i, r := range body.CapabilityRules {
		if r.Host == identity.ID && r.Capability == name {
			index = i
		}
	}
	limitChange := ""
	changed := false
	if index >= 0 {
		r := &body.CapabilityRules[index]
		if calls != 0 && calls != r.MaxCallsPerHour {
			// Recipients are shown by label where the principal resolves.
			labels := map[string]string{}
			for _, p := range o.persons {
				labels["person:"+p.PersonID] = p.Member
			}
			var affected []string
			for _, p := range append(append([]string{}, r.Principals...), principalUnless(r.Principals, principal)...) {
				if label, ok := labels[p]; ok {
					p = label
				}
				affected = append(affected, p)
			}
			limitChange = fmt.Sprintf("Calls per hour: %d, now %d, for every recipient: %s\n", r.MaxCallsPerHour, calls, strings.Join(affected, ", "))
			r.MaxCallsPerHour, changed = calls, true
		}
		if !contains(r.Principals, principal) {
			r.Principals, changed = append(r.Principals, principal), true
		}
	} else {
		limit := int64(shareMaxCallsPerHour)
		if calls != 0 {
			limit = calls
		}
		body.CapabilityRules = append(body.CapabilityRules, membership.CapabilityRule{Host: identity.ID, Capability: name, Principals: []string{principal}, MaxInputBytes: shareMaxInputBytes, MaxCallsPerHour: limit})
		changed = true
	}
	label := ""
	for _, p := range o.persons {
		if p.PersonID == o.ownerID {
			label = p.Member
		}
	}
	printReview(errOut, label+"/"+name, c, server, given, limitChange)
	if err = confirmShare(errOut, yes); err != nil {
		return err
	}
	if guided {
		// An identical capability that already exists is not created again;
		// otherwise creating it claims the name in every network and shares
		// it in this one, in one policy per network.
		createSpec, err := createBody(listing, spec)
		if err != nil {
			return err
		}
		if _, existsErr := client.Call(ctx, "GET", "/v1/capabilities/"+url.PathEscape(name), nil); existsErr == nil {
			// The create request is always made: an identical capability
			// answers 200 and is shared below; a different one under the
			// name answers 409, and nothing is shared.
			createSpec["policies"] = []membership.Policy{}
			if _, err = client.Call(ctx, "POST", "/v1/capabilities", createSpec); err != nil {
				return err
			}
		} else {
			_, signed, err := createWithClaims(ctx, client, keyPath, name, createSpec, network, principal, calls)
			if err != nil {
				return err
			}
			var policy any
			if p, ok := signed[network]; ok {
				policy = p
			}
			return printJSON(out, map[string]any{"policy": policy, "capability": name, "principal": principal, "created": true})
		}
	}
	if !changed {
		var policy any
		if o.current != nil {
			policy = o.current
		}
		return printJSON(out, map[string]any{"policy": policy, "capability": name, "principal": principal, "created": false})
	}
	data, _, err := o.edit(ctx, client, false, func(body *membership.PolicyBody) (bool, error) {
		return shareRule(body, identity.ID, name, principal, calls), nil
	})
	if err != nil {
		return err
	}
	return printJSON(out, map[string]any{"policy": json.RawMessage(data), "capability": name, "principal": principal, "created": false})
}

// shareRule adds principal to this host's rule for name, usually its claim,
// creating the rule when the policy has none; calls, when nonzero, sets its
// limit. It reports whether anything changed.
func shareRule(body *membership.PolicyBody, hostID, name, principal string, calls int64) bool {
	i := hostRule(body.CapabilityRules, hostID, name)
	if i < 0 {
		limit := int64(shareMaxCallsPerHour)
		if calls != 0 {
			limit = calls
		}
		body.CapabilityRules = append(body.CapabilityRules, membership.CapabilityRule{Host: hostID, Capability: name, Principals: []string{principal}, MaxInputBytes: shareMaxInputBytes, MaxCallsPerHour: limit})
		return true
	}
	r := &body.CapabilityRules[i]
	changed := false
	if calls != 0 && calls != r.MaxCallsPerHour {
		r.MaxCallsPerHour, changed = calls, true
	}
	if !contains(r.Principals, principal) {
		r.Principals, changed = append(r.Principals, principal), true
	}
	return changed
}

// hostRule is the index of the capability rule binding name to hostID, or
// -1.
func hostRule(rules []membership.CapabilityRule, hostID, name string) int {
	for i, r := range rules {
		if r.Host == hostID && r.Capability == name {
			return i
		}
	}
	return -1
}

func sortedNetworks(ids map[string]string) []string {
	out := make([]string, 0, len(ids))
	for n := range ids {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// createWithClaims creates a capability and claims its name: for every
// network in which this host is bound to its person, it signs that
// person's policy with this host's rule for the name, a claim without
// principals, or in shareNetwork the rule with principal, and sends the
// policies with the record. An identical repeat signs nothing. An
// edit_conflict starts again from the edit route, at most 3 times. It
// returns the daemon's answer and the signed policies by network.
func createWithClaims(ctx context.Context, client host.Client, keyPath, name string, body map[string]any, shareNetwork, principal string, calls int64) (json.RawMessage, map[string]membership.Policy, error) {
	signed := map[string]membership.Policy{}
	body["policies"] = []membership.Policy{}
	if _, err := client.Call(ctx, "GET", "/v1/capabilities/"+url.PathEscape(name), nil); err == nil {
		data, err := client.Call(ctx, "POST", "/v1/capabilities", body)
		return data, signed, err
	}
	_, persons, err := readHostPersons(ctx, client)
	if err != nil {
		return nil, nil, err
	}
	if len(persons.ids) == 0 {
		// A host without a person creates the record without claims.
		data, err := client.Call(ctx, "POST", "/v1/capabilities", body)
		return data, signed, err
	}
	// Claims are signed in the networks where this host is bound to the
	// signing person; networks bound to another person gain the claim at
	// their first share.
	signer, err := person.Load(keyPath)
	if err != nil {
		return nil, nil, err
	}
	signerID := membership.PersonID(signer.PublicKey())
	signer.Close()
	networks := []string{}
	for _, n := range sortedNetworks(persons.ids) {
		if persons.ids[n] == signerID {
			networks = append(networks, n)
		}
	}
	if len(networks) == 0 {
		return nil, nil, fmt.Errorf("this host is not bound to the person key %s in any network", signerID)
	}
	owners := map[string]*ownerContext{}
	defer func() {
		for _, o := range owners {
			o.signer.Close()
		}
	}()
	for attempt := 0; ; attempt++ {
		policies := []membership.Policy{}
		for _, n := range networks {
			o := owners[n]
			if o == nil {
				if o, err = loadOwner(ctx, client, n, keyPath); err != nil {
					return nil, nil, fmt.Errorf("claiming %s in %s: %w", name, n, err)
				}
				owners[n] = o
			} else if err = o.start(ctx, client); err != nil {
				return nil, nil, err
			}
			b := o.body()
			// A name another host holds is refused before anything is signed.
			for _, r := range b.CapabilityRules {
				if r.Capability == name && r.Host != o.hostID {
					return nil, nil, fmt.Errorf("a capability rule of yours binds %s to host %s (409); choose another name", name, r.Host)
				}
			}
			if n == shareNetwork {
				shareRule(&b, o.hostID, name, principal, calls)
			} else if hostRule(b.CapabilityRules, o.hostID, name) < 0 {
				b.CapabilityRules = append(b.CapabilityRules, membership.CapabilityRule{Host: o.hostID, Capability: name, Principals: []string{}, MaxInputBytes: shareMaxInputBytes, MaxCallsPerHour: shareMaxCallsPerHour})
			}
			p, err := o.next(n, b, n != shareNetwork)
			if err != nil {
				return nil, nil, err
			}
			policies = append(policies, p)
			signed[n] = p
		}
		body["policies"] = policies
		data, err := client.Call(ctx, "POST", "/v1/capabilities", body)
		if isEditConflict(err) && attempt < editRetries {
			continue
		}
		return data, signed, err
	}
}

func principalUnless(list []string, principal string) []string {
	if contains(list, principal) {
		return nil
	}
	return []string{principal}
}

// ownNetworks lists this host's networks.
func ownNetworks(ctx context.Context, client host.Client) []string {
	networks, err := call[[]host.Network](ctx, client, "GET", "/v1/networks")
	if err != nil {
		return nil
	}
	ids := make([]string, len(networks))
	for i, n := range networks {
		ids[i] = n.ID
	}
	return ids
}

// runUnshare removes a principal from the capability's rule for this host.
func runUnshare(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	network, _ := fs.GetString("network")
	given, _ := fs.GetString("with")
	keyPath, _ := fs.GetString("person-key")
	if given == "" {
		return errors.New("unshare needs --with PRINCIPAL")
	}
	name := args[1]
	identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
	if err != nil {
		return err
	}
	o, err := loadOwner(ctx, client, network, keyPath)
	if err != nil {
		return err
	}
	defer o.signer.Close()
	principal, err := resolveTopPrincipal(o.persons, given)
	if err != nil {
		return err
	}
	removed := 0
	data, _, err := o.edit(ctx, client, true, func(body *membership.PolicyBody) (bool, error) {
		removed = 0
		// The rule stays as a claim when its last principal goes.
		if i := hostRule(body.CapabilityRules, identity.ID, name); i >= 0 && contains(body.CapabilityRules[i].Principals, principal) {
			body.CapabilityRules[i].Principals = without(body.CapabilityRules[i].Principals, []string{principal})
			removed++
		}
		return removed > 0, nil
	})
	if err != nil {
		return err
	}
	if removed == 0 {
		var policy any
		if o.current != nil {
			policy = o.current
		}
		return printJSON(out, map[string]any{"policy": policy, "capability": name, "principal": principal, "removed": 0, "note": "the rule for " + name + " on this host does not name " + principal + "; access through a group or everyone is unaffected, and block stops a person at once"})
	}
	fmt.Fprintf(errOut, "%s's future calls to %s are denied. Calls already running finish, and queued calls are refused when they would start.\n", given, name)
	return printJSON(out, map[string]any{"policy": json.RawMessage(data), "capability": name, "principal": principal, "removed": removed})
}

// runShares lists this host's capabilities with their recipients, and every
// capability rule in this person's stored policies.
func runShares(ctx context.Context, client host.Client, fs *pflag.FlagSet, out io.Writer) error {
	network, _ := fs.GetString("network")
	asJSON, _ := fs.GetBool("json")
	list, err := call[struct {
		Capabilities []json.RawMessage `json:"capabilities"`
	}](ctx, client, "GET", "/v1/capabilities")
	if err != nil {
		return err
	}
	identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
	if err != nil {
		return err
	}
	_, persons, err := readHostPersons(ctx, client)
	if err != nil {
		return err
	}
	capabilities := []map[string]any{}
	for _, raw := range list.Capabilities {
		var entry map[string]any
		if err = json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		var c capabilityRecord
		_ = json.Unmarshal(raw, &c)
		commands := []string{}
		for _, r := range c.Recipients {
			if network == "" || r.NetworkID == network {
				commands = append(commands, fmt.Sprintf("peerspan unshare %s --with %s --network %s", c.Name, r.Principal, r.NetworkID))
			}
		}
		entry["unshare"] = commands
		capabilities = append(capabilities, entry)
	}
	rules := []map[string]any{}
	for _, n := range ownNetworks(ctx, client) {
		if network != "" && n != network {
			continue
		}
		person := persons.ids[n]
		if person == "" {
			continue
		}
		p, err := currentPolicy(ctx, client, n, person)
		if err != nil || p == nil {
			continue
		}
		for _, r := range p.CapabilityRules {
			entry := map[string]any{"network_id": n, "host": r.Host, "capability": r.Capability, "principals": r.Principals, "max_input_bytes": r.MaxInputBytes, "allow_disconnected": r.AllowDisconnected, "max_calls_per_hour": r.MaxCallsPerHour, "this_host": r.Host == identity.ID}
			rules = append(rules, entry)
		}
	}
	if asJSON {
		return printJSON(out, map[string]any{"capabilities": capabilities, "rules": rules})
	}
	if len(capabilities) == 0 && len(rules) == 0 {
		fmt.Fprintln(out, "Nothing is shared, and this host has no capabilities.")
	}
	for _, entry := range capabilities {
		data, _ := json.Marshal(entry)
		var c capabilityRecord
		_ = json.Unmarshal(data, &c)
		credential := "the source's own environment"
		if c.Credential.EnvFile != nil || c.Credential.Args != nil {
			credential = "its own environment file " + deref(c.Credential.EnvFile)
		}
		fmt.Fprintf(out, "%s  from %s/%s  %s  operations: %s  credentials: %s\n", c.Name, c.Source.Agent, c.Source.Server, c.State, strings.Join(c.Operations, ", "), credential)
		for _, r := range c.Recipients {
			label := r.Principal
			if r.Label != nil {
				label = *r.Label
			}
			fmt.Fprintf(out, "  shared with %s in %s; undo: peerspan unshare %s --with %s --network %s\n", label, r.NetworkID, c.Name, r.Principal, r.NetworkID)
		}
	}
	for _, r := range rules {
		if r["this_host"] == true {
			continue
		}
		fmt.Fprintf(out, "%s on %s, in %s: %v\n", r["capability"], r["host"], r["network_id"], r["principals"])
	}
	return nil
}

// runDiscover lists reachable agents and usable capabilities.
func runDiscover(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out io.Writer) error {
	network, _ := fs.GetString("network")
	asJSON, _ := fs.GetBool("json")
	query := url.Values{}
	if len(args) > 1 {
		query.Set("person", args[1])
	}
	if network != "" {
		query.Set("network", network)
	}
	data, err := client.Call(ctx, "GET", "/v1/discover?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(out, data)
	}
	var d host.Discovery
	if err = json.Unmarshal(data, &d); err != nil {
		return err
	}
	fmt.Fprintln(out, "Agents:")
	if len(d.Agents) == 0 {
		fmt.Fprintln(out, "  none")
	}
	for _, a := range d.Agents {
		fmt.Fprintf(out, "  %s  %s\n", a.Address, strings.Join(a.Actions, ", "))
	}
	fmt.Fprintln(out, "Capabilities:")
	if len(d.Capabilities) == 0 {
		fmt.Fprintln(out, "  none")
	}
	for _, c := range d.Capabilities {
		var names []string
		for _, op := range c.Operations {
			names = append(names, op.Name)
		}
		fmt.Fprintf(out, "  %s  %s  %s\n", c.Address, c.State, strings.Join(names, ", "))
	}
	for _, u := range d.Unanswered {
		fmt.Fprintf(out, "did not answer: %s (%s)\n", u.HostID, u.Error)
	}
	return nil
}
