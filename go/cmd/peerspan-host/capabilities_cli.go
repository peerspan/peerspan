package main

import (
	"context"
	"encoding/base64"
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
	builtinOnly := false
	if fs.Lookup("builtin") != nil {
		builtinOnly, _ = fs.GetBool("builtin")
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
		if builtinOnly && agentName != "" {
			return errors.New("sources refresh takes --builtin or --agent, not both")
		}
		results := []map[string]any{}
		for _, p := range profiles {
			if builtinOnly {
				break
			}
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
		if agentName == "" {
			// Built-in discovery runs without --agent, and alone with --builtin.
			summary := attachSummary{Servers: []attachServer{}, Errors: []discoveryError{}}
			builtin, err := storeBuiltin(ctx, client)
			if err != nil {
				summary.Errors = append(summary.Errors, discoveryError{Source: "builtin", Error: "storing the built-in sources failed: " + err.Error()})
			} else {
				summary.Servers = summarizeBuiltin(builtin)
			}
			fmt.Fprintf(errOut, "builtin: %d built-in sources\n", len(summary.Servers))
			results = append(results, map[string]any{"agent_id": nil, "agent": "builtin", "workspace": nil, "sources": summary})
		}
		return printJSON(out, results)
	case "login":
		return runLogin(ctx, client, "sources", args[2], fs, out, errOut)
	case "logout":
		return runLogout(ctx, client, "sources", args[2], fs, out, errOut)
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
			if s.Transport == "remote" {
				fmt.Fprintf(out, "    url: %s\n", deref(s.URL))
				fmt.Fprintf(out, "    %s\n", authLine(a.Agent.Name+"/"+s.Name, s))
			}
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
	if len(listing.Builtin) > 0 {
		fmt.Fprintln(out, "builtin")
	}
	for _, s := range listing.Builtin {
		state := "usable"
		if !s.Shareable {
			state = "not usable: " + deref(s.Reason)
		}
		account := "unknown"
		if s.Account != nil {
			account = *s.Account
		}
		version := "unknown"
		if s.Version != nil {
			version = *s.Version
		}
		fmt.Fprintf(out, "  builtin/%s  gh %s  account %s  %s\n", s.Name, version, account, state)
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
		if len(s.Capabilities) > 0 {
			fmt.Fprintf(out, "    capabilities: %s\n", strings.Join(s.Capabilities, ", "))
		}
		fmt.Fprintf(out, "    reach: %s\n", reachSentence(s.Reach, s.Account))
	}
	if len(listing.OpenTo) > 0 {
		fmt.Fprintf(out, "Open to: %s\n", strings.Join(listing.OpenTo, ", "))
	}
	if findGH() == "" {
		fmt.Fprintln(out, ghHint)
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
	State           string                `json:"state"`
	Unavailable     []string              `json:"unavailable"`
	Bounds          host.CapabilityBounds `json:"bounds"`
	CredentialReach *host.GHReach         `json:"credential_reach"`
	Auth            *host.AuthView        `json:"auth"`
	Approval        struct {
		Operations json.RawMessage `json:"operations"`
		AgentSelf  *bool           `json:"agent_self"`
	} `json:"approval"`
	Recipients []struct {
		NetworkID  string  `json:"network_id"`
		Principal  string  `json:"principal"`
		Label      *string `json:"label"`
		AgentState *string `json:"agent_state"`
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
		if agent == "builtin" {
			break // builtin/NAME names a built-in source
		}
		if (agent == "" || a.Agent.Name == agent) && a.server(server) != nil {
			matches = append(matches, a)
		}
	}
	if agent == "" || agent == "builtin" {
		builtin := sourcesAgent{}
		builtin.Agent.ID, builtin.Agent.Name = "builtin", "builtin"
		for _, b := range listing.Builtin {
			builtin.Servers = append(builtin.Servers, b.sourceServer)
		}
		builtin.fill()
		if builtin.server(server) != nil {
			matches = append(matches, builtin)
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
	// approval is the requirement's operations as given ("" when not
	// given); noAgentSelf sends agent_self false.
	approval    string
	noAgentSelf bool
	bounds      host.CapabilityBounds
}

// approvalOperations is the JSON operations of an approval mode given on
// the command line: none, changing, all, or OP[,OP...].
func approvalOperations(mode string) any {
	switch mode {
	case "none", "changing", "all":
		return mode
	}
	list := splitList(mode)
	if list == nil {
		list = []string{}
	}
	return list
}

// approvalRequest is the approval object for a spec, or nil when neither
// --approval nor --no-agent-self-approval was given.
func (spec capabilitySpec) approvalRequest() map[string]any {
	if spec.approval == "" && !spec.noAgentSelf {
		return nil
	}
	mode := spec.approval
	if mode == "" {
		mode = "none"
	}
	body := map[string]any{"operations": approvalOperations(mode)}
	if spec.noAgentSelf {
		body["agent_self"] = false
	}
	return body
}

// approvalMode reads a record's approval operations: the mode, or "" and
// the list.
func (c capabilityRecord) approvalMode() (string, []string) {
	var mode string
	if json.Unmarshal(c.Approval.Operations, &mode) == nil && mode != "" {
		return mode, nil
	}
	var list []string
	if json.Unmarshal(c.Approval.Operations, &list) == nil && list != nil {
		return "", list
	}
	return "none", nil
}

// approvalText is the readable approval of capability list: MODE and
// +agent_self or -agent_self.
func (c capabilityRecord) approvalText() string {
	mode, list := c.approvalMode()
	if mode == "" {
		mode = strings.Join(list, ",")
	}
	self := "+agent_self"
	if c.Approval.AgentSelf != nil && !*c.Approval.AgentSelf {
		self = "-agent_self"
	}
	return mode + " " + self
}

// writeTool reports whether a selected operation is a tool the snapshot
// does not mark read-only.
func writeTool(server sourceServer, op string) bool {
	for _, t := range server.Tools {
		if t.Name == op {
			return !t.ReadOnly
		}
	}
	return true
}

// printApprovalReview prints share's approval lines: at most one line for
// the covered operations, then under changing the warning about tools the
// server marks.
func printApprovalReview(errOut io.Writer, c capabilityRecord, server sourceServer) {
	mode, list := c.approvalMode()
	ops := append([]string{}, c.Operations...)
	if string(c.Resources) != "" && string(c.Resources) != "null" {
		ops = append(ops, "read")
	}
	var covered []string
	anyWrite := false
	for _, op := range ops {
		write := op != "read" && writeTool(server, op)
		anyWrite = anyWrite || write
		switch mode {
		case "changing":
			if write {
				covered = append(covered, op)
			}
		case "":
			if contains(list, op) {
				covered = append(covered, op)
			}
		}
	}
	switch {
	case mode == "all":
		fmt.Fprintln(errOut, "Every call waits for your approval at this machine (peerspan approvals).")
	case len(covered) > 0:
		fmt.Fprintf(errOut, "Calls to %s wait for your approval at this machine (peerspan approvals).\n", strings.Join(covered, ", "))
	case anyWrite:
		fmt.Fprintf(errOut, "No call waits for your approval. To require it: peerspan capability approval %s changing\n", c.Name)
	}
	if mode == "changing" {
		fmt.Fprintln(errOut, "Tools are marked by the server itself; a tool it wrongly marks read-only runs without approval.")
	}
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
	if approval := spec.approvalRequest(); approval != nil {
		body["approval"] = approval
	}
	if spec.bounds.Set() {
		body["bounds"] = spec.bounds
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
		if fs.Changed("approval") {
			if spec.approval, _ = fs.GetString("approval"); spec.approval == "" {
				spec.approval = ","
			}
		}
		spec.noAgentSelf, _ = fs.GetBool("no-agent-self-approval")
		boundValues, _ := fs.GetStringArray("bound")
		var err error
		if spec.bounds, err = parseBounds(boundValues); err != nil {
			return err
		}
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
		printWarnings(errOut, data)
		return printJSON(out, data)
	case "list":
		asJSON, _ := fs.GetBool("json")
		data, err := client.Call(ctx, "GET", "/v1/capabilities?lookup=true", nil)
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
			fmt.Fprintf(out, "  approval: %s", c.approvalText())
			fmt.Fprintf(out, "  recipients: %d", len(c.Recipients))
			if c.Bounds.Set() {
				fmt.Fprintf(out, "  bounds: %s", host.BoundsAllowedText(c.Bounds))
			}
			fmt.Fprintln(out)
		}
		return nil
	case "show":
		data, err := client.Call(ctx, "GET", "/v1/capabilities/"+url.PathEscape(args[2])+"?lookup=true", nil)
		if err != nil {
			return err
		}
		return printJSON(out, data)
	case "remove":
		return removeCapability(ctx, client, args[2], fs, out, errOut)
	case "login":
		return runLogin(ctx, client, "capability", args[2], fs, out, errOut)
	case "logout":
		return runLogout(ctx, client, "capability", args[2], fs, out, errOut)
	case "approval":
		self, _ := fs.GetBool("agent-self")
		noSelf, _ := fs.GetBool("no-agent-self")
		if self && noSelf {
			return errors.New("give --agent-self or --no-agent-self, not both")
		}
		body := map[string]any{"operations": approvalOperations(args[3])}
		if self || noSelf {
			body["agent_self"] = self
		}
		data, err := client.Call(ctx, "PUT", "/v1/capabilities/"+url.PathEscape(args[2])+"/approval", body)
		if err != nil {
			return err
		}
		return printJSON(out, data)
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
	// Every stored policy that holds this host's rule for the name, claim
	// included, whoever owns it and whether or not this host is still bound
	// in that network: a claim left behind would come back on rebinding.
	type holder struct{ network, personID, label string }
	var holders []holder
	for _, n := range ownNetworks(ctx, client) {
		persons, err := personsOf(ctx, client, n)
		if err != nil {
			return err
		}
		for _, p := range persons {
			if policy, err := currentPolicy(ctx, client, n, p.PersonID); err == nil && policy != nil && hostRule(policy.CapabilityRules, identity.ID, name) >= 0 {
				holders = append(holders, holder{n, p.PersonID, p.Member})
			}
		}
	}
	signed := []json.RawMessage{}
	if len(holders) > 0 {
		signer, err := person.Load(keyPath)
		if err != nil {
			return fmt.Errorf("withdrawing %s needs the person key; the capability is kept: %w", name, err)
		}
		signerID := membership.PersonID(signer.PublicKey())
		signer.Close()
		var others []holder
		for _, h := range holders {
			if h.personID != signerID {
				// Another person's policy cannot be withdrawn with this key.
				others = append(others, h)
				continue
			}
			o, err := loadOwner(ctx, client, h.network, keyPath)
			if err != nil {
				return fmt.Errorf("withdrawing %s from %s failed; the capability is kept, and repeating the command finishes the removal: %w", name, h.network, err)
			}
			data, changed, err := o.edit(ctx, client, true, func(body *membership.PolicyBody) (bool, error) {
				i := hostRule(body.CapabilityRules, identity.ID, name)
				if i < 0 {
					return false, nil
				}
				body.CapabilityRules = append(body.CapabilityRules[:i:i], body.CapabilityRules[i+1:]...)
				return true, nil
			})
			o.close()
			if changed {
				signed = append(signed, data)
			}
			if err != nil {
				return fmt.Errorf("withdrawing %s from %s failed; the capability is kept, and repeating the command finishes the removal: %w", name, h.network, err)
			}
		}
		if len(others) > 0 {
			var named []string
			for _, h := range others {
				who := h.personID
				if h.label != "" {
					who = h.label + " (" + h.personID + ")"
				}
				named = append(named, who+" in network "+h.network)
			}
			return fmt.Errorf("the policy of %s holds this host's rule for %s, and this key cannot withdraw it; the capability is kept; run the command again with that person's key (--person-key)", strings.Join(named, ", and of "), name)
		}
	}
	data, err := client.Call(ctx, "DELETE", "/v1/capabilities/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	return printJSON(out, map[string]any{"capability": json.RawMessage(data), "policies": signed})
}

// review is what share prints before asking for confirmation.
func printReview(errOut io.Writer, address string, c capabilityRecord, server sourceServer, principal, recipientExtra, limitChange string, reach *host.GHReach, account *string) {
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
	for _, line := range boundsBlock(c, server) {
		fmt.Fprintln(errOut, line)
	}
	printApprovalReview(errOut, c, server)
	auth := c.Auth
	if auth == nil {
		auth = server.Auth
	}
	if text := credentialText(c, server, auth); text != "" {
		fmt.Fprintf(errOut, "Credential: %s\n", text)
	} else if c.Credential.EnvFile != nil || c.Credential.Args != nil {
		fmt.Fprintf(errOut, "Credentials: the capability's own environment file %s", deref(c.Credential.EnvFile))
		if c.Credential.Args != nil {
			fmt.Fprintf(errOut, ", with arguments %s", strings.Join(c.Credential.Args, " "))
		}
		fmt.Fprintln(errOut)
	} else {
		fmt.Fprintf(errOut, "Credentials: the source's own environment on this host\n")
	}
	fmt.Fprintf(errOut, "Recipient: %s\n", principal)
	fmt.Fprint(errOut, recipientExtra)
	if limitChange != "" {
		fmt.Fprint(errOut, limitChange)
	}
	fmt.Fprintln(errOut, reachStatement(principal, c, reach, account))
}

// printWarnings prints a create answer's warnings to stderr.
func printWarnings(errOut io.Writer, data []byte) {
	var created struct {
		Warnings []string `json:"warnings"`
	}
	_ = json.Unmarshal(data, &created)
	for _, w := range created.Warnings {
		fmt.Fprintln(errOut, "warning: "+w)
	}
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
	if fs.Changed("approval") {
		if spec.approval, _ = fs.GetString("approval"); spec.approval == "" {
			spec.approval = ","
		}
	}
	spec.noAgentSelf, _ = fs.GetBool("no-agent-self-approval")
	boundValues, _ := fs.GetStringArray("bound")
	var err error
	if spec.bounds, err = parseBounds(boundValues); err != nil {
		return spec, sourcesListing{}, err
	}
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
		if agent, server, err := resolveSource(listing, spec.source); err == nil && deref(server.Reason) == "login" {
			source := agent.Agent.Name + "/" + server.Name
			return spec, listing, fmt.Errorf("%s needs a sign-in first: run peerspan sources login %s", source, source)
		}
		return spec, listing, nil
	}
	if spec.source == "" {
		var choices []string
		for _, a := range listing.Agents {
			for _, s := range a.Servers {
				if s.Shareable || deref(s.Reason) == "login" {
					choices = append(choices, a.Agent.Name+"/"+s.Name)
				}
			}
		}
		for _, b := range listing.Builtin {
			if b.Shareable {
				choices = append(choices, "builtin/"+b.Name)
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
	if deref(server.Reason) == "login" {
		// A source that needs a sign-in gets it before the operations.
		if err = signIn(ctx, client, agent.Agent.Name, server.Name, nil, loginOptions{command: "sources login"}, io.Discard, errOut); err != nil {
			return spec, listing, err
		}
		if listing, err = readSources(ctx, client, "/v1/sources"); err != nil {
			return spec, listing, err
		}
		if agent, server, err = resolveSource(listing, agent.Agent.Name+"/"+server.Name); err != nil {
			return spec, listing, err
		}
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
	// Without --approval, a selection with a tool that can change things
	// asks whether its calls wait for approval.
	if !fs.Changed("approval") {
		write := false
		for _, op := range spec.operations {
			write = write || writeTool(server, op)
		}
		if write {
			fmt.Fprint(errOut, "Require your approval for each call to tools that can change things? [Y/n] ")
			switch strings.ToLower(readLine()) {
			case "", "y", "yes":
				spec.approval = "changing"
			default:
				spec.approval = "none"
			}
		}
	}
	if !fs.Changed("resources") && len(server.Resources) > 0 {
		if askYes(errOut, fmt.Sprintf("Include its %d resources?", len(server.Resources))) {
			spec.resources = "all"
		}
	}
	if !fs.Changed("bound") {
		if spec.bounds, err = askBounds(errOut, agent.Agent.Name == "builtin"); err != nil {
			return spec, listing, err
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
	// share NAME never changes an existing capability's requirement.
	if len(args) >= 2 && (fs.Changed("approval") || fs.Changed("no-agent-self-approval")) {
		return fmt.Errorf("share %s never changes its approval requirement; use peerspan capability approval %s MODE", args[1], args[1])
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
	defer o.close()
	principal, recipient, err := resolveRecipient(ctx, client, o, network, given)
	if err != nil {
		return err
	}
	guided := len(args) < 2
	if guided {
		// The guided share may create the capability, which claims its
		// name in the signing person's networks: the share network must be
		// one of them, or nothing is created.
		_, persons, err := readHostPersons(ctx, client)
		if err != nil {
			return err
		}
		if persons.ids[network] != o.ownerID {
			return fmt.Errorf("this host is not bound to %s in network %s; nothing was created", o.ownerID, network)
		}
	}
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
		if approval := spec.approvalRequest(); approval != nil {
			c.Approval.Operations, _ = json.Marshal(approval["operations"])
			if self, ok := approval["agent_self"].(bool); ok {
				c.Approval.AgentSelf = &self
			}
		} else {
			c.Approval.Operations = json.RawMessage(`"none"`)
		}
		c.Bounds = spec.bounds
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
	// The reach: the capability's credential's, or for a new capability the
	// source's, unchecked when it will have its own credential.
	var reach *host.GHReach
	var account *string
	if b := builtinSource(listing, c.Source.Server); b != nil && c.Source.Agent == "builtin" {
		account = b.Account
		switch {
		case !guided:
			reach = c.CredentialReach
		case spec.envFile == "":
			reach = b.Reach
		}
	} else if !guided {
		reach = c.CredentialReach
	}
	recipientText, recipientExtra := given, ""
	if recipient != nil {
		recipientText, recipientExtra = recipient.Address, recipientLines(o, recipient)
	}
	printReview(errOut, label+"/"+name, c, server, recipientText, recipientExtra, limitChange, reach, account)
	printAgentReview(errOut, o, principal)
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
			created, signed, err := createWithClaims(ctx, client, keyPath, name, createSpec, network, principal, calls)
			if err != nil {
				return err
			}
			printWarnings(errOut, created)
			var policy any
			if p, ok := signed[network]; ok {
				policy = p
			}
			return printJSON(out, map[string]any{"policy": policy, "capability": name, "principal": principal, "recipient": recipient.view(), "created": true})
		}
	}
	if !changed {
		var policy any
		if o.current != nil {
			policy = o.current
		}
		return printJSON(out, map[string]any{"policy": policy, "capability": name, "principal": principal, "recipient": recipient.view(), "created": false})
	}
	data, _, err := o.edit(ctx, client, false, func(body *membership.PolicyBody) (bool, error) {
		return shareRule(body, identity.ID, name, principal, calls), nil
	})
	if err != nil {
		return err
	}
	return printJSON(out, map[string]any{"policy": json.RawMessage(data), "capability": name, "principal": principal, "recipient": recipient.view(), "created": false})
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
	signerID := ""
	if keyPath == "" {
		for _, network := range sortedNetworks(persons.ids) {
			selected, e := selectedLinkAdministrator(ctx, client, network, keyPath)
			if e != nil {
				return nil, nil, e
			}
			if selected != nil {
				signerID = personIDFromKey(selected.PersonPublicKey)
				break
			}
		}
	}
	if signerID == "" {
		signer, err := person.Load(keyPath)
		if err != nil {
			return nil, nil, err
		}
		signerID = membership.PersonID(signer.PublicKey())
		signer.Close()
	}
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
			o.close()
		}
	}()
	for attempt := 0; ; attempt++ {
		policies := []membership.Policy{}
		catalogs := []host.CapabilityClaimCatalog{}
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
			if o.device != nil {
				encoded, err := json.Marshal(p)
				if err != nil {
					return nil, nil, err
				}
				var fields map[string]json.RawMessage
				if err = json.Unmarshal(encoded, &fields); err != nil {
					return nil, nil, err
				}
				delete(fields, "signature")
				encoded, err = json.Marshal(fields)
				if err != nil {
					return nil, nil, err
				}
				intent, err := json.Marshal(map[string]string{"capability": name, "policy_base64": base64.StdEncoding.EncodeToString(encoded)})
				if err != nil {
					return nil, nil, err
				}
				prepared, err := linkCall[host.LinkActionResult](ctx, client, "POST", "/v1/networks/"+url.PathEscape(n)+"/link-actions", host.LinkActionRequest{Kind: "policy_claim", PayloadBase64: base64.StdEncoding.EncodeToString(intent), CertificateID: o.device.CertificateID})
				if err != nil {
					return nil, nil, err
				}
				if prepared.Committed {
					return nil, nil, errors.New("claim preparation unexpectedly committed a policy")
				}
				catalogs = append(catalogs, host.CapabilityClaimCatalog{NetworkID: n, Catalog: prepared.Catalog})
			} else {
				policies = append(policies, p)
			}
			signed[n] = p
		}
		body["policies"] = policies
		body["catalogs"] = catalogs
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
	defer o.close()
	var rule *membership.CapabilityRule
	if o.current != nil {
		body := o.body()
		if i := hostRule(body.CapabilityRules, identity.ID, name); i >= 0 {
			rule = &body.CapabilityRules[i]
		}
	}
	principal, recipient, err := resolveRecipient(ctx, client, o, network, given)
	if err != nil {
		// A gone agent can always be removed by its principal.
		var failure *host.ClientError
		if errors.As(err, &failure) && (failure.Code == "unknown" || failure.Code == "unknown_host") {
			fmt.Fprintln(errOut, "error:", err)
			agentFallback(ctx, client, errOut, o, rule, name, network, given)
			return exitStatus(1)
		}
		return err
	}
	removed := 0
	var after membership.CapabilityRule
	data, _, err := o.edit(ctx, client, true, func(body *membership.PolicyBody) (bool, error) {
		removed = 0
		// The rule stays as a claim when its last principal goes.
		if i := hostRule(body.CapabilityRules, identity.ID, name); i >= 0 && contains(body.CapabilityRules[i].Principals, principal) {
			body.CapabilityRules[i].Principals = without(body.CapabilityRules[i].Principals, []string{principal})
			after = body.CapabilityRules[i]
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
		note := "the rule for " + name + " on this host does not name " + principal + "; access through a group or everyone is unaffected, and block stops a person at once"
		if recipient != nil {
			note = "the rule for " + name + " on this host does not name " + principal + ". Access through a group or everyone is unaffected."
			if p, ok := hostPerson(o.persons, recipient.HostID); ok && recipient.PersonID != nil {
				note = "the rule for " + name + " on this host does not name " + principal + ". Access through person:" + p.Member + ", a group, or everyone is unaffected."
			}
		}
		return printJSON(out, map[string]any{"policy": policy, "capability": name, "principal": principal, "recipient": recipient.view(), "removed": 0, "note": note})
	}
	fmt.Fprintf(errOut, "%s's future calls to %s are denied. Calls already running finish, and queued calls are refused when they would start.\n", given, name)
	result := map[string]any{"policy": json.RawMessage(data), "capability": name, "principal": principal, "recipient": recipient.view(), "removed": removed}
	if strings.HasPrefix(principal, "person:") {
		if note := agentsLeftNote(ctx, client, o, after, name, network, principal); note != "" {
			result["note"] = note
		}
	}
	return printJSON(out, result)
}

// runShares lists this host's capabilities with their recipients, and every
// capability rule in this person's stored policies.
func runShares(ctx context.Context, client host.Client, fs *pflag.FlagSet, out io.Writer) error {
	network, _ := fs.GetString("network")
	asJSON, _ := fs.GetBool("json")
	list, err := call[struct {
		Capabilities []json.RawMessage `json:"capabilities"`
	}](ctx, client, "GET", "/v1/capabilities?lookup=true")
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
	listing, err := readSources(ctx, client, "/v1/sources")
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
		recipients, _ := entry["recipients"].([]any)
		for i, r := range c.Recipients {
			command := fmt.Sprintf("peerspan unshare %s --with %s --network %s", c.Name, r.Principal, r.NetworkID)
			if r.AgentState != nil {
				// An agent found on its host is removed by its host's address,
				// HOST_ID/NAME, which names exactly that agent.
				if *r.AgentState == "found" {
					if address := removalAddress(r.Principal, r.Label); address != "" {
						command = fmt.Sprintf("peerspan unshare %s --with %s --network %s", c.Name, address, r.NetworkID)
					}
				}
				if i < len(recipients) {
					if m, ok := recipients[i].(map[string]any); ok {
						m["unshare"] = command
					}
				}
			}
			if network == "" || r.NetworkID == network {
				commands = append(commands, command)
			}
		}
		entry["unshare"] = commands
		var account *string
		if b := builtinSource(listing, c.Source.Server); b != nil {
			account = b.Account
		}
		entry["reach"] = reachStatement("Recipients", c, c.CredentialReach, account)
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
		commands, _ := entry["unshare"].([]string)
		for i, r := range c.Recipients {
			label := r.Principal
			if r.Label != nil {
				label = *r.Label
			}
			if r.AgentState != nil {
				if *r.AgentState == "found" {
					label += " (agent)"
				} else {
					label += " (agent, gone)"
				}
			}
			command := fmt.Sprintf("peerspan unshare %s --with %s --network %s", c.Name, r.Principal, r.NetworkID)
			if network == "" && i < len(commands) {
				command = commands[i]
			}
			fmt.Fprintf(out, "  shared with %s in %s; undo: %s\n", label, r.NetworkID, command)
		}
		bounds := "none"
		if c.Bounds.Set() {
			bounds = host.BoundsAllowedText(c.Bounds)
		}
		fmt.Fprintf(out, "  bounds: %s\n", bounds)
		fmt.Fprintf(out, "  reach: %s\n", entry["reach"])
		for _, a := range listing.Agents {
			if srv := a.server(c.Source.Server); a.Agent.Name == c.Source.Agent && srv != nil {
				if text := credentialText(c, *srv, c.Auth); text != "" {
					fmt.Fprintf(out, "  credential: %s\n", text)
				}
			}
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
	if fromAgent, _ := fs.GetString("from-agent"); fromAgent != "" {
		agent, err := localAgentID(ctx, client, fromAgent)
		if err != nil {
			return err
		}
		query.Set("from_agent", agent)
		data, err := client.Call(ctx, "GET", "/v1/discover?"+query.Encode(), nil)
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(out, data)
		}
		var list host.AdapterCapabilities
		if err = json.Unmarshal(data, &list); err != nil {
			return err
		}
		fmt.Fprintf(out, "Capabilities %s may call:\n", fromAgent)
		if len(list.Capabilities) == 0 {
			fmt.Fprintln(out, "  none")
		}
		for _, c := range list.Capabilities {
			var names []string
			for _, op := range c.Operations {
				names = append(names, op.Name)
			}
			fmt.Fprintf(out, "  %s  %s  %s\n", c.Address, c.State, strings.Join(names, ", "))
		}
		for _, u := range list.Unanswered {
			fmt.Fprintf(out, "did not answer: %s (%s)\n", u.HostID, u.Error)
		}
		return nil
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
			name := op.Name
			if op.Approval {
				name += " (needs approval)"
			}
			names = append(names, name)
		}
		line := fmt.Sprintf("  %s  %s  %s", c.Address, c.State, strings.Join(names, ", "))
		if c.ForAgents != nil {
			var agents []string
			for _, a := range c.ForAgents {
				if a.Name != nil {
					agents = append(agents, *a.Name)
				} else {
					agents = append(agents, a.AgentID)
				}
			}
			noun := "agent"
			if len(agents) > 1 {
				noun = "agents"
			}
			line += fmt.Sprintf("  only for your %s %s", noun, strings.Join(agents, ", "))
		}
		fmt.Fprintln(out, line)
		if c.Bounds.Set() {
			fmt.Fprintf(out, "    limited to %s\n", host.BoundsAllowedText(c.Bounds))
		}
	}
	for _, u := range d.Unanswered {
		fmt.Fprintf(out, "did not answer: %s (%s)\n", u.HostID, u.Error)
	}
	return nil
}
