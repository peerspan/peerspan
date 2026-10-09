package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/person"
	"github.com/spf13/pflag"
)

// Owner access policy. The CLI signs each new version with the owner's
// person key, after fetching the current version from the daemon; the
// daemon verifies and submits it. Blocks are host-local and need no key.

func policyPath(network string) string {
	return "/v1/networks/" + url.PathEscape(network) + "/policy"
}

// currentPolicy fetches the newest verified policy of a person, or nil.
func currentPolicy(ctx context.Context, client host.Client, network, personID string) (*membership.Policy, error) {
	data, err := client.Call(ctx, "GET", policyPath(network)+"?"+url.Values{"person": {personID}}.Encode(), nil)
	var failure *host.ClientError
	if errors.As(err, &failure) && failure.Status == 404 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	delete(fields, "expires_soon")
	data, _ = json.Marshal(fields)
	p, err := membership.DecodePolicy(data)
	return &p, err
}

// resolvePrincipal accepts network, group:NAME, person:PERSON, and
// agent:HOST_ID/AGENT_ID, where PERSON is a person ID, key, or unambiguous
// label.
func resolvePrincipal(persons []host.Person, given string) (string, error) {
	switch {
	case given == membership.PrincipalNetwork:
		return given, nil
	case strings.HasPrefix(given, "agent:"):
		if _, _, ok := membership.AgentPrincipal(given); !ok {
			return "", fmt.Errorf("invalid agent principal %q; use agent:HOST_ID/AGENT_ID", given)
		}
		return given, nil
	case strings.HasPrefix(given, "group:"):
		if !membership.ValidGroupName(strings.TrimPrefix(given, "group:")) {
			return "", fmt.Errorf("invalid group in principal %q", given)
		}
		return given, nil
	case strings.HasPrefix(given, "person:"):
		p, err := host.ResolvePerson(persons, strings.TrimPrefix(given, "person:"))
		if err != nil {
			return "", err
		}
		return "person:" + p.PersonID, nil
	}
	return "", fmt.Errorf("invalid principal %q; use person:PERSON, group:NAME, network, or agent:HOST_ID/AGENT_ID", given)
}

func accessRequest(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet) (string, string, any, error) {
	invalid := invalidCommand()
	if len(args) < 2 {
		return "", "", nil, invalid
	}
	var network, agent, personKey, who, hostID string
	var principals, actions []string
	var maxBytes, maxArtifactBytes int64
	var allowDisconnected, status bool
	var validDays int
	switch args[1] {
	case "allow", "deny", "renew":
		network, _ = fs.GetString("network")
		personKey, _ = fs.GetString("person-key")
		if args[1] != "renew" {
			agent, _ = fs.GetString("agent")
			principals, _ = fs.GetStringArray("principal")
		}
		if args[1] == "allow" {
			actions, _ = fs.GetStringArray("action")
			maxBytes, _ = fs.GetInt64("max-message-bytes")
			maxArtifactBytes, _ = fs.GetInt64("max-artifact-bytes")
			allowDisconnected, _ = fs.GetBool("allow-disconnected")
			validDays, _ = fs.GetInt("valid-days")
		}
	case "show":
		network, _ = fs.GetString("network")
		who, _ = fs.GetString("person")
	case "sync":
		network, _ = fs.GetString("network")
		status, _ = fs.GetBool("status")
	case "block", "unblock":
		who, _ = fs.GetString("person")
		hostID, _ = fs.GetString("host")
	case "blocks":
	default:
		return "", "", nil, invalid
	}

	switch args[1] {
	case "blocks":
		return "GET", "/v1/access-blocks", nil, nil
	case "block", "unblock":
		if (who == "") == (hostID == "") {
			return "", "", nil, fmt.Errorf("access %s needs exactly one of --person or --host", args[1])
		}
		path := "/v1/access-blocks"
		if args[1] == "unblock" {
			path += "/remove"
		}
		return "POST", path, host.BlockAccess{Person: who, Host: hostID}, nil
	case "sync":
		if network == "" {
			return "", "", nil, errors.New("access sync needs --network")
		}
		if status {
			return "GET", policyPath(network) + "/sync", nil, nil
		}
		return "POST", policyPath(network) + "/sync", nil, nil
	case "show":
		if network == "" {
			return "", "", nil, errors.New("access show needs --network")
		}
		path := policyPath(network)
		if who != "" {
			path += "?" + url.Values{"person": {who}}.Encode()
		}
		return "GET", path, nil, nil
	}
	if network == "" || (args[1] != "renew" && agent == "") {
		return "", "", nil, fmt.Errorf("access %s needs --network%s", args[1], map[bool]string{true: "", false: " and --agent"}[args[1] == "renew"])
	}
	if args[1] == "allow" && len(principals) == 0 {
		return "", "", nil, errors.New("access allow needs at least one --principal")
	}
	if len(actions) == 0 {
		actions = []string{membership.PolicyActionMessage}
	}
	for _, action := range actions {
		if !membership.ValidPolicyAction(action) {
			return "", "", nil, fmt.Errorf("--action must be %s, %s, or %s", membership.PolicyActionMessage, membership.PolicyActionTask, membership.PolicyActionDelegate)
		}
	}
	if validDays < 0 || (args[1] == "allow" && (validDays < 1 || validDays > 90)) {
		return "", "", nil, errors.New("--valid-days must be 1 to 90")
	}
	signer, err := person.Load(personKey)
	if err != nil {
		return "", "", nil, err
	}
	defer signer.Close()
	owner := membership.EncodeKey(signer.PublicKey())
	persons, err := personsOf(ctx, client, network)
	if err != nil {
		return "", "", nil, err
	}
	ownerID := ""
	for _, p := range persons {
		if p.PublicKey == owner {
			ownerID = p.PersonID
		}
	}
	if ownerID == "" {
		return "", "", nil, fmt.Errorf("the person key %s is not a current person of that network", membership.PersonID(signer.PublicKey()))
	}
	current, err := currentPolicy(ctx, client, network, ownerID)
	if err != nil {
		return "", "", nil, err
	}
	now := time.Now().Truncate(time.Second)
	if args[1] == "renew" {
		if current == nil {
			return "", "", nil, errors.New("you have no access policy in that network to renew; use access allow")
		}
		p, err := membership.Renewal(signer, *current, now)
		return "POST", policyPath(network), host.SubmitPolicy{Policy: &p}, err
	}
	resolved := make([]string, 0, len(principals))
	for _, given := range principals {
		principal, err := resolvePrincipal(persons, given)
		if err != nil {
			return "", "", nil, err
		}
		resolved = append(resolved, principal)
	}
	version, validFor := int64(1), time.Duration(validDays)*24*time.Hour
	var rules []membership.PolicyRule
	found := false
	if current != nil {
		version = current.Version + 1
		for _, rule := range current.Rules {
			if rule.Agent != agent {
				rules = append(rules, rule)
				continue
			}
			switch {
			case args[1] == "allow" && found:
				// Several rules for the agent become one.
			case args[1] == "allow":
				rules = append(rules, membership.PolicyRule{Agent: agent, Principals: resolved, Actions: []string(actions), MaxMessageBytes: maxBytes, MaxArtifactBytes: maxArtifactBytes, AllowDisconnected: allowDisconnected})
			case len(resolved) != 0:
				rule.Principals = without(rule.Principals, resolved)
				if len(rule.Principals) != 0 {
					rules = append(rules, rule)
				}
			}
			found = true
		}
		if args[1] == "deny" {
			issued, _ := membership.ParseTime(current.IssuedAt)
			until, _ := membership.ParseTime(current.ValidUntil)
			validFor = until.Sub(issued)
		}
	}
	if !found {
		if args[1] == "deny" {
			return "", "", nil, fmt.Errorf("your access policy has no rule for agent %q", agent)
		}
		rules = append(rules, membership.PolicyRule{Agent: agent, Principals: resolved, Actions: []string(actions), MaxMessageBytes: maxBytes, MaxArtifactBytes: maxArtifactBytes, AllowDisconnected: allowDisconnected})
	}
	p, err := membership.SignPolicy(signer, network, version, now, validFor, rules)
	return "POST", policyPath(network), host.SubmitPolicy{Policy: &p}, err
}

// without removes the given principals, keeping the others in order.
func without(principals, removed []string) []string {
	drop := map[string]bool{}
	for _, p := range removed {
		drop[p] = true
	}
	out := []string{}
	for _, p := range principals {
		if !drop[p] {
			out = append(out, p)
		}
	}
	return out
}

// sizeLimit is the largest --files bound: 1 GiB.
const sizeLimit = membership.PolicyMaxArtifactBytes

// parseSize reads a byte count with an optional K, M, or G suffix (powers of
// 1024), from 1 byte to 1 GiB.
func parseSize(value string) (int64, error) {
	invalid := fmt.Errorf("invalid size %q: give 1 to %d bytes, with an optional K, M, or G suffix", value, sizeLimit)
	digits, unit := value, int64(1)
	if n := len(value); n > 0 {
		switch value[n-1] {
		case 'K':
			digits, unit = value[:n-1], 1<<10
		case 'M':
			digits, unit = value[:n-1], 1<<20
		case 'G':
			digits, unit = value[:n-1], 1<<30
		}
	}
	if digits == "" || len(digits) > 10 {
		return 0, invalid
	}
	var n int64
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, invalid
		}
		n = n*10 + int64(c-'0')
	}
	if n < 1 || n > sizeLimit/unit {
		return 0, invalid
	}
	return n * unit, nil
}

// resolveTopPrincipal resolves the PRINCIPAL of allow, deny: everyone or
// network, group:NAME, agent:HOST/AGENT, or person:PERSON or a bare PERSON.
func resolveTopPrincipal(persons []host.Person, given string) (string, error) {
	switch {
	case given == "everyone":
		return membership.PrincipalNetwork, nil
	case given == membership.PrincipalNetwork, strings.HasPrefix(given, "group:"), strings.HasPrefix(given, "agent:"), strings.HasPrefix(given, "person:"):
		return resolvePrincipal(persons, given)
	}
	p, err := host.ResolvePerson(persons, given)
	if err != nil {
		return "", err
	}
	return "person:" + p.PersonID, nil
}

// sameSettings reports whether two rules have the same actions, as sets,
// and the same bounds.
func sameSettings(a, b membership.PolicyRule) bool {
	if a.MaxMessageBytes != b.MaxMessageBytes || a.MaxArtifactBytes != b.MaxArtifactBytes || a.AllowDisconnected != b.AllowDisconnected || len(a.Actions) != len(b.Actions) {
		return false
	}
	have := map[string]bool{}
	for _, action := range a.Actions {
		have[action] = true
	}
	for _, action := range b.Actions {
		if !have[action] {
			return false
		}
	}
	return true
}

// allowOrDeny runs the top-level allow and deny. allow sets a principal's
// access for one agent scope (--agent, default *): it removes the principal
// from every rule of that scope, adds it to the first rule of the scope with
// identical settings or appends a new rule, drops rules left without
// principals, and signs the next version, valid for 7 days. deny removes the
// principal from every rule of the scope, or of every scope without --agent.
func allowOrDeny(ctx context.Context, client host.Client, command, given string, fs *pflag.FlagSet, out io.Writer) error {
	network, _ := fs.GetString("network")
	agent, _ := fs.GetString("agent")
	keyPath, _ := fs.GetString("person-key")
	if !membership.ValidLabel(agent) {
		return fmt.Errorf("invalid agent name %q", agent)
	}
	rule := membership.PolicyRule{Agent: agent, Actions: []string{membership.PolicyActionMessage}, MaxMessageBytes: 65536}
	if command == "allow" {
		noTasks, _ := fs.GetBool("no-tasks")
		delegate, _ := fs.GetBool("delegate")
		files, _ := fs.GetString("files")
		if noTasks && (delegate || fs.Changed("files")) {
			return errors.New("--delegate and --files need tasks; drop --no-tasks")
		}
		if !noTasks {
			rule.Actions = append(rule.Actions, membership.PolicyActionTask)
		}
		if delegate {
			rule.Actions = append(rule.Actions, membership.PolicyActionDelegate)
		}
		if fs.Changed("files") {
			bound, err := parseSize(files)
			if err != nil {
				return err
			}
			rule.MaxArtifactBytes = bound
		}
	}
	signer, err := person.Load(keyPath)
	if err != nil {
		return err
	}
	defer signer.Close()
	owner := membership.EncodeKey(signer.PublicKey())
	persons, err := personsOf(ctx, client, network)
	if err != nil {
		return err
	}
	ownerID := ""
	for _, p := range persons {
		if p.PublicKey == owner {
			ownerID = p.PersonID
		}
	}
	if ownerID == "" {
		return fmt.Errorf("the person key %s is not a current person of that network", membership.PersonID(signer.PublicKey()))
	}
	principal, err := resolveTopPrincipal(persons, given)
	if errors.Is(err, host.ErrNotFound) {
		// A person admitted moments ago may not have reached this host yet:
		// sync the network once and resolve again.
		if _, err = client.Call(ctx, "POST", "/v1/networks/"+url.PathEscape(network)+"/sync", nil); err != nil {
			return err
		}
		if persons, err = personsOf(ctx, client, network); err != nil {
			return err
		}
		principal, err = resolveTopPrincipal(persons, given)
	}
	if err != nil {
		return err
	}
	current, err := currentPolicy(ctx, client, network, ownerID)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	version, validFor := int64(1), 7*24*time.Hour
	var old []membership.PolicyRule
	if current != nil {
		version, old = current.Version+1, current.Rules
	}
	scoped := command == "allow" || fs.Changed("agent")
	var rules []membership.PolicyRule
	removed := 0
	for _, r := range old {
		r.Principals = append([]string{}, r.Principals...)
		if !scoped || r.Agent == agent {
			if kept := without(r.Principals, []string{principal}); len(kept) != len(r.Principals) {
				r.Principals = kept
				removed++
			}
		}
		rules = append(rules, r)
	}
	if command == "allow" {
		added := false
		for i := range rules {
			if rules[i].Agent == agent && sameSettings(rules[i], rule) {
				rules[i].Principals = append(rules[i].Principals, principal)
				added = true
				break
			}
		}
		if !added {
			rule.Principals = []string{principal}
			rules = append(rules, rule)
		}
	}
	kept := []membership.PolicyRule{}
	for _, r := range rules {
		if len(r.Principals) != 0 {
			kept = append(kept, r)
		}
	}
	if command == "deny" {
		if removed == 0 {
			var policy any
			if current != nil {
				policy = current
			}
			return printJSON(out, map[string]any{"policy": policy, "removed": 0, "note": "no rule of your policy names " + principal + "; access through a group or everyone is unaffected, and block stops a person at once"})
		}
		issued, _ := membership.ParseTime(current.IssuedAt)
		until, _ := membership.ParseTime(current.ValidUntil)
		validFor = until.Sub(issued)
	}
	p, err := membership.SignPolicy(signer, network, version, now, validFor, kept)
	if err != nil {
		return err
	}
	data, err := client.Call(ctx, "POST", policyPath(network), host.SubmitPolicy{Policy: &p})
	if err != nil {
		return err
	}
	var stored json.RawMessage = data
	if command == "deny" {
		return printJSON(out, map[string]any{"policy": stored, "removed": removed})
	}
	return printJSON(out, map[string]any{"policy": stored, "principal": principal, "agent": agent, "actions": rule.Actions, "max_artifact_bytes": rule.MaxArtifactBytes})
}
