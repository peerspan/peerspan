package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/person"
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

func accessRequest(ctx context.Context, client host.Client, args []string, errOut io.Writer) (string, string, any, error) {
	invalid := errors.New("invalid command; see capsule-host --help")
	if len(args) < 2 {
		return "", "", nil, invalid
	}
	var network, agent, personKey, who, hostID string
	var principals, actions repeated
	var maxBytes, maxArtifactBytes int64
	var allowDisconnected bool
	var validDays int
	fs := flag.NewFlagSet("access "+args[1], flag.ContinueOnError)
	fs.SetOutput(errOut)
	switch args[1] {
	case "allow", "deny", "renew":
		fs.StringVar(&network, "network", "", "network ID")
		fs.StringVar(&personKey, "person-key", "", "ssh-ed25519 public key in ssh-agent, or an unencrypted OpenSSH private key file")
		if args[1] != "renew" {
			fs.StringVar(&agent, "agent", "", "local agent name the rule covers")
			fs.Var(&principals, "principal", "person:PERSON, group:NAME, network, or agent:HOST_ID/AGENT_ID; repeatable")
		}
		if args[1] == "allow" {
			fs.Int64Var(&maxBytes, "max-message-bytes", 65536, "content byte limit, 1 to 65536")
			fs.Int64Var(&maxArtifactBytes, "max-artifact-bytes", 0, "bound on a task's input and result artifacts together, 0 to 1073741824; 0 refuses artifacts; needs --action task.submit")
			fs.BoolVar(&allowDisconnected, "allow-disconnected", false, "permit messages while the receiver is out of sync with coordination")
			fs.IntVar(&validDays, "valid-days", 7, "policy validity, 1 to 90 days")
			fs.Var(&actions, "action", "message.append (the default) or task.submit; repeatable")
		}
	case "show":
		fs.StringVar(&network, "network", "", "network ID")
		fs.StringVar(&who, "person", "", "person ID or label; this host's person by default")
	case "block", "unblock":
		fs.StringVar(&who, "person", "", "person ID or label to block")
		fs.StringVar(&hostID, "host", "", "host ID to block")
	case "blocks":
	default:
		return "", "", nil, invalid
	}
	if err := fs.Parse(args[2:]); err != nil {
		return "", "", nil, err
	}
	if fs.NArg() != 0 {
		return "", "", nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
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
		actions = repeated{membership.PolicyActionMessage}
	}
	for _, action := range actions {
		if !membership.ValidPolicyAction(action) {
			return "", "", nil, fmt.Errorf("--action must be %s or %s", membership.PolicyActionMessage, membership.PolicyActionTask)
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
			found = true
			switch {
			case args[1] == "allow":
				rules = append(rules, membership.PolicyRule{Agent: agent, Principals: resolved, Actions: []string(actions), MaxMessageBytes: maxBytes, MaxArtifactBytes: maxArtifactBytes, AllowDisconnected: allowDisconnected})
			case len(resolved) != 0:
				rule.Principals = without(rule.Principals, resolved)
				if len(rule.Principals) != 0 {
					rules = append(rules, rule)
				}
			}
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
