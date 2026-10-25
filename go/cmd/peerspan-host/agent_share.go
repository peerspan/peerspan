package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// agentRecipient is GET /v1/agent-lookup's answer for an agent address.
type agentRecipient struct {
	Principal  string            `json:"principal"`
	HostID     string            `json:"host_id"`
	AgentID    string            `json:"agent_id"`
	PersonID   *string           `json:"person_id"`
	Address    string            `json:"address"`
	Unanswered []host.Unanswered `json:"unanswered"`
}

// recipientView is the recipient object of share and unshare output.
func (a *agentRecipient) view() any {
	if a == nil {
		return nil
	}
	return map[string]any{"address": a.Address, "host_id": a.HostID, "agent_id": a.AgentID, "person_id": a.PersonID}
}

// lookupAgent resolves PERSON/AGENT or HOST_ID/AGENT through the daemon,
// syncing the network once when the person or host is not known yet.
func lookupAgent(ctx context.Context, client host.Client, network, address string) (*agentRecipient, error) {
	path := "/v1/agent-lookup?" + url.Values{"address": {address}, "network": {network}}.Encode()
	found, err := call[agentRecipient](ctx, client, "GET", path)
	var failure *host.ClientError
	if errors.As(err, &failure) && (failure.Code == "unknown_person" || failure.Code == "unknown_host") {
		if _, err = client.Call(ctx, "POST", "/v1/networks/"+url.PathEscape(network)+"/sync", nil); err != nil {
			return nil, err
		}
		found, err = call[agentRecipient](ctx, client, "GET", path)
	}
	if err != nil {
		return nil, err
	}
	return &found, nil
}

// resolveRecipient resolves a --with value of share, unshare, allow, or
// deny: an agent address through the lookup route, and any other value as
// a principal, syncing once when a person is not known yet. It returns the
// principal and, for an agent address, the lookup's answer.
func resolveRecipient(ctx context.Context, client host.Client, o *ownerContext, network, given string) (string, *agentRecipient, error) {
	if _, _, ok, err := host.SplitAgentAddress(given); err != nil {
		return "", nil, errors.New(strings.TrimPrefix(err.Error(), host.ErrInvalid.Error()+": "))
	} else if ok {
		found, err := lookupAgent(ctx, client, network, given)
		if err != nil {
			return "", nil, err
		}
		// The lookup may have synced: persons may have changed.
		if persons, err := personsOf(ctx, client, network); err == nil {
			o.persons = persons
		}
		return found.Principal, found, nil
	}
	principal, err := resolveTopPrincipal(o.persons, given)
	if errors.Is(err, host.ErrNotFound) {
		// A person admitted moments ago may not have reached this host yet:
		// sync the network once and resolve again.
		if _, err = client.Call(ctx, "POST", "/v1/networks/"+url.PathEscape(network)+"/sync", nil); err != nil {
			return "", nil, err
		}
		if o.persons, err = personsOf(ctx, client, network); err != nil {
			return "", nil, err
		}
		principal, err = resolveTopPrincipal(o.persons, given)
	}
	return principal, nil, err
}

// hostPerson is the person a host is bound to among persons, if any.
func hostPerson(persons []host.Person, hostID string) (host.Person, bool) {
	for _, p := range persons {
		if slices.Contains(p.Hosts, hostID) {
			return p, true
		}
	}
	return host.Person{}, false
}

// printAgentReview prints the review lines specific to an agent principal:
// the agent paragraph and, for the signer's own agent on a trusted host,
// the self access note.
func printAgentReview(errOut io.Writer, o *ownerContext, principal string) {
	hostID, _, ok := membership.AgentPrincipal(principal)
	if !ok {
		return
	}
	fmt.Fprintf(errOut, "Only calls that %s says come from this agent are allowed.\n", hostID)
	p, bound := hostPerson(o.persons, hostID)
	if bound {
		fmt.Fprintf(errOut, "That host makes the claim itself: %s, and any program that can run peerspan as %s on that machine, can call as this agent. %s's other machines and other agents, and other people, cannot.\n", p.Member, p.Member, p.Member)
	} else {
		fmt.Fprintln(errOut, "That host makes the claim itself: anyone, and any program, that can run peerspan as that host's owner can call as this agent. Other machines, other agents, and other people cannot.")
	}
	fmt.Fprintln(errOut, "The share stays with this agent on this machine. If the agent is set up again on another machine, share it again.")
	if bound && p.PersonID == o.ownerID && o.current != nil && slices.Contains(o.current.TrustedHosts, hostID) {
		fmt.Fprintln(errOut, "This machine is trusted, so this agent already reaches all your capabilities through self access. This share matters only if you untrust it.")
	}
}

// recipientLines is the recipient part of the review for an agent address.
func recipientLines(o *ownerContext, found *agentRecipient) string {
	var b strings.Builder
	if p, ok := hostPerson(o.persons, found.HostID); ok && found.PersonID != nil {
		fmt.Fprintf(&b, "  agent %s on host %s, bound to %s\n", found.AgentID, found.HostID, p.Member)
	} else {
		fmt.Fprintf(&b, "  agent %s on host %s, not bound to a person\n", found.AgentID, found.HostID)
	}
	if len(found.Unanswered) > 0 {
		parts := make([]string, len(found.Unanswered))
		for i, u := range found.Unanswered {
			parts[i] = fmt.Sprintf("%s (%s)", u.HostID, u.Error)
		}
		fmt.Fprintf(&b, "Not checked: %s\n", strings.Join(parts, ", "))
	}
	return b.String()
}

// agentFallback lists, after a failed agent resolution in unshare, the
// rule's agent principals on the address's hosts, each with its command.
func agentFallback(ctx context.Context, client host.Client, errOut io.Writer, o *ownerContext, rule *membership.CapabilityRule, name, network, given string) {
	if rule == nil {
		return
	}
	left, _, ok, _ := host.SplitAgentAddress(given)
	if !ok {
		return
	}
	var hosts []string
	if strings.HasPrefix(left, "host_") {
		hosts = []string{left}
	} else if p, err := host.ResolvePerson(o.persons, left); err == nil {
		hosts = p.Hosts
		// A host no longer in the network may have been the person's: its
		// binding is gone with it.
		if members, err := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/members"); err == nil {
			for _, principal := range rule.Principals {
				h, _, ok := membership.AgentPrincipal(principal)
				if ok && !slices.ContainsFunc(members, func(m host.NetworkMember) bool { return m.HostID == h }) {
					hosts = append(hosts, h)
				}
			}
		}
	}
	var lines []string
	for _, principal := range rule.Principals {
		if h, _, ok := membership.AgentPrincipal(principal); ok && slices.Contains(hosts, h) {
			lines = append(lines, fmt.Sprintf("  %s: peerspan unshare %s --with %s --network %s", principal, name, principal, network))
		}
	}
	if len(lines) > 0 {
		fmt.Fprintf(errOut, "Agent shares of %s on those hosts:\n%s\n", name, strings.Join(lines, "\n"))
	}
}

// agentsLeftNote is unshare's note after removing a person whose hosts'
// agents still have their own shares in the rule.
func agentsLeftNote(ctx context.Context, client host.Client, o *ownerContext, rule membership.CapabilityRule, name, network, personPrincipal string) string {
	personID := strings.TrimPrefix(personPrincipal, "person:")
	var p host.Person
	for _, candidate := range o.persons {
		if candidate.PersonID == personID {
			p = candidate
		}
	}
	if p.PersonID == "" {
		return ""
	}
	labels, addresses := map[string]string{}, map[string]string{}
	if list, err := call[struct {
		Recipients []struct {
			NetworkID  string  `json:"network_id"`
			Principal  string  `json:"principal"`
			Label      *string `json:"label"`
			AgentState *string `json:"agent_state"`
		} `json:"recipients"`
	}](ctx, client, "GET", "/v1/capabilities/"+url.PathEscape(name)+"?lookup=true"); err == nil {
		for _, r := range list.Recipients {
			if r.NetworkID == network && r.Label != nil && r.AgentState != nil && *r.AgentState == "found" {
				if address := removalAddress(r.Principal, r.Label); address != "" {
					labels[r.Principal], addresses[r.Principal] = *r.Label, address
				}
			}
		}
	}
	var sentences []string
	for _, principal := range rule.Principals {
		h, _, ok := membership.AgentPrincipal(principal)
		if !ok || !slices.Contains(p.Hosts, h) {
			continue
		}
		label, address := principal, principal
		if l, ok := labels[principal]; ok {
			label, address = l, addresses[principal]
		}
		sentences = append(sentences, fmt.Sprintf("%s still has its own share. Run peerspan unshare %s --with %s --network %s to remove it.", label, name, address, network))
	}
	return strings.Join(sentences, " ")
}

// removalAddress is the HOST_ID/NAME address that removes a found agent
// recipient, from its principal and label (PERSON/NAME or HOST_ID/NAME),
// or "" when the label names no agent.
func removalAddress(principal string, label *string) string {
	hostID, _, ok := membership.AgentPrincipal(principal)
	if !ok || label == nil {
		return ""
	}
	name := (*label)[strings.LastIndex(*label, "/")+1:]
	if !host.AddressableName(name) {
		return ""
	}
	return hostID + "/" + name
}

// localAgentID resolves --from-agent: an agent ID registered on this
// host, or else the exact name of one.
func localAgentID(ctx context.Context, client host.Client, given string) (string, error) {
	agents, err := call[[]host.Agent](ctx, client, "GET", "/v1/agents")
	if err != nil {
		return "", err
	}
	var named []string
	for _, a := range agents {
		if a.ID == given {
			return a.ID, nil
		}
		if a.Name == given {
			named = append(named, a.ID)
		}
	}
	switch len(named) {
	case 0:
		return "", fmt.Errorf("no agent %s on this host", given)
	case 1:
		return named[0], nil
	}
	return "", fmt.Errorf("several agents on this host are named %s; give the agent ID", given)
}
