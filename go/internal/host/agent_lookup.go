package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Sharing with one agent (capabilities slice 3): an owner names another
// person's agent as PERSON/AGENT or HOST_ID/AGENT, and this host asks the
// hosts it may be on, by exact name, with the peer lookup route. The
// resulting principal is the existing agent:HOST_ID/AGENT_ID; names never
// authorize. shares labels such principals by asking their hosts by agent
// ID, and keeps the answers in memory only.

const (
	// agentLookupMaxQuery bounds the lookup route's query string.
	agentLookupMaxQuery = 256
	// agentLookupMaxBody bounds the lookup route's response.
	agentLookupMaxBody = 4096
)

// Agent recipient states, as shares and GET /v1/capabilities show them.
const (
	agentFound      = "found"
	agentNotFound   = "not_found"
	agentHostGone   = "host_gone"
	agentUnanswered = "unanswered"
	agentUnbound    = "unbound"
)

// LookupAgent is the lookup route's agent: its ID and its name, null when
// the name is not addressable.
type LookupAgent struct {
	AgentID string  `json:"agent_id"`
	Name    *string `json:"name"`
}

// AgentLookupResult is GET /v1/agent-lookup.
type AgentLookupResult struct {
	Principal  string       `json:"principal"`
	HostID     string       `json:"host_id"`
	AgentID    string       `json:"agent_id"`
	PersonID   *string      `json:"person_id"`
	Address    string       `json:"address"`
	Unanswered []Unanswered `json:"unanswered"`
}

// SplitAgentAddress reports whether a --with value is an agent address,
// PERSON/AGENT or HOST_ID/AGENT, and splits it. A value with a KIND: prefix,
// everyone, network, or no '/' is not one. A value with two or more '/' or
// an agent name that is not addressable is an error.
func SplitAgentAddress(given string) (left, name string, ok bool, err error) {
	if given == "everyone" || given == membership.PrincipalNetwork {
		return "", "", false, nil
	}
	for _, prefix := range []string{"person:", "group:", "agent:"} {
		if strings.HasPrefix(given, prefix) {
			return "", "", false, nil
		}
	}
	switch strings.Count(given, "/") {
	case 0:
		return "", "", false, nil
	case 1:
	default:
		return "", "", false, fmt.Errorf("%w: invalid recipient %q: use PERSON/AGENT, HOST_ID/AGENT, or person:LABEL for a label that contains /", ErrInvalid, given)
	}
	left, name, _ = strings.Cut(given, "/")
	if left == "" {
		return "", "", false, fmt.Errorf("%w: invalid recipient %q: use PERSON/AGENT, HOST_ID/AGENT, or person:LABEL for a label that contains /", ErrInvalid, given)
	}
	if !AddressableName(name) {
		return "", "", false, fmt.Errorf("%w: invalid agent name %q", ErrInvalid, name)
	}
	return left, name, true, nil
}

// isHostID reports whether an address's left part is a host ID.
func isHostID(left string) bool { return validID(left, "host", 32) }

// LookupLocalAgent is the peer lookup route: whether this host has an
// agent with the exact addressable name, or the agent ID, the query names.
func (s *Store) LookupLocalAgent(ctx context.Context, caller, network, rawQuery string) (*LookupAgent, error) {
	// Both memberships come from current verified members in one read.
	members, err := s.membersOf(ctx, s.db, network)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if _, exists := members[s.identity.ID]; !exists {
		return nil, &codedError{status: http.StatusNotFound, code: "not_found", message: "this host is not in network " + network}
	}
	if _, member := members[caller]; !member || caller == s.identity.ID {
		return nil, ErrForbidden
	}
	invalid := fmt.Errorf("%w: give exactly one of name or agent_id", ErrInvalid)
	if len(rawQuery) > agentLookupMaxQuery {
		return nil, fmt.Errorf("%w: the query is longer than %d bytes", ErrInvalid, agentLookupMaxQuery)
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) != 1 {
		return nil, invalid
	}
	var key, value string
	for k, v := range values {
		if len(v) != 1 || v[0] == "" || (k != "name" && k != "agent_id") {
			return nil, invalid
		}
		key, value = k, v[0]
	}
	locals, err := s.localAgents(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range locals {
		if (key == "name" && a.name == value && AddressableName(value)) || (key == "agent_id" && a.id == value) {
			found := &LookupAgent{AgentID: a.id}
			if AddressableName(a.name) {
				name := a.name
				found.Name = &name
			}
			return found, nil
		}
	}
	return nil, nil
}

// lookupAnswer is one host's answer to a lookup.
type lookupAnswer struct {
	agent       *LookupAgent
	unsupported bool
}

// askAgentLookup asks one host for an agent by name or agent_id within 5
// seconds. A 404 without a JSON code is a host that predates the route.
func (s *Store) askAgentLookup(ctx context.Context, network, host, key, value string) (lookupAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, listingTimeout)
	defer cancel()
	peer, err := s.dialPeer(ctx, host)
	if err != nil {
		return lookupAnswer{}, err
	}
	path := "/peer/v1/networks/" + url.PathEscape(network) + "/agent-lookup?" + url.Values{key: {value}}.Encode()
	status, data, err := s.peerRequestLimit(ctx, peer, http.MethodGet, path, nil, agentLookupMaxBody)
	if err != nil {
		if ctx.Err() != nil {
			return lookupAnswer{}, errors.New("timeout")
		}
		return lookupAnswer{}, err
	}
	if status == http.StatusNotFound {
		var refusal struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(data, &refusal) != nil || refusal.Code == "" {
			return lookupAnswer{unsupported: true}, nil
		}
	}
	if status != http.StatusOK {
		return lookupAnswer{}, fmt.Errorf("peer returned HTTP %d", status)
	}
	var answer struct {
		Agent *LookupAgent `json:"agent"`
	}
	if err = json.Unmarshal(data, &answer); err != nil {
		return lookupAnswer{}, errors.New("invalid lookup answer")
	}
	if a := answer.Agent; a != nil {
		if !validID(a.AgentID, "agent", 16) || (a.Name != nil && !AddressableName(*a.Name)) {
			return lookupAnswer{}, errors.New("invalid lookup answer")
		}
		if (key == "name" && (a.Name == nil || *a.Name != value)) || (key == "agent_id" && a.AgentID != value) {
			return lookupAnswer{}, errors.New("invalid lookup answer")
		}
	}
	return lookupAnswer{agent: answer.Agent}, nil
}

// cachedDirectoryAgent finds an agent in this host's cached directory
// entries of a host, by name or agent ID, for a host without the route.
func (s *Store) cachedDirectoryAgent(network, host, key, value string) *LookupAgent {
	d := s.directoryInit()
	nd := d.networkDir(network)
	d.mu.Lock()
	defer d.mu.Unlock()
	h := nd.hosts[host]
	if h == nil {
		return nil
	}
	for _, a := range h.agents {
		if (key == "name" && a.Name == value) || (key == "agent_id" && a.AgentID == value) {
			found := &LookupAgent{AgentID: a.AgentID}
			if AddressableName(a.Name) {
				name := a.Name
				found.Name = &name
			}
			return found
		}
	}
	return nil
}

// lookupTarget is one host to ask, in one network.
type lookupTarget struct{ network, host, value string }

// lookupResult is a lookup's outcome for one target: found, the agent
// (nil when the host answered that it has none), or err when it did not
// answer.
type lookupResult struct {
	agent *LookupAgent
	err   string
}

// lookupMany asks the targets by key, at most 8 at once. A host that
// predates the route answers from the cached directory, or is unsupported.
func (s *Store) lookupMany(ctx context.Context, targets []lookupTarget, key string) []lookupResult {
	out := make([]lookupResult, len(targets))
	slots := make(chan struct{}, listingConcurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			answer, err := s.askAgentLookup(ctx, t.network, t.host, key, t.value)
			switch {
			case err != nil:
				out[i] = lookupResult{err: err.Error()}
			case answer.unsupported:
				if a := s.cachedDirectoryAgent(t.network, t.host, key, t.value); a != nil {
					out[i] = lookupResult{agent: a}
				} else {
					out[i] = lookupResult{err: hostStateUnsupported}
				}
			default:
				out[i] = lookupResult{agent: answer.agent}
				if answer.agent != nil {
					s.rememberAgent(t.host, answer.agent.AgentID, answer.agent.Name, agentFound)
				} else if key == "agent_id" {
					s.rememberAgent(t.host, t.value, nil, agentNotFound)
				}
			}
		}()
	}
	wg.Wait()
	return out
}

// ResolveAgentAddress is GET /v1/agent-lookup: it turns PERSON/AGENT or
// HOST_ID/AGENT into the agent principal, asking the hosts the agent may
// be on.
func (s *Store) ResolveAgentAddress(ctx context.Context, address, given string) (AgentLookupResult, error) {
	left, name, ok, err := SplitAgentAddress(address)
	if err != nil {
		return AgentLookupResult{}, err
	}
	if !ok {
		return AgentLookupResult{}, fmt.Errorf("%w: %q is not an agent address; use PERSON/AGENT or HOST_ID/AGENT", ErrInvalid, address)
	}
	network, err := s.directoryNetwork(ctx, given)
	if err != nil {
		return AgentLookupResult{}, err
	}
	members, err := s.NetworkMembers(ctx, network)
	if err != nil {
		return AgentLookupResult{}, err
	}
	byHost := map[string]NetworkMember{}
	for _, m := range members {
		byHost[m.HostID] = m
	}
	var hosts []string
	who := left
	if isHostID(left) {
		if _, ok := byHost[left]; !ok {
			return AgentLookupResult{}, &codedError{status: http.StatusNotFound, code: "unknown_host", message: fmt.Sprintf("unknown host %s in network %s", left, network)}
		}
		hosts = []string{left}
	} else {
		g, err := s.loadProductGovernance(ctx, s.db, network)
		if err != nil {
			return AgentLookupResult{}, err
		}
		p, err := ResolvePerson(g.personList(), left)
		if errors.Is(err, ErrNotFound) {
			return AgentLookupResult{}, &codedError{status: http.StatusNotFound, code: "unknown_person", message: strings.TrimPrefix(err.Error(), ErrNotFound.Error()+": ")}
		}
		if err != nil {
			return AgentLookupResult{}, err
		}
		who = p.Member
		for _, m := range members {
			if m.PersonID != nil && *m.PersonID == p.PersonID {
				hosts = append(hosts, m.HostID)
			}
		}
	}
	var targets []lookupTarget
	for _, h := range hosts {
		if h != s.identity.ID {
			targets = append(targets, lookupTarget{network, h, name})
			continue
		}
		locals, err := s.localAgents(ctx)
		if err != nil {
			return AgentLookupResult{}, err
		}
		for _, a := range locals {
			if a.name == name {
				return AgentLookupResult{}, &codedError{status: http.StatusBadRequest, code: "local", message: fmt.Sprintf("%s is on this host, and a host never calls itself. Share with an agent on another machine.", address)}
			}
		}
	}
	results := s.lookupMany(ctx, targets, "name")
	unanswered := []Unanswered{}
	var matches []int
	for i, r := range results {
		switch {
		case r.err != "":
			unanswered = append(unanswered, Unanswered{HostID: targets[i].host, Error: r.err})
		case r.agent != nil:
			matches = append(matches, i)
		}
	}
	sort.Slice(unanswered, func(i, j int) bool { return unanswered[i].HostID < unanswered[j].HostID })
	switch len(matches) {
	case 0:
		message := fmt.Sprintf("%s has no agent named %s on the hosts that answered.", who, name)
		if isHostID(left) {
			message = fmt.Sprintf("%s has no agent named %s.", left, name)
		}
		if len(unanswered) > 0 {
			parts := make([]string, len(unanswered))
			for i, u := range unanswered {
				parts[i] = fmt.Sprintf("%s (%s)", u.HostID, u.Error)
			}
			message += fmt.Sprintf(" Not answered: %s. Try again when it is online, or use agent:HOST_ID/AGENT_ID.", strings.Join(parts, ", "))
		}
		return AgentLookupResult{}, &codedError{status: http.StatusNotFound, code: "unknown", message: message, unanswered: unanswered}
	case 1:
	default:
		var found []AddressMatch
		for _, i := range matches {
			found = append(found, AddressMatch{Address: targets[i].host + "/" + name, NetworkID: network})
		}
		sort.Slice(found, func(i, j int) bool { return found[i].Address < found[j].Address })
		return AgentLookupResult{}, &codedError{status: http.StatusConflict, code: "ambiguous", message: fmt.Sprintf("more than one host has an agent named %s; use one of these addresses", name), matches: found}
	}
	host := targets[matches[0]].host
	agent := results[matches[0]].agent
	m := byHost[host]
	out := AgentLookupResult{Principal: "agent:" + host + "/" + agent.AgentID, HostID: host, AgentID: agent.AgentID, PersonID: m.PersonID, Address: host + "/" + name, Unanswered: unanswered}
	if m.PersonID != nil && m.PersonMember != nil && !strings.Contains(*m.PersonMember, "/") {
		out.Address = *m.PersonMember + "/" + name
	}
	return out, nil
}

// agentLabelCache keeps the latest lookup answer for each agent principal,
// in memory only, so GET /v1/capabilities labels agents without peer
// traffic.
type agentLabelCache struct {
	mu      sync.Mutex
	entries map[string]agentLabelEntry
}

type agentLabelEntry struct {
	// name is the agent's addressable name from the latest answer that
	// found it, if any.
	name *string
	// state is found, not_found, or unanswered.
	state string
}

// rememberAgent records a lookup answer for an agent of a host. A state
// other than found keeps the name an earlier answer gave.
func (s *Store) rememberAgent(host, agent string, name *string, state string) {
	c := &s.agentLabels
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]agentLabelEntry{}
	}
	key := host + "/" + agent
	entry := c.entries[key]
	if state == agentFound {
		entry.name = name
	}
	entry.state = state
	c.entries[key] = entry
}

func (s *Store) cachedAgent(host, agent string) (agentLabelEntry, bool) {
	c := &s.agentLabels
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[host+"/"+agent]
	return entry, ok
}

// labelAgentRecipients sets label and agent_state on the agent recipients.
// With lookup, it first asks each agent's host by agent ID, skipping hosts
// that left the network, and updates the cache.
func (s *Store) labelAgentRecipients(ctx context.Context, recipients []Recipient, lookup bool) error {
	members := map[string]map[string]NetworkMember{}
	memberOf := func(network, host string) (NetworkMember, bool, error) {
		if members[network] == nil {
			list, err := s.NetworkMembers(ctx, network)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return NetworkMember{}, false, err
			}
			members[network] = map[string]NetworkMember{}
			for _, m := range list {
				members[network][m.HostID] = m
			}
		}
		m, ok := members[network][host]
		return m, ok, nil
	}
	if lookup {
		var targets []lookupTarget
		seen := map[string]bool{}
		for _, r := range recipients {
			host, agent, ok := membership.AgentPrincipal(r.Principal)
			if !ok {
				continue
			}
			if _, member, err := memberOf(r.NetworkID, host); err != nil {
				return err
			} else if !member || seen[r.NetworkID+"/"+r.Principal] {
				continue
			}
			seen[r.NetworkID+"/"+r.Principal] = true
			targets = append(targets, lookupTarget{r.NetworkID, host, agent})
		}
		for i, result := range s.lookupMany(ctx, targets, "agent_id") {
			t := targets[i]
			if result.err != "" {
				s.rememberAgent(t.host, t.value, nil, agentUnanswered)
			} else if result.agent != nil {
				s.rememberAgent(t.host, t.value, result.agent.Name, agentFound)
			}
		}
	}
	for i := range recipients {
		r := &recipients[i]
		host, agent, ok := membership.AgentPrincipal(r.Principal)
		if !ok {
			continue
		}
		m, member, err := memberOf(r.NetworkID, host)
		if err != nil {
			return err
		}
		entry, cached := s.cachedAgent(host, agent)
		state := agentUnanswered
		switch {
		case !member:
			state = agentHostGone
		case cached && entry.state == agentFound && m.PersonID == nil:
			state = agentUnbound
		case cached:
			state = entry.state
		}
		r.AgentState = &state
		r.Label = nil
		if entry.name != nil {
			label := host + "/" + *entry.name
			if member && m.PersonID != nil && m.PersonMember != nil && !strings.Contains(*m.PersonMember, "/") {
				label = *m.PersonMember + "/" + *entry.name
			}
			r.Label = &label
		}
	}
	return nil
}

func agentLookupRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/agent-lookup", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.ResolveAgentAddress(r.Context(), r.URL.Query().Get("address"), r.URL.Query().Get("network"))
		respond(w, http.StatusOK, result, err)
	})
}

func agentLookupPeerRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("GET /peer/v1/networks/{network}/agent-lookup", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		agent, err := store.LookupLocalAgent(r.Context(), id, r.PathValue("network"), r.URL.RawQuery)
		respond(w, http.StatusOK, map[string]any{"agent": agent}, err)
	})
}
