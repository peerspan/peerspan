package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// The calling side of remote tools: owner calls by target, a durable local
// record per (peer, call_id), automatic idempotent retry of uncertain
// submissions as for tasks, and polling until a final status, sharing the
// task workers' slots.

const (
	listingTimeout     = 5 * time.Second
	listingConcurrency = 8
	// peerToolsMaxBody bounds a listing or call status response, which may
	// hold a 1 MiB result.
	peerToolsMaxBody = 4 << 20
)

// SubmitCall is POST /v1/calls. A null field is treated as absent.
type SubmitCall struct {
	// Target is PERSON/CAPABILITY, HOST_ID/CAPABILITY, PERSON/AGENT/SERVER,
	// or HOST_ID/AGENT/SERVER.
	Target    string          `json:"target"`
	Operation string          `json:"operation"`
	Input     json.RawMessage `json:"input,omitempty"`
	Deadline  string          `json:"deadline,omitempty"`
	Network   string          `json:"network,omitempty"`
	CallID    string          `json:"call_id,omitempty"`
	// Origin makes the call as one of this host's agents.
	Origin *Origin `json:"origin,omitempty"`
}

func sameOrigin(a, b *Origin) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// OutboundCall is the local record of a submitted call.
type OutboundCall struct {
	PeerHostID string `json:"peer_host_id"`
	Target     string `json:"target"`
	// NetworkID is the network of the cited authorization.
	NetworkID   *string         `json:"network_id"`
	Request     CallRequest     `json:"request"`
	SubmitState string          `json:"submit_state"`
	Status      *CallStatus     `json:"status"`
	Result      json.RawMessage `json:"result"`
	CancelState *string         `json:"cancel_state"`
	Attempts    int64           `json:"attempts"`
	// NextAttemptAt is the next automatic submission or status query.
	NextAttemptAt *string `json:"next_attempt_at"`
	Error         *string `json:"error"`
	StatusQueries int64   `json:"status_queries"`
	// AdapterID is the credential that made an agent's call, or null for
	// an owner call.
	AdapterID *string `json:"adapter_id"`
}

// MarshalJSON shows a missing result as null.
func (o OutboundCall) MarshalJSON() ([]byte, error) {
	type plain OutboundCall
	request, err := json.Marshal(o.Request)
	if err != nil {
		return nil, err
	}
	if o.Result == nil {
		o.Result = json.RawMessage("null")
	}
	return json.Marshal(struct {
		plain
		Request json.RawMessage `json:"request"`
	}{plain(o), request})
}

// UnmarshalJSON reads a stored record, whose request may show grant_id null.
func (o *OutboundCall) UnmarshalJSON(data []byte) error {
	type plain OutboundCall
	var raw struct {
		plain
		Request map[string]json.RawMessage `json:"request"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*o = OutboundCall(raw.plain)
	if string(raw.Request["grant_id"]) == "null" {
		delete(raw.Request, "grant_id")
	}
	request, err := json.Marshal(raw.Request)
	if err != nil {
		return err
	}
	if string(o.Result) == "null" {
		o.Result = nil
	}
	return json.Unmarshal(request, &o.Request)
}

// needsPoll reports whether the call is accepted and not yet final here; a
// final status with a result is stored only together with that result.
func (o OutboundCall) needsPoll() bool {
	if o.SubmitState != submitAccepted {
		return false
	}
	return o.Status == nil || !callFinal(o.Status.State)
}

// OutboundCallItem is one entry of calls list.
type OutboundCallItem struct {
	Sequence int64        `json:"sequence"`
	Call     OutboundCall `json:"call"`
}

func callKey(peer, id string) string { return "call:" + peer + "/" + id }

func (s *Store) OutboundCall(ctx context.Context, peer, id string) (OutboundCall, error) {
	return readJSON[OutboundCall](s.db.QueryRowContext(ctx, `SELECT record FROM outbound_calls WHERE peer = ? AND call_id = ?`, peer, id))
}

// OutboundCallView is the local record, polled soon when still pending.
func (s *Store) OutboundCallView(ctx context.Context, peer, id string) (OutboundCall, error) {
	out, err := s.OutboundCall(ctx, peer, id)
	if err == nil && out.needsPoll() {
		s.pollSoon(callKey(peer, id))
	}
	return out, err
}

// pollSoon brings a scheduled poll forward to now when it lies more than a
// second ahead, so an owner waiting on a call sees its outcome promptly.
func (s *Store) pollSoon(key string) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if p, ok := s.tasks.poll[key]; ok && p.at.After(time.Now().Add(time.Second)) {
		delete(s.tasks.poll, key)
	}
}

// OutboundCalls pages local call records in insertion order.
func (s *Store) OutboundCalls(ctx context.Context, after, limit int64) ([]OutboundCallItem, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rowid, record FROM outbound_calls WHERE rowid > ? ORDER BY rowid LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OutboundCallItem{}
	pageBytes := 2
	for rows.Next() {
		var item OutboundCallItem
		var record string
		if err = rows.Scan(&item.Sequence, &record); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(record), &item.Call); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if pageBytes+len(encoded)+1 > 900000 && len(items) > 0 {
			break
		}
		pageBytes += len(encoded) + 1
		items = append(items, item)
	}
	return items, rows.Err()
}

// Unanswered is a host whose listing could not be fetched.
type Unanswered struct {
	HostID string `json:"host_id"`
	Error  string `json:"error"`
}

// DiscoveredCapability is one capability, or opened source, in discover.
type DiscoveredCapability struct {
	Address string `json:"address"`
	HostID  string `json:"host_id"`
	ListedCapability
	// ForAgents names the local agents an agent-only capability is for;
	// nil for the others.
	ForAgents []ForAgent `json:"for_agents,omitempty"`
}

// ForAgent is a local agent an agent-only capability is shared with.
type ForAgent struct {
	AgentID string  `json:"agent_id"`
	Name    *string `json:"name"`
}

// agentOnly reports whether every via entry of a listed entry has
// from_agent set.
func agentOnly(e ListedCapability) bool {
	for _, v := range e.Via {
		if v.FromAgent == nil {
			return false
		}
	}
	return len(e.Via) > 0
}

func (e DiscoveredCapability) MarshalJSON() ([]byte, error) {
	listed, err := json.Marshal(e.ListedCapability)
	if err != nil {
		return nil, err
	}
	head, err := json.Marshal(struct {
		Address   string     `json:"address"`
		HostID    string     `json:"host_id"`
		ForAgents []ForAgent `json:"for_agents,omitempty"`
	}{e.Address, e.HostID, e.ForAgents})
	if err != nil {
		return nil, err
	}
	return append(append(head[:len(head)-1], ','), listed[1:]...), nil
}

// ReachableAgent is one reachable entry of agents --json.
type ReachableAgent struct {
	Address   string   `json:"address"`
	HostID    string   `json:"host_id"`
	AgentID   string   `json:"agent_id"`
	Connected bool     `json:"connected"`
	HostState string   `json:"host_state"`
	Actions   []string `json:"actions"`
	Endpoint  Endpoint `json:"endpoint"`
}

// Discovery is GET /v1/discover.
type Discovery struct {
	Agents       []ReachableAgent       `json:"agents"`
	Capabilities []DiscoveredCapability `json:"capabilities"`
	Unanswered   []Unanswered           `json:"unanswered"`
}

// fetchListing reads GET /peer/v1/capabilities from one host within 5
// seconds.
func (s *Store) fetchListing(ctx context.Context, host, network string) ([]ListedCapability, error) {
	peer, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, listingTimeout)
	defer cancel()
	path := "/peer/v1/capabilities"
	if network != "" {
		path += "?" + url.Values{"network": {network}}.Encode()
	}
	code, data, err := s.peerRequestLimit(ctx, peer, http.MethodGet, path, nil, peerToolsMaxBody)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("peer returned HTTP %d", code)
	}
	var listing []ListedCapability
	if err = json.Unmarshal(data, &listing); err != nil {
		return nil, errors.New("invalid capability listing")
	}
	return listing, nil
}

// selectedNetworks is the given network, or every network of this host.
func (s *Store) selectedNetworks(ctx context.Context, network string) ([]string, error) {
	if network != "" {
		if _, err := s.Network(ctx, network); err != nil {
			return nil, err
		}
		return []string{network}, nil
	}
	all, err := s.Networks(ctx)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, n := range all {
		ids = append(ids, n.ID)
	}
	return ids, nil
}

// personHost is a host bound to a person in one network, with the
// person's label. A host may be bound to different persons in different
// networks.
type personHost struct {
	host, network, person, label string
}

// uniqueHosts lists the distinct hosts of bindings, sorted.
func uniqueHosts(bindings []personHost) []string {
	var out []string
	for _, b := range bindings {
		if !slices.Contains(out, b.host) {
			out = append(out, b.host)
		}
	}
	sort.Strings(out)
	return out
}

// entryBinding is the binding of a listed entry's host that its via
// networks choose: the first via network in which the host is bound.
func entryBinding(bindings []personHost, host string, e ListedCapability) (personHost, bool) {
	for _, via := range e.Via {
		if via.NetworkID == nil {
			continue
		}
		for _, b := range bindings {
			if b.host == host && b.network == *via.NetworkID {
				return b, true
			}
		}
	}
	return personHost{}, false
}

// personHosts lists the other hosts bound to a person in the selected
// networks' maps; person "" means every person, and otherwise a label or
// person ID resolved in each network.
func (s *Store) personHosts(ctx context.Context, person, network string) ([]personHost, error) {
	networks, err := s.selectedNetworks(ctx, network)
	if err != nil {
		return nil, err
	}
	var out []personHost
	resolved := false
	for _, id := range networks {
		g, err := s.loadGovernance(ctx, s.db, id)
		if err != nil {
			return nil, err
		}
		labels := map[string]string{}
		for _, p := range g.personList() {
			labels[p.PersonID] = p.Member
		}
		want := ""
		if person != "" {
			p, err := ResolvePerson(g.personList(), person)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			want, resolved = p.PersonID, true
		}
		members, err := s.NetworkMembers(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			if m.PersonID == nil || m.HostID == s.identity.ID || (want != "" && *m.PersonID != want) {
				continue
			}
			out = append(out, personHost{host: m.HostID, network: id, person: *m.PersonID, label: labels[*m.PersonID]})
		}
	}
	if person != "" && !resolved {
		return nil, &codedError{status: http.StatusNotFound, code: "not_found", message: fmt.Sprintf("no current person %q", person), unanswered: []Unanswered{}}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].host != out[j].host {
			return out[i].host < out[j].host
		}
		return out[i].network < out[j].network
	})
	return out, nil
}

// listingView is whose view of the listings a caller takes. The owner's
// (the zero value) ignores via entries whose from_agent is set, since an
// owner call carries no origin; an agent's also keeps those for its agent,
// and keeps only capabilities. Entries left without a via entry are
// omitted.
type listingView struct {
	agent            string
	capabilitiesOnly bool
	// agentOnly, in the owner's view, also keeps capabilities whose every
	// via entry has from_agent set, with all those entries (slice 3).
	agentOnly bool
}

func (v listingView) filter(listing []ListedCapability) []ListedCapability {
	out := []ListedCapability{}
	for _, e := range listing {
		if v.capabilitiesOnly && e.Kind != ListedKindCapability {
			continue
		}
		var via []ToolVia
		for _, entry := range e.Via {
			if entry.FromAgent == nil || (v.agent != "" && *entry.FromAgent == v.agent) {
				via = append(via, entry)
			}
		}
		if len(via) == 0 && v.agent == "" && v.agentOnly {
			via = e.Via
		}
		if len(via) == 0 {
			continue
		}
		e.Via = via
		out = append(out, e)
	}
	return out
}

// fetchListings reads the listings of several hosts, at most 8 at once, as
// view sees them.
func (s *Store) fetchListings(ctx context.Context, hosts []string, network string, view listingView) (map[string][]ListedCapability, []Unanswered) {
	var mu sync.Mutex
	listings := map[string][]ListedCapability{}
	unanswered := []Unanswered{}
	slots := make(chan struct{}, listingConcurrency)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			listing, err := s.fetchListing(ctx, h, network)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				unanswered = append(unanswered, Unanswered{HostID: h, Error: err.Error()})
				return
			}
			listings[h] = view.filter(listing)
		}()
	}
	wg.Wait()
	sort.Slice(unanswered, func(i, j int) bool { return unanswered[i].HostID < unanswered[j].HostID })
	return listings, unanswered
}

// reachableAgents are the reachable entries of agents --json for one
// network, limited to one person's agents when person is given.
func (s *Store) reachableAgents(ctx context.Context, network, person string) ([]ReachableAgent, error) {
	d, err := s.DirectoryOf(ctx, network)
	if err != nil {
		return nil, err
	}
	members, err := s.NetworkMembers(ctx, network)
	if err != nil {
		return nil, err
	}
	states := map[string]string{}
	for _, h := range d.Hosts {
		states[h.HostID] = h.State
	}
	out := []ReachableAgent{}
	for _, a := range d.Agents {
		if a.Address == nil || (person != "" && (a.PersonID == nil || *a.PersonID != person)) {
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
		out = append(out, ReachableAgent{*a.Address, a.HostID, a.AgentID, a.Connected, states[a.HostID], actions, s.endpointOf(ctx, members, a.HostID)})
	}
	return out, nil
}

// Discover lists reachable agents and usable capabilities together, for
// one person or every person, in the selected networks.
func (s *Store) Discover(ctx context.Context, person, network string) (Discovery, error) {
	hosts, err := s.personHosts(ctx, person, network)
	if err != nil {
		return Discovery{}, err
	}
	out := Discovery{Agents: []ReachableAgent{}}
	networks, err := s.selectedNetworks(ctx, network)
	if err != nil {
		return Discovery{}, err
	}
	personID := ""
	if person != "" && len(hosts) > 0 {
		personID = hosts[0].person
	}
	for _, id := range networks {
		agents, err := s.reachableAgents(ctx, id, personID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return Discovery{}, err
		}
		out.Agents = append(out.Agents, agents...)
	}
	out.Capabilities, out.Unanswered, err = s.discoverCapabilities(ctx, hosts, network, listingView{agentOnly: true})
	return out, err
}

// forAgents names the local agents an agent-only entry is for, in via
// order.
func (s *Store) forAgents(ctx context.Context, e ListedCapability) ([]ForAgent, error) {
	locals, err := s.localAgents(ctx)
	if err != nil {
		return nil, err
	}
	out := []ForAgent{}
	for _, v := range e.Via {
		if v.FromAgent == nil || slices.ContainsFunc(out, func(f ForAgent) bool { return f.AgentID == *v.FromAgent }) {
			continue
		}
		f := ForAgent{AgentID: *v.FromAgent}
		for _, a := range locals {
			if a.id == f.AgentID {
				name := a.name
				f.Name = &name
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// agentOnlyError refuses an owner call to an agent-only capability.
func (s *Store) agentOnlyError(ctx context.Context, address string, e ListedCapability) error {
	agents, err := s.forAgents(ctx, e)
	if err != nil {
		return err
	}
	names := make([]string, len(agents))
	for i, a := range agents {
		names[i] = a.AgentID
		if a.Name != nil {
			names[i] = *a.Name
		}
	}
	noun := "agent"
	if len(names) > 1 {
		noun = "agents"
	}
	return &codedError{status: http.StatusForbidden, code: "agent_only", message: fmt.Sprintf("%s is shared only with your %s %s. Add --from-agent %s to call as that agent.", address, noun, strings.Join(names, ", "), names[0]), forAgents: agents}
}

// discoverCapabilities lists the capabilities, and sources, of the given
// person hosts as view sees them, each with its discover address.
func (s *Store) discoverCapabilities(ctx context.Context, hosts []personHost, network string, view listingView) ([]DiscoveredCapability, []Unanswered, error) {
	out := []DiscoveredCapability{}
	ids := uniqueHosts(hosts)
	listings, unanswered := s.fetchListings(ctx, ids, network, view)
	entries, err := s.personAddressed(ctx, hosts, listings, network)
	if err != nil {
		return nil, nil, err
	}
	for _, host := range ids {
		for i, e := range listings[host] {
			a := entries[host][i]
			if !a.bound {
				continue // not reached in a network binding the host to the person
			}
			address := host + "/" + e.Capability
			if a.personal && a.binding.label != "" {
				address = a.binding.label + "/" + e.Capability
			}
			found := DiscoveredCapability{Address: address, HostID: host, ListedCapability: e}
			if view.agent == "" && view.agentOnly && agentOnly(e) {
				if found.ForAgents, err = s.forAgents(ctx, e); err != nil {
					return nil, nil, err
				}
			}
			out = append(out, found)
		}
	}
	return out, unanswered, nil
}

// entryAddress is how discover addresses one listed entry: the binding its
// via networks choose, and whether the address is PERSON/CAPABILITY.
type entryAddress struct {
	binding  personHost
	bound    bool
	personal bool
	// unsettled is a capability no policy of the person binds, which the
	// person has on more than one host.
	unsettled bool
	// slash marks a person whose label contains '/', who is never PERSON
	// in an address.
	slash bool
}

// personAddressed decides, for each listed entry, the person it is
// addressed under, by the host's binding to any person in the entry's via
// networks, the first such network deciding; an entry whose binding is not
// among wanted, the searched person's bindings, is not bound. It also decides
// whether discover addresses it as PERSON/CAPABILITY. A capability is when
// that person's policy for the entry's network binds the name to that
// host, or when none of the person's policies binds the name and the
// person has it on only one host. A source is when the person has that
// agent and server on only one host. Neither is when the person's label
// contains '/': such a person's entries are addressed by host ID.
func (s *Store) personAddressed(ctx context.Context, wanted []personHost, listings map[string][]ListedCapability, network string) (map[string][]entryAddress, error) {
	// Whose an entry is depends on every person's bindings, not only the
	// searched person's.
	hosts, err := s.personHosts(ctx, "", network)
	if err != nil {
		return nil, err
	}
	out := map[string][]entryAddress{}
	count := map[string]int{}
	for _, host := range uniqueHosts(wanted) {
		list := make([]entryAddress, len(listings[host]))
		for i, e := range listings[host] {
			b, ok := entryBinding(hosts, host, e)
			if ok && !slices.ContainsFunc(wanted, func(w personHost) bool { return w.host == b.host && w.network == b.network }) {
				ok = false
			}
			list[i] = entryAddress{binding: b, bound: ok}
			if ok {
				count[b.person+"/"+e.Capability]++
			}
		}
		out[host] = list
	}
	networks, err := s.selectedNetworks(ctx, network)
	if err != nil {
		return nil, err
	}
	// bindings maps network/person/capability to the host its rule names.
	bindings := map[string]string{}
	bound := map[string]bool{} // person/capability bound in any policy
	persons := map[string]bool{}
	for _, h := range hosts {
		persons[h.person] = true
	}
	for _, id := range networks {
		g, err := s.loadGovernance(ctx, s.db, id)
		if err != nil {
			return nil, err
		}
		for person := range persons {
			key, ok := g.personKey(person)
			if !ok {
				continue
			}
			p, ok := g.storedPolicy(key)
			if !ok {
				continue
			}
			for _, r := range p.CapabilityRules {
				bindings[id+"/"+person+"/"+r.Capability] = r.Host
				bound[person+"/"+r.Capability] = true
			}
		}
	}
	for host, list := range out {
		for i := range list {
			a := &list[i]
			if !a.bound {
				continue
			}
			e := listings[host][i]
			person := a.binding.person
			if a.slash = strings.Contains(a.binding.label, "/"); a.slash {
				continue
			}
			if e.Kind == ListedKindSource {
				a.personal = count[person+"/"+e.Capability] == 1
				continue
			}
			here := false
			for _, via := range e.Via {
				if via.NetworkID != nil && bindings[*via.NetworkID+"/"+person+"/"+e.Capability] == host {
					here = true
				}
			}
			a.personal = here || (!bound[person+"/"+e.Capability] && count[person+"/"+e.Capability] == 1)
			a.unsettled = !bound[person+"/"+e.Capability] && count[person+"/"+e.Capability] > 1
		}
	}
	return out, nil
}

// splitAddress splits PERSON|HOST_ID/CAPABILITY or PERSON|HOST_ID/AGENT/SERVER
// into its left part and the capability (AGENT/SERVER for a source).
func splitAddress(address string) (string, string, error) {
	parts := strings.Split(address, "/")
	invalid := fmt.Errorf("%w: an address is PERSON/CAPABILITY, HOST_ID/CAPABILITY, PERSON/AGENT/SERVER, or HOST_ID/AGENT/SERVER", ErrInvalid)
	if len(parts) < 2 || len(parts) > 3 || len(address) > 512 {
		return "", "", invalid
	}
	for _, p := range parts {
		if p == "" {
			return "", "", invalid
		}
	}
	return parts[0], strings.Join(parts[1:], "/"), nil
}

// resolveCapabilityAddress finds the one host that lists the address's
// capability or source for this host, as view sees the listings.
func (s *Store) resolveCapabilityAddress(ctx context.Context, address, network string, view listingView) (string, ListedCapability, error) {
	left, capability, err := splitAddress(address)
	if err != nil {
		return "", ListedCapability{}, err
	}
	var hosts []string
	var found []personHost
	if validID(left, "host", 32) {
		var member bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM network_members WHERE host_id = ?)`, left).Scan(&member); err != nil {
			return "", ListedCapability{}, err
		}
		if !member || left == s.identity.ID {
			return "", ListedCapability{}, &codedError{status: http.StatusNotFound, code: "not_found", message: fmt.Sprintf("no network of this host has the member %s", left), unanswered: []Unanswered{}}
		}
		hosts = []string{left}
	} else {
		found, err = s.personHosts(ctx, left, network)
		if err != nil {
			return "", ListedCapability{}, err
		}
		hosts = uniqueHosts(found)
	}
	listings, unanswered := s.fetchListings(ctx, hosts, network, view)
	type match struct {
		host  string
		entry ListedCapability
	}
	// PERSON/CAPABILITY matches only entries discover addresses that way.
	// An entry reached only in a network binding its host to another
	// person is not that person's.
	var addressed map[string][]entryAddress
	if found != nil {
		if addressed, err = s.personAddressed(ctx, found, listings, network); err != nil {
			return "", ListedCapability{}, err
		}
	}
	var matches, unsettled []match
	for _, h := range hosts {
		for i, e := range listings[h] {
			if e.Capability != capability {
				continue
			}
			if addressed != nil {
				a := addressed[h][i]
				if a.unsettled {
					unsettled = append(unsettled, match{h, e})
				}
				// A person whose label contains '/' is never PERSON in an
				// address.
				if !a.bound || a.slash || (e.Kind != ListedKindSource && !a.personal) {
					continue
				}
			}
			matches = append(matches, match{h, e})
		}
	}
	// With no match, a name no policy binds that the person has on
	// several hosts is unsettled, and its copies are the candidates.
	if len(matches) == 0 && len(unsettled) > 1 {
		matches = unsettled
	}
	switch len(matches) {
	case 0:
		message := fmt.Sprintf("no host lists %s for this host", address)
		if len(unanswered) > 0 {
			var ids []string
			for _, u := range unanswered {
				ids = append(ids, u.HostID)
			}
			message += "; hosts that did not answer: " + strings.Join(ids, ", ")
		}
		return "", ListedCapability{}, &codedError{status: http.StatusNotFound, code: "not_found", message: message, unanswered: unanswered}
	case 1:
		return matches[0].host, matches[0].entry, nil
	}
	names := make([]string, len(matches))
	for i, m := range matches {
		names[i] = m.host + "/" + m.entry.Capability
	}
	sort.Strings(names)
	return "", ListedCapability{}, &codedError{status: http.StatusConflict, code: "ambiguous", message: fmt.Sprintf("the address %s names more than one host's %s: %s; use HOST_ID/%s", address, capability, strings.Join(names, ", "), capability), candidates: names}
}

// citeVia turns a listing's via entry into the request's authorization.
func (s *Store) citeVia(ctx context.Context, via ToolVia, r *CallRequest) error {
	if via.NetworkID == nil {
		return errors.New("invalid via entry")
	}
	switch via.Kind {
	case AuthorizationPolicy:
		if via.PersonID == nil || via.Version == nil {
			return errors.New("invalid via entry")
		}
		r.Policy = &CallPolicyCitation{PersonID: *via.PersonID, NetworkID: *via.NetworkID, Version: *via.Version}
		return nil
	case AuthorizationSelf:
		person, err := s.ownPerson(ctx, s.db, *via.NetworkID)
		if err != nil {
			return err
		}
		if person == "" {
			return fmt.Errorf("%w: this host is not bound to a person in %s", ErrInvalid, *via.NetworkID)
		}
		r.Self = &CallSelfCitation{PersonID: person, NetworkID: *via.NetworkID}
		return nil
	}
	return errors.New("invalid via entry")
}

// PrepareCall resolves a call's address, chooses its citation from the
// listing, and persists the outbound record before any submission.
func (s *Store) PrepareCall(ctx context.Context, r SubmitCall) (OutboundCall, error) {
	if err := s.checkLocalOrigin(ctx, r.Origin); err != nil {
		return OutboundCall{}, err
	}
	if r.CallID == "" {
		id, err := newID("call")
		if err != nil {
			return OutboundCall{}, err
		}
		r.CallID = id
	}
	if !validID(r.CallID, "call", 16) {
		return OutboundCall{}, fmt.Errorf("%w: invalid call ID", ErrInvalid)
	}
	now := time.Now()
	input := r.Input
	if len(bytes.TrimSpace(input)) == 0 || string(bytes.TrimSpace(input)) == "null" {
		input = json.RawMessage("{}")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, input); err != nil || compact.Len() == 0 || compact.Bytes()[0] != '{' {
		return OutboundCall{}, fmt.Errorf("%w: input must be a JSON object", ErrInvalid)
	}
	if r.Operation == "" {
		return OutboundCall{}, fmt.Errorf("%w: a call needs an operation", ErrInvalid)
	}
	request := CallRequest{CallID: r.CallID, Operation: r.Operation, Input: compact.Bytes()}
	if r.Deadline != "" {
		deadline, err := parseTime(r.Deadline)
		if err != nil || !deadline.After(now) || deadline.After(now.Add(callMaxDeadline)) {
			return OutboundCall{}, fmt.Errorf("%w: the deadline must be in the future, at most 15 minutes ahead", ErrInvalid)
		}
		request.Deadline = timestamp(deadline)
	}
	// A repeated call ID returns its record without resolving again.
	if old, err := readJSON[OutboundCall](s.db.QueryRowContext(ctx, `SELECT record FROM outbound_calls WHERE call_id = ? ORDER BY rowid LIMIT 1`, r.CallID)); err == nil {
		if old.Target != r.Target || old.Request.Operation != request.Operation || !bytes.Equal(old.Request.Input, request.Input) || (r.Deadline != "" && old.Request.Deadline != request.Deadline) || !sameOrigin(old.Request.Origin, r.Origin) {
			return old, ErrConflict
		}
		return old, nil
	} else if !errors.Is(err, ErrNotFound) {
		return OutboundCall{}, err
	}
	// An owner call made as one of this host's agents (call --from-agent)
	// takes that agent's view and carries its origin.
	view := listingView{agentOnly: true}
	if r.Origin != nil {
		if strings.Count(r.Target, "/") >= 2 {
			return OutboundCall{}, &codedError{status: http.StatusBadRequest, code: "source", message: "Agents cannot call sources; call them without --from-agent."}
		}
		view = listingView{agent: r.Origin.AgentID, capabilitiesOnly: true}
		request.Origin = r.Origin
	}
	peer, entry, err := s.resolveCapabilityAddress(ctx, r.Target, r.Network, view)
	if err != nil {
		return OutboundCall{}, err
	}
	if r.Origin == nil && agentOnly(entry) {
		return OutboundCall{}, s.agentOnlyError(ctx, r.Target, entry)
	}
	request.Capability = entry.Capability
	listed := false
	for _, op := range entry.Operations {
		if op.Name == r.Operation {
			listed = true
		}
	}
	if !listed {
		return OutboundCall{}, fmt.Errorf("%w: %s/%s has no operation %s", ErrInvalid, peer, entry.Capability, r.Operation)
	}
	var chosen *ToolVia
	for i := range entry.Via {
		if r.Network == "" || deref(entry.Via[i].NetworkID) == r.Network {
			chosen = &entry.Via[i]
			break
		}
	}
	if chosen == nil {
		return OutboundCall{}, fmt.Errorf("%w: nothing authorizes this call", ErrInvalid)
	}
	if err = s.citeVia(ctx, *chosen, &request); err != nil {
		return OutboundCall{}, err
	}
	if request.Deadline == "" {
		deadline := now.Add(callMaxDeadline)
		if request.Policy != nil {
			if g, err := s.loadGovernance(ctx, s.db, request.Policy.NetworkID); err == nil {
				if key, ok := g.personKey(request.Policy.PersonID); ok {
					if p, ok := g.storedPolicy(key); ok {
						if until, err := membership.ParseTime(p.ValidUntil); err == nil && until.Before(deadline) {
							deadline = until
						}
					}
				}
			}
		}
		request.Deadline = timestamp(deadline)
	}
	if err = validateCall(request); err != nil {
		return OutboundCall{}, err
	}
	network := chosen.NetworkID
	out := OutboundCall{PeerHostID: peer, Target: r.Target, NetworkID: network, Request: request, SubmitState: submitUnknown, NextAttemptAt: s.initialAttempt()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = putJSON(ctx, tx, `INSERT INTO outbound_calls (record, peer, call_id) VALUES (?, ?, ?)`, out, peer, request.CallID); err != nil {
		if isUniqueViolation(err) {
			return out, ErrConflict
		}
		return out, err
	}
	if err = appendEvent(ctx, tx, "call.submitted", callSubject(peer, request.CallID), timestamp(now)); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// updateOutboundCall applies a change to the stored record in one
// transaction; the change returns how many call.updated activities to add.
func (s *Store) updateOutboundCall(ctx context.Context, peer, id string, change func(out *OutboundCall) int) (OutboundCall, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundCall{}, err
	}
	defer tx.Rollback()
	out, err := readJSON[OutboundCall](tx.QueryRowContext(ctx, `SELECT record FROM outbound_calls WHERE peer = ? AND call_id = ?`, peer, id))
	if err != nil {
		return out, err
	}
	wasFinal := outboundCallFinal(out)
	wasAwaiting := out.Status != nil && out.Status.Approval != nil && out.Status.Approval.State == ApprovalPending
	updates := change(&out)
	if err = putJSON(ctx, tx, `UPDATE outbound_calls SET record = ? WHERE peer = ? AND call_id = ?`, out, peer, id); err != nil {
		return out, err
	}
	at := timestamp(time.Now())
	// An agent's call that becomes final gets its call-update notification
	// in the same transaction.
	becameFinal := !wasFinal && outboundCallFinal(out)
	if becameFinal && out.AdapterID != nil {
		if err = createCallUpdate(ctx, tx, out, at); err != nil {
			return out, err
		}
	}
	for range updates {
		if err = appendEvent(ctx, tx, "call.updated", callSubject(peer, id), at); err != nil {
			return out, err
		}
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	// Requests held on the call answer as soon as its final status is
	// stored.
	if becameFinal {
		s.signalFinal(callKey(peer, id))
	}
	// A decided approval of a call not yet final starts a new held window,
	// so its result also arrives at once.
	if wasAwaiting && !outboundCallFinal(out) && out.Status != nil && out.Status.Approval != nil && out.Status.Approval.State != ApprovalPending {
		s.restartHeldWindow(callKey(peer, id), time.Now())
	}
	return out, nil
}

// validCallStatus checks a receiver's status record for our call.
func (s *Store) validCallStatus(st CallStatus, peer string, r CallRequest) bool {
	_, created := parseTime(st.CreatedAt)
	return created == nil && st.CallID == r.CallID && st.SenderHostID == s.identity.ID && st.ReceiverHostID == peer && st.Capability == r.Capability && st.Operation == r.Operation && validCallState(st.State)
}

// hasResult reports whether a final status has a result at the receiver:
// result_bytes is set, and the result was not too large to store.
func hasResult(st CallStatus) bool {
	return callFinal(st.State) && st.ResultBytes != nil && deref(st.Error) != callResultTooLarge
}

// storeCallStatus keeps a status record and, once final, its result. A
// final status with a result is stored only together with it, from a GET
// (fromGet); one learned from a submit or cancel response is not stored,
// so the record never shows a final call without its result, and the poll
// fetches both. It returns how many call.updated activities to add.
func storeCallStatus(out *OutboundCall, st CallStatus, fromGet bool) int {
	if hasResult(st) && !fromGet && out.Result == nil {
		return 0
	}
	// A stored state never moves backwards: a final status is never
	// replaced, and an answer earlier than the stored state (queued after
	// running), such as a held answer overtaken by a cancel, is discarded.
	if out.Status != nil && (callFinal(out.Status.State) || stateRank(st.State) < stateRank(out.Status.State)) {
		return 0
	}
	// Nor does a decided approval go back to pending.
	if out.Status != nil && out.Status.Approval != nil && out.Status.Approval.State != ApprovalPending && callApprovalState(st) == ApprovalPending {
		return 0
	}
	changed := out.Status == nil || out.Status.State != st.State || out.Status.CancelRequested != st.CancelRequested || callApprovalState(*out.Status) != callApprovalState(st)
	result := st.Result
	st.Result = nil
	out.Status = &st
	if callFinal(st.State) && result != nil && string(result) != "null" {
		changed = changed || out.Result == nil
		out.Result = result
	}
	if changed {
		return 1
	}
	return 0
}

// ExchangeCall makes one submission attempt for an unknown record, or a
// status query once the deadline has passed (statusOnly).
func (s *Store) ExchangeCall(ctx context.Context, peerID, id string, statusOnly bool) (OutboundCall, error) {
	out, err := s.exchangeCall(ctx, peerID, id, statusOnly)
	if err == nil && out.SubmitState == submitAccepted && out.Status == nil {
		// A final status with a result is stored only with its result:
		// fetch it now. If this fails, the call stays pollable.
		if _, pollErr := s.pollCall(ctx, peerID, id); pollErr == nil {
			out, err = s.OutboundCall(ctx, peerID, id)
		}
	}
	return out, err
}

func (s *Store) exchangeCall(ctx context.Context, peerID, id string, statusOnly bool) (OutboundCall, error) {
	unlock, err := s.lockOutbound(ctx, callKey(peerID, id))
	if err != nil {
		return OutboundCall{}, err
	}
	defer unlock()
	out, err := s.OutboundCall(ctx, peerID, id)
	if err != nil || out.SubmitState != submitUnknown {
		return out, err
	}
	peer, err := s.dialPeer(ctx, peerID)
	if err != nil {
		return out, err
	}
	method, path := http.MethodPost, "/peer/v1/calls"
	var body []byte
	if statusOnly {
		method, path = http.MethodGet, "/peer/v1/calls/"+id
	} else if body, err = json.Marshal(out.Request); err != nil {
		return out, err
	}
	state := submitUnknown
	var status *CallStatus
	code, data, err := s.peerRequestLimit(ctx, peer, method, path, body, peerToolsMaxBody)
	switch {
	case err != nil:
	case code == 200:
		var st CallStatus
		if err = json.Unmarshal(data, &st); err == nil && !s.validCallStatus(st, peerID, out.Request) {
			err = errors.New("invalid peer call status")
		}
		if err == nil {
			state, status = submitAccepted, &st
			s.noteCallAccepted(callKey(peerID, id), time.Now())
		}
	case statusOnly && code == 404:
		err = errors.New("the receiver has no record of this call")
	default:
		if !statusOnly && (code == 400 || code == 403 || code == 404 || code == 409 || code == 413 || code == 429) {
			state = submitRejected
		}
		err = fmt.Errorf("peer returned HTTP %d%s", code, peerRefusal(data))
	}
	var failure *string
	if err != nil {
		message := err.Error()
		failure = &message
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.updateOutboundCall(finishCtx, peerID, id, func(out *OutboundCall) int {
		if out.SubmitState != submitUnknown {
			return 0
		}
		out.Attempts++
		out.SubmitState, out.Error = state, failure
		updates := 0
		if status != nil {
			updates = storeCallStatus(out, *status, statusOnly)
		}
		out.NextAttemptAt = s.nextAttempt(out.SubmitState, out.Request.Deadline, out.Attempts, &out.StatusQueries, statusOnly)
		if state != submitUnknown && updates == 0 {
			updates = 1
		}
		return updates
	})
}

// peerRefusal is the error text of a peer's refusal body, if any.
func peerRefusal(data []byte) string {
	var body struct {
		Error string `json:"error"`
		Limit string `json:"limit"`
	}
	if json.Unmarshal(data, &body) != nil || body.Error == "" || body.Error == "forbidden" {
		return ""
	}
	if body.Limit != "" {
		return ": " + body.Error + " (" + body.Limit + ")"
	}
	return ": " + body.Error
}

// pollCall sends a pending cancellation, then fetches the status, storing
// the result once final. It reports whether anything changed.
func (s *Store) pollCall(ctx context.Context, peerID, id string) (bool, error) {
	return s.pollCallWait(ctx, peerID, id, 0)
}

// pollCallWait is pollCall with a held status request: with wait above 0,
// the receiver holds the GET until the call is final or wait seconds pass,
// and the record's lock is released while it is held.
func (s *Store) pollCallWait(ctx context.Context, peerID, id string, wait int) (bool, error) {
	unlock, err := s.lockOutbound(ctx, callKey(peerID, id))
	if err != nil {
		return false, err
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	out, err := s.OutboundCall(ctx, peerID, id)
	if err != nil || out.SubmitState != submitAccepted {
		return false, err
	}
	peer, err := s.dialPeer(ctx, peerID)
	if err != nil {
		return false, err
	}
	progressed := false
	if out.CancelState != nil && *out.CancelState == cancelUnknown && (out.Status == nil || !callFinal(out.Status.State)) {
		if err = s.sendCallCancel(ctx, peer, out); err != nil {
			return false, err
		}
		progressed = true
	}
	if out, err = s.OutboundCall(ctx, peerID, id); err != nil || !out.needsPoll() {
		return progressed, err
	}
	path, timeout := "/peer/v1/calls/"+id, time.Duration(0)
	if wait > 0 {
		// The receiver holds the request until the state differs from the
		// one stored here.
		path += "?wait=" + strconv.Itoa(wait)
		if out.Status != nil {
			path += "&state=" + url.QueryEscape(out.Status.State) + "&approval=" + url.QueryEscape(callApprovalState(*out.Status))
		}
		timeout = time.Duration(wait) * time.Second
		unlock()
		locked = false
	}
	code, data, err := s.peerRequestTimed(ctx, peer, http.MethodGet, path, nil, peerToolsMaxBody, timeout)
	if err != nil {
		return progressed, err
	}
	if code != 200 {
		return progressed, fmt.Errorf("peer returned HTTP %d", code)
	}
	var st CallStatus
	if err = json.Unmarshal(data, &st); err != nil || !s.validCallStatus(st, peerID, out.Request) {
		return progressed, errors.New("invalid peer call status")
	}
	storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if !locked {
		// The lock was released while the request was held: take it again
		// before storing, which rechecks the stored state.
		if unlock, err = s.lockOutbound(storeCtx, callKey(peerID, id)); err != nil {
			return progressed, err
		}
		locked = true
	}
	changed := 0
	_, err = s.updateOutboundCall(storeCtx, peerID, id, func(out *OutboundCall) int {
		changed = storeCallStatus(out, st, true)
		return changed
	})
	return progressed || changed > 0, err
}

// sendCallCancel posts the cancellation once; a confirmed status marks it
// sent. Callers hold the record's lock.
func (s *Store) sendCallCancel(ctx context.Context, peer Peer, out OutboundCall) error {
	id := out.Request.CallID
	code, data, err := s.peerRequestLimit(ctx, peer, http.MethodPost, "/peer/v1/calls/"+id+"/cancel", []byte("{}"), peerToolsMaxBody)
	if err == nil && code != 200 {
		err = fmt.Errorf("peer returned HTTP %d", code)
	}
	var st CallStatus
	if err == nil && (json.Unmarshal(data, &st) != nil || !s.validCallStatus(st, peer.ID, out.Request)) {
		err = errors.New("invalid peer call status")
	}
	if err != nil {
		return err
	}
	storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err = s.updateOutboundCall(storeCtx, peer.ID, id, func(out *OutboundCall) int {
		sent := cancelSent
		out.CancelState = &sent
		return storeCallStatus(out, st, false)
	})
	return err
}

// CancelOutboundCall records the owner's cancellation and sends it now if
// the receiver accepted the call; an uncertain send is resent by the poll
// workers. A rejected submission or a final call is returned unchanged.
func (s *Store) CancelOutboundCall(ctx context.Context, peerID, id string) (OutboundCall, error) {
	out, err := s.updateOutboundCall(ctx, peerID, id, func(out *OutboundCall) int {
		if out.SubmitState == submitRejected || (out.Status != nil && callFinal(out.Status.State)) || out.CancelState != nil {
			return 0
		}
		state := cancelUnknown
		out.CancelState = &state
		return 0
	})
	if err != nil || out.SubmitState != submitAccepted || out.CancelState == nil || *out.CancelState != cancelUnknown || (out.Status != nil && callFinal(out.Status.State)) {
		return out, err
	}
	unlock, err := s.lockOutbound(ctx, callKey(peerID, id))
	if err != nil {
		return out, err
	}
	if peer, err := s.dialPeer(ctx, peerID); err == nil {
		_ = s.sendCallCancel(ctx, peer, out)
	}
	unlock()
	s.schedulePoll(callKey(peerID, id), true)
	// A cancel answered with a final status that has a result stores it
	// only with the result: fetch it now.
	if current, err := s.OutboundCall(ctx, peerID, id); err == nil && current.needsPoll() && current.CancelState != nil && *current.CancelState == cancelSent {
		_, _ = s.pollCall(ctx, peerID, id)
	}
	return s.OutboundCall(ctx, peerID, id)
}

// pendingCalls lists outbound calls to submit or poll.
func (s *Store) pendingCalls(ctx context.Context) ([]OutboundCall, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM outbound_calls WHERE json_extract(record, '$.submit_state') != 'rejected' ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []OutboundCall
	for rows.Next() {
		out, err := readJSON[OutboundCall](rows)
		if err != nil {
			return nil, err
		}
		if out.SubmitState == submitUnknown || out.needsPoll() {
			items = append(items, out)
		}
	}
	return items, rows.Err()
}

// retryCall makes one automatic submission attempt, or a status query after
// the deadline.
func (s *Store) retryCall(ctx context.Context, out OutboundCall) {
	current, err := s.OutboundCall(ctx, out.PeerHostID, out.Request.CallID)
	if err != nil || !attemptDue(current.SubmitState, current.NextAttemptAt, current.Attempts, s.retryNow()) {
		return
	}
	deadline, err := parseTime(current.Request.Deadline)
	if err != nil {
		return
	}
	statusOnly := !s.retryNow().Before(deadline)
	if _, err = s.ExchangeCall(ctx, current.PeerHostID, current.Request.CallID, statusOnly); err != nil && ctx.Err() == nil {
		message := err.Error()
		queries := current.StatusQueries
		at := s.nextAttempt(current.SubmitState, current.Request.Deadline, current.Attempts+1, &queries, false)
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = s.updateOutboundCall(finishCtx, current.PeerHostID, current.Request.CallID, func(o *OutboundCall) int {
			if o.SubmitState == submitUnknown {
				o.NextAttemptAt, o.Error = at, &message
			}
			return 0
		})
	}
}

// callJobs are the outbound calls due for a retry or a poll now.
func (s *Store) callJobs(ctx context.Context, now time.Time) []OutboundCall {
	items, err := s.pendingCalls(ctx)
	if err != nil {
		return nil
	}
	var due []OutboundCall
	for _, out := range items {
		key := callKey(out.PeerHostID, out.Request.CallID)
		submit := out.SubmitState == submitUnknown
		if s.inflightOutbound(key) || (submit && !attemptDue(out.SubmitState, out.NextAttemptAt, out.Attempts, s.retryNow())) || (!submit && (!s.pollDue(key, now) || s.inHeldWindow(key, now) || s.following(key))) {
			continue
		}
		due = append(due, out)
	}
	return due
}

// runCallJob runs one retry or poll of an outbound call.
func (s *Store) runCallJob(ctx context.Context, out OutboundCall) {
	if out.SubmitState == submitUnknown {
		s.retryCall(ctx, out)
		return
	}
	key := callKey(out.PeerHostID, out.Request.CallID)
	progressed, _ := s.pollCall(ctx, out.PeerHostID, out.Request.CallID)
	s.schedulePoll(key, progressed)
}

// SubmitOwnerCall prepares and submits an owner call.
func (s *Store) SubmitOwnerCall(ctx context.Context, r SubmitCall) (OutboundCall, error) {
	out, err := s.PrepareCall(ctx, r)
	if err == nil && out.SubmitState == submitUnknown {
		out, err = s.ExchangeCall(ctx, out.PeerHostID, out.Request.CallID, false)
	}
	return out, err
}

func localCallRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/discover", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Has("from_agent") {
			result, err := store.AgentDiscover(r.Context(), q.Get("from_agent"), q.Get("person"), q.Get("network"))
			respond(w, http.StatusOK, result, err)
			return
		}
		result, err := store.Discover(r.Context(), q.Get("person"), q.Get("network"))
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("POST /v1/calls", func(w http.ResponseWriter, r *http.Request) {
		var req SubmitCall
		if !decode(w, r, &req, "target?", "operation?", "input?", "deadline?", "network?", "call_id?", "origin?") {
			return
		}
		out, err := store.SubmitOwnerCall(r.Context(), req)
		respond(w, http.StatusOK, out, err)
	})
	mux.HandleFunc("GET /v1/calls", func(w http.ResponseWriter, r *http.Request) {
		after, limit, err := pageParams(r)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		items, err := store.OutboundCalls(r.Context(), after, limit)
		respond(w, http.StatusOK, items, err)
	})
	mux.HandleFunc("GET /v1/calls/received", func(w http.ResponseWriter, r *http.Request) {
		after, limit, err := pageParams(r)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		items, err := store.ReceivedCalls(r.Context(), after, limit)
		respond(w, http.StatusOK, items, err)
	})
	mux.HandleFunc("GET /v1/calls/{peer}/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.OutboundCallView(r.Context(), r.PathValue("peer"), r.PathValue("id"))
		respond(w, http.StatusOK, out, err)
	})
	mux.HandleFunc("POST /v1/calls/{peer}/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.CancelOutboundCall(r.Context(), r.PathValue("peer"), r.PathValue("id"))
		respond(w, http.StatusOK, out, err)
	})
}

// callsRunning counts received calls running, for status.
func callsRunning(ctx context.Context, tx *sql.Tx) (int64, error) { return runningCalls(ctx, tx) }

// stateRank orders call states: queued, then running, then final.
func stateRank(state string) int {
	switch {
	case state == CallQueued:
		return 0
	case state == CallRunning:
		return 1
	}
	return 2
}
