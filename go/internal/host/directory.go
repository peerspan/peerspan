package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/quic-go/quic-go"
)

// The agent directory (milestone 7, slice 4). Each host serves the agents
// an authenticated member may reach now; each daemon caches what its
// network's other members serve, in memory, so people and agents can
// address an agent as PERSON/AGENT or HOST_ID/AGENT. Names only label agents:
// nothing authorizes by name.

// The v13 schema lets an adapter send carry no route (a send by address),
// and counts sends and delegations by address for the hourly cap.
const directorySchema = `
CREATE TABLE adapter_outbound_v13 (peer TEXT NOT NULL, request_id TEXT NOT NULL, adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), session_id TEXT NOT NULL REFERENCES sessions(id), route_id TEXT REFERENCES adapter_routes(id), next_poll_at INTEGER NOT NULL, reply_delivery TEXT, PRIMARY KEY(peer, request_id), UNIQUE(adapter_id, request_id), FOREIGN KEY(peer, request_id) REFERENCES outbound_messages(peer, request_id));
INSERT INTO adapter_outbound_v13 SELECT peer, request_id, adapter_id, session_id, route_id, next_poll_at, reply_delivery FROM adapter_outbound;
DROP TABLE adapter_outbound;
ALTER TABLE adapter_outbound_v13 RENAME TO adapter_outbound;
CREATE INDEX adapter_outbound_due ON adapter_outbound(next_poll_at);
CREATE INDEX adapter_outbound_route ON adapter_outbound(route_id);
CREATE TABLE directory_sends (adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), kind TEXT NOT NULL CHECK (kind IN ('message', 'task')), peer TEXT NOT NULL, request_id TEXT NOT NULL, sent_at_ms INTEGER NOT NULL, PRIMARY KEY(kind, peer, request_id));
CREATE INDEX directory_sends_adapter ON directory_sends(adapter_id, sent_at_ms);
PRAGMA user_version = 13;
`

const (
	directoryInterval     = 5 * time.Minute
	directoryQueryTimeout = 5 * time.Second
	directoryWait         = 10 * time.Second
	directoryQueries      = 8
	// directoryRetry is the wait before a synchronous refresh asks a host
	// once more that may not have learned of this host's change yet.
	directoryRetry         = 2 * time.Second
	defaultMaxSendsPerHour = 100
)

// Authorization kinds a peer lists.
const (
	authorizationKindSelf   = "self"
	authorizationKindPolicy = "policy"
	authorizationKindGrant  = "grant"
)

// DirectoryAuthorization is one current authorization of the caller for an
// agent: self access, a policy rule, or a grant. FromAgent limits a rule or
// grant to requests from one of the caller's agents.
type DirectoryAuthorization struct {
	Kind             string
	GrantID          string
	Actions          []string
	MaxMessageBytes  int64
	MaxArtifactBytes int64
	FromAgent        *string
	ExpiresAt        string
}

func (a DirectoryAuthorization) MarshalJSON() ([]byte, error) {
	actions := a.Actions
	if actions == nil {
		actions = []string{}
	}
	switch a.Kind {
	case authorizationKindSelf:
		return json.Marshal(struct {
			Kind             string   `json:"kind"`
			Actions          []string `json:"actions"`
			MaxMessageBytes  int64    `json:"max_message_bytes"`
			MaxArtifactBytes int64    `json:"max_artifact_bytes"`
		}{a.Kind, actions, a.MaxMessageBytes, a.MaxArtifactBytes})
	case authorizationKindGrant:
		return json.Marshal(struct {
			Kind             string   `json:"kind"`
			GrantID          string   `json:"grant_id"`
			Actions          []string `json:"actions"`
			MaxMessageBytes  int64    `json:"max_message_bytes"`
			MaxArtifactBytes int64    `json:"max_artifact_bytes"`
			ExpiresAt        string   `json:"expires_at"`
			FromAgent        *string  `json:"from_agent"`
		}{a.Kind, a.GrantID, actions, a.MaxMessageBytes, a.MaxArtifactBytes, a.ExpiresAt, a.FromAgent})
	}
	return json.Marshal(struct {
		Kind             string   `json:"kind"`
		Actions          []string `json:"actions"`
		MaxMessageBytes  int64    `json:"max_message_bytes"`
		MaxArtifactBytes int64    `json:"max_artifact_bytes"`
		FromAgent        *string  `json:"from_agent"`
	}{a.Kind, actions, a.MaxMessageBytes, a.MaxArtifactBytes, a.FromAgent})
}

func (a *DirectoryAuthorization) UnmarshalJSON(data []byte) error {
	var raw struct {
		Kind             string   `json:"kind"`
		GrantID          *string  `json:"grant_id"`
		Actions          []string `json:"actions"`
		MaxMessageBytes  int64    `json:"max_message_bytes"`
		MaxArtifactBytes int64    `json:"max_artifact_bytes"`
		FromAgent        *string  `json:"from_agent"`
		ExpiresAt        *string  `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*a = DirectoryAuthorization{Kind: raw.Kind, Actions: raw.Actions, MaxMessageBytes: raw.MaxMessageBytes, MaxArtifactBytes: raw.MaxArtifactBytes, FromAgent: raw.FromAgent}
	switch raw.Kind {
	case authorizationKindSelf:
	case authorizationKindPolicy, authorizationKindGrant:
		if raw.FromAgent != nil && !validID(*raw.FromAgent, "agent", 16) {
			return ErrInvalid
		}
		if raw.Kind == authorizationKindPolicy {
			break
		}
		if raw.GrantID == nil || !validID(*raw.GrantID, "grant", 16) || raw.ExpiresAt == nil {
			return ErrInvalid
		}
		a.GrantID, a.ExpiresAt = *raw.GrantID, *raw.ExpiresAt
	default:
		return ErrInvalid
	}
	for _, action := range raw.Actions {
		if !membership.ValidPolicyAction(action) {
			return ErrInvalid
		}
	}
	if a.Kind == authorizationKindSelf {
		a.FromAgent = nil
	}
	return nil
}

// allows reports whether the authorization permits action for a request
// originating from agent (empty for none asserted).
func (a DirectoryAuthorization) allows(action, agent string) bool {
	if a.Kind == authorizationKindSelf {
		return true
	}
	if a.FromAgent != nil && *a.FromAgent != agent {
		return false
	}
	for _, have := range a.Actions {
		if actionGranted(have, action) {
			return true
		}
	}
	return false
}

// PeerAgent is one agent a host lists to an authenticated member.
type PeerAgent struct {
	Name           string                   `json:"name"`
	AgentID        string                   `json:"agent_id"`
	Connected      bool                     `json:"connected"`
	Authorizations []DirectoryAuthorization `json:"authorizations"`
	// Channel is verified when a verified session holds a lease, unverified
	// when only unverified sessions do, else null. Connected means verified.
	Channel *string `json:"channel"`
}

// ReachableAgents is the peer route: this host's agents that caller, a
// current member of network, may reach now, each with every current
// authorization, evaluated as for a request. Blocks hide policy rules and
// grants, never self access.
func (s *Store) ReachableAgents(ctx context.Context, caller, network string) ([]PeerAgent, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM network_members WHERE network_id = ? AND host_id = ?)", network, s.identity.ID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	member, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", network, caller))
	if errors.Is(err, ErrNotFound) || caller == s.identity.ID {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	_, self, err := s.boundPerson(ctx, tx, s.identity.ID, caller)
	if err != nil {
		return nil, err
	}
	refused, err := blocked(ctx, tx, caller)
	if err != nil {
		return nil, err
	}
	var policy *membership.Policy
	var g governance
	own, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", network, s.identity.ID))
	if err != nil {
		return nil, err
	}
	if own.PersonID != nil && !refused {
		if g, err = s.loadGovernance(ctx, tx, network); err != nil {
			return nil, err
		}
		if key, ok := g.personKey(*own.PersonID); ok {
			if p, ok := g.storedPolicy(key); ok && membership.PolicyActive(p, now) {
				policy = &p
			}
		}
	}
	grants := map[string][]Grant{}
	if !refused {
		all, err := records[Grant](ctx, tx, "SELECT record FROM grants ORDER BY id")
		if err != nil {
			return nil, err
		}
		for _, grant := range all {
			expires, err := parseTime(grant.ExpiresAt)
			if err != nil || grant.RequesterHostID != caller || grant.RevokedAt != nil || !expires.After(now) {
				continue
			}
			grants[grant.TargetAgentID] = append(grants[grant.TargetAgentID], grant)
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT id, name FROM agents ORDER BY name, id")
	if err != nil {
		return nil, err
	}
	var agents []Agent
	for rows.Next() {
		var a Agent
		if err = rows.Scan(&a.ID, &a.Name); err != nil {
			rows.Close()
			return nil, err
		}
		agents = append(agents, a)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	listed := []PeerAgent{}
	for _, agent := range agents {
		auths := []DirectoryAuthorization{}
		if self {
			auths = append(auths, DirectoryAuthorization{Kind: authorizationKindSelf, Actions: []string{membership.PolicyActionMessage, membership.PolicyActionTask, membership.PolicyActionDelegate}, MaxMessageBytes: selfMaxMessageBytes, MaxArtifactBytes: selfMaxArtifactBytes})
		}
		if policy != nil {
			named := membership.NamesAgent(*policy, agent.Name)
			for _, rule := range policy.Rules {
				if !membership.RuleApplies(rule, agent.Name, named) {
					continue
				}
				entry := DirectoryAuthorization{Kind: authorizationKindPolicy, Actions: append([]string{}, rule.Actions...), MaxMessageBytes: rule.MaxMessageBytes, MaxArtifactBytes: rule.MaxArtifactBytes}
				var broad []string
				var from []string
				for _, principal := range rule.Principals {
					if host, id, ok := membership.AgentPrincipal(principal); ok {
						if host == caller && !contains(from, id) {
							from = append(from, id)
						}
						continue
					}
					broad = append(broad, principal)
				}
				if g.principalMatches(membership.PolicyRule{Principals: broad}, member, nil) {
					auths = append(auths, entry)
					continue
				}
				for _, id := range from {
					limited := entry
					limited.FromAgent = &id
					auths = append(auths, limited)
				}
			}
		}
		for _, grant := range grants[agent.ID] {
			auths = append(auths, DirectoryAuthorization{Kind: authorizationKindGrant, GrantID: grant.ID, Actions: []string{grant.Action}, MaxMessageBytes: grant.MaxMessageBytes, MaxArtifactBytes: grant.MaxArtifactBytes, ExpiresAt: grant.ExpiresAt, FromAgent: grant.RequesterAgentID})
		}
		if len(auths) == 0 {
			continue
		}
		channel, err := agentChannel(ctx, tx, agent.ID, now)
		if err != nil {
			return nil, err
		}
		connected := channel != nil && *channel == ChannelVerified
		listed = append(listed, PeerAgent{Name: agent.Name, AgentID: agent.ID, Connected: connected, Authorizations: auths, Channel: channel})
	}
	return listed, nil
}

func directoryPeerRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("GET /peer/v1/networks/{network}/agents", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		agents, err := store.ReachableAgents(r.Context(), id, r.PathValue("network"))
		respond(w, http.StatusOK, agents, err)
	})
}

// Directory host states.
const (
	hostStateOK          = "ok"
	hostStateError       = "error"
	hostStateUnsupported = "unsupported"
	hostStatePending     = "pending"
)

// directoryState is the in-memory directory of every network.
type directoryState struct {
	mu       sync.Mutex
	networks map[string]*networkDirectory
	// dirty networks are refreshed by RunDirectory soon; wake signals it.
	dirty map[string]bool
	wake  chan struct{}
	// queries bounds peer queries across all refreshes.
	queries chan struct{}
	// maps holds a digest of each network's applied map, to notice changes.
	maps map[string]string
}

type networkDirectory struct {
	refreshedAt *time.Time
	hosts       map[string]*directoryHost
	// refresh serializes refreshes of the whole network.
	refresh sync.Mutex
	// queries serializes the queries of each host, so a single-host refresh
	// (after a presence notification) need not wait for a whole-network
	// refresh to finish with slower hosts, and results apply in order.
	queries map[string]*sync.Mutex
}

type directoryHost struct {
	state       string
	refreshedAt *time.Time
	err         *string
	agents      []PeerAgent
}

func (s *Store) directoryInit() *directoryState {
	d := &s.directory
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.networks == nil {
		d.networks = map[string]*networkDirectory{}
		d.dirty = map[string]bool{}
		d.wake = make(chan struct{}, 1)
		d.queries = make(chan struct{}, directoryQueries)
		d.maps = map[string]string{}
	}
	return d
}

// networkDir returns a network's directory, created empty.
func (d *directoryState) networkDir(network string) *networkDirectory {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.networks[network]
	if n == nil {
		n = &networkDirectory{hosts: map[string]*directoryHost{}, queries: map[string]*sync.Mutex{}}
		d.networks[network] = n
	}
	return n
}

// directoryChanged schedules a refresh of a network, after a change to its
// map or a stored policy.
func (s *Store) directoryChanged(network string) {
	d := s.directoryInit()
	d.mu.Lock()
	d.dirty[network] = true
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// mapApplied notes a network's applied members; a change to their hosts or
// bindings schedules a refresh.
func (s *Store) mapApplied(network string, members []NetworkMember) {
	parts := make([]string, 0, len(members))
	for _, m := range members {
		person, label := "", ""
		if m.PersonID != nil {
			person = *m.PersonID
		}
		if m.PersonMember != nil {
			label = *m.PersonMember
		}
		parts = append(parts, m.HostID+"|"+person+"|"+label)
	}
	sort.Strings(parts)
	digest := strings.Join(parts, ",")
	d := s.directoryInit()
	d.mu.Lock()
	changed := d.maps[network] != digest
	d.maps[network] = digest
	d.mu.Unlock()
	if changed {
		s.directoryChanged(network)
	}
}

// RunDirectory refreshes every network's directory at startup, every 5
// minutes, and at once after a change, until ctx is cancelled.
func (s *Store) RunDirectory(ctx context.Context) {
	d := s.directoryInit()
	ticker := time.NewTicker(directoryInterval)
	defer ticker.Stop()
	all := true
	for {
		var targets []string
		if all {
			networks, err := s.Networks(ctx)
			if err == nil {
				for _, n := range networks {
					targets = append(targets, n.ID)
				}
			}
			d.mu.Lock()
			d.dirty = map[string]bool{}
			d.mu.Unlock()
		} else {
			d.mu.Lock()
			for id := range d.dirty {
				targets = append(targets, id)
			}
			d.dirty = map[string]bool{}
			d.mu.Unlock()
		}
		var refreshes sync.WaitGroup
		for _, id := range targets {
			refreshes.Add(1)
			go func() {
				defer refreshes.Done()
				_ = s.refreshDirectory(ctx, id, "", false)
			}()
		}
		refreshes.Wait()
		all = false
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			all = true
		case <-d.wake:
		}
	}
}

// refreshDirectory queries every current member of a network other than
// this host, or only one host when only is set. A host that fails keeps its
// previous agents. Whole-network refreshes run one at a time; a single-host
// refresh waits only for queries of that host.
// retry marks a synchronous refresh, which retries a host that may not
// have learned of a change yet.
func (s *Store) refreshDirectory(ctx context.Context, network, only string, retry bool) error {
	d := s.directoryInit()
	nd := d.networkDir(network)
	if only == "" {
		nd.refresh.Lock()
		defer nd.refresh.Unlock()
	}
	members, err := s.NetworkMembers(ctx, network)
	if errors.Is(err, ErrNotFound) {
		d.mu.Lock()
		delete(d.networks, network)
		d.mu.Unlock()
		return err
	}
	if err != nil {
		return err
	}
	current := map[string]bool{}
	var targets []string
	for _, m := range members {
		if m.HostID == s.identity.ID {
			continue
		}
		current[m.HostID] = true
		if only == "" || only == m.HostID {
			targets = append(targets, m.HostID)
		}
	}
	d.mu.Lock()
	for id := range nd.hosts {
		if !current[id] {
			delete(nd.hosts, id)
			delete(nd.queries, id)
		}
	}
	for id := range current {
		if nd.hosts[id] == nil {
			nd.hosts[id] = &directoryHost{state: hostStatePending}
		}
	}
	locks := map[string]*sync.Mutex{}
	for _, id := range targets {
		if nd.queries[id] == nil {
			nd.queries[id] = &sync.Mutex{}
		}
		locks[id] = nd.queries[id]
	}
	d.mu.Unlock()
	var queries sync.WaitGroup
	for _, id := range targets {
		queries.Add(1)
		go func() {
			defer queries.Done()
			locks[id].Lock()
			defer locks[id].Unlock()
			select {
			case d.queries <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-d.queries }()
			agents, state, err := s.queryAgents(ctx, network, id)
			// A synchronous refresh asks once more, shortly, a host that may
			// not have learned of this host's join, binding, or policy yet:
			// one that answered 403 or refused this host's key in the
			// handshake, or a sibling (bound to this host's person) whose
			// answer lacks self access.
			if retry && (errors.Is(err, errDirectoryForbidden) || peerAuthRefused(err) || (state == hostStateOK && !hasSelf(agents) && s.boundToOwnPerson(ctx, id))) {
				select {
				case <-time.After(directoryRetry):
					agents, state, err = s.queryAgents(ctx, network, id)
				case <-ctx.Done():
				}
			}
			now := time.Now().UTC()
			d.mu.Lock()
			defer d.mu.Unlock()
			h := nd.hosts[id]
			if h == nil {
				return
			}
			h.state, h.err = state, nil
			switch state {
			case hostStateOK:
				h.agents, h.refreshedAt = agents, &now
			case hostStateUnsupported:
				h.agents = nil
			default:
				message := err.Error()
				h.err = &message
			}
		}()
	}
	queries.Wait()
	if only == "" && ctx.Err() == nil {
		now := time.Now().UTC()
		d.mu.Lock()
		nd.refreshedAt = &now
		d.mu.Unlock()
	}
	return nil
}

// hasSelf reports whether any listed agent carries self access.
func hasSelf(agents []PeerAgent) bool {
	for _, a := range agents {
		for _, auth := range a.Authorizations {
			if auth.Kind == authorizationKindSelf {
				return true
			}
		}
	}
	return false
}

// boundToOwnPerson reports whether this host's map binds a host to this host's
// own person.
func (s *Store) boundToOwnPerson(ctx context.Context, host string) bool {
	_, ok, err := s.selfPerson(ctx, s.db, host)
	return err == nil && ok
}

// peerAuthRefused reports a peer that closed the handshake with a TLS
// alert, as one that does not know this host yet does.
func peerAuthRefused(err error) bool {
	var transport *quic.TransportError
	return errors.As(err, &transport) && transport.Remote && transport.ErrorCode.IsCryptoError()
}

// errDirectoryForbidden is a host's 403 to a directory query.
var errDirectoryForbidden = errors.New("peer returned HTTP 403")

// queryAgents asks one host for the agents this host may reach. A 404 is
// an older receiver without the route.
func (s *Store) queryAgents(ctx context.Context, network, host string) ([]PeerAgent, string, error) {
	ctx, cancel := context.WithTimeout(ctx, directoryQueryTimeout)
	defer cancel()
	peer, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, hostStateError, err
	}
	status, data, err := s.peerRequest(ctx, peer, http.MethodGet, "/peer/v1/networks/"+url.PathEscape(network)+"/agents", nil)
	switch {
	case err != nil:
		return nil, hostStateError, err
	case status == http.StatusNotFound:
		return nil, hostStateUnsupported, nil
	case status == http.StatusForbidden:
		return nil, hostStateError, errDirectoryForbidden
	case status != http.StatusOK:
		return nil, hostStateError, fmt.Errorf("peer returned HTTP %d", status)
	}
	var agents []PeerAgent
	if err = json.Unmarshal(data, &agents); err != nil || agents == nil {
		return nil, hostStateError, errors.New("invalid peer agent list")
	}
	valid := agents[:0]
	for _, a := range agents {
		if validID(a.AgentID, "agent", 16) && a.Name != "" {
			if a.Authorizations == nil {
				a.Authorizations = []DirectoryAuthorization{}
			}
			if a.Channel != nil && *a.Channel != ChannelVerified && *a.Channel != ChannelUnverified {
				a.Channel = nil
			}
			valid = append(valid, a)
		}
	}
	return valid, hostStateOK, nil
}

// refreshWithin runs a refresh, returning after at most 10 seconds while it
// continues in the background.
func (s *Store) refreshWithin(ctx context.Context, network, only string) error {
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directoryWait+directoryQueryTimeout)
		defer cancel()
		done <- s.refreshDirectory(ctx, network, only, true)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(directoryWait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// AddressableName reports whether an agent name can be addressed: 1 to 64
// lowercase ASCII letters, digits, '.', '_', and '-', starting with a letter
// or digit.
func AddressableName(name string) bool {
	return validRouteName(name)
}

// Directory is GET /v1/directory for one network.
type Directory struct {
	NetworkID   string           `json:"network_id"`
	RefreshedAt *string          `json:"refreshed_at"`
	Hosts       []DirectoryHost  `json:"hosts"`
	Agents      []DirectoryAgent `json:"agents"`
}

type DirectoryHost struct {
	HostID      string  `json:"host_id"`
	PersonID    *string `json:"person_id"`
	PersonLabel *string `json:"person_label"`
	State       string  `json:"state"`
	RefreshedAt *string `json:"refreshed_at"`
	Error       *string `json:"error"`
}

type DirectoryAgent struct {
	Address        *string                  `json:"address"`
	HostID         string                   `json:"host_id"`
	PersonID       *string                  `json:"person_id"`
	PersonLabel    *string                  `json:"person_label"`
	Name           string                   `json:"name"`
	AgentID        string                   `json:"agent_id"`
	Connected      bool                     `json:"connected"`
	Authorizations []DirectoryAuthorization `json:"authorizations"`
	Channel        *string                  `json:"channel"`
}

func optionalTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	value := timestamp(*t)
	return &value
}

// localAgent is one of this host's agents, for addresses and conflicts.
type localAgent struct{ id, name string }

func (s *Store) localAgents(ctx context.Context) ([]localAgent, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name FROM agents ORDER BY name, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []localAgent
	for rows.Next() {
		var a localAgent
		if err = rows.Scan(&a.id, &a.name); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DirectoryOf is the cached directory of one network. Addresses use the
// person label, or the host ID for a host without a person and for a name
// that more than one agent of the person uses, including this host's.
func (s *Store) DirectoryOf(ctx context.Context, network string) (Directory, error) {
	if _, err := s.Network(ctx, network); err != nil {
		return Directory{}, err
	}
	members, err := s.NetworkMembers(ctx, network)
	if err != nil {
		return Directory{}, err
	}
	locals, err := s.localAgents(ctx)
	if err != nil {
		return Directory{}, err
	}
	return s.directoryView(network, members, locals), nil
}

func (s *Store) directoryView(network string, members []NetworkMember, locals []localAgent) Directory {
	byHost := map[string]NetworkMember{}
	for _, m := range members {
		byHost[m.HostID] = m
	}
	d := s.directoryInit()
	nd := d.networkDir(network)
	d.mu.Lock()
	defer d.mu.Unlock()
	view := Directory{NetworkID: network, RefreshedAt: optionalTime(nd.refreshedAt), Hosts: []DirectoryHost{}, Agents: []DirectoryAgent{}}
	// Names each person uses, counted over the directory and this host.
	uses := map[string]int{}
	if own, ok := byHost[s.identity.ID]; ok && own.PersonID != nil {
		for _, a := range locals {
			uses[*own.PersonID+"/"+a.name]++
		}
	}
	for id, h := range nd.hosts {
		m, ok := byHost[id]
		if !ok || m.PersonID == nil {
			continue
		}
		for _, a := range h.agents {
			uses[*m.PersonID+"/"+a.Name]++
		}
	}
	for id, h := range nd.hosts {
		m, ok := byHost[id]
		if !ok {
			continue
		}
		view.Hosts = append(view.Hosts, DirectoryHost{HostID: id, PersonID: m.PersonID, PersonLabel: m.PersonMember, State: h.state, RefreshedAt: optionalTime(h.refreshedAt), Error: h.err})
		for _, a := range h.agents {
			entry := DirectoryAgent{HostID: id, PersonID: m.PersonID, PersonLabel: m.PersonMember, Name: a.Name, AgentID: a.AgentID, Connected: a.Connected, Authorizations: a.Authorizations, Channel: a.Channel}
			if AddressableName(a.Name) {
				address := id + "/" + a.Name
				if m.PersonID != nil && m.PersonMember != nil && uses[*m.PersonID+"/"+a.Name] == 1 {
					address = *m.PersonMember + "/" + a.Name
				}
				entry.Address = &address
			}
			view.Agents = append(view.Agents, entry)
		}
	}
	sort.Slice(view.Hosts, func(i, j int) bool { return view.Hosts[i].HostID < view.Hosts[j].HostID })
	sort.Slice(view.Agents, func(i, j int) bool {
		a, b := view.Agents[i], view.Agents[j]
		if (a.Address == nil) != (b.Address == nil) {
			return b.Address == nil
		}
		if a.Address != nil && *a.Address != *b.Address {
			return *a.Address < *b.Address
		}
		if a.HostID != b.HostID {
			return a.HostID < b.HostID
		}
		return a.AgentID < b.AgentID
	})
	return view
}

// RefreshDirectory refreshes a network's directory synchronously, waiting
// at most 10 seconds, and returns it.
func (s *Store) RefreshDirectory(ctx context.Context, network string) (Directory, error) {
	if _, err := s.Network(ctx, network); err != nil {
		return Directory{}, err
	}
	if err := s.refreshWithin(ctx, network, ""); err != nil && !errors.Is(err, ErrNotFound) {
		return Directory{}, err
	}
	return s.DirectoryOf(ctx, network)
}

// directoryNetwork applies slice 1 network defaulting to a query parameter.
func (s *Store) directoryNetwork(ctx context.Context, given string) (string, error) {
	if given != "" {
		return given, nil
	}
	networks, err := s.Networks(ctx)
	if err != nil {
		return "", err
	}
	switch len(networks) {
	case 0:
		return "", fmt.Errorf("%w: not a member of any network", ErrInvalid)
	case 1:
		return networks[0].ID, nil
	}
	names := make([]string, len(networks))
	for i, n := range networks {
		names[i] = n.ID + " (" + n.Name + ")"
	}
	return "", fmt.Errorf("%w: several networks; give network: %s", ErrInvalid, strings.Join(names, ", "))
}

func localDirectoryRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/directory", func(w http.ResponseWriter, r *http.Request) {
		network, err := store.directoryNetwork(r.Context(), r.URL.Query().Get("network"))
		var d Directory
		if err == nil {
			d, err = store.DirectoryOf(r.Context(), network)
		}
		respond(w, http.StatusOK, d, err)
	})
	mux.HandleFunc("POST /v1/directory/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != 0 && !decode(w, r, &struct{}{}) {
			return
		}
		network, err := store.directoryNetwork(r.Context(), r.URL.Query().Get("network"))
		var d Directory
		if err == nil {
			d, err = store.RefreshDirectory(r.Context(), network)
		}
		respond(w, http.StatusOK, d, err)
	})
}

// nameConflicts is status item 12: names this host's person uses for more
// than one agent in a network's directory, where this host has one of them.
func (s *Store) nameConflicts(ctx context.Context, tx *sql.Tx, attend func(kind, subject, detail, command string)) error {
	own, err := membershipsOf(ctx, tx, s.identity.ID)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT a.id, a.name, (SELECT integration FROM sessions WHERE agent_id = a.id ORDER BY created_at DESC, id DESC LIMIT 1) FROM agents a ORDER BY a.name")
	if err != nil {
		return err
	}
	type named struct{ id, integration string }
	locals := map[string]named{}
	for rows.Next() {
		var id, name string
		var integration sql.NullString
		if err = rows.Scan(&id, &name, &integration); err != nil {
			rows.Close()
			return err
		}
		locals[name] = named{id, integration.String}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	d := s.directoryInit()
	for _, n := range own {
		if n.member.PersonID == nil {
			continue
		}
		person := *n.member.PersonID
		members, err := membersOf(ctx, tx, n.network)
		if err != nil {
			return err
		}
		d.mu.Lock()
		nd := d.networks[n.network]
		var others []string
		if nd != nil {
			for id, h := range nd.hosts {
				if m, ok := members[id]; !ok || m.PersonID == nil || *m.PersonID != person {
					continue
				}
				for _, a := range h.agents {
					if _, ok := locals[a.Name]; ok {
						others = append(others, a.Name+"\x00"+id)
					}
				}
			}
		}
		d.mu.Unlock()
		hosts := map[string][]string{}
		for _, entry := range others {
			name, id, _ := strings.Cut(entry, "\x00")
			hosts[name] = append(hosts[name], id)
		}
		for name, ids := range hosts {
			sort.Strings(ids)
			harness := locals[name].integration
			switch harness {
			case "":
				harness = "HARNESS"
			case "claude-code":
				harness = "claude"
			}
			attend("agent_name_conflict", n.network+"/"+name, fmt.Sprintf("agent %s (%s) on this host shares its name with your agent on %s; addresses by name are ambiguous", name, locals[name].id, strings.Join(ids, ", ")), "peerspan attach "+harness+" --name NEW")
		}
	}
	return nil
}

// membersOf maps a network's current members by host ID.
func membersOf(ctx context.Context, q queryer, network string) (map[string]NetworkMember, error) {
	rows, err := q.QueryContext(ctx, "SELECT record FROM network_members WHERE network_id = ?", network)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]NetworkMember{}
	for rows.Next() {
		m, err := readJSON[NetworkMember](rows)
		if err != nil {
			return nil, err
		}
		out[m.HostID] = m
	}
	return out, rows.Err()
}
