package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/person"
)

// Owner access policy (milestone 2b, slice 3). A message is authorized by a
// manual grant or by the target agent owner's signed policy; the host-local
// block list overrides both. The CLI signs policies with the owner's person
// key; the daemon renews them only by asking an ssh-agent, and never holds
// the key.

const kindPolicy = "policy" // subject: person key; the newest verified version

// The v8 schema adds the host-local block list.
const accessBlocksSchema = `
CREATE TABLE access_blocks (kind TEXT NOT NULL, subject TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(kind, subject));
PRAGMA user_version = 8;
`

// PolicyCitation names the owner policy a message relies on: the owner and
// the newest version the sender has verified.
type PolicyCitation struct {
	PersonID string `json:"person_id"`
	Version  int64  `json:"version"`
}

func (c *PolicyCitation) UnmarshalJSON(data []byte) error {
	type plain PolicyCitation
	return membership.Strict(data, (*plain)(c), "person_id", "version")
}

// authority is what a grant or the matching policy rules permit.
type authority struct {
	maxMessageBytes   int64
	allowDisconnected bool
	// maxArtifactBytes bounds a task's input and result artifacts together.
	maxArtifactBytes int64
	// delegate is true when the grant or a matching rule has task.delegate.
	delegate bool
}

// artifactsAllowed reports whether a bound admits a request's input
// artifacts: none, or a nonzero bound no smaller than their total.
func artifactsAllowed(r MessageRequest, bound int64) bool {
	return r.artifacts == 0 || (bound > 0 && r.artifactBytes <= bound)
}

// SubmitPolicy is {policy}, signed by its owner through the CLI.
type SubmitPolicy struct {
	Policy *membership.Policy `json:"policy"`
}

// PolicyView is `access show`: the newest verified policy and whether less
// than a quarter of its validity remains.
type PolicyView struct {
	membership.Policy
	ExpiresSoon bool `json:"expires_soon"`
}

func (v PolicyView) MarshalJSON() ([]byte, error) {
	type plain membership.Policy
	return json.Marshal(struct {
		plain
		ExpiresSoon bool `json:"expires_soon"`
	}{plain(v.Policy), v.ExpiresSoon})
}

// AccessBlock is one host-local block: kind "person" or "host".
type AccessBlock struct {
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	CreatedAt string `json:"created_at"`
}

// BlockAccess names exactly one person (ID, key, or label) or host ID.
type BlockAccess struct {
	Person string `json:"person,omitempty"`
	Host   string `json:"host,omitempty"`
}

// applyPolicies keeps, for each owner, the highest version whose signature
// verifies: persisted versions always, served ones only from current persons.
// A lower version never replaces a higher one.
func (a *appliedMap) applyPolicies(persisted persistedStatements, m membership.Map) {
	a.policies = map[string]membership.Policy{}
	consider := func(p membership.Policy) {
		if membership.VerifyPolicy(a.chain.NetworkID, p) != nil {
			return
		}
		if old, ok := a.policies[p.PersonPublicKey]; !ok || old.Version < p.Version {
			a.policies[p.PersonPublicKey] = p
		}
	}
	for _, key := range sortedKeys(persisted.policies) {
		var p membership.Policy
		if json.Unmarshal(persisted.policies[key], &p) == nil && p.PersonPublicKey == key {
			consider(p)
		}
	}
	for _, p := range membership.DecodeRaw[membership.Policy](m.Policies) {
		if _, ok := a.persons[p.PersonPublicKey]; ok {
			consider(p)
		}
	}
}

func (s *Store) persistPolicies(ctx context.Context, tx *sql.Tx, network string, a appliedMap, now string) error {
	stored, err := loadStatements(ctx, tx, network)
	if err != nil {
		return err
	}
	for _, key := range sortedKeys(a.policies) {
		if err = recordPolicy(ctx, tx, network, stored, a.policies[key], now); err != nil {
			return err
		}
	}
	return nil
}

// recordPolicy stores a verified policy unless the same or a higher version
// is stored.
func recordPolicy(ctx context.Context, tx *sql.Tx, network string, stored persistedStatements, p membership.Policy, now string) error {
	var old membership.Policy
	if data, ok := stored.policies[p.PersonPublicKey]; ok && json.Unmarshal(data, &old) == nil && old.Version >= p.Version {
		return nil
	}
	if err := putRecord(ctx, tx, network, kindPolicy, p.PersonPublicKey, p); err != nil {
		return err
	}
	return appendEvent(ctx, tx, "network.policy_updated", personIDOf(p.PersonPublicKey), now)
}

// storedPolicy is the newest version of an owner's policy this host has
// verified, within its window or not.
func (g governance) storedPolicy(key string) (membership.Policy, bool) {
	var p membership.Policy
	data, ok := g.persisted.policies[key]
	if !ok || json.Unmarshal(data, &p) != nil || p.PersonPublicKey != key || membership.VerifyPolicy(g.network.ID, p) != nil {
		return p, false
	}
	return p, true
}

// personKey is the key of a current person by ID.
func (g governance) personKey(id string) (string, bool) {
	for key := range g.persons() {
		if personIDOf(key) == id {
			return key, true
		}
	}
	return "", false
}

type networkRecord struct {
	network string
	member  NetworkMember
}

// membershipsOf lists a host's member records, ordered by network ID.
func membershipsOf(ctx context.Context, q queryer, host string) ([]networkRecord, error) {
	rows, err := q.QueryContext(ctx, "SELECT network_id, record FROM network_members WHERE host_id = ? ORDER BY network_id", host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []networkRecord
	for rows.Next() {
		var r networkRecord
		var record string
		if err = rows.Scan(&r.network, &record); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(record), &r.member); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SubmitPolicy verifies an owner-signed policy, submits it to the network's
// coordinator, and records it once accepted.
func (s *Store) SubmitPolicy(ctx context.Context, id string, p membership.Policy) (membership.Policy, error) {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return p, err
	}
	if err = membership.VerifyPolicy(id, p); err != nil {
		return p, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !membership.PolicyActive(p, time.Now()) {
		return p, fmt.Errorf("%w: the policy is not within its validity window", ErrInvalid)
	}
	if _, ok := g.persons()[p.PersonPublicKey]; !ok {
		return p, fmt.Errorf("%w: the policy owner is not a current person of this network", ErrForbidden)
	}
	// An identical resubmission is passed on; the coordinator accepts it again.
	if old, ok := g.storedPolicy(p.PersonPublicKey); ok && old.Version >= p.Version && (old.Version != p.Version || old.Signature != p.Signature) {
		return p, fmt.Errorf("%w: policy version %d is not above the newest verified version %d", ErrConflict, p.Version, old.Version)
	}
	if _, err = s.callCoordinator(ctx, g.network, networkPath(g.network, "/policies"), map[string]any{"policy": p}); err != nil {
		return p, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	stored, err := loadStatements(ctx, tx, id)
	if err != nil {
		return p, err
	}
	if err = recordPolicy(ctx, tx, id, stored, p, timestamp(time.Now())); err != nil {
		return p, err
	}
	if err = tx.Commit(); err != nil {
		return p, err
	}
	if _, err = s.SyncNetwork(ctx, id); err != nil {
		return p, err
	}
	return p, nil
}

// Policy is the newest verified policy of a person, this host's bound person
// by default.
func (s *Store) Policy(ctx context.Context, id, given string) (PolicyView, error) {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return PolicyView{}, err
	}
	var key string
	if given == "" {
		self, err := readJSON[NetworkMember](s.db.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", id, s.identity.ID))
		if err != nil {
			return PolicyView{}, err
		}
		if self.PersonID == nil {
			return PolicyView{}, fmt.Errorf("%w: this host is not bound to a person in that network; give --person", ErrNotFound)
		}
		var ok bool
		if key, ok = g.personKey(*self.PersonID); !ok {
			return PolicyView{}, ErrNotFound
		}
	} else {
		p, err := ResolvePerson(g.personList(), given)
		if err != nil {
			return PolicyView{}, err
		}
		key = p.PublicKey
	}
	p, ok := g.storedPolicy(key)
	if !ok {
		return PolicyView{}, fmt.Errorf("%w: no access policy", ErrNotFound)
	}
	return PolicyView{Policy: p, ExpiresSoon: membership.PolicyExpiresSoon(p, time.Now())}, nil
}

// blocked reports whether the block list refuses a sender: by host ID, or as
// bound to a blocked person in any network.
func blocked(ctx context.Context, tx *sql.Tx, sender string) (bool, error) {
	var found bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM access_blocks WHERE (kind = 'host' AND subject = ?1) OR (kind = 'person' AND subject IN (SELECT json_extract(record, '$.person_id') FROM network_members WHERE host_id = ?1)))`, sender).Scan(&found)
	return found, err
}

// messageBounds checks everything except coordination connectivity: the
// block list, then the grant or the cited owner's policy. Its denials are
// final, except a receiver behind the cited policy version (ErrUnavailable).
func (s *Store) messageBounds(ctx context.Context, tx *sql.Tx, sender string, r MessageRequest, requireDeadline bool) (authority, error) {
	return s.actionBounds(ctx, tx, sender, membership.PolicyActionMessage, r, requireDeadline)
}

// actionBounds is messageBounds for any action: a task request is checked as
// a message whose content is the task input.
func (s *Store) actionBounds(ctx context.Context, tx *sql.Tx, sender, action string, r MessageRequest, requireDeadline bool) (authority, error) {
	if refused, err := blocked(ctx, tx, sender); err != nil || refused {
		if err == nil {
			err = ErrForbidden
		}
		return authority{}, err
	}
	if r.Policy != nil {
		return s.policyBounds(ctx, tx, sender, action, r, requireDeadline)
	}
	g, err := grantBounds(ctx, tx, sender, action, r, requireDeadline)
	return authority{g.MaxMessageBytes, g.AllowDisconnected, g.MaxArtifactBytes, g.Action == membership.PolicyActionDelegate}, err
}

// policyBounds authorizes a message under the cited owner's newest verified
// policy, in each network where this host is bound to that owner. Matching
// rules combine: the largest size limit and any allow_disconnected apply.
func (s *Store) policyBounds(ctx context.Context, tx *sql.Tx, sender, action string, r MessageRequest, requireDeadline bool) (authority, error) {
	now := time.Now()
	deadline, err := parseTime(r.Deadline)
	if err != nil {
		return authority{}, err
	}
	if requireDeadline && !deadline.After(now) {
		return authority{}, ErrForbidden
	}
	var agent string
	err = tx.QueryRowContext(ctx, "SELECT name FROM agents WHERE id = ?", r.TargetAgentID).Scan(&agent)
	if errors.Is(err, sql.ErrNoRows) {
		return authority{}, ErrForbidden
	}
	if err != nil {
		return authority{}, err
	}
	own, err := membershipsOf(ctx, tx, s.identity.ID)
	if err != nil {
		return authority{}, err
	}
	var allowed *authority
	behind := false
	for _, n := range own {
		if n.member.PersonID == nil || *n.member.PersonID != r.Policy.PersonID || sender == s.identity.ID {
			continue
		}
		g, err := s.loadGovernance(ctx, tx, n.network)
		if err != nil {
			return authority{}, err
		}
		key, ok := g.personKey(r.Policy.PersonID)
		if !ok {
			continue
		}
		p, ok := g.storedPolicy(key)
		if !ok || p.Version < r.Policy.Version {
			behind = true
			continue
		}
		// The receiver evaluates its own newest version.
		until, _ := membership.ParseTime(p.ValidUntil)
		if !membership.PolicyActive(p, now) || deadline.After(until) {
			continue
		}
		member, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", n.network, sender))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return authority{}, err
		}
		for _, rule := range p.Rules {
			if rule.Agent != agent || !ruleAllows(rule, action) || int64(len(r.Content)) > rule.MaxMessageBytes || !artifactsAllowed(r, rule.MaxArtifactBytes) || !g.principalMatches(rule, member, r.Origin) {
				continue
			}
			if allowed == nil {
				allowed = &authority{}
			}
			allowed.maxMessageBytes = max(allowed.maxMessageBytes, rule.MaxMessageBytes)
			allowed.allowDisconnected = allowed.allowDisconnected || rule.AllowDisconnected
			allowed.maxArtifactBytes = max(allowed.maxArtifactBytes, rule.MaxArtifactBytes)
			allowed.delegate = allowed.delegate || hasAction(rule, membership.PolicyActionDelegate)
		}
	}
	switch {
	case allowed != nil:
		return *allowed, nil
	case behind:
		return authority{}, fmt.Errorf("%w: this host has not yet verified the cited policy version", ErrUnavailable)
	}
	return authority{}, ErrForbidden
}

// ruleAllows reports whether a rule permits an action; task.delegate implies
// task.submit.
func ruleAllows(rule membership.PolicyRule, want string) bool {
	for _, action := range rule.Actions {
		if actionGranted(action, want) {
			return true
		}
	}
	return false
}

func hasAction(rule membership.PolicyRule, want string) bool {
	for _, action := range rule.Actions {
		if action == want {
			return true
		}
	}
	return false
}

// principalMatches reports whether a sender member matches any of a rule's
// principals: bound to the person, bound to a group member, any member, or
// that host with that asserted origin agent.
func (g governance) principalMatches(rule membership.PolicyRule, sender NetworkMember, origin *Origin) bool {
	for _, principal := range rule.Principals {
		if host, agent, ok := membership.AgentPrincipal(principal); ok {
			if host == sender.HostID && origin != nil && origin.AgentID == agent {
				return true
			}
			continue
		}
		switch {
		case principal == membership.PrincipalNetwork:
			return true
		case sender.PersonID == nil:
		case strings.HasPrefix(principal, "person:"):
			if strings.TrimPrefix(principal, "person:") == *sender.PersonID {
				return true
			}
		case strings.HasPrefix(principal, "group:"):
			if group, ok := g.storedGroup(strings.TrimPrefix(principal, "group:")); ok {
				for _, member := range group.Members {
					if member == *sender.PersonID {
						return true
					}
				}
			}
		}
	}
	return false
}

// policyCitation is what a send without a grant cites: the target host's
// bound person's newest verified policy, in the first network that has one.
func (s *Store) policyCitation(ctx context.Context, q dbQuerier, peer string) (*PolicyCitation, error) {
	citation, _, err := s.policyCitationUntil(ctx, q, peer)
	return citation, err
}

// policyCitationUntil is policyCitation with the cited policy's valid_until.
func (s *Store) policyCitationUntil(ctx context.Context, q dbQuerier, peer string) (*PolicyCitation, time.Time, error) {
	memberships, err := membershipsOf(ctx, q, peer)
	if err != nil {
		return nil, time.Time{}, err
	}
	owner := ""
	for _, n := range memberships {
		if n.member.PersonID == nil {
			continue
		}
		owner = *n.member.PersonID
		g, err := s.loadGovernance(ctx, q, n.network)
		if err != nil {
			return nil, time.Time{}, err
		}
		key, ok := g.personKey(owner)
		if !ok {
			continue
		}
		if p, ok := g.storedPolicy(key); ok {
			until, err := membership.ParseTime(p.ValidUntil)
			if err != nil {
				return nil, until, err
			}
			return &PolicyCitation{PersonID: owner, Version: p.Version}, until, nil
		}
	}
	if owner == "" {
		return nil, time.Time{}, fmt.Errorf("%w: no grant given, and host %s is not bound to a person in any shared network; ask its owner for a grant", ErrInvalid, peer)
	}
	return nil, time.Time{}, fmt.Errorf("%w: no grant given, and the owner of host %s (%s) has no access policy; ask them to run access allow, or give a grant", ErrInvalid, peer, owner)
}

func (s *Store) AccessBlocks(ctx context.Context) ([]AccessBlock, error) {
	return records[AccessBlock](ctx, s.db, "SELECT record FROM access_blocks ORDER BY kind, subject")
}

// blockSubject resolves a block request: a host ID, or a person by ID, key,
// or unambiguous label among every network's current persons. A well-formed
// person ID need not be known.
func (s *Store) blockSubject(ctx context.Context, r BlockAccess) (string, string, error) {
	switch {
	case r.Host != "" && r.Person == "":
		if !validID(r.Host, "host", 32) {
			return "", "", fmt.Errorf("%w: invalid host ID", ErrInvalid)
		}
		return "host", r.Host, nil
	case r.Person != "" && r.Host == "":
		networks, err := s.Networks(ctx)
		if err != nil {
			return "", "", err
		}
		seen := map[string]bool{}
		var persons []Person
		for _, n := range networks {
			g, err := s.loadGovernance(ctx, s.db, n.ID)
			if err != nil {
				return "", "", err
			}
			for _, p := range g.personList() {
				if !seen[p.PersonID] {
					seen[p.PersonID] = true
					persons = append(persons, p)
				}
			}
		}
		sort.Slice(persons, func(i, j int) bool { return persons[i].PersonID < persons[j].PersonID })
		p, err := ResolvePerson(persons, r.Person)
		if errors.Is(err, ErrNotFound) && membership.ValidPersonID(r.Person) {
			return "person", r.Person, nil
		}
		return "person", p.PersonID, err
	}
	return "", "", fmt.Errorf("%w: give exactly one of person or host", ErrInvalid)
}

// Block adds a host-local block, effective at once; blocking again returns
// the existing block.
func (s *Store) Block(ctx context.Context, r BlockAccess) (AccessBlock, error) {
	kind, subject, err := s.blockSubject(ctx, r)
	if err != nil {
		return AccessBlock{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessBlock{}, err
	}
	defer tx.Rollback()
	old, err := readJSON[AccessBlock](tx.QueryRowContext(ctx, "SELECT record FROM access_blocks WHERE kind = ? AND subject = ?", kind, subject))
	if err == nil || !errors.Is(err, ErrNotFound) {
		return old, err
	}
	b := AccessBlock{Kind: kind, Subject: subject, CreatedAt: timestamp(time.Now())}
	if err = putJSON(ctx, tx, "INSERT INTO access_blocks (record, kind, subject) VALUES (?, ?, ?)", b, kind, subject); err != nil {
		return b, err
	}
	if err = appendEvent(ctx, tx, "access.blocked", subject, b.CreatedAt); err != nil {
		return b, err
	}
	return b, tx.Commit()
}

// Unblock removes a block and returns it; an unknown block is not found.
func (s *Store) Unblock(ctx context.Context, r BlockAccess) (AccessBlock, error) {
	kind, subject, err := s.blockSubject(ctx, r)
	if err != nil {
		return AccessBlock{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessBlock{}, err
	}
	defer tx.Rollback()
	old, err := readJSON[AccessBlock](tx.QueryRowContext(ctx, "SELECT record FROM access_blocks WHERE kind = ? AND subject = ?", kind, subject))
	if err != nil {
		return old, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM access_blocks WHERE kind = ? AND subject = ?", kind, subject); err != nil {
		return old, err
	}
	if err = appendEvent(ctx, tx, "access.unblocked", subject, timestamp(time.Now())); err != nil {
		return old, err
	}
	return old, tx.Commit()
}

// personAgent is the ssh-agent socket the daemon asks for policy renewals.
type personAgent struct {
	sync.Mutex
	socket string
}

// ConfigurePersonAgent sets the ssh-agent socket for policy renewal; empty
// disables renewal.
func (s *Store) ConfigurePersonAgent(socket string) {
	s.agent.Lock()
	defer s.agent.Unlock()
	s.agent.socket = socket
}

// RenewPolicies renews this host's bound persons' policies that have less
// than a quarter of their validity left, signing through the ssh-agent. Each
// renewal keeps the rules and duration at version + 1, issued now. Several of
// an owner's hosts may renew at once; the coordinator accepts one and returns
// 409 to the rest, which keep the accepted one at the next sync.
func (s *Store) RenewPolicies(ctx context.Context, logf func(string, ...any)) {
	s.agent.Lock()
	socket := s.agent.socket
	s.agent.Unlock()
	if socket == "" {
		return
	}
	own, err := membershipsOf(ctx, s.db, s.identity.ID)
	if err != nil {
		return
	}
	now := time.Now()
	for _, n := range own {
		if n.member.PersonID == nil {
			continue
		}
		g, err := s.loadGovernance(ctx, s.db, n.network)
		if err != nil {
			continue
		}
		key, ok := g.personKey(*n.member.PersonID)
		if !ok {
			continue
		}
		p, ok := g.storedPolicy(key)
		until, _ := membership.ParseTime(p.ValidUntil)
		if !ok || !membership.PolicyExpiresSoon(p, now) || !now.Before(until) {
			continue
		}
		public, err := membership.DecodeKey(key)
		if err != nil {
			continue
		}
		signer, err := person.LoadKeyAt(socket, ed25519.PublicKey(public))
		if err != nil {
			continue // the agent does not hold this owner's key
		}
		renewed, err := membership.Renewal(signer, p, now.Truncate(time.Second))
		signer.Close()
		if err != nil {
			logf("policy renewal for %s: %v", n.network, err)
			continue
		}
		_, err = s.SubmitPolicy(ctx, n.network, renewed)
		switch {
		case err == nil:
			logf("renewed access policy %d for %s", renewed.Version, n.network)
		case errors.Is(err, ErrConflict):
			// Another of the owner's hosts renewed first.
			_, _ = s.SyncNetwork(ctx, n.network)
		default:
			logf("policy renewal for %s: %v", n.network, err)
		}
	}
}

func localPolicyRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/networks/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		var req SubmitPolicy
		if !decode(w, r, &req, "policy") {
			return
		}
		if req.Policy == nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		result, err := store.SubmitPolicy(r.Context(), r.PathValue("id"), *req.Policy)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("GET /v1/networks/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.Policy(r.Context(), r.PathValue("id"), r.URL.Query().Get("person"))
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("GET /v1/access-blocks", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.AccessBlocks(r.Context())
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("POST /v1/access-blocks", func(w http.ResponseWriter, r *http.Request) {
		var req BlockAccess
		if !decode(w, r, &req, "person", "host") {
			return
		}
		result, err := store.Block(r.Context(), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/access-blocks/remove", func(w http.ResponseWriter, r *http.Request) {
		var req BlockAccess
		if !decode(w, r, &req, "person", "host") {
			return
		}
		result, err := store.Unblock(r.Context(), req)
		respond(w, http.StatusOK, result, err)
	})
}
