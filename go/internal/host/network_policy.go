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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
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

// SelfCitation is self access: the request relies on sender and receiver
// being bound to one person, the sender's, in a network they share.
type SelfCitation struct {
	PersonID string `json:"person_id"`
}

func (c *SelfCitation) UnmarshalJSON(data []byte) error {
	type plain SelfCitation
	return membership.Strict(data, (*plain)(c), "person_id")
}

// Self access bounds: every action, with these effective limits.
const (
	selfMaxMessageBytes  = 65536
	selfMaxArtifactBytes = membership.PolicyMaxArtifactBytes
)

// Route and request authorization kinds.
const (
	AuthorizationGrant  = "grant"
	AuthorizationPolicy = "policy"
	AuthorizationSelf   = "self"
)

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
	data, err := json.Marshal(v.Policy)
	if err != nil {
		return nil, err
	}
	// The policy's own fields, then expires_soon.
	data = append(append(data[:len(data)-1], `,"expires_soon":`...), strconv.FormatBool(v.ExpiresSoon)...)
	return append(data, '}'), nil
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

// applyPolicies keeps, for each owner, the preferred policy whose signature
// verifies (the highest version, or of equal versions the lower statement
// hash): persisted versions always, served ones only from current persons and
// within their window. A lower version never replaces a higher one.
func (a *appliedMap) applyPolicies(persisted persistedStatements, m membership.Map) {
	a.policies = map[string]membership.Policy{}
	now := time.Now()
	consider := func(p membership.Policy, served bool) {
		if membership.VerifyPolicy(a.chain.NetworkID, p) != nil || (served && !membership.PolicyActive(p, now)) {
			return
		}
		if old, ok := a.policies[p.PersonPublicKey]; !ok || membership.PolicyPreferred(p, old) {
			a.policies[p.PersonPublicKey] = p
		}
	}
	for _, key := range sortedKeys(persisted.policies) {
		var p membership.Policy
		if json.Unmarshal(persisted.policies[key], &p) == nil && p.PersonPublicKey == key {
			consider(p, false)
		}
	}
	for _, p := range membership.DecodeRaw[membership.Policy](m.Policies) {
		if _, ok := a.persons[p.PersonPublicKey]; ok {
			consider(p, true)
		}
	}
}

// persistPolicies stores each policy the map application preferred over the
// stored one, queuing deliveries of this host's own person's policy.
func (s *Store) persistPolicies(ctx context.Context, tx *sql.Tx, network string, a appliedMap, now string) error {
	stored, err := loadStatements(ctx, tx, network)
	if err != nil {
		return err
	}
	for _, key := range sortedKeys(a.policies) {
		p := a.policies[key]
		var old membership.Policy
		if data, ok := stored.policies[key]; ok && json.Unmarshal(data, &old) == nil && old.PersonPublicKey == key && !membership.PolicyPreferred(p, old) {
			continue
		}
		if err = s.storePolicy(ctx, tx, network, p, now); err != nil {
			return err
		}
	}
	return nil
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

// SubmitPolicy verifies an owner-signed policy from the CLI and stores it
// under the acceptance rule before submitting it anywhere, so it applies here
// at once. A policy of this host's own person is then delivered to its
// siblings and the coordinator; another owner's goes to the coordinator only.
// One coordinator attempt is made now; the delivery worker retries. An
// identical resubmission changes nothing.
func (s *Store) SubmitPolicy(ctx context.Context, id string, p membership.Policy) (membership.Policy, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	g, err := s.loadGovernance(ctx, tx, id)
	if err != nil {
		return p, err
	}
	if old, ok := g.storedPolicy(p.PersonPublicKey); ok && old.Version == p.Version && old.Signature == p.Signature {
		return p, nil
	}
	now := time.Now()
	stored, err := s.acceptPolicy(ctx, tx, id, p, now)
	if err != nil {
		return p, err
	}
	if !stored {
		old, _ := g.storedPolicy(p.PersonPublicKey)
		return p, fmt.Errorf("%w: policy version %d does not supersede the stored version %d", ErrConflict, p.Version, old.Version)
	}
	person := personIDOf(p.PersonPublicKey)
	own, err := s.ownPerson(ctx, tx, id)
	if err != nil {
		return p, err
	}
	if own != person {
		if err = queueDeliveries(ctx, tx, id, person, p, []string{policyTargetCoordinator}, timestamp(now)); err != nil {
			return p, err
		}
	}
	if err = tx.Commit(); err != nil {
		return p, err
	}
	s.wakePolicyDeliveries()
	delivered, err := s.attemptDelivery(ctx, id, person, policyTargetCoordinator)
	if err != nil {
		return p, err
	}
	if delivered {
		if _, err = s.SyncNetwork(ctx, id); err != nil {
			return p, err
		}
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
	if r.Self != nil {
		return s.selfBounds(ctx, tx, sender, r, requireDeadline)
	}
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
		named := membership.NamesAgent(p, agent)
		for _, rule := range p.Rules {
			if !membership.RuleApplies(rule, agent, named) || !ruleAllows(rule, action) || int64(len(r.Content)) > rule.MaxMessageBytes || !artifactsAllowed(r, rule.MaxArtifactBytes) || !g.principalMatches(rule, member, r.Origin) {
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

// ownerCitation is what a request without a grant cites: self, or the
// owner policy and its valid_until.
type ownerCitation struct {
	policy *PolicyCitation
	self   *SelfCitation
	until  time.Time
}

// ownerCitation is what a send without a grant cites: self access when the
// target host is bound to this host's person in a network they share,
// otherwise the target host's bound person's newest verified policy, in the
// first network that has one.
func (s *Store) ownerCitation(ctx context.Context, q dbQuerier, peer string) (ownerCitation, error) {
	return s.chainCitation(ctx, q, peer, s.identity.ID)
}

// chainCitation is ownerCitation for a request whose authorization is the
// originator's: in a forward, which carries a chain of two or more links,
// self access is cited when the originator host and the target are bound to
// one person, the originator's, in a network both share.
func (s *Store) chainCitation(ctx context.Context, q dbQuerier, peer, originator string) (ownerCitation, error) {
	if person, ok, err := s.boundPerson(ctx, q, originator, peer); err != nil || ok {
		if ok {
			return ownerCitation{self: &SelfCitation{PersonID: person}}, nil
		}
		return ownerCitation{}, err
	}
	citation, until, err := s.policyCitationUntil(ctx, q, peer)
	return ownerCitation{policy: citation, until: until}, err
}

// selfPerson is this host's person when peer, a current member, is bound to
// that person in a network both hosts share, in the lowest such network.
func (s *Store) selfPerson(ctx context.Context, q queryer, peer string) (string, bool, error) {
	if peer == s.identity.ID {
		return "", false, nil
	}
	return s.boundPerson(ctx, q, s.identity.ID, peer)
}

// boundPerson is the person both hosts are bound to in the lowest network
// where both are current members bound to one person, in this host's view.
func (s *Store) boundPerson(ctx context.Context, q queryer, host, peer string) (string, bool, error) {
	own, err := membershipsOf(ctx, q, host)
	if err != nil {
		return "", false, err
	}
	theirs, err := membershipsOf(ctx, q, peer)
	if err != nil {
		return "", false, err
	}
	for _, n := range own {
		if n.member.PersonID == nil {
			continue
		}
		for _, t := range theirs {
			if t.network == n.network && t.member.PersonID != nil && *t.member.PersonID == *n.member.PersonID {
				return *n.member.PersonID, true, nil
			}
		}
	}
	return "", false, nil
}

// selfBounds authorizes self access: this host and the sender (for a chain
// of two or more links, the originator host), a current member, are both bound to the cited person in a network they share. It
// needs no grant or policy, allows every action within the self access
// bounds, and holds without coordination. Blocks do not apply.
func (s *Store) selfBounds(ctx context.Context, tx *sql.Tx, sender string, r MessageRequest, requireDeadline bool) (authority, error) {
	deadline, err := parseTime(r.Deadline)
	if err != nil {
		return authority{}, err
	}
	if requireDeadline && !deadline.After(time.Now()) {
		return authority{}, ErrForbidden
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?)", r.TargetAgentID).Scan(&exists); err != nil || !exists {
		if err == nil {
			err = ErrForbidden
		}
		return authority{}, err
	}
	ok, err := s.boundTogether(ctx, tx, sender, r.Self.PersonID)
	if err != nil || !ok {
		if err == nil {
			err = ErrForbidden
		}
		return authority{}, err
	}
	if int64(len(r.Content)) > selfMaxMessageBytes || !artifactsAllowed(r, selfMaxArtifactBytes) {
		return authority{}, ErrForbidden
	}
	return authority{maxMessageBytes: selfMaxMessageBytes, allowDisconnected: true, maxArtifactBytes: selfMaxArtifactBytes, delegate: true}, nil
}

// boundTogether reports whether this host and peer are both bound to person
// in some network they share. A chain may return to its originator, so peer
// may be this host.
func (s *Store) boundTogether(ctx context.Context, q dbQuerier, peer, person string) (bool, error) {
	var found bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM network_members a JOIN network_members b ON a.network_id = b.network_id WHERE a.host_id = ? AND b.host_id = ? AND json_extract(a.record, '$.person_id') = ? AND json_extract(b.record, '$.person_id') = ?)`, s.identity.ID, peer, person, person).Scan(&found)
	return found, err
}

// policyCitationUntil is the policy a send cites, with its valid_until.
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
		// A person admitted moments ago may not have reached this host yet,
		// so an unresolved label syncs every network once and resolves again.
		for synced := false; ; synced = true {
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
			if !errors.Is(err, ErrNotFound) || synced {
				return "person", p.PersonID, err
			}
			for _, n := range networks {
				_, _ = s.SyncNetwork(ctx, n.ID)
			}
		}
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
	// keyFile is the CLI-generated person key the daemon may also renew
	// with (run --person-key-file), or "".
	keyFile string
}

// ConfigurePersonAgent sets the ssh-agent socket for policy renewal; empty
// disables renewal.
func (s *Store) ConfigurePersonAgent(socket string) {
	s.agent.Lock()
	defer s.agent.Unlock()
	s.agent.socket = socket
}

// ConfigurePersonKeyFile sets the generated person key file used for
// renewal when the ssh-agent lacks the person's key; empty disables it. The
// file is read when a renewal needs it.
func (s *Store) ConfigurePersonKeyFile(path string) {
	s.agent.Lock()
	defer s.agent.Unlock()
	s.agent.keyFile = path
}

// renewalSigner is a signer for an owner key: through the ssh-agent, or
// else from the person key file when it holds that key.
func (s *Store) renewalSigner(public ed25519.PublicKey) (person.Signer, error) {
	s.agent.Lock()
	socket, keyFile := s.agent.socket, s.agent.keyFile
	s.agent.Unlock()
	err := errors.New("the daemon has no ssh-agent (--person-agent) to renew your access policy")
	if socket != "" {
		var signer person.Signer
		if signer, err = person.LoadKeyAt(socket, public); err == nil {
			return signer, nil
		}
		err = fmt.Errorf("the daemon cannot renew your access policy through its ssh-agent %s: %w", socket, err)
	}
	if keyFile != "" {
		if signer, fileErr := person.LoadPrivateFile(keyFile); fileErr == nil {
			if signer.PublicKey().Equal(public) {
				return signer, nil
			}
			signer.Close()
		}
	}
	return nil, err
}

// RenewPolicies renews this host's bound persons' policies that have less
// than a quarter of their validity left, signing through the ssh-agent. Each
// renewal keeps the rules and duration at version + 1, issued now. Several of
// an owner's hosts may renew at once; they converge on the renewal with the
// lower statement hash by direct propagation.
func (s *Store) RenewPolicies(ctx context.Context, logf func(string, ...any)) {
	s.agent.Lock()
	enabled := s.agent.socket != "" || s.agent.keyFile != ""
	s.agent.Unlock()
	if !enabled {
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
		signer, err := s.renewalSigner(ed25519.PublicKey(public))
		if err != nil {
			continue // neither the agent nor the key file holds this owner's key
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
			// Another of the owner's hosts renewed first, and its renewal won.
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
