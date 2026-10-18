package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Capabilities: the owner's named, host-local definitions of one use case
// each, binding a source, selected operations, and the credential context
// that serves calls.

// Capability states.
const (
	CapabilityAvailable   = "available"
	CapabilityUnavailable = "unavailable"
	// unavailableSource marks a capability whose source is gone.
	unavailableSource = "source"
)

// CapabilitySource names a capability's source on this host.
type CapabilitySource struct {
	Agent  string `json:"agent"`
	Server string `json:"server"`
}

// CapabilityResources is a capability's resources: none (null), every
// resource of the snapshot ("all"), or a list of URIs.
type CapabilityResources struct {
	Set  bool
	All  bool
	URIs []string
}

func (r CapabilityResources) MarshalJSON() ([]byte, error) {
	switch {
	case !r.Set:
		return []byte("null"), nil
	case r.All:
		return []byte(`"all"`), nil
	}
	return json.Marshal(r.URIs)
}

func (r *CapabilityResources) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	*r = CapabilityResources{}
	switch {
	case string(trimmed) == "null":
		return nil
	case string(trimmed) == `"all"`:
		r.Set, r.All = true, true
		return nil
	}
	var uris []string
	if err := json.Unmarshal(trimmed, &uris); err != nil || uris == nil {
		return fmt.Errorf("%w: resources are null, \"all\", or a list of URIs", ErrInvalid)
	}
	r.Set, r.URIs = true, uris
	return nil
}

// CapabilityCredential is a capability's credential context; both null
// means the source's own instance and environment.
type CapabilityCredential struct {
	EnvFile *string  `json:"env_file"`
	Args    []string `json:"args"`
}

// capabilityRecord is capabilities.record: the definition, the agent it is
// built on, and its own snapshot when it has its own credential.
type capabilityRecord struct {
	Name       string               `json:"name"`
	Source     CapabilitySource     `json:"source"`
	Operations []string             `json:"operations"`
	Resources  CapabilityResources  `json:"resources"`
	Credential CapabilityCredential `json:"credential"`
	CreatedAt  string               `json:"created_at"`
	AgentID    string               `json:"agent_id"`
	Snapshot   *toolSnapshotState   `json:"snapshot,omitempty"`
}

func (c capabilityRecord) ownInstance() bool {
	return c.Credential.EnvFile != nil || c.Credential.Args != nil
}

func (c capabilityRecord) credential() *ownCredential {
	if !c.ownInstance() {
		return nil
	}
	return &ownCredential{capability: c.Name, envFile: c.Credential.EnvFile, args: c.Credential.Args}
}

// Capability is a capability record as the local API shows it.
type Capability struct {
	Name        string               `json:"name"`
	Source      CapabilitySource     `json:"source"`
	Operations  []string             `json:"operations"`
	Resources   CapabilityResources  `json:"resources"`
	Credential  CapabilityCredential `json:"credential"`
	Bounds      map[string]any       `json:"bounds"`
	State       string               `json:"state"`
	Unavailable []string             `json:"unavailable"`
	CreatedAt   string               `json:"created_at"`
}

// Recipient is one principal a rule for a capability on this host names.
type Recipient struct {
	NetworkID string  `json:"network_id"`
	Principal string  `json:"principal"`
	Label     *string `json:"label"`
}

// CapabilityWithRecipients is a capability with its recipients.
type CapabilityWithRecipients struct {
	Capability
	Recipients []Recipient `json:"recipients"`
}

func (c CapabilityWithRecipients) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(c.Capability)
	if err != nil {
		return nil, err
	}
	recipients, err := json.Marshal(c.Recipients)
	if err != nil {
		return nil, err
	}
	return append(append(data[:len(data)-1], []byte(`,"recipients":`)...), append(recipients, '}')...), nil
}

// CreateCapability is POST /v1/capabilities.
type CreateCapability struct {
	Name       string              `json:"name"`
	Source     CapabilitySource    `json:"source"`
	Operations []string            `json:"operations"`
	Resources  CapabilityResources `json:"resources"`
	EnvFile    *string             `json:"env_file"`
	Args       []string            `json:"args"`
	// Policies claim the name: one signed policy per network in which this
	// host is bound to its person, each with this host's rule for the name.
	Policies []membership.Policy `json:"policies"`
}

func readCapability(ctx context.Context, q dbQuerier, name string) (capabilityRecord, error) {
	return readJSON[capabilityRecord](q.QueryRowContext(ctx, `SELECT record FROM capabilities WHERE name = ?`, name))
}

// capabilitySnapshot is the snapshot a capability's operations are checked
// against, with whether its source is still there and shareable.
func capabilitySnapshot(ctx context.Context, q dbQuerier, c capabilityRecord) (toolSnapshotState, bool, error) {
	rec, err := readToolServer(ctx, q, c.AgentID, c.Source.Server)
	if errors.Is(err, ErrNotFound) {
		return toolSnapshotState{}, false, nil
	}
	if err != nil || !rec.Shareable {
		return toolSnapshotState{}, false, err
	}
	if c.ownInstance() {
		if c.Snapshot == nil {
			return toolSnapshotState{}, true, nil
		}
		return *c.Snapshot, true, nil
	}
	return rec.toolSnapshotState, true, nil
}

// readURIs are the capability's resources currently in the snapshot.
func readURIs(c capabilityRecord, snap toolSnapshotState) []SnapshotResource {
	out := []SnapshotResource{}
	if !c.Resources.Set {
		return out
	}
	for _, r := range snap.Resources {
		if c.Resources.All || slices.Contains(c.Resources.URIs, r.URI) {
			out = append(out, r)
		}
	}
	return out
}

// capabilityState computes a capability's state: unavailable with source
// when its source is gone; otherwise the operations missing from the
// snapshot, and read when none of its resources is there.
func capabilityState(ctx context.Context, q dbQuerier, c capabilityRecord) (string, []string, toolSnapshotState, error) {
	snap, present, err := capabilitySnapshot(ctx, q, c)
	if err != nil {
		return "", nil, snap, err
	}
	if !present {
		return CapabilityUnavailable, []string{unavailableSource}, snap, nil
	}
	missing := []string{}
	for _, op := range c.Operations {
		if _, ok := snapshotTool(snap, op); !ok {
			missing = append(missing, op)
		}
	}
	if c.Resources.Set && len(readURIs(c, snap)) == 0 {
		missing = append(missing, membership.OperationRead)
	}
	if len(missing) > 0 {
		return CapabilityUnavailable, missing, snap, nil
	}
	return CapabilityAvailable, missing, snap, nil
}

func (s *Store) capabilityView(ctx context.Context, q dbQuerier, c capabilityRecord) (Capability, error) {
	state, unavailable, _, err := capabilityState(ctx, q, c)
	if err != nil {
		return Capability{}, err
	}
	ops := c.Operations
	if ops == nil {
		ops = []string{}
	}
	return Capability{Name: c.Name, Source: c.Source, Operations: ops, Resources: c.Resources, Credential: c.Credential, Bounds: map[string]any{}, State: state, Unavailable: unavailable, CreatedAt: c.CreatedAt}, nil
}

// recipients lists the principals of the rules for a capability on this
// host in this host's person's stored policies, with person labels.
func (s *Store) recipients(ctx context.Context, q dbQuerier, name string) ([]Recipient, error) {
	rules, err := s.ownCapabilityRules(ctx, q)
	if err != nil {
		return nil, err
	}
	out := []Recipient{}
	labels := map[string]map[string]string{}
	for _, r := range rules {
		if r.Host != s.identity.ID || r.Capability != name {
			continue
		}
		if labels[r.NetworkID] == nil {
			labels[r.NetworkID] = map[string]string{}
			if g, err := s.loadGovernance(ctx, q, r.NetworkID); err == nil {
				for _, p := range g.personList() {
					labels[r.NetworkID]["person:"+p.PersonID] = p.Member
				}
			}
		}
		for _, principal := range r.Principals {
			rec := Recipient{NetworkID: r.NetworkID, Principal: principal}
			if label, ok := labels[r.NetworkID][principal]; ok {
				rec.Label = &label
			}
			out = append(out, rec)
		}
	}
	return out, nil
}

// boundElsewhere reports whether a stored capability rule of this host's
// person binds a name to another host.
func (s *Store) boundElsewhere(ctx context.Context, q dbQuerier, name string) (bool, error) {
	rules, err := s.ownCapabilityRules(ctx, q)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if r.Capability == name && r.Host != s.identity.ID {
			return true, nil
		}
	}
	return false, nil
}

// errCapabilityExists marks an identical repeat of a capability, answered
// 200.
var errCapabilityExists = errors.New("the capability exists")

func sameCapability(a capabilityRecord, b CreateCapability) bool {
	ops := b.Operations
	if ops == nil {
		ops = []string{}
	}
	aops := a.Operations
	if aops == nil {
		aops = []string{}
	}
	ra, _ := json.Marshal(a.Resources)
	rb, _ := json.Marshal(b.Resources)
	return a.Source == b.Source && slices.Equal(aops, ops) && bytes.Equal(ra, rb) && deref(a.Credential.EnvFile) == deref(b.EnvFile) && (a.Credential.EnvFile == nil) == (b.EnvFile == nil) && sameArgs(a.Credential.Args, b.Args)
}

func sameArgs(a, b []string) bool {
	return (a == nil) == (b == nil) && slices.Equal(a, b)
}

// CreateCapability records a capability without sharing it. The source must
// be shareable, and each operation and URI must be in its snapshot, or in
// the capability's own snapshot when it has its own credential.
func (s *Store) CreateCapability(ctx context.Context, r CreateCapability) (Capability, error) {
	if !membership.ValidCapabilityName(r.Name) {
		return Capability{}, fmt.Errorf("%w: a capability name matches [a-z0-9][a-z0-9_-]{0,62} and is not read", ErrInvalid)
	}
	if r.Source.Agent == "" || r.Source.Server == "" {
		return Capability{}, fmt.Errorf("%w: source needs agent and server", ErrInvalid)
	}
	if r.EnvFile != nil && (!filepath.IsAbs(*r.EnvFile) || strings.ContainsRune(*r.EnvFile, 0)) {
		return Capability{}, fmt.Errorf("%w: env_file must be an absolute path", ErrInvalid)
	}
	for _, arg := range r.Args {
		if strings.ContainsRune(arg, 0) || len(arg) > 65536 {
			return Capability{}, fmt.Errorf("%w: invalid argument", ErrInvalid)
		}
	}
	seen := map[string]bool{}
	for _, op := range r.Operations {
		if op == membership.OperationRead {
			return Capability{}, fmt.Errorf("%w: read is reserved for resources and cannot be an operation", ErrInvalid)
		}
		if op == "" || seen[op] {
			return Capability{}, fmt.Errorf("%w: operations are distinct tool names", ErrInvalid)
		}
		seen[op] = true
	}
	if len(r.Operations) == 0 && !r.Resources.Set {
		return Capability{}, fmt.Errorf("%w: a capability needs an operation or resources", ErrInvalid)
	}
	if r.Resources.Set && !r.Resources.All && len(r.Resources.URIs) == 0 {
		return Capability{}, fmt.Errorf("%w: resources lists at least one URI", ErrInvalid)
	}
	var agentID string
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM agents WHERE name = ?`, r.Source.Agent).Scan(&agentID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Capability{}, fmt.Errorf("%w: no local agent %q", ErrNotFound, r.Source.Agent)
		}
		return Capability{}, err
	}
	rec, err := readToolServer(ctx, s.db, agentID, r.Source.Server)
	if errors.Is(err, ErrNotFound) {
		return Capability{}, fmt.Errorf("%w: agent %s has no source %q", ErrNotFound, r.Source.Agent, r.Source.Server)
	}
	if err != nil {
		return Capability{}, err
	}
	if old, err := readCapability(ctx, s.db, r.Name); err == nil {
		if !sameCapability(old, r) {
			return Capability{}, fmt.Errorf("%w: a different capability %s exists on this host", ErrConflict, r.Name)
		}
		view, err := s.capabilityView(ctx, s.db, old)
		if err != nil {
			return view, err
		}
		return view, errCapabilityExists
	} else if !errors.Is(err, ErrNotFound) {
		return Capability{}, err
	}
	if elsewhere, err := s.boundElsewhere(ctx, s.db, r.Name); err != nil || elsewhere {
		if err == nil {
			err = fmt.Errorf("%w: a capability rule of yours binds %s to another host", ErrConflict, r.Name)
		}
		return Capability{}, err
	}
	if !rec.Shareable {
		return Capability{}, fmt.Errorf("%w: source %s/%s is not shareable (%s)", ErrInvalid, r.Source.Agent, r.Source.Server, deref(rec.Reason))
	}
	if r.EnvFile != nil {
		if info, err := os.Stat(*r.EnvFile); err != nil || !info.Mode().IsRegular() {
			return Capability{}, fmt.Errorf("%w: env_file %s does not exist", ErrInvalid, *r.EnvFile)
		}
	}
	c := capabilityRecord{Name: r.Name, Source: r.Source, Operations: r.Operations, Resources: r.Resources, Credential: CapabilityCredential{EnvFile: r.EnvFile, Args: r.Args}, AgentID: agentID}
	if c.Operations == nil {
		c.Operations = []string{}
	}
	snap := rec.toolSnapshotState
	if c.ownInstance() {
		// A capability with its own credential is checked against a snapshot
		// taken with that credential.
		spec, err := s.toolLaunch(ctx, s.db, agentID, r.Source.Server, c.credential())
		var taken toolSnapshot
		if err == nil {
			taken, err = takeSnapshot(context.WithoutCancel(ctx), spec)
		}
		if err != nil {
			return Capability{}, fmt.Errorf("%w: the snapshot with the capability's credential failed: %v", ErrInvalid, err)
		}
		at := timestamp(time.Now())
		snap = toolSnapshotState{Tools: taken.Tools, Resources: taken.Resources, SnapshotAt: &at}
		c.Snapshot = &snap
	}
	for _, op := range c.Operations {
		if _, ok := snapshotTool(snap, op); !ok {
			return Capability{}, fmt.Errorf("%w: the source's snapshot has no tool %q", ErrInvalid, op)
		}
	}
	for _, uri := range r.Resources.URIs {
		if _, ok := snapshotResource(snap, uri); !ok {
			return Capability{}, fmt.Errorf("%w: the source's snapshot has no resource %q", ErrInvalid, uri)
		}
	}
	claims, err := s.checkClaims(ctx, r)
	if err != nil {
		return Capability{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Capability{}, err
	}
	defer tx.Rollback()
	now := time.Now()
	c.CreatedAt = timestamp(now)
	// The claims and the record are stored together; a refusal stores
	// nothing.
	for _, p := range claims {
		if err = s.submitPolicyIn(ctx, tx, p.NetworkID, p, now); err != nil {
			if errors.Is(err, ErrForbidden) {
				err = fmt.Errorf("%w: %v", ErrInvalid, err)
			}
			return Capability{}, err
		}
	}
	if err = putJSON(ctx, tx, `INSERT INTO capabilities (record, name) VALUES (?, ?)`, c, c.Name); err != nil {
		if isUniqueViolation(err) {
			return Capability{}, ErrConflict
		}
		return Capability{}, err
	}
	if err = appendEvent(ctx, tx, "capability.created", c.Name, c.CreatedAt); err != nil {
		return Capability{}, err
	}
	if err = tx.Commit(); err != nil {
		return Capability{}, err
	}
	// The claims are delivered as any policy, by the delivery worker; the
	// record is answered without waiting on the coordinator.
	if len(claims) > 0 {
		s.wakePolicyDeliveries()
	}
	return s.capabilityView(ctx, s.db, c)
}

// checkClaims checks a new capability's policies: signed by one person, and
// exactly one for each network in which this host is bound to that person,
// verifying, and holding this host's rule for the name. Networks where this
// host is bound to another person gain the claim at their first share.
func (s *Store) checkClaims(ctx context.Context, r CreateCapability) ([]membership.Policy, error) {
	own, err := membershipsOf(ctx, s.db, s.identity.ID)
	if err != nil {
		return nil, err
	}
	given := map[string]membership.Policy{}
	signer := ""
	for _, p := range r.Policies {
		if _, dup := given[p.NetworkID]; dup {
			return nil, fmt.Errorf("%w: policies has more than one policy for network %s", ErrInvalid, p.NetworkID)
		}
		person := personIDOf(p.PersonPublicKey)
		if signer != "" && person != signer {
			return nil, fmt.Errorf("%w: the policies are signed by more than one person", ErrInvalid)
		}
		signer = person
		given[p.NetworkID] = p
	}
	out := []membership.Policy{}
	for _, n := range own {
		if n.member.PersonID == nil {
			continue
		}
		// Without policies, the claims of any person bound here are missing.
		if signer != "" && *n.member.PersonID != signer {
			continue
		}
		p, ok := given[n.network]
		if !ok {
			return nil, fmt.Errorf("%w: policies lacks a policy for network %s, in which this host is bound", ErrInvalid, n.network)
		}
		delete(given, n.network)
		if err := membership.VerifyPolicy(n.network, p); err != nil {
			return nil, fmt.Errorf("%w: the policy for network %s: %v", ErrInvalid, n.network, err)
		}
		claimed := false
		for _, rule := range p.CapabilityRules {
			if rule.Host == s.identity.ID && rule.Capability == r.Name {
				claimed = true
			}
		}
		if !claimed {
			return nil, fmt.Errorf("%w: the policy for network %s has no claim of %s for this host", ErrInvalid, n.network, r.Name)
		}
		out = append(out, p)
	}
	for network := range given {
		return nil, fmt.Errorf("%w: this host is not bound to the policies' person in network %s", ErrInvalid, network)
	}
	return out, nil
}

// Capabilities lists this host's capabilities, sorted by name, with their
// recipients.
func (s *Store) Capabilities(ctx context.Context) ([]CapabilityWithRecipients, error) {
	list, err := records[capabilityRecord](ctx, s.db, `SELECT record FROM capabilities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := []CapabilityWithRecipients{}
	for _, c := range list {
		view, err := s.capabilityView(ctx, s.db, c)
		if err != nil {
			return nil, err
		}
		recipients, err := s.recipients(ctx, s.db, c.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, CapabilityWithRecipients{view, recipients})
	}
	return out, nil
}

// CapabilityOf is one capability with its recipients.
func (s *Store) CapabilityOf(ctx context.Context, name string) (CapabilityWithRecipients, error) {
	c, err := readCapability(ctx, s.db, name)
	if err != nil {
		return CapabilityWithRecipients{}, err
	}
	view, err := s.capabilityView(ctx, s.db, c)
	if err != nil {
		return CapabilityWithRecipients{}, err
	}
	recipients, err := s.recipients(ctx, s.db, name)
	return CapabilityWithRecipients{view, recipients}, err
}

// ruleHeld reports whether any stored policy, of any owner and in any
// network of this host, holds this host's rule for a capability name.
func (s *Store) ruleHeld(ctx context.Context, name string) (string, bool, error) {
	networks, err := s.Networks(ctx)
	if err != nil {
		return "", false, err
	}
	for _, n := range networks {
		g, err := s.loadGovernance(ctx, s.db, n.ID)
		if err != nil {
			return "", false, err
		}
		current := g.persons()
		for _, key := range sortedKeys(g.persisted.policies) {
			p, ok := g.storedPolicy(key)
			if _, person := current[key]; !ok || !person {
				continue // a removed person's policy no longer applies
			}
			for _, r := range p.CapabilityRules {
				if r.Host == s.identity.ID && r.Capability == name {
					return n.ID, true, nil
				}
			}
		}
	}
	return "", false, nil
}

// RemoveCapability deletes a capability once no stored rule of this host's
// person shares it from this host; the CLI signs those withdrawals first.
func (s *Store) RemoveCapability(ctx context.Context, name string) (Capability, error) {
	c, err := readCapability(ctx, s.db, name)
	if err != nil {
		return Capability{}, err
	}
	if network, held, err := s.ruleHeld(ctx, name); err != nil || held {
		if err == nil {
			err = fmt.Errorf("%w: a stored policy in network %s still holds this host's rule for %s; withdraw it first", ErrConflict, network, name)
		}
		return Capability{}, err
	}
	view, err := s.capabilityView(ctx, s.db, c)
	if err != nil {
		return view, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return view, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM capabilities WHERE name = ?`, name); err != nil {
		return view, err
	}
	if err = appendEvent(ctx, tx, "capability.removed", name, timestamp(time.Now())); err != nil {
		return view, err
	}
	if err = tx.Commit(); err != nil {
		return view, err
	}
	s.retireCapability(name)
	return view, nil
}

func localCapabilityRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		var req CreateCapability
		if !decode(w, r, &req, "name", "source", "operations?", "resources?", "env_file?", "args", "policies") {
			return
		}
		c, err := store.CreateCapability(r.Context(), req)
		status := http.StatusCreated
		if errors.Is(err, errCapabilityExists) {
			status, err = http.StatusOK, nil
		}
		respond(w, status, c, err)
	})
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		list, err := store.Capabilities(r.Context())
		respond(w, http.StatusOK, map[string]any{"capabilities": list}, err)
	})
	mux.HandleFunc("GET /v1/capabilities/{name}", func(w http.ResponseWriter, r *http.Request) {
		c, err := store.CapabilityOf(r.Context(), r.PathValue("name"))
		respond(w, http.StatusOK, c, err)
	})
	mux.HandleFunc("DELETE /v1/capabilities/{name}", func(w http.ResponseWriter, r *http.Request) {
		c, err := store.RemoveCapability(r.Context(), r.PathValue("name"))
		respond(w, http.StatusOK, c, err)
	})
}
