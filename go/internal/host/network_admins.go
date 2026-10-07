package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Administrators and groups (milestone 2b, slice 2). The root delegates
// administrators, who sign everything the root may except governing the root.
// The daemon signs with the root seed when this host holds it; otherwise the
// CLI signs with the person key (or a root key) and the daemon checks the
// signer and submits the statement. The daemon never sees those keys.

const (
	kindAdmin        = "admin"         // subject: person key; the latest verified delegation
	kindAdminRemoval = "admin_removal" // subject: person key; the map's "admin" revocation kind
	kindGroup        = "group"         // subject: group name; the newest verified version
)

type dbQuerier interface {
	queryer
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// governance is this host's verified view of a network's authority: the root
// chain accepting its administrators' signatures, and the revocations that
// still apply.
type governance struct {
	network   Network
	chain     membership.Chain
	admins    membership.AdminState
	revoked   membership.Revoked
	persisted persistedStatements
}

func (s *Store) loadGovernance(ctx context.Context, q dbQuerier, id string) (governance, error) {
	var g governance
	n, err := scanNetwork(q.QueryRowContext(ctx, networkColumns+" WHERE id = ?", id))
	if err != nil {
		return g, err
	}
	g.network = n
	genesis, err := genesisOf(n)
	if err != nil {
		return g, err
	}
	if g.persisted, err = loadStatements(ctx, q, id); err != nil {
		return g, err
	}
	chain, err := membership.VerifyChain(genesis, g.persisted.rotations)
	if err != nil {
		return g, err
	}
	g.admins = chain.Administrators(rawValues[membership.AdminDelegation](g.persisted.admins), adminRemovals(g.persisted.revocations))
	g.chain = chain.WithAdminState(g.admins)
	g.revoked = verifiedRevoked(g.chain, g.persisted.revocations)
	return g, nil
}

func rawValues[T any](records map[string]json.RawMessage) []T {
	raw := make([]json.RawMessage, 0, len(records))
	for _, data := range records {
		raw = append(raw, data)
	}
	return membership.DecodeRaw[T](raw)
}

func adminRemovals(records []statementRecord) []membership.AdminRemoval {
	var out []membership.AdminRemoval
	for _, r := range records {
		var removal membership.AdminRemoval
		if r.kind == kindAdminRemoval && json.Unmarshal(r.statement, &removal) == nil {
			out = append(out, removal)
		}
	}
	return out
}

func signatureOf(statement json.RawMessage) string {
	var s struct {
		Signature string `json:"signature"`
	}
	_ = json.Unmarshal(statement, &s)
	return s.Signature
}

// revocationValid re-verifies a persisted revocation an administrator signed:
// a removal with revoke_admitted invalidates it.
func revocationValid(chain membership.Chain, r statementRecord) bool {
	if r.kind == membership.KindUnbind || r.kind == membership.KindLeave || !chain.AdminSigned(signatureOf(r.statement)) {
		return true
	}
	_, _, err := chain.VerifyRevocation(membership.Revocation{Kind: revocationKind(r.kind), Statement: r.statement})
	return err == nil
}

func verifiedRevoked(chain membership.Chain, records []statementRecord) membership.Revoked {
	revoked := membership.NewRevoked()
	for _, r := range records {
		if revocationValid(chain, r) {
			revoked.Add(revocationKind(r.kind), r.subject)
		}
	}
	return revoked
}

// persons returns valid, unremoved persons by key.
func (g governance) persons() map[string]membership.PersonProof {
	out := map[string]membership.PersonProof{}
	for key, data := range g.persisted.persons {
		var proof membership.PersonProof
		if g.revoked.Persons[key] || json.Unmarshal(data, &proof) != nil || (proof.Admission == nil) == (proof.Membership == nil) {
			continue
		}
		if verified, _, err := g.chain.VerifyPerson(proof); err != nil || verified != key {
			continue
		}
		if proof.Membership != nil && g.revoked.Invites[proof.Membership.InvitePublicKey] {
			continue
		}
		out[key] = proof
	}
	return out
}

// currentAdmins are administrators now: delegated at the current epoch, not
// removed, and valid persons.
func (g governance) currentAdmins() map[string]bool {
	persons := g.persons()
	out := map[string]bool{}
	for key := range g.admins.Current {
		if _, ok := persons[key]; ok {
			out[key] = true
		}
	}
	return out
}

// acceptKey checks that a statement handed over by the CLI is signed by the
// current root or a current administrator.
func (g governance) acceptKey(key string) error {
	if key == g.chain.CurrentPublicKey() || g.currentAdmins()[key] {
		return nil
	}
	return fmt.Errorf("%w: signer is not this network's root or a current administrator", ErrForbidden)
}

// acceptSignature is acceptKey for a statement's signature; a raw signature
// can only be a root's, which the statement's verification then checks.
func (g governance) acceptSignature(signature string) error {
	signer := membership.SignerOf(signature)
	if signer == "" {
		return nil
	}
	return g.acceptKey(signer)
}

// signerValid reports whether a stored invite or admission's signer is still
// accepted.
func (g governance) memberSignerValid(m NetworkMember) bool {
	switch {
	case m.Membership != nil:
		return g.chain.SignerValid(m.Membership.InviteMessage(), m.Membership.InviteSignature)
	case m.Admission != nil:
		return g.chain.SignerValid(m.Admission.Message(), m.Admission.Signature)
	}
	return true
}

// Fingerprint is the OpenSSH SHA256 fingerprint of a person key.
func Fingerprint(key string) string {
	public, err := membership.DecodeKey(key)
	if err != nil {
		return ""
	}
	line := membership.SSHAuthorizedKey(public)
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ResolvePerson finds one person by person ID, public key (Base64 or an
// ssh-ed25519 line), or label, failing on an unknown or ambiguous label.
func ResolvePerson(persons []Person, given string) (Person, error) {
	key, _ := membership.NormalizePersonKey(given)
	for _, p := range persons {
		if p.PersonID == given || p.PublicKey == given || (key != "" && p.PublicKey == key) {
			return p, nil
		}
	}
	var matches []Person
	for _, p := range persons {
		if membership.LabelsConflict(p.Member, given) {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return Person{}, fmt.Errorf("%w: no current person %q", ErrNotFound, given)
	case 1:
		return matches[0], nil
	}
	names := make([]string, len(matches))
	for i, p := range matches {
		names[i] = fmt.Sprintf("%s (%s, %s)", p.Member, p.PersonID, Fingerprint(p.PublicKey))
	}
	return Person{}, fmt.Errorf("%w: label %q is ambiguous; give a person ID: %s", ErrInvalid, given, strings.Join(names, ", "))
}

// applyAdmins verifies the served and persisted delegations and removals and
// makes a.chain accept the administrators' signatures.
func (a *appliedMap) applyAdmins(persisted persistedStatements, m membership.Map) {
	removals := adminRemovals(persisted.revocations)
	for _, raw := range m.Revocations {
		var entry membership.Revocation
		var r membership.AdminRemoval
		if json.Unmarshal(raw, &entry) == nil && entry.Kind == membership.KindAdmin && json.Unmarshal(entry.Statement, &r) == nil {
			removals = append(removals, r)
		}
	}
	delegations := append(rawValues[membership.AdminDelegation](persisted.admins), membership.DecodeRaw[membership.AdminDelegation](m.Admins)...)
	a.admins = a.chain.Administrators(delegations, removals)
	a.chain = a.chain.WithAdminState(a.admins)
}

// applyGroups keeps the highest valid version of each group, persisted or
// served. A persisted version whose signer was removed with revoke_admitted
// no longer verifies, so the group reverts to the newest still valid.
func (a *appliedMap) applyGroups(persisted persistedStatements, m membership.Map) {
	groups := append(rawValues[membership.GroupDefinition](persisted.groups), membership.DecodeRaw[membership.GroupDefinition](m.Groups)...)
	a.groups = a.chain.NewestGroups(groups)
}

// rootSSH reports whether the current root signs with SSHSIG, as seen in any
// current statement it signed.
func (a appliedMap) rootSSH() bool {
	current := a.chain.CurrentPublicKey()
	byRoot := func(signature string) bool { return membership.SignerOf(signature) == current }
	for _, at := range a.attestations {
		if at.Epoch == a.chain.Epoch() && byRoot(at.Signature) {
			return true
		}
	}
	for _, d := range a.admins.Delegations {
		if byRoot(d.Signature) {
			return true
		}
	}
	for _, p := range a.persons {
		if p.Admission != nil && byRoot(p.Admission.Signature) {
			return true
		}
	}
	for _, m := range a.members {
		if m.Admission != nil && byRoot(m.Admission.Signature) {
			return true
		}
	}
	for _, g := range a.groups {
		if byRoot(g.Signature) {
			return true
		}
	}
	return false
}

func putRecord(ctx context.Context, tx *sql.Tx, network, kind, subject string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO network_statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET record = excluded.record", network, kind, subject, string(data))
	return err
}

// persistAdmins stores verified delegations (removed administrators'
// included, as their statements may stay valid), removals, and the newest
// version of each group, recording events for changes.
func (s *Store) persistAdmins(ctx context.Context, tx *sql.Tx, network string, a appliedMap, now string) error {
	stored, err := loadStatements(ctx, tx, network)
	if err != nil {
		return err
	}
	for _, key := range sortedKeys(a.admins.Delegations) {
		d := a.admins.Delegations[key]
		data, err := json.Marshal(d)
		if err != nil {
			return err
		}
		previous, had := stored.admins[key]
		if had && membership.EqualRaw(previous, data) {
			continue
		}
		if err = putRecord(ctx, tx, network, kindAdmin, key, d); err != nil {
			return err
		}
		if !had {
			if err = appendEvent(ctx, tx, "network.admin_delegated", personIDOf(key), now); err != nil {
				return err
			}
		}
	}
	storedRemovals := map[string]membership.AdminRemoval{}
	for _, r := range adminRemovals(stored.revocations) {
		storedRemovals[r.PersonPublicKey] = r
	}
	for _, key := range sortedKeys(a.admins.Removals) {
		if err = s.putAdminRemoval(ctx, tx, network, storedRemovals, a.admins.Removals[key], now); err != nil {
			return err
		}
	}
	previous := map[string]membership.GroupDefinition{}
	for name, data := range stored.groups {
		var g membership.GroupDefinition
		if json.Unmarshal(data, &g) == nil {
			previous[name] = g
		}
	}
	for _, name := range sortedKeys(previous) {
		if _, ok := a.groups[name]; ok {
			continue
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM network_statements WHERE network_id = ? AND kind = ? AND subject = ?", network, kindGroup, name); err != nil {
			return err
		}
		if err = appendEvent(ctx, tx, "network.group_updated", name, now); err != nil {
			return err
		}
	}
	for _, name := range sortedKeys(a.groups) {
		g := a.groups[name]
		old, had := previous[name]
		if had && old.Version == g.Version && old.Signature == g.Signature {
			continue
		}
		if err = putRecord(ctx, tx, network, kindGroup, name, g); err != nil {
			return err
		}
		if had && old.Version == g.Version && strings.Join(old.Members, " ") == strings.Join(g.Members, " ") {
			continue // renewed by a new root: the same version
		}
		if err = appendEvent(ctx, tx, "network.group_updated", name, now); err != nil {
			return err
		}
	}
	return nil
}

// putAdminRemoval stores one removal per key; a later one with
// revoke_admitted escalates one without. Any other is ignored. It updates
// stored.
func (s *Store) putAdminRemoval(ctx context.Context, tx *sql.Tx, network string, stored map[string]membership.AdminRemoval, r membership.AdminRemoval, now string) error {
	if previous, had := stored[r.PersonPublicKey]; had && (previous.RevokeAdmitted || !r.RevokeAdmitted) {
		return nil
	}
	if err := putRecord(ctx, tx, network, kindAdminRemoval, r.PersonPublicKey, r); err != nil {
		return err
	}
	stored[r.PersonPublicKey] = r
	return appendEvent(ctx, tx, "network.admin_removed", personIDOf(r.PersonPublicKey), now)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// DelegateAdmin is {person} for this host to sign with the root seed, or a
// root-signed {delegation} from the CLI.
type DelegateAdmin struct {
	Person     string                      `json:"person,omitempty"`
	Delegation *membership.AdminDelegation `json:"delegation,omitempty"`
}
type Delegated struct {
	NetworkID string `json:"network_id"`
	PersonID  string `json:"person_id"`
}

// RemoveAdmin is {person, revoke_admitted} for this host to sign, or a
// root-signed {removal}.
type RemoveAdmin struct {
	Person         string                   `json:"person,omitempty"`
	RevokeAdmitted bool                     `json:"revoke_admitted,omitempty"`
	Removal        *membership.AdminRemoval `json:"removal,omitempty"`
}

// SetGroup is {name, members} for this host to sign the next version with
// the root seed, or a signed {group} from the CLI.
type SetGroup struct {
	Name    string                      `json:"name,omitempty"`
	Members []string                    `json:"members,omitempty"`
	Group   *membership.GroupDefinition `json:"group,omitempty"`
}

// Group is a group as `network groups` shows it. Members that are not current
// persons are omitted; signer is the signing key.
type Group struct {
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	Members []string `json:"members"`
	Signer  string   `json:"signer"`
}

// personsOf lists the governance's valid persons for resolution.
func (g governance) personList() []Person {
	var out []Person
	for key, proof := range g.persons() {
		out = append(out, Person{PersonID: personIDOf(key), PublicKey: key, Member: personLabel(proof)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PersonID < out[j].PersonID })
	return out
}

// resolveAny resolves a person among valid persons, then among delegated
// keys, so a removed person can still be removed as administrator.
func (g governance) resolveAny(given string) (string, error) {
	p, err := ResolvePerson(g.personList(), given)
	if err == nil || !errors.Is(err, ErrNotFound) {
		return p.PublicKey, err
	}
	for key := range g.admins.Delegations {
		if personIDOf(key) == given || key == given {
			return key, nil
		}
	}
	return "", err
}

func (s *Store) DelegateAdmin(ctx context.Context, id string, r DelegateAdmin) (Delegated, error) {
	if (r.Person == "") == (r.Delegation == nil) {
		return Delegated{}, fmt.Errorf("%w: give exactly one of person or delegation", ErrInvalid)
	}
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return Delegated{}, err
	}
	n := g.network
	var d membership.AdminDelegation
	if r.Delegation != nil {
		d = *r.Delegation
		if _, err = g.chain.VerifyDelegation(d); err != nil || d.Epoch != g.chain.Epoch() {
			return Delegated{}, fmt.Errorf("%w: delegation is not signed by the current root at the current epoch", ErrForbidden)
		}
	} else {
		_, root, err := s.administeredNetwork(ctx, s.db, id)
		if err != nil {
			return Delegated{}, err
		}
		p, err := ResolvePerson(g.personList(), r.Person)
		if err != nil {
			return Delegated{}, err
		}
		if d, err = membership.SignAdminDelegation(membership.RawSigner{Key: root}, n.ID, g.chain.Epoch(), p.PublicKey, timestamp(time.Now())); err != nil {
			return Delegated{}, err
		}
	}
	if _, ok := g.persons()[d.PersonPublicKey]; !ok {
		return Delegated{}, fmt.Errorf("%w: person is not admitted to this network", ErrNotFound)
	}
	if _, removed := g.admins.Removals[d.PersonPublicKey]; removed {
		return Delegated{}, fmt.Errorf("%w: administrator removal is permanent for this key", ErrConflict)
	}
	if _, err = s.callCoordinator(ctx, n, networkPath(n, "/admins"), map[string]any{"delegation": d}); err != nil {
		return Delegated{}, err
	}
	if _, err = s.SyncNetwork(ctx, id); err != nil {
		return Delegated{}, err
	}
	return Delegated{NetworkID: n.ID, PersonID: personIDOf(d.PersonPublicKey)}, nil
}

// RemoveAdmin is sticky and local-first, like a revocation: the removal is
// enforced here at once and resubmitted until the coordinator serves it.
func (s *Store) RemoveAdmin(ctx context.Context, id string, r RemoveAdmin) (RevocationResult, error) {
	if (r.Person == "") == (r.Removal == nil) || (r.Removal != nil && r.RevokeAdmitted) {
		return RevocationResult{}, fmt.Errorf("%w: give exactly one of person or removal", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RevocationResult{}, err
	}
	defer tx.Rollback()
	g, err := s.loadGovernance(ctx, tx, id)
	if err != nil {
		return RevocationResult{}, err
	}
	var removal membership.AdminRemoval
	if r.Removal != nil {
		removal = *r.Removal
		if err = g.chain.VerifyAdminRemoval(removal); err != nil {
			return RevocationResult{}, fmt.Errorf("%w: removal is not signed by this network's root", ErrForbidden)
		}
	} else {
		_, root, err := s.administeredNetwork(ctx, tx, id)
		if err != nil {
			return RevocationResult{}, err
		}
		key, err := g.resolveAny(r.Person)
		if err != nil {
			return RevocationResult{}, err
		}
		var kept []string
		if !r.RevokeAdmitted {
			if kept, err = s.keptDigests(ctx, tx, g, key); err != nil {
				return RevocationResult{}, err
			}
		}
		if removal, err = membership.SignAdminRemoval(membership.RawSigner{Key: root}, id, key, r.RevokeAdmitted, kept, timestamp(time.Now())); err != nil {
			return RevocationResult{}, err
		}
	}
	if _, delegated := g.admins.Delegations[removal.PersonPublicKey]; !delegated {
		return RevocationResult{}, fmt.Errorf("%w: that person is not an administrator", ErrNotFound)
	}
	// One removal per key; revoke_admitted may escalate a plain one.
	if previous, removed := g.admins.Removals[removal.PersonPublicKey]; removed && (previous.RevokeAdmitted || !removal.RevokeAdmitted) {
		return RevocationResult{}, fmt.Errorf("%w: this administrator has already been removed", ErrConflict)
	}
	stored := map[string]membership.AdminRemoval{}
	for key, previous := range g.admins.Removals {
		stored[key] = previous
	}
	now := timestamp(time.Now())
	if err = s.putAdminRemoval(ctx, tx, id, stored, removal, now); err != nil {
		return RevocationResult{}, err
	}
	if err = s.dropExcludedMembers(ctx, tx, id, now); err != nil {
		return RevocationResult{}, err
	}
	if err = s.endBindings(ctx, tx, id, now); err != nil {
		return RevocationResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return RevocationResult{}, err
	}
	statement, err := json.Marshal(removal)
	if err != nil {
		return RevocationResult{}, err
	}
	_, submitErr := s.callCoordinator(ctx, g.network, networkPath(g.network, "/admin-removals"), map[string]any{"statement": json.RawMessage(statement)})
	return RevocationResult{NetworkID: id, Kind: membership.KindAdmin, Subject: removal.PersonPublicKey, Submitted: submitErr == nil}, nil
}

// storedGroup returns the newest version of a group this host has verified,
// deleted or not.
func (g governance) storedGroup(name string) (membership.GroupDefinition, bool) {
	var group membership.GroupDefinition
	data, ok := g.persisted.groups[name]
	if !ok || json.Unmarshal(data, &group) != nil {
		return group, false
	}
	if _, err := g.chain.VerifyGroup(group); err != nil {
		return group, false
	}
	return group, true
}

func (s *Store) SetGroup(ctx context.Context, id string, r SetGroup) (Group, error) {
	if (r.Group == nil) == (r.Name == "") || (r.Group != nil && len(r.Members) != 0) {
		return Group{}, fmt.Errorf("%w: give name and members, or group", ErrInvalid)
	}
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return Group{}, err
	}
	n := g.network
	var group membership.GroupDefinition
	if r.Group != nil {
		group = *r.Group
		if _, err = g.chain.VerifyGroup(group); err != nil {
			return Group{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if err = g.acceptSignature(group.Signature); err != nil {
			return Group{}, err
		}
	} else {
		_, root, err := s.administeredNetwork(ctx, s.db, id)
		if err != nil {
			return Group{}, err
		}
		if !membership.ValidGroupName(r.Name) {
			return Group{}, fmt.Errorf("%w: group names are 1-64 lowercase letters, digits, '.', '_', and '-'", ErrInvalid)
		}
		persons := g.personList()
		ids := make([]string, 0, len(r.Members))
		for _, given := range r.Members {
			p, err := ResolvePerson(persons, given)
			if err != nil {
				return Group{}, err
			}
			ids = append(ids, p.PersonID)
		}
		version := int64(1)
		if previous, ok := g.storedGroup(r.Name); ok {
			version = previous.Version + 1
		}
		if group, err = membership.SignGroup(membership.RawSigner{Key: root}, n.ID, r.Name, version, ids, timestamp(time.Now())); err != nil {
			return Group{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	if previous, ok := g.storedGroup(group.Name); ok && group.Version <= previous.Version {
		return Group{}, fmt.Errorf("%w: group %s is already at version %d", ErrConflict, group.Name, previous.Version)
	}
	if _, err = s.callCoordinator(ctx, n, networkPath(n, "/groups"), map[string]any{"group": group}); err != nil {
		return Group{}, err
	}
	if _, err = s.SyncNetwork(ctx, id); err != nil {
		return Group{}, err
	}
	return groupView(g.chain, group, nil), nil
}

func groupView(chain membership.Chain, group membership.GroupDefinition, persons map[string]bool) Group {
	signer := membership.SignerOf(group.Signature)
	if signer == "" {
		signer, _ = chain.VerifySigned(group.Message(), group.Signature)
	}
	members := []string{}
	for _, member := range group.Members {
		if persons == nil || persons[member] {
			members = append(members, member)
		}
	}
	return Group{Name: group.Name, Version: group.Version, Members: members, Signer: signer}
}

// Groups lists current groups by name; with all, deleted groups too, so an
// administrator signing through the CLI can choose the next version.
func (s *Store) Groups(ctx context.Context, id string, all bool) ([]Group, error) {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	persons := map[string]bool{}
	for key := range g.persons() {
		persons[personIDOf(key)] = true
	}
	out := []Group{}
	for _, name := range sortedKeys(g.persisted.groups) {
		group, ok := g.storedGroup(name)
		if !ok || (len(group.Members) == 0 && !all) {
			continue
		}
		out = append(out, groupView(g.chain, group, persons))
	}
	return out, nil
}

func localAdminRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/networks/{id}/admins", func(w http.ResponseWriter, r *http.Request) {
		var req DelegateAdmin
		if !decode(w, r, &req, "person", "delegation") {
			return
		}
		result, err := store.DelegateAdmin(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/admin-removals", func(w http.ResponseWriter, r *http.Request) {
		var req RemoveAdmin
		if !decode(w, r, &req, "person", "revoke_admitted", "removal") {
			return
		}
		result, err := store.RemoveAdmin(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/groups", func(w http.ResponseWriter, r *http.Request) {
		var req SetGroup
		if !decode(w, r, &req, "name", "members", "group") {
			return
		}
		result, err := store.SetGroup(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("GET /v1/networks/{id}/groups", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.Groups(r.Context(), r.PathValue("id"), r.URL.Query().Get("all") == "true")
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("GET /v1/networks/{id}/admin-removal-plan", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.AdminRemovalPlan(r.Context(), r.PathValue("id"), r.URL.Query().Get("person"))
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("GET /v1/networks/{id}/rotation-plan", func(w http.ResponseWriter, r *http.Request) {
		// The plan covers the coordinator's current members.
		if _, err := store.SyncNetwork(r.Context(), r.PathValue("id")); err != nil {
			respond(w, 0, nil, err)
			return
		}
		result, err := store.RotationPlan(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, result, err)
	})
}

// RotationPlan lists what a new root must sign at the next epoch: attestations
// for members whose invite a root signed, renewals of root-signed host and
// person admissions, and delegations of current administrators. Statements
// administrators signed stay valid and are not renewed.
type RotationPlan struct {
	NetworkID            string        `json:"network_id"`
	Epoch                int64         `json:"epoch"`
	CurrentRootPublicKey string        `json:"current_root_public_key"`
	Attestations         []PlannedItem `json:"attestations"`
	HostAdmissions       []PlannedItem `json:"host_admissions"`
	PersonAdmissions     []PlannedItem `json:"person_admissions"`
	Admins               []string      `json:"admins"`
	// Groups are the root-signed groups, renewed at the same version.
	Groups []PlannedGroup `json:"groups"`
}
type PlannedGroup struct {
	Name    string   `json:"name"`
	Version int64    `json:"version"`
	Members []string `json:"members"`
}
type PlannedItem struct {
	PublicKey string `json:"public_key"`
	Member    string `json:"member"`
}

func (s *Store) RotationPlan(ctx context.Context, id string) (RotationPlan, error) {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return RotationPlan{}, err
	}
	// The coordinator requires coverage of its current members, so pending
	// local revocations are submitted first.
	pending := []statementRecord{}
	for _, r := range g.persisted.revocations {
		if r.kind != membership.KindLeave && revocationValid(g.chain, r) {
			pending = append(pending, r)
		}
	}
	s.submitMissingRevocations(ctx, g.network, pending)
	members, err := s.NetworkMembers(ctx, id)
	if err != nil {
		return RotationPlan{}, err
	}
	plan := RotationPlan{NetworkID: id, Epoch: g.chain.Epoch() + 1, CurrentRootPublicKey: g.chain.CurrentPublicKey(), Attestations: []PlannedItem{}, HostAdmissions: []PlannedItem{}, PersonAdmissions: []PlannedItem{}, Admins: []string{}}
	for _, member := range members {
		if member.Membership != nil && !g.chain.AdminSigned(member.Membership.InviteSignature) {
			plan.Attestations = append(plan.Attestations, PlannedItem{member.PublicKey, member.Membership.Member})
		}
	}
	// Root-signed host admissions still valid at the current epoch, joined or not.
	for _, key := range sortedKeys(g.persisted.hostAdmissions) {
		var a membership.HostAdmission
		if json.Unmarshal(g.persisted.hostAdmissions[key], &a) != nil || g.revoked.ExcludesHost(a.HostPublicKey, "") || g.chain.AdminSigned(a.Signature) {
			continue
		}
		if _, err = g.chain.VerifyHostAdmission(a); err == nil {
			plan.HostAdmissions = append(plan.HostAdmissions, PlannedItem{a.HostPublicKey, a.Member})
		}
	}
	persons := g.persons()
	for _, key := range sortedKeys(persons) {
		proof := persons[key]
		signature := ""
		if proof.Admission != nil {
			signature = proof.Admission.Signature
		} else {
			signature = proof.Membership.InviteSignature
		}
		if !g.chain.AdminSigned(signature) {
			plan.PersonAdmissions = append(plan.PersonAdmissions, PlannedItem{key, personLabel(proof)})
		}
	}
	plan.Admins = append(plan.Admins, sortedKeys(g.currentAdmins())...)
	plan.Groups = []PlannedGroup{}
	for _, name := range sortedKeys(g.persisted.groups) {
		if group, ok := g.storedGroup(name); ok && !g.chain.AdminSigned(group.Signature) {
			plan.Groups = append(plan.Groups, PlannedGroup{group.Name, group.Version, group.Members})
		}
	}
	return plan, nil
}

// SignedPlan is a rotation plan signed by the new root.
type SignedPlan struct {
	Attestations []membership.Attestation
	Admissions   []json.RawMessage
	Groups       []membership.GroupDefinition
}

// SignRotationPlan signs a plan's statements with the new root; the CLI uses
// it for a root it holds.
func SignRotationPlan(plan RotationPlan, next membership.StatementSigner, at string) (SignedPlan, error) {
	out := SignedPlan{Attestations: []membership.Attestation{}, Admissions: []json.RawMessage{}, Groups: []membership.GroupDefinition{}}
	add := func(v any, err error) error {
		if err != nil {
			return err
		}
		data, err := json.Marshal(v)
		out.Admissions = append(out.Admissions, data)
		return err
	}
	for _, item := range plan.Attestations {
		a, err := membership.SignAttestationWith(next, plan.NetworkID, plan.Epoch, item.PublicKey, item.Member, at)
		if err != nil {
			return out, err
		}
		out.Attestations = append(out.Attestations, a)
	}
	for _, item := range plan.HostAdmissions {
		if err := add(membership.SignHostAdmissionWith(next, plan.NetworkID, plan.Epoch, item.PublicKey, item.Member, at)); err != nil {
			return out, err
		}
	}
	for _, item := range plan.PersonAdmissions {
		if err := add(membership.SignPersonAdmissionWith(next, plan.NetworkID, plan.Epoch, item.PublicKey, item.Member, at)); err != nil {
			return out, err
		}
	}
	for _, key := range plan.Admins {
		if err := add(membership.SignAdminDelegation(next, plan.NetworkID, plan.Epoch, key, at)); err != nil {
			return out, err
		}
	}
	for _, item := range plan.Groups {
		g, err := membership.SignGroup(next, plan.NetworkID, item.Name, item.Version, item.Members, at)
		if err != nil {
			return out, err
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}

// RotateRoot is a rotation to a root the CLI holds: everything the new root
// signs, and the rotation itself unless this host signs it with the root seed.
type RotateRoot struct {
	RootPublicKey string                       `json:"root_public_key"`
	Rotation      *membership.Rotation         `json:"rotation,omitempty"`
	Attestations  []membership.Attestation     `json:"attestations"`
	Admissions    []json.RawMessage            `json:"admissions"`
	Groups        []membership.GroupDefinition `json:"groups"`
}

// rotateToKey verifies a rotation to a root this host will not hold, persists
// it as pending with no seed, and submits it.
func (s *Store) rotateToKey(ctx context.Context, id string, r RotateRoot) (Network, error) {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return Network{}, err
	}
	n := g.network
	next, err := membership.DecodeKey(r.RootPublicKey)
	if err != nil {
		return n, fmt.Errorf("%w: root_public_key must be canonical Base64", ErrInvalid)
	}
	epoch := g.chain.Epoch() + 1
	var rotation membership.Rotation
	if r.Rotation != nil {
		rotation = *r.Rotation
	} else {
		_, current, err := s.administeredNetwork(ctx, s.db, id)
		if err != nil {
			return n, err
		}
		rotation = membership.SignRotation(current, id, epoch, next, timestamp(time.Now()))
	}
	nextChain, err := membership.VerifyChain(g.chain.Roots[0], append(append([]membership.Rotation{}, g.chain.Rotations...), rotation))
	if err != nil || rotation.Epoch != epoch || !nextChain.Current().Equal(next) {
		return n, fmt.Errorf("%w: rotation is not signed by the current root to that key", ErrForbidden)
	}
	for _, a := range r.Attestations {
		if err = nextChain.VerifyAttestation(a); err != nil {
			return n, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	for _, data := range r.Admissions {
		if err = verifyRenewal(nextChain, data); err != nil {
			return n, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	for _, group := range r.Groups {
		if signer, err := nextChain.VerifyGroup(group); err != nil || signer != nextChain.CurrentPublicKey() {
			return n, fmt.Errorf("%w: group renewals must be signed by the new root", ErrInvalid)
		}
	}
	p := &pendingRotation{Rotation: rotation, Attestations: r.Attestations, Admissions: r.Admissions, Groups: r.Groups}
	if p.Attestations == nil {
		p.Attestations = []membership.Attestation{}
	}
	if p.Admissions == nil {
		p.Admissions = []json.RawMessage{}
	}
	if p.Groups == nil {
		p.Groups = []membership.GroupDefinition{}
	}
	data, err := json.Marshal(p)
	if err != nil {
		return n, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return n, err
	}
	defer tx.Rollback()
	if err = putStatementRecord(ctx, tx, id, statementRecord{kindPendingRotation, fmt.Sprint(epoch), data}); err != nil {
		return n, err
	}
	if err = tx.Commit(); err != nil {
		return n, err
	}
	return s.completeRotation(ctx, n, p)
}

// verifyRenewal checks one statement a new root signs at a rotation: a host
// or person admission, or a delegation.
func verifyRenewal(next membership.Chain, data json.RawMessage) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	switch {
	case fields["delegated_at"] != nil:
		var d membership.AdminDelegation
		if err := json.Unmarshal(data, &d); err != nil {
			return err
		}
		if d.Epoch != next.Epoch() {
			return errors.New("delegation is not at the new epoch")
		}
		_, err := next.VerifyDelegation(d)
		return err
	case fields["host_public_key"] != nil:
		var a membership.HostAdmission
		if err := json.Unmarshal(data, &a); err != nil {
			return err
		}
		_, err := next.VerifyHostAdmission(a)
		return err
	default:
		var a membership.PersonAdmission
		if err := json.Unmarshal(data, &a); err != nil {
			return err
		}
		return next.VerifyPersonAdmission(a)
	}
}

// recordSignedInvite records an invite an administrator (or a root key held
// by the CLI) signed: a host-only, member, or person invite token for this
// network at the current epoch.
func (s *Store) recordSignedInvite(ctx context.Context, id string, r CreateInvite) (Invite, error) {
	if r.Member != "" || r.ExpiresAt != "" || r.HostOnly {
		return Invite{}, fmt.Errorf("%w: give a token or a member and expiration, not both", ErrInvalid)
	}
	now := time.Now()
	var host *membership.Token
	var person *membership.PersonToken
	var err error
	switch {
	case strings.HasPrefix(r.Token, membership.MemberTokenPrefix):
		var t membership.MemberToken
		if t, err = membership.DecodeMemberToken(r.Token, now); err == nil {
			p := t.PersonToken()
			host, person = &t.Token, &p
		}
	case strings.HasPrefix(r.Token, membership.PersonTokenPrefix):
		var t membership.PersonToken
		if t, err = membership.DecodePersonToken(r.Token, now); err == nil {
			person = &t
		}
	default:
		var t membership.Token
		if t, err = membership.DecodeToken(r.Token, now); err == nil {
			host = &t
		}
	}
	if err != nil {
		return Invite{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	token := host
	if token == nil {
		token = &person.Token
	}
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return Invite{}, err
	}
	if token.NetworkID != id {
		return Invite{}, fmt.Errorf("%w: the invite is for a different network", ErrInvalid)
	}
	if err = g.acceptKey(token.RootPublicKey); err != nil {
		return Invite{}, err
	}
	if host != nil {
		if _, err = g.chain.VerifySigned(membership.InviteStatement(id, host.InvitePublicKey, host.Member, host.InviteExpiresAt), host.InviteSignature); err != nil {
			return Invite{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	if person != nil {
		if person.InviteEpoch != g.chain.Epoch() {
			return Invite{}, fmt.Errorf("%w: the invite is not at the current epoch", ErrInvalid)
		}
		if _, err = g.chain.VerifySigned(membership.PersonInviteStatement(id, person.InviteEpoch, person.InvitePublicKey, person.Member, person.InviteExpiresAt), person.InviteSignature); err != nil {
			return Invite{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if host == nil {
			if err = s.labelTaken(ctx, id, person.Member, ""); err != nil {
				return Invite{}, err
			}
		}
	}
	if expires, _ := parseTime(token.InviteExpiresAt); expires.After(now.Add(30 * 24 * time.Hour)) {
		return Invite{}, fmt.Errorf("%w: invite expiration must be in the next 30 days", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invite{}, err
	}
	defer tx.Rollback()
	if err = appendEvent(ctx, tx, "network.invite_issued", id, timestamp(now)); err != nil {
		return Invite{}, err
	}
	return Invite{NetworkID: id, Member: token.Member, InvitePublicKey: token.InvitePublicKey, InviteExpiresAt: token.InviteExpiresAt, Token: r.Token}, tx.Commit()
}

// keptDigests lists the digests of every statement this host has verified as
// signed by the administrator key: members' invites and admissions, stored
// host admissions, persons' admissions and invites, revocations, and the
// newest group versions. A removal without revoke_admitted keeps exactly these.
func (s *Store) keptDigests(ctx context.Context, q dbQuerier, g governance, key string) ([]string, error) {
	digests := map[string]bool{}
	add := func(message []byte, signature string) {
		if membership.SignerOf(signature) != key {
			return
		}
		if signer, err := g.chain.VerifySigned(message, signature); err == nil && signer == key {
			digests[membership.StatementDigest(message)] = true
		}
	}
	rows, err := q.QueryContext(ctx, "SELECT record FROM network_members WHERE network_id = ?", g.network.ID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		m, err := readJSON[NetworkMember](rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if m.Membership != nil {
			add(m.Membership.InviteMessage(), m.Membership.InviteSignature)
		}
		if m.Admission != nil {
			add(m.Admission.Message(), m.Admission.Signature)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for _, data := range g.persisted.hostAdmissions {
		var a membership.HostAdmission
		if json.Unmarshal(data, &a) == nil {
			add(a.Message(), a.Signature)
		}
	}
	for _, proof := range g.persons() {
		if a := proof.Admission; a != nil {
			add(a.Message(), a.Signature)
		} else if m := proof.Membership; m != nil {
			add(membership.PersonInviteStatement(m.NetworkID, m.InviteEpoch, m.InvitePublicKey, m.Member, m.InviteExpiresAt), m.InviteSignature)
		}
	}
	for _, r := range g.persisted.revocations {
		switch r.kind {
		case membership.KindHost:
			var v membership.HostRevocation
			if json.Unmarshal(r.statement, &v) == nil {
				add(v.Message(), v.Signature)
			}
		case membership.KindInvite:
			var v membership.InviteRevocation
			if json.Unmarshal(r.statement, &v) == nil {
				add(v.Message(), v.Signature)
			}
		case kindPersonRemoval:
			var v membership.PersonRemoval
			if json.Unmarshal(r.statement, &v) == nil {
				add(v.Message(), v.Signature)
			}
		}
	}
	for name := range g.persisted.groups {
		if group, ok := g.storedGroup(name); ok {
			add(group.Message(), group.Signature)
		}
	}
	return sortedKeys(digests), nil
}

// AdminRemovalPlan is what a removal without revoke_admitted keeps, for the
// CLI to sign with --root-key.
type AdminRemovalPlan struct {
	PersonPublicKey string   `json:"person_public_key"`
	Kept            []string `json:"kept"`
}

func (s *Store) AdminRemovalPlan(ctx context.Context, id, person string) (AdminRemovalPlan, error) {
	g, err := s.loadGovernance(ctx, s.db, id)
	if err != nil {
		return AdminRemovalPlan{}, err
	}
	key, err := g.resolveAny(person)
	if err != nil {
		return AdminRemovalPlan{}, err
	}
	kept, err := s.keptDigests(ctx, s.db, g, key)
	return AdminRemovalPlan{PersonPublicKey: key, Kept: kept}, err
}

// refuseAdminRemoval refuses removing a person who is a current
// administrator: their administrator role must be removed first, so what
// happens to their statements is explicit.
func (g governance) refuseAdminRemoval(personKey string) error {
	if g.currentAdmins()[personKey] {
		return fmt.Errorf("%w: that person is a current administrator; remove the administrator role first with network remove-admin", ErrConflict)
	}
	return nil
}
