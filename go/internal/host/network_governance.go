package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Signed revocation, leaving, and root rotation (milestone 2a). Hosts persist
// every verified statement and keep enforcing revocations even when a
// coordinator omits them or serves an older map.

const (
	kindRotation        = "rotation"
	kindAttestation     = "attestation"
	kindPendingRotation = "pending_rotation"
	// Persons and host binding: admissions and bindings are not revocations.
	kindPersonStatement = "person"         // subject: person key; a PersonProof
	kindHostAdmission   = "host_admission" // subject: host key
	kindBinding         = "binding"        // subject: host key
	// A member's join statement, kept after the member is dropped so a
	// host that joined through a root-revoked invite can still be named
	// by host ID (retired policy edits entries).
	kindMembership = "membership" // subject: host key
	// A person removal is stored apart from the "person" admission kind; it
	// is the "person" kind in a map's revocations.
	kindPersonRemoval = "person_removal"
)

// revocationKind maps a stored revocation kind to its map kind, and back.
func revocationKind(stored string) string {
	switch stored {
	case kindPersonRemoval:
		return membership.KindPerson
	case kindAdminRemoval:
		return membership.KindAdmin
	}
	return stored
}
func storedKind(kind string) string {
	switch kind {
	case membership.KindPerson:
		return kindPersonRemoval
	case membership.KindAdmin:
		return kindAdminRemoval
	}
	return kind
}

// pendingRotation is a signed rotation persisted before it is submitted, so a
// crash after the coordinator accepts it cannot lose the new root seed. The
// old root stays current locally until the coordinator accepts.
type pendingRotation struct {
	Rotation     membership.Rotation      `json:"rotation"`
	Attestations []membership.Attestation `json:"attestations"`
	// Admissions re-sign, under the new root, every root-signed host and
	// person admission and every current administrator's delegation.
	Admissions []json.RawMessage `json:"admissions"`
	// RootSeed is empty for a rotation to a root this host does not hold,
	// such as an SSH key.
	RootSeed string `json:"root_seed"`
	// Groups renew root-signed groups at the same version.
	Groups []membership.GroupDefinition `json:"groups,omitempty"`
}

type statementRecord struct {
	kind, subject string
	statement     json.RawMessage
}

type persistedStatements struct {
	rotations      []membership.Rotation
	attestations   []json.RawMessage
	revocations    []statementRecord // kinds as stored
	persons        map[string]json.RawMessage
	hostAdmissions map[string]json.RawMessage
	admins         map[string]json.RawMessage // delegations by person key
	groups         map[string]json.RawMessage // newest version by name
	policies       map[string]json.RawMessage // newest version by owner key
	move           json.RawMessage            // the latest valid move held, or nil
}

// appliedMap is a verified map: valid members under the root chain, plus the
// statements to persist and the local revocations the coordinator lacks.
type appliedMap struct {
	chain         membership.Chain
	previousEpoch int64
	members       []NetworkMember
	attestations  []membership.Attestation
	revocations   []statementRecord // stored kinds
	missing       []statementRecord // stored kinds
	persons       map[string]membership.PersonProof
	bindings      map[string]membership.HostBinding // by host key
	admins        membership.AdminState
	groups        map[string]membership.GroupDefinition
	policies      map[string]membership.Policy // by owner key
	// move is the map's move when valid under this view, or nil.
	move *membership.Move
	// lacking reports that the map lacks a signed statement this host holds,
	// which a repair import re-submits.
	lacking bool
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadStatements(ctx context.Context, q queryer, network string) (persistedStatements, error) {
	p := persistedStatements{persons: map[string]json.RawMessage{}, hostAdmissions: map[string]json.RawMessage{}, admins: map[string]json.RawMessage{}, groups: map[string]json.RawMessage{}, policies: map[string]json.RawMessage{}}
	rows, err := q.QueryContext(ctx, "SELECT kind, subject, record FROM network_statements WHERE network_id = ?", network)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var r statementRecord
		var record string
		if err = rows.Scan(&r.kind, &r.subject, &record); err != nil {
			return p, err
		}
		r.statement = json.RawMessage(record)
		switch r.kind {
		case kindRotation:
			var rotation membership.Rotation
			if err = json.Unmarshal(r.statement, &rotation); err != nil {
				return p, err
			}
			p.rotations = append(p.rotations, rotation)
		case kindAttestation:
			p.attestations = append(p.attestations, r.statement)
		case kindPendingRotation, kindBinding, kindMoveApplied, kindMembership:
		case kindMove:
			p.move = r.statement
		case kindPersonStatement:
			p.persons[r.subject] = r.statement
		case kindHostAdmission:
			p.hostAdmissions[r.subject] = r.statement
		case kindAdmin:
			p.admins[r.subject] = r.statement
		case kindGroup:
			p.groups[r.subject] = r.statement
		case kindPolicy:
			p.policies[r.subject] = r.statement
		default:
			p.revocations = append(p.revocations, r)
		}
	}
	sort.Slice(p.rotations, func(i, j int) bool { return p.rotations[i].Epoch < p.rotations[j].Epoch })
	return p, rows.Err()
}

func genesisOf(n Network) (ed25519.PublicKey, error) {
	genesis, err := membership.DecodeKey(n.RootPublicKey)
	if err == nil && membership.NetworkID(genesis) != n.ID {
		err = errors.New("network root does not derive its ID")
	}
	return genesis, err
}

// verifyMap keeps only members valid under the root chain and not excluded by
// any persisted or newly seen revocation. It drops entries sharing an invite
// key with a different host or a host ID with another entry, keeps an invalid
// address as "", and requires this host to be included. The map's chain must
// extend or equal the persisted chain.
func (s *Store) verifyMap(ctx context.Context, n Network, m membership.Map) (appliedMap, error) {
	var a appliedMap
	if m.NetworkID != n.ID || m.RootPublicKey != n.RootPublicKey {
		return a, errors.New("coordinator map is for a different network")
	}
	genesis, err := genesisOf(n)
	if err != nil {
		return a, err
	}
	persisted, err := loadStatements(ctx, s.db, n.ID)
	if err != nil {
		return a, err
	}
	persistedChain, err := membership.VerifyChain(genesis, persisted.rotations)
	if err != nil {
		return a, err
	}
	a.previousEpoch = persistedChain.Epoch()
	rotations := make([]membership.Rotation, len(m.Rotations))
	for i, raw := range m.Rotations {
		if err = json.Unmarshal(raw, &rotations[i]); err != nil {
			return a, fmt.Errorf("coordinator map has a malformed rotation: %v", err)
		}
	}
	if a.chain, err = membership.VerifyChain(genesis, rotations); err != nil {
		return a, fmt.Errorf("coordinator map has an invalid root chain: %v", err)
	}
	if err = persistedChain.Extends(a.chain); err != nil {
		return a, err
	}
	a.applyAdmins(persisted, m)
	attested := map[string]membership.Attestation{}
	for _, raw := range append(append([]json.RawMessage{}, persisted.attestations...), m.Attestations...) {
		var at membership.Attestation
		if json.Unmarshal(raw, &at) != nil || a.chain.VerifyAttestation(at) != nil {
			continue
		}
		if _, ok := attested[at.HostPublicKey]; !ok {
			attested[at.HostPublicKey] = at
			a.attestations = append(a.attestations, at)
		}
	}
	// Revocations an administrator removed with revoke_admitted signed no
	// longer apply.
	revoked := membership.NewRevoked()
	known := map[string]bool{}
	var valid []statementRecord
	for _, r := range persisted.revocations {
		if !revocationValid(a.chain, r) {
			continue
		}
		valid = append(valid, r)
		revoked.Add(revocationKind(r.kind), r.subject)
		known[r.kind+" "+r.subject] = true
	}
	served := map[string]bool{}
	for _, raw := range m.Revocations {
		var entry membership.Revocation
		if json.Unmarshal(raw, &entry) != nil {
			continue
		}
		kind, subject, err := a.chain.VerifyRevocation(entry)
		if err != nil {
			continue
		}
		revoked.Add(kind, subject)
		kind = storedKind(kind)
		served[servedKey(statementRecord{kind, subject, entry.Statement})] = true
		// Administrator removals are persisted with the delegations.
		if !known[kind+" "+subject] && kind != kindAdminRemoval {
			known[kind+" "+subject] = true
			a.revocations = append(a.revocations, statementRecord{kind, subject, entry.Statement})
		}
	}
	unserved := false
	for _, r := range valid {
		if !served[servedKey(r)] {
			unserved = true
			if r.kind != membership.KindLeave {
				a.missing = append(a.missing, r)
			}
		}
	}
	// Persons are valid under the current root and not removed.
	a.persons = map[string]membership.PersonProof{}
	for _, entry := range m.Persons {
		proof, ok := personProof(entry)
		if !ok {
			continue
		}
		key, _, err := a.chain.VerifyPerson(proof)
		public, keyErr := membership.DecodeKey(key)
		if err != nil || keyErr != nil || key != entry.PersonPublicKey || membership.PersonID(public) != entry.PersonID || revoked.Persons[key] {
			continue
		}
		// Revoking a person invite also drops persons admitted only through it.
		if proof.Membership != nil && revoked.Invites[proof.Membership.InvitePublicKey] {
			continue
		}
		a.persons[key] = proof
	}
	a.applyGroups(persisted, m)
	a.applyPolicies(persisted, m)
	a.bindings = map[string]membership.HostBinding{}
	var candidates []NetworkMember
	invites := map[string]map[string]bool{}
	hosts := map[string]int{}
	excludedSelf := false
	for _, entry := range m.Members {
		member, ok := a.verifyMember(entry, attested, revoked)
		if !ok {
			continue
		}
		if revoked.ExcludesHost(member.PublicKey, member.inviteKey()) {
			excludedSelf = excludedSelf || member.HostID == s.identity.ID
			continue
		}
		if invite := member.inviteKey(); invite != "" {
			if invites[invite] == nil {
				invites[invite] = map[string]bool{}
			}
			invites[invite][member.PublicKey] = true
		}
		hosts[member.HostID]++
		candidates = append(candidates, member)
	}
	a.members = []NetworkMember{}
	var found bool
	for _, member := range candidates {
		if invite := member.inviteKey(); (invite != "" && len(invites[invite]) != 1) || hosts[member.HostID] != 1 {
			continue
		}
		// Any validly signed membership or admission for this host's key is
		// accepted; a coordinator keeps the original when a join is retried.
		found = found || member.HostID == s.identity.ID
		a.members = append(a.members, member)
	}
	if revoked.Hosts[s.identity.PublicKey] || revoked.Left[s.identity.PublicKey] || excludedSelf {
		return a, errors.New("this host has been revoked from the network or has left it")
	}
	if !found {
		return a, errors.New("coordinator map does not include this host's membership")
	}
	sort.Slice(a.members, func(i, j int) bool { return a.members[i].HostID < a.members[j].HostID })
	a.move = a.mapMove(m.Move)
	if a.lacking, err = s.mapLacks(ctx, n.ID, persisted, m, &a, attested, revoked); err != nil {
		return a, err
	}
	a.lacking = a.lacking || unserved
	return a, nil
}

// servedKey identifies a revocation for resubmission; an administrator
// removal with revoke_admitted is resubmitted while one without is served.
func servedKey(r statementRecord) string {
	key := r.kind + " " + r.subject
	var removal membership.AdminRemoval
	if r.kind == kindAdminRemoval && json.Unmarshal(r.statement, &removal) == nil && removal.RevokeAdmitted {
		key += " revoke_admitted"
	}
	return key
}

func personProof(entry membership.MapPerson) (membership.PersonProof, bool) {
	var proof membership.PersonProof
	if len(entry.Admission) > 0 && string(entry.Admission) != "null" {
		proof.Admission = new(membership.PersonAdmission)
		if json.Unmarshal(entry.Admission, proof.Admission) != nil {
			return proof, false
		}
	}
	if len(entry.Membership) > 0 && string(entry.Membership) != "null" {
		proof.Membership = new(membership.PersonMembership)
		if json.Unmarshal(entry.Membership, proof.Membership) != nil {
			return proof, false
		}
	}
	return proof, (proof.Admission == nil) != (proof.Membership == nil)
}

func present(raw json.RawMessage) bool { return len(raw) > 0 && string(raw) != "null" }

// verifyMember checks one map entry: an invite chain valid under the root
// chain, or a host admission by the current root; then its binding, kept only
// if signed by a valid person for this host and not unbound.
func (a *appliedMap) verifyMember(entry membership.MapMember, attested map[string]membership.Attestation, revoked membership.Revoked) (NetworkMember, bool) {
	var member NetworkMember
	switch {
	case present(entry.Membership) && !present(entry.Admission):
		var proof membership.Membership
		if json.Unmarshal(entry.Membership, &proof) != nil {
			return member, false
		}
		id, err := a.chain.ValidMember(proof, attested)
		if err != nil || id != entry.HostID {
			return member, false
		}
		member = NetworkMember{HostID: id, PublicKey: proof.HostPublicKey, Member: proof.Member, Membership: &proof}
	case present(entry.Admission) && !present(entry.Membership):
		var admission membership.HostAdmission
		if json.Unmarshal(entry.Admission, &admission) != nil {
			return member, false
		}
		id, err := a.chain.VerifyHostAdmission(admission)
		if err != nil || id != entry.HostID {
			return member, false
		}
		member = NetworkMember{HostID: id, PublicKey: admission.HostPublicKey, Member: admission.Member, Admission: &admission}
	default:
		return member, false
	}
	if _, err := parseTime(entry.UpdatedAt); err != nil {
		return member, false
	}
	member.Address, member.UpdatedAt = entry.Address, entry.UpdatedAt
	if !membership.ValidAddress(member.Address) {
		member.Address = ""
	}
	// Invalid candidates are dropped, not the member.
	member.Candidates = membership.FilterCandidates(entry.Candidates)
	if present(entry.Binding) {
		var b membership.HostBinding
		if json.Unmarshal(entry.Binding, &b) == nil && b.HostPublicKey == member.PublicKey && membership.VerifyHostBinding(a.chain.NetworkID, b) == nil && revoked.Bound(b.PersonPublicKey, b.HostPublicKey) {
			if proof, ok := a.persons[b.PersonPublicKey]; ok {
				key, _ := membership.DecodeKey(b.PersonPublicKey)
				id, label := membership.PersonID(key), personLabel(proof)
				member.PersonID, member.PersonMember = &id, &label
				a.bindings[b.HostPublicKey] = b
			}
		}
	}
	return member, true
}

func personLabel(p membership.PersonProof) string {
	if p.Admission != nil {
		return p.Admission.Member
	}
	return p.Membership.Member
}

func putStatementRecord(ctx context.Context, tx *sql.Tx, network string, r statementRecord) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO network_statements VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING", network, r.kind, r.subject, string(r.statement))
	return err
}

// persistStatements stores the verified chain, current-epoch attestations,
// and newly seen revocations. Revocations are never removed; attestations are
// replaced only when the epoch advances.
func (s *Store) persistStatements(ctx context.Context, tx *sql.Tx, network string, a appliedMap, now string) error {
	for _, rotation := range a.chain.Rotations {
		data, err := json.Marshal(rotation)
		if err != nil {
			return err
		}
		if err = putStatementRecord(ctx, tx, network, statementRecord{kindRotation, strconv.FormatInt(rotation.Epoch, 10), data}); err != nil {
			return err
		}
	}
	if a.chain.Epoch() > a.previousEpoch {
		if _, err := tx.ExecContext(ctx, "DELETE FROM network_statements WHERE network_id = ? AND kind = ?", network, kindAttestation); err != nil {
			return err
		}
		if err := appendEvent(ctx, tx, "network.root_rotated", network, now); err != nil {
			return err
		}
	}
	for _, at := range a.attestations {
		data, err := json.Marshal(at)
		if err != nil {
			return err
		}
		if err = putStatementRecord(ctx, tx, network, statementRecord{kindAttestation, at.HostPublicKey, data}); err != nil {
			return err
		}
	}
	if err := s.persistPersons(ctx, tx, network, a, now); err != nil {
		return err
	}
	if err := s.persistAdmins(ctx, tx, network, a, now); err != nil {
		return err
	}
	if err := s.persistPolicies(ctx, tx, network, a, now); err != nil {
		return err
	}
	for _, r := range a.revocations {
		if err := putStatementRecord(ctx, tx, network, r); err != nil {
			return err
		}
		if r.kind == kindPersonRemoval {
			if key, err := membership.DecodeKey(r.subject); err == nil {
				if err = appendEvent(ctx, tx, "network.person_removed", membership.PersonID(key), now); err != nil {
					return err
				}
			}
		}
		if r.kind == membership.KindLeave && r.subject != s.identity.PublicKey {
			if key, err := membership.DecodeKey(r.subject); err == nil {
				if err = appendEvent(ctx, tx, "network.member_left", membership.HostID(key), now); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Store) submitMissingRevocations(ctx context.Context, n Network, missing []statementRecord) {
	for _, r := range missing {
		_, _ = s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(n.ID)+"/revocations", map[string]any{"kind": revocationKind(r.kind), "statement": r.statement})
	}
}

// administeredNetwork returns the network and its current root key, or
// ErrForbidden on a host that is not its administrator.
func (s *Store) administeredNetwork(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (Network, ed25519.PrivateKey, error) {
	var record string
	var seed []byte
	err := q.QueryRowContext(ctx, "SELECT record, root_seed FROM networks WHERE id = ?", id).Scan(&record, &seed)
	if errors.Is(err, sql.ErrNoRows) {
		return Network{}, nil, ErrNotFound
	}
	if err != nil {
		return Network{}, nil, err
	}
	var n Network
	if err = json.Unmarshal([]byte(record), &n); err != nil {
		return n, nil, err
	}
	if n.CurrentRootPublicKey == "" {
		n.CurrentRootPublicKey = n.RootPublicKey
	}
	n.Administrator = len(seed) == ed25519.SeedSize
	if !n.Administrator {
		return n, nil, ErrForbidden
	}
	return n, ed25519.NewKeyFromSeed(seed), nil
}

// RevokeMembership names a host or an invite for this host to revoke with the
// root seed, or carries a host or invite revocation an administrator signed.
type RevokeMembership struct {
	HostID          string          `json:"host_id,omitempty"`
	InvitePublicKey string          `json:"invite_public_key,omitempty"`
	Revocation      json.RawMessage `json:"revocation,omitempty"`
}
type RevocationResult struct {
	NetworkID string `json:"network_id"`
	Kind      string `json:"kind"`
	Subject   string `json:"subject"`
	Submitted bool   `json:"submitted"`
}

// Revoke signs a host or invite revocation with the current root, enforces it
// locally at once, and submits it; an unsubmitted revocation is resubmitted
// on every later sync until the coordinator serves it.
func (s *Store) Revoke(ctx context.Context, id string, r RevokeMembership) (RevocationResult, error) {
	given := 0
	for _, set := range []bool{r.HostID != "", r.InvitePublicKey != "", len(r.Revocation) != 0} {
		if set {
			given++
		}
	}
	if given != 1 {
		return RevocationResult{}, fmt.Errorf("%w: give exactly one of host_id, invite_public_key, or revocation", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RevocationResult{}, err
	}
	defer tx.Rollback()
	var n Network
	var root ed25519.PrivateKey
	if len(r.Revocation) == 0 {
		if n, root, err = s.administeredNetwork(ctx, tx, id); err != nil {
			return RevocationResult{}, err
		}
	}
	now := timestamp(time.Now())
	var record statementRecord
	var event, eventSubject string
	if len(r.Revocation) != 0 {
		g, err := s.loadGovernance(ctx, tx, id)
		if err != nil {
			return RevocationResult{}, err
		}
		n = g.network
		kind := membership.KindInvite
		var fields map[string]json.RawMessage
		if json.Unmarshal(r.Revocation, &fields) == nil && fields["host_public_key"] != nil {
			kind = membership.KindHost
		}
		if err = g.acceptSignature(signatureOf(r.Revocation)); err != nil {
			return RevocationResult{}, err
		}
		_, subject, err := g.chain.VerifyRevocation(membership.Revocation{Kind: kind, Statement: r.Revocation})
		if err != nil {
			return RevocationResult{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		record, event, eventSubject = statementRecord{kind, subject, r.Revocation}, "network.invite_revoked", subject
		if kind == membership.KindHost {
			key, _ := membership.DecodeKey(subject)
			if subject == s.identity.PublicKey {
				return RevocationResult{}, fmt.Errorf("%w: a host cannot revoke itself", ErrConflict)
			}
			event, eventSubject = "network.host_revoked", membership.HostID(key)
		}
	} else if r.HostID != "" {
		if r.HostID == s.identity.ID {
			return RevocationResult{}, fmt.Errorf("%w: the administrator cannot revoke itself", ErrConflict)
		}
		// A stored revocation for this host ID takes precedence, so a repeat
		// after the host was dropped returns it rather than 404.
		hostKey, err := storedRevokedHostKey(ctx, tx, id, r.HostID)
		if err != nil {
			return RevocationResult{}, err
		}
		if hostKey == "" {
			member, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", id, r.HostID))
			if err != nil {
				return RevocationResult{}, err
			}
			hostKey = member.PublicKey
		}
		data, err := json.Marshal(membership.SignHostRevocation(root, id, hostKey, now))
		if err != nil {
			return RevocationResult{}, err
		}
		record, event, eventSubject = statementRecord{membership.KindHost, hostKey, data}, "network.host_revoked", r.HostID
	} else {
		if _, err := membership.DecodeKey(r.InvitePublicKey); err != nil {
			return RevocationResult{}, fmt.Errorf("%w: invite key must be canonical Base64", ErrInvalid)
		}
		self, err := readJSON[NetworkMember](tx.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", id, s.identity.ID))
		if err != nil {
			return RevocationResult{}, err
		}
		if self.inviteKey() == r.InvitePublicKey {
			return RevocationResult{}, fmt.Errorf("%w: this host joined with that invite", ErrConflict)
		}
		data, err := json.Marshal(membership.SignInviteRevocation(root, id, r.InvitePublicKey, now))
		if err != nil {
			return RevocationResult{}, err
		}
		record, event, eventSubject = statementRecord{membership.KindInvite, r.InvitePublicKey, data}, "network.invite_revoked", r.InvitePublicKey
	}
	// A repeated revocation keeps and resubmits the stored statement and
	// records no second event.
	var stored string
	err = tx.QueryRowContext(ctx, "SELECT record FROM network_statements WHERE network_id = ? AND kind = ? AND subject = ?", id, record.kind, record.subject).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		if err = putStatementRecord(ctx, tx, id, record); err != nil {
			return RevocationResult{}, err
		}
		if err = appendEvent(ctx, tx, event, eventSubject, now); err != nil {
			return RevocationResult{}, err
		}
	} else if err != nil {
		return RevocationResult{}, err
	} else {
		record.statement = json.RawMessage(stored)
	}
	if err = s.dropExcludedMembers(ctx, tx, id, now); err != nil {
		return RevocationResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return RevocationResult{}, err
	}
	_, submitErr := s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(id)+"/revocations", map[string]any{"kind": record.kind, "statement": record.statement})
	return RevocationResult{NetworkID: id, Kind: record.kind, Subject: record.subject, Submitted: submitErr == nil}, nil
}

// storedRevokedHostKey returns the host key of a stored host revocation whose
// key derives hostID, or "".
func storedRevokedHostKey(ctx context.Context, tx *sql.Tx, network, hostID string) (string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT subject FROM network_statements WHERE network_id = ? AND kind = ?", network, membership.KindHost)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var subject string
		if err = rows.Scan(&subject); err != nil {
			return "", err
		}
		if key, err := membership.DecodeKey(subject); err == nil && membership.HostID(key) == hostID {
			return subject, nil
		}
	}
	return "", rows.Err()
}

// dropExcludedMembers removes local members excluded by persisted revocations,
// or whose invite or admission an administrator removed with revoke_admitted
// signed.
func (s *Store) dropExcludedMembers(ctx context.Context, tx *sql.Tx, network, now string) error {
	g, err := s.loadGovernance(ctx, tx, network)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT record FROM network_members WHERE network_id = ?", network)
	if err != nil {
		return err
	}
	var drop []string
	for rows.Next() {
		member, err := readJSON[NetworkMember](rows)
		if err != nil {
			rows.Close()
			return err
		}
		if member.HostID != s.identity.ID && (g.revoked.ExcludesHost(member.PublicKey, member.inviteKey()) || !g.memberSignerValid(member)) {
			drop = append(drop, member.HostID)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	sort.Strings(drop)
	for _, host := range drop {
		if _, err = tx.ExecContext(ctx, "DELETE FROM network_members WHERE network_id = ? AND host_id = ?", network, host); err != nil {
			return err
		}
		if err = appendEvent(ctx, tx, "network.member_removed", host, now); err != nil {
			return err
		}
	}
	return nil
}

type LeaveResult struct {
	NetworkID string `json:"network_id"`
	Submitted bool   `json:"submitted"`
}

// LeaveNetwork signs this host's departure, tries the coordinator once, and
// removes the network locally whether or not the coordinator accepted.
func (s *Store) LeaveNetwork(ctx context.Context, id string) (LeaveResult, error) {
	n, err := s.Network(ctx, id)
	if err != nil {
		return LeaveResult{}, err
	}
	if n.Administrator {
		return LeaveResult{}, fmt.Errorf("%w: the administrator cannot leave its network", ErrConflict)
	}
	leave, err := json.Marshal(membership.SignLeave(s.privateKey, id, timestamp(time.Now())))
	if err != nil {
		return LeaveResult{}, err
	}
	_, submitErr := s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(id)+"/leave", map[string]any{"statement": json.RawMessage(leave)})
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(finishCtx, nil)
	if err != nil {
		return LeaveResult{}, err
	}
	defer tx.Rollback()
	for _, table := range []string{"network_members", "network_statements"} {
		if _, err = tx.ExecContext(finishCtx, "DELETE FROM "+table+" WHERE network_id = ?", id); err != nil {
			return LeaveResult{}, err
		}
	}
	if _, err = tx.ExecContext(finishCtx, "DELETE FROM networks WHERE id = ?", id); err != nil {
		return LeaveResult{}, err
	}
	if err = appendEvent(finishCtx, tx, "network.left", id, timestamp(time.Now())); err != nil {
		return LeaveResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return LeaveResult{}, err
	}
	s.wakeRelays()
	return LeaveResult{NetworkID: id, Submitted: submitErr == nil}, nil
}

func loadPendingRotation(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, network string) (*pendingRotation, error) {
	var record string
	err := q.QueryRowContext(ctx, "SELECT record FROM network_statements WHERE network_id = ? AND kind = ?", network, kindPendingRotation).Scan(&record)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p pendingRotation
	if err = json.Unmarshal([]byte(record), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// prepareRotation signs a rotation to a new root, and with the new root the
// rotation plan, and persists them as pending.
func (s *Store) prepareRotation(ctx context.Context, n Network, current ed25519.PrivateKey) (*pendingRotation, error) {
	plan, err := s.RotationPlan(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	if plan.CurrentRootPublicKey != membership.PublicKey(current) {
		return nil, errors.New("stored root seed does not match the current root")
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := timestamp(time.Now())
	signed, err := SignRotationPlan(plan, membership.RawSigner{Key: next}, now)
	if err != nil {
		return nil, err
	}
	p := &pendingRotation{Rotation: membership.SignRotation(current, n.ID, plan.Epoch, next.Public().(ed25519.PublicKey), now), Attestations: signed.Attestations, Admissions: signed.Admissions, Groups: signed.Groups, RootSeed: membership.Seed(next)}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = putStatementRecord(ctx, tx, n.ID, statementRecord{kindPendingRotation, strconv.FormatInt(plan.Epoch, 10), data}); err != nil {
		return nil, err
	}
	return p, tx.Commit()
}

// RotateRoot replaces the network root. The current root signs the rotation
// and the new root attests every current member. The rotation is persisted as
// pending first, and becomes current only once the coordinator accepts it; a
// pending rotation is resubmitted by RotateRoot or the next sync.
//
// With a RotateRoot body, the new root is a key the CLI holds, such as an SSH
// key: the CLI signs everything the new root signs, and this host never holds
// its seed. Once accepted, this host deletes any root seed it held.
func (s *Store) RotateRoot(ctx context.Context, id string, to *RotateRoot) (Network, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	pending, err := loadPendingRotation(ctx, s.db, id)
	if err != nil {
		return Network{}, err
	}
	if pending != nil {
		n, err := s.Network(ctx, id)
		if err != nil {
			return n, err
		}
		return s.completeRotation(ctx, n, pending)
	}
	if to != nil {
		return s.rotateToKey(ctx, id, *to)
	}
	n, current, err := s.administeredNetwork(ctx, s.db, id)
	if err != nil {
		return n, err
	}
	if pending == nil {
		if pending, err = s.prepareRotation(ctx, n, current); err != nil {
			return n, err
		}
	}
	return s.completeRotation(ctx, n, pending)
}

// completeRotation submits a pending rotation. On acceptance it atomically
// makes the new root current. If the coordinator refuses it as a fork (409)
// or as no longer applicable (400), the pending rotation is discarded and the
// failure recorded as a sync error; otherwise it stays pending.
func (s *Store) completeRotation(ctx context.Context, n Network, p *pendingRotation) (Network, error) {
	feature, _, featureErr := readLinkFeature(ctx, s.db, n.ID)
	if featureErr != nil {
		return n, featureErr
	}
	if feature != "-" {
		return s.completeLinkRotation(ctx, n, p)
	}
	admissions, groups := p.Admissions, p.Groups
	if admissions == nil {
		admissions = []json.RawMessage{}
	}
	if groups == nil {
		groups = []membership.GroupDefinition{}
	}
	m, err := s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(n.ID)+"/rotations", map[string]any{"rotation": p.Rotation, "attestations": p.Attestations, "admissions": admissions, "groups": groups})
	var applied appliedMap
	if err == nil {
		applied, err = s.verifyMap(ctx, n, m)
		if err == nil && (applied.chain.Epoch() < p.Rotation.Epoch || applied.chain.Rotations[p.Rotation.Epoch-1] != p.Rotation) {
			err = fmt.Errorf("%w: coordinator did not apply the rotation", ErrConflict)
		}
		if err != nil && !errors.Is(err, ErrConflict) {
			err = fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err != nil {
		if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrInvalid) {
			return n, err // stays pending; retried on the next sync
		}
		tx, txErr := s.db.BeginTx(finishCtx, nil)
		if txErr != nil {
			return n, txErr
		}
		defer tx.Rollback()
		if _, txErr = tx.ExecContext(finishCtx, "DELETE FROM network_statements WHERE network_id = ? AND kind = ?", n.ID, kindPendingRotation); txErr != nil {
			return n, txErr
		}
		message := "root rotation discarded: " + err.Error()
		n.LastSyncError = &message
		if txErr = putJSON(finishCtx, tx, "UPDATE networks SET record = ? WHERE id = ?", n, n.ID); txErr != nil {
			return n, txErr
		}
		if txErr = tx.Commit(); txErr != nil {
			return n, txErr
		}
		return n, err
	}
	// A rotation to a root this host does not hold deletes its seed.
	var seed []byte
	if p.RootSeed != "" {
		key, err := membership.DecodeSeed(p.RootSeed)
		if err != nil {
			return n, err
		}
		seed = key.Seed()
	}
	now := timestamp(time.Now())
	tx, err := s.db.BeginTx(finishCtx, nil)
	if err != nil {
		return n, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(finishCtx, "UPDATE networks SET root_seed = ? WHERE id = ?", seed, n.ID); err != nil {
		return n, err
	}
	n.Administrator = seed != nil
	n.RootSSH = seed == nil
	if _, err = tx.ExecContext(finishCtx, "DELETE FROM network_statements WHERE network_id = ? AND kind = ?", n.ID, kindPendingRotation); err != nil {
		return n, err
	}
	if err = s.replaceMembers(finishCtx, tx, n.ID, applied.members, now); err != nil {
		return n, err
	}
	if err = s.persistStatements(finishCtx, tx, n.ID, applied, now); err != nil {
		return n, err
	}
	n.RootEpoch, n.CurrentRootPublicKey = applied.chain.Epoch(), applied.chain.CurrentPublicKey()
	n.LastSyncAt, n.LastSyncError = &now, nil
	if err = putJSON(finishCtx, tx, "UPDATE networks SET record = ? WHERE id = ?", n, n.ID); err != nil {
		return n, err
	}
	return n, tx.Commit()
}

func localGovernanceRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/networks/{id}/revocations", func(w http.ResponseWriter, r *http.Request) {
		// Null fields are treated as absent.
		var raw map[string]json.RawMessage
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil || !utf8.Valid(data) || json.Unmarshal(data, &raw) != nil || raw == nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		var req RevokeMembership
		for field, value := range raw {
			if string(value) == "null" {
				continue
			}
			var err error
			switch field {
			case "host_id":
				err = json.Unmarshal(value, &req.HostID)
			case "invite_public_key":
				err = json.Unmarshal(value, &req.InvitePublicKey)
			case "revocation":
				req.Revocation = value
			default:
				err = ErrInvalid
			}
			if err != nil {
				respond(w, 0, nil, ErrInvalid)
				return
			}
		}
		result, err := store.Revoke(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/leave", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.LeaveNetwork(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		// An empty body rotates to a new root seed held by this host.
		var to *RotateRoot
		if r.ContentLength != 0 {
			to = new(RotateRoot)
			if !decode(w, r, to, "root_public_key", "rotation", "attestations", "admissions", "groups") {
				return
			}
		}
		n, err := store.RotateRoot(r.Context(), r.PathValue("id"), to)
		respond(w, http.StatusOK, n, err)
	})
}

// persistPersons replaces the verified persons and bindings, and records host
// admissions served for members admitted by public key. Locally signed host
// admissions are kept so the administrator can renew them at a rotation.
func (s *Store) persistPersons(ctx context.Context, tx *sql.Tx, network string, a appliedMap, now string) error {
	previous := map[string]bool{}
	rows, err := tx.QueryContext(ctx, "SELECT subject FROM network_statements WHERE network_id = ? AND kind = ?", network, kindPersonStatement)
	if err != nil {
		return err
	}
	for rows.Next() {
		var subject string
		if err = rows.Scan(&subject); err != nil {
			rows.Close()
			return err
		}
		previous[subject] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM network_statements WHERE network_id = ? AND kind IN (?, ?)", network, kindPersonStatement, kindBinding); err != nil {
		return err
	}
	keys := make([]string, 0, len(a.persons))
	for key := range a.persons {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		data, err := json.Marshal(a.persons[key])
		if err != nil {
			return err
		}
		if err = putStatementRecord(ctx, tx, network, statementRecord{kindPersonStatement, key, data}); err != nil {
			return err
		}
		if !previous[key] {
			public, _ := membership.DecodeKey(key)
			if err = appendEvent(ctx, tx, "network.person_admitted", membership.PersonID(public), now); err != nil {
				return err
			}
		}
	}
	for host, b := range a.bindings {
		data, err := json.Marshal(b)
		if err != nil {
			return err
		}
		if err = putStatementRecord(ctx, tx, network, statementRecord{kindBinding, host, data}); err != nil {
			return err
		}
	}
	for _, member := range a.members {
		if member.Admission == nil {
			continue
		}
		data, err := json.Marshal(member.Admission)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO network_statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET record = excluded.record", network, kindHostAdmission, member.PublicKey, string(data)); err != nil {
			return err
		}
	}
	return nil
}
