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

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Signed revocation, leaving, and root rotation (milestone 2a). Hosts persist
// every verified statement and keep enforcing revocations even when a
// coordinator omits them or serves an older map.

const (
	kindRotation        = "rotation"
	kindAttestation     = "attestation"
	kindPendingRotation = "pending_rotation"
)

// pendingRotation is a signed rotation persisted before it is submitted, so a
// crash after the coordinator accepts it cannot lose the new root seed. The
// old root stays current locally until the coordinator accepts.
type pendingRotation struct {
	Rotation     membership.Rotation      `json:"rotation"`
	Attestations []membership.Attestation `json:"attestations"`
	RootSeed     string                   `json:"root_seed"`
}

type statementRecord struct {
	kind, subject string
	statement     json.RawMessage
}

type persistedStatements struct {
	rotations    []membership.Rotation
	attestations []json.RawMessage
	revocations  []statementRecord
}

// appliedMap is a verified map: valid members under the root chain, plus the
// statements to persist and the local revocations the coordinator lacks.
type appliedMap struct {
	chain         membership.Chain
	previousEpoch int64
	members       []NetworkMember
	attestations  []membership.Attestation
	revocations   []statementRecord
	missing       []statementRecord
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadStatements(ctx context.Context, q queryer, network string) (persistedStatements, error) {
	var p persistedStatements
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
		case kindPendingRotation:
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
	revoked := membership.NewRevoked()
	known := map[string]bool{}
	for _, r := range persisted.revocations {
		revoked.Add(r.kind, r.subject)
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
		served[kind+" "+subject] = true
		revoked.Add(kind, subject)
		if !known[kind+" "+subject] {
			known[kind+" "+subject] = true
			a.revocations = append(a.revocations, statementRecord{kind, subject, entry.Statement})
		}
	}
	for _, r := range persisted.revocations {
		if !served[r.kind+" "+r.subject] && r.kind != membership.KindLeave {
			a.missing = append(a.missing, r)
		}
	}
	var candidates []NetworkMember
	invites := map[string]map[string]bool{}
	hosts := map[string]int{}
	excludedSelf := false
	for _, entry := range m.Members {
		var proof membership.Membership
		if json.Unmarshal(entry.Membership, &proof) != nil {
			continue
		}
		id, err := a.chain.ValidMember(proof, attested)
		if err != nil || id != entry.HostID {
			continue
		}
		if revoked.Excludes(proof) {
			excludedSelf = excludedSelf || id == s.identity.ID
			continue
		}
		if !membership.ValidAddress(entry.Address) {
			entry.Address = ""
		}
		if _, err = parseTime(entry.UpdatedAt); err != nil {
			continue
		}
		if invites[proof.InvitePublicKey] == nil {
			invites[proof.InvitePublicKey] = map[string]bool{}
		}
		invites[proof.InvitePublicKey][proof.HostPublicKey] = true
		hosts[id]++
		// Invalid candidates are dropped, not the member.
		candidates = append(candidates, NetworkMember{HostID: id, PublicKey: proof.HostPublicKey, Member: proof.Member, Address: entry.Address, Candidates: membership.FilterCandidates(entry.Candidates), UpdatedAt: entry.UpdatedAt, Membership: proof})
	}
	a.members = []NetworkMember{}
	var found bool
	for _, member := range candidates {
		if len(invites[member.Membership.InvitePublicKey]) != 1 || hosts[member.HostID] != 1 {
			continue
		}
		// Any validly signed membership for this host's key is accepted; a
		// coordinator keeps the original membership when a join is retried.
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
	return a, nil
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
	for _, r := range a.revocations {
		if err := putStatementRecord(ctx, tx, network, r); err != nil {
			return err
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
		_, _ = s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(n.ID)+"/revocations", map[string]any{"kind": r.kind, "statement": r.statement})
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

type RevokeMembership struct {
	HostID          string `json:"host_id"`
	InvitePublicKey string `json:"invite_public_key"`
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
	if (r.HostID == "") == (r.InvitePublicKey == "") {
		return RevocationResult{}, fmt.Errorf("%w: give exactly one of host_id or invite_public_key", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RevocationResult{}, err
	}
	defer tx.Rollback()
	n, root, err := s.administeredNetwork(ctx, tx, id)
	if err != nil {
		return RevocationResult{}, err
	}
	now := timestamp(time.Now())
	var record statementRecord
	var event, eventSubject string
	if r.HostID != "" {
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
		if self.Membership.InvitePublicKey == r.InvitePublicKey {
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

// dropExcludedMembers removes local members excluded by persisted revocations.
func (s *Store) dropExcludedMembers(ctx context.Context, tx *sql.Tx, network, now string) error {
	persisted, err := loadStatements(ctx, tx, network)
	if err != nil {
		return err
	}
	revoked := membership.NewRevoked()
	for _, r := range persisted.revocations {
		revoked.Add(r.kind, r.subject)
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
		if member.HostID != s.identity.ID && revoked.Excludes(member.Membership) {
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

// prepareRotation signs a rotation to a new root and attestations for every
// current member, and persists them as pending. The coordinator requires
// attestations for exactly its current members, so pending local revocations
// are submitted first.
func (s *Store) prepareRotation(ctx context.Context, n Network, current ed25519.PrivateKey) (*pendingRotation, error) {
	genesis, err := genesisOf(n)
	if err != nil {
		return nil, err
	}
	persisted, err := loadStatements(ctx, s.db, n.ID)
	if err != nil {
		return nil, err
	}
	chain, err := membership.VerifyChain(genesis, persisted.rotations)
	if err != nil {
		return nil, err
	}
	if !chain.Current().Equal(current.Public()) {
		return nil, errors.New("stored root seed does not match the current root")
	}
	pending := []statementRecord{}
	for _, r := range persisted.revocations {
		if r.kind != membership.KindLeave {
			pending = append(pending, r)
		}
	}
	s.submitMissingRevocations(ctx, n, pending)
	members, err := s.NetworkMembers(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := timestamp(time.Now())
	epoch := chain.Epoch() + 1
	p := &pendingRotation{Rotation: membership.SignRotation(current, n.ID, epoch, next.Public().(ed25519.PublicKey), now), Attestations: []membership.Attestation{}, RootSeed: membership.Seed(next)}
	for _, member := range members {
		p.Attestations = append(p.Attestations, membership.SignAttestation(next, n.ID, epoch, member.PublicKey, member.Membership.Member, now))
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = putStatementRecord(ctx, tx, n.ID, statementRecord{kindPendingRotation, strconv.FormatInt(epoch, 10), data}); err != nil {
		return nil, err
	}
	return p, tx.Commit()
}

// RotateRoot replaces the network root. The current root signs the rotation
// and the new root attests every current member. The rotation is persisted as
// pending first, and becomes current only once the coordinator accepts it; a
// pending rotation is resubmitted by RotateRoot or the next sync.
func (s *Store) RotateRoot(ctx context.Context, id string) (Network, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, current, err := s.administeredNetwork(ctx, s.db, id)
	if err != nil {
		return n, err
	}
	pending, err := loadPendingRotation(ctx, s.db, id)
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
	m, err := s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(n.ID)+"/rotations", map[string]any{"rotation": p.Rotation, "attestations": p.Attestations})
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
	seed, err := membership.DecodeSeed(p.RootSeed)
	if err != nil {
		return n, err
	}
	now := timestamp(time.Now())
	tx, err := s.db.BeginTx(finishCtx, nil)
	if err != nil {
		return n, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(finishCtx, "UPDATE networks SET root_seed = ? WHERE id = ?", seed.Seed(), n.ID); err != nil {
		return n, err
	}
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
		var raw map[string]*string
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil || !utf8.Valid(data) || json.Unmarshal(data, &raw) != nil || raw == nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		var req RevokeMembership
		for field, value := range raw {
			switch {
			case value == nil:
			case field == "host_id":
				req.HostID = *value
			case field == "invite_public_key":
				req.InvitePublicKey = *value
			default:
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
		n, err := store.RotateRoot(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, n, err)
	})
}
