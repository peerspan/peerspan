package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Coordinator moves and repair (milestone 8, slice 3). The network root or a
// current administrator signs a move of one network to another coordinator.
// A host learns a move from its coordinator's map, from a peer's push, or by
// asking peers when its coordinators are unreachable; a valid move with a
// sequence above the one it applied becomes its pending coordinator, ahead of
// any successor. Any member host re-submits, through the coordinator's
// import, the signed statements a coordinator lacks.

const (
	kindMove        = "move"         // subject: empty; the latest valid move this host holds
	kindMoveApplied = "move_applied" // subject: empty; {"sequence": N}, the move sequence switched to
)

// moveLookupFailures is how many consecutive failed syncs make a host ask
// its peers for a move.
const moveLookupFailures = 3

// moveState is the in-memory schedule of lookups and imports per network.
type moveState struct {
	mu       sync.Mutex
	failures map[string]int
	lookedUp map[string]time.Time
	imported map[string]time.Time
}

// considerMove makes a valid move n's pending coordinator when its sequence
// is above applied and it names a coordinator other than the pin; a pending
// move with a sequence at least as high stays. A move naming the pinned
// coordinator needs no switch and counts as applied. It returns whether the
// pending coordinator changed and the applied sequence.
func considerMove(n *Network, mv membership.Move, applied int64) (bool, int64) {
	if mv.Sequence <= applied {
		return false, applied
	}
	if mv.Address == n.CoordinatorAddress && mv.PublicKey == n.CoordinatorPublicKey {
		if p := n.CoordinatorPending; p.isMove() && *p.MoveSequence <= mv.Sequence {
			n.CoordinatorPending = nil
		}
		return false, mv.Sequence
	}
	if p := n.CoordinatorPending; p.isMove() && *p.MoveSequence >= mv.Sequence {
		return false, applied
	}
	sequence := mv.Sequence
	n.CoordinatorPending = &CoordinatorPending{Address: mv.Address, PublicKey: mv.PublicKey, Sequence: sequence, Source: pendingMove, MoveSequence: &sequence}
	return true, applied
}

// heldMove is the latest valid move this host holds for a network, if any,
// and the move sequence it applied.
func heldMove(ctx context.Context, q dbQuerier, network string) (*membership.Move, int64, error) {
	var held *membership.Move
	var applied int64
	rows, err := q.QueryContext(ctx, "SELECT kind, record FROM network_statements WHERE network_id = ? AND kind IN (?, ?) AND subject = ''", network, kindMove, kindMoveApplied)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, record string
		if err = rows.Scan(&kind, &record); err != nil {
			return nil, 0, err
		}
		if kind == kindMove {
			var mv membership.Move
			if json.Unmarshal([]byte(record), &mv) == nil {
				held = &mv
			}
			continue
		}
		var a struct {
			Sequence int64 `json:"sequence"`
		}
		if json.Unmarshal([]byte(record), &a) == nil {
			applied = a.Sequence
		}
	}
	return held, applied, rows.Err()
}

// storeMove keeps a verified move when its sequence is above the held one,
// and reports whether it did.
func storeMove(ctx context.Context, tx *sql.Tx, network string, mv membership.Move) (bool, error) {
	held, _, err := heldMove(ctx, tx, network)
	if err != nil || (held != nil && held.Sequence >= mv.Sequence) {
		return false, err
	}
	return true, putRecord(ctx, tx, network, kindMove, "", mv)
}

// storeApplied records the move sequence this host switched to.
func storeApplied(ctx context.Context, tx *sql.Tx, network string, sequence int64) error {
	return putRecord(ctx, tx, network, kindMoveApplied, "", map[string]int64{"sequence": sequence})
}

// verifyMove checks a move under this host's view of the network: signed by
// the current root or a current administrator.
func (g governance) verifyMove(mv membership.Move) error {
	if err := g.chain.VerifyMove(mv, g.currentAdmins()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// mapMove verifies a map's move under the applied map's view; an invalid or
// absent move is nil.
func (a appliedMap) mapMove(raw json.RawMessage) *membership.Move {
	if !present(raw) {
		return nil
	}
	var mv membership.Move
	if json.Unmarshal(raw, &mv) != nil {
		return nil
	}
	current := map[string]bool{}
	for key := range a.admins.Current {
		if _, ok := a.persons[key]; ok {
			current[key] = true
		}
	}
	if a.chain.VerifyMove(mv, current) != nil {
		return nil
	}
	return &mv
}

// importBody is the import request for a network: the signed statements
// this host holds, as a map, with move in place of the held move when given.
func (s *Store) importBody(ctx context.Context, n Network, move *membership.Move) (map[string]any, error) {
	p, err := loadStatements(ctx, s.db, n.ID)
	if err != nil {
		return nil, err
	}
	bindings := map[string]json.RawMessage{}
	rows, err := s.db.QueryContext(ctx, "SELECT subject, record FROM network_statements WHERE network_id = ? AND kind = ?", n.ID, kindBinding)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var subject, record string
		if err = rows.Scan(&subject, &record); err != nil {
			rows.Close()
			return nil, err
		}
		bindings[subject] = json.RawMessage(record)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	stored, err := s.NetworkMembers(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	members := []membership.MapMember{}
	for _, m := range stored {
		entry := membership.MapMember{HostID: m.HostID, Binding: bindings[m.PublicKey], Address: m.Address, Candidates: m.Candidates, UpdatedAt: m.UpdatedAt}
		if m.Membership != nil {
			entry.Membership, _ = json.Marshal(m.Membership)
		}
		if m.Admission != nil {
			entry.Admission, _ = json.Marshal(m.Admission)
		}
		members = append(members, entry)
	}
	persons := []membership.MapPerson{}
	for _, key := range sortedKeys(p.persons) {
		var proof membership.PersonProof
		if json.Unmarshal(p.persons[key], &proof) != nil || (proof.Admission == nil) == (proof.Membership == nil) {
			continue
		}
		entry := membership.MapPerson{PersonID: personIDOf(key), PersonPublicKey: key, Member: personLabel(proof)}
		if proof.Admission != nil {
			entry.Admission, _ = json.Marshal(proof.Admission)
		} else {
			entry.Membership, _ = json.Marshal(proof.Membership)
		}
		persons = append(persons, entry)
	}
	revocations := []membership.Revocation{}
	for _, r := range p.revocations {
		revocations = append(revocations, membership.Revocation{Kind: revocationKind(r.kind), Statement: r.statement})
	}
	values := func(records map[string]json.RawMessage) []json.RawMessage {
		out := []json.RawMessage{}
		for _, key := range sortedKeys(records) {
			out = append(out, records[key])
		}
		return out
	}
	var moved any
	if move != nil {
		moved = move
	} else if len(p.move) > 0 {
		moved = p.move
	}
	attestations := append([]json.RawMessage{}, p.attestations...)
	return map[string]any{"name": n.Name, "root_public_key": n.RootPublicKey, "map": map[string]any{
		"network_id": n.ID, "members": members, "rotations": append([]membership.Rotation{}, p.rotations...), "attestations": attestations,
		"revocations": revocations, "persons": persons, "admins": values(p.admins), "groups": values(p.groups), "policies": values(p.policies), "move": moved,
	}}, nil
}

// ImportResult is a coordinator's answer to an import.
type ImportResult struct {
	Added   int64          `json:"added"`
	Skipped int64          `json:"skipped"`
	Map     membership.Map `json:"map"`
}

// importInto imports body into the coordinator target names.
func (s *Store) importInto(ctx context.Context, target Network, body map[string]any) (ImportResult, error) {
	var result ImportResult
	data, err := s.coordinatorRequest(ctx, target, http.MethodPost, "/coord/v1/networks/import", body)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return result, fmt.Errorf("%w: malformed import result", ErrUnavailable)
	}
	return result, nil
}

// importAllowed reports whether a repair import of a network may run now,
// at most once per sync interval, and records it.
func (s *Store) importAllowed(network string) bool {
	_, interval := s.coordinationConfig()
	s.moves.mu.Lock()
	defer s.moves.mu.Unlock()
	if s.moves.imported == nil {
		s.moves.imported = map[string]time.Time{}
	}
	if last, ok := s.moves.imported[network]; ok && time.Since(last) < interval {
		return false
	}
	s.moves.imported[network] = time.Now()
	return true
}

// syncResult counts consecutive failed syncs of a network; after
// moveLookupFailures of them, it asks the network's peers for a move at most
// once per interval.
func (s *Store) syncResult(network string, failed bool) {
	_, interval := s.coordinationConfig()
	s.moves.mu.Lock()
	if s.moves.failures == nil {
		s.moves.failures, s.moves.lookedUp = map[string]int{}, map[string]time.Time{}
	}
	if !failed {
		delete(s.moves.failures, network)
		s.moves.mu.Unlock()
		return
	}
	s.moves.failures[network]++
	due := s.moves.failures[network] >= moveLookupFailures && time.Since(s.moves.lookedUp[network]) >= interval
	if due {
		s.moves.lookedUp[network] = time.Now()
	}
	s.moves.mu.Unlock()
	if due {
		go s.lookupMove(network, interval)
	}
}

// lookupMove asks each member this host can reach on a direct path for its
// latest move, and keeps any valid one above the held move, then syncs.
func (s *Store) lookupMove(network string, interval time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), max(interval, peerRequestTimeout))
	defer cancel()
	members, err := s.NetworkMembers(ctx, network)
	if err != nil {
		return
	}
	learned := false
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, member := range members {
		if member.HostID == s.identity.ID || member.Address == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer := Peer{ID: member.HostID, PublicKey: member.PublicKey, Address: member.Address}
			status, data, err := s.peerRequest(ctx, peer, http.MethodGet, "/peer/v1/networks/"+url.PathEscape(network)+"/move", nil)
			if err != nil || status != http.StatusOK {
				return
			}
			var answer struct {
				Move membership.Move `json:"move"`
			}
			if decodeStrict(data, &answer) != nil {
				return
			}
			if stored, err := s.keepMove(ctx, network, answer.Move); err == nil && stored {
				mu.Lock()
				learned = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if learned {
		s.networkChanged(network)
	}
}

// keepMove verifies a move learned from a peer and stores it when its
// sequence is above the held one. The next sync makes it pending.
func (s *Store) keepMove(ctx context.Context, network string, mv membership.Move) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	g, err := s.loadGovernance(ctx, tx, network)
	if err != nil {
		return false, err
	}
	if err = g.verifyMove(mv); err != nil {
		return false, err
	}
	stored, err := storeMove(ctx, tx, network, mv)
	if err != nil {
		return false, err
	}
	return stored, tx.Commit()
}

// currentMember checks that a peer is a current member host of a network
// this host belongs to.
func (s *Store) currentMember(ctx context.Context, network, sender string) error {
	if _, err := s.Network(ctx, network); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM network_members WHERE network_id = ? AND host_id = ?", network, sender).Scan(&n); err != nil {
		return err
	}
	if n == 0 || sender == s.identity.ID {
		return ErrForbidden
	}
	return nil
}

// ReceiveMove verifies and stores a move a member pushed, then syncs.
func (s *Store) ReceiveMove(ctx context.Context, sender, network string, mv membership.Move) (MoveRecord, error) {
	if err := s.currentMember(ctx, network, sender); err != nil {
		return MoveRecord{}, err
	}
	stored, err := s.keepMove(ctx, network, mv)
	if err != nil {
		return MoveRecord{}, err
	}
	if stored {
		s.networkChanged(network)
	}
	held, _, err := heldMove(ctx, s.db, network)
	return MoveRecord{Move: held}, err
}

// PeerMove returns the latest valid move this host holds, for a member.
func (s *Store) PeerMove(ctx context.Context, sender, network string) (MoveRecord, error) {
	if err := s.currentMember(ctx, network, sender); err != nil {
		return MoveRecord{}, err
	}
	held, _, err := heldMove(ctx, s.db, network)
	if err == nil && held == nil {
		err = fmt.Errorf("%w: no move", ErrNotFound)
	}
	return MoveRecord{Move: held}, err
}

// MoveRecord is the peer route's view of a held move.
type MoveRecord struct {
	Move *membership.Move `json:"move"`
}

func movePeerRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("GET /peer/v1/networks/{network}/move", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		record, err := store.PeerMove(r.Context(), id, r.PathValue("network"))
		respond(w, http.StatusOK, record, err)
	})
	mux.HandleFunc("POST /peer/v1/networks/{network}/move", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		var req struct {
			Move *membership.Move `json:"move"`
		}
		if !decode(w, r, &req, "move") {
			return
		}
		if req.Move == nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		record, err := store.ReceiveMove(r.Context(), id, r.PathValue("network"), *req.Move)
		respond(w, http.StatusOK, record, err)
	})
}

// MoveNetwork moves a network to another coordinator. Move is the move an
// administrator signed through the CLI; without it, this host signs as the
// root with its root seed.
type MoveNetwork struct {
	CoordinatorAddress   string           `json:"coordinator_address"`
	CoordinatorPublicKey string           `json:"coordinator_public_key"`
	Move                 *membership.Move `json:"move,omitempty"`
}

type MoveCoordinator struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

type MoveImported struct {
	Added   int64 `json:"added"`
	Skipped int64 `json:"skipped"`
}

// MoveResult reports a move: the import into the new coordinator, the
// previous coordinator's answer (accepted, refused, or unreachable), and the
// pushes to the other current member hosts.
type MoveResult struct {
	NetworkID           string          `json:"network_id"`
	Sequence            int64           `json:"sequence"`
	Coordinator         MoveCoordinator `json:"coordinator"`
	Imported            MoveImported    `json:"imported"`
	PreviousCoordinator string          `json:"previous_coordinator"`
	Pushed              int             `json:"pushed"`
	Members             int             `json:"members"`
}

// MovePlan tells the CLI the move to sign: the held move and the next
// sequence.
type MovePlan struct {
	Move         *membership.Move `json:"move"`
	NextSequence int64            `json:"next_sequence"`
}

func (s *Store) MovePlan(ctx context.Context, network string) (MovePlan, error) {
	if _, err := s.Network(ctx, network); err != nil {
		return MovePlan{}, err
	}
	held, applied, err := heldMove(ctx, s.db, network)
	if err != nil {
		return MovePlan{}, err
	}
	next := applied + 1
	if held != nil {
		next = max(next, held.Sequence+1)
	}
	return MovePlan{Move: held, NextSequence: next}, nil
}

// Move signs or checks a move, imports the network with it into the new
// coordinator (nothing changes if that fails), submits it once to the
// current coordinator, pushes it to every other current member host it
// reaches, and switches to the new coordinator.
func (s *Store) Move(ctx context.Context, network string, r MoveNetwork) (MoveResult, error) {
	var result MoveResult
	if !membership.ValidCoordinatorAddress(r.CoordinatorAddress) {
		return result, fmt.Errorf("%w: coordinator address must be HOST:PORT", ErrInvalid)
	}
	if _, err := membership.DecodeKey(r.CoordinatorPublicKey); err != nil {
		return result, fmt.Errorf("%w: coordinator key must be canonical Base64", ErrInvalid)
	}
	n, err := s.Network(ctx, network)
	if err != nil {
		return result, err
	}
	if n.CoordinatorAddress == r.CoordinatorAddress && n.CoordinatorPublicKey == r.CoordinatorPublicKey {
		return result, fmt.Errorf("%w: the network already uses that coordinator", ErrInvalid)
	}
	plan, err := s.MovePlan(ctx, network)
	if err != nil {
		return result, err
	}
	g, err := s.loadGovernance(ctx, s.db, network)
	if err != nil {
		return result, err
	}
	mv := r.Move
	if mv == nil {
		var seed []byte
		if err = s.db.QueryRowContext(ctx, "SELECT root_seed FROM networks WHERE id = ?", network).Scan(&seed); err != nil {
			return result, err
		}
		if len(seed) != ed25519.SeedSize {
			return result, fmt.Errorf("%w: this host does not hold the network's root seed; sign the move as an administrator", ErrForbidden)
		}
		signed, err := membership.SignMove(membership.RawSigner{Key: ed25519.NewKeyFromSeed(seed)}, true, network, plan.NextSequence, r.CoordinatorAddress, r.CoordinatorPublicKey, timestamp(time.Now()))
		if err != nil {
			return result, err
		}
		mv = &signed
	} else if mv.NetworkID != network || mv.Address != r.CoordinatorAddress || mv.PublicKey != r.CoordinatorPublicKey || mv.Sequence != plan.NextSequence {
		return result, fmt.Errorf("%w: the signed move must name this network and coordinator at sequence %d", ErrInvalid, plan.NextSequence)
	}
	if err = g.verifyMove(*mv); err != nil {
		return result, err
	}
	body, err := s.importBody(ctx, n, mv)
	if err != nil {
		return result, err
	}
	target := n
	target.CoordinatorAddress, target.CoordinatorPublicKey, target.CoordinatorPending = r.CoordinatorAddress, r.CoordinatorPublicKey, nil
	imported, err := s.importInto(ctx, target, body)
	if err != nil {
		return result, fmt.Errorf("%w: importing into the new coordinator failed: %v", ErrUnavailable, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err = storeMove(ctx, tx, network, *mv); err != nil {
		return result, err
	}
	if err = tx.Commit(); err != nil {
		return result, err
	}
	result = MoveResult{NetworkID: network, Sequence: mv.Sequence, Coordinator: MoveCoordinator{r.CoordinatorAddress, r.CoordinatorPublicKey}, Imported: MoveImported{imported.Added, imported.Skipped}}
	_, err = s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(network)+"/moves", map[string]any{"move": mv})
	var limited *CoordinatorLimitError
	switch {
	case err == nil:
		result.PreviousCoordinator = "accepted"
	case errors.Is(err, ErrUnavailable) && !errors.As(err, &limited):
		result.PreviousCoordinator = "unreachable"
	default:
		result.PreviousCoordinator = "refused"
	}
	result.Pushed, result.Members = s.pushMove(ctx, network, *mv)
	// The held move becomes pending at the start of this sync, which tries
	// the new coordinator first.
	_, err = s.SyncNetwork(ctx, network)
	return result, err
}

// pushMove delivers a move to every other current member host, in parallel,
// and returns how many accepted it and how many there are.
func (s *Store) pushMove(ctx context.Context, network string, mv membership.Move) (int, int) {
	members, err := s.NetworkMembers(ctx, network)
	if err != nil {
		return 0, 0
	}
	body, err := json.Marshal(map[string]any{"move": mv})
	if err != nil {
		return 0, 0
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	pushed, others := 0, 0
	for _, member := range members {
		if member.HostID == s.identity.ID {
			continue
		}
		others++
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer, err := s.dialPeer(ctx, member.HostID)
			if err != nil {
				return
			}
			status, _, err := s.peerRequest(ctx, peer, http.MethodPost, "/peer/v1/networks/"+url.PathEscape(network)+"/move", body)
			if err == nil && status == http.StatusOK {
				mu.Lock()
				pushed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return pushed, others
}

func localMoveRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/networks/{id}/move", func(w http.ResponseWriter, r *http.Request) {
		plan, err := store.MovePlan(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, plan, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/move", func(w http.ResponseWriter, r *http.Request) {
		var req MoveNetwork
		if !decode(w, r, &req, "coordinator_address", "coordinator_public_key", "move?") {
			return
		}
		result, err := store.Move(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusOK, result, err)
	})
}

// mapLacks reports whether a verified map lacks a signed statement this host
// held before applying it: a current member, an attestation at the current
// epoch, a person, a binding, an administrator delegation, a newer group or
// policy version, or a move with a higher sequence. Revocations are compared
// by verifyMap.
func (s *Store) mapLacks(ctx context.Context, network string, persisted persistedStatements, m membership.Map, a *appliedMap, attested map[string]membership.Attestation, revoked membership.Revoked) (bool, error) {
	valid := map[string]bool{}
	for _, member := range a.members {
		valid[member.HostID] = true
	}
	// A network being joined has no stored members yet.
	held, err := s.NetworkMembers(ctx, network)
	if errors.Is(err, ErrNotFound) {
		held, err = nil, nil
	}
	if err != nil {
		return false, err
	}
	for _, member := range held {
		if valid[member.HostID] {
			continue
		}
		entry := membership.MapMember{HostID: member.HostID, Address: member.Address, Candidates: member.Candidates, UpdatedAt: member.UpdatedAt}
		if member.Membership != nil {
			entry.Membership, _ = json.Marshal(member.Membership)
		}
		if member.Admission != nil {
			entry.Admission, _ = json.Marshal(member.Admission)
		}
		if verified, ok := a.verifyMember(entry, attested, revoked); ok && !revoked.ExcludesHost(verified.PublicKey, verified.inviteKey()) {
			return true, nil
		}
	}
	served := map[string]bool{}
	for _, at := range membership.DecodeRaw[membership.Attestation](m.Attestations) {
		if a.chain.VerifyAttestation(at) == nil {
			served[at.HostPublicKey] = true
		}
	}
	for _, at := range membership.DecodeRaw[membership.Attestation](persisted.attestations) {
		if a.chain.VerifyAttestation(at) == nil && !served[at.HostPublicKey] {
			return true, nil
		}
	}
	for key, data := range persisted.persons {
		var proof membership.PersonProof
		if json.Unmarshal(data, &proof) != nil || (proof.Admission == nil) == (proof.Membership == nil) || revoked.Persons[key] {
			continue
		}
		if proof.Membership != nil && revoked.Invites[proof.Membership.InvitePublicKey] {
			continue
		}
		if verified, _, err := a.chain.VerifyPerson(proof); err != nil || verified != key {
			continue
		}
		if _, ok := a.persons[key]; !ok {
			return true, nil
		}
	}
	members := map[string]bool{}
	for _, member := range a.members {
		members[member.PublicKey] = true
	}
	rows, err := s.db.QueryContext(ctx, "SELECT subject, record FROM network_statements WHERE network_id = ? AND kind = ?", network, kindBinding)
	if err != nil {
		return false, err
	}
	var bindings []membership.HostBinding
	for rows.Next() {
		var subject, record string
		if err = rows.Scan(&subject, &record); err != nil {
			rows.Close()
			return false, err
		}
		var b membership.HostBinding
		if json.Unmarshal([]byte(record), &b) == nil && b.HostPublicKey == subject {
			bindings = append(bindings, b)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return false, err
	}
	for _, b := range bindings {
		if _, ok := a.persons[b.PersonPublicKey]; !ok || !members[b.HostPublicKey] || !revoked.Bound(b.PersonPublicKey, b.HostPublicKey) {
			continue
		}
		if current, ok := a.bindings[b.HostPublicKey]; !ok || current.PersonPublicKey != b.PersonPublicKey {
			if membership.VerifyHostBinding(network, b) == nil {
				return true, nil
			}
		}
	}
	delegated := map[string]int64{}
	for _, d := range membership.DecodeRaw[membership.AdminDelegation](m.Admins) {
		if key, err := a.chain.VerifyDelegation(d); err == nil {
			if previous, ok := delegated[key]; !ok || d.Epoch > previous {
				delegated[key] = d.Epoch
			}
		}
	}
	for _, d := range rawValues[membership.AdminDelegation](persisted.admins) {
		key, err := a.chain.VerifyDelegation(d)
		if err != nil {
			continue
		}
		if epoch, ok := delegated[key]; !ok || epoch < d.Epoch {
			return true, nil
		}
	}
	servedGroups := a.chain.NewestGroups(membership.DecodeRaw[membership.GroupDefinition](m.Groups))
	for name, g := range a.chain.NewestGroups(rawValues[membership.GroupDefinition](persisted.groups)) {
		if current, ok := servedGroups[name]; !ok || current.Version < g.Version {
			return true, nil
		}
	}
	servedPolicies := map[string]int64{}
	for _, p := range membership.DecodeRaw[membership.Policy](m.Policies) {
		if membership.VerifyPolicy(network, p) == nil && p.Version > servedPolicies[p.PersonPublicKey] {
			servedPolicies[p.PersonPublicKey] = p.Version
		}
	}
	now := time.Now()
	for key, data := range persisted.policies {
		var p membership.Policy
		if _, ok := a.persons[key]; !ok || json.Unmarshal(data, &p) != nil || p.PersonPublicKey != key {
			continue
		}
		if membership.VerifyPolicy(network, p) == nil && membership.PolicyActive(p, now) && p.Version > servedPolicies[key] {
			return true, nil
		}
	}
	// A held move counts while it is still valid, against the sequence the
	// map serves, valid or not.
	if len(persisted.move) > 0 {
		var mv, served membership.Move
		if json.Unmarshal(persisted.move, &mv) == nil && a.mapMove(persisted.move) != nil {
			if !present(m.Move) || json.Unmarshal(m.Move, &served) != nil || served.Sequence < mv.Sequence {
				return true, nil
			}
		}
	}
	return false, nil
}
