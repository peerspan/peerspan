package coord

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Network import (milestone 8, slice 3). A member host sends the signed
// statements it holds for a network: to a new coordinator when an
// administrator moves the network, or to any coordinator that lacks some of
// them, such as one restored from an older backup. Each statement is verified
// as on its own submission route, in dependency order, and merged: what the
// coordinator lacks is added and what it has is kept when its own is newer.
// Statements that fail verification are skipped.

type importRequest struct {
	Name          string          `json:"name"`
	RootPublicKey string          `json:"root_public_key"`
	Map           json.RawMessage `json:"map"`
}

// importedMap holds the signed fields of an imported map. Other fields, such
// as members' addresses, are ignored: they come from each member's own syncs.
type importedMap struct {
	NetworkID    *string           `json:"network_id"`
	Members      []json.RawMessage `json:"members"`
	Rotations    []json.RawMessage `json:"rotations"`
	Attestations []json.RawMessage `json:"attestations"`
	Revocations  []json.RawMessage `json:"revocations"`
	Persons      []json.RawMessage `json:"persons"`
	Admins       []json.RawMessage `json:"admins"`
	Groups       []json.RawMessage `json:"groups"`
	Policies     []json.RawMessage `json:"policies"`
	Move         json.RawMessage   `json:"move"`
}

type importResult struct {
	Added   int64           `json:"added"`
	Skipped int64           `json:"skipped"`
	Map     *membership.Map `json:"map"`
}

func (s *Server) importNetwork(ctx context.Context, caller, source string, req importRequest) (int, *importResult, error) {
	root, err := membership.DecodeKey(req.RootPublicKey)
	if err != nil {
		return 0, nil, err
	}
	network := membership.NetworkID(root)
	var in importedMap
	if trimmed := bytes.TrimSpace(req.Map); len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(req.Map, &in) != nil {
		return 0, nil, fmt.Errorf("%w: map must be an object of statement arrays", errInvalid)
	}
	if in.NetworkID != nil && *in.NetworkID != network {
		return 0, nil, fmt.Errorf("%w: map is for a different network", errInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	status := http.StatusOK
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM networks WHERE id = ?`, network).Scan(&exists); err != nil {
		return 0, nil, err
	}
	if exists == 0 {
		if !membership.ValidLabel(req.Name) {
			return 0, nil, fmt.Errorf("%w: invalid network name", errInvalid)
		}
		if err = s.checkRegistration(ctx, tx, source, network); err != nil {
			return 0, nil, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO networks VALUES (?, ?, ?, ?)`, network, req.Name, req.RootPublicKey, membership.Timestamp(s.Now())); err != nil {
			return 0, nil, err
		}
		status = http.StatusCreated
	}
	im := &importer{s: s, tx: tx, network: network}
	if err = im.run(ctx, in); err != nil {
		return 0, nil, err
	}
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return 0, nil, err
	}
	if err = dropExcluded(ctx, tx, chain); err != nil {
		return 0, nil, err
	}
	if err = isMember(ctx, tx, network, caller); err != nil {
		return 0, nil, fmt.Errorf("%w: the caller is not a current member of the imported network", errForbidden)
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return 0, nil, err
	}
	if err = tx.Commit(); err != nil {
		return 0, nil, err
	}
	return status, &importResult{Added: im.added, Skipped: im.skipped, Map: m}, nil
}

type importer struct {
	s              *Server
	tx             *sql.Tx
	network        string
	added, skipped int64
}

// importEntry applies one statement under the network's current chain.
type importEntry func(ctx context.Context, chain membership.Chain) error

// run imports in dependency order: the root chain, then current-epoch
// attestations, then persons, delegations, members, bindings, groups, and
// policies, then revocations with administrator removals last, so statements
// an administrator signed before a removal are verified while it was current,
// and finally the move. Within a stage, entries that fail are retried while
// others succeed, since one may depend on another (an administrator's
// delegation before the persons it admitted).
func (im *importer) run(ctx context.Context, in importedMap) error {
	if err := im.rotations(ctx, in.Rotations); err != nil {
		return err
	}
	var stage []importEntry
	for _, raw := range in.Attestations {
		stage = append(stage, func(ctx context.Context, chain membership.Chain) error { return im.attestation(ctx, chain, raw) })
	}
	if err := im.settle(ctx, stage, false); err != nil {
		return err
	}
	stage = nil
	for _, raw := range in.Persons {
		stage = append(stage, func(ctx context.Context, chain membership.Chain) error { return im.person(ctx, chain, raw) })
	}
	for _, raw := range in.Admins {
		stage = append(stage, func(ctx context.Context, chain membership.Chain) error {
			var d membership.AdminDelegation
			if err := json.Unmarshal(raw, &d); err != nil {
				return fmt.Errorf("%w: %v", errInvalid, err)
			}
			return delegateIn(ctx, im.tx, chain, d, true)
		})
	}
	for _, raw := range in.Members {
		stage = append(stage, func(ctx context.Context, chain membership.Chain) error { return im.member(ctx, chain, raw) })
	}
	for _, raw := range in.Members {
		var entry struct {
			Binding json.RawMessage `json:"binding"`
		}
		if json.Unmarshal(raw, &entry) != nil || !present(entry.Binding) {
			continue
		}
		stage = append(stage, func(ctx context.Context, chain membership.Chain) error {
			var b membership.HostBinding
			if err := json.Unmarshal(entry.Binding, &b); err != nil {
				return fmt.Errorf("%w: %v", errInvalid, err)
			}
			return bindIn(ctx, im.tx, chain, b)
		})
	}
	for _, raw := range in.Groups {
		stage = append(stage, func(ctx context.Context, chain membership.Chain) error {
			var g membership.GroupDefinition
			if err := json.Unmarshal(raw, &g); err != nil {
				return fmt.Errorf("%w: %v", errInvalid, err)
			}
			return defineGroupIn(ctx, im.tx, chain, g)
		})
	}
	for _, raw := range in.Policies {
		stage = append(stage, func(ctx context.Context, chain membership.Chain) error {
			var p membership.Policy
			if err := json.Unmarshal(raw, &p); err != nil {
				return fmt.Errorf("%w: %v", errInvalid, err)
			}
			return submitPolicyIn(ctx, im.tx, chain, p)
		})
	}
	if err := im.settle(ctx, stage, false); err != nil {
		return err
	}
	// A person removal of a current administrator waits for the
	// administrator's removal, so conflicts are retried in this stage.
	stage = nil
	var removals []importEntry
	for _, raw := range in.Revocations {
		var entry membership.Revocation
		decoded := json.Unmarshal(raw, &entry)
		apply := func(ctx context.Context, chain membership.Chain) error {
			if decoded != nil {
				return fmt.Errorf("%w: %v", errInvalid, decoded)
			}
			switch entry.Kind {
			case membership.KindHost, membership.KindInvite, membership.KindLeave, membership.KindPerson, membership.KindUnbind, membership.KindAdmin:
			default:
				return fmt.Errorf("%w: unknown revocation kind", errInvalid)
			}
			return revokeIn(ctx, im.tx, chain, revocationRequest{Kind: entry.Kind, Statement: entry.Statement})
		}
		if decoded == nil && entry.Kind == membership.KindAdmin {
			removals = append(removals, apply)
		} else {
			stage = append(stage, apply)
		}
	}
	if err := im.settle(ctx, append(stage, removals...), true); err != nil {
		return err
	}
	if !present(in.Move) {
		return nil
	}
	return im.settle(ctx, []importEntry{func(ctx context.Context, chain membership.Chain) error {
		var mv membership.Move
		if err := json.Unmarshal(in.Move, &mv); err != nil {
			return fmt.Errorf("%w: %v", errInvalid, err)
		}
		return submitMoveIn(ctx, im.tx, chain, mv)
	}}, false)
}

func present(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

// settle applies entries in passes until a pass makes no progress. A conflict
// means the coordinator keeps what it has, which is neither added nor
// skipped, unless retryConflicts. Entries still failing are skipped.
func (im *importer) settle(ctx context.Context, entries []importEntry, retryConflicts bool) error {
	pending := entries
	for len(pending) > 0 {
		var failed []importEntry
		progress := false
		for _, apply := range pending {
			added, err := im.try(ctx, apply)
			var fatal *importFatal
			switch {
			case errors.As(err, &fatal):
				return fatal.err
			case err == nil:
				progress = true
				if added {
					im.added++
				}
			case errors.Is(err, errConflict) && !retryConflicts:
				progress = true
			default:
				failed = append(failed, apply)
			}
		}
		pending = failed
		if !progress {
			break
		}
	}
	im.skipped += int64(len(pending))
	return nil
}

// importFatal is a failure of the import itself rather than of one entry.
type importFatal struct{ err error }

func (e *importFatal) Error() string { return e.err.Error() }

// try applies one entry inside a savepoint, rolling it back if it fails, and
// reports whether it changed the network's stored state.
func (im *importer) try(ctx context.Context, apply importEntry) (bool, error) {
	if _, err := im.tx.ExecContext(ctx, `SAVEPOINT import_entry`); err != nil {
		return false, &importFatal{err}
	}
	before, err := im.changes(ctx)
	if err != nil {
		return false, &importFatal{err}
	}
	chain, err := chainOf(ctx, im.tx, im.network)
	if err == nil {
		err = apply(ctx, chain)
	}
	if err != nil {
		if _, rollbackErr := im.tx.ExecContext(ctx, `ROLLBACK TO import_entry; RELEASE import_entry`); rollbackErr != nil {
			return false, &importFatal{rollbackErr}
		}
		if ctx.Err() != nil {
			return false, &importFatal{ctx.Err()}
		}
		return false, err
	}
	after, err := im.changes(ctx)
	if err != nil {
		return false, &importFatal{err}
	}
	if _, err = im.tx.ExecContext(ctx, `RELEASE import_entry`); err != nil {
		return false, &importFatal{err}
	}
	return after > before, nil
}

// changes counts the rows this connection has changed; the database has one
// connection, which the transaction holds.
func (im *importer) changes(ctx context.Context) (int64, error) {
	var n int64
	err := im.tx.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&n)
	return n, err
}

// rotations extends the stored root chain with the imported rotations that
// follow it, in epoch order. At each new epoch the stored attestations lapse,
// as do root-signed admissions; the imported ones under the new root renew
// them. A different rotation at a stored epoch is a fork: the coordinator
// keeps its own.
func (im *importer) rotations(ctx context.Context, raw []json.RawMessage) error {
	var rotations []membership.Rotation
	for _, data := range raw {
		var r membership.Rotation
		if json.Unmarshal(data, &r) != nil {
			im.skipped++
			continue
		}
		rotations = append(rotations, r)
	}
	sort.SliceStable(rotations, func(i, j int) bool { return rotations[i].Epoch < rotations[j].Epoch })
	var entries []importEntry
	for _, r := range rotations {
		entries = append(entries, func(ctx context.Context, chain membership.Chain) error {
			if r.Epoch >= 1 && r.Epoch <= chain.Epoch() {
				if chain.Rotations[r.Epoch-1] != r {
					return fmt.Errorf("%w: a different rotation exists at epoch %d", errConflict, r.Epoch)
				}
				return nil
			}
			if _, err := membership.VerifyChain(chain.Roots[0], append(append([]membership.Rotation{}, chain.Rotations...), r)); err != nil {
				return err
			}
			data, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err = putStatement(ctx, im.tx, im.network, kindRotation, strconv.FormatInt(r.Epoch, 10), data); err != nil {
				return err
			}
			if _, err = im.tx.ExecContext(ctx, `DELETE FROM statements WHERE network_id = ? AND kind = ?`, im.network, kindAttestation); err != nil {
				return err
			}
			return replaceAdmissions(ctx, im.tx, chain, nil, nil)
		})
	}
	// Each pass applies the rotations in order, so one pass settles them.
	return im.settle(ctx, entries, false)
}

func (im *importer) attestation(ctx context.Context, chain membership.Chain, raw json.RawMessage) error {
	var a membership.Attestation
	if err := json.Unmarshal(raw, &a); err != nil {
		return fmt.Errorf("%w: %v", errInvalid, err)
	}
	if err := chain.VerifyAttestation(a); err != nil {
		return err
	}
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = putStatement(ctx, im.tx, im.network, kindAttestation, a.HostPublicKey, data)
	return err
}

func (im *importer) person(ctx context.Context, chain membership.Chain, raw json.RawMessage) error {
	var entry struct {
		Admission  json.RawMessage `json:"admission"`
		Membership json.RawMessage `json:"membership"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return fmt.Errorf("%w: %v", errInvalid, err)
	}
	var proof membership.PersonProof
	if present(entry.Admission) {
		proof.Admission = new(membership.PersonAdmission)
		if err := json.Unmarshal(entry.Admission, proof.Admission); err != nil {
			return fmt.Errorf("%w: %v", errInvalid, err)
		}
	}
	if present(entry.Membership) {
		proof.Membership = new(membership.PersonMembership)
		if err := json.Unmarshal(entry.Membership, proof.Membership); err != nil {
			return fmt.Errorf("%w: %v", errInvalid, err)
		}
	}
	if (proof.Admission == nil) == (proof.Membership == nil) {
		return fmt.Errorf("%w: a person has exactly one admission or membership", errInvalid)
	}
	return im.s.admitPersonIn(ctx, im.tx, chain, proof, true)
}

// member adds a member host the coordinator lacks, verified as a join is.
// A joiner's asserted time does not prove an expired invite was redeemed. Its
// address and candidates stay empty until its own sync. A host admitted by
// public key whose admission the new root renewed has it replaced.
func (im *importer) member(ctx context.Context, chain membership.Chain, raw json.RawMessage) error {
	var entry struct {
		HostID     string          `json:"host_id"`
		Membership json.RawMessage `json:"membership"`
		Admission  json.RawMessage `json:"admission"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return fmt.Errorf("%w: %v", errInvalid, err)
	}
	revoked, err := revokedOf(ctx, im.tx, chain)
	if err != nil {
		return err
	}
	tx, network := im.tx, im.network
	switch {
	case present(entry.Membership) && !present(entry.Admission):
		var m membership.Membership
		if err = json.Unmarshal(entry.Membership, &m); err != nil {
			return fmt.Errorf("%w: %v", errInvalid, err)
		}
		attested, err := attestationsOf(ctx, tx, chain)
		if err != nil {
			return err
		}
		id, err := chain.ValidMember(m, attested)
		if err != nil {
			return err
		}
		if entry.HostID != "" && entry.HostID != id {
			return fmt.Errorf("%w: membership is for a different host", errInvalid)
		}
		if revoked.Excludes(m) || !chain.SignerValid(m.InviteMessage(), m.InviteSignature) {
			return fmt.Errorf("%w: host or invite has been revoked, or the host has left", errForbidden)
		}
		var user string
		err = tx.QueryRowContext(ctx, `SELECT host_id FROM members WHERE network_id = ? AND invite_public_key = ?`, network, m.InvitePublicKey).Scan(&user)
		switch {
		case err == nil && user == id:
			return nil
		case err == nil:
			return fmt.Errorf("%w: invite has already been used", errConflict)
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if exists, err := memberExists(ctx, tx, network, id); err != nil || exists {
			if err == nil {
				err = fmt.Errorf("%w: host is already a member through another invite", errConflict)
			}
			return err
		}
		expires, _ := membership.ParseTime(m.InviteExpiresAt)
		if !expires.After(im.s.Now()) {
			// A current-root attestation independently authorizes this host.
			// Otherwise recovery needs a fresh administrator admission.
			if a, ok := attested[m.HostPublicKey]; !ok || a.Member != m.Member {
				return fmt.Errorf("%w: missing membership has an expired invite; obtain a fresh host admission", errForbidden)
			}
		}
		if err = im.s.checkMembers(ctx, tx, network); err != nil {
			return err
		}
		return im.s.insertMember(ctx, tx, id, m, "", []string{})
	case present(entry.Admission) && !present(entry.Membership):
		var a membership.HostAdmission
		if err = json.Unmarshal(entry.Admission, &a); err != nil {
			return fmt.Errorf("%w: %v", errInvalid, err)
		}
		id, err := chain.VerifyHostAdmission(a)
		if err != nil {
			return err
		}
		if entry.HostID != "" && entry.HostID != id {
			return fmt.Errorf("%w: admission is for a different host", errInvalid)
		}
		if revoked.ExcludesHost(a.HostPublicKey, "") || !chain.SignerValid(a.Message(), a.Signature) {
			return fmt.Errorf("%w: host has been revoked or has left", errForbidden)
		}
		stored, err := hostAdmissionFor(ctx, tx, network, id)
		if err != nil {
			return err
		}
		if stored == nil || *stored != a {
			if err = requireCurrent(ctx, tx, chain, a.Signature); err != nil {
				return err
			}
		}
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		var membershipColumn, admission string
		err = tx.QueryRowContext(ctx, `SELECT membership, COALESCE(admission, '') FROM members WHERE network_id = ? AND host_id = ?`, network, id).Scan(&membershipColumn, &admission)
		if err == nil {
			if membershipColumn != "" || membership.EqualRaw(json.RawMessage(admission), data) {
				return nil
			}
			var current membership.HostAdmission
			if json.Unmarshal([]byte(admission), &current) == nil {
				if _, err := chain.VerifyHostAdmission(current); err == nil {
					return nil // the stored admission is still valid
				}
			}
			// A renewed admission replaces the stored one.
			if _, err = tx.ExecContext(ctx, `UPDATE members SET admission = ? WHERE network_id = ? AND host_id = ?`, string(data), network, id); err != nil {
				return err
			}
			return putHostAdmission(ctx, tx, network, a.HostPublicKey, data)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err = im.s.checkMembers(ctx, tx, network); err != nil {
			return err
		}
		if err = putHostAdmission(ctx, tx, network, a.HostPublicKey, data); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at, admission) VALUES (?, ?, ?, '', '', ?, ?)`, network, id, admissionPrefix+a.HostPublicKey, membership.Timestamp(im.s.Now()), string(data)); err != nil {
			return err
		}
		return putCandidates(ctx, tx, network, id, []string{})
	}
	return fmt.Errorf("%w: a member has exactly one membership or admission", errInvalid)
}

func memberExists(ctx context.Context, tx *sql.Tx, network, host string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM members WHERE network_id = ? AND host_id = ?`, network, host).Scan(&n)
	return n > 0, err
}

func putHostAdmission(ctx context.Context, tx *sql.Tx, network, hostKey string, data []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET statement = excluded.statement`, network, kindHostAdmission, hostKey, string(data))
	return err
}

// attestationsOf returns the stored attestations valid at the chain's
// current epoch, by host key.
func attestationsOf(ctx context.Context, tx *sql.Tx, chain membership.Chain) (map[string]membership.Attestation, error) {
	raw, err := statementsOf(ctx, tx, chain.NetworkID, kindAttestation)
	if err != nil {
		return nil, err
	}
	out := map[string]membership.Attestation{}
	for _, a := range membership.DecodeRaw[membership.Attestation](raw) {
		if chain.VerifyAttestation(a) == nil {
			out[a.HostPublicKey] = a
		}
	}
	return out, nil
}
