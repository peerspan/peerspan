package coord

import (
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

// Signed revocations, departures, and root rotations. The coordinator verifies
// what it accepts and stores it permanently; hosts verify it again.

const (
	kindRotation    = "rotation"
	kindAttestation = "attestation"
)

// chainOf returns the network's verified root chain, accepting the signatures
// of its administrators, or errNotFound.
func chainOf(ctx context.Context, tx *sql.Tx, network string) (membership.Chain, error) {
	chain, err := rootChainOf(ctx, tx, network)
	if err != nil {
		return chain, err
	}
	state, err := adminStateOf(ctx, tx, chain)
	if err != nil {
		return chain, err
	}
	return chain.WithAdminState(state), nil
}

// rootChainOf returns the network's verified root chain, or errNotFound.
func rootChainOf(ctx context.Context, tx *sql.Tx, network string) (membership.Chain, error) {
	var genesisKey string
	err := tx.QueryRowContext(ctx, `SELECT root_public_key FROM networks WHERE id = ?`, network).Scan(&genesisKey)
	if errors.Is(err, sql.ErrNoRows) {
		return membership.Chain{}, errNotFound
	}
	if err != nil {
		return membership.Chain{}, err
	}
	genesis, err := membership.DecodeKey(genesisKey)
	if err != nil {
		return membership.Chain{}, err
	}
	raw, err := statementsOf(ctx, tx, network, kindRotation)
	if err != nil {
		return membership.Chain{}, err
	}
	rotations := make([]membership.Rotation, len(raw))
	for i, data := range raw {
		if err = json.Unmarshal(data, &rotations[i]); err != nil {
			return membership.Chain{}, err
		}
	}
	sort.Slice(rotations, func(i, j int) bool { return rotations[i].Epoch < rotations[j].Epoch })
	return membership.VerifyChain(genesis, rotations)
}

func statementsOf(ctx context.Context, tx *sql.Tx, network, kind string) ([]json.RawMessage, error) {
	rows, err := tx.QueryContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? ORDER BY subject`, network, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(data))
	}
	return out, rows.Err()
}

// revokedOf collects stored revocations. They were verified on acceptance;
// those an administrator signed are verified again, since a removal with
// revoke_admitted invalidates them.
func revokedOf(ctx context.Context, tx *sql.Tx, chain membership.Chain) (membership.Revoked, error) {
	revoked := membership.NewRevoked()
	rows, err := tx.QueryContext(ctx, `SELECT kind, subject, statement FROM statements WHERE network_id = ? AND kind IN ('host', 'invite', 'leave', 'person', 'unbind')`, chain.NetworkID)
	if err != nil {
		return revoked, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, subject, statement string
		if err = rows.Scan(&kind, &subject, &statement); err != nil {
			return revoked, err
		}
		if chain.AdminSigned(signatureOf(json.RawMessage(statement))) {
			if _, _, err := chain.VerifyRevocation(membership.Revocation{Kind: kind, Statement: json.RawMessage(statement)}); err != nil {
				continue
			}
		}
		revoked.Add(kind, subject)
	}
	return revoked, rows.Err()
}

func revokedHost(ctx context.Context, tx *sql.Tx, chain membership.Chain, hostKey string) (bool, error) {
	revoked, err := revokedOf(ctx, tx, chain)
	return revoked.ExcludesHost(hostKey, ""), err
}

func isMember(ctx context.Context, tx *sql.Tx, network, caller string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM members WHERE network_id = ? AND host_id = ?`, network, caller).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: not a member of this network", errForbidden)
	}
	return nil
}

// putStatement stores a statement once. A repeat of the same subject keeps the
// original; changed reports whether anything was stored.
func putStatement(ctx context.Context, tx *sql.Tx, network, kind, subject string, statement json.RawMessage) (bool, error) {
	result, err := tx.ExecContext(ctx, `INSERT INTO statements VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`, network, kind, subject, string(statement))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}

// dropExcluded removes members that a revocation or departure excludes, or
// whose invite or admission an administrator removed with revoke_admitted
// signed, so they are no longer served, synced, or relayed.
func dropExcluded(ctx context.Context, tx *sql.Tx, chain membership.Chain) error {
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT host_id, membership, COALESCE(admission, '') FROM members WHERE network_id = ?`, chain.NetworkID)
	if err != nil {
		return err
	}
	var drop []string
	for rows.Next() {
		var host, data, admission string
		if err = rows.Scan(&host, &data, &admission); err != nil {
			rows.Close()
			return err
		}
		if data == "" {
			var a membership.HostAdmission
			if json.Unmarshal([]byte(admission), &a) != nil || revoked.ExcludesHost(a.HostPublicKey, "") || !chain.SignerValid(a.Message(), a.Signature) {
				drop = append(drop, host)
			}
			continue
		}
		var m membership.Membership
		if json.Unmarshal([]byte(data), &m) != nil || revoked.Excludes(m) || !chain.SignerValid(m.InviteMessage(), m.InviteSignature) {
			drop = append(drop, host)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, host := range drop {
		if _, err = tx.ExecContext(ctx, `DELETE FROM members WHERE network_id = ? AND host_id = ?`, chain.NetworkID, host); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM member_candidates WHERE network_id = ? AND host_id = ?`, chain.NetworkID, host); err != nil {
			return err
		}
	}
	return nil
}

// addStatements fills a map's rotations, current-epoch attestations, and
// revocations.
func addStatements(ctx context.Context, tx *sql.Tx, m *membership.Map) error {
	m.Rotations, m.Attestations, m.Revocations = []json.RawMessage{}, []json.RawMessage{}, []json.RawMessage{}
	rotations, err := statementsOf(ctx, tx, m.NetworkID, kindRotation)
	if err != nil {
		return err
	}
	// Subjects are decimal epochs; order numerically.
	sort.SliceStable(rotations, func(i, j int) bool { return epochOf(rotations[i]) < epochOf(rotations[j]) })
	m.Rotations = append(m.Rotations, rotations...)
	attestations, err := statementsOf(ctx, tx, m.NetworkID, kindAttestation)
	if err != nil {
		return err
	}
	m.Attestations = append(m.Attestations, attestations...)
	for _, kind := range []string{membership.KindHost, membership.KindInvite, membership.KindLeave, membership.KindPerson, membership.KindUnbind, membership.KindAdmin} {
		raw, err := statementsOf(ctx, tx, m.NetworkID, kind)
		if err != nil {
			return err
		}
		for _, statement := range raw {
			entry, err := json.Marshal(membership.Revocation{Kind: kind, Statement: statement})
			if err != nil {
				return err
			}
			m.Revocations = append(m.Revocations, entry)
		}
	}
	return nil
}

func epochOf(data json.RawMessage) int64 {
	var r struct {
		Epoch int64 `json:"epoch"`
	}
	_ = json.Unmarshal(data, &r)
	return r.Epoch
}

type revocationRequest struct {
	Kind      string          `json:"kind"`
	Statement json.RawMessage `json:"statement"`
}
type leaveRequest struct {
	Statement json.RawMessage `json:"statement"`
}
type rotationRequest struct {
	Rotation     membership.Rotation      `json:"rotation"`
	Attestations []membership.Attestation `json:"attestations"`
	// Admissions are host and person admissions and administrator
	// delegations re-signed by the new root, each a bare statement told
	// apart by host_public_key, delegated_at, or person_public_key.
	Admissions []json.RawMessage `json:"admissions"`
	// Groups renew the current root-signed groups under the new root, at
	// the same version and members. Absent is empty.
	Groups []membership.GroupDefinition `json:"groups"`
}

func (s *Server) governanceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v1/networks/{network}/revocations", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req revocationRequest
		if !decode(w, r, &req, "kind", "statement") {
			return
		}
		m, err := s.revoke(r.Context(), caller, r.PathValue("network"), req)
		respond(w, http.StatusOK, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/leave", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req leaveRequest
		if !decode(w, r, &req, "statement") {
			return
		}
		err := s.leave(r.Context(), caller, r.PathValue("network"), req.Statement)
		respond(w, http.StatusOK, struct{}{}, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/rotations", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req rotationRequest
		data, ok := readBody(w, r)
		if !ok {
			return
		}
		fields := []string{"rotation", "attestations", "admissions", "groups"}
		if raw, err := rawFields(data); err == nil && raw["groups"] == nil {
			fields = fields[:3]
		}
		if err := membership.Strict(data, &req, fields...); err != nil {
			respond(w, 0, nil, fmt.Errorf("%w: %v", errInvalid, err))
			return
		}
		m, err := s.rotate(r.Context(), caller, r.PathValue("network"), req)
		respond(w, http.StatusOK, m, err)
	})
}

func (s *Server) revoke(ctx context.Context, caller, network string, req revocationRequest) (*membership.Map, error) {
	switch req.Kind {
	case membership.KindHost, membership.KindInvite, membership.KindPerson, membership.KindUnbind, membership.KindAdmin:
	default:
		return nil, fmt.Errorf("%w: kind must be host, invite, person, unbind, or admin", errInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if err = isMember(ctx, tx, network, caller); err != nil {
		return nil, err
	}
	if err = revokeIn(ctx, tx, chain, req); err != nil {
		return nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// revokeIn verifies and stores a revocation or administrator removal as the
// revocations route does, then drops the members it excludes.
func revokeIn(ctx context.Context, tx *sql.Tx, chain membership.Chain, req revocationRequest) error {
	network := chain.NetworkID
	kind, subject, err := chain.VerifyRevocation(membership.Revocation{Kind: req.Kind, Statement: req.Statement})
	if err != nil {
		return err
	}
	if kind == membership.KindAdmin {
		if err = putAdminRemoval(ctx, tx, network, subject, req.Statement); err != nil {
			return err
		}
		// The removal may invalidate what the administrator signed.
		if chain, err = chainOf(ctx, tx, network); err != nil {
			return err
		}
	} else {
		if kind == membership.KindPerson {
			// An administrator's role is removed explicitly first.
			current, err := currentAdmins(ctx, tx, chain)
			if err != nil {
				return err
			}
			if current[subject] {
				return fmt.Errorf("%w: that person is a current administrator; remove the administrator role first", errConflict)
			}
		}
		if kind != membership.KindUnbind && kind != membership.KindLeave {
			if err = requireCurrent(ctx, tx, chain, signatureOf(req.Statement)); err != nil {
				return err
			}
		}
		if _, err = putStatement(ctx, tx, network, kind, subject, req.Statement); err != nil {
			return err
		}
	}
	return dropExcluded(ctx, tx, chain)
}

func (s *Server) leave(ctx context.Context, caller, network string, statement json.RawMessage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return mapNotFound(err)
	}
	_, subject, err := chain.VerifyRevocation(membership.Revocation{Kind: membership.KindLeave, Statement: statement})
	if err != nil {
		return err
	}
	key, err := membership.DecodeKey(subject)
	if err != nil {
		return err
	}
	if membership.HostID(key) != caller {
		return fmt.Errorf("%w: a host can only leave for itself", errForbidden)
	}
	if _, err = putStatement(ctx, tx, network, membership.KindLeave, subject, statement); err != nil {
		return err
	}
	if err = dropExcluded(ctx, tx, chain); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) rotate(ctx context.Context, caller, network string, req rotationRequest) (*membership.Map, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if err = isMember(ctx, tx, network, caller); err != nil {
		return nil, err
	}
	if req.Rotation.Epoch >= 1 && req.Rotation.Epoch <= chain.Epoch() {
		if chain.Rotations[req.Rotation.Epoch-1] != req.Rotation {
			return nil, fmt.Errorf("%w: a different rotation exists at epoch %d", errConflict, req.Rotation.Epoch)
		}
		m, err := networkMap(ctx, tx, network)
		return m, err
	}
	next, err := membership.VerifyChain(chain.Roots[0], append(append([]membership.Rotation{}, chain.Rotations...), req.Rotation))
	if err != nil {
		return nil, err
	}
	next.Admins, next.Kept = chain.Admins, chain.Kept
	// Attestations must cover the current members whose invite a root
	// signed, under the new root; those an administrator invited stay valid.
	members, invites, err := memberKeys(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	attested := map[string]bool{}
	for _, a := range req.Attestations {
		if err = next.VerifyAttestation(a); err != nil {
			return nil, err
		}
		member, ok := members[a.HostPublicKey]
		if !ok || member != a.Member || attested[a.HostPublicKey] {
			return nil, fmt.Errorf("%w: attestation for a host that is not a current member", errInvalid)
		}
		attested[a.HostPublicKey] = true
	}
	for key, signature := range invites {
		if !attested[key] && !chain.AdminSigned(signature) {
			return nil, fmt.Errorf("%w: attestations must cover every current member", errInvalid)
		}
	}
	var admissions []json.RawMessage
	var delegations []membership.AdminDelegation
	for _, data := range req.Admissions {
		fields, err := rawFields(data)
		if err != nil {
			return nil, err
		}
		if fields["delegated_at"] == nil {
			admissions = append(admissions, data)
			continue
		}
		var d membership.AdminDelegation
		if err = json.Unmarshal(data, &d); err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalid, err)
		}
		delegations = append(delegations, d)
	}
	if err = rotationDelegations(ctx, tx, chain, next, delegations); err != nil {
		return nil, err
	}
	hostAdmissions, personAdmissions, err := s.rotationAdmissions(ctx, tx, chain, next, admissions)
	if err != nil {
		return nil, err
	}
	if err = rotationGroups(ctx, tx, chain, next, req.Groups); err != nil {
		return nil, err
	}
	rotation, err := json.Marshal(req.Rotation)
	if err != nil {
		return nil, err
	}
	if _, err = putStatement(ctx, tx, network, kindRotation, strconv.FormatInt(req.Rotation.Epoch, 10), rotation); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM statements WHERE network_id = ? AND kind = ?`, network, kindAttestation); err != nil {
		return nil, err
	}
	for _, a := range req.Attestations {
		data, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		if _, err = putStatement(ctx, tx, network, kindAttestation, a.HostPublicKey, data); err != nil {
			return nil, err
		}
	}
	if err = replaceAdmissions(ctx, tx, chain, hostAdmissions, personAdmissions); err != nil {
		return nil, err
	}
	for _, d := range delegations {
		if err = putDelegation(ctx, tx, network, d); err != nil {
			return nil, err
		}
	}
	for _, g := range req.Groups {
		if err = putGroup(ctx, tx, network, g); err != nil {
			return nil, err
		}
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// memberKeys maps each current invite-chain member's host key to its member
// label and invite signature; members admitted by public key are covered by
// admissions instead.
func memberKeys(ctx context.Context, tx *sql.Tx, network string) (map[string]string, map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT membership FROM members WHERE network_id = ? AND membership != ''`, network)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	keys, invites := map[string]string{}, map[string]string{}
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			return nil, nil, err
		}
		var m membership.Membership
		if json.Unmarshal([]byte(data), &m) == nil {
			keys[m.HostPublicKey] = m.Member
			invites[m.HostPublicKey] = m.InviteSignature
		}
	}
	return keys, invites, rows.Err()
}

// mapNotFound turns an unknown network into 403, as for sync, so the
// endpoints do not reveal which networks exist.
func mapNotFound(err error) error {
	if errors.Is(err, errNotFound) {
		return fmt.Errorf("%w: not a member of this network", errForbidden)
	}
	return err
}
