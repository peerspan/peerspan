package coord

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Administrators and groups (milestone 2b, slice 2). The root delegates and
// removes administrators; administrators sign everything else the root may.
// The coordinator verifies signers against its own view and accepts new
// administrator-signed statements only from current administrators; hosts
// verify everything again.

const (
	kindDelegation = "admin_delegation" // subject: person key; the latest delegation
	kindGroup      = "group"            // subject: name and zero-padded version; every version
)

// adminStateOf verifies the stored delegations and removals.
func adminStateOf(ctx context.Context, tx *sql.Tx, chain membership.Chain) (membership.AdminState, error) {
	delegations, err := statementsOf(ctx, tx, chain.NetworkID, kindDelegation)
	if err != nil {
		return membership.AdminState{}, err
	}
	removals, err := statementsOf(ctx, tx, chain.NetworkID, membership.KindAdmin)
	if err != nil {
		return membership.AdminState{}, err
	}
	return chain.Administrators(membership.DecodeRaw[membership.AdminDelegation](delegations), membership.DecodeRaw[membership.AdminRemoval](removals)), nil
}

// currentAdmins returns administrators that are current now: delegated at the
// current epoch, not removed, and valid, unremoved persons.
func currentAdmins(ctx context.Context, tx *sql.Tx, chain membership.Chain) (map[string]bool, error) {
	state, err := adminStateOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	persons, err := validPersons(ctx, tx, chain, revoked)
	if err != nil {
		return nil, err
	}
	current := map[string]bool{}
	for key := range state.Current {
		if _, ok := persons[key]; ok {
			current[key] = true
		}
	}
	return current, nil
}

// requireCurrent refuses a newly submitted, already verified statement whose
// administrator signer is no longer a current administrator. Statements an
// administrator signed while current stay valid, but a removed administrator
// cannot add new ones here.
func requireCurrent(ctx context.Context, tx *sql.Tx, chain membership.Chain, signature string) error {
	if !chain.AdminSigned(signature) {
		return nil
	}
	current, err := currentAdmins(ctx, tx, chain)
	if err != nil {
		return err
	}
	if !current[membership.SignerOf(signature)] {
		return fmt.Errorf("%w: signer is not a current administrator", errForbidden)
	}
	return nil
}

func signatureOf(statement json.RawMessage) string {
	var s struct {
		Signature string `json:"signature"`
	}
	_ = json.Unmarshal(statement, &s)
	return s.Signature
}

func groupSubject(name string, version int64) string { return fmt.Sprintf("%s %020d", name, version) }

// groupsOf returns the newest valid definition per name.
func groupsOf(ctx context.Context, tx *sql.Tx, chain membership.Chain) (map[string]membership.GroupDefinition, error) {
	raw, err := statementsOf(ctx, tx, chain.NetworkID, kindGroup)
	if err != nil {
		return nil, err
	}
	return chain.NewestGroups(membership.DecodeRaw[membership.GroupDefinition](raw)), nil
}

// addAdmins fills the map's delegations and groups. Delegations include
// removed administrators, whose statements may stay valid; the removals are
// served with the revocations.
func addAdmins(ctx context.Context, tx *sql.Tx, m *membership.Map) error {
	m.Admins, m.Groups = []json.RawMessage{}, []json.RawMessage{}
	chain, err := chainOf(ctx, tx, m.NetworkID)
	if err != nil {
		return err
	}
	state, err := adminStateOf(ctx, tx, chain)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(state.Delegations))
	for key := range state.Delegations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		data, err := json.Marshal(state.Delegations[key])
		if err != nil {
			return err
		}
		m.Admins = append(m.Admins, data)
	}
	groups, err := groupsOf(ctx, tx, chain)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	// A deletion (no members) is served too, so hosts drop the group.
	for _, name := range names {
		data, err := json.Marshal(groups[name])
		if err != nil {
			return err
		}
		m.Groups = append(m.Groups, data)
	}
	return nil
}

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v1/networks/{network}/admins", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req struct {
			Delegation membership.AdminDelegation `json:"delegation"`
		}
		if !decode(w, r, &req, "delegation") {
			return
		}
		m, err := s.delegate(r.Context(), caller, r.PathValue("network"), req.Delegation)
		respond(w, http.StatusOK, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/admin-removals", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req leaveRequest
		if !decode(w, r, &req, "statement") {
			return
		}
		m, err := s.revoke(r.Context(), caller, r.PathValue("network"), revocationRequest{Kind: membership.KindAdmin, Statement: req.Statement})
		respond(w, http.StatusOK, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/groups", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req struct {
			Group membership.GroupDefinition `json:"group"`
		}
		if !decode(w, r, &req, "group") {
			return
		}
		m, err := s.defineGroup(r.Context(), caller, r.PathValue("network"), req.Group)
		respond(w, http.StatusOK, m, err)
	})
}

func (s *Server) delegate(ctx context.Context, caller, network string, d membership.AdminDelegation) (*membership.Map, error) {
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
	key, err := chain.VerifyDelegation(d)
	if err != nil {
		return nil, err
	}
	if d.Epoch != chain.Epoch() {
		return nil, fmt.Errorf("%w: delegation must be at the current epoch", errInvalid)
	}
	state, err := adminStateOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	if _, removed := state.Removals[key]; removed {
		return nil, fmt.Errorf("%w: administrator removal is permanent for this key", errForbidden)
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	persons, err := validPersons(ctx, tx, chain, revoked)
	if err != nil {
		return nil, err
	}
	if _, ok := persons[key]; !ok {
		return nil, fmt.Errorf("%w: person is not admitted to this network", errForbidden)
	}
	// The first delegation at an epoch is kept; one at a newer epoch
	// replaces an older one.
	if previous, ok := state.Delegations[key]; !ok || previous.Epoch < d.Epoch {
		if err = putDelegation(ctx, tx, network, d); err != nil {
			return nil, err
		}
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

func putDelegation(ctx context.Context, tx *sql.Tx, network string, d membership.AdminDelegation) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET statement = excluded.statement`, network, kindDelegation, d.PersonPublicKey, string(data))
	return err
}

// putAdminRemoval stores one removal per key. A repeat of the stored removal
// is accepted; a removal with revoke_admitted may replace a plain one, as an
// escalation; any other second removal is a conflict.
func putAdminRemoval(ctx context.Context, tx *sql.Tx, network, subject string, statement json.RawMessage) error {
	var next membership.AdminRemoval
	if err := json.Unmarshal(statement, &next); err != nil {
		return err
	}
	var stored string
	err := tx.QueryRowContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? AND subject = ?`, network, membership.KindAdmin, subject).Scan(&stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = putStatement(ctx, tx, network, membership.KindAdmin, subject, statement)
		return err
	case err != nil:
		return err
	}
	if membership.EqualRaw(json.RawMessage(stored), statement) {
		return nil
	}
	var previous membership.AdminRemoval
	if json.Unmarshal([]byte(stored), &previous) != nil || previous.RevokeAdmitted || !next.RevokeAdmitted {
		return fmt.Errorf("%w: this administrator has already been removed", errConflict)
	}
	_, err = tx.ExecContext(ctx, `UPDATE statements SET statement = ? WHERE network_id = ? AND kind = ? AND subject = ?`, string(statement), network, membership.KindAdmin, subject)
	return err
}

func (s *Server) defineGroup(ctx context.Context, caller, network string, g membership.GroupDefinition) (*membership.Map, error) {
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
	if _, err = chain.VerifyGroup(g); err != nil {
		return nil, err
	}
	groups, err := groupsOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	if current, ok := groups[g.Name]; ok && g.Version == current.Version && renewal(chain, current, g) {
		// The current root renews a group at the same version.
	} else if ok && g.Version <= current.Version {
		stored, _ := json.Marshal(current)
		if g.Version == current.Version && membership.EqualRaw(stored, data) {
			m, err := networkMap(ctx, tx, network) // a retried submission
			return m, err
		}
		return nil, fmt.Errorf("%w: group %s is already at version %d", errConflict, g.Name, current.Version)
	}
	if err = requireCurrent(ctx, tx, chain, g.Signature); err != nil {
		return nil, err
	}
	// Replace any invalid statement, or the renewed one, at this version.
	if err = putGroup(ctx, tx, network, g); err != nil {
		return nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// rotationDelegations verifies delegations re-signed at the new epoch. They
// must cover every current administrator.
func rotationDelegations(ctx context.Context, tx *sql.Tx, chain, next membership.Chain, delegations []membership.AdminDelegation) error {
	current, err := currentAdmins(ctx, tx, chain)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, d := range delegations {
		key, err := next.VerifyDelegation(d)
		if err != nil {
			return err
		}
		if d.Epoch != next.Epoch() || !current[key] || seen[key] {
			return fmt.Errorf("%w: delegation for a person that is not a current administrator", errInvalid)
		}
		seen[key] = true
	}
	if len(seen) != len(current) {
		return fmt.Errorf("%w: delegations must cover every current administrator", errInvalid)
	}
	return nil
}

func putGroup(ctx context.Context, tx *sql.Tx, network string, g membership.GroupDefinition) error {
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET statement = excluded.statement`, network, kindGroup, groupSubject(g.Name, g.Version), string(data))
	return err
}

// renewal reports whether next renews current: the same version and members,
// signed by the chain's current root.
func renewal(chain membership.Chain, current, next membership.GroupDefinition) bool {
	signer, err := chain.VerifySigned(next.Message(), next.Signature)
	if err != nil || signer != chain.CurrentPublicKey() || next.Version != current.Version || len(next.Members) != len(current.Members) {
		return false
	}
	for i := range next.Members {
		if next.Members[i] != current.Members[i] {
			return false
		}
	}
	return true
}

// rotationGroups verifies renewals of the current root-signed groups by the
// new root; they must cover every such group. Groups an administrator
// signed stay valid.
func rotationGroups(ctx context.Context, tx *sql.Tx, chain, next membership.Chain, renewals []membership.GroupDefinition) error {
	groups, err := groupsOf(ctx, tx, chain)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, g := range renewals {
		current, ok := groups[g.Name]
		if _, err := next.VerifyGroup(g); err != nil {
			return err
		}
		if !ok || seen[g.Name] || chain.AdminSigned(current.Signature) || !renewal(next, current, g) {
			return fmt.Errorf("%w: group renewal for a group that is not current and root-signed", errInvalid)
		}
		seen[g.Name] = true
	}
	for name, g := range groups {
		if !seen[name] && !chain.AdminSigned(g.Signature) {
			return fmt.Errorf("%w: renewals must cover every root-signed group", errInvalid)
		}
	}
	return nil
}
