package coord

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Owner access policies (milestone 2b, slice 3). The coordinator keeps the
// newest accepted policy of each person and serves those of current persons
// to every member; hosts verify them again and enforce them.

const kindPolicy = "policy" // subject: person key; the newest accepted version

func (s *Server) policyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v1/networks/{network}/policies", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req struct {
			Policy membership.Policy `json:"policy"`
		}
		if !decode(w, r, &req, "policy") {
			return
		}
		m, err := s.submitPolicy(r.Context(), caller, r.PathValue("network"), req.Policy)
		respond(w, http.StatusOK, m, err)
	})
}

// storedPolicy is the newest accepted policy of a person key.
func storedPolicy(ctx context.Context, tx *sql.Tx, network, key string) (membership.Policy, bool, error) {
	var p membership.Policy
	var data string
	err := tx.QueryRowContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? AND subject = ?`, network, kindPolicy, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return p, false, nil
	}
	if err != nil {
		return p, false, err
	}
	return p, json.Unmarshal([]byte(data), &p) == nil, nil
}

// submitPolicy accepts a policy signed by a current person, within its
// window, at a version above the stored one. An identical resubmission of the
// stored policy is accepted again; any other version that is not higher is a
// conflict, so of several hosts renewing at once, one is accepted and the
// rest take it from the map.
func (s *Server) submitPolicy(ctx context.Context, caller, network string, p membership.Policy) (*membership.Map, error) {
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
	if err = membership.VerifyPolicy(network, p); err != nil {
		return nil, err
	}
	if !membership.PolicyActive(p, time.Now()) {
		return nil, fmt.Errorf("%w: the policy is not within its validity window", errInvalid)
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return nil, err
	}
	persons, err := validPersons(ctx, tx, chain, revoked)
	if err != nil {
		return nil, err
	}
	if _, ok := persons[p.PersonPublicKey]; !ok {
		return nil, fmt.Errorf("%w: the policy owner is not a current person", errForbidden)
	}
	current, ok, err := storedPolicy(ctx, tx, network, p.PersonPublicKey)
	if err != nil {
		return nil, err
	}
	if ok && p.Version <= current.Version {
		if p.Version == current.Version && p.Signature == current.Signature {
			return networkMap(ctx, tx, network) // an identical resubmission
		}
		return nil, fmt.Errorf("%w: policy version %d is not above the current version %d", errConflict, p.Version, current.Version)
	}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO statements VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET statement = excluded.statement`, network, kindPolicy, p.PersonPublicKey, string(data)); err != nil {
		return nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// addPolicies fills the map's policies: the newest accepted policy of every
// current person, ordered by person key.
func addPolicies(ctx context.Context, tx *sql.Tx, m *membership.Map) error {
	m.Policies = []json.RawMessage{}
	chain, err := chainOf(ctx, tx, m.NetworkID)
	if err != nil {
		return err
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return err
	}
	persons, err := validPersons(ctx, tx, chain, revoked)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(persons))
	for key := range persons {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var data string
		err := tx.QueryRowContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? AND subject = ?`, m.NetworkID, kindPolicy, key).Scan(&data)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		m.Policies = append(m.Policies, json.RawMessage(data))
	}
	return nil
}
