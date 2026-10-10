package coord

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Coordinator moves (milestone 8, slice 3). The network root or a current
// administrator signs a move of one network to another coordinator. The
// coordinator keeps the valid move with the highest sequence and serves it in
// the map; it keeps serving the network after a move away from it.

const kindMove = "move" // subject: empty; the move with the highest sequence

func (s *Server) moveRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v1/networks/{network}/moves", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req struct {
			Move membership.Move `json:"move"`
		}
		if !decode(w, r, &req, "move") {
			return
		}
		m, err := s.submitMove(r.Context(), caller, r.PathValue("network"), req.Move)
		respond(w, http.StatusOK, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/import", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req importRequest
		if !decode(w, r, &req, "name", "root_public_key", "map") {
			return
		}
		status, result, err := s.importNetwork(r.Context(), caller, sourceOf(r.RemoteAddr), req)
		respond(w, status, result, err)
		if err == nil && result.Added > 0 {
			s.relay.changed(result.Map.NetworkID)
		}
	})
}

func (s *Server) submitMove(ctx context.Context, caller, network string, mv membership.Move) (*membership.Map, error) {
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
	if err = submitMoveIn(ctx, tx, chain, mv); err != nil {
		return nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// submitMoveIn stores a valid move whose sequence is higher than the stored
// one; a sequence that is not higher is a conflict.
func submitMoveIn(ctx context.Context, tx *sql.Tx, chain membership.Chain, mv membership.Move) error {
	current, err := currentAdmins(ctx, tx, chain)
	if err != nil {
		return err
	}
	if err = chain.VerifyMove(mv, current); err != nil {
		return err
	}
	stored, ok, err := storedMove(ctx, tx, chain.NetworkID)
	if err != nil {
		return err
	}
	if ok && mv.Sequence <= stored.Sequence {
		return fmt.Errorf("%w: move sequence %d is not above the current sequence %d", errConflict, mv.Sequence, stored.Sequence)
	}
	data, err := json.Marshal(mv)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO statements VALUES (?, ?, '', ?) ON CONFLICT DO UPDATE SET statement = excluded.statement`, chain.NetworkID, kindMove, string(data))
	return err
}

// storedMove returns the stored move. A stored move that no longer decodes
// counts as sequence 0.
func storedMove(ctx context.Context, tx *sql.Tx, network string) (membership.Move, bool, error) {
	var mv membership.Move
	var data string
	err := tx.QueryRowContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? AND subject = ''`, network, kindMove).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return mv, false, nil
	}
	if err != nil {
		return mv, false, err
	}
	if json.Unmarshal([]byte(data), &mv) != nil {
		return membership.Move{}, true, nil
	}
	return mv, true, nil
}

// addMove fills the map's move, served as stored, or null.
func addMove(ctx context.Context, tx *sql.Tx, m *membership.Map) error {
	var data string
	err := tx.QueryRowContext(ctx, `SELECT statement FROM statements WHERE network_id = ? AND kind = ? AND subject = ''`, m.NetworkID, kindMove).Scan(&data)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		m.Move = nil
		return nil
	case err != nil:
		return err
	}
	m.Move = json.RawMessage(data)
	return nil
}
