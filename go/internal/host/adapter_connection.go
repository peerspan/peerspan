package host

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

const adapterConnectionSchema = `
CREATE TABLE adapter_connections (adapter_id TEXT PRIMARY KEY REFERENCES adapter_credentials(id), instance_hash TEXT, lease_until_ms INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT, recoverable INTEGER NOT NULL DEFAULT 0 CHECK(recoverable IN (0,1)));
INSERT INTO adapter_connections(adapter_id) SELECT id FROM adapter_credentials;
PRAGMA user_version = 6;
`

// AdapterAuth proves both the authorization and the bound adapter instance.
type AdapterAuth struct{ Token, Instance string }
type Connection struct {
	AdapterID      string  `json:"adapter_id"`
	SessionID      string  `json:"session_id"`
	State          string  `json:"state"`
	Recoverable    bool    `json:"recoverable"`
	LeaseExpiresAt *string `json:"lease_expires_at"`
	LastSeenAt     *string `json:"last_seen_at"`
}

func adapterAuthority(ctx context.Context, tx *sql.Tx, auth AdapterAuth) (Adapter, Session, error) {
	a, ss, err := credentialAuthority(ctx, tx, auth.Token)
	if err != nil {
		return a, ss, err
	}
	var hash sql.NullString
	var until int64
	var recoverable bool
	if err = tx.QueryRowContext(ctx, `SELECT instance_hash,lease_until_ms,recoverable FROM adapter_connections WHERE adapter_id = ?`, a.ID).Scan(&hash, &until, &recoverable); err != nil {
		return a, ss, err
	}
	if !validID(auth.Instance, "instance", 32) || !hash.Valid || tokenHash(auth.Instance) != hash.String {
		return a, ss, ErrForbidden
	}
	if ss.State == SessionDetached && !recoverable {
		return a, ss, ErrForbidden
	}
	if ss.State != SessionAttached || until <= time.Now().UnixMilli() {
		return a, ss, ErrAdapterOffline
	}
	return a, ss, nil
}

func connectionStatus(ctx context.Context, tx *sql.Tx, a Adapter, ss Session) (Connection, error) {
	var hash, last sql.NullString
	var until int64
	var recoverable bool
	err := tx.QueryRowContext(ctx, `SELECT instance_hash,lease_until_ms,last_seen_at,recoverable FROM adapter_connections WHERE adapter_id = ?`, a.ID).Scan(&hash, &until, &last, &recoverable)
	if err != nil {
		return Connection{}, err
	}
	exp, err := parseTime(a.ExpiresAt)
	if err != nil {
		return Connection{}, err
	}
	c := Connection{AdapterID: a.ID, SessionID: ss.ID, State: "offline", Recoverable: recoverable && hash.Valid && a.RevokedAt == nil && exp.After(time.Now())}
	if last.Valid {
		c.LastSeenAt = &last.String
	}
	if until > 0 {
		at := timestamp(time.UnixMilli(until))
		c.LeaseExpiresAt = &at
	}
	switch {
	case a.RevokedAt != nil:
		c.State = "revoked"
	case !exp.After(time.Now()):
		c.State = "expired"
	case ss.State == SessionDetached && !recoverable:
		c.State = "detached"
	case !hash.Valid:
		c.State = "registered"
	case ss.State == SessionAttached && until > time.Now().UnixMilli():
		c.State = "ready"
	}
	return c, nil
}

func (s *Store) AdapterConnection(ctx context.Context, id string) (Connection, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Connection{}, err
	}
	defer tx.Rollback()
	a, err := readJSON[Adapter](tx.QueryRowContext(ctx, `SELECT record FROM adapter_credentials WHERE id = ?`, id))
	if err != nil {
		return Connection{}, err
	}
	ss, err := scanSession(tx.QueryRowContext(ctx, `SELECT id,agent_id,integration,state,created_at,updated_at FROM sessions WHERE id = ?`, a.SessionID))
	if err != nil {
		return Connection{}, err
	}
	return connectionStatus(ctx, tx, a, ss)
}

func (s *Store) ConnectAdapter(ctx context.Context, token, instance, adapterID, sessionID string) (Connection, error) {
	if !validID(instance, "instance", 32) || !validID(adapterID, "adapter", 16) || !validID(sessionID, "session", 16) {
		return Connection{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Connection{}, err
	}
	defer tx.Rollback()
	a, ss, err := credentialAuthority(ctx, tx, token)
	if err != nil {
		return Connection{}, err
	}
	if a.ID != adapterID || ss.ID != sessionID {
		return Connection{}, ErrForbidden
	}
	var hash sql.NullString
	var until int64
	var recoverable bool
	if err = tx.QueryRowContext(ctx, `SELECT instance_hash,lease_until_ms,recoverable FROM adapter_connections WHERE adapter_id = ?`, a.ID).Scan(&hash, &until, &recoverable); err != nil {
		return Connection{}, err
	}
	if ss.State == SessionDetached && (!hash.Valid || !recoverable) {
		return Connection{}, ErrForbidden
	}
	if hash.Valid && hash.String != tokenHash(instance) {
		return Connection{}, ErrConflict
	}
	now := time.Now()
	expiry, err := parseTime(a.ExpiresAt)
	if err != nil {
		return Connection{}, err
	}
	lease := now.Add(15 * time.Second)
	if expiry.Before(lease) {
		lease = expiry
	}
	at := timestamp(now)
	if ss.State == SessionDetached {
		if _, err = tx.ExecContext(ctx, `UPDATE sessions SET state = 'attached',updated_at = ? WHERE id = ?`, at, ss.ID); err != nil {
			return Connection{}, err
		}
		if err = appendEvent(ctx, tx, "session.reconnected", ss.ID, at); err != nil {
			return Connection{}, err
		}
		ss.State = SessionAttached
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_connections SET instance_hash = ?,lease_until_ms = ?,last_seen_at = ?,recoverable = 1 WHERE adapter_id = ?`, tokenHash(instance), lease.UnixMilli(), at, a.ID); err != nil {
		return Connection{}, err
	}
	if !hash.Valid || until <= now.UnixMilli() {
		if err = appendEvent(ctx, tx, "adapter.connected", a.ID, at); err != nil {
			return Connection{}, err
		}
	}
	c, err := connectionStatus(ctx, tx, a, ss)
	if err != nil {
		return c, err
	}
	return c, tx.Commit()
}

func (s *Store) RotateAdapter(ctx context.Context, id string) (AdapterCredential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AdapterCredential{}, err
	}
	defer tx.Rollback()
	a, err := readJSON[Adapter](tx.QueryRowContext(ctx, `SELECT record FROM adapter_credentials WHERE id = ?`, id))
	if err != nil {
		return AdapterCredential{}, err
	}
	ss, err := scanSession(tx.QueryRowContext(ctx, `SELECT id,agent_id,integration,state,created_at,updated_at FROM sessions WHERE id = ?`, a.SessionID))
	if err != nil {
		return AdapterCredential{}, err
	}
	c, err := connectionStatus(ctx, tx, a, ss)
	if err != nil {
		return AdapterCredential{}, err
	}
	if a.RevokedAt != nil || c.State == "expired" || c.State == "detached" {
		return AdapterCredential{}, ErrForbidden
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return AdapterCredential{}, err
	}
	token := "token_" + hex.EncodeToString(random)
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_credentials SET token_hash = ? WHERE id = ?`, tokenHash(token), a.ID); err != nil {
		return AdapterCredential{}, err
	}
	if err = appendEvent(ctx, tx, "adapter.credential_rotated", a.ID, timestamp(time.Now())); err != nil {
		return AdapterCredential{}, err
	}
	return AdapterCredential{Adapter: a, Token: token}, tx.Commit()
}

func adapterConnectionRoutes(mux *http.ServeMux, s *Store, auth func(*http.Request) AdapterAuth) {
	mux.HandleFunc("POST /adapter/v1/connect", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			InstanceID string `json:"instance_id"`
			AdapterID  string `json:"adapter_id"`
			SessionID  string `json:"session_id"`
		}
		if !decode(w, r, &body, "instance_id", "adapter_id", "session_id") {
			return
		}
		c, err := s.ConnectAdapter(r.Context(), auth(r).Token, body.InstanceID, body.AdapterID, body.SessionID)
		respond(w, 200, c, err)
	})
}
func localConnectionRoutes(mux *http.ServeMux, s *Store) {
	mux.HandleFunc("GET /v1/adapters/{id}/connection", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.AdapterConnection(r.Context(), r.PathValue("id"))
		respond(w, 200, c, err)
	})
	mux.HandleFunc("POST /v1/adapters/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.RotateAdapter(r.Context(), r.PathValue("id"))
		respond(w, 200, c, err)
	})
}

var ErrAdapterOffline = errors.New("adapter connection is not ready")
