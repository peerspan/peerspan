package host

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *Store) AttachSession(ctx context.Context, req AttachSession) (Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	session, err := attachSession(ctx, tx, req, "")
	if err != nil {
		return Session{}, err
	}
	return session, tx.Commit()
}
func attachSession(ctx context.Context, tx *sql.Tx, req AttachSession, id string) (Session, error) {
	req.Integration = strings.TrimSpace(req.Integration)
	if req.AgentID == "" || req.Integration == "" || len(req.Integration) > 128 {
		return Session{}, fmt.Errorf("%w: agent_id and integration are required; integration must be at most 128 bytes", ErrInvalid)
	}
	if id == "" {
		var err error
		id, err = newID("session")
		if err != nil {
			return Session{}, err
		}
	} else if !validID(id, "session", 16) {
		return Session{}, ErrInvalid
	}
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE id = ?", id).Scan(&exists); err != nil {
		return Session{}, err
	}
	if exists != 0 {
		return Session{}, ErrConflict
	}
	now := time.Now().UTC()
	session := Session{ID: id, AgentID: req.AgentID, Integration: req.Integration, State: SessionAttached, CreatedAt: now, UpdatedAt: now}
	var err error
	var agentID string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM agents WHERE id = ?`, req.AgentID).Scan(&agentID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?)`, session.ID, session.AgentID, session.Integration, session.State, timestamp(now), timestamp(now)); err != nil {
		return Session{}, err
	}
	if err = appendEvent(ctx, tx, "session.attached", session.ID, timestamp(now)); err != nil {
		return Session{}, err
	}
	return session, nil
}

func scanSession(row interface{ Scan(...any) error }) (Session, error) {
	var session Session
	var created, updated string
	if err := row.Scan(&session.ID, &session.AgentID, &session.Integration, &session.State, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return session, ErrNotFound
		}
		return session, err
	}
	var err error
	session.CreatedAt, err = parseTime(created)
	if err != nil {
		return session, err
	}
	session.UpdatedAt, err = parseTime(updated)
	return session, err
}

func (s *Store) Session(ctx context.Context, id string) (Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, `SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE id = ?`, id))
}

func (s *Store) Sessions(ctx context.Context, agentID string) ([]Session, error) {
	if agentID != "" {
		if _, err := s.Agent(ctx, agentID); err != nil {
			return nil, err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE (? = '' OR agent_id = ?) ORDER BY created_at, id`, agentID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Session{}
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, session)
	}
	return items, rows.Err()
}

func (s *Store) DetachSession(ctx context.Context, id string) (Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	session, err := scanSession(tx.QueryRowContext(ctx, `SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE id = ?`, id))
	if err != nil {
		return Session{}, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE adapter_connections SET recoverable = 0,lease_until_ms = 0 WHERE adapter_id IN (SELECT id FROM adapter_credentials WHERE session_id = ?) AND recoverable = 1`, id)
	if err != nil {
		return Session{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Session{}, err
	}
	if session.State == SessionDetached && changed == 0 {
		return session, nil
	}
	session.State, session.UpdatedAt = SessionDetached, time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET state = ?, updated_at = ? WHERE id = ?`, session.State, timestamp(session.UpdatedAt), id); err != nil {
		return Session{}, err
	}
	if err = appendEvent(ctx, tx, "session.detached", id, timestamp(session.UpdatedAt)); err != nil {
		return Session{}, err
	}
	if err = tx.Commit(); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s *Store) Events(ctx context.Context, after int64, limit int) ([]Event, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: after must be nonnegative and limit must be between 1 and 1000", ErrInvalid)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence, kind, subject_id, created_at FROM events WHERE sequence > ? ORDER BY sequence LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Event{}
	for rows.Next() {
		var event Event
		var created string
		if err := rows.Scan(&event.Sequence, &event.Kind, &event.SubjectID, &created); err != nil {
			return nil, err
		}
		event.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		items = append(items, event)
	}
	return items, rows.Err()
}
