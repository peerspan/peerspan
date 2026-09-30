package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

// SaveSession writes a peering session into the database and creates its artifact directory.
func (s Store) SaveSession(sess session.Session) error {
	if !capsule.ValidID(sess.ID) {
		return fmt.Errorf("invalid session id %q", sess.ID)
	}
	if err := os.MkdirAll(s.SessionDir(sess.ID), 0o755); err != nil {
		return err
	}
	body, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.withDB(func(db *sql.DB) error {
		_, err := db.Exec(`
			INSERT INTO sessions (id, created_at, record) VALUES (?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET created_at = excluded.created_at, record = excluded.record
		`, sess.ID, createdAt(sess.CreatedAt), string(body))
		return err
	})
}

// LoadSession reads one peering session.
func (s Store) LoadSession(id string) (session.Session, error) {
	if !capsule.ValidID(id) {
		return session.Session{}, fmt.Errorf("invalid session id %q", id)
	}
	var sess session.Session
	err := s.withDB(func(db *sql.DB) error {
		var body string
		err := db.QueryRow(`SELECT record FROM sessions WHERE id = ?`, id).Scan(&body)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("session %s not found", id)
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(body), &sess)
	})
	return sess, err
}

// ListSessions returns every peering session, oldest first.
func (s Store) ListSessions() ([]session.Session, error) {
	var sessions []session.Session
	err := s.withDB(func(db *sql.DB) error {
		rows, err := db.Query(`SELECT record FROM sessions ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var body string
			if err := rows.Scan(&body); err != nil {
				return err
			}
			var sess session.Session
			if err := json.Unmarshal([]byte(body), &sess); err != nil {
				return err
			}
			sessions = append(sessions, sess)
		}
		return rows.Err()
	})
	return sessions, err
}

// SaveEvidence writes the export bundle to sessions/<id>/evidence.json.
func (s Store) SaveEvidence(id string, evidence session.Evidence) error {
	if !capsule.ValidID(id) {
		return fmt.Errorf("invalid session id %q", id)
	}
	dir := filepath.Join(s.Dir, "sessions", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "evidence.json"), evidence)
}

// SessionDir is the directory that holds a session's artifacts and evidence bundle.
func (s Store) SessionDir(id string) string {
	return filepath.Join(s.Dir, "sessions", id)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
