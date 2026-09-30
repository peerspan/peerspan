package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

// SaveSession writes a peering session under sessions/<id>/session.json.
func (s Store) SaveSession(sess session.Session) error {
	if !capsule.ValidID(sess.ID) {
		return fmt.Errorf("invalid session id %q", sess.ID)
	}
	dir := filepath.Join(s.Dir, "sessions", sess.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "session.json"), sess)
}

// LoadSession reads one peering session.
func (s Store) LoadSession(id string) (session.Session, error) {
	if !capsule.ValidID(id) {
		return session.Session{}, fmt.Errorf("invalid session id %q", id)
	}
	data, err := os.ReadFile(filepath.Join(s.Dir, "sessions", id, "session.json"))
	if errors.Is(err, os.ErrNotExist) {
		return session.Session{}, fmt.Errorf("session %s not found", id)
	}
	if err != nil {
		return session.Session{}, err
	}
	var sess session.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return session.Session{}, err
	}
	return sess, nil
}

// ListSessions returns every peering session.
func (s Store) ListSessions() ([]session.Session, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, "sessions"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sessions []session.Session
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sess, err := s.LoadSession(entry.Name())
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// SessionDir is the directory that holds a session record and its artifacts.
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
