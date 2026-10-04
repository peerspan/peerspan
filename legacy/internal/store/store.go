// Package store persists capsule and session records in a local SQLite database.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
)

// Store is the local database at <dir>/capsule.db.
// Workspace files, command logs, session artifacts, and evidence bundles stay on disk beside it.
type Store struct {
	Dir string
}

// Save writes c, replacing any existing record for the same id.
func (s Store) Save(c capsule.Capsule) error {
	if !capsule.ValidID(c.ID) {
		return fmt.Errorf("invalid capsule id %q", c.ID)
	}
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.withDB(func(db *sql.DB) error {
		_, err := db.Exec(`
			INSERT INTO capsules (id, created_at, record) VALUES (?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET created_at = excluded.created_at, record = excluded.record
		`, c.ID, createdAt(c.CreatedAt), string(body))
		return err
	})
}

// Load reads one capsule record.
func (s Store) Load(id string) (capsule.Capsule, error) {
	if !capsule.ValidID(id) {
		return capsule.Capsule{}, fmt.Errorf("invalid capsule id %q", id)
	}
	var c capsule.Capsule
	err := s.withDB(func(db *sql.DB) error {
		var body string
		err := db.QueryRow(`SELECT record FROM capsules WHERE id = ?`, id).Scan(&body)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("capsule %s not found", id)
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(body), &c)
	})
	return c, err
}

// List returns every capsule record, oldest first.
func (s Store) List() ([]capsule.Capsule, error) {
	var capsules []capsule.Capsule
	err := s.withDB(func(db *sql.DB) error {
		rows, err := db.Query(`SELECT record FROM capsules ORDER BY created_at, id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var body string
			if err := rows.Scan(&body); err != nil {
				return err
			}
			var c capsule.Capsule
			if err := json.Unmarshal([]byte(body), &c); err != nil {
				return err
			}
			capsules = append(capsules, c)
		}
		return rows.Err()
	})
	return capsules, err
}
