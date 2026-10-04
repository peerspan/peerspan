package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS capsules (
	id TEXT PRIMARY KEY,
	created_at TEXT NOT NULL,
	record TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	created_at TEXT NOT NULL,
	record TEXT NOT NULL
);
`

func (s Store) withDB(fn func(*sql.DB) error) error {
	if s.Dir == "" {
		return fmt.Errorf("store directory is empty")
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", filepath.Join(s.Dir, "capsule.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		return err
	}
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	return fn(db)
}

func createdAt(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}
