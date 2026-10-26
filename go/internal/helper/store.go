package helper

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// Resource storage is private to the helper. It contains opaque carrier bytes
// and resource accounting, never the host database or network authority.
type resourceStore struct {
	db *sql.DB
}

func openResources(state *ownedState) (*resourceStore, error) {
	return openResourceDatabase(state, "resources.db")
}

func openResourceDatabase(state *ownedState, name string) (*resourceStore, error) {
	dirfd := int(state.directory.Fd())
	newFile := false
	f, err := protectedFile(dirfd, name, unix.O_RDWR)
	if errors.Is(err, os.ErrNotExist) {
		f, err = protectedFile(dirfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL)
		newFile = err == nil
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	f.Close()
	if err != nil || info.Mode().Perm() != 0600 {
		return nil, errState
	}
	// SQLite may reopen sidecars. Refuse an existing symlink or unprotected
	// sidecar before opening inside the exclusively owned private directory.
	for _, sidecar := range []string{name + "-wal", name + "-shm", name + "-journal"} {
		f, err := protectedFile(dirfd, sidecar, unix.O_RDWR)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		f.Close()
		if err != nil || info.Mode().Perm() != 0600 {
			return nil, errState
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(state.path, name))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	for _, statement := range []string{"PRAGMA busy_timeout = 5000", "PRAGMA foreign_keys = ON", "PRAGMA synchronous = FULL"} {
		if _, err := db.Exec(statement); err != nil {
			return nil, err
		}
	}
	if newFile {
		tx, err := db.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		for _, statement := range []string{
			`CREATE TABLE helper_format (version INTEGER PRIMARY KEY CHECK(version=1));`,
			`INSERT INTO helper_format(version) VALUES(1);`,
			`CREATE TABLE mailboxes (
			 locator TEXT PRIMARY KEY, request_id TEXT NOT NULL,
			 read_cap_hash TEXT NOT NULL, created_at TEXT NOT NULL,
			 expires_at TEXT NOT NULL, expires_unix INTEGER NOT NULL,
			 creator_key TEXT NOT NULL, source_bucket TEXT NOT NULL,
			 account_id TEXT NOT NULL, creation_identity_hash TEXT NOT NULL,
			 state TEXT NOT NULL CHECK(state IN ('active','deleted','expired')),
			 ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes>=0)
			);`,
			`CREATE INDEX mailbox_expiry ON mailboxes(expires_unix);`,
			`CREATE TABLE frames (
			 locator TEXT NOT NULL REFERENCES mailboxes(locator) ON DELETE CASCADE,
			 frame_id TEXT NOT NULL, role TEXT NOT NULL,
			 writer_key TEXT NOT NULL, body BLOB NOT NULL,
			 ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes>=16),
			 PRIMARY KEY(locator,frame_id)
			);`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				return nil, err
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		if err := state.directory.Sync(); err != nil {
			return nil, err
		}
	} else {
		var format int
		if err := db.QueryRow("SELECT version FROM helper_format").Scan(&format); err != nil || format != 1 {
			return nil, errState
		}
		var integrity string
		if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
			return nil, errState
		}
		// Prepare every durable column without rewriting or filling malformed
		// existing state. Runtime record checks validate the signed frame bytes.
		for _, query := range []string{
			"SELECT locator,request_id,read_cap_hash,created_at,expires_at,expires_unix,creator_key,source_bucket,account_id,creation_identity_hash,state,ciphertext_bytes FROM mailboxes LIMIT 0",
			"SELECT locator,frame_id,role,writer_key,body,ciphertext_bytes FROM frames LIMIT 0",
		} {
			rows, err := db.Query(query)
			if err != nil {
				return nil, errState
			}
			rows.Close()
		}
	}
	if err := validateResources(db); err != nil {
		return nil, err
	}
	for _, statement := range []string{"PRAGMA journal_mode = WAL"} {
		if _, err := db.Exec(statement); err != nil {
			return nil, err
		}
	}
	ok = true
	return &resourceStore{db: db}, nil
}

func (s *resourceStore) close() error { return s.db.Close() }

// Expiration and deletion erase carrier bytes in the same transaction that
// releases active/byte quotas. Metadata survives only the fixed tombstone span.
func collectResources(ctx context.Context, tx *sql.Tx, now time.Time) error {
	for _, action := range []struct {
		query string
		value int64
	}{
		{"DELETE FROM frames WHERE locator IN (SELECT locator FROM mailboxes WHERE state='active' AND expires_unix<=?)", now.Unix()},
		{"UPDATE mailboxes SET state='expired',ciphertext_bytes=0 WHERE state='active' AND expires_unix<=?", now.Unix()},
		{"DELETE FROM mailboxes WHERE state!='active' AND expires_unix<=?", now.Unix() - 86400},
	} {
		if _, err := tx.ExecContext(ctx, action.query, action.value); err != nil {
			return err
		}
	}
	return nil
}
