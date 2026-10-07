package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE identity (
 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
 private_key BLOB NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE agents (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL UNIQUE,
 owner TEXT NOT NULL,
 capabilities TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE sessions (
 id TEXT PRIMARY KEY,
 agent_id TEXT NOT NULL REFERENCES agents(id),
 integration TEXT NOT NULL,
 state TEXT NOT NULL CHECK (state IN ('attached', 'detached')),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX sessions_agent ON sessions(agent_id);
CREATE TABLE events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL,
 subject_id TEXT NOT NULL,
 created_at TEXT NOT NULL
);
PRAGMA user_version = 1;
`

// Store owns one host state directory. A process lock prevents two daemons from
// claiming the same host identity and managing its sessions concurrently.
type Store struct {
	db         *sql.DB
	lock       *os.File
	dir        string
	identity   Identity
	privateKey ed25519.PrivateKey
	closeOnce  sync.Once
	closeErr   error
	// Immutable startup deadlines give previously bound instances time to reconnect.
	adapterRecoveryUntil map[string]time.Time

	coordination sync.Mutex // guards advertise and interval
	advertise    string
	interval     time.Duration
	syncing      sync.Mutex // serializes coordinator syncs and map application

	peer peerTransport // the daemon's UDP socket and cached QUIC connections
	// relayWake wakes RunRelays when this host creates or joins a network, so it
	// becomes reachable through the new coordinator without waiting to poll.
	relayWake chan struct{}

	retry outboundRetry // automatic retry state for uncertain sends
	agent personAgent   // the ssh-agent for policy renewal
}

func Open(ctx context.Context, dir string) (_ *Store, err error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: state directory is empty", ErrInvalid)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("state directory must be a private directory (mode 0700): %s", dir)
	}
	s := &Store{dir: dir, relayWake: make(chan struct{}, 1)}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	s.lock, err = privateFile(filepath.Join(dir, "host.lock"))
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("host state is already in use: %w", err)
	}
	dbPath := filepath.Join(dir, "host.db")
	f, err := privateFile(dbPath)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: dbPath}).String()
	s.db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s.db.SetMaxOpenConns(1)
	if _, err = s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = FULL;`); err != nil {
		return nil, err
	}
	var version int
	if err = s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return nil, err
	}
	if version < 0 || version > 8 {
		return nil, fmt.Errorf("unsupported host database version: %d", version)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if version == 0 {
		if _, err = tx.ExecContext(ctx, schema); err != nil {
			return nil, err
		}
	}
	if version < 2 {
		if _, err = tx.ExecContext(ctx, peerSchema); err != nil {
			return nil, err
		}
	}
	if version < 3 {
		if _, err = tx.ExecContext(ctx, networkSchema); err != nil {
			return nil, err
		}
	}
	if version < 4 {
		if _, err = tx.ExecContext(ctx, adapterSchema); err != nil {
			return nil, err
		}
	}
	var key []byte
	if version < 5 {
		if _, err = tx.ExecContext(ctx, adapterOutboundSchema); err != nil {
			return nil, err
		}
	}
	if version < 6 {
		if _, err = tx.ExecContext(ctx, adapterConnectionSchema); err != nil {
			return nil, err
		}
	}
	if version < 7 {
		if _, err = tx.ExecContext(ctx, statementsSchema); err != nil {
			return nil, err
		}
	}
	if version < 8 {
		if _, err = tx.ExecContext(ctx, accessBlocksSchema); err != nil {
			return nil, err
		}
	}
	var created string
	err = tx.QueryRowContext(ctx, `SELECT private_key, created_at FROM identity WHERE singleton = 1`).Scan(&key, &created)
	if errors.Is(err, sql.ErrNoRows) {
		_, private, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			return nil, keyErr
		}
		key, created = private, timestamp(time.Now())
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity VALUES (1, ?, ?)`, key, created); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]).Equal(ed25519.PrivateKey(key)) {
		return nil, errors.New("invalid persisted host identity")
	}
	s.privateKey = ed25519.PrivateKey(key)
	public := s.privateKey.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	s.identity = Identity{ID: "host_" + hex.EncodeToString(digest[:]), PublicKey: base64.StdEncoding.EncodeToString(public)}
	s.identity.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	// Leases never survive restart. Only a bound instance can recover its attachment.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM sessions WHERE state = 'attached'`)
	if err != nil {
		return nil, err
	}
	var stale []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		stale = append(stale, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	now := timestamp(time.Now())
	if _, err = tx.ExecContext(ctx, `UPDATE sessions SET state = 'detached', updated_at = ? WHERE state = 'attached'`, now); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_connections SET lease_until_ms = 0`); err != nil {
		return nil, err
	}
	for _, id := range stale {
		if err = appendEvent(ctx, tx, "session.disconnected", id, now); err != nil {
			return nil, err
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT adapter_id FROM adapter_connections WHERE instance_hash IS NOT NULL AND recoverable = 1`)
	if err != nil {
		return nil, err
	}
	var recovering []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		recovering = append(recovering, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.adapterRecoveryUntil = make(map[string]time.Time, len(recovering))
	deadline := time.Now().Add(adapterLeaseDuration)
	for _, id := range recovering {
		s.adapterRecoveryUntil[id] = deadline
	}
	return s, nil
}

func privateFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("host state file must be private and regular: %s", path)
	}
	return f, nil
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.closePeerTransport()
		if s.db != nil {
			s.closeErr = errors.Join(s.closeErr, s.db.Close())
		}
		if s.lock != nil {
			s.closeErr = errors.Join(s.closeErr, s.lock.Close())
		}
	})
	return s.closeErr
}

func (s *Store) Identity() Identity { return s.identity }
func (s *Store) SocketPath() string { return filepath.Join(s.dir, "admin.sock") }

func newID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

func timestamp(t time.Time) string          { return t.UTC().Format(time.RFC3339Nano) }
func parseTime(t string) (time.Time, error) { return time.Parse(time.RFC3339Nano, t) }
func appendEvent(ctx context.Context, tx *sql.Tx, kind, subject, at string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO events (kind, subject_id, created_at) VALUES (?, ?, ?)`, kind, subject, at)
	return err
}

func (s *Store) RegisterAgent(ctx context.Context, req RegisterAgent) (Agent, error) {
	req.Name, req.Owner = strings.TrimSpace(req.Name), strings.TrimSpace(req.Owner)
	if req.Name == "" || req.Owner == "" {
		return Agent{}, fmt.Errorf("%w: name and owner are required", ErrInvalid)
	}
	if len(req.Name) > 128 || len(req.Owner) > 128 {
		return Agent{}, fmt.Errorf("%w: name and owner must be at most 128 bytes", ErrInvalid)
	}
	caps := make([]string, 0, len(req.Capabilities))
	seen := map[string]bool{}
	for _, capability := range req.Capabilities {
		capability = strings.TrimSpace(capability)
		if capability == "" || len(capability) > 256 {
			return Agent{}, fmt.Errorf("%w: invalid capability name", ErrInvalid)
		}
		if !seen[capability] {
			caps = append(caps, capability)
			seen[capability] = true
		}
	}
	id, err := newID("agent")
	if err != nil {
		return Agent{}, err
	}
	a := Agent{ID: id, Name: req.Name, Owner: req.Owner, Capabilities: caps, CreatedAt: time.Now().UTC()}
	encoded, err := json.Marshal(caps)
	if err != nil {
		return Agent{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Agent{}, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE name = ?`, a.Name).Scan(&exists); err != nil {
		return Agent{}, err
	}
	if exists != 0 {
		return Agent{}, fmt.Errorf("%w: agent name already exists", ErrConflict)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO agents VALUES (?, ?, ?, ?, ?)`, a.ID, a.Name, a.Owner, string(encoded), timestamp(a.CreatedAt)); err != nil {
		return Agent{}, err
	}
	if err = appendEvent(ctx, tx, "agent.registered", a.ID, timestamp(a.CreatedAt)); err != nil {
		return Agent{}, err
	}
	if err = tx.Commit(); err != nil {
		return Agent{}, err
	}
	return a, nil
}

func scanAgent(row interface{ Scan(...any) error }) (Agent, error) {
	var a Agent
	var caps, created string
	if err := row.Scan(&a.ID, &a.Name, &a.Owner, &caps, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return a, ErrNotFound
		}
		return a, err
	}
	if err := json.Unmarshal([]byte(caps), &a.Capabilities); err != nil {
		return a, err
	}
	var err error
	a.CreatedAt, err = parseTime(created)
	return a, err
}

func (s *Store) Agent(ctx context.Context, id string) (Agent, error) {
	return scanAgent(s.db.QueryRowContext(ctx, `SELECT id, name, owner, capabilities, created_at FROM agents WHERE id = ?`, id))
}

func (s *Store) Agents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, owner, capabilities, created_at FROM agents ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, a)
	}
	return items, rows.Err()
}
