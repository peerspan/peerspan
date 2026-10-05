// Package coord implements capsule-coord, the coordination service. It stores
// signed membership chains, enforces single use of invite keys, records
// advertised addresses, and serves network maps. It is trusted for
// availability only: hosts verify every chain they receive.
package coord

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), private_key BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE networks (id TEXT PRIMARY KEY, name TEXT NOT NULL, root_public_key TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE members (
 network_id TEXT NOT NULL REFERENCES networks(id),
 host_id TEXT NOT NULL,
 invite_public_key TEXT NOT NULL,
 membership TEXT NOT NULL,
 address TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY (network_id, host_id),
 UNIQUE (network_id, invite_public_key)
);
PRAGMA user_version = 1;
`

var (
	errInvalid   = errors.New("invalid request")
	errForbidden = errors.New("forbidden")
	errNotFound  = errors.New("not found")
	errConflict  = errors.New("conflict")
)

// Identity is the coordinator's public identity, pinned by hosts.
type Identity struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// Server owns one coordinator state directory.
type Server struct {
	db        *sql.DB
	lock      *os.File
	key       ed25519.PrivateKey
	identity  Identity
	Now       func() time.Time
	closeOnce sync.Once
	closeErr  error
}

func DefaultStateDir() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", errors.New("XDG_STATE_HOME must be an absolute path")
		}
		return filepath.Join(dir, "capsule", "coord"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "capsule", "coord"), nil
}

func privateDir(dir string, create bool) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("state directory is empty")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if create {
		if err = os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("state directory must be a private directory (mode 0700): %s", dir)
	}
	return dir, nil
}

func privateFile(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
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
		return nil, fmt.Errorf("coordinator state file must be private and regular: %s", path)
	}
	return f, nil
}

func openDB(path string, readOnly bool) (*sql.DB, error) {
	u := &url.URL{Scheme: "file", Path: path}
	if readOnly {
		u.RawQuery = "mode=ro"
	}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func identityOf(key ed25519.PrivateKey) Identity {
	public := key.Public().(ed25519.PublicKey)
	return Identity{ID: membership.CoordinatorID(public), PublicKey: membership.EncodeKey(public)}
}

func readKey(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (ed25519.PrivateKey, error) {
	var key []byte
	if err := q.QueryRowContext(ctx, `SELECT private_key FROM identity WHERE singleton = 1`).Scan(&key); err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]).Equal(ed25519.PrivateKey(key)) {
		return nil, errors.New("invalid persisted coordinator identity")
	}
	return ed25519.PrivateKey(key), nil
}

// Open acquires the state lock, creating state and an identity on first use.
func Open(ctx context.Context, dir string) (_ *Server, err error) {
	dir, err = privateDir(dir, true)
	if err != nil {
		return nil, err
	}
	s := &Server{Now: time.Now}
	defer func() {
		if err != nil {
			_ = s.Close()
		}
	}()
	if s.lock, err = privateFile(filepath.Join(dir, "coord.lock"), unix.O_RDWR|unix.O_CREAT); err != nil {
		return nil, err
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("coordinator state is already in use: %w", err)
	}
	path := filepath.Join(dir, "coord.db")
	f, err := privateFile(path, unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if s.db, err = openDB(path, false); err != nil {
		return nil, err
	}
	if _, err = s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = FULL;`); err != nil {
		return nil, err
	}
	var version int
	if err = s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return nil, err
	}
	if version != 0 && version != 1 {
		return nil, fmt.Errorf("unsupported coordinator database version: %d", version)
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
		_, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			return nil, keyErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity VALUES (1, ?, ?)`, []byte(key), membership.Timestamp(time.Now())); err != nil {
			return nil, err
		}
	}
	if s.key, err = readKey(ctx, tx); err != nil {
		return nil, err
	}
	s.identity = identityOf(s.key)
	return s, tx.Commit()
}

// ReadIdentity reads the public identity without taking the state lock, so it
// works while the service is running.
func ReadIdentity(ctx context.Context, dir string) (Identity, error) {
	dir, err := privateDir(dir, false)
	if err != nil {
		return Identity{}, err
	}
	path := filepath.Join(dir, "coord.db")
	f, err := privateFile(path, unix.O_RDONLY)
	if err != nil {
		return Identity{}, fmt.Errorf("coordinator state is not initialized: %w", err)
	}
	f.Close()
	db, err := openDB(path, true)
	if err != nil {
		return Identity{}, err
	}
	defer db.Close()
	key, err := readKey(ctx, db)
	if err != nil {
		return Identity{}, err
	}
	return identityOf(key), nil
}

func (s *Server) Identity() Identity { return s.identity }

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		if s.db != nil {
			s.closeErr = s.db.Close()
		}
		if s.lock != nil {
			s.closeErr = errors.Join(s.closeErr, s.lock.Close())
		}
	})
	return s.closeErr
}

// TLSConfig requires every client to prove possession of an Ed25519 key; the
// caller's host ID is derived from that key.
func (s *Server) TLSConfig() (*tls.Config, error) {
	config := tlsid.Config()
	config.ClientAuth = tls.RequireAnyClientCert
	cache := &tlsid.Cache{Key: s.key, Name: s.identity.ID}
	if _, err := cache.Get(); err != nil {
		return nil, err
	}
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cache.Get() }
	config.VerifyConnection = func(state tls.ConnectionState) error {
		_, err := tlsid.PeerKey(state)
		return err
	}
	return config, nil
}

func (s *Server) Listen(address string) (net.Listener, error) {
	config, err := s.TLSConfig()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(listener, config), nil
}

// Serve runs the coordination API until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	server := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		if serveErr := <-done; !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
		return err
	}
}

type registerRequest struct {
	Name          string                `json:"name"`
	RootPublicKey string                `json:"root_public_key"`
	Membership    membership.Membership `json:"membership"`
	Address       string                `json:"address"`
}
type joinRequest struct {
	Membership membership.Membership `json:"membership"`
	Address    string                `json:"address"`
}
type syncRequest struct {
	Address string `json:"address"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /coord/v1/networks", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req registerRequest
		if !decode(w, r, &req, "name", "root_public_key", "membership", "address") {
			return
		}
		status, m, err := s.register(r.Context(), caller, req)
		respond(w, status, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/members", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req joinRequest
		if !decode(w, r, &req, "membership", "address") {
			return
		}
		status, m, err := s.join(r.Context(), caller, r.PathValue("network"), req)
		respond(w, status, m, err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/sync", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req syncRequest
		if !decode(w, r, &req, "address") {
			return
		}
		m, err := s.sync(r.Context(), caller, r.PathValue("network"), req.Address)
		respond(w, http.StatusOK, m, err)
	})
	return mux
}

func callerID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.TLS == nil {
		respond(w, 0, nil, errForbidden)
		return "", false
	}
	public, err := tlsid.PeerKey(*r.TLS)
	if err != nil {
		respond(w, 0, nil, errForbidden)
		return "", false
	}
	return membership.HostID(public), true
}

func decode(w http.ResponseWriter, r *http.Request, dst any, fields ...string) bool {
	defer r.Body.Close()
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err == nil {
		err = membership.Strict(data, dst, fields...)
	}
	if err != nil {
		respond(w, 0, nil, fmt.Errorf("%w: %v", errInvalid, err))
		return false
	}
	return true
}

func respond(w http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		code, message := "internal", "internal error"
		status = http.StatusInternalServerError
		switch {
		case errors.Is(err, errInvalid), errors.Is(err, membership.ErrInvalid):
			status, code, message = http.StatusBadRequest, "invalid", err.Error()
		case errors.Is(err, errForbidden):
			status, code, message = http.StatusForbidden, "forbidden", err.Error()
		case errors.Is(err, errNotFound):
			status, code, message = http.StatusNotFound, "not_found", "not found"
		case errors.Is(err, errConflict):
			status, code, message = http.StatusConflict, "conflict", err.Error()
		}
		value = struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}{code, message}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// verifyCaller checks a submitted chain and that it belongs to the caller.
func verifyCaller(caller, rootKey string, m membership.Membership, address string) error {
	if !membership.ValidAddress(address) {
		return fmt.Errorf("%w: address must be empty or IP:port", errInvalid)
	}
	root, err := membership.DecodeKey(rootKey)
	if err != nil {
		return err
	}
	host, err := m.Verify(root)
	if err != nil {
		return err
	}
	if host != caller {
		return fmt.Errorf("%w: membership is for a different host", errForbidden)
	}
	return nil
}

func (s *Server) insertMember(ctx context.Context, tx *sql.Tx, caller string, m membership.Membership, address string) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO members VALUES (?, ?, ?, ?, ?, ?)`, m.NetworkID, caller, m.InvitePublicKey, string(data), address, membership.Timestamp(s.Now()))
	return err
}

func (s *Server) register(ctx context.Context, caller string, req registerRequest) (int, *membership.Map, error) {
	if !membership.ValidLabel(req.Name) {
		return 0, nil, fmt.Errorf("%w: invalid network name", errInvalid)
	}
	if err := verifyCaller(caller, req.RootPublicKey, req.Membership, req.Address); err != nil {
		return 0, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM networks WHERE id = ?`, req.Membership.NetworkID).Scan(&exists); err != nil {
		return 0, nil, err
	}
	if exists != 0 {
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM members WHERE network_id = ? AND host_id = ?`, req.Membership.NetworkID, caller).Scan(&exists); err != nil {
			return 0, nil, err
		}
		if exists == 0 {
			return 0, nil, fmt.Errorf("%w: network already registered", errConflict)
		}
		m, err := networkMap(ctx, tx, req.Membership.NetworkID)
		return http.StatusOK, m, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO networks VALUES (?, ?, ?, ?)`, req.Membership.NetworkID, req.Name, req.RootPublicKey, membership.Timestamp(s.Now())); err != nil {
		return 0, nil, err
	}
	if err = s.insertMember(ctx, tx, caller, req.Membership, req.Address); err != nil {
		return 0, nil, err
	}
	m, err := networkMap(ctx, tx, req.Membership.NetworkID)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, m, tx.Commit()
}

func (s *Server) join(ctx context.Context, caller, network string, req joinRequest) (int, *membership.Map, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	var root string
	err = tx.QueryRowContext(ctx, `SELECT root_public_key FROM networks WHERE id = ?`, network).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, errNotFound
	}
	if err != nil {
		return 0, nil, err
	}
	if req.Membership.NetworkID != network {
		return 0, nil, fmt.Errorf("%w: membership is for a different network", errInvalid)
	}
	if err = verifyCaller(caller, root, req.Membership, req.Address); err != nil {
		return 0, nil, err
	}
	var user string
	err = tx.QueryRowContext(ctx, `SELECT host_id FROM members WHERE network_id = ? AND invite_public_key = ?`, network, req.Membership.InvitePublicKey).Scan(&user)
	if err == nil {
		if user != caller {
			return 0, nil, fmt.Errorf("%w: invite has already been used", errConflict)
		}
		// A retried join keeps the originally stored membership.
		m, err := networkMap(ctx, tx, network)
		return http.StatusOK, m, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, err
	}
	expires, _ := membership.ParseTime(req.Membership.InviteExpiresAt)
	if !expires.After(s.Now()) {
		return 0, nil, fmt.Errorf("%w: invite has expired", errForbidden)
	}
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM members WHERE network_id = ? AND host_id = ?`, network, caller).Scan(&exists); err != nil {
		return 0, nil, err
	}
	if exists != 0 {
		return 0, nil, fmt.Errorf("%w: host is already a member through another invite", errConflict)
	}
	if err = s.insertMember(ctx, tx, caller, req.Membership, req.Address); err != nil {
		return 0, nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, m, tx.Commit()
}

func (s *Server) sync(ctx context.Context, caller, network, address string) (*membership.Map, error) {
	if !membership.ValidAddress(address) {
		return nil, fmt.Errorf("%w: address must be empty or IP:port", errInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE members SET address = ?, updated_at = ? WHERE network_id = ? AND host_id = ?`, address, membership.Timestamp(s.Now()), network, caller)
	if err != nil {
		return nil, err
	}
	if n, err := result.RowsAffected(); err != nil || n == 0 {
		return nil, errors.Join(err, fmt.Errorf("%w: not a member of this network", errForbidden))
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	return m, tx.Commit()
}

// networkMap returns stored entries as-is; a corrupted or injected row is
// served and left for hosts to reject.
func networkMap(ctx context.Context, tx *sql.Tx, network string) (*membership.Map, error) {
	m := &membership.Map{NetworkID: network, Members: []membership.MapMember{}}
	if err := tx.QueryRowContext(ctx, `SELECT name, root_public_key FROM networks WHERE id = ?`, network).Scan(&m.Name, &m.RootPublicKey); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT host_id, membership, address, updated_at FROM members WHERE network_id = ? ORDER BY host_id`, network)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry rawMember
		if err = rows.Scan(&entry.HostID, &entry.Membership, &entry.Address, &entry.UpdatedAt); err != nil {
			return nil, err
		}
		m.Members = append(m.Members, membership.MapMember{HostID: entry.HostID, Membership: json.RawMessage(entry.Membership), Address: entry.Address, UpdatedAt: entry.UpdatedAt})
	}
	return m, rows.Err()
}

type rawMember struct{ HostID, Membership, Address, UpdatedAt string }
