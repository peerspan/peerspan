// Package coord implements capsule-coord, the coordination service. It stores
// signed membership chains, enforces single use of invite keys, records
// advertised addresses, and serves network maps. It is trusted for
// availability only: hosts verify every chain they receive.
package coord

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/relay"
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

// candidatesSchema (version 2) stores path discovery candidates beside, not
// inside, member rows, so a member row without candidates serves an empty list.
const candidatesSchema = `
CREATE TABLE member_candidates (
 network_id TEXT NOT NULL,
 host_id TEXT NOT NULL,
 candidates TEXT NOT NULL,
 PRIMARY KEY (network_id, host_id)
);
PRAGMA user_version = 2;
`

// statementsSchema (version 3) stores accepted rotations, current-epoch
// attestations, and revocations. Hosts verify them all; they are stored as
// submitted.
const statementsSchema = `
CREATE TABLE statements (
 network_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 subject TEXT NOT NULL,
 statement TEXT NOT NULL,
 PRIMARY KEY (network_id, kind, subject)
);
PRAGMA user_version = 3;
`

// admissionSchema (version 4) lets a host join with an administrator's
// admission of its public key instead of an invite chain. Such a member has an
// empty membership and a synthetic, unique invite_public_key of
// "admission:" + its host key.
const admissionSchema = `
ALTER TABLE members ADD COLUMN admission TEXT;
PRAGMA user_version = 4;
`

// schemaVersion is the newest database version this build opens; Open
// upgrades older ones.
const schemaVersion = 6

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
	db   *sql.DB
	lock *os.File
	// identities are in sequence order; key and identity are the latest's.
	identities []coordIdentity
	key        ed25519.PrivateKey
	identity   Identity
	Now        func() time.Time
	relay      *relayServer
	// Limits apply to new networks, joins, and relayed bytes; set before Serve.
	Limits Limits
	// Log receives the JSON log lines; set before Serve.
	Log       *slog.Logger
	metrics   *metrics
	hosts     identityHosts
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
	s := &Server{Now: time.Now, Limits: DefaultLimits, Log: slog.New(slog.DiscardHandler), metrics: newMetrics()}
	s.relay = newRelayServer(s)
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
	// Every accepted change makes each member sync at once, and every sync
	// commits a write, so commits must be cheap: write-ahead logging with
	// full synchronization keeps each commit durable with one fsync instead
	// of a rollback journal's several. SQLite creates the -wal and -shm files
	// with coord.db's private permissions.
	if _, err = s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;`); err != nil {
		return nil, err
	}
	var version int
	if err = s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return nil, err
	}
	if version < 0 || version > schemaVersion {
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
	if version < 2 {
		if _, err = tx.ExecContext(ctx, candidatesSchema); err != nil {
			return nil, err
		}
	}
	if version < 3 {
		if _, err = tx.ExecContext(ctx, statementsSchema); err != nil {
			return nil, err
		}
	}
	if version < 4 {
		if _, err = tx.ExecContext(ctx, admissionSchema); err != nil {
			return nil, err
		}
	}
	if version < 5 {
		if _, err = tx.ExecContext(ctx, limitsSchema); err != nil {
			return nil, err
		}
	}
	if version < 6 {
		if _, err = tx.ExecContext(ctx, successorsSchema); err != nil {
			return nil, err
		}
	}
	if s.identities, err = readIdentities(ctx, tx, schemaVersion); err != nil {
		return nil, err
	}
	latest := s.identities[len(s.identities)-1]
	s.key, s.identity = latest.key, latest.identity
	return s, tx.Commit()
}

// openState opens the state's database read-only without taking the state
// lock, so it works while the service is running.
func openState(ctx context.Context, dir string) (*sql.DB, error) {
	dir, err := privateDir(dir, false)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "coord.db")
	f, err := privateFile(path, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("coordinator state is not initialized: %w", err)
	}
	f.Close()
	db, err := openDB(path, true)
	if err != nil {
		return nil, err
	}
	// The running service may hold a write lock briefly; wait instead of failing.
	if _, err = db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// ReadIdentity reads the latest public identity without taking the state
// lock, so it works while the service is running.
func ReadIdentity(ctx context.Context, dir string) (Identity, error) {
	info, err := ReadInfo(ctx, dir)
	return Identity{ID: info.ID, PublicKey: info.PublicKey}, err
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
func (s *Server) TLSConfig() (*tls.Config, error) { return s.tlsConfigFor(s.Latest()) }

// tlsConfigFor presents an identity's key.
func (s *Server) tlsConfigFor(sequence int64) (*tls.Config, error) {
	if sequence < 0 || sequence > s.Latest() {
		return nil, fmt.Errorf("no coordinator identity %d", sequence)
	}
	identity := s.identities[sequence]
	config := tlsid.Config()
	config.ClientAuth = tls.RequireAnyClientCert
	// The relay shares this listener and is selected by ALPN.
	// Version 2 is preferred when a host offers it.
	config.NextProtos = []string{"http/1.1", relay.ALPNv2, relay.ALPN}
	cache := &tlsid.Cache{Key: identity.key, Name: identity.identity.ID}
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

// Listen listens on address presenting the latest identity.
func (s *Server) Listen(address string) (net.Listener, error) {
	return s.ListenIdentity(s.Latest(), address)
}

func tlsListener(listener net.Listener, config *tls.Config) net.Listener {
	return tls.NewListener(listener, config)
}

// Serve runs the coordination API, the relay, and a STUN responder on each
// listener until ctx is cancelled. Every listener shares the database and the
// relay; each answers as the identity it presents (the latest unless it came
// from ListenIdentity). Serve returns when every listener has stopped; one
// failing stops the others.
func (s *Server) Serve(ctx context.Context, listeners ...net.Listener) error {
	if len(listeners) == 0 {
		return errors.New("no coordination listener")
	}
	stunConns := make([]*net.UDPConn, 0, len(listeners))
	defer func() {
		for _, c := range stunConns {
			c.Close()
		}
	}()
	for _, listener := range listeners {
		stunConn, err := listenSTUN(listener.Addr())
		if err != nil {
			return err
		}
		stunConns = append(stunConns, stunConn)
	}
	for _, c := range stunConns {
		go serveSTUN(c)
	}
	// Relay usage is persisted periodically and once more on shutdown.
	flushCtx, stopFlush := context.WithCancel(context.Background())
	flushed := make(chan struct{})
	go s.runUsageFlush(flushCtx, flushed)
	defer func() { stopFlush(); <-flushed }()
	handler := s.Handler()
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(listeners))
	for _, listener := range listeners {
		go func() {
			err := s.serveListener(serveCtx, listener, handler)
			cancel()
			errs <- err
		}()
	}
	var err error
	for range listeners {
		err = errors.Join(err, <-errs)
	}
	return err
}

// serveListener serves one listener. Each connection completes its TLS
// handshake first, then relay connections leave for the relay and the rest go
// to http.Server, whose request timeouts must not apply to long-lived relay
// connections.
func (s *Server) serveListener(ctx context.Context, listener net.Listener, handler http.Handler) error {
	sequence := s.sequenceOf(listener)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: s.httpErrorLog(),
		BaseContext: func(net.Listener) context.Context {
			return context.WithValue(context.Background(), sequenceKey{}, sequence)
		}}
	httpConns := newConnListener(listener.Addr())
	serveCtx, cancelServe := context.WithCancel(ctx)
	// Serve returns after every relay connection has closed, so each has
	// logged its relay line before the caller logs stop.
	var active sync.WaitGroup
	accepting := make(chan struct{})
	defer func() {
		cancelServe()
		_ = listener.Close()
		s.relay.closeAll()
		httpConns.Close()
		<-accepting
		active.Wait()
	}()
	go func() {
		defer close(accepting)
		for {
			c, err := listener.Accept()
			if err != nil {
				// On cancellation, Shutdown closes httpConns itself.
				if serveCtx.Err() == nil {
					httpConns.Close()
				}
				return
			}
			active.Add(1)
			go func() {
				defer active.Done()
				s.dispatch(serveCtx, c, httpConns, sequence)
			}()
		}
	}()
	stopAccept := context.AfterFunc(serveCtx, func() { _ = listener.Close() })
	defer stopAccept()
	done := make(chan error, 1)
	go func() { done <- server.Serve(httpConns) }()
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
	Candidates    []string              `json:"candidates"`
}
type joinRequest struct {
	Membership membership.Membership `json:"membership"`
	Address    string                `json:"address"`
	Candidates []string              `json:"candidates"`
}
type syncRequest struct {
	Address    string   `json:"address"`
	Candidates []string `json:"candidates"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /coord/v1/networks", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req registerRequest
		if !decode(w, r, &req, "name", "root_public_key", "membership", "address", "candidates") {
			return
		}
		status, m, err := s.registerFrom(r.Context(), caller, sourceOf(r.RemoteAddr), req)
		respond(w, status, s.withSuccessors(r, m), err)
		if err == nil && status == http.StatusCreated {
			s.relay.changed(m.NetworkID)
		}
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/members", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		data, ok := readBody(w, r)
		if !ok {
			return
		}
		status, m, err := s.joinRequest(r.Context(), caller, r.PathValue("network"), data)
		respond(w, status, s.withSuccessors(r, m), err)
	})
	mux.HandleFunc("POST /coord/v1/networks/{network}/sync", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		var req syncRequest
		if !decode(w, r, &req, "address", "candidates") {
			return
		}
		m, err := s.sync(r.Context(), caller, r.PathValue("network"), req.Address, req.Candidates)
		respond(w, http.StatusOK, s.withSuccessors(r, m), err)
	})
	s.governanceRoutes(mux)
	s.personRoutes(mux)
	s.adminRoutes(mux)
	s.policyRoutes(mux)
	s.limitRoutes(mux)
	s.moveRoutes(mux)
	return s.observe(mux, s.notifyChanges(mux))
}

// notifyChanges sends changed frames after every accepted change to a
// network: each POST under /coord/v1/networks/{network}/ except sync, which
// only updates an address and candidates. A request that leaves the
// network's statements and members as they were, such as a retried join or
// a resubmitted policy, is not a change; when that cannot be read, the
// request counts as one.
func (s *Server) notifyChanges(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, "/coord/v1/networks/")
		parts := strings.Split(rest, "/")
		network := ""
		if ok && r.Method == http.MethodPost && len(parts) == 2 && parts[0] != "" && parts[1] != "sync" {
			network = parts[0]
		}
		if network == "" {
			next.ServeHTTP(w, r)
			return
		}
		before := s.changeDigest(network)
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if recorder.status >= 200 && recorder.status <= 299 && (before == "" || s.changeDigest(network) != before) {
			s.relay.changed(network)
		}
	})
}

// changeDigest summarizes what a change can alter in a network's map, in
// one query: the network row, each member's membership and admission (not
// its address, candidates, or time), and every stored statement.
func (s *Server) changeDigest(network string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var digest sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT
 (SELECT name || '|' || root_public_key FROM networks WHERE id = ?1) || char(10) ||
 COALESCE((SELECT group_concat(host_id || '|' || membership || '|' || COALESCE(admission, ''), char(10)) FROM (SELECT * FROM members WHERE network_id = ?1 ORDER BY host_id)), '') || char(10) ||
 COALESCE((SELECT group_concat(kind || '|' || subject || '|' || statement, char(10)) FROM (SELECT * FROM statements WHERE network_id = ?1 ORDER BY kind, subject)), '')`, network).Scan(&digest)
	if err != nil || !digest.Valid {
		return ""
	}
	sum := sha256.Sum256([]byte(digest.String))
	return string(sum[:])
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

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
	data, ok := readBody(w, r)
	if !ok {
		return false
	}
	if err := membership.Strict(data, dst, fields...); err != nil {
		respond(w, 0, nil, fmt.Errorf("%w: %v", errInvalid, err))
		return false
	}
	return true
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	defer r.Body.Close()
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		respond(w, 0, nil, fmt.Errorf("%w: %v", errInvalid, err))
		return nil, false
	}
	return data, true
}

func respond(w http.ResponseWriter, status int, value any, err error) {
	recordError(w, err)
	var limited *limitError
	if errors.As(err, &limited) {
		status, value, err = http.StatusTooManyRequests, struct {
			Code  string `json:"code"`
			Error string `json:"error"`
			Limit string `json:"limit"`
		}{"limit", limited.message, limited.limit}, nil
	}
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

// verifyCaller checks a submitted chain against the network's current root
// and that it belongs to the caller.
func verifyCaller(caller, network string, chain membership.Chain, m membership.Membership, address string, candidates []string) error {
	if err := validEndpoints(address, candidates); err != nil {
		return err
	}
	host, err := chain.VerifyMembership(m)
	if err != nil {
		return err
	}
	if host != caller {
		return fmt.Errorf("%w: membership is for a different host", errForbidden)
	}
	return nil
}

func validEndpoints(address string, candidates []string) error {
	if !membership.ValidAddress(address) {
		return fmt.Errorf("%w: address must be empty or IP:port", errInvalid)
	}
	if !membership.ValidCandidates(candidates) {
		return fmt.Errorf("%w: candidates must be at most %d distinct IP:port values", errInvalid, membership.MaxCandidates)
	}
	return nil
}

func (s *Server) insertMember(ctx context.Context, tx *sql.Tx, caller string, m membership.Membership, address string, candidates []string) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, m.NetworkID, caller, m.InvitePublicKey, string(data), address, membership.Timestamp(s.Now())); err != nil {
		return err
	}
	return putCandidates(ctx, tx, m.NetworkID, caller, candidates)
}

func putCandidates(ctx context.Context, tx *sql.Tx, network, host string, candidates []string) error {
	data, err := json.Marshal(candidates)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO member_candidates VALUES (?, ?, ?) ON CONFLICT (network_id, host_id) DO UPDATE SET candidates = excluded.candidates`, network, host, string(data))
	return err
}

func (s *Server) register(ctx context.Context, caller string, req registerRequest) (int, *membership.Map, error) {
	return s.registerFrom(ctx, caller, "", req)
}

// registerFrom registers a network for a caller at a source address; only new
// networks count toward the source's registration limit.
func (s *Server) registerFrom(ctx context.Context, caller, source string, req registerRequest) (int, *membership.Map, error) {
	if !membership.ValidLabel(req.Name) {
		return 0, nil, fmt.Errorf("%w: invalid network name", errInvalid)
	}
	root, err := membership.DecodeKey(req.RootPublicKey)
	if err != nil {
		return 0, nil, err
	}
	genesis, err := membership.VerifyChain(root, nil)
	if err != nil {
		return 0, nil, err
	}
	if err := verifyCaller(caller, genesis.NetworkID, genesis, req.Membership, req.Address, req.Candidates); err != nil {
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
			chain, err := chainOf(ctx, tx, req.Membership.NetworkID)
			if err != nil {
				return 0, nil, err
			}
			if revoked, err := revokedHost(ctx, tx, chain, req.Membership.HostPublicKey); err != nil || revoked {
				return 0, nil, errors.Join(err, fmt.Errorf("%w: host has been revoked or has left", errForbidden))
			}
			return 0, nil, fmt.Errorf("%w: network already registered", errConflict)
		}
		m, err := networkMap(ctx, tx, req.Membership.NetworkID)
		return http.StatusOK, m, err
	}
	if err = s.checkRegistration(ctx, tx, source, req.Membership.NetworkID); err != nil {
		return 0, nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO networks VALUES (?, ?, ?, ?)`, req.Membership.NetworkID, req.Name, req.RootPublicKey, membership.Timestamp(s.Now())); err != nil {
		return 0, nil, err
	}
	if err = s.insertMember(ctx, tx, caller, req.Membership, req.Address, req.Candidates); err != nil {
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
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return 0, nil, err
	}
	if req.Membership.NetworkID != network {
		return 0, nil, fmt.Errorf("%w: membership is for a different network", errInvalid)
	}
	// Joins verify under the current root or an administrator: after a
	// rotation, invites signed by an older root are refused.
	if err = verifyCaller(caller, network, chain, req.Membership, req.Address, req.Candidates); err != nil {
		return 0, nil, err
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return 0, nil, err
	}
	if revoked.Excludes(req.Membership) {
		return 0, nil, fmt.Errorf("%w: host or invite has been revoked, or the host has left", errForbidden)
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
	if err = s.checkMembers(ctx, tx, network); err != nil {
		return 0, nil, err
	}
	if err = s.insertMember(ctx, tx, caller, req.Membership, req.Address, req.Candidates); err != nil {
		return 0, nil, err
	}
	m, err := networkMap(ctx, tx, network)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, m, tx.Commit()
}

func (s *Server) sync(ctx context.Context, caller, network, address string, candidates []string) (*membership.Map, error) {
	if err := validEndpoints(address, candidates); err != nil {
		return nil, err
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
	if err = putCandidates(ctx, tx, network, caller, candidates); err != nil {
		return nil, err
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
	rows, err := tx.QueryContext(ctx, `SELECT m.host_id, m.membership, COALESCE(m.admission, ''), m.address, m.updated_at, COALESCE(c.candidates, '[]') FROM members m LEFT JOIN member_candidates c ON c.network_id = m.network_id AND c.host_id = m.host_id WHERE m.network_id = ? ORDER BY m.host_id`, network)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry rawMember
		var candidates, admission string
		if err = rows.Scan(&entry.HostID, &entry.Membership, &admission, &entry.Address, &entry.UpdatedAt, &candidates); err != nil {
			return nil, err
		}
		member := membership.MapMember{HostID: entry.HostID, Membership: rawOrNull(entry.Membership), Admission: rawOrNull(admission), Address: entry.Address, Candidates: []string{}, UpdatedAt: entry.UpdatedAt}
		if json.Unmarshal([]byte(candidates), &member.Candidates) != nil || member.Candidates == nil {
			member.Candidates = []string{}
		}
		m.Members = append(m.Members, member)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = addStatements(ctx, tx, m); err != nil {
		return nil, err
	}
	if err = addPersons(ctx, tx, m); err != nil {
		return nil, err
	}
	if err = addAdmins(ctx, tx, m); err != nil {
		return nil, err
	}
	if err = addMove(ctx, tx, m); err != nil {
		return nil, err
	}
	return m, addPolicies(ctx, tx, m)
}

// rawOrNull serves an empty stored column as JSON null.
func rawOrNull(value string) json.RawMessage {
	if value == "" {
		return nil
	}
	return json.RawMessage(value)
}

type rawMember struct{ HostID, Membership, Address, UpdatedAt string }
