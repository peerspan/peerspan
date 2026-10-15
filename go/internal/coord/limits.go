package coord

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// limitsSchema (version 5) counts network registrations per source address
// and relayed bytes per network and UTC month, for the hosted limits.
const limitsSchema = `
CREATE TABLE registrations (source TEXT NOT NULL, network_id TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE relay_usage (network_id TEXT NOT NULL, month TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY(network_id, month));
PRAGMA user_version = 5;
`

// Limits bound what anyone may use on a coordinator that accepts networks
// from anyone. Zero disables a limit.
type Limits struct {
	MaxMembers         int64
	MaxNetworksPerIP   int64
	RelayBytesPerMonth int64
}

// DefaultLimits are peerspan-coord run's defaults.
var DefaultLimits = Limits{MaxMembers: 50, MaxNetworksPerIP: 20, RelayBytesPerMonth: 10_000_000_000}

// Limit names, as reported in a 429 body.
const (
	limitMembers       = "members"
	limitNetworksPerIP = "networks_per_ip"
	limitRelayBytes    = "relay_bytes"
)

const (
	registrationWindow = 24 * time.Hour
	relayFlushInterval = 60 * time.Second
	// registrationTime is fixed-width so stored times compare as text.
	registrationTime = "2006-01-02T15:04:05Z"
)

// limitError is a request refused by a limit; it is answered with 429.
type limitError struct {
	limit, message string
}

func (e *limitError) Error() string { return e.message }

// sourceOf is the registration source of a TCP peer address: IPv4 in full,
// IPv6 by its /64.
func sourceOf(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return remote
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	prefix, _ := addr.Prefix(64)
	return prefix.String()
}

// checkRegistration refuses a new network once its source has registered
// the limit within the last 24 hours, and otherwise counts it.
func (s *Server) checkRegistration(ctx context.Context, tx *sql.Tx, source, network string) error {
	now := s.Now().UTC()
	cutoff := now.Add(-registrationWindow).Format(registrationTime)
	if _, err := tx.ExecContext(ctx, `DELETE FROM registrations WHERE created_at <= ?`, cutoff); err != nil {
		return err
	}
	if limit := s.Limits.MaxNetworksPerIP; limit > 0 {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registrations WHERE source = ? AND created_at > ?`, source, cutoff).Scan(&count); err != nil {
			return err
		}
		if count >= limit {
			return &limitError{limitNetworksPerIP, fmt.Sprintf("this address has registered %d networks in the last 24 hours, the limit", limit)}
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO registrations VALUES (?, ?, ?)`, source, network, now.Format(registrationTime))
	return err
}

func memberCount(ctx context.Context, tx *sql.Tx, network string) (int64, error) {
	var count int64
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM members WHERE network_id = ?`, network).Scan(&count)
	return count, err
}

// checkMembers refuses a new member host once the network is at the limit.
func (s *Server) checkMembers(ctx context.Context, tx *sql.Tx, network string) error {
	limit := s.Limits.MaxMembers
	if limit <= 0 {
		return nil
	}
	count, err := memberCount(ctx, tx, network)
	if err != nil {
		return err
	}
	if count >= limit {
		return &limitError{limitMembers, fmt.Sprintf("the network has %d member hosts, the limit", limit)}
	}
	return nil
}

// relayUsage counts relayed bytes per network in the current UTC month. The
// in-memory totals are authoritative; they are written to the database at
// least every relayFlushInterval and on orderly shutdown.
type relayUsage struct {
	mu     sync.Mutex
	totals map[usageKey]int64
	dirty  map[usageKey]bool
}

type usageKey struct{ network, month string }

func monthOf(t time.Time) string { return t.UTC().Format("2006-01") }

// loadLocked returns a total, reading the stored value on first use.
func (u *relayUsage) loadLocked(ctx context.Context, db *sql.DB, key usageKey) (int64, error) {
	if total, ok := u.totals[key]; ok {
		return total, nil
	}
	if u.totals == nil {
		u.totals, u.dirty = map[usageKey]int64{}, map[usageKey]bool{}
	}
	var total int64
	err := db.QueryRowContext(ctx, `SELECT bytes FROM relay_usage WHERE network_id = ? AND month = ?`, key.network, key.month).Scan(&total)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	u.totals[key] = total
	return total, nil
}

func (u *relayUsage) total(ctx context.Context, db *sql.DB, key usageKey) (int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.loadLocked(ctx, db, key)
}

// charge adds n bytes to a network's month unless it has reached limit;
// it reports whether the frame may be forwarded.
func (u *relayUsage) charge(ctx context.Context, db *sql.DB, key usageKey, n, limit int64) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	total, err := u.loadLocked(ctx, db, key)
	if err != nil {
		return limit <= 0
	}
	if limit > 0 && total >= limit {
		return false
	}
	u.totals[key] = total + n
	u.dirty[key] = true
	return true
}

// flush writes changed totals and forgets past months.
func (u *relayUsage) flush(ctx context.Context, db *sql.DB, now time.Time) error {
	u.mu.Lock()
	pending := map[usageKey]int64{}
	for key := range u.dirty {
		pending[key] = u.totals[key]
	}
	u.dirty = map[usageKey]bool{}
	month := monthOf(now)
	for key := range u.totals {
		if _, changed := pending[key]; key.month != month && !changed {
			delete(u.totals, key)
		}
	}
	u.mu.Unlock()
	var errs error
	for key, total := range pending {
		_, err := db.ExecContext(ctx, `INSERT INTO relay_usage VALUES (?, ?, ?) ON CONFLICT (network_id, month) DO UPDATE SET bytes = MAX(bytes, excluded.bytes)`, key.network, key.month, total)
		if err != nil {
			errs = errors.Join(errs, err)
			u.mu.Lock()
			u.dirty[key] = true
			u.mu.Unlock()
		}
	}
	return errs
}

// usageResponse is GET /coord/v1/networks/{network}/usage.
type usageResponse struct {
	Members       int64  `json:"members"`
	MaxMembers    int64  `json:"max_members"`
	RelayBytes    int64  `json:"relay_bytes"`
	MaxRelayBytes int64  `json:"max_relay_bytes"`
	Month         string `json:"month"`
}

func (s *Server) usage(ctx context.Context, caller, network string) (*usageResponse, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = isMember(ctx, tx, network, caller); err != nil {
		return nil, err
	}
	u := &usageResponse{MaxMembers: max(s.Limits.MaxMembers, 0), MaxRelayBytes: max(s.Limits.RelayBytesPerMonth, 0), Month: monthOf(s.Now())}
	if u.Members, err = memberCount(ctx, tx, network); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	u.RelayBytes, err = s.relay.usage.total(ctx, s.db, usageKey{network, u.Month})
	return u, err
}

func (s *Server) limitRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /coord/v1/networks/{network}/usage", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerID(w, r)
		if !ok {
			return
		}
		u, err := s.usage(r.Context(), caller, r.PathValue("network"))
		respond(w, http.StatusOK, u, err)
	})
}

// runUsageFlush persists relay usage every relayFlushInterval until ctx
// ends, then once more.
func (s *Server) runUsageFlush(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(relayFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := s.relay.usage.flush(context.Background(), s.db, s.Now()); err != nil {
				s.logError("relay usage could not be saved at shutdown", err, "", "")
			}
			return
		case <-ticker.C:
			if err := s.relay.usage.flush(ctx, s.db, s.Now()); err != nil {
				s.logError("relay usage could not be saved; it is retried at the next flush", err, "", "")
			}
		}
	}
}
