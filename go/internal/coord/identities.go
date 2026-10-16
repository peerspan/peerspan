package coord

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
	"golang.org/x/sys/unix"
)

// Coordinator identities: identity 0 is the key in the identity table, and
// each later identity has an address, a key (possibly the previous one), and
// a successor statement signed by the previous identity's key.

// successorsSchema (version 6) stores identities after the first.
const successorsSchema = `
CREATE TABLE IF NOT EXISTS successors (sequence INTEGER PRIMARY KEY CHECK (sequence >= 1), private_key BLOB NOT NULL, successor TEXT NOT NULL, created_at TEXT NOT NULL);
PRAGMA user_version = 6;
`

// ErrNothingChanges refuses a successor with the latest key and address.
var ErrNothingChanges = errors.New("nothing changes")

type coordIdentity struct {
	sequence  int64
	key       ed25519.PrivateKey
	identity  Identity
	address   string          // "" for identity 0
	successor json.RawMessage // nil for identity 0
}

// IdentityInfo is one entry of info's identities.
type IdentityInfo struct {
	Sequence  int64   `json:"sequence"`
	ID        string  `json:"id"`
	PublicKey string  `json:"public_key"`
	Address   *string `json:"address"`
}

// Info is printed by peerspan-coord info: the latest identity and all of them.
type Info struct {
	ID         string         `json:"id"`
	PublicKey  string         `json:"public_key"`
	Identities []IdentityInfo `json:"identities"`
}

// SuccessorResult is printed by peerspan-coord successor.
type SuccessorResult struct {
	Sequence  int64                `json:"sequence"`
	ID        string               `json:"id"`
	PublicKey string               `json:"public_key"`
	Address   string               `json:"address"`
	Successor membership.Successor `json:"successor"`
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func validKey(key []byte) bool {
	return len(key) == ed25519.PrivateKeySize && ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]).Equal(ed25519.PrivateKey(key))
}

// readIdentities reads every identity in order. Databases before version 6
// have only identity 0.
func readIdentities(ctx context.Context, q queryer, version int) ([]coordIdentity, error) {
	key, err := readKey(ctx, q)
	if err != nil {
		return nil, err
	}
	identities := []coordIdentity{{sequence: 0, key: key, identity: identityOf(key)}}
	if version < 6 {
		return identities, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT sequence, private_key, successor FROM successors ORDER BY sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var next coordIdentity
		var stored string
		if err = rows.Scan(&next.sequence, &next.key, &stored); err != nil {
			return nil, err
		}
		previous := identities[len(identities)-1]
		successor, err := membership.DecodeSuccessor([]byte(stored))
		if err != nil || !validKey(next.key) || next.sequence != previous.sequence+1 || successor.Sequence != next.sequence ||
			successor.PreviousPublicKey != previous.identity.PublicKey || successor.PublicKey != membership.PublicKey(next.key) {
			return nil, fmt.Errorf("invalid persisted coordinator identity %d", next.sequence)
		}
		next.identity, next.address, next.successor = identityOf(next.key), successor.Address, json.RawMessage(stored)
		identities = append(identities, next)
	}
	return identities, rows.Err()
}

func userVersion(ctx context.Context, q queryer) (int, error) {
	var version int
	err := q.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version)
	return version, err
}

func infoOf(identities []coordIdentity) Info {
	latest := identities[len(identities)-1].identity
	info := Info{ID: latest.ID, PublicKey: latest.PublicKey, Identities: []IdentityInfo{}}
	for _, i := range identities {
		entry := IdentityInfo{Sequence: i.sequence, ID: i.identity.ID, PublicKey: i.identity.PublicKey}
		if i.sequence > 0 {
			address := i.address
			entry.Address = &address
		}
		info.Identities = append(info.Identities, entry)
	}
	return info
}

// ReadInfo reads the public identities without taking the state lock, so it
// works while the service is running.
func ReadInfo(ctx context.Context, dir string) (Info, error) {
	db, err := openState(ctx, dir)
	if err != nil {
		return Info{}, err
	}
	defer db.Close()
	version, err := userVersion(ctx, db)
	if err != nil {
		return Info{}, err
	}
	identities, err := readIdentities(ctx, db, version)
	if err != nil {
		return Info{}, err
	}
	return infoOf(identities), nil
}

// AppendSuccessor adds an identity after the latest one, at address, with a
// new key or the latest key. The coordinator must be stopped.
func AppendSuccessor(ctx context.Context, dir, address string, newKey bool) (*SuccessorResult, error) {
	dir, err := privateDir(dir, false)
	if err != nil {
		return nil, err
	}
	if found, err := exists(filepath.Join(dir, "coord.db")); err != nil || !found {
		return nil, errors.Join(err, errors.New("coordinator state is not initialized"))
	}
	s, err := Open(ctx, dir)
	if err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, err
	}
	defer s.Close()
	if !membership.ValidCoordinatorAddress(address) {
		return nil, errors.New("--address must be HOST:PORT, where HOST is an IP literal or a DNS name")
	}
	latest := s.identities[len(s.identities)-1]
	key := latest.key
	if newKey {
		if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	} else if address == latest.address {
		return nil, ErrNothingChanges
	}
	sequence := latest.sequence + 1
	successor, err := membership.SignSuccessor(latest.key, sequence, address, key.Public().(ed25519.PublicKey), membership.Timestamp(s.Now().Truncate(time.Second)))
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(successor)
	if err != nil {
		return nil, err
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO successors VALUES (?, ?, ?, ?)`, sequence, []byte(key), string(data), membership.Timestamp(s.Now())); err != nil {
		return nil, err
	}
	identity := identityOf(key)
	return &SuccessorResult{Sequence: sequence, ID: identity.ID, PublicKey: identity.PublicKey, Address: address, Successor: successor}, nil
}

// Latest is the sequence of the latest identity.
func (s *Server) Latest() int64 { return s.identities[len(s.identities)-1].sequence }

// successorsFrom is the chain from identity sequence to the latest, in order.
func (s *Server) successorsFrom(sequence int64) []json.RawMessage {
	chain := []json.RawMessage{}
	for _, i := range s.identities {
		if i.sequence > sequence {
			chain = append(chain, i.successor)
		}
	}
	return chain
}

// ParsePreviousListen reads a --previous-listen value, SEQUENCE=HOST:PORT.
func ParsePreviousListen(value string) (int64, string, error) {
	sequence, address, ok := strings.Cut(value, "=")
	n, err := strconv.ParseInt(sequence, 10, 64)
	if !ok || err != nil || n < 0 || strconv.FormatInt(n, 10) != sequence || address == "" {
		return 0, "", fmt.Errorf("--previous-listen must be SEQUENCE=HOST:PORT")
	}
	return n, address, nil
}

// CheckPrevious accepts a sequence of an identity before the latest.
func (s *Server) CheckPrevious(sequence int64) error {
	if sequence < 0 || sequence >= s.Latest() {
		return fmt.Errorf("--previous-listen sequence %d is not an earlier identity", sequence)
	}
	return nil
}

// identityListener is a coordination listener presenting one identity.
type identityListener struct {
	net.Listener
	sequence int64
}

// ListenIdentity listens on address presenting an identity's key.
func (s *Server) ListenIdentity(sequence int64, address string) (net.Listener, error) {
	config, err := s.tlsConfigFor(sequence)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &identityListener{Listener: tlsListener(listener, config), sequence: sequence}, nil
}

// sequenceOf is the identity a listener presents: the latest unless it came
// from ListenIdentity.
func (s *Server) sequenceOf(listener net.Listener) int64 {
	if l, ok := listener.(*identityListener); ok {
		return l.sequence
	}
	return s.Latest()
}

type sequenceKey struct{}

// requestSequence is the identity whose listener received a request.
func (s *Server) requestSequence(ctx context.Context) int64 {
	if sequence, ok := ctx.Value(sequenceKey{}).(int64); ok {
		return sequence
	}
	return s.Latest()
}

// answeredAs is the identity a request reached. A listener presents one
// key, but identities that keep the previous key share it, as when one
// listener serves an old and a new name: the request's Host then picks the
// identity whose address it names, and otherwise the earliest identity with
// that key, from which a host pinning the key verifies the chain.
func (s *Server) answeredAs(r *http.Request) int64 {
	listener := s.identities[s.requestSequence(r.Context())]
	earliest := listener.sequence
	for _, i := range s.identities {
		if i.identity.PublicKey != listener.identity.PublicKey {
			continue
		}
		if i.sequence > 0 && sameAddress(r.Host, i.address) {
			return i.sequence
		}
		if i.sequence < earliest {
			earliest = i.sequence
		}
	}
	return earliest
}

// sameAddress compares a Host header with a coordinator address; DNS names
// compare without case, and a Host without a port is port 443.
func sameAddress(host, address string) bool {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
	}
	return strings.EqualFold(host, address)
}

// withSuccessors adds successors to a register, join, or sync map: the chain
// from the identity the request reached to the latest.
func (s *Server) withSuccessors(r *http.Request, m *membership.Map) any {
	if m == nil {
		return nil
	}
	return struct {
		*membership.Map
		Successors []json.RawMessage `json:"successors"`
	}{m, s.successorsFrom(s.answeredAs(r))}
}

// identityHostWindow is how long a host counts toward its listener's
// peerspan_coord_identity_hosts.
const identityHostWindow = 24 * time.Hour
const identityHostLimit = 4096
const identityHostSweep = time.Minute

// identityHosts records when each host last completed a request or opened a
// relay connection through each identity's listener.
type identityHosts struct {
	mu   sync.Mutex
	seen map[int64]map[string]time.Time
	// Overflow preserves the retirement safety signal without retaining
	// unbounded identities. A saturated listener cannot report zero yet.
	overflow  map[int64]time.Time
	lastSweep time.Time
}

func (h *identityHosts) record(sequence int64, host string, now time.Time) {
	if host == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen == nil {
		h.seen = map[int64]map[string]time.Time{}
		h.overflow = map[int64]time.Time{}
	}
	if now.Sub(h.lastSweep) >= identityHostSweep {
		h.prune(now)
	}
	if h.seen[sequence] == nil {
		h.seen[sequence] = map[string]time.Time{}
	}
	if _, exists := h.seen[sequence][host]; exists || len(h.seen[sequence]) < identityHostLimit {
		h.seen[sequence][host] = now
	} else {
		h.overflow[sequence] = now
	}
}

// prune requires the mutex and runs on traffic as well as scrapes.
func (h *identityHosts) prune(now time.Time) {
	for _, hosts := range h.seen {
		for host, at := range hosts {
			if now.Sub(at) > identityHostWindow {
				delete(hosts, host)
			}
		}
	}
	for sequence, at := range h.overflow {
		if now.Sub(at) > identityHostWindow {
			delete(h.overflow, sequence)
		}
	}
	h.lastSweep = now
}

// counts reports a bounded count, including an overflow marker while any
// untracked host may still be within the retirement window.
func (h *identityHosts) counts(now time.Time) map[int64]int {
	h.mu.Lock()
	defer h.mu.Unlock()
	counts := map[int64]int{}
	h.prune(now)
	for sequence, hosts := range h.seen {
		counts[sequence] = len(hosts)
		if _, ok := h.overflow[sequence]; ok {
			counts[sequence]++
		}
	}
	return counts
}

// sortedSequences lists every identity's sequence.
func (s *Server) sortedSequences() []int64 {
	sequences := make([]int64, 0, len(s.identities))
	for _, i := range s.identities {
		sequences = append(sequences, i.sequence)
	}
	sort.Slice(sequences, func(a, b int) bool { return sequences[a] < sequences[b] })
	return sequences
}
