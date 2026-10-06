package host

import (
	"bytes"
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
	"sort"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
)

// The v3 schema is shared with Rust. Records are the local API views below;
// root_seed is present only on the network creator's host.
const networkSchema = `
CREATE TABLE networks (id TEXT PRIMARY KEY, record TEXT NOT NULL, root_seed BLOB);
CREATE TABLE network_members (network_id TEXT NOT NULL, host_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, host_id));
PRAGMA user_version = 3;
`

const defaultCoordinationInterval = 30 * time.Second

type Network struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	RootPublicKey        string  `json:"root_public_key"`
	Member               string  `json:"member"`
	CoordinatorAddress   string  `json:"coordinator_address"`
	CoordinatorPublicKey string  `json:"coordinator_public_key"`
	Administrator        bool    `json:"administrator"`
	LastSyncAt           *string `json:"last_sync_at"`
	LastSyncError        *string `json:"last_sync_error"`
}

// NetworkMember is a verified map entry. Membership is the host's own proof.
type NetworkMember struct {
	HostID     string                `json:"host_id"`
	PublicKey  string                `json:"public_key"`
	Member     string                `json:"member"`
	Address    string                `json:"address"`
	UpdatedAt  string                `json:"updated_at"`
	Membership membership.Membership `json:"membership"`
}

type CreateNetwork struct {
	Name                 string `json:"name"`
	Member               string `json:"member"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
}
type CreateInvite struct {
	Member    string `json:"member"`
	ExpiresAt string `json:"expires_at"`
}
type Invite struct {
	NetworkID       string `json:"network_id"`
	Member          string `json:"member"`
	InvitePublicKey string `json:"invite_public_key"`
	InviteExpiresAt string `json:"invite_expires_at"`
	Token           string `json:"token"`
}
type JoinNetwork struct {
	Token string `json:"token"`
}

// ConfigureCoordination sets the daemon's advertised peer address and sync
// interval. A grant without allow_disconnected requires a sync within three
// intervals.
func (s *Store) ConfigureCoordination(advertise string, interval time.Duration) error {
	if !membership.ValidAddress(advertise) {
		return fmt.Errorf("%w: advertised address must be IP:port", ErrInvalid)
	}
	if interval < time.Second || interval > time.Hour {
		return fmt.Errorf("%w: coordination interval must be 1 to 3600 seconds", ErrInvalid)
	}
	s.coordination.Lock()
	defer s.coordination.Unlock()
	s.advertise, s.interval = advertise, interval
	return nil
}

func (s *Store) coordinationConfig() (string, time.Duration) {
	s.coordination.Lock()
	defer s.coordination.Unlock()
	if s.interval == 0 {
		return s.advertise, defaultCoordinationInterval
	}
	return s.advertise, s.interval
}

// administrator is derived from root_seed rather than trusted from the record,
// matching the Rust implementation's reading of shared v3 state.
const networkColumns = "SELECT record, root_seed IS NOT NULL FROM networks"

func scanNetwork(row interface{ Scan(...any) error }) (Network, error) {
	var n Network
	var record string
	var administrator bool
	if err := row.Scan(&record, &administrator); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return n, ErrNotFound
		}
		return n, err
	}
	err := json.Unmarshal([]byte(record), &n)
	n.Administrator = administrator
	return n, err
}

func (s *Store) Networks(ctx context.Context) ([]Network, error) {
	rows, err := s.db.QueryContext(ctx, networkColumns+" ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	networks := []Network{}
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		networks = append(networks, n)
	}
	return networks, rows.Err()
}

func (s *Store) Network(ctx context.Context, id string) (Network, error) {
	return scanNetwork(s.db.QueryRowContext(ctx, networkColumns+" WHERE id = ?", id))
}

func (s *Store) NetworkMembers(ctx context.Context, id string) ([]NetworkMember, error) {
	if _, err := s.Network(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM network_members WHERE network_id = ? ORDER BY host_id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := []NetworkMember{}
	for rows.Next() {
		m, err := readJSON[NetworkMember](rows)
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func putJSON(ctx context.Context, tx *sql.Tx, query string, value any, args ...any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, query, append([]any{string(data)}, args...)...)
	return err
}

func (s *Store) CreateNetwork(ctx context.Context, r CreateNetwork) (Network, error) {
	if !membership.ValidLabel(r.Name) || !membership.ValidLabel(r.Member) {
		return Network{}, fmt.Errorf("%w: name and member must be trimmed 1-128 byte labels without control characters", ErrInvalid)
	}
	if !membership.ValidCoordinatorAddress(r.CoordinatorAddress) {
		return Network{}, fmt.Errorf("%w: coordinator address must be HOST:PORT", ErrInvalid)
	}
	if _, err := membership.DecodeKey(r.CoordinatorPublicKey); err != nil {
		return Network{}, fmt.Errorf("%w: coordinator key must be canonical Base64", ErrInvalid)
	}
	_, root, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Network{}, err
	}
	now := timestamp(time.Now())
	// The creator joins through an invite of its own, so every member has the
	// same chain shape.
	token, err := membership.Invite(root, r.Member, timestamp(time.Now().Add(30*24*time.Hour)))
	if err != nil {
		return Network{}, err
	}
	self, err := token.Join(s.privateKey, now)
	if err != nil {
		return Network{}, err
	}
	n := Network{ID: token.NetworkID, Name: r.Name, RootPublicKey: token.RootPublicKey, Member: r.Member, CoordinatorAddress: r.CoordinatorAddress, CoordinatorPublicKey: r.CoordinatorPublicKey, Administrator: true}
	advertise, _ := s.coordinationConfig()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return n, err
	}
	defer tx.Rollback()
	data, err := json.Marshal(n)
	if err != nil {
		return n, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO networks VALUES (?, ?, ?)", n.ID, string(data), root.Seed()); err != nil {
		return n, err
	}
	member := NetworkMember{HostID: s.identity.ID, PublicKey: s.identity.PublicKey, Member: r.Member, Address: advertise, UpdatedAt: now, Membership: self}
	if err = putJSON(ctx, tx, "INSERT INTO network_members (record, network_id, host_id) VALUES (?, ?, ?)", member, n.ID, member.HostID); err != nil {
		return n, err
	}
	if err = appendEvent(ctx, tx, "network.created", n.ID, now); err != nil {
		return n, err
	}
	if err = tx.Commit(); err != nil {
		return n, err
	}
	return s.SyncNetwork(ctx, n.ID)
}

func (s *Store) CreateInvite(ctx context.Context, id string, r CreateInvite) (Invite, error) {
	var record string
	var seed []byte
	err := s.db.QueryRowContext(ctx, "SELECT record, root_seed FROM networks WHERE id = ?", id).Scan(&record, &seed)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	if err != nil {
		return Invite{}, err
	}
	var n Network
	if err = json.Unmarshal([]byte(record), &n); err != nil {
		return Invite{}, err
	}
	if len(seed) != ed25519.SeedSize {
		return Invite{}, ErrForbidden
	}
	if !membership.ValidLabel(r.Member) {
		return Invite{}, fmt.Errorf("%w: invalid member label", ErrInvalid)
	}
	expires, err := parseTime(r.ExpiresAt)
	now := time.Now()
	if err != nil || !expires.After(now) || expires.After(now.Add(30*24*time.Hour)) {
		return Invite{}, fmt.Errorf("%w: invite expiration must be in the next 30 days", ErrInvalid)
	}
	token, err := membership.Invite(ed25519.NewKeyFromSeed(seed), r.Member, r.ExpiresAt)
	if err != nil {
		return Invite{}, err
	}
	token.NetworkName, token.CoordinatorAddress, token.CoordinatorPublicKey = n.Name, n.CoordinatorAddress, n.CoordinatorPublicKey
	encoded, err := token.Encode()
	if err != nil {
		return Invite{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invite{}, err
	}
	defer tx.Rollback()
	if err = appendEvent(ctx, tx, "network.invite_issued", n.ID, timestamp(now)); err != nil {
		return Invite{}, err
	}
	return Invite{NetworkID: n.ID, Member: r.Member, InvitePublicKey: token.InvitePublicKey, InviteExpiresAt: r.ExpiresAt, Token: encoded}, tx.Commit()
}

func (s *Store) JoinNetwork(ctx context.Context, r JoinNetwork) (Network, error) {
	now := time.Now()
	token, err := membership.DecodeToken(r.Token, now)
	if err != nil {
		return Network{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err = s.Network(ctx, token.NetworkID); err == nil {
		return Network{}, fmt.Errorf("%w: network already joined", ErrConflict)
	} else if !errors.Is(err, ErrNotFound) {
		return Network{}, err
	}
	self, err := token.Join(s.privateKey, timestamp(now))
	if err != nil {
		return Network{}, err
	}
	n := Network{ID: token.NetworkID, Name: token.NetworkName, RootPublicKey: token.RootPublicKey, Member: token.Member, CoordinatorAddress: token.CoordinatorAddress, CoordinatorPublicKey: token.CoordinatorPublicKey}
	advertise, _ := s.coordinationConfig()
	m, err := s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(n.ID)+"/members", map[string]any{"membership": self, "address": advertise})
	if err != nil {
		return n, err
	}
	members, err := s.verifyMap(n, m)
	if err != nil {
		return n, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	synced := timestamp(time.Now())
	n.LastSyncAt = &synced
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return n, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM networks WHERE id = ?", n.ID).Scan(&exists); err != nil {
		return n, err
	}
	if exists != 0 {
		return n, fmt.Errorf("%w: network already joined", ErrConflict)
	}
	if err = putJSON(ctx, tx, "INSERT INTO networks (record, id) VALUES (?, ?)", n, n.ID); err != nil {
		return n, err
	}
	for _, member := range members {
		if err = putJSON(ctx, tx, "INSERT INTO network_members (record, network_id, host_id) VALUES (?, ?, ?)", member, n.ID, member.HostID); err != nil {
			return n, err
		}
	}
	if err = appendEvent(ctx, tx, "network.joined", n.ID, synced); err != nil {
		return n, err
	}
	for _, member := range members {
		if member.HostID != s.identity.ID {
			if err = appendEvent(ctx, tx, "network.member_added", member.HostID, synced); err != nil {
				return n, err
			}
		}
	}
	return n, tx.Commit()
}

// SyncNetwork registers an unregistered administered network, or syncs it,
// and applies the returned map. A coordination failure is recorded in the
// network's last_sync_error rather than returned.
func (s *Store) SyncNetwork(ctx context.Context, id string) (Network, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, err := s.Network(ctx, id)
	if err != nil {
		return n, err
	}
	self, err := readJSON[NetworkMember](s.db.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", id, s.identity.ID))
	if err != nil {
		return n, err
	}
	advertise, _ := s.coordinationConfig()
	var m membership.Map
	if n.Administrator && n.LastSyncAt == nil {
		m, err = s.callCoordinator(ctx, n, "/coord/v1/networks", map[string]any{"name": n.Name, "root_public_key": n.RootPublicKey, "membership": self.Membership, "address": advertise})
	} else {
		m, err = s.callCoordinator(ctx, n, "/coord/v1/networks/"+url.PathEscape(n.ID)+"/sync", map[string]any{"address": advertise})
	}
	var members []NetworkMember
	if err == nil {
		members, err = s.verifyMap(n, m)
	}
	// Persist outcomes even if the requesting client disconnected.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, txErr := s.db.BeginTx(finishCtx, nil)
	if txErr != nil {
		return n, txErr
	}
	defer tx.Rollback()
	now := timestamp(time.Now())
	if err != nil {
		message := err.Error()
		n.LastSyncError = &message
	} else {
		n.LastSyncAt, n.LastSyncError = &now, nil
		if txErr = s.replaceMembers(finishCtx, tx, n.ID, members, now); txErr != nil {
			return n, txErr
		}
	}
	if txErr = putJSON(finishCtx, tx, "UPDATE networks SET record = ? WHERE id = ?", n, n.ID); txErr != nil {
		return n, txErr
	}
	return n, tx.Commit()
}

func (s *Store) replaceMembers(ctx context.Context, tx *sql.Tx, network string, members []NetworkMember, now string) error {
	rows, err := tx.QueryContext(ctx, "SELECT host_id FROM network_members WHERE network_id = ?", network)
	if err != nil {
		return err
	}
	previous := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		previous[id] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM network_members WHERE network_id = ?", network); err != nil {
		return err
	}
	current := map[string]bool{}
	for _, member := range members {
		current[member.HostID] = true
		if err = putJSON(ctx, tx, "INSERT INTO network_members (record, network_id, host_id) VALUES (?, ?, ?)", member, network, member.HostID); err != nil {
			return err
		}
		if !previous[member.HostID] && member.HostID != s.identity.ID {
			if err = appendEvent(ctx, tx, "network.member_added", member.HostID, now); err != nil {
				return err
			}
		}
	}
	removed := []string{}
	for id := range previous {
		if !current[id] && id != s.identity.ID {
			removed = append(removed, id)
		}
	}
	sort.Strings(removed)
	for _, id := range removed {
		if err = appendEvent(ctx, tx, "network.member_removed", id, now); err != nil {
			return err
		}
	}
	return nil
}

// verifyMap keeps only entries whose chains verify under the stored root, and
// drops every entry sharing an invite key with a different host or sharing a
// host ID with another entry. An invalid address is kept as "". The map must
// include this host.
func (s *Store) verifyMap(n Network, m membership.Map) ([]NetworkMember, error) {
	if m.NetworkID != n.ID || m.RootPublicKey != n.RootPublicKey {
		return nil, errors.New("coordinator map is for a different network")
	}
	root, err := membership.DecodeKey(n.RootPublicKey)
	if err != nil {
		return nil, err
	}
	var candidates []NetworkMember
	invites := map[string]map[string]bool{}
	hosts := map[string]int{}
	for _, entry := range m.Members {
		var proof membership.Membership
		if json.Unmarshal(entry.Membership, &proof) != nil {
			continue
		}
		id, err := proof.Verify(root)
		if err != nil || id != entry.HostID {
			continue
		}
		if !membership.ValidAddress(entry.Address) {
			entry.Address = ""
		}
		if _, err = parseTime(entry.UpdatedAt); err != nil {
			continue
		}
		if invites[proof.InvitePublicKey] == nil {
			invites[proof.InvitePublicKey] = map[string]bool{}
		}
		invites[proof.InvitePublicKey][proof.HostPublicKey] = true
		hosts[id]++
		candidates = append(candidates, NetworkMember{HostID: id, PublicKey: proof.HostPublicKey, Member: proof.Member, Address: entry.Address, UpdatedAt: entry.UpdatedAt, Membership: proof})
	}
	members := []NetworkMember{}
	var found bool
	for _, member := range candidates {
		if len(invites[member.Membership.InvitePublicKey]) != 1 || hosts[member.HostID] != 1 {
			continue
		}
		// Any validly signed membership for this host's key is accepted; a
		// coordinator keeps the original membership when a join is retried.
		found = found || member.HostID == s.identity.ID
		members = append(members, member)
	}
	if !found {
		return nil, errors.New("coordinator map does not include this host's membership")
	}
	sort.Slice(members, func(i, j int) bool { return members[i].HostID < members[j].HostID })
	return members, nil
}

// coordinatorTLS proves this host's key and pins the network's coordinator,
// offering one application protocol: the coordination API or the relay.
func (s *Store) coordinatorTLS(n Network, alpn string) (*tls.Config, error) {
	pinned, err := membership.DecodeKey(n.CoordinatorPublicKey)
	if err != nil {
		return nil, err
	}
	cert, err := s.peerCertificate()
	if err != nil {
		return nil, err
	}
	config := tlsid.Config()
	config.NextProtos = []string{alpn}
	config.Certificates = []tls.Certificate{cert}
	// The coordinator is authenticated by its pinned key, not a CA or DNS name.
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		public, err := tlsid.PeerKey(state)
		if err != nil {
			return err
		}
		if !bytes.Equal(public, pinned) {
			return errors.New("coordinator identity pin mismatch")
		}
		return nil
	}
	return config, nil
}

// callCoordinator posts to the pinned coordinator and decodes its map.
func (s *Store) callCoordinator(ctx context.Context, n Network, path string, body any) (membership.Map, error) {
	var m membership.Map
	config, err := s.coordinatorTLS(n, "http/1.1")
	if err != nil {
		return m, err
	}
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	encoded, err := json.Marshal(body)
	if err != nil {
		return m, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+n.CoordinatorAddress+path, bytes.NewReader(encoded))
	if err != nil {
		return m, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return m, fmt.Errorf("%w: coordinator: %v", ErrUnavailable, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return m, fmt.Errorf("%w: coordinator response unreadable or too large", ErrUnavailable)
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &failure)
		cause := map[int]error{400: ErrInvalid, 403: ErrForbidden, 404: ErrNotFound, 409: ErrConflict}[response.StatusCode]
		if cause == nil {
			cause = ErrUnavailable
		}
		return m, fmt.Errorf("%w: coordinator returned HTTP %d: %s", cause, response.StatusCode, failure.Error)
	}
	if err = json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("%w: malformed coordinator map", ErrUnavailable)
	}
	return m, nil
}

// RunCoordination syncs every network each interval until ctx is cancelled.
func (s *Store) RunCoordination(ctx context.Context, logf func(string, ...any)) {
	_, interval := s.coordinationConfig()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		networks, err := s.Networks(ctx)
		if err != nil && ctx.Err() == nil {
			logf("coordination: %v", err)
		}
		for _, n := range networks {
			if ctx.Err() != nil {
				return
			}
			if _, err := s.SyncNetwork(ctx, n.ID); err != nil && ctx.Err() == nil {
				logf("coordination sync %s: %v", n.ID, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// KnownHost resolves a manually configured peer, or a verified member of any
// network other than this host. When public is given it must match.
func (s *Store) KnownHost(ctx context.Context, id string, public []byte) (Peer, error) {
	p, err := s.Peer(ctx, id)
	if errors.Is(err, ErrNotFound) && id != s.identity.ID {
		var member NetworkMember
		member, err = readJSON[NetworkMember](s.db.QueryRowContext(ctx, "SELECT record FROM network_members WHERE host_id = ? LIMIT 1", id))
		p = Peer{ID: member.HostID, PublicKey: member.PublicKey}
	}
	if err != nil {
		return p, err
	}
	key, err := peerKey(p)
	if err != nil || (public != nil && !bytes.Equal(key, public)) {
		return p, ErrNotFound
	}
	return p, nil
}

// dialPeer prefers a manual peer's address, then the nonempty member address
// most recently updated by any coordinator.
func (s *Store) dialPeer(ctx context.Context, id string) (Peer, error) {
	p, err := s.KnownHost(ctx, id, nil)
	if err != nil || p.Address != "" {
		return p, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM network_members WHERE host_id = ?", id)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	var latest time.Time
	for rows.Next() {
		member, err := readJSON[NetworkMember](rows)
		if err != nil {
			return p, err
		}
		updated, err := parseTime(member.UpdatedAt)
		if err == nil && member.Address != "" && (p.Address == "" || updated.After(latest)) {
			p.Address, latest = member.Address, updated
		}
	}
	return p, rows.Err()
}

// connected reports whether the requester is a member of a network this host
// synced within three coordination intervals.
func (s *Store) connected(ctx context.Context, tx *sql.Tx, requester string, now time.Time) (bool, error) {
	_, interval := s.coordinationConfig()
	rows, err := tx.QueryContext(ctx, "SELECT n.record FROM networks n JOIN network_members m ON m.network_id = n.id WHERE m.host_id = ?", requester)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		n, err := readJSON[Network](rows)
		if err != nil {
			return false, err
		}
		if n.LastSyncAt == nil {
			continue
		}
		if synced, err := parseTime(*n.LastSyncAt); err == nil && !now.After(synced.Add(3*interval)) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func localNetworkRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/networks", func(w http.ResponseWriter, r *http.Request) {
		var req CreateNetwork
		if !decode(w, r, &req, "name", "member", "coordinator_address", "coordinator_public_key") {
			return
		}
		n, err := store.CreateNetwork(r.Context(), req)
		respond(w, http.StatusCreated, n, err)
	})
	mux.HandleFunc("POST /v1/networks/join", func(w http.ResponseWriter, r *http.Request) {
		var req JoinNetwork
		if !decode(w, r, &req, "token") {
			return
		}
		n, err := store.JoinNetwork(r.Context(), req)
		respond(w, http.StatusCreated, n, err)
	})
	mux.HandleFunc("GET /v1/networks", func(w http.ResponseWriter, r *http.Request) {
		n, err := store.Networks(r.Context())
		respond(w, http.StatusOK, n, err)
	})
	mux.HandleFunc("GET /v1/networks/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		m, err := store.NetworkMembers(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, m, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/invites", func(w http.ResponseWriter, r *http.Request) {
		var req CreateInvite
		if !decode(w, r, &req, "member", "expires_at") {
			return
		}
		invite, err := store.CreateInvite(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusCreated, invite, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/sync", func(w http.ResponseWriter, r *http.Request) {
		n, err := store.SyncNetwork(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, n, err)
	})
}
