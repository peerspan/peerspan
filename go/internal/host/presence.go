package host

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/relay"
)

// Presence notifications (launch contract, slice 6). A host's presence in a
// network is what its peer route would serve for its local agents, ignoring
// authorizations: the set of agents and each agent's connected and channel.
// Agents are not per network, so a change is a change in every network. The
// host announces a change with a presence frame on each of its version 3
// relay connections; hosts told of another member's change refresh that one
// host's directory entry.

const (
	// presenceGap bounds presence frames per network; later changes in the
	// window are sent together once it ends.
	presenceGap = 250 * time.Millisecond
	// presenceRecheck is the fallback recomputation interval for changes no
	// request or lease deadline signals.
	presenceRecheck = 5 * time.Second
)

type presenceState struct {
	// wake asks the monitor to recompute presence now.
	wake chan struct{}

	mu sync.Mutex
	// sent is the per-network send state: the last send and whether a
	// trailing send is scheduled.
	sent map[string]*presenceSend
	// refreshing holds the (network, host) pairs with a presence refresh in
	// flight, each true when another presence arrived during it.
	refreshing map[string]bool
	ctx        context.Context
}

type presenceSend struct {
	last    time.Time
	pending bool
}

func newPresenceState() presenceState {
	return presenceState{wake: make(chan struct{}, 1), sent: map[string]*presenceSend{}, refreshing: map[string]bool{}}
}

// presenceChanged asks the monitor to compare this host's presence with the
// last it saw, without blocking.
func (s *Store) presenceChanged() {
	select {
	case s.presence.wake <- struct{}{}:
	default:
	}
}

// presenceTouching wraps a local or adapter handler so that every request
// that may change state rechecks presence once it has been answered and its
// transaction committed: registrations, attachments, detachments,
// revocations, replacements, leases, and channel verification all arrive
// this way.
func (s *Store) presenceTouching(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.presenceChanged()
		}
	})
}

// presenceView is this host's presence as a comparable string, and the
// earliest time a lease that counts now lapses, when presence changes by
// time alone (a lease never outlasts its authorization's expiry).
func (s *Store) presenceView(ctx context.Context) (string, time.Time, error) {
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id, name FROM agents ORDER BY id")
	if err != nil {
		return "", time.Time{}, err
	}
	var agents []localAgent
	for rows.Next() {
		var a localAgent
		if err = rows.Scan(&a.id, &a.name); err != nil {
			rows.Close()
			return "", time.Time{}, err
		}
		agents = append(agents, a)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return "", time.Time{}, err
	}
	var b strings.Builder
	for _, a := range agents {
		channel, err := agentChannel(ctx, tx, a.id, now)
		if err != nil {
			return "", time.Time{}, err
		}
		state := "-"
		if channel != nil {
			state = *channel
		}
		b.WriteString(a.id + "\x00" + a.name + "\x00" + state + "\n")
	}
	var next *int64
	err = tx.QueryRowContext(ctx, `SELECT MIN(x.lease_until_ms) FROM sessions ss JOIN adapter_credentials c ON c.session_id = ss.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE ss.state = 'attached' AND x.lease_until_ms > ? AND json_extract(c.record, '$.revoked_at') IS NULL AND json_extract(c.record, '$.expires_at') > ?`, now.UnixMilli(), timestamp(now)).Scan(&next)
	if err != nil {
		return "", time.Time{}, err
	}
	var lapse time.Time
	if next != nil {
		lapse = time.UnixMilli(*next)
	}
	return b.String(), lapse, nil
}

// runPresence watches this host's presence and announces each change in
// every network. It recomputes after state-changing requests, when the
// earliest counted lease lapses (nothing calls the daemon then), and every
// presenceRecheck as a fallback. Announcements after startup and relay
// (re)connections are made by the relay clients, unconditionally.
func (s *Store) runPresence(ctx context.Context) {
	s.presence.mu.Lock()
	s.presence.ctx = ctx
	s.presence.mu.Unlock()
	last, lapse, err := s.presenceView(ctx)
	known := err == nil
	timer := time.NewTimer(presenceRecheck)
	defer timer.Stop()
	for {
		wait := presenceRecheck
		if !lapse.IsZero() {
			// A lease counts while lease_until_ms > now, so check just after.
			wait = min(wait, time.Until(lapse)+time.Millisecond)
		}
		timer.Reset(max(wait, 0))
		select {
		case <-ctx.Done():
			return
		case <-s.presence.wake:
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		view, next, err := s.presenceView(ctx)
		if err != nil {
			lapse = time.Time{}
			continue
		}
		lapse = next
		if known && view == last {
			continue
		}
		last, known = view, true
		networks, err := s.Networks(ctx)
		if err != nil {
			continue
		}
		for _, n := range networks {
			s.sendPresence(n.ID)
		}
	}
}

// sendPresence announces this host's presence in a network now, or, within
// presenceGap of the previous announcement, once when the gap ends, so the
// last change is always announced.
func (s *Store) sendPresence(network string) {
	p := &s.presence
	p.mu.Lock()
	state := p.sent[network]
	if state == nil {
		state = &presenceSend{}
		p.sent[network] = state
	}
	if state.pending {
		p.mu.Unlock()
		return
	}
	now := time.Now()
	wait := state.last.Add(presenceGap).Sub(now)
	if state.last.IsZero() || wait <= 0 {
		state.last = now
		p.mu.Unlock()
		s.writePresence(network)
		return
	}
	state.pending = true
	p.mu.Unlock()
	time.AfterFunc(wait, func() {
		p.mu.Lock()
		state.pending, state.last = false, time.Now()
		p.mu.Unlock()
		s.writePresence(network)
	})
}

// writePresence queues a presence frame on the current relay connection to
// the network's coordinator, when that connection is up at version 3. A
// connection established later announces presence itself.
func (s *Store) writePresence(network string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n, err := s.Network(ctx, network)
	if err != nil {
		return
	}
	s.peer.mu.Lock()
	client := s.peer.relays[relayKey(n)]
	s.peer.mu.Unlock()
	if client != nil {
		client.presence(network)
	}
}

// relayConnected announces presence in each of this host's networks on a
// newly established version 3 connection to their coordinator, because its
// leases may not have survived a restart and peers may hold an older view.
func (s *Store) relayConnected(client *relayClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	networks, err := s.Networks(ctx)
	if err != nil {
		return
	}
	key := relayKey(client.network)
	for _, n := range networks {
		if relayKey(n) == key {
			s.sendPresence(n.ID)
		}
	}
}

// presenceReceived refreshes the directory entry of a host whose presence in
// a network changed. It is ignored for a network this host is not in, one
// that this coordinator does not serve, or a host that is not a current
// member of it in this host's map. At most one refresh per (network, host)
// runs; a presence arriving during one causes one more after it.
func (s *Store) presenceReceived(client *relayClient, source relay.HostID, network string) {
	host := source.String()
	if host == s.identity.ID {
		return
	}
	p := &s.presence
	key := network + "\x00" + host
	p.mu.Lock()
	if _, running := p.refreshing[key]; running {
		p.refreshing[key] = true
		p.mu.Unlock()
		return
	}
	p.refreshing[key] = false
	parent := p.ctx
	p.mu.Unlock()
	if parent == nil {
		parent = context.Background()
	}
	go func() {
		defer func() {
			p.mu.Lock()
			delete(p.refreshing, key)
			p.mu.Unlock()
		}()
		if !s.presenceSource(parent, client, host, network) {
			return
		}
		for {
			ctx, cancel := context.WithTimeout(parent, directoryWait+directoryQueryTimeout)
			_ = s.refreshDirectory(ctx, network, host, false)
			cancel()
			p.mu.Lock()
			again := p.refreshing[key]
			p.refreshing[key] = false
			p.mu.Unlock()
			if !again || parent.Err() != nil {
				return
			}
		}
	}()
}

// presenceSource reports whether host is a current member of a network this
// host is in, according to this host's map, and the network's coordinator is
// the one that relayed the presence.
func (s *Store) presenceSource(ctx context.Context, client *relayClient, host, network string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	n, err := s.Network(ctx, network)
	if err != nil || relayKey(n) != relayKey(client.network) {
		return false
	}
	members, err := membersOf(ctx, s.db, network)
	if err != nil {
		return false
	}
	_, ok := members[host]
	return ok
}
