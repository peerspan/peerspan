package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/disco"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/relay"
	"github.com/Cerebral-Systems/capsule/go/internal/stun"
)

// Path discovery timing from the messaging contract.
const (
	discoCallEvery   = 10 * time.Second // at most one call-me-maybe per peer
	discoPingEvery   = 2 * time.Second  // ping candidates during a round
	discoRound       = 10 * time.Second // length of a discovery round
	discoKeepalive   = 5 * time.Second  // ping a direct path in use
	discoPathTimeout = 15 * time.Second // drop a direct path without pongs
	discoRetry       = 30 * time.Second // wait before discovering again
	discoPingTTL     = 5 * time.Second  // how long a ping awaits its pong
	discoIdle        = 60 * time.Second // forget a peer with no traffic
	discoTick        = 250 * time.Millisecond
	stunWait         = time.Second
)

// discoRoute is how a discovery message arrived, and so how to answer it.
type discoRoute struct {
	udp    netip.AddrPort // set for the UDP socket
	client *relayClient   // set for a relay connection
	peer   relay.HostID   // the relay frame's source host
}

type discoInbound struct {
	data  []byte
	route discoRoute
}

type pendingPing struct {
	endpoint netip.AddrPort
	sent     time.Time
}

type validPath struct {
	rtt      time.Duration
	lastPong time.Time
}

// peerPath is the discovery state for one relay-capable peer.
type peerPath struct {
	candidates    map[netip.AddrPort]bool
	pings         map[disco.TxID]pendingPing
	valid         map[netip.AddrPort]*validPath
	best          netip.AddrPort
	lastActive    time.Time // QUIC traffic to or from this peer
	lastRelayed   time.Time // QUIC traffic sent through the relay
	lastCall      time.Time
	roundUntil    time.Time
	lastRoundPing time.Time
	nextAttempt   time.Time
	lastKeepalive time.Time
}

type stunWaiter struct {
	from netip.AddrPort
	done chan netip.AddrPort
}

// pathManager finds and keeps direct UDP paths to relayed peers, below QUIC:
// QUIC always addresses such a peer by its synthetic address, and the packet
// conn sends to the peer's validated endpoint when one exists.
type pathManager struct {
	store *Store
	conn  *packetConn
	inbox chan discoInbound
	done  chan struct{}
	// skew shifts the clock; tests use it to pass timeouts without waiting.
	skew atomic.Int64

	mu    sync.Mutex
	peers map[relay.HostID]*peerPath
	seen  map[[44]byte]time.Time
	stun  map[stun.TxID]stunWaiter
	own   []netip.AddrPort // this host's published candidates
}

func newPathManager(s *Store, conn *packetConn) *pathManager {
	m := &pathManager{store: s, conn: conn, inbox: make(chan discoInbound, 256), done: make(chan struct{}), peers: map[relay.HostID]*peerPath{}, seen: map[[44]byte]time.Time{}, stun: map[stun.TxID]stunWaiter{}}
	go m.run()
	return m
}

func (m *pathManager) now() time.Time { return time.Now().Add(time.Duration(m.skew.Load())) }

func (m *pathManager) close() {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
}

func (m *pathManager) peer(id relay.HostID) *peerPath {
	p := m.peers[id]
	if p == nil {
		p = &peerPath{candidates: map[netip.AddrPort]bool{}, pings: map[disco.TxID]pendingPing{}, valid: map[netip.AddrPort]*validPath{}}
		m.peers[id] = p
	}
	return p
}

// active records QUIC traffic with a peer. relayed marks traffic sent through
// the relay, which starts discovery.
func (m *pathManager) active(id relay.HostID, relayed bool) {
	if m == nil {
		return
	}
	now := m.now()
	m.mu.Lock()
	p := m.peer(id)
	p.lastActive = now
	if relayed {
		p.lastRelayed = now
	}
	m.mu.Unlock()
}

// receive queues a STUN or discovery datagram; it never blocks the socket.
func (m *pathManager) receive(data []byte, route discoRoute) {
	if m == nil {
		return
	}
	select {
	case m.inbox <- discoInbound{data: data, route: route}:
	default:
	}
}

func (m *pathManager) run() {
	ticker := time.NewTicker(discoTick)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case in := <-m.inbox:
			if stun.IsMessage(in.data) {
				m.handleSTUN(in.data, in.route.udp)
			} else {
				m.handleDisco(in.data, in.route)
			}
		case <-ticker.C:
			m.tick()
		}
	}
}

func normalize(e netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(e.Addr().Unmap(), e.Port())
}

func newTxID() (t disco.TxID) {
	_, _ = rand.Read(t[:])
	return t
}

func (m *pathManager) self() relay.HostID {
	id, _ := relay.ParseHostID(m.store.identity.ID)
	return id
}

func (m *pathManager) encode(msg disco.Message) []byte {
	msg.Sender, msg.TxID, msg.Time = m.self(), newTxID(), m.now()
	return disco.Encode(msg, m.store.privateKey)
}

// sendPing pings an endpoint over UDP and records the ping so that only its
// own pong can validate the endpoint. Must be called with m.mu held.
func (m *pathManager) sendPing(id relay.HostID, p *peerPath, endpoint netip.AddrPort) {
	data := m.encode(disco.Message{Type: disco.Ping})
	parsed, err := disco.Parse(data)
	if err != nil {
		return
	}
	p.pings[parsed.TxID] = pendingPing{endpoint: endpoint, sent: m.now()}
	m.conn.writeUDP(data, endpoint)
}

// sendCall sends this host's candidates to a peer through the relay.
func (m *pathManager) sendCall(id relay.HostID) {
	m.mu.Lock()
	own := append([]netip.AddrPort(nil), m.own...)
	m.mu.Unlock()
	m.conn.writeRelay(id, m.encode(disco.Message{Type: disco.CallMeMaybe, Endpoints: own}))
}

// mapCandidates returns the candidates a peer published in any shared network.
func (m *pathManager) mapCandidates(id relay.HostID) []netip.AddrPort {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rows, err := m.store.db.QueryContext(ctx, "SELECT record FROM network_members WHERE host_id = ?", id.String())
	if err != nil {
		return nil
	}
	defer rows.Close()
	var endpoints []netip.AddrPort
	for rows.Next() {
		member, err := readJSON[NetworkMember](rows)
		if err != nil {
			continue
		}
		for _, c := range member.Candidates {
			if e, err := netip.ParseAddrPort(c); err == nil {
				endpoints = append(endpoints, normalize(e))
			}
		}
	}
	return endpoints
}

func (m *pathManager) tick() {
	now := m.now()
	m.mu.Lock()
	for key, at := range m.seen {
		if now.Sub(at) > disco.ReplayWindow {
			delete(m.seen, key)
		}
	}
	var starting, forget []relay.HostID
	for id, p := range m.peers {
		for tx, ping := range p.pings {
			if now.Sub(ping.sent) > discoPingTTL {
				delete(p.pings, tx)
			}
		}
		if now.Sub(p.lastActive) > discoIdle && now.After(p.roundUntil) {
			forget = append(forget, id)
			continue
		}
		if p.best.IsValid() {
			if now.Sub(p.valid[p.best].lastPong) > discoPathTimeout {
				// The direct path went quiet: back to the relay, and retry later.
				delete(p.valid, p.best)
				p.best = netip.AddrPort{}
				p.nextAttempt = now.Add(discoRetry)
				m.conn.setDirect(id, m.bestOf(p))
				continue
			}
			if now.Sub(p.lastKeepalive) >= discoKeepalive {
				p.lastKeepalive = now
				for endpoint := range p.valid {
					m.sendPing(id, p, endpoint)
				}
			}
			continue
		}
		if now.Before(p.roundUntil) {
			if now.Sub(p.lastRoundPing) >= discoPingEvery {
				p.lastRoundPing = now
				for endpoint := range p.candidates {
					m.sendPing(id, p, endpoint)
				}
			}
			continue
		}
		// Start a round while QUIC traffic still goes through the relay.
		if now.Sub(p.lastRelayed) < discoRound && !now.Before(p.nextAttempt) {
			p.roundUntil = now.Add(discoRound)
			p.nextAttempt = p.roundUntil.Add(discoRetry)
			p.lastRoundPing = time.Time{}
			starting = append(starting, id)
		}
	}
	for _, id := range forget {
		delete(m.peers, id)
		m.conn.setDirect(id, netip.AddrPort{})
	}
	m.mu.Unlock()
	for _, id := range starting {
		candidates := m.mapCandidates(id)
		m.mu.Lock()
		p := m.peer(id)
		for _, c := range candidates {
			p.candidates[c] = true
		}
		call := now.Sub(p.lastCall) >= discoCallEvery
		if call {
			p.lastCall = now
		}
		m.mu.Unlock()
		if call {
			m.sendCall(id)
		}
	}
}

// bestOf picks the validated endpoint with the lowest round trip.
func (m *pathManager) bestOf(p *peerPath) netip.AddrPort {
	var best netip.AddrPort
	var rtt time.Duration = math.MaxInt64
	endpoints := make([]netip.AddrPort, 0, len(p.valid))
	for e := range p.valid {
		endpoints = append(endpoints, e)
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].String() < endpoints[j].String() })
	for _, e := range endpoints {
		if p.valid[e].rtt < rtt {
			best, rtt = e, p.valid[e].rtt
		}
	}
	return best
}

// handleDisco accepts a message only from a known host, signed by its pinned
// key, fresh within 30 seconds, and not a replayed transaction ID.
func (m *pathManager) handleDisco(data []byte, route discoRoute) {
	msg, err := disco.Parse(data)
	if err != nil {
		return
	}
	sender := relay.HostID(msg.Sender)
	if route.client != nil && sender != route.peer {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	peer, err := m.store.KnownHost(ctx, sender.String(), nil)
	cancel()
	if err != nil {
		return
	}
	key, err := peerKey(peer)
	if err != nil || !msg.Verify(ed25519.PublicKey(key)) || !msg.Fresh(m.now()) {
		return
	}
	var replay [44]byte
	copy(replay[:32], msg.Sender[:])
	copy(replay[32:], msg.TxID[:])
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[replay]; ok {
		return
	}
	m.seen[replay] = now
	p := m.peer(sender)
	switch msg.Type {
	case disco.Ping:
		pong := m.encode(disco.Message{Type: disco.Pong, PongTxID: msg.TxID, Observed: route.udp})
		if route.client != nil {
			route.client.send(sender, pong)
			return
		}
		m.conn.writeUDP(pong, route.udp)
		// The source becomes a candidate. Ping back at once and keep pinging
		// for a round, so this side validates the endpoint too before the peer
		// moves its QUIC traffic onto it. Only this host's own pong validates.
		p.candidates[route.udp] = true
		if _, ok := p.valid[route.udp]; !ok {
			m.sendPing(sender, p, route.udp)
			if !p.best.IsValid() && !now.Before(p.roundUntil) {
				p.lastActive = now
				p.roundUntil = now.Add(discoRound)
				p.lastRoundPing = now
			}
		}
	case disco.Pong:
		ping, ok := p.pings[msg.PongTxID]
		if !ok || !route.udp.IsValid() {
			return // only this host's own ping, answered over UDP, validates
		}
		delete(p.pings, msg.PongTxID)
		v := p.valid[route.udp]
		if v == nil {
			v = &validPath{}
			p.valid[route.udp] = v
		}
		v.rtt, v.lastPong = now.Sub(ping.sent), now
		if best := m.bestOf(p); best != p.best {
			p.best = best
			p.lastKeepalive = now
			m.conn.setDirect(sender, best)
		}
	case disco.CallMeMaybe:
		if route.client == nil {
			return // call-me-maybe travels through the relay only
		}
		for _, e := range msg.Endpoints {
			if e.Port() != 0 && e.Addr().IsValid() && !e.Addr().IsUnspecified() {
				p.candidates[normalize(e)] = true
			}
		}
		// Answer by pinging the listed endpoints, which opens this host's NAT.
		if !p.best.IsValid() {
			p.lastActive = now
			p.roundUntil = now.Add(discoRound)
			p.lastRoundPing = time.Time{}
		}
	}
}

func (m *pathManager) handleSTUN(data []byte, from netip.AddrPort) {
	tx, mapped, ok := stun.ParseResponse(data)
	if !ok {
		return
	}
	m.mu.Lock()
	waiter, ok := m.stun[tx]
	if ok && waiter.from == from {
		delete(m.stun, tx)
	}
	m.mu.Unlock()
	if ok && waiter.from == from {
		waiter.done <- mapped
	}
}

// reflexive asks a coordinator's STUN responder for this socket's public
// mapping, accepting only the matching transaction from that address.
func (m *pathManager) reflexive(ctx context.Context, coordinator string) (netip.AddrPort, error) {
	resolved, err := net.ResolveUDPAddr("udp", coordinator)
	if err != nil {
		return netip.AddrPort{}, err
	}
	to := normalize(resolved.AddrPort())
	var tx stun.TxID
	_, _ = rand.Read(tx[:])
	waiter := stunWaiter{from: to, done: make(chan netip.AddrPort, 1)}
	m.mu.Lock()
	m.stun[tx] = waiter
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.stun, tx)
		m.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, stunWait)
	defer cancel()
	for {
		m.conn.writeUDP(stun.Request(tx), to)
		select {
		case mapped := <-waiter.done:
			return normalize(mapped), nil
		case <-ctx.Done():
			return netip.AddrPort{}, errors.New("no STUN response from coordinator")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// setOwn records this host's published candidates for call-me-maybe.
func (m *pathManager) setOwn(candidates []string) {
	var own []netip.AddrPort
	for _, c := range candidates {
		if e, err := netip.ParseAddrPort(c); err == nil {
			own = append(own, e)
		}
	}
	m.mu.Lock()
	m.own = own
	m.mu.Unlock()
}

// PeerPath is the owner-local view of how this host reaches a peer.
type PeerPath struct {
	HostID   string   `json:"host_id"`
	Path     string   `json:"path"`
	Endpoint *string  `json:"endpoint"`
	RTTMs    *float64 `json:"rtt_ms"`
}

func (m *pathManager) state(id relay.HostID) PeerPath {
	view := PeerPath{HostID: id.String(), Path: "none"}
	m.mu.Lock()
	if p := m.peers[id]; p != nil && p.best.IsValid() {
		endpoint := p.best.String()
		rtt := math.Round(float64(p.valid[p.best].rtt.Microseconds())) / 1000
		view.Path, view.Endpoint, view.RTTMs = "direct", &endpoint, &rtt
	}
	m.mu.Unlock()
	if view.Path == "none" && m.conn.relayed(id) {
		view.Path = "relay"
	}
	return view
}

// PeerPath reports whether a known host is currently reached directly or
// through a relay. It reports state only and grants nothing.
func (s *Store) PeerPath(ctx context.Context, id string) (PeerPath, error) {
	if _, err := s.KnownHost(ctx, id, nil); err != nil {
		return PeerPath{}, err
	}
	host, err := relay.ParseHostID(id)
	if err != nil {
		return PeerPath{}, fmt.Errorf("%w: invalid host ID", ErrInvalid)
	}
	s.peer.mu.Lock()
	paths := s.peer.paths
	s.peer.mu.Unlock()
	if paths == nil {
		return PeerPath{HostID: id, Path: "none"}, nil
	}
	return paths.state(host), nil
}

// ownCandidates returns the candidates this host publishes to a network's
// coordinator: its reflexive address there, then its non-loopback interface
// addresses with the bound peer port, at most 8. A host without a peer
// listener publishes none.
func (s *Store) ownCandidates(ctx context.Context, coordinator string) []string {
	s.peer.mu.Lock()
	listening, paths, packets := s.peer.listening, s.peer.paths, s.peer.packets
	s.peer.mu.Unlock()
	candidates := []string{}
	if !listening || paths == nil || packets == nil {
		return candidates
	}
	if mapped, err := paths.reflexive(ctx, coordinator); err == nil {
		candidates = append(candidates, mapped.String())
	}
	bound := normalize(packets.udp.LocalAddr().(*net.UDPAddr).AddrPort())
	var addresses []netip.Addr
	if bound.Addr().IsUnspecified() {
		interfaces, _ := net.InterfaceAddrs()
		for _, a := range interfaces {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			addr := prefix.Addr().Unmap()
			// An IPv4 wildcard socket cannot use IPv6 interface addresses.
			if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() || (bound.Addr().Is4() && !addr.Is4()) {
				continue
			}
			addresses = append(addresses, addr)
		}
	} else if !bound.Addr().IsLoopback() {
		addresses = append(addresses, bound.Addr())
	}
	for _, addr := range addresses {
		candidates = append(candidates, netip.AddrPortFrom(addr, bound.Port()).String())
	}
	candidates = membership.FilterCandidates(candidates)
	paths.setOwn(candidates)
	return candidates
}
