package coord

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/relay"
	"github.com/peerspan/peerspan/go/internal/tlsid"
)

// Relay limits from the coordination contract.
const (
	relayMaxConnections      = 4096
	coordinatorMaxHandshakes = 128
	relayMaxRefused          = 64
	relayIdleTimeout         = 45 * time.Second
	relayQueueBytes          = 1 << 20
	relayRateBytes           = 8 << 20
	relayBurstBytes          = 8 << 20
	relayMembershipTTL       = 5 * time.Second
	relayHandshake           = 10 * time.Second
	relayWriteTimeout        = 10 * time.Second
	relayUnreachableGap      = time.Second
	// relayChangedGap bounds changed frames per network per connection, and
	// presence frames per (network, source host) per connection; later ones
	// coalesce into the next frame.
	relayChangedGap = 250 * time.Millisecond
)

// relayServer forwards already-encrypted peer datagrams between hosts that are
// currently members of a common network on this coordinator.
type relayServer struct {
	s *Server

	maxConns int
	idle     time.Duration
	queue    int
	rate     float64
	burst    float64
	ttl      time.Duration
	now      func() time.Time

	mu         sync.Mutex
	admissions chan struct{}
	conns      map[relay.HostID]*relayConn
	members    map[relay.HostID]cachedNetworks
	usage      relayUsage
}

type cachedNetworks struct {
	networks map[string]bool
	fetched  time.Time
}

type relayConn struct {
	id           relay.HostID
	conn         net.Conn
	out          chan []byte
	done         chan struct{}
	once         sync.Once
	mu           sync.Mutex
	queued       int
	tokens       float64
	refill       time.Time
	refused      map[relay.HostID]time.Time
	refusedSweep time.Time
	// version is the negotiated relay version: 2 and later receive changed
	// frames, and 3 sends and receives presence frames.
	version int
	// notices holds the state of frames sent on this connection: changed
	// frames per network, and presence frames per network and source host.
	// inbound holds the state of presence frames this host sent, per network.
	notices map[string]*notice
	inbound map[string]*notice
	// Frame bytes read and written, for the relay log line.
	bytesIn, bytesOut atomic.Int64
}

// notice is the changed-frame state of one network on one connection.
type notice struct {
	last    time.Time
	pending bool
}

func newRelayServer(s *Server) *relayServer {
	return &relayServer{s: s, maxConns: relayMaxConnections, idle: relayIdleTimeout, queue: relayQueueBytes,
		rate: relayRateBytes, burst: relayBurstBytes, ttl: relayMembershipTTL, now: time.Now,
		admissions: make(chan struct{}, coordinatorMaxHandshakes),
		conns:      map[relay.HostID]*relayConn{}, members: map[relay.HostID]cachedNetworks{}}
}

// networksOf returns the networks a host belongs to, refreshed at most every
// ttl so membership changes take effect within that bound.
func (r *relayServer) networksOf(ctx context.Context, id relay.HostID) (map[string]bool, error) {
	now := r.now()
	r.mu.Lock()
	cached, ok := r.members[id]
	r.mu.Unlock()
	if ok && now.Sub(cached.fetched) < r.ttl {
		return cached.networks, nil
	}
	rows, err := r.s.db.QueryContext(ctx, `SELECT network_id FROM members WHERE host_id = ?`, id.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	networks := map[string]bool{}
	for rows.Next() {
		var network string
		if err = rows.Scan(&network); err != nil {
			return nil, err
		}
		networks[network] = true
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	// Cache only live registrations. Rejected identities and disconnected
	// hosts must not accumulate state; conns bounds this cache's cardinality.
	if len(networks) > 0 && r.conns[id] != nil {
		r.members[id] = cachedNetworks{networks: networks, fetched: now}
	} else {
		delete(r.members, id)
	}
	r.mu.Unlock()
	return networks, nil
}

// sharedNetwork is the lowest-ID network both hosts belong to, the one hosts
// use to choose the relay and the one relayed bytes are charged to.
func (r *relayServer) sharedNetwork(ctx context.Context, a, b relay.HostID) (string, bool) {
	first, err := r.networksOf(ctx, a)
	if err != nil {
		return "", false
	}
	second, err := r.networksOf(ctx, b)
	if err != nil {
		return "", false
	}
	lowest := ""
	for network := range first {
		if second[network] && (lowest == "" || network < lowest) {
			lowest = network
		}
	}
	return lowest, lowest != ""
}

// serve runs one authenticated relay connection until it fails, goes idle,
// is replaced, or ctx ends.
func (r *relayServer) serve(ctx context.Context, conn *tls.Conn, sequence int64) {
	defer conn.Close()
	public, err := tlsid.PeerKey(conn.ConnectionState())
	if err != nil {
		return
	}
	id, err := relay.ParseHostID(membership.HostID(public))
	if err != nil {
		return
	}
	alpn := conn.ConnectionState().NegotiatedProtocol
	// Even a refused authenticated client still uses this identity's
	// listener. Keep that retirement signal in the bounded telemetry cache.
	r.s.hosts.record(sequence, id.String(), time.Now())
	start := time.Now()
	var c *relayConn
	defer func() {
		var in, out int64
		if c != nil {
			in, out = c.bytesIn.Load(), c.bytesOut.Load()
		}
		r.s.Log.LogAttrs(context.Background(), slog.LevelInfo, "relay", slog.String("host", id.String()), slog.String("alpn", alpn),
			slog.Int64("bytes_in", in), slog.Int64("bytes_out", out), slog.Float64("duration_ms", milliseconds(time.Since(start))))
	}()
	// Check admission before allocating the connection's output queue.
	// TLS negotiation is already complete, so independently bound callers
	// waiting for the serialized database admission lookup.
	select {
	case r.admissions <- struct{}{}:
	default:
		return
	}
	networks, err := func() (map[string]bool, error) {
		defer func() { <-r.admissions }()
		return r.networksOf(ctx, id)
	}()
	if err != nil || len(networks) == 0 {
		return
	}
	r.mu.Lock()
	old := r.conns[id]
	if old == nil && len(r.conns) >= r.maxConns {
		r.mu.Unlock()
		return
	}
	c = &relayConn{id: id, conn: conn, out: make(chan []byte, 4096), done: make(chan struct{}), tokens: r.burst, refill: r.now(), refused: map[relay.HostID]time.Time{},
		version: relayVersion(alpn), notices: map[string]*notice{}, inbound: map[string]*notice{}}
	r.conns[id] = c
	r.members[id] = cachedNetworks{networks: networks, fetched: r.now()}
	r.mu.Unlock()
	if old != nil {
		old.close()
	}
	defer func() {
		c.close()
		r.mu.Lock()
		if r.conns[id] == c {
			delete(r.conns, id)
			delete(r.members, id)
		}
		r.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, c.close)
	defer stop()
	go c.write()
	reader := bufio.NewReaderSize(countingReader{conn, &c.bytesIn}, 64<<10)
	for {
		_ = conn.SetReadDeadline(r.now().Add(r.idle))
		kind, dest, datagram, err := relay.Read(reader, true)
		if err != nil {
			return
		}
		switch kind {
		case relay.FrameSend:
			r.forward(ctx, c, dest, datagram)
		case relay.FramePresence:
			// Version 1 and 2 connections never carry presence frames.
			if c.version < 3 {
				return
			}
			r.presence(ctx, c, string(datagram))
		}
	}
}

func (r *relayServer) forward(ctx context.Context, src *relayConn, dest relay.HostID, datagram []byte) {
	if !src.take(r, len(datagram)) {
		return
	}
	r.mu.Lock()
	target := r.conns[dest]
	r.mu.Unlock()
	network, shared := "", false
	if target != nil && dest != src.id {
		network, shared = r.sharedNetwork(ctx, src.id, dest)
	}
	// A network over its monthly relay bytes has its frames dropped, and the
	// sender is told the destination is unreachable.
	charged := shared && r.usage.charge(ctx, r.s.db, usageKey{network, monthOf(r.now())}, int64(len(datagram)), r.s.Limits.RelayBytesPerMonth)
	if shared && !charged {
		r.s.metrics.refused(limitRelayBytes)
	}
	if !charged {
		now := r.now()
		if now.Sub(src.refusedSweep) >= relayUnreachableGap {
			for id, at := range src.refused {
				if now.Sub(at) >= relayUnreachableGap {
					delete(src.refused, id)
				}
			}
			src.refusedSweep = now
		}
		if last, ok := src.refused[dest]; !ok || now.Sub(last) >= relayUnreachableGap {
			if !ok && len(src.refused) >= relayMaxRefused {
				return // Bound random-destination bookkeeping and notifications.
			}
			src.refused[dest] = now
			src.enqueue(r, frame(relay.FrameUnreachable, dest[:]))
		}
		return
	}
	r.s.metrics.relayBytes.Add(uint64(len(datagram)))
	target.enqueue(r, frame(relay.FrameReceive, src.id[:], datagram))
}

// connections counts open relay connections by negotiated ALPN.
func (r *relayServer) connections() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := map[string]int{}
	for _, c := range r.conns {
		counts[relayALPN(c.version)]++
	}
	return counts
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// changed tells every member host of a network with a current version 2
// relay connection that the network changed. Membership may have changed, so
// the forwarding cache is dropped too.
func (r *relayServer) changed(network string) {
	r.mu.Lock()
	r.members = map[relay.HostID]cachedNetworks{}
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := r.s.db.QueryContext(ctx, `SELECT host_id FROM members WHERE network_id = ?`, network)
	if err != nil {
		return
	}
	var hosts []relay.HostID
	for rows.Next() {
		var host string
		if rows.Scan(&host) != nil {
			continue
		}
		if id, err := relay.ParseHostID(host); err == nil {
			hosts = append(hosts, id)
		}
	}
	rows.Close()
	for _, id := range hosts {
		r.mu.Lock()
		c := r.conns[id]
		r.mu.Unlock()
		if c != nil && c.version >= 2 {
			c.notify(r, network)
		}
	}
}

// notify sends a changed frame for a network now, or, within relayChangedGap
// of the previous one, once when the gap ends.
func (c *relayConn) notify(r *relayServer, network string) {
	c.throttle(r, c.notices, network, func() {
		if c.enqueue(r, frame(relay.FrameChanged, []byte(network))) {
			r.s.metrics.notified.Add(1)
		}
	})
}

// throttle runs send for key now, or, within relayChangedGap of its previous
// run, once when the gap ends; requests during the gap coalesce into that one.
// Nothing runs once the connection has closed.
func (c *relayConn) throttle(r *relayServer, notices map[string]*notice, key string, send func()) {
	c.mu.Lock()
	n := notices[key]
	if n == nil {
		n = &notice{}
		notices[key] = n
	}
	if n.pending {
		c.mu.Unlock()
		return
	}
	now := r.now()
	wait := n.last.Add(relayChangedGap).Sub(now)
	if n.last.IsZero() || wait <= 0 {
		n.last = now
		c.mu.Unlock()
		send()
		return
	}
	n.pending = true
	c.mu.Unlock()
	time.AfterFunc(wait, func() {
		c.mu.Lock()
		n.pending, n.last = false, r.now()
		c.mu.Unlock()
		select {
		case <-c.done:
		default:
			send()
		}
	})
}

// relayVersion is the relay protocol version an ALPN selects.
func relayVersion(alpn string) int {
	switch alpn {
	case relay.ALPNv3:
		return 3
	case relay.ALPNv2:
		return 2
	}
	return 1
}

// relayALPN is the ALPN of a relay protocol version.
func relayALPN(version int) string {
	switch version {
	case 3:
		return relay.ALPNv3
	case 2:
		return relay.ALPNv2
	}
	return relay.ALPN
}

// presence handles a presence frame from a version 3 connection. It is
// forwarded only when its sender is a current member of that network, at most
// once per network per relayChangedGap from this connection, later ones
// coalescing into the next; anything else is dropped without a reply.
// Nothing about it is stored.
func (r *relayServer) presence(ctx context.Context, src *relayConn, network string) {
	networks, err := r.networksOf(ctx, src.id)
	if err != nil || !networks[network] {
		return
	}
	src.throttle(r, src.inbound, network, func() { r.announce(src.id, network) })
}

// announce forwards a member's presence to the current version 3 relay
// connection of every other current member of the network, at most once per
// (network, source host) per connection per relayChangedGap.
func (r *relayServer) announce(source relay.HostID, network string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := r.s.db.QueryContext(ctx, `SELECT host_id FROM members WHERE network_id = ?`, network)
	if err != nil {
		return
	}
	var hosts []relay.HostID
	member := false
	for rows.Next() {
		var host string
		if rows.Scan(&host) != nil {
			continue
		}
		id, err := relay.ParseHostID(host)
		switch {
		case err != nil:
		case id == source:
			member = true
		default:
			hosts = append(hosts, id)
		}
	}
	rows.Close()
	// The sender may have been revoked since its frame arrived.
	if !member {
		return
	}
	data := frame(relay.FramePresence, source[:], []byte(network))
	key := network + "\x00" + source.String()
	for _, id := range hosts {
		r.mu.Lock()
		c := r.conns[id]
		r.mu.Unlock()
		if c != nil && c.version >= 3 {
			c.throttle(r, c.notices, key, func() { c.enqueue(r, data) })
		}
	}
}

func frame(kind byte, parts ...[]byte) []byte {
	var buf frameBuffer
	_ = relay.Write(&buf, kind, parts...)
	return buf
}

type frameBuffer []byte

func (b *frameBuffer) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}

// take applies the per-source token bucket; frames over the rate are dropped.
func (c *relayConn) take(r *relayServer, n int) bool {
	now := r.now()
	c.tokens += now.Sub(c.refill).Seconds() * r.rate
	if c.tokens > r.burst {
		c.tokens = r.burst
	}
	c.refill = now
	if c.tokens < float64(n) {
		return false
	}
	c.tokens -= float64(n)
	return true
}

// enqueue drops the frame when the destination's buffer is full; QUIC
// recovers the loss.
func (c *relayConn) enqueue(r *relayServer, data []byte) bool {
	c.mu.Lock()
	if c.queued+len(data) > r.queue {
		c.mu.Unlock()
		return false
	}
	select {
	case c.out <- data:
		c.queued += len(data)
		c.mu.Unlock()
		return true
	default:
		c.mu.Unlock()
		return false
	}
}

func (c *relayConn) write() {
	for {
		select {
		case <-c.done:
			return
		case data := <-c.out:
			_ = c.conn.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
			n, err := c.conn.Write(data)
			c.bytesOut.Add(int64(n))
			c.mu.Lock()
			c.queued -= len(data)
			c.mu.Unlock()
			if err != nil {
				c.close()
				return
			}
		}
	}
}

func (c *relayConn) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

func (r *relayServer) closeAll() {
	r.mu.Lock()
	conns := make([]*relayConn, 0, len(r.conns))
	for _, c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()
	for _, c := range conns {
		c.close()
	}
}

// connListener feeds already-handshaken non-relay connections to http.Server.
type connListener struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.addr }

// handshake releases its admission slot as soon as negotiation completes;
// established relay connections must not occupy handshake slots.
func (s *Server) handshake(ctx context.Context, c net.Conn) error {
	defer func() { <-s.handshakes }()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return nil
	}
	_ = tc.SetDeadline(time.Now().Add(relayHandshake))
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	_ = tc.SetDeadline(time.Time{})
	return nil
}

// dispatch routes a negotiated connection by ALPN.
func (s *Server) dispatch(ctx context.Context, c net.Conn, httpConns *connListener, sequence int64) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		httpConns.push(c)
		return
	}
	if protocol := tc.ConnectionState().NegotiatedProtocol; protocol == relay.ALPN || protocol == relay.ALPNv2 || protocol == relay.ALPNv3 {
		s.relay.serve(ctx, tc, sequence)
		return
	}
	httpConns.push(tc)
}
