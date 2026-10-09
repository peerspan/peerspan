package coord

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/relay"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
)

// Relay limits from the coordination contract.
const (
	relayMaxConnections = 4096
	relayIdleTimeout    = 45 * time.Second
	relayQueueBytes     = 1 << 20
	relayRateBytes      = 8 << 20
	relayBurstBytes     = 8 << 20
	relayMembershipTTL  = 5 * time.Second
	relayHandshake      = 10 * time.Second
	relayWriteTimeout   = 10 * time.Second
	relayUnreachableGap = time.Second
	// relayChangedGap bounds changed frames per network per connection;
	// later changes coalesce into the next frame.
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

	mu      sync.Mutex
	conns   map[relay.HostID]*relayConn
	members map[relay.HostID]cachedNetworks
	usage   relayUsage
}

type cachedNetworks struct {
	networks map[string]bool
	fetched  time.Time
}

type relayConn struct {
	id      relay.HostID
	conn    net.Conn
	out     chan []byte
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	queued  int
	tokens  float64
	refill  time.Time
	refused map[relay.HostID]time.Time
	// v2 connections negotiated capsule-relay/2 and receive changed frames.
	v2      bool
	notices map[string]*notice
}

// notice is the changed-frame state of one network on one connection.
type notice struct {
	last    time.Time
	pending bool
}

func newRelayServer(s *Server) *relayServer {
	return &relayServer{s: s, maxConns: relayMaxConnections, idle: relayIdleTimeout, queue: relayQueueBytes,
		rate: relayRateBytes, burst: relayBurstBytes, ttl: relayMembershipTTL, now: time.Now,
		conns: map[relay.HostID]*relayConn{}, members: map[relay.HostID]cachedNetworks{}}
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
	r.members[id] = cachedNetworks{networks: networks, fetched: now}
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
func (r *relayServer) serve(ctx context.Context, conn *tls.Conn) {
	defer conn.Close()
	public, err := tlsid.PeerKey(conn.ConnectionState())
	if err != nil {
		return
	}
	id, err := relay.ParseHostID(membership.HostID(public))
	if err != nil {
		return
	}
	if networks, err := r.networksOf(ctx, id); err != nil || len(networks) == 0 {
		return
	}
	c := &relayConn{id: id, conn: conn, out: make(chan []byte, 4096), done: make(chan struct{}), tokens: r.burst, refill: r.now(), refused: map[relay.HostID]time.Time{},
		v2: conn.ConnectionState().NegotiatedProtocol == relay.ALPNv2, notices: map[string]*notice{}}
	r.mu.Lock()
	// The cap counts current registrations; a replacement does not add one.
	old := r.conns[id]
	if old == nil && len(r.conns) >= r.maxConns {
		r.mu.Unlock()
		return
	}
	r.conns[id] = c
	r.mu.Unlock()
	if old != nil {
		old.close()
	}
	defer func() {
		c.close()
		r.mu.Lock()
		if r.conns[id] == c {
			delete(r.conns, id)
		}
		r.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, c.close)
	defer stop()
	go c.write()
	reader := bufio.NewReaderSize(conn, 64<<10)
	for {
		_ = conn.SetReadDeadline(r.now().Add(r.idle))
		kind, dest, datagram, err := relay.Read(reader, true)
		if err != nil {
			return
		}
		if kind != relay.FrameSend {
			continue
		}
		r.forward(ctx, c, dest, datagram)
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
	if !shared || !r.usage.charge(ctx, r.s.db, usageKey{network, monthOf(r.now())}, int64(len(datagram)), r.s.Limits.RelayBytesPerMonth) {
		now := r.now()
		if last, ok := src.refused[dest]; !ok || now.Sub(last) >= relayUnreachableGap {
			src.refused[dest] = now
			src.enqueue(r, frame(relay.FrameUnreachable, dest[:]))
		}
		return
	}
	target.enqueue(r, frame(relay.FrameReceive, src.id[:], datagram))
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
		if c != nil && c.v2 {
			c.notify(r, network)
		}
	}
}

// notify sends a changed frame for a network now, or, within relayChangedGap
// of the previous one, once when the gap ends.
func (c *relayConn) notify(r *relayServer, network string) {
	c.mu.Lock()
	n := c.notices[network]
	if n == nil {
		n = &notice{}
		c.notices[network] = n
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
		c.enqueue(r, frame(relay.FrameChanged, []byte(network)))
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
			c.enqueue(r, frame(relay.FrameChanged, []byte(network)))
		}
	})
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
			_, err := c.conn.Write(data)
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

// dispatch completes the TLS handshake and routes the connection by ALPN.
func (s *Server) dispatch(ctx context.Context, c net.Conn, httpConns *connListener) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		httpConns.push(c)
		return
	}
	_ = tc.SetDeadline(time.Now().Add(relayHandshake))
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	if protocol := tc.ConnectionState().NegotiatedProtocol; protocol == relay.ALPN || protocol == relay.ALPNv2 {
		s.relay.serve(ctx, tc)
		return
	}
	httpConns.push(tc)
}
