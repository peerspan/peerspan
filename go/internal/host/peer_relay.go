package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"net/netip"

	"github.com/Cerebral-Systems/capsule/go/internal/disco"
	"github.com/Cerebral-Systems/capsule/go/internal/relay"
	"github.com/Cerebral-Systems/capsule/go/internal/stun"
)

// Relay client timing from the coordination contract.
const (
	relayPingAfter      = 15 * time.Second
	relayBackoffMin     = time.Second
	relayBackoffMax     = 30 * time.Second
	relayDirectAttempt  = 2 * time.Second
	relayDialTimeout    = 5 * time.Second
	relayReadyWait      = 2 * time.Second
	relayOnDemandIdle   = 60 * time.Second
	relayManagerRefresh = 2 * time.Second
)

// syntheticPrefix marks addresses that stand for relayed peers. They come
// from a private IPv6 range and are never sent on the real UDP socket.
var syntheticPrefix = [4]byte{0xfd, 0x63, 0x61, 0x70}

// packetConn is the peer QUIC endpoint's socket. Real addresses use the UDP
// socket; synthetic addresses, one per relayed peer host ID, use the relay
// connection on which that peer's datagrams arrived, or the one chosen to
// dial it.
type packetConn struct {
	udp  *net.UDPConn
	in   chan datagram
	done chan struct{}
	once sync.Once

	// paths runs path discovery; it is set once, right after construction.
	paths *pathManager

	mu       sync.Mutex
	peers    map[[16]byte]relay.HostID
	routes   map[relay.HostID]*relayClient
	direct   map[relay.HostID]netip.AddrPort // validated endpoint in use
	owners   map[netip.AddrPort]relay.HostID // inverse of direct
	deadline time.Time
	changed  chan struct{}
}

type datagram struct {
	data []byte
	addr net.Addr
}

func newPacketConn(udp *net.UDPConn) *packetConn {
	c := &packetConn{udp: udp, in: make(chan datagram, 1024), done: make(chan struct{}), peers: map[[16]byte]relay.HostID{}, routes: map[relay.HostID]*relayClient{}, direct: map[relay.HostID]netip.AddrPort{}, owners: map[netip.AddrPort]relay.HostID{}, changed: make(chan struct{})}
	go c.readUDP()
	return c
}

func (c *packetConn) readUDP() {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		from := normalize(addr.AddrPort())
		switch {
		case isQUIC(data):
			// A validated endpoint's packets reach QUIC from the peer's
			// synthetic address, so QUIC never sees the path change.
			c.mu.Lock()
			id, direct := c.owners[from]
			c.mu.Unlock()
			if direct {
				c.paths.active(id, false)
				c.push(datagram{data: data, addr: c.synthetic(id)})
			} else {
				c.push(datagram{data: data, addr: addr})
			}
		case stun.IsMessage(data), disco.IsMessage(data):
			c.paths.receive(data, discoRoute{udp: from})
		}
	}
}

// isQUIC classifies a datagram by the QUIC fixed bit; STUN and path discovery
// messages always have it clear. This relies on no host greasing the fixed bit
// (RFC 9287): quic-go v0.63 never advertises grease_quic_bit (0x2ab2), always
// sets the bit, rejects packets without it, and ignores the parameter when a
// peer offers it, so a conforming peer never clears the bit toward a Go host.
// The Rust host disables quinn's grease_quic_bit for the same reason.
func isQUIC(data []byte) bool { return len(data) > 0 && data[0]&0x40 != 0 }

// push drops the datagram when the endpoint is not keeping up; QUIC recovers.
func (c *packetConn) push(d datagram) {
	select {
	case c.in <- d:
	case <-c.done:
	default:
	}
}

// synthetic returns the stable address standing for a relayed peer.
func (c *packetConn) synthetic(id relay.HostID) *net.UDPAddr {
	var ip [16]byte
	copy(ip[:], syntheticPrefix[:])
	copy(ip[4:], id[:12])
	c.mu.Lock()
	c.peers[ip] = id
	c.mu.Unlock()
	return &net.UDPAddr{IP: net.IP(ip[:]), Port: 1}
}

func isSynthetic(addr *net.UDPAddr) bool {
	ip := addr.IP.To16()
	return ip != nil && addr.IP.To4() == nil && [4]byte(ip[:4]) == syntheticPrefix
}

// route sets the relay used to reach a peer host.
func (c *packetConn) route(id relay.HostID, client *relayClient) {
	c.mu.Lock()
	c.routes[id] = client
	c.mu.Unlock()
}

// deliver hands a relayed datagram to the endpoint and records its return path.
func (c *packetConn) deliver(from relay.HostID, data []byte, client *relayClient) {
	addr := c.synthetic(from)
	c.route(from, client)
	switch {
	case isQUIC(data):
		c.paths.active(from, false)
		c.push(datagram{data: data, addr: addr})
	case disco.IsMessage(data):
		c.paths.receive(data, discoRoute{client: client, peer: from})
	}
}

// writeUDP sends a datagram on the real socket.
func (c *packetConn) writeUDP(data []byte, to netip.AddrPort) {
	_, _ = c.udp.WriteToUDPAddrPort(data, to)
}

// writeRelay sends a datagram to a peer through its current relay route.
func (c *packetConn) writeRelay(id relay.HostID, data []byte) {
	c.mu.Lock()
	client := c.routes[id]
	c.mu.Unlock()
	if client != nil {
		client.send(id, data)
	}
}

// relayed reports whether a peer has a relay route.
func (c *packetConn) relayed(id relay.HostID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.routes[id] != nil
}

// setDirect sends a peer's synthetic-addressed packets to a validated endpoint,
// or, given an invalid endpoint, back through the relay.
func (c *packetConn) setDirect(id relay.HostID, endpoint netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.direct[id]; ok {
		delete(c.owners, old)
		delete(c.direct, id)
	}
	if endpoint.IsValid() {
		if previous, ok := c.owners[endpoint]; ok {
			delete(c.direct, previous)
		}
		c.direct[id] = endpoint
		c.owners[endpoint] = id
	}
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		deadline, changed := c.deadline, c.changed
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			timeout = timer.C
		}
		select {
		case d := <-c.in:
			if timer != nil {
				timer.Stop()
			}
			return copy(p, d.data), d.addr, nil
		case <-c.done:
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("unsupported peer address")
	}
	if !isSynthetic(udp) {
		return c.udp.WriteTo(p, udp)
	}
	var ip [16]byte
	copy(ip[:], udp.IP.To16())
	c.mu.Lock()
	id, known := c.peers[ip]
	client := c.routes[id]
	endpoint, direct := c.direct[id]
	c.mu.Unlock()
	if !known {
		return len(p), nil
	}
	if direct {
		c.paths.active(id, false)
		_, err := c.udp.WriteToUDPAddrPort(p, endpoint)
		return len(p), err
	}
	if client != nil {
		c.paths.active(id, true)
		client.send(id, p)
	}
	// An unroutable relayed datagram is dropped like lost UDP.
	return len(p), nil
}

func (c *packetConn) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		err = c.udp.Close()
	})
	return err
}

func (c *packetConn) LocalAddr() net.Addr { return c.udp.LocalAddr() }

func (c *packetConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.udp.SetWriteDeadline(t)
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// SetReadBuffer and SetWriteBuffer let quic-go size the real socket's buffers.
func (c *packetConn) SetReadBuffer(bytes int) error  { return c.udp.SetReadBuffer(bytes) }
func (c *packetConn) SetWriteBuffer(bytes int) error { return c.udp.SetWriteBuffer(bytes) }

// relayClient keeps one relay connection to a coordinator, reconnecting with
// backoff while its context lives.
type relayClient struct {
	store     *Store
	network   Network
	packets   *packetConn
	out       chan []byte
	cancel    context.CancelFunc
	connected chan struct{}
	mu        sync.Mutex
	up        bool
	// persistent clients belong to a listening host; on-demand clients close
	// after relayOnDemandIdle without relayed traffic. QUIC connections idle
	// out after 30 seconds, so by then no relayed connection uses the client.
	persistent atomic.Bool
	lastUsed   atomic.Int64
}

func (r *relayClient) touch() { r.lastUsed.Store(time.Now().UnixNano()) }

func (r *relayClient) idle() bool {
	return !r.persistent.Load() && time.Since(time.Unix(0, r.lastUsed.Load())) > relayOnDemandIdle
}

func (r *relayClient) send(to relay.HostID, data []byte) {
	if len(data) == 0 || len(data) > relay.MaxDatagram {
		return
	}
	r.touch()
	var frame frameBytes
	_ = relay.Write(&frame, relay.FrameSend, to[:], data)
	select {
	case r.out <- frame:
	default:
	}
}

type frameBytes []byte

func (b *frameBytes) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}

func (r *relayClient) run(ctx context.Context) {
	reap := time.NewTicker(5 * time.Second)
	defer reap.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reap.C:
				if r.idle() {
					r.store.dropRelay(r)
					return
				}
			}
		}
	}()
	backoff := relayBackoffMin
	for ctx.Err() == nil {
		started := time.Now()
		err := r.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil && time.Since(started) > relayBackoffMax {
			backoff = relayBackoffMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, relayBackoffMax)
	}
}

// session runs one relay connection until it fails.
func (r *relayClient) session(ctx context.Context) error {
	config, err := r.store.coordinatorTLS(r.network, relay.ALPN)
	if err != nil {
		return err
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: relayDialTimeout}, Config: config}
	dialCtx, cancel := context.WithTimeout(ctx, relayDialTimeout)
	raw, err := dialer.DialContext(dialCtx, "tcp", r.network.CoordinatorAddress)
	cancel()
	if err != nil {
		return err
	}
	conn := raw.(*tls.Conn)
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != relay.ALPN {
		return errors.New("coordinator did not negotiate " + relay.ALPN)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	r.setUp(true)
	defer r.setUp(false)
	failed := make(chan error, 1)
	go func() {
		reader := bufio.NewReaderSize(conn, 64<<10)
		for {
			kind, peer, data, err := relay.Read(reader, false)
			if err != nil {
				failed <- err
				return
			}
			if kind == relay.FrameReceive {
				r.touch()
				r.packets.deliver(peer, data, r)
			}
		}
	}()
	ping := time.NewTimer(relayPingAfter)
	defer ping.Stop()
	for {
		var frame []byte
		select {
		case err := <-failed:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case frame = <-r.out:
		case <-ping.C:
			var p frameBytes
			_ = relay.Write(&p, relay.FramePing)
			frame = p
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(frame); err != nil {
			return err
		}
		ping.Reset(relayPingAfter)
	}
}

func (r *relayClient) setUp(up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if up && !r.up {
		close(r.connected)
	}
	if !up && r.up {
		r.connected = make(chan struct{})
	}
	r.up = up
}

// ready returns a channel closed while a relay connection is established.
func (r *relayClient) ready() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected
}

func relayKey(n Network) string { return n.CoordinatorAddress + "|" + n.CoordinatorPublicKey }

// relayFor returns the running relay client for this network's coordinator,
// starting one if needed. persistent marks a listening host's connection.
func (s *Store) relayFor(n Network, persistent bool) (*relayClient, error) {
	s.peer.mu.Lock()
	defer s.peer.mu.Unlock()
	if s.peer.packets == nil {
		return nil, errors.New("peer socket is closed")
	}
	key := relayKey(n)
	if client, ok := s.peer.relays[key]; ok {
		if persistent {
			client.persistent.Store(true)
		}
		client.touch()
		return client, nil
	}
	if s.peer.relays == nil {
		s.peer.relays = map[string]*relayClient{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &relayClient{store: s, network: n, packets: s.peer.packets, out: make(chan []byte, 1024), cancel: cancel, connected: make(chan struct{})}
	client.persistent.Store(persistent)
	client.touch()
	s.peer.relays[key] = client
	go client.run(ctx)
	return client, nil
}

// dropRelay stops an idle on-demand relay client.
func (s *Store) dropRelay(client *relayClient) {
	s.peer.mu.Lock()
	if s.peer.relays[relayKey(client.network)] == client {
		delete(s.peer.relays, relayKey(client.network))
	}
	s.peer.mu.Unlock()
	client.cancel()
}

// relayNetwork returns the lowest-ID network this host shares with a peer,
// whose coordinator relays between them.
func (s *Store) relayNetwork(ctx context.Context, id string) (Network, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT n.record, n.root_seed IS NOT NULL FROM networks n JOIN network_members m ON m.network_id = n.id WHERE m.host_id = ? AND m.host_id != ? ORDER BY n.id LIMIT 1`, id, s.identity.ID)
	n, err := scanNetwork(row)
	if errors.Is(err, ErrNotFound) {
		return n, false, nil
	}
	return n, err == nil, err
}

// RunRelays keeps a relay connection to every coordinator of this host's
// networks, so a listening host is reachable through them. Hosts without a
// peer listener use relays only on demand to dial out.
func (s *Store) RunRelays(ctx context.Context) {
	ticker := time.NewTicker(relayManagerRefresh)
	defer ticker.Stop()
	for {
		networks, err := s.Networks(ctx)
		if err == nil {
			wanted := map[string]bool{}
			for _, n := range networks {
				wanted[relayKey(n)] = true
				if _, err := s.relayFor(n, true); err != nil {
					break
				}
			}
			s.peer.mu.Lock()
			for key, client := range s.peer.relays {
				if !wanted[key] {
					client.cancel()
					delete(s.peer.relays, key)
				}
			}
			s.peer.mu.Unlock()
		}
		// Polling is the fallback; creating or joining a network wakes this early.
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.relayWake:
		}
	}
}

// wakeRelays asks RunRelays to refresh now, without blocking.
func (s *Store) wakeRelays() {
	select {
	case s.relayWake <- struct{}{}:
	default:
	}
}
