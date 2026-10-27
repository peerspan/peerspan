package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/helper"
	"github.com/peerspan/peerspan/go/internal/relay"
	"github.com/peerspan/peerspan/go/internal/tlsid"
	"github.com/quic-go/quic-go"
)

// PeerALPN identifies the peer protocol: one HTTP/1.1 exchange per QUIC
// bidirectional stream.
const PeerALPN = "peerspan-peer/1"

const (
	peerHandshakeTimeout = 5 * time.Second
	peerIdleTimeout      = 30 * time.Second
	peerMaxConnections   = 64
	peerMaxStreams       = 16
	peerMaxBody          = 1 << 20
	peerRequestTimeout   = 8 * time.Second
)

// PeerQUICConfig bounds handshakes, idle connections, and concurrent streams.
// Neither side accepts unidirectional streams; a client accepts no streams.
func PeerQUICConfig(server bool) *quic.Config {
	streams := int64(-1)
	handshake := peerHandshakeTimeout
	if server {
		streams = peerMaxStreams
		// quic-go's total handshake deadline is twice its idle bound.
		handshake /= 2
	}
	// A fixed sliding receive window bounds bytes buffered before HTTP has
	// reserved its body. It does not limit total body size or normal streams.
	return &quic.Config{HandshakeIdleTimeout: handshake, MaxIdleTimeout: peerIdleTimeout, MaxIncomingStreams: streams, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 16 << 10,
		InitialConnectionReceiveWindow: 16 << 10, MaxConnectionReceiveWindow: 16 << 10}
}

// peerTransport owns the daemon's single UDP socket, its relay connections,
// and its cached outbound connections, keyed by peer host ID.
type peerTransport struct {
	mu        sync.Mutex
	transport *quic.Transport
	packets   *packetConn
	paths     *pathManager
	listening bool // a peer listener accepts inbound connections
	closed    bool // terminal Store.Close; outbound work cannot recreate UDP
	relays    map[string]*relayClient
	resources map[string]*decRelayClient
	mailbox   *helper.ParticipantMailbox
	conns     map[string]cachedPeerConn
	// users counts in-flight requests per outbound connection. An evicted
	// connection is closed only when its last request finishes, so one failed
	// stream never cancels other requests sharing the connection.
	users   map[*quic.Conn]*connUsers
	timeout time.Duration
}

type connUsers struct {
	active  int
	evicted bool
}

type cachedPeerConn struct {
	key  string
	conn *quic.Conn
}

// statelessResetKey is derived from the host key, so a restarted daemon on the
// same socket resets connections its previous process held. Peers then fail
// fast instead of waiting for a timeout.
func (s *Store) statelessResetKey() *quic.StatelessResetKey {
	mac := hmac.New(sha256.New, s.privateKey.Seed())
	mac.Write([]byte("peerspan-peer stateless reset"))
	var key quic.StatelessResetKey
	copy(key[:], mac.Sum(nil))
	return &key
}

func (s *Store) peerUDP(bind *net.UDPAddr) (*quic.Transport, error) {
	s.peer.mu.Lock()
	defer s.peer.mu.Unlock()
	if s.peer.closed {
		return nil, net.ErrClosed
	}
	if s.peer.transport != nil {
		if bind != nil {
			return nil, errors.New("peer socket already open")
		}
		return s.peer.transport, nil
	}
	if bind == nil {
		bind = &net.UDPAddr{}
	}
	socket, err := net.ListenUDP("udp", bind)
	if err != nil {
		return nil, err
	}
	// Both implementations use 4-byte connection IDs so a restarted daemon of
	// either language can reset connections its predecessor held.
	s.peer.packets = newPacketConn(socket)
	s.peer.paths = newPathManager(s, s.peer.packets)
	s.peer.packets.paths = s.peer.paths
	s.peer.transport = &quic.Transport{Conn: s.peer.packets, StatelessResetKey: s.statelessResetKey(), ConnectionIDLength: 4, ConnContext: s.decPeerHandshakeContext}
	return s.peer.transport, nil
}

func (s *Store) closePeerTransport() error {
	// ConnContext and route retirement may inspect the peer transport. Detach
	// under the mutex, then cancel/close outside it so shutdown cannot wait for
	// a handshake which is itself waiting for this mutex.
	s.peer.mu.Lock()
	s.peer.closed = true
	connections := map[*quic.Conn]bool{}
	for id, c := range s.peer.conns {
		connections[c.conn] = true
		delete(s.peer.conns, id)
	}
	for conn := range s.peer.users {
		connections[conn] = true
		delete(s.peer.users, conn)
	}
	cancels := []context.CancelFunc{}
	for key, client := range s.peer.relays {
		cancels = append(cancels, client.cancel)
		delete(s.peer.relays, key)
	}
	for key, client := range s.peer.resources {
		cancels = append(cancels, client.cancel)
		delete(s.peer.resources, key)
	}
	transport, packets, paths := s.peer.transport, s.peer.packets, s.peer.paths
	s.peer.transport, s.peer.packets, s.peer.paths = nil, nil, nil
	s.peer.listening = false
	s.peer.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for conn := range connections {
		_ = conn.CloseWithError(0, "closing")
	}
	if transport == nil {
		return nil
	}
	err := transport.Close()
	err = errors.Join(err, packets.Close())
	paths.close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

// ListenPeer binds the daemon's UDP socket and returns a listener of QUIC
// streams, each carrying one HTTP/1.1 exchange for PeerHandler.
func (s *Store) ListenPeer(ctx context.Context, address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("%w: peer bind address must be IP:port", ErrInvalid)
	}
	bind, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("%w: peer bind address must be IP:port", ErrInvalid)
	}
	config, err := s.PeerTLS(ctx, nil)
	if err != nil {
		return nil, err
	}
	ordinaryVerify := config.VerifyConnection
	config.NextProtos = []string{PeerALPN, DecRepairALPN, DecCompletionALPN}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if state.NegotiatedProtocol == DecRepairALPN || state.NegotiatedProtocol == DecCompletionALPN {
			_, e := tlsid.PeerKey(state)
			return e
		}
		return ordinaryVerify(state)
	}
	transport, err := s.peerUDP(bind)
	if err != nil {
		return nil, err
	}
	ln, err := transport.Listen(config, PeerQUICConfig(true))
	if err != nil {
		return nil, err
	}
	s.peer.mu.Lock()
	s.peer.listening = true
	s.peer.mu.Unlock()
	listenCtx, cancel := context.WithCancel(context.Background())
	l := &streamListener{ln: ln, ctx: listenCtx, cancel: cancel, streams: make(chan net.Conn), slots: make(chan struct{}, peerMaxConnections),
		completionSlots: make(chan struct{}, 128), repair: s.serveDecRepairConnection, repairKnown: s.decRememberedRepairPeer, completion: s.serveDecCompletionQUIC}
	go l.acceptConnections()
	return l, nil
}

type streamListener struct {
	ln              *quic.Listener
	ctx             context.Context
	cancel          context.CancelFunc
	streams         chan net.Conn
	slots           chan struct{}
	once            sync.Once
	repair          func(context.Context, net.Conn, tls.ConnectionState)
	repairKnown     func(context.Context, tls.ConnectionState) bool
	completionSlots chan struct{}
	completion      func(context.Context, *quic.Conn, *decPeerHandshake)
}

func (l *streamListener) acceptConnections() {
	for {
		conn, err := l.ln.Accept(l.ctx)
		if err != nil {
			return
		}
		meta, ok := conn.Context().Value(decPeerHandshakeKey{}).(*decPeerHandshake)
		if !ok || time.Since(meta.created) > peerHandshakeTimeout {
			_ = conn.CloseWithError(1, "peer handshake deadline")
			continue
		}
		// The shared pending reservation remains held until this bounded
		// dispatch finishes. A slow repair lookup cannot stall the accept loop.
		go l.dispatchConnection(conn, meta)
	}
}

func (l *streamListener) dispatchConnection(conn *quic.Conn, meta *decPeerHandshake) {
	defer meta.pending()
	state := conn.ConnectionState().TLS
	if meta.provisional != nil && state.NegotiatedProtocol != DecCompletionALPN {
		meta.provisional.retire()
		_ = conn.CloseWithError(1, "completion route protocol required")
		return
	}
	key, keyError := tlsid.PeerKey(state)
	if keyError != nil || meta.relayed && keyID(key) != meta.claimed.String() {
		meta.buffer()
		_ = conn.CloseWithError(1, "peer route key mismatch")
		return
	}
	if state.NegotiatedProtocol == DecCompletionALPN {
		if meta.provisional != nil {
			if !meta.provisional.complete(conn) {
				_ = conn.CloseWithError(1, "completion route deadline")
				return
			}
			defer meta.provisional.retire()
		}
		select {
		case l.completionSlots <- struct{}{}:
			defer func() { <-l.completionSlots }()
			l.completion(conn.Context(), conn, meta)
		default:
			meta.buffer()
			_ = conn.CloseWithError(2, "completion capacity")
		}
		return
	}
	meta.buffer()
	if state.NegotiatedProtocol == DecRepairALPN {
		lookup, cancel := context.WithTimeout(conn.Context(), 5*time.Second)
		known := l.repairKnown(lookup, state)
		cancel()
		if !known {
			_ = conn.CloseWithError(1, "unknown repair peer")
			return
		}
	}
	if protocol := state.NegotiatedProtocol; protocol != PeerALPN && protocol != DecRepairALPN {
		_ = conn.CloseWithError(1, "unsupported application protocol")
		return
	}
	select {
	case l.slots <- struct{}{}:
		go l.serveConnection(conn)
	default:
		_ = conn.CloseWithError(2, "too many peer connections")
	}
}

func (l *streamListener) serveConnection(conn *quic.Conn) {
	defer func() { <-l.slots }()
	state := conn.ConnectionState().TLS
	for {
		stream, err := conn.AcceptStream(l.ctx)
		if err != nil {
			return
		}
		if state.NegotiatedProtocol == DecRepairALPN {
			go l.repair(conn.Context(), newStreamConn(stream, conn, state), state)
			continue
		}
		select {
		case l.streams <- newStreamConn(stream, conn, state):
		case <-l.ctx.Done():
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return
		}
	}
}

func (l *streamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.streams:
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *streamListener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		err = l.ln.Close()
	})
	return err
}

func (l *streamListener) Addr() net.Addr { return l.ln.Addr() }

// streamConn presents one QUIC stream as a net.Conn for http.Server. It carries
// the connection's TLS state so PeerHandler can identify the sender.
//
// Clients finish their send side right after the request. http.Server treats
// read EOF as a closed client and cancels the request context, so Read holds
// EOF until the server closes the stream after its one response, or until a
// read deadline passes (http.Server uses one to abort its background read).
type streamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
	state  tls.ConnectionState
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
}

func newStreamConn(stream *quic.Stream, conn *quic.Conn, state tls.ConnectionState) *streamConn {
	return &streamConn{stream: stream, conn: conn, state: state, closed: make(chan struct{}), changed: make(chan struct{})}
}

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.stream.Read(p)
	if !errors.Is(err, io.EOF) {
		return n, err
	}
	if n > 0 {
		return n, nil
	}
	return 0, c.holdEOF()
}

func (c *streamConn) holdEOF() error {
	for {
		c.mu.Lock()
		deadline, changed := c.deadline, c.changed
		c.mu.Unlock()
		timer := time.NewTimer(time.Hour)
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				timer.Stop()
				return os.ErrDeadlineExceeded
			}
			timer.Reset(wait)
		}
		var err error
		select {
		case <-c.closed:
			err = io.EOF
		case <-c.conn.Context().Done():
			err = io.EOF
		case <-timer.C:
			if !deadline.IsZero() {
				err = os.ErrDeadlineExceeded
			}
		case <-changed:
		}
		timer.Stop()
		if err != nil {
			return err
		}
	}
}

func (c *streamConn) setReadDeadline(t time.Time) {
	c.mu.Lock()
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}
func (c *streamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *streamConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	c.stream.CancelRead(0)
	return c.stream.Close()
}
func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }
func (c *streamConn) SetDeadline(t time.Time) error {
	c.setReadDeadline(t)
	return c.stream.SetDeadline(t)
}
func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.setReadDeadline(t)
	return c.stream.SetReadDeadline(t)
}
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

type peerTLSKey struct{}

// peerConnContext exposes a stream's TLS state to handlers, since http.Server
// only fills Request.TLS for *tls.Conn.
func peerConnContext(ctx context.Context, c net.Conn) context.Context {
	if s, ok := c.(*streamConn); ok {
		return context.WithValue(ctx, peerTLSKey{}, &s.state)
	}
	return ctx
}

func requestTLS(r *http.Request) *tls.ConnectionState {
	if r.TLS != nil {
		return r.TLS
	}
	state, _ := r.Context().Value(peerTLSKey{}).(*tls.ConnectionState)
	return state
}

// peerConn returns a cached connection for this exact peer identity, address,
// and relay, or dials one. reused reports whether it came from the cache. A
// nonempty address is tried directly first; otherwise, or when that fails, the
// connection goes through the relay of the lowest-ID network both hosts share.
func (s *Store) peerConn(ctx context.Context, peer Peer) (conn *quic.Conn, reused bool, err error) {
	network, relayed, err := s.relayNetwork(ctx, peer.ID)
	if err != nil {
		return nil, false, err
	}
	key := peer.ID + "|" + peer.PublicKey + "|" + peer.Address + "|"
	if relayed {
		key += relayKey(network)
	}
	resources := s.decResourceClients()
	for _, client := range resources {
		key += "|4:" + client.setting.Address + "/" + client.setting.Key
	}
	s.peer.mu.Lock()
	if c, ok := s.peer.conns[peer.ID]; ok {
		if c.key == key && c.conn.Context().Err() == nil {
			s.acquireConnLocked(c.conn)
			s.peer.mu.Unlock()
			return c.conn, true, nil
		}
		delete(s.peer.conns, peer.ID)
		s.retireConnLocked(c.conn, "peer changed")
	}
	s.peer.mu.Unlock()
	transport, err := s.peerUDP(nil)
	if err != nil {
		return nil, false, err
	}
	config, err := s.PeerTLS(ctx, &peer)
	if err != nil {
		return nil, false, err
	}
	if peer.Address != "" {
		var addr *net.UDPAddr
		if addr, err = net.ResolveUDPAddr("udp", peer.Address); err == nil {
			direct := ctx
			if relayed || len(resources) != 0 {
				var cancel context.CancelFunc
				direct, cancel = context.WithTimeout(ctx, relayDirectAttempt)
				defer cancel()
			}
			conn, err = transport.Dial(direct, addr, config, PeerQUICConfig(false))
		}
		if err != nil && !relayed && len(resources) == 0 {
			return nil, false, err
		}
	} else if !relayed && len(resources) == 0 {
		return nil, false, errors.New("peer has no direct address and shares no network relay")
	}
	if conn == nil {
		if len(resources) != 0 {
			conn, err = s.dialDecResourcePeer(ctx, transport, peer, config, resources)
		} else {
			conn, err = s.dialRelayed(ctx, transport, network, peer, config)
		}
		if err != nil {
			return nil, false, err
		}
	}
	if conn.ConnectionState().TLS.NegotiatedProtocol != PeerALPN {
		_ = conn.CloseWithError(0x1, "unsupported application protocol")
		return nil, false, errors.New("peer did not negotiate " + PeerALPN)
	}
	s.peer.mu.Lock()
	defer s.peer.mu.Unlock()
	if s.peer.conns == nil {
		s.peer.conns = map[string]cachedPeerConn{}
	}
	if c, ok := s.peer.conns[peer.ID]; ok && c.key == key && c.conn.Context().Err() == nil {
		_ = conn.CloseWithError(0, "duplicate")
		s.acquireConnLocked(c.conn)
		return c.conn, true, nil
	}
	s.peer.conns[peer.ID] = cachedPeerConn{key: key, conn: conn}
	s.acquireConnLocked(conn)
	return conn, false, nil
}

// dialRelayed connects to a peer through a coordinator relay. The peer's
// synthetic address routes datagrams over that relay connection.
func (s *Store) dialRelayed(ctx context.Context, transport *quic.Transport, network Network, peer Peer, config *tls.Config) (*quic.Conn, error) {
	id, err := relay.ParseHostID(peer.ID)
	if err != nil {
		return nil, err
	}
	client, err := s.relayFor(network, false)
	if err != nil {
		return nil, err
	}
	// The whole request, including this wait and the handshake, stays within
	// the request bound.
	wait, cancel := context.WithTimeout(ctx, relayReadyWait)
	defer cancel()
	select {
	case <-client.ready():
	case <-wait.Done():
		return nil, errors.New("relay is not connected")
	}
	s.peer.mu.Lock()
	packets := s.peer.packets
	s.peer.mu.Unlock()
	if packets == nil {
		return nil, errors.New("peer socket is closed")
	}
	packets.route(id, client)
	return transport.Dial(ctx, packets.synthetic(id), config, PeerQUICConfig(false))
}

// acquireConnLocked records one more in-flight request on conn. s.peer.mu is held.
func (s *Store) acquireConnLocked(conn *quic.Conn) {
	if s.peer.users == nil {
		s.peer.users = map[*quic.Conn]*connUsers{}
	}
	u := s.peer.users[conn]
	if u == nil {
		u = &connUsers{}
		s.peer.users[conn] = u
	}
	u.active++
}

// retireConnLocked stops new requests from using conn and closes it once no
// request is using it. s.peer.mu is held.
func (s *Store) retireConnLocked(conn *quic.Conn, reason string) {
	u := s.peer.users[conn]
	if u != nil && u.active > 0 {
		u.evicted = true
		return
	}
	delete(s.peer.users, conn)
	_ = conn.CloseWithError(0, reason)
}

// releaseConn ends one request's use of conn, closing an evicted connection
// after its last request.
func (s *Store) releaseConn(conn *quic.Conn) {
	s.peer.mu.Lock()
	defer s.peer.mu.Unlock()
	u := s.peer.users[conn]
	if u == nil {
		return
	}
	if u.active--; u.active > 0 {
		return
	}
	if u.evicted {
		delete(s.peer.users, conn)
		_ = conn.CloseWithError(0, "request failed")
	} else if conn.Context().Err() != nil {
		delete(s.peer.users, conn)
	}
}

// evictPeerConn removes a connection from the cache after a failed request, so
// new requests dial fresh. Requests already in flight on it finish first.
func (s *Store) evictPeerConn(id string, conn *quic.Conn) {
	s.peer.mu.Lock()
	defer s.peer.mu.Unlock()
	if c, ok := s.peer.conns[id]; ok && c.conn == conn {
		delete(s.peer.conns, id)
	}
	s.retireConnLocked(conn, "request failed")
}

// peerRequest performs one bounded exchange with a peer. A request that fails
// because a reused connection was closed underneath it, such as after the peer
// restarted, is retried once on a fresh connection; receivers deduplicate
// retried messages by request ID. Any other failure leaves the outcome unknown.
func (s *Store) peerRequest(ctx context.Context, peer Peer, method, path string, body []byte) (int, []byte, error) {
	return s.peerRequestLimit(ctx, peer, method, path, body, peerMaxBody)
}

// peerRequestLimit is peerRequest reading a response of at most limit bytes.
func (s *Store) peerRequestLimit(ctx context.Context, peer Peer, method, path string, body []byte, limit int) (int, []byte, error) {
	return s.peerRequestTimed(ctx, peer, method, path, body, limit, 0)
}

// peerRequestTimed is peerRequestLimit for a request the peer may hold for
// up to held before answering.
func (s *Store) peerRequestTimed(ctx context.Context, peer Peer, method, path string, body []byte, limit int, held time.Duration) (int, []byte, error) {
	timeout := s.peer.timeout
	if timeout == 0 {
		timeout = peerRequestTimeout
	}
	timeout += held
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		conn, reused, err := s.peerConn(ctx, peer)
		if err != nil {
			return 0, nil, err
		}
		host := peer.Address
		if host == "" {
			host = "relay.invalid"
		}
		status, data, err := peerStreamRequest(ctx, conn, host, method, path, body, limit)
		if err == nil {
			s.releaseConn(conn)
			return status, data, nil
		}
		s.evictPeerConn(peer.ID, conn)
		s.releaseConn(conn)
		if !reused || attempt > 0 || conn.Context().Err() == nil || ctx.Err() != nil {
			return 0, nil, err
		}
	}
}

// PeerStreamRequest writes one HTTP/1.1 request on a new bidirectional stream,
// finishes the send side, and reads one bounded response.
func PeerStreamRequest(ctx context.Context, conn *quic.Conn, address, method, path string, body []byte) (int, []byte, error) {
	return peerStreamRequest(ctx, conn, address, method, path, body, peerMaxBody)
}

// PeerStreamRequestLimit is PeerStreamRequest reading at most limit bytes.
func PeerStreamRequestLimit(ctx context.Context, conn *quic.Conn, address, method, path string, body []byte, limit int) (int, []byte, error) {
	return peerStreamRequest(ctx, conn, address, method, path, body, limit)
}

// PeerResponseLimit preserves each declared route's bound, including complete
// DEC normal/repair catalogs rather than truncating them at the legacy1MiB.
func PeerResponseLimit(method, path string) int {
	route, _, _ := strings.Cut(path, "?")
	if method == http.MethodGet && strings.HasPrefix(route, "/repair/v1/networks/") && strings.HasSuffix(route, "/catalog") {
		return decPublicationLimit
	}
	if strings.HasPrefix(route, "/peer/v2/networks/") {
		if strings.HasSuffix(route, "/catalog") {
			return decPublicationLimit
		}
		if strings.HasSuffix(route, "/contacts") {
			return 1 << 20
		}
		if strings.HasSuffix(route, "/contact") {
			return 16 << 10
		}
	}
	if method == http.MethodGet && strings.HasPrefix(route, "/peer/v1/networks/") && strings.HasSuffix(route, "/agent-lookup") {
		return agentLookupMaxBody
	}
	if method == http.MethodGet && (route == "/peer/v1/capabilities" || (strings.HasPrefix(route, "/peer/v1/calls/") && !strings.Contains(strings.TrimPrefix(route, "/peer/v1/calls/"), "/"))) {
		return peerToolsMaxBody
	}
	return peerMaxBody
}

func peerStreamRequest(ctx context.Context, conn *quic.Conn, address, method, path string, body []byte, limit int) (int, []byte, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()
	defer stream.CancelRead(0)
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+address+path, reader)
	if err != nil {
		stream.CancelWrite(0)
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if err = request.Write(stream); err != nil {
		stream.CancelWrite(0)
		return 0, nil, err
	}
	if err = stream.Close(); err != nil {
		return 0, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(stream), request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return 0, nil, err
	}
	if len(data) > limit {
		return 0, nil, errors.New("peer response too large")
	}
	return response.StatusCode, data, nil
}

// peerDownload performs one GET whose 200 body is streamed to w, reading at
// most limit+1 bytes so an oversized body is detected. Other responses are
// read within the usual bound and discarded.
func (s *Store) peerDownload(ctx context.Context, peer Peer, path string, w io.Writer, limit int64) (int, int64, error) {
	conn, _, err := s.peerConn(ctx, peer)
	if err != nil {
		return 0, 0, err
	}
	host := peer.Address
	if host == "" {
		host = "relay.invalid"
	}
	status, n, err := PeerStreamDownload(ctx, conn, host, path, w, limit)
	if err != nil {
		s.evictPeerConn(peer.ID, conn)
	}
	s.releaseConn(conn)
	return status, n, err
}

// PeerStreamDownload is PeerStreamRequest for a GET whose successful body is
// copied to w rather than held in memory.
func PeerStreamDownload(ctx context.Context, conn *quic.Conn, address, path string, w io.Writer, limit int64) (int, int64, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, 0, err
	}
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()
	defer stream.CancelRead(0)
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+path, nil)
	if err != nil {
		stream.CancelWrite(0)
		return 0, 0, err
	}
	if err = request.Write(stream); err != nil {
		stream.CancelWrite(0)
		return 0, 0, err
	}
	if err = stream.Close(); err != nil {
		return 0, 0, err
	}
	response, err := http.ReadResponse(bufio.NewReader(stream), request)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, peerMaxBody))
		return response.StatusCode, 0, err
	}
	n, err := io.Copy(w, io.LimitReader(response.Body, limit+1))
	return response.StatusCode, n, err
}
