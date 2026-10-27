package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/relay"
	"github.com/peerspan/peerspan/go/internal/tlsid"
	"github.com/quic-go/quic-go"
)

const decRelayALPN = "peerspan-relay/4"

// A resource relay is selected only by this process's explicit private config.
// It knows no network, coordinator, member map, presence or authority provider.
type decRelayClient struct {
	store   *Store
	setting decHelperSetting
	token   []byte
	packets *packetConn
	out     chan []byte
	cancel  context.CancelFunc
	mu      sync.Mutex
	up      bool
	source  string // actual pinned helper TCP source, never RECEIVE's claimed host
	changed chan struct{}
	known   map[relay.HostID]decRelayPin
}

type decRelayPin struct {
	checked time.Time
	known   bool
}

type decRelayFrame struct {
	kind byte
	peer relay.HostID
	data []byte
	err  error
}

func readDecRelayFrame(reader *bufio.Reader) decRelayFrame {
	var header [3]byte
	if _, e := io.ReadFull(reader, header[:]); e != nil {
		return decRelayFrame{err: e}
	}
	kind, size := header[0], int(binary.BigEndian.Uint16(header[1:]))
	valid := (kind == 7 || kind == 8 || kind == relay.FramePing) && size == 0 ||
		kind == relay.FrameReceive && size > relay.HostIDSize && size <= relay.HostIDSize+relay.MaxDatagram ||
		kind == relay.FrameUnreachable && size == relay.HostIDSize
	if !valid {
		return decRelayFrame{err: errors.New("invalid resource relay frame")}
	}
	payload := make([]byte, size)
	if _, e := io.ReadFull(reader, payload); e != nil {
		return decRelayFrame{err: e}
	}
	frame := decRelayFrame{kind: kind}
	if kind == relay.FrameReceive || kind == relay.FrameUnreachable {
		copy(frame.peer[:], payload[:relay.HostIDSize])
		frame.data = payload[relay.HostIDSize:]
	}
	return frame
}

func (r *decRelayClient) send(to relay.HostID, data []byte) {
	if len(data) == 0 || len(data) > relay.MaxDatagram {
		return
	}
	var frame frameBytes
	if relay.Write(&frame, relay.FrameSend, to[:], data) != nil {
		return
	}
	select {
	case r.out <- frame:
	default:
	}
}

func (r *decRelayClient) setReady(up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if up && !r.up {
		close(r.changed)
	} else if !up && r.up {
		r.changed = make(chan struct{})
	}
	r.up = up
}

func (r *decRelayClient) ready() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed
}

// A claimed relay source cannot grow synthetic routing maps without a locally
// remembered pin. This cache is bounded and conveys no per-request authority.
func (r *decRelayClient) knownSource(ctx context.Context, id relay.HostID) bool {
	now := time.Now()
	if old, ok := r.known[id]; ok && now.Sub(old.checked) < time.Second {
		return old.known
	}
	if len(r.known) >= 4096 {
		for key, old := range r.known {
			if now.Sub(old.checked) >= time.Second {
				delete(r.known, key)
			}
		}
		if len(r.known) >= 4096 {
			return false
		}
	}
	lookup, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	_, e := r.store.KnownHost(lookup, id.String(), nil)
	if e != nil {
		// Missing origin/container bytes do not erase an independently remembered
		// member pin. The dedicated repair view remains nonactionable.
		if networks, err := r.store.networkIDs(lookup, r.store.db); err == nil {
			for _, network := range networks {
				view, err := r.store.decRepairSnapshot(lookup, network)
				if err != nil {
					continue
				}
				for host := range view.Hosts {
					key, err := membership.DecodeKey(host)
					if err == nil && membership.HostID(key) == id.String() {
						e = nil
						break
					}
				}
				if e == nil {
					break
				}
			}
		}
	}
	cancel()
	r.known[id] = decRelayPin{checked: now, known: e == nil}
	return e == nil
}

func (r *decRelayClient) deliver(ctx context.Context, frame decRelayFrame) {
	if !r.knownSource(ctx, frame.peer) {
		r.deliverCompletion(frame)
		return
	}
	var ip [16]byte
	copy(ip[:], syntheticPrefix[:])
	copy(ip[4:], frame.peer[:12])
	r.packets.mu.Lock()
	old, exists := r.packets.peers[ip]
	if exists && old != frame.peer || !exists && (len(r.packets.peers) >= 4096 || len(r.packets.routes) >= 4096) {
		r.packets.mu.Unlock()
		return
	}
	r.packets.peers[ip] = frame.peer
	r.packets.routes[frame.peer] = r
	r.packets.mu.Unlock()
	r.packets.deliver(frame.peer, frame.data, r)
}

func (r *decRelayClient) session(ctx context.Context) error {
	cert, e := r.store.peerCertificate()
	if e != nil {
		return e
	}
	config := tlsid.Config()
	config.NextProtos = []string{decRelayALPN}
	config.Certificates = []tls.Certificate{cert}
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		key, e := tlsid.PeerKey(state)
		if e != nil || state.NegotiatedProtocol != decRelayALPN || base64.StdEncoding.EncodeToString(key) != r.setting.Key {
			return errors.New("resource relay pin or protocol mismatch")
		}
		return nil
	}
	dialing, cancel := context.WithTimeout(ctx, 5*time.Second)
	raw, e := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config}).DialContext(dialing, "tcp", r.setting.Address)
	cancel()
	if e != nil {
		return e
	}
	conn := raw.(*tls.Conn)
	defer conn.Close()
	source, e := decBootstrapSource(conn.RemoteAddr())
	if e != nil {
		return e
	}
	r.mu.Lock()
	r.source = source
	r.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = conn.NetConn().Close() })
	defer stop()
	defer r.setReady(false)
	finished := make(chan struct{})
	defer close(finished)
	incoming := make(chan decRelayFrame, 32)
	go func() {
		reader := bufio.NewReaderSize(conn, 16<<10)
		for {
			frame := readDecRelayFrame(reader)
			select {
			case incoming <- frame:
			case <-finished:
				return
			case <-ctx.Done():
				return
			}
			if frame.err != nil {
				return
			}
		}
	}()
	write := func(kind byte, data []byte) error {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if e := relay.Write(conn, kind, data); e != nil {
			return e
		}
		return conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
	// Registration/renewal deadlines are anchored to AUTH send, never a delayed
	// ACK. SEND is disabled for the entire outstanding AUTH interval.
	sent := time.Now()
	if e = write(0, r.token); e != nil {
		return e
	}
	pending, registered := true, false
	authDeadline := sent.Add(5 * time.Second)
	var expires, renew time.Time
	lastWrite := time.Now()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		now := time.Now()
		if pending && !now.Before(authDeadline) || registered && !now.Before(expires) {
			return errors.New("resource relay registration expired")
		}
		if registered && !pending && !now.Before(renew) {
			sent, pending = now, true
			authDeadline = sent.Add(5 * time.Second)
			r.setReady(false)
			if e = write(0, r.token); e != nil {
				return e
			}
			lastWrite = time.Now()
		}
		var output <-chan []byte
		if registered && !pending {
			output = r.out
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame := <-incoming:
			if frame.err != nil {
				return frame.err
			}
			now = time.Now()
			if pending && !now.Before(authDeadline) || registered && !now.Before(expires) {
				return errors.New("resource relay late registration frame")
			}
			_ = conn.SetReadDeadline(now.Add(60 * time.Second))
			switch frame.kind {
			case 7:
				if !pending {
					return errors.New("unsolicited resource relay acknowledgment")
				}
				pending, registered = false, true
				expires, renew = sent.Add(300*time.Second), sent.Add(240*time.Second)
				r.setReady(true)
			case 8:
				return errors.New("resource relay refused registration")
			default:
				if !registered {
					return errors.New("resource relay data before registration")
				}
				if frame.kind == relay.FrameReceive {
					r.deliver(ctx, frame)
				}
			}
		case frame := <-output:
			// A ready queue is not a registration lease; recheck immediately
			// before writing even when the select was delayed.
			if !time.Now().Before(expires) {
				return errors.New("resource relay registration expired")
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, e = conn.Write(frame); e != nil {
				return e
			}
			lastWrite = time.Now()
			_ = conn.SetReadDeadline(lastWrite.Add(60 * time.Second))
		case <-tick.C:
			if time.Since(lastWrite) >= 15*time.Second {
				if e = write(relay.FramePing, nil); e != nil {
					return e
				}
				lastWrite = time.Now()
			}
		}
	}
}

func (r *decRelayClient) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		_ = r.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= 30*time.Second {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

func (s *Store) runDecResourceRelays(ctx context.Context) {
	s.decTransport.mu.RLock()
	settings := append([]decHelperSetting(nil), s.decTransport.Relays...)
	tokens := make(map[string][]byte, len(settings))
	for _, setting := range settings {
		key := setting.Address + "/" + setting.Key
		tokens[key] = append([]byte(nil), s.decTransport.RelayCredentials["relay/"+key]...)
	}
	s.decTransport.mu.RUnlock()
	if len(settings) == 0 || len(settings) > 4 {
		return
	}
	if _, e := s.peerUDP(nil); e != nil {
		return
	}
	var workers sync.WaitGroup
	s.peer.mu.Lock()
	if s.peer.resources == nil {
		s.peer.resources = map[string]*decRelayClient{}
	}
	for _, setting := range settings {
		key := setting.Address + "/" + setting.Key
		if s.peer.resources[key] != nil {
			continue
		}
		running, cancel := context.WithCancel(ctx)
		client := &decRelayClient{store: s, setting: setting, token: tokens[key], packets: s.peer.packets, out: make(chan []byte, 1024), cancel: cancel, changed: make(chan struct{}), known: map[relay.HostID]decRelayPin{}}
		s.peer.resources[key] = client
		workers.Add(1)
		go func() { defer workers.Done(); client.run(running) }()
	}
	s.peer.mu.Unlock()
	workers.Wait()
}

func (s *Store) decResourceClients() []*decRelayClient {
	s.peer.mu.Lock()
	defer s.peer.mu.Unlock()
	keys := make([]string, 0, len(s.peer.resources))
	for key := range s.peer.resources {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	clients := make([]*decRelayClient, 0, len(keys))
	for _, key := range keys {
		clients = append(clients, s.peer.resources[key])
	}
	return clients
}

// The outer request supplies its unchanged total deadline. Each resource path
// has a5s connection bound; disconnected helpers cannot select a legacy relay.
func (s *Store) dialDecResourcePeer(ctx context.Context, transport *quic.Transport, peer Peer, config *tls.Config, clients []*decRelayClient) (*quic.Conn, error) {
	id, e := relay.ParseHostID(peer.ID)
	if e != nil {
		return nil, e
	}
	var last error = errors.New("selected resource relays are unavailable")
	for _, client := range clients {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// The persistent worker registers all configured helpers independently;
		// an unavailable first helper cannot block a healthy already-ready one.
		select {
		case <-client.ready():
		default:
			continue
		}
		s.peer.mu.Lock()
		packets := s.peer.packets
		s.peer.mu.Unlock()
		if packets == nil {
			return nil, net.ErrClosed
		}
		release := func() {}
		if config.NextProtos[0] == DecCompletionALPN {
			release, e = packets.beginCompletionDial(id, client)
			if e != nil {
				last = e
				continue
			}
		} else {
			packets.route(id, client)
		}
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, e := transport.Dial(attempt, packets.synthetic(id), config, PeerQUICConfig(false))
		cancel()
		if e == nil {
			if conn.ConnectionState().TLS.NegotiatedProtocol != config.NextProtos[0] {
				_ = conn.CloseWithError(1, "wrong protocol")
				release()
				return nil, errors.New("resource peer protocol mismatch")
			}
			context.AfterFunc(conn.Context(), release)
			return conn, nil
		}
		release()
		last = e
	}
	return nil, last
}
