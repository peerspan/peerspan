package helper

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

type relayOutput struct {
	typeByte byte
	payload  []byte
	ack      chan bool
}

type relayClient struct {
	conn        *tls.Conn
	peer        transportPeer
	id          [32]byte
	account     string
	queue       chan relayOutput
	done        chan struct{}
	once        sync.Once
	queueMu     sync.Mutex
	authMu      sync.Mutex
	expires     time.Time
	last        time.Time
	authPending bool
}

func (c *relayClient) close() {
	c.once.Do(func() {
		c.queueMu.Lock()
		defer c.queueMu.Unlock()
		close(c.done)
		// Replacing a client runs under the registration lock. Abort its
		// owned transport directly: TLS Close can wait on a close_notify
		// write to a nonreading peer for five seconds.
		c.conn.NetConn().Close()
	})
}

type relayHub struct {
	mu       sync.Mutex
	clients  map[[32]byte]*relayClient
	pending  map[*relayClient]string
	limits   *limits
	accounts resourceAccounts
}

func newRelayHub(l *limits, accounts resourceAccounts) *relayHub {
	return &relayHub{clients: map[[32]byte]*relayClient{}, pending: map[*relayClient]string{}, limits: l, accounts: accounts}
}

func (h *relayHub) current(c *relayClient, now time.Time) bool {
	return h.clients[c.id] == c && now.Before(c.expires)
}

func (h *relayHub) enqueue(c *relayClient, kind byte, payload []byte, ack chan bool) bool {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	select {
	case <-c.done:
		return false
	default:
	}
	size := int64(3 + len(payload))
	if !h.limits.reserve("relay", size) {
		return false
	}
	frame := relayOutput{kind, append([]byte(nil), payload...), ack}
	select {
	case c.queue <- frame:
		return true
	default:
		h.limits.release("relay", size)
		return false
	}
}

func (h *relayHub) touch(c *relayClient) {
	c.last = time.Now()
	deadline := c.last.Add(60 * time.Second)
	if !c.expires.IsZero() && c.expires.Before(deadline) {
		deadline = c.expires
	}
	if c.expires.IsZero() {
		deadline = c.last.Add(5 * time.Second)
	}
	_ = c.conn.SetReadDeadline(deadline)
}

func (h *relayHub) writer(c *relayClient, finished chan struct{}) {
	defer close(finished)
	defer func() {
		// No producer can enqueue after close. Drain every reserved byte and
		// waiting control acknowledgment, including on a write failure.
		c.close()
		for {
			select {
			case frame := <-c.queue:
				h.limits.release("relay", int64(3+len(frame.payload)))
				if frame.ack != nil {
					frame.ack <- false
				}
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-c.done:
			return
		case frame := <-c.queue:
			atomicAuth := frame.typeByte == 7
			if atomicAuth {
				c.authMu.Lock()
			}
			h.mu.Lock()
			now := time.Now()
			control := frame.typeByte == 7 || frame.typeByte == 8
			allowed := control && (c.expires.IsZero() || now.Before(c.expires)) || !control && h.current(c, now)
			account, reserved := h.pending[c]
			allowed = allowed && (!atomicAuth || reserved)
			h.mu.Unlock()
			if !allowed {
				if atomicAuth {
					c.authMu.Unlock()
				}
				h.limits.release("relay", int64(3+len(frame.payload)))
				if frame.ack != nil {
					frame.ack <- false
				}
				return
			}
			var header [3]byte
			header[0] = frame.typeByte
			binary.BigEndian.PutUint16(header[1:], uint16(len(frame.payload)))
			_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			buffers := net.Buffers{header[:], frame.payload}
			_, err := buffers.WriteTo(c.conn)
			if atomicAuth {
				// Only this client's reader waits during its AUTH_OK. Socket I/O
				// never holds the shared routing/registration lock.
				h.mu.Lock()
				if err == nil && !h.activate(c, account) {
					err = io.ErrClosedPipe
				}
				h.mu.Unlock()
				c.authMu.Unlock()
			}
			h.limits.release("relay", int64(3+len(frame.payload)))
			if frame.ack != nil {
				frame.ack <- err == nil
			}
			if err != nil {
				return
			}
			h.mu.Lock()
			h.touch(c)
			h.mu.Unlock()
		}
	}
}

func (h *relayHub) control(c *relayClient, kind byte) bool {
	ack := make(chan bool, 1)
	if !h.enqueue(c, kind, nil, ack) {
		return false
	}
	select {
	case <-c.done:
		return false
	case ok := <-ack:
		return ok
	}
}

func (h *relayHub) reserveAuth(c *relayClient, account string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.clients[c.id]
	if old != nil && old.peer.key != c.peer.key {
		return false
	}
	sourceCount, accountCount := 0, 0
	for _, registered := range h.clients {
		if registered == old {
			continue
		}
		if registered.peer.source == c.peer.source {
			sourceCount++
		}
		if account != "" && registered.account == account {
			accountCount++
		}
	}
	for pending, pendingAccount := range h.pending {
		// Renewal/replacement reserves only occupancy not already supplied
		// by this identity's registration in the same source/account bucket.
		registered := h.clients[pending.id]
		if pending.peer.source == c.peer.source && (registered == nil || registered.peer.source != pending.peer.source) {
			sourceCount++
		}
		if account != "" && pendingAccount == account && (registered == nil || registered.account != pendingAccount) {
			accountCount++
		}
	}
	if sourceCount >= 64 || accountCount >= 64 {
		return false
	}
	h.pending[c] = account
	c.authPending = true
	return true
}

// activate runs under the hub lock, immediately after a successful AUTH_OK
// write and before another connection can observe the replacement state.
func (h *relayHub) activate(c *relayClient, account string) bool {
	delete(h.pending, c)
	c.authPending = false
	select {
	case <-c.done:
		return false
	default:
	}
	if old := h.clients[c.id]; old != nil && old != c {
		if old.peer.key != c.peer.key {
			return false
		}
		old.close()
	}
	c.account = account
	c.expires = time.Now().Add(300 * time.Second)
	h.clients[c.id] = c
	h.touch(c)
	return true
}

func (h *relayHub) send(c *relayClient, payload []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.current(c, time.Now()) || c.authPending {
		return false
	}
	var destination [32]byte
	copy(destination[:], payload[:32])
	target := h.clients[destination]
	if target == nil || !h.current(target, time.Now()) {
		h.enqueue(c, 3, destination[:], nil)
		return true
	}
	forward := make([]byte, len(payload))
	copy(forward, c.id[:])
	copy(forward[32:], payload[32:])
	h.enqueue(target, 2, forward, nil)
	return true
}

func (h *relayHub) serve(conn *tls.Conn, peer transportPeer) {
	key, _ := base64.StdEncoding.DecodeString(peer.key) // TLS key was validated.
	c := &relayClient{conn: conn, peer: peer, id: sha256.Sum256(key), queue: make(chan relayOutput, 1024), done: make(chan struct{}), last: time.Now()}
	finished := make(chan struct{})
	go h.writer(c, finished)
	defer func() {
		c.close()
		h.mu.Lock()
		delete(h.pending, c)
		if h.clients[c.id] == c {
			delete(h.clients, c.id)
		}
		h.mu.Unlock()
		<-finished
	}()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, 16<<10)
	for {
		var header [3]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return
		}
		kind, size := header[0], int(binary.BigEndian.Uint16(header[1:]))
		c.authMu.Lock()
		h.mu.Lock()
		account := c.account
		current := h.current(c, time.Now())
		pending := c.authPending
		everRegistered := !c.expires.IsZero()
		h.mu.Unlock()
		c.authMu.Unlock()
		keys := resourceKeys(peer.key, peer.source, account)
		if !h.limits.allow("relay_frames", keys, 1024, 1024, 0) || everRegistered && !current || !everRegistered && (kind != 0 || pending) || pending && kind != 4 {
			return
		}
		if kind != 0 && kind != 1 && kind != 4 || kind == 0 && size > 1024 || kind == 1 && (size < 33 || size > 1532) || kind == 4 && size != 0 {
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return
		}
		h.mu.Lock()
		h.touch(c)
		h.mu.Unlock()
		if kind == 0 {
			// Data already read ahead with AUTH arrived before its response.
			// It cannot be deferred into a newly authenticated SEND. A renewal
			// may pipeline only exact empty PINGs under the old registration.
			for reader.Buffered() > 0 {
				if !everRegistered || reader.Buffered() < 3 {
					return
				}
				ping, _ := reader.Peek(3)
				if ping[0] != 4 || ping[1] != 0 || ping[2] != 0 || !h.limits.allow("relay_frames", keys, 1024, 1024, 0) {
					return
				}
				_, _ = reader.Discard(3)
			}
			if !validToken(payload) {
				return
			}
			authAllowed := h.limits.allow("relay_auth", resourceKeys(peer.key, peer.source, ""), 2, 8, 0)
			newAccount, known := h.accounts[string(payload)]
			if len(payload) == 0 && h.accounts == nil {
				known = true
			}
			if known && newAccount != "" {
				authAllowed = h.limits.allow("relay_auth", []string{"account:" + newAccount}, 2, 8, 0) && authAllowed
			}
			if !known || !authAllowed || !h.reserveAuth(c, newAccount) {
				h.control(c, 8)
				return
			}
			go func() {
				if !h.control(c, 7) {
					c.close()
				}
			}()
			continue
		}
		if kind == 1 {
			if !h.limits.allow("relay_bytes", keys, 1e12, 1e12, int64(len(payload)-32)) {
				continue // QUIC loss/backpressure, never fabricated application success.
			}
			if !h.send(c, payload) {
				return
			}
		}
	}
}
