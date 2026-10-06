package coord

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/relay"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
)

type relayHarness struct {
	s    *Server
	addr string
}

func startRelay(t *testing.T, configure func(*relayServer)) *relayHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Open(ctx, filepath.Join(t.TempDir(), "coord"))
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(s.relay)
	}
	listener, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
		listener.Close()
		s.Close()
	})
	return &relayHarness{s: s, addr: listener.Addr().String()}
}

// member records host k in network directly, as registration would.
func (h *relayHarness) member(t *testing.T, network string, k ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.s.db.ExecContext(ctx, `INSERT OR IGNORE INTO networks VALUES (?, 'n', 'root', 'now')`, network); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.db.ExecContext(ctx, `INSERT INTO members VALUES (?, ?, ?, '{}', '', 'now')`, network, id(k), id(k)); err != nil {
		t.Fatal(err)
	}
}

type relayClient struct {
	conn   *tls.Conn
	reader *bufio.Reader
	id     relay.HostID
}

func (h *relayHarness) dial(t *testing.T, k ed25519.PrivateKey) *relayClient {
	t.Helper()
	config := tlsid.Config()
	config.NextProtos = []string{relay.ALPN}
	config.InsecureSkipVerify = true
	cert, err := tlsid.Certificate(k, "host", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	config.Certificates = []tls.Certificate{cert}
	conn, err := tls.Dial("tcp", h.addr, config)
	if err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().NegotiatedProtocol != relay.ALPN {
		t.Fatal("relay ALPN not negotiated")
	}
	t.Cleanup(func() { conn.Close() })
	hostID, _ := relay.ParseHostID(id(k))
	return &relayClient{conn: conn, reader: bufio.NewReader(conn), id: hostID}
}

// current waits until each client's connection is the registered one, since
// registration completes just after the client's handshake returns.
func (h *relayHarness) current(t *testing.T, clients ...*relayClient) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for _, c := range clients {
		for {
			h.s.relay.mu.Lock()
			registered := h.s.relay.conns[c.id]
			h.s.relay.mu.Unlock()
			if registered != nil && registered.conn.RemoteAddr().String() == c.conn.LocalAddr().String() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("relay connection was not registered")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (c *relayClient) send(t *testing.T, to *relayClient, data string) {
	t.Helper()
	if err := relay.Write(c.conn, relay.FrameSend, to.id[:], []byte(data)); err != nil {
		t.Fatal(err)
	}
}

// next reads one frame, or returns io.EOF when the relay closed the connection
// and os.ErrDeadlineExceeded when nothing arrived within wait.
func (c *relayClient) next(wait time.Duration) (byte, relay.HostID, string, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(wait))
	kind, peer, data, err := relay.Read(c.reader, false)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		err = os.ErrDeadlineExceeded
	} else if err != nil {
		err = io.EOF
	}
	return kind, peer, string(data), err
}

func (c *relayClient) closed(t *testing.T) {
	t.Helper()
	if _, _, _, err := c.next(2 * time.Second); err != io.EOF {
		t.Fatalf("connection stayed open: %v", err)
	}
}

func TestRelayForwardsOnlyBetweenCoMembers(t *testing.T) {
	h := startRelay(t, nil)
	alice, bob, carol, dave := key(t), key(t), key(t), key(t)
	h.member(t, "net_a", alice)
	h.member(t, "net_a", bob)
	h.member(t, "net_a", dave)
	h.member(t, "net_b", carol)
	a, b, c := h.dial(t, alice), h.dial(t, bob), h.dial(t, carol)
	h.current(t, a, b, c)

	a.send(t, b, "hello bob")
	kind, from, data, err := b.next(2 * time.Second)
	if err != nil || kind != relay.FrameReceive || from != a.id || data != "hello bob" {
		t.Fatal(kind, from, data, err)
	}
	b.send(t, a, "reply")
	if kind, from, data, err = a.next(2 * time.Second); err != nil || kind != relay.FrameReceive || from != b.id || data != "reply" {
		t.Fatal(kind, from, data, err)
	}

	// Carol shares no network with Alice; Dave is a member but not connected.
	a.send(t, c, "not allowed")
	if kind, from, _, err = a.next(2 * time.Second); err != nil || kind != relay.FrameUnreachable || from != c.id {
		t.Fatal(kind, from, err)
	}
	if _, _, _, err = c.next(300 * time.Millisecond); err != os.ErrDeadlineExceeded {
		t.Fatalf("non-co-member received a datagram: %v", err)
	}
	daveID, _ := relay.ParseHostID(id(dave))
	d := &relayClient{id: daveID}
	a.send(t, d, "offline")
	a.send(t, d, "offline again")
	if kind, from, _, err = a.next(2 * time.Second); err != nil || kind != relay.FrameUnreachable || from != daveID {
		t.Fatal(kind, from, err)
	}
	if kind, _, _, err = a.next(300 * time.Millisecond); err != os.ErrDeadlineExceeded {
		t.Fatalf("second unreachable frame within a second: %v %v", kind, err)
	}
	a.send(t, a, "self")
	if kind, from, _, err = a.next(2 * time.Second); err != nil || kind != relay.FrameUnreachable || from != a.id {
		t.Fatal("datagram to self was not refused", kind, err)
	}

	// The coordination API is still served on the same listener.
	config := tlsid.Config()
	config.InsecureSkipVerify = true
	cert, _ := tlsid.Certificate(key(t), "host", time.Now())
	config.Certificates = []tls.Certificate{cert}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
	response, err := client.Post("https://"+h.addr+"/coord/v1/networks/net_a/sync", "application/json", strings.NewReader(`{"address":"","candidates":[]}`))
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatal(response, err)
	}
	response.Body.Close()
}

func TestRelayRefusesNonMembersAndInvalidFrames(t *testing.T) {
	h := startRelay(t, nil)
	stranger := h.dial(t, key(t))
	stranger.closed(t)

	alice := key(t)
	h.member(t, "net_a", alice)
	a := h.dial(t, alice)
	h.current(t, a)
	// A receive frame is only valid from the relay.
	if err := relay.Write(a.conn, relay.FrameReceive, a.id[:], []byte("x")); err != nil {
		t.Fatal(err)
	}
	a.closed(t)
	b := h.dial(t, alice)
	if _, err := b.conn.Write([]byte{relay.FrameSend, 0x06, 0x00}); err != nil {
		t.Fatal(err)
	}
	b.closed(t)
}

func TestRelayReplacesOlderConnectionAndBoundsConnections(t *testing.T) {
	h := startRelay(t, func(r *relayServer) { r.maxConns = 2 })
	alice, bob, carol := key(t), key(t), key(t)
	for _, k := range []ed25519.PrivateKey{alice, bob, carol} {
		h.member(t, "net_a", k)
	}
	first := h.dial(t, alice)
	h.current(t, first)
	second := h.dial(t, alice)
	first.closed(t)
	b := h.dial(t, bob)
	h.current(t, second, b)
	second.send(t, b, "from the current connection")
	if _, _, data, err := b.next(2 * time.Second); err != nil || data != "from the current connection" {
		t.Fatal(data, err)
	}
	// Two connections are current, so a third host is refused.
	h.dial(t, carol).closed(t)
}

func TestRelayIdleTimeoutAndPings(t *testing.T) {
	h := startRelay(t, func(r *relayServer) { r.idle = 300 * time.Millisecond })
	alice, bob := key(t), key(t)
	h.member(t, "net_a", alice)
	h.member(t, "net_a", bob)
	a, b := h.dial(t, alice), h.dial(t, bob)
	h.current(t, a, b)
	for range 6 {
		if err := relay.Write(b.conn, relay.FramePing); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	a.closed(t)
	b.send(t, b, "still open")
	if kind, _, _, err := b.next(2 * time.Second); err != nil || kind != relay.FrameUnreachable {
		t.Fatal("pinging connection was closed", kind, err)
	}
}

func TestRelayMembershipChangesApplyWithinTTL(t *testing.T) {
	h := startRelay(t, func(r *relayServer) { r.ttl = 100 * time.Millisecond })
	alice, bob := key(t), key(t)
	h.member(t, "net_a", alice)
	h.member(t, "net_a", bob)
	a, b := h.dial(t, alice), h.dial(t, bob)
	h.current(t, a, b)
	a.send(t, b, "before")
	if _, _, data, err := b.next(2 * time.Second); err != nil || data != "before" {
		t.Fatal(data, err)
	}
	if _, err := h.s.db.Exec(`DELETE FROM members WHERE host_id = ?`, id(bob)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	a.send(t, b, "after")
	if kind, _, _, err := a.next(2 * time.Second); err != nil || kind != relay.FrameUnreachable {
		t.Fatal(kind, err)
	}
	if _, _, data, err := b.next(300 * time.Millisecond); err != os.ErrDeadlineExceeded {
		t.Fatalf("removed member received %q: %v", data, err)
	}
}

func TestRelayRateAndQueueLimits(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRelayServer(nil)
	r.now = func() time.Time { return now }
	r.rate, r.burst, r.queue = 1000, 2000, 10
	c := &relayConn{out: make(chan []byte, 8), tokens: r.burst, refill: now}
	if !c.take(r, 1500) || c.take(r, 1000) {
		t.Fatal("burst not enforced")
	}
	now = now.Add(time.Second)
	if !c.take(r, 1000) {
		t.Fatal("tokens did not refill at the configured rate")
	}
	now = now.Add(time.Hour)
	if !c.take(r, 2000) || c.take(r, 1) {
		t.Fatal("refill exceeded the burst")
	}
	if !c.enqueue(r, make([]byte, 6)) || c.enqueue(r, make([]byte, 6)) || !c.enqueue(r, make([]byte, 4)) {
		t.Fatal("destination buffer limit not enforced")
	}
}
