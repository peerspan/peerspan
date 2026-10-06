package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type quicHost struct {
	store   *Store
	address string
	dir     string
	stop    func()
}

func startQUICHost(t *testing.T, dir, address string) *quicHost {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := s.ListenPeer(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, PeerHandler(s)) }()
	h := &quicHost{store: s, address: listener.Addr().String(), dir: dir}
	var stopped bool
	h.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			t.Errorf("peer server: %v", err)
		}
		s.Close()
	}
	t.Cleanup(h.stop)
	return h
}

func (h *quicHost) peer() Peer {
	return Peer{ID: h.store.Identity().ID, PublicKey: h.store.Identity().PublicKey, Address: h.address}
}

func receiptLookup(t *testing.T, sender *Store, receiver Peer) int {
	t.Helper()
	status, _, err := sender.peerRequest(context.Background(), receiver, http.MethodGet, "/peer/v1/receipts/request_00000000000000000000000000000000", nil)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func TestQUICPeerAuthentication(t *testing.T) {
	ctx := context.Background()
	receiver := startQUICHost(t, filepath.Join(t.TempDir(), "receiver"), "127.0.0.1:0")
	sender := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")

	// The receiver does not know the sender yet: the handshake fails.
	if _, _, err := sender.store.peerRequest(ctx, receiver.peer(), http.MethodGet, "/peer/v1/receipts/x", nil); err == nil {
		t.Fatal("unknown key was accepted")
	}
	if _, err := receiver.store.AddPeer(ctx, sender.peer()); err != nil {
		t.Fatal(err)
	}
	// A known sender is authenticated; the missing receipt is a 404, not a 403.
	if status := receiptLookup(t, sender.store, receiver.peer()); status != http.StatusNotFound {
		t.Fatalf("known sender: HTTP %d", status)
	}

	// A wrong pin for the receiver fails on the sender's side.
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := receiver.peer()
	wrong.PublicKey = base64.StdEncoding.EncodeToString(public)
	if _, _, err := sender.store.peerRequest(ctx, wrong, http.MethodGet, "/peer/v1/receipts/x", nil); err == nil {
		t.Fatal("wrong identity pin was accepted")
	}

	// Any other ALPN fails the handshake.
	config, err := sender.store.PeerTLS(ctx, &Peer{ID: receiver.peer().ID, PublicKey: receiver.peer().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	config.NextProtos = []string{"h3"}
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if conn, err := quic.DialAddr(dialCtx, receiver.address, config, PeerQUICConfig(false)); err == nil {
		conn.CloseWithError(0, "")
		t.Fatal("wrong ALPN was accepted")
	}
}

func TestQUICReusedConnectionRechecksSender(t *testing.T) {
	ctx := context.Background()
	receiver := startQUICHost(t, filepath.Join(t.TempDir(), "receiver"), "127.0.0.1:0")
	sender := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")
	if _, err := receiver.store.AddPeer(ctx, sender.peer()); err != nil {
		t.Fatal(err)
	}
	if status := receiptLookup(t, sender.store, receiver.peer()); status != http.StatusNotFound {
		t.Fatalf("known sender: HTTP %d", status)
	}
	first := sender.store.peer.conns[receiver.peer().ID].conn
	// The receiver forgets the sender while the connection stays open.
	if _, err := receiver.store.db.ExecContext(ctx, `DELETE FROM peers WHERE id = ?`, sender.peer().ID); err != nil {
		t.Fatal(err)
	}
	if status := receiptLookup(t, sender.store, receiver.peer()); status != http.StatusForbidden {
		t.Fatalf("removed sender on reused connection: HTTP %d", status)
	}
	if sender.store.peer.conns[receiver.peer().ID].conn != first {
		t.Fatal("connection was not reused")
	}
	// A changed dial address never reuses the connection.
	moved := receiver.peer()
	moved.Address = "127.0.0.1:1"
	dialCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if _, _, err := sender.store.peerConn(dialCtx, moved); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	if first.Context().Err() == nil {
		t.Fatal("connection for the old address stayed open")
	}
}

func TestQUICServerCertificateIsHostKey(t *testing.T) {
	ctx := context.Background()
	receiver := startQUICHost(t, filepath.Join(t.TempDir(), "receiver"), "127.0.0.1:0")
	sender := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")
	if _, err := receiver.store.AddPeer(ctx, sender.peer()); err != nil {
		t.Fatal(err)
	}
	conn, _, err := sender.store.peerConn(ctx, receiver.peer())
	if err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState().TLS
	if state.NegotiatedProtocol != PeerALPN || state.DidResume || len(state.PeerCertificates) != 1 {
		t.Fatalf("unexpected TLS state: %+v", state)
	}
	key, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(key, receiver.store.privateKey.Public().(ed25519.PublicKey)) {
		t.Fatal("served certificate does not carry the host key")
	}
}

func TestQUICRestartedPeerIsRetriedOnFreshConnection(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "receiver")
	receiver := startQUICHost(t, dir, "127.0.0.1:0")
	sender := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")
	if _, err := receiver.store.AddPeer(ctx, sender.peer()); err != nil {
		t.Fatal(err)
	}
	if status := receiptLookup(t, sender.store, receiver.peer()); status != http.StatusNotFound {
		t.Fatalf("before restart: HTTP %d", status)
	}
	first := sender.store.peer.conns[receiver.peer().ID].conn
	address := receiver.address
	receiver.stop()
	restarted := startQUICHost(t, dir, address)
	// The restarted daemon resets the stale connection, and the request is
	// retried once on a fresh one well within the request timeout.
	started := time.Now()
	if status := receiptLookup(t, sender.store, restarted.peer()); status != http.StatusNotFound {
		t.Fatalf("after restart: HTTP %d", status)
	}
	if time.Since(started) > 4*time.Second {
		t.Fatalf("restart recovery took %s", time.Since(started))
	}
	if sender.store.peer.conns[restarted.peer().ID].conn == first {
		t.Fatal("stale connection was reused")
	}
}

func TestQUICLostResponseIsUnknown(t *testing.T) {
	ctx := context.Background()
	receiver, err := Open(ctx, filepath.Join(t.TempDir(), "receiver"))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")
	sender.store.peer.timeout = 500 * time.Millisecond
	if _, err = receiver.AddPeer(ctx, sender.peer()); err != nil {
		t.Fatal(err)
	}
	// A server with the receiver's identity that reads requests but never answers.
	config, err := receiver.PeerTLS(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: socket}
	defer transport.Close()
	ln, err := transport.Listen(config, PeerQUICConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		for {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() { _, _ = stream.Read(make([]byte, 1<<16)) }()
		}
	}()
	peer := Peer{ID: receiver.Identity().ID, PublicKey: receiver.Identity().PublicKey, Address: socket.LocalAddr().String()}
	if _, err = sender.store.AddPeer(ctx, peer); err != nil {
		t.Fatal(err)
	}
	agent := "agent_" + "00000000000000000000000000000000"
	out, err := sender.store.PrepareOutbound(ctx, SendMessage{PeerHostID: peer.ID, MessageRequest: MessageRequest{GrantID: "grant_00000000000000000000000000000000", TargetAgentID: agent, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = sender.store.Exchange(ctx, out, false)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != "unknown" || out.Error == nil {
		t.Fatalf("lost response: %+v", out)
	}
}

// A stream-level failure on a shared connection evicts it from the cache but
// must not cancel another request in flight on the same connection.
func TestEvictionWaitsForInFlightRequests(t *testing.T) {
	ctx := context.Background()
	receiver, err := Open(ctx, filepath.Join(t.TempDir(), "receiver"))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")
	if _, err = receiver.AddPeer(ctx, sender.peer()); err != nil {
		t.Fatal(err)
	}
	config, err := receiver.PeerTLS(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: socket}
	defer transport.Close()
	ln, err := transport.Listen(config, PeerQUICConfig(true))
	if err != nil {
		t.Fatal(err)
	}
	var accepted sync.WaitGroup
	connections := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			connections <- struct{}{}
			accepted.Add(1)
			go func() {
				defer accepted.Done()
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						request, err := http.ReadRequest(bufio.NewReader(stream))
						if err != nil {
							return
						}
						switch request.URL.Path {
						case "/fail":
							stream.CancelWrite(7)
							stream.CancelRead(7)
							return
						case "/slow":
							time.Sleep(700 * time.Millisecond)
						}
						_, _ = io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
						_ = stream.Close()
					}()
				}
			}()
		}
	}()
	peer := Peer{ID: receiver.Identity().ID, PublicKey: receiver.Identity().PublicKey, Address: socket.LocalAddr().String()}
	if _, err = sender.store.AddPeer(ctx, peer); err != nil {
		t.Fatal(err)
	}
	// Warm the cache so both requests below share one connection.
	if status, _, err := sender.store.peerRequest(ctx, peer, http.MethodGet, "/ok", nil); err != nil || status != 200 {
		t.Fatalf("warm-up: %d %v", status, err)
	}
	slow := make(chan error, 1)
	go func() {
		status, _, err := sender.store.peerRequest(ctx, peer, http.MethodGet, "/slow", nil)
		if err == nil && status != 200 {
			err = fmt.Errorf("status %d", status)
		}
		slow <- err
	}()
	time.Sleep(150 * time.Millisecond)
	if _, _, err := sender.store.peerRequest(ctx, peer, http.MethodGet, "/fail", nil); err == nil {
		t.Fatal("reset stream reported success")
	}
	if err := <-slow; err != nil {
		t.Fatalf("in-flight request was cancelled by another request's eviction: %v", err)
	}
	// The failed connection left the cache: the next request dials fresh.
	if status, _, err := sender.store.peerRequest(ctx, peer, http.MethodGet, "/ok", nil); err != nil || status != 200 {
		t.Fatalf("after eviction: %d %v", status, err)
	}
	if got := len(connections); got != 2 {
		t.Fatalf("server saw %d connections, want 2 (one evicted, one fresh)", got)
	}
	sender.store.peer.mu.Lock()
	leftover := len(sender.store.peer.users)
	sender.store.peer.mu.Unlock()
	if leftover > 1 {
		t.Fatalf("%d connections still tracked after requests finished", leftover)
	}
}
