package host

// A test executable exposing control only through the production private Unix
// socket. The network echo endpoint never exists in shipped peerspan-host.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
)

func TestConnectivityNetworkHelper(t *testing.T) {
	state := os.Getenv("PEERSPAN_NET_STATE")
	if state == "" {
		t.Skip("opt-in network fixture helper")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	store, err := Open(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	bind := os.Getenv("PEERSPAN_NET_BIND")
	if bind == "" {
		bind = "0.0.0.0:7401"
	}
	peerListener, err := store.ListenPeer(ctx, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer peerListener.Close()
	localListener, err := store.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer localListener.Close()
	if err := store.ConfigureCoordination("", time.Second); err != nil {
		t.Fatal(err)
	}
	go store.RunCoordination(ctx, t.Logf)
	go store.RunRelays(ctx)
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tls := requestTLS(r)
		if tls == nil {
			http.Error(w, "identity", 403)
			return
		}
		key, err := tlsid.PeerKey(*tls)
		if err != nil {
			http.Error(w, "identity", 403)
			return
		}
		if _, err := store.KnownHost(r.Context(), keyID(key), key); err != nil {
			http.Error(w, "unknown", 403)
			return
		}
		if r.URL.Path != "/bench/echo" {
			http.NotFound(w, r)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "method", 400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || len(body) > 65536 {
			http.Error(w, "body", 413)
			return
		}
		w.Header().Set("Connection", "close")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
	local := http.NewServeMux()
	local.Handle("/", Handler(store))
	local.HandleFunc("POST /bench", func(w http.ResponseWriter, r *http.Request) {
		var cmd struct {
			Op          string `json:"op"`
			PeerID      string `json:"peer_id"`
			Target      *Peer  `json:"target"`
			Count       int    `json:"count"`
			Concurrency int    `json:"concurrency"`
			Size        int    `json:"size"`
			Token       string `json:"token"`
			Path        string `json:"path"`
			RawHead     string `json:"raw_head"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&cmd); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		send := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
		switch cmd.Op {
		case "info":
			send(store.Identity())
			return
		case "path":
			view, err := store.PeerPath(r.Context(), cmd.PeerID)
			if err == nil && view.Path == "none" {
				store.peer.mu.Lock()
				cached, ok := store.peer.conns[cmd.PeerID]
				store.peer.mu.Unlock()
				if ok && cached.conn.Context().Err() == nil {
					send(map[string]any{"path": "direct", "endpoint": cached.conn.RemoteAddr().String()})
					return
				}
			}
			if err != nil {
				send(map[string]any{"path": "none", "error": err.Error()})
			} else {
				send(view)
			}
			return
		case "drop":
			store.peer.mu.Lock()
			cached, ok := store.peer.conns[cmd.PeerID]
			store.peer.mu.Unlock()
			if ok {
				store.evictPeerConn(cmd.PeerID, cached.conn)
			}
			send(map[string]bool{"ok": true})
			return
		case "forget":
			_, err := store.db.ExecContext(r.Context(), "DELETE FROM peers WHERE id = ?", cmd.PeerID)
			send(map[string]any{"ok": err == nil})
			return
		case "run":
		default:
			http.Error(w, "unknown operation", 400)
			return
		}
		target := Peer{}
		if cmd.Target != nil {
			target = *cmd.Target
		} else {
			var failure error
			target, failure = store.dialPeer(r.Context(), cmd.PeerID)
			if failure != nil {
				send(map[string]any{"succeeded": 0, "failed": 1, "error": failure.Error()})
				return
			}
		}
		if cmd.Count == 0 {
			cmd.Count = 1
		}
		if cmd.Concurrency == 0 {
			cmd.Concurrency = 1
		}
		if cmd.Size == 0 {
			cmd.Size = 16
		}
		if cmd.Path == "" {
			cmd.Path = "/bench/echo"
		}
		if cmd.Count < 1 || cmd.Count > 10000 || cmd.Concurrency < 1 || cmd.Concurrency > 64 || cmd.Size < 16 || cmd.Size > 65536 {
			http.Error(w, "invalid workload", 400)
			return
		}
		type sample struct {
			Index    int     `json:"index"`
			Seconds  float64 `json:"seconds"`
			Verified bool    `json:"verified"`
			Error    *string `json:"error"`
		}
		samples := make([]sample, cmd.Count)
		var workers sync.WaitGroup
		start := time.Now()
		for worker := 0; worker < cmd.Concurrency; worker++ {
			workers.Add(1)
			go func(worker int) {
				defer workers.Done()
				for i := worker; i < cmd.Count; i += cmd.Concurrency {
					payload := make([]byte, cmd.Size)
					for j := range payload {
						payload[j] = byte(j % 251)
					}
					copy(payload, []byte(cmd.Token))
					binary.BigEndian.PutUint64(payload[cmd.Size-8:], uint64(i))
					before := time.Now()
					status, response, err := 0, []byte(nil), error(nil)
					if cmd.RawHead != "" {
						requestCtx, done := context.WithTimeout(r.Context(), 8*time.Second)
						conn, _, failure := store.peerConn(requestCtx, target)
						if failure == nil {
							stream, failure := conn.OpenStreamSync(requestCtx)
							if failure == nil {
								_ = stream.SetDeadline(time.Now().Add(8 * time.Second))
								_, failure = stream.Write([]byte(cmd.RawHead))
								if failure == nil {
									failure = stream.Close()
								}
								if failure == nil {
									reply, e := http.ReadResponse(bufio.NewReader(stream), nil)
									failure = e
									if e == nil {
										status = reply.StatusCode
										response, _ = io.ReadAll(io.LimitReader(reply.Body, 65537))
										_ = reply.Body.Close()
									}
								}
								stream.CancelRead(0)
							}
							store.releaseConn(conn)
							err = failure
						} else {
							err = failure
						}
						done()
					} else {
						status, response, err = store.peerRequest(r.Context(), target, "POST", cmd.Path, payload)
					}
					if err == nil && (status != 200 || !bytes.Equal(response, payload)) {
						err = fmt.Errorf("HTTP %d or echo mismatch", status)
					}
					samples[i] = sample{Index: i, Seconds: time.Since(before).Seconds(), Verified: err == nil}
					if err != nil {
						message := err.Error()
						samples[i].Error = &message
					}
				}
			}(worker)
		}
		workers.Wait()
		wall := time.Since(start).Seconds()
		succeeded := 0
		for _, s := range samples {
			if s.Verified {
				succeeded++
			}
		}
		send(map[string]any{"attempts": samples, "succeeded": succeeded, "failed": cmd.Count - succeeded, "count": cmd.Count, "concurrency": cmd.Concurrency, "content_bytes": cmd.Size, "wall_seconds": wall})
	})
	// Bench batches can be longer than the daemon's individual admin request
	// timeout; each production peer exchange remains bounded to eight seconds.
	adminServer := &http.Server{Handler: local, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = adminServer.Serve(localListener) }()
	go func() { _ = Serve(ctx, peerListener, echo) }()
	<-ctx.Done()
	_ = adminServer.Close()
}
