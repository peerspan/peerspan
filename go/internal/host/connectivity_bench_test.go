package host

// Test-only echo over the production endpoint, pins, combined socket and stream
// client. It adds no benchmark route to a shipped daemon.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestConnectivityBenchmark(t *testing.T) {
	output := os.Getenv("CAPSULE_BENCH_OUTPUT")
	if output == "" {
		t.Skip("opt-in benchmark driven by conformance/connectivity_bench.py")
	}
	parameter := func(name string, fallback int) int {
		if value := os.Getenv(name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		return fallback
	}
	count, cold := parameter("CAPSULE_BENCH_COUNT", 200), parameter("CAPSULE_BENCH_COLD", 20)
	warmup, concurrency := parameter("CAPSULE_BENCH_WARMUP", 20), parameter("CAPSULE_BENCH_CONCURRENCY", 8)
	if count < 1 || cold < 1 || warmup < 0 || concurrency < 1 || concurrency > 16 {
		t.Fatal("invalid workload parameters")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender, err := Open(ctx, filepath.Join(t.TempDir(), "sender"))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := Open(ctx, filepath.Join(t.TempDir(), "receiver"))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sl, err := sender.ListenPeer(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sl.Close()
	rl, err := receiver.ListenPeer(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	peer := func(s *Store, address string) Peer {
		id := s.Identity()
		return Peer{ID: id.ID, PublicKey: id.PublicKey, Address: address}
	}
	target := peer(receiver, rl.Addr().String())
	if _, err := sender.AddPeer(ctx, target); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.AddPeer(ctx, peer(sender, sl.Addr().String())); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		served <- Serve(ctx, rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/bench/echo" {
				http.Error(w, "unexpected request", 400)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			if err != nil || len(body) > 65536 {
				http.Error(w, "invalid payload", 400)
				return
			}
			w.Header().Set("Connection", "close")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		}))
	}()
	defer func() {
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
	}()
	var conn *quic.Conn
	connect := func() error {
		c, reused, err := sender.peerConn(ctx, target)
		if err != nil {
			return err
		}
		if reused {
			return fmt.Errorf("cold connection was reused")
		}
		sender.releaseConn(c)
		conn = c
		return nil
	}
	disconnect := func() {
		if conn != nil {
			sender.evictPeerConn(target.ID, conn)
			conn = nil
		}
	}
	exchange := func(payload []byte) error {
		requestCtx, done := context.WithTimeout(ctx, 8*time.Second)
		defer done()
		status, response, err := PeerStreamRequest(requestCtx, conn, target.Address, "POST", "/bench/echo", payload)
		if err != nil {
			return err
		}
		if status != 200 || !bytes.Equal(response, payload) {
			return fmt.Errorf("echo mismatch (HTTP %d)", status)
		}
		return nil
	}
	coldSeconds := []float64{}
	for i := 0; i < cold; i++ {
		disconnect()
		started := time.Now()
		if err := connect(); err != nil {
			t.Fatal(err)
		}
		if err := exchange(bytes.Repeat([]byte{42}, 16)); err != nil {
			t.Fatal(err)
		}
		coldSeconds = append(coldSeconds, time.Since(started).Seconds())
	}
	workloads := []map[string]any{}
	for _, size := range []int{16, 65536} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		for i := 0; i < warmup; i++ {
			if err := exchange(payload); err != nil {
				t.Fatal(err)
			}
		}
		sequential := []float64{}
		for i := 0; i < count; i++ {
			started := time.Now()
			if err := exchange(payload); err != nil {
				t.Fatal(err)
			}
			sequential = append(sequential, time.Since(started).Seconds())
		}
		samples := make([]float64, count)
		failures := make(chan error, concurrency)
		var workers sync.WaitGroup
		started := time.Now()
		for worker := 0; worker < concurrency; worker++ {
			workers.Add(1)
			go func(worker int) {
				defer workers.Done()
				for i := worker; i < count; i += concurrency {
					start := time.Now()
					if err := exchange(payload); err != nil {
						failures <- err
						return
					}
					samples[i] = time.Since(start).Seconds()
				}
			}(worker)
		}
		workers.Wait()
		wall := time.Since(started).Seconds()
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		workloads = append(workloads, map[string]any{"content_bytes": size, "sequential_seconds": sequential, "concurrent_seconds": samples, "concurrent_wall_seconds": wall})
	}
	disconnect()
	report := map[string]any{"backend": "capsule-go", "cold_first_echo_seconds": coldSeconds, "workloads": workloads, "count": count, "cold": cold, "warmup": warmup, "concurrency": concurrency}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, data, 0600); err != nil {
		t.Fatal(err)
	}
}
