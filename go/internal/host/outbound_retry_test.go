package host

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

func fixedRetry(s *Store, start time.Time) *testClock {
	clock := &testClock{at: start}
	s.retry.mu.Lock()
	s.retry.now = clock.now
	s.retry.jitter = func() float64 { return 1 }
	s.retry.mu.Unlock()
	return clock
}

func scheduledAfter(t *testing.T, out OutboundMessage, from time.Time) time.Duration {
	t.Helper()
	if out.NextAttemptAt == nil {
		t.Fatalf("no next attempt: %+v", out)
	}
	at, err := parseTime(*out.NextAttemptAt)
	if err != nil {
		t.Fatal(err)
	}
	return at.Sub(from)
}

func TestRetryBackoffDoublesToCap(t *testing.T) {
	s := openStore(t)
	start := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	fixedRetry(s, start)
	out := OutboundMessage{PeerHostID: "host_x", State: "unknown", Request: MessageRequest{RequestID: "request_1", Deadline: timestamp(start.Add(time.Hour))}}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i, seconds := range want {
		out.Attempts = int64(i + 1)
		s.scheduleAfterAttempt(&out, false)
		if got := scheduledAfter(t, out, start); got != seconds*time.Second {
			t.Fatalf("attempt %d: next after %v, want %v", i+1, got, seconds*time.Second)
		}
	}
	// Jitter stays within ±20%.
	s.retry.mu.Lock()
	s.retry.jitter = nil
	s.retry.mu.Unlock()
	out.Attempts = 3
	for range 50 {
		s.scheduleAfterAttempt(&out, false)
		if got := scheduledAfter(t, out, start); got < 3200*time.Millisecond || got > 4800*time.Millisecond {
			t.Fatalf("jittered delay %v outside ±20%% of 4s", got)
		}
	}
}

func TestRetryStopsOnFinalOutcomesAndAfterTheDeadline(t *testing.T) {
	s := openStore(t)
	start := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	clock := fixedRetry(s, start)
	deadline := start.Add(time.Minute)
	base := OutboundMessage{PeerHostID: "host_x", Attempts: 3, Request: MessageRequest{RequestID: "request_2", Deadline: timestamp(deadline)}}
	for _, state := range []string{"accepted", "rejected"} {
		out := base
		out.State = state
		s.scheduleAfterAttempt(&out, false)
		if out.NextAttemptAt != nil {
			t.Fatalf("%s record still scheduled", state)
		}
	}
	// After the deadline only receipt queries run, at most ten of them.
	clock.advance(2 * time.Minute)
	out := base
	out.State = "unknown"
	for i := 1; i < retryRefreshLimit; i++ {
		s.scheduleAfterAttempt(&out, true)
		if out.NextAttemptAt == nil || out.ReceiptQueries != int64(i) {
			t.Fatalf("after %d receipt queries: %+v", i, out)
		}
	}
	s.scheduleAfterAttempt(&out, true)
	if out.NextAttemptAt != nil || out.ReceiptQueries != retryRefreshLimit {
		t.Fatalf("still scheduled after ten receipt queries: %+v", out)
	}
	// A receipt query before the deadline is not counted.
	early := base
	early.State = "unknown"
	s.retry.mu.Lock()
	s.retry.now = func() time.Time { return start }
	s.retry.mu.Unlock()
	s.scheduleAfterAttempt(&early, true)
	if early.ReceiptQueries != 0 || early.NextAttemptAt == nil {
		t.Fatalf("receipt query before the deadline: %+v", early)
	}
	s.retry.mu.Lock()
	s.retry.now = clock.now
	s.retry.mu.Unlock()
	// The counter is serialized only when nonzero.
	data, _ := json.Marshal(early)
	if strings.Contains(string(data), "receipt_queries") {
		t.Fatalf("zero counter serialized: %s", data)
	}
	// Retries stop altogether 24 hours past the deadline.
	other := base
	other.State, other.Request.RequestID = "unknown", "request_3"
	clock.advance(retryGiveUp)
	s.scheduleAfterAttempt(&other, true)
	if other.NextAttemptAt != nil {
		t.Fatal("still scheduled 24 hours past the deadline")
	}
}

func TestRetryDueRecords(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	past, future := timestamp(now.Add(-time.Second)), timestamp(now.Add(time.Second))
	cases := []struct {
		out  OutboundMessage
		want bool
	}{
		{OutboundMessage{State: "unknown"}, true},                                    // from before automatic retry
		{OutboundMessage{State: "unknown", Attempts: 4}, false},                      // retries stopped
		{OutboundMessage{State: "unknown", Attempts: 1, NextAttemptAt: &past}, true}, // overdue
		{OutboundMessage{State: "unknown", Attempts: 1, NextAttemptAt: &future}, false},
		{OutboundMessage{State: "rejected", NextAttemptAt: &past}, false},
		{OutboundMessage{State: "accepted"}, false},
	}
	for i, c := range cases {
		if got := due(c.out, now); got != c.want {
			t.Fatalf("case %d: due = %v, want %v", i, got, c.want)
		}
	}
}

func TestRetryStartupSpreadsOverdueRecords(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	start := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	fixedRetry(s, start)
	past := timestamp(start.Add(-time.Hour))
	for i := range 5 {
		out := OutboundMessage{PeerHostID: "host_x", State: "unknown", Attempts: 1, NextAttemptAt: &past, Request: MessageRequest{RequestID: "request_" + string(rune('a'+i)), Deadline: timestamp(start.Add(time.Hour))}}
		if i == 4 {
			out.NextAttemptAt, out.Attempts = nil, 0 // a record from before automatic retry
		}
		data, _ := json.Marshal(out)
		if _, err := s.db.ExecContext(ctx, "INSERT INTO outbound_messages VALUES (?, ?, ?)", out.PeerHostID, out.Request.RequestID, string(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.spreadOverdue(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := s.unknownOutbound(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[time.Duration]bool{}
	for _, out := range items {
		offset := scheduledAfter(t, out, start)
		if offset < 0 || offset >= retryStartupSpread || seen[offset] {
			t.Fatalf("overdue record scheduled at +%v (seen %v)", offset, seen)
		}
		seen[offset] = true
	}
	if len(seen) != 5 {
		t.Fatalf("spread %d records, want 5", len(seen))
	}
}

func TestAutomaticRetryDeliversOnceTheReceiverIsBack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Reserve a UDP port for the receiver, which starts offline.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	probe.Close()
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
	peer := Peer{ID: receiver.Identity().ID, PublicKey: receiver.Identity().PublicKey, Address: address}
	if _, err = sender.store.AddPeer(ctx, peer); err != nil {
		t.Fatal(err)
	}
	agent, err := receiver.RegisterAgent(ctx, RegisterAgent{Name: "agent", Owner: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := receiver.CreateGrant(ctx, CreateGrant{RequesterHostID: sender.store.Identity().ID, TargetAgentID: agent.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 100, AllowDisconnected: true})
	if err != nil {
		t.Fatal(err)
	}
	out, err := sender.store.PrepareOutbound(ctx, SendMessage{PeerHostID: peer.ID, MessageRequest: MessageRequest{GrantID: ref(grant.ID), TargetAgentID: agent.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "hello"}})
	if err != nil {
		t.Fatal(err)
	}
	if out, err = sender.store.Exchange(ctx, out, false); err != nil || out.State != "unknown" || out.Attempts != 1 || out.NextAttemptAt == nil {
		t.Fatalf("offline receiver: %+v %v", out, err)
	}
	go sender.store.RunOutboundRetries(ctx)
	// Bring the receiver up; the scheduler delivers without an explicit retry.
	listener, err := receiver.ListenPeer(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = Serve(ctx, listener, PeerHandler(receiver)) }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, err := sender.store.Outbound(ctx, peer.ID, out.Request.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State == "accepted" {
			if got.NextAttemptAt != nil || got.Attempts < 2 {
				t.Fatalf("accepted record: %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not accepted automatically: %+v", got)
		}
		time.Sleep(100 * time.Millisecond)
	}
	messages, err := receiver.Messages(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("receiver has %d messages, want exactly one", len(messages))
	}
}
