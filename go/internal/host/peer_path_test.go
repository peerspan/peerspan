package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/disco"
	"github.com/Cerebral-Systems/capsule/go/internal/relay"
	"github.com/Cerebral-Systems/capsule/go/internal/stun"
)

func stunRequestForTest() []byte { return stun.Request(stun.TxID{1}) }

// joinNetwork makes every store a member of one network on the coordinator.
func joinNetwork(t *testing.T, network *testNet, stores ...*Store) Network {
	t.Helper()
	ctx := context.Background()
	created, err := stores[0].CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "first", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, joiner := range stores[1:] {
		invite, err := stores[0].CreateInvite(ctx, created.ID, CreateInvite{Member: "member", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = joiner.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range stores {
		if n, err := s.SyncNetwork(ctx, created.ID); err != nil || n.LastSyncError != nil {
			t.Fatalf("sync: %+v %v", n, err)
		}
	}
	return created
}

func hostIDOf(t *testing.T, s *Store) relay.HostID {
	id, err := relay.ParseHostID(s.Identity().ID)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// discoFrom signs a message as from, with the given key (normally its own).
func discoFrom(from relay.HostID, key ed25519.PrivateKey, m disco.Message) []byte {
	m.Sender = from
	if m.TxID == (disco.TxID{}) {
		_, _ = rand.Read(m.TxID[:])
	}
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	return disco.Encode(m, key)
}

func TestPathDiscoveryChecks(t *testing.T) {
	network := startCoordinator(t)
	alice := startRelayHost(t, "alice", "0.0.0.0:0", "")
	bob := startRelayHost(t, "bob", "0.0.0.0:0", "")
	joinNetwork(t, network, alice, bob)
	ctx := context.Background()
	if _, err := alice.peerUDP(nil); err != nil {
		t.Fatal(err)
	}
	pm, packets := alice.peer.paths, alice.peer.packets
	// Drive the handler directly, without the background loop.
	pm.close()
	bobID := hostIDOf(t, bob)
	endpoint := netip.MustParseAddrPort("192.0.2.7:7401")

	pm.mu.Lock()
	p := pm.peer(bobID)
	pm.sendPing(bobID, p, endpoint)
	var tx disco.TxID
	for k := range p.pings {
		tx = k
	}
	pm.mu.Unlock()
	valid := func() bool {
		pm.mu.Lock()
		defer pm.mu.Unlock()
		_, ok := p.valid[endpoint]
		return ok
	}
	udp := discoRoute{udp: endpoint}
	strangerPublic, strangerKey, _ := ed25519.GenerateKey(rand.Reader)
	strangerID, _ := relay.ParseHostID(keyID(strangerPublic))

	rejected := map[string][]byte{
		"unknown sender":      discoFrom(strangerID, strangerKey, disco.Message{Type: disco.Pong, PongTxID: tx}),
		"wrong signature":     discoFrom(bobID, alice.privateKey, disco.Message{Type: disco.Pong, PongTxID: tx}),
		"stale":               discoFrom(bobID, bob.privateKey, disco.Message{Type: disco.Pong, PongTxID: tx, Time: time.Now().Add(-31 * time.Second)}),
		"future":              discoFrom(bobID, bob.privateKey, disco.Message{Type: disco.Pong, PongTxID: tx, Time: time.Now().Add(31 * time.Second)}),
		"not our transaction": discoFrom(bobID, bob.privateKey, disco.Message{Type: disco.Pong, PongTxID: disco.TxID{9}}),
	}
	for name, data := range rejected {
		pm.handleDisco(data, udp)
		if valid() {
			t.Fatalf("%s validated the endpoint", name)
		}
	}
	// Our own pong, but through the relay: only a UDP pong validates.
	pm.handleDisco(discoFrom(bobID, bob.privateKey, disco.Message{Type: disco.Pong, PongTxID: tx}), discoRoute{client: &relayClient{out: make(chan []byte, 1)}, peer: bobID})
	if valid() {
		t.Fatal("a relayed pong validated the endpoint")
	}
	// A ping from the peer over UDP is answered and pinged back, but does not
	// validate the endpoint by itself.
	pingSource := netip.MustParseAddrPort("192.0.2.8:7401")
	pm.handleDisco(discoFrom(bobID, bob.privateKey, disco.Message{Type: disco.Ping}), discoRoute{udp: pingSource})
	pm.mu.Lock()
	_, sourceValid := p.valid[pingSource]
	pingedBack := false
	for _, ping := range p.pings {
		pingedBack = pingedBack || ping.endpoint == pingSource
	}
	pm.mu.Unlock()
	if sourceValid || !pingedBack {
		t.Fatalf("ping from the peer: valid=%v pinged back=%v", sourceValid, pingedBack)
	}

	// Call-me-maybe counts only through the relay.
	cmm := disco.Message{Type: disco.CallMeMaybe, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.4:9")}}
	pm.handleDisco(discoFrom(bobID, bob.privateKey, cmm), udp)
	pm.mu.Lock()
	listed := p.candidates[netip.MustParseAddrPort("198.51.100.4:9")]
	pm.mu.Unlock()
	if listed {
		t.Fatal("call-me-maybe over UDP was used")
	}
	pm.handleDisco(discoFrom(bobID, bob.privateKey, cmm), discoRoute{client: &relayClient{out: make(chan []byte, 1)}, peer: bobID})
	pm.mu.Lock()
	listed, round := p.candidates[netip.MustParseAddrPort("198.51.100.4:9")], p.roundUntil.After(time.Now())
	pm.mu.Unlock()
	if !listed || !round {
		t.Fatalf("call-me-maybe through the relay: listed=%v round=%v", listed, round)
	}

	// Our own ping, answered over UDP, validates the endpoint.
	pong := discoFrom(bobID, bob.privateKey, disco.Message{Type: disco.Pong, PongTxID: tx})
	pm.handleDisco(pong, udp)
	if !valid() {
		t.Fatal("own pong did not validate")
	}
	packets.mu.Lock()
	direct := packets.direct[bobID]
	owner := packets.owners[endpoint]
	packets.mu.Unlock()
	if direct != endpoint || owner != bobID {
		t.Fatalf("packet routing: %v %v", direct, owner)
	}
	if view, err := alice.PeerPath(ctx, bob.Identity().ID); err != nil || view.Path != "direct" || *view.Endpoint != endpoint.String() || view.RTTMs == nil {
		t.Fatalf("path view: %+v %v", view, err)
	}

	// A replayed message is ignored even if its transaction is pending again.
	pm.mu.Lock()
	delete(p.valid, endpoint)
	p.best = netip.AddrPort{}
	p.pings[tx] = pendingPing{endpoint: endpoint, sent: time.Now()}
	pm.mu.Unlock()
	pm.handleDisco(pong, udp)
	if valid() {
		t.Fatal("replayed pong validated the endpoint")
	}

	// Validate afresh, then let 15 seconds pass without a pong: the peer goes
	// back to the relay and discovery waits 30 seconds.
	pm.mu.Lock()
	pm.sendPing(bobID, p, endpoint)
	var fresh disco.TxID
	for k, ping := range p.pings {
		if ping.endpoint == endpoint && k != tx {
			fresh = k
		}
	}
	pm.mu.Unlock()
	pm.handleDisco(discoFrom(bobID, bob.privateKey, disco.Message{Type: disco.Pong, PongTxID: fresh}), udp)
	if !valid() {
		t.Fatal("fresh pong did not validate")
	}
	pm.skew.Store(int64(16 * time.Second))
	pm.tick()
	pm.mu.Lock()
	best, retry := p.best, p.nextAttempt.Sub(pm.now())
	pm.mu.Unlock()
	packets.mu.Lock()
	_, stillDirect := packets.direct[bobID]
	packets.mu.Unlock()
	if best.IsValid() || stillDirect || retry < 29*time.Second || retry > discoRetry {
		t.Fatalf("fallback: best=%v direct=%v retry=%v", best, stillDirect, retry)
	}
}

// Two relay-only hosts on loopback find a direct path from their reflexive
// candidates, and keep exchanging messages after the coordinator stops.
func TestDirectPathReplacesRelay(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice := startRelayHost(t, "alice", "0.0.0.0:0", "")
	bob := startRelayHost(t, "bob", "0.0.0.0:0", "")
	created := joinNetwork(t, network, alice, bob)
	members, err := alice.NetworkMembers(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.Address != "" || len(m.Candidates) == 0 {
			t.Fatalf("member %s: address %q candidates %v", m.HostID, m.Address, m.Candidates)
		}
	}
	agent, err := bob.RegisterAgent(ctx, RegisterAgent{Name: "agent", Owner: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := bob.CreateGrant(ctx, CreateGrant{RequesterHostID: alice.Identity().ID, TargetAgentID: agent.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 100, AllowDisconnected: true})
	if err != nil {
		t.Fatal(err)
	}
	send := func(content string) OutboundMessage {
		t.Helper()
		out, err := alice.PrepareOutbound(ctx, SendMessage{PeerHostID: bob.Identity().ID, MessageRequest: MessageRequest{GrantID: grant.ID, TargetAgentID: agent.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: content}})
		if err != nil {
			t.Fatal(err)
		}
		if out, err = alice.Exchange(ctx, out, false); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := send("relayed"); out.State != "accepted" {
		t.Fatalf("relayed send: %+v", out)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		view, err := alice.PeerPath(ctx, bob.Identity().ID)
		if err != nil {
			t.Fatal(err)
		}
		if view.Path == "direct" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no direct path: %+v", view)
		}
		// Keep traffic flowing through the relay, as an active exchange would.
		send("keepalive")
		time.Sleep(200 * time.Millisecond)
	}
	network.stop()
	if out := send("direct"); out.State != "accepted" {
		t.Fatalf("send with the coordinator stopped: %+v", out)
	}
	if view, _ := bob.PeerPath(ctx, alice.Identity().ID); view.Path != "direct" {
		t.Fatalf("bob's view: %+v", view)
	}
}

// Demultiplexing relies on the QUIC fixed bit: STUN and path discovery
// messages always have it clear, and QUIC packets always have it set.
func TestDatagramClassification(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	ping := disco.Encode(disco.Message{Type: disco.Ping, Time: time.Now()}, key)
	if isQUIC(ping) || !disco.IsMessage(ping) {
		t.Fatal("ping misclassified")
	}
	request := stunRequestForTest()
	if isQUIC(request) || disco.IsMessage(request) {
		t.Fatal("STUN misclassified")
	}
	for _, first := range []byte{0xc0, 0x40, 0x7f, 0xff} {
		if !isQUIC([]byte{first, 0}) {
			t.Fatalf("QUIC first byte %#x misclassified", first)
		}
	}
	// A greased short header (fixed bit clear) is not QUIC to this host.
	if isQUIC([]byte{0x00, 1, 2, 3}) || isQUIC(nil) {
		t.Fatal("fixed bit clear classified as QUIC")
	}
}
