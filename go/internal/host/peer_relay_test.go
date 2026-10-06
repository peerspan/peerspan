package host

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/relay"
)

// startRelayHost runs a host that listens on listen (none when empty) and
// advertises advertise. A listening host keeps its relay connections.
func startRelayHost(t *testing.T, name, listen, advertise string) *Store {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Open(ctx, filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureCoordination(advertise, time.Second); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	if listen != "" {
		listener, err := s.ListenPeer(ctx, listen)
		if err != nil {
			t.Fatal(err)
		}
		go func() { done <- Serve(ctx, listener, PeerHandler(s)) }()
		go s.RunRelays(ctx)
	} else {
		done <- nil
	}
	t.Cleanup(func() {
		cancel()
		<-done
		s.Close()
	})
	return s
}

func TestRelayedExchangeAndPathChoice(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	// Alice and Bob listen on unspecified addresses, so they advertise none and
	// are reachable only through the relay. Carol advertises a dead address.
	// Erin has no peer listener and accepts nothing inbound.
	alice := startRelayHost(t, "alice", "0.0.0.0:0", "")
	bob := startRelayHost(t, "bob", "0.0.0.0:0", "")
	carol := startRelayHost(t, "carol", "127.0.0.1:0", "127.0.0.1:9")
	erin := startRelayHost(t, "erin", "", "")
	created, err := alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	for _, joiner := range []*Store{bob, carol, erin} {
		invite, err := alice.CreateInvite(ctx, created.ID, CreateInvite{Member: "member", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = joiner.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*Store{alice, bob, carol, erin} {
		if n, err := s.SyncNetwork(ctx, created.ID); err != nil || n.LastSyncError != nil {
			t.Fatalf("sync: %+v %v", n, err)
		}
	}
	agents := map[*Store]Agent{}
	for _, s := range []*Store{alice, carol, erin} {
		agent, err := s.RegisterAgent(ctx, RegisterAgent{Name: "agent", Owner: "owner"})
		if err != nil {
			t.Fatal(err)
		}
		agents[s] = agent
	}
	send := func(from, to *Store) OutboundMessage {
		t.Helper()
		grant, err := to.CreateGrant(ctx, CreateGrant{RequesterHostID: from.Identity().ID, TargetAgentID: agents[to].ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 100, AllowDisconnected: true})
		if err != nil {
			t.Fatal(err)
		}
		out, err := from.PrepareOutbound(ctx, SendMessage{PeerHostID: to.Identity().ID, MessageRequest: MessageRequest{GrantID: grant.ID, TargetAgentID: agents[to].ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "hello"}})
		if err != nil {
			t.Fatal(err)
		}
		out, err = from.Exchange(ctx, out, false)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := send(bob, alice); out.State != "accepted" {
		t.Fatalf("relayed send: %+v %s", out, *out.Error)
	}
	if out := send(bob, carol); out.State != "accepted" {
		t.Fatalf("fallback from a dead direct address: %+v", out)
	}
	if out := send(erin, alice); out.State != "accepted" {
		t.Fatalf("dial-only host sending through the relay: %+v", out)
	}
	if out := send(alice, erin); out.State != "unknown" {
		t.Fatalf("dial-only host accepted an inbound connection: %+v", out)
	}

	// A manual peer that shares no network has no relay path.
	stranger := startRelayHost(t, "stranger", "127.0.0.1:0", "")
	if _, err = bob.AddPeer(ctx, Peer{ID: stranger.Identity().ID, PublicKey: stranger.Identity().PublicKey, Address: "127.0.0.1:9"}); err != nil {
		t.Fatal(err)
	}
	if _, relayed, err := bob.relayNetwork(ctx, stranger.Identity().ID); err != nil || relayed {
		t.Fatalf("relay path to a host sharing no network: %v %v", relayed, err)
	}
	if network, relayed, err := bob.relayNetwork(ctx, alice.Identity().ID); err != nil || !relayed || network.ID != created.ID {
		t.Fatalf("relay path to a co-member: %+v %v %v", network, relayed, err)
	}
}

func TestSyntheticAddressesNeverUseTheSocket(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c := newPacketConn(udp)
	defer c.Close()
	id, _ := relay.ParseHostID("host_" + strings.Repeat("ab", 32))
	addr := c.synthetic(id)
	if !isSynthetic(addr) || isSynthetic(&net.UDPAddr{IP: net.ParseIP("fd00::1"), Port: 1}) || isSynthetic(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}) {
		t.Fatal("synthetic address classification")
	}
	if again := c.synthetic(id); !again.IP.Equal(addr.IP) || again.Port != addr.Port {
		t.Fatal("synthetic address is not stable")
	}
	// Without a route the datagram is dropped, never sent as UDP.
	if n, err := c.WriteTo([]byte("x"), addr); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := c.ReadFrom(make([]byte, 10)); err == nil {
		t.Fatal("read without a datagram")
	}
}

func TestOnDemandRelayClientsCloseWhenIdle(t *testing.T) {
	client := &relayClient{}
	client.touch()
	if client.idle() {
		t.Fatal("fresh client is idle")
	}
	client.lastUsed.Store(time.Now().Add(-relayOnDemandIdle - time.Second).UnixNano())
	if !client.idle() {
		t.Fatal("unused on-demand client stayed open")
	}
	client.persistent.Store(true)
	if client.idle() {
		t.Fatal("a listening host's relay client closed for idleness")
	}
}
