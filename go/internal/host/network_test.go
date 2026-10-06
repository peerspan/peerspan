package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/coord"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

type testNet struct {
	coord   *coord.Server
	dir     string
	address string
	stop    func() // stops the coordinator; safe to call more than once
}

func startCoordinator(t *testing.T) *testNet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir := filepath.Join(t.TempDir(), "coord")
	server, err := coord.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := server.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			<-done
			server.Close()
		})
	}
	t.Cleanup(stop)
	return &testNet{coord: server, dir: dir, address: listener.Addr().String(), stop: stop}
}

func startPeerHost(t *testing.T, name string) *Store {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Open(ctx, filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := s.ListenPeer(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureCoordination(listener.Addr().String(), time.Second); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, PeerHandler(s)) }()
	t.Cleanup(func() {
		cancel()
		<-done
		s.Close()
	})
	return s
}

func TestEnrollmentAndConnectedGrants(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, carol := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "carol")
	created, err := alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey})
	if err != nil || created.LastSyncAt == nil || created.LastSyncError != nil || !created.Administrator {
		t.Fatalf("create: %+v %v", created, err)
	}
	if _, err = bob.CreateInvite(ctx, created.ID, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour))}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-member invite: %v", err)
	}
	invite, err := alice.CreateInvite(ctx, created.ID, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = alice.CreateInvite(ctx, created.ID, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(31 * 24 * time.Hour))}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long invite: %v", err)
	}
	joined, err := bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token})
	if err != nil || joined.Administrator || joined.ID != created.ID {
		t.Fatalf("join: %+v %v", joined, err)
	}
	if _, err = bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeat join: %v", err)
	}
	if _, err = carol.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); !errors.Is(err, ErrConflict) {
		t.Fatalf("invite reuse: %v", err)
	}
	if _, err = carol.Network(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rejected join persisted a network")
	}
	if _, err = carol.JoinNetwork(ctx, JoinNetwork{Token: invite.Token[:len(invite.Token)-4] + "AAAA"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered token: %v", err)
	}
	if n, err := alice.SyncNetwork(ctx, created.ID); err != nil || n.LastSyncError != nil {
		t.Fatalf("sync: %+v %v", n, err)
	}
	members, err := alice.NetworkMembers(ctx, created.ID)
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %+v %v", members, err)
	}
	var bobEntry NetworkMember
	for _, m := range members {
		if m.HostID == bob.Identity().ID {
			bobEntry = m
		}
	}
	if bobEntry.Member != "bob" || bobEntry.Address == "" {
		t.Fatalf("bob entry: %+v", bobEntry)
	}
	if peers, _ := alice.Peers(ctx); len(peers) != 0 {
		t.Fatal("membership created manual peers")
	}

	// A connected-only grant works without peer add while coordination is fresh.
	agent, err := alice.RegisterAgent(ctx, RegisterAgent{Name: "alice", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := alice.CreateGrant(ctx, CreateGrant{RequesterHostID: bob.Identity().ID, TargetAgentID: agent.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = alice.CreateGrant(ctx, CreateGrant{RequesterHostID: carol.Identity().ID, TargetAgentID: agent.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 100}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("grant to non-member: %v", err)
	}
	send := func(content string) OutboundMessage {
		t.Helper()
		out, err := bob.PrepareOutbound(ctx, SendMessage{PeerHostID: alice.Identity().ID, MessageRequest: MessageRequest{GrantID: grant.ID, TargetAgentID: agent.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: content}})
		if err != nil {
			t.Fatal(err)
		}
		out, err = bob.Exchange(ctx, out, false)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := send("connected"); out.State != "accepted" {
		t.Fatalf("connected send: %+v", out)
	}
	// After three intervals without a sync, only disconnected grants work.
	stale := timestamp(time.Now().Add(-4 * time.Second))
	n, _ := alice.Network(ctx, created.ID)
	n.LastSyncAt = &stale
	data, _ := json.Marshal(n)
	if _, err = alice.db.ExecContext(ctx, "UPDATE networks SET record = ? WHERE id = ?", string(data), n.ID); err != nil {
		t.Fatal(err)
	}
	// The lapsed connected state is retryable: 503, recorded as unknown.
	if out := send("stale"); out.State != "unknown" || out.Error == nil || !strings.Contains(*out.Error, "HTTP 503") {
		t.Fatalf("stale send: %+v", out)
	}

	// A compromised coordinator cannot add a host without an invite secret.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	_, otherRoot, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := membership.Invite(otherRoot, "mallory", timestamp(time.Now().Add(time.Hour)))
	forged.NetworkID = created.ID
	proof, _ := forged.Join(rogue, timestamp(time.Now()))
	if err = injectMember(network, proof); err != nil {
		t.Fatal(err)
	}
	if n, err := alice.SyncNetwork(ctx, created.ID); err != nil || n.LastSyncError != nil {
		t.Fatalf("sync after injection: %+v %v", n, err)
	}
	if members, _ := alice.NetworkMembers(ctx, created.ID); len(members) != 2 {
		t.Fatalf("injected member accepted: %+v", members)
	}
	if _, err = alice.KnownHost(ctx, membership.HostID(rogue.Public().(ed25519.PublicKey)), nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("injected host is known")
	}
}

// injectMember writes a row directly, as a compromised coordinator could.
func injectMember(n *testNet, m membership.Membership) error {
	db, err := sql.Open("sqlite", filepath.Join(n.dir, "coord.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	data, _ := json.Marshal(m)
	key, _ := membership.DecodeKey(m.HostPublicKey)
	_, err = db.Exec("INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at) VALUES (?, ?, ?, ?, '', ?)", m.NetworkID, membership.HostID(key), m.InvitePublicKey, string(data), timestamp(time.Now()))
	return err
}

func TestVerifyMapDropsSharedInvites(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "host"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	expires := timestamp(time.Now().Add(time.Hour))
	token, _ := membership.Invite(root, "a", expires)
	selfToken, _ := membership.Invite(root, "self", expires)
	self, _ := selfToken.Join(s.privateKey, timestamp(time.Now()))
	_, k1, _ := ed25519.GenerateKey(rand.Reader)
	_, k2, _ := ed25519.GenerateKey(rand.Reader)
	m1, _ := token.Join(k1, timestamp(time.Now()))
	m2, _ := token.Join(k2, timestamp(time.Now()))
	entry := func(m membership.Membership) membership.MapMember {
		data, _ := json.Marshal(m)
		key, _ := membership.DecodeKey(m.HostPublicKey)
		return membership.MapMember{HostID: membership.HostID(key), Membership: data, UpdatedAt: timestamp(time.Now())}
	}
	n := Network{ID: token.NetworkID, RootPublicKey: token.RootPublicKey}
	m := membership.Map{NetworkID: n.ID, RootPublicKey: n.RootPublicKey, Members: []membership.MapMember{entry(self), entry(m1), entry(m2)}}
	applied, err := s.verifyMap(context.Background(), n, m)
	members := applied.members
	if err != nil || len(members) != 1 || members[0].HostID != s.Identity().ID {
		t.Fatalf("shared invite accepted: %+v %v", members, err)
	}
	bad := entry(m1)
	bad.Membership = json.RawMessage(strings.Replace(string(bad.Membership), `"member":"a"`, `"member":null`, 1))
	m.Members = []membership.MapMember{entry(self), bad}
	if applied, err = s.verifyMap(context.Background(), n, m); err != nil || len(applied.members) != 1 {
		t.Fatalf("malformed entry: %+v %v", applied.members, err)
	}
	m.Members = []membership.MapMember{entry(m1)}
	if _, err = s.verifyMap(context.Background(), n, m); err == nil {
		t.Fatal("map omitting this host accepted")
	}
}
