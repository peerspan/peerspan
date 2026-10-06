package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func coordDB(t *testing.T, n *testNet) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(n.dir, "coord.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func countEvents(t *testing.T, s *Store, kind, subject string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM events WHERE kind = ? AND subject_id = ?", kind, subject).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustSync(t *testing.T, s *Store, id string) Network {
	t.Helper()
	n, err := s.SyncNetwork(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRevocationLeaveAndRotation(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, carol, dave := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "carol"), startPeerHost(t, "dave")
	created, err := alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	id := created.ID
	invite := func(label string) Invite {
		t.Helper()
		i, err := alice.CreateInvite(ctx, id, CreateInvite{Member: label, ExpiresAt: timestamp(time.Now().Add(time.Hour))})
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	for _, joiner := range []*Store{bob, carol} {
		if _, err = joiner.JoinNetwork(ctx, JoinNetwork{Token: invite("member").Token}); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []*Store{alice, bob, carol} {
		mustSync(t, s, id)
	}
	if _, err = carol.KnownHost(ctx, bob.Identity().ID, nil); err != nil {
		t.Fatalf("bob unknown before revocation: %v", err)
	}
	// Only the administrator revokes, never itself.
	if _, err = carol.Revoke(ctx, id, RevokeMembership{HostID: bob.Identity().ID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member revocation: %v", err)
	}
	if _, err = alice.Revoke(ctx, id, RevokeMembership{HostID: alice.Identity().ID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("self revocation: %v", err)
	}
	if _, err = alice.Revoke(ctx, id, RevokeMembership{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty revocation: %v", err)
	}
	result, err := alice.Revoke(ctx, id, RevokeMembership{HostID: bob.Identity().ID})
	if err != nil || !result.Submitted || result.Kind != "host" || result.Subject != bob.Identity().PublicKey {
		t.Fatalf("revoke: %+v %v", result, err)
	}
	if _, err = alice.KnownHost(ctx, bob.Identity().ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revocation not enforced at once on the administrator: %v", err)
	}
	if again, err := alice.Revoke(ctx, id, RevokeMembership{HostID: bob.Identity().ID}); err != nil || again != result {
		t.Fatalf("repeat revocation of a dropped member: %+v %v", again, err)
	}
	if _, err = alice.Revoke(ctx, id, RevokeMembership{HostID: "host_" + strings.Repeat("0", 64)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host revocation: %v", err)
	}
	if countEvents(t, alice, "network.host_revoked", bob.Identity().ID) != 1 {
		t.Fatal("host_revoked not recorded exactly once")
	}
	self, err := readJSON[NetworkMember](alice.db.QueryRow("SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", id, alice.Identity().ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = alice.Revoke(ctx, id, RevokeMembership{InvitePublicKey: self.Membership.InvitePublicKey}); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoking this host's own invite: %v", err)
	}
	mustSync(t, carol, id)
	if _, err = carol.KnownHost(ctx, bob.Identity().ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revocation not applied from the map: %v", err)
	}
	if n := mustSync(t, bob, id); n.LastSyncError == nil {
		t.Fatal("revoked host still syncs")
	}

	// Sticky: a coordinator that loses the revocation and re-serves bob does
	// not restore him, and the revocation is resubmitted.
	bobProof, err := readJSON[NetworkMember](bob.db.QueryRow("SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", id, bob.Identity().ID))
	if err != nil {
		t.Fatal(err)
	}
	db := coordDB(t, network)
	if _, err = db.Exec("DELETE FROM statements WHERE kind = 'host'"); err != nil {
		t.Fatal(err)
	}
	if err = injectMember(network, bobProof.Membership); err != nil {
		t.Fatal(err)
	}
	mustSync(t, carol, id)
	if _, err = carol.KnownHost(ctx, bob.Identity().ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("omitting coordinator restored a revoked host")
	}
	var restored int
	if err = db.QueryRow("SELECT COUNT(*) FROM statements WHERE kind = 'host'").Scan(&restored); err != nil || restored != 1 {
		t.Fatalf("revocation not resubmitted: %d %v", restored, err)
	}

	// A revoked invite blocks joins.
	unused := invite("dave")
	if _, err = alice.Revoke(ctx, id, RevokeMembership{InvitePublicKey: unused.InvitePublicKey}); err != nil {
		t.Fatal(err)
	}
	if _, err = dave.JoinNetwork(ctx, JoinNetwork{Token: unused.Token}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("join with revoked invite: %v", err)
	}

	// Root rotation: members keep working through attestations, old invites stop.
	stale := invite("dave")
	var genesisSeed []byte
	if err = alice.db.QueryRow("SELECT root_seed FROM networks WHERE id = ?", id).Scan(&genesisSeed); err != nil {
		t.Fatal(err)
	}
	rotated, err := alice.RotateRoot(ctx, id)
	if err != nil || rotated.RootEpoch != 1 || rotated.CurrentRootPublicKey == rotated.RootPublicKey {
		t.Fatalf("rotate: %+v %v", rotated, err)
	}
	if n := mustSync(t, carol, id); n.LastSyncError != nil || n.RootEpoch != 1 || n.CurrentRootPublicKey != rotated.CurrentRootPublicKey {
		t.Fatalf("member after rotation: %+v", n)
	}
	if _, err = carol.KnownHost(ctx, alice.Identity().ID, nil); err != nil {
		t.Fatalf("attested administrator unknown: %v", err)
	}
	if _, err = dave.JoinNetwork(ctx, JoinNetwork{Token: stale.Token}); err == nil {
		t.Fatal("old-root invite accepted after rotation")
	}
	if _, err = dave.JoinNetwork(ctx, JoinNetwork{Token: invite("dave").Token}); err != nil {
		t.Fatalf("current-root invite: %v", err)
	}
	mustSync(t, carol, id)
	if _, err = carol.KnownHost(ctx, dave.Identity().ID, nil); err != nil {
		t.Fatalf("post-rotation member unknown: %v", err)
	}
	if countEvents(t, carol, "network.root_rotated", id) != 1 {
		t.Fatal("root_rotated not recorded")
	}

	// A coordinator serving a fork is refused, and the persisted chain is kept.
	genesis := ed25519.NewKeyFromSeed(genesisSeed)
	_, other, _ := ed25519.GenerateKey(nil)
	fork, _ := json.Marshal(membership.SignRotation(genesis, id, 1, other.Public().(ed25519.PublicKey), timestamp(time.Now())))
	if _, err = db.Exec("UPDATE statements SET statement = ? WHERE kind = 'rotation' AND subject = '1'", string(fork)); err != nil {
		t.Fatal(err)
	}
	n := mustSync(t, carol, id)
	if n.LastSyncError == nil || !strings.Contains(*n.LastSyncError, "root chain conflict") || n.CurrentRootPublicKey != rotated.CurrentRootPublicKey {
		t.Fatalf("fork accepted: %+v", n)
	}
	var persisted string
	if err = carol.db.QueryRow("SELECT record FROM network_statements WHERE network_id = ? AND kind = 'rotation' AND subject = '1'", id).Scan(&persisted); err != nil || strings.Contains(persisted, membership.EncodeKey(other.Public().(ed25519.PublicKey))) {
		t.Fatalf("persisted chain replaced: %v", err)
	}
	if _, err = db.Exec("UPDATE statements SET statement = ? WHERE kind = 'rotation' AND subject = '1'", persisted); err != nil {
		t.Fatal(err)
	}

	// Leaving: the administrator cannot; a member leaves locally at once.
	if _, err = alice.LeaveNetwork(ctx, id); !errors.Is(err, ErrConflict) {
		t.Fatalf("administrator leave: %v", err)
	}
	left, err := carol.LeaveNetwork(ctx, id)
	if err != nil || !left.Submitted {
		t.Fatalf("leave: %+v %v", left, err)
	}
	if _, err = carol.Network(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("left network still present")
	}
	mustSync(t, alice, id)
	if _, err = alice.KnownHost(ctx, carol.Identity().ID, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("departed host still known")
	}
	if countEvents(t, alice, "network.member_left", carol.Identity().ID) != 1 {
		t.Fatal("member_left not recorded")
	}
	// Leaving works locally even with the coordinator down.
	network.stop()
	left, err = dave.LeaveNetwork(ctx, id)
	if err != nil || left.Submitted {
		t.Fatalf("offline leave: %+v %v", left, err)
	}
	if _, err = dave.Network(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("offline leave kept the network")
	}
}

func TestPendingRotationSurvivesCrashAndForkDiscards(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	dir := filepath.Join(t.TempDir(), "alice")
	open := func() *Store {
		t.Helper()
		s, err := Open(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.ConfigureCoordination("", time.Second); err != nil {
			t.Fatal(err)
		}
		return s
	}
	alice := open()
	defer func() { alice.Close() }()
	bob := startPeerHost(t, "bob")
	created, err := alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	id := created.ID
	invite, err := alice.CreateInvite(ctx, id, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); err != nil {
		t.Fatal(err)
	}
	mustSync(t, alice, id)
	seed := func() []byte {
		var s []byte
		if err := alice.db.QueryRow("SELECT root_seed FROM networks WHERE id = ?", id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	pendingCount := func() int {
		var n int
		if err := alice.db.QueryRow("SELECT COUNT(*) FROM network_statements WHERE network_id = ? AND kind = 'pending_rotation'", id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// The coordinator accepts the rotation, but the daemon crashes before
	// committing it locally.
	n, current, err := alice.administeredNetwork(ctx, alice.db, id)
	if err != nil {
		t.Fatal(err)
	}
	original := seed()
	pending, err := alice.prepareRotation(ctx, n, current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = alice.callCoordinator(ctx, n, "/coord/v1/networks/"+id+"/rotations", map[string]any{"rotation": pending.Rotation, "attestations": pending.Attestations}); err != nil {
		t.Fatal(err)
	}
	if after, _ := alice.Network(ctx, id); after.RootEpoch != 0 || string(seed()) != string(original) || pendingCount() != 1 {
		t.Fatalf("rotation committed before acceptance was recorded: %+v", after)
	}
	alice.Close()
	alice = open()
	synced := mustSync(t, alice, id)
	next, _ := membership.DecodeSeed(pending.RootSeed)
	if synced.RootEpoch != 1 || synced.LastSyncError != nil || string(seed()) != string(next.Seed()) || pendingCount() != 0 {
		t.Fatalf("pending rotation not completed after restart: %+v", synced)
	}
	if countEvents(t, alice, "network.root_rotated", id) != 1 {
		t.Fatal("root_rotated not recorded once")
	}
	if n := mustSync(t, bob, id); n.RootEpoch != 1 || n.LastSyncError != nil {
		t.Fatalf("member after recovered rotation: %+v", n)
	}

	// A pending rotation that the coordinator refuses as a fork is discarded.
	n, current, err = alice.administeredNetwork(ctx, alice.db, id)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err = alice.prepareRotation(ctx, n, current); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	fork, _ := json.Marshal(membership.SignRotation(current, id, 2, other.Public().(ed25519.PublicKey), timestamp(time.Now())))
	if _, err = coordDB(t, network).Exec("INSERT INTO statements VALUES (?, 'rotation', '2', ?)", id, string(fork)); err != nil {
		t.Fatal(err)
	}
	discarded := mustSync(t, alice, id)
	if pendingCount() != 0 || discarded.LastSyncError == nil || !strings.Contains(*discarded.LastSyncError, "root rotation discarded") || string(seed()) != string(next.Seed()) {
		t.Fatalf("forked pending rotation not discarded: %+v", discarded)
	}
}
