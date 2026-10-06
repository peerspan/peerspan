package coord

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

type governed struct {
	s       *Server
	root    ed25519.PrivateKey
	network string
}

func openGoverned(t *testing.T, members ...ed25519.PrivateKey) (governed, []membership.Token) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "coord"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	root := key(t)
	now := membership.Timestamp(time.Now())
	later := membership.Timestamp(time.Now().Add(time.Hour))
	self, _ := membership.Invite(root, "admin", later)
	proof, _ := self.Join(members[0], now)
	if _, _, err = s.register(ctx, id(members[0]), registerRequest{Name: "team", RootPublicKey: self.RootPublicKey, Membership: proof, Candidates: []string{}}); err != nil {
		t.Fatal(err)
	}
	var tokens []membership.Token
	for i, k := range members[1:] {
		invite, _ := membership.Invite(root, "member", later)
		tokens = append(tokens, invite)
		joined, _ := invite.Join(k, now)
		if _, _, err = s.join(ctx, id(k), self.NetworkID, joinRequest{Membership: joined, Candidates: []string{}}); err != nil {
			t.Fatalf("join %d: %v", i, err)
		}
	}
	return governed{s, root, self.NetworkID}, tokens
}

func rawOf(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func memberIDs(m *membership.Map) map[string]bool {
	ids := map[string]bool{}
	for _, member := range m.Members {
		ids[member.HostID] = true
	}
	return ids
}

func TestRevocationsExcludeHostsAndInvites(t *testing.T) {
	ctx := context.Background()
	admin, bob, carol, dave := key(t), key(t), key(t), key(t)
	g, tokens := openGoverned(t, admin, bob, carol)
	now := membership.Timestamp(time.Now())
	revokeBob := membership.SignHostRevocation(g.root, g.network, membership.PublicKey(bob), now)
	if _, err := g.s.revoke(ctx, id(dave), g.network, revocationRequest{membership.KindHost, rawOf(t, revokeBob)}); !errors.Is(err, errForbidden) {
		t.Fatalf("non-member revocation: %v", err)
	}
	forged := membership.SignHostRevocation(dave, g.network, membership.PublicKey(bob), now)
	if _, err := g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindHost, rawOf(t, forged)}); err == nil {
		t.Fatal("revocation signed by a non-root accepted")
	}
	m, err := g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindHost, rawOf(t, revokeBob)})
	if err != nil || memberIDs(m)[id(bob)] || len(m.Revocations) != 1 {
		t.Fatalf("host revocation: %v %+v", err, m)
	}
	if _, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindHost, rawOf(t, revokeBob)}); err != nil {
		t.Fatalf("repeat revocation: %v", err)
	}
	if _, err = g.s.sync(ctx, id(bob), g.network, "", []string{}); !errors.Is(err, errForbidden) {
		t.Fatalf("revoked host sync: %v", err)
	}
	// A revoked host cannot rejoin, even with a fresh invite.
	fresh, _ := membership.Invite(g.root, "again", membership.Timestamp(time.Now().Add(time.Hour)))
	again, _ := fresh.Join(bob, now)
	if _, _, err = g.s.join(ctx, id(bob), g.network, joinRequest{Membership: again, Candidates: []string{}}); !errors.Is(err, errForbidden) {
		t.Fatalf("revoked host rejoin: %v", err)
	}
	// Revoking a used invite drops the host that joined with it, and blocks joins.
	revokeInvite := membership.SignInviteRevocation(g.root, g.network, tokens[1].InvitePublicKey, now)
	if m, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindInvite, rawOf(t, revokeInvite)}); err != nil || memberIDs(m)[id(carol)] {
		t.Fatalf("invite revocation: %v", err)
	}
	unused, _ := membership.Invite(g.root, "unused", membership.Timestamp(time.Now().Add(time.Hour)))
	revokeUnused := membership.SignInviteRevocation(g.root, g.network, unused.InvitePublicKey, now)
	if _, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindInvite, rawOf(t, revokeUnused)}); err != nil {
		t.Fatal(err)
	}
	blocked, _ := unused.Join(dave, now)
	if _, _, err = g.s.join(ctx, id(dave), g.network, joinRequest{Membership: blocked, Candidates: []string{}}); !errors.Is(err, errForbidden) {
		t.Fatalf("join with revoked invite: %v", err)
	}
	if _, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindLeave, rawOf(t, membership.SignLeave(admin, g.network, now))}); !errors.Is(err, errInvalid) {
		t.Fatalf("leave through the revocations endpoint: %v", err)
	}
}

func TestLeave(t *testing.T) {
	ctx := context.Background()
	admin, bob, carol := key(t), key(t), key(t)
	g, _ := openGoverned(t, admin, bob, carol)
	now := membership.Timestamp(time.Now())
	if err := g.s.leave(ctx, id(carol), g.network, rawOf(t, membership.SignLeave(bob, g.network, now))); !errors.Is(err, errForbidden) {
		t.Fatalf("leave for another host: %v", err)
	}
	if err := g.s.leave(ctx, id(bob), g.network, rawOf(t, membership.SignLeave(bob, g.network, now))); err != nil {
		t.Fatal(err)
	}
	m, err := g.s.sync(ctx, id(admin), g.network, "", []string{})
	if err != nil || memberIDs(m)[id(bob)] || len(m.Revocations) != 1 {
		t.Fatalf("after leave: %v %+v", err, m)
	}
	var entry membership.Revocation
	if err = json.Unmarshal(m.Revocations[0], &entry); err != nil || entry.Kind != membership.KindLeave {
		t.Fatalf("leave entry: %v %+v", err, entry)
	}
}

func TestRootRotation(t *testing.T) {
	ctx := context.Background()
	admin, bob, carol := key(t), key(t), key(t)
	g, _ := openGoverned(t, admin, bob)
	now := membership.Timestamp(time.Now())
	next, fork := key(t), key(t)
	rotation := membership.SignRotation(g.root, g.network, 1, next.Public().(ed25519.PublicKey), now)
	attest := func(root ed25519.PrivateKey, epoch int64, hosts ...ed25519.PrivateKey) []membership.Attestation {
		var out []membership.Attestation
		labels := map[string]string{id(admin): "admin", id(bob): "member"}
		for _, h := range hosts {
			out = append(out, membership.SignAttestation(root, g.network, epoch, membership.PublicKey(h), labels[id(h)], now))
		}
		return out
	}
	if _, err := g.s.rotate(ctx, id(admin), g.network, rotationRequest{rotation, attest(next, 1, admin), nil}); !errors.Is(err, errInvalid) {
		t.Fatalf("rotation missing an attestation: %v", err)
	}
	if _, err := g.s.rotate(ctx, id(admin), g.network, rotationRequest{rotation, attest(g.root, 1, admin, bob), nil}); err == nil {
		t.Fatal("attestations by the old root accepted")
	}
	m, err := g.s.rotate(ctx, id(admin), g.network, rotationRequest{rotation, attest(next, 1, admin, bob), nil})
	if err != nil || len(m.Rotations) != 1 || len(m.Attestations) != 2 || len(m.Members) != 2 {
		t.Fatalf("rotation: %v %+v", err, m)
	}
	if _, err = g.s.rotate(ctx, id(admin), g.network, rotationRequest{rotation, attest(next, 1, admin, bob), nil}); err != nil {
		t.Fatalf("repeat rotation: %v", err)
	}
	forked := membership.SignRotation(g.root, g.network, 1, fork.Public().(ed25519.PublicKey), now)
	if _, err = g.s.rotate(ctx, id(admin), g.network, rotationRequest{forked, attest(fork, 1, admin, bob), nil}); !errors.Is(err, errConflict) {
		t.Fatalf("forked rotation: %v", err)
	}
	// Invites signed by the old root are refused; the new root's are accepted.
	old, _ := membership.Invite(g.root, "carol", membership.Timestamp(time.Now().Add(time.Hour)))
	stale, _ := old.Join(carol, now)
	if _, _, err = g.s.join(ctx, id(carol), g.network, joinRequest{Membership: stale, Candidates: []string{}}); err == nil {
		t.Fatal("old-root invite accepted after rotation")
	}
	current, _ := membership.InviteFor(g.network, next, "carol", membership.Timestamp(time.Now().Add(time.Hour)))
	joined, _ := current.Join(carol, now)
	if _, _, err = g.s.join(ctx, id(carol), g.network, joinRequest{Membership: joined, Candidates: []string{}}); err != nil {
		t.Fatalf("current-root invite: %v", err)
	}
	// Revocations by the old root still apply.
	if m, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindHost, rawOf(t, membership.SignHostRevocation(g.root, g.network, membership.PublicKey(bob), now))}); err != nil || memberIDs(m)[id(bob)] {
		t.Fatalf("old-root revocation after rotation: %v", err)
	}
}

func TestStatementsMigrationFromVersion2(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "coord")
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	identity := s.Identity()
	s.Close()
	db, err := sql.Open("sqlite", filepath.Join(dir, "coord.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DROP TABLE statements; ALTER TABLE members DROP COLUMN admission; PRAGMA user_version = 2;`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version, tables int
	if err = s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 4 {
		t.Fatalf("version %d %v", version, err)
	}
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'statements'`).Scan(&tables); err != nil || tables != 1 || s.Identity() != identity {
		t.Fatalf("migration: %d %v", tables, err)
	}
}
