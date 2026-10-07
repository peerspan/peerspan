package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func personOf(t *testing.T, s *Store, network, key string) *Person {
	t.Helper()
	persons, err := s.Persons(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	for i := range persons {
		if persons[i].PublicKey == key {
			return &persons[i]
		}
	}
	return nil
}

func hasMember(t *testing.T, s *Store, network, host string) bool {
	t.Helper()
	members, err := s.NetworkMembers(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.HostID == host {
			return true
		}
	}
	return false
}

func groupNamed(t *testing.T, s *Store, network, name string) *Group {
	t.Helper()
	groups, err := s.Groups(context.Background(), network, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i]
		}
	}
	return nil
}

func TestAdministratorsAndGroups(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, carol, dave, erin := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "carol"), startPeerHost(t, "dave"), startPeerHost(t, "erin")
	pat, quinn := personKey(t), personKey(t)
	patKey, quinnKey := membership.EncodeKey(pat.PublicKey()), membership.EncodeKey(quinn.PublicKey())
	patID, quinnID := membership.PersonID(pat.PublicKey()), membership.PersonID(quinn.PublicKey())
	admin := membership.SSHSigner{PersonSigner: pat}
	now := func() string { return timestamp(time.Now()) }

	// Creating with a person also delegates that person.
	created, err := alice.createWithPerson(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey, PersonPublicKey: patKey})
	if err != nil || created.Person == nil || created.Person.Skipped != nil {
		t.Fatalf("create: %v %+v", err, created.Person)
	}
	id := created.ID
	if p := personOf(t, alice, id, patKey); p == nil || !p.Administrator || countEvents(t, alice, "network.admin_delegated", patID) != 1 {
		t.Fatalf("creator not an administrator: %+v", p)
	}
	invite := must(alice.CreateInvite(ctx, id, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
	if _, err = bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); err != nil {
		t.Fatal(err)
	}

	// Bob's host holds no root seed: pat administers from it by signing
	// through the CLI. Pat admits carol's host and the person quinn.
	if _, err = bob.AdmitHost(ctx, id, AdmitHost{HostPublicKey: carol.Identity().PublicKey, Member: "carol"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unsigned admission on a host without the root seed: %v", err)
	}
	stranger := membership.SSHSigner{PersonSigner: personKey(t)}
	forged := must(membership.SignHostAdmissionWith(stranger, id, 0, carol.Identity().PublicKey, "carol", now()))
	if _, err = bob.AdmitHost(ctx, id, AdmitHost{Admission: &forged}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admission by a non-administrator: %v", err)
	}
	carolAdmission := must(membership.SignHostAdmissionWith(admin, id, 0, carol.Identity().PublicKey, "carol", now()))
	admitted, err := bob.AdmitHost(ctx, id, AdmitHost{Admission: &carolAdmission})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = carol.JoinNetwork(ctx, JoinNetwork{Descriptor: admitted.Descriptor}); err != nil {
		t.Fatal(err)
	}
	quinnAdmission := must(membership.SignPersonAdmissionWith(admin, id, 0, quinnKey, "quinn", now()))
	if _, err = bob.AdmitPerson(ctx, id, AdmitPerson{Admission: &quinnAdmission}); err != nil {
		t.Fatal(err)
	}
	// Pat's member invite lets dave join.
	token := must(membership.MemberInviteWith(id, admin, 0, "dave", timestamp(time.Now().Add(time.Hour))))
	token.NetworkName, token.CoordinatorAddress, token.CoordinatorPublicKey = "team", network.address, network.coord.Identity().PublicKey
	recorded, err := bob.CreateInvite(ctx, id, CreateInvite{Token: must(token.Encode())})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = dave.JoinNetwork(ctx, JoinNetwork{Token: recorded.Token}); err != nil {
		t.Fatal(err)
	}

	// Groups: the root's version 1, then pat's version 2.
	if _, err = alice.SetGroup(ctx, id, SetGroup{Name: "backend", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	mustSync(t, bob, id)
	v2 := must(membership.SignGroup(admin, id, "backend", 2, []string{patID, quinnID}, now()))
	if _, err = bob.SetGroup(ctx, id, SetGroup{Group: &v2}); err != nil {
		t.Fatal(err)
	}
	if _, err = bob.SetGroup(ctx, id, SetGroup{Group: &v2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale group version: %v", err)
	}
	mustSync(t, alice, id)
	if g := groupNamed(t, alice, id, "backend"); g == nil || g.Version != 2 || len(g.Members) != 2 || g.Signer != patKey {
		t.Fatalf("group: %+v", g)
	}
	if _, err = alice.SetGroup(ctx, id, SetGroup{Name: "backend", Members: []string{"nobody"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown member label: %v", err)
	}

	// A current administrator cannot be removed as a person.
	if _, err = alice.RemovePerson(ctx, id, RemovePerson{PersonID: patID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("removed a current administrator as a person: %v", err)
	}
	// Removing pat without revoke_admitted keeps what pat signed, listed by
	// digest; pat can sign nothing new.
	if _, err = alice.RemoveAdmin(ctx, id, RemoveAdmin{Person: "ALICE"}); err != nil {
		t.Fatal(err)
	}
	mustSync(t, bob, id)
	if p := personOf(t, bob, id, patKey); p == nil || p.Administrator {
		t.Fatalf("removed administrator still current: %+v", p)
	}
	if !hasMember(t, bob, id, carol.Identity().ID) || !hasMember(t, bob, id, dave.Identity().ID) || personOf(t, bob, id, quinnKey) == nil {
		t.Fatal("removal without revoke_admitted dropped what the administrator admitted")
	}
	var removal membership.AdminRemoval
	for _, r := range adminRemovals(must(loadStatements(ctx, alice.db, id)).revocations) {
		removal = r
	}
	if len(removal.Kept) != 4 { // carol's and quinn's admissions, dave's invite, group v2
		t.Fatalf("kept digests: %v", removal.Kept)
	}
	// A backdated admission pat signs after the removal, served by the
	// coordinator from its database, is ignored by hosts.
	backdated := must(membership.SignHostAdmissionWith(admin, id, 0, erin.Identity().PublicKey, "erin", "2020-01-01T00:00:00Z"))
	if _, err = coordDB(t, network).Exec("INSERT INTO members (network_id, host_id, invite_public_key, membership, address, updated_at, admission) VALUES (?, ?, ?, '', '', ?, ?)", id, erin.Identity().ID, "admission:"+erin.Identity().PublicKey, now(), string(rawJSON(t, backdated))); err != nil {
		t.Fatal(err)
	}
	mustSync(t, bob, id)
	if hasMember(t, bob, id, erin.Identity().ID) || !hasMember(t, bob, id, carol.Identity().ID) {
		t.Fatal("a backdated statement by a removed administrator was accepted, or a kept one dropped")
	}
	if _, err = coordDB(t, network).Exec("DELETE FROM members WHERE host_id = ?", erin.Identity().ID); err != nil {
		t.Fatal(err)
	}
	erinAdmission := must(membership.SignHostAdmissionWith(admin, id, 0, erin.Identity().PublicKey, "erin", now()))
	if _, err = bob.AdmitHost(ctx, id, AdmitHost{Admission: &erinAdmission}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("removed administrator admitted a host: %v", err)
	}
	if _, err = alice.RemoveAdmin(ctx, id, RemoveAdmin{Person: patID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second plain removal: %v", err)
	}
	if _, err = alice.DelegateAdmin(ctx, id, DelegateAdmin{Person: patID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-delegated a removed administrator: %v", err)
	}

	// With revoke_admitted, everything pat signed goes: at once on alice,
	// and on bob after a sync. The group reverts to the root's version.
	result, err := alice.RemoveAdmin(ctx, id, RemoveAdmin{Person: patID, RevokeAdmitted: true})
	if err != nil || !result.Submitted || result.Kind != membership.KindAdmin {
		t.Fatalf("remove with revoke_admitted: %v %+v", err, result)
	}
	if hasMember(t, alice, id, carol.Identity().ID) || hasMember(t, alice, id, dave.Identity().ID) {
		t.Fatal("revoke_admitted did not drop members locally at once")
	}
	if countEvents(t, alice, "network.admin_removed", patID) != 2 {
		t.Fatal("administrator removals not recorded")
	}
	for _, s := range []*Store{alice, bob} {
		mustSync(t, s, id)
		if hasMember(t, s, id, carol.Identity().ID) || hasMember(t, s, id, dave.Identity().ID) || personOf(t, s, id, quinnKey) != nil {
			t.Fatal("revoke_admitted kept what the administrator admitted")
		}
		if g := groupNamed(t, s, id, "backend"); g == nil || g.Version != 1 {
			t.Fatalf("group did not revert: %+v", g)
		}
	}
	if countEvents(t, bob, "network.group_updated", "backend") < 3 {
		t.Fatal("group changes not recorded")
	}
}

func TestRotateRootToSSH(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, carol := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "carol")
	pat, quinn := personKey(t), personKey(t)
	patKey, quinnKey := membership.EncodeKey(pat.PublicKey()), membership.EncodeKey(quinn.PublicKey())
	created, err := alice.createWithPerson(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey, PersonPublicKey: patKey})
	if err != nil {
		t.Fatal(err)
	}
	id := created.ID
	invite := must(alice.CreateInvite(ctx, id, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
	if _, err = bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); err != nil {
		t.Fatal(err)
	}
	// An administrator-admitted host needs no renewal at the rotation.
	admin := membership.SSHSigner{PersonSigner: pat}
	carolAdmission := must(membership.SignHostAdmissionWith(admin, id, 0, carol.Identity().PublicKey, "carol", timestamp(time.Now())))
	admitted := must(bob.AdmitHost(ctx, id, AdmitHost{Admission: &carolAdmission}))
	if _, err = carol.JoinNetwork(ctx, JoinNetwork{Descriptor: admitted.Descriptor}); err != nil {
		t.Fatal(err)
	}

	// A root-signed group is renewed at the same version.
	if _, err = alice.SetGroup(ctx, id, SetGroup{Name: "ops", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	sshRoot := membership.SSHSigner{PersonSigner: personKey(t)}
	mustSync(t, alice, id)
	plan := must(alice.RotationPlan(ctx, id))
	if plan.Epoch != 1 || len(plan.Attestations) != 2 || len(plan.PersonAdmissions) != 1 || len(plan.HostAdmissions) != 0 || len(plan.Admins) != 1 {
		t.Fatalf("plan: %+v", plan)
	}
	signed, err := SignRotationPlan(plan, sshRoot, timestamp(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := alice.RotateRoot(ctx, id, &RotateRoot{RootPublicKey: membership.EncodeKey(sshRoot.PublicKey()), Attestations: signed.Attestations, Admissions: signed.Admissions, Groups: signed.Groups})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Administrator || !rotated.RootSSH || rotated.RootEpoch != 1 {
		t.Fatalf("rotated network: %+v", rotated)
	}
	var seed []byte
	if err = alice.db.QueryRow("SELECT root_seed FROM networks WHERE id = ?", id).Scan(&seed); err != nil || seed != nil {
		t.Fatalf("root seed kept after rotating to an SSH root: %v", err)
	}
	for _, s := range []*Store{bob, carol} {
		if n := mustSync(t, s, id); !n.RootSSH || n.RootEpoch != 1 {
			t.Fatalf("peer view after rotation: %+v", n)
		}
	}
	if !hasMember(t, bob, id, carol.Identity().ID) {
		t.Fatal("administrator-admitted host lapsed at the rotation")
	}
	if g := groupNamed(t, bob, id, "ops"); g == nil || g.Version != 1 || g.Signer != membership.EncodeKey(sshRoot.PublicKey()) || len(g.Members) != 1 {
		t.Fatalf("root-signed group not renewed at the rotation: %+v", g)
	}
	if countEvents(t, bob, "network.group_updated", "ops") != 1 {
		t.Fatal("a renewal recorded a group change")
	}
	if p := personOf(t, bob, id, patKey); p == nil || !p.Administrator {
		t.Fatal("administrator delegation not renewed")
	}
	// Root actions now come signed from the CLI; this host no longer signs.
	if _, err = alice.AdmitPerson(ctx, id, AdmitPerson{PersonPublicKey: quinnKey, Member: "quinn"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unsigned admission after rotating to an SSH root: %v", err)
	}
	quinnAdmission := must(membership.SignPersonAdmissionWith(sshRoot, id, 1, quinnKey, "quinn", timestamp(time.Now())))
	if _, err = alice.AdmitPerson(ctx, id, AdmitPerson{Admission: &quinnAdmission}); err != nil {
		t.Fatal(err)
	}
	delegation := must(membership.SignAdminDelegation(sshRoot, id, 1, quinnKey, timestamp(time.Now())))
	if _, err = alice.DelegateAdmin(ctx, id, DelegateAdmin{Delegation: &delegation}); err != nil {
		t.Fatal(err)
	}
	byAdmin := must(membership.SignAdminDelegation(admin, id, 1, quinnKey, timestamp(time.Now())))
	if _, err = alice.DelegateAdmin(ctx, id, DelegateAdmin{Delegation: &byAdmin}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an administrator delegated: %v", err)
	}
	mustSync(t, bob, id)
	if p := personOf(t, bob, id, quinnKey); p == nil || !p.Administrator {
		t.Fatalf("SSH-root delegation: %+v", p)
	}
}
