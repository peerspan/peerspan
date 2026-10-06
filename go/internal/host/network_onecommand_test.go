package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// cliBinding signs a binding of host as the person, the way the CLI does,
// without the host signature the daemon adds itself.
func cliBinding(t *testing.T, signer membership.KeySigner, network string, host *Store) json.RawMessage {
	t.Helper()
	b, err := membership.SignHostBinding(signer, network, host.Identity().PublicKey, timestamp(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	return rawJSON(t, map[string]string{"network_id": b.NetworkID, "person_public_key": b.PersonPublicKey, "host_public_key": b.HostPublicKey, "bound_at": b.BoundAt, "signature": b.Signature})
}

func TestOneCommandCreateAndJoin(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, bob2, carol, dave := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "bob2"), startPeerHost(t, "carol"), startPeerHost(t, "dave")
	alicePerson, bobPerson, carolPerson := personKey(t), personKey(t), personKey(t)

	// The creator is admitted as a person by the new root; the CLI then binds.
	created, err := alice.createWithPerson(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey, PersonPublicKey: membership.EncodeKey(alicePerson.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	id := created.ID
	if created.Person == nil || !created.Person.Admitted || created.Person.Bound || created.Person.Skipped != nil || created.Person.Next == nil || !strings.Contains(*created.Person.Next, "network bind --network "+created.ID) {
		t.Fatalf("create person part: %+v", created.Person)
	}
	if _, err = alice.Bind(ctx, id, BindHost{Binding: cliBinding(t, alicePerson, id, alice)}); err != nil {
		t.Fatal(err)
	}

	// The default invite is a member invite: one join admits and binds Bob.
	invite, err := alice.CreateInvite(ctx, id, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
	if err != nil || !strings.HasPrefix(invite.Token, membership.MemberTokenPrefix) {
		t.Fatalf("member invite: %v %q", err, invite.Token)
	}
	joined, err := bob.joinWithPerson(ctx, JoinNetwork{Token: invite.Token, PersonPublicKey: membership.EncodeKey(bobPerson.PublicKey()), Binding: cliBinding(t, bobPerson, id, bob)})
	if err != nil {
		t.Fatal(err)
	}
	if p := joined.Person; p == nil || !p.Admitted || !p.Bound || p.Skipped != nil || p.Next != nil {
		t.Fatalf("join person part: %+v", p)
	}
	bobID := membership.PersonID(bobPerson.PublicKey())
	if m := memberOf(t, bob, id, bob.Identity().ID); m.PersonID == nil || *m.PersonID != bobID {
		t.Fatalf("bob not bound: %+v", m)
	}

	// Bob's second machine: Bob is already admitted, so the join only binds.
	second, err := alice.CreateInvite(ctx, id, CreateInvite{Member: "bob", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	joined, err = bob2.joinWithPerson(ctx, JoinNetwork{Token: second.Token, PersonPublicKey: membership.EncodeKey(bobPerson.PublicKey()), Binding: cliBinding(t, bobPerson, id, bob2)})
	if err != nil || joined.Person == nil || !joined.Person.Admitted || !joined.Person.Bound {
		t.Fatalf("second machine: %v %+v", err, joined.Person)
	}
	persons, err := alice.Persons(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range persons {
		if p.PersonID == bobID && len(p.Hosts) != 2 {
			t.Fatalf("bob's hosts: %+v", p)
		}
	}

	// A taken label skips the person part without undoing the host join, and
	// the same token's person half stays redeemable.
	taken, err := alice.CreateInvite(ctx, id, CreateInvite{Member: "BOB", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	joined, err = carol.joinWithPerson(ctx, JoinNetwork{Token: taken.Token, PersonPublicKey: membership.EncodeKey(carolPerson.PublicKey()), Binding: cliBinding(t, carolPerson, id, carol)})
	if err != nil {
		t.Fatalf("host join must survive a person failure: %v", err)
	}
	if p := joined.Person; p == nil || p.Admitted || p.Bound || p.Skipped == nil || p.Next == nil || !strings.Contains(*p.Next, "redeem-person --token "+taken.Token) {
		t.Fatalf("taken label: %+v", p)
	}
	if m := memberOf(t, carol, id, carol.Identity().ID); m.PersonID != nil {
		t.Fatalf("carol bound despite skipped person: %+v", m)
	}

	// A host-only invite joins as before; a person given without a member
	// invite or admission is skipped with the next command.
	hostOnly, err := alice.CreateInvite(ctx, id, CreateInvite{Member: "dave", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true})
	if err != nil || !strings.HasPrefix(hostOnly.Token, membership.TokenPrefix) {
		t.Fatalf("host-only invite: %v %q", err, hostOnly.Token)
	}
	davePerson := personKey(t)
	joined, err = dave.joinWithPerson(ctx, JoinNetwork{Token: hostOnly.Token, PersonPublicKey: membership.EncodeKey(davePerson.PublicKey()), Binding: cliBinding(t, davePerson, id, dave)})
	if err != nil || joined.Person == nil || joined.Person.Admitted || joined.Person.Skipped == nil || !strings.Contains(*joined.Person.Next, "network bind --network "+id) {
		t.Fatalf("host-only join with unadmitted person: %v %+v", err, joined.Person)
	}
	// Without a person key the response carries no person part.
	if joined.Network.ID != id {
		t.Fatalf("dave did not join: %+v", joined.Network)
	}
}
