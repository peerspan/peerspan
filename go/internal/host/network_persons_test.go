package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func personKey(t *testing.T) membership.KeySigner {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return membership.KeySigner{Key: key}
}

func rawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func memberOf(t *testing.T, s *Store, network, host string) NetworkMember {
	t.Helper()
	members, err := s.NetworkMembers(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.HostID == host {
			return m
		}
	}
	t.Fatalf("%s is not a member", host)
	return NetworkMember{}
}

func TestPersonsAdmissionBindingAndRemoval(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, carol := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "carol")
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
	// Carol joins by descriptor after the administrator admits her key.
	if _, err = bob.AdmitHost(ctx, id, AdmitHost{HostPublicKey: carol.Identity().PublicKey, Member: "carol"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-administrator admitted a host: %v", err)
	}
	admitted, err := alice.AdmitHost(ctx, id, AdmitHost{HostPublicKey: carol.Identity().PublicKey, Member: "carol"})
	if err != nil || admitted.HostID != carol.Identity().ID {
		t.Fatalf("admit host: %v %+v", err, admitted)
	}
	joined, err := carol.JoinNetwork(ctx, JoinNetwork{Descriptor: admitted.Descriptor})
	if err != nil || joined.Member != "carol" {
		t.Fatalf("join by descriptor: %v %+v", err, joined)
	}
	if m := memberOf(t, carol, id, carol.Identity().ID); m.Admission == nil || m.Membership != nil {
		t.Fatalf("admitted member record: %+v", m)
	}
	// A person admitted by public key binds two hosts, each with its consent.
	pat := personKey(t)
	patKey := membership.EncodeKey(pat.PublicKey())
	patID := membership.PersonID(pat.PublicKey())
	if _, err = alice.AdmitPerson(ctx, id, AdmitPerson{PersonPublicKey: patKey, Member: "pat"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{bob, carol} {
		mustSync(t, s, id)
		binding, err := membership.SignHostBinding(pat, id, s.Identity().PublicKey, timestamp(time.Now()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Bind(ctx, id, BindHost{Binding: rawJSON(t, binding)}); err != nil {
			t.Fatal(err)
		}
	}
	// A binding naming another host is refused locally.
	wrong, _ := membership.SignHostBinding(pat, id, carol.Identity().PublicKey, timestamp(time.Now()))
	if _, err = bob.Bind(ctx, id, BindHost{Binding: rawJSON(t, wrong)}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("binding for another host: %v", err)
	}
	mustSync(t, alice, id)
	persons, err := alice.Persons(ctx, id)
	if err != nil || len(persons) != 1 || persons[0].PersonID != patID || len(persons[0].Hosts) != 2 {
		t.Fatalf("persons: %v %+v", err, persons)
	}
	if m := memberOf(t, alice, id, bob.Identity().ID); m.PersonID == nil || *m.PersonID != patID || *m.PersonMember != "pat" {
		t.Fatalf("bob not bound to pat: %+v", m)
	}
	// A compromised coordinator serves a binding of alice that alice never
	// signed: peers verify the host signature themselves and ignore it.
	forged, _ := membership.SignHostBinding(pat, id, alice.Identity().PublicKey, timestamp(time.Now()))
	forged.HostSignature = forged.Signature[:88]
	if _, err = coordDB(t, network).Exec("INSERT INTO statements (network_id, kind, subject, statement) VALUES (?, 'binding', ?, ?)", id, alice.Identity().PublicKey, string(rawJSON(t, forged))); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{bob, carol} {
		mustSync(t, s, id)
		if m := memberOf(t, s, id, alice.Identity().ID); m.PersonID != nil {
			t.Fatalf("peer accepted a binding without the host's signature: %+v", m)
		}
	}
	// A person invite admits a second person.
	inviteP, err := alice.CreatePersonInvite(ctx, id, CreateInvite{Member: "quinn", ExpiresAt: timestamp(time.Now().Add(time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	quinn := personKey(t)
	if _, err = bob.RedeemPerson(ctx, RedeemPerson{Token: inviteP.Token, PersonPublicKey: membership.EncodeKey(quinn.PublicKey())}); err != nil {
		t.Fatal(err)
	}
	if _, err = carol.RedeemPerson(ctx, RedeemPerson{Token: inviteP.Token, PersonPublicKey: patKey}); !errors.Is(err, ErrConflict) {
		t.Fatalf("person invite reused: %v", err)
	}
	// Unbinding is enforced locally at once and is sticky.
	unbinding, _ := membership.SignHostUnbinding(pat, id, carol.Identity().PublicKey, timestamp(time.Now()))
	result, err := bob.Unbind(ctx, id, UnbindHost{Unbinding: unbinding})
	if err != nil || result.Kind != membership.KindUnbind || !result.Submitted {
		t.Fatalf("unbind: %v %+v", err, result)
	}
	for _, s := range []*Store{alice, bob} {
		mustSync(t, s, id)
		if m := memberOf(t, s, id, carol.Identity().ID); m.PersonID != nil {
			t.Fatalf("carol still bound after unbinding: %+v", m)
		}
	}
	if countEvents(t, alice, "network.host_unbound", carol.Identity().ID) != 1 {
		t.Fatal("missing host_unbound event")
	}
	// Removing a person ends its remaining bindings, even if the coordinator
	// later drops the removal.
	if _, err = bob.RemovePerson(ctx, id, RemovePerson{PersonID: patID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-administrator removed a person: %v", err)
	}
	if _, err = alice.RemovePerson(ctx, id, RemovePerson{PersonID: patID}); err != nil {
		t.Fatal(err)
	}
	mustSync(t, bob, id)
	db := coordDB(t, network)
	if _, err = db.Exec("DELETE FROM statements WHERE kind IN ('person', 'unbind')"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{alice, bob} {
		mustSync(t, s, id)
		if m := memberOf(t, s, id, bob.Identity().ID); m.PersonID != nil {
			t.Fatalf("binding of a removed person after coordinator omission: %+v", m)
		}
		persons, _ := s.Persons(ctx, id)
		for _, p := range persons {
			if p.PersonID == patID {
				t.Fatal("removed person listed")
			}
		}
	}
	// Resubmission restores the coordinator's copy.
	var restored int
	if err = db.QueryRow("SELECT COUNT(*) FROM statements WHERE kind = 'person'").Scan(&restored); err != nil || restored != 1 {
		t.Fatalf("removal not resubmitted: %d %v", restored, err)
	}
	// Rotation renews the admitted host and the remaining person.
	if _, err = alice.RotateRoot(ctx, id); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{bob, carol} {
		n := mustSync(t, s, id)
		if n.RootEpoch != 1 || n.LastSyncError != nil {
			t.Fatalf("after rotation: %+v", n)
		}
	}
	if m := memberOf(t, bob, id, carol.Identity().ID); m.Admission == nil || m.Admission.Epoch != 1 {
		t.Fatalf("admitted host not renewed: %+v", m)
	}
	persons, _ = bob.Persons(ctx, id)
	if len(persons) != 1 || persons[0].Member != "quinn" {
		t.Fatalf("persons after rotation: %+v", persons)
	}
}
