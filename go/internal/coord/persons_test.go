package coord

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// hostBinding returns a binding signed by the person and by the host itself.
func hostBinding(t *testing.T, person membership.PersonSigner, host ed25519.PrivateKey, network, at string) membership.HostBinding {
	t.Helper()
	b, err := membership.SignHostBinding(person, network, membership.PublicKey(host), at)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.SignHost(host); err != nil {
		t.Fatal(err)
	}
	return b
}

func joinBody(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func personByKey(m *membership.Map, key string) *membership.MapPerson {
	for i := range m.Persons {
		if m.Persons[i].PersonPublicKey == key {
			return &m.Persons[i]
		}
	}
	return nil
}

func memberEntry(m *membership.Map, host string) *membership.MapMember {
	for i := range m.Members {
		if m.Members[i].HostID == host {
			return &m.Members[i]
		}
	}
	return nil
}

func TestHostAdmissionAndJoinByDescriptor(t *testing.T) {
	ctx := context.Background()
	admin, carol, eve := key(t), key(t), key(t)
	g, _ := openGoverned(t, admin)
	now := membership.Timestamp(time.Now())
	admission := membership.SignHostAdmission(g.root, g.network, 0, membership.PublicKey(carol), "carol", now)
	if _, err := g.s.admitHost(ctx, id(eve), g.network, admission); !errors.Is(err, errForbidden) {
		t.Fatalf("non-member admitted a host: %v", err)
	}
	if _, err := g.s.admitHost(ctx, id(admin), g.network, membership.SignHostAdmission(eve, g.network, 0, membership.PublicKey(carol), "carol", now)); err == nil {
		t.Fatal("admission signed by a non-root accepted")
	}
	if _, err := g.s.admitHost(ctx, id(admin), g.network, admission); err != nil {
		t.Fatal(err)
	}
	empty := joinBody(t, map[string]any{"address": "", "candidates": []string{}})
	if _, _, err := g.s.joinRequest(ctx, id(eve), g.network, empty); !errors.Is(err, errForbidden) {
		t.Fatalf("unadmitted host joined: %v", err)
	}
	status, m, err := g.s.joinRequest(ctx, id(carol), g.network, empty)
	if err != nil || status != 201 {
		t.Fatalf("join by stored admission: %d %v", status, err)
	}
	entry := memberEntry(m, id(carol))
	if entry == nil || entry.Membership != nil || entry.Admission == nil {
		t.Fatalf("admitted member entry: %+v", entry)
	}
	if status, _, err = g.s.joinRequest(ctx, id(carol), g.network, joinBody(t, map[string]any{"admission": admission, "address": "", "candidates": []string{}})); err != nil || status != 200 {
		t.Fatalf("repeat join: %d %v", status, err)
	}
	if _, err = g.s.sync(ctx, id(carol), g.network, "", []string{}); err != nil {
		t.Fatalf("admitted host sync: %v", err)
	}
	// Revoking an admitted host drops it.
	revoke := membership.SignHostRevocation(g.root, g.network, membership.PublicKey(carol), now)
	if m, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindHost, rawOf(t, revoke)}); err != nil || memberEntry(m, id(carol)) != nil {
		t.Fatalf("revoked admitted host still served: %v", err)
	}
}

func TestPersonsBindingsAndRemoval(t *testing.T) {
	ctx := context.Background()
	admin, bob, carol, person, stranger := key(t), key(t), key(t), key(t), key(t)
	g, _ := openGoverned(t, admin, bob, carol)
	now := membership.Timestamp(time.Now())
	pub := membership.PublicKey(person)
	admission := membership.SignPersonAdmission(g.root, g.network, 0, pub, "pat", now)
	if _, err := g.s.admitPerson(ctx, id(stranger), g.network, joinBody(t, map[string]any{"admission": admission})); !errors.Is(err, errForbidden) {
		t.Fatalf("non-member admitted a person: %v", err)
	}
	if _, err := g.s.admitPerson(ctx, id(admin), g.network, joinBody(t, map[string]any{"admission": admission, "membership": nil})); err != nil {
		t.Fatal(err)
	}
	m, err := g.s.admitPerson(ctx, id(admin), g.network, joinBody(t, map[string]any{"admission": admission}))
	if err != nil || personByKey(m, pub) == nil || personByKey(m, pub).Member != "pat" {
		t.Fatalf("person not served: %v %+v", err, m.Persons)
	}
	// A person invite is single use and verified under the current root.
	token, _ := membership.PersonInvite(g.network, g.root, 0, "quinn", membership.Timestamp(time.Now().Add(time.Hour)))
	quinn, other := key(t), key(t)
	redeemed, _ := token.Redeem(membership.PublicKey(quinn), now)
	if _, err = g.s.admitPerson(ctx, id(bob), g.network, joinBody(t, map[string]any{"membership": redeemed})); err != nil {
		t.Fatal(err)
	}
	again, _ := token.Redeem(membership.PublicKey(other), now)
	if _, err = g.s.admitPerson(ctx, id(bob), g.network, joinBody(t, map[string]any{"membership": again})); !errors.Is(err, errConflict) {
		t.Fatalf("person invite reused: %v", err)
	}
	signer := membership.KeySigner{Key: person}
	binding := hostBinding(t, signer, bob, g.network, now)
	// A binding without, or with another host's, host signature is refused.
	personOnly, _ := membership.SignHostBinding(signer, g.network, membership.PublicKey(bob), now)
	if _, err = g.s.bind(ctx, id(bob), g.network, personOnly); !errors.Is(err, membership.ErrInvalid) {
		t.Fatalf("binding without host signature: %v", err)
	}
	forged := personOnly
	forged.HostSignature = hostBinding(t, signer, carol, g.network, now).HostSignature
	if _, err = g.s.bind(ctx, id(bob), g.network, forged); !errors.Is(err, membership.ErrInvalid) {
		t.Fatalf("binding with another host's signature: %v", err)
	}
	// Consent: only the bound host may submit its binding.
	if _, err = g.s.bind(ctx, id(carol), g.network, binding); !errors.Is(err, errForbidden) {
		t.Fatalf("binding submitted by another host: %v", err)
	}
	unadmitted := hostBinding(t, membership.KeySigner{Key: other}, bob, g.network, now)
	if _, err = g.s.bind(ctx, id(bob), g.network, unadmitted); !errors.Is(err, errForbidden) {
		t.Fatalf("binding by an unadmitted person: %v", err)
	}
	if m, err = g.s.bind(ctx, id(bob), g.network, binding); err != nil || memberEntry(m, id(bob)).Binding == nil {
		t.Fatalf("binding not served: %v", err)
	}
	second := hostBinding(t, membership.KeySigner{Key: quinn}, bob, g.network, now)
	if _, err = g.s.bind(ctx, id(bob), g.network, second); !errors.Is(err, errConflict) {
		t.Fatalf("second binding: %v", err)
	}
	// Unbinding is permanent for that host and person.
	unbind, _ := membership.SignHostUnbinding(signer, g.network, membership.PublicKey(bob), now)
	if m, err = g.s.revoke(ctx, id(carol), g.network, revocationRequest{membership.KindUnbind, rawOf(t, unbind)}); err != nil || memberEntry(m, id(bob)).Binding != nil {
		t.Fatalf("unbind: %v", err)
	}
	if _, err = g.s.bind(ctx, id(bob), g.network, binding); !errors.Is(err, errForbidden) {
		t.Fatalf("rebinding after unbind: %v", err)
	}
	if _, err = g.s.bind(ctx, id(bob), g.network, second); err != nil {
		t.Fatalf("binding to another person after unbind: %v", err)
	}
	// Removing a person ends its bindings and is permanent.
	quinnBinding := hostBinding(t, membership.KeySigner{Key: quinn}, carol, g.network, now)
	if _, err = g.s.bind(ctx, id(carol), g.network, quinnBinding); err != nil {
		t.Fatal(err)
	}
	removal := membership.SignPersonRemoval(g.root, g.network, membership.PublicKey(quinn), now)
	if m, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindPerson, rawOf(t, removal)}); err != nil {
		t.Fatal(err)
	}
	if personByKey(m, membership.PublicKey(quinn)) != nil || memberEntry(m, id(carol)).Binding != nil || memberEntry(m, id(bob)).Binding != nil {
		t.Fatal("removed person or its bindings still served")
	}
	readmit := membership.SignPersonAdmission(g.root, g.network, 0, membership.PublicKey(quinn), "quinn", now)
	if _, err = g.s.admitPerson(ctx, id(admin), g.network, joinBody(t, map[string]any{"admission": readmit})); !errors.Is(err, errForbidden) {
		t.Fatalf("removed person readmitted: %v", err)
	}
}

func TestRotationRequiresAdmissions(t *testing.T) {
	ctx := context.Background()
	admin, carol, person := key(t), key(t), key(t)
	g, _ := openGoverned(t, admin)
	now := membership.Timestamp(time.Now())
	hostAdmission := membership.SignHostAdmission(g.root, g.network, 0, membership.PublicKey(carol), "carol", now)
	if _, err := g.s.admitHost(ctx, id(admin), g.network, hostAdmission); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.s.joinRequest(ctx, id(carol), g.network, joinBody(t, map[string]any{"address": "", "candidates": []string{}})); err != nil {
		t.Fatal(err)
	}
	if _, err := g.s.admitPerson(ctx, id(admin), g.network, joinBody(t, map[string]any{"admission": membership.SignPersonAdmission(g.root, g.network, 0, membership.PublicKey(person), "pat", now)})); err != nil {
		t.Fatal(err)
	}
	next := key(t)
	rotation := membership.SignRotation(g.root, g.network, 1, next.Public().(ed25519.PublicKey), now)
	attest := []membership.Attestation{membership.SignAttestation(next, g.network, 1, membership.PublicKey(admin), "admin", now)}
	hostRenewal := rawOf(t, membership.SignHostAdmission(next, g.network, 1, membership.PublicKey(carol), "carol", now))
	personRenewal := rawOf(t, membership.SignPersonAdmission(next, g.network, 1, membership.PublicKey(person), "pat", now))
	if _, err := g.s.rotate(ctx, id(admin), g.network, rotationRequest{rotation, attest, []json.RawMessage{hostRenewal}}); !errors.Is(err, errInvalid) {
		t.Fatalf("rotation without person admissions: %v", err)
	}
	m, err := g.s.rotate(ctx, id(admin), g.network, rotationRequest{rotation, attest, []json.RawMessage{hostRenewal, personRenewal}})
	if err != nil {
		t.Fatal(err)
	}
	var served membership.HostAdmission
	if err = json.Unmarshal(memberEntry(m, id(carol)).Admission, &served); err != nil || served.Epoch != 1 {
		t.Fatalf("admitted member not renewed: %v %+v", err, served)
	}
	p := personByKey(m, membership.PublicKey(person))
	if p == nil || p.Admission == nil {
		t.Fatal("person not renewed")
	}
}

func TestRevokingPersonInviteDropsInviteOnlyPerson(t *testing.T) {
	ctx := context.Background()
	admin, quinn := key(t), key(t)
	g, _ := openGoverned(t, admin)
	now := membership.Timestamp(time.Now())
	token, _ := membership.PersonInvite(g.network, g.root, 0, "quinn", membership.Timestamp(time.Now().Add(time.Hour)))
	redeemed, _ := token.Redeem(membership.PublicKey(quinn), now)
	if _, err := g.s.admitPerson(ctx, id(admin), g.network, joinBody(t, map[string]any{"membership": redeemed})); err != nil {
		t.Fatal(err)
	}
	revoke := membership.SignInviteRevocation(g.root, g.network, token.InvitePublicKey, now)
	m, err := g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindInvite, rawOf(t, revoke)})
	if err != nil || personByKey(m, membership.PublicKey(quinn)) != nil {
		t.Fatalf("person admitted only through a revoked invite still served: %v", err)
	}
}

func TestPersonLabelsAreUniqueUntilRemoved(t *testing.T) {
	ctx := context.Background()
	admin, bob, first, second, third := key(t), key(t), key(t), key(t), key(t)
	g, _ := openGoverned(t, admin, bob)
	now := membership.Timestamp(time.Now())
	admit := func(person ed25519.PrivateKey, label string) error {
		a := membership.SignPersonAdmission(g.root, g.network, 0, membership.PublicKey(person), label, now)
		_, err := g.s.admitPerson(ctx, id(admin), g.network, joinBody(t, map[string]any{"admission": a}))
		return err
	}
	if err := admit(first, "bob"); err != nil {
		t.Fatal(err)
	}
	// A repeat for the same key is still idempotent.
	if err := admit(first, "bob"); err != nil {
		t.Fatalf("repeat admission refused: %v", err)
	}
	if err := admit(second, "BoB"); !errors.Is(err, errConflict) {
		t.Fatalf("label differing in ASCII case admitted: %v", err)
	}
	// A person invite redeemed under a taken label conflicts too.
	token, _ := membership.PersonInvite(g.network, g.root, 0, "bob", membership.Timestamp(time.Now().Add(time.Hour)))
	redeemed, err := token.Redeem(membership.PublicKey(third), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.s.admitPerson(ctx, id(bob), g.network, joinBody(t, map[string]any{"membership": redeemed})); !errors.Is(err, errConflict) {
		t.Fatalf("invite redeemed under a taken label: %v", err)
	}
	if err = admit(second, "bob.smith"); err != nil {
		t.Fatal(err)
	}
	// Removing the first bob frees the label.
	removal := membership.SignPersonRemoval(g.root, g.network, membership.PublicKey(first), now)
	if _, err = g.s.revoke(ctx, id(admin), g.network, revocationRequest{membership.KindPerson, rawOf(t, removal)}); err != nil {
		t.Fatal(err)
	}
	if _, err = g.s.admitPerson(ctx, id(bob), g.network, joinBody(t, map[string]any{"membership": redeemed})); err != nil {
		t.Fatalf("freed label refused: %v", err)
	}
}
