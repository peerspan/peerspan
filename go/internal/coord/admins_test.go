package coord

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// must returns a signing result; signing with valid inputs does not fail.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// adminNetwork admits the person pat by the root and delegates pat.
func adminNetwork(t *testing.T, members ...ed25519.PrivateKey) (governed, ed25519.PrivateKey, membership.SSHSigner) {
	t.Helper()
	ctx := context.Background()
	g, _ := openGoverned(t, members...)
	now := membership.Timestamp(time.Now())
	pat := key(t)
	if _, err := g.s.admitPerson(ctx, id(members[0]), g.network, joinBody(t, map[string]any{"admission": membership.SignPersonAdmission(g.root, g.network, 0, membership.PublicKey(pat), "pat", now)})); err != nil {
		t.Fatal(err)
	}
	d := must(membership.SignAdminDelegation(membership.RawSigner{Key: g.root}, g.network, 0, membership.PublicKey(pat), now))
	m, err := g.s.delegate(ctx, id(members[0]), g.network, d)
	if err != nil || len(m.Admins) != 1 {
		t.Fatalf("delegation: %v %+v", err, m)
	}
	return g, pat, membership.SSHSigner{PersonSigner: membership.KeySigner{Key: pat}}
}

func mustTx(t *testing.T, s *Server) *sql.Tx {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return tx
}

func groupOf(t *testing.T, m *membership.Map, name string) *membership.GroupDefinition {
	t.Helper()
	for _, raw := range m.Groups {
		var g membership.GroupDefinition
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
		if g.Name == name {
			return &g
		}
	}
	return nil
}

func TestAdministratorsAndRemoval(t *testing.T) {
	ctx := context.Background()
	host, carol, dave := key(t), key(t), key(t)
	g, pat, admin := adminNetwork(t, host)
	now := membership.Timestamp(time.Now())
	later := membership.Timestamp(time.Now().Add(time.Hour))
	patKey := membership.PublicKey(pat)

	// Only the root delegates, and only admitted persons.
	selfDelegated := must(membership.SignAdminDelegation(admin, g.network, 0, patKey, now))
	if _, err := g.s.delegate(ctx, id(host), g.network, selfDelegated); err == nil {
		t.Fatal("accepted a delegation signed by an administrator")
	}
	stranger := must(membership.SignAdminDelegation(membership.RawSigner{Key: g.root}, g.network, 0, membership.PublicKey(key(t)), now))
	if _, err := g.s.delegate(ctx, id(host), g.network, stranger); !errors.Is(err, errForbidden) {
		t.Fatalf("delegated a non-person: %v", err)
	}

	// The administrator admits a host and a person and issues an invite.
	carolAdmission := must(membership.SignHostAdmissionWith(admin, g.network, 0, membership.PublicKey(carol), "carol", now))
	if _, err := g.s.admitHost(ctx, id(host), g.network, carolAdmission); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.s.joinRequest(ctx, id(carol), g.network, joinBody(t, map[string]any{"address": "", "candidates": []string{}})); err != nil {
		t.Fatal(err)
	}
	quinn := key(t)
	quinnAdmission := must(membership.SignPersonAdmissionWith(admin, g.network, 0, membership.PublicKey(quinn), "quinn", now))
	if _, err := g.s.admitPerson(ctx, id(host), g.network, joinBody(t, map[string]any{"admission": quinnAdmission})); err != nil {
		t.Fatal(err)
	}
	invite := must(membership.InviteWith(g.network, admin, "dave", later))
	if _, _, err := g.s.join(ctx, id(dave), g.network, joinRequest{Membership: must(invite.Join(dave, now)), Candidates: []string{}}); err != nil {
		t.Fatalf("join through an administrator's invite: %v", err)
	}

	// Groups: versions only increase; a retry is accepted.
	root := membership.RawSigner{Key: g.root}
	quinnID := membership.PersonID(quinn.Public().(ed25519.PublicKey))
	patID := membership.PersonID(pat.Public().(ed25519.PublicKey))
	v1 := must(membership.SignGroup(root, g.network, "backend", 1, []string{patID}, now))
	v2 := must(membership.SignGroup(admin, g.network, "backend", 2, []string{patID, quinnID}, now))
	if _, err := g.s.defineGroup(ctx, id(host), g.network, v1); err != nil {
		t.Fatal(err)
	}
	m, err := g.s.defineGroup(ctx, id(host), g.network, v2)
	if err != nil || groupOf(t, m, "backend").Version != 2 {
		t.Fatalf("group v2: %v", err)
	}
	if _, err = g.s.defineGroup(ctx, id(host), g.network, v2); err != nil {
		t.Fatalf("retried group: %v", err)
	}
	stale := must(membership.SignGroup(admin, g.network, "backend", 2, []string{quinnID}, now))
	if _, err = g.s.defineGroup(ctx, id(host), g.network, stale); !errors.Is(err, errConflict) {
		t.Fatalf("stale group version: %v", err)
	}

	// Removal without revoke_admitted: earlier statements stay valid, but the
	// administrator can sign nothing new.
	// It lists what pat signed; a backdated statement pat signs later is not
	// listed and is ignored even though it is stored.
	kept := []string{}
	for _, message := range [][]byte{carolAdmission.Message(), quinnAdmission.Message(), membership.InviteStatement(g.network, invite.InvitePublicKey, "dave", later), v2.Message()} {
		kept = append(kept, membership.StatementDigest(message))
	}
	keep := must(membership.SignAdminRemoval(root, g.network, patKey, false, kept, now))
	// A person who is a current administrator cannot be removed as a person.
	personRemoval := membership.SignPersonRemoval(g.root, g.network, patKey, now)
	if _, err = g.s.revoke(ctx, id(host), g.network, revocationRequest{membership.KindPerson, rawOf(t, personRemoval)}); !errors.Is(err, errConflict) {
		t.Fatalf("removed a current administrator as a person: %v", err)
	}
	if m, err = g.s.revoke(ctx, id(host), g.network, revocationRequest{membership.KindAdmin, rawOf(t, keep)}); err != nil {
		t.Fatal(err)
	}
	if !memberIDs(m)[id(carol)] || !memberIDs(m)[id(dave)] || personByKey(m, membership.PublicKey(quinn)) == nil || groupOf(t, m, "backend").Version != 2 || len(m.Admins) != 1 {
		t.Fatalf("removal without revoke_admitted dropped statements: %+v", m)
	}
	backdated := must(membership.SignPersonAdmissionWith(admin, g.network, 0, membership.PublicKey(key(t)), "mallory", "2020-01-01T00:00:00Z"))
	if _, err = g.s.db.Exec(`INSERT INTO statements VALUES (?, ?, ?, ?)`, g.network, kindPersonAdmission, backdated.PersonPublicKey, string(rawOf(t, membership.PersonProof{Admission: &backdated}))); err != nil {
		t.Fatal(err)
	}
	tx := mustTx(t, g.s)
	m, err = networkMap(ctx, tx, g.network)
	tx.Rollback()
	if err != nil || personByKey(m, backdated.PersonPublicKey) != nil {
		t.Fatalf("served a backdated statement by a removed administrator: %v", err)
	}
	if _, err = g.s.revoke(ctx, id(host), g.network, revocationRequest{membership.KindAdmin, rawOf(t, keep)}); err != nil {
		t.Fatalf("retried removal: %v", err)
	}
	second := must(membership.SignAdminRemoval(root, g.network, patKey, false, append(kept, membership.StatementDigest(backdated.Message())), now))
	if _, err = g.s.revoke(ctx, id(host), g.network, revocationRequest{membership.KindAdmin, rawOf(t, second)}); !errors.Is(err, errConflict) {
		t.Fatalf("second plain removal: %v", err)
	}
	eve := key(t)
	if _, err = g.s.admitHost(ctx, id(host), g.network, must(membership.SignHostAdmissionWith(admin, g.network, 0, membership.PublicKey(eve), "eve", now))); err == nil {
		t.Fatalf("removed administrator admitted a host: %v", err)
	}
	v3 := must(membership.SignGroup(admin, g.network, "backend", 3, nil, now))
	if _, err = g.s.defineGroup(ctx, id(host), g.network, v3); err == nil {
		t.Fatalf("removed administrator defined a group: %v", err)
	}
	again := must(membership.SignAdminDelegation(root, g.network, 0, patKey, now))
	if _, err = g.s.delegate(ctx, id(host), g.network, again); !errors.Is(err, errForbidden) {
		t.Fatalf("re-delegated a removed administrator: %v", err)
	}

	// Removal with revoke_admitted: everything pat signed is invalid.
	cascade := must(membership.SignAdminRemoval(root, g.network, patKey, true, nil, now))
	if m, err = g.s.revoke(ctx, id(host), g.network, revocationRequest{membership.KindAdmin, rawOf(t, cascade)}); err != nil {
		t.Fatal(err)
	}
	if memberIDs(m)[id(carol)] || memberIDs(m)[id(dave)] || personByKey(m, membership.PublicKey(quinn)) != nil {
		t.Fatalf("revoke_admitted kept what the administrator admitted: %+v", m)
	}
	if g := groupOf(t, m, "backend"); g == nil || g.Version != 1 {
		t.Fatalf("group did not revert: %+v", g)
	}
	removals := 0
	for _, raw := range m.Revocations {
		var r membership.Revocation
		if json.Unmarshal(raw, &r) == nil && r.Kind == membership.KindAdmin {
			removals++
			var stored membership.AdminRemoval
			if json.Unmarshal(r.Statement, &stored) != nil || !stored.RevokeAdmitted {
				t.Fatal("revoke_admitted removal not served")
			}
		}
	}
	if removals != 1 {
		t.Fatalf("served %d administrator removals", removals)
	}
}

func TestRotationCarriesDelegations(t *testing.T) {
	ctx := context.Background()
	host, carol := key(t), key(t)
	g, pat, admin := adminNetwork(t, host)
	now := membership.Timestamp(time.Now())
	if _, err := g.s.admitHost(ctx, id(host), g.network, must(membership.SignHostAdmissionWith(admin, g.network, 0, membership.PublicKey(carol), "carol", now))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.s.joinRequest(ctx, id(carol), g.network, joinBody(t, map[string]any{"address": "", "candidates": []string{}})); err != nil {
		t.Fatal(err)
	}
	rootGroup := must(membership.SignGroup(membership.RawSigner{Key: g.root}, g.network, "ops", 3, []string{membership.PersonID(pat.Public().(ed25519.PublicKey))}, now))
	if _, err := g.s.defineGroup(ctx, id(host), g.network, rootGroup); err != nil {
		t.Fatal(err)
	}
	next := key(t)
	nextSigner := membership.SSHSigner{PersonSigner: membership.KeySigner{Key: next}}
	rotation := membership.SignRotation(g.root, g.network, 1, next.Public().(ed25519.PublicKey), now)
	attest := []membership.Attestation{must(membership.SignAttestationWith(nextSigner, g.network, 1, membership.PublicKey(host), "admin", now))}
	person := rawOf(t, must(membership.SignPersonAdmissionWith(nextSigner, g.network, 1, membership.PublicKey(pat), "pat", now)))
	delegation := rawOf(t, must(membership.SignAdminDelegation(nextSigner, g.network, 1, membership.PublicKey(pat), now)))
	if _, err := g.s.rotate(ctx, id(host), g.network, rotationRequest{rotation, attest, []json.RawMessage{person}, nil}); !errors.Is(err, errInvalid) {
		t.Fatalf("rotation without delegations: %v", err)
	}
	if _, err := g.s.rotate(ctx, id(host), g.network, rotationRequest{rotation, attest, []json.RawMessage{person, delegation}, nil}); !errors.Is(err, errInvalid) {
		t.Fatalf("rotation without renewing a root-signed group: %v", err)
	}
	changed := must(membership.SignGroup(nextSigner, g.network, "ops", 3, nil, now))
	if _, err := g.s.rotate(ctx, id(host), g.network, rotationRequest{rotation, attest, []json.RawMessage{person, delegation}, []membership.GroupDefinition{changed}}); !errors.Is(err, errInvalid) {
		t.Fatalf("renewal with different members: %v", err)
	}
	renewed := must(membership.SignGroup(nextSigner, g.network, "ops", 3, rootGroup.Members, now))
	// The administrator's host admission needs no renewal.
	m, err := g.s.rotate(ctx, id(host), g.network, rotationRequest{rotation, attest, []json.RawMessage{person, delegation}, []membership.GroupDefinition{renewed}})
	if err != nil {
		t.Fatal(err)
	}
	if ops := groupOf(t, m, "ops"); ops == nil || ops.Version != 3 || ops.Signature != renewed.Signature {
		t.Fatalf("root-signed group not renewed: %+v", ops)
	}
	if !memberIDs(m)[id(carol)] {
		t.Fatal("administrator-admitted host lapsed at the rotation")
	}
	var d membership.AdminDelegation
	if len(m.Admins) != 1 || json.Unmarshal(m.Admins[0], &d) != nil || d.Epoch != 1 {
		t.Fatalf("delegation not renewed: %+v", m.Admins)
	}
	// The administrator stays current under the SSH root.
	dave := key(t)
	if _, err = g.s.admitHost(ctx, id(host), g.network, must(membership.SignHostAdmissionWith(admin, g.network, 1, membership.PublicKey(dave), "dave", now))); err != nil {
		t.Fatal(err)
	}
}
