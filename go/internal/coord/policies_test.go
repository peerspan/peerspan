package coord

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func TestPoliciesAreVersionedAndServedForCurrentPersons(t *testing.T) {
	ctx := context.Background()
	host := key(t)
	g, _, _ := adminNetwork(t, host)
	pat := key(t)
	if _, err := g.s.admitPerson(ctx, id(host), g.network, joinBody(t, map[string]any{"admission": membership.SignPersonAdmission(g.root, g.network, 0, membership.PublicKey(pat), "quinn", membership.Timestamp(time.Now()))})); err != nil {
		t.Fatal(err)
	}
	owner := membership.KeySigner{Key: pat}
	rules := []membership.PolicyRule{{Agent: "reviewer", Principals: []string{membership.PrincipalNetwork}, Actions: []string{membership.PolicyActionMessage}, MaxMessageBytes: 10}}
	sign := func(signer membership.PersonSigner, version int64, issued time.Time) membership.Policy {
		return must(membership.SignPolicy(signer, g.network, version, issued, 7*24*time.Hour, rules))
	}
	if _, err := g.s.submitPolicy(ctx, id(key(t)), g.network, sign(owner, 1, time.Now())); !errors.Is(err, errForbidden) {
		t.Fatalf("non-member submitted: %v", err)
	}
	if _, err := g.s.submitPolicy(ctx, id(host), g.network, sign(membership.KeySigner{Key: key(t)}, 1, time.Now())); !errors.Is(err, errForbidden) {
		t.Fatalf("policy of a non-person: %v", err)
	}
	if _, err := g.s.submitPolicy(ctx, id(host), g.network, sign(owner, 1, time.Now().Add(-8*24*time.Hour))); !errors.Is(err, errInvalid) {
		t.Fatalf("expired policy: %v", err)
	}
	tampered := sign(owner, 1, time.Now())
	tampered.Rules[0].MaxMessageBytes = 11
	if _, err := g.s.submitPolicy(ctx, id(host), g.network, tampered); err == nil {
		t.Fatal("tampered policy accepted")
	}
	v1 := sign(owner, 1, time.Now())
	m, err := g.s.submitPolicy(ctx, id(host), g.network, v1)
	if err != nil || len(m.Policies) != 1 {
		t.Fatalf("submit: %v %+v", err, m)
	}
	// An identical resubmission is accepted; another version that is not
	// higher is refused.
	if m, err = g.s.submitPolicy(ctx, id(host), g.network, v1); err != nil || len(m.Policies) != 1 {
		t.Fatalf("identical resubmission: %v", err)
	}
	if _, err = g.s.submitPolicy(ctx, id(host), g.network, sign(owner, 1, time.Now().Add(time.Second))); !errors.Is(err, errConflict) {
		t.Fatalf("version not higher: %v", err)
	}
	v3 := sign(owner, 3, time.Now())
	if m, err = g.s.submitPolicy(ctx, id(host), g.network, v3); err != nil || len(m.Policies) != 1 || string(m.Policies[0]) != string(rawOf(t, v3)) {
		t.Fatalf("higher version: %v %+v", err, m)
	}
	// A removed person's policy is no longer served.
	removal := membership.SignPersonRemoval(g.root, g.network, membership.PublicKey(pat), membership.Timestamp(time.Now()))
	if m, err = g.s.revoke(ctx, id(host), g.network, revocationRequest{membership.KindPerson, rawOf(t, removal)}); err != nil {
		t.Fatal(err)
	}
	if len(m.Policies) != 0 {
		t.Fatalf("removed person's policy served: %+v", m.Policies)
	}
}
