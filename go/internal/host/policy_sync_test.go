package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

type siblingNet struct {
	net               *testNet
	id                string
	alice, bob, carol *Store
	pat, quinn        membership.KeySigner
	patID             string
}

// startSiblings binds alice and bob to pat and carol to quinn.
func startSiblings(t *testing.T) siblingNet {
	t.Helper()
	ctx := context.Background()
	n := siblingNet{net: startCoordinator(t), alice: startPeerHost(t, "alice"), bob: startPeerHost(t, "bob"), carol: startPeerHost(t, "carol"), pat: personKey(t), quinn: personKey(t)}
	created := must(n.alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: n.net.address, CoordinatorPublicKey: n.net.coord.Identity().PublicKey}))
	n.id, n.patID = created.ID, membership.PersonID(n.pat.PublicKey())
	for _, s := range []*Store{n.bob, n.carol} {
		invite := must(n.alice.CreateInvite(ctx, n.id, CreateInvite{Member: "m", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
		must(s.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}))
	}
	for label, key := range map[string]membership.KeySigner{"pat": n.pat, "quinn": n.quinn} {
		must(n.alice.AdmitPerson(ctx, n.id, AdmitPerson{PersonPublicKey: membership.EncodeKey(key.PublicKey()), Member: label}))
	}
	bindTo(t, n.alice, n.id, n.pat)
	bindTo(t, n.bob, n.id, n.pat)
	bindTo(t, n.carol, n.id, n.quinn)
	for _, s := range []*Store{n.alice, n.bob, n.carol} {
		mustSync(t, s, n.id)
	}
	return n
}

func (n siblingNet) sign(t *testing.T, version uint64, issued time.Time, rules ...membership.PolicyRule) membership.Policy {
	t.Helper()
	return must(membership.SignPolicy(n.pat, n.id, version, issued, 7*24*time.Hour, rules))
}

func deliveries(status PolicySyncStatus) map[string]PolicyDelivery {
	out := map[string]PolicyDelivery{}
	for _, d := range status.Deliveries {
		out[d.Target] = d
	}
	return out
}

func TestPolicyPushAndSync(t *testing.T) {
	ctx := context.Background()
	n := startSiblings(t)
	alice, bob, carol := n.alice, n.bob, n.carol
	a, b := alice.Identity().ID, bob.Identity().ID
	if _, hosts, _ := alice.siblings(ctx, alice.db, n.id); len(hosts) != 1 || hosts[0] != b {
		t.Fatalf("alice's siblings: %v", hosts)
	}
	if _, hosts, _ := carol.siblings(ctx, carol.db, n.id); len(hosts) != 0 {
		t.Fatalf("carol's siblings: %v", hosts)
	}

	// Stored first; the coordinator is attempted at once, the sibling queued.
	v1 := n.sign(t, 1, time.Now(), rule("reviewer", 100, false, "network"))
	must(alice.SubmitPolicy(ctx, n.id, v1))
	status := must(alice.PolicySyncStatus(ctx, n.id))
	d := deliveries(status)
	if status.PersonID != n.patID || *status.Version != 1 || *status.SHA256 != membership.PolicyHash(v1) || len(d) != 2 {
		t.Fatalf("status: %+v", status)
	}
	if d["coordinator"].State != "delivered" || d["coordinator"].DeliveredAt == nil || d["coordinator"].NextAttemptAt != nil || d["coordinator"].Attempts != 1 {
		t.Fatalf("coordinator delivery: %+v", d["coordinator"])
	}
	if d[b].State != "pending" || d[b].Attempts != 0 || d[b].NextAttemptAt == nil || d[b].Version != 1 {
		t.Fatalf("sibling delivery: %+v", d[b])
	}
	status = must(alice.SyncPolicyNow(ctx, n.id, t.Logf))
	if d = deliveries(status); d[b].State != "delivered" || d[b].Error != nil {
		t.Fatalf("after sync: %+v", d[b])
	}
	if got := must(bob.Policy(ctx, n.id, "")); got.Signature != v1.Signature {
		t.Fatalf("bob holds %d", got.Version)
	}
	if countEvents(t, alice, "network.policy_delivered", n.patID+"/"+b) != 1 || countEvents(t, alice, "network.policy_delivered", n.patID+"/coordinator") != 1 {
		t.Fatal("delivery events")
	}
	// A push stores without a sync event; bob queues its own deliveries.
	if countEvents(t, bob, "network.policy_synced", n.patID+"/"+a) != 0 || countEvents(t, bob, "network.policy_updated", n.patID) != 1 {
		t.Fatal("bob's events after a push")
	}
	if d = deliveries(must(bob.PolicySyncStatus(ctx, n.id))); d[a].State != "pending" || d["coordinator"].State != "pending" {
		t.Fatalf("bob's deliveries: %+v", d)
	}

	// With the coordinator stopped, a withdrawal still reaches the sibling.
	n.net.stop()
	v2 := n.sign(t, 2, time.Now(), []membership.PolicyRule{}...)
	must(alice.SubmitPolicy(ctx, n.id, v2))
	if got := must(alice.Policy(ctx, n.id, "")); got.Version != 2 {
		t.Fatalf("alice holds %d", got.Version)
	}
	d = deliveries(must(alice.PolicySyncStatus(ctx, n.id)))
	if c := d["coordinator"]; c.State != "pending" || c.Attempts != 1 || c.Error == nil || c.Version != 2 || c.DeliveredAt != nil {
		t.Fatalf("coordinator delivery while stopped: %+v", c)
	}
	if d[b].State != "pending" || d[b].Version != 2 || d[b].Attempts != 0 {
		t.Fatalf("superseded sibling delivery: %+v", d[b])
	}
	d = deliveries(must(alice.SyncPolicyNow(ctx, n.id, t.Logf)))
	if d[b].State != "delivered" || d["coordinator"].State != "pending" || d["coordinator"].Attempts != 2 {
		t.Fatalf("after sync while stopped: %+v", d)
	}
	if got := must(bob.Policy(ctx, n.id, "")); got.Version != 2 || len(got.Rules) != 0 {
		t.Fatalf("bob holds %+v", got)
	}

	// Peer routes: a lower version is reported, not stored; non-siblings and
	// invalid policies are refused.
	head := must(bob.ReceivePolicy(ctx, a, n.id, v1))
	if head.Version != 2 || head.SHA256 != membership.PolicyHash(v2) || head.PersonID != n.patID {
		t.Fatalf("head after a lower push: %+v", head)
	}
	if _, err := bob.ReceivePolicy(ctx, carol.Identity().ID, n.id, v2); !errors.Is(err, ErrForbidden) {
		t.Fatalf("push from a non-sibling: %v", err)
	}
	if _, err := carol.ReceivePolicy(ctx, a, n.id, v2); !errors.Is(err, ErrForbidden) {
		t.Fatalf("push to a non-sibling: %v", err)
	}
	if _, err := bob.SiblingPolicy(ctx, carol.Identity().ID, n.id, n.patID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("fetch by a non-sibling: %v", err)
	}
	if _, err := bob.SiblingPolicy(ctx, a, n.id, membership.PersonID(n.quinn.PublicKey())); !errors.Is(err, ErrForbidden) {
		t.Fatalf("fetch of another person: %v", err)
	}
	if got := must(bob.SiblingPolicy(ctx, a, n.id, n.patID)); got.Signature != v2.Signature {
		t.Fatalf("fetched %d", got.Version)
	}
	tampered := v2
	tampered.Version = 9
	expired := must(membership.SignPolicy(n.pat, n.id, 9, time.Now().Add(-48*time.Hour), 24*time.Hour, nil))
	other := v2
	other.NetworkID = "net_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for name, p := range map[string]membership.Policy{"tampered": tampered, "expired": expired, "other network": other} {
		if _, err := bob.ReceivePolicy(ctx, a, n.id, p); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s push: %v", name, err)
		}
	}
	if _, err := alice.SubmitPolicy(ctx, n.id, v1); !errors.Is(err, ErrConflict) {
		t.Fatalf("lower local submission: %v", err)
	}

	// Concurrent same-version policies converge on the lower hash, by sync.
	x := n.sign(t, 3, time.Now(), rule("x", 1, false, "network"))
	y := n.sign(t, 3, time.Now(), rule("y", 1, false, "network"))
	low, high := x, y
	if membership.PolicyHash(low) > membership.PolicyHash(high) {
		low, high = high, low
	}
	if _, err := alice.db.ExecContext(ctx, "UPDATE policy_deliveries SET record = json_set(record, '$.next_attempt_at', '2999-01-01T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	must(alice.SubmitPolicy(ctx, n.id, high))
	must(bob.SubmitPolicy(ctx, n.id, low))
	if _, err := bob.SubmitPolicy(ctx, n.id, high); !errors.Is(err, ErrConflict) {
		t.Fatalf("higher-hash equal version: %v", err)
	}
	must(alice.SyncPolicyNow(ctx, n.id, t.Logf))
	for _, s := range []*Store{alice, bob} {
		if got := must(s.Policy(ctx, n.id, "")); got.Signature != low.Signature {
			t.Fatalf("%s kept the higher hash", s.Identity().ID[:9])
		}
	}
	if countEvents(t, alice, "network.policy_synced", n.patID+"/"+b) != 1 {
		t.Fatal("sync event")
	}
	// Alice's delivery of the loser to bob completes: bob reports the same version.
	d = deliveries(must(alice.PolicySyncStatus(ctx, n.id)))
	if d[b].Version != 3 {
		t.Fatalf("alice's delivery after the tie-break: %+v", d[b])
	}

	// A delivery to a host that is no longer a sibling is dropped.
	c := carol.Identity().ID
	record := policyDeliveryRecord{PolicyDelivery{Target: c, Version: 3, State: "pending", NextAttemptAt: ref(timestamp(time.Now()))}, low}
	if _, err := alice.db.ExecContext(ctx, "INSERT INTO policy_deliveries VALUES (?, ?, ?, ?)", n.id, n.patID, c, string(rawJSON(t, record))); err != nil {
		t.Fatal(err)
	}
	if _, ok := deliveries(must(alice.PolicySyncStatus(ctx, n.id)))[c]; ok {
		t.Fatal("delivery to a non-sibling kept")
	}
	var rows int
	if err := alice.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM policy_deliveries WHERE target = ?", c).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rows %d %v", rows, err)
	}
	// A host not bound in the network has no sync status.
	if _, err := carol.PolicySyncStatus(ctx, "net_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown network: %v", err)
	}
}

func TestPolicyFromAnotherOwnerGoesToCoordinatorOnly(t *testing.T) {
	ctx := context.Background()
	n := startSiblings(t)
	p := n.sign(t, 1, time.Now(), rule("reviewer", 100, false, "network"))
	must(n.carol.SubmitPolicy(ctx, n.id, p))
	var targets []string
	rows, err := n.carol.db.QueryContext(ctx, "SELECT target FROM policy_deliveries WHERE person_id = ?", n.patID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var target string
		_ = rows.Scan(&target)
		targets = append(targets, target)
	}
	rows.Close()
	if len(targets) != 1 || targets[0] != "coordinator" {
		t.Fatalf("targets %v", targets)
	}
	// Alice receives it from the map, as her own person's, and queues it.
	mustSync(t, n.alice, n.id)
	d := deliveries(must(n.alice.PolicySyncStatus(ctx, n.id)))
	if d[n.bob.Identity().ID].State != "pending" || len(d) != 2 {
		t.Fatalf("alice's deliveries after the map: %+v", d)
	}
}

func TestPolicyBackoff(t *testing.T) {
	s := &Store{}
	s.retry.jitter = func() float64 { return 1 }
	for attempts, want := range map[int64]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 9: 256 * time.Second, 10: 5 * time.Minute, 40: 5 * time.Minute} {
		if got := s.policyBackoff(attempts); got != want {
			t.Errorf("attempt %d: %v, want %v", attempts, got, want)
		}
	}
	s.retry.jitter = func() float64 { return 1.2 }
	if got := s.policyBackoff(20); got != 6*time.Minute {
		t.Errorf("jittered cap: %v", got)
	}
}

func TestSiblingGainedSchedulesSync(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob := startPeerHost(t, "alice"), startPeerHost(t, "bob")
	created := must(alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey}))
	invite := must(alice.CreateInvite(ctx, created.ID, CreateInvite{Member: "m", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
	must(bob.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}))
	pat := personKey(t)
	must(alice.AdmitPerson(ctx, created.ID, AdmitPerson{PersonPublicKey: membership.EncodeKey(pat.PublicKey()), Member: "pat"}))
	bindTo(t, alice, created.ID, pat)
	mustSync(t, alice, created.ID)
	gained := func() bool {
		p := alice.policyState()
		p.mu.Lock()
		defer p.mu.Unlock()
		found := p.networks[created.ID]
		p.networks = map[string]bool{}
		return found
	}
	gained() // alice's own binding may have scheduled one
	mustSync(t, alice, created.ID)
	if gained() {
		t.Fatal("sync scheduled without a new sibling")
	}
	bindTo(t, bob, created.ID, pat)
	mustSync(t, alice, created.ID)
	if !gained() {
		t.Fatal("no sync scheduled for a new sibling")
	}
}

func TestPolicyDeliveriesMigrationToVersion12(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir() + "/host"
	s := must(Open(ctx, dir))
	if _, err := s.db.ExecContext(ctx, "DROP TABLE policy_edits; DROP TABLE directory_sends; DROP TABLE policy_deliveries; PRAGMA user_version = 11"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = must(Open(ctx, dir))
	defer s.Close()
	var version int
	var sql string
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 18 {
		t.Fatalf("version %d %v", version, err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE name = 'policy_deliveries'").Scan(&sql); err != nil || sql != "CREATE TABLE policy_deliveries (network_id TEXT NOT NULL, person_id TEXT NOT NULL, target TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, person_id, target))" {
		t.Fatalf("schema %q %v", sql, err)
	}
}
