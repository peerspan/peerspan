package host

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/peerspan/peerspan/go/internal/membership"
)

func bindTo(t *testing.T, s *Store, id string, owner membership.KeySigner) {
	t.Helper()
	mustSync(t, s, id)
	binding, err := membership.SignHostBinding(owner, id, s.Identity().PublicKey, timestamp(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Bind(context.Background(), id, BindHost{Binding: rawJSON(t, binding)}); err != nil {
		t.Fatal(err)
	}
}

func rule(agent string, bytes int64, disconnected bool, principals ...string) membership.PolicyRule {
	return membership.PolicyRule{Agent: agent, Principals: principals, Actions: []string{membership.PolicyActionMessage}, MaxMessageBytes: bytes, AllowDisconnected: disconnected}
}

// serveAgent serves an in-process ssh-agent holding key.
func serveAgent(t *testing.T, key membership.KeySigner) string {
	t.Helper()
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: &key.Key}); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _ = agent.ServeAgent(keyring, conn) }()
		}
	}()
	return socket
}

func TestOwnerAccessPolicy(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, carol := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "carol")
	// The receiver accepts non-disconnected sends only within three intervals
	// of its last sync; widen the window so slow runs (-race, load) stay
	// connected. The stale case below backdates the sync by an hour.
	advertise, _ := alice.coordinationConfig()
	if err := alice.ConfigureCoordination(advertise, time.Minute); err != nil {
		t.Fatal(err)
	}
	created, err := alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	id := created.ID
	for _, s := range []*Store{bob, carol} {
		invite := must(alice.CreateInvite(ctx, id, CreateInvite{Member: "m", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
		if _, err = s.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}); err != nil {
			t.Fatal(err)
		}
	}
	pat, quinn := personKey(t), personKey(t)
	patID, quinnID := membership.PersonID(pat.PublicKey()), membership.PersonID(quinn.PublicKey())
	for label, key := range map[string]membership.KeySigner{"pat": pat, "quinn": quinn} {
		if _, err = alice.AdmitPerson(ctx, id, AdmitPerson{PersonPublicKey: membership.EncodeKey(key.PublicKey()), Member: label}); err != nil {
			t.Fatal(err)
		}
	}
	bindTo(t, alice, id, pat)
	bindTo(t, bob, id, quinn)
	for _, s := range []*Store{alice, bob, carol} {
		mustSync(t, s, id)
	}
	reviewer := must(alice.RegisterAgent(ctx, RegisterAgent{Name: "reviewer", Owner: "pat"}))
	triage := must(alice.RegisterAgent(ctx, RegisterAgent{Name: "triage", Owner: "pat"}))

	send := func(from *Store, agent, content string) (OutboundMessage, error) {
		t.Helper()
		out, err := from.PrepareOutbound(ctx, SendMessage{PeerHostID: alice.Identity().ID, MessageRequest: MessageRequest{TargetAgentID: agent, Deadline: timestamp(time.Now().Add(time.Minute)), Content: content}})
		if err != nil {
			return out, err
		}
		return from.Exchange(ctx, out, false)
	}
	expect := func(from *Store, agent, content, state string) OutboundMessage {
		t.Helper()
		out, err := send(from, agent, content)
		if err != nil || out.State != state {
			t.Fatalf("send %q: want %s, got %v %+v", content, state, err, out)
		}
		return out
	}
	// Without a grant or a policy, the send is refused before persisting.
	if _, err = send(bob, reviewer.ID, "early"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "no access policy") {
		t.Fatalf("send without policy: %v", err)
	}
	if _, err = alice.Policy(ctx, id, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("show before any policy: %v", err)
	}

	sign := func(version int64, issued time.Time, validFor time.Duration, rules ...membership.PolicyRule) membership.Policy {
		t.Helper()
		return must(membership.SignPolicy(pat, id, version, issued, validFor, rules))
	}
	week := 7 * 24 * time.Hour
	v1 := sign(1, time.Now(), week, rule("reviewer", 100, false, "person:"+quinnID))
	if _, err = alice.SubmitPolicy(ctx, id, v1); err != nil {
		t.Fatal(err)
	}
	if _, err = bob.SubmitPolicy(ctx, id, v1); err != nil {
		t.Fatalf("identical resubmission: %v", err)
	}
	// Another version 1 is refused unless its statement hash is lower.
	another := sign(1, time.Now().Add(time.Second), week, v1.Rules...)
	for i := 2; membership.PolicyHash(another) < membership.PolicyHash(v1); i++ {
		another = sign(1, time.Now().Add(time.Duration(i)*time.Second), week, v1.Rules...)
	}
	if _, err = alice.SubmitPolicy(ctx, id, another); !errors.Is(err, ErrConflict) {
		t.Fatalf("another version 1: %v", err)
	}
	if _, err = alice.SubmitPolicy(ctx, id, sign(2, time.Now().Add(-8*24*time.Hour), week, v1.Rules...)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired policy accepted: %v", err)
	}
	if _, err = alice.SubmitPolicy(ctx, id, must(membership.SignPolicy(personKey(t), id, 2, time.Now(), week, v1.Rules))); !errors.Is(err, ErrForbidden) {
		t.Fatalf("policy of a non-person accepted: %v", err)
	}
	if countEvents(t, alice, "network.policy_updated", patID) != 1 {
		t.Fatal("no policy event")
	}
	mustSync(t, bob, id)
	mustSync(t, carol, id)
	if view := must(bob.Policy(ctx, id, "pat")); view.Version != 1 || view.ExpiresSoon {
		t.Fatalf("show: %+v", view)
	}

	// Quinn's host may message reviewer within the bounds; carol's may not.
	out := expect(bob, reviewer.ID, "hello", "accepted")
	if out.Request.Policy == nil || *out.Request.Policy != (PolicyCitation{patID, 1}) || out.Request.GrantID != nil {
		t.Fatalf("citation: %+v", out.Request)
	}
	if data, _ := json.Marshal(out.Request); strings.Contains(string(data), "grant_id") {
		t.Fatalf("policy request carries grant_id: %s", data)
	}
	expect(bob, reviewer.ID, strings.Repeat("x", 101), "rejected")
	expect(bob, triage.ID, "no rule", "rejected")
	rejected := expect(carol, reviewer.ID, "not a principal", "rejected")
	if rejected.Error == nil || !strings.Contains(*rejected.Error, "policy does not allow") {
		t.Fatalf("refusal is not explained: %+v", rejected)
	}

	// An adapter route without a grant cites the policy too.
	sender := must(bob.RegisterAgent(ctx, RegisterAgent{Name: "author", Owner: "quinn"}))
	session := must(bob.AttachSession(ctx, AttachSession{AgentID: sender.ID, Integration: "test"}))
	credential := must(bob.CreateAdapter(ctx, CreateAdapter{SessionID: session.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour))}))
	auth := AdapterAuth{Token: credential.Token, Instance: "instance_" + strings.Repeat("a", 64)}
	if _, err = bob.ConnectAdapter(ctx, auth.Token, auth.Instance, credential.Adapter.ID, session.ID); err != nil {
		t.Fatal(err)
	}
	for _, route := range []CreateOutboundRoute{{Name: "reviewer", PeerHostID: alice.Identity().ID}, {Name: "carol", PeerHostID: carol.Identity().ID}} {
		route.AdapterID, route.TargetAgentID, route.ExpiresAt, route.MaxMessageBytes, route.MaxMessages = credential.Adapter.ID, reviewer.ID, timestamp(time.Now().Add(30*time.Minute)), 100, 10
		created, err := bob.CreateOutboundRoute(ctx, route)
		if err != nil || !strings.Contains(string(rawJSON(t, created)), `"grant_id":null`) {
			t.Fatalf("route without a grant: %v %s", err, rawJSON(t, created))
		}
	}
	routed, err := bob.PrepareAdapterSend(ctx, auth, AdapterSend{Destination: "reviewer", RequestID: "request_" + strings.Repeat("1", 32), Content: "routed"})
	if err != nil || routed.Request.Policy == nil || routed.Request.Origin == nil || *routed.Request.Origin != (Origin{AgentID: sender.ID, SessionID: session.ID}) {
		t.Fatalf("route send: %v %+v", err, routed)
	}
	if routed = must(bob.Exchange(ctx, routed, false)); routed.State != "accepted" {
		t.Fatalf("route send: %+v", routed)
	}
	if _, err = bob.PrepareAdapterSend(ctx, auth, AdapterSend{Destination: "carol", RequestID: "request_" + strings.Repeat("2", 32), Content: "unbound"}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not bound to a person") {
		t.Fatalf("route to an unbound host: %v", err)
	}

	// Blocks override the policy, and grants, at once.
	grant := must(alice.CreateGrant(ctx, CreateGrant{RequesterHostID: bob.Identity().ID, TargetAgentID: triage.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour)), MaxMessageBytes: 100}))
	sendGrant := func() string {
		out := must(bob.PrepareOutbound(ctx, SendMessage{PeerHostID: alice.Identity().ID, MessageRequest: MessageRequest{GrantID: ref(grant.ID), TargetAgentID: triage.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "grant"}}))
		return must(bob.Exchange(ctx, out, false)).State
	}
	for _, block := range []BlockAccess{{Person: "quinn"}, {Host: bob.Identity().ID}} {
		b, err := alice.Block(ctx, block)
		if err != nil {
			t.Fatal(err)
		}
		if again := must(alice.Block(ctx, block)); again != b {
			t.Fatalf("repeat block: %+v %+v", again, b)
		}
		expect(bob, reviewer.ID, "blocked", "rejected")
		if state := sendGrant(); state != "rejected" {
			t.Fatalf("blocked grant send: %s", state)
		}
		if blocks := must(alice.AccessBlocks(ctx)); len(blocks) != 1 || blocks[0] != b {
			t.Fatalf("blocks: %+v", blocks)
		}
		if _, err = alice.Unblock(ctx, block); err != nil {
			t.Fatal(err)
		}
		if _, err = alice.Unblock(ctx, block); !errors.Is(err, ErrNotFound) {
			t.Fatalf("repeat unblock: %v", err)
		}
		expect(bob, reviewer.ID, "unblocked", "accepted")
	}
	if countEvents(t, alice, "access.blocked", quinnID) != 1 || countEvents(t, alice, "access.unblocked", bob.Identity().ID) != 1 {
		t.Fatal("block events")
	}
	if _, err = alice.Block(ctx, BlockAccess{Person: "quinn", Host: bob.Identity().ID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("block of both: %v", err)
	}

	// A sender ahead of the receiver gets 503 until it syncs.
	ahead := must(bob.PrepareOutbound(ctx, SendMessage{PeerHostID: alice.Identity().ID, MessageRequest: MessageRequest{Policy: &PolicyCitation{patID, 2}, TargetAgentID: reviewer.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "ahead"}}))
	if ahead = must(bob.Exchange(ctx, ahead, false)); ahead.State != "unknown" || !strings.Contains(*ahead.Error, "HTTP 503") {
		t.Fatalf("cited version above the receiver's: %+v", ahead)
	}
	// Exactly one authorization: both, or an empty grant ID, is invalid.
	for _, grantID := range []string{grant.ID, ""} {
		both := MessageRequest{RequestID: "request_" + strings.Repeat("3", 32), GrantID: ref(grantID), Policy: &PolicyCitation{patID, 1}, TargetAgentID: reviewer.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "both"}
		if _, err = bob.PrepareOutbound(ctx, SendMessage{PeerHostID: alice.Identity().ID, MessageRequest: both}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("grant %q and policy: %v", grantID, err)
		}
		if _, err = alice.AcceptMessage(ctx, bob.Identity().ID, both); !errors.Is(err, ErrInvalid) {
			t.Fatalf("peer request with grant %q and policy: %v", grantID, err)
		}
	}
	if _, err = bob.PrepareOutbound(ctx, SendMessage{PeerHostID: alice.Identity().ID, MessageRequest: MessageRequest{GrantID: ref(""), TargetAgentID: reviewer.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "empty"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty grant ID: %v", err)
	}
	// Outbound records show a missing grant as null; the wire omits it.
	var record struct{ Request map[string]any }
	if err = json.Unmarshal(rawJSON(t, ahead), &record); err != nil {
		t.Fatal(err)
	}
	if grantID, ok := record.Request["grant_id"]; !ok || grantID != nil {
		t.Fatalf("outbound record: %v", record)
	}

	// Groups and the network principal; a narrowed policy rechecks stored
	// messages as final denials.
	if _, err = alice.SetGroup(ctx, id, SetGroup{Name: "backend", Members: []string{"quinn"}}); err != nil {
		t.Fatal(err)
	}
	v2 := sign(2, time.Now(), week, rule("reviewer", 100, false, "group:backend"), rule("triage", 50, true, membership.PrincipalNetwork))
	if _, err = bob.SubmitPolicy(ctx, id, v2); err != nil {
		t.Fatal(err)
	}
	mustSync(t, alice, id)
	mustSync(t, carol, id)
	held := expect(bob, reviewer.ID, "group", "accepted")
	expect(carol, triage.ID, "network", "accepted")
	expect(carol, reviewer.ID, "group only", "rejected")
	// The receiver evaluates its newest version, whatever the sender cites.
	if ahead = must(bob.Exchange(ctx, ahead, false)); ahead.State != "accepted" {
		t.Fatalf("retried citation after sync: %+v", ahead)
	}
	recheck := func() error {
		tx := must(alice.db.BeginTx(ctx, nil))
		defer tx.Rollback()
		_, err := alice.messageBounds(ctx, tx, bob.Identity().ID, held.Request, false)
		return err
	}
	if err = recheck(); err != nil {
		t.Fatalf("recheck under v2: %v", err)
	}
	v3 := sign(3, time.Now(), week, rule("triage", 50, true, membership.PrincipalNetwork))
	if _, err = alice.SubmitPolicy(ctx, id, v3); err != nil {
		t.Fatal(err)
	}
	if err = recheck(); !errors.Is(err, ErrForbidden) {
		t.Fatalf("recheck under a narrowed policy: %v", err)
	}

	// allow_disconnected keeps a rule usable while the receiver is stale.
	n, _ := alice.Network(ctx, id)
	stale := timestamp(time.Now().Add(-time.Hour))
	n.LastSyncAt = &stale
	if _, err = alice.db.ExecContext(ctx, "UPDATE networks SET record = ? WHERE id = ?", string(rawJSON(t, n)), id); err != nil {
		t.Fatal(err)
	}
	expect(carol, triage.ID, "disconnected", "accepted")

	// A coordinator serving an older version cannot roll the policy back.
	if _, err = coordDB(t, network).Exec("UPDATE statements SET statement = ? WHERE network_id = ? AND kind = 'policy'", string(rawJSON(t, v1)), id); err != nil {
		t.Fatal(err)
	}
	mustSync(t, alice, id)
	if view := must(alice.Policy(ctx, id, "")); view.Version != 3 {
		t.Fatalf("rolled back to %d", view.Version)
	}

	// Renewal through the ssh-agent once less than a quarter remains.
	if _, err = coordDB(t, network).Exec("UPDATE statements SET statement = ? WHERE network_id = ? AND kind = 'policy'", string(rawJSON(t, v3)), id); err != nil {
		t.Fatal(err)
	}
	old := sign(4, time.Now().Add(-6*24*time.Hour), week, v3.Rules...)
	if _, err = alice.SubmitPolicy(ctx, id, old); err != nil {
		t.Fatal(err)
	}
	if view := must(alice.Policy(ctx, id, "")); !view.ExpiresSoon {
		t.Fatalf("expires_soon: %+v", view)
	}
	alice.RenewPolicies(ctx, t.Logf) // no agent configured: nothing happens
	alice.ConfigurePersonAgent(serveAgent(t, quinn))
	alice.RenewPolicies(ctx, t.Logf) // the agent lacks pat's key
	if view := must(alice.Policy(ctx, id, "")); view.Version != 4 {
		t.Fatalf("renewed without the owner's key: %+v", view)
	}
	alice.ConfigurePersonAgent(serveAgent(t, pat))
	alice.RenewPolicies(ctx, t.Logf)
	renewed := must(alice.Policy(ctx, id, ""))
	if renewed.Version != 5 || renewed.ExpiresSoon || len(renewed.Rules) != 1 {
		t.Fatalf("renewal: %+v", renewed)
	}
	if issued, _ := membership.ParseTime(renewed.IssuedAt); time.Since(issued) > time.Minute {
		t.Fatalf("renewal issued at %s", renewed.IssuedAt)
	}
	// A host that signs the same version concurrently stores its own first;
	// the coordinator keeps the one it accepted first and answers 409, which
	// completes the delivery. Seeing both, a host keeps the lower hash.
	race := must(membership.Renewal(pat, old, time.Now().Add(time.Second)))
	if _, err = carol.SubmitPolicy(ctx, id, race); err != nil {
		t.Fatalf("racing renewal: %v", err)
	}
	var state string
	if err = carol.db.QueryRowContext(ctx, "SELECT json_extract(record, '$.state') FROM policy_deliveries WHERE network_id = ? AND person_id = ? AND target = 'coordinator'", id, patID).Scan(&state); err != nil || state != "delivered" {
		t.Fatalf("coordinator delivery after 409: %q %v", state, err)
	}
	mustSync(t, carol, id)
	winner := renewed.Policy
	if membership.PolicyHash(race) < membership.PolicyHash(winner) {
		winner = race
	}
	if view := must(carol.Policy(ctx, id, patID)); view.Signature != winner.Signature {
		t.Fatalf("carol kept %d %s, want the lower hash", view.Version, view.IssuedAt)
	}
	// The equal-version loser is refused locally.
	loser := race
	if winner.Signature == race.Signature {
		loser = renewed.Policy
	}
	if _, err = carol.SubmitPolicy(ctx, id, loser); !errors.Is(err, ErrConflict) {
		t.Fatalf("equal-version loser: %v", err)
	}
}

func TestPolicyViewJSON(t *testing.T) {
	p := must(membership.SignPolicy(personKey(t), "net_"+strings.Repeat("0", 64), 1, time.Now(), 24*time.Hour, []membership.PolicyRule{rule("a", 1, false, membership.PrincipalNetwork)}))
	var fields map[string]any
	if err := json.Unmarshal(rawJSON(t, PolicyView{Policy: p, ExpiresSoon: true}), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 8 || fields["expires_soon"] != true || fields["version"] != float64(1) {
		t.Fatalf("view: %v", fields)
	}
}

func TestAccessBlocksMigrationToVersion8(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "host")
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	// A v7 database gains the block list; a newer version is refused.
	if _, err = s.db.ExecContext(ctx, "DROP TABLE access_blocks; "+dropTaskTables+"; PRAGMA user_version = 7"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err = Open(ctx, dir); err != nil {
		t.Fatal(err)
	}
	var version int
	if err = s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 15 {
		t.Fatalf("version %d %v", version, err)
	}
	if blocks, err := s.AccessBlocks(ctx); err != nil || len(blocks) != 0 {
		t.Fatalf("blocks: %v %v", blocks, err)
	}
	if _, err = s.db.ExecContext(ctx, "PRAGMA user_version = 16"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err = Open(ctx, dir); err == nil || !strings.Contains(err.Error(), "unsupported host database version") {
		t.Fatalf("version 16 opened: %v", err)
	}
}

func ref(value string) *string { return &value }

func TestSetupRouteGrantIsOptional(t *testing.T) {
	base := `"name":"r","peer_host_id":"h","target_agent_id":"a","expires_at":"t","max_message_bytes":1,"max_messages":1`
	for body, valid := range map[string]bool{
		"{" + base + "}":                      true,
		"{" + base + `,"grant_id":null}`:      true,
		"{" + base + `,"grant_id":"grant_x"}`: true,
		"{" + base + `,"extra":1}`:            false,
		`{"name":null,` + base[9:] + "}":      false,
		"{" + base + `,"grant_id":"g","x":1}`: false,
	} {
		var r SetupRoute
		if err := json.Unmarshal([]byte(body), &r); (err == nil) != valid {
			t.Errorf("%s: %v", body, err)
		}
	}
}
