package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

func TestOriginJSONIsStrict(t *testing.T) {
	agent, session := "agent_"+strings.Repeat("a", 32), "session_"+strings.Repeat("b", 32)
	base := `"request_id":"request_` + strings.Repeat("1", 32) + `","grant_id":"grant_` + strings.Repeat("2", 32) + `","target_agent_id":"agent_` + strings.Repeat("3", 32) + `","deadline":"2099-01-01T00:00:00Z","content":"hi"`
	for origin, valid := range map[string]bool{
		`{"agent_id":"` + agent + `"}`:                                true,
		`{"agent_id":"` + agent + `","session_id":"` + session + `"}`: true,
		`{"session_id":"` + session + `"}`:                            false,
		`{"agent_id":null}`:                                           false,
		`{"agent_id":"` + agent + `","session_id":null}`:              false,
		`{"agent_id":"` + agent + `","extra":1}`:                      false,
		`{"agent_id":"agent_bad"}`:                                    false,
		`{"agent_id":"` + agent + `","session_id":"session_bad"}`:     false,
		`{"agent_id":"` + agent + `","session_id":""}`:                false,
		`{"agent_id":"` + session + `"}`:                              false,
		`{"agent_id":5}`:                                              false,
		`{}`:                                                          false,
		`[]`:                                                          false,
		`"` + agent + `"`:                                             false,
	} {
		var r MessageRequest
		err := json.Unmarshal([]byte(`{`+base+`,"origin":`+origin+`}`), &r)
		if err == nil {
			err = validateMessage(r)
		}
		if (err == nil) != valid {
			t.Errorf("origin %s: %v", origin, err)
		}
	}
	// An absent session is omitted, never null or empty.
	data := rawJSON(t, MessageRequest{Origin: &Origin{AgentID: agent}})
	if !strings.Contains(string(data), `"origin":{"agent_id":"`+agent+`"}`) {
		t.Fatalf("encoded: %s", data)
	}
	if strings.Contains(string(rawJSON(t, MessageRequest{})), "origin") {
		t.Fatal("absent origin is encoded")
	}
}

func TestOriginIsPartOfTheRequest(t *testing.T) {
	a, b := "agent_"+strings.Repeat("a", 32), "agent_"+strings.Repeat("b", 32)
	s := "session_" + strings.Repeat("c", 32)
	base := MessageRequest{RequestID: "request_1", Content: "x"}
	with := func(o *Origin) MessageRequest { r := base; r.Origin = o; return r }
	if !with(&Origin{AgentID: a, SessionID: s}).same(with(&Origin{AgentID: a, SessionID: s})) || !base.same(base) {
		t.Fatal("identical requests differ")
	}
	for _, pair := range [][2]*Origin{{nil, {AgentID: a}}, {{AgentID: a}, {AgentID: b}}, {{AgentID: a}, {AgentID: a, SessionID: s}}} {
		if with(pair[0]).same(with(pair[1])) || with(pair[1]).same(with(pair[0])) {
			t.Fatalf("origins %+v and %+v compare equal", pair[0], pair[1])
		}
	}
}

func TestReplyOriginMustNameTheReplyingSession(t *testing.T) {
	agent, session := "agent_"+strings.Repeat("a", 32), "session_"+strings.Repeat("b", 32)
	m := MessageRequest{RequestID: "request_1", TargetAgentID: agent}
	r := Reply{SenderHostID: "s", ReceiverHostID: "r", RequestID: m.RequestID, TargetAgentID: agent, SessionID: session, DeliveryID: "delivery_" + strings.Repeat("c", 32), Content: "ok", RepliedAt: timestamp(time.Now())}
	if !validReply(r, "s", "r", m) {
		t.Fatal("reply without origin refused")
	}
	for origin, valid := range map[Origin]bool{
		{AgentID: agent, SessionID: session}: true,
		{AgentID: agent}:                     false,
		{AgentID: "agent_" + strings.Repeat("d", 32), SessionID: session}: false,
		{AgentID: agent, SessionID: "session_" + strings.Repeat("e", 32)}: false,
	} {
		r.Origin = &origin
		if validReply(r, "s", "r", m) != valid {
			t.Errorf("reply origin %+v: want valid=%v", origin, valid)
		}
	}
}

// localCall sends a request to the owner-local administration API.
func localCall(t *testing.T, s *Store, method, path string, body any) (int, []byte) {
	t.Helper()
	var data []byte
	switch v := body.(type) {
	case string:
		data = []byte(v)
	case nil:
	default:
		data = rawJSON(t, v)
	}
	w := httptest.NewRecorder()
	Handler(s).ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(data)))
	return w.Code, w.Body.Bytes()
}

func TestAgentOriginAndRequesterAgentGrants(t *testing.T) {
	ctx := context.Background()
	receiverHost := startQUICHost(t, filepath.Join(t.TempDir(), "receiver"), "127.0.0.1:0")
	senderHost := startQUICHost(t, filepath.Join(t.TempDir(), "sender"), "127.0.0.1:0")
	receiver, sender := receiverHost.store, senderHost.store
	must(receiver.AddPeer(ctx, senderHost.peer()))
	must(sender.AddPeer(ctx, receiverHost.peer()))

	target := must(receiver.RegisterAgent(ctx, RegisterAgent{Name: "target", Owner: "pat"}))
	targetSession := must(receiver.AttachSession(ctx, AttachSession{AgentID: target.ID, Integration: "test"}))
	credential := must(receiver.CreateAdapter(ctx, CreateAdapter{SessionID: targetSession.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour))}))
	auth := AdapterAuth{Token: credential.Token, Instance: "instance_" + strings.Repeat("a", 64)}
	must(receiver.ConnectAdapter(ctx, auth.Token, auth.Instance, credential.Adapter.ID, targetSession.ID))
	must(receiver.ReadyAdapter(ctx, auth, strings.Repeat("0", 32)))

	author := must(sender.RegisterAgent(ctx, RegisterAgent{Name: "author", Owner: "quinn"}))
	other := must(sender.RegisterAgent(ctx, RegisterAgent{Name: "other", Owner: "quinn"}))
	authorSession := must(sender.AttachSession(ctx, AttachSession{AgentID: author.ID, Integration: "test"}))
	otherSession := must(sender.AttachSession(ctx, AttachSession{AgentID: other.ID, Integration: "test"}))

	// Grant creation validates the requester agent and records it.
	expires := timestamp(time.Now().Add(time.Hour))
	if _, err := receiver.CreateGrant(ctx, CreateGrant{RequesterHostID: sender.Identity().ID, TargetAgentID: target.ID, ExpiresAt: expires, MaxMessageBytes: 100, AllowDisconnected: true, RequesterAgentID: ref("agent_bad")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed requester agent: %v", err)
	}
	if code, body := localCall(t, receiver, "POST", "/v1/grants", map[string]any{"requester_host_id": sender.Identity().ID, "target_agent_id": target.ID, "expires_at": expires, "max_message_bytes": 100, "allow_disconnected": true, "requester_agent_id": "agent_x"}); code != http.StatusBadRequest {
		t.Fatalf("malformed requester agent over the API: %d %s", code, body)
	}
	open := must(receiver.CreateGrant(ctx, CreateGrant{RequesterHostID: sender.Identity().ID, TargetAgentID: target.ID, ExpiresAt: expires, MaxMessageBytes: 100, AllowDisconnected: true}))
	if !strings.Contains(string(rawJSON(t, open)), `"requester_agent_id":null`) {
		t.Fatalf("grant without a requester agent: %s", rawJSON(t, open))
	}
	code, body := localCall(t, receiver, "POST", "/v1/grants", map[string]any{"requester_host_id": sender.Identity().ID, "target_agent_id": target.ID, "expires_at": expires, "max_message_bytes": 100, "allow_disconnected": true, "requester_agent_id": author.ID})
	var scoped Grant
	if code != http.StatusCreated && code != http.StatusOK || json.Unmarshal(body, &scoped) != nil || scoped.RequesterAgentID == nil || *scoped.RequesterAgentID != author.ID {
		t.Fatalf("grant with a requester agent: %d %s", code, body)
	}

	deadline := timestamp(time.Now().Add(time.Minute))
	send := func(grant string, origin any) (int, []byte) {
		t.Helper()
		m := map[string]any{"peer_host_id": receiver.Identity().ID, "request_id": "", "grant_id": grant, "target_agent_id": target.ID, "deadline": deadline, "content": "hello"}
		if origin != nil {
			m["origin"] = origin
		}
		return localCall(t, sender, "POST", "/v1/outbound", m)
	}
	outboundCount := func() int {
		var n int
		if err := sender.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbound_messages").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The owner may assert only a registered local agent and one of its own
	// sessions; anything else is refused before persisting.
	for origin, want := range map[string]int{
		`{"agent_id":"agent_` + strings.Repeat("9", 32) + `"}`:                                    http.StatusNotFound,
		`{"agent_id":"` + author.ID + `","session_id":"session_` + strings.Repeat("9", 32) + `"}`: http.StatusNotFound,
		`{"agent_id":"` + author.ID + `","session_id":"` + otherSession.ID + `"}`:                 http.StatusNotFound,
		`{"agent_id":"bad"}`:                            http.StatusBadRequest,
		`{"agent_id":"` + author.ID + `","extra":true}`: http.StatusBadRequest,
		`null`: http.StatusBadRequest,
	} {
		if code, body := send(scoped.ID, json.RawMessage(origin)); code != want {
			t.Errorf("origin %s: want %d, got %d %s", origin, want, code, body)
		}
	}
	if n := outboundCount(); n != 0 {
		t.Fatalf("refused sends persisted %d records", n)
	}

	// An origin round-trips through the outbound record, the wire, and the
	// received message.
	origin := Origin{AgentID: author.ID, SessionID: authorSession.ID}
	code, body = send(scoped.ID, origin)
	var out OutboundMessage
	if code != http.StatusOK && code != http.StatusCreated || json.Unmarshal(body, &out) != nil || out.Request.Origin == nil || *out.Request.Origin != origin {
		t.Fatalf("send with origin: %d %s", code, body)
	}
	if out = must(sender.Exchange(ctx, out, false)); out.State != "accepted" {
		t.Fatalf("scoped grant with its agent: %+v", out)
	}
	received := must(receiver.Messages(ctx, 0, 10))
	if len(received) != 1 || received[0].Request.Origin == nil || *received[0].Request.Origin != origin {
		t.Fatalf("received: %+v", received)
	}
	// The same request ID with a changed origin conflicts, locally and on the
	// wire; an identical retry returns the original receipt.
	changed := out.Request
	changed.Origin = &Origin{AgentID: other.ID}
	if _, err := sender.PrepareOutbound(ctx, SendMessage{PeerHostID: receiver.Identity().ID, MessageRequest: changed}); !errors.Is(err, ErrConflict) {
		t.Fatalf("local resend with a changed origin: %v", err)
	}
	changed.Origin = &Origin{AgentID: author.ID}
	if _, err := receiver.AcceptMessage(ctx, sender.Identity().ID, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("wire retry with a changed session: %v", err)
	}
	if receipt := must(receiver.AcceptMessage(ctx, sender.Identity().ID, out.Request)); receipt.RequestID != out.Request.RequestID {
		t.Fatalf("identical retry: %+v", receipt)
	}

	// A requester-agent grant refuses another agent, and no origin, at once.
	for _, o := range []any{Origin{AgentID: other.ID, SessionID: otherSession.ID}, nil} {
		code, body := send(scoped.ID, o)
		if code != http.StatusOK && code != http.StatusCreated || json.Unmarshal(body, &out) != nil {
			t.Fatalf("send: %d %s", code, body)
		}
		if out = must(sender.Exchange(ctx, out, false)); out.State != "rejected" || !strings.Contains(*out.Error, "403") {
			t.Fatalf("scoped grant with origin %+v: %+v", o, out)
		}
	}
	// An unscoped grant accepts any origin, or none.
	code, body = send(open.ID, nil)
	if json.Unmarshal(body, &out) != nil || must(sender.Exchange(ctx, out, false)).State != "accepted" {
		t.Fatalf("open grant without origin: %d %s", code, body)
	}

	// Handoff carries the origin and, for an unbound sender, null persons.
	handoff := must(receiver.NextDelivery(ctx, auth))
	if handoff == nil || handoff.Request.Origin == nil || *handoff.Request.Origin != origin || handoff.SenderPersonID != nil || handoff.SenderPerson != nil {
		t.Fatalf("handoff: %+v", handoff)
	}
	var fields map[string]any
	if err := json.Unmarshal(rawJSON(t, handoff), &fields); err != nil {
		t.Fatal(err)
	}
	if v, ok := fields["sender_person_id"]; !ok || v != nil {
		t.Fatalf("handoff fields: %v", fields)
	}
	if v, ok := fields["sender_person"]; !ok || v != nil {
		t.Fatalf("handoff fields: %v", fields)
	}

	// Reply rechecks the requester agent.
	setRequester := func(agent string) {
		t.Helper()
		if _, err := receiver.db.ExecContext(ctx, "UPDATE grants SET record = json_set(record, '$.requester_agent_id', ?) WHERE id = ?", agent, scoped.ID); err != nil {
			t.Fatal(err)
		}
	}
	setRequester(other.ID)
	if _, err := receiver.Reply(ctx, auth, handoff.Delivery.ID, "done"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reply after the requester agent changed: %v", err)
	}
	setRequester(author.ID)
	reply := must(receiver.Reply(ctx, auth, handoff.Delivery.ID, "done"))
	if reply.Origin == nil || *reply.Origin != (Origin{AgentID: target.ID, SessionID: targetSession.ID}) {
		t.Fatalf("reply origin: %+v", reply)
	}
	fetched := must(sender.FetchReply(ctx, receiver.Identity().ID, handoff.Request.RequestID))
	if fetched.State != "replied" || fetched.Reply.Origin == nil || *fetched.Reply.Origin != *reply.Origin {
		t.Fatalf("fetched reply: %+v", fetched)
	}

	// The next message, from the open grant, has no origin.
	if next := must(receiver.NextDelivery(ctx, auth)); next == nil || next.Request.Origin != nil {
		t.Fatalf("handoff without origin: %+v", next)
	}

	// Handoff rechecks the requester agent: a narrowed grant blocks delivery.
	code, body = send(scoped.ID, origin)
	if json.Unmarshal(body, &out) != nil || must(sender.Exchange(ctx, out, false)).State != "accepted" {
		t.Fatalf("second scoped send: %d %s", code, body)
	}
	setRequester(other.ID)
	if next := must(receiver.NextDelivery(ctx, auth)); next != nil {
		t.Fatalf("handoff after the requester agent changed: %+v", next)
	}
	records := must(receiver.Deliveries(ctx, 0, 10))
	if last := records[len(records)-1]; last.Delivery.RequestID != out.Request.RequestID || last.Delivery.State != "blocked" {
		t.Fatalf("delivery records: %+v", records)
	}
}

func TestAgentPrincipal(t *testing.T) {
	ctx := context.Background()
	network := startCoordinator(t)
	alice, bob, carol := startPeerHost(t, "alice"), startPeerHost(t, "bob"), startPeerHost(t, "carol")
	created := must(alice.CreateNetwork(ctx, CreateNetwork{Name: "team", Member: "alice", CoordinatorAddress: network.address, CoordinatorPublicKey: network.coord.Identity().PublicKey}))
	id := created.ID
	for _, s := range []*Store{bob, carol} {
		invite := must(alice.CreateInvite(ctx, id, CreateInvite{Member: "m", ExpiresAt: timestamp(time.Now().Add(time.Hour)), HostOnly: true}))
		must(s.JoinNetwork(ctx, JoinNetwork{Token: invite.Token}))
	}
	pat, quinn := personKey(t), personKey(t)
	quinnID := membership.PersonID(quinn.PublicKey())
	for label, key := range map[string]membership.KeySigner{"pat": pat, "quinn": quinn} {
		must(alice.AdmitPerson(ctx, id, AdmitPerson{PersonPublicKey: membership.EncodeKey(key.PublicKey()), Member: label}))
	}
	bindTo(t, alice, id, pat)
	bindTo(t, bob, id, quinn)
	reviewer := must(alice.RegisterAgent(ctx, RegisterAgent{Name: "reviewer", Owner: "pat"}))
	author := must(bob.RegisterAgent(ctx, RegisterAgent{Name: "author", Owner: "quinn"}))
	other := must(bob.RegisterAgent(ctx, RegisterAgent{Name: "other", Owner: "quinn"}))
	principal := "agent:" + bob.Identity().ID + "/" + author.ID
	policy := must(membership.SignPolicy(pat, id, 1, time.Now(), 7*24*time.Hour, []membership.PolicyRule{rule("reviewer", 100, false, principal)}))
	must(alice.SubmitPolicy(ctx, id, policy))
	for _, s := range []*Store{alice, bob, carol} {
		mustSync(t, s, id)
	}

	expect := func(from *Store, origin *Origin, state string) OutboundMessage {
		t.Helper()
		out, err := from.PrepareOutbound(ctx, SendMessage{PeerHostID: alice.Identity().ID, MessageRequest: MessageRequest{TargetAgentID: reviewer.ID, Deadline: timestamp(time.Now().Add(time.Minute)), Content: "hi", Origin: origin}})
		if err == nil {
			out, err = from.Exchange(ctx, out, false)
		}
		if err != nil || out.State != state {
			t.Fatalf("send from %+v: want %s, got %v %+v", origin, state, err, out)
		}
		return out
	}
	// Only that host's asserted agent matches; another host asserting the
	// same agent ID does not.
	expect(bob, &Origin{AgentID: author.ID}, "accepted")
	expect(bob, nil, "rejected")
	expect(bob, &Origin{AgentID: other.ID}, "rejected")
	expect(carol, &Origin{AgentID: author.ID}, "rejected")

	// Handoff names the sender's person and its label.
	session := must(alice.AttachSession(ctx, AttachSession{AgentID: reviewer.ID, Integration: "test"}))
	credential := must(alice.CreateAdapter(ctx, CreateAdapter{SessionID: session.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour))}))
	auth := AdapterAuth{Token: credential.Token, Instance: "instance_" + strings.Repeat("b", 64)}
	must(alice.ConnectAdapter(ctx, auth.Token, auth.Instance, credential.Adapter.ID, session.ID))
	must(alice.ReadyAdapter(ctx, auth, strings.Repeat("0", 32)))
	handoff := must(alice.NextDelivery(ctx, auth))
	if handoff == nil || handoff.SenderPersonID == nil || *handoff.SenderPersonID != quinnID || handoff.SenderPerson == nil || *handoff.SenderPerson != "quinn" || handoff.Request.Origin.AgentID != author.ID {
		t.Fatalf("handoff: %+v", handoff)
	}

	// Malformed agent principals are refused.
	for _, bad := range []string{"agent:" + bob.Identity().ID, "agent:" + author.ID + "/" + bob.Identity().ID, "agent:host_x/agent_y", "agent:" + bob.Identity().ID + "/" + author.ID + "/x"} {
		if membership.ValidPrincipal(bad) {
			t.Errorf("principal %q accepted", bad)
		}
	}
}
