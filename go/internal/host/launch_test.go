package host

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestRenewableCredentialFollowsConnections(t *testing.T) {
	ctx := context.Background()
	s, other := openStore(t), openStore(t)
	must(s.AddPeer(ctx, Peer{ID: other.Identity().ID, PublicKey: other.Identity().PublicKey, Address: "127.0.0.1:9"}))
	agent := must(s.RegisterAgent(ctx, RegisterAgent{Name: "renewing", Owner: "pat"}))
	session := must(s.AttachSession(ctx, AttachSession{AgentID: agent.ID, Integration: "test"}))
	credential := must(s.CreateAdapter(ctx, CreateAdapter{SessionID: session.ID}))
	if !credential.Adapter.Renewable {
		t.Fatal("a credential without expires_at is not renewable")
	}
	if exp, _ := parseTime(credential.Adapter.ExpiresAt); exp.Sub(time.Now()) < 23*time.Hour {
		t.Fatalf("renewable expiry %s", credential.Adapter.ExpiresAt)
	}
	route := CreateOutboundRoute{AdapterID: credential.Adapter.ID, Name: "follow", PeerHostID: other.Identity().ID, TargetAgentID: agent.ID, MaxMessageBytes: 10, MaxMessages: 1}
	follower := must(s.CreateOutboundRoute(ctx, route))
	if !follower.FollowsCredential || follower.ExpiresAt != credential.Adapter.ExpiresAt {
		t.Fatalf("route does not follow its credential: %+v", follower)
	}
	route.Name, route.ExpiresAt = "pinned", timestamp(time.Now().Add(time.Hour))
	pinned := must(s.CreateOutboundRoute(ctx, route))

	auth := AdapterAuth{Token: credential.Token, Instance: "instance_" + "11111111111111111111111111111111" + "11111111111111111111111111111111"}
	connect := func() Adapter {
		t.Helper()
		must(s.ConnectAdapter(ctx, auth.Token, auth.Instance, credential.Adapter.ID, session.ID))
		return must(s.Adapter(ctx, credential.Adapter.ID))
	}
	renewals := func() int {
		t.Helper()
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE kind = 'adapter.renewed' AND subject_id = ?`, credential.Adapter.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Within a minute of issue, a connection gains too little to renew.
	if a := connect(); a.ExpiresAt != credential.Adapter.ExpiresAt || renewals() != 0 {
		t.Fatalf("renewed too early: %+v", a)
	}
	// Age the credential and its following route by two hours.
	aged := timestamp(time.Now().Add(22 * time.Hour))
	if _, err := s.db.Exec(`UPDATE adapter_credentials SET record = json_set(record, '$.expires_at', ?) WHERE id = ?`, aged, credential.Adapter.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE adapter_routes SET record = json_set(record, '$.expires_at', ?) WHERE id = ?`, aged, follower.ID); err != nil {
		t.Fatal(err)
	}
	renewed := connect()
	if exp, _ := parseTime(renewed.ExpiresAt); exp.Sub(time.Now()) < 23*time.Hour || renewals() != 1 {
		t.Fatalf("not renewed: %+v, %d events", renewed, renewals())
	}
	routes := must(s.OutboundRoutes(ctx, credential.Adapter.ID))
	for _, r := range routes {
		if r.ID == follower.ID && r.ExpiresAt != renewed.ExpiresAt {
			t.Fatalf("following route kept %s", r.ExpiresAt)
		}
		if r.ID == pinned.ID && r.ExpiresAt != pinned.ExpiresAt {
			t.Fatalf("explicit route expiry moved to %s", r.ExpiresAt)
		}
	}
	// A second renewal within the hour records no further activity.
	if _, err := s.db.Exec(`UPDATE adapter_credentials SET record = json_set(record, '$.expires_at', ?) WHERE id = ?`, aged, credential.Adapter.ID); err != nil {
		t.Fatal(err)
	}
	if a := connect(); a.ExpiresAt == aged || renewals() != 1 {
		t.Fatalf("second renewal: %+v, %d events", a, renewals())
	}
	// An expired renewable credential stays expired.
	past := timestamp(time.Now().Add(-time.Minute))
	if _, err := s.db.Exec(`UPDATE adapter_credentials SET record = json_set(record, '$.expires_at', ?) WHERE id = ?`, past, credential.Adapter.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConnectAdapter(ctx, auth.Token, auth.Instance, credential.Adapter.ID, session.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired credential connected: %v", err)
	}
	if a := must(s.Adapter(ctx, credential.Adapter.ID)); a.ExpiresAt != past {
		t.Fatalf("expired credential renewed to %s", a.ExpiresAt)
	}

	// A fixed credential refuses a following route.
	fixedAgent := must(s.RegisterAgent(ctx, RegisterAgent{Name: "fixed", Owner: "pat"}))
	fixedSession := must(s.AttachSession(ctx, AttachSession{AgentID: fixedAgent.ID, Integration: "test"}))
	fixed := must(s.CreateAdapter(ctx, CreateAdapter{SessionID: fixedSession.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour))}))
	if fixed.Adapter.Renewable {
		t.Fatal("a credential with expires_at is renewable")
	}
	route = CreateOutboundRoute{AdapterID: fixed.Adapter.ID, Name: "follow", PeerHostID: other.Identity().ID, TargetAgentID: agent.ID, MaxMessageBytes: 10, MaxMessages: 1}
	if _, err := s.CreateOutboundRoute(ctx, route); !errors.Is(err, ErrInvalid) {
		t.Fatalf("fixed credential accepted a following route: %v", err)
	}
}

func TestStatusAttention(t *testing.T) {
	ctx := context.Background()
	s := openStore(t)
	if err := s.ConfigureArtifacts(100); err != nil {
		t.Fatal(err)
	}
	st := must(s.Status(ctx))
	if st.HostID != s.Identity().ID || len(st.Attention) != 0 || len(st.Networks) != 0 || len(st.Agents) != 0 {
		t.Fatalf("fresh status: %+v", st)
	}
	agent := must(s.RegisterAgent(ctx, RegisterAgent{Name: "b", Owner: "pat"}))
	session := must(s.AttachSession(ctx, AttachSession{AgentID: agent.ID, Integration: "test"}))
	fixed := must(s.CreateAdapter(ctx, CreateAdapter{SessionID: session.ID, ExpiresAt: timestamp(time.Now().Add(time.Hour))}))
	idle := must(s.RegisterAgent(ctx, RegisterAgent{Name: "a", Owner: "pat"}))
	bare := must(s.AttachSession(ctx, AttachSession{AgentID: idle.ID, Integration: "test"}))
	if _, err := s.UploadArtifact(ctx, "large", "application/octet-stream", bytes.NewReader(make([]byte, 95))); err != nil {
		t.Fatal(err)
	}
	st = must(s.Status(ctx))
	if len(st.Attention) != 2 || st.Attention[0].Kind != "credential_expiring" || st.Attention[0].Subject != fixed.Adapter.ID || st.Attention[1].Kind != "artifact_quota" || st.Attention[1].Command != "peerspan artifact prune" {
		t.Fatalf("attention: %+v", st.Attention)
	}
	if len(st.Agents) != 2 || st.Agents[0].ID != idle.ID || st.Agents[0].Sessions[0].ID != bare.ID || st.Agents[0].Sessions[0].AdapterID != nil {
		t.Fatalf("agents: %+v", st.Agents)
	}
	view := st.Agents[1].Sessions[0]
	if *view.AdapterID != fixed.Adapter.ID || *view.Connection != "registered" || view.Renewable {
		t.Fatalf("session: %+v", view)
	}
}
