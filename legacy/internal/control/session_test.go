package control

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime"
	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/session"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func TestSessionExchange(t *testing.T) {
	svc := testService(t)
	opened := mustCapsule(t, svc, "mkdir -p logs && printf fail > logs/failure.txt", "share")
	joined := mustCapsule(t, svc, "")

	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: opened.ID,
		Task:      "sdk fails in staging",
		Allow:     []string{"logs/failure.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != session.StatusPending {
		t.Fatalf("status = %q", sess.Status)
	}

	sess, err = svc.AcceptSession(sess.ID, joined.ID, []string{"notes/diag.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	joinedMember, ok := sess.Member(joined.ID)
	if sess.Status != session.StatusActive || !ok || joinedMember.Role != session.RoleJoined {
		t.Fatalf("accepted = %+v", sess)
	}

	if _, err := svc.MessageSession(sess.ID, opened.ID, "failure is attached"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MessageSession(sess.ID, "cap-outsider", "hello"); err == nil {
		t.Fatal("expected outsider to be refused")
	}

	shared, err := svc.ShareSession(sess.ID, opened.ID, "logs/failure.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(shared.Artifacts) != 1 || shared.Artifacts[0].SHA256 == "" {
		t.Fatalf("artifacts = %+v", shared.Artifacts)
	}
	body, err := os.ReadFile(filepath.Join(svc.Store.SessionDir(sess.ID), filepath.FromSlash(shared.Artifacts[0].SavedAs)))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "fail" {
		t.Fatalf("artifact = %q", body)
	}
	if _, err := svc.ShareSession(sess.ID, opened.ID, "logs/other.txt"); err == nil {
		t.Fatal("expected a path outside the allowlist to be refused")
	}

	exported, err := svc.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.Transcript) != 1 || exported.Transcript[0].Text != "failure is attached" {
		t.Fatalf("transcript = %+v", exported.Transcript)
	}

	capsules, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(capsules) != 2 {
		t.Fatalf("capsule list = %d", len(capsules))
	}
}

func TestSessionRevokeAndExpiry(t *testing.T) {
	svc := testService(t)
	opened := mustCapsule(t, svc, "")
	joined := mustCapsule(t, svc, "")
	sess, err := svc.CreateSession(CreateSessionRequest{CapsuleID: opened.ID, Task: "issue", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, joined.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MessageSession(sess.ID, opened.ID, "too late"); err == nil {
		t.Fatal("expected a revoked session to refuse messages")
	}

	svc.Now = func() time.Time { return time.Now().UTC() }
	expiring, err := svc.CreateSession(CreateSessionRequest{CapsuleID: opened.ID, Task: "expires", TTL: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	svc.Now = func() time.Time { return time.Now().UTC().Add(time.Second) }
	got, err := svc.ExportSession(expiring.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != session.StatusExpired {
		t.Fatalf("status = %q", got.Status)
	}
	if got.EndedAt == nil {
		t.Fatal("expected an end time on the expired session")
	}
}

func TestEvidenceIncludesCommandsDuringSession(t *testing.T) {
	svc := testService(t)
	opened := mustCapsule(t, svc, "", "exec")
	if _, err := svc.Exec(context.Background(), opened.ID, []string{"echo", "before"}); err != nil {
		t.Fatal(err)
	}
	joined := mustCapsule(t, svc, "")
	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: opened.ID,
		Task:      "evidence",
		AllowExec: []string{"echo during"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, joined.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(context.Background(), opened.ID, []string{"echo", "during"}); err != nil {
		t.Fatal(err)
	}
	evidence, err := svc.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Commands) != 1 || evidence.Commands[0].Argv[1] != "during" {
		t.Fatalf("commands = %+v", evidence.Commands)
	}
	if evidence.Participants[0].Capabilities[0] != "exec" {
		t.Fatalf("capabilities = %+v", evidence.Participants[0].Capabilities)
	}
	if _, err := os.Stat(filepath.Join(svc.Store.SessionDir(sess.ID), "evidence.json")); err != nil {
		t.Fatal(err)
	}
}

func TestCapabilityGate(t *testing.T) {
	svc := testService(t)
	opened := mustCapsule(t, svc, "printf secret > notes.txt", "share:approval-required", "exec")
	joined := mustCapsule(t, svc, "")
	if _, err := svc.Exec(context.Background(), joined.ID, []string{"echo", "no"}); err == nil {
		t.Fatal("expected exec without a capability to be refused")
	}

	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: opened.ID,
		Task:      "approval",
		Allow:     []string{"notes.txt"},
		AllowExec: []string{"echo ok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, joined.ID, nil, nil); err != nil {
		t.Fatal(err)
	}

	pending, err := svc.ShareSession(sess.ID, opened.ID, "notes.txt")
	if err == nil {
		t.Fatal("expected share to wait for approval")
	}
	if len(pending.Artifacts) != 0 || len(pending.Approvals) != 1 || pending.Approvals[0].Status != session.ApprovalPending {
		t.Fatalf("pending = %+v", pending)
	}
	if _, err := svc.ApproveSession(sess.ID, opened.ID, "share notes.txt"); err != nil {
		t.Fatal(err)
	}
	shared, err := svc.ShareSession(sess.ID, opened.ID, "notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(shared.Artifacts) != 1 {
		t.Fatalf("artifacts = %+v", shared.Artifacts)
	}

	if _, err := svc.Exec(context.Background(), opened.ID, []string{"echo", "nope"}); err == nil {
		t.Fatal("expected a command outside the session allowlist to be refused")
	}
	if _, err := svc.Exec(context.Background(), opened.ID, []string{"echo", "ok"}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionReachability(t *testing.T) {
	svc := testService(t)
	opened := mustCapsule(t, svc, "")
	joined := mustCapsule(t, svc, "")
	other := mustCapsule(t, svc, "")
	sess, err := svc.CreateSession(CreateSessionRequest{CapsuleID: opened.ID, Task: "reach", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sess, err = svc.AcceptSession(sess.ID, joined.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	joinedEP, ok := endpoint(sess.Link, joined.ID)
	openedEP, openedOK := endpoint(sess.Link, opened.ID)
	if !ok || !openedOK || joinedEP.Name != joined.Network.Name {
		t.Fatalf("link = %+v", sess.Link)
	}
	record, err := svc.Inspect(opened.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Network.Endpoints) != 1 || record.Network.Endpoints[0] != openedEP.IP {
		t.Fatalf("endpoints = %+v", record.Network.Endpoints)
	}
	if code, output := ping(t, svc, opened.Runtime.PID, joined.Network.Name); code != 0 {
		t.Fatalf("ping joined name: %s", output)
	}
	if code, _ := ping(t, svc, other.Runtime.PID, openedEP.IP); code == 0 {
		t.Fatal("a capsule outside the session reached the link")
	}

	if _, err := svc.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if code, output := ping(t, svc, opened.Runtime.PID, joined.Network.Name); code == 0 {
		t.Fatalf("still reachable after revoke: %s", output)
	}
	record, err = svc.Inspect(opened.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Network.Endpoints) != 0 {
		t.Fatalf("endpoints after revoke = %+v", record.Network.Endpoints)
	}
	evidence, err := svc.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := endpoint(evidence.Reachability, opened.ID); !ok {
		t.Fatalf("reachability = %+v", evidence.Reachability)
	}

	sess, err = svc.CreateSession(CreateSessionRequest{CapsuleID: opened.ID, Task: "expires", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, joined.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	svc.Now = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	expired, err := svc.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if expired.Status != session.StatusExpired {
		t.Fatalf("status = %q", expired.Status)
	}
	if code, output := ping(t, svc, opened.Runtime.PID, joined.Network.Name); code == 0 {
		t.Fatalf("still reachable after expiry: %s", output)
	}
}

func TestSessionThreePeers(t *testing.T) {
	svc := testService(t)
	opened := mustCapsule(t, svc, "mkdir -p logs && printf a > logs/a.txt", "share", "exec")
	second := mustCapsule(t, svc, "mkdir -p notes && printf b > notes/b.txt", "share", "exec")
	third := mustCapsule(t, svc, "mkdir -p notes && printf c > notes/c.txt", "share", "exec")
	other := mustCapsule(t, svc, "")

	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: opened.ID,
		Task:      "three peers",
		Allow:     []string{"logs/a.txt"},
		AllowExec: []string{"echo from-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err = svc.AcceptSession(sess.ID, second.ID, []string{"notes/b.txt"}, []string{"echo from-b"})
	if err != nil {
		t.Fatal(err)
	}
	sess, err = svc.AcceptSession(sess.ID, third.ID, []string{"notes/c.txt"}, []string{"echo from-c"})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != session.StatusActive || len(sess.Members) != 3 || len(sess.Link.Endpoints) != 3 {
		t.Fatalf("session = %+v", sess)
	}
	if _, err := svc.AcceptSession(sess.ID, third.ID, nil, nil); err == nil {
		t.Fatal("expected a second join by the same capsule to be refused")
	}
	if _, err := svc.MessageSession(sess.ID, third.ID, "joined"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MessageSession(sess.ID, other.ID, "no"); err == nil {
		t.Fatal("expected an outsider to be refused")
	}
	shared, err := svc.ShareSession(sess.ID, third.ID, "notes/c.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(shared.Artifacts) != 1 || shared.Artifacts[0].CapsuleID != third.ID {
		t.Fatalf("artifacts = %+v", shared.Artifacts)
	}
	if _, err := svc.ShareSession(sess.ID, second.ID, "notes/c.txt"); err == nil {
		t.Fatal("expected the second peer's allowlist to refuse the third peer's path")
	}
	if _, err := svc.Exec(context.Background(), third.ID, []string{"echo", "from-b"}); err == nil {
		t.Fatal("expected the third peer's exec allowlist to refuse another peer's command")
	}
	if _, err := svc.Exec(context.Background(), third.ID, []string{"echo", "from-c"}); err != nil {
		t.Fatal(err)
	}

	openedEP, ok := endpoint(sess.Link, opened.ID)
	if !ok {
		t.Fatal("missing opener endpoint")
	}
	for _, peer := range []capsule.Capsule{opened, second, third} {
		for _, target := range []capsule.Capsule{opened, second, third} {
			if peer.ID == target.ID {
				continue
			}
			if code, output := ping(t, svc, peer.Runtime.PID, target.Network.Name); code != 0 {
				t.Fatalf("%s ping %s: %s", peer.ID, target.Network.Name, output)
			}
		}
	}
	if code, _ := ping(t, svc, other.Runtime.PID, openedEP.IP); code == 0 {
		t.Fatal("a capsule outside the session reached the link")
	}

	if _, err := svc.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if code, output := ping(t, svc, opened.Runtime.PID, third.Network.Name); code == 0 {
		t.Fatalf("still reachable after revoke: %s", output)
	}
	evidence, err := svc.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Participants) != 3 || len(evidence.Reachability.Endpoints) != 3 {
		t.Fatalf("evidence peers = %d endpoints = %+v", len(evidence.Participants), evidence.Reachability)
	}
	joined := 0
	for _, p := range evidence.Participants {
		if p.Role == session.RoleJoined {
			joined++
		}
	}
	if joined != 2 {
		t.Fatalf("joined participants = %d", joined)
	}
}

func TestSessionRemotePeer(t *testing.T) {
	const (
		aUnder = "10.188.1.1"
		bUnder = "10.188.1.2"
	)
	addSites(t)

	svcA := testService(t)
	svcA.Underlay = aUnder
	svcA.Runtime = local.Runtime{Netns: "boxa"}
	svcB := testService(t)
	svcB.Underlay = bUnder
	svcB.Runtime = local.Runtime{Netns: "boxb"}
	opened := mustCapsule(t, svcA, "")
	remote := mustCapsule(t, svcB, "")
	other := mustCapsule(t, svcA, "")

	sess, err := svcA.CreateSession(CreateSessionRequest{CapsuleID: opened.ID, Task: "across"})
	if err != nil {
		t.Fatal(err)
	}
	sess, err = svcA.AcceptRemoteSession(sess.ID, remote.ID, nil, nil, remote.Network.Name, remote.Owner, bUnder)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = svcA.RevokeSession(sess.ID)
		_ = svcB.LeaveSession(sess.ID, remote.ID)
	})
	if sess.Link == nil || len(sess.Link.Endpoints) != 2 {
		t.Fatalf("link = %+v", sess.Link)
	}
	if err := svcB.LinkSession(sess.ID, remote.ID, *sess.Link); err != nil {
		t.Fatal(err)
	}
	if _, err := svcA.MessageSession(sess.ID, remote.ID, "from the other machine"); err != nil {
		t.Fatal(err)
	}
	if code, output := ping(t, svcA, opened.Runtime.PID, remote.Network.Name); code != 0 {
		t.Fatalf("ping remote: %s", output)
	}
	if code, output := ping(t, svcB, remote.Runtime.PID, opened.Network.Name); code != 0 {
		t.Fatalf("ping opener: %s", output)
	}
	openedEP, ok := endpoint(sess.Link, opened.ID)
	if !ok {
		t.Fatal("missing opener endpoint")
	}
	if code, _ := ping(t, svcA, other.Runtime.PID, openedEP.IP); code == 0 {
		t.Fatal("a capsule outside the session reached the link")
	}
	evidence, err := svcA.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Participants) != 2 || evidence.Participants[1].Owner != remote.Owner {
		t.Fatalf("participants = %+v", evidence.Participants)
	}
	if _, err := svcA.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if code, output := ping(t, svcA, opened.Runtime.PID, remote.Network.Name); code == 0 {
		t.Fatalf("still reachable after revoke: %s", output)
	}
	if err := svcB.LeaveSession(sess.ID, remote.ID); err != nil {
		t.Fatal(err)
	}
}

func addSites(t *testing.T) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	_ = exec.Command("/usr/sbin/ip", "netns", "delete", "boxa").Run()
	_ = exec.Command("/usr/sbin/ip", "netns", "delete", "boxb").Run()
	run("/usr/sbin/ip", "netns", "add", "boxa")
	run("/usr/sbin/ip", "netns", "add", "boxb")
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "netns", "delete", "boxa").Run()
		_ = exec.Command("/usr/sbin/ip", "netns", "delete", "boxb").Run()
	})
	run("/usr/sbin/ip", "link", "add", "va", "type", "veth", "peer", "name", "vb")
	run("/usr/sbin/ip", "link", "set", "va", "netns", "boxa")
	run("/usr/sbin/ip", "link", "set", "vb", "netns", "boxb")
	run("/usr/sbin/ip", "netns", "exec", "boxa", "/usr/sbin/ip", "link", "set", "lo", "up")
	run("/usr/sbin/ip", "netns", "exec", "boxb", "/usr/sbin/ip", "link", "set", "lo", "up")
	run("/usr/sbin/ip", "netns", "exec", "boxa", "/usr/sbin/ip", "addr", "add", "10.188.1.1/24", "dev", "va")
	run("/usr/sbin/ip", "netns", "exec", "boxb", "/usr/sbin/ip", "addr", "add", "10.188.1.2/24", "dev", "vb")
	run("/usr/sbin/ip", "netns", "exec", "boxa", "/usr/sbin/ip", "link", "set", "va", "up")
	run("/usr/sbin/ip", "netns", "exec", "boxb", "/usr/sbin/ip", "link", "set", "vb", "up")
}

func endpoint(link *session.Link, capsuleID string) (session.Endpoint, bool) {
	if link == nil {
		return session.Endpoint{}, false
	}
	for _, ep := range link.Endpoints {
		if ep.CapsuleID == capsuleID {
			return ep, true
		}
	}
	return session.Endpoint{}, false
}

func ping(t *testing.T, svc Service, pid int, target string) (int, string) {
	t.Helper()
	result, err := svc.Runtime.Exec(context.Background(), runtime.ExecSpec{
		PID:     pid,
		Argv:    []string{"/usr/bin/ping", "-c", "1", "-W", "1", target},
		LogPath: filepath.Join(svc.Store.Dir, "ping.log"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.ExitCode, result.Output
}

func testService(t *testing.T) Service {
	t.Helper()
	svc := Service{Store: store.Store{Dir: t.TempDir()}, Runtime: local.Runtime{}}
	t.Cleanup(func() {
		capsules, err := svc.List()
		if err != nil {
			return
		}
		for _, c := range capsules {
			_, _ = svc.Destroy(c.ID)
		}
	})
	return svc
}

func mustCapsule(t *testing.T, svc Service, setup string, caps ...string) capsule.Capsule {
	t.Helper()
	c, err := svc.Create(context.Background(), CreateRequest{Task: "peering", Setup: setup, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
