package control

import (
	"context"
	"os"
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
	host := mustCapsule(t, svc, "mkdir -p logs && printf fail > logs/failure.txt", "share")
	guest := mustCapsule(t, svc, "")

	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: host.ID,
		Task:      "sdk fails in staging",
		Allow:     []string{"logs/failure.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != session.StatusPending {
		t.Fatalf("status = %q", sess.Status)
	}

	sess, err = svc.AcceptSession(sess.ID, guest.ID, []string{"notes/diag.txt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != session.StatusActive || sess.GuestCapsule != guest.ID {
		t.Fatalf("accepted = %+v", sess)
	}

	if _, err := svc.MessageSession(sess.ID, host.ID, "failure is attached"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MessageSession(sess.ID, "cap-outsider", "hello"); err == nil {
		t.Fatal("expected outsider to be refused")
	}

	shared, err := svc.ShareSession(sess.ID, host.ID, "logs/failure.txt")
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
	if _, err := svc.ShareSession(sess.ID, host.ID, "logs/other.txt"); err == nil {
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
	host := mustCapsule(t, svc, "")
	guest := mustCapsule(t, svc, "")
	sess, err := svc.CreateSession(CreateSessionRequest{CapsuleID: host.ID, Task: "issue", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, guest.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MessageSession(sess.ID, host.ID, "too late"); err == nil {
		t.Fatal("expected a revoked session to refuse messages")
	}

	svc.Now = func() time.Time { return time.Now().UTC() }
	expiring, err := svc.CreateSession(CreateSessionRequest{CapsuleID: host.ID, Task: "expires", TTL: time.Millisecond})
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
	host := mustCapsule(t, svc, "", "exec")
	if _, err := svc.Exec(context.Background(), host.ID, []string{"echo", "before"}); err != nil {
		t.Fatal(err)
	}
	guest := mustCapsule(t, svc, "")
	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: host.ID,
		Task:      "evidence",
		AllowExec: []string{"echo during"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, guest.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(context.Background(), host.ID, []string{"echo", "during"}); err != nil {
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
	host := mustCapsule(t, svc, "printf secret > notes.txt", "share:approval-required", "exec")
	guest := mustCapsule(t, svc, "")
	if _, err := svc.Exec(context.Background(), guest.ID, []string{"echo", "no"}); err == nil {
		t.Fatal("expected exec without a capability to be refused")
	}

	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: host.ID,
		Task:      "approval",
		Allow:     []string{"notes.txt"},
		AllowExec: []string{"echo ok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, guest.ID, nil, nil); err != nil {
		t.Fatal(err)
	}

	pending, err := svc.ShareSession(sess.ID, host.ID, "notes.txt")
	if err == nil {
		t.Fatal("expected share to wait for approval")
	}
	if len(pending.Artifacts) != 0 || len(pending.Approvals) != 1 || pending.Approvals[0].Status != session.ApprovalPending {
		t.Fatalf("pending = %+v", pending)
	}
	if _, err := svc.ApproveSession(sess.ID, host.ID, "share notes.txt"); err != nil {
		t.Fatal(err)
	}
	shared, err := svc.ShareSession(sess.ID, host.ID, "notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(shared.Artifacts) != 1 {
		t.Fatalf("artifacts = %+v", shared.Artifacts)
	}

	if _, err := svc.Exec(context.Background(), host.ID, []string{"echo", "nope"}); err == nil {
		t.Fatal("expected a command outside the session allowlist to be refused")
	}
	if _, err := svc.Exec(context.Background(), host.ID, []string{"echo", "ok"}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionReachability(t *testing.T) {
	svc := testService(t)
	host := mustCapsule(t, svc, "")
	guest := mustCapsule(t, svc, "")
	other := mustCapsule(t, svc, "")
	sess, err := svc.CreateSession(CreateSessionRequest{CapsuleID: host.ID, Task: "reach", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sess, err = svc.AcceptSession(sess.ID, guest.ID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Link == nil || sess.Link.GuestName != guest.Network.Name {
		t.Fatalf("link = %+v", sess.Link)
	}
	record, err := svc.Inspect(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Network.Endpoints) != 1 || record.Network.Endpoints[0] != sess.Link.HostIP {
		t.Fatalf("endpoints = %+v", record.Network.Endpoints)
	}
	if code, output := ping(t, svc, host.Runtime.PID, guest.Network.Name); code != 0 {
		t.Fatalf("ping guest name: %s", output)
	}
	if code, _ := ping(t, svc, other.Runtime.PID, sess.Link.HostIP); code == 0 {
		t.Fatal("a capsule outside the session reached the link")
	}

	if _, err := svc.RevokeSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if code, output := ping(t, svc, host.Runtime.PID, guest.Network.Name); code == 0 {
		t.Fatalf("still reachable after revoke: %s", output)
	}
	record, err = svc.Inspect(host.ID)
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
	if evidence.Reachability == nil || evidence.Reachability.HostIP == "" {
		t.Fatalf("reachability = %+v", evidence.Reachability)
	}

	sess, err = svc.CreateSession(CreateSessionRequest{CapsuleID: host.ID, Task: "expires", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, guest.ID, nil, nil); err != nil {
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
	if code, output := ping(t, svc, host.Runtime.PID, guest.Network.Name); code == 0 {
		t.Fatalf("still reachable after expiry: %s", output)
	}
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
