package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/session"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func TestSessionExchange(t *testing.T) {
	svc := testService(t)
	host := mustCapsule(t, svc, "mkdir -p logs && printf fail > logs/failure.txt")
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

	sess, err = svc.AcceptSession(sess.ID, guest.ID, []string{"notes/diag.txt"})
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
	if _, err := svc.AcceptSession(sess.ID, guest.ID, nil); err != nil {
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

func mustCapsule(t *testing.T, svc Service, setup string) capsule.Capsule {
	t.Helper()
	c, err := svc.Create(context.Background(), CreateRequest{Task: "peering", Setup: setup})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
