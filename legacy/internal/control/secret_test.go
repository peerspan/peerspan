package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func TestSecretStaysOnTheHost(t *testing.T) {
	dir := t.TempDir()
	svc := Service{
		Store:   store.Store{Dir: dir},
		Runtime: local.Runtime{},
	}
	const value = "super-secret-value"
	if err := svc.SetSecret("token", value); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), CreateRequest{Task: "missing", Secrets: []string{"missing"}}); err == nil {
		t.Fatal("expected a missing secret to fail")
	}
	if _, err := svc.Create(context.Background(), CreateRequest{Task: "repeat", Secrets: []string{"token", "token"}}); err == nil {
		t.Fatal("expected a repeated secret to fail")
	}

	ctx := context.Background()
	c, err := svc.Create(ctx, CreateRequest{
		Task:         "inject",
		Capabilities: []string{"exec", "share"},
		Secrets:      []string{"token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = svc.Destroy(c.ID) })
	other, err := svc.Create(ctx, CreateRequest{Task: "peer"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = svc.Destroy(other.ID) })

	mounted, err := os.ReadFile(fmt.Sprintf("/proc/%d/root/run/secrets/token", c.Runtime.PID))
	if err != nil {
		t.Fatal(err)
	}
	if string(mounted) != value {
		t.Fatalf("mounted secret = %q", mounted)
	}
	entries, err := os.ReadDir(c.Runtime.WorkDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("workspace = %v", entries)
	}

	if _, err := svc.Exec(ctx, c.ID, []string{"sh", "-c", "printf x >> /run/secrets/token"}); err == nil {
		t.Fatal("expected the secret mount to be read-only")
	}
	host, err := os.ReadFile(filepath.Join(dir, "secrets", "token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(host) != value {
		t.Fatalf("host secret changed to %q", host)
	}

	output, err := svc.Exec(ctx, c.ID, []string{"cat", "/run/secrets/token"})
	if err != nil {
		t.Fatal(err)
	}
	if output != "[redacted]" {
		t.Fatalf("exec output = %q", output)
	}
	if _, err := svc.Exec(ctx, c.ID, []string{"printf", "%s", value}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(ctx, c.ID, []string{"sh", "-c", "cat /run/secrets/token > leak.txt"}); err != nil {
		t.Fatal(err)
	}

	inspected, err := svc.Inspect(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := json.Marshal(inspected)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(recorded), value) {
		t.Fatal("capsule record contains the secret value")
	}
	if !strings.Contains(string(recorded), "[redacted]") {
		t.Fatal("command record was not redacted")
	}

	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: c.ID,
		Task:      "share the leak",
		Allow:     []string{"leak.txt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, other.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ShareSession(sess.ID, c.ID, "leak.txt"); err == nil || !strings.Contains(err.Error(), "contains a secret value") {
		t.Fatalf("share err = %v", err)
	}
	evidence, err := svc.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Artifacts) != 0 {
		t.Fatalf("artifacts = %+v", evidence.Artifacts)
	}
	exported, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), value) {
		t.Fatal("evidence contains the secret value")
	}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if strings.HasPrefix(path, filepath.Join(dir, "secrets")) || strings.HasPrefix(path, c.Runtime.WorkDir) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), value) {
			t.Errorf("secret value leaked into %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
