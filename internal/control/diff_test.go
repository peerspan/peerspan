package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func TestDiffWorkspace(t *testing.T) {
	before := t.TempDir()
	after := t.TempDir()
	if err := os.WriteFile(filepath.Join(before, "keep.txt"), []byte("same\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(after, "keep.txt"), []byte("same\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(after, "notes.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(before, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(before, ".git", "config"), []byte("noise\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	patch, paths, err := diffWorkspace(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "notes.txt" {
		t.Fatalf("paths = %v", paths)
	}
	if !strings.Contains(patch, "+hello") {
		t.Fatalf("patch = %s", patch)
	}
	if strings.Contains(patch, "noise") {
		t.Fatalf("patch included .git: %s", patch)
	}
}

func TestExecRecordsWorkspaceDiff(t *testing.T) {
	dir := t.TempDir()
	svc := Service{Store: store.Store{Dir: dir}, Runtime: local.Runtime{}}
	const value = "super-secret-value"
	if err := svc.SetSecret("token", value); err != nil {
		t.Fatal(err)
	}
	c, err := svc.Create(context.Background(), CreateRequest{
		Task:         "diff",
		Capabilities: []string{"exec"},
		Secrets:      []string{"token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = svc.Destroy(c.ID) })

	if _, err := svc.Exec(context.Background(), c.ID, []string{"sh", "-c", "printf 'hello\\n' > notes.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(context.Background(), c.ID, []string{"sh", "-c", "cat /run/secrets/token > leak.txt"}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Inspect(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Commands) != 2 || len(got.Commands[0].Paths) != 1 || got.Commands[0].Paths[0] != "notes.txt" {
		t.Fatalf("commands = %+v", got.Commands)
	}
	body, err := os.ReadFile(got.Commands[0].DiffPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "+hello") {
		t.Fatalf("diff = %s", body)
	}
	secretDiff, err := os.ReadFile(got.Commands[1].DiffPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(secretDiff), value) {
		t.Fatal("diff contains the secret value")
	}
	if !strings.Contains(string(secretDiff), "[redacted]") {
		t.Fatalf("secret diff = %s", secretDiff)
	}

	joined := mustCapsule(t, svc, "")
	t.Cleanup(func() { _, _ = svc.Destroy(joined.ID) })
	sess, err := svc.CreateSession(CreateSessionRequest{
		CapsuleID: c.ID,
		Task:      "diff evidence",
		AllowExec: []string{"true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AcceptSession(sess.ID, joined.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Exec(context.Background(), c.ID, []string{"true"}); err != nil {
		t.Fatal(err)
	}
	evidence, err := svc.ExportSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Commands) != 1 || len(evidence.Commands[0].Paths) != 0 {
		t.Fatalf("evidence commands = %+v", evidence.Commands)
	}
	exported, err := os.ReadFile(filepath.Join(svc.Store.SessionDir(sess.ID), "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), value) || strings.Contains(string(exported), "+hello") {
		t.Fatal("evidence included patch contents")
	}
}
