package local

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
)

func TestStartStop(t *testing.T) {
	rt := Runtime{}
	root := t.TempDir()
	handle, err := rt.Start(context.Background(), runtime.Spec{ID: "cap-test", Root: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Stop(handle.PID) })

	if !rt.Alive(handle.PID) {
		t.Fatalf("pid %d is not alive", handle.PID)
	}
	if _, err := os.Stat(handle.WorkDir); err != nil {
		t.Fatal(err)
	}
	if err := rt.Stop(handle.PID); err != nil {
		t.Fatal(err)
	}
	if rt.Alive(handle.PID) {
		t.Fatalf("pid %d still alive", handle.PID)
	}
}

func TestStartClonesRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	script := "git init && git add README.md && git -c user.email=test@example.com -c user.name=test commit -m init"
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init repo: %v: %s", err, out)
	}

	rt := Runtime{}
	root := t.TempDir()
	handle, err := rt.Start(context.Background(), runtime.Spec{ID: "cap-repo", Root: root, Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Stop(handle.PID) })

	data, err := os.ReadFile(filepath.Join(handle.WorkDir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("readme = %q", data)
	}
}

func TestStartRunsSetup(t *testing.T) {
	rt := Runtime{}
	root := t.TempDir()
	handle, err := rt.Start(context.Background(), runtime.Spec{ID: "cap-setup", Root: root, Setup: "touch ready"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Stop(handle.PID) })
	if _, err := os.Stat(filepath.Join(handle.WorkDir, "ready")); err != nil {
		t.Fatal(err)
	}
}

func TestStartSetupFailure(t *testing.T) {
	rt := Runtime{}
	root := t.TempDir()
	_, err := rt.Start(context.Background(), runtime.Spec{ID: "cap-bad-setup", Root: root, Setup: "exit 1"})
	if err == nil {
		t.Fatal("expected setup to fail")
	}
}
