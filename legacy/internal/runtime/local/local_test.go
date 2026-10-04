package local

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestWorkcellIsIsolated(t *testing.T) {
	rt := Runtime{}
	root := t.TempDir()
	handle, err := rt.Start(context.Background(), runtime.Spec{ID: "cap-iso", Root: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Stop(handle.PID) })

	wrote, err := rt.Exec(context.Background(), runtime.ExecSpec{
		PID:     handle.PID,
		Argv:    []string{"touch", "from-cell"},
		LogPath: filepath.Join(root, "touch.log"),
	})
	if err != nil || wrote.ExitCode != 0 {
		t.Fatalf("touch: code %d err %v output %s", wrote.ExitCode, err, wrote.Output)
	}
	if _, err := os.Stat(filepath.Join(handle.WorkDir, "from-cell")); err != nil {
		t.Fatal(err)
	}

	hidden, err := rt.Exec(context.Background(), runtime.ExecSpec{
		PID:     handle.PID,
		Argv:    []string{"ls", "/root"},
		LogPath: filepath.Join(root, "ls-root.log"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if hidden.ExitCode == 0 {
		t.Fatalf("workcell can see the host root: %s", hidden.Output)
	}

	links, err := rt.Exec(context.Background(), runtime.ExecSpec{
		PID:     handle.PID,
		Argv:    []string{"/usr/sbin/ip", "-o", "link"},
		LogPath: filepath.Join(root, "ip.log"),
	})
	if err != nil || links.ExitCode != 0 {
		t.Fatalf("ip: code %d err %v output %s", links.ExitCode, err, links.Output)
	}
	if !strings.Contains(links.Output, "lo:") || strings.Contains(links.Output, "eth") || strings.Contains(links.Output, "ens") {
		t.Fatalf("network = %q", links.Output)
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
