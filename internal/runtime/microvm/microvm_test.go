package microvm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
)

func TestExecWritesTheHostWorkspace(t *testing.T) {
	rt := &Runtime{}
	if err := rt.Available(); err != nil {
		t.Skip(err.Error())
	}
	root := t.TempDir()
	secretPath := filepath.Join(root, "token")
	if err := os.WriteFile(secretPath, []byte("STAGING_TOKEN"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	handle, err := rt.Start(ctx, runtime.Spec{
		ID:   "cap-test",
		Root: root,
		Secrets: []runtime.Secret{{
			Name:     "token",
			HostPath: secretPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Stop(handle.PID) })

	echo, err := rt.Exec(ctx, runtime.ExecSpec{
		PID:     handle.PID,
		WorkDir: handle.WorkDir,
		Argv:    []string{"echo", "hello"},
		LogPath: filepath.Join(root, "echo.log"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if echo.ExitCode != 0 || strings.TrimSpace(echo.Output) != "hello" {
		t.Fatalf("echo = %d %q", echo.ExitCode, echo.Output)
	}

	wrote, err := rt.Exec(ctx, runtime.ExecSpec{
		PID:     handle.PID,
		WorkDir: handle.WorkDir,
		Argv:    []string{"sh", "-c", "echo hi > note.txt"},
		LogPath: filepath.Join(root, "write.log"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrote.ExitCode != 0 {
		t.Fatalf("write exit %d %q", wrote.ExitCode, wrote.Output)
	}
	body, err := os.ReadFile(filepath.Join(handle.WorkDir, "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(body)) != "hi" {
		t.Fatalf("note.txt = %q", body)
	}

	status, err := rt.Exec(ctx, runtime.ExecSpec{
		PID:     handle.PID,
		WorkDir: handle.WorkDir,
		Argv:    []string{"sh", "-c", "exit 3"},
		LogPath: filepath.Join(root, "status.log"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.ExitCode != 3 {
		t.Fatalf("exit = %d %q", status.ExitCode, status.Output)
	}

	secretOut, err := rt.Exec(ctx, runtime.ExecSpec{
		PID:         handle.PID,
		WorkDir:     handle.WorkDir,
		Argv:        []string{"cat", "/run/secrets/token"},
		LogPath:     filepath.Join(root, "secret.log"),
		SecretPaths: []string{secretPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	if secretOut.ExitCode != 0 || strings.TrimSpace(secretOut.Output) != "[redacted]" {
		t.Fatalf("secret exec = %d %q", secretOut.ExitCode, secretOut.Output)
	}
	logged, err := os.ReadFile(filepath.Join(root, "secret.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), "STAGING_TOKEN") {
		t.Fatal("command log contains the secret value")
	}
}
