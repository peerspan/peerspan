package control

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func TestCreateDestroy(t *testing.T) {
	svc := Service{
		Store:   store.Store{Dir: t.TempDir()},
		Runtime: local.Runtime{},
	}
	c, err := svc.Create(context.Background(), CreateRequest{
		Task:         "Fix issue 418",
		Owner:        "ada",
		Capabilities: []string{"github:pull_request:write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = svc.Destroy(c.ID) })

	if c.Status != capsule.StatusRunning {
		t.Fatalf("status = %q", c.Status)
	}
	if !svc.Runtime.Alive(c.Runtime.PID) {
		t.Fatalf("pid %d is not alive", c.Runtime.PID)
	}
	if c.Network.Name != c.ID+".capsule.local" {
		t.Fatalf("network name = %q", c.Network.Name)
	}

	destroyed, err := svc.Destroy(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if destroyed.Status != capsule.StatusDestroyed {
		t.Fatalf("status = %q", destroyed.Status)
	}
	if svc.Runtime.Alive(c.Runtime.PID) {
		t.Fatalf("pid %d still alive", c.Runtime.PID)
	}
}

func TestListMarksExitedProcess(t *testing.T) {
	svc := Service{
		Store:   store.Store{Dir: t.TempDir()},
		Runtime: local.Runtime{},
	}
	c, err := svc.Create(context.Background(), CreateRequest{Task: "run tests"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = svc.Destroy(c.ID) })

	if err := syscall.Kill(c.Runtime.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for svc.Runtime.Alive(c.Runtime.PID) {
		if time.Now().After(deadline) {
			t.Fatal("process did not exit")
		}
		time.Sleep(20 * time.Millisecond)
	}

	listed, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Status != capsule.StatusExited {
		t.Fatalf("list = %+v", listed)
	}
}

func TestUnsupportedRuntime(t *testing.T) {
	dir := t.TempDir()
	svc := Service{Store: store.Store{Dir: dir}, Runtime: local.Runtime{}}
	if _, err := svc.Create(context.Background(), CreateRequest{Task: "x", Backend: "firecracker"}); err == nil {
		t.Fatal("expected an error")
	}
	listed, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 0 {
		t.Fatalf("store has %d capsules", len(listed))
	}
}

func TestSetupAndExec(t *testing.T) {
	svc := Service{
		Store:   store.Store{Dir: t.TempDir()},
		Runtime: local.Runtime{},
	}
	c, err := svc.Create(context.Background(), CreateRequest{
		Task:  "run tests",
		Setup: "touch from-setup",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = svc.Destroy(c.ID) })
	if _, err := os.Stat(filepath.Join(c.Runtime.WorkDir, "from-setup")); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Exec(context.Background(), c.ID, []string{"touch", "from-exec"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.Runtime.WorkDir, "from-exec")); err != nil {
		t.Fatal(err)
	}

	_, err = svc.Exec(context.Background(), c.ID, []string{"sh", "-c", "exit 3"})
	if err == nil {
		t.Fatal("expected a non-zero exit")
	}
	got, err := svc.Inspect(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != capsule.StatusRunning {
		t.Fatalf("status = %q", got.Status)
	}
	if len(got.Commands) != 2 || got.Commands[1].ExitCode != 3 {
		t.Fatalf("commands = %+v", got.Commands)
	}
}

func TestSetupFailureDoesNotStart(t *testing.T) {
	svc := Service{
		Store:   store.Store{Dir: t.TempDir()},
		Runtime: local.Runtime{},
	}
	c, err := svc.Create(context.Background(), CreateRequest{Task: "bad setup", Setup: "exit 1"})
	if err == nil {
		t.Fatal("expected setup to fail")
	}
	if c.Status != capsule.StatusFailed {
		t.Fatalf("status = %q", c.Status)
	}
	if c.Runtime.PID != 0 {
		t.Fatalf("pid = %d", c.Runtime.PID)
	}
}
