package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/runtime/microvm"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func TestMicroVMBackendRequiresTheRuntime(t *testing.T) {
	svc := Service{
		Store:   store.Store{Dir: t.TempDir()},
		Runtime: local.Runtime{},
	}
	_, err := svc.Create(context.Background(), CreateRequest{
		Task:    "boot a guest",
		Backend: capsule.RuntimeMicroVM,
	})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatal(err)
	}
}

func TestMicroVMExecThroughTheControlPlane(t *testing.T) {
	rt := &microvm.Runtime{}
	if err := rt.Available(); err != nil {
		t.Skip(err.Error())
	}
	svc := Service{
		Store:   store.Store{Dir: t.TempDir()},
		MicroVM: rt,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c, err := svc.Create(ctx, CreateRequest{
		Task:         "boot a guest",
		Backend:      capsule.RuntimeMicroVM,
		Capabilities: []string{"exec"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = svc.Destroy(c.ID) })
	if c.Status != capsule.StatusRunning {
		t.Fatalf("status = %q", c.Status)
	}
	if c.Runtime.Backend != capsule.RuntimeMicroVM {
		t.Fatalf("backend = %q", c.Runtime.Backend)
	}

	if _, err := svc.Exec(ctx, c.ID, []string{"sh", "-c", "echo hi > note.txt"}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(c.Runtime.WorkDir, "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(body)) != "hi" {
		t.Fatalf("note.txt = %q", body)
	}

	destroyed, err := svc.Destroy(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if destroyed.Status != capsule.StatusDestroyed {
		t.Fatalf("status = %q", destroyed.Status)
	}
	if rt.Alive(c.Runtime.PID) {
		t.Fatalf("pid %d still alive", c.Runtime.PID)
	}
}
