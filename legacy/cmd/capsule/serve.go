package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Cerebral-Systems/capsule/internal/control"
	"github.com/Cerebral-Systems/capsule/internal/runtime/local"
	"github.com/Cerebral-Systems/capsule/internal/runtime/microvm"
	"github.com/Cerebral-Systems/capsule/internal/server"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", server.DefaultAddr, "listen address")
	data := fs.String("data", ".capsules", "directory for capsule and session records")
	underlay := fs.String("underlay", "", "this machine's address, for a capsule joining from another machine")
	firecracker := fs.String("firecracker", "", "Firecracker binary used by --runtime microvm")
	kernel := fs.String("kernel", "", "guest kernel used by --runtime microvm")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "capsule serve listening on http://%s\n", *addr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = server.Serve(ctx, *addr, control.Service{
		Store:    store.Store{Dir: dir},
		Runtime:  local.Runtime{},
		MicroVM:  &microvm.Runtime{Firecracker: *firecracker, Kernel: *kernel},
		Underlay: *underlay,
	})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
