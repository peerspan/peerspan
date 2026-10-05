package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Cerebral-Systems/capsule/go/internal/coord"
)

const usage = `capsule-coord runs the Capsule coordination service.

Usage:
  capsule-coord [--state DIR] run --listen HOST:PORT
  capsule-coord [--state DIR] info

Coordination stores signed membership chains and serves network maps. It
carries no collaboration traffic, and hosts verify every chain it serves.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("capsule-coord", flag.ContinueOnError)
	flags.SetOutput(errOut)
	state := flags.String("state", "", "private state directory")
	flags.Usage = func() { fmt.Fprint(out, usage) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = flags.Args()
	if len(args) == 0 || args[0] == "help" {
		fmt.Fprint(out, usage)
		return nil
	}
	if *state == "" {
		var err error
		if *state, err = coord.DefaultStateDir(); err != nil {
			return err
		}
	}
	switch args[0] {
	case "info":
		if len(args) != 1 {
			return errors.New("unexpected arguments")
		}
		identity, err := coord.ReadIdentity(ctx, *state)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(identity)
	case "run":
		runFlags := flag.NewFlagSet("run", flag.ContinueOnError)
		runFlags.SetOutput(errOut)
		listen := runFlags.String("listen", "", "bind address, HOST:PORT")
		if err := runFlags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if runFlags.NArg() != 0 || *listen == "" {
			return errors.New("run requires --listen HOST:PORT")
		}
		server, err := coord.Open(ctx, *state)
		if err != nil {
			return err
		}
		defer server.Close()
		listener, err := server.Listen(*listen)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Fprintf(errOut, "coordinator %s listening on %s\n", server.Identity().ID, listener.Addr())
		return server.Serve(ctx, listener)
	}
	return errors.New("invalid command; see capsule-coord --help")
}
