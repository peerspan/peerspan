package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
)

const usage = `capsule-host runs and controls a local Capsule host daemon.

Usage:
  capsule-host [--state DIR] run
  capsule-host [--state DIR] info
  capsule-host [--state DIR] agent register --name NAME --owner OWNER [--capability NAME]
  capsule-host [--state DIR] agent list
  capsule-host [--state DIR] agent inspect ID
  capsule-host [--state DIR] session attach --agent ID --integration NAME
  capsule-host [--state DIR] session list [--agent ID]
  capsule-host [--state DIR] session inspect ID
  capsule-host [--state DIR] session detach ID
  capsule-host [--state DIR] activity [--after SEQUENCE] [--limit COUNT]

The serve command is a compatibility alias for run.
Session attachment records metadata only; agent integration is a later milestone.
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
	flags := flag.NewFlagSet("capsule-host", flag.ContinueOnError)
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
		*state, err = host.DefaultStateDir()
		if err != nil {
			return err
		}
	}
	if args[0] == "run" || args[0] == "serve" {
		if len(args) != 1 {
			return fmt.Errorf("%s accepts no positional arguments", args[0])
		}
		store, err := host.Open(ctx, *state)
		if err != nil {
			return err
		}
		defer store.Close()
		listener, err := store.Listen()
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Fprintf(errOut, "host daemon %s listening on local control socket %s\n", store.Identity().ID, store.SocketPath())
		return host.Serve(ctx, listener, host.Handler(store))
	}
	method, path, body, err := request(args, errOut)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	result, err := (host.Client{SocketPath: filepath.Join(*state, "admin.sock")}).Call(ctx, method, path, body)
	if err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(result, &value); err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

type repeated []string

func (r *repeated) String() string         { return fmt.Sprint([]string(*r)) }
func (r *repeated) Set(value string) error { *r = append(*r, value); return nil }

func request(args []string, errOut io.Writer) (string, string, any, error) {
	invalid := func() (string, string, any, error) {
		return "", "", nil, errors.New("invalid command; see capsule-host --help")
	}
	parse := func(name string, args []string, configure func(*flag.FlagSet)) error {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(errOut)
		configure(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments: %v", fs.Args())
		}
		return nil
	}
	switch args[0] {
	case "info":
		if len(args) != 1 {
			return invalid()
		}
		return "GET", "/v1/host", nil, nil
	case "agent":
		if len(args) < 2 {
			return invalid()
		}
		switch args[1] {
		case "register":
			var req host.RegisterAgent
			var caps repeated
			err := parse("agent register", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&req.Name, "name", "", "agent name")
				fs.StringVar(&req.Owner, "owner", "", "local owner label")
				fs.Var(&caps, "capability", "advertised capability; repeatable")
			})
			req.Capabilities = caps
			return "POST", "/v1/agents", req, err
		case "list":
			if len(args) != 2 {
				return invalid()
			}
			return "GET", "/v1/agents", nil, nil
		case "inspect":
			if len(args) != 3 {
				return invalid()
			}
			return "GET", "/v1/agents/" + url.PathEscape(args[2]), nil, nil
		}
	case "session":
		if len(args) < 2 {
			return invalid()
		}
		switch args[1] {
		case "attach":
			var req host.AttachSession
			err := parse("session attach", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&req.AgentID, "agent", "", "registered agent ID")
				fs.StringVar(&req.Integration, "integration", "", "integration label")
			})
			return "POST", "/v1/sessions", req, err
		case "list":
			var agentID string
			err := parse("session list", args[2:], func(fs *flag.FlagSet) { fs.StringVar(&agentID, "agent", "", "filter by registered agent ID") })
			return "GET", "/v1/sessions?" + (url.Values{"agent_id": {agentID}}).Encode(), nil, err
		case "inspect", "detach":
			if len(args) != 3 {
				return invalid()
			}
			path := "/v1/sessions/" + url.PathEscape(args[2])
			if args[1] == "detach" {
				return "POST", path + "/detach", nil, nil
			}
			return "GET", path, nil, nil
		}
	case "activity":
		var after int64
		var limit int
		err := parse("activity", args[1:], func(fs *flag.FlagSet) {
			fs.Int64Var(&after, "after", 0, "read events after this sequence")
			fs.IntVar(&limit, "limit", 100, "maximum events, 1 to 1000")
		})
		return "GET", fmt.Sprintf("/v1/activity?after=%d&limit=%d", after, limit), nil, err
	}
	return invalid()
}
