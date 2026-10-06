package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
)

const usage = `capsule-host runs and controls a local Capsule host daemon.

Usage:
  capsule-host [--state DIR] run [--peer-listen IP:PORT] [--advertise IP:PORT] [--coordination-interval SECONDS]
  capsule-host [--state DIR] info
  capsule-host [--state DIR] agent register --name NAME --owner OWNER [--capability NAME]
  capsule-host [--state DIR] agent list
  capsule-host [--state DIR] agent inspect ID
  capsule-host [--state DIR] session attach --agent ID --integration NAME
  capsule-host [--state DIR] session list [--agent ID]
  capsule-host [--state DIR] session inspect ID
  capsule-host [--state DIR] session detach ID
  capsule-host [--state DIR] activity [--after SEQUENCE] [--limit COUNT]

  capsule-host [--state DIR] peer add --id HOST --public-key KEY --address IP:PORT
  capsule-host [--state DIR] peer list
  capsule-host [--state DIR] peer path HOST
  capsule-host [--state DIR] grant create --peer HOST --agent ID --expires-at TIME [--max-message-bytes N] [--allow-disconnected]
  capsule-host [--state DIR] grant list
  capsule-host [--state DIR] grant revoke ID
  capsule-host [--state DIR] message send --peer HOST --grant ID --agent ID --deadline TIME --content TEXT [--request ID]
  capsule-host [--state DIR] message list [--after SEQUENCE] [--limit COUNT]
  capsule-host [--state DIR] message inspect|retry|refresh|reply|origin --peer HOST ID
  capsule-host [--state DIR] adapter create --session ID --expires-at TIME
  capsule-host [--state DIR] adapter list|inspect|revoke|rotate|connection [ID]
  capsule-host [--state DIR] adapter route add --adapter ID --name NAME --peer HOST --agent TARGET --grant ID --expires-at TIME [--max-message-bytes N --max-messages N]
  capsule-host [--state DIR] adapter route list --adapter ID
  capsule-host [--state DIR] adapter route revoke ID
  capsule-host [--state DIR] delivery list [--after SEQUENCE --limit COUNT]
  capsule-host [--state DIR] delivery inspect ID

  capsule-host [--state DIR] network create --name NAME --member LABEL --coordinator HOST:PORT --coordinator-key KEY
  capsule-host [--state DIR] network invite --network ID --member LABEL --expires-at TIME
  capsule-host [--state DIR] network join --token TOKEN
  capsule-host [--state DIR] network list
  capsule-host [--state DIR] network members ID
  capsule-host [--state DIR] network sync ID

The serve command is a compatibility alias for run.
Session attachment records metadata; a scoped adapter connects an opted-in session.
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
		runFlags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		runFlags.SetOutput(errOut)
		peerListen := runFlags.String("peer-listen", "", "opt-in peer bind address, UDP IP:port")
		advertise := runFlags.String("advertise", "", "peer address advertised to coordination, IP:port; defaults to a specific --peer-listen address")
		interval := runFlags.Int("coordination-interval", 30, "seconds between coordination syncs, 1 to 3600")
		if err := runFlags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if runFlags.NArg() != 0 {
			return errors.New("unexpected daemon arguments")
		}
		if *advertise != "" && *peerListen == "" {
			return errors.New("--advertise requires --peer-listen")
		}
		if *interval < 1 || *interval > 3600 {
			return errors.New("--coordination-interval must be 1 to 3600 seconds")
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
		daemonCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		var peerListener net.Listener
		if *peerListen != "" {
			peerListener, err = store.ListenPeer(daemonCtx, *peerListen)
			if err != nil {
				return err
			}
			defer peerListener.Close()
			if *advertise == "" {
				if bound, err := netip.ParseAddrPort(peerListener.Addr().String()); err == nil && !bound.Addr().IsUnspecified() {
					*advertise = bound.String()
				}
			}
			fmt.Fprintf(errOut, "peer listener %s (advertised %q)\n", peerListener.Addr(), *advertise)
			// A listening host stays reachable through its networks' relays.
			go store.RunRelays(daemonCtx)
		}
		if err = store.ConfigureCoordination(*advertise, time.Duration(*interval)*time.Second); err != nil {
			return err
		}
		coordinationDone := make(chan struct{})
		go func() {
			defer close(coordinationDone)
			store.RunCoordination(daemonCtx, func(format string, args ...any) { fmt.Fprintf(errOut, format+"\n", args...) })
		}()
		defer func() { cancel(); <-coordinationDone }()
		repliesDone := make(chan struct{})
		go func() { defer close(repliesDone); store.RunReplyWorkers(daemonCtx) }()
		defer func() { cancel(); <-repliesDone }()
		adapterListener, err := store.ListenAdapter()
		if err != nil {
			return err
		}
		defer adapterListener.Close()
		results := make(chan error, 3)
		go func() { results <- host.Serve(daemonCtx, listener, host.Handler(store)) }()
		go func() { results <- host.Serve(daemonCtx, adapterListener, host.AdapterHandler(store)) }()
		count := 2
		if peerListener != nil {
			count++
			go func() { results <- host.Serve(daemonCtx, peerListener, host.PeerHandler(store)) }()
		}
		first := <-results
		cancel()
		for range count - 1 {
			first = errors.Join(first, <-results)
		}
		return first
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
	case "peer":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "list" && len(args) == 2 {
			return "GET", "/v1/peers", nil, nil
		}
		if args[1] == "path" && len(args) == 3 {
			return "GET", "/v1/peers/" + url.PathEscape(args[2]) + "/path", nil, nil
		}
		if args[1] == "add" {
			var p host.Peer
			err := parse("peer add", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&p.ID, "id", "", "expected host ID")
				fs.StringVar(&p.PublicKey, "public-key", "", "owner-verified public key")
				fs.StringVar(&p.Address, "address", "", "peer IP:port")
			})
			return "POST", "/v1/peers", p, err
		}
	case "grant":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "list" && len(args) == 2 {
			return "GET", "/v1/grants", nil, nil
		}
		if args[1] == "revoke" && len(args) == 3 {
			return "POST", "/v1/grants/" + url.PathEscape(args[2]) + "/revoke", nil, nil
		}
		if args[1] == "create" {
			var g host.CreateGrant
			err := parse("grant create", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&g.RequesterHostID, "peer", "", "requester host ID")
				fs.StringVar(&g.TargetAgentID, "agent", "", "target local agent ID")
				fs.StringVar(&g.ExpiresAt, "expires-at", "", "UTC grant expiration")
				fs.Int64Var(&g.MaxMessageBytes, "max-message-bytes", 65536, "content byte limit")
				fs.BoolVar(&g.AllowDisconnected, "allow-disconnected", false, "permit work without coordination")
			})
			return "POST", "/v1/grants", g, err
		}
	case "message":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "list" {
			var after, limit int64
			err := parse("message list", args[2:], func(fs *flag.FlagSet) {
				fs.Int64Var(&after, "after", 0, "read messages after sequence")
				fs.Int64Var(&limit, "limit", 100, "maximum records, 1 to 1000")
			})
			return "GET", fmt.Sprintf("/v1/messages?after=%d&limit=%d", after, limit), nil, err
		}
		if args[1] == "send" {
			var m host.SendMessage
			err := parse("message send", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&m.PeerHostID, "peer", "", "receiving host ID")
				fs.StringVar(&m.RequestID, "request", "", "stable request ID; generated if omitted")
				fs.StringVar(&m.GrantID, "grant", "", "receiver grant ID")
				fs.StringVar(&m.TargetAgentID, "agent", "", "receiver agent ID")
				fs.StringVar(&m.Deadline, "deadline", "", "UTC request deadline")
				fs.StringVar(&m.Content, "content", "", "message text")
			})
			return "POST", "/v1/outbound", m, err
		}
		if args[1] == "inspect" || args[1] == "retry" || args[1] == "refresh" || args[1] == "reply" || args[1] == "origin" {
			fs := flag.NewFlagSet("message "+args[1], flag.ContinueOnError)
			fs.SetOutput(errOut)
			peer := fs.String("peer", "", "receiving host ID")
			if err := fs.Parse(args[2:]); err != nil {
				return "", "", nil, err
			}
			if *peer == "" || fs.NArg() != 1 {
				return invalid()
			}
			path := "/v1/outbound/" + url.PathEscape(*peer) + "/" + url.PathEscape(fs.Arg(0))
			if args[1] == "inspect" {
				return "GET", path, nil, nil
			}
			if args[1] == "origin" {
				return "GET", path + "/origin", nil, nil
			}
			return "POST", path + "/" + args[1], nil, nil
		}
	case "network":
		if len(args) < 2 {
			return invalid()
		}
		switch args[1] {
		case "create":
			var n host.CreateNetwork
			err := parse("network create", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&n.Name, "name", "", "network name")
				fs.StringVar(&n.Member, "member", "", "this host's member label")
				fs.StringVar(&n.CoordinatorAddress, "coordinator", "", "coordinator HOST:PORT")
				fs.StringVar(&n.CoordinatorPublicKey, "coordinator-key", "", "pinned coordinator public key")
			})
			return "POST", "/v1/networks", n, err
		case "invite":
			var network string
			var i host.CreateInvite
			err := parse("network invite", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&network, "network", "", "network ID")
				fs.StringVar(&i.Member, "member", "", "invitee member label")
				fs.StringVar(&i.ExpiresAt, "expires-at", "", "UTC invite expiration, at most 30 days ahead")
			})
			if err == nil && network == "" {
				return invalid()
			}
			return "POST", "/v1/networks/" + url.PathEscape(network) + "/invites", i, err
		case "join":
			var j host.JoinNetwork
			err := parse("network join", args[2:], func(fs *flag.FlagSet) { fs.StringVar(&j.Token, "token", "", "invite token") })
			return "POST", "/v1/networks/join", j, err
		case "list":
			if len(args) != 2 {
				return invalid()
			}
			return "GET", "/v1/networks", nil, nil
		case "members", "sync":
			if len(args) != 3 {
				return invalid()
			}
			path := "/v1/networks/" + url.PathEscape(args[2])
			if args[1] == "sync" {
				return "POST", path + "/sync", nil, nil
			}
			return "GET", path + "/members", nil, nil
		}
	case "adapter":
		if len(args) < 2 {
			return invalid()
		}
		if len(args) == 3 && (args[1] == "rotate" || args[1] == "connection") {
			method := "GET"
			if args[1] == "rotate" {
				method = "POST"
			}
			return method, "/v1/adapters/" + url.PathEscape(args[2]) + "/" + args[1], nil, nil
		}
		if args[1] == "route" {
			if len(args) < 3 {
				return invalid()
			}
			if args[2] == "add" {
				var req host.CreateOutboundRoute
				err := parse("adapter route add", args[3:], func(fs *flag.FlagSet) {
					fs.StringVar(&req.AdapterID, "adapter", "", "local adapter credential ID")
					fs.StringVar(&req.Name, "name", "", "destination name")
					fs.StringVar(&req.PeerHostID, "peer", "", "receiving host ID")
					fs.StringVar(&req.TargetAgentID, "agent", "", "remote agent ID")
					fs.StringVar(&req.GrantID, "grant", "", "receiver's grant ID")
					fs.StringVar(&req.ExpiresAt, "expires-at", "", "route expiration")
					fs.Int64Var(&req.MaxMessageBytes, "max-message-bytes", 65536, "maximum content bytes")
					fs.Int64Var(&req.MaxMessages, "max-messages", 100, "lifetime message budget")
				})
				return "POST", "/v1/adapter-routes", req, err
			}
			if args[2] == "list" {
				var id string
				err := parse("adapter route list", args[3:], func(fs *flag.FlagSet) { fs.StringVar(&id, "adapter", "", "adapter credential ID") })
				if err == nil && id == "" {
					return invalid()
				}
				return "GET", "/v1/adapters/" + url.PathEscape(id) + "/routes", nil, err
			}
			if args[2] == "revoke" && len(args) == 4 {
				return "POST", "/v1/adapter-routes/" + url.PathEscape(args[3]) + "/revoke", nil, nil
			}
			return invalid()
		}
		if args[1] == "create" {
			var req host.CreateAdapter
			err := parse("adapter create", args[2:], func(fs *flag.FlagSet) {
				fs.StringVar(&req.SessionID, "session", "", "one attached session ID")
				fs.StringVar(&req.ExpiresAt, "expires-at", "", "credential expiration")
			})
			return "POST", "/v1/adapters", req, err
		}
		if args[1] == "list" && len(args) == 2 {
			return "GET", "/v1/adapters", nil, nil
		}
		if len(args) == 3 && (args[1] == "inspect" || args[1] == "revoke") {
			path := "/v1/adapters/" + url.PathEscape(args[2])
			if args[1] == "revoke" {
				return "POST", path + "/revoke", nil, nil
			}
			return "GET", path, nil, nil
		}
	case "delivery":
		if len(args) < 2 {
			return invalid()
		}
		if args[1] == "inspect" && len(args) == 3 {
			return "GET", "/v1/deliveries/" + url.PathEscape(args[2]), nil, nil
		}
		if args[1] == "list" {
			var after, limit int64
			err := parse("delivery list", args[2:], func(fs *flag.FlagSet) {
				fs.Int64Var(&after, "after", 0, "read after this sequence")
				fs.Int64Var(&limit, "limit", 100, "maximum records")
			})
			return "GET", fmt.Sprintf("/v1/deliveries?after=%d&limit=%d", after, limit), nil, err
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
