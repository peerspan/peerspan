package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/pflag"
)

// Launch CLI shape: expiry defaults, network defaulting, and status.

const messageDefaultDeadline = time.Hour

// fixedExpiryDefaults are the lifetimes applied when a command is given
// neither --expires-at nor --expires-in. Commands taking those flags that are
// not listed send no expiry: adapter create issues a renewable credential, and
// adapter route add a route that follows it.
var fixedExpiryDefaults = map[string]time.Duration{
	"grant create":          30 * 24 * time.Hour,
	"network invite":        7 * 24 * time.Hour,
	"network invite-person": 7 * 24 * time.Hour,
}

// expiryIn is the RFC3339 time d from now, in whole seconds.
func expiryIn(d time.Duration) string {
	return time.Now().UTC().Add(d).Format(time.RFC3339)
}

// resolveExpiry turns --expires-in, or the command's default, into
// --expires-at, so the daemon APIs are unchanged.
func resolveExpiry(args []string, fs *pflag.FlagSet) error {
	if fs.Lookup("expires-in") == nil || fs.Lookup("expires-at") == nil {
		return nil
	}
	at, _ := fs.GetString("expires-at")
	in, _ := fs.GetString("expires-in")
	if at != "" && in != "" {
		return errors.New("--expires-at and --expires-in are mutually exclusive")
	}
	if in != "" {
		d, err := relativeExpiryDuration(in)
		if err != nil {
			return err
		}
		return fs.Set("expires-at", expiryIn(d))
	}
	if d, ok := fixedExpiryDefaults[strings.Join(args[:2], " ")]; ok && at == "" {
		return fs.Set("expires-at", expiryIn(d))
	}
	return nil
}

// networkFlagOptional lists the commands whose --network defaults to the only
// network; networkArgOptional those whose network ID argument does.
var (
	networkFlagOptional = map[string]bool{
		"network enable-linking": true,
		"network invite":         true, "network invite-person": true, "network remove-person": true,
		"network revoke-invite": true, "network admit": true, "network bind": true, "network unbind": true,
		"network delegate-admin": true, "network group": true, "network move": true,
		"access allow": true, "access deny": true, "access renew": true, "access show": true, "access sync": true,
		"allow": true, "deny": true, "trust": true, "untrust": true, "share": true, "unshare": true,
	}
	networkArgOptional = map[string]bool{"network members": true, "network sync": true, "network persons": true, "network groups": true, "network repair": true}
)

// defaultNetwork fills in an omitted network when this host is in exactly
// one. It never guesses among several.
func defaultNetwork(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet) ([]string, error) {
	if len(args) < 2 && args[0] != "trust" && args[0] != "share" {
		return args, nil
	}
	command := args[0]
	if len(args) >= 2 {
		command = strings.Join(args[:2], " ")
	}
	if args[0] == "allow" || args[0] == "deny" || args[0] == "trust" || args[0] == "untrust" || args[0] == "share" || args[0] == "unshare" {
		command = args[0]
	}
	flag := networkFlagOptional[command] && fs.Lookup("network") != nil && !fs.Changed("network")
	positional := networkArgOptional[command] && len(args) == 2
	if !flag && !positional {
		return args, nil
	}
	networks, err := call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
	if err != nil {
		return nil, err
	}
	switch len(networks) {
	case 0:
		return nil, errors.New("not a member of any network")
	case 1:
	default:
		listed := make([]string, len(networks))
		for i, n := range networks {
			listed[i] = fmt.Sprintf("%s (%s)", n.ID, n.Name)
		}
		return nil, errors.New("this host is in several networks; choose one with --network: " + strings.Join(listed, ", "))
	}
	if positional {
		return append(append([]string{}, args...), networks[0].ID), nil
	}
	return args, fs.Set("network", networks[0].ID)
}

// runStatus prints the daemon's status and exits 0 when nothing needs
// attention, 1 when something does, and 2 when the daemon is unreachable.
func runStatus(ctx context.Context, client host.Client, fs *pflag.FlagSet, state string, out io.Writer) error {
	asJSON, _ := fs.GetBool("json")
	data, err := client.Call(ctx, "GET", "/v2/status", nil)
	var unreachable *net.OpError
	if err != nil && errors.As(err, &unreachable) {
		dir, _ := filepath.Abs(state)
		service := readServiceStatus(ctx)
		if asJSON {
			if err := printJSON(out, map[string]any{"daemon": "not running", "state": dir, "service": service}); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(out, "The host daemon is not running for state %s.\n", dir)
			if service.Installed {
				fmt.Fprintf(out, "Its %s service is installed at %s.\n", *service.Manager, *service.Unit)
			} else {
				fmt.Fprintf(out, "Start it with: %s install, or %s run in the foreground\n", programName, programName)
			}
		}
		return exitStatus(2)
	}
	if err != nil {
		return err
	}
	st, modern, err := decodeStatus(data)
	if err != nil {
		return err
	}
	// The CLI adds the service and its attention items to the daemon's view.
	service := readServiceStatus(ctx)
	st.Attention = append(st.Attention, serviceAttention(service, true)...)
	host.SortAttention(st.Attention)
	if asJSON {
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		value["service"] = service
		value["attention"] = st.Attention
		if err := printJSON(out, value); err != nil {
			return err
		}
	} else {
		printStatus(out, st, service, modern...)
	}
	if len(st.Attention) > 0 {
		return exitStatus(1)
	}
	return nil
}

func printStatus(out io.Writer, st host.Status, service serviceStatus, modern ...host.DecNetworkView) {
	fmt.Fprintf(out, "Host %s (version %s)\n", st.HostID, st.Version)
	switch {
	case service.Manager == nil:
		fmt.Fprintln(out, "Service: no supported service manager")
	case !service.Installed:
		fmt.Fprintf(out, "Service: not installed (%s)\n", *service.Manager)
	default:
		state := "inactive"
		if service.Active {
			state = "active"
		}
		line := fmt.Sprintf("Service: %s %s, %s", *service.Manager, *service.Unit, state)
		if service.Linger != nil {
			line += fmt.Sprintf(", lingering %t", *service.Linger)
		}
		fmt.Fprintln(out, line)
	}
	if len(st.Networks)+len(modern) == 0 {
		fmt.Fprintln(out, "\nNetworks: none")
	} else {
		fmt.Fprintln(out, "\nNetworks:")
	}
	for _, n := range modern {
		fmt.Fprintf(out, "  %s %s: decentralized, authority %s, provider %s; %d proof deliveries pending\n", n.Name, n.ID, n.Authority.State, n.ProviderState.State, len(n.Delivery.Proofs))
		fmt.Fprintf(out, "    person %s; current root %s, epoch %d\n", n.Person, n.Root, n.RootEpoch)
	}
	for _, n := range st.Networks {
		sync := "never synced"
		if n.LastSyncAt != nil {
			sync = "synced " + *n.LastSyncAt
		}
		if n.LastSyncError != nil {
			sync += ", last sync failed: " + *n.LastSyncError
		}
		fmt.Fprintf(out, "  %s %s: legacy history (migration required), %d members, historical coordinator %s, %s\n", n.Name, n.ID, n.Members, n.Coordinator, sync)
		if n.Person == nil {
			fmt.Fprintln(out, "    no person bound to this host")
			continue
		}
		label := n.Person.ID
		if n.Person.Label != nil {
			label = *n.Person.Label
		}
		policy := "no access policy"
		if n.Policy != nil {
			policy = fmt.Sprintf("access policy version %d, valid until %s", n.Policy.Version, n.Policy.ValidUntil)
		}
		fmt.Fprintf(out, "    person %s; %s; %d policy deliveries pending\n", label, policy, n.PolicyDeliveriesPending)
	}
	if len(st.Agents) == 0 {
		fmt.Fprintln(out, "\nAgents: none")
	} else {
		fmt.Fprintln(out, "\nAgents:")
	}
	for _, a := range st.Agents {
		fmt.Fprintf(out, "  %s %s: %d sessions\n", a.Name, a.ID, len(a.Sessions))
		for _, s := range a.Sessions {
			line := fmt.Sprintf("    %s %s", s.ID, s.Integration)
			if s.Connection != nil {
				line += ", " + *s.Connection
			}
			if s.ExpiresAt != nil {
				if s.Renewable {
					line += ", renewable, expires " + *s.ExpiresAt
				} else {
					line += ", expires " + *s.ExpiresAt
				}
			}
			fmt.Fprintln(out, line)
		}
	}
	fmt.Fprintf(out, "\nArtifacts: %d stored and %d pending of %d bytes\n", st.Artifacts.StoredBytes, st.Artifacts.PendingBytes, st.Artifacts.Quota)
	fmt.Fprintf(out, "Blocks: %d\n", st.Blocks)
	if len(st.Attention) == 0 {
		fmt.Fprintln(out, "\nNothing needs attention.")
		return
	}
	fmt.Fprintln(out, "\nNeeds attention:")
	for _, item := range st.Attention {
		fmt.Fprintf(out, "  %s %s: %s\n", item.Kind, item.Subject, item.Detail)
		if item.Command != "" {
			fmt.Fprintf(out, "    run: %s\n", item.Command)
		}
	}
}

// The product status fields are shared, while new network entries retain the
// exact NETWORK_VIEW shape rather than pretending to be legacy coordinator data.
func decodeStatus(raw []byte) (host.Status, []host.DecNetworkView, error) {
	var value map[string]json.RawMessage
	var st host.Status
	modern := []host.DecNetworkView{}
	if e := json.Unmarshal(raw, &value); e != nil {
		return st, nil, e
	}
	var networks []json.RawMessage
	if e := json.Unmarshal(value["networks"], &networks); e != nil {
		return st, nil, e
	}
	delete(value, "networks")
	common, e := json.Marshal(value)
	if e != nil {
		return st, nil, e
	}
	if e = json.Unmarshal(common, &st); e != nil {
		return st, nil, e
	}
	st.Networks = []host.NetworkStatus{}
	for _, raw := range networks {
		var tag struct {
			Mode string `json:"mode"`
		}
		if e = json.Unmarshal(raw, &tag); e != nil {
			return st, nil, e
		}
		if tag.Mode == "decentralized" {
			var n host.DecNetworkView
			if e = json.Unmarshal(raw, &n); e != nil {
				return st, nil, e
			}
			modern = append(modern, n)
		} else {
			var n host.NetworkStatus
			if e = json.Unmarshal(raw, &n); e != nil {
				return st, nil, e
			}
			st.Networks = append(st.Networks, n)
		}
	}
	return st, modern, nil
}
