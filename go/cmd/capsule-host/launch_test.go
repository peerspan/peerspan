package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// helpCommands parses the Commands section of a help text.
func helpCommands(t *testing.T, args ...string) []string {
	t.Helper()
	var out bytes.Buffer
	if err := run(context.Background(), args, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.String(), "\n")
	var paths []string
	for i, line := range lines {
		if line != "Commands:" {
			continue
		}
		for _, entry := range lines[i+1:] {
			if strings.TrimSpace(entry) == "" {
				break
			}
			path, _, _ := strings.Cut(strings.TrimSpace(entry), "  ")
			paths = append(paths, path)
		}
	}
	return paths
}

func TestRootHelpListsMainCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"help"}} {
		if paths := helpCommands(t, args...); !reflect.DeepEqual(paths, rootCommands) {
			t.Fatalf("%v listed %v", args, paths)
		}
	}
	advanced := helpCommands(t, "help", "advanced")
	if !reflect.DeepEqual(advanced, helpCommands(t, "--help-advanced")) {
		t.Fatal("help advanced and --help-advanced differ")
	}
	listed := map[string]bool{}
	for _, path := range advanced {
		listed[path] = true
	}
	for _, path := range append(append([]string{}, rootCommands...), "grant create", "adapter route add", "network revoke", "activity", "info") {
		if !listed[path] {
			t.Fatalf("help advanced omits %s", path)
		}
	}
}

// resolved runs a command's expiry resolution and returns its --expires-at.
func resolved(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newCommand(io.Discard, io.Discard)
	var expiresAt string
	var resolveErr error
	var replace func(*cobra.Command)
	replace = func(cmd *cobra.Command) {
		if cmd.RunE != nil && cmd != root {
			cmd.RunE = func(cmd *cobra.Command, positional []string) error {
				resolveErr = resolveExpiry(strings.Fields(commandPath(cmd)), cmd.Flags())
				expiresAt, _ = cmd.Flags().GetString("expires-at")
				return nil
			}
		}
		for _, child := range cmd.Commands() {
			replace(child)
		}
	}
	replace(root)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	return expiresAt, resolveErr
}

func TestExpiryDefaults(t *testing.T) {
	near := func(value string, want time.Duration) bool {
		at, err := time.Parse(time.RFC3339, value)
		return err == nil && (time.Until(at)-want).Abs() < time.Minute
	}
	for _, tc := range []struct {
		args []string
		want time.Duration
	}{
		{[]string{"grant", "create"}, 30 * 24 * time.Hour},
		{[]string{"network", "invite"}, 7 * 24 * time.Hour},
		{[]string{"network", "invite-person"}, 7 * 24 * time.Hour},
		{[]string{"grant", "create", "--expires-in", "90m"}, 90 * time.Minute},
		{[]string{"adapter", "create", "--expires-in", "2h"}, 2 * time.Hour},
		{[]string{"adapter", "route", "add", "--expires-in", "1h"}, time.Hour},
		{[]string{"adapter", "create"}, 0},
		{[]string{"adapter", "route", "add"}, 0},
	} {
		value, err := resolved(t, tc.args...)
		if err != nil || (tc.want == 0 && value != "") || (tc.want != 0 && !near(value, tc.want)) {
			t.Fatalf("%v: %q %v", tc.args, value, err)
		}
	}
	if value, err := resolved(t, "grant", "create", "--expires-at", "2099-01-01T00:00:00Z"); err != nil || value != "2099-01-01T00:00:00Z" {
		t.Fatalf("explicit expiry changed: %q %v", value, err)
	}
	if _, err := resolved(t, "network", "invite", "--expires-at", "2099-01-01T00:00:00Z", "--expires-in", "1h"); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("both expiry flags: %v", err)
	}
	if _, err := resolved(t, "adapter", "create", "--expires-in", "721h"); err == nil {
		t.Fatal("out-of-range --expires-in accepted")
	}
}

func TestNetworkDefaulting(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var networks []host.Network
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(networks)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	client := host.Client{SocketPath: socket}
	flags := func() *pflag.FlagSet {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		fs.String("network", "", "")
		return fs
	}
	ctx := context.Background()
	if _, err := defaultNetwork(ctx, client, []string{"network", "members"}, flags()); err == nil || err.Error() != "not a member of any network" {
		t.Fatalf("no network: %v", err)
	}
	networks = []host.Network{{ID: "net_a", Name: "one"}}
	if args, err := defaultNetwork(ctx, client, []string{"network", "members"}, flags()); err != nil || !reflect.DeepEqual(args, []string{"network", "members", "net_a"}) {
		t.Fatalf("one network: %v %v", args, err)
	}
	fs := flags()
	if _, err := defaultNetwork(ctx, client, []string{"access", "show"}, fs); err != nil {
		t.Fatal(err)
	}
	if value, _ := fs.GetString("network"); value != "net_a" {
		t.Fatalf("--network defaulted to %q", value)
	}
	if args, err := defaultNetwork(ctx, client, []string{"network", "leave"}, flags()); err != nil || len(args) != 2 {
		t.Fatalf("leave was defaulted: %v %v", args, err)
	}
	networks = append(networks, host.Network{ID: "net_b", Name: "two"})
	_, err = defaultNetwork(ctx, client, []string{"access", "show"}, flags())
	for _, want := range []string{"net_a", "one", "net_b", "two"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("two networks: %v", err)
		}
	}
}

func TestStatusWithoutDaemon(t *testing.T) {
	state := t.TempDir()
	var out bytes.Buffer
	err := run(context.Background(), []string{"--state", state, "status", "--json"}, &out, io.Discard)
	var code exitStatus
	if !errors.As(err, &code) || code != 2 {
		t.Fatalf("exit %v", err)
	}
	var value map[string]string
	if err := json.Unmarshal(out.Bytes(), &value); err != nil || value["daemon"] != "not running" || value["state"] != state {
		t.Fatalf("output %s: %v", out.String(), err)
	}
}
