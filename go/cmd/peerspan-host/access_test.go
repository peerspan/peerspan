package main

import (
	"context"
	"io"
	"testing"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/cobra"
)

// accessSync parses through the real command tree and returns the access request.
func accessSync(args ...string) (method, path string, body any, err error) {
	root := newCommand(io.Discard, io.Discard)
	sync, _, findErr := root.Find([]string{"access", "sync"})
	if findErr != nil {
		return "", "", nil, findErr
	}
	sync.RunE = func(cmd *cobra.Command, _ []string) error {
		method, path, body, err = accessRequest(context.Background(), host.Client{}, []string{"access", "sync"}, cmd.Flags())
		return nil
	}
	root.SetArgs(append([]string{"access", "sync"}, args...))
	if execErr := root.Execute(); execErr != nil {
		return "", "", nil, execErr
	}
	return
}

func TestAccessSyncRequest(t *testing.T) {
	for args, want := range map[[2]string]string{
		{"--network", "net_x"}:          "POST /v1/networks/net_x/policy/sync",
		{"--network=net_x", "--status"}: "GET /v1/networks/net_x/policy/sync",
	} {
		method, path, body, err := accessSync(args[0], args[1])
		if err != nil || method+" "+path != want || body != nil {
			t.Errorf("%v: %s %s %v %v", args, method, path, body, err)
		}
	}
	if _, _, _, err := accessSync("--status"); err == nil {
		t.Error("access sync without --network")
	}
}
