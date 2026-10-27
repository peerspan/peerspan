package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/spf13/pflag"
)

// Display uses the current verified read API without requiring a signing key.
// Retained historical heads remain available through the exact catalog reader.
func runDecAccessShow(ctx context.Context, client host.Client, fs *pflag.FlagSet, out io.Writer) (bool, error) {
	network, _ := fs.GetString("network")
	if network == "" {
		return true, errors.New("access show needs --network")
	}
	networks, e := call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
	if e != nil {
		return true, e
	}
	var selected *host.DecNetworkView
	for _, n := range networks {
		if n.ID == network || n.Name == network {
			copy := n
			selected = &copy
			break
		}
	}
	if selected == nil {
		return false, nil
	}
	people, e := decCurrentPeople(ctx, client, *selected)
	if e != nil {
		return true, e
	}
	given, _ := fs.GetString("person")
	if given == "" {
		public, e := membership.DecodeKey(selected.Host)
		if e != nil {
			return true, e
		}
		for _, p := range people {
			for _, h := range p.Hosts {
				if h == membership.HostID(public) {
					given = p.PublicKey
				}
			}
		}
		if given == "" {
			return true, errors.New("this host has no current bound person; give --person")
		}
	}
	person, e := host.ResolvePerson(people, given)
	if e != nil {
		return true, e
	}
	statement, e := decReadCurrentPolicy(ctx, client, *selected, person.PublicKey)
	if e != nil {
		return true, e
	}
	return true, printJSON(out, json.RawMessage(statement.Raw))
}
