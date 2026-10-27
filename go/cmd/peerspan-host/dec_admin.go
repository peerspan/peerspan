package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/spf13/pflag"
	"io"
	"sort"
	"time"
)

// A planning head supplies a version/parent proposal only. The owner-local
// action verifier independently checks its actual current authority before any
// signature; this helper never derives an admitted prior from public bodies.
func runDecGroupSet(ctx context.Context, client host.Client, fs *pflag.FlagSet, out, errOut io.Writer) (bool, error) {
	network, _ := fs.GetString("network")
	n, e := decLinkNetwork(ctx, client, network)
	if errors.Is(e, errNotJoined) {
		return false, nil
	}
	if e != nil {
		return true, e
	}
	plan, e := call[decCLIPlanning](ctx, client, "GET", decNetworkPath(n.ID)+"/planning")
	if e != nil {
		return true, e
	}
	d, e := decLinkDescriptor(plan.Network)
	if e != nil {
		return true, e
	}
	if plan.Network.ID != n.ID || plan.Network.Context != n.Context {
		return true, errors.New("network changed during group review")
	}
	catalog, e := dec.ReadCatalog(d, plan.Catalog)
	if e != nil {
		return true, e
	}
	name, _ := fs.GetString("group")
	if name == "" {
		return true, errors.New("--group is required")
	}
	given, _ := fs.GetStringArray("person")
	members := []string{}
	for _, value := range given {
		p, e := resolvePerson(ctx, client, n.ID, value)
		if e != nil {
			return true, e
		}
		key, e := membership.DecodeKey(p.PublicKey)
		if e != nil || membership.PersonID(key) != p.PersonID {
			return true, errors.New("group member changes the exact verified person identity")
		}
		members = append(members, p.PersonID)
	}
	sort.Strings(members)
	unique := []string{}
	for _, p := range members {
		if len(unique) == 0 || unique[len(unique)-1] != p {
			unique = append(unique, p)
		}
	}
	stream, _ := decStream(plan, "group", name)
	if len(stream.Heads) > 1 {
		return true, errors.New("state_conflict: resolve all exact group heads before a fresh definition")
	}
	if stream.Version == ^uint64(0) {
		return true, errors.New("version_exhausted")
	}
	a, e := decNativeAuthorityFor(ctx, client, plan, d, catalog, fs, 8, true, 24*time.Hour)
	if e != nil {
		return true, e
	}
	now, until, issuer, parents := a.Now, a.Until, a.Issuer, a.Parents
	issued := now.Format(time.RFC3339)
	body, e := json.Marshal(map[string]any{"network_id": n.ID, "name": name, "version": stream.Version + 1, "defined_at": issued, "members": unique})
	if e != nil {
		return true, e
	}
	payload, e := json.Marshal(dec.Access{Root: plan.Network.Root, Operation: "-", Sequence: stream.Version + 1, Predecessors: append([]string{}, stream.Heads...), Resolves: []string{}, Issuer: issuer, Parents: parents, Issued: issued, Before: issued, After: until.Format(time.RFC3339), BodyBase64: base64.StdEncoding.EncodeToString(body)})
	if e != nil {
		return true, e
	}
	fixed, e := dec.ReadActionPayload(d, "group", payload)
	if e != nil {
		return true, e
	}
	result, e := runDecNativeAction(ctx, client, a, fixed, fs, out, errOut, "Approve this exact finite group definition?")
	if e != nil {
		return true, e
	}
	return true, printJSON(out, result)
}
