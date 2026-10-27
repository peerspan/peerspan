package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/spf13/pflag"
)

func decNativeTargetPerson(ctx context.Context, client host.Client, network, given string) (string, error) {
	if dec.ValidPublicKey(given) {
		return given, nil
	}
	if given == "" {
		return "", errors.New("--person is required")
	}
	p, e := resolvePerson(ctx, client, network, given)
	if e != nil {
		return "", e
	}
	return p.PublicKey, nil
}
func decNativeTargetHost(ctx context.Context, client host.Client, n host.DecNetworkView, given string) (string, error) {
	if dec.ValidPublicKey(given) {
		return given, nil
	}
	if given == "" {
		return "", errors.New("--host is required")
	}
	view, e := call[struct {
		Context string               `json:"context_id"`
		Members []host.DecMemberView `json:"members"`
	}](ctx, client, "GET", decNetworkPath(n.ID)+"/members")
	if e != nil {
		return "", e
	}
	if view.Context != n.Context || view.Members == nil {
		return "", errors.New("member view changes selected context")
	}
	found := ""
	for _, member := range view.Members {
		key, e := membership.DecodeKey(member.Host)
		if e != nil {
			return "", e
		}
		if given == membership.HostID(key) || given == member.Member {
			if found != "" && found != member.Host {
				return "", errors.New("ambiguous host label; give its exact public key or host ID")
			}
			found = member.Host
		}
	}
	if found == "" {
		return "", errors.New("host not found; an inactive target requires its exact stable public key")
	}
	return found, nil
}
func decNativeExactIDs(ids []string) ([]string, error) {
	ids = append([]string{}, ids...)
	sort.Strings(ids)
	for n, id := range ids {
		if !dec.ValidID(id, "ds_") || n > 0 && id == ids[n-1] {
			return nil, errors.New("expected unique exact ds_ references")
		}
	}
	return ids, nil
}
func runDecAdminMutation(ctx context.Context, client host.Client, command string, fs *pflag.FlagSet, out, errOut io.Writer) (bool, error) {
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
		return true, errors.New("network changed during administration review")
	}
	catalog, e := dec.ReadCatalog(d, plan.Catalog)
	if e != nil {
		return true, e
	}
	roleRoot := command == "delegate-admin" || command == "remove-admin"
	if roleRoot {
		signer, _ := fs.GetString("signer")
		root, _ := fs.GetString("root-key")
		if signer != "network_root" && root == "" {
			return true, errors.New("forbidden: this root-only role action requires explicit --signer network_root or --root-key")
		}
	}
	needed, rootAllowed := uint64(8), true
	if command == "unbind" {
		needed, rootAllowed = 2, false
	}
	a, e := decNativeAuthorityFor(ctx, client, plan, d, catalog, fs, needed, rootAllowed, 7*24*time.Hour)
	if e != nil {
		return true, e
	}
	if roleRoot && a.Issuer.Kind != "root" {
		return true, errors.New("forbidden: only the exact current root may grant or withdraw the administrator role")
	}
	target := dec.Target{Person: "-", Host: "-", Device: "-", Statement: "-"}
	kept := []string{}
	kind := ""
	var payload []byte
	switch command {
	case "delegate-admin":
		given, _ := fs.GetString("person")
		target.Person, e = decNativeTargetPerson(ctx, client, n.ID, given)
		if e != nil {
			return true, e
		}
		stream, _ := decStream(plan, "admin", target.Person)
		if stream.Version == ^uint64(0) {
			return true, errors.New("version_exhausted")
		}
		resolves, _ := fs.GetStringArray("resolve")
		if len(stream.Heads) > 1 {
			resolves = append(resolves, stream.Heads...)
		}
		// Only explicit restriction IDs are proposed. Public presence does not make
		// a withdrawal known/admitted or authorize a silent role restoration.
		set := map[string]bool{}
		for _, id := range resolves {
			set[id] = true
		}
		resolves = decCLISorted(set)
		resolves, e = decNativeExactIDs(resolves)
		if e != nil {
			return true, e
		}
		until := a.Until
		if explicit, _ := fs.GetString("not-after"); explicit != "" {
			until, e = dec.ParseTime(explicit)
			if e != nil {
				return true, e
			}
			if !until.After(a.Now) || until.After(a.Until) {
				return true, errors.New("not-after exceeds the current seven-day finite ceiling")
			}
		}
		kind = "admin_lease"
		payload, e = json.Marshal(dec.Lease{Root: plan.Network.Root, Operation: "-", Sequence: stream.Version + 1, Predecessors: append([]string{}, stream.Heads...), Resolves: resolves, Retained: []string{}, Subject: dec.Subject{Person: target.Person, Host: "-", Device: "-", Member: "-", Scopes: 8}, Issuer: a.Issuer, Parents: a.Parents, Issued: a.Now.Format(time.RFC3339), Before: a.Now.Format(time.RFC3339), After: until.Format(time.RFC3339)})
	case "remove-admin":
		given, _ := fs.GetString("person")
		target.Person, e = decNativeTargetPerson(ctx, client, n.ID, given)
		if e != nil {
			return true, e
		}
		exact, _ := fs.GetString("statement")
		if exact == "" {
			exact, e = decHead(plan, "admin", target.Person)
			if e != nil {
				return true, e
			}
		}
		if exact == "-" {
			return true, errors.New("not_found: no remembered administrator role for this person")
		}
		if !dec.ValidID(exact, "ds_") {
			return true, errors.New("invalid exact administrator role ID")
		}
		role := catalog.Statements[exact]
		if role == nil {
			return true, fmt.Errorf("proof_required: exact administrator lease %s is missing", exact)
		}
		if role.Kind != "admin_lease" || role.Lease.Subject.Person != target.Person {
			return true, errors.New("administrator target does not match the exact reviewed person")
		}
		target.Statement = exact
		kind = "admin_withdraw"
		kept, _ = fs.GetStringArray("keep")
		drop, _ := fs.GetBool("revoke-admitted")
		if drop && len(kept) > 0 {
			return true, errors.New("--keep and --revoke-admitted are mutually exclusive")
		}
		if !drop && !fs.Changed("keep") {
			return true, errors.New("review_required: give every exact --keep admission, or explicitly --revoke-admitted; no role-specific retention default is inferred from raw heads")
		}
		kept, e = decNativeExactIDs(kept)
		if e != nil {
			return true, e
		}
		for _, id := range kept {
			p := catalog.Statements[id]
			if p == nil {
				return true, fmt.Errorf("proof_required: kept admission %s is missing", id)
			}
			if p.Lease == nil || p.Kind != "person_lease" && p.Kind != "host_lease" {
				return true, errors.New("kept role withdrawal accepts exact person/host admissions only")
			}
			found := false
			for _, parent := range p.Lease.Parents {
				found = found || parent.Role == "issuer_admin" && parent.ID == exact
			}
			if !found {
				return true, errors.New("kept admission was not issued under this exact administrator role")
			}
		}
	case "remove-person":
		given, _ := fs.GetString("person")
		target.Person, e = decNativeTargetPerson(ctx, client, n.ID, given)
		if e != nil {
			return true, e
		}
		kind = "person_remove"
	case "revoke":
		given, _ := fs.GetString("host")
		target.Host, e = decNativeTargetHost(ctx, client, n, given)
		if e != nil {
			return true, e
		}
		kind = "host_revoke"
	case "unbind":
		given, _ := fs.GetString("host")
		target.Host, e = decNativeTargetHost(ctx, client, n, given)
		if e != nil {
			return true, e
		}
		id, e := decHead(plan, "binding", target.Host)
		if e != nil {
			return true, e
		}
		if id == "-" {
			return true, errors.New("not_found: no remembered owner binding for this host")
		}
		b := catalog.Statements[id]
		if b == nil {
			return true, fmt.Errorf("proof_required: exact binding %s is missing", id)
		}
		if b.Kind != "binding_lease" || b.Lease.Subject.Host != target.Host || b.Lease.Subject.Person != a.Issuer.Person {
			return true, errors.New("forbidden: unbind requires this exact original owner or same-person bound device2")
		}
		target.Person, target.Statement = b.Lease.Subject.Person, id
		kind = "host_unbind"
	default:
		return true, invalidCommand()
	}
	if e != nil {
		return true, e
	}
	if payload == nil {
		payload, e = json.Marshal(dec.Restriction{Root: plan.Network.Root, Issuer: a.Issuer, Parents: a.Parents, Issued: a.Now.Format(time.RFC3339), Target: target, Kept: kept, Ratifies: "-"})
		if e != nil {
			return true, e
		}
	}
	fixed, e := dec.ReadActionPayload(d, kind, payload)
	if e != nil {
		return true, e
	}
	prompt := "Approve this exact administration action?"
	if kind == "host_unbind" {
		prompt = "Approve withdrawal of only this exact owner binding?"
	}
	if kind == "person_remove" || kind == "host_revoke" {
		prompt = "Approve this irreversible stable-key network ban?"
	}
	result, e := runDecNativeAction(ctx, client, a, fixed, fs, out, errOut, prompt)
	if e != nil {
		return true, e
	}
	return true, printJSON(out, result)
}
