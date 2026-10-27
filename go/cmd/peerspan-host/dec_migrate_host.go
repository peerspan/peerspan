package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/pflag"
)

func runDecMigrationHost(ctx context.Context, client host.Client, network, proposal string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	path, _ := fs.GetString("host-lease-file")
	raw, e := migrationCLIFile(path, dec.MaxObject)
	if e != nil {
		return e
	}
	evidence, e := linkCall[host.DecMigrationEvidence](ctx, client, "GET", decNetworkPath(network)+"/migration/evidence", nil)
	if e != nil {
		return e
	}
	d, e := migrationCLIDescriptor(evidence.Proposal)
	if e != nil {
		return e
	}
	p, e := dec.ReadStatement(d, evidence.Proposal)
	if e != nil {
		return e
	}
	statement, e := dec.ReadStatementTemplate(d, raw)
	if e != nil {
		return e
	}
	own, e := call[host.Identity](ctx, client, "GET", "/v1/host")
	if e != nil {
		return e
	}
	l := statement.Lease
	if d.NetworkID != network || p.ID != proposal || statement.Kind != "host_lease" || l == nil || l.Operation != proposal || l.Subject.Host != own.PublicKey || l.Subject.Person != "-" || l.Subject.Device != "-" || l.Subject.Scopes != 0 {
		return errors.New("the host-membership template does not name this exact unbound local host and proposal")
	}
	input := host.DecMigrationHostLease{Proposal: proposal, Template: base64.StdEncoding.EncodeToString(raw)}
	base := decNetworkPath(network) + "/migration/host-lease"
	result, e := linkCall[host.DecMigrationHostResult](ctx, client, "POST", base, input)
	if e != nil {
		return e
	}
	r := result.Review
	if r.Stage != "host_membership" || r.Network != network || r.Proposal != proposal || r.Host != own.PublicKey || r.Member != l.Subject.Member || r.Root != l.Root || r.Lease != statement.ID || r.Issued != l.Issued || r.Before != l.Before || r.After != l.After || r.Warning == "" || result.Migration.Context != d.ContextID || result.Migration.Proposal != proposal || len(result.Signing) != 0 {
		return errors.New("the host-membership preview changes its exact typed template or identity")
	}
	_, _ = fmt.Fprintf(errOut, "Host membership %s: network %s proposal %s root %s\nHost %s member %s; issued %s valid %s through %s\n%s\n", r.Lease, network, proposal, r.Root, r.Host, r.Member, r.Issued, r.Before, r.After, r.Warning)
	approve, _ := fs.GetBool("approve")
	if approve || isTerminal(os.Stdin) && askYes(errOut, "Approve only this finite host membership, without acknowledgment or adoption?") {
		input.Approve = true
		result, e = linkCall[host.DecMigrationHostResult](ctx, client, "POST", base, input)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(result.Review, r) || len(result.Signing) != 0 {
			return errors.New("host-membership approval changes the fixed review")
		}
		body, e := base64.StdEncoding.Strict().DecodeString(result.Template)
		if e != nil {
			return e
		}
		full, e := dec.ReadStatement(d, body)
		if e != nil {
			return e
		}
		if full.ID != statement.ID || !bytes.Equal(full.Payload, statement.Payload) || full.Signer("host") != own.PublicKey || full.Signer("issuer") != statement.Signer("issuer") {
			return errors.New("completed host membership changes its original payload or signers")
		}
		for _, role := range statement.Signatures {
			if role.Role == "issuer" {
				found := false
				for _, other := range full.Signatures {
					found = found || other == role
				}
				if !found {
					return errors.New("host membership replaces the original issuer signature")
				}
			}
		}
	}
	return printJSON(out, result)
}
