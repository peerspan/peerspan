package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

func runDecBind(ctx context.Context, client host.Client, fs *pflag.FlagSet, out, errOut io.Writer) error {
	network, _ := fs.GetString("network")
	n, e := decLinkNetwork(ctx, client, network)
	if e != nil {
		return e
	}
	signer, e := person.Load(personKey(fs))
	if e != nil {
		return e
	}
	defer signer.Close()
	public := membership.EncodeKey(signer.PublicKey())
	plan, e := call[decCLIPlanning](ctx, client, "GET", decNetworkPath(n.ID)+"/planning")
	if e != nil {
		return e
	}
	d, e := decLinkDescriptor(plan.Network)
	if e != nil {
		return e
	}
	identity, e := call[host.Identity](ctx, client, "GET", "/v1/host")
	if e != nil {
		return e
	}
	if plan.Network.ID != n.ID || plan.Network.Context != n.Context || plan.Network.Host != identity.PublicKey || plan.Network.Person != "-" && plan.Network.Person != public {
		return errors.New("binding must keep this exact network, original person and owned host")
	}
	catalog, e := dec.ReadCatalog(d, plan.Catalog)
	if e != nil {
		return e
	}
	approve, _ := fs.GetBool("approve")
	if stream, ok := decStream(plan, "binding", identity.PublicKey); ok && (len(stream.Heads) != 0 || stream.Version != 0) {
		// Existing binding eligibility, including unbind/fork/expiry, is checked
		// by the explicit provider route. Never mint a replacement as fallback.
		return selectDecBoundOriginal(ctx, client, plan, public, approve, out, errOut)
	}
	pID, e := decHead(plan, "person", public)
	if e != nil {
		return e
	}
	hID, e := decHead(plan, "host", identity.PublicKey)
	if e != nil {
		return e
	}
	p, h := catalog.Statements[pID], catalog.Statements[hID]
	if p == nil || h == nil || p.Lease == nil || h.Lease == nil {
		return errors.New("proof_required: exact admitted person and own host leases are required")
	}
	if p.Kind != "person_lease" || h.Kind != "host_lease" || p.Lease.Subject.Person != public || h.Lease.Subject.Host != identity.PublicKey || p.Lease.Subject.Member != h.Lease.Subject.Member {
		return errors.New("the admitted person and host do not share the exact reviewed member identity")
	}
	at, e := dec.ParseTime(plan.Time)
	if e != nil {
		return e
	}
	until := at.Add(7 * 24 * time.Hour)
	seen := map[string]bool{}
	var ceiling func(string, int) error
	ceiling = func(id string, depth int) error {
		if depth > dec.MaxDepth {
			return errors.New("quota_exceeded: finite binding ancestry is too deep")
		}
		if seen[id] {
			return nil
		}
		seen[id] = true
		s := catalog.Statements[id]
		if s == nil || s.Lease == nil {
			return errors.New("proof_required: exact finite binding ancestor is missing")
		}
		end, e := dec.ParseTime(s.Lease.After)
		if e != nil {
			return e
		}
		if end.Before(until) {
			until = end
		}
		for _, parent := range s.Lease.Parents {
			if e = ceiling(parent.ID, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	for _, id := range []string{pID, hID} {
		if e = ceiling(id, 0); e != nil {
			return e
		}
	}
	// The public coherent H path includes any current retaining contribution;
	// the daemon still checks the complete current P/H paths before each phase.
	if plan.Network.Authority.NotAfter != "-" {
		end, err := dec.ParseTime(plan.Network.Authority.NotAfter)
		if err != nil {
			return err
		}
		if end.Before(until) {
			until = end
		}
	}
	if !until.After(at) {
		return errors.New("authority_expired")
	}
	payload, e := json.Marshal(dec.Lease{Root: plan.Network.Root, Operation: "-", Sequence: 1, Predecessors: []string{}, Resolves: []string{}, Retained: []string{}, Subject: dec.Subject{Person: public, Host: identity.PublicKey, Device: "-", Member: "-", Scopes: 2}, Issuer: dec.Issuer{Kind: "person", Person: public}, Parents: []dec.Parent{{Role: "issuer_person", ID: pID}, {Role: "subject_host", ID: hID}, {Role: "subject_person", ID: pID}}, Issued: plan.Time, Before: plan.Time, After: until.Format(time.RFC3339)})
	if e != nil {
		return e
	}
	fixed, e := dec.ReadActionPayload(d, "binding_lease", payload)
	if e != nil {
		return e
	}
	input := host.DecActionRequest{Kind: "binding_lease", Provider: public, Format: "sshsig", Payload: base64.StdEncoding.EncodeToString(payload)}
	base := decNetworkPath(n.ID) + "/actions"
	preview, e := linkCall[host.DecActionResult](ctx, client, "POST", base, input)
	if e != nil {
		return e
	}
	check := func(r host.DecActionResult) error {
		if r.ID != dec.ActionID(d.ContextID, "binding_lease", fixed.ID, public) || r.Review.Kind != "binding_lease" || r.Review.Statement != fixed.ID || r.Review.Sequence != 1 || r.Review.After != fixed.Lease.After || r.Review.Provider.Kind != "original_person" || r.Review.Provider.Person != public || r.Review.Provider.Host != identity.PublicKey || r.Review.Provider.Root != fixed.Lease.Root || r.Review.Provider.Lease != pID {
			return errors.New("binding review changes the exact original person, host or finite statement")
		}
		return nil
	}
	if e = check(preview); e != nil {
		return e
	}
	fmt.Fprintf(errOut, "Bind network %s, original person %s, owned host %s until %s, then explicitly select that original provider.\n", n.ID, public, identity.PublicKey, fixed.Lease.After)
	if !approve && (!isTerminal(os.Stdin) || !askYes(errOut, "Bind and select this exact original person on this host?")) {
		if e = printJSON(out, preview); e != nil {
			return e
		}
		return exitStatus(1)
	}
	input.Approve = true
	result, e := linkCall[host.DecActionResult](ctx, client, "POST", base, input)
	if e != nil {
		return e
	}
	if e = check(result); e != nil {
		return e
	}
	if !result.Committed {
		if len(result.Signing) != 1 {
			return errors.New("binding signing is incomplete; retain and resume its exact action")
		}
		slot := result.Signing[0]
		raw, err := base64.StdEncoding.Strict().DecodeString(slot.Template)
		if err != nil {
			return err
		}
		template, err := dec.ReadStatementTemplate(d, raw)
		if err != nil || template.ID != fixed.ID || !bytes.Equal(template.Payload, payload) || slot.Object != fixed.ID || slot.Type != "binding_lease" || slot.Slot != 1 || slot.Role != "issuer" || slot.Public != public || slot.Format != "sshsig" || len(template.Signatures) != 2 {
			return errors.New("binding signing slot changes the exact reviewed template")
		}
		for _, role := range template.Signatures {
			if role.Role == "issuer" {
				if role.PublicKey != public || role.Format != "sshsig" || role.Signature != "-" {
					return errors.New("binding original-person role is not the exact unfilled external slot")
				}
			} else if role.Role != "host" || role.PublicKey != identity.PublicKey || role.Format != "ed25519" || role.Signature == "-" {
				return errors.New("binding lacks the exact durable owned-host consent")
			}
		}
		message := dec.SignatureMessage(fixed.ID, "issuer", public)
		given, err := base64.StdEncoding.Strict().DecodeString(slot.Message)
		if err != nil || !bytes.Equal(given, message) || template.Signer("host") != identity.PublicKey || template.Signer("issuer") != public {
			return errors.New("binding signing changes its exact owner or host role")
		}
		now, err := host.DecentralizedDecisionTime()
		if err != nil || now.Before(at) || now.Sub(at) > 300*time.Second || !now.Before(until) {
			return errors.New("binding signing window expired or clock rolled back; retain the exact action")
		}
		signature, err := membership.SignSSHSIG(signer, message)
		if err != nil {
			return err
		}
		result, e = linkCall[host.DecActionResult](ctx, client, "POST", base+"/"+url.PathEscape(result.ID)+"/signed", map[string]any{"intent_id": slot.Intent, "signatures": []map[string]any{{"slot_id": slot.Slot, "role": slot.Role, "signature": signature}}})
		if e != nil {
			return e
		}
	}
	if e = check(result); e != nil {
		return e
	}
	if !result.Committed || len(result.Signing) != 0 {
		return errors.New("binding remains incomplete; no provider was selected")
	}
	envelope, e := base64.StdEncoding.Strict().DecodeString(result.Statement)
	if e != nil {
		return e
	}
	complete, e := dec.ReadStatement(d, envelope)
	if e != nil || complete.ID != fixed.ID || !bytes.Equal(complete.Payload, payload) || result.Proof != dec.ProofID("binding_lease", envelope) {
		return errors.New("applied binding differs from the exact reviewed statement")
	}
	return selectDecBoundOriginal(ctx, client, plan, public, true, out, errOut)
}

func selectDecBoundOriginal(ctx context.Context, client host.Client, plan decCLIPlanning, public string, approve bool, out, errOut io.Writer) error {
	input := host.DecSelectProvider{Provider: public, Person: public, Host: plan.Network.Host}
	path := decNetworkPath(plan.Network.ID) + "/provider"
	type selection struct {
		Network  host.DecNetworkView   `json:"network"`
		Provider *host.DecProviderView `json:"provider"`
		State    host.DecProviderState `json:"provider_state"`
	}
	preview, e := linkCall[selection](ctx, client, "POST", path, input)
	if e != nil {
		return e
	}
	if preview.Network.ID != plan.Network.ID || preview.Network.Context != plan.Network.Context || preview.Provider == nil || preview.Provider.Kind != "original_person" || preview.Provider.Person != public || preview.Provider.Host != plan.Network.Host {
		return errors.New("provider selection changes the exact reviewed binding")
	}
	if !approve {
		fmt.Fprintf(errOut, "Select exact original person %s on host %s in network %s.\n", public, plan.Network.Host, plan.Network.ID)
		if !isTerminal(os.Stdin) || !askYes(errOut, "Select this exact original provider?") {
			if e = printJSON(out, preview); e != nil {
				return e
			}
			return exitStatus(1)
		}
	}
	input.Approve = true
	result, e := linkCall[selection](ctx, client, "POST", path, input)
	if e != nil {
		return e
	}
	if result.Network.ID != plan.Network.ID || result.Network.Context != plan.Network.Context || result.Network.Person != public || result.Provider == nil || result.Provider.Kind != "original_person" || result.Provider.Person != public || result.Provider.Host != plan.Network.Host {
		return errors.New("provider selection response changes the exact approved identity")
	}
	return printJSON(out, result)
}
