package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
	"io"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

type decNativeAuthority struct {
	Plan                        decCLIPlanning
	Descriptor                  dec.Descriptor
	Catalog                     *dec.Catalog
	ProviderID, Format, KeyPath string
	Issuer                      dec.Issuer
	Parents                     []dec.Parent
	Provider                    *host.DecProviderView
	Now, Until                  time.Time
	Needed                      uint64
}

func decNativeAuthorityFor(ctx context.Context, client host.Client, plan decCLIPlanning, d dec.Descriptor, catalog *dec.Catalog, fs *pflag.FlagSet, needed uint64, rootAllowed bool, span time.Duration) (*decNativeAuthority, error) {
	now, e := host.DecentralizedDecisionTime()
	if e != nil {
		return nil, e
	}
	now = now.UTC().Truncate(time.Second)
	until := now.Add(span)
	providerID, _ := fs.GetString("signer")
	format, keyPath := "auto", personKey(fs)
	if providerID != "auto" && providerID != "network_root" && !dec.ValidPublicKey(providerID) && !dec.ValidID(providerID, "ds_") {
		return nil, errors.New("--signer must be auto, network_root, or the exact original/device provider")
	}
	issuer := dec.Issuer{Kind: "person", Person: plan.Network.Person}
	parents := []dec.Parent{}
	rootPath, _ := fs.GetString("root-key")
	if rootPath != "" && keyPath != "" {
		return nil, errors.New("choose one exact root or original-person key")
	}
	if rootPath != "" && providerID != "auto" && providerID != "network_root" {
		return nil, errors.New("--root-key conflicts with the explicit non-root signer")
	}
	if rootPath != "" {
		providerID = "network_root"
	}
	var selected *host.DecProviderView
	if providerID == "network_root" {
		if !rootAllowed {
			return nil, errors.New("forbidden: root cannot replace this owner authority")
		}
		if keyPath != "" {
			return nil, errors.New("root signing uses --root-key, not --person-key")
		}
		issuer = dec.Issuer{Kind: "root", Person: "-"}
		if rootPath != "" {
			key, e := person.Load(rootPath)
			if e != nil {
				return nil, e
			}
			public := membership.EncodeKey(key.PublicKey())
			key.Close()
			if public != plan.Network.RootKey || !dec.ValidID(plan.Network.Root, "ds_") {
				return nil, errors.New("the explicit root key does not match the unique current root")
			}
			providerID, format, keyPath = "network_root", "sshsig", rootPath
		}
	} else {
		selected = plan.Network.Provider
		if keyPath != "" {
			key, e := person.Load(keyPath)
			if e != nil {
				return nil, e
			}
			public := membership.EncodeKey(key.PublicKey())
			key.Close()
			if providerID != "auto" && providerID != public {
				return nil, errors.New("the original key conflicts with the explicit signer")
			}
			providerID = public
			format = "sshsig"
		}
		if providerID != "auto" {
			preview, e := linkCall[struct {
				Provider *host.DecProviderView `json:"provider"`
			}](ctx, client, "POST", decNetworkPath(plan.Network.ID)+"/provider", host.DecSelectProvider{Provider: providerID, Person: plan.Network.Person, Host: plan.Network.Host, Approve: false})
			if e != nil {
				return nil, e
			}
			selected = preview.Provider
		} else if plan.Network.ProviderState.State != "available" {
			return nil, fmt.Errorf("selected provider requires repair: %s", plan.Network.ProviderState.Code)
		}
		if selected == nil || selected.Person != plan.Network.Person || selected.Host != plan.Network.Host || selected.Scopes&needed != needed {
			return nil, errors.New("forbidden: this exact selected provider lacks current required authority")
		}
		issuer.Person = selected.Person
		roles := []struct{ stream, role string }{{"person", "issuer_person"}}
		if needed == 8 {
			roles = append(roles, struct{ stream, role string }{"admin", "issuer_admin"})
		}
		for _, role := range roles {
			id, e := decHead(plan, role.stream, selected.Person)
			if e != nil {
				return nil, e
			}
			if id == "-" {
				return nil, errors.New("proof_required: current administrator/person lease is missing")
			}
			parents = append(parents, dec.Parent{Role: role.role, ID: id})
		}
		if selected.Kind == "device" {
			issuer.Kind = "device"
			parents = append(parents, dec.Parent{Role: "issuer_device", ID: selected.Lease})
		}
		if selected.Kind != "device" && selected.Kind != "original_person" {
			return nil, errors.New("invalid action provider role")
		}
		if needed == 8 && selected.NotAfter != "-" {
			at, e := dec.ParseTime(selected.NotAfter)
			if e != nil {
				return nil, e
			}
			if at.Before(until) {
				until = at
			}
		}
	}
	seen := map[string]bool{}
	var capParent func(string, int) error
	capParent = func(id string, depth int) error {
		if depth > dec.MaxDepth {
			return errors.New("quota_exceeded: action ancestry exceeds bound")
		}
		if seen[id] {
			return nil
		}
		seen[id] = true
		p := catalog.Statements[id]
		if p == nil || p.Lease == nil {
			return errors.New("proof_required: exact action issuer ancestry is missing")
		}
		at, e := dec.ParseTime(p.Lease.After)
		if e != nil {
			return e
		}
		if at.Before(until) {
			until = at
		}
		for _, parent := range p.Lease.Parents {
			if e = capParent(parent.ID, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	for _, parent := range parents {
		if e = capParent(parent.ID, 0); e != nil {
			return nil, e
		}
	}
	if !until.After(now) {
		return nil, errors.New("authority_expired")
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i].Role < parents[j].Role })

	return &decNativeAuthority{Plan: plan, Descriptor: d, Catalog: catalog, ProviderID: providerID, Format: format, KeyPath: keyPath, Issuer: issuer, Parents: parents, Provider: selected, Now: now, Until: until, Needed: needed}, nil
}

func decNativeActionSubject(s *dec.Statement) (json.RawMessage, uint64, string, error) {
	if s.Lease != nil {
		b, e := json.Marshal(s.Lease.Subject)
		return b, s.Lease.Sequence, s.Lease.After, e
	}
	if s.Restriction != nil {
		b, e := json.Marshal(s.Restriction.Target)
		return b, 0, "-", e
	}
	if s.Access != nil && s.Kind == "group" {
		b, e := json.Marshal(map[string]json.RawMessage{"name": s.Body["name"]})
		return b, s.Access.Sequence, s.Access.After, e
	}
	return nil, 0, "", errors.New("unsupported native action subject")
}
func checkDecNativeActionReview(result host.DecActionResult, a *decNativeAuthority, s *dec.Statement) error {
	subject, seq, after, e := decNativeActionSubject(s)
	if e != nil {
		return e
	}
	if !dec.ValidID(result.ID, "act_") || result.Review.Kind != s.Kind || result.Review.Statement != s.ID || result.Review.Sequence != seq || result.Review.After != after || result.Review.Warning == "" || result.Signing == nil {
		return errors.New("action changes the exact kind/statement/deadline")
	}
	var want, got map[string]json.RawMessage
	if json.Unmarshal(subject, &want) != nil {
		return errors.New("invalid typed action subject")
	}
	fields := []string{}
	for field := range want {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	if dec.ReadPrivateRecord(result.Review.Subject, strings.Join(fields, " "), &got) != nil {
		return errors.New("action changes exact subject")
	}
	for field, raw := range want {
		var x, y any
		if json.Unmarshal(raw, &x) != nil || json.Unmarshal(got[field], &y) != nil || !reflect.DeepEqual(x, y) {
			return errors.New("action changes exact subject field")
		}
	}
	p := result.Review.Provider
	if p.Root != a.Plan.Network.Root || p.Scopes&a.Needed != a.Needed {
		return errors.New("action changes the current root/required provider power")
	}
	if a.ProviderID == "network_root" {
		if p.Kind != "network_root" || p.Scopes != 8 || p.Person != "-" || p.Host != "-" || p.Device != "-" || p.Lease != "-" {
			return errors.New("root review claims an owner binding")
		}
	} else if a.Provider == nil || p.Kind != a.Provider.Kind || p.Person != a.Provider.Person || p.Host != a.Provider.Host || p.Device != a.Provider.Device || p.Lease != a.Provider.Lease {
		return errors.New("action changes the explicit selected provider")
	}
	return nil
}
func (a *decNativeAuthority) signerKey() string {
	if a.Provider == nil {
		return a.Plan.Network.RootKey
	}
	if a.Provider.Kind == "device" {
		return a.Provider.Device
	}
	return a.Provider.Person
}
func runDecNativeAction(ctx context.Context, client host.Client, a *decNativeAuthority, s *dec.Statement, fs *pflag.FlagSet, out, errOut io.Writer, prompt string) (result host.DecActionResult, err error) {
	base := decNetworkPath(a.Plan.Network.ID) + "/actions"
	request := host.DecActionRequest{Kind: s.Kind, Provider: a.ProviderID, Format: a.Format, Payload: base64.StdEncoding.EncodeToString(s.Payload)}
	preview, e := linkCall[host.DecActionResult](ctx, client, "POST", base, request)
	if e != nil {
		return result, e
	}
	result = preview
	if err = checkDecNativeActionReview(result, a, s); err != nil {
		return result, err
	}
	_, _ = fmt.Fprintf(errOut, "Action %s; exact statement %s; kind %s\nProvider %s key %s; root %s; person %s; host %s; device %s; lease %s\nSubject %s; finite deadline %s\n%s\n", result.ID, s.ID, s.Kind, result.Review.Provider.Kind, a.signerKey(), result.Review.Provider.Root, result.Review.Provider.Person, result.Review.Provider.Host, result.Review.Provider.Device, result.Review.Provider.Lease, string(result.Review.Subject), result.Review.After, result.Review.Warning)
	_, _ = fmt.Fprintf(errOut, "Provider finite ceiling %s; exact issuer parents %v\n", result.Review.Provider.NotAfter, a.Parents)
	if s.Access != nil {
		_, _ = fmt.Fprintf(errOut, "Sequence %d; predecessors %v; resolves %v\n", s.Access.Sequence, s.Access.Predecessors, s.Access.Resolves)
	}
	if s.Lease != nil {
		_, _ = fmt.Fprintf(errOut, "Sequence %d; predecessors %v; resolves %v; retained %v; exact parents %v\n", s.Lease.Sequence, s.Lease.Predecessors, s.Lease.Resolves, s.Lease.Retained, s.Lease.Parents)
	}
	if s.Restriction != nil {
		_, _ = fmt.Fprintf(errOut, "Exact kept admissions %v. Stable person/host/device bans are irreversible; role/binding withdrawal affects this exact generation.\n", s.Restriction.Kept)
	}
	approve, _ := fs.GetBool("approve")
	if !approve && !(isTerminal(os.Stdin) && askYes(errOut, prompt)) {
		return result, nil
	}
	// Any later error still displays the retained action/intent. Never regenerate
	// payload/time/provider or suppress an already committed publication.
	defer func() {
		if err != nil {
			_ = printJSON(out, result)
		}
	}()
	review, actionID := result.Review, result.ID
	request.Approve = true
	approved, e := linkCall[host.DecActionResult](ctx, client, "POST", base, request)
	if e != nil {
		return result, e
	}
	result = approved
	actual := result.Review
	actual.Warning = review.Warning
	if result.ID != actionID || !reflect.DeepEqual(actual, review) {
		return result, errors.New("approval changes the exact action/provider review")
	}
	if err = checkDecNativeActionReview(result, a, s); err != nil {
		return result, err
	}
	if len(result.Signing) > 0 {
		if len(result.Signing) != 1 {
			return result, errors.New("unexpected action signing roles; retain exact action")
		}
		slot := result.Signing[0]
		var key person.Signer
		key, err = person.Load(a.KeyPath)
		if err != nil {
			return result, err
		}
		defer key.Close()
		public := membership.EncodeKey(key.PublicKey())
		raw, e := base64.StdEncoding.Strict().DecodeString(slot.Template)
		if e != nil {
			return result, e
		}
		typed, e := dec.ReadStatementTemplate(a.Descriptor, raw)
		if e != nil {
			return result, e
		}
		if public != a.signerKey() || slot.Slot != 1 || slot.Type != s.Kind || slot.Role != "issuer" || slot.Format != "sshsig" || slot.Public != public || slot.Object != s.ID || typed.ID != s.ID || !bytes.Equal(typed.Payload, s.Payload) || len(typed.Signatures) != 1 || typed.Signatures[0] != (dec.Signature{Role: "issuer", PublicKey: public, Format: "sshsig", Signature: "-"}) {
			return result, errors.New("action slot changes the exact typed issuer/template")
		}
		message := dec.SignatureMessage(s.ID, "issuer", public)
		supplied, e := base64.StdEncoding.Strict().DecodeString(slot.Message)
		if e != nil || !bytes.Equal(message, supplied) {
			return result, errors.New("action signing message differs from its typed role")
		}
		at, e := host.DecentralizedDecisionTime()
		if e != nil {
			return result, e
		}
		if at.Before(a.Now) || at.Sub(a.Now) > 300*time.Second || !at.Before(a.Until) {
			return result, errors.New("expired action signing window; retain exact action")
		}
		signature, e := membership.SignSSHSIG(key, message)
		if e != nil {
			return result, e
		}
		signed, e := linkCall[host.DecActionResult](ctx, client, "POST", base+"/"+url.PathEscape(actionID)+"/signed", map[string]any{"intent_id": slot.Intent, "signatures": []map[string]any{{"slot_id": slot.Slot, "role": slot.Role, "signature": signature}}})
		if e != nil {
			return result, e
		}
		result = signed
	}
	if result.ID != actionID || !result.Committed || result.Statement == "-" || len(result.Signing) != 0 {
		return result, errors.New("action is pending; retain its exact action ID")
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(result.Statement)
	if e != nil {
		return result, e
	}
	final, e := dec.ReadStatement(a.Descriptor, raw)
	if e != nil || final.ID != s.ID || !bytes.Equal(final.Payload, s.Payload) || result.Proof != dec.ProofID(s.Kind, raw) || final.Signer("issuer") != a.signerKey() {
		return result, errors.New("applied result changes the exact reviewed statement/signer")
	}
	return result, nil
}
