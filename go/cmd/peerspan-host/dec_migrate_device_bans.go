package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

func migrationDeviceBanCLIIntentID(id string) bool {
	if !strings.HasPrefix(id, "dint_") || len(id) != len("dint_")+32 {
		return false
	}
	b, e := hex.DecodeString(id[len("dint_"):])
	return e == nil && hex.EncodeToString(b) == id[len("dint_"):]
}

func migrationDeviceBanCLIReview(out io.Writer, r host.DecMigrationDeviceBanReview) {
	_, _ = fmt.Fprintf(out, "Migration %s: inherited device bans for original %s in context %s\nRoot %s; person lease %s\nSource %s; source state %s\n", r.Proposal, r.Person, r.Context, r.Root, r.PersonLease, r.SourceHash, r.StateHash)
	for _, copy := range r.Copies {
		_, _ = fmt.Fprintf(out, "Irreversibly copy device ban %s from ALL source proofs %v; statement %s\n", copy.Device, copy.Proofs, copy.Statement)
	}
	for _, maximum := range r.Maxima {
		_, _ = fmt.Fprintf(out, "Preserve access maximum %s %s %d %s\n", maximum.Kind, maximum.Subject, maximum.Version, maximum.Hash)
	}
	_, _ = fmt.Fprintln(out, r.Warning)
}

type migrationDeviceBanCLIContext struct {
	Descriptor      dec.Descriptor
	Issued, Expires string
	Person          *dec.Statement
}

// Inspect only the exact signed source and pending root/person facts. This is
// typed signing review, not a projection, provider selection or local admission.
func migrationDeviceBanCLICheck(ctx context.Context, client host.Client, network string, result host.DecMigrationDeviceBanResult) (*migrationDeviceBanCLIContext, error) {
	r := result.Review
	if r.Stage != "inherited_device_bans" || result.Migration.Network != network || r.Network != network || r.Proposal != result.Migration.Proposal || r.Context != result.Migration.Context || !dec.ValidID(r.Proposal, "ds_") || !dec.ValidID(r.Context, "ctx_") || !dec.ValidPublicKey(r.Person) || !dec.ValidID(r.Root, "ds_") || !dec.ValidID(r.PersonLease, "ds_") || r.Copies == nil || r.Maxima == nil || result.Signing == nil || len(result.Signing) > 16 || r.Warning == "" {
		return nil, errors.New("invalid inherited-device-ban review pins")
	}
	evidence, e := linkCall[host.DecMigrationEvidence](ctx, client, "GET", decNetworkPath(network)+"/migration/evidence")
	if e != nil {
		return nil, e
	}
	d, e := migrationCLIDescriptor(evidence.Proposal)
	if e != nil {
		return nil, e
	}
	if d.NetworkID != network || d.ContextID != r.Context {
		return nil, errors.New("device-ban evidence changes the reviewed context")
	}
	proposal, e := dec.ReadStatement(d, evidence.Proposal)
	if e != nil {
		return nil, e
	}
	var p struct {
		Root    string `json:"legacy_root_public_key"`
		Epoch   uint64 `json:"legacy_epoch"`
		Legacy  string `json:"legacy_descriptor_base64"`
		Feature string `json:"legacy_feature_id"`
		Source  string `json:"source_catalog_sha256"`
		State   string `json:"source_state_sha256"`
		Issued  string `json:"issued_at"`
		Expires string `json:"expires_at"`
	}
	if json.Unmarshal(proposal.Payload, &p) != nil || proposal.Kind != "migration_proposal" || proposal.ID != r.Proposal || proposal.Signer("issuer") != p.Root || p.Source != r.SourceHash || p.State != r.StateHash {
		return nil, errors.New("device-ban proposal changes the exact endorsed source")
	}
	bans, e := host.DecentralizedMigrationInheritedBans(d, evidence)
	if e != nil {
		return nil, e
	}
	legacy, e := base64.StdEncoding.Strict().DecodeString(p.Legacy)
	if e != nil {
		return nil, e
	}
	source, e := base64.StdEncoding.Strict().DecodeString(evidence.Source)
	if e != nil {
		return nil, e
	}
	state, e := base64.StdEncoding.Strict().DecodeString(evidence.State)
	if e != nil {
		return nil, e
	}
	snapshot, facts, e := dec.VerifyMigrationSourceSnapshot(d, legacy, source, state, p.Epoch, p.Feature, p.Root, p.Issued)
	if e != nil {
		return nil, e
	}
	if !facts.Facts.State.Persons[r.Person].Admitted || !reflect.DeepEqual(snapshot.Maxima, r.Maxima) {
		return nil, errors.New("device-ban review changes source admission or access maxima")
	}
	copies := []host.DecMigrationDeviceCopy{}
	for _, ban := range bans {
		if ban.Kind == "device_revoke" && ban.Target.Person == r.Person {
			copies = append(copies, host.DecMigrationDeviceCopy{Device: ban.Target.Device, Proofs: ban.Proofs, Statement: "-"})
		}
	}
	if len(copies) != len(r.Copies) {
		return nil, errors.New("device-ban review changes the complete inherited target set")
	}
	for n, copy := range r.Copies {
		if copy.Device != copies[n].Device || !reflect.DeepEqual(copy.Proofs, copies[n].Proofs) || copy.Statement != "-" && !dec.ValidID(copy.Statement, "ds_") {
			return nil, errors.New("device-ban review changes an exact stable target or source proof")
		}
	}
	catalog, e := dec.ReadCatalog(d, evidence.Catalog)
	if e != nil {
		return nil, e
	}
	root := catalog.Statements[r.Root]
	person := catalog.Statements[r.PersonLease]
	if root == nil || root.Root == nil || root.Root.Migration != r.Proposal || root.Root.Key != p.Root || root.Root.Epoch != p.Epoch || len(root.Root.Predecessors) != 0 || len(root.Root.Resolves) != 0 || len(root.Root.Retained) != 0 || root.Signer("issuer") != p.Root || person == nil || person.Lease == nil {
		return nil, errors.New("device-ban review lacks the exact pending initial root/person")
	}
	l := person.Lease
	if person.Kind != "person_lease" || l.Root != r.Root || l.Operation != "-" || l.Sequence != 1 || len(l.Predecessors) != 0 || len(l.Resolves) != 0 || len(l.Retained) != 0 || len(l.Parents) != 0 || l.Issuer != (dec.Issuer{Kind: "root", Person: "-"}) || person.Signer("issuer") != p.Root || l.Subject.Person != r.Person || l.Subject.Host != "-" || l.Subject.Device != "-" || l.Subject.Scopes != 0 || l.Subject.Member != facts.Facts.PersonLabels[r.Person] {
		return nil, errors.New("device-ban shared person lease changes the reviewed source tuple")
	}
	return &migrationDeviceBanCLIContext{d, p.Issued, p.Expires, person}, nil
}

func signDecMigrationDeviceBans(ctx context.Context, client host.Client, network string, result host.DecMigrationDeviceBanResult, fs *pflag.FlagSet) (host.DecMigrationDeviceBanResult, error) {
	checked, e := migrationDeviceBanCLICheck(ctx, client, network, result)
	if e != nil {
		return result, e
	}
	path, _ := fs.GetString("person-key")
	if path == "" || len(result.Signing) == 0 {
		return result, nil
	}
	signer, e := person.Load(path)
	if e != nil {
		return result, e
	}
	defer signer.Close()
	key := membership.EncodeKey(signer.PublicKey())
	if key != result.Review.Person {
		return result, errors.New("the selected key is not this exact original person")
	}
	review := result.Review
	templates := map[uint64]string{}
	objects := map[uint64]string{}
	intent := ""
	issued := ""
	for round := 0; len(result.Signing) > 0 && round < dec.MaxObjects; round++ {
		if e = ctx.Err(); e != nil {
			return result, e
		}
		batch := []map[string]any{}
		seen := map[uint64]bool{}
		for _, slot := range result.Signing {
			if intent == "" {
				intent = slot.Intent
			}
			if !migrationDeviceBanCLIIntentID(intent) || slot.Intent != intent || slot.Slot == 0 || slot.Slot > uint64(len(review.Copies)) || seen[slot.Slot] || slot.Role != "issuer" || slot.Public != key || slot.Format != "sshsig" || slot.Type != "device_revoke" {
				return result, errors.New("device-ban slot changes its fixed original intent/role")
			}
			seen[slot.Slot] = true
			raw, e := base64.StdEncoding.Strict().DecodeString(slot.Template)
			if e != nil || base64.StdEncoding.EncodeToString(raw) != slot.Template {
				return result, errors.New("invalid device-ban template encoding")
			}
			s, e := dec.ReadStatementTemplate(checked.Descriptor, raw)
			if e != nil {
				return result, e
			}
			v := s.Restriction
			if s.ID != slot.Object || s.Kind != "device_revoke" || v == nil || v.Root != review.Root || v.Issuer != (dec.Issuer{Kind: "person", Person: key}) || !reflect.DeepEqual(v.Parents, []dec.Parent{{Role: "issuer_person", ID: review.PersonLease}}) || v.Target.Person != key || v.Target.Host != "-" || v.Target.Statement != "-" || len(v.Kept) != 0 || v.Ratifies != "-" || len(s.Signatures) != 1 || s.Signatures[0] != (dec.Signature{Role: "issuer", PublicKey: key, Format: "sshsig", Signature: "-"}) {
				return result, errors.New("device-ban template changes the exact restrictive copy")
			}
			found := false
			for _, copy := range review.Copies {
				found = found || copy.Statement == s.ID && copy.Device == v.Target.Device
			}
			if !found {
				return result, errors.New("device-ban template is outside the fixed reviewed copies")
			}
			if prior, ok := templates[slot.Slot]; ok && prior != slot.Template {
				return result, errors.New("device-ban template changed after review")
			}
			if prior, ok := objects[slot.Slot]; ok && prior != s.ID {
				return result, errors.New("device-ban slot changed its statement")
			}
			templates[slot.Slot], objects[slot.Slot] = slot.Template, s.ID
			if issued == "" {
				issued = v.Issued
			}
			if v.Issued != issued {
				return result, errors.New("device-ban intent changes its fixed approval time")
			}
			now, e := host.DecentralizedDecisionTime()
			if e != nil {
				return result, e
			}
			at := now.UTC().Format("2006-01-02T15:04:05Z")
			if v.Issued < checked.Issued || at < v.Issued || v.Issued >= checked.Expires || at >= checked.Expires || v.Issued < checked.Person.Lease.Before || at < checked.Person.Lease.Before || at >= checked.Person.Lease.After {
				return result, errors.New("expired or not-yet-valid inherited device-ban signing window; preserve the exact intent")
			}
			message := dec.SignatureMessage(s.ID, "issuer", key)
			provided, e := base64.StdEncoding.Strict().DecodeString(slot.Message)
			if e != nil || !bytes.Equal(message, provided) {
				return result, errors.New("device-ban signing message differs from its exact typed role")
			}
			signature, e := membership.SignSSHSIG(signer, message)
			if e != nil {
				return result, e
			}
			batch = append(batch, map[string]any{"slot_id": slot.Slot, "role": "issuer", "signature": signature})
		}
		result, e = linkCall[host.DecMigrationDeviceBanResult](ctx, client, "POST", decNetworkPath(network)+"/migration/signed", map[string]any{"intent_id": intent, "signatures": batch})
		if e != nil {
			return result, e
		}
		actual := result.Review
		actual.Warning = review.Warning
		if !reflect.DeepEqual(actual, review) {
			return result, errors.New("signature submission changed the fixed inherited-ban review")
		}
		checked, e = migrationDeviceBanCLICheck(ctx, client, network, result)
		if e != nil {
			return result, e
		}
	}
	return result, nil
}

func runDecMigrationDeviceBans(ctx context.Context, client host.Client, network, proposal string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	selected, _ := fs.GetString("person")
	if !dec.ValidPublicKey(selected) {
		return errors.New("--person requires the exact still-admitted original public key")
	}
	input := host.DecMigrationDeviceBans{Proposal: proposal, Person: selected}
	value, e := linkCall[host.DecMigrationDeviceBanResult](ctx, client, "POST", decNetworkPath(network)+"/migration/device-bans", input)
	if e != nil {
		return e
	}
	if _, e = migrationDeviceBanCLICheck(ctx, client, network, value); e != nil {
		return e
	}
	if value.Review.Person != selected || value.Review.Proposal != proposal {
		return errors.New("device-ban preview changes the requested person or proposal")
	}
	review := value.Review
	migrationDeviceBanCLIReview(errOut, review)
	approve, _ := fs.GetBool("approve")
	if approve || isTerminal(os.Stdin) && askYes(errOut, "Approve only these exact inherited irreversible device-ban copies?") {
		input.Approve = true
		value, e = linkCall[host.DecMigrationDeviceBanResult](ctx, client, "POST", decNetworkPath(network)+"/migration/device-bans", input)
		if e != nil {
			return e
		}
		actual := value.Review
		actual.Warning = review.Warning
		if len(actual.Copies) != len(review.Copies) {
			return errors.New("approval changes the complete inherited-ban set")
		}
		for n := range actual.Copies {
			if review.Copies[n].Statement == "-" {
				actual.Copies[n].Statement = "-"
			}
		}
		if !reflect.DeepEqual(actual, review) {
			return errors.New("approval changes the inherited-ban review")
		}
		value, e = signDecMigrationDeviceBans(ctx, client, network, value, fs)
		if e != nil {
			return e
		}
	}
	return printJSON(out, value)
}
