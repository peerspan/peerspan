package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/pflag"
)

type decCLIMigrationPreparation struct {
	Descriptor    dec.Descriptor
	Root, RootKey string
	Roster        []host.DecMigrationRoster
	Catalog       *dec.Catalog
}

// This is exact public preparation evidence, never a manufactured NETWORK_VIEW,
// current provider, private prior, or authority for an ordinary operation.
func readCLIMigrationPreparation(ctx context.Context, client host.Client, network, proposal string) (decCLIMigrationPreparation, error) {
	var result decCLIMigrationPreparation
	view, e := call[host.DecMigrationView](ctx, client, "GET", decNetworkPath(network)+"/migration")
	if e != nil {
		return result, e
	}
	if view.Proposal != proposal || !view.Approved || view.Fenced {
		return result, errors.New("review the exact unfenced migration proposal locally before preparing this host")
	}
	evidence, e := linkCall[host.DecMigrationEvidence](ctx, client, "GET", decNetworkPath(network)+"/migration/evidence", nil)
	if e != nil {
		return result, e
	}
	d, e := migrationCLIDescriptor(evidence.Proposal)
	if e != nil {
		return result, e
	}
	statement, e := dec.ReadStatement(d, evidence.Proposal)
	if e != nil {
		return result, e
	}
	var p struct {
		Legacy  string                    `json:"legacy_descriptor_base64"`
		Feature string                    `json:"legacy_feature_id"`
		Epoch   uint64                    `json:"legacy_epoch"`
		Root    string                    `json:"legacy_root_public_key"`
		Source  string                    `json:"source_catalog_sha256"`
		State   string                    `json:"source_state_sha256"`
		Roster  []host.DecMigrationRoster `json:"roster"`
		Issued  string                    `json:"issued_at"`
		Expires string                    `json:"expires_at"`
	}
	if json.Unmarshal(statement.Payload, &p) != nil || statement.Kind != "migration_proposal" || statement.ID != proposal || d.NetworkID != network || d.ContextID != view.Context || p.Source != view.SourceHash || p.State != view.StateHash || statement.Signer("issuer") != p.Root {
		return result, errors.New("migration evidence changes the exact reviewed source")
	}
	decode := func(encoded string, max int) ([]byte, error) {
		raw, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || len(raw) > max || base64.StdEncoding.EncodeToString(raw) != encoded {
			return nil, errors.New("invalid migration source encoding")
		}
		return raw, nil
	}
	legacy, e := decode(p.Legacy, dec.MaxObject)
	if e != nil {
		return result, e
	}
	source, e := decode(evidence.Source, 512<<10)
	if e != nil {
		return result, e
	}
	state, e := decode(evidence.State, dec.MaxPayload)
	if e != nil {
		return result, e
	}
	if fmt.Sprintf("%x", sha256.Sum256(source)) != p.Source || fmt.Sprintf("%x", sha256.Sum256(state)) != p.State {
		return result, errors.New("migration source bytes differ from the signed proposal")
	}
	_, facts, e := dec.VerifyMigrationSourceSnapshot(d, legacy, source, state, p.Epoch, p.Feature, p.Root, p.Issued)
	if e != nil {
		return result, e
	}
	if len(facts.Members) != len(p.Roster) {
		return result, errors.New("migration roster omits a known source host")
	}
	for n, row := range p.Roster {
		member := facts.Members[n]
		if member.HostPublicKey != row.Host || member.PersonPublicKey != row.Person || member.Member != row.Member {
			return result, errors.New("migration roster changes the verified source identities")
		}
	}
	now, e := host.DecentralizedDecisionTime()
	if e != nil {
		return result, e
	}
	at := now.UTC().Format("2006-01-02T15:04:05Z")
	if at < p.Issued || at >= p.Expires {
		return result, errors.New("migration signing window expired; retain its exact evidence")
	}
	catalog, e := dec.ReadCatalog(d, evidence.Catalog)
	if e != nil {
		return result, e
	}
	root := "-"
	for _, s := range catalog.Statements {
		if s.Root == nil {
			continue
		}
		r := s.Root
		if root != "-" && root != s.ID || r.Migration != proposal || r.Key != p.Root || r.Epoch != p.Epoch || r.Issued != p.Issued || len(r.Predecessors) != 0 || len(r.Resolves) != 0 || len(r.Retained) != 0 || s.Signer("issuer") != p.Root {
			return result, errors.New("migration initial root changes its frozen source")
		}
		root = s.ID
	}
	if root == "-" || root != view.Root {
		return result, errors.New("proof_required: exact proposed initial root is missing")
	}
	return decCLIMigrationPreparation{d, root, p.Root, p.Roster, catalog}, nil
}

func runDecMigrationLinkApproval(ctx context.Context, client host.Client, command, code string, token *dec.PairingToken, fs *pflag.FlagSet, out, errOut io.Writer) error {
	network := token.Terms.Network
	if chosen := linkFlag(fs, "network"); chosen != "-" && chosen != network {
		return errors.New("staged linking requires the exact proposal network ID")
	}
	prepared, e := readCLIMigrationPreparation(ctx, client, network, token.Terms.Migration)
	if e != nil {
		return e
	}
	if token.Terms.Mode != "new" || token.Terms.Context != prepared.Descriptor.ContextID {
		return errors.New("staged request changes the exact new context")
	}
	var row host.DecMigrationRoster
	for _, candidate := range prepared.Roster {
		if candidate.Host == token.Terms.Host {
			row = candidate
		}
	}
	if row.Host == "" || row.Person != token.Terms.Person || row.Device != token.Terms.Device || row.Person == "-" {
		return errors.New("staged request differs from the exact owned roster tuple")
	}
	for _, flag := range []string{"person", "expect-person"} {
		if target := linkFlag(fs, flag); target != "-" && target != row.Person {
			return errors.New("staged approval changes the original person")
		}
	}
	hostKey, deviceKey := linkFlag(fs, "expect-host-key"), linkFlag(fs, "expect-device-key")
	if hostKey == "-" {
		hostKey = row.Host
	}
	if deviceKey == "-" {
		deviceKey = row.Device
	}
	provider := linkFlag(fs, "signer")
	var submit func(bool) (host.DecApprovalResult, error)
	if command == "approve" {
		if provider != "-" && provider != "auto" && provider != "person_root" && provider != row.Person {
			return errors.New("migration owner approval requires this exact original person")
		}
		scopes, _ := fs.GetUint64("scopes")
		if !fs.Changed("scopes") {
			scopes = row.Scopes
		}
		if scopes != row.Scopes {
			return errors.New("migration cannot replace the reviewed device profile")
		}
		deadline, _ := fs.GetString("not-after")
		if deadline == "" {
			now, e := host.DecentralizedDecisionTime()
			if e != nil {
				return e
			}
			deadline = now.Add(7 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05Z")
			for _, s := range prepared.Catalog.Statements {
				if s.Kind == "person_lease" && s.Lease.Subject.Person == row.Person && s.Lease.After < deadline {
					deadline = s.Lease.After
				}
			}
		}
		input := host.DecOwnerApproval{Code: code, Network: network, Person: row.Person, Provider: row.Person, Format: "sshsig", Scopes: scopes, NotAfter: deadline, Host: hostKey, Device: deviceKey}
		submit = func(approve bool) (host.DecApprovalResult, error) {
			input.Approve = approve
			return linkCall[host.DecApprovalResult](ctx, client, "POST", "/v2/link/approvals", input)
		}
	} else {
		if provider != "-" && provider != "auto" && provider != "network_root" {
			return errors.New("staged administrator approval requires the exact legacy root")
		}
		owner, selection := linkFlag(fs, "owner-offer"), linkFlag(fs, "selection")
		if owner == "-" || selection == "-" {
			return errors.New("administrator review requires exact --owner-offer and --selection")
		}
		format := "ed25519"
		if key, _ := fs.GetString("root-key"); key != "" {
			format = "sshsig"
		}
		input := host.DecAdministratorApproval{Code: code, Network: network, Person: row.Person, Provider: "network_root", Format: format, Owner: owner, Selection: selection, Host: hostKey, Device: deviceKey}
		submit = func(approve bool) (host.DecApprovalResult, error) {
			input.Approve = approve
			return linkCall[host.DecApprovalResult](ctx, client, "POST", "/v2/link/admissions", input)
		}
	}
	result, e := submit(false)
	if e != nil {
		return e
	}
	r := result.Review
	if result.Request.Migration != token.Terms.Migration || r.Network != network || r.Context != prepared.Descriptor.ContextID || r.Root != prepared.Root || r.Person != row.Person || r.Host != row.Host || r.Device != row.Device {
		return errors.New("migration review changed the exact staged target")
	}
	_, _ = fmt.Fprintf(errOut, "Staged migration %s, original person %s, host %s, device %s, exact nominal scopes %d, expires %s. No active context, provider or outcome until whole migration. Conditional8 needs its independent current role.\n", token.Terms.Migration, r.Person, r.Host, r.Device, r.Scopes, r.NotAfter)
	approve, _ := fs.GetBool("approve")
	if !approve && isTerminal(os.Stdin) {
		approve = askYes(errOut, "Approve only this exact staged machine preparation?")
	}
	if approve {
		preview := result.Review
		result, e = submit(true)
		if e != nil {
			return e
		}
		if e = sameDecLinkReview(preview, result.Review); e != nil {
			return e
		}
		result, e = signDecLink(ctx, client, result, fs)
		if e != nil {
			return e
		}
	}
	return decLinkViewOutput(out, result.Request)
}
