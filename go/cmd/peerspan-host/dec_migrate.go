package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

func configureDecMigrationFlags(fs *pflag.FlagSet, command string) {
	if command == "status" {
		return
	}
	fs.String("proposal", "", "exact reviewed proposal ds_ (defaults to the retained proposal)")
	switch command {
	case "identity":
		fs.Uint64("scopes", 7, "exact preserved device scopes; unbound hosts require0")
	case "prepare":
		fs.String("roster-file", "", "exact complete JSON roster file, or - for stdin")
	case "evidence":
		fs.String("evidence-file", "", "import exact public evidence file or - for stdin; omit to export")
	case "device-bans":
		fs.String("person", "", "exact still-admitted original person whose inherited device bans are copied")
	case "host-lease":
		fs.String("host-lease-file", "", "exact root-signed partial unbound host lease file, or - for stdin")
	case "commit":
		fs.StringArray("acknowledgment", nil, "exact acknowledgment ds_; repeatable, defaults to all retained ACKs")
	case "adopt":
		fs.String("commit", "", "exact retained root commit ds_")
	}
	if command == "prepare" || command == "commit" || command == "resume" {
		fs.String("root-key", "", "explicit current root SSH key/agent identity for exact typed slots")
	}
	if command == "device-bans" || command == "resume" {
		fs.String("person-key", "", "exact original SSH key/agent identity for inherited device-ban signatures only")
	}
	if command == "commit" || command == "ack" {
		fs.String("prepared-catalog", "", "exact prepared-catalog SHA256 (defaults to retained hash)")
	}
	if command == "identity" || command == "prepare" || command == "review" || command == "host-lease" || command == "device-bans" || command == "ack" || command == "commit" || command == "adopt" {
		fs.Bool("approve", false, "approve the exact displayed migration review")
	}
}

func migrationCLIFile(path string, max int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("an exact public file or - for stdin is required")
	}
	var reader io.Reader = os.Stdin
	if path != "-" {
		file, e := os.Open(path)
		if e != nil {
			return nil, e
		}
		defer file.Close()
		reader = file
	}
	raw, e := io.ReadAll(io.LimitReader(reader, int64(max)+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > max {
		return nil, errors.New("quota_exceeded: public evidence file is too large")
	}
	return raw, nil
}

func migrationCLIReview(out io.Writer, r host.DecMigrationReview) {
	_, _ = fmt.Fprintf(out, "Migration %s: stage %s, legacy root %s epoch %d, new context %s\nSource %s; source state %s; prepared %s\n", r.Proposal, r.Stage, r.LegacyRoot, r.Epoch, r.Context, r.SourceHash, r.StateHash, r.PreparedHash)
	for _, row := range r.Roster {
		_, _ = fmt.Fprintf(out, "Host %s member %s person %s device %s scopes %d\n", row.Host, row.Member, row.Person, row.Device, row.Scopes)
	}
	_, _ = fmt.Fprintln(out, r.Warning)
}

func migrationCLIDescriptor(raw []byte) (dec.Descriptor, error) {
	var envelope struct {
		Payload string `json:"payload_base64"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return dec.Descriptor{}, errors.New("invalid migration proposal template")
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if e != nil {
		return dec.Descriptor{}, e
	}
	var proposal struct {
		Descriptor json.RawMessage `json:"new_descriptor"`
	}
	if json.Unmarshal(payload, &proposal) != nil {
		return dec.Descriptor{}, errors.New("invalid migration descriptor")
	}
	return dec.ReadDescriptor(proposal.Descriptor)
}

func decCLISorted(set map[string]bool) []string {
	values := []string{}
	for id := range set {
		values = append(values, id)
	}
	sort.Strings(values)
	return values
}

func migrationCLIValidateReview(result host.DecMigrationResult, network string) error {
	r := result.Review
	if result.Migration.Network != network || r.Network != network || r.Context != result.Migration.Context || r.Proposal != result.Migration.Proposal || !dec.ValidID(r.Proposal, "ds_") || !dec.ValidID(r.Context, "ctx_") || !dec.ValidPublicKey(r.LegacyRoot) || !dec.ValidID(r.SourceHash, "") || !dec.ValidID(r.StateHash, "") || r.Roster == nil || result.Signing == nil || r.Warning == "" {
		return errors.New("migration review changes the selected network/proposal/context")
	}
	previous := ""
	for _, row := range r.Roster {
		if !dec.ValidPublicKey(row.Host) || row.Host <= previous || !membership.ValidLabel(row.Member) || row.Person == "-" && (row.Device != "-" || row.Scopes != 0) || row.Person != "-" && (!dec.ValidPublicKey(row.Person) || !dec.ValidPublicKey(row.Device) || row.Scopes == 0 || row.Scopes > 15) {
			return errors.New("invalid exact migration roster")
		}
		previous = row.Host
	}
	return nil
}

// Migration signing is limited to exact typed legacy-root slots. The CLI
// recomputes each role message and validates its proposal/root/finite fields;
// a returned arbitrary message is never sent to ssh-agent.
func signDecMigration(ctx context.Context, client host.Client, network string, result host.DecMigrationResult, fs *pflag.FlagSet) (host.DecMigrationResult, error) {
	if e := migrationCLIValidateReview(result, network); e != nil {
		return result, e
	}
	path, _ := fs.GetString("root-key")
	if path == "" || len(result.Signing) == 0 {
		return result, nil
	}
	signer, e := person.Load(path)
	if e != nil {
		return result, e
	}
	defer signer.Close()
	key := membership.EncodeKey(signer.PublicKey())
	if key != result.Review.LegacyRoot {
		return result, errors.New("the root key does not match this exact migration review")
	}
	review := result.Review
	var d dec.Descriptor
	var proposalRaw []byte
	for _, slot := range result.Signing {
		if slot.Type == "migration_proposal" {
			raw, e := base64.StdEncoding.Strict().DecodeString(slot.Template)
			if e != nil {
				return result, e
			}
			d, e = migrationCLIDescriptor(raw)
			if e != nil {
				return result, e
			}
			proposalRaw = raw
			break
		}
	}
	if d.ContextID == "" {
		evidence, e := linkCall[host.DecMigrationEvidence](ctx, client, "GET", decNetworkPath(network)+"/migration/evidence", nil)
		if e != nil {
			return result, e
		}
		d, e = migrationCLIDescriptor(evidence.Proposal)
		if e != nil {
			return result, e
		}
		proposalRaw = evidence.Proposal
	}
	if d.NetworkID != network || d.ContextID != review.Context {
		return result, errors.New("migration signing descriptor changes the review")
	}
	proposal, e := dec.ReadStatementTemplate(d, proposalRaw)
	if e != nil {
		return result, e
	}
	var window struct {
		Issued  string `json:"issued_at"`
		Expires string `json:"expires_at"`
	}
	if proposal.Kind != "migration_proposal" || proposal.ID != review.Proposal || json.Unmarshal(proposal.Payload, &window) != nil {
		return result, errors.New("migration proposal differs from the selected signing window")
	}
	rootID := result.Migration.Root
	var inherited []host.DecMigrationInheritedBan
	for round := 0; len(result.Signing) > 0 && round < 4096; round++ {
		intent := result.Signing[0].Intent
		batch := []map[string]any{}
		for _, slot := range result.Signing {
			now, e := host.DecentralizedDecisionTime()
			if e != nil {
				return result, e
			}
			at := now.UTC().Format("2006-01-02T15:04:05Z")
			if at < window.Issued || at >= window.Expires {
				return result, errors.New("expired: retain the exact migration preparation without new signatures")
			}
			raw, e := base64.StdEncoding.Strict().DecodeString(slot.Template)
			if e != nil || base64.StdEncoding.EncodeToString(raw) != slot.Template {
				return result, errors.New("invalid exact migration template encoding")
			}
			s, e := dec.ReadStatementTemplate(d, raw)
			if e != nil {
				return result, e
			}
			if slot.Intent != intent || slot.Object != s.ID || slot.Type != s.Kind || slot.Slot == 0 {
				return result, errors.New("migration slot changes its typed intent")
			}
			if slot.Role == "host" && s.Kind == "host_lease" {
				continue
			}
			if slot.Role != "issuer" || slot.Public != key || slot.Format != "sshsig" {
				return result, errors.New("migration slot changes the reviewed original root role/format")
			}
			declared := false
			for _, sig := range s.Signatures {
				declared = declared || sig.Role == slot.Role && sig.PublicKey == key && sig.Format == slot.Format && sig.Signature == "-"
			}
			if !declared {
				return result, errors.New("migration slot is not an unfilled declared root role")
			}
			switch s.Kind {
			case "migration_proposal":
				var p struct {
					Root       string                    `json:"legacy_root_public_key"`
					Epoch      uint64                    `json:"legacy_epoch"`
					Source     string                    `json:"source_catalog_sha256"`
					State      string                    `json:"source_state_sha256"`
					Roster     []host.DecMigrationRoster `json:"roster"`
					Descriptor json.RawMessage           `json:"new_descriptor"`
				}
				if json.Unmarshal(s.Payload, &p) != nil || s.ID != review.Proposal || p.Root != key || p.Epoch != review.Epoch || p.Source != review.SourceHash || p.State != review.StateHash || !reflect.DeepEqual(p.Roster, review.Roster) {
					return result, errors.New("migration proposal differs from the exact reviewed source/roster")
				}
				other, e := dec.ReadDescriptor(p.Descriptor)
				if e != nil || other.ContextID != d.ContextID {
					return result, errors.New("migration proposal changes the exact descriptor")
				}
			case "root_state":
				r := s.Root
				if r == nil || r.Migration != review.Proposal || r.Key != key || r.Epoch != review.Epoch || len(r.Predecessors) != 0 || len(r.Resolves) != 0 || len(r.Retained) != 0 {
					return result, errors.New("migration initial root changes the review")
				}
				rootID = s.ID
			case "person_lease", "host_lease":
				l := s.Lease
				if l == nil || l.Root != rootID || l.Sequence != 1 || len(l.Predecessors) != 0 || len(l.Resolves) != 0 || len(l.Retained) != 0 || len(l.Parents) != 0 || l.Issuer.Kind != "root" || l.Issuer.Person != "-" || l.Subject.Scopes != 0 {
					return result, errors.New("migration finite template changes reviewed authority")
				}
				if s.Kind == "person_lease" {
					if l.Operation != "-" || !dec.ValidPublicKey(l.Subject.Person) || l.Subject.Host != "-" || l.Subject.Device != "-" {
						return result, errors.New("invalid shared migration person lease")
					}
				} else {
					found := false
					for _, row := range review.Roster {
						found = found || row.Person == "-" && row.Host == l.Subject.Host && row.Member == l.Subject.Member
					}
					if !found || l.Operation != review.Proposal || l.Subject.Person != "-" || l.Subject.Device != "-" {
						return result, errors.New("migration host lease is outside the exact unbound roster")
					}
				}
				before, e := dec.ParseTime(l.Before)
				if e != nil {
					return result, e
				}
				after, e := dec.ParseTime(l.After)
				if e != nil || !before.Before(after) || after.Sub(before) > 7*24*time.Hour {
					return result, errors.New("invalid migration finite interval")
				}
			case "person_remove", "host_revoke":
				if inherited == nil {
					evidence, e := linkCall[host.DecMigrationEvidence](ctx, client, "GET", decNetworkPath(network)+"/migration/evidence")
					if e != nil {
						return result, e
					}
					endorsed, e := dec.ReadStatement(d, evidence.Proposal)
					if e != nil || endorsed.ID != review.Proposal {
						return result, errors.New("inherited bans change the exact endorsed source proposal")
					}
					inherited, e = host.DecentralizedMigrationInheritedBans(d, evidence)
					if e != nil {
						return result, e
					}
				}
				r := s.Restriction
				if r == nil || r.Root != rootID || r.Issuer != (dec.Issuer{Kind: "root", Person: "-"}) || len(r.Parents) != 0 || r.Issued != window.Issued || r.Ratifies != "-" || len(r.Kept) != 0 {
					return result, errors.New("inherited root ban changes its exact source/root pins")
				}
				found := false
				for _, ban := range inherited {
					found = found || ban.Kind == s.Kind && ban.Target == r.Target && len(ban.Proofs) > 0
				}
				if !found {
					return result, errors.New("root ban is outside the exact inherited source set")
				}
			case "migration_commit":
				var p struct {
					Proposal string `json:"proposal_id"`
					Root     string `json:"root_state_id"`
					Hash     string `json:"prepared_catalog_sha256"`
				}
				if json.Unmarshal(s.Payload, &p) != nil || p.Proposal != review.Proposal || p.Root != rootID || p.Hash != review.PreparedHash {
					return result, errors.New("migration commit changes the exact prepared state")
				}
			default:
				return result, errors.New("migration slot is not an allowed typed root statement")
			}
			message := dec.SignatureMessage(s.ID, slot.Role, key)
			provided, e := base64.StdEncoding.Strict().DecodeString(slot.Message)
			if e != nil || !bytes.Equal(message, provided) {
				return result, errors.New("migration signing message differs from its exact template")
			}
			signature, e := membership.SignSSHSIG(signer, message)
			if e != nil {
				return result, e
			}
			batch = append(batch, map[string]any{"slot_id": slot.Slot, "role": slot.Role, "signature": signature})
			if s.Kind == "migration_proposal" {
				// Fix the source endorsement first. Later root-ban slots can then
				// inspect that exact public source without exporting unsigned drafts.
				break
			}
		}
		if len(batch) == 0 {
			break
		}
		result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", decNetworkPath(network)+"/migration/signed", map[string]any{"intent_id": intent, "signatures": batch})
		if e != nil {
			return result, e
		}
		if e = migrationCLIValidateReview(result, network); e != nil {
			return result, e
		}
		actual := result.Review
		actual.Warning = review.Warning
		if !reflect.DeepEqual(actual, review) {
			return result, errors.New("signature submission changed the fixed migration review")
		}
	}
	return result, nil
}

func runDecMigration(ctx context.Context, client host.Client, command, network string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	if !dec.ValidID(network, "net_") {
		return errors.New("an exact legacy network ID is required")
	}
	base := decNetworkPath(network) + "/migration"
	if command == "status" {
		value, e := call[host.DecMigrationView](ctx, client, "GET", base)
		if e != nil {
			return e
		}
		return printJSON(out, value)
	}
	if command == "evidence" {
		path, _ := fs.GetString("evidence-file")
		if path == "" {
			raw, e := client.Call(ctx, "GET", base+"/evidence", nil)
			if e != nil {
				return e
			}
			return printJSON(out, json.RawMessage(raw))
		}
		raw, e := migrationCLIFile(path, 20<<20)
		if e != nil {
			return e
		}
		var input host.DecMigrationEvidence
		if e = dec.ReadPrivateRecord(raw, host.DecMigrationEvidenceFields, &input); e != nil {
			return e
		}
		value, e := linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/evidence", input)
		if e != nil {
			return e
		}
		return printJSON(out, value)
	}
	status, e := call[host.DecMigrationView](ctx, client, "GET", base)
	if e != nil {
		return e
	}
	proposal, _ := fs.GetString("proposal")
	if proposal == "" {
		proposal = status.Proposal
	}
	approve, _ := fs.GetBool("approve")
	var result host.DecMigrationResult
	switch command {
	case "identity":
		scopes, _ := fs.GetUint64("scopes")
		input := host.DecMigrationIdentityRequest{Scopes: scopes}
		value, e := linkCall[host.DecMigrationIdentityResult](ctx, client, "POST", base+"/identity", input)
		if e != nil {
			return e
		}
		migrationCLIReview(errOut, value.Review)
		if approve || isTerminal(os.Stdin) && askYes(errOut, "Approve this exact local migration identity?") {
			input.Approve = true
			value, e = linkCall[host.DecMigrationIdentityResult](ctx, client, "POST", base+"/identity", input)
			if e != nil {
				return e
			}
		}
		return printJSON(out, value)
	case "prepare":
		path, _ := fs.GetString("roster-file")
		raw, e := migrationCLIFile(path, 1<<20)
		if e != nil {
			return e
		}
		var roster []host.DecMigrationRoster
		if json.Unmarshal(raw, &roster) != nil || roster == nil {
			return errors.New("invalid exact JSON migration roster")
		}
		format := "auto"
		if root, _ := fs.GetString("root-key"); root != "" {
			format = "sshsig"
		}
		input := host.DecMigrationPreparation{Roster: roster, Format: format}
		result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/prepare", input)
		if e != nil {
			return e
		}
		migrationCLIReview(errOut, result.Review)
		if approve || isTerminal(os.Stdin) && askYes(errOut, "Approve this exact root migration proposal?") {
			input.Approve = true
			result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/prepare", input)
			if e != nil {
				return e
			}
			result, e = signDecMigration(ctx, client, network, result, fs)
		}
	case "review":
		input := host.DecMigrationApproval{Proposal: proposal}
		result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/review", input)
		if e != nil {
			return e
		}
		migrationCLIReview(errOut, result.Review)
		if approve || isTerminal(os.Stdin) && askYes(errOut, "Approve staged participation in this exact proposal?") {
			input.Approve = true
			result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/review", input)
		}
	case "link":
		value, e := linkCall[decCLILink](ctx, client, "POST", base+"/link", host.DecMigrationLinkRequest{Proposal: proposal})
		if e != nil {
			return e
		}
		return decLinkOutput(out, value, true)
	case "device-bans":
		return runDecMigrationDeviceBans(ctx, client, network, proposal, fs, out, errOut)
	case "host-lease":
		return runDecMigrationHost(ctx, client, network, proposal, fs, out, errOut)
	case "ack":
		hash, _ := fs.GetString("prepared-catalog")
		if hash == "" {
			hash = status.PreparedHash
		}
		input := host.DecMigrationAcknowledgment{Proposal: proposal, Prepared: hash}
		result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/acknowledgment", input)
		if e != nil {
			return e
		}
		if e = migrationCLIValidateReview(result, network); e != nil {
			return e
		}
		if result.Review.Stage != "acknowledgment" || result.Review.Proposal != proposal || result.Review.PreparedHash != hash {
			return errors.New("acknowledgment preview changes the exact proposal or prepared hash")
		}
		review := result.Review
		migrationCLIReview(errOut, review)
		if approve || isTerminal(os.Stdin) && askYes(errOut, "Approve this exact irreversible migration acknowledgment and eventual adoption?") {
			input.Approve = true
			result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/acknowledgment", input)
			if e != nil {
				return e
			}
			actual := result.Review
			actual.Warning = review.Warning
			if !reflect.DeepEqual(actual, review) || !result.Migration.Fenced || result.Migration.LocalAck == "-" {
				return errors.New("acknowledgment changes the fixed review or lacks the durable fence")
			}
		}
	case "commit":
		hash, _ := fs.GetString("prepared-catalog")
		if hash == "" {
			hash = status.PreparedHash
		}
		ids, _ := fs.GetStringArray("acknowledgment")
		if !fs.Changed("acknowledgment") {
			evidence, e := linkCall[host.DecMigrationEvidence](ctx, client, "GET", base+"/evidence", nil)
			if e != nil {
				return e
			}
			d, e := migrationCLIDescriptor(evidence.Proposal)
			if e != nil {
				return e
			}
			set := map[string]bool{}
			for _, raw := range evidence.Acknowledgments {
				ack, e := dec.ReadStatement(d, raw)
				if e != nil {
					return e
				}
				set[ack.ID] = true
			}
			ids = decCLISorted(set)
		}
		format := "auto"
		if root, _ := fs.GetString("root-key"); root != "" {
			format = "sshsig"
		}
		input := host.DecMigrationCommit{Proposal: proposal, Prepared: hash, Acks: ids, Format: format}
		result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/commit", input)
		if e != nil {
			return e
		}
		migrationCLIReview(errOut, result.Review)
		_, _ = fmt.Fprintln(errOut, "Exact acknowledgments:", ids)
		if approve || isTerminal(os.Stdin) && askYes(errOut, "Approve the exact all-host root final commit?") {
			input.Approve = true
			result, e = linkCall[host.DecMigrationResult](ctx, client, "POST", base+"/commit", input)
			if e != nil {
				return e
			}
			result, e = signDecMigration(ctx, client, network, result, fs)
		}
	case "adopt":
		commit, _ := fs.GetString("commit")
		if commit == "" {
			commit = status.Commit
		}
		input := host.DecMigrationAdoption{Proposal: proposal, Commit: commit}
		value, e := linkCall[host.DecMigrationAdoptionResult](ctx, client, "POST", base+"/adopt", input)
		if e != nil {
			return e
		}
		_, _ = fmt.Fprintf(errOut, "Adopt exact migration %s commit %s; retain all identities and the acknowledged prepared state.\n", proposal, commit)
		if approve || isTerminal(os.Stdin) && askYes(errOut, "Apply this exact previously acknowledged migration?") {
			input.Approve = true
			value, e = linkCall[host.DecMigrationAdoptionResult](ctx, client, "POST", base+"/adopt", input)
			if e != nil {
				return e
			}
		}
		return printJSON(out, value)
	case "resume":
		raw, err := client.Call(ctx, "POST", base+"/resume", map[string]any{})
		if err != nil {
			return err
		}
		var envelope struct {
			Review struct {
				Stage string `json:"stage"`
			} `json:"review"`
		}
		if err = json.Unmarshal(raw, &envelope); err != nil {
			return err
		}
		if envelope.Review.Stage == "inherited_device_bans" {
			var value host.DecMigrationDeviceBanResult
			if err = json.Unmarshal(raw, &value); err != nil {
				return err
			}
			value, err = signDecMigrationDeviceBans(ctx, client, network, value, fs)
			if err != nil {
				return err
			}
			return printJSON(out, value)
		}
		if e = json.Unmarshal(raw, &result); e == nil {
			result, e = signDecMigration(ctx, client, network, result, fs)
		}
	default:
		return invalidCommand()
	}
	if e != nil {
		return e
	}
	return printJSON(out, result)
}
