package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

type decRootReviewSubject struct {
	Key   string `json:"root_public_key"`
	Epoch uint64 `json:"epoch"`
}

func runDecRoot(ctx context.Context, client host.Client, command, network string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	plan, e := call[decCLIPlanning](ctx, client, "GET", decNetworkPath(network)+"/planning")
	if e != nil {
		return e
	}
	d, e := decLinkDescriptor(plan.Network)
	if e != nil {
		return e
	}
	catalog, e := dec.ReadCatalog(d, plan.Catalog)
	if e != nil {
		return e
	}
	stream, exists := decStream(plan, "root", "-")
	if !exists || len(stream.Heads) == 0 {
		return errors.New("proof_required: repair the exact retained root heads before rotation")
	}
	if stream.Version == math.MaxUint64 {
		return errors.New("version_exhausted")
	}
	if command == "rotate-root" && len(stream.Heads) != 1 || command == "resolve-root" && len(stream.Heads) < 2 {
		return errors.New("state_conflict: use rotate-root for a unique root or resolve-root for all incomparable heads")
	}
	retained, _ := fs.GetStringArray("retain")
	empty, _ := fs.GetBool("retain-none")
	if empty && fs.Changed("retain") {
		return errors.New("--retain and --retain-none are mutually exclusive")
	}
	if !empty && !fs.Changed("retain") {
		preview, e := call[host.DecRootRetentionView](ctx, client, "GET", decNetworkPath(network)+"/root-retention")
		if e != nil {
			return e
		}
		if preview.Network != d.NetworkID || preview.Context != d.ContextID || preview.Candidates == nil || preview.Excluded == nil {
			return errors.New("root retention preview changes the network/context")
		}
		left, _ := json.Marshal(preview.Roots)
		right, _ := json.Marshal(stream.Heads)
		if !bytes.Equal(left, right) {
			return errors.New("state_conflict: root heads changed during retention review")
		}
		at, e := dec.ParseTime(preview.Time)
		if e != nil {
			return e
		}
		catalog, e = dec.ReadCatalog(d, preview.Catalog)
		if e != nil {
			return e
		}
		selected := map[string]bool{}
		previous := ""
		for _, candidate := range preview.Candidates {
			statement := catalog.Statements[candidate.Statement]
			if candidate.Statement <= previous || statement == nil || statement.Kind != candidate.Kind || statement.Lease == nil && statement.Access == nil || candidate.Required == nil || candidate.Scopes > 15 {
				return errors.New("invalid finite retention preview")
			}
			previous = candidate.Statement
			after, e := dec.ParseTime(candidate.After)
			if e != nil || !at.Before(after) {
				return errors.New("expired finite retention preview")
			}
			found := false
			prior := ""
			for _, id := range candidate.Required {
				if !dec.ValidID(id, "ds_") || id <= prior {
					return errors.New("invalid required retention IDs")
				}
				prior = id
				body := catalog.Statements[id]
				if body == nil || body.Lease == nil && body.Access == nil {
					return errors.New("proof_required: required finite retention body is missing")
				}
				found = found || id == candidate.Statement
				selected[id] = true
			}
			if !found {
				return errors.New("retention preview omits its own candidate")
			}
			_, _ = fmt.Fprintf(errOut, "Eligible %s %s: scopes %d, until %s; required %v\n", candidate.Kind, candidate.Statement, candidate.Scopes, candidate.After, candidate.Required)
		}
		previous = ""
		missing := false
		for _, entry := range preview.Excluded {
			if !dec.ValidID(entry.Statement, "ds_") || entry.Statement <= previous || entry.Code == "" || entry.Required == nil {
				return errors.New("invalid excluded retention entry")
			}
			previous = entry.Statement
			_, _ = fmt.Fprintf(errOut, "Excluded %s: %s %v\n", entry.Statement, entry.Code, entry.Required)
			missing = missing || entry.Code == "proof_required"
		}
		if missing {
			return errors.New("proof_required: repair unknown retention eligibility before using the full-set default, or select an explicit --retain subset/--retain-none")
		}
		retained = []string{}
		for id := range selected {
			retained = append(retained, id)
		}
	}
	if retained == nil {
		retained = []string{}
	}
	sort.Strings(retained)
	for n, id := range retained {
		if !dec.ValidID(id, "ds_") || n > 0 && retained[n-1] == id {
			return errors.New("--retain requires distinct exact ds_ statement IDs")
		}
	}
	signers := map[string]person.Signer{}
	defer func() {
		for _, signer := range signers {
			_ = signer.Close()
		}
	}()
	load := func(path string) (string, error) {
		signer, e := person.Load(path)
		if e != nil {
			return "", e
		}
		key := membership.EncodeKey(signer.PublicKey())
		if signers[key] != nil {
			_ = signer.Close()
		} else {
			signers[key] = signer
		}
		return key, nil
	}
	input := host.DecRootTransition{Key: "-", NewFormat: "ed25519", Format: "auto", Retained: retained, Approve: false}
	if command == "resolve-root" {
		path, _ := fs.GetString("new-root-key")
		if path == "" {
			return errors.New("resolve-root needs --new-root-key PATH")
		}
		input.Key, e = load(path)
		if e != nil {
			return e
		}
		input.NewFormat = "sshsig"
		// Ed25519 branch roles permit a held daemon seed and independently
		// supplied SSH key/agent identities in the same exact resolution.
		input.Format = "ed25519"
		paths, _ := fs.GetStringArray("root-key")
		for _, path := range paths {
			if _, e = load(path); e != nil {
				return e
			}
		}
	} else {
		toSSH, _ := fs.GetBool("to-ssh")
		path, _ := fs.GetString("root-key")
		if toSSH != (path != "") {
			return errors.New("rotate-root takes --to-ssh with --root-key PATH, or neither")
		}
		if toSSH {
			input.Key, e = load(path)
			if e != nil {
				return e
			}
			input.NewFormat = "sshsig"
		}
	}
	rootKeys := map[string]string{}
	for _, id := range stream.Heads {
		root := catalog.Statements[id]
		if root == nil || root.Root == nil {
			return fmt.Errorf("proof_required: exact root body %s is missing", id)
		}
		role := "issuer"
		if len(stream.Heads) > 1 {
			role = "root_branch:" + id
		}
		rootKeys[role] = root.Root.Key
	}
	path := decNetworkPath(network) + "/root-transitions"
	result, e := linkCall[host.DecActionResult](ctx, client, "POST", path, input)
	if e != nil && command == "rotate-root" {
		var failure *host.ClientError
		if errors.As(e, &failure) && failure.Code == "signer_unavailable" {
			key, keyErr := membership.DecodeKey(rootKeys["issuer"])
			if keyErr != nil {
				return keyErr
			}
			signer, keyErr := person.LoadKey(key)
			if keyErr != nil {
				return fmt.Errorf("the current exact SSH root must be available: %w", keyErr)
			}
			signers[rootKeys["issuer"]] = signer
			input.Format = "sshsig"
			result, e = linkCall[host.DecActionResult](ctx, client, "POST", path, input)
		}
	}
	if e != nil {
		return e
	}
	var subject decRootReviewSubject
	if dec.ReadPrivateRecord(result.Review.Subject, "root_public_key epoch", &subject) != nil || !dec.ValidPublicKey(subject.Key) || subject.Epoch != stream.Version+1 || input.Key != "-" && subject.Key != input.Key || result.Review.Kind != "root_state" || result.Review.Sequence != subject.Epoch || !dec.ValidID(result.Review.Statement, "ds_") || result.Review.Warning == "" || result.ID != dec.ActionID(d.ContextID, "root_state", result.Review.Statement, "network_root") {
		return errors.New("root preview differs from the requested exact transition")
	}
	resolves := []string{}
	if len(stream.Heads) > 1 {
		resolves = append(resolves, stream.Heads...)
	}
	check := func(statement *dec.Statement, signing bool) error {
		if statement == nil || statement.Root == nil || statement.ID != result.Review.Statement || statement.Root.Key != subject.Key || statement.Root.Epoch != subject.Epoch || statement.Root.Migration != "-" {
			return errors.New("root template changes the reviewed transition")
		}
		for _, pair := range [][2][]string{{statement.Root.Predecessors, stream.Heads}, {statement.Root.Resolves, resolves}, {statement.Root.Retained, retained}} {
			a, _ := json.Marshal(pair[0])
			b, _ := json.Marshal(pair[1])
			if !bytes.Equal(a, b) {
				return errors.New("root template changes the exact heads or retention list")
			}
		}
		issued, e := dec.ParseTime(statement.Root.Issued)
		if e != nil {
			return e
		}
		if !signing {
			return nil
		}
		now, e := host.DecentralizedDecisionTime()
		if e != nil {
			return e
		}
		if now.Before(issued) || now.Sub(issued) > 300*time.Second {
			return errors.New("expired: review the retained exact root action")
		}
		return nil
	}
	_, _ = fmt.Fprintf(errOut, "Root transition to %s at epoch %d; retaining %d explicitly named statements.\n", subject.Key, subject.Epoch, len(retained))
	_, _ = fmt.Fprintf(errOut, "Exact root heads: %v\nRetained finite contributions: %v\n", stream.Heads, retained)
	if len(retained) == 0 {
		_, _ = fmt.Fprintln(errOut, "No delegated leases are retained by this transition.")
	}
	input.Approve = true
	approved, e := linkCall[host.DecActionResult](ctx, client, "POST", path, input)
	if e != nil {
		return e
	}
	var approvedSubject decRootReviewSubject
	if dec.ReadPrivateRecord(approved.Review.Subject, "root_public_key epoch", &approvedSubject) != nil || approvedSubject != subject || approved.ID != result.ID || approved.Review.Statement != result.Review.Statement {
		return errors.New("root approval changed the fixed preview")
	}
	result = approved
	for round := 0; !result.Committed && round < 4096; round++ {
		if len(result.Signing) == 0 {
			break
		}
		intent := result.Signing[0].Intent
		batch := []map[string]any{}
		for _, slot := range result.Signing {
			raw, e := base64.StdEncoding.Strict().DecodeString(slot.Template)
			if e != nil {
				return e
			}
			statement, e := dec.ReadStatementTemplate(d, raw)
			if e != nil {
				return e
			}
			if e = check(statement, true); e != nil {
				return e
			}
			key, format := rootKeys[slot.Role], input.Format
			if slot.Role == "new_root" {
				key, format = subject.Key, input.NewFormat
			}
			if slot.Intent != intent || slot.Slot != 1 || slot.Type != "root_state" || slot.Object != statement.ID || key == "" || slot.Public != key || slot.Format != format {
				return errors.New("root signing slot changes the exact role, key or format")
			}
			found := false
			for _, sig := range statement.Signatures {
				if sig.Role == slot.Role && sig.PublicKey == key && sig.Format == format && sig.Signature == "-" {
					found = true
				}
			}
			if !found {
				return errors.New("root slot is not a declared unfilled role")
			}
			message := dec.SignatureMessage(statement.ID, slot.Role, key)
			supplied, e := base64.StdEncoding.Strict().DecodeString(slot.Message)
			if e != nil || !bytes.Equal(message, supplied) {
				return errors.New("root signing message differs from the exact typed template")
			}
			signer := signers[key]
			if signer == nil {
				continue
			}
			var signature string
			if format == "sshsig" {
				signature, e = membership.SignSSHSIG(signer, message)
			} else {
				var raw []byte
				raw, e = signer.Sign(message)
				signature = base64.StdEncoding.EncodeToString(raw)
			}
			if e != nil {
				return e
			}
			batch = append(batch, map[string]any{"slot_id": slot.Slot, "role": slot.Role, "signature": signature})
		}
		if len(batch) == 0 {
			break
		}
		before := result
		result, e = linkCall[host.DecActionResult](ctx, client, "POST", decNetworkPath(network)+"/actions/"+url.PathEscape(result.ID)+"/signed", map[string]any{"intent_id": intent, "signatures": batch})
		if e != nil {
			return e
		}
		if result.ID != before.ID || result.Review.Statement != before.Review.Statement {
			return errors.New("root signature submission changed the fixed operation")
		}
	}
	if !result.Committed {
		if e = printJSON(out, result); e != nil {
			return e
		}
		return errors.New("root action needs its remaining exact signing slots; preserve and resume the returned action_id")
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(result.Statement)
	if e != nil {
		return e
	}
	statement, e := dec.ReadStatement(d, raw)
	if e != nil {
		return e
	}
	if e = check(statement, false); e != nil {
		return e
	}
	if result.Proof != dec.ProofID("root_state", raw) || len(result.Signing) != 0 {
		return errors.New("inconsistent completed root action")
	}
	return printJSON(out, result)
}
