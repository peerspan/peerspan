package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecRootTransition struct {
	Key       string   `json:"new_root_public_key"`
	NewFormat string   `json:"new_root_signature_format"`
	Format    string   `json:"signature_format"`
	Retained  []string `json:"retained_statement_ids"`
	Approve   bool     `json:"approve"`
}

func validateDecRootTransition(r DecRootTransition) error {
	if r.Key != "-" && !dec.ValidPublicKey(r.Key) || r.NewFormat != "ed25519" && r.NewFormat != "sshsig" || r.Key == "-" && r.NewFormat != "ed25519" || r.Format != "auto" && r.Format != "ed25519" && r.Format != "sshsig" || r.Retained == nil || len(r.Retained) > dec.MaxObjects {
		return decFailure("invalid")
	}
	for n, id := range r.Retained {
		if !dec.ValidID(id, "ds_") || n > 0 && r.Retained[n-1] >= id {
			return decFailure("invalid")
		}
	}
	return nil
}

// A resolution has no selected positive root provider. Its private selector
// names one exact branch solely to re-run the pure all-branch intent verifier;
// every actual role remains pinned separately in the immutable template.
func (s *Store) decTransitionProvider(ctx context.Context, q dbQuerier, snapshot *decSnapshot, p *dec.Projection, format string) (DecProviderView, decIntentProvider, dec.Actor, error) {
	if len(p.Root.HeadIDs) == 1 && p.Root.Code == "-" {
		return s.decActionProvider(ctx, q, snapshot, p, "network_root", format)
	}
	view := DecProviderView{"network_root", "-", "-", "-", "-", "-", 0, "-"}
	actor := dec.Actor{Person: "-", Host: "-", Device: "-", IssuerID: "-"}
	if len(snapshot.Fenced) != 0 {
		return view, decIntentProvider{}, actor, decFailure("migration_pending", snapshot.Fenced...)
	}
	if p.Root.Code != "state_conflict" || len(p.Root.HeadIDs) < 2 {
		code := p.Root.Code
		if code == "-" {
			code = "state_conflict"
		}
		return view, decIntentProvider{}, actor, decFailure(code, p.Root.RequiredIDs...)
	}
	if format == "auto" {
		owned := "-"
		if len(snapshot.RootSeed) == ed25519.SeedSize {
			owned = membership.EncodeKey(ed25519.NewKeyFromSeed(snapshot.RootSeed).Public().(ed25519.PublicKey))
		}
		available := false
		for _, id := range p.Root.HeadIDs {
			root := snapshot.Catalog.Statements[id]
			if root != nil && root.Root != nil && root.Root.Key == owned {
				available = true
			}
		}
		if !available {
			return view, decIntentProvider{}, actor, decFailure("signer_unavailable")
		}
		format = "ed25519"
	}
	first := p.Root.HeadIDs[0]
	root := snapshot.Catalog.Statements[first]
	if root == nil || root.Root == nil {
		return view, decIntentProvider{}, actor, decFailure("proof_required", first)
	}
	actor.IssuerID = first
	return view, decIntentProvider{"root", root.Root.Key, format, "-"}, actor, nil
}

func pendingDecRootTransition(ctx context.Context, q dbQuerier, network string) (*decIntent, error) {
	rows, e := q.QueryContext(ctx, `SELECT intent_id FROM dec_intents WHERE network_id=? AND kind='root_transition' ORDER BY intent_id`, network)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	var found *decIntent
	for _, id := range ids {
		i, e := readDecIntent(ctx, q, id)
		if e != nil {
			return nil, e
		}
		if i.Record.Terminal != "-" {
			continue
		}
		if found != nil {
			return nil, decStorageError()
		}
		copy := i
		found = &copy
	}
	return found, nil
}

func matchesDecRootTransition(i decIntent, statement *dec.Statement, r DecRootTransition) bool {
	if statement.Root == nil || (r.Key == "-") != (len(i.Secret) == ed25519.SeedSize) || r.Key != "-" && statement.Root.Key != r.Key || r.Format != "auto" && i.Record.Provider.Format != r.Format {
		return false
	}
	left, _ := json.Marshal(statement.Root.Retained)
	right, _ := json.Marshal(r.Retained)
	if !bytes.Equal(left, right) {
		return false
	}
	for _, sig := range statement.Signatures {
		if sig.Role == "new_root" {
			return sig.Format == r.NewFormat
		}
	}
	return false
}

func (s *Store) PrepareDecentralizedRootTransition(ctx context.Context, network string, input DecRootTransition) (json.RawMessage, error) {
	if e := validateDecRootTransition(input); e != nil {
		return nil, e
	}
	i, facts, e := s.prepareDecRootTransition(ctx, network, input)
	if e != nil {
		return nil, e
	}
	if e = facts.wait(ctx); e != nil {
		return nil, e
	}
	if i.Record.Approved {
		var direct json.RawMessage
		i, direct, facts, e = s.persistDecActionSignatures(ctx, network, i.Record.Operation, DecSignatureBatch{Intent: i.ID, Signatures: []decIntentSignature{}})
		if e != nil || direct != nil {
			return direct, e
		}
		if e = facts.wait(ctx); e != nil {
			return nil, e
		}
	}
	return s.applyPreparedDecAction(ctx, i)
}

func (s *Store) prepareDecRootTransition(ctx context.Context, network string, input DecRootTransition) (decIntent, decCommittedFacts, error) {
	var i decIntent
	facts := decCommittedFacts{}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return i, facts, e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	now, e := decNow()
	if e != nil {
		return i, facts, e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return i, facts, e
	}
	held, e := pendingDecRootTransition(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	fresh, wasApproved := held == nil, false
	if held != nil {
		i = *held
		_, statement, _, e := readDecAction(i, snapshot.Descriptor)
		if e != nil {
			return i, facts, e
		}
		if !matchesDecRootTransition(i, statement, input) {
			// An approved or signed intent is never replaced on a clock/transport
			// guess. An explicitly changed unsigned preview may be superseded.
			if i.Record.Approved || len(i.Record.Signatures) != 0 {
				return i, facts, decFailure("operation_conflict")
			}
			i.Record.Terminal = "cancelled"
			i.Secret = nil
			if e = storeDecIntent(ctx, tx, i, false); e != nil {
				return i, facts, e
			}
			fresh = true
		} else {
			wasApproved = i.Record.Approved
		}
	}
	if fresh {
		if e = decIntentCapacity(ctx, tx); e != nil {
			return i, facts, e
		}
		view, provider, actor, e := s.decTransitionProvider(ctx, tx, snapshot, p, input.Format)
		if e != nil {
			return i, facts, e
		}
		if p.Root.Maximum == math.MaxUint64 {
			return i, facts, decFailure("version_exhausted")
		}
		resolves := []string{}
		if len(p.Root.HeadIDs) > 1 {
			resolves = append(resolves, p.Root.HeadIDs...)
		}
		// Validate exact heads, retained provenance, budgets and overflow using
		// an existing public key before generating any new owned secret.
		key := input.Key
		if key == "-" {
			key = provider.Signer
		}
		payload := dec.RootState{Epoch: p.Root.Maximum + 1, Predecessors: append([]string{}, p.Root.HeadIDs...), Resolves: resolves, Migration: "-", Key: key, Issued: p.DecisionTime, Retained: input.Retained}
		build := func() (decIntent, error) {
			raw, e := json.Marshal(payload)
			if e != nil {
				return decIntent{}, e
			}
			return s.makeDecAction(snapshot, p, DecActionRequest{Kind: "root_state", Provider: "network_root", Format: provider.Format, Payload: base64.StdEncoding.EncodeToString(raw), Approve: input.Approve, rootPreparation: true, newRootFormat: input.NewFormat}, view, provider, actor, p.DecisionTime)
		}
		i, e = build()
		if e != nil {
			return i, facts, e
		}
		_, statement, body, e := readDecAction(i, snapshot.Descriptor)
		if e != nil {
			return i, facts, e
		}
		if e = s.preflightDecActionOutbox(ctx, tx, snapshot, p, i, statement, body); e != nil {
			return i, facts, e
		}
		if input.Key == "-" {
			public, private, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return i, facts, e
			}
			payload.Key = membership.EncodeKey(public)
			i, e = build()
			if e != nil {
				return i, facts, e
			}
			i.Secret = append([]byte{}, private.Seed()...)
		}
	}
	if input.Approve && !i.Record.Approved {
		i.Record.Approved = true
		i.Record.ApprovedAt = p.DecisionTime
	}
	if _, _, _, e = verifyDecAction(snapshot, i, p.DecisionTime); e != nil {
		return i, facts, e
	}
	// Recheck the actual control clock at the final transaction boundary. The
	// immutable root payload/key/expiry is never refreshed by this retry.
	latest, e := decNow()
	if e != nil {
		return i, facts, e
	}
	if _, e = dec.DecisionTime(linkTime(latest), p.DecisionTime); e != nil {
		return i, facts, e
	}
	if _, _, _, e = verifyDecAction(snapshot, i, linkTime(latest)); e != nil {
		return i, facts, e
	}
	if e = storeDecIntent(ctx, tx, i, fresh); e != nil {
		return i, facts, e
	}
	decision, e := dec.DecisionTime(linkTime(latest), snapshot.Prior.ClockGuard)
	if e != nil {
		return i, facts, e
	}
	clock, _ := json.Marshal(decClockRecord{1, decision})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), network); e != nil {
		return i, facts, e
	}
	if e = tx.Commit(); e != nil {
		return i, facts, e
	}
	facts.operation = i.Record.Operation
	if fresh {
		facts.add("dec.intent.after_commit")
	}
	if i.Record.Approved && !wasApproved {
		facts.add("dec.approval.after_commit")
	}
	return i, facts, nil
}
