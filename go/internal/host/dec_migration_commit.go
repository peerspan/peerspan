package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"reflect"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecMigrationCommit struct {
	Proposal string   `json:"proposal_id"`
	Prepared string   `json:"prepared_catalog_sha256"`
	Acks     []string `json:"acknowledgment_ids"`
	Format   string   `json:"signature_format"`
	Approve  bool     `json:"approve"`
}

type decMigrationCommitPayload struct {
	Proposal string   `json:"proposal_id"`
	Root     string   `json:"root_state_id"`
	Prepared string   `json:"prepared_catalog_sha256"`
	Acks     []string `json:"acknowledgment_ids"`
	At       string   `json:"committed_at"`
}

func migrationDescriptor(r decMigrationRecord) (dec.Descriptor, error) {
	if r.Proposal == "-" {
		return dec.Descriptor{}, decFailure("proof_required")
	}
	var envelope struct {
		Payload string `json:"payload_base64"`
	}
	if json.Unmarshal(mustDecBytes(r.Proposal), &envelope) != nil {
		return dec.Descriptor{}, decStorageError()
	}
	var payload struct {
		Descriptor json.RawMessage `json:"new_descriptor"`
	}
	if json.Unmarshal(mustDecBytes(envelope.Payload), &payload) != nil {
		return dec.Descriptor{}, decStorageError()
	}
	d, e := dec.ReadDescriptor(payload.Descriptor)
	if e != nil {
		return d, e
	}
	proposal, e := dec.ReadStatement(d, mustDecBytes(r.Proposal))
	if e != nil || proposal.Kind != "migration_proposal" || d.ContextID != r.Context {
		return d, decStorageError()
	}
	return d, nil
}

func completeMigrationBody(r decMigrationRecord) ([]byte, error) {
	if r.Proposal == "-" || r.PreparedCatalog == "-" || r.Commit == "-" {
		return nil, decFailure("proof_required")
	}
	acks := []json.RawMessage{}
	for _, encoded := range r.Acknowledgments {
		acks = append(acks, mustDecBytes(encoded))
	}
	return migrationCompositeBody(mustDecBytes(r.Proposal), r.SourceCatalog, r.SourceState, r.PreparedCatalog, acks, mustDecBytes(r.Commit))
}

// All component schemas are checked by the caller. Append their exact raw
// JSON values rather than asking encoding/json to compact RawMessage values.
// Only this unsigned composite framing is newly produced; no component is
// normalized, re-signed or replaced by another semantic alias.
func migrationCompositeBody(proposal []byte, source, state, prepared string, acks []json.RawMessage, commit []byte) ([]byte, error) {
	encodedSource, _ := json.Marshal(source)
	encodedState, _ := json.Marshal(state)
	encodedPrepared, _ := json.Marshal(prepared)
	size := len(proposal) + len(encodedSource) + len(encodedState) + len(encodedPrepared) + len(commit) + 256
	for _, ack := range acks {
		size += len(ack) + 1
		if size > dec.MaxObject+256 {
			return nil, decFailure("quota_exceeded")
		}
	}
	if size > dec.MaxObject+256 {
		return nil, decFailure("quota_exceeded")
	}
	raw := append([]byte(`{"format":1,"proposal":`), proposal...)
	raw = append(raw, []byte(`,"source_catalog_base64":`)...)
	raw = append(raw, encodedSource...)
	raw = append(raw, []byte(`,"source_state_base64":`)...)
	raw = append(raw, encodedState...)
	raw = append(raw, []byte(`,"prepared_catalog_base64":`)...)
	raw = append(raw, encodedPrepared...)
	raw = append(raw, []byte(`,"acknowledgments":[`)...)
	for n, ack := range acks {
		if n > 0 {
			raw = append(raw, ',')
		}
		raw = append(raw, ack...)
	}
	raw = append(raw, []byte(`],"commit":`)...)
	raw = append(raw, commit...)
	raw = append(raw, '}')
	if len(raw) > dec.MaxObject {
		return nil, decFailure("quota_exceeded")
	}
	return raw, nil
}

func migrationCommitIntent(ctx context.Context, q dbQuerier, network string, r decMigrationRecord) (*decIntent, error) {
	var found *decIntent
	for _, id := range r.RootIntents {
		i, e := readDecIntent(ctx, q, id)
		if e != nil {
			return nil, e
		}
		if i.Network != network || i.Context != r.Context || i.Kind != "migration" {
			return nil, decStorageError()
		}
		if len(i.Record.Templates) != 1 || i.Record.Templates[0].Type != "migration_commit" {
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

func checkMigrationCommitIntent(d dec.Descriptor, i decIntent, r decMigrationRecord, prefix *decMigrationPrefix) (DecMigrationReview, *dec.Statement, []byte, error) {
	var review DecMigrationReview
	bad := func() (DecMigrationReview, *dec.Statement, []byte, error) { return review, nil, nil, decStorageError() }
	if prefix.Root == nil || i.Network != d.NetworkID || i.Context != d.ContextID || i.Kind != "migration" || i.Record.Operation != prefix.Proposal.ID || i.Secret != nil || i.Record.Provider.Kind != "root" || i.Record.Provider.Signer != prefix.Fields.Root || i.Record.Provider.Lease != "-" || i.Record.Root != prefix.Root.ID || i.Record.Person != "-" || i.Record.Host != "-" || i.Record.Device != "-" || i.Record.Scopes != 8 || i.Record.NotAfter != "-" || i.Record.Result != "-" || i.Record.Terminal != "-" || i.Record.Expires != prefix.Fields.Expires || len(i.Record.Templates) != 1 || i.Record.Templates[0].Type != "migration_commit" {
		return bad()
	}
	statements, bodies, e := decIntentStatements(d, i)
	if e != nil {
		return review, nil, nil, e
	}
	s := statements[0]
	var p decMigrationCommitPayload
	if dec.ReadPrivateRecord(s.Payload, "proposal_id root_state_id prepared_catalog_sha256 acknowledgment_ids committed_at", &p) != nil || p.Proposal != prefix.Proposal.ID || p.Root != prefix.Root.ID || p.Prepared != decMigrationHash(mustDecBytes(r.PreparedCatalog)) || p.At != i.Record.Created || p.At < prefix.Fields.Issued || p.At >= prefix.Fields.Expires || len(s.Signatures) != 1 || s.Signatures[0].Role != "issuer" || s.Signatures[0].PublicKey != prefix.Fields.Root || s.Signatures[0].Format != i.Record.Provider.Format || i.Record.Completed != decActionComplete(s) {
		return bad()
	}
	ids := []string{}
	for _, raw := range migrationRecordEvidence(r).Acknowledgments {
		ack, e := dec.ReadStatement(d, raw)
		if e != nil {
			return review, nil, nil, e
		}
		ids = append(ids, ack.ID)
	}
	if !reflect.DeepEqual(decSorted(decSet(ids)), p.Acks) {
		return bad()
	}
	if r.Commit != "-" && (!i.Record.Completed || !bytes.Equal(bodies[0], mustDecBytes(r.Commit))) {
		return bad()
	}
	if dec.ReadPrivateRecord(mustDecBytes(i.Record.Review), decMigrationReviewFields, &review) != nil {
		return bad()
	}
	want := migrationParticipationReview(i.Network, prefix, r, "root_commit")
	want.Warning = review.Warning
	if review.Warning == "" || !reflect.DeepEqual(review, want) {
		return bad()
	}
	return review, s, bodies[0], nil
}

func (s *Store) prepareMigrationCommit(ctx context.Context, network string, input DecMigrationCommit) (i decIntent, facts decCommittedFacts, err error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return i, facts, e
	}
	defer tx.Rollback()
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	staged, e := s.migrationPreparationContext(ctx, tx, network, input.Proposal, now)
	if e != nil {
		return i, facts, e
	}
	r, prefix := staged.Record, staged.Prefix
	if !r.Fenced || r.LocalAck == "-" || prefix.Root == nil || input.Prepared != decMigrationHash(mustDecBytes(r.PreparedCatalog)) {
		return i, facts, decFailure("review_required")
	}
	if staged.Source.Facts.RootPublicKey != prefix.Fields.Root || staged.Source.Facts.Epoch != prefix.Fields.Epoch {
		return i, facts, decFailure("state_conflict")
	}
	ackRaw := [][]byte{}
	for _, encoded := range r.Acknowledgments {
		ackRaw = append(ackRaw, mustDecBytes(encoded))
	}
	_, ids, e := dec.VerifyMigrationAcknowledgments(staged.Source.Descriptor, prefix.Proposal.Raw, mustDecBytes(r.SourceCatalog), mustDecBytes(r.SourceState), mustDecBytes(r.PreparedCatalog), ackRaw, now)
	if e != nil {
		return i, facts, e
	}
	if !reflect.DeepEqual(input.Acks, ids) {
		return i, facts, decFailure("operation_conflict")
	}
	format := input.Format
	if format == "auto" || format == "ed25519" {
		key, e := migrationRootSeed(ctx, tx, network, prefix.Fields.Root)
		if e != nil {
			return i, facts, e
		}
		if key == nil {
			return i, facts, decFailure("signer_unavailable")
		}
		format = "ed25519"
	} else if format != "sshsig" {
		return i, facts, decFailure("invalid")
	}
	previous, e := migrationCommitIntent(ctx, tx, network, r)
	if e != nil {
		return i, facts, e
	}
	fresh, wasApproved := previous == nil, false
	if fresh {
		if r.Commit != "-" {
			return i, facts, decFailure("operation_conflict")
		}
		if e = decIntentCapacity(ctx, tx); e != nil {
			return i, facts, e
		}
		body, e := json.Marshal(decMigrationCommitPayload{input.Proposal, prefix.Root.ID, input.Prepared, ids, now})
		if e != nil {
			return i, facts, e
		}
		template, e := dec.StatementTemplate(staged.Source.Descriptor, "migration_commit", body, []dec.Signature{{Role: "issuer", PublicKey: prefix.Fields.Root, Format: format, Signature: "-"}})
		if e != nil {
			return i, facts, e
		}
		id, e := decRandomID("dint_")
		if e != nil {
			return i, facts, e
		}
		review := migrationParticipationReview(network, prefix, r, "root_commit")
		review.Warning = "Approve the one exact all-host migration commit. Every roster acknowledgment and the prepared catalog hash are fixed; this final root signature cannot replace any host's consent or clear its durable fence."
		reviewRaw, _ := json.Marshal(review)
		approvedAt := "-"
		if input.Approve {
			approvedAt = now
		}
		i = decIntent{ID: id, Network: network, Context: r.Context, Kind: "migration", Record: decIntentRecord{Format: 1, Operation: input.Proposal, Approved: input.Approve, ApprovedAt: approvedAt, Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: decIntentProvider{"root", prefix.Fields.Root, format, "-"}, Root: prefix.Root.ID, Person: "-", Host: "-", Device: "-", Scopes: 8, NotAfter: "-", Created: now, Expires: prefix.Fields.Expires, Templates: []decIntentTemplate{{1, "migration_commit", base64.StdEncoding.EncodeToString(template)}}, Signatures: []decIntentSignature{}, Terminal: "-", Result: "-"}}
		r.RootIntents = append(r.RootIntents, id)
	} else {
		i = *previous
		if i.Record.Provider.Format != format {
			return i, facts, decFailure("operation_conflict")
		}
		wasApproved = i.Record.Approved
		if input.Approve && !wasApproved {
			i.Record.Approved, i.Record.ApprovedAt = true, now
		}
	}
	_, statement, body, e := checkMigrationCommitIntent(staged.Source.Descriptor, i, r, prefix)
	if e != nil {
		return i, facts, e
	}
	budget := r
	budget.Commit = base64.StdEncoding.EncodeToString(body)
	full, e := completeMigrationBody(budget)
	if e != nil {
		return i, facts, e
	}
	// Fixed Ed25519/SSHSIG encodings have exact declared lengths. Account for
	// the missing signature without producing one or inventing public evidence.
	additional := 0
	for _, sig := range statement.Signatures {
		if sig.Signature != "-" {
			continue
		}
		raw := make([]byte, 64)
		if sig.Format == "sshsig" {
			key, e := membership.DecodeKey(sig.PublicKey)
			if e != nil {
				return i, facts, e
			}
			raw = membership.SSHSIGBlob(key, raw)
		}
		additional += base64.StdEncoding.EncodedLen(len(raw)) - 1
	}
	if len(full)+additional > dec.MaxObject {
		return i, facts, decFailure("quota_exceeded")
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	if latest >= prefix.Fields.Expires {
		return i, facts, decFailure("expired")
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return i, facts, e
	}
	if e = storeDecIntent(ctx, tx, i, fresh); e != nil {
		return i, facts, e
	}
	if e = storeDecMigration(ctx, tx, network, input.Proposal, r, false); e != nil {
		return i, facts, e
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return i, facts, e
	}
	if e = tx.Commit(); e != nil {
		return i, facts, e
	}
	facts.operation = input.Proposal
	if fresh {
		facts.add("dec.intent.after_commit")
	}
	if i.Record.Approved && !wasApproved {
		facts.add("dec.approval.after_commit")
	}
	return i, facts, nil
}

func (s *Store) CommitDecentralizedMigration(ctx context.Context, network string, input DecMigrationCommit) (DecMigrationResult, error) {
	if !dec.ValidID(network, "net_") || !dec.ValidID(input.Proposal, "ds_") || !decIDs(input.Acks, "ds_") {
		return DecMigrationResult{}, decFailure("invalid")
	}
	// A completed exact root commit remains a historical response after cutover
	// or expiry. It never prepares another signature or reads the decision clock.
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationResult{}, e
	}
	proposal, r, readError := migrationRecord(ctx, tx, network)
	var historical *decIntent
	if readError == nil {
		historical, readError = migrationCommitIntent(ctx, tx, network, r)
	}
	tx.Rollback()
	if readError != nil {
		return DecMigrationResult{}, readError
	}
	if historical != nil && historical.Record.Completed {
		if proposal != input.Proposal || input.Prepared != decMigrationHash(mustDecBytes(r.PreparedCatalog)) || (input.Format != historical.Record.Provider.Format && !(input.Format == "auto" && historical.Record.Provider.Format == "ed25519")) {
			return DecMigrationResult{}, decFailure("operation_conflict")
		}
		d, e := migrationDescriptor(r)
		if e != nil {
			return DecMigrationResult{}, e
		}
		statement, e := dec.ReadStatement(d, mustDecBytes(r.Commit))
		if e != nil {
			return DecMigrationResult{}, e
		}
		var payload decMigrationCommitPayload
		if json.Unmarshal(statement.Payload, &payload) != nil || !reflect.DeepEqual(payload.Acks, input.Acks) {
			return DecMigrationResult{}, decFailure("operation_conflict")
		}
		return s.migrationCommitResult(ctx, network, historical.ID)
	}
	i, facts, e := s.prepareMigrationCommit(ctx, network, input)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if e = facts.wait(ctx); e != nil {
		return DecMigrationResult{}, e
	}
	if i.Record.Approved && !i.Record.Completed {
		return s.advanceMigrationCommit(ctx, network, i.ID, nil)
	}
	return s.migrationCommitResult(ctx, network, i.ID)
}

func (s *Store) migrationCommitResult(ctx context.Context, network, id string) (DecMigrationResult, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationResult{}, e
	}
	defer tx.Rollback()
	_, r, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	d, e := migrationDescriptor(r)
	if e != nil {
		return DecMigrationResult{}, e
	}
	prefix, e := readMigrationPrefix(d, migrationRecordEvidence(r))
	if e != nil {
		return DecMigrationResult{}, e
	}
	i, e := readDecIntent(ctx, tx, id)
	if e != nil {
		return DecMigrationResult{}, e
	}
	review, statement, body, e := checkMigrationCommitIntent(d, i, r, prefix)
	if e != nil {
		return DecMigrationResult{}, e
	}
	view, e := s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	return DecMigrationResult{view, review, migrationSigning(i, []*dec.Statement{statement}, [][]byte{body})}, nil
}

func (s *Store) advanceMigrationCommit(ctx context.Context, network, id string, batch *DecSignatureBatch) (DecMigrationResult, error) {
	facts, e := s.persistMigrationCommitSignature(ctx, network, id, batch)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if e = facts.wait(ctx); e != nil {
		return DecMigrationResult{}, e
	}
	return s.migrationCommitResult(ctx, network, id)
}

func (s *Store) persistMigrationCommitSignature(ctx context.Context, network, id string, batch *DecSignatureBatch) (facts decCommittedFacts, err error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return facts, e
	}
	defer tx.Rollback()
	proposal, r, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	i, e := readDecIntent(ctx, tx, id)
	if e != nil {
		return facts, e
	}
	if !containsString(r.RootIntents, id) {
		return facts, decFailure("operation_conflict")
	}
	d, e := migrationDescriptor(r)
	if e != nil {
		return facts, e
	}
	prefix, e := readMigrationPrefix(d, migrationRecordEvidence(r))
	if e != nil {
		return facts, e
	}
	_, statement, _, e := checkMigrationCommitIntent(d, i, r, prefix)
	if e != nil {
		return facts, e
	}
	if !i.Record.Approved {
		return facts, decFailure("review_required")
	}
	if i.Record.Completed {
		if batch != nil {
			for _, sig := range batch.Signatures {
				if sig.Slot != 1 || sig.Role != "issuer" || decSlotSignature(i, 1, "issuer") != sig.Signature {
					return facts, decFailure("operation_conflict")
				}
			}
		}
		return facts, nil
	}
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	staged, e := s.migrationPreparationContext(ctx, tx, network, proposal, now)
	if e != nil {
		return facts, e
	}
	if !r.Fenced || r.LocalAck == "-" || staged.Source.Facts.RootPublicKey != i.Record.Provider.Signer || staged.Source.Facts.Epoch != prefix.Fields.Epoch {
		return facts, decFailure("state_conflict")
	}
	if now < i.Record.Created {
		return facts, decFailure("clock_rollback")
	}
	ackRaw := [][]byte{}
	for _, encoded := range r.Acknowledgments {
		ackRaw = append(ackRaw, mustDecBytes(encoded))
	}
	if _, _, e = dec.VerifyMigrationAcknowledgments(d, prefix.Proposal.Raw, mustDecBytes(r.SourceCatalog), mustDecBytes(r.SourceState), mustDecBytes(r.PreparedCatalog), ackRaw, now); e != nil {
		return facts, e
	}
	before := len(i.Record.Signatures)
	if batch != nil {
		if batch.Intent != id || validateDecSignatureBatch(*batch) != nil {
			return facts, decFailure("invalid")
		}
		for _, sig := range batch.Signatures {
			if sig.Slot != 1 || sig.Role != "issuer" {
				return facts, decFailure("invalid")
			}
			if e = dec.VerifySignature(i.Record.Provider.Signer, i.Record.Provider.Format, dec.SignatureMessage(statement.ID, "issuer", i.Record.Provider.Signer), sig.Signature); e != nil {
				return facts, e
			}
			if e = addDecSignature(&i, sig); e != nil {
				return facts, e
			}
		}
	}
	if i.Record.Provider.Format == "ed25519" && decSlotSignature(i, 1, "issuer") == "-" {
		key, e := migrationRootSeed(ctx, tx, network, i.Record.Provider.Signer)
		if e != nil {
			return facts, e
		}
		if key == nil {
			return facts, decFailure("signer_unavailable")
		}
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, dec.SignatureMessage(statement.ID, "issuer", i.Record.Provider.Signer)))
		if e = addDecSignature(&i, decIntentSignature{1, "issuer", sig}); e != nil {
			return facts, e
		}
	}
	statements, bodies, e := decIntentStatements(d, i)
	if e != nil {
		return facts, e
	}
	i.Record.Completed = decActionComplete(statements[0])
	if i.Record.Completed {
		r.Commit = base64.StdEncoding.EncodeToString(bodies[0])
		full, e := completeMigrationBody(r)
		if e != nil {
			return facts, e
		}
		if _, e = dec.VerifyMigration(d, []byte(`"-"`), []byte(`"-"`), full, now, "evidence", "-"); e != nil {
			return facts, e
		}
		r.Migration = base64.StdEncoding.EncodeToString(full)
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	if latest >= i.Record.Expires {
		return facts, decFailure("expired")
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return facts, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return facts, e
	}
	if e = storeDecMigration(ctx, tx, network, proposal, r, false); e != nil {
		return facts, e
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return facts, e
	}
	if e = tx.Commit(); e != nil {
		return facts, e
	}
	facts.operation = proposal
	if len(i.Record.Signatures) > before {
		facts.add("dec.signature.after_commit")
	}
	if i.Record.Completed {
		facts.add("dec.migration_commit.after_commit")
	}
	return facts, nil
}
