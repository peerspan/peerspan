package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecMigrationAcknowledgment struct {
	Proposal string `json:"proposal_id"`
	Prepared string `json:"prepared_catalog_sha256"`
	Approve  bool   `json:"approve"`
}

// Only this machine's completed reviewed requester ceremony supplies its local
// binding/device consent. A public activation cannot manufacture those flags.
func (s *Store) migrationOwnPreparedConsent(ctx context.Context, q dbQuerier, staged *decMigrationLinkContext, evidence *dec.MigrationPreparedEvidence) error {
	for _, row := range evidence.Hosts {
		if row.Host != staged.Own.Host {
			continue
		}
		if row.Person != staged.Own.Person || row.Device != staged.Own.Device {
			return decFailure("operation_conflict")
		}
		if row.Person == "-" {
			i, e := migrationHostIntent(ctx, q, staged.Source.Network.ID, staged.Prefix.Proposal.ID, staged.Own.Host)
			if e != nil {
				return e
			}
			if i == nil || !i.Record.Approved || !i.Record.Completed {
				return decFailure("review_required")
			}
			_, h, body, e := checkMigrationHostIntent(staged.Source.Descriptor, staged, *i)
			if e != nil {
				return e
			}
			if h.ID != row.HostLease {
				return decFailure("operation_conflict")
			}
			for _, object := range staged.Prefix.Catalog.Objects {
				if object.ID == dec.ProofID("host_lease", body) && bytes.Equal(object.Body, body) {
					return nil
				}
			}
			return decFailure("proof_required", dec.ProofID("host_lease", body))
		}
		activation := staged.Prefix.Catalog.Activations[row.Activation]
		if activation == nil {
			return decFailure("proof_required", row.Activation)
		}
		p, e := readDecPending(ctx, q, activation.Request.RequestID)
		if e != nil {
			return e
		}
		if p.Record.Migration != staged.Prefix.Proposal.ID || p.Record.Terminal != "migration_prepared" || !containsString(p.Record.Roles, "requester") || !p.Record.Selected || !p.Record.Committed || p.Record.ActivationID != row.Activation || !bytes.Equal(p.Request.Raw, activation.Request.Raw) || !bytes.Equal(mustDecBytes(p.Record.Selection), activation.Selection.Raw) || !bytes.Equal(mustDecBytes(p.Record.Commit), activation.Commit.Raw) {
			return decFailure("review_required")
		}
		return nil
	}
	return decFailure("forbidden")
}

func (s *Store) migrationAckContext(ctx context.Context, q dbQuerier, network, proposal, now string) (*decMigrationLinkContext, *dec.MigrationPreparedEvidence, error) {
	staged, e := s.migrationPreparationContext(ctx, q, network, proposal, now)
	if e != nil {
		return nil, nil, e
	}
	r := staged.Record
	if r.PreparedCatalog == "-" || staged.Prefix.Root == nil {
		return nil, nil, decFailure("proof_required", proposal)
	}
	evidence, e := dec.VerifyMigrationPrepared(staged.Source.Descriptor, staged.Prefix.Proposal.Raw, mustDecBytes(r.SourceCatalog), mustDecBytes(r.SourceState), mustDecBytes(r.PreparedCatalog), now, s.identity.PublicKey)
	if e != nil {
		return nil, nil, e
	}
	if e = s.migrationOwnPreparedConsent(ctx, q, staged, evidence); e != nil {
		return nil, nil, e
	}
	pending, e := migrationLegacyPending(ctx, q, network)
	if e != nil {
		return nil, nil, e
	}
	if len(pending) > 0 {
		return nil, nil, decFailure("migration_pending", pending...)
	}
	if staged.Own.Person != "-" {
		owned, e := s.migrationLinkContext(ctx, q, network, proposal, now)
		if e != nil {
			return nil, nil, e
		}
		staged.Seed = owned.Seed
	}
	return staged, evidence, nil
}

func migrationAckProvider(staged *decMigrationLinkContext, evidence *dec.MigrationPreparedEvidence) (decIntentProvider, error) {
	if staged.Own.Person == "-" {
		return decIntentProvider{"host", staged.Own.Host, "ed25519", "-"}, nil
	}
	for _, row := range evidence.Hosts {
		if row.Host == staged.Own.Host {
			return decIntentProvider{"device", staged.Own.Device, "ed25519", row.DeviceLease}, nil
		}
	}
	return decIntentProvider{}, decFailure("forbidden")
}

func checkMigrationAckIntent(d dec.Descriptor, staged *decMigrationLinkContext, evidence *dec.MigrationPreparedEvidence, i decIntent) (DecMigrationReview, *dec.Statement, []byte, error) {
	var review DecMigrationReview
	r := i.Record
	provider, e := migrationAckProvider(staged, evidence)
	if e != nil {
		return review, nil, nil, e
	}
	if i.Network != d.NetworkID || i.Context != d.ContextID || i.Kind != "migration" || i.Secret != nil || r.Provider != provider || r.Operation != staged.Prefix.Proposal.ID || r.Root != evidence.Root || r.Person != staged.Own.Person || r.Host != staged.Own.Host || r.Device != staged.Own.Device || r.Scopes != staged.Own.Scopes || r.NotAfter != "-" || r.Expires != staged.Prefix.Fields.Expires || r.Created < staged.Prefix.Fields.Issued || r.Created >= r.Expires || r.Approved && r.ApprovedAt >= r.Expires || r.Result != "-" || r.Terminal != "-" || len(r.Templates) != 1 || r.Templates[0].Type != "migration_ack" {
		return review, nil, nil, decStorageError()
	}
	statement, body, e := decFilledTemplate(d, i, r.Templates[0])
	if e != nil {
		return review, nil, nil, e
	}
	wantPayload, e := dec.MigrationAcknowledgmentPayload(evidence, staged.Own.Host, r.Created)
	if e != nil {
		return review, nil, nil, e
	}
	var actual, want any
	if json.Unmarshal(statement.Payload, &actual) != nil || json.Unmarshal(wantPayload, &want) != nil || !reflect.DeepEqual(actual, want) || r.Completed != decActionComplete(statement) {
		return review, nil, nil, decStorageError()
	}
	wantRoles := []dec.Signature{{Role: "host", PublicKey: staged.Own.Host, Format: "ed25519"}}
	if staged.Own.Person != "-" {
		wantRoles = append([]dec.Signature{{Role: "device", PublicKey: staged.Own.Device, Format: "ed25519"}}, wantRoles...)
	}
	if len(statement.Signatures) != len(wantRoles) {
		return review, nil, nil, decStorageError()
	}
	for n, sig := range statement.Signatures {
		role := wantRoles[n]
		if sig.Role != role.Role || sig.PublicKey != role.PublicKey || sig.Format != role.Format {
			return review, nil, nil, decStorageError()
		}
	}
	if dec.ReadPrivateRecord(mustDecBytes(r.Review), decMigrationReviewFields, &review) != nil {
		return review, nil, nil, decStorageError()
	}
	wantReview := migrationParticipationReview(d.NetworkID, staged.Prefix, staged.Record, "acknowledgment")
	wantReview.Warning = review.Warning
	if review.Warning == "" || len(review.Warning) > 1024 || !reflect.DeepEqual(review, wantReview) {
		return review, nil, nil, decStorageError()
	}
	return review, statement, body, nil
}

// Account for ALL future roster ACKs and the final root signature without
// signing anything. Their key/hash/time encodings have fixed lengths. This is
// size preflight only, never a public incomplete proof or authority candidate.
func migrationAckBudget(staged *decMigrationLinkContext, evidence *dec.MigrationPreparedEvidence, now string) error {
	d, r := staged.Source.Descriptor, staged.Record
	acks, ids, extra := []json.RawMessage{}, []string{}, 0
	for _, row := range evidence.Hosts {
		payload, e := dec.MigrationAcknowledgmentPayload(evidence, row.Host, now)
		if e != nil {
			return e
		}
		roles := []dec.Signature{{Role: "host", PublicKey: row.Host, Format: "ed25519", Signature: "-"}}
		if row.Person != "-" {
			roles = append(roles, dec.Signature{Role: "device", PublicKey: row.Device, Format: "ed25519", Signature: "-"})
		}
		raw, e := dec.StatementTemplate(d, "migration_ack", payload, roles)
		if e != nil {
			return e
		}
		statement, e := dec.ReadStatementTemplate(d, raw)
		if e != nil {
			return e
		}
		acks = append(acks, raw)
		ids = append(ids, statement.ID)
		extra += len(roles) * (base64.StdEncoding.EncodedLen(ed25519.SignatureSize) - 1)
	}
	sort.Strings(ids)
	payload, _ := json.Marshal(decMigrationCommitPayload{staged.Prefix.Proposal.ID, evidence.Root, evidence.PreparedHash, ids, now})
	// Root commit selects its format independently of the proposal. Reserve
	// the larger permitted SSHSIG encoding before this host becomes fenced.
	format := "sshsig"
	commit, e := dec.StatementTemplate(d, "migration_commit", payload, []dec.Signature{{Role: "issuer", PublicKey: staged.Prefix.Fields.Root, Format: format, Signature: "-"}})
	if e != nil {
		return e
	}
	key, e := membership.DecodeKey(staged.Prefix.Fields.Root)
	if e != nil {
		return e
	}
	rootSignatureSize := ed25519.SignatureSize
	if format == "sshsig" {
		rootSignatureSize = len(membership.SSHSIGBlob(key, make([]byte, ed25519.SignatureSize)))
	}
	extra += base64.StdEncoding.EncodedLen(rootSignatureSize) - 1
	raw, e := migrationCompositeBody(mustDecBytes(r.Proposal), r.SourceCatalog, r.SourceState, r.PreparedCatalog, acks, commit)
	if e != nil {
		return e
	}
	if len(raw)+extra > dec.MaxObject {
		return decFailure("quota_exceeded")
	}
	return nil
}

func (s *Store) prepareMigrationAck(ctx context.Context, network string, input DecMigrationAcknowledgment) (decIntent, decCommittedFacts, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	var i decIntent
	facts := decCommittedFacts{operation: input.Proposal}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return i, facts, e
	}
	defer tx.Rollback()
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	staged, evidence, e := s.migrationAckContext(ctx, tx, network, input.Proposal, now)
	if e != nil {
		return i, facts, e
	}
	r := staged.Record
	if input.Prepared != evidence.PreparedHash {
		return i, facts, decFailure("operation_conflict")
	}
	if e = migrationAckBudget(staged, evidence, now); e != nil {
		return i, facts, e
	}
	fresh, wasApproved := r.AckIntent == "-", false
	if fresh {
		if r.Fenced || r.LocalAck != "-" || r.Commit != "-" {
			return i, facts, decFailure("migration_pending")
		}
		if e = decIntentCapacity(ctx, tx); e != nil {
			return i, facts, e
		}
		id, e := decRandomID("dint_")
		if e != nil {
			return i, facts, e
		}
		payload, e := dec.MigrationAcknowledgmentPayload(evidence, staged.Own.Host, now)
		if e != nil {
			return i, facts, e
		}
		roles := []dec.Signature{{Role: "host", PublicKey: staged.Own.Host, Format: "ed25519", Signature: "-"}}
		if staged.Own.Person != "-" {
			roles = append(roles, dec.Signature{Role: "device", PublicKey: staged.Own.Device, Format: "ed25519", Signature: "-"})
		}
		template, e := dec.StatementTemplate(staged.Source.Descriptor, "migration_ack", payload, roles)
		if e != nil {
			return i, facts, e
		}
		provider, e := migrationAckProvider(staged, evidence)
		if e != nil {
			return i, facts, e
		}
		review := migrationParticipationReview(network, staged.Prefix, r, "acknowledgment")
		review.Warning = "Approve eventual adoption of this exact complete prepared catalog and every roster host. The later durable acknowledgment fence has no timeout abort; missing peers cannot clear it. This signs only this machine's exact host/device contribution and selects no active provider."
		reviewRaw, _ := json.Marshal(review)
		approvedAt := "-"
		if input.Approve {
			approvedAt = now
		}
		i = decIntent{ID: id, Network: network, Context: r.Context, Kind: "migration", Record: decIntentRecord{Format: 1, Operation: input.Proposal, Approved: input.Approve, ApprovedAt: approvedAt, Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: provider, Root: evidence.Root, Person: staged.Own.Person, Host: staged.Own.Host, Device: staged.Own.Device, Scopes: staged.Own.Scopes, NotAfter: "-", Created: now, Expires: staged.Prefix.Fields.Expires, Templates: []decIntentTemplate{{1, "migration_ack", base64.StdEncoding.EncodeToString(template)}}, Signatures: []decIntentSignature{}, Terminal: "-", Result: "-"}}
		r.AckIntent = id
	} else {
		i, e = readDecIntent(ctx, tx, r.AckIntent)
		if e != nil {
			return i, facts, e
		}
		wasApproved = i.Record.Approved
		if input.Approve && !wasApproved {
			i.Record.Approved = true
			i.Record.ApprovedAt = now
		}
	}
	if _, _, _, e = checkMigrationAckIntent(staged.Source.Descriptor, staged, evidence, i); e != nil {
		return i, facts, e
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return i, facts, e
	}
	if _, _, e = s.migrationAckContext(ctx, tx, network, input.Proposal, latest); e != nil {
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
	if fresh {
		facts.add("dec.intent.after_commit")
	}
	if i.Record.Approved && !wasApproved {
		facts.add("dec.approval.after_commit")
	}
	return i, facts, nil
}

func (s *Store) AcknowledgeDecentralizedMigration(ctx context.Context, network string, input DecMigrationAcknowledgment) (DecMigrationResult, error) {
	if !dec.ValidID(network, "net_") || !dec.ValidID(input.Proposal, "ds_") || !dec.ValidID(input.Prepared, "") {
		return DecMigrationResult{}, decFailure("invalid")
	}
	read, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationResult{}, e
	}
	proposal, r, e := migrationRecord(ctx, read, network)
	read.Rollback()
	if e != nil {
		return DecMigrationResult{}, e
	}
	if proposal != input.Proposal || r.PreparedCatalog != "-" && decMigrationHash(mustDecBytes(r.PreparedCatalog)) != input.Prepared {
		return DecMigrationResult{}, decFailure("operation_conflict")
	}
	if r.LocalAck != "-" && r.Fenced {
		return s.migrationAckResult(ctx, network)
	}
	i, facts, e := s.prepareMigrationAck(ctx, network, input)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if e = facts.wait(ctx); e != nil {
		return DecMigrationResult{}, e
	}
	if i.Record.Approved {
		return s.advanceMigrationAck(ctx, network)
	}
	return s.migrationAckResult(ctx, network)
}

func (s *Store) advanceMigrationAck(ctx context.Context, network string) (DecMigrationResult, error) {
	for _, fence := range []bool{false, true} {
		facts, e := s.persistMigrationAckPhase(ctx, network, fence)
		if e != nil {
			return DecMigrationResult{}, e
		}
		if e = facts.wait(ctx); e != nil {
			return DecMigrationResult{}, e
		}
	}
	return s.migrationAckResult(ctx, network)
}

func (s *Store) persistMigrationAckPhase(ctx context.Context, network string, fence bool) (decCommittedFacts, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	facts := decCommittedFacts{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return facts, e
	}
	defer tx.Rollback()
	proposal, r, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	facts.operation = proposal
	if r.Fenced && r.LocalAck != "-" {
		return facts, nil
	}
	if r.AckIntent == "-" {
		return facts, decFailure("review_required")
	}
	i, e := readDecIntent(ctx, tx, r.AckIntent)
	if e != nil {
		return facts, e
	}
	if !i.Record.Approved {
		return facts, decFailure("review_required")
	}
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	staged, evidence, e := s.migrationAckContext(ctx, tx, network, proposal, now)
	if e != nil {
		return facts, e
	}
	_, statement, body, e := checkMigrationAckIntent(staged.Source.Descriptor, staged, evidence, i)
	if e != nil {
		return facts, e
	}
	if now < i.Record.Created {
		return facts, decFailure("clock_rollback")
	}
	if e = migrationAckBudget(staged, evidence, now); e != nil {
		return facts, e
	}
	if !fence {
		if i.Record.Completed {
			return facts, nil
		}
		for _, role := range statement.Signatures {
			var key ed25519.PrivateKey
			if role.Role == "host" {
				key = s.privateKey
			} else {
				key = ed25519.NewKeyFromSeed(staged.Seed)
			}
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, dec.SignatureMessage(statement.ID, role.Role, role.PublicKey)))
			if e = addDecSignature(&i, decIntentSignature{1, role.Role, sig}); e != nil {
				return facts, e
			}
		}
		i.Record.Completed = true
		if _, _, _, e = checkMigrationAckIntent(staged.Source.Descriptor, staged, evidence, i); e != nil {
			return facts, e
		}
		facts.add("dec.signature.after_commit")
	} else {
		if !i.Record.Completed {
			return facts, decFailure("review_required")
		}
		if _, e = dec.ReadStatement(staged.Source.Descriptor, body); e != nil {
			return facts, e
		}
		if _, e = s.checkMigrationLocalAckConflict(staged.Source.Descriptor, r, statement); e != nil {
			return facts, e
		}
		r.LocalAck = base64.StdEncoding.EncodeToString(body)
		r.Fenced = true
		r.State = "acknowledged"
		found := false
		for _, encoded := range r.Acknowledgments {
			existing, e := dec.ReadStatement(staged.Source.Descriptor, mustDecBytes(encoded))
			if e != nil {
				return facts, e
			}
			found = found || existing.ID == statement.ID
		}
		if !found {
			r.Acknowledgments = append(r.Acknowledgments, r.LocalAck)
		}
		sort.Slice(r.Acknowledgments, func(a, b int) bool {
			left, _ := dec.ReadStatement(staged.Source.Descriptor, mustDecBytes(r.Acknowledgments[a]))
			right, _ := dec.ReadStatement(staged.Source.Descriptor, mustDecBytes(r.Acknowledgments[b]))
			return left.Signer("host") < right.Signer("host")
		})
		facts.add("dec.migration_fence.after_commit")
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return facts, e
	}
	if _, _, e = s.migrationAckContext(ctx, tx, network, proposal, latest); e != nil {
		return facts, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return facts, e
	}
	if fence {
		if e = storeDecMigration(ctx, tx, network, proposal, r, false); e != nil {
			return facts, e
		}
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return facts, e
	}
	if e = tx.Commit(); e != nil {
		return facts, e
	}
	return facts, nil
}

func (s *Store) checkMigrationLocalAckConflict(d dec.Descriptor, r decMigrationRecord, statement *dec.Statement) (bool, error) {
	for _, encoded := range r.Acknowledgments {
		ack, e := dec.ReadStatement(d, mustDecBytes(encoded))
		if e != nil {
			return false, e
		}
		if ack.Signer("host") == s.identity.PublicKey && ack.ID != statement.ID {
			return false, decFailure("state_conflict")
		}
	}
	return true, nil
}

func (s *Store) migrationAckResult(ctx context.Context, network string) (DecMigrationResult, error) {
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
	i, e := readDecIntent(ctx, tx, r.AckIntent)
	if e != nil {
		return DecMigrationResult{}, e
	}
	// Historical result checks source/prepared provenance at the original fixed
	// instant, without advancing the guard or requiring present signing power.
	evidence, e := dec.VerifyMigrationPrepared(d, prefix.Proposal.Raw, mustDecBytes(r.SourceCatalog), mustDecBytes(r.SourceState), mustDecBytes(r.PreparedCatalog), i.Record.Created, "-")
	if e != nil {
		return DecMigrationResult{}, e
	}
	var own DecMigrationRoster
	for _, row := range prefix.Fields.Roster {
		if row.Host == s.identity.PublicKey {
			own = row
		}
	}
	staged := &decMigrationLinkContext{Prefix: prefix, Record: r, Own: own}
	review, _, _, e := checkMigrationAckIntent(d, staged, evidence, i)
	if e != nil {
		return DecMigrationResult{}, e
	}
	view, e := s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	return DecMigrationResult{view, review, []DecSigningRequest{}}, nil
}
