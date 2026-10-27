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
)

type DecMigrationHostLease struct {
	Proposal string `json:"proposal_id"`
	Template string `json:"host_lease_base64"`
	Approve  bool   `json:"approve"`
}

type DecMigrationHostReview struct {
	Stage    string `json:"stage"`
	Network  string `json:"network_id"`
	Proposal string `json:"proposal_id"`
	Host     string `json:"host_public_key"`
	Member   string `json:"member"`
	Root     string `json:"root_state_id"`
	Lease    string `json:"host_lease_id"`
	Issued   string `json:"issued_at"`
	Before   string `json:"not_before"`
	After    string `json:"not_after"`
	Warning  string `json:"authority_warning"`
}

const decMigrationHostReviewFields = "stage network_id proposal_id host_public_key member root_state_id host_lease_id issued_at not_before not_after authority_warning"

type DecMigrationHostResult struct {
	Migration DecMigrationView       `json:"migration"`
	Template  string                 `json:"host_lease_base64"`
	Review    DecMigrationHostReview `json:"review"`
	Signing   []DecSigningRequest    `json:"signing_requests"`
}

func migrationHostReview(network, proposal string, statement *dec.Statement) DecMigrationHostReview {
	l := statement.Lease
	return DecMigrationHostReview{"host_membership", network, proposal, l.Subject.Host, l.Subject.Member, l.Root, statement.ID, l.Issued, l.Before, l.After, "Approve only this exact finite host membership. This creates no person or device ownership, acknowledgment, fence, active context or selected provider; acknowledgment requires separate approval of the complete prepared catalog."}
}

func checkMigrationHostTemplate(d dec.Descriptor, staged *decMigrationLinkContext, raw []byte, complete bool, now string) (*dec.Statement, error) {
	statement, e := dec.ReadStatementTemplate(d, raw)
	if e != nil {
		return nil, e
	}
	l := statement.Lease
	if staged.Own.Person != "-" || staged.Own.Device != "-" || staged.Own.Scopes != 0 || staged.Prefix.Root == nil || l == nil || statement.Kind != "host_lease" || l.Root != staged.Prefix.Root.ID || l.Operation != staged.Prefix.Proposal.ID || l.Sequence != 1 || len(l.Predecessors) != 0 || len(l.Resolves) != 0 || len(l.Retained) != 0 || len(l.Parents) != 0 || l.Issuer != (dec.Issuer{Kind: "root", Person: "-"}) || l.Subject != (dec.Subject{Host: staged.Own.Host, Person: "-", Device: "-", Member: staged.Own.Member, Scopes: 0}) || len(statement.Signatures) != 2 {
		return nil, decFailure("forbidden")
	}
	for _, sig := range statement.Signatures {
		switch sig.Role {
		case "host":
			if sig.PublicKey != staged.Own.Host || sig.Format != "ed25519" || (sig.Signature != "-") != complete {
				return nil, decFailure("invalid")
			}
		case "issuer":
			if sig.PublicKey != staged.Prefix.Fields.Root || sig.Signature == "-" {
				return nil, decFailure("invalid")
			}
		default:
			return nil, decFailure("invalid")
		}
	}
	if l.Issued < staged.Prefix.Fields.Issued || l.Issued >= staged.Prefix.Fields.Expires {
		return nil, decFailure("invalid")
	}
	if now != "-" {
		if now < l.Issued || now < l.Before {
			return nil, decFailure("not_yet_valid")
		}
		if now >= l.After {
			return nil, decFailure("authority_expired")
		}
	}
	return statement, nil
}

func migrationHostIntent(ctx context.Context, q dbQuerier, network, proposal, host string) (*decIntent, error) {
	rows, e := q.QueryContext(ctx, `SELECT intent_id FROM dec_intents WHERE network_id=? AND kind='migration' ORDER BY intent_id`, network)
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
		if i.Record.Operation != proposal || i.Record.Provider.Kind != "host" || i.Record.Host != host || len(i.Record.Templates) != 1 || i.Record.Templates[0].Type != "host_lease" {
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

func migrationHostBudget(staged *decMigrationLinkContext, statement *dec.Statement, raw []byte) error {
	objects := []dec.CatalogObject{}
	if staged.Prefix.Catalog != nil {
		objects = append(objects, staged.Prefix.Catalog.Objects...)
		for _, existing := range staged.Prefix.Catalog.Statements {
			if existing.ID == statement.ID {
				return migrationPreparationBudget(staged.Record, staged.Prefix.Proposal.Raw, staged.Prefix.Catalog.Raw)
			}
		}
	}
	// Size-only stand-in for the fixed-length raw host signature. These bytes
	// are never parsed as a proof, stored, returned, signed or admitted.
	estimated := make([]byte, len(raw)+base64.StdEncoding.EncodedLen(ed25519.SignatureSize)-1)
	objects = append(objects, dec.CatalogObject{ID: dec.ProofID("host_lease", raw), Kind: "host_lease", BodyBase64: base64.StdEncoding.EncodeToString(estimated)})
	prepared, e := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, staged.Prefix.Proposal.ContextID, objects})
	if e != nil {
		return e
	}
	return migrationPreparationBudget(staged.Record, staged.Prefix.Proposal.Raw, prepared)
}

func checkMigrationHostIntent(d dec.Descriptor, staged *decMigrationLinkContext, i decIntent) (DecMigrationHostReview, *dec.Statement, []byte, error) {
	var review DecMigrationHostReview
	if !decHostSelectorAllowed(i) || !i.Record.Approved || i.Record.ApprovedAt >= i.Record.Expires || i.Record.Provider.Kind != "host" || i.Kind != "migration" || i.Network != d.NetworkID || i.Context != d.ContextID || i.Record.Operation != staged.Prefix.Proposal.ID || i.Record.Host != staged.Own.Host || i.Record.Expires != staged.Prefix.Fields.Expires || i.Secret != nil {
		return review, nil, nil, decStorageError()
	}
	statement, body, e := decFilledTemplate(d, i, i.Record.Templates[0])
	if e != nil {
		return review, nil, nil, e
	}
	if _, e = checkMigrationHostTemplate(d, staged, body, i.Record.Completed, "-"); e != nil {
		return review, nil, nil, e
	}
	if i.Record.Root != statement.Lease.Root || i.Record.NotAfter != statement.Lease.After || i.Record.Created < staged.Prefix.Fields.Issued || i.Record.Created >= staged.Prefix.Fields.Expires || dec.ReadPrivateRecord(mustDecBytes(i.Record.Review), decMigrationHostReviewFields, &review) != nil {
		return review, nil, nil, decStorageError()
	}
	want := migrationHostReview(d.NetworkID, staged.Prefix.Proposal.ID, statement)
	want.Warning = review.Warning
	if review.Warning == "" || len(review.Warning) > 1024 || !reflect.DeepEqual(review, want) {
		return review, nil, nil, decStorageError()
	}
	return review, statement, body, nil
}

func (s *Store) PrepareDecentralizedMigrationHost(ctx context.Context, network string, input DecMigrationHostLease) (DecMigrationHostResult, error) {
	if !dec.ValidID(network, "net_") || !dec.ValidID(input.Proposal, "ds_") {
		return DecMigrationHostResult{}, decFailure("invalid")
	}
	raw, e := decBytes(input.Template, dec.MaxObject)
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	read, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	previous, e := migrationHostIntent(ctx, read, network, input.Proposal, s.identity.PublicKey)
	read.Rollback()
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	if previous != nil && previous.Record.Completed {
		if previous.Record.Templates[0].Template != input.Template {
			return DecMigrationHostResult{}, decFailure("operation_conflict")
		}
		return s.migrationHostResult(ctx, network, previous.ID)
	}
	i, preview, facts, e := s.prepareMigrationHost(ctx, network, input, raw)
	if e != nil {
		return preview, e
	}
	if e = facts.wait(ctx); e != nil {
		return preview, e
	}
	if i == nil {
		return preview, nil
	}
	if i.Record.Approved && !i.Record.Completed {
		facts, e = s.signMigrationHost(ctx, network, i.ID)
		if e != nil {
			return preview, e
		}
		if e = facts.wait(ctx); e != nil {
			return preview, e
		}
	}
	return s.migrationHostResult(ctx, network, i.ID)
}

func (s *Store) prepareMigrationHost(ctx context.Context, network string, input DecMigrationHostLease, raw []byte) (*decIntent, DecMigrationHostResult, decCommittedFacts, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	result := DecMigrationHostResult{Signing: []DecSigningRequest{}}
	facts := decCommittedFacts{operation: input.Proposal}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, result, facts, e
	}
	defer tx.Rollback()
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return nil, result, facts, e
	}
	staged, e := s.migrationPreparationContext(ctx, tx, network, input.Proposal, now)
	if e != nil {
		return nil, result, facts, e
	}
	statement, e := checkMigrationHostTemplate(staged.Source.Descriptor, staged, raw, false, now)
	if e != nil {
		return nil, result, facts, e
	}
	previous, e := migrationHostIntent(ctx, tx, network, input.Proposal, s.identity.PublicKey)
	if e != nil {
		return nil, result, facts, e
	}
	review := migrationHostReview(network, input.Proposal, statement)
	result.Review, result.Template = review, input.Template
	result.Migration, e = s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return nil, result, facts, e
	}
	if previous != nil {
		if previous.Record.Templates[0].Template != input.Template {
			return nil, result, facts, decFailure("operation_conflict")
		}
		if _, _, _, e = checkMigrationHostIntent(staged.Source.Descriptor, staged, *previous); e != nil {
			return nil, result, facts, e
		}
		return previous, result, facts, nil
	}
	if !input.Approve {
		return nil, result, facts, nil
	}
	if e = migrationHostBudget(staged, statement, raw); e != nil {
		return nil, result, facts, e
	}
	if staged.Record.Fenced || staged.Record.Commit != "-" {
		return nil, result, facts, decFailure("migration_pending")
	}
	if e = decIntentCapacity(ctx, tx); e != nil {
		return nil, result, facts, e
	}
	id, e := decRandomID("dint_")
	if e != nil {
		return nil, result, facts, e
	}
	reviewRaw, _ := json.Marshal(review)
	i := decIntent{ID: id, Network: network, Context: staged.Source.Descriptor.ContextID, Kind: "migration", Record: decIntentRecord{Format: 1, Operation: input.Proposal, Approved: true, ApprovedAt: now, Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: decIntentProvider{"host", s.identity.PublicKey, "ed25519", "-"}, Root: statement.Lease.Root, Person: "-", Host: s.identity.PublicKey, Device: "-", Scopes: 0, NotAfter: statement.Lease.After, Created: now, Expires: staged.Prefix.Fields.Expires, Templates: []decIntentTemplate{{1, "host_lease", input.Template}}, Signatures: []decIntentSignature{}, Terminal: "-", Result: "-"}}
	if _, _, _, e = checkMigrationHostIntent(staged.Source.Descriptor, staged, i); e != nil {
		return nil, result, facts, e
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return nil, result, facts, e
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return nil, result, facts, e
	}
	if _, e = s.migrationPreparationContext(ctx, tx, network, input.Proposal, latest); e != nil {
		return nil, result, facts, e
	}
	if _, e = checkMigrationHostTemplate(staged.Source.Descriptor, staged, raw, false, latest); e != nil {
		return nil, result, facts, e
	}
	if e = storeDecIntent(ctx, tx, i, true); e != nil {
		return nil, result, facts, e
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return nil, result, facts, e
	}
	if e = tx.Commit(); e != nil {
		return nil, result, facts, e
	}
	facts.add("dec.intent.after_commit")
	facts.add("dec.approval.after_commit")
	return &i, result, facts, nil
}

func (s *Store) signMigrationHost(ctx context.Context, network, id string) (decCommittedFacts, error) {
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
	i, e := readDecIntent(ctx, tx, id)
	if e != nil {
		return facts, e
	}
	facts.operation = i.Record.Operation
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	staged, e := s.migrationPreparationContext(ctx, tx, network, i.Record.Operation, now)
	if e != nil {
		return facts, e
	}
	_, statement, body, e := checkMigrationHostIntent(staged.Source.Descriptor, staged, i)
	if e != nil {
		return facts, e
	}
	if !i.Record.Approved {
		return facts, decFailure("review_required")
	}
	if i.Record.Completed {
		return facts, nil
	}
	if _, e = checkMigrationHostTemplate(staged.Source.Descriptor, staged, body, false, now); e != nil {
		return facts, e
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, dec.SignatureMessage(statement.ID, "host", s.identity.PublicKey)))
	if e = addDecSignature(&i, decIntentSignature{1, "host", sig}); e != nil {
		return facts, e
	}
	i.Record.Completed = true
	_, body, e = decFilledTemplate(staged.Source.Descriptor, i, i.Record.Templates[0])
	if e != nil {
		return facts, e
	}
	full, e := dec.ReadStatement(staged.Source.Descriptor, body)
	if e != nil {
		return facts, e
	}
	catalog, e := migrationProposalCatalog(staged.Source.Descriptor, []*dec.Statement{full}, [][]byte{body})
	if e != nil {
		return facts, e
	}
	r := staged.Record
	if e = mergeMigrationPrepared(staged.Source.Descriptor, &r, DecMigrationEvidence{Catalog: catalog, Acknowledgments: []json.RawMessage{}, Commit: json.RawMessage(`"-"`)}); e != nil {
		return facts, e
	}
	if e = migrationPreparationBudget(r, mustDecBytes(r.Proposal), mustDecBytes(r.PreparedCatalog)); e != nil {
		return facts, e
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return facts, e
	}
	if _, e = s.migrationPreparationContext(ctx, tx, network, i.Record.Operation, latest); e != nil {
		return facts, e
	}
	if _, e = checkMigrationHostTemplate(staged.Source.Descriptor, staged, body, true, latest); e != nil {
		return facts, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return facts, e
	}
	if e = storeDecMigration(ctx, tx, network, i.Record.Operation, r, false); e != nil {
		return facts, e
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return facts, e
	}
	if e = tx.Commit(); e != nil {
		return facts, e
	}
	facts.add("dec.signature.after_commit")
	return facts, nil
}

func (s *Store) migrationHostResult(ctx context.Context, network, id string) (DecMigrationHostResult, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	defer tx.Rollback()
	_, r, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	d, e := migrationDescriptor(r)
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	prefix, e := readMigrationPrefix(d, migrationRecordEvidence(r))
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	i, e := readDecIntent(ctx, tx, id)
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	var own DecMigrationRoster
	for _, row := range prefix.Fields.Roster {
		if row.Host == s.identity.PublicKey {
			own = row
		}
	}
	review, _, body, e := checkMigrationHostIntent(d, &decMigrationLinkContext{Prefix: prefix, Own: own}, i)
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	view, e := s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return DecMigrationHostResult{}, e
	}
	if !bytes.Equal(mustDecBytes(i.Record.Templates[0].Template), body) && !i.Record.Completed {
		return DecMigrationHostResult{}, decStorageError()
	}
	return DecMigrationHostResult{view, base64.StdEncoding.EncodeToString(body), review, []DecSigningRequest{}}, nil
}
