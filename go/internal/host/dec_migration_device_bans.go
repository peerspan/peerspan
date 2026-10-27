package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecMigrationDeviceBans struct {
	Proposal string `json:"proposal_id"`
	Person   string `json:"person_public_key"`
	Approve  bool   `json:"approve"`
}
type DecMigrationDeviceCopy struct {
	Device    string   `json:"device_public_key"`
	Proofs    []string `json:"source_proof_ids"`
	Statement string   `json:"statement_id"`
}
type DecMigrationDeviceBanReview struct {
	Stage       string                   `json:"stage"`
	Network     string                   `json:"network_id"`
	Proposal    string                   `json:"proposal_id"`
	Context     string                   `json:"new_context_id"`
	Person      string                   `json:"person_public_key"`
	Root        string                   `json:"root_state_id"`
	PersonLease string                   `json:"person_lease_id"`
	SourceHash  string                   `json:"source_catalog_sha256"`
	StateHash   string                   `json:"source_state_sha256"`
	Copies      []DecMigrationDeviceCopy `json:"copies"`
	Maxima      []dec.LegacyMaximum      `json:"access_maxima"`
	Warning     string                   `json:"authority_warning"`
}
type DecMigrationDeviceBanResult struct {
	Migration DecMigrationView            `json:"migration"`
	Review    DecMigrationDeviceBanReview `json:"review"`
	Signing   []DecSigningRequest         `json:"signing_requests"`
}

const migrationDeviceBanReviewFields = "stage network_id proposal_id new_context_id person_public_key root_state_id person_lease_id source_catalog_sha256 source_state_sha256 copies access_maxima authority_warning"

func migrationDeviceBanIntent(i decIntent) bool {
	if i.Kind != "migration" || i.Record.Provider.Kind != "original" || len(i.Record.Templates) == 0 {
		return false
	}
	for _, t := range i.Record.Templates {
		if t.Type != "device_revoke" {
			return false
		}
	}
	return true
}
func migrationDeviceBanIntents(ctx context.Context, q dbQuerier, network, proposal, person string) ([]decIntent, error) {
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
	found := []decIntent{}
	seen := map[string]bool{}
	for _, id := range ids {
		i, e := readDecIntent(ctx, q, id)
		if e != nil {
			return nil, e
		}
		if !migrationDeviceBanIntent(i) || i.Record.Operation != proposal || person != "-" && i.Record.Person != person {
			continue
		}
		if seen[i.Record.Person] {
			return nil, decStorageError()
		}
		seen[i.Record.Person] = true
		found = append(found, i)
	}
	sort.Slice(found, func(a, b int) bool { return found[a].Record.Person < found[b].Record.Person })
	return found, nil
}
func migrationDeviceBanContext(staged *decMigrationLinkContext, person, now string) (*dec.Statement, []decMigrationBan, error) {
	if !dec.ValidPublicKey(person) {
		return nil, nil, decFailure("invalid")
	}
	if !staged.Prefix.Facts.Facts.State.Persons[person].Admitted {
		return nil, nil, decFailure("forbidden")
	}
	if staged.Prefix.Root == nil || staged.Prefix.Catalog == nil {
		return nil, nil, decFailure("proof_required", staged.Prefix.Proposal.ID)
	}
	var p *dec.Statement
	for _, s := range staged.Prefix.Catalog.Statements {
		if s.Kind != "person_lease" || s.Lease.Subject.Person != person {
			continue
		}
		if p != nil && p.ID != s.ID {
			return nil, nil, decFailure("state_conflict")
		}
		l := s.Lease
		if l.Root != staged.Prefix.Root.ID || l.Operation != "-" || l.Sequence != 1 || len(l.Predecessors) != 0 || len(l.Resolves) != 0 || len(l.Retained) != 0 || len(l.Parents) != 0 || l.Issuer != (dec.Issuer{Kind: "root", Person: "-"}) || s.Signer("issuer") != staged.Prefix.Fields.Root || l.Subject.Host != "-" || l.Subject.Device != "-" || l.Subject.Scopes != 0 || l.Subject.Member != staged.Prefix.Facts.Facts.PersonLabels[person] {
			return nil, nil, decFailure("forbidden")
		}
		if now < l.Issued || now < l.Before {
			return nil, nil, decFailure("not_yet_valid")
		}
		if now >= l.After {
			return nil, nil, decFailure("authority_expired")
		}
		p = s
	}
	if p == nil {
		// Its exact ID is not derivable until the signed shared P is supplied.
		return nil, nil, decFailure("proof_required")
	}
	bans, e := migrationRequiredBans(&decMigrationSource{Network: staged.Source.Network, Catalog: mustDecBytes(staged.Record.SourceCatalog), Snapshot: staged.Prefix.Snapshot, Facts: staged.Prefix.Facts})
	if e != nil {
		return nil, nil, e
	}
	selected := []decMigrationBan{}
	for _, ban := range bans {
		if ban.Kind == "device_revoke" && ban.Target.Person == person {
			selected = append(selected, ban)
		}
	}
	sort.Slice(selected, func(a, b int) bool { return selected[a].Target.Device < selected[b].Target.Device })
	return p, selected, nil
}
func migrationDeviceBanReview(network string, staged *decMigrationLinkContext, p *dec.Statement, bans []decMigrationBan) DecMigrationDeviceBanReview {
	r := DecMigrationDeviceBanReview{Stage: "inherited_device_bans", Network: network, Proposal: staged.Prefix.Proposal.ID, Context: staged.Source.Descriptor.ContextID, Person: p.Lease.Subject.Person, Root: staged.Prefix.Root.ID, PersonLease: p.ID, SourceHash: staged.Prefix.Fields.SourceHash, StateHash: staged.Prefix.Fields.StateHash, Copies: []DecMigrationDeviceCopy{}, Maxima: append([]dec.LegacyMaximum{}, staged.Prefix.Snapshot.Maxima...), Warning: "Approve only these exact inherited irreversible device bans and every retained source access maximum. Their original-person signatures enter inert preparation only: no current provider, membership, ordinary restriction event, acknowledgment, fence or adoption is created."}
	for _, b := range bans {
		r.Copies = append(r.Copies, DecMigrationDeviceCopy{b.Target.Device, append([]string{}, b.Proofs...), "-"})
	}
	return r
}
func checkMigrationDeviceBanIntent(staged *decMigrationLinkContext, i decIntent, now string) (DecMigrationDeviceBanReview, []*dec.Statement, [][]byte, error) {
	var review DecMigrationDeviceBanReview
	bad := func() (DecMigrationDeviceBanReview, []*dec.Statement, [][]byte, error) {
		return review, nil, nil, decStorageError()
	}
	if staged.Prefix.Root == nil {
		return review, nil, nil, decFailure("proof_required", staged.Prefix.Proposal.ID)
	}
	r := i.Record
	if !migrationDeviceBanIntent(i) || !r.Approved || i.Network != staged.Source.Network.ID || i.Context != staged.Source.Descriptor.ContextID || r.Operation != staged.Prefix.Proposal.ID || r.Provider != (decIntentProvider{"original", r.Person, "sshsig", "-"}) || r.Root != staged.Prefix.Root.ID || r.Host != staged.Own.Host || r.Device != "-" || r.Scopes != 0 || r.NotAfter != "-" || r.Result != "-" || r.Terminal != "-" || i.Secret != nil || r.Created < staged.Prefix.Fields.Issued || r.Created >= r.Expires || r.ApprovedAt != r.Created || r.Expires != staged.Prefix.Fields.Expires {
		return bad()
	}
	if now < r.Created {
		return review, nil, nil, decFailure("clock_rollback")
	}
	p, bans, e := migrationDeviceBanContext(staged, r.Person, now)
	if e != nil {
		return review, nil, nil, e
	}
	if r.Created < p.Lease.Issued || r.Created < p.Lease.Before || r.Created >= p.Lease.After {
		return bad()
	}
	if len(bans) != len(r.Templates) || len(bans) == 0 {
		return bad()
	}
	statements, bodies, e := decIntentStatements(staged.Source.Descriptor, i)
	if e != nil {
		return review, nil, nil, e
	}
	want := migrationDeviceBanReview(i.Network, staged, p, bans)
	complete := true
	for n, s := range statements {
		v := s.Restriction
		if s.Kind != "device_revoke" || v == nil || v.Root != r.Root || v.Issuer != (dec.Issuer{Kind: "person", Person: r.Person}) || v.Issued != r.Created || v.Target != bans[n].Target || v.Ratifies != "-" || len(v.Kept) != 0 || !reflect.DeepEqual(v.Parents, []dec.Parent{{Role: "issuer_person", ID: p.ID}}) || len(s.Signatures) != 1 || s.Signatures[0].Role != "issuer" || s.Signatures[0].PublicKey != r.Person || s.Signatures[0].Format != "sshsig" {
			return bad()
		}
		want.Copies[n].Statement = s.ID
		complete = complete && decActionComplete(s)
	}
	if r.Completed != complete || dec.ReadPrivateRecord(mustDecBytes(r.Review), migrationDeviceBanReviewFields, &review) != nil || review.Warning == "" {
		return bad()
	}
	want.Warning = review.Warning
	if !reflect.DeepEqual(review, want) {
		return bad()
	}
	return review, statements, bodies, nil
}
func migrationDeviceBanBudget(staged *decMigrationLinkContext, statements []*dec.Statement, bodies [][]byte) error {
	objects := append([]dec.CatalogObject{}, staged.Prefix.Catalog.Objects...)
	seen := map[string]bool{}
	for _, object := range objects {
		seen[object.ID] = true
	}
	for n, s := range statements {
		body := bodies[n]
		if !decActionComplete(s) {
			key, e := membership.DecodeKey(s.Signer("issuer"))
			if e != nil {
				return e
			}
			size := base64.StdEncoding.EncodedLen(len(membership.SSHSIGBlob(key, make([]byte, ed25519.SignatureSize)))) - 1
			// Size-only opaque bytes; never parsed, stored, exported or admitted.
			body = make([]byte, len(body)+size)
		}
		id := dec.ProofID(s.Kind, body)
		if !seen[id] {
			objects = append(objects, dec.CatalogObject{ID: id, Kind: s.Kind, BodyBase64: base64.StdEncoding.EncodeToString(body)})
			seen[id] = true
		}
	}
	if len(objects) > dec.MaxObjects {
		return decFailure("quota_exceeded")
	}
	sort.Slice(objects, func(a, b int) bool { return objects[a].ID < objects[b].ID })
	raw, e := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, staged.Source.Descriptor.ContextID, objects})
	if e != nil {
		return e
	}
	// Future ACK references are not authority here. Reserve their exact encoding
	// lengths and the largest permitted final root signature before any copy is
	// signed; this prospective body is never verified, persisted or exported.
	placeholder := "ds_" + strings.Repeat("0", 64)
	acks, ids, extra := []json.RawMessage{}, []string{}, 0
	for _, row := range staged.Prefix.Fields.Roster {
		binding, device, activation := "-", "-", "-"
		roles := []dec.Signature{{Role: "host", PublicKey: row.Host, Format: "ed25519", Signature: "-"}}
		if row.Person != "-" {
			binding, device, activation = placeholder, placeholder, "da_"+strings.Repeat("0", 64)
			roles = append(roles, dec.Signature{Role: "device", PublicKey: row.Device, Format: "ed25519", Signature: "-"})
		}
		payload, _ := json.Marshal(map[string]any{"proposal_id": staged.Prefix.Proposal.ID, "root_state_id": staged.Prefix.Root.ID, "prepared_catalog_sha256": decMigrationHash(raw), "host_public_key": row.Host, "person_public_key": row.Person, "device_public_key": row.Device, "host_lease_id": placeholder, "binding_lease_id": binding, "device_lease_id": device, "activation_id": activation, "acknowledged_at": staged.Prefix.Fields.Issued})
		ack, e := dec.StatementTemplate(staged.Source.Descriptor, "migration_ack", payload, roles)
		if e != nil {
			return e
		}
		acks = append(acks, ack)
		statement, e := dec.ReadStatementTemplate(staged.Source.Descriptor, ack)
		if e != nil {
			return e
		}
		ids = append(ids, statement.ID)
		extra += len(roles) * (base64.StdEncoding.EncodedLen(ed25519.SignatureSize) - 1)
	}
	sort.Strings(ids)
	payload, _ := json.Marshal(decMigrationCommitPayload{staged.Prefix.Proposal.ID, staged.Prefix.Root.ID, decMigrationHash(raw), ids, staged.Prefix.Fields.Issued})
	commit, e := dec.StatementTemplate(staged.Source.Descriptor, "migration_commit", payload, []dec.Signature{{Role: "issuer", PublicKey: staged.Prefix.Fields.Root, Format: "sshsig", Signature: "-"}})
	if e != nil {
		return e
	}
	key, e := membership.DecodeKey(staged.Prefix.Fields.Root)
	if e != nil {
		return e
	}
	extra += base64.StdEncoding.EncodedLen(len(membership.SSHSIGBlob(key, make([]byte, ed25519.SignatureSize)))) - 1
	body, e := migrationCompositeBody(staged.Prefix.Proposal.Raw, staged.Record.SourceCatalog, staged.Record.SourceState, base64.StdEncoding.EncodeToString(raw), acks, commit)
	if e != nil {
		return e
	}
	if len(body)+extra > dec.MaxObject {
		return decFailure("quota_exceeded")
	}
	return nil
}
func (s *Store) PrepareDecentralizedMigrationDeviceBans(ctx context.Context, network string, input DecMigrationDeviceBans) (DecMigrationDeviceBanResult, error) {
	s.linkMu.Lock()
	s.syncing.Lock()
	result, facts, e := s.prepareMigrationDeviceBans(ctx, network, input)
	s.syncing.Unlock()
	s.linkMu.Unlock()
	if e == nil {
		e = facts.wait(ctx)
	}
	return result, e
}
func (s *Store) prepareMigrationDeviceBans(ctx context.Context, network string, input DecMigrationDeviceBans) (DecMigrationDeviceBanResult, decCommittedFacts, error) {
	result := DecMigrationDeviceBanResult{Signing: []DecSigningRequest{}}
	facts := decCommittedFacts{operation: input.Proposal}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, facts, e
	}
	defer tx.Rollback()
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return result, facts, e
	}
	staged, e := s.migrationPreparationContext(ctx, tx, network, input.Proposal, now)
	if e != nil {
		return result, facts, e
	}
	p, bans, e := migrationDeviceBanContext(staged, input.Person, now)
	if e != nil {
		return result, facts, e
	}
	result.Review = migrationDeviceBanReview(network, staged, p, bans)
	result.Migration, e = s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return result, facts, e
	}
	existing, e := migrationDeviceBanIntents(ctx, tx, network, input.Proposal, input.Person)
	if e != nil {
		return result, facts, e
	}
	if len(existing) > 0 {
		i := existing[0]
		review, statements, bodies, e := checkMigrationDeviceBanIntent(staged, i, now)
		if e != nil {
			return result, facts, e
		}
		result.Review = review
		if input.Approve {
			result.Signing = migrationSigning(i, statements, bodies)
		}
		return result, facts, nil
	}
	if !input.Approve || len(bans) == 0 {
		return result, facts, nil
	}
	if staged.Record.Fenced || staged.Record.Commit != "-" || staged.Record.AckIntent != "-" || len(staged.Record.Acknowledgments) > 0 {
		return result, facts, decFailure("migration_pending")
	}
	if e = decIntentCapacity(ctx, tx); e != nil {
		return result, facts, e
	}
	id, e := decRandomID("dint_")
	if e != nil {
		return result, facts, e
	}
	i := decIntent{ID: id, Network: network, Context: staged.Source.Descriptor.ContextID, Kind: "migration", Record: decIntentRecord{Format: 1, Operation: input.Proposal, Approved: true, ApprovedAt: now, Provider: decIntentProvider{"original", input.Person, "sshsig", "-"}, Root: staged.Prefix.Root.ID, Person: input.Person, Host: s.identity.PublicKey, Device: "-", Scopes: 0, NotAfter: "-", Created: now, Expires: staged.Prefix.Fields.Expires, Templates: []decIntentTemplate{}, Signatures: []decIntentSignature{}, Terminal: "-", Result: "-"}}
	for n, b := range bans {
		payload, e := json.Marshal(dec.Restriction{Root: i.Record.Root, Issuer: dec.Issuer{Kind: "person", Person: input.Person}, Parents: []dec.Parent{{Role: "issuer_person", ID: p.ID}}, Issued: now, Target: b.Target, Kept: []string{}, Ratifies: "-"})
		if e != nil {
			return result, facts, e
		}
		raw, e := dec.StatementTemplate(staged.Source.Descriptor, "device_revoke", payload, []dec.Signature{{Role: "issuer", PublicKey: input.Person, Format: "sshsig", Signature: "-"}})
		if e != nil {
			return result, facts, e
		}
		statement, e := dec.ReadStatementTemplate(staged.Source.Descriptor, raw)
		if e != nil {
			return result, facts, e
		}
		i.Record.Templates = append(i.Record.Templates, decIntentTemplate{uint64(n + 1), "device_revoke", base64.StdEncoding.EncodeToString(raw)})
		result.Review.Copies[n].Statement = statement.ID
	}
	reviewRaw, e := json.Marshal(result.Review)
	if e != nil {
		return result, facts, e
	}
	if len(reviewRaw) > dec.MaxObject {
		return result, facts, decFailure("quota_exceeded")
	}
	i.Record.Review = base64.StdEncoding.EncodeToString(reviewRaw)
	_, statements, bodies, e := checkMigrationDeviceBanIntent(staged, i, now)
	if e != nil {
		return result, facts, e
	}
	if e = migrationDeviceBanBudget(staged, statements, bodies); e != nil {
		return result, facts, e
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return result, facts, e
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return result, facts, e
	}
	if _, e = s.migrationPreparationContext(ctx, tx, network, input.Proposal, latest); e != nil {
		return result, facts, e
	}
	if _, _, e = migrationDeviceBanContext(staged, input.Person, latest); e != nil {
		return result, facts, e
	}
	if e = storeDecIntent(ctx, tx, i, true); e == nil {
		e = writeMigrationClock(ctx, tx, network, latest)
	}
	if e != nil {
		return result, facts, e
	}
	if e = tx.Commit(); e != nil {
		return result, facts, e
	}
	facts.add("dec.intent.after_commit")
	facts.add("dec.approval.after_commit")
	result.Signing = migrationSigning(i, statements, bodies)
	return result, facts, nil
}

func (s *Store) migrationDeviceBanResult(ctx context.Context, network, id string) (DecMigrationDeviceBanResult, error) {
	result := DecMigrationDeviceBanResult{Signing: []DecSigningRequest{}}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	i, e := readDecIntent(ctx, tx, id)
	if e != nil {
		return result, e
	}
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return result, e
	}
	staged, e := s.migrationPreparationContext(ctx, tx, network, i.Record.Operation, now)
	if e != nil {
		return result, e
	}
	review, statements, bodies, e := checkMigrationDeviceBanIntent(staged, i, now)
	if e != nil {
		return result, e
	}
	result.Migration, e = s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return result, e
	}
	result.Review = review
	result.Signing = migrationSigning(i, statements, bodies)
	return result, nil
}
func (s *Store) signedMigrationDeviceBans(ctx context.Context, network string, batch DecSignatureBatch) (DecMigrationDeviceBanResult, error) {
	if e := validateDecSignatureBatch(batch); e != nil {
		return DecMigrationDeviceBanResult{}, e
	}
	s.linkMu.Lock()
	s.syncing.Lock()
	facts, e := s.persistMigrationDeviceBanSignatures(ctx, network, batch)
	s.syncing.Unlock()
	s.linkMu.Unlock()
	if e == nil {
		e = facts.wait(ctx)
	}
	if e != nil {
		return DecMigrationDeviceBanResult{}, e
	}
	return s.migrationDeviceBanResult(ctx, network, batch.Intent)
}
func (s *Store) persistMigrationDeviceBanSignatures(ctx context.Context, network string, batch DecSignatureBatch) (decCommittedFacts, error) {
	facts := decCommittedFacts{}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return facts, e
	}
	defer tx.Rollback()
	i, e := readDecIntent(ctx, tx, batch.Intent)
	if e != nil {
		return facts, e
	}
	if i.Network != network || !migrationDeviceBanIntent(i) {
		return facts, decFailure("operation_conflict")
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
	_, statements, _, e := checkMigrationDeviceBanIntent(staged, i, now)
	if e != nil {
		return facts, e
	}
	before := len(i.Record.Signatures)
	for _, submitted := range batch.Signatures {
		if submitted.Slot == 0 || submitted.Slot > uint64(len(statements)) || submitted.Role != "issuer" {
			return facts, decFailure("invalid")
		}
		s := statements[submitted.Slot-1]
		if e = dec.VerifySignature(i.Record.Person, "sshsig", dec.SignatureMessage(s.ID, "issuer", i.Record.Person), submitted.Signature); e != nil {
			return facts, e
		}
		if e = addDecSignature(&i, submitted); e != nil {
			return facts, e
		}
	}
	if before == len(i.Record.Signatures) {
		return facts, nil
	}
	if staged.Record.Fenced || staged.Record.Commit != "-" || staged.Record.AckIntent != "-" || len(staged.Record.Acknowledgments) > 0 {
		return facts, decFailure("migration_pending")
	}
	statements, bodies, e := decIntentStatements(staged.Source.Descriptor, i)
	if e != nil {
		return facts, e
	}
	i.Record.Completed = true
	for _, statement := range statements {
		i.Record.Completed = i.Record.Completed && decActionComplete(statement)
	}
	if _, _, _, e = checkMigrationDeviceBanIntent(staged, i, now); e != nil {
		return facts, e
	}
	objects := []dec.CatalogObject{}
	for n, statement := range statements {
		if decActionComplete(statement) {
			objects = append(objects, dec.CatalogObject{ID: dec.ProofID(statement.Kind, bodies[n]), Kind: statement.Kind, BodyBase64: base64.StdEncoding.EncodeToString(bodies[n])})
		}
	}
	sort.Slice(objects, func(a, b int) bool { return objects[a].ID < objects[b].ID })
	candidateRaw, e := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, i.Context, objects})
	if e != nil {
		return facts, e
	}
	candidate, e := dec.ReadCatalog(staged.Source.Descriptor, candidateRaw)
	if e != nil {
		return facts, e
	}
	union, e := dec.UnionCatalog(staged.Source.Descriptor, staged.Prefix.Catalog, candidate)
	if e != nil {
		return facts, e
	}
	if e = migrationDeviceBanBudget(staged, statements, bodies); e != nil {
		return facts, e
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return facts, e
	}
	current, e := s.migrationPreparationContext(ctx, tx, network, i.Record.Operation, latest)
	if e != nil {
		return facts, e
	}
	if _, _, _, e = checkMigrationDeviceBanIntent(current, i, latest); e != nil {
		return facts, e
	}
	current.Record.PreparedCatalog = base64.StdEncoding.EncodeToString(union.Raw)
	if e = storeDecIntent(ctx, tx, i, false); e == nil {
		e = storeDecMigration(ctx, tx, network, i.Record.Operation, current.Record, false)
	}
	if e == nil {
		e = writeMigrationClock(ctx, tx, network, latest)
	}
	if e != nil {
		return facts, e
	}
	if e = tx.Commit(); e != nil {
		return facts, e
	}
	facts.add("dec.signature.after_commit")
	return facts, nil
}

// Response dispatch selects only the exact private migration intent family.
// There is no caller-controlled alternate verifier/provider or staged grant.
func (s *Store) signedMigrationResponse(ctx context.Context, network string, batch DecSignatureBatch) (any, error) {
	if !dec.ValidID(network, "net_") {
		return nil, decFailure("invalid")
	}
	i, e := readDecIntent(ctx, s.db, batch.Intent)
	if e != nil {
		return nil, e
	}
	if migrationDeviceBanIntent(i) {
		return s.signedMigrationDeviceBans(ctx, network, batch)
	}
	return s.SignedDecentralizedMigration(ctx, network, batch)
}
func (s *Store) resumeMigrationResponse(ctx context.Context, network string) (any, error) {
	ordinary, e := s.ResumeDecentralizedMigration(ctx, network)
	if e != nil {
		return nil, e
	}
	if len(ordinary.Signing) > 0 || ordinary.Migration.Fenced || ordinary.Migration.State == "adopted" || ordinary.Review.Stage == "acknowledgment" || ordinary.Review.Stage == "root_commit" || ordinary.Review.Stage == "adoption" {
		return ordinary, nil
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	copies, e := migrationDeviceBanIntents(ctx, tx, network, ordinary.Migration.Proposal, "-")
	tx.Rollback()
	if e != nil {
		return nil, e
	}
	for _, i := range copies {
		if i.Record.Approved && !i.Record.Completed {
			return s.migrationDeviceBanResult(ctx, network, i.ID)
		}
	}
	if len(copies) > 0 {
		return s.migrationDeviceBanResult(ctx, network, copies[0].ID)
	}
	return ordinary, nil
}
