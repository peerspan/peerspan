package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecMigrationPreparation struct {
	Roster  []DecMigrationRoster `json:"roster"`
	Format  string               `json:"signature_format"`
	Approve bool                 `json:"approve"`
}
type DecMigrationResult struct {
	Migration DecMigrationView    `json:"migration"`
	Review    DecMigrationReview  `json:"review"`
	Signing   []DecSigningRequest `json:"signing_requests"`
}
type decMigrationProposal struct {
	Nonce      string               `json:"proposal_nonce"`
	Legacy     string               `json:"legacy_descriptor_base64"`
	Feature    string               `json:"legacy_feature_id"`
	Epoch      uint64               `json:"legacy_epoch"`
	Root       string               `json:"legacy_root_public_key"`
	SourceHash string               `json:"source_catalog_sha256"`
	StateHash  string               `json:"source_state_sha256"`
	Descriptor json.RawMessage      `json:"new_descriptor"`
	Roster     []DecMigrationRoster `json:"roster"`
	Issued     string               `json:"issued_at"`
	Expires    string               `json:"expires_at"`
}

func migrationRecord(ctx context.Context, q dbQuerier, network string) (string, decMigrationRecord, error) {
	rows, e := q.QueryContext(ctx, `SELECT proposal_id,record FROM dec_migrations WHERE network_id=? ORDER BY proposal_id`, network)
	if e != nil {
		return "", decMigrationRecord{}, e
	}
	defer rows.Close()
	var id, raw string
	count := 0
	for rows.Next() {
		if e = rows.Scan(&id, &raw); e != nil {
			return "", decMigrationRecord{}, e
		}
		count++
		if count > 1 {
			return "", decMigrationRecord{}, decFailure("state_conflict")
		}
	}
	if e = rows.Err(); e != nil {
		return "", decMigrationRecord{}, e
	}
	if count == 0 {
		return "", decMigrationRecord{}, ErrNotFound
	}
	var r decMigrationRecord
	if e = dec.ReadPrivateRecord([]byte(raw), decMigrationFields, &r); e != nil {
		return "", r, e
	}
	if r.Format != 1 || !dec.ValidID(id, "ds_") || !dec.ValidID(r.Context, "ctx_") || r.Acknowledgments == nil || r.RootIntents == nil {
		return "", r, decStorageError()
	}
	switch r.State {
	case "needs_approvals", "prepared", "acknowledged", "adopted", "conflict":
	default:
		return "", r, decStorageError()
	}
	if len(r.Acknowledgments) > 4096 || len(r.RootIntents) > 4096 {
		return "", r, decStorageError()
	}
	return id, r, nil
}
func storeDecMigration(ctx context.Context, tx *sql.Tx, network, id string, r decMigrationRecord, insert bool) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(raw) > dec.MaxPrivateRecord {
		return decFailure("quota_exceeded")
	}
	if insert {
		_, e = tx.ExecContext(ctx, `INSERT INTO dec_migrations(network_id,proposal_id,record) VALUES(?,?,?)`, network, id, string(raw))
	} else {
		_, e = tx.ExecContext(ctx, `UPDATE dec_migrations SET record=? WHERE network_id=? AND proposal_id=?`, string(raw), network, id)
	}
	return e
}
func migrationRootSeed(ctx context.Context, q dbQuerier, network, key string) (ed25519.PrivateKey, error) {
	var seed []byte
	if e := q.QueryRowContext(ctx, `SELECT root_seed FROM networks WHERE id=?`, network).Scan(&seed); e != nil {
		return nil, e
	}
	if seed == nil {
		return nil, nil
	}
	if len(seed) != ed25519.SeedSize {
		return nil, decStorageError()
	}
	owned := ed25519.NewKeyFromSeed(seed)
	if membership.EncodeKey(owned.Public().(ed25519.PublicKey)) != key {
		return nil, nil
	}
	return owned, nil
}
func (s *Store) checkMigrationRoster(ctx context.Context, q dbQuerier, source *decMigrationSource, roster []DecMigrationRoster) error {
	if roster == nil || len(roster) != len(source.Facts.Members) || len(roster) > dec.MaxObjects {
		return decFailure("invalid")
	}
	members := map[string]DecMigrationRoster{}
	for _, m := range source.Facts.Members {
		members[m.HostPublicKey] = DecMigrationRoster{Host: m.HostPublicKey, Member: m.Member, Person: m.PersonPublicKey}
	}
	for n, row := range roster {
		old, ok := members[row.Host]
		if !ok || n > 0 && roster[n-1].Host >= row.Host || old.Member != row.Member || old.Person != row.Person {
			return decFailure("operation_conflict")
		}
		if row.Person == "-" {
			if row.Device != "-" || row.Scopes != 0 {
				return decFailure("invalid")
			}
		} else if !dec.ValidPublicKey(row.Device) || row.Scopes == 0 || row.Scopes > 15 {
			return decFailure("invalid")
		}
	}
	return s.checkMigrationOwnRoster(ctx, q, source, roster)
}

// A participant may know fewer historical members than the independently
// verified proposed source. Its caller first verifies that complete source and
// coverage of every local fact; this check supplies only its OWN private consent.
func (s *Store) checkMigrationOwnRoster(ctx context.Context, q dbQuerier, source *decMigrationSource, roster []DecMigrationRoster) error {
	// Only this machine can approve its private selection. The other known
	// hosts independently check their contributions before staged consent/ACK.
	identity, e := s.migrationIdentityIntent(ctx, q, source.Network.ID)
	if e != nil {
		return e
	}
	if identity == nil {
		return decFailure("review_required")
	}
	review, e := readDecMigrationIdentityIntent(*identity)
	if e != nil {
		return e
	}
	for _, row := range roster {
		if row.Host == s.identity.PublicKey {
			actual, e := s.migrationOwnIdentity(ctx, q, source, row.Scopes)
			if e != nil {
				return e
			}
			if actual.Device == "-" && actual.Person != "-" {
				actual.Device = review.Roster[0].Device
				if identity.Secret == nil {
					return decFailure("signer_unavailable")
				}
			}
			if row != review.Roster[0] || row != actual {
				return decFailure("operation_conflict")
			}
			return nil
		}
	}
	return decFailure("forbidden")
}

// The root prepares only its exact proposal, inert initial root, shared person
// admissions, unbound host memberships and source-derived stable root bans.
// Original-person device-ban copies require their separate reviewed writer.
func migrationProposalTemplates(d dec.Descriptor, p decMigrationProposal, format string, people map[string]string, bans []decMigrationBan, pinned ...string) ([]decIntentTemplate, *dec.Statement, error) {
	templates := []decIntentTemplate{}
	appendTemplate := func(kind string, payload any, extra ...dec.Signature) (*dec.Statement, error) {
		body, e := json.Marshal(payload)
		if e != nil {
			return nil, e
		}
		signatures := append([]dec.Signature{{Role: "issuer", PublicKey: p.Root, Format: format, Signature: "-"}}, extra...)
		sort.Slice(signatures, func(a, b int) bool { return signatures[a].Role < signatures[b].Role })
		raw, e := dec.StatementTemplate(d, kind, body, signatures)
		if e != nil {
			return nil, e
		}
		statement, e := dec.ReadStatementTemplate(d, raw)
		if e != nil {
			return nil, e
		}
		templates = append(templates, decIntentTemplate{uint64(len(templates) + 1), kind, base64.StdEncoding.EncodeToString(raw)})
		return statement, nil
	}
	proposal, e := appendTemplate("migration_proposal", p)
	if e != nil {
		return nil, nil, e
	}
	proposalID := proposal.ID
	if len(pinned) > 0 {
		proposalID = pinned[0]
	}
	r, e := appendTemplate("root_state", dec.RootState{Epoch: p.Epoch, Predecessors: []string{}, Resolves: []string{}, Migration: proposalID, Key: p.Root, Issued: p.Issued, Retained: []string{}})
	if e != nil {
		return nil, nil, e
	}
	rootID := r.ID
	if len(pinned) > 1 {
		rootID = pinned[1]
	}
	if len(people)+2 > 4096 {
		return nil, nil, decFailure("quota_exceeded")
	}
	keys := []string{}
	for person := range people {
		keys = append(keys, person)
	}
	sort.Strings(keys)
	issued, e := dec.ParseTime(p.Issued)
	if e != nil {
		return nil, nil, e
	}
	for _, person := range keys {
		_, e = appendTemplate("person_lease", dec.Lease{Root: rootID, Operation: "-", Sequence: 1, Predecessors: []string{}, Resolves: []string{}, Retained: []string{}, Subject: dec.Subject{Person: person, Host: "-", Device: "-", Member: people[person], Scopes: 0}, Issuer: dec.Issuer{Kind: "root", Person: "-"}, Parents: []dec.Parent{}, Issued: p.Issued, Before: p.Issued, After: linkTime(issued.Add(7 * 24 * time.Hour))})
		if e != nil {
			return nil, nil, e
		}
	}
	for _, row := range p.Roster {
		if row.Person != "-" {
			continue
		}
		if len(templates) == 4096 {
			return nil, nil, decFailure("quota_exceeded")
		}
		_, e = appendTemplate("host_lease", dec.Lease{Root: rootID, Operation: proposalID, Sequence: 1, Predecessors: []string{}, Resolves: []string{}, Retained: []string{}, Subject: dec.Subject{Person: "-", Host: row.Host, Device: "-", Member: row.Member, Scopes: 0}, Issuer: dec.Issuer{Kind: "root", Person: "-"}, Parents: []dec.Parent{}, Issued: p.Issued, Before: p.Issued, After: linkTime(issued.Add(7 * 24 * time.Hour))}, dec.Signature{Role: "host", PublicKey: row.Host, Format: "ed25519", Signature: "-"})
		if e != nil {
			return nil, nil, e
		}
	}
	for _, ban := range bans {
		if ban.Kind == "device_revoke" {
			continue
		}
		if ban.Kind != "person_remove" && ban.Kind != "host_revoke" {
			return nil, nil, decStorageError()
		}
		if len(templates) == 4096 {
			return nil, nil, decFailure("quota_exceeded")
		}
		_, e = appendTemplate(ban.Kind, dec.Restriction{Root: rootID, Issuer: dec.Issuer{Kind: "root", Person: "-"}, Parents: []dec.Parent{}, Issued: p.Issued, Target: ban.Target, Kept: []string{}, Ratifies: "-"})
		if e != nil {
			return nil, nil, e
		}
	}
	return templates, proposal, nil
}

func migrationPeople(source *decMigrationSource) map[string]string {
	people := map[string]string{}
	for person, state := range source.Facts.Facts.State.Persons {
		if state.Admitted {
			people[person] = source.Facts.Facts.PersonLabels[person]
		}
	}
	return people
}

func newMigrationProposal(source *decMigrationSource, roster []DecMigrationRoster, format string, approve bool) (decIntent, decMigrationRecord, error) {
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return decIntent{}, decMigrationRecord{}, e
	}
	issued, e := dec.ParseTime(source.Time)
	if e != nil {
		return decIntent{}, decMigrationRecord{}, e
	}
	p := decMigrationProposal{base64.StdEncoding.EncodeToString(nonce[:]), base64.StdEncoding.EncodeToString(source.Legacy), source.Feature, source.Facts.Epoch, source.Facts.RootPublicKey, decMigrationHash(source.Catalog), decMigrationHash(source.State), json.RawMessage(source.Descriptor.Raw), roster, source.Time, linkTime(issued.Add(24 * time.Hour))}
	bans, e := migrationRequiredBans(source)
	if e != nil {
		return decIntent{}, decMigrationRecord{}, e
	}
	templates, proposal, e := migrationProposalTemplates(source.Descriptor, p, format, migrationPeople(source), bans)
	if e != nil {
		return decIntent{}, decMigrationRecord{}, e
	}
	root, e := dec.ReadStatementTemplate(source.Descriptor, mustDecBytes(templates[1].Template))
	if e != nil {
		return decIntent{}, decMigrationRecord{}, e
	}
	id, e := decRandomID("dint_")
	if e != nil {
		return decIntent{}, decMigrationRecord{}, e
	}
	review := DecMigrationReview{Stage: "proposal", Network: source.Network.ID, Proposal: proposal.ID, LegacyRoot: p.Root, Epoch: p.Epoch, Context: source.Descriptor.ContextID, Roster: roster, SourceHash: p.SourceHash, StateHash: p.StateHash, PreparedHash: "-", Warning: "Migration requires every known host and each original person to approve the exact finite authority using their existing keys. It preserves all required source person/host bans; inherited device bans require their original person's separate signature. Parent leases expire within seven days. A later host acknowledgment creates a durable fence with no timeout abort; this proposal does not acknowledge or adopt the network."}
	reviewRaw, e := json.Marshal(review)
	if e != nil {
		return decIntent{}, decMigrationRecord{}, e
	}
	approvedAt := "-"
	if approve {
		approvedAt = source.Time
	}
	i := decIntent{ID: id, Network: source.Network.ID, Context: source.Descriptor.ContextID, Kind: "migration", Record: decIntentRecord{Format: 1, Operation: proposal.ID, Approved: approve, ApprovedAt: approvedAt, Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: decIntentProvider{Kind: "root", Signer: p.Root, Format: format, Lease: "-"}, Root: root.ID, Person: "-", Host: "-", Device: "-", Scopes: 8, NotAfter: "-", Created: p.Issued, Expires: p.Expires, Templates: templates, Signatures: []decIntentSignature{}, Completed: false, Terminal: "-", Result: "-"}}
	r := decMigrationRecord{Format: 1, Context: i.Context, State: "needs_approvals", Proposal: "-", SourceCatalog: base64.StdEncoding.EncodeToString(source.Catalog), SourceState: base64.StdEncoding.EncodeToString(source.State), PreparedCatalog: "-", InitialRoot: "-", Acknowledgments: []string{}, Commit: "-", Migration: "-", LocalAck: "-", RootIntents: []string{id}, AckIntent: "-"}
	return i, r, nil
}

func checkMigrationProposalIntent(d dec.Descriptor, i decIntent, r decMigrationRecord) (DecMigrationReview, decMigrationProposal, []*dec.Statement, [][]byte, error) {
	var review DecMigrationReview
	var p decMigrationProposal
	bad := func() (DecMigrationReview, decMigrationProposal, []*dec.Statement, [][]byte, error) {
		return review, p, nil, nil, decStorageError()
	}
	if i.Kind != "migration" || i.Context != d.ContextID || i.Network != d.NetworkID || i.Record.Provider.Kind != "root" || i.Record.Provider.Lease != "-" || i.Record.Person != "-" || i.Record.Host != "-" || i.Record.Device != "-" || i.Record.Scopes != 8 || i.Record.NotAfter != "-" || i.Secret != nil || i.Record.Terminal != "-" || i.Record.Result != "-" || len(i.Record.Templates) < 2 {
		return bad()
	}
	statements, bodies, e := decIntentStatements(d, i)
	if e != nil {
		return review, p, nil, nil, e
	}
	if statements[0].Kind != "migration_proposal" || statements[0].ID != i.Record.Operation || dec.ReadPrivateRecord(statements[0].Payload, "proposal_nonce legacy_descriptor_base64 legacy_feature_id legacy_epoch legacy_root_public_key source_catalog_sha256 source_state_sha256 new_descriptor roster issued_at expires_at", &p) != nil {
		return bad()
	}
	if i.Record.Created != p.Issued || i.Record.Expires != p.Expires || i.Record.Provider.Signer != p.Root || i.Record.Root != statements[1].ID {
		return bad()
	}
	source, e := decBytes(r.SourceCatalog, 512<<10)
	if e != nil {
		return review, p, nil, nil, e
	}
	state, e := decBytes(r.SourceState, dec.MaxPayload)
	if e != nil {
		return review, p, nil, nil, e
	}
	if r.Context != d.ContextID || decMigrationHash(source) != p.SourceHash || decMigrationHash(state) != p.StateHash {
		return bad()
	}
	verified, facts, e := dec.VerifyMigrationSourceSnapshot(d, mustDecBytes(p.Legacy), source, state, p.Epoch, p.Feature, p.Root, p.Issued)
	if e != nil {
		return review, p, nil, nil, e
	}
	people := migrationPeople(&decMigrationSource{Facts: facts})
	bans, e := migrationRequiredBans(&decMigrationSource{Network: Network{ID: d.NetworkID}, Catalog: source, Snapshot: verified, Facts: facts})
	if e != nil {
		return review, p, nil, nil, e
	}
	expected, _, e := migrationProposalTemplates(d, p, i.Record.Provider.Format, people, bans, statements[0].ID, statements[1].ID)
	if e != nil {
		return review, p, nil, nil, e
	}
	if len(expected) != len(statements) {
		return bad()
	}
	complete := true
	for n, statement := range statements {
		want, e := dec.ReadStatementTemplate(d, mustDecBytes(expected[n].Template))
		if e != nil {
			return review, p, nil, nil, e
		}
		// Typed payload equality permits foreign JSON field ordering; each
		// original template remains byte-exact for its own signatures/IDs.
		var a, b any
		actualDecoder := json.NewDecoder(bytes.NewReader(statement.Payload))
		actualDecoder.UseNumber()
		expectedDecoder := json.NewDecoder(bytes.NewReader(want.Payload))
		expectedDecoder.UseNumber()
		if actualDecoder.Decode(&a) != nil || expectedDecoder.Decode(&b) != nil || !reflect.DeepEqual(a, b) || statement.Kind != want.Kind || len(statement.Signatures) != len(want.Signatures) {
			return bad()
		}
		for index, sig := range statement.Signatures {
			role := want.Signatures[index]
			if sig.Role != role.Role || sig.PublicKey != role.PublicKey || sig.Format != role.Format {
				return bad()
			}
		}
		complete = complete && decActionComplete(statement)
	}
	if complete != i.Record.Completed {
		return bad()
	}
	for n, encoded := range []string{r.Proposal, r.InitialRoot} {
		if encoded != "-" && (!decActionComplete(statements[n]) || !bytes.Equal(mustDecBytes(encoded), bodies[n])) {
			return bad()
		}
	}
	raw, e := decBytes(i.Record.Review, 1<<20)
	if e != nil {
		return review, p, nil, nil, e
	}
	if dec.ReadPrivateRecord(raw, decMigrationReviewFields, &review) != nil || review.Stage != "proposal" || review.Network != i.Network || review.Proposal != statements[0].ID || review.Context != d.ContextID || review.LegacyRoot != p.Root || review.Epoch != p.Epoch || review.SourceHash != p.SourceHash || review.StateHash != p.StateHash || review.PreparedHash != "-" || !reflect.DeepEqual(review.Roster, p.Roster) || review.Warning == "" {
		return bad()
	}
	return review, p, statements, bodies, nil
}

func migrationProposalCatalog(d dec.Descriptor, statements []*dec.Statement, bodies [][]byte) ([]byte, error) {
	objects := []dec.CatalogObject{}
	for n, statement := range statements {
		if !decActionComplete(statement) {
			continue
		}
		objects = append(objects, dec.CatalogObject{ID: dec.ProofID(statement.Kind, bodies[n]), Kind: statement.Kind, BodyBase64: base64.StdEncoding.EncodeToString(bodies[n])})
	}
	sort.Slice(objects, func(a, b int) bool { return objects[a].ID < objects[b].ID })
	raw, e := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, objects})
	if e != nil {
		return nil, e
	}
	if _, e = dec.ReadCatalog(d, raw); e != nil {
		return nil, e
	}
	return raw, nil
}

// Even the initial partial preparation must not commit a known impossible
// origin. Final complete-catalog/ACK checks apply the same bound again.
func migrationPreparationBudget(r decMigrationRecord, proposal, prepared []byte) error {
	acks := []json.RawMessage{}
	for _, encoded := range r.Acknowledgments {
		acks = append(acks, mustDecBytes(encoded))
	}
	commit := json.RawMessage(`"-"`)
	if r.Commit != "-" {
		commit = mustDecBytes(r.Commit)
	}
	_, e := migrationCompositeBody(proposal, r.SourceCatalog, r.SourceState, base64.StdEncoding.EncodeToString(prepared), acks, commit)
	return e
}

func (s *Store) checkCurrentMigrationProposal(ctx context.Context, q dbQuerier, source *decMigrationSource, i decIntent, r decMigrationRecord) (DecMigrationReview, []*dec.Statement, [][]byte, error) {
	review, p, statements, bodies, e := checkMigrationProposalIntent(source.Descriptor, i, r)
	if e != nil {
		return review, nil, nil, e
	}
	compatible, e := migrationLocalSourceEqual(source, p, r)
	if e != nil {
		return review, nil, nil, e
	}
	if source.Facts.RootPublicKey != p.Root || source.Facts.Epoch != p.Epoch || source.Feature != p.Feature || !compatible {
		return review, nil, nil, decFailure("state_conflict")
	}
	if source.Time < p.Issued {
		return review, nil, nil, decFailure("clock_rollback")
	}
	if source.Time >= p.Expires {
		return review, nil, nil, decFailure("expired")
	}
	if e = s.checkMigrationRoster(ctx, q, source, p.Roster); e != nil {
		return review, nil, nil, e
	}
	return review, statements, bodies, nil
}

func migrationSigning(i decIntent, statements []*dec.Statement, bodies [][]byte) []DecSigningRequest {
	requests := []DecSigningRequest{}
	if !i.Record.Approved {
		return requests
	}
	for n, statement := range statements {
		for _, sig := range statement.Signatures {
			if sig.Signature != "-" {
				continue
			}
			if sig.Role == "host" && decSlotSignature(i, uint64(n+1), "issuer") == "-" {
				continue
			}
			requests = append(requests, DecSigningRequest{i.ID, uint64(n + 1), statement.Kind, statement.ID, sig.Role, sig.PublicKey, sig.Format, base64.StdEncoding.EncodeToString(bodies[n]), base64.StdEncoding.EncodeToString(dec.SignatureMessage(statement.ID, sig.Role, sig.PublicKey))})
			if len(requests) == 16 {
				return requests
			}
		}
	}
	return requests
}

func writeMigrationClock(ctx context.Context, tx *sql.Tx, network, now string) error {
	raw, _ := json.Marshal(decClockRecord{1, now})
	_, e := tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, network, string(raw))
	return e
}

func (s *Store) prepareMigrationProposal(ctx context.Context, network string, input DecMigrationPreparation) (i decIntent, facts decCommittedFacts, err error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return i, facts, e
	}
	defer tx.Rollback()
	source, e := s.decMigrationSource(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	if e = s.checkMigrationRoster(ctx, tx, source, input.Roster); e != nil {
		return i, facts, e
	}
	format := input.Format
	if format == "auto" || format == "ed25519" {
		key, e := migrationRootSeed(ctx, tx, network, source.Facts.RootPublicKey)
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
	_, r, e := migrationRecord(ctx, tx, network)
	fresh := errors.Is(e, ErrNotFound)
	if e != nil && !fresh {
		return i, facts, e
	}
	wasApproved := false
	if fresh {
		if e = decIntentCapacity(ctx, tx); e != nil {
			return i, facts, e
		}
		i, r, e = newMigrationProposal(source, input.Roster, format, input.Approve)
		if e != nil {
			return i, facts, e
		}
	} else {
		if r.Fenced || r.State == "adopted" || len(r.RootIntents) != 1 {
			return i, facts, decFailure("operation_conflict")
		}
		i, e = readDecIntent(ctx, tx, r.RootIntents[0])
		if e != nil {
			return i, facts, e
		}
		_, p, _, _, e := checkMigrationProposalIntent(source.Descriptor, i, r)
		if e != nil {
			return i, facts, e
		}
		if !reflect.DeepEqual(p.Roster, input.Roster) || i.Record.Provider.Format != format {
			return i, facts, decFailure("operation_conflict")
		}
		wasApproved = i.Record.Approved
		if input.Approve && !wasApproved {
			i.Record.Approved = true
			i.Record.ApprovedAt = source.Time
		}
	}
	_, statements, bodies, e := s.checkCurrentMigrationProposal(ctx, tx, source, i, r)
	if e != nil {
		return i, facts, e
	}
	// A size-only unsigned carrier is conservative for all currently known
	// source/templates; it asserts no signatures or complete origin authority.
	budgetObjects := []dec.CatalogObject{}
	for n, statement := range statements {
		budgetObjects = append(budgetObjects, dec.CatalogObject{ID: dec.ProofID(statement.Kind, bodies[n]), Kind: statement.Kind, BodyBase64: base64.StdEncoding.EncodeToString(bodies[n])})
	}
	budget, _ := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, i.Context, budgetObjects})
	if e = migrationPreparationBudget(r, bodies[0], budget); e != nil {
		return i, facts, e
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return i, facts, e
	}
	if latest >= i.Record.Expires {
		return i, facts, decFailure("expired")
	}
	if _, e = dec.DecisionTime(latest, source.Time); e != nil {
		return i, facts, e
	}
	if e = storeDecIntent(ctx, tx, i, fresh); e != nil {
		return i, facts, e
	}
	if fresh {
		if e = storeDecMigration(ctx, tx, network, i.Record.Operation, r, true); e != nil {
			return i, facts, e
		}
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return i, facts, e
	}
	if e = tx.Commit(); e != nil {
		return i, facts, e
	}
	facts.operation = i.Record.Operation
	if fresh {
		facts.add("dec.intent.after_commit")
		facts.add("dec.migration_proposal.after_commit")
	}
	if i.Record.Approved && !wasApproved {
		facts.add("dec.approval.after_commit")
	}
	return i, facts, nil
}

func (s *Store) PrepareDecentralizedMigration(ctx context.Context, network string, input DecMigrationPreparation) (DecMigrationResult, error) {
	if !dec.ValidID(network, "net_") {
		return DecMigrationResult{}, decFailure("invalid")
	}
	i, facts, e := s.prepareMigrationProposal(ctx, network, input)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if e = facts.wait(ctx); e != nil {
		return DecMigrationResult{}, e
	}
	if i.Record.Approved {
		return s.advanceMigrationProposal(ctx, network, i.ID, nil)
	}
	return s.migrationProposalResult(ctx, network, i.ID)
}

func (s *Store) migrationProposalResult(ctx context.Context, network, id string) (DecMigrationResult, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationResult{}, e
	}
	defer tx.Rollback()
	_, r, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	i, e := readDecIntent(ctx, tx, id)
	if e != nil {
		return DecMigrationResult{}, e
	}
	// The descriptor is fixed in the signed/unsigned proposal, never guessed
	// from another active network or from a helper response.
	if len(i.Record.Templates) == 0 {
		return DecMigrationResult{}, decStorageError()
	}
	var carrier struct {
		Payload string `json:"payload_base64"`
	}
	if json.Unmarshal(mustDecBytes(i.Record.Templates[0].Template), &carrier) != nil {
		return DecMigrationResult{}, decStorageError()
	}
	var p decMigrationProposal
	if json.Unmarshal(mustDecBytes(carrier.Payload), &p) != nil {
		return DecMigrationResult{}, decStorageError()
	}
	d, e := dec.ReadDescriptor(p.Descriptor)
	if e != nil {
		return DecMigrationResult{}, e
	}
	review, _, statements, bodies, e := checkMigrationProposalIntent(d, i, r)
	if e != nil {
		return DecMigrationResult{}, e
	}
	view, e := s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	return DecMigrationResult{view, review, migrationSigning(i, statements, bodies)}, nil
}

func (s *Store) advanceMigrationProposal(ctx context.Context, network, id string, batch *DecSignatureBatch) (DecMigrationResult, error) {
	facts, e := s.persistMigrationProposalSignatures(ctx, network, id, batch)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if e = facts.wait(ctx); e != nil {
		return DecMigrationResult{}, e
	}
	return s.migrationProposalResult(ctx, network, id)
}
func (s *Store) persistMigrationProposalSignatures(ctx context.Context, network, id string, batch *DecSignatureBatch) (facts decCommittedFacts, err error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return facts, e
	}
	defer tx.Rollback()
	source, e := s.decMigrationSource(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	proposalID, r, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	if len(r.RootIntents) != 1 || r.RootIntents[0] != id || r.Fenced {
		return facts, decFailure("operation_conflict")
	}
	i, e := readDecIntent(ctx, tx, id)
	if e != nil {
		return facts, e
	}
	_, statements, _, e := s.checkCurrentMigrationProposal(ctx, tx, source, i, r)
	if e != nil {
		return facts, e
	}
	if !i.Record.Approved {
		return facts, decFailure("review_required")
	}
	before := len(i.Record.Signatures)
	if batch != nil {
		if batch.Intent != id {
			return facts, decFailure("operation_conflict")
		}
		if e = validateDecSignatureBatch(*batch); e != nil {
			return facts, e
		}
		for _, sig := range batch.Signatures {
			if sig.Slot > uint64(len(statements)) || sig.Role != "issuer" && sig.Role != "host" {
				return facts, decFailure("invalid")
			}
			statement := statements[sig.Slot-1]
			var role dec.Signature
			for _, declared := range statement.Signatures {
				if declared.Role == sig.Role {
					role = declared
				}
			}
			if role.Role == "" || role.Role == "host" && decSlotSignature(i, sig.Slot, "issuer") == "-" {
				return facts, decFailure("invalid")
			}
			if e = dec.VerifySignature(role.PublicKey, role.Format, dec.SignatureMessage(statement.ID, role.Role, role.PublicKey), sig.Signature); e != nil {
				return facts, e
			}
			if e = addDecSignature(&i, sig); e != nil {
				return facts, e
			}
		}
	}
	if i.Record.Provider.Format == "ed25519" {
		key, e := migrationRootSeed(ctx, tx, network, i.Record.Provider.Signer)
		if e != nil {
			return facts, e
		}
		if key == nil {
			return facts, decFailure("signer_unavailable")
		}
		for n, statement := range statements {
			if decSlotSignature(i, uint64(n+1), "issuer") != "-" {
				continue
			}
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, dec.SignatureMessage(statement.ID, "issuer", i.Record.Provider.Signer)))
			if e = addDecSignature(&i, decIntentSignature{uint64(n + 1), "issuer", sig}); e != nil {
				return facts, e
			}
		}
	}
	// A target may return its complete exact H through the public-file evidence
	// path. Copy only the missing host signature over our fixed payload/issuer;
	// never replace a template or accept a merely matching semantic alias.
	if r.PreparedCatalog != "-" {
		catalog, e := dec.ReadCatalog(source.Descriptor, mustDecBytes(r.PreparedCatalog))
		if e != nil {
			return facts, e
		}
		for n, statement := range statements {
			if statement.Kind != "host_lease" || decSlotSignature(i, uint64(n+1), "host") != "-" {
				continue
			}
			for _, object := range catalog.Objects {
				other := catalog.Proofs[object.ID]
				if other == nil || other.ID != statement.ID {
					continue
				}
				for _, role := range other.Signatures {
					if role.Role != "host" {
						continue
					}
					candidate := i
					candidate.Record.Signatures = append([]decIntentSignature{}, i.Record.Signatures...)
					if e = addDecSignature(&candidate, decIntentSignature{uint64(n + 1), "host", role.Signature}); e != nil {
						return facts, e
					}
					_, body, e := decFilledTemplate(source.Descriptor, candidate, candidate.Record.Templates[n])
					if e != nil {
						return facts, e
					}
					if bytes.Equal(body, object.Body) {
						i = candidate
					}
				}
			}
		}
	}
	statements, bodies, e := decIntentStatements(source.Descriptor, i)
	if e != nil {
		return facts, e
	}
	i.Record.Completed = true
	for _, statement := range statements {
		i.Record.Completed = i.Record.Completed && decActionComplete(statement)
	}
	if decActionComplete(statements[0]) {
		r.Proposal = base64.StdEncoding.EncodeToString(bodies[0])
	}
	if decActionComplete(statements[1]) {
		r.InitialRoot = base64.StdEncoding.EncodeToString(bodies[1])
	}
	prepared, e := migrationProposalCatalog(source.Descriptor, statements, bodies)
	if e != nil {
		return facts, e
	}
	if e = migrationPreparationBudget(r, bodies[0], prepared); e != nil {
		return facts, e
	}
	if e = mergeMigrationPrepared(source.Descriptor, &r, DecMigrationEvidence{Catalog: prepared, Acknowledgments: []json.RawMessage{}, Commit: json.RawMessage(`"-"`)}); e != nil {
		return facts, e
	}
	if e = migrationPreparationBudget(r, bodies[0], mustDecBytes(r.PreparedCatalog)); e != nil {
		return facts, e
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return facts, e
	}
	if latest >= i.Record.Expires {
		return facts, decFailure("expired")
	}
	if _, e = dec.DecisionTime(latest, source.Time); e != nil {
		return facts, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return facts, e
	}
	if e = storeDecMigration(ctx, tx, network, proposalID, r, false); e != nil {
		return facts, e
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return facts, e
	}
	if e = tx.Commit(); e != nil {
		return facts, e
	}
	facts.operation = proposalID
	if len(i.Record.Signatures) > before {
		facts.add("dec.signature.after_commit")
	}
	return facts, nil
}

func (s *Store) SignedDecentralizedMigration(ctx context.Context, network string, batch DecSignatureBatch) (DecMigrationResult, error) {
	if !dec.ValidID(network, "net_") {
		return DecMigrationResult{}, decFailure("invalid")
	}
	if e := validateDecSignatureBatch(batch); e != nil {
		return DecMigrationResult{}, e
	}
	i, e := readDecIntent(ctx, s.db, batch.Intent)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if i.Network != network || i.Kind != "migration" {
		return DecMigrationResult{}, decFailure("operation_conflict")
	}
	if i.Record.Provider.Kind == "host" || len(i.Record.Templates) == 1 && i.Record.Templates[0].Type == "migration_ack" {
		return DecMigrationResult{}, decFailure("invalid")
	}
	if len(i.Record.Templates) == 1 && i.Record.Templates[0].Type == "migration_commit" {
		return s.advanceMigrationCommit(ctx, network, batch.Intent, &batch)
	}
	return s.advanceMigrationProposal(ctx, network, batch.Intent, &batch)
}
