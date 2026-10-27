package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/linking"
)

type DecMigrationEvidence struct {
	Proposal        json.RawMessage
	Source          string
	State           string
	Catalog         json.RawMessage
	Acknowledgments []json.RawMessage
	Commit          json.RawMessage
}
type DecMigrationApproval struct {
	Proposal string `json:"proposal_id"`
	Approve  bool   `json:"approve"`
}
type decMigrationPrefix struct {
	Proposal *dec.Statement
	Fields   decMigrationProposal
	Snapshot *dec.SourceState
	Facts    linking.NetworkState
	Catalog  *dec.Catalog
	Root     *dec.Statement
}

// DecentralizedMigrationEvidence returns the retained transition snapshot.
// It never prepares a proposal, fills a signature or refreshes local authority.
func (s *Store) DecentralizedMigrationEvidence(ctx context.Context, network string) (json.RawMessage, error) {
	if !dec.ValidID(network, "net_") {
		return nil, decFailure("invalid")
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	_, record, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return nil, e
	}
	if record.Proposal == "-" {
		return nil, ErrNotFound
	}
	if _, e = s.decMigrationStatus(ctx, tx, network); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(migrationRecordEvidence(record))
	if e != nil {
		return nil, e
	}
	if len(raw) > dec.MaxPrivateRecord {
		return nil, decFailure("quota_exceeded")
	}
	return raw, tx.Commit()
}

// Prefix verification supplies preparation facts only. It never constructs an
// ordinary prior, grants a signer, or treats another host's approval as local.
func readMigrationPrefix(d dec.Descriptor, input DecMigrationEvidence) (*decMigrationPrefix, error) {
	if input.Acknowledgments == nil || len(input.Acknowledgments) > 4096 {
		return nil, decFailure("invalid")
	}
	proposal, e := dec.ReadStatement(d, input.Proposal)
	if e != nil {
		return nil, e
	}
	if proposal.Kind != "migration_proposal" {
		return nil, decFailure("invalid")
	}
	var p decMigrationProposal
	if e = dec.ReadPrivateRecord(proposal.Payload, "proposal_nonce legacy_descriptor_base64 legacy_feature_id legacy_epoch legacy_root_public_key source_catalog_sha256 source_state_sha256 new_descriptor roster issued_at expires_at", &p); e != nil {
		return nil, e
	}
	source, e := decBytes(input.Source, 512<<10)
	if e != nil {
		return nil, e
	}
	state, e := decBytes(input.State, dec.MaxPayload)
	if e != nil {
		return nil, e
	}
	if decMigrationHash(source) != p.SourceHash || decMigrationHash(state) != p.StateHash {
		return nil, decFailure("invalid")
	}
	snapshot, facts, e := dec.VerifyMigrationSourceSnapshot(d, mustDecBytes(p.Legacy), source, state, p.Epoch, p.Feature, p.Root, p.Issued)
	if e != nil {
		return nil, e
	}
	if proposal.Signer("issuer") != facts.RootPublicKey || len(p.Roster) != len(facts.Members) {
		return nil, decFailure("invalid")
	}
	for n, row := range p.Roster {
		member := facts.Members[n]
		if row.Host != member.HostPublicKey || row.Member != member.Member || row.Person != member.PersonPublicKey {
			return nil, decFailure("invalid")
		}
	}
	result := &decMigrationPrefix{Proposal: proposal, Fields: p, Snapshot: snapshot, Facts: facts}
	if bytes.Equal(input.Catalog, []byte(`"-"`)) {
		if len(input.Acknowledgments) > 0 || !bytes.Equal(input.Commit, []byte(`"-"`)) {
			return nil, decFailure("proof_required", proposal.ID)
		}
		return result, nil
	}
	catalog, e := dec.ReadCatalog(d, input.Catalog)
	if e != nil {
		return nil, e
	}
	result.Catalog = catalog
	if len(catalog.Migrations) > 0 {
		return nil, decFailure("invalid")
	}
	for _, statement := range catalog.Statements {
		if statement.Kind == "migration_proposal" {
			if statement.ID != proposal.ID || !bytes.Equal(statement.Payload, proposal.Payload) || statement.Signer("issuer") != p.Root {
				return nil, decFailure("state_conflict")
			}
			continue
		}
		if statement.Root != nil {
			root := statement.Root
			if result.Root != nil && result.Root.ID != statement.ID {
				return nil, decFailure("state_conflict")
			}
			if root.Migration != proposal.ID || root.Epoch != p.Epoch || root.Key != p.Root || root.Issued != p.Issued || len(root.Predecessors) != 0 || len(root.Resolves) != 0 || len(root.Retained) != 0 || statement.Signer("issuer") != p.Root {
				return nil, decFailure("invalid")
			}
			result.Root = statement
		}
	}
	for _, object := range catalog.Objects {
		statement := catalog.Proofs[object.ID]
		if statement == nil {
			continue
		}
		if statement.Kind == "migration_proposal" || statement.Root != nil {
			if statement.Signer("issuer") != p.Root {
				return nil, decFailure("invalid")
			}
			continue
		}
		var root string
		var issuer dec.Issuer
		if statement.Lease != nil {
			root, issuer = statement.Lease.Root, statement.Lease.Issuer
		} else if statement.Access != nil {
			root, issuer = statement.Access.Root, statement.Access.Issuer
		} else if statement.Restriction != nil {
			root, issuer = statement.Restriction.Root, statement.Restriction.Issuer
		} else {
			return nil, decFailure("invalid")
		}
		if result.Root == nil {
			return nil, decFailure("proof_required", root)
		}
		if root != result.Root.ID {
			return nil, decFailure("invalid")
		}
		if issuer.Kind == "root" && statement.Signer("issuer") != p.Root {
			return nil, decFailure("invalid")
		}
	}
	for _, activation := range catalog.ActivationProofs {
		var request struct {
			Mode     string `json:"mode"`
			Proposal string `json:"migration_proposal_id"`
		}
		if json.Unmarshal(activation.Request.Payload, &request) != nil || request.Mode != "new" || request.Proposal != proposal.ID {
			return nil, decFailure("invalid")
		}
	}
	last := ""
	for _, raw := range input.Acknowledgments {
		ack, e := dec.ReadStatement(d, raw)
		if e != nil {
			return nil, e
		}
		var pin struct {
			Proposal string `json:"proposal_id"`
			Root     string `json:"root_state_id"`
			Hash     string `json:"prepared_catalog_sha256"`
			Host     string `json:"host_public_key"`
			Person   string `json:"person_public_key"`
			Device   string `json:"device_public_key"`
			Time     string `json:"acknowledged_at"`
		}
		if json.Unmarshal(ack.Payload, &pin) != nil || ack.Kind != "migration_ack" || pin.Proposal != proposal.ID || pin.Hash != decMigrationHash(input.Catalog) || result.Root == nil || pin.Root != result.Root.ID || pin.Host <= last || ack.Signer("host") != pin.Host || pin.Time < p.Issued || pin.Time >= p.Expires || pin.Device != "-" && ack.Signer("device") != pin.Device {
			return nil, decFailure("invalid")
		}
		found := false
		for _, row := range p.Roster {
			if row.Host == pin.Host && row.Person == pin.Person && row.Device == pin.Device {
				found = true
			}
		}
		if !found {
			return nil, decFailure("invalid")
		}
		// A signed partial ACK can freeze the prepared identity before a final
		// root commit exists. Check its full prepared authority at the signed
		// historical decision time and every exact H/B/D/activation reference
		// before retaining it; keys/hash alone do not establish these facts.
		prepared, e := dec.VerifyMigrationPrepared(d, input.Proposal, source, state, input.Catalog, pin.Time, pin.Host)
		if e != nil {
			return nil, e
		}
		expected, e := dec.MigrationAcknowledgmentPayload(prepared, pin.Host, pin.Time)
		if e != nil {
			return nil, e
		}
		var actualFields, expectedFields map[string]string
		if json.Unmarshal(ack.Payload, &actualFields) != nil || json.Unmarshal(expected, &expectedFields) != nil || !reflect.DeepEqual(actualFields, expectedFields) {
			return nil, decFailure("invalid")
		}
		last = pin.Host
	}
	if !bytes.Equal(input.Commit, []byte(`"-"`)) {
		// Once a commit exists the complete original portable migration must
		// verify. Incomplete prepared evidence cannot be laundered by a root.
		full, e := migrationCompositeBody(input.Proposal, input.Source, input.State, base64.StdEncoding.EncodeToString(input.Catalog), input.Acknowledgments, input.Commit)
		if e != nil {
			return nil, e
		}
		if len(full) > dec.MaxObject {
			return nil, decFailure("quota_exceeded")
		}
		if _, e = dec.VerifyMigration(d, []byte(`"-"`), []byte(`"-"`), full, p.Issued, "evidence", "-"); e != nil {
			return nil, e
		}
	}
	return result, nil
}

// Every local fact is a lower bound on the proposed source. The proposal's
// source remains unchanged; the union is used only to expose contradictions.
func (s *Store) checkMigrationSourceKnown(ctx context.Context, q dbQuerier, local *decMigrationSource, prefix *decMigrationPrefix, input DecMigrationEvidence) error {
	p := prefix.Fields
	compatible, e := dec.MigrationLegacyDescriptorsEqual(local.Legacy, mustDecBytes(p.Legacy))
	if e != nil {
		return e
	}
	if !compatible || p.Epoch < local.Facts.Epoch || local.Feature != "-" && p.Feature != local.Feature {
		return decFailure("state_conflict")
	}
	union, e := mergeLinkCatalog(local.Network.ID, local.Catalog, mustDecBytes(input.Source))
	if e != nil {
		return e
	}
	now, e := dec.ParseTime(local.Time)
	if e != nil {
		return e
	}
	facts, e := linking.VerifyStoredLegacyMigrationSource(linking.CatalogFactContext{Network: local.Legacy, Epoch: p.Epoch, KnownFeatureID: local.Feature, Now: now}, union)
	if e != nil {
		return decLegacyError(e)
	}
	if facts.RootPublicKey != p.Root || facts.Epoch != p.Epoch {
		return decFailure("state_conflict")
	}
	hosts := map[string]bool{}
	for _, host := range prefix.Snapshot.Hosts {
		hosts[host] = true
	}
	for _, member := range facts.Members {
		if !hosts[member.HostPublicKey] {
			return decFailure("forbidden")
		}
	}
	floors := map[string]dec.LegacyMaximum{}
	for _, floor := range prefix.Snapshot.Maxima {
		floors[floor.Kind+"\x00"+floor.Subject] = floor
	}
	for _, floor := range local.Snapshot.Maxima {
		next, ok := floors[floor.Kind+"\x00"+floor.Subject]
		if !ok || next.Version < floor.Version {
			return decFailure("forbidden")
		}
		if next.Version == floor.Version && floor.Hash != "-" && next.Hash != floor.Hash {
			return decFailure("state_conflict")
		}
	}
	restrictions := map[string]dec.LegacyRestriction{}
	for _, restriction := range prefix.Snapshot.Restrictions {
		restrictions[restriction.ProofID] = restriction
	}
	for _, restriction := range local.Snapshot.Restrictions {
		if restrictions[restriction.ProofID] != restriction {
			return decFailure("forbidden")
		}
	}
	return nil
}

func migrationRecordEvidence(r decMigrationRecord) DecMigrationEvidence {
	proposal, prepared, commit := json.RawMessage(`"-"`), json.RawMessage(`"-"`), json.RawMessage(`"-"`)
	if r.Proposal != "-" {
		proposal = mustDecBytes(r.Proposal)
	}
	if r.PreparedCatalog != "-" {
		prepared = mustDecBytes(r.PreparedCatalog)
	}
	if r.Commit != "-" {
		commit = mustDecBytes(r.Commit)
	}
	acks := []json.RawMessage{}
	for _, ack := range r.Acknowledgments {
		acks = append(acks, mustDecBytes(ack))
	}
	return DecMigrationEvidence{proposal, r.SourceCatalog, r.SourceState, prepared, acks, commit}
}
func mergeMigrationPrepared(d dec.Descriptor, r *decMigrationRecord, input DecMigrationEvidence) error {
	if bytes.Equal(input.Catalog, []byte(`"-"`)) {
		return nil
	}
	if r.PreparedCatalog == "-" {
		r.PreparedCatalog = base64.StdEncoding.EncodeToString(input.Catalog)
		return nil
	}
	old, e := dec.ReadCatalog(d, mustDecBytes(r.PreparedCatalog))
	if e != nil {
		return e
	}
	next, e := dec.ReadCatalog(d, input.Catalog)
	if e != nil {
		return e
	}
	if bytes.Equal(old.Raw, next.Raw) {
		return nil
	}
	if r.AckIntent != "-" || r.Fenced || len(r.Acknowledgments) > 0 || r.LocalAck != "-" || r.Commit != "-" || r.Migration != "-" {
		return decFailure("operation_conflict")
	}
	// A superset received with an ACK must preserve that sender's exact
	// prepared bytes. Ordinary prefix union retains all exact old objects.
	containsOld := true
	for _, object := range old.Objects {
		found := false
		for _, other := range next.Objects {
			found = found || object.ID == other.ID && bytes.Equal(object.Body, other.Body)
		}
		containsOld = containsOld && found
	}
	if containsOld {
		r.PreparedCatalog = base64.StdEncoding.EncodeToString(input.Catalog)
		return nil
	}
	if len(input.Acknowledgments) > 0 || !bytes.Equal(input.Commit, []byte(`"-"`)) {
		return decFailure("operation_conflict")
	}
	union, e := dec.UnionCatalog(d, old, next)
	if e != nil {
		return e
	}
	r.PreparedCatalog = base64.StdEncoding.EncodeToString(union.Raw)
	return nil
}

func (s *Store) ReceiveDecentralizedMigrationEvidence(ctx context.Context, network string, input DecMigrationEvidence) (DecMigrationResult, error) {
	return s.receiveDecMigration(ctx, network, input, "")
}

func (s *Store) receiveDecMigration(ctx context.Context, network string, input DecMigrationEvidence, caller string) (DecMigrationResult, error) {
	if !dec.ValidID(network, "net_") {
		return DecMigrationResult{}, decFailure("invalid")
	}
	if result, handled, e := s.receiveAdoptedDecMigration(ctx, network, input, caller); handled {
		return result, e
	}
	facts := decCommittedFacts{}
	result, e := s.receiveDecMigrationEvidence(ctx, network, input, &facts, caller)
	if e != nil {
		return result, e
	}
	if e = facts.wait(ctx); e != nil {
		return result, e
	}
	return result, nil
}
func (s *Store) receiveDecMigrationEvidence(ctx context.Context, network string, input DecMigrationEvidence, facts *decCommittedFacts, caller string) (DecMigrationResult, error) {
	if !dec.ValidID(network, "net_") {
		return DecMigrationResult{}, decFailure("invalid")
	}
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return DecMigrationResult{}, e
	}
	defer tx.Rollback()
	local, e := s.decMigrationSource(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if caller != "" {
		if e = checkMigrationSourcePeer(local, caller, s.identity.PublicKey); e != nil {
			return DecMigrationResult{}, e
		}
	}
	prefix, e := readMigrationPrefix(local.Descriptor, input)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if e = s.checkMigrationSourceKnown(ctx, tx, local, prefix, input); e != nil {
		return DecMigrationResult{}, e
	}
	id, r, e := migrationRecord(ctx, tx, network)
	fresh := errors.Is(e, ErrNotFound)
	if e != nil && !fresh {
		return DecMigrationResult{}, e
	}
	if fresh {
		r = decMigrationRecord{Format: 1, Context: local.Descriptor.ContextID, State: "needs_approvals", Proposal: "-", SourceCatalog: input.Source, SourceState: input.State, PreparedCatalog: "-", InitialRoot: "-", Acknowledgments: []string{}, Commit: "-", Migration: "-", LocalAck: "-", RootIntents: []string{}, AckIntent: "-"}
		id = prefix.Proposal.ID
	} else {
		if id != prefix.Proposal.ID || r.SourceCatalog != input.Source || r.SourceState != input.State {
			return DecMigrationResult{}, decFailure("state_conflict")
		}
		if r.Proposal != "-" {
			old, e := dec.ReadStatement(local.Descriptor, mustDecBytes(r.Proposal))
			if e != nil {
				return DecMigrationResult{}, e
			}
			if old.ID != prefix.Proposal.ID || !bytes.Equal(old.Payload, prefix.Proposal.Payload) {
				return DecMigrationResult{}, decFailure("state_conflict")
			}
		}
	}
	if r.Proposal == "-" {
		r.Proposal = base64.StdEncoding.EncodeToString(input.Proposal)
	}
	if e = mergeMigrationPrepared(local.Descriptor, &r, input); e != nil {
		return DecMigrationResult{}, e
	}
	if prefix.Root != nil {
		if r.InitialRoot != "-" {
			old, e := dec.ReadStatement(local.Descriptor, mustDecBytes(r.InitialRoot))
			if e != nil {
				return DecMigrationResult{}, e
			}
			if old.ID != prefix.Root.ID {
				return DecMigrationResult{}, decFailure("state_conflict")
			}
		} else {
			r.InitialRoot = base64.StdEncoding.EncodeToString(prefix.Root.Raw)
		}
	}
	acks := map[string]json.RawMessage{}
	for _, raw := range append(migrationRecordEvidence(r).Acknowledgments, input.Acknowledgments...) {
		ack, e := dec.ReadStatement(local.Descriptor, raw)
		if e != nil {
			return DecMigrationResult{}, e
		}
		host := ack.Signer("host")
		if old, ok := acks[host]; ok {
			previous, e := dec.ReadStatement(local.Descriptor, old)
			if e != nil {
				return DecMigrationResult{}, e
			}
			if previous.ID != ack.ID {
				return DecMigrationResult{}, decFailure("state_conflict")
			}
		} else {
			acks[host] = raw
		}
	}
	hosts := []string{}
	for host := range acks {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	r.Acknowledgments = []string{}
	for _, host := range hosts {
		r.Acknowledgments = append(r.Acknowledgments, base64.StdEncoding.EncodeToString(acks[host]))
	}
	if !bytes.Equal(input.Commit, []byte(`"-"`)) {
		if r.Commit != "-" && !bytes.Equal(mustDecBytes(r.Commit), input.Commit) {
			return DecMigrationResult{}, decFailure("state_conflict")
		}
		r.Commit = base64.StdEncoding.EncodeToString(input.Commit)
	}
	combined := migrationRecordEvidence(r)
	if _, e = readMigrationPrefix(local.Descriptor, combined); e != nil {
		return DecMigrationResult{}, e
	}
	prepared := mustDecBytes(r.PreparedCatalog)
	if r.PreparedCatalog == "-" {
		prepared = []byte(`"-"`)
	}
	if e = migrationPreparationBudget(r, combined.Proposal, prepared); e != nil {
		return DecMigrationResult{}, e
	}
	if r.Commit != "-" && r.Migration == "-" {
		full, e := completeMigrationBody(r)
		if e != nil {
			return DecMigrationResult{}, e
		}
		if len(full) > dec.MaxObject {
			return DecMigrationResult{}, decFailure("quota_exceeded")
		}
		r.Migration = base64.StdEncoding.EncodeToString(full)
		if r.State == "needs_approvals" {
			r.State = "prepared"
		}
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	if _, e = dec.DecisionTime(latest, local.Time); e != nil {
		return DecMigrationResult{}, e
	}
	if caller != "" {
		current, e := s.decMigrationSource(ctx, tx, network)
		if e != nil {
			return DecMigrationResult{}, e
		}
		if e = checkMigrationSourcePeer(current, caller, s.identity.PublicKey); e != nil {
			return DecMigrationResult{}, e
		}
		if e = s.checkMigrationSourceKnown(ctx, tx, current, prefix, input); e != nil {
			return DecMigrationResult{}, e
		}
	}
	if e = storeDecMigration(ctx, tx, network, id, r, fresh); e != nil {
		return DecMigrationResult{}, e
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return DecMigrationResult{}, e
	}
	view, e := s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	review := migrationParticipationReview(network, prefix, r, "participation")
	if e = tx.Commit(); e != nil {
		return DecMigrationResult{}, e
	}
	facts.operation = id
	if fresh {
		facts.add("dec.migration_proposal.after_commit")
	}
	return DecMigrationResult{view, review, []DecSigningRequest{}}, nil
}

func migrationParticipationReview(network string, prefix *decMigrationPrefix, r decMigrationRecord, stage string) DecMigrationReview {
	p := prefix.Fields
	hash := "-"
	if r.PreparedCatalog != "-" {
		hash = decMigrationHash(mustDecBytes(r.PreparedCatalog))
	}
	return DecMigrationReview{stage, network, prefix.Proposal.ID, p.Root, p.Epoch, prefix.Proposal.ContextID, p.Roster, p.SourceHash, p.StateHash, hash, "Review the exact immutable source, roster and finite authority. Every original person and known host must separately approve. Participation does not acknowledge or adopt; a later acknowledgment creates a durable fence with no timeout abort."}
}

func (s *Store) ReviewDecentralizedMigration(ctx context.Context, network string, input DecMigrationApproval) (DecMigrationResult, error) {
	if !dec.ValidID(network, "net_") || !dec.ValidID(input.Proposal, "ds_") {
		return DecMigrationResult{}, decFailure("invalid")
	}
	facts := decCommittedFacts{operation: input.Proposal}
	result, e := func() (DecMigrationResult, error) {
		s.linkMu.Lock()
		defer s.linkMu.Unlock()
		s.syncing.Lock()
		defer s.syncing.Unlock()
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return DecMigrationResult{}, e
		}
		defer tx.Rollback()
		local, e := s.decMigrationSource(ctx, tx, network)
		if e != nil {
			return DecMigrationResult{}, e
		}
		id, r, e := migrationRecord(ctx, tx, network)
		if e != nil {
			return DecMigrationResult{}, e
		}
		if id != input.Proposal {
			return DecMigrationResult{}, decFailure("operation_conflict")
		}
		if r.Proposal == "-" {
			return DecMigrationResult{}, decFailure("proof_required", id)
		}
		evidence := migrationRecordEvidence(r)
		prefix, e := readMigrationPrefix(local.Descriptor, evidence)
		if e != nil {
			return DecMigrationResult{}, e
		}
		if e = s.checkMigrationSourceKnown(ctx, tx, local, prefix, evidence); e != nil {
			return DecMigrationResult{}, e
		}
		if local.Time < prefix.Fields.Issued {
			return DecMigrationResult{}, decFailure("not_yet_valid")
		}
		if local.Time >= prefix.Fields.Expires {
			return DecMigrationResult{}, decFailure("expired")
		}
		if e = s.checkMigrationOwnRoster(ctx, tx, local, prefix.Fields.Roster); e != nil {
			return DecMigrationResult{}, e
		}
		view, e := s.decMigrationStatus(ctx, tx, network)
		if e != nil {
			return DecMigrationResult{}, e
		}
		review := migrationParticipationReview(network, prefix, r, "participation")
		if !input.Approve || r.Approved {
			return DecMigrationResult{view, review, []DecSigningRequest{}}, nil
		}
		latest, e := decCreationClock(ctx, tx, network)
		if e != nil {
			return DecMigrationResult{}, e
		}
		if _, e = dec.DecisionTime(latest, local.Time); e != nil {
			return DecMigrationResult{}, e
		}
		if latest >= prefix.Fields.Expires {
			return DecMigrationResult{}, decFailure("expired")
		}
		r.Approved = true
		if e = storeDecMigration(ctx, tx, network, id, r, false); e != nil {
			return DecMigrationResult{}, e
		}
		if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
			return DecMigrationResult{}, e
		}
		if e = tx.Commit(); e != nil {
			return DecMigrationResult{}, e
		}
		view.Approved = true
		facts.add("dec.approval.after_commit")
		return DecMigrationResult{view, review, []DecSigningRequest{}}, nil
	}()
	if e != nil {
		return result, e
	}
	if e = facts.wait(ctx); e != nil {
		return result, e
	}
	return result, nil
}

func (s *Store) ResumeDecentralizedMigration(ctx context.Context, network string) (DecMigrationResult, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationResult{}, e
	}
	_, r, e := migrationRecord(ctx, tx, network)
	if e != nil {
		tx.Rollback()
		return DecMigrationResult{}, e
	}
	if r.AckIntent != "-" && r.Commit == "-" && r.State != "adopted" {
		i, e := readDecIntent(ctx, tx, r.AckIntent)
		tx.Rollback()
		if e != nil {
			return DecMigrationResult{}, e
		}
		if i.Record.Approved && !r.Fenced {
			return s.advanceMigrationAck(ctx, network)
		}
		return s.migrationAckResult(ctx, network)
	}
	if r.State != "adopted" && !r.Fenced {
		proposal, _, e := migrationRecord(ctx, tx, network)
		if e != nil {
			tx.Rollback()
			return DecMigrationResult{}, e
		}
		i, e := migrationHostIntent(ctx, tx, network, proposal, s.identity.PublicKey)
		if e != nil {
			tx.Rollback()
			return DecMigrationResult{}, e
		}
		if i != nil && i.Record.Approved && !i.Record.Completed {
			tx.Rollback()
			facts, e := s.signMigrationHost(ctx, network, i.ID)
			if e != nil {
				return DecMigrationResult{}, e
			}
			if e = facts.wait(ctx); e != nil {
				return DecMigrationResult{}, e
			}
			return s.ResumeDecentralizedMigration(ctx, network)
		}
	}
	if r.State == "adopted" || r.Commit != "-" && r.LocalAck != "-" && r.Fenced {
		d, e := migrationDescriptor(r)
		if e != nil {
			tx.Rollback()
			return DecMigrationResult{}, e
		}
		prefix, e := readMigrationPrefix(d, migrationRecordEvidence(r))
		if e != nil {
			tx.Rollback()
			return DecMigrationResult{}, e
		}
		commit, e := dec.ReadStatement(d, mustDecBytes(r.Commit))
		tx.Rollback()
		if e != nil {
			return DecMigrationResult{}, e
		}
		// The exact durable ACK already approved eventual adoption. Resume adds
		// no new consent, signature or alternative proposal/catalog pin.
		adopted, e := s.AdoptDecentralizedMigration(ctx, network, DecMigrationAdoption{prefix.Proposal.ID, commit.ID, true})
		if e != nil {
			return DecMigrationResult{}, e
		}
		return DecMigrationResult{adopted.Migration, migrationParticipationReview(network, prefix, r, "adoption"), []DecSigningRequest{}}, nil
	}
	commit, e := migrationCommitIntent(ctx, tx, network, r)
	if e != nil {
		tx.Rollback()
		return DecMigrationResult{}, e
	}
	if commit != nil {
		tx.Rollback()
		if commit.Record.Approved && !commit.Record.Completed {
			return s.advanceMigrationCommit(ctx, network, commit.ID, nil)
		}
		return s.migrationCommitResult(ctx, network, commit.ID)
	}
	if len(r.RootIntents) > 0 {
		i, e := readDecIntent(ctx, tx, r.RootIntents[0])
		tx.Rollback()
		if e != nil {
			return DecMigrationResult{}, e
		}
		if len(i.Record.Templates) == 0 || i.Record.Templates[0].Type != "migration_proposal" {
			return DecMigrationResult{}, decFailure("recovery_required")
		}
		if i.Record.Approved && !i.Record.Completed {
			return s.advanceMigrationProposal(ctx, network, i.ID, nil)
		}
		return s.migrationProposalResult(ctx, network, i.ID)
	}
	defer tx.Rollback()
	local, e := s.decMigrationSource(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	evidence := migrationRecordEvidence(r)
	prefix, e := readMigrationPrefix(local.Descriptor, evidence)
	if e != nil {
		return DecMigrationResult{}, e
	}
	view, e := s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, e
	}
	return DecMigrationResult{view, migrationParticipationReview(network, prefix, r, "participation"), []DecSigningRequest{}}, nil
}
