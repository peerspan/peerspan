package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// Post-adoption evidence is ordinary proof replication. It cannot replace the
// immutable original transition snapshot or create another local adoption.
func (s *Store) receiveAdoptedDecMigration(ctx context.Context, network string, input DecMigrationEvidence, caller string) (DecMigrationResult, bool, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	defer tx.Rollback()
	_, d, _, e := readDecNetwork(ctx, tx, network, s.identity.PublicKey)
	if dec.Code(e) == "upgrade_required" {
		return DecMigrationResult{}, false, nil
	}
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	_, retained, e := migrationRecord(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	if retained.State != "adopted" {
		return DecMigrationResult{}, true, decFailure("state_conflict")
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	if snapshot.Context.Origin != "migration" {
		return DecMigrationResult{}, true, decFailure("state_conflict")
	}
	// Strictly verify the complete incoming transcript before considering it an
	// alias or conflicting origin. A partial prefix cannot edit adopted history.
	prefix, e := readMigrationPrefix(d, input)
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	if prefix.Catalog == nil || bytes.Equal(input.Commit, []byte(`"-"`)) {
		return DecMigrationResult{}, true, decFailure("operation_conflict")
	}
	carrier := decMigrationRecord{Proposal: base64.StdEncoding.EncodeToString(input.Proposal), SourceCatalog: input.Source, SourceState: input.State, PreparedCatalog: base64.StdEncoding.EncodeToString(input.Catalog), Commit: base64.StdEncoding.EncodeToString(input.Commit), Acknowledgments: []string{}}
	for _, ack := range input.Acknowledgments {
		carrier.Acknowledgments = append(carrier.Acknowledgments, base64.StdEncoding.EncodeToString(ack))
	}
	body, e := completeMigrationBody(carrier)
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	known := false
	proof := dec.ProofID("migration", body)
	for _, object := range snapshot.Catalog.Objects {
		if object.ID == proof {
			if object.Kind != "migration" || !bytes.Equal(object.Body, body) {
				return DecMigrationResult{}, true, decStorageError()
			}
			known = true
			break
		}
	}
	// Exact component retry is independent of the unsigned full-M wrapper's
	// key order across runtimes. Preserve its first retained bytes and outcome.
	exactOriginal := migrationEvidenceExact(retained, input)
	if exactOriginal {
		known = true
	}
	// This peer path is original archival exchange only after adoption. New
	// complete origins use the ordinary current /catalog importer, never this
	// transition route. Owner-local public-file import retains its own path.
	if caller != "" && !exactOriginal {
		return DecMigrationResult{}, true, decFailure("operation_conflict")
	}
	view, e := s.decMigrationStatus(ctx, tx, network)
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	original, e := readMigrationPrefix(d, migrationRecordEvidence(retained))
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	result := DecMigrationResult{view, migrationParticipationReview(network, original, retained, "adoption"), []DecSigningRequest{}}
	if e = tx.Rollback(); e != nil {
		return DecMigrationResult{}, true, e
	}
	if known {
		if view.State == "conflict" {
			return result, true, decFailure("state_conflict")
		}
		return result, true, nil
	}
	catalog, e := migrationOriginCatalog(d, body)
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	// The normal importer loads the actual durable prior, unions every exact
	// proof, verifies all origins and rechecks NOW in its final transaction.
	// It neither selects a provider nor touches the retained migration record.
	_, projection, e := s.applyDecCatalog(ctx, network, catalog, "repair")
	if e != nil {
		return DecMigrationResult{}, true, e
	}
	if projection.Root.Code != "-" {
		return result, true, decFailure(projection.Root.Code, projection.Root.RequiredIDs...)
	}
	return result, true, nil
}

func migrationEvidenceExact(r decMigrationRecord, input DecMigrationEvidence) bool {
	if !bytes.Equal(input.Proposal, mustDecBytes(r.Proposal)) || input.Source != r.SourceCatalog || input.State != r.SourceState || !bytes.Equal(input.Catalog, mustDecBytes(r.PreparedCatalog)) || !bytes.Equal(input.Commit, mustDecBytes(r.Commit)) || len(input.Acknowledgments) != len(r.Acknowledgments) {
		return false
	}
	for n, ack := range input.Acknowledgments {
		if !bytes.Equal(ack, mustDecBytes(r.Acknowledgments[n])) {
			return false
		}
	}
	return true
}

func migrationOriginsConflict(catalog *dec.Catalog) bool {
	origins := map[string]bool{}
	for _, m := range catalog.Migrations {
		origins[m.Proposal.ID+"/"+decMigrationHash(m.PreparedCatalog)] = true
	}
	return len(origins) > 1
}
