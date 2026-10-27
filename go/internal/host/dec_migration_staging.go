package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
)

// A complete per-host transcript fixes prepared evidence only. It cannot cross
// the separate all-host acknowledgment/root-commit adoption boundary.
func (s *Store) prepareStoredDecMigrationLink(ctx context.Context, id string) error {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return e
	}
	if p.Record.Terminal == "migration_prepared" || p.Record.Terminal == "migration_adopted" {
		return nil
	}
	if p.Record.Migration == "-" || p.Record.Terminal != "-" || containsString(p.Record.Roles, "requester") && (!p.Record.Selected || !p.Record.Committed) {
		return decFailure("review_required")
	}
	activation, catalog, _, e := decPendingActivation(p)
	if e != nil {
		return e
	}
	now, e := decCreationClock(ctx, tx, p.Record.Network)
	if e != nil {
		return e
	}
	if _, e = s.verifyDecMigrationActivation(ctx, tx, p, catalog, activation, now); e != nil {
		return e
	}
	proposal, record, e := migrationRecord(ctx, tx, p.Record.Network)
	if e != nil {
		return e
	}
	if proposal != p.Record.Migration || !record.Approved {
		return decFailure("review_required")
	}
	evidence := migrationRecordEvidence(record)
	evidence.Catalog = catalog.Raw
	evidence.Acknowledgments = []json.RawMessage{}
	evidence.Commit = json.RawMessage(`"-"`)
	if e = mergeMigrationPrepared(p.Descriptor, &record, evidence); e != nil {
		return e
	}
	if e = migrationPreparationBudget(record, mustDecBytes(record.Proposal), mustDecBytes(record.PreparedCatalog)); e != nil {
		return e
	}
	p.Record.Terminal = "migration_prepared"
	p.Record.Catalog = base64.StdEncoding.EncodeToString(catalog.Raw)
	if record.State == "needs_approvals" {
		record.State = "prepared"
	}
	if e = storeDecMigration(ctx, tx, p.Record.Network, proposal, record, false); e != nil {
		return e
	}
	if e = putDecPending(ctx, tx, p); e != nil {
		return e
	}
	if e = writeMigrationClock(ctx, tx, p.Record.Network, now); e != nil {
		return e
	}
	return tx.Commit()
}
