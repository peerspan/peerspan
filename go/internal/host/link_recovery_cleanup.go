package host

import (
	"context"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
)

// Expired public preview bookkeeping cannot permanently consume repair capacity.
// Unresolved submitted outcomes remain exact regardless of their deadline.
func (s *Store) pruneLinkImports(ctx context.Context, network string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT subject,record FROM network_statements WHERE network_id=? AND kind=? ORDER BY subject`, network, kindLinkImportIntent)
	if e != nil {
		return e
	}
	type row struct{ id, raw string }
	all := []row{}
	for rows.Next() {
		var item row
		if e = rows.Scan(&item.id, &item.raw); e != nil {
			break
		}
		all = append(all, item)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	for _, item := range all {
		var intent linkImportIntent
		if linking.DecodeStoredJSON([]byte(item.raw), "format import_id approved state network_base64 catalog_base64 authorization_template_base64 signature submitted result_map_base64", &intent) != nil || intent.ImportID != item.id {
			return linkFail("state_conflict", "-", "feature_import")
		}
		_, _, authorization, err := intent.materialize(network)
		if err != nil {
			return err
		}
		until, err := linkStamp(authorization.ExpiresAt)
		if err != nil {
			return err
		}
		if !now.After(until.Add(24*time.Hour)) || intent.Submitted && intent.State != "complete" {
			continue
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM network_statements WHERE network_id=? AND kind=? AND subject=? AND record=?`, network, kindLinkImportIntent, item.id, item.raw); e != nil {
			return e
		}
	}
	return tx.Commit()
}
