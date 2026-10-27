package host

import (
	"context"
	"database/sql"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type DecRootRetentionView struct {
	Network    string                       `json:"network_id"`
	Context    string                       `json:"context_id"`
	Time       string                       `json:"decision_time"`
	Roots      []string                     `json:"root_head_ids"`
	Catalog    json.RawMessage              `json:"catalog"`
	Candidates []dec.RootRetentionCandidate `json:"candidates"`
	Excluded   []dec.RootRetentionExcluded  `json:"excluded"`
}

func (s *Store) DecentralizedRootRetention(ctx context.Context, network string) (DecRootRetentionView, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecRootRetentionView{}, e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return DecRootRetentionView{}, e
	}
	if len(snapshot.Fenced) > 0 {
		return DecRootRetentionView{}, decFailure("migration_pending", snapshot.Fenced...)
	}
	now, e := decNow()
	if e != nil {
		return DecRootRetentionView{}, e
	}
	// All retained bytes/metadata are now in this immutable local snapshot.
	// Pure graph planning need not retain a SQLite read transaction.
	if e = tx.Rollback(); e != nil {
		return DecRootRetentionView{}, e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return DecRootRetentionView{}, e
	}
	candidates, excluded, e := p.RootRetention()
	if e != nil {
		return DecRootRetentionView{}, e
	}
	view := DecRootRetentionView{network, snapshot.Descriptor.ContextID, p.DecisionTime, p.Root.HeadIDs, json.RawMessage(snapshot.Catalog.Raw), candidates, excluded}
	raw, e := json.Marshal(view)
	if e != nil {
		return view, e
	}
	if len(raw) > 32<<20 {
		return DecRootRetentionView{}, decFailure("quota_exceeded")
	}
	return view, nil
}
