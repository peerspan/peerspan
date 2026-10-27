package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

const (
	decOutboxRows    = 4096
	decOutboxBodies  = 512 << 20
	decOutboxRecords = 1 << 30
)

type decHeldDelivery struct {
	ID, Network, Context, Target, Raw string
	Record                            decDeliveryRecord
	Body                              []byte
}

type decOutboxPlan struct {
	Network, Context string
	Inserts          []decHeldDelivery
	Retire           map[string]bool
}

func validateDecDelivery(id, target, raw string) (decDeliveryRecord, []byte, error) {
	var r decDeliveryRecord
	if e := dec.ReadPrivateRecord([]byte(raw), "format kind body_base64 proof_ids created_at attempts next_attempt_at last_error_code last_error_detail", &r); e != nil {
		return r, nil, e
	}
	if r.Format != 1 || !decLocalID(id, "ddel_") || !dec.ValidPublicKey(target) || !decIDs(r.Proofs, "dp_") || len(r.Detail) > 1024 || r.Kind != "proofs" && r.Kind != "activation" && r.Kind != "migration" {
		return r, nil, decStorageError()
	}
	if _, e := dec.ParseTime(r.Created); e != nil {
		return r, nil, e
	}
	if _, e := dec.ParseTime(r.Next); e != nil {
		return r, nil, e
	}
	body, e := decBytes(r.Body, 20<<20)
	return r, body, e
}

func heldDecDeliveries(ctx context.Context, q dbQuerier) ([]decHeldDelivery, error) {
	rows, e := q.QueryContext(ctx, `SELECT delivery_id,network_id,context_id,target_key,record FROM dec_outbox ORDER BY delivery_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	held := []decHeldDelivery{}
	for rows.Next() {
		var row decHeldDelivery
		if e = rows.Scan(&row.ID, &row.Network, &row.Context, &row.Target, &row.Raw); e != nil {
			return nil, e
		}
		if !dec.ValidID(row.Network, "net_") || !dec.ValidID(row.Context, "ctx_") {
			return nil, decStorageError()
		}
		row.Record, row.Body, e = validateDecDelivery(row.ID, row.Target, row.Raw)
		if e != nil {
			return nil, e
		}
		held = append(held, row)
		if len(held) > decOutboxRows {
			return nil, decFailure("quota_exceeded")
		}
	}
	return held, rows.Err()
}

// All three ceilings count the prospective queue, including deliveries belonging
// to other networks. A transport failure never authorizes removal. Retirement
// here is limited to proof-preserving exact monotonic coalescing.
func checkDecDeliveryBudget(held, added []decHeldDelivery, retired map[string]bool) error {
	var count, bodyBytes, recordBytes int64
	for _, batch := range [][]decHeldDelivery{held, added} {
		for _, row := range batch {
			if retired[row.ID] {
				continue
			}
			count++
			bodyBytes += int64(len(row.Body))
			recordBytes += int64(len(row.Raw))
			if count > decOutboxRows || bodyBytes > decOutboxBodies || recordBytes > decOutboxRecords {
				return decFailure("quota_exceeded")
			}
		}
	}
	return nil
}

// Creation has no other member targets. Its signatures still require the same
// whole-host preflight, even when there is nothing to enqueue for this network.
func preflightDecCreationOutbox(ctx context.Context, q dbQuerier) error {
	held, e := heldDecDeliveries(ctx, q)
	if e != nil {
		return e
	}
	return checkDecDeliveryBudget(held, nil, nil)
}

func (s *Store) planDecProofs(ctx context.Context, q dbQuerier, old *decSnapshot, p *dec.Projection) (*decOutboxPlan, error) {
	held, e := heldDecDeliveries(ctx, q)
	if e != nil {
		return nil, e
	}
	plan := &decOutboxPlan{old.Descriptor.NetworkID, old.Descriptor.ContextID, []decHeldDelivery{}, map[string]bool{}}
	next, e := p.AdmittedPrior()
	if e != nil {
		return nil, e
	}
	raw, e := decBytes(next.CatalogBase64, dec.MaxCatalog)
	if e != nil {
		return nil, e
	}
	catalog, e := dec.ReadCatalog(old.Descriptor, raw)
	if e != nil {
		return nil, e
	}
	if bytes.Equal(catalog.Raw, old.Catalog.Raw) {
		return plan, checkDecDeliveryBudget(held, nil, nil)
	}
	body, e := json.Marshal(struct {
		Catalog json.RawMessage `json:"catalog"`
	}{json.RawMessage(raw)})
	if e != nil {
		return nil, e
	}
	if len(body) > 20<<20 {
		return nil, decFailure("quota_exceeded")
	}
	heldProofs := decSet(catalog.ProofIDs())
	prior, e := dec.Project(old.Descriptor, old.PriorRaw, []byte("-"), p.DecisionTime, "read")
	if e != nil {
		return nil, e
	}
	targets := map[string]bool{}
	for _, projection := range []*dec.Projection{prior, p} {
		for _, member := range decMemberViews(projection) {
			if member.Host != s.identity.PublicKey {
				targets[member.Host] = true
			}
		}
	}
	for _, row := range held {
		if row.Network != plan.Network || row.Context != plan.Context || !targets[row.Target] || row.Record.Kind != "proofs" {
			continue
		}
		var previous struct {
			Catalog json.RawMessage `json:"catalog"`
		}
		if e = dec.ReadPrivateRecord(row.Body, "catalog", &previous); e != nil {
			return nil, e
		}
		previousCatalog, e := dec.ReadCatalog(old.Descriptor, previous.Catalog)
		if e != nil {
			return nil, e
		}
		for _, proofs := range [][]string{previousCatalog.ProofIDs(), row.Record.Proofs} {
			for _, proof := range proofs {
				if !heldProofs[proof] {
					return nil, decFailure("proof_required", proof)
				}
			}
		}
		plan.Retire[row.ID] = true
	}
	for _, target := range decSorted(targets) {
		id, e := decRandomID("ddel_")
		if e != nil {
			return nil, e
		}
		record := decDeliveryRecord{1, "proofs", base64.StdEncoding.EncodeToString(body), catalog.ProofIDs(), p.DecisionTime, 0, linkTime(time.Now()), "-", "-"}
		rawRecord, e := json.Marshal(record)
		if e != nil {
			return nil, e
		}
		if len(rawRecord) > dec.MaxPrivateRecord {
			return nil, decFailure("quota_exceeded")
		}
		plan.Inserts = append(plan.Inserts, decHeldDelivery{id, plan.Network, plan.Context, target, string(rawRecord), record, body})
	}
	return plan, checkDecDeliveryBudget(held, plan.Inserts, plan.Retire)
}

func (p *decOutboxPlan) store(ctx context.Context, tx *sql.Tx) error {
	for _, row := range p.Inserts {
		if _, e := tx.ExecContext(ctx, `INSERT INTO dec_outbox(delivery_id,network_id,context_id,target_key,record) VALUES(?,?,?,?,?)`, row.ID, row.Network, row.Context, row.Target, row.Raw); e != nil {
			return e
		}
	}
	for id := range p.Retire {
		if _, e := tx.ExecContext(ctx, `DELETE FROM dec_outbox WHERE delivery_id=? AND network_id=? AND context_id=?`, id, p.Network, p.Context); e != nil {
			return e
		}
	}
	return nil
}
