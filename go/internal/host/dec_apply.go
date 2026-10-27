package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func decStoredVersion(version uint64) any {
	if version <= uint64(^uint64(0)>>1) {
		return int64(version)
	}
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], version)
	return raw[:]
}
func decTuple(stream []string) (string, string, string) {
	subject, second := "-", "-"
	if len(stream) > 1 {
		subject = stream[1]
	}
	if len(stream) > 2 {
		second = stream[2]
	}
	return stream[0], subject, second
}
func decRandomID(prefix string) (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func putDecRecord(ctx context.Context, tx *sql.Tx, table, columns string, values []any, record any) error {
	raw, e := json.Marshal(record)
	if e != nil {
		return e
	}
	if len(raw) > dec.MaxPrivateRecord {
		return decFailure("quota_exceeded")
	}
	marks := ""
	for range values {
		marks += "?,"
	}
	marks += "?"
	args := append(append([]any{}, values...), string(raw))
	_, e = tx.ExecContext(ctx, `INSERT INTO `+table+` (`+columns+`,record) VALUES (`+marks+`)`, args...)
	return e
}
func decSet(ids []string) map[string]bool {
	result := map[string]bool{}
	for _, id := range ids {
		result[id] = true
	}
	return result
}
func decSorted(ids map[string]bool) []string {
	result := []string{}
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}
func decProofSource(c *dec.Catalog, id string) (string, error) {
	ids := append([]string{}, c.Sources[id]...)
	sort.Strings(ids)
	if len(ids) == 0 {
		return "", decFailure("proof_required", id)
	}
	return ids[0], nil
}

// storeDecProjection is called only after the final coherent NOW verification
// inside this write transaction. It does not infer local context adoption,
// requester consent or provider selection from public proof replication.
func (s *Store) storeDecProjection(ctx context.Context, tx *sql.Tx, old *decSnapshot, p *dec.Projection) error {
	next, e := p.AdmittedPrior()
	if e != nil {
		return e
	}
	catalogRaw, e := decBytes(next.CatalogBase64, dec.MaxCatalog)
	if e != nil {
		return e
	}
	c, e := dec.ReadCatalog(old.Descriptor, catalogRaw)
	if e != nil {
		return e
	}
	for _, object := range c.Objects {
		var kind string
		var stored any
		e = tx.QueryRowContext(ctx, `SELECT kind,body FROM dec_objects WHERE network_id=? AND context_id=? AND proof_id=?`, old.Descriptor.NetworkID, old.Descriptor.ContextID, object.ID).Scan(&kind, &stored)
		if e == nil {
			body, ok := stored.([]byte)
			if !ok || kind != object.Kind || !bytes.Equal(body, object.Body) {
				return decStorageError()
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_objects(network_id,context_id,proof_id,kind,body) VALUES(?,?,?,?,?)`, old.Descriptor.NetworkID, old.Descriptor.ContextID, object.ID, object.Kind, object.Body); e != nil {
			return e
		}
	}
	for _, rows := range []struct {
		table, column string
		old, next     []string
	}{{"dec_admissions", "statement_id", old.Prior.AdmittedStatements, next.AdmittedStatements}, {"dec_restrictions", "restriction_id", old.Prior.AdmittedRestrictions, next.AdmittedRestrictions}} {
		known := decSet(rows.old)
		for _, id := range rows.next {
			if known[id] {
				continue
			}
			statement := c.Statements[id]
			if statement == nil {
				return decFailure("proof_required", id)
			}
			basis, e := p.Admission(id, false)
			if e != nil {
				return e
			}
			proof, e := decProofSource(c, id)
			if e != nil {
				return e
			}
			record := decAdmissionRecord{1, statement.Kind, proof, p.DecisionTime, decBasis{basis.Kind, basis.Evidence}}
			if e = putDecRecord(ctx, tx, rows.table, "network_id,context_id,"+rows.column, []any{old.Descriptor.NetworkID, old.Descriptor.ContextID, id}, record); e != nil {
				return e
			}
		}
	}
	knownActivations := decSet(old.Prior.AdmittedActivations)
	for _, id := range next.AdmittedActivations {
		if knownActivations[id] {
			continue
		}
		activation := c.Activations[id]
		if activation == nil {
			return decFailure("proof_required", id)
		}
		basis, e := p.Admission(id, true)
		if e != nil {
			return e
		}
		proof := ""
		for _, object := range c.Objects {
			if object.Kind == "activation" && dec.ProofID("activation", activation.Raw) == object.ID {
				proof = object.ID
				break
			}
		}
		if proof == "" {
			for _, m := range c.Migrations {
				var prepared struct {
					Objects []dec.CatalogObject `json:"objects"`
				}
				if json.Unmarshal(m.PreparedCatalog, &prepared) != nil {
					return decStorageError()
				}
				for _, object := range prepared.Objects {
					if object.Kind == "activation" && object.ID == dec.ProofID("activation", activation.Raw) {
						proof = dec.ProofID("migration", m.Raw)
						break
					}
				}
				if proof != "" {
					break
				}
			}
		}
		if proof == "" {
			return decFailure("proof_required", id)
		}
		record := decActivationRecord{1, proof, activation.ManifestID, p.DecisionTime, decBasis{basis.Kind, basis.Evidence}}
		if e = putDecRecord(ctx, tx, "dec_activations", "network_id,context_id,activation_id,request_id", []any{old.Descriptor.NetworkID, old.Descriptor.ContextID, id, activation.Request.RequestID}, record); e != nil {
			return e
		}
	}
	for _, m := range next.Maxima {
		kind, subject, second := decTuple(m.Stream)
		key, _ := json.Marshal(m.Stream)
		floors := decSet(old.FloorProofs[string(key)])
		for _, origin := range c.Migrations {
			var state dec.SourceState
			if json.Unmarshal(origin.SourceState, &state) != nil {
				return decStorageError()
			}
			for _, floor := range state.Maxima {
				if len(m.Stream) == 2 && floor.Kind == kind && floor.Subject == subject && floor.Version <= m.Sequence {
					floors[dec.ProofID("migration", origin.Raw)] = true
				}
			}
		}
		headRaw, _ := json.Marshal(decHeadRecord{1, m.HeadIDs})
		waterRaw, _ := json.Marshal(decWaterRecord{1, m.StatementIDs, decSorted(floors)})
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_heads(network_id,context_id,stream_kind,subject,subject2,record) VALUES(?,?,?,?,?,?) ON CONFLICT(network_id,context_id,stream_kind,subject,subject2) DO UPDATE SET record=excluded.record`, old.Descriptor.NetworkID, old.Descriptor.ContextID, kind, subject, second, string(headRaw)); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_highwater(network_id,context_id,stream_kind,subject,subject2,version,record) VALUES(?,?,?,?,?,?,?) ON CONFLICT(network_id,context_id,stream_kind,subject,subject2) DO UPDATE SET version=excluded.version,record=excluded.record`, old.Descriptor.NetworkID, old.Descriptor.ContextID, kind, subject, second, decStoredVersion(m.Sequence), string(waterRaw)); e != nil {
			return e
		}
	}
	n := old.Network
	n.Root = p.Root.SelectedID
	seed := old.RootSeed
	if seed != nil {
		if len(seed) != ed25519.SeedSize {
			return decStorageError()
		}
		key := ed25519.NewKeyFromSeed(seed)
		if p.Root.Code == "-" {
			root := c.Statements[p.Root.SelectedID]
			if root == nil || root.Root == nil {
				return decStorageError()
			}
			if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != root.Root.Key {
				seed = nil
			}
		}
	}
	raw, e := json.Marshal(n)
	if e != nil {
		return e
	}
	var storedSeed any
	if seed != nil {
		storedSeed = seed
	}
	if _, e = tx.ExecContext(ctx, `UPDATE networks SET record=?,root_seed=? WHERE id=?`, string(raw), storedSeed, old.Descriptor.NetworkID); e != nil {
		return e
	}
	clockRaw, _ := json.Marshal(decClockRecord{1, p.DecisionTime})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, old.Descriptor.NetworkID, string(clockRaw)); e != nil {
		return e
	}
	if e = s.storeDecMemberCache(ctx, tx, old.Descriptor, c, p); e != nil {
		return e
	}
	current := *old
	current.Catalog = c
	return s.reconcileDecPolicyEdits(ctx, tx, &current, p)
}

type decCachedMember struct {
	Format      uint64 `json:"format"`
	Mode        string `json:"mode"`
	Host        string `json:"host_public_key"`
	Member      string `json:"member"`
	Person      string `json:"person_public_key"`
	HostLease   string `json:"host_lease_id"`
	PersonLease string `json:"person_lease_id"`
	Binding     string `json:"binding_lease_id"`
	Activation  string `json:"activation_id"`
}

func (s *Store) storeDecMemberCache(ctx context.Context, tx *sql.Tx, d dec.Descriptor, c *dec.Catalog, p *dec.Projection) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM network_members WHERE network_id=?`, d.NetworkID); e != nil {
		return e
	}
	for _, member := range decMemberViews(p) {
		person, activation := "-", "-"
		if member.Person != "-" {
			if value, _, e := p.Current([]string{"person", member.Person}); e == nil {
				person = value.ID
			}
			if binding, _, e := p.Current([]string{"binding", member.Host}); e == nil && binding.Lease.Operation != "-" {
				for id, a := range c.Activations {
					if a.Request.RequestID == binding.Lease.Operation {
						if activation != "-" && activation != id {
							activation = "-"
							break
						}
						activation = id
					}
				}
			}
		}
		key, e := membership.DecodeKey(member.Host)
		if e != nil {
			return e
		}
		record := decCachedMember{2, "decentralized", member.Host, member.Member, member.Person, member.HostLease, person, member.Binding, activation}
		if e = putDecRecord(ctx, tx, "network_members", "network_id,host_id", []any{d.NetworkID, membership.HostID(key)}, record); e != nil {
			return e
		}
	}
	return nil
}

// applyDecCatalog performs a local admission. The public candidate can supply
// evidence only; all prior metadata, consent and pins come from durable rows.
func (s *Store) applyDecCatalog(ctx context.Context, id string, candidate []byte, operation string) (*decSnapshot, *dec.Projection, error) {
	return s.applyDecCatalogChecked(ctx, id, candidate, operation, "")
}
func (s *Store) applyDecCatalogFromPeer(ctx context.Context, id, caller string, candidate []byte) (*decSnapshot, *dec.Projection, error) {
	return s.applyDecCatalogChecked(ctx, id, candidate, "repair", caller)
}
func (s *Store) applyDecCatalogChecked(ctx context.Context, id string, candidate []byte, operation, caller string) (*decSnapshot, *dec.Projection, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	now, e := decNow()
	if e != nil {
		return nil, nil, e
	}
	old, _, e := s.decentralizedProjection(ctx, id, linkTime(now))
	if e != nil {
		return nil, nil, e
	}
	if caller != "" {
		prior, e := verifyDecSnapshot(old, linkTime(now))
		if e != nil {
			return nil, nil, e
		}
		if e = decRequireMember(old, prior, caller); e != nil {
			return nil, nil, e
		}
	}
	preview, e := dec.Project(old.Descriptor, old.PriorRaw, candidate, linkTime(now), operation)
	if e != nil {
		return nil, nil, e
	}
	preflight, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, nil, e
	}
	_, e = s.planDecProofs(ctx, preflight, old, preview)
	closeError := preflight.Rollback()
	if e != nil {
		return nil, nil, e
	}
	if closeError != nil {
		return nil, nil, closeError
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, nil, e
	}
	defer tx.Rollback()
	current, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		return nil, nil, e
	}
	if current.Fingerprint != old.Fingerprint {
		return nil, nil, decFailure("state_conflict")
	}
	now, e = decNow()
	if e != nil {
		return nil, nil, e
	}
	if caller != "" {
		prior, e := verifyDecSnapshot(current, linkTime(now))
		if e != nil {
			return nil, nil, e
		}
		if e = decRequireMember(current, prior, caller); e != nil {
			return nil, nil, e
		}
	}
	p, e := dec.Project(current.Descriptor, current.PriorRaw, candidate, linkTime(now), operation)
	if e != nil {
		return nil, nil, e
	}
	if e = s.storeDecProjection(ctx, tx, current, p); e != nil {
		return nil, nil, e
	}
	if e = s.queueDecProofs(ctx, tx, current, p); e != nil {
		return nil, nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, nil, e
	}
	snapshot, p, e := s.decentralizedProjection(ctx, id, linkTime(now))
	return snapshot, p, e
}

// A full current exact union can coalesce older public-proof deliveries for a
// target only after preserving every old exact required proof. The entire
// prospective fanout is budgeted before any delivery rows are changed.
func (s *Store) queueDecProofs(ctx context.Context, tx *sql.Tx, old *decSnapshot, p *dec.Projection) error {
	plan, e := s.planDecProofs(ctx, tx, old, p)
	if e != nil {
		return e
	}
	return plan.store(ctx, tx)
}
