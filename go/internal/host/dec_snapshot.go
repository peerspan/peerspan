package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type decOwnIdentity struct {
	Member string `json:"member"`
	Person string `json:"person_public_key"`
	Host   string `json:"host_public_key"`
}
type decNetworkRecord struct {
	Format     uint64         `json:"format"`
	Mode       string         `json:"mode"`
	Descriptor string         `json:"descriptor_base64"`
	Context    string         `json:"context_id"`
	Root       string         `json:"root_state_id"`
	Own        decOwnIdentity `json:"own_identity"`
	Created    string         `json:"created_at"`
}
type decContextRecord struct {
	Format      uint64 `json:"format"`
	Descriptor  string `json:"descriptor_base64"`
	Origin      string `json:"origin"`
	InitialRoot string `json:"initial_root_state_id"`
	OriginProof string `json:"origin_proof_id"`
	Proposal    string `json:"migration_proposal_id"`
	Adopted     string `json:"adopted_at"`
}
type decBasis struct {
	Kind     string   `json:"kind"`
	Evidence []string `json:"evidence_ids"`
}
type decAdmissionRecord struct {
	Format uint64   `json:"format"`
	Kind   string   `json:"kind"`
	Proof  string   `json:"proof_id"`
	At     string   `json:"admitted_at"`
	Basis  decBasis `json:"basis"`
}
type decActivationRecord struct {
	Format   uint64   `json:"format"`
	Proof    string   `json:"proof_id"`
	Manifest string   `json:"manifest_id"`
	At       string   `json:"admitted_at"`
	Basis    decBasis `json:"basis"`
}
type decHeadRecord struct {
	Format uint64   `json:"format"`
	IDs    []string `json:"head_ids"`
}
type decWaterRecord struct {
	Format uint64   `json:"format"`
	IDs    []string `json:"statement_ids"`
	Floors []string `json:"floor_proof_ids"`
}
type decClockRecord struct {
	Format  uint64 `json:"format"`
	Largest string `json:"largest_local_time"`
}
type decSelectedProvider struct{ Kind, Person, Device, Lease string }
type decMigrationRecord struct {
	Format          uint64   `json:"format"`
	Context         string   `json:"context_id"`
	State           string   `json:"state"`
	Proposal        string   `json:"proposal_base64"`
	SourceCatalog   string   `json:"source_catalog_base64"`
	SourceState     string   `json:"source_state_base64"`
	PreparedCatalog string   `json:"prepared_catalog_base64"`
	InitialRoot     string   `json:"initial_root_state_base64"`
	Acknowledgments []string `json:"acknowledgments_base64"`
	Commit          string   `json:"commit_base64"`
	Migration       string   `json:"migration_base64"`
	LocalAck        string   `json:"local_acknowledgment_base64"`
	RootIntents     []string `json:"root_intent_ids"`
	AckIntent       string   `json:"local_ack_intent_id"`
	Approved        bool     `json:"approved"`
	Fenced          bool     `json:"fenced"`
	Published       bool     `json:"publication_started"`
}

// A snapshot contains local durable metadata only. It is never decoded from a
// peer response or returned as public transport authority.
type decSnapshot struct {
	referenceProof   *dec.Projection
	referenceCatalog *dec.Catalog
	referencePrior   []byte
	FloorProofs      map[string][]string
	DeviceSeed       []byte
	Delivery         DecDeliveryView
	Network          decNetworkRecord
	Context          decContextRecord
	Descriptor       dec.Descriptor
	Catalog          *dec.Catalog
	Prior            dec.Prior
	PriorRaw         []byte
	RootSeed         []byte
	Provider         *decSelectedProvider
	Fenced           []string
	Fingerprint      string
}

func decStorageError() error { return &dec.Failure{Code: "state_conflict", RequiredIDs: []string{}} }
func decBytes(value string, max int) ([]byte, error) {
	if len(value) > base64.StdEncoding.EncodedLen(max) {
		return nil, &dec.Failure{Code: "quota_exceeded", RequiredIDs: []string{}}
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(value)
	if e != nil || base64.StdEncoding.EncodeToString(raw) != value || len(raw) > max {
		return nil, decStorageError()
	}
	return raw, nil
}
func decIDs(ids []string, prefix string) bool {
	if ids == nil || len(ids) > dec.MaxObjects {
		return false
	}
	for i, id := range ids {
		if !dec.ValidID(id, prefix) || i > 0 && ids[i-1] >= id {
			return false
		}
	}
	return true
}
func decEvidence(ids []string) bool {
	if ids == nil || len(ids) > dec.MaxObjects {
		return false
	}
	for i, id := range ids {
		valid := false
		for _, prefix := range []string{"ds_", "dp_", "da_", "dm_", "dpk_", "link_"} {
			if dec.ValidID(id, prefix) {
				valid = true
				break
			}
		}
		if !valid || i > 0 && ids[i-1] >= id {
			return false
		}
	}
	return true
}
func decVersion(value any, zero bool) (uint64, error) {
	if n, ok := value.(int64); ok && n >= 0 && (zero || n > 0) {
		return uint64(n), nil
	}
	if b, ok := value.([]byte); ok && len(b) == 8 && b[0]&128 != 0 {
		return binary.BigEndian.Uint64(b), nil
	}
	return 0, decStorageError()
}
func decStream(kind, subject, second string) ([]string, error) {
	stream := []string{kind, subject}
	if kind == "root" {
		if subject != "-" || second != "-" {
			return nil, decStorageError()
		}
		stream = []string{"root"}
	} else if kind == "device" {
		stream = append(stream, second)
	} else if second != "-" {
		return nil, decStorageError()
	}
	if !dec.ValidStream(stream) {
		return nil, decStorageError()
	}
	return stream, nil
}
func readDecNetwork(ctx context.Context, q dbQuerier, id, ownHost string) (decNetworkRecord, dec.Descriptor, []byte, error) {
	var n decNetworkRecord
	var raw string
	var seed []byte
	var seedValue any
	if e := q.QueryRowContext(ctx, `SELECT record,root_seed FROM networks WHERE id=?`, id).Scan(&raw, &seedValue); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return n, dec.Descriptor{}, nil, ErrNotFound
		}
		return n, dec.Descriptor{}, nil, e
	}
	if seedValue != nil {
		value, ok := seedValue.([]byte)
		if !ok {
			return n, dec.Descriptor{}, nil, decStorageError()
		}
		seed = append([]byte{}, value...)
	}
	var tag struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal([]byte(raw), &tag) != nil {
		return n, dec.Descriptor{}, nil, decStorageError()
	}
	if tag.Mode != "decentralized" {
		return n, dec.Descriptor{}, nil, &dec.Failure{Code: "upgrade_required", RequiredIDs: []string{}}
	}
	if e := dec.ReadPrivateRecord([]byte(raw), "format mode descriptor_base64 context_id root_state_id own_identity created_at", &n); e != nil {
		return n, dec.Descriptor{}, nil, e
	}
	if n.Format != 2 || n.Own.Host != ownHost || !membership.ValidLabel(n.Own.Member) || n.Own.Person != "-" && !dec.ValidPublicKey(n.Own.Person) || n.Root != "-" && !dec.ValidID(n.Root, "ds_") {
		return n, dec.Descriptor{}, nil, decStorageError()
	}
	if _, e := dec.ParseTime(n.Created); e != nil {
		return n, dec.Descriptor{}, nil, e
	}
	descriptor, e := decBytes(n.Descriptor, dec.MaxObject)
	if e != nil {
		return n, dec.Descriptor{}, nil, e
	}
	d, e := dec.ReadDescriptor(descriptor)
	if e != nil {
		return n, d, nil, e
	}
	if d.NetworkID != id || d.ContextID != n.Context {
		return n, d, nil, decStorageError()
	}
	return n, d, seed, nil
}

func readDecCatalog(ctx context.Context, q dbQuerier, d dec.Descriptor) (*dec.Catalog, error) {
	rows, e := q.QueryContext(ctx, `SELECT proof_id,kind,body FROM dec_objects WHERE network_id=? AND context_id=? ORDER BY proof_id`, d.NetworkID, d.ContextID)
	if e != nil {
		return nil, e
	}
	objects := []dec.CatalogObject{}
	for rows.Next() {
		var row dec.CatalogObject
		var body any
		if e = rows.Scan(&row.ID, &row.Kind, &body); e != nil {
			rows.Close()
			return nil, e
		}
		var ok bool
		row.Body, ok = body.([]byte)
		if !ok {
			rows.Close()
			return nil, decStorageError()
		}
		if len(objects) >= dec.MaxObjects || len(row.Body) > dec.MaxObject {
			rows.Close()
			return nil, &dec.Failure{Code: "quota_exceeded", RequiredIDs: []string{}}
		}
		row.BodyBase64 = base64.StdEncoding.EncodeToString(row.Body)
		objects = append(objects, row)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, objects})
	if e != nil {
		return nil, e
	}
	return dec.ReadCatalog(d, raw)
}

func readDecAdmissions(ctx context.Context, q dbQuerier, s *decSnapshot) error {
	for _, table := range []string{"dec_admissions", "dec_restrictions"} {
		column := "statement_id"
		if table == "dec_restrictions" {
			column = "restriction_id"
		}
		rows, e := q.QueryContext(ctx, `SELECT `+column+`,record FROM `+table+` WHERE network_id=? AND context_id=? ORDER BY `+column, s.Descriptor.NetworkID, s.Descriptor.ContextID)
		if e != nil {
			return e
		}
		for rows.Next() {
			var id, raw string
			if e = rows.Scan(&id, &raw); e != nil {
				rows.Close()
				return e
			}
			var record decAdmissionRecord
			if e = dec.ReadPrivateRecord([]byte(raw), "format kind proof_id admitted_at basis", &record); e != nil {
				rows.Close()
				return e
			}
			if record.Format != 1 || !dec.ValidID(id, "ds_") || !dec.ValidID(record.Proof, "dp_") || !decEvidence(record.Basis.Evidence) || record.At > s.Prior.ClockGuard {
				rows.Close()
				return decStorageError()
			}
			if _, e = dec.ParseTime(record.At); e != nil {
				rows.Close()
				return e
			}
			basis := record.Basis.Kind
			if basis != "current" && basis != "migration" && (table == "dec_admissions" && basis != "retention" || table == "dec_restrictions" && basis != "ratification") {
				rows.Close()
				return decStorageError()
			}
			if statement := s.Catalog.Statements[id]; statement != nil {
				if statement.Kind != record.Kind || (table == "dec_restrictions") != (statement.Restriction != nil) {
					rows.Close()
					return decStorageError()
				}
				for _, object := range s.Catalog.Objects {
					if object.ID == record.Proof && !containsDecID(s.Catalog.Sources[id], record.Proof) {
						rows.Close()
						return decStorageError()
					}
				}
			}
			if table == "dec_admissions" {
				s.Prior.AdmittedStatements = append(s.Prior.AdmittedStatements, id)
			} else {
				s.Prior.AdmittedRestrictions = append(s.Prior.AdmittedRestrictions, id)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	rows, e := q.QueryContext(ctx, `SELECT activation_id,request_id,record FROM dec_activations WHERE network_id=? AND context_id=? ORDER BY activation_id`, s.Descriptor.NetworkID, s.Descriptor.ContextID)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id, request, raw string
		var record decActivationRecord
		if e = rows.Scan(&id, &request, &raw); e != nil {
			return e
		}
		if e = dec.ReadPrivateRecord([]byte(raw), "format proof_id manifest_id admitted_at basis", &record); e != nil {
			return e
		}
		a := s.Catalog.Activations[id]
		if record.Format != 1 || !dec.ValidID(record.Proof, "dp_") || !decEvidence(record.Basis.Evidence) || record.At > s.Prior.ClockGuard || record.Basis.Kind != "current" && record.Basis.Kind != "retention" && record.Basis.Kind != "migration" {
			return decStorageError()
		}
		if a == nil {
			return decFailure("proof_required", record.Proof)
		}
		if a.Request.RequestID != request || a.ManifestID != record.Manifest {
			return decStorageError()
		}
		if _, e = dec.ParseTime(record.At); e != nil {
			return e
		}
		found := false
		for _, o := range s.Catalog.Objects {
			if o.ID == record.Proof && o.Kind == "activation" && dec.ProofID("activation", a.Raw) == o.ID {
				found = true
			}
			if o.ID == record.Proof && o.Kind == "migration" {
				for _, m := range s.Catalog.Migrations {
					if dec.ProofID("migration", m.Raw) == o.ID {
						var prepared struct {
							Objects []dec.CatalogObject `json:"objects"`
						}
						if json.Unmarshal(m.PreparedCatalog, &prepared) == nil {
							for _, p := range prepared.Objects {
								if p.Kind == "activation" && p.ID == dec.ProofID("activation", a.Raw) {
									found = true
								}
							}
						}
					}
				}
			}
		}
		if !found {
			return decStorageError()
		}
		s.Prior.AdmittedActivations = append(s.Prior.AdmittedActivations, id)
	}
	return rows.Err()
}
func containsDecID(ids []string, id string) bool {
	for _, actual := range ids {
		if actual == id {
			return true
		}
	}
	return false
}

func readDecWater(ctx context.Context, q dbQuerier, s *decSnapshot) error {
	heads := map[string]decHeadRecord{}
	rows, e := q.QueryContext(ctx, `SELECT stream_kind,subject,subject2,record FROM dec_heads WHERE network_id=? AND context_id=? ORDER BY stream_kind,subject,subject2`, s.Descriptor.NetworkID, s.Descriptor.ContextID)
	if e != nil {
		return e
	}
	for rows.Next() {
		var kind, subject, second, raw string
		if e = rows.Scan(&kind, &subject, &second, &raw); e != nil {
			rows.Close()
			return e
		}
		stream, e := decStream(kind, subject, second)
		if e != nil {
			rows.Close()
			return e
		}
		var record decHeadRecord
		if e = dec.ReadPrivateRecord([]byte(raw), "format head_ids", &record); e != nil {
			rows.Close()
			return e
		}
		if record.Format != 1 || !decIDs(record.IDs, "ds_") {
			rows.Close()
			return decStorageError()
		}
		key, _ := json.Marshal(stream)
		heads[string(key)] = record
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	rows, e = q.QueryContext(ctx, `SELECT stream_kind,subject,subject2,version,record FROM dec_highwater WHERE network_id=? AND context_id=? ORDER BY stream_kind,subject,subject2`, s.Descriptor.NetworkID, s.Descriptor.ContextID)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var kind, subject, second, raw string
		var stored any
		if e = rows.Scan(&kind, &subject, &second, &stored, &raw); e != nil {
			return e
		}
		stream, e := decStream(kind, subject, second)
		if e != nil {
			return e
		}
		version, e := decVersion(stored, kind == "root")
		if e != nil {
			return e
		}
		var record decWaterRecord
		if e = dec.ReadPrivateRecord([]byte(raw), "format statement_ids floor_proof_ids", &record); e != nil {
			return e
		}
		if record.Format != 1 || !decIDs(record.IDs, "ds_") || !decIDs(record.Floors, "dp_") {
			return decStorageError()
		}
		if len(record.IDs) == 0 && len(record.Floors) == 0 {
			return decStorageError()
		}
		for _, proof := range record.Floors {
			matched := false
			for _, migration := range s.Catalog.Migrations {
				if dec.ProofID("migration", migration.Raw) != proof {
					continue
				}
				var source dec.SourceState
				if json.Unmarshal(migration.SourceState, &source) != nil {
					return decStorageError()
				}
				for _, floor := range source.Maxima {
					if len(stream) == 2 && floor.Kind == kind && floor.Subject == subject && version >= floor.Version && (len(record.IDs) > 0 || version == floor.Version) {
						matched = true
					}
				}
			}
			if !matched {
				return decStorageError()
			}
		}
		key, _ := json.Marshal(stream)
		head, ok := heads[string(key)]
		if !ok {
			return decStorageError()
		}
		delete(heads, string(key))
		if kind == "root" {
			s.Prior.RootHeads = append([]string{}, head.IDs...)
		}
		if s.FloorProofs == nil {
			s.FloorProofs = map[string][]string{}
		}
		s.FloorProofs[string(key)] = append([]string{}, record.Floors...)
		s.Prior.Maxima = append(s.Prior.Maxima, dec.Maximum{Stream: stream, Sequence: version, StatementIDs: record.IDs, HeadIDs: head.IDs})
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if len(heads) != 0 {
		return decStorageError()
	}
	return nil
}

// loadDecSnapshot executes entirely within the caller's immutable database
// snapshot. Callers close it before pure expensive verification or any I/O.
func (s *Store) loadDecSnapshot(ctx context.Context, q dbQuerier, id string) (*decSnapshot, error) {
	n, d, seed, e := readDecNetwork(ctx, q, id, s.identity.PublicKey)
	if e != nil {
		return nil, e
	}
	snapshot := &decSnapshot{Network: n, Descriptor: d, RootSeed: seed, Prior: dec.Prior{Format: 1, ContextID: d.ContextID, AdmittedStatements: []string{}, AdmittedRestrictions: []string{}, AdmittedActivations: []string{}, RootHeads: []string{}, Maxima: []dec.Maximum{}}}
	var raw string
	if e = q.QueryRowContext(ctx, `SELECT record FROM dec_contexts WHERE network_id=? AND context_id=?`, id, d.ContextID).Scan(&raw); e != nil {
		return nil, decStorageError()
	}
	if e = dec.ReadPrivateRecord([]byte(raw), "format descriptor_base64 origin initial_root_state_id origin_proof_id migration_proposal_id adopted_at", &snapshot.Context); e != nil {
		return nil, e
	}
	c := snapshot.Context
	if c.Format != 1 || c.Descriptor != n.Descriptor || !dec.ValidID(c.InitialRoot, "ds_") || !dec.ValidID(c.OriginProof, "dp_") || c.Origin != "genesis" && c.Origin != "migration" || c.Origin == "genesis" && c.Proposal != "-" || c.Origin == "migration" && !dec.ValidID(c.Proposal, "ds_") {
		return nil, decStorageError()
	}
	if _, e = dec.ParseTime(c.Adopted); e != nil {
		return nil, e
	}
	snapshot.Prior.Migration = c.Proposal
	if e = q.QueryRowContext(ctx, `SELECT record FROM dec_clock WHERE network_id=?`, id).Scan(&raw); e != nil {
		return nil, decStorageError()
	}
	var clock decClockRecord
	if e = dec.ReadPrivateRecord([]byte(raw), "format largest_local_time", &clock); e != nil {
		return nil, e
	}
	if clock.Format != 1 || clock.Largest < n.Created || clock.Largest < c.Adopted {
		return nil, decStorageError()
	}
	if _, e = dec.ParseTime(clock.Largest); e != nil {
		return nil, e
	}
	snapshot.Prior.ClockGuard = clock.Largest
	snapshot.Catalog, e = readDecCatalog(ctx, q, d)
	if e != nil {
		return nil, e
	}
	snapshot.Prior.CatalogBase64 = base64.StdEncoding.EncodeToString(snapshot.Catalog.Raw)
	if e = readDecAdmissions(ctx, q, snapshot); e != nil {
		return nil, e
	}
	if e = readDecWater(ctx, q, snapshot); e != nil {
		return nil, e
	}
	var provider decSelectedProvider
	e = q.QueryRowContext(ctx, `SELECT provider_kind,person_key,device_key,lease_id FROM dec_signers WHERE network_id=? AND context_id=?`, id, d.ContextID).Scan(&provider.Kind, &provider.Person, &provider.Device, &provider.Lease)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	if e == nil {
		if provider.Person != n.Own.Person || !dec.ValidPublicKey(provider.Person) || provider.Kind != "original" && provider.Kind != "device" || provider.Kind == "original" && (provider.Device != "-" || provider.Lease != "-") || provider.Kind == "device" && (!dec.ValidPublicKey(provider.Device) || !dec.ValidID(provider.Lease, "ds_")) {
			return nil, decStorageError()
		}
		snapshot.Provider = &provider
		if provider.Kind == "device" {
			var seed any
			var created string
			err := q.QueryRowContext(ctx, `SELECT seed,created_at FROM link_device_keys WHERE public_key=?`, provider.Device).Scan(&seed, &created)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			if err == nil {
				if value, ok := seed.([]byte); ok {
					snapshot.DeviceSeed = append([]byte{}, value...)
				}
				if _, e = dec.ParseTime(created); e != nil {
					snapshot.DeviceSeed = nil
				}
			}
		}
	}
	if e = readDecDelivery(ctx, q, snapshot); e != nil {
		return nil, e
	}
	if e = readDecFences(ctx, q, snapshot); e != nil {
		return nil, e
	}
	snapshot.Fingerprint, e = decSnapshotFingerprint(ctx, q, id, d.ContextID)
	if e != nil {
		return nil, e
	}
	snapshot.PriorRaw, e = json.Marshal(snapshot.Prior)
	if e != nil {
		return nil, e
	}
	return snapshot, nil
}

func (s *Store) decentralizedProjection(ctx context.Context, id, now string) (*decSnapshot, *dec.Projection, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, nil, e
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, id)
	_ = tx.Rollback()
	if e != nil {
		return nil, nil, e
	}
	projection, e := verifyDecSnapshot(snapshot, now)
	return snapshot, projection, e
}
func verifyDecSnapshot(snapshot *decSnapshot, now string) (*dec.Projection, error) {
	projection, e := dec.Project(snapshot.Descriptor, snapshot.PriorRaw, []byte("-"), now, "read")
	if e != nil {
		return nil, e
	}
	if e = validateDecOrigin(snapshot, now); e != nil {
		return nil, e
	}
	return projection, nil
}

func validateDecOrigin(s *decSnapshot, now string) error {
	pin := s.Context
	if pin.Origin == "genesis" {
		root := s.Catalog.Proofs[pin.OriginProof]
		if root == nil {
			return &dec.Failure{Code: "proof_required", RequiredIDs: []string{pin.OriginProof}}
		}
		if root.ID != pin.InitialRoot || root.Kind != "root_state" || root.Root.Epoch != 0 || root.Root.Key != s.Descriptor.GenesisRootPublicKey || root.Root.Migration != "-" || len(root.Root.Predecessors) != 0 {
			return decStorageError()
		}
		for _, object := range s.Catalog.Objects {
			if object.ID == pin.OriginProof && object.Kind == "root_state" {
				return nil
			}
		}
		return decStorageError()
	}
	for _, migration := range s.Catalog.Migrations {
		if dec.ProofID("migration", migration.Raw) != pin.OriginProof {
			continue
		}
		result, e := dec.VerifyMigration(s.Descriptor, []byte(`"-"`), []byte(`"-"`), migration.Raw, now, "evidence", "-")
		if e != nil {
			return e
		}
		if result.ProposalID != pin.Proposal || result.RootStateID != pin.InitialRoot {
			return decStorageError()
		}
		return nil
	}
	return &dec.Failure{Code: "proof_required", RequiredIDs: []string{pin.OriginProof}}
}

func readDecFences(ctx context.Context, q dbQuerier, s *decSnapshot) error {
	s.Fenced = []string{}
	rows, e := q.QueryContext(ctx, `SELECT proposal_id,record FROM dec_migrations WHERE network_id=? ORDER BY proposal_id`, s.Descriptor.NetworkID)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw string
		var record decMigrationRecord
		if e = rows.Scan(&id, &raw); e != nil {
			return e
		}
		if e = dec.ReadPrivateRecord([]byte(raw), "format context_id state proposal_base64 source_catalog_base64 source_state_base64 prepared_catalog_base64 initial_root_state_base64 acknowledgments_base64 commit_base64 migration_base64 local_acknowledgment_base64 root_intent_ids local_ack_intent_id approved fenced publication_started", &record); e != nil {
			return e
		}
		if record.Format != 1 || !dec.ValidID(id, "ds_") || !dec.ValidID(record.Context, "ctx_") || record.Acknowledgments == nil || record.RootIntents == nil || len(record.RootIntents) > 4096 || len(record.Acknowledgments) > 4096 {
			return decStorageError()
		}
		switch record.State {
		case "needs_approvals", "prepared", "acknowledged", "adopted", "conflict":
		default:
			return decStorageError()
		}
		seen := map[string]bool{}
		for _, intent := range record.RootIntents {
			if !decLocalID(intent, "dint_") || seen[intent] {
				return decStorageError()
			}
			seen[intent] = true
		}
		if record.AckIntent != "-" && !decLocalID(record.AckIntent, "dint_") {
			return decStorageError()
		}
		for _, encoded := range []struct {
			value string
			max   int
		}{{record.Proposal, dec.MaxObject}, {record.SourceCatalog, dec.MaxCatalog}, {record.SourceState, dec.MaxPayload}, {record.PreparedCatalog, dec.MaxCatalog}, {record.InitialRoot, dec.MaxObject}, {record.Commit, dec.MaxObject}, {record.Migration, dec.MaxObject}, {record.LocalAck, dec.MaxObject}} {
			if encoded.value != "-" {
				if _, e = decBytes(encoded.value, encoded.max); e != nil {
					return e
				}
			}
		}
		for _, ack := range record.Acknowledgments {
			if _, e = decBytes(ack, dec.MaxObject); e != nil {
				return e
			}
		}
		if record.Fenced {
			if !record.Approved || record.LocalAck == "-" || record.Proposal == "-" {
				return decStorageError()
			}
			proposalRaw, _ := decBytes(record.Proposal, dec.MaxObject)
			proposal, e := dec.ReadStatement(s.Descriptor, proposalRaw)
			if e != nil {
				return e
			}
			ackRaw, _ := decBytes(record.LocalAck, dec.MaxObject)
			ack, e := dec.ReadStatement(s.Descriptor, ackRaw)
			if e != nil {
				return e
			}
			if proposal.ID != id || proposal.Kind != "migration_proposal" || ack.Kind != "migration_ack" || ack.Signer("host") != s.Network.Own.Host {
				return decStorageError()
			}
			var pin struct {
				Proposal string `json:"proposal_id"`
			}
			if json.Unmarshal(ack.Payload, &pin) != nil || pin.Proposal != id {
				return decStorageError()
			}
			if record.State != "adopted" {
				s.Fenced = append(s.Fenced, id)
			}
		} else if record.State == "acknowledged" || record.State == "adopted" {
			return decStorageError()
		}
	}
	return rows.Err()
}

// The fingerprint is private concurrency metadata, never a signed public head.
// It covers exact authority/provenance/selection/fence bytes and their SQLite
// storage classes. Final writers compare it inside their own write transaction.
func decSnapshotFingerprint(ctx context.Context, q dbQuerier, id, contextID string) (string, error) {
	h := sha256.New()
	queries := []struct {
		sql  string
		args []any
	}{
		{`SELECT id,record,root_seed FROM networks WHERE id=?`, []any{id}},
		{`SELECT record FROM dec_contexts WHERE network_id=? AND context_id=?`, []any{id, contextID}},
		{`SELECT proof_id,kind,body FROM dec_objects WHERE network_id=? AND context_id=? ORDER BY proof_id`, []any{id, contextID}},
		{`SELECT statement_id,record FROM dec_admissions WHERE network_id=? AND context_id=? ORDER BY statement_id`, []any{id, contextID}},
		{`SELECT restriction_id,record FROM dec_restrictions WHERE network_id=? AND context_id=? ORDER BY restriction_id`, []any{id, contextID}},
		{`SELECT activation_id,request_id,record FROM dec_activations WHERE network_id=? AND context_id=? ORDER BY activation_id`, []any{id, contextID}},
		{`SELECT stream_kind,subject,subject2,record FROM dec_heads WHERE network_id=? AND context_id=? ORDER BY stream_kind,subject,subject2`, []any{id, contextID}},
		{`SELECT stream_kind,subject,subject2,version,record FROM dec_highwater WHERE network_id=? AND context_id=? ORDER BY stream_kind,subject,subject2`, []any{id, contextID}},
		{`SELECT provider_kind,person_key,device_key,lease_id FROM dec_signers WHERE network_id=? AND context_id=?`, []any{id, contextID}},
		{`SELECT record FROM dec_clock WHERE network_id=?`, []any{id}},
		{`SELECT proposal_id,record FROM dec_migrations WHERE network_id=? ORDER BY proposal_id`, []any{id}},
		{`SELECT k.public_key,k.seed,k.created_at FROM link_device_keys k JOIN dec_signers s ON k.public_key=s.device_key WHERE s.network_id=? AND s.context_id=?`, []any{id, contextID}},
	}
	for _, query := range queries {
		decHashField(h, []byte(query.sql))
		rows, e := q.QueryContext(ctx, query.sql, query.args...)
		if e != nil {
			return "", e
		}
		columns, e := rows.Columns()
		if e != nil {
			rows.Close()
			return "", e
		}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(values))
			for i := range values {
				dest[i] = &values[i]
			}
			if e = rows.Scan(dest...); e != nil {
				rows.Close()
				return "", e
			}
			decHashField(h, []byte("row"))
			for _, v := range values {
				switch v := v.(type) {
				case nil:
					decHashField(h, []byte("null"))
				case string:
					decHashField(h, []byte("text"))
					decHashField(h, []byte(v))
				case []byte:
					decHashField(h, []byte("blob"))
					decHashField(h, v)
				case int64:
					decHashField(h, []byte("integer"))
					decHashField(h, []byte(fmt.Sprint(v)))
				default:
					rows.Close()
					return "", decStorageError()
				}
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func decHashField(h hash.Hash, b []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(b)))
	h.Write(length[:])
	h.Write(b)
}

func decLocalID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+32 {
		return false
	}
	raw, e := hex.DecodeString(value[len(prefix):])
	return e == nil && hex.EncodeToString(raw) == value[len(prefix):]
}
