package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type decIntentProvider struct {
	Kind   string `json:"kind"`
	Signer string `json:"signer_public_key"`
	Format string `json:"signature_format"`
	Lease  string `json:"lease_id"`
}
type decIntentTemplate struct {
	Slot     uint64 `json:"slot_id"`
	Type     string `json:"object_type"`
	Template string `json:"template_base64"`
}
type decIntentSignature struct {
	Slot      uint64 `json:"slot_id"`
	Role      string `json:"role"`
	Signature string `json:"signature"`
}
type decIntentRecord struct {
	Format     uint64               `json:"format"`
	Operation  string               `json:"operation_id"`
	Approved   bool                 `json:"approved"`
	ApprovedAt string               `json:"approved_at"`
	Review     string               `json:"review_base64"`
	Provider   decIntentProvider    `json:"provider"`
	Root       string               `json:"root_state_id"`
	Person     string               `json:"person_public_key"`
	Host       string               `json:"host_public_key"`
	Device     string               `json:"device_public_key"`
	Scopes     uint64               `json:"scopes"`
	NotAfter   string               `json:"not_after"`
	Created    string               `json:"created_at"`
	Expires    string               `json:"expires_at"`
	Templates  []decIntentTemplate  `json:"templates"`
	Signatures []decIntentSignature `json:"signatures"`
	Completed  bool                 `json:"completed"`
	Terminal   string               `json:"terminal"`
	Result     string               `json:"result_base64"`
}
type decIntent struct {
	ID, Network, Context, Kind string
	Record                     decIntentRecord
	Secret                     []byte
}

const decIntentFields = "format operation_id approved approved_at review_base64 provider root_state_id person_public_key host_public_key device_public_key scopes not_after created_at expires_at templates signatures completed terminal result_base64"

func validateDecIntent(record *decIntentRecord) error {
	r := record
	if r.Result != "-" {
		if _, e := decBytes(r.Result, 32<<20); e != nil {
			return e
		}
		if r.Terminal != "applied" || !r.Completed || !r.Approved {
			return decStorageError()
		}
	}
	if len(r.Signatures) > 0 && !r.Approved {
		return decStorageError()
	}
	if r.Format != 1 || r.Templates == nil || r.Signatures == nil || len(r.Templates) > 4096 || len(r.Signatures) > 4096 || r.Scopes > 15 || r.Root != "-" && !dec.ValidID(r.Root, "ds_") || r.Person != "-" && !dec.ValidPublicKey(r.Person) || r.Host != "-" && !dec.ValidPublicKey(r.Host) || r.Device != "-" && !dec.ValidPublicKey(r.Device) {
		return decStorageError()
	}
	switch r.Terminal {
	case "-", "applied", "cancelled", "expired":
	default:
		return decStorageError()
	}
	if _, e := dec.ParseTime(r.Created); e != nil {
		return e
	}
	if _, e := dec.ParseTime(r.Expires); e != nil {
		return e
	}
	if r.Expires <= r.Created {
		return decStorageError()
	}
	if r.Approved {
		if _, e := dec.ParseTime(r.ApprovedAt); e != nil {
			return e
		}
		if r.ApprovedAt < r.Created {
			return decStorageError()
		}
	} else if r.ApprovedAt != "-" {
		return decStorageError()
	}
	if r.NotAfter != "-" {
		if _, e := dec.ParseTime(r.NotAfter); e != nil {
			return e
		}
	}
	if r.Review != "-" {
		if _, e := decBytes(r.Review, 1<<20); e != nil {
			return e
		}
	}
	p := r.Provider
	if p.Kind != "original" && p.Kind != "device" && p.Kind != "root" && p.Kind != "requester" && p.Kind != "host" || !dec.ValidPublicKey(p.Signer) || p.Format != "ed25519" && p.Format != "sshsig" || p.Kind == "device" && (p.Format != "ed25519" || !dec.ValidID(p.Lease, "ds_")) || p.Kind == "original" && (p.Format != "sshsig" || p.Lease != "-") || (p.Kind == "root" || p.Kind == "requester" || p.Kind == "host") && p.Lease != "-" || (p.Kind == "requester" || p.Kind == "host") && p.Format != "ed25519" {
		return decStorageError()
	}
	for i, t := range r.Templates {
		if t.Slot != uint64(i+1) {
			return decStorageError()
		}
		switch t.Type {
		case "selection_packet", "commit_packet", "owner_offer_packet", "admin_lease", "person_lease", "host_lease", "binding_lease", "device_lease", "administrator_packet", "owner_finalization_packet", "root_state", "policy", "group", "admin_withdraw", "person_remove", "host_revoke", "host_unbind", "device_revoke", "migration_proposal", "migration_ack", "migration_commit":
		default:
			return decStorageError()
		}
		if t.Template != "-" {
			if _, e := decBytes(t.Template, dec.MaxObject); e != nil {
				return e
			}
		}
	}
	last := decIntentSignature{}
	for _, signature := range r.Signatures {
		if signature.Slot < 1 || signature.Slot > uint64(len(r.Templates)) || signature.Role == "" || signature.Signature == "-" || signature.Slot < last.Slot || signature.Slot == last.Slot && signature.Role <= last.Role {
			return decStorageError()
		}
		last = signature
	}
	return nil
}
func readDecIntent(ctx context.Context, q dbQuerier, id string) (decIntent, error) {
	var result decIntent
	result.ID = id
	if !decLocalID(id, "dint_") {
		return result, decFailure("invalid")
	}
	var raw string
	var secret any
	e := q.QueryRowContext(ctx, `SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?`, id).Scan(&result.Network, &result.Context, &result.Kind, &raw, &secret)
	if errors.Is(e, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if e != nil {
		return result, e
	}
	if e = dec.ReadPrivateRecord([]byte(raw), decIntentFields, &result.Record); e != nil {
		return result, e
	}
	if e = validateDecIntent(&result.Record); e != nil {
		return result, e
	}
	switch result.Kind {
	case "owner", "administrator", "create", "action", "policy_claim", "root_transition", "migration", "migration_identity", "selection", "requester_commit":
	default:
		return result, decStorageError()
	}
	if (result.Record.Provider.Kind == "requester") != requesterDecIntent(result.Kind) || requesterDecIntent(result.Kind) && secret != nil {
		return result, decStorageError()
	}
	if !decHostSelectorAllowed(result) {
		return result, decStorageError()
	}
	if result.Network != "-" && !dec.ValidID(result.Network, "net_") || result.Context != "-" && !dec.ValidID(result.Context, "ctx_") {
		return result, decStorageError()
	}
	if result.Record.Result != "-" && result.Kind != "create" && result.Kind != "action" && result.Kind != "root_transition" {
		return result, decStorageError()
	}
	if result.Record.Terminal == "applied" && (result.Kind == "create" || result.Kind == "action" || result.Kind == "root_transition") && result.Record.Result == "-" {
		return result, decStorageError()
	}
	if secret != nil {
		raw, ok := secret.([]byte)
		if !ok || len(raw) != 32 || result.Kind != "create" && result.Kind != "root_transition" && result.Kind != "migration_identity" || result.Record.Terminal == "applied" {
			return result, decStorageError()
		}
		result.Secret = append([]byte{}, raw...)
	}
	if result.Kind == "migration_identity" {
		if _, e = readDecMigrationIdentityIntent(result); e != nil {
			return result, e
		}
	}
	if statementDecIntent(result.Kind) {
		completed, e := decStatementIntentCompleted(ctx, q, result)
		if e != nil {
			return result, e
		}
		if result.Record.Completed != completed {
			return result, decStorageError()
		}
	}
	if ceremonyDecIntent(result.Kind) {
		completed, e := decCeremonyIntentCompleted(ctx, q, result)
		if e != nil {
			return result, e
		}
		if result.Record.Completed != completed {
			return result, decStorageError()
		}
	}
	if requesterDecIntent(result.Kind) {
		complete, e := decRequesterIntentComplete(ctx, q, result)
		if e != nil {
			return result, e
		}
		if complete != result.Record.Completed {
			return result, decStorageError()
		}
	}
	return result, nil
}
func storeDecIntent(ctx context.Context, tx *sql.Tx, i decIntent, insert bool) error {
	if (i.Record.Provider.Kind == "requester") != requesterDecIntent(i.Kind) {
		return decStorageError()
	}
	if !decHostSelectorAllowed(i) {
		return decStorageError()
	}
	if i.Kind == "migration_identity" {
		if _, e := readDecMigrationIdentityIntent(i); e != nil {
			return e
		}
	}
	if requesterDecIntent(i.Kind) {
		complete, e := decRequesterIntentComplete(ctx, tx, i)
		if e != nil {
			return e
		}
		i.Record.Completed = complete
	}
	if statementDecIntent(i.Kind) {
		completed, e := decStatementIntentCompleted(ctx, tx, i)
		if e != nil {
			return e
		}
		i.Record.Completed = completed
	}
	if ceremonyDecIntent(i.Kind) {
		completed, e := decCeremonyIntentCompleted(ctx, tx, i)
		if e != nil {
			return e
		}
		i.Record.Completed = completed
	}
	if i.Secret != nil && (len(i.Secret) != 32 || (i.Kind != "create" && i.Kind != "root_transition" && i.Kind != "migration_identity") || i.Record.Terminal == "applied") {
		return decStorageError()
	}
	if i.Record.Result != "-" && i.Kind != "create" && i.Kind != "action" && i.Kind != "root_transition" {
		return decStorageError()
	}
	if e := validateDecIntent(&i.Record); e != nil {
		return e
	}
	raw, e := json.Marshal(i.Record)
	if e != nil {
		return e
	}
	if len(raw) > dec.MaxPrivateRecord {
		return decFailure("quota_exceeded")
	}
	var secret any
	if i.Secret != nil {
		secret = i.Secret
	}
	if insert {
		_, e = tx.ExecContext(ctx, `INSERT INTO dec_intents(intent_id,network_id,context_id,kind,record,secret) VALUES(?,?,?,?,?,?)`, i.ID, i.Network, i.Context, i.Kind, string(raw), secret)
	} else {
		_, e = tx.ExecContext(ctx, `UPDATE dec_intents SET record=?,secret=? WHERE intent_id=? AND network_id=? AND context_id=? AND kind=?`, string(raw), secret, i.ID, i.Network, i.Context, i.Kind)
	}
	return e
}

// The migration host selector is possession of this exact own unbound-host
// contribution, never a generic authority provider or arbitrary signing key.
func decHostSelectorAllowed(i decIntent) bool {
	if i.Kind == "migration_identity" {
		return i.Record.Provider.Kind == "host"
	}
	if i.Record.Provider.Kind != "host" {
		return true
	}
	r := i.Record
	return i.Kind == "migration" && i.Secret == nil && dec.ValidID(r.Operation, "ds_") && dec.ValidID(r.Root, "ds_") && r.Provider == (decIntentProvider{"host", r.Host, "ed25519", "-"}) && r.Person == "-" && r.Device == "-" && r.Scopes == 0 && r.Result == "-" && r.Terminal == "-" && len(r.Templates) == 1 && (r.Templates[0].Type == "host_lease" || r.Templates[0].Type == "migration_ack") && migrationHostSignaturesOnly(r.Signatures)
}

func migrationHostSignaturesOnly(signatures []decIntentSignature) bool {
	for _, sig := range signatures {
		if sig.Slot != 1 || sig.Role != "host" {
			return false
		}
	}
	return true
}
func decIntentCapacity(ctx context.Context, tx *sql.Tx) error {
	rows, e := tx.QueryContext(ctx, `SELECT record FROM dec_intents ORDER BY intent_id`)
	if e != nil {
		return e
	}
	defer rows.Close()
	total, active := 0, 0
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return e
		}
		total++
		if total > 4096 {
			return decFailure("quota_exceeded")
		}
		var r decIntentRecord
		if e = dec.ReadPrivateRecord([]byte(raw), decIntentFields, &r); e != nil {
			return e
		}
		if e = validateDecIntent(&r); e != nil {
			return e
		}
		if !r.Completed && r.Terminal == "-" {
			active++
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if total >= 4096 || active >= 64 {
		return decFailure("quota_exceeded")
	}
	return nil
}

type DecSigningRequest struct {
	Intent   string `json:"intent_id"`
	Slot     uint64 `json:"slot_id"`
	Type     string `json:"object_type"`
	Object   string `json:"object_id"`
	Role     string `json:"role"`
	Public   string `json:"public_key"`
	Format   string `json:"format"`
	Template string `json:"template_base64"`
	Message  string `json:"message_base64"`
}

func decFilledTemplate(d dec.Descriptor, i decIntent, slot decIntentTemplate) (*dec.Statement, []byte, error) {
	if slot.Template == "-" {
		return nil, nil, decFailure("proof_required")
	}
	raw, e := decBytes(slot.Template, dec.MaxObject)
	if e != nil {
		return nil, nil, e
	}
	filled := map[string]string{}
	for _, signature := range i.Record.Signatures {
		if signature.Slot == slot.Slot {
			filled[signature.Role] = signature.Signature
		}
	}
	raw, e = dec.FillStatementTemplate(d, raw, filled)
	if e != nil {
		return nil, nil, e
	}
	statement, e := dec.ReadStatementTemplate(d, raw)
	if e != nil {
		return nil, nil, e
	}
	if statement.Kind != slot.Type {
		return nil, nil, decStorageError()
	}
	return statement, raw, nil
}
func decIntentStatements(d dec.Descriptor, i decIntent) ([]*dec.Statement, [][]byte, error) {
	statements := []*dec.Statement{}
	bodies := [][]byte{}
	for _, slot := range i.Record.Templates {
		statement, raw, e := decFilledTemplate(d, i, slot)
		if e != nil {
			return nil, nil, e
		}
		statements = append(statements, statement)
		bodies = append(bodies, raw)
	}
	return statements, bodies, nil
}
func decSlotSignature(i decIntent, slot uint64, role string) string {
	for _, signature := range i.Record.Signatures {
		if signature.Slot == slot && signature.Role == role {
			return signature.Signature
		}
	}
	return "-"
}
func addDecSignature(i *decIntent, signature decIntentSignature) error {
	old := decSlotSignature(*i, signature.Slot, signature.Role)
	if old != "-" {
		if old != signature.Signature {
			return decFailure("operation_conflict")
		}
		return nil
	}
	i.Record.Signatures = append(i.Record.Signatures, signature)
	sort.Slice(i.Record.Signatures, func(a, b int) bool {
		x, y := i.Record.Signatures[a], i.Record.Signatures[b]
		return x.Slot < y.Slot || x.Slot == y.Slot && x.Role < y.Role
	})
	return nil
}

func statementDecIntent(kind string) bool {
	return kind == "create" || kind == "action" || kind == "policy_claim" || kind == "root_transition"
}
func decStatementIntentCompleted(ctx context.Context, q dbQuerier, i decIntent) (bool, error) {
	var d dec.Descriptor
	var e error
	if i.Kind == "create" {
		d, _, e = decCreationDescriptor(i)
	} else {
		var raw string
		e = q.QueryRowContext(ctx, `SELECT record FROM dec_contexts WHERE network_id=? AND context_id=?`, i.Network, i.Context).Scan(&raw)
		if e == nil {
			var record decContextRecord
			e = dec.ReadPrivateRecord([]byte(raw), "format descriptor_base64 origin initial_root_state_id origin_proof_id migration_proposal_id adopted_at", &record)
			if e == nil {
				var descriptor []byte
				descriptor, e = decBytes(record.Descriptor, dec.MaxObject)
				if e == nil {
					d, e = dec.ReadDescriptor(descriptor)
				}
			}
		}
	}
	if e != nil {
		return false, e
	}
	if d.ContextID != i.Context || d.NetworkID != i.Network {
		return false, decStorageError()
	}
	complete := len(i.Record.Templates) > 0
	for _, slot := range i.Record.Templates {
		if slot.Template == "-" {
			complete = false
			for _, signature := range i.Record.Signatures {
				if signature.Slot == slot.Slot {
					return false, decStorageError()
				}
			}
			continue
		}
		statement, _, e := decFilledTemplate(d, i, slot)
		if e != nil {
			return false, e
		}
		if !decActionComplete(statement) {
			complete = false
		}
	}
	return complete, nil
}
