package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

const decMigrationFields = "format context_id state proposal_base64 source_catalog_base64 source_state_base64 prepared_catalog_base64 initial_root_state_base64 acknowledgments_base64 commit_base64 migration_base64 local_acknowledgment_base64 root_intent_ids local_ack_intent_id approved fenced publication_started"

type DecMigrationView struct {
	Network      string   `json:"network_id"`
	Proposal     string   `json:"proposal_id"`
	Context      string   `json:"context_id"`
	State        string   `json:"state"`
	SourceHash   string   `json:"source_catalog_sha256"`
	StateHash    string   `json:"source_state_sha256"`
	PreparedHash string   `json:"prepared_catalog_sha256"`
	Root         string   `json:"root_state_id"`
	LocalAck     string   `json:"local_acknowledgment_id"`
	Commit       string   `json:"root_commit_id"`
	Missing      []string `json:"missing_host_keys"`
	Required     []string `json:"required_proof_ids"`
	Approved     bool     `json:"approved"`
	Fenced       bool     `json:"fenced"`
	Expires      string   `json:"expires_at"`
}

func emptyDecMigrationView(network string) DecMigrationView {
	return DecMigrationView{Network: network, Proposal: "-", Context: "-", State: "needs_approvals", SourceHash: "-", StateHash: "-", PreparedHash: "-", Root: "-", LocalAck: "-", Commit: "-", Missing: []string{}, Required: []string{}, Expires: "-"}
}
func decMigrationHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Store) DecentralizedMigrationStatus(ctx context.Context, network string) (DecMigrationView, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return emptyDecMigrationView(network), e
	}
	defer tx.Rollback()
	return s.decMigrationStatus(ctx, tx, network)
}

func (s *Store) decMigrationStatus(ctx context.Context, tx dbQuerier, network string) (DecMigrationView, error) {
	view := emptyDecMigrationView(network)
	if !dec.ValidID(network, "net_") {
		return view, decFailure("invalid")
	}
	var e error
	var networkRaw string
	if e = tx.QueryRowContext(ctx, `SELECT record FROM networks WHERE id=?`, network).Scan(&networkRaw); errors.Is(e, sql.ErrNoRows) {
		return view, ErrNotFound
	} else if e != nil {
		return view, e
	}
	var tag struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal([]byte(networkRaw), &tag) != nil {
		return view, decStorageError()
	}
	rows, e := tx.QueryContext(ctx, `SELECT proposal_id,record FROM dec_migrations WHERE network_id=? ORDER BY proposal_id`, network)
	if e != nil {
		return view, e
	}
	var proposalID, recordRaw string
	count := 0
	for rows.Next() {
		if e = rows.Scan(&proposalID, &recordRaw); e != nil {
			rows.Close()
			return view, e
		}
		count++
		if count > 1 {
			rows.Close()
			return view, decFailure("state_conflict")
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return view, e
	}
	if count == 0 {
		if tag.Mode == "decentralized" {
			return view, decFailure("invalid")
		}
		// Verify the actual source before describing an eligible legacy network.
		// This does not fix its source bytes, generate keys or advance its clock.
		_, e = s.decMigrationSource(ctx, tx, network)
		return view, e
	}
	var d dec.Descriptor
	if tag.Mode == "decentralized" {
		_, d, _, e = readDecNetwork(ctx, tx, network, s.identity.PublicKey)
	} else {
		var n Network
		n, e = scanNetwork(tx.QueryRowContext(ctx, networkColumns+" WHERE id=?", network))
		if e == nil {
			var raw []byte
			raw, e = json.Marshal(dec.Descriptor{Format: 1, Protocol: dec.Protocol, NetworkID: n.ID, Name: n.Name, GenesisRootPublicKey: n.RootPublicKey})
			if e == nil {
				d, e = dec.ReadDescriptor(raw)
			}
		}
	}
	if e != nil {
		return view, e
	}
	var r decMigrationRecord
	if e = dec.ReadPrivateRecord([]byte(recordRaw), decMigrationFields, &r); e != nil {
		return view, e
	}
	if r.Format != 1 || !dec.ValidID(proposalID, "ds_") || r.Context != d.ContextID || r.Acknowledgments == nil || r.RootIntents == nil || len(r.Acknowledgments) > 4096 || len(r.RootIntents) > 4096 {
		return view, decStorageError()
	}
	switch r.State {
	case "needs_approvals", "prepared", "acknowledged", "adopted", "conflict":
	default:
		return view, decStorageError()
	}
	view.Proposal, view.Context, view.State, view.Approved, view.Fenced = proposalID, r.Context, r.State, r.Approved, r.Fenced
	var proposal *dec.Statement
	if r.Proposal != "-" {
		raw, e := decBytes(r.Proposal, dec.MaxObject)
		if e != nil {
			return view, e
		}
		proposal, e = dec.ReadStatement(d, raw)
		if e != nil {
			return view, e
		}
	}
	seenIntents := map[string]bool{}
	for _, id := range r.RootIntents {
		if seenIntents[id] {
			return view, decStorageError()
		}
		seenIntents[id] = true
		i, e := readDecIntent(ctx, tx, id)
		if e != nil {
			return view, e
		}
		if i.Kind != "migration" || i.Network != network || i.Context != d.ContextID {
			return view, decStorageError()
		}
		for _, slot := range i.Record.Templates {
			if slot.Type != "migration_proposal" || slot.Template == "-" {
				continue
			}
			statement, _, e := decFilledTemplate(d, i, slot)
			if e != nil {
				return view, e
			}
			if proposal == nil {
				proposal = statement
			} else if proposal.ID != statement.ID {
				return view, decStorageError()
			}
		}
	}
	if proposal == nil || proposal.Kind != "migration_proposal" || proposal.ID != proposalID {
		return view, decFailure("proof_required", proposalID)
	}
	var fields struct {
		Legacy     string `json:"legacy_descriptor_base64"`
		Feature    string `json:"legacy_feature_id"`
		Epoch      uint64 `json:"legacy_epoch"`
		Key        string `json:"legacy_root_public_key"`
		SourceHash string `json:"source_catalog_sha256"`
		StateHash  string `json:"source_state_sha256"`
		Issued     string `json:"issued_at"`
		Expires    string `json:"expires_at"`
		Roster     []struct {
			Host string `json:"host_public_key"`
		} `json:"roster"`
	}
	if json.Unmarshal(proposal.Payload, &fields) != nil || proposal.Signer("issuer") != fields.Key {
		return view, decStorageError()
	}
	legacy, e := decBytes(fields.Legacy, dec.MaxObject)
	if e != nil {
		return view, e
	}
	source, e := decBytes(r.SourceCatalog, 512<<10)
	if e != nil {
		return view, e
	}
	state, e := decBytes(r.SourceState, dec.MaxPayload)
	if e != nil {
		return view, e
	}
	if decMigrationHash(source) != fields.SourceHash || decMigrationHash(state) != fields.StateHash {
		return view, decStorageError()
	}
	if _, _, e = dec.VerifyMigrationSourceSnapshot(d, legacy, source, state, fields.Epoch, fields.Feature, fields.Key, fields.Issued); e != nil {
		return view, e
	}
	view.SourceHash, view.StateHash, view.Expires = fields.SourceHash, fields.StateHash, fields.Expires
	if r.InitialRoot != "-" {
		raw, e := decBytes(r.InitialRoot, dec.MaxObject)
		if e != nil {
			return view, e
		}
		root, e := dec.ReadStatement(d, raw)
		if e != nil {
			return view, e
		}
		if root.Root == nil || root.Root.Migration != proposalID || root.Root.Key != fields.Key || root.Root.Epoch != fields.Epoch {
			return view, decStorageError()
		}
		view.Root = root.ID
	}
	if r.PreparedCatalog != "-" {
		raw, e := decBytes(r.PreparedCatalog, dec.MaxCatalog)
		if e != nil {
			return view, e
		}
		if _, e = dec.ReadCatalog(d, raw); e != nil {
			return view, e
		}
		view.PreparedHash = decMigrationHash(raw)
	}
	acks := map[string]string{}
	allAcks := append([]string{}, r.Acknowledgments...)
	if r.LocalAck != "-" {
		allAcks = append(allAcks, r.LocalAck)
	}
	for _, encoded := range allAcks {
		raw, e := decBytes(encoded, dec.MaxObject)
		if e != nil {
			return view, e
		}
		ack, e := dec.ReadStatement(d, raw)
		if e != nil {
			return view, e
		}
		var pin struct {
			Proposal string `json:"proposal_id"`
			Hash     string `json:"prepared_catalog_sha256"`
		}
		if json.Unmarshal(ack.Payload, &pin) != nil || ack.Kind != "migration_ack" || pin.Proposal != proposalID || pin.Hash != view.PreparedHash {
			return view, decStorageError()
		}
		host := ack.Signer("host")
		found := false
		for _, row := range fields.Roster {
			found = found || row.Host == host
		}
		if !found {
			return view, decStorageError()
		}
		if old, ok := acks[host]; ok && old != ack.ID {
			return view, decStorageError()
		}
		acks[host] = ack.ID
		if encoded == r.LocalAck {
			if host != s.identity.PublicKey {
				return view, decStorageError()
			}
			view.LocalAck = ack.ID
		}
	}
	for _, row := range fields.Roster {
		if acks[row.Host] == "" {
			view.Missing = append(view.Missing, row.Host)
		}
	}
	if r.Fenced && (!r.Approved || view.LocalAck == "-") || !r.Fenced && (r.State == "acknowledged" || r.State == "adopted") {
		return view, decStorageError()
	}
	if r.Commit != "-" {
		raw, e := decBytes(r.Commit, dec.MaxObject)
		if e != nil {
			return view, e
		}
		commit, e := dec.ReadStatement(d, raw)
		if e != nil {
			return view, e
		}
		var pin struct {
			Proposal string `json:"proposal_id"`
			Hash     string `json:"prepared_catalog_sha256"`
		}
		if json.Unmarshal(commit.Payload, &pin) != nil || commit.Kind != "migration_commit" || pin.Proposal != proposalID || pin.Hash != view.PreparedHash || commit.Signer("issuer") != fields.Key {
			return view, decStorageError()
		}
		view.Commit = commit.ID
	}
	if r.Migration != "-" {
		raw, e := decBytes(r.Migration, dec.MaxObject)
		if e != nil {
			return view, e
		}
		now, e := decCreationClock(ctx, tx, network)
		if e != nil {
			return view, e
		}
		evidence, e := dec.VerifyMigration(d, []byte(`"-"`), []byte(`"-"`), raw, now, "evidence", s.identity.PublicKey)
		if e != nil {
			return view, e
		}
		if evidence.ProposalID != proposalID || evidence.PreparedHash != view.PreparedHash || evidence.RootStateID != view.Root {
			return view, decStorageError()
		}
		var original struct {
			Format          uint64            `json:"format"`
			Proposal        json.RawMessage   `json:"proposal"`
			Source          string            `json:"source_catalog_base64"`
			State           string            `json:"source_state_base64"`
			Prepared        string            `json:"prepared_catalog_base64"`
			Acknowledgments []json.RawMessage `json:"acknowledgments"`
			Commit          json.RawMessage   `json:"commit"`
		}
		if dec.ReadPrivateRecord(raw, "format proposal source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments commit", &original) != nil || original.Source != r.SourceCatalog || original.State != r.SourceState || original.Prepared != r.PreparedCatalog || !bytes.Equal(bytes.TrimSpace(original.Proposal), bytes.TrimSpace(mustDecBytes(r.Proposal))) || !bytes.Equal(bytes.TrimSpace(original.Commit), bytes.TrimSpace(mustDecBytes(r.Commit))) || len(original.Acknowledgments) != len(r.Acknowledgments) {
			return view, decStorageError()
		}
		for n, ack := range original.Acknowledgments {
			if !bytes.Equal(bytes.TrimSpace(ack), bytes.TrimSpace(mustDecBytes(r.Acknowledgments[n]))) {
				return view, decStorageError()
			}
		}
	} else if r.State == "adopted" {
		return view, decStorageError()
	}
	if r.State == "adopted" {
		if tag.Mode != "decentralized" {
			return view, decStorageError()
		}
		snapshot, e := s.loadDecSnapshot(ctx, tx, network)
		if e != nil {
			return view, e
		}
		if snapshot.Context.Origin != "migration" || snapshot.Context.Proposal != proposalID {
			return view, decStorageError()
		}
		if migrationOriginsConflict(snapshot.Catalog) {
			// Only independently verified complete origins can affect this view;
			// the original snapshot/state stays immutable for exact export/retry.
			now, e := decNow()
			if e != nil {
				return view, e
			}
			if _, e = verifyDecSnapshot(snapshot, linkTime(now)); e != nil {
				return view, e
			}
			view.State = "conflict"
		}
	}
	return view, nil
}
