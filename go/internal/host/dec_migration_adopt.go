package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecMigrationAdoption struct {
	Proposal string `json:"proposal_id"`
	Commit   string `json:"commit_id"`
	Approve  bool   `json:"approve"`
}

type DecMigrationAdoptionResult struct {
	Migration DecMigrationView `json:"migration"`
	Network   *DecNetworkView  `json:"network"`
}

// Only a previously signed legacy final commitment blocks the cutover fence.
// Unsigned/cancelled preparation cannot acquire authority by being in this list.
func migrationLegacyPending(ctx context.Context, q dbQuerier, network string) ([]string, error) {
	rows, e := q.QueryContext(ctx, `SELECT p.request_id,p.record,COALESCE(o.locally_applied,0) FROM link_pending p LEFT JOIN link_operations o ON p.request_id=o.request_id ORDER BY p.request_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id, raw string
		var applied int
		if e = rows.Scan(&id, &raw, &applied); e != nil {
			return nil, e
		}
		record, e := decodeLinkRecord([]byte(raw))
		if e != nil {
			return nil, e
		}
		if record.CommitPacketBase64 == "-" || applied == 1 {
			continue
		}
		actual := record.ExpectedNetworkID
		if record.NetworkBase64 != "-" {
			var descriptor struct {
				Network string `json:"network_id"`
			}
			if json.Unmarshal(mustDecBytes(record.NetworkBase64), &descriptor) != nil || !dec.ValidID(descriptor.Network, "net_") {
				return nil, decStorageError()
			}
			if actual != "-" && actual != descriptor.Network {
				return nil, decStorageError()
			}
			actual = descriptor.Network
		}
		if actual == network {
			ids = append(ids, id)
		}
		if len(ids) > 4096 {
			return nil, decFailure("quota_exceeded")
		}
	}
	return ids, rows.Err()
}

func migrationLegacyPrior(source *decMigrationSource, r decMigrationRecord, proposal string, pending []string) ([]byte, error) {
	return json.Marshal(dec.LegacyPrior{Format: 1, Descriptor: base64.StdEncoding.EncodeToString(source.Legacy), Catalog: base64.StdEncoding.EncodeToString(source.Catalog), Feature: source.Feature, Epoch: source.Facts.Epoch, Root: source.Facts.RootPublicKey, Source: base64.StdEncoding.EncodeToString(source.State), ClockGuard: source.Time, Pending: pending, Proposal: proposal, Prepared: decMigrationHash(mustDecBytes(r.PreparedCatalog)), Acknowledgment: r.LocalAck, AdoptedContext: "-", AdoptedProposal: "-"})
}

// Local consent is durable private state. Even a correctly signed public ACK
// cannot manufacture this machine's approved typed intent or selected tuple.
func (s *Store) checkMigrationLocalAcknowledgment(ctx context.Context, q dbQuerier, d dec.Descriptor, prefix *decMigrationPrefix, r decMigrationRecord, own DecMigrationRoster) (*dec.Statement, error) {
	proposal := prefix.Proposal.ID
	if !r.Approved || !r.Fenced || r.LocalAck == "-" || r.AckIntent == "-" {
		return nil, decFailure("review_required")
	}
	i, e := readDecIntent(ctx, q, r.AckIntent)
	if e != nil {
		return nil, e
	}
	if i.Network != d.NetworkID || i.Context != d.ContextID || i.Kind != "migration" || !i.Record.Approved || !i.Record.Completed || i.Record.Operation != proposal || i.Secret != nil || len(i.Record.Templates) != 1 || i.Record.Templates[0].Type != "migration_ack" {
		return nil, decStorageError()
	}
	statements, bodies, e := decIntentStatements(d, i)
	if e != nil {
		return nil, e
	}
	ack := statements[0]
	if !decActionComplete(ack) || !bytes.Equal(bodies[0], mustDecBytes(r.LocalAck)) || ack.Signer("host") != s.identity.PublicKey {
		return nil, decStorageError()
	}
	var fields struct {
		Proposal    string `json:"proposal_id"`
		Root        string `json:"root_state_id"`
		Prepared    string `json:"prepared_catalog_sha256"`
		Host        string `json:"host_public_key"`
		Person      string `json:"person_public_key"`
		Device      string `json:"device_public_key"`
		HostLease   string `json:"host_lease_id"`
		Binding     string `json:"binding_lease_id"`
		DeviceLease string `json:"device_lease_id"`
		Activation  string `json:"activation_id"`
		At          string `json:"acknowledged_at"`
	}
	if dec.ReadPrivateRecord(ack.Payload, "proposal_id root_state_id prepared_catalog_sha256 host_public_key person_public_key device_public_key host_lease_id binding_lease_id device_lease_id activation_id acknowledged_at", &fields) != nil || fields.Proposal != proposal || fields.Prepared != decMigrationHash(mustDecBytes(r.PreparedCatalog)) || fields.Host != own.Host || fields.Person != own.Person || fields.Device != own.Device || i.Record.Root != fields.Root || i.Record.Host != own.Host || i.Record.Person != own.Person || i.Record.Device != own.Device || i.Record.Scopes != own.Scopes {
		return nil, decStorageError()
	}
	provider := decIntentProvider{"host", own.Host, "ed25519", "-"}
	if own.Person != "-" {
		provider = decIntentProvider{"device", own.Device, "ed25519", fields.DeviceLease}
	}
	if i.Record.Provider != provider {
		return nil, decStorageError()
	}
	var review DecMigrationReview
	if dec.ReadPrivateRecord(mustDecBytes(i.Record.Review), decMigrationReviewFields, &review) != nil {
		return nil, decStorageError()
	}
	want := migrationParticipationReview(d.NetworkID, prefix, r, "acknowledgment")
	want.Warning = review.Warning
	if review.Warning == "" || len(review.Warning) > 1024 || !reflect.DeepEqual(review, want) || fields.At != i.Record.Created || i.Record.Expires != prefix.Fields.Expires {
		return nil, decStorageError()
	}
	return ack, nil
}

func (s *Store) migrationAdoptionEvidence(ctx context.Context, q dbQuerier, network string, input DecMigrationAdoption) (*decMigrationSource, *decMigrationPrefix, decMigrationRecord, *dec.MigrationEvidence, error) {
	source, e := s.decMigrationSource(ctx, q, network)
	if e != nil {
		return nil, nil, decMigrationRecord{}, nil, e
	}
	proposal, r, e := migrationRecord(ctx, q, network)
	if e != nil {
		return nil, nil, r, nil, e
	}
	if proposal != input.Proposal || r.Commit == "-" || r.Migration == "-" {
		return nil, nil, r, nil, decFailure("proof_required", input.Commit)
	}
	prefix, e := readMigrationPrefix(source.Descriptor, migrationRecordEvidence(r))
	if e != nil {
		return nil, nil, r, nil, e
	}
	commit, e := dec.ReadStatement(source.Descriptor, mustDecBytes(r.Commit))
	if e != nil {
		return nil, nil, r, nil, e
	}
	if commit.ID != input.Commit || prefix.Proposal.ID != proposal || r.Context != source.Descriptor.ContextID || r.State == "conflict" {
		return nil, nil, r, nil, decFailure("state_conflict")
	}
	if source.Facts.RootPublicKey != prefix.Fields.Root || source.Facts.Epoch != prefix.Fields.Epoch {
		return nil, nil, r, nil, decFailure("state_conflict")
	}
	if e = s.checkMigrationSourceKnown(ctx, q, source, prefix, migrationRecordEvidence(r)); e != nil {
		return nil, nil, r, nil, e
	}
	if e = s.checkMigrationOwnRoster(ctx, q, source, prefix.Fields.Roster); e != nil {
		return nil, nil, r, nil, e
	}
	var own DecMigrationRoster
	for _, row := range prefix.Fields.Roster {
		if row.Host == s.identity.PublicKey {
			own = row
		}
	}
	if own.Host == "" {
		return nil, nil, r, nil, decFailure("forbidden")
	}
	ack, e := s.checkMigrationLocalAcknowledgment(ctx, q, source.Descriptor, prefix, r, own)
	if e != nil {
		return nil, nil, r, nil, e
	}
	if own.Person != "-" {
		var activationID string
		if json.Unmarshal(ack.Object["activation_id"], &activationID) != nil {
			return nil, nil, r, nil, decStorageError()
		}
		activation := prefix.Catalog.Activations[activationID]
		if activation == nil {
			return nil, nil, r, nil, decFailure("proof_required", activationID)
		}
		p, e := readDecPending(ctx, q, activation.Request.RequestID)
		if e != nil {
			return nil, nil, r, nil, e
		}
		if p.Record.Migration != proposal || p.Record.Terminal != "migration_prepared" || !containsString(p.Record.Roles, "requester") || !p.Record.Selected || !p.Record.Committed || p.Record.ActivationID != activationID || !bytes.Equal(p.Request.Raw, activation.Request.Raw) || !bytes.Equal(mustDecBytes(p.Record.Selection), activation.Selection.Raw) || !bytes.Equal(mustDecBytes(p.Record.Commit), activation.Commit.Raw) {
			return nil, nil, r, nil, decFailure("review_required")
		}
	}
	pending, e := migrationLegacyPending(ctx, q, network)
	if e != nil {
		return nil, nil, r, nil, e
	}
	legacy, e := migrationLegacyPrior(source, r, proposal, pending)
	if e != nil {
		return nil, nil, r, nil, e
	}
	evidence, e := dec.VerifyMigration(source.Descriptor, legacy, []byte(`"-"`), mustDecBytes(r.Migration), source.Time, "adoption", s.identity.PublicKey)
	if e != nil {
		return nil, nil, r, nil, e
	}
	if evidence.ProposalID != proposal || evidence.PreparedHash != decMigrationHash(mustDecBytes(r.PreparedCatalog)) || prefix.Root == nil || evidence.RootStateID != prefix.Root.ID {
		return nil, nil, r, nil, decFailure("state_conflict")
	}
	// Verify that the first retained composite contains these exact source,
	// prepared, ACK and commit bytes, rather than another unsigned wrapper.
	if _, e = s.decMigrationStatus(ctx, q, network); e != nil {
		return nil, nil, r, nil, e
	}
	return source, prefix, r, evidence, nil
}

func migrationOriginCatalog(d dec.Descriptor, body []byte) ([]byte, error) {
	return json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, []dec.CatalogObject{{ID: dec.ProofID("migration", body), Kind: "migration", BodyBase64: base64.StdEncoding.EncodeToString(body)}}})
}

func (s *Store) adoptedMigrationResult(ctx context.Context, q dbQuerier, network string, input DecMigrationAdoption) (DecMigrationAdoptionResult, bool, error) {
	proposal, r, e := migrationRecord(ctx, q, network)
	if e != nil {
		return DecMigrationAdoptionResult{}, false, e
	}
	if r.State != "adopted" {
		return DecMigrationAdoptionResult{}, false, nil
	}
	d, e := migrationDescriptor(r)
	if e != nil {
		return DecMigrationAdoptionResult{}, true, e
	}
	commit, e := dec.ReadStatement(d, mustDecBytes(r.Commit))
	if e != nil {
		return DecMigrationAdoptionResult{}, true, e
	}
	if proposal != input.Proposal || commit.ID != input.Commit {
		return DecMigrationAdoptionResult{}, true, decFailure("operation_conflict")
	}
	view, e := s.decMigrationStatus(ctx, q, network)
	if e != nil {
		return DecMigrationAdoptionResult{}, true, e
	}
	snapshot, e := s.loadDecSnapshot(ctx, q, network)
	if e != nil {
		return DecMigrationAdoptionResult{}, true, e
	}
	now, e := decCreationClock(ctx, q, network)
	if e != nil {
		return DecMigrationAdoptionResult{}, true, e
	}
	p, e := verifyDecSnapshot(snapshot, now)
	if e != nil {
		return DecMigrationAdoptionResult{}, true, e
	}
	public, e := decNetworkViewPublic(snapshot, p)
	return DecMigrationAdoptionResult{view, &public}, true, e
}

// Whole migration adoption is the only place this staged context becomes active.
// The final write TX reopens actual source/approvals/keys/NOW; no remote prior or
// the earlier per-host transcript can select a provider on its own.
func (s *Store) AdoptDecentralizedMigration(ctx context.Context, network string, input DecMigrationAdoption) (DecMigrationAdoptionResult, error) {
	if !dec.ValidID(network, "net_") || !dec.ValidID(input.Proposal, "ds_") || !dec.ValidID(input.Commit, "ds_") {
		return DecMigrationAdoptionResult{}, decFailure("invalid")
	}
	read, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecMigrationAdoptionResult{}, e
	}
	old, done, e := s.adoptedMigrationResult(ctx, read, network, input)
	if e != nil || done {
		read.Rollback()
		return old, e
	}
	_, _, _, _, e = s.migrationAdoptionEvidence(ctx, read, network, input)
	if e != nil {
		read.Rollback()
		return DecMigrationAdoptionResult{}, e
	}
	view, e := s.decMigrationStatus(ctx, read, network)
	read.Rollback()
	if e != nil {
		return DecMigrationAdoptionResult{}, e
	}
	if !input.Approve {
		return DecMigrationAdoptionResult{Migration: view}, nil
	}
	if e = decBarrier(ctx, "dec.apply.before_transaction", input.Proposal); e != nil {
		return DecMigrationAdoptionResult{}, e
	}
	s.linkMu.Lock()
	s.syncing.Lock()
	applied := false
	result, e := func() (DecMigrationAdoptionResult, error) {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return DecMigrationAdoptionResult{}, e
		}
		defer tx.Rollback()
		result, done, e := s.adoptedMigrationResult(ctx, tx, network, input)
		if e != nil || done {
			return result, e
		}
		source, prefix, r, evidence, e := s.migrationAdoptionEvidence(ctx, tx, network, input)
		if e != nil {
			return result, e
		}
		raw, e := migrationOriginCatalog(source.Descriptor, mustDecBytes(r.Migration))
		if e != nil {
			return result, e
		}
		p, e := dec.Project(source.Descriptor, []byte(`"-"`), raw, source.Time, "repair")
		if e != nil {
			return result, e
		}
		if p.Root.Code != "-" || p.Root.SelectedID != evidence.RootStateID {
			return result, decFailure("state_conflict")
		}
		var existing int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM dec_contexts WHERE network_id=?`, network).Scan(&existing); e != nil {
			return result, e
		}
		if existing != 0 {
			return result, decFailure("state_conflict")
		}
		var own DecMigrationRoster
		for _, row := range prefix.Fields.Roster {
			if row.Host == s.identity.PublicKey {
				own = row
			}
		}
		identity, e := s.migrationIdentityIntent(ctx, tx, network)
		if e != nil {
			return result, e
		}
		if identity == nil {
			return result, decFailure("review_required")
		}
		if own.Person != "-" {
			seed := identity.Secret
			if len(seed) == 0 {
				seed, e = decOwnedDeviceSeed(ctx, tx, own.Device)
				if e != nil {
					return result, e
				}
			}
			if len(seed) != 32 || membership.EncodeKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) != own.Device {
				return result, decFailure("signer_unavailable")
			}
			var held []byte
			e = tx.QueryRowContext(ctx, `SELECT seed FROM link_device_keys WHERE public_key=?`, own.Device).Scan(&held)
			if errors.Is(e, sql.ErrNoRows) {
				if _, e = tx.ExecContext(ctx, `INSERT INTO link_device_keys(public_key,seed,created_at) VALUES(?,?,?)`, own.Device, seed, identity.Record.Created); e != nil {
					return result, e
				}
			} else if e != nil {
				return result, e
			} else if !bytes.Equal(held, seed) {
				return result, decStorageError()
			}
		}
		identity.Secret = nil
		identity.Record.Terminal = "applied"
		if e = storeDecIntent(ctx, tx, *identity, false); e != nil {
			return result, e
		}
		n := decNetworkRecord{2, "decentralized", base64.StdEncoding.EncodeToString(source.Descriptor.Raw), r.Context, evidence.RootStateID, decOwnIdentity{own.Member, own.Person, own.Host}, source.Time}
		networkRaw, e := json.Marshal(n)
		if e != nil {
			return result, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE networks SET record=? WHERE id=?`, string(networkRaw), network); e != nil {
			return result, e
		}
		pin := decContextRecord{1, n.Descriptor, "migration", evidence.RootStateID, dec.ProofID("migration", mustDecBytes(r.Migration)), input.Proposal, source.Time}
		if e = putDecRecord(ctx, tx, "dec_contexts", "network_id,context_id", []any{network, r.Context}, pin); e != nil {
			return result, e
		}
		before := emptyDecSnapshot(source.Descriptor, n, pin)
		key, e := migrationRootSeed(ctx, tx, network, prefix.Fields.Root)
		if e != nil {
			return result, e
		}
		if key != nil {
			before.RootSeed = key.Seed()
		}
		if e = s.storeDecProjection(ctx, tx, before, p); e != nil {
			return result, e
		}
		if own.Person != "-" {
			ack, e := dec.ReadStatement(source.Descriptor, mustDecBytes(r.LocalAck))
			if e != nil {
				return result, e
			}
			var deviceID string
			if json.Unmarshal(ack.Object["device_lease_id"], &deviceID) != nil {
				return result, decStorageError()
			}
			// Selection records this host's exact reviewed cutover identity. It
			// is not an admission or current-power assertion: an expired prepared
			// D stays selected and unavailable, so repair/renew keeps the same
			// owned key rather than inferring an absent/original provider.
			if _, e = tx.ExecContext(ctx, `INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?,?,'device',?,?,?)`, network, r.Context, own.Person, own.Device, deviceID); e != nil {
				return result, e
			}
		}
		ids, e := decPendingIDs(ctx, tx)
		if e != nil {
			return result, e
		}
		for _, id := range ids {
			pending, e := readDecPending(ctx, tx, id)
			if e != nil {
				return result, e
			}
			if pending.Record.Migration != input.Proposal {
				continue
			}
			var activation *dec.ParsedActivation
			for _, candidate := range prefix.Catalog.Activations {
				if candidate.Request.RequestID == id {
					activation = candidate
					break
				}
			}
			// Other incomplete attempts remain evidence, without being mislabeled
			// as an adopted operation or blocking unrelated complete roster work.
			if activation == nil {
				continue
			}
			if pending.Record.Network != network || pending.Record.Context != r.Context || !bytes.Equal(pending.Request.Raw, activation.Request.Raw) || containsString(pending.Record.Roles, "requester") && (!pending.Record.Selected || !pending.Record.Committed) {
				return result, decFailure("state_conflict")
			}
			for _, item := range []struct {
				old    string
				packet *dec.Packet
			}{{pending.Record.Owner, activation.Owner}, {pending.Record.Selection, activation.Selection}, {pending.Record.Administrator, activation.Administrator}, {pending.Record.Finalization, activation.Finalization}, {pending.Record.Commit, activation.Commit}} {
				if item.old == "-" {
					continue
				}
				actual, e := dec.ReadPacket(source.Descriptor, mustDecBytes(item.old))
				if e != nil {
					return result, e
				}
				if item.packet == nil || actual.ID != item.packet.ID {
					return result, decFailure("operation_conflict")
				}
			}
			original := pending.Record
			if e = decCompletePendingFacts(&pending, source.Descriptor, activation, mustDecBytes(r.PreparedCatalog)); e != nil {
				return result, e
			}
			// Keep first received exact packet aliases while filling any missing
			// public facts; their verified semantic IDs above must match.
			for _, item := range []struct {
				old    string
				target *string
			}{{original.Owner, &pending.Record.Owner}, {original.Selection, &pending.Record.Selection}, {original.Administrator, &pending.Record.Administrator}, {original.Finalization, &pending.Record.Finalization}, {original.Commit, &pending.Record.Commit}} {
				if item.old != "-" {
					*item.target = item.old
				}
			}
			pending.Record.Terminal = "migration_adopted"
			pending.Secret = nil
			pending.TerminalCap = nil
			pending.Record.Outbound = []decOutboundFrame{}
			pending.Frames = map[string]*dec.Frame{}
			if _, e = tx.ExecContext(ctx, `DELETE FROM dec_frames WHERE request_id=?`, id); e != nil {
				return result, e
			}
			if e = putDecPending(ctx, tx, pending); e != nil {
				return result, e
			}
		}
		r.State = "adopted"
		if e = storeDecMigration(ctx, tx, network, input.Proposal, r, false); e != nil {
			return result, e
		}
		if e = s.queueDecProofs(ctx, tx, before, p); e != nil {
			return result, e
		}
		if e = appendEvent(ctx, tx, "network.migrated", network, source.Time); e != nil {
			return result, e
		}
		latest, e := decCreationClock(ctx, tx, network)
		if e != nil {
			return result, e
		}
		if _, e = dec.DecisionTime(latest, source.Time); e != nil {
			return result, e
		}
		// Re-run against the same original empty new-context prior: freshly
		// inserted rows must not become historical admissions for this check.
		if latest != source.Time {
			current, e := dec.Project(source.Descriptor, []byte(`"-"`), raw, latest, "repair")
			if e != nil {
				return result, e
			}
			a, e := p.AdmittedPrior()
			if e != nil {
				return result, e
			}
			b, e := current.AdmittedPrior()
			if e != nil {
				return result, e
			}
			a.ClockGuard, b.ClockGuard = "-", "-"
			left, _ := json.Marshal(a)
			right, _ := json.Marshal(b)
			if !bytes.Equal(left, right) {
				return result, decFailure("authority_expired")
			}
			if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
				return result, e
			}
		}
		result, done, e = s.adoptedMigrationResult(ctx, tx, network, input)
		if e != nil || !done {
			if e == nil {
				e = decStorageError()
			}
			return result, e
		}
		if e = tx.Commit(); e != nil {
			return result, e
		}
		applied = true
		return result, nil
	}()
	s.syncing.Unlock()
	s.linkMu.Unlock()
	if e == nil && applied {
		e = decBarrier(ctx, "dec.apply.after_commit", input.Proposal)
	}
	return result, e
}
