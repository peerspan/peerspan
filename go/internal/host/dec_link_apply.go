package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type decOperationRecord struct {
	Format     uint64 `json:"format"`
	Activation string `json:"activation_base64"`
	Catalog    string `json:"catalog_base64"`
	Outcome    string `json:"outcome_packet_base64"`
	Applied    string `json:"applied_at"`
}
type decParticipantOutcome struct {
	Outcome    json.RawMessage `json:"outcome"`
	Activation json.RawMessage `json:"activation"`
	Catalog    json.RawMessage `json:"catalog"`
}

func decPendingActivation(p decPending) ([]byte, *dec.Catalog, *dec.ParsedActivation, error) {
	if p.Record.Commit == "-" || p.Record.Owner == "-" || p.Record.Selection == "-" || p.Record.Finalization == "-" || p.Record.Catalog == "-" {
		return nil, nil, nil, decFailure("proof_required", p.ID)
	}
	packets := []*dec.Packet{}
	for _, body := range []string{p.Record.Owner, p.Record.Selection, p.Record.Administrator, p.Record.Finalization, p.Record.Commit} {
		if body == "-" {
			packets = append(packets, nil)
			continue
		}
		raw, e := decBytes(body, dec.MaxObject)
		if e != nil {
			return nil, nil, nil, e
		}
		packet, e := dec.ReadPacket(p.Descriptor, raw)
		if e != nil {
			return nil, nil, nil, e
		}
		packets = append(packets, packet)
	}
	raw, e := decBytes(p.Record.Catalog, dec.MaxCatalog)
	if e != nil {
		return nil, nil, nil, e
	}
	catalog, e := dec.ReadCatalog(p.Descriptor, raw)
	if e != nil {
		return nil, nil, nil, e
	}
	// Preserve the actual enclosing activation bytes chosen at commit/receive;
	// reconstructing its wrapper would change DP across language serializers.
	for _, object := range catalog.Objects {
		if object.Kind != "activation" {
			continue
		}
		parsed, e := dec.ReadActivation(p.Descriptor, object.Body)
		if e != nil {
			return nil, nil, nil, e
		}
		if parsed.ID != p.Record.ActivationID || parsed.ManifestID != p.Record.ManifestID {
			continue
		}
		actual := []*dec.Packet{parsed.Owner, parsed.Selection, parsed.Administrator, parsed.Finalization, parsed.Commit}
		matches := true
		for i, packet := range packets {
			if (packet == nil) != (actual[i] == nil) || packet != nil && !bytes.Equal(packet.Raw, actual[i].Raw) {
				matches = false
				break
			}
		}
		if matches {
			return object.Body, catalog, parsed, nil
		}
	}
	return nil, nil, nil, decStorageError()
}

func decLinkContext(d dec.Descriptor, catalog *dec.Catalog, now string) (decContextRecord, error) {
	var pin decContextRecord
	for _, migration := range catalog.Migrations {
		origin, e := dec.VerifyMigration(d, []byte(`"-"`), []byte(`"-"`), migration.Raw, now, "evidence", "-")
		if e != nil {
			return pin, e
		}
		candidate := decContextRecord{1, base64.StdEncoding.EncodeToString(d.Raw), "migration", origin.RootStateID, dec.ProofID("migration", migration.Raw), origin.ProposalID, now}
		if pin.Origin != "" && (pin.InitialRoot != candidate.InitialRoot || pin.OriginProof != candidate.OriginProof) {
			return pin, decFailure("state_conflict")
		}
		pin = candidate
	}
	if pin.Origin != "" {
		return pin, nil
	}
	for _, object := range catalog.Objects {
		if object.Kind != "root_state" {
			continue
		}
		root := catalog.Proofs[object.ID]
		if root == nil || root.Root == nil || root.Root.Epoch != 0 || len(root.Root.Predecessors) != 0 || root.Root.Migration != "-" || root.Root.Key != d.GenesisRootPublicKey {
			continue
		}
		return decContextRecord{1, base64.StdEncoding.EncodeToString(d.Raw), "genesis", root.ID, object.ID, "-", now}, nil
	}
	return pin, decFailure("proof_required")
}

func emptyDecSnapshot(d dec.Descriptor, n decNetworkRecord, pin decContextRecord) *decSnapshot {
	raw, _ := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, []dec.CatalogObject{}})
	catalog, _ := dec.ReadCatalog(d, raw)
	return &decSnapshot{Network: n, Context: pin, Descriptor: d, Catalog: catalog, Prior: dec.Prior{Format: 1, ContextID: d.ContextID, AdmittedStatements: []string{}, AdmittedRestrictions: []string{}, AdmittedActivations: []string{}, RootHeads: []string{}, Maxima: []dec.Maximum{}, Migration: pin.Proposal, ClockGuard: "-"}, PriorRaw: []byte(`"-"`), FloorProofs: map[string][]string{}}
}

func decManifestString(a *dec.ParsedActivation, name string) string {
	var value string
	_ = json.Unmarshal(a.Manifest[name], &value)
	return value
}

// The fully signed request is durable before this function is entered. Apply
// reopens the actual latest private state and clock after the before-TX barrier.
func (s *Store) applyStoredDecLink(ctx context.Context, id string) error {
	p, e := s.readDecPendingSnapshot(ctx, id)
	if e != nil {
		return e
	}
	if p.Record.Terminal == "applied" {
		_, e = s.retainedDecOutcome(ctx, p.Descriptor, p.ID, "-")
		return e
	}
	activation, _, parsed, e := decPendingActivation(p)
	if e != nil {
		return e
	}
	if p.Record.Migration != "-" {
		return s.prepareStoredDecMigrationLink(ctx, id)
	}
	if e = decBarrier(ctx, "dec.apply.before_transaction", id); e != nil {
		return e
	}
	s.linkMu.Lock()
	s.syncing.Lock()
	applied, sealedOutcome := false, false
	e = func() error {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		current, e := readDecPending(ctx, tx, id)
		if e != nil {
			return e
		}
		if current.Record.Terminal == "applied" {
			return nil
		}
		if current.Record.Commit != p.Record.Commit || current.Record.ManifestID != p.Record.ManifestID || current.Record.ActivationID != p.Record.ActivationID || current.Record.Catalog != p.Record.Catalog {
			return decFailure("operation_conflict")
		}
		now, e := decCreationClock(ctx, tx, p.Descriptor.NetworkID)
		if e != nil {
			return e
		}
		_, e = s.applyDecParticipant(ctx, tx, &current, activation, parsed, now)
		if e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		applied = true
		sealedOutcome = len(current.Record.Outbound) > 0
		return nil
	}()
	s.syncing.Unlock()
	s.linkMu.Unlock()
	if e == nil && sealedOutcome {
		e = decBarrier(ctx, "dec.frame.after_commit", id)
	}
	if e == nil && applied {
		e = decBarrier(ctx, "dec.apply.after_commit", id)
	}
	return e
}

func (s *Store) applyDecParticipant(ctx context.Context, tx *sql.Tx, p *decPending, activation []byte, parsed *dec.ParsedActivation, now string) (decParticipantOutcome, error) {
	var result decParticipantOutcome
	if parsed.Request.RequestID != p.ID || !bytes.Equal(parsed.Request.Raw, p.Request.Raw) || p.Record.Migration != "-" {
		return result, decFailure("operation_conflict")
	}
	participant := parsed.Request.Writer == s.identity.PublicKey || parsed.Owner.Writer == s.identity.PublicKey || parsed.Administrator != nil && parsed.Administrator.Writer == s.identity.PublicKey
	if !participant {
		return result, decFailure("forbidden")
	}
	requester := parsed.Request.Writer == s.identity.PublicKey
	if requester && (!p.Record.Selected || !p.Record.Committed || !bytes.Equal(parsed.Selection.Raw, mustDecBytes(p.Record.Selection)) || !bytes.Equal(parsed.Commit.Raw, mustDecBytes(p.Record.Commit))) {
		return result, decFailure("review_required")
	}
	var count int
	if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM dec_operations WHERE network_id=?`, p.Descriptor.NetworkID).Scan(&count); e != nil {
		return result, e
	}
	if count >= 4096 {
		return result, decFailure("quota_exceeded")
	}
	catalogRaw, e := decBytes(p.Record.Catalog, dec.MaxCatalog)
	if e != nil {
		return result, e
	}
	catalog, e := dec.ReadCatalog(p.Descriptor, catalogRaw)
	if e != nil {
		return result, e
	}
	old, e := s.loadDecSnapshot(ctx, tx, p.Descriptor.NetworkID)
	newNetwork := errors.Is(e, ErrNotFound)
	prior := []byte(`"-"`)
	if !newNetwork {
		if e != nil {
			return result, e
		}
		if !bytes.Equal(old.Descriptor.Raw, p.Descriptor.Raw) {
			return result, decFailure("state_conflict")
		}
		if len(old.Fenced) > 0 {
			return result, decFailure("migration_pending", old.Fenced...)
		}
		if _, e = verifyDecSnapshot(old, now); e != nil {
			return result, e
		}
		prior = old.PriorRaw
		catalog, e = dec.UnionCatalog(p.Descriptor, old.Catalog, catalog)
		if e != nil {
			return result, e
		}
	} else if !requester {
		return result, decFailure("recovery_required")
	}
	evidence, e := dec.VerifyActivation(p.Descriptor, prior, catalog.Raw, activation, []byte(`"-"`), now)
	if e != nil {
		return result, e
	}
	if evidence.ActivationID != p.Record.ActivationID || evidence.ManifestID != p.Record.ManifestID {
		return result, decFailure("operation_conflict")
	}
	projection, e := dec.Project(p.Descriptor, prior, catalog.Raw, now, "repair")
	if e != nil {
		return result, e
	}
	if projection.Root.Code != "-" {
		return result, decFailure(projection.Root.Code, projection.Root.RequiredIDs...)
	}
	person := parsed.Owner.Person
	if requester {
		if _, e = decOwnedDeviceSeed(ctx, tx, p.Record.Device); e != nil {
			return result, e
		}
		member, e := decCurrentMember(projection, s.identity.PublicKey)
		if e != nil {
			return result, e
		}
		if member.BindingError != nil {
			return result, member.BindingError
		}
		if member.View.Person != person || member.View.Binding != decManifestString(parsed, "binding_lease_id") {
			return result, decFailure("forbidden")
		}
		if old != nil {
			old.Network.Own = decOwnIdentity{member.View.Member, person, s.identity.PublicKey}
		}
	}
	if newNetwork {
		pin, e := decLinkContext(p.Descriptor, catalog, now)
		if e != nil {
			return result, e
		}
		var ownerTerms decOwnerTerms
		if json.Unmarshal(parsed.Owner.Payload, &ownerTerms) != nil {
			return result, decStorageError()
		}
		network := decNetworkRecord{2, "decentralized", base64.StdEncoding.EncodeToString(p.Descriptor.Raw), p.Descriptor.ContextID, projection.Root.SelectedID, decOwnIdentity{ownerTerms.Member, person, s.identity.PublicKey}, now}
		old = emptyDecSnapshot(p.Descriptor, network, pin)
		if e = s.creationNameConflict(ctx, tx, p.Descriptor.Name); e != nil {
			return result, e
		}
		raw, _ := json.Marshal(network)
		if _, e = tx.ExecContext(ctx, `INSERT INTO networks(id,record,root_seed) VALUES(?,?,NULL)`, p.Descriptor.NetworkID, string(raw)); e != nil {
			return result, e
		}
		if e = putDecRecord(ctx, tx, "dec_contexts", "network_id,context_id", []any{p.Descriptor.NetworkID, p.Descriptor.ContextID}, pin); e != nil {
			return result, e
		}
	}
	catalog, e = decCatalogWithActivation(p.Descriptor, catalog, activation)
	if e != nil {
		return result, e
	}
	projection, e = dec.Project(p.Descriptor, prior, catalog.Raw, now, "repair")
	if e != nil {
		return result, e
	}
	plan, e := s.planDecProofs(ctx, tx, old, projection)
	if e != nil {
		return result, e
	}
	// Fold every applicable current packet path before the final clock read;
	// no new signatures or mutable authority are produced by that pure work.
	ceiling, e := projection.ActivationDeadline(parsed)
	if e != nil {
		return result, e
	}
	if e = s.storeDecProjection(ctx, tx, old, projection); e != nil {
		return result, e
	}
	if requester {
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?,?,'device',?,?,?) ON CONFLICT(network_id,context_id) DO UPDATE SET provider_kind=excluded.provider_kind,person_key=excluded.person_key,device_key=excluded.device_key,lease_id=excluded.lease_id`, p.Descriptor.NetworkID, p.Descriptor.ContextID, person, p.Record.Device, evidence.DeviceLeaseID); e != nil {
			return result, e
		}
	}
	if e = plan.store(ctx, tx); e != nil {
		return result, e
	}
	finalNow, e := decCreationClock(ctx, tx, p.Descriptor.NetworkID)
	if e != nil {
		return result, e
	}
	if ceiling != "-" && finalNow >= ceiling {
		return result, decFailure("authority_expired")
	}
	now = finalNow
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, p.Descriptor.NetworkID, string(clock)); e != nil {
		return result, e
	}
	activationHash := sha256.Sum256(activation)
	payload, _ := json.Marshal(struct {
		Context    string `json:"context_id"`
		Request    string `json:"request_id"`
		Manifest   string `json:"manifest_id"`
		Activation string `json:"activation_id"`
		Hash       string `json:"activation_sha256"`
		Root       string `json:"observed_root_state_id"`
		At         string `json:"applied_at"`
	}{p.Descriptor.ContextID, p.ID, evidence.ManifestID, evidence.ActivationID, hex.EncodeToString(activationHash[:]), projection.Root.SelectedID, now})
	template, e := dec.PacketTemplate(p.Descriptor, p.Descriptor.ContextID, p.ID, "outcome", s.identity.PublicKey, "-", "-", "-", "-", payload)
	if e != nil {
		return result, e
	}
	outcome, e := dec.ReadPacketTemplate(p.Descriptor, template)
	if e != nil {
		return result, e
	}
	raw, e := dec.FillPacketTemplate(p.Descriptor, template, map[string]string{"host": base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, outcome.Message))})
	if e != nil {
		return result, e
	}
	outcome, e = dec.ReadPacket(p.Descriptor, raw)
	if e != nil {
		return result, e
	}
	record := decOperationRecord{1, base64.StdEncoding.EncodeToString(activation), base64.StdEncoding.EncodeToString(catalog.Raw), base64.StdEncoding.EncodeToString(outcome.Raw), now}
	stored, _ := json.Marshal(record)
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_operations(network_id,context_id,request_id,activation_id,manifest_id,record,locally_applied) VALUES(?,?,?,?,?,?,1)`, p.Descriptor.NetworkID, p.Descriptor.ContextID, p.ID, evidence.ActivationID, evidence.ManifestID, string(stored)); e != nil {
		return result, e
	}
	// Seal only the terminal outcome while the original secret still exists.
	// Then remove every decryptable nonterminal frame in the same apply TX.
	if len(p.Secret) == 16 && now < p.Deadline {
		if e = s.queueDecStage(ctx, tx, p, outcome, nil, now); e != nil {
			return result, e
		}
		p.TerminalCap, e = dec.FrameReadCapability(p.Secret)
		if e != nil {
			return result, e
		}
	}
	frames := map[string]*dec.Frame{}
	outbound := []decOutboundFrame{}
	for _, entry := range p.Record.Outbound {
		if entry.Role == "outcome" && entry.Writer == s.identity.PublicKey {
			outbound = append(outbound, entry)
			key := decFrameKey(entry.Role, entry.Writer, entry.ID)
			frames[key] = p.Frames[key]
		}
	}
	if len(outbound) == 0 {
		p.TerminalCap = nil
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM dec_frames WHERE request_id=? AND role!='outcome'`, p.ID); e != nil {
		return result, e
	}
	if len(outbound) == 0 {
		if _, e = tx.ExecContext(ctx, `DELETE FROM dec_frames WHERE request_id=?`, p.ID); e != nil {
			return result, e
		}
	}
	p.Secret = nil
	p.Frames = frames
	p.Record.Outbound = outbound
	if requester {
		for _, id := range []string{p.Record.SelectionIntent, p.Record.CommitIntent} {
			intent, e := readDecIntent(ctx, tx, id)
			if e != nil {
				return result, e
			}
			if !intent.Record.Completed {
				return result, decStorageError()
			}
			intent.Record.Terminal = "applied"
			if e = storeDecIntent(ctx, tx, intent, false); e != nil {
				return result, e
			}
		}
	}
	p.Record.Terminal = "applied"
	p.Record.Outcome = record.Outcome
	p.Record.Catalog = record.Catalog
	if e = putDecPending(ctx, tx, *p); e != nil {
		return result, e
	}
	if e = appendEvent(ctx, tx, "network.link_applied", p.Descriptor.NetworkID, now); e != nil {
		return result, e
	}
	return decParticipantOutcome{outcome.Raw, activation, catalog.Raw}, nil
}

func mustDecBytes(body string) []byte { raw, _ := base64.StdEncoding.DecodeString(body); return raw }

func (s *Store) retainedDecOutcome(ctx context.Context, d dec.Descriptor, id, caller string) (decParticipantOutcome, error) {
	var result decParticipantOutcome
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	var activationID, manifestID, recordRaw string
	var locally int
	e = tx.QueryRowContext(ctx, `SELECT activation_id,manifest_id,record,locally_applied FROM dec_operations WHERE network_id=? AND context_id=? AND request_id=?`, d.NetworkID, d.ContextID, id).Scan(&activationID, &manifestID, &recordRaw, &locally)
	if errors.Is(e, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if e != nil {
		return result, e
	}
	var record decOperationRecord
	if locally != 1 || dec.ReadPrivateRecord([]byte(recordRaw), "format activation_base64 catalog_base64 outcome_packet_base64 applied_at", &record) != nil || record.Format != 1 {
		return result, decStorageError()
	}
	activation, e := decBytes(record.Activation, dec.MaxObject)
	if e != nil {
		return result, e
	}
	parsed, e := dec.ReadActivation(d, activation)
	if e != nil {
		return result, e
	}
	participant := func(key string) bool {
		return key == parsed.Request.Writer || key == parsed.Owner.Writer || parsed.Administrator != nil && key == parsed.Administrator.Writer
	}
	if !participant(s.identity.PublicKey) || caller != "-" && !participant(caller) {
		return result, decFailure("forbidden")
	}
	if parsed.ID != activationID || parsed.ManifestID != manifestID || parsed.Request.RequestID != id {
		return result, decStorageError()
	}
	catalog, e := decBytes(record.Catalog, dec.MaxCatalog)
	if e != nil {
		return result, e
	}
	if _, e = dec.ReadCatalog(d, catalog); e != nil {
		return result, e
	}
	outcomeRaw, e := decBytes(record.Outcome, dec.MaxObject)
	if e != nil {
		return result, e
	}
	outcome, e := dec.ReadPacket(d, outcomeRaw)
	if e != nil {
		return result, e
	}
	var fields struct {
		Context    string `json:"context_id"`
		Request    string `json:"request_id"`
		Manifest   string `json:"manifest_id"`
		Activation string `json:"activation_id"`
		Hash       string `json:"activation_sha256"`
		Root       string `json:"observed_root_state_id"`
		At         string `json:"applied_at"`
	}
	if json.Unmarshal(outcome.Payload, &fields) != nil {
		return result, decStorageError()
	}
	hash := sha256.Sum256(activation)
	if outcome.Role != "outcome" || outcome.Writer != s.identity.PublicKey || outcome.RequestID != id || fields.Context != d.ContextID || fields.Request != id || fields.Manifest != manifestID || fields.Activation != activationID || fields.Hash != hex.EncodeToString(hash[:]) || fields.At != record.Applied {
		return result, decStorageError()
	}
	if _, e = dec.ParseTime(record.Applied); e != nil {
		return result, e
	}
	return decParticipantOutcome{outcome.Raw, activation, catalog}, nil
}
