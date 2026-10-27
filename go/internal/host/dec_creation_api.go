package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecCreationApproval struct {
	Context string `json:"context_id"`
	Root    string `json:"root_state_id"`
	Person  string `json:"person_public_key"`
	Host    string `json:"host_public_key"`
	Approve bool   `json:"approve"`
}
type DecSignatureBatch struct {
	Intent     string               `json:"intent_id"`
	Signatures []decIntentSignature `json:"signatures"`
}

func validateDecSignatureBatch(input DecSignatureBatch) error {
	if !decLocalID(input.Intent, "dint_") || input.Signatures == nil || len(input.Signatures) < 1 || len(input.Signatures) > 16 {
		return decFailure("invalid")
	}
	last := decIntentSignature{}
	for _, s := range input.Signatures {
		if s.Slot == 0 || s.Role == "" || s.Signature == "" || s.Signature == "-" || s.Slot < last.Slot || s.Slot == last.Slot && s.Role <= last.Role {
			return decFailure("invalid")
		}
		last = s
	}
	return nil
}
func creationIntentIDs(ctx context.Context, q dbQuerier) ([]string, error) {
	rows, e := q.QueryContext(ctx, `SELECT intent_id FROM dec_intents WHERE kind='create' ORDER BY intent_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		if len(ids) >= 4096 {
			return nil, decFailure("quota_exceeded")
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func findDecCreation(ctx context.Context, q dbQuerier, operation string) (decIntent, error) {
	if !dec.ValidID(operation, "create_") {
		return decIntent{}, decFailure("invalid")
	}
	ids, e := creationIntentIDs(ctx, q)
	if e != nil {
		return decIntent{}, e
	}
	var found *decIntent
	for _, id := range ids {
		i, e := readDecIntent(ctx, q, id)
		if e != nil {
			return i, e
		}
		if i.Record.Operation == operation {
			if found != nil {
				return i, decStorageError()
			}
			copy := i
			found = &copy
		}
	}
	if found == nil {
		return decIntent{}, ErrNotFound
	}
	return *found, nil
}
func decCreationClock(ctx context.Context, q dbQuerier, id string) (string, error) {
	now, e := decNow()
	if e != nil {
		return "", e
	}
	guard := "-"
	var raw string
	e = q.QueryRowContext(ctx, `SELECT record FROM dec_clock WHERE network_id=?`, id).Scan(&raw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return "", e
	}
	if e == nil {
		var r decClockRecord
		if e = dec.ReadPrivateRecord([]byte(raw), "format largest_local_time", &r); e != nil {
			return "", e
		}
		if r.Format != 1 {
			return "", decStorageError()
		}
		guard = r.Largest
	}
	return dec.DecisionTime(linkTime(now), guard)
}
func decCreationResponse(s *Store, i decIntent, now string) (json.RawMessage, error) {
	if i.Record.Terminal == "applied" {
		return validateDecCreationResult(i)
	}
	_, review, e := decCreationDescriptor(i)
	if e != nil {
		return nil, e
	}
	requests, e := s.decCreationSigning(i, now)
	if e != nil && dec.Code(e) != "review_required" {
		return nil, e
	}
	if dec.Code(e) == "review_required" {
		requests = []DecSigningRequest{}
	}
	raw, e := json.Marshal(decCreationResult{i.Record.Operation, review, requests, nil, false})
	if e != nil {
		return nil, e
	}
	if len(raw) > 32<<20 {
		return nil, decFailure("quota_exceeded")
	}
	return raw, nil
}
func validateDecCreationResult(i decIntent) (json.RawMessage, error) {
	raw, e := decBytes(i.Record.Result, 32<<20)
	if e != nil {
		return nil, e
	}
	var result decCreationResult
	if e = dec.ReadPrivateRecord(raw, "creation_id review signing_requests network committed", &result); e != nil {
		return nil, e
	}
	d, review, e := decCreationDescriptor(i)
	if e != nil {
		return nil, e
	}
	if i.Record.Terminal != "applied" || !i.Record.Completed || !result.Committed || result.ID != i.Record.Operation || result.Signing == nil || len(result.Signing) != 0 || result.Network == nil || result.Network.Provider == nil {
		return nil, decStorageError()
	}
	a, _ := json.Marshal(review)
	b, _ := json.Marshal(result.Review)
	if !bytes.Equal(a, b) {
		return nil, decStorageError()
	}
	statements, bodies, e := decIntentStatements(d, i)
	if e != nil {
		return nil, e
	}
	catalog, e := decCreationCatalog(d, statements, bodies)
	if e != nil {
		return nil, e
	}
	if _, e = dec.VerifyLocalGenesis(d, catalog, review.Person, review.Host, review.Member, result.Network.Created); e != nil {
		return nil, e
	}
	n := result.Network
	personLease := "-"
	for _, statement := range statements {
		if statement.Kind == "person_lease" {
			personLease = statement.ID
		}
	}
	if n.ID != d.NetworkID || n.Name != d.Name || n.Mode != "decentralized" || n.Context != d.ContextID || n.Genesis != d.GenesisRootPublicKey || n.Root != review.Root || n.RootKey != d.GenesisRootPublicKey || n.RootEpoch != 0 || n.Member != review.Member || n.Person != review.Person || n.Host != review.Host || n.Provider.Kind != "original_person" || n.Provider.Person != review.Person || n.Provider.Host != review.Host || n.Provider.Device != "-" || n.Provider.Lease != personLease || n.Provider.Root != review.Root || n.Provider.Scopes != 15 || n.Provider.NotAfter != review.NotAfter || n.Authority.State != "usable" || n.Authority.NotAfter != review.NotAfter {
		return nil, decStorageError()
	}
	if _, e = dec.ParseTime(n.Created); e != nil || n.Created < i.Record.Created {
		return nil, decStorageError()
	}
	return json.RawMessage(raw), nil
}
func decCreationCatalog(d dec.Descriptor, statements []*dec.Statement, bodies [][]byte) ([]byte, error) {
	objects := []dec.CatalogObject{}
	for index, body := range bodies {
		statement, e := dec.ReadStatement(d, body)
		if e != nil {
			return nil, e
		}
		if statement.ID != statements[index].ID {
			return nil, decStorageError()
		}
		objects = append(objects, dec.CatalogObject{ID: statement.ProofID, Kind: statement.Kind, BodyBase64: base64.StdEncoding.EncodeToString(body)})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID < objects[j].ID })
	return json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, objects})
}
func (s *Store) creationNameConflict(ctx context.Context, q dbQuerier, name string) error {
	rows, e := q.QueryContext(ctx, `SELECT record FROM networks ORDER BY id`)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var tag struct {
			Name       string `json:"name"`
			Mode       string `json:"mode"`
			Descriptor string `json:"descriptor_base64"`
		}
		if e = rows.Scan(&raw); e != nil {
			return e
		}
		if json.Unmarshal([]byte(raw), &tag) != nil {
			return decStorageError()
		}
		if tag.Mode == "decentralized" {
			body, e := decBytes(tag.Descriptor, dec.MaxObject)
			if e != nil {
				return e
			}
			d, e := dec.ReadDescriptor(body)
			if e != nil {
				return e
			}
			tag.Name = d.Name
		} else if tag.Mode != "" {
			return decStorageError()
		}
		if tag.Name == name {
			return decFailure("state_conflict")
		}
	}
	return rows.Err()
}
func (s *Store) PrepareDecentralizedNetwork(ctx context.Context, request DecCreateNetwork) (responseRaw json.RawMessage, returnError error) {
	facts := decCommittedFacts{}
	applyComplete := false
	defer func() {
		if returnError == nil {
			returnError = facts.wait(ctx)
		}
		if returnError == nil && applyComplete {
			responseRaw, returnError = s.applyStoredDecentralizedCreation(ctx, facts.operation)
		}
	}()
	if !membershipValidCreate(request) {
		return nil, decFailure("invalid")
	}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	ids, e := creationIntentIDs(ctx, tx)
	if e != nil {
		return nil, e
	}
	var selected *decIntent
	unresolved := 0
	for _, id := range ids {
		i, e := readDecIntent(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		_, review, e := decCreationDescriptor(i)
		if e != nil {
			return nil, e
		}
		if i.Record.Terminal == "-" {
			unresolved++
		}
		if review.Name == request.Name {
			if review.Member != request.Member || review.Person != request.Person || review.Host != s.identity.PublicKey {
				return nil, decFailure("state_conflict")
			}
			if selected != nil {
				return nil, decStorageError()
			}
			copy := i
			selected = &copy
		}
	}
	if selected != nil && selected.Record.Terminal == "applied" {
		return validateDecCreationResult(*selected)
	}
	freshIntent := selected == nil
	wasApproved, oldSignatures := false, 0
	if selected != nil {
		wasApproved = selected.Record.Approved
		oldSignatures = len(selected.Record.Signatures)
	}
	if selected == nil {
		if unresolved >= 8 {
			return nil, decFailure("quota_exceeded")
		}
		if e = decIntentCapacity(ctx, tx); e != nil {
			return nil, e
		}
		if e = s.creationNameConflict(ctx, tx, request.Name); e != nil {
			return nil, e
		}
		now, e := decNow()
		if e != nil {
			return nil, e
		}
		_, root, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		i, _, e := s.makeDecCreation(request, root, now)
		if e != nil {
			return nil, e
		}
		if e = storeDecIntent(ctx, tx, i, true); e != nil {
			return nil, e
		}
		selected = &i
	}
	i := *selected
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return nil, e
	}
	if request.Approve {
		complete, e := decCreationHasCompleteSignatures(i)
		if e != nil {
			return nil, e
		}
		if !complete {
			if i.Record.Approved {
				if e = decCreationApprovalCurrent(i, now); e != nil {
					return nil, e
				}
			} else if now > i.Record.Expires {
				return nil, decFailure("review_required")
			}
		}
		if !i.Record.Approved {
			i.Record.Approved = true
			i.Record.ApprovedAt = now
		}
	}
	if request.Approve {
		if e = preflightDecCreationOutbox(ctx, tx); e != nil {
			return nil, e
		}
		if e = s.signDecCreationOwned(&i, now); e != nil {
			return nil, e
		}
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return nil, e
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, i.Network, string(clock)); e != nil {
		return nil, e
	}
	response, e := decCreationResponse(s, i, now)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	facts.operation = i.Record.Operation
	applyComplete = request.Approve && i.Record.Completed
	if freshIntent {
		facts.add("dec.intent.after_commit")
	}
	if i.Record.Approved && !wasApproved {
		facts.add("dec.approval.after_commit")
	}
	if len(i.Record.Signatures) > oldSignatures {
		facts.add("dec.signature.after_commit")
	}
	return response, nil
}
func (s *Store) DecentralizedCreation(ctx context.Context, operation string) (json.RawMessage, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	i, e := findDecCreation(ctx, tx, operation)
	if e != nil {
		return nil, e
	}
	if i.Record.Terminal == "applied" {
		return validateDecCreationResult(i)
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return nil, e
	}
	if e = tx.Rollback(); e != nil {
		return nil, e
	}
	return decCreationResponse(s, i, now)
}

func membershipValidCreate(request DecCreateNetwork) bool {
	return membership.ValidLabel(request.Name) && membership.ValidLabel(request.Member) && dec.ValidPublicKey(request.Person)
}

func (s *Store) ApproveDecentralizedCreation(ctx context.Context, operation string, input DecCreationApproval) (responseRaw json.RawMessage, returnError error) {
	facts := decCommittedFacts{}
	applyComplete := false
	defer func() {
		if returnError == nil {
			returnError = facts.wait(ctx)
		}
		if returnError == nil && applyComplete {
			responseRaw, returnError = s.applyStoredDecentralizedCreation(ctx, operation)
		}
	}()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	i, e := findDecCreation(ctx, tx, operation)
	if e != nil {
		return nil, e
	}
	wasApproved, oldApprovedAt, oldSignatures := i.Record.Approved, i.Record.ApprovedAt, len(i.Record.Signatures)
	if input.Context != i.Context || input.Root != i.Record.Root || input.Person != i.Record.Person || input.Host != i.Record.Host {
		return nil, decFailure("invalid")
	}
	if i.Record.Terminal == "applied" {
		return validateDecCreationResult(i)
	}
	if i.Record.Terminal != "-" {
		return nil, decFailure("state_conflict")
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return nil, e
	}
	if !input.Approve {
		return decCreationResponse(s, i, now)
	}
	completeStored, e := decCreationHasCompleteSignatures(i)
	if e != nil {
		return nil, e
	}
	if _, _, _, _, e = s.checkDecCreation(i, now); e != nil {
		return nil, e
	}
	refresh := !i.Record.Approved
	if i.Record.Approved && !completeStored {
		approvalError := decCreationApprovalCurrent(i, now)
		if approvalError != nil && dec.Code(approvalError) != "review_required" {
			return nil, approvalError
		}
		refresh = approvalError != nil
	}
	if refresh {
		i.Record.Approved = true
		i.Record.ApprovedAt = now
	}
	if e = preflightDecCreationOutbox(ctx, tx); e != nil {
		return nil, e
	}
	if e = s.signDecCreationOwned(&i, now); e != nil {
		return nil, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return nil, e
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), i.Network); e != nil {
		return nil, e
	}
	result, e := decCreationResponse(s, i, now)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	facts.operation = i.Record.Operation
	applyComplete = i.Record.Completed
	if i.Record.Approved && (!wasApproved || i.Record.ApprovedAt != oldApprovedAt) {
		facts.add("dec.approval.after_commit")
	}
	if len(i.Record.Signatures) > oldSignatures {
		facts.add("dec.signature.after_commit")
	}
	return result, nil
}
func (s *Store) acceptCreationSignatures(i *decIntent, input DecSignatureBatch, now string) error {
	if input.Intent != i.ID {
		return decFailure("invalid")
	}
	d, _, e := decCreationDescriptor(*i)
	if e != nil {
		return e
	}
	ready := map[string]bool{}
	if i.Record.Terminal != "applied" {
		requests, e := s.decCreationSigning(*i, now)
		if e != nil {
			return e
		}
		for _, request := range requests {
			ready[fmt.Sprint(request.Slot)+"/"+request.Role] = true
		}
	}
	for _, signature := range input.Signatures {
		if signature.Slot < 1 || signature.Slot > uint64(len(i.Record.Templates)) {
			return decFailure("invalid")
		}
		slot := i.Record.Templates[signature.Slot-1]
		templateRaw, e := decBytes(slot.Template, dec.MaxObject)
		if e != nil {
			return e
		}
		template, e := dec.ReadStatementTemplate(d, templateRaw)
		if e != nil {
			return e
		}
		var expected *dec.Signature
		for index := range template.Signatures {
			if template.Signatures[index].Role == signature.Role {
				expected = &template.Signatures[index]
				break
			}
		}
		if expected == nil {
			return decFailure("invalid")
		}
		if e = dec.VerifySignature(expected.PublicKey, expected.Format, dec.SignatureMessage(template.ID, signature.Role, expected.PublicKey), signature.Signature); e != nil {
			return e
		}
		old := decSlotSignature(*i, signature.Slot, signature.Role)
		if old != "-" {
			if old != signature.Signature {
				return decFailure("operation_conflict")
			}
			continue
		}
		if i.Record.Terminal == "applied" {
			return decFailure("operation_conflict")
		}
		if !ready[fmt.Sprint(signature.Slot)+"/"+signature.Role] {
			return decFailure("state_conflict")
		}
		if e = addDecSignature(i, signature); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) creationPrivateAvailability(person string) DecProviderState {
	key, e := membership.DecodeKey(person)
	if e != nil {
		return decUnavailable(decStorageError())
	}
	signer, e := s.renewalSigner(key)
	if e != nil {
		return decUnavailable(decFailure("signer_unavailable"))
	}
	signer.Close()
	return decAvailable()
}
func (s *Store) SignedDecentralizedCreation(ctx context.Context, operation string, input DecSignatureBatch) (json.RawMessage, error) {
	if e := validateDecSignatureBatch(input); e != nil {
		return nil, e
	}
	result, complete, changed, e := s.saveDecCreationSignatures(ctx, operation, input)
	if e != nil {
		return nil, e
	}
	if changed {
		if e = decBarrier(ctx, "dec.signature.after_commit", operation); e != nil {
			return nil, e
		}
	}
	if !complete {
		return result, nil
	}
	return s.applyStoredDecentralizedCreation(ctx, operation)
}

func (s *Store) saveDecCreationSignatures(ctx context.Context, operation string, input DecSignatureBatch) (json.RawMessage, bool, bool, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, false, false, e
	}
	defer tx.Rollback()
	i, e := findDecCreation(ctx, tx, operation)
	if e != nil {
		return nil, false, false, e
	}
	if i.Record.Terminal == "applied" {
		if e = s.acceptCreationSignatures(&i, input, i.Record.Created); e != nil {
			return nil, false, false, e
		}
		result, e := validateDecCreationResult(i)
		return result, false, false, e
	}
	if i.Record.Terminal != "-" {
		return nil, false, false, decFailure("state_conflict")
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return nil, false, false, e
	}
	complete, e := decCreationHasCompleteSignatures(i)
	if e != nil {
		return nil, false, false, e
	}
	if !complete {
		if e = decCreationApprovalCurrent(i, now); e != nil {
			return nil, false, false, e
		}
	}
	if e = preflightDecCreationOutbox(ctx, tx); e != nil {
		return nil, false, false, e
	}
	oldCount := len(i.Record.Signatures)
	if e = s.acceptCreationSignatures(&i, input, now); e != nil {
		return nil, false, false, e
	}
	if _, _, _, _, e = s.checkDecCreation(i, now); e != nil {
		return nil, false, false, e
	}
	complete, e = decCreationHasCompleteSignatures(i)
	if e != nil {
		return nil, false, false, e
	}
	i.Record.Completed = complete
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return nil, false, false, e
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), i.Network); e != nil {
		return nil, false, false, e
	}
	result, e := decCreationResponse(s, i, now)
	if e != nil {
		return nil, false, false, e
	}
	if e = tx.Commit(); e != nil {
		return nil, false, false, e
	}
	return result, complete, len(i.Record.Signatures) > oldCount, nil
}

// The complete fixed signatures survive this boundary. A restart, clock change
// or quota/authority failure cannot regenerate them or pretend local apply ran.
func (s *Store) applyStoredDecentralizedCreation(ctx context.Context, operation string) (json.RawMessage, error) {
	read, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	before, e := findDecCreation(ctx, read, operation)
	if e != nil {
		read.Rollback()
		return nil, e
	}
	if before.Record.Terminal == "applied" {
		read.Rollback()
		return validateDecCreationResult(before)
	}
	now, e := decCreationClock(ctx, read, before.Network)
	if e == nil {
		_, _, _, _, e = s.checkDecCreation(before, now)
	}
	if e == nil {
		var complete bool
		complete, e = decCreationHasCompleteSignatures(before)
		if e == nil && !complete {
			e = decFailure("review_required")
		}
	}
	if rollback := read.Rollback(); e == nil {
		e = rollback
	}
	if e != nil {
		return nil, e
	}
	availability := s.creationPrivateAvailability(before.Record.Person)
	if e = decBarrier(ctx, "dec.apply.before_transaction", operation); e != nil {
		return nil, e
	}
	s.syncing.Lock()
	didApply := false
	result, e := func() (json.RawMessage, error) {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		i, e := findDecCreation(ctx, tx, operation)
		if e != nil {
			return nil, e
		}
		if i.Record.Terminal == "applied" {
			return validateDecCreationResult(i)
		}
		oldRaw, _ := json.Marshal(before.Record)
		currentRaw, _ := json.Marshal(i.Record)
		if !bytes.Equal(oldRaw, currentRaw) || !bytes.Equal(before.Secret, i.Secret) {
			return nil, decFailure("state_conflict")
		}
		if i.Record.Terminal != "-" {
			return nil, decFailure("state_conflict")
		}
		now, e := decCreationClock(ctx, tx, i.Network)
		if e != nil {
			return nil, e
		}
		result, e := s.applyDecCreationTransaction(ctx, tx, i, now, availability)
		if e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
		didApply = true
		return result, nil
	}()
	s.syncing.Unlock()
	if e != nil {
		return nil, e
	}
	if didApply {
		if e = decBarrier(ctx, "dec.apply.after_commit", operation); e != nil {
			return nil, e
		}
	}
	return result, nil
}

func (s *Store) applyDecCreationTransaction(ctx context.Context, tx *sql.Tx, i decIntent, now string, originalAvailability DecProviderState) (json.RawMessage, error) {
	d, review, statements, bodies, e := s.checkDecCreation(i, now)
	if e != nil {
		return nil, e
	}
	complete, e := decCreationHasCompleteSignatures(i)
	if e != nil {
		return nil, e
	}
	if !complete || !i.Record.Approved {
		return nil, decFailure("review_required")
	}
	if e = preflightDecCreationOutbox(ctx, tx); e != nil {
		return nil, e
	}
	catalogRaw, e := decCreationCatalog(d, statements, bodies)
	if e != nil {
		return nil, e
	}
	p, e := dec.VerifyLocalGenesis(d, catalogRaw, review.Person, review.Host, review.Member, now)
	if e != nil {
		return nil, e
	}
	if e = s.creationNameConflict(ctx, tx, d.Name); e != nil {
		return nil, e
	}
	emptyRaw, _ := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, []dec.CatalogObject{}})
	empty, e := dec.ReadCatalog(d, emptyRaw)
	if e != nil {
		return nil, e
	}
	record := decNetworkRecord{2, "decentralized", base64.StdEncoding.EncodeToString(d.Raw), d.ContextID, review.Root, decOwnIdentity{review.Member, review.Person, review.Host}, now}
	raw, e := json.Marshal(record)
	if e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO networks(id,record,root_seed) VALUES(?,?,?)`, d.NetworkID, string(raw), i.Secret); e != nil {
		return nil, e
	}
	rootProof := ""
	for index, statement := range statements {
		if statement.Kind == "root_state" {
			rootProof = dec.ProofID("root_state", bodies[index])
		}
	}
	contextPin := decContextRecord{1, record.Descriptor, "genesis", review.Root, rootProof, "-", now}
	if e = putDecRecord(ctx, tx, "dec_contexts", "network_id,context_id", []any{d.NetworkID, d.ContextID}, contextPin); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_signers(network_id,context_id,provider_kind,person_key,device_key,lease_id) VALUES(?,?,'original',?,'-','-')`, d.NetworkID, d.ContextID, review.Person); e != nil {
		return nil, e
	}
	old := &decSnapshot{Network: record, Context: contextPin, Descriptor: d, Catalog: empty, RootSeed: append([]byte{}, i.Secret...), Prior: dec.Prior{Format: 1, ContextID: d.ContextID, AdmittedStatements: []string{}, AdmittedRestrictions: []string{}, AdmittedActivations: []string{}, RootHeads: []string{}, Maxima: []dec.Maximum{}, Migration: "-", ClockGuard: "-"}, PriorRaw: []byte(`"-"`), FloorProofs: map[string][]string{}}
	if e = s.storeDecProjection(ctx, tx, old, p); e != nil {
		return nil, e
	}
	if e = s.queueDecProofs(ctx, tx, old, p); e != nil {
		return nil, e
	}
	if e = appendEvent(ctx, tx, "network.created", d.NetworkID, now); e != nil {
		return nil, e
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, d.NetworkID)
	if e != nil {
		return nil, e
	}
	current, e := verifyDecSnapshot(snapshot, now)
	if e != nil {
		return nil, e
	}
	view, e := decNetworkViewPublic(snapshot, current)
	if e != nil {
		return nil, e
	}
	view.ProviderState = originalAvailability
	result, e := json.Marshal(decCreationResult{i.Record.Operation, review, []DecSigningRequest{}, &view, true})
	if e != nil {
		return nil, e
	}
	if len(result) > 32<<20 {
		return nil, decFailure("quota_exceeded")
	}
	i.Record.Completed = true
	i.Record.Terminal = "applied"
	i.Record.Result = base64.StdEncoding.EncodeToString(result)
	i.Secret = nil
	if _, e = validateDecCreationResult(i); e != nil {
		return nil, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return nil, e
	}
	return json.RawMessage(result), nil
}
