package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/helper"
)

// This is the isolated bootstrap participant callback, never the owner-local
// administration router. Both host identities are checked against signed
// transcript packets before any historical response or current application.
func (s *Store) completeDecParticipant(ctx context.Context, request helper.ParticipantRequest) (helper.ParticipantResponse, error) {
	var result decParticipantOutcome
	var err error
	id, network, contextID := "-", "-", "-"
	if !dec.ValidPublicKey(request.HostPublicKey) {
		return decCompletionResponse(nil, decFailure("invalid"), network, contextID, id)
	}
	if request.Method == "GET" {
		id = strings.TrimPrefix(request.Path, "/bootstrap/v1/operations/")
		if !dec.ValidID(id, "link_") || len(request.Body) != 0 {
			err = decFailure("invalid")
		} else {
			var d dec.Descriptor
			d, err = s.decCompletionDescriptor(ctx, id, "-")
			if err == nil {
				network, contextID = d.NetworkID, d.ContextID
				result, err = s.retainedDecOutcome(ctx, d, id, request.HostPublicKey)
			}
		}
		return decCompletionResponse(result, err, network, contextID, id)
	}
	if request.Method != "POST" || request.Path != "/bootstrap/v1/activations" || len(request.Body) > 20<<20 {
		return decCompletionResponse(nil, decFailure("invalid"), network, contextID, id)
	}
	var input struct {
		Activation json.RawMessage `json:"activation"`
		Catalog    json.RawMessage `json:"catalog"`
	}
	if dec.ReadPrivateRecord(request.Body, "activation catalog", &input) != nil {
		return decCompletionResponse(nil, decFailure("invalid"), network, contextID, id)
	}
	// Only locate an already retained descriptor from these untrusted fields.
	// Every byte and reference is subsequently checked by the strict readers.
	var carrier struct {
		Format        uint64          `json:"format"`
		Context       string          `json:"context_id"`
		Request       json.RawMessage `json:"request"`
		Owner         json.RawMessage `json:"owner"`
		Selection     json.RawMessage `json:"selection"`
		Administrator json.RawMessage `json:"administrator"`
		Finalization  json.RawMessage `json:"owner_finalization"`
		Commit        json.RawMessage `json:"commit"`
	}
	if dec.ReadPrivateRecord(input.Activation, "format context_id request owner selection administrator owner_finalization commit", &carrier) != nil {
		return decCompletionResponse(nil, decFailure("invalid"), network, contextID, id)
	}
	target, e := dec.ReadPacket(dec.Descriptor{}, carrier.Request)
	if e != nil || target.Role != "request" || !dec.ValidID(carrier.Context, "ctx_") {
		return decCompletionResponse(nil, decFailure("invalid"), network, contextID, id)
	}
	id = target.RequestID
	d, e := s.decCompletionDescriptor(ctx, id, carrier.Context)
	if e != nil {
		return decCompletionResponse(nil, e, network, carrier.Context, id)
	}
	network, contextID = d.NetworkID, d.ContextID
	parsed, e := dec.ReadActivation(d, input.Activation)
	if e == nil {
		_, e = dec.ReadCatalog(d, input.Catalog)
	}
	if e != nil {
		return decCompletionResponse(nil, e, network, contextID, id)
	}
	if !decActivationParticipant(parsed, request.HostPublicKey) || !decActivationParticipant(parsed, s.identity.PublicKey) {
		return decCompletionResponse(nil, decFailure("forbidden"), network, contextID, id)
	}
	result, e = s.retainedDecOutcome(ctx, d, id, request.HostPublicKey)
	if e == nil {
		old, readErr := dec.ReadActivation(d, result.Activation)
		if readErr != nil {
			return helper.ParticipantResponse{}, readErr
		}
		if old.ID != parsed.ID || old.ManifestID != parsed.ManifestID || !bytes.Equal(old.Request.Raw, parsed.Request.Raw) {
			e = decFailure("operation_conflict")
		}
		return decCompletionResponse(result, e, network, contextID, id)
	}
	if !errors.Is(e, ErrNotFound) {
		return decCompletionResponse(nil, e, network, contextID, id)
	}
	if e = decBarrier(ctx, "dec.apply.before_transaction", id); e != nil {
		return helper.ParticipantResponse{}, e
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
		// Recheck the outcome identity after the barrier and writer serialization.
		var existing string
		e = tx.QueryRowContext(ctx, `SELECT activation_id FROM dec_operations WHERE network_id=? AND context_id=? AND request_id=?`, network, contextID, id).Scan(&existing)
		if e == nil {
			if existing != parsed.ID {
				return decFailure("operation_conflict")
			}
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		p, e := readDecPending(ctx, tx, id)
		if errors.Is(e, ErrNotFound) {
			if parsed.Request.Writer == s.identity.PublicKey {
				return decFailure("review_required")
			}
			var count int
			if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM dec_pending`).Scan(&count); e != nil {
				return e
			}
			if count >= 4096 {
				return decFailure("quota_exceeded")
			}
			p, e = decCompletionPending(d, parsed, s.identity.PublicKey)
		}
		if e != nil {
			return e
		}
		if p.Descriptor.ContextID != "" && !bytes.Equal(p.Descriptor.Raw, d.Raw) || !bytes.Equal(p.Request.Raw, parsed.Request.Raw) {
			return decFailure("operation_conflict")
		}
		if p.Record.Committed && (p.Record.ManifestID != parsed.ManifestID || p.Record.ActivationID != parsed.ID) {
			return decFailure("operation_conflict")
		}
		// Requester approval flags and exact locally committed packets are never
		// reconstructed from public evidence. Other participants retain signed facts.
		if containsString(p.Record.Roles, "requester") && (!p.Record.Committed || !bytes.Equal(mustDecBytes(p.Record.Commit), parsed.Commit.Raw) || !bytes.Equal(mustDecBytes(p.Record.Selection), parsed.Selection.Raw)) {
			return decFailure("review_required")
		}
		if e = decCompletePendingFacts(&p, d, parsed, input.Catalog); e != nil {
			return e
		}
		now, e := decCreationClock(ctx, tx, network)
		if e != nil {
			return e
		}
		result, e = s.applyDecParticipant(ctx, tx, &p, input.Activation, parsed, now)
		if e != nil {
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		applied = true
		sealedOutcome = len(p.Record.Outbound) > 0
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
	if e == nil && !applied {
		result, e = s.retainedDecOutcome(ctx, d, id, request.HostPublicKey)
	}
	return decCompletionResponse(result, e, network, contextID, id)
}

func decActivationParticipant(a *dec.ParsedActivation, key string) bool {
	return key == a.Request.Writer || key == a.Owner.Writer || a.Administrator != nil && key == a.Administrator.Writer
}

func (s *Store) decCompletionDescriptor(ctx context.Context, id, contextID string) (dec.Descriptor, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return dec.Descriptor{}, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e == nil && p.Descriptor.ContextID != "" {
		if contextID != "-" && contextID != p.Descriptor.ContextID {
			return dec.Descriptor{}, decFailure("operation_conflict")
		}
		return p.Descriptor, nil
	}
	if e != nil && !errors.Is(e, ErrNotFound) {
		return dec.Descriptor{}, e
	}
	var raw string
	if contextID == "-" {
		e = tx.QueryRowContext(ctx, `SELECT c.record FROM dec_contexts c JOIN dec_operations o ON o.network_id=c.network_id AND o.context_id=c.context_id WHERE o.request_id=?`, id).Scan(&raw)
	} else {
		e = tx.QueryRowContext(ctx, `SELECT record FROM dec_contexts WHERE context_id=?`, contextID).Scan(&raw)
	}
	if errors.Is(e, sql.ErrNoRows) {
		return dec.Descriptor{}, ErrNotFound
	}
	if e != nil {
		return dec.Descriptor{}, e
	}
	var pin decContextRecord
	if dec.ReadPrivateRecord([]byte(raw), "format descriptor_base64 origin initial_root_state_id origin_proof_id migration_proposal_id adopted_at", &pin) != nil || pin.Format != 1 {
		return dec.Descriptor{}, decStorageError()
	}
	body, e := decBytes(pin.Descriptor, dec.MaxPayload)
	if e != nil {
		return dec.Descriptor{}, e
	}
	return dec.ReadDescriptor(body)
}

func decCompletionPending(d dec.Descriptor, a *dec.ParsedActivation, own string) (decPending, error) {
	terms, e := a.Request.RequestTerms()
	if e != nil {
		return decPending{}, e
	}
	roles := []string{}
	if a.Owner.Writer == own {
		roles = append(roles, "owner")
	}
	if a.Administrator != nil && a.Administrator.Writer == own {
		roles = append(roles, "administrator")
	}
	if len(roles) == 0 {
		return decPending{}, decFailure("forbidden")
	}
	r := decPendingRecord{Format: 1, Roles: roles, Mode: terms.Mode, Migration: terms.Migration, Network: terms.Network, Context: terms.Context, Person: terms.Person, Invitation: "-", Descriptor: base64.StdEncoding.EncodeToString(d.Raw), Host: terms.Host, Device: terms.Device, Nonce: terms.Nonce, Request: base64.StdEncoding.EncodeToString(a.Request.Raw), Owner: "-", Selection: "-", Administrator: "-", Finalization: "-", Commit: "-", Outcome: "-", Catalog: "-", OwnerID: "-", SelectionID: "-", AdministratorID: "-", FinalizationID: "-", ManifestID: "-", ActivationID: "-", OwnerIntent: "-", AdministratorIntent: "-", SelectionIntent: "-", CommitIntent: "-", Terminal: "-", Carriers: []decCarrier{}, Outbound: []decOutboundFrame{}}
	return decPending{ID: a.Request.RequestID, Deadline: terms.Expires, Record: r, Request: a.Request, Terms: terms, Descriptor: d, Frames: map[string]*dec.Frame{}}, nil
}

func decCompletePendingFacts(p *decPending, d dec.Descriptor, a *dec.ParsedActivation, catalog []byte) error {
	c, e := dec.ReadCatalog(d, catalog)
	if e != nil {
		return e
	}
	if p.Record.Catalog != "-" {
		old, e := dec.ReadCatalog(d, mustDecBytes(p.Record.Catalog))
		if e != nil {
			return e
		}
		c, e = dec.UnionCatalog(d, old, c)
		if e != nil {
			return e
		}
	}
	c, e = decCatalogWithActivation(d, c, a.Raw)
	if e != nil {
		return e
	}
	p.Descriptor = d
	r := &p.Record
	r.Descriptor = base64.StdEncoding.EncodeToString(d.Raw)
	for _, item := range []struct {
		packet   *dec.Packet
		body, id *string
	}{{a.Owner, &r.Owner, &r.OwnerID}, {a.Selection, &r.Selection, &r.SelectionID}, {a.Administrator, &r.Administrator, &r.AdministratorID}, {a.Finalization, &r.Finalization, &r.FinalizationID}} {
		if item.packet == nil {
			*item.body = "-"
			*item.id = "-"
		} else {
			*item.body = base64.StdEncoding.EncodeToString(item.packet.Raw)
			*item.id = item.packet.ID
		}
	}
	r.Commit = base64.StdEncoding.EncodeToString(a.Commit.Raw)
	r.ManifestID = a.ManifestID
	r.ActivationID = a.ID
	r.Catalog = base64.StdEncoding.EncodeToString(c.Raw)
	return nil
}

type decCompletionWriter struct {
	header http.Header
	status int
	bytes.Buffer
}

func (w *decCompletionWriter) Header() http.Header    { return w.header }
func (w *decCompletionWriter) WriteHeader(status int) { w.status = status }
func decCompletionResponse(result any, e error, network, contextID, id string) (helper.ParticipantResponse, error) {
	w := &decCompletionWriter{header: http.Header{}}
	respondDec(w, 200, result, e, network, contextID, id, "apply")
	if w.status == 500 || w.status == 426 {
		if e == nil {
			e = decStorageError()
		}
		return helper.ParticipantResponse{}, e
	}
	if w.Len() > 20<<20 {
		return helper.ParticipantResponse{}, decFailure("quota_exceeded")
	}
	return helper.ParticipantResponse{Status: w.status, Body: append([]byte{}, w.Bytes()...)}, nil
}
