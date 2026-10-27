package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecPolicyClaimRequest struct {
	Capability string `json:"capability"`
	Provider   string `json:"provider_id"`
	Format     string `json:"signature_format"`
	Payload    string `json:"payload_base64"`
	Approve    bool   `json:"approve"`
}

func checkDecClaimPolicy(statement *dec.Statement, name, host string) error {
	if !membership.ValidCapabilityName(name) || statement.Kind != "policy" {
		return decFailure("invalid")
	}
	body, e := decPolicyBody(statement)
	if e != nil {
		return e
	}
	held := false
	for _, rule := range body.Capabilities {
		if rule.Capability != name {
			continue
		}
		if rule.Host != host {
			return decFailure("forbidden")
		}
		held = true
	}
	if !held {
		return decFailure("invalid")
	}
	return nil
}

// A complete preparation exposes the exact signed candidate without admitting
// it. Its catalog is public proof material, never next_prior or publication.
func decFinishedClaim(snapshot *decSnapshot, i decIntent, review decActionReview, statement *dec.Statement, body []byte) (json.RawMessage, error) {
	if i.Kind != "policy_claim" || !i.Record.Approved || !decActionComplete(statement) {
		return nil, decStorageError()
	}
	candidate, e := decActionCandidate(snapshot.Descriptor, statement, body)
	if e != nil {
		return nil, e
	}
	catalog, e := dec.ReadCatalog(snapshot.Descriptor, candidate)
	if e != nil {
		return nil, e
	}
	union, e := dec.UnionCatalog(snapshot.Descriptor, snapshot.Catalog, catalog)
	if e != nil {
		return nil, e
	}
	result, e := json.Marshal(decActionResult{i.Record.Operation, review, []DecSigningRequest{}, base64.StdEncoding.EncodeToString(body), dec.ProofID("policy", body), json.RawMessage(union.Raw), false, snapshot.Delivery})
	if e != nil {
		return nil, e
	}
	if len(result) > 32<<20 {
		return nil, decFailure("quota_exceeded")
	}
	return result, nil
}
func (s *Store) PrepareDecentralizedPolicyClaim(ctx context.Context, id string, input DecPolicyClaimRequest) (json.RawMessage, error) {
	if !membership.ValidCapabilityName(input.Capability) {
		return nil, decFailure("invalid")
	}
	return s.PrepareDecentralizedAction(ctx, id, DecActionRequest{claim: input.Capability, Kind: "policy", Provider: input.Provider, Format: input.Format, Payload: input.Payload, Approve: input.Approve})
}
func (s *Store) requireDecPolicyClaim(ctx context.Context, id, operation string) error {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	intent, e := findDecAction(ctx, tx, id, operation)
	if e != nil {
		return e
	}
	if intent.Kind != "policy_claim" {
		return ErrNotFound
	}
	return nil
}
func decClaimRoutes(mux *http.ServeMux, s *Store) {
	mux.HandleFunc("POST /v2/networks/{id}/policy-claims", func(w http.ResponseWriter, r *http.Request) {
		var input DecPolicyClaimRequest
		if !decodeDecMutation(w, r, "capability provider_id signature_format payload_base64 approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedPolicyClaim(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "claim")
	})
	mux.HandleFunc("GET /v2/networks/{id}/policy-claims/{action}", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		var value json.RawMessage
		e := s.requireDecPolicyClaim(r.Context(), r.PathValue("id"), r.PathValue("action"))
		if e == nil {
			value, e = s.DecentralizedAction(r.Context(), r.PathValue("id"), r.PathValue("action"))
		}
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "claim")
	})
	mux.HandleFunc("POST /v2/networks/{id}/policy-claims/{action}/signed", func(w http.ResponseWriter, r *http.Request) {
		var input DecSignatureBatch
		if !decodeDecMutation(w, r, "intent_id signatures", &input, 1<<20) {
			return
		}
		var value json.RawMessage
		e := s.requireDecPolicyClaim(r.Context(), r.PathValue("id"), r.PathValue("action"))
		if e == nil {
			value, e = s.SignedDecentralizedAction(r.Context(), r.PathValue("id"), r.PathValue("action"), input)
		}
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "claim")
	})
}
