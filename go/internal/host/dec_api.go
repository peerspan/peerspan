package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type decErrorDetails struct {
	Network   string   `json:"network_id"`
	Context   string   `json:"context_id"`
	Request   string   `json:"request_id"`
	Stage     string   `json:"stage"`
	Required  []string `json:"required_ids"`
	Conflicts []string `json:"conflict_ids"`
	Next      []string `json:"next"`
}

func respondDec(w http.ResponseWriter, status int, value any, err error, network, contextID, request, stage string) {
	w.Header().Set("Content-Type", "application/json")
	if err == nil {
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		if raw, ok := value.(json.RawMessage); ok {
			_, _ = w.Write(raw)
			return
		}
		_ = json.NewEncoder(w).Encode(value)
		return
	}
	code, message := "internal", "internal error"
	status = 500
	var failure *dec.Failure
	if errors.As(err, &failure) {
		code = failure.Code
		message = code
		switch code {
		case "invalid":
			status = 400
		case "forbidden", "authority_expired", "device_revoked", "not_yet_valid", "authority_would_be_invalidated":
			status = 403
		case "not_found":
			status = 404
		case "expired":
			status = 410
		case "rate_limited":
			status = 429
			retry := 1
			var carrier interface{ retryAfter() int }
			if errors.As(err, &carrier) && carrier.retryAfter() > 0 {
				retry = carrier.retryAfter()
			}
			w.Header().Set("Retry-After", fmt.Sprint(retry))
		case "upgrade_required":
			status = 426
		case "proof_required", "state_conflict", "operation_conflict", "version_exhausted", "quota_exceeded", "clock_rollback", "migration_pending", "review_required", "signer_unavailable", "recovery_required":
			status = 409
		default:
			code, message = "internal", "internal error"
		}
	} else if errors.Is(err, ErrNotFound) {
		status, code, message = 404, "not_found", "not_found"
	}
	ids := []string{}
	if failure != nil && code == "proof_required" {
		ids = append(ids, failure.RequiredIDs...)
		sort.Strings(ids)
	}
	for _, field := range []*string{&network, &contextID, &request} {
		if *field == "" {
			*field = "-"
		}
	}
	var control interface{ decErrorStage() string }
	if errors.As(err, &control) {
		stage = control.decErrorStage()
	}
	details := decErrorDetails{network, contextID, request, stage, ids, []string{}, []string{}}
	var conflicts interface{ decConflictReferences() []string }
	if code == "state_conflict" && errors.As(err, &conflicts) {
		details.Conflicts = decSorted(decSet(conflicts.decConflictReferences()))
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code    string          `json:"code"`
		Error   string          `json:"error"`
		Details decErrorDetails `json:"details"`
	}{code, message, details})
}
func validDecRead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		respondDecMethod(w)
		return false
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(r.Body, 1))
	if r.URL.RawQuery != "" || r.URL.ForceQuery || e != nil || len(raw) != 0 {
		respondDec(w, 0, nil, decFailure("invalid"), r.PathValue("id"), "-", "-", "request")
		return false
	}
	return true
}
func localDecRoutes(mux *http.ServeMux, s *Store) {
	mux.HandleFunc("GET /v2/info", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		respondDec(w, 200, s.Info(), nil, "-", "-", "-", "repair")
	})
	decClaimRoutes(mux, s)
	mux.HandleFunc("GET /v2/networks/{id}/groups", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedGroups(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), value.Context, "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/root-retention", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedRootRetention(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/migration", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedMigrationStatus(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/identity", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationIdentityRequest
		if !decodeDecMutation(w, r, "scopes approve", &input, 1024) {
			return
		}
		value, e := s.PrepareDecentralizedMigrationIdentity(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/prepare", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationPreparation
		if !decodeDecMutation(w, r, "roster signature_format approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedMigration(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/signed", func(w http.ResponseWriter, r *http.Request) {
		var input DecSignatureBatch
		if !decodeDecMutation(w, r, "intent_id signatures", &input, 1<<20) {
			return
		}
		value, e := s.signedMigrationResponse(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/host-lease", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationHostLease
		if !decodeDecMutation(w, r, "proposal_id host_lease_base64 approve", &input, 2<<20) {
			return
		}
		value, e := s.PrepareDecentralizedMigrationHost(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/device-bans", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationDeviceBans
		if !decodeDecMutation(w, r, "proposal_id person_public_key approve", &input, 1024) {
			return
		}
		value, e := s.PrepareDecentralizedMigrationDeviceBans(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/acknowledgment", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationAcknowledgment
		if !decodeDecMutation(w, r, "proposal_id prepared_catalog_sha256 approve", &input, 1024) {
			return
		}
		value, e := s.AcknowledgeDecentralizedMigration(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/commit", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationCommit
		if !decodeDecMutation(w, r, "proposal_id prepared_catalog_sha256 acknowledgment_ids signature_format approve", &input, 1<<20) {
			return
		}
		value, e := s.CommitDecentralizedMigration(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/adopt", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationAdoption
		if !decodeDecMutation(w, r, "proposal_id commit_id approve", &input, 1024) {
			return
		}
		value, e := s.AdoptDecentralizedMigration(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("GET /v2/networks/{id}/migration/evidence", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedMigrationEvidence(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/evidence", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationEvidence
		if !decodeDecMutation(w, r, DecMigrationEvidenceFields, &input, decPublicationLimit) {
			return
		}
		value, e := s.ReceiveDecentralizedMigrationEvidence(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/link", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationLinkRequest
		if !decodeDecMutation(w, r, "proposal_id", &input, 1024) {
			return
		}
		value, reused, e := s.CreateDecentralizedMigrationLink(r.Context(), r.PathValue("id"), input)
		status := 201
		if reused {
			status = 200
		}
		respondDec(w, status, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/review", func(w http.ResponseWriter, r *http.Request) {
		var input DecMigrationApproval
		if !decodeDecMutation(w, r, "proposal_id approve", &input, 1024) {
			return
		}
		value, e := s.ReviewDecentralizedMigration(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/migration/resume", func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !decodeDecMutation(w, r, "", &input, 1024) {
			return
		}
		value, e := s.resumeMigrationResponse(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "migration")
	})
	mux.HandleFunc("POST /v2/networks/{id}/sync", func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !decodeDecMutation(w, r, "", &input, 1024) {
			return
		}
		value, e := s.SyncDecentralizedNetwork(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "transport")
	})
	mux.HandleFunc("GET /v2/status", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedStatus(r.Context())
		respondDec(w, 200, value, e, "-", "-", "-", "repair")
	})
	mux.HandleFunc("/v2", func(w http.ResponseWriter, r *http.Request) {
		respondDec(w, 0, nil, ErrNotFound, "-", "-", "-", "request")
	})
	mux.HandleFunc("POST /v2/link/approvals", func(w http.ResponseWriter, r *http.Request) {
		var input DecOwnerApproval
		if !decodeDecMutation(w, r, "code network_id person_public_key provider_id signature_format scopes not_after expected_host_public_key expected_device_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedOwner(r.Context(), input)
		respondDec(w, 200, value, e, input.Network, "-", "-", "owner")
	})
	mux.HandleFunc("POST /v2/link/admissions", func(w http.ResponseWriter, r *http.Request) {
		var input DecAdministratorApproval
		if !decodeDecMutation(w, r, "code network_id person_public_key provider_id signature_format owner_offer_id selection_id expected_host_public_key expected_device_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedAdministrator(r.Context(), input)
		respondDec(w, 200, value, e, input.Network, "-", "-", "administrator")
	})
	mux.HandleFunc("POST /v2/link/requests/{request}/finalization", func(w http.ResponseWriter, r *http.Request) {
		var input DecLinkFinalization
		if !decodeDecMutation(w, r, "owner_offer_id selection_id administrator_offer_id network_id context_id person_public_key host_public_key device_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedFinalization(r.Context(), r.PathValue("request"), input)
		respondDec(w, 200, value, e, input.Network, input.Context, r.PathValue("request"), "owner_finalization")
	})
	mux.HandleFunc("POST /v2/link/requests/{request}/commit", func(w http.ResponseWriter, r *http.Request) {
		var input DecLinkCommit
		if !decodeDecMutation(w, r, "owner_offer_id selection_id administrator_offer_id owner_finalization_id network_id context_id person_public_key host_public_key device_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.CommitDecentralizedLink(r.Context(), r.PathValue("request"), input)
		respondDec(w, 200, value, e, input.Network, input.Context, r.PathValue("request"), "commit")
	})
	mux.HandleFunc("GET /v2/link/requests/{request}/approval", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedApproval(r.Context(), r.PathValue("request"))
		respondDec(w, 200, value, e, "-", "-", r.PathValue("request"), "owner")
	})
	mux.HandleFunc("POST /v2/link/requests/{request}/signed", func(w http.ResponseWriter, r *http.Request) {
		var input DecSignatureBatch
		if !decodeDecMutation(w, r, "intent_id signatures", &input, 1<<20) {
			return
		}
		value, e := s.SignedDecentralizedApproval(r.Context(), r.PathValue("request"), input)
		respondDec(w, 200, value, e, "-", "-", r.PathValue("request"), "sign")
	})
	mux.HandleFunc("POST /v2/link/requests", func(w http.ResponseWriter, r *http.Request) {
		var input DecLinkCreate
		if !decodeDecMutation(w, r, "mode network_id person_public_key migration_proposal_id contact_invitation helpers", &input, 1<<20) {
			return
		}
		value, reused, e := s.CreateDecentralizedLink(r.Context(), input)
		status := 201
		if reused {
			status = 200
		}
		respondDec(w, status, value, e, input.Network, "-", "-", "request")
	})
	mux.HandleFunc("GET /v2/link/requests", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedLinks(r.Context())
		respondDec(w, 200, value, e, "-", "-", "-", "request")
	})
	mux.HandleFunc("GET /v2/link/requests/{request}", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedLink(r.Context(), r.PathValue("request"))
		respondDec(w, 200, value, e, "-", "-", r.PathValue("request"), "request")
	})
	mux.HandleFunc("POST /v2/link/requests/{request}/cancel", func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !decodeDecMutation(w, r, "", &input, 1<<20) {
			return
		}
		value, e := s.CancelDecentralizedLink(r.Context(), r.PathValue("request"))
		respondDec(w, 200, value, e, "-", "-", r.PathValue("request"), "request")
	})
	mux.HandleFunc("POST /v2/link/requests/{request}/resume", func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !decodeDecMutation(w, r, "", &input, 1<<20) {
			return
		}
		value, e := s.ResumeDecentralizedLink(r.Context(), r.PathValue("request"), true)
		respondDec(w, 200, value, e, "-", "-", r.PathValue("request"), "transport")
	})
	mux.HandleFunc("POST /v2/link/requests/{request}/selection", func(w http.ResponseWriter, r *http.Request) {
		var input DecLinkSelection
		if !decodeDecMutation(w, r, "owner_offer_id network_id context_id person_public_key host_public_key device_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.SelectDecentralizedLink(r.Context(), r.PathValue("request"), input)
		respondDec(w, 200, value, e, input.Network, input.Context, r.PathValue("request"), "selection")
	})
	mux.HandleFunc("POST /v2/networks/{id}/policy-edits", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Provider string `json:"provider_id"`
		}
		if !decodeDecMutation(w, r, "provider_id", &input, 1<<20) {
			return
		}
		value, e := s.ReserveDecentralizedPolicyEdit(r.Context(), r.PathValue("id"), input.Provider)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "sign")
	})
	mux.HandleFunc("POST /v2/networks/{id}/policy-edits/reapply-preview", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Provider string `json:"provider_id"`
		}
		if !decodeDecMutation(w, r, "provider_id", &input, 1<<20) {
			return
		}
		value, e := s.PreviewDecentralizedPolicyReapply(r.Context(), r.PathValue("id"), input.Provider)
		respondDec(w, 200, value, e, r.PathValue("id"), value.Context, "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/policy-edits", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedPolicyEdits(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "repair")
	})
	mux.HandleFunc("POST /v2/networks/{id}/actions", func(w http.ResponseWriter, r *http.Request) {
		var input DecActionRequest
		if !decodeDecMutation(w, r, "kind provider_id signature_format payload_base64 approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedAction(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "sign")
	})
	mux.HandleFunc("POST /v2/networks/{id}/root-transitions", func(w http.ResponseWriter, r *http.Request) {
		var input DecRootTransition
		if !decodeDecMutation(w, r, "new_root_public_key new_root_signature_format signature_format retained_statement_ids approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedRootTransition(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "sign")
	})
	mux.HandleFunc("POST /v2/networks/{id}/invitations", func(w http.ResponseWriter, r *http.Request) {
		var input DecInvitationRequest
		if !decodeDecMutation(w, r, "member expected_person_public_key", &input, 1<<20) {
			return
		}
		value, e := s.DecentralizedInvitation(r.Context(), r.PathValue("id"), input)
		respondDec(w, 201, value, e, r.PathValue("id"), "-", "-", "request")
	})
	mux.HandleFunc("GET /v2/networks/{id}/actions/{action}", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedAction(r.Context(), r.PathValue("id"), r.PathValue("action"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "sign")
	})
	mux.HandleFunc("POST /v2/networks/{id}/actions/{action}/signed", func(w http.ResponseWriter, r *http.Request) {
		var input DecSignatureBatch
		if !decodeDecMutation(w, r, "intent_id signatures", &input, 1<<20) {
			return
		}
		value, e := s.SignedDecentralizedAction(r.Context(), r.PathValue("id"), r.PathValue("action"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "sign")
	})
	mux.HandleFunc("POST /v2/networks", func(w http.ResponseWriter, r *http.Request) {
		var input DecCreateNetwork
		if !decodeDecMutation(w, r, "name member person_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.PrepareDecentralizedNetwork(r.Context(), input)
		respondDec(w, 200, value, e, "-", "-", "-", "create")
	})
	mux.HandleFunc("GET /v2/network-creations/{creation}", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedCreation(r.Context(), r.PathValue("creation"))
		respondDec(w, 200, value, e, "-", "-", "-", "create")
	})
	mux.HandleFunc("POST /v2/network-creations/{creation}/approve", func(w http.ResponseWriter, r *http.Request) {
		var input DecCreationApproval
		if !decodeDecMutation(w, r, "context_id root_state_id person_public_key host_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.ApproveDecentralizedCreation(r.Context(), r.PathValue("creation"), input)
		respondDec(w, 200, value, e, "-", "-", "-", "create")
	})
	mux.HandleFunc("POST /v2/network-creations/{creation}/signed", func(w http.ResponseWriter, r *http.Request) {
		var input DecSignatureBatch
		if !decodeDecMutation(w, r, "intent_id signatures", &input, 1<<20) {
			return
		}
		value, e := s.SignedDecentralizedCreation(r.Context(), r.PathValue("creation"), input)
		respondDec(w, 200, value, e, "-", "-", "-", "sign")
	})

	mux.HandleFunc("POST /v2/networks/{id}/provider", func(w http.ResponseWriter, r *http.Request) {
		var input DecSelectProvider
		if !decodeDecMutation(w, r, "provider_id person_public_key host_public_key approve", &input, 1<<20) {
			return
		}
		value, e := s.SelectDecentralizedProvider(r.Context(), r.PathValue("id"), input)
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "sign")
	})

	mux.HandleFunc("GET /v2/networks", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedNetworks(r.Context())
		respondDec(w, 200, value, e, "-", "-", "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !validDecRead(w, r) {
			return
		}
		value, e := s.DecentralizedNetwork(r.Context(), r.PathValue("id"))
		respondDec(w, 200, value, e, r.PathValue("id"), "-", "-", "repair")
	})
	snapshot := func(w http.ResponseWriter, r *http.Request) (*decSnapshot, *dec.Projection, bool) {
		if !validDecRead(w, r) {
			return nil, nil, false
		}
		now, e := decNow()
		if e != nil {
			respondDec(w, 0, nil, e, r.PathValue("id"), "-", "-", "clock")
			return nil, nil, false
		}
		state, p, e := s.decentralizedProjection(r.Context(), r.PathValue("id"), linkTime(now))
		if e != nil {
			respondDec(w, 0, nil, e, r.PathValue("id"), "-", "-", "repair")
			return nil, nil, false
		}
		return state, p, true
	}
	mux.HandleFunc("GET /v2/networks/{id}/catalog", func(w http.ResponseWriter, r *http.Request) {
		state, _, ok := snapshot(w, r)
		if !ok {
			return
		}
		respondDec(w, 200, decCatalogResponse(state), nil, state.Descriptor.NetworkID, state.Descriptor.ContextID, "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/provider", func(w http.ResponseWriter, r *http.Request) {
		state, p, ok := snapshot(w, r)
		if !ok {
			return
		}
		value, e := decPublicProvider(state, p)
		if e == nil {
			availability := s.decProviderAvailable(state, value, nil)
			if availability.State != "available" {
				e = decFailure(availability.Code, availability.Required...)
			}
		}
		respondDec(w, 200, value, e, state.Descriptor.NetworkID, state.Descriptor.ContextID, "-", "sign")
	})

	mux.HandleFunc("GET /v2/networks/{id}/access-versions", func(w http.ResponseWriter, r *http.Request) {
		state, _, ok := snapshot(w, r)
		if !ok {
			return
		}
		respondDec(w, 200, decAccessVersions(state), nil, state.Descriptor.NetworkID, state.Descriptor.ContextID, "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/planning", func(w http.ResponseWriter, r *http.Request) {
		state, p, ok := snapshot(w, r)
		if !ok {
			return
		}
		respondDec(w, 200, struct {
			Network DecNetworkView      `json:"network"`
			Time    string              `json:"decision_time"`
			Catalog json.RawMessage     `json:"catalog"`
			Streams []decPlanningStream `json:"streams"`
		}{s.decNetworkView(state, p), p.DecisionTime, json.RawMessage(state.Catalog.Raw), decPlanningStreams(state)}, nil, state.Descriptor.NetworkID, state.Descriptor.ContextID, "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		state, p, ok := snapshot(w, r)
		if !ok {
			return
		}
		respondDec(w, 200, struct {
			Context string          `json:"context_id"`
			Members []DecMemberView `json:"members"`
		}{state.Descriptor.ContextID, decMemberViews(p)}, nil, state.Descriptor.NetworkID, state.Descriptor.ContextID, "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/persons", func(w http.ResponseWriter, r *http.Request) {
		state, p, ok := snapshot(w, r)
		if !ok {
			return
		}
		people, e := decCurrentPersons(p)
		respondDec(w, 200, struct {
			Context string          `json:"context_id"`
			Persons []DecPersonView `json:"persons"`
		}{state.Descriptor.ContextID, people}, e, state.Descriptor.NetworkID, state.Descriptor.ContextID, "-", "repair")
	})
	mux.HandleFunc("GET /v2/networks/{id}/policy/{person}", func(w http.ResponseWriter, r *http.Request) {
		state, p, ok := snapshot(w, r)
		if !ok {
			return
		}
		value, e := decCurrentPolicyStatement(p, r.PathValue("person"))
		respondDec(w, 200, value, e, state.Descriptor.NetworkID, state.Descriptor.ContextID, "-", "repair")
	})
	// The fallback is owner-local JSON. A peer/bootstrap router never receives an
	// unknown v2 administration request, including an undeclared method.
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		methods := []string{}
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			clone := r.Clone(r.Context())
			clone.Method = method
			_, pattern := mux.Handler(clone)
			if pattern != "/v2/" && pattern != "" {
				methods = append(methods, method)
			}
		}
		if len(methods) > 0 {
			w.Header().Set("Allow", strings.Join(methods, ", "))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(405)
			_ = json.NewEncoder(w).Encode(struct {
				Code    string          `json:"code"`
				Error   string          `json:"error"`
				Details decErrorDetails `json:"details"`
			}{"invalid", "invalid", decErrorDetails{"-", "-", "-", "request", []string{}, []string{}, []string{}}})
			return
		}
		respondDec(w, 0, nil, ErrNotFound, "-", "-", "-", "request")
	})
}

func respondDecMethod(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(405)
	_ = json.NewEncoder(w).Encode(struct {
		Code    string          `json:"code"`
		Error   string          `json:"error"`
		Details decErrorDetails `json:"details"`
	}{"invalid", "invalid", decErrorDetails{"-", "-", "-", "request", []string{}, []string{}, []string{}}})
}

func decodeDecMutation(w http.ResponseWriter, r *http.Request, names string, target any, max int) bool {
	defer r.Body.Close()
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		respondDec(w, 0, nil, decFailure("invalid"), r.PathValue("id"), "-", "-", "request")
		return false
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if e != nil || len(raw) > max || dec.ReadPrivateRecord(raw, names, target) != nil {
		respondDec(w, 0, nil, decFailure("invalid"), r.PathValue("id"), "-", "-", "request")
		return false
	}
	return true
}
