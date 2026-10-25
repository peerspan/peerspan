package host

import (
	"io"
	"net/http"

	"github.com/peerspan/peerspan/go/internal/linking"
)

func decodeLinkMutation(w http.ResponseWriter, r *http.Request, required string, dst any) bool {
	defer r.Body.Close()
	if r.URL.RawQuery != "" {
		respondLink(w, 0, nil, linkFail("invalid", r.PathValue("id"), "request"), r.PathValue("id"), "request")
		return false
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 || linking.DecodeMutation(raw, required, dst) != nil {
		respondLink(w, 0, nil, linkFail("invalid", r.PathValue("id"), "request"), r.PathValue("id"), "request")
		return false
	}
	return true
}
func validLinkRead(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" || r.ContentLength != 0 {
		respondLink(w, 0, nil, linkFail("invalid", r.PathValue("id"), "request"), r.PathValue("id"), "request")
		return false
	}
	return true
}
func localLinkRoutes(mux *http.ServeMux, s *Store) {
	linkRecoveryRoutes(mux, s)
	mux.HandleFunc("GET /v1/networks/{id}/link-catalog", func(w http.ResponseWriter, r *http.Request) {
		if !validLinkRead(w, r) {
			return
		}
		value, e := s.LinkCatalog(r.Context(), s.identity.ID, r.PathValue("id"))
		respondLink(w, http.StatusOK, value, e, "-", "catalog")
	})
	mux.HandleFunc("GET /v1/networks/{id}/link-access-versions", func(w http.ResponseWriter, r *http.Request) {
		if !validLinkRead(w, r) {
			return
		}
		value, e := s.LinkAccessVersions(r.Context(), r.PathValue("id"))
		respondLink(w, http.StatusOK, value, e, "-", "versions")
	})
	mux.HandleFunc("GET /v1/link/requests/{id}/approval", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || r.ContentLength != 0 {
			respondLink(w, 0, nil, linkFail("invalid", r.PathValue("id"), "approval"), r.PathValue("id"), "approval")
			return
		}
		value, e := s.LinkApproval(r.Context(), r.PathValue("id"))
		respondLink(w, http.StatusOK, value, e, r.PathValue("id"), "approval")
	})
	approval := func(administrator bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var request ApproveLink
			if !decodeLinkMutation(w, r, "code network_id expected_person_id expected_host_key expected_device_key signer approve", &request) {
				return
			}
			value, e := s.ApproveLink(r.Context(), request, administrator)
			respondLink(w, http.StatusOK, value, e, "-", "approval")
		}
	}
	mux.HandleFunc("POST /v1/link/approvals", approval(false))
	mux.HandleFunc("POST /v1/link/admissions", approval(true))
	mux.HandleFunc("POST /v1/link/requests/{id}/signed", func(w http.ResponseWriter, r *http.Request) {
		var request linkSignature
		if !decodeLinkMutation(w, r, "object_type signature", &request) {
			return
		}
		value, e := s.SignLinkIntent(r.Context(), r.PathValue("id"), request.ObjectType, request.Signature)
		respondLink(w, http.StatusOK, value, e, r.PathValue("id"), "signing")
	})
	mux.HandleFunc("POST /v1/link/requests/{id}/selection", func(w http.ResponseWriter, r *http.Request) {
		var request SelectLink
		if !decodeLinkMutation(w, r, "owner_offer_id network_id person_public_key host_public_key device_public_key approve", &request) {
			return
		}
		value, e := s.SelectLink(r.Context(), r.PathValue("id"), request)
		respondLink(w, http.StatusOK, value, e, r.PathValue("id"), "selection")
	})
	mux.HandleFunc("POST /v1/link/requests/{id}/commit", func(w http.ResponseWriter, r *http.Request) {
		var request CommitLink
		if !decodeLinkMutation(w, r, "owner_offer_id selection_id administrator_offer_id network_id person_public_key host_public_key device_public_key approve", &request) {
			return
		}
		value, e := s.CommitLink(r.Context(), r.PathValue("id"), request)
		respondLink(w, http.StatusOK, value, e, r.PathValue("id"), "commit")
	})
	mux.HandleFunc("POST /v1/networks/{id}/link-feature", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Activate bool `json:"activate"`
		}
		if !decodeLinkMutation(w, r, "activate", &request) {
			return
		}
		value, e := s.LinkFeature(r.Context(), r.PathValue("id"), request.Activate, "")
		respondLink(w, http.StatusOK, value, e, "-", "feature")
	})
	mux.HandleFunc("POST /v1/networks/{id}/link-feature/signed", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Signature string `json:"signature"`
		}
		if !decodeLinkMutation(w, r, "signature", &request) {
			return
		}
		value, e := s.LinkFeature(r.Context(), r.PathValue("id"), false, request.Signature)
		respondLink(w, http.StatusOK, value, e, "-", "feature")
	})
	mux.HandleFunc("GET /v1/networks/{id}/link-signer", func(w http.ResponseWriter, r *http.Request) {
		if !validLinkRead(w, r) {
			return
		}
		value, e := s.LinkSigner(r.Context(), r.PathValue("id"))
		respondLink(w, http.StatusOK, value, e, "-", "signer")
	})
	mux.HandleFunc("POST /v1/networks/{id}/link-actions", func(w http.ResponseWriter, r *http.Request) {
		var request LinkActionRequest
		if !decodeLinkMutation(w, r, "kind payload_base64 certificate_id", &request) {
			return
		}
		value, e := s.LinkAction(r.Context(), r.PathValue("id"), request)
		respondLink(w, http.StatusOK, value, e, "-", "action")
	})
	mux.HandleFunc("POST /v1/link/requests", func(w http.ResponseWriter, r *http.Request) {
		var request CreateLinkRequest
		if !decodeLinkMutation(w, r, "mode network_id person_public_key coordinator_address coordinator_public_key", &request) {
			return
		}
		value, e := s.CreateLinkRequest(r.Context(), request)
		respondLink(w, http.StatusCreated, value, e, "-", "request")
	})
	mux.HandleFunc("GET /v1/link/requests", func(w http.ResponseWriter, r *http.Request) {
		if !validLinkRead(w, r) {
			return
		}
		value, e := s.LinkRequests(r.Context())
		respondLink(w, http.StatusOK, value, e, "-", "request")
	})
	mux.HandleFunc("GET /v1/link/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !validLinkRead(w, r) {
			return
		}
		value, e := s.LinkRequest(r.Context(), r.PathValue("id"))
		respondLink(w, http.StatusOK, value, e, r.PathValue("id"), "request")
	})
	mux.HandleFunc("POST /v1/link/requests/{id}/resume", func(w http.ResponseWriter, r *http.Request) {
		var request struct{}
		if !decodeLinkMutation(w, r, "", &request) {
			return
		}
		value, e := s.ResumeLinkRequest(r.Context(), r.PathValue("id"))
		respondLink(w, http.StatusOK, value, e, r.PathValue("id"), "resume")
	})
	mux.HandleFunc("POST /v1/link/requests/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		var request struct{}
		if !decodeLinkMutation(w, r, "", &request) {
			return
		}
		value, e := s.CancelLinkRequest(r.Context(), r.PathValue("id"))
		respondLink(w, http.StatusOK, value, e, r.PathValue("id"), "cancel")
	})
}
