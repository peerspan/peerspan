package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Handler is the owner-local administration API, served only over a private
// Unix socket by Serve. It is not a peer API and does not enforce network grants.
func Handler(store *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/host", func(w http.ResponseWriter, r *http.Request) {
		respond(w, http.StatusOK, store.Identity(), nil)
	})
	mux.HandleFunc("POST /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		var req RegisterAgent
		if !decode(w, r, &req, "name", "owner", "capabilities") {
			return
		}
		a, err := store.RegisterAgent(r.Context(), req)
		respond(w, http.StatusCreated, a, err)
	})
	mux.HandleFunc("GET /v1/agents", func(w http.ResponseWriter, r *http.Request) {
		a, err := store.Agents(r.Context())
		respond(w, http.StatusOK, a, err)
	})
	mux.HandleFunc("GET /v1/agents/{id}", func(w http.ResponseWriter, r *http.Request) {
		a, err := store.Agent(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, a, err)
	})
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		var req AttachSession
		if !decode(w, r, &req, "agent_id", "integration") {
			return
		}
		s, err := store.AttachSession(r.Context(), req)
		respond(w, http.StatusCreated, s, err)
	})
	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		s, err := store.Sessions(r.Context(), r.URL.Query().Get("agent_id"))
		respond(w, http.StatusOK, s, err)
	})
	mux.HandleFunc("GET /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		s, err := store.Session(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, s, err)
	})
	mux.HandleFunc("POST /v1/sessions/{id}/detach", func(w http.ResponseWriter, r *http.Request) {
		s, err := store.DetachSession(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, s, err)
	})
	mux.HandleFunc("GET /v1/activity", func(w http.ResponseWriter, r *http.Request) {
		after, limit := int64(0), 100
		var err error
		if value := r.URL.Query().Get("after"); value != "" {
			after, err = strconv.ParseInt(value, 10, 64)
		}
		if err == nil {
			if value := r.URL.Query().Get("limit"); value != "" {
				limit, err = strconv.Atoi(value)
			}
		}
		if err != nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		events, err := store.Events(r.Context(), after, limit)
		respond(w, http.StatusOK, events, err)
	})
	localPeerRoutes(mux, store)
	localNetworkRoutes(mux, store)
	localGovernanceRoutes(mux, store)
	localPersonRoutes(mux, store)
	localAdminRoutes(mux, store)
	localPolicyRoutes(mux, store)
	localAdapterRoutes(mux, store)
	localTaskRoutes(mux, store)
	return mux
}

// decode reads a strict JSON object of the allowed fields, without nulls;
// a field named with a trailing "?" may be null.
func decode(w http.ResponseWriter, r *http.Request, dst any, allowed ...string) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		respond(w, 0, nil, ErrInvalid)
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		respond(w, 0, nil, ErrInvalid)
		return false
	}
	if !utf8.Valid(raw) {
		respond(w, 0, nil, ErrInvalid)
		return false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		respond(w, 0, nil, ErrInvalid)
		return false
	}
	for field, value := range fields {
		known, nullable := false, false
		for _, name := range allowed {
			if field == strings.TrimSuffix(name, "?") {
				known, nullable = true, strings.HasSuffix(name, "?")
				break
			}
		}
		if !known || (!nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null"))) {
			respond(w, 0, nil, ErrInvalid)
			return false
		}
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		respond(w, 0, nil, ErrInvalid)
		return false
	}
	return true
}

func respond(w http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		code, message := "internal", "internal error"
		status = http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrInvalid):
			status, code, message = http.StatusBadRequest, "invalid", err.Error()
		case errors.Is(err, ErrForbidden):
			status, code, message = http.StatusForbidden, "forbidden", "forbidden"
		case errors.Is(err, ErrNotFound):
			status, code, message = http.StatusNotFound, "not_found", err.Error()
		case errors.Is(err, ErrConflict):
			status, code, message = http.StatusConflict, "conflict", err.Error()
		case errors.Is(err, ErrUnavailable), errors.Is(err, ErrAdapterOffline):
			status, code, message = http.StatusServiceUnavailable, "unavailable", err.Error()
		}
		value = struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}{code, message}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
