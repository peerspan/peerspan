package helper

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const maxCompletionBody int64 = 20 << 20
const activationPath = "/bootstrap/v1/activations"
const operationPrefix = "/bootstrap/v1/operations/"

// ParticipantRequest contains only server-derived TLS identity, literal route
// and exact bounded bytes. The host verifier must authenticate BOTH actual
// participants, consent, current or historical authority and atomic adoption.
// No asserted client identity, authority marker or local-admin router is used.
type ParticipantRequest struct {
	HostPublicKey string
	Method        string
	Path          string
	Body          []byte
}

type ParticipantResponse struct {
	Status int
	Body   []byte
}

// ParticipantCompletion is installed once before serving. Errors mean an
// unavailable carrier and close that connection; they are never fabricated
// authority outcomes. Returned JSON must fit the publication response bound.
type ParticipantCompletion func(context.Context, ParticipantRequest) (ParticipantResponse, error)

func (h *mailboxHandler) completionRoute(path string) bool {
	return h.completion != nil && (path == activationPath || strings.HasPrefix(path, operationPrefix))
}

func (h *mailboxHandler) serveCompletion(w http.ResponseWriter, r *http.Request, peer transportPeer) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.RequestURI != r.URL.Path {
		respondError(w, wireError("invalid"))
		return
	}
	method := http.MethodPost
	if r.URL.Path != activationPath {
		if !wireID(strings.TrimPrefix(r.URL.Path, operationPrefix), "link_") {
			respondError(w, wireError("invalid"))
			return
		}
		method = http.MethodGet
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		respondJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": "invalid", "error": "invalid", "required_ids": []string{}})
		return
	}
	if r.ContentLength < 0 || r.ContentLength > maxCompletionBody || !h.limits.reserve("receive", r.ContentLength) {
		respondError(w, wireError("quota_exceeded"))
		return
	}
	defer h.limits.release("receive", r.ContentLength)
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCompletionBody+1))
	if err != nil {
		var deadline net.Error
		if errors.As(err, &deadline) && deadline.Timeout() {
			panic(http.ErrAbortHandler)
		}
		respondError(w, wireError("invalid"))
		return
	}
	if int64(len(body)) != r.ContentLength || method == http.MethodGet && len(body) != 0 {
		respondError(w, wireError("invalid"))
		return
	}
	// Reserve the declared maximum before invoking the host, so concurrently
	// returned publications cannot accumulate outside the transport budget.
	if !h.limits.reserve("response", maxCompletionBody) {
		respondError(w, wireError("quota_exceeded"))
		return
	}
	if h.queuedResponse != nil {
		h.queuedResponse(maxCompletionBody)
	} else {
		defer h.limits.release("response", maxCompletionBody)
	}
	result, err := h.completion(r.Context(), ParticipantRequest{HostPublicKey: peer.key, Method: method, Path: r.URL.Path, Body: body})
	if err != nil || int64(len(result.Body)) > maxCompletionBody || !json.Valid(result.Body) {
		panic(http.ErrAbortHandler)
	}
	switch result.Status {
	case 200, 400, 403, 404, 409, 410, 429:
	default:
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(result.Body)))
	if result.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
}
