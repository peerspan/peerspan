package helper

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type transportPeer struct {
	key, source   string
	invalidHeader bool
}
type transportContextKey struct{}

type mailboxHandler struct {
	store          *resourceStore
	limits         *limits
	accounts       resourceAccounts
	completion     ParticipantCompletion
	completionOnly bool
	queuedResponse func(int64) // retain QUIC response credit until carrier closes
}

func respondJSON(w http.ResponseWriter, status int, value any) {
	b, err := json.Marshal(value)
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func respondError(w http.ResponseWriter, err error) {
	var code wireError
	if !errors.As(err, &code) {
		// Storage/clock/transport failure is an unavailable carrier, not a
		// fabricated authority answer. Do not expose SQLite or private paths.
		panic(http.ErrAbortHandler)
	}
	status := map[wireError]int{
		"invalid": 400, "forbidden": 403, "not_found": 404,
		"state_conflict": 409, "operation_conflict": 409,
		"quota_exceeded": 409, "expired": 410, "rate_limited": 429,
	}[code]
	if status == 0 {
		panic(http.ErrAbortHandler)
	}
	if status == 429 {
		w.Header().Set("Retry-After", "1")
	}
	respondJSON(w, status, struct {
		Code        string   `json:"code"`
		Error       string   `json:"error"`
		RequiredIDs []string `json:"required_ids"`
	}{string(code), string(code), []string{}})
}

func readCapability(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", wireError("forbidden")
	}
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || !wireID(strings.TrimPrefix(values[0], "Bearer "), "") {
		return "", wireError("invalid")
	}
	return values[0][len("Bearer "):], nil
}

func (accounts resourceAccounts) credential(value string, present bool) (string, error) {
	if !present {
		if accounts != nil {
			return "", wireError("forbidden")
		}
		return "", nil
	}
	token, err := canonicalBase64(value, 1024)
	if err != nil || len(token) == 0 || !validToken(token) {
		return "", wireError("invalid")
	}
	account, found := accounts[string(token)]
	if !found {
		return "", wireError("forbidden")
	}
	return account, nil
}

func (h *mailboxHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	peer, ok := r.Context().Value(transportContextKey{}).(transportPeer)
	if !ok {
		panic(http.ErrAbortHandler)
	}
	kind, rate, burst := "mutation", 2.0, 8.0
	if r.Method == http.MethodGet && !h.completionRoute(r.URL.Path) {
		kind, rate, burst = "get", 1, 4
	}
	if !h.limits.allow(kind, resourceKeys(peer.key, peer.source, ""), rate, burst, 0) {
		respondError(w, wireError("rate_limited"))
		return
	}
	if peer.invalidHeader {
		respondError(w, wireError("invalid"))
		return
	}
	if h.completionOnly && r.URL.Path != activationPath && (!strings.HasPrefix(r.URL.Path, operationPrefix) || !wireID(strings.TrimPrefix(r.URL.Path, operationPrefix), "link_")) {
		respondError(w, wireError("not_found"))
		return
	}
	if h.completionRoute(r.URL.Path) {
		h.serveCompletion(w, r, peer)
		return
	}
	if h.completionOnly {
		respondError(w, wireError("not_found"))
		return
	}
	const base = "/bootstrap/v1/mailboxes"
	path := r.URL.Path
	create, appendFrame, box := path == base, false, false
	locator := ""
	if strings.HasPrefix(path, base+"/") {
		parts := strings.Split(strings.TrimPrefix(path, base+"/"), "/")
		if len(parts) == 1 || len(parts) == 2 && parts[1] == "frames" {
			locator = parts[0]
			if !wireID(locator, "") || strings.Contains(r.RequestURI, "%") {
				respondError(w, wireError("invalid"))
				return
			}
			box, appendFrame = len(parts) == 1, len(parts) == 2
		}
	}
	if !create && !appendFrame && !box {
		respondError(w, wireError("not_found"))
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		respondError(w, wireError("invalid"))
		return
	}
	allow := "POST"
	validMethod := r.Method == http.MethodPost
	if box {
		allow = "GET, DELETE"
		validMethod = r.Method == http.MethodGet || r.Method == http.MethodDelete
	}
	if !validMethod {
		w.Header().Set("Allow", allow)
		respondJSON(w, 405, struct {
			Code        string   `json:"code"`
			Error       string   `json:"error"`
			RequiredIDs []string `json:"required_ids"`
		}{"invalid", "invalid", []string{}})
		return
	}
	capability, err := readCapability(r)
	if err != nil {
		respondError(w, err)
		return
	}
	values := r.Header.Values("X-Peerspan-Resource-Token")
	if len(values) > 1 {
		respondError(w, wireError("invalid"))
		return
	}
	value := ""
	if len(values) == 1 {
		value = values[0]
	}
	account, err := h.accounts.credential(value, len(values) == 1)
	if err != nil {
		respondError(w, err)
		return
	}
	if account != "" && !h.limits.allow(kind, []string{"account:" + account}, rate, burst, 0) {
		respondError(w, wireError("rate_limited"))
		return
	}
	now := time.Now()
	if create || appendFrame {
		if r.ContentLength < 0 || r.ContentLength > maxMutationBody || !h.limits.reserve("receive", r.ContentLength) {
			respondError(w, wireError("quota_exceeded"))
			return
		}
		defer h.limits.release("receive", r.ContentLength)
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxMutationBody+1))
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				panic(http.ErrAbortHandler)
			}
			respondError(w, wireError("invalid"))
			return
		}
		if len(raw) > maxMutationBody {
			respondError(w, wireError("quota_exceeded"))
			return
		}
		// Upload time cannot extend the fixed mailbox/FRAME lifetime.
		now = time.Now()
		if create {
			c, f, err := parseCreation(raw, peer.key, now)
			if err != nil {
				respondError(w, err)
				return
			}
			want := wireHash([]byte(capability))
			if subtle.ConstantTimeCompare([]byte(want), []byte(c.ReadCapHash)) != 1 {
				respondError(w, wireError("forbidden"))
				return
			}
			created, err := h.store.create(r.Context(), c, f, peer.source, account, now)
			if err != nil {
				respondError(w, err)
				return
			}
			status := http.StatusOK
			if created {
				status = http.StatusCreated
			}
			respondJSON(w, status, struct {
				RequestID string `json:"request_id"`
				Locator   string `json:"locator"`
			}{c.RequestID, c.Locator})
			return
		}
		var body struct {
			Frame json.RawMessage `json:"frame"`
		}
		if strictJSON(raw, &body) != nil {
			respondError(w, wireError("invalid"))
			return
		}
		f, err := parseCarrierFrame(body.Frame, peer.key)
		if err == nil && f.Locator != locator {
			err = wireError("invalid")
		}
		if err == nil {
			err = carrierWindow(f.Created, f.Expires, now)
		}
		if err == nil {
			err = h.store.append(r.Context(), f, capability, now)
		}
		if err != nil {
			respondError(w, err)
			return
		}
		respondJSON(w, 200, struct {
			FrameID string `json:"frame_id"`
		}{f.FrameID})
		return
	}
	var empty [1]byte
	if n, err := r.Body.Read(empty[:]); n != 0 || err != io.EOF {
		respondError(w, wireError("invalid"))
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.store.remove(r.Context(), locator, capability, now); err != nil {
			respondError(w, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	if !h.limits.reserve("response", maxGetBody) {
		respondError(w, wireError("quota_exceeded"))
		return
	}
	defer h.limits.release("response", maxGetBody)
	result, err := h.store.get(r.Context(), locator, capability, now)
	if err != nil {
		respondError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(result)))
	w.WriteHeader(200)
	_, _ = w.Write(result)
}
