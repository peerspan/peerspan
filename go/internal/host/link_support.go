package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkDetails struct {
	RequestID   string   `json:"request_id"`
	Stage       string   `json:"stage"`
	RequiredIDs []string `json:"required_ids"`
	Next        []string `json:"next"`
}
type linkFailure struct {
	Code       string      `json:"code"`
	Message    string      `json:"error"`
	Details    linkDetails `json:"details"`
	Status     int         `json:"-"`
	RetryAfter int64       `json:"-"`
	// Set only after a strict authenticated coordinator HTTP refusal.
	coordinatorResponse bool
}

func (e *linkFailure) Error() string { return "linking: " + e.Code }
func linkFail(code, request, stage string, required ...string) *linkFailure {
	if request == "" {
		request = "-"
	}
	if stage == "" {
		stage = "-"
	}
	status := map[string]int{"invalid": 400, "forbidden": 403, "authority_expired": 403, "device_revoked": 403, "authority_would_be_invalidated": 403, "not_found": 404, "operation_conflict": 409, "state_conflict": 409, "quota_exceeded": 409, "proof_required": 409, "expired": 410, "deleted": 410, "upgrade_required": 426, "rate_limited": 429, "internal": 500, "unavailable": 503}[code]
	if status == 0 {
		status = 500
		code = "internal"
	}
	ids := append([]string{}, required...)
	return &linkFailure{Code: code, Message: strings.ReplaceAll(code, "_", " "), Status: status, Details: linkDetails{RequestID: request, Stage: stage, RequiredIDs: ids, Next: []string{}}}
}
func linkCause(err error, request, stage string) *linkFailure {
	if errors.Is(err, membership.ErrAccessVersionExhausted) {
		failure := linkFail("quota_exceeded", request, stage)
		failure.Message = "access version exhausted"
		return failure
	}
	var failure *linkFailure
	if errors.As(err, &failure) {
		copy := *failure
		if copy.Details.RequestID == "-" && request != "" {
			copy.Details.RequestID = request
		}
		return &copy
	}
	var path *linking.PathError
	if errors.As(err, &path) {
		return linkFail(path.Code, request, stage, path.RequiredIDs...)
	}
	var invalidate *linking.ActionInvalidation
	if errors.As(err, &invalidate) {
		return linkFail("authority_would_be_invalidated", request, stage, invalidate.CertificateIDs...)
	}
	code := "internal"
	switch {
	case errors.Is(err, ErrInvalid), errors.Is(err, membership.ErrInvalid):
		code = "invalid"
	case errors.Is(err, ErrForbidden):
		code = "forbidden"
	case errors.Is(err, ErrNotFound):
		code = "not_found"
	case errors.Is(err, ErrConflict):
		code = "state_conflict"
	case errors.Is(err, ErrUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		code = "unavailable"
	}
	return linkFail(code, request, stage)
}
func respondLink(w http.ResponseWriter, status int, value any, err error, request, stage string) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		failure := linkCause(err, request, stage)
		if failure.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(failure.RetryAfter, 10))
		}
		w.WriteHeader(failure.Status)
		_ = json.NewEncoder(w).Encode(failure)
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func linkStamp(value string) (time.Time, error) {
	t, e := time.Parse("2006-01-02T15:04:05Z", value)
	if e != nil || len(value) != 20 || t.UTC().Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, linkFail("invalid", "-", "clock")
	}
	return t, nil
}
func linkTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
func linkNow() (time.Time, error) {
	if os.Getenv("PEERSPAN_LINK_TEST_MODE") == "1" && os.Getenv("PEERSPAN_LINK_TEST_CLOCK_FILE") != "" {
		b, e := os.ReadFile(os.Getenv("PEERSPAN_LINK_TEST_CLOCK_FILE"))
		if e != nil {
			return time.Time{}, linkFail("internal", "-", "clock")
		}
		value := strings.TrimSuffix(string(b), "\n")
		t, e := linkStamp(value)
		if e != nil {
			return time.Time{}, linkFail("internal", "-", "clock")
		}
		return t, nil
	}
	return time.Now().UTC().Truncate(time.Second), nil
}

// LinkingDecisionTime supplies the local decision clock for CLI-side creation
// and validation of feature-bound invitations. Network inputs cannot set it.
func LinkingDecisionTime() (time.Time, error) {
	return linkNow()
}

func linkBarrier(ctx context.Context, name, request string) error {
	if os.Getenv("PEERSPAN_LINK_TEST_MODE") != "1" {
		return nil
	}
	dir := os.Getenv("PEERSPAN_LINK_TEST_BARRIER_DIR")
	if dir == "" {
		return nil
	}
	arm := filepath.Join(dir, name+".arm")
	if _, e := os.Stat(arm); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return linkFail("internal", request, "barrier")
	}
	if e := os.WriteFile(filepath.Join(dir, name+".entered"), []byte(request), 0600); e != nil {
		return linkFail("internal", request, "barrier")
	}
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		if _, e := os.Stat(filepath.Join(dir, name+".continue")); e == nil {
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return linkFail("internal", request, "barrier")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func linkNetworkDescriptor(n Network) map[string]any {
	return map[string]any{"network_id": n.ID, "name": n.Name, "genesis_root_public_key": n.RootPublicKey, "coordinator_address": n.CoordinatorAddress, "coordinator_public_key": n.CoordinatorPublicKey}
}
func linkFingerprint(public string) string {
	b, e := membership.DecodeKey(public)
	if e != nil {
		return "-"
	}
	digest := sha256.Sum256(b)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}
