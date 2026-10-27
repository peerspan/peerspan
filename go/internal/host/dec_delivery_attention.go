package host

import (
	"encoding/json"
	"errors"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

func decAddNext(view *DecLinkView, next string) {
	if !containsString(view.Next, next) {
		view.Next = append(view.Next, next)
	}
}

// Delivery failure after a committed local stage cannot erase that stage or
// hide the exact request code behind an uncommitted-looking HTTP refusal.
func decPublicationAttention(view DecLinkView, e error) DecLinkView {
	code := dec.Code(e)
	switch code {
	case "invalid", "forbidden", "not_found", "state_conflict", "operation_conflict", "quota_exceeded", "expired", "rate_limited", "authority_expired", "device_revoked", "proof_required", "signer_unavailable", "recovery_required", "review_required", "clock_rollback", "internal":
	default:
		code = "unavailable"
	}
	prefix := "publication_"
	var stage interface{ decErrorStage() string }
	if errors.As(e, &stage) && stage.decErrorStage() == "transport" {
		prefix = "transport_"
	}
	attention := prefix + code
	if !containsString(view.Attention, attention) {
		view.Attention = append(view.Attention, attention)
	}
	decAddNext(&view, "resume")
	return view
}

func decRequestPublicationAttention(raw json.RawMessage, e error) (json.RawMessage, error) {
	var view DecLinkView
	if json.Unmarshal(raw, &view) != nil {
		return nil, decStorageError()
	}
	view = decPublicationAttention(view, e)
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, decStorageError()
	}
	fields["attention"], _ = json.Marshal(view.Attention)
	fields["next"], _ = json.Marshal(view.Next)
	return json.Marshal(fields)
}
