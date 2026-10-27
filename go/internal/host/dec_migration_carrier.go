package host

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

const DecMigrationEvidenceFields = "proposal_base64 source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments_base64 commit_base64"

type decMigrationCarrier struct {
	Proposal        string          `json:"proposal_base64"`
	Source          string          `json:"source_catalog_base64"`
	State           string          `json:"source_state_base64"`
	Prepared        string          `json:"prepared_catalog_base64"`
	Acknowledgments json.RawMessage `json:"acknowledgments_base64"`
	Commit          string          `json:"commit_base64"`
}

func migrationCarrierBytes(value string, max int) (json.RawMessage, error) {
	if value == "-" {
		return json.RawMessage(`"-"`), nil
	}
	raw, e := decBytes(value, max)
	if e != nil {
		return nil, e
	}
	return json.RawMessage(raw), nil
}

func migrationCarrierString(raw []byte, max int) (string, error) {
	if bytes.Equal(raw, []byte(`"-"`)) {
		return "-", nil
	}
	if len(raw) == 0 || len(raw) > max {
		return "", decFailure("quota_exceeded")
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// The wire wrapper may be freely reserialized. Every public component remains
// an exact canonical Base64 string; none is decoded and reserialized as JSON.
func (input DecMigrationEvidence) MarshalJSON() ([]byte, error) {
	var w decMigrationCarrier
	var e error
	if w.Proposal, e = migrationCarrierString(input.Proposal, dec.MaxObject); e != nil {
		return nil, e
	}
	if w.Prepared, e = migrationCarrierString(input.Catalog, dec.MaxObject); e != nil {
		return nil, e
	}
	if w.Commit, e = migrationCarrierString(input.Commit, dec.MaxObject); e != nil {
		return nil, e
	}
	w.Source, w.State = input.Source, input.State
	for _, field := range []struct {
		value string
		max   int
	}{{w.Source, 512 << 10}, {w.State, dec.MaxPayload}} {
		if field.value != "-" {
			if _, e = decBytes(field.value, field.max); e != nil {
				return nil, e
			}
		}
	}
	if input.Acknowledgments == nil || len(input.Acknowledgments) > 4096 {
		return nil, decFailure("invalid")
	}
	acks := []string{}
	for _, raw := range input.Acknowledgments {
		value, e := migrationCarrierString(raw, dec.MaxObject)
		if e != nil {
			return nil, e
		}
		if value == "-" {
			return nil, decFailure("invalid")
		}
		acks = append(acks, value)
	}
	w.Acknowledgments, e = json.Marshal(acks)
	if e != nil {
		return nil, e
	}
	if w.Proposal == "-" && (w.Source != "-" || w.State != "-" || w.Prepared != "-" || len(acks) != 0 || w.Commit != "-") || w.Proposal != "-" && (w.Source == "-" || w.State == "-") || w.Prepared == "-" && (len(acks) != 0 || w.Commit != "-") {
		return nil, decFailure("invalid")
	}
	return json.Marshal(w)
}

func (input *DecMigrationEvidence) UnmarshalJSON(raw []byte) error {
	var w decMigrationCarrier
	if e := dec.ReadPrivateRecord(raw, DecMigrationEvidenceFields, &w); e != nil {
		return e
	}
	var next DecMigrationEvidence
	var e error
	if next.Proposal, e = migrationCarrierBytes(w.Proposal, dec.MaxObject); e != nil {
		return e
	}
	if next.Catalog, e = migrationCarrierBytes(w.Prepared, dec.MaxObject); e != nil {
		return e
	}
	if next.Commit, e = migrationCarrierBytes(w.Commit, dec.MaxObject); e != nil {
		return e
	}
	next.Source, next.State = w.Source, w.State
	for _, field := range []struct {
		value string
		max   int
	}{{w.Source, 512 << 10}, {w.State, dec.MaxPayload}} {
		if field.value != "-" {
			if _, e = decBytes(field.value, field.max); e != nil {
				return e
			}
		}
	}
	// Bound the count before materializing a potentially attacker-sized slice.
	reader := json.NewDecoder(bytes.NewReader(w.Acknowledgments))
	token, e := reader.Token()
	if e != nil || token != json.Delim('[') {
		return decFailure("invalid")
	}
	next.Acknowledgments = []json.RawMessage{}
	for reader.More() {
		if len(next.Acknowledgments) == 4096 {
			return decFailure("quota_exceeded")
		}
		var value string
		if reader.Decode(&value) != nil || value == "-" {
			return decFailure("invalid")
		}
		body, e := migrationCarrierBytes(value, dec.MaxObject)
		if e != nil {
			return e
		}
		next.Acknowledgments = append(next.Acknowledgments, body)
	}
	if token, e = reader.Token(); e != nil || token != json.Delim(']') {
		return decFailure("invalid")
	}
	if _, e = reader.Token(); e != io.EOF {
		return decFailure("invalid")
	}
	if w.Proposal == "-" && (w.Source != "-" || w.State != "-" || w.Prepared != "-" || len(next.Acknowledgments) != 0 || w.Commit != "-") || w.Proposal != "-" && (w.Source == "-" || w.State == "-") || w.Prepared == "-" && (len(next.Acknowledgments) != 0 || w.Commit != "-") {
		return decFailure("invalid")
	}
	*input = next
	return nil
}
