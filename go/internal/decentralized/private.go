package decentralized

import (
	"bytes"
	"encoding/json"
	"time"
)

const MaxPrivateRecord = 32 << 20

// ReadPrivateRecord decodes an owner-local persisted record with the fixed
// private budget. This is syntax only; it cannot turn remote proof metadata
// into local admission, consent, a clock guard or a selected provider.
func ReadPrivateRecord(raw []byte, names string, target any) error {
	o, e := parseLimit(raw, MaxPrivateRecord)
	if e != nil {
		return e
	}
	if fields(o, names) != nil {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return invalid()
	}
	return nil
}
func ValidPublicKey(public string) bool         { return key(public) }
func ValidID(id, prefix string) bool            { return identifier(id, prefix) }
func ParseTime(value string) (time.Time, error) { return stamp(value) }
func ValidStream(stream []string) bool          { return validStream(stream) }
