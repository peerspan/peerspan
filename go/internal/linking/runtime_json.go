package linking

import "encoding/json"

func decodeRuntimeJSON(raw []byte, required string, dst any, limit int) error {
	o, err := parseLimit(raw, limit)
	if err != nil || fields(o, required) != nil {
		return invalid()
	}
	if err = json.Unmarshal(raw, dst); err != nil {
		return invalid()
	}
	return nil
}

// DecodeMutation checks strict runtime request JSON under the fixed 1 MiB
// bound. It does not verify signatures or authorize any operation.
func DecodeMutation(raw []byte, required string, dst any) error {
	return decodeRuntimeJSON(raw, required, dst, MaxObject)
}

// DecodeStoredJSON checks private persisted records that retain original public
// bytes through Base64, under a fixed 32 MiB bound. It is never a mutation or
// network response limit; callers enforce their smaller transport bounds first.
// Parsing does not establish authority or replace signed-catalog verification.
func DecodeStoredJSON(raw []byte, required string, dst any) error {
	return decodeRuntimeJSON(raw, required, dst, 32<<20)
}
