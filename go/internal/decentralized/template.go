package decentralized

import (
	"bytes"
	"encoding/json"
	"sort"
)

// ReadStatementTemplate is an ephemeral typed-intent reader. Unfilled declared
// signature positions may be '-', but roles, key identities, formats and every
// payload field remain strict. It makes no signed proof/admission claim.
func ReadStatementTemplate(d Descriptor, raw []byte) (*Statement, error) {
	return readStatementMode(d, raw, false, true)
}

func StatementTemplate(d Descriptor, kind string, payload []byte, signatures []Signature) ([]byte, error) {
	signatures = append([]Signature{}, signatures...)
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].Role < signatures[j].Role })
	raw, e := json.Marshal(struct {
		Format     uint64      `json:"format"`
		Kind       string      `json:"kind"`
		Context    string      `json:"context_id"`
		Payload    string      `json:"payload_base64"`
		Signatures []Signature `json:"signatures"`
	}{1, kind, d.ContextID, b64(payload), signatures})
	if e != nil {
		return nil, e
	}
	if _, e = ReadStatementTemplate(d, raw); e != nil {
		return nil, e
	}
	return raw, nil
}

// FillStatementTemplate replaces only the declared signature string spans in
// the exact saved template. It preserves payload and outer bytes across Go/Rust
// reopen and never normalizes a filled signature alias or an exact proof ID.
func FillStatementTemplate(d Descriptor, raw []byte, filled map[string]string) ([]byte, error) {
	statement, e := ReadStatementTemplate(d, raw)
	if e != nil {
		return nil, e
	}
	known := map[string]Signature{}
	for _, signature := range statement.Signatures {
		known[signature.Role] = signature
	}
	for role, signature := range filled {
		expected, ok := known[role]
		if !ok || signature == "-" {
			return nil, invalid()
		}
		if expected.Signature != "-" && expected.Signature != signature {
			return nil, failure("operation_conflict")
		}
		if e = VerifySignature(expected.PublicKey, expected.Format, SignatureMessage(statement.ID, role, expected.PublicKey), signature); e != nil {
			return nil, e
		}
	}
	type span struct {
		start, end int
		value      []byte
	}
	spans := []span{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if _, e = decoder.Token(); e != nil {
		return nil, invalid()
	}
	for decoder.More() {
		key, e := decoder.Token()
		if e != nil {
			return nil, invalid()
		}
		if key != "signatures" {
			var skip json.RawMessage
			if decoder.Decode(&skip) != nil {
				return nil, invalid()
			}
			continue
		}
		if _, e = decoder.Token(); e != nil {
			return nil, invalid()
		}
		index := 0
		for decoder.More() {
			var entry json.RawMessage
			if decoder.Decode(&entry) != nil {
				return nil, invalid()
			}
			entryStart := int(decoder.InputOffset()) - len(entry)
			role := statement.Signatures[index].Role
			index++
			value, ok := filled[role]
			if !ok {
				continue
			}
			inner := json.NewDecoder(bytes.NewReader(entry))
			if _, e = inner.Token(); e != nil {
				return nil, invalid()
			}
			for inner.More() {
				key, e := inner.Token()
				if e != nil {
					return nil, invalid()
				}
				var field json.RawMessage
				if inner.Decode(&field) != nil {
					return nil, invalid()
				}
				if key == "signature" {
					end := entryStart + int(inner.InputOffset())
					encoded, _ := json.Marshal(value)
					spans = append(spans, span{end - len(field), end, encoded})
				}
			}
		}
		if _, e = decoder.Token(); e != nil {
			return nil, invalid()
		}
	}
	result := append([]byte{}, raw...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	for _, change := range spans {
		next := make([]byte, 0, len(result)+len(change.value)-(change.end-change.start))
		next = append(next, result[:change.start]...)
		next = append(next, change.value...)
		next = append(next, result[change.end:]...)
		result = next
	}
	if _, e = ReadStatementTemplate(d, result); e != nil {
		return nil, e
	}
	return result, nil
}
