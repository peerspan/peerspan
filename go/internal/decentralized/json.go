// Package decentralized verifies the exact DEC protocol. Decoding never grants
// authority; current use also requires the independently admitted projection.
package decentralized

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/edwards25519"
	"github.com/peerspan/peerspan/go/internal/membership"
)

const (
	MaxObject         = 1 << 20
	MaxPayload        = 256 << 10
	MaxCatalog        = 16 << 20
	MaxDecodedCatalog = 8 << 20
	MaxObjects        = 4096
	MaxDepth          = 64
	MaxProbe          = 64 << 20
)

type Object map[string]json.RawMessage

func invalid() error             { return failure("invalid") }
func digest(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func message(s ...string) []byte { return []byte(strings.Join(s, "\n")) }
func identifier(s, prefix string) bool {
	if len(s) != len(prefix)+64 || !strings.HasPrefix(s, prefix) {
		return false
	}
	for _, c := range s[len(prefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func point(b []byte) bool {
	p, e := new(edwards25519.Point).SetBytes(b)
	return e == nil && bytes.Equal(p.Bytes(), b) && new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1
}
func key(s string) bool { b, e := membership.DecodeKey(s); return e == nil && point(b) }
func stamp(s string) (time.Time, error) {
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	if e != nil || t.Format("2006-01-02T15:04:05Z") != s || t.Year() < 1 {
		return t, invalid()
	}
	return t, nil
}
func decode(s string, max int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(max) {
		return nil, failure("quota_exceeded")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, invalid()
	}
	if len(b) > max {
		return nil, failure("quota_exceeded")
	}
	return b, nil
}

// Reject unpaired UTF-16 escapes before encoding/json can replace them with
// U+FFFD. Literal UTF-8 was checked separately. Paired surrogates remain valid.
func scalarEscapes(b []byte) bool {
	in := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			in = !in
			continue
		}
		if !in || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, e := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
			return false
		}
		low, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
		if e != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
func walk(d *json.Decoder, depth int) error {
	if depth > MaxDepth {
		return failure("quota_exceeded")
	}
	t, e := d.Token()
	if e != nil {
		return invalid()
	}
	switch x := t.(type) {
	case nil:
		return invalid()
	case json.Number:
		s := string(x)
		if s == "" || (len(s) > 1 && s[0] == '0') {
			return invalid()
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return invalid()
			}
		}
		if _, e := strconv.ParseUint(s, 10, 64); e != nil {
			return invalid()
		}
	case json.Delim:
		switch x {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return invalid()
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return invalid()
				}
				seen[s] = true
				if e = walk(d, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return invalid()
			}
		case '[':
			for d.More() {
				if e := walk(d, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return invalid()
			}
		default:
			return invalid()
		}
	case string, bool:
	default:
		return invalid()
	}
	return nil
}
func parse(b []byte) (Object, error) { return parseLimit(b, MaxObject) }
func parseLimit(b []byte, limit int) (Object, error) {
	if len(b) > limit {
		return nil, failure("quota_exceeded")
	}
	if !utf8.Valid(b) || !scalarEscapes(b) {
		return nil, invalid()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := walk(d, 0); e != nil {
		return nil, e
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, invalid()
	}
	var o Object
	if e := json.Unmarshal(b, &o); e != nil || o == nil {
		return nil, invalid()
	}
	return o, nil
}
func fields(o Object, required string, optional ...string) error {
	allowed := map[string]bool{}
	for _, s := range strings.Fields(required) {
		allowed[s] = true
		if _, ok := o[s]; !ok {
			return invalid()
		}
	}
	for _, s := range optional {
		allowed[s] = true
	}
	for s := range o {
		if !allowed[s] {
			return invalid()
		}
	}
	return nil
}
func text(o Object, k string) (string, error) {
	var s string
	if e := json.Unmarshal(o[k], &s); e != nil || strings.ContainsAny(s, "\r\n\x00") {
		return "", invalid()
	}
	return s, nil
}
func num(o Object, k string) (uint64, error) {
	b := bytes.TrimSpace(o[k])
	if len(b) == 0 || b[0] < '0' || b[0] > '9' {
		return 0, invalid()
	}
	v, e := strconv.ParseUint(string(b), 10, 64)
	if e != nil {
		return 0, invalid()
	}
	return v, nil
}

func texts(o Object, keys ...string) ([]string, error) {
	out := []string{}
	for _, k := range keys {
		s, e := text(o, k)
		if e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, nil
}
func version(o Object, n uint64) error {
	v, e := num(o, "format")
	if e != nil || v != n {
		return invalid()
	}
	return nil
}
func stringsOf(o Object, k string) ([]string, error) {
	var a []string
	if e := json.Unmarshal(o[k], &a); e != nil || a == nil {
		return nil, invalid()
	}
	if len(a) > MaxObjects {
		return nil, failure("quota_exceeded")
	}
	return a, nil
}
func sorted(a []string) bool {
	for i, s := range a {
		if strings.ContainsAny(s, "\r\n\x00") || i > 0 && a[i-1] >= s {
			return false
		}
	}
	return true
}
