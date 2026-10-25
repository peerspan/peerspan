package host

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// Resource bounds (capabilities slice 3): a capability may restrict the
// values of named top-level arguments of its tool operations. A bound is a
// list of combinations; a call passes when every argument one combination
// names is present as a matching string.

const (
	boundMaxCombinations = 16
	boundMaxEntries      = 4
	boundMaxValue        = 256
)

var boundName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// BoundCombination maps argument names to the one value each must have.
type BoundCombination map[string]string

// CapabilityBounds is a capability's bounds: {} for none, or
// {"arguments": [...]}.
type CapabilityBounds struct {
	Arguments []BoundCombination
}

func (b CapabilityBounds) MarshalJSON() ([]byte, error) {
	if len(b.Arguments) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(struct {
		Arguments []BoundCombination `json:"arguments"`
	}{b.Arguments})
}

// UnmarshalJSON reads bounds leniently, as stored or as listed by a peer:
// null or {} is no bound.
func (b *CapabilityBounds) UnmarshalJSON(data []byte) error {
	*b = CapabilityBounds{}
	if string(bytes.TrimSpace(data)) == "null" {
		return nil
	}
	var raw struct {
		Arguments []BoundCombination `json:"arguments"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	b.Arguments = raw.Arguments
	return nil
}

// Set reports whether there is a bound.
func (b CapabilityBounds) Set() bool { return len(b.Arguments) > 0 }

func (b CapabilityBounds) equal(o CapabilityBounds) bool {
	x, _ := json.Marshal(b)
	y, _ := json.Marshal(o)
	return bytes.Equal(x, y)
}

// parseBounds reads the bounds of POST /v1/capabilities strictly: absent,
// {}, or {"arguments": [COMBINATION, ...]}.
func parseBounds(raw json.RawMessage) (CapabilityBounds, error) {
	invalid := func(detail string) (CapabilityBounds, error) {
		return CapabilityBounds{}, fmt.Errorf("%w: bounds %s", ErrInvalid, detail)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return CapabilityBounds{}, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return invalid("is {} or {\"arguments\": [...]}")
	}
	if len(top) == 0 {
		return CapabilityBounds{}, nil
	}
	list, ok := top["arguments"]
	if !ok || len(top) != 1 {
		return invalid("has only arguments")
	}
	var combos []json.RawMessage
	if err := json.Unmarshal(list, &combos); err != nil || combos == nil {
		return invalid("arguments is a list of combinations")
	}
	if len(combos) < 1 || len(combos) > boundMaxCombinations {
		return invalid(fmt.Sprintf("arguments holds 1 to %d combinations", boundMaxCombinations))
	}
	out := CapabilityBounds{}
	for _, item := range combos {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil || fields == nil {
			return invalid("combinations are objects")
		}
		if len(fields) < 1 || len(fields) > boundMaxEntries {
			return invalid(fmt.Sprintf("combinations name 1 to %d arguments", boundMaxEntries))
		}
		combo := BoundCombination{}
		for name, value := range fields {
			if !boundName.MatchString(name) {
				return invalid(fmt.Sprintf("argument name %q does not match [A-Za-z_][A-Za-z0-9_]{0,63}", name))
			}
			s, ok := jsonString(value)
			if !ok {
				return invalid(fmt.Sprintf("value of %s is a string", name))
			}
			if !validBoundValue(s) {
				return invalid(fmt.Sprintf("value of %s is 1 to %d bytes without control characters", name, boundMaxValue))
			}
			combo[name] = s
		}
		out.Arguments = append(out.Arguments, combo)
	}
	return out, nil
}

func validBoundValue(s string) bool {
	if s == "" || len(s) > boundMaxValue || !utf8.ValidString(s) {
		return false
	}
	return !hasControl(s)
}

// hasControl reports a character below U+0020 or U+007F.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func sortedCombo(c BoundCombination) []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// boundNames lists every name in order of first appearance: the first
// combination's, then each later combination's new ones, each in byte order.
func (b CapabilityBounds) boundNames() []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range b.Arguments {
		for _, k := range sortedCombo(c) {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// allowedText is ALLOWED: the combinations joined by " or ", each as
// "KEY is VALUE" joined by " and ".
func (b CapabilityBounds) allowedText() string {
	parts := make([]string, 0, len(b.Arguments))
	for _, c := range b.Arguments {
		var entries []string
		for _, k := range sortedCombo(c) {
			entries = append(entries, k+" is "+c[k])
		}
		parts = append(parts, strings.Join(entries, " and "))
	}
	return strings.Join(parts, " or ")
}

// BoundsAllowedText is ALLOWED for the CLI.
func BoundsAllowedText(b CapabilityBounds) string { return b.allowedText() }

// ghRepoWildcard reports whether a gh repo bound value is OWNER/*.
func ghRepoWildcard(value string) (string, bool) {
	owner, rest, ok := strings.Cut(value, "/")
	return owner, ok && rest == "*"
}

var ghOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

// matchBoundValue matches one input value against a bound value: exactly,
// or for a gh source's repo, ignoring ASCII case, with OWNER/*.
func matchBoundValue(gh bool, name, bound, got string) bool {
	if !gh || name != "repo" {
		return bound == got
	}
	if owner, wild := ghRepoWildcard(bound); wild {
		gotOwner, rest, ok := strings.Cut(got, "/")
		return ok && rest != "" && strings.EqualFold(owner, gotOwner)
	}
	return asciiEqualFold(bound, got)
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// checkBounds checks a call's input against a capability's bounds, and
// returns the out_of_bounds refusal when it fails.
func checkBounds(b CapabilityBounds, gh bool, input json.RawMessage) error {
	if !b.Set() {
		return nil
	}
	var args map[string]json.RawMessage
	_ = json.Unmarshal(input, &args)
	for _, c := range b.Arguments {
		ok := true
		for name, want := range c {
			raw, present := args[name]
			got, isString := jsonString(raw)
			if !present || !isString || !matchBoundValue(gh, name, want, got) {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
	}
	var got []string
	for _, name := range b.boundNames() {
		raw, present := args[name]
		s, isString := jsonString(raw)
		switch {
		case !present:
			got = append(got, "no "+name)
		case !isString:
			got = append(got, "a non-string "+name)
		default:
			got = append(got, name+" "+resultTextString(s))
		}
	}
	text := "This capability is limited to calls where " + b.allowedText() + ". The call has " + strings.Join(got, " and ") + ". Nothing was run."
	return &codedError{status: http.StatusForbidden, code: "out_of_bounds", message: text, bounds: &b}
}

// resultTextString encodes a string as the call view's result text does:
// raw UTF-8, escaping only ", \, and characters below U+0020.
func resultTextString(s string) string {
	var buf strings.Builder
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return buf.String()
}

// errBoundUnenforceable is the refusal for an operation that cannot carry a
// bound.
func errBoundUnenforceable(op, key string) error {
	return &codedError{status: http.StatusBadRequest, code: "bound_unenforceable", message: "Operation " + op + " has no string argument " + key + ", so Peerspan cannot check this bound for it. Leave the operation out, or narrow the credential instead (--env-file)."}
}

// schemaProperties reads the top-level properties of an input schema.
func schemaProperties(schema json.RawMessage) map[string]json.RawMessage {
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(schema, &s) != nil {
		return nil
	}
	return s.Properties
}

// stringProperty reports whether a schema declares name as a top-level
// property of type "string".
func stringProperty(schema json.RawMessage, name string) bool {
	raw, ok := schemaProperties(schema)[name]
	if !ok {
		return false
	}
	var p struct {
		Type json.RawMessage `json:"type"`
	}
	return json.Unmarshal(raw, &p) == nil && string(bytes.TrimSpace(p.Type)) == `"string"`
}

// checkBoundsAtCreate checks a new capability's bounds: gh repo values,
// at least one tool operation, and each operation declaring each bound
// argument as a string.
func checkBoundsAtCreate(b CapabilityBounds, gh bool, operations []string, snap toolSnapshotState) error {
	if !b.Set() {
		return nil
	}
	if gh {
		for _, c := range b.Arguments {
			if v, ok := c["repo"]; ok {
				owner, wild := ghRepoWildcard(v)
				if !(wild && ghOwnerPattern.MatchString(owner)) && !validGHRepo(v) {
					return &codedError{status: http.StatusBadRequest, code: "invalid", message: "A gh repository bound is OWNER/REPO or OWNER/*."}
				}
			}
		}
	}
	if len(operations) == 0 {
		return &codedError{status: http.StatusBadRequest, code: "invalid", message: "A bound applies to tool operations, and the capability has none."}
	}
	names := b.boundNames()
	for _, op := range operations {
		t, _ := snapshotTool(snap, op)
		for _, name := range names {
			if !stringProperty(t.InputSchema, name) {
				return errBoundUnenforceable(op, name)
			}
		}
	}
	return nil
}

// narrowSchema narrows a listed tool operation's input schema to a bound:
// a single argument with exact values becomes an enum, otherwise each bound
// property's description names the allowed values.
func narrowSchema(schema json.RawMessage, b CapabilityBounds, gh bool) json.RawMessage {
	if !b.Set() {
		return schema
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(schema, &top) != nil || top == nil {
		return schema
	}
	var props map[string]json.RawMessage
	if json.Unmarshal(top["properties"], &props) != nil || props == nil {
		return schema
	}
	single := ""
	enum := true
	var values []string
	for i, c := range b.Arguments {
		if len(c) != 1 {
			enum = false
			break
		}
		for k, v := range c {
			if i == 0 {
				single = k
			}
			if k != single {
				enum = false
			}
			if _, wild := ghRepoWildcard(v); gh && k == "repo" && wild {
				enum = false
			}
			if !slices.Contains(values, v) {
				values = append(values, v)
			}
		}
	}
	if enum {
		if _, ok := props[single]; ok {
			props[single], _ = json.Marshal(map[string]any{"type": "string", "enum": values})
		}
	} else {
		sentence := "Limited by the owner: " + b.allowedText() + "."
		for _, name := range b.boundNames() {
			raw, ok := props[name]
			if !ok {
				continue
			}
			var p map[string]json.RawMessage
			if json.Unmarshal(raw, &p) != nil || p == nil {
				continue
			}
			desc, ok := jsonString(p["description"])
			if ok {
				desc += " " + sentence
			} else {
				desc = sentence
			}
			p["description"], _ = json.Marshal(desc)
			props[name], _ = json.Marshal(p)
		}
	}
	top["properties"], _ = json.Marshal(props)
	out, err := json.Marshal(top)
	if err != nil {
		return schema
	}
	return out
}

// jsonString reads a JSON string; null and every other type are not one.
func jsonString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	var s string
	if len(trimmed) == 0 || trimmed[0] != '"' || json.Unmarshal(trimmed, &s) != nil {
		return "", false
	}
	return s, true
}
