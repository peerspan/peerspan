// Package linking reads signed objects and evaluates exact certificate paths.
// Signature verification alone does not establish live authority. Path evaluation
// requires independently verified state and does not authorize a mutation.
package linking

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/edwards25519"
	"github.com/peerspan/peerspan/go/internal/membership"
)

const MaxObject = 1 << 20
const MaxPayload = 256 << 10
const MaxDepth = 64

type Object map[string]json.RawMessage

// SignedObject retains the exact signed message and payload. It is NOT an
// authorization decision. The caller must resolve authority independently.
type SignedObject struct {
	Message []byte
	ID      string
	Payload []byte
}

func invalid() error             { return fmt.Errorf("%w: invalid linking signed object", membership.ErrInvalid) }
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
	if e != nil || t.Format("2006-01-02T15:04:05Z") != s {
		return t, invalid()
	}
	return t, nil
}
func decode(s string, max int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(max) {
		return nil, invalid()
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) > max || base64.StdEncoding.EncodeToString(b) != s {
		return nil, invalid()
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
		return invalid()
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
	if len(b) > limit || !utf8.Valid(b) || !scalarEscapes(b) {
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
	if e := json.Unmarshal(o[k], &a); e != nil || a == nil || len(a) > 4096 {
		return nil, invalid()
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
func rootSignature(k string, m []byte, s string) error {
	b, e := decode(s, MaxObject)
	if e != nil {
		return e
	}
	if len(b) == 64 {
		return rawSignature(k, m, s)
	}
	if !key(k) {
		return invalid()
	}
	return personSignature(k, m, s)
}
func rawSignature(k string, m []byte, s string) error {
	pub, e := membership.DecodeKey(k)
	if e != nil {
		return invalid()
	}
	sig, e := decode(s, 64)
	if e != nil || len(sig) != 64 || !point(sig[:32]) || !ed25519.Verify(pub, m, sig) {
		return invalid()
	}
	return nil
}
func personSignature(k string, m []byte, s string) error {
	if !key(k) {
		return invalid()
	}
	pub, e := membership.DecodeKey(k)
	if e != nil {
		return invalid()
	}
	if e = membership.VerifySSHSIG(pub, m, s); e != nil {
		return e
	}
	blob, e := decode(s, MaxObject)
	if e != nil || len(blob) < 64 || !point(blob[len(blob)-64:len(blob)-32]) {
		return invalid()
	}
	return nil
}

func scope(o Object) (string, error) {
	n, e := num(o, "scopes")
	if e != nil || n == 0 || n > 15 {
		return "", invalid()
	}
	return strconv.FormatUint(n, 10), nil
}
func rootPerson(person, cert, signer string) bool {
	return key(person) && (cert == "root" && person == signer || identifier(cert, "dc_"))
}

// Read verifies one signed object's byte-level shape and signatures using
// externally resolved expected keys. The returned ID does not activate it.
func Read(kind string, data []byte, signer, device string) (SignedObject, error) {
	o, e := parse(data)
	if e != nil || !key(signer) || (kind != "packet" && device != "-") {
		return SignedObject{}, invalid()
	}
	var r SignedObject
	switch kind {
	case "certificate":
		r, e = certificate(o, signer)
	case "person_record":
		r, e = record(o, signer, false)
	case "root_record":
		r, e = record(o, signer, true)
	case "device_revocation":
		r, e = revocation(o, signer)
	case "checkpoint":
		r, e = checkpoint(o, signer)
	case "packet":
		r, e = packet(o, signer, device)
	case "feature_proposal":
		r, e = proposal(o, signer)
	case "feature_ack":
		r, e = ack(o, signer)
	case "feature":
		r, e = feature(o, signer)
	case "admin_removal_v2":
		r, e = adminRemoval(o, signer)
	default:
		e = invalid()
	}
	if e != nil {
		return SignedObject{}, e
	}
	if r.ID == "" {
		r.ID = "-"
	}
	return r, nil
}
func certificate(o Object, signer string) (SignedObject, error) {
	if fields(o, "format network_id person_public_key device_public_key host_public_key parent_id scopes issued_at not_after request_id signature") != nil || version(o, 1) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "network_id", "person_public_key", "device_public_key", "host_public_key", "parent_id")
	if e != nil {
		return SignedObject{}, e
	}
	sc, e := scope(o)
	if e != nil {
		return SignedObject{}, e
	}
	b, e := texts(o, "issued_at", "not_after", "request_id", "signature")
	if e != nil {
		return SignedObject{}, e
	}
	start, e := stamp(b[0])
	if e != nil {
		return SignedObject{}, e
	}
	end, e := stamp(b[1])
	if e != nil || !end.After(start) || end.Sub(start) > 90*24*time.Hour {
		return SignedObject{}, invalid()
	}
	if !identifier(a[0], "net_") || !key(a[1]) || !key(a[2]) || !key(a[3]) || a[1] == a[2] || a[2] == a[3] || !(a[4] == "root" && signer == a[1] || identifier(a[4], "dc_")) || !identifier(b[2], "link_") {
		return SignedObject{}, invalid()
	}
	m := message(append(append([]string{"peerspan-device-certificate-v1"}, a...), sc, b[0], b[1], b[2])...)
	if e = personSignature(signer, m, b[3]); e != nil {
		return SignedObject{}, e
	}
	return SignedObject{Message: m, ID: "dc_" + digest(m)}, nil
}
func payload(o Object) ([]byte, Object, error) {
	s, e := text(o, "payload_base64")
	if e != nil {
		return nil, nil, e
	}
	b, e := decode(s, MaxPayload)
	if e != nil {
		return nil, nil, e
	}
	p, e := parse(b)
	return b, p, e
}
func record(o Object, signer string, root bool) (SignedObject, error) {
	names := "format kind network_id epoch operation_id payload_base64 signature"
	if !root {
		names += " person_public_key certificate_id host_signature"
	}
	if fields(o, names) != nil || version(o, 1) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "kind", "network_id", "operation_id", "signature")
	if e != nil {
		return SignedObject{}, e
	}
	epoch, e := num(o, "epoch")
	if e != nil || !identifier(a[1], "net_") || !(a[2] == "-" || identifier(a[2], "link_")) {
		return SignedObject{}, invalid()
	}
	b, p, e := payload(o)
	if e != nil {
		return SignedObject{}, e
	}
	if e = recordPayload(a[0], p); e != nil {
		return SignedObject{}, e
	}
	net, e := text(p, "network_id")
	if e != nil || net != a[1] {
		return SignedObject{}, invalid()
	}
	if _, ok := p["epoch"]; ok {
		n, e := num(p, "epoch")
		if e != nil || n != epoch {
			return SignedObject{}, invalid()
		}
	}
	if _, ok := p["invite_epoch"]; ok {
		n, e := num(p, "invite_epoch")
		if e != nil || n != epoch {
			return SignedObject{}, invalid()
		}
	}
	epochText := strconv.FormatUint(epoch, 10)
	if root {
		if a[0] != "peerspan-host-admit-v1" || a[2] == "-" {
			return SignedObject{}, invalid()
		}
		m := message("peerspan-root-authorization-v1", a[0], a[1], epochText, a[2], digest(b))
		if e = rootSignature(signer, m, a[3]); e != nil {
			return SignedObject{}, e
		}
		return SignedObject{Message: m, ID: "rr_" + digest(message("peerspan-root-authorized-record-v1", digest(m), a[3])), Payload: b}, nil
	}
	ctx, e := texts(o, "person_public_key", "certificate_id", "host_signature")
	if e != nil || !rootPerson(ctx[0], ctx[1], signer) {
		return SignedObject{}, invalid()
	}
	if strings.HasPrefix(a[0], "peerspan-policy-") || a[0] == "peerspan-host-bind-v1" || a[0] == "peerspan-host-unbind-v1" {
		person, e := text(p, "person_public_key")
		if e != nil || person != ctx[0] {
			return SignedObject{}, invalid()
		}
	}
	m := message("peerspan-person-authorization-v1", a[0], a[1], epochText, a[2], ctx[0], ctx[1], digest(b))
	if e = personSignature(signer, m, a[3]); e != nil {
		return SignedObject{}, e
	}
	if a[0] == "peerspan-host-bind-v1" {
		host, e := text(p, "host_public_key")
		if e != nil {
			return SignedObject{}, e
		}
		if e = rawSignature(host, message("peerspan-binding-consent-v1", digest(m)), ctx[2]); e != nil {
			return SignedObject{}, e
		}
	} else if ctx[2] != "-" {
		return SignedObject{}, invalid()
	}
	return SignedObject{Message: m, ID: "ar_" + digest(message("peerspan-authorized-record-v1", digest(m), a[3], ctx[2])), Payload: b}, nil
}
func recordPayload(kind string, p Object) error {
	shapes := map[string]string{
		"peerspan-host-bind-v1": "network_id person_public_key host_public_key bound_at", "peerspan-host-unbind-v1": "network_id person_public_key host_public_key unbound_at", "peerspan-host-admit-v1": "network_id epoch host_public_key member admitted_at", "peerspan-person-admit-v1": "network_id epoch person_public_key member admitted_at", "peerspan-person-remove-v1": "network_id person_public_key removed_at", "peerspan-revoke-host-v1": "network_id host_public_key revoked_at", "peerspan-revoke-invite-v1": "network_id invite_public_key revoked_at", "peerspan-invite-v1": "network_id invite_public_key member invite_expires_at", "peerspan-person-invite-v1": "network_id invite_epoch invite_public_key member invite_expires_at", "peerspan-group-v1": "network_id name version defined_at members",
	}
	if kind == "peerspan-policy-v1" || kind == "peerspan-policy-v2" {
		names := "network_id person_public_key version issued_at valid_until rules"
		if kind == "peerspan-policy-v2" {
			names += " format"
			if version(p, 2) != nil {
				return invalid()
			}
		}
		optional := []string{}
		if kind == "peerspan-policy-v2" {
			optional = []string{"capability_rules", "trusted_hosts", "edits"}
		}
		if e := fields(p, names, optional...); e != nil {
			return e
		}
		for _, f := range []string{"rules", "capability_rules", "trusted_hosts", "edits"} {
			if v, ok := p[f]; ok {
				var a []json.RawMessage
				if json.Unmarshal(v, &a) != nil || a == nil {
					return invalid()
				}
			}
		}
		if e := publicFields(p); e != nil {
			return e
		}
		validated := Object{}
		for k, v := range p {
			validated[k] = v
		}
		// publicFields checked the retained version as a positive uint64.
		// The legacy shape checker only needs positivity, but its storage model
		// uses int64. Keep that representation out of the signed-object reader.
		validated["version"] = json.RawMessage(`1`)
		validated["signature"] = json.RawMessage(`"-"`)
		if kind == "peerspan-policy-v2" {
			for _, k := range []string{"capability_rules", "trusted_hosts", "edits"} {
				if _, ok := validated[k]; !ok {
					validated[k] = json.RawMessage(`[]`)
				}
			}
		}
		encoded, e := json.Marshal(validated)
		if e != nil {
			return e
		}
		var policy membership.Policy
		if e = json.Unmarshal(encoded, &policy); e != nil {
			return invalid()
		}
		return membership.CheckPolicy(policy.NetworkID, policy)
	}
	names, ok := shapes[kind]
	if !ok {
		return invalid()
	}
	if e := fields(p, names); e != nil {
		return e
	}
	if kind == "peerspan-group-v1" {
		name, e := text(p, "name")
		if e != nil || !membership.ValidGroupName(name) {
			return invalid()
		}
		a, e := stringsOf(p, "members")
		if e != nil || !sorted(a) {
			return invalid()
		}
		for _, s := range a {
			if !identifier(s, "person_") {
				return invalid()
			}
		}
	}
	return publicFields(p)
}
func publicFields(p Object) error {
	for k := range p {
		switch k {
		case "network_id":
			s, e := text(p, k)
			if e != nil || !identifier(s, "net_") {
				return invalid()
			}
		case "person_public_key", "host_public_key", "invite_public_key", "device_public_key", "genesis_root_public_key", "coordinator_public_key":
			s, e := text(p, k)
			if e != nil || !key(s) {
				return invalid()
			}
		case "epoch", "invite_epoch", "version":
			n, e := num(p, k)
			if e != nil || k == "version" && n == 0 {
				return invalid()
			}
		case "bound_at", "unbound_at", "admitted_at", "removed_at", "revoked_at", "invite_expires_at", "defined_at", "issued_at", "valid_until", "created_at", "expires_at", "not_after":
			s, e := text(p, k)
			if e != nil {
				return e
			}
			if _, e = stamp(s); e != nil {
				return e
			}
		case "member":
			s, e := text(p, k)
			if e != nil || !membership.ValidLabel(s) {
				return invalid()
			}
		}
	}
	return nil
}
func revocation(o Object, signer string) (SignedObject, error) {
	if fields(o, "format network_id person_public_key target_device_public_key target_certificate_id issuer_certificate_id revoked_at signature") != nil || version(o, 1) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "network_id", "person_public_key", "target_device_public_key", "target_certificate_id", "issuer_certificate_id", "revoked_at", "signature")
	if e != nil {
		return SignedObject{}, e
	}
	if !identifier(a[0], "net_") || !rootPerson(a[1], a[4], signer) || !key(a[2]) || !identifier(a[3], "dc_") {
		return SignedObject{}, invalid()
	}
	if _, e = stamp(a[5]); e != nil {
		return SignedObject{}, e
	}
	m := message(append([]string{"peerspan-device-revoke-v1"}, a[:6]...)...)
	if e = personSignature(signer, m, a[6]); e != nil {
		return SignedObject{}, e
	}
	return SignedObject{Message: m, ID: "dr_" + digest(m)}, nil
}
func checkpoint(o Object, signer string) (SignedObject, error) {
	if fields(o, "format network_id person_public_key issuer_certificate_id issued_at records signature") != nil || version(o, 1) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "network_id", "person_public_key", "issuer_certificate_id", "issued_at", "signature")
	if e != nil || !identifier(a[0], "net_") || !rootPerson(a[1], a[2], signer) {
		return SignedObject{}, invalid()
	}
	if _, e = stamp(a[3]); e != nil {
		return SignedObject{}, e
	}
	records, e := stringsOf(o, "records")
	if e != nil || !sorted(records) {
		return SignedObject{}, invalid()
	}
	for _, s := range records {
		if !identifier(s, "ar_") && !identifier(s, "dr_") && !identifier(s, "pf_") {
			return SignedObject{}, invalid()
		}
	}
	m := message(append([]string{"peerspan-person-checkpoint-v1", a[0], a[1], a[2], a[3], strconv.Itoa(len(records))}, records...)...)
	if e = personSignature(signer, m, a[4]); e != nil {
		return SignedObject{}, e
	}
	return SignedObject{Message: m}, nil
}
func packet(o Object, signer, device string) (SignedObject, error) {
	if fields(o, "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature") != nil || version(o, 1) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "request_id", "role", "writer_public_key", "person_public_key", "certificate_id", "host_signature", "device_signature", "authority_signature")
	if e != nil || !identifier(a[0], "link_") || a[2] != signer {
		return SignedObject{}, invalid()
	}
	b, p, e := payload(o)
	if e != nil {
		return SignedObject{}, e
	}
	if e = packetPayload(a[1], p); e != nil {
		return SignedObject{}, e
	}
	m := message("peerspan-link-packet-v1", a[0], a[1], a[2], a[3], a[4], digest(b))
	switch a[1] {
	case "request", "selection", "commit":
		if !key(device) || a[4] != "-" || a[7] != "-" {
			return SignedObject{}, invalid()
		}
		if a[1] == "request" {
			host, e := text(p, "host_public_key")
			if e != nil || host != signer {
				return SignedObject{}, invalid()
			}
			dev, e := text(p, "device_public_key")
			if e != nil || dev != device || a[3] != "-" {
				return SignedObject{}, invalid()
			}
		} else if !key(a[3]) {
			return SignedObject{}, invalid()
		}
		if e = rawSignature(signer, m, a[5]); e == nil {
			e = personSignature(device, m, a[6])
		}
	case "owner", "administrator":
		if device != "-" || a[5] != "-" || a[6] != "-" {
			return SignedObject{}, invalid()
		}
		if a[1] == "administrator" && a[4] == "network_root" && a[3] == "-" {
			e = rootSignature(signer, m, a[7])
		} else if rootPerson(a[3], a[4], signer) {
			e = personSignature(signer, m, a[7])
		} else {
			e = invalid()
		}
	case "result":
		if device != "-" || a[3] != "-" || a[4] != "coordinator" || a[5] != "-" || a[6] != "-" {
			return SignedObject{}, invalid()
		}
		e = rawSignature(signer, m, a[7])
	default:
		e = invalid()
	}
	if e != nil {
		return SignedObject{}, e
	}
	return SignedObject{Message: m, ID: "lp_" + digest(message("peerspan-link-packet-id-v1", digest(m), a[5], a[6], a[7])), Payload: b}, nil
}
func packetPayload(role string, p Object) error {
	shapes := map[string]string{
		"request":       "mode host_public_key device_public_key request_nonce coordinator_address coordinator_public_key created_at expires_at expected_network_id expected_person_public_key renewed_certificate_id",
		"owner":         "request_packet_id network epoch feature_id person_public_key certificate binding_record membership_proof_id binding_proof_id",
		"selection":     "owner_offer_id network_id epoch feature_id person_public_key",
		"administrator": "owner_offer_id selection_id admission_record",
		"commit":        "mode request_packet_id owner_offer_id selection_id administrator_offer_id network_id epoch feature_id person_public_key certificate_id binding_record admission_record_id expires_at",
		"result":        "manifest_id activation catalog",
	}
	s, ok := shapes[role]
	if !ok {
		return invalid()
	}
	if e := fields(p, s); e != nil {
		return e
	}
	if e := publicFields(p); e != nil {
		return e
	}
	if e := packetScalars(p); e != nil {
		return e
	}
	switch role {
	case "owner":
		n, e := parse(p["network"])
		if e != nil {
			return e
		}
		if e = fields(n, "network_id name genesis_root_public_key coordinator_address coordinator_public_key"); e != nil {
			return e
		}
		if e = publicFields(n); e != nil {
			return e
		}
		if _, e = texts(n, "name", "coordinator_address"); e != nil {
			return e
		}
		c, e := parse(p["certificate"])
		if e != nil {
			return e
		}
		if e = fields(c, "format network_id person_public_key device_public_key host_public_key parent_id scopes issued_at not_after request_id signature"); e != nil {
			return e
		}
		if e = version(c, 1); e != nil {
			return e
		}
		if e = publicFields(c); e != nil {
			return e
		}
		if _, e = scope(c); e != nil {
			return e
		}
		if _, e = texts(c, "parent_id", "request_id", "signature"); e != nil {
			return e
		}
		if !absent(p["binding_record"]) {
			return nestedRecord(p["binding_record"])
		}
	case "administrator":
		return nestedRecord(p["admission_record"])
	case "commit":
		if !absent(p["binding_record"]) {
			return nestedRecord(p["binding_record"])
		}
	case "result":
		return resultPayload(p)
	}
	return nil
}

func absent(b []byte) bool {
	var s string
	return json.Unmarshal(b, &s) == nil && s == "-"
}

// Check packet scalars without resolving references or granting nested authority.
func packetScalars(p Object) error {
	for k := range p {
		switch k {
		case "epoch", "network", "certificate", "binding_record", "admission_record", "activation", "catalog":
			continue
		}
		s, e := text(p, k)
		if e != nil {
			return e
		}
		valid := true
		switch k {
		case "mode":
			valid = s == "new" || s == "renew"
		case "request_nonce":
			b, e := decode(s, 32)
			valid = e == nil && len(b) == 32
		case "expected_network_id":
			valid = s == "-" || identifier(s, "net_")
		case "expected_person_public_key":
			valid = s == "-" || key(s)
		case "renewed_certificate_id":
			valid = s == "-" || identifier(s, "dc_")
		case "certificate_id":
			valid = identifier(s, "dc_")
		case "request_packet_id", "owner_offer_id", "selection_id", "manifest_id":
			valid = identifier(s, "lp_")
		case "administrator_offer_id":
			valid = s == "-" || identifier(s, "lp_")
		case "feature_id":
			valid = identifier(s, "lf_")
		case "membership_proof_id", "binding_proof_id":
			valid = s == "-" || identifier(s, "pf_")
		case "admission_record_id":
			valid = s == "-" || identifier(s, "ar_") || identifier(s, "rr_")
		}
		if !valid {
			return invalid()
		}
	}
	return nil
}
func resultPayload(p Object) error {
	a, e := parse(p["activation"])
	if e != nil || fields(a, "request owner selection administrator commit") != nil {
		return invalid()
	}
	for k, v := range a {
		if k == "administrator" && absent(v) {
			continue
		}
		if _, e = parse(v); e != nil {
			return e
		}
	}
	c, e := parse(p["catalog"])
	if e != nil || fields(c, "format network_id objects") != nil || version(c, 1) != nil || publicFields(c) != nil {
		return invalid()
	}
	var entries []json.RawMessage
	if json.Unmarshal(c["objects"], &entries) != nil || entries == nil || len(entries) > 4096 {
		return invalid()
	}
	for _, raw := range entries {
		o, e := parse(raw)
		if e != nil || fields(o, "id kind body_base64") != nil {
			return invalid()
		}
		v, e := texts(o, "id", "kind", "body_base64")
		if e != nil || !identifier(v[0], "pf_") {
			return invalid()
		}
		b, e := decode(v[2], MaxObject)
		if e != nil {
			return e
		}
		if _, e = parse(b); e != nil {
			return e
		}
	}
	return nil
}
func nestedRecord(data []byte) error {
	o, e := parse(data)
	if e != nil {
		return e
	}
	names := "format kind network_id epoch operation_id payload_base64 signature"
	if _, ok := o["person_public_key"]; ok {
		names += " person_public_key certificate_id host_signature"
	}
	if e = fields(o, names); e != nil {
		return e
	}
	if e = version(o, 1); e != nil {
		return e
	}
	if e = publicFields(o); e != nil {
		return e
	}
	if _, e = texts(o, "operation_id", "signature"); e != nil {
		return e
	}
	if _, ok := o["person_public_key"]; ok {
		if _, e = texts(o, "certificate_id", "host_signature"); e != nil {
			return e
		}
	}
	kind, e := text(o, "kind")
	if e != nil {
		return e
	}
	_, p, e := payload(o)
	if e != nil {
		return e
	}
	return recordPayload(kind, p)
}
func proposal(o Object, signer string) (SignedObject, error) {
	if fields(o, "format network_id epoch version issued_at host_public_keys signature") != nil || version(o, 1) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "network_id", "issued_at", "signature")
	if e != nil || !identifier(a[0], "net_") {
		return SignedObject{}, invalid()
	}
	epoch, e := num(o, "epoch")
	if e != nil {
		return SignedObject{}, e
	}
	v, e := num(o, "version")
	if e != nil || v != 1 {
		return SignedObject{}, invalid()
	}
	if _, e = stamp(a[1]); e != nil {
		return SignedObject{}, e
	}
	hosts, e := stringsOf(o, "host_public_keys")
	if e != nil || len(hosts) == 0 || !sorted(hosts) {
		return SignedObject{}, invalid()
	}
	for _, h := range hosts {
		if !key(h) {
			return SignedObject{}, invalid()
		}
	}
	m := message(append([]string{"peerspan-link-feature-v1", a[0], strconv.FormatUint(epoch, 10), "1", a[1], strconv.Itoa(len(hosts))}, hosts...)...)
	if e = rootSignature(signer, m, a[2]); e != nil {
		return SignedObject{}, e
	}
	return SignedObject{Message: m, ID: "lf_" + digest(m)}, nil
}
func ack(o Object, signer string) (SignedObject, error) {
	if fields(o, "format feature_id host_public_key signature") != nil || version(o, 1) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "feature_id", "host_public_key", "signature")
	if e != nil || !identifier(a[0], "lf_") || a[1] != signer {
		return SignedObject{}, invalid()
	}
	m := message("peerspan-link-feature-ack-v1", a[0], a[1])
	if e = rawSignature(signer, m, a[2]); e != nil {
		return SignedObject{}, e
	}
	return SignedObject{Message: m}, nil
}
func feature(o Object, signer string) (SignedObject, error) {
	if fields(o, "proposal acknowledgments") != nil {
		return SignedObject{}, invalid()
	}
	p, e := parse(o["proposal"])
	if e != nil {
		return SignedObject{}, e
	}
	r, e := proposal(p, signer)
	if e != nil {
		return SignedObject{}, e
	}
	hosts, e := stringsOf(p, "host_public_keys")
	if e != nil {
		return SignedObject{}, e
	}
	var a []json.RawMessage
	if json.Unmarshal(o["acknowledgments"], &a) != nil || len(a) != len(hosts) {
		return SignedObject{}, invalid()
	}
	for i, data := range a {
		v, e := parse(data)
		if e != nil {
			return SignedObject{}, e
		}
		f, e := text(v, "feature_id")
		if e != nil || f != r.ID {
			return SignedObject{}, invalid()
		}
		if _, e = ack(v, hosts[i]); e != nil {
			return SignedObject{}, e
		}
	}
	return r, nil
}
func adminRemoval(o Object, signer string) (SignedObject, error) {
	if fields(o, "format network_id person_public_key revoke_admitted removed_at kept signature") != nil || version(o, 2) != nil {
		return SignedObject{}, invalid()
	}
	a, e := texts(o, "network_id", "person_public_key", "removed_at", "signature")
	if e != nil || !identifier(a[0], "net_") || !key(a[1]) {
		return SignedObject{}, invalid()
	}
	if _, e = stamp(a[2]); e != nil {
		return SignedObject{}, e
	}
	var revoke bool
	if json.Unmarshal(o["revoke_admitted"], &revoke) != nil {
		return SignedObject{}, invalid()
	}
	kept, e := stringsOf(o, "kept")
	if e != nil || !sorted(kept) || revoke && len(kept) > 0 {
		return SignedObject{}, invalid()
	}
	for _, s := range kept {
		switch {
		case strings.HasPrefix(s, "legacy:"):
			if !identifier(strings.TrimPrefix(s, "legacy:"), "") {
				return SignedObject{}, invalid()
			}
		case strings.HasPrefix(s, "record:"):
			if !identifier(strings.TrimPrefix(s, "record:"), "ar_") {
				return SignedObject{}, invalid()
			}
		case strings.HasPrefix(s, "redemption:"):
			if !identifier(strings.TrimPrefix(s, "redemption:"), "pf_") {
				return SignedObject{}, invalid()
			}
		default:
			return SignedObject{}, invalid()
		}
	}
	m := message(append([]string{"peerspan-admin-remove-v2", a[0], a[1], strconv.FormatBool(revoke), a[2], strconv.Itoa(len(kept))}, kept...)...)
	if e = rootSignature(signer, m, a[3]); e != nil {
		return SignedObject{}, e
	}
	return SignedObject{Message: m}, nil
}

// Probe is a conformance-only adapter. It never reads or mutates daemon state.
func Probe(data []byte) any {
	fail := map[string]any{"ok": false, "code": "invalid"}
	o, e := parseLimit(data, 2<<20)
	if e != nil {
		return fail
	}
	if kind, _ := text(o, "kind"); kind == "path" {
		return pathProbe(o)
	}
	if kind, _ := text(o, "kind"); kind == "activation" {
		return activationProbe(o)
	}
	if kind, _ := text(o, "kind"); kind == "feature_activation" {
		return featureProbe(o)
	}
	if kind, _ := text(o, "kind"); kind == "action_authorization" {
		return actionProbe(o)
	}
	if fields(o, "kind object_base64 signer_public_key device_public_key") != nil {
		return fail
	}
	a, e := texts(o, "kind", "object_base64", "signer_public_key", "device_public_key")
	if e != nil {
		return fail
	}
	b, e := decode(a[1], MaxObject)
	if e != nil {
		return fail
	}
	r, e := Read(a[0], b, a[2], a[3])
	if e != nil {
		return fail
	}
	p := "-"
	if r.Payload != nil {
		p = base64.StdEncoding.EncodeToString(r.Payload)
	}
	return map[string]any{"ok": true, "message_base64": base64.StdEncoding.EncodeToString(r.Message), "id": r.ID, "payload_base64": p}
}
