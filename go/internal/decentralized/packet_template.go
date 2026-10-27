package decentralized

import (
	"bytes"
	"encoding/json"
	"sort"
)

func packetSignature(public, format string, m []byte, signature string, unsigned bool) error {
	if !key(public) || format != "ed25519" && format != "sshsig" {
		return invalid()
	}
	if unsigned && signature == "-" {
		return nil
	}
	return VerifySignature(public, format, m, signature)
}
func ReadPacket(d Descriptor, raw []byte) (*Packet, error) { return readPacket(d, raw) }

// ReadPacketTemplate validates a fixed typed draft with declared unfilled
// signature fields only. It never establishes complete consent or admission.
func ReadPacketTemplate(d Descriptor, raw []byte) (*Packet, error) {
	return readPacketMode(d, raw, true)
}

func PacketTemplate(d Descriptor, context, request, role, writer, signer, person, issuer, format string, payload []byte) ([]byte, error) {
	raw, e := json.Marshal(struct {
		Format          uint64 `json:"format"`
		Context         string `json:"context_id"`
		Request         string `json:"request_id"`
		Role            string `json:"role"`
		Writer          string `json:"writer_host_public_key"`
		Signer          string `json:"signer_public_key"`
		Person          string `json:"person_public_key"`
		Issuer          string `json:"issuer_id"`
		Payload         string `json:"payload_base64"`
		Host            string `json:"host_signature"`
		Device          string `json:"device_signature"`
		AuthorityFormat string `json:"authority_signature_format"`
		Authority       string `json:"authority_signature"`
	}{1, context, request, role, writer, signer, person, issuer, b64(payload), "-", "-", format, "-"})
	if e != nil {
		return nil, e
	}
	if _, e = ReadPacketTemplate(d, raw); e != nil {
		return nil, e
	}
	return raw, nil
}

type PacketSignatureRole struct{ Role, PublicKey, Format string }

func PacketSignatureRoles(p *Packet) []PacketSignatureRole {
	roles := []PacketSignatureRole{{"host", p.Writer, "ed25519"}}
	switch p.Role {
	case "request", "selection", "commit":
		roles = append(roles, PacketSignatureRole{"device", p.Signer, "ed25519"})
	case "owner", "owner_finalization", "administrator":
		roles = append(roles, PacketSignatureRole{"authority", p.Signer, p.AuthorityFormat})
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Role < roles[j].Role })
	return roles
}

// FillPacketTemplate preserves every original payload/envelope byte except
// the exact declared signature string spans. It is not a raw signing service.
func FillPacketTemplate(d Descriptor, raw []byte, filled map[string]string) ([]byte, error) {
	p, e := ReadPacketTemplate(d, raw)
	if e != nil {
		return nil, e
	}
	declared := map[string]PacketSignatureRole{}
	current := map[string]string{"host": p.HostSignature, "device": p.DeviceSignature, "authority": p.AuthoritySignature}
	for _, role := range PacketSignatureRoles(p) {
		declared[role.Role] = role
	}
	for role, signature := range filled {
		expected, ok := declared[role]
		if !ok || signature == "-" {
			return nil, invalid()
		}
		if current[role] != "-" && current[role] != signature {
			return nil, failure("operation_conflict")
		}
		if e = VerifySignature(expected.PublicKey, expected.Format, p.Message, signature); e != nil {
			return nil, e
		}
	}
	type change struct {
		start, end int
		value      []byte
	}
	changes := []change{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if _, e = decoder.Token(); e != nil {
		return nil, invalid()
	}
	fields := map[string]string{"host_signature": "host", "device_signature": "device", "authority_signature": "authority"}
	for decoder.More() {
		token, e := decoder.Token()
		if e != nil {
			return nil, invalid()
		}
		name, ok := token.(string)
		if !ok {
			return nil, invalid()
		}
		var field json.RawMessage
		if e = decoder.Decode(&field); e != nil {
			return nil, invalid()
		}
		role, ok := fields[name]
		if !ok {
			continue
		}
		signature, ok := filled[role]
		if !ok {
			continue
		}
		value, _ := json.Marshal(signature)
		end := int(decoder.InputOffset())
		changes = append(changes, change{end - len(field), end, value})
	}
	result := append([]byte{}, raw...)
	sort.Slice(changes, func(i, j int) bool { return changes[i].start > changes[j].start })
	for _, c := range changes {
		next := make([]byte, 0, len(result)+len(c.value)-(c.end-c.start))
		next = append(next, result[:c.start]...)
		next = append(next, c.value...)
		next = append(next, result[c.end:]...)
		result = next
	}
	if _, e = ReadPacketTemplate(d, result); e != nil {
		return nil, e
	}
	return result, nil
}
func RequestID(payload []byte) string {
	return "link_" + digest(message("peerspan-decentralized-request-id-v1", digest(payload)))
}
