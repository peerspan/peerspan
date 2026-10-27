package decentralized

import (
	"bytes"
)

const (
	MaxRequest  = 8 << 10
	MaxManifest = 16 << 10
)

type Packet struct {
	Raw, Payload, Message                                                           []byte
	ID, ContextID, RequestID, Role, Writer, Signer, Person, Issuer, AuthorityFormat string
	HostSignature, DeviceSignature, AuthoritySignature                              string
	Object                                                                          Object
	Statements                                                                      []*Statement
}

func readPacket(d Descriptor, raw []byte) (*Packet, error) { return readPacketMode(d, raw, false) }
func readPacketMode(d Descriptor, raw []byte, unsigned bool) (*Packet, error) {
	o, e := parse(raw)
	if e != nil {
		return nil, e
	}
	if fields(o, "format context_id request_id role writer_host_public_key signer_public_key person_public_key issuer_id payload_base64 host_signature device_signature authority_signature_format authority_signature") != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	a, e := texts(o, "context_id", "request_id", "role", "writer_host_public_key", "signer_public_key", "person_public_key", "issuer_id", "payload_base64", "host_signature", "device_signature", "authority_signature_format", "authority_signature")
	if e != nil {
		return nil, e
	}
	if a[2] == "request" && len(raw) > MaxRequest {
		return nil, failure("quota_exceeded")
	}
	if !literalOrID(a[0], "ctx_") || !identifier(a[1], "link_") || !key(a[3]) || !literalOrKey(a[4]) || !literalOrKey(a[5]) || !literalOrID(a[6], "ds_") {
		return nil, invalid()
	}
	payload, e := decode(a[7], MaxPayload)
	if e != nil {
		return nil, e
	}
	po, e := parseLimit(payload, MaxPayload)
	if e != nil {
		return nil, e
	}
	p := &Packet{Raw: append([]byte{}, raw...), Payload: payload, ContextID: a[0], RequestID: a[1], Role: a[2], Writer: a[3], Signer: a[4], Person: a[5], Issuer: a[6], HostSignature: a[8], DeviceSignature: a[9], AuthorityFormat: a[10], AuthoritySignature: a[11], Object: po, Statements: []*Statement{}}
	p.Message = message("peerspan-decentralized-packet-v1", p.ContextID, p.RequestID, p.Role, p.Writer, p.Signer, p.Person, p.Issuer, p.AuthorityFormat, digest(payload))
	p.ID = "dpk_" + digest(p.Message)
	if e = packetSignature(p.Writer, "ed25519", p.Message, p.HostSignature, unsigned); e != nil {
		return nil, e
	}
	switch p.Role {
	case "request", "selection", "commit":
		if !key(p.Signer) || p.Issuer != "-" || p.AuthorityFormat != "-" || p.AuthoritySignature != "-" {
			return nil, invalid()
		}
		if e = packetSignature(p.Signer, "ed25519", p.Message, p.DeviceSignature, unsigned); e != nil {
			return nil, e
		}
		if p.Role == "request" {
			if p.ContextID != "-" || p.Person != "-" {
				return nil, invalid()
			}
		} else if p.ContextID != d.ContextID || !key(p.Person) {
			return nil, invalid()
		}
	case "owner", "owner_finalization", "administrator":
		if p.ContextID != d.ContextID || !key(p.Signer) || p.DeviceSignature != "-" {
			return nil, invalid()
		}
		if p.Person == "-" {
			if p.Role != "administrator" || !identifier(p.Issuer, "ds_") {
				return nil, invalid()
			}
		} else {
			if !key(p.Person) || p.Issuer == "-" && (p.Signer != p.Person || p.AuthorityFormat != "sshsig") || p.Issuer != "-" && p.AuthorityFormat != "ed25519" {
				return nil, invalid()
			}
		}
		if e = packetSignature(p.Signer, p.AuthorityFormat, p.Message, p.AuthoritySignature, unsigned); e != nil {
			return nil, e
		}
	case "outcome":
		if p.ContextID != d.ContextID || p.Signer != "-" || p.Person != "-" || p.Issuer != "-" || p.DeviceSignature != "-" || p.AuthoritySignature != "-" || p.AuthorityFormat != "-" {
			return nil, invalid()
		}
	default:
		return nil, invalid()
	}
	if e = p.checkPayload(d); e != nil {
		return nil, e
	}
	return p, nil
}
func (p *Packet) checkPayload(d Descriptor) error {
	o := p.Object
	switch p.Role {
	case "request":
		if fields(o, "mode host_public_key device_public_key request_nonce expected_network_id expected_context_id expected_person_public_key migration_proposal_id renewed_device_lease_id created_at expires_at") != nil {
			return invalid()
		}
		a, e := texts(o, "mode", "host_public_key", "device_public_key", "request_nonce", "expected_network_id", "expected_context_id", "expected_person_public_key", "migration_proposal_id", "renewed_device_lease_id", "created_at", "expires_at")
		if e != nil {
			return e
		}
		nonce, e := decode(a[3], 32)
		if e != nil {
			return e
		}
		if a[0] != "new" && a[0] != "renew" || a[1] != p.Writer || a[2] != p.Signer || len(nonce) != 32 || !literalOrID(a[4], "net_") || !literalOrID(a[5], "ctx_") || !literalOrKey(a[6]) || !literalOrID(a[7], "ds_") || !literalOrID(a[8], "ds_") {
			return invalid()
		}
		if a[0] == "renew" && (a[4] == "-" || a[5] == "-" || a[6] == "-" || a[8] == "-") || a[0] == "new" && a[8] != "-" {
			return invalid()
		}
		created, e := stamp(a[9])
		if e != nil {
			return e
		}
		expires, e := stamp(a[10])
		if e != nil || expires.Unix()-created.Unix() != 300 {
			return invalid()
		}
		if p.RequestID != "link_"+digest(message("peerspan-decentralized-request-id-v1", digest(p.Payload))) {
			return invalid()
		}
	case "owner":
		if fields(o, "request_packet_id descriptor root_state_id person_lease_id issuer_lease_ids mode member host_public_key device_public_key scopes not_after renewed_device_lease_id") != nil {
			return invalid()
		}
		a, e := texts(o, "request_packet_id", "root_state_id", "person_lease_id", "mode", "member", "host_public_key", "device_public_key", "not_after", "renewed_device_lease_id")
		if e != nil || !identifier(a[0], "dpk_") || !literalOrID(a[1], "ds_") || !literalOrID(a[2], "ds_") || a[3] != "new" && a[3] != "renew" || !key(a[5]) || !key(a[6]) || !literalOrID(a[8], "ds_") {
			return invalid()
		}
		if _, e = stamp(a[7]); e != nil {
			return e
		}
		if _, e = ReadDescriptor(o["descriptor"]); e != nil {
			return e
		}
		od, e := ReadDescriptor(o["descriptor"])
		if e != nil || od.ContextID != d.ContextID {
			return invalid()
		}
		// Label validation is independent from the public-key identity.
		if !validMember(a[4]) {
			return invalid()
		}
		n, e := num(o, "scopes")
		if e != nil || n == 0 || n > 15 {
			return invalid()
		}
		if _, e = ids(o, "issuer_lease_ids", "ds_"); e != nil {
			return e
		}
	case "selection":
		if fields(o, "request_packet_id owner_offer_id context_id person_public_key host_public_key device_public_key selected_at") != nil {
			return invalid()
		}
		if e := packetReferences(o, "request_packet_id", "owner_offer_id"); e != nil {
			return e
		}
		if stringField(o, "context_id") != d.ContextID || stringField(o, "person_public_key") != p.Person || stringField(o, "host_public_key") != p.Writer || stringField(o, "device_public_key") != p.Signer {
			return invalid()
		}
		if _, e := stamp(stringField(o, "selected_at")); e != nil {
			return e
		}
	case "administrator":
		if fields(o, "selection_id owner_offer_id root_state_id issuer_lease_ids person_lease host_lease") != nil {
			return invalid()
		}
		if e := packetReferences(o, "selection_id", "owner_offer_id"); e != nil {
			return e
		}
		if !identifier(stringField(o, "root_state_id"), "ds_") {
			return invalid()
		}
		if _, e := ids(o, "issuer_lease_ids", "ds_"); e != nil {
			return e
		}
		for _, field := range []struct{ name, kind string }{{"person_lease", "person_lease"}, {"host_lease", "host_lease"}} {
			if e := p.component(d, field.name, field.kind, false); e != nil {
				return e
			}
		}
	case "owner_finalization":
		if fields(o, "selection_id administrator_offer_id root_state_id person_lease_id host_lease_id binding_lease device_lease") != nil {
			return invalid()
		}
		if !identifier(stringField(o, "selection_id"), "dpk_") || !literalOrID(stringField(o, "administrator_offer_id"), "dpk_") {
			return invalid()
		}
		for _, k := range []string{"root_state_id", "person_lease_id", "host_lease_id"} {
			if !identifier(stringField(o, k), "ds_") {
				return invalid()
			}
		}
		if e := p.component(d, "binding_lease", "binding_lease", true); e != nil {
			return e
		}
		if e := p.component(d, "device_lease", "device_lease", false); e != nil {
			return e
		}
	case "commit":
		if fields(o, "manifest_base64 binding_host_signature committed_at") != nil {
			return invalid()
		}
		raw, e := decode(stringField(o, "manifest_base64"), MaxManifest)
		if e != nil {
			return e
		}
		if _, e = readManifest(d, raw); e != nil {
			return e
		}
		if _, e = stamp(stringField(o, "committed_at")); e != nil {
			return e
		}
		sig, e := text(o, "binding_host_signature")
		if e != nil {
			return e
		}
		if sig != "-" {
			b, e := decode(sig, 64)
			if e != nil {
				return e
			}
			if len(b) != 64 {
				return invalid()
			}
		}
	case "outcome":
		if fields(o, "context_id request_id manifest_id activation_id activation_sha256 observed_root_state_id applied_at") != nil {
			return invalid()
		}
		if stringField(o, "context_id") != d.ContextID || stringField(o, "request_id") != p.RequestID || !identifier(stringField(o, "manifest_id"), "dm_") || !identifier(stringField(o, "activation_id"), "da_") || !hashString(stringField(o, "activation_sha256")) || !identifier(stringField(o, "observed_root_state_id"), "ds_") {
			return invalid()
		}
		if _, e := stamp(stringField(o, "applied_at")); e != nil {
			return e
		}
	}
	return nil
}
func packetReferences(o Object, fields ...string) error {
	for _, f := range fields {
		if !identifier(stringField(o, f), "dpk_") {
			return invalid()
		}
	}
	return nil
}
func (p *Packet) component(d Descriptor, name, kind string, pending bool) error {
	if bytes.HasPrefix(bytes.TrimSpace(p.Object[name]), []byte(`"`)) {
		id, e := text(p.Object, name)
		if e != nil || !identifier(id, "ds_") || name == "device_lease" {
			return invalid()
		}
		return nil
	}
	s, e := readStatement(d, p.Object[name], pending)
	if e != nil {
		return e
	}
	if s.Kind != kind {
		return invalid()
	}
	p.Statements = append(p.Statements, s)
	return nil
}
func readManifest(d Descriptor, raw []byte) (Object, error) {
	o, e := parseLimit(raw, MaxManifest)
	if e != nil {
		return nil, e
	}
	if fields(o, "format context_id request_id request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id binding_proof_id device_proof_id ancestor_statement_ids proof_ids") != nil || version(o, 1) != nil || stringField(o, "context_id") != d.ContextID || !identifier(stringField(o, "request_id"), "link_") {
		return nil, invalid()
	}
	for _, f := range []string{"request_packet_id", "owner_offer_id", "selection_id", "owner_finalization_id"} {
		if !identifier(stringField(o, f), "dpk_") {
			return nil, invalid()
		}
	}
	if !literalOrID(stringField(o, "administrator_offer_id"), "dpk_") {
		return nil, invalid()
	}
	for _, f := range []string{"root_state_id", "person_lease_id", "host_lease_id", "binding_lease_id", "device_lease_id"} {
		if !identifier(stringField(o, f), "ds_") {
			return nil, invalid()
		}
	}
	for _, f := range []string{"binding_proof_id", "device_proof_id"} {
		if !identifier(stringField(o, f), "dp_") {
			return nil, invalid()
		}
	}
	if _, e = ids(o, "ancestor_statement_ids", "ds_"); e != nil {
		return nil, e
	}
	if _, e = ids(o, "proof_ids", "dp_"); e != nil {
		return nil, e
	}
	return o, nil
}

type ParsedActivation struct {
	Raw                                                            []byte
	Request, Owner, Selection, Administrator, Finalization, Commit *Packet
	Manifest                                                       Object
	ManifestRaw                                                    []byte
	ManifestID, ID                                                 string
}

func readActivation(d Descriptor, raw []byte) (*ParsedActivation, error) {
	o, e := parse(raw)
	if e != nil {
		return nil, e
	}
	if fields(o, "format context_id request owner selection administrator owner_finalization commit") != nil || version(o, 1) != nil || stringField(o, "context_id") != d.ContextID {
		return nil, invalid()
	}
	a := &ParsedActivation{Raw: append([]byte{}, raw...)}
	for _, entry := range []struct {
		name, role string
		dst        **Packet
	}{{"request", "request", &a.Request}, {"owner", "owner", &a.Owner}, {"selection", "selection", &a.Selection}, {"administrator", "administrator", &a.Administrator}, {"owner_finalization", "owner_finalization", &a.Finalization}, {"commit", "commit", &a.Commit}} {
		if entry.name == "administrator" && bytes.Equal(bytes.TrimSpace(o[entry.name]), []byte(`"-"`)) {
			continue
		}
		*entry.dst, e = readPacket(d, o[entry.name])
		if e != nil {
			return nil, e
		}
		if (*entry.dst).Role != entry.role {
			return nil, invalid()
		}
	}
	for _, p := range []*Packet{a.Owner, a.Selection, a.Administrator, a.Finalization, a.Commit} {
		if p != nil && p.RequestID != a.Request.RequestID {
			return nil, invalid()
		}
	}
	if a.Selection.Writer != a.Request.Writer || a.Selection.Signer != a.Request.Signer || a.Commit.Writer != a.Request.Writer || a.Commit.Signer != a.Request.Signer || a.Selection.Person != a.Owner.Person || a.Finalization.Person != a.Owner.Person || a.Commit.Person != a.Owner.Person || a.Finalization.Signer != a.Owner.Signer || a.Finalization.Issuer != a.Owner.Issuer {
		return nil, invalid()
	}
	if stringField(a.Owner.Object, "request_packet_id") != a.Request.ID || stringField(a.Selection.Object, "request_packet_id") != a.Request.ID || stringField(a.Selection.Object, "owner_offer_id") != a.Owner.ID || stringField(a.Finalization.Object, "selection_id") != a.Selection.ID {
		return nil, invalid()
	}
	adminID := "-"
	if a.Administrator != nil {
		adminID = a.Administrator.ID
		if stringField(a.Administrator.Object, "selection_id") != a.Selection.ID || stringField(a.Administrator.Object, "owner_offer_id") != a.Owner.ID {
			return nil, invalid()
		}
	} else if stringField(a.Request.Object, "mode") != "renew" {
		return nil, invalid()
	}
	if stringField(a.Finalization.Object, "administrator_offer_id") != adminID {
		return nil, invalid()
	}
	a.ManifestRaw, e = decode(stringField(a.Commit.Object, "manifest_base64"), MaxManifest)
	if e != nil {
		return nil, e
	}
	a.Manifest, e = readManifest(d, a.ManifestRaw)
	if e != nil {
		return nil, e
	}
	a.ManifestID = "dm_" + digest(message("peerspan-decentralized-manifest-v1", digest(a.ManifestRaw)))
	a.ID = "da_" + digest(message("peerspan-decentralized-activation-v1", d.ContextID, a.Request.RequestID, a.ManifestID, a.Commit.ID))
	for k, v := range map[string]string{"request_id": a.Request.RequestID, "request_packet_id": a.Request.ID, "owner_offer_id": a.Owner.ID, "selection_id": a.Selection.ID, "administrator_offer_id": adminID, "owner_finalization_id": a.Finalization.ID} {
		if stringField(a.Manifest, k) != v {
			return nil, invalid()
		}
	}
	return a, nil
}
