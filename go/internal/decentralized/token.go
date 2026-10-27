package decentralized

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const MaxPairingToken = 32 << 10

type RequestTerms struct {
	Mode          string `json:"mode"`
	Host          string `json:"host_public_key"`
	Device        string `json:"device_public_key"`
	Nonce         string `json:"request_nonce"`
	Network       string `json:"expected_network_id"`
	Context       string `json:"expected_context_id"`
	Person        string `json:"expected_person_public_key"`
	Migration     string `json:"migration_proposal_id"`
	RenewedDevice string `json:"renewed_device_lease_id"`
	Created       string `json:"created_at"`
	Expires       string `json:"expires_at"`
}

func (p *Packet) RequestTerms() (RequestTerms, error) {
	var terms RequestTerms
	if p.Role != "request" || json.Unmarshal(p.Payload, &terms) != nil {
		return terms, invalid()
	}
	return terms, nil
}

type PairingToken struct {
	Raw      []byte
	Request  *Packet
	Terms    RequestTerms
	Secret   []byte
	Contacts []*Contact
	Helpers  []ContactRelay
}

func tokenBody(token, prefix string) ([]byte, error) {
	if len(token) > MaxPairingToken {
		return nil, failure("quota_exceeded")
	}
	if !strings.HasPrefix(token, prefix) {
		return nil, invalid()
	}
	text := strings.TrimPrefix(token, prefix)
	raw, e := base64.RawURLEncoding.Strict().DecodeString(text)
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != text {
		return nil, invalid()
	}
	return raw, nil
}

// Token contact ordering does not normalize signed bodies. Equal semantic
// messages may have different exact envelopes; a same-sequence message fork is
// refused rather than resolved by its exact-byte hash.
func tokenContacts(raw json.RawMessage, context, host string) ([]*Contact, error) {
	var bodies []json.RawMessage
	if json.Unmarshal(raw, &bodies) != nil || bodies == nil || len(bodies) > 4 {
		return nil, invalid()
	}
	result := make([]*Contact, 0, len(bodies))
	for _, body := range bodies {
		c, e := ReadContact(body)
		if e != nil {
			return nil, e
		}
		if c.Context != context || c.Host != host {
			return nil, invalid()
		}
		if len(result) != 0 {
			previous := result[len(result)-1]
			if previous.Sequence > c.Sequence || previous.Sequence == c.Sequence && digest(previous.Raw) >= digest(c.Raw) {
				return nil, invalid()
			}
			if previous.Sequence == c.Sequence && !bytes.Equal(previous.Message, c.Message) {
				return nil, failure("state_conflict")
			}
		}
		result = append(result, c)
	}
	return result, nil
}

func tokenHelpers(raw json.RawMessage) ([]ContactRelay, error) {
	var helpers []ContactRelay
	if json.Unmarshal(raw, &helpers) != nil {
		return nil, invalid()
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) > 4 {
		return nil, invalid()
	}
	for index, entry := range entries {
		if _, e := readObject(entry, "address public_key"); e != nil {
			return nil, e
		}
		if !ValidEndpoint(helpers[index].Address) || !key(helpers[index].PublicKey) {
			return nil, invalid()
		}
		if index > 0 {
			previous, current := helpers[index-1], helpers[index]
			if previous.Address > current.Address || previous.Address == current.Address && previous.PublicKey >= current.PublicKey {
				return nil, invalid()
			}
		}
	}
	return helpers, nil
}

func ReadPairingToken(token string) (*PairingToken, error) {
	raw, e := tokenBody(token, "psl2-")
	if e != nil {
		return nil, e
	}
	o, e := readObjectLimit(raw, "format request_id secret_base64 request_packet_base64 contacts helpers", MaxPairingToken)
	if e != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	fields, e := texts(o, "request_id", "secret_base64", "request_packet_base64")
	if e != nil {
		return nil, e
	}
	secret, e := decode(fields[1], 16)
	if e != nil || len(secret) != 16 {
		return nil, invalid()
	}
	packetRaw, e := decode(fields[2], MaxRequest)
	if e != nil {
		return nil, e
	}
	request, e := ReadPacket(Descriptor{}, packetRaw)
	if e != nil {
		return nil, e
	}
	terms, e := request.RequestTerms()
	if e != nil || request.RequestID != fields[0] {
		return nil, invalid()
	}
	contacts, e := tokenContacts(o["contacts"], terms.Context, request.Writer)
	if e != nil {
		return nil, e
	}
	helpers, e := tokenHelpers(o["helpers"])
	if e != nil {
		return nil, e
	}
	return &PairingToken{raw, request, terms, secret, contacts, helpers}, nil
}

func (t *PairingToken) Current(now string) error {
	if _, e := stamp(now); e != nil {
		return e
	}
	if now < t.Terms.Created {
		return failure("not_yet_valid")
	}
	if now >= t.Terms.Expires {
		return failure("expired")
	}
	for _, c := range t.Contacts {
		if e := c.Current(now); e != nil {
			return e
		}
	}
	return nil
}

func PairingCode(request []byte, secret []byte, contacts []json.RawMessage, helpers []ContactRelay) (string, error) {
	p, e := ReadPacket(Descriptor{}, request)
	if e != nil || p.Role != "request" || len(secret) != 16 {
		return "", invalid()
	}
	// The wrapper has no signed authority of its own. A shared sorted-key writer
	// permits exact code regeneration after reopening with the other runtime;
	// request bytes and initial frame contact objects are retained verbatim.
	raw, e := json.Marshal(map[string]any{"format": uint64(1), "request_id": p.RequestID, "secret_base64": b64(secret), "request_packet_base64": b64(request), "contacts": contacts, "helpers": helpers})
	if e != nil {
		return "", e
	}
	code := "psl2-" + base64.RawURLEncoding.EncodeToString(raw)
	if _, e = ReadPairingToken(code); e != nil {
		return "", e
	}
	return code, nil
}

type ContactInvitation struct {
	Raw, Payload, Message                              []byte
	ID, Context, Host, Person, Member, Issued, Expires string
	Descriptor                                         Descriptor
	Contacts                                           []*Contact
	Helpers                                            []ContactRelay
}

func ReadContactInvitation(token string) (*ContactInvitation, error) {
	raw, e := tokenBody(token, "psi2-")
	if e != nil {
		return nil, e
	}
	return ReadContactInvitationBody(raw)
}

// ReadContactInvitationBody preserves the exact reviewed public invitation in
// private pending state. Reopen checks its creation-time validity separately.
func ReadContactInvitationBody(raw []byte) (*ContactInvitation, error) {
	if len("psi2-")+base64.RawURLEncoding.EncodedLen(len(raw)) > MaxPairingToken {
		return nil, failure("quota_exceeded")
	}
	o, e := readObjectLimit(raw, "format context_id inviter_host_public_key payload_base64 signature", MaxPairingToken)
	if e != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	fields, e := texts(o, "context_id", "inviter_host_public_key", "payload_base64", "signature")
	if e != nil || !identifier(fields[0], "ctx_") || !key(fields[1]) {
		return nil, invalid()
	}
	payload, e := decode(fields[2], MaxPairingToken)
	if e != nil {
		return nil, e
	}
	po, e := readObjectLimit(payload, "descriptor expected_person_public_key member issued_at expires_at contacts helpers", MaxPairingToken)
	if e != nil {
		return nil, e
	}
	terms, e := texts(po, "expected_person_public_key", "member", "issued_at", "expires_at")
	if e != nil || !literalOrKey(terms[0]) || !validMember(terms[1]) {
		return nil, invalid()
	}
	d, e := ReadDescriptor(po["descriptor"])
	if e != nil || d.ContextID != fields[0] {
		return nil, invalid()
	}
	issued, e := stamp(terms[2])
	if e != nil {
		return nil, e
	}
	expires, e := stamp(terms[3])
	if e != nil || expires.Sub(issued) != 300*time.Second {
		return nil, invalid()
	}
	message := message("peerspan-decentralized-contact-invitation-v1", fields[0], fields[1], digest(payload))
	if e = VerifySignature(fields[1], "ed25519", message, fields[3]); e != nil {
		return nil, e
	}
	contacts, e := tokenContacts(po["contacts"], d.ContextID, fields[1])
	if e != nil {
		return nil, e
	}
	helpers, e := tokenHelpers(po["helpers"])
	if e != nil {
		return nil, e
	}
	return &ContactInvitation{raw, payload, message, "di_" + digest(message), d.ContextID, fields[1], terms[0], terms[1], terms[2], terms[3], d, contacts, helpers}, nil
}

func (i *ContactInvitation) Current(now string) error {
	at, e := stamp(now)
	if e != nil {
		return e
	}
	issued, _ := stamp(i.Issued)
	if issued.After(at.Add(30 * time.Second)) {
		return failure("not_yet_valid")
	}
	if now >= i.Expires {
		return failure("expired")
	}
	for _, c := range i.Contacts {
		if e := c.Current(now); e != nil {
			return e
		}
	}
	return nil
}

func SignContactInvitation(d Descriptor, person, member, issued string, contacts []json.RawMessage, helpers []ContactRelay, host ed25519.PrivateKey) (string, error) {
	if len(host) != ed25519.PrivateKeySize {
		return "", invalid()
	}
	at, e := stamp(issued)
	if e != nil {
		return "", e
	}
	payload, e := json.Marshal(struct {
		Descriptor json.RawMessage   `json:"descriptor"`
		Person     string            `json:"expected_person_public_key"`
		Member     string            `json:"member"`
		Issued     string            `json:"issued_at"`
		Expires    string            `json:"expires_at"`
		Contacts   []json.RawMessage `json:"contacts"`
		Helpers    []ContactRelay    `json:"helpers"`
	}{d.Raw, person, member, issued, at.Add(300 * time.Second).UTC().Format(time.RFC3339), contacts, helpers})
	if e != nil {
		return "", e
	}
	public := b64(host.Public().(ed25519.PublicKey))
	m := message("peerspan-decentralized-contact-invitation-v1", d.ContextID, public, digest(payload))
	raw, e := json.Marshal(struct {
		Format    uint64 `json:"format"`
		Context   string `json:"context_id"`
		Host      string `json:"inviter_host_public_key"`
		Payload   string `json:"payload_base64"`
		Signature string `json:"signature"`
	}{1, d.ContextID, public, b64(payload), b64(ed25519.Sign(host, m))})
	if e != nil {
		return "", e
	}
	code := "psi2-" + base64.RawURLEncoding.EncodeToString(raw)
	if _, e = ReadContactInvitation(code); e != nil {
		return "", e
	}
	return code, nil
}
