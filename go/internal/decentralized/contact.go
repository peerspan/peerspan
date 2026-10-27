package decentralized

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const MaxContact = 8 << 10

type ContactRelay struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}
type ContactPayload struct {
	QUIC      []string       `json:"quic_addresses"`
	Bootstrap []string       `json:"bootstrap_addresses"`
	Relays    []ContactRelay `json:"relays"`
}
type Contact struct {
	Format                uint64         `json:"format"`
	Context               string         `json:"context_id"`
	Host                  string         `json:"host_public_key"`
	Sequence              uint64         `json:"sequence"`
	Issued                string         `json:"issued_at"`
	Expires               string         `json:"expires_at"`
	PayloadBase64         string         `json:"payload_base64"`
	Signature             string         `json:"signature"`
	Raw, Payload, Message []byte         `json:"-"`
	Addresses             ContactPayload `json:"-"`
}

// ValidEndpoint accepts only the signed new-mode canonical spelling. It does
// not resolve DNS, normalize an alias, or assert reachability/authority.
func ValidEndpoint(value string) bool {
	if len(value) == 0 || len(value) > 260 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	host, port, e := net.SplitHostPort(value)
	if e != nil || host == "" || net.JoinHostPort(host, port) != value {
		return false
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		return ip.Zone() == "" && !ip.IsUnspecified() && !ip.Is4In6() && ip.String() == host
	}
	if strings.ContainsAny(host, ":[]%") || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	numeric := true
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		onlyDigits := true
		for _, b := range []byte(label) {
			if b < '0' || b > '9' {
				onlyDigits = false
			}
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
		numeric = numeric && onlyDigits
	}
	return !numeric
}
func validateContactPayload(p ContactPayload) error {
	if p.QUIC == nil || p.Bootstrap == nil || p.Relays == nil || len(p.QUIC) > 8 || len(p.Bootstrap) > 8 || len(p.Relays) > 8 || len(p.QUIC)+len(p.Bootstrap)+len(p.Relays) > 16 {
		return invalid()
	}
	for _, list := range [][]string{p.QUIC, p.Bootstrap} {
		for index, address := range list {
			if !ValidEndpoint(address) || index > 0 && list[index-1] >= address {
				return invalid()
			}
		}
	}
	for index, r := range p.Relays {
		if !ValidEndpoint(r.Address) || !key(r.PublicKey) {
			return invalid()
		}
		if index > 0 {
			previous := p.Relays[index-1]
			if previous.Address > r.Address || previous.Address == r.Address && previous.PublicKey >= r.PublicKey {
				return invalid()
			}
		}
	}
	return nil
}
func ReadContact(raw []byte) (*Contact, error) {
	o, e := readObjectLimit(raw, "format context_id host_public_key sequence issued_at expires_at payload_base64 signature", MaxContact)
	if e != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	var c Contact
	if json.Unmarshal(raw, &c) != nil || !literalOrID(c.Context, "ctx_") || !key(c.Host) {
		return nil, invalid()
	}
	if _, e = num(o, "sequence"); e != nil {
		return nil, e
	}
	if _, e = texts(o, "context_id", "host_public_key", "issued_at", "expires_at", "payload_base64", "signature"); e != nil {
		return nil, e
	}
	issued, e := stamp(c.Issued)
	if e != nil {
		return nil, e
	}
	expires, e := stamp(c.Expires)
	if e != nil || !expires.After(issued) || expires.Sub(issued) > 300*time.Second {
		return nil, invalid()
	}
	c.Payload, e = decode(c.PayloadBase64, MaxContact)
	if e != nil {
		return nil, e
	}
	if _, e = readObjectLimit(c.Payload, "quic_addresses bootstrap_addresses relays", MaxContact); e != nil {
		return nil, e
	}
	if e = ReadPrivateRecord(c.Payload, "quic_addresses bootstrap_addresses relays", &c.Addresses); e != nil {
		return nil, e
	}
	if e = validateContactPayload(c.Addresses); e != nil {
		return nil, e
	}
	c.Message = message("peerspan-decentralized-contact-v1", c.Context, c.Host, strconv.FormatUint(c.Sequence, 10), c.Issued, c.Expires, digest(c.Payload))
	if e = VerifySignature(c.Host, "ed25519", c.Message, c.Signature); e != nil {
		return nil, e
	}
	c.Raw = append([]byte{}, raw...)
	return &c, nil
}
func (c *Contact) Current(now string) error {
	at, e := stamp(now)
	if e != nil {
		return e
	}
	issued, _ := stamp(c.Issued)
	expires, _ := stamp(c.Expires)
	if issued.After(at.Add(30 * time.Second)) {
		return failure("not_yet_valid")
	}
	if !at.Before(expires) {
		return failure("expired")
	}
	return nil
}
func SignContact(context string, sequence uint64, issued, expires string, p ContactPayload, host ed25519.PrivateKey) ([]byte, error) {
	if len(host) != ed25519.PrivateKeySize || !literalOrID(context, "ctx_") {
		return nil, invalid()
	}
	if e := validateContactPayload(p); e != nil {
		return nil, e
	}
	at, e := stamp(issued)
	if e != nil {
		return nil, e
	}
	end, e := stamp(expires)
	if e != nil || !end.After(at) || end.Sub(at) > 300*time.Second {
		return nil, invalid()
	}
	payload, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	public := b64(host.Public().(ed25519.PublicKey))
	m := message("peerspan-decentralized-contact-v1", context, public, strconv.FormatUint(sequence, 10), issued, expires, digest(payload))
	c := Contact{Format: 1, Context: context, Host: public, Sequence: sequence, Issued: issued, Expires: expires, PayloadBase64: b64(payload), Signature: b64(ed25519.Sign(host, m))}
	raw, e := json.Marshal(c)
	if e != nil {
		return nil, e
	}
	if _, e = ReadContact(raw); e != nil {
		return nil, e
	}
	return raw, nil
}
