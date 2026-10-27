package decentralized

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const MaxFramePlaintext = 4 << 20
const MaxFrameWire = 8 << 20
const MaxCatalogComponent = 2 << 20

type Frame struct {
	Format             uint64 `json:"format"`
	Request            string `json:"request_id"`
	Locator            string `json:"locator"`
	Role               string `json:"role"`
	Writer             string `json:"writer_host_public_key"`
	ID                 string `json:"frame_id"`
	Created            string `json:"created_at"`
	Expires            string `json:"expires_at"`
	Ciphertext         string `json:"ciphertext_base64"`
	Signature          string `json:"signature"`
	Raw, Encrypted, AD []byte `json:"-"`
}
type FramePlaintext struct {
	Packet   string            `json:"packet_base64"`
	Catalog  string            `json:"catalog_base64"`
	Contacts []json.RawMessage `json:"contacts"`
}

func FrameLocator(secret []byte) (string, error) {
	if len(secret) != 16 {
		return "", invalid()
	}
	return digest(message("peerspan-decentralized-locator-v1", b64(secret))), nil
}
func FrameReadCapability(secret []byte) ([]byte, error) {
	if len(secret) != 16 {
		return nil, invalid()
	}
	h := sha256.Sum256(message("peerspan-decentralized-read-cap-v1", b64(secret)))
	return h[:], nil
}
func frameAD(f Frame) []byte {
	return message("peerspan-decentralized-frame-v1", f.Request, f.Locator, f.Role, f.Writer, f.ID, f.Created, f.Expires)
}
func frameMessage(f Frame, ciphertext []byte) []byte {
	return message("peerspan-decentralized-frame-envelope-v1", string(frameAD(f)), digest(ciphertext))
}
func validFrameRole(role string) bool {
	switch role {
	case "request", "owner", "selection", "administrator", "owner_finalization", "commit", "outcome", "proofs":
		return true
	}
	return false
}
func ReadFrame(raw []byte) (*Frame, error) {
	o, e := readObjectLimit(raw, "format request_id locator role writer_host_public_key frame_id created_at expires_at ciphertext_base64 signature", MaxFrameWire)
	if e != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	var f Frame
	if json.Unmarshal(raw, &f) != nil || !identifier(f.Request, "link_") || !identifier(f.Locator, "") || !identifier(f.ID, "") || !key(f.Writer) || !validFrameRole(f.Role) {
		return nil, invalid()
	}
	if _, e = texts(o, "request_id", "locator", "role", "writer_host_public_key", "frame_id", "created_at", "expires_at", "ciphertext_base64", "signature"); e != nil {
		return nil, e
	}
	created, e := stamp(f.Created)
	if e != nil {
		return nil, e
	}
	expires, e := stamp(f.Expires)
	if e != nil || expires.Sub(created) != 300*time.Second {
		return nil, invalid()
	}
	f.Encrypted, e = decode(f.Ciphertext, MaxFramePlaintext+16)
	if e != nil {
		return nil, e
	}
	if len(f.Encrypted) < 16 {
		return nil, invalid()
	}
	f.AD = frameAD(f)
	if e = VerifySignature(f.Writer, "ed25519", frameMessage(f, f.Encrypted), f.Signature); e != nil {
		return nil, e
	}
	f.Raw = append([]byte{}, raw...)
	return &f, nil
}
func frameCipher(secret []byte, f Frame) (cipher.AEAD, []byte, error) {
	locator, e := FrameLocator(secret)
	if e != nil {
		return nil, nil, e
	}
	if locator != f.Locator {
		return nil, nil, invalid()
	}
	salt := sha256.Sum256(message("peerspan-decentralized-frame-salt-v1", f.Request))
	key := make([]byte, 32)
	if _, e = io.ReadFull(hkdf.New(sha256.New, secret, salt[:], message("peerspan-decentralized-frame-key-v1", f.Request, f.Role, f.Writer)), key); e != nil {
		return nil, nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, nil, e
	}
	nonce := sha256.Sum256(message("peerspan-decentralized-frame-nonce-v1", f.ID))
	return aead, nonce[:12], nil
}
func validateFramePlaintext(d Descriptor, raw []byte, role, writer string) (FramePlaintext, error) {
	var p FramePlaintext
	if e := readObjectFields(raw, "packet_base64 catalog_base64 contacts", MaxFramePlaintext, &p); e != nil {
		return p, e
	}
	if p.Packet == "-" && p.Catalog == "-" || p.Contacts == nil || len(p.Contacts) > 4 {
		return p, invalid()
	}
	if role == "proofs" && p.Packet != "-" || role != "proofs" && p.Packet == "-" {
		return p, invalid()
	}
	if p.Packet != "-" {
		packetRaw, e := decode(p.Packet, MaxObject)
		if e != nil {
			return p, e
		}
		packet, e := readFramePacket(d, packetRaw)
		if e != nil {
			return p, e
		}
		if packet.Role != role || packet.Writer != writer {
			return p, invalid()
		}
		if d.ContextID == "" && packet.Role == "owner" {
			d, e = ReadDescriptor(packet.Object["descriptor"])
			if e != nil {
				return p, e
			}
		}
	}
	if p.Catalog != "-" {
		catalogRaw, e := decode(p.Catalog, MaxCatalogComponent)
		if e != nil {
			return p, e
		}
		if _, e = ReadCatalog(d, catalogRaw); e != nil {
			return p, e
		}
	}
	previous := ""
	for _, raw := range p.Contacts {
		c, e := ReadContact(raw)
		if e != nil {
			return p, e
		}
		// Frame contacts are transport hints. Their signatures/shape are checked;
		// network eligibility, time and sticky sequence are separate host decisions.
		hash := digest(c.Raw)
		order := c.Context + "\n" + c.Host + "\n" + hex.EncodeToString(uint64Bytes(c.Sequence)) + "\n" + hash
		if previous != "" && order <= previous {
			return p, invalid()
		}
		previous = order
	}
	return p, nil
}
func readObjectFields(raw []byte, fields string, max int, target any) error {
	if _, e := readObjectLimit(raw, fields, max); e != nil {
		return e
	}
	return ReadPrivateRecord(raw, fields, target)
}
func uint64Bytes(value uint64) []byte {
	result := make([]byte, 8)
	for index := 7; index >= 0; index-- {
		result[index] = byte(value)
		value >>= 8
	}
	return result
}

// SealFrame creates exactly one envelope. The caller supplies a fresh frame ID,
// persists returned exact bytes before publication, and never reseals a retry.
func SealFrame(d Descriptor, secret []byte, request, role, id, created, expires string, plaintext []byte, host ed25519.PrivateKey) ([]byte, error) {
	if len(host) != ed25519.PrivateKeySize || !identifier(request, "link_") || !identifier(id, "") || !validFrameRole(role) {
		return nil, invalid()
	}
	locator, e := FrameLocator(secret)
	if e != nil {
		return nil, e
	}
	writer := b64(host.Public().(ed25519.PublicKey))
	p, e := validateFramePlaintext(d, plaintext, role, writer)
	if e != nil {
		return nil, e
	}
	start, e := stamp(created)
	if e != nil {
		return nil, e
	}
	end, e := stamp(expires)
	if e != nil || end.Sub(start) != 300*time.Second {
		return nil, invalid()
	}
	f := Frame{Format: 1, Request: request, Locator: locator, Role: role, Writer: writer, ID: id, Created: created, Expires: expires}
	if e = framePacketPins(d, f, p); e != nil {
		return nil, e
	}
	aead, nonce, e := frameCipher(secret, f)
	if e != nil {
		return nil, e
	}
	encrypted := aead.Seal(nil, nonce, plaintext, frameAD(f))
	f.Ciphertext = b64(encrypted)
	f.Signature = b64(ed25519.Sign(host, frameMessage(f, encrypted)))
	raw, e := json.Marshal(f)
	if e != nil {
		return nil, e
	}
	if _, e = ReadFrame(raw); e != nil {
		return nil, e
	}
	return raw, nil
}
func OpenFrame(d Descriptor, secret, raw []byte) (FramePlaintext, []byte, error) {
	var empty FramePlaintext
	f, e := ReadFrame(raw)
	if e != nil {
		return empty, nil, e
	}
	aead, nonce, e := frameCipher(secret, *f)
	if e != nil {
		return empty, nil, e
	}
	plaintext, e := aead.Open(nil, nonce, f.Encrypted, f.AD)
	if e != nil {
		return empty, nil, invalid()
	}
	p, e := validateFramePlaintext(d, plaintext, f.Role, f.Writer)
	if e != nil {
		return empty, nil, e
	}
	if e = framePacketPins(d, *f, p); e != nil {
		return empty, nil, e
	}
	return p, plaintext, nil
}

// OpenFrameContexts selects only among caller-supplied exact descriptors. The
// untrusted inner context ID is a parsing selector, never context adoption or
// authority. Decrypt once rather than retrying a large carrier per context.
func OpenFrameContexts(descriptors map[string]Descriptor, secret, raw []byte) (FramePlaintext, error) {
	var empty FramePlaintext
	f, e := ReadFrame(raw)
	if e != nil {
		return empty, e
	}
	aead, nonce, e := frameCipher(secret, *f)
	if e != nil {
		return empty, e
	}
	plain, e := aead.Open(nil, nonce, f.Encrypted, f.AD)
	if e != nil {
		return empty, invalid()
	}
	var envelope FramePlaintext
	if e = readObjectFields(plain, "packet_base64 catalog_base64 contacts", MaxFramePlaintext, &envelope); e != nil {
		return empty, e
	}
	context := ""
	if envelope.Packet != "-" {
		body, e := decode(envelope.Packet, MaxObject)
		if e != nil {
			return empty, e
		}
		o, e := parse(body)
		if e != nil {
			return empty, e
		}
		context = stringField(o, "context_id")
	} else if envelope.Catalog != "-" {
		body, e := decode(envelope.Catalog, MaxCatalogComponent)
		if e != nil {
			return empty, e
		}
		o, e := parseLimit(body, MaxCatalogComponent)
		if e != nil {
			return empty, e
		}
		context = stringField(o, "context_id")
	}
	d, ok := descriptors[context]
	if !ok || d.ContextID != context {
		return empty, invalid()
	}
	result, e := validateFramePlaintext(d, plain, f.Role, f.Writer)
	if e != nil {
		return empty, e
	}
	if e = framePacketPins(d, *f, result); e != nil {
		return empty, e
	}
	return result, nil
}

func framePacketPins(d Descriptor, f Frame, p FramePlaintext) error {
	if p.Packet == "-" {
		return nil
	}
	raw, e := decode(p.Packet, MaxObject)
	if e != nil {
		return e
	}
	packet, e := readFramePacket(d, raw)
	if e != nil {
		return e
	}
	if packet.RequestID != f.Request {
		return invalid()
	}
	if packet.Role == "request" && (stringField(packet.Object, "created_at") != f.Created || stringField(packet.Object, "expires_at") != f.Expires) {
		return invalid()
	}
	return nil
}

func readFramePacket(d Descriptor, raw []byte) (*Packet, error) {
	// An unadopted requester can receive an owner's self-contained introduction.
	// Its descriptor is an untrusted decoding context only; no adoption, provider
	// selection, consent or public authority follows from decrypting this frame.
	if d.ContextID == "" {
		o, e := parse(raw)
		if e != nil {
			return nil, e
		}
		if stringField(o, "role") == "owner" {
			payload, e := decode(stringField(o, "payload_base64"), MaxPayload)
			if e != nil {
				return nil, e
			}
			terms, e := parseLimit(payload, MaxPayload)
			if e != nil {
				return nil, e
			}
			d, e = ReadDescriptor(terms["descriptor"])
			if e != nil {
				return nil, e
			}
		}
	}
	return readPacket(d, raw)
}
