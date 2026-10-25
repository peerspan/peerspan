package host

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"github.com/peerspan/peerspan/go/internal/membership"
)

const linkPlainLimit = 64 << 10

type linkFrame struct {
	Format          uint64 `json:"format"`
	RequestID       string `json:"request_id"`
	Locator         string `json:"locator"`
	Role            string `json:"role"`
	WriterPublicKey string `json:"writer_public_key"`
	FrameID         string `json:"frame_id"`
	Ciphertext      string `json:"ciphertext"`
}

func linkHash(b []byte) string           { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func linkMessage(parts ...string) []byte { return []byte(strings.Join(parts, "\n")) }
func linkID(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, b := range value[len(prefix):] {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
func linkPublicKey(value string) bool {
	b, e := membership.DecodeKey(value)
	if e != nil {
		return false
	}
	p, e := new(edwards25519.Point).SetBytes(b)
	return e == nil && bytes.Equal(p.Bytes(), b) && new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1
}
func linkBytes(value string, limit int) ([]byte, error) {
	if len(value) > ((limit+2)/3)*4 {
		return nil, fmt.Errorf("invalid linking encoding")
	}
	b, e := base64.StdEncoding.DecodeString(value)
	if e != nil || len(b) > limit || base64.StdEncoding.EncodeToString(b) != value {
		return nil, fmt.Errorf("invalid linking encoding")
	}
	return b, nil
}
func linkJSON(value any) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var plain any
	if e = d.Decode(&plain); e != nil {
		return nil, e
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if e = enc.Encode(plain); e != nil {
		return nil, e
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}
func linkCode(secret []byte) string {
	if len(secret) != 16 {
		return ""
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return "psl1-" + s[:5] + "-" + s[5:10] + "-" + s[10:15] + "-" + s[15:20] + "-" + s[20:]
}
func linkSecret(value string) ([]byte, error) {
	for _, b := range []byte(value) {
		if b > 127 {
			return nil, fmt.Errorf("invalid linking code")
		}
	}
	upper := strings.ToUpper(value)
	if len(upper) == 35 && strings.HasPrefix(upper, "PSL1-") {
		groups := strings.Split(upper[5:], "-")
		if len(groups) != 5 || len(groups[0]) != 5 || len(groups[1]) != 5 || len(groups[2]) != 5 || len(groups[3]) != 5 || len(groups[4]) != 6 {
			return nil, fmt.Errorf("invalid linking code")
		}
		upper = strings.Join(groups, "")
	}
	if len(upper) != 26 {
		return nil, fmt.Errorf("invalid linking code")
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	b, e := encoding.DecodeString(upper)
	if e != nil || len(b) != 16 || encoding.EncodeToString(b) != upper {
		return nil, fmt.Errorf("invalid linking code")
	}
	return b, nil
}
func linkLocator(secret []byte) string {
	return linkHash(append([]byte("peerspan-link-locator-v1\x00"), secret...))
}
func linkFrameAEAD(secret []byte, coordinator string, f linkFrame) (cipher.AEAD, []byte, error) {
	if len(secret) != 16 || f.Format != 1 || !linkID(f.RequestID, "link_") || !linkID(f.Locator, "") || !linkID(f.FrameID, "") || !linkPublicKey(coordinator) || !linkPublicKey(f.WriterPublicKey) || f.Locator != linkLocator(secret) {
		return nil, nil, fmt.Errorf("invalid linking frame")
	}
	switch f.Role {
	case "request", "owner", "selection", "administrator", "commit", "result":
	default:
		return nil, nil, fmt.Errorf("invalid linking frame")
	}
	coord, _ := membership.DecodeKey(coordinator)
	salt := sha256.Sum256(append([]byte("peerspan-link-extract-v1\x00"), coord...))
	prk, e := hkdf.Extract(sha256.New, secret, salt[:])
	if e != nil {
		return nil, nil, e
	}
	context := linkMessage("peerspan-link-frame-v1", f.RequestID, f.Locator, coordinator, f.Role, f.WriterPublicKey, f.FrameID)
	key, e := hkdf.Expand(sha256.New, prk, string(context), 32)
	if e != nil {
		return nil, nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, nil, e
	}
	aead, e := cipher.NewGCM(block)
	return aead, context, e
}

// sealLinkFrame allocates a one-use frame ID. Callers persist the returned exact
// bytes before publishing and retransmit those bytes after an uncertain result.
func sealLinkFrame(secret []byte, coordinator, request, role, writer string, plaintext []byte) (linkFrame, []byte, error) {
	f := linkFrame{Format: 1, RequestID: request, Locator: linkLocator(secret), Role: role, WriterPublicKey: writer}
	if len(plaintext) > linkPlainLimit {
		return f, nil, fmt.Errorf("linking frame plaintext exceeds limit")
	}
	var id [32]byte
	if _, e := rand.Read(id[:]); e != nil {
		return f, nil, e
	}
	f.FrameID = hex.EncodeToString(id[:])
	aead, aad, e := linkFrameAEAD(secret, coordinator, f)
	if e != nil {
		return f, nil, e
	}
	f.Ciphertext = base64.StdEncoding.EncodeToString(aead.Seal(nil, make([]byte, aead.NonceSize()), plaintext, aad))
	raw, e := linkJSON(f)
	return f, raw, e
}
func openLinkFrame(secret []byte, coordinator string, f linkFrame) ([]byte, error) {
	aead, aad, e := linkFrameAEAD(secret, coordinator, f)
	if e != nil {
		return nil, e
	}
	ciphertext, e := linkBytes(f.Ciphertext, linkPlainLimit+aead.Overhead())
	if e != nil || len(ciphertext) < aead.Overhead() {
		return nil, fmt.Errorf("invalid linking frame")
	}
	plaintext, e := aead.Open(nil, make([]byte, aead.NonceSize()), ciphertext, aad)
	if e != nil {
		return nil, fmt.Errorf("invalid linking frame")
	}
	return plaintext, nil
}
