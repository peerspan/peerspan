package helper

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"filippo.io/edwards25519"
)

const (
	maxMutationBody = 8 << 20
	maxCiphertext   = (4 << 20) + 16
	maxBoxBytes     = 32 << 20
	maxGetBody      = 48 << 20
)

type carrierFrame struct {
	Format     uint64 `json:"format"`
	RequestID  string `json:"request_id"`
	Locator    string `json:"locator"`
	Role       string `json:"role"`
	Writer     string `json:"writer_host_public_key"`
	FrameID    string `json:"frame_id"`
	Created    string `json:"created_at"`
	Expires    string `json:"expires_at"`
	Ciphertext string `json:"ciphertext_base64"`
	Signature  string `json:"signature"`
	Raw        []byte `json:"-"`
	Bytes      int64  `json:"-"`
}

type wireError string

func (e wireError) Error() string { return string(e) }

func wireHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func wireLines(parts ...string) []byte { return []byte(strings.Join(parts, "\n")) }

func wireID(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+64 {
		return false
	}
	for _, c := range s[len(prefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func publicKey(value string) (ed25519.PublicKey, error) {
	b, err := canonicalBase64(value, ed25519.PublicKeySize)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, wireError("invalid")
	}
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil || !bytes.Equal(p.Bytes(), b) || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, wireError("invalid")
	}
	return ed25519.PublicKey(b), nil
}

func wholeUTC(value string) (time.Time, error) {
	at, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || len(value) != 20 || at.Year() < 1 || at.Format("2006-01-02T15:04:05Z") != value {
		return time.Time{}, wireError("invalid")
	}
	return at, nil
}

func parseCarrierFrame(raw []byte, actualKey string) (*carrierFrame, error) {
	if len(raw) > maxMutationBody {
		return nil, wireError("quota_exceeded")
	}
	var frame carrierFrame
	if strictJSON(raw, &frame) != nil || frame.Format != 1 || !wireID(frame.RequestID, "link_") || !wireID(frame.Locator, "") || !wireID(frame.FrameID, "") {
		return nil, wireError("invalid")
	}
	switch frame.Role {
	case "request", "owner", "selection", "administrator", "owner_finalization", "commit", "outcome", "proofs":
	default:
		return nil, wireError("invalid")
	}
	key, err := publicKey(frame.Writer)
	if err != nil {
		return nil, wireError("invalid")
	}
	created, err := wholeUTC(frame.Created)
	if err != nil {
		return nil, err
	}
	expires, err := wholeUTC(frame.Expires)
	if err != nil || expires.Unix()-created.Unix() != 300 {
		return nil, wireError("invalid")
	}
	if len(frame.Ciphertext) > base64.StdEncoding.EncodedLen(maxCiphertext) {
		return nil, wireError("quota_exceeded")
	}
	ciphertext, err := canonicalBase64(frame.Ciphertext, maxCiphertext+2)
	if err != nil || len(ciphertext) < 16 {
		return nil, wireError("invalid")
	}
	if len(ciphertext) > maxCiphertext {
		return nil, wireError("quota_exceeded")
	}
	ad := wireLines("peerspan-decentralized-frame-v1", frame.RequestID, frame.Locator, frame.Role, frame.Writer, frame.FrameID, frame.Created, frame.Expires)
	message := wireLines("peerspan-decentralized-frame-envelope-v1", string(ad), wireHash(ciphertext))
	signature, err := canonicalBase64(frame.Signature, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature) {
		return nil, wireError("invalid")
	}
	if actualKey != "" && actualKey != frame.Writer {
		return nil, wireError("forbidden")
	}
	frame.Raw = append([]byte(nil), raw...)
	frame.Bytes = int64(len(ciphertext))
	return &frame, nil
}

func carrierWindow(created, expires string, now time.Time) error {
	start, err := wholeUTC(created)
	if err != nil {
		return err
	}
	end, err := wholeUTC(expires)
	if err != nil || end.Unix()-start.Unix() != 300 || start.After(now.Add(30*time.Second)) {
		return wireError("invalid")
	}
	if !now.Before(end) {
		return wireError("expired")
	}
	return nil
}
