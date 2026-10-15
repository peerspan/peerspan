package membership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Person statements are signed in OpenSSH SSHSIG format (PROTOCOL.sshsig), so
// a person key can stay in ssh-agent and `ssh-keygen -Y verify` accepts the
// signatures. Only ssh-ed25519 keys are supported.

const (
	PersonNamespace = "peerspan-person-v1"
	sshsigMagic     = "SSHSIG"
	sshsigHash      = "sha512"
	sshEd25519      = "ssh-ed25519"
)

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// SSHPublicKeyBlob is the OpenSSH wire encoding of an Ed25519 public key.
func SSHPublicKeyBlob(key ed25519.PublicKey) []byte {
	return append(sshString([]byte(sshEd25519)), sshString(key)...)
}

// SSHAuthorizedKey returns the `ssh-ed25519 AAAA…` line for a key.
func SSHAuthorizedKey(key ed25519.PublicKey) string {
	return sshEd25519 + " " + base64.StdEncoding.EncodeToString(SSHPublicKeyBlob(key))
}

// SSHSIGSignedData is what the person key signs for message.
func SSHSIGSignedData(message []byte) []byte {
	digest := sha512.Sum512(message)
	out := []byte(sshsigMagic)
	out = append(out, sshString([]byte(PersonNamespace))...)
	out = append(out, sshString(nil)...)
	out = append(out, sshString([]byte(sshsigHash))...)
	return append(out, sshString(digest[:])...)
}

// SSHSIGBlob assembles the binary SSHSIG blob for a raw Ed25519 signature
// over SSHSIGSignedData.
func SSHSIGBlob(key ed25519.PublicKey, signature []byte) []byte {
	out := []byte(sshsigMagic)
	out = binary.BigEndian.AppendUint32(out, 1)
	out = append(out, sshString(SSHPublicKeyBlob(key))...)
	out = append(out, sshString([]byte(PersonNamespace))...)
	out = append(out, sshString(nil)...)
	out = append(out, sshString([]byte(sshsigHash))...)
	return append(out, sshString(append(sshString([]byte(sshEd25519)), sshString(signature)...))...)
}

// PersonSigner produces raw Ed25519 signatures with a person key, for example
// through ssh-agent or from an OpenSSH key file.
type PersonSigner interface {
	PublicKey() ed25519.PublicKey
	Sign(data []byte) ([]byte, error)
}

// KeySigner signs with an in-memory Ed25519 key.
type KeySigner struct{ Key ed25519.PrivateKey }

func (k KeySigner) PublicKey() ed25519.PublicKey     { return k.Key.Public().(ed25519.PublicKey) }
func (k KeySigner) Sign(data []byte) ([]byte, error) { return ed25519.Sign(k.Key, data), nil }

// SignSSHSIG returns the standard Base64 of the binary SSHSIG blob.
func SignSSHSIG(signer PersonSigner, message []byte) (string, error) {
	signature, err := signer.Sign(SSHSIGSignedData(message))
	if err != nil {
		return "", err
	}
	if len(signature) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: person key returned a non-Ed25519 signature", ErrInvalid)
	}
	return base64.StdEncoding.EncodeToString(SSHSIGBlob(signer.PublicKey(), signature)), nil
}

type sshReader struct{ b []byte }

func (r *sshReader) string() ([]byte, bool) {
	if len(r.b) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(len(r.b)-4) < uint64(n) {
		return nil, false
	}
	value := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return value, true
}

// VerifySSHSIG checks a Base64 SSHSIG blob over message: magic and version 1,
// an ssh-ed25519 public key equal to key, the person namespace, an empty
// reserved field, sha512, and the Ed25519 signature.
func VerifySSHSIG(key ed25519.PublicKey, message []byte, signature string) error {
	blob, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || base64.StdEncoding.EncodeToString(blob) != signature {
		return fmt.Errorf("%w: SSHSIG signature must be canonical Base64", ErrInvalid)
	}
	invalid := fmt.Errorf("%w: malformed or mismatched SSHSIG signature", ErrInvalid)
	if !bytes.HasPrefix(blob, []byte(sshsigMagic)) || len(blob) < len(sshsigMagic)+4 {
		return invalid
	}
	r := &sshReader{b: blob[len(sshsigMagic):]}
	if binary.BigEndian.Uint32(r.b) != 1 {
		return invalid
	}
	r.b = r.b[4:]
	publicBlob, ok1 := r.string()
	namespace, ok2 := r.string()
	reserved, ok3 := r.string()
	hash, ok4 := r.string()
	sigBlob, ok5 := r.string()
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || len(r.b) != 0 {
		return invalid
	}
	if !bytes.Equal(publicBlob, SSHPublicKeyBlob(key)) || string(namespace) != PersonNamespace || len(reserved) != 0 || string(hash) != sshsigHash {
		return invalid
	}
	inner := &sshReader{b: sigBlob}
	format, ok1 := inner.string()
	raw, ok2 := inner.string()
	if !ok1 || !ok2 || len(inner.b) != 0 || string(format) != sshEd25519 || len(raw) != ed25519.SignatureSize {
		return invalid
	}
	if !ed25519.Verify(key, SSHSIGSignedData(message), raw) {
		return fmt.Errorf("%w: SSHSIG signature does not verify", ErrInvalid)
	}
	return nil
}

// NormalizePersonKey accepts canonical Base64 of a raw Ed25519 key or an
// `ssh-ed25519 AAAA… [comment]` line, and returns canonical Base64.
func NormalizePersonKey(value string) (string, error) {
	if _, err := DecodeKey(value); err == nil {
		return value, nil
	}
	fields := strings.Fields(value)
	if len(fields) < 2 || fields[0] != sshEd25519 {
		return "", fmt.Errorf("%w: person key must be canonical Base64 or an ssh-ed25519 line", ErrInvalid)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(fields[1])
	if err != nil {
		return "", fmt.Errorf("%w: malformed ssh-ed25519 key", ErrInvalid)
	}
	r := &sshReader{b: blob}
	kind, ok1 := r.string()
	key, ok2 := r.string()
	if !ok1 || !ok2 || len(r.b) != 0 || string(kind) != sshEd25519 || len(key) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: malformed ssh-ed25519 key", ErrInvalid)
	}
	return EncodeKey(key), nil
}
