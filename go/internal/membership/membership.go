// Package membership implements the signed network membership chain:
// root key → one-time invite key → host key. Hosts verify every chain
// themselves; a coordinator only stores and distributes them.
package membership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid membership")

const TokenPrefix = "capsule-invite-v1."

// Membership is the signed chain proving that a host joined a network.
type Membership struct {
	NetworkID       string `json:"network_id"`
	Member          string `json:"member"`
	InvitePublicKey string `json:"invite_public_key"`
	InviteExpiresAt string `json:"invite_expires_at"`
	InviteSignature string `json:"invite_signature"`
	HostPublicKey   string `json:"host_public_key"`
	JoinedAt        string `json:"joined_at"`
	HostSignature   string `json:"host_signature"`
}

var membershipFields = []string{"network_id", "member", "invite_public_key", "invite_expires_at", "invite_signature", "host_public_key", "joined_at", "host_signature"}

// Token is the decoded bearer invite. InviteSeed is the one-time private key.
type Token struct {
	NetworkID            string `json:"network_id"`
	NetworkName          string `json:"network_name"`
	RootPublicKey        string `json:"root_public_key"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
	Member               string `json:"member"`
	InvitePublicKey      string `json:"invite_public_key"`
	InviteSeed           string `json:"invite_seed"`
	InviteExpiresAt      string `json:"invite_expires_at"`
	InviteSignature      string `json:"invite_signature"`
}

var tokenFields = []string{"network_id", "network_name", "root_public_key", "coordinator_address", "coordinator_public_key", "member", "invite_public_key", "invite_seed", "invite_expires_at", "invite_signature"}

func digestID(prefix string, public []byte) string {
	sum := sha256.Sum256(public)
	return prefix + hex.EncodeToString(sum[:])
}
func NetworkID(root ed25519.PublicKey) string        { return digestID("net_", root) }
func HostID(host ed25519.PublicKey) string           { return digestID("host_", host) }
func CoordinatorID(coord ed25519.PublicKey) string   { return digestID("coord_", coord) }
func EncodeKey(b []byte) string                      { return base64.StdEncoding.EncodeToString(b) }
func Seed(key ed25519.PrivateKey) string             { return EncodeKey(key.Seed()) }
func PublicKey(key ed25519.PrivateKey) string        { return EncodeKey(key.Public().(ed25519.PublicKey)) }
func Timestamp(t time.Time) string                   { return t.UTC().Format(time.RFC3339Nano) }
func ParseTime(value string) (time.Time, error)      { return time.Parse(time.RFC3339Nano, value) }
func sign(key ed25519.PrivateKey, msg []byte) string { return EncodeKey(ed25519.Sign(key, msg)) }

// canonical decodes standard Base64 of exactly size bytes and rejects any
// spelling that does not re-encode identically.
func canonical(value string, size int) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != size || base64.StdEncoding.EncodeToString(b) != value {
		return nil, fmt.Errorf("%w: expected canonical Base64 of %d bytes", ErrInvalid, size)
	}
	return b, nil
}
func DecodeKey(value string) (ed25519.PublicKey, error) {
	b, err := canonical(value, ed25519.PublicKeySize)
	return ed25519.PublicKey(b), err
}
func DecodeSeed(value string) (ed25519.PrivateKey, error) {
	b, err := canonical(value, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(b), nil
}
func verify(key ed25519.PublicKey, msg []byte, signature string) error {
	sig, err := canonical(signature, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, msg, sig) {
		return fmt.Errorf("%w: signature does not verify", ErrInvalid)
	}
	return nil
}

// ValidLabel reports whether a name or member label is already trimmed,
// 1–128 UTF-8 bytes, and free of control characters.
func ValidLabel(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidAddress accepts "" (not directly reachable) or a literal IP:PORT.
func ValidAddress(value string) bool {
	if value == "" {
		return true
	}
	address, err := netip.ParseAddrPort(value)
	return err == nil && address.Port() != 0 && address.Addr().Zone() == ""
}

// ValidCoordinatorAddress accepts HOST:PORT, where HOST is an IP or DNS name.
func ValidCoordinatorAddress(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\@?#%") {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	for _, r := range host {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func InviteStatement(networkID, invitePublicKey, member, expiresAt string) []byte {
	return []byte(strings.Join([]string{"capsule-invite-v1", networkID, invitePublicKey, member, expiresAt}, "\n"))
}
func MemberStatement(networkID, invitePublicKey, hostPublicKey, joinedAt string) []byte {
	return []byte(strings.Join([]string{"capsule-member-v1", networkID, invitePublicKey, hostPublicKey, joinedAt}, "\n"))
}

// Invite creates a one-time invite key for member, signed by the root key.
func Invite(root ed25519.PrivateKey, member, expiresAt string) (Token, error) {
	if !ValidLabel(member) {
		return Token{}, fmt.Errorf("%w: invalid member label", ErrInvalid)
	}
	if _, err := ParseTime(expiresAt); err != nil {
		return Token{}, fmt.Errorf("%w: invalid expiration", ErrInvalid)
	}
	_, invite, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Token{}, err
	}
	network := NetworkID(root.Public().(ed25519.PublicKey))
	t := Token{NetworkID: network, RootPublicKey: PublicKey(root), Member: member, InvitePublicKey: PublicKey(invite), InviteSeed: Seed(invite), InviteExpiresAt: expiresAt}
	t.InviteSignature = sign(root, InviteStatement(network, t.InvitePublicKey, member, expiresAt))
	return t, nil
}

// Join signs host's key with the token's invite key.
func (t Token) Join(host ed25519.PrivateKey, joinedAt string) (Membership, error) {
	invite, err := DecodeSeed(t.InviteSeed)
	if err != nil {
		return Membership{}, err
	}
	m := Membership{NetworkID: t.NetworkID, Member: t.Member, InvitePublicKey: t.InvitePublicKey, InviteExpiresAt: t.InviteExpiresAt, InviteSignature: t.InviteSignature, HostPublicKey: PublicKey(host), JoinedAt: joinedAt}
	m.HostSignature = sign(invite, MemberStatement(m.NetworkID, m.InvitePublicKey, m.HostPublicKey, joinedAt))
	return m, nil
}

// Verify checks the chain against the network root key and returns the host ID.
func (m Membership) Verify(root ed25519.PublicKey) (string, error) {
	if m.NetworkID != NetworkID(root) {
		return "", fmt.Errorf("%w: network ID does not match root key", ErrInvalid)
	}
	if !ValidLabel(m.Member) {
		return "", fmt.Errorf("%w: invalid member label", ErrInvalid)
	}
	invite, err := DecodeKey(m.InvitePublicKey)
	if err != nil {
		return "", err
	}
	host, err := DecodeKey(m.HostPublicKey)
	if err != nil {
		return "", err
	}
	expires, err := ParseTime(m.InviteExpiresAt)
	if err != nil {
		return "", fmt.Errorf("%w: invalid invite expiration", ErrInvalid)
	}
	joined, err := ParseTime(m.JoinedAt)
	if err != nil {
		return "", fmt.Errorf("%w: invalid join time", ErrInvalid)
	}
	if err = verify(root, InviteStatement(m.NetworkID, m.InvitePublicKey, m.Member, m.InviteExpiresAt), m.InviteSignature); err != nil {
		return "", err
	}
	if err = verify(invite, MemberStatement(m.NetworkID, m.InvitePublicKey, m.HostPublicKey, m.JoinedAt), m.HostSignature); err != nil {
		return "", err
	}
	if joined.After(expires) {
		return "", fmt.Errorf("%w: joined after invite expiration", ErrInvalid)
	}
	return HostID(host), nil
}

// UnmarshalJSON requires exactly the membership fields, none null.
func (m *Membership) UnmarshalJSON(data []byte) error {
	type plain Membership
	return Strict(data, (*plain)(m), membershipFields...)
}

// Encode returns the bearer token string.
func (t Token) Encode() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeToken parses a token and checks everything that can be checked
// without contacting the coordinator.
func DecodeToken(value string, now time.Time) (Token, error) {
	var t Token
	encoded, ok := strings.CutPrefix(value, TokenPrefix)
	if !ok {
		return t, fmt.Errorf("%w: not an invite token", ErrInvalid)
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != encoded {
		return t, fmt.Errorf("%w: malformed invite token", ErrInvalid)
	}
	if err = Strict(data, &t, tokenFields...); err != nil {
		return t, err
	}
	root, err := DecodeKey(t.RootPublicKey)
	if err != nil {
		return t, err
	}
	if t.NetworkID != NetworkID(root) {
		return t, fmt.Errorf("%w: network ID does not match root key", ErrInvalid)
	}
	if !ValidLabel(t.NetworkName) || !ValidLabel(t.Member) {
		return t, fmt.Errorf("%w: invalid label", ErrInvalid)
	}
	if !ValidCoordinatorAddress(t.CoordinatorAddress) {
		return t, fmt.Errorf("%w: invalid coordinator address", ErrInvalid)
	}
	if _, err = DecodeKey(t.CoordinatorPublicKey); err != nil {
		return t, err
	}
	invite, err := DecodeSeed(t.InviteSeed)
	if err != nil {
		return t, err
	}
	if PublicKey(invite) != t.InvitePublicKey {
		return t, fmt.Errorf("%w: invite seed does not match its public key", ErrInvalid)
	}
	expires, err := ParseTime(t.InviteExpiresAt)
	if err != nil {
		return t, fmt.Errorf("%w: invalid invite expiration", ErrInvalid)
	}
	if !expires.After(now) {
		return t, fmt.Errorf("%w: invite has expired", ErrInvalid)
	}
	if err = verify(root, InviteStatement(t.NetworkID, t.InvitePublicKey, t.Member, t.InviteExpiresAt), t.InviteSignature); err != nil {
		return t, err
	}
	return t, nil
}

// Strict decodes one JSON object containing exactly fields, none null, and
// nothing after it.
func Strict(data []byte, dst any, fields ...string) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var raw map[string]json.RawMessage
	if err := decoder.Decode(&raw); err != nil || raw == nil {
		return fmt.Errorf("%w: expected a JSON object", ErrInvalid)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON", ErrInvalid)
	}
	if len(raw) != len(fields) {
		return fmt.Errorf("%w: unexpected or missing fields", ErrInvalid)
	}
	for _, field := range fields {
		value, ok := raw[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%w: missing or null field %s", ErrInvalid, field)
		}
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// Map is the coordinator's view of a network, served to its members. Hosts
// verify every entry before using it.
type Map struct {
	NetworkID     string      `json:"network_id"`
	Name          string      `json:"name"`
	RootPublicKey string      `json:"root_public_key"`
	Members       []MapMember `json:"members"`
}

type MapMember struct {
	HostID string `json:"host_id"`
	// Membership stays raw so a host can reject one bad entry without
	// rejecting the map.
	Membership json.RawMessage `json:"membership"`
	Address    string          `json:"address"`
	UpdatedAt  string          `json:"updated_at"`
}
