package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Statements that revoke membership, record departures, and rotate the root.
// Revocations are sticky: hosts persist every valid one they see.

var (
	ErrFork = errors.New("root chain conflict")
	// ErrBehind marks a chain shorter than one already persisted.
	ErrBehind = errors.New("coordinator root chain is behind this host")
)

const (
	KindHost   = "host"
	KindInvite = "invite"
	KindLeave  = "leave"
)

type HostRevocation struct {
	NetworkID     string `json:"network_id"`
	HostPublicKey string `json:"host_public_key"`
	RevokedAt     string `json:"revoked_at"`
	Signature     string `json:"signature"`
}

type InviteRevocation struct {
	NetworkID       string `json:"network_id"`
	InvitePublicKey string `json:"invite_public_key"`
	RevokedAt       string `json:"revoked_at"`
	Signature       string `json:"signature"`
}

type Leave struct {
	NetworkID     string `json:"network_id"`
	HostPublicKey string `json:"host_public_key"`
	LeftAt        string `json:"left_at"`
	Signature     string `json:"signature"`
}

type Rotation struct {
	NetworkID             string `json:"network_id"`
	Epoch                 int64  `json:"epoch"`
	PreviousRootPublicKey string `json:"previous_root_public_key"`
	RootPublicKey         string `json:"root_public_key"`
	RotatedAt             string `json:"rotated_at"`
	Signature             string `json:"signature"`
}

type Attestation struct {
	NetworkID     string `json:"network_id"`
	Epoch         int64  `json:"epoch"`
	HostPublicKey string `json:"host_public_key"`
	Member        string `json:"member"`
	AttestedAt    string `json:"attested_at"`
	Signature     string `json:"signature"`
}

// Revocation is a map entry: a host revocation, invite revocation, or leave.
type Revocation struct {
	Kind      string          `json:"kind"`
	Statement json.RawMessage `json:"statement"`
}

func statement(lines ...string) []byte { return []byte(strings.Join(lines, "\n")) }

func (r HostRevocation) Message() []byte {
	return statement("capsule-revoke-host-v1", r.NetworkID, r.HostPublicKey, r.RevokedAt)
}
func (r InviteRevocation) Message() []byte {
	return statement("capsule-revoke-invite-v1", r.NetworkID, r.InvitePublicKey, r.RevokedAt)
}
func (l Leave) Message() []byte {
	return statement("capsule-leave-v1", l.NetworkID, l.HostPublicKey, l.LeftAt)
}
func (r Rotation) Message() []byte {
	return statement("capsule-root-rotate-v1", r.NetworkID, strconv.FormatInt(r.Epoch, 10), r.PreviousRootPublicKey, r.RootPublicKey, r.RotatedAt)
}
func (a Attestation) Message() []byte {
	return statement("capsule-attest-v1", a.NetworkID, strconv.FormatInt(a.Epoch, 10), a.HostPublicKey, a.Member, a.AttestedAt)
}

func (r *HostRevocation) UnmarshalJSON(data []byte) error {
	type plain HostRevocation
	return Strict(data, (*plain)(r), "network_id", "host_public_key", "revoked_at", "signature")
}
func (r *InviteRevocation) UnmarshalJSON(data []byte) error {
	type plain InviteRevocation
	return Strict(data, (*plain)(r), "network_id", "invite_public_key", "revoked_at", "signature")
}
func (l *Leave) UnmarshalJSON(data []byte) error {
	type plain Leave
	return Strict(data, (*plain)(l), "network_id", "host_public_key", "left_at", "signature")
}
func (r *Rotation) UnmarshalJSON(data []byte) error {
	type plain Rotation
	return Strict(data, (*plain)(r), "network_id", "epoch", "previous_root_public_key", "root_public_key", "rotated_at", "signature")
}
func (a *Attestation) UnmarshalJSON(data []byte) error {
	type plain Attestation
	return Strict(data, (*plain)(a), "network_id", "epoch", "host_public_key", "member", "attested_at", "signature")
}
func (r *Revocation) UnmarshalJSON(data []byte) error {
	type plain Revocation
	return Strict(data, (*plain)(r), "kind", "statement")
}

func validTime(value string) error {
	if _, err := ParseTime(value); err != nil {
		return fmt.Errorf("%w: invalid time", ErrInvalid)
	}
	return nil
}

func SignHostRevocation(root ed25519.PrivateKey, networkID, hostPublicKey, at string) HostRevocation {
	r := HostRevocation{NetworkID: networkID, HostPublicKey: hostPublicKey, RevokedAt: at}
	r.Signature = sign(root, r.Message())
	return r
}
func SignInviteRevocation(root ed25519.PrivateKey, networkID, invitePublicKey, at string) InviteRevocation {
	r := InviteRevocation{NetworkID: networkID, InvitePublicKey: invitePublicKey, RevokedAt: at}
	r.Signature = sign(root, r.Message())
	return r
}
func SignLeave(host ed25519.PrivateKey, networkID, at string) Leave {
	l := Leave{NetworkID: networkID, HostPublicKey: PublicKey(host), LeftAt: at}
	l.Signature = sign(host, l.Message())
	return l
}
func SignRotation(previous ed25519.PrivateKey, networkID string, epoch int64, next ed25519.PublicKey, at string) Rotation {
	r := Rotation{NetworkID: networkID, Epoch: epoch, PreviousRootPublicKey: PublicKey(previous), RootPublicKey: EncodeKey(next), RotatedAt: at}
	r.Signature = sign(previous, r.Message())
	return r
}
func SignAttestation(root ed25519.PrivateKey, networkID string, epoch int64, hostPublicKey, member, at string) Attestation {
	a := Attestation{NetworkID: networkID, Epoch: epoch, HostPublicKey: hostPublicKey, Member: member, AttestedAt: at}
	a.Signature = sign(root, a.Message())
	return a
}

// Chain is a network's verified root chain: the genesis root, which derives
// the network ID, followed by rotations in epoch order.
type Chain struct {
	NetworkID string
	Roots     []ed25519.PublicKey
	Rotations []Rotation
	// Admins are the administrator keys whose signatures are accepted on the
	// statements an administrator may sign (see AdminState.Signers).
	Admins map[string]bool
	// Kept limits administrators removed without revoke_admitted to the
	// digests their removal lists.
	Kept map[string]map[string]bool
}

// VerifyChain checks that each rotation is signed by the previous root,
// names it, and increments the epoch by exactly one.
func VerifyChain(genesis ed25519.PublicKey, rotations []Rotation) (Chain, error) {
	c := Chain{NetworkID: NetworkID(genesis), Roots: []ed25519.PublicKey{genesis}}
	for i, r := range rotations {
		previous := c.Roots[len(c.Roots)-1]
		if r.NetworkID != c.NetworkID || r.Epoch != int64(i+1) || r.PreviousRootPublicKey != EncodeKey(previous) {
			return c, fmt.Errorf("%w: rotation %d does not extend the root chain", ErrInvalid, i+1)
		}
		next, err := DecodeKey(r.RootPublicKey)
		if err != nil {
			return c, err
		}
		if err = validTime(r.RotatedAt); err != nil {
			return c, err
		}
		if err = verifyRoot(previous, r.Message(), r.Signature); err != nil {
			return c, err
		}
		c.Roots = append(c.Roots, next)
		c.Rotations = append(c.Rotations, r)
	}
	return c, nil
}

func (c Chain) Epoch() int64               { return int64(len(c.Roots) - 1) }
func (c Chain) Current() ed25519.PublicKey { return c.Roots[len(c.Roots)-1] }
func (c Chain) CurrentPublicKey() string   { return EncodeKey(c.Current()) }
func sameRotation(a, b Rotation) bool      { return a == b }
func rootIndex(c Chain, key string) int {
	for i, root := range c.Roots {
		if EncodeKey(root) == key {
			return i
		}
	}
	return -1
}

// Extends reports whether next extends or equals the persisted chain c. A
// different rotation at a persisted epoch is a fork; a shorter chain is stale.
func (c Chain) Extends(next Chain) error {
	if next.NetworkID != c.NetworkID {
		return fmt.Errorf("%w: different network", ErrInvalid)
	}
	for i, r := range c.Rotations {
		if i >= len(next.Rotations) {
			return fmt.Errorf("%w (epoch %d < %d)", ErrBehind, next.Epoch(), c.Epoch())
		}
		if !sameRotation(r, next.Rotations[i]) {
			return fmt.Errorf("%w: different rotation at epoch %d", ErrFork, r.Epoch)
		}
	}
	return nil
}

// VerifyAttestation checks an attestation for the chain's current epoch.
func (c Chain) VerifyAttestation(a Attestation) error {
	if a.NetworkID != c.NetworkID || a.Epoch != c.Epoch() || !ValidLabel(a.Member) {
		return fmt.Errorf("%w: attestation is not for this network's current epoch", ErrInvalid)
	}
	if _, err := DecodeKey(a.HostPublicKey); err != nil {
		return err
	}
	if err := validTime(a.AttestedAt); err != nil {
		return err
	}
	return verifyRoot(c.Current(), a.Message(), a.Signature)
}

// VerifyRevocation checks a map revocation entry and returns its kind and
// subject key. Host and invite revocations verify under any root in the
// chain; a leave verifies under the departing host's own key.
func (c Chain) VerifyRevocation(entry Revocation) (string, string, error) {
	switch entry.Kind {
	case KindHost:
		var r HostRevocation
		if err := json.Unmarshal(entry.Statement, &r); err != nil {
			return "", "", err
		}
		return KindHost, r.HostPublicKey, c.verifyByAnyRoot(r.NetworkID, r.HostPublicKey, r.RevokedAt, r.Message(), r.Signature)
	case KindInvite:
		var r InviteRevocation
		if err := json.Unmarshal(entry.Statement, &r); err != nil {
			return "", "", err
		}
		return KindInvite, r.InvitePublicKey, c.verifyByAnyRoot(r.NetworkID, r.InvitePublicKey, r.RevokedAt, r.Message(), r.Signature)
	case KindLeave:
		var l Leave
		if err := json.Unmarshal(entry.Statement, &l); err != nil {
			return "", "", err
		}
		if l.NetworkID != c.NetworkID {
			return "", "", fmt.Errorf("%w: leave is for a different network", ErrInvalid)
		}
		host, err := DecodeKey(l.HostPublicKey)
		if err != nil {
			return "", "", err
		}
		if err = validTime(l.LeftAt); err != nil {
			return "", "", err
		}
		return KindLeave, l.HostPublicKey, verify(host, l.Message(), l.Signature)
	case KindPerson:
		var r PersonRemoval
		if err := json.Unmarshal(entry.Statement, &r); err != nil {
			return "", "", err
		}
		return KindPerson, r.PersonPublicKey, c.verifyPersonRemoval(r)
	case KindUnbind:
		var u HostUnbinding
		if err := json.Unmarshal(entry.Statement, &u); err != nil {
			return "", "", err
		}
		return KindUnbind, UnbindSubject(u.PersonPublicKey, u.HostPublicKey), VerifyHostUnbinding(c.NetworkID, u)
	case KindAdmin:
		var r AdminRemoval
		if err := json.Unmarshal(entry.Statement, &r); err != nil {
			return "", "", err
		}
		return KindAdmin, r.PersonPublicKey, c.VerifyAdminRemoval(r)
	}
	return "", "", fmt.Errorf("%w: unknown revocation kind", ErrInvalid)
}

func (c Chain) verifyByAnyRoot(network, subject, at string, message []byte, signature string) error {
	if network != c.NetworkID {
		return fmt.Errorf("%w: revocation is for a different network", ErrInvalid)
	}
	if _, err := DecodeKey(subject); err != nil {
		return err
	}
	if err := validTime(at); err != nil {
		return err
	}
	// Any root in the chain, or an acceptable administrator.
	if _, _, err := c.signerKey(message, signature, false); err != nil {
		return fmt.Errorf("%w: revocation is not signed by a root or administrator of this network", ErrInvalid)
	}
	return nil
}

// Revoked is the set of revoked host keys, revoked invite keys, departed
// host keys, removed person keys, and unbound person-host pairs for one
// network.
type Revoked struct {
	Hosts, Invites, Left, Persons, Unbound, Admins map[string]bool
}

func NewRevoked() Revoked {
	return Revoked{Hosts: map[string]bool{}, Invites: map[string]bool{}, Left: map[string]bool{}, Persons: map[string]bool{}, Unbound: map[string]bool{}, Admins: map[string]bool{}}
}

func (r Revoked) Add(kind, subject string) {
	switch kind {
	case KindHost:
		r.Hosts[subject] = true
	case KindInvite:
		r.Invites[subject] = true
	case KindLeave:
		r.Left[subject] = true
	case KindPerson:
		r.Persons[subject] = true
	case KindUnbind:
		r.Unbound[subject] = true
	case KindAdmin:
		r.Admins[subject] = true
	}
}

// ExcludesHost reports whether a host key, joined through inviteKey ("" for a
// host admitted by public key), is revoked or departed.
func (r Revoked) ExcludesHost(hostKey, inviteKey string) bool {
	return r.Hosts[hostKey] || r.Left[hostKey] || (inviteKey != "" && r.Invites[inviteKey])
}

// Bound reports whether a binding of host by person is still in effect.
func (r Revoked) Bound(personKey, hostKey string) bool {
	return !r.Persons[personKey] && !r.Unbound[UnbindSubject(personKey, hostKey)]
}

// Excludes reports whether a membership is revoked, departed, or joined
// through a revoked invite.
func (r Revoked) Excludes(m Membership) bool {
	return r.Hosts[m.HostPublicKey] || r.Left[m.HostPublicKey] || r.Invites[m.InvitePublicKey]
}

// ValidMember returns the host ID of a membership that is valid under the
// chain: at epoch 0 by its invite chain under the genesis root, and later by
// an invite chain under the current root or an attestation of its host key by
// the current root. attestations maps host public keys to verified
// current-epoch attestations.
func (c Chain) ValidMember(m Membership, attestations map[string]Attestation) (string, error) {
	if c.Epoch() == 0 {
		return c.VerifyMembership(m)
	}
	if id, err := c.VerifyMembership(m); err == nil {
		return id, nil
	}
	a, ok := attestations[m.HostPublicKey]
	if !ok || a.Member != m.Member {
		return "", fmt.Errorf("%w: membership is not signed or attested by the current root", ErrInvalid)
	}
	// The membership must still be internally consistent: its host signature
	// binds the host key to the invite it names.
	host, err := DecodeKey(m.HostPublicKey)
	if err != nil {
		return "", err
	}
	if m.NetworkID != c.NetworkID {
		return "", fmt.Errorf("%w: membership is for a different network", ErrInvalid)
	}
	return HostID(host), nil
}

// RootIndex returns the epoch of a root key in the chain, or -1.
func (c Chain) RootIndex(key string) int { return rootIndex(c, key) }

// EqualRaw compares two JSON statements for equality after compaction.
func EqualRaw(a, b json.RawMessage) bool {
	var x, y bytes.Buffer
	return json.Compact(&x, a) == nil && json.Compact(&y, b) == nil && bytes.Equal(x.Bytes(), y.Bytes())
}
