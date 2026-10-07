package membership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Administrators and groups (milestone 2b, slice 2). The root delegates
// administrator rights to person keys; an administrator signs, in SSHSIG
// format, the statements a root may sign except delegation, administrator
// removal, rotation, and attestation. A root signature is raw Ed25519 or an
// SSHSIG blob whose key is the root, so the root can be an SSH key.

const (
	KindAdmin = "admin" // an administrator removal in a map's revocations

	GroupTokenMax = 64
)

// StatementSigner signs statement bytes and returns the encoded signature.
type StatementSigner interface {
	PublicKey() ed25519.PublicKey
	SignStatement(message []byte) (string, error)
}

// RawSigner signs with raw Ed25519, as a root seed held by a host does.
type RawSigner struct{ Key ed25519.PrivateKey }

func (r RawSigner) PublicKey() ed25519.PublicKey { return r.Key.Public().(ed25519.PublicKey) }
func (r RawSigner) SignStatement(message []byte) (string, error) {
	return sign(r.Key, message), nil
}

// SSHSigner signs in SSHSIG format with a person or SSH root key.
type SSHSigner struct{ PersonSigner }

func (s SSHSigner) SignStatement(message []byte) (string, error) {
	return SignSSHSIG(s.PersonSigner, message)
}

// SSHSIGKey returns the public key embedded in an SSHSIG signature.
func SSHSIGKey(signature string) (ed25519.PublicKey, bool) {
	blob, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || !bytes.HasPrefix(blob, []byte(sshsigMagic)) || len(blob) < len(sshsigMagic)+4 {
		return nil, false
	}
	r := &sshReader{b: blob[len(sshsigMagic)+4:]}
	if binary.BigEndian.Uint32(blob[len(sshsigMagic):]) != 1 {
		return nil, false
	}
	public, ok := r.string()
	if !ok {
		return nil, false
	}
	inner := &sshReader{b: public}
	kind, ok1 := inner.string()
	key, ok2 := inner.string()
	if !ok1 || !ok2 || len(inner.b) != 0 || string(kind) != sshEd25519 || len(key) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(key), true
}

// isSSHSIG reports whether a signature is an SSHSIG blob rather than raw.
func isSSHSIG(signature string) bool {
	_, ok := SSHSIGKey(signature)
	return ok
}

// verifyRoot accepts a raw Ed25519 signature or an SSHSIG signature by root.
func verifyRoot(root ed25519.PublicKey, message []byte, signature string) error {
	if isSSHSIG(signature) {
		return VerifySSHSIG(root, message, signature)
	}
	return verify(root, message, signature)
}

// signerKey returns the key that signed a statement under the chain: a root
// key (raw or SSHSIG) or an acceptable administrator (SSHSIG). currentOnly
// limits roots to the current root.
func (c Chain) signerKey(message []byte, signature string, currentOnly bool) (string, bool, error) {
	roots := c.Roots
	if currentOnly {
		roots = []ed25519.PublicKey{c.Current()}
	}
	for _, root := range roots {
		if verifyRoot(root, message, signature) == nil {
			return EncodeKey(root), true, nil
		}
	}
	if key, ok := SSHSIGKey(signature); ok && c.Admins[EncodeKey(key)] {
		if err := VerifySSHSIG(key, message, signature); err != nil {
			return "", false, err
		}
		if kept, removed := c.Kept[EncodeKey(key)]; removed && !kept[StatementDigest(message)] {
			return "", false, fmt.Errorf("%w: not among the statements kept when this administrator was removed", ErrInvalid)
		}
		return EncodeKey(key), false, nil
	}
	return "", false, fmt.Errorf("%w: not signed by this network's root or an administrator", ErrInvalid)
}

// RootSigned reports whether a signature verifies under some root of the
// chain (raw or SSHSIG); statements signed by administrators are not.
func (c Chain) RootSigned(message []byte, signature string) bool {
	for _, root := range c.Roots {
		if verifyRoot(root, message, signature) == nil {
			return true
		}
	}
	return false
}

// SignerOf returns the signing key of a statement signature, without
// verifying it: the embedded SSHSIG key, or "" for a raw (root) signature.
func SignerOf(signature string) string {
	if key, ok := SSHSIGKey(signature); ok {
		return EncodeKey(key)
	}
	return ""
}

type AdminDelegation struct {
	NetworkID       string `json:"network_id"`
	Epoch           int64  `json:"epoch"`
	PersonPublicKey string `json:"person_public_key"`
	DelegatedAt     string `json:"delegated_at"`
	Signature       string `json:"signature"`
}

type AdminRemoval struct {
	NetworkID       string `json:"network_id"`
	PersonPublicKey string `json:"person_public_key"`
	RevokeAdmitted  bool   `json:"revoke_admitted"`
	RemovedAt       string `json:"removed_at"`
	// Kept lists, without revoke_admitted, the digests of the statements the
	// administrator signed that stay valid, in ascending order. It is empty
	// with revoke_admitted.
	Kept      []string `json:"kept"`
	Signature string   `json:"signature"`
}

type GroupDefinition struct {
	NetworkID string   `json:"network_id"`
	Name      string   `json:"name"`
	Version   int64    `json:"version"`
	DefinedAt string   `json:"defined_at"`
	Members   []string `json:"members"`
	Signature string   `json:"signature"`
}

func (d AdminDelegation) Message() []byte {
	return statement("capsule-admin-delegate-v1", d.NetworkID, strconv.FormatInt(d.Epoch, 10), d.PersonPublicKey, d.DelegatedAt)
}
func (r AdminRemoval) Message() []byte {
	return statement(append([]string{"capsule-admin-remove-v1", r.NetworkID, r.PersonPublicKey, strconv.FormatBool(r.RevokeAdmitted), r.RemovedAt}, r.Kept...)...)
}

// StatementDigest is the lowercase hex SHA-256 of a statement's signed lines.
func StatementDigest(message []byte) string {
	sum := sha256.Sum256(message)
	return hex.EncodeToString(sum[:])
}

// validKept checks a kept list: ascending, distinct digests, and none with
// revoke_admitted.
func validKept(r AdminRemoval) bool {
	if r.RevokeAdmitted && len(r.Kept) != 0 {
		return false
	}
	for i, d := range r.Kept {
		if len(d) != 64 || strings.ToLower(d) != d {
			return false
		}
		if _, err := hex.DecodeString(d); err != nil || (i > 0 && r.Kept[i-1] >= d) {
			return false
		}
	}
	return true
}
func (g GroupDefinition) Message() []byte {
	return statement(append([]string{"capsule-group-v1", g.NetworkID, g.Name, strconv.FormatInt(g.Version, 10), g.DefinedAt}, g.Members...)...)
}

func (d *AdminDelegation) UnmarshalJSON(data []byte) error {
	type plain AdminDelegation
	return Strict(data, (*plain)(d), "network_id", "epoch", "person_public_key", "delegated_at", "signature")
}
func (r *AdminRemoval) UnmarshalJSON(data []byte) error {
	type plain AdminRemoval
	return Strict(data, (*plain)(r), "network_id", "person_public_key", "revoke_admitted", "removed_at", "kept", "signature")
}
func (g *GroupDefinition) UnmarshalJSON(data []byte) error {
	type plain GroupDefinition
	return Strict(data, (*plain)(g), "network_id", "name", "version", "defined_at", "members", "signature")
}

var (
	groupName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	personIDs = regexp.MustCompile(`^person_[0-9a-f]{64}$`)
)

// ValidGroupName reports whether name is 1–64 bytes of lowercase ASCII
// letters, digits, ".", "_", and "-", starting with a letter or digit.
func ValidGroupName(name string) bool { return groupName.MatchString(name) }

// ValidPersonID reports whether id is person_ followed by 64 lowercase hex.
func ValidPersonID(id string) bool { return personIDs.MatchString(id) }

// SortedMembers returns person IDs in ascending byte order without
// duplicates, or an error for an invalid ID.
func SortedMembers(ids []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		if !ValidPersonID(id) {
			return nil, fmt.Errorf("%w: invalid person ID %q", ErrInvalid, id)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

func SignAdminDelegation(root StatementSigner, network string, e int64, personPublicKey, at string) (AdminDelegation, error) {
	d := AdminDelegation{NetworkID: network, Epoch: e, PersonPublicKey: personPublicKey, DelegatedAt: at}
	var err error
	d.Signature, err = root.SignStatement(d.Message())
	return d, err
}

// SignAdminRemoval signs a removal; kept are the digests of the statements
// that stay valid without revoke_admitted, sorted here.
func SignAdminRemoval(root StatementSigner, network, personPublicKey string, revokeAdmitted bool, kept []string, at string) (AdminRemoval, error) {
	r := AdminRemoval{NetworkID: network, PersonPublicKey: personPublicKey, RevokeAdmitted: revokeAdmitted, RemovedAt: at, Kept: []string{}}
	if !revokeAdmitted {
		seen := map[string]bool{}
		for _, d := range kept {
			if !seen[d] {
				seen[d] = true
				r.Kept = append(r.Kept, d)
			}
		}
		sort.Strings(r.Kept)
	}
	if !validKept(r) {
		return r, fmt.Errorf("%w: kept digests must be lowercase hex SHA-256", ErrInvalid)
	}
	var err error
	r.Signature, err = root.SignStatement(r.Message())
	return r, err
}
func SignGroup(signer StatementSigner, network, name string, version int64, members []string, at string) (GroupDefinition, error) {
	sorted, err := SortedMembers(members)
	if err != nil {
		return GroupDefinition{}, err
	}
	if !ValidGroupName(name) || version < 1 {
		return GroupDefinition{}, fmt.Errorf("%w: invalid group name or version", ErrInvalid)
	}
	g := GroupDefinition{NetworkID: network, Name: name, Version: version, DefinedAt: at, Members: sorted}
	g.Signature, err = signer.SignStatement(g.Message())
	return g, err
}

// Signed variants of the root statements an administrator may also sign.

func SignHostAdmissionWith(s StatementSigner, network string, e int64, hostPublicKey, member, at string) (HostAdmission, error) {
	a := HostAdmission{NetworkID: network, Epoch: e, HostPublicKey: hostPublicKey, Member: member, AdmittedAt: at}
	var err error
	a.Signature, err = s.SignStatement(a.Message())
	return a, err
}
func SignPersonAdmissionWith(s StatementSigner, network string, e int64, personPublicKey, member, at string) (PersonAdmission, error) {
	a := PersonAdmission{NetworkID: network, Epoch: e, PersonPublicKey: personPublicKey, Member: member, AdmittedAt: at}
	var err error
	a.Signature, err = s.SignStatement(a.Message())
	return a, err
}
func SignHostRevocationWith(s StatementSigner, network, hostPublicKey, at string) (HostRevocation, error) {
	r := HostRevocation{NetworkID: network, HostPublicKey: hostPublicKey, RevokedAt: at}
	var err error
	r.Signature, err = s.SignStatement(r.Message())
	return r, err
}
func SignInviteRevocationWith(s StatementSigner, network, invitePublicKey, at string) (InviteRevocation, error) {
	r := InviteRevocation{NetworkID: network, InvitePublicKey: invitePublicKey, RevokedAt: at}
	var err error
	r.Signature, err = s.SignStatement(r.Message())
	return r, err
}
func SignPersonRemovalWith(s StatementSigner, network, personPublicKey, at string) (PersonRemoval, error) {
	r := PersonRemoval{NetworkID: network, PersonPublicKey: personPublicKey, RemovedAt: at}
	var err error
	r.Signature, err = s.SignStatement(r.Message())
	return r, err
}
func SignRotationWith(previous StatementSigner, network string, e int64, next ed25519.PublicKey, at string) (Rotation, error) {
	r := Rotation{NetworkID: network, Epoch: e, PreviousRootPublicKey: EncodeKey(previous.PublicKey()), RootPublicKey: EncodeKey(next), RotatedAt: at}
	var err error
	r.Signature, err = previous.SignStatement(r.Message())
	return r, err
}
func SignAttestationWith(root StatementSigner, network string, e int64, hostPublicKey, member, at string) (Attestation, error) {
	a := Attestation{NetworkID: network, Epoch: e, HostPublicKey: hostPublicKey, Member: member, AttestedAt: at}
	var err error
	a.Signature, err = root.SignStatement(a.Message())
	return a, err
}

// InviteWith creates a host invite whose invite signature is made by signer
// (a root or an administrator); RootPublicKey names the signer.
func InviteWith(network string, signer StatementSigner, member, expiresAt string) (Token, error) {
	t, err := newInviteToken(network, member, expiresAt)
	if err != nil {
		return t, err
	}
	t.RootPublicKey = EncodeKey(signer.PublicKey())
	t.InviteSignature, err = signer.SignStatement(InviteStatement(network, t.InvitePublicKey, member, expiresAt))
	return t, err
}

// PersonInviteWith creates a person invite signed by signer at epoch e.
func PersonInviteWith(network string, signer StatementSigner, e int64, member, expiresAt string) (PersonToken, error) {
	t, err := newInviteToken(network, member, expiresAt)
	if err != nil {
		return PersonToken{}, err
	}
	t.RootPublicKey = EncodeKey(signer.PublicKey())
	p := PersonToken{Token: t, InviteEpoch: e}
	p.InviteSignature, err = signer.SignStatement(PersonInviteStatement(network, e, t.InvitePublicKey, member, expiresAt))
	return p, err
}

// MemberInviteWith signs one invite key twice with signer.
func MemberInviteWith(network string, signer StatementSigner, e int64, member, expiresAt string) (MemberToken, error) {
	host, err := InviteWith(network, signer, member, expiresAt)
	if err != nil {
		return MemberToken{}, err
	}
	t := MemberToken{Token: host, InviteEpoch: e}
	t.PersonInviteSignature, err = signer.SignStatement(PersonInviteStatement(network, e, t.InvitePublicKey, member, expiresAt))
	return t, err
}

// VerifyDelegation checks a delegation signed by the root of its epoch and
// returns the delegated person key.
func (c Chain) VerifyDelegation(d AdminDelegation) (string, error) {
	if d.NetworkID != c.NetworkID || d.Epoch < 0 || d.Epoch > c.Epoch() {
		return "", fmt.Errorf("%w: delegation is not for this network's root chain", ErrInvalid)
	}
	if err := checkKeyTime(d.PersonPublicKey, d.DelegatedAt); err != nil {
		return "", err
	}
	if err := verifyRoot(c.Roots[d.Epoch], d.Message(), d.Signature); err != nil {
		return "", err
	}
	return d.PersonPublicKey, nil
}

// VerifyAdminRemoval checks an administrator removal under any root.
func (c Chain) VerifyAdminRemoval(r AdminRemoval) error {
	if r.NetworkID != c.NetworkID {
		return fmt.Errorf("%w: removal is for a different network", ErrInvalid)
	}
	if err := checkKeyTime(r.PersonPublicKey, r.RemovedAt); err != nil {
		return err
	}
	if r.Kept == nil || !validKept(r) {
		return fmt.Errorf("%w: invalid kept digests", ErrInvalid)
	}
	for _, root := range c.Roots {
		if verifyRoot(root, r.Message(), r.Signature) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: administrator removal is not signed by a root of this network", ErrInvalid)
}

// VerifyGroup checks a group definition signed by the current root or an
// acceptable administrator, and returns the signer key.
func (c Chain) VerifyGroup(g GroupDefinition) (string, error) {
	if g.NetworkID != c.NetworkID || !ValidGroupName(g.Name) || g.Version < 1 {
		return "", fmt.Errorf("%w: invalid group definition", ErrInvalid)
	}
	if err := validTime(g.DefinedAt); err != nil {
		return "", err
	}
	sorted, err := SortedMembers(g.Members)
	if err != nil || len(sorted) != len(g.Members) {
		return "", fmt.Errorf("%w: group members must be distinct person IDs in ascending order", ErrInvalid)
	}
	for i := range sorted {
		if sorted[i] != g.Members[i] {
			return "", fmt.Errorf("%w: group members must be in ascending order", ErrInvalid)
		}
	}
	key, _, err := c.signerKey(g.Message(), g.Signature, true)
	return key, err
}

// AdminState is a network's administrators under a chain.
type AdminState struct {
	// Signers are keys whose administrator signatures are accepted: every key
	// with a verified delegation, except those removed with revoke_admitted.
	Signers map[string]bool
	// Current are administrators now: delegated at the current epoch and not
	// removed. The caller also requires them to be valid, unremoved persons.
	Current map[string]bool
	// Delegations holds the latest verified delegation per key.
	Delegations map[string]AdminDelegation
	// Removals holds verified removals by key (revoke_admitted if any says so).
	Removals map[string]AdminRemoval
	// Kept maps each administrator removed without revoke_admitted to the
	// digests of its statements that stay valid, from its one removal.
	Kept map[string]map[string]bool
}

// Administrators computes the administrator state from delegations and
// removals; invalid statements are ignored.
func (c Chain) Administrators(delegations []AdminDelegation, removals []AdminRemoval) AdminState {
	s := AdminState{Signers: map[string]bool{}, Current: map[string]bool{}, Delegations: map[string]AdminDelegation{}, Removals: map[string]AdminRemoval{}, Kept: map[string]map[string]bool{}}
	for _, r := range removals {
		if c.VerifyAdminRemoval(r) != nil {
			continue
		}
		previous, ok := s.Removals[r.PersonPublicKey]
		if !ok || (r.RevokeAdmitted && !previous.RevokeAdmitted) {
			s.Removals[r.PersonPublicKey] = r
		}
	}
	for _, d := range delegations {
		key, err := c.VerifyDelegation(d)
		if err != nil {
			continue
		}
		if previous, ok := s.Delegations[key]; !ok || d.Epoch > previous.Epoch {
			s.Delegations[key] = d
		}
	}
	// One removal per key: the first given wins, unless a later one
	// escalates to revoke_admitted. Kept lists are never merged.
	for key, removal := range s.Removals {
		if !removal.RevokeAdmitted {
			s.Kept[key] = map[string]bool{}
			for _, d := range removal.Kept {
				s.Kept[key][d] = true
			}
		}
	}
	for key, d := range s.Delegations {
		removal, removed := s.Removals[key]
		if !removed || !removal.RevokeAdmitted {
			s.Signers[key] = true
		}
		if !removed && d.Epoch == c.Epoch() {
			s.Current[key] = true
		}
	}
	return s
}

// WithAdmins returns the chain accepting signatures by signers.
func (c Chain) WithAdmins(signers map[string]bool) Chain {
	c.Admins = signers
	return c
}

// WithAdminState returns the chain accepting the state's signers; a removed
// administrator's statements verify only if their digest was kept.
func (c Chain) WithAdminState(s AdminState) Chain {
	c.Admins, c.Kept = s.Signers, s.Kept
	return c
}

// NewestGroups keeps, per name, the valid definition with the highest
// version.
func (c Chain) NewestGroups(groups []GroupDefinition) map[string]GroupDefinition {
	out := map[string]GroupDefinition{}
	for _, g := range groups {
		if _, err := c.VerifyGroup(g); err != nil {
			continue
		}
		if previous, ok := out[g.Name]; !ok || g.Version > previous.Version {
			out[g.Name] = g
		}
	}
	return out
}

// DecodeRaw parses statements, skipping malformed entries.
func DecodeRaw[T any](raw []json.RawMessage) []T {
	out := make([]T, 0, len(raw))
	for _, data := range raw {
		var v T
		if json.Unmarshal(data, &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// AdminSigned reports whether a signature is an administrator's SSHSIG rather
// than a root's.
func (c Chain) AdminSigned(signature string) bool {
	signer := SignerOf(signature)
	return signer != "" && c.RootIndex(signer) < 0
}

// SignerValid reports whether a stored statement's signer is still accepted:
// a root, or an administrator not removed with revoke_admitted whose removal,
// if any, kept this statement. It does not verify the signature.
func (c Chain) SignerValid(message []byte, signature string) bool {
	if !c.AdminSigned(signature) {
		return true
	}
	signer := SignerOf(signature)
	if kept, removed := c.Kept[signer]; removed && !kept[StatementDigest(message)] {
		return false
	}
	return c.Admins[signer]
}

// InviteMessage is the host invite statement a membership's invite signs.
func (m Membership) InviteMessage() []byte {
	return InviteStatement(m.NetworkID, m.InvitePublicKey, m.Member, m.InviteExpiresAt)
}

// VerifySigned verifies a signature by the current root or an acceptable
// administrator and returns the signing key.
func (c Chain) VerifySigned(message []byte, signature string) (string, error) {
	key, _, err := c.signerKey(message, signature, true)
	return key, err
}
