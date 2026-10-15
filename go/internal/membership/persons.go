package membership

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Persons and host binding (milestone 2b, slice 1). Administrators admit
// hosts as before and may also admit persons; a person binds hosts that are
// already admitted. Root statements are raw Ed25519; person statements are
// SSHSIG.

const (
	KindPerson = "person" // a person removal in a map's revocations
	KindUnbind = "unbind" // a host unbinding in a map's revocations

	PersonTokenPrefix = "peerspan-person-invite-v1."
	DescriptorPrefix  = "peerspan-network-v1."
)

func PersonID(key ed25519.PublicKey) string { return digestID("person_", key) }

// UnbindSubject keys a host unbinding by person and host.
func UnbindSubject(personKey, hostKey string) string { return personKey + " " + hostKey }

type PersonAdmission struct {
	NetworkID       string `json:"network_id"`
	Epoch           int64  `json:"epoch"`
	PersonPublicKey string `json:"person_public_key"`
	Member          string `json:"member"`
	AdmittedAt      string `json:"admitted_at"`
	Signature       string `json:"signature"`
}

// PersonMembership is a person admitted through a one-time person invite.
type PersonMembership struct {
	NetworkID       string `json:"network_id"`
	Member          string `json:"member"`
	InvitePublicKey string `json:"invite_public_key"`
	InviteExpiresAt string `json:"invite_expires_at"`
	InviteEpoch     int64  `json:"invite_epoch"`
	InviteSignature string `json:"invite_signature"`
	PersonPublicKey string `json:"person_public_key"`
	JoinedAt        string `json:"joined_at"`
	PersonSignature string `json:"person_signature"`
}

type PersonRemoval struct {
	NetworkID       string `json:"network_id"`
	PersonPublicKey string `json:"person_public_key"`
	RemovedAt       string `json:"removed_at"`
	Signature       string `json:"signature"`
}

type HostAdmission struct {
	NetworkID     string `json:"network_id"`
	Epoch         int64  `json:"epoch"`
	HostPublicKey string `json:"host_public_key"`
	Member        string `json:"member"`
	AdmittedAt    string `json:"admitted_at"`
	Signature     string `json:"signature"`
}

// HostBinding is signed by the person (SSHSIG, Signature) and by the bound
// host's own key (raw Ed25519, HostSignature) over the same statement, so a
// coordinator cannot bind a host without that host's consent.
type HostBinding struct {
	NetworkID       string `json:"network_id"`
	PersonPublicKey string `json:"person_public_key"`
	HostPublicKey   string `json:"host_public_key"`
	BoundAt         string `json:"bound_at"`
	Signature       string `json:"signature"`
	HostSignature   string `json:"host_signature"`
}

type HostUnbinding struct {
	NetworkID       string `json:"network_id"`
	PersonPublicKey string `json:"person_public_key"`
	HostPublicKey   string `json:"host_public_key"`
	UnboundAt       string `json:"unbound_at"`
	Signature       string `json:"signature"`
}

func epoch(e int64) string { return strconv.FormatInt(e, 10) }

func (a PersonAdmission) Message() []byte {
	return statement("peerspan-person-admit-v1", a.NetworkID, epoch(a.Epoch), a.PersonPublicKey, a.Member, a.AdmittedAt)
}
func PersonInviteStatement(network string, inviteEpoch int64, invitePublicKey, member, expiresAt string) []byte {
	return statement("peerspan-person-invite-v1", network, epoch(inviteEpoch), invitePublicKey, member, expiresAt)
}
func PersonMemberStatement(network, invitePublicKey, personPublicKey, joinedAt string) []byte {
	return statement("peerspan-person-member-v1", network, invitePublicKey, personPublicKey, joinedAt)
}
func (r PersonRemoval) Message() []byte {
	return statement("peerspan-person-remove-v1", r.NetworkID, r.PersonPublicKey, r.RemovedAt)
}
func (a HostAdmission) Message() []byte {
	return statement("peerspan-host-admit-v1", a.NetworkID, epoch(a.Epoch), a.HostPublicKey, a.Member, a.AdmittedAt)
}
func (b HostBinding) Message() []byte {
	return statement("peerspan-host-bind-v1", b.NetworkID, b.PersonPublicKey, b.HostPublicKey, b.BoundAt)
}
func (u HostUnbinding) Message() []byte {
	return statement("peerspan-host-unbind-v1", u.NetworkID, u.PersonPublicKey, u.HostPublicKey, u.UnboundAt)
}

func (a *PersonAdmission) UnmarshalJSON(data []byte) error {
	type plain PersonAdmission
	return Strict(data, (*plain)(a), "network_id", "epoch", "person_public_key", "member", "admitted_at", "signature")
}
func (m *PersonMembership) UnmarshalJSON(data []byte) error {
	type plain PersonMembership
	return Strict(data, (*plain)(m), "network_id", "member", "invite_public_key", "invite_expires_at", "invite_epoch", "invite_signature", "person_public_key", "joined_at", "person_signature")
}
func (r *PersonRemoval) UnmarshalJSON(data []byte) error {
	type plain PersonRemoval
	return Strict(data, (*plain)(r), "network_id", "person_public_key", "removed_at", "signature")
}
func (a *HostAdmission) UnmarshalJSON(data []byte) error {
	type plain HostAdmission
	return Strict(data, (*plain)(a), "network_id", "epoch", "host_public_key", "member", "admitted_at", "signature")
}
func (b *HostBinding) UnmarshalJSON(data []byte) error {
	type plain HostBinding
	return Strict(data, (*plain)(b), "network_id", "person_public_key", "host_public_key", "bound_at", "signature", "host_signature")
}

// DecodePersonBinding reads a binding the person has signed but the host has
// not yet, as the CLI hands it to its daemon: host_signature may be absent.
func DecodePersonBinding(data []byte) (HostBinding, error) {
	var b HostBinding
	if err := json.Unmarshal(data, &b); err == nil {
		return b, nil
	}
	type plain HostBinding
	err := Strict(data, (*plain)(&b), "network_id", "person_public_key", "host_public_key", "bound_at", "signature")
	return b, err
}

// SignHost adds the bound host's own signature; host must be the bound key.
func (b *HostBinding) SignHost(host ed25519.PrivateKey) error {
	if PublicKey(host) != b.HostPublicKey {
		return fmt.Errorf("%w: a host signs only bindings of its own key", ErrInvalid)
	}
	b.HostSignature = sign(host, b.Message())
	return nil
}
func (u *HostUnbinding) UnmarshalJSON(data []byte) error {
	type plain HostUnbinding
	return Strict(data, (*plain)(u), "network_id", "person_public_key", "host_public_key", "unbound_at", "signature")
}

func SignPersonAdmission(root ed25519.PrivateKey, network string, e int64, personPublicKey, member, at string) PersonAdmission {
	a := PersonAdmission{NetworkID: network, Epoch: e, PersonPublicKey: personPublicKey, Member: member, AdmittedAt: at}
	a.Signature = sign(root, a.Message())
	return a
}
func SignPersonRemoval(root ed25519.PrivateKey, network, personPublicKey, at string) PersonRemoval {
	r := PersonRemoval{NetworkID: network, PersonPublicKey: personPublicKey, RemovedAt: at}
	r.Signature = sign(root, r.Message())
	return r
}
func SignHostAdmission(root ed25519.PrivateKey, network string, e int64, hostPublicKey, member, at string) HostAdmission {
	a := HostAdmission{NetworkID: network, Epoch: e, HostPublicKey: hostPublicKey, Member: member, AdmittedAt: at}
	a.Signature = sign(root, a.Message())
	return a
}
func SignHostBinding(person PersonSigner, network, hostPublicKey, at string) (HostBinding, error) {
	b := HostBinding{NetworkID: network, PersonPublicKey: EncodeKey(person.PublicKey()), HostPublicKey: hostPublicKey, BoundAt: at}
	var err error
	b.Signature, err = SignSSHSIG(person, b.Message())
	return b, err
}
func SignHostUnbinding(person PersonSigner, network, hostPublicKey, at string) (HostUnbinding, error) {
	u := HostUnbinding{NetworkID: network, PersonPublicKey: EncodeKey(person.PublicKey()), HostPublicKey: hostPublicKey, UnboundAt: at}
	var err error
	u.Signature, err = SignSSHSIG(person, u.Message())
	return u, err
}

func checkKeyTime(key, at string) error {
	if _, err := DecodeKey(key); err != nil {
		return err
	}
	return validTime(at)
}

// VerifyPersonBinding checks a binding's fields and person signature only.
func VerifyPersonBinding(network string, b HostBinding) error {
	if b.NetworkID != network {
		return fmt.Errorf("%w: binding is for a different network", ErrInvalid)
	}
	if err := checkKeyTime(b.HostPublicKey, b.BoundAt); err != nil {
		return err
	}
	person, err := DecodeKey(b.PersonPublicKey)
	if err != nil {
		return err
	}
	return VerifySSHSIG(person, b.Message(), b.Signature)
}

// VerifyHostBinding checks both the person's SSHSIG and the bound host's own
// signature. Whether the person and host are currently valid is checked by the
// caller.
func VerifyHostBinding(network string, b HostBinding) error {
	if err := VerifyPersonBinding(network, b); err != nil {
		return err
	}
	host, _ := DecodeKey(b.HostPublicKey)
	if err := verify(host, b.Message(), b.HostSignature); err != nil {
		return fmt.Errorf("%w: binding lacks the bound host's signature", ErrInvalid)
	}
	return nil
}

func VerifyHostUnbinding(network string, u HostUnbinding) error {
	if u.NetworkID != network {
		return fmt.Errorf("%w: unbinding is for a different network", ErrInvalid)
	}
	if err := checkKeyTime(u.HostPublicKey, u.UnboundAt); err != nil {
		return err
	}
	person, err := DecodeKey(u.PersonPublicKey)
	if err != nil {
		return err
	}
	return VerifySSHSIG(person, u.Message(), u.Signature)
}

// VerifyHostAdmission checks a host admission by the current root at the
// current epoch and returns the host ID.
func (c Chain) VerifyHostAdmission(a HostAdmission) (string, error) {
	if a.NetworkID != c.NetworkID || a.Epoch < 0 || a.Epoch > c.Epoch() || !ValidLabel(a.Member) {
		return "", fmt.Errorf("%w: host admission is not for this network's root chain", ErrInvalid)
	}
	if err := checkKeyTime(a.HostPublicKey, a.AdmittedAt); err != nil {
		return "", err
	}
	if err := c.verifyAdmitted(a.Epoch, a.Message(), a.Signature); err != nil {
		return "", err
	}
	key, _ := DecodeKey(a.HostPublicKey)
	return HostID(key), nil
}

// VerifyPersonAdmission checks a person admission by the current root at the
// current epoch.
func (c Chain) VerifyPersonAdmission(a PersonAdmission) error {
	if a.NetworkID != c.NetworkID || a.Epoch < 0 || a.Epoch > c.Epoch() || !ValidLabel(a.Member) {
		return fmt.Errorf("%w: person admission is not for this network's root chain", ErrInvalid)
	}
	if err := checkKeyTime(a.PersonPublicKey, a.AdmittedAt); err != nil {
		return err
	}
	return c.verifyAdmitted(a.Epoch, a.Message(), a.Signature)
}

// verifyAdmitted accepts a statement signed by the current root at the
// current epoch, or by an acceptable administrator at any epoch: an
// administrator's statements need no re-signing at a rotation.
func (c Chain) verifyAdmitted(e int64, message []byte, signature string) error {
	_, root, err := c.signerKey(message, signature, true)
	if err != nil {
		return err
	}
	if root && e != c.Epoch() {
		return fmt.Errorf("%w: a root-signed statement must be for the current epoch", ErrInvalid)
	}
	return nil
}

// VerifyPersonMembership checks a person admitted by invite: the invite is
// signed by the current root at the current epoch, the invite key signs the
// person key, and the person joined before the invite expired.
func (c Chain) VerifyPersonMembership(m PersonMembership) error {
	if m.NetworkID != c.NetworkID || m.InviteEpoch < 0 || m.InviteEpoch > c.Epoch() || !ValidLabel(m.Member) {
		return fmt.Errorf("%w: person invite is not for this network's root chain", ErrInvalid)
	}
	invite, err := DecodeKey(m.InvitePublicKey)
	if err != nil {
		return err
	}
	if _, err = DecodeKey(m.PersonPublicKey); err != nil {
		return err
	}
	expires, err := ParseTime(m.InviteExpiresAt)
	if err != nil {
		return fmt.Errorf("%w: invalid invite expiration", ErrInvalid)
	}
	joined, err := ParseTime(m.JoinedAt)
	if err != nil {
		return fmt.Errorf("%w: invalid join time", ErrInvalid)
	}
	if err = c.verifyAdmitted(m.InviteEpoch, PersonInviteStatement(m.NetworkID, m.InviteEpoch, m.InvitePublicKey, m.Member, m.InviteExpiresAt), m.InviteSignature); err != nil {
		return err
	}
	if err = verify(invite, PersonMemberStatement(m.NetworkID, m.InvitePublicKey, m.PersonPublicKey, m.JoinedAt), m.PersonSignature); err != nil {
		return err
	}
	if joined.After(expires) {
		return fmt.Errorf("%w: joined after invite expiration", ErrInvalid)
	}
	return nil
}

// PersonProof is a person's admission: exactly one of Admission and
// Membership is set.
type PersonProof struct {
	Admission  *PersonAdmission  `json:"admission"`
	Membership *PersonMembership `json:"membership"`
}

// VerifyPerson returns the person key and member label of a valid proof.
func (c Chain) VerifyPerson(p PersonProof) (string, string, error) {
	switch {
	case p.Admission != nil && p.Membership == nil:
		return p.Admission.PersonPublicKey, p.Admission.Member, c.VerifyPersonAdmission(*p.Admission)
	case p.Membership != nil && p.Admission == nil:
		return p.Membership.PersonPublicKey, p.Membership.Member, c.VerifyPersonMembership(*p.Membership)
	}
	return "", "", fmt.Errorf("%w: a person needs exactly one of admission or membership", ErrInvalid)
}

// PersonToken is a one-time person invite: the host-invite fields plus the
// epoch of the root that signed it.
type PersonToken struct {
	Token
	InviteEpoch int64 `json:"invite_epoch"`
}

// PersonInvite creates a person invite signed by root at epoch e.
func PersonInvite(network string, root ed25519.PrivateKey, e int64, member, expiresAt string) (PersonToken, error) {
	return PersonInviteWith(network, RawSigner{Key: root}, e, member, expiresAt)
}

// Redeem signs the person key with the invite key.
func (t PersonToken) Redeem(personPublicKey, joinedAt string) (PersonMembership, error) {
	invite, err := DecodeSeed(t.InviteSeed)
	if err != nil {
		return PersonMembership{}, err
	}
	if _, err = DecodeKey(personPublicKey); err != nil {
		return PersonMembership{}, err
	}
	m := PersonMembership{NetworkID: t.NetworkID, Member: t.Member, InvitePublicKey: t.InvitePublicKey, InviteExpiresAt: t.InviteExpiresAt, InviteEpoch: t.InviteEpoch, InviteSignature: t.InviteSignature, PersonPublicKey: personPublicKey, JoinedAt: joinedAt}
	m.PersonSignature = sign(invite, PersonMemberStatement(t.NetworkID, t.InvitePublicKey, personPublicKey, joinedAt))
	return m, nil
}

func (t PersonToken) Encode() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return PersonTokenPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodePersonToken checks everything that can be checked without the
// network's root chain: shape, labels, seed, expiry, and that the invite is
// signed by the root the token names.
func DecodePersonToken(value string, now time.Time) (PersonToken, error) {
	var t PersonToken
	data, err := decodePrefixed(value, PersonTokenPrefix)
	if err != nil {
		return t, err
	}
	if err = Strict(data, &t, append(append([]string{}, tokenFields...), "invite_epoch")...); err != nil {
		return t, err
	}
	if t.InviteEpoch < 0 || !strings.HasPrefix(t.NetworkID, "net_") || len(t.NetworkID) != 68 || !ValidLabel(t.Member) || !ValidLabel(t.NetworkName) {
		return t, fmt.Errorf("%w: invalid person invite", ErrInvalid)
	}
	if !ValidCoordinatorAddress(t.CoordinatorAddress) {
		return t, fmt.Errorf("%w: invalid coordinator address", ErrInvalid)
	}
	if _, err = DecodeKey(t.CoordinatorPublicKey); err != nil {
		return t, err
	}
	root, err := DecodeKey(t.RootPublicKey)
	if err != nil {
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
	if err != nil || !expires.After(now) {
		return t, fmt.Errorf("%w: person invite has expired or is invalid", ErrInvalid)
	}
	if err = verifyRoot(root, PersonInviteStatement(t.NetworkID, t.InviteEpoch, t.InvitePublicKey, t.Member, t.InviteExpiresAt), t.InviteSignature); err != nil {
		return t, err
	}
	return t, nil
}

// Descriptor lets an admitted host or person find and pin a network. It is
// not a secret and grants nothing by itself.
type Descriptor struct {
	NetworkID            string `json:"network_id"`
	NetworkName          string `json:"network_name"`
	RootPublicKey        string `json:"root_public_key"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
}

func (d Descriptor) Encode() (string, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return DescriptorPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeDescriptor parses a descriptor whose genesis root derives its ID.
func DecodeDescriptor(value string) (Descriptor, error) {
	var d Descriptor
	data, err := decodePrefixed(value, DescriptorPrefix)
	if err != nil {
		return d, err
	}
	if err = Strict(data, &d, "network_id", "network_name", "root_public_key", "coordinator_address", "coordinator_public_key"); err != nil {
		return d, err
	}
	root, err := DecodeKey(d.RootPublicKey)
	if err != nil {
		return d, err
	}
	if NetworkID(root) != d.NetworkID || !ValidLabel(d.NetworkName) || !ValidCoordinatorAddress(d.CoordinatorAddress) {
		return d, fmt.Errorf("%w: invalid network descriptor", ErrInvalid)
	}
	if _, err = DecodeKey(d.CoordinatorPublicKey); err != nil {
		return d, err
	}
	return d, nil
}

func decodePrefixed(value, prefix string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(value, prefix)
	if !ok {
		return nil, fmt.Errorf("%w: expected %s", ErrInvalid, prefix)
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != encoded {
		return nil, fmt.Errorf("%w: malformed %s", ErrInvalid, prefix)
	}
	return data, nil
}

// verifyPersonRemoval checks a removal under any root in the chain.
func (c Chain) verifyPersonRemoval(r PersonRemoval) error {
	return c.verifyByAnyRoot(r.NetworkID, r.PersonPublicKey, r.RemovedAt, r.Message(), r.Signature)
}
