package membership

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MemberTokenPrefix marks a member invite: one invite key signed by the root
// both as a host invite and as a person invite, so a single token can join a
// host and admit the person who runs it.
const MemberTokenPrefix = "capsule-member-invite-v1."

// MemberToken is a host invite token plus the person half of the same invite.
type MemberToken struct {
	Token
	InviteEpoch           int64  `json:"invite_epoch"`
	PersonInviteSignature string `json:"person_invite_signature"`
}

var memberTokenFields = append(append([]string{}, tokenFields...), "invite_epoch", "person_invite_signature")

// MemberInvite signs one invite key twice with root (the current root, at
// epoch e): as a host invite and as a person invite with the same label and
// expiry.
func MemberInvite(network string, root ed25519.PrivateKey, e int64, member, expiresAt string) (MemberToken, error) {
	host, err := InviteFor(network, root, member, expiresAt)
	if err != nil {
		return MemberToken{}, err
	}
	t := MemberToken{Token: host, InviteEpoch: e}
	t.PersonInviteSignature = sign(root, PersonInviteStatement(network, e, t.InvitePublicKey, member, expiresAt))
	return t, nil
}

// PersonToken returns the person half of the invite.
func (t MemberToken) PersonToken() PersonToken {
	p := PersonToken{Token: t.Token, InviteEpoch: t.InviteEpoch}
	p.InviteSignature = t.PersonInviteSignature
	return p
}

func (t MemberToken) Encode() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return MemberTokenPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeMemberToken checks both halves of a member invite without contacting
// the coordinator.
func DecodeMemberToken(value string, now time.Time) (MemberToken, error) {
	var t MemberToken
	data, err := decodePrefixed(value, MemberTokenPrefix)
	if err != nil {
		return t, err
	}
	if err = Strict(data, &t, memberTokenFields...); err != nil {
		return t, err
	}
	if t.InviteEpoch < 0 {
		return t, fmt.Errorf("%w: invalid invite epoch", ErrInvalid)
	}
	if err = checkToken(t.Token, now); err != nil {
		return t, err
	}
	root, err := DecodeKey(t.RootPublicKey)
	if err != nil {
		return t, err
	}
	if err = verify(root, PersonInviteStatement(t.NetworkID, t.InviteEpoch, t.InvitePublicKey, t.Member, t.InviteExpiresAt), t.PersonInviteSignature); err != nil {
		return t, err
	}
	return t, nil
}

// DecodeAnyPersonToken accepts a person invite or a member invite and returns
// its person half.
func DecodeAnyPersonToken(value string, now time.Time) (PersonToken, error) {
	if strings.HasPrefix(value, MemberTokenPrefix) {
		t, err := DecodeMemberToken(value, now)
		if err != nil {
			return PersonToken{}, err
		}
		return t.PersonToken(), nil
	}
	return DecodePersonToken(value, now)
}

// NetworkOf returns the network ID named by an invite token, member invite,
// person invite, or descriptor, without validating it; the daemon validates.
// The CLI uses it to sign a binding before joining.
func NetworkOf(value string) (string, error) {
	for _, prefix := range []string{TokenPrefix, MemberTokenPrefix, PersonTokenPrefix, DescriptorPrefix} {
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		data, err := decodePrefixed(value, prefix)
		if err != nil {
			return "", err
		}
		var fields struct {
			NetworkID string `json:"network_id"`
		}
		if err = json.Unmarshal(data, &fields); err != nil || fields.NetworkID == "" {
			return "", fmt.Errorf("%w: token names no network", ErrInvalid)
		}
		return fields.NetworkID, nil
	}
	return "", fmt.Errorf("%w: not an invite token or network descriptor", ErrInvalid)
}
