package membership

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMemberInviteCarriesHostAndPersonHalves(t *testing.T) {
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	network := NetworkID(root.Public().(ed25519.PublicKey))
	expires := Timestamp(time.Now().Add(time.Hour))
	token, err := MemberInvite(network, root, 0, "bob", expires)
	if err != nil {
		t.Fatal(err)
	}
	token.NetworkName, token.CoordinatorAddress, token.CoordinatorPublicKey = "team", "127.0.0.1:7400", PublicKey(root)
	encoded, err := token.Encode()
	if err != nil || !strings.HasPrefix(encoded, MemberTokenPrefix) {
		t.Fatalf("encode: %v %q", err, encoded)
	}
	decoded, err := DecodeMemberToken(encoded, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The host half joins like a host invite; the person half redeems like a
	// person invite. Both use the same one-time invite key.
	_, host, _ := ed25519.GenerateKey(rand.Reader)
	m, err := decoded.Token.Join(host, Timestamp(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Verify(root.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("host half: %v", err)
	}
	person, _, _ := ed25519.GenerateKey(rand.Reader)
	p, err := decoded.PersonToken().Redeem(EncodeKey(person), Timestamp(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if err = (Chain{NetworkID: network, Roots: []ed25519.PublicKey{root.Public().(ed25519.PublicKey)}}).VerifyPersonMembership(p); err != nil {
		t.Fatalf("person half: %v", err)
	}
	if any, err := DecodeAnyPersonToken(encoded, time.Now()); err != nil || any.InvitePublicKey != token.InvitePublicKey {
		t.Fatalf("person half via DecodeAnyPersonToken: %v", err)
	}
	if got, err := NetworkOf(encoded); err != nil || got != network {
		t.Fatalf("NetworkOf: %q %v", got, err)
	}

	// Tampering with either half, or presenting it as another token kind, fails.
	tamper := func(field, value string) string {
		data, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, MemberTokenPrefix))
		var fields map[string]any
		_ = json.Unmarshal(data, &fields)
		fields[field] = value
		data, _ = json.Marshal(fields)
		return MemberTokenPrefix + base64.RawURLEncoding.EncodeToString(data)
	}
	other := base64.StdEncoding.EncodeToString(make([]byte, 64))
	for _, bad := range []string{tamper("person_invite_signature", other), tamper("invite_signature", other), tamper("member", "mallory")} {
		if _, err = DecodeMemberToken(bad, time.Now()); err == nil {
			t.Fatal("tampered member invite accepted")
		}
	}
	if _, err = DecodeToken(encoded, time.Now()); err == nil {
		t.Fatal("member invite decoded as a host invite")
	}
	if _, err = DecodeMemberToken(encoded, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired member invite accepted")
	}
}
