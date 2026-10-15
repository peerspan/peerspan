package membership

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Vectors from docs/coordination-contract.md.
var vector = Membership{
	NetworkID:       "net_34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e",
	Member:          "alice",
	InvitePublicKey: "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=",
	InviteExpiresAt: "2026-11-01T00:00:00Z",
	InviteSignature: "jCdKpz/36wwIgHnZmbIALehw0KPuFefRlkKMmgIv3f1aJfCpfqf4bDJm/WUbI2ONX5oW+ZN4i08YSsCWwusCAg==",
	HostPublicKey:   "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=",
	JoinedAt:        "2026-10-05T12:00:00Z",
	HostSignature:   "V5T2OGpQUQ7F6923mnjWVeyYGopVhMNz6eLP4V0WQSqlPJHS59w+YE1CSDapAAA3w8dxKqxmVFm0R55l7W8SBw==",
}

const (
	rootSeed   = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	rootPublic = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
	inviteSeed = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	hostSeed   = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	hostID     = "host_b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709"
)

func mustSeed(t *testing.T, seed string) ed25519.PrivateKey {
	t.Helper()
	key, err := DecodeSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestVectorsReproduce(t *testing.T) {
	root, invite, host := mustSeed(t, rootSeed), mustSeed(t, inviteSeed), mustSeed(t, hostSeed)
	if PublicKey(root) != rootPublic || NetworkID(root.Public().(ed25519.PublicKey)) != vector.NetworkID {
		t.Fatal("root vector mismatch")
	}
	if PublicKey(invite) != vector.InvitePublicKey || PublicKey(host) != vector.HostPublicKey || HostID(host.Public().(ed25519.PublicKey)) != hostID {
		t.Fatal("key vector mismatch")
	}
	token := Token{NetworkID: vector.NetworkID, Member: "alice", InvitePublicKey: PublicKey(invite), InviteSeed: inviteSeed, InviteExpiresAt: vector.InviteExpiresAt,
		InviteSignature: sign(root, InviteStatement(vector.NetworkID, vector.InvitePublicKey, "alice", vector.InviteExpiresAt))}
	m, err := token.Join(host, vector.JoinedAt)
	if err != nil {
		t.Fatal(err)
	}
	if m != vector {
		t.Fatalf("signatures differ from vectors:\n%+v", m)
	}
	id, err := vector.Verify(root.Public().(ed25519.PublicKey))
	if err != nil || id != hostID {
		t.Fatalf("vector does not verify: %v", err)
	}
}

func TestTamperedFieldsRejected(t *testing.T) {
	root, _ := DecodeKey(rootPublic)
	other := mustSeed(t, hostSeed).Public().(ed25519.PublicKey)
	if _, err := vector.Verify(other); err == nil {
		t.Fatal("wrong root accepted")
	}
	tamper := map[string]func(*Membership){
		"network_id":        func(m *Membership) { m.NetworkID = "net_" + strings.Repeat("0", 64) },
		"member":            func(m *Membership) { m.Member = "mallory" },
		"invite_public_key": func(m *Membership) { m.InvitePublicKey = rootPublic },
		"invite_expires_at": func(m *Membership) { m.InviteExpiresAt = "2026-12-01T00:00:00Z" },
		"invite_signature":  func(m *Membership) { m.InviteSignature = m.HostSignature },
		"host_public_key":   func(m *Membership) { m.HostPublicKey = rootPublic },
		"joined_at":         func(m *Membership) { m.JoinedAt = "2026-10-05T12:00:01Z" },
		"host_signature":    func(m *Membership) { m.HostSignature = m.InviteSignature },
		"joined_late":       func(m *Membership) { m.JoinedAt = "2026-11-02T00:00:00Z" },
		"expiry_spelling":   func(m *Membership) { m.InviteExpiresAt = "2026-11-01T00:00:00.0Z" },
	}
	for name, change := range tamper {
		m := vector
		change(&m)
		if _, err := m.Verify(root); err == nil {
			t.Errorf("tampered %s accepted", name)
		}
	}
}

func TestNonCanonicalBase64Rejected(t *testing.T) {
	for _, value := range []string{
		"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",    // missing padding
		"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1x=",   // non-zero trailing bits
		"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=\n", // trailing newline
		"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=" + "AA==",
		"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w_",
	} {
		if _, err := DecodeKey(value); err == nil {
			t.Errorf("non-canonical key %q accepted", value)
		}
	}
	m := vector
	m.HostSignature = strings.TrimSuffix(m.HostSignature, "==")
	root, _ := DecodeKey(rootPublic)
	if _, err := m.Verify(root); err == nil {
		t.Fatal("unpadded signature accepted")
	}
}

func TestStrictMembershipJSON(t *testing.T) {
	data, _ := json.Marshal(vector)
	var m Membership
	if err := json.Unmarshal(data, &m); err != nil || m != vector {
		t.Fatalf("round trip failed: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(string(data), `"member":"alice"`, `"member":null`, 1),
		strings.Replace(string(data), `{`, `{"extra":"x",`, 1),
		strings.Replace(string(data), `"member":"alice",`, ``, 1),
	} {
		if err := json.Unmarshal([]byte(bad), &m); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestTokenRoundTripAndChecks(t *testing.T) {
	root := mustSeed(t, rootSeed)
	expires := Timestamp(time.Now().Add(time.Hour))
	token, err := Invite(root, "bob", expires)
	if err != nil {
		t.Fatal(err)
	}
	token.NetworkName, token.CoordinatorAddress, token.CoordinatorPublicKey = "team", "coord.example:7400", rootPublic
	encoded, err := token.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeToken(encoded, time.Now())
	if err != nil || decoded != token {
		t.Fatalf("token round trip: %v", err)
	}
	if _, err := DecodeToken(encoded, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired token accepted")
	}
	host := mustSeed(t, hostSeed)
	m, err := decoded.Join(host, Timestamp(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if id, err := m.Verify(root.Public().(ed25519.PublicKey)); err != nil || id != hostID {
		t.Fatalf("joined membership: %v", err)
	}
	mutations := []func(*Token){
		func(t *Token) { t.Member = "mallory" },
		func(t *Token) { t.InviteSeed = hostSeed },
		func(t *Token) { t.NetworkID = "net_" + strings.Repeat("1", 64) },
		func(t *Token) { t.CoordinatorPublicKey = "short" },
		func(t *Token) { t.CoordinatorAddress = "no-port" },
		func(t *Token) { t.NetworkName = " padded" },
	}
	for i, mutate := range mutations {
		changed := token
		mutate(&changed)
		value, _ := changed.Encode()
		if _, err := DecodeToken(value, time.Now()); err == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
	for _, bad := range []string{"", encoded[len(TokenPrefix):], encoded + "=", "peerspan-invite-v1.!!"} {
		if _, err := DecodeToken(bad, time.Now()); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLabelsAndAddresses(t *testing.T) {
	for _, ok := range []string{"a", "Alice Smith", strings.Repeat("x", 128), "é"} {
		if !ValidLabel(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", " a", "a ", "a\nb", "a\x7f", strings.Repeat("x", 129)} {
		if ValidLabel(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, ok := range []string{"", "127.0.0.1:1", "[::1]:7400"} {
		if !ValidAddress(ok) {
			t.Errorf("rejected address %q", ok)
		}
	}
	for _, bad := range []string{"127.0.0.1:0", "host:1", "127.0.0.1", "[fe80::1%eth0]:1"} {
		if ValidAddress(bad) {
			t.Errorf("accepted address %q", bad)
		}
	}
	for _, ok := range []string{"coord.example:7400", "127.0.0.1:1", "[::1]:7400"} {
		if !ValidCoordinatorAddress(ok) {
			t.Errorf("rejected coordinator %q", ok)
		}
	}
	for _, bad := range []string{"coord.example", ":1", "a:0", "a:65536", "a b:1", "a:01"} {
		if ValidCoordinatorAddress(bad) {
			t.Errorf("accepted coordinator %q", bad)
		}
	}
}
