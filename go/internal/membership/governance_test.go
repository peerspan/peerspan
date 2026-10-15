package membership

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
)

// Revocation, leave, rotation, and attestation vectors from
// docs/coordination-contract.md.
const (
	newRootSeed   = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
	newRootPublic = "ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw="
	vectorAt      = "2026-10-07T00:00:00Z"
)

func TestGovernanceVectorsReproduce(t *testing.T) {
	root, host, next := mustSeed(t, rootSeed), mustSeed(t, hostSeed), mustSeed(t, newRootSeed)
	if PublicKey(next) != newRootPublic {
		t.Fatal("new root vector mismatch")
	}
	net := vector.NetworkID
	checks := []struct{ name, got, want string }{
		{"host revocation", SignHostRevocation(root, net, vector.HostPublicKey, vectorAt).Signature, "jclqdyH6N8H3WoO07mGA1trPc7WpmmvKIH1zibL1m9+zFoIK6ppGXuC7k8oXFhF8IWYtmuGGy70xBTsvkYzSCw=="},
		{"invite revocation", SignInviteRevocation(root, net, vector.InvitePublicKey, vectorAt).Signature, "pF9qtTO3npiuO+rf47SQ5PpgiSlq6dWYlIQPT+DTFO0PN9Yxf1bmacK83dinaY4qu+KMyk3JNnZW8v1CxZiJCA=="},
		{"leave", SignLeave(host, net, vectorAt).Signature, "36abHHiIjCXzpVFnssBQAEV+guYtiZGp3hsd5JmpBSH9f8VnZun74fql4G622oBx4aQHZ733k+nSdAfI1xPmDg=="},
		{"rotation", SignRotation(root, net, 1, next.Public().(ed25519.PublicKey), vectorAt).Signature, "gbWynmghmMqYfKSbPS5tnw20vNrvq8QqugZ4pJQ1IvhSUy0aO2VLtB7+VPFMJpinw7q+zyG52lMGyfaCSWPbCQ=="},
		{"attestation", SignAttestation(next, net, 1, vector.HostPublicKey, "alice", vectorAt).Signature, "oqBN8M8UY8e9c41wKnms8ZwWoH9zoHjMc0lwYi8iYWtLykbyts25SRgt+s1agJmbBIfGAx8nJp0QaP3yzx1IAw=="},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s signature %s, want %s", c.name, c.got, c.want)
		}
	}
}

func revocationEntry(t *testing.T, kind string, statement any) Revocation {
	t.Helper()
	data, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return Revocation{Kind: kind, Statement: data}
}

func TestChainRotationAttestationAndRevocations(t *testing.T) {
	root, host, next := mustSeed(t, rootSeed), mustSeed(t, hostSeed), mustSeed(t, newRootSeed)
	genesis := root.Public().(ed25519.PublicKey)
	net := vector.NetworkID
	rotation := SignRotation(root, net, 1, next.Public().(ed25519.PublicKey), vectorAt)
	chain, err := VerifyChain(genesis, []Rotation{rotation})
	if err != nil || chain.Epoch() != 1 || chain.CurrentPublicKey() != newRootPublic {
		t.Fatalf("chain: %v %+v", err, chain)
	}
	// A genesis-signed membership alone is not valid after rotation.
	if _, err = chain.ValidMember(vector, nil); err == nil {
		t.Fatal("old-root membership accepted after rotation")
	}
	attestation := SignAttestation(next, net, 1, vector.HostPublicKey, "alice", vectorAt)
	if err = chain.VerifyAttestation(attestation); err != nil {
		t.Fatal(err)
	}
	if id, err := chain.ValidMember(vector, map[string]Attestation{vector.HostPublicKey: attestation}); err != nil || id != hostID {
		t.Fatalf("attested member: %v %s", err, id)
	}
	if err = chain.VerifyAttestation(SignAttestation(root, net, 1, vector.HostPublicKey, "alice", vectorAt)); err == nil {
		t.Fatal("attestation by old root accepted")
	}
	if err = chain.VerifyAttestation(SignAttestation(next, net, 2, vector.HostPublicKey, "alice", vectorAt)); err == nil {
		t.Fatal("attestation for another epoch accepted")
	}
	// Revocations verify under any root in the chain; a leave under its host.
	for _, entry := range []Revocation{
		revocationEntry(t, KindHost, SignHostRevocation(root, net, vector.HostPublicKey, vectorAt)),
		revocationEntry(t, KindHost, SignHostRevocation(next, net, vector.HostPublicKey, vectorAt)),
		revocationEntry(t, KindInvite, SignInviteRevocation(root, net, vector.InvitePublicKey, vectorAt)),
		revocationEntry(t, KindLeave, SignLeave(host, net, vectorAt)),
	} {
		if _, _, err := chain.VerifyRevocation(entry); err != nil {
			t.Errorf("%s revocation rejected: %v", entry.Kind, err)
		}
	}
	other := mustSeed(t, inviteSeed)
	for _, entry := range []Revocation{
		revocationEntry(t, KindHost, SignHostRevocation(other, net, vector.HostPublicKey, vectorAt)),
		revocationEntry(t, KindLeave, SignLeave(other, net, vectorAt)),
		revocationEntry(t, "unknown", SignLeave(host, net, vectorAt)),
		revocationEntry(t, KindHost, SignHostRevocation(root, "net_"+vector.NetworkID[4:67]+"0", vector.HostPublicKey, vectorAt)),
	} {
		kind, subject, err := chain.VerifyRevocation(entry)
		if entry.Kind == KindLeave && err == nil && subject == PublicKey(other) {
			// A leave signed by another key is that key's own departure, not host's.
			continue
		}
		if err == nil {
			t.Errorf("forged %s revocation accepted (%s %s)", entry.Kind, kind, subject)
		}
	}
	revoked := NewRevoked()
	revoked.Add(KindInvite, vector.InvitePublicKey)
	if !revoked.Excludes(vector) {
		t.Fatal("membership through a revoked invite not excluded")
	}
}

func TestChainRejectsTamperingForksAndStaleChains(t *testing.T) {
	root, next := mustSeed(t, rootSeed), mustSeed(t, newRootSeed)
	genesis := root.Public().(ed25519.PublicKey)
	net := vector.NetworkID
	good := SignRotation(root, net, 1, next.Public().(ed25519.PublicKey), vectorAt)
	tampered := []Rotation{good, good, good, good}
	tampered[0].Epoch = 2
	tampered[1].RootPublicKey = rootPublic
	tampered[2].PreviousRootPublicKey = newRootPublic
	tampered[3].RotatedAt = "2026-10-08T00:00:00Z"
	for i, r := range tampered {
		if _, err := VerifyChain(genesis, []Rotation{r}); err == nil {
			t.Errorf("tampered rotation %d accepted", i)
		}
	}
	persisted, err := VerifyChain(genesis, []Rotation{good})
	if err != nil {
		t.Fatal(err)
	}
	genesisOnly, _ := VerifyChain(genesis, nil)
	if err = genesisOnly.Extends(persisted); err != nil {
		t.Fatalf("longer chain should extend: %v", err)
	}
	if err = persisted.Extends(genesisOnly); !errors.Is(err, ErrBehind) {
		t.Fatalf("shorter chain accepted: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	fork, err := VerifyChain(genesis, []Rotation{SignRotation(root, net, 1, other.Public().(ed25519.PublicKey), vectorAt)})
	if err != nil {
		t.Fatal(err)
	}
	if err = persisted.Extends(fork); !errors.Is(err, ErrFork) {
		t.Fatalf("fork accepted: %v", err)
	}
	if err = persisted.Extends(persisted); err != nil {
		t.Fatalf("equal chain rejected: %v", err)
	}
}

func TestStatementsAreStrictJSON(t *testing.T) {
	root := mustSeed(t, rootSeed)
	data, _ := json.Marshal(SignHostRevocation(root, vector.NetworkID, vector.HostPublicKey, vectorAt))
	var r HostRevocation
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"network_id":"x","host_public_key":"y","revoked_at":"z"}`,
		`{"network_id":"x","host_public_key":"y","revoked_at":"z","signature":"s","extra":1}`,
		`{"network_id":null,"host_public_key":"y","revoked_at":"z","signature":"s"}`,
	} {
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	var rot Rotation
	if err := json.Unmarshal([]byte(`{"network_id":"x","epoch":"1","previous_root_public_key":"a","root_public_key":"b","rotated_at":"c","signature":"d"}`), &rot); err == nil {
		t.Error("string epoch accepted")
	}
}

func TestRotatedRootIssuesInvites(t *testing.T) {
	root, next, host := mustSeed(t, rootSeed), mustSeed(t, newRootSeed), mustSeed(t, hostSeed)
	chain, err := VerifyChain(root.Public().(ed25519.PublicKey), []Rotation{SignRotation(root, vector.NetworkID, 1, next.Public().(ed25519.PublicKey), vectorAt)})
	if err != nil {
		t.Fatal(err)
	}
	token, err := InviteFor(vector.NetworkID, next, "bob", "2026-11-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	m, err := token.Join(host, vectorAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = chain.ValidMember(m, nil); err != nil {
		t.Fatalf("current-root invite rejected: %v", err)
	}
	if _, err = m.Verify(root.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("current-root invite verified under genesis root")
	}
}
