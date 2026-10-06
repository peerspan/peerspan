package membership

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Person and host-binding vectors from docs/coordination-contract.md.
const (
	personSeed      = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="
	personPublic    = "bnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E="
	personSSH       = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG56HN0psLeP0Tr0xVmP7/TvKpcWbjym8uT7/M2AUFvx"
	personIDVector  = "person_7599776c3085e3f9da0d13071eb0b4ab50fd2bf64c06dd92c2365af3a328eca3"
	personAt        = "2026-10-08T00:00:00Z"
	personInviteExp = "2026-11-01T00:00:00Z"
	bindingVector   = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABADAULCAWp02fy0fuxtv6fhaI8PHqxyBPr6SzVcTupgU0xsTYIMciLKFSVOaqYIOshUcKvNhgbAmBsiz6Cbe7UBw=="
	unbindingVector = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAkiK02ZWdpz63BExI0ccVmkrPSaSUJEVrherPRCB7IWIDjvE6x1VieH2UJnMuWmp5tiXmTHuTs4mxDyehsUr4AA=="
	admissionVector = "57pOZqduTPBJKqC2gEAjW23pzd7zwul08CTAxX2KBRSlI36JJfb5WNf8x9LOlaLKK1jBL2r72mLJXIkpTYi+BA=="
	inviteVector    = "DOs/7yFxVmC3IuPAcfqlF1EDczkw0++1gRZOjIQNCcK7d3nOPFDZoWcnrhMpBIzdLlEF6fR52K45m8TXGKNVAQ=="
	memberVector    = "FP3SdKMjbdMcRQIsfMffRb6mnyqnDnX4hxj/cTz6DHyWeozcrRxdGU+/lYLEakp8tiS/jwOiCLJA/7DXhfOrDw=="
	removalVector   = "gIGBRuXaZVCyEU+jkM1JUxo88yDrpZ8k7JbmKGObmeF14QeY2//Wdrn4CgetByjN4szTFbssvtuS6ynt3O8jBA=="
	hostAdmitVector = "fYyNXrDCWJs61KeT2macWLkh/D+WVMI1i10iiC2mpFoQ9fz7EhDhy8KXAr+zjRfpdRzhzpGfAfEF4dBcMYGUCw=="
)

func TestPersonVectorsReproduce(t *testing.T) {
	root, invite, person := mustSeed(t, rootSeed), mustSeed(t, inviteSeed), mustSeed(t, personSeed)
	signer := KeySigner{person}
	if PublicKey(person) != personPublic || SSHAuthorizedKey(signer.PublicKey()) != personSSH || PersonID(signer.PublicKey()) != personIDVector {
		t.Fatal("person key vector mismatch")
	}
	net := vector.NetworkID
	binding, err := SignHostBinding(signer, net, vector.HostPublicKey, personAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = binding.SignHost(mustSeed(t, inviteSeed)); err == nil {
		t.Fatal("signed a binding with another host's key")
	}
	if err = binding.SignHost(mustSeed(t, hostSeed)); err != nil {
		t.Fatal(err)
	}
	if binding.HostSignature != "xv+sVNH6/g1gJrknO2ImE97qrROduO2Oe0U4gvqcddbHibmhzR28SRWf7RtYUDizWnWE4Eufy3F1aijw6uvSDg==" {
		t.Errorf("binding host_signature %s", binding.HostSignature)
	}
	unbinding, err := SignHostUnbinding(signer, net, vector.HostPublicKey, personAt)
	if err != nil {
		t.Fatal(err)
	}
	token := PersonToken{Token: Token{NetworkID: net, Member: "bob", InvitePublicKey: vector.InvitePublicKey, InviteSeed: Seed(invite), InviteExpiresAt: personInviteExp}}
	token.InviteSignature = sign(root, PersonInviteStatement(net, 0, vector.InvitePublicKey, "bob", personInviteExp))
	redeemed, err := token.Redeem(personPublic, personAt)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct{ name, got, want string }{
		{"person admission", SignPersonAdmission(root, net, 0, personPublic, "bob", personAt).Signature, admissionVector},
		{"person invite", token.InviteSignature, inviteVector},
		{"person membership", redeemed.PersonSignature, memberVector},
		{"person removal", SignPersonRemoval(root, net, personPublic, personAt).Signature, removalVector},
		{"host admission", SignHostAdmission(root, net, 0, vector.HostPublicKey, "carol", personAt).Signature, hostAdmitVector},
		{"host binding", binding.Signature, bindingVector},
		{"host unbinding", unbinding.Signature, unbindingVector},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s signature %s, want %s", c.name, c.got, c.want)
		}
	}
	chain, err := VerifyChain(root.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = chain.VerifyPersonMembership(redeemed); err != nil {
		t.Fatalf("person membership vector: %v", err)
	}
	if err = VerifyHostBinding(net, binding); err != nil {
		t.Fatalf("binding vector: %v", err)
	}
	for _, bad := range []string{"", base64.StdEncoding.EncodeToString(make([]byte, 64)), sign(mustSeed(t, inviteSeed), binding.Message())} {
		tampered := binding
		tampered.HostSignature = bad
		if VerifyHostBinding(net, tampered) == nil {
			t.Fatalf("binding with host_signature %q verified", bad)
		}
	}
	if err = VerifyHostUnbinding(net, unbinding); err != nil {
		t.Fatalf("unbinding vector: %v", err)
	}
}

func TestSSHSIGRejectsTamperingNamespaceAndKeyType(t *testing.T) {
	person := KeySigner{mustSeed(t, personSeed)}
	message := []byte("capsule test")
	good, err := SignSSHSIG(person, message)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifySSHSIG(person.PublicKey(), message, good); err != nil {
		t.Fatal(err)
	}
	if VerifySSHSIG(person.PublicKey(), []byte("capsule tesT"), good) == nil {
		t.Fatal("changed message verified")
	}
	other := mustSeed(t, hostSeed).Public().(ed25519.PublicKey)
	if VerifySSHSIG(other, message, good) == nil {
		t.Fatal("wrong person key verified")
	}
	blob, _ := base64.StdEncoding.DecodeString(good)
	// Flip each byte in turn: every tamper must be rejected.
	for i := range blob {
		tampered := append([]byte{}, blob...)
		tampered[i] ^= 0x01
		if VerifySSHSIG(person.PublicKey(), message, base64.StdEncoding.EncodeToString(tampered)) == nil {
			t.Fatalf("tampered byte %d verified", i)
		}
	}
	// A different namespace, signed correctly, is refused.
	wrongNS := strings.Replace(string(SSHSIGSignedData(message)), PersonNamespace, "file", 1)
	sig := ed25519.Sign(mustSeed(t, personSeed), []byte(wrongNS))
	b := []byte(strings.Replace(string(SSHSIGBlob(person.PublicKey(), sig)), PersonNamespace, "file", 1))
	if VerifySSHSIG(person.PublicKey(), message, base64.StdEncoding.EncodeToString(b)) == nil {
		t.Fatal("wrong namespace verified")
	}
	// A non-Ed25519 key type is refused.
	rsa := []byte(strings.Replace(string(blob), "ssh-ed25519", "ssh-rsa\x00\x00\x00\x00", 1))
	if VerifySSHSIG(person.PublicKey(), message, base64.StdEncoding.EncodeToString(rsa)) == nil {
		t.Fatal("wrong key type verified")
	}
	if VerifySSHSIG(person.PublicKey(), message, good+"=") == nil || VerifySSHSIG(person.PublicKey(), message, "") == nil {
		t.Fatal("non-canonical or empty signature verified")
	}
}

func TestPersonValidityAcrossRotation(t *testing.T) {
	root, next, person := mustSeed(t, rootSeed), mustSeed(t, newRootSeed), mustSeed(t, personSeed)
	genesis := root.Public().(ed25519.PublicKey)
	net := NetworkID(genesis)
	zero, _ := VerifyChain(genesis, nil)
	admission := SignPersonAdmission(root, net, 0, PublicKey(person), "bob", personAt)
	host := SignHostAdmission(root, net, 0, vector.HostPublicKey, "carol", personAt)
	if err := zero.VerifyPersonAdmission(admission); err != nil {
		t.Fatal(err)
	}
	if _, err := zero.VerifyHostAdmission(host); err != nil {
		t.Fatal(err)
	}
	rotated, err := VerifyChain(genesis, []Rotation{SignRotation(root, net, 1, next.Public().(ed25519.PublicKey), vectorAt)})
	if err != nil {
		t.Fatal(err)
	}
	// Epoch-0 admissions no longer count after a rotation; re-signed ones do.
	if rotated.VerifyPersonAdmission(admission) == nil {
		t.Fatal("old-epoch person admission accepted after rotation")
	}
	if _, err = rotated.VerifyHostAdmission(host); err == nil {
		t.Fatal("old-epoch host admission accepted after rotation")
	}
	if err = rotated.VerifyPersonAdmission(SignPersonAdmission(next, net, 1, PublicKey(person), "bob", personAt)); err != nil {
		t.Fatal(err)
	}
	if rotated.VerifyPersonAdmission(SignPersonAdmission(root, net, 1, PublicKey(person), "bob", personAt)) == nil {
		t.Fatal("admission signed by the old root at the new epoch accepted")
	}
	// Removal verifies under any root; tampering is refused.
	removal := SignPersonRemoval(root, net, PublicKey(person), personAt)
	entry := func(kind string, v any) Revocation {
		data, _ := json.Marshal(v)
		return Revocation{Kind: kind, Statement: data}
	}
	if kind, subject, err := rotated.VerifyRevocation(entry(KindPerson, removal)); err != nil || kind != KindPerson || subject != PublicKey(person) {
		t.Fatalf("removal: %v %s %s", err, kind, subject)
	}
	removal.PersonPublicKey = vector.HostPublicKey
	if _, _, err := rotated.VerifyRevocation(entry(KindPerson, removal)); err == nil {
		t.Fatal("tampered removal verified")
	}
	unbind, _ := SignHostUnbinding(KeySigner{person}, net, vector.HostPublicKey, personAt)
	if kind, subject, err := rotated.VerifyRevocation(entry(KindUnbind, unbind)); err != nil || kind != KindUnbind || subject != UnbindSubject(PublicKey(person), vector.HostPublicKey) {
		t.Fatalf("unbind: %v %s %s", err, kind, subject)
	}
	revoked := NewRevoked()
	revoked.Add(KindUnbind, UnbindSubject(PublicKey(person), vector.HostPublicKey))
	if revoked.Bound(PublicKey(person), vector.HostPublicKey) {
		t.Fatal("unbound binding still in effect")
	}
}

func TestPersonTokenAndDescriptor(t *testing.T) {
	root := mustSeed(t, rootSeed)
	net := NetworkID(root.Public().(ed25519.PublicKey))
	token, err := PersonInvite(net, root, 0, "bob", Timestamp(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	token.NetworkName, token.CoordinatorAddress, token.CoordinatorPublicKey = "team", "127.0.0.1:7400", PublicKey(root)
	encoded, err := token.Encode()
	if err != nil || !strings.HasPrefix(encoded, PersonTokenPrefix) {
		t.Fatal(err)
	}
	decoded, err := DecodePersonToken(encoded, time.Now())
	if err != nil || decoded.InviteEpoch != 0 || decoded.InviteSeed != token.InviteSeed {
		t.Fatalf("%v %+v", err, decoded)
	}
	if _, err = DecodePersonToken(strings.Replace(encoded, PersonTokenPrefix, TokenPrefix, 1), time.Now()); err == nil {
		t.Fatal("host token prefix accepted as a person invite")
	}
	if _, err = DecodePersonToken(encoded, time.Now().Add(2*time.Hour)); err == nil {
		t.Fatal("expired person invite accepted")
	}
	d := Descriptor{NetworkID: net, NetworkName: "team", RootPublicKey: PublicKey(root), CoordinatorAddress: "coord.example:7400", CoordinatorPublicKey: PublicKey(root)}
	text, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeDescriptor(text); err != nil || got != d {
		t.Fatalf("%v %+v", err, got)
	}
	d.NetworkID = vector.NetworkID[:len(vector.NetworkID)-1] + "0"
	bad, _ := d.Encode()
	if _, err = DecodeDescriptor(bad); err == nil {
		t.Fatal("descriptor whose root does not derive its ID accepted")
	}
}

func TestNormalizePersonKey(t *testing.T) {
	for _, value := range []string{personPublic, personSSH, personSSH + " pat@laptop"} {
		if got, err := NormalizePersonKey(value); err != nil || got != personPublic {
			t.Fatalf("%q: %v %s", value, err, got)
		}
	}
	for _, value := range []string{"", "ssh-rsa AAAA", "ssh-ed25519 !!!", strings.Replace(personSSH, "ssh-ed25519 ", "ssh-ed25519 AA", 1)} {
		if _, err := NormalizePersonKey(value); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
}
