package membership

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// Administrator and group vectors from docs/coordination-contract.md.
const (
	otherSeed       = "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY="
	otherPublic     = "iodf/x6zhFFXes1a/uQFRWVo3XyJ4JCGOgVXvHr0nxc="
	otherIDVector   = "person_72456720412037a6b339f884ce6d91bb4cc163a7dc3e4c58c658e6c2097b92a2"
	adminAt         = "2026-10-09T00:00:00Z"
	delegateVector  = "Lyfxr+rP0KdHx1qziif9X0KJ1aXCA3wxHQYofwptOAoYHq2fIAhK+kD8mF1GyyF/Kn2zBOH70P17YD2kCQBKBQ=="
	removeAdmVector = "IniB2OCVaCcC7RqYuR7Er1ZQMx83mhAs9GYjYSAQw2AaTbsJ8n3Qoj+3MFL0bsWujvhu4OGPqKAj1wXMxannBw=="
	adminHostVector = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQM3rbU3AdWJe6aK++xaJX9jLWFTA13B/dDI+N45tsD2Bth8jsxk2e0A0UQGRJlpBh3jIoWQAT1BnmHqTupPcNw8="
	groupVector     = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAAScGVlcnNwYW4tcGVyc29uLXYxAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQJ8BRATXZY4iPbocOCfUvJpR8/FLoXx+sowzBd3SIgxl1j7wnUcpiDGLIMzOSzkFa6a3lShI3r+qTeKn7nJOBwE="
)

func TestAdminVectorsReproduce(t *testing.T) {
	root, person, other := mustSeed(t, rootSeed), mustSeed(t, personSeed), mustSeed(t, otherSeed)
	if PublicKey(other) != otherPublic || PersonID(other.Public().(ed25519.PublicKey)) != otherIDVector {
		t.Fatal("second person key vector mismatch")
	}
	net := vector.NetworkID
	admin := SSHSigner{KeySigner{person}}
	delegation, err := SignAdminDelegation(RawSigner{root}, net, 0, personPublic, adminAt)
	if err != nil {
		t.Fatal(err)
	}
	removal, err := SignAdminRemoval(RawSigner{root}, net, personPublic, true, nil, adminAt)
	if err != nil {
		t.Fatal(err)
	}
	host, err := SignHostAdmissionWith(admin, net, 0, vector.HostPublicKey, "carol", adminAt)
	if err != nil {
		t.Fatal(err)
	}
	group, err := SignGroup(admin, net, "backend", 1, []string{personIDVector, otherIDVector}, adminAt)
	if err != nil {
		t.Fatal(err)
	}
	if group.Members[0] != otherIDVector || group.Members[1] != personIDVector {
		t.Fatalf("group members not sorted: %v", group.Members)
	}
	checks := []struct{ name, got, want string }{
		{"delegation", delegation.Signature, delegateVector},
		{"administrator removal", removal.Signature, removeAdmVector},
		{"administrator host admission", host.Signature, adminHostVector},
		{"group", group.Signature, groupVector},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s signature %s, want %s", c.name, c.got, c.want)
		}
	}
	// The statements round-trip strictly and verify under the chain.
	chain, err := VerifyChain(root.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := chain.VerifyDelegation(delegation); err != nil || key != personPublic {
		t.Fatalf("delegation does not verify: %v", err)
	}
	if err = chain.VerifyAdminRemoval(removal); err != nil {
		t.Fatal(err)
	}
	// Without the administrator, its statements do not verify; with it they do.
	if _, err = chain.VerifyHostAdmission(host); err == nil {
		t.Fatal("accepted an administrator admission without the administrator")
	}
	if _, err = chain.VerifyGroup(group); err == nil {
		t.Fatal("accepted an administrator group without the administrator")
	}
	state := chain.Administrators([]AdminDelegation{delegation}, nil)
	if !state.Current[personPublic] || !state.Signers[personPublic] {
		t.Fatal("delegated person is not an administrator")
	}
	admins := chain.WithAdminState(state)
	if _, err = admins.VerifyHostAdmission(host); err != nil {
		t.Fatal(err)
	}
	if signer, err := admins.VerifyGroup(group); err != nil || signer != personPublic {
		t.Fatalf("group does not verify: %v", err)
	}
	for _, v := range []any{&delegation, &removal, &group} {
		data, _ := json.Marshal(v)
		if err = json.Unmarshal(data, v); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdminRemovalAndRotation(t *testing.T) {
	_, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	root := RawSigner{rootKey}
	chain, _ := VerifyChain(root.PublicKey(), nil)
	_, adminKey, _ := ed25519.GenerateKey(rand.Reader)
	admin := SSHSigner{KeySigner{adminKey}}
	adminPublic := EncodeKey(admin.PublicKey())
	net := chain.NetworkID
	at := "2026-10-09T00:00:00Z"
	delegation, _ := SignAdminDelegation(root, net, 0, adminPublic, at)
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := SignHostAdmissionWith(admin, net, 0, PublicKey(hostKey), "h", at)

	// Removal without revoke_admitted keeps earlier statements valid; the
	// administrator is no longer current.
	keep, _ := SignAdminRemoval(root, net, adminPublic, false, []string{StatementDigest(host.Message())}, at)
	state := chain.Administrators([]AdminDelegation{delegation}, []AdminRemoval{keep})
	if state.Current[adminPublic] || !state.Signers[adminPublic] {
		t.Fatalf("removal without revoke_admitted: %+v", state)
	}
	if _, err := chain.WithAdminState(state).VerifyHostAdmission(host); err != nil {
		t.Fatal(err)
	}
	// A statement the removal does not list, backdated or not, is invalid.
	backdated, _ := SignHostAdmissionWith(admin, net, 0, PublicKey(hostKey), "other", "2020-01-01T00:00:00Z")
	if _, err := chain.WithAdminState(state).VerifyHostAdmission(backdated); err == nil {
		t.Fatal("accepted an unlisted statement by a removed administrator")
	}
	if chain.WithAdminState(state).SignerValid(backdated.Message(), backdated.Signature) {
		t.Fatal("SignerValid accepted an unlisted statement")
	}
	// The kept list is part of the signed removal and must be sorted hex.
	tampered := keep
	tampered.Kept = append([]string{StatementDigest(backdated.Message())}, keep.Kept...)
	if chain.VerifyAdminRemoval(tampered) == nil {
		t.Fatal("accepted a kept list changed after signing")
	}
	data, _ := json.Marshal(keep)
	var decoded AdminRemoval
	if err := json.Unmarshal(data, &decoded); err != nil || chain.VerifyAdminRemoval(decoded) != nil {
		t.Fatalf("removal round trip: %v", err)
	}
	// A second plain removal does not widen the kept list.
	wider, _ := SignAdminRemoval(root, net, adminPublic, false, []string{StatementDigest(backdated.Message())}, at)
	if _, err := chain.WithAdminState(chain.Administrators([]AdminDelegation{delegation}, []AdminRemoval{keep, wider})).VerifyHostAdmission(backdated); err == nil {
		t.Fatal("merged the kept lists of two removals")
	}
	// With revoke_admitted, everything the administrator signed is invalid.
	cascade, _ := SignAdminRemoval(root, net, adminPublic, true, nil, at)
	state = chain.Administrators([]AdminDelegation{delegation}, []AdminRemoval{keep, cascade})
	if state.Signers[adminPublic] {
		t.Fatal("revoke_admitted kept the administrator as a signer")
	}
	if _, err := chain.WithAdminState(state).VerifyHostAdmission(host); err == nil {
		t.Fatal("accepted a statement by an administrator removed with revoke_admitted")
	}
	// An administrator cannot delegate, remove administrators, or rotate.
	byAdmin, _ := SignAdminDelegation(admin, net, 0, adminPublic, at)
	if _, err := chain.WithAdmins(map[string]bool{adminPublic: true}).VerifyDelegation(byAdmin); err == nil {
		t.Fatal("accepted a delegation signed by an administrator")
	}

	// Rotating to an SSH root: the rotation is raw by the old root; later
	// root statements are SSHSIG by the new root and verify the same way.
	_, sshRootKey, _ := ed25519.GenerateKey(rand.Reader)
	sshRoot := SSHSigner{KeySigner{sshRootKey}}
	rotation, _ := SignRotationWith(root, net, 1, sshRoot.PublicKey(), at)
	next, err := VerifyChain(root.PublicKey(), []Rotation{rotation})
	if err != nil {
		t.Fatal(err)
	}
	renewed, _ := SignAdminDelegation(sshRoot, net, 1, adminPublic, at)
	if _, err = next.VerifyDelegation(renewed); err != nil {
		t.Fatal(err)
	}
	state = next.Administrators([]AdminDelegation{delegation}, nil)
	if state.Current[adminPublic] || !state.Signers[adminPublic] {
		t.Fatal("an epoch-0 delegation must not be current at epoch 1")
	}
	state = next.Administrators([]AdminDelegation{delegation, renewed}, nil)
	if !state.Current[adminPublic] {
		t.Fatal("renewed delegation is not current")
	}
	// The administrator's epoch-0 admission still verifies at epoch 1, while
	// a root-signed epoch-0 admission does not.
	if _, err = next.WithAdminState(state).VerifyHostAdmission(host); err != nil {
		t.Fatal(err)
	}
	old := SignHostAdmission(rootKey, net, 0, PublicKey(hostKey), "h", at)
	if _, err = next.VerifyHostAdmission(old); err == nil {
		t.Fatal("accepted a root admission from an earlier epoch")
	}
	sshAdmission, _ := SignHostAdmissionWith(sshRoot, net, 1, PublicKey(hostKey), "h", at)
	if _, err = next.VerifyHostAdmission(sshAdmission); err != nil {
		t.Fatal(err)
	}
	// A root removal can also be SSHSIG.
	sshRemoval, _ := SignAdminRemoval(sshRoot, net, adminPublic, false, nil, at)
	if err = next.VerifyAdminRemoval(sshRemoval); err != nil {
		t.Fatal(err)
	}
}

func TestGroupRules(t *testing.T) {
	_, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	root := RawSigner{rootKey}
	chain, _ := VerifyChain(root.PublicKey(), nil)
	at := "2026-10-09T00:00:00Z"
	for _, name := range []string{"", "Backend", "-x", "a b", string(make([]byte, 65))} {
		if ValidGroupName(name) {
			t.Errorf("accepted group name %q", name)
		}
	}
	if !ValidGroupName("backend.team_1-a") {
		t.Error("refused a valid group name")
	}
	v1, _ := SignGroup(root, chain.NetworkID, "backend", 1, []string{personIDVector}, at)
	v2, _ := SignGroup(root, chain.NetworkID, "backend", 2, nil, at)
	newest := chain.NewestGroups([]GroupDefinition{v2, v1})
	if newest["backend"].Version != 2 || len(newest["backend"].Members) != 0 {
		t.Fatalf("newest group: %+v", newest)
	}
	unsorted := v1
	unsorted.Members = []string{personIDVector, otherIDVector}
	if _, err := chain.VerifyGroup(unsorted); err == nil {
		t.Fatal("accepted unsorted members")
	}
	if _, err := SignGroup(root, chain.NetworkID, "backend", 1, []string{"bob"}, at); err == nil {
		t.Fatal("accepted a label as a group member")
	}
}
