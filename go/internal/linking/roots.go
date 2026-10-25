package linking

import (
	"sort"
	"strconv"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// loadRoots resolves only exact signed lineage. Persisted-prefix comparison is
// the caller's transaction responsibility, not an assertion in this catalog.
func (v *activationVerifier) loadRoots() error {
	rotations := map[uint64]Object{}
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind != "rotation" {
			continue
		}
		o := p.object
		epoch, e := num(o, "epoch")
		if e != nil || epoch == 0 || fields(o, "network_id epoch previous_root_public_key root_public_key rotated_at signature") != nil || scalar(o, "network_id") != v.net || !key(scalar(o, "previous_root_public_key")) || !key(scalar(o, "root_public_key")) {
			return pathError("invalid")
		}
		if _, e = stamp(scalar(o, "rotated_at")); e != nil {
			return pathError("invalid")
		}
		if old, ok := rotations[epoch]; ok && !equivalent(old, o) {
			return pathError("state_conflict")
		}
		rotations[epoch] = o
	}
	epochs := make([]uint64, 0, len(rotations))
	for epoch := range rotations {
		epochs = append(epochs, epoch)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
	v.roots = []string{scalar(v.network, "genesis_root_public_key")}
	for _, epoch := range epochs {
		if epoch != uint64(len(v.roots)) {
			return pathError("proof_required")
		}
		o := rotations[epoch]
		previous := v.roots[len(v.roots)-1]
		m := message("peerspan-root-rotate-v1", v.net, strconv.FormatUint(epoch, 10), previous, scalar(o, "root_public_key"), scalar(o, "rotated_at"))
		if scalar(o, "previous_root_public_key") != previous || rootSignature(previous, m, scalar(o, "signature")) != nil {
			return pathError("invalid")
		}
		v.roots = append(v.roots, scalar(o, "root_public_key"))
	}
	tip := uint64(len(v.roots) - 1)
	if v.epoch > tip {
		return pathError("proof_required")
	}
	if v.epoch < tip {
		return pathError("state_conflict")
	}
	v.root = v.roots[tip]
	return nil
}

func (v *activationVerifier) epochRoot(o Object, field string) (string, uint64, error) {
	epoch, e := num(o, field)
	if e != nil {
		return "", 0, pathError("invalid")
	}
	if epoch >= uint64(len(v.roots)) {
		return "", 0, pathError("proof_required")
	}
	return v.roots[epoch], epoch, nil
}

func (v *activationVerifier) anyRootSignature(m []byte, sig string) bool {
	for _, root := range v.roots {
		if rootSignature(root, m, sig) == nil {
			return true
		}
	}
	return false
}

func (v *activationVerifier) legacyGrant(o Object, field string, m []byte, sig string) (bool, error) {
	root, epoch, e := v.epochRoot(o, field)
	if e != nil {
		return false, e
	}
	if rootSignature(root, m, sig) == nil {
		return epoch == v.epoch, nil
	}
	if v.anyRootSignature(m, sig) {
		return false, pathError("invalid")
	}
	return v.legacyAuthority(m, sig)
}

func (v *activationVerifier) loadAttestations() error {
	v.attested = map[string]string{}
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind != "attestation" {
			continue
		}
		o := p.object
		if fields(o, "network_id epoch host_public_key member attested_at signature") != nil || scalar(o, "network_id") != v.net || !key(scalar(o, "host_public_key")) || !membership.ValidLabel(scalar(o, "member")) {
			return pathError("invalid")
		}
		root, epoch, e := v.epochRoot(o, "epoch")
		if e != nil {
			return e
		}
		if _, e = stamp(scalar(o, "attested_at")); e != nil {
			return pathError("invalid")
		}
		if rootSignature(root, message("peerspan-attest-v1", v.net, strconv.FormatUint(epoch, 10), scalar(o, "host_public_key"), scalar(o, "member"), scalar(o, "attested_at")), scalar(o, "signature")) != nil {
			return pathError("invalid")
		}
		if epoch != v.epoch {
			continue
		}
		host, label := scalar(o, "host_public_key"), scalar(o, "member")
		if old, ok := v.attested[host]; ok && old != label {
			return pathError("state_conflict")
		}
		v.attested[host], v.hosts[host], v.state.Hosts[host] = label, label, true
	}
	return nil
}

type historicalLabel struct {
	person string
	epoch  uint64
	label  string
}

func (v *activationVerifier) historicalLabel(person string, epoch uint64, label string) bool {
	for k := range v.historicalPersons {
		if k.person == person && k.epoch <= epoch && k.label == label {
			return true
		}
	}
	return epoch == v.epoch && v.persons[person] == label
}

func (v *activationVerifier) historicalAdmissionKnown(person string) bool {
	if _, ok := v.persons[person]; ok {
		return true
	}
	for k := range v.historicalPersons {
		if k.person == person {
			return true
		}
	}
	return false
}

func epochIs(o Object, epoch uint64) bool { n, e := num(o, "epoch"); return e == nil && n == epoch }
