package linking

import (
	"math"
	"strconv"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Transport evidence recognizes signatures without selecting or changing a pin.
func (v *activationVerifier) coordinatorEvidence() error {
	seen := map[string]Object{}
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		o := p.object
		if p.kind != "coordinator_move" && p.kind != "coordinator_successor" {
			continue
		}
		sequence, e := num(o, "sequence")
		if e != nil || sequence == 0 || sequence > math.MaxInt64 || !membership.ValidCoordinatorAddress(scalar(o, "address")) || !key(scalar(o, "public_key")) {
			return pathError("invalid")
		}
		n := strconv.FormatUint(sequence, 10)
		var identity string
		if p.kind == "coordinator_move" {
			if fields(o, "network_id sequence address public_key moved_at signer signature") != nil || scalar(o, "network_id") != v.net {
				return pathError("invalid")
			}
			if _, e := stamp(scalar(o, "moved_at")); e != nil {
				return pathError("invalid")
			}
			m := message("peerspan-coordinator-move-v1", v.net, n, scalar(o, "address"), scalar(o, "public_key"), scalar(o, "moved_at"))
			signer := scalar(o, "signer")
			if signer == "root" {
				if !v.anyRootSignature(m, scalar(o, "signature")) {
					return pathError("invalid")
				}
			} else {
				if !key(signer) {
					return pathError("invalid")
				}
				if !v.history.delegated[signer] {
					return pathError("forbidden")
				}
				if personSignature(signer, m, scalar(o, "signature")) != nil {
					return pathError("invalid")
				}
			}
			identity = "move:" + v.net + ":" + n
		} else {
			if fields(o, "sequence previous_public_key address public_key signed_at signature") != nil || !key(scalar(o, "previous_public_key")) {
				return pathError("invalid")
			}
			if _, e := stamp(scalar(o, "signed_at")); e != nil {
				return pathError("invalid")
			}
			m := message("peerspan-coordinator-successor-v1", n, scalar(o, "previous_public_key"), scalar(o, "address"), scalar(o, "public_key"), scalar(o, "signed_at"))
			if rawSignature(scalar(o, "previous_public_key"), m, scalar(o, "signature")) != nil {
				return pathError("invalid")
			}
			identity = "successor:" + scalar(o, "previous_public_key") + ":" + n
		}
		if previous, ok := seen[identity]; ok && !equivalent(previous, o) {
			return pathError("state_conflict")
		}
		seen[identity] = o
	}
	return nil
}
