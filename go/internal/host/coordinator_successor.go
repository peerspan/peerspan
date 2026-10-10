package host

import (
	"encoding/json"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// CoordinatorPending is the last entry of a verified chain of coordinator
// successors: the coordinator a network moves to once a sync with it
// succeeds.
type CoordinatorPending struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	Sequence  int64  `json:"sequence"`
}

// invalidSuccessor is last_sync_error when a served successor chain does not
// verify from the pinned coordinator key.
const invalidSuccessor = "invalid coordinator successor"

// followChain verifies successors served with a map from n's pinned key. A
// valid chain makes its last entry n's pending coordinator, replacing any
// earlier one, and returns true; an invalid one leaves n as it was and sets
// notice. An empty chain changes nothing.
func followChain(n *Network, chain []json.RawMessage, notice **string) bool {
	if len(chain) == 0 {
		return false
	}
	last, err := membership.VerifySuccessors(n.CoordinatorPublicKey, chain)
	if err != nil {
		message := invalidSuccessor
		*notice = &message
		return false
	}
	if last.Address == n.CoordinatorAddress && last.PublicKey == n.CoordinatorPublicKey {
		return false
	}
	n.CoordinatorPending = &CoordinatorPending{Address: last.Address, PublicKey: last.PublicKey, Sequence: last.Sequence}
	return true
}

// syncFollowing syncs a network, following coordinator successors. With a
// pending coordinator it syncs that one first and, if the sync and its map
// succeed, makes it the pinned coordinator; otherwise it syncs the pinned
// one. A valid chain in the pinned coordinator's answer sets a pending
// coordinator, which is synced at once unless this sync already tried it. A
// chain served by a coordinator just switched to is recorded and followed on
// the next sync. notice is what last_sync_error reports alongside a
// successful map: an invalid chain, or why the pending coordinator failed.
func (s *Store) syncFollowing(n Network, call func(Network) (appliedMap, []json.RawMessage, error)) (Network, appliedMap, *string, error) {
	var notice *string
	tried := ""
	tryPending := func() (appliedMap, bool) {
		p := n.CoordinatorPending
		tried = p.Address + "|" + p.PublicKey
		target := n
		target.CoordinatorAddress, target.CoordinatorPublicKey, target.CoordinatorPending = p.Address, p.PublicKey, nil
		applied, chain, err := call(target)
		if err != nil {
			message := "coordinator successor " + p.Address + ": " + err.Error()
			notice = &message
			return applied, false
		}
		n, notice = target, nil
		followChain(&n, chain, &notice)
		return applied, true
	}
	if n.CoordinatorPending != nil {
		if applied, ok := tryPending(); ok {
			return n, applied, notice, nil
		}
	}
	applied, chain, err := call(n)
	if err != nil {
		return n, applied, nil, err
	}
	if followChain(&n, chain, &notice) && n.CoordinatorPending.Address+"|"+n.CoordinatorPending.PublicKey != tried {
		if switched, ok := tryPending(); ok {
			return n, switched, notice, nil
		}
	}
	return n, applied, notice, nil
}
