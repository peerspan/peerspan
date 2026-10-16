package host

import (
	"encoding/json"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// CoordinatorPending is the coordinator a network moves to once a sync with
// it succeeds: the last entry of a verified chain of coordinator successors,
// or a verified move. Sequence is the successor's or the move's sequence;
// MoveSequence is the move's, and null for a successor.
type CoordinatorPending struct {
	Address      string `json:"address"`
	PublicKey    string `json:"public_key"`
	Sequence     int64  `json:"sequence"`
	Source       string `json:"source"`
	MoveSequence *int64 `json:"move_sequence"`
}

// Sources of a pending coordinator.
const (
	pendingSuccessor = "successor"
	pendingMove      = "move"
)

func (p *CoordinatorPending) isMove() bool { return p != nil && p.Source == pendingMove }

// invalidSuccessor is last_sync_error when a served successor chain does not
// verify from the pinned coordinator key.
const invalidSuccessor = "invalid coordinator successor"

// followChain verifies successors served with a map from n's pinned key. A
// valid chain makes its last entry n's pending coordinator, replacing any
// earlier one, and returns true; an invalid one leaves n as it was and sets
// notice. An empty chain changes nothing, and a successor never replaces a
// pending move.
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
	if (last.Address == n.CoordinatorAddress && last.PublicKey == n.CoordinatorPublicKey) || n.CoordinatorPending.isMove() {
		return false
	}
	n.CoordinatorPending = &CoordinatorPending{Address: last.Address, PublicKey: last.PublicKey, Sequence: last.Sequence, Source: pendingSuccessor}
	return true
}

// syncFollowing syncs a network, following coordinator moves and successors.
// With a pending coordinator it syncs that one first and, if the sync and its
// map succeed, makes it the pinned coordinator; otherwise it syncs the pinned
// one. A valid move with a sequence above applied in the pinned
// coordinator's map, or a valid chain in its answer, sets a pending
// coordinator, which is synced at once unless this sync already tried it; a
// move replaces a pending successor, and a successor never replaces a
// pending move. A move or chain served by a coordinator just switched to is
// recorded and followed on the next sync. notice is what last_sync_error
// reports alongside a successful map: an invalid chain, or why the pending
// coordinator failed. The returned sequence is the move sequence to record
// as applied: that of a move switched to, or of one naming the pinned
// coordinator.
func (s *Store) syncFollowing(n Network, applied int64, call func(Network) (appliedMap, []json.RawMessage, error)) (Network, appliedMap, *string, int64, error) {
	var notice *string
	tried := ""
	learn := func(a appliedMap) {
		if a.move != nil {
			_, applied = considerMove(&n, *a.move, applied)
		}
	}
	tryPending := func() (appliedMap, bool) {
		p := n.CoordinatorPending
		tried = p.Address + "|" + p.PublicKey
		target := n
		target.CoordinatorAddress, target.CoordinatorPublicKey, target.CoordinatorPending = p.Address, p.PublicKey, nil
		result, chain, err := call(target)
		if err != nil {
			source := "successor"
			if p.isMove() {
				source = "move"
			}
			message := "coordinator " + source + " " + p.Address + ": " + err.Error()
			notice = &message
			return result, false
		}
		if p.isMove() {
			applied = max(applied, *p.MoveSequence)
		}
		n, notice = target, nil
		followChain(&n, chain, &notice)
		learn(result)
		return result, true
	}
	if n.CoordinatorPending != nil {
		if result, ok := tryPending(); ok {
			return n, result, notice, applied, nil
		}
	}
	result, chain, err := call(n)
	if err != nil {
		return n, result, nil, applied, err
	}
	followChain(&n, chain, &notice)
	learn(result)
	if p := n.CoordinatorPending; p != nil && p.Address+"|"+p.PublicKey != tried {
		if switched, ok := tryPending(); ok {
			return n, switched, notice, applied, nil
		}
	}
	return n, result, notice, applied, nil
}
