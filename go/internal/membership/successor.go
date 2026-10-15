package membership

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Successor is a coordinator identity's signed statement naming the identity
// that follows it: a new address, a new key, or both. It grants nothing beyond
// availability; hosts follow a chain of them from the key they pin.
type Successor struct {
	Sequence          int64  `json:"sequence"`
	PreviousPublicKey string `json:"previous_public_key"`
	Address           string `json:"address"`
	PublicKey         string `json:"public_key"`
	SignedAt          string `json:"signed_at"`
	Signature         string `json:"signature"`
}

var successorFields = []string{"sequence", "previous_public_key", "address", "public_key", "signed_at", "signature"}

// SuccessorStatement is the text a successor's previous key signs.
func SuccessorStatement(sequence int64, previousPublicKey, address, publicKey, signedAt string) []byte {
	return []byte(strings.Join([]string{"peerspan-coordinator-successor-v1", strconv.FormatInt(sequence, 10), previousPublicKey, address, publicKey, signedAt}, "\n"))
}

// SignSuccessor signs a successor with the previous identity's key.
func SignSuccessor(previous ed25519.PrivateKey, sequence int64, address string, public ed25519.PublicKey, signedAt string) (Successor, error) {
	if sequence < 1 || !ValidCoordinatorAddress(address) {
		return Successor{}, fmt.Errorf("%w: successor needs a positive sequence and a HOST:PORT address", ErrInvalid)
	}
	s := Successor{Sequence: sequence, PreviousPublicKey: PublicKey(previous), Address: address, PublicKey: EncodeKey(public), SignedAt: signedAt}
	s.Signature = sign(previous, SuccessorStatement(s.Sequence, s.PreviousPublicKey, s.Address, s.PublicKey, s.SignedAt))
	return s, nil
}

// DecodeSuccessor reads a strict successor object and checks its encodings
// and signature, but not its place in a chain.
func DecodeSuccessor(data []byte) (Successor, error) {
	var s Successor
	if err := Strict(data, &s, successorFields...); err != nil {
		return s, err
	}
	previous, err := DecodeKey(s.PreviousPublicKey)
	if err != nil {
		return s, err
	}
	if _, err = DecodeKey(s.PublicKey); err != nil {
		return s, err
	}
	if s.Sequence < 1 || !ValidCoordinatorAddress(s.Address) {
		return s, fmt.Errorf("%w: successor needs a positive sequence and a HOST:PORT address", ErrInvalid)
	}
	return s, verify(previous, SuccessorStatement(s.Sequence, s.PreviousPublicKey, s.Address, s.PublicKey, s.SignedAt), s.Signature)
}

// VerifySuccessors checks a chain of successors from the pinned coordinator
// key and returns its last entry: the first names pinned as its previous key,
// each signature verifies, sequences increase by exactly 1, and each later
// entry's previous key is the preceding entry's key.
func VerifySuccessors(pinned string, chain []json.RawMessage) (Successor, error) {
	if len(chain) == 0 {
		return Successor{}, fmt.Errorf("%w: empty successor chain", ErrInvalid)
	}
	var last Successor
	for i, raw := range chain {
		s, err := DecodeSuccessor(raw)
		if err != nil {
			return Successor{}, err
		}
		if i == 0 && s.PreviousPublicKey != pinned {
			return Successor{}, fmt.Errorf("%w: successor chain does not start at the pinned coordinator key", ErrInvalid)
		}
		if i > 0 && (s.Sequence != last.Sequence+1 || s.PreviousPublicKey != last.PublicKey) {
			return Successor{}, fmt.Errorf("%w: successor chain is not consecutive", ErrInvalid)
		}
		last = s
	}
	return last, nil
}
