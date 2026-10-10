package membership

import (
	"fmt"
	"strconv"
)

// Move is a signed statement moving one network to another coordinator. The
// network's current root or a current administrator signs it; for each
// network the valid move with the highest sequence applies, and it always
// takes precedence over coordinator successors.
type Move struct {
	NetworkID string `json:"network_id"`
	Sequence  int64  `json:"sequence"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	MovedAt   string `json:"moved_at"`
	// Signer is MoveRoot or the administrator's person public key.
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

// MoveRoot is a move's signer when the network's current root signs it.
const MoveRoot = "root"

var moveFields = []string{"network_id", "sequence", "address", "public_key", "moved_at", "signer", "signature"}

// MoveStatement is the text a move's signer signs.
func MoveStatement(network string, sequence int64, address, publicKey, movedAt string) []byte {
	return statement("capsule-coordinator-move-v1", network, strconv.FormatInt(sequence, 10), address, publicKey, movedAt)
}

func (m Move) Message() []byte {
	return MoveStatement(m.NetworkID, m.Sequence, m.Address, m.PublicKey, m.MovedAt)
}

// UnmarshalJSON requires exactly the move fields, none null.
func (m *Move) UnmarshalJSON(data []byte) error {
	type plain Move
	return Strict(data, (*plain)(m), moveFields...)
}

// SignMove signs a move as the network's root (raw, or SSHSIG for an SSH
// root) when asRoot, or else as the administrator whose person key signer
// holds (SSHSIG).
func SignMove(signer StatementSigner, asRoot bool, network string, sequence int64, address, publicKey, movedAt string) (Move, error) {
	if sequence < 1 || !ValidCoordinatorAddress(address) {
		return Move{}, fmt.Errorf("%w: a move needs a positive sequence and a HOST:PORT address", ErrInvalid)
	}
	if _, err := DecodeKey(publicKey); err != nil {
		return Move{}, err
	}
	m := Move{NetworkID: network, Sequence: sequence, Address: address, PublicKey: publicKey, MovedAt: movedAt, Signer: MoveRoot}
	if !asRoot {
		m.Signer = EncodeKey(signer.PublicKey())
	}
	var err error
	m.Signature, err = signer.SignStatement(m.Message())
	return m, err
}

// VerifyMove checks a move under the chain: it is for the chain's network,
// its sequence is at least 1, its address is a valid coordinator address, its
// key is canonical, and it is signed by the current root or, in SSHSIG, by
// the administrator it names, which must be in current (the network's
// current administrators).
func (c Chain) VerifyMove(m Move, current map[string]bool) error {
	if m.NetworkID != c.NetworkID {
		return fmt.Errorf("%w: move is for a different network", ErrInvalid)
	}
	if m.Sequence < 1 || !ValidCoordinatorAddress(m.Address) {
		return fmt.Errorf("%w: a move needs a positive sequence and a HOST:PORT address", ErrInvalid)
	}
	if _, err := DecodeKey(m.PublicKey); err != nil {
		return err
	}
	if m.Signer == MoveRoot {
		return verifyRoot(c.Current(), m.Message(), m.Signature)
	}
	key, err := DecodeKey(m.Signer)
	if err != nil {
		return fmt.Errorf("%w: a move's signer is root or a person key", ErrInvalid)
	}
	if !current[m.Signer] {
		return fmt.Errorf("%w: the move's signer is not a current administrator", ErrInvalid)
	}
	return VerifySSHSIG(key, m.Message(), m.Signature)
}
