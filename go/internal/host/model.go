// Package host implements the host daemon, private local administration, and
// an opt-in authenticated peer message interface. It has no coordination dependency.
package host

import (
	"errors"
	"time"
)

var (
	ErrInvalid   = errors.New("invalid request")
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
	ErrConflict  = errors.New("conflict")
)

// Identity identifies this installation. The private key stays in the local store.
// The peer transport proves possession of this key. Network membership and
// member/agent identity verification remain separate concerns.
type Identity struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

// Agent is a durable participant, independent of its running sessions. Owner is
// local descriptive metadata, not an authenticated network member identity.
type Agent struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Owner        string    `json:"owner"`
	Capabilities []string  `json:"capabilities"`
	CreatedAt    time.Time `json:"created_at"`
}

type RegisterAgent struct {
	Name         string   `json:"name"`
	Owner        string   `json:"owner"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// Session is a registry attachment, not proof that an agent integration can
// accept incoming work. This initial service does not operate the agent process.
type Session struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Integration string    `json:"integration"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const (
	SessionAttached = "attached"
	SessionDetached = "detached"
)

type AttachSession struct {
	AgentID     string `json:"agent_id"`
	Integration string `json:"integration"`
}

// Event is an append-only local activity record. Sequence can be used as a
// cursor when reading activity; it does not imply ordering across hosts.
type Event struct {
	Sequence  int64     `json:"sequence"`
	Kind      string    `json:"kind"`
	SubjectID string    `json:"subject_id"`
	CreatedAt time.Time `json:"created_at"`
}
