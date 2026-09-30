// Package session is the peering record shared by two capsules.
package session

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
)

const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"

	ApprovalPending = "pending"
	ApprovalGranted = "granted"
)

// Session is one temporary peering between two capsules.
type Session struct {
	ID           string               `json:"id"`
	Task         string               `json:"task"`
	Status       string               `json:"status"`
	HostCapsule  string               `json:"host_capsule"`
	GuestCapsule string               `json:"guest_capsule,omitempty"`
	HostAllow    []string             `json:"host_allow,omitempty"`
	GuestAllow   []string             `json:"guest_allow,omitempty"`
	HostExec     []string             `json:"host_exec,omitempty"`
	GuestExec    []string             `json:"guest_exec,omitempty"`
	ExpiresAt    *time.Time           `json:"expires_at,omitempty"`
	Transcript   []Entry              `json:"transcript,omitempty"`
	Artifacts    []Artifact           `json:"artifacts,omitempty"`
	Approvals    []Approval           `json:"approvals,omitempty"`
	Audit        []capsule.AuditEvent `json:"audit"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
}

// Entry is one message in the session transcript.
type Entry struct {
	At        time.Time `json:"at"`
	CapsuleID string    `json:"capsule_id"`
	Text      string    `json:"text"`
}

// Artifact is one file copied into the session from a capsule workspace.
type Artifact struct {
	At        time.Time `json:"at"`
	CapsuleID string    `json:"capsule_id"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	SavedAs   string    `json:"saved_as"`
}

// Evidence is the record session export writes when a peering session is reviewed.
type Evidence struct {
	ID           string               `json:"id"`
	Task         string               `json:"task"`
	Status       string               `json:"status"`
	CreatedAt    time.Time            `json:"created_at"`
	EndedAt      *time.Time           `json:"ended_at,omitempty"`
	Participants []Participant        `json:"participants"`
	Transcript   []Entry              `json:"transcript,omitempty"`
	Artifacts    []Artifact           `json:"artifacts,omitempty"`
	Approvals    []Approval           `json:"approvals,omitempty"`
	Commands     []Executed           `json:"commands,omitempty"`
	Audit        []capsule.AuditEvent `json:"audit"`
}

// Participant is one capsule in the evidence bundle.
// Role is "opened" for the capsule that created the session and "joined" for the capsule that accepted it.
type Participant struct {
	CapsuleID    string   `json:"capsule_id"`
	Owner        string   `json:"owner,omitempty"`
	Role         string   `json:"role"`
	Capabilities []string `json:"capabilities,omitempty"`
	Allow        []string `json:"allow,omitempty"`
	AllowExec    []string `json:"allow_exec,omitempty"`
}

// Executed is one command run in a participant capsule during the session.
type Executed struct {
	At        time.Time `json:"at"`
	CapsuleID string    `json:"capsule_id"`
	Argv      []string  `json:"argv"`
	ExitCode  int       `json:"exit_code"`
}

// Approval is a human decision recorded against one session action.
type Approval struct {
	At        time.Time `json:"at"`
	CapsuleID string    `json:"capsule_id"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
}

// NewID returns a session id that is unique enough for local use.
func NewID(now time.Time) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("ses-%s-%x", now.UTC().Format("20060102-150405"), b), nil
}
