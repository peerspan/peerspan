// Package session is the peering record shared by the capsules in one session.
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

	RoleOpened = "opened"
	RoleJoined = "joined"
)

// Session is one temporary peering. One capsule opens it. Any number of capsules join it.
type Session struct {
	ID         string               `json:"id"`
	Task       string               `json:"task"`
	Status     string               `json:"status"`
	Members    []Member             `json:"members,omitempty"`
	ExpiresAt  *time.Time           `json:"expires_at,omitempty"`
	Transcript []Entry              `json:"transcript,omitempty"`
	Artifacts  []Artifact           `json:"artifacts,omitempty"`
	Approvals  []Approval           `json:"approvals,omitempty"`
	Link       *Link                `json:"link,omitempty"`
	Audit      []capsule.AuditEvent `json:"audit"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
}

// Member is one capsule in the session. Role is opened or joined.
// Allow and AllowExec belong to that capsule alone.
type Member struct {
	CapsuleID string   `json:"capsule_id"`
	Role      string   `json:"role"`
	Allow     []string `json:"allow,omitempty"`
	AllowExec []string `json:"allow_exec,omitempty"`
}

// Member returns the capsule's membership, if it is in the session.
func (s Session) Member(capsuleID string) (Member, bool) {
	for _, member := range s.Members {
		if member.CapsuleID == capsuleID {
			return member, true
		}
	}
	return Member{}, false
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
	Reachability *Link                `json:"reachability,omitempty"`
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

// Link is the session-scoped path among the members.
// The addresses stay on the record after the session ends so the evidence bundle can show what was reachable.
type Link struct {
	Endpoints []Endpoint `json:"endpoints"`
}

// Endpoint is one member's name and address on the session link.
type Endpoint struct {
	CapsuleID string `json:"capsule_id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
}

// Executed is one command run in a participant capsule during the session.
// Paths are workspace files that changed. The patch itself stays on the host.
type Executed struct {
	At        time.Time `json:"at"`
	CapsuleID string    `json:"capsule_id"`
	Argv      []string  `json:"argv"`
	ExitCode  int       `json:"exit_code"`
	Paths     []string  `json:"paths,omitempty"`
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
