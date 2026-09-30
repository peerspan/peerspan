// Package capsule is the control-plane record for an agent capsule.
package capsule

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"
)

const (
	StatusCreated   = "created"
	StatusRunning   = "running"
	StatusExited    = "exited"
	StatusFailed    = "failed"
	StatusDestroyed = "destroyed"

	RuntimeLocal = "local"
)

// Capsule is the record the control plane keeps for one agent task.
// Human-note: this is written to memory currently via instantiations of this struct
// eventually we want to persist this to a database
type Capsule struct {
	ID           string       `json:"id"`
	Repo         string       `json:"repo,omitempty"`
	Task         string       `json:"task"`
	Owner        string       `json:"owner"`
	Status       string       `json:"status"`
	Runtime      Runtime      `json:"runtime"`
	Network      Network      `json:"network"`
	Authority    Authority    `json:"authority"`
	Audit        []AuditEvent `json:"audit"`
	Commands     []Command    `json:"commands,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	DestroyAfter *time.Time   `json:"destroy_after,omitempty"`
}

// Runtime describes where the capsule executes.
type Runtime struct {
	Backend string `json:"backend"`
	Image   string `json:"image,omitempty"`
	Setup   string `json:"setup,omitempty"`
	PID     int    `json:"pid,omitempty"`
	WorkDir string `json:"work_dir,omitempty"`
	LogPath string `json:"log_path,omitempty"`
}

// Command is one process run inside a capsule workspace.
type Command struct {
	At       time.Time `json:"at"`
	Argv     []string  `json:"argv"`
	ExitCode int       `json:"exit_code"`
	LogPath  string    `json:"log_path"`
}

// Network describes how the capsule is reached.
type Network struct {
	Mode      string   `json:"mode"`
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints,omitempty"`
}

// Authority is the static allowlist attached to a capsule.
type Authority struct {
	Capabilities []string   `json:"capabilities,omitempty"`
	Secrets      []string   `json:"secrets,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// AuditEvent is one append-only lifecycle record.
type AuditEvent struct {
	At      time.Time `json:"at"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
}

// NewID returns a capsule id that is unique enough for local use.
func NewID(now time.Time) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("cap-%s-%x", now.UTC().Format("20060102-150405"), b), nil
}

// ValidID reports whether id can be used as a single path segment.
func ValidID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	return !strings.ContainsAny(id, `/\`)
}
