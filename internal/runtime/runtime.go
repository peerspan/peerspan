// Package runtime is the boundary between the control plane and a capsule execution backend.
//
// The host is the machine that runs the control plane. The guest is the isolated
// environment that machine starts. Today the guest is a workcell. Later it is a microVM.
package runtime

import "context"

// Secret is one host file mounted read-only in the guest at /run/secrets/<Name>.
type Secret struct {
	Name     string
	HostPath string
}

// Spec is what the control plane hands a backend when a capsule should start.
type Spec struct {
	ID      string
	Root    string // capsule state directory, parent of the workspace
	Repo    string // git URL or local git path; empty means an empty workspace
	Setup   string // shell command run inside the workcell after it starts
	Secrets []Secret
}

// ExecSpec is one command to run inside an already started capsule.
type ExecSpec struct {
	PID         int    // workcell process to enter
	WorkDir     string // host path of the workspace
	Argv        []string
	LogPath     string
	SecretPaths []string // host files whose values are removed from captured output
}

// ExecResult is the captured outcome of one command.
type ExecResult struct {
	ExitCode int
	Output   string
}

// Handle identifies one guest as seen from the host.
type Handle struct {
	PID     int
	WorkDir string
	LogPath string
}

// Peer is one capsule side of a session link.
type Peer struct {
	PID  int
	Name string // recorded capsule name, such as <id>.capsule.local
}

// Link is the address pair assigned for one session.
// Opened is the capsule that created the session. Joined is the capsule that accepted it.
type Link struct {
	OpenedIP string
	JoinedIP string
}

// Runtime starts and stops the process that belongs to one capsule.
type Runtime interface {
	Start(ctx context.Context, spec Spec) (Handle, error)
	Stop(pid int) error
	Alive(pid int) bool
	Exec(ctx context.Context, spec ExecSpec) (ExecResult, error)
	// Connect lets the two workcells reach each other by their recorded names.
	Connect(ctx context.Context, sessionID string, opened, joined Peer) (Link, error)
	// Disconnect removes the session link. It succeeds when the link is already gone.
	Disconnect(ctx context.Context, sessionID string, openedPID, joinedPID int) error
}
