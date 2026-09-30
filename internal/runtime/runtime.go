// Package runtime is the boundary between the control plane and a capsule execution backend.
package runtime

import "context"

// Spec is what the control plane hands a backend when a capsule should start.
type Spec struct {
	ID    string
	Root  string // capsule state directory, parent of the workspace
	Repo  string // git URL or local git path; empty means an empty workspace
	Setup string // shell command run inside the workcell after it starts
}

// ExecSpec is one command to run inside an already started capsule.
type ExecSpec struct {
	PID     int    // workcell process to enter
	WorkDir string // host path of the workspace
	Argv    []string
	LogPath string
}

// ExecResult is the captured outcome of one command.
type ExecResult struct {
	ExitCode int
	Output   string
}

// Handle is what a backend returns after a capsule is running.
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
type Link struct {
	HostIP  string
	GuestIP string
}

// Runtime starts and stops the process that belongs to one capsule.
type Runtime interface {
	Start(ctx context.Context, spec Spec) (Handle, error)
	Stop(pid int) error
	Alive(pid int) bool
	Exec(ctx context.Context, spec ExecSpec) (ExecResult, error)
	// Connect lets the two workcells reach each other by their recorded names.
	Connect(ctx context.Context, sessionID string, host, guest Peer) (Link, error)
	// Disconnect removes the session link. It succeeds when the link is already gone.
	Disconnect(ctx context.Context, sessionID string, hostPID, guestPID int) error
}
