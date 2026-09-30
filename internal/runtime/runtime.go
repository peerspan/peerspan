// Package runtime is the boundary between the control plane and a capsule execution backend.
package runtime

import "context"

// Spec is what the control plane hands a backend when a capsule should start.
type Spec struct {
	ID    string
	Root  string // capsule state directory, parent of the workspace
	Repo  string // git URL or local git path; empty means an empty workspace
	Setup string // shell command run in the workspace before the process starts
}

// ExecSpec is one command to run inside an already started capsule.
type ExecSpec struct {
	WorkDir string
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

// Runtime starts and stops the process that belongs to one capsule.
type Runtime interface {
	Start(ctx context.Context, spec Spec) (Handle, error)
	Stop(pid int) error
	Alive(pid int) bool
	Exec(ctx context.Context, spec ExecSpec) (ExecResult, error)
}
