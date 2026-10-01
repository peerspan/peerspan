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

// Peer is one capsule on a session link.
// A local guest has a PID. A guest on another machine has an Underlay address instead.
type Peer struct {
	PID      int
	Name     string // recorded capsule name, such as <id>.capsule.local
	Underlay string // machine address, set only when the guest is not on this machine
}

// Address is one capsule's name and address on the session link.
type Address struct {
	Name string
	IP   string
}

// Runtime starts and stops the process that belongs to one capsule.
type Runtime interface {
	Start(ctx context.Context, spec Spec) (Handle, error)
	Stop(pid int) error
	Alive(pid int) bool
	Exec(ctx context.Context, spec ExecSpec) (ExecResult, error)
	// Connect attaches every peer to the session link. Peers already on the link stay.
	// Every peer can reach every other peer by its recorded name.
	// localUnderlay is this machine's address. It is used when a peer is on another machine.
	// The session subnet is not given an address on the host. The underlay is the only path between machines, and it exists for the life of the session.
	Connect(ctx context.Context, sessionID, localUnderlay string, peers []Peer) ([]Address, error)
	// Disconnect removes this machine's side of the session link. It succeeds when the link is already gone.
	// localUnderlay matches the address passed to Connect.
	Disconnect(ctx context.Context, sessionID, localUnderlay string, peers []Peer) error
}
