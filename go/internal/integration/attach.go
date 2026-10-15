package integration

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Attach profiles are session setup directories at
// $XDG_CONFIG_HOME/peerspan/sessions/HOST_ID/AGENT_NAME that record the
// project they serve as workspace. A profile being replaced is kept at
// .AGENT_NAME.old until its replacement is set up; names never start with a
// dot.

// SessionsDir is $XDG_CONFIG_HOME/peerspan/sessions, by default under
// ~/.config.
func SessionsDir() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "peerspan", "sessions"), nil
}

// ReadProfile loads and validates the profile in a setup directory.
func ReadProfile(dir string) (*Profile, error) {
	return loadProfile(Options{Directory: dir})
}

// HostProfiles lists the valid attach profiles of one host.
func HostProfiles(host string) ([]*Profile, error) {
	root, err := SessionsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(root, host))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Profile
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p, err := ReadProfile(filepath.Join(root, host, e.Name()))
		if err == nil && p.Workspace != "" && p.HostID == host {
			out = append(out, p)
		}
	}
	return out, nil
}

// WorkspaceProfile finds the attach profile of state whose recorded
// workspace is the given directory, for session start and doctor.
func WorkspaceProfile(state, workspace string) (string, error) {
	found, err := WorkspaceProfiles(state, workspace)
	if err != nil {
		return "", err
	}
	switch len(found) {
	case 0:
		return "", errors.New("no attach profile for this directory; run peerspan attach HARNESS here, or give --directory")
	case 1:
		return found[0], nil
	}
	return "", errors.New("several attach profiles record this directory; give --directory: " + strings.Join(found, ", "))
}

// WorkspaceProfiles lists, sorted, the attach profiles of state whose
// recorded workspace is the given directory; an empty state matches the
// profiles of every state.
func WorkspaceProfiles(state, workspace string) ([]string, error) {
	root, err := SessionsDir()
	if err != nil {
		return nil, err
	}
	if workspace, err = filepath.EvalSymlinks(workspace); err != nil {
		return nil, err
	}
	if state != "" {
		if state, err = filepath.Abs(state); err != nil {
			return nil, err
		}
	}
	matches, _ := filepath.Glob(filepath.Join(root, "*", "*", "profile.json"))
	var found []string
	for _, path := range matches {
		dir := filepath.Dir(path)
		if strings.HasPrefix(filepath.Base(dir), ".") {
			continue
		}
		p, err := ReadProfile(dir)
		if err == nil && p.Workspace == workspace && (state == "" || p.State == state) {
			found = append(found, dir)
		}
	}
	sort.Strings(found)
	return found, nil
}
