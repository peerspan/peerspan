package integration

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
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

// AttachmentState is the existing daemon state of an exact configured profile.
// Reading it neither renews a lease nor issues replacement authorization.
type AttachmentState struct {
	Adapter    host.Adapter
	Session    host.Session
	Connection host.Connection
}

// ValidateAttachment checks the private credential and the public identities
// before guided setup reuses a live or recoverable attachment.
func ValidateAttachment(ctx context.Context, p *Profile) (AttachmentState, error) {
	var out AttachmentState
	if p.Phase != "configured" {
		return out, errors.New("the attachment is not configured")
	}
	if err := sameHost(ctx, p); err != nil {
		return out, err
	}
	secret, err := readCredential(p)
	if err != nil {
		return out, err
	}
	if err = call(ctx, p, "GET", "/v1/adapters/"+url.PathEscape(p.AdapterID), nil, &out.Adapter); err != nil {
		return out, err
	}
	if err = call(ctx, p, "GET", "/v1/sessions/"+url.PathEscape(p.SessionID), nil, &out.Session); err != nil {
		return out, err
	}
	if err = call(ctx, p, "GET", "/v1/adapters/"+url.PathEscape(p.AdapterID)+"/connection", nil, &out.Connection); err != nil {
		return out, err
	}
	until, err := time.Parse(time.RFC3339Nano, out.Adapter.ExpiresAt)
	if err != nil || out.Adapter.RevokedAt != nil || !until.After(time.Now()) || out.Adapter.ID != p.AdapterID || out.Adapter.SessionID != p.SessionID || out.Session.ID != p.SessionID || out.Session.AgentID != p.AgentID || out.Session.Integration != p.Harness.ID || out.Connection.AdapterID != p.AdapterID || out.Connection.SessionID != p.SessionID {
		return out, errors.New("the existing attachment authorization or identity requires repair")
	}
	matched, err := verify(ctx, p, secret.Token)
	if err != nil {
		return out, err
	}
	if !matched {
		return out, errors.New("credential file must match the existing attachment; inspect session doctor")
	}
	return out, nil
}

// ValidateAttachmentManifest rejects a different explicitly selected provider
// before guided setup changes service, trust or enrollment state.
func ValidateAttachmentManifest(p *Profile, root, runner string) error {
	if root == "" && runner == "" {
		return nil
	}
	selected, err := loadManifest(root, p.Harness.ID, runner)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(selected, p.Harness) {
		return errors.New("the requested integration manifest or runner differs from this project's attachment")
	}
	return nil
}
