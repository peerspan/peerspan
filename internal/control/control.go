// Package control is the local control plane. It owns capsule records and
// asks a runtime to start or stop the process behind each one.
// Human-note: this local control plane is OK to start with, but we want to build this into a real service in the future.
package control

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/runtime"
	"github.com/Cerebral-Systems/capsule/internal/store"
)

// CreateRequest is the user input for a new capsule.
type CreateRequest struct {
	Repo         string   `json:"repo,omitempty"`
	Task         string   `json:"task"`
	Owner        string   `json:"owner,omitempty"`
	Backend      string   `json:"backend,omitempty"`
	Image        string   `json:"image,omitempty"`
	Setup        string   `json:"setup,omitempty"`
	NetworkMode  string   `json:"network_mode,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Secrets      []string `json:"secrets,omitempty"`
}

// Service wires the record store to a runtime.
type Service struct {
	Store   store.Store
	Runtime runtime.Runtime
	Now     func() time.Time
}

// Create records a capsule and starts its runtime.
func (s Service) Create(ctx context.Context, req CreateRequest) (capsule.Capsule, error) {
	task := strings.TrimSpace(req.Task)
	if task == "" {
		return capsule.Capsule{}, fmt.Errorf("create requires --task")
	}
	backend := strings.TrimSpace(req.Backend)
	if backend == "" {
		backend = capsule.RuntimeLocal
	}
	if backend != capsule.RuntimeLocal {
		return capsule.Capsule{}, fmt.Errorf("unsupported runtime %q", backend)
	}
	if s.Runtime == nil {
		return capsule.Capsule{}, fmt.Errorf("no runtime configured")
	}

	now := s.now()
	id, err := capsule.NewID(now)
	if err != nil {
		return capsule.Capsule{}, err
	}
	network := strings.TrimSpace(req.NetworkMode)
	if network == "" {
		network = "local"
	}
	c := capsule.Capsule{
		ID:     id,
		Repo:   strings.TrimSpace(req.Repo),
		Task:   task,
		Owner:  strings.TrimSpace(req.Owner),
		Status: capsule.StatusCreated,
		Runtime: capsule.Runtime{
			Backend: backend,
			Image:   strings.TrimSpace(req.Image),
			Setup:   strings.TrimSpace(req.Setup),
		},
		Network: capsule.Network{
			Mode: network,
			Name: id + ".capsule.local",
		},
		Authority: capsule.Authority{
			Capabilities: req.Capabilities,
			Secrets:      req.Secrets,
		},
		Audit: []capsule.AuditEvent{{
			At:      now,
			Type:    "capsule.created",
			Message: "capsule record created",
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.Store.Save(c); err != nil {
		return capsule.Capsule{}, err
	}

	handle, err := s.Runtime.Start(ctx, runtime.Spec{
		ID:    c.ID,
		Root:  filepath.Join(s.Store.Dir, c.ID),
		Repo:  c.Repo,
		Setup: c.Runtime.Setup,
	})
	if err != nil {
		failed := s.now()
		c.Status = capsule.StatusFailed
		c.UpdatedAt = failed
		c.Audit = append(c.Audit, capsule.AuditEvent{
			At:      failed,
			Type:    "runtime.failed",
			Message: clip(err.Error()),
		})
		_ = s.Store.Save(c)
		return c, fmt.Errorf("start capsule %s: %w", c.ID, err)
	}

	started := s.now()
	c.Status = capsule.StatusRunning
	c.UpdatedAt = started
	c.Runtime.PID = handle.PID
	c.Runtime.WorkDir = handle.WorkDir
	c.Runtime.LogPath = handle.LogPath
	c.Audit = append(c.Audit, capsule.AuditEvent{
		At:      started,
		Type:    "runtime.started",
		Message: fmt.Sprintf("local process started (pid %d)", handle.PID),
	})
	if err := s.Store.Save(c); err != nil {
		_ = s.Runtime.Stop(handle.PID)
		return c, err
	}
	return c, nil
}

// List returns capsule records, updating any whose process has exited.
func (s Service) List() ([]capsule.Capsule, error) {
	capsules, err := s.Store.List()
	if err != nil {
		return nil, err
	}
	for i, c := range capsules {
		refreshed, err := s.refresh(c)
		if err != nil {
			return nil, err
		}
		capsules[i] = refreshed
	}
	return capsules, nil
}

// Inspect returns one capsule record, updating it if its process has exited.
func (s Service) Inspect(id string) (capsule.Capsule, error) {
	c, err := s.Store.Load(id)
	if err != nil {
		return capsule.Capsule{}, err
	}
	return s.refresh(c)
}

// Exec runs argv in a running capsule and appends a command record.
// The returned string is the combined output. A non-zero exit is an error
// after the record has been saved.
func (s Service) Exec(ctx context.Context, id string, argv []string) (string, error) {
	if len(argv) == 0 {
		return "", fmt.Errorf("exec requires a command")
	}
	if s.Runtime == nil {
		return "", fmt.Errorf("no runtime configured")
	}
	c, err := s.Inspect(id)
	if err != nil {
		return "", err
	}
	if c.Status != capsule.StatusRunning {
		return "", fmt.Errorf("capsule %s is %s", c.ID, c.Status)
	}
	if err := s.authorizeExec(c, argv); err != nil {
		return "", err
	}

	logPath := filepath.Join(s.Store.Dir, c.ID, "commands", fmt.Sprintf("%04d.log", len(c.Commands)+1))
	result, runErr := s.Runtime.Exec(ctx, runtime.ExecSpec{
		WorkDir: c.Runtime.WorkDir,
		Argv:    argv,
		LogPath: logPath,
	})
	code := result.ExitCode
	if runErr != nil && code == 0 {
		code = -1
	}

	now := s.now()
	c.UpdatedAt = now
	c.Commands = append(c.Commands, capsule.Command{
		At:       now,
		Argv:     argv,
		ExitCode: code,
		LogPath:  logPath,
	})
	c.Audit = append(c.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "command.exited",
		Message: clip(fmt.Sprintf("%s exited %d", strings.Join(argv, " "), code)),
	})
	if err := s.Store.Save(c); err != nil {
		return result.Output, err
	}
	if runErr != nil {
		return result.Output, runErr
	}
	if code != 0 {
		return result.Output, fmt.Errorf("exit status %d", code)
	}
	return result.Output, nil
}

// Destroy stops the runtime and marks the capsule destroyed.
func (s Service) Destroy(id string) (capsule.Capsule, error) {
	c, err := s.Store.Load(id)
	if err != nil {
		return capsule.Capsule{}, err
	}
	if c.Status == capsule.StatusDestroyed {
		return c, nil
	}
	if c.Runtime.PID > 0 && s.Runtime != nil {
		if err := s.Runtime.Stop(c.Runtime.PID); err != nil {
			return c, err
		}
	}
	now := s.now()
	c.Status = capsule.StatusDestroyed
	c.UpdatedAt = now
	c.Audit = append(c.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "capsule.destroyed",
		Message: "capsule destroyed",
	})
	if err := s.Store.Save(c); err != nil {
		return c, err
	}
	return c, nil
}

func (s Service) refresh(c capsule.Capsule) (capsule.Capsule, error) {
	if c.Status != capsule.StatusRunning || c.Runtime.PID <= 0 || s.Runtime == nil {
		return c, nil
	}
	if s.Runtime.Alive(c.Runtime.PID) {
		return c, nil
	}
	now := s.now()
	c.Status = capsule.StatusExited
	c.UpdatedAt = now
	c.Audit = append(c.Audit, capsule.AuditEvent{
		At:      now,
		Type:    "runtime.exited",
		Message: "local process is no longer running",
	})
	if err := s.Store.Save(c); err != nil {
		return c, err
	}
	return c, nil
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func clip(msg string) string {
	msg = strings.TrimSpace(msg)
	const max = 500
	if len(msg) <= max {
		return msg
	}
	return msg[:max] + "..."
}
