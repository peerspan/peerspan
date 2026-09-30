// Package local is the v0 runtime. One capsule is one local process whose
// working directory is the capsule workspace.
package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
)

// Runtime starts a sleep process in a per-capsule workspace.
// A git repo, when set, is cloned into that workspace first.
type Runtime struct{}

// Start prepares the workspace and starts the capsule process.
func (Runtime) Start(ctx context.Context, spec runtime.Spec) (runtime.Handle, error) {
	if err := os.MkdirAll(spec.Root, 0o755); err != nil {
		return runtime.Handle{}, err
	}
	workDir := filepath.Join(spec.Root, "workspace")
	if spec.Repo != "" {
		if err := clone(ctx, spec.Repo, workDir); err != nil {
			return runtime.Handle{}, err
		}
	} else if err := os.MkdirAll(workDir, 0o755); err != nil {
		return runtime.Handle{}, err
	}

	logPath := filepath.Join(spec.Root, "process.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return runtime.Handle{}, err
	}
	defer logFile.Close()

	if spec.Setup != "" {
		setup := exec.CommandContext(ctx, "sh", "-c", spec.Setup)
		setup.Dir = workDir
		setup.Stdout = logFile
		setup.Stderr = logFile
		if err := setup.Run(); err != nil {
			return runtime.Handle{}, fmt.Errorf("setup: %w", err)
		}
	}

	cmd := exec.Command("sleep", "infinity")
	cmd.Dir = workDir
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return runtime.Handle{}, err
	}
	go func() { _ = cmd.Wait() }()

	return runtime.Handle{PID: cmd.Process.Pid, WorkDir: workDir, LogPath: logPath}, nil
}

// Stop signals the capsule process group and waits until it is gone.
func (Runtime) Stop(pid int) error {
	if pid <= 0 {
		return nil
	}
	if err := signal(pid, syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := signal(pid, syscall.SIGKILL); err != nil {
		return err
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("process %d did not exit", pid)
}

// Alive reports whether pid is still running.
func (Runtime) Alive(pid int) bool {
	return alive(pid)
}

// Exec runs argv in workDir and writes combined output to the log file.
// A non-zero exit is returned in ExecResult. An error means the command did not start.
func (Runtime) Exec(ctx context.Context, spec runtime.ExecSpec) (runtime.ExecResult, error) {
	if len(spec.Argv) == 0 {
		return runtime.ExecResult{}, fmt.Errorf("exec requires a command")
	}
	if err := os.MkdirAll(filepath.Dir(spec.LogPath), 0o755); err != nil {
		return runtime.ExecResult{}, err
	}
	logFile, err := os.OpenFile(spec.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return runtime.ExecResult{}, err
	}
	defer logFile.Close()

	cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	cmd.Dir = spec.WorkDir
	var buf bytes.Buffer
	cmd.Stdout = io.MultiWriter(logFile, &buf)
	cmd.Stderr = io.MultiWriter(logFile, &buf)
	err = cmd.Run()
	result := runtime.ExecResult{Output: buf.String()}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	result.ExitCode = -1
	return result, err
}

func clone(ctx context.Context, repo, workDir string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repo, workDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("clone repo: %w", err)
		}
		return fmt.Errorf("clone repo: %w: %s", err, msg)
	}
	return nil
}

func signal(pid int, sig syscall.Signal) error {
	err := syscall.Kill(-pid, sig)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	err = syscall.Kill(pid, sig)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}
