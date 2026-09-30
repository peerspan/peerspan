// Package local is the runtime. One capsule is one workcell: a process in its
// own mount, pid, and network namespaces, with the workspace mounted at /workspace.
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

// Runtime starts a workcell whose workspace is a directory on the host.
// A git repo, when set, is cloned into that workspace before the workcell starts.
type Runtime struct{}

// Start prepares the workspace and starts the workcell.
func (Runtime) Start(ctx context.Context, spec runtime.Spec) (runtime.Handle, error) {
	if os.Geteuid() != 0 {
		return runtime.Handle{}, fmt.Errorf("workcell namespaces require root")
	}
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
	handle, err := startWorkcell(spec.Root, workDir, logPath)
	if err != nil {
		return runtime.Handle{}, err
	}
	if spec.Setup != "" {
		result, execErr := (Runtime{}).Exec(ctx, runtime.ExecSpec{
			PID:     handle.PID,
			Argv:    []string{"sh", "-c", spec.Setup},
			LogPath: filepath.Join(spec.Root, "setup.log"),
		})
		if execErr != nil || result.ExitCode != 0 {
			_ = (Runtime{}).Stop(handle.PID)
			if execErr != nil {
				return runtime.Handle{}, fmt.Errorf("setup: %w", execErr)
			}
			msg := strings.TrimSpace(result.Output)
			if msg == "" {
				return runtime.Handle{}, fmt.Errorf("setup: exit status %d", result.ExitCode)
			}
			return runtime.Handle{}, fmt.Errorf("setup: exit status %d: %s", result.ExitCode, msg)
		}
	}
	return handle, nil
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

// Exec runs argv inside the workcell and writes combined output to the log file.
// A non-zero exit is returned in ExecResult. An error means the command did not start.
func (Runtime) Exec(ctx context.Context, spec runtime.ExecSpec) (runtime.ExecResult, error) {
	if len(spec.Argv) == 0 {
		return runtime.ExecResult{}, fmt.Errorf("exec requires a command")
	}
	if spec.PID <= 0 {
		return runtime.ExecResult{}, fmt.Errorf("exec requires a workcell")
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return runtime.ExecResult{}, fmt.Errorf("nsenter is required to enter a workcell")
	}
	if err := os.MkdirAll(filepath.Dir(spec.LogPath), 0o755); err != nil {
		return runtime.ExecResult{}, err
	}
	logFile, err := os.OpenFile(spec.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return runtime.ExecResult{}, err
	}
	defer logFile.Close()

	args := []string{"-t", fmt.Sprint(spec.PID), "-m", "-p", "-n", "-u", "-i", "--", "sh", "-c", `cd /workspace && exec "$@"`, "sh"}
	args = append(args, spec.Argv...)
	cmd := exec.CommandContext(ctx, nsenter, args...)
	cmd.Dir = "/"
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
