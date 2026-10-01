// Package microvm boots a Firecracker guest and runs commands inside it.
//
// The host is the machine that starts the guest. The guest is the microVM.
// The workspace is an ext4 disk mounted at /workspace. Commands cross a vsock
// to a guest agent. The workcell remains the default runtime.
package microvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
	"github.com/Cerebral-Systems/capsule/internal/runtime/microvm/protocol"
	"github.com/Cerebral-Systems/capsule/internal/secret"
)

const (
	defaultFirecracker = "/var/tmp/capsule-microvm/release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	defaultKernel      = "/var/tmp/capsule-microvm/vmlinux"
	vsockPort          = 52
	guestCID           = 3
)

// Runtime starts one Firecracker process per capsule.
type Runtime struct {
	Firecracker string
	Kernel      string

	mu     sync.Mutex
	guests map[int]*guest
}

var _ runtime.Runtime = (*Runtime)(nil)

type guest struct {
	mu      sync.Mutex
	pid     int
	vsock   string
	image   string
	secrets string
	workDir string
	serial  string
	log     string
	dir     string
	cmd     *exec.Cmd
}

// Available reports whether this host can boot a guest.
func (r *Runtime) Available() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("microvm requires root")
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return fmt.Errorf("/dev/kvm is not available")
	}
	fc, kernel, err := r.tools()
	if err != nil {
		return err
	}
	if _, err := os.Stat(fc); err != nil {
		return fmt.Errorf("firecracker binary: %w", err)
	}
	if _, err := os.Stat(kernel); err != nil {
		return fmt.Errorf("kernel: %w", err)
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		return fmt.Errorf("mkfs.ext4 is required")
	}
	if _, err := os.Stat("/usr/bin/busybox"); err != nil {
		return fmt.Errorf("busybox is required at /usr/bin/busybox")
	}
	return nil
}

// Start prepares the workspace disk and boots the guest.
func (r *Runtime) Start(ctx context.Context, spec runtime.Spec) (runtime.Handle, error) {
	if err := r.Available(); err != nil {
		return runtime.Handle{}, err
	}
	fc, kernel, err := r.tools()
	if err != nil {
		return runtime.Handle{}, err
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
	image := filepath.Join(spec.Root, "workspace.img")
	if err := writeWorkspaceImage(workDir, image); err != nil {
		return runtime.Handle{}, err
	}
	secretsImage, err := writeSecretsImage(spec.Root, spec.Secrets)
	if err != nil {
		return runtime.Handle{}, err
	}
	initrd, err := guestInitrd()
	if err != nil {
		return runtime.Handle{}, err
	}

	dir, err := os.MkdirTemp("", "capsule-microvm-")
	if err != nil {
		return runtime.Handle{}, err
	}
	g := &guest{
		vsock:   filepath.Join(dir, "vsock.sock"),
		image:   image,
		secrets: secretsImage,
		workDir: workDir,
		serial:  filepath.Join(spec.Root, "serial.log"),
		log:     filepath.Join(spec.Root, "process.log"),
		dir:     dir,
	}
	fail := func(err error) (runtime.Handle, error) {
		r.cleanup(g)
		msg := err.Error()
		if s := tail(g.serial); s != "" {
			msg += "\nserial:\n" + s
		}
		if s := tail(g.log); s != "" {
			msg += "\nfirecracker:\n" + s
		}
		return runtime.Handle{}, errors.New(msg)
	}
	if err := os.WriteFile(g.serial, nil, 0o600); err != nil {
		return fail(err)
	}
	logFile, err := os.Create(g.log)
	if err != nil {
		return fail(err)
	}
	sock := filepath.Join(dir, "api.sock")
	cmd := exec.Command(fc, "--api-sock", sock)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fail(err)
	}
	g.cmd = cmd
	g.pid = cmd.Process.Pid
	go func() { _ = cmd.Wait(); logFile.Close() }()

	if err := waitSock(ctx, sock); err != nil {
		return fail(fmt.Errorf("microvm: api socket: %w", err))
	}
	client := apiClient(sock)
	puts := []struct {
		path string
		body any
	}{
		{"/machine-config", map[string]any{"vcpu_count": 1, "mem_size_mib": 256}},
		{"/boot-source", map[string]any{
			"kernel_image_path": kernel,
			"initrd_path":       initrd,
			"boot_args":         "console=ttyS0 reboot=k panic=1 pci=off",
		}},
		{"/drives/workspace", map[string]any{
			"drive_id":       "workspace",
			"path_on_host":   image,
			"is_root_device": false,
			"is_read_only":   false,
		}},
	}
	if secretsImage != "" {
		puts = append(puts, struct {
			path string
			body any
		}{"/drives/secrets", map[string]any{
			"drive_id":       "secrets",
			"path_on_host":   secretsImage,
			"is_root_device": false,
			"is_read_only":   true,
		}})
	}
	puts = append(puts,
		struct {
			path string
			body any
		}{"/vsock", map[string]any{"guest_cid": guestCID, "uds_path": g.vsock}},
		struct {
			path string
			body any
		}{"/serial", map[string]any{"serial_out_path": g.serial}},
		struct {
			path string
			body any
		}{"/actions", map[string]any{"action_type": "InstanceStart"}},
	)
	for _, put := range puts {
		if err := apiPut(ctx, client, put.path, put.body); err != nil {
			return fail(err)
		}
	}
	if err := waitReady(ctx, g); err != nil {
		return fail(err)
	}
	r.mu.Lock()
	if r.guests == nil {
		r.guests = map[int]*guest{}
	}
	r.guests[g.pid] = g
	r.mu.Unlock()

	handle := runtime.Handle{PID: g.pid, WorkDir: workDir, LogPath: g.log}
	if spec.Setup != "" {
		result, execErr := r.Exec(ctx, runtime.ExecSpec{
			PID:         g.pid,
			WorkDir:     workDir,
			Argv:        []string{"sh", "-c", spec.Setup},
			LogPath:     filepath.Join(spec.Root, "setup.log"),
			SecretPaths: secretPaths(spec.Secrets),
		})
		if execErr != nil || result.ExitCode != 0 {
			_ = r.Stop(g.pid)
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

// Stop kills the Firecracker process for pid.
func (r *Runtime) Stop(pid int) error {
	if pid <= 0 {
		return nil
	}
	r.mu.Lock()
	g := r.guests[pid]
	delete(r.guests, pid)
	r.mu.Unlock()
	if g == nil {
		if !alive(pid) {
			return nil
		}
		return fmt.Errorf("microvm: pid %d is not a guest", pid)
	}
	r.cleanup(g)
	return nil
}

// Alive reports whether pid is a guest this runtime started and that process is still running.
func (r *Runtime) Alive(pid int) bool {
	r.mu.Lock()
	_, ok := r.guests[pid]
	r.mu.Unlock()
	return ok && alive(pid)
}

// Exec runs argv inside the guest and copies the workspace disk back to the host.
// A non-zero exit is returned in ExecResult. An error means the command did not finish.
func (r *Runtime) Exec(ctx context.Context, spec runtime.ExecSpec) (runtime.ExecResult, error) {
	if len(spec.Argv) == 0 {
		return runtime.ExecResult{}, fmt.Errorf("exec requires a command")
	}
	r.mu.Lock()
	g := r.guests[spec.PID]
	r.mu.Unlock()
	if g == nil {
		return runtime.ExecResult{}, fmt.Errorf("microvm: pid %d is not a guest", spec.PID)
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(spec.LogPath), 0o755); err != nil {
		return runtime.ExecResult{}, err
	}
	code, out, err := g.call(ctx, protocol.OpExec, spec.Argv)
	if err != nil {
		return runtime.ExecResult{}, err
	}
	values, err := readSecretValues(spec.SecretPaths)
	if err != nil {
		return runtime.ExecResult{}, err
	}
	output := secret.Redact(string(out), values)
	if err := os.WriteFile(spec.LogPath, []byte(output), 0o644); err != nil {
		return runtime.ExecResult{}, err
	}
	result := runtime.ExecResult{ExitCode: int(code), Output: output}
	if _, _, err := g.call(ctx, protocol.OpUnmount, nil); err != nil {
		return result, fmt.Errorf("unmount workspace: %w", err)
	}
	if err := publishWorkspace(g.image, g.workDir); err != nil {
		return result, err
	}
	if _, _, err := g.call(ctx, protocol.OpMount, nil); err != nil {
		return result, fmt.Errorf("mount workspace: %w", err)
	}
	return result, nil
}

// Connect reports that a microVM cannot join a session link yet.
func (*Runtime) Connect(context.Context, string, string, []runtime.Peer) ([]runtime.Address, error) {
	return nil, fmt.Errorf("microvm: session link is not implemented")
}

// Disconnect has no session link to remove.
func (*Runtime) Disconnect(context.Context, string, string, []runtime.Peer) error {
	return nil
}

func (r *Runtime) tools() (string, string, error) {
	fc := firstSet(r.Firecracker, os.Getenv("CAPSULE_FIRECRACKER"), defaultFirecracker)
	kernel := firstSet(r.Kernel, os.Getenv("CAPSULE_KERNEL"), defaultKernel)
	if fc == "" || kernel == "" {
		return "", "", fmt.Errorf("microvm: set CAPSULE_FIRECRACKER and CAPSULE_KERNEL")
	}
	return fc, kernel, nil
}

func (r *Runtime) cleanup(g *guest) {
	if g == nil {
		return
	}
	if g.cmd != nil && g.cmd.Process != nil {
		_ = g.cmd.Process.Kill()
	}
	if g.dir != "" {
		_ = os.RemoveAll(g.dir)
	}
	if g.secrets != "" {
		_ = os.Remove(g.secrets)
	}
}

func (g *guest) call(ctx context.Context, op byte, argv []string) (int32, []byte, error) {
	conn, err := dialVsock(ctx, g.vsock, vsockPort)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := protocol.WriteRequest(conn, op, argv); err != nil {
		return 0, nil, err
	}
	code, out, err := protocol.ReadResult(conn)
	if err != nil {
		return 0, nil, err
	}
	if op != protocol.OpExec && code != 0 {
		return code, out, fmt.Errorf("%s", out)
	}
	return code, out, nil
}

func dialVsock(ctx context.Context, uds string, port int) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", uds)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		conn.Close()
		return nil, err
	}
	line, err := readLine(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("microvm: vsock handshake: %w", err)
	}
	if !strings.HasPrefix(line, "OK ") {
		conn.Close()
		return nil, fmt.Errorf("microvm: vsock handshake: %s", strings.TrimSpace(line))
	}
	return conn, nil
}

func readLine(r io.Reader) (string, error) {
	var buf bytes.Buffer
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		buf.WriteByte(b[0])
		if b[0] == '\n' {
			return buf.String(), nil
		}
		if buf.Len() > 64 {
			return "", fmt.Errorf("line too long")
		}
	}
}

func waitReady(ctx context.Context, g *guest) error {
	deadline := time.Now().Add(20 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	var last error
	for time.Now().Before(deadline) {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		conn, err := dialVsock(probe, g.vsock, vsockPort)
		cancel()
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
		if !alive(g.pid) {
			return fmt.Errorf("microvm: firecracker exited before the guest was ready")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if last == nil {
		last = fmt.Errorf("timed out")
	}
	return fmt.Errorf("microvm: guest was not ready: %w", last)
}

func waitSock(ctx context.Context, sock string) error {
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not ready")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func apiClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
}

func apiPut(ctx context.Context, client *http.Client, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("microvm: %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return fmt.Errorf("microvm: %s: %s: %s", path, resp.Status, strings.TrimSpace(buf.String()))
	}
	return nil
}

func secretPaths(secrets []runtime.Secret) []string {
	paths := make([]string, len(secrets))
	for i, secret := range secrets {
		paths[i] = secret.HostPath
	}
	return paths
}

func readSecretValues(paths []string) ([]string, error) {
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		values = append(values, string(body))
	}
	return values, nil
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

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

func tail(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	if len(b) > 2000 {
		b = b[len(b)-2000:]
	}
	return string(b)
}

func firstSet(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
