package local

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
)

// enterScript runs as pid 1 in the new namespaces. It builds a private root
// that can see the system binaries and this capsule's workspace, then sleeps.
const enterScript = `
set -eu
rootfs=$1
work=$2
mount=/usr/bin/mount
pivot=/usr/sbin/pivot_root
"$mount" --make-rprivate /
mkdir -p "$rootfs"
"$mount" -t tmpfs -o mode=0755 tmpfs "$rootfs"
mkdir -p "$rootfs/workspace" "$rootfs/proc" "$rootfs/tmp" "$rootfs/dev" "$rootfs/etc" "$rootfs/old"
for d in bin sbin lib lib64 usr; do
  if [ -d "/$d" ]; then
    mkdir -p "$rootfs/$d"
    "$mount" --bind "/$d" "$rootfs/$d"
    "$mount" -o remount,bind,ro "$rootfs/$d"
  fi
done
printf 'root:x:0:0:root:/workspace:/bin/sh\n' > "$rootfs/etc/passwd"
printf 'root:x:0:\n' > "$rootfs/etc/group"
"$mount" --bind "$work" "$rootfs/workspace"
"$mount" -t proc proc "$rootfs/proc"
"$mount" -t tmpfs -o mode=1777 tmpfs "$rootfs/tmp"
for dev in null zero urandom random tty; do
  if [ -e "/dev/$dev" ]; then
    touch "$rootfs/dev/$dev"
    "$mount" --bind "/dev/$dev" "$rootfs/dev/$dev"
  fi
done
if [ -x /usr/sbin/ip ]; then
  /usr/sbin/ip link set lo up
fi
cd "$rootfs"
"$pivot" . old
cd /
umount -l /old
rmdir /old 2>/dev/null || true
cd /workspace
exec /bin/sleep infinity
`

func startWorkcell(root, workDir, logPath string) (runtime.Handle, error) {
	for _, tool := range []string{"/bin/sh", "/usr/bin/mount", "/usr/sbin/pivot_root", "/bin/sleep"} {
		if _, err := os.Stat(tool); err != nil {
			return runtime.Handle{}, fmt.Errorf("workcell requires %s", tool)
		}
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return runtime.Handle{}, err
	}
	defer logFile.Close()

	rootfs := filepath.Join(root, "rootfs")
	cmd := exec.Command("/bin/sh", "-c", enterScript, "sh", rootfs, workDir)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Setpgid:    true,
	}
	if err := cmd.Start(); err != nil {
		return runtime.Handle{}, err
	}
	go func() { _ = cmd.Wait() }()

	if err := waitReady(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		data, _ := os.ReadFile(logPath)
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			return runtime.Handle{}, err
		}
		return runtime.Handle{}, fmt.Errorf("%w: %s", err, msg)
	}
	return runtime.Handle{PID: cmd.Process.Pid, WorkDir: workDir, LogPath: logPath}, nil
}

func waitReady(pid int) error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return fmt.Errorf("workcell exited during start")
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d/root/workspace", pid)); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("workcell did not become ready")
}
