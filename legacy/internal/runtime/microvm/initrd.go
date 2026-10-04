package microvm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const initScript = `#!/bin/sh
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
exec /agent
`

var (
	initrdOnce sync.Once
	initrdPath string
	initrdErr  error
)

func guestInitrd() (string, error) {
	initrdOnce.Do(func() {
		dir, err := os.MkdirTemp("", "capsule-initrd-")
		if err != nil {
			initrdErr = err
			return
		}
		initrdPath = filepath.Join(dir, "initrd")
		initrdErr = buildInitrd(initrdPath)
	})
	return initrdPath, initrdErr
}

func buildInitrd(archive string) error {
	root := filepath.Join(filepath.Dir(archive), "root")
	for _, dir := range []string{"bin", "proc", "sys", "dev", "workspace", "run", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "init"), []byte(initScript), 0o755); err != nil {
		return err
	}
	busybox := "/usr/bin/busybox"
	guestBusybox := filepath.Join(root, "bin", "busybox")
	if err := copyFile(busybox, guestBusybox); err != nil {
		return fmt.Errorf("busybox: %w", err)
	}
	if err := os.Chmod(guestBusybox, 0o755); err != nil {
		return err
	}
	// Symlinks must be relative. busybox --install points them at the host path.
	listed, err := exec.Command(busybox, "--list").Output()
	if err != nil {
		return fmt.Errorf("busybox --list: %w", err)
	}
	for _, name := range strings.Fields(string(listed)) {
		if name == "busybox" {
			continue
		}
		if err := os.Symlink("busybox", filepath.Join(root, "bin", name)); err != nil {
			return err
		}
	}
	agent := filepath.Join(filepath.Dir(archive), "agent")
	if err := buildAgent(agent); err != nil {
		return err
	}
	if err := os.Rename(agent, filepath.Join(root, "agent")); err != nil {
		return err
	}
	out, err := os.Create(archive)
	if err != nil {
		return err
	}
	defer out.Close()
	find := exec.Command("find", ".", "-print0")
	find.Dir = root
	cpio := exec.Command("cpio", "--null", "-o", "-H", "newc")
	cpio.Dir = root
	cpio.Stdout = out
	pipe, err := find.StdoutPipe()
	if err != nil {
		return err
	}
	cpio.Stdin = pipe
	if err := cpio.Start(); err != nil {
		return err
	}
	if err := find.Run(); err != nil {
		return err
	}
	if err := cpio.Wait(); err != nil {
		return fmt.Errorf("cpio: %w", err)
	}
	return nil
}

func buildAgent(out string) error {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("microvm: cannot locate guest source")
	}
	cmd := exec.Command("go", "build", "-tags", "guest", "-o", out, "./init")
	cmd.Dir = filepath.Dir(file)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	msg, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build guest agent: %w: %s", err, msg)
	}
	return nil
}
