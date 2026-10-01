//go:build guest

// Command agent is pid 1 inside the Firecracker guest.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/runtime/microvm/protocol"
	"golang.org/x/sys/unix"
)

func main() {
	console, err := os.OpenFile("/dev/console", os.O_RDWR, 0)
	if err == nil {
		unix.Dup2(int(console.Fd()), 1)
		unix.Dup2(int(console.Fd()), 2)
	}
	if err := waitBlock("/dev/vda"); err != nil {
		fmt.Fprintf(os.Stderr, "workspace disk: %v\n", err)
		os.Exit(1)
	}
	if err := unix.Mount("/dev/vda", "/workspace", "ext4", 0, ""); err != nil {
		fmt.Fprintf(os.Stderr, "mount workspace: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stat("/dev/vdb"); err == nil {
		if err := os.MkdirAll("/run/secrets", 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "secrets dir: %v\n", err)
			os.Exit(1)
		}
		if err := unix.Mount("/dev/vdb", "/run/secrets", "ext4", unix.MS_RDONLY, ""); err != nil {
			fmt.Fprintf(os.Stderr, "mount secrets: %v\n", err)
			os.Exit(1)
		}
	}
	fd, err := listen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vsock: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("capsule-guest-ready")
	for {
		conn, _, err := unix.Accept(fd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept: %v\n", err)
			continue
		}
		go handle(conn)
	}
}

func waitBlock(path string) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not appear", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func listen() (int, error) {
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
		if err == nil {
			err = unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: 52})
			if err == nil {
				if err = unix.Listen(fd, 16); err == nil {
					return fd, nil
				}
			}
			unix.Close(fd)
		}
		last = err
		if time.Now().After(deadline) {
			return -1, last
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func handle(fd int) {
	f := os.NewFile(uintptr(fd), "vsock")
	defer f.Close()
	op, argv, err := protocol.ReadRequest(f)
	if err != nil {
		return
	}
	switch op {
	case protocol.OpExec:
		code, out := run(argv)
		_ = protocol.WriteResult(f, code, out)
	case protocol.OpUnmount:
		unix.Sync()
		if err := unix.Unmount("/workspace", 0); err != nil {
			_ = protocol.WriteResult(f, 1, []byte(err.Error()))
			return
		}
		_ = protocol.WriteResult(f, 0, nil)
	case protocol.OpMount:
		if err := unix.Mount("/dev/vda", "/workspace", "ext4", 0, ""); err != nil {
			_ = protocol.WriteResult(f, 1, []byte(err.Error()))
			return
		}
		_ = protocol.WriteResult(f, 0, nil)
	default:
		_ = protocol.WriteResult(f, 1, []byte("unknown operation"))
	}
}

func run(argv []string) (int32, []byte) {
	if len(argv) == 0 {
		return 127, []byte("exec requires a command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = "/workspace"
	cmd.Env = []string{"PATH=/bin", "HOME=/tmp"}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err == nil {
		return 0, buf.Bytes()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return int32(exitErr.ExitCode()), buf.Bytes()
	}
	if buf.Len() == 0 {
		buf.WriteString(err.Error())
	}
	return 127, buf.Bytes()
}
