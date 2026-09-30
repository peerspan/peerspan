package local

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
)

const ipPath = "/usr/sbin/ip"

// Connect builds a veth pair between two workcells and publishes each recorded name
// to the other side. The host network is not attached.
func (Runtime) Connect(ctx context.Context, sessionID string, opened, joined runtime.Peer) (runtime.Link, error) {
	if opened.PID <= 0 || joined.PID <= 0 {
		return runtime.Link{}, fmt.Errorf("reachability requires two running workcells")
	}
	if strings.TrimSpace(opened.Name) == "" || strings.TrimSpace(joined.Name) == "" {
		return runtime.Link{}, fmt.Errorf("reachability requires a name for each capsule")
	}
	openedIf, joinedIf, openedIP, joinedIP := linkPlan(sessionID)
	if err := run(ctx, ipPath, "link", "add", openedIf, "type", "veth", "peer", "name", joinedIf); err != nil {
		return runtime.Link{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = run(context.Background(), ipPath, "link", "delete", openedIf)
			_ = (Runtime{}).Disconnect(context.Background(), sessionID, opened.PID, joined.PID)
		}
	}()
	if err := run(ctx, ipPath, "link", "set", openedIf, "netns", strconv.Itoa(opened.PID)); err != nil {
		return runtime.Link{}, err
	}
	if err := run(ctx, ipPath, "link", "set", joinedIf, "netns", strconv.Itoa(joined.PID)); err != nil {
		return runtime.Link{}, err
	}
	if err := addrUp(ctx, opened.PID, openedIf, openedIP); err != nil {
		return runtime.Link{}, err
	}
	if err := addrUp(ctx, joined.PID, joinedIf, joinedIP); err != nil {
		return runtime.Link{}, err
	}
	if err := addHost(ctx, opened.PID, joinedIP, joined.Name); err != nil {
		return runtime.Link{}, err
	}
	if err := addHost(ctx, joined.PID, openedIP, opened.Name); err != nil {
		return runtime.Link{}, err
	}
	cleanup = false
	return runtime.Link{OpenedIP: openedIP, JoinedIP: joinedIP}, nil
}

// Disconnect deletes the session veth and the names published for it.
func (Runtime) Disconnect(ctx context.Context, sessionID string, openedPID, joinedPID int) error {
	openedIf, joinedIf, openedIP, joinedIP := linkPlan(sessionID)
	if err := deleteLink(ctx, openedPID, openedIf); err != nil && !gone(err) {
		return err
	} else if gone(err) {
		if err := deleteLink(ctx, joinedPID, joinedIf); err != nil && !gone(err) {
			return err
		}
	}
	_ = removeHost(ctx, openedPID, joinedIP)
	_ = removeHost(ctx, joinedPID, openedIP)
	return nil
}

func linkPlan(sessionID string) (openedIf, joinedIf, openedIP, joinedIP string) {
	sum := sha256.Sum256([]byte(sessionID))
	n := (int(sum[0])<<8 | int(sum[1])) % 16384
	base := n * 4
	openedIf = fmt.Sprintf("co%x", sum[:4])[:8]
	joinedIf = fmt.Sprintf("cj%x", sum[:4])[:8]
	openedIP = fmt.Sprintf("10.88.%d.%d", (base+1)/256, (base+1)%256)
	joinedIP = fmt.Sprintf("10.88.%d.%d", (base+2)/256, (base+2)%256)
	return openedIf, joinedIf, openedIP, joinedIP
}

func addrUp(ctx context.Context, pid int, iface, ip string) error {
	if err := nsenter(ctx, pid, false, ipPath, "addr", "add", ip+"/30", "dev", iface); err != nil {
		return err
	}
	return nsenter(ctx, pid, false, ipPath, "link", "set", iface, "up")
}

func addHost(ctx context.Context, pid int, ip, name string) error {
	line := ip + " " + name
	return nsenter(ctx, pid, true, "/bin/sh", "-c", `printf '%s\n' "$1" >> /etc/hosts`, "sh", line)
}

func removeHost(ctx context.Context, pid int, ip string) error {
	if pid <= 0 || ip == "" {
		return nil
	}
	return nsenter(ctx, pid, true, "/bin/sh", "-c", `grep -v -F "$1 " /etc/hosts > /tmp/hosts.new || true; cat /tmp/hosts.new > /etc/hosts`, "sh", ip)
}

func deleteLink(ctx context.Context, pid int, iface string) error {
	if pid <= 0 {
		return fmt.Errorf("Cannot find device %q", iface)
	}
	return nsenter(ctx, pid, false, ipPath, "link", "delete", iface)
}

func nsenter(ctx context.Context, pid int, mount bool, argv ...string) error {
	bin, err := exec.LookPath("nsenter")
	if err != nil {
		return fmt.Errorf("nsenter is required")
	}
	args := []string{"-t", strconv.Itoa(pid), "-n"}
	if mount {
		args = append(args, "-m")
	}
	args = append(args, "--")
	args = append(args, argv...)
	return run(ctx, append([]string{bin}, args...)...)
}

func run(ctx context.Context, argv ...string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return fmt.Errorf("%s: %s", strings.Join(argv, " "), msg)
}

func gone(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Cannot find device") ||
		strings.Contains(msg, "No such file") ||
		strings.Contains(msg, "No such process") ||
		strings.Contains(msg, "no such process")
}
