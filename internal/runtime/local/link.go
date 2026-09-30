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
func (Runtime) Connect(ctx context.Context, sessionID string, host, guest runtime.Peer) (runtime.Link, error) {
	if host.PID <= 0 || guest.PID <= 0 {
		return runtime.Link{}, fmt.Errorf("reachability requires two running workcells")
	}
	if strings.TrimSpace(host.Name) == "" || strings.TrimSpace(guest.Name) == "" {
		return runtime.Link{}, fmt.Errorf("reachability requires a name for each capsule")
	}
	hostIf, guestIf, hostIP, guestIP := linkPlan(sessionID)
	if err := run(ctx, ipPath, "link", "add", hostIf, "type", "veth", "peer", "name", guestIf); err != nil {
		return runtime.Link{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = run(context.Background(), ipPath, "link", "delete", hostIf)
			_ = (Runtime{}).Disconnect(context.Background(), sessionID, host.PID, guest.PID)
		}
	}()
	if err := run(ctx, ipPath, "link", "set", hostIf, "netns", strconv.Itoa(host.PID)); err != nil {
		return runtime.Link{}, err
	}
	if err := run(ctx, ipPath, "link", "set", guestIf, "netns", strconv.Itoa(guest.PID)); err != nil {
		return runtime.Link{}, err
	}
	if err := addrUp(ctx, host.PID, hostIf, hostIP); err != nil {
		return runtime.Link{}, err
	}
	if err := addrUp(ctx, guest.PID, guestIf, guestIP); err != nil {
		return runtime.Link{}, err
	}
	if err := addHost(ctx, host.PID, guestIP, guest.Name); err != nil {
		return runtime.Link{}, err
	}
	if err := addHost(ctx, guest.PID, hostIP, host.Name); err != nil {
		return runtime.Link{}, err
	}
	cleanup = false
	return runtime.Link{HostIP: hostIP, GuestIP: guestIP}, nil
}

// Disconnect deletes the session veth and the names published for it.
func (Runtime) Disconnect(ctx context.Context, sessionID string, hostPID, guestPID int) error {
	hostIf, guestIf, hostIP, guestIP := linkPlan(sessionID)
	if err := deleteLink(ctx, hostPID, hostIf); err != nil && !gone(err) {
		return err
	} else if gone(err) {
		if err := deleteLink(ctx, guestPID, guestIf); err != nil && !gone(err) {
			return err
		}
	}
	_ = removeHost(ctx, hostPID, guestIP)
	_ = removeHost(ctx, guestPID, hostIP)
	return nil
}

func linkPlan(sessionID string) (hostIf, guestIf, hostIP, guestIP string) {
	sum := sha256.Sum256([]byte(sessionID))
	n := (int(sum[0])<<8 | int(sum[1])) % 16384
	base := n * 4
	hostIf = fmt.Sprintf("ch%x", sum[:4])[:8]
	guestIf = fmt.Sprintf("cg%x", sum[:4])[:8]
	hostIP = fmt.Sprintf("10.88.%d.%d", (base+1)/256, (base+1)%256)
	guestIP = fmt.Sprintf("10.88.%d.%d", (base+2)/256, (base+2)%256)
	return hostIf, guestIf, hostIP, guestIP
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
