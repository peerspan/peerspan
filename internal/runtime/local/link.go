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

// Connect builds a bridge in its own network namespace and a veth from each workcell
// into that bridge. The host network is not attached. A later call adds peers that
// are not on the link yet and leaves the ones already there in place.
func (Runtime) Connect(ctx context.Context, sessionID string, peers []runtime.Peer) ([]runtime.Address, error) {
	if len(peers) < 2 {
		return nil, fmt.Errorf("reachability requires at least two running workcells")
	}
	for _, peer := range peers {
		if peer.PID <= 0 || strings.TrimSpace(peer.Name) == "" {
			return nil, fmt.Errorf("reachability requires a running workcell and a name for each capsule")
		}
	}
	addrs, err := plan(sessionID, peers)
	if err != nil {
		return nil, err
	}
	ns := netnsName(sessionID)
	createdNS, err := ensureBridge(ctx, ns)
	if err != nil {
		return nil, err
	}
	var created []string
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		for _, bridgeIf := range created {
			_ = run(context.Background(), ipPath, "netns", "exec", ns, ipPath, "link", "delete", bridgeIf)
		}
		if createdNS {
			_ = deleteNetns(context.Background(), ns)
		}
	}()

	var priorPeers []runtime.Peer
	var priorAddrs []runtime.Address
	for i, peer := range peers {
		guestIf, bridgeIf := ifaces(sessionID, peer.Name)
		exists, err := ifaceExists(ctx, peer.PID, guestIf)
		if err != nil {
			return nil, err
		}
		if exists {
			priorPeers = append(priorPeers, peer)
			priorAddrs = append(priorAddrs, addrs[i])
			continue
		}
		if err := addPeer(ctx, ns, peer.PID, guestIf, bridgeIf, addrs[i].IP); err != nil {
			return nil, err
		}
		created = append(created, bridgeIf)
	}
	if err := publish(ctx, peers, addrs); err != nil {
		for _, bridgeIf := range created {
			_ = run(context.Background(), ipPath, "netns", "exec", ns, ipPath, "link", "delete", bridgeIf)
		}
		created = nil
		if len(priorPeers) >= 2 {
			_ = publish(context.Background(), priorPeers, priorAddrs)
		}
		return nil, err
	}
	cleanup = false
	return addrs, nil
}

// Disconnect deletes the session bridge and the names published for it.
func (Runtime) Disconnect(ctx context.Context, sessionID string, peers []runtime.Peer) error {
	if err := deleteNetns(ctx, netnsName(sessionID)); err != nil && !gone(err) {
		return err
	}
	for _, peer := range peers {
		_ = writeHosts(ctx, peer.PID, nil)
	}
	return nil
}

func plan(sessionID string, peers []runtime.Peer) ([]runtime.Address, error) {
	if len(peers) > 254 {
		return nil, fmt.Errorf("session link supports 254 peers")
	}
	sum := sha256.Sum256([]byte("ip\x00" + sessionID))
	out := make([]runtime.Address, len(peers))
	for i, peer := range peers {
		out[i] = runtime.Address{
			Name: peer.Name,
			IP:   fmt.Sprintf("10.88.%d.%d", int(sum[0]), i+1),
		}
	}
	return out, nil
}

func netnsName(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return fmt.Sprintf("c%x", sum[:7])
}

func ifaces(sessionID, name string) (guestIf, bridgeIf string) {
	sum := sha256.Sum256([]byte(sessionID + "\x00" + name))
	guestIf = fmt.Sprintf("g%x", sum[:4])[:8]
	bridgeIf = fmt.Sprintf("b%x", sum[:4])[:8]
	return guestIf, bridgeIf
}

func ensureBridge(ctx context.Context, ns string) (bool, error) {
	err := run(ctx, ipPath, "netns", "add", ns)
	created := err == nil
	if err != nil && !fileExists(err) {
		return false, err
	}
	showErr := run(ctx, ipPath, "netns", "exec", ns, ipPath, "link", "show", "br0")
	if showErr != nil {
		if err := run(ctx, ipPath, "netns", "exec", ns, ipPath, "link", "add", "br0", "type", "bridge"); err != nil {
			if created {
				_ = deleteNetns(context.Background(), ns)
			}
			return false, err
		}
	}
	if err := run(ctx, ipPath, "netns", "exec", ns, ipPath, "link", "set", "br0", "up"); err != nil {
		if created {
			_ = deleteNetns(context.Background(), ns)
		}
		return false, err
	}
	return created, nil
}

func addPeer(ctx context.Context, ns string, pid int, guestIf, bridgeIf, ip string) error {
	if err := run(ctx, ipPath, "link", "add", guestIf, "type", "veth", "peer", "name", bridgeIf); err != nil {
		return err
	}
	if err := run(ctx, ipPath, "link", "set", guestIf, "netns", strconv.Itoa(pid)); err != nil {
		_ = run(context.Background(), ipPath, "link", "delete", guestIf)
		return err
	}
	if err := run(ctx, ipPath, "link", "set", bridgeIf, "netns", ns); err != nil {
		_ = deleteLink(ctx, pid, guestIf)
		return err
	}
	if err := run(ctx, ipPath, "netns", "exec", ns, ipPath, "link", "set", bridgeIf, "master", "br0"); err != nil {
		_ = run(context.Background(), ipPath, "netns", "exec", ns, ipPath, "link", "delete", bridgeIf)
		return err
	}
	if err := run(ctx, ipPath, "netns", "exec", ns, ipPath, "link", "set", bridgeIf, "up"); err != nil {
		_ = run(context.Background(), ipPath, "netns", "exec", ns, ipPath, "link", "delete", bridgeIf)
		return err
	}
	if err := addrUp(ctx, pid, guestIf, ip); err != nil {
		_ = run(context.Background(), ipPath, "netns", "exec", ns, ipPath, "link", "delete", bridgeIf)
		return err
	}
	return nil
}

func publish(ctx context.Context, peers []runtime.Peer, addrs []runtime.Address) error {
	for i, peer := range peers {
		var lines []string
		for j, addr := range addrs {
			if i == j {
				continue
			}
			lines = append(lines, addr.IP+" "+addr.Name)
		}
		if err := writeHosts(ctx, peer.PID, lines); err != nil {
			return err
		}
	}
	return nil
}

func addrUp(ctx context.Context, pid int, iface, ip string) error {
	if err := nsenter(ctx, pid, false, ipPath, "addr", "add", ip+"/24", "dev", iface); err != nil {
		return err
	}
	return nsenter(ctx, pid, false, ipPath, "link", "set", iface, "up")
}

func writeHosts(ctx context.Context, pid int, lines []string) error {
	if pid <= 0 {
		return nil
	}
	body := "127.0.0.1 localhost"
	if len(lines) > 0 {
		body += "\n" + strings.Join(lines, "\n")
	}
	return nsenter(ctx, pid, true, "/bin/sh", "-c", `printf '%s\n' "$1" > /etc/hosts`, "sh", body)
}

func ifaceExists(ctx context.Context, pid int, iface string) (bool, error) {
	err := nsenter(ctx, pid, false, ipPath, "link", "show", iface)
	if err == nil {
		return true, nil
	}
	if gone(err) {
		return false, nil
	}
	return false, err
}

func deleteLink(ctx context.Context, pid int, iface string) error {
	if pid <= 0 {
		return fmt.Errorf("Cannot find device %q", iface)
	}
	return nsenter(ctx, pid, false, ipPath, "link", "delete", iface)
}

func deleteNetns(ctx context.Context, ns string) error {
	return run(ctx, ipPath, "netns", "delete", ns)
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

func fileExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "File exists")
}

func gone(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Cannot find device") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "No such file") ||
		strings.Contains(msg, "No such process") ||
		strings.Contains(msg, "no such process")
}
