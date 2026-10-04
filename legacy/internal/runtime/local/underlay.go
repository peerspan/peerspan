package local

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/Cerebral-Systems/capsule/internal/runtime"
)

const bridgeBin = "/usr/sbin/bridge"

func validatePeers(localUnderlay string, peers []runtime.Peer) error {
	if len(peers) < 2 {
		return fmt.Errorf("reachability requires at least two peers")
	}
	local := 0
	remote := 0
	for _, peer := range peers {
		if strings.TrimSpace(peer.Name) == "" {
			return fmt.Errorf("reachability requires a name for each capsule")
		}
		switch {
		case peer.PID > 0 && peer.Underlay == "":
			local++
		case peer.PID <= 0 && peer.Underlay != "":
			remote++
		default:
			return fmt.Errorf("a peer is either a local workcell or a remote underlay")
		}
	}
	if local == 0 {
		return fmt.Errorf("reachability requires a local workcell")
	}
	if remote > 0 && strings.TrimSpace(localUnderlay) == "" {
		return fmt.Errorf("remote peers require this machine's underlay address")
	}
	return nil
}

func remoteUnderlays(local string, peers []runtime.Peer) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, peer := range peers {
		if peer.Underlay == "" || peer.Underlay == local {
			continue
		}
		if net.ParseIP(peer.Underlay) == nil {
			return nil, fmt.Errorf("underlay %q is not an address", peer.Underlay)
		}
		if seen[peer.Underlay] {
			continue
		}
		seen[peer.Underlay] = true
		out = append(out, peer.Underlay)
	}
	return out, nil
}

// ensureUnderlay connects this machine's session bridge to each remote underlay.
// The host bridge and the VXLAN have no session address. created reports whether
// this call created that path.
func ensureUnderlay(ctx context.Context, sessionID, local, key, netns string, remotes []string) (bool, error) {
	if net.ParseIP(local) == nil {
		return false, fmt.Errorf("local underlay %q is not an address", local)
	}
	hostBr := hostBridge(key)
	existed := linkExists(ctx, netns, hostBr)
	if err := ensureHostBridge(ctx, netns, hostBr); err != nil {
		return false, err
	}
	vx := vxlanName(key)
	if err := ensureVxlan(ctx, netns, vx, sessionID, local, hostBr); err != nil {
		if !existed {
			_ = deleteHostPath(context.Background(), key, netns)
		}
		return false, err
	}
	hostEnd, sessEnd := patchIfaces(key)
	if err := ensurePatch(ctx, netns, netnsName(key), hostBr, hostEnd, sessEnd); err != nil {
		if !existed {
			_ = deleteHostPath(context.Background(), key, netns)
		}
		return false, err
	}
	if err := replaceFlood(ctx, netns, vx, remotes); err != nil {
		if !existed {
			_ = deleteHostPath(context.Background(), key, netns)
		}
		return false, err
	}
	return !existed, nil
}

func deleteHostPath(ctx context.Context, key, netns string) error {
	vx := vxlanName(key)
	hostEnd, _ := patchIfaces(key)
	hostBr := hostBridge(key)
	for _, dev := range []string{vx, hostEnd, hostBr} {
		if err := nsrun(ctx, netns, ipPath, "link", "delete", dev); err != nil && !gone(err) {
			return err
		}
	}
	return nil
}

func ensureHostBridge(ctx context.Context, netns, name string) error {
	if linkExists(ctx, netns, name) {
		return nsrun(ctx, netns, ipPath, "link", "set", name, "up")
	}
	if err := nsrun(ctx, netns, ipPath, "link", "add", name, "type", "bridge"); err != nil {
		return err
	}
	return nsrun(ctx, netns, ipPath, "link", "set", name, "up")
}

func ensureVxlan(ctx context.Context, netns, name, sessionID, local, hostBr string) error {
	if !linkExists(ctx, netns, name) {
		if err := nsrun(ctx, netns, ipPath, "link", "add", name, "type", "vxlan",
			"id", fmt.Sprintf("%d", vxlanVNI(sessionID)),
			"local", local,
			"dstport", fmt.Sprintf("%d", vxlanPort(sessionID)),
			"ttl", "16",
			"nolearning",
		); err != nil {
			return err
		}
	}
	if err := nsrun(ctx, netns, ipPath, "link", "set", name, "master", hostBr); err != nil {
		return err
	}
	return nsrun(ctx, netns, ipPath, "link", "set", name, "up")
}

func ensurePatch(ctx context.Context, netns, sessionNS, hostBr, hostEnd, sessEnd string) error {
	if linkExists(ctx, netns, hostEnd) {
		return nil
	}
	if err := nsrun(ctx, netns, ipPath, "link", "add", hostEnd, "type", "veth", "peer", "name", sessEnd); err != nil {
		return err
	}
	if err := nsrun(ctx, netns, ipPath, "link", "set", hostEnd, "master", hostBr); err != nil {
		_ = nsrun(context.Background(), netns, ipPath, "link", "delete", hostEnd)
		return err
	}
	if err := nsrun(ctx, netns, ipPath, "link", "set", hostEnd, "up"); err != nil {
		_ = nsrun(context.Background(), netns, ipPath, "link", "delete", hostEnd)
		return err
	}
	if err := nsrun(ctx, netns, ipPath, "link", "set", sessEnd, "netns", sessionNS); err != nil {
		_ = nsrun(context.Background(), netns, ipPath, "link", "delete", hostEnd)
		return err
	}
	if err := run(ctx, ipPath, "netns", "exec", sessionNS, ipPath, "link", "set", sessEnd, "master", "br0"); err != nil {
		_ = nsrun(context.Background(), netns, ipPath, "link", "delete", hostEnd)
		return err
	}
	if err := run(ctx, ipPath, "netns", "exec", sessionNS, ipPath, "link", "set", sessEnd, "up"); err != nil {
		_ = nsrun(context.Background(), netns, ipPath, "link", "delete", hostEnd)
		return err
	}
	return nil
}

func replaceFlood(ctx context.Context, netns, vx string, remotes []string) error {
	if err := nsrun(ctx, netns, bridgeBin, "fdb", "flush", "dev", vx); err != nil && !gone(err) {
		return err
	}
	for _, remote := range remotes {
		if err := nsrun(ctx, netns, bridgeBin, "fdb", "append", "00:00:00:00:00:00", "dev", vx, "dst", remote); err != nil {
			return err
		}
	}
	return nil
}

func linkExists(ctx context.Context, netns, name string) bool {
	return nsrun(ctx, netns, ipPath, "link", "show", name) == nil
}

func nsrun(ctx context.Context, netns string, args ...string) error {
	if netns == "" {
		return run(ctx, args...)
	}
	cmd := append([]string{ipPath, "netns", "exec", netns}, args...)
	return run(ctx, cmd...)
}

func hostBridge(key string) string {
	sum := sha256.Sum256([]byte("hb\x00" + key))
	return fmt.Sprintf("h%x", sum[:4])[:8]
}

func vxlanName(key string) string {
	sum := sha256.Sum256([]byte("vx\x00" + key))
	return fmt.Sprintf("v%x", sum[:4])[:8]
}

func patchIfaces(key string) (hostEnd, sessEnd string) {
	sum := sha256.Sum256([]byte("patch\x00" + key))
	hostEnd = fmt.Sprintf("p%x", sum[:3])[:7]
	sessEnd = fmt.Sprintf("q%x", sum[:3])[:7]
	return hostEnd, sessEnd
}

func vxlanVNI(sessionID string) int {
	sum := sha256.Sum256([]byte("vni\x00" + sessionID))
	n := int(sum[0])<<16 | int(sum[1])<<8 | int(sum[2])
	if n == 0 {
		n = 1
	}
	return n
}

func vxlanPort(sessionID string) int {
	sum := sha256.Sum256([]byte("port\x00" + sessionID))
	return 20000 + (int(sum[0])<<8|int(sum[1]))%25000
}
