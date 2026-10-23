package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/pflag"
)

// The daemon as a user service: peerspan install and uninstall, and the
// service part of status. Service tools are found on PATH.

const (
	systemdUnitName   = "peerspan.service"
	launchdLabel      = "dev.peerspan.host"
	firstPeerPort     = 7401
	lastPeerPort      = 7499
	installSocketWait = 10 * time.Second
)

var errNoServiceManager = errors.New("no supported service manager")

// serviceManager is systemd or launchd, chosen by which tool is on PATH.
type serviceManager struct {
	name string // "systemd" or "launchd"
	unit string // the unit or property list path
}

// findServiceManager returns the user service manager, or nil without one.
func findServiceManager() (*serviceManager, error) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		config := os.Getenv("XDG_CONFIG_HOME")
		if config == "" {
			config = filepath.Join(home, ".config")
		}
		return &serviceManager{"systemd", filepath.Join(config, "systemd", "user", systemdUnitName)}, nil
	}
	if _, err := exec.LookPath("launchctl"); err == nil {
		return &serviceManager{"launchd", filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")}, nil
	}
	return nil, nil
}

func (m *serviceManager) launchdTarget() string {
	return "gui/" + strconv.Itoa(os.Getuid()) + "/" + launchdLabel
}

// tool runs a service tool and returns its standard output.
func tool(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		output := strings.TrimSpace(stderr.String() + stdout.String())
		return stdout.String(), fmt.Errorf("%s %s failed: %v %s", name, strings.Join(args, " "), err, output)
	}
	return stdout.String(), nil
}

// active reports whether the installed service is running.
func (m *serviceManager) active(ctx context.Context) bool {
	if m.name == "systemd" {
		out, _ := tool(ctx, "systemctl", "--user", "is-active", systemdUnitName)
		return strings.TrimSpace(out) == "active"
	}
	_, err := tool(ctx, "launchctl", "print", m.launchdTarget())
	return err == nil
}

// linger reads systemd lingering for the current user; launchd has none.
func (m *serviceManager) linger(ctx context.Context) *bool {
	if m.name != "systemd" {
		return nil
	}
	name := os.Getenv("USER")
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	out, err := tool(ctx, "loginctl", "show-user", name, "--property=Linger")
	enabled := false
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "Linger=yes" {
				enabled = true
			}
		}
	}
	return &enabled
}

// daemonReachable reports whether a daemon accepts connections on the
// state's admin socket.
func daemonReachable(state string) bool {
	conn, err := net.DialTimeout("unix", filepath.Join(state, "admin.sock"), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// systemdQuote quotes one ExecStart or Environment argument.
func systemdQuote(arg string) string {
	plain := arg != ""
	for _, r := range arg {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._:@+=,-", r)) {
			plain = false
			break
		}
	}
	if plain {
		return arg
	}
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(arg)
	return `"` + escaped + `"`
}

// systemdUnquote splits an ExecStart value into words.
func systemdUnquote(value string) []string {
	var words []string
	var word strings.Builder
	inWord, quoted, escaped := false, false, false
	for _, r := range value {
		switch {
		case escaped:
			word.WriteRune(r)
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted, inWord = !quoted, true
		case !quoted && (r == ' ' || r == '\t'):
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	for i, w := range words {
		words[i] = strings.NewReplacer("%%", "%", "$$", "$").Replace(w)
	}
	return words
}

func xmlEscape(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(value)
}

func xmlUnescape(value string) string {
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace(value)
}

// render returns the unit or property list for the daemon's arguments.
func (m *serviceManager) render(args []string, agentSocket string) string {
	var b strings.Builder
	if m.name == "systemd" {
		quoted := make([]string, len(args))
		for i, arg := range args {
			quoted[i] = systemdQuote(arg)
		}
		b.WriteString("[Unit]\nDescription=Peerspan host daemon\n\n[Service]\n")
		b.WriteString("ExecStart=" + strings.Join(quoted, " ") + "\n")
		if agentSocket != "" {
			b.WriteString("Environment=" + systemdQuote("SSH_AUTH_SOCK="+agentSocket) + "\n")
		}
		b.WriteString("Restart=on-failure\n\n[Install]\nWantedBy=default.target\n")
		return b.String()
	}
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	b.WriteString("\t<key>Label</key>\n\t<string>" + launchdLabel + "</string>\n")
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, arg := range args {
		b.WriteString("\t\t<string>" + xmlEscape(arg) + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

// installedPeerListen is the --peer-listen address in an installed unit.
func (m *serviceManager) installedArguments(unit string) []string {
	var words []string
	if m.name == "systemd" {
		for _, line := range strings.Split(unit, "\n") {
			if value, ok := strings.CutPrefix(line, "ExecStart="); ok {
				words = systemdUnquote(value)
				break
			}
		}
	} else {
		for _, line := range strings.Split(unit, "\n") {
			line = strings.TrimSpace(line)
			if value, ok := strings.CutPrefix(line, "<string>"); ok {
				if value, ok = strings.CutSuffix(value, "</string>"); ok {
					words = append(words, xmlUnescape(value))
				}
			}
		}
	}
	return words
}

func (m *serviceManager) installedPeerListen(unit string) string {
	words := m.installedArguments(unit)
	for i, word := range words {
		if word == "--peer-listen" && i+1 < len(words) {
			return words[i+1]
		}
	}
	return ""
}

// freePeerListen is the first UDP port from 7401 to 7499 that binds on all
// interfaces.
func freePeerListen() (string, error) {
	for port := firstPeerPort; port <= lastPeerPort; port++ {
		address := "0.0.0.0:" + strconv.Itoa(port)
		conn, err := net.ListenPacket("udp", address)
		if err == nil {
			conn.Close()
			return address, nil
		}
	}
	return "", fmt.Errorf("no free UDP port from %d to %d; pass --peer-listen", firstPeerPort, lastPeerPort)
}

func printJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// runInstall installs the daemon as a user service and, unless --no-start,
// starts it and waits for its admin socket.
func runInstall(ctx context.Context, fs *pflag.FlagSet, state string, out io.Writer) error {
	return installService(ctx, fs, state, func(result map[string]any) error { return printJSON(out, result) })
}

func installService(ctx context.Context, fs *pflag.FlagSet, state string, complete func(map[string]any) error) error {
	peerListen, _ := fs.GetString("peer-listen")
	noStart, _ := fs.GetBool("no-start")
	m, err := findServiceManager()
	if err != nil {
		return err
	}
	if m == nil {
		return errNoServiceManager
	}
	if state, err = filepath.Abs(state); err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		return err
	}
	if peerListen != "" {
		if _, err := netip.ParseAddrPort(peerListen); err != nil {
			return errors.New("--peer-listen must be IP:PORT")
		}
	}
	if daemonReachable(state) && !m.active(ctx) {
		return fmt.Errorf("a daemon is already running on %s outside the service; stop it first", state)
	}
	previous, err := os.ReadFile(m.unit)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	exists := err == nil
	if peerListen == "" && exists {
		peerListen = m.installedPeerListen(string(previous))
	}
	if peerListen == "" {
		if peerListen, err = freePeerListen(); err != nil {
			return err
		}
	}
	agentSocket := ""
	if m.name == "systemd" {
		agentSocket = os.Getenv("SSH_AUTH_SOCK")
	}
	unit := m.render([]string{binary, "--state", state, "run", "--peer-listen", peerListen}, agentSocket)
	same := exists && string(previous) == unit
	if !same {
		if err = os.MkdirAll(filepath.Dir(m.unit), 0o755); err != nil {
			return err
		}
		if err = os.WriteFile(m.unit, []byte(unit), 0o644); err != nil {
			return err
		}
	}
	result := map[string]any{"service": m.name, "unit": m.unit, "state": state, "peer_listen": peerListen, "linger": nil, "started": false}
	if m.name == "systemd" {
		if !same {
			if _, err = tool(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
				return err
			}
		}
		enable := []string{"--user", "enable", "--now", systemdUnitName}
		if noStart {
			enable = []string{"--user", "enable", systemdUnitName}
		}
		if _, err = tool(ctx, "systemctl", enable...); err != nil {
			return err
		}
		if exists && !same && !noStart {
			if _, err = tool(ctx, "systemctl", "--user", "restart", systemdUnitName); err != nil {
				return err
			}
		}
		_, lingerErr := tool(ctx, "loginctl", "enable-linger")
		result["linger"] = lingerErr == nil
	} else if !noStart {
		domain := "gui/" + strconv.Itoa(os.Getuid())
		if exists && !same {
			_, _ = tool(ctx, "launchctl", "bootout", m.launchdTarget())
		}
		if _, err = tool(ctx, "launchctl", "bootstrap", domain, m.unit); err != nil && !same {
			return err
		}
	}
	if !noStart {
		deadline := time.Now().Add(installSocketWait)
		for {
			if daemonReachable(state) {
				result["started"] = true
				break
			}
			if time.Now().After(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return complete(result)
}

// runUninstall stops, disables, and removes the service, keeping the state
// and lingering.
func runUninstall(ctx context.Context, out io.Writer) error {
	m, err := findServiceManager()
	if err != nil {
		return err
	}
	if m == nil {
		return errNoServiceManager
	}
	result := map[string]any{"service": m.name, "unit": m.unit, "removed": false}
	if _, err := os.Stat(m.unit); errors.Is(err, os.ErrNotExist) {
		return printJSON(out, result)
	} else if err != nil {
		return err
	}
	if m.name == "systemd" {
		if _, err = tool(ctx, "systemctl", "--user", "disable", "--now", systemdUnitName); err != nil {
			return err
		}
	} else {
		_, _ = tool(ctx, "launchctl", "bootout", m.launchdTarget())
	}
	if err = os.Remove(m.unit); err != nil {
		return err
	}
	result["removed"] = true
	return printJSON(out, result)
}

// serviceStatus is the service object status adds.
type serviceStatus struct {
	Manager   *string `json:"manager"`
	Unit      *string `json:"unit"`
	Installed bool    `json:"installed"`
	Active    bool    `json:"active"`
	Linger    *bool   `json:"linger"`
}

func readServiceStatus(ctx context.Context) serviceStatus {
	var st serviceStatus
	m, err := findServiceManager()
	if err != nil || m == nil {
		return st
	}
	st.Manager, st.Unit = &m.name, &m.unit
	if info, err := os.Stat(m.unit); err == nil && info.Mode().IsRegular() {
		st.Installed = true
		st.Active = m.active(ctx)
	}
	st.Linger = m.linger(ctx)
	return st
}

// serviceAttention is the attention the CLI adds about the service.
func serviceAttention(st serviceStatus, daemonRunning bool) []host.AttentionItem {
	var items []host.AttentionItem
	if !st.Installed && daemonRunning {
		items = append(items, host.AttentionItem{Kind: "service_not_installed", Subject: "service",
			Detail: "the daemon runs outside a user service and stops when you log out or reboot", Command: "peerspan install"})
	}
	if st.Installed && st.Manager != nil && *st.Manager == "systemd" && st.Linger != nil && !*st.Linger {
		items = append(items, host.AttentionItem{Kind: "linger_disabled", Subject: "service",
			Detail: "systemd lingering is off, so the service stops when you log out", Command: "loginctl enable-linger"})
	}
	return items
}
