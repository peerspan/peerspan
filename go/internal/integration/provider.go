// Package integration implements owner-local setup independently of a harness.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const limit = 1 << 20

type Manifest struct {
	Version    int      `json:"version"`
	ID         string   `json:"id"`
	Command    []string `json:"command"`
	Operations []string `json:"operations"`
}
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type Launch struct {
	Program string   `json:"program"`
	Args    []string `json:"args"`
}
type providerResult struct {
	Version int               `json:"version"`
	Checks  []Check           `json:"checks"`
	State   json.RawMessage   `json:"state,omitempty"`
	Files   map[string]string `json:"files,omitempty"`
	Launch  *Launch           `json:"launch,omitempty"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var filePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var checkPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var secretPattern = regexp.MustCompile(`(?:token|instance)_[0-9a-f]{64}`)

func scrub(s string) string {
	s = secretPattern.ReplaceAllString(s, "[redacted]")
	if len(s) > 600 {
		s = s[:600]
	}
	return s
}
func (m Manifest) supports(op string) bool {
	for _, value := range m.Operations {
		if value == op {
			return true
		}
	}
	return false
}
func (m Manifest) validate() error {
	if m.Version != 1 || !namePattern.MatchString(m.ID) || len(m.Command) == 0 || len(m.Command) > 64 || !m.supports("prepare") || !m.supports("check") {
		return errors.New("invalid integration manifest")
	}
	seen := map[string]bool{}
	for _, op := range m.Operations {
		if seen[op] || (op != "prepare" && op != "check" && op != "launch") {
			return errors.New("invalid integration operations")
		}
		seen[op] = true
	}
	for _, arg := range m.Command {
		if strings.ContainsRune(arg, 0) {
			return errors.New("invalid integration command")
		}
	}
	return nil
}
func executable(program string) (string, error) {
	path, err := exec.LookPath(program)
	if err != nil {
		return "", errors.New("integration executable is missing or not executable")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}
func loadManifest(root, id, runner string) (Manifest, error) {
	if !namePattern.MatchString(id) {
		return Manifest{}, errors.New("use a valid --harness ID")
	}
	if root == "" {
		root = os.Getenv("CAPSULE_INTEGRATIONS_DIR")
	}
	if root == "" {
		binary, err := os.Executable()
		if err != nil {
			return Manifest{}, err
		}
		root = filepath.Join(filepath.Dir(binary), "..", "share", "capsule", "integrations")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Manifest{}, errors.New("integration directory is missing; specify --integrations DIR")
	}
	var selected *Manifest
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name(), "integration.json")
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		data, err := readFile(path, false)
		if err != nil {
			continue
		}
		var identity struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &identity) != nil || identity.ID != id {
			continue
		}
		var m Manifest
		if err := readJSON(path, &m, false); err != nil {
			return Manifest{}, errors.New("invalid installed integration manifest")
		}
		if err := m.validate(); err != nil {
			return Manifest{}, err
		}
		if m.ID != id {
			continue
		}
		if selected != nil {
			return Manifest{}, errors.New("duplicate harness ID in integration directory")
		}
		for index, arg := range m.Command {
			if strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
				m.Command[index], err = filepath.Abs(filepath.Join(filepath.Dir(path), arg))
				if err != nil {
					return Manifest{}, err
				}
			}
		}
		selected = &m
	}
	if selected == nil {
		return Manifest{}, errors.New("harness is not installed in the integration directory")
	}
	if runner != "" {
		selected.Command[0] = runner
	}
	selected.Command[0], err = executable(selected.Command[0])
	return *selected, err
}
func readJSON(path string, dst any, private bool) error {
	data, err := readFile(path, private)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid JSON configuration")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid JSON configuration")
	}
	return nil
}
func readFile(path string, private bool) ([]byte, error) {
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if private {
		flags |= syscall.O_NOFOLLOW
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > limit {
		return nil, errors.New("configuration must be a regular file of at most 1 MiB")
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if private && (!ok || owner.Uid != uint32(os.Getuid()) || stat.Mode().Perm()&0077 != 0) {
		return nil, errors.New("setup files must be private and owned by this account")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if len(data) > limit {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	return data, err
}
func privateDirectory(path string) error {
	stat, err := os.Lstat(path)
	if err != nil {
		return errors.New("private setup directory is missing")
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if !stat.IsDir() || stat.Mode().Perm()&0077 != 0 || !ok || owner.Uid != uint32(os.Getuid()) {
		return errors.New("setup directory must be private and owned by this account")
	}
	return nil
}
func writeFile(path string, data []byte) error {
	if len(data) > limit {
		return errors.New("configuration exceeds 1 MiB")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".integration-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(data, '\n'))
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data)+b.Len() > limit {
		return 0, errors.New("integration response exceeds 1 MiB")
	}
	return b.Buffer.Write(data)
}
func provider(ctx context.Context, p *Profile, op, workspace string, args []string) (providerResult, error) {
	if !p.Harness.supports(op) {
		return providerResult{}, fmt.Errorf("this integration does not support %s", op)
	}
	if args == nil {
		args = []string{}
	}
	input := map[string]any{"version": 1, "operation": op, "context": map[string]any{
		"directory": p.Directory, "state": p.State, "agent_id": p.AgentID, "session_id": p.SessionID,
		"adapter_socket": filepath.Join(p.State, "adapter.sock"), "credential_file": filepath.Join(p.Directory, "credential.json"),
		"options": p.Options, "provider_state": p.ProviderState, "workspace": workspace, "arguments": args,
	}}
	if op == "launch" {
		// The launch names the running CLI, which the Claude integration's
		// session start hook runs as `capsule session pending --hook`.
		executable, err := os.Executable()
		if err == nil {
			executable, err = filepath.Abs(executable)
		}
		if err != nil {
			return providerResult{}, fmt.Errorf("could not find the running capsule executable: %w", err)
		}
		input["context"].(map[string]any)["capsule_executable"] = executable
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > limit {
		return providerResult{}, errors.New("integration request exceeds 1 MiB")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Harness.Command[0], p.Harness.Command[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = io.Discard
	var output boundedOutput
	cmd.Stdout = &output
	err = cmd.Run()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if err != nil {
		return providerResult{}, errors.New("integration helper failed or timed out; check its installation and runtime")
	}
	var result providerResult
	data = output.Bytes()
	if !utf8.Valid(data) {
		return result, errors.New("invalid integration response")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || bytes.Equal(bytes.TrimSpace(fields["files"]), []byte("null")) {
		return result, errors.New("invalid integration response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.Version != 1 || result.Checks == nil {
		return result, errors.New("invalid integration response")
	}
	for index := range result.Checks {
		check := &result.Checks[index]
		if !checkPattern.MatchString(check.Name) || (check.Status != "ok" && check.Status != "error") {
			return result, errors.New("invalid integration check")
		}
		check.Name = "harness/" + check.Name
		check.Detail = scrub(check.Detail)
	}
	if result.Launch != nil && result.Launch.Args == nil {
		return result, errors.New("invalid integration launch plan")
	}
	for name := range result.Files {
		if !filePattern.MatchString(name) || name == "profile.json" || name == "credential.json" {
			return result, errors.New("integration returned an invalid artifact filename")
		}
	}
	return result, nil
}
func failed(checks []Check) bool {
	for _, check := range checks {
		if check.Status != "ok" {
			return true
		}
	}
	return false
}
