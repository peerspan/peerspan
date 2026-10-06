package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

type claudeOptions struct {
	Action     string   `json:"action"`
	Directory  string   `json:"directory"`
	State      string   `json:"state,omitempty"`
	Agent      string   `json:"agent,omitempty"`
	Channel    string   `json:"channel,omitempty"`
	Node       string   `json:"node,omitempty"`
	Claude     string   `json:"claude,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Routes     string   `json:"routes,omitempty"`
	Workspace  string   `json:"workspace,omitempty"`
	ClaudeArgs []string `json:"claude_args,omitempty"`
}

func runClaude(args []string, state string, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(errOut, "Usage: capsule-host [--state DIR] claude setup|start|doctor --directory DIR [options]\nSetup needs --agent ID --channel FILE --expires-at TIME; start may create a setup or use an existing directory.\nOptional: --routes FILE --node PROGRAM --claude PROGRAM --workspace DIR (start only).")
		return nil
	}
	o := claudeOptions{Action: args[0], State: state}
	if o.Action != "setup" && o.Action != "start" && o.Action != "doctor" {
		return errors.New("unknown Claude command")
	}
	fs := flag.NewFlagSet("claude "+o.Action, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&o.Directory, "directory", "", "private setup directory")
	fs.StringVar(&o.Node, "node", "", "Node 22+ executable; defaults to the prepared setup's Node or PATH")
	fs.StringVar(&o.Claude, "claude", "", "Claude executable; defaults to the prepared setup's Claude or PATH")
	if o.Action != "doctor" {
		fs.StringVar(&o.Agent, "agent", "", "registered agent ID; omit to start a prepared setup")
		fs.StringVar(&o.Channel, "channel", "", "installed Capsule channel.mjs")
		fs.StringVar(&o.ExpiresAt, "expires-at", "", "authorization expiry, UTC RFC3339")
		fs.StringVar(&o.Routes, "routes", "", "owner-defined destination array, JSON")
	}
	if o.Action == "start" {
		fs.StringVar(&o.Workspace, "workspace", "", "Claude working directory; defaults to this directory")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if o.Directory == "" {
		return errors.New("--directory is required")
	}
	if fs.NArg() != 0 {
		separator := false
		for _, arg := range args[1:] {
			if arg == "--" {
				separator = true
			}
		}
		if o.Action != "start" || !separator {
			return errors.New("Claude arguments require start and a -- separator")
		}
		o.ClaudeArgs = fs.Args()
	}
	if o.Action == "setup" || o.Action == "start" && o.Agent != "" {
		if o.Agent == "" || o.Channel == "" || o.ExpiresAt == "" {
			return errors.New("new setup requires --agent, --channel and --expires-at")
		}
	} else if o.Channel != "" || o.ExpiresAt != "" || o.Routes != "" {
		return errors.New("setup options require --agent")
	}
	if o.Channel == "" {
		metadata, err := privateClaudeProfile(o.Directory)
		if err != nil {
			return err
		}
		o.Channel = metadata.Channel
		if o.Node == "" {
			o.Node = metadata.Node
		}
	}
	if o.Node == "" {
		o.Node = "node"
	}
	node, err := exec.LookPath(o.Node)
	if err != nil {
		return errors.New("Node 22+ was not found; specify --node PROGRAM")
	}
	node, err = filepath.Abs(node)
	if err != nil {
		return err
	}
	o.Node = node
	channel, err := filepath.Abs(o.Channel)
	if err != nil {
		return err
	}
	o.Channel = channel
	helper := filepath.Join(filepath.Dir(channel), "setup.mjs")
	if _, err := os.Stat(helper); err != nil {
		return errors.New("Capsule setup helper is missing beside channel.mjs; install the complete Claude integration")
	}
	options, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return syscall.Exec(node, []string{node, helper, string(options)}, os.Environ())
}

// Only public bootstrap paths are read here; the shared helper validates the
// full private profile and credential before contacting the daemon.
func privateClaudeProfile(directory string) (struct{ Channel, Node string }, error) {
	var profile struct{ Channel, Node string }
	dir, err := os.Lstat(directory)
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return profile, errors.New("setup directory must be a private directory")
	}
	if stat, ok := dir.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) {
		return profile, errors.New("setup directory must belong to this account")
	}
	file, err := os.OpenFile(filepath.Join(directory, "profile.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return profile, errors.New("private setup profile is missing; run claude setup first")
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 || stat.Size() > 1<<20 {
		return profile, errors.New("setup profile must be a private regular file")
	}
	if owner, ok := stat.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Getuid()) {
		return profile, errors.New("setup profile must belong to this account")
	}
	if err := json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&profile); err != nil || profile.Channel == "" || profile.Node == "" {
		return profile, errors.New("invalid setup profile")
	}
	return profile, nil
}
