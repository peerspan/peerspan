package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/client"
	"github.com/Cerebral-Systems/capsule/internal/control"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printHelp()
		return nil
	}
	switch args[0] {
	case "create":
		return create(args[1:])
	case "list":
		return list()
	case "inspect":
		return inspect(args[1:])
	case "exec":
		return execCmd(args[1:])
	case "destroy":
		return destroy(args[1:])
	case "session":
		return sessionCmd(args[1:])
	case "secret":
		return secretCmd(args[1:])
	case "serve":
		return serve(args[1:])
	case "help", "--help", "-h":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func create(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	repo := fs.String("repo", "", "git URL or local git path to clone into the workspace")
	task := fs.String("task", "", "task description")
	owner := fs.String("owner", os.Getenv("USER"), "capsule owner")
	backend := fs.String("runtime", capsule.RuntimeLocal, "runtime backend")
	image := fs.String("image", "", "runtime image")
	setup := fs.String("setup", "", "shell command run in the workspace before the process starts")
	networkMode := fs.String("network", "local", "network mode")
	var caps multiFlag
	var secrets multiFlag
	fs.Var(&caps, "capability", "allowed capability; repeatable")
	fs.Var(&secrets, "secret", "secret reference; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := openClient()
	if err != nil {
		return err
	}
	c, err := svc.Create(context.Background(), control.CreateRequest{
		Repo:         *repo,
		Task:         *task,
		Owner:        *owner,
		Backend:      *backend,
		Image:        *image,
		Setup:        *setup,
		NetworkMode:  *networkMode,
		Capabilities: caps,
		Secrets:      secrets,
	})
	if c.ID != "" {
		fmt.Println(c.ID)
	}
	return err
}

func list() error {
	svc, err := openClient()
	if err != nil {
		return err
	}
	capsules, err := svc.List(context.Background())
	if err != nil {
		return err
	}
	if len(capsules) == 0 {
		fmt.Println("no capsules")
		return nil
	}
	fmt.Printf("%-32s %-10s %-12s %s\n", "ID", "STATUS", "RUNTIME", "TASK")
	for _, c := range capsules {
		fmt.Printf("%-32s %-10s %-12s %s\n", c.ID, c.Status, c.Runtime.Backend, c.Task)
	}
	return nil
}

func inspect(args []string) error {
	if len(args) != 1 {
		return errors.New("inspect requires a capsule id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	c, err := svc.Inspect(context.Background(), args[0])
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

func execCmd(args []string) error {
	if len(args) < 2 {
		return errors.New("exec requires a capsule id and a command")
	}
	argv := args[1:]
	if argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return errors.New("exec requires a command")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	output, err := svc.Exec(context.Background(), args[0], argv)
	if output != "" {
		fmt.Print(output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
	}
	return err
}

func destroy(args []string) error {
	if len(args) != 1 {
		return errors.New("destroy requires a capsule id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	c, err := svc.Destroy(context.Background(), args[0])
	if err != nil {
		return err
	}
	fmt.Println(c.ID)
	return nil
}

func secretCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("secret requires set or list")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	switch args[0] {
	case "set":
		if len(args) != 2 {
			return errors.New("secret set requires a name")
		}
		body, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		if len(body) > 0 && body[len(body)-1] == '\n' {
			body = body[:len(body)-1]
		}
		return svc.SetSecret(context.Background(), args[1], string(body))
	case "list":
		names, err := svc.ListSecrets(context.Background())
		if err != nil {
			return err
		}
		for _, name := range names {
			fmt.Println(name)
		}
		return nil
	default:
		return fmt.Errorf("unknown secret command %q", args[0])
	}
}

func openClient() (client.Client, error) {
	base := os.Getenv("CAPSULE_ADDR")
	if base == "" {
		base = client.DefaultBaseURL
	}
	return client.Client{BaseURL: base}, nil
}

func printHelp() {
	fmt.Println(`capsule manages local agent capsules.

Usage:
  capsule serve [--addr 127.0.0.1:8077] [--data .capsules] [--underlay ADDR]
  capsule create --task "Fix issue 418" [--repo URL] [--capability NAME]
  capsule list
  capsule inspect <capsule-id>
  capsule exec <capsule-id> -- <command> [args]
  capsule destroy <capsule-id>
  capsule session create --capsule <id> --task "issue" [--allow PATH]
  capsule session accept <session-id> --capsule <id> [--allow PATH] [--remote URL]
  capsule session leave <session-id> --capsule <id>
  capsule session message <session-id> --from <id> --text "..."
  capsule session share <session-id> --from <id> --path REL
  capsule session approve <session-id> --by <id> --action ACTION
  capsule session revoke <session-id>
  capsule session export <session-id>
  capsule secret set <name>
  capsule secret list

serve hosts the control plane. Other commands call it at CAPSULE_ADDR, or http://127.0.0.1:8077.
secret set reads the value from stdin and stores it on the host. create --secret mounts that name read-only at /run/secrets/<name> inside the workcell.
create starts a local process. Its working directory is .capsules/<id>/workspace on the server.
If --repo is set, that directory is a git clone of the repository.
If --setup is set, that shell command runs in the workspace before the process starts.
exec runs a command in the workspace and records its exit code.
destroy stops the process.`)
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, strings.TrimSpace(value))
	return nil
}
