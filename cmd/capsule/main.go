package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const stateDirName = ".capsules"

type Capsule struct {
	ID           string       `json:"id"`
	Repo         string       `json:"repo,omitempty"`
	Task         string       `json:"task"`
	Owner        string       `json:"owner"`
	Status       string       `json:"status"`
	Runtime      Runtime      `json:"runtime"`
	Network      Network      `json:"network"`
	Authority    Authority    `json:"authority"`
	Audit        []AuditEvent `json:"audit"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	DestroyAfter *time.Time   `json:"destroy_after,omitempty"`
}

type Runtime struct {
	Backend string `json:"backend"`
	Image   string `json:"image,omitempty"`
}

type Network struct {
	Mode      string   `json:"mode"`
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints,omitempty"`
}

type Authority struct {
	Capabilities []string   `json:"capabilities,omitempty"`
	Secrets      []string   `json:"secrets,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

type AuditEvent struct {
	At      time.Time `json:"at"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
}

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
	case "destroy":
		return destroy(args[1:])
	case "help", "--help", "-h":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func create(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	repo := fs.String("repo", "", "repo URL or local path")
	task := fs.String("task", "", "task description")
	owner := fs.String("owner", os.Getenv("USER"), "capsule owner")
	runtime := fs.String("runtime", "local", "runtime backend")
	image := fs.String("image", "", "runtime image")
	networkMode := fs.String("network", "local", "network mode")
	caps := multiFlag{}
	secrets := multiFlag{}
	fs.Var(&caps, "capability", "allowed capability; repeatable")
	fs.Var(&secrets, "secret", "secret reference; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*task) == "" {
		return errors.New("create requires --task")
	}

	now := time.Now().UTC()
	id := newID(now)
	c := Capsule{
		ID:     id,
		Repo:   strings.TrimSpace(*repo),
		Task:   strings.TrimSpace(*task),
		Owner:  strings.TrimSpace(*owner),
		Status: "created",
		Runtime: Runtime{
			Backend: strings.TrimSpace(*runtime),
			Image:   strings.TrimSpace(*image),
		},
		Network: Network{
			Mode: strings.TrimSpace(*networkMode),
			Name: id + ".capsule.local",
		},
		Authority: Authority{
			Capabilities: caps,
			Secrets:      secrets,
		},
		Audit: []AuditEvent{{
			At:      now,
			Type:    "capsule.created",
			Message: "capsule record created",
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := saveCapsule(c); err != nil {
		return err
	}

	fmt.Println(c.ID)
	return nil
}

func list() error {
	capsules, err := loadCapsules()
	if err != nil {
		return err
	}
	if len(capsules) == 0 {
		fmt.Println("no capsules")
		return nil
	}
	fmt.Printf("%-22s %-10s %-12s %s\n", "ID", "STATUS", "RUNTIME", "TASK")
	for _, c := range capsules {
		fmt.Printf("%-22s %-10s %-12s %s\n", c.ID, c.Status, c.Runtime.Backend, c.Task)
	}
	return nil
}

func inspect(args []string) error {
	if len(args) != 1 {
		return errors.New("inspect requires a capsule id")
	}
	c, err := loadCapsule(args[0])
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

func destroy(args []string) error {
	if len(args) != 1 {
		return errors.New("destroy requires a capsule id")
	}
	c, err := loadCapsule(args[0])
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	c.Status = "destroyed"
	c.UpdatedAt = now
	c.Audit = append(c.Audit, AuditEvent{
		At:      now,
		Type:    "capsule.destroyed",
		Message: "capsule marked destroyed",
	})
	if err := saveCapsule(c); err != nil {
		return err
	}
	fmt.Println(c.ID)
	return nil
}

func saveCapsule(c Capsule) error {
	dir, err := stateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, c.ID+".json")
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func loadCapsules() ([]Capsule, error) {
	dir, err := stateDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var capsules []Capsule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		c, err := loadCapsule(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		capsules = append(capsules, c)
	}
	return capsules, nil
}

func loadCapsule(id string) (Capsule, error) {
	dir, err := stateDir()
	if err != nil {
		return Capsule{}, err
	}
	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return Capsule{}, err
	}
	var c Capsule
	if err := json.Unmarshal(data, &c); err != nil {
		return Capsule{}, err
	}
	return c, nil
}

func stateDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, stateDirName), nil
}

func newID(t time.Time) string {
	return "cap-" + strings.ReplaceAll(t.Format("20060102-150405.000000000"), ".", "-")
}

func printHelp() {
	fmt.Println(`capsule manages local agent capsule records.

Usage:
  capsule create --task "Fix issue 418" [--repo URL] [--capability NAME]
  capsule list
  capsule inspect <capsule-id>
  capsule destroy <capsule-id>`)
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, strings.TrimSpace(value))
	return nil
}
