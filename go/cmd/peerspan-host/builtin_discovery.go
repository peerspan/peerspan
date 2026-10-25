package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
)

// Built-in discovery (capabilities slice 3): the CLI finds gh on its PATH,
// reads its version and github.com accounts, captures each account's token,
// and sends the definitions to the daemon.

const (
	ghDiscoveryTimeout = 10 * time.Second
	ghMinVersion       = "2.81.0"
)

var ghVersionLine = regexp.MustCompile(`^gh version ([0-9]+)\.([0-9]+)\.([0-9]+)`)

// findGH searches PATH, skipping empty and relative entries, for a regular
// executable file named gh.
func findGH() string {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		path := filepath.Join(dir, "gh")
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return path
		}
	}
	return ""
}

// ghCommand runs one discovery command with the CLI's environment, minus
// the token variables, and a 10-second timeout. Its output is never shown.
func ghCommand(ctx context.Context, gh string, args ...string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, ghDiscoveryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gh, args...)
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_PROMPT_DISABLED", "GH_NO_UPDATE_NOTIFIER":
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1")
	cmd.WaitDelay = time.Second
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	return stdout.Bytes(), err == nil
}

// versionBelow compares X.Y.Z numerically.
func versionBelow(version, min string) bool {
	var v, m [3]int
	parse := func(s string, out *[3]int) {
		for i, part := range strings.SplitN(s, ".", 3) {
			n := 0
			for _, c := range part {
				n = n*10 + int(c-'0')
			}
			out[i] = n
		}
	}
	parse(version, &v)
	parse(min, &m)
	for i := range v {
		if v[i] != m[i] {
			return v[i] < m[i]
		}
	}
	return false
}

// ghSourceName is gh-LOGIN for an account other than the active one.
func ghSourceName(login string) string {
	var b strings.Builder
	b.WriteString("gh-")
	for _, r := range strings.ToLower(login) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	name := b.String()
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

type builtinPut struct {
	Sources []host.BuiltinDefinition     `json:"sources"`
	Values  map[string]map[string]string `json:"values"`
}

// discoverBuiltin runs gh discovery.
func discoverBuiltin(ctx context.Context) builtinPut {
	put := builtinPut{Sources: []host.BuiltinDefinition{}, Values: map[string]map[string]string{}}
	gh := findGH()
	if gh == "" {
		return put
	}
	missing := map[string]host.ToolEnv{"GH_TOKEN": {Source: "missing", Variables: []string{"GH_TOKEN"}}}
	def := func(name string, version, account *string, authenticated bool) host.BuiltinDefinition {
		return host.BuiltinDefinition{Name: name, Adapter: "gh", Command: gh, Version: version, Host: "github.com", Account: account, Authenticated: authenticated, Env: missing}
	}
	var version *string
	if out, ok := ghCommand(ctx, gh, "--version"); ok {
		first, _, _ := strings.Cut(string(out), "\n")
		if m := ghVersionLine.FindStringSubmatch(first); m != nil {
			v := m[1] + "." + m[2] + "." + m[3]
			version = &v
		}
	}
	if version == nil || versionBelow(*version, ghMinVersion) {
		put.Sources = append(put.Sources, def("gh", version, nil, false))
		return put
	}
	type account struct {
		State       string `json:"state"`
		Active      bool   `json:"active"`
		Login       string `json:"login"`
		TokenSource string `json:"tokenSource"`
	}
	var status struct {
		Hosts map[string][]account `json:"hosts"`
	}
	var accounts []account
	if out, ok := ghCommand(ctx, gh, "auth", "status", "--json", "hosts"); ok && json.Unmarshal(out, &status) == nil {
		for _, a := range status.Hosts["github.com"] {
			if a.TokenSource == "GH_TOKEN" || a.TokenSource == "GITHUB_TOKEN" || a.Login == "" {
				continue
			}
			accounts = append(accounts, a)
		}
	}
	if len(accounts) == 0 {
		put.Sources = append(put.Sources, def("gh", version, nil, false))
		return put
	}
	active := 0
	for i, a := range accounts {
		if a.Active {
			active = i
			break
		}
	}
	seen := map[string]bool{}
	names := make([]string, len(accounts))
	names[active] = "gh"
	seen["gh"] = true
	for i, a := range accounts {
		if i == active {
			continue
		}
		names[i] = ghSourceName(a.Login)
	}
	for i, a := range accounts {
		name := names[i]
		if i != active {
			if seen[name] {
				continue
			}
			seen[name] = true
		}
		login := a.Login
		d := def(name, version, &login, a.State == "success")
		if d.Authenticated {
			if out, ok := ghCommand(ctx, gh, "auth", "token", "--hostname", "github.com", "--user", login); ok {
				if token := strings.Trim(string(out), " \t\n\r"); token != "" {
					d.Env = map[string]host.ToolEnv{"GH_TOKEN": {Source: "captured"}}
					put.Values[name] = map[string]string{"env.GH_TOKEN": token}
				}
			}
		}
		put.Sources = append(put.Sources, d)
	}
	return put
}

// builtinSourcesView is a built-in SERVER as the CLI reads it.
type builtinSourcesView struct {
	sourceServer
	Adapter string        `json:"adapter"`
	Version *string       `json:"version"`
	Account *string       `json:"account"`
	Reach   *host.GHReach `json:"reach"`
}

// storeBuiltin runs built-in discovery and stores the result.
func storeBuiltin(ctx context.Context, client host.Client) ([]builtinSourcesView, error) {
	put := discoverBuiltin(ctx)
	data, err := client.Call(ctx, "PUT", "/v1/builtin-sources", put)
	if err != nil {
		return nil, err
	}
	var stored struct {
		Builtin []builtinSourcesView `json:"builtin"`
	}
	err = json.Unmarshal(data, &stored)
	return stored.Builtin, err
}

// summarizeBuiltin is the attach and refresh entry list for built-in
// sources.
func summarizeBuiltin(list []builtinSourcesView) []attachServer {
	out := []attachServer{}
	for _, s := range list {
		readOnly := 0
		for _, t := range s.Tools {
			if t.ReadOnly {
				readOnly++
			}
		}
		missing := s.MissingEnv
		if missing == nil {
			missing = []string{}
		}
		out = append(out, attachServer{s.Name, s.Transport, s.Shareable, s.Reason, missing, len(s.Tools), readOnly, s.SnapshotError})
	}
	return out
}

// reachSentence states what a gh credential reaches.
func reachSentence(reach *host.GHReach, account *string) string {
	login := "unknown"
	if account != nil {
		login = *account
	}
	if reach != nil && reach.Account != nil {
		login = *reach.Account
	}
	host := "github.com"
	if reach == nil {
		return "Peerspan could not check the reach of the gh account " + login + " on " + host + " (not checked yet). Assume everything the account can reach."
	}
	if reach.Error != nil {
		return "Peerspan could not check the reach of the gh account " + login + " on " + host + " (" + *reach.Error + "). Assume everything the account can reach."
	}
	scopes := strings.Join(reach.Scopes, ", ")
	has := func(s string) bool {
		for _, x := range reach.Scopes {
			if x == s {
				return true
			}
		}
		return false
	}
	switch {
	case reach.Scopes != nil && has("repo"):
		return "The gh account " + login + " on " + host + " (token scopes: " + scopes + ") can read and change every repository " + login + " can, public and private."
	case reach.Scopes != nil && has("public_repo"):
		return "The gh account " + login + " on " + host + " (token scopes: " + scopes + ") can read public repositories and change public repositories " + login + " can."
	case reach.Scopes != nil && (reach.TokenType == "oauth" || reach.TokenType == "classic"):
		if scopes == "" {
			scopes = "none"
		}
		return "The gh account " + login + " on " + host + " (token scopes: " + scopes + ") can read public repositories only."
	}
	return "The gh account " + login + " on " + host + " uses a token that states no scopes, so Peerspan cannot tell which repositories it reaches. Assume every repository it was granted."
}

const ghHint = "GitHub CLI (gh) not found on PATH; install gh 2.81.0 or later and run peerspan sources refresh to use it as a source."
