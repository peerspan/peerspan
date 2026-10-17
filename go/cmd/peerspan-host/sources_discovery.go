package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/peerspan/peerspan/go/internal/host"
)

// Discovery of shared MCP servers from a harness's configuration (remote
// tools contract). It runs in the CLI, which has the user's environment and
// the project directory, and sends definitions and values to the daemon.

// discoveryError is a configuration source that did not parse.
type discoveryError struct {
	Source string  `json:"source"`
	Path   *string `json:"path"`
	Server *string `json:"server"`
	Error  string  `json:"error"`
}

// discovery is what one harness's configuration yields.
type discovery struct {
	put    host.PutToolServers
	errors []discoveryError
	// paths are the files read, by source.
	paths map[string]string
}

// ownServer matches the Peerspan MCP entries integrations write, peerspan and
// peerspan_ followed by 32 hex digits, which are never discovered.
var ownServer = regexp.MustCompile(`^peerspan(_[0-9a-f]{32})?$`)

// rawServer is one harness definition before normalization.
type rawServer struct {
	name, source       string
	remote, disabled   bool
	command            *string
	args               []string
	env                map[string]string
	url                *string
	envKeysOrderedHint []string
}

// configHome is $XDG_CONFIG_HOME, by default ~/.config.
func configHome(home string) string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return dir
	}
	return filepath.Join(home, ".config")
}

// readJSONSource reads a JSON configuration file: missing contributes
// nothing; unparsable is an error and contributes nothing.
func readJSONSource(path string, source string, d *discovery) (map[string]any, bool) {
	d.paths[source] = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	var value map[string]any
	if err == nil {
		err = json.Unmarshal(data, &value)
		if err == nil && value == nil {
			err = errors.New("not a JSON object")
		}
	}
	if err != nil {
		d.errors = append(d.errors, discoveryError{Source: source, Path: &path, Error: err.Error()})
		return nil, false
	}
	return value, true
}

func stringOf(v any) (*string, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	return &s, true
}

func stringList(v any) []string {
	items, _ := v.([]any)
	out := []string{}
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, fmt.Sprint(item))
		}
	}
	return out
}

func stringMap(v any) map[string]string {
	m, _ := v.(map[string]any)
	out := map[string]string{}
	for k, item := range m {
		if s, ok := item.(string); ok {
			out[k] = s
		} else {
			out[k] = fmt.Sprint(item)
		}
	}
	return out
}

// claudeServers reads Claude Code mcpServers entries.
func claudeServers(entries any, source string) []rawServer {
	m, _ := entries.(map[string]any)
	var out []rawServer
	for name, v := range m {
		e, _ := v.(map[string]any)
		r := rawServer{name: name, source: source, args: []string{}, env: map[string]string{}}
		kind, _ := e["type"].(string)
		r.url, _ = stringOf(e["url"])
		if kind == "http" || kind == "sse" || (kind != "stdio" && r.url != nil) {
			r.remote = true
		} else {
			r.command, _ = stringOf(e["command"])
			r.args = stringList(e["args"])
			r.env = stringMap(e["env"])
		}
		out = append(out, r)
	}
	return out
}

func discoverClaude(home, workspace string, d *discovery) [][]rawServer {
	var layers [][]rawServer
	user, ok := readJSONSource(filepath.Join(home, ".claude.json"), "claude-code:user", d)
	if ok {
		layers = append(layers, claudeServers(user["mcpServers"], "claude-code:user"))
	}
	if project, ok := readJSONSource(filepath.Join(workspace, ".mcp.json"), "claude-code:project", d); ok {
		layers = append(layers, claudeServers(project["mcpServers"], "claude-code:project"))
	}
	if user != nil {
		projects, _ := user["projects"].(map[string]any)
		if p, ok := projects[workspace].(map[string]any); ok {
			layers = append(layers, claudeServers(p["mcpServers"], "claude-code:local"))
		}
	}
	return layers
}

func discoverCodex(home string, d *discovery) [][]rawServer {
	dir := os.Getenv("CODEX_HOME")
	if dir == "" {
		dir = filepath.Join(home, ".codex")
	}
	path := filepath.Join(dir, "config.toml")
	d.paths["codex:user"] = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var config map[string]any
	if err == nil {
		_, err = toml.Decode(string(data), &config)
	}
	if err != nil {
		d.errors = append(d.errors, discoveryError{Source: "codex:user", Path: &path, Error: err.Error()})
		return nil
	}
	servers, _ := config["mcp_servers"].(map[string]any)
	var out []rawServer
	for name, v := range servers {
		e, _ := v.(map[string]any)
		r := rawServer{name: name, source: "codex:user", args: []string{}, env: map[string]string{}}
		r.url, _ = stringOf(e["url"])
		if enabled, ok := e["enabled"].(bool); ok && !enabled {
			r.disabled = true
		}
		if r.url != nil {
			r.remote = true
		} else {
			r.command, _ = stringOf(e["command"])
			r.args = stringList(e["args"])
			r.env = stringMap(e["env"])
		}
		out = append(out, r)
	}
	return [][]rawServer{out}
}

func opencodeServers(config map[string]any, source string) []rawServer {
	servers, _ := config["mcp"].(map[string]any)
	var out []rawServer
	for name, v := range servers {
		e, _ := v.(map[string]any)
		r := rawServer{name: name, source: source, args: []string{}, env: map[string]string{}}
		kind, _ := e["type"].(string)
		r.url, _ = stringOf(e["url"])
		if enabled, ok := e["enabled"].(bool); ok && !enabled {
			r.disabled = true
		}
		if kind == "remote" || (kind != "local" && r.url != nil) {
			r.remote = true
		} else {
			command := stringList(e["command"])
			if len(command) > 0 {
				r.command, r.args = &command[0], command[1:]
			}
			env := e["environment"]
			if env == nil {
				env = e["env"]
			}
			r.env = stringMap(env)
		}
		out = append(out, r)
	}
	return out
}

func discoverOpencode(home, workspace string, d *discovery) [][]rawServer {
	var layers [][]rawServer
	if global, ok := readJSONSource(filepath.Join(configHome(home), "opencode", "opencode.json"), "opencode:global", d); ok {
		layers = append(layers, opencodeServers(global, "opencode:global"))
	}
	if project, ok := readJSONSource(filepath.Join(workspace, "opencode.json"), "opencode:project", d); ok {
		layers = append(layers, opencodeServers(project, "opencode:project"))
	}
	return layers
}

// resolveReferences resolves ${NAME} and ${NAME:-DEFAULT} from the
// environment. It reports whether text had a reference and the names that
// had no value and no default.
func resolveReferences(text string, lookup func(string) (string, bool)) (string, bool, []string) {
	var missing []string
	found := false
	resolved := referencePattern.ReplaceAllStringFunc(text, func(match string) string {
		found = true
		m := referencePattern.FindStringSubmatch(match)
		value, ok := lookup(m[1])
		if m[2] != "" {
			if !ok || value == "" {
				return m[2][2:]
			}
			return value
		}
		if !ok {
			missing = append(missing, m[1])
			return ""
		}
		return value
	})
	return resolved, found, missing
}

var referencePattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\}`)

// discoverServers reads an integration's configuration sources, lowest
// precedence first, and normalizes each server: a name defined in several
// sources takes the highest-precedence definition whole.
func discoverServers(integrationID, workspace string) discovery {
	d := discovery{put: host.PutToolServers{Workspace: workspace, Servers: []host.ToolServerDefinition{}, Values: map[string]map[string]string{}}, paths: map[string]string{}}
	home, err := os.UserHomeDir()
	if err != nil {
		d.errors = append(d.errors, discoveryError{Source: integrationID, Error: err.Error()})
		return d
	}
	var layers [][]rawServer
	switch integrationID {
	case "claude-code":
		layers = discoverClaude(home, workspace, &d)
	case "codex":
		layers = discoverCodex(home, &d)
	case "opencode":
		layers = discoverOpencode(home, workspace, &d)
	default:
		return d
	}
	chosen := map[string]rawServer{}
	for _, layer := range layers {
		for _, r := range layer {
			chosen[r.name] = r
		}
	}
	names := make([]string, 0, len(chosen))
	for name := range chosen {
		if !ownServer.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		r := chosen[name]
		def := host.ToolServerDefinition{Name: name, Transport: "stdio", Args: []string{}, Env: map[string]host.ToolEnv{}, Source: r.source, Disabled: r.disabled}
		values := map[string]string{}
		if !r.remote && (r.command == nil || *r.command == "") {
			// A stdio entry without a command is reported, not sent.
			server := name
			var path *string
			if p, ok := d.paths[r.source]; ok {
				path = &p
			}
			d.errors = append(d.errors, discoveryError{Source: r.source, Path: path, Server: &server, Error: "a stdio server needs a command"})
			continue
		}
		if r.remote {
			def.Transport, def.URL = "remote", r.url
		} else {
			def.Command, def.Args = r.command, r.args
			if r.command != nil {
				if resolved, found, missing := resolveReferences(*r.command, os.LookupEnv); found && len(missing) == 0 {
					values["command"] = resolved
				}
			}
			for i, arg := range r.args {
				if resolved, found, missing := resolveReferences(arg, os.LookupEnv); found && len(missing) == 0 {
					values["args."+strconv.Itoa(i)] = resolved
				}
			}
			for envName, raw := range r.env {
				resolved, found, missing := resolveReferences(raw, os.LookupEnv)
				switch {
				case !found:
					def.Env[envName] = host.ToolEnv{Source: "literal"}
					values["env."+envName] = raw
				case len(missing) > 0:
					def.Env[envName] = host.ToolEnv{Source: "missing", Variables: missing}
				default:
					def.Env[envName] = host.ToolEnv{Source: "captured"}
					values["env."+envName] = resolved
				}
			}
		}
		d.put.Servers = append(d.put.Servers, def)
		if len(values) > 0 {
			d.put.Values[name] = values
		}
	}
	return d
}
