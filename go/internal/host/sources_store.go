package host

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Capabilities (milestone 10, slice 1): sources discovered from an attached
// agent's harness configuration by the CLI, their snapshots, the owner's
// capabilities built on them, and the open list for the person's own
// machines. The v16 schema is shared with Rust.
const toolsSchema = `
CREATE TABLE tool_servers (agent_id TEXT NOT NULL REFERENCES agents(id), name TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(agent_id, name));
CREATE TABLE tool_values (agent_id TEXT NOT NULL, server TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(agent_id, server, field));
CREATE TABLE capabilities (name TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE source_access (host_id TEXT PRIMARY KEY, created_at TEXT NOT NULL);
CREATE TABLE received_calls (sender TEXT NOT NULL, call_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id));
CREATE TABLE outbound_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, call_id));
PRAGMA user_version = 16;
`

// Reasons a server is not shareable.
const (
	reasonName       = "name"
	reasonRemote     = "remote"
	reasonDisabled   = "disabled"
	reasonMissingEnv = "missing_env"
)

// ToolEnv says how one environment variable's value is obtained: literal,
// captured, or missing.
type ToolEnv struct {
	Source string `json:"source"`
	// Variables names the unresolved references of a missing entry.
	Variables []string `json:"variables,omitempty"`
}

// ToolServerDefinition is a server as the CLI discovered it. Values are
// never part of it.
type ToolServerDefinition struct {
	Name      string             `json:"name"`
	Transport string             `json:"transport"`
	Command   *string            `json:"command"`
	Args      []string           `json:"args"`
	Env       map[string]ToolEnv `json:"env"`
	URL       *string            `json:"url"`
	Source    string             `json:"source"`
	// Disabled marks a definition disabled in its harness.
	Disabled bool `json:"disabled,omitempty"`
}

// PutToolServers is PUT /v1/agents/{agent_id}/tool-servers: the agent's
// complete discovered configuration and its values.
type PutToolServers struct {
	Workspace string                       `json:"workspace"`
	Servers   []ToolServerDefinition       `json:"servers"`
	Values    map[string]map[string]string `json:"values"`
}

// UnmarshalJSON reads the definitions: each has exactly name, transport,
// command, args, env, url, and source, plus an optional boolean disabled.
func (r *PutToolServers) UnmarshalJSON(data []byte) error {
	var raw struct {
		Workspace string                       `json:"workspace"`
		Servers   []json.RawMessage            `json:"servers"`
		Values    map[string]map[string]string `json:"values"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Workspace, r.Values, r.Servers = raw.Workspace, raw.Values, []ToolServerDefinition{}
	required := []string{"name", "transport", "command", "args", "env", "url", "source"}
	for _, item := range raw.Servers {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil || fields == nil {
			return ErrInvalid
		}
		for _, field := range required {
			if _, ok := fields[field]; !ok {
				return fmt.Errorf("%w: a server definition needs %s", ErrInvalid, field)
			}
		}
		for field, value := range fields {
			if field == "disabled" {
				if string(value) != "true" && string(value) != "false" {
					return fmt.Errorf("%w: disabled is a boolean", ErrInvalid)
				}
				continue
			}
			if !slices.Contains(required, field) {
				return fmt.Errorf("%w: unknown server definition field %q", ErrInvalid, field)
			}
		}
		var d ToolServerDefinition
		if err := json.Unmarshal(item, &d); err != nil {
			return ErrInvalid
		}
		// Each env entry is exactly {source} for literal or captured, or
		// {source: missing, variables} with variables.
		var env map[string]map[string]json.RawMessage
		if err := json.Unmarshal(fields["env"], &env); err != nil {
			return ErrInvalid
		}
		for name, entry := range env {
			e := d.Env[name]
			want := 1
			if e.Source == "missing" {
				want = 2
				if len(e.Variables) == 0 {
					return fmt.Errorf("%w: missing env entry %s needs variables", ErrInvalid, name)
				}
				for _, v := range e.Variables {
					if v == "" {
						return fmt.Errorf("%w: invalid variable name in env entry %s", ErrInvalid, name)
					}
				}
			}
			if _, ok := entry["source"]; !ok || len(entry) != want || (want == 2 && entry["variables"] == nil) {
				return fmt.Errorf("%w: invalid env entry %s", ErrInvalid, name)
			}
		}
		r.Servers = append(r.Servers, d)
	}
	return nil
}

// toolServerRecord is tool_servers.record: the definition and the snapshot.
type toolServerRecord struct {
	ToolServerDefinition
	Workspace  string   `json:"workspace"`
	Shareable  bool     `json:"shareable"`
	Reason     *string  `json:"reason"`
	MissingEnv []string `json:"missing_env"`
	toolSnapshotState
}

// toolSnapshotState is a source's or capability's own snapshot and health.
type toolSnapshotState struct {
	Tools         []SnapshotTool     `json:"tools"`
	Resources     []SnapshotResource `json:"resources"`
	SnapshotAt    *string            `json:"snapshot_at"`
	SnapshotError *string            `json:"snapshot_error"`
	// StartFailedAt is the latest failed instance start; AuthErrorAt the
	// latest JSON-RPC error that suggests authentication.
	StartFailedAt *string `json:"start_failed_at"`
	AuthErrorAt   *string `json:"auth_error_at"`
}

func (r toolServerRecord) MarshalJSON() ([]byte, error) {
	type plain toolServerRecord
	if r.Args == nil {
		r.Args = []string{}
	}
	if r.Env == nil {
		r.Env = map[string]ToolEnv{}
	}
	if r.MissingEnv == nil {
		r.MissingEnv = []string{}
	}
	data, err := json.Marshal(struct {
		plain
		Disabled bool `json:"disabled"`
	}{plain(r), r.Disabled})
	return data, err
}

// SourceView is SERVER in GET /v1/sources.
type SourceView struct {
	Name          string             `json:"name"`
	Transport     string             `json:"transport"`
	Command       *string            `json:"command"`
	Args          []string           `json:"args"`
	Env           map[string]ToolEnv `json:"env"`
	URL           *string            `json:"url"`
	Source        string             `json:"source"`
	Disabled      bool               `json:"disabled"`
	Shareable     bool               `json:"shareable"`
	Reason        *string            `json:"reason"`
	MissingEnv    []string           `json:"missing_env"`
	Tools         []SnapshotTool     `json:"tools"`
	Resources     []SnapshotResource `json:"resources"`
	SnapshotAt    *string            `json:"snapshot_at"`
	SnapshotError *string            `json:"snapshot_error"`
	StartFailedAt *string            `json:"start_failed_at"`
	AuthErrorAt   *string            `json:"auth_error_at"`
	Capabilities  []string           `json:"capabilities"`
}

func emptySnapshot(st toolSnapshotState) toolSnapshotState {
	if st.Tools == nil {
		st.Tools = []SnapshotTool{}
	}
	if st.Resources == nil {
		st.Resources = []SnapshotResource{}
	}
	return st
}

func sourceView(r toolServerRecord) SourceView {
	st := emptySnapshot(r.toolSnapshotState)
	v := SourceView{Name: r.Name, Transport: r.Transport, Command: r.Command, Args: r.Args, Env: r.Env, URL: r.URL, Source: r.Source, Disabled: r.Disabled,
		Shareable: r.Shareable, Reason: r.Reason, MissingEnv: r.MissingEnv, Tools: st.Tools, Resources: st.Resources, SnapshotAt: st.SnapshotAt,
		SnapshotError: st.SnapshotError, StartFailedAt: st.StartFailedAt, AuthErrorAt: st.AuthErrorAt, Capabilities: []string{}}
	if v.Args == nil {
		v.Args = []string{}
	}
	if v.Env == nil {
		v.Env = map[string]ToolEnv{}
	}
	if v.MissingEnv == nil {
		v.MissingEnv = []string{}
	}
	return v
}

// AgentRef names an agent in GET /v1/sources.
type AgentRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AgentSources is AGENT in GET /v1/sources, and the PUT's answer.
type AgentSources struct {
	Agent     AgentRef     `json:"agent"`
	Workspace *string      `json:"workspace"`
	Servers   []SourceView `json:"servers"`
}

// SourcesListing is GET /v1/sources.
type SourcesListing struct {
	Agents []AgentSources `json:"agents"`
	OpenTo []string       `json:"open_to"`
}

// toolState serializes discovery and snapshots per agent.
type toolState struct {
	mu     sync.Mutex
	agents map[string]*sync.Mutex
}

func (s *Store) agentToolLock(agent string) *sync.Mutex {
	s.toolState.mu.Lock()
	defer s.toolState.mu.Unlock()
	if s.toolState.agents == nil {
		s.toolState.agents = map[string]*sync.Mutex{}
	}
	m := s.toolState.agents[agent]
	if m == nil {
		m = &sync.Mutex{}
		s.toolState.agents[agent] = m
	}
	return m
}

func migrateTools(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, strings.ReplaceAll(toolsSchema, "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS "))
	return err
}

// references matches ${NAME} and ${NAME:-DEFAULT}.
var references = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-[^}]*)?\}`)

func referencedNames(text string) []string {
	var names []string
	for _, m := range references.FindAllStringSubmatch(text, -1) {
		names = append(names, m[1])
	}
	return names
}

// shareability decides whether a server may be shared, and why not: an
// invalid name, a remote transport, a disabled definition, or variables
// without values.
func shareability(d ToolServerDefinition, values map[string]string) (bool, *string, []string) {
	missing := map[string]bool{}
	for _, e := range d.Env {
		if e.Source == "missing" {
			for _, name := range e.Variables {
				missing[name] = true
			}
		}
	}
	if d.Command != nil {
		if _, ok := values["command"]; !ok {
			for _, name := range referencedNames(*d.Command) {
				missing[name] = true
			}
		}
	}
	for i, arg := range d.Args {
		if _, ok := values["args."+strconv.Itoa(i)]; !ok {
			for _, name := range referencedNames(arg) {
				missing[name] = true
			}
		}
	}
	names := sortedKeys(missing)
	reason := ""
	switch {
	case !membership.ValidName(d.Name):
		reason = reasonName
	case d.Transport != "stdio":
		reason = reasonRemote
	case d.Disabled:
		reason = reasonDisabled
	case len(names) > 0:
		reason = reasonMissingEnv
	case d.Command == nil || *d.Command == "":
		reason = reasonMissingEnv
	}
	if reason == "" {
		return true, nil, names
	}
	return false, &reason, names
}

func validServerLabel(name string) bool {
	if name == "" || len(name) > 256 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validateToolServers(r PutToolServers) error {
	if !filepath.IsAbs(r.Workspace) || strings.ContainsRune(r.Workspace, 0) {
		return fmt.Errorf("%w: workspace must be an absolute path", ErrInvalid)
	}
	if len(r.Servers) > 1000 {
		return fmt.Errorf("%w: at most 1000 servers", ErrInvalid)
	}
	seen := map[string]ToolServerDefinition{}
	for _, d := range r.Servers {
		if !validServerLabel(d.Name) {
			return fmt.Errorf("%w: invalid server name %q", ErrInvalid, d.Name)
		}
		if _, dup := seen[d.Name]; dup {
			return fmt.Errorf("%w: server %q is listed twice", ErrInvalid, d.Name)
		}
		seen[d.Name] = d
		if d.Transport != "stdio" && d.Transport != "remote" {
			return fmt.Errorf("%w: a server's transport is stdio or remote", ErrInvalid)
		}
		if len(d.Args) > 1000 {
			return fmt.Errorf("%w: too many args", ErrInvalid)
		}
		for name, e := range d.Env {
			if name == "" || strings.ContainsAny(name, "=\x00") {
				return fmt.Errorf("%w: invalid environment variable name %q", ErrInvalid, name)
			}
			if e.Source != "literal" && e.Source != "captured" && e.Source != "missing" {
				return fmt.Errorf("%w: an env source is literal, captured, or missing", ErrInvalid)
			}
		}
	}
	for server, fields := range r.Values {
		d, ok := seen[server]
		if !ok {
			return fmt.Errorf("%w: values name unknown server %q", ErrInvalid, server)
		}
		for field, value := range fields {
			if len(value) > 65536 || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
				return fmt.Errorf("%w: invalid value for %s %s", ErrInvalid, server, field)
			}
			switch {
			case field == "command":
			case strings.HasPrefix(field, "env."):
				if e, ok := d.Env[strings.TrimPrefix(field, "env.")]; !ok || e.Source == "missing" {
					return fmt.Errorf("%w: value %s of %s names no literal or captured env entry", ErrInvalid, field, server)
				}
			case strings.HasPrefix(field, "args."):
				n, err := strconv.Atoi(strings.TrimPrefix(field, "args."))
				if err != nil || n < 0 || n >= len(d.Args) || strconv.Itoa(n) != strings.TrimPrefix(field, "args.") {
					return fmt.Errorf("%w: value %s of %s names no argument", ErrInvalid, field, server)
				}
			default:
				return fmt.Errorf("%w: a value's field is env.NAME, command, or args.N", ErrInvalid)
			}
		}
	}
	return nil
}

func readToolServer(ctx context.Context, q dbQuerier, agent, name string) (toolServerRecord, error) {
	return readJSON[toolServerRecord](q.QueryRowContext(ctx, `SELECT record FROM tool_servers WHERE agent_id = ? AND name = ?`, agent, name))
}

func toolValues(ctx context.Context, q queryer, agent, server string) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT field, value FROM tool_values WHERE agent_id = ? AND server = ?`, agent, server)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var field, value string
		if err = rows.Scan(&field, &value); err != nil {
			return nil, err
		}
		out[field] = value
	}
	return out, rows.Err()
}

// PutToolServers replaces an agent's server definitions and values in one
// transaction, then snapshots each shareable source and the capabilities
// with their own credential built on them, and returns the agent.
func (s *Store) PutToolServers(ctx context.Context, agentID string, r PutToolServers) (AgentSources, error) {
	if err := validateToolServers(r); err != nil {
		return AgentSources{}, err
	}
	if _, err := s.Agent(ctx, agentID); err != nil {
		return AgentSources{}, err
	}
	lock := s.agentToolLock(agentID)
	lock.Lock()
	defer lock.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AgentSources{}, err
	}
	defer tx.Rollback()
	old := map[string]toolServerRecord{}
	olds, err := records[toolServerRecord](ctx, tx, `SELECT record FROM tool_servers WHERE agent_id = ?`, agentID)
	if err != nil {
		return AgentSources{}, err
	}
	// changed collects the servers dropped, or with a new definition or new
	// values: only their running instances are retired.
	changed := map[string]bool{}
	launchOf := func(d ToolServerDefinition, values map[string]string) string {
		data, _ := json.Marshal(struct {
			D ToolServerDefinition
			V map[string]string
		}{d, values})
		return string(data)
	}
	for _, o := range olds {
		old[o.Name] = o
		values, err := toolValues(ctx, tx, agentID, o.Name)
		if err != nil {
			return AgentSources{}, err
		}
		changed[o.Name] = true
		for _, d := range r.Servers {
			if d.Name == o.Name && launchOf(d, nonNil(r.Values[d.Name])) == launchOf(o.ToolServerDefinition, values) {
				delete(changed, o.Name)
			}
		}
	}
	// A dropped server's capabilities remain, and become unavailable.
	for _, q := range []string{`DELETE FROM tool_servers WHERE agent_id = ?`, `DELETE FROM tool_values WHERE agent_id = ?`} {
		if _, err = tx.ExecContext(ctx, q, agentID); err != nil {
			return AgentSources{}, err
		}
	}
	for _, d := range r.Servers {
		values := r.Values[d.Name]
		rec := toolServerRecord{ToolServerDefinition: d, Workspace: r.Workspace}
		if rec.Args == nil {
			rec.Args = []string{}
		}
		if rec.Env == nil {
			rec.Env = map[string]ToolEnv{}
		}
		rec.Shareable, rec.Reason, rec.MissingEnv = shareability(d, values)
		if o, ok := old[d.Name]; ok {
			// The previous snapshot stays until a new one succeeds.
			rec.toolSnapshotState = o.toolSnapshotState
		}
		if err = putJSON(ctx, tx, `INSERT INTO tool_servers (record, agent_id, name) VALUES (?, ?, ?)`, rec, agentID, d.Name); err != nil {
			return AgentSources{}, err
		}
		for field, value := range values {
			if _, err = tx.ExecContext(ctx, `INSERT INTO tool_values VALUES (?, ?, ?, ?)`, agentID, d.Name, field, value); err != nil {
				return AgentSources{}, err
			}
		}
	}
	if err = appendEvent(ctx, tx, "sources.discovered", agentID, timestamp(time.Now())); err != nil {
		return AgentSources{}, err
	}
	if err = tx.Commit(); err != nil {
		return AgentSources{}, err
	}
	// Instances started from an old definition take no new calls; those of
	// unchanged sources keep running until their idle stop.
	s.retireInstances(agentID, changed)
	if err = s.snapshotAgent(ctx, agentID); err != nil {
		return AgentSources{}, err
	}
	all, err := s.Sources(ctx, agentID)
	if err != nil || len(all) == 0 {
		return AgentSources{}, err
	}
	return all[0], nil
}

// snapshotTarget is one source, or one capability's own instance, to
// snapshot.
type snapshotTarget struct {
	server string
	own    *ownCredential
}

// snapshotAgent snapshots every shareable source of an agent and the
// capabilities with their own credential built on them, concurrently, and
// records each outcome.
func (s *Store) snapshotAgent(ctx context.Context, agentID string) error {
	servers, err := records[toolServerRecord](ctx, s.db, `SELECT record FROM tool_servers WHERE agent_id = ? ORDER BY name`, agentID)
	if err != nil {
		return err
	}
	capabilities, err := records[capabilityRecord](ctx, s.db, `SELECT record FROM capabilities ORDER BY name`)
	if err != nil {
		return err
	}
	var targets []snapshotTarget
	for _, srv := range servers {
		if !srv.Shareable {
			continue
		}
		targets = append(targets, snapshotTarget{server: srv.Name})
		for _, c := range capabilities {
			if c.AgentID == agentID && c.Source.Server == srv.Name && c.ownInstance() {
				targets = append(targets, snapshotTarget{server: srv.Name, own: c.credential()})
			}
		}
	}
	var wg sync.WaitGroup
	results := make([]error, len(targets))
	snaps := make([]toolSnapshot, len(targets))
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spec, err := s.toolLaunch(ctx, s.db, agentID, t.server, t.own)
			if err == nil {
				snaps[i], err = takeSnapshot(context.WithoutCancel(ctx), spec)
			}
			results[i] = err
		}()
	}
	wg.Wait()
	for i, t := range targets {
		if err := s.recordSnapshot(context.WithoutCancel(ctx), agentID, t, snaps[i], results[i]); err != nil {
			return err
		}
	}
	return nil
}

// recordSnapshot stores a snapshot, or on failure its error, keeping the
// previous snapshot.
func (s *Store) recordSnapshot(ctx context.Context, agentID string, t snapshotTarget, snap toolSnapshot, failure error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := timestamp(time.Now())
	update := func(state *toolSnapshotState) {
		if failure != nil {
			message := failure.Error()
			state.SnapshotError = &message
			return
		}
		state.Tools, state.Resources, state.SnapshotAt, state.SnapshotError = snap.Tools, snap.Resources, &now, nil
	}
	if t.own == nil {
		rec, err := readToolServer(ctx, tx, agentID, t.server)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		update(&rec.toolSnapshotState)
		if err = putJSON(ctx, tx, `UPDATE tool_servers SET record = ? WHERE agent_id = ? AND name = ?`, rec, agentID, t.server); err != nil {
			return err
		}
		if failure != nil {
			if err = appendEvent(ctx, tx, "sources.snapshot_failed", agentID+"/"+t.server, now); err != nil {
				return err
			}
		}
	} else {
		c, err := readCapability(ctx, tx, t.own.capability)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if c.Snapshot == nil {
			c.Snapshot = &toolSnapshotState{}
		}
		update(c.Snapshot)
		if err = putJSON(ctx, tx, `UPDATE capabilities SET record = ? WHERE name = ?`, c, c.Name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ToolEnvFile is $XDG_CONFIG_HOME/peerspan/env, by default under ~/.config.
func ToolEnvFile() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "peerspan", "env")
}

// envFileTooOpen reports whether the environment file exists with
// permissions wider than 0600.
func envFileTooOpen(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm()&0o077 != 0
}

// readEnvFile reads NAME=VALUE lines, skipping blank lines and # comments.
func readEnvFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, value, ok := strings.Cut(trimmed, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsRune(value, 0) {
			continue
		}
		out = append(out, name+"="+value)
	}
	return out, scanner.Err()
}

// ownCredential is a capability's own credential context: its own instance,
// with its env_file applied whole and args replacing the source's.
type ownCredential struct {
	capability string
	envFile    *string
	args       []string
}

// toolLogPath is STATE/tool-logs/AGENT_ID/SERVER.log, or
// SERVER@CAPABILITY.log for a capability's own instance.
func (s *Store) toolLogPath(agentID, server, capability string) string {
	name := server
	if capability != "" {
		name += "@" + capability
	}
	return filepath.Join(s.dir, "tool-logs", agentID, name+".log")
}

// toolLaunch builds how to start a source's instance, or a capability's own:
// the stored command and args with values substituted (a capability's args
// replacing the source's), an environment of the daemon's PATH and HOME, the
// definition's env with its values, the environment file filtered to the
// definition's names, and a capability's whole env_file, in the agent's
// workspace.
func (s *Store) toolLaunch(ctx context.Context, q dbQuerier, agentID, server string, own *ownCredential) (launchSpec, error) {
	capability := ""
	if own != nil {
		capability = own.capability
	}
	rec, err := readToolServer(ctx, q, agentID, server)
	if err != nil {
		return launchSpec{}, err
	}
	values, err := toolValues(ctx, q, agentID, server)
	if err != nil {
		return launchSpec{}, err
	}
	spec := launchSpec{Dir: rec.Workspace, LogPath: s.toolLogPath(agentID, server, capability)}
	if rec.Command != nil {
		spec.Command = *rec.Command
	}
	if v, ok := values["command"]; ok {
		spec.Command = v
	}
	spec.Args = make([]string, len(rec.Args))
	for i, arg := range rec.Args {
		spec.Args[i] = arg
		if v, ok := values["args."+strconv.Itoa(i)]; ok {
			spec.Args[i] = v
		}
	}
	env := map[string]string{}
	var order []string
	set := func(name, value string) {
		if _, ok := env[name]; !ok {
			order = append(order, name)
		}
		env[name] = value
	}
	for _, name := range []string{"PATH", "HOME"} {
		if v, ok := os.LookupEnv(name); ok {
			set(name, v)
		}
	}
	for _, name := range sortedKeys(rec.Env) {
		if v, ok := values["env."+name]; ok {
			set(name, v)
		}
	}
	apply := func(lines []string) {
		for _, line := range lines {
			name, value, _ := strings.Cut(line, "=")
			set(name, value)
		}
	}
	// The environment file supplies only variables the definition names.
	if path := ToolEnvFile(); path != "" && !envFileTooOpen(path) {
		if lines, err := readEnvFile(path); err == nil {
			for _, line := range lines {
				name, value, _ := strings.Cut(line, "=")
				if _, named := rec.Env[name]; named {
					set(name, value)
				}
			}
		}
	}
	if own != nil {
		if own.args != nil {
			spec.Args = append([]string{}, own.args...)
		}
		if own.envFile != nil {
			lines, err := readEnvFile(*own.envFile)
			if err != nil {
				return launchSpec{}, fmt.Errorf("the capability's env file cannot be read: %w", err)
			}
			apply(lines)
		}
	}
	for _, name := range order {
		spec.Env = append(spec.Env, name+"="+env[name])
	}
	return spec, nil
}

// Sources lists every agent, or one by ID, with its sources and the names of
// this host's capabilities built on each.
func (s *Store) Sources(ctx context.Context, agentID string) ([]AgentSources, error) {
	agents, err := s.Agents(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Name != agents[j].Name {
			return agents[i].Name < agents[j].Name
		}
		return agents[i].ID < agents[j].ID
	})
	capabilities, err := records[capabilityRecord](ctx, s.db, `SELECT record FROM capabilities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := []AgentSources{}
	for _, a := range agents {
		if agentID != "" && a.ID != agentID {
			continue
		}
		at := AgentSources{Agent: AgentRef{ID: a.ID, Name: a.Name}, Servers: []SourceView{}}
		servers, err := records[toolServerRecord](ctx, s.db, `SELECT record FROM tool_servers WHERE agent_id = ? ORDER BY name`, a.ID)
		if err != nil {
			return nil, err
		}
		for _, srv := range servers {
			if at.Workspace == nil {
				w := srv.Workspace
				at.Workspace = &w
			}
			view := sourceView(srv)
			for _, c := range capabilities {
				if c.AgentID == a.ID && c.Source.Server == srv.Name {
					view.Capabilities = append(view.Capabilities, c.Name)
				}
			}
			at.Servers = append(at.Servers, view)
		}
		out = append(out, at)
	}
	if agentID != "" && len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// OwnCapabilityRule is a capability rule of this host's person's stored
// policy in one network.
type OwnCapabilityRule struct {
	NetworkID string
	membership.CapabilityRule
}

// ownCapabilityRules lists the capability rules of this host's person's
// stored policy in each network where this host is bound.
func (s *Store) ownCapabilityRules(ctx context.Context, q dbQuerier) ([]OwnCapabilityRule, error) {
	own, err := membershipsOf(ctx, q, s.identity.ID)
	if err != nil {
		return nil, err
	}
	out := []OwnCapabilityRule{}
	for _, n := range own {
		if n.member.PersonID == nil {
			continue
		}
		g, err := s.loadGovernance(ctx, q, n.network)
		if err != nil {
			return nil, err
		}
		key, ok := g.personKey(*n.member.PersonID)
		if !ok {
			continue
		}
		p, ok := g.storedPolicy(key)
		if !ok {
			continue
		}
		for _, r := range p.CapabilityRules {
			out = append(out, OwnCapabilityRule{NetworkID: n.network, CapabilityRule: r})
		}
	}
	return out, nil
}

func nonNil(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return values
}

// agentsIn lists local agents by name, within a transaction.
func agentsIn(ctx context.Context, q queryer) ([]localAgent, error) {
	rows, err := q.QueryContext(ctx, "SELECT id, name FROM agents ORDER BY name, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []localAgent
	for rows.Next() {
		var a localAgent
		if err = rows.Scan(&a.id, &a.name); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// OpenTo is one entry of this host's source open list.
type OpenTo struct {
	HostID    string `json:"host_id"`
	CreatedAt string `json:"created_at"`
}

// openList is this host's open list: host IDs and "*", "*" first.
func openList(ctx context.Context, q queryer) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT host_id FROM source_access ORDER BY host_id = '*' DESC, host_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// openTo reports whether this host's open list covers a host.
func openTo(ctx context.Context, q dbQuerier, host string) (bool, error) {
	var found bool
	err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM source_access WHERE host_id = ? OR host_id = '*')`, host).Scan(&found)
	return found, err
}

// OpenSources adds a host, or "*", to the open list. A host must be bound
// to this host's person in at least one network map, and is never this
// host. It reports whether the entry was added.
func (s *Store) OpenSources(ctx context.Context, host string) (OpenTo, bool, error) {
	if host != "*" {
		if !validID(host, "host", 32) || host == s.identity.ID {
			return OpenTo{}, false, fmt.Errorf("%w: give another host ID, or * for all", ErrInvalid)
		}
		var bound bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM network_members a JOIN network_members b ON a.network_id = b.network_id WHERE a.host_id = ? AND b.host_id = ? AND json_extract(a.record, '$.person_id') IS NOT NULL AND json_extract(a.record, '$.person_id') = json_extract(b.record, '$.person_id'))`, s.identity.ID, host).Scan(&bound); err != nil {
			return OpenTo{}, false, err
		}
		if !bound {
			return OpenTo{}, false, fmt.Errorf("%w: host %s is not bound to this host's person in any network", ErrInvalid, host)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OpenTo{}, false, err
	}
	defer tx.Rollback()
	var entry OpenTo
	err = tx.QueryRowContext(ctx, `SELECT host_id, created_at FROM source_access WHERE host_id = ?`, host).Scan(&entry.HostID, &entry.CreatedAt)
	if err == nil {
		return entry, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return OpenTo{}, false, err
	}
	entry = OpenTo{HostID: host, CreatedAt: timestamp(time.Now())}
	if _, err = tx.ExecContext(ctx, `INSERT INTO source_access VALUES (?, ?)`, entry.HostID, entry.CreatedAt); err != nil {
		return entry, false, err
	}
	if err = appendEvent(ctx, tx, "sources.opened", host, entry.CreatedAt); err != nil {
		return entry, false, err
	}
	return entry, true, tx.Commit()
}

// CloseSources removes a host, or "*", from the open list, reporting how
// many entries were removed. Removing "*" leaves hosts listed one by one.
func (s *Store) CloseSources(ctx context.Context, host string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM source_access WHERE host_id = ?`, host)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	if err != nil || removed == 0 {
		return 0, err
	}
	if err = appendEvent(ctx, tx, "sources.closed", host, timestamp(time.Now())); err != nil {
		return 0, err
	}
	return removed, tx.Commit()
}

func localSourceRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("PUT /v1/agents/{id}/tool-servers", func(w http.ResponseWriter, r *http.Request) {
		var req PutToolServers
		if !decode(w, r, &req, "workspace", "servers", "values") {
			return
		}
		result, err := store.PutToolServers(r.Context(), r.PathValue("id"), req)
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("GET /v1/sources", func(w http.ResponseWriter, r *http.Request) {
		agent := ""
		if name := r.URL.Query().Get("agent"); name != "" {
			var id string
			err := store.db.QueryRowContext(r.Context(), `SELECT id FROM agents WHERE name = ? OR id = ?`, name, name).Scan(&id)
			if err != nil {
				respond(w, 0, nil, fmt.Errorf("%w: no local agent %q", ErrNotFound, name))
				return
			}
			agent = id
		}
		agents, err := store.Sources(r.Context(), agent)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		open, err := openList(r.Context(), store.db)
		respond(w, http.StatusOK, SourcesListing{Agents: agents, OpenTo: open}, err)
	})
	mux.HandleFunc("POST /v1/sources/open-to", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			HostID string `json:"host_id"`
		}
		if !decode(w, r, &req, "host_id") {
			return
		}
		entry, added, err := store.OpenSources(r.Context(), req.HostID)
		status := http.StatusOK
		if added {
			status = http.StatusCreated
		}
		respond(w, status, entry, err)
	})
	mux.HandleFunc("DELETE /v1/sources/open-to/{host}", func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		removed, err := store.CloseSources(r.Context(), host)
		respond(w, http.StatusOK, map[string]any{"host_id": host, "removed": removed}, err)
	})
}
