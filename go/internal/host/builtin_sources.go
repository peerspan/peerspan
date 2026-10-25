package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Built-in sources (capabilities slice 3): adapters Peerspan ships and the
// CLI detects on the host, addressed builtin/NAME and stored apart from
// agents' sources. The only adapter is gh. Their values are tool_values
// rows with agent_id builtin.

// ghWarningBudget bounds the bound warnings' checks in all.
const ghWarningBudget = 40 * time.Second

// builtinAgent is the agent position of every built-in source.
const builtinAgent = "builtin"

const builtinSchema = `
CREATE TABLE builtin_sources (name TEXT PRIMARY KEY, record TEXT NOT NULL);
PRAGMA user_version = 21;
`

func migrateBuiltin(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, strings.ReplaceAll(builtinSchema, "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS "))
	return err
}

// Reasons a built-in source is not shareable, beside name and missing_env.
const (
	reasonVersion          = "version"
	reasonNotAuthenticated = "not_authenticated"
)

// BuiltinDefinition is a built-in source as the CLI discovered it.
type BuiltinDefinition struct {
	Name          string             `json:"name"`
	Adapter       string             `json:"adapter"`
	Command       string             `json:"command"`
	Version       *string            `json:"version"`
	Host          string             `json:"host"`
	Account       *string            `json:"account"`
	Authenticated bool               `json:"authenticated"`
	Env           map[string]ToolEnv `json:"env"`
	Disabled      bool               `json:"disabled"`
}

// GHReach is what a gh credential reaches, from the reach check; never the
// token.
type GHReach struct {
	Account   *string  `json:"account"`
	Host      string   `json:"host"`
	TokenType string   `json:"token_type"`
	Scopes    []string `json:"scopes"`
	CheckedAt string   `json:"checked_at"`
	Error     *string  `json:"error"`
}

// builtinRecord is builtin_sources.record.
type builtinRecord struct {
	BuiltinDefinition
	Shareable  bool     `json:"shareable"`
	Reason     *string  `json:"reason"`
	MissingEnv []string `json:"missing_env"`
	toolSnapshotState
}

// UnmarshalJSON reads a record in this host's shape or as the Rust host
// writes it (a ServerRecord with the definition under builtin and the
// snapshot nested), so a database moved between the two reads either way.
func (b *builtinRecord) UnmarshalJSON(data []byte) error {
	type plain builtinRecord
	var probe struct {
		Builtin *BuiltinDefinition `json:"builtin"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if probe.Builtin == nil {
		return json.Unmarshal(data, (*plain)(b))
	}
	var r struct {
		Shareable  bool     `json:"shareable"`
		Reason     *string  `json:"reason"`
		MissingEnv []string `json:"missing_env"`
		Snapshot   *struct {
			Tools     []SnapshotTool     `json:"tools"`
			Resources []SnapshotResource `json:"resources"`
			TakenAt   string             `json:"taken_at"`
			Reach     *GHReach           `json:"reach"`
		} `json:"snapshot"`
		SnapshotError *string `json:"snapshot_error"`
		Health        struct {
			StartFailedAt *string `json:"start_failed_at"`
			AuthErrorAt   *string `json:"auth_error_at"`
		} `json:"health"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	*b = builtinRecord{BuiltinDefinition: *probe.Builtin, Shareable: r.Shareable, Reason: r.Reason, MissingEnv: r.MissingEnv}
	if r.Snapshot != nil {
		at := r.Snapshot.TakenAt
		b.Tools, b.Resources, b.SnapshotAt, b.Reach = r.Snapshot.Tools, r.Snapshot.Resources, &at, r.Snapshot.Reach
	}
	b.SnapshotError, b.StartFailedAt, b.AuthErrorAt = r.SnapshotError, r.Health.StartFailedAt, r.Health.AuthErrorAt
	return nil
}

// PutBuiltinSources is PUT /v1/builtin-sources.
type PutBuiltinSources struct {
	Sources []BuiltinDefinition          `json:"sources"`
	Values  map[string]map[string]string `json:"values"`
}

// UnmarshalJSON reads the definitions strictly: exactly the definition
// fields.
func (r *PutBuiltinSources) UnmarshalJSON(data []byte) error {
	var raw struct {
		Sources []json.RawMessage            `json:"sources"`
		Values  map[string]map[string]string `json:"values"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Values, r.Sources = raw.Values, []BuiltinDefinition{}
	fieldsWanted := []string{"name", "adapter", "command", "version", "host", "account", "authenticated", "env", "disabled"}
	for _, item := range raw.Sources {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil || fields == nil {
			return ErrInvalid
		}
		for _, f := range fieldsWanted {
			if _, ok := fields[f]; !ok {
				return fmt.Errorf("%w: a built-in source definition needs %s", ErrInvalid, f)
			}
		}
		for f := range fields {
			if !slices.Contains(fieldsWanted, f) {
				return fmt.Errorf("%w: unknown built-in source field %q", ErrInvalid, f)
			}
		}
		for _, f := range []string{"authenticated", "disabled"} {
			if v := string(bytes.TrimSpace(fields[f])); v != "true" && v != "false" {
				return fmt.Errorf("%w: %s is a boolean", ErrInvalid, f)
			}
		}
		for _, f := range []string{"name", "adapter", "command", "host"} {
			var s string
			if json.Unmarshal(fields[f], &s) != nil {
				return fmt.Errorf("%w: %s is a string", ErrInvalid, f)
			}
		}
		var d BuiltinDefinition
		if err := json.Unmarshal(item, &d); err != nil {
			return ErrInvalid
		}
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
			}
			if _, ok := entry["source"]; !ok || len(entry) != want || (want == 2 && entry["variables"] == nil) {
				return fmt.Errorf("%w: invalid env entry %s", ErrInvalid, name)
			}
		}
		r.Sources = append(r.Sources, d)
	}
	return nil
}

func validateBuiltinSources(r PutBuiltinSources) error {
	if len(r.Sources) > 100 {
		return fmt.Errorf("%w: at most 100 built-in sources", ErrInvalid)
	}
	seen := map[string]BuiltinDefinition{}
	for _, d := range r.Sources {
		if !validServerLabel(d.Name) {
			return fmt.Errorf("%w: invalid built-in source name %q", ErrInvalid, d.Name)
		}
		if _, dup := seen[d.Name]; dup {
			return fmt.Errorf("%w: built-in source %q is listed twice", ErrInvalid, d.Name)
		}
		seen[d.Name] = d
		if d.Adapter != "gh" {
			return fmt.Errorf("%w: the only built-in adapter is gh", ErrInvalid)
		}
		if !filepath.IsAbs(d.Command) || strings.ContainsRune(d.Command, 0) {
			return fmt.Errorf("%w: command is an absolute path", ErrInvalid)
		}
		if d.Host != ghHost {
			return fmt.Errorf("%w: host is github.com", ErrInvalid)
		}
		if (d.Version != nil && !validServerLabel(*d.Version)) || (d.Account != nil && !validServerLabel(*d.Account)) {
			return fmt.Errorf("%w: invalid version or account", ErrInvalid)
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
			return fmt.Errorf("%w: values name unknown built-in source %q", ErrInvalid, server)
		}
		for field, value := range fields {
			if len(value) > 65536 || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
				return fmt.Errorf("%w: invalid value for %s %s", ErrInvalid, server, field)
			}
			e, ok := d.Env[strings.TrimPrefix(field, "env.")]
			if !strings.HasPrefix(field, "env.") || !ok || e.Source == "missing" {
				return fmt.Errorf("%w: value %s of %s names no literal or captured env entry", ErrInvalid, field, server)
			}
		}
	}
	return nil
}

// versionBelow reports whether X.Y.Z is below min, numerically.
func versionBelow(version, min string) bool {
	parse := func(v string) ([3]int, bool) {
		var out [3]int
		parts := strings.Split(v, ".")
		if len(parts) != 3 {
			return out, false
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || p == "" || strings.ContainsAny(p, "+-") {
				return out, false
			}
			out[i] = n
		}
		return out, true
	}
	v, ok := parse(version)
	m, _ := parse(min)
	if !ok {
		return true
	}
	for i := range v {
		if v[i] != m[i] {
			return v[i] < m[i]
		}
	}
	return false
}

// builtinShareability decides whether a built-in source may be shared:
// name, version, not_authenticated, and missing_env, in that order.
func builtinShareability(d BuiltinDefinition, agentServers map[string]bool) (bool, *string, []string) {
	missing := map[string]bool{}
	for _, e := range d.Env {
		if e.Source == "missing" {
			for _, name := range e.Variables {
				missing[name] = true
			}
		}
	}
	names := sortedKeys(missing)
	reason := ""
	switch {
	case !membership.ValidName(d.Name) || agentServers[d.Name]:
		reason = reasonName
	case d.Version == nil || versionBelow(*d.Version, ghMinVersion):
		reason = reasonVersion
	case !d.Authenticated:
		reason = reasonNotAuthenticated
	case len(names) > 0:
		reason = reasonMissingEnv
	}
	if reason == "" {
		return true, nil, names
	}
	return false, &reason, names
}

// builtinAgentServers lists the tool server names of an agent named
// builtin, if one exists.
func builtinAgentServers(ctx context.Context, q queryer) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT t.name FROM tool_servers t JOIN agents a ON a.id = t.agent_id WHERE a.name = ?`, builtinAgent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func readBuiltin(ctx context.Context, q dbQuerier, name string) (builtinRecord, error) {
	return readJSON[builtinRecord](q.QueryRowContext(ctx, `SELECT record FROM builtin_sources WHERE name = ?`, name))
}

// asToolServer presents a built-in source as a source record, so every
// path keyed by agent and server works for it.
func (b builtinRecord) asToolServer() toolServerRecord {
	command := b.Command
	rec := toolServerRecord{
		ToolServerDefinition: ToolServerDefinition{Name: b.Name, Transport: "stdio", Command: &command, Args: []string{}, Env: b.Env, Source: builtinAgent, Disabled: b.Disabled},
		Shareable:            b.Shareable, Reason: b.Reason, MissingEnv: b.MissingEnv, toolSnapshotState: b.toolSnapshotState,
		builtin: &b,
	}
	if rec.Env == nil {
		rec.Env = map[string]ToolEnv{}
	}
	return rec
}

// sourceRecords lists an agent's sources, or the built-in sources, by name.
func sourceRecords(ctx context.Context, q queryer, agentID string) ([]toolServerRecord, error) {
	if agentID != builtinAgent {
		return records[toolServerRecord](ctx, q, `SELECT record FROM tool_servers WHERE agent_id = ? ORDER BY name`, agentID)
	}
	list, err := records[builtinRecord](ctx, q, `SELECT record FROM builtin_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]toolServerRecord, len(list))
	for i, b := range list {
		out[i] = b.asToolServer()
	}
	return out, nil
}

// updateSourceState changes the snapshot and health fields of a source,
// built-in or not, in a transaction. A source that is gone is left alone.
func updateSourceState(ctx context.Context, tx *sql.Tx, agentID, server string, change func(*toolSnapshotState)) (bool, error) {
	if agentID == builtinAgent {
		rec, err := readBuiltin(ctx, tx, server)
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		change(&rec.toolSnapshotState)
		return true, putJSON(ctx, tx, `UPDATE builtin_sources SET record = ? WHERE name = ?`, rec, server)
	}
	rec, err := readToolServer(ctx, tx, agentID, server)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	change(&rec.toolSnapshotState)
	return true, putJSON(ctx, tx, `UPDATE tool_servers SET record = ? WHERE agent_id = ? AND name = ?`, rec, agentID, server)
}

// PutBuiltinSources replaces the built-in source definitions and values in
// one transaction, then snapshots each shareable one and the capabilities
// with their own credential built on them, and returns the listing.
func (s *Store) PutBuiltinSources(ctx context.Context, r PutBuiltinSources) ([]BuiltinSourceView, error) {
	if err := validateBuiltinSources(r); err != nil {
		return nil, err
	}
	lock := s.agentToolLock(builtinAgent)
	lock.Lock()
	defer lock.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	olds, err := records[builtinRecord](ctx, tx, `SELECT record FROM builtin_sources`)
	if err != nil {
		return nil, err
	}
	agentServers, err := builtinAgentServers(ctx, tx)
	if err != nil {
		return nil, err
	}
	launchOf := func(d BuiltinDefinition, values map[string]string) string {
		data, _ := json.Marshal(struct {
			D BuiltinDefinition
			V map[string]string
		}{d, values})
		return string(data)
	}
	old := map[string]builtinRecord{}
	changed := map[string]bool{}
	for _, o := range olds {
		old[o.Name] = o
		values, err := toolValues(ctx, tx, builtinAgent, o.Name)
		if err != nil {
			return nil, err
		}
		changed[o.Name] = true
		for _, d := range r.Sources {
			if d.Name == o.Name && launchOf(d, nonNil(r.Values[d.Name])) == launchOf(o.BuiltinDefinition, values) {
				delete(changed, o.Name)
			}
		}
	}
	for _, q := range []string{`DELETE FROM builtin_sources`, `DELETE FROM tool_values WHERE agent_id = 'builtin'`} {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			return nil, err
		}
	}
	for _, d := range r.Sources {
		if d.Env == nil {
			d.Env = map[string]ToolEnv{}
		}
		rec := builtinRecord{BuiltinDefinition: d}
		rec.Shareable, rec.Reason, rec.MissingEnv = builtinShareability(d, agentServers)
		if o, ok := old[d.Name]; ok {
			rec.toolSnapshotState = o.toolSnapshotState
		}
		if err = putJSON(ctx, tx, `INSERT INTO builtin_sources (record, name) VALUES (?, ?)`, rec, d.Name); err != nil {
			return nil, err
		}
		for field, value := range r.Values[d.Name] {
			if _, err = tx.ExecContext(ctx, `INSERT INTO tool_values VALUES (?, ?, ?, ?)`, builtinAgent, d.Name, field, value); err != nil {
				return nil, err
			}
		}
	}
	if err = appendEvent(ctx, tx, "sources.discovered", builtinAgent, timestamp(time.Now())); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.retireInstances(builtinAgent, changed)
	if err = s.snapshotAgent(ctx, builtinAgent); err != nil {
		return nil, err
	}
	return s.builtinSources(ctx)
}

// BuiltinSourceView is a built-in SERVER in GET /v1/sources.
type BuiltinSourceView struct {
	SourceView
	Adapter       string   `json:"adapter"`
	Version       *string  `json:"version"`
	Host          string   `json:"host"`
	Account       *string  `json:"account"`
	Authenticated bool     `json:"authenticated"`
	Reach         *GHReach `json:"reach"`
}

// builtinSources lists the built-in sources with the capabilities built on
// each.
func (s *Store) builtinSources(ctx context.Context) ([]BuiltinSourceView, error) {
	list, err := records[builtinRecord](ctx, s.db, `SELECT record FROM builtin_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	capabilities, err := records[capabilityRecord](ctx, s.db, `SELECT record FROM capabilities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := []BuiltinSourceView{}
	for _, b := range list {
		view := BuiltinSourceView{SourceView: sourceView(b.asToolServer()), Adapter: b.Adapter, Version: b.Version, Host: b.Host, Account: b.Account, Authenticated: b.Authenticated, Reach: b.Reach}
		for _, c := range capabilities {
			if c.AgentID == builtinAgent && c.Source.Server == b.Name {
				view.Capabilities = append(view.Capabilities, c.Name)
			}
		}
		out = append(out, view)
	}
	return out, nil
}

// builtinLaunch is how to start a built-in source's server: this
// executable's hidden builtin-source subcommand, given the gh path and the
// state directory, in STATE/builtin/gh/work.
func (s *Store) builtinLaunch(rec toolServerRecord, spec *launchSpec) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	work, _ := ghDirs(s.dir)
	gh := deref(rec.Command)
	spec.Command, spec.Args, spec.Dir, spec.ghPath = self, []string{"builtin-source", "gh", "--gh", gh, "--state", s.dir}, work, gh
	return nil
}

// tokenType names a gh token's type by its prefix.
func tokenType(token string) string {
	switch {
	case strings.HasPrefix(token, "gho_"):
		return "oauth"
	case strings.HasPrefix(token, "ghp_"):
		return "classic"
	case strings.HasPrefix(token, "github_pat_"):
		return "fine_grained"
	case strings.HasPrefix(token, "ghu_"), strings.HasPrefix(token, "ghs_"):
		return "app"
	}
	return "unknown"
}

func envValue(env []string, name string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// checkReach runs gh api --include --hostname github.com user with the gh
// environment of an instance, and reads the account and scopes.
func (s *Store) checkReach(ctx context.Context, spec launchSpec, account *string) GHReach {
	work, config := ghDirs(s.dir)
	env := ghEnv(spec.Env, config)
	reach := GHReach{Account: account, Host: ghHost, TokenType: tokenType(envValue(env, "GH_TOKEN")), CheckedAt: timestamp(time.Now())}
	fail := func(text string) GHReach {
		reach.Error = &text
		return reach
	}
	run := runGH(ctx, spec.ghPath, []string{"api", "--include", "--hostname", ghHost, "user"}, env, work, nil, ghCheckTimeout)
	switch {
	case run.notStart:
		return fail("gh could not be started")
	case run.timedOut:
		return fail(fmt.Sprintf("gh did not finish within %d seconds", int(ghCheckTimeout/time.Second)))
	case run.overLimit || run.cancelled:
		return fail("gh returned output Peerspan could not read")
	case run.exitCode != 0:
		return fail(fmt.Sprintf("gh exited with status %d", run.exitCode))
	}
	unreadable := "gh returned output Peerspan could not read"
	rest := run.stdout
	nextLine := func() (string, bool) {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			return "", false
		}
		line := strings.TrimSuffix(string(rest[:i]), "\r")
		rest = rest[i+1:]
		return line, true
	}
	status, ok := nextLine()
	if !ok || !strings.HasPrefix(status, "HTTP/") {
		return fail(unreadable)
	}
	var scopes []string
	found := false
	for {
		line, ok := nextLine()
		if !ok {
			return fail(unreadable)
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "X-OAuth-Scopes") {
			found = true
			scopes = []string{}
			for _, scope := range strings.Split(value, ",") {
				if scope = strings.Trim(scope, ghSpace); scope != "" {
					scopes = append(scopes, scope)
				}
			}
		}
	}
	var body struct {
		Login *string `json:"login"`
	}
	if json.Unmarshal(bytes.Trim(rest, ghSpace), &body) != nil || body.Login == nil {
		return fail(unreadable)
	}
	reach.Account = body.Login
	if found {
		reach.Scopes = scopes
	}
	return reach
}

// boundWarnings checks, for a new capability on a gh source with a bound,
// that each exact bound repository is visible to the capability's
// credential, by running repo_view.
func (s *Store) boundWarnings(ctx context.Context, name string) []string {
	warnings := []string{}
	c, err := readCapability(ctx, s.db, name)
	if err != nil || c.Source.Agent != builtinAgent || !c.Bounds.Set() {
		return warnings
	}
	spec, err := s.toolLaunch(ctx, s.db, builtinAgent, c.Source.Server, c.credential())
	if err != nil {
		return warnings
	}
	work, config := ghDirs(s.dir)
	env := ghEnv(spec.Env, config)
	op, _ := ghOperation("repo_view")
	seen := map[string]bool{}
	var repos []string
	for _, combo := range c.Bounds.Arguments {
		repo, ok := combo["repo"]
		if _, wild := ghRepoWildcard(repo); !ok || wild || seen[repo] {
			continue
		}
		seen[repo] = true
		repos = append(repos, repo)
	}
	// The checks run in order and share one budget, so the create answers
	// well inside the CLI's request timeout however many repositories the
	// bound names; a repository the budget leaves no time for is not
	// checked and gets no warning.
	deadline := time.Now().Add(ghWarningBudget)
	for _, repo := range repos {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		argv, _ := ghArgv(op, ghArgs{strs: map[string]string{"repo": repo}})
		run := runGH(ctx, spec.ghPath, argv, env, work, nil, min(left, ghCheckTimeout))
		if run.notStart || run.timedOut || run.overLimit || run.cancelled || run.exitCode != 0 {
			warnings = append(warnings, repo+" is not visible to this credential")
		}
	}
	return warnings
}

func localBuiltinRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("PUT /v1/builtin-sources", func(w http.ResponseWriter, r *http.Request) {
		var req PutBuiltinSources
		if !decode(w, r, &req, "sources", "values") {
			return
		}
		list, err := store.PutBuiltinSources(r.Context(), req)
		respond(w, http.StatusOK, map[string]any{"builtin": list}, err)
	})
}
