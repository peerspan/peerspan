package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
)

type Options struct {
	Action, Directory, State, Harness, Integrations, Runner string
	Agent, ExpiresAt, Routes, Workspace                     string
	// Program is the CLI name the next command uses.
	Program         string
	ProviderOptions map[string]string
	Args            []string
	// AttachWorkspace, set by attach, is the project the profile records.
	AttachWorkspace string
	// MaxSendsPerHour, when nonzero, gives the session directory access.
	MaxSendsPerHour int64
	// MaxCallsPerHour, when nonzero, lets the session call capabilities.
	MaxCallsPerHour int64
}
type Profile struct {
	Version       int                      `json:"version"`
	Phase         string                   `json:"phase"`
	Directory     string                   `json:"directory"`
	State         string                   `json:"state"`
	HostID        string                   `json:"host_id"`
	AgentID       string                   `json:"agent_id"`
	SessionID     string                   `json:"session_id"`
	AdapterID     string                   `json:"adapter_id,omitempty"`
	Harness       Manifest                 `json:"harness"`
	Options       map[string]string        `json:"options"`
	ProviderState json.RawMessage          `json:"provider_state"`
	Files         map[string]string        `json:"files"`
	Request       host.AdapterSetupRequest `json:"request"`
	// Workspace is the project's real path, recorded only by attach.
	Workspace string `json:"workspace,omitempty"`
	// credential is the issued authorization, kept for the setup result.
	credential host.Adapter
}

func validID(value, prefix string, bytes int) bool {
	if !strings.HasPrefix(value, prefix+"_") || len(value) != len(prefix)+1+bytes*2 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix)+1:])
	return err == nil && strings.ToLower(value) == value
}
func future(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.After(time.Now())
}
func loadProfile(o Options) (*Profile, error) {
	dir, err := filepath.Abs(o.Directory)
	if err != nil {
		return nil, err
	}
	if err := privateDirectory(dir); err != nil {
		return nil, err
	}
	var p Profile
	if err := readJSON(filepath.Join(dir, "profile.json"), &p, true); err != nil {
		return nil, err
	}
	if p.Version != 2 {
		return nil, errors.New("unsupported setup profile; use a fresh session setup directory")
	}
	if p.Harness.validate() != nil || !filepath.IsAbs(p.Harness.Command[0]) || p.Directory != dir || !filepath.IsAbs(p.State) || !validID(p.AgentID, "agent", 16) || !validID(p.SessionID, "session", 16) || p.Request.AgentID != p.AgentID || p.Request.SessionID != p.SessionID || p.Request.Integration != p.Harness.ID || (p.Phase != "configured" && p.Phase != "preparing") || (p.Phase == "configured" && !validID(p.AdapterID, "adapter", 16)) || p.Files == nil || p.Options == nil || !json.Valid(p.ProviderState) {
		return nil, errors.New("invalid setup profile")
	}
	for name := range p.Files {
		if !filePattern.MatchString(name) || name == "profile.json" || name == "credential.json" {
			return nil, errors.New("invalid setup artifact")
		}
	}
	if o.State != "" {
		state, _ := filepath.Abs(o.State)
		if state != p.State {
			return nil, errors.New("this setup belongs to another state directory")
		}
	}
	return &p, nil
}
func call(ctx context.Context, p *Profile, method, path string, body, dst any) error {
	data, err := (host.Client{SocketPath: filepath.Join(p.State, "admin.sock")}).Call(ctx, method, path, body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return errors.New("invalid daemon response")
	}
	return nil
}
func sameHost(ctx context.Context, p *Profile) error {
	var identity struct {
		ID string `json:"id"`
	}
	if err := call(ctx, p, "GET", "/v1/host", nil, &identity); err != nil {
		return err
	}
	if identity.ID != p.HostID {
		return errors.New("host_changed: daemon identity differs from the setup; prepare a fresh setup for this host")
	}
	return nil
}
func readCredential(p *Profile) (host.AdapterCredential, error) {
	var value host.AdapterCredential
	if err := readJSON(filepath.Join(p.Directory, "credential.json"), &value, true); err != nil {
		return value, err
	}
	if !validID(value.Token, "token", 32) || value.Adapter.ID != p.AdapterID || value.Adapter.SessionID != p.SessionID {
		return value, errors.New("credential file does not belong to this attachment")
	}
	return value, nil
}
func verify(ctx context.Context, p *Profile, token string) (bool, error) {
	var value struct {
		Matches bool `json:"matches"`
	}
	err := call(ctx, p, "POST", "/v1/adapters/"+p.AdapterID+"/verify-credential", map[string]string{"token": token}, &value)
	return value.Matches, err
}
func finish(p *Profile, result host.AdapterSetup) error {
	if result.Session.ID != p.SessionID || result.Session.AgentID != p.AgentID || result.Session.Integration != p.Harness.ID || result.Credential.Adapter.SessionID != p.SessionID || !validID(result.Credential.Adapter.ID, "adapter", 16) || !validID(result.Credential.Token, "token", 32) {
		return errors.New("daemon response does not match the prepared attachment")
	}
	p.AdapterID = result.Credential.Adapter.ID
	p.credential = result.Credential.Adapter
	if err := writeJSON(filepath.Join(p.Directory, "credential.json"), result.Credential); err != nil {
		return err
	}
	p.Phase = "configured"
	return writeJSON(filepath.Join(p.Directory, "profile.json"), p)
}
func ensureArtifacts(p *Profile) error {
	for name, content := range p.Files {
		path := filepath.Join(p.Directory, name)
		data, err := readFile(path, true)
		if errors.Is(err, os.ErrNotExist) {
			if err := writeFile(path, []byte(content)); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if string(data) != content {
			return errors.New("preparing integration configuration changed; inspect it before resuming")
		}
	}
	return nil
}
func recoverSetup(ctx context.Context, p *Profile) error {
	if err := sameHost(ctx, p); err != nil {
		return err
	}
	var session host.Session
	err := call(ctx, p, "GET", "/v1/sessions/"+p.SessionID, nil, &session)
	if err != nil {
		var failure *host.ClientError
		if !errors.As(err, &failure) || failure.Status != 404 {
			return err
		}
		var result host.AdapterSetup
		if err := call(ctx, p, "POST", "/v1/adapters/setup", p.Request, &result); err != nil {
			return err
		}
		return finish(p, result)
	}
	if session.AgentID != p.AgentID || session.Integration != p.Harness.ID || session.State != host.SessionAttached {
		return errors.New("recovery refused: original session changed or was detached")
	}
	var all []host.Adapter
	if err := call(ctx, p, "GET", "/v1/adapters", nil, &all); err != nil {
		return err
	}
	matching := []host.Adapter{}
	for _, a := range all {
		if a.SessionID == p.SessionID {
			matching = append(matching, a)
		}
	}
	// A renewable request matches a renewable credential, whatever its
	// current expiry; a fixed one matches its exact expiry.
	if len(matching) != 1 || matching[0].RevokedAt != nil || matching[0].Renewable != (p.Request.ExpiresAt == "") || (!matching[0].Renewable && matching[0].ExpiresAt != p.Request.ExpiresAt) || !future(matching[0].ExpiresAt) {
		return errors.New("recovery refused: preparing authorization is missing, changed, revoked, or expired")
	}
	p.AdapterID = matching[0].ID
	var connection struct {
		State string `json:"state"`
	}
	if err := call(ctx, p, "GET", "/v1/adapters/"+p.AdapterID+"/connection", nil, &connection); err != nil {
		return err
	}
	if connection.State != "registered" {
		return errors.New("recovery refused: preparing attachment has already connected; it cannot be adopted")
	}
	var routes []host.OutboundRoute
	if err := call(ctx, p, "GET", "/v1/adapters/"+p.AdapterID+"/routes", nil, &routes); err != nil {
		return err
	}
	wanted := append([]host.SetupRoute{}, p.Request.Routes...)
	for i := range wanted {
		if wanted[i].Action == "" {
			wanted[i].Action = "message.append"
		}
	}
	actual := []host.SetupRoute{}
	for _, r := range routes {
		if r.RevokedAt != nil {
			return errors.New("recovery refused: preparing destinations were withdrawn")
		}
		expiry := r.ExpiresAt
		if r.FollowsCredential {
			expiry = "" // requested without an expiry
		}
		actual = append(actual, host.SetupRoute{Name: r.Name, PeerHostID: r.PeerHostID, TargetAgentID: r.TargetAgentID, GrantID: r.GrantID, ExpiresAt: expiry, MaxMessageBytes: r.MaxMessageBytes, MaxMessages: r.MaxMessages, Action: r.Action})
	}
	sort.Slice(wanted, func(i, j int) bool { return wanted[i].Name < wanted[j].Name })
	sort.Slice(actual, func(i, j int) bool { return actual[i].Name < actual[j].Name })
	if !reflect.DeepEqual(wanted, actual) {
		return errors.New("recovery refused: destinations differ from the original request")
	}
	secret, err := readCredential(p)
	if err == nil {
		matched, err := verify(ctx, p, secret.Token)
		if err != nil {
			return err
		}
		if !matched {
			secret = host.AdapterCredential{}
		}
	}
	if secret.Token == "" || err != nil {
		if err := call(ctx, p, "POST", "/v1/adapters/"+p.AdapterID+"/rotate", nil, &secret); err != nil {
			return err
		}
	}
	return finish(p, host.AdapterSetup{Session: session, Credential: secret})
}
func readRoutes(path, expiry string) ([]host.SetupRoute, error) {
	result := []host.SetupRoute{}
	if path == "" {
		return result, nil
	}
	var rows []json.RawMessage
	if err := readJSON(path, &rows, false); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) > 100 {
		return nil, errors.New("destinations must be an array of at most 100 routes")
	}
	for _, raw := range rows {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return nil, errors.New("invalid destination")
		}
		for key, value := range fields {
			if string(value) == "null" && key != "grant_id" {
				return nil, errors.New("destination fields cannot be null")
			}
			switch key {
			case "name", "peer_host_id", "target_agent_id", "grant_id", "expires_at", "max_message_bytes", "max_messages", "action":
			default:
				return nil, errors.New("unknown destination field")
			}
		}
		// Without a setup expiry, a route without one follows the renewable
		// credential.
		for key, value := range map[string]any{"expires_at": expiry, "max_message_bytes": 65536, "max_messages": 100} {
			if _, ok := fields[key]; !ok && value != "" {
				fields[key], _ = json.Marshal(value)
			}
		}
		encoded, _ := json.Marshal(fields)
		var route host.SetupRoute
		if json.Unmarshal(encoded, &route) != nil {
			return nil, errors.New("invalid destination")
		}
		result = append(result, route)
	}
	return result, nil
}
func prepare(ctx context.Context, o Options) (*Profile, error) {
	dir, err := filepath.Abs(o.Directory)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("setup directory already exists; start or diagnose it, or choose a fresh directory")
	}
	if !validID(o.Agent, "agent", 16) || (o.ExpiresAt != "" && !future(o.ExpiresAt)) {
		return nil, errors.New("use a registered agent ID and a future RFC3339 expiry")
	}
	m, err := loadManifest(o.Integrations, o.Harness, o.Runner)
	if err != nil {
		return nil, err
	}
	state := o.State
	if state == "" {
		state, err = host.DefaultStateDir()
		if err != nil {
			return nil, err
		}
	}
	state, err = filepath.Abs(state)
	if err != nil {
		return nil, err
	}
	routes, err := readRoutes(o.Routes, o.ExpiresAt)
	if err != nil {
		return nil, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	p := &Profile{Version: 2, Phase: "preparing", Directory: dir, State: state, AgentID: o.Agent, SessionID: "session_" + hex.EncodeToString(random), Harness: m, Options: o.ProviderOptions, ProviderState: json.RawMessage(`{}`), Workspace: o.AttachWorkspace}
	if p.Options == nil {
		p.Options = map[string]string{}
	}
	p.Request = host.AdapterSetupRequest{AgentID: p.AgentID, SessionID: p.SessionID, Integration: m.ID, ExpiresAt: o.ExpiresAt, Routes: routes}
	if o.MaxSendsPerHour > 0 {
		limit := o.MaxSendsPerHour
		p.Request.Directory, p.Request.MaxSendsPerHour = true, &limit
	}
	if o.MaxCallsPerHour > 0 {
		limit := o.MaxCallsPerHour
		p.Request.Calls, p.Request.MaxCallsPerHour = true, &limit
	}
	prepared, err := provider(ctx, p, "prepare", "", nil)
	if err != nil {
		return nil, err
	}
	if failed(prepared.Checks) {
		return nil, errors.New(checkErrors(prepared.Checks))
	}
	p.ProviderState = prepared.State
	if len(p.ProviderState) == 0 {
		p.ProviderState = json.RawMessage(`{}`)
	}
	p.Files = prepared.Files
	if p.Files == nil {
		p.Files = map[string]string{}
	}
	var identity struct {
		ID string `json:"id"`
	}
	var agent json.RawMessage
	if err := call(ctx, p, "GET", "/v1/host", nil, &identity); err != nil {
		return nil, err
	}
	p.HostID = identity.ID
	if err := call(ctx, p, "GET", "/v1/agents/"+p.AgentID, nil, &agent); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, errors.New("choose a fresh writable setup directory")
	}
	if err := writeJSON(filepath.Join(dir, "profile.json"), p); err != nil {
		return nil, err
	}
	if err := ensureArtifacts(p); err != nil {
		return nil, err
	}
	var setup host.AdapterSetup
	if err := call(ctx, p, "POST", "/v1/adapters/setup", p.Request, &setup); err != nil {
		var failure *host.ClientError
		if errors.As(err, &failure) && failure.Status >= 400 && failure.Status < 500 {
			for name := range p.Files {
				_ = os.Remove(filepath.Join(dir, name))
			}
			_ = os.Remove(filepath.Join(dir, "profile.json"))
			_ = os.Remove(dir)
		}
		return nil, err
	}
	return p, finish(p, setup)
}
func checkErrors(checks []Check) string {
	parts := []string{}
	for _, c := range checks {
		if c.Status == "error" {
			parts = append(parts, c.Detail)
		}
	}
	return strings.Join(parts, " ")
}

type Destination struct {
	Name              string `json:"name"`
	Status            string `json:"status"`
	ExpiresAt         string `json:"expires_at"`
	MessagesRemaining int64  `json:"messages_remaining"`
	RemoteAcceptance  string `json:"remote_acceptance"`
}
type Report struct {
	CheckedAt          string          `json:"checked_at"`
	Directory          string          `json:"directory"`
	Harness            string          `json:"harness"`
	AgentID            string          `json:"agent_id"`
	SessionID          string          `json:"session_id"`
	AdapterID          string          `json:"adapter_id"`
	AdapterReady       bool            `json:"adapter_ready"`
	Channel            *string         `json:"channel"`
	ModelAvailability  string          `json:"model_availability"`
	MessageConsumption string          `json:"message_consumption"`
	Connection         json.RawMessage `json:"connection"`
	Checks             []Check         `json:"checks"`
	Destinations       []Destination   `json:"destinations"`
}

func providerChecks(ctx context.Context, p *Profile) []Check {
	checks := []Check{}
	for name := range p.Files {
		if _, err := readFile(filepath.Join(p.Directory, name), true); err != nil {
			checks = append(checks, Check{"private_file", "error", scrub(err.Error())})
		}
	}
	result, err := provider(ctx, p, "check", "", nil)
	if err != nil {
		checks = append(checks, Check{"integration", "error", scrub(err.Error())})
	} else {
		checks = append(checks, result.Checks...)
	}
	return checks
}
func inspect(ctx context.Context, p *Profile, checks []Check) Report {
	r := Report{CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), Directory: p.Directory, Harness: p.Harness.ID, AgentID: p.AgentID, SessionID: p.SessionID, AdapterID: p.AdapterID, ModelAvailability: "unknown", MessageConsumption: "unverified", Connection: json.RawMessage(`null`), Checks: checks, Destinations: []Destination{}}
	check := func(name string, ok bool, detail string) {
		status := "ok"
		if !ok {
			status = "error"
		}
		r.Checks = append(r.Checks, Check{name, status, scrub(detail)})
	}
	check("setup", p.Phase == "configured", "Interrupted setup can be resumed with session start --directory DIR.")
	if err := sameHost(ctx, p); err != nil {
		name := "daemon"
		if strings.HasPrefix(err.Error(), "host_changed:") {
			name = "host_changed"
		}
		check(name, false, err.Error())
		return r
	}
	check("daemon", true, "The original host daemon is reachable.")
	if p.Phase != "configured" {
		return r
	}
	secret, err := readCredential(p)
	if err != nil {
		check("credential", false, err.Error())
		return r
	}
	matched, err := verify(ctx, p, secret.Token)
	if err != nil {
		check("credential", false, err.Error())
		return r
	}
	check("credential", matched, "Credential file must match the daemon; save adapter rotate output atomically when rotating.")
	var adapter host.Adapter
	var session host.Session
	if err := call(ctx, p, "GET", "/v1/adapters/"+p.AdapterID, nil, &adapter); err != nil {
		check("authorization", false, err.Error())
		return r
	}
	if err := call(ctx, p, "GET", "/v1/sessions/"+p.SessionID, nil, &session); err != nil {
		check("authorization", false, err.Error())
		return r
	}
	check("authorization", adapter.RevokedAt == nil && future(adapter.ExpiresAt) && adapter.SessionID == p.SessionID && session.AgentID == p.AgentID, "Authorization must belong to this session and remain valid; rotation does not extend expiry.")
	var connection json.RawMessage
	if err := call(ctx, p, "GET", "/v1/adapters/"+p.AdapterID+"/connection", nil, &connection); err != nil {
		check("adapter_connection", false, err.Error())
		return r
	}
	r.Connection = connection
	var conn struct {
		State           string  `json:"state"`
		Channel         *string `json:"channel"`
		ProtocolVersion *string `json:"protocol_version"`
	}
	_ = json.Unmarshal(connection, &conn)
	details := map[string]string{
		"registered": "Configuration is prepared but no adapter has connected. Launch or connect through this integration.",
		"ready":      "The original adapter has a valid lease; model availability and message consumption remain unverified.",
		"offline":    "Adapter lease expired. Check the original harness process, daemon availability, and rotated credential file.",
		"detached":   "Owner detached this session. Prepare a fresh setup.", "revoked": "Owner revoked this authorization. Prepare a fresh setup.", "expired": "Authorization expired. Prepare a fresh setup.",
	}
	check("adapter_connection", conn.State == "ready", details[conn.State])
	r.Channel = conn.Channel
	switch {
	case conn.Channel == nil:
		check("channel", true, "not running")
	case *conn.Channel == host.ChannelVerified:
		check("channel", true, "verified")
	default:
		name := p.AgentID
		var agent host.Agent
		if err := call(ctx, p, "GET", "/v1/agents/"+p.AgentID, nil, &agent); err == nil && agent.Name != "" {
			name = agent.Name
		}
		check("channel", false, "unverified: "+host.ChannelUnverifiedDetail(name))
	}
	switch {
	case conn.ProtocolVersion == nil:
		check("mcp_protocol", true, "The adapter has not reported its MCP protocol revision.")
	case protocolTooNew(*conn.ProtocolVersion):
		check("mcp_protocol", false, "The adapter negotiated MCP protocol revision "+*conn.ProtocolVersion+"; revisions from "+mcpProtocolLimit+" do not deliver channel events. Launch Claude Code with MCP_PROTOCOL_NEGOTIATION=legacy.")
	default:
		check("mcp_protocol", true, "The adapter negotiated MCP protocol revision "+*conn.ProtocolVersion+".")
	}
	var routes []host.RouteStatus
	if err := call(ctx, p, "GET", "/v1/adapters/"+p.AdapterID+"/route-status", nil, &routes); err != nil {
		check("destinations", false, err.Error())
		return r
	}
	for _, entry := range routes {
		status := "configured"
		if entry.Route.RevokedAt != nil {
			status = "revoked"
		} else if !future(entry.Route.ExpiresAt) {
			status = "expired"
		} else if entry.MessagesRemaining <= 0 {
			status = "budget_exhausted"
		}
		r.Destinations = append(r.Destinations, Destination{entry.Route.Name, status, entry.Route.ExpiresAt, entry.MessagesRemaining, "unverified"})
	}
	r.AdapterReady = conn.State == "ready" && conn.Channel != nil && *conn.Channel == host.ChannelVerified && !failed(r.Checks)
	return r
}

// mcpProtocolLimit is the first MCP protocol revision under which Claude Code
// drops channel events.
const mcpProtocolLimit = "2026-07-28"

// protocolTooNew reports whether a dated MCP protocol revision is at or after
// the limit. Revisions that are not dates are not compared.
func protocolTooNew(revision string) bool {
	at, err := time.Parse("2006-01-02", revision)
	if err != nil {
		return false
	}
	limit, _ := time.Parse("2006-01-02", mcpProtocolLimit)
	return !at.Before(limit)
}
func printJSON(out io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

// Setup prepares a new session setup with o.Agent, or else resumes the
// interrupted setup in o.Directory, and returns its configured profile.
func Setup(ctx context.Context, o Options) (*Profile, error) {
	if o.Agent != "" {
		return prepare(ctx, o)
	}
	p, err := loadProfile(o)
	if err == nil && p.Phase != "preparing" {
		err = errors.New("setup is already configured; use session start or session doctor")
	}
	if err == nil {
		err = ensureArtifacts(p)
	}
	if err == nil {
		checks := providerChecks(ctx, p)
		if failed(checks) {
			err = errors.New(checkErrors(checks))
		}
	}
	if err == nil {
		err = recoverSetup(ctx, p)
	}
	return p, err
}

// Launchable reports whether the profile's integration supports launch.
func (p *Profile) Launchable() bool { return p.Harness.supports("launch") }

// Run returns diagnostics through out; all authorization mutations remain in
// the daemon's existing atomic setup/rotation API.
func Run(ctx context.Context, o Options, out io.Writer) error {
	if o.Program == "" {
		o.Program = "peerspan-host"
	}
	if o.Action == "setup" {
		p, err := Setup(ctx, o)
		if err != nil {
			return err
		}
		names := []string{}
		for _, route := range p.Request.Routes {
			names = append(names, route.Name)
		}
		return printJSON(out, map[string]any{"state": "configured", "adapter_ready": false, "directory": p.Directory, "harness": p.Harness.ID, "agent_id": p.AgentID, "session_id": p.SessionID, "adapter_id": p.AdapterID, "expires_at": p.credential.ExpiresAt, "renewable": p.credential.Renewable, "destinations": names, "launch_supported": p.Harness.supports("launch"), "next": []string{o.Program, "session", nextOperation(p), "--directory", p.Directory}})
	}
	p, err := loadProfile(o)
	if err != nil {
		return err
	}
	if o.Action == "doctor" {
		r := inspect(ctx, p, providerChecks(ctx, p))
		if err := printJSON(out, r); err != nil {
			return err
		}
		if !r.AdapterReady {
			return errors.New("session is not ready; inspect the diagnostic checks")
		}
		return nil
	}
	if o.Action != "start" {
		return errors.New("unknown session integration operation")
	}
	if !p.Harness.supports("launch") {
		return errors.New("this integration does not support launch; connect its consumer using the prepared configuration")
	}
	workspace := o.Workspace
	if workspace == "" {
		workspace, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	workspace, err = filepath.Abs(workspace)
	if err != nil {
		return err
	}
	if stat, err := os.Stat(workspace); err != nil || !stat.IsDir() {
		return errors.New("workspace must be an existing directory")
	}
	for _, arg := range o.Args {
		if strings.ContainsRune(arg, 0) {
			return errors.New("invalid harness argument")
		}
	}
	if p.Phase == "preparing" {
		if err := ensureArtifacts(p); err != nil {
			return err
		}
	}
	checks := providerChecks(ctx, p)
	if failed(checks) {
		return errors.New(checkErrors(checks))
	}
	plan, err := provider(ctx, p, "launch", workspace, o.Args)
	if err != nil {
		return err
	}
	if failed(plan.Checks) {
		return errors.New(checkErrors(plan.Checks))
	}
	if plan.Launch == nil || !filepath.IsAbs(plan.Launch.Program) {
		return errors.New("integration returned an invalid launch plan")
	}
	program, err := executable(plan.Launch.Program)
	if err != nil {
		return err
	}
	for _, arg := range plan.Launch.Args {
		if strings.ContainsRune(arg, 0) {
			return errors.New("invalid launch argument")
		}
	}
	if p.Phase == "preparing" {
		if err := recoverSetup(ctx, p); err != nil {
			return err
		}
	}
	report := inspect(ctx, p, checks)
	blocked := []Check{}
	for _, c := range report.Checks {
		if c.Status == "error" && c.Name != "adapter_connection" {
			blocked = append(blocked, c)
		}
	}
	if failed(blocked) {
		return errors.New(checkErrors(blocked))
	}
	var conn struct {
		State string `json:"state"`
	}
	_ = json.Unmarshal(report.Connection, &conn)
	if conn.State != "registered" {
		return errors.New("attachment has already connected or was withdrawn; keep its original process or prepare a fresh owner-authorized setup")
	}
	if err := os.Chdir(workspace); err != nil {
		return err
	}
	return syscall.Exec(program, append([]string{program}, plan.Launch.Args...), os.Environ())
}

var optionPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

func ParseOptions(values []string) (map[string]string, error) {
	result := map[string]string{}
	for _, value := range values {
		key, text, ok := strings.Cut(value, "=")
		if !ok || !optionPattern.MatchString(key) || strings.ContainsRune(text, 0) {
			return nil, errors.New("integration options use KEY=VALUE")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("duplicate integration option")
		}
		result[key] = text
	}
	return result, nil
}

func nextOperation(p *Profile) string {
	if p.Harness.supports("launch") {
		return "start"
	}
	return "doctor"
}
