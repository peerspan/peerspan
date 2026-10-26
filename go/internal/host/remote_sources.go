package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Remote MCP servers (capabilities slice 3, item A): remote definitions,
// their reasons and auth modes, and the OAuth credentials this host keeps.

// Reasons a remote server is not shareable.
const (
	reasonInsecureURL   = "insecure_url"
	reasonSSE           = "sse"
	reasonHeadersHelper = "headers_helper"
	reasonLogin         = "login"
)

// Auth modes of a remote source.
const (
	authNone    = "none"
	authHeaders = "headers"
	authOAuth   = "oauth"
)

// Credential states.
const (
	credOK            = "ok"
	credRefreshFailed = "refresh_failed"
	credLoginRequired = "login_required"
)

// RemoteOAuth holds a harness's public OAuth hints.
type RemoteOAuth struct {
	ClientID     *string `json:"client_id"`
	Scopes       *string `json:"scopes"`
	CallbackPort *int    `json:"callback_port"`
}

// RemoteDefinition is the remote part of a server definition.
type RemoteDefinition struct {
	Protocol      string       `json:"protocol"`
	OAuth         *RemoteOAuth `json:"oauth"`
	HeadersHelper bool         `json:"headers_helper"`
}

func defaultRemote() *RemoteDefinition {
	return &RemoteDefinition{Protocol: "http", OAuth: &RemoteOAuth{}}
}

// remote is the definition's remote part, with defaults.
func (d ToolServerDefinition) remote() RemoteDefinition {
	if d.Remote == nil {
		return *defaultRemote()
	}
	return *d.Remote
}

// authChallenge is a stored OAuth challenge.
type authChallenge struct {
	ResourceMetadata *string `json:"resource_metadata"`
	Scope            *string `json:"scope"`
}

// AuthView is auth in GET /v1/sources and in the capability view.
type AuthView struct {
	Mode         *string `json:"mode"`
	State        *string `json:"state"`
	Issuer       *string `json:"issuer"`
	Scope        *string `json:"scope"`
	Account      *string `json:"account"`
	Registration *string `json:"registration"`
	ObtainedAt   *string `json:"obtained_at"`
	ExpiresAt    *string `json:"expires_at"`
	// Own is set only in the capability view.
	Own *bool `json:"own,omitempty"`
}

var headerToken = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func exactKeys(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil || len(m) != len(keys) {
		return nil, false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, false
		}
	}
	return m, true
}

// readRemoteFields reads a definition's optional remote and headers fields
// exactly, and applies their defaults.
func readRemoteFields(d *ToolServerDefinition, fields map[string]json.RawMessage) error {
	d.Remote, d.Headers = nil, map[string]ToolEnv{}
	if raw, ok := fields["remote"]; ok && string(raw) != "null" {
		m, ok := exactKeys(raw, "protocol", "oauth", "headers_helper")
		if !ok {
			return fmt.Errorf("%w: remote is exactly {protocol, oauth, headers_helper}", ErrInvalid)
		}
		var r RemoteDefinition
		if json.Unmarshal(m["protocol"], &r.Protocol) != nil || (r.Protocol != "http" && r.Protocol != "sse") {
			return fmt.Errorf("%w: remote.protocol is http or sse", ErrInvalid)
		}
		if json.Unmarshal(m["headers_helper"], &r.HeadersHelper) != nil {
			return fmt.Errorf("%w: remote.headers_helper is a boolean", ErrInvalid)
		}
		if string(m["oauth"]) != "null" {
			o, ok := exactKeys(m["oauth"], "client_id", "scopes", "callback_port")
			if !ok {
				return fmt.Errorf("%w: remote.oauth is null or exactly {client_id, scopes, callback_port}", ErrInvalid)
			}
			var hints RemoteOAuth
			if json.Unmarshal(o["client_id"], &hints.ClientID) != nil || json.Unmarshal(o["scopes"], &hints.Scopes) != nil || json.Unmarshal(o["callback_port"], &hints.CallbackPort) != nil {
				return fmt.Errorf("%w: invalid remote.oauth hints", ErrInvalid)
			}
			if hints.CallbackPort != nil && (*hints.CallbackPort < 1 || *hints.CallbackPort > 65535) {
				return fmt.Errorf("%w: remote.oauth.callback_port is 1 to 65535", ErrInvalid)
			}
			r.OAuth = &hints
		}
		d.Remote = &r
	} else if ok && d.Transport == "stdio" {
		d.Remote = nil
	}
	if raw, ok := fields["headers"]; ok && string(raw) != "null" {
		var entries map[string]map[string]json.RawMessage
		if json.Unmarshal(raw, &entries) != nil || entries == nil {
			return fmt.Errorf("%w: headers is an object", ErrInvalid)
		}
		if err := json.Unmarshal(raw, &d.Headers); err != nil {
			return fmt.Errorf("%w: invalid headers", ErrInvalid)
		}
		for name, entry := range entries {
			h := d.Headers[name]
			want := 1
			switch h.Source {
			case "literal":
			case "captured", "missing":
				want = 2
				if len(h.Variables) == 0 {
					return fmt.Errorf("%w: header %s needs variables", ErrInvalid, name)
				}
				for _, v := range h.Variables {
					if v == "" {
						return fmt.Errorf("%w: invalid variable name in header %s", ErrInvalid, name)
					}
				}
			default:
				return fmt.Errorf("%w: a header source is literal, captured, or missing", ErrInvalid)
			}
			if _, ok := entry["source"]; !ok || len(entry) != want || (want == 2 && entry["variables"] == nil) {
				return fmt.Errorf("%w: invalid header entry %s", ErrInvalid, name)
			}
		}
	}
	if d.Transport == "remote" && d.Remote == nil {
		d.Remote = defaultRemote()
	}
	return nil
}

// validateRemoteDefinition checks the shape that depends on the transport.
func validateRemoteDefinition(d ToolServerDefinition) error {
	if d.Transport == "stdio" {
		if d.Remote != nil || len(d.Headers) > 0 {
			return fmt.Errorf("%w: a stdio server has no remote or headers", ErrInvalid)
		}
		return nil
	}
	if d.Command != nil || len(d.Args) > 0 || len(d.Env) > 0 {
		return fmt.Errorf("%w: a remote server has a null command, no args, and no env", ErrInvalid)
	}
	if len(d.Headers) > 64 {
		return fmt.Errorf("%w: at most 64 headers", ErrInvalid)
	}
	for name := range d.Headers {
		if !headerToken.MatchString(name) {
			return fmt.Errorf("%w: invalid header name %q", ErrInvalid, name)
		}
	}
	return nil
}

// validateRemoteValue checks one values field of a remote server.
func validateRemoteValue(d ToolServerDefinition, server, field string) error {
	switch {
	case field == "url":
		return nil
	case strings.HasPrefix(field, "headers."):
		if h, ok := d.Headers[strings.TrimPrefix(field, "headers.")]; ok && h.Source != "missing" {
			return nil
		}
	case strings.HasPrefix(field, "header_templates."):
		if h, ok := d.Headers[strings.TrimPrefix(field, "header_templates.")]; ok && h.Source == "captured" {
			return nil
		}
	}
	return fmt.Errorf("%w: value %s of %s is not a field of a remote server", ErrInvalid, field, server)
}

// remoteURL is a remote definition's URL, resolved when it had references.
func remoteURL(d ToolServerDefinition, values map[string]string) string {
	if v, ok := values["url"]; ok {
		return v
	}
	if d.URL != nil {
		return *d.URL
	}
	return ""
}

func loopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// secureURL accepts https, and http on a loopback host.
func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Hostname() == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		return loopbackHost(strings.ToLower(u.Hostname()))
	}
	return false
}

// canonicalURL lowercases the scheme and host, drops the fragment, and
// removes trailing slashes from the path.
func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	u.Fragment, u.RawFragment = "", ""
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	return u.String()
}

// urlHost is a URL's host, lowercased, without port; IPv6 keeps brackets.
func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	h := strings.ToLower(u.Hostname())
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// resolveTemplate resolves ${NAME} and ${NAME:-DEFAULT} with lookup.
func resolveTemplate(text string, lookup map[string]string) string {
	return references.ReplaceAllStringFunc(text, func(match string) string {
		m := references.FindStringSubmatch(match)
		value, ok := lookup[m[1]]
		if m[2] != "" && (!ok || value == "") {
			return m[2][2:]
		}
		return value
	})
}

// skippedHeaders are set by the client itself.
var skippedHeaders = map[string]bool{"content-type": true, "accept": true, "content-length": true, "host": true, "mcp-protocol-version": true, "mcp-session-id": true}

// remoteHeaders builds the headers sent to a remote server: stored values,
// with a captured header resolved again from the capability's env file and
// the environment file when they define every variable it references.
func remoteHeaders(d ToolServerDefinition, values map[string]string, envFile, capEnv []string) [][2]string {
	lookup := map[string]string{}
	for _, lines := range [][]string{envFile, capEnv} {
		for _, line := range lines {
			name, value, _ := strings.Cut(line, "=")
			lookup[name] = value
		}
	}
	var out [][2]string
	for _, name := range sortedKeys(d.Headers) {
		if skippedHeaders[strings.ToLower(name)] {
			continue
		}
		h := d.Headers[name]
		value, ok := values["headers."+name]
		if h.Source == "missing" || !ok {
			continue
		}
		if h.Source == "captured" {
			all := true
			for _, v := range h.Variables {
				if _, defined := lookup[v]; !defined {
					all = false
				}
			}
			if template, has := values["header_templates."+name]; all && has {
				value = resolveTemplate(template, lookup)
			}
		}
		out = append(out, [2]string{name, value})
	}
	return out
}

// hasAuthorization reports whether a definition configures an
// Authorization header.
func hasAuthorization(d ToolServerDefinition) bool {
	for name := range d.Headers {
		if strings.EqualFold(name, "Authorization") {
			return true
		}
	}
	return false
}

// credKey names one OAuth credential: a source's own (capability "") or a
// capability's.
type credKey struct {
	Agent, Server, Capability string
}

func (k credKey) subject() string {
	if k.Capability != "" {
		return k.Agent + "/" + k.Server + "@" + k.Capability
	}
	return k.Agent + "/" + k.Server
}

type oauthClientRef struct {
	Issuer      string `json:"issuer"`
	RedirectURI string `json:"redirect_uri"`
}

// oauthCredential is oauth_credentials.record.
type oauthCredential struct {
	Issuer             string         `json:"issuer"`
	Resource           string         `json:"resource"`
	Registration       string         `json:"registration"`
	Client             oauthClientRef `json:"client"`
	TokenEndpoint      string         `json:"token_endpoint"`
	RevocationEndpoint *string        `json:"revocation_endpoint"`
	AccessToken        string         `json:"access_token"`
	RefreshToken       *string        `json:"refresh_token"`
	TokenType          string         `json:"token_type"`
	ExpiresAt          *string        `json:"expires_at"`
	Scope              *string        `json:"scope"`
	Account            *string        `json:"account"`
	ObtainedAt         string         `json:"obtained_at"`
	RefreshedAt        *string        `json:"refreshed_at"`
	State              string         `json:"state"`
	RefreshFailedAt    *string        `json:"refresh_failed_at"`
}

// oauthClient is oauth_clients.record: one registration per issuer and
// redirect URI.
type oauthClient struct {
	Issuer                  string  `json:"issuer"`
	RedirectURI             string  `json:"redirect_uri"`
	ClientID                string  `json:"client_id"`
	ClientSecret            *string `json:"client_secret"`
	RegistrationAccessToken *string `json:"registration_access_token"`
	Method                  string  `json:"method"`
	Registration            string  `json:"registration"`
	CreatedAt               string  `json:"created_at"`
}

const oauthSchema = `
CREATE TABLE IF NOT EXISTS oauth_clients (issuer TEXT NOT NULL, redirect_uri TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(issuer, redirect_uri));
CREATE TABLE IF NOT EXISTS oauth_credentials (agent_id TEXT NOT NULL, server TEXT NOT NULL, capability TEXT NOT NULL DEFAULT '', record TEXT NOT NULL, PRIMARY KEY(agent_id, server, capability));
PRAGMA user_version = 22;
`

func readCredential(ctx context.Context, q dbQuerier, k credKey) (oauthCredential, bool, error) {
	c, err := readJSON[oauthCredential](q.QueryRowContext(ctx, `SELECT record FROM oauth_credentials WHERE agent_id = ? AND server = ? AND capability = ?`, k.Agent, k.Server, k.Capability))
	if errors.Is(err, ErrNotFound) {
		return oauthCredential{}, false, nil
	}
	return c, err == nil, err
}

func writeCredential(ctx context.Context, tx *sql.Tx, k credKey, c oauthCredential) error {
	return putJSON(ctx, tx, `INSERT INTO oauth_credentials (record, agent_id, server, capability) VALUES (?, ?, ?, ?) ON CONFLICT(agent_id, server, capability) DO UPDATE SET record = excluded.record`, c, k.Agent, k.Server, k.Capability)
}

// deleteCredentials deletes credentials, all of a source (capability nil)
// or one, and returns them for revocation.
func deleteCredentials(ctx context.Context, tx *sql.Tx, agent, server string, capability *string) ([]oauthCredential, error) {
	query, args := `SELECT record FROM oauth_credentials WHERE agent_id = ? AND server = ?`, []any{agent, server}
	if capability != nil {
		query, args = query+` AND capability = ?`, append(args, *capability)
	}
	list, err := records[oauthCredential](ctx, tx, query, args...)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, strings.Replace(query, "SELECT record", "DELETE", 1), args...); err != nil {
		return nil, err
	}
	return list, nil
}

func readClient(ctx context.Context, q dbQuerier, issuer, redirect string) (oauthClient, bool, error) {
	c, err := readJSON[oauthClient](q.QueryRowContext(ctx, `SELECT record FROM oauth_clients WHERE issuer = ? AND redirect_uri = ?`, issuer, redirect))
	if errors.Is(err, ErrNotFound) {
		return oauthClient{}, false, nil
	}
	return c, err == nil, err
}

// latestClient is the most recently created registration for an issuer.
func latestClient(ctx context.Context, q queryer, issuer string) (*oauthClient, error) {
	list, err := records[oauthClient](ctx, q, `SELECT record FROM oauth_clients WHERE issuer = ?`, issuer)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].CreatedAt > list[j].CreatedAt })
	return &list[0], nil
}

// usable reports whether a credential can serve requests to a URL.
func (c oauthCredential) usable(target string) bool {
	return (c.State == credOK || c.State == credRefreshFailed) && c.Resource == canonicalURL(target)
}

// applyLoginReason gives a remote source whose auth mode is oauth, and
// that has no definition reason, the reason login when it has no usable
// credential.
func applyLoginReason(ctx context.Context, q dbQuerier, agentID string, rec *toolServerRecord, values map[string]string) error {
	if rec.Transport != "remote" || rec.Reason != nil || rec.AuthMode == nil || *rec.AuthMode != authOAuth {
		return nil
	}
	c, found, err := readCredential(ctx, q, credKey{agentID, rec.Name, ""})
	if err != nil {
		return err
	}
	if !found || !c.usable(remoteURL(rec.ToolServerDefinition, values)) {
		reason := reasonLogin
		rec.Shareable, rec.Reason = false, &reason
	}
	return nil
}

// syncLoginReason recomputes a stored source's reason after its auth mode
// or credential changed.
func syncLoginReason(ctx context.Context, tx *sql.Tx, agentID, server string) error {
	if agentID == builtinAgent {
		return nil
	}
	rec, err := readToolServer(ctx, tx, agentID, server)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	values, err := toolValues(ctx, tx, agentID, server)
	if err != nil {
		return err
	}
	rec.Shareable, rec.Reason, rec.MissingEnv = shareability(rec.ToolServerDefinition, values)
	if err = applyLoginReason(ctx, tx, agentID, &rec, values); err != nil {
		return err
	}
	return putJSON(ctx, tx, `UPDATE tool_servers SET record = ? WHERE agent_id = ? AND name = ?`, rec, agentID, server)
}

// sourceAuth is auth in GET /v1/sources: null for stdio and built-in
// sources.
func sourceAuth(ctx context.Context, q dbQuerier, agentID string, rec toolServerRecord) (*AuthView, error) {
	if rec.Transport != "remote" || agentID == builtinAgent {
		return nil, nil
	}
	return credentialAuth(ctx, q, rec.AuthMode, credKey{agentID, rec.Name, ""})
}

// credentialAuth builds the auth view for an auth mode and the credential
// used.
func credentialAuth(ctx context.Context, q dbQuerier, mode *string, k credKey) (*AuthView, error) {
	v := &AuthView{Mode: mode}
	if mode == nil || *mode != authOAuth {
		return v, nil
	}
	c, found, err := readCredential(ctx, q, k)
	if err != nil {
		return nil, err
	}
	state := credLoginRequired
	if found {
		state = c.State
		registration, obtained := c.Registration, c.ObtainedAt
		issuer := c.Issuer
		v.Issuer, v.Scope, v.Account, v.Registration, v.ObtainedAt, v.ExpiresAt = &issuer, c.Scope, c.Account, &registration, &obtained, c.ExpiresAt
	}
	v.State = &state
	return v, nil
}

// capabilityAuth is auth in the capability view: null for a capability on
// a stdio or built-in source.
func capabilityAuth(ctx context.Context, q dbQuerier, c capabilityRecord) (*AuthView, error) {
	if c.AgentID == builtinAgent {
		return nil, nil
	}
	rec, err := readToolServer(ctx, q, c.AgentID, c.Source.Server)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil || rec.Transport != "remote" {
		return nil, err
	}
	key := credKey{c.AgentID, c.Source.Server, ""}
	mode := rec.AuthMode
	if c.OwnSignIn {
		key.Capability = c.Name
		oauth := authOAuth
		mode = &oauth
	}
	v, err := credentialAuth(ctx, q, mode, key)
	if err != nil {
		return nil, err
	}
	own := c.OwnSignIn
	v.Own = &own
	return v, nil
}

// capabilityAuthLapsed reports whether a capability on a remote source
// lacks a usable credential: its own, or its source's.
func capabilityAuthLapsed(ctx context.Context, q dbQuerier, c capabilityRecord, rec toolServerRecord) (bool, error) {
	if rec.Transport != "remote" {
		return false, nil
	}
	if !c.OwnSignIn {
		return rec.Reason != nil && *rec.Reason == reasonLogin, nil
	}
	values, err := toolValues(ctx, q, c.AgentID, c.Source.Server)
	if err != nil {
		return false, err
	}
	cred, found, err := readCredential(ctx, q, credKey{c.AgentID, c.Source.Server, c.Name})
	if err != nil {
		return false, err
	}
	return !found || !cred.usable(remoteURL(rec.ToolServerDefinition, values)), nil
}

// errAuthLapsed refuses a call whose capability's sign-in has lapsed.
var errAuthLapsed = &codedError{status: 409, code: "unavailable", message: "the capability's sign-in has lapsed on its host"}

// unavailableAuth marks a capability whose credential is not usable.
const unavailableAuth = "auth"

// noteInsufficientScope records a 403 insufficient_scope on a source or a
// capability's own instance.
func (s *Store) noteInsufficientScope(ctx context.Context, target instanceTarget, scope *string) {
	s.noteServer(ctx, target, func(st *toolSnapshotState) {
		at := timestamp(time.Now())
		st.InsufficientScopeAt, st.InsufficientScope = &at, scope
	})
}

// remoteSpec is how to reach a remote server's instance.
type remoteSpec struct {
	URL     string
	Headers [][2]string
	// Cred is the OAuth credential the instance uses, if any.
	Cred *credKey
	// What the probe needs to know of the definition.
	HasHeaders, HasAuthorization, OAuthOff bool
}

// remoteLaunch builds a remote server's launch: its URL, its headers with
// the environment file and a capability's env_file applied, and the OAuth
// credential it uses.
func (s *Store) remoteLaunch(agentID string, rec toolServerRecord, values map[string]string, own *ownCredential, spec launchSpec) (launchSpec, error) {
	var envFile, capEnv []string
	if path := ToolEnvFile(); path != "" && !envFileTooOpen(path) {
		envFile, _ = readEnvFile(path)
	}
	if own != nil && own.envFile != nil {
		lines, err := readEnvFile(*own.envFile)
		if err != nil {
			return launchSpec{}, fmt.Errorf("the capability's env file cannot be read: %w", err)
		}
		capEnv = lines
	}
	r := &remoteSpec{URL: remoteURL(rec.ToolServerDefinition, values), Headers: remoteHeaders(rec.ToolServerDefinition, values, envFile, capEnv)}
	switch {
	case own != nil && own.ownSignIn:
		r.Cred = &credKey{agentID, rec.Name, own.capability}
	case rec.AuthMode != nil && *rec.AuthMode == authOAuth:
		r.Cred = &credKey{agentID, rec.Name, ""}
	}
	r.HasHeaders, r.HasAuthorization, r.OAuthOff = len(rec.Headers) > 0, hasAuthorization(rec.ToolServerDefinition), rec.remote().OAuth == nil
	spec.Remote = r
	return spec, nil
}

// remoteSnapshotCredential decides whether a snapshot carries a token: a
// source's credential only when usable, otherwise the probe goes without
// one; a capability's own sign-in that is not usable means no snapshot.
func (s *Store) remoteSnapshotCredential(ctx context.Context, spec *launchSpec) (bool, error) {
	k := spec.Remote.Cred
	if k == nil {
		return true, nil
	}
	c, found, err := readCredential(ctx, s.db, *k)
	if err != nil {
		return false, err
	}
	if found && c.usable(spec.Remote.URL) {
		return true, nil
	}
	if k.Capability != "" {
		return false, nil
	}
	spec.Remote.Cred = nil
	return true, nil
}

// remoteProbe reads what initialize told about a remote source's auth
// mode. done means the snapshot ends here, with err as its outcome.
func remoteProbe(spec launchSpec, snap toolSnapshot, err error) (toolSnapshot, bool, error) {
	r := spec.Remote
	var status *httpStatusError
	switch {
	case err == nil:
		switch {
		case r.Cred != nil:
			snap.authMode = authOAuth
		case r.HasHeaders:
			snap.authMode = authHeaders
		default:
			snap.authMode = authNone
		}
		return snap, false, nil
	case errors.Is(err, errLoginRequired):
		return toolSnapshot{authMode: authOAuth, skip: true}, true, nil
	case errors.As(err, &status) && status.status == 401:
		if params, ok := bearerChallenge(status.header); ok && r.Cred == nil && !r.HasAuthorization && !r.OAuthOff {
			return toolSnapshot{authMode: authOAuth, skip: true, challenge: &authChallenge{ResourceMetadata: optional(params, "resource_metadata"), Scope: optional(params, "scope")}}, true, nil
		}
		return snap, true, errors.New("unauthorized")
	}
	return snap, false, err
}
