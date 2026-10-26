package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OAuth for remote MCP servers (capabilities slice 3, item A): Peerspan is
// its own OAuth client, signs in once per source or capability, and keeps
// its tokens in host state.

const (
	loginLifetime   = 10 * time.Minute
	refreshMargin   = 60 * time.Second
	oauthTimeout    = 30 * time.Second
	metadataMaxBody = 1 << 20
)

// oauthState is the in-memory OAuth state: pending sign-ins, refresh locks,
// and credentials marked by a 401 to a call.
type oauthState struct {
	mu     sync.Mutex
	logins map[string]*pendingLogin
	locks  map[credKey]*sync.Mutex
	stale  map[credKey]string
}

func (s *Store) oauth() *oauthState {
	s.oauthOnce.Do(func() {
		s.oauthMem = &oauthState{logins: map[string]*pendingLogin{}, locks: map[credKey]*sync.Mutex{}, stale: map[credKey]string{}}
	})
	return s.oauthMem
}

func (o *oauthState) lock(k credKey) *sync.Mutex {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.locks[k]
	if m == nil {
		m = &sync.Mutex{}
		o.locks[k] = m
	}
	return m
}

// markStale makes the next request with this credential refresh first,
// after a 401 answered a call that used tok.
func (s *Store) markStale(k credKey, tok string) {
	o := s.oauth()
	o.mu.Lock()
	o.stale[k] = tok
	o.mu.Unlock()
}

// markLoginRequired records that a credential was refused after a
// refresh, while tok, the refused token, is still the current one.
func (s *Store) markLoginRequired(ctx context.Context, k credKey, tok string) {
	lock := s.oauth().lock(k)
	lock.Lock()
	defer lock.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	c, found, err := readCredential(ctx, tx, k)
	if err != nil || !found || c.State == credLoginRequired || c.AccessToken != tok {
		return
	}
	c.State = credLoginRequired
	if writeCredential(ctx, tx, k, c) != nil || syncLoginReason(ctx, tx, k.Agent, k.Server) != nil {
		return
	}
	_ = tx.Commit()
}

// oauthError is an OAuth error answer.
type oauthError struct {
	status      int
	code        string
	description string
}

func (e *oauthError) Error() string {
	if e.code == "" {
		return fmt.Sprintf("HTTP %d", e.status)
	}
	return e.code
}

// text is "ERROR (DESCRIPTION)" or "ERROR".
func (e *oauthError) text() string {
	code := e.code
	if code == "" {
		code = fmt.Sprintf("HTTP %d", e.status)
	}
	if e.description != "" {
		return code + " (" + e.description + ")"
	}
	return code
}

// tokenAnswer is a token endpoint's success answer.
type tokenAnswer struct {
	AccessToken  string   `json:"access_token"`
	TokenType    *string  `json:"token_type"`
	RefreshToken *string  `json:"refresh_token"`
	ExpiresIn    *float64 `json:"expires_in"`
	Scope        *string  `json:"scope"`
}

// clientAuth adds the client's authentication to a form request.
func clientAuth(req *http.Request, form url.Values, cl oauthClient) {
	form.Set("client_id", cl.ClientID)
	switch {
	case cl.ClientSecret == nil:
	case cl.Method == "client_secret_basic":
		req.SetBasicAuth(url.QueryEscape(cl.ClientID), url.QueryEscape(*cl.ClientSecret))
	default:
		form.Set("client_secret", *cl.ClientSecret)
	}
}

// postForm posts a form to an OAuth endpoint with the client's
// authentication, never following redirects, and returns the status and
// the body.
func postForm(ctx context.Context, endpoint string, form url.Values, cl oauthClient) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	clientAuth(req, form, cl)
	body := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	client := remoteHTTPClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, unwrapURLError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, metadataMaxBody))
	return resp.StatusCode, data, err
}

// tokenRequest posts to the token endpoint and reads the answer.
func tokenRequest(ctx context.Context, endpoint string, form url.Values, cl oauthClient) (tokenAnswer, error) {
	status, data, err := postForm(ctx, endpoint, form, cl)
	if err != nil {
		return tokenAnswer{}, err
	}
	if status != http.StatusOK {
		var e struct {
			Error       *string `json:"error"`
			Description *string `json:"error_description"`
		}
		out := &oauthError{status: status}
		if json.Unmarshal(data, &e) == nil {
			out.code, out.description = deref(e.Error), deref(e.Description)
		}
		return tokenAnswer{}, out
	}
	var answer tokenAnswer
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil || json.Unmarshal(data, &answer) != nil || answer.AccessToken == "" {
		return tokenAnswer{}, &oauthError{status: status, code: "invalid_response", description: "the token answer has no access_token"}
	}
	if answer.TokenType != nil && !strings.EqualFold(*answer.TokenType, "bearer") {
		return tokenAnswer{}, &oauthError{status: status, code: "invalid_response", description: "the token type is not Bearer"}
	}
	return answer, nil
}

func expiresAt(at time.Time, answer tokenAnswer) *string {
	if answer.ExpiresIn == nil {
		return nil
	}
	t := timestamp(at.Add(time.Duration(*answer.ExpiresIn * float64(time.Second))))
	return &t
}

// oauthToken returns a credential's access token, refreshing it first when
// it expires within 60 seconds, when a 401 marked it, or when stale (the
// token a request was refused with) is still the current one.
func (s *Store) oauthToken(ctx context.Context, k credKey, stale, target string) (string, bool, error) {
	o := s.oauth()
	lock := o.lock(k)
	lock.Lock()
	defer lock.Unlock()
	c, found, err := readCredential(ctx, s.db, k)
	if err != nil {
		return "", false, err
	}
	// A session uses a credential only for its own resource, so a new
	// sign-in to a changed URL never reaches an older session.
	if !found || c.State == credLoginRequired || c.Resource != canonicalURL(target) {
		return "", false, errLoginRequired
	}
	o.mu.Lock()
	marked := o.stale[k]
	o.mu.Unlock()
	need := (stale != "" && stale == c.AccessToken) || (marked != "" && marked == c.AccessToken)
	if c.ExpiresAt != nil {
		if t, err := parseTime(*c.ExpiresAt); err == nil && time.Until(t) <= refreshMargin {
			need = true
		}
	}
	if !need {
		return c.AccessToken, false, nil
	}
	o.mu.Lock()
	delete(o.stale, k)
	o.mu.Unlock()
	return s.refresh(ctx, k, c)
}

// refresh exchanges the refresh token, storing the new tokens before they
// are used. A refused refresh makes the credential login_required; any
// other failure makes it refresh_failed and keeps the current token.
func (s *Store) refresh(ctx context.Context, k credKey, c oauthCredential) (string, bool, error) {
	now := time.Now()
	cl, found, err := readClient(ctx, s.db, c.Client.Issuer, c.Client.RedirectURI)
	if err != nil {
		return "", false, err
	}
	var answer tokenAnswer
	refused := c.RefreshToken == nil || !found
	if !refused {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {*c.RefreshToken}, "resource": {c.Resource}}
		answer, err = tokenRequest(ctx, c.TokenEndpoint, form, cl)
		var oe *oauthError
		if errors.As(err, &oe) && (oe.status == 400 || oe.status == 401) && (oe.code == "invalid_grant" || oe.code == "invalid_client") {
			refused = true
		}
	}
	tx, txErr := s.db.BeginTx(context.WithoutCancel(ctx), nil)
	if txErr != nil {
		return "", false, txErr
	}
	defer tx.Rollback()
	// The result is stored only while the credential is still the one
	// refreshed: a sign-out, a dropped source, or a new sign-in in the
	// meantime wins, and newly issued tokens are revoked.
	current, still, err2 := readCredential(ctx, tx, k)
	if err2 != nil {
		return "", false, err2
	}
	if !still || current.AccessToken != c.AccessToken {
		if !refused && err == nil {
			fresh := c
			fresh.AccessToken, fresh.RefreshToken = answer.AccessToken, answer.RefreshToken
			s.revokeInBackground([]oauthCredential{fresh})
		}
		return "", false, errLoginRequired
	}
	at := timestamp(now)
	switch {
	case refused:
		c.State = credLoginRequired
	case err != nil:
		c.State = credRefreshFailed
		if c.RefreshFailedAt == nil {
			c.RefreshFailedAt = &at
		}
	default:
		c.AccessToken, c.ExpiresAt, c.RefreshedAt, c.State, c.RefreshFailedAt = answer.AccessToken, expiresAt(now, answer), &at, credOK, nil
		if answer.RefreshToken != nil {
			c.RefreshToken = answer.RefreshToken
		}
		if answer.Scope != nil {
			c.Scope = answer.Scope
		}
	}
	if err := writeCredential(ctx, tx, k, c); err != nil {
		return "", false, err
	}
	if refused || err != nil {
		if e := appendEvent(ctx, tx, "sources.token_refresh_failed", k.subject(), at); e != nil {
			return "", false, e
		}
	}
	if refused {
		if e := syncLoginReason(ctx, tx, k.Agent, k.Server); e != nil {
			return "", false, e
		}
	}
	if e := tx.Commit(); e != nil {
		return "", false, e
	}
	if refused {
		return "", false, errLoginRequired
	}
	return c.AccessToken, err == nil, nil
}

// revoke posts the refresh token, then the access token, to the revocation
// endpoint, and reports whether every one got a 200.
func (s *Store) revoke(ctx context.Context, c oauthCredential) bool {
	if c.RevocationEndpoint == nil {
		return false
	}
	cl, found, err := readClient(ctx, s.db, c.Client.Issuer, c.Client.RedirectURI)
	if err != nil || !found {
		return false
	}
	ok := true
	post := func(token, hint string) {
		status, _, err := postForm(ctx, *c.RevocationEndpoint, url.Values{"token": {token}, "token_type_hint": {hint}}, cl)
		ok = ok && err == nil && status == http.StatusOK
	}
	if c.RefreshToken != nil {
		post(*c.RefreshToken, "refresh_token")
	}
	post(c.AccessToken, "access_token")
	return ok
}

// revokeInBackground revokes deleted credentials, best effort.
func (s *Store) revokeInBackground(list []oauthCredential) {
	for _, c := range list {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*oauthTimeout)
			defer cancel()
			s.revoke(ctx, c)
		}()
	}
}

// fetchMetadata fetches a JSON object from a metadata URL, which must be
// https or http on a loopback host. It reports the status separately.
func fetchMetadata(ctx context.Context, raw string) (map[string]any, int, error) {
	if !secureURL(raw) {
		return nil, 0, fmt.Errorf("%s is neither https nor loopback", raw)
	}
	ctx, cancel := context.WithTimeout(ctx, oauthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	client := remoteHTTPClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, unwrapURLError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("%s answered HTTP %d", raw, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, metadataMaxBody))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	var out map[string]any
	if json.Unmarshal(data, &out) != nil || out == nil {
		return nil, resp.StatusCode, fmt.Errorf("%s did not answer with a JSON object", raw)
	}
	return out, resp.StatusCode, nil
}

func originOf(u *url.URL) string { return u.Scheme + "://" + u.Host }

// protectedResource finds the authorization servers of an MCP URL.
func protectedResource(ctx context.Context, mcpURL string, challenge *authChallenge) (map[string]any, string, error) {
	u, err := url.Parse(canonicalURL(mcpURL))
	if err != nil {
		return nil, "", err
	}
	var candidates []string
	if challenge != nil && challenge.ResourceMetadata != nil {
		candidates = append(candidates, *challenge.ResourceMetadata)
	}
	if path := strings.TrimPrefix(u.EscapedPath(), "/"); path != "" {
		candidates = append(candidates, originOf(u)+"/.well-known/oauth-protected-resource/"+path)
	}
	candidates = append(candidates, originOf(u)+"/.well-known/oauth-protected-resource")
	var last error
	for _, candidate := range candidates {
		doc, _, err := fetchMetadata(ctx, candidate)
		if err != nil {
			last = err
			continue
		}
		list, _ := doc["authorization_servers"].([]any)
		if len(list) == 0 {
			last = fmt.Errorf("%s lists no authorization_servers", candidate)
			continue
		}
		issuer, ok := list[0].(string)
		allStrings := true
		for _, item := range list {
			if _, isString := item.(string); !isString {
				allStrings = false
			}
		}
		if !ok || !allStrings || issuer == "" {
			last = fmt.Errorf("%s has an invalid authorization_servers", candidate)
			continue
		}
		return doc, issuer, nil
	}
	return nil, "", last
}

// authorizationServer fetches an issuer's metadata from the well-known
// paths in order, and checks it.
func authorizationServer(ctx context.Context, issuer string) (map[string]any, error) {
	u, err := url.Parse(issuer)
	if err != nil || !u.IsAbs() {
		return nil, fmt.Errorf("the issuer %s is not a URL", issuer)
	}
	origin := originOf(u)
	var candidates []string
	if path := strings.TrimRight(u.EscapedPath(), "/"); path != "" {
		candidates = []string{origin + "/.well-known/oauth-authorization-server" + path, origin + "/.well-known/openid-configuration" + path, strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"}
	} else {
		candidates = []string{origin + "/.well-known/oauth-authorization-server", origin + "/.well-known/openid-configuration"}
	}
	var last error
	for _, candidate := range candidates {
		doc, _, err := fetchMetadata(ctx, candidate)
		if err != nil {
			last = err
			continue
		}
		if got, _ := doc["issuer"].(string); got != issuer {
			return nil, fmt.Errorf("the metadata at %s names issuer %q", candidate, got)
		}
		for _, field := range []string{"authorization_endpoint", "token_endpoint"} {
			value, ok := doc[field].(string)
			if !ok || value == "" {
				return nil, fmt.Errorf("the metadata has no %s", field)
			}
		}
		for _, field := range []string{"authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"} {
			if value, ok := doc[field].(string); ok && !secureURL(value) {
				return nil, fmt.Errorf("the metadata's %s is neither https nor loopback", field)
			}
		}
		return doc, nil
	}
	return nil, last
}

func stringField(doc map[string]any, name string) *string {
	if v, ok := doc[name].(string); ok {
		return &v
	}
	return nil
}

func listsString(doc map[string]any, name, value string) bool {
	list, _ := doc[name].([]any)
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// HostLabel is this machine's host name up to its first dot, at most 64
// bytes.
func HostLabel() string {
	name, _ := os.Hostname()
	name, _, _ = strings.Cut(name, ".")
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func clientName() string {
	if label := HostLabel(); label != "" {
		return "Peerspan (" + label + ")"
	}
	return "Peerspan"
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// pendingLogin is a started sign-in, kept in memory only.
type pendingLogin struct {
	id, state, verifier string
	client              oauthClient
	issuer, redirect    string
	scopes, account     *string
	key                 credKey
	source              string
	tokenEndpoint       string
	revocation          *string
	resource            string
	expires             time.Time
}

// LoginStart is POST /v1/sources/{agent}/{server}/login.
type LoginStart struct {
	Capability   *string `json:"capability"`
	Scopes       *string `json:"scopes"`
	ClientID     *string `json:"client_id"`
	ClientSecret *string `json:"client_secret"`
	RedirectPort *int    `json:"redirect_port"`
	Account      *string `json:"account"`
}

// LoginStarted answers a started sign-in.
type LoginStarted struct {
	LoginID          string `json:"login_id"`
	AuthorizationURL string `json:"authorization_url"`
	RedirectURI      string `json:"redirect_uri"`
	ExpiresAt        string `json:"expires_at"`
}

// LoginResult answers a completed sign-in.
type LoginResult struct {
	Source       string  `json:"source"`
	Capability   *string `json:"capability"`
	Issuer       string  `json:"issuer"`
	Scopes       *string `json:"scopes"`
	Account      *string `json:"account"`
	ExpiresAt    *string `json:"expires_at"`
	Registration string  `json:"registration"`
}

func refusal(status int, code, message string) error {
	return &codedError{status: status, code: code, message: message}
}

// resolveSourceArg finds a source by agent name or ID and server.
func (s *Store) resolveSourceArg(ctx context.Context, agent, server string) (string, string, toolServerRecord, error) {
	var id, name string
	err := s.db.QueryRowContext(ctx, `SELECT id, name FROM agents WHERE name = ? OR id = ? ORDER BY name = ? DESC LIMIT 1`, agent, agent, agent).Scan(&id, &name)
	source := agent + "/" + server
	if err == nil {
		source = name + "/" + server
		var rec toolServerRecord
		rec, err = readToolServer(ctx, s.db, id, server)
		if err == nil {
			return id, name, rec, nil
		}
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrNotFound) {
		return "", "", toolServerRecord{}, refusal(http.StatusNotFound, "not_found", "No source "+source+" on this host. Run peerspan sources.")
	}
	return "", "", toolServerRecord{}, err
}

// loginCapability checks a capability named for a sign-in or sign-out.
func (s *Store) loginCapability(ctx context.Context, name *string, agentID, server, source string) (*capabilityRecord, error) {
	if name == nil {
		return nil, nil
	}
	c, err := readCapability(ctx, s.db, *name)
	if errors.Is(err, ErrNotFound) {
		return nil, refusal(http.StatusNotFound, "not_found", "No capability "+*name+" on this host. Run peerspan capability list.")
	}
	if err != nil {
		return nil, err
	}
	if c.AgentID != agentID || c.Source.Server != server {
		return nil, refusal(http.StatusBadRequest, "invalid", *name+" is not built on "+source+".")
	}
	return &c, nil
}

// StartLogin starts a sign-in: it probes the source for its challenge,
// finds the authorization server, gets a client, and builds the PKCE
// authorization URL.
func (s *Store) StartLogin(ctx context.Context, agent, server string, r LoginStart) (LoginStarted, error) {
	if r.RedirectPort != nil && (*r.RedirectPort < 1 || *r.RedirectPort > 65535) {
		return LoginStarted{}, fmt.Errorf("%w: redirect_port is 1 to 65535", ErrInvalid)
	}
	if r.Account != nil && (len(*r.Account) > 256 || strings.ContainsFunc(*r.Account, func(c rune) bool { return c < 0x20 || c == 0x7f })) {
		return LoginStarted{}, fmt.Errorf("%w: account is at most 256 bytes without control characters", ErrInvalid)
	}
	if r.ClientSecret != nil && r.ClientID == nil {
		return LoginStarted{}, fmt.Errorf("%w: client_secret needs client_id", ErrInvalid)
	}
	if r.ClientID != nil && *r.ClientID == "" {
		return LoginStarted{}, fmt.Errorf("%w: client_id is not empty", ErrInvalid)
	}
	agentID, agentName, rec, err := s.resolveSourceArg(ctx, agent, server)
	if err != nil {
		return LoginStarted{}, err
	}
	source := agentName + "/" + server
	capability, err := s.loginCapability(ctx, r.Capability, agentID, server, source)
	if err != nil {
		return LoginStarted{}, err
	}
	noChallenge := refusal(http.StatusConflict, "no_challenge", source+" did not ask for a sign-in, so there is nothing to sign in to.")
	if rec.Transport != "remote" {
		return LoginStarted{}, noChallenge
	}
	if rec.remote().OAuth == nil {
		return LoginStarted{}, refusal(http.StatusConflict, "oauth_disabled", source+" has OAuth turned off in its harness configuration.")
	}
	values, err := toolValues(ctx, s.db, agentID, server)
	if err != nil {
		return LoginStarted{}, err
	}
	if ok, reason, _ := shareability(rec.ToolServerDefinition, values); !ok {
		return LoginStarted{}, refusal(http.StatusConflict, "not_usable", source+" is not usable ("+*reason+"), so Peerspan cannot sign in to it.")
	}
	if hasAuthorization(rec.ToolServerDefinition) {
		return LoginStarted{}, noChallenge
	}
	// The probe: initialize without a token must answer a Bearer challenge.
	spec, err := s.toolLaunch(ctx, s.db, agentID, server, nil)
	if err != nil {
		return LoginStarted{}, err
	}
	spec.Remote.Cred = nil
	conn, err := newHTTPConn(s, spec)
	if err != nil {
		return LoginStarted{}, err
	}
	probeCtx, cancel := context.WithTimeout(ctx, instanceStartTime)
	_, err = conn.initialize(probeCtx)
	cancel()
	conn.stop()
	var status *httpStatusError
	if err == nil || !errors.As(err, &status) {
		if err != nil && strings.HasPrefix(err.Error(), "Peerspan could not reach the server") {
			return LoginStarted{}, refusal(http.StatusBadGateway, "unreachable", "Peerspan could not reach "+source+": "+strings.TrimPrefix(err.Error(), "Peerspan could not reach the server: "))
		}
		return LoginStarted{}, noChallenge
	}
	params, bearer := bearerChallenge(status.header)
	if status.status != 401 || !bearer {
		return LoginStarted{}, noChallenge
	}
	challenge := &authChallenge{ResourceMetadata: optional(params, "resource_metadata"), Scope: optional(params, "scope")}
	if err = s.storeChallenge(ctx, agentID, server, challenge); err != nil {
		return LoginStarted{}, err
	}
	target := remoteURL(rec.ToolServerDefinition, values)
	metadataFailure := func(err error) error {
		return refusal(http.StatusBadGateway, "oauth_metadata", "Peerspan could not read the authorization server metadata for "+source+": "+err.Error())
	}
	resourceDoc, issuer, err := protectedResource(ctx, target, challenge)
	if err != nil {
		return LoginStarted{}, metadataFailure(err)
	}
	meta, err := authorizationServer(ctx, issuer)
	if err != nil {
		return LoginStarted{}, metadataFailure(err)
	}
	if !listsString(meta, "code_challenge_methods_supported", "S256") {
		return LoginStarted{}, refusal(http.StatusConflict, "no_pkce", "The authorization server for "+source+" ("+issuer+") does not advertise PKCE, so Peerspan will not sign in to it.")
	}
	hints := rec.remote().OAuth
	port := 0
	switch {
	case r.RedirectPort != nil:
		port = *r.RedirectPort
	case hints.CallbackPort != nil:
		port = *hints.CallbackPort
	default:
		latest, err := latestClient(ctx, s.db, issuer)
		if err != nil {
			return LoginStarted{}, err
		}
		if latest != nil {
			if u, err := url.Parse(latest.RedirectURI); err == nil {
				port, _ = strconv.Atoi(u.Port())
			}
		}
		if port == 0 {
			if port, err = freePort(); err != nil {
				return LoginStarted{}, err
			}
		}
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	cl, err := s.loginClient(ctx, r, hints, meta, issuer, redirect, source)
	if err != nil {
		return LoginStarted{}, err
	}
	scopes := r.Scopes
	if scopes == nil {
		scopes = hints.Scopes
	}
	if scopes == nil {
		scopes = challenge.Scope
	}
	if scopes == nil {
		if list, ok := resourceDoc["scopes_supported"].([]any); ok && len(list) > 0 {
			var parts []string
			for _, item := range list {
				if v, ok := item.(string); ok {
					parts = append(parts, v)
				}
			}
			joined := strings.Join(parts, " ")
			scopes = &joined
		}
	}
	if scopes != nil && *scopes == "" {
		scopes = nil
	}
	verifierBytes := make([]byte, 32)
	_, _ = rand.Read(verifierBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	digest := sha256.Sum256([]byte(verifier))
	state := randomHex(32)
	resource := canonicalURL(target)
	query := url.Values{"response_type": {"code"}, "client_id": {cl.ClientID}, "redirect_uri": {redirect}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}, "state": {state}, "resource": {resource}}
	if scopes != nil {
		query.Set("scope", *scopes)
	}
	endpoint := *stringField(meta, "authorization_endpoint")
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	key := credKey{agentID, server, ""}
	if capability != nil {
		key.Capability = capability.Name
	}
	login := &pendingLogin{id: "login_" + randomHex(16), state: state, verifier: verifier, client: cl, issuer: issuer, redirect: redirect, scopes: scopes, account: r.Account,
		key: key, source: source, tokenEndpoint: *stringField(meta, "token_endpoint"), revocation: stringField(meta, "revocation_endpoint"), resource: resource, expires: time.Now().Add(loginLifetime)}
	o := s.oauth()
	o.mu.Lock()
	for id, l := range o.logins {
		if time.Now().After(l.expires) {
			delete(o.logins, id)
		}
	}
	o.logins[login.id] = login
	o.mu.Unlock()
	return LoginStarted{LoginID: login.id, AuthorizationURL: endpoint + separator + query.Encode(), RedirectURI: redirect, ExpiresAt: timestamp(login.expires)}, nil
}

// storeChallenge records a probe's challenge and the oauth auth mode.
func (s *Store) storeChallenge(ctx context.Context, agentID, server string, challenge *authChallenge) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rec, err := readToolServer(ctx, tx, agentID, server)
	if err != nil {
		return err
	}
	mode := authOAuth
	rec.AuthMode, rec.Challenge = &mode, challenge
	if err = putJSON(ctx, tx, `UPDATE tool_servers SET record = ? WHERE agent_id = ? AND name = ?`, rec, agentID, server); err != nil {
		return err
	}
	if err = syncLoginReason(ctx, tx, agentID, server); err != nil {
		return err
	}
	return tx.Commit()
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// loginClient gets the client for a sign-in: a given client ID, a stored
// registration, the harness hint, or dynamic client registration.
func (s *Store) loginClient(ctx context.Context, r LoginStart, hints *RemoteOAuth, meta map[string]any, issuer, redirect, source string) (oauthClient, error) {
	now := timestamp(time.Now())
	store := func(cl oauthClient) (oauthClient, error) {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return cl, err
		}
		defer tx.Rollback()
		if err = putJSON(ctx, tx, `INSERT INTO oauth_clients (record, issuer, redirect_uri) VALUES (?, ?, ?) ON CONFLICT(issuer, redirect_uri) DO UPDATE SET record = excluded.record`, cl, cl.Issuer, cl.RedirectURI); err != nil {
			return cl, err
		}
		return cl, tx.Commit()
	}
	if r.ClientID != nil {
		cl := oauthClient{Issuer: issuer, RedirectURI: redirect, ClientID: *r.ClientID, ClientSecret: r.ClientSecret, Method: "none", Registration: "manual", CreatedAt: now}
		if cl.ClientSecret != nil {
			cl.Method = "client_secret_post"
			if listsString(meta, "token_endpoint_auth_methods_supported", "client_secret_basic") && !listsString(meta, "token_endpoint_auth_methods_supported", "client_secret_post") {
				cl.Method = "client_secret_basic"
			}
		}
		return store(cl)
	}
	if cl, found, err := readClient(ctx, s.db, issuer, redirect); err != nil || found {
		return cl, err
	}
	if hints.ClientID != nil && *hints.ClientID != "" {
		return store(oauthClient{Issuer: issuer, RedirectURI: redirect, ClientID: *hints.ClientID, Method: "none", Registration: "harness", CreatedAt: now})
	}
	endpoint := stringField(meta, "registration_endpoint")
	if endpoint == nil {
		u, _ := url.Parse(redirect)
		return oauthClient{}, refusal(http.StatusConflict, "no_registration", "The authorization server for "+source+" ("+issuer+") does not let Peerspan register itself. Register an OAuth app with the provider, with redirect URI http://127.0.0.1:"+u.Port()+"/callback, then run: peerspan sources login "+source+" --client-id ID [--client-secret-file PATH]")
	}
	cl, err := register(ctx, *endpoint, redirect)
	if err != nil {
		return oauthClient{}, refusal(http.StatusBadGateway, "registration_failed", "The authorization server for "+source+" ("+issuer+") refused to register Peerspan: "+err.Error())
	}
	cl.Issuer, cl.RedirectURI, cl.CreatedAt = issuer, redirect, now
	return store(cl)
}

// register performs dynamic client registration.
func register(ctx context.Context, endpoint, redirect string) (oauthClient, error) {
	body, _ := json.Marshal(map[string]any{"client_name": clientName(), "redirect_uris": []string{redirect}, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none", "application_type": "native"})
	ctx, cancel := context.WithTimeout(ctx, oauthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return oauthClient{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := remoteHTTPClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return oauthClient{}, unwrapURLError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, metadataMaxBody))
	if err != nil {
		return oauthClient{}, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return oauthClient{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var answer struct {
		ClientID                *string `json:"client_id"`
		ClientSecret            *string `json:"client_secret"`
		RegistrationAccessToken *string `json:"registration_access_token"`
		Method                  *string `json:"token_endpoint_auth_method"`
	}
	if json.Unmarshal(data, &answer) != nil || answer.ClientID == nil || *answer.ClientID == "" {
		return oauthClient{}, errors.New("the answer has no client_id")
	}
	cl := oauthClient{ClientID: *answer.ClientID, ClientSecret: answer.ClientSecret, RegistrationAccessToken: answer.RegistrationAccessToken, Method: "none", Registration: "dcr"}
	if cl.ClientSecret != nil && *cl.ClientSecret != "" {
		cl.Method = "client_secret_basic"
		if answer.Method != nil && *answer.Method == "client_secret_post" {
			cl.Method = "client_secret_post"
		}
	} else {
		cl.ClientSecret = nil
	}
	return cl, nil
}

// CompleteLogin finishes a sign-in with the redirect URL: it checks state,
// exchanges the code, stores the credential, and snapshots.
func (s *Store) CompleteLogin(ctx context.Context, id, callback string) (LoginResult, error) {
	o := s.oauth()
	o.mu.Lock()
	login := o.logins[id]
	delete(o.logins, id)
	o.mu.Unlock()
	if login == nil {
		return LoginResult{}, refusal(http.StatusBadRequest, "login_expired", "This sign-in link is no longer valid. Run peerspan sources login SOURCE again.")
	}
	expired := refusal(http.StatusBadRequest, "login_expired", "This sign-in link is no longer valid. Run peerspan sources login "+login.source+" again.")
	u, err := url.Parse(strings.TrimSpace(callback))
	if err != nil || time.Now().After(login.expires) {
		return LoginResult{}, expired
	}
	q := u.Query()
	if q.Get("state") == "" || q.Get("state") != login.state {
		return LoginResult{}, expired
	}
	if e := q.Get("error"); e != "" {
		text := "The provider refused the sign-in: " + e
		if d := q.Get("error_description"); d != "" {
			text += " (" + d + ")"
		}
		return LoginResult{}, refusal(http.StatusBadRequest, "provider_refused", text+".")
	}
	code := q.Get("code")
	if code == "" {
		return LoginResult{}, refusal(http.StatusBadRequest, "no_code", "The redirect carried no authorization code. Run peerspan sources login "+login.source+" again.")
	}
	now := time.Now()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {login.redirect}, "code_verifier": {login.verifier}, "resource": {login.resource}}
	answer, err := tokenRequest(ctx, login.tokenEndpoint, form, login.client)
	if err != nil {
		oe, ok := err.(*oauthError)
		if !ok {
			oe = &oauthError{code: "unreachable", description: err.Error()}
		}
		return LoginResult{}, refusal(http.StatusBadGateway, "token_refused", "The provider refused to issue a token: "+oe.text()+".")
	}
	scope := answer.Scope
	if scope == nil {
		scope = login.scopes
	}
	cred := oauthCredential{Issuer: login.issuer, Resource: login.resource, Registration: login.client.Registration, Client: oauthClientRef{login.issuer, login.redirect},
		TokenEndpoint: login.tokenEndpoint, RevocationEndpoint: login.revocation, AccessToken: answer.AccessToken, RefreshToken: answer.RefreshToken, TokenType: "Bearer",
		ExpiresAt: expiresAt(now, answer), Scope: scope, Account: login.account, ObtainedAt: timestamp(now), State: credOK}
	k := login.key
	lock := o.lock(k)
	lock.Lock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		lock.Unlock()
		return LoginResult{}, err
	}
	defer tx.Rollback()
	// The sign-in's target must still be there, at the same resource: a
	// source dropped or changed, or a capability removed, while the person
	// approved invalidates it, and the issued tokens are revoked.
	if live, err := loginTargetLive(ctx, tx, k, login.resource); err != nil || !live {
		lock.Unlock()
		if err != nil {
			return LoginResult{}, err
		}
		s.revokeInBackground([]oauthCredential{cred})
		return LoginResult{}, expired
	}
	old, hadOld, err := readCredential(ctx, tx, k)
	if err == nil {
		err = writeCredential(ctx, tx, k, cred)
	}
	if err == nil && k.Capability != "" {
		var c capabilityRecord
		if c, err = readCapability(ctx, tx, k.Capability); err == nil {
			c.OwnSignIn = true
			err = putJSON(ctx, tx, `UPDATE capabilities SET record = ? WHERE name = ?`, c, c.Name)
		}
	}
	if err == nil {
		err = appendEvent(ctx, tx, "sources.login", k.subject(), cred.ObtainedAt)
	}
	if err == nil {
		err = syncLoginReason(ctx, tx, k.Agent, k.Server)
	}
	if err == nil {
		err = tx.Commit()
	}
	lock.Unlock()
	if err != nil {
		return LoginResult{}, err
	}
	o.mu.Lock()
	delete(o.stale, k)
	o.mu.Unlock()
	if hadOld && old.AccessToken != cred.AccessToken && (old.RefreshToken == nil || cred.RefreshToken == nil || *old.RefreshToken != *cred.RefreshToken) {
		s.revokeInBackground([]oauthCredential{old})
	}
	s.snapshotAfterLogin(context.WithoutCancel(ctx), k)
	var capability *string
	if k.Capability != "" {
		name := k.Capability
		capability = &name
	}
	return LoginResult{Source: login.source, Capability: capability, Issuer: cred.Issuer, Scopes: cred.Scope, Account: cred.Account, ExpiresAt: cred.ExpiresAt, Registration: cred.Registration}, nil
}

// loginTargetLive reports whether a sign-in's source still exists at its
// resource, and its capability, if any, still exists on that source.
func loginTargetLive(ctx context.Context, tx *sql.Tx, k credKey, resource string) (bool, error) {
	rec, err := readToolServer(ctx, tx, k.Agent, k.Server)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	values, err := toolValues(ctx, tx, k.Agent, k.Server)
	if err != nil {
		return false, err
	}
	if rec.Transport != "remote" || canonicalURL(remoteURL(rec.ToolServerDefinition, values)) != resource {
		return false, nil
	}
	if k.Capability == "" {
		return true, nil
	}
	c, err := readCapability(ctx, tx, k.Capability)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil && c.AgentID == k.Agent && c.Source.Server == k.Server, err
}

// snapshotAfterLogin retires the instances that used the old credential and
// snapshots the source, or the capability's own instance.
func (s *Store) snapshotAfterLogin(ctx context.Context, k credKey) {
	lock := s.agentToolLock(k.Agent)
	lock.Lock()
	defer lock.Unlock()
	target := snapshotTarget{server: k.Server}
	if k.Capability != "" {
		c, err := readCapability(ctx, s.db, k.Capability)
		if err != nil {
			return
		}
		target.own = c.credential()
		s.retireCapability(k.Capability)
	} else {
		s.retireInstances(k.Agent, map[string]bool{k.Server: true})
	}
	spec, err := s.toolLaunch(ctx, s.db, k.Agent, k.Server, target.own)
	var snap toolSnapshot
	if err == nil {
		snap, err = s.takeSnapshot(ctx, spec)
	}
	_ = s.recordSnapshot(ctx, k.Agent, target, snap, err)
}

// Logout is POST /v1/sources/{agent}/{server}/logout's answer.
type Logout struct {
	Source     string  `json:"source"`
	Capability *string `json:"capability"`
	Revoked    bool    `json:"revoked"`
	Deleted    bool    `json:"deleted"`
}

// Logout revokes a credential where the provider allows it, then deletes
// it whatever the revocation did. A capability keeps own_sign_in.
func (s *Store) Logout(ctx context.Context, agent, server string, capability *string) (Logout, error) {
	agentID, agentName, _, err := s.resolveSourceArg(ctx, agent, server)
	if err != nil {
		return Logout{}, err
	}
	source := agentName + "/" + server
	if _, err = s.loginCapability(ctx, capability, agentID, server, source); err != nil {
		return Logout{}, err
	}
	k := credKey{agentID, server, deref(capability)}
	out := Logout{Source: source, Capability: capability}
	// Held across reading, revoking, and deleting, so a refresh cannot
	// rotate the tokens in between.
	lock := s.oauth().lock(k)
	lock.Lock()
	defer lock.Unlock()
	cred, found, err := readCredential(ctx, s.db, k)
	if err != nil || !found {
		return out, err
	}
	out.Revoked = s.revoke(ctx, cred)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	name := k.Capability
	deleted, err := deleteCredentials(ctx, tx, agentID, server, &name)
	if err != nil {
		return out, err
	}
	out.Deleted = len(deleted) > 0
	if out.Deleted {
		if err = appendEvent(ctx, tx, "sources.logout", k.subject(), timestamp(time.Now())); err != nil {
			return out, err
		}
	}
	if err = syncLoginReason(ctx, tx, agentID, server); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	if k.Capability != "" {
		s.retireCapability(k.Capability)
	} else {
		s.retireInstances(agentID, map[string]bool{server: true})
	}
	return out, nil
}

func oauthRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/sources/{agent}/{server}/login", func(w http.ResponseWriter, r *http.Request) {
		var req LoginStart
		if !decode(w, r, &req, "capability?", "scopes?", "client_id?", "client_secret?", "redirect_port?", "account?") {
			return
		}
		started, err := store.StartLogin(r.Context(), r.PathValue("agent"), r.PathValue("server"), req)
		respond(w, http.StatusOK, started, err)
	})
	mux.HandleFunc("POST /v1/oauth/logins/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CallbackURL string `json:"callback_url"`
		}
		if !decode(w, r, &req, "callback_url") {
			return
		}
		result, err := store.CompleteLogin(r.Context(), r.PathValue("id"), req.CallbackURL)
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("POST /v1/sources/{agent}/{server}/logout", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Capability *string `json:"capability"`
		}
		if !decode(w, r, &req, "capability?") {
			return
		}
		result, err := store.Logout(r.Context(), r.PathValue("agent"), r.PathValue("server"), req.Capability)
		respond(w, http.StatusOK, result, err)
	})
}
