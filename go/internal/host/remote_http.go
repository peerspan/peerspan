package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The Streamable HTTP MCP client (capabilities slice 3, item A): one MCP
// session per instance, each JSON-RPC message a POST, answered with JSON or
// an event stream.

// mcpConn is one running server instance: a stdio process or an HTTP
// session.
type mcpConn interface {
	initialize(ctx context.Context) (map[string]json.RawMessage, error)
	request(ctx context.Context, method string, params any) (rpcResponse, error)
	send(method string, params any) (int64, chan rpcResponse, error)
	forget(id int64)
	notify(method string, params any) error
	doneChan() <-chan struct{}
	logf(format string, args ...any)
	setLate(func(id int64))
	stop()
}

func (p *mcpProcess) doneChan() <-chan struct{} { return p.done }
func (p *mcpProcess) setLate(f func(id int64)) {
	p.mu.Lock()
	p.late = f
	p.mu.Unlock()
}

// transportFailure is how an HTTP exchange ended a call without a JSON-RPC
// response.
type transportFailure struct {
	state, err string
	// endSession ends the session once the answer is delivered.
	endSession bool
}

const (
	remoteMaxBody       = 2 << 20
	remoteConnectTime   = 10 * time.Second
	remoteNotifyTimeout = 10 * time.Second
)

var remoteVersions = map[string]bool{"2025-03-26": true, "2025-06-18": true, "2025-11-25": true}

// remoteHTTPClient never uses a proxy and never follows redirects. TLS uses
// the system's trust store.
func remoteHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: remoteConnectTime}).DialContext,
		TLSHandshakeTimeout: remoteConnectTime,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		// One connection per request, as the Rust host does.
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// httpStatusError is a non-2xx answer outside a call.
type httpStatusError struct {
	status int
	header http.Header
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("the server answered HTTP %d", e.status) }

// errLoginRequired means the instance's credential cannot be used.
var errLoginRequired = errors.New("the sign-in has lapsed; sign in again")

// bearerChallenge reads the Bearer challenge of WWW-Authenticate headers.
func bearerChallenge(h http.Header) (map[string]string, bool) {
	for _, value := range h.Values("WWW-Authenticate") {
		trimmed := strings.TrimSpace(value)
		if len(trimmed) < 6 || !strings.EqualFold(trimmed[:6], "bearer") || (len(trimmed) > 6 && trimmed[6] != ' ' && trimmed[6] != '\t') {
			continue
		}
		params := map[string]string{}
		for _, m := range challengeParam.FindAllStringSubmatch(trimmed[6:], -1) {
			v := m[2]
			if strings.HasPrefix(v, `"`) {
				v = strings.ReplaceAll(strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`), `\\`, `\`)
			}
			params[strings.ToLower(m[1])] = v
		}
		return params, true
	}
	return nil, false
}

var challengeParam = regexp.MustCompile(`([A-Za-z0-9_\-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s,]+)`)

func optional(params map[string]string, name string) *string {
	if v, ok := params[name]; ok {
		return &v
	}
	return nil
}

// httpConn is one MCP session with a remote server.
type httpConn struct {
	store   *Store
	spec    remoteSpec
	client  *http.Client
	logFile *os.File
	ctx     context.Context
	cancel  context.CancelFunc

	mu       sync.Mutex
	session  string
	version  string
	nextID   int64
	inflight map[int64]context.CancelFunc
	done     chan struct{}
	ended    bool
	late     func(int64)
	lastTok  string
	// onScope records a 403 insufficient_scope with its scope.
	onScope func(scope *string)
}

func newHTTPConn(s *Store, spec launchSpec) (*httpConn, error) {
	logFile, err := prepareToolLog(spec.LogPath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &httpConn{store: s, spec: *spec.Remote, client: remoteHTTPClient(), logFile: logFile, ctx: ctx, cancel: cancel, inflight: map[int64]context.CancelFunc{}, done: make(chan struct{})}, nil
}

func (c *httpConn) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logFile != nil {
		fmt.Fprintf(c.logFile, "[peerspan %s] %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
}

func (c *httpConn) doneChan() <-chan struct{} { return c.done }
func (c *httpConn) setLate(f func(int64)) {
	c.mu.Lock()
	c.late = f
	c.mu.Unlock()
}

// end closes the session: the instance is gone.
func (c *httpConn) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ended {
		c.ended = true
		close(c.done)
		// Outstanding exchanges end with the session.
		for id, cancel := range c.inflight {
			cancel()
			delete(c.inflight, id)
		}
	}
}

// token returns the credential's access token, refreshed when due; with
// force, it refreshes unless another request already replaced stale.
func (c *httpConn) token(ctx context.Context, force bool) (string, error) {
	if c.spec.Cred == nil {
		return "", nil
	}
	c.mu.Lock()
	stale := ""
	if force {
		stale = c.lastTok
	}
	c.mu.Unlock()
	tok, refreshed, err := c.store.oauthToken(ctx, *c.spec.Cred, stale, c.spec.URL)
	if refreshed {
		c.logf("refreshed the access token")
	}
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.lastTok = tok
	c.mu.Unlock()
	return tok, nil
}

// exchange is one POST and what came back.
type exchange struct {
	status  int
	header  http.Header
	resp    rpcResponse
	ok      bool
	sent    bool // the request was written
	dropped bool // the connection failed before a complete answer
	tooBig  bool
	bad     bool // a 2xx that was not a readable response
	err     error
}

// post sends one JSON-RPC message. With id, it reads the answer for it.
func (c *httpConn) post(ctx context.Context, message map[string]any, id *int64, tok string) exchange {
	body, err := json.Marshal(message)
	if err != nil {
		return exchange{err: err}
	}
	var out exchange
	trace := &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { out.sent = true }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, c.spec.URL, bytes.NewReader(body))
	if err != nil {
		out.err = err
		return out
	}
	c.setHeaders(req, tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := c.client.Do(req)
	if err != nil {
		out.err = unwrapURLError(err)
		out.dropped = out.sent
		return out
	}
	defer resp.Body.Close()
	out.status, out.header = resp.StatusCode, resp.Header
	c.logf("%s answered HTTP %d", methodOf(message), resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode > 299 || id == nil {
		// The status decides; the body is not read (connections are never
		// reused), so an answer whose body stays open cannot stall.
		return out
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mediaType {
	case "application/json":
		data, err := io.ReadAll(io.LimitReader(resp.Body, remoteMaxBody+1))
		if err != nil {
			out.dropped, out.err = true, err
			return out
		}
		if len(data) > remoteMaxBody {
			out.tooBig = true
			return out
		}
		r, ok := parseResponse(data, *id)
		out.resp, out.ok, out.bad = r, ok, !ok
	case "text/event-stream":
		c.readStream(ctx, resp.Body, *id, tok, &out)
	default:
		out.bad = true
	}
	return out
}

func methodOf(message map[string]any) string {
	if m, ok := message["method"].(string); ok {
		return m
	}
	return "a response"
}

func unwrapURLError(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err
	}
	return err
}

func (c *httpConn) setHeaders(req *http.Request, tok string) {
	for _, h := range c.spec.Headers {
		req.Header.Set(h[0], h[1])
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	c.mu.Lock()
	session, version := c.session, c.version
	c.mu.Unlock()
	if version != "" {
		req.Header.Set("MCP-Protocol-Version", version)
	}
	if session != "" {
		req.Header.Set("MCP-Session-Id", session)
	}
}

// parseResponse reads one JSON-RPC response for id.
func parseResponse(data []byte, id int64) (rpcResponse, bool) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return rpcResponse{}, false
	}
	var got int64
	if json.Unmarshal(msg.ID, &got) != nil || got != id || (msg.Result == nil && msg.Error == nil) {
		return rpcResponse{}, false
	}
	r := rpcResponse{Result: msg.Result, Error: msg.Error, Size: len(msg.Result)}
	if msg.Error != nil {
		encoded, _ := json.Marshal(msg.Error)
		r.Size = len(encoded)
	}
	return r, true
}

// readStream reads an event stream until the response to id, answering
// requests from the server and dropping everything else.
func (c *httpConn) readStream(ctx context.Context, body io.Reader, id int64, tok string, out *exchange) {
	reader := bufio.NewReaderSize(io.LimitReader(body, remoteMaxBody+1), 64<<10)
	read := 0
	var data []string
	for {
		line, err := reader.ReadString('\n')
		read += len(line)
		if read > remoteMaxBody {
			out.tooBig = true
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" && (err == nil || line != "") {
			if len(data) > 0 {
				payload := []byte(strings.Join(data, "\n"))
				data = nil
				if r, ok := parseResponse(payload, id); ok {
					out.resp, out.ok = r, true
					return
				}
				c.serverMessage(ctx, payload, tok)
			}
		} else if strings.HasPrefix(trimmed, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(trimmed, "data:"), " "))
		}
		if err != nil {
			out.dropped = true
			if !errors.Is(err, io.EOF) {
				out.err = err
			}
			return
		}
	}
}

// serverMessage handles a message on a stream that is not this request's
// response: a request is answered (ping with {}, anything else -32601);
// the rest is dropped.
func (c *httpConn) serverMessage(ctx context.Context, payload []byte, tok string) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method *string         `json:"method"`
	}
	if json.Unmarshal(payload, &msg) != nil {
		c.logf("dropped an unreadable message on an event stream")
		return
	}
	if msg.Method == nil || len(msg.ID) == 0 || string(msg.ID) == "null" {
		c.logf("dropped a message on an event stream")
		return
	}
	answer := map[string]any{"jsonrpc": "2.0", "id": msg.ID}
	if *msg.Method == "ping" {
		answer["result"] = map[string]any{}
	} else {
		answer["error"] = rpcError{Code: -32601, Message: "method not found"}
	}
	c.logf("answered a %s request from the server", *msg.Method)
	go func() {
		ctx, cancel := context.WithTimeout(c.ctx, remoteNotifyTimeout)
		defer cancel()
		c.post(ctx, answer, nil, tok)
	}()
}

// listing methods are repeated once after a refresh on 401.
var retriedMethods = map[string]bool{"initialize": true, "tools/list": true, "resources/list": true}

// call sends a request and waits for its answer, outside calls: a 401 is
// retried once after a refresh for the listing methods.
func (c *httpConn) call(ctx context.Context, method string, params any) (rpcResponse, http.Header, error) {
	for attempt := 0; ; attempt++ {
		tok, err := c.token(ctx, attempt > 0)
		if err != nil {
			return rpcResponse{}, nil, err
		}
		c.mu.Lock()
		c.nextID++
		id := c.nextID
		c.mu.Unlock()
		out := c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}, &id, tok)
		switch {
		case out.err != nil && out.status == 0:
			if ctx.Err() != nil {
				return rpcResponse{}, nil, ctx.Err()
			}
			return rpcResponse{}, nil, fmt.Errorf("Peerspan could not reach the server: %v", out.err)
		case out.status == http.StatusUnauthorized && c.spec.Cred != nil && retriedMethods[method]:
			if attempt == 0 {
				continue
			}
			c.store.markLoginRequired(context.WithoutCancel(ctx), *c.spec.Cred, tok)
			return rpcResponse{}, out.header, errLoginRequired
		case out.status == http.StatusNotFound && c.hasSession():
			c.end()
			return rpcResponse{}, out.header, errors.New("the server ended the session")
		case out.status < 200 || out.status > 299:
			return rpcResponse{}, out.header, &httpStatusError{status: out.status, header: out.header}
		case out.tooBig:
			return rpcResponse{}, out.header, errors.New("the server's response exceeded 2 MiB")
		case !out.ok:
			return rpcResponse{}, out.header, errors.New("the server's answer was not a readable JSON-RPC response")
		}
		return out.resp, out.header, nil
	}
}

func (c *httpConn) hasSession() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != ""
}

func (c *httpConn) request(ctx context.Context, method string, params any) (rpcResponse, error) {
	r, _, err := c.call(ctx, method, params)
	return r, err
}

// initialize opens the session: initialize, the session ID and version it
// sets, then notifications/initialized.
func (c *httpConn) initialize(ctx context.Context) (map[string]json.RawMessage, error) {
	r, header, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "peerspan", "version": Version},
	})
	if err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, fmt.Errorf("initialize failed: %s", r.Error.Message)
	}
	var result struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
	}
	if err = json.Unmarshal(r.Result, &result); err != nil {
		return nil, fmt.Errorf("invalid initialize result: %w", err)
	}
	if !remoteVersions[result.ProtocolVersion] {
		return nil, fmt.Errorf("the server negotiated unsupported protocol version %q", result.ProtocolVersion)
	}
	c.mu.Lock()
	c.version = result.ProtocolVersion
	if session := header.Get("Mcp-Session-Id"); session != "" {
		c.session = session
	}
	hasSession := c.session != ""
	c.mu.Unlock()
	if hasSession {
		c.logf("the server opened a session")
	}
	tok, err := c.token(ctx, false)
	if err != nil {
		return nil, err
	}
	if out := c.post(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, nil, tok); out.err != nil && out.status == 0 {
		return nil, fmt.Errorf("Peerspan could not reach the server: %v", out.err)
	}
	if result.Capabilities == nil {
		result.Capabilities = map[string]json.RawMessage{}
	}
	return result.Capabilities, nil
}

// send starts a call's request and returns the channel its answer, or its
// transport failure, arrives on.
func (c *httpConn) send(method string, params any) (int64, chan rpcResponse, error) {
	c.mu.Lock()
	if c.ended {
		c.mu.Unlock()
		return 0, nil, errProcessExited
	}
	c.nextID++
	id := c.nextID
	ctx, cancel := context.WithCancel(c.ctx)
	c.inflight[id] = cancel
	c.mu.Unlock()
	ch := make(chan rpcResponse, 1)
	go func() {
		defer func() {
			c.mu.Lock()
			delete(c.inflight, id)
			c.mu.Unlock()
			cancel()
		}()
		r := c.callExchange(ctx, method, params, id)
		if ctx.Err() == nil || r.Fail == nil {
			ch <- r
		}
		// A session-ending answer is published before the session ends, so
		// the call sees it rather than the end.
		if r.Fail != nil && r.Fail.endSession {
			c.end()
		}
	}()
	return id, ch, nil
}

func failed(err string) rpcResponse {
	return rpcResponse{Fail: &transportFailure{state: CallFailed, err: err}}
}

// callExchange maps one call's HTTP exchange to its outcome.
func (c *httpConn) callExchange(ctx context.Context, method string, params any, id int64) rpcResponse {
	tok, err := c.token(ctx, false)
	if err != nil {
		return failed(callAuthRequired)
	}
	out := c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}, &id, tok)
	switch {
	case out.status == 0 && !out.sent:
		if out.err != nil {
			c.logf("could not connect: %v", out.err)
		}
		return failed(callServerExited)
	case out.status == 0:
		return rpcResponse{Fail: &transportFailure{state: CallUncertain, err: callConnectionLost}}
	case out.status == http.StatusUnauthorized:
		if c.spec.Cred != nil {
			c.store.markStale(*c.spec.Cred, tok)
		}
		return failed(callAuthRequired)
	case out.status == http.StatusForbidden:
		if params, ok := bearerChallenge(out.header); ok && params["error"] == "insufficient_scope" {
			if c.onScope != nil {
				c.onScope(optional(params, "scope"))
			}
			return failed(callInsufficientScope)
		}
		return failed(callHTTPError)
	case out.status == http.StatusNotFound && c.hasSession():
		// The session ends once this answer is delivered (see send).
		c.logf("the server ended the session")
		r := failed(callServerExited)
		r.Fail.endSession = true
		return r
	case out.status >= 500:
		return rpcResponse{Fail: &transportFailure{state: CallUncertain, err: callHTTPError}}
	case out.status < 200 || out.status > 299:
		return failed(callHTTPError)
	case out.tooBig:
		return failed(callResultTooLarge)
	case out.dropped:
		return rpcResponse{Fail: &transportFailure{state: CallUncertain, err: callConnectionLost}}
	case !out.ok:
		return failed(callHTTPError)
	}
	return out.resp
}

// forget abandons a call's answer.
func (c *httpConn) forget(id int64) {
	c.mu.Lock()
	cancel := c.inflight[id]
	delete(c.inflight, id)
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// notify posts a notification on the session, in the background.
func (c *httpConn) notify(method string, params any) error {
	message := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		message["params"] = params
	}
	go func() {
		ctx, cancel := context.WithTimeout(c.ctx, remoteNotifyTimeout)
		defer cancel()
		tok, err := c.token(ctx, false)
		if err != nil {
			return
		}
		c.post(ctx, message, nil, tok)
	}()
	return nil
}

// stop ends the session with a DELETE when the server set an ID.
func (c *httpConn) stop() {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.spec.URL, nil); err == nil {
			tok, _ := c.token(ctx, false)
			c.setHeaders(req, tok)
			if resp, err := c.client.Do(req); err == nil {
				resp.Body.Close()
				c.logf("ended the session: HTTP %d", resp.StatusCode)
			}
		}
		cancel()
	}
	c.cancel()
	c.end()
	c.mu.Lock()
	if c.logFile != nil {
		c.logFile.Close()
		c.logFile = nil
	}
	c.mu.Unlock()
	c.client.CloseIdleConnections()
}

// startConn starts an instance: a stdio process, or a remote session.
func (s *Store) startConn(spec launchSpec, target instanceTarget) (mcpConn, error) {
	if spec.Remote == nil {
		p, err := startMCP(spec)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
	c, err := newHTTPConn(s, spec)
	if err != nil {
		return nil, err
	}
	c.onScope = func(scope *string) { s.noteInsufficientScope(context.Background(), target, scope) }
	return c, nil
}
