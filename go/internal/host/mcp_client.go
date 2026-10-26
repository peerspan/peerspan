package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// A minimal MCP client over stdio (capabilities contract): newline-delimited
// JSON-RPC 2.0 with one server process, used for snapshots and calls.

const (
	mcpProtocolVersion = "2025-06-18"
	// mcpMaxLine bounds one message from a server; a larger one ends the
	// process as broken.
	mcpMaxLine = 16 << 20
	// toolLogLimit is what a server's stderr log keeps at each start.
	toolLogLimit = 1 << 20
)

// mcpSupportedVersions are the protocol versions this client accepts when a
// server negotiates one other than the one requested.
var mcpSupportedVersions = map[string]bool{"2025-06-18": true, "2025-03-26": true, "2024-11-05": true}

// rpcError is a JSON-RPC error object.
type rpcError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// rpcResponse is a server's answer to one request.
type rpcResponse struct {
	Result json.RawMessage
	Error  *rpcError
	// Size is the encoded size of the result or error object.
	Size int
	// Fail is set when a remote exchange ended without a response.
	Fail *transportFailure
}

// launchSpec is how to start one source or capability instance.
type launchSpec struct {
	Command string
	Args    []string
	Env     []string
	Dir     string
	LogPath string
	// ghPath is the gh executable of a built-in gh source's instance.
	ghPath string
	// Remote is set for a remote server's instance.
	Remote *remoteSpec
}

// mcpProcess is one running server.
type mcpProcess struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[int64]chan rpcResponse
	nextID  int64
	done    chan struct{}
	exitErr error
	logFile *os.File
	// late is called with each response that arrives for no pending request.
	late func(id int64)
}

var errProcessExited = errors.New("the server exited")

// prepareToolLog truncates a server's stderr log to its last 1 MiB and opens
// it for appending, creating it and its directory privately.
func prepareToolLog(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(filepath.Dir(filepath.Dir(path)), 0o700)
	_ = os.Chmod(filepath.Dir(path), 0o700)
	if info, err := os.Stat(path); err == nil && info.Size() > toolLogLimit {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		tail := make([]byte, toolLogLimit)
		_, err = f.ReadAt(tail, info.Size()-toolLogLimit)
		f.Close()
		if err != nil {
			return nil, err
		}
		if err = os.WriteFile(path, tail, 0o600); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(0o600)
	return f, nil
}

// startMCP starts a server process in its own process group.
func startMCP(spec launchSpec) (*mcpProcess, error) {
	if spec.Command == "" {
		return nil, errors.New("the server has no command")
	}
	logFile, err := prepareToolLog(spec.LogPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = spec.Env
	cmd.Dir = spec.Dir
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		logFile.Close()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logFile.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		logFile.Close()
		return nil, err
	}
	p := &mcpProcess{cmd: cmd, stdin: stdin, pending: map[int64]chan rpcResponse{}, done: make(chan struct{}), logFile: logFile}
	go p.read(stdout)
	return p, nil
}

// logf appends a note to the server's log.
func (p *mcpProcess) logf(format string, args ...any) {
	fmt.Fprintf(p.logFile, "[peerspan %s] %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// read dispatches responses until the server's stdout ends, then reaps it.
func (p *mcpProcess) read(stdout io.Reader) {
	reader := bufio.NewReaderSize(stdout, 64<<10)
	var err error
	for {
		var line []byte
		line, err = readLine(reader)
		if err != nil {
			break
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		p.handle(line)
	}
	_ = p.stdin.Close()
	waitErr := p.cmd.Wait()
	p.mu.Lock()
	if errors.Is(err, errLineTooLong) {
		p.exitErr = err
	} else {
		p.exitErr = waitErr
	}
	// Waiters see done; their responses will never come.
	p.pending = map[int64]chan rpcResponse{}
	p.mu.Unlock()
	close(p.done)
	p.logFile.Close()
}

var errLineTooLong = errors.New("a server message exceeded the size limit")

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > mcpMaxLine {
			return nil, errLineTooLong
		}
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if len(line) > 0 && errors.Is(err, io.EOF) {
				return line, nil
			}
			return nil, err
		}
	}
}

// handle routes one message: a response to a pending request, a request
// from the server (answered: ping, otherwise method not found), or a
// notification (ignored).
func (p *mcpProcess) handle(line []byte) {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method *string         `json:"method"`
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if json.Unmarshal(line, &msg) != nil {
		return
	}
	if msg.Method != nil {
		if len(msg.ID) == 0 || string(msg.ID) == "null" {
			return
		}
		if *msg.Method == "ping" {
			_ = p.write(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{}})
			return
		}
		_ = p.write(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": rpcError{Code: -32601, Message: "method not found"}})
		return
	}
	var id int64
	if json.Unmarshal(msg.ID, &id) != nil {
		return
	}
	p.mu.Lock()
	ch, ok := p.pending[id]
	delete(p.pending, id)
	late := p.late
	p.mu.Unlock()
	if !ok {
		if late != nil {
			late(id)
		}
		return
	}
	r := rpcResponse{Result: msg.Result, Error: msg.Error, Size: len(msg.Result)}
	if msg.Error != nil {
		data, _ := json.Marshal(msg.Error)
		r.Size = len(data)
	}
	if msg.Result == nil && msg.Error == nil {
		r.Error = &rpcError{Code: -32603, Message: "the server's response had neither result nor error"}
	}
	ch <- r
}

func (p *mcpProcess) write(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, err = p.stdin.Write(append(data, '\n'))
	return err
}

// send writes a request and returns its ID and the channel its response
// arrives on.
func (p *mcpProcess) send(method string, params any) (int64, chan rpcResponse, error) {
	ch := make(chan rpcResponse, 1)
	p.mu.Lock()
	select {
	case <-p.done:
		p.mu.Unlock()
		return 0, nil, errProcessExited
	default:
	}
	p.nextID++
	id := p.nextID
	p.pending[id] = ch
	p.mu.Unlock()
	if err := p.write(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		p.forget(id)
		return 0, nil, err
	}
	return id, ch, nil
}

// forget drops a pending request, so its response, if it comes, is late.
func (p *mcpProcess) forget(id int64) {
	p.mu.Lock()
	delete(p.pending, id)
	p.mu.Unlock()
}

// request sends a request and waits for its response, the context, or exit.
func (p *mcpProcess) request(ctx context.Context, method string, params any) (rpcResponse, error) {
	id, ch, err := p.send(method, params)
	if err != nil {
		return rpcResponse{}, err
	}
	select {
	case r := <-ch:
		return r, nil
	case <-p.done:
		return rpcResponse{}, errProcessExited
	case <-ctx.Done():
		p.forget(id)
		return rpcResponse{}, ctx.Err()
	}
}

func (p *mcpProcess) notify(method string, params any) error {
	message := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		message["params"] = params
	}
	return p.write(message)
}

// initialize performs the MCP handshake and returns the server's
// capabilities.
func (p *mcpProcess) initialize(ctx context.Context) (map[string]json.RawMessage, error) {
	r, err := p.request(ctx, "initialize", map[string]any{
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
	if !mcpSupportedVersions[result.ProtocolVersion] {
		return nil, fmt.Errorf("the server negotiated unsupported protocol version %q", result.ProtocolVersion)
	}
	if err = p.notify("notifications/initialized", nil); err != nil {
		return nil, err
	}
	if result.Capabilities == nil {
		result.Capabilities = map[string]json.RawMessage{}
	}
	return result.Capabilities, nil
}

// stop ends the server: stdin is closed, then its process group gets
// SIGTERM and, after two seconds, SIGKILL.
func (p *mcpProcess) stop() {
	_ = p.stdin.Close()
	if p.cmd.Process == nil {
		return
	}
	pgid := p.cmd.Process.Pid
	select {
	case <-p.done:
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	case <-time.After(200 * time.Millisecond):
	}
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-p.done
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}

// SnapshotTool is one tool as a snapshot stores it.
type SnapshotTool struct {
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	ReadOnly    bool            `json:"read_only"`
}

// SnapshotResource is one resource as a snapshot stores it.
type SnapshotResource struct {
	URI         string  `json:"uri"`
	Name        *string `json:"name"`
	Description *string `json:"description"`
	MimeType    *string `json:"mime_type"`
}

// toolSnapshot is what a server reported when it was last listed.
type toolSnapshot struct {
	Tools     []SnapshotTool
	Resources []SnapshotResource
	Reach     *GHReach
	// authMode is what a remote source's probe learned, with its
	// challenge; skip means no snapshot was taken, and none failed.
	authMode  string
	challenge *authChallenge
	skip      bool
}

const (
	snapshotTimeout   = 30 * time.Second
	snapshotMaxItems  = 1000
	snapshotMaxBytes  = 1 << 20
	instanceStartTime = 30 * time.Second
)

// takeSnapshot starts the server, lists its tools and resources, following
// cursors up to 1,000 entries each, and stops it, all within 30 seconds.
func (s *Store) takeSnapshot(ctx context.Context, spec launchSpec) (toolSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	var p mcpConn
	snap := toolSnapshot{Tools: []SnapshotTool{}, Resources: []SnapshotResource{}}
	if spec.Remote != nil {
		usable, err := s.remoteSnapshotCredential(ctx, &spec)
		if err != nil {
			return toolSnapshot{}, err
		}
		if !usable {
			// A capability's own sign-in that cannot be used: no snapshot.
			return toolSnapshot{skip: true}, nil
		}
		c, err := newHTTPConn(s, spec)
		if err != nil {
			return toolSnapshot{}, err
		}
		p = c
	} else {
		proc, err := startMCP(spec)
		if err != nil {
			return toolSnapshot{}, err
		}
		stopOnDone := context.AfterFunc(ctx, func() { _ = proc.stdin.Close() })
		defer stopOnDone()
		p = proc
	}
	defer p.stop()
	capabilities, err := p.initialize(ctx)
	if spec.Remote != nil {
		var done bool
		if snap, done, err = remoteProbe(spec, snap, err); done {
			return snap, err
		}
	}
	if err != nil {
		return toolSnapshot{}, timeoutError(ctx, err)
	}
	if _, ok := capabilities["tools"]; ok {
		err = listPages(ctx, p, "tools/list", "tools", func(raw json.RawMessage) error {
			var t struct {
				Name        *string         `json:"name"`
				Description *string         `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
				Annotations *struct {
					ReadOnlyHint *bool `json:"readOnlyHint"`
				} `json:"annotations"`
			}
			if err := json.Unmarshal(raw, &t); err != nil || t.Name == nil || *t.Name == "" {
				return errors.New("the server listed an invalid tool")
			}
			entry := SnapshotTool{Name: *t.Name, Description: t.Description, InputSchema: t.InputSchema}
			if len(entry.InputSchema) == 0 {
				entry.InputSchema = json.RawMessage("null")
			}
			entry.ReadOnly = t.Annotations != nil && t.Annotations.ReadOnlyHint != nil && *t.Annotations.ReadOnlyHint
			snap.Tools = append(snap.Tools, entry)
			return nil
		}, func() int { return len(snap.Tools) })
		if err != nil {
			return toolSnapshot{}, timeoutError(ctx, err)
		}
	}
	if _, ok := capabilities["resources"]; ok {
		err = listPages(ctx, p, "resources/list", "resources", func(raw json.RawMessage) error {
			var r struct {
				URI         *string `json:"uri"`
				Name        *string `json:"name"`
				Description *string `json:"description"`
				MimeType    *string `json:"mimeType"`
			}
			if err := json.Unmarshal(raw, &r); err != nil || r.URI == nil || *r.URI == "" {
				return errors.New("the server listed an invalid resource")
			}
			snap.Resources = append(snap.Resources, SnapshotResource{URI: *r.URI, Name: r.Name, Description: r.Description, MimeType: r.MimeType})
			return nil
		}, func() int { return len(snap.Resources) })
		if err != nil {
			return toolSnapshot{}, timeoutError(ctx, err)
		}
	}
	data, err := json.Marshal(map[string]any{"tools": snap.Tools, "resources": snap.Resources})
	if err != nil {
		return toolSnapshot{}, err
	}
	if len(data) > snapshotMaxBytes {
		return toolSnapshot{}, fmt.Errorf("the snapshot is %d bytes of JSON, over the 1 MiB limit", len(data))
	}
	return snap, nil
}

func timeoutError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return errors.New("the snapshot did not finish within 30 seconds")
	}
	return err
}

// listPages calls a list method, following nextCursor, until there is no
// cursor or 1,000 entries were read.
func listPages(ctx context.Context, p mcpConn, method, field string, add func(json.RawMessage) error, count func() int) error {
	var cursor *string
	for pages := 0; pages < snapshotMaxItems+1; pages++ {
		params := map[string]any{}
		if cursor != nil {
			params["cursor"] = *cursor
		}
		r, err := p.request(ctx, method, params)
		if err != nil {
			return err
		}
		if r.Error != nil {
			if r.Error.Code == -32601 {
				return nil
			}
			return fmt.Errorf("%s failed: %s", method, r.Error.Message)
		}
		var page map[string]json.RawMessage
		if err = json.Unmarshal(r.Result, &page); err != nil {
			return fmt.Errorf("invalid %s result", method)
		}
		var items []json.RawMessage
		if raw, ok := page[field]; ok {
			if err = json.Unmarshal(raw, &items); err != nil {
				return fmt.Errorf("invalid %s result", method)
			}
		}
		for _, item := range items {
			if count() >= snapshotMaxItems {
				return errTooManyEntries
			}
			if err = add(item); err != nil {
				return err
			}
		}
		cursor = nil
		if raw, ok := page["nextCursor"]; ok && string(raw) != "null" {
			var next string
			if json.Unmarshal(raw, &next) != nil {
				return fmt.Errorf("invalid %s cursor", method)
			}
			cursor = &next
		}
		if cursor == nil {
			return nil
		}
		if count() >= snapshotMaxItems {
			return errTooManyEntries
		}
	}
	return errTooManyEntries
}

// errTooManyEntries is the snapshot error for a listing past 1,000 entries.
var errTooManyEntries = errors.New("too_many_entries")
