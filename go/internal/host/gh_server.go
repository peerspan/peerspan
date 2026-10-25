package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// RunGHServer is the hidden builtin-source gh subcommand: a stdio MCP
// server, started by the daemon as any source, that serves the gh
// operations by running the gh executable at ghPath. It handles several
// calls at once, and kills a call's gh process on notifications/cancelled.
// Its log, on logw, names each operation, its exit, and its duration, never
// arguments, input, output, or the token.
func RunGHServer(ctx context.Context, in io.Reader, out io.Writer, logw io.Writer, ghPath, state string) error {
	work, config := ghDirs(state)
	env := ghEnv(os.Environ(), config)
	var writeMu sync.Mutex
	send := func(message map[string]any) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if enc.Encode(message) != nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_, _ = out.Write(buf.Bytes())
	}
	reply := func(id json.RawMessage, result any) {
		send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
	fail := func(id json.RawMessage, code int64, message string) {
		send(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
	}
	var mu sync.Mutex
	running := map[string]context.CancelFunc{}
	var calls sync.WaitGroup
	defer calls.Wait()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64<<10), mcpMaxLine)
	for scanner.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &msg) != nil || msg.Method == "" {
			continue
		}
		hasID := len(msg.ID) > 0 && string(msg.ID) != "null"
		switch msg.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			version := mcpProtocolVersion
			if mcpSupportedVersions[p.ProtocolVersion] {
				version = p.ProtocolVersion
			}
			reply(msg.ID, map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "peerspan-gh", "version": Version}})
		case "ping":
			reply(msg.ID, map[string]any{})
		case "tools/list":
			reply(msg.ID, map[string]any{"tools": ghToolList()})
		case "notifications/cancelled":
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			if json.Unmarshal(msg.Params, &p) == nil {
				mu.Lock()
				if cancel := running[string(p.RequestID)]; cancel != nil {
					cancel()
				}
				mu.Unlock()
			}
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			op, ok := ghOperation(p.Name)
			if !ok {
				fail(msg.ID, -32602, "Unknown tool: "+p.Name)
				continue
			}
			args, err := validateGH(op, p.Arguments)
			if err != nil {
				reply(msg.ID, toolText("Invalid arguments for "+op.name+": "+err.Error(), true))
				continue
			}
			callCtx, cancel := context.WithCancel(ctx)
			key := string(msg.ID)
			mu.Lock()
			running[key] = cancel
			mu.Unlock()
			calls.Add(1)
			go func(id json.RawMessage) {
				defer calls.Done()
				defer func() {
					mu.Lock()
					delete(running, key)
					mu.Unlock()
					cancel()
				}()
				argv, stdin := ghArgv(op, args)
				started := time.Now()
				run := runGH(callCtx, ghPath, argv, env, work, stdin, ghCallTimeout)
				result := ghResult(op, args, run)
				fmt.Fprintf(logw, "%s exit=%s duration_ms=%d\n", op.name, result.exit, time.Since(started).Milliseconds())
				switch {
				case result.silent:
				case result.rpc != nil:
					fail(id, result.rpc.Code, result.rpc.Message)
				default:
					reply(id, toolText(result.text, result.isError))
				}
			}(msg.ID)
		default:
			if hasID {
				fail(msg.ID, -32601, "Method not found: "+msg.Method)
			}
		}
	}
	// The daemon closed standard input: stop running calls.
	mu.Lock()
	for _, cancel := range running {
		cancel()
	}
	mu.Unlock()
	return scanner.Err()
}

func toolText(text string, isError bool) map[string]any {
	result := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
	if isError {
		result["isError"] = true
	}
	return result
}
