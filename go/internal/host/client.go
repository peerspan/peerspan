package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client talks only to the owner-local Unix socket; it cannot call remote hosts.
type Client struct{ SocketPath string }

func (c Client) Call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		input = bytes.NewReader(encoded)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.SocketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, input)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to local host service: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("host response exceeds 1 MiB")
	}
	if resp.StatusCode >= 400 {
		var failure struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(data, &failure); err != nil {
			return nil, fmt.Errorf("host service returned HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("host service: %s", failure.Error)
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid JSON from host service")
	}
	return data, nil
}
