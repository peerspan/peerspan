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

// ClientError retains the status for owner workflows that must distinguish a
// confirmed refusal from an unknown outcome after a lost response.
type ClientError struct {
	Status        int
	Code, Message string
}

func (e *ClientError) Error() string { return "host service: " + e.Message }

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
	// Directory refreshes and sends by address may wait 10 seconds for
	// peers, and then for the exchange.
	client := &http.Client{Transport: transport, Timeout: time.Minute}
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, fmt.Errorf("host response exceeds 16 MiB")
	}
	if resp.StatusCode >= 400 {
		var failure struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if err := json.Unmarshal(data, &failure); err != nil {
			return nil, fmt.Errorf("host service returned HTTP %d", resp.StatusCode)
		}
		return nil, &ClientError{Status: resp.StatusCode, Code: failure.Code, Message: failure.Error}
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid JSON from host service")
	}
	return data, nil
}

func (c Client) transport() *http.Transport {
	return &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.SocketPath)
	}}
}

// clientError decodes a JSON error response.
func clientError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var failure struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(data, &failure); err != nil {
		return fmt.Errorf("host service returned HTTP %d", resp.StatusCode)
	}
	return &ClientError{Status: resp.StatusCode, Code: failure.Code, Message: failure.Error}
}

// Upload posts a raw body, such as an artifact file, and returns the JSON
// response.
func (c Client) Upload(ctx context.Context, path string, body io.Reader, size int64) (json.RawMessage, error) {
	transport := c.transport()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+path, body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to local host service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, clientError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid JSON from host service")
	}
	return data, nil
}

// Download copies a raw response body, such as an artifact, to w and returns
// the number of bytes written.
func (c Client) Download(ctx context.Context, path string, w io.Writer) (int64, error) {
	transport := c.transport()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("connect to local host service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, clientError(resp)
	}
	n, err := io.Copy(w, resp.Body)
	if err == nil && resp.ContentLength >= 0 && n != resp.ContentLength {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
