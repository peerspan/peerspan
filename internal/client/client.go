// Package client calls a running capsule serve process.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/control"
	"github.com/Cerebral-Systems/capsule/internal/server"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

// DefaultBaseURL is the URL of a serve process on the default address.
const DefaultBaseURL = "http://" + server.DefaultAddr

// Client is one CLI's view of the control plane.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

type envelope struct {
	Error    string            `json:"error,omitempty"`
	Capsule  *capsule.Capsule  `json:"capsule,omitempty"`
	Capsules []capsule.Capsule `json:"capsules,omitempty"`
	Output   string            `json:"output,omitempty"`
	Session  *session.Session  `json:"session,omitempty"`
}

// Create asks the server to record a capsule and start its runtime.
func (c Client) Create(ctx context.Context, req control.CreateRequest) (capsule.Capsule, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/capsules", req)
	if env.Capsule != nil {
		return *env.Capsule, err
	}
	return capsule.Capsule{}, err
}

// List returns the server's capsule records.
func (c Client) List(ctx context.Context) ([]capsule.Capsule, error) {
	env, err := c.call(ctx, http.MethodGet, "/v1/capsules", nil)
	return env.Capsules, err
}

// Inspect returns one capsule record.
func (c Client) Inspect(ctx context.Context, id string) (capsule.Capsule, error) {
	env, err := c.call(ctx, http.MethodGet, "/v1/capsules/"+id, nil)
	if env.Capsule != nil {
		return *env.Capsule, err
	}
	return capsule.Capsule{}, err
}

// Exec runs a command in a capsule workspace.
func (c Client) Exec(ctx context.Context, id string, argv []string) (string, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/capsules/"+id+"/exec", map[string]any{"argv": argv})
	return env.Output, err
}

// Destroy stops a capsule.
func (c Client) Destroy(ctx context.Context, id string) (capsule.Capsule, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/capsules/"+id+"/destroy", struct{}{})
	if env.Capsule != nil {
		return *env.Capsule, err
	}
	return capsule.Capsule{}, err
}

// CreateSession opens a pending peering session.
func (c Client) CreateSession(ctx context.Context, req control.CreateSessionRequest) (session.Session, error) {
	body := map[string]any{
		"capsule_id": req.CapsuleID,
		"task":       req.Task,
		"allow":      req.Allow,
		"allow_exec": req.AllowExec,
	}
	if req.TTL > 0 {
		body["ttl"] = req.TTL.String()
	}
	env, err := c.call(ctx, http.MethodPost, "/v1/sessions", body)
	if env.Session != nil {
		return *env.Session, err
	}
	return session.Session{}, err
}

// AcceptSession joins the second capsule to a pending session.
func (c Client) AcceptSession(ctx context.Context, id, capsuleID string, allow, allowExec []string) (session.Session, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/sessions/"+id+"/accept", map[string]any{
		"capsule_id": capsuleID,
		"allow":      allow,
		"allow_exec": allowExec,
	})
	if env.Session != nil {
		return *env.Session, err
	}
	return session.Session{}, err
}

// MessageSession appends a transcript entry.
func (c Client) MessageSession(ctx context.Context, id, capsuleID, text string) (session.Session, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/sessions/"+id+"/message", map[string]string{
		"from": capsuleID,
		"text": text,
	})
	if env.Session != nil {
		return *env.Session, err
	}
	return session.Session{}, err
}

// ShareSession copies an allowlisted file into the session.
func (c Client) ShareSession(ctx context.Context, id, capsuleID, path string) (session.Session, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/sessions/"+id+"/share", map[string]string{
		"from": capsuleID,
		"path": path,
	})
	if env.Session != nil {
		return *env.Session, err
	}
	return session.Session{}, err
}

// ApproveSession records a granted approval.
func (c Client) ApproveSession(ctx context.Context, id, capsuleID, action string) (session.Session, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/sessions/"+id+"/approve", map[string]string{
		"by":     capsuleID,
		"action": action,
	})
	if env.Session != nil {
		return *env.Session, err
	}
	return session.Session{}, err
}

// RevokeSession ends a session.
func (c Client) RevokeSession(ctx context.Context, id string) (session.Session, error) {
	env, err := c.call(ctx, http.MethodPost, "/v1/sessions/"+id+"/revoke", struct{}{})
	if env.Session != nil {
		return *env.Session, err
	}
	return session.Session{}, err
}

// ExportSession returns the session record.
func (c Client) ExportSession(ctx context.Context, id string) (session.Session, error) {
	env, err := c.call(ctx, http.MethodGet, "/v1/sessions/"+id, nil)
	if env.Session != nil {
		return *env.Session, err
	}
	return session.Session{}, err
}

func (c Client) call(ctx context.Context, method, path string, body any) (envelope, error) {
	var buf io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return envelope{}, err
		}
		buf = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, buf)
	if err != nil {
		return envelope{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return envelope{}, fmt.Errorf("capsule serve is not running at %s", c.base())
		}
		var op *net.OpError
		if errors.As(err, &op) && errors.Is(op.Err, syscall.ECONNREFUSED) {
			return envelope{}, fmt.Errorf("capsule serve is not running at %s", c.base())
		}
		return envelope{}, err
	}
	defer resp.Body.Close()
	var env envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return envelope{}, err
	}
	if env.Error != "" {
		return env, errors.New(env.Error)
	}
	if resp.StatusCode >= 300 {
		return env, fmt.Errorf("server returned %s", resp.Status)
	}
	return env, nil
}

func (c Client) base() string {
	if c.BaseURL == "" {
		return DefaultBaseURL
	}
	return strings.TrimRight(c.BaseURL, "/")
}
