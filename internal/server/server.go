// Package server is the local HTTP control plane.
// The CLI calls this process instead of opening the capsule store itself.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/capsule"
	"github.com/Cerebral-Systems/capsule/internal/control"
	"github.com/Cerebral-Systems/capsule/internal/session"
)

// DefaultAddr is where capsule serve listens, and where the CLI connects.
const DefaultAddr = "127.0.0.1:8077"

// Handler routes control-plane calls onto svc.
func Handler(svc control.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value string `json:"value"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		err := svc.SetSecret(r.PathValue("name"), req.Value)
		writeResult(w, envelope{}, err)
	})
	mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		names, err := svc.ListSecrets()
		writeResult(w, envelope{Secrets: names}, err)
	})
	mux.HandleFunc("POST /v1/capsules", func(w http.ResponseWriter, r *http.Request) {
		var req control.CreateRequest
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		c, err := svc.Create(r.Context(), req)
		writeResult(w, envelope{Capsule: &c}, err)
	})
	mux.HandleFunc("GET /v1/capsules", func(w http.ResponseWriter, r *http.Request) {
		capsules, err := svc.List()
		writeResult(w, envelope{Capsules: capsules}, err)
	})
	mux.HandleFunc("GET /v1/capsules/{id}", func(w http.ResponseWriter, r *http.Request) {
		c, err := svc.Inspect(r.PathValue("id"))
		writeResult(w, envelope{Capsule: &c}, err)
	})
	mux.HandleFunc("POST /v1/capsules/{id}/exec", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Argv []string `json:"argv"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		output, err := svc.Exec(r.Context(), r.PathValue("id"), req.Argv)
		writeResult(w, envelope{Output: output}, err)
	})
	mux.HandleFunc("POST /v1/capsules/{id}/destroy", func(w http.ResponseWriter, r *http.Request) {
		c, err := svc.Destroy(r.PathValue("id"))
		writeResult(w, envelope{Capsule: &c}, err)
	})
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CapsuleID string   `json:"capsule_id"`
			Task      string   `json:"task"`
			Allow     []string `json:"allow,omitempty"`
			AllowExec []string `json:"allow_exec,omitempty"`
			TTL       string   `json:"ttl,omitempty"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		create := control.CreateSessionRequest{
			CapsuleID: req.CapsuleID,
			Task:      req.Task,
			Allow:     req.Allow,
			AllowExec: req.AllowExec,
		}
		if req.TTL != "" && req.TTL != "0" {
			dur, err := time.ParseDuration(req.TTL)
			if err != nil {
				writeError(w, fmt.Errorf("invalid ttl %q", req.TTL))
				return
			}
			create.TTL = dur
		}
		sess, err := svc.CreateSession(create)
		writeResult(w, envelope{Session: &sess}, err)
	})
	mux.HandleFunc("POST /v1/sessions/{id}/accept", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CapsuleID string   `json:"capsule_id"`
			Allow     []string `json:"allow,omitempty"`
			AllowExec []string `json:"allow_exec,omitempty"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		sess, err := svc.AcceptSession(r.PathValue("id"), req.CapsuleID, req.Allow, req.AllowExec)
		writeResult(w, envelope{Session: &sess}, err)
	})
	mux.HandleFunc("POST /v1/sessions/{id}/message", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			From string `json:"from"`
			Text string `json:"text"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		sess, err := svc.MessageSession(r.PathValue("id"), req.From, req.Text)
		writeResult(w, envelope{Session: &sess}, err)
	})
	mux.HandleFunc("POST /v1/sessions/{id}/share", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			From string `json:"from"`
			Path string `json:"path"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		sess, err := svc.ShareSession(r.PathValue("id"), req.From, req.Path)
		writeResult(w, envelope{Session: &sess}, err)
	})
	mux.HandleFunc("POST /v1/sessions/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			By     string `json:"by"`
			Action string `json:"action"`
		}
		if err := readJSON(w, r, &req); err != nil {
			writeError(w, err)
			return
		}
		sess, err := svc.ApproveSession(r.PathValue("id"), req.By, req.Action)
		writeResult(w, envelope{Session: &sess}, err)
	})
	mux.HandleFunc("POST /v1/sessions/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		sess, err := svc.RevokeSession(r.PathValue("id"))
		writeResult(w, envelope{Session: &sess}, err)
	})
	mux.HandleFunc("GET /v1/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
		evidence, err := svc.ExportSession(r.PathValue("id"))
		writeResult(w, envelope{Evidence: &evidence}, err)
	})
	return mux
}

// Serve listens until ctx is cancelled, then shuts down.
func Serve(ctx context.Context, addr string, svc control.Service) error {
	srv := &http.Server{Addr: addr, Handler: Handler(svc)}
	errc := make(chan error, 1)
	go func() {
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		<-errc
		return nil
	}
}

type envelope struct {
	Error    string            `json:"error,omitempty"`
	Capsule  *capsule.Capsule  `json:"capsule,omitempty"`
	Capsules []capsule.Capsule `json:"capsules,omitempty"`
	Output   string            `json:"output,omitempty"`
	Session  *session.Session  `json:"session,omitempty"`
	Evidence *session.Evidence `json:"evidence,omitempty"`
	Secrets  []string          `json:"secrets,omitempty"`
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid json: %w", err)
	}
	return nil
}

func writeResult(w http.ResponseWriter, env envelope, err error) {
	if err != nil {
		env.Error = err.Error()
		writeJSON(w, statusCode(err), env)
		return
	}
	writeJSON(w, http.StatusOK, env)
}

func writeError(w http.ResponseWriter, err error) {
	writeResult(w, envelope{}, err)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func statusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if strings.Contains(err.Error(), "not found") {
		return http.StatusNotFound
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return http.StatusBadGateway
	}
	return http.StatusBadRequest
}
