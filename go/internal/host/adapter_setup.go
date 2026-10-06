package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
)

func (s *Store) VerifyAdapterCredential(ctx context.Context, id, token string) (bool, error) {
	if !validID(token, "token", 32) {
		return false, ErrInvalid
	}
	var digest string
	if err := s.db.QueryRowContext(ctx, "SELECT token_hash FROM adapter_credentials WHERE id = ?", id).Scan(&digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		return false, err
	}
	return digest == tokenHash(token), nil
}

type RouteStatus struct {
	Route             OutboundRoute `json:"route"`
	MessagesRemaining int64         `json:"messages_remaining"`
}

func (s *Store) RouteStatus(ctx context.Context, id string) ([]RouteStatus, error) {
	if _, err := s.Adapter(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT r.record,(SELECT COUNT(*) FROM adapter_outbound o WHERE o.route_id = r.id) FROM adapter_routes r WHERE adapter_id = ? ORDER BY name", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RouteStatus{}
	for rows.Next() {
		var encoded string
		var used int64
		if err := rows.Scan(&encoded, &used); err != nil {
			return nil, err
		}
		var route OutboundRoute
		if err := json.Unmarshal([]byte(encoded), &route); err != nil {
			return nil, err
		}
		result = append(result, RouteStatus{Route: route, MessagesRemaining: route.MaxMessages - used})
	}
	return result, rows.Err()
}

// Owner setup commits attachment, authorization, destinations and any offline
// replacement together. No credential or instance is issued on the peer router.
type AdapterSetupRequest struct {
	AgentID     string       `json:"agent_id"`
	SessionID   string       `json:"session_id"`
	Integration string       `json:"integration"`
	ExpiresAt   string       `json:"expires_at"`
	Routes      []SetupRoute `json:"routes"`
}
type SetupRoute struct {
	Name            string `json:"name"`
	PeerHostID      string `json:"peer_host_id"`
	TargetAgentID   string `json:"target_agent_id"`
	GrantID         string `json:"grant_id"`
	ExpiresAt       string `json:"expires_at"`
	MaxMessageBytes int64  `json:"max_message_bytes"`
	MaxMessages     int64  `json:"max_messages"`
}

func (r *SetupRoute) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 7 {
		return ErrInvalid
	}
	for key, value := range fields {
		switch key {
		case "name", "peer_host_id", "target_agent_id", "grant_id", "expires_at", "max_message_bytes", "max_messages":
		default:
			return ErrInvalid
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalid
		}
	}
	type plain SetupRoute
	return json.Unmarshal(data, (*plain)(r))
}

type AdapterSetup struct {
	Session    Session           `json:"session"`
	Credential AdapterCredential `json:"credential"`
	Routes     []OutboundRoute   `json:"routes"`
}

func (s *Store) SetupAdapter(ctx context.Context, r AdapterSetupRequest) (AdapterSetup, error) {
	if !validID(r.SessionID, "session", 16) || len(r.Routes) > 100 {
		return AdapterSetup{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AdapterSetup{}, err
	}
	defer tx.Rollback()
	ss, err := attachSession(ctx, tx, AttachSession{AgentID: r.AgentID, Integration: r.Integration}, r.SessionID)
	if err != nil {
		return AdapterSetup{}, err
	}
	credential, err := s.createAdapter(ctx, tx, CreateAdapter{SessionID: ss.ID, ExpiresAt: r.ExpiresAt})
	if err != nil {
		return AdapterSetup{}, err
	}
	routes := []OutboundRoute{}
	for _, route := range r.Routes {
		created, err := s.createOutboundRoute(ctx, tx, CreateOutboundRoute{AdapterID: credential.Adapter.ID, Name: route.Name, PeerHostID: route.PeerHostID, TargetAgentID: route.TargetAgentID, GrantID: route.GrantID, ExpiresAt: route.ExpiresAt, MaxMessageBytes: route.MaxMessageBytes, MaxMessages: route.MaxMessages})
		if err != nil {
			return AdapterSetup{}, err
		}
		routes = append(routes, created)
	}
	return AdapterSetup{Session: ss, Credential: credential, Routes: routes}, tx.Commit()
}

func localSetupRoute(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/adapters/{id}/route-status", func(w http.ResponseWriter, r *http.Request) {
		status, err := store.RouteStatus(r.Context(), r.PathValue("id"))
		respond(w, 200, status, err)
	})
	mux.HandleFunc("POST /v1/adapters/{id}/verify-credential", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if !decode(w, r, &req, "token") {
			return
		}
		matches, err := store.VerifyAdapterCredential(r.Context(), r.PathValue("id"), req.Token)
		respond(w, 200, struct {
			Matches bool `json:"matches"`
		}{matches}, err)
	})
	mux.HandleFunc("POST /v1/adapters/setup", func(w http.ResponseWriter, r *http.Request) {
		var req AdapterSetupRequest
		if !decode(w, r, &req, "agent_id", "session_id", "integration", "expires_at", "routes") {
			return
		}
		setup, err := store.SetupAdapter(r.Context(), req)
		respond(w, 201, setup, err)
	})
}
