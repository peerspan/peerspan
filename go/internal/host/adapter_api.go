package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// AdapterHandler has no owner administration or arbitrary outbound routes.
func AdapterHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	token := func(r *http.Request) AdapterAuth {
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			return AdapterAuth{}
		}
		value, ok := strings.CutPrefix(values[0], "Bearer ")
		if !ok {
			return AdapterAuth{}
		}
		instance := r.Header.Values("X-Capsule-Instance")
		if len(instance) != 1 {
			return AdapterAuth{Token: value}
		}
		return AdapterAuth{Token: value, Instance: instance[0]}
	}
	mux.HandleFunc("GET /adapter/v1/session", func(w http.ResponseWriter, r *http.Request) {
		tx, err := store.db.BeginTx(r.Context(), nil)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		defer tx.Rollback()
		_, ss, err := adapterAuthority(r.Context(), tx, token(r))
		if err == nil {
			ss.Channel, err = sessionChannel(r.Context(), tx, ss.ID, time.Now())
		}
		respond(w, 200, ss, err)
	})
	mux.HandleFunc("POST /adapter/v1/next", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		h, err := store.NextDelivery(r.Context(), token(r))
		respond(w, 200, h, err)
	})
	mux.HandleFunc("POST /adapter/v1/deliveries/{id}/forwarded", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		d, err := store.Forwarded(r.Context(), token(r), r.PathValue("id"))
		respond(w, 200, d, err)
	})
	mux.HandleFunc("POST /adapter/v1/deliveries/{id}/reply", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content string `json:"content"`
		}
		if !decode(w, r, &req, "content") {
			return
		}
		reply, err := store.Reply(r.Context(), token(r), r.PathValue("id"), req.Content)
		respond(w, 200, reply, err)
	})
	adapterOutboundRoutes(mux, store, token)
	adapterConnectionRoutes(mux, store, token)
	adapterTaskRoutes(mux, store, token)
	adapterLiveDeliveryRoutes(mux, store, token)
	return store.presenceTouching(mux)
}
func localAdapterRoutes(mux *http.ServeMux, store *Store) {
	localSetupRoute(mux, store)
	localOutboundRoutes(mux, store)
	localConnectionRoutes(mux, store)
	localLiveDeliveryRoutes(mux, store)
	mux.HandleFunc("POST /v1/adapters", func(w http.ResponseWriter, r *http.Request) {
		var req CreateAdapter
		if !decode(w, r, &req, "session_id", "expires_at") {
			return
		}
		a, err := store.CreateAdapter(r.Context(), req)
		respond(w, 201, a, err)
	})
	mux.HandleFunc("GET /v1/adapters", func(w http.ResponseWriter, r *http.Request) {
		a, err := store.Adapters(r.Context())
		respond(w, 200, a, err)
	})
	mux.HandleFunc("GET /v1/adapters/{id}", func(w http.ResponseWriter, r *http.Request) {
		a, err := store.Adapter(r.Context(), r.PathValue("id"))
		respond(w, 200, a, err)
	})
	mux.HandleFunc("POST /v1/adapters/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		a, err := store.RevokeAdapter(r.Context(), r.PathValue("id"))
		respond(w, 200, a, err)
	})
	mux.HandleFunc("GET /v1/deliveries/{id}", func(w http.ResponseWriter, r *http.Request) {
		d, err := store.Delivery(r.Context(), r.PathValue("id"))
		respond(w, 200, d, err)
	})
	mux.HandleFunc("GET /v1/deliveries", func(w http.ResponseWriter, r *http.Request) {
		after, limit := int64(0), int64(100)
		var err error
		if v := r.URL.Query().Get("after"); v != "" {
			after, err = strconv.ParseInt(v, 10, 64)
		}
		if v := r.URL.Query().Get("limit"); v != "" && err == nil {
			limit, err = strconv.ParseInt(v, 10, 64)
		}
		if err != nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		d, err := store.Deliveries(r.Context(), after, limit)
		respond(w, 200, d, err)
	})
	mux.HandleFunc("POST /v1/outbound/{peer}/{id}/reply", func(w http.ResponseWriter, r *http.Request) {
		reply, err := store.FetchReply(r.Context(), r.PathValue("peer"), r.PathValue("id"))
		respond(w, 200, reply, err)
	})
}
func adapterPeerRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("GET /peer/v1/replies/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		reply, err := store.ReceivedReply(r.Context(), id, r.PathValue("id"))
		respond(w, 200, reply, err)
	})
}
func (s *Store) FetchReply(ctx context.Context, peerID, id string) (ReplyStatus, error) {
	out, err := s.Outbound(ctx, peerID, id)
	if err != nil {
		return ReplyStatus{}, err
	}
	if saved, err := s.OutboundReply(ctx, peerID, id); err == nil {
		return ReplyStatus{State: "replied", Reply: &saved}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return ReplyStatus{}, err
	}
	peer, err := s.dialPeer(ctx, peerID)
	if err != nil {
		return ReplyStatus{}, err
	}
	// A peer without a direct address may still be reachable through a relay.
	status := ReplyStatus{State: "unknown"}
	code, data, err := s.peerRequest(ctx, peer, http.MethodGet, "/peer/v1/replies/"+id, nil)
	if err == nil {
		if code == 404 {
			status.State = "pending"
			return status, nil
		}
		if code != 200 {
			err = errors.New("peer reply lookup failed")
		} else {
			var reply Reply
			if err == nil {
				decoder := json.NewDecoder(bytes.NewReader(data))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&reply)
				if err == nil && decoder.Decode(new(any)) != io.EOF {
					err = errors.New("invalid peer reply")
				}
			}
			if err == nil && (!utf8.Valid(data) || !validReply(reply, s.identity.ID, peerID, out.Request)) {
				err = errors.New("invalid peer reply")
			}
			if err == nil {
				finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				reply, err = s.SaveOutboundReply(finishCtx, peerID, reply)
				if err != nil {
					return ReplyStatus{}, err
				}
				return ReplyStatus{State: "replied", Reply: &reply}, nil
			}
		}
	}
	if err != nil {
		message := "peer reply could not be confirmed"
		status.Error = &message
	}
	return status, nil
}
func validReply(r Reply, sender, receiver string, m MessageRequest) bool {
	_, err := parseTime(r.RepliedAt)
	return err == nil && r.SenderHostID == sender && r.ReceiverHostID == receiver && r.RequestID == m.RequestID && r.TargetAgentID == m.TargetAgentID && validID(r.SessionID, "session", 16) && validID(r.DeliveryID, "delivery", 16) && r.Content != "" && len(r.Content) <= 65536 &&
		(r.Origin == nil || (r.Origin.valid() && r.Origin.AgentID == r.TargetAgentID && r.Origin.SessionID == r.SessionID))
}
