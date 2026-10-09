package host

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
)

func (s *Store) peerCertificate() (tls.Certificate, error) {
	return tlsid.Certificate(s.privateKey, s.identity.ID, time.Now())
}
func (s *Store) PeerTLS(ctx context.Context, expected *Peer) (*tls.Config, error) {
	config := tlsid.Config()
	config.NextProtos = []string{PeerALPN}
	if expected == nil {
		config.ClientAuth = tls.RequireAnyClientCert
		cache := &tlsid.Cache{Key: s.privateKey, Name: s.identity.ID}
		if _, err := cache.Get(); err != nil {
			return nil, err
		}
		config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cache.Get() }
	} else {
		// Each outbound connection constructs a current certificate.
		cert, err := s.peerCertificate()
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
		// Identity is the owner-pinned key, not a DNS name or public CA. Go still
		// verifies CertificateVerify signatures; VerifyConnection below checks trust.
		config.InsecureSkipVerify = true
	}
	config.VerifyConnection = func(connection tls.ConnectionState) error {
		public, err := tlsid.PeerKey(connection)
		if err != nil {
			return err
		}
		if expected != nil {
			key, err := peerKey(*expected)
			if err != nil {
				return err
			}
			if !bytes.Equal(public, key) {
				return errors.New("peer identity pin mismatch")
			}
			return nil
		}
		if _, err := s.KnownHost(ctx, keyID(public), public); err != nil {
			return errors.New("unknown peer")
		}
		return nil
	}
	return config, nil
}

// PeerHandler exposes only message acceptance and sender-scoped receipts.
// Each request rechecks that the connection's key is still a known host, so a
// host removed while its connection stays open is refused.
func PeerHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	sender := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		state := requestTLS(r)
		if state == nil {
			respond(w, 0, nil, ErrForbidden)
			return "", false
		}
		public, err := tlsid.PeerKey(*state)
		if err != nil {
			respond(w, 0, nil, ErrForbidden)
			return "", false
		}
		id := keyID(public)
		if _, err = store.KnownHost(r.Context(), id, public); err != nil {
			respond(w, 0, nil, ErrForbidden)
			return "", false
		}
		return id, true
	}
	mux.HandleFunc("POST /peer/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		var request MessageRequest
		if !decode(w, r, &request, "request_id", "grant_id", "policy", "self", "target_agent_id", "deadline", "content", "origin") {
			return
		}
		receipt, err := store.AcceptMessage(r.Context(), id, request)
		respond(w, http.StatusOK, receipt, err)
	})
	mux.HandleFunc("GET /peer/v1/receipts/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		receipt, err := store.MessageReceipt(r.Context(), id, r.PathValue("id"))
		respond(w, http.StatusOK, receipt, err)
	})
	adapterPeerRoutes(mux, store, sender)
	taskPeerRoutes(mux, store, sender)
	policyPeerRoutes(mux, store, sender)
	directoryPeerRoutes(mux, store, sender)
	// A stream carries exactly one exchange.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		mux.ServeHTTP(w, r)
	})
}
func (s *Store) Exchange(ctx context.Context, out OutboundMessage, receiptOnly bool) (OutboundMessage, error) {
	if out.State == "accepted" {
		return out, nil
	}
	unlock, err := s.lockOutbound(ctx, outboundKey(out.PeerHostID, out.Request.RequestID))
	if err != nil {
		return out, err
	}
	defer unlock()
	// Another attempt may have finished while this one waited.
	if current, err := s.Outbound(ctx, out.PeerHostID, out.Request.RequestID); err == nil && current.State == "accepted" {
		return current, nil
	}
	peer, err := s.dialPeer(ctx, out.PeerHostID)
	if err != nil {
		return out, err
	}
	method, path := http.MethodPost, "/peer/v1/messages"
	var body []byte
	if receiptOnly {
		method, path = http.MethodGet, "/peer/v1/receipts/"+out.Request.RequestID
	} else {
		body, err = json.Marshal(out.Request)
		if err != nil {
			return out, err
		}
	}
	out.State = "unknown"
	out.Error = nil
	status, data, err := s.peerRequest(ctx, peer, method, path, body)
	if err == nil && status == 200 {
		var receipt Receipt
		err = json.Unmarshal(data, &receipt)
		if err == nil && (receipt.SenderHostID != s.identity.ID || receipt.ReceiverHostID != peer.ID || receipt.RequestID != out.Request.RequestID || receipt.TargetAgentID != out.Request.TargetAgentID) {
			err = errors.New("invalid peer receipt")
		}
		if err == nil {
			if _, err = parseTime(receipt.AcceptedAt); err == nil {
				out.State = "accepted"
				out.Receipt = &receipt
			}
		}
	} else if err == nil {
		if !receiptOnly && (status == 400 || status == 403 || status == 404 || status == 409) {
			out.State = "rejected"
		}
		err = fmt.Errorf("peer returned HTTP %d%s", status, refusalHint(out.Request, status))
	}
	if err != nil {
		message := err.Error()
		out.Error = &message
	}
	// Persist outcomes even if the submitting CLI disconnected after the send.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.FinishOutbound(finishCtx, out, receiptOnly)
}
func localPeerRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("POST /v1/peers", func(w http.ResponseWriter, r *http.Request) {
		var p Peer
		if !decode(w, r, &p, "id", "public_key", "address") {
			return
		}
		p, err := store.AddPeer(r.Context(), p)
		respond(w, 200, p, err)
	})
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, r *http.Request) {
		p, err := store.Peers(r.Context())
		respond(w, 200, p, err)
	})
	mux.HandleFunc("GET /v1/peers/{host}/path", func(w http.ResponseWriter, r *http.Request) {
		p, err := store.PeerPath(r.Context(), r.PathValue("host"))
		respond(w, 200, p, err)
	})
	mux.HandleFunc("POST /v1/grants", func(w http.ResponseWriter, r *http.Request) {
		var g CreateGrant
		if !decode(w, r, &g, "requester_host_id", "target_agent_id", "expires_at", "max_message_bytes", "allow_disconnected", "requester_agent_id?", "action", "max_artifact_bytes") {
			return
		}
		grant, err := store.CreateGrant(r.Context(), g)
		respond(w, 201, grant, err)
	})
	mux.HandleFunc("GET /v1/grants", func(w http.ResponseWriter, r *http.Request) {
		g, err := store.Grants(r.Context())
		respond(w, 200, g, err)
	})
	mux.HandleFunc("POST /v1/grants/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		g, err := store.RevokeGrant(r.Context(), r.PathValue("id"))
		respond(w, 200, g, err)
	})
	mux.HandleFunc("GET /v1/messages", func(w http.ResponseWriter, r *http.Request) {
		after, limit := int64(0), int64(100)
		var err error
		if value := r.URL.Query().Get("after"); value != "" {
			after, err = strconv.ParseInt(value, 10, 64)
		}
		if value := r.URL.Query().Get("limit"); value != "" && err == nil {
			limit, err = strconv.ParseInt(value, 10, 64)
		}
		if err != nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		m, err := store.Messages(r.Context(), after, limit)
		respond(w, 200, m, err)
	})
	mux.HandleFunc("POST /v1/outbound", func(w http.ResponseWriter, r *http.Request) {
		var request SendMessage
		if !decode(w, r, &request, "peer_host_id", "request_id", "grant_id?", "target_agent_id", "deadline", "content", "origin", "to", "network") {
			return
		}
		if err := store.checkLocalOrigin(r.Context(), request.Origin); err != nil {
			respond(w, 0, nil, err)
			return
		}
		if request.To == nil && request.Network != "" {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		if request.To != nil {
			// The address is resolved, and an authorization chosen, before
			// anything is persisted.
			if err := store.addressOutbound(r.Context(), &request); err != nil {
				respond(w, 0, nil, err)
				return
			}
		}
		out, err := store.PrepareOutbound(r.Context(), request)
		if err == nil {
			out, err = store.Exchange(r.Context(), out, false)
		}
		respond(w, 200, out, err)
	})
	mux.HandleFunc("GET /v1/outbound/{peer}/{id}", func(w http.ResponseWriter, r *http.Request) {
		out, err := store.Outbound(r.Context(), r.PathValue("peer"), r.PathValue("id"))
		respond(w, 200, out, err)
	})
	for _, action := range []string{"retry", "refresh"} {
		mux.HandleFunc("POST /v1/outbound/{peer}/{id}/"+action, func(w http.ResponseWriter, r *http.Request) {
			out, err := store.Outbound(r.Context(), r.PathValue("peer"), r.PathValue("id"))
			if err == nil {
				out, err = store.Exchange(r.Context(), out, action == "refresh")
			}
			respond(w, 200, out, err)
		})
	}
}

// refusalHint explains a peer's refusal of a policy-cited request.
func refusalHint(r MessageRequest, status int) string {
	switch {
	case r.Self != nil && status == http.StatusForbidden:
		return ": self access needs this host and the receiver bound to the same person in a network they share"
	case r.Policy == nil:
	case status == http.StatusForbidden:
		return ": the receiver's owner policy does not allow this host to message that agent within these bounds, or the receiver blocks this host or its person"
	case status == http.StatusServiceUnavailable:
		return ": the receiver has not yet verified the cited policy version, or is out of sync with coordination; it retries"
	}
	return ""
}
