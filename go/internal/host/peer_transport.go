package host

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
func (s *Store) ListenPeer(ctx context.Context, address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("%w: peer bind address must be IP:port", ErrInvalid)
	}
	config, err := s.PeerTLS(ctx, nil)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(listener, config), nil
}

// PeerHandler exposes only message acceptance and sender-scoped receipts.
func PeerHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	sender := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if r.TLS == nil {
			respond(w, 0, nil, ErrForbidden)
			return "", false
		}
		public, err := tlsid.PeerKey(*r.TLS)
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
		if !decode(w, r, &request, "request_id", "grant_id", "target_agent_id", "deadline", "content") {
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
	return mux
}
func (s *Store) Exchange(ctx context.Context, out OutboundMessage, receiptOnly bool) (OutboundMessage, error) {
	if out.State == "accepted" {
		return out, nil
	}
	peer, err := s.dialPeer(ctx, out.PeerHostID)
	if err != nil {
		return out, err
	}
	if peer.Address == "" {
		message := "peer has no reachable address"
		out.State, out.Error = "unknown", &message
		return s.FinishOutbound(ctx, out)
	}
	config, err := s.PeerTLS(ctx, &peer)
	if err != nil {
		return out, err
	}
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	method, path := http.MethodPost, "/peer/v1/messages"
	var body io.Reader
	if receiptOnly {
		method, path = http.MethodGet, "/peer/v1/receipts/"+out.Request.RequestID
	} else {
		encoded, err := json.Marshal(out.Request)
		if err != nil {
			return out, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+peer.Address+path, body)
	if err != nil {
		return out, err
	}
	request.Header.Set("Content-Type", "application/json")
	out.State = "unknown"
	out.Error = nil
	response, err := client.Do(request)
	if err == nil {
		defer response.Body.Close()
		var data []byte
		data, err = io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		if err == nil && len(data) > 1<<20 {
			err = errors.New("peer response too large")
		}
		if err == nil {
			if response.StatusCode == 200 {
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
			} else {
				if !receiptOnly && (response.StatusCode == 400 || response.StatusCode == 403 || response.StatusCode == 404 || response.StatusCode == 409) {
					out.State = "rejected"
				}
				err = fmt.Errorf("peer returned HTTP %d", response.StatusCode)
			}
		}
	}
	if err != nil {
		message := err.Error()
		out.Error = &message
	}
	// Persist outcomes even if the submitting CLI disconnected after the send.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.FinishOutbound(finishCtx, out)
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
	mux.HandleFunc("POST /v1/grants", func(w http.ResponseWriter, r *http.Request) {
		var g CreateGrant
		if !decode(w, r, &g, "requester_host_id", "target_agent_id", "expires_at", "max_message_bytes", "allow_disconnected") {
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
		if !decode(w, r, &request, "peer_host_id", "request_id", "grant_id", "target_agent_id", "deadline", "content") {
			return
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
