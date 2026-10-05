package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"time"
)

func (s *Store) peerCertificate() (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: s.identity.ID}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, s.privateKey.Public(), s.privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: s.privateKey}, nil
}
func certificateKey(cert *x509.Certificate) ([]byte, error) {
	public, ok := cert.PublicKey.(ed25519.PublicKey)
	now := time.Now()
	if !ok || len(public) != 32 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || len(cert.UnhandledCriticalExtensions) > 0 {
		return nil, errors.New("invalid peer certificate")
	}
	return public, nil
}
func (s *Store) PeerTLS(ctx context.Context, expected *Peer) (*tls.Config, error) {
	cert, err := s.peerCertificate()
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	if expected == nil {
		config.ClientAuth = tls.RequireAnyClientCert
	} else {
		// Identity is the owner-pinned key, not a DNS name or public CA. Go still
		// verifies CertificateVerify signatures; VerifyConnection below checks trust.
		config.InsecureSkipVerify = true
	}
	config.VerifyConnection = func(connection tls.ConnectionState) error {
		if len(connection.PeerCertificates) != 1 {
			return errors.New("one peer certificate required")
		}
		public, err := certificateKey(connection.PeerCertificates[0])
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
		peer, err := s.Peer(ctx, keyID(public))
		if err != nil {
			return errors.New("unknown peer")
		}
		key, err := peerKey(peer)
		if err != nil || !bytes.Equal(public, key) {
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
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			respond(w, 0, nil, ErrForbidden)
			return "", false
		}
		public, err := certificateKey(r.TLS.PeerCertificates[0])
		if err != nil {
			respond(w, 0, nil, ErrForbidden)
			return "", false
		}
		id := keyID(public)
		if _, err = store.Peer(r.Context(), id); err != nil {
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
	return mux
}
func (s *Store) Exchange(ctx context.Context, out OutboundMessage, receiptOnly bool) (OutboundMessage, error) {
	if out.State == "accepted" {
		return out, nil
	}
	peer, err := s.Peer(ctx, out.PeerHostID)
	if err != nil {
		return out, err
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
