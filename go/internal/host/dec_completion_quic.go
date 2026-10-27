package host

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"github.com/peerspan/peerspan/go/internal/relay"
	"github.com/peerspan/peerspan/go/internal/tlsid"
	"github.com/quic-go/quic-go"
)

const DecCompletionALPN = "peerspan-completion/1"

type decPeerHandshakeKey struct{}

type decPeerHandshake struct {
	source      string
	claimed     relay.HostID
	relayed     bool
	created     time.Time
	pending     func()
	buffer      func()
	provisional *decCompletionRoute
}

// This runs before QUIC creates its per-connection stream buffers. Direct TCP,
// direct QUIC and provisional relay handshakes use one admission counter.
func (s *Store) decPeerHandshakeContext(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if provisional, found, e := s.decProvisionalHandshake(ctx, info.RemoteAddr); found || e != nil {
		return provisional, e
	}
	source, claimed, relayed, helperKey, e := s.decPeerSource(info.RemoteAddr)
	if e != nil {
		return nil, e
	}
	keys := []string{"source:" + source}
	if helperKey != "" {
		keys = append(keys, "helper:"+helperKey)
	}
	release, ok := s.decHandshakeBudget().reserve(keys...)
	if !ok {
		return nil, errors.New("peer handshake capacity")
	}
	meta := &decPeerHandshake{source: source, claimed: claimed, relayed: relayed, created: time.Now(), pending: release, buffer: func() {}}
	s.peer.mu.Lock()
	mailbox := s.peer.mailbox
	s.peer.mu.Unlock()
	if mailbox != nil {
		meta.buffer, ok = mailbox.ReserveCompletionTransport()
		if !ok {
			release()
			return nil, errors.New("peer receive capacity")
		}
	}
	context.AfterFunc(ctx, func() { meta.pending(); meta.buffer() })
	return context.WithValue(ctx, decPeerHandshakeKey{}, meta), nil
}

// A synthetic host digest is a routing hint. Source quotas belong to the
// actual helper connection (and helper public key), never that claimed digest.
func (s *Store) decPeerSource(address net.Addr) (string, relay.HostID, bool, string, error) {
	var claimed relay.HostID
	udp, ok := address.(*net.UDPAddr)
	if !ok || !isSynthetic(udp) {
		source, e := decBootstrapSource(address)
		return source, claimed, false, "", e
	}
	s.peer.mu.Lock()
	packets := s.peer.packets
	s.peer.mu.Unlock()
	if packets == nil {
		return "", claimed, false, "", errors.New("peer socket closed")
	}
	var ip [16]byte
	copy(ip[:], udp.IP.To16())
	packets.mu.Lock()
	claimed, exists := packets.peers[ip]
	client := packets.routes[claimed]
	direct := packets.direct[claimed]
	packets.mu.Unlock()
	if !exists {
		return "", claimed, false, "", errors.New("unknown peer route")
	}
	if direct.IsValid() {
		source, e := decBootstrapSource(net.UDPAddrFromAddrPort(direct))
		return source, claimed, true, "", e
	}
	if resource, ok := client.(*decRelayClient); ok {
		resource.mu.Lock()
		source := resource.source
		resource.mu.Unlock()
		if source == "" {
			return "", claimed, true, "", errors.New("resource source unavailable")
		}
		return source, claimed, true, resource.setting.Key, nil
	}
	// This is the isolated historical coordinator-relay fixture path. Its
	// actual membership gates remain; it cannot carry an unknown DEC peer.
	source, e := decBootstrapSource(address)
	return source, claimed, true, "", e
}

// Repair's TLS/application boundary requires an independently admitted H.
// Manual pins and contacts are deliberately insufficient. Known revocations
// remain recognizable here so the isolated repair route can return its403.
func (s *Store) decRememberedRepairPeer(ctx context.Context, state tls.ConnectionState) bool {
	key, e := tlsid.PeerKey(state)
	if e != nil {
		return false
	}
	writer := base64.StdEncoding.EncodeToString(key)
	ids, e := s.networkIDs(ctx, s.db)
	if e != nil {
		return false
	}
	for _, network := range ids {
		tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			return false
		}
		view, e := s.loadDecRepairView(ctx, tx, network)
		if e == nil {
			rows, err := tx.QueryContext(ctx, `SELECT statement_id FROM dec_admissions WHERE network_id=? AND context_id=?`, network, view.Descriptor.ContextID)
			if err == nil {
				found := false
				for rows.Next() {
					var id string
					if rows.Scan(&id) != nil {
						break
					}
					statement := view.Catalog.Statements[id]
					found = found || statement != nil && statement.Kind == "host_lease" && statement.Lease.Subject.Host == writer
				}
				err = rows.Err()
				rows.Close()
				if found && err == nil {
					tx.Rollback()
					return true
				}
			}
		}
		tx.Rollback()
	}
	return false
}

func (s *Store) serveDecCompletionQUIC(parent context.Context, conn *quic.Conn, meta *decPeerHandshake) {
	defer conn.CloseWithError(0, "completion finished")
	defer meta.buffer()
	s.peer.mu.Lock()
	mailbox := s.peer.mailbox
	s.peer.mu.Unlock()
	if mailbox == nil {
		return
	}
	ctx, cancel := context.WithDeadline(parent, meta.created.Add(30*time.Second))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "completion deadline") })
	defer stop()
	mailbox.ServeCompletion(ctx, conn.ConnectionState().TLS, meta.source, func(waiting context.Context) (net.Conn, error) {
		stream, e := conn.AcceptStream(waiting)
		if e != nil {
			return nil, e
		}
		// Only the first stream can reach HTTP. Another stream closes this
		// bounded carrier without dispatching another request or growing credit.
		go func() {
			if extra, e := conn.AcceptStream(ctx); e == nil {
				extra.CancelRead(0)
				extra.CancelWrite(0)
				_ = conn.CloseWithError(1, "one completion stream required")
			}
		}()
		return newStreamConn(stream, conn, conn.ConnectionState().TLS), nil
	})
	// Stream.Close queues FIN; immediately closing QUIC could discard a queued
	// response. The client closes after consuming it. A stalled client retains
	// only this accounted transport window until the original overall deadline.
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
	}
}
