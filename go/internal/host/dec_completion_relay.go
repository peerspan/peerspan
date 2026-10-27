package host

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/relay"
	"github.com/quic-go/quic-go"
)

// These are bounded packet routes, never remembered host pins or network state.
// A claimed digest gets no path-discovery state and must match inner TLS.
type decCompletionRoute struct {
	packets *packetConn
	id      relay.HostID
	client  *decRelayClient
	meta    *decPeerHandshake
	claimed bool
	closed  bool
	timer   *time.Timer
	conn    *quic.Conn
}

type decCompletionDial struct {
	users     int
	client    *decRelayClient
	temporary bool
}

func decSyntheticIP(id relay.HostID) (ip [16]byte) {
	copy(ip[:], syntheticPrefix[:])
	copy(ip[4:], id[:12])
	return
}

// Explicitly pinned outbound completion owns a short-lived reply route. It
// grants no inbound normal/repair eligibility or unsolicited discovery access.
func (p *packetConn) beginCompletionDial(id relay.HostID, client *decRelayClient) (func(), error) {
	ip := decSyntheticIP(id)
	p.mu.Lock()
	if old, exists := p.peers[ip]; exists && old != id {
		p.mu.Unlock()
		return nil, errors.New("peer route collision")
	}
	dial := p.completionDials[id]
	if dial == nil {
		if len(p.completionDials) >= 128 || len(p.peers) >= 4096 || len(p.routes) >= 4096 {
			p.mu.Unlock()
			return nil, errors.New("completion route capacity")
		}
		dial = &decCompletionDial{client: client, temporary: p.routes[id] == nil}
		p.completionDials[id] = dial
	}
	if dial.client != client {
		p.mu.Unlock()
		return nil, errors.New("completion route busy")
	}
	dial.users++
	p.peers[ip], p.routes[id] = id, client
	p.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			dial.users--
			if dial.users != 0 {
				return
			}
			delete(p.completionDials, id)
			if dial.temporary && p.provisional[id] == nil && p.routes[id] == client {
				delete(p.routes, id)
				delete(p.peers, ip)
			}
		})
	}, nil
}

func (r *decCompletionRoute) retire() {
	p := r.packets
	p.mu.Lock()
	if r.closed {
		p.mu.Unlock()
		return
	}
	r.closed = true
	if r.timer != nil {
		r.timer.Stop()
	}
	if p.provisional[r.id] == r {
		delete(p.provisional, r.id)
		if p.completionDials[r.id] == nil && p.routes[r.id] == r.client {
			delete(p.routes, r.id)
			delete(p.peers, decSyntheticIP(r.id))
		}
	}
	conn := r.conn
	p.mu.Unlock()
	r.meta.pending()
	r.meta.buffer()
	if conn != nil {
		_ = conn.CloseWithError(0, "completion route retired")
	}
}

func (r *decCompletionRoute) complete(conn *quic.Conn) bool {
	r.packets.mu.Lock()
	defer r.packets.mu.Unlock()
	if r.closed || time.Since(r.meta.created) >= peerHandshakeTimeout {
		return false
	}
	r.conn = conn
	r.timer.Stop()
	r.timer = time.AfterFunc(time.Until(r.meta.created.Add(30*time.Second)), r.retire)
	return true
}

// Only QUIC bytes of a locally initiated pinned completion, or a bounded
// provisional initial route, enter this path. No claimed digest creates a quota
// principal. Repeated packets cannot extend the route's five/thirty-second bound.
func (r *decRelayClient) deliverCompletion(frame decRelayFrame) {
	if !isQUIC(frame.data) {
		return
	}
	p := r.packets
	r.mu.Lock()
	source := r.source
	r.mu.Unlock()
	if source == "" {
		return
	}
	r.store.peer.mu.Lock()
	mailbox := r.store.peer.mailbox
	r.store.peer.mu.Unlock()
	if mailbox == nil {
		return
	}
	ip := decSyntheticIP(frame.peer)
	p.mu.Lock()
	if old, exists := p.peers[ip]; exists && old != frame.peer {
		p.mu.Unlock()
		return
	}
	dial := p.completionDials[frame.peer]
	if dial != nil {
		if dial.client != r {
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		p.push(datagram{data: frame.data, addr: &net.UDPAddr{IP: net.IP(ip[:]), Port: 1}})
		return
	}
	route := p.provisional[frame.peer]
	if route == nil {
		if len(p.provisional) >= 128 || len(p.peers) >= 4096 || len(p.routes) >= 4096 {
			p.mu.Unlock()
			return
		}
		release, ok := r.store.decHandshakeBudget().reserve("source:"+source, "helper:"+r.setting.Key)
		if !ok {
			p.mu.Unlock()
			return
		}
		buffer, ok := mailbox.ReserveCompletionTransport()
		if !ok {
			release()
			p.mu.Unlock()
			return
		}
		meta := &decPeerHandshake{source: source, claimed: frame.peer, relayed: true, created: time.Now(), pending: release, buffer: buffer}
		route = &decCompletionRoute{packets: p, id: frame.peer, client: r, meta: meta}
		meta.provisional = route
		p.provisional[frame.peer], p.peers[ip], p.routes[frame.peer] = route, frame.peer, r
		route.timer = time.AfterFunc(peerHandshakeTimeout, route.retire)
	}
	if route.closed || route.client != r {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	p.push(datagram{data: frame.data, addr: &net.UDPAddr{IP: net.IP(ip[:]), Port: 1}})
}

func (s *Store) decProvisionalHandshake(ctx context.Context, address net.Addr) (context.Context, bool, error) {
	udp, ok := address.(*net.UDPAddr)
	if !ok || !isSynthetic(udp) {
		return nil, false, nil
	}
	s.peer.mu.Lock()
	p := s.peer.packets
	s.peer.mu.Unlock()
	if p == nil {
		return nil, false, net.ErrClosed
	}
	var ip [16]byte
	copy(ip[:], udp.IP.To16())
	p.mu.Lock()
	route := p.provisional[p.peers[ip]]
	if route == nil {
		p.mu.Unlock()
		return nil, false, nil
	}
	if route.closed || route.claimed {
		p.mu.Unlock()
		return nil, true, errors.New("completion route already claimed")
	}
	route.claimed = true
	meta := route.meta
	p.mu.Unlock()
	context.AfterFunc(ctx, route.retire)
	return context.WithValue(ctx, decPeerHandshakeKey{}, meta), true, nil
}
