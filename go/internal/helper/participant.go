package helper

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/tlsid"
	"golang.org/x/sys/unix"
)

// ParticipantMailbox serves only the opaque bootstrap carrier on an existing
// host TLS listener. Its resource database has no trust-state references and
// opening it never creates a helper identity, listener or authority provider.
type ParticipantMailbox struct {
	state       *ownedState
	store       *resourceStore
	handler     *mailboxHandler
	connections *connectionSet
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	failure     error
	workers     sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

// OpenParticipantMailbox opens only dec-bootstrap.db and its protected
// resource lock in an existing private host state directory. The caller owns
// the host's listener and TLS configuration; this service never receives keys.
func OpenParticipantMailbox(parent context.Context, databasePath string) (*ParticipantMailbox, error) {
	return OpenParticipantMailboxWithCompletion(parent, databasePath, nil)
}

// OpenParticipantMailboxWithCompletion additionally installs only the host's
// complete activation/outcome verifier. A nil callback retains resource-only
// behavior. The callback receives no authority from this transport service.
func OpenParticipantMailboxWithCompletion(parent context.Context, databasePath string, completion ParticipantCompletion) (*ParticipantMailbox, error) {
	if parent == nil {
		return nil, errState
	}
	path, err := filepath.Abs(databasePath)
	if err != nil || filepath.Base(path) != "dec-bootstrap.db" {
		return nil, errState
	}
	dir, err := privateDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	state := &ownedState{directory: dir, path: filepath.Dir(path)}
	ok := false
	defer func() {
		if !ok {
			state.close()
		}
	}()
	state.lock, err = protectedFile(int(dir.Fd()), "dec-bootstrap.lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	info, err := state.lock.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		return nil, errState
	}
	if unix.Flock(int(state.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errors.New("participant mailbox already owned")
	}
	store, err := openResourceDatabase(state, "dec-bootstrap.db")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	m := &ParticipantMailbox{state: state, store: store, ctx: ctx, cancel: cancel,
		connections: &connectionSet{clients: map[*ownedConn]bool{}, sources: map[string]int{}, pending: map[string]int{}}}
	m.handler = &mailboxHandler{store: store, limits: newLimits(), completion: completion}
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				tx, e := store.begin(ctx, now)
				if e == nil {
					e = tx.Commit()
				}
				if e != nil && ctx.Err() == nil {
					m.mu.Lock()
					m.failure = errors.New("participant mailbox storage unavailable")
					m.mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	ok = true
	return m, nil
}

// ServeConn requires a completed TLS1.3 client-key proof on the bootstrap ALPN.
// Identity and source buckets come from that connection, never caller headers.
// The host must also apply its pre-handshake connection/timeout budgets.
func (m *ParticipantMailbox) ServeConn(parent context.Context, conn *tls.Conn) {
	if conn == nil {
		return
	}
	transport := conn.NetConn()
	defer transport.Close()
	if parent == nil {
		return
	}
	cs := conn.ConnectionState()
	if !cs.HandshakeComplete || cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != protocols[0] {
		return
	}
	key, err := tlsid.PeerKey(cs)
	if err != nil {
		return
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if _, err = publicKey(encoded); err != nil {
		return
	}
	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil {
		m.mu.Unlock()
		return
	}
	m.workers.Add(1)
	m.mu.Unlock()
	defer m.workers.Done()
	owned := m.connections.accept(transport)
	if owned == nil {
		return
	}
	defer owned.Close()
	owned.handshaken()
	ctx, cancel := context.WithCancel(m.ctx)
	defer cancel()
	stopParent := context.AfterFunc(parent, cancel)
	defer stopParent()
	stopTransport := context.AfterFunc(ctx, func() { transport.Close() })
	defer stopTransport()
	serveMailbox(ctx, conn, transportPeer{key: encoded, source: owned.source}, m.handler)
}

// ServeCompletion accepts one stream only after the actual QUIC TLS proof and
// host-derived source bucket have passed the caller's transport gates. It uses
// the SAME request/rate/byte pools as TCP bootstrap, before accepting a stream,
// and exposes ONLY the original complete-publication routes. The service owns
// no keys and derives no identity from HTTP or a relay's claimed source ID.
func (m *ParticipantMailbox) ServeCompletion(parent context.Context, state tls.ConnectionState, source string, accept func(context.Context) (net.Conn, error)) {
	if parent == nil || accept == nil || source == "" || len(source) > 512 || !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "peerspan-completion/1" {
		return
	}
	key, err := tlsid.PeerKey(state)
	if err != nil {
		return
	}
	peer := transportPeer{key: base64.StdEncoding.EncodeToString(key), source: source}
	m.mu.Lock()
	if m.closed || m.ctx.Err() != nil || m.handler.completion == nil {
		m.mu.Unlock()
		return
	}
	m.workers.Add(1)
	m.mu.Unlock()
	defer m.workers.Done()
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()
	stopParent := context.AfterFunc(parent, cancel)
	defer stopParent()
	if !m.handler.limits.beginRequest(peer) {
		return
	}
	defer m.handler.limits.endRequest(peer)
	waiting, stop := context.WithTimeout(ctx, 5*time.Second)
	conn, err := accept(waiting)
	stop()
	if err != nil || conn == nil {
		return
	}
	defer conn.Close()
	stopTransport := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopTransport()
	var queued int64
	defer func() { m.handler.limits.release("response", queued) }()
	handler := &mailboxHandler{limits: m.handler.limits, completion: m.handler.completion, completionOnly: true, queuedResponse: func(amount int64) { queued += amount }}
	serveMailboxRequest(ctx, conn, peer, handler)
	_ = conn.Close() // queue FIN before waiting for the client to consume it
	select {
	case <-parent.Done():
	case <-ctx.Done():
	}
}

// ReserveCompletionTransport accounts for the bounded QUIC receive window and
// HTTP header lookahead BEFORE an unqualified connection advertises data credit.
// Body and queued-response reservations continue to use these same pools.
func (m *ParticipantMailbox) ReserveCompletionTransport() (func(), bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil || !m.handler.limits.reserve("receive", 64<<10) {
		return nil, false
	}
	if !m.handler.limits.reserve("response", 64<<10) {
		m.handler.limits.release("receive", 64<<10)
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() { m.handler.limits.release("receive", 64<<10); m.handler.limits.release("response", 64<<10) })
	}, true
}

// ReserveCompletionExchange bounds an outgoing complete request and its
// response in the SAME pools as participant server traffic. It carries no key,
// endpoint, operation or authority information.
func (m *ParticipantMailbox) ReserveCompletionExchange() (func(), bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil || !m.handler.limits.reserve("receive", maxCompletionBody) {
		return nil, false
	}
	if !m.handler.limits.reserve("response", maxCompletionBody) {
		m.handler.limits.release("receive", maxCompletionBody)
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			m.handler.limits.release("receive", maxCompletionBody)
			m.handler.limits.release("response", maxCompletionBody)
		})
	}, true
}

// Close cancels and drains this service's exact connections before closing its
// resource database. It has no effect on the host's trust database or listener.
func (m *ParticipantMailbox) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.cancel()
		m.mu.Unlock()
		m.connections.closeAll()
		m.workers.Wait()
		m.closeErr = m.store.close()
		if m.closeErr == nil {
			m.closeErr = m.failure
		}
		m.state.close()
	})
	return m.closeErr
}
