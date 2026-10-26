package helper

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
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
