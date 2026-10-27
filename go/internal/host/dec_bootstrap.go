package host

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/helper"
	"github.com/peerspan/peerspan/go/internal/tlsid"
)

const DecBootstrapALPN = "peerspan-bootstrap/1"

type decHelperSetting struct {
	Address   string `json:"address"`
	Key       string `json:"public_key"`
	TokenFile string `json:"token_file"`
}
type decTransportConfig struct {
	Format     uint64             `json:"format"`
	Bootstrap  []string           `json:"advertise_bootstrap"`
	QUIC       []string           `json:"advertise_quic"`
	Rendezvous []decHelperSetting `json:"rendezvous"`
	Relays     []decHelperSetting `json:"relays"`
	Publish    bool               `json:"publish_contacts"`
}

// Resource polling uses elapsed monotonic transport time. The independent
// decision stamp only invalidates reuse when the authority clock rewinds.
type decSuccessfulPoll struct {
	Decision string
	Received time.Time
}
type decTransportState struct {
	mu              sync.RWMutex
	Bootstrap, QUIC []string
	Configured      bool
	Publish         bool
	Polls           map[string]decSuccessfulPoll
	ReadTokens      float64
	ReadUpdated     time.Time
	ReceiveBytes    int64
	RepairRates     map[string]decRepairRate
	RepairActive    int
	RepairKeys      map[string]int
	RepairSources   map[string]int
	// Only this process's explicit private config selects resource helpers.
	Relays           []decHelperSetting
	RelayCredentials map[string][]byte
	Handshakes       *decHandshakeBudget
}

func decOrderedEndpoints(addresses []string, max int) bool {
	if addresses == nil || len(addresses) > max {
		return false
	}
	for i, a := range addresses {
		if !dec.ValidEndpoint(a) || i > 0 && addresses[i-1] >= a {
			return false
		}
	}
	return true
}
func readDecTransportConfig(path string) (*decTransportConfig, map[string][]byte, error) {
	if path == "" {
		return nil, nil, nil
	}
	raw, e := decControlFile(path, 1<<20, true)
	if e != nil {
		return nil, nil, errors.New("invalid private transport configuration")
	}
	var c decTransportConfig
	if e = dec.ReadPrivateRecord(raw, "format advertise_bootstrap advertise_quic rendezvous relays publish_contacts", &c); e != nil {
		return nil, nil, e
	}
	if c.Format != 1 || !decOrderedEndpoints(c.Bootstrap, 8) || !decOrderedEndpoints(c.QUIC, 8) || c.Rendezvous == nil || c.Relays == nil || len(c.Rendezvous) > 4 || len(c.Relays) > 4 || len(c.Bootstrap)+len(c.QUIC)+len(c.Relays) > 16 {
		return nil, nil, decFailure("invalid")
	}
	tokens := map[string][]byte{}
	for _, entry := range []struct {
		kind string
		list []decHelperSetting
	}{{"rendezvous", c.Rendezvous}, {"relay", c.Relays}} {
		for i, h := range entry.list {
			if !dec.ValidEndpoint(h.Address) || !dec.ValidPublicKey(h.Key) || h.TokenFile == "" || i > 0 && (entry.list[i-1].Address > h.Address || entry.list[i-1].Address == h.Address && entry.list[i-1].Key >= h.Key) {
				return nil, nil, decFailure("invalid")
			}
			if h.TokenFile == "-" {
				continue
			}
			token, e := decControlFile(h.TokenFile, 1024, true)
			if e != nil || len(token) == 0 || !utf8.Valid(token) || strings.ContainsAny(string(token), "\r\n\x00") {
				return nil, nil, errors.New("invalid private helper credential")
			}
			tokens[entry.kind+"/"+h.Address+"/"+h.Key] = token
		}
	}
	return &c, tokens, nil
}
func (s *Store) configureDecTransport(ctx context.Context, c *decTransportConfig, tokens map[string][]byte, bootstrap, peer net.Addr) error {
	boot, quic := decLocalEndpoints(bootstrap), decLocalEndpoints(peer)
	if c != nil {
		boot, quic = c.Bootstrap, c.QUIC
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, `UPDATE dec_helpers SET record=?`, `{"format":1,"enabled":false}`); e != nil {
			return e
		}
		for _, entry := range []struct {
			kind string
			list []decHelperSetting
		}{{"rendezvous", c.Rendezvous}, {"relay", c.Relays}} {
			for _, h := range entry.list {
				if _, e = tx.ExecContext(ctx, `INSERT INTO dec_helpers(kind,address,public_key,record,credential) VALUES(?,?,?,?,?) ON CONFLICT(kind,address,public_key) DO UPDATE SET record=excluded.record,credential=excluded.credential`, entry.kind, h.Address, h.Key, `{"format":1,"enabled":true}`, tokens[entry.kind+"/"+h.Address+"/"+h.Key]); e != nil {
					return e
				}
			}
		}
		if e = tx.Commit(); e != nil {
			return e
		}
	}
	s.decTransport.mu.Lock()
	defer s.decTransport.mu.Unlock()
	s.decTransport.Bootstrap = append([]string{}, boot...)
	s.decTransport.QUIC = append([]string{}, quic...)
	s.decTransport.Configured = true
	s.decTransport.Publish = c != nil && c.Publish
	s.decTransport.Relays = nil
	s.decTransport.RelayCredentials = map[string][]byte{}
	if c != nil {
		s.decTransport.Relays = append([]decHelperSetting{}, c.Relays...)
		for key, token := range tokens {
			s.decTransport.RelayCredentials[key] = append([]byte(nil), token...)
		}
	}
	return nil
}

// A wildcard bind is local configuration, never a signed hint. Enumerate only
// actual interface IPs and the actual bound port, with no address-as-authority.
func decLocalEndpoints(address net.Addr) []string {
	out := []string{}
	if address == nil {
		return out
	}
	host, port, e := net.SplitHostPort(address.String())
	if e != nil {
		return out
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return out
	}
	if !ip.IsUnspecified() {
		value := net.JoinHostPort(ip.Unmap().String(), port)
		if dec.ValidEndpoint(value) {
			return []string{value}
		}
		return out
	}
	addresses, e := net.InterfaceAddrs()
	if e != nil {
		return out
	}
	loop := []string{}
	for _, value := range addresses {
		prefix, e := netip.ParsePrefix(value.String())
		if e != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			continue
		}
		endpoint := net.JoinHostPort(ip.String(), port)
		if !dec.ValidEndpoint(endpoint) {
			continue
		}
		if ip.IsLoopback() {
			loop = append(loop, endpoint)
		} else {
			out = append(out, endpoint)
		}
	}
	if len(out) == 0 {
		out = loop
	}
	sort.Strings(out)
	dedup := out[:0]
	for _, a := range out {
		if len(dedup) == 0 || dedup[len(dedup)-1] != a {
			dedup = append(dedup, a)
		}
	}
	if len(dedup) > 8 {
		dedup = dedup[:8]
	}
	return dedup
}

type DecBootstrapListener struct {
	listener        net.Listener
	mailbox         *helper.ParticipantMailbox
	config          *tls.Config
	mu              sync.Mutex
	closed          bool
	connections     map[net.Conn]string
	handshakes      map[string]int
	activeKeys      map[string]int
	activeSources   map[string]int
	active          int
	pending         int
	wg              sync.WaitGroup
	once            sync.Once
	closeError      error
	repair          func(context.Context, *tls.Conn)
	handshakeBudget *decHandshakeBudget
}

func (l *DecBootstrapListener) Addr() net.Addr { return l.listener.Addr() }
func decBootstrapSource(address net.Addr) (string, error) {
	host, _, e := net.SplitHostPort(address.String())
	if e != nil {
		return "", e
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return "", e
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String(), nil
	}
	return netip.PrefixFrom(ip, 64).Masked().String(), nil
}
func (s *Store) ListenDecentralizedBootstrap(ctx context.Context, requested string, peer net.Addr, configPath string) (*DecBootstrapListener, error) {
	c, tokens, e := readDecTransportConfig(configPath)
	if e != nil {
		return nil, e
	}
	if requested == "" {
		host := "127.0.0.1"
		if peer != nil {
			host, _, e = net.SplitHostPort(peer.String())
			if e != nil {
				return nil, e
			}
		}
		requested = net.JoinHostPort(host, "0")
	}
	listener, e := net.Listen("tcp", requested)
	if e != nil {
		return nil, e
	}
	mailbox, e := helper.OpenParticipantMailboxWithCompletion(ctx, filepath.Join(s.dir, "dec-bootstrap.db"), s.completeDecParticipant)
	if e != nil {
		listener.Close()
		return nil, e
	}
	cache := &tlsid.Cache{Key: s.privateKey, Name: s.identity.ID}
	if _, e = cache.Get(); e != nil {
		mailbox.Close()
		listener.Close()
		return nil, e
	}
	config := tlsid.Config()
	config.NextProtos = []string{DecBootstrapALPN, DecRepairALPN}
	config.ClientAuth = tls.RequireAnyClientCert
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cache.Get() }
	config.VerifyConnection = func(c tls.ConnectionState) error {
		if c.NegotiatedProtocol != DecBootstrapALPN && c.NegotiatedProtocol != DecRepairALPN {
			return errors.New("bootstrap ALPN required")
		}
		_, e := tlsid.PeerKey(c)
		return e
	}
	if e = s.configureDecTransport(ctx, c, tokens, listener.Addr(), peer); e != nil {
		mailbox.Close()
		listener.Close()
		return nil, e
	}
	s.peer.mu.Lock()
	s.peer.mailbox = mailbox
	s.peer.mu.Unlock()
	return &DecBootstrapListener{listener: listener, mailbox: mailbox, config: config, repair: s.serveDecRepair, handshakeBudget: s.decHandshakeBudget(), connections: map[net.Conn]string{}, handshakes: map[string]int{}, activeKeys: map[string]int{}, activeSources: map[string]int{}}, nil
}
func (l *DecBootstrapListener) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	for {
		conn, e := l.listener.Accept()
		if e != nil {
			if ctx.Err() != nil || errors.Is(e, net.ErrClosed) {
				return nil
			}
			return e
		}
		source, e := decBootstrapSource(conn.RemoteAddr())
		if e != nil {
			conn.Close()
			continue
		}
		releaseHandshake, allowed := l.handshakeBudget.reserve("source:" + source)
		if !allowed {
			conn.Close()
			continue
		}
		l.mu.Lock()
		if l.closed || l.pending >= 128 || l.handshakes[source] >= 16 || len(l.connections) >= 1024 {
			l.mu.Unlock()
			releaseHandshake()
			conn.Close()
			continue
		}
		l.pending++
		l.handshakes[source]++
		l.connections[conn] = source
		l.wg.Add(1)
		l.mu.Unlock()
		go func() {
			defer releaseHandshake()
			defer l.wg.Done()
			defer conn.Close()
			pending := true
			defer func() {
				l.mu.Lock()
				delete(l.connections, conn)
				if pending {
					l.pending--
					l.handshakes[source]--
					if l.handshakes[source] == 0 {
						delete(l.handshakes, source)
					}
				}
				l.mu.Unlock()
			}()
			secure := tls.Server(conn, l.config)
			_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
			if secure.HandshakeContext(ctx) != nil {
				return
			}
			releaseHandshake()
			l.mu.Lock()
			l.pending--
			l.handshakes[source]--
			if l.handshakes[source] == 0 {
				delete(l.handshakes, source)
			}
			pending = false
			l.mu.Unlock()
			public, e := tlsid.PeerKey(secure.ConnectionState())
			if e != nil {
				return
			}
			key := base64.StdEncoding.EncodeToString(public)
			l.mu.Lock()
			if l.active >= 128 || l.activeSources[source] >= 16 || l.activeKeys[key] >= 4 {
				l.mu.Unlock()
				return
			}
			l.active++
			l.activeSources[source]++
			l.activeKeys[key]++
			l.mu.Unlock()
			defer func() {
				l.mu.Lock()
				l.active--
				l.activeSources[source]--
				if l.activeSources[source] == 0 {
					delete(l.activeSources, source)
				}
				l.activeKeys[key]--
				if l.activeKeys[key] == 0 {
					delete(l.activeKeys, key)
				}
				l.mu.Unlock()
			}()
			_ = secure.SetDeadline(time.Time{})
			if secure.ConnectionState().NegotiatedProtocol == DecRepairALPN {
				l.repair(ctx, secure)
				return
			}
			l.mailbox.ServeConn(ctx, secure)
		}()
	}
}
func (l *DecBootstrapListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		owned := make([]net.Conn, 0, len(l.connections))
		for c := range l.connections {
			owned = append(owned, c)
		}
		l.mu.Unlock()
		_ = l.listener.Close()
		for _, c := range owned {
			_ = c.Close()
		}
		l.wg.Wait()
		l.closeError = l.mailbox.Close()
	})
	return l.closeError
}

func (s *Store) decOwnContact(ctx context.Context, tx *sql.Tx, network, contextID, now, expires string) ([]json.RawMessage, error) {
	s.decTransport.mu.RLock()
	addresses := dec.ContactPayload{QUIC: append([]string{}, s.decTransport.QUIC...), Bootstrap: append([]string{}, s.decTransport.Bootstrap...), Relays: []dec.ContactRelay{}}
	for _, helper := range s.decTransport.Relays {
		addresses.Relays = append(addresses.Relays, dec.ContactRelay{Address: helper.Address, PublicKey: helper.Key})
	}
	s.decTransport.mu.RUnlock()
	if len(addresses.QUIC)+len(addresses.Bootstrap)+len(addresses.Relays) == 0 {
		return []json.RawMessage{}, nil
	}
	sequence := uint64(1)
	var version any
	var record string
	e := tx.QueryRowContext(ctx, `SELECT sequence,record FROM dec_contacts WHERE network_id=? AND context_id=? AND host_key=?`, network, contextID, s.identity.PublicKey).Scan(&version, &record)
	if e == nil {
		previous, e := decVersion(version, true)
		if e != nil {
			return nil, e
		}
		if previous == ^uint64(0) {
			return nil, decFailure("version_exhausted")
		}
		sequence = previous + 1
		var retained struct {
			Format     uint64   `json:"format"`
			Hashes     []string `json:"message_hashes"`
			Conflicted bool     `json:"conflicted"`
			Contacts   []string `json:"contacts_base64"`
		}
		if e = dec.ReadPrivateRecord([]byte(record), "format message_hashes conflicted contacts_base64", &retained); e != nil {
			return nil, e
		}
		if retained.Format != 1 || retained.Contacts == nil || retained.Hashes == nil {
			return nil, decStorageError()
		}
		for _, body := range retained.Contacts {
			raw, e := decBytes(body, dec.MaxContact)
			if e != nil {
				return nil, e
			}
			contact, e := dec.ReadContact(raw)
			if e != nil {
				return nil, e
			}
			if contact.Sequence != previous || contact.Host != s.identity.PublicKey || contact.Context != contextID {
				return nil, decStorageError()
			}
			if now < contact.Issued {
				return nil, decFailure("clock_rollback")
			}
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return nil, e
	}
	raw, e := dec.SignContact(contextID, sequence, now, expires, addresses, s.privateKey)
	if e != nil {
		return nil, e
	}
	contact, e := dec.ReadContact(raw)
	if e != nil {
		return nil, e
	}
	recordRaw, _ := json.Marshal(struct {
		Format     uint64   `json:"format"`
		Hashes     []string `json:"message_hashes"`
		Conflicted bool     `json:"conflicted"`
		Contacts   []string `json:"contacts_base64"`
	}{1, []string{func() string { hash := sha256.Sum256(contact.Message); return hex.EncodeToString(hash[:]) }()}, false, []string{base64.StdEncoding.EncodeToString(raw)}})
	_, e = tx.ExecContext(ctx, `INSERT INTO dec_contacts(network_id,context_id,host_key,sequence,record) VALUES(?,?,?,?,?) ON CONFLICT(network_id,context_id,host_key) DO UPDATE SET sequence=excluded.sequence,record=excluded.record`, network, contextID, s.identity.PublicKey, linkVersionValue(sequence), string(recordRaw))
	if e != nil {
		return nil, e
	}
	return []json.RawMessage{raw}, nil
}
