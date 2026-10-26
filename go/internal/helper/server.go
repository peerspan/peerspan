package helper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/tlsid"
)

var protocols = []string{"peerspan-bootstrap/1", "peerspan-relay/4"}

type ServeOptions struct{ State, Listen, TokensFile string }

func Info(path string, out io.Writer) error {
	key, err := PublicIdentity(path)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		PublicKey string   `json:"public_key"`
		Protocols []string `json:"protocols"`
	}{key, protocols})
}

type connectionSet struct {
	mu      sync.Mutex
	clients map[*ownedConn]bool
	sources map[string]int
	pending map[string]int
	total   int
}

type ownedConn struct {
	net.Conn
	owner  *connectionSet
	source string
	once   sync.Once
}

func (s *connectionSet) accept(conn net.Conn) *ownedConn {
	source, err := sourceBucket(conn.RemoteAddr())
	if err != nil {
		conn.Close()
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) >= 1024 || s.sources[source] >= 64 || s.total >= 128 || s.pending[source] >= 16 {
		conn.Close()
		return nil
	}
	c := &ownedConn{Conn: conn, owner: s, source: source}
	s.clients[c] = true
	s.sources[source]++
	s.pending[source]++
	s.total++
	return c
}

func (c *ownedConn) handshaken() {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	if c.owner.clients[c] {
		c.owner.clients[c] = false
		c.owner.pending[c.source]--
		if c.owner.pending[c.source] == 0 {
			delete(c.owner.pending, c.source)
		}
		c.owner.total--
	}
}

func (c *ownedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.owner.mu.Lock()
		defer c.owner.mu.Unlock()
		if c.owner.clients[c] {
			c.owner.total--
			c.owner.pending[c.source]--
			if c.owner.pending[c.source] == 0 {
				delete(c.owner.pending, c.source)
			}
		}
		delete(c.owner.clients, c)
		c.owner.sources[c.source]--
		if c.owner.sources[c.source] == 0 {
			delete(c.owner.sources, c.source)
		}
	})
	return err
}

func (s *connectionSet) closeAll() {
	s.mu.Lock()
	conns := make([]*ownedConn, 0, len(s.clients))
	for c := range s.clients {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// Serve owns a separate transport identity/resource database. Neither router
// has a reference to host state, authority evaluation, or participant outcomes.
func Serve(parent context.Context, options ServeOptions, out io.Writer) error {
	host, port, err := net.SplitHostPort(options.Listen)
	if err != nil || strings.ContainsAny(host, "\r\n\x00") {
		return errors.New("invalid listen address")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("invalid listen port")
	}
	accounts, err := loadAccounts(options.TokensFile)
	if err != nil {
		return errors.New("invalid resource configuration")
	}
	state, err := ownState(options.State)
	if err != nil {
		return err
	}
	defer state.close()
	store, err := openResources(state)
	if err != nil {
		return err
	}
	defer store.close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	listener, err := net.Listen("tcp", options.Listen)
	if err != nil {
		return errors.New("helper listen failed")
	}
	defer listener.Close()
	connections := &connectionSet{clients: map[*ownedConn]bool{}, sources: map[string]int{}, pending: map[string]int{}}
	var workers sync.WaitGroup
	defer func() { cancel(); listener.Close(); connections.closeAll(); workers.Wait() }()
	cache := &tlsid.Cache{Key: state.key, Name: "peerspan-helper"}
	config := tlsid.Config()
	config.NextProtos = protocols
	config.ClientAuth = tls.RequireAnyClientCert
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cache.Get() }
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.NegotiatedProtocol != protocols[0] && cs.NegotiatedProtocol != protocols[1] {
			return errors.New("unsupported helper protocol")
		}
		key, err := tlsid.PeerKey(cs)
		if err != nil {
			return err
		}
		_, err = publicKey(base64.StdEncoding.EncodeToString(key))
		return err
	}
	limits := newLimits()
	mailboxes := &mailboxHandler{store: store, limits: limits, accounts: accounts}
	relay := newRelayHub(limits, accounts)
	if err := json.NewEncoder(out).Encode(struct {
		PublicKey string   `json:"public_key"`
		Address   string   `json:"address"`
		Protocols []string `json:"protocols"`
	}{base64.StdEncoding.EncodeToString(state.key.Public().(ed25519.PublicKey)), listener.Addr().String(), protocols}); err != nil {
		return err
	}
	fatal := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				tx, err := store.begin(ctx, now)
				if err == nil {
					err = tx.Commit()
				}
				if err != nil && ctx.Err() == nil {
					fatal <- errors.New("helper storage unavailable")
					cancel()
					return
				}
			}
		}
	}()
	go func() { <-ctx.Done(); listener.Close(); connections.closeAll() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				select {
				case err := <-fatal:
					return err
				default:
					return nil
				}
			}
			return errors.New("helper accept failed")
		}
		owned := connections.accept(conn)
		if owned == nil {
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer owned.Close()
			conn := tls.Server(owned, config)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if conn.HandshakeContext(ctx) != nil {
				return
			}
			owned.handshaken()
			_ = conn.SetDeadline(time.Time{})
			cs := conn.ConnectionState()
			key, err := tlsid.PeerKey(cs)
			if err != nil {
				return
			}
			peer := transportPeer{key: base64.StdEncoding.EncodeToString(key), source: owned.source}
			if cs.NegotiatedProtocol == protocols[0] {
				serveMailbox(ctx, conn, peer, mailboxes)
			} else if cs.NegotiatedProtocol == protocols[1] {
				relay.serve(conn, peer)
			}
		}()
	}
}

type wireResponse struct {
	conn   net.Conn
	header http.Header
	wrote  bool
}

func (w *wireResponse) Header() http.Header { return w.header }
func (w *wireResponse) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	_ = w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	w.header.Set("Connection", "close")
	if w.header.Get("Content-Length") == "" {
		w.header.Set("Content-Length", "0")
	}
	_, _ = fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	_ = w.header.Write(w.conn)
	_, _ = io.WriteString(w.conn, "\r\n")
}
func (w *wireResponse) Write(body []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.conn.Write(body)
}

// HTTP responses close their connection; all resource counters persist across
// reconnects. Inspect exact security header values before net/http trims OWS.
// Body framing still uses the standard bounded HTTP/1 parser.
func serveMailbox(ctx context.Context, conn net.Conn, peer transportPeer, handler *mailboxHandler) {
	defer func() { _ = recover() }() // Abort only this unprivileged carrier connection.
	if !handler.limits.beginRequest(peer) {
		return // No request framing exists yet; close the carrier on saturation.
	}
	defer handler.limits.endRequest(peer)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, 16<<10)
	response := &wireResponse{conn: conn, header: http.Header{}}
	badHTTP := func() {
		kind, rate, burst := "mutation", 2.0, 8.0
		if prefix, _ := reader.Peek(4); bytes.Equal(prefix, []byte("GET ")) {
			kind, rate, burst = "get", 1, 4
		}
		code := wireError("invalid")
		if !handler.limits.allow(kind, resourceKeys(peer.key, peer.source, ""), rate, burst, 0) {
			code = wireError("rate_limited")
		}
		respondError(response, code)
	}
	var header []byte
	for n := 1; n <= 16<<10; n++ {
		part, err := reader.Peek(n)
		if err != nil {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				badHTTP()
			}
			return
		}
		if part[n-1] == '\n' && (n < 2 || part[n-2] != '\r') {
			badHTTP()
			return
		}
		if n >= 4 && bytes.Equal(part[n-4:], []byte("\r\n\r\n")) {
			header = part
			break
		}
	}
	if header == nil {
		badHTTP()
		return
	}
	headerFields, lengths := 0, 0
	var declaredLength int64
	for i, line := range bytes.Split(header, []byte("\r\n")) {
		if i == 0 || len(line) == 0 {
			continue
		}
		headerFields++
		if headerFields > 64 {
			badHTTP()
			return
		}
		if line[0] == ' ' || line[0] == '\t' {
			peer.invalidHeader = true
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name, value := string(line[:colon]), string(line[colon+1:])
		if strings.EqualFold(name, "Transfer-Encoding") {
			badHTTP()
			return
		}
		if strings.EqualFold(name, "Content-Length") {
			lengths++
			canonical := strings.TrimSpace(value)
			parsed, err := strconv.ParseInt(canonical, 10, 64)
			if lengths != 1 || err != nil || parsed < 0 || strconv.FormatInt(parsed, 10) != canonical {
				badHTTP()
				return
			}
			declaredLength = parsed
		}
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-Peerspan-Resource-Token") {
			value = strings.TrimPrefix(value, " ")
			if value != strings.TrimSpace(value) {
				peer.invalidHeader = true
			}
		}
	}
	request, err := http.ReadRequest(reader)
	if err != nil {
		badHTTP()
		return
	}
	if request.ProtoMajor != 1 || request.ProtoMinor != 1 ||
		request.Method == http.MethodPost && lengths != 1 ||
		(request.Method == http.MethodGet || request.Method == http.MethodDelete) && declaredLength != 0 ||
		int64(reader.Buffered()) > declaredLength {
		badHTTP()
		return
	}
	request.RemoteAddr = conn.RemoteAddr().String()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	request = request.WithContext(context.WithValue(ctx, transportContextKey{}, peer))
	handler.ServeHTTP(response, request)
}
