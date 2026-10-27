package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/tlsid"
)

type decCarrierError struct {
	code  string
	retry int
}

func (e *decCarrierError) Error() string         { return e.code }
func (e *decCarrierError) Unwrap() error         { return decFailure(e.code) }
func (e *decCarrierError) decErrorStage() string { return "transport" }
func (e *decCarrierError) retryAfter() int       { return e.retry }
func decTransportFailure() error {
	return &decControlError{decFailure("recovery_required"), "transport"}
}

func (s *Store) decCarrierCredential(ctx context.Context, c decCarrier) ([]byte, error) {
	if c.Kind != "helper" {
		return nil, nil
	}
	var record string
	var token []byte
	e := s.db.QueryRowContext(ctx, `SELECT record,credential FROM dec_helpers WHERE kind='rendezvous' AND address=? AND public_key=?`, c.Address, c.Key).Scan(&record, &token)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var config struct {
		Format  uint64 `json:"format"`
		Enabled bool   `json:"enabled"`
	}
	if e = dec.ReadPrivateRecord([]byte(record), "format enabled", &config); e != nil {
		return nil, e
	}
	if config.Format != 1 {
		return nil, decStorageError()
	}
	if !config.Enabled {
		return nil, nil
	}
	if len(token) > 1024 || strings.ContainsAny(string(token), "\r\n\x00") {
		return nil, decStorageError()
	}
	return token, nil
}

// Each exchange has one actual pinned TLS peer and one bounded HTTP message.
// The capability is never sent until that key and bootstrap ALPN are verified.
func (s *Store) decMailboxExchange(ctx context.Context, c decCarrier, method, path string, capability []byte, body []byte, max int) ([]byte, int, error) {
	return s.decBootstrapExchange(ctx, c, method, path, capability, body, max, false)
}
func (s *Store) decBootstrapExchange(ctx context.Context, c decCarrier, method, path string, capability []byte, body []byte, max int, completion bool) ([]byte, int, error) {
	return s.decPinnedTLSExchange(ctx, c, method, path, capability, body, max, completion, DecBootstrapALPN)
}
func (s *Store) decStateRepairExchange(ctx context.Context, c decCarrier, path string) ([]byte, int, error) {
	return s.decPinnedTLSExchange(ctx, c, "GET", path, nil, nil, decPublicationLimit, true, DecRepairALPN)
}
func (s *Store) decPinnedTLSExchange(ctx context.Context, c decCarrier, method, path string, capability []byte, body []byte, max int, completion bool, protocol string) ([]byte, int, error) {
	bodyLimit := 8 << 20
	if completion {
		bodyLimit = 20 << 20
	}
	if !dec.ValidEndpoint(c.Address) || !dec.ValidPublicKey(c.Key) || !completion && len(capability) != 32 || completion && c.Kind != "participant" || len(body) > bodyLimit {
		return nil, 0, decFailure("invalid")
	}
	token, e := s.decCarrierCredential(ctx, c)
	if e != nil {
		return nil, 0, e
	}
	cert, e := s.peerCertificate()
	if e != nil {
		return nil, 0, decTransportFailure()
	}
	config := tlsid.Config()
	config.NextProtos = []string{protocol}
	config.Certificates = []tls.Certificate{cert}
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.NegotiatedProtocol != protocol {
			return errors.New("wrong bootstrap protocol")
		}
		key, e := tlsid.PeerKey(cs)
		if e != nil {
			return e
		}
		if base64.StdEncoding.EncodeToString(key) != c.Key {
			return errors.New("wrong carrier key")
		}
		return nil
	}
	raw, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", c.Address)
	if e != nil {
		return nil, 0, decTransportFailure()
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	secure := tls.Client(raw, config)
	_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
	if secure.HandshakeContext(ctx) != nil {
		return nil, 0, decTransportFailure()
	}
	_ = secure.SetDeadline(time.Now().Add(30 * time.Second))
	request, e := http.NewRequestWithContext(ctx, method, "https://"+c.Address+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, decFailure("invalid")
	}
	request.Close = true
	if !completion {
		request.Header.Set("Authorization", "Bearer "+hex.EncodeToString(capability))
	}
	request.Header.Set("Content-Type", "application/json")
	if len(token) > 0 {
		request.Header.Set("X-Peerspan-Resource-Token", base64.StdEncoding.EncodeToString(token))
	}
	if e = request.Write(secure); e != nil {
		return nil, 0, decTransportFailure()
	}
	reader := bufio.NewReaderSize(secure, 16<<10)
	var header []byte
	for n := 1; n <= 16<<10; n++ {
		prefix, e := reader.Peek(n)
		if e != nil {
			return nil, 0, decTransportFailure()
		}
		if n >= 4 && bytes.Equal(prefix[n-4:], []byte("\r\n\r\n")) {
			header = append([]byte{}, prefix...)
			_, _ = reader.Discard(n)
			break
		}
	}
	if header == nil {
		return nil, 0, decTransportFailure()
	}
	lengths := 0
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if strings.EqualFold(string(line[:colon]), "Transfer-Encoding") {
			return nil, 0, decTransportFailure()
		}
		if strings.EqualFold(string(line[:colon]), "Content-Length") {
			lengths++
			text := strings.TrimSpace(string(line[colon+1:]))
			n, e := strconv.ParseUint(text, 10, 64)
			if e != nil || strconv.FormatUint(n, 10) != text {
				return nil, 0, decTransportFailure()
			}
		}
	}
	if lengths != 1 {
		return nil, 0, decTransportFailure()
	}
	response, e := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader)), request)
	if e != nil {
		return nil, 0, decTransportFailure()
	}
	defer response.Body.Close()
	if response.ContentLength < 0 || response.ContentLength > int64(max) {
		return nil, 0, decTransportFailure()
	}
	s.decTransport.mu.Lock()
	if s.decTransport.ReceiveBytes+response.ContentLength > 64<<20 {
		s.decTransport.mu.Unlock()
		return nil, 0, decFailure("quota_exceeded")
	}
	s.decTransport.ReceiveBytes += response.ContentLength
	s.decTransport.mu.Unlock()
	defer func() {
		s.decTransport.mu.Lock()
		s.decTransport.ReceiveBytes -= response.ContentLength
		s.decTransport.mu.Unlock()
	}()
	result, e := io.ReadAll(io.LimitReader(response.Body, int64(max)+1))
	if e != nil || int64(len(result)) != response.ContentLength || len(result) > max {
		return nil, 0, decTransportFailure()
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return result, response.StatusCode, nil
	}
	if completion {
		var failure struct {
			Code    string          `json:"code"`
			Error   string          `json:"error"`
			Details decErrorDetails `json:"details"`
		}
		if len(result) > 8192 || dec.ReadPrivateRecord(result, "code error details", &failure) != nil || failure.Error != failure.Code || failure.Details.Required == nil || failure.Details.Conflicts == nil || failure.Details.Next == nil {
			return nil, 0, decTransportFailure()
		}
		expected := map[string]int{"invalid": 400, "forbidden": 403, "authority_expired": 403, "device_revoked": 403, "not_yet_valid": 403, "not_found": 404, "proof_required": 409, "state_conflict": 409, "operation_conflict": 409, "quota_exceeded": 409, "clock_rollback": 409, "migration_pending": 409, "review_required": 409, "signer_unavailable": 409, "recovery_required": 409, "expired": 410, "rate_limited": 429}
		if expected[failure.Code] != response.StatusCode {
			return nil, 0, decTransportFailure()
		}
		for i, id := range failure.Details.Required {
			if !dec.ValidID(id, "") || i > 0 && failure.Details.Required[i-1] >= id {
				return nil, 0, decTransportFailure()
			}
		}
		if failure.Code == "rate_limited" {
			text := response.Header.Get("Retry-After")
			retry, e := strconv.Atoi(text)
			if e != nil || retry < 1 || strconv.Itoa(retry) != text {
				return nil, 0, decTransportFailure()
			}
			return nil, response.StatusCode, &decCarrierError{failure.Code, retry}
		}
		return nil, response.StatusCode, &dec.Failure{Code: failure.Code, RequiredIDs: failure.Details.Required}
	}
	var failure struct {
		Code     string   `json:"code"`
		Error    string   `json:"error"`
		Required []string `json:"required_ids"`
	}
	if len(result) > 4096 || dec.ReadPrivateRecord(result, "code error required_ids", &failure) != nil || failure.Required == nil || len(failure.Required) != 0 || len(failure.Error) > 1024 {
		return nil, 0, decTransportFailure()
	}
	expected := map[string]int{"invalid": 400, "forbidden": 403, "not_found": 404, "state_conflict": 409, "operation_conflict": 409, "quota_exceeded": 409, "expired": 410, "rate_limited": 429}
	if expected[failure.Code] != response.StatusCode {
		return nil, 0, decTransportFailure()
	}
	retry := 0
	if failure.Code == "rate_limited" {
		text := response.Header.Get("Retry-After")
		retry, e = strconv.Atoi(text)
		if e != nil || retry < 1 || strconv.Itoa(retry) != text {
			return nil, 0, decTransportFailure()
		}
	}
	return nil, response.StatusCode, &decCarrierError{failure.Code, retry}
}
func decFrameBody(frame []byte) []byte {
	body := append([]byte(`{"frame":`), frame...)
	return append(body, '}')
}
func decMailboxCreation(p decPending, frame *dec.Frame, capability []byte) ([]byte, error) {
	capHash := sha256.Sum256([]byte(hex.EncodeToString(capability)))
	base, e := json.Marshal(struct {
		Format  uint64 `json:"format"`
		Request string `json:"request_id"`
		Locator string `json:"locator"`
		Hash    string `json:"read_cap_hash"`
		Created string `json:"created_at"`
		Expires string `json:"expires_at"`
	}{1, p.ID, frame.Locator, hex.EncodeToString(capHash[:]), p.Terms.Created, p.Deadline})
	if e != nil {
		return nil, e
	}
	// Preserve the exact saved outer-frame bytes, including whitespace.
	body := append(base[:len(base)-1], []byte(`,"frame":`)...)
	body = append(body, frame.Raw...)
	return append(body, '}'), nil
}

func (s *Store) acknowledgeDecFrame(ctx context.Context, id string, frame *dec.Frame, carrier decCarrier) error {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return e
	}
	key := decFrameKey(frame.Role, frame.Writer, frame.ID)
	if old := p.Frames[key]; old == nil {
		return nil
	} else if !bytes.Equal(old.Raw, frame.Raw) {
		return decFailure("operation_conflict")
	}
	for i := range p.Record.Outbound {
		entry := &p.Record.Outbound[i]
		if decFrameKey(entry.Role, entry.Writer, entry.ID) != key {
			continue
		}
		ack := decFrameAck{carrier.Address, carrier.Key}
		found := false
		for _, old := range entry.Acknowledged {
			if old == ack {
				found = true
				break
			}
		}
		if !found {
			entry.Acknowledged = append(entry.Acknowledged, ack)
			sort.Slice(entry.Acknowledged, func(i, j int) bool { return decFrameAckLess(entry.Acknowledged[i], entry.Acknowledged[j]) })
		}
	}
	if p.Record.Terminal == "applied" && frame.Role == "outcome" && len(p.Secret) == 0 {
		if _, e = tx.ExecContext(ctx, `DELETE FROM dec_frames WHERE request_id=? AND role=? AND writer_key=? AND frame_id=?`, p.ID, frame.Role, frame.Writer, frame.ID); e != nil {
			return e
		}
		delete(p.Frames, key)
		outbound := []decOutboundFrame{}
		for _, entry := range p.Record.Outbound {
			if decFrameKey(entry.Role, entry.Writer, entry.ID) != key {
				outbound = append(outbound, entry)
			}
		}
		p.Record.Outbound = outbound
		if len(p.Frames) == 0 {
			p.TerminalCap = nil
		}
	}
	if e = putDecPending(ctx, tx, p); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) publishDecFrames(ctx context.Context, p decPending) error {
	if len(p.Secret) == 0 && len(p.TerminalCap) == 0 {
		return nil
	}
	capability := p.TerminalCap
	var e error
	if len(p.Secret) > 0 {
		capability, e = dec.FrameReadCapability(p.Secret)
		if e != nil {
			return e
		}
	}
	var last error
	for _, carrier := range p.Record.Carriers {
		for _, entry := range p.Record.Outbound {
			if entry.Writer != s.identity.PublicKey {
				continue
			}
			ack := decFrameAck{carrier.Address, carrier.Key}
			known := false
			for _, old := range entry.Acknowledged {
				if old == ack {
					known = true
					break
				}
			}
			if known {
				continue
			}
			frame := p.Frames[decFrameKey(entry.Role, entry.Writer, entry.ID)]
			if frame == nil {
				return decStorageError()
			}
			if entry.Role != "request" && entry.Role != "outcome" {
				if e = s.checkDecStagePublication(ctx, p.ID, frame); e != nil {
					return e
				}
			}
			path, body := "/bootstrap/v1/mailboxes/"+frame.Locator+"/frames", decFrameBody(frame.Raw)
			if frame.Role == "request" {
				path = "/bootstrap/v1/mailboxes"
				body, e = decMailboxCreation(p, frame, capability)
				if e != nil {
					return e
				}
			}
			result, status, e := s.decMailboxExchange(ctx, carrier, "POST", path, capability, body, 4096)
			if e != nil {
				last = e
				break
			}
			if frame.Role == "request" {
				var r struct {
					Request string `json:"request_id"`
					Locator string `json:"locator"`
				}
				if (status != 200 && status != 201) || dec.ReadPrivateRecord(result, "request_id locator", &r) != nil || r.Request != p.ID || r.Locator != frame.Locator {
					return decTransportFailure()
				}
			} else {
				var r struct {
					Frame string `json:"frame_id"`
				}
				if status != 200 || dec.ReadPrivateRecord(result, "frame_id", &r) != nil || r.Frame != frame.ID {
					return decTransportFailure()
				}
			}
			if e = s.acknowledgeDecFrame(ctx, p.ID, frame, carrier); e != nil {
				return e
			}
			// The first actual storage acknowledgment retires the terminal-only
			// capability and ciphertext; do not keep publishing a stale copy.
			if p.Record.Terminal == "applied" {
				return nil
			}
		}
	}
	return last
}

func (s *Store) readDecPendingSnapshot(ctx context.Context, id string) (decPending, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return decPending{}, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return p, e
	}
	return p, tx.Commit()
}

// Poll success only persists exact signed, decryptable frames. Interpretation,
// offer selection, authority admission and requester consent are separate steps.
func (s *Store) receiveDecMailbox(ctx context.Context, id string, carrier decCarrier) error {
	p, e := s.readDecPendingSnapshot(ctx, id)
	if e != nil {
		return e
	}
	if len(p.Secret) != 16 {
		return nil
	}
	capability, e := dec.FrameReadCapability(p.Secret)
	if e != nil {
		return e
	}
	locator, e := dec.FrameLocator(p.Secret)
	if e != nil {
		return e
	}
	now, e := decNow()
	if e != nil {
		return e
	}
	fingerprint := sha256.Sum256(append(append([]byte(p.ID+"/"+locator+"/"+carrier.Address+"/"+carrier.Key+"/"), p.Request.Raw...), []byte(p.Record.Descriptor)...))
	pollKey := hex.EncodeToString(fingerprint[:])
	s.decTransport.mu.Lock()
	last := s.decTransport.Polls[pollKey]
	if !last.Received.IsZero() && last.Decision <= linkTime(now) {
		elapsed := time.Since(last.Received)
		if elapsed >= 0 && elapsed < 2*time.Second {
			s.decTransport.mu.Unlock()
			return nil
		}
	}
	transportNow := time.Now()
	if s.decTransport.ReadUpdated.IsZero() {
		s.decTransport.ReadTokens = 4
	} else {
		s.decTransport.ReadTokens = math.Min(4, s.decTransport.ReadTokens+transportNow.Sub(s.decTransport.ReadUpdated).Seconds())
	}
	s.decTransport.ReadUpdated = transportNow
	if s.decTransport.ReadTokens < 1 {
		retry := int(math.Ceil(1 - s.decTransport.ReadTokens))
		s.decTransport.mu.Unlock()
		return &decCarrierError{"rate_limited", retry}
	}
	s.decTransport.ReadTokens--
	s.decTransport.mu.Unlock()
	result, status, e := s.decMailboxExchange(ctx, carrier, "GET", "/bootstrap/v1/mailboxes/"+locator, capability, nil, 48<<20)
	if e != nil {
		return e
	}
	var response struct {
		Format  uint64            `json:"format"`
		Request string            `json:"request_id"`
		Created string            `json:"created_at"`
		Expires string            `json:"expires_at"`
		Frames  []json.RawMessage `json:"frames"`
	}
	if status != 200 || dec.ReadPrivateRecord(result, "format request_id created_at expires_at frames", &response) != nil || response.Format != 1 || response.Request != id || response.Created != p.Terms.Created || response.Expires != p.Deadline || response.Frames == nil || len(response.Frames) > 64 {
		return decTransportFailure()
	}
	previous := ""
	for _, raw := range response.Frames {
		f, e := dec.ReadFrame(raw)
		if e != nil {
			return e
		}
		key := decFrameKey(f.Role, f.Writer, f.ID)
		if previous != "" && previous >= key || f.Request != id || f.Locator != locator || f.Created != p.Terms.Created || f.Expires != p.Deadline {
			return decFailure("invalid")
		}
		previous = key
	}
	inserted, e := func() (bool, error) {
		s.linkMu.Lock()
		defer s.linkMu.Unlock()
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return false, e
		}
		defer tx.Rollback()
		current, e := readDecPending(ctx, tx, id)
		if e != nil {
			return false, e
		}
		if !bytes.Equal(current.Secret, p.Secret) || !bytes.Equal(current.Request.Raw, p.Request.Raw) {
			return false, decFailure("operation_conflict")
		}
		ordered := append([]json.RawMessage{}, response.Frames...)
		// Owner descriptors are parsing contexts only. Cache their verified exact
		// envelopes before components from that context, independent of wire order.
		sort.SliceStable(ordered, func(a, b int) bool {
			x, _ := dec.ReadFrame(ordered[a])
			y, _ := dec.ReadFrame(ordered[b])
			return x.Role == "owner" && y.Role != "owner"
		})
		changed := false
		for _, raw := range ordered {
			added, err := insertDecFrame(ctx, tx, &current, raw)
			if err != nil {
				return false, err
			}
			changed = changed || added
		}
		return changed, tx.Commit()
	}()
	if e != nil {
		return e
	}
	if inserted {
		if e = decBarrier(ctx, "dec.frame.after_commit", id); e != nil {
			return e
		}
	}
	// Frame bytes are durable before any dependent stage interpretation.
	if e = s.observeDecReceived(ctx, id, linkTime(now)); e != nil {
		return e
	}
	s.decTransport.mu.Lock()
	if len(s.decTransport.Polls) >= 8192 {
		s.decTransport.Polls = map[string]decSuccessfulPoll{}
	}
	if s.decTransport.Polls == nil {
		s.decTransport.Polls = map[string]decSuccessfulPoll{}
	}
	s.decTransport.Polls[pollKey] = decSuccessfulPoll{Decision: linkTime(now), Received: time.Now()}
	s.decTransport.mu.Unlock()
	return nil
}

func (s *Store) ResumeDecentralizedLink(ctx context.Context, id string, display bool) (json.RawMessage, error) {
	if !dec.ValidID(id, "link_") {
		return nil, decFailure("invalid")
	}
	p, e := s.readDecPendingSnapshot(ctx, id)
	if e != nil {
		return nil, e
	}
	// Explicit completed resume repairs delivery of the exact public operation.
	// Pure GET/exact application retries remain local immutable reads elsewhere.
	if p.Record.Terminal == "applied" {
		if _, e = s.retainedDecOutcome(ctx, p.Descriptor, id, "-"); e != nil {
			return nil, e
		}
		raw, e := decRequestResponse(p, p.Terms.Created, false)
		if e != nil {
			return nil, e
		}
		if e = s.publishDecCompletion(ctx, p); e != nil {
			return decRequestPublicationAttention(raw, e)
		}
		return raw, nil
	}
	if p.Record.Terminal == "migration_adopted" {
		return decRequestResponse(p, p.Terms.Created, false)
	}
	now, e := decNow()
	if e != nil {
		return nil, e
	}
	at := linkTime(now)
	if at < p.Terms.Created {
		return nil, decFailure("clock_rollback")
	}
	if decPendingResolved(p.Record.Terminal) || p.Record.Terminal == "migration_prepared" {
		return decRequestResponse(p, at, false)
	}
	var attention error
	if at < p.Deadline {
		attention = s.publishDecFrames(ctx, p)
		for _, carrier := range p.Record.Carriers {
			if e = s.receiveDecMailbox(ctx, id, carrier); e != nil && attention == nil {
				attention = e
			}
		}
		p, e = s.readDecPendingSnapshot(ctx, id)
		if e != nil {
			return nil, e
		}
		if p.Record.OwnerIntent != "-" {
			i, e := readDecIntent(ctx, s.db, p.Record.OwnerIntent)
			if e != nil {
				return nil, e
			}
			if i.Record.Approved {
				if _, e = s.advanceDecOwnerIntent(ctx, id); e != nil && attention == nil {
					attention = e
				}
			}
		}
		if p.Record.AdministratorIntent != "-" {
			i, e := readDecIntent(ctx, s.db, p.Record.AdministratorIntent)
			if e != nil {
				return nil, e
			}
			if i.Record.Approved {
				if _, e = s.advanceDecAdministrator(ctx, id, nil); e != nil && attention == nil {
					attention = e
				}
			}
		}
		p, e = s.readDecPendingSnapshot(ctx, id)
		if e != nil {
			return nil, e
		}
		// Advancing the already approved owner terms supplies dependent slots,
		// never either requester consent or a different administrator decision.
		if p.Record.OwnerIntent != "-" && p.Record.Selection != "-" && p.Record.Finalization == "-" && (p.Record.Administrator != "-" || p.Record.Mode == "renew") {
			if _, e = s.PrepareDecentralizedFinalization(ctx, id, decCachedCommitInput(p)); e != nil && attention == nil {
				attention = e
			}
			p, e = s.readDecPendingSnapshot(ctx, id)
			if e != nil {
				return nil, e
			}
		}
	}
	if p.Record.Selected && at < p.Deadline {
		if e = s.advanceDecRequester(ctx, id); e != nil {
			attention = e
		}
		p, e = s.readDecPendingSnapshot(ctx, id)
		if e != nil {
			return nil, e
		}
	}
	if p.Record.Migration == "-" && p.Record.Commit == "-" && p.Record.Finalization != "-" {
		if recovered, recoveryErr := s.recoverDecCompletion(ctx, p); recoveryErr != nil {
			attention = recoveryErr
		} else if recovered {
			p, e = s.readDecPendingSnapshot(ctx, id)
			if e != nil {
				return nil, e
			}
			return decRequestResponse(p, at, false)
		}
	}
	if p.Record.Commit != "-" {
		// Expiry retires only the opaque transport. A durable final commit remains
		// exact and can still apply if its complete authority is actually current.
		if publication := s.attemptDecCommitFrames(ctx, p); publication != nil && attention == nil {
			attention = publication
		}
		if e = s.applyStoredDecLink(ctx, id); e != nil {
			attention = e
		} else {
			p, e = s.readDecPendingSnapshot(ctx, id)
			if e != nil {
				return nil, e
			}
			if p.Record.Migration == "-" {
				if e = s.publishDecCompletion(ctx, p); e != nil && attention == nil {
					attention = e
				}
			}
			if e = s.publishDecFrames(ctx, p); e != nil && attention == nil {
				attention = e
			}
		}
	}
	if at >= p.Deadline {
		s.linkMu.Lock()
		tx, beginErr := s.db.BeginTx(ctx, nil)
		if beginErr == nil {
			p, beginErr = readDecPending(ctx, tx, id)
			if beginErr == nil {
				beginErr = retireDecPending(ctx, tx, &p, at)
			}
			if beginErr == nil {
				beginErr = tx.Commit()
			}
			_ = tx.Rollback()
		}
		s.linkMu.Unlock()
		if beginErr != nil {
			return nil, beginErr
		}
	}
	raw, e := decRequestResponse(p, at, display)
	if e != nil {
		return nil, e
	}
	if attention != nil {
		return decRequestPublicationAttention(raw, attention)
	}
	return raw, nil
}

func (s *Store) observeDecReceived(ctx context.Context, id, now string) error {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	current, e := readDecPending(ctx, tx, id)
	if e != nil {
		return e
	}
	if e = s.observeDecContacts(ctx, tx, &current, now); e != nil {
		return e
	}
	if e = observeDecOwner(ctx, tx, &current); e != nil {
		return e
	}
	if e = s.observeDecCeremony(ctx, tx, &current); e != nil {
		return e
	}
	return tx.Commit()
}
