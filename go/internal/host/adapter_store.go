package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

const adapterSchema = `
CREATE TABLE adapter_credentials (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id), token_hash TEXT NOT NULL UNIQUE, record TEXT NOT NULL);
CREATE TABLE deliveries (id TEXT PRIMARY KEY, sender TEXT NOT NULL, request_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, request_id));
CREATE TABLE received_replies (sender TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, request_id));
CREATE TABLE outbound_replies (peer TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, request_id));
PRAGMA user_version = 4;
`

type Adapter struct {
	ID        string  `json:"id"`
	SessionID string  `json:"session_id"`
	ExpiresAt string  `json:"expires_at"`
	RevokedAt *string `json:"revoked_at"`
	// Renewable credentials were created without an expiry: each connection
	// or lease renewal moves expires_at to 24 hours ahead.
	Renewable bool `json:"renewable"`
	// Directory credentials may send and delegate by address to any agent
	// in the directory, at most MaxSendsPerHour times in any 60 minutes;
	// MaxSendsPerHour is null without directory access.
	Directory       bool   `json:"directory"`
	MaxSendsPerHour *int64 `json:"max_sends_per_hour"`
	// Calls credentials may list and call capabilities, at most
	// MaxCallsPerHour calls in any 60 minutes; MaxCallsPerHour is null
	// without calls. A record from before calls reads as false and null.
	Calls           bool   `json:"calls"`
	MaxCallsPerHour *int64 `json:"max_calls_per_hour"`
}

// CreateAdapter without ExpiresAt issues a renewable credential.
type CreateAdapter struct {
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at,omitempty"`
	// maxSendsPerHour, nonzero only through setup, grants directory access.
	maxSendsPerHour int64
	// maxCallsPerHour, nonzero only through setup, grants calls.
	maxCallsPerHour int64
}

const (
	adapterRenewal        = 24 * time.Hour
	adapterRenewalMinimum = time.Minute
	adapterRenewedEvery   = time.Hour
)

type AdapterCredential struct {
	Adapter            Adapter  `json:"adapter"`
	Token              string   `json:"token"`
	ReplacedAdapterIDs []string `json:"replaced_adapter_ids,omitempty"`
}
type Delivery struct {
	ID            string `json:"id"`
	SenderHostID  string `json:"sender_host_id"`
	RequestID     string `json:"request_id"`
	TargetAgentID string `json:"target_agent_id"`
	SessionID     string `json:"session_id"`
	AdapterID     string `json:"adapter_id"`
	State         string `json:"state"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}
type DeliveryRecord struct {
	Sequence int64    `json:"sequence"`
	Delivery Delivery `json:"delivery"`
}
type Handoff struct {
	Delivery Delivery       `json:"delivery"`
	Request  MessageRequest `json:"request"`
	// SenderPersonID and SenderPerson name the person the sending host is
	// bound to, if any, in the first network by ID that binds it.
	SenderPersonID *string `json:"sender_person_id"`
	SenderPerson   *string `json:"sender_person"`
	// Redelivered marks a message claimed again after its holding
	// authorization ended without seeing it.
	Redelivered bool `json:"redelivered"`
}
type Reply struct {
	SenderHostID   string `json:"sender_host_id"`
	RequestID      string `json:"request_id"`
	ReceiverHostID string `json:"receiver_host_id"`
	TargetAgentID  string `json:"target_agent_id"`
	SessionID      string `json:"session_id"`
	DeliveryID     string `json:"delivery_id"`
	Content        string `json:"content"`
	RepliedAt      string `json:"replied_at"`
	// Origin is the agent and session that replied, as the replying host
	// asserts it.
	Origin *Origin `json:"origin,omitempty"`
}
type ReplyStatus struct {
	State string  `json:"state"`
	Reply *Reply  `json:"reply"`
	Error *string `json:"error"`
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (s *Store) CreateAdapter(ctx context.Context, r CreateAdapter) (AdapterCredential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AdapterCredential{}, err
	}
	defer tx.Rollback()
	credential, err := s.createAdapter(ctx, tx, r)
	if err != nil {
		return AdapterCredential{}, err
	}
	return credential, tx.Commit()
}
func (s *Store) createAdapter(ctx context.Context, tx *sql.Tx, r CreateAdapter) (AdapterCredential, error) {
	renewable := r.ExpiresAt == ""
	if renewable {
		r.ExpiresAt = timestamp(time.Now().Add(adapterRenewal))
	}
	expires, err := parseTime(r.ExpiresAt)
	if err != nil || !expires.After(time.Now()) {
		return AdapterCredential{}, ErrInvalid
	}
	session, err := scanSession(tx.QueryRowContext(ctx, `SELECT id, agent_id, integration, state, created_at, updated_at FROM sessions WHERE id = ?`, r.SessionID))
	if err != nil {
		return AdapterCredential{}, err
	}
	if session.State != SessionAttached {
		return AdapterCredential{}, ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.record,x.instance_hash,x.lease_until_ms FROM adapter_credentials c JOIN sessions s ON c.session_id = s.id JOIN adapter_connections x ON x.adapter_id = c.id WHERE s.agent_id = ? AND (s.state = 'attached' OR x.recoverable = 1) ORDER BY c.id`, session.AgentID)
	if err != nil {
		return AdapterCredential{}, err
	}
	now := time.Now()
	var stale []Adapter
	for rows.Next() {
		var encoded string
		var hash sql.NullString
		var until int64
		if err = rows.Scan(&encoded, &hash, &until); err != nil {
			break
		}
		var old Adapter
		if err = json.Unmarshal([]byte(encoded), &old); err != nil {
			break
		}
		var exp time.Time
		exp, err = parseTime(old.ExpiresAt)
		if err != nil {
			break
		}
		if old.RevokedAt != nil || !exp.After(now) {
			continue
		}
		// Issuing a credential for a different session is the owner's replacement
		// decision. An unbound setup, live lease, or startup reconnect window
		// still reserves the agent.
		if old.SessionID == r.SessionID {
			err = fmt.Errorf("%w: replacement requires a fresh session attachment", ErrConflict)
			break
		}
		if !hash.Valid {
			err = fmt.Errorf("%w: adapter %s has not connected; revoke it or detach its session to cancel that setup", ErrConflict, old.ID)
			break
		}
		if until > now.UnixMilli() {
			err = fmt.Errorf("%w: adapter %s has a live lease until %s; retry after it expires or explicitly detach its session", ErrConflict, old.ID, timestamp(time.UnixMilli(until)))
			break
		}
		if deadline := s.adapterRecoveryUntil[old.ID]; deadline.After(now) {
			err = fmt.Errorf("%w: adapter %s has a restart reconnect window until %s; retry after it expires or explicitly detach its session", ErrConflict, old.ID, timestamp(deadline))
			break
		}
		stale = append(stale, old)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return AdapterCredential{}, err
	}
	if !expires.After(now) {
		return AdapterCredential{}, ErrInvalid
	}
	replaced := []string{}
	at := timestamp(now)
	for _, old := range stale {
		old.RevokedAt = &at
		data, err := json.Marshal(old)
		if err != nil {
			return AdapterCredential{}, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE adapter_credentials SET record = ? WHERE id = ?`, string(data), old.ID); err != nil {
			return AdapterCredential{}, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE adapter_connections SET recoverable = 0,lease_until_ms = 0 WHERE adapter_id = ?`, old.ID); err != nil {
			return AdapterCredential{}, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE sessions SET state = 'detached',updated_at = ? WHERE id = ?`, at, old.SessionID); err != nil {
			return AdapterCredential{}, err
		}
		if err = appendEvent(ctx, tx, "adapter.replaced", old.ID, at); err != nil {
			return AdapterCredential{}, err
		}
		if err = appendEvent(ctx, tx, "session.detached", old.SessionID, at); err != nil {
			return AdapterCredential{}, err
		}
		replaced = append(replaced, old.ID)
	}
	id, err := newID("adapter")
	if err != nil {
		return AdapterCredential{}, err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return AdapterCredential{}, err
	}
	token := "token_" + hex.EncodeToString(random)
	adapter := Adapter{ID: id, SessionID: r.SessionID, ExpiresAt: r.ExpiresAt, Renewable: renewable}
	if r.maxSendsPerHour > 0 {
		adapter.Directory, adapter.MaxSendsPerHour = true, &r.maxSendsPerHour
	}
	if r.maxCallsPerHour > 0 {
		adapter.Calls, adapter.MaxCallsPerHour = true, &r.maxCallsPerHour
	}
	data, err := json.Marshal(adapter)
	if err != nil {
		return AdapterCredential{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO adapter_credentials VALUES (?, ?, ?, ?)`, id, r.SessionID, tokenHash(token), string(data)); err != nil {
		return AdapterCredential{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO adapter_connections(adapter_id) VALUES (?)`, id); err != nil {
		return AdapterCredential{}, err
	}
	if err = appendEvent(ctx, tx, "adapter.created", id, timestamp(time.Now())); err != nil {
		return AdapterCredential{}, err
	}
	return AdapterCredential{Adapter: adapter, Token: token, ReplacedAdapterIDs: replaced}, nil
}
func (s *Store) Adapter(ctx context.Context, id string) (Adapter, error) {
	return readJSON[Adapter](s.db.QueryRowContext(ctx, `SELECT record FROM adapter_credentials WHERE id = ?`, id))
}
func (s *Store) Adapters(ctx context.Context) ([]Adapter, error) {
	return records[Adapter](ctx, s.db, `SELECT record FROM adapter_credentials ORDER BY id`)
}
func (s *Store) RevokeAdapter(ctx context.Context, id string) (Adapter, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Adapter{}, err
	}
	defer tx.Rollback()
	a, err := readJSON[Adapter](tx.QueryRowContext(ctx, `SELECT record FROM adapter_credentials WHERE id = ?`, id))
	if err != nil {
		return a, err
	}
	if a.RevokedAt != nil {
		return a, nil
	}
	at := timestamp(time.Now())
	a.RevokedAt = &at
	data, err := json.Marshal(a)
	if err != nil {
		return a, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_credentials SET record = ? WHERE id = ?`, string(data), id); err != nil {
		return a, err
	}
	if err = appendEvent(ctx, tx, "adapter.revoked", id, at); err != nil {
		return a, err
	}
	return a, tx.Commit()
}
func credentialAuthority(ctx context.Context, tx *sql.Tx, token string) (Adapter, Session, error) {
	if !validID(token, "token", 32) {
		return Adapter{}, Session{}, ErrForbidden
	}
	a, err := readJSON[Adapter](tx.QueryRowContext(ctx, `SELECT record FROM adapter_credentials WHERE token_hash = ?`, tokenHash(token)))
	if errors.Is(err, ErrNotFound) {
		err = ErrForbidden
	}
	if err != nil {
		return a, Session{}, err
	}
	expires, err := parseTime(a.ExpiresAt)
	if err != nil {
		return a, Session{}, err
	}
	if a.RevokedAt != nil || !expires.After(time.Now()) {
		return a, Session{}, ErrForbidden
	}
	ss, err := scanSession(tx.QueryRowContext(ctx, `SELECT id,agent_id,integration,state,created_at,updated_at FROM sessions WHERE id = ?`, a.SessionID))
	return a, ss, err
}

func (s *Store) NextDelivery(ctx context.Context, token AdapterAuth) (*Handoff, error) {
	if err := s.returnEnded(ctx, token); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, token)
	if err != nil {
		return nil, err
	}
	if err = requireVerified(ctx, tx, a.ID); err != nil {
		return nil, err
	}
	// Messages returned by the agent's ended authorizations come first.
	if h, err := s.claimReturnedDelivery(ctx, tx, a, ss); err != nil || h != nil {
		if err != nil {
			return nil, err
		}
		return h, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT m.sender,m.request FROM received_messages m WHERE json_extract(m.request,'$.target_agent_id') = ? AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.sender = m.sender AND d.request_id = m.request_id) ORDER BY m.rowid LIMIT 100`, ss.AgentID)
	if err != nil {
		return nil, err
	}
	type pending struct {
		sender  string
		request MessageRequest
	}
	items := []pending{}
	for rows.Next() {
		var p pending
		var encoded string
		if err = rows.Scan(&p.sender, &encoded); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(encoded), &p.request); err != nil {
			break
		}
		items = append(items, p)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	var result *Handoff
	for _, p := range items {
		g, err := s.messageBounds(ctx, tx, p.sender, p.request, true)
		if errors.Is(err, ErrUnavailable) {
			continue // behind the cited policy version: recoverable
		}
		if err != nil && !errors.Is(err, ErrForbidden) {
			return nil, err
		}
		if err == nil {
			// A recoverable connected state is not final: leave the message
			// unclaimed, without a delivery record, until syncing resumes or
			// its deadline passes. A sender that is no longer a member is
			// blocked like any final denial.
			usable, recoverable, e := s.grantConnected(ctx, tx, p.sender, g)
			if e != nil {
				return nil, e
			}
			if !usable && recoverable {
				continue
			}
			if !usable {
				err = ErrForbidden
			}
		}
		state := "unknown"
		if err != nil {
			state = "blocked"
		}
		id, e := newID("delivery")
		if e != nil {
			return nil, e
		}
		at := timestamp(time.Now())
		d := Delivery{ID: id, SenderHostID: p.sender, RequestID: p.request.RequestID, TargetAgentID: ss.AgentID, SessionID: ss.ID, AdapterID: a.ID, State: state, CreatedAt: at, UpdatedAt: at}
		data, e := json.Marshal(d)
		if e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO deliveries (id, sender, request_id, session_id, record) VALUES (?, ?, ?, ?, ?)`, id, p.sender, d.RequestID, ss.ID, string(data)); e != nil {
			return nil, e
		}
		kind := "message.handoff"
		if state == "blocked" {
			kind = "message.blocked"
		}
		if e = appendEvent(ctx, tx, kind, id, at); e != nil {
			return nil, e
		}
		if state == "unknown" {
			result = &Handoff{Delivery: d, Request: p.request}
			if result.SenderPersonID, result.SenderPerson, e = senderPerson(ctx, tx, p.sender); e != nil {
				return nil, e
			}
			break
		}
	}
	return result, tx.Commit()
}

// claimReturnedDelivery claims the oldest returned message of the session's
// agent, rechecking its authorization as a first handoff does: a recoverable
// denial leaves it returned, and a final one blocks it.
func (s *Store) claimReturnedDelivery(ctx context.Context, tx *sql.Tx, a Adapter, ss Session) (*Handoff, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.record, m.request FROM deliveries d JOIN received_messages m ON m.sender = d.sender AND m.request_id = d.request_id WHERE d.returned_at IS NOT NULL AND json_extract(d.record, '$.target_agent_id') = ? ORDER BY d.rowid LIMIT 100`, ss.AgentID)
	if err != nil {
		return nil, err
	}
	type returned struct {
		delivery Delivery
		request  MessageRequest
	}
	var items []returned
	for rows.Next() {
		var p returned
		var record, request string
		if err = rows.Scan(&record, &request); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(record), &p.delivery); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(request), &p.request); err != nil {
			break
		}
		items = append(items, p)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, p := range items {
		g, err := s.messageBounds(ctx, tx, p.delivery.SenderHostID, p.request, true)
		if errors.Is(err, ErrUnavailable) {
			continue
		}
		if err != nil && !errors.Is(err, ErrForbidden) {
			return nil, err
		}
		if err == nil {
			usable, recoverable, e := s.grantConnected(ctx, tx, p.delivery.SenderHostID, g)
			if e != nil {
				return nil, e
			}
			if !usable && recoverable {
				continue
			}
			if !usable {
				err = ErrForbidden
			}
		}
		d := p.delivery
		at := timestamp(time.Now())
		if err != nil {
			d.State, d.UpdatedAt = "blocked", at
			if _, e := tx.ExecContext(ctx, `UPDATE deliveries SET returned_at = NULL WHERE id = ?`, d.ID); e != nil {
				return nil, e
			}
			if e := updateDelivery(ctx, tx, d, "message.blocked"); e != nil {
				return nil, e
			}
			continue
		}
		d.AdapterID, d.SessionID, d.State, d.UpdatedAt = a.ID, ss.ID, "unknown", at
		data, e := json.Marshal(d)
		if e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE deliveries SET record = ?, session_id = ?, returned_at = NULL, redeliveries = redeliveries + 1 WHERE id = ?`, string(data), ss.ID, d.ID); e != nil {
			return nil, e
		}
		if e = appendEvent(ctx, tx, "message.handoff", d.ID, at); e != nil {
			return nil, e
		}
		h := &Handoff{Delivery: d, Request: p.request, Redelivered: true}
		if h.SenderPersonID, h.SenderPerson, e = senderPerson(ctx, tx, d.SenderHostID); e != nil {
			return nil, e
		}
		return h, nil
	}
	return nil, nil
}

func (s *Store) Delivery(ctx context.Context, id string) (Delivery, error) {
	return readJSON[Delivery](s.db.QueryRowContext(ctx, `SELECT record FROM deliveries WHERE id = ?`, id))
}
func (s *Store) Deliveries(ctx context.Context, after, limit int64) ([]DeliveryRecord, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rowid,record FROM deliveries WHERE rowid > ? ORDER BY rowid LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DeliveryRecord{}
	for rows.Next() {
		var item DeliveryRecord
		var encoded string
		if err = rows.Scan(&item.Sequence, &encoded); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(encoded), &item.Delivery); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func ownedDelivery(ctx context.Context, tx *sql.Tx, token AdapterAuth, id string) (Delivery, error) {
	a, ss, err := adapterAuthority(ctx, tx, token)
	if err != nil {
		return Delivery{}, err
	}
	var record string
	var returned bool
	err = tx.QueryRowContext(ctx, `SELECT record, returned_at IS NOT NULL FROM deliveries WHERE id = ?`, id).Scan(&record, &returned)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, ErrNotFound
	}
	if err != nil {
		return Delivery{}, err
	}
	var d Delivery
	if err = json.Unmarshal([]byte(record), &d); err != nil {
		return d, err
	}
	if d.AdapterID != a.ID || d.SessionID != ss.ID || d.State == "blocked" || returned {
		return d, ErrForbidden
	}
	return d, nil
}
func updateDelivery(ctx context.Context, tx *sql.Tx, d Delivery, kind string) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE deliveries SET record = ? WHERE id = ?`, string(data), d.ID); err != nil {
		return err
	}
	return appendEvent(ctx, tx, kind, d.ID, d.UpdatedAt)
}
func (s *Store) Forwarded(ctx context.Context, token AdapterAuth, id string) (Delivery, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Delivery{}, err
	}
	defer tx.Rollback()
	d, err := ownedDelivery(ctx, tx, token, id)
	if err != nil {
		return d, err
	}
	if d.State != "unknown" {
		return d, nil
	}
	d.State, d.UpdatedAt = "forwarded", timestamp(time.Now())
	if err = updateDelivery(ctx, tx, d, "message.forwarded"); err != nil {
		return d, err
	}
	return d, tx.Commit()
}
func (s *Store) Reply(ctx context.Context, token AdapterAuth, id, content string) (Reply, error) {
	if content == "" || !utf8.ValidString(content) || len(content) > 65536 {
		return Reply{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Reply{}, err
	}
	defer tx.Rollback()
	d, err := ownedDelivery(ctx, tx, token, id)
	if err != nil {
		return Reply{}, err
	}
	m, err := readJSON[MessageRequest](tx.QueryRowContext(ctx, `SELECT request FROM received_messages WHERE sender = ? AND request_id = ?`, d.SenderHostID, d.RequestID))
	if err != nil {
		return Reply{}, err
	}
	// A reply answers content this host already delivered, so only final
	// bounds apply; a lapsed connected state does not strand it.
	g, err := s.messageBounds(ctx, tx, d.SenderHostID, m, false)
	if err != nil {
		return Reply{}, err
	}
	if int64(len(content)) > g.maxMessageBytes {
		return Reply{}, ErrForbidden
	}
	// A reply reports the delivery seen.
	if _, err = tx.ExecContext(ctx, `UPDATE deliveries SET seen_at = COALESCE(seen_at, ?) WHERE id = ?`, timestamp(time.Now()), d.ID); err != nil {
		return Reply{}, err
	}
	old, err := readJSON[Reply](tx.QueryRowContext(ctx, `SELECT record FROM received_replies WHERE sender = ? AND request_id = ?`, d.SenderHostID, d.RequestID))
	if err == nil {
		if old.Content != content {
			return old, ErrConflict
		}
		return old, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return old, err
	}
	at := timestamp(time.Now())
	r := Reply{SenderHostID: d.SenderHostID, RequestID: d.RequestID, ReceiverHostID: s.identity.ID, TargetAgentID: d.TargetAgentID, SessionID: d.SessionID, DeliveryID: d.ID, Content: content, RepliedAt: at, Origin: &Origin{AgentID: d.TargetAgentID, SessionID: d.SessionID}}
	data, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO received_replies VALUES (?, ?, ?)`, d.SenderHostID, d.RequestID, string(data)); err != nil {
		return r, err
	}
	d.State, d.UpdatedAt = "replied", at
	if err = updateDelivery(ctx, tx, d, "message.replied"); err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *Store) ReceivedReply(ctx context.Context, sender, id string) (Reply, error) {
	return readJSON[Reply](s.db.QueryRowContext(ctx, `SELECT record FROM received_replies WHERE sender = ? AND request_id = ?`, sender, id))
}
func (s *Store) OutboundReply(ctx context.Context, peer, id string) (Reply, error) {
	return readJSON[Reply](s.db.QueryRowContext(ctx, `SELECT record FROM outbound_replies WHERE peer = ? AND request_id = ?`, peer, id))
}
func (s *Store) SaveOutboundReply(ctx context.Context, peer string, r Reply) (Reply, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	old, err := readJSON[Reply](tx.QueryRowContext(ctx, `SELECT record FROM outbound_replies WHERE peer = ? AND request_id = ?`, peer, r.RequestID))
	if err == nil {
		if old != r {
			return old, ErrConflict
		}
		return old, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return r, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO outbound_replies VALUES (?, ?, ?)`, peer, r.RequestID, string(data)); err != nil {
		return r, err
	}
	if err = appendEvent(ctx, tx, "reply.received", peer+"/"+r.RequestID, timestamp(time.Now())); err != nil {
		return r, err
	}
	return r, tx.Commit()
}

// senderPerson is the person a host is bound to, and its label, in the first
// network by ID that binds it; both are nil for an unbound host.
func senderPerson(ctx context.Context, tx *sql.Tx, host string) (*string, *string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT record FROM network_members WHERE host_id = ? ORDER BY network_id", host)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		member, err := readJSON[NetworkMember](rows)
		if err != nil {
			return nil, nil, err
		}
		if member.PersonID != nil {
			return member.PersonID, member.PersonMember, nil
		}
	}
	return nil, nil, rows.Err()
}
