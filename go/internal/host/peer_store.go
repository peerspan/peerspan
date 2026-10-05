package host

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// The v2 schema is shared with Rust. All changes and their activity commit together.
const peerSchema = `
CREATE TABLE peers (id TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE grants (id TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE received_messages (sender TEXT NOT NULL, request_id TEXT NOT NULL, request TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY(sender, request_id));
CREATE TABLE outbound_messages (peer TEXT NOT NULL, request_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, request_id));
PRAGMA user_version = 2;
`

type Peer struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}
type Grant struct {
	ID                string  `json:"id"`
	RequesterHostID   string  `json:"requester_host_id"`
	TargetAgentID     string  `json:"target_agent_id"`
	Action            string  `json:"action"`
	ExpiresAt         string  `json:"expires_at"`
	MaxMessageBytes   int64   `json:"max_message_bytes"`
	AllowDisconnected bool    `json:"allow_disconnected"`
	RevokedAt         *string `json:"revoked_at"`
}
type CreateGrant struct {
	RequesterHostID   string `json:"requester_host_id"`
	TargetAgentID     string `json:"target_agent_id"`
	ExpiresAt         string `json:"expires_at"`
	MaxMessageBytes   int64  `json:"max_message_bytes"`
	AllowDisconnected bool   `json:"allow_disconnected"`
}
type MessageRequest struct {
	RequestID     string `json:"request_id"`
	GrantID       string `json:"grant_id"`
	TargetAgentID string `json:"target_agent_id"`
	Deadline      string `json:"deadline"`
	Content       string `json:"content"`
}
type SendMessage struct {
	PeerHostID string `json:"peer_host_id"`
	MessageRequest
}
type Receipt struct {
	SenderHostID   string `json:"sender_host_id"`
	RequestID      string `json:"request_id"`
	ReceiverHostID string `json:"receiver_host_id"`
	TargetAgentID  string `json:"target_agent_id"`
	AcceptedAt     string `json:"accepted_at"`
}
type ReceivedMessage struct {
	Sequence int64          `json:"sequence"`
	Request  MessageRequest `json:"request"`
	Receipt  Receipt        `json:"receipt"`
}
type OutboundMessage struct {
	PeerHostID string         `json:"peer_host_id"`
	Request    MessageRequest `json:"request"`
	State      string         `json:"state"`
	Receipt    *Receipt       `json:"receipt"`
	Error      *string        `json:"error"`
}

func validID(id, prefix string, bytes int) bool {
	if len(id) != len(prefix)+1+bytes*2 || !strings.HasPrefix(id, prefix+"_") {
		return false
	}
	b, err := hex.DecodeString(id[len(prefix)+1:])
	return err == nil && len(b) == bytes && strings.ToLower(id) == id
}
func keyID(public []byte) string {
	hash := sha256.Sum256(public)
	return "host_" + hex.EncodeToString(hash[:])
}
func peerKey(p Peer) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(p.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != p.PublicKey || keyID(key) != p.ID {
		return nil, fmt.Errorf("%w: peer ID and public key must match", ErrInvalid)
	}
	return key, nil
}
func readJSON[T any](row interface{ Scan(...any) error }) (T, error) {
	var value T
	var encoded string
	if err := row.Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return value, ErrNotFound
		}
		return value, err
	}
	err := json.Unmarshal([]byte(encoded), &value)
	return value, err
}
func records[T any](ctx context.Context, db *sql.DB, query string) ([]T, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []T{}
	for rows.Next() {
		v, err := readJSON[T](rows)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}
func (s *Store) Peers(ctx context.Context) ([]Peer, error) {
	return records[Peer](ctx, s.db, "SELECT record FROM peers ORDER BY id")
}
func (s *Store) Peer(ctx context.Context, id string) (Peer, error) {
	return readJSON[Peer](s.db.QueryRowContext(ctx, "SELECT record FROM peers WHERE id = ?", id))
}
func (s *Store) AddPeer(ctx context.Context, p Peer) (Peer, error) {
	if _, err := peerKey(p); err != nil {
		return p, err
	}
	address, err := netip.ParseAddrPort(p.Address)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" {
		return p, fmt.Errorf("%w: address must be an IP and nonzero port", ErrInvalid)
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	old, err := readJSON[Peer](tx.QueryRowContext(ctx, "SELECT record FROM peers WHERE id = ?", p.ID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return p, err
	}
	if err == nil && old == p {
		return p, nil
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO peers VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET record = excluded.record", p.ID, string(encoded)); err != nil {
		return p, err
	}
	if err = appendEvent(ctx, tx, "peer.configured", p.ID, timestamp(time.Now())); err != nil {
		return p, err
	}
	return p, tx.Commit()
}
func (s *Store) Grants(ctx context.Context) ([]Grant, error) {
	return records[Grant](ctx, s.db, "SELECT record FROM grants ORDER BY id")
}
func (s *Store) Grant(ctx context.Context, id string) (Grant, error) {
	return readJSON[Grant](s.db.QueryRowContext(ctx, "SELECT record FROM grants WHERE id = ?", id))
}
func (s *Store) CreateGrant(ctx context.Context, r CreateGrant) (Grant, error) {
	expires, err := parseTime(r.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || r.MaxMessageBytes < 1 || r.MaxMessageBytes > 65536 {
		return Grant{}, ErrInvalid
	}
	id, err := newID("grant")
	if err != nil {
		return Grant{}, err
	}
	g := Grant{ID: id, RequesterHostID: r.RequesterHostID, TargetAgentID: r.TargetAgentID, Action: "message.append", ExpiresAt: r.ExpiresAt, MaxMessageBytes: r.MaxMessageBytes, AllowDisconnected: r.AllowDisconnected}
	if _, err = s.KnownHost(ctx, r.RequesterHostID, nil); err != nil {
		return g, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return g, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE id = ?", r.TargetAgentID).Scan(&count); err != nil {
		return g, err
	}
	if count == 0 {
		return g, ErrNotFound
	}
	data, err := json.Marshal(g)
	if err != nil {
		return g, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO grants VALUES (?, ?)", g.ID, string(data)); err != nil {
		return g, err
	}
	if err = appendEvent(ctx, tx, "grant.created", g.ID, timestamp(time.Now())); err != nil {
		return g, err
	}
	return g, tx.Commit()
}
func (s *Store) RevokeGrant(ctx context.Context, id string) (Grant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, err
	}
	defer tx.Rollback()
	g, err := readJSON[Grant](tx.QueryRowContext(ctx, "SELECT record FROM grants WHERE id = ?", id))
	if err != nil {
		return g, err
	}
	if g.RevokedAt != nil {
		return g, nil
	}
	at := timestamp(time.Now())
	g.RevokedAt = &at
	data, err := json.Marshal(g)
	if err != nil {
		return g, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE grants SET record = ? WHERE id = ?", string(data), id); err != nil {
		return g, err
	}
	if err = appendEvent(ctx, tx, "grant.revoked", id, at); err != nil {
		return g, err
	}
	return g, tx.Commit()
}

// messageAuthority is shared by wire acceptance and adapter handoff/reply.
func (s *Store) messageAuthority(ctx context.Context, tx *sql.Tx, sender string, r MessageRequest, requireDeadline bool) (Grant, error) {
	g, err := grantBounds(ctx, tx, sender, r, requireDeadline)
	if err != nil {
		return g, err
	}
	connected, err := s.grantConnected(ctx, tx, sender, g)
	if err == nil && !connected {
		err = ErrForbidden
	}
	return g, err
}

// grantBounds checks everything except coordination connectivity. Its denials
// are final: revocation, expiry, a passed deadline, and size never recover.
func grantBounds(ctx context.Context, tx *sql.Tx, sender string, r MessageRequest, requireDeadline bool) (Grant, error) {
	g, err := readJSON[Grant](tx.QueryRowContext(ctx, `SELECT record FROM grants WHERE id = ?`, r.GrantID))
	if errors.Is(err, ErrNotFound) {
		err = ErrForbidden
	}
	if err != nil {
		return g, err
	}
	expires, err := parseTime(g.ExpiresAt)
	if err != nil {
		return g, err
	}
	deadline, err := parseTime(r.Deadline)
	if err != nil {
		return g, err
	}
	now := time.Now()
	if g.RequesterHostID != sender || g.TargetAgentID != r.TargetAgentID || g.Action != "message.append" || g.RevokedAt != nil || !expires.After(now) || deadline.After(expires) || (requireDeadline && !deadline.After(now)) || int64(len(r.Content)) > g.MaxMessageBytes {
		return g, ErrForbidden
	}
	return g, nil
}

// grantConnected reports whether the grant may be used now. Without
// coordination, only a grant that opts in permits new work. Unlike
// grantBounds, a false result can change once syncing resumes.
func (s *Store) grantConnected(ctx context.Context, tx *sql.Tx, sender string, g Grant) (bool, error) {
	if g.AllowDisconnected {
		return true, nil
	}
	return s.connected(ctx, tx, sender, time.Now())
}
func validateMessage(r MessageRequest) error {
	if !validID(r.RequestID, "request", 16) || !validID(r.GrantID, "grant", 16) || !validID(r.TargetAgentID, "agent", 16) || r.Content == "" || !utf8.ValidString(r.Content) || len(r.Content) > 65536 {
		return ErrInvalid
	}
	if _, err := parseTime(r.Deadline); err != nil {
		return ErrInvalid
	}
	return nil
}
func (s *Store) AcceptMessage(ctx context.Context, sender string, r MessageRequest) (Receipt, error) {
	if err := validateMessage(r); err != nil {
		return Receipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	if _, err = s.messageAuthority(ctx, tx, sender, r, true); err != nil {
		return Receipt{}, err
	}
	now := time.Now()
	var oldRequest, oldReceipt string
	err = tx.QueryRowContext(ctx, "SELECT request, receipt FROM received_messages WHERE sender = ? AND request_id = ?", sender, r.RequestID).Scan(&oldRequest, &oldReceipt)
	if err == nil {
		var old MessageRequest
		var receipt Receipt
		if err = json.Unmarshal([]byte(oldRequest), &old); err != nil {
			return receipt, err
		}
		if old != r {
			return receipt, ErrConflict
		}
		err = json.Unmarshal([]byte(oldReceipt), &receipt)
		return receipt, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}
	receipt := Receipt{SenderHostID: sender, RequestID: r.RequestID, ReceiverHostID: s.identity.ID, TargetAgentID: r.TargetAgentID, AcceptedAt: timestamp(now)}
	requestData, err := json.Marshal(r)
	if err != nil {
		return receipt, err
	}
	receiptData, err := json.Marshal(receipt)
	if err != nil {
		return receipt, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO received_messages VALUES (?, ?, ?, ?)", sender, r.RequestID, string(requestData), string(receiptData)); err != nil {
		return receipt, err
	}
	if err = appendEvent(ctx, tx, "message.accepted", sender+"/"+r.RequestID, receipt.AcceptedAt); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit()
}
func (s *Store) MessageReceipt(ctx context.Context, sender, id string) (Receipt, error) {
	return readJSON[Receipt](s.db.QueryRowContext(ctx, "SELECT receipt FROM received_messages WHERE sender = ? AND request_id = ?", sender, id))
}
func (s *Store) Messages(ctx context.Context, after, limit int64) ([]ReceivedMessage, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT rowid,request,receipt FROM received_messages WHERE rowid > ? ORDER BY rowid LIMIT ?", after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ReceivedMessage{}
	pageBytes := 2
	for rows.Next() {
		var a, b string
		var item ReceivedMessage
		if err = rows.Scan(&item.Sequence, &a, &b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(a), &item.Request); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(b), &item.Receipt); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if pageBytes+len(encoded)+1 > 900000 {
			break
		}
		pageBytes += len(encoded) + 1
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Store) Outbound(ctx context.Context, peer, id string) (OutboundMessage, error) {
	return readJSON[OutboundMessage](s.db.QueryRowContext(ctx, "SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?", peer, id))
}
func (s *Store) PrepareOutbound(ctx context.Context, r SendMessage) (OutboundMessage, error) {
	if r.RequestID == "" {
		id, err := newID("request")
		if err != nil {
			return OutboundMessage{}, err
		}
		r.RequestID = id
	}
	if err := validateMessage(r.MessageRequest); err != nil {
		return OutboundMessage{}, err
	}
	if _, err := s.KnownHost(ctx, r.PeerHostID, nil); err != nil {
		return OutboundMessage{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundMessage{}, err
	}
	defer tx.Rollback()
	old, err := readJSON[OutboundMessage](tx.QueryRowContext(ctx, "SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?", r.PeerHostID, r.RequestID))
	if err == nil {
		if old.Request != r.MessageRequest {
			return old, ErrConflict
		}
		return old, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return old, err
	}
	out := OutboundMessage{PeerHostID: r.PeerHostID, Request: r.MessageRequest, State: "unknown"}
	data, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO outbound_messages VALUES (?, ?, ?)", out.PeerHostID, out.Request.RequestID, string(data)); err != nil {
		return out, err
	}
	if err = appendEvent(ctx, tx, "message.queued", out.PeerHostID+"/"+out.Request.RequestID, timestamp(time.Now())); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Store) FinishOutbound(ctx context.Context, out OutboundMessage) (OutboundMessage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	old, err := readJSON[OutboundMessage](tx.QueryRowContext(ctx, "SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?", out.PeerHostID, out.Request.RequestID))
	if err != nil {
		return out, err
	}
	if old.State == "accepted" {
		return old, nil
	}
	data, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE outbound_messages SET record = ? WHERE peer = ? AND request_id = ?", string(data), out.PeerHostID, out.Request.RequestID); err != nil {
		return out, err
	}
	if out.State != old.State {
		if err = appendEvent(ctx, tx, "message."+out.State, out.PeerHostID+"/"+out.Request.RequestID, timestamp(time.Now())); err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}
