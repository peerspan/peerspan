package host

import (
	"bytes"
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

	"github.com/peerspan/peerspan/go/internal/membership"
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
	ID              string `json:"id"`
	RequesterHostID string `json:"requester_host_id"`
	TargetAgentID   string `json:"target_agent_id"`
	Action          string `json:"action"`
	ExpiresAt       string `json:"expires_at"`
	MaxMessageBytes int64  `json:"max_message_bytes"`
	// MaxArtifactBytes bounds a task's input and result artifacts together;
	// 0 refuses artifacts.
	MaxArtifactBytes  int64   `json:"max_artifact_bytes"`
	AllowDisconnected bool    `json:"allow_disconnected"`
	RevokedAt         *string `json:"revoked_at"`
	// RequesterAgentID, when set, limits the grant to requests whose asserted
	// origin is that agent of the requester host.
	RequesterAgentID *string `json:"requester_agent_id"`
}
type CreateGrant struct {
	RequesterHostID   string  `json:"requester_host_id"`
	TargetAgentID     string  `json:"target_agent_id"`
	ExpiresAt         string  `json:"expires_at"`
	MaxMessageBytes   int64   `json:"max_message_bytes"`
	AllowDisconnected bool    `json:"allow_disconnected"`
	RequesterAgentID  *string `json:"requester_agent_id,omitempty"`
	// Action is message.append (the default when empty), task.submit, or
	// task.delegate.
	Action string `json:"action,omitempty"`
	// MaxArtifactBytes, when nonzero, needs a task action.
	MaxArtifactBytes int64 `json:"max_artifact_bytes,omitempty"`
}

// MessageRequest names exactly one authorization: a grant, or the owner
// policy it relies on.
type MessageRequest struct {
	RequestID     string          `json:"request_id"`
	GrantID       *string         `json:"grant_id,omitempty"`
	Policy        *PolicyCitation `json:"policy,omitempty"`
	Self          *SelfCitation   `json:"self,omitempty"`
	TargetAgentID string          `json:"target_agent_id"`
	Deadline      string          `json:"deadline"`
	Content       string          `json:"content"`
	// Origin is the sending host's assertion of which of its agents, and
	// optionally which session, originated the request. It is exactly as
	// strong as the authenticated host.
	Origin *Origin `json:"origin,omitempty"`
	// artifacts and artifactBytes describe a task's input manifest for
	// authorization; messages have none.
	artifacts     int
	artifactBytes int64
}

// Origin names a local agent and, optionally, one of its sessions.
type Origin struct {
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id,omitempty"`
}

// UnmarshalJSON accepts exactly agent_id and an optional session_id, never
// null and never unknown fields.
func (o *Origin) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return ErrInvalid
	}
	for field, value := range raw {
		if (field != "agent_id" && field != "session_id") || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalid
		}
	}
	if _, ok := raw["agent_id"]; !ok {
		return ErrInvalid
	}
	type plain Origin
	if err := json.Unmarshal(data, (*plain)(o)); err != nil {
		return err
	}
	// A present session ID must be a session ID; "" is not "absent".
	if _, ok := raw["session_id"]; ok && o.SessionID == "" {
		return ErrInvalid
	}
	return nil
}

func (o *Origin) valid() bool {
	return o == nil || (validID(o.AgentID, "agent", 16) && (o.SessionID == "" || validID(o.SessionID, "session", 16)))
}

// same reports whether two requests are identical.
func (r MessageRequest) same(o MessageRequest) bool {
	if (r.Policy == nil) != (o.Policy == nil) || (r.Policy != nil && *r.Policy != *o.Policy) {
		return false
	}
	if (r.GrantID == nil) != (o.GrantID == nil) || (r.GrantID != nil && *r.GrantID != *o.GrantID) {
		return false
	}
	if (r.Self == nil) != (o.Self == nil) || (r.Self != nil && *r.Self != *o.Self) {
		return false
	}
	if (r.Origin == nil) != (o.Origin == nil) || (r.Origin != nil && *r.Origin != *o.Origin) {
		return false
	}
	r.Policy, o.Policy, r.GrantID, o.GrantID, r.Origin, o.Origin, r.Self, o.Self = nil, nil, nil, nil, nil, nil, nil, nil
	return r == o
}

// grantOf is a request's grant ID, or "".
func grantOf(r MessageRequest) string {
	if r.GrantID == nil {
		return ""
	}
	return *r.GrantID
}

type SendMessage struct {
	PeerHostID string `json:"peer_host_id"`
	MessageRequest
	// To, with an optional Network, is an address given instead of
	// PeerHostID and TargetAgentID.
	To      *string `json:"to,omitempty"`
	Network string  `json:"network,omitempty"`
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
	PeerHostID string `json:"peer_host_id"`
	// To is the address the send was given; records not sent by address
	// keep their earlier shape, without it.
	To      *string        `json:"to,omitempty"`
	Request MessageRequest `json:"request"`
	State   string         `json:"state"`
	Receipt *Receipt       `json:"receipt"`
	Error   *string        `json:"error"`
	// Attempts counts transmissions, including receipt queries. NextAttemptAt
	// is the next automatic attempt; nil once the outcome is final or retries
	// stopped. A record from before automatic retry has neither field and is
	// treated as attempts 0 and due now.
	Attempts      int64   `json:"attempts"`
	NextAttemptAt *string `json:"next_attempt_at"`
	// ReceiptQueries counts receipt queries made at or after the deadline,
	// automatic or explicit; automatic retry stops after ten of them.
	ReceiptQueries int64 `json:"receipt_queries,omitempty"`
}

// recordedRequest is a request as an outbound record shows it: grant_id is
// null, rather than absent, when the request cites a policy.
type recordedRequest struct {
	RequestID     string          `json:"request_id"`
	GrantID       *string         `json:"grant_id"`
	Policy        *PolicyCitation `json:"policy,omitempty"`
	Self          *SelfCitation   `json:"self,omitempty"`
	TargetAgentID string          `json:"target_agent_id"`
	Deadline      string          `json:"deadline"`
	Content       string          `json:"content"`
	Origin        *Origin         `json:"origin,omitempty"`
}

func (o OutboundMessage) MarshalJSON() ([]byte, error) {
	type plain OutboundMessage
	return json.Marshal(struct {
		plain
		Request recordedRequest `json:"request"`
	}{plain(o), recordedRequest{o.Request.RequestID, o.Request.GrantID, o.Request.Policy, o.Request.Self, o.Request.TargetAgentID, o.Request.Deadline, o.Request.Content, o.Request.Origin}})
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
func records[T any](ctx context.Context, q queryer, query string, args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
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
	if r.Action == "" {
		r.Action = membership.PolicyActionMessage
	}
	expires, err := parseTime(r.ExpiresAt)
	if err != nil || !membership.ValidPolicyAction(r.Action) || !expires.After(time.Now()) || r.MaxMessageBytes < 1 || r.MaxMessageBytes > 65536 || (r.RequesterAgentID != nil && !validID(*r.RequesterAgentID, "agent", 16)) {
		return Grant{}, ErrInvalid
	}
	if r.MaxArtifactBytes < 0 || r.MaxArtifactBytes > membership.PolicyMaxArtifactBytes || (r.MaxArtifactBytes != 0 && !membership.TaskAction(r.Action)) {
		return Grant{}, fmt.Errorf("%w: max_artifact_bytes must be 0 to %d, and nonzero only for %s or %s", ErrInvalid, membership.PolicyMaxArtifactBytes, membership.PolicyActionTask, membership.PolicyActionDelegate)
	}
	id, err := newID("grant")
	if err != nil {
		return Grant{}, err
	}
	g := Grant{ID: id, RequesterHostID: r.RequesterHostID, TargetAgentID: r.TargetAgentID, Action: r.Action, ExpiresAt: r.ExpiresAt, MaxMessageBytes: r.MaxMessageBytes, MaxArtifactBytes: r.MaxArtifactBytes, AllowDisconnected: r.AllowDisconnected, RequesterAgentID: r.RequesterAgentID}
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

// messageAuthority authorizes wire acceptance. A connected state that can
// recover is reported as ErrUnavailable (503), so senders can retry the same
// request once the receiver syncs again; final denials remain ErrForbidden.
func (s *Store) messageAuthority(ctx context.Context, tx *sql.Tx, sender string, r MessageRequest, requireDeadline bool) (authority, error) {
	return s.actionAuthority(ctx, tx, sender, membership.PolicyActionMessage, r, requireDeadline)
}

// actionAuthority is messageAuthority for any action.
func (s *Store) actionAuthority(ctx context.Context, tx *sql.Tx, sender, action string, r MessageRequest, requireDeadline bool) (authority, error) {
	g, err := s.actionBounds(ctx, tx, sender, action, r, requireDeadline)
	if err != nil {
		return g, err
	}
	usable, recoverable, err := s.grantConnected(ctx, tx, sender, g)
	switch {
	case err != nil || usable:
	case recoverable:
		err = fmt.Errorf("%w: coordination disconnected", ErrUnavailable)
	default:
		err = ErrForbidden
	}
	return g, err
}

// actionGranted reports whether a grant's or rule's action permits a request
// for want: task.delegate implies task.submit.
func actionGranted(have, want string) bool {
	return have == want || (want == membership.PolicyActionTask && have == membership.PolicyActionDelegate)
}

// grantBounds checks everything except coordination connectivity. Its denials
// are final: revocation, expiry, a passed deadline, and size never recover.
func grantBounds(ctx context.Context, tx *sql.Tx, sender, action string, r MessageRequest, requireDeadline bool) (Grant, error) {
	g, err := readJSON[Grant](tx.QueryRowContext(ctx, `SELECT record FROM grants WHERE id = ?`, grantOf(r)))
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
	if g.RequesterHostID != sender || g.TargetAgentID != r.TargetAgentID || !actionGranted(g.Action, action) || g.RevokedAt != nil || !expires.After(now) || deadline.After(expires) || (requireDeadline && !deadline.After(now)) || int64(len(r.Content)) > g.MaxMessageBytes || !artifactsAllowed(r, g.MaxArtifactBytes) || (g.RequesterAgentID != nil && (r.Origin == nil || r.Origin.AgentID != *g.RequesterAgentID)) {
		return g, ErrForbidden
	}
	return g, nil
}

// grantConnected reports whether the grant or policy rule may be used now.
// Without coordination, only one that opts in permits new work. When it may not,
// recoverable is true only if the requester is a verified member of a network
// this host has not synced recently, so resumed syncing can restore it.
func (s *Store) grantConnected(ctx context.Context, tx *sql.Tx, sender string, g authority) (usable, recoverable bool, err error) {
	if g.allowDisconnected {
		return true, false, nil
	}
	// A DEC grant/rule never uses recent coordinator sync as freshness.
	ids, e := s.networkIDs(ctx, tx)
	if e != nil {
		return false, false, e
	}
	for _, id := range ids {
		g, e := s.loadProductGovernance(ctx, tx, id)
		if e != nil {
			return false, false, e
		}
		if g.snapshot == nil {
			continue
		}
		members := g.members()
		if _, own := members[s.identity.ID]; own {
			if _, peer := members[sender]; peer {
				return true, false, nil
			}
		}
	}
	if usable, err = s.connected(ctx, tx, sender, time.Now()); err != nil || usable {
		return usable, false, err
	}
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM network_members WHERE host_id = ?)`, sender).Scan(&recoverable)
	return false, recoverable, err
}
func validateMessage(r MessageRequest) error {
	// Exactly one authorization: a grant ID, a policy citation, or self.
	var authorized bool
	switch {
	case r.Policy != nil:
		authorized = r.GrantID == nil && r.Self == nil && membership.ValidPersonID(r.Policy.PersonID) && r.Policy.Version >= 1
	case r.Self != nil:
		authorized = r.GrantID == nil && membership.ValidPersonID(r.Self.PersonID)
	default:
		authorized = validID(grantOf(r), "grant", 16)
	}
	if !validID(r.RequestID, "request", 16) || !authorized || !validID(r.TargetAgentID, "agent", 16) || !r.Origin.valid() || r.Content == "" || !utf8.ValidString(r.Content) || len(r.Content) > 65536 {
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
		if !old.same(r) {
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
	// Without a grant, the send cites self access when the target host is
	// bound to this host's person, and otherwise its owner's policy.
	if r.GrantID == nil && r.Policy == nil && r.Self == nil {
		c, err := s.ownerCitation(ctx, s.db, r.PeerHostID)
		if err != nil {
			return OutboundMessage{}, err
		}
		r.Policy, r.Self = c.policy, c.self
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
		// A resend keeps its original citation.
		if r.GrantID == nil && (old.Request.Policy != nil || old.Request.Self != nil) {
			r.Policy, r.Self = old.Request.Policy, old.Request.Self
		}
		if !old.Request.same(r.MessageRequest) {
			return old, ErrConflict
		}
		return old, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return old, err
	}
	out := OutboundMessage{PeerHostID: r.PeerHostID, To: r.To, Request: r.MessageRequest, State: "unknown", NextAttemptAt: s.initialAttempt()}
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

// FinishOutbound records one attempt's outcome and schedules the next automatic
// attempt while the outcome stays unknown. An accepted record is never downgraded.
func (s *Store) FinishOutbound(ctx context.Context, out OutboundMessage, refresh bool) (OutboundMessage, error) {
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
	out.Attempts, out.ReceiptQueries = old.Attempts+1, old.ReceiptQueries
	s.scheduleAfterAttempt(&out, refresh)
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

// checkLocalOrigin requires an owner-asserted origin to name a registered
// local agent and, if given, one of that agent's sessions.
func (s *Store) checkLocalOrigin(ctx context.Context, o *Origin) error {
	if o == nil {
		return nil
	}
	if !o.valid() {
		return ErrInvalid
	}
	var found int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agents WHERE id = ?", o.AgentID).Scan(&found); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("%w: no local agent %s", ErrNotFound, o.AgentID)
	}
	if o.SessionID == "" {
		return nil
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE id = ? AND agent_id = ?", o.SessionID, o.AgentID).Scan(&found); err != nil {
		return err
	}
	if found == 0 {
		return fmt.Errorf("%w: no session %s of agent %s", ErrNotFound, o.SessionID, o.AgentID)
	}
	return nil
}
