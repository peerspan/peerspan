package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const adapterOutboundSchema = `
CREATE TABLE adapter_routes (id TEXT PRIMARY KEY, adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), name TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(adapter_id, name));
CREATE TABLE adapter_outbound (peer TEXT NOT NULL, request_id TEXT NOT NULL, adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), session_id TEXT NOT NULL REFERENCES sessions(id), route_id TEXT NOT NULL REFERENCES adapter_routes(id), next_poll_at INTEGER NOT NULL, reply_delivery TEXT, PRIMARY KEY(peer, request_id), UNIQUE(adapter_id, request_id), FOREIGN KEY(peer, request_id) REFERENCES outbound_messages(peer, request_id));
CREATE INDEX adapter_outbound_due ON adapter_outbound(next_poll_at);
CREATE INDEX adapter_outbound_route ON adapter_outbound(route_id);
PRAGMA user_version = 5;
`

type OutboundRoute struct {
	ID              string  `json:"id"`
	AdapterID       string  `json:"adapter_id"`
	Name            string  `json:"name"`
	PeerHostID      string  `json:"peer_host_id"`
	TargetAgentID   string  `json:"target_agent_id"`
	GrantID         *string `json:"grant_id"`
	ExpiresAt       string  `json:"expires_at"`
	MaxMessageBytes int64   `json:"max_message_bytes"`
	MaxMessages     int64   `json:"max_messages"`
	RevokedAt       *string `json:"revoked_at"`
}
type CreateOutboundRoute struct {
	AdapterID       string  `json:"adapter_id"`
	Name            string  `json:"name"`
	PeerHostID      string  `json:"peer_host_id"`
	TargetAgentID   string  `json:"target_agent_id"`
	GrantID         *string `json:"grant_id,omitempty"`
	ExpiresAt       string  `json:"expires_at"`
	MaxMessageBytes int64   `json:"max_message_bytes"`
	MaxMessages     int64   `json:"max_messages"`
}
type Destination struct {
	Name              string `json:"name"`
	ExpiresAt         string `json:"expires_at"`
	MaxMessageBytes   int64  `json:"max_message_bytes"`
	MessagesRemaining int64  `json:"messages_remaining"`
}
type AdapterSend struct {
	Destination string `json:"destination"`
	RequestID   string `json:"request_id"`
	Content     string `json:"content"`
}
type ReplyDelivery struct {
	ID         string `json:"id"`
	PeerHostID string `json:"peer_host_id"`
	RequestID  string `json:"request_id"`
	AdapterID  string `json:"adapter_id"`
	SessionID  string `json:"session_id"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}
type ReplyHandoff struct {
	Delivery ReplyDelivery `json:"delivery"`
	Reply    Reply         `json:"reply"`
}

type OutboundOrigin struct {
	PeerHostID    string         `json:"peer_host_id"`
	RequestID     string         `json:"request_id"`
	AdapterID     string         `json:"adapter_id"`
	SessionID     string         `json:"session_id"`
	RouteID       string         `json:"route_id"`
	ReplyDelivery *ReplyDelivery `json:"reply_delivery"`
}

// OutboundOrigin exposes durable session and notification state to the owner.
func (s *Store) OutboundOrigin(ctx context.Context, peer, id string) (OutboundOrigin, error) {
	out := OutboundOrigin{PeerHostID: peer, RequestID: id}
	var delivery sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT adapter_id,session_id,route_id,reply_delivery FROM adapter_outbound WHERE peer = ? AND request_id = ?`, peer, id).Scan(&out.AdapterID, &out.SessionID, &out.RouteID, &delivery)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if delivery.Valid {
		err = json.Unmarshal([]byte(delivery.String), &out.ReplyDelivery)
	}
	return out, err
}

func validRouteName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for i, b := range []byte(name) {
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
			continue
		}
		if i == 0 || !strings.ContainsRune("._-", rune(b)) {
			return false
		}
	}
	return true
}
func (s *Store) CreateOutboundRoute(ctx context.Context, r CreateOutboundRoute) (OutboundRoute, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundRoute{}, err
	}
	defer tx.Rollback()
	route, err := s.createOutboundRoute(ctx, tx, r)
	if err != nil {
		return OutboundRoute{}, err
	}
	return route, tx.Commit()
}
func (s *Store) createOutboundRoute(ctx context.Context, tx *sql.Tx, r CreateOutboundRoute) (OutboundRoute, error) {
	exp, err := parseTime(r.ExpiresAt)
	if err != nil || !exp.After(time.Now()) || !validRouteName(r.Name) || !validID(r.TargetAgentID, "agent", 16) || (r.GrantID != nil && !validID(*r.GrantID, "grant", 16)) || r.MaxMessageBytes < 1 || r.MaxMessageBytes > 65536 || r.MaxMessages < 1 || r.MaxMessages > 10000 {
		return OutboundRoute{}, ErrInvalid
	}
	var known int
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM peers WHERE id = ?) + (SELECT COUNT(*) FROM network_members WHERE host_id = ? AND host_id != ?)", r.PeerHostID, r.PeerHostID, s.identity.ID).Scan(&known); err != nil {
		return OutboundRoute{}, err
	}
	if known == 0 {
		return OutboundRoute{}, ErrNotFound
	}
	a, err := readJSON[Adapter](tx.QueryRowContext(ctx, `SELECT record FROM adapter_credentials WHERE id = ?`, r.AdapterID))
	if err != nil {
		return OutboundRoute{}, err
	}
	aExp, err := parseTime(a.ExpiresAt)
	if err != nil {
		return OutboundRoute{}, err
	}
	ss, err := scanSession(tx.QueryRowContext(ctx, `SELECT id,agent_id,integration,state,created_at,updated_at FROM sessions WHERE id = ?`, a.SessionID))
	if err != nil {
		return OutboundRoute{}, err
	}
	if a.RevokedAt != nil || ss.State != SessionAttached || !aExp.After(time.Now()) {
		return OutboundRoute{}, ErrForbidden
	}
	if exp.After(aExp) {
		return OutboundRoute{}, ErrInvalid
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM adapter_routes WHERE adapter_id = ? AND name = ?`, r.AdapterID, r.Name).Scan(&count); err != nil {
		return OutboundRoute{}, err
	}
	if count != 0 {
		return OutboundRoute{}, ErrConflict
	}
	id, err := newID("route")
	if err != nil {
		return OutboundRoute{}, err
	}
	route := OutboundRoute{ID: id, AdapterID: r.AdapterID, Name: r.Name, PeerHostID: r.PeerHostID, TargetAgentID: r.TargetAgentID, GrantID: r.GrantID, ExpiresAt: r.ExpiresAt, MaxMessageBytes: r.MaxMessageBytes, MaxMessages: r.MaxMessages}
	data, err := json.Marshal(route)
	if err != nil {
		return route, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO adapter_routes VALUES (?, ?, ?, ?)`, id, route.AdapterID, route.Name, string(data)); err != nil {
		return route, err
	}
	if err = appendEvent(ctx, tx, "adapter.route_created", id, timestamp(time.Now())); err != nil {
		return route, err
	}
	return route, nil
}
func (s *Store) OutboundRoutes(ctx context.Context, adapterID string) ([]OutboundRoute, error) {
	if _, err := s.Adapter(ctx, adapterID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM adapter_routes WHERE adapter_id = ? ORDER BY name`, adapterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OutboundRoute{}
	for rows.Next() {
		r, err := readJSON[OutboundRoute](rows)
		if err != nil {
			return nil, err
		}
		items = append(items, r)
	}
	return items, rows.Err()
}
func (s *Store) RevokeOutboundRoute(ctx context.Context, id string) (OutboundRoute, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundRoute{}, err
	}
	defer tx.Rollback()
	r, err := readJSON[OutboundRoute](tx.QueryRowContext(ctx, `SELECT record FROM adapter_routes WHERE id = ?`, id))
	if err != nil {
		return r, err
	}
	if r.RevokedAt != nil {
		return r, nil
	}
	at := timestamp(time.Now())
	r.RevokedAt = &at
	data, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_routes SET record = ? WHERE id = ?`, string(data), id); err != nil {
		return r, err
	}
	if err = appendEvent(ctx, tx, "adapter.route_revoked", id, at); err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *Store) Destinations(ctx context.Context, token AdapterAuth) ([]Destination, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, _, err := adapterAuthority(ctx, tx, token)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.record,(SELECT COUNT(*) FROM adapter_outbound o WHERE o.route_id = r.id) FROM adapter_routes r WHERE adapter_id = ? ORDER BY name`, a.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Destination{}
	for rows.Next() {
		var data string
		var used int64
		if err = rows.Scan(&data, &used); err != nil {
			return nil, err
		}
		var r OutboundRoute
		if err = json.Unmarshal([]byte(data), &r); err != nil {
			return nil, err
		}
		exp, err := parseTime(r.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if r.RevokedAt == nil && exp.After(time.Now()) {
			items = append(items, Destination{Name: r.Name, ExpiresAt: r.ExpiresAt, MaxMessageBytes: r.MaxMessageBytes, MessagesRemaining: r.MaxMessages - used})
		}
	}
	return items, rows.Err()
}
func (s *Store) PrepareAdapterSend(ctx context.Context, token AdapterAuth, r AdapterSend) (OutboundMessage, error) {
	if !validRouteName(r.Destination) || !validID(r.RequestID, "request", 16) || r.Content == "" || !utf8.ValidString(r.Content) || len(r.Content) > 65536 {
		return OutboundMessage{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundMessage{}, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, token)
	if err != nil {
		return OutboundMessage{}, err
	}
	route, err := readJSON[OutboundRoute](tx.QueryRowContext(ctx, `SELECT record FROM adapter_routes WHERE adapter_id = ? AND name = ?`, a.ID, r.Destination))
	if errors.Is(err, ErrNotFound) {
		err = ErrForbidden
	}
	if err != nil {
		return OutboundMessage{}, err
	}
	exp, err := parseTime(route.ExpiresAt)
	if err != nil {
		return OutboundMessage{}, err
	}
	if route.RevokedAt != nil || !exp.After(time.Now()) || int64(len(r.Content)) > route.MaxMessageBytes {
		return OutboundMessage{}, ErrForbidden
	}
	var reused int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM adapter_outbound WHERE adapter_id = ? AND request_id = ? AND route_id != ?`, a.ID, r.RequestID, route.ID).Scan(&reused); err != nil {
		return OutboundMessage{}, err
	}
	if reused != 0 {
		return OutboundMessage{}, ErrConflict
	}
	old, err := readJSON[OutboundMessage](tx.QueryRowContext(ctx, `SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?`, route.PeerHostID, r.RequestID))
	if err == nil {
		var adapterID, sessionID, routeID string
		if err = tx.QueryRowContext(ctx, `SELECT adapter_id,session_id,route_id FROM adapter_outbound WHERE peer = ? AND request_id = ?`, route.PeerHostID, r.RequestID).Scan(&adapterID, &sessionID, &routeID); errors.Is(err, sql.ErrNoRows) {
			return old, ErrConflict
		} else if err != nil {
			return old, err
		}
		if adapterID != a.ID || sessionID != ss.ID {
			return old, ErrForbidden
		}
		if routeID != route.ID || old.Request.Content != r.Content {
			return old, ErrConflict
		}
		deadline, err := parseTime(old.Request.Deadline)
		if err != nil {
			return old, err
		}
		if !deadline.After(time.Now()) && old.State != "accepted" {
			return old, ErrForbidden
		}
		return old, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return old, err
	}
	var used int64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM adapter_outbound WHERE route_id = ?`, route.ID).Scan(&used); err != nil {
		return old, err
	}
	if used >= route.MaxMessages {
		return old, ErrForbidden
	}
	deadline := time.Now().Add(5 * time.Minute)
	if exp.Before(deadline) {
		deadline = exp
	}
	// A route without a grant cites the target host's owner's policy.
	var citation *PolicyCitation
	if route.GrantID == nil {
		if citation, err = s.policyCitation(ctx, tx, route.PeerHostID); err != nil {
			return old, err
		}
	}
	out := OutboundMessage{PeerHostID: route.PeerHostID, Request: MessageRequest{RequestID: r.RequestID, GrantID: route.GrantID, Policy: citation, TargetAgentID: route.TargetAgentID, Deadline: timestamp(deadline), Content: r.Content, Origin: &Origin{AgentID: ss.AgentID, SessionID: ss.ID}}, State: "unknown", NextAttemptAt: s.initialAttempt()}
	if err = insertOutbound(ctx, tx, out); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO adapter_outbound VALUES (?, ?, ?, ?, ?, 0, NULL)`, out.PeerHostID, out.Request.RequestID, a.ID, ss.ID, route.ID); err != nil {
		return out, err
	}
	if err = appendEvent(ctx, tx, "adapter.message_queued", out.PeerHostID+"/"+out.Request.RequestID, timestamp(time.Now())); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func insertOutbound(ctx context.Context, tx *sql.Tx, out OutboundMessage) error {
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO outbound_messages VALUES (?, ?, ?)`, out.PeerHostID, out.Request.RequestID, string(data)); err != nil {
		return err
	}
	return appendEvent(ctx, tx, "message.queued", out.PeerHostID+"/"+out.Request.RequestID, timestamp(time.Now()))
}
func (s *Store) NextReply(ctx context.Context, token AdapterAuth) (*ReplyHandoff, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, token)
	if err != nil {
		return nil, err
	}
	var peer, id string
	var data string
	err = tx.QueryRowContext(ctx, `SELECT o.peer,o.request_id,r.record FROM adapter_outbound o JOIN outbound_replies r ON r.peer = o.peer AND r.request_id = o.request_id WHERE o.adapter_id = ? AND o.session_id = ? AND o.reply_delivery IS NULL ORDER BY o.rowid LIMIT 1`, a.ID, ss.ID).Scan(&peer, &id, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var reply Reply
	if err = json.Unmarshal([]byte(data), &reply); err != nil {
		return nil, err
	}
	nid, err := newID("notification")
	if err != nil {
		return nil, err
	}
	at := timestamp(time.Now())
	d := ReplyDelivery{ID: nid, PeerHostID: peer, RequestID: id, AdapterID: a.ID, SessionID: ss.ID, State: "unknown", CreatedAt: at, UpdatedAt: at}
	encoded, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_outbound SET reply_delivery = ? WHERE peer = ? AND request_id = ?`, string(encoded), peer, id); err != nil {
		return nil, err
	}
	if err = appendEvent(ctx, tx, "reply.handoff", nid, at); err != nil {
		return nil, err
	}
	return &ReplyHandoff{Delivery: d, Reply: reply}, tx.Commit()
}
func (s *Store) ReplyForwarded(ctx context.Context, token AdapterAuth, id string) (ReplyDelivery, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReplyDelivery{}, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, token)
	if err != nil {
		return ReplyDelivery{}, err
	}
	d, err := readJSON[ReplyDelivery](tx.QueryRowContext(ctx, `SELECT reply_delivery FROM adapter_outbound WHERE json_extract(reply_delivery,'$.id') = ? AND adapter_id = ? AND session_id = ?`, id, a.ID, ss.ID))
	if err != nil {
		return d, err
	}
	if d.State == "forwarded" {
		return d, nil
	}
	d.State, d.UpdatedAt = "forwarded", timestamp(time.Now())
	data, err := json.Marshal(d)
	if err != nil {
		return d, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_outbound SET reply_delivery = ? WHERE peer = ? AND request_id = ?`, string(data), d.PeerHostID, d.RequestID); err != nil {
		return d, err
	}
	if err = appendEvent(ctx, tx, "reply.forwarded", id, d.UpdatedAt); err != nil {
		return d, err
	}
	return d, tx.Commit()
}

type replyJob struct{ peer, id string }

func (s *Store) nextReplyJob(ctx context.Context) (*replyJob, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT o.peer,o.request_id,c.record FROM adapter_outbound o JOIN adapter_credentials c ON c.id = o.adapter_id JOIN sessions ss ON ss.id = o.session_id JOIN adapter_connections ac ON ac.adapter_id = o.adapter_id WHERE ac.lease_until_ms > ? AND ss.state = 'attached' AND o.next_poll_at <= ? AND NOT EXISTS (SELECT 1 FROM outbound_replies r WHERE r.peer = o.peer AND r.request_id = o.request_id) ORDER BY o.next_poll_at,o.rowid LIMIT 100`, time.Now().UnixMilli(), time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	var job *replyJob
	var inactive []replyJob
	for rows.Next() {
		var p, i, data string
		if err = rows.Scan(&p, &i, &data); err != nil {
			break
		}
		var a Adapter
		if err = json.Unmarshal([]byte(data), &a); err != nil {
			break
		}
		var exp time.Time
		exp, err = parseTime(a.ExpiresAt)
		if err != nil {
			break
		}
		if a.RevokedAt == nil && exp.After(time.Now()) {
			job = &replyJob{p, i}
			break
		}
		inactive = append(inactive, replyJob{p, i})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, old := range inactive {
		if _, err = tx.ExecContext(ctx, `UPDATE adapter_outbound SET next_poll_at = ? WHERE peer = ? AND request_id = ?`, int64(1<<63-1), old.peer, old.id); err != nil {
			return nil, err
		}
	}
	if job != nil {
		if _, err = tx.ExecContext(ctx, `UPDATE adapter_outbound SET next_poll_at = ? WHERE peer = ? AND request_id = ?`, time.Now().Add(10*time.Second).UnixMilli(), job.peer, job.id); err != nil {
			return nil, err
		}
	}
	return job, tx.Commit()
}
func (s *Store) RunReplyWorkers(ctx context.Context) {
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				job, err := s.nextReplyJob(ctx)
				if err != nil || job == nil {
					continue
				}
				_, _ = s.FetchReply(ctx, job.peer, job.id)
				if ctx.Err() != nil {
					return
				}
				_, _ = s.db.ExecContext(ctx, `UPDATE adapter_outbound SET next_poll_at = ? WHERE peer = ? AND request_id = ?`, time.Now().Add(2*time.Second).UnixMilli(), job.peer, job.id)
			}
		}()
	}
	workers.Wait()
}
