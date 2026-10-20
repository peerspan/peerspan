package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Agent capability tools (milestone 10, slice 2): attached agents list and
// call capabilities through their adapter credential, when it has calls.
// Each call is an outbound call with the agent's origin, counted against
// the credential's max_calls_per_hour when first persisted. When a call
// becomes final, a call-update notification bound to the session that made
// it follows live delivery's seen and redelivery rules.

const callsSchema = `
CREATE TABLE adapter_calls (peer TEXT NOT NULL, call_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id), adapter_id TEXT NOT NULL REFERENCES adapter_credentials(id), session_id TEXT NOT NULL REFERENCES sessions(id), called_at_ms INTEGER NOT NULL, PRIMARY KEY(peer, call_id), UNIQUE(agent_id, call_id), FOREIGN KEY(peer, call_id) REFERENCES outbound_calls(peer, call_id));
CREATE INDEX adapter_calls_rate ON adapter_calls(adapter_id, called_at_ms);
CREATE TABLE call_update_notifications (id TEXT PRIMARY KEY, peer TEXT NOT NULL, call_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, seen_at TEXT, redeliveries INTEGER NOT NULL DEFAULT 0, returned_at TEXT, UNIQUE(peer, call_id));
PRAGMA user_version = 18;
`

const (
	defaultMaxCallsPerHour = 100
	// callPartBytes bounds a result returned inline, and each part.
	callPartBytes = 65536
	// adapterCallResolve bounds resolving, citing, and persisting an agent's
	// call; adapterCallSubmit bounds the route's wait for the first attempt.
	adapterCallResolve = 20 * time.Second
	adapterCallSubmit  = 25 * time.Second
	// callFastPolls is how long after acceptance an agent's call is polled
	// every second.
	callFastPolls = 60 * time.Second
)

// Call view notes.
const (
	notePending   = "The call has not finished. Its result arrives as a kind=call_update event; call_status reports it at any time."
	noteUncertain = "The call was running when it ended without a result, so it may or may not have taken effect. Do not call it again on your own: check whether it took effect, or ask the person."
	noteNeverRan  = "The call never ran, so it had no effect. Calling again makes a new call."
	noteParts     = "The result is in parts; call call_status with offset set to next_offset for the next part."
)

// callSubmitting is the call view's state while the submission is unknown.
const callSubmitting = "submitting"

var errNoCalls = &codedError{status: http.StatusForbidden, code: "no_calls", message: "this session may not call capabilities; the person enables it with peerspan attach --calls"}

// callsAuthority is adapterAuthority for the capability call routes.
func callsAuthority(ctx context.Context, tx *sql.Tx, auth AdapterAuth) (Adapter, Session, error) {
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err == nil && !a.Calls {
		err = errNoCalls
	}
	return a, ss, err
}

// AdapterCapability is one entry of GET /adapter/v1/capabilities.
type AdapterCapability struct {
	Address     string             `json:"address"`
	HostID      string             `json:"host_id"`
	Capability  string             `json:"capability"`
	Operations  []ListedOperation  `json:"operations"`
	Resources   []SnapshotResource `json:"resources"`
	State       string             `json:"state"`
	Unavailable []string           `json:"unavailable"`
}

// AdapterCapabilities is GET /adapter/v1/capabilities.
type AdapterCapabilities struct {
	Capabilities []AdapterCapability `json:"capabilities"`
	Unanswered   []Unanswered        `json:"unanswered"`
}

// agentDiscovery lists what an agent may call, as discover does over every
// network of this host, keeping capabilities whose via entries apply to
// the agent.
func (s *Store) agentDiscovery(ctx context.Context, agent string) ([]DiscoveredCapability, []Unanswered, error) {
	hosts, err := s.personHosts(ctx, "", "")
	if err != nil {
		return nil, nil, err
	}
	return s.discoverCapabilities(ctx, hosts, "", listingView{agent: agent, capabilitiesOnly: true})
}

// AdapterCapabilityList lists the capabilities this session's agent may
// call, sorted by address, then host ID.
func (s *Store) AdapterCapabilityList(ctx context.Context, auth AdapterAuth) (AdapterCapabilities, error) {
	ss, err := s.callsSession(ctx, auth)
	if err != nil {
		return AdapterCapabilities{}, err
	}
	found, unanswered, err := s.agentDiscovery(ctx, ss.AgentID)
	if err != nil {
		return AdapterCapabilities{}, err
	}
	out := AdapterCapabilities{Capabilities: []AdapterCapability{}, Unanswered: unanswered}
	for _, e := range found {
		out.Capabilities = append(out.Capabilities, AdapterCapability{e.Address, e.HostID, e.Capability, e.Operations, e.Resources, e.State, e.Unavailable})
	}
	sort.SliceStable(out.Capabilities, func(i, j int) bool {
		a, b := out.Capabilities[i], out.Capabilities[j]
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.HostID < b.HostID
	})
	return out, nil
}

// callsSession checks the credential, lease, and calls, in a transaction of
// its own, and returns the session.
func (s *Store) callsSession(ctx context.Context, auth AdapterAuth) (Session, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	_, ss, err := callsAuthority(ctx, tx, auth)
	return ss, err
}

// AdapterCall is POST /adapter/v1/calls.
type AdapterCall struct {
	CallID    string          `json:"call_id"`
	Address   string          `json:"address"`
	Operation string          `json:"operation"`
	Input     json.RawMessage `json:"input"`
}

// CallView is how an agent sees one of its calls, with the result inline
// or one part of it from an offset.
type CallView struct {
	CallID      string          `json:"call_id"`
	Address     string          `json:"address"`
	PeerHostID  string          `json:"peer_host_id"`
	Operation   string          `json:"operation"`
	SubmitState string          `json:"submit_state"`
	State       string          `json:"state"`
	Error       *string         `json:"error"`
	CreatedAt   string          `json:"created_at"`
	Deadline    string          `json:"deadline"`
	Result      json.RawMessage `json:"result"`
	ResultPart  *string         `json:"result_part"`
	Truncated   bool            `json:"truncated"`
	ResultBytes *int64          `json:"result_bytes"`
	Offset      int64           `json:"offset"`
	NextOffset  *int64          `json:"next_offset"`
	Note        *string         `json:"note"`
}

// outboundCallFinal reports whether the local record is final: its
// submission refused, or its status final, which is stored only with its
// result.
func outboundCallFinal(o OutboundCall) bool {
	return o.SubmitState == submitRejected || (o.Status != nil && callFinal(o.Status.State))
}

// viewState is the call view's state: submitting while the submission is
// unknown, rejected when it was refused, and otherwise the status record's.
func viewState(o OutboundCall) string {
	switch {
	case o.SubmitState == submitUnknown:
		return callSubmitting
	case o.SubmitState == submitRejected:
		return CallRejected
	case o.Status == nil:
		// Accepted, with a final status not yet stored with its result.
		return CallQueued
	}
	return o.Status.State
}

// resultText is the compact JSON encoding of the stored result as this
// daemon encodes it: strings as UTF-8 rather than escapes, and numbers as
// received; or nil before there is a result.
func resultText(o OutboundCall) ([]byte, error) {
	if o.Result == nil {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(o.Result))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonicalJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// canonicalJSON writes the contract's result text encoding: no whitespace
// outside strings, object keys sorted by their UTF-8 bytes, numbers as
// received, and strings as raw UTF-8 escaping only '"', '\', and
// characters below U+0020.
func canonicalJSON(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case json.Number:
		buf.WriteString(v.String())
	case string:
		canonicalString(buf, v)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			canonicalString(buf, k)
			buf.WriteByte(':')
			if err := canonicalJSON(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unexpected JSON value %T", value)
	}
	return nil
}

func canonicalString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[c>>4])
				buf.WriteByte(hex[c&0xf])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}

// callView builds the view of an agent's call from byte offset of its
// result text. createdAt is when the call was persisted here.
func callView(o OutboundCall, createdAt string, offset int64) (CallView, error) {
	if offset < 0 {
		return CallView{}, fmt.Errorf("%w: offset is at least 0", ErrInvalid)
	}
	v := CallView{CallID: o.Request.CallID, Address: o.Target, PeerHostID: o.PeerHostID, Operation: o.Request.Operation, SubmitState: o.SubmitState, State: viewState(o), CreatedAt: createdAt, Deadline: o.Request.Deadline, Offset: offset}
	switch {
	case o.SubmitState == submitRejected:
		v.Error = o.Error
	case o.Status != nil:
		v.Error = o.Status.Error
	}
	text, err := resultText(o)
	if err != nil {
		return v, err
	}
	if text == nil && offset != 0 {
		return CallView{}, fmt.Errorf("%w: there is no result yet, so offset is 0", ErrInvalid)
	}
	if text != nil {
		size := int64(len(text))
		v.ResultBytes = &size
		if offset > size || (offset < size && !utf8.RuneStart(text[offset])) {
			return CallView{}, fmt.Errorf("%w: offset is past the result or inside a character", ErrInvalid)
		}
		if size <= callPartBytes && offset == 0 {
			v.Result = json.RawMessage(text)
		} else {
			end := min(offset+callPartBytes, size)
			for end < size && !utf8.RuneStart(text[end]) {
				end--
			}
			part := string(text[offset:end])
			v.ResultPart, v.Truncated = &part, true
			if end < size {
				v.NextOffset = &end
			}
		}
	}
	note := ""
	switch v.State {
	case callSubmitting, CallQueued, CallRunning:
		note = notePending
	case CallUncertain:
		note = noteUncertain
	case CallRejected, CallExpired, CallCancelled:
		note = noteNeverRan
	case CallSucceeded, CallFailed:
		if v.Truncated {
			note = noteParts
		}
	}
	if note != "" {
		v.Note = &note
	}
	return v, nil
}

// agentCall is an agent's call row: the call, its peer, and when and by
// which session it was made.
type agentCall struct {
	peer, callID, session, adapter string
	calledAt                       int64
}

func (c agentCall) createdAt() string { return timestamp(time.UnixMilli(c.calledAt)) }

// findAgentCall is the agent's call with an ID, made through any credential
// of the agent on this host.
func findAgentCall(ctx context.Context, q dbQuerier, agent, id string) (agentCall, error) {
	c := agentCall{callID: id}
	err := q.QueryRowContext(ctx, `SELECT peer, session_id, adapter_id, called_at_ms FROM adapter_calls WHERE agent_id = ? AND call_id = ?`, agent, id).Scan(&c.peer, &c.session, &c.adapter, &c.calledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, fmt.Errorf("%w: this agent has no call %s", ErrNotFound, id)
	}
	return c, err
}

// viewAgentCall reads an agent's call and builds its view; a final view
// marks the call's update notification this session holds as seen.
func (s *Store) viewAgentCall(ctx context.Context, tx *sql.Tx, a Adapter, ss Session, c agentCall, offset int64) (CallView, error) {
	out, err := readJSON[OutboundCall](tx.QueryRowContext(ctx, `SELECT record FROM outbound_calls WHERE peer = ? AND call_id = ?`, c.peer, c.callID))
	if err != nil {
		return CallView{}, err
	}
	v, err := callView(out, c.createdAt(), offset)
	if err != nil {
		return v, err
	}
	if !outboundCallFinal(out) {
		return v, nil
	}
	now := time.Now()
	at := timestamp(now)
	if _, err = tx.ExecContext(ctx, `UPDATE call_update_notifications SET seen_at = ? WHERE peer = ? AND call_id = ? AND session_id = ? AND json_extract(record, '$.adapter_id') = ? AND returned_at IS NULL AND seen_at IS NULL`, at, c.peer, c.callID, ss.ID, a.ID); err != nil {
		return v, err
	}
	// A late notification no session holds yet (never claimed, made for an
	// authorization that has ended) is bound to a verified session of its
	// agent that gets the final view, and is seen at once.
	if requireVerified(ctx, tx, a.ID) != nil {
		return v, nil
	}
	ended, err := endedAdapters(ctx, tx, ss.AgentID, now)
	if err != nil {
		return v, err
	}
	n, err := readJSON[callUpdateRecord](tx.QueryRowContext(ctx, `SELECT n.record FROM call_update_notifications n WHERE n.peer = ? AND n.call_id = ? AND n.returned_at IS NULL AND n.seen_at IS NULL AND `+callUpdateUnclaimed+` AND json_extract(n.record, '$.adapter_id') IN (SELECT value FROM json_each(?))`, c.peer, c.callID, jsonList(ended)))
	if errors.Is(err, ErrNotFound) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	if at == n.CreatedAt {
		at = timestamp(now.Add(time.Nanosecond))
	}
	n.AdapterID, n.SessionID, n.UpdatedAt = a.ID, ss.ID, at
	err = putJSON(ctx, tx, `UPDATE call_update_notifications SET record = ?, session_id = ?, seen_at = ? WHERE id = ?`, n.CallUpdateNotification, ss.ID, at, n.ID)
	return v, err
}

// checkCallRate enforces the credential's max_calls_per_hour over the calls
// persisted through it in the preceding 60 minutes.
func checkCallRate(ctx context.Context, tx *sql.Tx, a Adapter, now time.Time) error {
	limit := int64(defaultMaxCallsPerHour)
	if a.MaxCallsPerHour != nil {
		limit = *a.MaxCallsPerHour
	}
	since := now.Add(-time.Hour).UnixMilli()
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM adapter_calls WHERE adapter_id = ? AND called_at_ms > ?`, a.ID, since).Scan(&count); err != nil {
		return err
	}
	if count < limit {
		return nil
	}
	// The call that must leave the window first to admit one more.
	var at int64
	if err := tx.QueryRowContext(ctx, `SELECT called_at_ms FROM adapter_calls WHERE adapter_id = ? AND called_at_ms > ? ORDER BY called_at_ms LIMIT 1 OFFSET ?`, a.ID, since, count-limit).Scan(&at); err != nil {
		return err
	}
	wait := (at + time.Hour.Milliseconds() - now.UnixMilli() + 999) / 1000
	return &codedError{status: http.StatusTooManyRequests, code: "rate_limited", message: fmt.Sprintf("this session may call capabilities at most %d times in 60 minutes", limit), retryAfter: max(wait, 1)}
}

var errCallTimeout = &codedError{status: http.StatusServiceUnavailable, code: "timeout", message: "the call could not be resolved and recorded within 20 seconds; nothing was recorded"}

// repeatAgentCall returns the view of a call ID this agent already used:
// the existing call when address, operation, and input are identical, and
// a conflict otherwise. found is false when the agent has no such call.
func (s *Store) repeatAgentCall(ctx context.Context, tx *sql.Tx, a Adapter, ss Session, r AdapterCall) (CallView, bool, error) {
	c, err := findAgentCall(ctx, tx, ss.AgentID, r.CallID)
	if errors.Is(err, ErrNotFound) {
		return CallView{}, false, nil
	}
	if err != nil {
		return CallView{}, true, err
	}
	out, err := readJSON[OutboundCall](tx.QueryRowContext(ctx, `SELECT record FROM outbound_calls WHERE peer = ? AND call_id = ?`, c.peer, c.callID))
	if err != nil {
		return CallView{}, true, err
	}
	if out.Target != r.Address || out.Request.Operation != r.Operation || !bytes.Equal(out.Request.Input, r.Input) {
		return CallView{}, true, fmt.Errorf("%w: this agent already used call_id %s for a different call", ErrConflict, r.CallID)
	}
	v, err := s.viewAgentCall(ctx, tx, a, ss, c, 0)
	return v, true, err
}

// SubmitAgentCall persists and submits one call of the session's agent, as
// the contract orders it: shape, repeat, rate limit, address, citation,
// deadline, persistence, and the first submission attempt.
func (s *Store) SubmitAgentCall(ctx context.Context, auth AdapterAuth, r AdapterCall) (CallView, error) {
	received := time.Now()
	ss, err := s.callsSession(ctx, auth)
	if err != nil {
		return CallView{}, err
	}
	// 1. Shape.
	var compact bytes.Buffer
	if !validID(r.CallID, "call", 16) || len(r.Address) > 256 || len(r.Operation) < 1 || len(r.Operation) > 128 || json.Compact(&compact, r.Input) != nil || compact.Len() == 0 || compact.Bytes()[0] != '{' {
		return CallView{}, fmt.Errorf("%w: a call is call_id (call_ and 32 lowercase hex digits), address (at most 256 bytes), operation (1 to 128 bytes), and an input object", ErrInvalid)
	}
	r.Input = compact.Bytes()
	// 2 and 3. A repeat returns the existing call; otherwise the rate limit
	// applies. Neither counts a repeat.
	if v, done, err := s.agentCallChecks(ctx, auth, r, received); done || err != nil {
		return v, err
	}
	// 4. The address, resolved over the entries list_capabilities would list.
	if strings.Count(r.Address, "/") == 2 {
		return CallView{}, &codedError{status: http.StatusBadRequest, code: "source", message: "sources can be called only from the peerspan CLI"}
	}
	resolveCtx, cancel := context.WithDeadline(ctx, received.Add(adapterCallResolve))
	defer cancel()
	peer, entry, err := s.resolveCapabilityAddress(resolveCtx, r.Address, "", listingView{agent: ss.AgentID, capabilitiesOnly: true})
	if time.Since(received) > adapterCallResolve || errors.Is(err, context.DeadlineExceeded) {
		return CallView{}, errCallTimeout
	}
	if err != nil {
		return CallView{}, err
	}
	// An operation the listing lacks is not refused here: the receiver
	// decides, and its refusal makes the call rejected.
	// 5. The citation: the first via entry that applies to this agent.
	if len(entry.Via) == 0 {
		return CallView{}, fmt.Errorf("%w: nothing authorizes this call", ErrInvalid)
	}
	chosen := entry.Via[0]
	request := CallRequest{CallID: r.CallID, Capability: entry.Capability, Operation: r.Operation, Input: r.Input, Origin: &Origin{AgentID: ss.AgentID, SessionID: ss.ID}}
	if err = s.citeVia(ctx, chosen, &request); err != nil {
		return CallView{}, err
	}
	// 6. The deadline: 15 minutes, capped by the cited policy's valid_until
	// and the credential's expires_at.
	deadline := time.Now().Add(callMaxDeadline)
	if request.Policy != nil {
		if g, err := s.loadGovernance(ctx, s.db, request.Policy.NetworkID); err == nil {
			if key, ok := g.personKey(request.Policy.PersonID); ok {
				if p, ok := g.storedPolicy(key); ok {
					if until, err := membership.ParseTime(p.ValidUntil); err == nil && until.Before(deadline) {
						deadline = until
					}
				}
			}
		}
	}
	// 7. Persist the outbound record, the adapter_calls row, and the
	// activity together.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallView{}, err
	}
	defer tx.Rollback()
	a, ss, err := callsAuthority(ctx, tx, auth)
	if err != nil {
		return CallView{}, err
	}
	if expires, err := parseTime(a.ExpiresAt); err == nil && expires.Before(deadline) {
		deadline = expires
	}
	request.Deadline = timestamp(deadline)
	if err = validateCall(request); err != nil {
		return CallView{}, err
	}
	if v, found, err := s.repeatAgentCall(ctx, tx, a, ss, r); found || err != nil {
		if err == nil {
			err = tx.Commit()
		}
		return v, err
	}
	now := time.Now()
	if err = checkCallRate(ctx, tx, a, now); err != nil {
		return CallView{}, err
	}
	if now.Sub(received) > adapterCallResolve {
		return CallView{}, errCallTimeout
	}
	adapterID := a.ID
	network := chosen.NetworkID
	out := OutboundCall{PeerHostID: peer, Target: r.Address, NetworkID: network, Request: request, SubmitState: submitUnknown, NextAttemptAt: s.initialAttempt(), AdapterID: &adapterID}
	if err = putJSON(ctx, tx, `INSERT INTO outbound_calls (record, peer, call_id) VALUES (?, ?, ?)`, out, peer, request.CallID); err != nil {
		if isUniqueViolation(err) {
			return CallView{}, fmt.Errorf("%w: call_id %s is in use", ErrConflict, request.CallID)
		}
		return CallView{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO adapter_calls VALUES (?, ?, ?, ?, ?, ?)`, peer, request.CallID, ss.AgentID, a.ID, ss.ID, now.UnixMilli()); err != nil {
		if isUniqueViolation(err) {
			return CallView{}, fmt.Errorf("%w: call_id %s is in use", ErrConflict, request.CallID)
		}
		return CallView{}, err
	}
	if err = appendEvent(ctx, tx, "call.submitted", callSubject(peer, request.CallID), timestamp(now)); err != nil {
		return CallView{}, err
	}
	// Steps 4 to 7 finish within 20 seconds of receipt or persist nothing:
	// a deadline passed while writing rolls the transaction back.
	if time.Since(received) > adapterCallResolve {
		return CallView{}, errCallTimeout
	}
	if err = tx.Commit(); err != nil {
		return CallView{}, err
	}
	// 8. The first attempt, waited on until 25 seconds after receipt; later
	// attempts continue in the background.
	submitCtx, cancelSubmit := context.WithDeadline(context.WithoutCancel(ctx), received.Add(adapterCallSubmit))
	_, _ = s.ExchangeCall(submitCtx, peer, request.CallID, false)
	cancelSubmit()
	return s.AgentCallView(ctx, auth, request.CallID, 0)
}

// agentCallChecks answers a repeated call ID, and otherwise applies the rate
// limit; done reports a repeat answered.
func (s *Store) agentCallChecks(ctx context.Context, auth AdapterAuth, r AdapterCall, now time.Time) (CallView, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallView{}, false, err
	}
	defer tx.Rollback()
	a, ss, err := callsAuthority(ctx, tx, auth)
	if err != nil {
		return CallView{}, false, err
	}
	v, found, err := s.repeatAgentCall(ctx, tx, a, ss, r)
	if found || err != nil {
		if err == nil {
			err = tx.Commit()
		}
		return v, found, err
	}
	return CallView{}, false, checkCallRate(ctx, tx, a, now)
}

// AgentCallView is the view of a call made through any credential of this
// session's agent on this host.
func (s *Store) AgentCallView(ctx context.Context, auth AdapterAuth, id string, offset int64) (CallView, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallView{}, err
	}
	defer tx.Rollback()
	a, ss, err := callsAuthority(ctx, tx, auth)
	if err != nil {
		return CallView{}, err
	}
	c, err := findAgentCall(ctx, tx, ss.AgentID, id)
	if err != nil {
		return CallView{}, err
	}
	v, err := s.viewAgentCall(ctx, tx, a, ss, c, offset)
	if err != nil {
		return v, err
	}
	if err = tx.Commit(); err != nil {
		return v, err
	}
	if !callFinal(v.State) && v.State != callSubmitting {
		s.pollSoon(callKey(c.peer, c.callID))
	}
	return v, nil
}

// CancelAgentCall sends cancellation of an agent's call, as calls cancel
// does, and returns its view.
func (s *Store) CancelAgentCall(ctx context.Context, auth AdapterAuth, id string) (CallView, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return CallView{}, err
	}
	_, ss, err := callsAuthority(ctx, tx, auth)
	var c agentCall
	if err == nil {
		c, err = findAgentCall(ctx, tx, ss.AgentID, id)
	}
	tx.Rollback()
	if err != nil {
		return CallView{}, err
	}
	out, err := s.CancelOutboundCall(ctx, c.peer, c.callID)
	if err != nil {
		return CallView{}, err
	}
	return callView(out, c.createdAt(), 0)
}

// CallUpdateNotification is a call-update notification: an agent's call
// became final.
type CallUpdateNotification struct {
	ID         string `json:"id"`
	PeerHostID string `json:"peer_host_id"`
	CallID     string `json:"call_id"`
	AdapterID  string `json:"adapter_id"`
	SessionID  string `json:"session_id"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// callUpdateRecord is call_update_notifications.record. A notification is
// created with updated_at equal to created_at, and every claim moves
// updated_at later, so one never claimed is one whose updated_at is still
// its created_at.
type callUpdateRecord struct {
	CallUpdateNotification
}

// callUpdateUnclaimed is the SQL condition for a notification never
// claimed.
const callUpdateUnclaimed = `json_extract(n.record, '$.updated_at') = json_extract(n.record, '$.created_at')`

// CallUpdateHandoff is a claimed call-update notification with the call
// view at offset 0.
type CallUpdateHandoff struct {
	Delivery    CallUpdateNotification `json:"delivery"`
	Call        CallView               `json:"call"`
	Redelivered bool                   `json:"redelivered"`
}

// createCallUpdate records the call-update notification of an agent's call
// that just became final, bound to the session that made it.
func createCallUpdate(ctx context.Context, tx *sql.Tx, out OutboundCall, at string) error {
	var session string
	err := tx.QueryRowContext(ctx, `SELECT session_id FROM adapter_calls WHERE peer = ? AND call_id = ?`, out.PeerHostID, out.Request.CallID).Scan(&session)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	id, err := newID("notification")
	if err != nil {
		return err
	}
	n := callUpdateRecord{CallUpdateNotification: CallUpdateNotification{ID: id, PeerHostID: out.PeerHostID, CallID: out.Request.CallID, AdapterID: deref(out.AdapterID), SessionID: session, State: "unknown", CreatedAt: at, UpdatedAt: at}}
	return putJSON(ctx, tx, `INSERT OR IGNORE INTO call_update_notifications (record, id, peer, call_id, session_id) VALUES (?, ?, ?, ?, ?)`, n.CallUpdateNotification, id, n.PeerHostID, n.CallID, session)
}

// NextCallUpdate claims the oldest unseen call-update notification this
// session may claim: one the agent's ended authorizations returned
// (redelivered), one bound to this session, or one created for an ended
// authorization of the agent that never claimed it.
func (s *Store) NextCallUpdate(ctx context.Context, auth AdapterAuth) (*CallUpdateHandoff, error) {
	if err := s.returnEnded(ctx, auth); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, ss, err := callsAuthority(ctx, tx, auth)
	if err != nil {
		return nil, err
	}
	if err = requireVerified(ctx, tx, a.ID); err != nil {
		return nil, err
	}
	now := time.Now()
	ended, err := endedAdapters(ctx, tx, ss.AgentID, now)
	if err != nil {
		return nil, err
	}
	var record string
	var returned bool
	err = tx.QueryRowContext(ctx, `SELECT n.record, n.returned_at IS NOT NULL FROM call_update_notifications n JOIN sessions s ON s.id = n.session_id WHERE n.seen_at IS NULL AND ((n.returned_at IS NOT NULL AND s.agent_id = ?) OR (n.returned_at IS NULL AND `+callUpdateUnclaimed+` AND ((n.session_id = ? AND json_extract(n.record, '$.adapter_id') = ?) OR json_extract(n.record, '$.adapter_id') IN (SELECT value FROM json_each(?))))) ORDER BY n.rowid LIMIT 1`, ss.AgentID, ss.ID, a.ID, jsonList(ended)).Scan(&record, &returned)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	var n callUpdateRecord
	if err = json.Unmarshal([]byte(record), &n); err != nil {
		return nil, err
	}
	at := timestamp(now)
	if at == n.CreatedAt {
		at = timestamp(now.Add(time.Nanosecond))
	}
	n.AdapterID, n.SessionID, n.State, n.UpdatedAt = a.ID, ss.ID, "unknown", at
	redeliveries := 0
	if returned {
		redeliveries = 1
	}
	if err = putJSON(ctx, tx, `UPDATE call_update_notifications SET record = ?, session_id = ?, returned_at = NULL, redeliveries = redeliveries + ? WHERE id = ?`, n.CallUpdateNotification, ss.ID, redeliveries, n.ID); err != nil {
		return nil, err
	}
	c := agentCall{peer: n.PeerHostID, callID: n.CallID}
	if err = tx.QueryRowContext(ctx, `SELECT session_id, adapter_id, called_at_ms FROM adapter_calls WHERE peer = ? AND call_id = ?`, c.peer, c.callID).Scan(&c.session, &c.adapter, &c.calledAt); err != nil {
		return nil, err
	}
	out, err := readJSON[OutboundCall](tx.QueryRowContext(ctx, `SELECT record FROM outbound_calls WHERE peer = ? AND call_id = ?`, c.peer, c.callID))
	if err != nil {
		return nil, err
	}
	view, err := callView(out, c.createdAt(), 0)
	if err != nil {
		return nil, err
	}
	h := &CallUpdateHandoff{Delivery: n.CallUpdateNotification, Call: view, Redelivered: returned}
	return h, tx.Commit()
}

// CallUpdateForwarded marks a call-update notification this session holds
// as forwarded.
func (s *Store) CallUpdateForwarded(ctx context.Context, auth AdapterAuth, id string) (CallUpdateNotification, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallUpdateNotification{}, err
	}
	defer tx.Rollback()
	a, ss, err := callsAuthority(ctx, tx, auth)
	if err != nil {
		return CallUpdateNotification{}, err
	}
	n, err := readJSON[callUpdateRecord](tx.QueryRowContext(ctx, `SELECT record FROM call_update_notifications WHERE id = ? AND json_extract(record, '$.adapter_id') = ? AND session_id = ? AND returned_at IS NULL`, id, a.ID, ss.ID))
	if err != nil || n.State == "forwarded" {
		return n.CallUpdateNotification, err
	}
	n.State, n.UpdatedAt = "forwarded", timestamp(time.Now())
	if err = putJSON(ctx, tx, `UPDATE call_update_notifications SET record = ? WHERE id = ?`, n.CallUpdateNotification, n.ID); err != nil {
		return n.CallUpdateNotification, err
	}
	return n.CallUpdateNotification, tx.Commit()
}

// markCallSeen marks, for mark_seen, the call-update notification of a
// call ID this authorization holds as seen. The authorization holds the ID
// when it holds the notification or made the call.
func markCallSeen(ctx context.Context, tx *sql.Tx, adapterID, sessionID, id, at string) (bool, bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE call_update_notifications SET seen_at = ? WHERE call_id = ? AND session_id = ? AND json_extract(record, '$.adapter_id') = ? AND returned_at IS NULL AND seen_at IS NULL`, at, id, sessionID, adapterID)
	if err != nil {
		return false, false, err
	}
	if changed, err := result.RowsAffected(); err != nil || changed > 0 {
		return true, changed > 0, err
	}
	var held bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM call_update_notifications WHERE call_id = ?1 AND session_id = ?2 AND json_extract(record, '$.adapter_id') = ?3 AND returned_at IS NULL) OR EXISTS(SELECT 1 FROM adapter_calls WHERE call_id = ?1 AND adapter_id = ?3)`, id, sessionID, adapterID).Scan(&held)
	return held, false, err
}

// PendingCall is a call a session still follows: not final, or final with
// an update notification it holds and has not seen.
type PendingCall struct {
	CallID      string  `json:"call_id"`
	Address     string  `json:"address"`
	Operation   string  `json:"operation"`
	State       string  `json:"state"`
	Error       *string `json:"error"`
	ResultBytes *int64  `json:"result_bytes"`
	CreatedAt   string  `json:"created_at"`
	Deadline    string  `json:"deadline"`
	SessionID   string  `json:"session_id"`
	Redelivered bool    `json:"redelivered"`
}

// pendingAgentCalls lists the calls made by a session, or by an ended
// authorization of its agent, that are not final, and the calls whose
// update notification the session holds unseen, oldest first.
func pendingAgentCalls(ctx context.Context, q queryer, session string) ([]PendingCall, error) {
	out := []PendingCall{}
	var agent string
	rows, err := q.QueryContext(ctx, `SELECT agent_id FROM sessions WHERE id = ?`, session)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		err = rows.Scan(&agent)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil || agent == "" {
		return out, err
	}
	ended, err := endedAdapters(ctx, q, agent, time.Now())
	if err != nil {
		return out, err
	}
	type item struct {
		call     PendingCall
		peer     string
		calledAt int64
	}
	var items []item
	seen := map[string]bool{}
	scan := func(query string, args []any, wantFinal bool) error {
		rows, err := q.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var it item
			var record string
			var redeliveries int64
			if err = rows.Scan(&it.peer, &it.call.SessionID, &it.calledAt, &record, &redeliveries); err != nil {
				return err
			}
			var o OutboundCall
			if err = json.Unmarshal([]byte(record), &o); err != nil {
				return err
			}
			key := it.peer + "/" + o.Request.CallID
			if outboundCallFinal(o) != wantFinal || seen[key] {
				continue
			}
			seen[key] = true
			v, err := callView(o, timestamp(time.UnixMilli(it.calledAt)), 0)
			if err != nil {
				return err
			}
			it.call = PendingCall{CallID: v.CallID, Address: v.Address, Operation: v.Operation, State: v.State, Error: v.Error, ResultBytes: v.ResultBytes, CreatedAt: v.CreatedAt, Deadline: v.Deadline, SessionID: it.call.SessionID, Redelivered: redeliveries > 0}
			items = append(items, it)
		}
		return rows.Err()
	}
	if err = scan(`SELECT c.peer, c.session_id, c.called_at_ms, o.record, 0 FROM adapter_calls c JOIN outbound_calls o ON o.peer = c.peer AND o.call_id = c.call_id WHERE c.session_id = ? OR (c.agent_id = ? AND c.adapter_id IN (SELECT value FROM json_each(?)))`, []any{session, agent, jsonList(ended)}, false); err != nil {
		return out, err
	}
	if err = scan(`SELECT c.peer, c.session_id, c.called_at_ms, o.record, n.redeliveries FROM call_update_notifications n JOIN adapter_calls c ON c.peer = n.peer AND c.call_id = n.call_id JOIN outbound_calls o ON o.peer = n.peer AND o.call_id = n.call_id WHERE n.session_id = ? AND n.returned_at IS NULL AND n.seen_at IS NULL`, []any{session}, true); err != nil {
		return out, err
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].calledAt < items[j].calledAt })
	for _, it := range items {
		out = append(out, it.call)
	}
	return out, nil
}

// noteCallAccepted starts an agent call's fast status checks.
func (s *Store) noteCallAccepted(key string, now time.Time) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if s.tasks.accepted == nil {
		s.tasks.accepted = map[string]time.Time{}
	}
	for k, at := range s.tasks.accepted {
		if now.Sub(at) > callFastPolls {
			delete(s.tasks.accepted, k)
		}
	}
	if _, ok := s.tasks.accepted[key]; !ok {
		s.tasks.accepted[key] = now
	}
}

// scheduleCallPoll schedules an outbound call's next status query: every
// second for an agent's call in its first 60 seconds after acceptance, and
// otherwise as for tasks.
func (s *Store) scheduleCallPoll(key string, progressed bool) {
	s.tasks.mu.Lock()
	at, fast := s.tasks.accepted[key]
	if fast && time.Since(at) < callFastPolls {
		if s.tasks.poll == nil {
			s.tasks.poll = map[string]taskPoll{}
		}
		s.tasks.poll[key] = taskPoll{at: time.Now().Add(taskPollFirst), delay: taskPollFirst}
		s.tasks.mu.Unlock()
		return
	}
	if fast {
		delete(s.tasks.accepted, key)
	}
	s.tasks.mu.Unlock()
	s.schedulePoll(key, progressed)
}

// respondView answers with a call view, or an object holding one, without
// HTML escaping, so an inline result reads as its result text does.
func respondView(w http.ResponseWriter, value any, err error) {
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func adapterCallRoutes(mux *http.ServeMux, s *Store, auth func(*http.Request) AdapterAuth) {
	mux.HandleFunc("GET /adapter/v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		list, err := s.AdapterCapabilityList(r.Context(), auth(r))
		respond(w, http.StatusOK, list, err)
	})
	mux.HandleFunc("POST /adapter/v1/calls", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if !decode(w, r, &body, "call_id", "address", "operation", "input") {
			return
		}
		var req AdapterCall
		valid := len(body) == 4
		for field, target := range map[string]any{"call_id": &req.CallID, "address": &req.Address, "operation": &req.Operation} {
			if valid && json.Unmarshal(body[field], target) != nil {
				valid = false
			}
		}
		req.Input = body["input"]
		if !valid {
			respond(w, 0, nil, fmt.Errorf("%w: a call is exactly call_id, address, operation, and input", ErrInvalid))
			return
		}
		v, err := s.SubmitAgentCall(r.Context(), auth(r), req)
		respondView(w, v, err)
	})
	mux.HandleFunc("GET /adapter/v1/calls/{id}", func(w http.ResponseWriter, r *http.Request) {
		offset := int64(0)
		if given := r.URL.Query().Get("offset"); given != "" {
			n, err := strconv.ParseInt(given, 10, 64)
			if err != nil || n < 0 {
				respond(w, 0, nil, fmt.Errorf("%w: offset is a whole number of bytes", ErrInvalid))
				return
			}
			offset = n
		}
		v, err := s.AgentCallView(r.Context(), auth(r), r.PathValue("id"), offset)
		respondView(w, v, err)
	})
	mux.HandleFunc("POST /adapter/v1/calls/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		v, err := s.CancelAgentCall(r.Context(), auth(r), r.PathValue("id"))
		respondView(w, v, err)
	})
	mux.HandleFunc("POST /adapter/v1/call-updates/next", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		h, err := s.NextCallUpdate(r.Context(), auth(r))
		respondView(w, h, err)
	})
	mux.HandleFunc("POST /adapter/v1/call-updates/{id}/forwarded", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		n, err := s.CallUpdateForwarded(r.Context(), auth(r), r.PathValue("id"))
		respond(w, http.StatusOK, n, err)
	})
}
