package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Per-call approval (capabilities slice 3, item B): the owner can require
// that calls to selected operations of a capability wait until the person
// approves each one at a terminal on this host. The requirement lives only
// in the capability record; each call that needs approval gets one approval
// record, keyed like the call, and one notice for the capability's source
// agent.

const approvalSchema = `
CREATE TABLE call_approvals (sender TEXT NOT NULL, call_id TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, call_id), FOREIGN KEY(sender, call_id) REFERENCES received_calls(sender, call_id));
CREATE INDEX call_approvals_state ON call_approvals(state, expires_at);
CREATE TABLE approval_notices (id TEXT PRIMARY KEY, sender TEXT NOT NULL, call_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id), session_id TEXT REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, call_id));
PRAGMA user_version = 20;
`

// Approval states.
const (
	ApprovalPending   = "pending"
	ApprovalApproved  = "approved"
	ApprovalDenied    = "denied"
	ApprovalExpired   = "expired"
	ApprovalCancelled = "cancelled"
	// approvalNone is the approval state of a call without approval in a
	// held status request.
	approvalNone = "none"
)

// Approval requirement modes.
const (
	ApprovalModeNone     = "none"
	ApprovalModeChanging = "changing"
	ApprovalModeAll      = "all"
)

// Call errors of approval.
const (
	callApprovalDenied  = "approval_denied"
	callApprovalTimeout = "approval_timeout"
)

const (
	// maxPendingApprovals bounds the approvals pending per pending key.
	maxPendingApprovals = 20
	// approvalReasonMax bounds a denial reason, in bytes.
	approvalReasonMax = 1024
	// approvalPreviewBytes bounds the input preview before escaping.
	approvalPreviewBytes = 512
	// approvalRecent is how long all lists decided approvals.
	approvalRecent = 7 * 24 * time.Hour
)

func validApprovalState(state string) bool {
	switch state {
	case ApprovalPending, ApprovalApproved, ApprovalDenied, ApprovalExpired, ApprovalCancelled:
		return true
	}
	return false
}

// ApprovalOperations is a requirement's operations: none, changing, all,
// or a sorted list of operation names.
type ApprovalOperations struct {
	Mode string
	List []string
}

func (o ApprovalOperations) MarshalJSON() ([]byte, error) {
	if o.Mode == "" {
		return json.Marshal(o.List)
	}
	return json.Marshal(o.Mode)
}

func (o *ApprovalOperations) UnmarshalJSON(data []byte) error {
	var mode string
	if err := json.Unmarshal(data, &mode); err == nil {
		*o = ApprovalOperations{Mode: mode}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	*o = ApprovalOperations{List: list}
	if o.List == nil {
		o.List = []string{}
	}
	return nil
}

// String is the readable mode: none, changing, all, or the list joined
// with ','.
func (o ApprovalOperations) String() string {
	if o.Mode != "" {
		return o.Mode
	}
	return strings.Join(o.List, ",")
}

// ApprovalRequirement is the approval field of a capability record.
type ApprovalRequirement struct {
	Operations ApprovalOperations `json:"operations"`
	AgentSelf  bool               `json:"agent_self"`
}

// defaultApproval is the requirement of a record without one.
func defaultApproval() ApprovalRequirement {
	return ApprovalRequirement{Operations: ApprovalOperations{Mode: ApprovalModeNone}, AgentSelf: true}
}

// approvalBody is the approval object of a create or PUT request:
// operations, required, and an optional agent_self.
type approvalBody struct {
	Operations json.RawMessage
	AgentSelf  *bool
}

func (b *approvalBody) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return fmt.Errorf("%w: approval is an object with operations and an optional agent_self", ErrInvalid)
	}
	for field := range raw {
		if field != "operations" && field != "agent_self" {
			return fmt.Errorf("%w: approval has only operations and agent_self", ErrInvalid)
		}
	}
	ops, ok := raw["operations"]
	if !ok {
		return fmt.Errorf("%w: approval needs operations", ErrInvalid)
	}
	b.Operations = ops
	// A null agent_self reads as absent.
	if value, ok := raw["agent_self"]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		var self bool
		if err := json.Unmarshal(value, &self); err != nil {
			return fmt.Errorf("%w: agent_self is a boolean", ErrInvalid)
		}
		b.AgentSelf = &self
	}
	return nil
}

// parseApprovalOperations validates operations against a record's
// operations and resources: none, changing, all, or a non-empty list of its
// operations (read only with resources), stored sorted without duplicates.
func parseApprovalOperations(raw json.RawMessage, operations []string, resources bool) (ApprovalOperations, error) {
	invalid := fmt.Errorf("%w: approval operations are none, changing, all, or a non-empty list of the capability's operations", ErrInvalid)
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ApprovalOperations{}, invalid
	}
	if trimmed[0] == '"' {
		var mode string
		if json.Unmarshal(trimmed, &mode) != nil {
			return ApprovalOperations{}, invalid
		}
		switch mode {
		case ApprovalModeNone, ApprovalModeChanging, ApprovalModeAll:
			return ApprovalOperations{Mode: mode}, nil
		}
		return ApprovalOperations{}, invalid
	}
	if trimmed[0] != '[' {
		return ApprovalOperations{}, invalid
	}
	var list []string
	if json.Unmarshal(trimmed, &list) != nil || len(list) == 0 {
		return ApprovalOperations{}, invalid
	}
	out := []string{}
	for _, name := range list {
		known := slices.Contains(operations, name) || (name == membership.OperationRead && resources)
		if !known {
			return ApprovalOperations{}, fmt.Errorf("%w: %q is not an operation of the capability", ErrInvalid, name)
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return ApprovalOperations{List: out}, nil
}

// requirement reads the record's approval, defaulting to none.
func (c capabilityRecord) requirement() ApprovalRequirement {
	if c.Approval == nil {
		return defaultApproval()
	}
	return *c.Approval
}

// covers reports whether the requirement covers an operation, reading
// read_only from snap under changing.
func (r ApprovalRequirement) covers(op string, snap toolSnapshotState) bool {
	switch r.Operations.Mode {
	case ApprovalModeNone:
		return false
	case ApprovalModeAll:
		return true
	case ApprovalModeChanging:
		if op == membership.OperationRead {
			return false
		}
		t, ok := snapshotTool(snap, op)
		return !ok || !t.ReadOnly
	case "":
		return slices.Contains(r.Operations.List, op)
	}
	return false
}

// CallApproval is the approval object of a peer status record.
type CallApproval struct {
	State       string  `json:"state"`
	RequestedAt string  `json:"requested_at"`
	ExpiresAt   string  `json:"expires_at"`
	DecidedAt   *string `json:"decided_at"`
	Reason      *string `json:"reason"`
}

// ApprovalCaller is who made a call awaiting approval.
type ApprovalCaller struct {
	PersonID    *string `json:"person_id"`
	PersonLabel *string `json:"person_label"`
	HostID      string  `json:"host_id"`
	Via         string  `json:"via"`
}

// ApprovalRecord is the approval of one received call.
type ApprovalRecord struct {
	SenderHostID  string         `json:"sender_host_id"`
	CallID        string         `json:"call_id"`
	State         string         `json:"state"`
	Capability    string         `json:"capability"`
	Operation     string         `json:"operation"`
	ChangesThings bool           `json:"changes_things"`
	Caller        ApprovalCaller `json:"caller"`
	Origin        *Origin        `json:"origin"`
	InputSHA256   string         `json:"input_sha256"`
	RequestedAt   string         `json:"requested_at"`
	ExpiresAt     string         `json:"expires_at"`
	DecidedAt     *string        `json:"decided_at"`
	Reason        *string        `json:"reason"`
}

// approvalRow is call_approvals.record: the record and its pending key,
// which is not shown.
type approvalRow struct {
	ApprovalRecord
	PendingKey string `json:"pending_key"`
}

func (a ApprovalRecord) status() *CallApproval {
	return &CallApproval{State: a.State, RequestedAt: a.RequestedAt, ExpiresAt: a.ExpiresAt, DecidedAt: a.DecidedAt, Reason: a.Reason}
}

// callApprovalState is a status record's approval state, or none.
func callApprovalState(st CallStatus) string {
	if st.Approval == nil {
		return approvalNone
	}
	return st.Approval.State
}

// awaitingApproval reports a status that is queued with its approval
// pending.
func awaitingApproval(st *CallStatus) bool {
	return st != nil && st.State == CallQueued && st.Approval != nil && st.Approval.State == ApprovalPending
}

func readApproval(ctx context.Context, q dbQuerier, sender, id string) (approvalRow, error) {
	return readJSON[approvalRow](q.QueryRowContext(ctx, `SELECT record FROM call_approvals WHERE sender = ? AND call_id = ?`, sender, id))
}

func writeApproval(ctx context.Context, tx *sql.Tx, a approvalRow) error {
	return putJSON(ctx, tx, `UPDATE call_approvals SET record = ?, state = ? WHERE sender = ? AND call_id = ?`, a, a.State, a.SenderHostID, a.CallID)
}

// leavePending moves a pending approval to state, sets decided_at, keeps the
// call's status record in step, and voids its notice if never claimed. The
// caller writes the call record.
func leavePending(ctx context.Context, tx *sql.Tx, a *approvalRow, c *receivedCall, state string, reason *string, now time.Time) error {
	at := timestamp(now)
	a.State, a.DecidedAt, a.Reason = state, &at, reason
	if err := writeApproval(ctx, tx, *a); err != nil {
		return err
	}
	c.Approval = a.status()
	_, err := tx.ExecContext(ctx, `UPDATE approval_notices SET record = json_set(record, '$.state', 'void') WHERE sender = ? AND call_id = ? AND session_id IS NULL`, a.SenderHostID, a.CallID)
	return err
}

// approvalNeed decides at acceptance whether a call needs approval: its
// operation is covered by the capability's requirement and it is not
// exempt (a source; self without origin; self with origin when agent_self
// is false). It also returns the capability record and changes_things.
func approvalNeed(ctx context.Context, q dbQuerier, r CallRequest) (bool, capabilityRecord, bool, error) {
	if _, _, isSource := r.sourceCall(); isSource {
		return false, capabilityRecord{}, false, nil
	}
	c, err := readCapability(ctx, q, r.Capability)
	if err != nil {
		return false, c, false, err
	}
	req := c.requirement()
	if r.Self != nil && (r.Origin == nil || !req.AgentSelf) {
		return false, c, false, nil
	}
	snap, _, err := capabilitySnapshot(ctx, q, c)
	if err != nil {
		return false, c, false, err
	}
	changes := false
	if r.Operation != membership.OperationRead {
		t, ok := snapshotTool(snap, r.Operation)
		changes = !ok || !t.ReadOnly
	}
	return req.covers(r.Operation, snap), c, changes, nil
}

// approvalCaller is the sender's bound person in the cited network, with
// its binding label, and the pending key: the budget key under policy, the
// caller alone under self.
func approvalCaller(ctx context.Context, q dbQuerier, sender string, r CallRequest, budgetKey string) (ApprovalCaller, string, error) {
	caller := ApprovalCaller{HostID: sender, Via: AuthorizationPolicy}
	network := ""
	if r.Self != nil {
		caller.Via, network = AuthorizationSelf, r.Self.NetworkID
	} else if r.Policy != nil {
		network = r.Policy.NetworkID
	}
	member, err := readJSON[NetworkMember](q.QueryRowContext(ctx, `SELECT record FROM network_members WHERE network_id = ? AND host_id = ?`, network, sender))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return caller, "", err
	}
	if err == nil && member.PersonID != nil {
		person := *member.PersonID
		caller.PersonID = &person
		if member.PersonMember != nil {
			label := *member.PersonMember
			caller.PersonLabel = &label
		}
	}
	if r.Self == nil {
		return caller, budgetKey, nil
	}
	who := sender
	if caller.PersonID != nil {
		who = *caller.PersonID
	}
	return caller, "self:" + who, nil
}

var errTooManyPending = &codedError{status: http.StatusTooManyRequests, code: "limit", limit: "max_pending_approvals", message: "too many calls are waiting for approval"}

// requestApproval checks the pending limit and persists a new call's
// approval, its notice, and the call.approval_requested activity, in the
// acceptance transaction. It returns the status record's approval.
func requestApproval(ctx context.Context, tx *sql.Tx, sender string, r CallRequest, c capabilityRecord, changes bool, budgetKey, inputSHA string, now time.Time) (*CallApproval, error) {
	caller, key, err := approvalCaller(ctx, tx, sender, r, budgetKey)
	if err != nil {
		return nil, err
	}
	var pending int64
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM call_approvals WHERE state = 'pending' AND json_extract(record, '$.pending_key') = ?`, key).Scan(&pending); err != nil {
		return nil, err
	}
	if pending >= maxPendingApprovals {
		return nil, errTooManyPending
	}
	at := timestamp(now)
	a := approvalRow{ApprovalRecord: ApprovalRecord{SenderHostID: sender, CallID: r.CallID, State: ApprovalPending, Capability: r.Capability, Operation: r.Operation, ChangesThings: changes, Caller: caller, Origin: r.Origin, InputSHA256: inputSHA, RequestedAt: at, ExpiresAt: r.Deadline}, PendingKey: key}
	if err = putJSON(ctx, tx, `INSERT INTO call_approvals (record, sender, call_id, state, expires_at) VALUES (?, ?, ?, ?, ?)`, a, sender, r.CallID, a.State, a.ExpiresAt); err != nil {
		return nil, err
	}
	// A built-in source has no source agent, so there is no session to
	// notify: the approval waits at the owner's CLI only.
	if c.AgentID != builtinAgent {
		id, err := newID("notice")
		if err != nil {
			return nil, err
		}
		n := noticeRecord{ApprovalNotice: ApprovalNotice{ID: id, SenderHostID: sender, CallID: r.CallID, AgentID: c.AgentID, State: "unknown", CreatedAt: at}}
		if err = putJSON(ctx, tx, `INSERT INTO approval_notices (record, id, sender, call_id, agent_id) VALUES (?, ?, ?, ?, ?)`, n, id, sender, r.CallID, c.AgentID); err != nil {
			return nil, err
		}
	}
	if err = appendEvent(ctx, tx, "call.approval_requested", callSubject(sender, r.CallID), at); err != nil {
		return nil, err
	}
	return a.status(), nil
}

// errNoLongerPending is the 409 of a decision on an approval no longer
// pending, with the record.
func errNoLongerPending(a ApprovalRecord) error {
	return &codedError{status: http.StatusConflict, code: "conflict", message: "the call is no longer waiting for approval", approval: a}
}

// DecideApproval approves or denies a pending approval, with its call
// change and activities, in one transaction.
func (s *Store) DecideApproval(ctx context.Context, sender, id string, approve bool, reason *string) (ApprovalRecord, error) {
	if reason != nil && *reason == "" {
		reason = nil
	}
	if reason != nil && len(*reason) > approvalReasonMax {
		return ApprovalRecord{}, fmt.Errorf("%w: a reason is at most %d bytes", ErrInvalid, approvalReasonMax)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalRecord{}, err
	}
	defer tx.Rollback()
	now := time.Now()
	// An approval past its deadline expires first, and is then no longer
	// pending.
	if err = expireCalls(ctx, tx, now); err != nil {
		return ApprovalRecord{}, err
	}
	a, err := readApproval(ctx, tx, sender, id)
	if errors.Is(err, ErrNotFound) {
		return ApprovalRecord{}, fmt.Errorf("%w: no approval %s/%s", ErrNotFound, sender, id)
	}
	if err != nil {
		return ApprovalRecord{}, err
	}
	if a.State != ApprovalPending {
		return ApprovalRecord{}, errNoLongerPending(a.ApprovalRecord)
	}
	c, err := readReceivedCall(ctx, tx, sender, id)
	if err != nil {
		return ApprovalRecord{}, err
	}
	subject, at := callSubject(sender, id), timestamp(now)
	if approve {
		if err = leavePending(ctx, tx, &a, &c, ApprovalApproved, nil, now); err != nil {
			return ApprovalRecord{}, err
		}
		if err = writeReceivedCall(ctx, tx, c); err != nil {
			return ApprovalRecord{}, err
		}
		err = appendEvent(ctx, tx, "call.approved", subject, at)
	} else {
		if err = leavePending(ctx, tx, &a, &c, ApprovalDenied, reason, now); err != nil {
			return ApprovalRecord{}, err
		}
		if err = appendEvent(ctx, tx, "call.denied", subject, at); err != nil {
			return ApprovalRecord{}, err
		}
		failure := callApprovalDenied
		err = finishCall(ctx, tx, &c, CallRejected, &failure, now)
	}
	if err != nil {
		return ApprovalRecord{}, err
	}
	if err = tx.Commit(); err != nil {
		return ApprovalRecord{}, err
	}
	s.wakeCalls()
	return a.ApprovalRecord, nil
}

// ApprovalItem is an approval with its input preview, for approvals.
type ApprovalItem struct {
	ApprovalRecord
	InputPreview *string `json:"input_preview"`
	InputBytes   *int64  `json:"input_bytes"`
}

// ApprovalDetail is one approval with its input, or null once deleted.
type ApprovalDetail struct {
	ApprovalItem
	Input json.RawMessage `json:"input"`
}

func (d ApprovalDetail) MarshalJSON() ([]byte, error) {
	item, err := json.Marshal(d.ApprovalItem)
	if err != nil {
		return nil, err
	}
	input := d.Input
	if input == nil {
		input = json.RawMessage("null")
	}
	return append(append(item[:len(item)-1], []byte(`,"input":`)...), append(input, '}')...), nil
}

// approvalInputText is the input encoded as the call view encodes a
// result.
func approvalInputText(input json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
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

// approvalPreview is the longest prefix of text of at most 512 bytes that
// ends on a character boundary, with U+007F and U+0080 to U+009F written
// as \u and four lowercase hex digits.
func approvalPreview(text []byte) string {
	end := min(len(text), approvalPreviewBytes)
	for end < len(text) && end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	var b strings.Builder
	for _, r := range string(text[:end]) {
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// approvalDetail adds the input preview and input of a received call.
func approvalDetail(ctx context.Context, q dbQuerier, a ApprovalRecord) (ApprovalDetail, error) {
	d := ApprovalDetail{ApprovalItem: ApprovalItem{ApprovalRecord: a}}
	var request string
	if err := q.QueryRowContext(ctx, `SELECT request FROM received_calls WHERE sender = ? AND call_id = ?`, a.SenderHostID, a.CallID).Scan(&request); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return d, nil
		}
		return d, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(request), &fields); err != nil {
		return d, err
	}
	raw, ok := fields["input"]
	if !ok || string(raw) == "null" {
		return d, nil
	}
	text, err := approvalInputText(raw)
	if err != nil {
		return d, nil
	}
	size := int64(len(text))
	preview := approvalPreview(text)
	d.InputBytes, d.InputPreview, d.Input = &size, &preview, raw
	return d, nil
}

// Approvals lists pending approvals, or with all, also those decided in
// the last 7 days, oldest first by requested_at, then sender, then call ID.
func (s *Store) Approvals(ctx context.Context, state string) ([]ApprovalItem, error) {
	if state == "" {
		state = "pending"
	}
	if state != "pending" && state != "all" {
		return nil, fmt.Errorf("%w: state is pending or all", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now()
	if err = expireCalls(ctx, tx, now); err != nil {
		return nil, err
	}
	query := `SELECT record FROM call_approvals WHERE state = 'pending'`
	if state == "all" {
		query = `SELECT record FROM call_approvals`
	}
	rows, err := records[approvalRow](ctx, tx, query)
	if err != nil {
		return nil, err
	}
	var kept []ApprovalRecord
	for _, a := range rows {
		if a.State != ApprovalPending {
			decided, err := parseTime(deref(a.DecidedAt))
			if err != nil || now.Sub(decided) > approvalRecent {
				continue
			}
		}
		kept = append(kept, a.ApprovalRecord)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		ta, _ := parseTime(a.RequestedAt)
		tb, _ := parseTime(b.RequestedAt)
		if !ta.Equal(tb) {
			return ta.Before(tb)
		}
		if a.SenderHostID != b.SenderHostID {
			return a.SenderHostID < b.SenderHostID
		}
		return a.CallID < b.CallID
	})
	out := []ApprovalItem{}
	for _, a := range kept {
		d, err := approvalDetail(ctx, tx, a)
		if err != nil {
			return nil, err
		}
		out = append(out, d.ApprovalItem)
	}
	return out, tx.Commit()
}

// Approval is one approval in any state, with its input.
func (s *Store) Approval(ctx context.Context, sender, id string) (ApprovalDetail, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalDetail{}, err
	}
	defer tx.Rollback()
	if err = expireCalls(ctx, tx, time.Now()); err != nil {
		return ApprovalDetail{}, err
	}
	a, err := readApproval(ctx, tx, sender, id)
	if errors.Is(err, ErrNotFound) {
		return ApprovalDetail{}, fmt.Errorf("%w: no approval %s/%s", ErrNotFound, sender, id)
	}
	if err != nil {
		return ApprovalDetail{}, err
	}
	d, err := approvalDetail(ctx, tx, a.ApprovalRecord)
	if err != nil {
		return d, err
	}
	return d, tx.Commit()
}

// ResolveApproval resolves a bare call ID: the one approval with it, 409
// ambiguous with the candidates when several senders used it, or 404.
func (s *Store) ResolveApproval(ctx context.Context, id string) (ApprovalDetail, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sender FROM call_approvals WHERE call_id = ? ORDER BY sender`, id)
	if err != nil {
		return ApprovalDetail{}, err
	}
	var senders []string
	for rows.Next() {
		var sender string
		if err = rows.Scan(&sender); err != nil {
			rows.Close()
			return ApprovalDetail{}, err
		}
		senders = append(senders, sender)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ApprovalDetail{}, err
	}
	switch len(senders) {
	case 0:
		return ApprovalDetail{}, fmt.Errorf("%w: no approval for call %s", ErrNotFound, id)
	case 1:
		return s.Approval(ctx, senders[0], id)
	}
	candidates := make([]string, len(senders))
	for i, sender := range senders {
		candidates[i] = sender + "/" + id
	}
	sort.Strings(candidates)
	return ApprovalDetail{}, &codedError{status: http.StatusConflict, code: "ambiguous", message: fmt.Sprintf("more than one sender used call ID %s: %s; use SENDER_HOST_ID/CALL_ID", id, strings.Join(candidates, ", ")), candidates: candidates}
}

// approvalsPending counts pending approvals, and reports the oldest.
func approvalsPending(ctx context.Context, q dbQuerier) (int64, *ApprovalRecord, error) {
	list, err := records[approvalRow](ctx, q, `SELECT record FROM call_approvals WHERE state = 'pending'`)
	if err != nil {
		return 0, nil, err
	}
	var oldest *ApprovalRecord
	var oldestAt time.Time
	for i := range list {
		at, _ := parseTime(list[i].RequestedAt)
		if oldest == nil || at.Before(oldestAt) {
			oldest, oldestAt = &list[i].ApprovalRecord, at
		}
	}
	return int64(len(list)), oldest, nil
}

// approvalAttention adds attention item 18, call_approval_pending, while an
// approval is pending.
func approvalAttention(ctx context.Context, tx *sql.Tx, st *CapabilitiesStatus, attend func(kind, subject, detail, command string)) error {
	n, oldest, err := approvalsPending(ctx, tx)
	if err != nil {
		return err
	}
	st.ApprovalsPending = n
	if n == 0 || oldest == nil {
		return nil
	}
	caller := oldest.Caller.HostID
	if oldest.Caller.PersonLabel != nil {
		caller = *oldest.Caller.PersonLabel
	}
	detail := fmt.Sprintf("the oldest is a call to %s (%s) from %s, waiting until %s", oldest.Capability, oldest.Operation, caller, oldest.ExpiresAt)
	attend("call_approval_pending", fmt.Sprint(n), detail, "peerspan approvals")
	return nil
}

// ApprovalNotice is a notice of an approval for the capability's source
// agent.
type ApprovalNotice struct {
	ID           string  `json:"id"`
	SenderHostID string  `json:"sender_host_id"`
	CallID       string  `json:"call_id"`
	AgentID      string  `json:"agent_id"`
	SessionID    *string `json:"session_id"`
	State        string  `json:"state"`
	CreatedAt    string  `json:"created_at"`
}

// noticeRecord is approval_notices.record: the notice and the credential
// that claimed it.
type noticeRecord struct {
	ApprovalNotice
	AdapterID string `json:"adapter_id,omitempty"`
}

// NoticeHandoff is a claimed notice with its approval.
type NoticeHandoff struct {
	Notice   ApprovalNotice `json:"notice"`
	Approval ApprovalRecord `json:"approval"`
}

// NextApprovalNotice claims the oldest notice for this session's agent
// that no session holds and whose approval is still pending. It needs the
// credential, lease, and a verified channel, not calls.
func (s *Store) NextApprovalNotice(ctx context.Context, auth AdapterAuth) (*NoticeHandoff, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return nil, err
	}
	if err = requireVerified(ctx, tx, a.ID); err != nil {
		return nil, err
	}
	if err = expireCalls(ctx, tx, time.Now()); err != nil {
		return nil, err
	}
	n, err := readJSON[noticeRecord](tx.QueryRowContext(ctx, `SELECT n.record FROM approval_notices n JOIN call_approvals c ON c.sender = n.sender AND c.call_id = n.call_id WHERE n.agent_id = ? AND n.session_id IS NULL AND c.state = 'pending' AND json_extract(n.record, '$.state') != 'void' ORDER BY n.rowid, n.id LIMIT 1`, ss.AgentID))
	if errors.Is(err, ErrNotFound) {
		return nil, tx.Commit()
	}
	if err != nil {
		return nil, err
	}
	session := ss.ID
	n.SessionID, n.AdapterID = &session, a.ID
	if err = putJSON(ctx, tx, `UPDATE approval_notices SET record = ?, session_id = ? WHERE id = ?`, n, ss.ID, n.ID); err != nil {
		return nil, err
	}
	approval, err := readApproval(ctx, tx, n.SenderHostID, n.CallID)
	if err != nil {
		return nil, err
	}
	h := &NoticeHandoff{Notice: n.ApprovalNotice, Approval: approval.ApprovalRecord}
	return h, tx.Commit()
}

// ApprovalNoticeForwarded marks a notice this credential claimed as
// forwarded; another credential's, or an unknown ID, is not found.
func (s *Store) ApprovalNoticeForwarded(ctx context.Context, auth AdapterAuth, id string) (ApprovalNotice, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalNotice{}, err
	}
	defer tx.Rollback()
	a, _, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return ApprovalNotice{}, err
	}
	n, err := readJSON[noticeRecord](tx.QueryRowContext(ctx, `SELECT record FROM approval_notices WHERE id = ?`, id))
	if err == nil && n.AdapterID != a.ID {
		err = ErrNotFound
	}
	if errors.Is(err, ErrNotFound) {
		return ApprovalNotice{}, fmt.Errorf("%w: no notice %s for this credential", ErrNotFound, id)
	}
	if err != nil || n.State == "forwarded" {
		return n.ApprovalNotice, err
	}
	n.State = "forwarded"
	if err = putJSON(ctx, tx, `UPDATE approval_notices SET record = ? WHERE id = ?`, n, n.ID); err != nil {
		return n.ApprovalNotice, err
	}
	return n.ApprovalNotice, tx.Commit()
}

func adapterApprovalRoutes(mux *http.ServeMux, s *Store, auth func(*http.Request) AdapterAuth) {
	mux.HandleFunc("POST /adapter/v1/approval-notices/next", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		h, err := s.NextApprovalNotice(r.Context(), auth(r))
		respond(w, http.StatusOK, h, err)
	})
	mux.HandleFunc("POST /adapter/v1/approval-notices/{id}/forwarded", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		n, err := s.ApprovalNoticeForwarded(r.Context(), auth(r), r.PathValue("id"))
		respond(w, http.StatusOK, n, err)
	})
}

// SetApproval is PUT /v1/capabilities/{name}/approval: it replaces the
// requirement, keeping agent_self when absent. It signs nothing.
func (s *Store) SetApproval(ctx context.Context, name string, body approvalBody) (CapabilityWithRecipients, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CapabilityWithRecipients{}, err
	}
	defer tx.Rollback()
	c, err := readCapability(ctx, tx, name)
	if errors.Is(err, ErrNotFound) {
		return CapabilityWithRecipients{}, fmt.Errorf("%w: no capability %s on this host", ErrNotFound, name)
	}
	if err != nil {
		return CapabilityWithRecipients{}, err
	}
	ops, err := parseApprovalOperations(body.Operations, c.Operations, c.Resources.Set)
	if err != nil {
		return CapabilityWithRecipients{}, err
	}
	req := c.requirement()
	req.Operations = ops
	if body.AgentSelf != nil {
		req.AgentSelf = *body.AgentSelf
	}
	c.Approval = &req
	if err = putJSON(ctx, tx, `UPDATE capabilities SET record = ? WHERE name = ?`, c, c.Name); err != nil {
		return CapabilityWithRecipients{}, err
	}
	if err = appendEvent(ctx, tx, "capability.approval_changed", c.Name, timestamp(time.Now())); err != nil {
		return CapabilityWithRecipients{}, err
	}
	if err = tx.Commit(); err != nil {
		return CapabilityWithRecipients{}, err
	}
	return s.CapabilityOf(ctx, name, false)
}

func localApprovalRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("PUT /v1/capabilities/{name}/approval", func(w http.ResponseWriter, r *http.Request) {
		var body approvalBody
		if !decode(w, r, &body, "operations", "agent_self?") {
			return
		}
		c, err := store.SetApproval(r.Context(), r.PathValue("name"), body)
		respond(w, http.StatusOK, c, err)
	})
	mux.HandleFunc("GET /v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		state := "pending"
		if values, ok := r.URL.Query()["state"]; ok {
			if len(values) != 1 {
				respond(w, 0, nil, fmt.Errorf("%w: state is pending or all", ErrInvalid))
				return
			}
			state = values[0]
			if state == "" {
				state = "invalid"
			}
		}
		list, err := store.Approvals(r.Context(), state)
		respond(w, http.StatusOK, map[string]any{"approvals": list}, err)
	})
	mux.HandleFunc("GET /v1/approvals/{call_id}", func(w http.ResponseWriter, r *http.Request) {
		d, err := store.ResolveApproval(r.Context(), r.PathValue("call_id"))
		respond(w, http.StatusOK, d, err)
	})
	mux.HandleFunc("GET /v1/approvals/{sender}/{call_id}", func(w http.ResponseWriter, r *http.Request) {
		d, err := store.Approval(r.Context(), r.PathValue("sender"), r.PathValue("call_id"))
		respond(w, http.StatusOK, d, err)
	})
	mux.HandleFunc("POST /v1/approvals/{sender}/{call_id}/approve", func(w http.ResponseWriter, r *http.Request) {
		if !decode(w, r, &struct{}{}) {
			return
		}
		a, err := store.DecideApproval(r.Context(), r.PathValue("sender"), r.PathValue("call_id"), true, nil)
		respond(w, http.StatusOK, a, err)
	})
	mux.HandleFunc("POST /v1/approvals/{sender}/{call_id}/deny", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Reason *string `json:"reason"`
		}
		if !decode(w, r, &body, "reason?") {
			return
		}
		a, err := store.DecideApproval(r.Context(), r.PathValue("sender"), r.PathValue("call_id"), false, body.Reason)
		respond(w, http.StatusOK, a, err)
	})
}
