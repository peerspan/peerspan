package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Seen tracking, redelivery, adoption, and pending work (milestone 9,
// slice 2). Every handed-off item records when the session holding it
// reported it seen. When an authorization ends, the items it was forwarded
// but never saw go back to the agent's queue, and the agent's next verified
// session claims them again; tasks still running are adopted the same way.

// The v15 schema adds the seen, return, and redelivery columns. Columns
// already present (a state whose version was lowered) are kept, so the
// result is the same schema either way. Existing rows are marked seen at the
// migration time, so nothing from before the upgrade is redelivered.
var liveDeliveryColumns = []struct {
	table   string
	columns []string
	seen    []string
}{
	{"deliveries", []string{"seen_at TEXT", "redeliveries INTEGER NOT NULL DEFAULT 0", "returned_at TEXT"}, []string{"seen_at"}},
	{"task_update_notifications", []string{"seen_at TEXT", "redeliveries INTEGER NOT NULL DEFAULT 0", "returned_at TEXT"}, []string{"seen_at"}},
	{"task_deliveries", []string{"seen_at TEXT", "redeliveries INTEGER NOT NULL DEFAULT 0", "returned_at TEXT", "cancel_seen_at TEXT", "adopted_at TEXT"}, []string{"seen_at", "cancel_seen_at"}},
	{"adapter_outbound", []string{"reply_seen_at TEXT", "reply_redeliveries INTEGER NOT NULL DEFAULT 0", "reply_returned_at TEXT"}, []string{"reply_seen_at"}},
}

func migrateLiveDelivery(ctx context.Context, tx *sql.Tx) error {
	now := timestamp(time.Now())
	for _, t := range liveDeliveryColumns {
		rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info('`+t.table+`')`)
		if err != nil {
			return err
		}
		present := map[string]bool{}
		for rows.Next() {
			var name string
			if err = rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			present[name] = true
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		for _, column := range t.columns {
			name, _, _ := strings.Cut(column, " ")
			if present[name] {
				continue
			}
			if _, err = tx.ExecContext(ctx, `ALTER TABLE `+t.table+` ADD COLUMN `+column); err != nil {
				return err
			}
		}
		for _, column := range t.seen {
			if _, err = tx.ExecContext(ctx, `UPDATE `+t.table+` SET `+column+` = ?`, now); err != nil {
				return err
			}
		}
	}
	_, err := tx.ExecContext(ctx, `PRAGMA user_version = 15`)
	return err
}

// redeliveryLimit is how many times an item is claimed again after a return.
const redeliveryLimit = 3

// taskNeverSeen is the error of a queued task past the redelivery limit.
const taskNeverSeen = "session never saw the task"

// previewRunes is the length of a pending work preview, in characters.
const previewRunes = 200

// liveReturns remembers the ended authorizations whose items were already
// returned. An ended authorization never holds new items, so each is
// processed once per daemon run.
type liveReturns struct {
	mu   sync.Mutex
	done map[string]bool
}

// endedAdapters lists the agent's authorizations that ended: replaced or
// revoked, expired, or detached without recovery.
func endedAdapters(ctx context.Context, q queryer, agent string, now time.Time) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT c.record, ss.state, x.recoverable FROM adapter_credentials c JOIN sessions ss ON ss.id = c.session_id JOIN adapter_connections x ON x.adapter_id = c.id WHERE ss.agent_id = ? ORDER BY c.id`, agent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ended := []string{}
	for rows.Next() {
		var record, state string
		var recoverable bool
		if err = rows.Scan(&record, &state, &recoverable); err != nil {
			return nil, err
		}
		var a Adapter
		if err = json.Unmarshal([]byte(record), &a); err != nil {
			return nil, err
		}
		exp, err := parseTime(a.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if a.RevokedAt != nil || !exp.After(now) || (state == SessionDetached && !recoverable) {
			ended = append(ended, a.ID)
		}
	}
	return ended, rows.Err()
}

func jsonList(ids []string) string {
	data, _ := json.Marshal(ids)
	return string(data)
}

// verifiedAuthority is the adapter's authority when it holds the lease and
// its channel is verified.
func verifiedAuthority(ctx context.Context, tx *sql.Tx, auth AdapterAuth) (Adapter, Session, bool, error) {
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return a, ss, false, err
	}
	var at sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT channel_verified_at FROM adapter_connections WHERE adapter_id = ?`, a.ID).Scan(&at); err != nil {
		return a, ss, false, err
	}
	return a, ss, at.Valid, nil
}

// returnEnded returns the unseen items of the agent's ended authorizations
// when a verified session of the agent claims work or lists its pending
// work. It runs in its own transaction before the claim; authority errors
// are left to the claim to report.
func (s *Store) returnEnded(ctx context.Context, auth AdapterAuth) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, ss, verified, err := verifiedAuthority(ctx, tx, auth)
	if err != nil || !verified {
		return nil
	}
	now := time.Now()
	ended, err := endedAdapters(ctx, tx, ss.AgentID, now)
	if err != nil {
		return err
	}
	s.returns.mu.Lock()
	todo := []string{}
	for _, id := range ended {
		if !s.returns.done[id] {
			todo = append(todo, id)
		}
	}
	s.returns.mu.Unlock()
	if len(todo) == 0 {
		return nil
	}
	if err = expireTasks(ctx, tx, now); err != nil {
		return err
	}
	if err = returnItems(ctx, tx, todo, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.returns.mu.Lock()
	if s.returns.done == nil {
		s.returns.done = map[string]bool{}
	}
	for _, id := range todo {
		s.returns.done[id] = true
	}
	s.returns.mu.Unlock()
	return nil
}

// returnItems returns every unseen item the given ended authorizations hold.
// A message past the redelivery limit is blocked, and a queued task past it
// fails; a reply or task update past it stays unseen and is not offered.
func returnItems(ctx context.Context, tx *sql.Tx, ended []string, now time.Time) error {
	at := timestamp(now)
	list := jsonList(ended)
	// Inbound deliveries not answered, blocked, or seen.
	type heldDelivery struct {
		delivery     Delivery
		deadline     string
		redeliveries int64
	}
	var deliveries []heldDelivery
	rows, err := tx.QueryContext(ctx, `SELECT d.record, json_extract(m.request, '$.deadline'), d.redeliveries FROM deliveries d JOIN received_messages m ON m.sender = d.sender AND m.request_id = d.request_id WHERE json_extract(d.record, '$.adapter_id') IN (SELECT value FROM json_each(?)) AND d.returned_at IS NULL AND d.seen_at IS NULL AND json_extract(d.record, '$.state') IN ('unknown', 'forwarded') ORDER BY d.rowid`, list)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h heldDelivery
		var record string
		var deadline sql.NullString
		if err = rows.Scan(&record, &deadline, &h.redeliveries); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(record), &h.delivery); err != nil {
			break
		}
		h.deadline = deadline.String
		deliveries = append(deliveries, h)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, h := range deliveries {
		// A message past its deadline, like a queued one at handoff, or past
		// the limit (its fourth holder ended without seeing it) is blocked.
		deadline, e := parseTime(h.deadline)
		if e != nil || !deadline.After(now) || h.redeliveries >= redeliveryLimit {
			d := h.delivery
			d.State, d.UpdatedAt = "blocked", at
			if err = updateDelivery(ctx, tx, d, "message.blocked"); err != nil {
				return err
			}
			continue
		}
		if _, err = tx.ExecContext(ctx, `UPDATE deliveries SET returned_at = ? WHERE id = ?`, at, h.delivery.ID); err != nil {
			return err
		}
	}

	// Tasks: running ones return for adoption; queued unseen ones return
	// for redelivery, or fail past the limit.
	type heldTask struct {
		id           string
		status       TaskStatus
		deadline     string
		redeliveries int64
		seen         bool
	}
	var tasks []heldTask
	rows, err = tx.QueryContext(ctx, `SELECT d.id, t.record, json_extract(t.request, '$.deadline'), d.redeliveries, d.seen_at IS NOT NULL FROM task_deliveries d JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE json_extract(d.record, '$.adapter_id') IN (SELECT value FROM json_each(?)) AND d.returned_at IS NULL AND json_extract(t.record, '$.state') IN ('queued', 'running') ORDER BY d.rowid`, list)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h heldTask
		var record string
		var deadline sql.NullString
		if err = rows.Scan(&h.id, &record, &deadline, &h.redeliveries, &h.seen); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(record), &h.status); err != nil {
			break
		}
		h.deadline = deadline.String
		tasks = append(tasks, h)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, h := range tasks {
		if h.status.State == TaskQueued {
			if h.seen {
				continue
			}
			if deadline, e := parseTime(h.deadline); e != nil || !deadline.After(now) {
				continue
			}
			if h.redeliveries >= redeliveryLimit {
				reason := taskNeverSeen
				st := h.status
				if err = appendTaskEvent(ctx, tx, &st, "failed", TaskFailed, &reason, nil, "task.failed", now); err != nil {
					return err
				}
				continue
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE task_deliveries SET returned_at = ? WHERE id = ?`, at, h.id); err != nil {
			return err
		}
	}

	// Task update notifications and reply notifications have no deadline.
	if _, err = tx.ExecContext(ctx, `UPDATE task_update_notifications SET returned_at = ? WHERE json_extract(record, '$.adapter_id') IN (SELECT value FROM json_each(?)) AND returned_at IS NULL AND seen_at IS NULL AND redeliveries < ?`, at, list, redeliveryLimit); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_outbound SET reply_returned_at = ? WHERE reply_delivery IS NOT NULL AND json_extract(reply_delivery, '$.adapter_id') IN (SELECT value FROM json_each(?)) AND reply_returned_at IS NULL AND reply_seen_at IS NULL AND reply_redeliveries < ?`, at, list, redeliveryLimit); err != nil {
		return err
	}
	// Call updates claimed and unseen return; one never claimed goes to the
	// agent's next verified session as a late arrival.
	_, err = tx.ExecContext(ctx, `UPDATE call_update_notifications SET returned_at = ? WHERE json_extract(record, '$.adapter_id') IN (SELECT value FROM json_each(?)) AND json_extract(record, '$.claimed_at') IS NOT NULL AND returned_at IS NULL AND seen_at IS NULL AND redeliveries < ?`, at, list, redeliveryLimit)
	return err
}

// latestProgress is the message of a received task's latest progress event.
func latestProgress(ctx context.Context, tx *sql.Tx, sender, id string) (*string, error) {
	var message sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT json_extract(record, '$.message') FROM task_events WHERE sender = ? AND task_id = ? AND json_extract(record, '$.kind') = 'progress' ORDER BY sequence DESC LIMIT 1`, sender, id).Scan(&message)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !message.Valid) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &message.String, nil
}

// chainOriginatorPerson is the person bound to a task chain's originator in
// the chain's network, or nil.
func chainOriginatorPerson(ctx context.Context, tx *sql.Tx, r TaskRequest) (*string, error) {
	if len(r.Delegation) == 0 {
		return nil, nil
	}
	members, err := networkMembers(ctx, tx, r.Delegation[0].NetworkID)
	if err != nil {
		return nil, err
	}
	if m, ok := members[r.Delegation[0].IssuerHostID]; ok && m.PersonID != nil {
		person := *m.PersonID
		return &person, nil
	}
	return nil, nil
}

var seenIDPattern = regexp.MustCompile(`^(delivery|request|task|call)_[0-9a-f]{32}$`)

// MarkSeen records items this session holds as seen, by delivery, request,
// task, or call ID, and returns the IDs newly seen. An ID the session does
// not hold fails the whole call as not found.
func (s *Store) MarkSeen(ctx context.Context, auth AdapterAuth, ids []string) ([]string, error) {
	if len(ids) < 1 || len(ids) > 100 {
		return nil, ErrInvalid
	}
	for _, id := range ids {
		if !seenIDPattern.MatchString(id) {
			return nil, ErrInvalid
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return nil, err
	}
	at := timestamp(time.Now())
	seen := []string{}
	done := map[string]bool{}
	for _, id := range ids {
		if done[id] {
			continue
		}
		done[id] = true
		held, changed, err := markSeen(ctx, tx, a.ID, ss.ID, id, at)
		if err != nil {
			return nil, err
		}
		if !held {
			return nil, ErrNotFound
		}
		if changed {
			seen = append(seen, id)
		}
	}
	return seen, tx.Commit()
}

// markSeen marks one ID seen for the holding authorization. It reports
// whether the authorization holds the ID and whether anything changed.
func markSeen(ctx context.Context, tx *sql.Tx, adapterID, sessionID, id, at string) (bool, bool, error) {
	count := func(query string, args ...any) (int64, error) {
		var n int64
		err := tx.QueryRowContext(ctx, query, args...).Scan(&n)
		return n, err
	}
	exec := func(query string, args ...any) (int64, error) {
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return 0, err
		}
		return result.RowsAffected()
	}
	switch {
	case strings.HasPrefix(id, "delivery_"):
		held, err := count(`SELECT COUNT(*) FROM deliveries WHERE id = ? AND json_extract(record, '$.adapter_id') = ? AND session_id = ? AND returned_at IS NULL AND json_extract(record, '$.state') != 'blocked'`, id, adapterID, sessionID)
		if err != nil {
			return false, false, err
		}
		if held > 0 {
			changed, err := exec(`UPDATE deliveries SET seen_at = ? WHERE id = ? AND seen_at IS NULL`, at, id)
			return true, changed > 0, err
		}
		// A task's delivery ID stands for the task.
		var task string
		err = tx.QueryRowContext(ctx, `SELECT task_id FROM task_deliveries WHERE id = ? AND json_extract(record, '$.adapter_id') = ? AND session_id = ? AND returned_at IS NULL`, id, adapterID, sessionID).Scan(&task)
		if errors.Is(err, sql.ErrNoRows) {
			return false, false, nil
		}
		if err != nil {
			return false, false, err
		}
		changed, err := exec(`UPDATE task_deliveries SET cancel_seen_at = ? WHERE id = ? AND json_extract(record, '$.cancel_claimed_at') IS NOT NULL AND cancel_seen_at IS NULL`, at, id)
		return true, changed > 0, err
	case strings.HasPrefix(id, "request_"):
		changed, err := exec(`UPDATE adapter_outbound SET reply_seen_at = ? WHERE request_id = ? AND reply_delivery IS NOT NULL AND json_extract(reply_delivery, '$.adapter_id') = ? AND reply_returned_at IS NULL AND reply_seen_at IS NULL`, at, id, adapterID)
		if err != nil || changed > 0 {
			return true, changed > 0, err
		}
		held, err := count(`SELECT COUNT(*) FROM adapter_outbound WHERE request_id = ? AND (adapter_id = ? OR (reply_delivery IS NOT NULL AND json_extract(reply_delivery, '$.adapter_id') = ? AND reply_returned_at IS NULL))`, id, adapterID, adapterID)
		return held > 0, false, err
	case strings.HasPrefix(id, "call_"):
		return markCallSeen(ctx, tx, adapterID, sessionID, id, at)
	default:
		held, changed, err := markTaskSeen(ctx, tx, adapterID, sessionID, id, false, at)
		return held, changed, err
	}
}

// markTaskSeen marks, for one task ID, the cancellation request and task
// update notifications this authorization holds as seen, and with accepted
// the received task itself. It reports whether the authorization holds the
// task (received or delegated) and whether anything changed.
func markTaskSeen(ctx context.Context, tx *sql.Tx, adapterID, sessionID, id string, accepted bool, at string) (bool, bool, error) {
	var changed int64
	exec := func(query string, args ...any) error {
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		changed += n
		return err
	}
	if accepted {
		if err := exec(`UPDATE task_deliveries SET seen_at = ? WHERE task_id = ? AND json_extract(record, '$.adapter_id') = ? AND session_id = ? AND returned_at IS NULL AND seen_at IS NULL`, at, id, adapterID, sessionID); err != nil {
			return false, false, err
		}
	}
	if err := exec(`UPDATE task_deliveries SET cancel_seen_at = ? WHERE task_id = ? AND json_extract(record, '$.adapter_id') = ? AND session_id = ? AND returned_at IS NULL AND json_extract(record, '$.cancel_claimed_at') IS NOT NULL AND cancel_seen_at IS NULL`, at, id, adapterID, sessionID); err != nil {
		return false, false, err
	}
	if err := exec(`UPDATE task_update_notifications SET seen_at = ? WHERE task_id = ? AND json_extract(record, '$.adapter_id') = ? AND json_extract(record, '$.session_id') = ? AND returned_at IS NULL AND seen_at IS NULL`, at, id, adapterID, sessionID); err != nil {
		return false, false, err
	}
	if changed > 0 {
		return true, true, nil
	}
	var held bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM task_deliveries WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2 AND session_id = ?3 AND returned_at IS NULL) OR EXISTS(SELECT 1 FROM task_update_notifications WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2 AND returned_at IS NULL) OR EXISTS(SELECT 1 FROM outbound_tasks WHERE task_id = ?1 AND json_extract(record, '$.adapter_id') = ?2)`, id, adapterID, sessionID).Scan(&held)
	return held, false, err
}

// TaskSeen records a task_* call on a task: the call marks the cancellation
// request and task updates this session was forwarded as seen, and
// task_accept and task_reject (accepted) the task itself. Items the session
// does not hold are left alone.
func (s *Store) TaskSeen(ctx context.Context, auth AdapterAuth, id string, accepted bool) error {
	if !validID(id, "task", 16) {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return nil
	}
	if _, _, err = markTaskSeen(ctx, tx, a.ID, ss.ID, id, accepted, timestamp(time.Now())); err != nil {
		return err
	}
	return tx.Commit()
}

// PendingWork is what a session still owes, oldest first in each list.
type PendingWork struct {
	Deliveries []PendingDelivery `json:"deliveries"`
	Replies    []PendingReply    `json:"replies"`
	Tasks      []PendingTask     `json:"tasks"`
	Calls      []PendingCall     `json:"calls"`
}

// PendingDelivery is an unanswered inbound delivery the session holds.
type PendingDelivery struct {
	DeliveryID    string  `json:"delivery_id"`
	RequestID     string  `json:"request_id"`
	SenderHostID  string  `json:"sender_host_id"`
	OriginAgentID *string `json:"origin_agent_id"`
	Preview       string  `json:"preview"`
	Seen          bool    `json:"seen"`
	Deadline      *string `json:"deadline"`
	Redelivered   bool    `json:"redelivered"`
}

// PendingReply is an unseen reply to the agent's send the session holds.
type PendingReply struct {
	NotificationID string `json:"notification_id"`
	RequestID      string `json:"request_id"`
	PeerHostID     string `json:"peer_host_id"`
	Preview        string `json:"preview"`
}

// PendingTask is a queued, running, or cancel-requested task the session
// holds.
type PendingTask struct {
	TaskID       string  `json:"task_id"`
	DeliveryID   string  `json:"delivery_id"`
	SenderHostID string  `json:"sender_host_id"`
	State        string  `json:"state"`
	Preview      string  `json:"preview"`
	Deadline     *string `json:"deadline"`
	Adopted      bool    `json:"adopted"`
}

func preview(text string) string {
	runes := []rune(text)
	if len(runes) > previewRunes {
		return string(runes[:previewRunes])
	}
	return text
}

func optionalText(text string) *string {
	if text == "" {
		return nil
	}
	return &text
}

// taskEventState is a task's state as events and pending work show it:
// cancel_requested for a running task whose cancellation was requested.
func taskEventState(st TaskStatus) string {
	if st.State == TaskRunning && st.CancelRequested {
		return "cancel_requested"
	}
	return st.State
}

// pendingWork lists a session's pending work, each list ordered by when the
// item first reached this host, so returned and adopted items keep their
// place.
func pendingWork(ctx context.Context, q queryer, session string) (PendingWork, error) {
	work := PendingWork{Deliveries: []PendingDelivery{}, Replies: []PendingReply{}, Tasks: []PendingTask{}, Calls: []PendingCall{}}
	rows, err := q.QueryContext(ctx, `SELECT d.record, d.seen_at IS NOT NULL, d.redeliveries, m.request FROM deliveries d JOIN received_messages m ON m.sender = d.sender AND m.request_id = d.request_id WHERE d.session_id = ? AND d.returned_at IS NULL AND json_extract(d.record, '$.state') IN ('unknown', 'forwarded') ORDER BY m.rowid`, session)
	if err != nil {
		return work, err
	}
	for rows.Next() {
		var record, request string
		var seen bool
		var redeliveries int64
		if err = rows.Scan(&record, &seen, &redeliveries, &request); err != nil {
			break
		}
		var d Delivery
		var m MessageRequest
		if err = json.Unmarshal([]byte(record), &d); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(request), &m); err != nil {
			break
		}
		item := PendingDelivery{DeliveryID: d.ID, RequestID: d.RequestID, SenderHostID: d.SenderHostID, Preview: preview(m.Content), Seen: seen, Deadline: optionalText(m.Deadline), Redelivered: redeliveries > 0}
		if m.Origin != nil {
			agent := m.Origin.AgentID
			item.OriginAgentID = &agent
		}
		work.Deliveries = append(work.Deliveries, item)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return work, err
	}
	rows, err = q.QueryContext(ctx, `SELECT o.reply_delivery, r.record FROM adapter_outbound o JOIN outbound_replies r ON r.peer = o.peer AND r.request_id = o.request_id WHERE o.reply_delivery IS NOT NULL AND json_extract(o.reply_delivery, '$.session_id') = ? AND o.reply_returned_at IS NULL AND o.reply_seen_at IS NULL ORDER BY r.rowid`, session)
	if err != nil {
		return work, err
	}
	for rows.Next() {
		var record, data string
		if err = rows.Scan(&record, &data); err != nil {
			break
		}
		var d ReplyDelivery
		var reply Reply
		if err = json.Unmarshal([]byte(record), &d); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(data), &reply); err != nil {
			break
		}
		work.Replies = append(work.Replies, PendingReply{NotificationID: d.ID, RequestID: d.RequestID, PeerHostID: d.PeerHostID, Preview: preview(reply.Content)})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return work, err
	}
	rows, err = q.QueryContext(ctx, `SELECT d.record, d.adopted_at IS NOT NULL, t.request, t.record FROM task_deliveries d JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE d.session_id = ? AND d.returned_at IS NULL AND json_extract(t.record, '$.state') IN ('queued', 'running') ORDER BY t.rowid`, session)
	if err != nil {
		return work, err
	}
	for rows.Next() {
		var record, request, status string
		var adopted bool
		if err = rows.Scan(&record, &adopted, &request, &status); err != nil {
			break
		}
		var d TaskDelivery
		var r TaskRequest
		var st TaskStatus
		if err = json.Unmarshal([]byte(record), &d); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(request), &r); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(status), &st); err != nil {
			break
		}
		work.Tasks = append(work.Tasks, PendingTask{TaskID: d.TaskID, DeliveryID: d.ID, SenderHostID: d.SenderHostID, State: taskEventState(st), Preview: preview(r.Input), Deadline: optionalText(r.Deadline), Adopted: adopted})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return work, err
	}
	work.Calls, err = pendingAgentCalls(ctx, q, session)
	return work, err
}

// AdapterPending is the pending work of the adapter's session. A verified
// session first takes back the items of the agent's ended authorizations.
func (s *Store) AdapterPending(ctx context.Context, auth AdapterAuth) (PendingWork, error) {
	if err := s.returnEnded(ctx, auth); err != nil {
		return PendingWork{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PendingWork{}, err
	}
	defer tx.Rollback()
	_, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return PendingWork{}, err
	}
	return pendingWork(ctx, tx, ss.ID)
}

// SessionPending is a session's pending work, for its owner.
func (s *Store) SessionPending(ctx context.Context, id string) (PendingWork, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PendingWork{}, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?)`, id).Scan(&exists); err != nil {
		return PendingWork{}, err
	}
	if !exists {
		return PendingWork{}, ErrNotFound
	}
	return pendingWork(ctx, tx, id)
}

func adapterLiveDeliveryRoutes(mux *http.ServeMux, s *Store, auth func(*http.Request) AdapterAuth) {
	mux.HandleFunc("POST /adapter/v1/seen", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IDs []string `json:"ids"`
		}
		if !decode(w, r, &body, "ids") {
			return
		}
		seen, err := s.MarkSeen(r.Context(), auth(r), body.IDs)
		respond(w, http.StatusOK, map[string][]string{"seen": seen}, err)
	})
	mux.HandleFunc("GET /adapter/v1/pending", func(w http.ResponseWriter, r *http.Request) {
		work, err := s.AdapterPending(r.Context(), auth(r))
		respond(w, http.StatusOK, work, err)
	})
}

func localLiveDeliveryRoutes(mux *http.ServeMux, s *Store) {
	mux.HandleFunc("GET /v1/sessions/{id}/pending", func(w http.ResponseWriter, r *http.Request) {
		work, err := s.SessionPending(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, work, err)
	})
}
