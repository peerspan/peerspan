package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Single-hop tasks (milestone 6, slice 2). A receiving host durably accepts
// responsibility for a task, hands it to one attached session of the target
// agent, and records every change with a per-task event sequence that the
// submitter polls. The v9 schema is shared with Rust.
const taskSchema = `
CREATE TABLE received_tasks (sender TEXT NOT NULL, task_id TEXT NOT NULL, request TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, task_id));
CREATE TABLE task_events (sender TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(sender, task_id, sequence));
CREATE TABLE outbound_tasks (peer TEXT NOT NULL, task_id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, task_id));
CREATE TABLE outbound_task_events (peer TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(peer, task_id, sequence));
CREATE TABLE task_deliveries (id TEXT PRIMARY KEY, sender TEXT NOT NULL, task_id TEXT NOT NULL, session_id TEXT NOT NULL REFERENCES sessions(id), record TEXT NOT NULL, UNIQUE(sender, task_id));
CREATE TABLE task_update_notifications (id TEXT PRIMARY KEY, peer TEXT NOT NULL, task_id TEXT NOT NULL, sequence INTEGER NOT NULL, record TEXT NOT NULL, UNIQUE(peer, task_id, sequence));
PRAGMA user_version = 9;
`

// Task states.
const (
	TaskQueued    = "queued"
	TaskRunning   = "running"
	TaskRejected  = "rejected"
	TaskExpired   = "expired"
	TaskSucceeded = "succeeded"
	TaskFailed    = "failed"
	TaskCancelled = "cancelled"
)

// taskLapsed is the rejection reason when authorization lapses before an
// agent accepts a task.
const taskLapsed = "authorization lapsed before acceptance"

func taskFinal(state string) bool {
	switch state {
	case TaskRejected, TaskExpired, TaskSucceeded, TaskFailed, TaskCancelled:
		return true
	}
	return false
}

func validTaskState(state string) bool {
	return state == TaskQueued || state == TaskRunning || taskFinal(state)
}

func validTaskEventKind(kind string) bool {
	switch kind {
	case "queued", "accepted", "rejected", "progress", "cancel_requested", "succeeded", "failed", "cancelled", "expired":
		return true
	}
	return false
}

// TaskRequest is a task submission on the peer wire. It names exactly one
// authorization, as a message does.
type TaskRequest struct {
	TaskID        string          `json:"task_id"`
	GrantID       *string         `json:"grant_id,omitempty"`
	Policy        *PolicyCitation `json:"policy,omitempty"`
	Self          *SelfCitation   `json:"self,omitempty"`
	TargetAgentID string          `json:"target_agent_id"`
	Deadline      string          `json:"deadline"`
	Input         string          `json:"input"`
	Origin        *Origin         `json:"origin,omitempty"`
	// Artifacts is the input manifest, absent without inputs.
	Artifacts []ArtifactEntry `json:"artifacts,omitempty"`
	// Delegation is the chain of links from the originator, absent for a
	// task that cannot be passed on.
	Delegation []membership.Link `json:"delegation,omitempty"`
}

// asMessage is the request as authorization sees it: its input bounded like
// message content, and its input artifacts by max_artifact_bytes.
func (r TaskRequest) asMessage() MessageRequest {
	m := MessageRequest{GrantID: r.GrantID, Policy: r.Policy, Self: r.Self, TargetAgentID: r.TargetAgentID, Deadline: r.Deadline, Content: r.Input, Origin: r.Origin}
	manifestAuthority(&m, r.Artifacts)
	return m
}

func (r TaskRequest) same(o TaskRequest) bool {
	a, b := r.asMessage(), o.asMessage()
	a.RequestID, b.RequestID = r.TaskID, o.TaskID
	return a.same(b) && sameManifest(r.Artifacts, o.Artifacts) && sameChain(r.Delegation, o.Delegation)
}

// TaskStatus is the status record a receiver keeps and serves to the submitter.
type TaskStatus struct {
	TaskID          string `json:"task_id"`
	SenderHostID    string `json:"sender_host_id"`
	ReceiverHostID  string `json:"receiver_host_id"`
	TargetAgentID   string `json:"target_agent_id"`
	State           string `json:"state"`
	CancelRequested bool   `json:"cancel_requested"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	LastEvent       int64  `json:"last_event"`
}

// TaskEvent is one change of a task. State is the state after the event.
type TaskEvent struct {
	Sequence  int64   `json:"sequence"`
	Kind      string  `json:"kind"`
	State     string  `json:"state"`
	Message   *string `json:"message"`
	Output    *string `json:"output"`
	CreatedAt string  `json:"created_at"`
	// Artifacts is the result manifest of a final succeeded or failed event,
	// otherwise null.
	Artifacts []ArtifactEntry `json:"artifacts"`
}

// TaskDelivery binds a claimed task to one adapter session.
type TaskDelivery struct {
	ID              string  `json:"id"`
	SenderHostID    string  `json:"sender_host_id"`
	TaskID          string  `json:"task_id"`
	TargetAgentID   string  `json:"target_agent_id"`
	SessionID       string  `json:"session_id"`
	AdapterID       string  `json:"adapter_id"`
	CancelClaimedAt *string `json:"cancel_claimed_at"`
	CreatedAt       string  `json:"created_at"`
}

// TaskHandoff is a claimed task, as the adapter receives it.
type TaskHandoff struct {
	Delivery       TaskDelivery `json:"delivery"`
	Task           TaskRequest  `json:"task"`
	Status         TaskStatus   `json:"status"`
	SenderPersonID *string      `json:"sender_person_id"`
	SenderPerson   *string      `json:"sender_person"`
	// OriginatorPersonID is the person bound to the chain's originator host,
	// or null; null without a chain.
	OriginatorPersonID *string `json:"originator_person_id"`
	// Delegable reports whether the receiving agent may pass the task on.
	Delegable bool `json:"delegable"`
	// Redelivered marks a task claimed again after its holding
	// authorization ended without seeing it; Adopted, a running task
	// claimed from an ended authorization, with its latest Progress.
	Redelivered bool    `json:"redelivered"`
	Adopted     bool    `json:"adopted"`
	Progress    *string `json:"progress"`
}

// TaskCancelHandoff is a claimed cancellation request.
type TaskCancelHandoff struct {
	Delivery TaskDelivery `json:"delivery"`
	Status   TaskStatus   `json:"status"`
}

// TaskChange is an adapter's change to a claimed task.
type TaskChange struct {
	Op      string // accept, reject, progress, complete, or cancelled
	Reason  string
	Message string
	Status  string
	Output  string
	// Artifacts is a completion's result manifest; nil without results.
	Artifacts []ArtifactEntry
}

func validText(text string, empty bool) bool {
	return (empty || text != "") && utf8.ValidString(text) && len(text) <= 65536
}

func validateTask(r TaskRequest) error {
	if !validID(r.TaskID, "task", 16) {
		return ErrInvalid
	}
	if r.Artifacts != nil && !validManifest(r.Artifacts) {
		return fmt.Errorf("%w: invalid artifact manifest", ErrInvalid)
	}
	if !validChain(r.Delegation) {
		return fmt.Errorf("%w: invalid delegation chain", ErrInvalid)
	}
	m := r.asMessage()
	m.RequestID = "request_00000000000000000000000000000000"
	return validateMessage(m)
}

func taskSubject(host, id string) string { return host + "/" + id }

func readTaskStatus(ctx context.Context, q dbQuerier, sender, id string) (TaskStatus, error) {
	return readJSON[TaskStatus](q.QueryRowContext(ctx, `SELECT record FROM received_tasks WHERE sender = ? AND task_id = ?`, sender, id))
}

// writeTaskStatus stores the status record, keeping the internal
// max_artifact_bytes and delegable keys that acceptance adds.
func writeTaskStatus(ctx context.Context, tx *sql.Tx, st TaskStatus) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE received_tasks SET record = CASE WHEN json_type(record, '$.delegable') IS NULL THEN `+keepBound+` ELSE json_set(`+keepBound+`, '$.delegable', json(record -> '$.delegable')) END WHERE sender = ?2 AND task_id = ?3`, string(data), st.SenderHostID, st.TaskID)
	return err
}

// keepBound is the new record ?1 with the stored max_artifact_bytes, if any.
const keepBound = `(CASE WHEN json_type(record, '$.max_artifact_bytes') IS NULL THEN ?1 ELSE json_set(?1, '$.max_artifact_bytes', json_extract(record, '$.max_artifact_bytes')) END)`

// taskArtifactBound is the artifact bound stored when the task was accepted.
func taskArtifactBound(ctx context.Context, tx *sql.Tx, sender, id string) (int64, error) {
	var bound sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT json_extract(record, '$.max_artifact_bytes') FROM received_tasks WHERE sender = ? AND task_id = ?`, sender, id).Scan(&bound)
	return bound.Int64, err
}

// appendTaskEvent records one change: the event, the updated status record,
// and its activity, in the caller's transaction.
func appendTaskEvent(ctx context.Context, tx *sql.Tx, st *TaskStatus, kind, state string, message, output *string, activity string, now time.Time, artifacts ...ArtifactEntry) error {
	at := timestamp(now)
	st.LastEvent++
	st.State, st.UpdatedAt = state, at
	e := TaskEvent{Sequence: st.LastEvent, Kind: kind, State: state, Message: message, Output: output, CreatedAt: at, Artifacts: emptyAsNone(artifacts)}
	if err := putJSON(ctx, tx, `INSERT INTO task_events (record, sender, task_id, sequence) VALUES (?, ?, ?, ?)`, e, st.SenderHostID, st.TaskID, e.Sequence); err != nil {
		return err
	}
	if err := writeTaskStatus(ctx, tx, *st); err != nil {
		return err
	}
	return appendEvent(ctx, tx, activity, taskSubject(st.SenderHostID, st.TaskID), at)
}

// expireTasks moves every queued task whose deadline has passed to expired.
func expireTasks(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT record, json_extract(request, '$.deadline') FROM received_tasks WHERE json_extract(record, '$.state') = 'queued' ORDER BY rowid`)
	if err != nil {
		return err
	}
	var due []TaskStatus
	for rows.Next() {
		var record, deadline string
		if err = rows.Scan(&record, &deadline); err != nil {
			break
		}
		var st TaskStatus
		if err = json.Unmarshal([]byte(record), &st); err != nil {
			break
		}
		if at, e := parseTime(deadline); e == nil && !at.After(now) {
			due = append(due, st)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, st := range due {
		if err = appendTaskEvent(ctx, tx, &st, "expired", TaskExpired, nil, nil, "task.expired", now); err != nil {
			return err
		}
	}
	return nil
}

// ExpireTasks applies expiry now; the daemon calls it periodically.
func (s *Store) ExpireTasks(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = expireTasks(ctx, tx, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

// RunTaskExpiry expires overdue queued tasks every second until ctx ends.
func (s *Store) RunTaskExpiry(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_ = s.ExpireTasks(ctx)
	}
}

// AcceptTask authorizes a submission for task.submit and persists it queued,
// idempotently by (sender, task_id).
func (s *Store) AcceptTask(ctx context.Context, sender string, r TaskRequest) (TaskStatus, error) {
	if err := validateTask(r); err != nil {
		return TaskStatus{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TaskStatus{}, err
	}
	defer tx.Rollback()
	now := time.Now()
	if _, _, err = s.taskAuthority(ctx, tx, sender, r, now); err != nil {
		return TaskStatus{}, err
	}
	if err = expireTasks(ctx, tx, now); err != nil {
		return TaskStatus{}, err
	}
	old, err := readJSON[TaskRequest](tx.QueryRowContext(ctx, `SELECT request FROM received_tasks WHERE sender = ? AND task_id = ?`, sender, r.TaskID))
	if err == nil {
		if !old.same(r) {
			return TaskStatus{}, ErrConflict
		}
		st, err := readTaskStatus(ctx, tx, sender, r.TaskID)
		if err != nil {
			return st, err
		}
		return st, tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return TaskStatus{}, err
	}
	if err = s.quotaFor(ctx, tx, r.Artifacts); err != nil {
		return TaskStatus{}, err
	}
	at := timestamp(now)
	st := TaskStatus{TaskID: r.TaskID, SenderHostID: sender, ReceiverHostID: s.identity.ID, TargetAgentID: r.TargetAgentID, State: TaskQueued, CreatedAt: at, UpdatedAt: at}
	requestData, err := json.Marshal(r)
	if err != nil {
		return st, err
	}
	recordData, err := json.Marshal(st)
	if err != nil {
		return st, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO received_tasks VALUES (?, ?, ?, ?)`, sender, r.TaskID, string(requestData), string(recordData)); err != nil {
		return st, err
	}
	if err = appendTaskEvent(ctx, tx, &st, "queued", TaskQueued, nil, nil, "task.received", now); err != nil {
		return st, err
	}
	if err = insertArtifacts(ctx, tx, sideReceived, sender, r.TaskID, directionInput, r.Artifacts, artifactPending); err != nil {
		return st, err
	}
	return st, tx.Commit()
}

// SubmitterTask is the status record of the sender's own task; anything else
// is not found. Expiry is applied first.
func (s *Store) SubmitterTask(ctx context.Context, sender, id string) (TaskStatus, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TaskStatus{}, err
	}
	defer tx.Rollback()
	if err = expireTasks(ctx, tx, time.Now()); err != nil {
		return TaskStatus{}, err
	}
	st, err := readTaskStatus(ctx, tx, sender, id)
	if err != nil {
		return st, err
	}
	return st, tx.Commit()
}

// SubmitterTaskEvents pages the sender's own task's events after a cursor.
func (s *Store) SubmitterTaskEvents(ctx context.Context, sender, id string, after, limit int64) ([]TaskEvent, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = expireTasks(ctx, tx, time.Now()); err != nil {
		return nil, err
	}
	if _, err = readTaskStatus(ctx, tx, sender, id); err != nil {
		return nil, err
	}
	events, err := taskEvents(ctx, tx, `SELECT record FROM task_events WHERE sender = ? AND task_id = ? AND sequence > ? ORDER BY sequence LIMIT ?`, sender, id, after, limit)
	if err != nil {
		return nil, err
	}
	return events, tx.Commit()
}

func taskEvents(ctx context.Context, q queryer, query string, args ...any) ([]TaskEvent, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []TaskEvent{}
	for rows.Next() {
		e, err := readJSON[TaskEvent](rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// RequestTaskCancel records the submitter's cancellation request once. A
// final task is returned unchanged.
func (s *Store) RequestTaskCancel(ctx context.Context, sender, id string) (TaskStatus, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TaskStatus{}, err
	}
	defer tx.Rollback()
	now := time.Now()
	if err = expireTasks(ctx, tx, now); err != nil {
		return TaskStatus{}, err
	}
	st, err := readTaskStatus(ctx, tx, sender, id)
	if err != nil {
		return st, err
	}
	var children []string
	if !taskFinal(st.State) && !st.CancelRequested {
		st.CancelRequested = true
		if err = appendTaskEvent(ctx, tx, &st, "cancel_requested", st.State, nil, nil, "task.cancel_requested", now); err != nil {
			return st, err
		}
		// Every task passed on from this one is asked to stop too.
		if children, err = cancelChildren(ctx, tx, sender, id); err != nil {
			return st, err
		}
	}
	if err = tx.Commit(); err != nil {
		return st, err
	}
	s.pollNow(children)
	return st, nil
}

// NextTask claims the oldest queued task for this session's agent after
// rechecking its authorization, as message handoff does. A recoverable
// denial leaves the task unclaimed; a final one rejects it.
func (s *Store) NextTask(ctx context.Context, auth AdapterAuth) (*TaskHandoff, error) {
	if err := s.returnEnded(ctx, auth); err != nil {
		return nil, err
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
	if err = requireVerified(ctx, tx, a.ID); err != nil {
		return nil, err
	}
	now := time.Now()
	if err = expireTasks(ctx, tx, now); err != nil {
		return nil, err
	}
	// Tasks returned by the agent's ended authorizations come first.
	if h, err := s.claimReturnedTask(ctx, tx, a, ss, now); err != nil || h != nil {
		if err != nil {
			return nil, err
		}
		return h, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT t.sender, t.request, t.record FROM received_tasks t WHERE json_extract(t.request, '$.target_agent_id') = ? AND json_extract(t.record, '$.state') = 'queued' AND NOT EXISTS (SELECT 1 FROM task_deliveries d WHERE d.sender = t.sender AND d.task_id = t.task_id) AND NOT EXISTS (SELECT 1 FROM task_artifacts a WHERE a.side = 'received' AND a.peer = t.sender AND a.task_id = t.task_id AND a.direction = 'input' AND json_extract(a.record, '$.state') != 'stored') ORDER BY t.rowid LIMIT 100`, ss.AgentID)
	if err != nil {
		return nil, err
	}
	type pending struct {
		sender  string
		request TaskRequest
		status  TaskStatus
	}
	var items []pending
	for rows.Next() {
		var p pending
		var request, record string
		if err = rows.Scan(&p.sender, &request, &record); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(request), &p.request); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(record), &p.status); err != nil {
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
	var result *TaskHandoff
	for _, p := range items {
		final, check, err := s.taskHandoffAuthority(ctx, tx, p.sender, p.request)
		if err != nil {
			return nil, err
		}
		if final == nil {
			continue // recoverable: leave it unclaimed
		}
		if !*final {
			reason := taskLapsed
			if err = appendTaskEvent(ctx, tx, &p.status, "rejected", TaskRejected, &reason, nil, "task.rejected", now); err != nil {
				return nil, err
			}
			continue
		}
		id, err := newID("delivery")
		if err != nil {
			return nil, err
		}
		d := TaskDelivery{ID: id, SenderHostID: p.sender, TaskID: p.request.TaskID, TargetAgentID: ss.AgentID, SessionID: ss.ID, AdapterID: a.ID, CreatedAt: timestamp(now)}
		if err = putJSON(ctx, tx, `INSERT INTO task_deliveries (record, id, sender, task_id, session_id) VALUES (?, ?, ?, ?, ?)`, d, d.ID, d.SenderHostID, d.TaskID, d.SessionID); err != nil {
			return nil, err
		}
		result = &TaskHandoff{Delivery: d, Task: p.request, Status: p.status}
		if result.SenderPersonID, result.SenderPerson, err = senderPerson(ctx, tx, p.sender); err != nil {
			return nil, err
		}
		if check.chain != nil {
			result.OriginatorPersonID = check.chain.originatorPerson
		}
		result.Delegable = check.delegable
		break
	}
	return result, tx.Commit()
}

// claimReturnedTask claims the oldest returned task of the session's agent,
// rebinding its delivery in place. A running task is adopted; a queued one
// is redelivered after rechecking its authorization as a first handoff does.
func (s *Store) claimReturnedTask(ctx context.Context, tx *sql.Tx, a Adapter, ss Session, now time.Time) (*TaskHandoff, error) {
	rows, err := tx.QueryContext(ctx, `SELECT d.record, d.redeliveries, t.request, t.record FROM task_deliveries d JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE d.returned_at IS NOT NULL AND json_extract(d.record, '$.target_agent_id') = ? AND json_extract(t.record, '$.state') IN ('queued', 'running') ORDER BY d.rowid LIMIT 100`, ss.AgentID)
	if err != nil {
		return nil, err
	}
	type returned struct {
		delivery     TaskDelivery
		redeliveries int64
		request      TaskRequest
		status       TaskStatus
	}
	var items []returned
	for rows.Next() {
		var p returned
		var record, request, status string
		if err = rows.Scan(&record, &p.redeliveries, &request, &status); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(record), &p.delivery); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(request), &p.request); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(status), &p.status); err != nil {
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
		d := p.delivery
		d.AdapterID, d.SessionID = a.ID, ss.ID
		h := &TaskHandoff{Task: p.request, Status: p.status}
		if p.status.State == TaskRunning {
			// Adoption: no redelivery is counted, and acceptance settled
			// whether the task may be passed on.
			if err = putJSON(ctx, tx, `UPDATE task_deliveries SET record = ?, session_id = ?, returned_at = NULL, adopted_at = ? WHERE id = ?`, d, ss.ID, timestamp(now), d.ID); err != nil {
				return nil, err
			}
			var delegable sql.NullBool
			if err = tx.QueryRowContext(ctx, `SELECT json_extract(record, '$.delegable') FROM received_tasks WHERE sender = ? AND task_id = ?`, d.SenderHostID, d.TaskID).Scan(&delegable); err != nil {
				return nil, err
			}
			h.Delegable, h.Adopted, h.Redelivered = delegable.Valid && delegable.Bool, true, p.redeliveries > 0
			if h.Progress, err = latestProgress(ctx, tx, d.SenderHostID, d.TaskID); err != nil {
				return nil, err
			}
			if h.OriginatorPersonID, err = chainOriginatorPerson(ctx, tx, p.request); err != nil {
				return nil, err
			}
		} else {
			final, check, err := s.taskHandoffAuthority(ctx, tx, d.SenderHostID, p.request)
			if err != nil {
				return nil, err
			}
			if final == nil {
				continue // recoverable: leave it returned
			}
			if !*final {
				reason := taskLapsed
				st := p.status
				if err = appendTaskEvent(ctx, tx, &st, "rejected", TaskRejected, &reason, nil, "task.rejected", now); err != nil {
					return nil, err
				}
				if _, err = tx.ExecContext(ctx, `UPDATE task_deliveries SET returned_at = NULL WHERE id = ?`, d.ID); err != nil {
					return nil, err
				}
				continue
			}
			if err = putJSON(ctx, tx, `UPDATE task_deliveries SET record = ?, session_id = ?, returned_at = NULL, adopted_at = NULL, redeliveries = redeliveries + 1 WHERE id = ?`, d, ss.ID, d.ID); err != nil {
				return nil, err
			}
			h.Delegable, h.Redelivered = check.delegable, true
			if check.chain != nil {
				h.OriginatorPersonID = check.chain.originatorPerson
			}
		}
		h.Delivery = d
		if h.SenderPersonID, h.SenderPerson, err = senderPerson(ctx, tx, d.SenderHostID); err != nil {
			return nil, err
		}
		return h, nil
	}
	return nil, nil
}

// handoffCheck is what an authorized handoff or acceptance learned: the
// artifact bound, the verified chain, and whether the task may be passed on.
type handoffCheck struct {
	bound     int64
	chain     *chainFacts
	delegable bool
}

// taskHandoffAuthority rechecks a queued task's chain and authorization. It
// returns nil when only a recoverable check fails, a pointer to true when the
// task is authorized, and to false when authorization has lapsed for good.
func (s *Store) taskHandoffAuthority(ctx context.Context, tx *sql.Tx, sender string, r TaskRequest) (*bool, handoffCheck, error) {
	allowed, lapsed := true, false
	chain, err := s.verifyChain(ctx, tx, sender, r, time.Now())
	if errors.Is(err, ErrForbidden) {
		return &lapsed, handoffCheck{}, nil
	}
	if err != nil {
		return nil, handoffCheck{}, err
	}
	requester, m := chain.requester(sender, r)
	g, err := s.actionBounds(ctx, tx, requester, membership.PolicyActionTask, m, true)
	if errors.Is(err, ErrUnavailable) {
		return nil, handoffCheck{}, nil
	}
	if errors.Is(err, ErrForbidden) {
		return &lapsed, handoffCheck{}, nil
	}
	if err != nil {
		return nil, handoffCheck{}, err
	}
	usable, recoverable, err := s.grantConnected(ctx, tx, requester, g)
	switch {
	case err != nil:
		return nil, handoffCheck{}, err
	case usable:
		return &allowed, handoffCheck{bound: g.maxArtifactBytes, chain: chain, delegable: chain.delegable(g)}, nil
	case recoverable:
		return nil, handoffCheck{}, nil
	}
	return &lapsed, handoffCheck{}, nil
}

// ownedTask resolves a task ID to this credential's delivery of it. A task
// claimed by another session or credential is forbidden; an unknown one is
// not found.
func ownedTask(ctx context.Context, tx *sql.Tx, auth AdapterAuth, id string) (TaskDelivery, TaskRequest, TaskStatus, error) {
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return TaskDelivery{}, TaskRequest{}, TaskStatus{}, err
	}
	d, err := readJSON[TaskDelivery](tx.QueryRowContext(ctx, `SELECT record FROM task_deliveries WHERE task_id = ? AND session_id = ? AND json_extract(record, '$.adapter_id') = ? AND returned_at IS NULL ORDER BY rowid LIMIT 1`, id, ss.ID, a.ID))
	if errors.Is(err, ErrNotFound) {
		var exists bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM received_tasks WHERE task_id = ?)`, id).Scan(&exists); err != nil {
			return d, TaskRequest{}, TaskStatus{}, err
		}
		if exists {
			return d, TaskRequest{}, TaskStatus{}, ErrForbidden
		}
		return d, TaskRequest{}, TaskStatus{}, ErrNotFound
	}
	if err != nil {
		return d, TaskRequest{}, TaskStatus{}, err
	}
	r, err := readJSON[TaskRequest](tx.QueryRowContext(ctx, `SELECT request FROM received_tasks WHERE sender = ? AND task_id = ?`, d.SenderHostID, d.TaskID))
	if err != nil {
		return d, r, TaskStatus{}, err
	}
	st, err := readTaskStatus(ctx, tx, d.SenderHostID, d.TaskID)
	return d, r, st, err
}

func validChange(c TaskChange) bool {
	switch c.Op {
	case "accept", "cancelled":
		return true
	case "reject":
		return validText(c.Reason, true)
	case "progress":
		return validText(c.Message, false)
	case "complete":
		return (c.Status == TaskSucceeded || c.Status == TaskFailed) && validText(c.Output, false) && (c.Artifacts == nil || validManifest(c.Artifacts))
	}
	return false
}

// ChangeTask applies an adapter's change to a task its session claimed. Each
// change persists the state and its event together; an identical repeat
// returns the record unchanged, and any other invalid transition conflicts.
func (s *Store) ChangeTask(ctx context.Context, auth AdapterAuth, id string, c TaskChange) (TaskStatus, error) {
	if !validChange(c) {
		return TaskStatus{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TaskStatus{}, err
	}
	defer tx.Rollback()
	now := time.Now()
	if err = expireTasks(ctx, tx, now); err != nil {
		return TaskStatus{}, err
	}
	d, r, st, err := ownedTask(ctx, tx, auth, id)
	if err != nil {
		return st, err
	}
	last, err := readJSON[TaskEvent](tx.QueryRowContext(ctx, `SELECT record FROM task_events WHERE sender = ? AND task_id = ? AND sequence = ?`, d.SenderHostID, d.TaskID, st.LastEvent))
	if err != nil {
		return st, err
	}
	unchanged := func() (TaskStatus, error) { return st, tx.Commit() }
	switch c.Op {
	case "accept":
		if st.State == TaskRunning {
			return unchanged()
		}
		if st.State != TaskQueued {
			return st, ErrConflict
		}
		final, check, err := s.taskHandoffAuthority(ctx, tx, d.SenderHostID, r)
		if err != nil {
			return st, err
		}
		if final == nil {
			return st, fmt.Errorf("%w: the task's authorization cannot be confirmed until coordination syncs", ErrUnavailable)
		}
		if !*final {
			reason := taskLapsed
			if err = appendTaskEvent(ctx, tx, &st, "rejected", TaskRejected, &reason, nil, "task.rejected", now); err != nil {
				return st, err
			}
			if err = tx.Commit(); err != nil {
				return st, err
			}
			return st, ErrForbidden
		}
		if err = appendTaskEvent(ctx, tx, &st, "accepted", TaskRunning, nil, nil, "task.accepted", now); err != nil {
			return st, err
		}
		// The bound checked now limits the results, and whether the task may
		// be passed on is settled; later revocation changes neither.
		_, err = tx.ExecContext(ctx, `UPDATE received_tasks SET record = json_set(record, '$.max_artifact_bytes', ?, '$.delegable', json(?)) WHERE sender = ? AND task_id = ?`, check.bound, strconv.FormatBool(check.delegable), d.SenderHostID, d.TaskID)
	case "reject":
		if st.State == TaskRejected && last.Kind == "rejected" && last.Message != nil && *last.Message == c.Reason {
			return unchanged()
		}
		if st.State != TaskQueued {
			return st, ErrConflict
		}
		err = appendTaskEvent(ctx, tx, &st, "rejected", TaskRejected, &c.Reason, nil, "task.rejected", now)
	case "progress":
		if st.State != TaskRunning {
			return st, ErrConflict
		}
		if last.Kind == "progress" && last.Message != nil && *last.Message == c.Message {
			return unchanged()
		}
		err = appendTaskEvent(ctx, tx, &st, "progress", TaskRunning, &c.Message, nil, "task.progress", now)
	case "complete":
		if st.State == c.Status && last.Kind == c.Status && last.Output != nil && *last.Output == c.Output && sameManifest(last.Artifacts, c.Artifacts) {
			return unchanged()
		}
		if st.State != TaskRunning {
			return st, ErrConflict
		}
		if len(c.Artifacts) > 0 {
			if err = requireStored(ctx, tx, c.Artifacts); err != nil {
				return st, err
			}
			bound, err := taskArtifactBound(ctx, tx, d.SenderHostID, d.TaskID)
			if err != nil {
				return st, err
			}
			if bound == 0 || manifestTotal(r.Artifacts)+manifestTotal(c.Artifacts) > bound {
				return st, fmt.Errorf("%w: the result artifacts exceed the task's max_artifact_bytes", ErrForbidden)
			}
		}
		if err = appendTaskEvent(ctx, tx, &st, c.Status, c.Status, nil, &c.Output, "task.completed", now, c.Artifacts...); err != nil {
			return st, err
		}
		err = insertArtifacts(ctx, tx, sideReceived, d.SenderHostID, d.TaskID, directionResult, c.Artifacts, artifactStored)
	case "cancelled":
		if st.State == TaskCancelled {
			return unchanged()
		}
		if st.State != TaskRunning || !st.CancelRequested {
			return st, ErrConflict
		}
		err = appendTaskEvent(ctx, tx, &st, "cancelled", TaskCancelled, nil, nil, "task.cancelled", now)
	}
	if err != nil {
		return st, err
	}
	return st, tx.Commit()
}

// NextTaskCancel claims one unseen cancellation request for this session's
// running tasks.
func (s *Store) NextTaskCancel(ctx context.Context, auth AdapterAuth) (*TaskCancelHandoff, error) {
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
	var record, status string
	err = tx.QueryRowContext(ctx, `SELECT d.record, t.record FROM task_deliveries d JOIN received_tasks t ON t.sender = d.sender AND t.task_id = d.task_id WHERE d.session_id = ? AND json_extract(d.record, '$.adapter_id') = ? AND d.returned_at IS NULL AND json_extract(d.record, '$.cancel_claimed_at') IS NULL AND json_extract(t.record, '$.state') = 'running' AND json_extract(t.record, '$.cancel_requested') = 1 ORDER BY d.rowid LIMIT 1`, ss.ID, a.ID).Scan(&record, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h TaskCancelHandoff
	if err = json.Unmarshal([]byte(record), &h.Delivery); err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(status), &h.Status); err != nil {
		return nil, err
	}
	at := timestamp(time.Now())
	h.Delivery.CancelClaimedAt = &at
	// The first claim of a cancellation request starts it unseen.
	if err = putJSON(ctx, tx, `UPDATE task_deliveries SET record = ?, cancel_seen_at = NULL WHERE id = ?`, h.Delivery, h.Delivery.ID); err != nil {
		return nil, err
	}
	return &h, tx.Commit()
}
