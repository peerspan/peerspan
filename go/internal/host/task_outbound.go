package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// The submitting side of tasks: a durable local record per (peer, task_id),
// automatic idempotent retry of uncertain submissions with the milestone 5
// schedule, and bounded workers that poll events until a final state.

const (
	taskDefaultDeadline = time.Hour
	taskPollFirst       = time.Second
	taskPollMax         = 60 * time.Second
	taskWorkers         = 4
)

// Submit states of a local task record, as for outbound messages.
const (
	submitUnknown  = "unknown"
	submitAccepted = "accepted"
	submitRejected = "rejected"
)

// Cancellation states of a local task record.
const (
	cancelUnknown = "unknown" // requested locally, not confirmed by the receiver
	cancelSent    = "sent"
)

// SubmitTask is the owner-local submission body.
type SubmitTask struct {
	PeerHostID    string  `json:"peer_host_id"`
	TaskID        string  `json:"task_id,omitempty"`
	GrantID       *string `json:"grant_id,omitempty"`
	TargetAgentID string  `json:"target_agent_id"`
	Deadline      string  `json:"deadline,omitempty"`
	Input         string  `json:"input"`
	Origin        *Origin `json:"origin,omitempty"`
	// Artifacts names stored uploads to attach as inputs.
	Artifacts []ArtifactEntry `json:"artifacts,omitempty"`
	// DelegationDepth, 0 to 2, creates link 0 of a delegation chain with
	// that depth and DelegationPrincipals (default network); 0 creates none.
	DelegationDepth      int64    `json:"delegation_depth,omitempty"`
	DelegationPrincipals []string `json:"delegation_principals,omitempty"`
	// Parent forwards a running received task instead, extending its chain.
	Parent *TaskParent `json:"parent,omitempty"`
	// To, with an optional Network, is an address given instead of
	// PeerHostID and TargetAgentID.
	To      *string `json:"to,omitempty"`
	Network string  `json:"network,omitempty"`
	// cite is the owner citation chosen for an address, if any.
	cite *ownerCitation
}

// OutboundTask is the local record of a submitted task.
type OutboundTask struct {
	PeerHostID string `json:"peer_host_id"`
	// To is the address the task was given; records not sent by address
	// keep their earlier shape, without it.
	To          *string     `json:"to,omitempty"`
	Request     TaskRequest `json:"request"`
	SubmitState string      `json:"submit_state"`
	// Status is the latest status record the receiver returned.
	Status *TaskStatus `json:"status"`
	// EventsAfter is the highest locally stored event sequence.
	EventsAfter int64   `json:"events_after"`
	CancelState *string `json:"cancel_state"`
	// AdapterID and RouteID bind an agent-initiated task to its credential
	// and route; both are null for owner submissions.
	AdapterID     *string `json:"adapter_id"`
	RouteID       *string `json:"route_id"`
	Attempts      int64   `json:"attempts"`
	NextAttemptAt *string `json:"next_attempt_at"`
	Error         *string `json:"error"`
	// StatusQueries counts status queries made at or after the deadline.
	StatusQueries int64 `json:"status_queries"`
	// Artifacts lists inputs, then results, with their local state. It is
	// read from task_artifacts when the record is returned, never stored.
	Artifacts []LocalArtifact `json:"artifacts"`
	// Parent is the received task this one was forwarded from, or null.
	Parent *TaskParent `json:"parent"`
	// Delegation is the chain this task was sent with, or null.
	Delegation []membership.Link `json:"delegation"`
}

// recordedTaskRequest shows grant_id as null, rather than absent, when the
// request cites a policy.
type recordedTaskRequest struct {
	TaskID        string            `json:"task_id"`
	GrantID       *string           `json:"grant_id"`
	Policy        *PolicyCitation   `json:"policy,omitempty"`
	Self          *SelfCitation     `json:"self,omitempty"`
	TargetAgentID string            `json:"target_agent_id"`
	Deadline      string            `json:"deadline"`
	Input         string            `json:"input"`
	Origin        *Origin           `json:"origin,omitempty"`
	Artifacts     []ArtifactEntry   `json:"artifacts,omitempty"`
	Delegation    []membership.Link `json:"delegation,omitempty"`
}

func (o OutboundTask) MarshalJSON() ([]byte, error) {
	type plain OutboundTask
	return json.Marshal(struct {
		plain
		Request recordedTaskRequest `json:"request"`
	}{plain(o), recordedTaskRequest(o.Request)})
}

// persisted is the record as stored: without its derived artifacts.
func (o OutboundTask) persisted() OutboundTask {
	o.Artifacts = nil
	return o
}

// needsPoll reports whether the receiver may still have events to fetch.
func (o OutboundTask) needsPoll() bool {
	return o.SubmitState == submitAccepted && (o.Status == nil || !taskFinal(o.Status.State) || o.EventsAfter < o.Status.LastEvent)
}

// OutboundTaskItem is one entry of the local task list.
type OutboundTaskItem struct {
	Sequence int64        `json:"sequence"`
	Task     OutboundTask `json:"task"`
}

// AdapterDelegate is an agent's task submission through a task.submit route.
type AdapterDelegate struct {
	Destination string `json:"destination"`
	// To, with an optional Network, is an address given instead of
	// Destination by a directory session.
	To        *string         `json:"to,omitempty"`
	Network   string          `json:"network,omitempty"`
	TaskID    string          `json:"task_id"`
	Input     string          `json:"input"`
	Artifacts []ArtifactEntry `json:"artifacts,omitempty"`
	// ParentTaskID forwards a task this session claimed and is running.
	ParentTaskID string `json:"parent_task_id,omitempty"`
}

// TaskUpdateDelivery is one task event handed to the originating session.
type TaskUpdateDelivery struct {
	ID         string `json:"id"`
	PeerHostID string `json:"peer_host_id"`
	TaskID     string `json:"task_id"`
	Sequence   int64  `json:"sequence"`
	AdapterID  string `json:"adapter_id"`
	SessionID  string `json:"session_id"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// TaskUpdateHandoff is a claimed task update.
type TaskUpdateHandoff struct {
	Delivery TaskUpdateDelivery `json:"delivery"`
	Event    TaskEvent          `json:"event"`
}

// taskWork is the in-memory poll schedule. A restart polls every unfinished
// task at once, resuming from its stored cursor.
type taskWork struct {
	mu   sync.Mutex
	poll map[string]taskPoll
	// fetching holds the digests being downloaded.
	fetching map[string]bool
}
type taskPoll struct {
	at    time.Time
	delay time.Duration
}

func taskKey(peer, id string) string { return "task:" + peer + "/" + id }

func (s *Store) OutboundTask(ctx context.Context, peer, id string) (OutboundTask, error) {
	return readJSON[OutboundTask](s.db.QueryRowContext(ctx, `SELECT record FROM outbound_tasks WHERE peer = ? AND task_id = ?`, peer, id))
}

// OutboundTasks pages local task records in insertion order.
func (s *Store) OutboundTasks(ctx context.Context, after, limit int64) ([]OutboundTaskItem, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rowid, record FROM outbound_tasks WHERE rowid > ? ORDER BY rowid LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	var all []OutboundTaskItem
	for rows.Next() {
		var item OutboundTaskItem
		var record string
		if err = rows.Scan(&item.Sequence, &record); err != nil {
			rows.Close()
			return nil, err
		}
		if err = json.Unmarshal([]byte(record), &item.Task); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	items := []OutboundTaskItem{}
	pageBytes := 2
	for _, item := range all {
		if item.Task, err = s.withArtifacts(ctx, item.Task, nil); err != nil {
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
	return items, nil
}

// OutboundTaskEvents pages a local task's stored events.
func (s *Store) OutboundTaskEvents(ctx context.Context, peer, id string, after, limit int64) ([]TaskEvent, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	if _, err := s.OutboundTask(ctx, peer, id); err != nil {
		return nil, err
	}
	return taskEvents(ctx, s.db, `SELECT record FROM outbound_task_events WHERE peer = ? AND task_id = ? AND sequence > ? ORDER BY sequence LIMIT ?`, peer, id, after, limit)
}

// PrepareOutboundTask persists an owner submission before any network
// attempt. Without a grant it cites the target host's owner's policy. A
// delegation depth creates link 0 of a chain; a parent forwards a running
// received task, extending its chain.
func (s *Store) PrepareOutboundTask(ctx context.Context, r SubmitTask) (OutboundTask, error) {
	if r.TaskID == "" {
		id, err := newID("task")
		if err != nil {
			return OutboundTask{}, err
		}
		r.TaskID = id
	}
	forward := r.Parent != nil
	if r.DelegationDepth < 0 || r.DelegationDepth > membership.DelegationMaxDepth || (r.DelegationDepth == 0 && r.DelegationPrincipals != nil) || (forward && r.DelegationDepth != 0) {
		return OutboundTask{}, fmt.Errorf("%w: delegation_depth is 0 to 2, delegation_principals needs a nonzero depth, and a forwarded task takes neither", ErrInvalid)
	}
	var principals []string
	if r.DelegationDepth > 0 {
		if r.Origin == nil {
			return OutboundTask{}, fmt.Errorf("%w: delegation needs an originating agent (--from-agent)", ErrInvalid)
		}
		var err error
		if principals, err = delegationPrincipals(r.DelegationPrincipals); err != nil {
			return OutboundTask{}, err
		}
	}
	if err := s.checkLocalOrigin(ctx, r.Origin); err != nil {
		return OutboundTask{}, err
	}
	request := TaskRequest{TaskID: r.TaskID, GrantID: r.GrantID, TargetAgentID: r.TargetAgentID, Deadline: r.Deadline, Input: r.Input, Origin: r.Origin, Artifacts: emptyAsNone(r.Artifacts)}
	old, err := s.OutboundTask(ctx, r.PeerHostID, r.TaskID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return old, err
	}
	exists := err == nil
	// A resubmission keeps its original default deadline and citation.
	if exists && r.Deadline == "" {
		request.Deadline = old.Request.Deadline
	}
	if exists && request.GrantID == nil {
		request.Policy, request.Self = old.Request.Policy, old.Request.Self
	}
	if !exists {
		if _, err := s.KnownHost(ctx, r.PeerHostID, nil); err != nil {
			return OutboundTask{}, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundTask{}, err
	}
	defer tx.Rollback()
	var parent TaskRequest
	var parentStatus TaskStatus
	if forward {
		if parent, parentStatus, err = receivedTask(ctx, tx, r.Parent.SenderHostID, r.Parent.TaskID); err != nil {
			return OutboundTask{}, err
		}
		// The forwarding agent is the one working on the parent task.
		if request.Origin == nil {
			request.Origin = &Origin{AgentID: parent.TargetAgentID}
		} else if request.Origin.AgentID != parent.TargetAgentID {
			return OutboundTask{}, fmt.Errorf("%w: a forwarded task originates from the parent task's agent", ErrForbidden)
		}
	}
	deadline := time.Now().Add(taskDefaultDeadline)
	if request.GrantID == nil && request.Policy == nil && request.Self == nil {
		originator := s.identity.ID
		if forward && len(parent.Delegation) > 0 {
			originator = parent.Delegation[0].IssuerHostID
		}
		c, err := s.chainCitation(ctx, tx, r.PeerHostID, originator)
		if r.cite != nil && originator == s.identity.ID {
			c, err = *r.cite, nil // chosen from the directory
		}
		if err != nil {
			return OutboundTask{}, err
		}
		request.Policy, request.Self = c.policy, c.self
		if c.policy != nil && c.until.Before(deadline) {
			deadline = c.until
		}
	}
	if request.Deadline == "" {
		request.Deadline = timestamp(deadline)
	}
	switch {
	case forward:
		err = forwardDeadline(&request, parent, r.Deadline != "")
	case r.DelegationDepth > 0:
		request.Deadline, err = utcDeadline(request.Deadline)
	}
	if err != nil {
		return OutboundTask{}, err
	}
	if err := validateTask(request); err != nil {
		return OutboundTask{}, err
	}
	if exists {
		if forward {
			sent := old.Request
			sent.Delegation = nil
			if old.Parent == nil || *old.Parent != *r.Parent || !sent.same(request) || old.AdapterID != nil {
				return old, ErrConflict
			}
			return old, nil
		}
		if r.DelegationDepth > 0 {
			link, err := s.firstLink(ctx, tx, r.PeerHostID, request, r.DelegationDepth, principals)
			if err != nil {
				return old, err
			}
			request.Delegation = []membership.Link{link}
		}
		if !old.Request.same(request) || old.AdapterID != nil || old.Parent != nil {
			return old, ErrConflict
		}
		return old, nil
	}
	switch {
	case forward:
		if err = s.checkForward(ctx, tx, parent, parentStatus, r.PeerHostID); err != nil {
			return OutboundTask{}, err
		}
		request.Delegation = append(append([]membership.Link{}, parent.Delegation...), s.nextLink(parent.Delegation, r.PeerHostID, request))
	case r.DelegationDepth > 0:
		link, err := s.firstLink(ctx, tx, r.PeerHostID, request, r.DelegationDepth, principals)
		if err != nil {
			return OutboundTask{}, err
		}
		request.Delegation = []membership.Link{link}
	}
	if err = requireStored(ctx, tx, request.Artifacts); err != nil {
		return OutboundTask{}, err
	}
	out := OutboundTask{PeerHostID: r.PeerHostID, To: r.To, Request: request, SubmitState: submitUnknown, NextAttemptAt: s.initialAttempt(), Parent: r.Parent, Delegation: request.Delegation}
	if err = insertOutboundTask(ctx, tx, out); err != nil {
		if isUniqueViolation(err) {
			return out, ErrConflict
		}
		return out, err
	}
	if forward {
		if err = recordForward(ctx, tx, *r.Parent, out); err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}

func isUniqueViolation(err error) bool {
	return err != nil && bytes.Contains([]byte(err.Error()), []byte("UNIQUE constraint failed"))
}

func insertOutboundTask(ctx context.Context, tx *sql.Tx, out OutboundTask) error {
	if err := putJSON(ctx, tx, `INSERT INTO outbound_tasks (record, peer, task_id) VALUES (?, ?, ?)`, out.persisted(), out.PeerHostID, out.Request.TaskID); err != nil {
		return err
	}
	if err := insertArtifacts(ctx, tx, sideSent, out.PeerHostID, out.Request.TaskID, directionInput, out.Request.Artifacts, artifactStored); err != nil {
		return err
	}
	return appendEvent(ctx, tx, "task.submitted", taskSubject(out.PeerHostID, out.Request.TaskID), timestamp(time.Now()))
}

// updateOutboundTask applies a change to the stored record in one
// transaction. The change may add task.updated activity by returning true.
func (s *Store) updateOutboundTask(ctx context.Context, peer, id string, change func(tx *sql.Tx, out *OutboundTask) (int, error)) (OutboundTask, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundTask{}, err
	}
	defer tx.Rollback()
	out, err := readJSON[OutboundTask](tx.QueryRowContext(ctx, `SELECT record FROM outbound_tasks WHERE peer = ? AND task_id = ?`, peer, id))
	if err != nil {
		return out, err
	}
	updates, err := change(tx, &out)
	if err != nil {
		return out, err
	}
	if err = putJSON(ctx, tx, `UPDATE outbound_tasks SET record = ? WHERE peer = ? AND task_id = ?`, out.persisted(), peer, id); err != nil {
		return out, err
	}
	at := timestamp(time.Now())
	for range updates {
		if err = appendEvent(ctx, tx, "task.updated", taskSubject(peer, id), at); err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}

// validTaskStatus checks a receiver's status record for our task.
func (s *Store) validTaskStatus(st TaskStatus, peer string, r TaskRequest) bool {
	_, created := parseTime(st.CreatedAt)
	_, updated := parseTime(st.UpdatedAt)
	return created == nil && updated == nil && st.TaskID == r.TaskID && st.SenderHostID == s.identity.ID && st.ReceiverHostID == peer && st.TargetAgentID == r.TargetAgentID && validTaskState(st.State) && st.LastEvent >= 1
}

// decodeStrict decodes exactly one JSON value without unknown fields.
func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// storeStatus keeps the newest of two status records.
func storeStatus(out *OutboundTask, st TaskStatus) {
	if out.Status == nil || st.LastEvent >= out.Status.LastEvent {
		out.Status = &st
	}
}

// ExchangeTask makes one submission attempt for an unknown record, or a
// status query once the deadline has passed (statusOnly).
func (s *Store) ExchangeTask(ctx context.Context, peerID, id string, statusOnly bool) (OutboundTask, error) {
	unlock, err := s.lockOutbound(ctx, taskKey(peerID, id))
	if err != nil {
		return OutboundTask{}, err
	}
	defer unlock()
	out, err := s.OutboundTask(ctx, peerID, id)
	if err != nil || out.SubmitState != submitUnknown {
		return out, err
	}
	peer, err := s.dialPeer(ctx, peerID)
	if err != nil {
		return out, err
	}
	method, path := http.MethodPost, "/peer/v1/tasks"
	var body []byte
	if statusOnly {
		method, path = http.MethodGet, "/peer/v1/tasks/"+id
	} else if body, err = json.Marshal(out.Request); err != nil {
		return out, err
	}
	state := submitUnknown
	var status *TaskStatus
	code, data, err := s.peerRequest(ctx, peer, method, path, body)
	switch {
	case err != nil:
	case code == 200:
		var st TaskStatus
		if err = decodeStrict(data, &st); err == nil && !s.validTaskStatus(st, peerID, out.Request) {
			err = errors.New("invalid peer task status")
		}
		if err == nil {
			state, status = submitAccepted, &st
		}
	case statusOnly && code == 404:
		err = errors.New("the receiver has no record of this task")
	default:
		if !statusOnly && (code == 400 || code == 403 || code == 404 || code == 409) {
			state = submitRejected
		}
		err = fmt.Errorf("peer returned HTTP %d%s", code, refusalHint(out.Request.asMessage(), code))
	}
	var failure *string
	if err != nil {
		message := err.Error()
		failure = &message
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return s.updateOutboundTask(finishCtx, peerID, id, func(_ *sql.Tx, out *OutboundTask) (int, error) {
		if out.SubmitState != submitUnknown {
			return 0, nil
		}
		out.Attempts++
		out.SubmitState, out.Error = state, failure
		if status != nil {
			storeStatus(out, *status)
		}
		out.NextAttemptAt = s.nextAttempt(out.SubmitState, out.Request.Deadline, out.Attempts, &out.StatusQueries, statusOnly)
		if state != submitUnknown {
			return 1, nil
		}
		return 0, nil
	})
}

// pollTask sends a pending cancellation request, then fetches the status and
// any new events. It reports whether anything new was stored.
func (s *Store) pollTask(ctx context.Context, peerID, id string) (bool, error) {
	unlock, err := s.lockOutbound(ctx, taskKey(peerID, id))
	if err != nil {
		return false, err
	}
	defer unlock()
	out, err := s.OutboundTask(ctx, peerID, id)
	if err != nil || out.SubmitState != submitAccepted {
		return false, err
	}
	peer, err := s.dialPeer(ctx, peerID)
	if err != nil {
		return false, err
	}
	progressed := false
	if out.CancelState != nil && *out.CancelState == cancelUnknown && (out.Status == nil || !taskFinal(out.Status.State)) {
		if err = s.sendTaskCancel(ctx, peer, out); err != nil {
			return false, err
		}
		progressed = true
	}
	if out, err = s.OutboundTask(ctx, peerID, id); err != nil || !out.needsPoll() {
		return progressed, err
	}
	code, data, err := s.peerRequest(ctx, peer, http.MethodGet, "/peer/v1/tasks/"+id, nil)
	if err != nil {
		return progressed, err
	}
	var st TaskStatus
	if code != 200 {
		return progressed, fmt.Errorf("peer returned HTTP %d", code)
	}
	if err = decodeStrict(data, &st); err != nil || !s.validTaskStatus(st, peerID, out.Request) {
		return progressed, errors.New("invalid peer task status")
	}
	cursor := out.EventsAfter
	var events []TaskEvent
	for cursor < st.LastEvent {
		code, data, err = s.peerRequest(ctx, peer, http.MethodGet, fmt.Sprintf("/peer/v1/tasks/%s/events?after=%d&limit=1000", id, cursor), nil)
		if err != nil {
			break
		}
		var page []TaskEvent
		if code != 200 || decodeStrict(data, &page) != nil || len(page) == 0 {
			err = errors.New("invalid peer task events")
			break
		}
		for _, e := range page {
			if !validTaskEventRecord(e, cursor+1) {
				err = errors.New("invalid peer task event")
				break
			}
			cursor = e.Sequence
			events = append(events, e)
		}
		if err != nil {
			break
		}
	}
	// Store what arrived intact, even if a later page failed.
	storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	stored := 0
	_, storeErr := s.updateOutboundTask(storeCtx, peerID, id, func(tx *sql.Tx, out *OutboundTask) (int, error) {
		for _, e := range events {
			if e.Sequence != out.EventsAfter+1 {
				continue
			}
			if err := putJSON(storeCtx, tx, `INSERT INTO outbound_task_events (record, peer, task_id, sequence) VALUES (?, ?, ?, ?)`, e, peerID, id, e.Sequence); err != nil {
				return 0, err
			}
			// Results are fetched once the final event is stored.
			if err := insertArtifacts(storeCtx, tx, sideSent, peerID, id, directionResult, e.Artifacts, artifactPending); err != nil {
				return 0, err
			}
			out.EventsAfter = e.Sequence
			stored++
		}
		storeStatus(out, st)
		return stored, nil
	})
	if storeErr != nil {
		return progressed, storeErr
	}
	return progressed || stored > 0, err
}

func validTaskEventRecord(e TaskEvent, sequence int64) bool {
	_, err := parseTime(e.CreatedAt)
	return err == nil && e.Sequence == sequence && validTaskEventKind(e.Kind) && validTaskState(e.State) &&
		(e.Message == nil || validText(*e.Message, true)) && (e.Output == nil || validText(*e.Output, true)) &&
		(e.Artifacts == nil || ((e.Kind == TaskSucceeded || e.Kind == TaskFailed) && validManifest(e.Artifacts)))
}

// sendTaskCancel posts the cancellation request once; a confirmed status
// marks it sent. Callers hold the record's lock.
func (s *Store) sendTaskCancel(ctx context.Context, peer Peer, out OutboundTask) error {
	id := out.Request.TaskID
	code, data, err := s.peerRequest(ctx, peer, http.MethodPost, "/peer/v1/tasks/"+id+"/cancel", []byte("{}"))
	if err == nil && code != 200 {
		err = fmt.Errorf("peer returned HTTP %d", code)
	}
	var st TaskStatus
	if err == nil && (decodeStrict(data, &st) != nil || !s.validTaskStatus(st, peer.ID, out.Request)) {
		err = errors.New("invalid peer task status")
	}
	if err != nil {
		return err
	}
	storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err = s.updateOutboundTask(storeCtx, peer.ID, id, func(_ *sql.Tx, out *OutboundTask) (int, error) {
		sent := cancelSent
		out.CancelState = &sent
		storeStatus(out, st)
		return 0, nil
	})
	return err
}

// CancelOutboundTask records the owner's cancellation request and sends it
// now if the receiver accepted the task; an uncertain send is retried by the
// poll workers. A rejected submission or final task is returned unchanged.
func (s *Store) CancelOutboundTask(ctx context.Context, peerID, id string) (OutboundTask, error) {
	out, err := s.updateOutboundTask(ctx, peerID, id, func(_ *sql.Tx, out *OutboundTask) (int, error) {
		if out.SubmitState == submitRejected || (out.Status != nil && taskFinal(out.Status.State)) || out.CancelState != nil {
			return 0, nil
		}
		state := cancelUnknown
		out.CancelState = &state
		return 0, nil
	})
	if err != nil || out.SubmitState != submitAccepted || out.CancelState == nil || *out.CancelState != cancelUnknown || (out.Status != nil && taskFinal(out.Status.State)) {
		return out, err
	}
	unlock, err := s.lockOutbound(ctx, taskKey(peerID, id))
	if err != nil {
		return out, err
	}
	if peer, err := s.dialPeer(ctx, peerID); err == nil {
		_ = s.sendTaskCancel(ctx, peer, out)
	}
	unlock()
	s.schedulePoll(taskKey(peerID, id), true)
	return s.OutboundTask(ctx, peerID, id)
}

func (s *Store) pollDue(key string, now time.Time) bool {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	p, ok := s.tasks.poll[key]
	return !ok || !p.at.After(now)
}

// schedulePoll sets the next poll: one second after progress, otherwise
// doubling up to a minute.
func (s *Store) schedulePoll(key string, progressed bool) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if s.tasks.poll == nil {
		s.tasks.poll = map[string]taskPoll{}
	}
	p := s.tasks.poll[key]
	switch {
	case progressed || p.delay == 0:
		p.delay = taskPollFirst
	default:
		p.delay = min(p.delay*2, taskPollMax)
	}
	p.at = time.Now().Add(p.delay)
	s.tasks.poll[key] = p
}

func (s *Store) pendingTasks(ctx context.Context) ([]OutboundTask, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM outbound_tasks WHERE json_extract(record, '$.submit_state') != 'rejected' ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []OutboundTask
	for rows.Next() {
		out, err := readJSON[OutboundTask](rows)
		if err != nil {
			return nil, err
		}
		if out.SubmitState == submitUnknown || out.needsPoll() {
			items = append(items, out)
		}
	}
	return items, rows.Err()
}

// spreadOverdueTasks reschedules unknown submissions that came due while the
// daemon was down across the startup window.
func (s *Store) spreadOverdueTasks(ctx context.Context) error {
	items, err := s.pendingTasks(ctx)
	if err != nil {
		return err
	}
	now := s.retryNow()
	var overdue []OutboundTask
	for _, out := range items {
		if attemptDue(out.SubmitState, out.NextAttemptAt, out.Attempts, now) {
			overdue = append(overdue, out)
		}
	}
	sort.Slice(overdue, func(i, j int) bool {
		return taskKey(overdue[i].PeerHostID, overdue[i].Request.TaskID) < taskKey(overdue[j].PeerHostID, overdue[j].Request.TaskID)
	})
	for i, out := range overdue {
		at := timestamp(now.Add(retryStartupSpread * time.Duration(i) / time.Duration(len(overdue))))
		if _, err = s.updateOutboundTask(ctx, out.PeerHostID, out.Request.TaskID, func(_ *sql.Tx, o *OutboundTask) (int, error) {
			if o.SubmitState == submitUnknown {
				o.NextAttemptAt = &at
			}
			return 0, nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// retryTask makes one automatic submission attempt, or a status query after
// the deadline.
func (s *Store) retryTask(ctx context.Context, out OutboundTask) {
	current, err := s.OutboundTask(ctx, out.PeerHostID, out.Request.TaskID)
	if err != nil || !attemptDue(current.SubmitState, current.NextAttemptAt, current.Attempts, s.retryNow()) {
		return
	}
	deadline, err := parseTime(current.Request.Deadline)
	if err != nil {
		return
	}
	statusOnly := !s.retryNow().Before(deadline)
	if _, err = s.ExchangeTask(ctx, current.PeerHostID, current.Request.TaskID, statusOnly); err != nil && ctx.Err() == nil {
		// The attempt failed before reaching the peer: reschedule without
		// counting it, as for messages.
		message := err.Error()
		next := current.Attempts + 1
		queries := current.StatusQueries
		at := s.nextAttempt(current.SubmitState, current.Request.Deadline, next, &queries, false)
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = s.updateOutboundTask(finishCtx, current.PeerHostID, current.Request.TaskID, func(_ *sql.Tx, o *OutboundTask) (int, error) {
			if o.SubmitState == submitUnknown {
				o.NextAttemptAt, o.Error = at, &message
			}
			return 0, nil
		})
	}
}

// RunTaskWorkers retries uncertain submissions and polls accepted tasks
// until they are final, with at most four jobs in flight.
func (s *Store) RunTaskWorkers(ctx context.Context) {
	if err := s.spreadOverdueTasks(ctx); err != nil && ctx.Err() != nil {
		return
	}
	slots := make(chan struct{}, taskWorkers)
	var running sync.WaitGroup
	defer running.Wait()
	ticker := time.NewTicker(retryPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		items, err := s.pendingTasks(ctx)
		if err != nil {
			continue
		}
		now := s.retryNow()
		for _, out := range items {
			key := taskKey(out.PeerHostID, out.Request.TaskID)
			submit := out.SubmitState == submitUnknown
			if s.inflightOutbound(key) || (submit && !attemptDue(out.SubmitState, out.NextAttemptAt, out.Attempts, now)) || (!submit && !s.pollDue(key, time.Now())) {
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			running.Add(1)
			go func(out OutboundTask) {
				defer running.Done()
				defer func() { <-slots }()
				if submit {
					s.retryTask(ctx, out)
					return
				}
				progressed, _ := s.pollTask(ctx, out.PeerHostID, out.Request.TaskID)
				s.schedulePoll(key, progressed)
			}(out)
		}
		for _, row := range s.fetchJobs(ctx) {
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			// Claimed before the job starts, so the next tick skips it.
			if !s.beginFetch(row.SHA256) {
				<-slots
				continue
			}
			key := fetchKey(row)
			running.Add(1)
			go func(row taskArtifact) {
				defer running.Done()
				defer func() { <-slots }()
				defer s.endFetch(row.SHA256)
				stored, _ := s.fetchArtifact(ctx, row)
				if !stored {
					s.backoffFetch(key)
				}
			}(row)
		}
	}
}

// backoffFetch doubles a failed fetch's delay, from 1 second up to a minute.
func (s *Store) backoffFetch(key string) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if s.tasks.poll == nil {
		s.tasks.poll = map[string]taskPoll{}
	}
	p := s.tasks.poll[key]
	p.delay = max(taskPollFirst, min(p.delay*2, taskPollMax))
	p.at = time.Now().Add(p.delay)
	s.tasks.poll[key] = p
}

// PrepareAdapterTask persists an agent's submission through a task.submit
// route, bound to its credential and session, before any network attempt.
func (s *Store) PrepareAdapterTask(ctx context.Context, auth AdapterAuth, r AdapterDelegate) (OutboundTask, error) {
	r.Artifacts = emptyAsNone(r.Artifacts)
	if r.To != nil {
		return s.prepareAddressTask(ctx, auth, r)
	}
	if r.Network != "" {
		return OutboundTask{}, ErrInvalid
	}
	if !validRouteName(r.Destination) || !validID(r.TaskID, "task", 16) || !validText(r.Input, false) || (r.Artifacts != nil && !validManifest(r.Artifacts)) || (r.ParentTaskID != "" && !validID(r.ParentTaskID, "task", 16)) {
		return OutboundTask{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundTask{}, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return OutboundTask{}, err
	}
	route, err := readJSON[OutboundRoute](tx.QueryRowContext(ctx, `SELECT record FROM adapter_routes WHERE adapter_id = ? AND name = ?`, a.ID, r.Destination))
	if errors.Is(err, ErrNotFound) {
		err = ErrForbidden
	}
	if err != nil {
		return OutboundTask{}, err
	}
	exp, err := parseTime(route.ExpiresAt)
	if err != nil {
		return OutboundTask{}, err
	}
	if route.RevokedAt != nil || route.Action != membership.PolicyActionTask || !exp.After(time.Now()) || int64(len(r.Input)) > route.MaxMessageBytes {
		return OutboundTask{}, ErrForbidden
	}
	var reused bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM outbound_tasks WHERE task_id = ? AND json_extract(record, '$.adapter_id') = ? AND json_extract(record, '$.route_id') IS NOT ?)`, r.TaskID, a.ID, route.ID).Scan(&reused); err != nil {
		return OutboundTask{}, err
	}
	if reused {
		return OutboundTask{}, ErrConflict
	}
	old, err := readJSON[OutboundTask](tx.QueryRowContext(ctx, `SELECT record FROM outbound_tasks WHERE peer = ? AND task_id = ?`, route.PeerHostID, r.TaskID))
	if err == nil {
		switch {
		case old.AdapterID == nil:
			return old, ErrConflict
		case *old.AdapterID != a.ID || old.Request.Origin == nil || old.Request.Origin.SessionID != ss.ID:
			return old, ErrForbidden
		case old.RouteID == nil || *old.RouteID != route.ID || old.Request.Input != r.Input || !sameManifest(old.Request.Artifacts, r.Artifacts) || (old.Parent == nil) != (r.ParentTaskID == "") || (old.Parent != nil && old.Parent.TaskID != r.ParentTaskID):
			return old, ErrConflict
		}
		return old, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return old, err
	}
	// A forward names a task this session claimed, still running.
	var parent *TaskParent
	var parentRequest TaskRequest
	if r.ParentTaskID != "" {
		d, request, st, err := ownedTask(ctx, tx, auth, r.ParentTaskID)
		if err != nil {
			return old, err
		}
		if err = s.checkForward(ctx, tx, request, st, route.PeerHostID); err != nil {
			return old, err
		}
		parent, parentRequest = &TaskParent{SenderHostID: d.SenderHostID, TaskID: d.TaskID}, request
	}
	var used int64
	if err = tx.QueryRowContext(ctx, `SELECT `+routeUsed+` FROM adapter_routes r WHERE r.id = ?`, route.ID).Scan(&used); err != nil {
		return old, err
	}
	if used >= route.MaxMessages {
		return old, ErrForbidden
	}
	deadline := time.Now().Add(taskDefaultDeadline)
	if exp.Before(deadline) {
		deadline = exp
	}
	var c ownerCitation
	if route.GrantID == nil {
		originator := s.identity.ID
		if parent != nil && len(parentRequest.Delegation) > 0 {
			originator = parentRequest.Delegation[0].IssuerHostID
		}
		if c, err = s.chainCitation(ctx, tx, route.PeerHostID, originator); err != nil {
			return old, err
		}
		if c.policy != nil && c.until.Before(deadline) {
			deadline = c.until
		}
	}
	if err = requireStored(ctx, tx, r.Artifacts); err != nil {
		return old, err
	}
	adapterID, routeID := a.ID, route.ID
	request := TaskRequest{TaskID: r.TaskID, GrantID: route.GrantID, Policy: c.policy, Self: c.self, TargetAgentID: route.TargetAgentID, Deadline: timestamp(deadline), Input: r.Input, Origin: &Origin{AgentID: ss.AgentID, SessionID: ss.ID}, Artifacts: r.Artifacts}
	switch {
	case parent != nil:
		if err = forwardDeadline(&request, parentRequest, false); err != nil {
			return old, err
		}
		request.Delegation = append(append([]membership.Link{}, parentRequest.Delegation...), s.nextLink(parentRequest.Delegation, route.PeerHostID, request))
	case route.DelegationDepth > 0:
		link, err := s.firstLink(ctx, tx, route.PeerHostID, request, route.DelegationDepth, []string{membership.PrincipalNetwork})
		if err != nil {
			return old, err
		}
		request.Delegation = []membership.Link{link}
	}
	out := OutboundTask{PeerHostID: route.PeerHostID, Request: request, SubmitState: submitUnknown, AdapterID: &adapterID, RouteID: &routeID, NextAttemptAt: s.initialAttempt(), Parent: parent, Delegation: request.Delegation}
	if err = insertOutboundTask(ctx, tx, out); err != nil {
		return out, err
	}
	if parent != nil {
		if err = recordForward(ctx, tx, *parent, out); err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}

// AdapterTask is the local record of a task this credential submitted.
func (s *Store) AdapterTask(ctx context.Context, auth AdapterAuth, id string) (OutboundTask, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return OutboundTask{}, err
	}
	defer tx.Rollback()
	a, _, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return OutboundTask{}, err
	}
	return readJSON[OutboundTask](tx.QueryRowContext(ctx, `SELECT record FROM outbound_tasks WHERE task_id = ? AND json_extract(record, '$.adapter_id') = ? ORDER BY rowid LIMIT 1`, id, a.ID))
}

// NextTaskUpdate claims the oldest stored event of a task this credential's
// session submitted that has not been handed to it.
func (s *Store) NextTaskUpdate(ctx context.Context, auth AdapterAuth) (*TaskUpdateHandoff, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return nil, err
	}
	var h TaskUpdateHandoff
	var record string
	err = tx.QueryRowContext(ctx, `SELECT e.peer, e.task_id, e.record FROM outbound_task_events e JOIN outbound_tasks t ON t.peer = e.peer AND t.task_id = e.task_id WHERE json_extract(t.record, '$.adapter_id') = ? AND json_extract(t.record, '$.request.origin.session_id') = ? AND NOT EXISTS (SELECT 1 FROM task_update_notifications n WHERE n.peer = e.peer AND n.task_id = e.task_id AND n.sequence = e.sequence) ORDER BY e.rowid LIMIT 1`, a.ID, ss.ID).Scan(&h.Delivery.PeerHostID, &h.Delivery.TaskID, &record)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(record), &h.Event); err != nil {
		return nil, err
	}
	if h.Delivery.ID, err = newID("notification"); err != nil {
		return nil, err
	}
	at := timestamp(time.Now())
	h.Delivery.Sequence, h.Delivery.AdapterID, h.Delivery.SessionID, h.Delivery.State, h.Delivery.CreatedAt, h.Delivery.UpdatedAt = h.Event.Sequence, a.ID, ss.ID, "unknown", at, at
	if err = putJSON(ctx, tx, `INSERT INTO task_update_notifications (record, id, peer, task_id, sequence) VALUES (?, ?, ?, ?, ?)`, h.Delivery, h.Delivery.ID, h.Delivery.PeerHostID, h.Delivery.TaskID, h.Delivery.Sequence); err != nil {
		return nil, err
	}
	return &h, tx.Commit()
}

// TaskUpdateForwarded acknowledges a task update notification write.
func (s *Store) TaskUpdateForwarded(ctx context.Context, auth AdapterAuth, id string) (TaskUpdateDelivery, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TaskUpdateDelivery{}, err
	}
	defer tx.Rollback()
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err != nil {
		return TaskUpdateDelivery{}, err
	}
	d, err := readJSON[TaskUpdateDelivery](tx.QueryRowContext(ctx, `SELECT record FROM task_update_notifications WHERE id = ? AND json_extract(record, '$.adapter_id') = ? AND json_extract(record, '$.session_id') = ?`, id, a.ID, ss.ID))
	if err != nil || d.State == "forwarded" {
		return d, err
	}
	d.State, d.UpdatedAt = "forwarded", timestamp(time.Now())
	if err = putJSON(ctx, tx, `UPDATE task_update_notifications SET record = ? WHERE id = ?`, d, d.ID); err != nil {
		return d, err
	}
	return d, tx.Commit()
}
