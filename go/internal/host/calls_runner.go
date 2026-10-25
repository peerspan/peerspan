package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Running servers: one instance per source, shared by the source's calls and
// its capabilities that use the source's own credential, and one per
// capability with its own credential. An instance runs at most 4 calls at
// once and stops after 10 minutes with no calls. A running call ends exactly
// once: with the server's response, or uncertain on cancellation, its
// deadline, the server's exit, or a daemon restart.

const (
	instanceConcurrency = 4
	instanceIdle        = 10 * time.Minute
	startFailureWindow  = 10 * time.Minute
	startFailureLimit   = 3
	callSweep           = 250 * time.Millisecond
	callPruneEvery      = time.Minute
)

type toolInstance struct {
	key      string
	target   instanceTarget
	proc     *mcpProcess // nil while starting
	active   int
	lastUsed time.Time
	retired  bool
}

type runningCall struct {
	signal   chan string
	instance *toolInstance
}

// callRuntime is the in-memory state of running servers and calls.
type callRuntime struct {
	mu        sync.Mutex
	instances map[string]*toolInstance
	running   map[string]*runningCall
	failures  map[string][]time.Time
	wake      chan struct{}
}

func (s *Store) callWake() chan struct{} {
	s.calls.mu.Lock()
	defer s.calls.mu.Unlock()
	if s.calls.wake == nil {
		s.calls.wake = make(chan struct{}, 1)
	}
	return s.calls.wake
}

// wakeCalls asks the call dispatcher to look for work now.
func (s *Store) wakeCalls() {
	select {
	case s.callWake() <- struct{}{}:
	default:
	}
}

// signalCall tells a running call's goroutine to stop waiting: the call was
// cancelled or reached its deadline.
func (s *Store) signalCall(sender, id, reason string) {
	s.calls.mu.Lock()
	rc := s.calls.running[callSubject(sender, id)]
	s.calls.mu.Unlock()
	if rc != nil {
		select {
		case rc.signal <- reason:
		default:
		}
	}
}

// retireInstances keeps the instances of an agent's changed or dropped
// sources from taking new calls, so the next call starts from the current
// definition; idle ones stop. Instances of unchanged sources keep running.
func (s *Store) retireInstances(agent string, servers map[string]bool) {
	s.calls.mu.Lock()
	for _, inst := range s.calls.instances {
		if inst.target.agentID == agent && servers[inst.target.server] {
			inst.retired = true
		}
	}
	s.calls.mu.Unlock()
	s.wakeCalls()
}

// retireCapability retires a removed capability's own instance.
func (s *Store) retireCapability(name string) {
	s.calls.mu.Lock()
	for _, inst := range s.calls.instances {
		if inst.target.own != nil && inst.target.own.capability == name {
			inst.retired = true
		}
	}
	s.calls.mu.Unlock()
	s.wakeCalls()
}

// recentFailures counts an instance's start failures in the last 10
// minutes, forgetting older ones.
func (s *Store) recentFailures(key string, now time.Time) int {
	kept := s.calls.failures[key][:0]
	for _, at := range s.calls.failures[key] {
		if now.Sub(at) < startFailureWindow {
			kept = append(kept, at)
		}
	}
	s.calls.failures[key] = kept
	return len(kept)
}

// RunCallWorkers dispatches queued calls to server instances, expires
// overdue calls, stops idle instances, and applies record retention, until
// ctx ends; then it stops every instance.
func (s *Store) RunCallWorkers(ctx context.Context) {
	s.calls.mu.Lock()
	if s.calls.instances == nil {
		s.calls.instances, s.calls.running, s.calls.failures = map[string]*toolInstance{}, map[string]*runningCall{}, map[string][]time.Time{}
	}
	s.calls.mu.Unlock()
	wake := s.callWake()
	ticker := time.NewTicker(callSweep)
	defer ticker.Stop()
	var calls sync.WaitGroup
	defer func() {
		s.calls.mu.Lock()
		var procs []*mcpProcess
		for _, inst := range s.calls.instances {
			if inst.proc != nil {
				procs = append(procs, inst.proc)
			}
		}
		s.calls.mu.Unlock()
		for _, p := range procs {
			p.stop()
		}
		calls.Wait()
	}()
	lastPrune := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-wake:
		}
		if now := time.Now(); now.Sub(lastPrune) > callPruneEvery {
			lastPrune = now
			_ = s.pruneCalls(ctx, now)
		}
		s.dispatchCalls(ctx, &calls)
		s.stopIdle(time.Now())
	}
}

// stopIdle stops instances with no calls for 10 minutes, and retired ones
// with none running.
func (s *Store) stopIdle(now time.Time) {
	s.calls.mu.Lock()
	var stop []*mcpProcess
	for key, inst := range s.calls.instances {
		if inst.proc == nil || inst.active > 0 {
			continue
		}
		if inst.retired || now.Sub(inst.lastUsed) >= instanceIdle {
			stop = append(stop, inst.proc)
			delete(s.calls.instances, key)
		}
	}
	s.calls.mu.Unlock()
	for _, p := range stop {
		go p.stop()
	}
}

type queuedCall struct {
	request CallRequest
	status  receivedCall
}

// queuedCalls reads the queued calls in arrival order, leaving out calls
// whose approval is pending: they are never started, start no instance,
// and take no slot.
func (s *Store) queuedCalls(ctx context.Context) ([]queuedCall, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT request, record FROM received_calls WHERE json_extract(record, '$.state') = 'queued' AND json_extract(record, '$.approval.state') IS NOT 'pending' ORDER BY rowid LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var queued []queuedCall
	for rows.Next() {
		var request, record string
		var q queuedCall
		if rows.Scan(&request, &record) != nil || json.Unmarshal([]byte(request), &q.request) != nil || json.Unmarshal([]byte(record), &q.status) != nil {
			continue
		}
		queued = append(queued, q)
	}
	return queued, rows.Err()
}

// dispatchCalls starts queued calls on instances with a free slot, starting
// instances as needed. A call whose capability no longer resolves goes
// straight to the recheck, which rejects it.
func (s *Store) dispatchCalls(ctx context.Context, calls *sync.WaitGroup) {
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	if err = expireCalls(ctx, tx, now); err != nil || tx.Commit() != nil {
		tx.Rollback()
		return
	}
	queued, err := s.queuedCalls(ctx)
	if err != nil {
		return
	}
	for _, q := range queued {
		target, err := s.resolveCallTarget(ctx, s.db, q.request)
		if err != nil {
			_, _ = s.startCall(ctx, q)
			continue
		}
		key := target.key()
		s.calls.mu.Lock()
		if s.recentFailures(key, now) >= startFailureLimit {
			s.calls.mu.Unlock()
			s.failQueued(ctx, key)
			continue
		}
		inst := s.calls.instances[key]
		if inst != nil && inst.retired {
			// A retired instance finishes its calls under another key.
			delete(s.calls.instances, key)
			s.calls.instances[key+"#retired#"+time.Now().String()] = inst
			inst = nil
		}
		if inst == nil {
			inst = &toolInstance{key: key, target: target, lastUsed: now}
			s.calls.instances[key] = inst
			s.calls.mu.Unlock()
			go s.startInstance(ctx, inst)
			continue
		}
		if inst.proc == nil || inst.active >= instanceConcurrency {
			s.calls.mu.Unlock()
			continue
		}
		inst.active++
		// Registered first, so a cancellation that follows the start finds it.
		rc := &runningCall{signal: make(chan string, 1), instance: inst}
		subject := callSubject(q.status.SenderHostID, q.status.CallID)
		s.calls.running[subject] = rc
		s.calls.mu.Unlock()
		started, err := s.startCall(ctx, q)
		if err != nil || !started {
			s.calls.mu.Lock()
			inst.active--
			delete(s.calls.running, subject)
			s.calls.mu.Unlock()
			continue
		}
		calls.Add(1)
		go func() {
			defer calls.Done()
			s.executeCall(ctx, inst, rc, q)
		}()
	}
}

// startCall rechecks the call's authorization and moves it to running. A
// recoverable denial leaves it queued; any other rejects it.
func (s *Store) startCall(ctx context.Context, q queuedCall) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := time.Now()
	c, err := readReceivedCall(ctx, tx, q.status.SenderHostID, q.status.CallID)
	if err != nil || c.State != CallQueued || (c.Approval != nil && c.Approval.State == ApprovalPending) {
		return false, err
	}
	if deadline, err := parseTime(q.request.Deadline); err == nil && !deadline.After(now) {
		if err = finishCall(ctx, tx, &c, CallExpired, nil, now); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	if _, _, err = s.callAuthority(ctx, tx, c.SenderHostID, q.request, now, false); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return false, nil
		}
		var coded *codedError
		if !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalid) && !errors.As(err, &coded) {
			return false, err
		}
		reason := callLapsed
		if err = finishCall(ctx, tx, &c, CallRejected, &reason, now); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	at := timestamp(now)
	c.State, c.StartedAt = CallRunning, &at
	if err = writeReceivedCall(ctx, tx, c); err != nil {
		return false, err
	}
	if err = appendEvent(ctx, tx, "call.started", callSubject(c.SenderHostID, c.CallID), at); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// failQueued fails every queued call of an instance with server_start_failed.
func (s *Store) failQueued(ctx context.Context, key string) {
	queued, err := s.queuedCalls(ctx)
	if err != nil {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	failure := callServerStartFailed
	now := time.Now()
	for _, q := range queued {
		target, err := s.resolveCallTarget(ctx, tx, q.request)
		if err != nil || target.key() != key {
			continue
		}
		c := q.status
		if finishCall(ctx, tx, &c, CallFailed, &failure, now) != nil {
			return
		}
	}
	_ = tx.Commit()
}

// startInstance starts a server instance and completes initialize within 30
// seconds; on failure its waiting calls fail with server_start_failed.
func (s *Store) startInstance(ctx context.Context, inst *toolInstance) {
	spec, err := s.toolLaunch(ctx, s.db, inst.target.agentID, inst.target.server, inst.target.own)
	var p *mcpProcess
	if err == nil {
		p, err = startMCP(spec)
	}
	if err == nil {
		startCtx, cancel := context.WithTimeout(ctx, instanceStartTime)
		_, err = p.initialize(startCtx)
		cancel()
		if err != nil {
			p.logf("initialize did not complete: %v", err)
			p.stop()
		}
	}
	now := time.Now()
	if err != nil {
		s.calls.mu.Lock()
		if s.calls.instances[inst.key] == inst {
			delete(s.calls.instances, inst.key)
		}
		s.calls.failures[inst.key] = append(s.calls.failures[inst.key], now)
		s.calls.mu.Unlock()
		s.noteServer(context.WithoutCancel(ctx), inst.target, func(st *toolSnapshotState) {
			at := timestamp(now)
			st.StartFailedAt = &at
		})
		if ctx.Err() == nil {
			s.failQueued(context.WithoutCancel(ctx), inst.key)
		}
		return
	}
	p.mu.Lock()
	p.late = func(id int64) { p.logf("discarded the response to request %d, which arrived after its call ended", id) }
	p.mu.Unlock()
	s.calls.mu.Lock()
	inst.proc, inst.lastUsed = p, now
	s.calls.mu.Unlock()
	go func() {
		<-p.done
		s.calls.mu.Lock()
		for key, i := range s.calls.instances {
			if i == inst {
				delete(s.calls.instances, key)
			}
		}
		s.calls.mu.Unlock()
		s.wakeCalls()
	}()
	s.wakeCalls()
}

// noteServer updates the health fields of a source, or of a capability's
// own instance.
func (s *Store) noteServer(ctx context.Context, target instanceTarget, change func(*toolSnapshotState)) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	if target.own == nil {
		if found, err := updateSourceState(ctx, tx, target.agentID, target.server, change); err != nil || !found {
			return
		}
	} else {
		c, err := readCapability(ctx, tx, target.own.capability)
		if err != nil {
			return
		}
		if c.Snapshot == nil {
			c.Snapshot = &toolSnapshotState{}
		}
		change(c.Snapshot)
		if err = putJSON(ctx, tx, `UPDATE capabilities SET record = ? WHERE name = ?`, c, c.Name); err != nil {
			return
		}
	}
	_ = tx.Commit()
}

// authHint matches JSON-RPC error messages that suggest authentication.
var authHint = regexp.MustCompile(`(?i)auth|401|403|token`)

// executeCall sends the call to its instance and ends it exactly once.
func (s *Store) executeCall(ctx context.Context, inst *toolInstance, rc *runningCall, q queuedCall) {
	sender, id := q.status.SenderHostID, q.status.CallID
	defer func() {
		s.calls.mu.Lock()
		delete(s.calls.running, callSubject(sender, id))
		inst.active--
		inst.lastUsed = time.Now()
		s.calls.mu.Unlock()
		s.wakeCalls()
	}()
	p := inst.proc
	method, params := "tools/call", map[string]any{"name": q.request.Operation, "arguments": q.request.Input}
	if q.request.Operation == membership.OperationRead {
		method, params = "resources/read", map[string]any{"uri": q.request.readURI()}
	}
	finish := func(state string, failure *string, result json.RawMessage, size *int64) {
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		tx, err := s.db.BeginTx(finishCtx, nil)
		if err != nil {
			return
		}
		defer tx.Rollback()
		c, err := readReceivedCall(finishCtx, tx, sender, id)
		if err != nil {
			return
		}
		if c.State != CallRunning {
			if result != nil || size != nil {
				p.logf("discarded the result of call %s, which had already ended %s", id, c.State)
			}
			return
		}
		c.StoredResult, c.ResultBytes = result, size
		if finishCall(finishCtx, tx, &c, state, failure, time.Now()) == nil {
			_ = tx.Commit()
		}
	}
	reqID, ch, err := p.send(method, params)
	if err != nil {
		failure := callServerExited
		finish(CallUncertain, &failure, nil, nil)
		return
	}
	deadline, _ := parseTime(q.request.Deadline)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	cancelled := func(reason string) {
		p.forget(reqID)
		_ = p.notify("notifications/cancelled", map[string]any{"requestId": reqID, "reason": reason})
	}
	select {
	case r := <-ch:
		if r.Error != nil && r.Error.Code == ghTooLargeCode && inst.target.agentID == builtinAgent {
			// A built-in source's output over its limit: no result is stored.
			failure := callResultTooLarge
			finish(CallFailed, &failure, nil, nil)
			return
		}
		if r.Error != nil {
			data, _ := json.Marshal(map[string]any{"code": r.Error.Code, "message": r.Error.Message})
			size := int64(len(data))
			failure := callJSONRPCError
			if authHint.MatchString(r.Error.Message) {
				s.noteServer(context.WithoutCancel(ctx), inst.target, func(st *toolSnapshotState) {
					at := timestamp(time.Now())
					st.AuthErrorAt = &at
				})
			}
			finish(CallFailed, &failure, data, &size)
			return
		}
		size := int64(r.Size)
		if size > callMaxResult {
			failure := callResultTooLarge
			finish(CallFailed, &failure, nil, &size)
			return
		}
		var result struct {
			IsError *bool `json:"isError"`
		}
		if q.request.Operation != membership.OperationRead && json.Unmarshal(r.Result, &result) == nil && result.IsError != nil && *result.IsError {
			failure := callToolError
			finish(CallFailed, &failure, r.Result, &size)
			return
		}
		finish(CallSucceeded, nil, r.Result, &size)
	case reason := <-rc.signal:
		cancelled(reason)
		failure := reason
		finish(CallUncertain, &failure, nil, nil)
	case <-timer.C:
		cancelled("deadline")
		failure := callDeadline
		finish(CallUncertain, &failure, nil, nil)
	case <-p.done:
		failure := callServerExited
		finish(CallUncertain, &failure, nil, nil)
	case <-ctx.Done():
		// The daemon is stopping: the call stays running, and the next start
		// records it uncertain.
	}
}

// runningCalls counts received calls now running.
func runningCalls(ctx context.Context, q dbQuerier) (int64, error) {
	var n int64
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM received_calls WHERE json_extract(record, '$.state') = 'running'`).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}
