package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"sort"
	"sync"
	"time"
)

// Automatic retry of uncertain sends. Receivers deduplicate by sender and
// request ID, so resubmitting the saved request never creates a second message
// or consumes route budget. Attempts stop once the outcome is final, or after
// the deadline once receipt queries are exhausted.
const (
	retryFirst         = time.Second
	retryMax           = 60 * time.Second
	retryRefreshLimit  = 10
	retryGiveUp        = 24 * time.Hour
	retryWorkers       = 4
	retryStartupSpread = 10 * time.Second
	retryPoll          = 250 * time.Millisecond
)

type outboundRetry struct {
	mu       sync.Mutex
	inflight map[string]chan struct{} // one attempt per record at a time
	now      func() time.Time
	jitter   func() float64 // factor in [0.8, 1.2]
}

func outboundKey(peer, id string) string { return peer + "/" + id }

func (s *Store) retryNow() time.Time {
	s.retry.mu.Lock()
	now := s.retry.now
	s.retry.mu.Unlock()
	if now != nil {
		return now()
	}
	return time.Now()
}

func (s *Store) retryJitter() float64 {
	s.retry.mu.Lock()
	jitter := s.retry.jitter
	s.retry.mu.Unlock()
	if jitter != nil {
		return jitter()
	}
	return 0.8 + 0.4*rand.Float64()
}

// lockOutbound serializes attempts on one record: an explicit command waits
// for a running automatic attempt instead of racing it on the same connection.
func (s *Store) lockOutbound(ctx context.Context, key string) (func(), error) {
	for {
		s.retry.mu.Lock()
		if s.retry.inflight == nil {
			s.retry.inflight = map[string]chan struct{}{}
		}
		busy, held := s.retry.inflight[key]
		if !held {
			done := make(chan struct{})
			s.retry.inflight[key] = done
			s.retry.mu.Unlock()
			return func() {
				s.retry.mu.Lock()
				delete(s.retry.inflight, key)
				s.retry.mu.Unlock()
				close(done)
			}, nil
		}
		s.retry.mu.Unlock()
		select {
		case <-busy:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *Store) inflightOutbound(key string) bool {
	s.retry.mu.Lock()
	defer s.retry.mu.Unlock()
	_, held := s.retry.inflight[key]
	return held
}

// scheduleAfterAttempt sets the next automatic attempt for a record whose
// latest attempt left it unknown, or clears it for a final outcome.
func (s *Store) scheduleAfterAttempt(out *OutboundMessage, refresh bool) {
	out.NextAttemptAt = s.nextAttempt(out.State, out.Request.Deadline, out.Attempts, &out.ReceiptQueries, refresh)
}

// nextAttempt is the schedule shared by messages and tasks: the next attempt
// after `attempts` attempts, or nil once the outcome is final or retries stop.
// A query (refresh) at or after the deadline counts toward the query limit.
func (s *Store) nextAttempt(state, deadlineText string, attempts int64, queries *int64, refresh bool) *string {
	now := s.retryNow()
	deadline, err := parseTime(deadlineText)
	if err != nil {
		return nil
	}
	if refresh && !now.Before(deadline) {
		*queries++
	}
	if state != "unknown" || now.After(deadline.Add(retryGiveUp)) || *queries >= retryRefreshLimit {
		return nil
	}
	delay := retryMax
	if attempts >= 1 && attempts <= 7 {
		delay = retryFirst << (attempts - 1)
		if delay > retryMax {
			delay = retryMax
		}
	}
	at := timestamp(now.Add(time.Duration(float64(delay) * s.retryJitter())))
	return &at
}

// initialAttempt is the fallback schedule for a newly queued request. It lies
// past the 8-second inline send bound, so the scheduler never races the inline
// send, which replaces it with the normal backoff once it finishes.
func (s *Store) initialAttempt() *string {
	at := timestamp(s.retryNow().Add(10 * time.Second))
	return &at
}

// due reports whether an unknown record should be attempted at now.
func due(out OutboundMessage, now time.Time) bool {
	return attemptDue(out.State, out.NextAttemptAt, out.Attempts, now)
}

func attemptDue(state string, next *string, attempts int64, now time.Time) bool {
	if state != "unknown" {
		return false
	}
	if next == nil {
		return attempts == 0 // a record from before automatic retry
	}
	at, err := parseTime(*next)
	return err == nil && !at.After(now)
}

func (s *Store) unknownOutbound(ctx context.Context) ([]OutboundMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM outbound_messages WHERE json_extract(record, '$.state') = 'unknown'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []OutboundMessage
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		var out OutboundMessage
		if err = json.Unmarshal([]byte(data), &out); err != nil {
			return nil, err
		}
		items = append(items, out)
	}
	return items, rows.Err()
}

// spreadOverdue reschedules records that came due while the daemon was down
// evenly across the startup window, so a restart does not cause a burst.
func (s *Store) spreadOverdue(ctx context.Context) error {
	items, err := s.unknownOutbound(ctx)
	if err != nil {
		return err
	}
	now := s.retryNow()
	var overdue []OutboundMessage
	for _, out := range items {
		if due(out, now) {
			overdue = append(overdue, out)
		}
	}
	sort.Slice(overdue, func(i, j int) bool {
		return outboundKey(overdue[i].PeerHostID, overdue[i].Request.RequestID) < outboundKey(overdue[j].PeerHostID, overdue[j].Request.RequestID)
	})
	for i, out := range overdue {
		at := timestamp(now.Add(retryStartupSpread * time.Duration(i) / time.Duration(len(overdue))))
		if err = s.updateSchedule(ctx, out.PeerHostID, out.Request.RequestID, &at, nil); err != nil {
			return err
		}
	}
	return nil
}

// updateSchedule changes only the schedule, and optionally the error, of a
// record that is still unknown.
func (s *Store) updateSchedule(ctx context.Context, peer, id string, at *string, failure *string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	out, err := readJSON[OutboundMessage](tx.QueryRowContext(ctx, "SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?", peer, id))
	if err != nil || out.State != "unknown" {
		return err
	}
	out.NextAttemptAt = at
	if failure != nil {
		out.Error = failure
	}
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE outbound_messages SET record = ? WHERE peer = ? AND request_id = ?", string(data), peer, id); err != nil {
		return err
	}
	return tx.Commit()
}

// retryOne makes one automatic attempt: a resubmission before the deadline,
// and a receipt query after it.
func (s *Store) retryOne(ctx context.Context, out OutboundMessage) {
	// An explicit command may have finished the record since it was listed.
	current, err := s.Outbound(ctx, out.PeerHostID, out.Request.RequestID)
	if err != nil || !due(current, s.retryNow()) {
		return
	}
	out = current
	deadline, err := parseTime(out.Request.Deadline)
	if err != nil {
		return
	}
	refresh := !s.retryNow().Before(deadline)
	if _, err = s.Exchange(ctx, out, refresh); err != nil && ctx.Err() == nil {
		// The attempt failed before reaching the peer (for example, no route).
		// It is not a network attempt, so reschedule without counting it, using
		// the backoff for the next attempt number.
		next := out
		next.Attempts++
		s.scheduleAfterAttempt(&next, false)
		message := err.Error()
		finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.updateSchedule(finishCtx, out.PeerHostID, out.Request.RequestID, next.NextAttemptAt, &message)
	}
}

// RunOutboundRetries attempts due unknown records until ctx is cancelled,
// with at most four attempts in flight.
func (s *Store) RunOutboundRetries(ctx context.Context) {
	if err := s.spreadOverdue(ctx); err != nil && ctx.Err() != nil {
		return
	}
	slots := make(chan struct{}, retryWorkers)
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
		items, err := s.unknownOutbound(ctx)
		if err != nil {
			continue
		}
		now := s.retryNow()
		for _, out := range items {
			if !due(out, now) || s.inflightOutbound(outboundKey(out.PeerHostID, out.Request.RequestID)) {
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				continue // all workers busy; the record stays due
			}
			running.Add(1)
			go func(out OutboundMessage) {
				defer running.Done()
				defer func() { <-slots }()
				s.retryOne(ctx, out)
			}(out)
		}
	}
}

// AdapterSendStatus reports a send made with this credential.
type AdapterSendStatus struct {
	RequestID string `json:"request_id"`
	// Destination is the route of a route send; To is the address of a
	// send by address. The other is null.
	Destination   *string `json:"destination"`
	To            *string `json:"to"`
	State         string  `json:"state"`
	Attempts      int64   `json:"attempts"`
	NextAttemptAt *string `json:"next_attempt_at"`
	Error         *string `json:"error"`
}

func (s *Store) AdapterSendStatus(ctx context.Context, token AdapterAuth, id string) (AdapterSendStatus, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AdapterSendStatus{}, err
	}
	defer tx.Rollback()
	a, _, err := adapterAuthority(ctx, tx, token)
	if err != nil {
		return AdapterSendStatus{}, err
	}
	// The send is this credential's, or one whose reply this credential
	// holds after claiming it from an ended authorization of its agent.
	var peer string
	var routeID sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT peer, route_id FROM adapter_outbound WHERE request_id = ?1 AND (adapter_id = ?2 OR (reply_delivery IS NOT NULL AND json_extract(reply_delivery, '$.adapter_id') = ?2 AND reply_returned_at IS NULL)) ORDER BY adapter_id = ?2 DESC LIMIT 1`, id, a.ID).Scan(&peer, &routeID)
	if errors.Is(err, sql.ErrNoRows) {
		return AdapterSendStatus{}, ErrNotFound
	}
	if err != nil {
		return AdapterSendStatus{}, err
	}
	var destination *string
	if routeID.Valid {
		route, err := readJSON[OutboundRoute](tx.QueryRowContext(ctx, `SELECT record FROM adapter_routes WHERE id = ?`, routeID.String))
		if err != nil {
			return AdapterSendStatus{}, err
		}
		destination = &route.Name
	}
	out, err := readJSON[OutboundMessage](tx.QueryRowContext(ctx, `SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?`, peer, id))
	if err != nil {
		return AdapterSendStatus{}, err
	}
	// Naming a send reports its reply seen, when this credential holds it.
	if _, err = tx.ExecContext(ctx, `UPDATE adapter_outbound SET reply_seen_at = ? WHERE peer = ? AND request_id = ? AND reply_delivery IS NOT NULL AND json_extract(reply_delivery, '$.adapter_id') = ? AND reply_returned_at IS NULL AND reply_seen_at IS NULL`, timestamp(time.Now()), peer, id, a.ID); err != nil {
		return AdapterSendStatus{}, err
	}
	return AdapterSendStatus{RequestID: id, Destination: destination, To: out.To, State: out.State, Attempts: out.Attempts, NextAttemptAt: out.NextAttemptAt, Error: out.Error}, tx.Commit()
}
