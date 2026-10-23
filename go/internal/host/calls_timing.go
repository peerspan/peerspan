package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Call timing (owner decision 15): an agent's call request is held at this
// daemon until the call is final or its wait ends, and for a call's first
// 60 seconds after acceptance this daemon holds a status request open at
// the serving host, so a result arrives as soon as it exists.

const (
	// callWaitLimit bounds how long POST /adapter/v1/calls holds its
	// response, and steps 4 to 7 of submitting. It must stay at or below
	// 45 seconds, within the adapter's 50-second request timeout.
	callWaitLimit = 15 * time.Second
	// peerWaitMax is the longest wait GET /peer/v1/calls/{id} accepts, and
	// the wait this daemon asks for.
	peerWaitMax = 10
	// callHeldWindow is how long after acceptance held status requests are
	// used instead of polling.
	callHeldWindow = 60 * time.Second
	// receiverHoldCheck is how often a held peer status request rechecks
	// the call.
	receiverHoldCheck = 50 * time.Millisecond
)

// callTiming is the in-memory state of held requests: the signals of calls
// becoming final here, the acceptance times of calls in their held window,
// the calls with a held status request in flight, and the calls an agent's
// POST is holding.
type callTiming struct {
	finals    map[string]chan struct{}
	accepted  map[string]time.Time
	following map[string]bool
	held      map[string]int
}

// finalSignal is closed when the outbound call's final status is stored.
// Take it before reading the record, so a change in between is not missed.
func (s *Store) finalSignal(key string) <-chan struct{} {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if s.tasks.timing.finals == nil {
		s.tasks.timing.finals = map[string]chan struct{}{}
	}
	ch, ok := s.tasks.timing.finals[key]
	if !ok {
		ch = make(chan struct{})
		s.tasks.timing.finals[key] = ch
	}
	return ch
}

// signalFinal wakes the requests held on an outbound call that just became
// final.
func (s *Store) signalFinal(key string) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if ch, ok := s.tasks.timing.finals[key]; ok {
		close(ch)
		delete(s.tasks.timing.finals, key)
	}
}

// noteCallAccepted starts an accepted call's held window.
func (s *Store) noteCallAccepted(key string, now time.Time) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	if s.tasks.timing.accepted == nil {
		s.tasks.timing.accepted = map[string]time.Time{}
	}
	if _, ok := s.tasks.timing.accepted[key]; !ok {
		s.tasks.timing.accepted[key] = now
	}
}

// inHeldWindow reports whether a call is in its held window, so the poll
// workers leave it to its held status requests.
func (s *Store) inHeldWindow(key string, now time.Time) bool {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	at, ok := s.tasks.timing.accepted[key]
	return ok && now.Sub(at) < callHeldWindow
}

// holdCall marks a call held by an agent's POST; the returned function
// ends the hold.
func (s *Store) holdCall(key string) func() {
	s.tasks.mu.Lock()
	if s.tasks.timing.held == nil {
		s.tasks.timing.held = map[string]int{}
	}
	s.tasks.timing.held[key]++
	s.tasks.mu.Unlock()
	return func() {
		s.tasks.mu.Lock()
		defer s.tasks.mu.Unlock()
		if s.tasks.timing.held[key]--; s.tasks.timing.held[key] <= 0 {
			delete(s.tasks.timing.held, key)
		}
	}
}

// heldCalls lists the calls held by an agent's POST, as PEER/CALL_ID.
func (s *Store) heldCalls() []string {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	list := []string{}
	for key := range s.tasks.timing.held {
		list = append(list, key[len("call:"):])
	}
	return list
}

// startHeldRequests starts, for each call in its held window that has none,
// the goroutine that keeps one held status request open at a time. They do
// not use the task polling slots.
func (s *Store) startHeldRequests(ctx context.Context, items []OutboundCall) {
	now := time.Now()
	for _, out := range items {
		if out.SubmitState != submitAccepted || !out.needsPoll() {
			continue
		}
		key := callKey(out.PeerHostID, out.Request.CallID)
		s.tasks.mu.Lock()
		at, ok := s.tasks.timing.accepted[key]
		start := ok && now.Sub(at) < callHeldWindow && !s.tasks.timing.following[key]
		if start {
			if s.tasks.timing.following == nil {
				s.tasks.timing.following = map[string]bool{}
			}
			s.tasks.timing.following[key] = true
		}
		s.tasks.mu.Unlock()
		if start {
			go s.followCall(ctx, out.PeerHostID, out.Request.CallID, at)
		}
	}
	// Forget windows that have passed.
	s.tasks.mu.Lock()
	for key, at := range s.tasks.timing.accepted {
		if now.Sub(at) >= callHeldWindow && !s.tasks.timing.following[key] {
			delete(s.tasks.timing.accepted, key)
		}
	}
	s.tasks.mu.Unlock()
}

// followCall sends held status requests one at a time, each as soon as the
// previous answers, until the call is final or its window passes. An answer
// in under a second without a final state, as from a host that predates
// wait, is followed by the next request a second later.
func (s *Store) followCall(ctx context.Context, peer, id string, accepted time.Time) {
	key := callKey(peer, id)
	defer func() {
		s.tasks.mu.Lock()
		delete(s.tasks.timing.following, key)
		s.tasks.mu.Unlock()
		// After the window, the poll workers back off as usual.
		s.schedulePoll(key, true)
	}()
	for ctx.Err() == nil && time.Since(accepted) < callHeldWindow {
		out, err := s.OutboundCall(ctx, peer, id)
		if err != nil || !out.needsPoll() {
			return
		}
		started := time.Now()
		_, _ = s.pollCallWait(ctx, peer, id, peerWaitMax)
		if out, err = s.OutboundCall(ctx, peer, id); err != nil || !out.needsPoll() {
			return
		}
		if wait := time.Second - time.Since(started); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}
}

// HeldSubmitterCall is SubmitterCall held until the call's state differs
// from its state when the request arrived (queued to running, or to a final
// state), or wait seconds pass; a call already final, or wait 0, answers at
// once.
func (s *Store) HeldSubmitterCall(ctx context.Context, sender, id string, wait int) (CallStatus, error) {
	until := time.Now().Add(time.Duration(wait) * time.Second)
	arrived := ""
	for {
		st, err := s.SubmitterCall(ctx, sender, id)
		if arrived == "" {
			arrived = st.State
		}
		if err != nil || callFinal(st.State) || st.State != arrived || !time.Now().Before(until) {
			return st, err
		}
		select {
		case <-ctx.Done():
			return st, nil
		case <-time.After(min(receiverHoldCheck, time.Until(until))):
		}
	}
}

// peerWait parses GET /peer/v1/calls/{id}?wait=N: absent is 0, and N is an
// integer from 0 to 10.
func peerWait(r *http.Request) (int, error) {
	given, ok := r.URL.Query()["wait"]
	if !ok {
		return 0, nil
	}
	n, err := strconv.Atoi(given[0])
	if len(given) != 1 || err != nil || n < 0 || n > peerWaitMax {
		return 0, fmt.Errorf("%w: wait is an integer from 0 to %d", ErrInvalid, peerWaitMax)
	}
	return n, nil
}

// holdAgentCall answers an agent's held POST: the call view once the call
// is final, or at until, whichever is first. The call's notification is not
// claimed while the POST holds it.
func (s *Store) holdAgentCall(ctx context.Context, auth AdapterAuth, peer, id string, until time.Time) (CallView, error) {
	key := callKey(peer, id)
	release := s.holdCall(key)
	defer release()
	for {
		signal := s.finalSignal(key)
		v, err := s.AgentCallView(ctx, auth, id, 0)
		if err != nil || callFinal(v.State) || !time.Now().Before(until) {
			return v, err
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-signal:
		case <-time.After(time.Until(until)):
		}
	}
}

// requestWait parses the optional wait of POST /adapter/v1/calls: an
// integer of at least 0, capped at the wait limit, which is also the
// default.
func requestWait(raw json.RawMessage) (time.Duration, error) {
	if raw == nil {
		return callWaitLimit, nil
	}
	text := string(raw)
	if text == "" || strings.Trim(text, "0123456789") != "" || (len(text) > 1 && text[0] == '0') {
		return 0, errors.New("wait is an integer of at least 0")
	}
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil || seconds > int64(callWaitLimit/time.Second) {
		return callWaitLimit, nil // capped at the wait limit
	}
	return time.Duration(seconds) * time.Second, nil
}

// following reports whether a held status request loop runs for a call.
func (s *Store) following(key string) bool {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	return s.tasks.timing.following[key]
}
