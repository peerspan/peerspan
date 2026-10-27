package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Delegation chains (milestone 6, slice 4). A task may carry a chain of
// signed links from its originator through every host that passed it on. The
// final receiver verifies the chain and authorizes the originator; a host
// passes a running task on only when the chain and its own authorization
// allow it. The v11 schema is shared with Rust.
const delegationSchema = `
CREATE TABLE task_children (sender TEXT NOT NULL, task_id TEXT NOT NULL, peer TEXT NOT NULL, child_task_id TEXT NOT NULL, PRIMARY KEY(sender, task_id, peer, child_task_id));
PRAGMA user_version = 11;
`

// TaskParent names a received task that a forwarded task continues.
type TaskParent struct {
	SenderHostID string `json:"sender_host_id"`
	TaskID       string `json:"task_id"`
}

func (p *TaskParent) UnmarshalJSON(data []byte) error {
	type plain TaskParent
	if err := membership.Strict(data, (*plain)(p), "sender_host_id", "task_id"); err != nil {
		return ErrInvalid
	}
	if !validID(p.SenderHostID, "host", 32) || !validID(p.TaskID, "task", 16) {
		return ErrInvalid
	}
	return nil
}

// validChain checks a chain's shape: 1 to 3 well-formed links.
func validChain(links []membership.Link) bool {
	if links == nil {
		return true
	}
	if len(links) < 1 || len(links) > membership.DelegationMaxLinks {
		return false
	}
	for _, l := range links {
		if membership.CheckLink(l) != nil {
			return false
		}
	}
	return true
}

func sameChain(a, b []membership.Link) bool {
	return (a == nil) == (b == nil) && reflect.DeepEqual(a, b)
}

// chainFacts is what a verified chain tells authorization.
type chainFacts struct {
	links      []membership.Link
	originator string // link 0's issuer
	agent      string // the originating agent
	// originatorPerson is the person bound to the originator in the chain's
	// network, or nil.
	originatorPerson *string
}

func (c *chainFacts) last() membership.Link { return c.links[len(c.links)-1] }

// delegable reports whether the chain lets the receiving agent pass the task
// on, given that its authorization included task.delegate.
func (c *chainFacts) delegable(a authority) bool {
	return c != nil && a.delegate && c.last().Depth >= 1
}

func chainRefused(format string, args ...any) error {
	return fmt.Errorf("%w: delegation chain: "+format, append([]any{ErrForbidden}, args...)...)
}

func boundIn(members map[string]NetworkMember) func(string) string {
	return func(host string) string {
		if m, ok := members[host]; ok && m.PersonID != nil {
			return *m.PersonID
		}
		return ""
	}
}

// verifyChain checks a request's chain from the authenticated sender at this
// receiver, with current membership, bindings, and blocks. It returns nil
// facts for a request without a chain. Every failure is ErrForbidden.
func (s *Store) verifyChain(ctx context.Context, tx *sql.Tx, sender string, r TaskRequest, now time.Time) (*chainFacts, error) {
	links := r.Delegation
	if len(links) == 0 {
		return nil, nil
	}
	network := links[0].NetworkID
	members, err := s.membersOf(ctx, tx, network)
	if err != nil {
		return nil, err
	}
	// 1. Signatures by current members, and this host is one.
	if _, ok := members[s.identity.ID]; !ok {
		return nil, chainRefused("this host is not a member of its network")
	}
	for k, l := range links {
		if l.NetworkID != network {
			return nil, chainRefused("link %d names another network", k)
		}
		issuer, ok := members[l.IssuerHostID]
		if _, audience := members[l.AudienceHostID]; !ok || !audience {
			return nil, chainRefused("link %d names a host that is not a current member", k)
		}
		key, err := membership.DecodeKey(issuer.PublicKey)
		if err != nil || membership.VerifyLink(key, l) != nil {
			return nil, chainRefused("link %d does not verify", k)
		}
	}
	// 2. Positions and hashes.
	for k, l := range links {
		previous := membership.DelegationNone
		if k > 0 {
			previous = links[k-1].Hash()
		}
		if l.Index != int64(k) || l.Previous != previous {
			return nil, chainRefused("link %d is out of place", k)
		}
	}
	// 3. Each link narrows the one before it.
	bound := boundIn(members)
	for k := 1; k < len(links); k++ {
		l, prev := links[k], links[k-1]
		if l.IssuerHostID != prev.AudienceHostID || l.OriginatorAgentID != prev.OriginatorAgentID {
			return nil, chainRefused("link %d does not continue link %d", k, k-1)
		}
		if !membership.PrincipalsCover(prev.Principals, "host:"+l.AudienceHostID, bound) {
			return nil, chainRefused("link %d's audience is outside link %d's principals", k, k-1)
		}
		for _, p := range l.Principals {
			if !membership.PrincipalsCover(prev.Principals, p, bound) {
				return nil, chainRefused("link %d widens the principals", k)
			}
		}
		at, _ := parseTime(l.Deadline)
		before, _ := parseTime(prev.Deadline)
		if at.After(before) {
			return nil, chainRefused("link %d extends the deadline", k)
		}
		if l.Depth != prev.Depth-1 || l.Depth < 0 {
			return nil, chainRefused("link %d does not reduce the depth by one", k)
		}
	}
	// 4. The last link reaches this request from its sender.
	last := links[len(links)-1]
	if last.IssuerHostID != sender || last.AudienceHostID != s.identity.ID || last.TaskID != r.TaskID || last.Deadline != r.Deadline {
		return nil, chainRefused("the last link does not name this task from its sender")
	}
	for k, l := range links {
		if at, _ := parseTime(l.Deadline); !at.After(now) {
			return nil, chainRefused("link %d has expired", k)
		}
	}
	// 5. Link 0 starts the chain at the originator.
	if links[0].Depth < 1 || links[0].Depth > membership.DelegationMaxDepth {
		return nil, chainRefused("link 0 has depth %d", links[0].Depth)
	}
	if len(links) == 1 && (r.Origin == nil || r.Origin.AgentID != links[0].OriginatorAgentID) {
		return nil, chainRefused("link 0 does not name the request's origin")
	}
	// 6. No participant is blocked.
	for k, l := range links {
		refused, err := s.blocked(ctx, tx, l.IssuerHostID)
		if err != nil {
			return nil, err
		}
		if refused {
			return nil, chainRefused("link %d's issuer is blocked", k)
		}
	}
	facts := &chainFacts{links: links, originator: links[0].IssuerHostID, agent: links[0].OriginatorAgentID}
	if m := members[facts.originator]; m.PersonID != nil {
		person := *m.PersonID
		facts.originatorPerson = &person
	}
	return facts, nil
}

// requester is whom a task request is authorized for: its sender, or the
// originator once the chain has two or more links.
func (c *chainFacts) requester(sender string, r TaskRequest) (string, MessageRequest) {
	m := r.asMessage()
	if c == nil || len(c.links) < 2 {
		return sender, m
	}
	m.Origin = &Origin{AgentID: c.agent}
	return c.originator, m
}

// taskAuthority verifies a request's chain and authorizes it for task.submit,
// with the connected check, as wire acceptance does.
func (s *Store) taskAuthority(ctx context.Context, tx *sql.Tx, sender string, r TaskRequest, now time.Time) (*chainFacts, authority, error) {
	chain, err := s.verifyChain(ctx, tx, sender, r, now)
	if err != nil {
		return nil, authority{}, err
	}
	requester, m := chain.requester(sender, r)
	a, err := s.actionAuthority(ctx, tx, requester, membership.PolicyActionTask, m, true)
	return chain, a, err
}

// sharedNetwork is the lowest network ID of which this host and peer are
// both current members.
func (s *Store) sharedNetwork(ctx context.Context, q dbQuerier, peer string) (string, error) {
	// Verified current members only: retained legacy history is not shared
	// for a new chain, as on the receiving side.
	ids, err := s.networkIDs(ctx, q)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		members, err := s.membersOf(ctx, q, id)
		if err != nil {
			return "", err
		}
		_, self := members[s.identity.ID]
		_, other := members[peer]
		if self && other {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: delegation needs a network shared with host %s", ErrInvalid, peer)
}

// delegationPrincipals validates, sorts, and de-duplicates link 0's
// principals; none means network.
func delegationPrincipals(given []string) ([]string, error) {
	if given == nil {
		return []string{membership.PrincipalNetwork}, nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, p := range given {
		if !membership.ValidDelegationPrincipal(p) {
			return nil, fmt.Errorf("%w: invalid delegation principal %q; use network, person:<person ID>, or host:<host ID>", ErrInvalid, p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	if len(out) < 1 || len(out) > membership.DelegationMaxPrincipals {
		return nil, fmt.Errorf("%w: delegation needs 1 to %d principals", ErrInvalid, membership.DelegationMaxPrincipals)
	}
	return out, nil
}

// firstLink creates and signs link 0 for a new task to peer.
func (s *Store) firstLink(ctx context.Context, q dbQuerier, peer string, r TaskRequest, depth int64, principals []string) (membership.Link, error) {
	network, err := s.sharedNetwork(ctx, q, peer)
	if err != nil {
		return membership.Link{}, err
	}
	return s.firstLinkIn(network, peer, r, depth, principals), nil
}

// firstLinkIn creates and signs link 0 in a given network, the one an
// address resolved in.
func (s *Store) firstLinkIn(network, peer string, r TaskRequest, depth int64, principals []string) membership.Link {
	l := membership.Link{NetworkID: network, Index: 0, Previous: membership.DelegationNone, IssuerHostID: s.identity.ID, AudienceHostID: peer, TaskID: r.TaskID, OriginatorAgentID: r.Origin.AgentID, Principals: principals, Deadline: r.Deadline, Depth: depth}
	return membership.SignLink(s.privateKey, l)
}

// nextLink extends a received chain to peer for a forwarded task.
func (s *Store) nextLink(chain []membership.Link, peer string, r TaskRequest) membership.Link {
	last := chain[len(chain)-1]
	l := membership.Link{NetworkID: last.NetworkID, Index: int64(len(chain)), Previous: last.Hash(), IssuerHostID: s.identity.ID, AudienceHostID: peer, TaskID: r.TaskID, OriginatorAgentID: last.OriginatorAgentID, Principals: append([]string{}, last.Principals...), Deadline: r.Deadline, Depth: last.Depth - 1}
	return membership.SignLink(s.privateKey, l)
}

// utcDeadline is a deadline in the UTC form links carry.
func utcDeadline(value string) (string, error) {
	at, err := parseTime(value)
	if err != nil {
		return "", ErrInvalid
	}
	return timestamp(at), nil
}

// receivedTask reads a received task's request and status.
func receivedTask(ctx context.Context, tx *sql.Tx, sender, id string) (TaskRequest, TaskStatus, error) {
	r, err := readJSON[TaskRequest](tx.QueryRowContext(ctx, `SELECT request FROM received_tasks WHERE sender = ? AND task_id = ?`, sender, id))
	if err != nil {
		return r, TaskStatus{}, err
	}
	st, err := readTaskStatus(ctx, tx, sender, id)
	return r, st, err
}

// checkForward reports whether a received task may be passed on to peer: it
// is running, not being cancelled, carries a chain with depth left, was
// accepted under task.delegate, and peer is within the last link's
// principals.
func (s *Store) checkForward(ctx context.Context, tx *sql.Tx, parent TaskRequest, st TaskStatus, peer string) error {
	if st.CancelRequested {
		return fmt.Errorf("%w: a cancellation of the parent task was requested", ErrConflict)
	}
	if st.State != TaskRunning {
		return fmt.Errorf("%w: only a running task can be passed on", ErrForbidden)
	}
	n := len(parent.Delegation)
	if n == 0 || parent.Delegation[n-1].Depth < 1 {
		return fmt.Errorf("%w: the parent task's submitter did not allow it to be passed on", ErrForbidden)
	}
	var delegable sql.NullBool
	if err := tx.QueryRowContext(ctx, `SELECT json_extract(record, '$.delegable') FROM received_tasks WHERE sender = ? AND task_id = ?`, st.SenderHostID, st.TaskID).Scan(&delegable); err != nil {
		return err
	}
	if !delegable.Valid || !delegable.Bool {
		return fmt.Errorf("%w: this host's owner did not allow the parent task to be passed on (task.delegate)", ErrForbidden)
	}
	if n+1 > membership.DelegationMaxLinks {
		return fmt.Errorf("%w: the chain would exceed %d links", ErrForbidden, membership.DelegationMaxLinks)
	}
	last := parent.Delegation[n-1]
	members, err := s.membersOf(ctx, tx, last.NetworkID)
	if err != nil {
		return err
	}
	_, self := members[s.identity.ID]
	_, member := members[peer]
	if !self || !member || !membership.PrincipalsCover(last.Principals, "host:"+peer, boundIn(members)) {
		return fmt.Errorf("%w: host %s is outside the parent task's delegation principals", ErrForbidden, peer)
	}
	return nil
}

// forwardDeadline caps a forwarded task's deadline at its parent's: an
// explicit later deadline is refused, and a default one is lowered.
func forwardDeadline(r *TaskRequest, parent TaskRequest, explicit bool) error {
	at, err := parseTime(r.Deadline)
	if err != nil {
		return ErrInvalid
	}
	limit, err := parseTime(parent.Deadline)
	if err != nil {
		return err
	}
	if at.After(limit) {
		if explicit {
			return fmt.Errorf("%w: a forwarded task's deadline may not be later than its parent's", ErrForbidden)
		}
		at = limit
	}
	r.Deadline = timestamp(at)
	return nil
}

// recordForward links a forwarded task to its parent, with its activity.
func recordForward(ctx context.Context, tx *sql.Tx, parent TaskParent, out OutboundTask) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO task_children VALUES (?, ?, ?, ?)`, parent.SenderHostID, parent.TaskID, out.PeerHostID, out.Request.TaskID); err != nil {
		return err
	}
	return appendEvent(ctx, tx, "task.delegated", taskSubject(out.PeerHostID, out.Request.TaskID), timestamp(time.Now()))
}

// cancelChildren marks every task forwarded from a received task for
// cancellation; the poll workers send each request with retries.
func cancelChildren(ctx context.Context, tx *sql.Tx, sender, id string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT o.peer, o.task_id, o.record FROM task_children c JOIN outbound_tasks o ON o.peer = c.peer AND o.task_id = c.child_task_id WHERE c.sender = ? AND c.task_id = ? ORDER BY o.rowid`, sender, id)
	if err != nil {
		return nil, err
	}
	type child struct {
		peer, id string
		out      OutboundTask
	}
	var children []child
	for rows.Next() {
		var c child
		var record string
		if err = rows.Scan(&c.peer, &c.id, &record); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(record), &c.out); err != nil {
			break
		}
		children = append(children, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, c := range children {
		out := c.out
		if out.SubmitState == submitRejected || (out.Status != nil && taskFinal(out.Status.State)) || out.CancelState != nil {
			continue
		}
		state := cancelUnknown
		out.CancelState = &state
		if err = putJSON(ctx, tx, `UPDATE outbound_tasks SET record = ? WHERE peer = ? AND task_id = ?`, out.persisted(), c.peer, c.id); err != nil {
			return nil, err
		}
		keys = append(keys, taskKey(c.peer, c.id))
	}
	return keys, nil
}

// pollNow makes the poll workers pick these tasks up at their next tick.
func (s *Store) pollNow(keys []string) {
	s.tasks.mu.Lock()
	defer s.tasks.mu.Unlock()
	for _, key := range keys {
		delete(s.tasks.poll, key)
	}
}
