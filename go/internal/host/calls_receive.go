package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

// Received calls: a peer's invocation of one operation of a capability on
// this host, or of a source opened to one of the person's trusted machines,
// authorized by a capability rule naming this host or by self access,
// persisted, and run asynchronously on the source's server.

// Call states.
const (
	CallQueued    = "queued"
	CallRunning   = "running"
	CallSucceeded = "succeeded"
	CallFailed    = "failed"
	CallRejected  = "rejected"
	CallExpired   = "expired"
	CallCancelled = "cancelled"
	CallUncertain = "uncertain"
)

// Call errors.
const (
	callServerStartFailed = "server_start_failed"
	callServerExited      = "server_exited"
	callResultTooLarge    = "result_too_large"
	callJSONRPCError      = "jsonrpc_error"
	callToolError         = "tool_error"
	callDaemonRestarted   = "daemon_restarted"
	callCancelRequested   = "cancel_requested"
	callDeadline          = "deadline"
	callLapsed            = "authorization lapsed before start"
	// Remote server outcomes (slice 3).
	callAuthRequired      = "auth_required"
	callInsufficientScope = "insufficient_scope"
	callHTTPError         = "http_error"
	callConnectionLost    = "connection_lost"
)

const (
	callMaxDeadline = 15 * time.Minute
	// callDeadlineSkew tolerates clock differences between hosts on the
	// 15-minute deadline bound.
	callDeadlineSkew  = time.Minute
	callMaxResult     = 1 << 20
	callRetention     = 7 * 24 * time.Hour
	selfMaxInputBytes = membership.PolicyMaxInputBytes
)

func callFinal(state string) bool {
	switch state {
	case CallSucceeded, CallFailed, CallRejected, CallExpired, CallCancelled, CallUncertain:
		return true
	}
	return false
}

func validCallState(state string) bool {
	return state == CallQueued || state == CallRunning || callFinal(state)
}

// CallPolicyCitation names the owner policy a call relies on, in one
// network.
type CallPolicyCitation struct {
	PersonID  string `json:"person_id"`
	NetworkID string `json:"network_id"`
	Version   uint64 `json:"version"`
}

func (c *CallPolicyCitation) UnmarshalJSON(data []byte) error {
	type plain CallPolicyCitation
	return membership.Strict(data, (*plain)(c), "person_id", "network_id", "version")
}

// CallSelfCitation is self access in one network.
type CallSelfCitation struct {
	PersonID  string `json:"person_id"`
	NetworkID string `json:"network_id"`
}

func (c *CallSelfCitation) UnmarshalJSON(data []byte) error {
	type plain CallSelfCitation
	return membership.Strict(data, (*plain)(c), "person_id", "network_id")
}

// CallRequest is a call submission on the peer wire, with exactly one
// authorization. Capability is a capability name, or AGENT/SERVER for a
// source.
type CallRequest struct {
	CallID     string              `json:"call_id"`
	Policy     *CallPolicyCitation `json:"policy,omitempty"`
	Self       *CallSelfCitation   `json:"self,omitempty"`
	Capability string              `json:"capability"`
	Operation  string              `json:"operation"`
	Input      json.RawMessage     `json:"input"`
	Deadline   string              `json:"deadline"`
	Origin     *Origin             `json:"origin,omitempty"`
}

// UnmarshalJSON accepts exactly the call's fields, with input compacted.
func (r *CallRequest) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return ErrInvalid
	}
	allowed := map[string]bool{"origin": true, "policy": true, "self": true}
	for _, field := range []string{"call_id", "capability", "operation", "input", "deadline"} {
		if _, ok := raw[field]; !ok {
			return ErrInvalid
		}
		allowed[field] = true
	}
	for field, value := range raw {
		if !allowed[field] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalid
		}
	}
	type plain CallRequest
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return ErrInvalid
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, p.Input); err != nil {
		return ErrInvalid
	}
	p.Input = compact.Bytes()
	*r = CallRequest(p)
	return nil
}

// sourceCall splits AGENT/SERVER, the capability of a source call.
func (r CallRequest) sourceCall() (agent, server string, ok bool) {
	agent, server, ok = strings.Cut(r.Capability, "/")
	return agent, server, ok
}

// inputBytes is the size max_input_bytes bounds: the JSON encoding of the
// input.
func (r CallRequest) inputBytes() int64 { return int64(len(r.Input)) }

// readURI is the uri of a read operation's input, or "".
func (r CallRequest) readURI() string {
	var input struct {
		URI string `json:"uri"`
	}
	_ = json.Unmarshal(r.Input, &input)
	return input.URI
}

func (r CallRequest) same(o CallRequest) bool {
	a, errA := json.Marshal(r)
	b, errB := json.Marshal(o)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func validNetworkID(id string) bool { return validID(id, "net", 32) }

func validateCall(r CallRequest) error {
	var authorized bool
	switch {
	case r.Policy != nil:
		authorized = r.Self == nil && membership.ValidPersonID(r.Policy.PersonID) && validNetworkID(r.Policy.NetworkID) && r.Policy.Version >= 1
	case r.Self != nil:
		authorized = membership.ValidPersonID(r.Self.PersonID) && validNetworkID(r.Self.NetworkID)
	}
	if !validID(r.CallID, "call", 16) || !authorized || !r.Origin.valid() {
		return ErrInvalid
	}
	if agent, server, ok := r.sourceCall(); ok {
		if agent == "" || strings.Contains(server, "/") || !membership.ValidName(server) {
			return fmt.Errorf("%w: a source is AGENT/SERVER", ErrInvalid)
		}
	} else if !membership.ValidCapabilityName(r.Capability) {
		return fmt.Errorf("%w: invalid capability name", ErrInvalid)
	}
	if r.Operation == "" || len(r.Operation) > 1024 || !utf8.ValidString(r.Operation) || len(r.Input) == 0 || r.Input[0] != '{' {
		return fmt.Errorf("%w: a call has an operation and an input object", ErrInvalid)
	}
	if _, err := parseTime(r.Deadline); err != nil {
		return ErrInvalid
	}
	return nil
}

// CallStatus is the status record a receiver keeps and serves to the
// submitter; Result is shown on GET once the call is final.
type CallStatus struct {
	CallID          string  `json:"call_id"`
	SenderHostID    string  `json:"sender_host_id"`
	ReceiverHostID  string  `json:"receiver_host_id"`
	Capability      string  `json:"capability"`
	Operation       string  `json:"operation"`
	State           string  `json:"state"`
	CancelRequested bool    `json:"cancel_requested"`
	Error           *string `json:"error"`
	ResultBytes     *int64  `json:"result_bytes"`
	CreatedAt       string  `json:"created_at"`
	StartedAt       *string `json:"started_at"`
	FinishedAt      *string `json:"finished_at"`
	// Approval is the call's approval, or null when it needed none (or the
	// receiver predates approval).
	Approval *CallApproval   `json:"approval"`
	Result   json.RawMessage `json:"result,omitempty"`
}

// receivedCall is received_calls.record: the status, the result, and what
// acceptance decided.
type receivedCall struct {
	CallStatus
	StoredResult json.RawMessage `json:"stored_result"`
	// BudgetKey counts the call toward its rule's hourly budget for its
	// caller; empty under self access. AcceptedMS is when.
	BudgetKey   string `json:"budget_key"`
	AcceptedMS  int64  `json:"accepted_ms"`
	InputSHA256 string `json:"input_sha256"`
	Purged      bool   `json:"purged"`
}

// status is the record as the wire shows it, with the result once final
// when withResult.
func (c receivedCall) status(withResult bool) CallStatus {
	st := c.CallStatus
	st.Result = nil
	if withResult && callFinal(st.State) {
		st.Result = c.StoredResult
		if st.Result == nil {
			st.Result = json.RawMessage("null")
		}
	}
	return st
}

func callSubject(host, id string) string { return host + "/" + id }

func readReceivedCall(ctx context.Context, q dbQuerier, sender, id string) (receivedCall, error) {
	return readJSON[receivedCall](q.QueryRowContext(ctx, `SELECT record FROM received_calls WHERE sender = ? AND call_id = ?`, sender, id))
}

func writeReceivedCall(ctx context.Context, tx *sql.Tx, c receivedCall) error {
	return putJSON(ctx, tx, `UPDATE received_calls SET record = ? WHERE sender = ? AND call_id = ?`, c, c.SenderHostID, c.CallID)
}

// finishCall moves a call to a final state with its activity.
func finishCall(ctx context.Context, tx *sql.Tx, c *receivedCall, state string, failure *string, now time.Time) error {
	at := timestamp(now)
	c.State, c.Error, c.FinishedAt = state, failure, &at
	if err := writeReceivedCall(ctx, tx, *c); err != nil {
		return err
	}
	return appendEvent(ctx, tx, "call.finished", callSubject(c.SenderHostID, c.CallID), at)
}

// uncertainAfterRestart ends every call still running with the previous
// daemon as uncertain.
func uncertainAfterRestart(ctx context.Context, tx *sql.Tx, now time.Time) error {
	calls, err := records[receivedCall](ctx, tx, `SELECT record FROM received_calls WHERE json_extract(record, '$.state') = 'running' ORDER BY rowid`)
	if err != nil {
		return err
	}
	failure := callDaemonRestarted
	for _, c := range calls {
		if err = finishCall(ctx, tx, &c, CallUncertain, &failure, now); err != nil {
			return err
		}
	}
	return nil
}

// expireCalls moves every queued call whose deadline has passed to expired.
func expireCalls(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT c.record, json_extract(c.request, '$.deadline') FROM received_calls c WHERE json_extract(c.record, '$.state') = 'queued' ORDER BY rowid`)
	if err != nil {
		return err
	}
	var due []receivedCall
	for rows.Next() {
		var record, deadline string
		if err = rows.Scan(&record, &deadline); err != nil {
			break
		}
		var c receivedCall
		if err = json.Unmarshal([]byte(record), &c); err != nil {
			break
		}
		if at, e := parseTime(deadline); e == nil && !at.After(now) {
			due = append(due, c)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range due {
		// A pending approval expires with its call; an approved call not yet
		// started expires as any queued call.
		if c.Approval != nil && c.Approval.State == ApprovalPending {
			a, err := readApproval(ctx, tx, c.SenderHostID, c.CallID)
			if err != nil {
				return err
			}
			if err = leavePending(ctx, tx, &a, &c, ApprovalExpired, nil, now); err != nil {
				return err
			}
			if err = appendEvent(ctx, tx, "call.approval_expired", callSubject(c.SenderHostID, c.CallID), timestamp(now)); err != nil {
				return err
			}
			failure := callApprovalTimeout
			if err = finishCall(ctx, tx, &c, CallExpired, &failure, now); err != nil {
				return err
			}
			continue
		}
		if err = finishCall(ctx, tx, &c, CallExpired, nil, now); err != nil {
			return err
		}
	}
	return nil
}

// callGrant is the authority a call relies on: its bounds and the budget
// key it counts toward.
type callGrant struct {
	maxInput          int64
	allowDisconnected bool
	maxCalls          int64 // 0 means no budget
	until             time.Time
	budgetKey         string
}

// callFailure ranks why a candidate authorization refused a call, so the
// furthest-reaching refusal is reported.
type callFailure struct {
	rank int
	err  error
}

func (f *callFailure) note(rank int, err error) {
	if f.err == nil || rank > f.rank {
		f.rank, f.err = rank, err
	}
}

func snapshotTool(snap toolSnapshotState, name string) (SnapshotTool, bool) {
	for _, t := range snap.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return SnapshotTool{}, false
}

func snapshotResource(snap toolSnapshotState, uri string) (SnapshotResource, bool) {
	for _, r := range snap.Resources {
		if r.URI == uri {
			return r, true
		}
	}
	return SnapshotResource{}, false
}

// ruleHash identifies a capability rule for its budget across policy
// versions: the network, owner, host, capability, and bounds, not the
// principals.
func ruleHash(network, person string, r membership.CapabilityRule) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{network, person, r.Host, r.Capability, strconv.FormatInt(r.MaxInputBytes, 10), strconv.FormatBool(r.AllowDisconnected), strconv.FormatInt(r.MaxCallsPerHour, 10)}, "\n")))
	return hex.EncodeToString(sum[:16])
}

// instanceTarget is the instance that serves a call: a source's own, or a
// capability's with its own credential.
type instanceTarget struct {
	agentID, server string
	own             *ownCredential
}

func (t instanceTarget) key() string {
	if t.own != nil {
		return t.agentID + "/" + t.server + "@" + t.own.capability
	}
	return t.agentID + "/" + t.server
}

var errUnavailableCapability = &codedError{status: http.StatusConflict, code: "unavailable", message: "the capability or operation is unavailable now"}

// resolveCallTarget checks that the call's capability or source exists here with
// the operation (404), that neither is unavailable (409), and for read that
// the URI is one of its resources in the snapshot (404). It returns the
// instance that serves the call.
func (s *Store) resolveCallTarget(ctx context.Context, q dbQuerier, r CallRequest) (instanceTarget, error) {
	if agent, server, ok := r.sourceCall(); ok {
		agentID := builtinAgent
		var err error
		if agent != builtinAgent {
			err = q.QueryRowContext(ctx, `SELECT id FROM agents WHERE name = ?`, agent).Scan(&agentID)
		}
		if errors.Is(err, sql.ErrNoRows) {
			return instanceTarget{}, fmt.Errorf("%w: no source %s", ErrNotFound, r.Capability)
		}
		if err != nil {
			return instanceTarget{}, err
		}
		rec, err := readToolServer(ctx, q, agentID, server)
		if err == nil && deref(rec.Reason) == reasonLogin {
			return instanceTarget{}, errAuthLapsed
		}
		if errors.Is(err, ErrNotFound) || (err == nil && (!rec.Shareable || rec.SnapshotAt == nil)) {
			return instanceTarget{}, fmt.Errorf("%w: no source %s", ErrNotFound, r.Capability)
		}
		if err != nil {
			return instanceTarget{}, err
		}
		if r.Operation == membership.OperationRead {
			if len(rec.Resources) == 0 {
				return instanceTarget{}, fmt.Errorf("%w: %s has no resources", ErrNotFound, r.Capability)
			}
			if _, ok := snapshotResource(rec.toolSnapshotState, r.readURI()); !ok {
				return instanceTarget{}, fmt.Errorf("%w: %s has no resource with that uri", ErrNotFound, r.Capability)
			}
		} else if _, ok := snapshotTool(rec.toolSnapshotState, r.Operation); !ok {
			return instanceTarget{}, fmt.Errorf("%w: %s has no operation %s", ErrNotFound, r.Capability, r.Operation)
		}
		return instanceTarget{agentID: agentID, server: server}, nil
	}
	c, err := readCapability(ctx, q, r.Capability)
	if errors.Is(err, ErrNotFound) {
		return instanceTarget{}, fmt.Errorf("%w: no capability %s on this host", ErrNotFound, r.Capability)
	}
	if err != nil {
		return instanceTarget{}, err
	}
	isRead := r.Operation == membership.OperationRead
	if !(isRead && c.Resources.Set) && !contains(c.Operations, r.Operation) {
		return instanceTarget{}, fmt.Errorf("%w: %s has no operation %s", ErrNotFound, r.Capability, r.Operation)
	}
	_, unavailable, snap, err := capabilityState(ctx, q, c)
	if err != nil {
		return instanceTarget{}, err
	}
	if contains(unavailable, unavailableAuth) {
		return instanceTarget{}, errAuthLapsed
	}
	// Only an unavailable operation, or a gone source, refuses the call.
	if contains(unavailable, unavailableSource) || contains(unavailable, r.Operation) {
		return instanceTarget{}, errUnavailableCapability
	}
	if isRead {
		found := false
		for _, res := range readURIs(c, snap) {
			if res.URI == r.readURI() {
				found = true
			}
		}
		if !found {
			return instanceTarget{}, fmt.Errorf("%w: %s has no resource with that uri", ErrNotFound, r.Capability)
		}
	} else if err := checkBounds(c.Bounds, c.Source.Agent == builtinAgent, r.Input); err != nil {
		// A bound is the capability check's last step: nothing runs.
		return instanceTarget{}, err
	}
	return instanceTarget{agentID: c.AgentID, server: c.Source.Server, own: c.credential()}, nil
}

// trustedSelf lists the networks, all or only the given one, where this
// host and the sender are both bound to person, and person's newest
// verified policy there is within its window and lists the sender as
// trusted.
func (s *Store) trustedSelf(ctx context.Context, q dbQuerier, sender, person, network string, now time.Time) ([]string, error) {
	if sender == s.identity.ID {
		return nil, nil
	}
	own, err := s.membershipsOf(ctx, q, s.identity.ID)
	if err != nil {
		return nil, err
	}
	networks := []string{}
	for _, n := range own {
		if n.member.PersonID == nil || *n.member.PersonID != person || (network != "" && n.network != network) {
			continue
		}
		members, e := s.membersOf(ctx, q, n.network)
		if e != nil {
			return nil, e
		}
		if member, ok := members[sender]; ok && member.PersonID != nil && *member.PersonID == person {
			networks = append(networks, n.network)
		}
	}
	var trusted []string
	for _, id := range networks {
		g, err := s.loadProductGovernance(ctx, q, id)
		if err != nil {
			return nil, err
		}
		key, ok := g.personKey(person)
		if !ok {
			continue
		}
		p, ok := g.storedPolicy(key)
		if !ok || !p.active(now) {
			continue
		}
		if p, err = s.enforcedProductPolicy(ctx, q, g, key, p); err != nil {
			return nil, err
		}
		if contains(p.TrustedHosts, sender) {
			trusted = append(trusted, id)
		}
	}
	return trusted, nil
}

// capabilityRuleCandidate is a capability rule naming this host that
// matches the sender, in one network.
type capabilityRuleCandidate struct {
	network, person string
	version         uint64
	rule            membership.CapabilityRule
	until           time.Time
	caller          string
	// In a listing, broad reports a principal other than agent: matching
	// the sender, and agents the sender's agents that agent: principals
	// name.
	broad  bool
	agents []string
}

// policyCapabilityRules lists the capability rules naming this host of
// person's newest verified policy in a network (or every network where this
// host is bound to person, when network is ""), whose principals match the
// sender, for one capability or all ("" capability). behind reports a
// policy older than cited. A listing matches any origin, and records which
// principals matched.
func (s *Store) policyCapabilityRules(ctx context.Context, q dbQuerier, sender, person string, cited uint64, network, capability string, origin *Origin, now time.Time, listing bool) ([]capabilityRuleCandidate, bool, error) {
	own, err := s.membershipsOf(ctx, q, s.identity.ID)
	if err != nil {
		return nil, false, err
	}
	var out []capabilityRuleCandidate
	behind := false
	for _, n := range own {
		if n.member.PersonID == nil || *n.member.PersonID != person || sender == s.identity.ID || (network != "" && n.network != network) {
			continue
		}
		g, err := s.loadProductGovernance(ctx, q, n.network)
		if err != nil {
			return nil, false, err
		}
		key, ok := g.personKey(person)
		if !ok {
			continue
		}
		p, ok := g.storedPolicy(key)
		if !ok || p.Version < cited {
			behind = true
			continue
		}
		if !p.active(now) {
			continue
		}
		// Withdrawals of this host's unsettled edits apply at once.
		if p, err = s.enforcedProductPolicy(ctx, q, g, key, p); err != nil {
			return nil, false, err
		}
		members, err := s.membersOf(ctx, q, n.network)
		if err != nil {
			return nil, false, err
		}
		member, present := members[sender]
		if !present {
			continue
		}
		until, _ := membership.ParseTime(p.ValidUntil)
		caller := sender
		if member.PersonID != nil {
			caller = *member.PersonID
		}
		for _, r := range p.CapabilityRules {
			// A rule naming another host never authorizes a call here.
			if r.Host != s.identity.ID || (capability != "" && r.Capability != capability) {
				continue
			}
			c := capabilityRuleCandidate{network: n.network, person: person, version: p.Version, rule: r, until: until, caller: caller}
			if listing {
				var others []string
				for _, principal := range r.Principals {
					if host, agent, ok := membership.AgentPrincipal(principal); ok {
						if host == sender && !contains(c.agents, agent) {
							c.agents = append(c.agents, agent)
						}
						continue
					}
					others = append(others, principal)
				}
				c.broad = g.principalMatches(membership.PolicyRule{Principals: others}, member, nil)
				if !c.broad && len(c.agents) == 0 {
					continue
				}
				sort.Strings(c.agents)
			} else if !g.principalMatches(membership.PolicyRule{Principals: r.Principals}, member, origin) {
				continue
			}
			out = append(out, c)
		}
	}
	return out, behind, nil
}

// callAuthority authorizes a call as the contract orders it: the citation,
// the block list (except self), the capability (404, or 409 when
// unavailable), the bounds, and, at submission, the hourly budget. Several
// matching rules combine: the first that allows the call is used, and
// otherwise the refusal that got furthest is reported. It also returns the
// instance that serves the call.
func (s *Store) callAuthority(ctx context.Context, tx *sql.Tx, sender string, r CallRequest, now time.Time, budget bool) (callGrant, instanceTarget, error) {
	deadline, err := parseTime(r.Deadline)
	if err != nil {
		return callGrant{}, instanceTarget{}, ErrInvalid
	}
	_, _, isSource := r.sourceCall()
	var candidates []callGrant
	self := r.Self != nil
	if self {
		networks, err := s.trustedSelf(ctx, tx, sender, r.Self.PersonID, r.Self.NetworkID, now)
		if err != nil {
			return callGrant{}, instanceTarget{}, err
		}
		if len(networks) == 0 {
			return callGrant{}, instanceTarget{}, ErrForbidden
		}
		if isSource {
			// The serving host must also have opened its sources to the sender.
			open, err := openTo(ctx, tx, sender)
			if err != nil || !open {
				if err == nil {
					err = ErrForbidden
				}
				return callGrant{}, instanceTarget{}, err
			}
		}
		candidates = append(candidates, callGrant{maxInput: selfMaxInputBytes, allowDisconnected: true})
	} else {
		if isSource {
			return callGrant{}, instanceTarget{}, ErrForbidden
		}
		rules, behind, err := s.policyCapabilityRules(ctx, tx, sender, r.Policy.PersonID, r.Policy.Version, r.Policy.NetworkID, r.Capability, r.Origin, now, false)
		if err != nil {
			return callGrant{}, instanceTarget{}, err
		}
		for _, c := range rules {
			candidates = append(candidates, callGrant{maxInput: c.rule.MaxInputBytes, allowDisconnected: c.rule.AllowDisconnected, maxCalls: c.rule.MaxCallsPerHour, until: c.until, budgetKey: "rule:" + ruleHash(c.network, c.person, c.rule) + ":" + c.caller})
		}
		if len(candidates) == 0 {
			if behind {
				return callGrant{}, instanceTarget{}, fmt.Errorf("%w: this host has not yet verified the cited policy version", ErrUnavailable)
			}
			return callGrant{}, instanceTarget{}, ErrForbidden
		}
		if refused, err := s.blocked(ctx, tx, sender); err != nil || refused {
			if err == nil {
				err = ErrForbidden
			}
			return callGrant{}, instanceTarget{}, err
		}
	}
	target, err := s.resolveCallTarget(ctx, tx, r)
	if err != nil {
		return callGrant{}, instanceTarget{}, err
	}
	var failure callFailure
	for _, g := range candidates {
		if r.inputBytes() > g.maxInput {
			failure.note(1, &codedError{status: http.StatusRequestEntityTooLarge, code: "too_large", message: fmt.Sprintf("the call's input exceeds max_input_bytes %d", g.maxInput)})
			continue
		}
		// At submission, the deadline is in the future and at most 15
		// minutes plus skew ahead.
		if budget && (!deadline.After(now) || deadline.After(now.Add(callMaxDeadline+callDeadlineSkew))) {
			return callGrant{}, instanceTarget{}, fmt.Errorf("%w: a call's deadline is in the future, at most 15 minutes after submission", ErrInvalid)
		}
		if !g.until.IsZero() && deadline.After(g.until) {
			failure.note(2, fmt.Errorf("%w: the deadline is after the policy's valid_until", ErrForbidden))
			continue
		}
		if !g.allowDisconnected {
			usable, recoverable, err := s.grantConnected(ctx, tx, sender, authority{})
			if err != nil {
				return callGrant{}, instanceTarget{}, err
			}
			if !usable {
				if recoverable {
					failure.note(3, fmt.Errorf("%w: coordination disconnected", ErrUnavailable))
				} else {
					failure.note(3, ErrForbidden)
				}
				continue
			}
		}
		if budget && g.maxCalls > 0 {
			var used int64
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM received_calls WHERE json_extract(record, '$.budget_key') = ? AND json_extract(record, '$.accepted_ms') > ?`, g.budgetKey, now.Add(-time.Hour).UnixMilli()).Scan(&used); err != nil {
				return callGrant{}, instanceTarget{}, err
			}
			if used >= g.maxCalls {
				failure.note(4, &codedError{status: http.StatusTooManyRequests, code: "limit", limit: "max_calls_per_hour", message: fmt.Sprintf("the caller has used max_calls_per_hour %d in the last hour", g.maxCalls)})
				continue
			}
		}
		return g, target, nil
	}
	return callGrant{}, instanceTarget{}, failure.err
}

// AcceptCall authorizes a submission and persists it queued, idempotently
// by (sender, call_id).
func (s *Store) AcceptCall(ctx context.Context, sender string, r CallRequest) (CallStatus, error) {
	if err := validateCall(r); err != nil {
		return CallStatus{}, err
	}
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallStatus{}, err
	}
	defer tx.Rollback()
	if err = expireCalls(ctx, tx, now); err != nil {
		return CallStatus{}, err
	}
	var oldRequest string
	err = tx.QueryRowContext(ctx, `SELECT request FROM received_calls WHERE sender = ? AND call_id = ?`, sender, r.CallID).Scan(&oldRequest)
	if err == nil {
		var old CallRequest
		c, err := readReceivedCall(ctx, tx, sender, r.CallID)
		if err != nil {
			return CallStatus{}, err
		}
		// An identical repeat returns the record; an input purged by
		// retention is compared by its hash.
		var fields map[string]json.RawMessage
		if err = json.Unmarshal([]byte(oldRequest), &fields); err != nil {
			return CallStatus{}, err
		}
		if c.Purged {
			fields["input"] = r.Input
			if sum := sha256.Sum256(r.Input); hex.EncodeToString(sum[:]) != c.InputSHA256 {
				return CallStatus{}, ErrConflict
			}
		}
		data, _ := json.Marshal(fields)
		if err = json.Unmarshal(data, &old); err != nil || !old.same(r) {
			return CallStatus{}, ErrConflict
		}
		return c.status(false), tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CallStatus{}, err
	}
	g, _, err := s.callAuthority(ctx, tx, sender, r, now, true)
	if err != nil {
		return CallStatus{}, err
	}
	// Whether the call needs approval is decided once, now.
	need, capability, changes, err := approvalNeed(ctx, tx, r)
	if err != nil {
		return CallStatus{}, err
	}
	at := timestamp(now)
	c := receivedCall{CallStatus: CallStatus{CallID: r.CallID, SenderHostID: sender, ReceiverHostID: s.identity.ID, Capability: r.Capability, Operation: r.Operation, State: CallQueued, CreatedAt: at},
		BudgetKey: g.budgetKey, AcceptedMS: now.UnixMilli()}
	sum := sha256.Sum256(r.Input)
	c.InputSHA256 = hex.EncodeToString(sum[:])
	requestData, err := json.Marshal(r)
	if err != nil {
		return CallStatus{}, err
	}
	recordData, err := json.Marshal(c)
	if err != nil {
		return CallStatus{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO received_calls VALUES (?, ?, ?, ?)`, sender, r.CallID, string(requestData), string(recordData)); err != nil {
		return CallStatus{}, err
	}
	if err = appendEvent(ctx, tx, "call.received", callSubject(sender, r.CallID), at); err != nil {
		return CallStatus{}, err
	}
	if need {
		// The pending limit refuses the call, and the rollback persists
		// nothing; otherwise the approval, its notice, and its activity are
		// stored with the call.
		if c.Approval, err = s.requestApproval(ctx, tx, sender, r, capability, changes, g.budgetKey, c.InputSHA256, now); err != nil {
			return CallStatus{}, err
		}
		if err = writeReceivedCall(ctx, tx, c); err != nil {
			return CallStatus{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return CallStatus{}, err
	}
	s.wakeCalls()
	return c.status(false), nil
}

// SubmitterCall is the sender's own call, with its result once final;
// anything else is not found.
func (s *Store) SubmitterCall(ctx context.Context, sender, id string) (CallStatus, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallStatus{}, err
	}
	defer tx.Rollback()
	if err = expireCalls(ctx, tx, time.Now()); err != nil {
		return CallStatus{}, err
	}
	c, err := readReceivedCall(ctx, tx, sender, id)
	if err != nil {
		return CallStatus{}, err
	}
	return c.status(true), tx.Commit()
}

// RequestCallCancel sets cancel_requested once: a queued call is cancelled
// at once, and a running one becomes uncertain and its server is sent
// notifications/cancelled. A repeat, or a final call, is unchanged.
func (s *Store) RequestCallCancel(ctx context.Context, sender, id string) (CallStatus, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CallStatus{}, err
	}
	defer tx.Rollback()
	now := time.Now()
	if err = expireCalls(ctx, tx, now); err != nil {
		return CallStatus{}, err
	}
	c, err := readReceivedCall(ctx, tx, sender, id)
	if err != nil {
		return CallStatus{}, err
	}
	if callFinal(c.State) || c.CancelRequested {
		return c.status(false), tx.Commit()
	}
	c.CancelRequested = true
	if err = appendEvent(ctx, tx, "call.cancel_requested", callSubject(sender, id), timestamp(now)); err != nil {
		return CallStatus{}, err
	}
	running := c.State == CallRunning
	if c.State == CallQueued && c.Approval != nil && c.Approval.State == ApprovalPending {
		// A cancel while pending cancels the approval with the call.
		a, err := readApproval(ctx, tx, sender, id)
		if err != nil {
			return CallStatus{}, err
		}
		if err = leavePending(ctx, tx, &a, &c, ApprovalCancelled, nil, now); err != nil {
			return CallStatus{}, err
		}
	}
	if c.State == CallQueued {
		err = finishCall(ctx, tx, &c, CallCancelled, nil, now)
	} else {
		failure := callCancelRequested
		err = finishCall(ctx, tx, &c, CallUncertain, &failure, now)
	}
	if err != nil {
		return CallStatus{}, err
	}
	if err = tx.Commit(); err != nil {
		return CallStatus{}, err
	}
	if running {
		s.signalCall(sender, id, callCancelRequested)
	}
	return c.status(false), nil
}

// ReceivedCallItem is one entry of calls received.
type ReceivedCallItem struct {
	Sequence int64           `json:"sequence"`
	Request  json.RawMessage `json:"request"`
	Status   CallStatus      `json:"status"`
}

// ReceivedCalls pages calls received by this host in insertion order.
func (s *Store) ReceivedCalls(ctx context.Context, after, limit int64) ([]ReceivedCallItem, error) {
	if after < 0 || limit < 1 || limit > 1000 {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rowid, request, record FROM received_calls WHERE rowid > ? ORDER BY rowid LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ReceivedCallItem{}
	pageBytes := 2
	for rows.Next() {
		var item ReceivedCallItem
		var request, record string
		if err = rows.Scan(&item.Sequence, &request, &record); err != nil {
			return nil, err
		}
		item.Request = json.RawMessage(request)
		var c receivedCall
		if err = json.Unmarshal([]byte(record), &c); err != nil {
			return nil, err
		}
		item.Status = c.status(false)
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if pageBytes+len(encoded)+1 > 900000 && len(items) > 0 {
			break
		}
		pageBytes += len(encoded) + 1
		items = append(items, item)
	}
	return items, rows.Err()
}

// pruneCalls deletes the input and result of calls final for more than 7
// days; the status record and input_sha256 remain.
func (s *Store) pruneCalls(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	calls, err := records[receivedCall](ctx, tx, `SELECT record FROM received_calls WHERE json_extract(record, '$.purged') IS NOT 1 AND json_extract(record, '$.finished_at') IS NOT NULL`)
	if err != nil {
		return err
	}
	for _, c := range calls {
		finished, err := parseTime(deref(c.FinishedAt))
		if err != nil || now.Sub(finished) < callRetention {
			continue
		}
		c.StoredResult, c.Purged = nil, true
		if err = writeReceivedCall(ctx, tx, c); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE received_calls SET request = json_remove(request, '$.input') WHERE sender = ? AND call_id = ?`, c.SenderHostID, c.CallID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ToolVia is what authorizes one listed capability for the sender.
type ToolVia struct {
	Kind      string  `json:"kind"`
	NetworkID *string `json:"network_id"`
	PersonID  *string `json:"person_id,omitempty"`
	Version   *uint64 `json:"version,omitempty"`
	// FromAgent, on a policy entry, is the agent of the sender whose agent:
	// principals alone match the rule, or null when another principal
	// does. A listing from a host that predates it reads as null.
	FromAgent *string `json:"from_agent,omitempty"`
}

// MarshalJSON shows from_agent on every policy entry, null or not, and
// never on a self entry.
func (v ToolVia) MarshalJSON() ([]byte, error) {
	type plain struct {
		Kind      string  `json:"kind"`
		NetworkID *string `json:"network_id"`
		PersonID  *string `json:"person_id,omitempty"`
		Version   *uint64 `json:"version,omitempty"`
	}
	p := plain{v.Kind, v.NetworkID, v.PersonID, v.Version}
	if v.Kind != AuthorizationPolicy {
		return json.Marshal(p)
	}
	return json.Marshal(struct {
		plain
		FromAgent *string `json:"from_agent"`
	}{p, v.FromAgent})
}

// ListedOperation is one operation in GET /peer/v1/capabilities.
type ListedOperation struct {
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	ReadOnly    bool            `json:"read_only"`
	// Approval is advisory: whether a call with an origin needs approval.
	// A listing from a host that predates it reads as false.
	Approval bool `json:"approval"`
}

// ListedCapability is one entry of GET /peer/v1/capabilities: a capability,
// or a source opened to the sender.
type ListedCapability struct {
	Kind        string             `json:"kind"`
	Capability  string             `json:"capability"`
	Operations  []ListedOperation  `json:"operations"`
	Resources   []SnapshotResource `json:"resources"`
	State       string             `json:"state"`
	Unavailable []string           `json:"unavailable"`
	Via         []ToolVia          `json:"via"`
	// Bounds is the capability's resource bound, {} for none, for a source,
	// and for a host that predates bounds.
	Bounds CapabilityBounds `json:"bounds"`
}

// Listing kinds.
const (
	ListedKindCapability = "capability"
	ListedKindSource     = "source"
)

// viaLess orders via entries self before policy, then by network, and
// within one network the entry with from_agent null first, then by agent.
func viaLess(a, b ToolVia) bool {
	rank := map[string]int{AuthorizationSelf: 0, AuthorizationPolicy: 1}
	if rank[a.Kind] != rank[b.Kind] {
		return rank[a.Kind] < rank[b.Kind]
	}
	if deref(a.NetworkID) != deref(b.NetworkID) {
		return deref(a.NetworkID) < deref(b.NetworkID)
	}
	if (a.FromAgent == nil) != (b.FromAgent == nil) {
		return a.FromAgent == nil
	}
	return deref(a.FromAgent) < deref(b.FromAgent)
}

// readOperation is the read operation over a capability's resources.
func readOperation(resources []SnapshotResource) ListedOperation {
	uris := make([]string, len(resources))
	for i, r := range resources {
		uris[i] = r.URI
	}
	schema, _ := json.Marshal(map[string]any{"type": "object", "properties": map[string]any{"uri": map[string]any{"type": "string", "enum": uris}}, "required": []string{"uri"}})
	return ListedOperation{Name: membership.OperationRead, InputSchema: schema, ReadOnly: true}
}

func toolOperation(snap toolSnapshotState, name string) ListedOperation {
	op := ListedOperation{Name: name, InputSchema: json.RawMessage("null")}
	if t, ok := snapshotTool(snap, name); ok {
		op.Description, op.InputSchema, op.ReadOnly = t.Description, t.InputSchema, t.ReadOnly
	}
	return op
}

// ListCapabilities lists the capabilities on this host the sender may use,
// and the sources opened to it, filtered by authorization without budgets
// or connectivity. With network, only that network is evaluated.
func (s *Store) ListCapabilities(ctx context.Context, sender, network string) ([]ListedCapability, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now()
	isBlocked, err := s.blocked(ctx, tx, sender)
	if err != nil {
		return nil, err
	}
	own, err := s.membershipsOf(ctx, tx, s.identity.ID)
	if err != nil {
		return nil, err
	}
	persons := map[string]bool{}
	var selfNetworks []string
	var rules []capabilityRuleCandidate
	for _, n := range own {
		if n.member.PersonID == nil || persons[*n.member.PersonID] {
			continue
		}
		persons[*n.member.PersonID] = true
		trusted, err := s.trustedSelf(ctx, tx, sender, *n.member.PersonID, network, now)
		if err != nil {
			return nil, err
		}
		selfNetworks = append(selfNetworks, trusted...)
		if !isBlocked {
			found, _, err := s.policyCapabilityRules(ctx, tx, sender, *n.member.PersonID, 0, network, "", nil, now, true)
			if err != nil {
				return nil, err
			}
			rules = append(rules, found...)
		}
	}
	sort.Strings(selfNetworks)
	selfVia := func() []ToolVia {
		list := []ToolVia{}
		for _, id := range selfNetworks {
			id := id
			list = append(list, ToolVia{Kind: AuthorizationSelf, NetworkID: &id})
		}
		return list
	}
	out := []ListedCapability{}
	capabilities, err := records[capabilityRecord](ctx, tx, `SELECT record FROM capabilities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for _, c := range capabilities {
		via := selfVia()
		seen := map[string]bool{}
		for _, r := range rules {
			if r.rule.Capability != c.Name {
				continue
			}
			// A rule any other principal matches appears once; one only
			// agent: principals of the sender match, once per agent.
			agents := []*string{nil}
			if !r.broad {
				agents = nil
				for _, agent := range r.agents {
					agents = append(agents, &agent)
				}
			}
			for _, agent := range agents {
				key := r.network + "/" + deref(agent)
				if seen[key] {
					continue
				}
				seen[key] = true
				network, person, version := r.network, r.person, r.version
				via = append(via, ToolVia{Kind: AuthorizationPolicy, NetworkID: &network, PersonID: &person, Version: &version, FromAgent: agent})
			}
		}
		if len(via) == 0 {
			continue
		}
		sort.SliceStable(via, func(i, j int) bool { return viaLess(via[i], via[j]) })
		state, unavailable, snap, err := capabilityState(ctx, tx, c)
		if err != nil {
			return nil, err
		}
		entry := ListedCapability{Kind: ListedKindCapability, Capability: c.Name, Operations: []ListedOperation{}, Resources: []SnapshotResource{}, State: state, Unavailable: unavailable, Via: via, Bounds: c.Bounds}
		for _, op := range c.Operations {
			listed := toolOperation(snap, op)
			listed.InputSchema = narrowSchema(listed.InputSchema, c.Bounds, c.Source.Agent == builtinAgent)
			entry.Operations = append(entry.Operations, listed)
		}
		if c.Resources.Set {
			entry.Resources = readURIs(c, snap)
			entry.Operations = append(entry.Operations, readOperation(entry.Resources))
		}
		// An operation needs approval when covered, and either a policy
		// authorizes the entry or agent_self is true.
		req := c.requirement()
		viaPolicy := false
		for _, v := range via {
			if v.Kind == AuthorizationPolicy {
				viaPolicy = true
			}
		}
		for i := range entry.Operations {
			entry.Operations[i].Approval = req.covers(entry.Operations[i].Name, snap) && (viaPolicy || req.AgentSelf)
		}
		out = append(out, entry)
	}
	// Sources opened to a trusted sender, as implicit capabilities.
	if len(selfNetworks) > 0 {
		open, err := openTo(ctx, tx, sender)
		if err != nil {
			return nil, err
		}
		agents, err := agentsIn(ctx, tx)
		if err != nil {
			return nil, err
		}
		// Built-in sources are listed as builtin/NAME, beside the agents'.
		agents = append(agents, localAgent{id: builtinAgent, name: builtinAgent})
		for _, a := range agents {
			if !open {
				break
			}
			if a.name == builtinAgent && a.id != builtinAgent {
				continue // an agent named builtin: the name means the built-in sources
			}
			servers, err := sourceRecords(ctx, tx, a.id)
			if err != nil {
				return nil, err
			}
			for _, srv := range servers {
				if !srv.Shareable || srv.SnapshotAt == nil {
					continue
				}
				entry := ListedCapability{Kind: ListedKindSource, Capability: a.name + "/" + srv.Name, Operations: []ListedOperation{}, Resources: []SnapshotResource{}, State: CapabilityAvailable, Unavailable: []string{}, Via: selfVia()}
				for _, t := range srv.Tools {
					if t.Name != membership.OperationRead {
						entry.Operations = append(entry.Operations, ListedOperation{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema, ReadOnly: t.ReadOnly})
					}
				}
				if len(srv.Resources) > 0 {
					entry.Resources = append(entry.Resources, srv.Resources...)
					entry.Operations = append(entry.Operations, readOperation(entry.Resources))
				}
				out = append(out, entry)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Capability < out[j].Capability })
	return out, nil
}

func callPeerRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("GET /peer/v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		result, err := store.ListCapabilities(r.Context(), id, r.URL.Query().Get("network"))
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("POST /peer/v1/calls", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		var request CallRequest
		if !decode(w, r, &request, "call_id", "policy", "self", "capability", "operation", "input", "deadline", "origin") {
			return
		}
		st, err := store.AcceptCall(r.Context(), id, request)
		respond(w, http.StatusOK, st, err)
	})
	mux.HandleFunc("GET /peer/v1/calls/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		wait, known, knownApproval, err := peerWait(r)
		if err != nil {
			respond(w, 0, nil, err)
			return
		}
		st, err := store.HeldSubmitterCall(r.Context(), id, r.PathValue("id"), wait, known, knownApproval)
		respond(w, http.StatusOK, st, err)
	})
	mux.HandleFunc("POST /peer/v1/calls/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		if !decode(w, r, &struct{}{}) {
			return
		}
		st, err := store.RequestCallCancel(r.Context(), id, r.PathValue("id"))
		respond(w, http.StatusOK, st, err)
	})
}
