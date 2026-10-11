package host

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Cerebral-Systems/capsule/go/internal/membership"
)

// Sending by address: the owner API, the CLI, and directory sessions name a
// target as PERSON/AGENT or HOST_ID/AGENT. The daemon resolves it in the
// directory and chooses an authorization before persisting anything; the
// stored request keeps the resolved host and agent, so retries and status
// never resolve again.

// AddressMatch is one candidate of an ambiguous address.
type AddressMatch struct {
	Address   string `json:"address"`
	NetworkID string `json:"network_id"`
}

// codedError is a refusal whose JSON body carries a specific code: address
// resolution (with matches), authorization, directory access, and the rate
// cap (with retry_after).
type codedError struct {
	status     int
	code       string
	message    string
	matches    []AddressMatch
	retryAfter int64
}

func (e *codedError) Error() string { return e.message }

func (e *codedError) body() any {
	switch {
	case e.matches != nil:
		return struct {
			Code    string         `json:"code"`
			Error   string         `json:"error"`
			Matches []AddressMatch `json:"matches"`
		}{e.code, e.message, e.matches}
	case e.code == "rate_limited":
		return struct {
			Code       string `json:"code"`
			Error      string `json:"error"`
			RetryAfter int64  `json:"retry_after"`
		}{e.code, e.message, e.retryAfter}
	}
	return struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}{e.code, e.message}
}

var errNoDirectory = &codedError{status: http.StatusForbidden, code: "no_directory", message: "this session has no directory access; it may send only through its configured destinations"}

// addressTarget is a resolved address: one remote agent in one network,
// with the authorizations its host lists for this host.
type addressTarget struct {
	network, host, agentID string
	auths                  []DirectoryAuthorization
	local                  bool
}

func (t addressTarget) match(name string) AddressMatch {
	return AddressMatch{Address: t.host + "/" + name, NetworkID: t.network}
}

// resolveAddress finds the one agent an address names, in the given network
// or in every network this host belongs to, refreshing the directory once
// when nothing matches.
func (s *Store) resolveAddress(ctx context.Context, to, network, action, origin string) (addressTarget, error) {
	cut := strings.LastIndex(to, "/")
	if cut <= 0 || cut == len(to)-1 || len(to) > 256 {
		return addressTarget{}, fmt.Errorf("%w: an address is PERSON/AGENT or HOST_ID/AGENT", ErrInvalid)
	}
	left, name := to[:cut], to[cut+1:]
	var networks []string
	if network != "" {
		if _, err := s.Network(ctx, network); err != nil {
			return addressTarget{}, err
		}
		networks = []string{network}
	} else {
		all, err := s.Networks(ctx)
		if err != nil {
			return addressTarget{}, err
		}
		for _, n := range all {
			networks = append(networks, n.ID)
		}
	}
	matches, err := s.findAddress(ctx, networks, left, name, action, origin)
	if err != nil {
		return addressTarget{}, err
	}
	if len(matches) == 0 && AddressableName(name) {
		for _, id := range networks {
			if err = s.refreshWithin(ctx, id, ""); err != nil && !errors.Is(err, ErrNotFound) {
				return addressTarget{}, err
			}
		}
		if matches, err = s.findAddress(ctx, networks, left, name, action, origin); err != nil {
			return addressTarget{}, err
		}
	}
	switch {
	case len(matches) == 0:
		return addressTarget{}, &codedError{status: http.StatusNotFound, code: "unknown", message: fmt.Sprintf("no agent in the directory has the address %s", to), matches: []AddressMatch{}}
	case len(matches) > 1:
		listed := make([]AddressMatch, len(matches))
		names := make([]string, len(matches))
		for i, m := range matches {
			listed[i] = m.match(name)
			names[i] = listed[i].Address + " in " + m.network
		}
		return addressTarget{}, &codedError{status: http.StatusConflict, code: "ambiguous", message: fmt.Sprintf("the address %s names more than one agent: %s; use HOST_ID/AGENT or --network", to, strings.Join(names, ", ")), matches: listed}
	case matches[0].local:
		return addressTarget{}, &codedError{status: http.StatusBadRequest, code: "local", message: fmt.Sprintf("the address %s names an agent on this host; Capsule has no local delivery", to), matches: []AddressMatch{}}
	}
	return matches[0], nil
}

// findAddress lists the agents an address names, each once, in the lowest
// network whose entry lists an authorization for the action and origin
// (else the lowest that lists it), sorted by network then host.
func (s *Store) findAddress(ctx context.Context, networks []string, left, name, action, origin string) ([]addressTarget, error) {
	if !AddressableName(name) {
		return nil, nil
	}
	byHost := validID(left, "host", 32)
	locals, err := s.localAgents(ctx)
	if err != nil {
		return nil, err
	}
	var local string
	for _, a := range locals {
		if a.name == name {
			local = a.id
		}
	}
	seen, remote := map[string]bool{}, map[string]int{}
	var out []addressTarget
	d := s.directoryInit()
	sort.Strings(networks)
	for _, network := range networks {
		members, err := membersOf(ctx, s.db, network)
		if err != nil {
			return nil, err
		}
		names := func(host string) bool {
			if byHost {
				return host == left
			}
			m, ok := members[host]
			return ok && m.PersonID != nil && m.PersonMember != nil && membership.LabelsConflict(*m.PersonMember, left)
		}
		if local != "" && names(s.identity.ID) && !seen[s.identity.ID+"/"+local] {
			seen[s.identity.ID+"/"+local] = true
			out = append(out, addressTarget{network: network, host: s.identity.ID, agentID: local, local: true})
		}
		d.mu.Lock()
		if nd := d.networks[network]; nd != nil {
			hosts := make([]string, 0, len(nd.hosts))
			for id := range nd.hosts {
				hosts = append(hosts, id)
			}
			sort.Strings(hosts)
			for _, id := range hosts {
				if _, member := members[id]; !member || !names(id) {
					continue
				}
				for _, a := range nd.hosts[id].agents {
					if a.Name != name {
						continue
					}
					target := addressTarget{network: network, host: id, agentID: a.AgentID, auths: a.Authorizations}
					// One agent listed in several networks is one match. It
					// resolves in the lowest network whose entry lists an
					// authorization for the action, else the lowest.
					if i, ok := remote[id+"/"+a.AgentID]; ok {
						if len(candidates(out[i].auths, action, origin)) == 0 && len(candidates(a.Authorizations, action, origin)) > 0 {
							out[i] = target
						}
						continue
					}
					remote[id+"/"+a.AgentID] = len(out)
					out = append(out, target)
				}
			}
		}
		d.mu.Unlock()
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].network != out[j].network {
			return out[i].network < out[j].network
		}
		return out[i].host < out[j].host
	})
	return out, nil
}

// cachedAuthorizations re-reads a target's authorizations from the cache.
func (s *Store) cachedAuthorizations(t addressTarget) []DirectoryAuthorization {
	d := s.directoryInit()
	d.mu.Lock()
	defer d.mu.Unlock()
	if nd := d.networks[t.network]; nd != nil {
		if h := nd.hosts[t.host]; h != nil {
			for _, a := range h.agents {
				if a.AgentID == t.agentID {
					return a.Authorizations
				}
			}
		}
	}
	return nil
}

// candidates orders the authorizations allowing action for origin: self
// access, then policy rules, then grants by latest expiry.
func candidates(auths []DirectoryAuthorization, action, origin string) []DirectoryAuthorization {
	var self, policies, grants []DirectoryAuthorization
	for _, a := range auths {
		if !a.allows(action, origin) {
			continue
		}
		switch a.Kind {
		case authorizationKindSelf:
			self = append(self, a)
		case authorizationKindPolicy:
			policies = append(policies, a)
		case authorizationKindGrant:
			grants = append(grants, a)
		}
	}
	sort.SliceStable(grants, func(i, j int) bool {
		a, aErr := parseTime(grants[i].ExpiresAt)
		b, bErr := parseTime(grants[j].ExpiresAt)
		return aErr == nil && (bErr != nil || a.After(b))
	})
	return append(append(self, policies...), grants...)
}

// citation is a request's authorization: a grant, or an owner citation.
type citation struct {
	grant *string
	owner ownerCitation
}

// authorizeTarget chooses the first listed authorization allowing action
// whose citation this host can form. With none, it syncs the network once,
// so a policy submitted moments ago can be cited, and refreshes the target's
// host, then tries again before refusing with not_authorized.
func (s *Store) authorizeTarget(ctx context.Context, t *addressTarget, action, origin string) (citation, error) {
	for attempt := 0; ; attempt++ {
		for _, a := range candidates(t.auths, action, origin) {
			switch a.Kind {
			case authorizationKindSelf:
				person, ok, err := s.selfPerson(ctx, s.db, t.host)
				if err != nil {
					return citation{}, err
				}
				if ok {
					return citation{owner: ownerCitation{self: &SelfCitation{PersonID: person}}}, nil
				}
			case authorizationKindPolicy:
				cited, until, err := s.policyCitationUntil(ctx, s.db, t.host)
				if err == nil {
					return citation{owner: ownerCitation{policy: cited, until: until}}, nil
				}
				if !errors.Is(err, ErrInvalid) {
					return citation{}, err
				}
			case authorizationKindGrant:
				id := a.GrantID
				return citation{grant: &id}, nil
			}
		}
		if attempt > 0 {
			return citation{}, &codedError{status: http.StatusForbidden, code: "not_authorized", message: fmt.Sprintf("no self access, policy rule, or grant of host %s allows %s to agent %s", t.host, action, t.agentID)}
		}
		// The sync and the refresh run together, so the retry costs the
		// longer of the two; any sync that starts meanwhile serves.
		synced, since := make(chan struct{}), time.Now()
		go func() {
			defer close(synced)
			_, _ = s.syncNetworkSince(ctx, t.network, since)
		}()
		err := s.refreshWithin(ctx, t.network, t.host)
		select {
		case <-synced:
		case <-ctx.Done():
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return citation{}, err
		}
		t.auths = s.cachedAuthorizations(*t)
	}
}

// addressOutbound resolves an owner send's address and chooses its
// authorization unless a grant is given.
func (s *Store) addressOutbound(ctx context.Context, r *SendMessage) error {
	if r.PeerHostID != "" || r.TargetAgentID != "" || r.Policy != nil || r.Self != nil {
		return fmt.Errorf("%w: give either to or peer_host_id and target_agent_id", ErrInvalid)
	}
	origin := ""
	if r.Origin != nil {
		origin = r.Origin.AgentID
	}
	t, err := s.resolveAddress(ctx, *r.To, r.Network, membership.PolicyActionMessage, origin)
	if err != nil {
		return err
	}
	r.PeerHostID, r.TargetAgentID = t.host, t.agentID
	if r.GrantID != nil {
		return nil
	}
	c, err := s.authorizeTarget(ctx, &t, membership.PolicyActionMessage, origin)
	if err != nil {
		return err
	}
	r.GrantID, r.Policy, r.Self = c.grant, c.owner.policy, c.owner.self
	return nil
}

// addressTask resolves an owner task submission's address and, unless it is
// a forward, chooses its authorization.
func (s *Store) addressTask(ctx context.Context, r *SubmitTask) error {
	if r.PeerHostID != "" || r.TargetAgentID != "" {
		return fmt.Errorf("%w: give either to or peer_host_id and target_agent_id", ErrInvalid)
	}
	origin, action := "", membership.PolicyActionTask
	if r.Origin != nil {
		origin = r.Origin.AgentID
	}
	if r.Parent != nil {
		action = membership.PolicyActionDelegate
	}
	t, err := s.resolveAddress(ctx, *r.To, r.Network, action, origin)
	if err != nil {
		return err
	}
	r.PeerHostID, r.TargetAgentID = t.host, t.agentID
	// A forward relies on its chain's originator's authorization, which
	// PrepareOutboundTask cites; it does not choose from the directory.
	if r.GrantID != nil || r.Parent != nil {
		return nil
	}
	c, err := s.authorizeTarget(ctx, &t, membership.PolicyActionTask, origin)
	if err != nil {
		return err
	}
	r.GrantID, r.cite = c.grant, &c.owner
	return nil
}

// checkRate enforces a directory credential's hourly cap on sends and
// delegations by address.
func checkRate(ctx context.Context, tx *sql.Tx, a Adapter, now time.Time) error {
	limit := int64(defaultMaxSendsPerHour)
	if a.MaxSendsPerHour != nil {
		limit = *a.MaxSendsPerHour
	}
	since := now.Add(-time.Hour).UnixMilli()
	var count int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM directory_sends WHERE adapter_id = ? AND sent_at_ms > ?`, a.ID, since).Scan(&count); err != nil {
		return err
	}
	if count < limit {
		return nil
	}
	// The send that must leave the window first to admit one more.
	var at int64
	if err := tx.QueryRowContext(ctx, `SELECT sent_at_ms FROM directory_sends WHERE adapter_id = ? AND sent_at_ms > ? ORDER BY sent_at_ms LIMIT 1 OFFSET ?`, a.ID, since, count-limit).Scan(&at); err != nil {
		return err
	}
	wait := (at + time.Hour.Milliseconds() - now.UnixMilli() + 999) / 1000
	return &codedError{status: http.StatusTooManyRequests, code: "rate_limited", message: fmt.Sprintf("this session may send and delegate by address at most %d times in 60 minutes", limit), retryAfter: max(wait, 1)}
}

func countSend(ctx context.Context, tx *sql.Tx, adapter, kind, peer, id string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO directory_sends VALUES (?, ?, ?, ?, ?)`, adapter, kind, peer, id, now.UnixMilli())
	return err
}

// directoryAuthority is adapterAuthority for a request by address.
func directoryAuthority(ctx context.Context, tx *sql.Tx, auth AdapterAuth) (Adapter, Session, error) {
	a, ss, err := adapterAuthority(ctx, tx, auth)
	if err == nil && !a.Directory {
		err = errNoDirectory
	}
	return a, ss, err
}

// repeatAddressSend returns the stored send of a request ID this credential
// already sent by address; found is false when there is none.
func repeatAddressSend(ctx context.Context, tx *sql.Tx, a Adapter, ss Session, r AdapterSend) (OutboundMessage, bool, error) {
	var peer, session string
	var route sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT peer, session_id, route_id FROM adapter_outbound WHERE adapter_id = ? AND request_id = ?`, a.ID, r.RequestID).Scan(&peer, &session, &route)
	if errors.Is(err, sql.ErrNoRows) {
		return OutboundMessage{}, false, nil
	}
	if err != nil {
		return OutboundMessage{}, true, err
	}
	old, err := readJSON[OutboundMessage](tx.QueryRowContext(ctx, `SELECT record FROM outbound_messages WHERE peer = ? AND request_id = ?`, peer, r.RequestID))
	if err != nil {
		return old, true, err
	}
	if session != ss.ID {
		return old, true, ErrForbidden
	}
	if route.Valid || old.To == nil || *old.To != *r.To || old.Request.Content != r.Content {
		return old, true, ErrConflict
	}
	deadline, err := parseTime(old.Request.Deadline)
	if err != nil {
		return old, true, err
	}
	if !deadline.After(time.Now()) && old.State != "accepted" {
		return old, true, ErrForbidden
	}
	return old, true, nil
}

// prepareAddressSend persists a directory session's send by address. It
// counts toward the hourly cap only when first persisted.
func (s *Store) prepareAddressSend(ctx context.Context, token AdapterAuth, r AdapterSend) (OutboundMessage, error) {
	if r.Destination != "" || *r.To == "" || !validID(r.RequestID, "request", 16) || r.Content == "" || !utf8.ValidString(r.Content) || len(r.Content) > 65536 {
		return OutboundMessage{}, ErrInvalid
	}
	check := func(tx *sql.Tx) (Adapter, Session, *OutboundMessage, error) {
		a, ss, err := directoryAuthority(ctx, tx, token)
		if err != nil {
			return a, ss, nil, err
		}
		old, found, err := repeatAddressSend(ctx, tx, a, ss, r)
		if found || err != nil {
			return a, ss, &old, err
		}
		return a, ss, nil, checkRate(ctx, tx, a, time.Now())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundMessage{}, err
	}
	_, ss, old, err := check(tx)
	tx.Rollback()
	if old != nil || err != nil {
		return deref(old), err
	}
	// Resolution may refresh the directory, so it runs outside a transaction.
	t, err := s.resolveAddress(ctx, *r.To, r.Network, membership.PolicyActionMessage, ss.AgentID)
	if err != nil {
		return OutboundMessage{}, err
	}
	c, err := s.authorizeTarget(ctx, &t, membership.PolicyActionMessage, ss.AgentID)
	if err != nil {
		return OutboundMessage{}, err
	}
	if tx, err = s.db.BeginTx(ctx, nil); err != nil {
		return OutboundMessage{}, err
	}
	defer tx.Rollback()
	a, ss, old, err := check(tx)
	if old != nil || err != nil {
		return deref(old), err
	}
	now := time.Now()
	deadline := now.Add(adapterSendDeadline)
	if exp, err := parseTime(a.ExpiresAt); err == nil && exp.Before(deadline) {
		deadline = exp
	}
	to := *r.To
	out := OutboundMessage{PeerHostID: t.host, To: &to, Request: MessageRequest{RequestID: r.RequestID, GrantID: c.grant, Policy: c.owner.policy, Self: c.owner.self, TargetAgentID: t.agentID, Deadline: timestamp(deadline), Content: r.Content, Origin: &Origin{AgentID: ss.AgentID, SessionID: ss.ID}}, State: "unknown", NextAttemptAt: s.initialAttempt()}
	if err = insertOutbound(ctx, tx, out); err != nil {
		if isUniqueViolation(err) {
			return out, ErrConflict
		}
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO adapter_outbound (peer, request_id, adapter_id, session_id, route_id, next_poll_at, reply_delivery) VALUES (?, ?, ?, ?, NULL, 0, NULL)`, out.PeerHostID, out.Request.RequestID, a.ID, ss.ID); err != nil {
		return out, err
	}
	if err = countSend(ctx, tx, a.ID, "message", out.PeerHostID, out.Request.RequestID, now); err != nil {
		return out, err
	}
	if err = appendEvent(ctx, tx, "adapter.message_queued", out.PeerHostID+"/"+out.Request.RequestID, timestamp(now)); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func deref[T any](v *T) T {
	if v == nil {
		var zero T
		return zero
	}
	return *v
}

// repeatAddressTask returns the stored task of a task ID this credential
// already delegated by address; found is false when there is none.
func repeatAddressTask(ctx context.Context, tx *sql.Tx, a Adapter, ss Session, r AdapterDelegate) (OutboundTask, bool, error) {
	old, err := readJSON[OutboundTask](tx.QueryRowContext(ctx, `SELECT record FROM outbound_tasks WHERE task_id = ? AND json_extract(record, '$.adapter_id') = ? ORDER BY rowid LIMIT 1`, r.TaskID, a.ID))
	if errors.Is(err, ErrNotFound) {
		return old, false, nil
	}
	if err != nil {
		return old, true, err
	}
	switch {
	case old.Request.Origin == nil || old.Request.Origin.SessionID != ss.ID:
		return old, true, ErrForbidden
	case old.RouteID != nil || old.To == nil || *old.To != *r.To || old.Request.Input != r.Input || !sameManifest(old.Request.Artifacts, r.Artifacts) || (old.Parent == nil) != (r.ParentTaskID == "") || (old.Parent != nil && old.Parent.TaskID != r.ParentTaskID):
		return old, true, ErrConflict
	case old.Parent == nil && firstDepth(old.Request.Delegation) != r.DelegationDepth:
		return old, true, ErrConflict
	}
	return old, true, nil
}

// forwardCitation is a forward by address's owner citation: self when the
// originator and target hosts are bound to one person in the chain's
// network, otherwise the target owner's policy.
func (s *Store) forwardCitation(ctx context.Context, tx *sql.Tx, network, originator, target string) (ownerCitation, error) {
	members, err := membersOf(ctx, tx, network)
	if err != nil {
		return ownerCitation{}, err
	}
	from, okFrom := members[originator]
	to, okTo := members[target]
	if okFrom && okTo && from.PersonID != nil && to.PersonID != nil && *from.PersonID == *to.PersonID {
		return ownerCitation{self: &SelfCitation{PersonID: *from.PersonID}}, nil
	}
	cited, until, err := s.policyCitationUntil(ctx, tx, target)
	if errors.Is(err, ErrInvalid) {
		return ownerCitation{}, &codedError{status: http.StatusForbidden, code: "not_authorized", message: fmt.Sprintf("this host holds no access policy of the owner of host %s to cite for the forward", target)}
	}
	return ownerCitation{policy: cited, until: until}, err
}

// firstDepth is the depth of a chain's link 0, or 0 without a chain.
func firstDepth(chain []membership.Link) int64 {
	if len(chain) == 0 {
		return 0
	}
	return chain[0].Depth
}

// prepareAddressTask persists a directory session's delegation by address;
// with a parent task it forwards that task, which needs task.delegate.
func (s *Store) prepareAddressTask(ctx context.Context, auth AdapterAuth, r AdapterDelegate) (OutboundTask, error) {
	out, err := s.prepareAddressTaskOnce(ctx, auth, r)
	var refused *codedError
	if r.ParentTaskID == "" || !errors.As(err, &refused) || refused.code != "not_authorized" {
		return out, err
	}
	// A forward found no policy to cite: sync once, so it cites the newest.
	networks, nerr := s.Networks(ctx)
	if nerr != nil {
		return out, err
	}
	for _, n := range networks {
		_, _ = s.SyncNetwork(ctx, n.ID)
	}
	return s.prepareAddressTaskOnce(ctx, auth, r)
}

func (s *Store) prepareAddressTaskOnce(ctx context.Context, auth AdapterAuth, r AdapterDelegate) (OutboundTask, error) {
	if r.Destination != "" || *r.To == "" || !validID(r.TaskID, "task", 16) || !validText(r.Input, false) || (r.Artifacts != nil && !validManifest(r.Artifacts)) || (r.ParentTaskID != "" && !validID(r.ParentTaskID, "task", 16)) {
		return OutboundTask{}, ErrInvalid
	}
	if r.DelegationDepth < 0 || r.DelegationDepth > membership.DelegationMaxDepth || (r.DelegationDepth != 0 && r.ParentTaskID != "") {
		return OutboundTask{}, fmt.Errorf("%w: delegation_depth is 0 to 2, and a forward with parent_task_id continues its chain", ErrInvalid)
	}
	check := func(tx *sql.Tx) (Adapter, Session, *OutboundTask, error) {
		a, ss, err := directoryAuthority(ctx, tx, auth)
		if err != nil {
			return a, ss, nil, err
		}
		old, found, err := repeatAddressTask(ctx, tx, a, ss, r)
		if found || err != nil {
			return a, ss, &old, err
		}
		return a, ss, nil, checkRate(ctx, tx, a, time.Now())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundTask{}, err
	}
	_, ss, old, err := check(tx)
	if err == nil && old == nil && r.ParentTaskID != "" {
		_, _, _, err = ownedTask(ctx, tx, auth, r.ParentTaskID)
	}
	tx.Rollback()
	if old != nil || err != nil {
		return deref(old), err
	}
	action := membership.PolicyActionTask
	if r.ParentTaskID != "" {
		action = membership.PolicyActionDelegate
	}
	t, err := s.resolveAddress(ctx, *r.To, r.Network, action, ss.AgentID)
	if err != nil {
		return OutboundTask{}, err
	}
	// A forward relies on its chain's originator's authorization, cited
	// below; it does not choose from this host's directory entries.
	var c citation
	if r.ParentTaskID == "" {
		if c, err = s.authorizeTarget(ctx, &t, membership.PolicyActionTask, ss.AgentID); err != nil {
			return OutboundTask{}, err
		}
	}
	if tx, err = s.db.BeginTx(ctx, nil); err != nil {
		return OutboundTask{}, err
	}
	defer tx.Rollback()
	a, ss, old, err := check(tx)
	if old != nil || err != nil {
		return deref(old), err
	}
	var parent *TaskParent
	var parentRequest TaskRequest
	if r.ParentTaskID != "" {
		d, request, st, err := ownedTask(ctx, tx, auth, r.ParentTaskID)
		if err != nil {
			return OutboundTask{}, err
		}
		if err = s.checkForward(ctx, tx, request, st, t.host); err != nil {
			return OutboundTask{}, err
		}
		parent, parentRequest = &TaskParent{SenderHostID: d.SenderHostID, TaskID: d.TaskID}, request
	}
	now := time.Now()
	deadline := now.Add(taskDefaultDeadline)
	if exp, err := parseTime(a.ExpiresAt); err == nil && exp.Before(deadline) {
		deadline = exp
	}
	owner := c.owner
	if parent != nil {
		// checkForward ensured a chain. Cite self when the originator host
		// and the target host are bound to one person in the chain's
		// network, else the target owner's policy.
		link := parentRequest.Delegation[0]
		if owner, err = s.forwardCitation(ctx, tx, link.NetworkID, link.IssuerHostID, t.host); err != nil {
			return OutboundTask{}, err
		}
	}
	if owner.policy != nil && owner.until.Before(deadline) {
		deadline = owner.until
	}
	if err = requireStored(ctx, tx, r.Artifacts); err != nil {
		return OutboundTask{}, err
	}
	request := TaskRequest{TaskID: r.TaskID, GrantID: c.grant, Policy: owner.policy, Self: owner.self, TargetAgentID: t.agentID, Deadline: timestamp(deadline), Input: r.Input, Origin: &Origin{AgentID: ss.AgentID, SessionID: ss.ID}, Artifacts: r.Artifacts}
	if parent != nil {
		if err = forwardDeadline(&request, parentRequest, false); err != nil {
			return OutboundTask{}, err
		}
		request.Delegation = append(append([]membership.Link{}, parentRequest.Delegation...), s.nextLink(parentRequest.Delegation, t.host, request))
	} else if r.DelegationDepth > 0 {
		// Link 0 is in the network the address resolved in.
		request.Delegation = []membership.Link{s.firstLinkIn(t.network, t.host, request, r.DelegationDepth, []string{membership.PrincipalNetwork})}
	}
	adapterID, to := a.ID, *r.To
	out := OutboundTask{PeerHostID: t.host, To: &to, Request: request, SubmitState: submitUnknown, AdapterID: &adapterID, NextAttemptAt: s.initialAttempt(), Parent: parent, Delegation: request.Delegation}
	if err = insertOutboundTask(ctx, tx, out); err != nil {
		if isUniqueViolation(err) {
			return out, ErrConflict
		}
		return out, err
	}
	if parent != nil {
		if err = recordForward(ctx, tx, *parent, out); err != nil {
			return out, err
		}
	}
	if err = countSend(ctx, tx, a.ID, "task", out.PeerHostID, r.TaskID, now); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// AdapterAgent is one addressable agent a directory session may reach,
// with the union of the authorizations that apply to its agent.
type AdapterAgent struct {
	Address          string   `json:"address"`
	NetworkID        string   `json:"network_id"`
	Connected        bool     `json:"connected"`
	Actions          []string `json:"actions"`
	MaxMessageBytes  int64    `json:"max_message_bytes"`
	MaxArtifactBytes int64    `json:"max_artifact_bytes"`
}

// AdapterAgents is GET /adapter/v1/agents: the directory's addressable
// agents, ignoring policy rules limited to another agent of this host.
func (s *Store) AdapterAgents(ctx context.Context, token AdapterAuth) ([]AdapterAgent, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	_, ss, err := directoryAuthority(ctx, tx, token)
	tx.Rollback()
	if err != nil {
		return nil, err
	}
	networks, err := s.Networks(ctx)
	if err != nil {
		return nil, err
	}
	locals, err := s.localAgents(ctx)
	if err != nil {
		return nil, err
	}
	out := []AdapterAgent{}
	for _, n := range networks {
		members, err := s.NetworkMembers(ctx, n.ID)
		if err != nil {
			return nil, err
		}
		for _, entry := range s.directoryView(n.ID, members, locals).Agents {
			if entry.Address == nil {
				continue
			}
			agent := AdapterAgent{Address: *entry.Address, NetworkID: n.ID, Connected: entry.Connected}
			have := map[string]bool{}
			applies := false
			for _, a := range entry.Authorizations {
				if a.FromAgent != nil && *a.FromAgent != ss.AgentID {
					continue
				}
				applies = true
				for _, action := range a.Actions {
					have[action] = true
				}
				agent.MaxMessageBytes = max(agent.MaxMessageBytes, a.MaxMessageBytes)
				agent.MaxArtifactBytes = max(agent.MaxArtifactBytes, a.MaxArtifactBytes)
			}
			if !applies {
				continue
			}
			agent.Actions = orderedActions(have)
			out = append(out, agent)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].NetworkID < out[j].NetworkID
	})
	return out, nil
}

// orderedActions lists a set of actions in policy order.
func orderedActions(have map[string]bool) []string {
	actions := []string{}
	for _, action := range []string{membership.PolicyActionMessage, membership.PolicyActionTask, membership.PolicyActionDelegate} {
		if have[action] {
			actions = append(actions, action)
		}
	}
	return actions
}
