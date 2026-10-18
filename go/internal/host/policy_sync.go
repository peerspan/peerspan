package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Direct policy propagation (roadmap 2c). A host bound to person P pushes P's
// policies to P's other hosts in each network (its siblings) and to the
// coordinator, and fetches P's policy from its siblings at start, every five
// minutes, and when a sibling appears. A coordinator that withholds a newer
// policy, such as a withdrawal, then also has to partition the owner's hosts
// from one another. Block lists stay host-local.

// The v12 schema adds the delivery queue, one row per policy owner and target.
const policyDeliveriesSchema = `
CREATE TABLE policy_deliveries (network_id TEXT NOT NULL, person_id TEXT NOT NULL, target TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, person_id, target));
PRAGMA user_version = 12;
`

const (
	policyTargetCoordinator = "coordinator"
	policyDeliveryFirst     = time.Second
	policyDeliveryMax       = 5 * time.Minute
	policySyncInterval      = 5 * time.Minute
	policyDeliveryPoll      = 250 * time.Millisecond
)

// PolicyDelivery is one queued delivery of an owner's policy to a sibling
// host or the coordinator.
type PolicyDelivery struct {
	Target        string  `json:"target"`
	Version       int64   `json:"version"`
	State         string  `json:"state"` // pending or delivered
	Attempts      int64   `json:"attempts"`
	NextAttemptAt *string `json:"next_attempt_at"`
	Error         *string `json:"error"`
	DeliveredAt   *string `json:"delivered_at"`
}

// policyDeliveryRecord is the stored row: the delivery and its policy.
type policyDeliveryRecord struct {
	PolicyDelivery
	Policy membership.Policy `json:"policy"`
}

// PolicyHead names a stored policy: what a sibling reports after a push.
type PolicyHead struct {
	PersonID string `json:"person_id"`
	Version  int64  `json:"version"`
	SHA256   string `json:"sha256"`
}

// PolicySyncStatus is `access sync --status`: this host's person's stored
// policy and its deliveries.
type PolicySyncStatus struct {
	PersonID   string             `json:"person_id"`
	Version    *int64             `json:"version"`
	SHA256     *string            `json:"sha256"`
	Deliveries []PolicyDelivery   `json:"deliveries"`
	Edits      []PolicyEditStatus `json:"edits"`
}

// policySync is the daemon's propagation state: deliveries in flight, and
// wake-ups for the delivery worker and for sibling syncs.
type policySync struct {
	mu       sync.Mutex
	inflight map[string]bool
	wake     chan struct{}
	networks map[string]bool // networks that gained a sibling
	gained   chan struct{}
	// editWake and reapply schedule re-applying policy edits; acks holds,
	// per network/person, the highest edit of this host each sibling and
	// the coordinator is known to hold.
	editWake chan struct{}
	reapply  map[string]bool
	acks     map[string]map[string]int64
}

func (s *Store) policyState() *policySync {
	p := &s.policies
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wake == nil {
		p.wake, p.gained, p.inflight, p.networks = make(chan struct{}, 1), make(chan struct{}, 1), map[string]bool{}, map[string]bool{}
		p.editWake, p.reapply, p.acks = make(chan struct{}, 1), map[string]bool{}, map[string]map[string]int64{}
	}
	return p
}

// wakePolicyDeliveries makes the delivery worker look for due deliveries now.
func (s *Store) wakePolicyDeliveries() {
	select {
	case s.policyState().wake <- struct{}{}:
	default:
	}
}

// siblingGained schedules a sync of a network whose membership view gained a
// sibling.
func (s *Store) siblingGained(network string) {
	p := s.policyState()
	p.mu.Lock()
	p.networks[network] = true
	p.mu.Unlock()
	select {
	case p.gained <- struct{}{}:
	default:
	}
}

// ownPerson is the person this host is bound to in a network, or "".
func (s *Store) ownPerson(ctx context.Context, q dbQuerier, network string) (string, error) {
	self, err := readJSON[NetworkMember](q.QueryRowContext(ctx, "SELECT record FROM network_members WHERE network_id = ? AND host_id = ?", network, s.identity.ID))
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil || self.PersonID == nil {
		return "", err
	}
	return *self.PersonID, nil
}

// boundHosts lists the other member hosts of a network bound to a person:
// for this host's own person, its siblings. Members are already only the
// current, unrevoked hosts of this host's view.
func (s *Store) boundHosts(ctx context.Context, q dbQuerier, network, person string) ([]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT host_id, record FROM network_members WHERE network_id = ? ORDER BY host_id", network)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, record string
		if err = rows.Scan(&id, &record); err != nil {
			return nil, err
		}
		var m NetworkMember
		if err = json.Unmarshal([]byte(record), &m); err != nil {
			return nil, err
		}
		if id != s.identity.ID && m.PersonID != nil && *m.PersonID == person {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// siblings returns this host's person in a network and its siblings there.
func (s *Store) siblings(ctx context.Context, q dbQuerier, network string) (string, []string, error) {
	person, err := s.ownPerson(ctx, q, network)
	if err != nil || person == "" {
		return person, nil, err
	}
	hosts, err := s.boundHosts(ctx, q, network, person)
	return person, hosts, err
}

// isSibling reports whether this host and another are both bound to a person
// in a network.
func (s *Store) isSibling(ctx context.Context, q dbQuerier, network, person, host string) (bool, error) {
	own, hosts, err := s.siblings(ctx, q, network)
	if err != nil || own != person || person == "" {
		return false, err
	}
	for _, h := range hosts {
		if h == host {
			return true, nil
		}
	}
	return false, nil
}

// acceptPolicy applies the acceptance rule to a policy from any source: it
// must verify, be inside its window, and belong to a current person, and it
// is stored if its version is higher than the stored one, or equal with a
// lower statement hash. It reports whether the policy was stored.
func (s *Store) acceptPolicy(ctx context.Context, tx *sql.Tx, network string, p membership.Policy, now time.Time) (bool, error) {
	g, err := s.loadGovernance(ctx, tx, network)
	if err != nil {
		return false, err
	}
	if err = membership.VerifyPolicy(network, p); err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !membership.PolicyActive(p, now) {
		return false, fmt.Errorf("%w: the policy is not within its validity window", ErrInvalid)
	}
	if _, ok := g.persons()[p.PersonPublicKey]; !ok {
		return false, fmt.Errorf("%w: the policy owner is not a current person of this network", ErrForbidden)
	}
	if old, ok := g.storedPolicy(p.PersonPublicKey); ok && !membership.PolicyPreferred(p, old) {
		return false, nil
	}
	return true, s.storePolicy(ctx, tx, network, p, timestamp(now))
}

// storePolicy records a policy that won the acceptance rule. A policy of this
// host's own person is queued for delivery to every sibling and the
// coordinator, superseding older deliveries.
func (s *Store) storePolicy(ctx context.Context, tx *sql.Tx, network string, p membership.Policy, now string) error {
	if err := putRecord(ctx, tx, network, kindPolicy, p.PersonPublicKey, p); err != nil {
		return err
	}
	// What other hosts list to this one may have changed.
	s.directoryChanged(network)
	person := personIDOf(p.PersonPublicKey)
	if err := appendEvent(ctx, tx, "network.policy_updated", person, now); err != nil {
		return err
	}
	at, _ := parseTime(now)
	if err := s.editsChanged(ctx, tx, network, p, at); err != nil {
		return err
	}
	own, hosts, err := s.siblings(ctx, tx, network)
	if err != nil || own != person {
		return err
	}
	return queueDeliveries(ctx, tx, network, person, p, append(hosts, policyTargetCoordinator), now)
}

// queueDeliveries replaces an owner's deliveries with fresh pending ones of p.
func queueDeliveries(ctx context.Context, tx *sql.Tx, network, person string, p membership.Policy, targets []string, now string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM policy_deliveries WHERE network_id = ? AND person_id = ?", network, person); err != nil {
		return err
	}
	for _, target := range targets {
		at := now
		record := policyDeliveryRecord{PolicyDelivery{Target: target, Version: p.Version, State: "pending", NextAttemptAt: &at}, p}
		if err := putJSON(ctx, tx, "INSERT INTO policy_deliveries (record, network_id, person_id, target) VALUES (?, ?, ?, ?)", record, network, person, target); err != nil {
			return err
		}
	}
	return nil
}

// policyBackoff is the delay after a delivery's attempts-th failed attempt:
// 1 second doubling to 5 minutes, with ±20% jitter.
func (s *Store) policyBackoff(attempts int64) time.Duration {
	delay := policyDeliveryMax
	if attempts >= 1 && attempts <= 9 {
		delay = min(policyDeliveryFirst<<(attempts-1), policyDeliveryMax)
	}
	return time.Duration(float64(delay) * s.retryJitter())
}

// claimDelivery serializes attempts on one delivery.
func (s *Store) claimDelivery(key string) (func(), bool) {
	p := s.policyState()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inflight[key] {
		return nil, false
	}
	p.inflight[key] = true
	return func() {
		p.mu.Lock()
		delete(p.inflight, key)
		p.mu.Unlock()
	}, true
}

// awaitDelivery waits, up to timeout, until no attempt of the delivery is
// in progress, so a caller reporting status sees that attempt's outcome.
func (s *Store) awaitDelivery(ctx context.Context, key string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		p := s.policyState()
		p.mu.Lock()
		busy := p.inflight[key]
		p.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// attemptDelivery makes one attempt of a pending delivery and records its
// outcome, unless a newer policy superseded it meanwhile. It reports whether
// the delivery is done. A delivery to a host that is no longer a sibling is
// dropped.
func (s *Store) attemptDelivery(ctx context.Context, network, person, target string) (bool, error) {
	release, ok := s.claimDelivery(network + "/" + person + "/" + target)
	if !ok {
		return false, nil
	}
	defer release()
	rec, err := readJSON[policyDeliveryRecord](s.db.QueryRowContext(ctx, "SELECT record FROM policy_deliveries WHERE network_id = ? AND person_id = ? AND target = ?", network, person, target))
	if err != nil || rec.State != "pending" {
		return rec.State == "delivered", ignoreNotFound(err)
	}
	if target != policyTargetCoordinator {
		sibling, err := s.isSibling(ctx, s.db, network, person, target)
		if err != nil {
			return false, err
		}
		if !sibling {
			_, err = s.db.ExecContext(ctx, "DELETE FROM policy_deliveries WHERE network_id = ? AND person_id = ? AND target = ?", network, person, target)
			return false, err
		}
	}
	n, err := s.Network(ctx, network)
	if err != nil {
		return false, err
	}
	done, attemptErr := false, error(nil)
	if target == policyTargetCoordinator {
		_, attemptErr = s.callCoordinator(ctx, n, networkPath(n, "/policies"), map[string]any{"policy": rec.Policy})
		done = attemptErr == nil || errors.Is(attemptErr, ErrConflict)
		if attemptErr == nil {
			s.ackEdits(network, person, policyTargetCoordinator, rec.Policy.EditSeq(s.identity.ID))
		}
	} else {
		var head PolicyHead
		head, attemptErr = s.pushPolicy(ctx, network, target, rec.Policy)
		done = attemptErr == nil && head.Version >= rec.Version
		if attemptErr == nil && head.SHA256 == membership.PolicyHash(rec.Policy) {
			s.ackEdits(network, person, target, rec.Policy.EditSeq(s.identity.ID))
		}
		if attemptErr == nil && !done {
			attemptErr = fmt.Errorf("sibling reported version %d", head.Version)
		}
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(finishCtx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	current, err := readJSON[policyDeliveryRecord](tx.QueryRowContext(finishCtx, "SELECT record FROM policy_deliveries WHERE network_id = ? AND person_id = ? AND target = ?", network, person, target))
	if err != nil || current.State != "pending" || current.Version != rec.Version || current.Policy.Signature != rec.Policy.Signature {
		return false, ignoreNotFound(err) // superseded or dropped meanwhile
	}
	now := s.retryNow()
	current.Attempts++
	if done {
		at := timestamp(now)
		current.State, current.NextAttemptAt, current.Error, current.DeliveredAt = "delivered", nil, nil, &at
		if err = appendEvent(finishCtx, tx, "network.policy_delivered", person+"/"+target, at); err != nil {
			return false, err
		}
	} else {
		message, next := attemptErr.Error(), timestamp(now.Add(s.policyBackoff(current.Attempts)))
		current.Error, current.NextAttemptAt = &message, &next
	}
	if err = putJSON(finishCtx, tx, "UPDATE policy_deliveries SET record = ? WHERE network_id = ? AND person_id = ? AND target = ?", current, network, person, target); err != nil {
		return false, err
	}
	return done, tx.Commit()
}

func ignoreNotFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// pushPolicy sends a policy to a sibling, which reports its stored policy.
func (s *Store) pushPolicy(ctx context.Context, network, sibling string, p membership.Policy) (PolicyHead, error) {
	var head PolicyHead
	peer, err := s.dialPeer(ctx, sibling)
	if err != nil {
		return head, err
	}
	body, err := json.Marshal(SubmitPolicy{Policy: &p})
	if err != nil {
		return head, err
	}
	status, data, err := s.peerRequest(ctx, peer, http.MethodPost, "/peer/v1/networks/"+url.PathEscape(network)+"/policies", body)
	if err != nil {
		return head, err
	}
	if status != http.StatusOK {
		return head, fmt.Errorf("sibling returned HTTP %d", status)
	}
	if err = decodeStrict(data, &head); err != nil {
		return head, fmt.Errorf("invalid sibling policy report: %v", err)
	}
	return head, nil
}

// fetchPolicy asks a sibling for its stored policy of a person; nil if none.
func (s *Store) fetchPolicy(ctx context.Context, network, sibling, person string) (*membership.Policy, error) {
	peer, err := s.dialPeer(ctx, sibling)
	if err != nil {
		return nil, err
	}
	status, data, err := s.peerRequest(ctx, peer, http.MethodGet, "/peer/v1/networks/"+url.PathEscape(network)+"/policies/"+url.PathEscape(person), nil)
	switch {
	case err != nil:
		return nil, err
	case status == http.StatusNotFound:
		return nil, nil
	case status != http.StatusOK:
		return nil, fmt.Errorf("sibling returned HTTP %d", status)
	}
	p, err := membership.DecodePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("invalid sibling policy: %v", err)
	}
	return &p, nil
}

// syncPolicy asks each sibling for its stored policy of this host's person
// in a network and applies the acceptance rule to each answer.
func (s *Store) syncPolicy(ctx context.Context, network string, logf func(string, ...any)) error {
	person, hosts, err := s.siblings(ctx, s.db, network)
	if err != nil || person == "" {
		return err
	}
	for _, sibling := range hosts {
		p, err := s.fetchPolicy(ctx, network, sibling, person)
		if err != nil {
			logf("policy sync %s with %s: %v", network, sibling, err)
			continue
		}
		if p == nil || p.NetworkID != network || personIDOf(p.PersonPublicKey) != person {
			continue
		}
		if membership.VerifyPolicy(network, *p) == nil {
			s.ackEdits(network, person, sibling, p.EditSeq(s.identity.ID))
		}
		stored, err := s.storeSynced(ctx, network, sibling, *p)
		if err != nil {
			logf("policy sync %s with %s: %v", network, sibling, err)
			continue
		}
		if stored {
			s.wakePolicyDeliveries()
		}
	}
	return nil
}

func (s *Store) storeSynced(ctx context.Context, network, sibling string, p membership.Policy) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	now := s.retryNow()
	stored, err := s.acceptPolicy(ctx, tx, network, p, now)
	if err != nil || !stored {
		return false, err
	}
	if err = appendEvent(ctx, tx, "network.policy_synced", personIDOf(p.PersonPublicKey)+"/"+sibling, timestamp(now)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ReceivePolicy applies a sibling's push and reports the stored policy.
func (s *Store) ReceivePolicy(ctx context.Context, sender, network string, p membership.Policy) (PolicyHead, error) {
	if p.NetworkID != network {
		return PolicyHead{}, fmt.Errorf("%w: the policy is for a different network", ErrInvalid)
	}
	if _, err := membership.DecodeKey(p.PersonPublicKey); err != nil {
		return PolicyHead{}, fmt.Errorf("%w: invalid policy owner key", ErrInvalid)
	}
	person := personIDOf(p.PersonPublicKey)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PolicyHead{}, err
	}
	defer tx.Rollback()
	if sibling, err := s.isSibling(ctx, tx, network, person, sender); err != nil || !sibling {
		if err == nil {
			err = ErrForbidden
		}
		return PolicyHead{}, err
	}
	stored, err := s.acceptPolicy(ctx, tx, network, p, s.retryNow())
	if errors.Is(err, ErrForbidden) {
		err = fmt.Errorf("%w: the policy owner is not a current person of this network", ErrInvalid)
	}
	if err != nil {
		return PolicyHead{}, err
	}
	g, err := s.loadGovernance(ctx, tx, network)
	if err != nil {
		return PolicyHead{}, err
	}
	current, ok := g.storedPolicy(p.PersonPublicKey)
	if !ok {
		return PolicyHead{}, errors.New("stored policy missing")
	}
	if err = tx.Commit(); err != nil {
		return PolicyHead{}, err
	}
	if stored {
		s.wakePolicyDeliveries()
	}
	return PolicyHead{PersonID: person, Version: current.Version, SHA256: membership.PolicyHash(current)}, nil
}

// SiblingPolicy is a sibling's fetch of this host's stored policy of their
// shared person.
func (s *Store) SiblingPolicy(ctx context.Context, sender, network, person string) (membership.Policy, error) {
	if sibling, err := s.isSibling(ctx, s.db, network, person, sender); err != nil || !sibling {
		if err == nil {
			err = ErrForbidden
		}
		return membership.Policy{}, err
	}
	g, err := s.loadGovernance(ctx, s.db, network)
	if err != nil {
		return membership.Policy{}, err
	}
	key, ok := g.personKey(person)
	if !ok {
		return membership.Policy{}, ErrNotFound
	}
	p, ok := g.storedPolicy(key)
	if !ok {
		return p, ErrNotFound
	}
	return p, nil
}

// PolicySyncStatus reports this host's person's stored policy in a network
// and its deliveries, dropping deliveries to hosts no longer siblings.
func (s *Store) PolicySyncStatus(ctx context.Context, network string) (PolicySyncStatus, error) {
	status := PolicySyncStatus{Deliveries: []PolicyDelivery{}, Edits: []PolicyEditStatus{}}
	if _, err := s.Network(ctx, network); err != nil {
		return status, err
	}
	person, hosts, err := s.siblings(ctx, s.db, network)
	if err != nil {
		return status, err
	}
	if person == "" {
		return status, fmt.Errorf("%w: this host is not bound to a person in that network", ErrNotFound)
	}
	status.PersonID = person
	g, err := s.loadGovernance(ctx, s.db, network)
	if err != nil {
		return status, err
	}
	if key, ok := g.personKey(person); ok {
		if p, ok := g.storedPolicy(key); ok {
			hash := membership.PolicyHash(p)
			status.Version, status.SHA256 = &p.Version, &hash
		}
	}
	current := map[string]bool{policyTargetCoordinator: true}
	for _, h := range hosts {
		current[h] = true
	}
	rows, err := s.db.QueryContext(ctx, "SELECT target, record FROM policy_deliveries WHERE network_id = ? AND person_id = ? ORDER BY target", network, person)
	if err != nil {
		return status, err
	}
	var dropped []string
	for rows.Next() {
		var target, record string
		var rec policyDeliveryRecord
		if err = rows.Scan(&target, &record); err == nil {
			err = json.Unmarshal([]byte(record), &rec)
		}
		if err != nil {
			rows.Close()
			return status, err
		}
		if !current[target] {
			dropped = append(dropped, target)
			continue
		}
		status.Deliveries = append(status.Deliveries, rec.PolicyDelivery)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return status, err
	}
	for _, target := range dropped {
		if _, err = s.db.ExecContext(ctx, "DELETE FROM policy_deliveries WHERE network_id = ? AND person_id = ? AND target = ?", network, person, target); err != nil {
			return status, err
		}
	}
	sort.Slice(status.Deliveries, func(i, j int) bool { return status.Deliveries[i].Target < status.Deliveries[j].Target })
	status.Edits, err = s.editStatus(ctx, s.db, network, person)
	return status, err
}

// SyncPolicyNow runs one sync with every sibling, then attempts every pending
// delivery of this host's person in the network, and reports the status.
func (s *Store) SyncPolicyNow(ctx context.Context, network string, logf func(string, ...any)) (PolicySyncStatus, error) {
	if _, err := s.PolicySyncStatus(ctx, network); err != nil {
		return PolicySyncStatus{}, err
	}
	if err := s.syncPolicy(ctx, network, logf); err != nil {
		return PolicySyncStatus{}, err
	}
	person, err := s.ownPerson(ctx, s.db, network)
	if err != nil {
		return PolicySyncStatus{}, err
	}
	pending, err := s.pendingDeliveries(ctx, "network_id = ? AND person_id = ?", network, person)
	if err != nil {
		return PolicySyncStatus{}, err
	}
	var running sync.WaitGroup
	for _, d := range pending {
		running.Add(1)
		go func() {
			defer running.Done()
			s.awaitDelivery(ctx, d.network+"/"+d.person+"/"+d.target, 15*time.Second)
			if _, err := s.attemptDelivery(ctx, d.network, d.person, d.target); err != nil {
				logf("policy delivery %s/%s to %s: %v", d.network, d.person, d.target, err)
			}
		}()
	}
	running.Wait()
	return s.PolicySyncStatus(ctx, network)
}

type pendingDelivery struct {
	network, person, target string
	next                    time.Time
}

func (s *Store) pendingDeliveries(ctx context.Context, where string, args ...any) ([]pendingDelivery, error) {
	query := "SELECT network_id, person_id, target, record FROM policy_deliveries WHERE json_extract(record, '$.state') = 'pending'"
	if where != "" {
		query += " AND " + where
	}
	rows, err := s.db.QueryContext(ctx, query+" ORDER BY network_id, person_id, target", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pendingDelivery
	for rows.Next() {
		var d pendingDelivery
		var record string
		var rec policyDeliveryRecord
		if err = rows.Scan(&d.network, &d.person, &d.target, &record); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(record), &rec) != nil {
			continue
		}
		if rec.NextAttemptAt != nil {
			d.next, _ = parseTime(*rec.NextAttemptAt)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// syncAllPolicies syncs every network where this host is bound.
func (s *Store) syncAllPolicies(ctx context.Context, logf func(string, ...any)) {
	networks, err := s.Networks(ctx)
	if err != nil {
		return
	}
	for _, n := range networks {
		if ctx.Err() != nil {
			return
		}
		if err := s.syncPolicy(ctx, n.ID, logf); err != nil && ctx.Err() == nil {
			logf("policy sync %s: %v", n.ID, err)
		}
	}
}

// RunPolicySync syncs with siblings at start, every five minutes, and when a
// network gains a sibling, and attempts due deliveries, until ctx is
// cancelled.
func (s *Store) RunPolicySync(ctx context.Context, logf func(string, ...any)) {
	p := s.policyState()
	var running sync.WaitGroup
	defer running.Wait()
	running.Add(2)
	go func() {
		defer running.Done()
		s.runPolicyEdits(ctx, logf)
	}()
	go func() {
		defer running.Done()
		s.syncAllPolicies(ctx, logf)
		ticker := time.NewTicker(policySyncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.syncAllPolicies(ctx, logf)
			case <-p.gained:
				p.mu.Lock()
				networks := p.networks
				p.networks = map[string]bool{}
				p.mu.Unlock()
				for _, network := range sortedKeys(networks) {
					if err := s.syncPolicy(ctx, network, logf); err != nil && ctx.Err() == nil {
						logf("policy sync %s: %v", network, err)
					}
				}
			}
		}
	}()
	ticker := time.NewTicker(policyDeliveryPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-p.wake:
		}
		pending, err := s.pendingDeliveries(ctx, "")
		if err != nil {
			continue
		}
		now := s.retryNow()
		for _, d := range pending {
			if d.next.After(now) {
				continue
			}
			p.mu.Lock()
			busy := p.inflight[d.network+"/"+d.person+"/"+d.target]
			p.mu.Unlock()
			if busy {
				continue
			}
			running.Add(1)
			go func() {
				defer running.Done()
				if _, err := s.attemptDelivery(ctx, d.network, d.person, d.target); err != nil && ctx.Err() == nil {
					logf("policy delivery %s/%s to %s: %v", d.network, d.person, d.target, err)
				}
			}()
		}
	}
}

func localPolicySyncRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/networks/{id}/policy/sync", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.PolicySyncStatus(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, result, err)
	})
	mux.HandleFunc("POST /v1/networks/{id}/policy/sync", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.SyncPolicyNow(r.Context(), r.PathValue("id"), func(string, ...any) {})
		respond(w, http.StatusOK, result, err)
	})
}

func policyPeerRoutes(mux *http.ServeMux, store *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("POST /peer/v1/networks/{network}/policies", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		var req SubmitPolicy
		if !decode(w, r, &req, "policy") {
			return
		}
		if req.Policy == nil {
			respond(w, 0, nil, ErrInvalid)
			return
		}
		head, err := store.ReceivePolicy(r.Context(), id, r.PathValue("network"), *req.Policy)
		respond(w, http.StatusOK, head, err)
	})
	mux.HandleFunc("GET /peer/v1/networks/{network}/policies/{person}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		p, err := store.SiblingPolicy(r.Context(), id, r.PathValue("network"), r.PathValue("person"))
		respond(w, http.StatusOK, p, err)
	})
}
