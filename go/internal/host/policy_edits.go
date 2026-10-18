package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Concurrent policy edits (coordination contract, Concurrent edits). Each
// policy a CLI command on this host signs to change the rules is an edit,
// numbered per network and policy owner by this daemon. The daemon keeps
// each edit until a stored policy reflects it, re-applies any that a
// concurrent policy displaced, and applies an unsettled edit's withdrawals
// here at once.

// The v17 schema adds the edit records.
const policyEditsSchema = `
CREATE TABLE policy_edits (network_id TEXT NOT NULL, person_id TEXT NOT NULL, seq INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(network_id, person_id, seq));
PRAGMA user_version = 17;
`

// Edit record states. Edits of a person this host is no longer bound to
// keep their state, suspended, and resume if that binding returns.
const (
	editReserved  = "reserved"
	editSettled   = "settled"
	editUnsettled = "unsettled"
	editClosed    = "closed"
)

const (
	editReservationLapse = 10 * time.Minute
	editUnsettledAfter   = time.Minute
	editClosedRetention  = 7 * 24 * time.Hour
	editDroppedWindow    = 7 * 24 * time.Hour
	editReapplyJitter    = 2 * time.Second
)

// policyEditRecord is policy_edits.record.
type policyEditRecord struct {
	Seq           int64              `json:"seq"`
	State         string             `json:"state"`
	Start         *membership.Policy `json:"start"`
	Signed        *membership.Policy `json:"signed"`
	SignedVersion *int64             `json:"signed_version"`
	Dropped       []string           `json:"dropped"`
	ReservedAt    string             `json:"reserved_at"`
	SignedAt      *string            `json:"signed_at"`
	// When the record last became unsettled, was closed, or dropped an
	// addition: for status items 16 and 17 and retention.
	UnsettledAt *string `json:"unsettled_at,omitempty"`
	ClosedAt    *string `json:"closed_at,omitempty"`
	DroppedAt   *string `json:"dropped_at,omitempty"`
}

// startBody is the edit's starting point, empty when there was no policy.
func (r policyEditRecord) startBody() membership.PolicyBody {
	if r.Start == nil {
		return membership.Policy{}.Body()
	}
	return r.Start.Body()
}

// EditStart is GET /v1/networks/{id}/policy/edit.
type EditStart struct {
	Policy  *membership.Policy `json:"policy"`
	Version int64              `json:"version"`
	Seq     int64              `json:"seq"`
}

// PolicyEditStatus is one entry of access sync --status edits.
type PolicyEditStatus struct {
	Seq           int64    `json:"seq"`
	State         string   `json:"state"`
	SignedVersion *int64   `json:"signed_version"`
	Dropped       []string `json:"dropped"`
}

var errEditConflict = &codedError{status: http.StatusConflict, code: "edit_conflict", message: "another policy was stored since this edit started; start again from the edit route"}

func editRecords(ctx context.Context, q queryer, network, person, where string) ([]policyEditRecord, error) {
	query := `SELECT record FROM policy_edits WHERE network_id = ? AND person_id = ?`
	if where != "" {
		query += " AND " + where
	}
	return records[policyEditRecord](ctx, q, query+" ORDER BY seq", network, person)
}

func putEdit(ctx context.Context, tx *sql.Tx, network, person string, r policyEditRecord) error {
	if r.Dropped == nil {
		r.Dropped = []string{}
	}
	return putJSON(ctx, tx, `INSERT INTO policy_edits (record, network_id, person_id, seq) VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET record = excluded.record`, r, network, person, r.Seq)
}

// ownPolicy is this host's person in a network and that person's stored
// policy, if any.
func (s *Store) ownPolicy(ctx context.Context, q dbQuerier, network string) (string, *membership.Policy, error) {
	person, err := s.ownPerson(ctx, q, network)
	if err != nil || person == "" {
		return person, nil, err
	}
	g, err := s.loadGovernance(ctx, q, network)
	if err != nil {
		return person, nil, err
	}
	key, ok := g.personKey(person)
	if !ok {
		return person, nil, nil
	}
	if p, ok := g.storedPolicy(key); ok {
		return person, &p, nil
	}
	return person, nil, nil
}

// settleEdits sets each settled or unsettled edit of the person by whether
// the stored policy p reflects it, and reports whether any is unsettled.
func (s *Store) settleEdits(ctx context.Context, tx *sql.Tx, network, person string, p *membership.Policy, now time.Time) (bool, error) {
	if person == "" {
		return false, nil
	}
	list, err := editRecords(ctx, tx, network, person, `json_extract(record, '$.state') IN ('settled', 'unsettled')`)
	if err != nil {
		return false, err
	}
	reflected := int64(0)
	if p != nil {
		reflected = p.EditSeq(s.identity.ID)
	}
	unsettled := false
	at := timestamp(now)
	for _, r := range list {
		state := editUnsettled
		if r.Seq <= reflected {
			state = editSettled
		}
		if state == editUnsettled {
			unsettled = true
		}
		if state == r.State {
			continue
		}
		r.State = state
		if state == editUnsettled {
			r.UnsettledAt = &at
		} else {
			r.UnsettledAt = nil
		}
		if err = putEdit(ctx, tx, network, person, r); err != nil {
			return false, err
		}
	}
	return unsettled, nil
}

// retiredDropped drops the edits entries of hosts whose membership ended
// for good: a host key revoked by a root signature, a host that joined
// through an invite revoked by a root signature, or a host with a valid
// leave statement. Entries of hosts removed any other way stay. More than
// 256 remaining entries are refused.
func (s *Store) retiredDropped(ctx context.Context, q dbQuerier, network string, edits []membership.PolicyEdit) ([]membership.PolicyEdit, error) {
	g, err := s.loadGovernance(ctx, q, network)
	if err != nil {
		return nil, err
	}
	retired := map[string]bool{}
	rootInvites := map[string]bool{}
	for _, r := range g.persisted.revocations {
		if !revocationValid(g.chain, r) {
			continue
		}
		switch {
		case r.kind == membership.KindLeave, r.kind == membership.KindHost && !g.chain.AdminSigned(signatureOf(r.statement)):
			if key, err := membership.DecodeKey(r.subject); err == nil {
				retired[membership.HostID(key)] = true
			}
		case r.kind == membership.KindInvite && !g.chain.AdminSigned(signatureOf(r.statement)):
			rootInvites[r.subject] = true
		}
	}
	if len(rootInvites) > 0 {
		// Hosts that joined through such an invite: current members, and
		// the join statements kept for members already dropped.
		members, err := records[NetworkMember](ctx, q, `SELECT record FROM network_members WHERE network_id = ?`, network)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			if rootInvites[m.inviteKey()] {
				retired[m.HostID] = true
			}
		}
		joined, err := records[membership.Membership](ctx, q, `SELECT record FROM network_statements WHERE network_id = ? AND kind = ?`, network, kindMembership)
		if err != nil {
			return nil, err
		}
		for _, m := range joined {
			if key, err := membership.DecodeKey(m.HostPublicKey); err == nil && rootInvites[m.InvitePublicKey] {
				retired[membership.HostID(key)] = true
			}
		}
	}
	out := []membership.PolicyEdit{}
	for _, e := range edits {
		if !retired[e.Host] || e.Host == s.identity.ID {
			out = append(out, e)
		}
	}
	if len(out) > membership.PolicyMaxEdits {
		return nil, fmt.Errorf("%w: the policy would have more than %d edits entries", ErrInvalid, membership.PolicyMaxEdits)
	}
	return out, nil
}

// withBody is p with its content replaced by body.
func withBody(p membership.Policy, body membership.PolicyBody) membership.Policy {
	p.Rules, p.CapabilityRules, p.TrustedHosts, p.Edits = body.Rules, body.CapabilityRules, body.TrustedHosts, body.Edits
	if p.Format != membership.PolicyFormat2 && (len(body.CapabilityRules) > 0 || len(body.TrustedHosts) > 0 || len(body.Edits) > 0) {
		p.Format = membership.PolicyFormat2
	}
	if p.Format == membership.PolicyFormat2 {
		if p.CapabilityRules == nil {
			p.CapabilityRules = []membership.CapabilityRule{}
		}
		if p.TrustedHosts == nil {
			p.TrustedHosts = []string{}
		}
		if p.Edits == nil {
			p.Edits = []membership.PolicyEdit{}
		}
	} else {
		p.CapabilityRules, p.TrustedHosts, p.Edits = nil, nil, nil
	}
	return p
}

// reapplied is the stored policy's body with the given edits re-applied in
// number order, and the additions each dropped.
func reapplied(stored membership.PolicyBody, edits []policyEditRecord) (membership.PolicyBody, [][]string) {
	body := stored
	if len(edits) > 0 {
		// Signing as v2 keeps one rule per agent.
		body, _ = membership.FirstRulePerAgent(body)
	}
	dropped := make([][]string, len(edits))
	for i, e := range edits {
		if e.Signed == nil {
			continue
		}
		body, dropped[i] = membership.MergeEdit(e.startBody(), e.Signed.Body(), body, false, e.Dropped)
	}
	return body, dropped
}

// EditStart reserves the next edit number of this host's person in a
// network and returns the starting point for the edit: the stored policy
// with this host's unsettled edits re-applied, without retired entries.
func (s *Store) EditStart(ctx context.Context, network string) (EditStart, error) {
	if _, err := s.Network(ctx, network); err != nil {
		return EditStart{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EditStart{}, err
	}
	defer tx.Rollback()
	person, stored, err := s.ownPolicy(ctx, tx, network)
	if err != nil {
		return EditStart{}, err
	}
	if person == "" {
		return EditStart{}, fmt.Errorf("%w: this host is not bound to a person in that network", ErrNotFound)
	}
	now := time.Now()
	if _, err = s.settleEdits(ctx, tx, network, person, stored, now); err != nil {
		return EditStart{}, err
	}
	out := EditStart{}
	next := int64(0)
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM policy_edits WHERE network_id = ? AND person_id = ?`, network, person).Scan(&next); err != nil {
		return EditStart{}, err
	}
	if stored != nil {
		out.Version = stored.Version
		next = max(next, stored.EditSeq(s.identity.ID))
		unsettled, err := editRecords(ctx, tx, network, person, `json_extract(record, '$.state') = 'unsettled'`)
		if err != nil {
			return EditStart{}, err
		}
		body, _ := reapplied(stored.Body(), unsettled)
		if body.Edits, err = s.retiredDropped(ctx, tx, network, body.Edits); err != nil {
			return EditStart{}, err
		}
		p := withBody(*stored, body)
		out.Policy = &p
	}
	out.Seq = next + 1
	if out.Seq > membership.PolicyMaxEditSeq {
		return EditStart{}, fmt.Errorf("%w: edit numbers are exhausted", ErrConflict)
	}
	rec := policyEditRecord{Seq: out.Seq, State: editReserved, Start: out.Policy, Dropped: []string{}, ReservedAt: timestamp(now)}
	if err = putEdit(ctx, tx, network, person, rec); err != nil {
		return EditStart{}, err
	}
	return out, tx.Commit()
}

// checkEdit applies the edit rules to a policy of this host's person
// submitted through the local route. A policy whose entry for this host
// is above the stored one's cites a reserved edit number: it must be
// the newest reservation, not lapsed, and the version the stored + 1. It
// returns the reservation, or nil for a policy that is not an edit.
func (s *Store) checkEdit(ctx context.Context, tx *sql.Tx, network, person string, stored *membership.Policy, p membership.Policy, now time.Time) (*policyEditRecord, error) {
	seq, old, version := p.EditSeq(s.identity.ID), int64(0), int64(0)
	if stored != nil {
		old, version = stored.EditSeq(s.identity.ID), stored.Version
	}
	if seq <= old {
		// Not a new edit of this host: a renewal, or a policy built from
		// an older one, which the acceptance rule handles.
		return nil, nil
	}
	rec, err := readJSON[policyEditRecord](tx.QueryRowContext(ctx, `SELECT record FROM policy_edits WHERE network_id = ? AND person_id = ? AND seq = ?`, network, person, seq))
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: the policy cites edit %d, which this host never reserved", ErrInvalid, seq)
	}
	if err != nil {
		return nil, err
	}
	if rec.State == editReserved {
		if at, err := parseTime(rec.ReservedAt); err != nil || now.Sub(at) > editReservationLapse {
			return nil, fmt.Errorf("%w: the reservation of edit %d lapsed", ErrInvalid, seq)
		}
	}
	var newest int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM policy_edits WHERE network_id = ? AND person_id = ? AND json_extract(record, '$.state') = 'reserved'`, network, person).Scan(&newest); err != nil {
		return nil, err
	}
	if rec.State != editReserved || seq != newest || p.Version != version+1 {
		return nil, errEditConflict
	}
	return &rec, nil
}

// recordEdit records a stored edit: its signed policy, settled.
func (s *Store) recordEdit(ctx context.Context, tx *sql.Tx, network, person string, rec policyEditRecord, p membership.Policy, now time.Time) error {
	at := timestamp(now)
	signed, version := p, p.Version
	rec.State, rec.Signed, rec.SignedVersion, rec.SignedAt, rec.UnsettledAt = editSettled, &signed, &version, &at, nil
	return putEdit(ctx, tx, network, person, rec)
}

// editsChanged runs after a policy of this host's person is stored: it
// settles the person's edits by it, and schedules a re-application when
// any is unsettled.
func (s *Store) editsChanged(ctx context.Context, tx *sql.Tx, network string, p membership.Policy, now time.Time) error {
	person, err := s.ownPerson(ctx, tx, network)
	if err != nil {
		return err
	}
	// Edits of another person are suspended: only their owner's policies
	// settle them.
	if person == "" || person != personIDOf(p.PersonPublicKey) {
		return nil
	}
	unsettled, err := s.settleEdits(ctx, tx, network, person, &p, now)
	if err == nil && unsettled {
		s.scheduleReapply(network)
	}
	return err
}

// enforcedPolicy is the policy a request is authorized under: for this
// host's person, the stored policy with the withdrawals of this host's
// unsettled edits applied.
func (s *Store) enforcedPolicy(ctx context.Context, q dbQuerier, network string, p membership.Policy) (membership.Policy, error) {
	person, err := s.ownPerson(ctx, q, network)
	if err != nil || person == "" || person != personIDOf(p.PersonPublicKey) {
		return p, err
	}
	unsettled, err := editRecords(ctx, q, network, person, `json_extract(record, '$.state') = 'unsettled'`)
	if err != nil || len(unsettled) == 0 {
		return p, err
	}
	body := p.Body()
	for _, e := range unsettled {
		if e.Signed != nil {
			body, _ = membership.MergeEdit(e.startBody(), e.Signed.Body(), body, true, nil)
		}
	}
	return withBody(p, body), nil
}

// scheduleReapply wakes the re-application worker for a network.
func (s *Store) scheduleReapply(network string) {
	p := s.policyState()
	p.mu.Lock()
	p.reapply[network] = true
	p.mu.Unlock()
	select {
	case p.editWake <- struct{}{}:
	default:
	}
}

// reapplyIfUnsettled schedules a re-application when this host's person in
// a network has unsettled edits, or edits a stored policy no longer
// reflects.
func (s *Store) reapplyIfUnsettled(ctx context.Context, network string) {
	person, stored, err := s.ownPolicy(ctx, s.db, network)
	if err != nil || person == "" || stored == nil {
		return
	}
	var pending bool
	err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM policy_edits WHERE network_id = ? AND person_id = ? AND (json_extract(record, '$.state') = 'unsettled' OR (json_extract(record, '$.state') = 'settled' AND seq > ?)))`, network, person, stored.EditSeq(s.identity.ID)).Scan(&pending)
	if err == nil && pending {
		s.scheduleReapply(network)
	}
}

// ackEdits records that a sibling or the coordinator holds a policy
// reflecting this host's edits up to seq.
func (s *Store) ackEdits(network, person, target string, seq int64) {
	if seq <= 0 {
		return
	}
	p := s.policyState()
	p.mu.Lock()
	defer p.mu.Unlock()
	key := network + "/" + person
	if p.acks[key] == nil {
		p.acks[key] = map[string]int64{}
	}
	p.acks[key][target] = max(p.acks[key][target], seq)
}

// ReapplyEdits re-applies the unsettled edits of this host's person in a
// network to the stored policy, signing with the renewal key when the
// content changes, and closing them when it does not.
func (s *Store) ReapplyEdits(ctx context.Context, network string, logf func(string, ...any)) error {
	s.editsMu.Lock()
	defer s.editsMu.Unlock()
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	person, stored, err := s.ownPolicy(ctx, tx, network)
	if err != nil {
		return err
	}
	if _, err = s.settleEdits(ctx, tx, network, person, stored, now); err != nil {
		return err
	}
	if person == "" || stored == nil {
		return tx.Commit()
	}
	unsettled, err := editRecords(ctx, tx, network, person, `json_extract(record, '$.state') = 'unsettled'`)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil || len(unsettled) == 0 {
		return err
	}
	_, ruleDrops := membership.FirstRulePerAgent(stored.Body())
	body, dropped := reapplied(stored.Body(), unsettled)
	changed := !membership.SameContent(body, stored.Body())
	var signedPolicy *membership.Policy
	if changed {
		public, err := membership.DecodeKey(stored.PersonPublicKey)
		if err != nil {
			return err
		}
		signer, err := s.renewalSigner(ed25519.PublicKey(public))
		if err != nil {
			return nil // without a renewal key, the edits stay unsettled
		}
		last := unsettled[len(unsettled)-1]
		issued, until, _ := policyDuration(*last.Signed)
		edits, err := s.retiredDropped(ctx, s.db, network, membership.WithEdit(stored.Edits, s.identity.ID, last.Seq))
		if err != nil {
			signer.Close()
			return err
		}
		body.Edits = edits
		p, err := membership.SignPolicyV2(signer, network, stored.Version+1, now.Truncate(time.Second), until.Sub(issued), body)
		signer.Close()
		if err != nil {
			logf("re-applying policy edits for %s: %v", network, err)
			return err
		}
		signedPolicy = &p
	}
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	person2, current, err := s.ownPolicy(ctx, tx, network)
	if err != nil {
		return err
	}
	if person2 != person || current == nil || current.Version != stored.Version || current.Signature != stored.Signature {
		s.scheduleReapply(network) // another policy arrived meanwhile
		return nil
	}
	at := timestamp(now)
	for i, e := range unsettled {
		if len(dropped[i]) > 0 {
			e.Dropped = append(e.Dropped, dropped[i]...)
			e.DroppedAt = &at
			if err = appendEvent(ctx, tx, "network.policy_edit_dropped", fmt.Sprintf("%s/%d", person, e.Seq), at); err != nil {
				return err
			}
		}
		if !changed {
			e.State, e.ClosedAt, e.UnsettledAt = editClosed, &at, nil
		}
		if err = putEdit(ctx, tx, network, person, e); err != nil {
			return err
		}
	}
	if changed {
		storedNow, err := s.acceptPolicy(ctx, tx, network, *signedPolicy, now)
		if err != nil {
			return err
		}
		if !storedNow {
			return nil
		}
		for _, agent := range ruleDrops {
			if err = appendEvent(ctx, tx, "network.policy_rule_dropped", person+"/"+agent, at); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if changed {
		logf("re-applied policy edits as version %d for %s", signedPolicy.Version, network)
		s.wakePolicyDeliveries()
		if _, err = s.attemptDelivery(ctx, network, person, policyTargetCoordinator); err != nil {
			return err
		}
	}
	return nil
}

func policyDuration(p membership.Policy) (time.Time, time.Time, error) {
	issued, err1 := membership.ParseTime(p.IssuedAt)
	until, err2 := membership.ParseTime(p.ValidUntil)
	if err1 != nil || err2 != nil {
		return issued, issued.Add(7 * 24 * time.Hour), errors.New("invalid policy window")
	}
	return issued, until, nil
}

// reapplyAll re-applies unsettled edits in every network.
func (s *Store) reapplyAll(ctx context.Context, logf func(string, ...any)) {
	networks, err := s.Networks(ctx)
	if err != nil {
		return
	}
	for _, n := range networks {
		if ctx.Err() != nil {
			return
		}
		if err := s.ReapplyEdits(ctx, n.ID, logf); err != nil && ctx.Err() == nil {
			logf("re-applying policy edits for %s: %v", n.ID, err)
		}
	}
}

// pruneEdits applies the retention rules to the edit records.
func (s *Store) pruneEdits(ctx context.Context, now time.Time) error {
	networks, err := s.Networks(ctx)
	if err != nil {
		return err
	}
	for _, n := range networks {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT person_id, record FROM policy_edits WHERE network_id = ? ORDER BY person_id, seq`, n.ID)
		if err != nil {
			tx.Rollback()
			return err
		}
		type row struct {
			person string
			rec    policyEditRecord
		}
		var all []row
		newest := map[string]int64{}
		for rows.Next() {
			var r row
			var record string
			if err = rows.Scan(&r.person, &record); err == nil {
				err = json.Unmarshal([]byte(record), &r.rec)
			}
			if err != nil {
				rows.Close()
				tx.Rollback()
				return err
			}
			all = append(all, r)
			newest[r.person] = max(newest[r.person], r.rec.Seq)
		}
		rows.Close()
		person, hosts, err := s.siblings(ctx, tx, n.ID)
		if err != nil {
			tx.Rollback()
			return err
		}
		// The lowest edit number every current sibling and the coordinator
		// have stored a policy reflecting.
		acked := int64(0)
		if person != "" {
			p := s.policyState()
			p.mu.Lock()
			acks := p.acks[n.ID+"/"+person]
			acked = acks[policyTargetCoordinator]
			for _, h := range hosts {
				acked = min(acked, acks[h])
			}
			p.mu.Unlock()
		}
		for _, r := range all {
			if r.rec.Seq == newest[r.person] || r.person != person {
				// Edit numbers keep increasing, and the edits of a person
				// this host is not bound to now are suspended.
				continue
			}
			remove := false
			switch r.rec.State {
			case editClosed:
				at, err := parseTime(deref(r.rec.ClosedAt))
				remove = err != nil || now.Sub(at) > editClosedRetention
			case editReserved:
				at, err := parseTime(r.rec.ReservedAt)
				remove = err != nil || now.Sub(at) > editReservationLapse
			case editSettled:
				remove = r.person == person && r.rec.Seq <= acked
				if r.rec.DroppedAt != nil {
					if at, err := parseTime(*r.rec.DroppedAt); err == nil && now.Sub(at) < editDroppedWindow {
						remove = false // still listed in item 17
					}
				}
			}
			if remove {
				if _, err = tx.ExecContext(ctx, `DELETE FROM policy_edits WHERE network_id = ? AND person_id = ? AND seq = ?`, n.ID, r.person, r.rec.Seq); err != nil {
					tx.Rollback()
					return err
				}
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// runPolicyEdits re-applies unsettled edits when a policy displaced them,
// after 0 to 2 seconds, and at each sync, and applies the retention rules.
func (s *Store) runPolicyEdits(ctx context.Context, logf func(string, ...any)) {
	p := s.policyState()
	ticker := time.NewTicker(policySyncInterval)
	defer ticker.Stop()
	s.reapplyAll(ctx, logf)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reapplyAll(ctx, logf)
			if err := s.pruneEdits(ctx, time.Now()); err != nil && ctx.Err() == nil {
				logf("pruning policy edits: %v", err)
			}
			continue
		case <-p.editWake:
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(rand.Int64N(int64(editReapplyJitter) + 1))):
		}
		p.mu.Lock()
		networks := p.reapply
		p.reapply = map[string]bool{}
		p.mu.Unlock()
		for _, network := range sortedKeys(networks) {
			if err := s.ReapplyEdits(ctx, network, logf); err != nil && ctx.Err() == nil {
				logf("re-applying policy edits for %s: %v", network, err)
			}
		}
	}
}

// editStatus lists the recorded edits of this host's person in a network,
// for access sync --status.
func (s *Store) editStatus(ctx context.Context, q queryer, network, person string) ([]PolicyEditStatus, error) {
	out := []PolicyEditStatus{}
	list, err := editRecords(ctx, q, network, person, `json_extract(record, '$.state') != 'reserved'`)
	if err != nil {
		return nil, err
	}
	for _, r := range list {
		dropped := r.Dropped
		if dropped == nil {
			dropped = []string{}
		}
		out = append(out, PolicyEditStatus{Seq: r.Seq, State: r.State, SignedVersion: r.SignedVersion, Dropped: dropped})
	}
	return out, nil
}

// editAttention adds status items 16, policy_edit_unsettled, and 17,
// policy_edit_dropped, for one network of this host's person.
func (s *Store) editAttention(ctx context.Context, q queryer, network, person string, now time.Time, attend func(kind, subject, detail, command string)) error {
	list, err := editRecords(ctx, q, network, person, "")
	if err != nil {
		return err
	}
	var oldest []int64
	for _, r := range list {
		if r.State == editUnsettled && r.UnsettledAt != nil {
			if at, err := parseTime(*r.UnsettledAt); err == nil && now.Sub(at) > editUnsettledAfter {
				oldest = append(oldest, r.Seq)
			}
		}
		if r.DroppedAt != nil && len(r.Dropped) > 0 {
			if at, err := parseTime(*r.DroppedAt); err == nil && now.Sub(at) < editDroppedWindow {
				attend("policy_edit_dropped", fmt.Sprintf("%s/%d", network, r.Seq), "a concurrent withdrawal won over these additions of edit "+fmt.Sprint(r.Seq)+": "+strings.Join(r.Dropped, "; "), "peerspan access show --network "+network)
			}
		}
	}
	if len(oldest) > 0 {
		sort.Slice(oldest, func(i, j int) bool { return oldest[i] < oldest[j] })
		attend("policy_edit_unsettled", network, fmt.Sprintf("policy edits %v of this host are not yet in your stored policy; the daemon has no key to re-apply them", oldest), "peerspan access renew --network "+network)
	}
	return nil
}

func localPolicyEditRoutes(mux *http.ServeMux, store *Store) {
	mux.HandleFunc("GET /v1/networks/{id}/policy/edit", func(w http.ResponseWriter, r *http.Request) {
		result, err := store.EditStart(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, result, err)
	})
}
