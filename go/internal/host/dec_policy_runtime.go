package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// Replication can displace a locally applied edit. Reconcile its obligation in
// the SAME projection transaction, before any new work can observe the policy.
// A remote body never settles an unsigned reservation or replaces frozen refs.
func (s *Store) reconcileDecPolicyEdits(ctx context.Context, tx *sql.Tx, snapshot *decSnapshot, p *dec.Projection) error {
	person := snapshot.Network.Own.Person
	if person == "-" {
		return nil
	}
	before, after := []string{}, []string{}
	for _, maximum := range snapshot.Prior.Maxima {
		if len(maximum.Stream) == 2 && maximum.Stream[0] == "policy" && maximum.Stream[1] == person {
			before = maximum.HeadIDs
		}
	}
	for _, stream := range p.Streams {
		if len(stream.Stream) == 2 && stream.Stream[0] == "policy" && stream.Stream[1] == person {
			after = stream.HeadIDs
		}
	}
	left, _ := json.Marshal(before)
	right, _ := json.Marshal(after)
	if string(left) == string(right) {
		return nil
	}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, person)
	if e != nil {
		return e
	}
	reflected := int64(0)
	for _, stream := range p.Streams {
		if len(stream.Stream) != 2 || stream.Stream[0] != "policy" || stream.Stream[1] != person || len(stream.HeadIDs) != 1 {
			continue
		}
		statement := snapshot.Catalog.Statements[stream.SelectedID]
		if statement != nil && statement.Access != nil {
			body, e := decPolicyBody(statement)
			if e != nil {
				return e
			}
			reflected = decBodyEditSeq(body.delta(), s.identity.ID)
		}
	}
	for _, edit := range edits {
		if edit.State != editSettled && edit.State != editUnsettled {
			continue
		}
		wanted := editUnsettled
		if edit.Seq <= reflected {
			wanted = editSettled
		}
		if edit.State == wanted {
			continue
		}
		edit.State = wanted
		edit.Unsettled = "-"
		if wanted == editUnsettled {
			edit.Unsettled = p.DecisionTime
		}
		if e = storeDecPolicyEdit(ctx, tx, snapshot.Descriptor.NetworkID, person, edit); e != nil {
			return e
		}
	}
	return nil
}

func decReappliedPolicy(snapshot *decSnapshot, body membership.PolicyBody, edits []decPolicyEdit, person, host string) (membership.PolicyBody, map[int64][]string, int64, error) {
	frozen := []decFrozenPolicyEdit{}
	last := decBodyEditSeq(body, host)
	for _, edit := range edits {
		if edit.State != editUnsettled {
			continue
		}
		_, start, e := readDecPolicyReference(snapshot, edit.Start, person)
		if e != nil {
			return body, nil, 0, e
		}
		_, signed, e := readDecPolicyReference(snapshot, edit.Signed, person)
		if e != nil {
			return body, nil, 0, e
		}
		skip, e := decPolicyDropSet(start, signed, edit.Dropped)
		if e != nil {
			return body, nil, 0, e
		}
		frozen = append(frozen, decFrozenPolicyEdit{edit.Seq, start, signed, skip, decPolicyDropKeys(start, signed)})
		last = max(last, edit.Seq)
	}
	sort.Slice(frozen, func(i, j int) bool { return frozen[i].seq < frozen[j].seq })
	result, dropped, e := decMergeFrozenEdits(body, frozen)
	return result, dropped, last, e
}
func decPolicyUpdatePayload(snapshot *decSnapshot, p *dec.Projection, view DecProviderView, body membership.PolicyBody, now string) ([]byte, error) {
	_, maximum, e := decPolicyStream(snapshot, view.Person)
	if e != nil {
		return nil, e
	}
	if maximum == ^uint64(0) {
		return nil, decFailure("version_exhausted")
	}
	person, _, e := p.Current([]string{"person", view.Person})
	if e != nil {
		return nil, e
	}
	parents := []dec.Parent{{Role: "issuer_person", ID: person.ID}}
	issuer := dec.Issuer{Kind: "person", Person: view.Person}
	if view.Kind == "device" {
		issuer.Kind = "device"
		parents = append(parents, dec.Parent{Role: "issuer_device", ID: view.Lease})
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i].Role < parents[j].Role })
	start, e := dec.ParseTime(now)
	if e != nil {
		return nil, e
	}
	until := start.Add(24 * time.Hour)
	seen := map[string]bool{}
	var ceiling func(string) error
	ceiling = func(id string) error {
		if seen[id] {
			return nil
		}
		seen[id] = true
		statement := snapshot.Catalog.Statements[id]
		if statement == nil {
			return decFailure("proof_required", id)
		}
		if statement.Lease == nil {
			return nil
		}
		at, e := dec.ParseTime(statement.Lease.After)
		if e != nil {
			return e
		}
		if at.Before(until) {
			until = at
		}
		for _, parent := range statement.Lease.Parents {
			if e = ceiling(parent.ID); e != nil {
				return e
			}
		}
		return nil
	}
	for _, parent := range parents {
		if e = ceiling(parent.ID); e != nil {
			return nil, e
		}
		_, path, e := p.StatementPath(parent.ID)
		if e != nil {
			return nil, e
		}
		at, e := dec.ParseTime(path.NotAfter)
		if e != nil {
			return nil, e
		}
		if at.Before(until) {
			until = at
		}
	}
	if !until.After(start) {
		return nil, decFailure("authority_expired")
	}
	if body.Rules == nil {
		body.Rules = []membership.PolicyRule{}
	}
	if body.CapabilityRules == nil {
		body.CapabilityRules = []membership.CapabilityRule{}
	}
	if body.TrustedHosts == nil {
		body.TrustedHosts = []string{}
	}
	if body.Edits == nil {
		body.Edits = []membership.PolicyEdit{}
	}
	content := decPolicyContent{2, snapshot.Descriptor.NetworkID, view.Person, maximum + 1, now, linkTime(until), body.Rules, body.CapabilityRules, body.TrustedHosts, body.Edits}
	contentRaw, e := json.Marshal(content)
	if e != nil {
		return nil, e
	}
	heads := []string{}
	for _, stream := range snapshot.Prior.Maxima {
		if len(stream.Stream) == 2 && stream.Stream[0] == "policy" && stream.Stream[1] == view.Person {
			heads = append(heads, stream.HeadIDs...)
		}
	}
	return json.Marshal(dec.Access{Root: p.Root.SelectedID, Operation: "-", Sequence: maximum + 1, Predecessors: heads, Resolves: []string{}, Issuer: issuer, Parents: parents, Issued: now, Before: now, After: linkTime(until), BodyBase64: base64.StdEncoding.EncodeToString(contentRaw)})
}

func (s *Store) finishDecAutomaticPolicy(ctx context.Context, network string, raw json.RawMessage) error {
	var result decActionResult
	if dec.ReadPrivateRecord(raw, "action_id review signing_requests statement_base64 proof_id catalog committed delivery", &result) != nil {
		return decStorageError()
	}
	if result.Committed {
		return nil
	}
	if len(result.Signing) != 1 {
		return decFailure("signer_unavailable")
	}
	slot := result.Signing[0]
	if slot.Type != "policy" || slot.Role != "issuer" || slot.Format != "sshsig" || slot.Public != result.Review.Provider.Person || result.Review.Provider.Kind != "original_person" {
		return decFailure("invalid")
	}
	message, e := decBytes(slot.Message, dec.MaxPayload)
	if e != nil {
		return e
	}
	key, e := membership.DecodeKey(slot.Public)
	if e != nil {
		return e
	}
	signer, e := s.renewalSigner(ed25519.PublicKey(key))
	if e != nil {
		return decFailure("signer_unavailable")
	}
	defer signer.Close()
	signature, e := membership.SignSSHSIG(signer, message)
	if e != nil {
		return decFailure("signer_unavailable")
	}
	_, e = s.SignedDecentralizedAction(ctx, network, result.ID, DecSignatureBatch{Intent: slot.Intent, Signatures: []decIntentSignature{{Slot: slot.Slot, Role: slot.Role, Signature: signature}}})
	return e
}

// This path renews a policy through a new ordinary typed intent; it cannot
// renew its fixed P/H/B/D ancestors, infer freshness, or switch providers.
func (s *Store) renewDecPolicy(ctx context.Context, network string, automatic bool) error {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		tx.Rollback()
		return e
	}
	now, e := decNow()
	if e != nil {
		tx.Rollback()
		return e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		tx.Rollback()
		return e
	}
	decision, e := dec.ParseTime(p.DecisionTime)
	if e != nil {
		tx.Rollback()
		return e
	}
	view, provider, _, e := s.decActionProvider(ctx, tx, snapshot, p, "auto", "auto")
	if e != nil {
		tx.Rollback()
		return e
	}
	if view.Scopes&1 == 0 {
		tx.Rollback()
		return decFailure("forbidden")
	}
	selected, maximum, e := decPolicyStream(snapshot, view.Person)
	if e != nil {
		tx.Rollback()
		return e
	}
	if selected == nil {
		tx.Rollback()
		return nil
	}
	current, e := decPolicyBody(selected)
	if e != nil {
		tx.Rollback()
		return e
	}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, view.Person)
	if e != nil {
		tx.Rollback()
		return e
	}
	body, _, last, e := decReappliedPolicy(snapshot, current.delta(), edits, view.Person, s.identity.ID)
	if e != nil {
		tx.Rollback()
		return e
	}
	changed := !membership.SameContent(body, current.delta())
	hasUnsettled := false
	for _, edit := range edits {
		hasUnsettled = hasUnsettled || edit.State == editUnsettled
	}
	if hasUnsettled && !changed {
		tx.Rollback()
		return s.closeDecReflectedEdits(ctx, network, snapshot.Fingerprint)
	}
	issued, e := dec.ParseTime(current.Before)
	if e != nil {
		tx.Rollback()
		return e
	}
	expires, e := dec.ParseTime(current.After)
	if e != nil {
		tx.Rollback()
		return e
	}
	if automatic && !changed && (!decision.Before(expires) || expires.Sub(decision) >= expires.Sub(issued)/4) {
		tx.Rollback()
		return nil
	}
	if changed {
		body.Edits = membership.WithEdit(body.Edits, s.identity.ID, last)
	}
	// Resume the exact approved unfinished policy for this selected provider,
	// rather than replacing a stale reviewed payload with another generation.
	rows, e := tx.QueryContext(ctx, `SELECT intent_id FROM dec_intents WHERE network_id=? AND kind='action' ORDER BY intent_id`, network)
	if e != nil {
		tx.Rollback()
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			tx.Rollback()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		tx.Rollback()
		return e
	}
	var pending, pendingIntent string
	for _, id := range ids {
		i, e := readDecIntent(ctx, tx, id)
		if e != nil {
			tx.Rollback()
			return e
		}
		if i.Record.Approved && i.Record.Terminal == "-" && i.Record.Person == view.Person && i.Record.Provider == provider {
			// Authenticate retained private bytes before deciding a fixed
			// approved action is stale. Never refresh or rewrite that row.
			review, statement, _, e := readDecAction(i, snapshot.Descriptor)
			if e != nil {
				tx.Rollback()
				return e
			}
			if review.Kind == "policy" {
				if statement.Access == nil || i.Secret != nil || i.Record.Host != s.identity.PublicKey || i.Record.Completed != decActionComplete(statement) {
					tx.Rollback()
					return decStorageError()
				}
				created, e := dec.ParseTime(i.Record.Created)
				if e != nil {
					tx.Rollback()
					return e
				}
				issued, e := dec.ParseTime(statement.Access.Issued)
				if e != nil {
					tx.Rollback()
					return e
				}
				// The private row is created at preparation time, which can
				// follow the fixed payload's issue time. Its immutable signing
				// deadline is anchored to that payload, never to this retry.
				if i.Record.Expires != linkTime(issued.Add(300*time.Second)) || created.Before(issued) || !created.Before(issued.Add(300*time.Second)) || decision.Before(created) {
					tx.Rollback()
					return decStorageError()
				}
				if decision.Sub(issued) > 300*time.Second || statement.Access.Root != p.Root.SelectedID || statement.Access.Sequence <= maximum || len(statement.Access.Predecessors) != 1 || statement.Access.Predecessors[0] != selected.ID {
					continue
				}
				_, _, _, e = verifyDecAction(snapshot, i, p.DecisionTime)
				if e == nil {
					e = checkDecActionEditBoundary(ctx, tx, snapshot, statement)
				}
				if e == nil {
					e = decCurrentIntentProvider(ctx, tx, snapshot, i)
				}
				if e != nil {
					if decStalePolicyAction(e) {
						continue
					}
					tx.Rollback()
					return e
				}
				pending = i.Record.Operation
				pendingIntent = i.ID
				break
			}
		}
	}
	payload, e := decPolicyUpdatePayload(snapshot, p, view, body, p.DecisionTime)
	tx.Rollback()
	if e != nil {
		return e
	}
	var raw json.RawMessage
	if pending != "" {
		var i decIntent
		var facts decCommittedFacts
		i, raw, facts, e = s.persistDecActionSignatures(ctx, network, pending, DecSignatureBatch{Intent: pendingIntent, Signatures: []decIntentSignature{}})
		if e == nil && raw == nil {
			if e = facts.wait(ctx); e == nil {
				raw, e = s.applyPreparedDecAction(ctx, i)
			}
		}
	} else {
		raw, e = s.PrepareDecentralizedAction(ctx, network, DecActionRequest{Kind: "policy", Provider: "auto", Format: "auto", Payload: base64.StdEncoding.EncodeToString(payload), Approve: true})
	}
	if e != nil {
		return e
	}
	return s.finishDecAutomaticPolicy(ctx, network, raw)
}

func decStalePolicyAction(e error) bool {
	switch decTransportCode(e) {
	case "expired", "authority_expired", "not_yet_valid", "forbidden", "proof_required", "state_conflict", "edit_conflict", "device_revoked":
		return true
	}
	return false
}

func (s *Store) closeDecReflectedEdits(ctx context.Context, network, fingerprint string) error {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return e
	}
	if snapshot.Fingerprint != fingerprint {
		return decFailure("state_conflict")
	}
	now, e := decNow()
	if e != nil {
		return e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return e
	}
	view, _, _, e := s.decActionProvider(ctx, tx, snapshot, p, "auto", "auto")
	if e != nil {
		return e
	}
	if view.Scopes&1 == 0 {
		return decFailure("forbidden")
	}
	selected, _, e := decPolicyStream(snapshot, view.Person)
	if e != nil {
		return e
	}
	if selected == nil {
		return decFailure("proof_required")
	}
	current, e := decPolicyBody(selected)
	if e != nil {
		return e
	}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, view.Person)
	if e != nil {
		return e
	}
	body, dropped, _, e := decReappliedPolicy(snapshot, current.delta(), edits, view.Person, s.identity.ID)
	if e != nil {
		return e
	}
	if !membership.SameContent(body, current.delta()) {
		return decFailure("state_conflict")
	}
	// No proof or permission changes: already reflected intent can close only
	// after current provider/heads/reference checks in this exact transaction.
	now, e = decNow()
	if e != nil {
		return e
	}
	p, e = verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return e
	}
	view, _, _, e = s.decActionProvider(ctx, tx, snapshot, p, "auto", "auto")
	if e != nil {
		return e
	}
	if view.Scopes&1 == 0 {
		return decFailure("forbidden")
	}
	for _, edit := range edits {
		if edit.State != editUnsettled {
			continue
		}
		edit.State = editClosed
		edit.Closed = p.DecisionTime
		edit.Unsettled = "-"
		if len(dropped[edit.Seq]) > 0 {
			_, start, e := readDecPolicyReference(snapshot, edit.Start, view.Person)
			if e != nil {
				return e
			}
			_, signed, e := readDecPolicyReference(snapshot, edit.Signed, view.Person)
			if e != nil {
				return e
			}
			updated, e := decAppendPolicyDrops(edit.Dropped, dropped[edit.Seq], start, signed)
			if e != nil {
				return e
			}
			if len(updated) != len(edit.Dropped) {
				edit.Dropped, edit.DroppedAt = updated, p.DecisionTime
			}
		}
		if e = storeDecPolicyEdit(ctx, tx, network, view.Person, edit); e != nil {
			return e
		}
	}
	clock, _ := json.Marshal(decClockRecord{1, p.DecisionTime})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), network); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) RunDecentralizedPolicyRenewal(ctx context.Context, logf func(string, ...any)) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		ids, e := s.networkIDs(ctx, s.db)
		if e != nil {
			continue
		}
		for _, id := range ids {
			modern, e := decContextMode(ctx, s.db, id)
			if e != nil || !modern {
				continue
			}
			if e = s.renewDecPolicy(ctx, id, true); e != nil && ctx.Err() == nil {
				logf("DEC policy renewal for %s: %s", id, decTransportCode(e))
			}
			if e = s.cleanupDecPolicyEdits(ctx, id); e != nil && ctx.Err() == nil {
				logf("DEC policy edit retention for %s: %s", id, decTransportCode(e))
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// Metadata retirement never infers delivery acknowledgment from an absent
// outbox row. Settled and unsettled signed obligations remain retained; only
// old unsigned/closed rows can retire, and the all-history counter row stays.
func (s *Store) cleanupDecPolicyEdits(ctx context.Context, network string) error {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return e
	}
	person := snapshot.Network.Own.Person
	if person == "-" {
		return nil
	}
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return e
	}
	decision, e := dec.ParseTime(now)
	if e != nil {
		return e
	}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, person)
	if e != nil {
		return e
	}
	var newest int64
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM policy_edits WHERE network_id=? AND person_id=?`, network, personIDOf(person)).Scan(&newest); e != nil {
		return e
	}
	retire := []int64{}
	for _, edit := range edits {
		if edit.Seq == newest {
			continue
		}
		var at string
		var keep time.Duration
		switch edit.State {
		case editReserved:
			at, keep = edit.Reserved, editReservationLapse
		case editClosed:
			at, keep = edit.Closed, editClosedRetention
		default:
			continue
		}
		start, e := dec.ParseTime(at)
		if e != nil {
			return e
		}
		if decision.Sub(start) <= keep {
			continue
		}
		if edit.DroppedAt != "-" {
			dropped, e := dec.ParseTime(edit.DroppedAt)
			if e != nil {
				return e
			}
			if decision.Sub(dropped) <= editClosedRetention {
				continue
			}
		}
		retire = append(retire, edit.Seq)
	}
	if len(retire) == 0 {
		return nil
	}
	latest, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return e
	}
	if _, e = dec.DecisionTime(latest, now); e != nil {
		return e
	}
	for _, seq := range retire {
		if _, e = tx.ExecContext(ctx, `DELETE FROM policy_edits WHERE network_id=? AND person_id=? AND seq=?`, network, personIDOf(person), seq); e != nil {
			return e
		}
	}
	if e = writeMigrationClock(ctx, tx, network, latest); e != nil {
		return e
	}
	return tx.Commit()
}
