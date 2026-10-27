package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type decPolicyReference struct {
	Statement string `json:"statement_id"`
	Proof     string `json:"proof_id"`
	Envelope  string `json:"statement_base64"`
	Body      string `json:"body_base64"`
}
type decPolicyEdit struct {
	Format    uint64          `json:"format"`
	Mode      string          `json:"mode"`
	Context   string          `json:"context_id"`
	Seq       int64           `json:"seq"`
	State     string          `json:"state"`
	Start     json.RawMessage `json:"start"`
	Signed    json.RawMessage `json:"signed"`
	Version   uint64          `json:"signed_version"`
	Dropped   []string        `json:"dropped"`
	Reserved  string          `json:"reserved_at"`
	SignedAt  string          `json:"signed_at"`
	Unsettled string          `json:"unsettled_at"`
	Closed    string          `json:"closed_at"`
	DroppedAt string          `json:"dropped_at"`
}

const decPolicyEditFields = "format mode context_id seq state start signed signed_version dropped reserved_at signed_at unsettled_at closed_at dropped_at"

type decPolicyContent struct {
	Format       uint64                      `json:"format"`
	Network      string                      `json:"network_id"`
	Person       string                      `json:"person_public_key"`
	Version      uint64                      `json:"version"`
	Before       string                      `json:"issued_at"`
	After        string                      `json:"valid_until"`
	Rules        []membership.PolicyRule     `json:"rules"`
	Capabilities []membership.CapabilityRule `json:"capability_rules"`
	Trusted      []string                    `json:"trusted_hosts"`
	Edits        []membership.PolicyEdit     `json:"edits"`
}

func decPolicyBody(s *dec.Statement) (decPolicyContent, error) {
	body := decPolicyContent{Rules: []membership.PolicyRule{}, Capabilities: []membership.CapabilityRule{}, Trusted: []string{}, Edits: []membership.PolicyEdit{}}
	if s == nil || s.Kind != "policy" || s.Access == nil {
		return body, decStorageError()
	}
	raw, e := decBytes(s.Access.BodyBase64, dec.MaxPayload)
	if e != nil {
		return body, e
	}
	if json.Unmarshal(raw, &body) != nil {
		return body, decStorageError()
	}
	return body, nil
}
func (b decPolicyContent) delta() membership.PolicyBody {
	return membership.PolicyBody{Rules: b.Rules, CapabilityRules: b.Capabilities, TrustedHosts: b.Trusted, Edits: b.Edits}
}
func decBodyEditSeq(body membership.PolicyBody, host string) int64 {
	for _, edit := range body.Edits {
		if edit.Host == host {
			return edit.Seq
		}
	}
	return 0
}
func decEmptyPolicyBody() membership.PolicyBody {
	return membership.PolicyBody{Rules: []membership.PolicyRule{}, CapabilityRules: []membership.CapabilityRule{}, TrustedHosts: []string{}, Edits: []membership.PolicyEdit{}}
}
func decSamePolicyBody(a, b membership.PolicyBody) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func readDecPolicyReference(snapshot *decSnapshot, raw json.RawMessage, person string) (*dec.Statement, membership.PolicyBody, error) {
	empty := decEmptyPolicyBody()
	if bytes.Equal(raw, []byte(`"-"`)) {
		return nil, empty, nil
	}
	var ref decPolicyReference
	if dec.ReadPrivateRecord(raw, "statement_id proof_id statement_base64 body_base64", &ref) != nil || !dec.ValidID(ref.Statement, "ds_") || !dec.ValidID(ref.Proof, "dp_") {
		return nil, empty, decStorageError()
	}
	envelope, e := decBytes(ref.Envelope, dec.MaxObject)
	if e != nil {
		return nil, empty, e
	}
	s, e := dec.ReadStatement(snapshot.Descriptor, envelope)
	if e != nil {
		return nil, empty, e
	}
	if s.Kind != "policy" || s.ID != ref.Statement || s.Access.BodyBase64 != ref.Body || !containsString(snapshot.Prior.AdmittedStatements, s.ID) {
		return nil, empty, decStorageError()
	}
	body, e := decPolicyBody(s)
	if e != nil {
		return nil, empty, e
	}
	if body.Person != person || body.Network != snapshot.Descriptor.NetworkID {
		return nil, empty, decStorageError()
	}
	var source *dec.CatalogObject
	for i := range snapshot.Catalog.Objects {
		if snapshot.Catalog.Objects[i].ID == ref.Proof {
			source = &snapshot.Catalog.Objects[i]
			break
		}
	}
	if source == nil {
		return nil, empty, decFailure("proof_required", ref.Proof)
	}
	wire, _ := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, snapshot.Descriptor.ContextID, []dec.CatalogObject{*source}})
	carrier, e := dec.ReadCatalog(snapshot.Descriptor, wire)
	if e != nil {
		return nil, empty, e
	}
	exact := carrier.Proofs[s.ProofID]
	if exact == nil || !bytes.Equal(exact.Raw, envelope) || !containsString(carrier.Sources[s.ID], ref.Proof) {
		return nil, empty, decStorageError()
	}
	if e = completeDecHistoricalReference(snapshot, s.ID); e != nil {
		return nil, empty, e
	}
	return s, body.delta(), nil
}

// Historical references need exact closure, not present authority. In
// particular expiry/fork cannot erase a signed withdrawal's frozen intent.
// Cache only structural READ output for these immutable snapshot bytes; a
// merged catalog/prior invalidates the cache even on a copied snapshot.
func completeDecHistoricalReference(snapshot *decSnapshot, id string) error {
	if snapshot.referenceProof == nil || snapshot.referenceCatalog != snapshot.Catalog || !bytes.Equal(snapshot.referencePrior, snapshot.PriorRaw) {
		at := snapshot.Prior.ClockGuard
		if at == "-" {
			at = snapshot.Network.Created
		}
		// A projection writer may be reconciling its exact retained union
		// before reloading the snapshot. Repack ONLY that actual catalog;
		// every durable admission/head/maximum/clock marker stays unchanged.
		prior := snapshot.Prior
		prior.CatalogBase64 = base64.StdEncoding.EncodeToString(snapshot.Catalog.Raw)
		raw, e := json.Marshal(prior)
		if e != nil {
			return e
		}
		p, e := dec.Project(snapshot.Descriptor, raw, []byte("-"), at, "read")
		if e != nil {
			return e
		}
		snapshot.referenceProof, snapshot.referenceCatalog = p, snapshot.Catalog
		snapshot.referencePrior = append([]byte{}, snapshot.PriorRaw...)
	}
	return snapshot.referenceProof.CompleteProof(id)
}
func makeDecPolicyReference(snapshot *decSnapshot, s *dec.Statement) (json.RawMessage, error) {
	if s == nil {
		return json.RawMessage(`"-"`), nil
	}
	for _, source := range snapshot.Catalog.Sources[s.ID] {
		ref := decPolicyReference{s.ID, source, base64.StdEncoding.EncodeToString(s.Raw), s.Access.BodyBase64}
		raw, _ := json.Marshal(ref)
		body, e := decPolicyBody(s)
		if e != nil {
			return nil, e
		}
		if _, _, e = readDecPolicyReference(snapshot, raw, body.Person); e == nil {
			return raw, nil
		} else if dec.Code(e) == "proof_required" {
			return nil, e
		}
	}
	return nil, decFailure("proof_required", s.ID)
}
func decPolicyStream(snapshot *decSnapshot, person string) (*dec.Statement, uint64, error) {
	for _, water := range snapshot.Prior.Maxima {
		if len(water.Stream) != 2 || water.Stream[0] != "policy" || water.Stream[1] != person {
			continue
		}
		if len(water.HeadIDs) > 1 {
			return nil, water.Sequence, decFailure("state_conflict")
		}
		if len(water.HeadIDs) == 0 {
			return nil, water.Sequence, nil
		}
		selected := snapshot.Catalog.Statements[water.HeadIDs[0]]
		if selected == nil {
			return nil, water.Sequence, decFailure("proof_required", water.HeadIDs[0])
		}
		if selected.Kind != "policy" || selected.Access.Sequence < water.Sequence {
			return nil, water.Sequence, decStorageError()
		}
		return selected, water.Sequence, nil
	}
	return nil, 0, nil
}
func readDecPolicyEdits(ctx context.Context, q dbQuerier, snapshot *decSnapshot, person string) ([]decPolicyEdit, error) {
	rows, e := q.QueryContext(ctx, `SELECT seq,record FROM policy_edits WHERE network_id=? AND person_id=? ORDER BY seq`, snapshot.Descriptor.NetworkID, personIDOf(person))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []decPolicyEdit{}
	for rows.Next() {
		var seq int64
		var raw string
		if e = rows.Scan(&seq, &raw); e != nil {
			return nil, e
		}
		var tag struct {
			Mode   string `json:"mode"`
			Format uint64 `json:"format"`
		}
		if json.Unmarshal([]byte(raw), &tag) != nil {
			return nil, decStorageError()
		}
		if tag.Mode == "" && tag.Format == 0 {
			continue
		} // exact legacy history remains untouched.
		var r decPolicyEdit
		if len(raw) > dec.MaxPrivateRecord || dec.ReadPrivateRecord([]byte(raw), decPolicyEditFields, &r) != nil || r.Format != 2 || r.Mode != "decentralized" || r.Context != snapshot.Descriptor.ContextID || r.Seq != seq || seq <= 0 || r.Dropped == nil {
			return nil, decStorageError()
		}
		for _, at := range []string{r.Reserved, r.SignedAt, r.Unsettled, r.Closed, r.DroppedAt} {
			if at != "-" {
				if _, e = dec.ParseTime(at); e != nil {
					return nil, e
				}
			}
		}
		if r.Reserved == "-" || r.SignedAt != "-" && r.SignedAt < r.Reserved || r.Unsettled != "-" && r.Unsettled < r.SignedAt || r.Closed != "-" && r.Closed < r.SignedAt || r.DroppedAt != "-" && r.DroppedAt < r.SignedAt {
			return nil, decStorageError()
		}
		_, start, e := readDecPolicyReference(snapshot, r.Start, person)
		if e != nil {
			return nil, e
		}
		signed, body, e := readDecPolicyReference(snapshot, r.Signed, person)
		if e != nil {
			return nil, e
		}
		if (len(r.Dropped) == 0) != (r.DroppedAt == "-") {
			return nil, decStorageError()
		}
		if _, e = decPolicyDropSet(start, body, r.Dropped); e != nil {
			return nil, e
		}
		switch r.State {
		case editReserved:
			if signed != nil || r.Version != 0 || r.SignedAt != "-" || r.Unsettled != "-" || r.Closed != "-" || len(r.Dropped) > 0 {
				return nil, decStorageError()
			}
		case editSettled, editUnsettled, editClosed:
			if signed == nil || r.Version != signed.Access.Sequence || r.SignedAt == "-" || (r.State == editUnsettled) != (r.Unsettled != "-") || (r.State == editClosed) != (r.Closed != "-") {
				return nil, decStorageError()
			}
		default:
			return nil, decStorageError()
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
func storeDecPolicyEdit(ctx context.Context, tx *sql.Tx, network, person string, r decPolicyEdit) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(raw) > dec.MaxPrivateRecord {
		return decFailure("quota_exceeded")
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO policy_edits(network_id,person_id,seq,record) VALUES(?,?,?,?) ON CONFLICT(network_id,person_id,seq) DO UPDATE SET record=excluded.record`, network, personIDOf(person), r.Seq, string(raw))
	return e
}

type DecEditReservation struct {
	Context string          `json:"context_id"`
	Person  string          `json:"person_public_key"`
	Policy  json.RawMessage `json:"policy"`
	Version uint64          `json:"version"`
	Seq     int64           `json:"seq"`
	Created string          `json:"created_at"`
	Expires string          `json:"expires_at"`
}
type DecEditSummary struct {
	Context string `json:"context_id"`
	Person  string `json:"person_public_key"`
	Edits   []struct {
		Seq     int64    `json:"seq"`
		State   string   `json:"state"`
		Version uint64   `json:"signed_version"`
		Dropped []string `json:"dropped"`
	} `json:"edits"`
}

func (s *Store) ReserveDecentralizedPolicyEdit(ctx context.Context, network, provider string) (DecEditReservation, error) {
	var result DecEditReservation
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return result, e
	}
	now, e := decCreationClock(ctx, tx, network)
	if e != nil {
		return result, e
	}
	projection, e := verifyDecSnapshot(snapshot, now)
	if e != nil {
		return result, e
	}
	view, _, _, e := s.decActionProvider(ctx, tx, snapshot, projection, provider, "auto")
	if e != nil {
		return result, e
	}
	if view.Kind == "network_root" || view.Scopes&1 == 0 || view.Person != snapshot.Network.Own.Person {
		return result, decFailure("forbidden")
	}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, view.Person)
	if e != nil {
		return result, e
	}
	for _, edit := range edits {
		if edit.State == editUnsettled {
			// A higher local sequence must not absorb a signed withdrawal
			// before exact old-sequence reapplication has settled it.
			return result, decFailure("state_conflict")
		}
	}
	selected, maximum, e := decPolicyStream(snapshot, view.Person)
	if e != nil {
		return result, e
	}
	if maximum == ^uint64(0) {
		return result, decFailure("version_exhausted")
	}
	var newest int64
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM policy_edits WHERE network_id=? AND person_id=?`, network, personIDOf(view.Person)).Scan(&newest); e != nil {
		return result, e
	}
	if selected != nil {
		body, e := decPolicyBody(selected)
		if e != nil {
			return result, e
		}
		newest = max(newest, decBodyEditSeq(body.delta(), s.identity.ID))
	}
	if newest >= membership.PolicyMaxEditSeq {
		return result, decFailure("version_exhausted")
	}
	baseline := json.RawMessage(`"-"`)
	if current, _, err := projection.Current([]string{"policy", view.Person}); err == nil {
		baseline, e = makeDecPolicyReference(snapshot, current)
		if e != nil {
			return result, e
		}
	} else if dec.Code(err) == "state_conflict" || dec.Code(err) == "proof_required" && selected != nil {
		return result, err
	}
	// Recheck the real guard and the same operation-specific provider after all
	// reference validation; no signature or selection mutation is performed.
	now, e = decCreationClock(ctx, tx, network)
	if e != nil {
		return result, e
	}
	projection, e = verifyDecSnapshot(snapshot, now)
	if e != nil {
		return result, e
	}
	view, _, _, e = s.decActionProvider(ctx, tx, snapshot, projection, provider, "auto")
	if e != nil {
		return result, e
	}
	if view.Scopes&1 == 0 {
		return result, decFailure("forbidden")
	}
	baseline = json.RawMessage(`"-"`)
	if active, _, err := projection.Current([]string{"policy", view.Person}); err == nil {
		baseline, e = makeDecPolicyReference(snapshot, active)
		if e != nil {
			return result, e
		}
	} else if dec.Code(err) == "state_conflict" || dec.Code(err) == "proof_required" && selected != nil {
		return result, err
	}
	r := decPolicyEdit{2, "decentralized", snapshot.Descriptor.ContextID, newest + 1, editReserved, baseline, json.RawMessage(`"-"`), 0, []string{}, now, "-", "-", "-", "-"}
	if e = storeDecPolicyEdit(ctx, tx, network, view.Person, r); e != nil {
		return result, e
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, network, string(clock)); e != nil {
		return result, e
	}
	at, _ := dec.ParseTime(now)
	result = DecEditReservation{snapshot.Descriptor.ContextID, view.Person, baseline, maximum, r.Seq, now, at.Add(editReservationLapse).Format("2006-01-02T15:04:05Z")}
	return result, tx.Commit()
}
func (s *Store) DecentralizedPolicyEdits(ctx context.Context, network string) (DecEditSummary, error) {
	var result DecEditSummary
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return result, e
	}
	result.Context, result.Person = snapshot.Descriptor.ContextID, snapshot.Network.Own.Person
	result.Edits = []struct {
		Seq     int64    `json:"seq"`
		State   string   `json:"state"`
		Version uint64   `json:"signed_version"`
		Dropped []string `json:"dropped"`
	}{}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, result.Person)
	if e != nil {
		return result, e
	}
	for _, edit := range edits {
		result.Edits = append(result.Edits, struct {
			Seq     int64    `json:"seq"`
			State   string   `json:"state"`
			Version uint64   `json:"signed_version"`
			Dropped []string `json:"dropped"`
		}{edit.Seq, edit.State, edit.Version, append([]string{}, edit.Dropped...)})
	}
	return result, nil
}

// Only an explicitly reviewed ordinary resolver may copy an admitted branch.
// The ordinary action verifier separately checks current authority and complete
// proof closure before every call. This does not choose a current policy.
func decPolicyResolverBranch(snapshot *decSnapshot, statement *dec.Statement) (bool, error) {
	if statement.Kind != "policy" || statement.Access == nil {
		return false, nil
	}
	body, e := decPolicyBody(statement)
	if e != nil {
		return false, e
	}
	for _, maximum := range snapshot.Prior.Maxima {
		if len(maximum.Stream) != 2 || maximum.Stream[0] != "policy" || maximum.Stream[1] != body.Person || len(maximum.HeadIDs) < 2 {
			continue
		}
		if maximum.Sequence == ^uint64(0) {
			return false, decFailure("version_exhausted")
		}
		pred, _ := json.Marshal(statement.Access.Predecessors)
		resolves, _ := json.Marshal(statement.Access.Resolves)
		heads, _ := json.Marshal(maximum.HeadIDs)
		if statement.Access.Sequence != maximum.Sequence+1 || !bytes.Equal(pred, heads) || !bytes.Equal(resolves, heads) {
			return false, decFailure("state_conflict")
		}
		matched := false
		for _, id := range maximum.HeadIDs {
			old := snapshot.Catalog.Statements[id]
			if old == nil {
				return false, decFailure("proof_required", id)
			}
			if !containsString(snapshot.Prior.AdmittedStatements, id) || old.Kind != "policy" {
				return false, decStorageError()
			}
			prior, e := decPolicyBody(old)
			if e != nil {
				return false, e
			}
			matched = matched || decSamePolicyBody(prior.delta(), body.delta())
		}
		if !matched {
			return false, decFailure("state_conflict")
		}
		return true, nil
	}
	return false, nil
}

func checkDecPolicyEditBoundary(ctx context.Context, q dbQuerier, snapshot *decSnapshot, statement *dec.Statement, allowResolver bool) error {
	if statement.Kind != "policy" {
		return nil
	}
	body, e := decPolicyBody(statement)
	if e != nil {
		return e
	}
	edits, e := readDecPolicyEdits(ctx, q, snapshot, body.Person)
	if e != nil {
		return e
	}
	if allowResolver {
		if resolver, e := decPolicyResolverBranch(snapshot, statement); e != nil {
			return e
		} else if resolver {
			return nil
		}
	}
	selected, maximum, e := decPolicyStream(snapshot, body.Person)
	if e != nil {
		return e
	}
	if maximum == ^uint64(0) {
		return decFailure("version_exhausted")
	}
	if statement.Access.Sequence != maximum+1 {
		return decFailure("state_conflict")
	}
	hostKey, e := membership.DecodeKey(snapshot.Network.Own.Host)
	if e != nil {
		return decStorageError()
	}
	hostID := membership.HostID(hostKey)
	current := decEmptyPolicyBody()
	if selected != nil {
		old, e := decPolicyBody(selected)
		if e != nil {
			return e
		}
		current = old.delta()
	}
	ownSeq, oldSeq := decBodyEditSeq(body.delta(), hostID), decBodyEditSeq(current, hostID)
	var cited *decPolicyEdit
	for i := range edits {
		if edits[i].Seq == ownSeq {
			cited = &edits[i]
		}
	}
	if ownSeq > oldSeq && cited != nil && cited.State == editReserved {
		for _, edit := range edits {
			if edit.State == editUnsettled {
				return decFailure("state_conflict")
			}
		}
		newest := int64(0)
		var reserved *decPolicyEdit
		for i := range edits {
			if edits[i].State == editReserved {
				newest = max(newest, edits[i].Seq)
			}
			if edits[i].Seq == ownSeq {
				reserved = &edits[i]
			}
		}
		if reserved == nil || reserved.State != editReserved || ownSeq != newest {
			return decFailure("state_conflict")
		}
		now, e := decNow()
		if e != nil {
			return e
		}
		decision, e := dec.DecisionTime(linkTime(now), snapshot.Prior.ClockGuard)
		if e != nil {
			return e
		}
		at, e := dec.ParseTime(reserved.Reserved)
		if e != nil {
			return e
		}
		currentTime, _ := dec.ParseTime(decision)
		if currentTime.Before(at) || currentTime.Sub(at) > editReservationLapse {
			return decFailure("review_required")
		}
		return nil
	}
	if decSamePolicyBody(current, body.delta()) {
		return nil
	}
	reapplied, _, reflected, e := decReappliedPolicy(snapshot, current, edits, body.Person, hostID)
	if e != nil {
		return e
	}
	if reflected > 0 {
		found := false
		for i := range reapplied.Edits {
			if reapplied.Edits[i].Host == hostID {
				reapplied.Edits[i].Seq = reflected
				found = true
			}
		}
		if !found {
			reapplied.Edits = append(reapplied.Edits, membership.PolicyEdit{Host: hostID, Seq: reflected})
		}
		sort.Slice(reapplied.Edits, func(i, j int) bool { return reapplied.Edits[i].Host < reapplied.Edits[j].Host })
	}

	if !decSamePolicyBody(reapplied, body.delta()) {
		return decFailure("state_conflict")
	}
	return nil
}

// This runs only after the exact policy was actually admitted in this same TX.
// Claim preparation never reaches it and cannot consume/settle a reservation.
func (s *Store) settleDecPolicyEdits(ctx context.Context, tx *sql.Tx, snapshot *decSnapshot, statement *dec.Statement, now string, allowResolver bool) error {
	if statement.Kind != "policy" {
		return nil
	}
	body, e := decPolicyBody(statement)
	if e != nil {
		return e
	}
	if allowResolver {
		if resolver, e := decPolicyResolverBranch(snapshot, statement); e != nil {
			return e
		} else if resolver {
			// storeDecProjection already reconciled ONLY live signed rows in
			// this TX. Never consume a coincidentally matching reservation or
			// replace an old signed reference during branch selection.
			return nil
		}
	}
	edits, e := readDecPolicyEdits(ctx, tx, snapshot, body.Person)
	if e != nil {
		return e
	}
	current, e := s.loadDecSnapshot(ctx, tx, snapshot.Descriptor.NetworkID)
	if e != nil {
		return e
	}
	reference, e := makeDecPolicyReference(current, statement)
	if e != nil {
		return e
	}
	reflected := decBodyEditSeq(body.delta(), s.identity.ID)
	dropped := map[int64][]string{}
	if previous, _, err := decPolicyStream(snapshot, body.Person); err != nil {
		return err
	} else if previous != nil {
		old, e := decPolicyBody(previous)
		if e != nil {
			return e
		}
		beforeReflected := decBodyEditSeq(old.delta(), s.identity.ID)
		priorEdits := append([]decPolicyEdit{}, edits...)
		for i := range priorEdits {
			if priorEdits[i].State == editSettled && priorEdits[i].Seq > beforeReflected {
				priorEdits[i].State = editUnsettled
			}
		}
		reapplied, items, _, e := decReappliedPolicy(snapshot, old.delta(), priorEdits, body.Person, s.identity.ID)
		if e != nil {
			return e
		}
		if membership.SameContent(reapplied, body.delta()) {
			dropped = items
		}
	}
	for _, edit := range edits {
		if edit.State == editReserved {
			if edit.Seq != reflected {
				continue
			}
			edit.Signed, edit.Version, edit.SignedAt = reference, statement.Access.Sequence, now
		} else if edit.State == editClosed {
			continue
		}
		if len(dropped[edit.Seq]) > 0 {
			_, start, e := readDecPolicyReference(snapshot, edit.Start, body.Person)
			if e != nil {
				return e
			}
			_, signed, e := readDecPolicyReference(snapshot, edit.Signed, body.Person)
			if e != nil {
				return e
			}
			updated, e := decAppendPolicyDrops(edit.Dropped, dropped[edit.Seq], start, signed)
			if e != nil {
				return e
			}
			if len(updated) != len(edit.Dropped) {
				edit.Dropped, edit.DroppedAt = updated, now
			}
		}
		state := editUnsettled
		if edit.Seq <= reflected {
			state = editSettled
		}
		if state == editUnsettled && edit.State != editUnsettled {
			edit.Unsettled = now
		}
		if state == editSettled {
			edit.Unsettled = "-"
		}
		edit.State = state
		if e = storeDecPolicyEdit(ctx, tx, snapshot.Descriptor.NetworkID, body.Person, edit); e != nil {
			return e
		}
	}
	return nil
}
