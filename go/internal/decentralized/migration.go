package decentralized

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
)

type MigrationEvidence struct {
	OK              bool     `json:"ok"`
	ContextID       string   `json:"context_id"`
	ProposalID      string   `json:"proposal_id"`
	RootStateID     string   `json:"root_state_id"`
	PreparedHash    string   `json:"prepared_catalog_sha256"`
	RosterHosts     []string `json:"roster_host_public_keys"`
	LocalMatched    bool     `json:"local_approval_matched"`
	OriginValid     bool     `json:"context_origin_valid"`
	UsableDevices   []string `json:"usable_device_lease_ids"`
	InactiveDevices []string `json:"inactive_device_lease_ids"`
}

type migrationRoster struct {
	Host   string `json:"host_public_key"`
	Member string `json:"member"`
	Person string `json:"person_public_key"`
	Device string `json:"device_public_key"`
	Scopes uint64 `json:"scopes"`
}

type migrationValidation struct {
	migration *ParsedMigration
	state     *SourceState
	legacy    linking.NetworkState
	prepared  *Catalog
	graph     *graph
	root      *Statement
	roster    []migrationRoster
}

// verifyMigrationOrigin verifies complete portable origin and the exact staged
// state. Its scratch graph is never an ordinary prior or signing provider.
func verifyMigrationOrigin(d Descriptor, m *ParsedMigration) (*migrationValidation, error) {
	return verifyMigrationParts(d, m, true)
}

// A prepared catalog is checked before any acknowledgment/final commit exists.
// Only this private path may omit those later signatures; ordinary portable
// origin verification always requests complete=true through the wrapper above.
func verifyMigrationParts(d Descriptor, m *ParsedMigration, complete bool) (*migrationValidation, error) {
	state, facts, e := verifyMigrationSource(d, m)
	if e != nil {
		return nil, e
	}
	if m.Proposal.Signer("issuer") != facts.RootPublicKey {
		return nil, invalid()
	}
	prepared, e := readCatalog(d, m.PreparedCatalog, false)
	if e != nil {
		return nil, e
	}
	v := &migrationValidation{migration: m, state: state, legacy: facts, prepared: prepared}
	if json.Unmarshal(m.Proposal.Object["roster"], &v.roster) != nil {
		return nil, invalid()
	}
	if len(v.roster) != len(facts.Members) {
		return nil, invalid()
	}
	for i, member := range facts.Members {
		row := v.roster[i]
		if row.Host != member.HostPublicKey || row.Member != member.Member || row.Person != member.PersonPublicKey {
			return nil, invalid()
		}
	}
	proposalFound := false
	for _, s := range prepared.Statements {
		if s.Kind == "migration_proposal" {
			if s.ID != m.Proposal.ID || !bytes.Equal(s.Payload, m.Proposal.Payload) {
				return nil, invalid()
			}
			proposalFound = true
		}
		if s.Root != nil {
			if v.root != nil && v.root.ID != s.ID {
				return nil, failure("state_conflict")
			}
			v.root = s
		}
	}
	if !proposalFound {
		return nil, failure("proof_required", m.Proposal.ID)
	}
	if v.root == nil {
		if complete {
			return nil, failure("proof_required", stringField(m.Commit.Object, "root_state_id"))
		}
		return nil, failure("proof_required")
	}
	r := v.root.Root
	epoch, _ := num(m.Proposal.Object, "legacy_epoch")
	if r.Migration != m.Proposal.ID || r.Epoch != epoch || r.Key != facts.RootPublicKey || r.Issued != stringField(m.Proposal.Object, "issued_at") || len(r.Predecessors) != 0 || len(r.Resolves) != 0 || len(r.Retained) != 0 || v.root.Signer("issuer") != facts.RootPublicKey {
		return nil, invalid()
	}
	if complete && stringField(m.Commit.Object, "root_state_id") != v.root.ID {
		return nil, invalid()
	}
	g := newGraph(d, prepared)
	g.migrationRoots[v.root.ID] = state
	v.graph = g
	g.migrationHosts[m.Proposal.ID] = map[string]bool{}
	for id, s := range prepared.Statements {
		if s.Kind == "host_lease" && s.Lease.Operation == m.Proposal.ID {
			g.migrationHosts[m.Proposal.ID][id] = true
		}
	}
	if e = g.prepareConsent(); e != nil {
		return nil, e
	}
	ids := []string{}
	for id := range prepared.Statements {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if e = g.validate(id); e != nil {
			return nil, e
		}
	}
	if e = g.validateAliases(); e != nil {
		return nil, e
	}
	if e = v.checkPrepared(); e != nil {
		return nil, e
	}
	if complete {
		if e = v.checkAcknowledgments(); e != nil {
			return nil, e
		}
	}
	return v, nil
}

func (v *migrationValidation) checkPrepared() error {
	m, root := v.migration, v.root
	persons, hosts := map[string]*Statement{}, map[string]*Statement{}
	roster := map[string]migrationRoster{}
	for _, row := range v.roster {
		roster[row.Host] = row
	}
	floors := map[string]uint64{}
	for _, f := range v.state.Maxima {
		floors[f.Kind+"\x00"+f.Subject] = f.Version
	}
	streams := map[string]string{}
	bans, e := v.requiredBans()
	if e != nil {
		return e
	}
	for _, s := range v.prepared.Statements {
		if s.Root != nil || s.Kind == "migration_proposal" {
			continue
		}
		if s.Lease == nil && s.Access == nil && s.Restriction == nil {
			return invalid()
		}
		if s.rootID() != root.ID {
			return invalid()
		}
		issued := s.issuedTime()
		start, _ := stamp(stringField(m.Proposal.Object, "issued_at"))
		end, _ := stamp(stringField(m.Proposal.Object, "expires_at"))
		if issued.Before(start) || !issued.Before(end) {
			return invalid()
		}
		if len(s.stream()) > 0 {
			key := streamKey(s.stream())
			if previous, ok := streams[key]; ok && previous != s.ID {
				return failure("state_conflict")
			}
			streams[key] = s.ID
		}
		if s.Lease != nil {
			if s.sequence() != 1 || len(s.predecessors()) != 0 || len(s.resolves()) != 0 || len(s.retained()) != 0 {
				return invalid()
			}
			switch s.Kind {
			case "person_lease":
				person := s.Lease.Subject.Person
				if s.Lease.Issuer.Kind != "root" || s.Lease.Operation != "-" || !v.legacy.Facts.State.Persons[person].Admitted || v.legacy.Facts.PersonLabels[person] != s.Lease.Subject.Member {
					return invalid()
				}
				persons[person] = s
			case "admin_lease":
				if s.Lease.Issuer.Kind != "root" || !v.legacy.Facts.State.Persons[s.Lease.Subject.Person].Admitted {
					return invalid()
				}
			case "host_lease":
				row, ok := roster[s.Lease.Subject.Host]
				if !ok || row.Member != s.Lease.Subject.Member || s.Lease.Issuer.Kind != "root" {
					return invalid()
				}
				if row.Person == "-" && s.Lease.Operation != m.Proposal.ID || row.Person != "-" && !identifier(s.Lease.Operation, "link_") {
					return invalid()
				}
				hosts[row.Host] = s
			case "binding_lease", "device_lease":
				row, ok := roster[s.Lease.Subject.Host]
				if !ok || row.Person == "-" || row.Person != s.Lease.Subject.Person || s.Lease.Issuer.Kind != "person" || s.Lease.Issuer.Person != row.Person || !identifier(s.Lease.Operation, "link_") {
					return invalid()
				}
				if s.Kind == "device_lease" && (s.Lease.Subject.Device != row.Device || s.Lease.Subject.Scopes != row.Scopes) {
					return invalid()
				}
			}
		}
		if s.Access != nil {
			if s.Kind == "policy" && s.Access.Issuer.Kind != "person" || s.Kind == "group" && s.Access.Issuer.Kind != "root" || len(s.predecessors()) != 0 || len(s.resolves()) != 0 {
				return invalid()
			}
			stream := s.stream()
			floor := floors[s.Kind+"\x00"+stream[1]]
			if floor == math.MaxUint64 {
				return failure("version_exhausted")
			}
			if s.sequence() <= floor {
				return failure("state_conflict")
			}
		}
		if s.Restriction != nil {
			if s.Kind != "person_remove" && s.Kind != "host_revoke" && s.Kind != "device_revoke" {
				return invalid()
			}
			if s.Kind == "device_revoke" {
				if s.Restriction.Issuer.Kind != "person" || !v.legacy.Facts.State.RevokedDevices[linking.DeviceKey{PersonPublicKey: s.Restriction.Target.Person, DevicePublicKey: s.Restriction.Target.Device}] {
					return invalid()
				}
			} else if s.Restriction.Issuer.Kind != "root" {
				return invalid()
			}
			key := migrationBanKey(s.Kind, s.Restriction.Target)
			if _, ok := bans[key]; !ok || s.Restriction.Target.Statement != "-" || s.Restriction.Ratifies != "-" || len(s.Restriction.Kept) != 0 {
				return invalid()
			}
			delete(bans, key)
		}
	}
	if len(bans) > 0 {
		// All exact source bodies were verified above. A complete prepared
		// context which omits a required inherited ban is independently denied,
		// not an invitation to supply an already present old proof again.
		return failure("forbidden")
	}
	for person, state := range v.legacy.Facts.State.Persons {
		if state.Admitted && persons[person] == nil {
			return failure("proof_required")
		}
	}
	for _, row := range v.roster {
		if hosts[row.Host] == nil {
			return failure("proof_required")
		}
	}
	for _, s := range v.prepared.Statements {
		if s.Kind == "binding_lease" || s.Kind == "device_lease" {
			if p := persons[s.Lease.Subject.Person]; p == nil || parentID(s.parents(), "subject_person") != p.ID || parentID(s.parents(), "issuer_person") != p.ID {
				return invalid()
			}
		}
	}
	seen := map[string]bool{}
	for _, a := range v.prepared.Activations {
		row, ok := roster[a.Request.Writer]
		if !ok || row.Person == "-" || seen[row.Host] || stringField(a.Request.Object, "mode") != "new" || stringField(a.Request.Object, "migration_proposal_id") != m.Proposal.ID || a.Owner.Person != row.Person || a.Owner.Signer != row.Person || a.Owner.Issuer != "-" || a.Request.Signer != row.Device || stringField(a.Manifest, "person_lease_id") != persons[row.Person].ID || stringField(a.Manifest, "host_lease_id") != hosts[row.Host].ID {
			return invalid()
		}
		seen[row.Host] = true
	}
	for _, row := range v.roster {
		if row.Person != "-" && !seen[row.Host] {
			return failure("proof_required")
		}
	}
	return nil
}

func (v *migrationValidation) checkAcknowledgments() error {
	m := v.migration
	if len(m.Acknowledgments) != len(v.roster) {
		return failure("proof_required")
	}
	for i, ack := range m.Acknowledgments {
		row := v.roster[i]
		if stringField(ack.Object, "host_public_key") != row.Host || stringField(ack.Object, "person_public_key") != row.Person || stringField(ack.Object, "device_public_key") != row.Device || stringField(ack.Object, "root_state_id") != v.root.ID {
			return invalid()
		}
		h, e := v.graph.get(stringField(ack.Object, "host_lease_id"))
		if e != nil {
			return e
		}
		if h.Kind != "host_lease" || h.Lease.Subject.Host != row.Host {
			return invalid()
		}
		if row.Person == "-" {
			continue
		}
		a := v.prepared.Activations[stringField(ack.Object, "activation_id")]
		if a == nil {
			return failure("proof_required", stringField(ack.Object, "activation_id"))
		}
		if a.Request.Writer != row.Host || a.Request.Signer != row.Device || a.Owner.Person != row.Person || stringField(a.Manifest, "host_lease_id") != h.ID || stringField(a.Manifest, "binding_lease_id") != stringField(ack.Object, "binding_lease_id") || stringField(a.Manifest, "device_lease_id") != stringField(ack.Object, "device_lease_id") {
			return invalid()
		}
	}
	return nil
}

func (v *migrationValidation) currentAuthority(now time.Time) *authority {
	admitted, restrictions := map[string]bool{}, map[string]bool{}
	for id, s := range v.prepared.Statements {
		if s.Root != nil || s.Lease != nil || s.Access != nil {
			admitted[id] = true
		}
		if s.Restriction != nil {
			restrictions[id] = true
		}
	}
	g := *v.graph
	g.migrationHosts = map[string]map[string]bool{v.migration.Proposal.ID: {}}
	for id, s := range v.prepared.Statements {
		if s.Kind == "host_lease" && s.Lease.Operation == v.migration.Proposal.ID {
			g.migrationHosts[v.migration.Proposal.ID][id] = true
		}
	}
	return &authority{graph: &g, now: now, admitted: admitted, restrictions: restrictions, heads: headsFor(&g, admitted), maxima: map[string]uint64{}, active: map[string]bool{}}
}

func VerifyMigration(d Descriptor, legacyRaw, priorRaw, migrationRaw []byte, now, purpose, host string) (*MigrationEvidence, error) {
	if purpose != "evidence" && purpose != "adoption" || !literalOrKey(host) {
		return nil, invalid()
	}
	m, e := readMigration(d, migrationRaw)
	if e != nil {
		return nil, e
	}
	v, e := verifyMigrationOrigin(d, m)
	if e != nil {
		return nil, e
	}
	prior, e := readPrior(d, priorRaw)
	if e != nil {
		return nil, e
	}
	guard := "-"
	if prior != nil {
		guard = prior.ClockGuard
		if prior.Migration != "-" && prior.Migration != m.Proposal.ID {
			return nil, failure("state_conflict")
		}
	}
	decision, e := DecisionTime(now, guard)
	if e != nil {
		return nil, e
	}
	legacy, e := readLegacyPrior(d, legacyRaw)
	if e != nil {
		return nil, e
	}
	matched := false
	if legacy != nil {
		other, e := DecisionTime(now, legacy.ClockGuard)
		if e != nil {
			return nil, e
		}
		if other > decision {
			decision = other
		}
		matched, e = verifyLegacyApproval(d, legacy, v, host, purpose == "adoption")
		if e != nil {
			return nil, e
		}
	}
	if purpose == "adoption" && !matched {
		return nil, failure("forbidden")
	}
	if prior != nil {
		for _, other := range prior.catalog.Migrations {
			if _, e = verifyMigrationOrigin(d, other); e != nil {
				return nil, e
			}
			if other.Proposal.ID != m.Proposal.ID || digest(other.PreparedCatalog) != digest(m.PreparedCatalog) {
				return nil, failure("state_conflict")
			}
		}
	}
	at, _ := stamp(decision)
	issued, _ := stamp(stringField(m.Proposal.Object, "issued_at"))
	if at.Before(issued) {
		return nil, failure("not_yet_valid")
	}
	// Portable origin validity is historical, while current device power must
	// include the caller's independently trusted restrictions, heads and maxima.
	// Reuse ordinary complete-origin projection rather than prepared-only state.
	candidate, e := json.Marshal(struct {
		Format  uint64          `json:"format"`
		Context string          `json:"context_id"`
		Objects []CatalogObject `json:"objects"`
	}{1, d.ContextID, []CatalogObject{{ID: ProofID("migration", m.Raw), Kind: "migration", BodyBase64: b64(m.Raw)}}})
	if e != nil {
		return nil, e
	}
	projection, e := Project(d, priorRaw, candidate, decision, "repair")
	if e != nil {
		return nil, e
	}
	a := projection.authority
	result := &MigrationEvidence{OK: true, ContextID: d.ContextID, ProposalID: m.Proposal.ID, RootStateID: v.root.ID, PreparedHash: digest(m.PreparedCatalog), RosterHosts: []string{}, LocalMatched: matched, OriginValid: true, UsableDevices: []string{}, InactiveDevices: []string{}}
	for _, row := range v.roster {
		result.RosterHosts = append(result.RosterHosts, row.Host)
	}
	for _, ack := range m.Acknowledgments {
		id := stringField(ack.Object, "device_lease_id")
		if id == "-" {
			continue
		}
		s, e := a.graph.get(id)
		if e != nil {
			return nil, e
		}
		if _, e = a.evaluate(s); e == nil {
			result.UsableDevices = append(result.UsableDevices, id)
		} else if Code(e) == "proof_required" || Code(e) == "invalid" {
			return nil, e
		} else {
			result.InactiveDevices = append(result.InactiveDevices, id)
		}
	}
	sort.Strings(result.UsableDevices)
	sort.Strings(result.InactiveDevices)
	return result, nil
}

// Only the exact root/all-host reviewed prepared set gets this staging
// admission basis. It cannot supply issuer power to another ordinary candidate
// in this pass, and every finite grant still needs its own NOW path.
func migrationCurrentGrants(a *authority, v *migrationValidation) ([]string, error) {
	view := *a
	view.admitted = copySet(a.admitted)
	eligible := map[string]bool{}
	for id, s := range v.prepared.Statements {
		if a.graph.pendingAdmissions[id] == "" && (s.Lease != nil || s.Access != nil) && candidateWindow(s, a.now) == nil {
			view.admitted[id] = true
			eligible[id] = true
		}
	}
	view.heads = advanceHeads(a.graph, a.heads, eligible)
	view.firstAdmissions = a.admitted
	accepted := map[string]bool{}
	for id := range eligible {
		view.proven = map[string]bool{}
		if _, e := view.evaluateContents(a.graph.catalog.Statements[id], nil, map[string]bool{}, true); e != nil {
			if Code(e) == "proof_required" {
				return nil, e
			}
			continue
		}
		for id := range view.proven {
			accepted[id] = true
		}
	}
	return keysSorted(accepted), nil
}

func migrationFloors(maxima []Maximum, origins map[string]*migrationValidation, now time.Time) []Maximum {
	rows := map[string]Maximum{}
	for _, m := range maxima {
		rows[streamKey(m.Stream)] = m
	}
	for _, origin := range origins {
		if origin.root.issuedTime().After(now) {
			continue
		}
		for _, floor := range origin.state.Maxima {
			stream := []string{floor.Kind, floor.Subject}
			key := streamKey(stream)
			if old, ok := rows[key]; !ok || floor.Version > old.Sequence {
				heads := old.HeadIDs
				if heads == nil {
					heads = []string{}
				}
				rows[key] = Maximum{Stream: stream, Sequence: floor.Version, StatementIDs: []string{}, HeadIDs: heads}
			}
		}
	}
	out := []Maximum{}
	for _, m := range rows {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return compareStreams(out[i].Stream, out[j].Stream) < 0 })
	return out
}
