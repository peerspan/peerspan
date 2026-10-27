package decentralized

import (
	"bytes"
	"math"
	"sort"
)

// graph resolves typed, exact references independently of current authority.
// A structurally valid historical edge never supplies a current grant by itself.
type graph struct {
	descriptor     Descriptor
	catalog        *Catalog
	done, busy     map[string]bool
	activated      map[string]*ParsedActivation
	migrationHosts map[string]map[string]bool
	migrationRoots map[string]*SourceState
	// pendingAdmissions is used only by the local ceremony preparation reader.
	// It checks the exact administrator's P/H components without admitting them
	// or pretending that requester final consent already exists.
	pendingAdmissions map[string]string
	// Read-only projections preserve per-domain missing-proof diagnostics.
	// A remembered head remains unavailable until its exact closure is present;
	// this map never relaxes candidate admission or trusts incomplete aliases.
	readMissing map[string]error
}

func newGraph(d Descriptor, c *Catalog) *graph {
	return &graph{descriptor: d, catalog: c, done: map[string]bool{}, busy: map[string]bool{}, activated: map[string]*ParsedActivation{}, migrationHosts: map[string]map[string]bool{}, migrationRoots: map[string]*SourceState{}}
}
func (g *graph) get(id string) (*Statement, error) {
	s := g.catalog.Statements[id]
	if s == nil {
		return nil, failure("proof_required", id)
	}
	return s, nil
}
func (g *graph) validate(id string) error {
	if g.done[id] {
		return nil
	}
	if g.busy[id] {
		return invalid()
	}
	s, e := g.get(id)
	if e != nil {
		return e
	}
	g.busy[id] = true
	defer delete(g.busy, id)
	if r := s.Root; r != nil {
		// A self-signed migrated root is a typed draft until the complete verified
		// old-root/all-host migration authenticates this exact origin. Successors
		// cannot turn that unauthenticated draft into an ordinary root lineage.
		if len(r.Predecessors) == 0 && r.Migration != "-" && g.migrationRoots[s.ID] == nil {
			return failure("proof_required", r.Migration)
		}
		max := uint64(0)
		for _, pred := range r.Predecessors {
			p, e := g.get(pred)
			if e != nil {
				return e
			}
			if p.Root == nil {
				return invalid()
			}
			if e = g.validate(pred); e != nil {
				return e
			}
			if p.Root.Epoch > max {
				max = p.Root.Epoch
			}
			role := "issuer"
			if len(r.Predecessors) > 1 {
				role = "root_branch:" + pred
			}
			if s.Signer(role) != p.Root.Key {
				return invalid()
			}
		}
		if len(r.Predecessors) > 0 && (max == math.MaxUint64 || r.Epoch != max+1) {
			return invalid()
		}
		for i, a := range r.Predecessors {
			for _, b := range r.Predecessors[i+1:] {
				if g.descends(a, b) || g.descends(b, a) {
					return invalid()
				}
			}
		}
	} else if s.Lease != nil || s.Access != nil || s.Restriction != nil {
		root, e := g.get(s.rootID())
		if e != nil {
			return e
		}
		if root.Root == nil {
			return invalid()
		}
		if e = g.validate(root.ID); e != nil {
			return e
		}
		for _, parent := range s.parents() {
			if e = g.validate(parent.ID); e != nil {
				return e
			}
		}
		if e = g.checkParentRelations(s); e != nil {
			return e
		}
		if s.Lease != nil && s.Lease.Operation != "-" && !identifier(s.Lease.Operation, "ds_") && g.pendingAdmissions[s.ID] != s.Lease.Operation {
			activation := g.activated[s.Lease.Operation]
			if activation == nil {
				return failure("proof_required", s.Lease.Operation)
			}
			field := map[string]string{"person_lease": "person_lease_id", "host_lease": "host_lease_id", "binding_lease": "binding_lease_id", "device_lease": "device_lease_id"}[s.Kind]
			if field == "" || stringField(activation.Manifest, field) != s.ID {
				return invalid()
			}
		} else if s.Lease != nil && identifier(s.Lease.Operation, "ds_") {
			if s.Kind != "host_lease" || !g.migrationHosts[s.Lease.Operation][s.ID] {
				return failure("proof_required", s.Lease.Operation)
			}
		}

		for _, pred := range s.predecessors() {
			p, e := g.get(pred)
			if e != nil {
				return e
			}
			if !equalStrings(p.stream(), s.stream()) || s.sequence() <= p.sequence() {
				return invalid()
			}
			if e = g.validate(pred); e != nil {
				return e
			}
		}
		if s.Restriction == nil {
			resolvedHeads := []string{}
			for _, id := range s.resolves() {
				target, e := g.get(id)
				if e != nil {
					return e
				}
				if target.Restriction == nil {
					resolvedHeads = append(resolvedHeads, id)
				}
			}
			if len(s.predecessors()) > 1 && !equalStrings(s.predecessors(), resolvedHeads) || len(s.predecessors()) <= 1 && len(resolvedHeads) != 0 {
				return invalid()
			}
		}
		if s.Restriction == nil && len(s.predecessors()) == 0 {
			// A first migrated access generation follows its exact authenticated
			// source floor even after an ordinary root transition. A root's marker
			// alone never supplies the source or relaxes an initial lease stream.
			floor, inherited := g.inheritedAccessFloor(root, s.stream(), map[string]bool{})
			if s.Access != nil && inherited {
				if s.sequence() <= floor {
					return failure("state_conflict")
				}
			} else if s.sequence() != 1 {
				return invalid()
			}
		}
		for _, resolved := range s.resolves() {
			target, e := g.get(resolved)
			if e != nil {
				return e
			}
			if target.Restriction == nil {
				if !equalStrings(target.stream(), s.stream()) || !contains(s.predecessors(), resolved) {
					return invalid()
				}
			} else if !validResolvedRestriction(s, target) {
				return invalid()
			}
		}
		if r := s.Restriction; r != nil {
			if r.Target.Statement != "-" {
				target, e := g.get(r.Target.Statement)
				if e != nil {
					return e
				}
				if r.Target.Person != target.LeasePerson() || s.Kind == "admin_withdraw" && target.Kind != "admin_lease" || s.Kind == "host_unbind" && (target.Kind != "binding_lease" || r.Target.Host != target.LeaseHost()) {
					return invalid()
				}
			}
			if r.Ratifies != "-" {
				old, e := g.get(r.Ratifies)
				if e != nil {
					return e
				}
				if old.Kind != s.Kind || old.Restriction == nil || old.Restriction.Target != r.Target || !equalStrings(old.Restriction.Kept, r.Kept) {
					return invalid()
				}
				if e = g.validate(old.ID); e != nil {
					return e
				}
			}
			for _, id := range r.Kept {
				kept, e := g.get(id)
				if e != nil {
					return e
				}
				if kept.Kind != "person_lease" && kept.Kind != "host_lease" || parentID(kept.parents(), "issuer_admin") != r.Target.Statement {
					return invalid()
				}
				if e = g.validate(id); e != nil {
					return e
				}
			}
		}
	}
	for _, retained := range s.retained() {
		child, e := g.get(retained)
		if e != nil {
			return e
		}
		if retained == s.ID || child.Root != nil || child.Restriction != nil || child.Lease == nil && child.Access == nil || g.dependsOn(child.ID, s.ID, map[string]bool{}) {
			return invalid()
		}
		if e = g.validate(retained); e != nil {
			return e
		}
		related := false
		for _, pred := range s.predecessors() {
			if g.relatedContribution(child, pred, map[string]bool{}) {
				related = true
			}
		}
		if !related {
			return invalid()
		}

	}
	g.done[id] = true
	return nil
}

// inheritedAccessFloor follows only the already structurally verified root
// lineage. The source pointers are installed by verified complete migration or
// its dedicated preparation reader, never by an untrusted root marker or prior
// maximum. Multiple authenticated carrying branches preserve the highest floor.
func (g *graph) inheritedAccessFloor(root *Statement, stream []string, seen map[string]bool) (uint64, bool) {
	if root == nil || root.Root == nil || seen[root.ID] || len(stream) != 2 || stream[0] != "policy" && stream[0] != "group" {
		return 0, false
	}
	seen[root.ID] = true
	var floor uint64
	found := false
	if source := g.migrationRoots[root.ID]; source != nil {
		for _, maximum := range source.Maxima {
			if maximum.Kind == stream[0] && maximum.Subject == stream[1] {
				floor, found = maximum.Version, true
			}
		}
	}
	for _, id := range root.Root.Predecessors {
		value, inherited := g.inheritedAccessFloor(g.catalog.Statements[id], stream, seen)
		if inherited {
			if !found || value > floor {
				floor = value
			}
			found = true
		}
	}
	return floor, found
}
func (s *Statement) LeasePerson() string {
	if s.Lease != nil {
		return s.Lease.Subject.Person
	}
	return ""
}
func (s *Statement) LeaseHost() string {
	if s.Lease != nil {
		return s.Lease.Subject.Host
	}
	return ""
}
func (s *Statement) retained() []string {
	if s.Root != nil {
		return s.Root.Retained
	}
	if s.Lease != nil {
		return s.Lease.Retained
	}
	return nil
}
func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
func (g *graph) descends(id, ancestor string) bool {
	return g.descendsSeen(id, ancestor, map[string]bool{})
}
func (g *graph) descendsSeen(id, ancestor string, seen map[string]bool) bool {
	if id == ancestor {
		return true
	}
	if seen[id] {
		return false
	}
	seen[id] = true
	s := g.catalog.Statements[id]
	if s == nil {
		return false
	}
	for _, pred := range s.predecessors() {
		if g.descendsSeen(pred, ancestor, seen) {
			return true
		}
	}
	return false
}
func (g *graph) dependsOn(id, ancestor string, seen map[string]bool) bool {
	if id == ancestor {
		return true
	}
	if seen[id] {
		return false
	}
	seen[id] = true
	s := g.catalog.Statements[id]
	if s == nil {
		return false
	}
	for _, p := range s.parents() {
		if g.dependsOn(p.ID, ancestor, seen) {
			return true
		}
	}
	return s.rootID() == ancestor
}
func (g *graph) checkParentRelations(s *Statement) error {
	var issuer Issuer
	if s.Lease != nil {
		issuer = s.Lease.Issuer
	}
	if s.Access != nil {
		issuer = s.Access.Issuer
	}
	if s.Restriction != nil {
		issuer = s.Restriction.Issuer
	}
	root := g.catalog.Statements[s.rootID()]
	expected := issuer.Person
	if issuer.Kind == "root" {
		expected = root.Root.Key
	}
	if issuer.Kind == "device" {
		d, e := g.get(parentID(s.parents(), "issuer_device"))
		if e != nil {
			return e
		}
		if d.Kind != "device_lease" || d.Lease.Subject.Person != issuer.Person {
			return invalid()
		}
		expected = d.Lease.Subject.Device
	}
	if s.Signer("issuer") != expected {
		return invalid()
	}
	for _, p := range s.parents() {
		parent := g.catalog.Statements[p.ID]
		if parent.Lease == nil {
			return invalid()
		}
		l := parent.Lease
		switch p.Role {
		case "issuer_person":
			if parent.Kind != "person_lease" || l.Subject.Person != issuer.Person {
				return invalid()
			}
		case "issuer_admin":
			if parent.Kind != "admin_lease" || l.Subject.Person != issuer.Person {
				return invalid()
			}
		case "issuer_device":
			if parent.Kind != "device_lease" || l.Subject.Person != issuer.Person {
				return invalid()
			}
		case "subject_person":
			if s.Lease == nil || parent.Kind != "person_lease" || l.Subject.Person != s.Lease.Subject.Person {
				return invalid()
			}
		case "subject_host":
			if s.Lease == nil || parent.Kind != "host_lease" || l.Subject.Host != s.Lease.Subject.Host {
				return invalid()
			}
		case "subject_binding":
			if s.Lease == nil || parent.Kind != "binding_lease" || l.Subject.Person != s.Lease.Subject.Person || l.Subject.Host != s.Lease.Subject.Host {
				return invalid()
			}
		default:
			return invalid()
		}
		if s.Lease != nil && s.Lease.After > l.After || s.Access != nil && s.Access.After > l.After {
			return invalid()
		}
	}
	if s.Lease != nil && s.Lease.KindScopeOwner() && issuer.Kind == "device" {
		parent := g.catalog.Statements[parentID(s.parents(), "issuer_device")]
		if s.Kind == "device_lease" && (s.Lease.Subject.Scopes & ^parent.Lease.Subject.Scopes) != 0 {
			return failure("forbidden")
		}
	}
	if s.Kind == "binding_lease" || s.Kind == "device_lease" {
		p := g.catalog.Statements[parentID(s.parents(), "subject_person")]
		h := g.catalog.Statements[parentID(s.parents(), "subject_host")]
		if p.Lease.Subject.Member != h.Lease.Subject.Member {
			return invalid()
		}
	}
	if s.Kind == "device_lease" {
		return g.deviceAncestry(s, []string{}, map[string]bool{})
	}
	return nil
}
func (l *Lease) KindScopeOwner() bool { return l.Subject.Person != "-" && l.Subject.Host != "-" }
func (g *graph) deviceAncestry(s *Statement, keys []string, busy map[string]bool) error {
	if busy[s.ID] || contains(keys, s.Lease.Subject.Device) {
		return invalid()
	}
	if len(keys) >= 8 {
		return failure("quota_exceeded")
	}
	busy[s.ID] = true
	defer delete(busy, s.ID)
	keys = append(keys, s.Lease.Subject.Device)
	if s.Lease.Issuer.Kind == "device" {
		p, e := g.get(parentID(s.Lease.Parents, "issuer_device"))
		if e != nil {
			return e
		}
		return g.deviceAncestry(p, keys, busy)
	}
	return nil
}
func validResolvedRestriction(s, target *Statement) bool {
	r := target.Restriction
	if s.Kind == "admin_lease" {
		return target.Kind == "admin_withdraw" && r.Target.Person == s.Lease.Subject.Person
	}
	if s.Kind == "binding_lease" {
		return target.Kind == "host_unbind" && r.Target.Person == s.Lease.Subject.Person && r.Target.Host == s.Lease.Subject.Host
	}
	return false
}
func equalIssuerSignature(a, b *Statement) bool {
	if !bytes.Equal(a.Payload, b.Payload) || a.ID != b.ID {
		return false
	}
	for _, as := range a.Signatures {
		if as.Role != "issuer" {
			continue
		}
		for _, bs := range b.Signatures {
			if bs.Role == "issuer" {
				return as == bs
			}
		}
	}
	return false
}

// validateAliases checks contextual role keys for every exact public proof, not
// just the semantic representative. A wrong-key alias is invalid even when a
// good same-payload alias was already admitted or happens to sort later.
func (g *graph) validateAliases() error {
	ids := make([]string, 0, len(g.catalog.Proofs))
	for id := range g.catalog.Proofs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := g.catalog.Proofs[id]
		if e := g.validateAlias(s); e != nil {
			if g.readMissing == nil || Code(e) != "proof_required" {
				return e
			}
			if g.readMissing[s.ID] == nil {
				g.readMissing[s.ID] = e
			}
		}
	}
	return nil
}
func (g *graph) validateAlias(s *Statement) error {
	if r := s.Root; r != nil {
		for _, pred := range r.Predecessors {
			p, e := g.get(pred)
			if e != nil {
				return e
			}
			if p.Root == nil {
				return invalid()
			}
			role := "issuer"
			if len(r.Predecessors) > 1 {
				role = "root_branch:" + pred
			}
			if s.Signer(role) != p.Root.Key {
				return invalid()
			}
		}
		return nil
	}
	if s.Lease != nil || s.Access != nil || s.Restriction != nil {
		if e := g.checkParentRelations(s); e != nil {
			return e
		}
	}
	if s.Kind == "migration_commit" {
		root, e := g.get(stringField(s.Object, "root_state_id"))
		if e != nil {
			return e
		}
		if root.Root == nil || s.Signer("issuer") != root.Root.Key {
			return invalid()
		}
	}
	return nil
}

func (g *graph) relatedContribution(child *Statement, predecessor string, seen map[string]bool) bool {
	if seen[child.ID] {
		return false
	}
	seen[child.ID] = true
	pred := g.catalog.Statements[predecessor]
	if pred == nil {
		return false
	}
	if equalStrings(child.stream(), pred.stream()) && g.descends(pred.ID, child.ID) {
		return true
	}
	if pred.Root != nil && child.rootID() != "" && g.descends(pred.ID, child.rootID()) {
		return true
	}
	for _, p := range child.parents() {
		ancestor := g.catalog.Statements[p.ID]
		if ancestor != nil && g.relatedContribution(ancestor, predecessor, seen) {
			return true
		}
	}
	return false
}
