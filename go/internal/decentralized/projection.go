package decentralized

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

type RootView struct {
	HeadIDs     []string `json:"head_ids"`
	Maximum     uint64   `json:"maximum"`
	SelectedID  string   `json:"selected_id"`
	Conflicted  bool     `json:"conflicted"`
	Code        string   `json:"code"`
	RequiredIDs []string `json:"required_ids"`
}
type StreamView struct {
	Stream      []string `json:"stream"`
	HeadIDs     []string `json:"head_ids"`
	Maximum     uint64   `json:"maximum"`
	SelectedID  string   `json:"selected_id"`
	Active      bool     `json:"active"`
	Code        string   `json:"code"`
	RequiredIDs []string `json:"required_ids"`
}
type Projection struct {
	OK           bool         `json:"ok"`
	ContextID    string       `json:"context_id"`
	DecisionTime string       `json:"decision_time"`
	Root         RootView     `json:"root"`
	Streams      []StreamView `json:"streams"`
	Restrictions []string     `json:"restrictions"`
	Inert        []string     `json:"inert_statement_ids"`
	NextPrior    any          `json:"next_prior"`
	authority    *authority
	prior        *Prior
}

func setOf(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}
func copySet(in map[string]bool) map[string]bool {
	m := map[string]bool{}
	for id, b := range in {
		if b {
			m[id] = true
		}
	}
	return m
}
func emptyCatalog(d Descriptor) *Catalog {
	raw, _ := json.Marshal(map[string]any{"format": 1, "context_id": d.ContextID, "objects": []CatalogObject{}})
	c, _ := ReadCatalog(d, raw)
	return c
}

// Project reads a coherent private prior plus untrusted candidates. Admission
// tests use the frozen prior issuer set; newly supplied grants never form an
// intra-batch issuer-authority fixed point.
func Project(d Descriptor, priorRaw, candidateRaw []byte, now, operation string) (*Projection, error) {
	if operation != "read" && operation != "fresh" && operation != "repair" {
		return nil, invalid()
	}
	prior, e := readPrior(d, priorRaw)
	if e != nil {
		return nil, e
	}
	guard := "-"
	if prior != nil {
		guard = prior.ClockGuard
	}
	decision, e := DecisionTime(now, guard)
	if e != nil {
		return nil, e
	}
	at, _ := stamp(decision)
	c := emptyCatalog(d)
	if prior != nil {
		c = prior.catalog
	}
	if operation == "read" {
		if string(candidateRaw) != "-" {
			return nil, invalid()
		}
	} else {
		candidate, e := ReadCatalog(d, candidateRaw)
		if e != nil {
			return nil, e
		}
		c, e = UnionCatalog(d, c, candidate)
		if e != nil {
			return nil, e
		}
	}
	g := newGraph(d, c)
	origins := map[string]*migrationValidation{}
	originKeys := map[string]bool{}
	for _, m := range c.Migrations {
		origin, e := verifyMigrationOrigin(d, m)
		if e != nil {
			return nil, e
		}
		// Same proposal with two independently valid prepared sets is still
		// competing complete origin evidence, never a last-map-entry winner.
		origins[m.Proposal.ID+"/"+digest(m.PreparedCatalog)] = origin
		g.migrationRoots[origin.root.ID] = true
		if g.migrationHosts[m.Proposal.ID] == nil {
			g.migrationHosts[m.Proposal.ID] = map[string]bool{}
		}
		for id, s := range origin.prepared.Statements {
			if s.Kind == "host_lease" && s.Lease.Operation == m.Proposal.ID {
				g.migrationHosts[m.Proposal.ID][id] = true
			}
		}
	}
	if e = g.prepareConsent(); e != nil {
		return nil, e
	}
	statementIDs := make([]string, 0, len(c.Statements))
	for id := range c.Statements {
		statementIDs = append(statementIDs, id)
	}
	sort.Strings(statementIDs)
	for _, id := range statementIDs {
		if e = g.validate(id); e != nil {
			return nil, e
		}
	}
	if e = g.validateAliases(); e != nil {
		return nil, e
	}
	admitted, restrictions, activations := map[string]bool{}, map[string]bool{}, map[string]bool{}
	if prior != nil {
		admitted = setOf(prior.AdmittedStatements)
		restrictions = setOf(prior.AdmittedRestrictions)
		activations = setOf(prior.AdmittedActivations)
	}
	oldIssuerIDs := copySet(admitted)
	// Root transitions have their own all-branch signatures and structural
	// equivocation rule; retired roots cannot use this exception for ordinary work.
	if operation != "read" {
		for changed := true; changed; {
			changed = false
			for _, id := range statementIDs {
				s := c.Statements[id]
				if s.Root == nil || admitted[id] || s.issuedTime().After(at) {
					continue
				}
				if s.Root.Migration != "-" {
					origin := matchingMigrationOrigin(origins, s)
					if origin == nil || origin.root.ID != s.ID {
						continue
					}
				}
				complete := true
				for _, parent := range s.Root.Predecessors {
					if !admitted[parent] {
						complete = false
						break
					}
				}
				if !complete {
					continue
				}
				admitted[id] = true
				changed = true
			}
		}
	}
	a := &authority{graph: g, now: at, admitted: admitted, restrictions: restrictions, heads: headsFor(g, admitted), maxima: map[string]uint64{}, active: map[string]bool{}}
	for key, origin := range origins {
		if admitted[origin.root.ID] {
			originKeys[key] = true
		}
	}
	for id := range admitted {
		if s := c.Statements[id]; s != nil && s.Root != nil && s.Root.Migration == "-" && len(s.Root.Predecessors) == 0 {
			originKeys["genesis"] = true
		}
	}
	a.originConflict = len(originKeys) > 1
	preserveHeads(a, prior)
	if prior != nil {
		for _, maximum := range prior.Maxima {
			a.maxima[streamKey(maximum.Stream)] = maximum.Sequence
		}
	}
	if operation != "read" {
		// Ordinary root facts have no delegated issuer parents. Operation-bound
		// admissions are held for the complete current consent group below.
		for _, id := range statementIDs {
			s := c.Statements[id]
			if admitted[id] || s.Lease == nil || s.Lease.Issuer.Kind != "root" || s.Lease.Operation != "-" {
				continue
			}
			if e := candidateWindow(s, at); e != nil {
				continue
			}
			if e := a.checkRestrictions(s, nil); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			if _, e := a.issuer(s, true); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			admitted[id] = true
		}
		a.heads = headsFor(g, admitted)
		preserveHeads(a, prior)
		// All restriction admission decisions see the immutable prior restrictions.
		// Their admitted union is enforced before any positive candidate is used.
		newRestrictions := copySet(restrictions)
		for _, origin := range origins {
			if origin.root.issuedTime().After(at) {
				continue
			}
			for id, s := range origin.prepared.Statements {
				if s.Restriction != nil {
					newRestrictions[id] = true
				}
			}
		}
		for _, id := range statementIDs {
			s := c.Statements[id]
			if s.Restriction == nil || restrictions[id] || s.issuedTime().After(at) {
				continue
			}
			if !issuerPreviouslyAdmitted(s, oldIssuerIDs) {
				continue
			}
			if _, e := a.issuer(s, true); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			newRestrictions[id] = true
			if s.Restriction.Ratifies != "-" {
				newRestrictions[s.Restriction.Ratifies] = true
			}
		}
		restrictions = newRestrictions
		a.restrictions = restrictions
		for id := range admitted {
			if oldIssuerIDs[id] {
				continue
			}
			if e := a.checkRestrictions(c.Statements[id], nil); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				delete(admitted, id)
			}
		}
		preserveHeads(a, prior)
		for _, id := range statementIDs {
			s := c.Statements[id]
			if admitted[id] || s.Lease == nil && s.Access == nil || s.Lease != nil && s.Lease.Operation != "-" {
				continue
			}
			if e := candidateWindow(s, at); e != nil {
				continue
			}
			if !issuerPreviouslyAdmitted(s, oldIssuerIDs) {
				continue
			}
			if e := a.checkRestrictions(s, nil); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			if _, e := a.issuer(s, true); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			if e := directParentsCurrent(a, s); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			admitted[id] = true
		}
		a.heads = headsFor(g, admitted)
		preserveHeads(a, prior)
		for _, origin := range origins {
			if origin.root.issuedTime().After(at) {
				continue
			}
			grants, e := migrationCurrentGrants(a, origin)
			if e != nil {
				return nil, e
			}
			for _, id := range grants {
				admitted[id] = true
			}
		}
		preserveHeads(a, prior)
		grants, e := activationAdmissions(a)
		if e != nil {
			return nil, e
		}
		for _, grant := range grants {
			admitted[grant] = true
		}
		for id := range c.Activations {
			// This records exact complete consent only; each selected statement
			// above independently proves its current authority before admission.
			activations[id] = true
		}
		a.heads = headsFor(g, admitted)
		preserveHeads(a, prior)
		// Exact portable retention is a separate signed admission basis. Each
		// decision sees the same admitted retainers, not another loop's newly
		// admitted child as a source of independent issuer authority.
		retained := map[string]bool{}
		for _, id := range statementIDs {
			if admitted[id] {
				continue
			}
			s := c.Statements[id]
			if s.Lease == nil && s.Access == nil {
				continue
			}
			closure, e := portableAdmission(a, s)
			if e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			for _, id := range closure {
				retained[id] = true
			}
		}
		for id := range retained {
			admitted[id] = true
			s := c.Statements[id]
			if s != nil && s.Lease != nil && s.Lease.Operation != "-" {
				if activation := g.activated[s.Lease.Operation]; activation != nil {
					activations[activation.ID] = true
				}
			}
		}
		a.heads = headsFor(g, admitted)
		preserveHeads(a, prior)
	}
	projection := &Projection{OK: true, ContextID: d.ContextID, DecisionTime: decision, Streams: []StreamView{}, Restrictions: keysSorted(restrictions), Inert: []string{}, authority: a, prior: prior}
	maxima := buildMaxima(g, admitted, prior)
	if operation != "read" {
		maxima = migrationFloors(maxima, origins, at)
	}
	a.maxima = map[string]uint64{}
	for _, m := range maxima {
		a.maxima[streamKey(m.Stream)] = m.Sequence
	}
	rootMax := uint64(0)
	for _, m := range maxima {
		if m.Stream[0] == "root" {
			rootMax = m.Sequence
		}
	}
	rootIDs := append([]string{}, a.heads["root"]...)
	projection.Root = RootView{rootIDs, rootMax, "-", len(rootIDs) > 1 || a.originConflict, "-", []string{}}
	if a.originConflict {
		projection.Root.Code = "state_conflict"
	} else if len(rootIDs) == 1 {
		projection.Root.SelectedID = rootIDs[0]
		root, e := g.get(rootIDs[0])
		if e != nil {
			projection.Root.Code = Code(e)
			projection.Root.RequiredIDs = RequiredIDs(e)
		} else if _, e = a.evaluate(root); e != nil {
			projection.Root.Code = Code(e)
			projection.Root.RequiredIDs = RequiredIDs(e)
		}
	} else if len(rootIDs) > 1 {
		projection.Root.Code = "state_conflict"
	} else {
		projection.Root.Code = "proof_required"
	}
	for _, m := range maxima {
		if m.Stream[0] == "root" {
			continue
		}
		row := StreamView{Stream: m.Stream, HeadIDs: append([]string{}, a.heads[streamKey(m.Stream)]...), Maximum: m.Sequence, SelectedID: "-", Code: "-", RequiredIDs: []string{}}
		if len(row.HeadIDs) > 1 {
			row.Code = "state_conflict"
		} else if len(row.HeadIDs) == 0 {
			row.Code = "proof_required"
		} else {
			row.SelectedID = row.HeadIDs[0]
			s, e := g.get(row.SelectedID)
			if e != nil {
				row.Code = Code(e)
				row.RequiredIDs = RequiredIDs(e)
			} else if _, e = a.evaluate(s); e != nil {
				row.Code = Code(e)
				row.RequiredIDs = RequiredIDs(e)
			} else {
				row.Active = true
			}
		}
		projection.Streams = append(projection.Streams, row)
	}
	for _, id := range statementIDs {
		s := c.Statements[id]
		if !admitted[id] && !restrictions[id] && (len(s.stream()) > 0 || s.Restriction != nil) {
			projection.Inert = append(projection.Inert, id)
		}
	}
	if operation == "read" {
		if prior == nil {
			projection.NextPrior = "-"
		} else {
			projection.NextPrior = json.RawMessage(prior.Raw)
		}
		return projection, nil
	}
	migration := "-"
	if prior != nil {
		migration = prior.Migration
	} else if len(origins) == 1 && len(originKeys) == 1 {
		for _, origin := range origins {
			if !origin.root.issuedTime().After(at) {
				migration = origin.migration.Proposal.ID
			}
		}
	}
	next := &Prior{Format: 1, ContextID: d.ContextID, CatalogBase64: b64(c.Raw), AdmittedStatements: keysSorted(admitted), AdmittedRestrictions: keysSorted(restrictions), AdmittedActivations: keysSorted(activations), RootHeads: rootIDs, Maxima: maxima, Migration: migration, ClockGuard: decision, catalog: c}
	projection.NextPrior = next
	return projection, nil
}
func issuerPreviouslyAdmitted(s *Statement, prior map[string]bool) bool {
	for _, p := range s.parents() {
		if strings.HasPrefix(p.Role, "issuer_") && !prior[p.ID] {
			return false
		}
	}
	return true
}
func candidateWindow(s *Statement, now time.Time) error {
	if s.issuedTime().After(now) {
		return failure("not_yet_valid")
	}
	if s.Lease != nil {
		return atTime(s.Lease.Before, s.Lease.After, now, false)
	}
	if s.Access != nil {
		return atTime(s.Access.Before, s.Access.After, now, true)
	}
	return nil
}
func directParentsCurrent(a *authority, s *Statement) error {
	for _, p := range s.parents() {
		parent, e := a.graph.get(p.ID)
		if e != nil {
			return e
		}
		// Preserve a concrete complete-proof denial before an empty head
		// lookup can mask it. Nonadmission alone is not evidence that every
		// required current dependency is present or independently forbidden.
		if !a.admitted[parent.ID] {
			if e = candidateWindow(parent, a.now); e != nil {
				return e
			}
			if e = a.carriedByRoot(parent); e != nil {
				return e
			}
			if e = a.checkRestrictions(parent, nil); e != nil {
				return e
			}
		}
		head, e := a.selected(parent.stream())
		if e != nil {
			return e
		}
		if head.ID != p.ID {
			return failure("forbidden")
		}
		if _, e = a.evaluate(parent); e != nil {
			return e
		}
	}
	return nil
}
func preserveHeads(a *authority, p *Prior) { a.heads = admissionHeads(a.graph, a.admitted, p) }

// admissionHeads starts with the caller's exact remembered heads. Recomputing
// only from available bodies would resurrect an old admitted predecessor when
// the real selected head's bytes are temporarily missing.
func admissionHeads(g *graph, admitted map[string]bool, p *Prior) map[string][]string {
	heads := map[string][]string{}
	previous := map[string]bool{}
	if p != nil {
		previous = setOf(p.AdmittedStatements)
		for _, m := range p.Maxima {
			heads[streamKey(m.Stream)] = append([]string{}, m.HeadIDs...)
		}
	}
	fresh := map[string]bool{}
	for id := range admitted {
		if !previous[id] {
			fresh[id] = true
		}
	}
	return advanceHeads(g, heads, fresh)
}
func advanceHeads(g *graph, base map[string][]string, added map[string]bool) map[string][]string {
	heads := map[string][]string{}
	for key, ids := range base {
		heads[key] = append([]string{}, ids...)
	}
	for id := range added {
		s := g.catalog.Statements[id]
		if s == nil || len(s.stream()) == 0 {
			continue
		}
		key := streamKey(s.stream())
		if !contains(heads[key], id) {
			heads[key] = append(heads[key], id)
		}
	}
	for key, ids := range heads {
		maximal := []string{}
		for _, id := range ids {
			dominated := false
			for _, other := range ids {
				if id != other && g.descends(other, id) {
					dominated = true
					break
				}
			}
			if !dominated {
				maximal = append(maximal, id)
			}
		}
		sort.Strings(maximal)
		heads[key] = maximal
	}
	return heads
}

func buildMaxima(g *graph, admitted map[string]bool, p *Prior) []Maximum {
	maxima := map[string]Maximum{}
	if p != nil {
		for _, m := range p.Maxima {
			maxima[streamKey(m.Stream)] = Maximum{Stream: append([]string{}, m.Stream...), Sequence: m.Sequence, StatementIDs: append([]string{}, m.StatementIDs...), HeadIDs: append([]string{}, m.HeadIDs...)}
		}
	}
	for id := range admitted {
		s := g.catalog.Statements[id]
		if s == nil || len(s.stream()) == 0 {
			continue
		}
		key := streamKey(s.stream())
		m, ok := maxima[key]
		if !ok || s.sequence() > m.Sequence {
			m = Maximum{Stream: s.stream(), Sequence: s.sequence(), StatementIDs: []string{id}, HeadIDs: []string{}}
		} else if s.sequence() == m.Sequence && !contains(m.StatementIDs, id) {
			m.StatementIDs = append(m.StatementIDs, id)
		}
		sort.Strings(m.StatementIDs)
		maxima[key] = m
	}
	heads := admissionHeads(g, admitted, p)
	for k, m := range maxima {
		m.HeadIDs = append([]string{}, heads[k]...)
		maxima[k] = m
	}
	out := make([]Maximum, 0, len(maxima))
	for _, m := range maxima {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return compareStreams(out[i].Stream, out[j].Stream) < 0 })
	return out
}

func matchingMigrationOrigin(origins map[string]*migrationValidation, root *Statement) *migrationValidation {
	for _, origin := range origins {
		if origin.migration.Proposal.ID == root.Root.Migration && origin.root.ID == root.ID {
			return origin
		}
	}
	return nil
}
