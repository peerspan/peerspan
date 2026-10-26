package decentralized

import (
	"sort"
	"time"
)

type authorityResult struct {
	Scopes uint64
	After  string
}

// authority evaluates one admitted view. Its sets are constructed from verified
// prior/admission results, never accepted from a public catalog's metadata.
type authority struct {
	retentionContext string
	graph            *graph
	now              time.Time
	admitted         map[string]bool
	restrictions     map[string]bool
	heads            map[string][]string
	maxima           map[string]uint64
	active           map[string]bool
	proven           map[string]bool
	firstAdmissions  map[string]bool
	allowPortable    bool
	originConflict   bool
}

func (a *authority) selected(stream []string) (*Statement, error) {
	h := a.heads[streamKey(stream)]
	if len(h) > 1 {
		return nil, failure("state_conflict")
	}
	if len(h) == 0 {
		return nil, failure("proof_required")
	}
	s, e := a.graph.get(h[0])
	if e != nil {
		return nil, e
	}
	if maximum, ok := a.maxima[streamKey(stream)]; ok && s.sequence() < maximum {
		return nil, failure("proof_required")
	}
	return s, nil
}
func (a *authority) root() (*Statement, error) {
	if a.originConflict {
		return nil, failure("state_conflict")
	}
	return a.selected([]string{"root"})
}
func minAfter(a, b string) string {
	if a == "-" || a == "" {
		return b
	}
	if b == "-" || b == "" {
		return a
	}
	if a < b {
		return a
	}
	return b
}
func neededScope(s *Statement) uint64 {
	switch s.Kind {
	case "policy":
		return 1
	case "binding_lease", "host_unbind":
		return 2
	case "device_lease", "device_revoke":
		return 4
	case "person_lease", "host_lease", "group", "person_remove", "host_revoke":
		return 8
	}
	return 0
}
func (a *authority) evaluate(s *Statement) (authorityResult, error) {
	return a.evaluateFor(s, nil, map[string]bool{})
}
func (a *authority) evaluateFor(s, consumer *Statement, busy map[string]bool) (authorityResult, error) {
	return a.evaluateContents(s, consumer, busy, false)
}
func (a *authority) evaluateContents(s, consumer *Statement, busy map[string]bool, predecessorCheck bool) (result authorityResult, err error) {
	result = authorityResult{After: "-"}
	defer func() {
		if err == nil && a.proven != nil {
			a.proven[s.ID] = true
		}
	}()
	if !a.admitted[s.ID] {
		return result, failure("forbidden")
	}
	key := a.retentionContext + "/" + s.ID
	if consumer != nil {
		key += "/" + consumer.ID
	}
	if busy[key] {
		return result, failure("forbidden")
	}
	busy[key] = true
	defer delete(busy, key)
	if s.Root != nil {
		root, e := a.root()
		if e != nil {
			return result, e
		}
		if root.ID != s.ID {
			return result, failure("forbidden")
		}
		if s.issuedTime().After(a.now) {
			return result, failure("not_yet_valid")
		}
		return result, nil
	}
	if s.Restriction != nil {
		return result, failure("forbidden")
	}
	if s.Lease == nil && s.Access == nil {
		return result, failure("forbidden")
	}
	if s.Lease != nil {
		result.Scopes = s.Lease.Subject.Scopes
		result.After = s.Lease.After
		if e := atTime(s.Lease.Before, s.Lease.After, a.now, false); e != nil {
			return result, e
		}
	}
	if s.Access != nil {
		result.After = s.Access.After
		if e := atTime(s.Access.Before, s.Access.After, a.now, true); e != nil {
			return result, e
		}
	}
	if e := a.checkRestrictions(s, consumer); e != nil {
		return result, e
	}
	if !predecessorCheck {
		head, e := a.selected(s.stream())
		if e != nil {
			return result, e
		}
		if head.ID != s.ID {
			if consumer == nil {
				return result, failure("forbidden")
			}
			extra, e := a.retainedHead(s, consumer, head, busy)
			if e != nil {
				return result, e
			}
			result.After = minAfter(result.After, extra.After)
			if s.Kind == "device_lease" {
				result.Scopes &= extra.Scopes
			}
		}
	}
	if e := a.carriedByRoot(s); e != nil {
		return result, e
	}
	previousDevice := a.firstAdmissions == nil || a.firstAdmissions[s.ID]
	if s.Kind == "device_lease" && !previousDevice && a.allowPortable {
		previousDevice = a.portableIssuance(s, busy)
	}
	if l := s.Lease; l != nil && l.Operation != "-" {
		if identifier(l.Operation, "ds_") {
			if s.Kind != "host_lease" || !a.graph.migrationHosts[l.Operation][s.ID] {
				return result, failure("proof_required", l.Operation)
			}
		} else {
			activation := a.graph.activated[l.Operation]
			if activation == nil {
				return result, failure("proof_required", l.Operation)
			}
			field := map[string]string{"person_lease": "person_lease_id", "host_lease": "host_lease_id", "binding_lease": "binding_lease_id", "device_lease": "device_lease_id"}[s.Kind]
			if field == "" || stringField(activation.Manifest, field) != s.ID {
				return result, failure("forbidden")
			}
			if s.Kind == "device_lease" && !previousDevice {
				if e := activationPacketAuthority(a, activation, s, busy); e != nil {
					return result, e
				}
			}
		}
	}
	for _, p := range s.parents() {
		parent, e := a.graph.get(p.ID)
		if e != nil {
			return result, e
		}
		pr, e := a.evaluateFor(parent, s, busy)
		if e != nil {
			return result, e
		}
		result.After = minAfter(result.After, pr.After)
		if parent.Kind == "device_lease" {
			if p.Role == "issuer_device" {
				need := neededScope(s)
				if s.Kind == "device_lease" && parent.Lease.Subject.Scopes&4 == 0 {
					// Retention can preserve an already issued child's current
					// subset, but cannot supply delegation power that its exact
					// original issuer never held. This check is independent of
					// private first-admission markers and scratch-view defaults.
					return result, failure("forbidden")
				}
				if s.Kind == "device_lease" && previousDevice {
					// An existing child's issuer contribution is intersected
					// below. Losing delegation scope4 does not erase surviving
					// child powers. Fresh issuance/activation still checks4.
					need = 0
				}
				if pr.Scopes&need != need {
					return result, failure("forbidden")
				}
				if s.Kind == "device_lease" && !previousDevice && s.Lease.Subject.Scopes & ^pr.Scopes != 0 {
					return result, failure("forbidden")
				}
				if s.Kind == "device_lease" {
					// Original signed scope ceilings are checked structurally.
					// A retaining ancestor can narrow an existing descendant's
					// effective powers without discarding the surviving subset.
					result.Scopes &= pr.Scopes
				}
			}
		}
	}
	return result, nil
}
func (a *authority) retainedHead(old, consumer, head *Statement, busy map[string]bool) (authorityResult, error) {
	result := authorityResult{After: "-", Scopes: 15}
	path, e := a.retentionPath(head, old.ID, map[string]bool{})
	if e != nil {
		return result, e
	}
	for _, successor := range path {
		// A signed successor can preserve an existing contribution, never
		// pre-authorize a child whose validity has not begun at that edge.
		if candidateWindow(old, successor.issuedTime()) != nil || candidateWindow(consumer, successor.issuedTime()) != nil {
			return result, failure("forbidden")
		}
		if !contains(successor.retained(), consumer.ID) || !contains(successor.retained(), old.ID) {
			return result, failure("forbidden")
		}
		if successor.Lease == nil || !sameSubjectContribution(old, successor) {
			return result, invalid()
		}
		if e := atTime(successor.Lease.Before, successor.Lease.After, a.now, false); e != nil {
			return result, e
		}
		if e := a.checkRestrictions(successor, nil); e != nil {
			return result, e
		}
		marker := "retention:" + successor.ID
		if busy[marker] {
			return result, failure("forbidden")
		}
		busy[marker] = true
		before, e := a.beforeReplacement(successor)
		if e != nil {
			return result, e
		}
		current, e := before.evaluateContents(successor, nil, busy, true)
		delete(busy, marker)
		if e != nil {
			return result, e
		}
		result.After = minAfter(result.After, current.After)
		result.After = minAfter(result.After, successor.Lease.After)
		if successor.Kind == "device_lease" {
			result.Scopes &= current.Scopes
		}
	}
	return result, nil
}
func sameSubjectContribution(a, b *Statement) bool {
	if a.Kind != b.Kind || !equalStrings(a.stream(), b.stream()) || a.Lease == nil || b.Lease == nil {
		return false
	}
	x, y := a.Lease.Subject, b.Lease.Subject
	return x.Person == y.Person && x.Host == y.Host && x.Device == y.Device
}
func (a *authority) retentionPath(head *Statement, old string, busy map[string]bool) ([]*Statement, error) {
	// Every relevant resolved branch must carry the old contribution. Visit
	// shared ancestors once rather than enumerating all paths through a DAG.
	result := []*Statement{}
	seen := map[string]bool{}
	var visit func(*Statement) error
	visit = func(node *Statement) error {
		if node.ID == old {
			return nil
		}
		if busy[node.ID] {
			return invalid()
		}
		if seen[node.ID] {
			return nil
		}
		busy[node.ID] = true
		defer delete(busy, node.ID)
		seen[node.ID] = true
		result = append(result, node)
		found := false
		for _, id := range node.predecessors() {
			if !a.admitted[id] {
				continue
			}
			parent, e := a.graph.get(id)
			if e != nil {
				return e
			}
			if parent.ID == old || a.graph.descends(parent.ID, old) {
				found = true
				if e = visit(parent); e != nil {
					return e
				}
			}
		}
		if !found {
			return failure("forbidden")
		}
		return nil
	}
	if e := visit(head); e != nil {
		return nil, e
	}
	return result, nil
}
func (a *authority) carriedByRoot(s *Statement) error {
	current, e := a.root()
	if e != nil {
		return e
	}
	if current.ID == s.rootID() {
		return nil
	}
	path, e := a.retentionPath(current, s.rootID(), map[string]bool{})
	if e != nil {
		return e
	}
	for _, successor := range path {
		if candidateWindow(s, successor.issuedTime()) != nil {
			return failure("forbidden")
		}
		if !contains(successor.Root.Retained, s.ID) {
			return failure("forbidden")
		}
	}
	return nil
}
func (a *authority) checkRestrictions(s, consumer *Statement) error {
	person, host, device := "", "", ""
	if s.Lease != nil {
		person = s.Lease.Subject.Person
		host = s.Lease.Subject.Host
		device = s.Lease.Subject.Device
	}
	if s.Access != nil {
		person = s.Access.Issuer.Person
	}
	for id := range a.restrictions {
		restriction := a.graph.catalog.Statements[id]
		if restriction == nil || restriction.Restriction == nil {
			return failure("proof_required", id)
		}
		r := restriction.Restriction
		switch restriction.Kind {
		case "person_remove":
			if person == r.Target.Person {
				return failure("forbidden")
			}
		case "host_revoke":
			if host == r.Target.Host {
				return failure("forbidden")
			}
		case "device_revoke":
			if person == r.Target.Person && device == r.Target.Device {
				return failure("device_revoked")
			}
		case "host_unbind":
			if s.Kind == "binding_lease" && (s.ID == r.Target.Statement || a.graph.descends(s.ID, r.Target.Statement)) && !contains(s.resolves(), id) && !a.resolvedByPredecessor(s, id, map[string]bool{}) {
				return failure("forbidden")
			}
		case "admin_withdraw":
			if s.Kind == "admin_lease" && (s.ID == r.Target.Statement || a.graph.descends(s.ID, r.Target.Statement)) && !contains(s.resolves(), id) && !a.resolvedByPredecessor(s, id, map[string]bool{}) {
				if consumer != nil && (consumer.Kind == "person_lease" || consumer.Kind == "host_lease") && contains(r.Kept, consumer.ID) {
					continue
				}
				return failure("forbidden")
			}
		}
	}
	return nil
}
func (a *authority) resolvedByPredecessor(s *Statement, restriction string, busy map[string]bool) bool {
	if busy[s.ID] {
		return false
	}
	busy[s.ID] = true
	for _, id := range s.predecessors() {
		p := a.graph.catalog.Statements[id]
		if p != nil && a.admitted[id] && (contains(p.resolves(), restriction) || a.resolvedByPredecessor(p, restriction, busy)) {
			return true
		}
	}
	return false
}
func (a *authority) issuer(s *Statement, requireCurrentRoot bool) (authorityResult, error) {
	result := authorityResult{After: "-"}
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
	root, e := a.root()
	if e != nil {
		return result, e
	}
	if requireCurrentRoot && root.ID != s.rootID() {
		return result, failure("forbidden")
	}
	if issuer.Kind == "root" {
		if s.Signer("issuer") != root.Root.Key {
			return result, failure("forbidden")
		}
		return result, nil
	}
	for _, role := range []string{"issuer_person", "issuer_admin", "issuer_device"} {
		id := parentID(s.parents(), role)
		if id == "" {
			continue
		}
		p, e := a.graph.get(id)
		if e != nil {
			return result, e
		}
		pr, e := a.evaluate(p)
		if e != nil {
			return result, e
		}
		result.After = minAfter(result.After, pr.After)
		if role == "issuer_device" {
			need := neededScope(s)
			if pr.Scopes&need != need {
				return result, failure("forbidden")
			}
			result.Scopes = pr.Scopes
		}
	}
	if s.Kind == "device_revoke" && issuer.Kind == "device" {
		signerID := parentID(s.parents(), "issuer_device")
		found := false
		for id := range a.admitted {
			target := a.graph.catalog.Statements[id]
			if target == nil || target.Kind != "device_lease" || target.Lease.Subject.Person != s.Restriction.Target.Person || target.Lease.Subject.Device != s.Restriction.Target.Device {
				continue
			}
			found = true
			if !a.strictDeviceAncestor(signerID, id, map[string]bool{}) {
				return result, failure("forbidden")
			}
		}
		if !found {
			return result, failure("proof_required")
		}
	}
	return result, nil
}
func (a *authority) strictDeviceAncestor(ancestor, target string, busy map[string]bool) bool {
	if busy[target] {
		return false
	}
	busy[target] = true
	s := a.graph.catalog.Statements[target]
	if s == nil || s.Lease == nil || s.Kind != "device_lease" {
		return false
	}
	p := parentID(s.parents(), "issuer_device")
	return p != "" && (p == ancestor || a.strictDeviceAncestor(ancestor, p, busy))
}
func headsFor(g *graph, admitted map[string]bool) map[string][]string {
	heads := map[string][]string{}
	for id := range admitted {
		s := g.catalog.Statements[id]
		if s == nil || len(s.stream()) == 0 {
			continue
		}
		k := streamKey(s.stream())
		heads[k] = append(heads[k], id)
	}
	for k, all := range heads {
		result := []string{}
		for _, id := range all {
			dominated := false
			for _, other := range all {
				if id != other && g.descends(other, id) {
					dominated = true
					break
				}
			}
			if !dominated {
				result = append(result, id)
			}
		}
		sort.Strings(result)
		heads[k] = result
	}
	return heads
}

// beforeReplacement is used only to verify a signed successor's retention
// contribution. It is never exposed as a current-head fallback for an action.
// Current restrictions, all other domains and hard deadlines remain unchanged.
func (a *authority) beforeReplacement(s *Statement) (*authority, error) {
	before := *a
	before.retentionContext = a.retentionContext + "/" + s.ID
	before.heads = map[string][]string{}
	for k, ids := range a.heads {
		before.heads[k] = append([]string{}, ids...)
	}
	before.maxima = map[string]uint64{}
	for k, v := range a.maxima {
		before.maxima[k] = v
	}
	key := streamKey(s.stream())
	before.heads[key] = append([]string{}, s.predecessors()...)
	maximum := uint64(0)
	for _, id := range s.predecessors() {
		p, e := a.graph.get(id)
		if e != nil {
			return nil, e
		}
		if p.sequence() > maximum {
			maximum = p.sequence()
		}
	}
	before.maxima[key] = maximum
	return &before, nil
}
