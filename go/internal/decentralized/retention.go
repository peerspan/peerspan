package decentralized

import "time"

// portableAdmission admits only exact already signed finite grants endorsed by
// a currently usable signed retainer. It does not run a grant-as-issuer fixed
// point: the retainer is independently admitted first, and every old original
// signature/consent/ceiling and intervening retention remains required.
func portableAdmission(a *authority, s *Statement) ([]string, error) {
	if a.graph.pendingAdmissions[s.ID] != "" {
		return nil, failure("forbidden")
	}
	if s.Lease == nil && s.Access == nil {
		return nil, failure("forbidden")
	}
	if e := candidateWindow(s, a.now); e != nil {
		return nil, e
	}
	endorsed := false
	for _, heads := range a.heads {
		if len(heads) != 1 {
			continue
		}
		retainer := a.graph.catalog.Statements[heads[0]]
		if retainer == nil || !contains(retainer.retained(), s.ID) {
			continue
		}
		if _, e := a.evaluate(retainer); e != nil {
			continue
		}
		endorsed = true
		break
	}
	if !endorsed {
		return nil, failure("forbidden")
	}
	closure := map[string]bool{}
	busy := map[string]bool{}
	var collect func(*Statement) error
	collect = func(node *Statement) error {
		if busy[node.ID] {
			return invalid()
		}
		if closure[node.ID] {
			return nil
		}
		busy[node.ID] = true
		defer delete(busy, node.ID)
		if node.Lease == nil && node.Access == nil && node.Root == nil {
			return invalid()
		}
		closure[node.ID] = true
		refs := append([]string{}, node.predecessors()...)
		if node.rootID() != "" {
			refs = append(refs, node.rootID())
		}
		for _, p := range node.parents() {
			refs = append(refs, p.ID)
		}
		for _, id := range refs {
			parent, e := a.graph.get(id)
			if e != nil {
				return e
			}
			if e = collect(parent); e != nil {
				return e
			}
		}
		return nil
	}
	if e := collect(s); e != nil {
		return nil, e
	}
	proofView := *a
	proofView.firstAdmissions = a.admitted
	proofView.allowPortable = true
	proofView.admitted = copySet(a.admitted)
	eligible := map[string]bool{}
	for id := range closure {
		if a.graph.pendingAdmissions[id] == "" && candidateWindow(a.graph.catalog.Statements[id], a.now) == nil {
			proofView.admitted[id] = true
			eligible[id] = true
		}
	}
	proofView.heads = advanceHeads(a.graph, a.heads, eligible)
	proofView.proven = map[string]bool{}
	if _, e := proofView.evaluate(s); e != nil {
		return nil, e
	}
	return keysSorted(proofView.proven), nil
}

// portableIssuance distinguishes a previously issued exact child from a fresh
// request for its old nominal mask. Current issuance remains available without
// this exception; only historical delegation/mask power needs this witness.
func (a *authority) portableIssuance(child *Statement, busy map[string]bool) bool {
	marker := "portable:" + child.ID
	if busy[marker] {
		return false
	}
	busy[marker] = true
	defer delete(busy, marker)
	if a.portableCarries(child, busy) != nil {
		return false
	}
	for _, stream := range keysSortedHeads(a.heads) {
		heads := a.heads[stream]
		if len(heads) != 1 {
			continue
		}
		head := a.graph.catalog.Statements[heads[0]]
		if head == nil || a.firstAdmissions == nil || !a.firstAdmissions[head.ID] || !contains(head.retained(), child.ID) {
			continue
		}
		if _, e := a.evaluateContents(head, nil, busy, false); e != nil {
			continue
		}
		for _, pred := range head.predecessors() {
			if !a.graph.relatedContribution(child, pred, map[string]bool{}) {
				continue
			}
			old, e := a.graph.get(pred)
			if e != nil {
				continue
			}
			if head.Root != nil {
				if a.portableRootCover(old.ID, child) != nil {
					continue
				}
			} else if _, e = a.retainedHead(old, child, head, busy); e != nil {
				continue
			}
			if a.originalIssuanceAt(child, head.issuedTime(), map[string]bool{}) == nil {
				return true
			}
		}
	}
	return false
}

func keysSortedHeads(heads map[string][]string) []string {
	m := map[string]bool{}
	for k := range heads {
		m[k] = true
	}
	return keysSorted(m)
}

func (a *authority) portableRootCover(old string, child *Statement) error {
	root, e := a.root()
	if e != nil {
		return e
	}
	path, e := a.retentionPath(root, old, map[string]bool{})
	if e != nil {
		return e
	}
	for _, edge := range path {
		if edge.Root == nil || !contains(edge.Root.Retained, child.ID) || candidateWindow(child, edge.issuedTime()) != nil {
			return failure("forbidden")
		}
	}
	return nil
}

func (a *authority) portableCarries(child *Statement, busy map[string]bool) error {
	if e := a.portableRootCover(child.rootID(), child); e != nil {
		return e
	}
	seen := map[string]bool{}
	var visit func(*Statement, bool) error
	visit = func(parent *Statement, keptAdmin bool) error {
		if seen[parent.ID] {
			return nil
		}
		seen[parent.ID] = true
		if !keptAdmin {
			head, e := a.selected(parent.stream())
			if e != nil {
				return e
			}
			if head.ID != parent.ID {
				if _, e = a.retainedHead(parent, child, head, busy); e != nil {
					return e
				}
			}
		}
		if e := a.portableRootCover(parent.rootID(), child); e != nil {
			return e
		}
		for _, ref := range parent.parents() {
			node, e := a.graph.get(ref.ID)
			if e != nil {
				return e
			}
			kept := false
			if ref.Role == "issuer_admin" && (parent.Kind == "person_lease" || parent.Kind == "host_lease") {
				for id := range a.restrictions {
					r := a.graph.catalog.Statements[id]
					if r != nil && r.Kind == "admin_withdraw" && r.Restriction.Target.Statement == node.ID && contains(r.Restriction.Kept, parent.ID) {
						kept = true
					}
				}
			}
			if e = visit(node, kept); e != nil {
				return e
			}
		}
		return nil
	}
	for _, ref := range child.parents() {
		node, e := a.graph.get(ref.ID)
		if e != nil {
			return e
		}
		if e = visit(node, false); e != nil {
			return e
		}
	}
	return nil
}

// Original role/window checks run at the fixed signed carrying transition.
// They follow typed parents and actual complete packet issuers, never a
// retention list, and supply none of those old keys with fresh signing power.
func (a *authority) originalIssuanceAt(s *Statement, at time.Time, seen map[string]bool) error {
	if seen[s.ID] {
		return nil
	}
	seen[s.ID] = true
	if candidateWindow(s, at) != nil {
		return failure("forbidden")
	}
	if s.rootID() != "" {
		root, e := a.graph.get(s.rootID())
		if e != nil {
			return e
		}
		if root.issuedTime().After(at) {
			return failure("forbidden")
		}
	}
	for _, ref := range s.parents() {
		parent, e := a.graph.get(ref.ID)
		if e != nil {
			return e
		}
		if ref.Role == "issuer_device" {
			need := neededScope(s)
			if parent.Lease == nil || parent.Lease.Subject.Scopes&need != need {
				return failure("forbidden")
			}
			if s.Kind == "device_lease" && s.Lease.Subject.Scopes & ^parent.Lease.Subject.Scopes != 0 {
				return failure("forbidden")
			}
		}
		if e = a.originalIssuanceAt(parent, at, seen); e != nil {
			return e
		}
	}
	if s.Kind == "device_lease" {
		activation := a.graph.activated[s.Lease.Operation]
		if activation == nil || stringField(activation.Manifest, "device_lease_id") != s.ID {
			return failure("proof_required", s.Lease.Operation)
		}
		if activation.Owner.Issuer != "-" && stringField(activation.Request.Object, "mode") == "renew" {
			old := stringField(activation.Request.Object, "renewed_device_lease_id")
			if !a.strictDeviceAncestor(activation.Owner.Issuer, old, map[string]bool{}) {
				return failure("forbidden")
			}
		}
		for _, packet := range []*Packet{activation.Owner, activation.Administrator} {
			if packet == nil {
				continue
			}
			refs, e := a.graph.packetIssuerRefs(packet)
			if e != nil {
				return e
			}
			for _, ref := range refs {
				if ref.Kind == "device_lease" {
					need := uint64(8)
					if packet.Role == "owner" {
						need = 4
						if !isString(activation.Finalization.Object["binding_lease"]) {
							need |= 2
						}
					}
					if ref.Lease.Subject.Scopes&need != need {
						return failure("forbidden")
					}
				}
				if e = a.originalIssuanceAt(ref, at, seen); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
