package decentralized

// activationAdmissions uses only the selected grants and the actual issuer
// ancestry of complete reviewed ceremonies. The provisional proof view is
// private and scoped to that finite closure; it never admits an unrelated
// ordinary candidate as an issuer. Complete consent and current component
// authority are deliberately independent.
func activationAdmissions(a *authority) ([]string, error) {
	accepted := map[string]bool{}
	for _, activation := range a.graph.catalog.Activations {
		for _, field := range []string{"person_lease_id", "host_lease_id", "binding_lease_id", "device_lease_id"} {
			s, e := a.graph.get(stringField(activation.Manifest, field))
			if e != nil {
				return nil, e
			}
			if a.admitted[s.ID] {
				continue
			}
			closure, e := activationComponentClosure(a, s)
			if e != nil {
				if Code(e) == "forbidden" || Code(e) == "authority_expired" {
					continue
				}
				return nil, e
			}
			view := *a
			view.admitted = copySet(a.admitted)
			eligible := map[string]bool{}
			for id := range closure {
				node := a.graph.catalog.Statements[id]
				if candidateWindow(node, a.now) == nil {
					view.admitted[id] = true
					eligible[id] = true
				}
			}
			view.heads = advanceHeads(a.graph, a.heads, eligible)
			view.proven = map[string]bool{}
			view.firstAdmissions = a.admitted
			// Ignore only this candidate's own selection, so independently
			// authorized competing heads are retained as a fork. Every parent
			// still requires a unique current head or exact retention.
			if _, e = view.evaluateContents(s, nil, map[string]bool{}, true); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				continue
			}
			for id := range view.proven {
				accepted[id] = true
			}
		}
	}
	// All independently verified branches now share one current view. A newly
	// learned conflicting/narrower parent cannot supply child power through a
	// per-component scratch view. Prior admitted history remains durable.
	for {
		view := *a
		view.admitted = copySet(a.admitted)
		for id := range accepted {
			view.admitted[id] = true
		}
		view.heads = advanceHeads(a.graph, a.heads, accepted)
		view.firstAdmissions = a.admitted
		remove := []string{}
		for id := range accepted {
			if a.admitted[id] {
				continue
			}
			s := a.graph.catalog.Statements[id]
			if _, e := view.evaluateContents(s, nil, map[string]bool{}, true); e != nil {
				if Code(e) == "proof_required" {
					return nil, e
				}
				remove = append(remove, id)
			}
		}
		if len(remove) == 0 {
			break
		}
		for _, id := range remove {
			delete(accepted, id)
		}
	}
	return keysSorted(accepted), nil
}

func activationComponentClosure(a *authority, s *Statement) (map[string]bool, error) {
	closure, busy := map[string]bool{}, map[string]bool{}
	var visit func(*Statement) error
	visit = func(node *Statement) error {
		if busy[node.ID] {
			return invalid()
		}
		if closure[node.ID] || a.admitted[node.ID] {
			return nil
		}
		busy[node.ID] = true
		defer delete(busy, node.ID)
		if node.Lease == nil && node.Root == nil {
			return invalid()
		}
		if node.Lease != nil && node.Lease.Operation != "-" {
			activation := a.graph.activated[node.Lease.Operation]
			if activation == nil {
				return failure("proof_required", node.Lease.Operation)
			}
			if node.Kind == "device_lease" && activation.Owner.Issuer != "-" && stringField(activation.Request.Object, "mode") == "renew" {
				old := stringField(activation.Request.Object, "renewed_device_lease_id")
				if !a.strictDeviceAncestor(activation.Owner.Issuer, old, map[string]bool{}) {
					return failure("forbidden")
				}
			}
			if node.Kind == "device_lease" {
				for _, packet := range []*Packet{activation.Owner, activation.Administrator} {
					if packet == nil {
						continue
					}
					refs, e := a.graph.packetIssuerRefs(packet)
					if e != nil {
						return e
					}
					for _, ref := range refs {
						if e = visit(ref); e != nil {
							return e
						}
					}
				}
			}
		}
		closure[node.ID] = true
		for _, p := range node.parents() {
			parent, e := a.graph.get(p.ID)
			if e != nil {
				return e
			}
			if e = visit(parent); e != nil {
				return e
			}
		}
		return nil
	}
	if e := visit(s); e != nil {
		return nil, e
	}
	return closure, nil
}

func activationPacketAuthority(a *authority, activation *ParsedActivation, target *Statement, busy map[string]bool) error {
	if target.Kind == "device_lease" && activation.Owner.Issuer != "-" && stringField(activation.Request.Object, "mode") == "renew" {
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
			if e := candidateWindow(ref, a.now); e != nil {
				return e
			}
			if e := a.checkRestrictions(ref, target); e != nil {
				return e
			}
			path, e := a.evaluateFor(ref, target, busy)
			if e != nil {
				return e
			}
			if ref.Kind != "device_lease" {
				continue
			}
			need := uint64(8)
			if packet.Role == "owner" {
				need = 4
				if !isString(activation.Finalization.Object["binding_lease"]) {
					need |= 2
				}
			}
			if path.Scopes&need != need {
				return failure("forbidden")
			}
		}
	}
	return nil
}
func stringsIssuerRole(role string) bool {
	return role == "issuer_person" || role == "issuer_admin" || role == "issuer_device"
}
