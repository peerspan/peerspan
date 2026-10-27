package decentralized

import "encoding/json"

// CeremonyAdmissions contains checked pending parents, not a projected grant.
// No admission, head, highwater, provider or participant outcome is produced.
type CeremonyAdmissions struct {
	Person, Host *Statement
	Root         string
}

// PrepareCeremonyAdmissions verifies the exact selected administrator stage
// before an owner signs its dependent B/D. A complete activation remains the
// only way these operation-bound components become network authority.
func (p *Projection) PrepareCeremonyAdmissions(request, owner, selection, administrator *Packet) (*CeremonyAdmissions, error) {
	if p == nil || p.authority == nil || request == nil || owner == nil || selection == nil {
		return nil, invalid()
	}
	a := p.authority
	d := a.graph.descriptor
	for _, packet := range []*Packet{request, owner, selection, administrator} {
		if packet == nil {
			continue
		}
		parsed, e := readPacket(d, packet.Raw)
		if e != nil || parsed.ID != packet.ID {
			return nil, invalid()
		}
	}
	if request.Role != "request" || owner.Role != "owner" || selection.Role != "selection" || owner.RequestID != request.RequestID || selection.RequestID != request.RequestID || stringField(owner.Object, "request_packet_id") != request.ID || stringField(selection.Object, "request_packet_id") != request.ID || stringField(selection.Object, "owner_offer_id") != owner.ID || selection.Writer != request.Writer || selection.Signer != request.Signer || selection.Person != owner.Person || stringField(owner.Object, "host_public_key") != request.Writer || stringField(owner.Object, "device_public_key") != request.Signer {
		return nil, invalid()
	}
	root, e := a.root()
	if e != nil {
		return nil, e
	}
	if a.now.Format("2006-01-02T15:04:05Z") < stringField(request.Object, "created_at") {
		return nil, failure("clock_rollback")
	}
	if a.now.Format("2006-01-02T15:04:05Z") >= stringField(request.Object, "expires_at") {
		return nil, failure("expired")
	}
	if stringField(selection.Object, "selected_at") < stringField(request.Object, "created_at") || stringField(selection.Object, "selected_at") >= stringField(request.Object, "expires_at") {
		return nil, invalid()
	}
	person, host := owner.Person, request.Writer
	result := &CeremonyAdmissions{Root: root.ID}
	if administrator == nil {
		if stringField(request.Object, "mode") != "renew" {
			return nil, invalid()
		}
		var personPath, hostPath Path
		result.Person, personPath, e = p.Current([]string{"person", person})
		if e == nil {
			result.Host, hostPath, e = p.Current([]string{"host", host})
		}
		if e != nil {
			return nil, e
		}
		if minAfter(personPath.NotAfter, hostPath.NotAfter) < stringField(owner.Object, "not_after") {
			return nil, failure("authority_expired")
		}
	} else {
		if administrator.Role != "administrator" || administrator.RequestID != request.RequestID || stringField(administrator.Object, "selection_id") != selection.ID || stringField(administrator.Object, "owner_offer_id") != owner.ID || stringField(administrator.Object, "root_state_id") != root.ID {
			return nil, invalid()
		}
		refs, e := a.graph.packetIssuerRefs(administrator)
		if e != nil {
			return nil, e
		}
		for _, ref := range refs {
			path, e := a.evaluate(ref)
			if e != nil {
				return nil, e
			}
			if ref.Kind == "device_lease" && path.Scopes&8 == 0 {
				return nil, failure("forbidden")
			}
		}
		g := *a.graph
		catalog := *g.catalog
		catalog.Statements = map[string]*Statement{}
		for id, s := range g.catalog.Statements {
			catalog.Statements[id] = s
		}
		g.catalog, g.done, g.busy = &catalog, map[string]bool{}, map[string]bool{}
		g.pendingAdmissions = map[string]string{}
		for _, s := range administrator.Statements {
			if s.Kind != "person_lease" && s.Kind != "host_lease" || s.Lease == nil || s.Lease.Operation != request.RequestID {
				return nil, invalid()
			}
			catalog.Statements[s.ID] = s
			g.pendingAdmissions[s.ID] = request.RequestID
		}
		view := *a
		view.graph = &g
		for _, entry := range []struct {
			field, kind string
			target      **Statement
		}{{"person_lease", "person_lease", &result.Person}, {"host_lease", "host_lease", &result.Host}} {
			var reference string
			if json.Unmarshal(administrator.Object[entry.field], &reference) == nil {
				s, e := g.get(reference)
				if e != nil {
					return nil, e
				}
				if s.Kind != entry.kind {
					return nil, invalid()
				}
				path, err := a.evaluate(s)
				if err != nil {
					return nil, err
				}
				if path.After < stringField(owner.Object, "not_after") {
					return nil, failure("authority_expired")
				}
				if e = candidateWindow(s, a.now); e != nil {
					return nil, e
				}
				*entry.target = s
				continue
			}
			for _, s := range administrator.Statements {
				if s.Kind == entry.kind {
					*entry.target = s
				}
			}
			s := *entry.target
			if s == nil {
				return nil, invalid()
			}
			if e = g.validate(s.ID); e != nil {
				return nil, e
			}
			if e = g.matchAdministratorIssuer(s, administrator); e != nil {
				return nil, e
			}
			if e = candidateWindow(s, a.now); e != nil {
				return nil, e
			}
			if s.rootID() != root.ID || s.Lease.After != stringField(owner.Object, "not_after") {
				return nil, failure("forbidden")
			}
			issuerPath, err := view.issuer(s, true)
			if err != nil {
				return nil, err
			}
			if issuerPath.After != "-" && s.Lease.After > issuerPath.After {
				return nil, failure("authority_expired")
			}
			if e = directParentsCurrent(&view, s); e != nil {
				return nil, e
			}
			if e = validateNextStream(&view, s); e != nil {
				return nil, e
			}
			if e = view.checkRestrictions(s, nil); e != nil {
				return nil, e
			}
		}
	}
	if result.Person.Lease.Subject.Person != person || result.Host.Lease.Subject.Host != host || result.Person.Lease.Subject.Member != stringField(owner.Object, "member") || result.Host.Lease.Subject.Member != stringField(owner.Object, "member") || result.Person.Lease.After < stringField(owner.Object, "not_after") || result.Host.Lease.After < stringField(owner.Object, "not_after") {
		return nil, failure("forbidden")
	}
	return result, nil
}

// CheckCeremonyOwnerLease checks a fixed typed B/D preparation against its
// exact checked pending admissions. The caller must separately verify the
// reviewed owner's current path; this function grants no issuer authority.
func (p *Projection) CheckCeremonyOwnerLease(s *Statement, admissions *CeremonyAdmissions, binding *Statement) error {
	if p == nil || p.authority == nil || s == nil || s.Lease == nil || admissions == nil || admissions.Person == nil || admissions.Host == nil || (s.Kind != "binding_lease" && s.Kind != "device_lease") || !identifier(s.Lease.Operation, "link_") {
		return invalid()
	}
	a := p.authority
	g := *a.graph
	catalog := *g.catalog
	catalog.Statements = map[string]*Statement{}
	for id, node := range g.catalog.Statements {
		catalog.Statements[id] = node
	}
	g.catalog, g.done, g.busy = &catalog, map[string]bool{}, map[string]bool{}
	g.pendingAdmissions = map[string]string{}
	for _, node := range []*Statement{admissions.Person, admissions.Host, binding, s} {
		if node == nil {
			continue
		}
		catalog.Statements[node.ID] = node
		if node.Lease != nil && node.Lease.Operation == s.Lease.Operation {
			g.pendingAdmissions[node.ID] = s.Lease.Operation
		}
	}
	if s.rootID() != admissions.Root {
		return failure("forbidden")
	}
	if e := g.validate(s.ID); e != nil {
		return e
	}
	if e := candidateWindow(s, a.now); e != nil {
		return e
	}
	if e := validateNextStream(a, s); e != nil {
		return e
	}
	view := *a
	view.graph = &g
	return view.checkRestrictions(s, nil)
}

type CeremonyFinalization struct {
	Admissions      *CeremonyAdmissions
	Binding, Device *Statement
	ReusedBinding   bool
}

// PrepareCeremonyFinalization verifies the completed prefix before requester
// final consent. It does not sign a binding/commit or admit any component.
// The caller separately checks the exact selected owner's current provider.
func (p *Projection) PrepareCeremonyFinalization(request, owner, selection, administrator, final *Packet) (*CeremonyFinalization, error) {
	admissions, e := p.PrepareCeremonyAdmissions(request, owner, selection, administrator)
	if e != nil {
		return nil, e
	}
	parsed, e := readPacket(p.authority.graph.descriptor, final.Raw)
	if e != nil {
		return nil, e
	}
	final = parsed
	adminID := "-"
	if administrator != nil {
		adminID = administrator.ID
	}
	if final.Role != "owner_finalization" || final.RequestID != request.RequestID || final.Person != owner.Person || final.Signer != owner.Signer || final.Issuer != owner.Issuer || final.AuthorityFormat != owner.AuthorityFormat || final.Writer != owner.Writer || stringField(final.Object, "selection_id") != selection.ID || stringField(final.Object, "administrator_offer_id") != adminID || stringField(final.Object, "root_state_id") != admissions.Root || stringField(final.Object, "person_lease_id") != admissions.Person.ID || stringField(final.Object, "host_lease_id") != admissions.Host.ID {
		return nil, invalid()
	}
	result := &CeremonyFinalization{Admissions: admissions}
	var reference string
	if json.Unmarshal(final.Object["binding_lease"], &reference) == nil {
		if stringField(request.Object, "mode") != "renew" {
			return nil, invalid()
		}
		binding, path, e := p.Current([]string{"binding", request.Writer})
		if e != nil {
			return nil, e
		}
		if binding.ID != reference || path.NotAfter < stringField(owner.Object, "not_after") {
			return nil, failure("forbidden")
		}
		result.Binding, result.ReusedBinding = binding, true
	}
	for _, s := range final.Statements {
		if s.Kind == "binding_lease" {
			result.Binding = s
		}
		if s.Kind == "device_lease" {
			result.Device = s
		}
	}
	if result.Binding == nil || result.Device == nil {
		return nil, invalid()
	}
	b, d := result.Binding, result.Device
	if b.Lease.Subject.Person != owner.Person || b.Lease.Subject.Host != request.Writer || d.Lease.Subject.Person != owner.Person || d.Lease.Subject.Host != request.Writer || d.Lease.Subject.Device != request.Signer || d.Lease.Operation != request.RequestID || d.Lease.After != stringField(owner.Object, "not_after") || parentID(d.parents(), "subject_person") != admissions.Person.ID || parentID(d.parents(), "subject_host") != admissions.Host.ID || parentID(d.parents(), "subject_binding") != b.ID {
		return nil, invalid()
	}
	scopes, _ := num(owner.Object, "scopes")
	if d.Lease.Subject.Scopes != scopes {
		return nil, invalid()
	}
	ownerP := stringField(owner.Object, "person_lease_id")
	if ownerP == "-" {
		ownerP = admissions.Person.ID
	}
	for _, s := range []*Statement{b, d} {
		if s == b && result.ReusedBinding {
			continue
		}
		if s.Lease.Operation != request.RequestID || s.Signer("issuer") != final.Signer {
			return nil, invalid()
		}
		if e = matchOwnerIssuer(s, owner, ownerP); e != nil {
			return nil, e
		}
		if e = p.CheckCeremonyOwnerLease(s, admissions, b); e != nil {
			return nil, e
		}
	}
	return result, nil
}
