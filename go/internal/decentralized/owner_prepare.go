package decentralized

// OwnerOfferPreparation is a preparation-only bound-path result. It contains
// no projection, next_prior, admission metadata or callable authority object.
type OwnerOfferPreparation struct {
	Person, Host, Binding, Device *Statement
	Scopes                        uint64
	NotAfter                      string
}

// PrepareOwnerOffer checks only this signed offer's existing owner binding and
// actual issuer ancestry. A cold requester may review an ordinary binding in
// the same supplied closure as its admitted person lease. The scoped scratch
// view cannot escape this function or admit unrelated policies/grants.
func (p *Projection) PrepareOwnerOffer(request, supplied *Packet) (*OwnerOfferPreparation, error) {
	if p == nil || p.authority == nil || request == nil || supplied == nil {
		return nil, invalid()
	}
	a := p.authority
	d := a.graph.descriptor
	owner, e := readPacket(d, supplied.Raw)
	if e != nil {
		return nil, e
	}
	req, e := readPacket(d, request.Raw)
	if e != nil {
		return nil, e
	}
	if owner.Role != "owner" || req.Role != "request" || owner.RequestID != req.RequestID || stringField(owner.Object, "request_packet_id") != req.ID || stringField(owner.Object, "host_public_key") != req.Writer || stringField(owner.Object, "device_public_key") != req.Signer || owner.Person == "-" {
		return nil, invalid()
	}
	root, e := a.root()
	if e != nil {
		return nil, e
	}
	if stringField(owner.Object, "root_state_id") != root.ID {
		return nil, failure("forbidden")
	}
	if a.now.Format("2006-01-02T15:04:05Z") < stringField(req.Object, "created_at") {
		return nil, failure("clock_rollback")
	}
	if a.now.Format("2006-01-02T15:04:05Z") >= stringField(req.Object, "expires_at") {
		return nil, failure("expired")
	}
	refs, e := a.graph.packetIssuerRefs(owner)
	if e != nil {
		return nil, e
	}
	result := &OwnerOfferPreparation{}
	for _, s := range refs {
		if s.Kind == "person_lease" {
			result.Person = s
		}
		if s.Kind == "device_lease" {
			result.Device = s
		}
	}
	if result.Person == nil || result.Person.ID != stringField(owner.Object, "person_lease_id") || result.Person.Lease.Subject.Member != stringField(owner.Object, "member") {
		return nil, invalid()
	}
	// Only direct typed owner/issuer ancestry is eligible here. Literal retained
	// lists are proof requirements, never a source of new same-pass issuers.
	clone := func(source *authority) *authority {
		view := *source
		view.admitted = copySet(source.admitted)
		view.heads = map[string][]string{}
		for k, h := range source.heads {
			view.heads[k] = append([]string{}, h...)
		}
		view.proven = nil
		return &view
	}
	var ensure func(*authority, *Statement) error
	var visit func(*authority, *Statement, map[string]bool) error
	visit = func(view *authority, s *Statement, busy map[string]bool) error {
		if view.admitted[s.ID] {
			return nil
		}
		if busy[s.ID] {
			return invalid()
		}
		busy[s.ID] = true
		defer delete(busy, s.ID)
		if s.Lease == nil || s.Lease.Operation != "-" || (s.Kind != "person_lease" && s.Kind != "host_lease" && s.Kind != "binding_lease" && s.Kind != "admin_lease") {
			return failure("forbidden")
		}
		if e := candidateWindow(s, view.now); e != nil {
			return e
		}
		for _, parent := range s.parents() {
			node, e := view.graph.get(parent.ID)
			if e != nil {
				return e
			}
			if e = visit(view, node, busy); e != nil {
				return e
			}
		}
		if _, e := view.issuer(s, true); e != nil {
			return e
		}
		if e := directParentsCurrent(view, s); e != nil {
			return e
		}
		if e := view.checkRestrictions(s, nil); e != nil {
			return e
		}
		view.admitted[s.ID] = true
		preserveHeads(view, p.prior)
		if _, e := view.evaluate(s); e != nil {
			return e
		}
		return nil
	}
	ensure = func(view *authority, s *Statement) error { return visit(view, s, map[string]bool{}) }
	view := clone(a)
	if e = ensure(view, result.Person); e != nil {
		return nil, e
	}
	personHead, e := view.selected(result.Person.stream())
	if e != nil {
		return nil, e
	}
	if personHead.ID != result.Person.ID {
		return nil, failure("forbidden")
	}
	if _, e = view.evaluate(result.Person); e != nil {
		return nil, e
	}
	// Consider every independently eligible binding in this exact owner-host
	// stream, retaining remembered heads/maxima. No hash winner is selected.
	var refused error
	bindings := map[string]bool{}
	for _, id := range keysSortedStatements(a.graph.catalog.Statements) {
		b := a.graph.catalog.Statements[id]
		if b.Kind != "binding_lease" || b.Lease.Subject.Host != owner.Writer || b.Lease.Subject.Person != owner.Person {
			continue
		}
		trial := clone(view)
		if err := ensure(trial, b); err != nil {
			if refused == nil {
				refused = err
			}
			continue
		}
		if _, err := trial.evaluate(b); err != nil {
			if refused == nil {
				refused = err
			}
			continue
		}
		for admitted := range trial.admitted {
			bindings[admitted] = true
		}
	}
	for id := range bindings {
		view.admitted[id] = true
	}
	preserveHeads(view, p.prior)
	binding, e := view.selected([]string{"binding", owner.Writer})
	if e != nil {
		if Code(e) == "proof_required" && len(view.heads[streamKey([]string{"binding", owner.Writer})]) == 0 && refused != nil {
			return nil, refused
		}
		return nil, e
	}
	if binding.Kind != "binding_lease" || binding.Lease.Subject.Person != owner.Person {
		return nil, failure("forbidden")
	}
	bpath, e := view.evaluate(binding)
	if e != nil {
		return nil, e
	}
	host, e := view.graph.get(parentID(binding.parents(), "subject_host"))
	if e != nil {
		return nil, e
	}
	if host.Kind != "host_lease" || host.Lease.Subject.Host != owner.Writer || host.Lease.Subject.Member != stringField(owner.Object, "member") {
		return nil, failure("forbidden")
	}
	result.Host, result.Binding = host, binding
	result.Scopes = 7
	result.NotAfter = bpath.After
	if result.Device != nil {
		path, e := a.evaluate(result.Device)
		if e != nil {
			return nil, e
		}
		if path.Scopes&4 == 0 {
			return nil, failure("forbidden")
		}
		result.Scopes = path.Scopes
		result.NotAfter = minAfter(result.NotAfter, path.After)
	}
	requestedAfter := result.NotAfter
	if admin, e := view.selected([]string{"admin", owner.Person}); e == nil {
		if path, e := view.evaluate(admin); e == nil {
			if result.Device == nil {
				result.Scopes |= 8
			}
			if result.Scopes&8 != 0 {
				result.NotAfter = minAfter(result.NotAfter, path.After)
				if scopes, _ := num(owner.Object, "scopes"); scopes&8 != 0 {
					requestedAfter = minAfter(requestedAfter, path.After)
				}
			}
		} else {
			result.Scopes &= 7
		}
	} else {
		result.Scopes &= 7
	}
	scopes, _ := num(owner.Object, "scopes")
	if scopes & ^result.Scopes != 0 || stringField(owner.Object, "not_after") > requestedAfter {
		return nil, failure("forbidden")
	}
	return result, nil
}

func keysSortedStatements(statements map[string]*Statement) []string {
	set := map[string]bool{}
	for id := range statements {
		set[id] = true
	}
	return keysSorted(set)
}
