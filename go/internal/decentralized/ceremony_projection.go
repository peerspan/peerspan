package decentralized

type ceremonyProjectionScope struct {
	markers    map[string]string
	statements map[string]*Statement
}

// PrepareCeremonyProjection checks a specific selected prefix containing
// standalone aliases of its inline pending grants. Those exact grants may be
// structurally complete before requester final consent. They remain inert:
// no activation marker, issuer admission or transferable prior is produced.
func PrepareCeremonyProjection(d Descriptor, priorRaw, catalogRaw []byte, request, owner, selection, administrator, final *Packet, now string) (*Projection, error) {
	if request == nil || owner == nil || selection == nil {
		return nil, invalid()
	}
	packets := []*Packet{request, owner, selection, administrator, final}
	for n, packet := range packets {
		if packet == nil {
			continue
		}
		parsed, e := readPacket(d, packet.Raw)
		if e != nil {
			return nil, e
		}
		if parsed.ID != packet.ID {
			return nil, invalid()
		}
		packets[n] = parsed
	}
	request, owner, selection, administrator, final = packets[0], packets[1], packets[2], packets[3], packets[4]
	if request.Role != "request" || owner.Role != "owner" || selection.Role != "selection" || owner.RequestID != request.RequestID || selection.RequestID != request.RequestID || stringField(owner.Object, "request_packet_id") != request.ID || stringField(selection.Object, "request_packet_id") != request.ID || stringField(selection.Object, "owner_offer_id") != owner.ID {
		return nil, invalid()
	}
	adminID := "-"
	if administrator == nil {
		// Only a renewal with independently current P/H may omit this
		// stage. The final whole-prefix check below validates those paths;
		// no pending P/H is added on the omitted-stage path.
		if stringField(request.Object, "mode") != "renew" || final == nil {
			return nil, invalid()
		}
	} else {
		if administrator.Role != "administrator" || administrator.RequestID != request.RequestID || stringField(administrator.Object, "owner_offer_id") != owner.ID || stringField(administrator.Object, "selection_id") != selection.ID {
			return nil, invalid()
		}
		adminID = administrator.ID
	}
	prior, e := readPrior(d, priorRaw)
	if e != nil {
		return nil, e
	}
	admitted := map[string]bool{}
	if prior != nil {
		admitted = setOf(prior.AdmittedStatements)
	}
	pending := &ceremonyProjectionScope{markers: map[string]string{}, statements: map[string]*Statement{}}
	collect := func(packet *Packet, kinds map[string]bool) error {
		for _, s := range packet.Statements {
			if !kinds[s.Kind] || s.Lease == nil || s.Lease.Operation != request.RequestID {
				return invalid()
			}
			// An incomplete local historical admission still needs its actual
			// retained activation; pending consent cannot repair its provenance.
			if !admitted[s.ID] {
				pending.markers[s.ID] = request.RequestID
				pending.statements[s.ID] = s
			}
		}
		return nil
	}
	if administrator != nil {
		if e = collect(administrator, map[string]bool{"person_lease": true, "host_lease": true}); e != nil {
			return nil, e
		}
	}
	if final != nil {
		if final.Role != "owner_finalization" || final.RequestID != request.RequestID || stringField(final.Object, "selection_id") != selection.ID || stringField(final.Object, "administrator_offer_id") != adminID {
			return nil, invalid()
		}
		if e = collect(final, map[string]bool{"binding_lease": true, "device_lease": true}); e != nil {
			return nil, e
		}
	}
	p, e := project(d, priorRaw, catalogRaw, now, "repair", pending)
	if e != nil {
		return nil, e
	}
	if final != nil {
		if _, e = p.PrepareCeremonyFinalization(request, owner, selection, administrator, final); e != nil {
			return nil, e
		}
	} else {
		if _, e = p.PrepareCeremonyAdmissions(request, owner, selection, administrator); e != nil {
			return nil, e
		}
	}
	// This is deliberately not an adoption/import interface. Callers retain
	// their original full catalog and use ordinary complete activation at apply.
	p.NextPrior = nil
	return p, nil
}
