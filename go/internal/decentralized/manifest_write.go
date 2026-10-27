package decentralized

import (
	"encoding/json"
	"sort"
)

func ReadActivation(d Descriptor, raw []byte) (*ParsedActivation, error) {
	return readActivation(d, raw)
}

// CommitManifest fixes exact received grant bodies and their full literal
// dependency closure. The caller supplies the completed target-host binding;
// this pure writer signs nothing and makes no admission/authority claim.
func CommitManifest(d Descriptor, base *Catalog, request, owner, selection, administrator, final *Packet, binding *Statement) ([]byte, *Catalog, error) {
	return commitManifest(d, base, request, owner, selection, administrator, final, binding, false)
}

// CommitManifestAccounting has no proof/authority output: its catalog includes
// a fixed-length zero-byte stand-in for the not-yet-created host signature.
// Use only its serialized sizes/proof-count for pre-sign quota accounting.
func CommitManifestAccounting(d Descriptor, base *Catalog, request, owner, selection, administrator, final *Packet, binding *Statement, reused bool) ([]byte, *Catalog, error) {
	copy := *binding
	if !reused {
		copy.Raw = make([]byte, len(binding.Raw)+base64SignatureSize()-1)
		copy.ProofID = ProofID(copy.Kind, copy.Raw)
	}
	return commitManifest(d, base, request, owner, selection, administrator, final, &copy, true)
}
func base64SignatureSize() int { return 88 }

func commitManifest(d Descriptor, base *Catalog, request, owner, selection, administrator, final *Packet, binding *Statement, accounting bool) ([]byte, *Catalog, error) {
	if base == nil || request == nil || owner == nil || selection == nil || final == nil || binding == nil || binding.Kind != "binding_lease" {
		return nil, nil, invalid()
	}
	objects := append([]CatalogObject{}, base.Objects...)
	add := func(s *Statement) {
		objects = append(objects, CatalogObject{ID: ProofID(s.Kind, s.Raw), Kind: s.Kind, BodyBase64: b64(s.Raw), Body: s.Raw})
	}
	add(binding)
	if administrator != nil {
		for _, s := range administrator.Statements {
			add(s)
		}
	}
	var device *Statement
	for _, s := range final.Statements {
		if s.Kind == "device_lease" {
			device = s
			add(s)
		}
	}
	if device == nil {
		return nil, nil, invalid()
	}
	byID := map[string]CatalogObject{}
	for _, o := range objects {
		byID[o.ID] = o
	}
	objects = []CatalogObject{}
	for _, id := range keysSortedObject(byID) {
		objects = append(objects, byID[id])
	}
	raw, e := json.Marshal(struct {
		Format  uint64          `json:"format"`
		Context string          `json:"context_id"`
		Objects []CatalogObject `json:"objects"`
	}{1, d.ContextID, objects})
	if e != nil {
		return nil, nil, e
	}
	var catalog *Catalog
	if !accounting {
		catalog, e = ReadCatalog(d, raw)
		if e != nil {
			return nil, nil, e
		}
	} else {
		catalog = &Catalog{Format: 1, ContextID: d.ContextID, Objects: objects, Raw: raw, Statements: map[string]*Statement{}, Proofs: map[string]*Statement{}, Sources: map[string][]string{}}
		for id, s := range base.Statements {
			catalog.Statements[id] = s
		}
		for id, s := range base.Proofs {
			catalog.Proofs[id] = s
		}
		for id, sources := range base.Sources {
			catalog.Sources[id] = append([]string{}, sources...)
		}
		grants := []*Statement{binding, device}
		if administrator != nil {
			grants = append(grants, administrator.Statements...)
		}
		for _, s := range grants {
			catalog.Statements[s.ID] = s
			catalog.Proofs[s.ProofID] = s
			catalog.Sources[s.ID] = append(catalog.Sources[s.ID], s.ProofID)
		}
	}
	person, e := catalogStatement(catalog, stringField(final.Object, "person_lease_id"))
	if e != nil {
		return nil, nil, e
	}
	host, e := catalogStatement(catalog, stringField(final.Object, "host_lease_id"))
	if e != nil {
		return nil, nil, e
	}
	g := newGraph(d, catalog)
	ancestors, e := g.ancestorIDs([]*Statement{person, host, binding, device})
	if e != nil {
		return nil, nil, e
	}
	needed := setOf(ancestors)
	needed[binding.ID] = true
	needed[device.ID] = true
	proofs := map[string]bool{}
	actual := map[string]bool{}
	for _, o := range catalog.Objects {
		actual[o.ID] = true
	}
	for id := range needed {
		s, e := catalogStatement(catalog, id)
		if e != nil {
			return nil, nil, e
		}
		proofs[s.ProofID] = true
		if actual[s.ProofID] {
			continue
		}
		sources := append([]string{}, catalog.Sources[id]...)
		sort.Strings(sources)
		found := false
		for _, source := range sources {
			if actual[source] {
				proofs[source] = true
				found = true
				break
			}
		}
		if !found {
			return nil, nil, failure("proof_required", id)
		}
	}
	adminID := "-"
	if administrator != nil {
		adminID = administrator.ID
	}
	manifest, e := json.Marshal(map[string]any{
		"format": uint64(1), "context_id": d.ContextID, "request_id": request.RequestID, "request_packet_id": request.ID,
		"owner_offer_id": owner.ID, "selection_id": selection.ID, "administrator_offer_id": adminID, "owner_finalization_id": final.ID,
		"root_state_id": stringField(final.Object, "root_state_id"), "person_lease_id": person.ID, "host_lease_id": host.ID,
		"binding_lease_id": binding.ID, "device_lease_id": device.ID, "binding_proof_id": binding.ProofID, "device_proof_id": device.ProofID,
		"ancestor_statement_ids": ancestors, "proof_ids": keysSorted(proofs),
	})
	if e != nil {
		return nil, nil, e
	}
	if _, e = readManifest(d, manifest); e != nil {
		return nil, nil, e
	}
	return manifest, catalog, nil
}

func catalogStatement(c *Catalog, id string) (*Statement, error) {
	s := c.Statements[id]
	if s == nil {
		return nil, failure("proof_required", id)
	}
	return s, nil
}
func keysSortedObject(objects map[string]CatalogObject) []string {
	ids := make([]string, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
