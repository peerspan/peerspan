package decentralized

import (
	"bytes"
	"encoding/json"
	"sort"
)

// prepareConsent checks immutable transcript relations and possession. The
// current owner/admin lease permissions remain separate authority checks.
func (g *graph) prepareConsent() error {
	requests := map[string]string{}
	for _, a := range g.catalog.ActivationProofs {
		if manifest, ok := requests[a.Request.RequestID]; ok && manifest != a.ManifestID {
			return failure("operation_conflict")
		}
		requests[a.Request.RequestID] = a.ManifestID
		if e := g.checkConsent(a); e != nil {
			return e
		}
		g.activated[a.Request.RequestID] = a
	}
	return nil
}
func (g *graph) checkConsent(a *ParsedActivation) error {
	request, owner, selection, final, commit := a.Request, a.Owner, a.Selection, a.Finalization, a.Commit
	for _, packet := range []*Packet{owner, a.Administrator} {
		if packet != nil {
			if _, e := g.packetIssuerRefs(packet); e != nil {
				return e
			}
		}
	}
	mode := stringField(request.Object, "mode")
	person := owner.Person
	host, device := request.Writer, request.Signer
	if stringField(owner.Object, "mode") != mode || stringField(owner.Object, "host_public_key") != host || stringField(owner.Object, "device_public_key") != device || stringField(selection.Object, "host_public_key") != host || stringField(selection.Object, "device_public_key") != device {
		return invalid()
	}
	for field, actual := range map[string]string{"expected_network_id": g.descriptor.NetworkID, "expected_context_id": g.descriptor.ContextID, "expected_person_public_key": person} {
		expected := stringField(request.Object, field)
		if expected != "-" && expected != actual {
			return invalid()
		}
	}
	if stringField(owner.Object, "renewed_device_lease_id") != stringField(request.Object, "renewed_device_lease_id") {
		return invalid()
	}
	migration := stringField(request.Object, "migration_proposal_id")
	root, e := g.get(stringField(a.Manifest, "root_state_id"))
	if e != nil {
		return e
	}
	if root.Root == nil || migration != "-" && root.Root.Migration != migration {
		return invalid()
	}
	// Non-initial roots following a migrated origin still use ordinary requests;
	// a staged request is pinned to its exact initial prepared root only.
	for _, p := range []*Packet{final, a.Administrator} {
		if p != nil && stringField(p.Object, "root_state_id") != root.ID {
			return invalid()
		}
	}
	ownerRoot := stringField(owner.Object, "root_state_id")
	if ownerRoot != "-" && ownerRoot != root.ID {
		return invalid()
	}
	selected := map[string]*Statement{}
	for _, f := range []struct{ field, kind string }{{"person_lease_id", "person_lease"}, {"host_lease_id", "host_lease"}, {"binding_lease_id", "binding_lease"}, {"device_lease_id", "device_lease"}} {
		s, e := g.get(stringField(a.Manifest, f.field))
		if e != nil {
			return e
		}
		if s.Kind != f.kind {
			return invalid()
		}
		if f.kind == "binding_lease" || f.kind == "device_lease" {
			proofField := "binding_proof_id"
			if f.kind == "device_lease" {
				proofField = "device_proof_id"
			}
			proof := stringField(a.Manifest, proofField)
			exact := g.catalog.Proofs[proof]
			if exact == nil {
				return failure("proof_required", proof)
			}
			if exact.ID != s.ID || exact.Kind != s.Kind {
				return invalid()
			}
			s = exact
		}
		selected[f.kind] = s
	}
	p, h, b, d := selected["person_lease"], selected["host_lease"], selected["binding_lease"], selected["device_lease"]
	if p.Lease.Subject.Person != person || h.Lease.Subject.Host != host || b.Lease.Subject.Person != person || b.Lease.Subject.Host != host || d.Lease.Subject.Person != person || d.Lease.Subject.Host != host || d.Lease.Subject.Device != device {
		return invalid()
	}
	member := stringField(owner.Object, "member")
	if p.Lease.Subject.Member != member || h.Lease.Subject.Member != member {
		return invalid()
	}
	scopes, _ := num(owner.Object, "scopes")
	if d.Lease.Subject.Scopes != scopes || d.Lease.After != stringField(owner.Object, "not_after") || d.Lease.Operation != request.RequestID {
		return invalid()
	}
	if d.rootID() != root.ID {
		return invalid()
	}
	if parentID(d.parents(), "subject_person") != p.ID || parentID(d.parents(), "subject_host") != h.ID || parentID(d.parents(), "subject_binding") != b.ID || d.Signer("issuer") != final.Signer {
		return invalid()
	}
	if stringField(final.Object, "person_lease_id") != p.ID || stringField(final.Object, "host_lease_id") != h.ID {
		return invalid()
	}
	ownerP := stringField(owner.Object, "person_lease_id")
	ownerRefs := []string{}
	if ownerP == "-" {
		if owner.Issuer != "-" || stringField(owner.Object, "root_state_id") != "-" {
			return invalid()
		}
		ownerP = p.ID
	} else {
		ownerRefs = append(ownerRefs, ownerP)
	}
	if owner.Issuer != "-" {
		ownerRefs = append(ownerRefs, owner.Issuer)
		issuer, e := g.get(owner.Issuer)
		if e != nil {
			return e
		}
		if issuer.Kind != "device_lease" || issuer.Lease.Subject.Person != owner.Person || issuer.Lease.Subject.Host != owner.Writer || issuer.Lease.Subject.Device != owner.Signer {
			return invalid()
		}
	}
	sort.Strings(ownerRefs)
	refs, e := ids(owner.Object, "issuer_lease_ids", "ds_")
	if e != nil || !equalStrings(refs, ownerRefs) {
		return invalid()
	}
	if e := matchOwnerIssuer(d, owner, ownerP); e != nil {
		return e
	}
	if a.Administrator != nil {
		for _, entry := range []struct {
			field string
			s     *Statement
		}{{"person_lease", p}, {"host_lease", h}} {
			if e := sameComponent(a.Administrator, entry.field, entry.s); e != nil {
				return e
			}
			if !isString(a.Administrator.Object[entry.field]) && (entry.s.Lease.Operation != request.RequestID || entry.s.Signer("issuer") != a.Administrator.Signer || entry.s.rootID() != root.ID) {
				return invalid()
			}
			if !isString(a.Administrator.Object[entry.field]) {
				if e := g.matchAdministratorIssuer(entry.s, a.Administrator); e != nil {
					return e
				}
			}
		}
	} else if mode != "renew" || p.Lease.Operation == request.RequestID || h.Lease.Operation == request.RequestID {
		return invalid()
	}
	newBinding := !isString(final.Object["binding_lease"])
	if e := sameComponent(final, "binding_lease", b); e != nil {
		return e
	}
	if e := sameComponent(final, "device_lease", d); e != nil {
		return e
	}
	if newBinding {
		if b.Lease.Operation != request.RequestID || b.Signer("issuer") != final.Signer || b.rootID() != root.ID {
			return invalid()
		}
		if e := matchOwnerIssuer(b, owner, ownerP); e != nil {
			return e
		}
		pending, e := readStatement(g.descriptor, final.Object["binding_lease"], true)
		if e != nil {
			return e
		}
		if !equalIssuerSignature(pending, b) {
			return invalid()
		}
		sig := stringField(commit.Object, "binding_host_signature")
		found := false
		for _, bs := range b.Signatures {
			if bs.Role == "host" && bs.Signature == sig && bs.PublicKey == host && bs.Format == "ed25519" {
				found = true
			}
		}
		if !found {
			return invalid()
		}
	} else if mode != "renew" || stringField(commit.Object, "binding_host_signature") != "-" {
		return invalid()
	}
	for field, s := range map[string]*Statement{"binding_proof_id": b, "device_proof_id": d} {
		proof := stringField(a.Manifest, field)
		exact := g.catalog.Proofs[proof]
		if exact == nil {
			return failure("proof_required", proof)
		}
		if exact.ID != s.ID {
			return invalid()
		}
	}
	if mode == "renew" {
		old, e := g.get(stringField(request.Object, "renewed_device_lease_id"))
		if e != nil {
			return e
		}
		if old.Kind != "device_lease" || old.Lease.Subject.Person != person || old.Lease.Subject.Host != host || old.Lease.Subject.Device != device || d.ID == old.ID {
			return invalid()
		}
	}
	// Requester clocks delimit its review attempt, not a global signing-time
	// assertion. Packet ordering must nevertheless fit the exact honest window.
	created := stringField(request.Object, "created_at")
	expires := stringField(request.Object, "expires_at")
	for _, at := range []string{stringField(selection.Object, "selected_at"), stringField(commit.Object, "committed_at")} {
		if at < created || at >= expires {
			return invalid()
		}
	}
	if stringField(commit.Object, "committed_at") < stringField(selection.Object, "selected_at") {
		return invalid()
	}
	ancestorIDs, e := g.ancestorIDs([]*Statement{p, h, b, d})
	if e != nil {
		return e
	}
	supplied, e := ids(a.Manifest, "ancestor_statement_ids", "ds_")
	if e != nil {
		return e
	}
	if !equalStrings(ancestorIDs, supplied) {
		return invalid()
	}
	proofIDs, e := ids(a.Manifest, "proof_ids", "dp_")
	if e != nil {
		return e
	}
	for _, proof := range proofIDs {
		if g.catalog.Proofs[proof] == nil {
			found := false
			for _, o := range g.catalog.Objects {
				if o.ID == proof {
					found = true
				}
			}
			if !found {
				return failure("proof_required", proof)
			}
		}
	}
	for _, s := range append([]*Statement{b, d}, g.statementsFor(ancestorIDs)...) {
		found := false
		for _, proof := range proofIDs {
			exact := g.catalog.Proofs[proof]
			if exact != nil && exact.ID == s.ID {
				found = true
				break
			}
		}
		if !found {
			return failure("proof_required", s.ID)
		}
	}
	return nil
}

// Packet roles pin a typed authority path, including when one public key has
// more than one role. Coincident signer bytes cannot substitute a root/person
// role or another selected device for the explicitly reviewed path.
func matchOwnerIssuer(s *Statement, owner *Packet, personLease string) error {
	kind := "person"
	if owner.Issuer != "-" {
		kind = "device"
	}
	if s.Lease.Issuer.Kind != kind || s.Lease.Issuer.Person != owner.Person || parentID(s.parents(), "issuer_person") != personLease {
		return invalid()
	}
	if kind == "device" && parentID(s.parents(), "issuer_device") != owner.Issuer {
		return invalid()
	}
	return nil
}
func (g *graph) matchAdministratorIssuer(s *Statement, admin *Packet) error {
	expected := []string{}
	kind := "root"
	if admin.Person == "-" {
		if admin.Issuer != s.rootID() {
			return invalid()
		}
	} else {
		kind = "person"
		if admin.Issuer != "-" {
			kind = "device"
			issuer, e := g.get(admin.Issuer)
			if e != nil {
				return e
			}
			if issuer.Kind != "device_lease" || issuer.Lease.Subject.Person != admin.Person || issuer.Lease.Subject.Host != admin.Writer || issuer.Lease.Subject.Device != admin.Signer || parentID(s.parents(), "issuer_device") != admin.Issuer {
				return invalid()
			}
			expected = append(expected, admin.Issuer)
		}
		for _, role := range []string{"issuer_person", "issuer_admin"} {
			expected = append(expected, parentID(s.parents(), role))
		}
	}
	if s.Lease.Issuer.Kind != kind || s.Lease.Issuer.Person != admin.Person {
		return invalid()
	}
	sort.Strings(expected)
	refs, e := ids(admin.Object, "issuer_lease_ids", "ds_")
	if e != nil || !equalStrings(refs, expected) {
		return invalid()
	}
	return nil
}

// packetIssuerRefs validates the exact typed identity references even when an
// administrator packet reuses existing P/H instead of carrying new grants.
func (g *graph) packetIssuerRefs(packet *Packet) ([]*Statement, error) {
	ids, e := ids(packet.Object, "issuer_lease_ids", "ds_")
	if e != nil {
		return nil, e
	}
	if packet.Person == "-" {
		root, e := g.get(packet.Issuer)
		if e != nil {
			return nil, e
		}
		if packet.Role != "administrator" || root.Root == nil || packet.Signer != root.Root.Key || root.ID != stringField(packet.Object, "root_state_id") || len(ids) != 0 {
			return nil, invalid()
		}
		return []*Statement{}, nil
	}
	wanted := map[string]bool{"person_lease": true}
	if packet.Role == "administrator" {
		wanted["admin_lease"] = true
	} else if stringField(packet.Object, "person_lease_id") == "-" {
		delete(wanted, "person_lease")
	}
	if packet.Issuer != "-" {
		wanted["device_lease"] = true
	}
	if len(ids) != len(wanted) {
		return nil, invalid()
	}
	refs := []*Statement{}
	for _, id := range ids {
		s, e := g.get(id)
		if e != nil {
			return nil, e
		}
		if !wanted[s.Kind] || s.Lease == nil || s.Lease.Subject.Person != packet.Person {
			return nil, invalid()
		}
		delete(wanted, s.Kind)
		if packet.Role == "owner" && s.Kind == "person_lease" && stringField(packet.Object, "person_lease_id") != id {
			return nil, invalid()
		}
		if s.Kind == "device_lease" && (id != packet.Issuer || s.Lease.Subject.Host != packet.Writer || s.Lease.Subject.Device != packet.Signer) {
			return nil, invalid()
		}
		refs = append(refs, s)
	}
	return refs, nil
}
func isString(raw []byte) bool { return bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) }
func sameComponent(p *Packet, field string, s *Statement) error {
	raw := p.Object[field]
	if isString(raw) {
		if stringField(p.Object, field) != s.ID {
			return invalid()
		}
		return nil
	}
	for _, component := range p.Statements {
		if component.ID == s.ID && bytes.Equal(component.Payload, s.Payload) {
			return nil
		}
	}
	return invalid()
}
func (g *graph) ancestorIDs(selected []*Statement) ([]string, error) {
	ids := map[string]bool{}
	busy := map[string]bool{}
	var visit func(*Statement) error
	visit = func(s *Statement) error {
		if busy[s.ID] {
			return invalid()
		}
		busy[s.ID] = true
		defer delete(busy, s.ID)
		refs := append([]string{}, s.predecessors()...)
		refs = append(refs, s.resolves()...)
		// Manifest completeness follows literal signed references, including
		// retention of other branches. This walk does not confer authority.
		refs = append(refs, s.retained()...)
		if s.rootID() != "" {
			refs = append(refs, s.rootID())
		}
		for _, p := range s.parents() {
			refs = append(refs, p.ID)
		}
		if r := s.Restriction; r != nil {
			for _, id := range []string{r.Target.Statement, r.Ratifies} {
				if id != "-" {
					refs = append(refs, id)
				}
			}
			refs = append(refs, r.Kept...)
		}
		for _, id := range refs {
			if ids[id] {
				continue
			}
			p, e := g.get(id)
			if e != nil {
				return e
			}
			ids[id] = true
			if e = visit(p); e != nil {
				return e
			}
		}
		return nil
	}
	for _, s := range selected {
		if e := visit(s); e != nil {
			return nil, e
		}
	}
	// The manifest names its issued device separately from the ancestor set.
	// Traverse its references normally; graph validation still rejects cycles.
	for _, s := range selected {
		if s.Kind == "device_lease" {
			delete(ids, s.ID)
		}
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}
func (g *graph) statementsFor(ids []string) []*Statement {
	out := []*Statement{}
	for _, id := range ids {
		if s := g.catalog.Statements[id]; s != nil {
			out = append(out, s)
		}
	}
	return out
}
func componentID(raw json.RawMessage, d Descriptor, pending bool) (string, error) {
	if isString(raw) {
		var s string
		if json.Unmarshal(raw, &s) != nil || !identifier(s, "ds_") {
			return "", invalid()
		}
		return s, nil
	}
	s, e := readStatement(d, raw, pending)
	if e != nil {
		return "", e
	}
	return s.ID, nil
}
