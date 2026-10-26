package decentralized

import (
	"encoding/json"
	"sort"
	"time"
)

type Actor struct {
	Person   string `json:"person_public_key"`
	Host     string `json:"host_public_key"`
	Device   string `json:"device_public_key"`
	IssuerID string `json:"issuer_id"`
}
type ActionAuthority struct {
	OK              bool     `json:"ok"`
	ContextID       string   `json:"context_id"`
	DecisionTime    string   `json:"decision_time"`
	IssuerID        string   `json:"issuer_id"`
	Signer          string   `json:"signer_public_key"`
	RequiredParents []string `json:"required_parent_ids"`
	After           string   `json:"effective_not_after"`
}

func readActor(raw []byte) (Actor, error) {
	var a Actor
	o, e := readObject(raw, "person_public_key host_public_key device_public_key issuer_id")
	if e != nil {
		return a, e
	}
	if json.Unmarshal(raw, &a) != nil {
		return a, invalid()
	}
	if _, e = texts(o, "person_public_key", "host_public_key", "device_public_key", "issuer_id"); e != nil {
		return a, e
	}
	if !literalOrKey(a.Person) || !literalOrKey(a.Host) || !literalOrKey(a.Device) || !literalOrID(a.IssuerID, "ds_") {
		return a, invalid()
	}
	return a, nil
}
func unsignedStatement(d Descriptor, kind string, raw []byte) (*Statement, error) {
	switch kind {
	case "admin_lease", "person_lease", "host_lease", "binding_lease", "policy", "group", "admin_withdraw", "person_remove", "host_revoke", "host_unbind", "device_revoke", "root_state":
	default:
		return nil, invalid()
	}
	o, e := parseLimit(raw, MaxPayload)
	if e != nil {
		return nil, e
	}
	s := &Statement{Kind: kind, ContextID: d.ContextID, Payload: append([]byte{}, raw...), Object: o, ProofID: "-", Signatures: []Signature{}}
	s.Message = StatementMessage(kind, d.ContextID, raw)
	s.ID = "ds_" + digest(s.Message)
	if _, e = s.checkPayload(d); e != nil {
		return nil, e
	}
	if s.Lease != nil && s.Lease.Operation != "-" {
		return nil, invalid()
	}
	return s, nil
}

// VerifyActionIntent verifies a fixed unsigned typed action. It produces no
// signature, admission, edit reservation, publication or owned-key claim.
func VerifyActionIntent(d Descriptor, priorRaw, candidateRaw, actorRaw, unsigned []byte, now, kind string) (*ActionAuthority, error) {
	actor, e := readActor(actorRaw)
	if e != nil {
		return nil, e
	}
	s, e := unsignedStatement(d, kind, unsigned)
	if e != nil {
		return nil, e
	}
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
	// Unused actor literals and intrinsic identity relations are framing, before
	// any dependency/current-authority lookup can hide them behind a repair error.
	if s.Root != nil || issuer.Kind == "root" {
		if actor.Person != "-" || actor.Host != "-" || actor.Device != "-" || !identifier(actor.IssuerID, "ds_") {
			return nil, invalid()
		}
	} else if issuer.Kind == "person" {
		if actor.Person != issuer.Person || actor.Host != "-" || actor.Device != "-" || actor.IssuerID != "-" {
			return nil, invalid()
		}
	} else if issuer.Kind == "device" {
		if actor.Person != issuer.Person || !key(actor.Host) || !key(actor.Device) || !identifier(actor.IssuerID, "ds_") || actor.IssuerID != parentID(s.parents(), "issuer_device") {
			return nil, invalid()
		}
	}
	projection, e := Project(d, priorRaw, candidateRaw, now, "repair")
	if e != nil {
		return nil, e
	}
	a := projection.authority
	// The pure carrier cannot manufacture a prior admission for an unsigned
	// action by first importing its issuer in this very same operation.
	priorIssuers := map[string]bool{}
	if projection.prior != nil {
		priorIssuers = setOf(projection.prior.AdmittedStatements)
	}
	after := "-"
	signer := ""
	parents := []string{}
	if s.Root != nil {
		// Competing complete migration origins can share a root statement ID.
		// A singleton root head therefore does not establish a unique origin.
		if a.originConflict {
			return nil, failure("state_conflict")
		}
		if actor.Person != "-" || actor.Host != "-" || actor.Device != "-" || !identifier(actor.IssuerID, "ds_") || len(s.Root.Predecessors) == 0 {
			return nil, invalid()
		}
		heads := append([]string{}, a.heads["root"]...)
		if !equalStrings(heads, s.Root.Predecessors) {
			return nil, failure("state_conflict")
		}
		if len(heads) == 1 {
			if actor.IssuerID != heads[0] {
				return nil, invalid()
			}
		} else if !contains(heads, actor.IssuerID) {
			return nil, invalid()
		}
		selected, e := a.graph.get(actor.IssuerID)
		if e != nil {
			return nil, e
		}
		if selected.Root == nil {
			return nil, invalid()
		}
		signer = selected.Root.Key
		parents = append(parents, s.Root.Predecessors...)
		for _, pred := range s.Root.Predecessors {
			p, e := a.graph.get(pred)
			if e != nil {
				return nil, e
			}
			role := "issuer"
			if len(s.Root.Predecessors) > 1 {
				role = "root_branch:" + pred
			}
			s.Signatures = append(s.Signatures, Signature{Role: role, PublicKey: p.Root.Key})
		}
		s.Signatures = append(s.Signatures, Signature{Role: "new_root", PublicKey: s.Root.Key})
	} else {
		root, e := a.root()
		if e != nil {
			return nil, e
		}
		if s.rootID() != root.ID {
			return nil, failure("forbidden")
		}
		switch issuer.Kind {
		case "root":
			if actor.Person != "-" || actor.Host != "-" || actor.Device != "-" || actor.IssuerID != root.ID {
				return nil, invalid()
			}
			signer = root.Root.Key
		case "person":
			if actor.Person != issuer.Person || actor.Host != "-" || actor.Device != "-" || actor.IssuerID != "-" {
				return nil, invalid()
			}
			signer = issuer.Person
		case "device":
			p, e := a.graph.get(actor.IssuerID)
			if e != nil {
				return nil, e
			}
			if p.Kind != "device_lease" || actor.Person != issuer.Person || p.Lease.Subject.Person != actor.Person || p.Lease.Subject.Host != actor.Host || p.Lease.Subject.Device != actor.Device || actor.IssuerID != parentID(s.parents(), "issuer_device") {
				return nil, invalid()
			}
			signer = actor.Device
		default:
			return nil, invalid()
		}
		s.Signatures = append(s.Signatures, Signature{Role: "issuer", PublicKey: signer})
		if s.Kind == "binding_lease" || s.Kind == "host_lease" {
			s.Signatures = append(s.Signatures, Signature{Role: "host", PublicKey: s.Lease.Subject.Host})
		}
		if !issuerPreviouslyAdmitted(s, priorIssuers) {
			return nil, failure("forbidden")
		}
		// Device self-invalidation has its explicit denial before target-ancestor
		// classification, rather than degrading it to an unrelated scope error.
		if issuer.Kind == "device" && wouldRestrictActor(a, s, actor.IssuerID) {
			return nil, failure("authority_would_be_invalidated")
		}
		path, e := a.issuer(s, true)
		if e != nil {
			return nil, e
		}
		after = path.After
		if e = directParentsCurrent(a, s); e != nil {
			return nil, e
		}
		parents = append(parents, s.rootID())
		for _, p := range s.parents() {
			parents = append(parents, p.ID)
		}
	}
	// Structural validation resolves all exact roots, predecessor/target and
	// ancestor relations. These ephemeral key-role placeholders are not signed
	// objects and are never inserted into the public catalog/returned state.
	g := *a.graph
	catalog := *g.catalog
	catalog.Statements = map[string]*Statement{}
	for id, p := range g.catalog.Statements {
		catalog.Statements[id] = p
	}
	catalog.Statements[s.ID] = s
	g.catalog = &catalog
	g.done = map[string]bool{}
	g.busy = map[string]bool{}
	if e = g.validate(s.ID); e != nil {
		return nil, e
	}
	issued := s.issuedTime()
	if issued.After(a.now) {
		return nil, invalid()
	}
	if a.now.Unix()-issued.Unix() > 300 {
		return nil, failure("expired")
	}
	if s.Lease != nil {
		if e := atTime(s.Lease.Before, s.Lease.After, a.now, false); e != nil {
			return nil, e
		}
		after = minAfter(after, s.Lease.After)
	}
	if s.Access != nil {
		if e := atTime(s.Access.Before, s.Access.After, a.now, true); e != nil {
			return nil, e
		}
		after = minAfter(after, s.Access.After)
	}
	if s.Root == nil {
		if e := validateNextStream(a, s); e != nil {
			return nil, e
		}
		// Restriction ancestry must include this exact unsigned successor too;
		// the prior catalog alone cannot discover its predecessor relation.
		candidateView := *a
		candidateView.graph = &g
		if e := candidateView.checkRestrictions(s, nil); e != nil {
			return nil, e
		}
	}
	for _, id := range s.retained() {
		child, e := a.graph.get(id)
		if e != nil {
			return nil, e
		}
		if !a.admitted[id] {
			return nil, failure("forbidden")
		}
		related := false
		for _, pred := range s.predecessors() {
			if a.graph.relatedContribution(child, pred, map[string]bool{}) {
				related = true
			}
		}
		if !related {
			return nil, invalid()
		}
		if candidateWindow(child, s.issuedTime()) != nil {
			return nil, failure("forbidden")
		}
		if _, e = a.evaluate(child); e != nil {
			return nil, e
		}
	}
	if issuer.Kind == "device" && s.Restriction == nil {
		next := *a
		next.graph = &g
		next.admitted = copySet(a.admitted)
		next.admitted[s.ID] = true
		next.heads = advanceHeads(&g, a.heads, map[string]bool{s.ID: true})
		selected, e := g.get(actor.IssuerID)
		if e != nil {
			return nil, e
		}
		if _, e = next.evaluate(selected); e != nil {
			return nil, failure("authority_would_be_invalidated")
		}
	}
	sort.Strings(parents)
	unique := parents[:0]
	for _, id := range parents {
		if len(unique) == 0 || unique[len(unique)-1] != id {
			unique = append(unique, id)
		}
	}
	return &ActionAuthority{true, d.ContextID, projection.DecisionTime, actor.IssuerID, signer, unique, after}, nil
}
func validateNextStream(a *authority, s *Statement) error {
	if s.Restriction != nil {
		return nil
	}
	heads := append([]string{}, a.heads[streamKey(s.stream())]...)
	if !equalStrings(heads, s.predecessors()) {
		return failure("state_conflict")
	}
	if maximum, ok := a.maxima[streamKey(s.stream())]; ok && s.sequence() <= maximum {
		return failure("state_conflict")
	}
	if len(heads) > 1 {
		for _, id := range heads {
			if !contains(s.resolves(), id) {
				return failure("state_conflict")
			}
		}
	}
	return nil
}
func wouldRestrictActor(a *authority, s *Statement, id string) bool {
	if s.Restriction == nil {
		return false
	}
	target := s.Restriction.Target
	seen := map[string]bool{}
	var visit func(string) bool
	visit = func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		p := a.graph.catalog.Statements[id]
		if p == nil || p.Lease == nil {
			return false
		}
		l := p.Lease
		switch s.Kind {
		case "person_remove":
			if target.Person == l.Subject.Person {
				return true
			}
		case "host_revoke":
			if target.Host == l.Subject.Host {
				return true
			}
		case "host_unbind":
			if target.Statement == id {
				return true
			}
		case "device_revoke":
			if target.Person == l.Subject.Person && target.Device == l.Subject.Device {
				return true
			}
		case "admin_withdraw":
			if target.Statement == id {
				return true
			}
		}
		for _, parent := range p.parents() {
			if visit(parent.ID) {
				return true
			}
		}
		return false
	}
	return visit(id)
}

func mustTime(s string) time.Time { t, _ := stamp(s); return t }
