package decentralized

import "encoding/json"

// VerifyLocalGenesis is the explicit local creation exception. It verifies one
// complete creator-owned root/A/P/H/B/policy closure with original-person and
// host consent, then returns private admission metadata. Public replication or
// a normal ordinary-write pass never invokes this exception.
func VerifyLocalGenesis(d Descriptor, catalogRaw []byte, person, host, member, now string) (*Projection, error) {
	if !key(person) || !key(host) {
		return nil, invalid()
	}
	c, e := ReadCatalog(d, catalogRaw)
	if e != nil {
		return nil, e
	}
	if len(c.Statements) != 6 || len(c.Activations) != 0 || len(c.Migrations) != 0 {
		return nil, invalid()
	}
	if e = checkLocalGenesisGraph(d, c, person, host, member); e != nil {
		return nil, e
	}
	g := newGraph(d, c)
	admitted := map[string]bool{}
	for id := range c.Statements {
		admitted[id] = true
	}
	at, e := stamp(now)
	if e != nil {
		return nil, e
	}
	a := &authority{graph: g, now: at, admitted: admitted, restrictions: map[string]bool{}, heads: headsFor(g, admitted), maxima: map[string]uint64{}, active: map[string]bool{}}
	for _, s := range c.Statements {
		if e = candidateWindow(s, at); e != nil {
			return nil, e
		}
		if _, e = a.evaluate(s); e != nil {
			return nil, e
		}
	}
	var root *Statement
	for _, statement := range c.Statements {
		if statement.Root != nil {
			root = statement
		}
	}
	p := &Prior{Format: 1, ContextID: d.ContextID, CatalogBase64: b64(c.Raw), AdmittedStatements: keysSorted(admitted), AdmittedRestrictions: []string{}, AdmittedActivations: []string{}, RootHeads: []string{root.ID}, Maxima: buildMaxima(g, admitted, nil), Migration: "-", ClockGuard: now, catalog: c}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	result, e := Project(d, raw, emptyCatalog(d).Raw, now, "fresh")
	if e != nil {
		return nil, e
	}
	// The dedicated gate above, rather than a fabricated public prior marker,
	// establishes every initial current admission and its exact provenance.
	result.admissions = map[string]AdmissionBasis{}
	for id, s := range c.Statements {
		result.admissions[id] = statementBasis(g, s, "current")
	}
	return result, nil
}

func checkLocalGenesisGraph(d Descriptor, c *Catalog, person, host, member string) error {
	var e error
	g := newGraph(d, c)
	if e = g.prepareConsent(); e != nil {
		return e
	}
	byKind := map[string]*Statement{}
	for id, s := range c.Statements {
		if byKind[s.Kind] != nil {
			return invalid()
		}
		byKind[s.Kind] = s
		if e = g.validate(id); e != nil {
			return e
		}
	}
	if e = g.validateAliases(); e != nil {
		return e
	}
	root := byKind["root_state"]
	if root == nil || root.Root.Epoch != 0 || root.Root.Key != d.GenesisRootPublicKey || root.Root.Migration != "-" || len(root.Root.Predecessors) != 0 {
		return invalid()
	}
	for _, kind := range []string{"admin_lease", "person_lease", "host_lease", "binding_lease", "policy"} {
		s := byKind[kind]
		if s == nil || s.rootID() != root.ID || s.sequence() != 1 || len(s.predecessors()) != 0 || len(s.resolves()) != 0 {
			return invalid()
		}
		if s.Lease != nil {
			l := s.Lease
			if l.Operation != "-" || len(l.Retained) != 0 {
				return invalid()
			}
			switch kind {
			case "admin_lease", "person_lease":
				if l.Subject.Person != person || l.Issuer.Kind != "root" {
					return invalid()
				}
			case "host_lease":
				if l.Subject.Host != host || l.Subject.Member != member || l.Issuer.Kind != "root" {
					return invalid()
				}
			case "binding_lease":
				if l.Subject.Person != person || l.Subject.Host != host || l.Issuer.Kind != "person" || l.Issuer.Person != person {
					return invalid()
				}
			}
			if kind == "person_lease" && l.Subject.Member != member {
				return invalid()
			}
		} else if s.Access == nil || s.Access.Issuer.Kind != "person" || s.Access.Issuer.Person != person {
			return invalid()
		}
	}
	return nil
}
func CheckLocalGenesisTemplates(d Descriptor, templates [][]byte, person, host, member, now string) error {
	c := &Catalog{Statements: map[string]*Statement{}, Proofs: map[string]*Statement{}, Activations: map[string]*ParsedActivation{}, ActivationProofs: []*ParsedActivation{}, Migrations: []*ParsedMigration{}}
	if len(templates) != 6 {
		return invalid()
	}
	for _, raw := range templates {
		statement, e := ReadStatementTemplate(d, raw)
		if e != nil {
			return e
		}
		if c.Statements[statement.ID] != nil {
			return invalid()
		}
		c.Statements[statement.ID] = statement
		c.Proofs[statement.ID] = statement
	}
	if e := checkLocalGenesisGraph(d, c, person, host, member); e != nil {
		return e
	}
	at, e := stamp(now)
	if e != nil {
		return e
	}
	for _, s := range c.Statements {
		if e = candidateWindow(s, at); e != nil {
			return e
		}
	}
	return nil
}
