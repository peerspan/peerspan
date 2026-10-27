package decentralized

import "encoding/json"

// Path is a current public authority result from an already verified coherent
// projection. It says nothing about locally owned signing keys or delivery.
type Path struct {
	Scopes   uint64
	NotAfter string
}

// CompleteProof checks historical exact closure without requiring a statement
// to be current or unexpired. It grants no authority or admission.
func (p *Projection) CompleteProof(id string) error {
	if _, e := p.authority.graph.get(id); e != nil {
		return e
	}
	return p.authority.graph.readMissing[id]
}

func (p *Projection) Current(stream []string) (*Statement, Path, error) {
	if !validStream(stream) {
		return nil, Path{}, invalid()
	}
	statement, e := p.authority.selected(stream)
	if e != nil {
		return nil, Path{}, e
	}
	result, e := p.authority.evaluate(statement)
	if e != nil {
		return statement, Path{}, e
	}
	return statement, Path{result.Scopes, result.After}, nil
}

// StatementPath keeps exact selected-device identity. It never chooses another
// head, a different device, or an original owner when this path is unusable.
func (p *Projection) StatementPath(id string) (*Statement, Path, error) {
	statement, e := p.authority.graph.get(id)
	if e != nil {
		return nil, Path{}, e
	}
	result, e := p.authority.evaluate(statement)
	if e != nil {
		return statement, Path{}, e
	}
	return statement, Path{result.Scopes, result.After}, nil
}

// AdmittedPrior returns a copy of the pure verifier's next durable metadata;
// callers must still perform explicit local adoption/consent and atomic writes.
func (p *Projection) AdmittedPrior() (*Prior, error) {
	prior, ok := p.NextPrior.(*Prior)
	if !ok {
		return nil, invalid()
	}
	raw, e := json.Marshal(prior)
	if e != nil {
		return nil, e
	}
	return readPrior(p.authority.graph.descriptor, raw)
}

// AdmissionBasis is private output of this local evaluation. It is excluded
// from public projections and can never be supplied by a catalog candidate.
type AdmissionBasis struct {
	Kind     string
	Evidence []string
}

func statementBasis(g *graph, s *Statement, kind string, extra ...string) AdmissionBasis {
	ids := map[string]bool{}
	for _, id := range extra {
		ids[id] = true
	}
	if s != nil {
		if id := s.rootID(); id != "" {
			ids[id] = true
		}
		for _, parent := range s.parents() {
			ids[parent.ID] = true
		}
		for _, id := range s.predecessors() {
			ids[id] = true
		}
		if s.Lease != nil && s.Lease.Operation != "-" {
			ids[s.Lease.Operation] = true
			if activation := g.activated[s.Lease.Operation]; activation != nil {
				ids[activation.ID] = true
				ids[activation.ManifestID] = true
			}
		}
	}
	return AdmissionBasis{kind, keysSorted(ids)}
}
func (p *Projection) Admission(id string, activation bool) (AdmissionBasis, error) {
	table := p.admissions
	if activation {
		table = p.activationBases
	}
	basis, ok := table[id]
	if !ok {
		return AdmissionBasis{}, invalid()
	}
	return AdmissionBasis{basis.Kind, append([]string{}, basis.Evidence...)}, nil
}
