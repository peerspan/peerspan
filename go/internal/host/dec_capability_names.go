package host

import (
	"context"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// A resource name/withdrawal decision cannot treat an unresolved remembered
// policy as an absent claim. This is stricter than an active-only permission
// map, which safely denies access when its required proof is unavailable.
func decCapabilityReadRoot(p *dec.Projection) error {
	if p == nil {
		return decStorageError()
	}
	if p.Root.Code != "-" {
		if p.Root.Code == "state_conflict" {
			return &decReadConflict{decSorted(decSet(p.Root.HeadIDs))}
		}
		return decFailure(p.Root.Code, p.Root.RequiredIDs...)
	}
	_, _, e := p.Current([]string{"root"})
	return e
}

func decCapabilityKnownHead(p *dec.Projection, kind, subject string) bool {
	for _, stream := range p.Streams {
		if len(stream.Stream) == 2 && stream.Stream[0] == kind && stream.Stream[1] == subject {
			return len(stream.HeadIDs) != 0
		}
	}
	return false
}

func checkedDecCapabilityPolicy(p *dec.Projection, person string) (productPolicy, bool, error) {
	if !decCapabilityKnownHead(p, "policy", person) {
		return productPolicy{}, false, nil
	}
	statement, path, e := p.Current([]string{"policy", person})
	if e != nil {
		if decInactiveRead(dec.Code(e)) {
			return productPolicy{}, false, nil
		}
		return productPolicy{}, false, e
	}
	body, e := decPolicyBody(statement)
	if e != nil {
		return productPolicy{}, false, e
	}
	return productPolicy{PolicyBody: body.delta(), Version: body.Version, ValidUntil: decEarlier(body.After, path.NotAfter), statement: statement}, true, nil
}

// Check only the current local owner's name obligations, before an active-only
// listing can discard an unknown policy head. The final create repeats this in
// its held transaction; no provider is opened and no candidate supplies facts.
func (s *Store) checkDecCapabilityNames(ctx context.Context, q dbQuerier) error {
	ids, e := s.networkIDs(ctx, q)
	if e != nil {
		return e
	}
	for _, id := range ids {
		modern, e := decContextMode(ctx, q, id)
		if e != nil {
			return e
		}
		if !modern {
			continue
		}
		g, e := s.loadProductGovernance(ctx, q, id)
		if e != nil {
			return e
		}
		if e = decCapabilityReadRoot(g.projection); e != nil {
			return e
		}
		// No admitted local membership/binding means no current local-person
		// claim obligation. A remembered head with missing bytes stays known
		// and reaches the exact proof/fork checks below instead of disappearing.
		if !decCapabilityKnownHead(g.projection, "host", s.identity.PublicKey) || !decCapabilityKnownHead(g.projection, "binding", s.identity.PublicKey) {
			continue
		}
		own, e := decCurrentMember(g.projection, s.identity.PublicKey)
		if e != nil {
			if decInactiveRead(dec.Code(e)) {
				continue
			}
			return e
		}
		if own.BindingError != nil {
			if decInactiveRead(dec.Code(own.BindingError)) {
				continue
			}
			return own.BindingError
		}
		if own.View.Person != "-" {
			if _, _, e = checkedDecCapabilityPolicy(g.projection, own.View.Person); e != nil {
				return e
			}
		}
	}
	return nil
}
