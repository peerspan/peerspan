package decentralized

import (
	"encoding/json"
	"time"
)

type RootRetentionCandidate struct {
	Statement string   `json:"statement_id"`
	Kind      string   `json:"kind"`
	Required  []string `json:"required_retained_ids"`
	Scopes    uint64   `json:"effective_scopes"`
	After     string   `json:"effective_not_after"`
}
type RootRetentionExcluded struct {
	Statement string   `json:"statement_id"`
	Code      string   `json:"code"`
	Required  []string `json:"required_ids"`
}

// This view is used only for retaining already signed finite contributions.
// No caller can turn it into a current root, provider or ordinary action view.
func (a *authority) rootRetentionCandidate(s *Statement) (RootRetentionCandidate, error) {
	result := RootRetentionCandidate{Statement: s.ID, Kind: s.Kind, Required: []string{}, Scopes: 15, After: "-"}
	if a.originConflict {
		return result, failure("state_conflict")
	}
	if s.Lease == nil && s.Access == nil {
		return result, invalid()
	}
	rootHeads := a.heads["root"]
	if len(rootHeads) == 0 {
		return result, failure("proof_required")
	}
	needed := map[string]bool{}
	for _, id := range rootHeads {
		root, e := a.graph.get(id)
		if e != nil {
			return result, e
		}
		if root.Root == nil || !a.admitted[id] {
			return result, invalid()
		}
		if root.issuedTime().After(a.now) {
			return result, failure("not_yet_valid")
		}
		view := *a
		view.heads = map[string][]string{}
		for key, heads := range a.heads {
			view.heads[key] = heads
		}
		view.heads["root"] = []string{id}
		view.maxima = map[string]uint64{}
		for key, n := range a.maxima {
			view.maxima[key] = n
		}
		view.maxima["root"] = root.Root.Epoch
		view.proven = map[string]bool{}
		path, e := view.evaluate(s)
		if e != nil {
			return result, e
		}
		result.Scopes &= path.Scopes
		result.After = minAfter(result.After, path.After)
		for finite := range view.proven {
			statement, e := a.graph.get(finite)
			if e != nil {
				return result, e
			}
			if statement.Lease != nil || statement.Access != nil {
				needed[finite] = true
			}
		}
	}
	// A conditional administrator bit does not mint the subject's admin role.
	// That role remains an independent stream; a missing/inactive role does not
	// erase the device's independently surviving policy/owner powers.
	if s.Kind == "device_lease" && result.Scopes&8 != 0 {
		role, e := a.selected([]string{"admin", s.Lease.Subject.Person})
		if e != nil {
			if Code(e) == "proof_required" && len(a.heads[streamKey([]string{"admin", s.Lease.Subject.Person})]) > 0 {
				return result, e
			}
			result.Scopes &^= 8
		} else {
			admin, e := a.rootRetentionCandidate(role)
			if e != nil {
				if Code(e) == "proof_required" {
					return result, e
				}
				result.Scopes &^= 8
			} else {
				for _, id := range admin.Required {
					needed[id] = true
				}
				result.After = minAfter(result.After, admin.After)
			}
		}
	}
	result.Required = keysSorted(needed)
	return result, nil
}

func (p *Projection) RootRetention() ([]RootRetentionCandidate, []RootRetentionExcluded, error) {
	candidates := []RootRetentionCandidate{}
	excluded := []RootRetentionExcluded{}
	if p.authority.originConflict {
		return nil, nil, failure("state_conflict")
	}
	if p.Root.Code != "-" && p.Root.Code != "state_conflict" {
		return nil, nil, failure(p.Root.Code, p.Root.RequiredIDs...)
	}
	for _, id := range p.Root.HeadIDs {
		root, e := p.authority.graph.get(id)
		if e != nil {
			return nil, nil, e
		}
		if root.Root == nil || !p.authority.admitted[id] {
			return nil, nil, invalid()
		}
	}
	heads := map[string]bool{}
	bytes := 0
	for key, ids := range p.authority.heads {
		if key != "root" {
			for _, id := range ids {
				heads[id] = true
			}
		}
	}
	for _, id := range keysSorted(heads) {
		s, e := p.authority.graph.get(id)
		if e == nil && s.Lease == nil && s.Access == nil {
			continue
		}
		var candidate RootRetentionCandidate
		if e == nil {
			candidate, e = p.authority.rootRetentionCandidate(s)
		}
		if e != nil {
			entry := RootRetentionExcluded{id, Code(e), RequiredIDs(e)}
			raw, _ := json.Marshal(entry)
			bytes += len(raw) + 1
			if bytes > 32<<20 {
				return nil, nil, failure("quota_exceeded")
			}
			excluded = append(excluded, entry)
			continue
		}
		raw, _ := json.Marshal(candidate)
		bytes += len(raw) + 1
		if bytes > 32<<20 {
			return nil, nil, failure("quota_exceeded")
		}
		candidates = append(candidates, candidate)
	}
	return candidates, excluded, nil
}

// An old finite ancestor may survive only as the exact contribution required
// by an eligible selected beneficiary. It need not be an active independent
// role (for example a withdrawn admin whose kept P/H remain valid).
func (a *authority) validateRootRetention(ids []string, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	if a.originConflict {
		return failure("state_conflict")
	}
	view := *a
	view.now = at
	requested := setOf(ids)
	covered := map[string]bool{}
	denied := map[string]error{}
	current := map[string]bool{}
	for key, heads := range view.heads {
		if key != "root" {
			for _, id := range heads {
				current[id] = true
			}
		}
	}
	for _, id := range ids {
		if !current[id] {
			continue
		}
		s, e := view.graph.get(id)
		if e != nil {
			return e
		}
		candidate, e := view.rootRetentionCandidate(s)
		if e != nil {
			// A role denied on its own can still be an exact contribution of
			// another selected beneficiary. Missing dependencies stay repair.
			if Code(e) == "proof_required" {
				return e
			}
			denied[id] = e
			continue
		}
		for _, required := range candidate.Required {
			if !requested[required] {
				return failure("forbidden")
			}
			covered[required] = true
		}
	}
	for _, id := range ids {
		if !covered[id] {
			if e := denied[id]; e != nil {
				return e
			}
			return failure("forbidden")
		}
	}
	return nil
}
