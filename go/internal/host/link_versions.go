package host

import (
	"context"
	"sort"

	"github.com/peerspan/peerspan/go/internal/linking"
)

type LinkAccessVersions struct {
	Policies []linking.PolicyHighWater `json:"policies"`
	Groups   []linking.GroupHighWater  `json:"groups"`
}

func (s *Store) LinkAccessVersions(ctx context.Context, network string) (LinkAccessVersions, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, network)
	if e != nil {
		return LinkAccessVersions{}, e
	}
	now, e := linkNow()
	if e != nil {
		return LinkAccessVersions{}, e
	}
	p, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return LinkAccessVersions{}, e
	}
	if p == nil {
		return LinkAccessVersions{}, linkFail("upgrade_required", "-", "feature")
	}
	out := LinkAccessVersions{Policies: []linking.PolicyHighWater{}, Groups: []linking.GroupHighWater{}}
	for _, selected := range p.Access.Policies {
		out.Policies = append(out.Policies, linking.PolicyHighWater{PersonPublicKey: selected.PersonPublicKey, AccessHighWater: selected.AccessHighWater})
	}
	for _, selected := range p.Access.Groups {
		out.Groups = append(out.Groups, linking.GroupHighWater{Name: selected.Name, AccessHighWater: selected.AccessHighWater})
	}
	sort.Slice(out.Policies, func(i, j int) bool { return out.Policies[i].PersonPublicKey < out.Policies[j].PersonPublicKey })
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].Name < out.Groups[j].Name })
	return out, nil
}
func linkPolicyVersion(ctx context.Context, q dbQuerier, network, personID string) (uint64, error) {
	policies, _, e := readLinkHighWater(ctx, q, network)
	if e != nil {
		return 0, e
	}
	for _, policy := range policies {
		if personIDOf(policy.PersonPublicKey) == personID {
			return policy.Version, nil
		}
	}
	return 0, nil
}
