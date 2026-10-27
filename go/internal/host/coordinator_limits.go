package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
)

// DefaultCoordinator and DefaultCoordinatorKey name the coordinator network
// create uses without --coordinator and --coordinator-key. Builds set both
// with -ldflags -X; a build without both has no default.
var (
	DefaultCoordinator    = ""
	DefaultCoordinatorKey = ""
)

// CoordinatorEndpoint is a coordinator address with its pinned key.
type CoordinatorEndpoint struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

// HostInfo is the public host identity and supported network protocols.
type HostInfo struct {
	Identity
	DefaultCoordinator *CoordinatorEndpoint `json:"default_coordinator"`
	NetworkProtocols   []string             `json:"network_protocols"`
}

func defaultCoordinator() *CoordinatorEndpoint {
	if DefaultCoordinator == "" || DefaultCoordinatorKey == "" {
		return nil
	}
	return &CoordinatorEndpoint{Address: DefaultCoordinator, PublicKey: DefaultCoordinatorKey}
}

// Info advertises the coordinator-free launch protocol. Legacy fixture
// configuration is never advertised as new-network authority.
func (s *Store) Info() HostInfo {
	return HostInfo{Identity: s.identity, NetworkProtocols: []string{"peerspan-decentralized-v1"}}
}

// withDefaultCoordinator fills an omitted coordinator from the build's
// default; one of the two alone is refused.
func withDefaultCoordinator(r CreateNetwork) (CreateNetwork, error) {
	switch {
	case r.CoordinatorAddress != "" && r.CoordinatorPublicKey != "":
		return r, nil
	case r.CoordinatorAddress != "" || r.CoordinatorPublicKey != "":
		return r, fmt.Errorf("%w: give both --coordinator and --coordinator-key, or neither", ErrInvalid)
	}
	d := defaultCoordinator()
	if d == nil {
		return r, fmt.Errorf("%w: this build has no default coordinator; pass --coordinator and --coordinator-key", ErrInvalid)
	}
	r.CoordinatorAddress, r.CoordinatorPublicKey = d.Address, d.PublicKey
	return r, nil
}

// CoordinatorLimitError is a coordinator's 429: a limit refused the request.
type CoordinatorLimitError struct {
	Limit, Message string
}

func (e *CoordinatorLimitError) Error() string {
	return fmt.Sprintf("%v: coordinator limit %s reached: %s", ErrUnavailable, e.Limit, e.Message)
}

func (e *CoordinatorLimitError) Unwrap() error { return ErrUnavailable }

// coordinatorUsage is GET /coord/v1/networks/{id}/usage.
type coordinatorUsage struct {
	Members       int64  `json:"members"`
	MaxMembers    int64  `json:"max_members"`
	RelayBytes    int64  `json:"relay_bytes"`
	MaxRelayBytes int64  `json:"max_relay_bytes"`
	Month         string `json:"month"`
}

// coordinatorLimits remembers, per network, the usage fetched after the last
// successful sync and the limit named by the last 429, until a later sync or
// join succeeds. It is in memory: the first sync after a restart refills it.
type coordinatorLimits struct {
	sync.Mutex
	usage   map[string]coordinatorUsage
	refused map[string]string
}

func (s *Store) limitRefused(network, limit string) {
	s.limits.Lock()
	defer s.limits.Unlock()
	if s.limits.refused == nil {
		s.limits.refused = map[string]string{}
	}
	s.limits.refused[network] = limit
}

// refreshUsage forgets a remembered refusal after a successful sync or join
// and fetches the network's usage. A 404 is an older coordinator without
// limits; other failures keep the previous usage.
func (s *Store) refreshUsage(ctx context.Context, n Network) {
	s.limits.Lock()
	delete(s.limits.refused, n.ID)
	s.limits.Unlock()
	data, err := s.coordinatorRequest(ctx, n, http.MethodGet, "/coord/v1/networks/"+url.PathEscape(n.ID)+"/usage", nil)
	var u coordinatorUsage
	if err == nil {
		err = json.Unmarshal(data, &u)
	}
	s.limits.Lock()
	defer s.limits.Unlock()
	switch {
	case err == nil:
		if s.limits.usage == nil {
			s.limits.usage = map[string]coordinatorUsage{}
		}
		s.limits.usage[n.ID] = u
	case errors.Is(err, ErrNotFound):
		delete(s.limits.usage, n.ID)
	}
}

// limitAttention reports each network's reached coordinator limits: from
// usage for networks this host is in, and from a 429, which may name a
// network a join was refused for.
func (s *Store) limitAttention(networks []NetworkStatus, attend func(kind, subject, detail, command string)) {
	s.limits.Lock()
	defer s.limits.Unlock()
	reached := map[string]string{}
	for _, n := range networks {
		u, ok := s.limits.usage[n.ID]
		if !ok {
			continue
		}
		if u.MaxMembers > 0 && u.Members >= u.MaxMembers {
			reached[n.ID+"/members"] = fmt.Sprintf("the network has %d of at most %d member hosts on its coordinator", u.Members, u.MaxMembers)
		}
		if u.MaxRelayBytes > 0 && u.RelayBytes >= u.MaxRelayBytes {
			reached[n.ID+"/relay_bytes"] = fmt.Sprintf("the network has relayed %d of at most %d bytes through its coordinator in %s; relayed traffic is dropped until next month", u.RelayBytes, u.MaxRelayBytes, u.Month)
		}
	}
	for network, limit := range s.limits.refused {
		reached[network+"/"+limit] = "the coordinator refused a request at its " + limit + " limit"
	}
	subjects := make([]string, 0, len(reached))
	for subject := range reached {
		subjects = append(subjects, subject)
	}
	sort.Strings(subjects)
	for _, subject := range subjects {
		attend("coordinator_limit", subject, reached[subject], "")
	}
}
