package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type capabilityNetwork struct {
	ID     string
	Modern *host.DecNetworkView
}

// History is not a current binding or an invitation to prepare fresh claims.
// A DEC network never enters the legacy collection/policy codec.
func capabilityNetworks(ctx context.Context, client host.Client) ([]capabilityNetwork, error) {
	raw, e := client.Call(ctx, "GET", "/v2/status", nil)
	if e != nil {
		return nil, e
	}
	status, modern, e := decodeStatus(raw)
	if e != nil {
		return nil, e
	}
	var tagged struct {
		Networks []struct {
			ID   string `json:"id"`
			Mode string `json:"mode"`
		} `json:"networks"`
	}
	if json.Unmarshal(raw, &tagged) != nil {
		return nil, errors.New("invalid network status")
	}
	history := map[string]bool{}
	for _, n := range tagged.Networks {
		history[n.ID] = n.Mode == "legacy_history"
	}
	result := []capabilityNetwork{}
	for _, n := range status.Networks {
		if !history[n.ID] {
			result = append(result, capabilityNetwork{ID: n.ID})
		}
	}
	for _, n := range modern {
		n := n
		result = append(result, capabilityNetwork{ID: n.ID, Modern: &n})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	for n := range result {
		if result[n].ID == "" || n > 0 && result[n-1].ID == result[n].ID {
			return nil, errors.New("invalid duplicate network status")
		}
	}
	return result, nil
}

func capabilityPolicyRules(ctx context.Context, client host.Client, n capabilityNetwork, person host.Person) ([]membership.CapabilityRule, error) {
	if n.Modern == nil {
		policy, e := currentPolicy(ctx, client, n.ID, person.PersonID)
		if e != nil || policy == nil {
			return nil, e
		}
		return policy.CapabilityRules, nil
	}
	statement, e := decReadCurrentPolicy(ctx, client, *n.Modern, person.PublicKey)
	var failure *host.ClientError
	if errors.As(e, &failure) && failure.Status == 404 {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	body, e := decContent(statement)
	return body.CapabilityRules, e
}

func capabilityPeople(ctx context.Context, client host.Client, n capabilityNetwork) ([]host.Person, error) {
	if n.Modern != nil {
		return decCurrentPeople(ctx, client, *n.Modern)
	}
	return personsOf(ctx, client, n.ID)
}
