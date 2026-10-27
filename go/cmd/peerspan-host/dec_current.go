package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// These are display/name-resolution facts from current private read APIs. They
// supply no reusable proof, signer selection or authority for later mutations.
func decCurrentPeople(ctx context.Context, client host.Client, network host.DecNetworkView) ([]host.Person, error) {
	view, e := call[struct {
		Context string               `json:"context_id"`
		Persons []host.DecPersonView `json:"persons"`
	}](ctx, client, "GET", decNetworkPath(network.ID)+"/persons")
	if e != nil {
		return nil, e
	}
	if view.Context != network.Context || view.Persons == nil || len(view.Persons) > 4096 {
		return nil, errors.New("the current person view changes its network context")
	}
	people := []host.Person{}
	index := map[string]int{}
	last := ""
	for _, p := range view.Persons {
		public, e := membership.DecodeKey(p.Person)
		if e != nil || p.Person <= last || !membership.ValidLabel(p.Member) || !dec.ValidID(p.Lease, "ds_") {
			return nil, errors.New("invalid current person admission view")
		}
		if _, e = dec.ParseTime(p.NotAfter); e != nil {
			return nil, e
		}
		last = p.Person
		index[p.Person] = len(people)
		people = append(people, host.Person{PersonID: membership.PersonID(public), PublicKey: p.Person, Member: p.Member, Hosts: []string{}})
	}
	members, e := call[struct {
		Context string               `json:"context_id"`
		Members []host.DecMemberView `json:"members"`
	}](ctx, client, "GET", decNetworkPath(network.ID)+"/members")
	if e != nil {
		return nil, e
	}
	if members.Context != network.Context {
		return nil, errors.New("the current member view changes its network context")
	}
	for _, m := range members.Members {
		if n, ok := index[m.Person]; ok {
			public, e := membership.DecodeKey(m.Host)
			if e != nil {
				return nil, e
			}
			people[n].Hosts = append(people[n].Hosts, membership.HostID(public))
		}
	}
	for n := range people {
		sort.Strings(people[n].Hosts)
		for m := range people {
			if n != m && membership.LabelsConflict(people[n].Member, people[m].Member) {
				people[n].LabelConflict = true
			}
		}
	}
	return people, nil
}

func decReadCurrentPolicy(ctx context.Context, client host.Client, network host.DecNetworkView, person string) (*dec.Statement, error) {
	view, e := call[host.DecPolicyStatementView](ctx, client, "GET", decNetworkPath(network.ID)+"/policy/"+url.PathEscape(person))
	if e != nil {
		return nil, e
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(view.Body)
	if e != nil || len(raw) > dec.MaxObject || base64.StdEncoding.EncodeToString(raw) != view.Body {
		return nil, errors.New("invalid exact current policy bytes")
	}
	d, e := decLinkDescriptor(network)
	if e != nil {
		return nil, e
	}
	statement, e := dec.ReadStatement(d, raw)
	if e != nil {
		return nil, e
	}
	if statement.ID != view.Statement || statement.Kind != "policy" || statement.Access == nil || statement.Access.Issuer.Person != person {
		return nil, errors.New("the current policy changes its exact person or statement")
	}
	return statement, nil
}
