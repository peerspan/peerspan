package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/linking"
)

type decMigrationSource struct {
	Network                Network
	Descriptor             dec.Descriptor
	Legacy, Catalog, State []byte
	Feature, Time          string
	Facts                  linking.NetworkState
	Snapshot               *dec.SourceState
}

// All bytes and remembered floors come from this same local read/write TX.
// Cached host tuples/hints supply exact historical proof bytes only; the old
// verifier independently derives membership, bindings, restrictions and root.
func (s *Store) decMigrationSource(ctx context.Context, q dbQuerier, network string) (*decMigrationSource, error) {
	n, e := scanNetwork(q.QueryRowContext(ctx, networkColumns+" WHERE id=?", network))
	if e != nil {
		return nil, e
	}
	at, e := decCreationClock(ctx, q, network)
	if e != nil {
		return nil, e
	}
	now, e := dec.ParseTime(at)
	if e != nil {
		return nil, e
	}
	legacy, e := json.Marshal(linkNetworkDescriptor(n))
	if e != nil {
		return nil, e
	}
	descriptor, e := json.Marshal(dec.Descriptor{Format: 1, Protocol: dec.Protocol, NetworkID: n.ID, Name: n.Name, GenesisRootPublicKey: n.RootPublicKey})
	if e != nil {
		return nil, e
	}
	d, e := dec.ReadDescriptor(descriptor)
	if e != nil {
		return nil, e
	}
	old, e := readLinkCatalog(ctx, q, network)
	if e != nil {
		return nil, e
	}
	rows, e := legacyLinkCatalogSnapshot(ctx, q, n)
	if e != nil {
		return nil, e
	}
	catalog, e := mergeLinkCatalog(network, old, rows)
	if e != nil {
		return nil, e
	}
	if len(catalog) > 512<<10 {
		return nil, decFailure("quota_exceeded")
	}
	objects, e := decodeLinkCatalog(catalog, network)
	if e != nil {
		return nil, e
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return nil, e
	}
	if n.RootEpoch < 0 || uint64(n.RootEpoch) > epoch {
		return nil, decFailure("state_conflict")
	}
	feature, _, e := readLinkFeature(ctx, q, network)
	if e != nil {
		return nil, e
	}
	facts, e := linking.VerifyStoredLegacyMigrationSource(linking.CatalogFactContext{Network: legacy, Epoch: epoch, KnownFeatureID: feature, Now: now}, catalog)
	if e != nil {
		return nil, decLegacyError(e)
	}
	if facts.RootPublicKey != n.CurrentRootPublicKey || facts.Epoch != epoch {
		return nil, decFailure("state_conflict")
	}
	policies, groups, e := readLinkHighWater(ctx, q, network)
	if e != nil {
		return nil, e
	}
	access, e := linking.VerifyStoredLegacyMigrationAccess(linking.AccessContext{Network: legacy, Epoch: epoch, KnownFeatureID: feature, Now: now, PriorPolicies: policies, PriorGroups: groups}, catalog)
	if e != nil {
		return nil, decLegacyError(e)
	}
	state := dec.SourceState{Format: 1, NetworkID: network, RootMaximum: epoch, Hosts: []string{}, Maxima: []dec.LegacyMaximum{}, Restrictions: []dec.LegacyRestriction{}}
	for _, policy := range access.Policies {
		state.Maxima = append(state.Maxima, dec.LegacyMaximum{Kind: "policy", Subject: policy.PersonPublicKey, Version: policy.Version, Hash: policy.MessageHash})
	}
	for _, group := range access.Groups {
		state.Maxima = append(state.Maxima, dec.LegacyMaximum{Kind: "group", Subject: group.Name, Version: group.Version, Hash: group.MessageHash})
	}
	// Retain even an inactive/missing body's independently remembered floor.
	floors := map[string]dec.LegacyMaximum{}
	for _, floor := range state.Maxima {
		floors[floor.Kind+"\x00"+floor.Subject] = floor
	}
	remember := func(kind, subject string, floor linking.AccessHighWater) error {
		key := kind + "\x00" + subject
		if previous, ok := floors[key]; ok && (previous.Version < floor.Version || previous.Version == floor.Version && previous.Hash != floor.MessageHash) {
			return decFailure("state_conflict")
		}
		if _, ok := floors[key]; !ok {
			floors[key] = dec.LegacyMaximum{Kind: kind, Subject: subject, Version: floor.Version, Hash: floor.MessageHash}
		}
		return nil
	}
	for _, floor := range policies {
		if e = remember("policy", floor.PersonPublicKey, floor.AccessHighWater); e != nil {
			return nil, e
		}
	}
	for _, floor := range groups {
		if e = remember("group", floor.Name, floor.AccessHighWater); e != nil {
			return nil, e
		}
	}
	state.Maxima = []dec.LegacyMaximum{}
	for _, floor := range floors {
		state.Maxima = append(state.Maxima, floor)
	}
	sort.Slice(state.Maxima, func(i, j int) bool {
		a, b := state.Maxima[i], state.Maxima[j]
		return a.Kind < b.Kind || a.Kind == b.Kind && a.Subject < b.Subject
	})
	// An exact locally applied restriction marker/statement is private admission
	// evidence. Mere presence of an inert catalog proof is not such a marker.
	sticky := map[string]bool{}
	markers, e := readLinkRestrictionMarkers(ctx, q, network)
	if e != nil {
		return nil, e
	}
	for _, id := range markers {
		sticky[id] = true
	}
	local, e := decodeLinkCatalog(rows, network)
	if e != nil {
		return nil, e
	}
	for _, object := range local.Objects {
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return nil, e
		}
		if linkRestrictiveProof(object.Kind, body) {
			sticky[object.ID] = true
		}
	}
	seen := map[string]bool{}
	removedHosts := map[string]bool{}
	for _, object := range objects.Objects {
		if !facts.RestrictionApplies(object.ID) && !sticky[object.ID] {
			continue
		}
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return nil, e
		}
		restriction, ban, restrictive, e := dec.MigrationSourceRestriction(object.ID, object.Kind, body)
		if e != nil {
			return nil, e
		}
		if !restrictive {
			continue
		}
		state.Restrictions = append(state.Restrictions, restriction)
		seen[object.ID] = true
		if ban == "host_revoke" {
			removedHosts[restriction.Host] = true
		}
	}
	for id := range sticky {
		if !seen[id] {
			return nil, decFailure("proof_required", id)
		}
	}
	for _, member := range facts.Members {
		if !removedHosts[member.HostPublicKey] {
			state.Hosts = append(state.Hosts, member.HostPublicKey)
		}
	}
	// Removed-person members remain admitted unbound hosts; the strict source
	// reader derives that distinction from the exact copied restriction set.
	sort.Strings(state.Hosts)
	sort.Slice(state.Restrictions, func(i, j int) bool { return state.Restrictions[i].ProofID < state.Restrictions[j].ProofID })
	stateRaw, e := json.Marshal(state)
	if e != nil {
		return nil, e
	}
	if len(stateRaw) > dec.MaxPayload {
		return nil, decFailure("quota_exceeded")
	}
	verified, facts, e := dec.VerifyMigrationSourceSnapshot(d, legacy, catalog, stateRaw, epoch, feature, facts.RootPublicKey, at)
	if e != nil {
		return nil, e
	}
	return &decMigrationSource{Network: n, Descriptor: d, Legacy: legacy, Catalog: catalog, State: stateRaw, Feature: feature, Time: at, Facts: facts, Snapshot: verified}, nil
}

func decLegacyError(e error) error {
	var path *linking.PathError
	if errors.As(e, &path) {
		return decFailure(path.Code, path.RequiredIDs...)
	}
	return e
}

// The source snapshot is a read, not migration approval or a clock write.
func (s *Store) readDecMigrationSource(ctx context.Context, network string) (*decMigrationSource, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	return s.decMigrationSource(ctx, tx, network)
}
