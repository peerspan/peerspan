package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecAuthorityView struct {
	State     string   `json:"state"`
	NotAfter  string   `json:"not_after"`
	Required  []string `json:"required_ids"`
	Conflicts []string `json:"conflict_ids"`
}
type DecProviderState struct {
	State    string   `json:"state"`
	Code     string   `json:"code"`
	Error    string   `json:"error"`
	Required []string `json:"required_ids"`
}
type DecProviderView struct {
	Kind     string `json:"kind"`
	Person   string `json:"person_public_key"`
	Host     string `json:"host_public_key"`
	Device   string `json:"device_public_key"`
	Lease    string `json:"lease_id"`
	Root     string `json:"root_state_id"`
	Scopes   uint64 `json:"scopes"`
	NotAfter string `json:"not_after"`
}
type DecPeerError struct {
	Host string `json:"host_public_key"`
	Code string `json:"code"`
}
type DecDeliveryView struct {
	Proofs []string       `json:"pending_proof_ids"`
	Errors []DecPeerError `json:"peer_errors"`
}
type DecNetworkView struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Mode          string           `json:"mode"`
	Context       string           `json:"context_id"`
	Genesis       string           `json:"genesis_root_public_key"`
	Root          string           `json:"root_state_id"`
	RootKey       string           `json:"root_public_key"`
	RootEpoch     uint64           `json:"root_epoch"`
	Member        string           `json:"member"`
	Host          string           `json:"host_public_key"`
	Person        string           `json:"person_public_key"`
	Provider      *DecProviderView `json:"provider"`
	ProviderState DecProviderState `json:"provider_state"`
	Authority     DecAuthorityView `json:"authority"`
	Delivery      DecDeliveryView  `json:"delivery"`
	Created       string           `json:"created_at"`
}
type DecMemberView struct {
	Host      string `json:"host_public_key"`
	Member    string `json:"member"`
	Person    string `json:"person_public_key"`
	HostLease string `json:"host_lease_id"`
	Binding   string `json:"binding_lease_id"`
	Device    string `json:"device_lease_id"`
	NotAfter  string `json:"not_after"`
}
type decMemberPath struct {
	View         DecMemberView
	Binding      *dec.Statement
	Path         dec.Path
	BindingError error
}

func decEarlier(a, b string) string {
	if a == "-" || a == "" {
		return b
	}
	if b == "-" || b == "" || a < b {
		return a
	}
	return b
}
func decUnavailable(e error) DecProviderState {
	code := dec.Code(e)
	if errors.Is(e, ErrNotFound) {
		code = "not_found"
	}
	return DecProviderState{"unavailable", code, code, dec.RequiredIDs(e)}
}
func decAvailable() DecProviderState { return DecProviderState{"available", "-", "-", []string{}} }
func decFailure(code string, ids ...string) error {
	return &dec.Failure{Code: code, RequiredIDs: append([]string{}, ids...)}
}

func decCurrentMember(p *dec.Projection, host string) (decMemberPath, error) {
	var result decMemberPath
	h, path, e := p.Current([]string{"host", host})
	if e != nil {
		return result, e
	}
	result.View = DecMemberView{Host: host, Member: h.Lease.Subject.Member, Person: "-", HostLease: h.ID, Binding: "-", Device: "-", NotAfter: path.NotAfter}
	result.Path = path
	b, bpath, e := p.Current([]string{"binding", host})
	if e != nil {
		result.BindingError = e
		return result, nil
	}
	if b.Lease.Subject.Host != host {
		return result, decFailure("forbidden")
	}
	result.Binding = b
	result.View.Person = b.Lease.Subject.Person
	result.View.Binding = b.ID
	result.View.NotAfter = decEarlier(path.NotAfter, bpath.NotAfter)
	return result, nil
}
func decAuthority(s *decSnapshot, p *dec.Projection) DecAuthorityView {
	result := DecAuthorityView{State: "usable", NotAfter: "-", Required: []string{}, Conflicts: []string{}}
	if len(s.Fenced) > 0 {
		result.State = "migration_pending"
		result.Conflicts = append([]string{}, s.Fenced...)
		return result
	}
	member, e := decCurrentMember(p, s.Network.Own.Host)
	if e == nil {
		result.NotAfter = member.View.NotAfter
		e = member.BindingError
		if e != nil {
			hasBinding := false
			for _, stream := range p.Streams {
				if len(stream.Stream) == 2 && stream.Stream[0] == "binding" && stream.Stream[1] == s.Network.Own.Host {
					hasBinding = true
					break
				}
			}
			if !hasBinding {
				result.State = "unbound"
				return result
			}
		}
	}
	if e != nil {
		result.NotAfter = "-"
		result.State = dec.Code(e)
		result.Required = dec.RequiredIDs(e)
		if result.State == "state_conflict" {
			result.Conflicts = decConflictIDs(p, s.Network.Own.Host)
		}
	}
	return result
}
func decConflictIDs(p *dec.Projection, host string) []string {
	ids := map[string]bool{}
	if p.Root.Conflicted {
		for _, id := range p.Root.HeadIDs {
			ids[id] = true
		}
	}
	for _, stream := range p.Streams {
		if stream.Code == "state_conflict" && len(stream.Stream) > 1 && (stream.Stream[1] == host) {
			for _, id := range stream.HeadIDs {
				ids[id] = true
			}
		}
	}
	result := []string{}
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func decPublicProvider(s *decSnapshot, p *dec.Projection) (*DecProviderView, error) {
	selected := s.Provider
	if selected == nil {
		return nil, ErrNotFound
	}
	view := &DecProviderView{Person: selected.Person, Host: s.Network.Own.Host, Device: selected.Device, Lease: selected.Lease, Root: p.Root.SelectedID, NotAfter: "-"}
	if selected.Kind == "device" {
		view.Kind = "device"
	} else {
		view.Kind = "original_person"
	}
	// Fill only exact remembered public selection information before evaluating
	// current power; an expired/missing path does not erase the selected identity.
	if selected.Kind == "device" {
		if d := s.Catalog.Statements[selected.Lease]; d != nil && d.Lease != nil {
			view.NotAfter = d.Lease.After
		}
	}
	if selected.Kind == "original" {
		for _, stream := range p.Streams {
			if len(stream.Stream) == 2 && stream.Stream[0] == "person" && stream.Stream[1] == selected.Person {
				view.Lease = stream.SelectedID
				if person := s.Catalog.Statements[stream.SelectedID]; person != nil && person.Lease != nil {
					view.NotAfter = person.Lease.After
				}
			}
		}
	}
	if len(s.Fenced) > 0 {
		return view, decFailure("migration_pending", s.Fenced...)
	}
	member, e := decCurrentMember(p, s.Network.Own.Host)
	if e != nil {
		return view, e
	}
	if member.BindingError != nil {
		return view, member.BindingError
	}
	if member.View.Person != selected.Person {
		return view, decFailure("forbidden")
	}
	if selected.Kind == "original" {
		person, path, e := p.Current([]string{"person", selected.Person})
		if e != nil {
			return view, e
		}
		view.Lease = person.ID
		view.Scopes = 7
		view.NotAfter = decEarlier(member.View.NotAfter, path.NotAfter)
		if _, admin, e := p.Current([]string{"admin", selected.Person}); e == nil {
			view.Scopes |= 8
			view.NotAfter = decEarlier(view.NotAfter, admin.NotAfter)
		}
	} else {
		d, path, e := p.StatementPath(selected.Lease)
		if e != nil {
			return view, e
		}
		if d.Kind != "device_lease" || d.Lease.Subject.Person != selected.Person || d.Lease.Subject.Host != s.Network.Own.Host || d.Lease.Subject.Device != selected.Device {
			return view, decFailure("forbidden")
		}
		view.Scopes = path.Scopes
		view.NotAfter = decEarlier(member.View.NotAfter, path.NotAfter)
		if view.Scopes&8 != 0 {
			if _, admin, e := p.Current([]string{"admin", selected.Person}); e != nil {
				view.Scopes &= 7
			} else {
				view.NotAfter = decEarlier(view.NotAfter, admin.NotAfter)
			}
		}
		if view.Scopes == 0 {
			return view, decFailure("forbidden")
		}
	}
	return view, nil
}
func (s *Store) decProviderAvailable(snapshot *decSnapshot, view *DecProviderView, publicErr error) DecProviderState {
	if publicErr != nil {
		return decUnavailable(publicErr)
	}
	// A selected owned device remains a device even when its seed is missing.
	if snapshot.Provider != nil && snapshot.Provider.Kind == "device" {
		if len(snapshot.DeviceSeed) != ed25519.SeedSize {
			return decUnavailable(decFailure("signer_unavailable"))
		}
		key := ed25519.NewKeyFromSeed(snapshot.DeviceSeed)
		if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != snapshot.Provider.Device {
			return decUnavailable(decFailure("signer_unavailable"))
		}
	}
	if snapshot.Provider.Kind == "original" {
		key, e := membership.DecodeKey(snapshot.Provider.Person)
		if e != nil {
			return decUnavailable(decFailure("signer_unavailable"))
		}
		signer, e := s.renewalSigner(key)
		if e != nil {
			return decUnavailable(decFailure("signer_unavailable"))
		}
		signer.Close()
	}
	return decAvailable()
}
func (s *Store) decNetworkView(snapshot *decSnapshot, p *dec.Projection) DecNetworkView {
	result, e := decNetworkViewPublic(snapshot, p)
	if snapshot.Provider != nil {
		result.ProviderState = s.decProviderAvailable(snapshot, result.Provider, e)
	}
	return result
}
func decNetworkViewPublic(snapshot *decSnapshot, p *dec.Projection) (DecNetworkView, error) {
	n := snapshot.Network
	d := snapshot.Descriptor
	result := DecNetworkView{ID: d.NetworkID, Name: d.Name, Mode: "decentralized", Context: d.ContextID, Genesis: d.GenesisRootPublicKey, Root: p.Root.SelectedID, RootKey: "-", RootEpoch: p.Root.Maximum, Member: n.Own.Member, Host: n.Own.Host, Person: n.Own.Person, Created: n.Created, Authority: decAuthority(snapshot, p), Delivery: snapshot.Delivery, ProviderState: DecProviderState{"not_selected", "-", "-", []string{}}}
	if p.Root.Code == "-" {
		if root := snapshot.Catalog.Statements[p.Root.SelectedID]; root != nil {
			result.RootKey = root.Root.Key
		}
	}
	if snapshot.Provider != nil {
		provider, e := decPublicProvider(snapshot, p)
		result.Provider = provider
		if e != nil {
			result.ProviderState = decUnavailable(e)
			return result, e
		}
		result.ProviderState = decAvailable()
	}
	return result, nil
}
func (s *Store) DecentralizedNetwork(ctx context.Context, id string) (DecNetworkView, error) {
	now, e := decNow()
	if e != nil {
		return DecNetworkView{}, e
	}
	snapshot, p, e := s.decentralizedProjection(ctx, id, linkTime(now))
	if e != nil {
		return DecNetworkView{}, e
	}
	return s.decNetworkView(snapshot, p), nil
}
func (s *Store) DecentralizedNetworks(ctx context.Context) ([]DecNetworkView, error) {
	now, e := decNow()
	if e != nil {
		return nil, e
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, `SELECT id,record FROM networks ORDER BY id`)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id, raw string
		if e = rows.Scan(&id, &raw); e != nil {
			rows.Close()
			return nil, e
		}
		var tag struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal([]byte(raw), &tag) != nil {
			rows.Close()
			return nil, decStorageError()
		}
		if tag.Mode == "decentralized" {
			ids = append(ids, id)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	snapshots := []*decSnapshot{}
	for _, id := range ids {
		snapshot, e := s.loadDecSnapshot(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		snapshots = append(snapshots, snapshot)
	}
	if e = tx.Rollback(); e != nil {
		return nil, e
	}
	result := []DecNetworkView{}
	for _, snapshot := range snapshots {
		p, e := verifyDecSnapshot(snapshot, linkTime(now))
		if e != nil {
			return nil, e
		}
		result = append(result, s.decNetworkView(snapshot, p))
	}
	return result, nil
}

type decDeliveryRecord struct {
	Format   uint64   `json:"format"`
	Kind     string   `json:"kind"`
	Body     string   `json:"body_base64"`
	Proofs   []string `json:"proof_ids"`
	Created  string   `json:"created_at"`
	Attempts uint64   `json:"attempts"`
	Next     string   `json:"next_attempt_at"`
	Code     string   `json:"last_error_code"`
	Detail   string   `json:"last_error_detail"`
}

func readDecDelivery(ctx context.Context, q dbQuerier, s *decSnapshot) error {
	s.Delivery = DecDeliveryView{[]string{}, []DecPeerError{}}
	rows, e := q.QueryContext(ctx, `SELECT delivery_id,target_key,record FROM dec_outbox WHERE network_id=? AND context_id=? ORDER BY target_key,delivery_id`, s.Descriptor.NetworkID, s.Descriptor.ContextID)
	if e != nil {
		return e
	}
	defer rows.Close()
	ids := map[string]bool{}
	peers := map[string]string{}
	for rows.Next() {
		var id, target, raw string
		var r decDeliveryRecord
		if e = rows.Scan(&id, &target, &raw); e != nil {
			return e
		}
		r, _, e = validateDecDelivery(id, target, raw)
		if e != nil {
			return e
		}
		for _, proof := range r.Proofs {
			ids[proof] = true
		}
		if r.Code != "-" {
			peers[target] = r.Code
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	for id := range ids {
		s.Delivery.Proofs = append(s.Delivery.Proofs, id)
	}
	sort.Strings(s.Delivery.Proofs)
	for target, code := range peers {
		s.Delivery.Errors = append(s.Delivery.Errors, DecPeerError{target, code})
	}
	sort.Slice(s.Delivery.Errors, func(i, j int) bool { return s.Delivery.Errors[i].Host < s.Delivery.Errors[j].Host })
	return nil
}

func decCatalogResponse(s *decSnapshot) any {
	return struct {
		Catalog json.RawMessage `json:"catalog"`
	}{json.RawMessage(s.Catalog.Raw)}
}

type decPolicyVersion struct {
	Person  string   `json:"person_public_key"`
	Version uint64   `json:"version"`
	IDs     []string `json:"statement_ids"`
	Heads   []string `json:"head_ids"`
}
type decGroupVersion struct {
	Name    string   `json:"name"`
	Version uint64   `json:"version"`
	IDs     []string `json:"statement_ids"`
	Heads   []string `json:"head_ids"`
}

func decAccessVersions(s *decSnapshot) any {
	result := struct {
		Policies []decPolicyVersion `json:"policies"`
		Groups   []decGroupVersion  `json:"groups"`
	}{[]decPolicyVersion{}, []decGroupVersion{}}
	for _, maximum := range s.Prior.Maxima {
		if maximum.Stream[0] == "policy" {
			result.Policies = append(result.Policies, decPolicyVersion{maximum.Stream[1], maximum.Sequence, maximum.StatementIDs, maximum.HeadIDs})
		}
		if maximum.Stream[0] == "group" {
			result.Groups = append(result.Groups, decGroupVersion{maximum.Stream[1], maximum.Sequence, maximum.StatementIDs, maximum.HeadIDs})
		}
	}
	return result
}

type decPlanningStream struct {
	Kind    string   `json:"stream_kind"`
	Subject string   `json:"subject"`
	Second  string   `json:"subject2"`
	Heads   []string `json:"head_ids"`
	Version uint64   `json:"version"`
	IDs     []string `json:"statement_ids"`
	Floors  []string `json:"floor_proof_ids"`
}

func decPlanningStreams(s *decSnapshot) []decPlanningStream {
	result := []decPlanningStream{}
	for _, m := range s.Prior.Maxima {
		subject, second := "-", "-"
		if len(m.Stream) > 1 {
			subject = m.Stream[1]
		}
		if len(m.Stream) > 2 {
			second = m.Stream[2]
		}
		key, _ := json.Marshal(m.Stream)
		floor := append([]string{}, s.FloorProofs[string(key)]...)
		result = append(result, decPlanningStream{m.Stream[0], subject, second, m.HeadIDs, m.Sequence, m.StatementIDs, floor})
	}
	return result
}
func decMemberViews(p *dec.Projection) []DecMemberView {
	result := []DecMemberView{}
	for _, stream := range p.Streams {
		if stream.Stream[0] != "host" || !stream.Active {
			continue
		}
		member, e := decCurrentMember(p, stream.Stream[1])
		if e != nil {
			continue
		}
		// Several device streams may validly share a host. A singular display field
		// cannot choose an authority winner across those independent streams.
		device := "-"
		for _, candidate := range p.Streams {
			if candidate.Stream[0] != "device" || !candidate.Active {
				continue
			}
			d, _, e := p.Current(candidate.Stream)
			if e == nil && d.Lease.Subject.Host == member.View.Host && d.Lease.Subject.Person == member.View.Person && decParentID(d.Lease.Parents, "subject_host") == member.View.HostLease && decParentID(d.Lease.Parents, "subject_binding") == member.View.Binding {
				if device != "-" {
					device = "-"
					break
				}
				device = d.ID
			}
		}
		member.View.Device = device
		result = append(result, member.View)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Host < result[j].Host })
	return result
}

func decParentID(parents []dec.Parent, role string) string {
	for _, parent := range parents {
		if parent.Role == role {
			return parent.ID
		}
	}
	return "-"
}
