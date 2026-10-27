package host

import (
	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// An explicit original person may consent to its first binding of an already
// admitted OWN unbound host. This action-only provider is never selected or
// returned by normal provider/policy resolution before the binding exists.
func decFirstBindingProvider(snapshot *decSnapshot, p *dec.Projection, request DecActionRequest) (DecProviderView, decIntentProvider, dec.Actor, bool, error) {
	var view DecProviderView
	var provider decIntentProvider
	actor := dec.Actor{Person: "-", Host: "-", Device: "-", IssuerID: "-"}
	if request.Kind != "binding_lease" || !dec.ValidPublicKey(request.Provider) || snapshot.Provider != nil || snapshot.Network.Own.Person != "-" {
		return view, provider, actor, false, nil
	}
	for _, stream := range p.Streams {
		if len(stream.Stream) == 2 && stream.Stream[0] == "binding" && stream.Stream[1] == snapshot.Network.Own.Host {
			return view, provider, actor, false, nil
		}
	}
	if len(snapshot.Fenced) > 0 {
		return view, provider, actor, true, decFailure("migration_pending", snapshot.Fenced...)
	}
	if request.Format != "auto" && request.Format != "sshsig" {
		return view, provider, actor, true, decFailure("invalid")
	}
	raw, e := decBytes(request.Payload, dec.MaxPayload)
	if e != nil {
		return view, provider, actor, true, e
	}
	statement, e := dec.ReadActionPayload(snapshot.Descriptor, "binding_lease", raw)
	if e != nil {
		return view, provider, actor, true, e
	}
	l := statement.Lease
	if l.Issuer.Kind != "person" || l.Issuer.Person != request.Provider || l.Subject.Person != request.Provider || l.Subject.Host != snapshot.Network.Own.Host || l.Sequence != 1 || len(l.Predecessors) != 0 || len(l.Resolves) != 0 {
		return view, provider, actor, true, decFailure("forbidden")
	}
	if p.Root.Code != "-" {
		return view, provider, actor, true, decFailure(p.Root.Code, p.Root.RequiredIDs...)
	}
	h, hpath, e := p.Current([]string{"host", snapshot.Network.Own.Host})
	if e != nil {
		return view, provider, actor, true, e
	}
	person, ppath, e := p.Current([]string{"person", request.Provider})
	if e != nil {
		return view, provider, actor, true, e
	}
	if h.Lease.Subject.Member != person.Lease.Subject.Member || l.Root != p.Root.SelectedID || decParentID(l.Parents, "subject_host") != h.ID || decParentID(l.Parents, "subject_person") != person.ID || decParentID(l.Parents, "issuer_person") != person.ID {
		return view, provider, actor, true, decFailure("forbidden")
	}
	view = DecProviderView{"original_person", request.Provider, snapshot.Network.Own.Host, "-", person.ID, p.Root.SelectedID, 7, decEarlier(hpath.NotAfter, ppath.NotAfter)}
	if _, path, e := p.Current([]string{"admin", request.Provider}); e == nil {
		view.Scopes |= 8
		view.NotAfter = decEarlier(view.NotAfter, path.NotAfter)
	}
	provider = decIntentProvider{"original", request.Provider, "sshsig", "-"}
	actor.Person = request.Provider
	return view, provider, actor, true, nil
}
