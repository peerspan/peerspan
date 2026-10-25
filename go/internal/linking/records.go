package linking

import (
	"sort"
	"time"
)

func ordinaryScope(kind string) uint64 {
	switch kind {
	case "peerspan-host-bind-v1", "peerspan-host-unbind-v1":
		return 2
	case "peerspan-host-admit-v1", "peerspan-person-admit-v1", "peerspan-person-remove-v1", "peerspan-revoke-host-v1", "peerspan-revoke-invite-v1":
		return 8
	}
	return 0
}

type ordinaryGrant struct {
	record  SignedObject
	payload Object
	person  string
	cert    string
	scope   uint64
}

func (v *activationVerifier) readOrdinary(p catalogProof) (ordinaryGrant, error) {
	o := p.object
	person, cert := scalar(o, "person_public_key"), scalar(o, "certificate_id")
	scope := ordinaryScope(scalar(o, "kind"))
	if p.kind != "person_record" || scope == 0 || !key(person) || cert != "root" && !identifier(cert, "dc_") {
		return ordinaryGrant{}, pathError("invalid")
	}
	signer := person
	if cert != "root" {
		c, e := v.structural(cert, person)
		if e != nil {
			return ordinaryGrant{}, e
		}
		if c.scopes&scope != scope {
			return ordinaryGrant{}, pathError("forbidden")
		}
		signer = c.device
	}
	r, payload, e := v.record(p.body, scalar(o, "kind"), "-", person, cert, signer)
	if e != nil {
		return ordinaryGrant{}, e
	}
	return ordinaryGrant{r, payload, person, cert, scope}, nil
}

// Resolve an original person's admission without allowing a signature to supply
// its own authority. Independent candidates can break an apparent graph cycle.
func (v *activationVerifier) ensurePerson(person string) error {
	p, known := v.state.Persons[person]
	if p.Admitted || v.history.persons[person] {
		return nil
	}
	var failure error
	for _, id := range v.orderedProofs() {
		candidate := v.proofs[id]
		o := candidate.object
		if candidate.kind == "invite_redemption" && scalar(o, "person_action") == "admit" && scalar(o, "person_public_key") == person {
			if e := v.redemptionRecord(id); e != nil && failure == nil {
				failure = e
			}
			if v.state.Persons[person].Admitted {
				return nil
			}
			continue
		}
		if candidate.kind != "person_record" || scalar(o, "operation_id") != "-" || scalar(o, "kind") != "peerspan-person-admit-v1" || v.activeRecords[id] || v.inertRecords[id] {
			continue
		}
		_, target, e := payload(o)
		if e != nil {
			return pathError("invalid")
		}
		if scalar(target, "person_public_key") != person {
			continue
		}
		if e = v.ordinaryRecord(id); e != nil && failure == nil {
			failure = e
		}
		if v.state.Persons[person].Admitted {
			return nil
		}
	}
	if _, exists := v.state.Persons[person]; known || exists {
		return nil
	}
	if failure != nil {
		return failure
	}
	return pathError("proof_required")
}

func (v *activationVerifier) ordinaryRecord(id string) error {
	if v.activeRecords[id] || v.inertRecords[id] {
		return nil
	}
	busy := "ordinary:" + id
	if v.busy[busy] || len(v.busy) >= 24 {
		return pathError("invalid")
	}
	v.busy[busy] = true
	defer delete(v.busy, busy)
	p, ok := v.proofs[id]
	if !ok {
		return pathError("proof_required", id)
	}
	g, e := v.readOrdinary(p)
	if e != nil {
		return e
	}
	if g.scope == 8 {
		kept, e := v.ordinaryAdminKept(g)
		if e != nil {
			return e
		}
		if !kept {
			// A valid withdrawn grant cannot hide another independent admission.
			switch scalar(p.object, "kind") {
			case "peerspan-person-admit-v1":
				k := scalar(g.payload, "person_public_key")
				if _, exists := v.state.Persons[k]; !exists {
					v.state.Persons[k] = PersonState{Administrator: v.admins[k]}
				}
			case "peerspan-host-admit-v1":
				k := scalar(g.payload, "host_public_key")
				if _, exists := v.state.Hosts[k]; !exists {
					v.state.Hosts[k] = false
				}
			}
			if v.inertRecords == nil {
				v.inertRecords = map[string]bool{}
			}
			v.inertRecords[id] = true
			return nil
		}
	}
	if _, e = v.actor(g.person, g.cert, g.scope, true, 0); e != nil {
		return e
	}
	if e = v.historicalRecord(g.record, p.object, g.scope, 0); e != nil {
		return e
	}
	switch scalar(p.object, "kind") {
	case "peerspan-host-bind-v1":
		if e = v.addBinding(scalar(g.payload, "host_public_key"), g.person); e != nil {
			return e
		}
	case "peerspan-host-admit-v1":
		host, label := scalar(g.payload, "host_public_key"), scalar(g.payload, "member")
		if old, exists := v.hosts[host]; exists && old != label {
			return pathError("state_conflict")
		}
		v.hosts[host], v.state.Hosts[host] = label, true
	case "peerspan-person-admit-v1":
		person, label := scalar(g.payload, "person_public_key"), scalar(g.payload, "member")
		if old, exists := v.persons[person]; exists && old != label {
			return pathError("state_conflict")
		}
		v.persons[person] = label
		epoch, _ := num(p.object, "epoch")
		v.historicalPersons[historicalLabel{person, epoch, label}] = true
		v.state.Persons[person] = PersonState{Admitted: true, Administrator: v.admins[person]}
	default:
		v.applyOrdinaryRestriction(g, scalar(p.object, "kind"))
	}
	v.restrictState()
	v.activeRecords[id] = true
	return nil
}

func (v *activationVerifier) ordinaryRecords() error {
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind == "person_record" && scalar(p.object, "operation_id") == "-" && !accessKind(scalar(p.object, "kind")) {
			if e := v.ordinaryRecord(id); e != nil {
				return e
			}
		}
	}
	return nil
}

// CatalogFactContext pins verified local context. The feature pin may be unknown
// for historical evidence; this entry point cannot enable the feature or writers.
type CatalogFactContext struct {
	Network        []byte
	Epoch          uint64
	KnownFeatureID string
	Now            time.Time
}

type CatalogFacts struct {
	NetworkID, FeatureID     string
	State                    *PathState
	PersonLabels, HostLabels map[string]string
}

func VerifyCatalogFacts(ctx CatalogFactContext, catalog []byte) (CatalogFacts, error) {
	if len(ctx.Network)+len(catalog) > MaxActivation {
		return CatalogFacts{}, pathError("invalid")
	}
	v, e := newCatalogVerifier(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now)
	if e != nil {
		return CatalogFacts{}, e
	}
	if e = v.catalog(catalog); e == nil {
		e = v.bootstrap(true)
	}
	if e == nil {
		e = v.revocations()
	}
	if e != nil {
		return CatalogFacts{}, e
	}
	return CatalogFacts{v.net, v.feature, v.state, v.persons, v.hosts}, nil
}

func catalogFactsProbe(o Object) any {
	fail := func(e error) any {
		r := map[string]any{"ok": false, "code": "invalid"}
		if p, ok := e.(*PathError); ok {
			r["code"] = p.Code
			if p.Code == "proof_required" {
				r["required_ids"] = p.RequiredIDs
			}
		}
		return r
	}
	if fields(o, "kind network_base64 catalog_base64 epoch known_feature_id now") != nil {
		return fail(invalid())
	}
	network, e := decode(scalar(o, "network_base64"), MaxActivation)
	if e != nil {
		return fail(e)
	}
	catalog, e := decode(scalar(o, "catalog_base64"), MaxActivation)
	if e != nil {
		return fail(e)
	}
	epoch, e := num(o, "epoch")
	if e != nil {
		return fail(e)
	}
	now, e := stamp(scalar(o, "now"))
	if e != nil {
		return fail(e)
	}
	r, e := VerifyCatalogFacts(CatalogFactContext{network, epoch, scalar(o, "known_feature_id"), now}, catalog)
	if e != nil {
		return fail(e)
	}
	persons, hosts, bindings, revoked := []any{}, []any{}, []any{}, []any{}
	label := func(labels map[string]string, k string) string {
		if s, ok := labels[k]; ok {
			return s
		}
		return "-"
	}
	personKeys, hostKeys, bindingKeys, certs := []string{}, []string{}, []string{}, []string{}
	for k := range r.State.Persons {
		personKeys = append(personKeys, k)
	}
	for k := range r.State.Hosts {
		hostKeys = append(hostKeys, k)
	}
	for k := range r.State.Bindings {
		bindingKeys = append(bindingKeys, k)
	}
	for k, active := range r.State.ActivatedCertificates {
		if active {
			certs = append(certs, k)
		}
	}
	sort.Strings(personKeys)
	sort.Strings(hostKeys)
	sort.Strings(bindingKeys)
	sort.Strings(certs)
	for _, k := range personKeys {
		p := r.State.Persons[k]
		persons = append(persons, map[string]any{"person_public_key": k, "member": label(r.PersonLabels, k), "admitted": p.Admitted, "administrator": p.Administrator})
	}
	for _, k := range hostKeys {
		hosts = append(hosts, map[string]any{"host_public_key": k, "member": label(r.HostLabels, k), "admitted": r.State.Hosts[k]})
	}
	for _, k := range bindingKeys {
		bindings = append(bindings, map[string]any{"host_public_key": k, "person_public_key": r.State.Bindings[k]})
	}
	devices := []DeviceKey{}
	for k, active := range r.State.RevokedDevices {
		if active {
			devices = append(devices, k)
		}
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].PersonPublicKey != devices[j].PersonPublicKey {
			return devices[i].PersonPublicKey < devices[j].PersonPublicKey
		}
		return devices[i].DevicePublicKey < devices[j].DevicePublicKey
	})
	for _, k := range devices {
		revoked = append(revoked, map[string]any{"person_public_key": k.PersonPublicKey, "device_public_key": k.DevicePublicKey})
	}
	return map[string]any{"ok": true, "network_id": r.NetworkID, "feature_id": r.FeatureID, "persons": persons, "hosts": hosts, "bindings": bindings, "activated_certificate_ids": certs, "revoked_devices": revoked}
}
