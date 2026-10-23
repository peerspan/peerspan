package linking

import (
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// PersonState is an independently verified current admission and root-issued role.
type PersonState struct {
	Admitted      bool
	Administrator bool
}

// DeviceKey scopes a sticky device revocation to its original person. The
// containing PathState supplies the network scope.
type DeviceKey struct {
	PersonPublicKey string
	DevicePublicKey string
}

// PathState is a coherent snapshot supplied by a trusted verifier. Persons,
// hosts, bindings, activation IDs and revocations MUST already be verified.
// Certificates are candidate bytes and are verified by EvaluatePath itself.
// A missing map entry means unknown proof; a false host value means removed,
// and a binding of "-" means known unbound. Do not fill this from unsigned maps.
// Callers must prevent concurrent mutation for the duration of evaluation.
type PathState struct {
	NetworkID             string
	Persons               map[string]PersonState
	Hosts                 map[string]bool
	Bindings              map[string]string
	Certificates          map[string][]byte
	ActivatedCertificates map[string]bool
	RevokedDevices        map[DeviceKey]bool
}

// SigningPath describes a usable path under one verified snapshot. It is not
// mutation authorization or verification of the snapshot's source evidence.
type SigningPath struct {
	CertificateID   string `json:"certificate_id"`
	PersonPublicKey string `json:"person_public_key"`
	SignerPublicKey string `json:"signer_public_key"`
	// Scopes is the certificate mask, not an unconditional role grant. Evaluate
	// each operation with its actual required bits, especially administration.
	Scopes         uint64   `json:"scopes"`
	NotAfter       string   `json:"not_after"`
	CertificateIDs []string `json:"certificate_ids"`
	HostPublicKeys []string `json:"host_public_keys"`
}

// PathError contains public repair details, without unsigned authority claims.
type PathError struct {
	Code        string
	RequiredIDs []string
}

func (e *PathError) Error() string { return "linking path: " + e.Code }

func pathError(code string, ids ...string) error {
	unique := map[string]bool{}
	for _, id := range ids {
		unique[id] = true
	}
	ordered := make([]string, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	return &PathError{Code: code, RequiredIDs: ordered}
}

type pathCertificate struct {
	id, person, device, host, parent, request string
	network, expiry                           string
	scopes                                    uint64
	issued, until                             time.Time
	body                                      []byte
}

func pathCertificateFrom(id string, body []byte) (pathCertificate, error) {
	o, e := parse(body)
	if e != nil {
		return pathCertificate{}, pathError("invalid")
	}
	v, e := texts(o, "network_id", "person_public_key", "device_public_key", "host_public_key", "parent_id", "request_id", "issued_at", "not_after")
	if e != nil || v[4] != "root" && !identifier(v[4], "dc_") {
		return pathCertificate{}, pathError("invalid")
	}
	scopes, e := num(o, "scopes")
	if e != nil {
		return pathCertificate{}, pathError("invalid")
	}
	issued, e := stamp(v[6])
	if e != nil {
		return pathCertificate{}, pathError("invalid")
	}
	until, e := stamp(v[7])
	if e != nil {
		return pathCertificate{}, pathError("invalid")
	}
	return pathCertificate{id: id, network: v[0], person: v[1], device: v[2], host: v[3], parent: v[4], request: v[5], issued: issued, until: until, expiry: v[7], scopes: scopes, body: body}, nil
}

// EvaluatePath resolves exactly the named path, oldest first, using verified
// state and an independently expected original person. The caller must still
// verify operation semantics, freshness and transaction-time authority.
func EvaluatePath(state *PathState, person, certificateID string, required uint64, now time.Time) (SigningPath, error) {
	fail := func(code string) (SigningPath, error) { return SigningPath{}, pathError(code) }
	if state == nil || !identifier(state.NetworkID, "net_") || !key(person) || required == 0 || required > 15 || certificateID != "root" && !identifier(certificateID, "dc_") {
		return fail("invalid")
	}
	chain := make([]pathCertificate, 0, 8)
	seen := map[string]bool{}
	for id := certificateID; id != "root"; {
		if seen[id] || len(chain) == 8 {
			return fail("invalid")
		}
		seen[id] = true
		body, ok := state.Certificates[id]
		if !ok {
			return SigningPath{}, pathError("proof_required", id)
		}
		c, e := pathCertificateFrom(id, body)
		if e != nil {
			return SigningPath{}, e
		}
		chain = append(chain, c)
		id = c.parent
	}
	// Resolve oldest first. The signer of each child comes only from the exact
	// already checked parent, never the SSHSIG's embedded key or an alternative.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	devices, hosts := map[string]bool{}, map[string]bool{}
	signer := person
	for i, c := range chain {
		r, e := Read("certificate", c.body, signer, "-")
		if e != nil || r.ID != c.id || c.network != state.NetworkID || c.person != person || devices[c.device] || hosts[c.host] || c.device == person {
			return fail("invalid")
		}
		if i > 0 {
			parent := chain[i-1]
			if c.scopes&parent.scopes != c.scopes || c.issued.Before(parent.issued) || c.until.After(parent.until) {
				return fail("invalid")
			}
			if parent.scopes&4 == 0 {
				return fail("forbidden")
			}
		}
		devices[c.device], hosts[c.host] = true, true
		signer = c.device
	}
	for device := range devices {
		if hosts[device] {
			return fail("invalid")
		}
	}
	p, ok := state.Persons[person]
	if !ok {
		return fail("proof_required")
	}
	if !p.Admitted {
		return fail("forbidden")
	}
	for _, c := range chain {
		if state.RevokedDevices[DeviceKey{PersonPublicKey: person, DevicePublicKey: c.device}] {
			return fail("device_revoked")
		}
		if now.Before(c.issued) || !now.Before(c.until) {
			return fail("authority_expired")
		}
		admitted, known := state.Hosts[c.host]
		if !known {
			return fail("proof_required")
		}
		if !admitted {
			return fail("forbidden")
		}
		binding, known := state.Bindings[c.host]
		if !known {
			return fail("proof_required")
		}
		if binding != person {
			return fail("forbidden")
		}
		if !state.ActivatedCertificates[c.id] {
			return SigningPath{}, pathError("proof_required", c.request)
		}
	}
	r := SigningPath{CertificateID: certificateID, PersonPublicKey: person, SignerPublicKey: signer, Scopes: 15, NotAfter: "-", CertificateIDs: []string{}, HostPublicKeys: []string{}}
	if len(chain) > 0 {
		leaf := chain[len(chain)-1]
		r.Scopes, r.NotAfter = leaf.scopes, leaf.expiry
	}
	if r.Scopes&required != required || required&8 != 0 && !p.Administrator {
		return fail("forbidden")
	}
	for _, c := range chain {
		r.CertificateIDs = append(r.CertificateIDs, c.id)
		r.HostPublicKeys = append(r.HostPublicKeys, c.host)
	}
	return r, nil
}

func pathEntries(o Object, name string) ([]Object, error) {
	var raw []json.RawMessage
	if json.Unmarshal(o[name], &raw) != nil || raw == nil || len(raw) > 4096 {
		return nil, invalid()
	}
	entries := make([]Object, 0, len(raw))
	for _, b := range raw {
		entry, e := parse(b)
		if e != nil {
			return nil, e
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// pathStateFrom is only the conformance bridge for injecting verified facts.
// It must not be used to turn an untrusted protocol response into PathState.
func pathStateFrom(b []byte) (*PathState, error) {
	o, e := parse(b)
	if e != nil || fields(o, "format network_id persons hosts bindings certificates activated_certificates revoked_devices") != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	network, e := text(o, "network_id")
	if e != nil || !identifier(network, "net_") {
		return nil, invalid()
	}
	s := &PathState{NetworkID: network, Persons: map[string]PersonState{}, Hosts: map[string]bool{}, Bindings: map[string]string{}, Certificates: map[string][]byte{}, ActivatedCertificates: map[string]bool{}, RevokedDevices: map[DeviceKey]bool{}}
	for _, name := range []string{"persons", "hosts", "bindings", "certificates", "revoked_devices"} {
		entries, e := pathEntries(o, name)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			switch name {
			case "persons", "hosts":
				shape := "public_key state"
				if name == "persons" {
					shape += " administrator"
				}
				if fields(entry, shape) != nil {
					return nil, invalid()
				}
				v, e := texts(entry, "public_key", "state")
				if e != nil || !key(v[0]) || v[1] != "admitted" && v[1] != "removed" {
					return nil, invalid()
				}
				if name == "persons" {
					var admin bool
					if json.Unmarshal(entry["administrator"], &admin) != nil {
						return nil, invalid()
					}
					if _, exists := s.Persons[v[0]]; exists {
						return nil, invalid()
					}
					s.Persons[v[0]] = PersonState{Admitted: v[1] == "admitted", Administrator: admin}
				} else {
					if _, exists := s.Hosts[v[0]]; exists {
						return nil, invalid()
					}
					s.Hosts[v[0]] = v[1] == "admitted"
				}
			case "bindings":
				if fields(entry, "host_public_key person_public_key") != nil {
					return nil, invalid()
				}
				v, e := texts(entry, "host_public_key", "person_public_key")
				if e != nil || !key(v[0]) || v[1] != "-" && !key(v[1]) {
					return nil, invalid()
				}
				if _, exists := s.Bindings[v[0]]; exists {
					return nil, invalid()
				}
				s.Bindings[v[0]] = v[1]
			case "certificates":
				if fields(entry, "id body_base64") != nil {
					return nil, invalid()
				}
				v, e := texts(entry, "id", "body_base64")
				if e != nil || !identifier(v[0], "dc_") {
					return nil, invalid()
				}
				if _, exists := s.Certificates[v[0]]; exists {
					return nil, invalid()
				}
				body, e := decode(v[1], MaxObject)
				if e != nil {
					return nil, e
				}
				s.Certificates[v[0]] = body
			case "revoked_devices":
				if fields(entry, "person_public_key device_public_key") != nil {
					return nil, invalid()
				}
				v, e := texts(entry, "person_public_key", "device_public_key")
				if e != nil || !key(v[0]) || !key(v[1]) {
					return nil, invalid()
				}
				ref := DeviceKey{PersonPublicKey: v[0], DevicePublicKey: v[1]}
				if s.RevokedDevices[ref] {
					return nil, invalid()
				}
				s.RevokedDevices[ref] = true
			}
		}
	}
	active, e := stringsOf(o, "activated_certificates")
	if e != nil {
		return nil, e
	}
	for _, id := range active {
		if !identifier(id, "dc_") || s.ActivatedCertificates[id] {
			return nil, invalid()
		}
		s.ActivatedCertificates[id] = true
	}
	return s, nil
}

func pathProbe(o Object) any {
	failure := func(e error) any {
		var p *PathError
		if !errors.As(e, &p) {
			p = &PathError{Code: "invalid", RequiredIDs: []string{}}
		}
		result := map[string]any{"ok": false, "code": p.Code}
		if p.Code == "proof_required" {
			result["required_ids"] = p.RequiredIDs
		}
		return result
	}
	if fields(o, "kind state_base64 person_public_key certificate_id required_scopes now") != nil {
		return failure(invalid())
	}
	v, e := texts(o, "state_base64", "person_public_key", "certificate_id", "now")
	if e != nil {
		return failure(e)
	}
	stateBytes, e := decode(v[0], MaxObject)
	if e != nil {
		return failure(e)
	}
	s, e := pathStateFrom(stateBytes)
	if e != nil {
		return failure(e)
	}
	now, e := stamp(v[3])
	if e != nil {
		return failure(e)
	}
	required, e := num(o, "required_scopes")
	if e != nil {
		return failure(e)
	}
	r, e := EvaluatePath(s, v[1], v[2], required, now)
	if e != nil {
		return failure(e)
	}
	return struct {
		OK bool `json:"ok"`
		SigningPath
	}{OK: true, SigningPath: r}
}
