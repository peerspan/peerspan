package linking

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/peerspan/peerspan/go/internal/membership"
)

type bindingPair struct{ person, host string }
type adminWithdrawal struct {
	revoke bool
	kept   map[string]bool
	object Object
	v2     bool
}
type historyFacts struct {
	delegated               map[string]bool
	withdrawals             map[string]adminWithdrawal
	persons, hosts, invites map[string]bool
	unbound                 map[bindingPair]bool
}

func (v *activationVerifier) loadWithdrawals() error {
	seen := map[string]Object{}
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind != "admin_removal" {
			continue
		}
		o := p.object
		v2 := false
		if _, ok := o["format"]; ok {
			v2 = true
		}
		required := "network_id person_public_key revoke_admitted removed_at kept signature"
		if v2 {
			required = "format " + required
		}
		if fields(o, required) != nil || scalar(o, "network_id") != v.net || !key(scalar(o, "person_public_key")) {
			return pathError("invalid")
		}
		var revoke bool
		if json.Unmarshal(o["revoke_admitted"], &revoke) != nil {
			return pathError("invalid")
		}
		kept, e := stringsOf(o, "kept")
		if e != nil || !sorted(kept) || revoke && len(kept) > 0 {
			return pathError("invalid")
		}
		if _, e = stamp(scalar(o, "removed_at")); e != nil {
			return pathError("invalid")
		}
		if v2 {
			if _, e = Read("admin_removal_v2", p.body, v.root, "-"); e != nil {
				return pathError("invalid")
			}
		} else {
			for _, k := range kept {
				if !identifier(k, "") {
					return pathError("invalid")
				}
			}
			m := message(append([]string{"peerspan-admin-remove-v1", v.net, scalar(o, "person_public_key"), boolText(revoke), scalar(o, "removed_at")}, kept...)...)
			if rootSignature(v.root, m, scalar(o, "signature")) != nil {
				return pathError("invalid")
			}
		}
		person := scalar(o, "person_public_key")
		versionKey := person + ":" + boolText(revoke)
		if old, ok := seen[versionKey]; ok && !equivalent(old, o) {
			return pathError("state_conflict")
		}
		seen[versionKey] = o
		if old, ok := v.history.withdrawals[person]; ok && !equivalent(old.object, o) {
			if old.revoke == revoke {
				return pathError("state_conflict")
			}
			if old.revoke {
				continue
			}
		}
		set := map[string]bool{}
		for _, k := range kept {
			set[k] = true
		}
		v.history.withdrawals[person] = adminWithdrawal{revoke: revoke, kept: set, object: o, v2: v2}
		v.admins[person] = false
	}
	return nil
}
func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// A valid but withdrawn legacy signature is different from a forged signature.
// Only the former can be ignored as superseded authority in a catalog snapshot.
func (v *activationVerifier) legacyAuthority(m []byte, sig string) (bool, error) {
	if rootSignature(v.root, m, sig) == nil {
		return true, nil
	}
	pub, ok := membership.SSHSIGKey(sig)
	if !ok || membership.EncodeKey(pub) == v.root {
		return false, pathError("invalid")
	}
	person := membership.EncodeKey(pub)
	if !v.history.delegated[person] {
		return false, pathError("forbidden")
	}
	if personSignature(person, m, sig) != nil {
		return false, pathError("invalid")
	}
	if r, removed := v.history.withdrawals[person]; removed {
		prefix := ""
		if r.v2 {
			prefix = "legacy:"
		}
		return !r.revoke && r.kept[prefix+digest(m)], nil
	}
	return true, nil
}

func (v *activationVerifier) loadRestrictions() error {
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		o := p.object
		var domain, subject, at string
		switch p.kind {
		case "person_removal":
			domain, subject, at = "peerspan-person-remove-v1", "person_public_key", "removed_at"
		case "host_revocation":
			domain, subject, at = "peerspan-revoke-host-v1", "host_public_key", "revoked_at"
		case "invite_revocation":
			domain, subject, at = "peerspan-revoke-invite-v1", "invite_public_key", "revoked_at"
		case "host_leave":
			domain, subject, at = "peerspan-leave-v1", "host_public_key", "left_at"
		case "host_unbinding":
			if fields(o, "network_id person_public_key host_public_key unbound_at signature") != nil || scalar(o, "network_id") != v.net || !key(scalar(o, "person_public_key")) || !key(scalar(o, "host_public_key")) {
				return pathError("invalid")
			}
			if _, e := stamp(scalar(o, "unbound_at")); e != nil {
				return pathError("invalid")
			}
			if personSignature(scalar(o, "person_public_key"), message("peerspan-host-unbind-v1", v.net, scalar(o, "person_public_key"), scalar(o, "host_public_key"), scalar(o, "unbound_at")), scalar(o, "signature")) != nil {
				return pathError("invalid")
			}
			v.history.unbound[bindingPair{scalar(o, "person_public_key"), scalar(o, "host_public_key")}] = true
			continue
		default:
			continue
		}
		if fields(o, "network_id "+subject+" "+at+" signature") != nil || scalar(o, "network_id") != v.net || !key(scalar(o, subject)) {
			return pathError("invalid")
		}
		if _, e := stamp(scalar(o, at)); e != nil {
			return pathError("invalid")
		}
		m := message(domain, v.net, scalar(o, subject), scalar(o, at))
		valid := true
		if p.kind == "host_leave" {
			if rawSignature(scalar(o, subject), m, scalar(o, "signature")) != nil {
				return pathError("invalid")
			}
		} else {
			var e error
			valid, e = v.legacyAuthority(m, scalar(o, "signature"))
			if e != nil {
				return e
			}
		}
		if !valid {
			continue
		}
		switch p.kind {
		case "person_removal":
			v.history.persons[scalar(o, subject)] = true
		case "invite_revocation":
			v.history.invites[scalar(o, subject)] = true
		default:
			v.history.hosts[scalar(o, subject)] = true
		}
	}
	return nil
}

func (v *activationVerifier) restrictState() {
	for person := range v.history.persons {
		p := v.state.Persons[person]
		p.Admitted = false
		p.Administrator = false
		v.state.Persons[person] = p
	}
	for host := range v.history.hosts {
		v.state.Hosts[host] = false
	}
	for host, person := range v.state.Bindings {
		if v.history.persons[person] || v.history.hosts[host] || v.history.unbound[bindingPair{person, host}] {
			v.state.Bindings[host] = "-"
		}
	}
}
func (v *activationVerifier) addBinding(host, person string) error {
	if v.history.persons[person] || v.history.hosts[host] || v.history.unbound[bindingPair{person, host}] {
		if _, ok := v.state.Bindings[host]; !ok {
			v.state.Bindings[host] = "-"
		}
		return nil
	}
	if old, ok := v.state.Bindings[host]; ok && old != "-" && old != person {
		return pathError("state_conflict")
	}
	v.state.Bindings[host] = person
	return nil
}

func (v *activationVerifier) bootstrap(checkHostFeatures bool) error {
	v.history = historyFacts{delegated: map[string]bool{}, withdrawals: map[string]adminWithdrawal{}, persons: map[string]bool{}, hosts: map[string]bool{}, invites: map[string]bool{}, unbound: map[bindingPair]bool{}}
	ids := v.orderedProofs()
	for _, id := range ids {
		p := v.proofs[id]
		if p.kind != "admin_delegation" {
			continue
		}
		o := p.object
		if fields(o, "network_id epoch person_public_key delegated_at signature") != nil || scalar(o, "network_id") != v.net || !key(scalar(o, "person_public_key")) {
			return pathError("invalid")
		}
		if e := genesisEpoch(o); e != nil {
			return e
		}
		if _, e := stamp(scalar(o, "delegated_at")); e != nil {
			return pathError("invalid")
		}
		if rootSignature(v.root, message("peerspan-admin-delegate-v1", v.net, "0", scalar(o, "person_public_key"), scalar(o, "delegated_at")), scalar(o, "signature")) != nil {
			return pathError("invalid")
		}
		v.admins[scalar(o, "person_public_key")] = true
		v.history.delegated[scalar(o, "person_public_key")] = true
	}
	if e := v.loadWithdrawals(); e != nil {
		return e
	}
	if e := v.loadRestrictions(); e != nil {
		return e
	}
	if e := v.loadOrdinaryRestrictions(); e != nil {
		return e
	}
	used := map[string]string{}
	for _, id := range ids {
		p := v.proofs[id]
		o := p.object
		switch p.kind {
		case "person_admission", "host_admission", "person_membership", "host_membership":
			person := strings.HasPrefix(p.kind, "person_")
			field := "host_public_key"
			if person {
				field = "person_public_key"
			}
			k, label := scalar(o, field), scalar(o, "member")
			if !key(k) || !membership.ValidLabel(label) || scalar(o, "network_id") != v.net {
				return pathError("invalid")
			}
			var valid bool
			var e error
			if strings.HasSuffix(p.kind, "admission") {
				if fields(o, "network_id epoch "+field+" member admitted_at signature") != nil {
					return pathError("invalid")
				}
				if e = genesisEpoch(o); e != nil {
					return e
				}
				if _, e = stamp(scalar(o, "admitted_at")); e != nil {
					return pathError("invalid")
				}
				domain := "peerspan-host-admit-v1"
				if person {
					domain = "peerspan-person-admit-v1"
				}
				valid, e = v.legacyAuthority(message(domain, v.net, "0", k, label, scalar(o, "admitted_at")), scalar(o, "signature"))
			} else {
				valid, e = v.legacyMembership(p, person)
				if e == nil {
					invite := scalar(o, "invite_public_key")
					half := field + ":" + invite
					if old, ok := used[half]; ok && old != k {
						return pathError("state_conflict")
					}
					used[half] = k
				}
			}
			if e != nil {
				return e
			}
			if person {
				if valid {
					if old, ok := v.persons[k]; ok && old != label {
						return pathError("state_conflict")
					}
					v.persons[k] = label
				}
				old := v.state.Persons[k]
				old.Admitted = old.Admitted || valid
				old.Administrator = v.admins[k]
				v.state.Persons[k] = old
			} else {
				if valid {
					if old, ok := v.hosts[k]; ok && old != label {
						return pathError("state_conflict")
					}
					v.hosts[k] = label
				}
				v.state.Hosts[k] = v.state.Hosts[k] || valid
			}
		case "feature":
			r, e := Read("feature", p.body, v.root, "-")
			if e != nil {
				return pathError("invalid")
			}
			proposal, e := parse(o["proposal"])
			if e != nil || scalar(proposal, "network_id") != v.net {
				return pathError("invalid")
			}
			if e = genesisEpoch(proposal); e != nil {
				return e
			}
			if v.feature != "" && v.feature != r.ID {
				return pathError("state_conflict")
			}
			if e = v.semantic(r.ID, o); e != nil {
				return e
			}
			v.feature = r.ID
		}
	}
	for _, id := range ids {
		p := v.proofs[id]
		o := p.object
		if p.kind != "host_binding" {
			continue
		}
		person, host, at := scalar(o, "person_public_key"), scalar(o, "host_public_key"), scalar(o, "bound_at")
		if fields(o, "network_id person_public_key host_public_key bound_at signature host_signature") != nil || scalar(o, "network_id") != v.net || !key(person) || !key(host) {
			return pathError("invalid")
		}
		if _, e := stamp(at); e != nil {
			return pathError("invalid")
		}
		m := message("peerspan-host-bind-v1", v.net, person, host, at)
		if personSignature(person, m, scalar(o, "signature")) != nil || rawSignature(host, m, scalar(o, "host_signature")) != nil {
			return pathError("invalid")
		}
		if e := v.addBinding(host, person); e != nil {
			return e
		}
	}
	v.restrictState()
	if v.feature == "" {
		return pathError("proof_required")
	}
	if v.ctx.KnownFeatureID != "-" && v.ctx.KnownFeatureID != v.feature {
		return pathError("state_conflict")
	}
	if e := v.ordinaryRecords(); e != nil {
		return e
	}
	roster := map[string]bool{}
	for _, id := range ids {
		p := v.proofs[id]
		if p.kind == "feature" {
			proposal, _ := parse(p.object["proposal"])
			hosts, _ := stringsOf(proposal, "host_public_keys")
			for _, h := range hosts {
				roster[h] = true
			}
		}
	}
	for _, id := range ids {
		p := v.proofs[id]
		if p.kind != "join_ack" {
			continue
		}
		host := scalar(p.object, "host_public_key")
		if _, e := Read("feature_ack", p.body, host, "-"); e != nil || scalar(p.object, "feature_id") != v.feature {
			return pathError("invalid")
		}
		roster[host] = true
	}
	for host, admitted := range v.state.Hosts {
		if checkHostFeatures && admitted && !roster[host] {
			if e := v.hostActivations(host, 0); e != nil {
				return e
			}
			for _, r := range v.done {
				if r.HostPublicKey == host && r.FeatureID == v.feature {
					roster[host] = true
				}
			}
			if !roster[host] {
				return pathError("proof_required")
			}
		}
	}
	return nil
}

func (v *activationVerifier) legacyMembership(p catalogProof, person bool) (bool, error) {
	o := p.object
	field, sigField := "host_public_key", "host_signature"
	extra := ""
	if person {
		field, sigField, extra = "person_public_key", "person_signature", " invite_epoch"
	}
	if fields(o, "network_id member invite_public_key invite_expires_at invite_signature "+field+" joined_at "+sigField+extra) != nil || !key(scalar(o, "invite_public_key")) {
		return false, pathError("invalid")
	}
	if person {
		n, e := num(o, "invite_epoch")
		if e != nil {
			return false, pathError("invalid")
		}
		if n != 0 {
			return false, pathError("upgrade_required")
		}
	}
	expires, e := stamp(scalar(o, "invite_expires_at"))
	if e != nil {
		return false, pathError("invalid")
	}
	joined, e := stamp(scalar(o, "joined_at"))
	if e != nil || joined.After(expires) {
		return false, pathError("invalid")
	}
	invite := scalar(o, "invite_public_key")
	parts := []string{"peerspan-invite-v1", v.net, invite, scalar(o, "member"), scalar(o, "invite_expires_at")}
	domain := "peerspan-member-v1"
	if person {
		parts = []string{"peerspan-person-invite-v1", v.net, "0", invite, scalar(o, "member"), scalar(o, "invite_expires_at")}
		domain = "peerspan-person-member-v1"
	}
	valid, e := v.legacyAuthority(message(parts...), scalar(o, "invite_signature"))
	if e != nil {
		return false, e
	}
	if rawSignature(invite, message(domain, v.net, invite, scalar(o, field), scalar(o, "joined_at")), scalar(o, sigField)) != nil {
		return false, pathError("invalid")
	}
	return valid && !v.history.invites[invite], nil
}

func (v *activationVerifier) ancestor(ancestor, leaf string) bool {
	for i := 0; i < 8 && leaf != "root"; i++ {
		b, ok := v.state.Certificates[leaf]
		if !ok {
			return false
		}
		c, e := pathCertificateFrom(leaf, b)
		if e != nil {
			return false
		}
		leaf = c.parent
		if leaf == ancestor {
			return true
		}
	}
	return false
}

// actor resolves historical signing intent without claiming present authority.
// Durable records are checked separately; first operations always use authority.
func (v *activationVerifier) actor(person, cert string, scope uint64, historical bool, depth int) (SigningPath, error) {
	if !historical {
		return v.authority(person, cert, scope, depth)
	}
	if !key(person) || cert != "root" && !identifier(cert, "dc_") {
		return SigningPath{}, pathError("invalid")
	}
	if e := v.ensurePerson(person); e != nil {
		return SigningPath{}, e
	}
	r := SigningPath{CertificateID: cert, PersonPublicKey: person, SignerPublicKey: person, Scopes: 15, NotAfter: "-", CertificateIDs: []string{}, HostPublicKeys: []string{}}
	if cert == "root" {
		return r, nil
	}
	c, e := v.structural(cert, person)
	if e != nil {
		return r, e
	}
	if c.scopes&scope != scope {
		return r, pathError("forbidden")
	}
	if !v.state.ActivatedCertificates[cert] {
		if _, e = v.activate(c.request, true, depth+1); e != nil {
			return r, e
		}
	}
	if !v.state.ActivatedCertificates[cert] {
		return r, pathError("invalid")
	}
	r.SignerPublicKey = c.device
	r.Scopes = c.scopes
	r.NotAfter = c.expiry
	return r, nil
}

// Separate path liveness from the root's retained administrator permission.
// This never authorizes an operation or substitutes a different certificate.
func (v *activationVerifier) recordPathLive(person, cert string) bool {
	if cert == "root" {
		return true
	}
	if !v.state.Persons[person].Admitted {
		return false
	}
	for i := 0; i < 8 && cert != "root"; i++ {
		c, e := pathCertificateFrom(cert, v.state.Certificates[cert])
		if e != nil {
			return false
		}
		if !v.state.ActivatedCertificates[cert] || v.ctx.Now.Before(c.issued) || !v.ctx.Now.Before(c.until) || v.state.RevokedDevices[DeviceKey{PersonPublicKey: person, DevicePublicKey: c.device}] || !v.state.Hosts[c.host] || v.state.Bindings[c.host] != person {
			return false
		}
		cert = c.parent
	}
	return cert == "root"
}

func (v *activationVerifier) historicalRecord(r SignedObject, o Object, scope uint64, depth int) error {
	person, cert := scalar(o, "person_public_key"), scalar(o, "certificate_id")
	if person == "" {
		return nil
	} // network-root companion, already pinned by Read
	if scope == 8 {
		if !v.history.delegated[person] {
			return pathError("forbidden")
		}
		if removed, ok := v.history.withdrawals[person]; ok {
			if removed.revoke || !removed.v2 || !removed.kept["record:"+r.ID] {
				return pathError("forbidden")
			}
		} else if !v.state.Persons[person].Admitted {
			return pathError("forbidden")
		}
	}
	if v.recordPathLive(person, cert) {
		return nil
	}
	return v.retained(r.ID, person, cert, depth+1)
}

// retentionSubject verifies original signatures and structural authority only.
// Looking up checkpoint members never marks their records/certificates active.
func (v *activationVerifier) retentionSubject(id string) (string, string, uint64, error) {
	p, ok := v.evidence[id]
	if !ok {
		return "", "", 0, pathError("proof_required", id)
	}
	o := p.object
	person, cert := scalar(o, "person_public_key"), scalar(o, "certificate_id")
	scope := uint64(0)
	switch p.kind {
	case "person_record":
		scope = ordinaryScope(scalar(o, "kind"))
		if scope == 0 {
			return "", "", 0, pathError("upgrade_required")
		}
	case "device_revocation":
		cert = scalar(o, "issuer_certificate_id")
		scope = 4
	default:
		return "", "", 0, pathError("invalid")
	}
	if scalar(o, "network_id") != v.net || !key(person) || cert != "root" && !identifier(cert, "dc_") {
		return "", "", 0, pathError("invalid")
	}
	signer := person
	if cert != "root" {
		c, e := v.structural(cert, person)
		if e != nil {
			return "", "", 0, e
		}
		if c.scopes&scope != scope {
			return "", "", 0, pathError("forbidden")
		}
		signer = c.device
	}
	r, e := Read(p.kind, p.body, signer, "-")
	if e != nil || r.ID != id {
		return "", "", 0, pathError("invalid")
	}
	if p.kind == "device_revocation" {
		target, e := v.structural(scalar(o, "target_certificate_id"), person)
		if e != nil {
			return "", "", 0, e
		}
		if target.device != scalar(o, "target_device_public_key") || cert != "root" && !v.ancestor(cert, target.id) {
			return "", "", 0, pathError("forbidden")
		}
	}
	return person, cert, scope, nil
}

func (v *activationVerifier) checkpoint(p catalogProof, id, person, cert string, depth int) error {
	o := p.object
	issuer := scalar(o, "issuer_certificate_id")
	signer := person
	if issuer != "root" {
		c, e := v.structural(issuer, person)
		if e != nil {
			return e
		}
		signer = c.device
	}
	if _, e := Read("checkpoint", p.body, signer, "-"); e != nil {
		return pathError("invalid")
	}
	records, e := stringsOf(o, "records")
	if e != nil {
		return pathError("invalid")
	}
	var required uint64
	for _, rid := range records {
		if identifier(rid, "pf_") {
			return pathError("upgrade_required")
		}
		owner, target, scope, e := v.retentionSubject(rid)
		if e != nil {
			return e
		}
		if owner != person {
			return pathError("forbidden")
		}
		if issuer != "root" && !v.ancestor(issuer, target) {
			return pathError("forbidden")
		}
		required |= scope
	}
	if issuer != "root" {
		if _, e = v.authority(person, issuer, required, depth+1); e != nil {
			var pe *PathError
			if errors.As(e, &pe) && (pe.Code == "authority_expired" || pe.Code == "device_revoked") {
				return pathError("proof_required", id)
			}
			return e
		}
	}
	return nil
}

func (v *activationVerifier) retained(id, person, cert string, depth int) error {
	if depth > 24 || v.busy["retain:"+id] {
		return pathError("invalid")
	}
	v.busy["retain:"+id] = true
	defer delete(v.busy, "retain:"+id)
	var candidates []catalogProof
	for _, pf := range v.orderedProofs() {
		p := v.proofs[pf]
		if p.kind != "checkpoint" || scalar(p.object, "network_id") != v.net || scalar(p.object, "person_public_key") != person {
			continue
		}
		ids, e := stringsOf(p.object, "records")
		if e != nil {
			continue
		}
		for _, rid := range ids {
			if rid == id {
				candidates = append(candidates, p)
				break
			}
		}
	}
	// Prefer durable anchors; another malformed candidate cannot hide one.
	var failure error
	for _, rootOnly := range []bool{true, false} {
		for _, p := range candidates {
			if (scalar(p.object, "issuer_certificate_id") == "root") != rootOnly {
				continue
			}
			e := v.checkpoint(p, id, person, cert, depth)
			if e == nil {
				return nil
			}
			if failure == nil {
				failure = e
			}
		}
	}
	if failure != nil {
		return failure
	}
	return pathError("proof_required", id)
}

func (v *activationVerifier) revocations() error {
	// Original-person restrictions first, regardless of catalog transport order.
	for _, rootOnly := range []bool{true, false} {
		for _, pf := range v.orderedProofs() {
			p := v.proofs[pf]
			if p.kind != "device_revocation" {
				continue
			}
			o := p.object
			person, issuer := scalar(o, "person_public_key"), scalar(o, "issuer_certificate_id")
			if (issuer == "root") != rootOnly {
				continue
			}
			signer := person
			if issuer != "root" {
				c, e := v.structural(issuer, person)
				if e != nil {
					return e
				}
				if c.scopes&4 == 0 {
					return pathError("forbidden")
				}
				signer = c.device
			}
			r, e := Read("device_revocation", p.body, signer, "-")
			if e != nil || scalar(o, "network_id") != v.net {
				return pathError("invalid")
			}
			target, e := v.structural(scalar(o, "target_certificate_id"), person)
			if e != nil {
				return e
			}
			if target.device != scalar(o, "target_device_public_key") {
				return pathError("invalid")
			}
			if issuer != "root" {
				if !v.ancestor(issuer, target.id) {
					return pathError("forbidden")
				}
				if _, e = v.actor(person, issuer, 4, true, 0); e != nil {
					return e
				}
				if !v.recordPathLive(person, issuer) {
					if e = v.retained(r.ID, person, issuer, 0); e != nil {
						return e
					}
				}
			}
			v.state.RevokedDevices[DeviceKey{PersonPublicKey: person, DevicePublicKey: target.device}] = true
		}
	}
	return v.settleHistory()
}

// Recheck against all known restrictions, including those learned after a
// dependency was visited. Traversal order cannot preserve withdrawn authority.
func (v *activationVerifier) settleHistory() error {
	for _, pf := range v.orderedProofs() {
		p := v.proofs[pf]
		if !v.activeRecords[pf] || p.kind != "person_record" || scalar(p.object, "operation_id") != "-" {
			continue
		}
		g, e := v.readOrdinary(p)
		if e != nil {
			return e
		}
		if e = v.historicalRecord(g.record, p.object, g.scope, 0); e != nil {
			return e
		}
	}
	for id, p := range v.evidence {
		if p.kind != "device_revocation" || scalar(p.object, "issuer_certificate_id") == "root" {
			continue
		}
		person, cert, _, e := v.retentionSubject(id)
		if e != nil {
			return e
		}
		if !v.recordPathLive(person, cert) {
			if e = v.retained(id, person, cert, 0); e != nil {
				return e
			}
		}
	}
	checked := map[string]bool{}
	for len(checked) < len(v.done) {
		for id, r := range v.done {
			if checked[id] {
				continue
			}
			checked[id] = true
			if r.Mode != "new" {
				continue
			}
			a, _ := parse(v.activations[id])
			commit, _ := parse(a["commit"])
			_, com, _ := payload(commit)
			admin, _ := parse(a["administrator"])
			_, adm, _ := payload(admin)
			for _, entry := range []struct {
				body  []byte
				scope uint64
			}{{adm["admission_record"], 8}, {com["binding_record"], 2}} {
				o, _ := parse(entry.body)
				typ := "root_record"
				signer := v.root
				if _, ok := o["person_public_key"]; ok {
					typ = "person_record"
					person, cert := scalar(o, "person_public_key"), scalar(o, "certificate_id")
					signer = person
					if cert != "root" {
						c, e := v.structural(cert, person)
						if e != nil {
							return e
						}
						signer = c.device
					}
				}
				r, e := Read(typ, entry.body, signer, "-")
				if e != nil {
					return pathError("invalid")
				}
				if e = v.historicalRecord(r, o, entry.scope, 0); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
