package linking

func ordinaryRestriction(kind string) bool {
	switch kind {
	case "peerspan-host-unbind-v1", "peerspan-person-remove-v1", "peerspan-revoke-host-v1", "peerspan-revoke-invite-v1":
		return true
	}
	return false
}

func (v *activationVerifier) ordinaryAdminKept(g ordinaryGrant) (bool, error) {
	if !v.history.delegated[g.person] {
		return false, pathError("forbidden")
	}
	r, removed := v.history.withdrawals[g.person]
	return !removed || !r.revoke && r.v2 && r.kept["record:"+g.record.ID], nil
}

// These facts can only restrict resolution. Their live/retained authority is
// still checked by ordinaryRecord and the final history audit before any state
// can leave the verifier. Seeding them first prevents catalog-order authority.
func (v *activationVerifier) loadOrdinaryRestrictions() error {
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind != "person_record" || scalar(p.object, "operation_id") != "-" || !ordinaryRestriction(scalar(p.object, "kind")) {
			continue
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
				continue
			}
		}
		if g.cert != "root" {
			kind := scalar(p.object, "kind")
			if kind == "peerspan-person-remove-v1" && scalar(g.payload, "person_public_key") == g.person {
				return pathError("forbidden")
			}
			if kind == "peerspan-host-unbind-v1" || kind == "peerspan-revoke-host-v1" {
				cert := g.cert
				for cert != "root" { // readOrdinary checked the complete bounded chain.
					c, e := pathCertificateFrom(cert, v.state.Certificates[cert])
					if e != nil {
						return e
					}
					if c.host == scalar(g.payload, "host_public_key") {
						return pathError("forbidden")
					}
					cert = c.parent
				}
			}
		}
		v.applyOrdinaryRestriction(g, scalar(p.object, "kind"))
	}
	return nil
}

func (v *activationVerifier) applyOrdinaryRestriction(g ordinaryGrant, kind string) {
	switch kind {
	case "peerspan-host-unbind-v1":
		v.history.unbound[bindingPair{g.person, scalar(g.payload, "host_public_key")}] = true
	case "peerspan-person-remove-v1":
		v.history.persons[scalar(g.payload, "person_public_key")] = true
	case "peerspan-revoke-host-v1":
		v.history.hosts[scalar(g.payload, "host_public_key")] = true
	case "peerspan-revoke-invite-v1":
		v.history.invites[scalar(g.payload, "invite_public_key")] = true
	}
}
