package linking

import (
	"strconv"

	"github.com/peerspan/peerspan/go/internal/membership"
)

type inviteHalf struct {
	host, legacy, kept                        bool
	person, cert, key, label, expires, record string
	epoch                                     uint64
}
type redemption struct {
	object Object
	halves []inviteHalf
}

func inviteKind(kind string) bool {
	return kind == "peerspan-invite-v1" || kind == "peerspan-person-invite-v1"
}

// Shape checks require no authority or catalog traversal.
func redemptionParts(o Object) ([]string, error) {
	bad := func() ([]string, error) { return nil, pathError("invalid") }
	if fields(o, "format mode person_action host_public_key person_public_key joined_at host_invite person_invite host_member_signature person_member_signature") != nil || version(o, 1) != nil {
		return bad()
	}
	a, e := texts(o, "mode", "person_action", "host_public_key", "person_public_key", "joined_at", "host_member_signature", "person_member_signature")
	if e != nil {
		return bad()
	}
	if _, e = stamp(a[4]); e != nil {
		return bad()
	}
	mode, action := a[0], a[1]
	if !(mode == "host" && action == "none" || mode == "person" && action == "admit" || mode == "member" && (action == "admit" || action == "skip")) {
		return bad()
	}
	parts := []string{}
	for _, host := range []bool{true, false} {
		part, subject, sig, needed := "person_invite", a[3], a[6], action == "admit"
		if host {
			part, subject, sig, needed = "host_invite", a[2], a[5], mode != "person"
		}
		if needed {
			if !key(subject) || sig == "-" {
				return bad()
			}
			if _, e := parse(o[part]); e != nil {
				return bad()
			}
			parts = append(parts, part)
		} else if scalar(o, part) != "-" || sig != "-" {
			return bad()
		}
	}
	if mode == "host" && a[3] != "-" || mode == "person" && a[2] != "-" || action == "skip" && !key(a[3]) {
		return bad()
	}
	return parts, nil
}

// Inline invitations are evidence for this completed object, never standalone
// grants. Index exact AR identities without activating an issuer.
func (v *activationVerifier) indexRedemption(id string, o Object) error {
	parts, e := redemptionParts(o)
	if e != nil {
		return e
	}
	for _, part := range parts {
		b := o[part]
		p, _ := parse(b)
		if _, envelope := p["format"]; !envelope {
			continue
		}
		kind := "peerspan-invite-v1"
		if part == "person_invite" {
			kind = "peerspan-person-invite-v1"
		}
		if nestedRecord(b) != nil || scalar(p, "kind") != kind || !key(scalar(p, "person_public_key")) || scalar(p, "operation_id") != "-" {
			return pathError("invalid")
		}
		raw, _, e := payload(p)
		if e != nil {
			return pathError("invalid")
		}
		epoch, e := num(p, "epoch")
		if e != nil {
			return pathError("invalid")
		}
		m := message("peerspan-person-authorization-v1", kind, scalar(p, "network_id"), strconv.FormatUint(epoch, 10), "-", scalar(p, "person_public_key"), scalar(p, "certificate_id"), digest(raw))
		rid := "ar_" + digest(message("peerspan-authorized-record-v1", digest(m), scalar(p, "signature"), scalar(p, "host_signature")))
		if e := v.semantic(rid, p); e != nil {
			return e
		}
		v.evidence[rid] = catalogProof{"person_record", b, p}
		v.inlineInvites[rid] = true
	}
	return nil
}

func (v *activationVerifier) readInvite(body []byte, host bool) (inviteHalf, error) {
	bad := func() (inviteHalf, error) { return inviteHalf{}, pathError("invalid") }
	o, e := parse(body)
	if e != nil {
		return bad()
	}
	h := inviteHalf{host: host, cert: "root"}
	kind := "peerspan-invite-v1"
	if !host {
		kind = "peerspan-person-invite-v1"
	}
	if _, envelope := o["format"]; envelope {
		h.epoch, e = num(o, "epoch")
		if e != nil {
			return bad()
		}
		h.person, h.cert = scalar(o, "person_public_key"), scalar(o, "certificate_id")
		if !key(h.person) || h.cert != "root" && !identifier(h.cert, "dc_") {
			return bad()
		}
		signer := h.person
		limit := "-"
		if h.cert != "root" {
			c, e := v.structural(h.cert, h.person)
			if e != nil {
				return inviteHalf{}, e
			}
			if c.scopes&8 == 0 {
				return inviteHalf{}, pathError("forbidden")
			}
			signer, limit = c.device, c.expiry
		}
		r, p, e := v.record(body, kind, "-", h.person, h.cert, signer)
		if e != nil {
			return inviteHalf{}, e
		}
		h.record, o = r.ID, p
		if limit != "-" {
			expires, _ := stamp(scalar(o, "invite_expires_at"))
			until, _ := stamp(limit)
			if expires.After(until) {
				return inviteHalf{}, pathError("forbidden")
			}
		}
	} else {
		names := "network_id invite_public_key member invite_expires_at signature"
		if !host {
			names += " invite_epoch"
		}
		if fields(o, names) != nil || scalar(o, "network_id") != v.net {
			return bad()
		}
		parts := []string{kind, v.net}
		if !host {
			epoch, e := num(o, "invite_epoch")
			if e != nil {
				return bad()
			}
			if epoch >= uint64(len(v.roots)) {
				return inviteHalf{}, pathError("proof_required")
			}
			h.epoch = epoch
			parts = append(parts, strconv.FormatUint(epoch, 10))
		}
		parts = append(parts, scalar(o, "invite_public_key"), scalar(o, "member"), scalar(o, "invite_expires_at"))
		m, sig := message(parts...), scalar(o, "signature")
		if host {
			h.kept, e = v.legacyAuthority(m, sig)
		} else {
			h.kept, e = v.legacyGrant(o, "invite_epoch", m, sig)
		}
		if e != nil {
			return inviteHalf{}, e
		}
		h.legacy, h.person = true, "-"
		if !v.anyRootSignature(m, sig) {
			pub, ok := membership.SSHSIGKey(sig)
			if !ok {
				return bad()
			}
			h.person = membership.EncodeKey(pub)
		}
	}
	h.key, h.label, h.expires = scalar(o, "invite_public_key"), scalar(o, "member"), scalar(o, "invite_expires_at")
	if !key(h.key) || !membership.ValidLabel(h.label) {
		return bad()
	}
	if _, e := stamp(h.expires); e != nil {
		return bad()
	}
	return h, nil
}

func (v *activationVerifier) readRedemption(p catalogProof) (redemption, error) {
	parts, e := redemptionParts(p.object)
	if e != nil {
		return redemption{}, e
	}
	r := redemption{object: p.object}
	joined, _ := stamp(scalar(p.object, "joined_at"))
	for _, part := range parts {
		host := part == "host_invite"
		h, e := v.readInvite(p.object[part], host)
		if e != nil {
			return redemption{}, e
		}
		expires, _ := stamp(h.expires)
		if joined.After(expires) {
			return redemption{}, pathError("invalid")
		}
		field, sig, domain := "person_public_key", "person_member_signature", "peerspan-person-member-v1"
		if host {
			field, sig, domain = "host_public_key", "host_member_signature", "peerspan-member-v1"
		}
		if rawSignature(h.key, message(domain, v.net, h.key, scalar(p.object, field), scalar(p.object, "joined_at")), scalar(p.object, sig)) != nil {
			return redemption{}, pathError("invalid")
		}
		if len(r.halves) != 0 {
			old := r.halves[0]
			if old.key != h.key || old.label != h.label || old.expires != h.expires || old.person != h.person || old.cert != h.cert {
				return redemption{}, pathError("invalid")
			}
		}
		r.halves = append(r.halves, h)
	}
	return r, nil
}

func (v *activationVerifier) redemptionHalf(id string, h inviteHalf) (bool, error) {
	if h.legacy {
		kept := h.kept
		if h.host && h.person == "-" {
			p := v.proofs[id]
			kept = kept || v.attested[scalar(p.object, "host_public_key")] == h.label
		}
		return kept && !v.history.invites[h.key], nil
	}
	if !v.history.delegated[h.person] {
		return false, pathError("forbidden")
	}
	if w, removed := v.history.withdrawals[h.person]; removed {
		if w.revoke || !w.v2 || !w.kept["record:"+h.record] || !w.kept["redemption:"+id] {
			return false, nil
		}
	} else {
		if e := v.ensurePerson(h.person); e != nil {
			return false, e
		}
		if !v.state.Persons[h.person].Admitted {
			return false, pathError("forbidden")
		}
	}
	if _, e := v.actor(h.person, h.cert, 8, true, 0); e != nil {
		return false, e
	}
	expires, _ := stamp(h.expires)
	if !v.ctx.Now.Before(expires) || !v.recordPathLive(h.person, h.cert) {
		if e := v.retainedRedemption(id, h); e != nil {
			return false, e
		}
	}
	return !v.history.invites[h.key], nil
}

func (v *activationVerifier) retainedRedemption(id string, h inviteHalf) error {
	busy := "retain:" + id + ":" + h.record
	if v.busy[busy] || len(v.busy) >= 24 {
		return pathError("invalid")
	}
	v.busy[busy] = true
	defer delete(v.busy, busy)
	var failure error
	for _, rootOnly := range []bool{true, false} {
		for _, pf := range v.orderedProofs() {
			p := v.proofs[pf]
			if p.kind != "checkpoint" || scalar(p.object, "network_id") != v.net || scalar(p.object, "person_public_key") != h.person || (scalar(p.object, "issuer_certificate_id") == "root") != rootOnly {
				continue
			}
			ids, e := stringsOf(p.object, "records")
			if e != nil {
				continue
			}
			found := map[string]bool{}
			for _, rid := range ids {
				found[rid] = true
			}
			if !found[id] || !found[h.record] {
				continue
			}
			if e := v.checkpoint(p, id, h.person, h.cert, 0); e == nil {
				return nil
			} else if failure == nil {
				failure = e
			}
		}
	}
	if failure != nil {
		return failure
	}
	return pathError("proof_required", id)
}

func (v *activationVerifier) redemptionRecord(id string) error {
	if v.redemptions[id] {
		return nil
	}
	busy := "redemption:" + id
	if v.busy[busy] || len(v.busy) >= 24 {
		return pathError("invalid")
	}
	v.busy[busy] = true
	defer delete(v.busy, busy)
	p, ok := v.proofs[id]
	if !ok {
		return pathError("proof_required", id)
	}
	r, e := v.readRedemption(p)
	if e != nil {
		return e
	}
	if scalar(r.object, "person_action") == "skip" {
		person := scalar(r.object, "person_public_key")
		if e := v.ensurePerson(person); e != nil {
			return e
		}
		if !v.state.Persons[person].Admitted {
			return pathError("forbidden")
		}
		if v.persons[person] != r.halves[0].label {
			return pathError("invalid")
		}
	}
	valid := []bool{}
	for _, h := range r.halves {
		usable, e := v.redemptionHalf(id, h)
		if e != nil {
			return e
		}
		valid = append(valid, usable)
		field := "person_public_key"
		if h.host {
			field = "host_public_key"
		}
		subject := scalar(r.object, field)
		use := field + ":" + h.key
		if old, used := v.inviteUses[use]; used && old != subject {
			return pathError("state_conflict")
		}
		v.inviteUses[use] = subject
	}
	for i, h := range r.halves {
		if h.host {
			host := scalar(r.object, "host_public_key")
			if valid[i] {
				if old, exists := v.hosts[host]; exists && old != h.label {
					return pathError("state_conflict")
				}
				v.hosts[host], v.state.Hosts[host] = h.label, true
			} else if _, exists := v.state.Hosts[host]; !exists {
				v.state.Hosts[host] = false
			}
		} else {
			person := scalar(r.object, "person_public_key")
			// Retain the verified invitation's original epoch, never the
			// selected tip. Historical root evidence does not admit currently.
			if valid[i] || h.legacy && h.person == "-" && !v.history.invites[h.key] {
				v.historicalPersons[historicalLabel{person, h.epoch, h.label}] = true
			}
			if valid[i] {
				if old, exists := v.persons[person]; exists && old != h.label {
					return pathError("state_conflict")
				}
				v.persons[person] = h.label
				v.state.Persons[person] = PersonState{Admitted: true, Administrator: v.admins[person]}
			} else if _, exists := v.state.Persons[person]; !exists {
				v.state.Persons[person] = PersonState{Administrator: v.admins[person]}
			}
		}
	}
	v.restrictState()
	v.redemptions[id] = true
	return nil
}

func (v *activationVerifier) redemptionRecords() error {
	for _, id := range v.orderedProofs() {
		if v.proofs[id].kind == "invite_redemption" {
			if e := v.redemptionRecord(id); e != nil {
				return e
			}
		}
	}
	return nil
}
