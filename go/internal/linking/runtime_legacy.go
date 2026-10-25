package linking

import (
	"encoding/json"
	"strconv"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// Historical signature recognition is deliberately broader than fresh writer
// authority. Newly submitted legacy mutations must use the current root or a
// currently admitted administrator, never a retired root or a kept withdrawal.
func freshLegacyMutation(kind string) bool {
	switch kind {
	case "admin_delegation", "admin_removal", "person_admission", "person_membership", "host_membership", "host_admission", "host_binding", "host_unbinding", "host_leave", "host_revocation", "invite_revocation", "person_removal", "policy", "group", "coordinator_move":
		return true
	}
	return false
}

func (v *activationVerifier) freshLegacy(p catalogProof) error {
	o := p.object
	rootOnly := false
	var m []byte
	sig := scalar(o, "signature")
	n := strconv.FormatUint(v.epoch, 10)
	switch p.kind {
	case "admin_delegation":
		if !epochIs(o, v.epoch) {
			return pathError("forbidden")
		}
		m = message("peerspan-admin-delegate-v1", v.net, n, scalar(o, "person_public_key"), scalar(o, "delegated_at"))
		rootOnly = true
	case "admin_removal":
		if _, ok := o["format"]; ok {
			if _, e := Read("admin_removal_v2", p.body, v.root, "-"); e != nil {
				return pathError("forbidden")
			}
			return nil
		}
		kept, e := stringsOf(o, "kept")
		if e != nil {
			return e
		}
		var revoke bool
		if e = json.Unmarshal(o["revoke_admitted"], &revoke); e != nil {
			return pathError("invalid")
		}
		m = message(append([]string{"peerspan-admin-remove-v1", v.net, scalar(o, "person_public_key"), boolText(revoke), scalar(o, "removed_at")}, kept...)...)
		rootOnly = true
	case "person_admission", "host_admission":
		if !epochIs(o, v.epoch) {
			return pathError("forbidden")
		}
		field, domain := "host_public_key", "peerspan-host-admit-v1"
		if p.kind == "person_admission" {
			field, domain = "person_public_key", "peerspan-person-admit-v1"
		}
		m = message(domain, v.net, n, scalar(o, field), scalar(o, "member"), scalar(o, "admitted_at"))
	case "host_membership", "person_membership":
		domain := "peerspan-invite-v1"
		parts := []string{domain, v.net}
		if p.kind == "person_membership" {
			epoch, e := num(o, "invite_epoch")
			if e != nil || epoch != v.epoch {
				return pathError("forbidden")
			}
			parts = []string{"peerspan-person-invite-v1", v.net, n}
		}
		parts = append(parts, scalar(o, "invite_public_key"), scalar(o, "member"), scalar(o, "invite_expires_at"))
		m = message(parts...)
		sig = scalar(o, "invite_signature")
		until, e := legacyStamp(scalar(o, "invite_expires_at"))
		if e != nil {
			return e
		}
		if !v.ctx.Now.Before(until) {
			return pathError("expired")
		}
		joined, e := legacyStamp(scalar(o, "joined_at"))
		if e != nil || v.ctx.Now.Before(joined) {
			return pathError("invalid")
		}
	case "host_binding", "host_unbinding":
		person, host := scalar(o, "person_public_key"), scalar(o, "host_public_key")
		if _, e := v.authority(person, "root", 2, 0); e != nil {
			return e
		}
		if !v.state.Hosts[host] {
			return pathError("forbidden")
		}
		if p.kind == "host_unbinding" && v.state.Bindings[host] != person {
			return pathError("state_conflict")
		}
		// Full snapshot verification already checked both original-person and
		// target-host consent; no legacy authority can substitute another person.
		return nil
	case "host_leave":
		if !v.state.Hosts[scalar(o, "host_public_key")] {
			return pathError("forbidden")
		}
		return nil
	case "host_revocation", "invite_revocation", "person_removal":
		domain, subject, at := "peerspan-revoke-host-v1", "host_public_key", "revoked_at"
		if p.kind == "invite_revocation" {
			domain, subject = "peerspan-revoke-invite-v1", "invite_public_key"
		}
		if p.kind == "person_removal" {
			domain, subject, at = "peerspan-person-remove-v1", "person_public_key", "removed_at"
		}
		m = message(domain, v.net, scalar(o, subject), scalar(o, at))
	case "coordinator_move":
		seq, e := num(o, "sequence")
		if e != nil {
			return e
		}
		m = message("peerspan-coordinator-move-v1", v.net, strconv.FormatUint(seq, 10), scalar(o, "address"), scalar(o, "public_key"), scalar(o, "moved_at"))
		if scalar(o, "signer") == "root" {
			rootOnly = true
		} else {
			pub, ok := membership.SSHSIGKey(sig)
			if !ok || membership.EncodeKey(pub) != scalar(o, "signer") {
				return pathError("invalid")
			}
		}
	default:
		return nil
	}
	if rootSignature(v.root, m, sig) == nil {
		return nil
	}
	if rootOnly {
		return pathError("forbidden")
	}
	pub, ok := membership.SSHSIGKey(sig)
	if !ok {
		return pathError("forbidden")
	}
	person := membership.EncodeKey(pub)
	if !v.state.Persons[person].Admitted || !v.state.Persons[person].Administrator {
		return pathError("forbidden")
	}
	if _, removed := v.history.withdrawals[person]; removed {
		return pathError("forbidden")
	}
	if personSignature(person, m, sig) != nil {
		return pathError("invalid")
	}
	return nil
}
