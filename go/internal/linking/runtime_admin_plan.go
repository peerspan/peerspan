package linking

import (
	"sort"
	"strconv"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// BuildStoredAdminRemovalPlan returns exact eligible historical grant tags.
// It neither signs a withdrawal nor grants authority to its caller.
func BuildStoredAdminRemovalPlan(ctx CatalogFactContext, catalog []byte, person string) ([]string, error) {
	if !key(person) {
		return nil, pathError("invalid")
	}
	if ctx.KnownFeatureID == "-" {
		return nil, pathError("upgrade_required")
	}
	v, e := storedWriterVerifier(ctx, catalog)
	if e != nil {
		return nil, e
	}
	if !v.history.delegated[person] {
		return nil, pathError("proof_required")
	}
	access, e := VerifyStoredAccessState(AccessContext{Network: ctx.Network, Epoch: ctx.Epoch, KnownFeatureID: ctx.KnownFeatureID, Now: ctx.Now}, catalog)
	if e != nil {
		return nil, e
	}
	groups := map[string]bool{}
	for _, selected := range access.Groups {
		if selected.Active {
			groups[selected.ProofID] = true
			groups[selected.RecordID] = true
		}
	}
	kept := map[string]bool{}
	addLegacy := func(m []byte, sig string) error {
		if v.anyRootSignature(m, sig) {
			return nil
		}
		public, ok := membership.SSHSIGKey(sig)
		if !ok || membership.EncodeKey(public) != person {
			return nil
		}
		valid, e := v.legacyAuthority(m, sig)
		if e != nil {
			return e
		}
		if valid {
			kept["legacy:"+digest(m)] = true
		}
		return nil
	}
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		o := p.object
		if p.kind == "invite_redemption" {
			r, e := v.readRedemption(p)
			if e != nil {
				return nil, e
			}
			eligible := true
			issued := false
			if scalar(o, "mode") != "person" && !v.state.Hosts[scalar(o, "host_public_key")] {
				eligible = false
			}
			if scalar(o, "person_action") == "admit" && !v.state.Persons[scalar(o, "person_public_key")].Admitted {
				eligible = false
			}
			for _, h := range r.halves {
				if h.person != person {
					eligible = false
					continue
				}
				issued = true
				valid, e := v.redemptionHalf(id, h)
				if e != nil {
					return nil, e
				}
				eligible = eligible && valid
			}
			if eligible && issued {
				kept["redemption:"+id] = true
				for _, h := range r.halves {
					if !h.legacy {
						kept["record:"+h.record] = true
						continue
					}
					part := "person_invite"
					kind := "peerspan-person-invite-v1"
					if h.host {
						part = "host_invite"
						kind = "peerspan-invite-v1"
					}
					half, e := parse(o[part])
					if e != nil {
						return nil, e
					}
					parts := []string{kind, v.net}
					if !h.host {
						parts = append(parts, strconv.FormatUint(h.epoch, 10))
					}
					parts = append(parts, h.key, h.label, h.expires)
					if e = addLegacy(message(parts...), scalar(half, "signature")); e != nil {
						return nil, e
					}
				}
			}
			continue
		}
		m, sig, e := adminPlanLegacyMessage(v, p, groups[id])
		if e != nil {
			return nil, e
		}
		if len(m) != 0 {
			if e = addLegacy(m, sig); e != nil {
				return nil, e
			}
		}
	}
	ids := make([]string, 0, len(v.evidence))
	for id := range v.evidence {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := v.evidence[id]
		o := p.object
		if p.kind != "person_record" || scalar(o, "person_public_key") != person || v.inlineInvites[id] {
			continue
		}
		kind := scalar(o, "kind")
		if kind == "peerspan-group-v1" {
			if groups[id] {
				kept["record:"+id] = true
			}
			continue
		}
		if ordinaryScope(kind) != 8 {
			continue
		}
		_, _, scope, e := v.retentionSubject(id)
		if e != nil {
			return nil, e
		}
		if e = v.historicalRecord(SignedObject{ID: id}, o, scope, 0); e != nil {
			if failure, ok := e.(*PathError); ok && (failure.Code == "forbidden" || failure.Code == "authority_expired" || failure.Code == "device_revoked") {
				continue
			}
			return nil, e
		}
		_, payload, e := payload(o)
		if e != nil {
			return nil, e
		}
		if kind == "peerspan-host-admit-v1" && !v.state.Hosts[scalar(payload, "host_public_key")] {
			continue
		}
		if kind == "peerspan-person-admit-v1" && !v.state.Persons[scalar(payload, "person_public_key")].Admitted {
			continue
		}
		kept["record:"+id] = true
	}
	out := make([]string, 0, len(kept))
	for tag := range kept {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out, nil
}
func adminPlanLegacyMessage(v *activationVerifier, p catalogProof, selectedGroup bool) ([]byte, string, error) {
	o := p.object
	sig := scalar(o, "signature")
	parts := []string{}
	switch p.kind {
	case "host_admission", "person_admission":
		field, kind := "host_public_key", "peerspan-host-admit-v1"
		if p.kind == "person_admission" {
			field, kind = "person_public_key", "peerspan-person-admit-v1"
			if !v.state.Persons[scalar(o, field)].Admitted {
				return nil, "", nil
			}
		} else if !v.state.Hosts[scalar(o, field)] {
			return nil, "", nil
		}
		epoch, _ := num(o, "epoch")
		parts = []string{kind, v.net, strconv.FormatUint(epoch, 10), scalar(o, field), scalar(o, "member"), scalar(o, "admitted_at")}
	case "host_membership", "person_membership":
		person := p.kind == "person_membership"
		if person && !v.state.Persons[scalar(o, "person_public_key")].Admitted || !person && !v.state.Hosts[scalar(o, "host_public_key")] {
			return nil, "", nil
		}
		valid, e := v.legacyMembership(p, person)
		if e != nil {
			return nil, "", e
		}
		if !valid {
			return nil, "", nil
		}
		sig = scalar(o, "invite_signature")
		parts = []string{"peerspan-invite-v1", v.net}
		if person {
			epoch, _ := num(o, "invite_epoch")
			parts = []string{"peerspan-person-invite-v1", v.net, strconv.FormatUint(epoch, 10)}
		}
		parts = append(parts, scalar(o, "invite_public_key"), scalar(o, "member"), scalar(o, "invite_expires_at"))
	case "group":
		if !selectedGroup {
			return nil, "", nil
		}
		version, _ := num(o, "version")
		members, _ := stringsOf(o, "members")
		parts = append([]string{"peerspan-group-v1", v.net, scalar(o, "name"), strconv.FormatUint(version, 10), scalar(o, "defined_at")}, members...)
	case "person_removal":
		parts = []string{"peerspan-person-remove-v1", v.net, scalar(o, "person_public_key"), scalar(o, "removed_at")}
	case "host_revocation":
		parts = []string{"peerspan-revoke-host-v1", v.net, scalar(o, "host_public_key"), scalar(o, "revoked_at")}
	case "invite_revocation":
		parts = []string{"peerspan-revoke-invite-v1", v.net, scalar(o, "invite_public_key"), scalar(o, "revoked_at")}
	default:
		return nil, "", nil
	}
	return message(parts...), sig, nil
}
func adminRemovalPlanProbe(o Object) any {
	fail := func(e error) any {
		out := map[string]any{"ok": false, "code": "invalid"}
		if p, ok := e.(*PathError); ok {
			out["code"] = p.Code
			if p.Code == "proof_required" {
				out["required_ids"] = p.RequiredIDs
			}
		}
		return out
	}
	if fields(o, "kind network_base64 catalog_base64 epoch known_feature_id now person_public_key") != nil {
		return fail(invalid())
	}
	network, e := decode(scalar(o, "network_base64"), MaxActivation)
	if e != nil {
		return fail(e)
	}
	catalog, e := decode(scalar(o, "catalog_base64"), MaxStoredCatalog)
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
	kept, e := BuildStoredAdminRemovalPlan(CatalogFactContext{Network: network, Epoch: epoch, KnownFeatureID: scalar(o, "known_feature_id"), Now: now}, catalog, scalar(o, "person_public_key"))
	if e != nil {
		return fail(e)
	}
	return map[string]any{"ok": true, "kept": kept}
}
