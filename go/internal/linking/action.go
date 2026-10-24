package linking

import (
	"encoding/json"
	"time"
)

// ActionContext pins independently verified local state and the exact selected
// signer. A catalog feature cannot substitute a previously persisted feature.
type ActionContext struct {
	Network                                        []byte
	Epoch                                          uint64
	KnownFeatureID, PersonPublicKey, CertificateID string
	Now                                            time.Time
}

// ActionAuthority proves current signing authority. It does not apply the action
// or check the future writer's conflict, version, freshness or retry state.
type ActionAuthority struct {
	ActionKind      string `json:"action_kind"`
	RecordID        string `json:"record_id"`
	NetworkID       string `json:"network_id"`
	FeatureID       string `json:"feature_id"`
	PersonPublicKey string `json:"person_public_key"`
	CertificateID   string `json:"certificate_id"`
	RequiredScope   uint64 `json:"required_scope"`
	NotAfter        string `json:"not_after"`
}

// ActionInvalidation identifies the selected path a delegated mutation would
// disable. Certificate IDs retain their order from oldest ancestor to leaf.
type ActionInvalidation struct {
	CertificateIDs []string
}

func (e *ActionInvalidation) Error() string { return "linking action: authority_would_be_invalidated" }

func actionScope(kind string) uint64 {
	switch kind {
	case "peerspan-policy-v1", "peerspan-policy-v2":
		return 1
	case "peerspan-host-bind-v1", "peerspan-host-unbind-v1":
		return 2
	case "peerspan-host-admit-v1", "peerspan-person-admit-v1", "peerspan-person-remove-v1", "peerspan-revoke-host-v1", "peerspan-revoke-invite-v1", "peerspan-invite-v1", "peerspan-person-invite-v1", "peerspan-group-v1":
		return 8
	}
	return 0
}

func VerifyActionAuthority(ctx ActionContext, actionKind string, catalog, action []byte) (ActionAuthority, error) {
	bad := func(code string) (ActionAuthority, error) { return ActionAuthority{}, pathError(code) }
	if len(ctx.Network)+len(catalog)+len(action) > MaxActivation || !key(ctx.PersonPublicKey) || ctx.CertificateID != "root" && !identifier(ctx.CertificateID, "dc_") || actionKind != "person_record" && actionKind != "device_revocation" {
		return bad("invalid")
	}
	v, e := newCatalogVerifier(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now)
	if e != nil {
		return ActionAuthority{}, e
	}
	if ctx.KnownFeatureID == "-" {
		return bad("upgrade_required")
	}
	o, e := parse(action)
	if e != nil || scalar(o, "network_id") != v.net || scalar(o, "person_public_key") != ctx.PersonPublicKey {
		return bad("invalid")
	}
	kind := scalar(o, "kind")
	required := uint64(4)
	if actionKind == "person_record" {
		if scalar(o, "certificate_id") != ctx.CertificateID || scalar(o, "operation_id") != "-" || !zeroEpoch(o) {
			return bad("invalid")
		}
		required = actionScope(kind)
		if required == 0 {
			return bad("invalid")
		}
	} else if scalar(o, "issuer_certificate_id") != ctx.CertificateID {
		return bad("invalid")
	}
	if e = v.catalog(catalog); e != nil {
		return ActionAuthority{}, e
	}
	if e = v.bootstrap(true); e != nil {
		return ActionAuthority{}, e
	}
	if e = v.revocations(); e != nil {
		return ActionAuthority{}, e
	}
	path, e := v.authority(ctx.PersonPublicKey, ctx.CertificateID, required, 0)
	if e != nil {
		return ActionAuthority{}, e
	}
	r, e := Read(actionKind, action, path.SignerPublicKey, "-")
	if e != nil {
		return bad("invalid")
	}
	invalidate := func() (ActionAuthority, error) {
		return ActionAuthority{}, &ActionInvalidation{CertificateIDs: append([]string{}, path.CertificateIDs...)}
	}
	if actionKind == "device_revocation" {
		target, e := v.structural(scalar(o, "target_certificate_id"), ctx.PersonPublicKey)
		if e != nil {
			return ActionAuthority{}, e
		}
		if target.device != scalar(o, "target_device_public_key") {
			return bad("invalid")
		}
		for _, id := range path.CertificateIDs {
			c, _ := pathCertificateFrom(id, v.state.Certificates[id]) // verified path
			if c.device == target.device {
				return invalidate()
			}
		}
		if ctx.CertificateID != "root" && !v.ancestor(ctx.CertificateID, target.id) {
			return bad("forbidden")
		}
	} else {
		p, _ := parse(r.Payload) // Read verified the strict unsigned payload.
		var expiry string
		switch kind {
		case "peerspan-policy-v1", "peerspan-policy-v2":
			expiry = scalar(p, "valid_until")
		case "peerspan-invite-v1", "peerspan-person-invite-v1":
			expiry = scalar(p, "invite_expires_at")
			until, _ := stamp(expiry)
			if !ctx.Now.Before(until) {
				return bad("expired")
			}
			if until.After(ctx.Now.Add(30 * 24 * time.Hour)) {
				return bad("invalid")
			}
		}
		if expiry != "" && path.NotAfter != "-" {
			until, _ := stamp(expiry)
			limit, _ := stamp(path.NotAfter)
			if until.After(limit) {
				return bad("forbidden")
			}
		}
		if ctx.CertificateID != "root" {
			if kind == "peerspan-person-remove-v1" && scalar(p, "person_public_key") == ctx.PersonPublicKey {
				return invalidate()
			}
			if kind == "peerspan-host-unbind-v1" || kind == "peerspan-revoke-host-v1" {
				for _, host := range path.HostPublicKeys {
					if host == scalar(p, "host_public_key") {
						return invalidate()
					}
				}
			}
		}
	}
	return ActionAuthority{actionKind, r.ID, v.net, v.feature, ctx.PersonPublicKey, ctx.CertificateID, required, path.NotAfter}, nil
}

func actionProbe(o Object) any {
	fail := func(e error) any {
		if p, ok := e.(*ActionInvalidation); ok {
			return map[string]any{"ok": false, "code": "authority_would_be_invalidated", "certificate_ids": p.CertificateIDs}
		}
		r := map[string]any{"ok": false, "code": "invalid"}
		if p, ok := e.(*PathError); ok {
			r["code"] = p.Code
			if p.Code == "proof_required" {
				r["required_ids"] = p.RequiredIDs
			}
		}
		return r
	}
	if fields(o, "kind action_kind network_base64 catalog_base64 action_base64 epoch known_feature_id person_public_key certificate_id now") != nil {
		return fail(invalid())
	}
	b := [][]byte{}
	for _, name := range []string{"network_base64", "catalog_base64", "action_base64"} {
		raw, e := decode(scalar(o, name), MaxActivation)
		if e != nil {
			return fail(e)
		}
		b = append(b, raw)
	}
	epoch, e := num(o, "epoch")
	if e != nil {
		return fail(e)
	}
	now, e := stamp(scalar(o, "now"))
	if e != nil {
		return fail(e)
	}
	r, e := VerifyActionAuthority(ActionContext{b[0], epoch, scalar(o, "known_feature_id"), scalar(o, "person_public_key"), scalar(o, "certificate_id"), now}, scalar(o, "action_kind"), b[1], b[2])
	if e != nil {
		return fail(e)
	}
	data, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	out["ok"] = true
	return out
}
