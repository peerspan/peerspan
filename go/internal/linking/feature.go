package linking

import (
	"encoding/json"
	"time"
)

// FeatureContext pins verified local state. Catalog presence never supplies the
// previously persisted feature ID. Its epoch selects the verified root-chain tip.
type FeatureContext struct {
	Network        []byte
	Epoch          uint64
	KnownFeatureID string
	Now            time.Time
}

// FeatureEvidence is eligibility for a future atomic activation, not persistence
// or proof that an acknowledging machine actually runs upgraded software.
type FeatureEvidence struct {
	NetworkID   string `json:"network_id"`
	FeatureID   string `json:"feature_id"`
	Epoch       uint64 `json:"epoch"`
	Disposition string `json:"disposition"`
}

func VerifyFeature(ctx FeatureContext, catalog, feature []byte) (FeatureEvidence, error) {
	return verifyFeature(ctx, catalog, feature, false)
}
func verifyFeature(ctx FeatureContext, catalog, feature []byte, stored bool) (FeatureEvidence, error) {
	bad := func(code string) (FeatureEvidence, error) { return FeatureEvidence{}, pathError(code) }
	if !verificationBudget(stored, len(ctx.Network), len(catalog), len(feature)) {
		return bad("invalid")
	}
	v, e := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, stored)
	if e != nil {
		return FeatureEvidence{}, e
	}
	if e = v.catalog(catalog); e != nil {
		return FeatureEvidence{}, e
	}
	if e = v.loadRoots(); e != nil {
		return FeatureEvidence{}, e
	}
	o, e := parse(feature)
	if e != nil {
		return bad("invalid")
	}
	proposal, e := parse(o["proposal"])
	if e != nil {
		return bad("invalid")
	}
	root, proposalEpoch, e := v.epochRoot(proposal, "epoch")
	if e != nil {
		return FeatureEvidence{}, e
	}
	r, e := Read("feature", feature, root, "-")
	if e != nil {
		return bad("invalid")
	}
	if ctx.KnownFeatureID != "-" && ctx.KnownFeatureID != r.ID {
		return bad("state_conflict")
	}
	if _, e = v.index("feature", feature); e != nil {
		return FeatureEvidence{}, e
	}
	first := ctx.KnownFeatureID == "-"
	if first {
		if proposalEpoch != v.epoch {
			return bad("invalid")
		}
		// A pending linking operation cannot justify the roster of the reader
		// upgrade that must precede that very operation.
		for _, p := range v.proofs {
			switch p.kind {
			case "activation", "certificate", "person_record", "root_record", "device_revocation", "checkpoint", "invite_redemption":
				return bad("forbidden")
			}
		}
	}
	if e = v.bootstrap(!first); e != nil {
		return FeatureEvidence{}, e
	}
	if e = v.revocations(); e != nil {
		return FeatureEvidence{}, e
	}
	if !first {
		return FeatureEvidence{v.net, r.ID, ctx.Epoch, "already_enabled"}, nil
	}

	issued, _ := stamp(scalar(proposal, "issued_at"))
	if ctx.Now.Before(issued) || !ctx.Now.Before(issued.Add(24*time.Hour)) {
		return bad("expired")
	}
	roster, _ := stringsOf(proposal, "host_public_keys")
	current := map[string]bool{}
	for host, admitted := range v.state.Hosts {
		if admitted {
			current[host] = true
		}
	}
	if len(current) != len(roster) {
		return bad("state_conflict")
	}
	for _, host := range roster {
		if !current[host] {
			return bad("state_conflict")
		}
	}
	return FeatureEvidence{v.net, r.ID, ctx.Epoch, "activate"}, nil
}

func featureProbe(o Object, stored bool) any {
	verify := VerifyFeature
	if stored {
		verify = VerifyStoredFeature
	}
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
	if fields(o, "kind network_base64 catalog_base64 feature_base64 epoch known_feature_id now") != nil {
		return fail(invalid())
	}
	b := [][]byte{}
	for _, name := range []string{"network_base64", "catalog_base64", "feature_base64"} {
		raw, e := decode(scalar(o, name), catalogProbeLimit(name, stored))
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
	r, e := verify(FeatureContext{b[0], epoch, scalar(o, "known_feature_id"), now}, b[1], b[2])
	if e != nil {
		return fail(e)
	}
	data, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	out["ok"] = true
	return out
}
