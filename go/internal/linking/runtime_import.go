package linking

import (
	"strconv"
	"time"
)

// FeatureImportEvidence binds an explicit fresh current-root recovery action to
// one complete historical snapshot and the caller's actual target descriptor.
// It supplies no person, host, or device authority.
type FeatureImportEvidence struct {
	FeatureID string
	State     NetworkState
}

func VerifyStoredFeatureImport(ctx CatalogFactContext, catalog, authorization []byte) (FeatureImportEvidence, error) {
	fail := func(err error) (FeatureImportEvidence, error) { return FeatureImportEvidence{}, err }
	if len(authorization) > MaxObject || len(catalog) > 1<<20 {
		return fail(pathError("invalid"))
	}
	v, err := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
	if err != nil {
		return fail(err)
	}
	if err = v.catalog(catalog); err != nil {
		return fail(err)
	}
	if err = v.loadRoots(); err != nil {
		return fail(err)
	}
	if string(authorization) == `"-"` {
		feature := ""
		for _, p := range v.proofs {
			if p.kind != "feature" {
				continue
			}
			proposal, e := parse(p.object["proposal"])
			if e != nil {
				return fail(pathError("invalid"))
			}
			root, _, e := v.epochRoot(proposal, "epoch")
			if e != nil {
				return fail(e)
			}
			r, e := Read("feature", p.body, root, "-")
			if e != nil {
				return fail(pathError("invalid"))
			}
			if feature != "" && feature != r.ID {
				return fail(pathError("state_conflict"))
			}
			feature = r.ID
		}
		if feature == "" {
			return fail(pathError("upgrade_required"))
		}
		ctx.KnownFeatureID = feature
		if _, e := VerifyStoredNetworkState(ctx, catalog); e != nil {
			return fail(e)
		}
		return fail(pathError("proof_required", feature))
	}
	o, err := parse(authorization)
	if err != nil || fields(o, "format network_id network_name epoch feature_id coordinator_address coordinator_public_key catalog_sha256 issued_at expires_at signature") != nil || version(o, 1) != nil {
		return fail(pathError("invalid"))
	}
	for field, descriptor := range map[string]string{"network_id": "network_id", "network_name": "name", "coordinator_address": "coordinator_address", "coordinator_public_key": "coordinator_public_key"} {
		if scalar(o, field) != scalar(v.network, descriptor) {
			return fail(pathError("invalid"))
		}
	}
	epoch, err := num(o, "epoch")
	if err != nil || epoch != v.epoch {
		return fail(pathError("invalid"))
	}
	feature := scalar(o, "feature_id")
	if !identifier(feature, "lf_") {
		return fail(pathError("invalid"))
	}
	if ctx.KnownFeatureID != "-" && ctx.KnownFeatureID != feature {
		return fail(pathError("state_conflict"))
	}
	if scalar(o, "catalog_sha256") != digest(catalog) {
		return fail(pathError("invalid"))
	}
	issued, err := stamp(scalar(o, "issued_at"))
	if err != nil {
		return fail(pathError("invalid"))
	}
	expires, err := stamp(scalar(o, "expires_at"))
	if err != nil || expires.Sub(issued) != 300*time.Second {
		return fail(pathError("invalid"))
	}
	if ctx.Now.Before(issued) {
		return fail(pathError("invalid"))
	}
	if !ctx.Now.Before(expires) {
		return fail(pathError("expired"))
	}
	m := message("peerspan-link-feature-import-v1", scalar(o, "network_id"), scalar(o, "network_name"), strconv.FormatUint(epoch, 10), feature, scalar(o, "coordinator_address"), scalar(o, "coordinator_public_key"), scalar(o, "catalog_sha256"), scalar(o, "issued_at"), scalar(o, "expires_at"))
	if rootSignature(v.root, m, scalar(o, "signature")) != nil {
		return fail(pathError("invalid"))
	}
	ctx.KnownFeatureID = feature
	state, err := VerifyStoredNetworkState(ctx, catalog)
	if err != nil {
		return fail(err)
	}
	return FeatureImportEvidence{feature, state}, nil
}
