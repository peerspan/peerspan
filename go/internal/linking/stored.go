package linking

import (
	"encoding/json"
	"time"
)

const MaxStoredCatalog = 16 << 20
const MaxStoredBodies = 8 << 20
const MaxStoredProbe = 24 << 20

func verificationBudget(stored bool, network, catalog, object int) bool {
	if stored {
		return catalog <= MaxStoredCatalog && network+object <= MaxActivation
	}
	return network+catalog+object <= MaxActivation
}

func newCatalogVerifierWithBudget(network []byte, epoch uint64, feature string, now time.Time, stored bool) (*activationVerifier, error) {
	v, e := newCatalogVerifier(network, epoch, feature, now)
	if e == nil {
		v.storedSnapshot = stored
	}
	return v, e
}

func catalogProbeLimit(field string, stored bool) int {
	if stored && field == "catalog_base64" {
		return MaxStoredCatalog
	}
	return MaxActivation
}

func parseCatalog(body []byte, stored bool) (Object, error) {
	if stored {
		return parseLimit(body, MaxStoredCatalog)
	}
	return parse(body)
}

func catalogEntries(o Object, stored bool) ([]Object, error) {
	if !stored {
		return pathEntries(o, "objects")
	}
	var rows []json.RawMessage
	if json.Unmarshal(o["objects"], &rows) != nil || rows == nil || len(rows) > 4096 {
		return nil, pathError("invalid")
	}
	entries := make([]Object, 0, len(rows))
	for _, raw := range rows {
		entry, e := parseLimit(raw, MaxStoredCatalog)
		if e != nil {
			return nil, e
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// VerifyStoredCatalogFacts verifies a complete stored snapshot without truncation.
func VerifyStoredCatalogFacts(ctx CatalogFactContext, catalog []byte) (CatalogFacts, error) {
	return verifyCatalogFacts(ctx, catalog, true)
}

// VerifyStoredActivation preserves the full stored dependency catalog budget.
func VerifyStoredActivation(ctx ActivationContext, catalog, activation []byte) (ActivationEvidence, error) {
	return verifyActivation(ctx, catalog, activation, true)
}

// VerifyStoredActionAuthority verifies an action against the complete stored state.
func VerifyStoredActionAuthority(ctx ActionContext, kind string, catalog, action []byte) (ActionAuthority, error) {
	return verifyActionAuthority(ctx, kind, catalog, action, true)
}

// VerifyStoredFeature verifies feature eligibility against the complete stored state.
func VerifyStoredFeature(ctx FeatureContext, catalog, feature []byte) (FeatureEvidence, error) {
	return verifyFeature(ctx, catalog, feature, true)
}

// VerifyStoredAccessState observes access maxima over the complete stored state.
func VerifyStoredAccessState(ctx AccessContext, catalog []byte) (AccessState, error) {
	return verifyAccessState(ctx, catalog, true)
}

// ProbeStoredSnapshot is a fixed-budget conformance adapter, never a runtime route.
func ProbeStoredSnapshot(body []byte) any {
	fail := map[string]any{"ok": false, "code": "invalid"}
	o, e := parseLimit(body, MaxStoredProbe)
	if e != nil {
		return fail
	}
	switch scalar(o, "kind") {
	case "catalog_facts":
		return catalogFactsProbe(o, true)
	case "activation":
		return activationProbe(o, true)
	case "feature_activation":
		return featureProbe(o, true)
	case "action_authorization":
		return actionProbe(o, true)
	case "access_state":
		return accessStateProbe(o, true)
	}
	return fail
}
