package linking

import "time"

// FeaturePreparation is current-roster eligibility, never enabled reader
// support. Only a complete separately verified feature can enable writers.
type FeaturePreparation struct {
	FeatureID string
	Epoch     uint64
	State     *PathState
}

// VerifyStoredFeaturePreparation validates an incomplete root proposal against
// the entire retained pre-upgrade snapshot without inventing host signatures.
// Its narrow bootstrap path accepts only existing legacy authority facts.
func VerifyStoredFeaturePreparation(ctx FeatureContext, catalog, proposal []byte) (FeaturePreparation, error) {
	bad := func(code string) (FeaturePreparation, error) { return FeaturePreparation{}, pathError(code) }
	if len(proposal) > MaxObject || ctx.KnownFeatureID != "-" {
		return bad("state_conflict")
	}
	v, err := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, "-", ctx.Now, true)
	if err != nil {
		return FeaturePreparation{}, err
	}
	if err = v.catalog(catalog); err != nil {
		return FeaturePreparation{}, err
	}
	if err = v.loadRoots(); err != nil {
		return FeaturePreparation{}, err
	}
	r, err := Read("feature_proposal", proposal, v.root, "-")
	if err != nil {
		return bad("invalid")
	}
	p, _ := parse(proposal)
	if scalar(p, "network_id") != v.net || !epochIs(p, ctx.Epoch) {
		return bad("invalid")
	}
	issued, _ := stamp(scalar(p, "issued_at"))
	if ctx.Now.Before(issued) || !ctx.Now.Before(issued.Add(24*time.Hour)) {
		return bad("expired")
	}
	for _, proof := range v.proofs {
		switch proof.kind {
		case "rotation", "attestation", "admin_delegation", "admin_removal", "person_admission", "person_membership", "host_membership", "host_admission", "host_binding", "host_unbinding", "host_leave", "host_revocation", "invite_revocation", "person_removal", "group", "policy", "coordinator_move", "coordinator_successor":
		default:
			return bad("forbidden")
		}
	}
	v.featurePreparation = true
	if err = v.bootstrap(false); err != nil {
		return FeaturePreparation{}, err
	}
	if err = v.revocations(); err != nil {
		return FeaturePreparation{}, err
	}
	hosts, _ := stringsOf(p, "host_public_keys")
	count := 0
	for _, admitted := range v.state.Hosts {
		if admitted {
			count++
		}
	}
	if count != len(hosts) {
		return bad("state_conflict")
	}
	for _, host := range hosts {
		if !v.state.Hosts[host] {
			return bad("state_conflict")
		}
	}
	return FeaturePreparation{r.ID, ctx.Epoch, v.state}, nil
}
