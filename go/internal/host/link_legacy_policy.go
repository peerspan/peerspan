package host

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// Original-person policy submissions use the same durable exact catalog as
// device authorizations. Commit locally before attempting propagation so an
// offline withdrawal takes effect immediately and retries retain its bytes.
func (s *Store) submitLinkLegacyPolicy(ctx context.Context, network string, policy membership.Policy) (membership.Policy, error) {
	s.syncing.Lock()
	err := func() error {
		n, e := s.Network(ctx, network)
		if e != nil {
			return e
		}
		now, e := linkNow()
		if e != nil {
			return e
		}
		body, e := linkJSON(policy)
		if e != nil {
			return e
		}
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		prior, e := readLinkCatalog(ctx, tx, network)
		if e != nil {
			return e
		}
		old, e := decodeLinkCatalog(prior, network)
		if e != nil {
			return e
		}
		proofID := linkProofID("policy", body)
		for _, object := range old.Objects {
			if object.ID == proofID {
				return nil
			}
		}
		delta, e := catalogWithLinkObject(network, "policy", body)
		if e != nil {
			return e
		}
		union, e := mergeLinkCatalog(network, prior, delta)
		if e != nil {
			return e
		}
		projection, e := s.verifyLinkProjection(ctx, tx, n, union, now)
		if e != nil {
			return e
		}
		fact := linking.CatalogFactContext{Network: projection.Descriptor, Epoch: projection.Network.Epoch, KnownFeatureID: projection.Network.Facts.FeatureID, Now: now}
		if e = linking.VerifyStoredCatalogAdditions(fact, prior, union); e != nil {
			return e
		}
		g, e := s.loadGovernance(ctx, tx, network)
		if e != nil {
			return e
		}
		own, e := s.ownPerson(ctx, tx, network)
		if e != nil {
			return e
		}
		person := personIDOf(policy.PersonPublicKey)
		var reservation *policyEditRecord
		if own == person {
			var current *membership.Policy
			if p, ok := g.storedPolicy(policy.PersonPublicKey); ok {
				current = &p
			}
			reservation, e = s.checkEdit(ctx, tx, network, person, current, policy, now)
			if e != nil {
				return e
			}
		}
		selected, e := linking.SelectStoredProofCatalog(fact, union, []linking.ProofSeed{{Kind: "policy", Body: body}})
		if e != nil {
			return e
		}
		mutation, e := linkJSON(map[string]any{"catalog": json.RawMessage(selected)})
		if e != nil {
			return e
		}
		if len(mutation) > 1<<20 {
			return linkFail("quota_exceeded", "-", "policy")
		}
		members, e := readLinkMembers(ctx, tx, network)
		if e != nil {
			return e
		}
		members = projectedLinkMembers(projection, members, linkTime(now))
		if e = s.applyLinkProjection(ctx, tx, &n, projection, members, linkTime(now)); e != nil {
			return e
		}
		if reservation != nil {
			if e = s.recordEdit(ctx, tx, network, person, *reservation, policy, now); e != nil {
				return e
			}
		}
		if own != person {
			if e = queueDeliveries(ctx, tx, network, person, policy, []string{policyTargetCoordinator}, linkTime(now)); e != nil {
				return e
			}
			record, e := readJSON[policyDeliveryRecord](tx.QueryRowContext(ctx, `SELECT record FROM policy_deliveries WHERE network_id=? AND person_id=? AND target=?`, network, person, policyTargetCoordinator))
			if e != nil {
				return e
			}
			record.CatalogBase64 = base64.StdEncoding.EncodeToString(selected)
			if e = putJSON(ctx, tx, `UPDATE policy_deliveries SET record=? WHERE network_id=? AND person_id=? AND target=?`, record, network, person, policyTargetCoordinator); e != nil {
				return e
			}
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		s.mapApplied(network, members)
		return nil
	}()
	s.syncing.Unlock()
	if err != nil {
		return policy, err
	}
	return policy, s.afterSubmit(ctx, network, personIDOf(policy.PersonPublicKey))
}
