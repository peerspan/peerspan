package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// CapabilityClaimCatalog carries exact public proofs, never an unsigned view.
type CapabilityClaimCatalog struct {
	NetworkID string          `json:"network_id"`
	Catalog   json.RawMessage `json:"catalog"`
}

func (c *CapabilityClaimCatalog) UnmarshalJSON(raw []byte) error {
	type wire CapabilityClaimCatalog
	var value wire
	if e := linking.DecodeMutation(raw, "network_id catalog", &value); e != nil {
		return e
	}
	*c = CapabilityClaimCatalog(value)
	return nil
}

type linkCapabilityClaim struct {
	network     Network
	projection  *linkProjection
	policy      membership.Policy
	reservation *policyEditRecord
}

func capabilityPolicyClaim(policy membership.Policy, hostID, name string) bool {
	claimed := false
	for _, rule := range policy.CapabilityRules {
		if rule.Capability != name {
			continue
		}
		if rule.Host != hostID {
			return false
		}
		claimed = true
	}
	return claimed
}
func (s *Store) prepareCapabilityCatalogs(ctx context.Context, tx *sql.Tx, request CreateCapability, now time.Time) (map[string]linkCapabilityClaim, error) {
	out := map[string]linkCapabilityClaim{}
	for _, submitted := range request.Catalogs {
		if _, duplicate := out[submitted.NetworkID]; duplicate {
			return nil, linkFail("invalid", "-", "capability_claim")
		}
		for _, legacy := range request.Policies {
			if legacy.NetworkID == submitted.NetworkID {
				return nil, linkFail("invalid", "-", "capability_claim")
			}
		}
		n, e := scanNetwork(tx.QueryRowContext(ctx, networkColumns+" WHERE id=?", submitted.NetworkID))
		if e != nil {
			return nil, e
		}
		before, e := s.readLinkProjection(ctx, tx, n, now)
		if e != nil {
			return nil, e
		}
		if before == nil {
			return nil, linkFail("upgrade_required", "-", "feature")
		}
		person, e := s.ownPerson(ctx, tx, n.ID)
		if e != nil {
			return nil, e
		}
		if person == "" {
			return nil, linkFail("forbidden", "-", "person")
		}
		union, e := mergeLinkCatalog(n.ID, before.Catalog, submitted.Catalog)
		if e != nil {
			return nil, e
		}
		p, e := s.verifyLinkProjection(ctx, tx, n, union, now)
		if e != nil {
			return nil, e
		}
		fact := linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}
		if e = linking.VerifyStoredCatalogAdditions(fact, before.Catalog, union); e != nil {
			return nil, e
		}
		var policy membership.Policy
		var record []byte
		recordKind := ""
		for _, selected := range p.Access.Policies {
			if !selected.Active || personIDOf(selected.PersonPublicKey) != person {
				continue
			}
			policy = p.Policies[selected.PersonPublicKey]
			for _, object := range p.Objects.Objects {
				if object.ID == selected.ProofID {
					recordKind = object.Kind
					break
				}
			}
			record, e = linkBytes(selected.BodyBase64, linking.MaxObject)
			if e != nil {
				return nil, e
			}
			break
		}
		if len(record) == 0 || !capabilityPolicyClaim(policy, s.identity.ID, request.Name) {
			return nil, linkFail("invalid", "-", "capability_claim")
		}
		if recordKind == "policy" {
			if e = membership.VerifyPolicy(n.ID, policy); e != nil {
				return nil, e
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(record, &fields) != nil {
				return nil, linkFail("invalid", "-", "capability_claim")
			}
			delete(fields, "signature")
			payload, e := linkJSON(fields)
			if e != nil {
				return nil, e
			}
			if e = s.linkActionPreconditions(before, policy.PersonPublicKey, "peerspan-policy-v2", payload, now); e != nil {
				return nil, e
			}
		} else {
			var envelope struct {
				Kind        string `json:"kind"`
				Person      string `json:"person_public_key"`
				Certificate string `json:"certificate_id"`
				Payload     string `json:"payload_base64"`
			}
			if recordKind != "person_record" || json.Unmarshal(record, &envelope) != nil || envelope.Kind != "peerspan-policy-v2" || envelope.Person != policy.PersonPublicKey {
				return nil, linkFail("invalid", "-", "capability_claim")
			}
			payload, e := linkBytes(envelope.Payload, linking.MaxPayload)
			if e != nil {
				return nil, e
			}
			if e = s.linkActionPreconditions(before, envelope.Person, envelope.Kind, payload, now); e != nil {
				return nil, e
			}
			if _, e = linking.VerifyStoredActionAuthority(linking.ActionContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, PersonPublicKey: envelope.Person, CertificateID: envelope.Certificate, Now: now}, "person_record", union, record); e != nil {
				return nil, e
			}
		}
		var prior *membership.Policy
		if old, ok := before.Policies[policy.PersonPublicKey]; ok {
			prior = &old
		}
		reservation, e := s.checkEdit(ctx, tx, n.ID, person, prior, policy, now)
		if e != nil {
			return nil, e
		}
		out[n.ID] = linkCapabilityClaim{n, p, policy, reservation}
	}
	return out, nil
}
func (s *Store) applyCapabilityCatalog(ctx context.Context, tx *sql.Tx, claim linkCapabilityClaim, now time.Time) error {
	members, e := readLinkMembers(ctx, tx, claim.network.ID)
	if e != nil {
		return e
	}
	members = projectedLinkMembers(claim.projection, members, linkTime(now))
	if e = s.applyLinkProjection(ctx, tx, &claim.network, claim.projection, members, linkTime(now)); e != nil {
		return e
	}
	if claim.reservation != nil {
		return s.recordEdit(ctx, tx, claim.network.ID, personIDOf(claim.policy.PersonPublicKey), *claim.reservation, claim.policy, now)
	}
	return nil
}
func decodePolicyClaimIntent(payload []byte) (string, []byte, error) {
	var request struct {
		Capability   string `json:"capability"`
		PolicyBase64 string `json:"policy_base64"`
	}
	if linking.DecodeMutation(payload, "capability policy_base64", &request) != nil || !membership.ValidCapabilityName(request.Capability) {
		return "", nil, linkFail("invalid", "-", "capability_claim")
	}
	raw, e := linkBytes(request.PolicyBase64, linking.MaxPayload)
	if e != nil {
		return "", nil, e
	}
	if linking.ValidateActionPayload("peerspan-policy-v2", raw) != nil {
		return "", nil, linkFail("invalid", "-", "capability_claim")
	}
	return request.Capability, raw, nil
}
func addClaimPolicyCatalog(network string, selected, record []byte) ([]byte, error) {
	entry, e := catalogWithLinkObject(network, "person_record", record)
	if e != nil {
		return nil, e
	}
	return mergeLinkCatalog(network, selected, entry)
}
