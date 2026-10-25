package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func (s *Store) queueLinkPolicies(ctx context.Context, tx *sql.Tx, n Network, p *linkProjection, members []NetworkMember, prior []linking.PolicyHighWater, stamp string) error {
	own := ""
	targets := []string{policyTargetCoordinator}
	for _, m := range members {
		if m.HostID == s.identity.ID && m.PersonID != nil {
			own = *m.PersonID
		}
	}
	if own == "" {
		return nil
	}
	for _, m := range members {
		if m.HostID != s.identity.ID && m.PersonID != nil && *m.PersonID == own {
			targets = append(targets, m.HostID)
		}
	}
	old := map[string]linking.AccessHighWater{}
	for _, w := range prior {
		old[w.PersonPublicKey] = w.AccessHighWater
	}
	now, e := linkStamp(stamp)
	if e != nil {
		return e
	}
	for _, selection := range p.Access.Policies {
		if !selection.Active || personIDOf(selection.PersonPublicKey) != own || old[selection.PersonPublicKey] == selection.AccessHighWater {
			continue
		}
		body, e := linkBytes(selection.BodyBase64, linking.MaxObject)
		if e != nil {
			return e
		}
		kind := "policy"
		if selection.RecordID != "-" {
			kind = "person_record"
		}
		catalog, e := linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, []linking.ProofSeed{{Kind: kind, Body: body}})
		if e != nil {
			return e
		}
		mutation, e := linkJSON(map[string]any{"catalog": json.RawMessage(catalog)})
		if e != nil {
			return e
		}
		if len(mutation) > 1<<20 {
			return linkFail("quota_exceeded", "-", "delivery")
		}
		policy := p.Policies[selection.PersonPublicKey]
		if e = queueDeliveries(ctx, tx, n.ID, own, policy, targets, stamp); e != nil {
			return e
		}
		for _, target := range targets {
			record, e := readJSON[policyDeliveryRecord](tx.QueryRowContext(ctx, `SELECT record FROM policy_deliveries WHERE network_id=? AND person_id=? AND target=?`, n.ID, own, target))
			if e != nil {
				return e
			}
			record.CatalogBase64 = base64.StdEncoding.EncodeToString(catalog)
			if e = putJSON(ctx, tx, `UPDATE policy_deliveries SET record=? WHERE network_id=? AND person_id=? AND target=?`, record, n.ID, own, target); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Store) deliverLinkCatalog(ctx context.Context, n Network, target, encoded string) error {
	catalog, e := linkBytes(encoded, linking.MaxStoredCatalog)
	if e != nil {
		return linkFail("state_conflict", "-", "delivery")
	}
	if _, e = decodeLinkCatalog(catalog, n.ID); e != nil {
		return e
	}
	body, e := linkJSON(map[string]any{"catalog": json.RawMessage(catalog)})
	if e != nil {
		return e
	}
	if len(body) > 1<<20 {
		return linkFail("quota_exceeded", "-", "delivery")
	}
	if target == policyTargetCoordinator {
		raw, e := s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+n.ID+"/statements", body)
		if e != nil {
			return e
		}
		wire, e := decodeLinkMap(raw, n)
		if e != nil {
			return e
		}
		return s.acceptLinkDeliveryReceipt(ctx, n, target, catalog, wire.Catalog)
	}
	peer, e := s.dialPeer(ctx, target)
	if e != nil {
		return e
	}
	status, raw, e := s.peerRequestLimit(ctx, peer, http.MethodPost, "/peer/v1/networks/"+url.PathEscape(n.ID)+"/link-catalog", body, 16<<20)
	if e != nil {
		return e
	}
	if status != 200 {
		return linkFail("unavailable", "-", "delivery")
	}
	var response struct {
		Catalog json.RawMessage `json:"catalog"`
	}
	if linking.DecodeStoredJSON(raw, "catalog", &response) != nil || len(raw) > 16<<20 {
		return linkFail("invalid", "-", "delivery")
	}
	return s.acceptLinkDeliveryReceipt(ctx, n, target, catalog, response.Catalog)
}

// A successful transport response acknowledges only exact retained public
// objects. Verify the receiver's complete catalog before acknowledging edits;
// a newer whole-body selection need not contain the edits in an older delivery.
func (s *Store) acceptLinkDeliveryReceipt(ctx context.Context, n Network, target string, sent, received []byte) error {
	objects, e := decodeLinkCatalog(sent, n.ID)
	if e != nil {
		return e
	}
	receipt, e := decodeLinkCatalog(received, n.ID)
	if e != nil {
		return e
	}
	retained := map[string]bool{}
	for _, object := range receipt.Objects {
		retained[object.ID] = true
	}
	for _, object := range objects.Objects {
		if !retained[object.ID] {
			return linkFail("proof_required", "-", "delivery", object.ID)
		}
	}
	now, e := linkNow()
	if e != nil {
		return e
	}
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return e
	}
	epoch, e := linkCatalogEpoch(receipt)
	if e != nil {
		return e
	}
	feature, _, e := readLinkFeature(ctx, s.db, n.ID)
	if e != nil {
		return e
	}
	if _, e = linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: feature, Now: now}, received); e != nil {
		return e
	}
	access, e := linking.VerifyStoredAccessState(linking.AccessContext{Network: descriptor, Epoch: epoch, KnownFeatureID: feature, Now: now}, received)
	if e != nil {
		return e
	}
	for _, selected := range access.Policies {
		if !selected.Active {
			continue
		}
		body, _, e := projectedAccessBody(selected.AccessSelection)
		if e != nil {
			return e
		}
		var policy membership.Policy
		if json.Unmarshal(body, &policy) != nil {
			return linkFail("invalid", "-", "delivery")
		}
		s.ackEdits(n.ID, personIDOf(selected.PersonPublicKey), target, policy.EditSeq(s.identity.ID))
	}
	return nil
}
