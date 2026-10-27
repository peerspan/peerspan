package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// Keep the existing source components stable and put each newly completed
// exact object in its own bounded component. The packet/signature hash ordering
// cannot change prospective frame occupancy after consent was approved.
func decCommitComponents(base, next *dec.Catalog) ([][]byte, error) {
	parts, e := decCatalogComponents(base)
	if e != nil {
		return nil, e
	}
	known := decSet(base.ProofIDs())
	for _, object := range next.Objects {
		if known[object.ID] {
			continue
		}
		raw, e := json.Marshal(struct {
			Format  uint64              `json:"format"`
			Context string              `json:"context_id"`
			Objects []dec.CatalogObject `json:"objects"`
		}{1, next.ContextID, []dec.CatalogObject{object}})
		if e != nil {
			return nil, e
		}
		if len(raw) > dec.MaxCatalogComponent {
			return nil, decFailure("quota_exceeded")
		}
		parts = append(parts, raw)
	}
	return parts, nil
}

func (s *Store) preflightDecLinkCommit(ctx context.Context, q dbQuerier, p decPending, plan decRequesterCommitPlan, now string) error {
	manifest, layout, e := dec.CommitManifestAccounting(plan.Offer.Descriptor, plan.Offer.Catalog, p.Request, plan.Offer.Owner, plan.Selection, plan.Administrator, plan.Finalization, plan.Prefix.Binding, plan.Prefix.ReusedBinding)
	if e != nil {
		return e
	}
	hostSignature := "-"
	if !plan.Prefix.ReusedBinding {
		hostSignature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	}
	payload, _ := json.Marshal(struct {
		Manifest string `json:"manifest_base64"`
		Binding  string `json:"binding_host_signature"`
		At       string `json:"committed_at"`
	}{base64.StdEncoding.EncodeToString(manifest), hostSignature, now})
	commitTemplate, e := dec.PacketTemplate(plan.Offer.Descriptor, plan.Offer.Descriptor.ContextID, p.ID, "commit", p.Record.Host, p.Record.Device, plan.Offer.Owner.Person, "-", "-", payload)
	if e != nil {
		return e
	}
	// Ed25519's two declared88-byte Base64 signatures replace two literal '-'.
	commit := &dec.Packet{Raw: make([]byte, len(commitTemplate)+2*(88-1))}
	activation, e := decActivationBody(p, plan.Offer.Owner, plan.Selection, plan.Administrator, plan.Finalization, commit)
	if e != nil {
		return e
	}
	if len(activation) > dec.MaxObject {
		return decFailure("quota_exceeded")
	}
	layout.Objects = append(layout.Objects, dec.CatalogObject{ID: dec.ProofID("activation", activation), Kind: "activation", BodyBase64: base64.StdEncoding.EncodeToString(activation), Body: activation})
	if len(layout.Objects) > dec.MaxObjects {
		return decFailure("quota_exceeded")
	}
	sort.Slice(layout.Objects, func(a, b int) bool { return layout.Objects[a].ID < layout.Objects[b].ID })
	decoded := 0
	for _, object := range layout.Objects {
		decoded += len(object.Body)
		if len(object.Body) > dec.MaxObject {
			return decFailure("quota_exceeded")
		}
	}
	if decoded > dec.MaxDecodedCatalog {
		return decFailure("quota_exceeded")
	}
	catalog, e := json.Marshal(layout)
	if e != nil {
		return e
	}
	if len(catalog) > dec.MaxCatalog {
		return decFailure("quota_exceeded")
	}
	// Complete participant publication carries both exact objects, not only
	// the ordinary proof-delivery catalog wrapper. Check the whole prospective
	// wire body before generating the target's binding/commit signatures.
	completionBytes := len(`{"activation":`) + len(activation) + len(`,"catalog":`) + len(catalog) + 1
	if completionBytes > 20<<20 {
		return decFailure("quota_exceeded")
	}

	body, e := json.Marshal(struct {
		Catalog json.RawMessage `json:"catalog"`
	}{json.RawMessage(catalog)})
	if e != nil {
		return e
	}
	if len(body) > 20<<20 {
		return decFailure("quota_exceeded")
	}
	components, e := decCommitComponents(plan.Offer.Catalog, layout)
	if e != nil {
		return e
	}
	if e = decStageFrameCapacity(p, components, len(commit.Raw)); e != nil {
		return e
	}
	if p.Record.Migration != "-" {
		// Staged consent has no ordinary outcome/outbox or member authority.
		// Account for the entire prospective prepared carrier before creating
		// the irreversible binding/commit signatures, not only at staging apply.
		proposal, record, e := migrationRecord(ctx, q, p.Record.Network)
		if e != nil {
			return e
		}
		if proposal != p.Record.Migration || !record.Approved {
			return decFailure("review_required")
		}
		return migrationPreparationBudget(record, mustDecBytes(record.Proposal), catalog)
	}
	held, e := heldDecDeliveries(ctx, q)
	if e != nil {
		return e
	}
	proofs := layout.ProofIDs()
	available := decSet(proofs)
	targets := map[string]bool{}
	for _, member := range decMemberViews(plan.Projection) {
		if member.Host != s.identity.PublicKey {
			targets[member.Host] = true
		}
	}
	if p.Record.Host != s.identity.PublicKey {
		targets[p.Record.Host] = true
	}
	retired := map[string]bool{}
	for _, row := range held {
		if row.Network != plan.Offer.Descriptor.NetworkID || row.Context != plan.Offer.Descriptor.ContextID || row.Record.Kind != "proofs" || !targets[row.Target] {
			continue
		}
		var previous struct {
			Catalog json.RawMessage `json:"catalog"`
		}
		if e = dec.ReadPrivateRecord(row.Body, "catalog", &previous); e != nil {
			return e
		}
		old, e := dec.ReadCatalog(plan.Offer.Descriptor, previous.Catalog)
		if e != nil {
			return e
		}
		for _, ids := range [][]string{old.ProofIDs(), row.Record.Proofs} {
			for _, id := range ids {
				if !available[id] {
					return decFailure("proof_required", id)
				}
			}
		}
		retired[row.ID] = true
	}
	added := []decHeldDelivery{}
	for _, target := range decSorted(targets) {
		r := decDeliveryRecord{1, "proofs", base64.StdEncoding.EncodeToString(body), proofs, now, 0, now, "-", "-"}
		raw, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if len(raw) > dec.MaxPrivateRecord {
			return decFailure("quota_exceeded")
		}
		added = append(added, decHeldDelivery{Target: target, Raw: string(raw), Body: body})
	}
	var outcomes int
	if e = q.QueryRowContext(ctx, `SELECT count(*) FROM dec_operations WHERE network_id=?`, plan.Offer.Descriptor.NetworkID).Scan(&outcomes); e != nil {
		return e
	}
	if outcomes >= 4096 {
		return decFailure("quota_exceeded")
	}
	return checkDecDeliveryBudget(held, added, retired)
}
