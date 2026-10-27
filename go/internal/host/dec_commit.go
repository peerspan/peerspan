package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecLinkCommit struct {
	Owner         string `json:"owner_offer_id"`
	Selection     string `json:"selection_id"`
	Administrator string `json:"administrator_offer_id"`
	Finalization  string `json:"owner_finalization_id"`
	Network       string `json:"network_id"`
	Context       string `json:"context_id"`
	Person        string `json:"person_public_key"`
	Host          string `json:"host_public_key"`
	Device        string `json:"device_public_key"`
	Approve       bool   `json:"approve"`
}
type decRequesterCommitPlan struct {
	Offer                                  decSelectedOffer
	Selection, Administrator, Finalization *dec.Packet
	Prefix                                 *dec.CeremonyFinalization
	Projection                             *dec.Projection
	Prior                                  []byte
	Old                                    *decSnapshot
	Review                                 decCeremonyReview
}

func (s *Store) decRequesterCommitPlan(ctx context.Context, q dbQuerier, p decPending, input DecLinkCommit, now string) (decRequesterCommitPlan, error) {
	var plan decRequesterCommitPlan
	if !containsString(p.Record.Roles, "requester") || !p.Record.Selected || input.Owner != p.Record.OwnerID || input.Selection != p.Record.SelectionID || input.Host != s.identity.PublicKey || input.Host != p.Record.Host || input.Device != p.Record.Device {
		return plan, decFailure("invalid")
	}
	offer, e := s.decSelectedOwner(ctx, q, p, input.Owner, now)
	if e != nil {
		return plan, e
	}
	if input.Network != offer.Descriptor.NetworkID || input.Context != offer.Descriptor.ContextID || input.Person != offer.Owner.Person {
		return plan, decFailure("invalid")
	}
	selection, e := decFindSelection(p, offer, input.Selection)
	if e != nil {
		return plan, e
	}
	var admin *dec.Packet
	if input.Administrator != "-" {
		admin, e = decFindStagePacket(p, "administrator", input.Administrator)
		if e != nil {
			return plan, e
		}
	}
	final, e := decFindStagePacket(p, "owner_finalization", input.Finalization)
	if e != nil {
		return plan, e
	}
	prior := []byte(`"-"`)
	catalog := offer.Catalog
	var old *decSnapshot
	var projection *dec.Projection
	if p.Record.Migration != "-" {
		projection, e = s.decMigrationProjection(ctx, q, p, offer, selection, admin, final, now)
	} else {
		old, e = s.loadDecSnapshot(ctx, q, input.Network)
		if e == nil {
			if !bytes.Equal(old.Descriptor.Raw, offer.Descriptor.Raw) {
				return plan, decFailure("state_conflict")
			}
			if _, e = verifyDecSnapshot(old, now); e != nil {
				return plan, e
			}
			prior = old.PriorRaw
			catalog, e = dec.UnionCatalog(offer.Descriptor, old.Catalog, catalog)
			if e != nil {
				return plan, e
			}
		} else if !errors.Is(e, ErrNotFound) {
			return plan, e
		} else {
			old = nil
		}
		projection, e = decPreparationProjection(offer.Descriptor, prior, catalog, p, offer.Owner, now)
	}
	if e != nil {
		return plan, e
	}
	for _, known := range catalog.Activations {
		if known.Request.RequestID == p.ID && (p.Record.Commit == "-" || known.ID != p.Record.ActivationID) {
			return plan, decFailure("operation_conflict")
		}
	}
	prefix, e := projection.PrepareCeremonyFinalization(p.Request, offer.Owner, selection, admin, final)
	if e != nil {
		return plan, e
	}
	offer.Catalog = catalog
	key, _ := membership.DecodeKey(input.Person)
	review := decCeremonyReview{"commit", input.Network, input.Context, membership.PersonID(key), input.Person, input.Host, input.Device, prefix.Admissions.Root, offer.Provider, input.Owner, input.Selection, input.Administrator, prefix.Admissions.Person.ID, prefix.Admissions.Host.ID, prefix.Binding.ID, prefix.Device.ID, offer.Terms.Scopes, offer.Terms.NotAfter, "Final machine consent is separate from owner selection. This fixes the exact binding, device authority and complete transcript; peer delivery is not a global receipt."}
	return decRequesterCommitPlan{offer, selection, admin, final, prefix, projection, prior, old, review}, nil
}

func decActivationBody(p decPending, owner, selection, admin, final, commit *dec.Packet) ([]byte, error) {
	if owner == nil || selection == nil || final == nil || commit == nil {
		return nil, decStorageError()
	}
	raw := []byte(`{"format":1,"context_id":`)
	contextID, _ := json.Marshal(owner.ContextID)
	raw = append(raw, contextID...)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"request", p.Request.Raw}, {"owner", owner.Raw}, {"selection", selection.Raw}, {"administrator", []byte(`"-"`)}, {"owner_finalization", final.Raw}, {"commit", commit.Raw}} {
		if entry.name == "administrator" && admin != nil {
			entry.body = admin.Raw
		}
		raw = append(raw, []byte(`,"`+entry.name+`":`)...)
		raw = append(raw, entry.body...)
	}
	return append(raw, '}'), nil
}

func decCatalogWithActivation(d dec.Descriptor, c *dec.Catalog, activation []byte) (*dec.Catalog, error) {
	objects := append([]dec.CatalogObject{}, c.Objects...)
	objects = append(objects, dec.CatalogObject{ID: dec.ProofID("activation", activation), Kind: "activation", BodyBase64: base64.StdEncoding.EncodeToString(activation), Body: activation})
	byID := map[string]dec.CatalogObject{}
	for _, object := range objects {
		if old, ok := byID[object.ID]; ok && !bytes.Equal(old.Body, object.Body) {
			return nil, decFailure("operation_conflict")
		}
		byID[object.ID] = object
	}
	ids := []string{}
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	objects = []dec.CatalogObject{}
	for _, id := range ids {
		objects = append(objects, byID[id])
	}
	raw, e := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, objects})
	if e != nil {
		return nil, e
	}
	return dec.ReadCatalog(d, raw)
}

func decExpectedLink(p decPending, plan decRequesterCommitPlan) []byte {
	raw, _ := json.Marshal(map[string]any{"request_id": p.ID, "context_id": plan.Offer.Descriptor.ContextID, "mode": p.Record.Mode, "person_public_key": plan.Offer.Owner.Person, "host_public_key": p.Record.Host, "device_public_key": p.Record.Device, "renewed_device_lease_id": p.Terms.RenewedDevice, "owner_offer_id": plan.Offer.Owner.ID, "selection_id": plan.Selection.ID, "administrator_offer_id": plan.Review.Administrator, "scopes": plan.Offer.Terms.Scopes, "not_after": plan.Offer.Terms.NotAfter})
	return raw
}

func (s *Store) CommitDecentralizedLink(ctx context.Context, id string, input DecLinkCommit) (result decConfirmationResult, err error) {
	if !dec.ValidID(id, "link_") || !dec.ValidID(input.Owner, "dpk_") || !dec.ValidID(input.Selection, "dpk_") || !dec.ValidID(input.Finalization, "dpk_") || input.Administrator != "-" && !dec.ValidID(input.Administrator, "dpk_") {
		return result, decFailure("invalid")
	}
	facts := decCommittedFacts{operation: id}
	historical := false
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
		if err == nil && input.Approve && !historical {
			p, e := s.readDecPendingSnapshot(ctx, id)
			if e != nil {
				err = e
				return
			}
			if e = s.advanceDecRequester(ctx, id); e != nil {
				err = e
				return
			}
			p, e = s.readDecPendingSnapshot(ctx, id)
			if e != nil {
				err = e
				return
			}
			if p.Record.Commit != "-" {
				publication := s.attemptDecCommitFrames(ctx, p)
				if e = s.applyStoredDecLink(ctx, id); e != nil {
					result.Request = decPublicationAttention(result.Request, e)
					return
				}
				p, e = s.readDecPendingSnapshot(ctx, id)
				if e != nil {
					err = e
					return
				}
				result.Request = decLinkView(p, p.Terms.Created)
				if publication != nil {
					result.Request = decPublicationAttention(result.Request, publication)
				}
				if p.Record.Migration == "-" {
					if e = s.publishDecCompletion(ctx, p); e != nil {
						result.Request = decPublicationAttention(result.Request, e)
					}
				}
				if e = s.publishDecFrames(ctx, p); e != nil {
					result.Request = decPublicationAttention(result.Request, e)
				}
			}
		}
	}()
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return result, e
	}
	if p.Record.Commit != "-" {
		historical = p.Record.Terminal == "applied"
		if p.Record.OwnerID != input.Owner || p.Record.SelectionID != input.Selection || p.Record.AdministratorID != input.Administrator || p.Record.FinalizationID != input.Finalization || p.Descriptor.NetworkID != input.Network || p.Descriptor.ContextID != input.Context || p.Record.Host != input.Host || p.Record.Device != input.Device {
			return result, decFailure("operation_conflict")
		}
		review, e := decHistoricalCommitReview(p)
		if e != nil {
			return result, e
		}
		if review.Person != input.Person {
			return result, decFailure("operation_conflict")
		}
		return decConfirmationResult{decLinkView(p, p.Terms.Created), review}, nil
	}
	if p.Record.Terminal != "-" {
		return result, decFailure("operation_conflict")
	}
	now, e := decCreationClock(ctx, tx, input.Network)
	if e != nil {
		return result, e
	}
	plan, e := s.decRequesterCommitPlan(ctx, tx, p, input, now)
	if e != nil {
		return result, e
	}
	if !input.Approve {
		return decConfirmationResult{decLinkView(p, now), plan.Review}, nil
	}
	if e = s.preflightDecLinkCommit(ctx, tx, p, plan, now); e != nil {
		return result, e
	}
	if p.Record.CommitIntent != "-" {
		i, e := readDecIntent(ctx, tx, p.Record.CommitIntent)
		if e != nil {
			return result, e
		}
		old, e := readDecCeremonyReview(i)
		if e != nil {
			return result, e
		}
		if old.Owner != input.Owner || old.Selection != input.Selection || old.Administrator != input.Administrator || p.Record.FinalizationID != input.Finalization || old.Person != input.Person {
			return result, decFailure("operation_conflict")
		}
		return decConfirmationResult{decLinkView(p, now), old}, nil
	}
	if _, e = s.decRequesterDeviceSeed(ctx, tx, p, now); e != nil {
		return result, e
	}
	now, e = decCreationClock(ctx, tx, input.Network)
	if e != nil {
		return result, e
	}
	plan, e = s.decRequesterCommitPlan(ctx, tx, p, input, now)
	if e != nil {
		return result, e
	}
	templates := []decIntentTemplate{}
	if !plan.Prefix.ReusedBinding {
		templates = append(templates, decIntentTemplate{1, "binding_lease", base64.StdEncoding.EncodeToString(plan.Prefix.Binding.Raw)})
	}
	templates = append(templates, decIntentTemplate{uint64(len(templates) + 1), "commit_packet", "-"})
	intent, e := s.newDecRequesterIntent(p, plan.Review, "requester_commit", now, templates)
	if e != nil {
		return result, e
	}
	if e = decIntentCapacity(ctx, tx); e != nil {
		return result, e
	}
	p.Record.Administrator, p.Record.AdministratorID = "-", input.Administrator
	if plan.Administrator != nil {
		p.Record.Administrator = base64.StdEncoding.EncodeToString(plan.Administrator.Raw)
	}
	p.Record.Finalization, p.Record.FinalizationID = base64.StdEncoding.EncodeToString(plan.Finalization.Raw), plan.Finalization.ID
	p.Record.Committed, p.Record.CommitIntent = true, intent.ID
	p.Record.Catalog = base64.StdEncoding.EncodeToString(plan.Offer.Catalog.Raw)
	if e = putDecPending(ctx, tx, p); e != nil {
		return result, e
	}
	if e = storeDecIntent(ctx, tx, intent, true); e != nil {
		return result, e
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, input.Network, string(clock)); e != nil {
		return result, e
	}
	facts.add("dec.intent.after_commit")
	facts.add("dec.approval.after_commit")
	return decConfirmationResult{decLinkView(p, now), plan.Review}, tx.Commit()
}

func decHistoricalCommitReview(p decPending) (decCeremonyReview, error) {
	var r decCeremonyReview
	if p.Record.Commit == "-" || p.Record.Finalization == "-" {
		return r, decStorageError()
	}
	raw, e := decBytes(p.Record.Commit, dec.MaxObject)
	if e != nil {
		return r, e
	}
	commit, e := dec.ReadPacket(p.Descriptor, raw)
	if e != nil {
		return r, e
	}
	var body struct {
		Manifest string `json:"manifest_base64"`
	}
	if json.Unmarshal(commit.Payload, &body) != nil {
		return r, decStorageError()
	}
	manifest, e := decBytes(body.Manifest, dec.MaxManifest)
	if e != nil {
		return r, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(manifest, &fields) != nil {
		return r, decStorageError()
	}
	value := func(name string) string { var s string; _ = json.Unmarshal(fields[name], &s); return s }
	ownerRaw, e := decBytes(p.Record.Owner, dec.MaxObject)
	if e != nil {
		return r, e
	}
	owner, e := dec.ReadPacket(p.Descriptor, ownerRaw)
	if e != nil {
		return r, e
	}
	var terms decOwnerTerms
	if json.Unmarshal(owner.Payload, &terms) != nil {
		return r, decStorageError()
	}
	key, _ := membership.DecodeKey(owner.Person)
	provider := DecProviderView{"original_person", owner.Person, owner.Writer, "-", terms.PersonLease, terms.Root, 0, "-"}
	if owner.Issuer != "-" {
		provider.Kind, provider.Device, provider.Lease = "device", owner.Signer, owner.Issuer
	}
	return decCeremonyReview{"commit", p.Descriptor.NetworkID, p.Descriptor.ContextID, membership.PersonID(key), owner.Person, p.Record.Host, p.Record.Device, value("root_state_id"), provider, p.Record.OwnerID, p.Record.SelectionID, p.Record.AdministratorID, value("person_lease_id"), value("host_lease_id"), value("binding_lease_id"), value("device_lease_id"), terms.Scopes, terms.NotAfter, "Exact retained historical consent; this response does not claim present authority."}, nil
}
