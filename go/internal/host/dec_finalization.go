package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type DecLinkFinalization struct {
	Owner         string `json:"owner_offer_id"`
	Selection     string `json:"selection_id"`
	Administrator string `json:"administrator_offer_id"`
	Network       string `json:"network_id"`
	Context       string `json:"context_id"`
	Person        string `json:"person_public_key"`
	Host          string `json:"host_public_key"`
	Device        string `json:"device_public_key"`
	Approve       bool   `json:"approve"`
}

type decFinalizationPlan struct {
	Owner                    decOwnerPlan
	Offer                    decSelectedOffer
	Selection, Administrator *dec.Packet
	Admissions               *dec.CeremonyAdmissions
	Projection               *dec.Projection
}

func (s *Store) decCurrentFinalization(ctx context.Context, q dbQuerier, p decPending, i decIntent, review decCeremonyReview, now string) (decFinalizationPlan, error) {
	plan, e := s.decFinalizationPlan(ctx, q, p, i, decFinalizationInput(i, review), now)
	if e != nil {
		return plan, e
	}
	if review.Root != plan.Admissions.Root || review.PersonLease != plan.Admissions.Person.ID || review.HostLease != plan.Admissions.Host.ID {
		return plan, decFailure("state_conflict")
	}
	var binding *dec.Statement
	if plan.Owner.BindingLease != "-" {
		if review.BindingLease != plan.Owner.BindingLease {
			return plan, decFailure("state_conflict")
		}
		binding = plan.Owner.Catalog.Statements[review.BindingLease]
	}
	for _, slot := range i.Record.Templates {
		template, e := readDecCeremonyTemplate(plan.Owner.Descriptor, i, slot)
		if e != nil {
			return plan, e
		}
		if slot.Type == "owner_offer_packet" && (template.Packet == nil || template.Packet.Writer != s.identity.PublicKey) {
			return plan, decStorageError()
		}
		if slot.Type == "owner_finalization_packet" && template.Packet != nil && template.Packet.Writer != s.identity.PublicKey {
			return plan, decStorageError()
		}
		if slot.Type != "binding_lease" && slot.Type != "device_lease" {
			continue
		}
		grant := template.Statement
		if grant == nil {
			return plan, decStorageError()
		}
		wantedID := review.BindingLease
		if slot.Type == "device_lease" {
			wantedID = review.DeviceLease
		}
		if grant.ID != wantedID {
			return plan, decStorageError()
		}
		// Compare the immutable authority/identity terms and current heads while
		// preserving the exact issued time and original payload serialization.
		expected, e := decOwnerLeaseTemplate(plan, p, i, slot.Type, review.BindingLease, grant.Lease.Issued)
		if e != nil {
			return plan, e
		}
		typed, e := dec.ReadStatementTemplate(plan.Owner.Descriptor, expected)
		if e != nil {
			return plan, e
		}
		left, _ := json.Marshal(grant.Lease)
		right, _ := json.Marshal(typed.Lease)
		if !bytes.Equal(left, right) {
			return plan, decFailure("state_conflict")
		}
		if e = plan.Projection.CheckCeremonyOwnerLease(grant, plan.Admissions, binding); e != nil {
			return plan, e
		}
		if slot.Type == "binding_lease" {
			binding = grant
		}
	}
	if binding == nil {
		return plan, decStorageError()
	}
	return plan, nil
}

func (s *Store) retainDecFinalization(ctx context.Context, tx *sql.Tx, p *decPending, i decIntent, plan decOwnerPlan, now string) (bool, error) {
	if p.Record.Finalization != "-" {
		return false, nil
	}
	last := i.Record.Templates[len(i.Record.Templates)-1]
	if last.Type != "owner_finalization_packet" {
		return false, decStorageError()
	}
	if last.Template == "-" {
		return false, nil
	}
	template, e := readDecCeremonyTemplate(plan.Descriptor, i, last)
	if e != nil {
		return false, e
	}
	for _, role := range template.Roles {
		if role.Signature == "-" {
			return false, nil
		}
	}
	packet, e := dec.ReadPacket(plan.Descriptor, template.Body)
	if e != nil {
		return false, e
	}
	p.Record.Finalization, p.Record.FinalizationID = base64.StdEncoding.EncodeToString(packet.Raw), packet.ID
	p.Record.Catalog = base64.StdEncoding.EncodeToString(plan.Catalog.Raw)
	return true, putDecPending(ctx, tx, *p)
}

func (s *Store) decFinalizationPlan(ctx context.Context, q dbQuerier, p decPending, i decIntent, input DecLinkFinalization, now string) (decFinalizationPlan, error) {
	var plan decFinalizationPlan
	if i.Kind != "owner" || !i.Record.Approved || input.Owner != p.Record.OwnerID || input.Network != i.Network || input.Context != i.Context || input.Person != i.Record.Person || input.Host != i.Record.Host || input.Device != i.Record.Device || input.Selection == "-" || p.Record.Terminal != "-" {
		return plan, decFailure("invalid")
	}
	owner, e := s.decOwnerPlan(ctx, q, p, DecOwnerApproval{Network: i.Network, Person: i.Record.Person, Provider: decConcreteProvider(i.Record.Provider), Format: i.Record.Provider.Format, Scopes: i.Record.Scopes, NotAfter: i.Record.NotAfter, Host: i.Record.Host, Device: i.Record.Device}, now)
	if e != nil {
		return plan, e
	}
	if owner.Provider != i.Record.Provider {
		return plan, decFailure("state_conflict")
	}
	offer, e := s.decSelectedOwner(ctx, q, p, input.Owner, now)
	if e != nil {
		return plan, e
	}
	if offer.Owner.Writer != s.identity.PublicKey || offer.Owner.Signer != i.Record.Provider.Signer {
		return plan, decFailure("forbidden")
	}
	selection, e := decFindSelection(p, offer, input.Selection)
	if e != nil {
		return plan, e
	}
	if containsString(p.Record.Roles, "requester") && !p.Record.Selected {
		return plan, decFailure("review_required")
	}
	var administrator *dec.Packet
	if input.Administrator != "-" {
		administrator, e = decFindStagePacket(p, "administrator", input.Administrator)
		if e != nil {
			return plan, e
		}
	}
	prior := []byte(`"-"`)
	catalog := offer.Catalog
	var projection *dec.Projection
	if p.Record.Migration != "-" {
		var final *dec.Packet
		if p.Record.Finalization != "-" {
			final, e = decFindStagePacket(p, "owner_finalization", p.Record.FinalizationID)
			if e != nil {
				return plan, e
			}
		}
		projection, e = s.decMigrationProjection(ctx, q, p, offer, selection, administrator, final, now)
	} else {
		var state *decSnapshot
		state, e = s.loadDecSnapshot(ctx, q, i.Network)
		if e == nil {
			if !bytes.Equal(state.Descriptor.Raw, owner.Descriptor.Raw) {
				return plan, decFailure("state_conflict")
			}
			if _, e = verifyDecSnapshot(state, now); e != nil {
				return plan, e
			}
			prior = state.PriorRaw
			catalog, e = dec.UnionCatalog(owner.Descriptor, state.Catalog, catalog)
			if e != nil {
				return plan, e
			}
		} else if !errors.Is(e, ErrNotFound) {
			return plan, e
		}
		projection, e = decPreparationProjection(owner.Descriptor, prior, catalog, p, offer.Owner, now)
	}
	if e != nil {
		return plan, e
	}
	admissions, e := projection.PrepareCeremonyAdmissions(p.Request, offer.Owner, selection, administrator)
	if e != nil {
		return plan, e
	}
	if owner.Root != "-" && owner.Root != admissions.Root || offer.Terms.Root != "-" && offer.Terms.Root != admissions.Root || offer.Terms.PersonLease != "-" && offer.Terms.PersonLease != owner.PersonLease {
		return plan, decFailure("state_conflict")
	}
	if owner.Root == "-" {
		if i.Record.Provider.Kind != "original" || offer.Terms.PersonLease != "-" || p.Record.Invitation == "-" {
			return plan, decFailure("forbidden")
		}
		owner.Root, owner.PersonLease = admissions.Root, admissions.Person.ID
	}
	owner.Catalog = catalog
	if owner.BindingLease != "-" {
		binding, path, e := projection.Current([]string{"binding", i.Record.Host})
		if e != nil {
			return plan, e
		}
		if binding.ID != owner.BindingLease || binding.Lease.Subject.Person != i.Record.Person || path.NotAfter < i.Record.NotAfter {
			return plan, decFailure("state_conflict")
		}
	}
	plan = decFinalizationPlan{owner, offer, selection, administrator, admissions, projection}
	return plan, nil
}

func decFinalizationInput(i decIntent, r decCeremonyReview) DecLinkFinalization {
	return DecLinkFinalization{r.Owner, r.Selection, r.Administrator, i.Network, i.Context, i.Record.Person, i.Record.Host, i.Record.Device, true}
}

func decOwnerLeaseTemplate(plan decFinalizationPlan, p decPending, i decIntent, kind, binding, now string) ([]byte, error) {
	stream := []string{"binding", i.Record.Host}
	if kind == "device_lease" {
		stream = []string{"device", i.Record.Person, i.Record.Device}
	}
	seq, preds, e := decGrantHead(plan.Projection, stream)
	if e != nil {
		return nil, e
	}
	subject := dec.Subject{Person: i.Record.Person, Host: i.Record.Host, Device: "-", Member: "-", Scopes: 2}
	issuer := dec.Issuer{Kind: "person", Person: i.Record.Person}
	parents := []dec.Parent{{Role: "issuer_person", ID: plan.Owner.PersonLease}, {Role: "subject_host", ID: plan.Admissions.Host.ID}, {Role: "subject_person", ID: plan.Admissions.Person.ID}}
	if i.Record.Provider.Kind == "device" {
		issuer.Kind = "device"
		parents = append(parents, dec.Parent{Role: "issuer_device", ID: i.Record.Provider.Lease})
	}
	signatures := []dec.Signature{{Role: "issuer", PublicKey: i.Record.Provider.Signer, Format: i.Record.Provider.Format, Signature: "-"}}
	if kind == "device_lease" {
		subject.Device, subject.Scopes = i.Record.Device, i.Record.Scopes
		parents = append(parents, dec.Parent{Role: "subject_binding", ID: binding})
	} else {
		signatures = append(signatures, dec.Signature{Role: "host", PublicKey: i.Record.Host, Format: "ed25519", Signature: "-"})
	}
	sort.Slice(parents, func(a, b int) bool { return parents[a].Role < parents[b].Role })
	lease := dec.Lease{Root: plan.Admissions.Root, Operation: p.ID, Sequence: seq, Predecessors: preds, Resolves: []string{}, Retained: []string{}, Subject: subject, Issuer: issuer, Parents: parents, Issued: now, Before: now, After: i.Record.NotAfter}
	payload, e := json.Marshal(lease)
	if e != nil {
		return nil, e
	}
	return dec.StatementTemplate(plan.Owner.Descriptor, kind, payload, signatures)
}

func materializeDecOwnerLeases(plan decFinalizationPlan, p decPending, i *decIntent, now string) error {
	review, e := readDecCeremonyReview(*i)
	if e != nil {
		return e
	}
	binding := plan.Owner.BindingLease
	for n := range i.Record.Templates {
		slot := &i.Record.Templates[n]
		if slot.Type != "binding_lease" && slot.Type != "device_lease" {
			continue
		}
		if slot.Template == "-" {
			raw, e := decOwnerLeaseTemplate(plan, p, *i, slot.Type, binding, now)
			if e != nil {
				return e
			}
			slot.Template = base64.StdEncoding.EncodeToString(raw)
		}
		raw, e := decBytes(slot.Template, dec.MaxObject)
		if e != nil {
			return e
		}
		statement, e := dec.ReadStatementTemplate(plan.Owner.Descriptor, raw)
		if e != nil {
			return e
		}
		if slot.Type == "binding_lease" {
			binding = statement.ID
		} else {
			review.DeviceLease = statement.ID
		}
	}
	if !dec.ValidID(binding, "ds_") {
		return decStorageError()
	}
	review.Stage, review.Root, review.Selection, review.Administrator = "owner_finalization", plan.Admissions.Root, plan.Selection.ID, "-"
	if plan.Administrator != nil {
		review.Administrator = plan.Administrator.ID
	}
	review.PersonLease, review.HostLease, review.BindingLease = plan.Admissions.Person.ID, plan.Admissions.Host.ID, binding
	review.Provider = plan.Owner.View
	if review.Provider.Root == "-" {
		review.Provider.Root = plan.Admissions.Root
		review.Provider.Lease = plan.Admissions.Person.ID
		review.Provider.Scopes = 7
		review.Provider.NotAfter = plan.Admissions.Person.Lease.After
	}
	review.Warning = "The exact owner signatures authorize only the reviewed target and finite terms. The target host must still provide separate binding and final machine consent."
	i.Record.Root = review.Root
	body, _ := json.Marshal(review)
	i.Record.Review = base64.StdEncoding.EncodeToString(body)
	return nil
}

func materializeDecFinalizationPacket(plan decFinalizationPlan, p decPending, i *decIntent) error {
	last := len(i.Record.Templates) - 1
	if last < 0 || i.Record.Templates[last].Type != "owner_finalization_packet" {
		return decStorageError()
	}
	if i.Record.Templates[last].Template != "-" {
		return nil
	}
	review, e := readDecCeremonyReview(*i)
	if e != nil {
		return e
	}
	var binding any = review.BindingLease
	var device json.RawMessage
	for _, slot := range i.Record.Templates {
		if slot.Type != "binding_lease" && slot.Type != "device_lease" {
			continue
		}
		template, e := readDecCeremonyTemplate(plan.Owner.Descriptor, *i, slot)
		if e != nil {
			return e
		}
		for _, role := range template.Roles {
			if role.Signature == "-" {
				return nil
			}
		}
		if slot.Type == "binding_lease" {
			binding = json.RawMessage(template.Body)
		} else {
			device = json.RawMessage(template.Body)
		}
	}
	if device == nil {
		return decStorageError()
	}
	payload, e := json.Marshal(struct {
		Selection     string          `json:"selection_id"`
		Administrator string          `json:"administrator_offer_id"`
		Root          string          `json:"root_state_id"`
		Person        string          `json:"person_lease_id"`
		Host          string          `json:"host_lease_id"`
		Binding       any             `json:"binding_lease"`
		Device        json.RawMessage `json:"device_lease"`
	}{review.Selection, review.Administrator, review.Root, review.PersonLease, review.HostLease, binding, device})
	if e != nil {
		return e
	}
	issuer := "-"
	if i.Record.Provider.Kind == "device" {
		issuer = i.Record.Provider.Lease
	}
	raw, e := dec.PacketTemplate(plan.Owner.Descriptor, i.Context, p.ID, "owner_finalization", plan.Offer.Owner.Writer, i.Record.Provider.Signer, i.Record.Person, issuer, i.Record.Provider.Format, payload)
	if e != nil {
		return e
	}
	i.Record.Templates[last].Template = base64.StdEncoding.EncodeToString(raw)
	return nil
}

func (s *Store) PrepareDecentralizedFinalization(ctx context.Context, id string, input DecLinkFinalization) (result decApprovalResult, err error) {
	if !dec.ValidID(id, "link_") || !dec.ValidID(input.Owner, "dpk_") || !dec.ValidID(input.Selection, "dpk_") || input.Administrator != "-" && !dec.ValidID(input.Administrator, "dpk_") {
		return result, decFailure("invalid")
	}
	facts := decCommittedFacts{operation: id}
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
		if err == nil && input.Approve {
			result, err = s.advanceDecOwnerIntent(ctx, id)
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
	if p.Record.OwnerIntent == "-" {
		return result, decFailure("review_required")
	}
	i, e := readDecIntent(ctx, tx, p.Record.OwnerIntent)
	if e != nil {
		return result, e
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	plan, e := s.decFinalizationPlan(ctx, tx, p, i, input, now)
	if e != nil {
		return result, e
	}
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return result, e
	}
	if review.Stage == "owner_finalization" {
		if review.Owner != input.Owner || review.Selection != input.Selection || review.Administrator != input.Administrator {
			return result, decFailure("state_conflict")
		}
		return decApprovalResponse(p, i, now)
	}
	if !input.Approve {
		review.Stage, review.Selection, review.Administrator = "owner_finalization", input.Selection, input.Administrator
		review.Root, review.PersonLease, review.HostLease = plan.Admissions.Root, plan.Admissions.Person.ID, plan.Admissions.Host.ID
		return decApprovalResult{decLinkView(p, now), review, []DecSigningRequest{}}, nil
	}
	// The approved owner intent already fixes the target, provider and finite
	// terms; this step can only supply the exact independently checked parents.
	now, e = decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	plan, e = s.decFinalizationPlan(ctx, tx, p, i, input, now)
	if e != nil {
		return result, e
	}
	components, e := decCatalogComponents(plan.Owner.Catalog)
	if e != nil {
		return result, e
	}
	if e = decStageFrameCapacity(p, components, dec.MaxObject); e != nil {
		return result, e
	}
	p.Record.Selection, p.Record.SelectionID = base64.StdEncoding.EncodeToString(plan.Selection.Raw), plan.Selection.ID
	if plan.Administrator != nil {
		p.Record.Administrator, p.Record.AdministratorID = base64.StdEncoding.EncodeToString(plan.Administrator.Raw), plan.Administrator.ID
	}
	p.Record.Catalog = base64.StdEncoding.EncodeToString(plan.Owner.Catalog.Raw)
	if e = materializeDecOwnerLeases(plan, p, &i, now); e != nil {
		return result, e
	}
	if e = putDecPending(ctx, tx, p); e != nil {
		return result, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return result, e
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, i.Network, string(clock)); e != nil {
		return result, e
	}
	result, e = decApprovalResponse(p, i, now)
	if e != nil {
		return result, e
	}
	facts.add("dec.intent.after_commit")
	return result, tx.Commit()
}
