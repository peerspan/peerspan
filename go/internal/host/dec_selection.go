package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecLinkSelection struct {
	Owner   string `json:"owner_offer_id"`
	Network string `json:"network_id"`
	Context string `json:"context_id"`
	Person  string `json:"person_public_key"`
	Host    string `json:"host_public_key"`
	Device  string `json:"device_public_key"`
	Approve bool   `json:"approve"`
}
type decConfirmationResult struct {
	Request DecLinkView       `json:"request"`
	Review  decCeremonyReview `json:"review"`
}
type decOwnerTerms struct {
	Request     string          `json:"request_packet_id"`
	Descriptor  json.RawMessage `json:"descriptor"`
	Root        string          `json:"root_state_id"`
	PersonLease string          `json:"person_lease_id"`
	Issuers     []string        `json:"issuer_lease_ids"`
	Mode        string          `json:"mode"`
	Member      string          `json:"member"`
	Host        string          `json:"host_public_key"`
	Device      string          `json:"device_public_key"`
	Scopes      uint64          `json:"scopes"`
	NotAfter    string          `json:"not_after"`
	Renewed     string          `json:"renewed_device_lease_id"`
}
type decSelectedOffer struct {
	Owner      *dec.Packet
	Terms      decOwnerTerms
	Descriptor dec.Descriptor
	Catalog    *dec.Catalog
	Projection *dec.Projection
	Provider   DecProviderView
}

func (s *Store) decSelectedOwner(ctx context.Context, q dbQuerier, p decPending, ownerID, now string) (decSelectedOffer, error) {
	var result decSelectedOffer
	owner, d, e := decFindOwner(p, ownerID)
	if e != nil {
		return result, e
	}
	var terms decOwnerTerms
	if json.Unmarshal(owner.Payload, &terms) != nil {
		return result, decStorageError()
	}
	if owner.RequestID != p.ID || terms.Request != p.Request.ID || terms.Host != p.Record.Host || terms.Device != p.Record.Device || terms.Mode != p.Record.Mode || terms.Renewed != p.Terms.RenewedDevice || p.Record.Network != "-" && p.Record.Network != d.NetworkID || p.Record.Context != "-" && p.Record.Context != d.ContextID || p.Record.Person != "-" && p.Record.Person != owner.Person {
		return result, decFailure("invalid")
	}
	if p.Record.Invitation != "-" {
		raw, e := decBytes(p.Record.Invitation, dec.MaxPairingToken)
		if e != nil {
			return result, e
		}
		inv, e := dec.ReadContactInvitationBody(raw)
		if e != nil {
			return result, e
		}
		if e = inv.Current(p.Terms.Created); e != nil {
			return result, e
		}
		if !bytes.Equal(inv.Descriptor.Raw, d.Raw) || inv.Member != terms.Member || inv.Person != "-" && inv.Person != owner.Person {
			return result, decFailure("invalid")
		}
	}
	if now < p.Terms.Created {
		return result, decFailure("clock_rollback")
	}
	if now >= p.Deadline {
		return result, decFailure("expired")
	}
	if terms.NotAfter <= now {
		return result, decFailure("authority_expired")
	}
	catalog, e := decPendingCatalog(p, d)
	if e != nil {
		return result, e
	}
	if p.Record.Migration != "-" {
		return s.decSelectedMigrationOwner(ctx, q, p, owner, d, terms, catalog, now)
	}
	prior := []byte(`"-"`)
	state, e := s.loadDecSnapshot(ctx, q, d.NetworkID)
	if e == nil {
		if !bytes.Equal(state.Descriptor.Raw, d.Raw) {
			return result, decFailure("state_conflict")
		}
		if len(state.Fenced) > 0 {
			return result, decFailure("migration_pending", state.Fenced...)
		}
		if _, e = verifyDecSnapshot(state, now); e != nil {
			return result, e
		}
		prior = state.PriorRaw
		catalog, e = dec.UnionCatalog(d, state.Catalog, catalog)
		if e != nil {
			return result, e
		}
	} else if !errors.Is(e, ErrNotFound) {
		return result, e
	}
	result = decSelectedOffer{Owner: owner, Terms: terms, Descriptor: d, Catalog: catalog}
	if terms.Root == "-" || terms.PersonLease == "-" {
		if terms.Root != "-" || terms.PersonLease != "-" || p.Record.Mode != "new" || owner.Issuer != "-" || owner.Signer != owner.Person || len(terms.Issuers) != 0 || containsString(p.Record.Roles, "requester") && p.Record.Invitation == "-" {
			return result, decFailure("forbidden")
		}
		result.Provider = DecProviderView{"original_person", owner.Person, owner.Writer, "-", "-", "-", 0, "-"}
		return result, nil
	}
	projection, e := decPreparationProjection(d, prior, catalog, p, owner, now)
	if e != nil {
		return result, e
	}
	if projection.Root.Code != "-" {
		return result, decFailure(projection.Root.Code, projection.Root.RequiredIDs...)
	}
	if projection.Root.SelectedID != terms.Root {
		return result, decFailure("forbidden")
	}
	prepared, e := projection.PrepareOwnerOffer(p.Request, owner)
	if e != nil {
		return result, e
	}
	view := DecProviderView{"original_person", owner.Person, owner.Writer, "-", prepared.Person.ID, terms.Root, prepared.Scopes, prepared.NotAfter}
	if prepared.Device != nil {
		view.Kind, view.Device, view.Lease = "device", owner.Signer, owner.Issuer
	}
	result.Projection, result.Provider = projection, view
	return result, nil
}

func decSelectionReview(p decPending, offer decSelectedOffer) decCeremonyReview {
	key, _ := membership.DecodeKey(offer.Owner.Person)
	return decCeremonyReview{"selection", offer.Descriptor.NetworkID, offer.Descriptor.ContextID, membership.PersonID(key), offer.Owner.Person, p.Record.Host, p.Record.Device, offer.Terms.Root, offer.Provider, offer.Owner.ID, "-", "-", offer.Terms.PersonLease, "-", "-", "-", offer.Terms.Scopes, offer.Terms.NotAfter, "Owner selection is separate from final machine consent; no network or provider is adopted yet."}
}

func (s *Store) SelectDecentralizedLink(ctx context.Context, id string, input DecLinkSelection) (result decConfirmationResult, err error) {
	if !dec.ValidID(input.Owner, "dpk_") || !dec.ValidID(input.Network, "net_") || !dec.ValidID(input.Context, "ctx_") || !dec.ValidPublicKey(input.Person) || input.Host != s.identity.PublicKey || !dec.ValidPublicKey(input.Device) {
		return result, decFailure("invalid")
	}
	facts := decCommittedFacts{operation: id}
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
		if err == nil && input.Approve {
			if err = s.advanceDecRequester(ctx, id); err != nil {
				return
			}
			p, e := s.readDecPendingSnapshot(ctx, id)
			if e != nil {
				err = e
				return
			}
			result.Request = decLinkView(p, p.Terms.Created)
			if e = s.publishDecFrames(ctx, p); e != nil {
				result.Request = decPublicationAttention(result.Request, e)
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
	if !containsString(p.Record.Roles, "requester") || p.Record.Host != input.Host || p.Record.Device != input.Device {
		return result, decFailure("invalid")
	}
	if p.Record.Selected && p.Record.OwnerID != input.Owner {
		return result, decFailure("invalid")
	}
	now, e := decCreationClock(ctx, tx, input.Network)
	if e != nil {
		return result, e
	}
	offer, e := s.decSelectedOwner(ctx, tx, p, input.Owner, now)
	if e != nil {
		return result, e
	}
	if input.Network != offer.Descriptor.NetworkID || input.Context != offer.Descriptor.ContextID || input.Person != offer.Owner.Person {
		return result, decFailure("invalid")
	}
	review := decSelectionReview(p, offer)
	if p.Record.Selected {
		review.Selection = p.Record.SelectionID
		return decConfirmationResult{decLinkView(p, now), review}, nil
	}
	if !input.Approve {
		return decConfirmationResult{decLinkView(p, now), review}, nil
	}
	if p.Record.Terminal != "-" || p.Record.Commit != "-" {
		return result, decFailure("operation_conflict")
	}
	if _, e = s.decRequesterDeviceSeed(ctx, tx, p, now); e != nil {
		return result, e
	}
	components, e := decCatalogComponents(offer.Catalog)
	if e != nil {
		return result, e
	}
	if e = decStageFrameCapacity(p, components, 8192); e != nil {
		return result, e
	}
	// The final local clock is read again before fixing the approved template.
	now, e = decCreationClock(ctx, tx, input.Network)
	if e != nil {
		return result, e
	}
	offer, e = s.decSelectedOwner(ctx, tx, p, input.Owner, now)
	if e != nil {
		return result, e
	}
	payload, _ := json.Marshal(struct {
		Request  string `json:"request_packet_id"`
		Owner    string `json:"owner_offer_id"`
		Context  string `json:"context_id"`
		Person   string `json:"person_public_key"`
		Host     string `json:"host_public_key"`
		Device   string `json:"device_public_key"`
		Selected string `json:"selected_at"`
	}{p.Request.ID, offer.Owner.ID, input.Context, input.Person, input.Host, input.Device, now})
	raw, e := dec.PacketTemplate(offer.Descriptor, input.Context, id, "selection", input.Host, input.Device, input.Person, "-", "-", payload)
	if e != nil {
		return result, e
	}
	packet, e := dec.ReadPacketTemplate(offer.Descriptor, raw)
	if e != nil {
		return result, e
	}
	p.Descriptor, p.Record.Descriptor = offer.Descriptor, base64.StdEncoding.EncodeToString(offer.Descriptor.Raw)
	p.Record.Owner, p.Record.OwnerID = base64.StdEncoding.EncodeToString(offer.Owner.Raw), offer.Owner.ID
	p.Record.Catalog = base64.StdEncoding.EncodeToString(offer.Catalog.Raw)
	review.Selection = packet.ID
	intent, e := s.newDecRequesterIntent(p, review, "selection", now, []decIntentTemplate{{1, "selection_packet", base64.StdEncoding.EncodeToString(raw)}})
	if e != nil {
		return result, e
	}
	if e = decIntentCapacity(ctx, tx); e != nil {
		return result, e
	}
	p.Record.Selected, p.Record.SelectionIntent = true, intent.ID
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
	if e = tx.Commit(); e != nil {
		return result, e
	}
	facts.add("dec.intent.after_commit")
	facts.add("dec.approval.after_commit")
	review = decSelectionReview(p, offer)
	review.Selection = packet.ID
	return decConfirmationResult{decLinkView(p, now), review}, nil
}
