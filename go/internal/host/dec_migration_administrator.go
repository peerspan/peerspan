package host

import (
	"bytes"
	"context"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

func (s *Store) decMigrationProjection(ctx context.Context, q dbQuerier, p decPending, offer decSelectedOffer, selection, administrator, final *dec.Packet, now string) (*dec.Projection, error) {
	staged, e := s.migrationPreparationContext(ctx, q, offer.Descriptor.NetworkID, p.Record.Migration, now)
	if e != nil {
		return nil, e
	}
	if staged.Record.Fenced {
		return nil, decFailure("migration_pending", p.Record.Migration)
	}
	return dec.PrepareMigrationCeremonyProjection(offer.Descriptor, mustDecBytes(staged.Record.Proposal), mustDecBytes(staged.Record.SourceCatalog), mustDecBytes(staged.Record.SourceState), offer.Catalog.Raw, p.Request, offer.Owner, selection, administrator, final, now)
}

func (s *Store) decMigrationAdministratorPlan(ctx context.Context, q dbQuerier, p decPending, input DecAdministratorApproval, now string) (decAdministratorPlan, error) {
	var result decAdministratorPlan
	if input.Provider != "network_root" {
		return result, decFailure("forbidden")
	}
	offer, e := s.decSelectedOwner(ctx, q, p, input.Owner, now)
	if e != nil {
		return result, e
	}
	if offer.Descriptor.NetworkID != input.Network || offer.Owner.Person != input.Person {
		return result, decFailure("invalid")
	}
	selection, e := decFindSelection(p, offer, input.Selection)
	if e != nil {
		return result, e
	}
	if containsString(p.Record.Roles, "requester") && !p.Record.Selected {
		return result, decFailure("review_required")
	}
	staged, e := s.migrationPreparationContext(ctx, q, input.Network, p.Record.Migration, now)
	if e != nil {
		return result, e
	}
	var administrator, final *dec.Packet
	if p.Record.Administrator != "-" {
		administrator, e = decFindStagePacket(p, "administrator", p.Record.AdministratorID)
		if e != nil {
			return result, e
		}
	}
	if p.Record.Finalization != "-" {
		final, e = decFindStagePacket(p, "owner_finalization", p.Record.FinalizationID)
		if e != nil {
			return result, e
		}
	}
	projection, e := s.decMigrationProjection(ctx, q, p, offer, selection, administrator, final, now)
	if e != nil {
		return result, e
	}
	owned, e := migrationRootSeed(ctx, q, input.Network, staged.Prefix.Fields.Root)
	if e != nil {
		return result, e
	}
	format := input.Format
	if format == "auto" {
		if owned == nil {
			return result, decFailure("signer_unavailable")
		}
		format = "ed25519"
	}
	if format != "ed25519" && format != "sshsig" {
		return result, decFailure("invalid")
	}
	provider := decIntentProvider{"root", staged.Prefix.Fields.Root, format, "-"}
	view := DecProviderView{"network_root", "-", "-", "-", "-", projection.Root.SelectedID, 8, "-"}
	result = decAdministratorPlan{Descriptor: offer.Descriptor, Catalog: offer.Catalog, Writer: s.identity.PublicKey, Projection: projection, Offer: offer, Selection: selection, Provider: provider, View: view, Issuer: dec.Issuer{Kind: "root", Person: "-"}, Parents: []dec.Parent{}}
	if owned != nil {
		result.Seed = owned.Seed()
	}
	return result, nil
}

// Exact complete staged consent is evidence for the prepared catalog, not an
// ordinary activation, active provider or local participant outcome.
func (s *Store) verifyDecMigrationActivation(ctx context.Context, q dbQuerier, p decPending, catalog *dec.Catalog, raw []byte, now string) (*dec.ParsedActivation, error) {
	activation, e := dec.ReadActivation(p.Descriptor, raw)
	if e != nil {
		return nil, e
	}
	if activation.Request.RequestID != p.ID || !bytes.Equal(activation.Request.Raw, p.Request.Raw) || p.Record.Migration == "-" || activation.Owner.ID != p.Record.OwnerID || activation.Selection.ID != p.Record.SelectionID || activation.Finalization.ID != p.Record.FinalizationID || decManifestString(activation, "administrator_offer_id") != p.Record.AdministratorID {
		return nil, decFailure("invalid")
	}
	var terms decOwnerTerms
	if json.Unmarshal(activation.Owner.Payload, &terms) != nil {
		return nil, decStorageError()
	}
	offer := decSelectedOffer{Owner: activation.Owner, Terms: terms, Descriptor: p.Descriptor, Catalog: catalog}
	if _, e = s.decMigrationProjection(ctx, q, p, offer, activation.Selection, activation.Administrator, activation.Finalization, now); e != nil {
		return nil, e
	}
	return activation, nil
}
