package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// Cache only signed public stage facts for the already selected exact offer.
// This never reconstructs either requester-local consent flag from remote data,
// materializes a signer slot, or admits a network/provider/catalog projection.
func (s *Store) observeDecCeremony(ctx context.Context, tx *sql.Tx, p *decPending) error {
	if p.Record.Owner == "-" || p.Descriptor.ContextID == "" {
		return nil
	}
	ownerRaw, e := decBytes(p.Record.Owner, dec.MaxObject)
	if e != nil {
		return e
	}
	owner, e := dec.ReadPacket(p.Descriptor, ownerRaw)
	if e != nil {
		return e
	}
	var terms decOwnerTerms
	if json.Unmarshal(owner.Payload, &terms) != nil {
		return decStorageError()
	}
	offer := decSelectedOffer{Owner: owner, Terms: terms, Descriptor: p.Descriptor}
	packets := map[string]*dec.Packet{}
	keys := []string{}
	for key := range p.Frames {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		frame := p.Frames[key]
		if frame.Role != "selection" && frame.Role != "administrator" && frame.Role != "owner_finalization" && frame.Role != "commit" {
			continue
		}
		plain, e := decOpenPendingFrame(*p, frame)
		if e != nil {
			return e
		}
		raw, e := decBytes(plain.Packet, dec.MaxObject)
		if e != nil {
			return e
		}
		var header struct {
			Context string `json:"context_id"`
		}
		if json.Unmarshal(raw, &header) != nil {
			return decStorageError()
		}
		if header.Context != p.Descriptor.ContextID {
			continue
		}
		packet, e := dec.ReadPacket(p.Descriptor, raw)
		if e != nil {
			return e
		}
		packets[packet.ID] = packet
	}
	if p.Record.Selection == "-" && !containsString(p.Record.Roles, "requester") {
		ids := []string{}
		for id, packet := range packets {
			if packet.Role == "selection" {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			packet := packets[id]
			if _, e = decCheckSelection(*p, offer, packet, id); e == nil {
				p.Record.Selection, p.Record.SelectionID = base64.StdEncoding.EncodeToString(packet.Raw), packet.ID
				break
			}
		}
	}
	if p.Record.Selection == "-" {
		return nil
	}
	if p.Record.Administrator == "-" {
		candidates := []*dec.Packet{}
		for _, packet := range packets {
			if packet.Role != "administrator" {
				continue
			}
			var fields struct {
				Owner     string `json:"owner_offer_id"`
				Selection string `json:"selection_id"`
			}
			if json.Unmarshal(packet.Payload, &fields) != nil {
				return decStorageError()
			}
			if fields.Owner == p.Record.OwnerID && fields.Selection == p.Record.SelectionID {
				candidates = append(candidates, packet)
			}
		}
		// Multiple signed proposals remain independent pending evidence until
		// an explicit exact finalization names one; no hash winner is chosen.
		if len(candidates) == 1 && p.Record.AdministratorIntent == "-" {
			p.Record.Administrator = base64.StdEncoding.EncodeToString(candidates[0].Raw)
			p.Record.AdministratorID = candidates[0].ID
		}
	}
	if p.Record.Finalization == "-" {
		ids := []string{}
		for id, packet := range packets {
			if packet.Role == "owner_finalization" {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			packet := packets[id]
			var refs struct {
				Selection     string `json:"selection_id"`
				Administrator string `json:"administrator_offer_id"`
			}
			if json.Unmarshal(packet.Payload, &refs) != nil {
				return decStorageError()
			}
			if refs.Selection != p.Record.SelectionID || packet.Writer != owner.Writer || packet.Signer != owner.Signer || packet.Person != owner.Person || packet.Issuer != owner.Issuer || packet.AuthorityFormat != owner.AuthorityFormat {
				continue
			}
			var administrator *dec.Packet
			if refs.Administrator != "-" {
				administrator = packets[refs.Administrator]
				if administrator == nil {
					administrator, e = decFindStagePacket(*p, "administrator", refs.Administrator)
					if e != nil {
						continue
					}
				}
				var a struct {
					Selection string `json:"selection_id"`
					Owner     string `json:"owner_offer_id"`
				}
				if json.Unmarshal(administrator.Payload, &a) != nil {
					return decStorageError()
				}
				if administrator.Role != "administrator" || a.Selection != p.Record.SelectionID || a.Owner != p.Record.OwnerID {
					continue
				}
				if p.Record.AdministratorIntent != "-" && p.Record.AdministratorID != "-" && p.Record.AdministratorID != administrator.ID {
					continue
				}
			} else if p.Record.Mode != "renew" {
				continue
			}
			p.Record.Finalization, p.Record.FinalizationID = base64.StdEncoding.EncodeToString(packet.Raw), packet.ID
			if administrator != nil {
				p.Record.Administrator, p.Record.AdministratorID = base64.StdEncoding.EncodeToString(administrator.Raw), administrator.ID
			}
			break
		}
	}
	catalog, e := decPendingCatalog(*p, p.Descriptor)
	if e != nil {
		return e
	}
	p.Record.Catalog = base64.StdEncoding.EncodeToString(catalog.Raw)
	if p.Record.Commit == "-" && p.Record.Finalization != "-" && !containsString(p.Record.Roles, "requester") {
		ids := []string{}
		for id, packet := range packets {
			if packet.Role == "commit" {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			commit := packets[id]
			if commit.Writer != p.Record.Host || commit.Signer != p.Record.Device || commit.Person != owner.Person {
				continue
			}
			selection, e := decFindStagePacket(*p, "selection", p.Record.SelectionID)
			if e != nil {
				return e
			}
			final, e := decFindStagePacket(*p, "owner_finalization", p.Record.FinalizationID)
			if e != nil {
				return e
			}
			var admin *dec.Packet
			if p.Record.Administrator != "-" {
				admin, e = decFindStagePacket(*p, "administrator", p.Record.AdministratorID)
				if e != nil {
					return e
				}
			}
			raw, e := decActivationBody(*p, owner, selection, admin, final, commit)
			if e != nil {
				return e
			}
			activation, e := dec.ReadActivation(p.Descriptor, raw)
			if e != nil {
				continue
			}
			if decManifestString(activation, "owner_offer_id") != p.Record.OwnerID || decManifestString(activation, "selection_id") != p.Record.SelectionID || decManifestString(activation, "administrator_offer_id") != p.Record.AdministratorID || decManifestString(activation, "owner_finalization_id") != p.Record.FinalizationID {
				continue
			}
			catalog, e = decCatalogWithActivation(p.Descriptor, catalog, raw)
			if e != nil {
				return e
			}
			p.Record.Commit = base64.StdEncoding.EncodeToString(commit.Raw)
			p.Record.ManifestID, p.Record.ActivationID = activation.ManifestID, activation.ID
			p.Record.Catalog = base64.StdEncoding.EncodeToString(catalog.Raw)
			break
		}
	}
	return putDecPending(ctx, tx, *p)
}
