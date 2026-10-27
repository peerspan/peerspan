package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// A signed owner introduction supplies a parsing descriptor, never an adopted
// network. Keep descriptors from different offers separate until exact consent.
func decOwnerFrame(p decPending, f *dec.Frame) (*dec.Packet, dec.Descriptor, error) {
	plain, _, e := dec.OpenFrame(dec.Descriptor{}, p.Secret, f.Raw)
	if e != nil {
		return nil, dec.Descriptor{}, e
	}
	raw, e := decBytes(plain.Packet, dec.MaxObject)
	if e != nil {
		return nil, dec.Descriptor{}, e
	}
	var envelope struct {
		Payload string `json:"payload_base64"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, dec.Descriptor{}, decStorageError()
	}
	payload, e := decBytes(envelope.Payload, dec.MaxPayload)
	if e != nil {
		return nil, dec.Descriptor{}, e
	}
	var object struct {
		Descriptor json.RawMessage `json:"descriptor"`
	}
	if json.Unmarshal(payload, &object) != nil {
		return nil, dec.Descriptor{}, decStorageError()
	}
	d, e := dec.ReadDescriptor(object.Descriptor)
	if e != nil {
		return nil, d, e
	}
	packet, e := dec.ReadPacket(d, raw)
	return packet, d, e
}

func decOpenPendingFrame(p decPending, f *dec.Frame) (dec.FramePlaintext, error) {
	if f.Role == "request" || f.Role == "owner" {
		plain, _, e := dec.OpenFrame(dec.Descriptor{}, p.Secret, f.Raw)
		return plain, e
	}
	descriptors := p.DecodeContexts
	var e error
	if descriptors == nil {
		descriptors, e = decPendingDescriptors(p)
		if e != nil {
			return dec.FramePlaintext{}, e
		}
	}
	return dec.OpenFrameContexts(descriptors, p.Secret, f.Raw)
}

func decPendingDescriptors(p decPending) (map[string]dec.Descriptor, error) {
	descriptors := map[string]dec.Descriptor{}
	if p.Descriptor.ContextID != "" {
		descriptors[p.Descriptor.ContextID] = p.Descriptor
	}
	for _, candidate := range p.Frames {
		if candidate.Role != "owner" {
			continue
		}
		_, d, e := decOwnerFrame(p, candidate)
		if e != nil {
			return nil, e
		}
		descriptors[d.ContextID] = d
	}
	return descriptors, nil
}

func decPendingCatalog(p decPending, d dec.Descriptor) (*dec.Catalog, error) {
	catalogs := []*dec.Catalog{}
	if p.Record.Catalog != "-" && p.Descriptor.ContextID == d.ContextID {
		raw, e := decBytes(p.Record.Catalog, dec.MaxCatalog)
		if e != nil {
			return nil, e
		}
		catalog, e := dec.ReadCatalog(d, raw)
		if e != nil {
			return nil, e
		}
		catalogs = append(catalogs, catalog)
	}
	for _, frame := range p.Frames {
		plain, e := decOpenPendingFrame(p, frame)
		if e != nil {
			return nil, e
		}
		if plain.Catalog == "-" {
			continue
		}
		raw, e := decBytes(plain.Catalog, dec.MaxCatalogComponent)
		if e != nil {
			return nil, e
		}
		var header struct {
			Context string `json:"context_id"`
		}
		if json.Unmarshal(raw, &header) != nil {
			return nil, decStorageError()
		}
		if header.Context != d.ContextID {
			continue
		} // another exact unselected offer
		catalog, e := dec.ReadCatalog(d, raw)
		if e != nil {
			return nil, e
		}
		catalogs = append(catalogs, catalog)
	}
	return dec.UnionCatalog(d, catalogs...)
}

func decFindStagePacket(p decPending, role, id string) (*dec.Packet, error) {
	if !dec.ValidID(id, "dpk_") {
		return nil, decFailure("invalid")
	}
	for _, saved := range []string{p.Record.Selection, p.Record.Administrator, p.Record.Finalization} {
		if saved == "-" {
			continue
		}
		raw, e := decBytes(saved, dec.MaxObject)
		if e != nil {
			return nil, e
		}
		packet, e := dec.ReadPacket(p.Descriptor, raw)
		if e != nil {
			return nil, e
		}
		if packet.Role == role && packet.ID == id {
			return packet, nil
		}
	}
	keys := []string{}
	for key, frame := range p.Frames {
		if frame.Role == role {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		plain, e := decOpenPendingFrame(p, p.Frames[key])
		if e != nil {
			return nil, e
		}
		raw, e := decBytes(plain.Packet, dec.MaxObject)
		if e != nil {
			return nil, e
		}
		var header struct {
			Context string `json:"context_id"`
		}
		if json.Unmarshal(raw, &header) != nil {
			return nil, decStorageError()
		}
		if header.Context != p.Descriptor.ContextID {
			continue
		}
		packet, e := dec.ReadPacket(p.Descriptor, raw)
		if e != nil {
			return nil, e
		}
		if packet.Role == role && packet.ID == id {
			return packet, nil
		}
	}
	return nil, decFailure("proof_required", id)
}

func decFindOwner(p decPending, id string) (*dec.Packet, dec.Descriptor, error) {
	if p.Record.OwnerID == id && p.Record.Owner != "-" {
		raw, e := decBytes(p.Record.Owner, dec.MaxObject)
		if e != nil {
			return nil, dec.Descriptor{}, e
		}
		owner, e := dec.ReadPacket(p.Descriptor, raw)
		return owner, p.Descriptor, e
	}
	keys := []string{}
	for key, frame := range p.Frames {
		if frame.Role == "owner" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		owner, d, e := decOwnerFrame(p, p.Frames[key])
		if e != nil {
			return nil, d, e
		}
		if owner.ID == id {
			return owner, d, nil
		}
	}
	return nil, dec.Descriptor{}, decFailure("proof_required", id)
}

// Observation selects no authority/provider and creates no network row. A UI
// may show a candidate; the separate selection route still requires its exact
// descriptor, identity and offer ID before producing requester consent.
func observeDecOwner(ctx context.Context, tx *sql.Tx, p *decPending) error {
	if p.Record.Selected || p.Record.OwnerIntent != "-" {
		return nil
	}
	if p.Record.Owner == "-" {
		owners := map[string]*dec.Packet{}
		descriptors := map[string]dec.Descriptor{}
		for _, frame := range p.Frames {
			if frame.Role != "owner" {
				continue
			}
			owner, d, e := decOwnerFrame(*p, frame)
			if e != nil {
				return e
			}
			var target struct {
				Request string `json:"request_packet_id"`
				Host    string `json:"host_public_key"`
				Device  string `json:"device_public_key"`
			}
			if json.Unmarshal(owner.Payload, &target) != nil {
				return decStorageError()
			}
			if owner.RequestID != p.ID || target.Request != p.Request.ID || target.Host != p.Record.Host || target.Device != p.Record.Device || p.Record.Network != "-" && p.Record.Network != d.NetworkID || p.Record.Context != "-" && p.Record.Context != d.ContextID || p.Record.Person != "-" && p.Record.Person != owner.Person {
				continue
			}
			owners[owner.ID], descriptors[owner.ID] = owner, d
		}
		ids := []string{}
		for id := range owners {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if len(ids) == 0 {
			return nil
		}
		owner, d := owners[ids[0]], descriptors[ids[0]]
		p.Record.Owner, p.Record.OwnerID = base64.StdEncoding.EncodeToString(owner.Raw), owner.ID
		p.Descriptor, p.Record.Descriptor = d, base64.StdEncoding.EncodeToString(d.Raw)
	}
	catalog, e := decPendingCatalog(*p, p.Descriptor)
	if e != nil {
		return e
	}
	p.Record.Catalog = base64.StdEncoding.EncodeToString(catalog.Raw)
	return putDecPending(ctx, tx, *p)
}
