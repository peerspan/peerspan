package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// Components divide only between exact original objects. They do not omit an
// oversized dependency or replace its signed bytes with a local projection.
func decCatalogComponents(catalog *dec.Catalog) ([][]byte, error) {
	if catalog == nil || len(catalog.Objects) == 0 {
		return [][]byte{}, nil
	}
	components := [][]byte{}
	current := dec.Catalog{Format: 1, ContextID: catalog.ContextID, Objects: []dec.CatalogObject{}}
	for _, object := range catalog.Objects {
		candidate := current
		candidate.Objects = append(append([]dec.CatalogObject{}, current.Objects...), object)
		raw, e := json.Marshal(candidate)
		if e != nil {
			return nil, e
		}
		if len(raw) > dec.MaxCatalogComponent {
			if len(current.Objects) == 0 {
				return nil, decFailure("quota_exceeded")
			}
			part, _ := json.Marshal(current)
			components = append(components, part)
			current.Objects = []dec.CatalogObject{object}
			raw, e = json.Marshal(current)
			if e != nil || len(raw) > dec.MaxCatalogComponent {
				return nil, decFailure("quota_exceeded")
			}
		} else {
			current = candidate
		}
	}
	if len(current.Objects) != 0 {
		raw, _ := json.Marshal(current)
		components = append(components, raw)
	}
	return components, nil
}

func decStageFrameCapacity(p decPending, components [][]byte, packetBytes int) error {
	count := len(components)
	if count == 0 {
		count = 1
	}
	if len(p.Frames)+count > 64 {
		return decFailure("quota_exceeded")
	}
	// The fixed packet, Base64 expansion, four bounded contacts and framing are
	// included before any typed signature. Exact ciphertext is checked on insert.
	prospective := base64.StdEncoding.EncodedLen(packetBytes) + count*(4*dec.MaxContact+4096)
	for _, component := range components {
		prospective += base64.StdEncoding.EncodedLen(len(component))
	}
	for _, frame := range p.Frames {
		prospective += len(frame.Encrypted)
	}
	if prospective > 32<<20 {
		return decFailure("quota_exceeded")
	}
	return nil
}

func (s *Store) queueDecStage(ctx context.Context, tx *sql.Tx, p *decPending, packet *dec.Packet, components [][]byte, now string) error {
	if packet.Writer != s.identity.PublicKey || packet.RequestID != p.ID || len(p.Secret) != 16 {
		return decFailure("forbidden")
	}
	if e := decStageFrameCapacity(*p, components, len(packet.Raw)); e != nil {
		return e
	}
	contacts, e := s.decOwnContact(ctx, tx, p.Descriptor.NetworkID, p.Descriptor.ContextID, now, p.Deadline)
	if e != nil {
		return e
	}
	count := len(components)
	if count == 0 {
		count = 1
	}
	for index := 0; index < count; index++ {
		plain := dec.FramePlaintext{Packet: "-", Catalog: "-", Contacts: []json.RawMessage{}}
		role := "proofs"
		if index == 0 {
			plain.Packet = base64.StdEncoding.EncodeToString(packet.Raw)
			plain.Contacts = contacts
			role = packet.Role
		}
		if index < len(components) {
			plain.Catalog = base64.StdEncoding.EncodeToString(components[index])
		}
		body, e := json.Marshal(plain)
		if e != nil {
			return e
		}
		id, e := decPublicOperation("")
		if e != nil {
			return e
		}
		frame, e := dec.SealFrame(p.Descriptor, p.Secret, p.ID, role, id, p.Terms.Created, p.Deadline, body, s.privateKey)
		if e != nil {
			return e
		}
		if _, e = insertDecFrame(ctx, tx, p, frame); e != nil {
			return e
		}
		p.Record.Outbound = append(p.Record.Outbound, decOutboundFrame{role, s.identity.PublicKey, id, []decFrameAck{}})
	}
	return nil
}
