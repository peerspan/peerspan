package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type decCeremonyRole struct {
	Role, Key, Format string
	Message           []byte
	Signature         string
}
type decCeremonyTemplate struct {
	Slot      decIntentTemplate
	ID        string
	Body      []byte
	Roles     []decCeremonyRole
	Statement *dec.Statement
	Packet    *dec.Packet
}

func decCeremonyDescriptor(ctx context.Context, q dbQuerier, i decIntent) (dec.Descriptor, error) {
	if i.Kind != "owner" && i.Kind != "administrator" || !dec.ValidID(i.Record.Operation, "link_") {
		return dec.Descriptor{}, decStorageError()
	}
	if i.Kind == "owner" && i.Record.Provider.Kind == "root" {
		return dec.Descriptor{}, decStorageError()
	}
	var record string
	if e := q.QueryRowContext(ctx, `SELECT record FROM dec_pending WHERE request_id=?`, i.Record.Operation).Scan(&record); e != nil {
		return dec.Descriptor{}, e
	}
	var pending decPendingRecord
	if e := dec.ReadPrivateRecord([]byte(record), decPendingFields, &pending); e != nil {
		return dec.Descriptor{}, e
	}
	if i.Kind == "owner" && pending.OwnerIntent != i.ID || i.Kind == "administrator" && pending.AdministratorIntent != i.ID || pending.Descriptor == "-" || pending.Person != "-" && pending.Person != i.Record.Person || pending.Host != i.Record.Host || pending.Device != i.Record.Device {
		return dec.Descriptor{}, decStorageError()
	}
	raw, e := decBytes(pending.Descriptor, dec.MaxPayload)
	if e != nil {
		return dec.Descriptor{}, e
	}
	d, e := dec.ReadDescriptor(raw)
	if e != nil {
		return d, e
	}
	if i.Network != d.NetworkID || i.Context != d.ContextID {
		return d, decStorageError()
	}
	return d, nil
}

// This reader verifies only fixed typed messages and existing signatures. Every
// caller that signs or publishes must separately recheck the current role/path,
// request deadline, frozen review, local key and latest decision guard.
func readDecCeremonyTemplate(d dec.Descriptor, i decIntent, slot decIntentTemplate) (decCeremonyTemplate, error) {
	result := decCeremonyTemplate{Slot: slot, Roles: []decCeremonyRole{}}
	if slot.Template == "-" {
		for _, s := range i.Record.Signatures {
			if s.Slot == slot.Slot {
				return result, decStorageError()
			}
		}
		return result, nil
	}
	raw, e := decBytes(slot.Template, dec.MaxObject)
	if e != nil {
		return result, e
	}
	filled := map[string]string{}
	for _, signature := range i.Record.Signatures {
		if signature.Slot == slot.Slot {
			filled[signature.Role] = signature.Signature
		}
	}
	packetRole := map[string]string{"owner_offer_packet": "owner", "administrator_packet": "administrator", "owner_finalization_packet": "owner_finalization"}[slot.Type]
	if packetRole != "" {
		body, e := dec.FillPacketTemplate(d, raw, filled)
		if e != nil {
			return result, e
		}
		packet, e := dec.ReadPacketTemplate(d, body)
		if e != nil {
			return result, e
		}
		if packet.Role != packetRole || packet.RequestID != i.Record.Operation {
			return result, decStorageError()
		}
		if packet.Signer != i.Record.Provider.Signer || packet.AuthorityFormat != i.Record.Provider.Format {
			return result, decStorageError()
		}
		if i.Kind == "owner" && packet.Person != i.Record.Person {
			return result, decStorageError()
		}
		if slot.Type == "owner_offer_packet" {
			review, e := readDecCeremonyReview(i)
			if e != nil {
				return result, e
			}
			var host, device, root, person, after string
			var scopes uint64
			for key, dst := range map[string]*string{"host_public_key": &host, "device_public_key": &device, "root_state_id": &root, "person_lease_id": &person, "not_after": &after} {
				if json.Unmarshal(packet.Object[key], dst) != nil {
					return result, decStorageError()
				}
			}
			rootMatched, personMatched := root == i.Record.Root, person == review.PersonLease
			if review.Stage == "owner_finalization" {
				// The immutable initial offer retains its original issuer P. The
				// later review names the separately supplied target admission P.
				personMatched = dec.ValidID(person, "ds_")
				if root == "-" && person == "-" && i.Record.Provider.Kind == "original" {
					rootMatched, personMatched = true, true
				}
			}
			if json.Unmarshal(packet.Object["scopes"], &scopes) != nil || host != i.Record.Host || device != i.Record.Device || !rootMatched || !personMatched || after != i.Record.NotAfter || scopes != i.Record.Scopes || packet.ID != review.Owner {
				return result, decStorageError()
			}
		}
		if slot.Type == "owner_finalization_packet" {
			review, e := readDecCeremonyReview(i)
			if e != nil {
				return result, e
			}
			for field, expected := range map[string]string{"root_state_id": review.Root, "selection_id": review.Selection, "administrator_offer_id": review.Administrator, "person_lease_id": review.PersonLease, "host_lease_id": review.HostLease} {
				var value string
				if json.Unmarshal(packet.Object[field], &value) != nil || value != expected {
					return result, decStorageError()
				}
			}
			for field, id := range map[string]string{"binding_lease": review.BindingLease, "device_lease": review.DeviceLease} {
				var reference string
				if json.Unmarshal(packet.Object[field], &reference) == nil {
					if reference != id {
						return result, decStorageError()
					}
					continue
				}
				found := false
				for _, s := range packet.Statements {
					if s.ID == id {
						found = true
					}
				}
				if !found {
					return result, decStorageError()
				}
			}
		}
		if slot.Type == "administrator_packet" {
			review, e := readDecCeremonyReview(i)
			if e != nil {
				return result, e
			}
			var root, owner, selection string
			for key, dst := range map[string]*string{"root_state_id": &root, "owner_offer_id": &owner, "selection_id": &selection} {
				if json.Unmarshal(packet.Object[key], dst) != nil {
					return result, decStorageError()
				}
			}
			if root != i.Record.Root || owner != review.Owner || selection != review.Selection || packet.ID != review.Administrator {
				return result, decStorageError()
			}
			for field, id := range map[string]string{"person_lease": review.PersonLease, "host_lease": review.HostLease} {
				var reference string
				if json.Unmarshal(packet.Object[field], &reference) == nil {
					if reference != id {
						return result, decStorageError()
					}
					continue
				}
				found := false
				for _, grant := range packet.Statements {
					if grant.ID == id {
						found = true
					}
				}
				if !found {
					return result, decStorageError()
				}
			}
		}
		if i.Record.Provider.Kind == "original" && packet.Issuer != "-" || i.Record.Provider.Kind == "device" && packet.Issuer != i.Record.Provider.Lease || i.Record.Provider.Kind == "root" && (packet.Person != "-" || packet.Issuer != i.Record.Root) {
			return result, decStorageError()
		}
		result.Packet = packet
		result.Body = body
		result.ID = packet.ID
		for _, role := range dec.PacketSignatureRoles(packet) {
			signature := "-"
			switch role.Role {
			case "host":
				signature = packet.HostSignature
			case "authority":
				signature = packet.AuthoritySignature
			case "device":
				signature = packet.DeviceSignature
			}
			result.Roles = append(result.Roles, decCeremonyRole{role.Role, role.PublicKey, role.Format, packet.Message, signature})
		}
		return result, nil
	}
	statement, body, e := decFilledTemplate(d, i, slot)
	if e != nil {
		return result, e
	}
	if statement.Kind != slot.Type {
		return result, decStorageError()
	}
	if statement.Lease == nil || statement.Lease.Operation != i.Record.Operation {
		return result, decStorageError()
	}
	for _, role := range statement.Signatures {
		if role.Role == "issuer" && (role.PublicKey != i.Record.Provider.Signer || role.Format != i.Record.Provider.Format) {
			return result, decStorageError()
		}
	}
	if statement.Kind == "person_lease" && statement.Lease.Subject.Person != i.Record.Person || statement.Kind == "host_lease" && statement.Lease.Subject.Host != i.Record.Host || statement.Kind == "binding_lease" && (statement.Lease.Subject.Person != i.Record.Person || statement.Lease.Subject.Host != i.Record.Host) || statement.Kind == "device_lease" && (statement.Lease.Subject.Person != i.Record.Person || statement.Lease.Subject.Host != i.Record.Host || statement.Lease.Subject.Device != i.Record.Device) {
		return result, decStorageError()
	}
	if i.Kind == "owner" && slot.Type != "binding_lease" && slot.Type != "device_lease" || i.Kind == "administrator" && slot.Type != "person_lease" && slot.Type != "host_lease" {
		return result, decStorageError()
	}
	result.Statement = statement
	result.Body = body
	result.ID = statement.ID
	for _, role := range statement.Signatures {
		if i.Kind == "owner" && slot.Type == "binding_lease" && role.Role == "host" {
			// Even a co-located owner must not replace the separate requester
			// confirmation with its readily available host key.
			if role.Signature != "-" || filled["host"] != "" {
				return result, decStorageError()
			}
			continue
		}
		result.Roles = append(result.Roles, decCeremonyRole{role.Role, role.PublicKey, role.Format, dec.SignatureMessage(statement.ID, role.Role, role.PublicKey), role.Signature})
	}
	return result, nil
}

func decCeremonyIntentCompleted(ctx context.Context, q dbQuerier, i decIntent) (bool, error) {
	d, e := decCeremonyDescriptor(ctx, q, i)
	if e != nil {
		return false, e
	}
	complete := len(i.Record.Templates) > 0
	for _, slot := range i.Record.Templates {
		template, e := readDecCeremonyTemplate(d, i, slot)
		if e != nil {
			return false, e
		}
		if template.Body == nil {
			complete = false
			continue
		}
		for _, role := range template.Roles {
			if role.Signature == "-" {
				complete = false
			}
		}
	}
	return complete, nil
}

func decCeremonySigning(d dec.Descriptor, i decIntent, now string) ([]DecSigningRequest, error) {
	requests := []DecSigningRequest{}
	if !i.Record.Approved || i.Record.Terminal != "-" {
		return requests, nil
	}
	if now < i.Record.Created {
		return nil, decFailure("clock_rollback")
	}
	if now >= i.Record.Expires {
		return nil, decFailure("expired")
	}
	for _, slot := range i.Record.Templates {
		template, e := readDecCeremonyTemplate(d, i, slot)
		if e != nil {
			return nil, e
		}
		if template.Body == nil {
			continue
		}
		for _, role := range template.Roles {
			if role.Signature != "-" || role.Format != "sshsig" || role.Key != i.Record.Provider.Signer || (role.Role != "issuer" && role.Role != "authority") {
				continue
			}
			if len(requests) >= 16 {
				return requests, nil
			}
			requests = append(requests, DecSigningRequest{i.ID, slot.Slot, slot.Type, template.ID, role.Role, role.Key, role.Format, base64.StdEncoding.EncodeToString(template.Body), base64.StdEncoding.EncodeToString(role.Message)})
		}
	}
	sort.Slice(requests, func(a, b int) bool {
		return requests[a].Slot < requests[b].Slot || requests[a].Slot == requests[b].Slot && requests[a].Role < requests[b].Role
	})
	return requests, nil
}

func acceptDecCeremonySignatures(d dec.Descriptor, i *decIntent, input DecSignatureBatch, now string) error {
	if input.Intent != i.ID || !i.Record.Approved || i.Record.Terminal != "-" {
		return decFailure("state_conflict")
	}
	if now < i.Record.Created {
		return decFailure("clock_rollback")
	}
	if now >= i.Record.Expires {
		return decFailure("expired")
	}
	for _, signature := range input.Signatures {
		if signature.Slot < 1 || signature.Slot > uint64(len(i.Record.Templates)) {
			return decFailure("invalid")
		}
		template, e := readDecCeremonyTemplate(d, *i, i.Record.Templates[signature.Slot-1])
		if e != nil {
			return e
		}
		var selected *decCeremonyRole
		for j := range template.Roles {
			if template.Roles[j].Role == signature.Role {
				selected = &template.Roles[j]
				break
			}
		}
		if selected == nil {
			return decFailure("invalid")
		}
		if e = dec.VerifySignature(selected.Key, selected.Format, selected.Message, signature.Signature); e != nil {
			return e
		}
		if e = addDecSignature(i, signature); e != nil {
			return e
		}
	}
	return nil
}

func (s *Store) signDecCeremonyOwned(d dec.Descriptor, i *decIntent, seed []byte, now string) error {
	if !i.Record.Approved {
		return nil
	}
	if now < i.Record.Created {
		return decFailure("clock_rollback")
	}
	if now >= i.Record.Expires {
		return decFailure("expired")
	}
	for _, slot := range i.Record.Templates {
		template, e := readDecCeremonyTemplate(d, *i, slot)
		if e != nil {
			return e
		}
		for _, role := range template.Roles {
			if role.Signature != "-" || role.Format != "ed25519" {
				continue
			}
			var signer ed25519.PrivateKey
			if role.Role == "host" && role.Key == s.identity.PublicKey {
				signer = s.privateKey
			}
			if (role.Role == "authority" || role.Role == "issuer") && i.Record.Provider.Kind != "original" && role.Key == i.Record.Provider.Signer {
				if len(seed) != 32 {
					return decFailure("signer_unavailable")
				}
				signer = ed25519.NewKeyFromSeed(seed)
				if base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)) != role.Key {
					return decFailure("signer_unavailable")
				}
			}
			if signer == nil {
				continue
			}
			if e = addDecSignature(i, decIntentSignature{slot.Slot, role.Role, base64.StdEncoding.EncodeToString(ed25519.Sign(signer, role.Message))}); e != nil {
				return e
			}
		}
	}
	return nil
}

// Use an exact kind discriminator in the shared private record. No packet is
// ever accepted by the ordinary statement decoder or generic arbitrary signer.
func ceremonyDecIntent(kind string) bool { return kind == "owner" || kind == "administrator" }
