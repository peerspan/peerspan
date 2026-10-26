package decentralized

import (
	"bytes"
	"encoding/json"
	"sort"
)

type ActivationEvidence struct {
	OK                 bool     `json:"ok"`
	ContextID          string   `json:"context_id"`
	RequestID          string   `json:"request_id"`
	ManifestID         string   `json:"manifest_id"`
	ActivationID       string   `json:"activation_id"`
	Person             string   `json:"person_public_key"`
	Host               string   `json:"host_public_key"`
	Device             string   `json:"device_public_key"`
	DeviceLeaseID      string   `json:"device_lease_id"`
	Scopes             uint64   `json:"scopes"`
	After              string   `json:"effective_not_after"`
	RequiredStatements []string `json:"required_statement_ids"`
	RequiredProofs     []string `json:"required_proof_ids"`
	PinsMatched        bool     `json:"review_pins_matched"`
}

func VerifyActivation(d Descriptor, priorRaw, catalogRaw, activationRaw, expectedRaw []byte, now string) (*ActivationEvidence, error) {
	activation, e := readActivation(d, activationRaw)
	if e != nil {
		return nil, e
	}
	pins := !bytes.Equal(bytes.TrimSpace(expectedRaw), []byte(`"-"`))
	if pins {
		if e = checkExpected(d, activation, expectedRaw); e != nil {
			return nil, e
		}
	}
	c, e := ReadCatalog(d, catalogRaw)
	if e != nil {
		return nil, e
	}
	proof := ProofID("activation", activationRaw)
	found := false
	for _, entry := range c.Objects {
		if entry.ID == proof {
			found = true
		}
	}
	if !found {
		wire := struct {
			Format  uint64          `json:"format"`
			Context string          `json:"context_id"`
			Objects []CatalogObject `json:"objects"`
		}{1, d.ContextID, append([]CatalogObject{}, c.Objects...)}
		wire.Objects = append(wire.Objects, CatalogObject{ID: proof, Kind: "activation", BodyBase64: b64(activationRaw), Body: activationRaw})
		sort.Slice(wire.Objects, func(i, j int) bool { return wire.Objects[i].ID < wire.Objects[j].ID })
		catalogRaw, e = json.Marshal(wire)
		if e != nil {
			return nil, invalid()
		}
	}
	projection, e := Project(d, priorRaw, catalogRaw, now, "repair")
	if e != nil {
		return nil, e
	}
	deviceID := stringField(activation.Manifest, "device_lease_id")
	device, e := projection.authority.graph.get(deviceID)
	if e != nil {
		return nil, e
	}
	if e := candidateWindow(device, projection.authority.now); e != nil {
		return nil, e
	}
	if e = activationPacketAuthority(projection.authority, activation, device, map[string]bool{}); e != nil {
		return nil, e
	}
	path, e := projection.authority.evaluate(device)
	if e != nil {
		return nil, e
	}
	ancestors, e := ids(activation.Manifest, "ancestor_statement_ids", "ds_")
	if e != nil {
		return nil, e
	}
	required := setOf(ancestors)
	required[deviceID] = true
	proofs, e := ids(activation.Manifest, "proof_ids", "dp_")
	if e != nil {
		return nil, e
	}
	proofset := setOf(proofs)
	proofset[proof] = true
	return &ActivationEvidence{true, d.ContextID, activation.Request.RequestID, activation.ManifestID, activation.ID, device.Lease.Subject.Person, device.Lease.Subject.Host, device.Lease.Subject.Device, deviceID, path.Scopes, path.After, keysSorted(required), keysSorted(proofset), pins}, nil
}
func checkExpected(d Descriptor, a *ParsedActivation, raw []byte) error {
	o, e := readObject(raw, "request_id context_id mode person_public_key host_public_key device_public_key renewed_device_lease_id owner_offer_id selection_id administrator_offer_id scopes not_after")
	if e != nil {
		return e
	}
	values := map[string]string{"request_id": a.Request.RequestID, "context_id": d.ContextID, "mode": stringField(a.Request.Object, "mode"), "person_public_key": a.Owner.Person, "host_public_key": a.Request.Writer, "device_public_key": a.Request.Signer, "renewed_device_lease_id": stringField(a.Request.Object, "renewed_device_lease_id"), "owner_offer_id": a.Owner.ID, "selection_id": a.Selection.ID, "administrator_offer_id": stringField(a.Manifest, "administrator_offer_id"), "not_after": stringField(a.Owner.Object, "not_after")}
	for k, v := range values {
		actual, e := text(o, k)
		if e != nil || actual != v {
			return invalid()
		}
	}
	n, e := num(o, "scopes")
	if e != nil {
		return e
	}
	scopes, _ := num(a.Owner.Object, "scopes")
	if n != scopes {
		return invalid()
	}
	return nil
}
