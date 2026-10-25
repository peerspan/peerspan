package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func (s *Store) openLinkApproval(ctx context.Context, n Network, code string, now time.Time) (result linkPending, err error) {
	secret, e := linkSecret(code)
	if e != nil {
		return linkPending{}, linkFail("invalid", "-", "code")
	}
	if !s.linkPollDue(n.CoordinatorPublicKey, secret, now) {
		var id string
		if e = s.db.QueryRowContext(ctx, `SELECT request_id FROM link_pending WHERE role='approver' AND secret=?`, secret).Scan(&id); e == nil {
			p, e := readLinkPending(ctx, s.db, id)
			if e != nil {
				return p, e
			}
			if p.Record.CoordinatorAddress != n.CoordinatorAddress || p.Record.CoordinatorPublicKey != n.CoordinatorPublicKey {
				return p, linkFail("invalid", id, "coordinator")
			}
			return p, nil
		}
	}
	raw, e := s.linkCoordinator(ctx, n, http.MethodGet, "/coord/v2/link-mailboxes/"+linkLocator(secret)+"?after=0", nil)
	if e != nil {
		return linkPending{}, e
	}
	defer func() {
		if err == nil {
			s.linkPolled(n.CoordinatorPublicKey, secret, now)
		}
	}()
	box, e := decodeLinkMailbox(raw)
	if e != nil {
		return linkPending{}, e
	}
	until, e := linkStamp(box.ExpiresAt)
	if e != nil {
		return linkPending{}, e
	}
	if box.State != "open" || !now.Before(until) {
		return linkPending{}, linkFail("expired", box.RequestID, "request")
	}
	if old, e := readLinkPending(ctx, s.db, box.RequestID); e == nil {
		if old.Role != "approver" || string(old.Secret) != string(secret) {
			return old, linkFail("state_conflict", box.RequestID, "request")
		}
		if e = s.receiveLinkMailbox(ctx, &old, box); e != nil {
			return old, e
		}
		return old, nil
	} else {
		var f *linkFailure
		if !errors.As(e, &f) || f.Code != "not_found" {
			return old, e
		}
	}
	p := linkPending{ID: box.RequestID, Role: "approver", State: "review", Deadline: box.ExpiresAt, Record: emptyLinkRecord(), Secret: secret}
	p.Record.CoordinatorAddress, p.Record.CoordinatorPublicKey = n.CoordinatorAddress, n.CoordinatorPublicKey
	for _, row := range box.Frames {
		frame, e := decodeLinkFrame(row.Frame)
		if e != nil {
			return p, e
		}
		if frame.Role != "request" {
			continue
		}
		plain, e := decodeLinkPlaintext(p, frame)
		if e != nil {
			return p, e
		}
		if linkAbsent(plain.Packet) {
			continue
		}
		packet, payload, e := decodeLinkPacket(plain.Packet)
		if e != nil {
			return p, e
		}
		var request struct {
			HostPublicKey           string `json:"host_public_key"`
			DevicePublicKey         string `json:"device_public_key"`
			RequestNonce            string `json:"request_nonce"`
			CoordinatorAddress      string `json:"coordinator_address"`
			CoordinatorPublicKey    string `json:"coordinator_public_key"`
			ExpectedNetworkID       string `json:"expected_network_id"`
			ExpectedPersonPublicKey string `json:"expected_person_public_key"`
			ExpiresAt               string `json:"expires_at"`
			CreatedAt               string `json:"created_at"`
		}
		if json.Unmarshal(payload, &request) != nil || request.CoordinatorAddress != n.CoordinatorAddress || request.CoordinatorPublicKey != n.CoordinatorPublicKey || request.ExpiresAt != p.Deadline || request.ExpectedNetworkID != "-" && request.ExpectedNetworkID != n.ID || request.HostPublicKey == s.identity.PublicKey {
			return p, linkFail("invalid", p.ID, "request")
		}
		created, e := linkStamp(request.CreatedAt)
		if e != nil || now.Before(created) || until.Sub(created) != 300*time.Second {
			return p, linkFail("invalid", p.ID, "request")
		}
		if _, e = linking.Read("packet", plain.Packet, packet.WriterPublicKey, request.DevicePublicKey); e != nil {
			return p, linkFail("invalid", p.ID, "request")
		}
		if p.ID != "link_"+linkHash(linkMessage("peerspan-link-request-id-v1", request.CoordinatorPublicKey, request.HostPublicKey, request.DevicePublicKey, request.RequestNonce)) {
			return p, linkFail("invalid", p.ID, "request")
		}
		p.Record.ExpectedNetworkID, p.Record.ExpectedPersonPublicKey = request.ExpectedNetworkID, request.ExpectedPersonPublicKey
		p.Record.HostPublicKey, p.Record.DevicePublicKey, p.Record.RequestNonce = request.HostPublicKey, request.DevicePublicKey, request.RequestNonce
		p.Record.RequestPacketBase64 = base64.StdEncoding.EncodeToString(plain.Packet)
		break
	}
	if p.Record.RequestPacketBase64 == "-" {
		return p, linkFail("proof_required", p.ID, "request")
	}
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return p, e
	}
	p.Record.NetworkBase64 = base64.StdEncoding.EncodeToString(descriptor)
	catalog, e := readLinkCatalog(ctx, s.db, n.ID)
	if e != nil {
		return p, e
	}
	p.Record.CatalogBase64 = base64.StdEncoding.EncodeToString(catalog)
	if e = s.saveLinkPending(ctx, p); e != nil {
		return p, e
	}
	if e = s.receiveLinkMailbox(ctx, &p, box); e != nil {
		return p, e
	}
	return p, nil
}

type linkApprovalSigner struct {
	Person, Certificate, Public, NotAfter string
	Scopes                                uint64
	Key                                   ed25519.PrivateKey
}

func (s *Store) resolveApprovalSigner(ctx context.Context, p *linkProjection, requested string, administrator bool, mode string, now time.Time) (linkApprovalSigner, error) {
	root := func() (linkApprovalSigner, error) {
		_, key, e := s.administeredNetwork(ctx, s.db, p.Network.Facts.NetworkID)
		if e != nil {
			return linkApprovalSigner{}, e
		}
		public := membership.EncodeKey(key.Public().(ed25519.PublicKey))
		if public != p.Network.RootPublicKey {
			return linkApprovalSigner{}, linkFail("forbidden", "-", "root")
		}
		return linkApprovalSigner{"-", "network_root", public, "-", 15, key}, nil
	}
	if requested == "network_root" {
		if !administrator {
			return linkApprovalSigner{}, linkFail("forbidden", "-", "signer")
		}
		return root()
	}
	person := p.Network.Facts.State.Bindings[s.identity.PublicKey]
	if !linkPublicKey(person) {
		if administrator && requested == "auto" {
			return root()
		}
		return linkApprovalSigner{}, linkFail("proof_required", "-", "person")
	}
	required := uint64(6)
	if mode == "renew" {
		required = 4
	}
	if administrator {
		required = 8
	}
	if requested == "auto" && mode == "renew" && !administrator {
		type candidate struct {
			id    string
			depth int
		}
		candidates := []candidate{}
		for id := range p.Network.Facts.State.Certificates {
			path, e := linking.EvaluatePath(p.Network.Facts.State, person, id, required, now)
			if e == nil {
				candidates = append(candidates, candidate{id, len(path.CertificateIDs)})
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].depth != candidates[j].depth {
				return candidates[i].depth < candidates[j].depth
			}
			return candidates[i].id < candidates[j].id
		})
		for _, candidate := range candidates {
			device, e := s.linkDeviceProvider(ctx, s.db, p, candidate.id, required, now)
			if e == nil {
				return linkApprovalSigner{device.View.PersonPublicKey, device.View.CertificateID, device.View.DevicePublicKey, device.View.NotAfter, device.View.Scopes, device.Key}, nil
			}
		}
	}
	if requested == "auto" || linkID(requested, "dc_") {
		device, e := s.linkDeviceProvider(ctx, s.db, p, requested, required, now)
		if e == nil {
			return linkApprovalSigner{device.View.PersonPublicKey, device.View.CertificateID, device.View.DevicePublicKey, device.View.NotAfter, device.View.Scopes, device.Key}, nil
		}
		var f *linkFailure
		if requested != "auto" || !errors.As(e, &f) || f.Code != "not_found" {
			return linkApprovalSigner{}, e
		}
		if administrator {
			if signer, e := root(); e == nil {
				return signer, nil
			}
		}
	} else if requested != "person_root" {
		return linkApprovalSigner{}, linkFail("invalid", "-", "signer")
	}
	path, e := linking.EvaluatePath(p.Network.Facts.State, person, "root", required, now)
	if e != nil {
		return linkApprovalSigner{}, e
	}
	return linkApprovalSigner{person, "root", person, path.NotAfter, path.Scopes, nil}, nil
}
func requestLinkMode(p linkPending) string {
	raw, _ := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
	_, payload, _ := decodeLinkPacket(raw)
	var request struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal(payload, &request)
	return request.Mode
}
func pinLinkApproval(input ApproveLink, person string, p linkPending) error {
	personID := personIDOf(person)
	if input.ExpectedPersonID != "-" && input.ExpectedPersonID != personID || input.ExpectedHostKey != "-" && input.ExpectedHostKey != p.Record.HostPublicKey || input.ExpectedDeviceKey != "-" && input.ExpectedDeviceKey != p.Record.DevicePublicKey {
		return linkFail("invalid", p.ID, "review")
	}
	if input.Approve && (input.ExpectedPersonID != personID || input.ExpectedHostKey != p.Record.HostPublicKey || input.ExpectedDeviceKey != p.Record.DevicePublicKey) {
		return linkFail("invalid", p.ID, "consent")
	}
	return nil
}
func (s *Store) ApproveLink(ctx context.Context, input ApproveLink, administrator bool) (LinkApprovalResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, input.NetworkID)
	if e != nil {
		return LinkApprovalResult{}, e
	}
	n, e = s.syncLinkNetworkLocked(ctx, n, s.ownCandidates(ctx, n.CoordinatorAddress))
	if e != nil {
		return LinkApprovalResult{}, e
	}
	now, e := linkNow()
	if e != nil {
		return LinkApprovalResult{}, e
	}
	projection, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return LinkApprovalResult{}, e
	}
	p, e := s.openLinkApproval(ctx, n, input.Code, now)
	if e != nil {
		return LinkApprovalResult{}, e
	}
	prior, e := linkBytes(p.Record.CatalogBase64, linking.MaxStoredCatalog)
	if e != nil {
		return LinkApprovalResult{}, e
	}
	merged, e := mergeLinkCatalog(n.ID, prior, projection.Catalog)
	if e != nil {
		return LinkApprovalResult{}, e
	}
	p.Record.CatalogBase64 = base64.StdEncoding.EncodeToString(merged)
	if e = s.refreshLinkOffers(ctx, &p, now, false); e != nil {
		return LinkApprovalResult{}, e
	}
	mode := requestLinkMode(p)
	var owner linking.SelectionEvidence
	if administrator {
		if mode != "new" {
			return LinkApprovalResult{}, linkFail("invalid", p.ID, "administrator")
		}
		if p.Record.SelectionPacketBase64 == "-" {
			packets, _, e := s.retainedLinkPackets(ctx, p)
			if e != nil {
				return LinkApprovalResult{}, e
			}
			verification, catalog, e := pendingLinkContext(p, now)
			if e != nil {
				return LinkApprovalResult{}, e
			}
			request, _ := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
			for _, offer := range packets["owner"] {
				for _, selection := range packets["selection"] {
					proof, e := linking.VerifyStoredSelection(verification, catalog, request, offer, selection)
					if e == nil && (owner.SelectionID == "" || proof.SelectionID < owner.SelectionID) {
						owner = proof
						p.Record.OwnerPacketBase64, p.Record.OwnerOfferID = base64.StdEncoding.EncodeToString(offer), proof.OwnerOfferID
						p.Record.SelectionPacketBase64, p.Record.SelectionID = base64.StdEncoding.EncodeToString(selection), proof.SelectionID
					}
				}
			}
			if owner.SelectionID == "" {
				return LinkApprovalResult{}, linkFail("proof_required", p.ID, "selection")
			}
		} else {
			verification, catalog, e := pendingLinkContext(p, now)
			if e != nil {
				return LinkApprovalResult{}, e
			}
			request, _ := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
			offer, _ := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
			selection, _ := linkBytes(p.Record.SelectionPacketBase64, linking.MaxObject)
			owner, e = linking.VerifyStoredSelection(verification, catalog, request, offer, selection)
			if e != nil {
				return LinkApprovalResult{}, e
			}
		}
	}
	slot := &p.Record.OwnerIntent
	if administrator {
		slot = &p.Record.AdministratorIntent
	}
	if slot.Intent == nil {
		signer, e := s.resolveApprovalSigner(ctx, projection, input.Signer, administrator, mode, now)
		if e != nil {
			return LinkApprovalResult{}, e
		}
		person := signer.Person
		if administrator {
			person = owner.PersonPublicKey
		}
		if p.Record.ExpectedPersonPublicKey != "-" && p.Record.ExpectedPersonPublicKey != person {
			return LinkApprovalResult{}, linkFail("invalid", p.ID, "person")
		}
		if e = pinLinkApproval(input, person, p); e != nil {
			return LinkApprovalResult{}, e
		}
		intent, e := s.prepareLinkIntent(p, projection, signer, owner, administrator, now)
		if e != nil {
			return LinkApprovalResult{}, e
		}
		slot.Intent = &intent
		if !administrator && mode == "new" {
			if _, authorityErr := linking.EvaluatePath(projection.Network.Facts.State, signer.Person, signer.Certificate, 8, now); authorityErr == nil {
				pendingOwner := linking.SelectionEvidence{OwnerOfferEvidence: linking.OwnerOfferEvidence{NetworkID: input.NetworkID, PersonPublicKey: signer.Person, HostPublicKey: p.Record.HostPublicKey, DevicePublicKey: p.Record.DevicePublicKey, Scopes: intent.Scopes, NotAfter: intent.NotAfter}}
				adminIntent, err := s.prepareLinkIntent(p, projection, signer, pendingOwner, true, now)
				if err != nil {
					return LinkApprovalResult{}, err
				}
				p.Record.AdministratorIntent.Intent = &adminIntent
			}
		}
	} else {
		person := slot.Intent.PersonPublicKey
		if administrator {
			person = owner.PersonPublicKey
		}
		if e = pinLinkApproval(input, person, p); e != nil {
			return LinkApprovalResult{}, e
		}
		if input.Signer != "auto" && input.Signer != "person_root" && input.Signer != slot.Intent.CertificateID || input.Signer == "person_root" && slot.Intent.CertificateID != "root" {
			return LinkApprovalResult{}, linkFail("state_conflict", p.ID, "signer")
		}
	}
	if input.Approve {
		slot.Intent.Approved = true
		if !administrator && p.Record.AdministratorIntent.Intent != nil {
			p.Record.AdministratorIntent.Intent.Approved = true
		}
	}
	if e = s.saveLinkPending(ctx, p); e != nil {
		return LinkApprovalResult{}, e
	}
	if slot.Intent.Approved {
		if e = s.advanceLinkIntent(ctx, &p, administrator, "", "", now); e != nil {
			return LinkApprovalResult{}, e
		}
	}
	if !administrator && p.Record.AdministratorIntent.Intent != nil && p.Record.AdministratorIntent.Intent.Approved && p.Record.SelectionPacketBase64 != "-" {
		if e = s.advanceLinkIntent(ctx, &p, true, "", "", now); e != nil {
			return LinkApprovalResult{}, e
		}
		administrator = true
	}
	return s.linkApprovalResult(ctx, &p, administrator, now)
}
func (s *Store) prepareLinkIntent(p linkPending, projection *linkProjection, signer linkApprovalSigner, owner linking.SelectionEvidence, administrator bool, now time.Time) (linkIntent, error) {
	i := linkIntent{Format: 1, Epoch: projection.Network.Epoch, FeatureID: projection.Network.Facts.FeatureID, PersonPublicKey: signer.Person, CertificateID: signer.Certificate, SignerPublicKey: signer.Public, Scopes: signer.Scopes, IssuedAt: linkTime(now), NotAfter: signer.NotAfter, CertificateTemplateBase64: "-", RecordTemplateBase64: "-", PacketTemplateBase64: "-", Signatures: []linkSignature{}}
	if administrator {
		i.Scopes = 8
		payload, e := linkJSON(map[string]any{"network_id": owner.NetworkID, "epoch": projection.Network.Epoch, "host_public_key": owner.HostPublicKey, "member": projection.Network.Facts.PersonLabels[owner.PersonPublicKey], "admitted_at": i.IssuedAt})
		if e != nil {
			return i, e
		}
		record := map[string]any{"format": 1, "kind": "peerspan-host-admit-v1", "network_id": owner.NetworkID, "epoch": projection.Network.Epoch, "operation_id": p.ID, "payload_base64": base64.StdEncoding.EncodeToString(payload), "signature": "-"}
		if signer.Certificate != "network_root" {
			record["person_public_key"], record["certificate_id"], record["host_signature"] = signer.Person, signer.Certificate, "-"
		}
		raw, e := linkJSON(record)
		if e != nil {
			return i, e
		}
		i.RecordTemplateBase64 = base64.StdEncoding.EncodeToString(raw)
		i.Signatures = []linkSignature{{"admission_authorization", "-"}, {"administrator_packet", "-"}}
		return i, nil
	}
	if projection.Network.Facts.State.RevokedDevices[linking.DeviceKey{PersonPublicKey: signer.Person, DevicePublicKey: p.Record.DevicePublicKey}] {
		return i, linkFail("device_revoked", p.ID, "certificate")
	}
	mode := requestLinkMode(p)
	if mode == "new" {
		if _, known := projection.Network.Facts.State.Hosts[p.Record.HostPublicKey]; known {
			return i, linkFail("state_conflict", p.ID, "host")
		}
	}
	if mode == "renew" {
		if !projection.Network.Facts.State.Hosts[p.Record.HostPublicKey] || projection.Network.Facts.State.Bindings[p.Record.HostPublicKey] != signer.Person {
			return i, linkFail("forbidden", p.ID, "renewal")
		}
	}
	if signer.Public == p.Record.DevicePublicKey {
		return i, linkFail("forbidden", p.ID, "certificate")
	}
	until := now.Add(90 * 24 * time.Hour)
	if signer.NotAfter != "-" {
		limit, e := linkStamp(signer.NotAfter)
		if e != nil {
			return i, e
		}
		if limit.Before(until) {
			until = limit
		}
	}
	i.NotAfter = linkTime(until)
	certificate, e := linkJSON(map[string]any{"format": 1, "network_id": projection.Network.Facts.NetworkID, "person_public_key": signer.Person, "device_public_key": p.Record.DevicePublicKey, "host_public_key": p.Record.HostPublicKey, "parent_id": signer.Certificate, "scopes": signer.Scopes, "issued_at": i.IssuedAt, "not_after": i.NotAfter, "request_id": p.ID, "signature": "-"})
	if e != nil {
		return i, e
	}
	i.CertificateTemplateBase64 = base64.StdEncoding.EncodeToString(certificate)
	i.Signatures = append(i.Signatures, linkSignature{"certificate", "-"})
	if mode == "new" {
		payload, e := linkJSON(map[string]any{"network_id": projection.Network.Facts.NetworkID, "person_public_key": signer.Person, "host_public_key": p.Record.HostPublicKey, "bound_at": i.IssuedAt})
		if e != nil {
			return i, e
		}
		record, e := linkJSON(map[string]any{"format": 1, "kind": "peerspan-host-bind-v1", "network_id": projection.Network.Facts.NetworkID, "epoch": projection.Network.Epoch, "operation_id": p.ID, "person_public_key": signer.Person, "certificate_id": signer.Certificate, "payload_base64": base64.StdEncoding.EncodeToString(payload), "signature": "-", "host_signature": "-"})
		if e != nil {
			return i, e
		}
		i.RecordTemplateBase64 = base64.StdEncoding.EncodeToString(record)
		i.Signatures = append(i.Signatures, linkSignature{"binding_authorization", "-"})
	}
	i.Signatures = append(i.Signatures, linkSignature{"owner_packet", "-"})
	return i, nil
}

func linkTemplateWithSignature(encoded, signature string) ([]byte, error) {
	raw, e := linkBytes(encoded, linking.MaxObject)
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, linkFail("state_conflict", "-", "intent")
	}
	fields["signature"], _ = json.Marshal(signature)
	return linkJSON(fields)
}
func linkIntentSignature(i *linkIntent, kind string) string {
	for _, slot := range i.Signatures {
		if slot.ObjectType == kind {
			return slot.Signature
		}
	}
	return "-"
}
func linkRecordMessage(raw []byte) ([]byte, error) {
	var o struct {
		Kind            string `json:"kind"`
		NetworkID       string `json:"network_id"`
		Epoch           uint64 `json:"epoch"`
		OperationID     string `json:"operation_id"`
		PersonPublicKey string `json:"person_public_key"`
		CertificateID   string `json:"certificate_id"`
		PayloadBase64   string `json:"payload_base64"`
	}
	if json.Unmarshal(raw, &o) != nil {
		return nil, linkFail("state_conflict", "-", "intent")
	}
	payload, e := linkBytes(o.PayloadBase64, linking.MaxPayload)
	if e != nil {
		return nil, e
	}
	if o.PersonPublicKey == "" {
		return linkMessage("peerspan-root-authorization-v1", o.Kind, o.NetworkID, strconv.FormatUint(o.Epoch, 10), o.OperationID, linkHash(payload)), nil
	}
	return linkMessage("peerspan-person-authorization-v1", o.Kind, o.NetworkID, strconv.FormatUint(o.Epoch, 10), o.OperationID, o.PersonPublicKey, o.CertificateID, linkHash(payload)), nil
}
