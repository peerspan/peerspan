package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
)

func selectionLinkReview(proof linking.OwnerOfferEvidence) LinkSelectionReview {
	return LinkSelectionReview{proof.OwnerOfferID, proof.NetworkID, personIDOf(proof.PersonPublicKey), proof.PersonPublicKey, proof.HostPublicKey, proof.DevicePublicKey, proof.CertificateID, proof.IssuerCertificateID, proof.Scopes, proof.NotAfter, proof.SignerPublicKey, "-"}
}

// A committed retry describes the immutable previously verified transcript.
// It does not ask its historical signer to regain current authority.
func persistedLinkCommitReview(p linkPending) (LinkCommitReview, error) {
	bad := func() (LinkCommitReview, error) {
		return LinkCommitReview{}, linkFail("state_conflict", p.ID, "result")
	}
	raw, e := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
	if e != nil {
		return bad()
	}
	packet, payload, e := decodeLinkPacket(raw)
	if e != nil {
		return bad()
	}
	read, e := linking.Read("packet", raw, packet.WriterPublicKey, "-")
	if e != nil || read.ID != p.Record.OwnerOfferID {
		return bad()
	}
	var owner struct {
		Network     linkDescriptor  `json:"network"`
		Certificate json.RawMessage `json:"certificate"`
	}
	if json.Unmarshal(payload, &owner) != nil {
		return bad()
	}
	certificate, e := linking.Read("certificate", owner.Certificate, packet.WriterPublicKey, "-")
	if e != nil {
		return bad()
	}
	var cert struct {
		NetworkID       string `json:"network_id"`
		PersonPublicKey string `json:"person_public_key"`
		HostPublicKey   string `json:"host_public_key"`
		DevicePublicKey string `json:"device_public_key"`
		ParentID        string `json:"parent_id"`
		Scopes          uint64 `json:"scopes"`
		NotAfter        string `json:"not_after"`
	}
	if json.Unmarshal(owner.Certificate, &cert) != nil || cert.NetworkID != owner.Network.NetworkID || cert.PersonPublicKey != packet.PersonPublicKey || cert.HostPublicKey != p.Record.HostPublicKey || cert.DevicePublicKey != p.Record.DevicePublicKey || cert.ParentID != packet.CertificateID {
		return bad()
	}
	selection := LinkSelectionReview{OwnerOfferID: read.ID, NetworkID: cert.NetworkID, PersonID: personIDOf(cert.PersonPublicKey), PersonPublicKey: cert.PersonPublicKey, HostPublicKey: cert.HostPublicKey, DevicePublicKey: cert.DevicePublicKey, CertificateID: certificate.ID, IssuerCertificateID: cert.ParentID, Scopes: cert.Scopes, NotAfter: cert.NotAfter, SignerPublicKey: packet.WriterPublicKey, AuthorityWarning: "-"}
	result := LinkCommitReview{LinkSelectionReview: selection, SelectionID: p.Record.SelectionID, AdministratorOfferID: p.Record.AdministratorOfferID, AdmissionRecordID: "-", AdmissionRecordBase64: "-", AdministratorSignerPublicKey: "-"}
	if p.Role == "new" {
		raw, e = linkBytes(p.Record.AdministratorPacketBase64, linking.MaxObject)
		if e != nil {
			return bad()
		}
		admin, payload, e := decodeLinkPacket(raw)
		if e != nil {
			return bad()
		}
		read, e = linking.Read("packet", raw, admin.WriterPublicKey, "-")
		if e != nil || read.ID != p.Record.AdministratorOfferID {
			return bad()
		}
		var offer struct {
			AdmissionRecord json.RawMessage `json:"admission_record"`
		}
		if json.Unmarshal(payload, &offer) != nil {
			return bad()
		}
		kind := "person_record"
		if admin.CertificateID == "network_root" {
			kind = "root_record"
		}
		admission, e := linking.Read(kind, offer.AdmissionRecord, admin.WriterPublicKey, "-")
		if e != nil {
			return bad()
		}
		result.AdmissionRecordID, result.AdmissionRecordBase64, result.AdministratorSignerPublicKey = admission.ID, base64.StdEncoding.EncodeToString(offer.AdmissionRecord), admin.WriterPublicKey
	}
	return result, nil
}
func checkSelectionPins(input SelectLink, review LinkSelectionReview) error {
	for _, pair := range [][2]string{{input.OwnerOfferID, review.OwnerOfferID}, {input.NetworkID, review.NetworkID}, {input.PersonPublicKey, review.PersonPublicKey}, {input.HostPublicKey, review.HostPublicKey}, {input.DevicePublicKey, review.DevicePublicKey}} {
		if pair[0] != "-" && pair[0] != pair[1] || input.Approve && pair[0] != pair[1] {
			return linkFail("invalid", "-", "consent")
		}
	}
	return nil
}
func validateLinkCommitInput(input CommitLink, mode string) error {
	for _, item := range []struct{ value, prefix string }{{input.OwnerOfferID, "lp_"}, {input.SelectionID, "lp_"}, {input.NetworkID, "net_"}} {
		if !linkID(item.value, item.prefix) && (input.Approve || item.value != "-") {
			return linkFail("invalid", "-", "commit")
		}
	}
	if !linkID(input.AdministratorOfferID, "lp_") && input.AdministratorOfferID != "-" || input.Approve && mode == "new" && input.AdministratorOfferID == "-" {
		return linkFail("invalid", "-", "commit")
	}
	for _, value := range []string{input.PersonPublicKey, input.HostPublicKey, input.DevicePublicKey} {
		if !linkPublicKey(value) && (input.Approve || value != "-") {
			return linkFail("invalid", "-", "commit")
		}
	}
	return nil
}
func (s *Store) SelectLink(ctx context.Context, id string, input SelectLink) (LinkSelectionResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	now, e := linkNow()
	if e != nil {
		return LinkSelectionResult{}, e
	}
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkSelectionResult{}, e
	}
	if p.Role == "approver" || linkTerminal(s.linkView(p, now).State) {
		return LinkSelectionResult{}, linkFail("state_conflict", id, "selection")
	}
	if e = s.publishLinkFrames(ctx, &p); e != nil {
		return LinkSelectionResult{}, e
	}
	if e = s.refreshLinkOffers(ctx, &p, now); e != nil {
		return LinkSelectionResult{}, e
	}
	verification, catalog, e := pendingLinkContext(p, now)
	if e != nil {
		return LinkSelectionResult{}, e
	}
	request, _ := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
	if !p.Record.SelectionApproved && input.OwnerOfferID != "-" && input.OwnerOfferID != p.Record.OwnerOfferID {
		packets, _, e := s.retainedLinkPackets(ctx, p)
		if e != nil {
			return LinkSelectionResult{}, e
		}
		found := false
		for _, candidate := range packets["owner"] {
			proof, e := linking.VerifyStoredOwnerOffer(verification, catalog, request, candidate)
			if e == nil && proof.OwnerOfferID == input.OwnerOfferID {
				p.Record.OwnerPacketBase64, p.Record.OwnerOfferID = base64.StdEncoding.EncodeToString(candidate), proof.OwnerOfferID
				found = true
				break
			}
		}
		if !found {
			return LinkSelectionResult{}, linkFail("proof_required", id, "owner", input.OwnerOfferID)
		}
	}
	owner, e := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
	if e != nil {
		return LinkSelectionResult{}, linkFail("proof_required", id, "owner")
	}
	proof, e := linking.VerifyStoredOwnerOffer(verification, catalog, request, owner)
	if e != nil {
		return LinkSelectionResult{}, e
	}
	review := selectionLinkReview(proof)
	if e = checkSelectionPins(input, review); e != nil {
		return LinkSelectionResult{}, e
	}
	if input.Approve && !p.Record.SelectionApproved {
		payload, e := linkJSON(map[string]any{"owner_offer_id": proof.OwnerOfferID, "network_id": proof.NetworkID, "epoch": verification.Epoch, "feature_id": proof.FeatureID, "person_public_key": proof.PersonPublicKey})
		if e != nil {
			return LinkSelectionResult{}, e
		}
		packet, selectionID, e := s.signRequesterPacket(ctx, s.db, p, "selection", proof.PersonPublicKey, payload)
		if e != nil {
			return LinkSelectionResult{}, e
		}
		if _, e = linking.VerifyStoredSelection(verification, catalog, request, owner, packet); e != nil {
			return LinkSelectionResult{}, e
		}
		p.Record.SelectionPacketBase64, p.Record.SelectionID, p.Record.SelectionApproved = base64.StdEncoding.EncodeToString(packet), selectionID, true
		p.State = "awaiting_administrator"
		if p.Role == "renew" {
			p.State = "ready_to_commit"
		}
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return LinkSelectionResult{}, e
		}
		defer tx.Rollback()
		if e = queueLinkPacket(ctx, tx, &p, "selection", s.identity.PublicKey, packet, nil); e != nil {
			return LinkSelectionResult{}, e
		}
		if e = putLinkPending(ctx, tx, p); e != nil {
			return LinkSelectionResult{}, e
		}
		if e = tx.Commit(); e != nil {
			return LinkSelectionResult{}, e
		}
		if e = linkBarrier(ctx, "host.selection.after_commit", id); e != nil {
			return LinkSelectionResult{}, e
		}
		if e = linkBarrier(ctx, "host.frame.after_commit", id); e != nil {
			return LinkSelectionResult{}, e
		}
		if e = s.publishLinkFrames(ctx, &p); e != nil {
			return LinkSelectionResult{}, e
		}
	} else if !input.Approve {
		if e = s.saveLinkPending(ctx, p); e != nil {
			return LinkSelectionResult{}, e
		}
	}
	return LinkSelectionResult{s.linkView(p, now), review}, nil
}
func activationLinkBytes(p linkPending) ([]byte, error) {
	fields := map[string]json.RawMessage{}
	for _, slot := range []struct{ kind, value string }{{"request", p.Record.RequestPacketBase64}, {"owner", p.Record.OwnerPacketBase64}, {"selection", p.Record.SelectionPacketBase64}, {"administrator", p.Record.AdministratorPacketBase64}, {"commit", p.Record.CommitPacketBase64}} {
		if slot.value == "-" {
			fields[slot.kind] = json.RawMessage(`"-"`)
		} else {
			raw, e := linkBytes(slot.value, linking.MaxObject)
			if e != nil {
				return nil, e
			}
			fields[slot.kind] = raw
		}
	}
	return linkJSON(fields)
}
func (s *Store) CommitLink(ctx context.Context, id string, input CommitLink) (LinkCommitResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	now, e := linkNow()
	if e != nil {
		return LinkCommitResult{}, e
	}
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkCommitResult{}, e
	}
	if p.Role == "approver" || !p.Record.SelectionApproved {
		return LinkCommitResult{}, linkFail("proof_required", id, "selection")
	}
	if e = validateLinkCommitInput(input, p.Role); e != nil {
		return LinkCommitResult{}, e
	}
	if p.Record.CommitApproved {
		review, e := persistedLinkCommitReview(p)
		if e != nil {
			return LinkCommitResult{}, e
		}
		pinConflict := false
		for _, pair := range [][2]string{{input.OwnerOfferID, review.OwnerOfferID}, {input.SelectionID, review.SelectionID}, {input.AdministratorOfferID, review.AdministratorOfferID}, {input.NetworkID, review.NetworkID}, {input.PersonPublicKey, review.PersonPublicKey}, {input.HostPublicKey, review.HostPublicKey}, {input.DevicePublicKey, review.DevicePublicKey}} {
			if pair[0] != "-" && pair[0] != pair[1] || input.Approve && pair[0] != pair[1] {
				pinConflict = true
			}
		}
		var manifest string
		var applied int
		e = s.db.QueryRowContext(ctx, `SELECT manifest_id,locally_applied FROM link_operations WHERE request_id=?`, id).Scan(&manifest, &applied)
		if e == nil && (manifest != p.Record.ManifestID || applied != 0 && applied != 1) {
			return LinkCommitResult{}, linkFail("state_conflict", id, "result")
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return LinkCommitResult{}, e
		}
		if p.State == "linked" && applied != 1 {
			return LinkCommitResult{}, linkFail("state_conflict", id, "result")
		}
		if pinConflict {
			code := "invalid"
			if applied == 1 {
				code = "operation_conflict"
			}
			return LinkCommitResult{}, linkFail(code, id, "commit")
		}
		if applied == 1 {
			if p.State != "linked" || len(p.Secret) != 0 {
				return LinkCommitResult{}, linkFail("state_conflict", id, "result")
			}
			return LinkCommitResult{s.linkView(p, now), review}, nil
		}
		if e = s.finalizeLinkOperation(ctx, &p, now); e != nil {
			return LinkCommitResult{}, e
		}
		return LinkCommitResult{s.linkView(p, now), review}, nil
	}
	if p.State != "linked" && !p.Record.CommitApproved {
		if e = s.publishLinkFrames(ctx, &p); e != nil {
			return LinkCommitResult{}, e
		}
		if e = s.refreshLinkOffers(ctx, &p, now); e != nil {
			return LinkCommitResult{}, e
		}
	}
	verification, catalog, e := pendingLinkContext(p, now)
	if e != nil {
		return LinkCommitResult{}, e
	}
	request, _ := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
	owner, _ := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
	selection, _ := linkBytes(p.Record.SelectionPacketBase64, linking.MaxObject)
	selected, e := linking.VerifyStoredSelection(verification, catalog, request, owner, selection)
	if e != nil {
		return LinkCommitResult{}, e
	}
	review := LinkCommitReview{LinkSelectionReview: selectionLinkReview(selected.OwnerOfferEvidence), SelectionID: p.Record.SelectionID, AdministratorOfferID: p.Record.AdministratorOfferID, AdmissionRecordID: "-", AdmissionRecordBase64: "-", AdministratorSignerPublicKey: "-"}
	if !p.Record.CommitApproved && p.Role == "new" {
		admin, e := linkBytes(p.Record.AdministratorPacketBase64, linking.MaxObject)
		if e != nil {
			return LinkCommitResult{}, linkFail("proof_required", id, "administrator")
		}
		proof, e := linking.VerifyStoredAdministratorOffer(verification, catalog, request, owner, selection, admin)
		if e != nil {
			return LinkCommitResult{}, e
		}
		review.AdministratorOfferID, review.AdmissionRecordID, review.AdmissionRecordBase64, review.AdministratorSignerPublicKey = proof.AdministratorOfferID, proof.AdmissionRecordID, base64.StdEncoding.EncodeToString(proof.AdmissionRecord), proof.AdministratorSignerPublicKey
	}
	if e = checkSelectionPins(SelectLink{input.OwnerOfferID, input.NetworkID, input.PersonPublicKey, input.HostPublicKey, input.DevicePublicKey, input.Approve}, review.LinkSelectionReview); e != nil {
		return LinkCommitResult{}, e
	}
	for _, pair := range [][2]string{{input.SelectionID, review.SelectionID}, {input.AdministratorOfferID, review.AdministratorOfferID}} {
		if pair[0] != "-" && pair[0] != pair[1] || input.Approve && pair[0] != pair[1] {
			return LinkCommitResult{}, linkFail("invalid", id, "consent")
		}
	}
	if !input.Approve {
		return LinkCommitResult{s.linkView(p, now), review}, nil
	}
	binding := json.RawMessage(`"-"`)
	if p.Role == "new" {
		var fields map[string]json.RawMessage
		if json.Unmarshal(selected.BindingDraft, &fields) != nil {
			return LinkCommitResult{}, linkFail("invalid", id, "binding")
		}
		fields["host_signature"], _ = json.Marshal(base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, linkMessage("peerspan-binding-consent-v1", linkHash(selected.BindingAuthorizationMessage)))))
		binding, e = linkJSON(fields)
		if e != nil {
			return LinkCommitResult{}, e
		}
	}
	payload, e := linkJSON(map[string]any{"mode": p.Role, "request_packet_id": selected.RequestPacketID, "owner_offer_id": selected.OwnerOfferID, "selection_id": selected.SelectionID, "administrator_offer_id": review.AdministratorOfferID, "network_id": selected.NetworkID, "epoch": verification.Epoch, "feature_id": selected.FeatureID, "person_public_key": selected.PersonPublicKey, "certificate_id": selected.CertificateID, "binding_record": binding, "admission_record_id": review.AdmissionRecordID, "expires_at": p.Deadline})
	if e != nil {
		return LinkCommitResult{}, e
	}
	packet, manifest, e := s.signRequesterPacket(ctx, s.db, p, "commit", selected.PersonPublicKey, payload)
	if e != nil {
		return LinkCommitResult{}, e
	}
	p.Record.CommitPacketBase64, p.Record.ManifestID, p.Record.CommitApproved = base64.StdEncoding.EncodeToString(packet), manifest, true
	p.State = "finalizing"
	activation, e := activationLinkBytes(p)
	if e != nil {
		return LinkCommitResult{}, e
	}
	if _, e = linking.VerifyStoredActivation(verification, catalog, activation); e != nil {
		return LinkCommitResult{}, e
	}
	if e = s.saveLinkPending(ctx, p); e != nil {
		return LinkCommitResult{}, e
	}
	if e = linkBarrier(ctx, "host.finalize.after_commit", id); e != nil {
		return LinkCommitResult{}, e
	}
	if e = s.finalizeLinkOperation(ctx, &p, now); e != nil {
		return LinkCommitResult{}, e
	}
	return LinkCommitResult{s.linkView(p, now), review}, nil
}
func (s *Store) finalizeLinkOperation(ctx context.Context, p *linkPending, now time.Time) error {
	if !p.Record.CommitApproved {
		return linkFail("forbidden", p.ID, "consent")
	}
	var descriptor linkDescriptor
	raw, e := linkBytes(p.Record.NetworkBase64, linking.MaxObject)
	if e != nil {
		return e
	}
	if json.Unmarshal(raw, &descriptor) != nil {
		return linkFail("state_conflict", p.ID, "network")
	}
	n := Network{ID: descriptor.NetworkID, Name: descriptor.Name, RootPublicKey: descriptor.GenesisRootPublicKey, CoordinatorAddress: p.Record.CoordinatorAddress, CoordinatorPublicKey: p.Record.CoordinatorPublicKey}
	result, e := s.linkCoordinator(ctx, n, http.MethodGet, "/coord/v2/networks/"+n.ID+"/link-operations/"+p.ID, nil)
	if e == nil {
		return s.applyLinkResult(ctx, p, result, now)
	}
	var failure *linkFailure
	if !errors.As(e, &failure) || failure.Code != "not_found" {
		return e
	}
	deadline, e := linkStamp(p.Deadline)
	if e != nil {
		return e
	}
	if !now.Before(deadline) {
		return nil
	}
	activation, e := activationLinkBytes(*p)
	if e != nil {
		return e
	}
	verification, catalog, e := pendingLinkContext(*p, now)
	if e != nil {
		return e
	}
	if _, e = linking.VerifyStoredActivation(verification, catalog, activation); e != nil {
		return e
	}
	selected, e := linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: verification.Network, Epoch: verification.Epoch, KnownFeatureID: verification.KnownFeatureID, Now: now}, catalog, []linking.ProofSeed{{Kind: "activation", Body: activation}})
	if e != nil {
		return e
	}
	advertise, _ := s.coordinationConfig()
	body, e := linkJSON(map[string]any{"activation": json.RawMessage(activation), "catalog": json.RawMessage(selected), "address": advertise, "candidates": s.ownCandidates(ctx, n.CoordinatorAddress)})
	if e != nil {
		return e
	}
	if len(body) > linking.MaxActivation {
		return linkFail("quota_exceeded", p.ID, "finalize")
	}
	result, e = s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+n.ID+"/link-operations", body)
	if e != nil {
		return e
	}
	return s.applyLinkResult(ctx, p, result, now)
}
func (s *Store) applyLinkResult(ctx context.Context, p *linkPending, result []byte, now time.Time) error {
	packet, payload, e := decodeLinkPacket(result)
	if e != nil {
		return e
	}
	if packet.Role != "result" || packet.RequestID != p.ID {
		return linkFail("invalid", p.ID, "result")
	}
	if _, e = linking.Read("packet", result, p.Record.CoordinatorPublicKey, "-"); e != nil {
		return linkFail("invalid", p.ID, "result")
	}
	var value struct {
		ManifestID string          `json:"manifest_id"`
		Activation json.RawMessage `json:"activation"`
		Catalog    json.RawMessage `json:"catalog"`
	}
	if linking.DecodeMutation(payload, "manifest_id activation catalog", &value) != nil || value.ManifestID != p.Record.ManifestID {
		return linkFail("operation_conflict", p.ID, "result")
	}
	expected, e := activationLinkBytes(*p)
	if e != nil {
		return e
	}
	var a, b any
	_ = json.Unmarshal(expected, &a)
	_ = json.Unmarshal(value.Activation, &b)
	left, _ := linkJSON(a)
	right, _ := linkJSON(b)
	if string(left) != string(right) {
		return linkFail("operation_conflict", p.ID, "result")
	}
	var storedManifest, storedResult string
	var alreadyApplied int
	e = s.db.QueryRowContext(ctx, `SELECT manifest_id,record,locally_applied FROM link_operations WHERE request_id=?`, p.ID).Scan(&storedManifest, &storedResult, &alreadyApplied)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil && (storedManifest != p.Record.ManifestID || storedResult != string(result) || alreadyApplied != 0 && alreadyApplied != 1) {
		return linkFail("operation_conflict", p.ID, "result")
	}
	if alreadyApplied == 1 {
		if p.State != "linked" || len(p.Secret) != 0 {
			return linkFail("state_conflict", p.ID, "result")
		}
		return nil
	}
	verification, private, e := pendingLinkContext(*p, now)
	if e != nil {
		return e
	}
	verification.Verification = "historical"
	var descriptor linkDescriptor
	if json.Unmarshal(verification.Network, &descriptor) != nil {
		return linkFail("invalid", p.ID, "network")
	}
	activationObject, e := catalogWithLinkObject(descriptor.NetworkID, "activation", value.Activation)
	if e != nil {
		return e
	}
	catalog, e := mergeLinkCatalog(descriptor.NetworkID, private, value.Catalog, activationObject)
	if e != nil {
		return e
	}
	activationEvidence, e := linking.VerifyStoredActivation(verification, catalog, value.Activation)
	if e != nil {
		return e
	}
	selectionRaw, e := linkBytes(p.Record.SelectionPacketBase64, linking.MaxObject)
	if e != nil {
		return e
	}
	_, selectionPayload, e := decodeLinkPacket(selectionRaw)
	if e != nil {
		return e
	}
	var selectedFeature struct {
		FeatureID string `json:"feature_id"`
	}
	if json.Unmarshal(selectionPayload, &selectedFeature) != nil || !p.Record.SelectionApproved || selectedFeature.FeatureID != activationEvidence.FeatureID {
		return linkFail("state_conflict", p.ID, "feature")
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, e := s.db.BeginTx(finish, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	n, e := scanNetwork(tx.QueryRowContext(finish, networkColumns+" WHERE id=?", descriptor.NetworkID))
	if errors.Is(e, ErrNotFound) {
		n = Network{ID: descriptor.NetworkID, Name: descriptor.Name, RootPublicKey: descriptor.GenesisRootPublicKey, CurrentRootPublicKey: descriptor.GenesisRootPublicKey, CoordinatorAddress: descriptor.CoordinatorAddress, CoordinatorPublicKey: descriptor.CoordinatorPublicKey}
		if e = putJSON(finish, tx, `INSERT INTO networks(record,id,root_seed) VALUES(?,?,NULL)`, n, n.ID); e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else if n.Name != descriptor.Name || n.RootPublicKey != descriptor.GenesisRootPublicKey || n.CoordinatorAddress != descriptor.CoordinatorAddress || n.CoordinatorPublicKey != descriptor.CoordinatorPublicKey {
		return linkFail("state_conflict", p.ID, "network")
	}
	prior, e := readLinkCatalog(finish, tx, n.ID)
	if e != nil {
		return e
	}
	catalog, e = mergeLinkCatalog(n.ID, prior, catalog)
	if e != nil {
		return e
	}
	projection, e := s.verifyLinkProjection(finish, tx, n, catalog, now, &linkFeatureAdoption{activationEvidence.FeatureID})
	if e != nil {
		return e
	}
	var oldManifest, oldResult string
	var applied int
	e = tx.QueryRowContext(finish, `SELECT manifest_id,record,locally_applied FROM link_operations WHERE request_id=?`, p.ID).Scan(&oldManifest, &oldResult, &applied)
	if e == nil && (oldManifest != p.Record.ManifestID || oldResult != string(result)) {
		return linkFail("operation_conflict", p.ID, "result")
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if applied == 0 {
		var count int
		if e = tx.QueryRowContext(finish, `SELECT count(*) FROM link_operations WHERE network_id=?`, n.ID).Scan(&count); e != nil {
			return e
		}
		if count >= 4096 && oldManifest == "" {
			return linkFail("quota_exceeded", p.ID, "operations")
		}
	}
	var selectedPerson, selectedDevice string
	e = tx.QueryRowContext(finish, `SELECT person_key,device_key FROM link_signers WHERE network_id=?`, n.ID).Scan(&selectedPerson, &selectedDevice)
	ownerRaw, _ := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
	ownerPacket, _, eOwner := decodeLinkPacket(ownerRaw)
	if eOwner != nil {
		return eOwner
	}
	person := ownerPacket.PersonPublicKey
	if e == nil && (selectedPerson != person || selectedDevice != p.Record.DevicePublicKey) {
		return linkFail("state_conflict", p.ID, "signer")
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if _, e = loadLinkDevice(finish, tx, p.Record.DevicePublicKey); e != nil {
		return e
	}
	certificate := ""
	var ownerBody struct {
		Certificate json.RawMessage `json:"certificate"`
	}
	_, body, _ := decodeLinkPacket(ownerRaw)
	if json.Unmarshal(body, &ownerBody) != nil {
		return linkFail("invalid", p.ID, "certificate")
	}
	var cert struct {
		ParentID string `json:"parent_id"`
	}
	if json.Unmarshal(ownerBody.Certificate, &cert) != nil {
		return linkFail("invalid", p.ID, "certificate")
	}
	readCert, e := linking.Read("certificate", ownerBody.Certificate, ownerPacket.WriterPublicKey, "-")
	if e != nil {
		return e
	}
	certificate = readCert.ID
	n.Member = projection.Network.Facts.PersonLabels[person]
	previousMembers, e := readLinkMembers(finish, tx, n.ID)
	if e != nil {
		return e
	}
	members := projectedLinkMembers(projection, previousMembers, linkTime(now))
	if e = s.applyLinkProjection(finish, tx, &n, projection, members, linkTime(now)); e != nil {
		return e
	}
	if _, e = tx.ExecContext(finish, `INSERT INTO link_signers(network_id,person_key,device_key,certificate_id) VALUES(?,?,?,?) ON CONFLICT(network_id) DO UPDATE SET person_key=excluded.person_key,device_key=excluded.device_key,certificate_id=excluded.certificate_id`, n.ID, person, p.Record.DevicePublicKey, certificate); e != nil {
		return e
	}
	if _, e = tx.ExecContext(finish, `INSERT INTO link_operations(request_id,network_id,manifest_id,record,locally_applied) VALUES(?,?,?,?,1) ON CONFLICT(request_id) DO UPDATE SET locally_applied=1`, p.ID, n.ID, p.Record.ManifestID, string(result)); e != nil {
		return e
	}
	p.Record.ResultPacketBase64 = base64.StdEncoding.EncodeToString(result)
	p.State = "linked"
	p.Secret = nil
	if e = putLinkPending(finish, tx, *p); e != nil {
		return e
	}
	if _, e = tx.ExecContext(finish, `DELETE FROM link_frames WHERE request_id=?`, p.ID); e != nil {
		return e
	}
	if applied == 0 {
		if e = appendEvent(finish, tx, "network.link_applied", p.ID, linkTime(now)); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.mapApplied(n.ID, members)
	if e = linkBarrier(ctx, "host.result.after_commit", p.ID); e != nil {
		return e
	}
	return nil
}
