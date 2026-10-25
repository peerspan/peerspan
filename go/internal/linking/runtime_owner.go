package linking

import (
	"strconv"
	"time"
)

// OwnerOfferEvidence is current authority for one exact pending owner offer.
// It never establishes activation or permission to skip requester consent.
type OwnerOfferEvidence struct {
	RequestID, RequestPacketID, OwnerOfferID               string
	NetworkID, FeatureID, PersonPublicKey                  string
	HostPublicKey, DevicePublicKey                         string
	CertificateID, IssuerCertificateID, SignerPublicKey    string
	Mode, NotAfter                                         string
	Scopes                                                 uint64
	Certificate, BindingDraft, BindingAuthorizationMessage []byte
	MembershipProofID, BindingProofID                      string
}
type SelectionEvidence struct {
	OwnerOfferEvidence
	SelectionID string
}
type AdministratorOfferEvidence struct {
	SelectionEvidence
	AdministratorOfferID, AdmissionRecordID, AdministratorSignerPublicKey string
	AdmissionRecord                                                       []byte
}

func freshCeremony(ctx ActivationContext, catalog []byte, objects ...[]byte) (*activationVerifier, error) {
	size := len(ctx.Network)
	for _, b := range objects {
		size += len(b)
	}
	if size > MaxActivation || len(catalog) > MaxStoredCatalog || ctx.Verification != "first" || !key(ctx.CallerHostPublicKey) || ctx.ExpectedPersonPublicKey != "-" && !key(ctx.ExpectedPersonPublicKey) {
		return nil, pathError("invalid")
	}
	v, e := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
	if e != nil {
		return nil, e
	}
	if ctx.KnownFeatureID == "-" {
		return nil, pathError("upgrade_required")
	}
	if e = v.catalog(catalog); e != nil {
		return nil, e
	}
	// Pending certificate bytes may satisfy an independently signed revocation;
	// indexing them supplies no activation or person authority.
	if len(objects) < 2 {
		return nil, pathError("invalid")
	}
	owner, e := parse(objects[1])
	if e != nil {
		return nil, pathError("invalid")
	}
	_, offer, e := payload(owner)
	if e != nil {
		return nil, pathError("invalid")
	}
	if _, e = v.index("certificate", offer["certificate"]); e != nil {
		return nil, e
	}
	e = v.bootstrap(true)
	if e == nil {
		e = v.revocations()
	}
	if e != nil {
		return nil, e
	}
	return v, nil
}
func (v *activationVerifier) bindingDraft(raw []byte, id, person, cert, signer, host string) ([]byte, error) {
	o, e := parse(raw)
	if e != nil || fields(o, "format kind network_id epoch operation_id person_public_key certificate_id payload_base64 signature host_signature") != nil || version(o, 1) != nil || scalar(o, "kind") != "peerspan-host-bind-v1" || scalar(o, "network_id") != v.net || scalar(o, "operation_id") != id || scalar(o, "person_public_key") != person || scalar(o, "certificate_id") != cert || scalar(o, "host_signature") != "-" {
		return nil, pathError("invalid")
	}
	epoch, e := num(o, "epoch")
	if e != nil || epoch != v.epoch {
		return nil, pathError("invalid")
	}
	b, p, e := payload(o)
	if e != nil || recordPayload("peerspan-host-bind-v1", p) != nil || scalar(p, "network_id") != v.net || scalar(p, "person_public_key") != person || scalar(p, "host_public_key") != host {
		return nil, pathError("invalid")
	}
	m := message("peerspan-person-authorization-v1", "peerspan-host-bind-v1", v.net, strconv.FormatUint(epoch, 10), id, person, cert, digest(b))
	if personSignature(signer, m, scalar(o, "signature")) != nil {
		return nil, pathError("invalid")
	}
	return m, nil
}
func (v *activationVerifier) pendingOwner(ctx ActivationContext, request, owner []byte) (OwnerOfferEvidence, error) {
	bad := func(code string) (OwnerOfferEvidence, error) { return OwnerOfferEvidence{}, pathError(code) }
	reqObject, e := parse(request)
	if e != nil {
		return bad("invalid")
	}
	id := scalar(reqObject, "request_id")
	_, requestPayload, e := payload(reqObject)
	if e != nil {
		return bad("invalid")
	}
	_, req, rid, e := v.checkedPacket(request, "request", id, ctx.CallerHostPublicKey, scalar(requestPayload, "device_public_key"))
	if e != nil {
		return OwnerOfferEvidence{}, e
	}
	host, device := scalar(req, "host_public_key"), scalar(req, "device_public_key")
	if host != ctx.CallerHostPublicKey || host == device || scalar(req, "coordinator_address") != scalar(v.network, "coordinator_address") || scalar(req, "coordinator_public_key") != scalar(v.network, "coordinator_public_key") {
		return bad("invalid")
	}
	expected := "link_" + digest(message("peerspan-link-request-id-v1", scalar(req, "coordinator_public_key"), host, device, scalar(req, "request_nonce")))
	if id != expected {
		return bad("invalid")
	}
	created, e := stamp(scalar(req, "created_at"))
	if e != nil {
		return bad("invalid")
	}
	expires, e := stamp(scalar(req, "expires_at"))
	if e != nil || expires.Sub(created) != 300*time.Second {
		return bad("invalid")
	}
	if v.ctx.Now.Before(created) || !v.ctx.Now.Before(expires) {
		return bad("expired")
	}
	oo, e := parse(owner)
	if e != nil {
		return bad("invalid")
	}
	_, offer, e := payload(oo)
	if e != nil {
		return bad("invalid")
	}
	person, issuer := scalar(offer, "person_public_key"), scalar(oo, "certificate_id")
	if scalar(oo, "person_public_key") != person || ctx.ExpectedPersonPublicKey != "-" && ctx.ExpectedPersonPublicKey != person || scalar(req, "expected_network_id") != "-" && scalar(req, "expected_network_id") != v.net || scalar(req, "expected_person_public_key") != "-" && scalar(req, "expected_person_public_key") != person {
		return bad("invalid")
	}
	network, e := parse(offer["network"])
	if e != nil || !equivalent(network, v.network) {
		return bad("invalid")
	}
	epoch, e := num(offer, "epoch")
	if e != nil || epoch != v.epoch || scalar(offer, "feature_id") != v.feature || scalar(offer, "request_packet_id") != rid {
		return bad("invalid")
	}
	if v.history.hosts[host] || v.history.persons[person] || v.history.unbound[bindingPair{person, host}] {
		return bad("forbidden")
	}
	mode := scalar(req, "mode")
	required := uint64(6)
	if mode == "renew" {
		required = 4
	}
	path, e := v.authority(person, issuer, required, 0)
	if e != nil {
		return OwnerOfferEvidence{}, e
	}
	_, offer, oid, e := v.checkedPacket(owner, "owner", id, path.SignerPublicKey, "-")
	if e != nil {
		return OwnerOfferEvidence{}, e
	}
	certObject, e := parse(offer["certificate"])
	if e != nil {
		return bad("invalid")
	}
	certificateID, e := candidateCertificateID(certObject)
	if e != nil {
		return OwnerOfferEvidence{}, e
	}
	candidate, e := pathCertificateFrom(certificateID, offer["certificate"])
	if e != nil {
		return OwnerOfferEvidence{}, e
	}
	if issuer != "root" {
		parent, e := v.structural(issuer, person)
		if e != nil {
			return OwnerOfferEvidence{}, e
		}
		if candidate.scopes&parent.scopes != candidate.scopes || candidate.issued.Before(parent.issued) || candidate.until.After(parent.until) {
			return bad("forbidden")
		}
	}
	c, e := v.structural(certificateID, person)
	if e != nil {
		return OwnerOfferEvidence{}, e
	}
	if c.person != person || c.host != host || c.device != device || c.parent != issuer || c.request != id || c.network != v.net {
		return bad("invalid")
	}
	if v.state.RevokedDevices[DeviceKey{PersonPublicKey: person, DevicePublicKey: device}] {
		return bad("device_revoked")
	}
	if v.ctx.Now.Before(c.issued) || !v.ctx.Now.Before(c.until) {
		return bad("authority_expired")
	}
	r := OwnerOfferEvidence{RequestID: id, RequestPacketID: rid, OwnerOfferID: oid, NetworkID: v.net, FeatureID: v.feature, PersonPublicKey: person, HostPublicKey: host, DevicePublicKey: device, CertificateID: certificateID, IssuerCertificateID: issuer, SignerPublicKey: path.SignerPublicKey, Mode: mode, NotAfter: c.expiry, Scopes: c.scopes, Certificate: offer["certificate"], MembershipProofID: scalar(offer, "membership_proof_id"), BindingProofID: scalar(offer, "binding_proof_id")}
	if mode == "new" {
		if scalar(req, "renewed_certificate_id") != "-" || r.MembershipProofID != "-" || r.BindingProofID != "-" || absent(offer["binding_record"]) {
			return bad("invalid")
		}
		r.BindingDraft = offer["binding_record"]
		r.BindingAuthorizationMessage, e = v.bindingDraft(r.BindingDraft, id, person, issuer, path.SignerPublicKey, host)
		if e != nil {
			return OwnerOfferEvidence{}, e
		}
		if e = v.hostActivations(host, 0); e != nil {
			return OwnerOfferEvidence{}, e
		}
		if v.state.Hosts[host] || v.state.Bindings[host] != "" && v.state.Bindings[host] != "-" {
			return bad("state_conflict")
		}
	} else if mode == "renew" {
		if !absent(offer["binding_record"]) || !identifier(r.MembershipProofID, "pf_") || !identifier(r.BindingProofID, "pf_") || scalar(req, "expected_network_id") != v.net || scalar(req, "expected_person_public_key") != person {
			return bad("invalid")
		}
		old, e := v.structural(scalar(req, "renewed_certificate_id"), person)
		if e != nil {
			return OwnerOfferEvidence{}, e
		}
		if old.host != host || old.device != device {
			return bad("invalid")
		}
		if !v.state.ActivatedCertificates[old.id] {
			if _, e = v.activate(old.request, true, 0); e != nil {
				return OwnerOfferEvidence{}, e
			}
		}
		if e = v.renewalProof(r.MembershipProofID, "peerspan-host-admit-v1", person, host, 0, false); e != nil {
			return OwnerOfferEvidence{}, e
		}
		if e = v.renewalProof(r.BindingProofID, "peerspan-host-bind-v1", person, host, 0, false); e != nil {
			return OwnerOfferEvidence{}, e
		}
		if !v.state.Hosts[host] || v.state.Bindings[host] != person {
			return bad("forbidden")
		}
	} else {
		return bad("invalid")
	}
	if e = v.revocations(); e != nil {
		return OwnerOfferEvidence{}, e
	}
	if _, e = v.authority(person, issuer, required, 0); e != nil {
		return OwnerOfferEvidence{}, e
	}
	if v.state.RevokedDevices[DeviceKey{PersonPublicKey: person, DevicePublicKey: device}] {
		return bad("device_revoked")
	}
	return r, nil
}
func (v *activationVerifier) pendingSelection(owner OwnerOfferEvidence, raw []byte) (SelectionEvidence, error) {
	o, p, sid, e := v.checkedPacket(raw, "selection", owner.RequestID, owner.HostPublicKey, owner.DevicePublicKey)
	if e != nil {
		return SelectionEvidence{}, e
	}
	epoch, e := num(p, "epoch")
	if e != nil || epoch != v.epoch || scalar(o, "person_public_key") != owner.PersonPublicKey || scalar(p, "owner_offer_id") != owner.OwnerOfferID || scalar(p, "network_id") != v.net || scalar(p, "feature_id") != v.feature || scalar(p, "person_public_key") != owner.PersonPublicKey {
		return SelectionEvidence{}, pathError("invalid")
	}
	return SelectionEvidence{owner, sid}, nil
}

// VerifyStoredOwnerOffer verifies a current offer before selecting it or signing
// an administrator response. Historical relaxation is deliberately unavailable.
func VerifyStoredOwnerOffer(ctx ActivationContext, catalog, request, owner []byte) (OwnerOfferEvidence, error) {
	v, e := freshCeremony(ctx, catalog, request, owner)
	if e != nil {
		return OwnerOfferEvidence{}, e
	}
	return v.pendingOwner(ctx, request, owner)
}
func VerifyStoredSelection(ctx ActivationContext, catalog, request, owner, selection []byte) (SelectionEvidence, error) {
	v, e := freshCeremony(ctx, catalog, request, owner, selection)
	if e != nil {
		return SelectionEvidence{}, e
	}
	o, e := v.pendingOwner(ctx, request, owner)
	if e != nil {
		return SelectionEvidence{}, e
	}
	return v.pendingSelection(o, selection)
}
func VerifyStoredAdministratorOffer(ctx ActivationContext, catalog, request, owner, selection, administrator []byte) (AdministratorOfferEvidence, error) {
	v, e := freshCeremony(ctx, catalog, request, owner, selection, administrator)
	if e != nil {
		return AdministratorOfferEvidence{}, e
	}
	o, e := v.pendingOwner(ctx, request, owner)
	if e != nil {
		return AdministratorOfferEvidence{}, e
	}
	s, e := v.pendingSelection(o, selection)
	if e != nil {
		return AdministratorOfferEvidence{}, e
	}
	if o.Mode != "new" {
		return AdministratorOfferEvidence{}, pathError("invalid")
	}
	a, e := parse(administrator)
	if e != nil {
		return AdministratorOfferEvidence{}, pathError("invalid")
	}
	person, cert := scalar(a, "person_public_key"), scalar(a, "certificate_id")
	signer := v.root
	if cert == "network_root" {
		if person != "-" {
			return AdministratorOfferEvidence{}, pathError("invalid")
		}
	} else {
		p, e := v.authority(person, cert, 8, 0)
		if e != nil {
			return AdministratorOfferEvidence{}, e
		}
		signer = p.SignerPublicKey
	}
	_, payload, aid, e := v.checkedPacket(administrator, "administrator", o.RequestID, signer, "-")
	if e != nil {
		return AdministratorOfferEvidence{}, e
	}
	if scalar(payload, "owner_offer_id") != o.OwnerOfferID || scalar(payload, "selection_id") != s.SelectionID {
		return AdministratorOfferEvidence{}, pathError("invalid")
	}
	raw := payload["admission_record"]
	admission, e := parse(raw)
	if e != nil {
		return AdministratorOfferEvidence{}, pathError("invalid")
	}
	if cert == "network_root" {
		person, cert = "-", "-"
	} else if _, rootRecord := admission["person_public_key"]; !rootRecord {
		return AdministratorOfferEvidence{}, pathError("invalid")
	}
	r, p, e := v.record(raw, "peerspan-host-admit-v1", o.RequestID, person, cert, signer)
	if e != nil {
		return AdministratorOfferEvidence{}, e
	}
	epoch, e := num(p, "epoch")
	if e != nil || epoch != v.epoch || scalar(p, "host_public_key") != o.HostPublicKey || scalar(p, "member") != v.persons[o.PersonPublicKey] {
		return AdministratorOfferEvidence{}, pathError("invalid")
	}
	return AdministratorOfferEvidence{s, aid, r.ID, signer, raw}, nil
}
