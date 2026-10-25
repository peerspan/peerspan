package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func linkCertificateMessage(raw []byte) ([]byte, error) {
	var c struct {
		NetworkID       string `json:"network_id"`
		PersonPublicKey string `json:"person_public_key"`
		DevicePublicKey string `json:"device_public_key"`
		HostPublicKey   string `json:"host_public_key"`
		ParentID        string `json:"parent_id"`
		Scopes          uint64 `json:"scopes"`
		IssuedAt        string `json:"issued_at"`
		NotAfter        string `json:"not_after"`
		RequestID       string `json:"request_id"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return nil, linkFail("state_conflict", "-", "intent")
	}
	return linkMessage("peerspan-device-certificate-v1", c.NetworkID, c.PersonPublicKey, c.DevicePublicKey, c.HostPublicKey, c.ParentID, strconv.FormatUint(c.Scopes, 10), c.IssuedAt, c.NotAfter, c.RequestID), nil
}
func (s *Store) nextLinkSigning(ctx context.Context, p *linkPending, administrator bool, now time.Time, materialize ...bool) (LinkSigningRequest, error) {
	i := p.Record.OwnerIntent.Intent
	if administrator {
		i = p.Record.AdministratorIntent.Intent
	}
	if i == nil || !i.Approved {
		return LinkSigningRequest{}, nil
	}
	for _, slot := range i.Signatures {
		if slot.Signature != "-" {
			continue
		}
		var message []byte
		switch slot.ObjectType {
		case "certificate":
			raw, e := linkBytes(i.CertificateTemplateBase64, linking.MaxObject)
			if e != nil {
				return LinkSigningRequest{}, e
			}
			message, e = linkCertificateMessage(raw)
			if e != nil {
				return LinkSigningRequest{}, e
			}
		case "binding_authorization", "admission_authorization":
			raw, e := linkBytes(i.RecordTemplateBase64, linking.MaxObject)
			if e != nil {
				return LinkSigningRequest{}, e
			}
			message, e = linkRecordMessage(raw)
			if e != nil {
				return LinkSigningRequest{}, e
			}
		case "owner_packet", "administrator_packet":
			if i.PacketTemplateBase64 == "-" {
				if len(materialize) > 0 && !materialize[0] {
					return LinkSigningRequest{}, nil
				}
				var payload []byte
				if administrator {
					record, e := linkTemplateWithSignature(i.RecordTemplateBase64, linkIntentSignature(i, "admission_authorization"))
					if e != nil {
						return LinkSigningRequest{}, e
					}
					payload, e = linkJSON(map[string]any{"owner_offer_id": p.Record.OwnerOfferID, "selection_id": p.Record.SelectionID, "admission_record": json.RawMessage(record)})
					if e != nil {
						return LinkSigningRequest{}, e
					}
				} else {
					certificate, e := linkTemplateWithSignature(i.CertificateTemplateBase64, linkIntentSignature(i, "certificate"))
					if e != nil {
						return LinkSigningRequest{}, e
					}
					binding := json.RawMessage(`"-"`)
					if i.RecordTemplateBase64 != "-" {
						binding, e = linkTemplateWithSignature(i.RecordTemplateBase64, linkIntentSignature(i, "binding_authorization"))
						if e != nil {
							return LinkSigningRequest{}, e
						}
					}
					network, e := linkBytes(p.Record.NetworkBase64, linking.MaxObject)
					if e != nil {
						return LinkSigningRequest{}, e
					}
					request, e := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
					if e != nil {
						return LinkSigningRequest{}, e
					}
					requestProof, e := linking.Read("packet", request, p.Record.HostPublicKey, p.Record.DevicePublicKey)
					if e != nil {
						return LinkSigningRequest{}, e
					}
					membershipID, bindingID := "-", "-"
					if requestLinkMode(*p) == "renew" {
						verification, catalog, e := pendingLinkContext(*p, now)
						if e != nil {
							return LinkSigningRequest{}, e
						}
						state, e := linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: verification.Network, Epoch: verification.Epoch, KnownFeatureID: verification.KnownFeatureID, Now: now}, catalog)
						if e != nil {
							return LinkSigningRequest{}, e
						}
						for _, m := range state.Members {
							if m.HostPublicKey == p.Record.HostPublicKey && m.PersonPublicKey == i.PersonPublicKey {
								membershipID, bindingID = m.MembershipProofID, m.BindingProofID
								break
							}
						}
						if membershipID == "-" || bindingID == "-" {
							return LinkSigningRequest{}, linkFail("proof_required", p.ID, "renewal")
						}
					}
					payload, e = linkJSON(map[string]any{"request_packet_id": requestProof.ID, "network": json.RawMessage(network), "epoch": i.Epoch, "feature_id": i.FeatureID, "person_public_key": i.PersonPublicKey, "certificate": json.RawMessage(certificate), "binding_record": binding, "membership_proof_id": membershipID, "binding_proof_id": bindingID})
					if e != nil {
						return LinkSigningRequest{}, e
					}
				}
				role := "owner"
				if administrator {
					role = "administrator"
				}
				packet := linkPacket{1, p.ID, role, i.SignerPublicKey, i.PersonPublicKey, i.CertificateID, base64.StdEncoding.EncodeToString(payload), "-", "-", "-"}
				raw, e := linkJSON(packet)
				if e != nil {
					return LinkSigningRequest{}, e
				}
				i.PacketTemplateBase64 = base64.StdEncoding.EncodeToString(raw)
				if e = s.saveLinkPending(ctx, *p); e != nil {
					return LinkSigningRequest{}, e
				}
			}
			raw, e := linkBytes(i.PacketTemplateBase64, linking.MaxObject)
			if e != nil {
				return LinkSigningRequest{}, e
			}
			packet, payload, e := decodeLinkPacket(raw)
			if e != nil {
				return LinkSigningRequest{}, e
			}
			message = packetLinkMessage(packet, payload)
		default:
			return LinkSigningRequest{}, linkFail("state_conflict", p.ID, "intent")
		}
		format := "sshsig"
		if i.CertificateID == "network_root" {
			format = "ed25519"
		}
		return LinkSigningRequest{slot.ObjectType, base64.StdEncoding.EncodeToString(message), i.SignerPublicKey, format}, nil
	}
	return LinkSigningRequest{}, nil
}
func (s *Store) intentSigningKey(ctx context.Context, p *linkPending, i *linkIntent, administrator bool, now time.Time) (ed25519.PrivateKey, error) {
	network, e := linkBytes(p.Record.NetworkBase64, linking.MaxObject)
	if e != nil {
		return nil, e
	}
	var descriptor linkDescriptor
	if json.Unmarshal(network, &descriptor) != nil {
		return nil, linkFail("state_conflict", p.ID, "intent")
	}
	n, e := s.Network(ctx, descriptor.NetworkID)
	if e != nil {
		return nil, e
	}
	n, e = s.syncLinkNetworkLocked(ctx, n, s.ownCandidates(ctx, n.CoordinatorAddress))
	if e != nil {
		return nil, e
	}
	if n.CoordinatorAddress != p.Record.CoordinatorAddress || n.CoordinatorPublicKey != p.Record.CoordinatorPublicKey {
		return nil, linkFail("state_conflict", p.ID, "coordinator")
	}
	now, e = linkNow()
	if e != nil {
		return nil, e
	}
	projection, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return nil, e
	}
	if projection.Network.Epoch != i.Epoch || projection.Network.Facts.FeatureID != i.FeatureID {
		return nil, linkFail("state_conflict", p.ID, "authority")
	}
	prior, e := linkBytes(p.Record.CatalogBase64, linking.MaxStoredCatalog)
	if e != nil {
		return nil, e
	}
	merged, e := mergeLinkCatalog(n.ID, prior, projection.Catalog)
	if e != nil {
		return nil, e
	}
	p.Record.CatalogBase64 = base64.StdEncoding.EncodeToString(merged)
	if !administrator {
		if projection.Network.Facts.State.RevokedDevices[linking.DeviceKey{PersonPublicKey: i.PersonPublicKey, DevicePublicKey: p.Record.DevicePublicKey}] {
			return nil, linkFail("device_revoked", p.ID, "certificate")
		}
		if requestLinkMode(*p) == "new" {
			if _, known := projection.Network.Facts.State.Hosts[p.Record.HostPublicKey]; known {
				return nil, linkFail("state_conflict", p.ID, "host")
			}
		} else if !projection.Network.Facts.State.Hosts[p.Record.HostPublicKey] || projection.Network.Facts.State.Bindings[p.Record.HostPublicKey] != i.PersonPublicKey {
			return nil, linkFail("forbidden", p.ID, "renewal")
		}
	}
	until, e := linkStamp(p.Deadline)
	if e != nil || !now.Before(until) {
		return nil, linkFail("expired", p.ID, "request")
	}
	if i.CertificateID == "network_root" {
		if !administrator || i.SignerPublicKey != projection.Network.RootPublicKey {
			return nil, linkFail("forbidden", p.ID, "root")
		}
		_, key, e := s.administeredNetwork(ctx, s.db, n.ID)
		if e != nil {
			return nil, nil
		}
		if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != i.SignerPublicKey {
			return nil, linkFail("forbidden", p.ID, "root")
		}
		return key, nil
	}
	required := uint64(6)
	if requestLinkMode(*p) == "renew" {
		required = 4
	}
	if administrator {
		required = 8
	}
	path, e := linking.EvaluatePath(projection.Network.Facts.State, i.PersonPublicKey, i.CertificateID, required, now)
	if e != nil {
		return nil, e
	}
	if path.SignerPublicKey != i.SignerPublicKey {
		return nil, linkFail("forbidden", p.ID, "signer")
	}
	if i.CertificateID == "root" {
		return nil, nil
	}
	return loadLinkDevice(ctx, s.db, i.SignerPublicKey)
}
func (s *Store) advanceLinkIntent(ctx context.Context, p *linkPending, administrator bool, objectType, signature string, now time.Time) error {
	i := p.Record.OwnerIntent.Intent
	if administrator {
		i = p.Record.AdministratorIntent.Intent
	}
	if i == nil || !i.Approved {
		return linkFail("forbidden", p.ID, "consent")
	}
	for {
		key, e := s.intentSigningKey(ctx, p, i, administrator, now)
		if e != nil {
			return e
		}
		next, e := s.nextLinkSigning(ctx, p, administrator, now)
		if e != nil {
			return e
		}
		if next.ObjectType == "" {
			break
		}
		message, e := linkBytes(next.MessageBase64, linking.MaxObject)
		if e != nil {
			return e
		}
		provided := signature != ""
		if provided {
			if objectType != next.ObjectType {
				return linkFail("operation_conflict", p.ID, "signing")
			}
		}
		if signature == "" {
			if len(key) == 0 {
				return nil
			}
			if i.CertificateID == "network_root" {
				signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))
			} else {
				signature, e = membership.SignSSHSIG(membership.KeySigner{Key: key}, message)
				if e != nil {
					return e
				}
			}
		}
		public, _ := membership.DecodeKey(i.SignerPublicKey)
		valid := membership.VerifySSHSIG(public, message, signature) == nil
		if i.CertificateID == "network_root" {
			if raw, e := linkBytes(signature, 64); e == nil && len(raw) == 64 {
				valid = ed25519.Verify(public, message, raw)
			}
		}
		if !valid {
			return linkFail("invalid", p.ID, "signature")
		}
		for index := range i.Signatures {
			if i.Signatures[index].ObjectType == next.ObjectType {
				i.Signatures[index].Signature = signature
				break
			}
		}
		if e = s.saveLinkPending(ctx, *p); e != nil {
			return e
		}
		signature, objectType = "", ""
		if provided && len(key) == 0 {
			break
		}
	}
	next, e := s.nextLinkSigning(ctx, p, administrator, now)
	if e != nil || next.ObjectType != "" {
		return e
	}
	packetRaw, e := linkBytes(i.PacketTemplateBase64, linking.MaxObject)
	if e != nil {
		return e
	}
	var packet linkPacket
	if json.Unmarshal(packetRaw, &packet) != nil {
		return linkFail("state_conflict", p.ID, "intent")
	}
	kind := "owner_packet"
	if administrator {
		kind = "administrator_packet"
	}
	packet.AuthoritySignature = linkIntentSignature(i, kind)
	packetRaw, e = linkJSON(packet)
	if e != nil {
		return e
	}
	read, e := linking.Read("packet", packetRaw, i.SignerPublicKey, "-")
	if e != nil {
		return linkFail("invalid", p.ID, "offer")
	}
	verification, catalog, e := pendingLinkContext(*p, now)
	if e != nil {
		return e
	}
	request, _ := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
	if administrator {
		owner, _ := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
		selection, _ := linkBytes(p.Record.SelectionPacketBase64, linking.MaxObject)
		if _, e = linking.VerifyStoredAdministratorOffer(verification, catalog, request, owner, selection, packetRaw); e != nil {
			return e
		}
		p.Record.AdministratorPacketBase64, p.Record.AdministratorOfferID = base64.StdEncoding.EncodeToString(packetRaw), read.ID
	} else {
		if _, e = linking.VerifyStoredOwnerOffer(verification, catalog, request, packetRaw); e != nil {
			return e
		}
		p.Record.OwnerPacketBase64, p.Record.OwnerOfferID = base64.StdEncoding.EncodeToString(packetRaw), read.ID
	}
	selected, e := linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: verification.Network, Epoch: verification.Epoch, KnownFeatureID: verification.KnownFeatureID, Now: now}, catalog, []linking.ProofSeed{{Kind: "packet", Body: packetRaw}})
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = queueLinkPacket(ctx, tx, p, packet.Role, packet.WriterPublicKey, packetRaw, selected); e != nil {
		return e
	}
	p.State = "offer_sent"
	if e = putLinkPending(ctx, tx, *p); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if e = linkBarrier(ctx, "host.frame.after_commit", p.ID); e != nil {
		return e
	}
	return s.publishLinkFrames(ctx, p)
}
func (s *Store) linkApprovalResult(ctx context.Context, p *linkPending, administrator bool, now time.Time, readOnly ...bool) (LinkApprovalResult, error) {
	i := p.Record.OwnerIntent.Intent
	if administrator {
		i = p.Record.AdministratorIntent.Intent
	}
	if i == nil {
		return LinkApprovalResult{}, linkFail("state_conflict", p.ID, "intent")
	}
	person := i.PersonPublicKey
	scopes, notAfter := i.Scopes, i.NotAfter
	if administrator {
		verification, catalog, e := pendingLinkContext(*p, now)
		if e != nil {
			return LinkApprovalResult{}, e
		}
		request, _ := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
		owner, _ := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
		proof, e := linking.VerifyStoredOwnerOffer(verification, catalog, request, owner)
		if e != nil {
			return LinkApprovalResult{}, e
		}
		person, scopes, notAfter = proof.PersonPublicKey, proof.Scopes, proof.NotAfter
	}
	result := LinkApprovalResult{Request: s.linkView(*p, now), Review: LinkReview{NetworkID: s.linkView(*p, now).NetworkID, PersonID: personIDOf(person), HostPublicKey: p.Record.HostPublicKey, DevicePublicKey: p.Record.DevicePublicKey, Scopes: scopes, NotAfter: notAfter, SignerPublicKey: i.SignerPublicKey, AuthorityWarning: "-"}, SigningRequests: []LinkSigningRequest{}}
	if !administrator && p.Record.AdministratorIntent.Intent != nil {
		result.Review.AuthorityWarning = "This same signer will also approve network admission after your matching selection."
	}
	if i.Approved {
		materialize := len(readOnly) == 0 || !readOnly[0]
		next, e := s.nextLinkSigning(ctx, p, administrator, now, materialize)
		if e != nil {
			return result, e
		}
		if next.ObjectType != "" {
			result.SigningRequests = append(result.SigningRequests, next)
		}
	}
	return result, nil
}

func (s *Store) LinkApproval(ctx context.Context, id string) (LinkApprovalResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkApprovalResult{}, e
	}
	if p.Role != "approver" {
		return LinkApprovalResult{}, linkFail("state_conflict", id, "approval")
	}
	administrator := p.Record.AdministratorIntent.Intent != nil && p.Record.AdministratorIntent.Intent.Approved && p.Record.SelectionPacketBase64 != "-"
	i := p.Record.OwnerIntent.Intent
	if administrator {
		i = p.Record.AdministratorIntent.Intent
	}
	if i == nil || !i.Approved {
		return LinkApprovalResult{}, linkFail("state_conflict", id, "approval")
	}
	now, e := linkNow()
	if e != nil {
		return LinkApprovalResult{}, e
	}
	return s.linkApprovalResult(ctx, &p, administrator, now, true)
}
func (s *Store) SignLinkIntent(ctx context.Context, id, objectType, signature string) (LinkApprovalResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkApprovalResult{}, e
	}
	if p.Role != "approver" {
		return LinkApprovalResult{}, linkFail("forbidden", id, "signing")
	}
	now, e := linkNow()
	if e != nil {
		return LinkApprovalResult{}, e
	}
	administrator := objectType == "admission_authorization" || objectType == "administrator_packet"
	if e = s.advanceLinkIntent(ctx, &p, administrator, objectType, signature, now); e != nil {
		return LinkApprovalResult{}, e
	}
	return s.linkApprovalResult(ctx, &p, administrator, now)
}
