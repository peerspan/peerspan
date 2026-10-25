package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type LinkSignerView struct {
	NetworkID       string `json:"network_id"`
	PersonPublicKey string `json:"person_public_key"`
	DevicePublicKey string `json:"device_public_key"`
	CertificateID   string `json:"certificate_id"`
	Scopes          uint64 `json:"scopes"`
	NotAfter        string `json:"not_after"`
}
type linkDeviceProvider struct {
	View LinkSignerView
	Path linking.SigningPath
	Key  ed25519.PrivateKey
}

func (s *Store) linkDeviceProvider(ctx context.Context, q dbQuerier, p *linkProjection, certificate string, required uint64, now time.Time) (linkDeviceProvider, error) {
	var selected LinkSignerView
	selected.NetworkID = p.Network.Facts.NetworkID
	e := q.QueryRowContext(ctx, `SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?`, selected.NetworkID).Scan(&selected.PersonPublicKey, &selected.DevicePublicKey, &selected.CertificateID)
	if errors.Is(e, sql.ErrNoRows) {
		return linkDeviceProvider{}, linkFail("not_found", "-", "signer")
	}
	if e != nil {
		return linkDeviceProvider{}, e
	}
	if !linkPublicKey(selected.PersonPublicKey) || !linkPublicKey(selected.DevicePublicKey) || !linkID(selected.CertificateID, "dc_") {
		return linkDeviceProvider{}, linkFail("state_conflict", "-", "signer")
	}
	if certificate != "auto" {
		if !linkID(certificate, "dc_") {
			return linkDeviceProvider{}, linkFail("invalid", "-", "signer")
		}
		body, ok := p.Network.Facts.State.Certificates[certificate]
		if !ok {
			return linkDeviceProvider{}, linkFail("proof_required", "-", "signer", certificate)
		}
		var cert struct {
			PersonPublicKey string `json:"person_public_key"`
			DevicePublicKey string `json:"device_public_key"`
		}
		if json.Unmarshal(body, &cert) != nil || cert.PersonPublicKey != selected.PersonPublicKey {
			return linkDeviceProvider{}, linkFail("forbidden", "-", "signer")
		}
		selected.CertificateID, selected.DevicePublicKey = certificate, cert.DevicePublicKey
	}
	if p.Network.Facts.State.Bindings[s.identity.PublicKey] != selected.PersonPublicKey {
		return linkDeviceProvider{}, linkFail("forbidden", "-", "signer")
	}
	key, e := loadLinkDevice(ctx, q, selected.DevicePublicKey)
	if e != nil {
		return linkDeviceProvider{}, e
	}
	if required == 0 {
		body, ok := p.Network.Facts.State.Certificates[selected.CertificateID]
		if !ok {
			return linkDeviceProvider{}, linkFail("proof_required", "-", "signer", selected.CertificateID)
		}
		var cert struct {
			Scopes uint64 `json:"scopes"`
		}
		if json.Unmarshal(body, &cert) != nil || cert.Scopes == 0 || cert.Scopes > 15 {
			return linkDeviceProvider{}, linkFail("state_conflict", "-", "signer")
		}
		for _, bit := range []uint64{1, 2, 4, 8} {
			if cert.Scopes&bit != 0 {
				required = bit
				break
			}
		}
	}
	path, e := linking.EvaluatePath(p.Network.Facts.State, selected.PersonPublicKey, selected.CertificateID, required, now)
	if e != nil {
		return linkDeviceProvider{}, e
	}
	if path.SignerPublicKey != selected.DevicePublicKey {
		return linkDeviceProvider{}, linkFail("state_conflict", "-", "signer")
	}
	selected.Scopes, selected.NotAfter = path.Scopes, path.NotAfter
	return linkDeviceProvider{selected, path, key}, nil
}
func (s *Store) LinkSigner(ctx context.Context, network string) (LinkSignerView, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, network)
	if e != nil {
		return LinkSignerView{}, e
	}
	// Distinguish absent selection before loading authority. A selected broken
	// path must stay a repair error and cannot trigger identity replacement.
	var exists int
	if e = s.db.QueryRowContext(ctx, `SELECT 1 FROM link_signers WHERE network_id=?`, network).Scan(&exists); errors.Is(e, sql.ErrNoRows) {
		return LinkSignerView{}, linkFail("not_found", "-", "signer")
	} else if e != nil {
		return LinkSignerView{}, e
	}
	now, e := linkNow()
	if e != nil {
		return LinkSignerView{}, e
	}
	p, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return LinkSignerView{}, e
	}
	provider, e := s.linkDeviceProvider(ctx, s.db, p, "auto", 0, now)
	return provider.View, e
}

type LinkActionRequest struct {
	Kind          string `json:"kind"`
	PayloadBase64 string `json:"payload_base64"`
	CertificateID string `json:"certificate_id"`
}
type LinkActionResult struct {
	RecordID     string          `json:"record_id"`
	ProofID      string          `json:"proof_id"`
	RecordBase64 string          `json:"record_base64"`
	Catalog      json.RawMessage `json:"catalog"`
	Committed    bool            `json:"committed"`
}

func linkActionScope(kind string) uint64 {
	switch kind {
	case "peerspan-policy-v1", "peerspan-policy-v2", "policy_claim":
		return 1
	case "peerspan-host-bind-v1", "peerspan-host-unbind-v1":
		return 2
	case "device_revocation":
		return 4
	case "checkpoint":
		// The retention verifier computes the union of referenced scopes.
		return 1
	case "invite_feature":
		return 8
	case "peerspan-host-admit-v1", "peerspan-person-admit-v1", "peerspan-person-remove-v1", "peerspan-revoke-host-v1", "peerspan-revoke-invite-v1", "peerspan-invite-v1", "peerspan-person-invite-v1", "peerspan-group-v1":
		return 8
	}
	return 0
}
func catalogWithLinkObject(network, kind string, body []byte) ([]byte, error) {
	return linkJSON(linkCatalog{1, network, []linkCatalogObject{{linkProofID(kind, body), kind, base64.StdEncoding.EncodeToString(body)}}})
}
func (s *Store) LinkAction(ctx context.Context, network string, input LinkActionRequest) (LinkActionResult, error) {
	return s.linkAction(ctx, network, input, nil)
}

type linkPolicyReapply struct {
	Version     uint64
	MessageHash string
	Records     []policyEditRecord
}

func (s *Store) linkAction(ctx context.Context, network string, input LinkActionRequest, reapply *linkPolicyReapply) (LinkActionResult, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	var result LinkActionResult
	required := linkActionScope(input.Kind)
	if required == 0 {
		return result, linkFail("invalid", "-", "action")
	}
	payload, e := linkBytes(input.PayloadBase64, linking.MaxPayload)
	if e != nil {
		return result, e
	}
	claimName := ""
	if input.Kind == "policy_claim" {
		claimName, payload, e = decodePolicyClaimIntent(payload)
		if e != nil {
			return result, e
		}
		input.Kind = "peerspan-policy-v2"
		input.PayloadBase64 = base64.StdEncoding.EncodeToString(payload)
	}
	if input.Kind != "device_revocation" && input.Kind != "checkpoint" && input.Kind != "invite_feature" && linking.ValidateActionPayload(input.Kind, payload) != nil {
		return result, linkFail("invalid", "-", "action")
	}
	n, e := s.Network(ctx, network)
	if e != nil {
		return result, e
	}
	n, e = s.syncLinkNetworkLocked(ctx, n, s.ownCandidates(ctx, n.CoordinatorAddress))
	if e != nil {
		return result, e
	}
	now, e := linkNow()
	if e != nil {
		return result, e
	}
	p, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return result, e
	}
	if input.Kind == "checkpoint" {
		required = 0
	}
	provider, e := s.linkDeviceProvider(ctx, s.db, p, input.CertificateID, required, now)
	if e != nil {
		return result, e
	}
	if claimName == "" {
		if known, ok, err := knownLinkAction(p, provider.View, input, payload, now); err != nil || ok {
			return known, err
		}
	}
	if e = s.linkActionPreconditions(p, provider.View.PersonPublicKey, input.Kind, payload, now); e != nil {
		return result, e
	}
	if input.Kind == "invite_feature" {
		return signLinkInviteFeature(p, provider, payload, now)
	}
	var editPolicy *membership.Policy
	var reservation *policyEditRecord
	if input.Kind == "peerspan-policy-v1" || input.Kind == "peerspan-policy-v2" {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(payload, &fields)
		fields["signature"] = json.RawMessage(`"-"`)
		body, err := linkJSON(fields)
		if err != nil {
			return result, err
		}
		var policy membership.Policy
		if json.Unmarshal(body, &policy) != nil {
			return result, linkFail("invalid", "-", "policy")
		}
		if claimName != "" && !capabilityPolicyClaim(policy, s.identity.ID, claimName) {
			return result, linkFail("invalid", "-", "capability_claim")
		}
		editPolicy = &policy
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return result, err
		}
		var prior *membership.Policy
		if current, exists := p.Policies[provider.View.PersonPublicKey]; exists {
			prior = &current
		}
		if reapply != nil {
			matches := false
			for _, selected := range p.Access.Policies {
				if selected.PersonPublicKey == policy.PersonPublicKey && selected.Active && selected.Version == reapply.Version && selected.MessageHash == reapply.MessageHash {
					matches = true
				}
			}
			if !matches {
				e = errEditConflict
			}
		} else {
			reservation, e = s.checkEdit(ctx, tx, network, personIDOf(policy.PersonPublicKey), prior, policy, now)
		}
		_ = tx.Rollback()
		if e != nil {
			return result, e
		}
	}
	actionContext := linking.ActionContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, PersonPublicKey: provider.View.PersonPublicKey, CertificateID: provider.View.CertificateID, Now: now}
	intent := payload
	actionKind := "device_revocation"
	if input.Kind == "checkpoint" {
		actionKind = "checkpoint"
		var checkpoint struct {
			PersonPublicKey     string `json:"person_public_key"`
			IssuerCertificateID string `json:"issuer_certificate_id"`
		}
		if json.Unmarshal(payload, &checkpoint) != nil || checkpoint.PersonPublicKey != provider.View.PersonPublicKey || checkpoint.IssuerCertificateID != provider.View.CertificateID {
			return result, linkFail("invalid", "-", "checkpoint")
		}
		if e = linking.VerifyStoredCheckpointIntent(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, payload); e != nil {
			return result, e
		}
	} else if input.Kind != "device_revocation" {
		actionKind = "person_record"
		intent, e = linkJSON(map[string]any{"kind": input.Kind, "payload_base64": input.PayloadBase64})
		if e != nil {
			return result, e
		}
	}
	if actionKind != "checkpoint" {
		if _, e = linking.VerifyStoredActionIntent(actionContext, actionKind, p.Catalog, intent); e != nil {
			return result, e
		}
	}
	var record []byte
	if actionKind == "person_record" {
		message := linkMessage("peerspan-person-authorization-v1", input.Kind, network, strconv.FormatUint(p.Network.Epoch, 10), "-", provider.View.PersonPublicKey, provider.View.CertificateID, linkHash(payload))
		signature, e := membership.SignSSHSIG(membership.KeySigner{Key: provider.Key}, message)
		if e != nil {
			return result, e
		}
		hostSignature := "-"
		if input.Kind == "peerspan-host-bind-v1" {
			hostSignature = membership.EncodeKey(ed25519.Sign(s.privateKey, linkMessage("peerspan-binding-consent-v1", linkHash(message))))
		}
		record, e = linkJSON(map[string]any{"format": 1, "kind": input.Kind, "network_id": network, "epoch": p.Network.Epoch, "operation_id": "-", "person_public_key": provider.View.PersonPublicKey, "certificate_id": provider.View.CertificateID, "payload_base64": input.PayloadBase64, "signature": signature, "host_signature": hostSignature})
		if e != nil {
			return result, e
		}
	} else {
		var fields map[string]json.RawMessage
		if json.Unmarshal(payload, &fields) != nil {
			return result, linkFail("invalid", "-", "action")
		}
		get := func(k string) string { var v string; _ = json.Unmarshal(fields[k], &v); return v }
		message := linkMessage("peerspan-device-revoke-v1", get("network_id"), get("person_public_key"), get("target_device_public_key"), get("target_certificate_id"), get("issuer_certificate_id"), get("revoked_at"))
		if actionKind == "checkpoint" {
			var records []string
			if json.Unmarshal(fields["records"], &records) != nil {
				return result, linkFail("invalid", "-", "checkpoint")
			}
			parts := []string{"peerspan-person-checkpoint-v1", get("network_id"), get("person_public_key"), get("issuer_certificate_id"), get("issued_at"), strconv.Itoa(len(records))}
			message = linkMessage(append(parts, records...)...)
		}
		signature, e := membership.SignSSHSIG(membership.KeySigner{Key: provider.Key}, message)
		if e != nil {
			return result, e
		}
		fields["signature"], _ = json.Marshal(signature)
		record, e = linkJSON(fields)
		if e != nil {
			return result, e
		}
	}
	recordID := "-"
	if actionKind == "checkpoint" {
		e = linking.VerifyStoredCheckpoint(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, record)
	} else {
		var authority linking.ActionAuthority
		authority, e = linking.VerifyStoredActionAuthority(actionContext, actionKind, p.Catalog, record)
		recordID = authority.RecordID
	}
	if e != nil {
		return result, e
	}
	selected, e := linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, []linking.ProofSeed{{Kind: actionKind, Body: record}})
	if e != nil {
		return result, e
	}
	result = LinkActionResult{recordID, linkProofID(actionKind, record), base64.StdEncoding.EncodeToString(record), selected, false}
	if claimName != "" {
		result.Catalog, e = addClaimPolicyCatalog(network, selected, record)
		if e != nil {
			return LinkActionResult{}, e
		}
		return result, nil
	}
	if input.Kind == "peerspan-invite-v1" || input.Kind == "peerspan-person-invite-v1" {
		return result, nil
	}
	entry, e := catalogWithLinkObject(network, actionKind, record)
	if e != nil {
		return result, e
	}
	publication, e := mergeLinkCatalog(network, selected, entry)
	if e != nil {
		return result, e
	}
	body, e := linkJSON(map[string]any{"catalog": json.RawMessage(publication)})
	if e != nil {
		return result, e
	}
	if len(body) > 1<<20 {
		return result, linkFail("quota_exceeded", "-", "action")
	}
	restrictive := linkRestrictiveProof(actionKind, record)
	if restrictive {
		union, err := mergeLinkCatalog(network, p.Catalog, entry)
		if err != nil {
			return LinkActionResult{}, err
		}
		projection, err := s.verifyLinkProjection(ctx, s.db, n, union, now)
		if err != nil {
			return LinkActionResult{}, err
		}
		fact := linking.CatalogFactContext{Network: projection.Descriptor, Epoch: projection.Network.Epoch, KnownFeatureID: projection.Network.Facts.FeatureID, Now: now}
		if err = linking.VerifyStoredCatalogAdditions(fact, p.Catalog, union); err != nil {
			return LinkActionResult{}, err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return LinkActionResult{}, err
		}
		defer tx.Rollback()
		members, err := readLinkMembers(ctx, tx, n.ID)
		if err != nil {
			return LinkActionResult{}, err
		}
		members = projectedLinkMembers(projection, members, linkTime(now))
		if err = s.applyLinkProjection(ctx, tx, &n, projection, members, linkTime(now)); err != nil {
			return LinkActionResult{}, err
		}
		if err = putLinkRestrictionMarker(ctx, tx, network, result.ProofID); err != nil {
			return LinkActionResult{}, err
		}
		if err = tx.Commit(); err != nil {
			return LinkActionResult{}, err
		}
		s.mapApplied(n.ID, members)
	}
	raw, e := s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+network+"/statements", body)
	if e != nil {
		return LinkActionResult{}, e
	}
	hook := func(ctx context.Context, tx *sql.Tx) error {
		if restrictive {
			if e := clearLinkRestrictionMarkers(ctx, tx, network, []string{result.ProofID}); e != nil {
				return e
			}
		}
		if reservation != nil {
			return s.recordEdit(ctx, tx, network, personIDOf(editPolicy.PersonPublicKey), *reservation, *editPolicy, now)
		}
		if reapply != nil {
			for _, record := range reapply.Records {
				if e := putEdit(ctx, tx, network, personIDOf(editPolicy.PersonPublicKey), record); e != nil {
					return e
				}
			}
			return s.editsChanged(ctx, tx, network, *editPolicy, now)
		}
		return nil
	}
	if _, e = s.applyLinkMapWithHook(ctx, n, raw, hook); e != nil {
		return LinkActionResult{}, e
	}
	result.Catalog = json.RawMessage(publication)
	result.Committed = true
	return result, nil
}

// A fresh sync has already established that the coordinator retained these
// exact public bytes. Repeating an identical typed intent does not reserve a
// new edit, advance a maximum or ask the private signer for another signature.
func knownLinkAction(p *linkProjection, signer LinkSignerView, input LinkActionRequest, payload []byte, now time.Time) (LinkActionResult, bool, error) {
	kind := "person_record"
	if input.Kind == "checkpoint" || input.Kind == "device_revocation" {
		kind = input.Kind
	}
	for _, object := range p.Objects.Objects {
		if object.Kind != kind {
			continue
		}
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return LinkActionResult{}, false, e
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			return LinkActionResult{}, false, linkFail("state_conflict", "-", "catalog")
		}
		text := func(field string) string { var value string; _ = json.Unmarshal(fields[field], &value); return value }
		if text("person_public_key") != signer.PersonPublicKey {
			continue
		}
		if kind == "person_record" {
			var epoch uint64
			_ = json.Unmarshal(fields["epoch"], &epoch)
			if text("kind") != input.Kind || text("operation_id") != "-" || text("certificate_id") != signer.CertificateID || text("payload_base64") != input.PayloadBase64 || epoch != p.Network.Epoch {
				continue
			}
		} else {
			if text("issuer_certificate_id") != signer.CertificateID {
				continue
			}
			delete(fields, "signature")
			unsigned, e := linkJSON(fields)
			if e != nil {
				return LinkActionResult{}, false, e
			}
			var proposed map[string]json.RawMessage
			if json.Unmarshal(payload, &proposed) != nil {
				return LinkActionResult{}, false, linkFail("invalid", "-", "action")
			}
			canonical, e := linkJSON(proposed)
			if e != nil {
				return LinkActionResult{}, false, e
			}
			if string(unsigned) != string(canonical) {
				continue
			}
		}
		read, e := linking.Read(kind, body, signer.DevicePublicKey, "-")
		if e != nil {
			return LinkActionResult{}, false, e
		}
		catalog, e := linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, []linking.ProofSeed{{Kind: kind, Body: body}})
		if e != nil {
			return LinkActionResult{}, false, e
		}
		entry, e := catalogWithLinkObject(p.Network.Facts.NetworkID, kind, body)
		if e != nil {
			return LinkActionResult{}, false, e
		}
		catalog, e = mergeLinkCatalog(p.Network.Facts.NetworkID, catalog, entry)
		if e != nil {
			return LinkActionResult{}, false, e
		}
		return LinkActionResult{read.ID, object.ID, object.BodyBase64, catalog, true}, true, nil
	}
	return LinkActionResult{}, false, nil
}

func (s *Store) linkActionPreconditions(p *linkProjection, person, kind string, raw []byte, now time.Time) error {
	var payload struct {
		NetworkID       string `json:"network_id"`
		PersonPublicKey string `json:"person_public_key"`
		HostPublicKey   string `json:"host_public_key"`
		Name            string `json:"name"`
		Version         uint64 `json:"version"`
		Member          string `json:"member"`
		ExpiresAt       string `json:"invite_expires_at"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.NetworkID != p.Network.Facts.NetworkID {
		return linkFail("invalid", "-", "action")
	}
	if kind == "peerspan-host-bind-v1" && payload.HostPublicKey != s.identity.PublicKey {
		return linkFail("forbidden", "-", "host_consent")
	}
	switch kind {
	case "peerspan-host-bind-v1":
		if !p.Network.Facts.State.Hosts[payload.HostPublicKey] || !p.Network.Facts.State.Persons[person].Admitted {
			return linkFail("forbidden", "-", "binding")
		}
		if old := p.Network.Facts.State.Bindings[payload.HostPublicKey]; old != "" && old != "-" && old != person {
			return linkFail("state_conflict", "-", "binding")
		}
	case "peerspan-host-unbind-v1":
		if p.Network.Facts.State.Bindings[payload.HostPublicKey] != person {
			return linkFail("forbidden", "-", "binding")
		}
	case "peerspan-person-remove-v1":
		if p.Network.Facts.State.Persons[payload.PersonPublicKey].Administrator {
			return linkFail("state_conflict", "-", "administrator_role")
		}
	case "peerspan-person-admit-v1":
		for key, state := range p.Network.Facts.State.Persons {
			if state.Admitted && key != payload.PersonPublicKey && membership.LabelsConflict(p.Network.Facts.PersonLabels[key], payload.Member) {
				return linkFail("state_conflict", "-", "person_label")
			}
		}
		if old := p.Network.Facts.PersonLabels[payload.PersonPublicKey]; p.Network.Facts.State.Persons[payload.PersonPublicKey].Admitted && old != payload.Member {
			return linkFail("state_conflict", "-", "person_label")
		}
	case "peerspan-host-admit-v1":
		if old := p.Network.Facts.HostLabels[payload.HostPublicKey]; p.Network.Facts.State.Hosts[payload.HostPublicKey] && old != payload.Member {
			return linkFail("state_conflict", "-", "host_label")
		}
	case "peerspan-invite-v1", "peerspan-person-invite-v1":
		expires, e := linkStamp(payload.ExpiresAt)
		if e != nil || !expires.After(now) || expires.After(now.Add(30*24*time.Hour)) {
			return linkFail("invalid", "-", "invite")
		}
	}
	if kind == "peerspan-policy-v1" || kind == "peerspan-policy-v2" {
		if payload.PersonPublicKey != person {
			return linkFail("forbidden", "-", "action")
		}
		var policyFields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &policyFields)
		policyFields["signature"] = json.RawMessage(`"-"`)
		body, _ := linkJSON(policyFields)
		var policy membership.Policy
		if json.Unmarshal(body, &policy) != nil || membership.CheckPolicy(p.Network.Facts.NetworkID, policy) != nil || !membership.PolicyActive(policy, now) {
			return linkFail("invalid", "-", "action")
		}
		for _, selected := range p.Access.Policies {
			if selected.PersonPublicKey == person && selected.Version == ^uint64(0) {
				return membership.ErrAccessVersionExhausted
			}
			if selected.PersonPublicKey == person && payload.Version <= selected.Version {
				return linkFail("state_conflict", "-", "version")
			}
		}
	}
	if kind == "peerspan-group-v1" {
		for _, selected := range p.Access.Groups {
			if selected.Name == payload.Name && selected.Version == ^uint64(0) {
				return membership.ErrAccessVersionExhausted
			}
			if selected.Name == payload.Name && payload.Version <= selected.Version {
				return linkFail("state_conflict", "-", "version")
			}
		}
	}
	return nil
}
