package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

func requesterDecIntent(kind string) bool { return kind == "selection" || kind == "requester_commit" }
func decRequesterIntentContext(ctx context.Context, q dbQuerier, i decIntent) (decPendingRecord, dec.Descriptor, error) {
	var p decPendingRecord
	var raw, deadline string
	if !requesterDecIntent(i.Kind) || i.Record.Provider.Kind != "requester" || !dec.ValidID(i.Record.Operation, "link_") {
		return p, dec.Descriptor{}, decStorageError()
	}
	if e := q.QueryRowContext(ctx, `SELECT record,deadline FROM dec_pending WHERE request_id=?`, i.Record.Operation).Scan(&raw, &deadline); e != nil {
		return p, dec.Descriptor{}, e
	}
	if dec.ReadPrivateRecord([]byte(raw), decPendingFields, &p) != nil || !containsString(p.Roles, "requester") || p.Host != i.Record.Host || p.Device != i.Record.Device || i.Record.Provider.Signer != p.Device || i.Record.Provider.Format != "ed25519" || i.Record.Provider.Lease != "-" || i.Secret != nil || i.Record.Expires != deadline || !i.Record.Approved || i.Kind == "selection" && (!p.Selected || p.SelectionIntent != i.ID) || i.Kind == "requester_commit" && (!p.Committed || p.CommitIntent != i.ID) {
		return p, dec.Descriptor{}, decStorageError()
	}
	d, e := dec.ReadDescriptor(mustDecBytes(p.Descriptor))
	if e != nil {
		return p, d, e
	}
	if i.Network != d.NetworkID || i.Context != d.ContextID {
		return p, d, decStorageError()
	}
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return p, d, e
	}
	stage := "selection"
	if i.Kind == "requester_commit" {
		stage = "commit"
	}
	if review.Stage != stage || review.Network != i.Network || review.Context != i.Context || review.Owner != p.OwnerID || review.Person != i.Record.Person || review.Host != p.Host || review.Device != p.Device || review.Root != i.Record.Root || review.Scopes != i.Record.Scopes || review.NotAfter != i.Record.NotAfter || i.Kind == "requester_commit" && (review.Selection != p.SelectionID || review.Administrator != p.AdministratorID) {
		return p, d, decStorageError()
	}
	return p, d, nil
}
func readDecRequesterTemplate(d dec.Descriptor, i decIntent, slot decIntentTemplate) (decCeremonyTemplate, error) {
	result := decCeremonyTemplate{Slot: slot, Roles: []decCeremonyRole{}}
	if slot.Template == "-" {
		if slot.Type != "commit_packet" {
			return result, decStorageError()
		}
		for _, sig := range i.Record.Signatures {
			if sig.Slot == slot.Slot {
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
	for _, sig := range i.Record.Signatures {
		if sig.Slot == slot.Slot {
			filled[sig.Role] = sig.Signature
		}
	}
	if slot.Type == "binding_lease" {
		if i.Kind != "requester_commit" || len(filled) > 1 || filled["issuer"] != "" {
			return result, decStorageError()
		}
		statement, body, e := decFilledTemplate(d, i, slot)
		if e != nil {
			return result, e
		}
		review, e := readDecCeremonyReview(i)
		if e != nil {
			return result, e
		}
		if statement.Kind != "binding_lease" || statement.ID != review.BindingLease || statement.Lease.Subject.Host != i.Record.Host || statement.Lease.Subject.Person != i.Record.Person || statement.Lease.Operation != i.Record.Operation {
			return result, decStorageError()
		}
		hostRole := false
		for _, sig := range statement.Signatures {
			if sig.Role == "host" {
				if sig.PublicKey != i.Record.Host || sig.Format != "ed25519" {
					return result, decStorageError()
				}
				hostRole = true
				result.Roles = append(result.Roles, decCeremonyRole{"host", sig.PublicKey, sig.Format, dec.SignatureMessage(statement.ID, "host", sig.PublicKey), sig.Signature})
			} else if sig.Signature == "-" {
				return result, decStorageError()
			}
		}
		if !hostRole {
			return result, decStorageError()
		}
		result.Body, result.ID, result.Statement = body, statement.ID, statement
		return result, nil
	}
	wanted := "selection"
	if i.Kind == "requester_commit" {
		wanted = "commit"
	}
	if slot.Type != wanted+"_packet" {
		return result, decStorageError()
	}
	body, e := dec.FillPacketTemplate(d, raw, filled)
	if e != nil {
		return result, e
	}
	packet, e := dec.ReadPacketTemplate(d, body)
	if e != nil {
		return result, e
	}
	if packet.Role != wanted || packet.RequestID != i.Record.Operation || packet.Writer != i.Record.Host || packet.Signer != i.Record.Device || packet.Person != i.Record.Person || packet.Issuer != "-" || packet.AuthoritySignature != "-" {
		return result, decStorageError()
	}
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return result, e
	}
	if wanted == "selection" {
		var owner, person, host, device, contextID, at string
		for name, dst := range map[string]*string{"owner_offer_id": &owner, "person_public_key": &person, "host_public_key": &host, "device_public_key": &device, "context_id": &contextID, "selected_at": &at} {
			if json.Unmarshal(packet.Object[name], dst) != nil {
				return result, decStorageError()
			}
		}
		if packet.ID != review.Selection || owner != review.Owner || person != i.Record.Person || host != i.Record.Host || device != i.Record.Device || contextID != i.Context || at != i.Record.Created {
			return result, decStorageError()
		}
	}
	if wanted == "commit" {
		var at, encoded, bindingSignature string
		for name, dst := range map[string]*string{"committed_at": &at, "manifest_base64": &encoded, "binding_host_signature": &bindingSignature} {
			if json.Unmarshal(packet.Object[name], dst) != nil {
				return result, decStorageError()
			}
		}
		if at != i.Record.Created {
			return result, decStorageError()
		}
		manifest, e := decBytes(encoded, dec.MaxManifest)
		if e != nil {
			return result, e
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(manifest, &fields) != nil {
			return result, decStorageError()
		}
		for name, expected := range map[string]string{"context_id": i.Context, "request_id": i.Record.Operation, "owner_offer_id": review.Owner, "selection_id": review.Selection, "administrator_offer_id": review.Administrator, "root_state_id": review.Root, "person_lease_id": review.PersonLease, "host_lease_id": review.HostLease, "binding_lease_id": review.BindingLease, "device_lease_id": review.DeviceLease} {
			var actual string
			if json.Unmarshal(fields[name], &actual) != nil || actual != expected {
				return result, decStorageError()
			}
		}
		if len(i.Record.Templates) == 1 {
			if bindingSignature != "-" {
				return result, decStorageError()
			}
		} else {
			binding, e := readDecRequesterTemplate(d, i, i.Record.Templates[0])
			if e != nil {
				return result, e
			}
			if len(binding.Roles) != 1 || bindingSignature != binding.Roles[0].Signature || bindingSignature == "-" {
				return result, decStorageError()
			}
		}
	}
	for _, role := range dec.PacketSignatureRoles(packet) {
		signature := "-"
		if role.Role == "host" {
			signature = packet.HostSignature
		} else if role.Role == "device" {
			signature = packet.DeviceSignature
		} else {
			return result, decStorageError()
		}
		if role.Format != "ed25519" || role.Role == "host" && role.PublicKey != i.Record.Host || role.Role == "device" && role.PublicKey != i.Record.Device {
			return result, decStorageError()
		}
		result.Roles = append(result.Roles, decCeremonyRole{role.Role, role.PublicKey, role.Format, packet.Message, signature})
	}
	result.Body, result.ID, result.Packet = body, packet.ID, packet
	return result, nil
}
func decRequesterIntentComplete(ctx context.Context, q dbQuerier, i decIntent) (bool, error) {
	_, d, e := decRequesterIntentContext(ctx, q, i)
	if e != nil {
		return false, e
	}
	if len(i.Record.Templates) < 1 || len(i.Record.Templates) > 2 || i.Kind == "selection" && len(i.Record.Templates) != 1 {
		return false, decStorageError()
	}
	complete := true
	for index, slot := range i.Record.Templates {
		if i.Kind == "selection" && slot.Type != "selection_packet" || i.Kind == "requester_commit" && (index == len(i.Record.Templates)-1 && slot.Type != "commit_packet" || index < len(i.Record.Templates)-1 && slot.Type != "binding_lease") {
			return false, decStorageError()
		}
		template, e := readDecRequesterTemplate(d, i, slot)
		if e != nil {
			return false, e
		}
		if template.Body == nil {
			complete = false
		}
		for _, role := range template.Roles {
			if role.Signature == "-" {
				complete = false
			}
		}
	}
	return complete, nil
}
func validateDecRequesterReferences(ctx context.Context, q dbQuerier, p decPending) error {
	for _, entry := range []struct{ id, kind string }{{p.Record.SelectionIntent, "selection"}, {p.Record.CommitIntent, "requester_commit"}} {
		if entry.id == "-" {
			continue
		}
		i, e := readDecIntent(ctx, q, entry.id)
		if e != nil {
			return e
		}
		if i.Kind != entry.kind || i.Record.Operation != p.ID {
			return decStorageError()
		}
		if p.Record.Selection != "-" && entry.kind == "selection" || p.Record.Commit != "-" && entry.kind == "requester_commit" {
			last := i.Record.Templates[len(i.Record.Templates)-1]
			template, e := readDecRequesterTemplate(p.Descriptor, i, last)
			if e != nil {
				return e
			}
			raw := p.Record.Selection
			if entry.kind == "requester_commit" {
				raw = p.Record.Commit
			}
			if !i.Record.Completed || !bytes.Equal(template.Body, mustDecBytes(raw)) {
				return decStorageError()
			}
		}
	}
	return nil
}
func (s *Store) newDecRequesterIntent(p decPending, review decCeremonyReview, kind, now string, templates []decIntentTemplate) (decIntent, error) {
	id, e := decRandomID("dint_")
	if e != nil {
		return decIntent{}, e
	}
	raw, e := json.Marshal(review)
	if e != nil {
		return decIntent{}, e
	}
	return decIntent{ID: id, Network: review.Network, Context: review.Context, Kind: kind, Record: decIntentRecord{Format: 1, Operation: p.ID, Approved: true, ApprovedAt: now, Review: base64.StdEncoding.EncodeToString(raw), Provider: decIntentProvider{"requester", p.Record.Device, "ed25519", "-"}, Root: review.Root, Person: review.Person, Host: p.Record.Host, Device: p.Record.Device, Scopes: review.Scopes, NotAfter: review.NotAfter, Created: now, Expires: p.Deadline, Templates: templates, Signatures: []decIntentSignature{}, Terminal: "-", Result: "-"}}, nil
}
func (s *Store) signDecRequester(d dec.Descriptor, i *decIntent, seed []byte) error {
	if i.Record.Host != s.identity.PublicKey || len(seed) != 32 {
		return decFailure("forbidden")
	}
	device := ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(device.Public().(ed25519.PublicKey)) != i.Record.Device {
		return decFailure("signer_unavailable")
	}
	for _, slot := range i.Record.Templates {
		template, e := readDecRequesterTemplate(d, *i, slot)
		if e != nil {
			return e
		}
		for _, role := range template.Roles {
			if role.Signature != "-" {
				continue
			}
			key := s.privateKey
			if role.Role == "device" {
				key = device
			}
			if base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) != role.Key {
				return decFailure("forbidden")
			}
			if e = addDecSignature(i, decIntentSignature{slot.Slot, role.Role, base64.StdEncoding.EncodeToString(ed25519.Sign(key, role.Message))}); e != nil {
				return e
			}
		}
	}
	return nil
}
func decRequesterInput(p decPending, r decCeremonyReview) DecLinkCommit {
	return DecLinkCommit{r.Owner, r.Selection, r.Administrator, p.Record.FinalizationID, p.Descriptor.NetworkID, p.Descriptor.ContextID, r.Person, p.Record.Host, p.Record.Device, true}
}

// A step owns one transaction only. The outer driver waits at durable barriers
// after releasing every writer lock and never obtains consent from a resume.
func (s *Store) advanceDecRequester(ctx context.Context, id string) error {
	for step := 0; step < 12; step++ {
		facts, changed, e := s.advanceDecRequesterStep(ctx, id)
		if e != nil {
			return e
		}
		if e = facts.wait(ctx); e != nil {
			return e
		}
		if !changed {
			return nil
		}
	}
	return decStorageError()
}
func (s *Store) advanceDecRequesterStep(ctx context.Context, id string) (facts decCommittedFacts, changed bool, err error) {
	facts.operation = id
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return facts, false, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return facts, false, e
	}
	if p.Record.Terminal != "-" {
		return facts, false, nil
	}
	selected := p.Record.SelectionIntent
	if p.Record.Selection != "-" && decStageSealed(p, "selection") {
		selected = p.Record.CommitIntent
	}
	if selected == "-" {
		return facts, false, nil
	}
	i, e := readDecIntent(ctx, tx, selected)
	if e != nil {
		return facts, false, e
	}
	if i.Record.Host != s.identity.PublicKey {
		return facts, false, decFailure("forbidden")
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return facts, false, e
	}
	if now < i.Record.Created {
		return facts, false, decFailure("clock_rollback")
	}
	if now >= p.Deadline {
		return facts, false, decFailure("expired")
	}
	seed, e := s.decRequesterDeviceSeed(ctx, tx, p, now)
	if e != nil {
		return facts, false, e
	}
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return facts, false, e
	}
	if i.Kind == "selection" {
		offer, e := s.decSelectedOwner(ctx, tx, p, review.Owner, now)
		if e != nil {
			return facts, false, e
		}
		if p.Record.Selection == "-" {
			if e = s.signDecRequester(p.Descriptor, &i, seed); e != nil {
				return facts, false, e
			}
			template, e := readDecRequesterTemplate(p.Descriptor, i, i.Record.Templates[0])
			if e != nil {
				return facts, false, e
			}
			packet, e := dec.ReadPacket(p.Descriptor, template.Body)
			if e != nil {
				return facts, false, e
			}
			p.Record.Selection, p.Record.SelectionID = base64.StdEncoding.EncodeToString(packet.Raw), packet.ID
			if e = storeDecIntent(ctx, tx, i, false); e != nil {
				return facts, false, e
			}
			facts.add("dec.signature.after_commit")
			facts.add("dec.selection.after_commit")
		} else {
			packet, e := dec.ReadPacket(p.Descriptor, mustDecBytes(p.Record.Selection))
			if e != nil {
				return facts, false, e
			}
			components, e := decCatalogComponents(offer.Catalog)
			if e != nil {
				return facts, false, e
			}
			if e = s.queueDecStage(ctx, tx, &p, packet, components, now); e != nil {
				return facts, false, e
			}
			facts.add("dec.frame.after_commit")
		}
	} else {
		plan, e := s.decRequesterCommitPlan(ctx, tx, p, decRequesterInput(p, review), now)
		if e != nil {
			return facts, false, e
		}
		if p.Record.Commit == "-" {
			if e = s.preflightDecLinkCommit(ctx, tx, p, plan, now); e != nil {
				return facts, false, e
			}
		} else {
			activation, catalog, _, err := decPendingActivation(p)
			if err != nil {
				return facts, false, err
			}
			if p.Record.Migration != "-" {
				_, e = s.verifyDecMigrationActivation(ctx, tx, p, catalog, activation, now)
			} else {
				_, e = dec.VerifyActivation(p.Descriptor, plan.Prior, catalog.Raw, activation, decExpectedLink(p, plan), now)
			}
			if e != nil {
				return facts, false, e
			}
		}
		last := len(i.Record.Templates) - 1
		if i.Record.Templates[last].Template == "-" {
			if last > 0 {
				binding, e := readDecRequesterTemplate(p.Descriptor, i, i.Record.Templates[0])
				if e != nil {
					return facts, false, e
				}
				if binding.Roles[0].Signature == "-" {
					if e = s.signDecRequester(p.Descriptor, &i, seed); e != nil {
						return facts, false, e
					}
					if e = storeDecIntent(ctx, tx, i, false); e != nil {
						return facts, false, e
					}
					facts.add("dec.signature.after_commit")
					goto saved
				}
			}
			if e = materializeDecRequesterCommit(p, plan, &i); e != nil {
				return facts, false, e
			}
			if e = storeDecIntent(ctx, tx, i, false); e != nil {
				return facts, false, e
			}
			facts.add("dec.intent.after_commit")
		} else if p.Record.Commit == "-" {
			if e = s.signDecRequester(p.Descriptor, &i, seed); e != nil {
				return facts, false, e
			}
			template, e := readDecRequesterTemplate(p.Descriptor, i, i.Record.Templates[last])
			if e != nil {
				return facts, false, e
			}
			commit, e := dec.ReadPacket(p.Descriptor, template.Body)
			if e != nil {
				return facts, false, e
			}
			if e = s.retainDecRequesterCommit(ctx, tx, &p, plan, commit, now); e != nil {
				return facts, false, e
			}
			if e = storeDecIntent(ctx, tx, i, false); e != nil {
				return facts, false, e
			}
			facts.add("dec.signature.after_commit")
			facts.add("dec.requester_commit.after_commit")
		} else if !decStageSealed(p, "commit") {
			commit, e := dec.ReadPacket(p.Descriptor, mustDecBytes(p.Record.Commit))
			if e != nil {
				return facts, false, e
			}
			catalog, e := decPendingCatalog(p, p.Descriptor)
			if e != nil {
				return facts, false, e
			}
			components, e := decCommitComponents(plan.Offer.Catalog, catalog)
			if e != nil {
				return facts, false, e
			}
			if e = s.queueDecStage(ctx, tx, &p, commit, components, now); e != nil {
				return facts, false, e
			}
			facts.add("dec.frame.after_commit")
		} else {
			return facts, false, nil
		}
	}
saved:
	if e = putDecPending(ctx, tx, p); e != nil {
		return facts, false, e
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, i.Network, string(clock)); e != nil {
		return facts, false, e
	}
	return facts, true, tx.Commit()
}
func decStageSealed(p decPending, role string) bool {
	for _, frame := range p.Record.Outbound {
		if frame.Role == role && frame.Writer == p.Record.Host {
			return true
		}
	}
	return false
}
func materializeDecRequesterCommit(p decPending, plan decRequesterCommitPlan, i *decIntent) error {
	binding := plan.Prefix.Binding
	hostSignature := "-"
	if !plan.Prefix.ReusedBinding {
		template, e := readDecRequesterTemplate(p.Descriptor, *i, i.Record.Templates[0])
		if e != nil {
			return e
		}
		if len(template.Roles) != 1 || template.Roles[0].Signature == "-" {
			return decStorageError()
		}
		hostSignature = template.Roles[0].Signature
		binding, e = dec.ReadStatement(p.Descriptor, template.Body)
		if e != nil {
			return e
		}
	}
	manifest, _, e := dec.CommitManifest(p.Descriptor, plan.Offer.Catalog, p.Request, plan.Offer.Owner, plan.Selection, plan.Administrator, plan.Finalization, binding)
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(struct {
		Manifest string `json:"manifest_base64"`
		Binding  string `json:"binding_host_signature"`
		At       string `json:"committed_at"`
	}{base64.StdEncoding.EncodeToString(manifest), hostSignature, i.Record.Created})
	raw, e := dec.PacketTemplate(p.Descriptor, p.Descriptor.ContextID, p.ID, "commit", p.Record.Host, p.Record.Device, i.Record.Person, "-", "-", payload)
	if e != nil {
		return e
	}
	i.Record.Templates[len(i.Record.Templates)-1].Template = base64.StdEncoding.EncodeToString(raw)
	return nil
}
func (s *Store) retainDecRequesterCommit(ctx context.Context, q dbQuerier, p *decPending, plan decRequesterCommitPlan, commit *dec.Packet, now string) error {
	activation, e := decActivationBody(*p, plan.Offer.Owner, plan.Selection, plan.Administrator, plan.Finalization, commit)
	if e != nil {
		return e
	}
	// The manifest's exact completed B alias was fixed before packet signing.
	catalog := plan.Offer.Catalog
	var body struct {
		Manifest string `json:"manifest_base64"`
	}
	if json.Unmarshal(commit.Payload, &body) != nil {
		return decStorageError()
	}
	var binding *dec.Statement = plan.Prefix.Binding
	if !plan.Prefix.ReusedBinding {
		var payload struct {
			Binding string `json:"binding_host_signature"`
		}
		if json.Unmarshal(commit.Payload, &payload) != nil {
			return decStorageError()
		}
		raw, e := dec.FillStatementTemplate(p.Descriptor, binding.Raw, map[string]string{"host": payload.Binding})
		if e != nil {
			return e
		}
		binding, e = dec.ReadStatement(p.Descriptor, raw)
		if e != nil {
			return e
		}
	}
	_, catalog, e = dec.CommitManifest(p.Descriptor, catalog, p.Request, plan.Offer.Owner, plan.Selection, plan.Administrator, plan.Finalization, binding)
	if e != nil {
		return e
	}
	catalog, e = decCatalogWithActivation(p.Descriptor, catalog, activation)
	if e != nil {
		return e
	}
	manifestID, activationID := "-", "-"
	if p.Record.Migration != "-" {
		parsed, e := s.verifyDecMigrationActivation(ctx, q, *p, catalog, activation, now)
		if e != nil {
			return e
		}
		manifestID, activationID = parsed.ManifestID, parsed.ID
	} else {
		evidence, e := dec.VerifyActivation(p.Descriptor, plan.Prior, catalog.Raw, activation, decExpectedLink(*p, plan), now)
		if e != nil {
			return e
		}
		manifestID, activationID = evidence.ManifestID, evidence.ActivationID
	}
	p.Record.Commit = base64.StdEncoding.EncodeToString(commit.Raw)
	p.Record.Catalog = base64.StdEncoding.EncodeToString(catalog.Raw)
	p.Record.ManifestID, p.Record.ActivationID = manifestID, activationID
	return nil
}
