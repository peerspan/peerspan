package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type DecLinkCreate struct {
	Mode       string             `json:"mode"`
	Network    string             `json:"network_id"`
	Person     string             `json:"person_public_key"`
	Migration  string             `json:"migration_proposal_id"`
	Invitation string             `json:"contact_invitation"`
	Helpers    []dec.ContactRelay `json:"helpers"`
}
type DecLinkView struct {
	Request       string   `json:"request_id"`
	Role          string   `json:"role"`
	Mode          string   `json:"mode"`
	State         string   `json:"state"`
	Network       string   `json:"network_id"`
	Context       string   `json:"context_id"`
	Migration     string   `json:"migration_proposal_id"`
	Person        string   `json:"person_public_key"`
	Host          string   `json:"host_public_key"`
	Device        string   `json:"device_public_key"`
	Created       string   `json:"created_at"`
	Expires       string   `json:"expires_at"`
	RequestPacket string   `json:"request_packet_id"`
	Owner         string   `json:"owner_offer_id"`
	Selection     string   `json:"selection_id"`
	Administrator string   `json:"administrator_offer_id"`
	Finalization  string   `json:"owner_finalization_id"`
	Manifest      string   `json:"manifest_id"`
	Activation    string   `json:"activation_id"`
	Outcome       string   `json:"outcome_id"`
	Selected      bool     `json:"selection_approved"`
	Committed     bool     `json:"commit_approved"`
	Completed     []string `json:"completed"`
	Attention     []string `json:"attention"`
	Next          []string `json:"next"`
}

func decLinkView(p decPending, now string) DecLinkView {
	r := p.Record
	v := DecLinkView{Request: p.ID, Role: "approver", Mode: r.Mode, State: "pending", Network: r.Network, Context: r.Context, Migration: r.Migration, Person: r.Person, Host: r.Host, Device: r.Device, Created: p.Terms.Created, Expires: p.Deadline, RequestPacket: p.Request.ID, Owner: r.OwnerID, Selection: r.SelectionID, Administrator: r.AdministratorID, Finalization: r.FinalizationID, Manifest: r.ManifestID, Activation: r.ActivationID, Outcome: "-", Selected: r.Selected, Committed: r.Committed, Completed: []string{"request_created"}, Attention: []string{}, Next: []string{"approve_on_existing_machine"}}
	if containsString(r.Roles, "requester") {
		v.Role = "requester"
	}
	if p.Descriptor.ContextID != "" {
		v.Network = p.Descriptor.NetworkID
		v.Context = p.Descriptor.ContextID
	}
	if r.Owner != "-" {
		raw, _ := decBytes(r.Owner, dec.MaxObject)
		if owner, e := dec.ReadPacket(p.Descriptor, raw); e == nil {
			v.Person = owner.Person
		}
		v.Completed = append(v.Completed, "owner_offered")
		v.State = "needs_selection"
		v.Next = []string{"select_owner_offer"}
	}
	if r.Selection != "-" {
		v.Completed = append(v.Completed, "owner_selected")
		v.State = "needs_administrator"
		v.Next = []string{"admit_on_administrator_machine"}
	}
	if r.Administrator != "-" {
		v.Completed = append(v.Completed, "administrator_offered")
		v.State = "needs_owner_finalization"
		v.Next = []string{"finalize_on_owner_machine"}
	}
	if r.Finalization != "-" {
		v.Completed = append(v.Completed, "owner_finalized")
		v.State = "needs_commit"
		v.Next = []string{"review_and_commit"}
	}
	if r.Selected && r.Selection == "-" || r.Committed && r.Commit == "-" {
		v.State = "pending"
		v.Attention = []string{"signing_pending"}
		v.Next = []string{"resume"}
	}
	if r.Commit != "-" {
		v.Completed = append(v.Completed, "commit_persisted")
		v.State = "finalizing"
		v.Next = []string{"resume"}
		v.Attention = []string{"outcome_pending"}
	}
	if r.Outcome != "-" {
		raw, _ := decBytes(r.Outcome, dec.MaxObject)
		if packet, e := dec.ReadPacket(p.Descriptor, raw); e == nil {
			v.Outcome = packet.ID
		}
	}
	switch r.Terminal {
	case "applied":
		v.State = "linked"
		v.Completed = append(v.Completed, "locally_applied")
		v.Next = []string{}
		v.Attention = []string{}
	case "migration_prepared":
		v.State = "migration_prepared"
		v.Next = []string{"resume_whole_migration"}
		v.Attention = []string{"migration_pending"}
	case "migration_adopted":
		v.State = "migration_adopted"
		v.Next = []string{}
		v.Attention = []string{}
	case "cancelled", "expired":
		v.State = r.Terminal
		v.Next = []string{"create_fresh_request"}
	case "stopped":
		v.State = "blocked"
		v.Next = []string{"repair_same_identity"}
	}
	if now < p.Terms.Created {
		v.State = "blocked"
		v.Attention = []string{"clock_rollback"}
		v.Next = []string{"correct_local_utc_or_wait"}
	}
	if r.Terminal == "-" && r.Commit == "-" && now >= p.Deadline {
		v.State = "expired"
		v.Next = []string{"create_fresh_request"}
	}
	if now < p.Deadline && !decPendingResolved(r.Terminal) {
		pending := false
		for _, frame := range r.Outbound {
			for _, carrier := range r.Carriers {
				ack := decFrameAck{carrier.Address, carrier.Key}
				found := false
				for _, saved := range frame.Acknowledged {
					if saved == ack {
						found = true
						break
					}
				}
				if !found {
					pending = true
				}
			}
		}
		if pending {
			v.Attention = append(v.Attention, "delivery_pending")
			decAddNext(&v, "resume")
		}
	}
	return v
}

func decRequestResponse(p decPending, now string, display bool) (json.RawMessage, error) {
	view := decLinkView(p, now)
	if !display || p.Record.Terminal != "-" || now >= p.Deadline || len(p.Secret) != 16 || !containsString(p.Record.Roles, "requester") {
		return json.Marshal(view)
	}
	contacts := []json.RawMessage{}
	// Exact requester contacts are part of its already sealed request frame.
	for _, entry := range p.Record.Outbound {
		if entry.Role != "request" {
			continue
		}
		if f := p.Frames[decFrameKey(entry.Role, entry.Writer, entry.ID)]; f != nil {
			plain, _, e := dec.OpenFrame(p.Descriptor, p.Secret, f.Raw)
			if e != nil {
				return nil, e
			}
			contacts = plain.Contacts
			break
		}
	}
	helpers := []dec.ContactRelay{}
	for _, c := range p.Record.Carriers {
		if c.Kind == "helper" {
			helpers = append(helpers, dec.ContactRelay{Address: c.Address, PublicKey: c.Key})
		}
	}
	code, e := dec.PairingCode(p.Request.Raw, p.Secret, contacts, helpers)
	if e != nil {
		return nil, e
	}
	return json.Marshal(struct {
		DecLinkView
		Code string `json:"display_code"`
	}{view, code})
}

func retireDecPending(ctx context.Context, tx *sql.Tx, p *decPending, now string) error {
	if now < p.Deadline || p.Record.Terminal == "migration_prepared" {
		return nil
	}
	if p.Record.Terminal == "-" && p.Record.Commit == "-" {
		p.Record.Terminal = "expired"
	}
	p.Secret = nil
	p.TerminalCap = nil
	p.Frames = map[string]*dec.Frame{}
	p.Record.Outbound = []decOutboundFrame{}
	if _, e := tx.ExecContext(ctx, `DELETE FROM dec_frames WHERE request_id=?`, p.ID); e != nil {
		return e
	}
	return putDecPending(ctx, tx, *p)
}

func (s *Store) CreateDecentralizedLink(ctx context.Context, input DecLinkCreate) (raw json.RawMessage, reused bool, err error) {
	if input.Migration != "-" {
		return nil, false, decFailure("invalid")
	}
	return s.createDecentralizedLink(ctx, input)
}

func (s *Store) createDecentralizedLink(ctx context.Context, input DecLinkCreate) (raw json.RawMessage, reused bool, err error) {
	if input.Mode != "new" && input.Mode != "renew" || input.Network != "-" && !dec.ValidID(input.Network, "net_") || input.Person != "-" && !dec.ValidPublicKey(input.Person) || input.Migration != "-" && (!dec.ValidID(input.Migration, "ds_") || input.Mode != "new" || input.Network == "-" || input.Invitation != "-") || input.Helpers == nil || len(input.Helpers) > 4 || input.Invitation == "" {
		return nil, false, decFailure("invalid")
	}
	for i, h := range input.Helpers {
		if !dec.ValidEndpoint(h.Address) || !dec.ValidPublicKey(h.PublicKey) || i > 0 && (input.Helpers[i-1].Address > h.Address || input.Helpers[i-1].Address == h.Address && input.Helpers[i-1].PublicKey >= h.PublicKey) {
			return nil, false, decFailure("invalid")
		}
	}
	var invitation *dec.ContactInvitation
	if input.Invitation != "-" {
		invitation, err = dec.ReadContactInvitation(input.Invitation)
		if err != nil {
			return nil, false, err
		}
		if input.Mode != "new" || input.Network != "-" && input.Network != invitation.Descriptor.NetworkID || invitation.Person != "-" && input.Person != invitation.Person || input.Person == "-" {
			return nil, false, decFailure("invalid")
		}
		input.Network = invitation.Descriptor.NetworkID
	}
	facts := decCommittedFacts{}
	publishID := ""
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
		if err == nil && publishID != "" {
			saved, e := s.readDecPendingSnapshot(ctx, publishID)
			if e != nil {
				err = e
				return
			}
			if e = s.publishDecFrames(ctx, saved); e != nil {
				raw, err = decRequestPublicationAttention(raw, e)
				return
			}
			// The created view describes the state after this first exact
			// publication, so an identical live retry returns the same view.
			published, e := s.readDecPendingSnapshot(ctx, publishID)
			if e != nil {
				err = e
				return
			}
			if fresh, e := decRequestResponse(published, published.Terms.Created, true); e == nil {
				raw = fresh
			}
		}
	}()
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, false, e
	}
	defer tx.Rollback()
	now, e := decCreationClock(ctx, tx, input.Network)
	if e != nil {
		return nil, false, e
	}
	var staged *decMigrationLinkContext
	if input.Migration != "-" {
		staged, e = s.migrationLinkContext(ctx, tx, input.Network, input.Migration, now)
		if e != nil {
			return nil, false, e
		}
		input.Person = staged.Own.Person
		input.Helpers, e = decSelectedRendezvous(ctx, tx)
		if e != nil {
			return nil, false, e
		}
	}
	ids, e := decPendingIDs(ctx, tx)
	if e != nil {
		return nil, false, e
	}
	active := 0
	for _, id := range ids {
		p, e := readDecPending(ctx, tx, id)
		if e != nil {
			return nil, false, e
		}
		if e = retireDecPending(ctx, tx, &p, now); e != nil {
			return nil, false, e
		}
		if decPendingResolved(p.Record.Terminal) {
			continue
		}
		active++
		if containsString(p.Record.Roles, "requester") && p.Record.Mode == input.Mode && p.Record.Network == input.Network {
			if p.Record.Migration != input.Migration || p.Record.Person != input.Person || (p.Record.Invitation != "-") != (invitation != nil) || invitation != nil && p.Record.Invitation != base64.StdEncoding.EncodeToString(invitation.Raw) {
				return nil, false, decFailure("operation_conflict")
			}
			original := []dec.ContactRelay{}
			for _, c := range p.Record.Carriers {
				if c.Kind == "helper" {
					original = append(original, dec.ContactRelay{Address: c.Address, PublicKey: c.Key})
				}
			}
			left, _ := json.Marshal(original)
			right, _ := json.Marshal(input.Helpers)
			if staged == nil && string(left) != string(right) {
				return nil, false, decFailure("operation_conflict")
			}
			raw, e = decRequestResponse(p, now, true)
			if e != nil {
				return nil, false, e
			}
			publishID = p.ID
			return raw, true, tx.Commit()
		}
	}
	if active >= 8 || len(ids) >= 4096 {
		return nil, false, decFailure("quota_exceeded")
	}
	if staged != nil && staged.Record.Fenced {
		return nil, false, decFailure("migration_pending", input.Migration)
	}
	if invitation != nil {
		if e = invitation.Current(now); e != nil {
			return nil, false, e
		}
	}
	d := dec.Descriptor{}
	expectedContext, renewed := "-", "-"
	var device ed25519.PrivateKey
	if staged != nil {
		d = staged.Source.Descriptor
		expectedContext = d.ContextID
		device = ed25519.NewKeyFromSeed(staged.Seed)
	} else if input.Network != "-" {
		state, e := s.loadDecSnapshot(ctx, tx, input.Network)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return nil, false, e
		}
		if e == nil {
			d = state.Descriptor
			expectedContext = d.ContextID
			if state.Network.Own.Person != "-" && state.Network.Own.Person != input.Person {
				return nil, false, decFailure("operation_conflict")
			}
			if len(state.Fenced) > 0 {
				return nil, false, decFailure("migration_pending")
			}
			if input.Mode == "renew" {
				if state.Provider == nil || state.Provider.Kind != "device" || state.Provider.Person != input.Person || len(state.DeviceSeed) != 32 {
					return nil, false, decFailure("forbidden")
				}
				device = ed25519.NewKeyFromSeed(state.DeviceSeed)
				renewed = state.Provider.Lease
			}
		} else if input.Mode == "renew" {
			return nil, false, decFailure("not_found")
		}
	}
	if input.Mode == "renew" && device == nil {
		return nil, false, decFailure("invalid")
	}
	if invitation != nil {
		if d.ContextID != "" && d.ContextID != invitation.Context {
			return nil, false, decFailure("operation_conflict")
		}
		d = invitation.Descriptor
		expectedContext = d.ContextID
	}
	newDevice := device == nil
	if newDevice {
		_, device, e = ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, false, e
		}
	}
	devicePublic := base64.StdEncoding.EncodeToString(device.Public().(ed25519.PublicKey))
	secret, nonce := make([]byte, 16), make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return nil, false, e
	}
	if _, e = rand.Read(nonce); e != nil {
		return nil, false, e
	}
	at, _ := dec.ParseTime(now)
	terms := dec.RequestTerms{Mode: input.Mode, Host: s.identity.PublicKey, Device: devicePublic, Nonce: base64.StdEncoding.EncodeToString(nonce), Network: input.Network, Context: expectedContext, Person: input.Person, Migration: input.Migration, RenewedDevice: renewed, Created: now, Expires: linkTime(at.Add(300 * time.Second))}
	payload, e := json.Marshal(terms)
	if e != nil {
		return nil, false, e
	}
	id := dec.RequestID(payload)
	template, e := dec.PacketTemplate(d, "-", id, "request", s.identity.PublicKey, devicePublic, "-", "-", "-", payload)
	if e != nil {
		return nil, false, e
	}
	packet, e := dec.ReadPacketTemplate(d, template)
	if e != nil {
		return nil, false, e
	}
	signed, e := dec.FillPacketTemplate(d, template, map[string]string{"host": base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, packet.Message)), "device": base64.StdEncoding.EncodeToString(ed25519.Sign(device, packet.Message))})
	if e != nil {
		return nil, false, e
	}
	p := decPending{ID: id, Deadline: terms.Expires, Secret: secret, Terms: terms, Descriptor: d, Frames: map[string]*dec.Frame{}, Record: decPendingRecord{Format: 1, Roles: []string{"requester"}, Mode: input.Mode, Migration: input.Migration, Network: input.Network, Context: expectedContext, Person: input.Person, Invitation: "-", Descriptor: "-", Host: s.identity.PublicKey, Device: devicePublic, Nonce: terms.Nonce, Request: base64.StdEncoding.EncodeToString(signed), Owner: "-", Selection: "-", Administrator: "-", Finalization: "-", Commit: "-", Outcome: "-", Catalog: "-", OwnerID: "-", SelectionID: "-", AdministratorID: "-", FinalizationID: "-", ManifestID: "-", ActivationID: "-", OwnerIntent: "-", AdministratorIntent: "-", SelectionIntent: "-", CommitIntent: "-", Terminal: "-", Carriers: []decCarrier{}, Outbound: []decOutboundFrame{}}}
	p.Request, e = dec.ReadPacket(d, signed)
	if e != nil {
		return nil, false, e
	}
	if d.ContextID != "" {
		p.Record.Descriptor = base64.StdEncoding.EncodeToString(d.Raw)
	}
	if invitation != nil {
		p.Record.Invitation = base64.StdEncoding.EncodeToString(invitation.Raw)
		for _, contact := range invitation.Contacts {
			for _, address := range contact.Addresses.Bootstrap {
				addDecCarriers(&p, decCarrier{"participant", address, contact.Host})
			}
		}
	}
	for _, h := range input.Helpers {
		addDecCarriers(&p, decCarrier{"helper", h.Address, h.PublicKey})
	}
	// First request ciphertext is fixed in the same transaction as its keys and
	// consent-free public request. Publication can only reuse these saved bytes.
	contactNetwork := input.Network
	if expectedContext == "-" {
		contactNetwork = "-"
	}
	contacts, e := s.decOwnContact(ctx, tx, contactNetwork, expectedContext, now, terms.Expires)
	if e != nil {
		return nil, false, e
	}
	for _, raw := range contacts {
		contact, e := dec.ReadContact(raw)
		if e != nil {
			return nil, false, e
		}
		for _, address := range contact.Addresses.Bootstrap {
			addDecCarriers(&p, decCarrier{"participant", address, contact.Host})
		}
	}
	plain, _ := json.Marshal(dec.FramePlaintext{Packet: p.Record.Request, Catalog: "-", Contacts: contacts})
	frameID, e := decPublicOperation("")
	if e != nil {
		return nil, false, e
	}
	frame, e := dec.SealFrame(d, secret, id, "request", frameID, now, terms.Expires, plain, s.privateKey)
	if e != nil {
		return nil, false, e
	}
	if _, e = insertDecFrame(ctx, tx, &p, frame); e != nil {
		return nil, false, e
	}
	p.Record.Outbound = append(p.Record.Outbound, decOutboundFrame{"request", s.identity.PublicKey, frameID, []decFrameAck{}})
	if newDevice {
		if _, e = tx.ExecContext(ctx, `INSERT INTO link_device_keys(public_key,seed,created_at) VALUES(?,?,?)`, devicePublic, device.Seed(), now); e != nil {
			return nil, false, e
		}
	}
	if e = putDecPending(ctx, tx, p); e != nil {
		return nil, false, e
	}
	if staged != nil {
		// The signing window and proposal approval are independent of carrier
		// clocks. Recheck the local clock and exact private tuple in the TX that
		// commits this immutable request, without changing its saved timestamps.
		now, e = decCreationClock(ctx, tx, input.Network)
		if e != nil {
			return nil, false, e
		}
		if _, e = s.decRequesterDeviceSeed(ctx, tx, p, now); e != nil {
			return nil, false, e
		}
	}
	if input.Network != "-" {
		clock, _ := json.Marshal(decClockRecord{1, now})
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, input.Network, string(clock)); e != nil {
			return nil, false, e
		}
	}
	raw, e = decRequestResponse(p, now, true)
	if e != nil {
		return nil, false, e
	}
	if e = tx.Commit(); e != nil {
		return nil, false, e
	}
	facts.operation = id
	facts.add("dec.request.after_commit")
	facts.add("dec.frame.after_commit")
	publishID = id
	return raw, false, nil
}

func (s *Store) DecentralizedLinks(ctx context.Context) ([]DecLinkView, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	ids, e := decPendingIDs(ctx, tx)
	if e != nil {
		return nil, e
	}
	now, e := decNow()
	if e != nil {
		return nil, e
	}
	views := []DecLinkView{}
	for _, id := range ids {
		p, e := readDecPending(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		views = append(views, decLinkView(p, linkTime(now)))
	}
	return views, tx.Commit()
}
func (s *Store) DecentralizedLink(ctx context.Context, id string) (DecLinkView, error) {
	if !dec.ValidID(id, "link_") {
		return DecLinkView{}, decFailure("invalid")
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecLinkView{}, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return DecLinkView{}, e
	}
	now, e := decNow()
	if e != nil {
		return DecLinkView{}, e
	}
	return decLinkView(p, linkTime(now)), tx.Commit()
}
func (s *Store) CancelDecentralizedLink(ctx context.Context, id string) (DecLinkView, error) {
	if !dec.ValidID(id, "link_") {
		return DecLinkView{}, decFailure("invalid")
	}
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return DecLinkView{}, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return DecLinkView{}, e
	}
	if p.Record.Commit != "-" || p.Record.Terminal == "migration_prepared" || p.Record.Terminal == "migration_adopted" || p.Record.Terminal == "applied" {
		return DecLinkView{}, decFailure("operation_conflict")
	}
	if p.Record.Terminal == "-" {
		p.Record.Terminal = "cancelled"
		p.Secret = nil
		p.TerminalCap = nil
		p.Record.Outbound = []decOutboundFrame{}
		p.Frames = map[string]*dec.Frame{}
		if _, e = tx.ExecContext(ctx, `DELETE FROM dec_frames WHERE request_id=?`, id); e != nil {
			return DecLinkView{}, e
		}
		if e = putDecPending(ctx, tx, p); e != nil {
			return DecLinkView{}, e
		}
	}
	now, e := decNow()
	if e != nil {
		return DecLinkView{}, e
	}
	return decLinkView(p, linkTime(now)), tx.Commit()
}
