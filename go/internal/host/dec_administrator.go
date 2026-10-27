package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecAdministratorApproval struct {
	Code      string `json:"code"`
	Network   string `json:"network_id"`
	Person    string `json:"person_public_key"`
	Provider  string `json:"provider_id"`
	Format    string `json:"signature_format"`
	Owner     string `json:"owner_offer_id"`
	Selection string `json:"selection_id"`
	Host      string `json:"expected_host_public_key"`
	Device    string `json:"expected_device_public_key"`
	Approve   bool   `json:"approve"`
}

type decAdministratorPlan struct {
	Descriptor dec.Descriptor
	Catalog    *dec.Catalog
	Writer     string
	Projection *dec.Projection
	Offer      decSelectedOffer
	Selection  *dec.Packet
	Provider   decIntentProvider
	View       DecProviderView
	Issuer     dec.Issuer
	Parents    []dec.Parent
	Seed       []byte
}

// Opening a code can cache independently signed transport without approving an
// issuer. No context/network/provider/admission row is created here.
func (s *Store) cacheDecAdministratorCode(ctx context.Context, token *dec.PairingToken, network string) error {
	s.linkMu.Lock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		s.linkMu.Unlock()
		return e
	}
	defer tx.Rollback()
	now, e := decCreationClock(ctx, tx, network)
	if e == nil {
		e = token.Current(now)
	}
	if e != nil {
		s.linkMu.Unlock()
		return e
	}
	p, e := readDecPending(ctx, tx, token.Request.RequestID)
	if errors.Is(e, ErrNotFound) {
		ids, err := decPendingIDs(ctx, tx)
		if err != nil {
			s.linkMu.Unlock()
			return err
		}
		active := 0
		for _, id := range ids {
			old, err := readDecPending(ctx, tx, id)
			if err != nil {
				s.linkMu.Unlock()
				return err
			}
			if !decPendingResolved(old.Record.Terminal) {
				active++
			}
		}
		if len(ids) >= 4096 || active >= 8 {
			s.linkMu.Unlock()
			return decFailure("quota_exceeded")
		}
		p = decPendingFromCode(token)
	} else if e != nil {
		s.linkMu.Unlock()
		return e
	} else if !bytes.Equal(p.Request.Raw, token.Request.Raw) || !bytes.Equal(p.Secret, token.Secret) {
		s.linkMu.Unlock()
		return decFailure("operation_conflict")
	}
	if p.Record.Terminal != "-" {
		s.linkMu.Unlock()
		return decFailure("operation_conflict")
	}
	addDecPendingRole(&p, "administrator")
	if e = putDecPending(ctx, tx, p); e == nil {
		e = tx.Commit()
	}
	s.linkMu.Unlock()
	if e != nil {
		return e
	}
	var first error
	success := len(p.Record.Carriers) == 0
	for _, carrier := range p.Record.Carriers {
		if e = s.receiveDecMailbox(ctx, p.ID, carrier); e != nil {
			if first == nil {
				first = e
			}
		} else {
			success = true
		}
	}
	if !success {
		return first
	}
	return nil
}

func decFindSelection(p decPending, offer decSelectedOffer, id string) (*dec.Packet, error) {
	keys := []string{}
	for key, frame := range p.Frames {
		if frame.Role == "selection" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if p.Record.Selection != "-" && p.Record.SelectionID == id {
		raw, e := decBytes(p.Record.Selection, dec.MaxObject)
		if e != nil {
			return nil, e
		}
		packet, e := dec.ReadPacket(offer.Descriptor, raw)
		if e == nil {
			return decCheckSelection(p, offer, packet, id)
		}
		return nil, e
	}
	for _, key := range keys {
		plain, e := decOpenPendingFrame(p, p.Frames[key])
		if e != nil {
			return nil, e
		}
		raw, e := decBytes(plain.Packet, dec.MaxObject)
		if e != nil {
			return nil, e
		}
		var header struct {
			Context string `json:"context_id"`
		}
		if json.Unmarshal(raw, &header) != nil {
			return nil, decStorageError()
		}
		if header.Context != offer.Descriptor.ContextID {
			continue
		}
		packet, e := dec.ReadPacket(offer.Descriptor, raw)
		if e != nil {
			return nil, e
		}
		if packet.ID == id {
			return decCheckSelection(p, offer, packet, id)
		}
	}
	return nil, decFailure("proof_required", id)
}
func decCheckSelection(p decPending, offer decSelectedOffer, packet *dec.Packet, id string) (*dec.Packet, error) {
	var terms struct {
		Request string `json:"request_packet_id"`
		Owner   string `json:"owner_offer_id"`
		Context string `json:"context_id"`
		Person  string `json:"person_public_key"`
		Host    string `json:"host_public_key"`
		Device  string `json:"device_public_key"`
		At      string `json:"selected_at"`
	}
	if json.Unmarshal(packet.Payload, &terms) != nil {
		return nil, decStorageError()
	}
	if packet.Role != "selection" || packet.ID != id || packet.RequestID != p.ID || packet.Writer != p.Record.Host || packet.Signer != p.Record.Device || packet.Person != offer.Owner.Person || terms.Request != p.Request.ID || terms.Owner != offer.Owner.ID || terms.Context != offer.Descriptor.ContextID || terms.Person != offer.Owner.Person || terms.Host != p.Record.Host || terms.Device != p.Record.Device || terms.At < p.Terms.Created || terms.At >= p.Deadline {
		return nil, decFailure("invalid")
	}
	return packet, nil
}

func (s *Store) decAdministratorPlan(ctx context.Context, q dbQuerier, p decPending, input DecAdministratorApproval, now string) (decAdministratorPlan, error) {
	var plan decAdministratorPlan
	if input.Host != p.Record.Host || input.Device != p.Record.Device || !dec.ValidPublicKey(input.Person) {
		return plan, decFailure("invalid")
	}
	if p.Record.Migration != "-" {
		return s.decMigrationAdministratorPlan(ctx, q, p, input, now)
	}
	offer, e := s.decSelectedOwner(ctx, q, p, input.Owner, now)
	if e != nil {
		return plan, e
	}
	if offer.Descriptor.NetworkID != input.Network || offer.Owner.Person != input.Person {
		return plan, decFailure("invalid")
	}
	selection, e := decFindSelection(p, offer, input.Selection)
	if e != nil {
		return plan, e
	}
	if containsString(p.Record.Roles, "requester") && !p.Record.Selected {
		return plan, decFailure("review_required")
	}
	state, e := s.loadDecSnapshot(ctx, q, input.Network)
	if e != nil {
		return plan, e
	}
	if !bytes.Equal(state.Descriptor.Raw, offer.Descriptor.Raw) {
		return plan, decFailure("invalid")
	}
	_, e = verifyDecSnapshot(state, now)
	if e != nil {
		return plan, e
	}
	union, e := dec.UnionCatalog(state.Descriptor, state.Catalog, offer.Catalog)
	if e != nil {
		return plan, e
	}
	projection, e := decPreparationProjection(state.Descriptor, state.PriorRaw, union, p, offer.Owner, now)
	if e != nil {
		return plan, e
	}
	coherent := *state
	coherent.Catalog = union
	state = &coherent
	view, provider, _, e := s.decActionProvider(ctx, q, state, projection, input.Provider, input.Format)
	if e != nil {
		return plan, e
	}
	if view.Scopes&8 == 0 {
		return plan, decFailure("forbidden")
	}
	if view.Root != projection.Root.SelectedID || offer.Terms.Root != "-" && offer.Terms.Root != view.Root {
		return plan, decFailure("forbidden")
	}
	if view.NotAfter != "-" && offer.Terms.NotAfter > view.NotAfter {
		return plan, decFailure("authority_expired")
	}
	issuer := dec.Issuer{Kind: "root", Person: "-"}
	parents := []dec.Parent{}
	if provider.Kind != "root" {
		person, _, e := projection.Current([]string{"person", view.Person})
		if e != nil {
			return plan, e
		}
		admin, _, e := projection.Current([]string{"admin", view.Person})
		if e != nil {
			return plan, e
		}
		issuer = dec.Issuer{Kind: "person", Person: view.Person}
		parents = []dec.Parent{{Role: "issuer_admin", ID: admin.ID}, {Role: "issuer_person", ID: person.ID}}
		if provider.Kind == "device" {
			issuer.Kind = "device"
			parents = append(parents, dec.Parent{Role: "issuer_device", ID: provider.Lease})
		}
		for _, parent := range parents {
			// Candidate target admissions may be reused, but newly learned
			// positive grants cannot bootstrap this stage's issuer authority.
			if !containsString(state.Prior.AdmittedStatements, parent.ID) {
				return plan, decFailure("forbidden")
			}
		}
		sort.Slice(parents, func(a, b int) bool { return parents[a].Role < parents[b].Role })
	}
	for _, id := range projection.Restrictions {
		r := state.Catalog.Statements[id]
		if r == nil || r.Restriction == nil {
			return plan, decFailure("proof_required", id)
		}
		if r.Kind == "person_remove" && r.Restriction.Target.Person == input.Person || r.Kind == "host_revoke" && r.Restriction.Target.Host == input.Host {
			return plan, decFailure("forbidden")
		}
		if r.Kind == "device_revoke" && r.Restriction.Target.Person == input.Person && r.Restriction.Target.Device == input.Device {
			return plan, decFailure("device_revoked")
		}
	}
	plan = decAdministratorPlan{Descriptor: state.Descriptor, Catalog: state.Catalog, Writer: s.identity.PublicKey, Projection: projection, Offer: offer, Selection: selection, Provider: provider, View: view, Issuer: issuer, Parents: parents}
	if provider.Kind == "root" {
		plan.Seed = state.RootSeed
	}
	if provider.Kind == "device" {
		plan.Seed, e = decOwnedDeviceSeed(ctx, q, provider.Signer)
		if e != nil {
			return plan, e
		}
	}
	return plan, nil
}

func decGrantHead(p *dec.Projection, stream []string) (uint64, []string, error) {
	for _, row := range p.Streams {
		if len(row.Stream) != len(stream) {
			continue
		}
		same := true
		for n := range stream {
			same = same && row.Stream[n] == stream[n]
		}
		if !same {
			continue
		}
		if len(row.HeadIDs) > 1 {
			return 0, nil, decFailure("state_conflict")
		}
		if row.Code == "proof_required" && len(row.HeadIDs) > 0 {
			return 0, nil, decFailure("proof_required", row.RequiredIDs...)
		}
		if row.Maximum == ^uint64(0) {
			return 0, nil, decFailure("version_exhausted")
		}
		return row.Maximum + 1, append([]string{}, row.HeadIDs...), nil
	}
	return 1, []string{}, nil
}

func decAdministratorGrant(plan decAdministratorPlan, p decPending, kind, now string) (string, []byte, error) {
	stream := []string{"person", plan.Offer.Owner.Person}
	if kind == "host_lease" {
		stream = []string{"host", p.Record.Host}
	}
	current, path, e := plan.Projection.Current(stream)
	if e == nil && current.Lease.Subject.Member == plan.Offer.Terms.Member && path.NotAfter >= plan.Offer.Terms.NotAfter {
		return current.ID, nil, nil
	}
	sequence, predecessors, e := decGrantHead(plan.Projection, stream)
	if e != nil {
		return "", nil, e
	}
	at, e := dec.ParseTime(now)
	if e != nil {
		return "", nil, e
	}
	if plan.Offer.Terms.NotAfter > linkTime(at.Add(7*24*time.Hour)) || plan.Offer.Terms.NotAfter <= now {
		return "", nil, decFailure("authority_expired")
	}
	subject := dec.Subject{Person: "-", Host: "-", Device: "-", Member: plan.Offer.Terms.Member, Scopes: 0}
	if kind == "person_lease" {
		subject.Person = plan.Offer.Owner.Person
	} else {
		subject.Host = p.Record.Host
	}
	lease := dec.Lease{Root: plan.Projection.Root.SelectedID, Operation: p.ID, Sequence: sequence, Predecessors: predecessors, Resolves: []string{}, Retained: []string{}, Subject: subject, Issuer: plan.Issuer, Parents: plan.Parents, Issued: now, Before: now, After: plan.Offer.Terms.NotAfter}
	payload, e := json.Marshal(lease)
	if e != nil {
		return "", nil, e
	}
	raw, e := dec.StatementTemplate(plan.Descriptor, kind, payload, []dec.Signature{{Role: "issuer", PublicKey: plan.Provider.Signer, Format: plan.Provider.Format, Signature: "-"}})
	if e != nil {
		return "", nil, e
	}
	statement, e := dec.ReadStatementTemplate(plan.Descriptor, raw)
	if e != nil {
		return "", nil, e
	}
	return statement.ID, raw, nil
}

func decAdministratorReview(plan decAdministratorPlan, p decPending, person, host string) decCeremonyReview {
	key, _ := membership.DecodeKey(plan.Offer.Owner.Person)
	return decCeremonyReview{"administrator", plan.Descriptor.NetworkID, plan.Descriptor.ContextID, membership.PersonID(key), plan.Offer.Owner.Person, p.Record.Host, p.Record.Device, plan.Projection.Root.SelectedID, plan.View, plan.Offer.Owner.ID, plan.Selection.ID, "-", person, host, "-", "-", plan.Offer.Terms.Scopes, plan.Offer.Terms.NotAfter, "This stage authorizes the exact finite person/host membership only. Owner device authority and requester final consent remain separate."}
}

func (s *Store) decCurrentAdministrator(ctx context.Context, q dbQuerier, p decPending, i decIntent, now string) (decAdministratorPlan, error) {
	if i.Kind != "administrator" {
		return decAdministratorPlan{}, decStorageError()
	}
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return decAdministratorPlan{}, e
	}
	plan, e := s.decAdministratorPlan(ctx, q, p, DecAdministratorApproval{Network: i.Network, Person: i.Record.Person, Provider: decConcreteProvider(i.Record.Provider), Format: i.Record.Provider.Format, Owner: review.Owner, Selection: review.Selection, Host: i.Record.Host, Device: i.Record.Device}, now)
	if e != nil {
		return plan, e
	}
	if plan.Provider != i.Record.Provider || plan.Projection.Root.SelectedID != i.Record.Root || plan.Offer.Terms.Scopes != i.Record.Scopes || plan.Offer.Terms.NotAfter != i.Record.NotAfter {
		return plan, decFailure("state_conflict")
	}
	newGrants := map[string]*dec.Statement{}
	for _, slot := range i.Record.Templates {
		if slot.Type == "administrator_packet" && slot.Template != "-" {
			template, e := readDecCeremonyTemplate(plan.Descriptor, i, slot)
			if e != nil {
				return plan, e
			}
			if template.Packet == nil || template.Packet.Writer != s.identity.PublicKey {
				return plan, decStorageError()
			}
		}
		if slot.Type != "person_lease" && slot.Type != "host_lease" {
			continue
		}
		template, e := readDecCeremonyTemplate(plan.Descriptor, i, slot)
		if e != nil {
			return plan, e
		}
		grant := template.Statement
		if grant == nil {
			return plan, decStorageError()
		}
		lease := grant.Lease
		if slot.Type == "person_lease" && grant.ID != review.PersonLease || slot.Type == "host_lease" && grant.ID != review.HostLease {
			return plan, decStorageError()
		}
		left, _ := json.Marshal(lease.Parents)
		right, _ := json.Marshal(plan.Parents)
		if lease.Root != i.Record.Root || lease.Issuer != plan.Issuer || !bytes.Equal(left, right) || lease.Subject.Member != plan.Offer.Terms.Member || lease.After != i.Record.NotAfter || lease.Before > now || lease.After <= now || lease.Issued > now {
			return plan, decFailure("forbidden")
		}
		stream := []string{"person", i.Record.Person}
		if slot.Type == "host_lease" {
			stream = []string{"host", i.Record.Host}
		}
		sequence, preds, e := decGrantHead(plan.Projection, stream)
		if e != nil {
			return plan, e
		}
		if sequence != lease.Sequence || len(preds) != len(lease.Predecessors) {
			return plan, decFailure("state_conflict")
		}
		for n := range preds {
			if preds[n] != lease.Predecessors[n] {
				return plan, decFailure("state_conflict")
			}
		}
		newGrants[grant.ID] = grant
	}
	for _, entry := range []struct{ id, kind, key string }{{review.PersonLease, "person", i.Record.Person}, {review.HostLease, "host", i.Record.Host}} {
		if newGrants[entry.id] != nil {
			continue
		}
		current, path, e := plan.Projection.Current([]string{entry.kind, entry.key})
		if e != nil {
			return plan, e
		}
		if current.ID != entry.id || current.Lease.Subject.Member != plan.Offer.Terms.Member || path.NotAfter < i.Record.NotAfter {
			return plan, decFailure("state_conflict")
		}
	}
	return plan, nil
}

func decApprovalIntent(ctx context.Context, q dbQuerier, p decPending) (decIntent, error) {
	var administrator *decIntent
	if p.Record.AdministratorIntent != "-" {
		i, e := readDecIntent(ctx, q, p.Record.AdministratorIntent)
		if e != nil {
			return decIntent{}, e
		}
		if i.Kind != "administrator" {
			return decIntent{}, decStorageError()
		}
		if i.Record.Approved {
			administrator = &i
			if p.Record.Administrator == "-" || p.Record.OwnerIntent == "-" {
				return i, nil
			}
		}
	}
	if p.Record.OwnerIntent != "-" {
		i, e := readDecIntent(ctx, q, p.Record.OwnerIntent)
		if e != nil {
			return i, e
		}
		if i.Kind != "owner" {
			return i, decStorageError()
		}
		if i.Record.Approved {
			return i, nil
		}
	}
	if administrator != nil {
		return *administrator, nil
	}
	return decIntent{}, decFailure("state_conflict")
}

func materializeDecAdministrator(plan decAdministratorPlan, p decPending, i *decIntent) error {
	last := len(i.Record.Templates) - 1
	if last < 0 || i.Record.Templates[last].Type != "administrator_packet" {
		return decStorageError()
	}
	if i.Record.Templates[last].Template != "-" {
		return nil
	}
	review, e := readDecCeremonyReview(*i)
	if e != nil {
		return e
	}
	var person, host any = review.PersonLease, review.HostLease
	for _, slot := range i.Record.Templates[:last] {
		template, e := readDecCeremonyTemplate(plan.Descriptor, *i, slot)
		if e != nil {
			return e
		}
		for _, role := range template.Roles {
			if role.Signature == "-" {
				return nil
			}
		}
		if _, e = dec.ReadStatement(plan.Descriptor, template.Body); e != nil {
			return e
		}
		if slot.Type == "person_lease" {
			person = json.RawMessage(template.Body)
		}
		if slot.Type == "host_lease" {
			host = json.RawMessage(template.Body)
		}
	}
	refs := []string{}
	for _, parent := range plan.Parents {
		refs = append(refs, parent.ID)
	}
	sort.Strings(refs)
	payload, e := json.Marshal(struct {
		Selection string   `json:"selection_id"`
		Owner     string   `json:"owner_offer_id"`
		Root      string   `json:"root_state_id"`
		Issuers   []string `json:"issuer_lease_ids"`
		Person    any      `json:"person_lease"`
		Host      any      `json:"host_lease"`
	}{plan.Selection.ID, plan.Offer.Owner.ID, i.Record.Root, refs, person, host})
	if e != nil {
		return e
	}
	issuer, personKey := "-", plan.View.Person
	if plan.Provider.Kind == "root" {
		issuer = i.Record.Root
		personKey = "-"
	}
	if plan.Provider.Kind == "device" {
		issuer = plan.Provider.Lease
	}
	raw, e := dec.PacketTemplate(plan.Descriptor, i.Context, p.ID, "administrator", plan.Writer, plan.Provider.Signer, personKey, issuer, plan.Provider.Format, payload)
	if e != nil {
		return e
	}
	packet, e := dec.ReadPacketTemplate(plan.Descriptor, raw)
	if e != nil {
		return e
	}
	i.Record.Templates[last].Template = base64.StdEncoding.EncodeToString(raw)
	review.Administrator = packet.ID
	body, _ := json.Marshal(review)
	i.Record.Review = base64.StdEncoding.EncodeToString(body)
	return nil
}

func (s *Store) saveDecAdministratorStage(ctx context.Context, tx *sql.Tx, p *decPending, i *decIntent, plan decAdministratorPlan, now string, facts *decCommittedFacts) (decApprovalResult, error) {
	var result decApprovalResult
	fresh, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	plan, e = s.decCurrentAdministrator(ctx, tx, *p, *i, fresh)
	if e != nil {
		return result, e
	}
	now = fresh
	components, e := decCatalogComponents(plan.Catalog)
	if e != nil {
		return result, e
	}
	if p.Record.Administrator == "-" {
		if e = decStageFrameCapacity(*p, components, 32<<10); e != nil {
			return result, e
		}
	}
	beforeTemplates, _ := json.Marshal(i.Record.Templates)
	if e = materializeDecAdministrator(plan, *p, i); e != nil {
		return result, e
	}
	afterTemplates, _ := json.Marshal(i.Record.Templates)
	if !bytes.Equal(beforeTemplates, afterTemplates) {
		if e = storeDecIntent(ctx, tx, *i, false); e != nil {
			return result, e
		}
		facts.add("dec.intent.after_commit")
		result, e = decApprovalResponse(*p, *i, now)
		if e != nil {
			return result, e
		}
		return result, tx.Commit()
	}
	before := len(i.Record.Signatures)
	if e = s.signDecCeremonyOwned(plan.Descriptor, i, plan.Seed, now); e != nil {
		return result, e
	}
	if before != len(i.Record.Signatures) {
		facts.add("dec.signature.after_commit")
	}
	if e = storeDecIntent(ctx, tx, *i, false); e != nil {
		return result, e
	}
	last := i.Record.Templates[len(i.Record.Templates)-1]
	if last.Template != "-" && p.Record.Administrator == "-" {
		template, e := readDecCeremonyTemplate(plan.Descriptor, *i, last)
		if e != nil {
			return result, e
		}
		complete := true
		for _, role := range template.Roles {
			if role.Signature == "-" {
				complete = false
			}
		}
		if complete {
			packet, e := dec.ReadPacket(plan.Descriptor, template.Body)
			if e != nil {
				return result, e
			}
			p.Record.Administrator, p.Record.AdministratorID = base64.StdEncoding.EncodeToString(packet.Raw), packet.ID
			p.Record.Catalog = base64.StdEncoding.EncodeToString(plan.Catalog.Raw)
			if e = putDecPending(ctx, tx, *p); e != nil {
				return result, e
			}
			facts.add("dec.administrator.after_commit")
		}
	}
	clock, _ := json.Marshal(decClockRecord{1, now})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), i.Network); e != nil {
		return result, e
	}
	result, e = decApprovalResponse(*p, *i, now)
	if e != nil {
		return result, e
	}
	return result, tx.Commit()
}

func (s *Store) PrepareDecentralizedAdministrator(ctx context.Context, input DecAdministratorApproval) (result decApprovalResult, err error) {
	token, e := dec.ReadPairingToken(input.Code)
	if e != nil {
		return result, e
	}
	if !dec.ValidID(input.Network, "net_") || !dec.ValidPublicKey(input.Person) || !dec.ValidID(input.Owner, "dpk_") || !dec.ValidID(input.Selection, "dpk_") || input.Host != token.Terms.Host || input.Device != token.Terms.Device || token.Terms.Network != "-" && token.Terms.Network != input.Network || token.Terms.Person != "-" && token.Terms.Person != input.Person {
		return result, decFailure("invalid")
	}
	if e = s.cacheDecAdministratorCode(ctx, token, input.Network); e != nil {
		return result, e
	}
	facts := decCommittedFacts{operation: token.Request.RequestID}
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
		if err == nil && input.Approve {
			result, err = s.advanceDecAdministrator(ctx, token.Request.RequestID, nil)
		}
	}()
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, token.Request.RequestID)
	if e != nil {
		return result, e
	}
	now, e := decCreationClock(ctx, tx, input.Network)
	if e != nil {
		return result, e
	}
	plan, e := s.decAdministratorPlan(ctx, tx, p, input, now)
	if e != nil {
		return result, e
	}
	p.Descriptor, p.Record.Descriptor = plan.Descriptor, base64.StdEncoding.EncodeToString(plan.Descriptor.Raw)
	p.Record.Owner, p.Record.OwnerID = base64.StdEncoding.EncodeToString(plan.Offer.Owner.Raw), plan.Offer.Owner.ID
	if p.Record.Selection != "-" && p.Record.SelectionID != plan.Selection.ID {
		return result, decFailure("operation_conflict")
	}
	p.Record.Selection, p.Record.SelectionID = base64.StdEncoding.EncodeToString(plan.Selection.Raw), plan.Selection.ID
	if p.Record.AdministratorIntent != "-" {
		i, e := readDecIntent(ctx, tx, p.Record.AdministratorIntent)
		if e != nil {
			return result, e
		}
		review, e := readDecCeremonyReview(i)
		if e != nil {
			return result, e
		}
		if i.Record.Provider != plan.Provider || review.Owner != input.Owner || review.Selection != input.Selection || i.Record.Person != input.Person || i.Record.Host != input.Host || i.Record.Device != input.Device {
			return result, decFailure("state_conflict")
		}
		if _, e = s.decCurrentAdministrator(ctx, tx, p, i, now); e != nil {
			return result, e
		}
		if !input.Approve {
			return decApprovalResponse(p, i, now)
		}
		if !i.Record.Approved {
			i.Record.Approved, i.Record.ApprovedAt = true, now
			facts.add("dec.approval.after_commit")
		}
		return s.saveDecAdministratorPreparation(ctx, tx, p, i, now)
	}
	if e = decIntentCapacity(ctx, tx); e != nil {
		return result, e
	}
	person, personRaw, e := decAdministratorGrant(plan, p, "person_lease", now)
	if e != nil {
		return result, e
	}
	host, hostRaw, e := decAdministratorGrant(plan, p, "host_lease", now)
	if e != nil {
		return result, e
	}
	review := decAdministratorReview(plan, p, person, host)
	body, _ := json.Marshal(review)
	templates := []decIntentTemplate{}
	for _, entry := range []struct {
		kind string
		raw  []byte
	}{{"person_lease", personRaw}, {"host_lease", hostRaw}} {
		if entry.raw != nil {
			templates = append(templates, decIntentTemplate{uint64(len(templates) + 1), entry.kind, base64.StdEncoding.EncodeToString(entry.raw)})
		}
	}
	templates = append(templates, decIntentTemplate{uint64(len(templates) + 1), "administrator_packet", "-"})
	id, e := decRandomID("dint_")
	if e != nil {
		return result, e
	}
	i := decIntent{ID: id, Network: input.Network, Context: plan.Descriptor.ContextID, Kind: "administrator", Record: decIntentRecord{Format: 1, Operation: p.ID, Approved: input.Approve, ApprovedAt: "-", Review: base64.StdEncoding.EncodeToString(body), Provider: plan.Provider, Root: plan.Projection.Root.SelectedID, Person: input.Person, Host: input.Host, Device: input.Device, Scopes: review.Scopes, NotAfter: review.NotAfter, Created: now, Expires: p.Deadline, Templates: templates, Signatures: []decIntentSignature{}, Terminal: "-", Result: "-"}}
	if input.Approve {
		i.Record.ApprovedAt = now
		facts.add("dec.approval.after_commit")
	}
	p.Record.AdministratorIntent = i.ID
	if e = putDecPending(ctx, tx, p); e != nil {
		return result, e
	}
	if e = storeDecIntent(ctx, tx, i, true); e != nil {
		return result, e
	}
	if _, e = s.decCurrentAdministrator(ctx, tx, p, i, now); e != nil {
		return result, e
	}
	components, e := decCatalogComponents(plan.Catalog)
	if e != nil {
		return result, e
	}
	if e = decStageFrameCapacity(p, components, 32<<10); e != nil {
		return result, e
	}
	facts.add("dec.intent.after_commit")
	return s.saveDecAdministratorPreparation(ctx, tx, p, i, now)
}

func (s *Store) saveDecAdministratorPreparation(ctx context.Context, tx *sql.Tx, p decPending, i decIntent, approvedAt string) (decApprovalResult, error) {
	var result decApprovalResult
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	if _, e = s.decCurrentAdministrator(ctx, tx, p, i, now); e != nil {
		return result, e
	}
	if i.Record.Approved && i.Record.ApprovedAt == approvedAt {
		i.Record.ApprovedAt = now
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return result, e
	}
	if i.Record.Approved {
		clock, _ := json.Marshal(decClockRecord{1, now})
		if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), i.Network); e != nil {
			return result, e
		}
	}
	result, e = decApprovalResponse(p, i, now)
	if e != nil {
		return result, e
	}
	return result, tx.Commit()
}

func (s *Store) advanceDecAdministratorStep(ctx context.Context, id string, batch *DecSignatureBatch) (result decApprovalResult, err error) {
	facts := decCommittedFacts{operation: id}
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
	}()
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return result, e
	}
	if p.Record.AdministratorIntent == "-" {
		return result, decFailure("state_conflict")
	}
	i, e := readDecIntent(ctx, tx, p.Record.AdministratorIntent)
	if e != nil {
		return result, e
	}
	if !i.Record.Approved {
		return result, decFailure("review_required")
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	plan, e := s.decCurrentAdministrator(ctx, tx, p, i, now)
	if e != nil {
		return result, e
	}
	components, e := decCatalogComponents(plan.Catalog)
	if e != nil {
		return result, e
	}
	if p.Record.Administrator == "-" {
		if e = decStageFrameCapacity(p, components, 32<<10); e != nil {
			return result, e
		}
	}
	if batch != nil {
		if e = validateDecSignatureBatch(*batch); e != nil {
			return result, e
		}
		before := len(i.Record.Signatures)
		if e = acceptDecCeremonySignatures(plan.Descriptor, &i, *batch, now); e != nil {
			return result, e
		}
		if before != len(i.Record.Signatures) {
			facts.add("dec.signature.after_commit")
		}
	}
	if batch != nil {
		if e = storeDecIntent(ctx, tx, i, false); e != nil {
			return result, e
		}
		result, e = decApprovalResponse(p, i, now)
		if e != nil {
			return result, e
		}
		return result, tx.Commit()
	}
	return s.saveDecAdministratorStage(ctx, tx, &p, &i, plan, now, &facts)
}

func (s *Store) advanceDecAdministrator(ctx context.Context, id string, batch *DecSignatureBatch) (decApprovalResult, error) {
	var result decApprovalResult
	for n := 0; n < 12; n++ {
		before, e := s.decStageFingerprint(ctx, id)
		if e != nil {
			return result, e
		}
		result, e = s.advanceDecAdministratorStep(ctx, id, batch)
		batch = nil
		if e != nil {
			return result, e
		}
		after, e := s.decStageFingerprint(ctx, id)
		if e != nil {
			return result, e
		}
		if before == after {
			break
		}
	}
	if e := s.sealDecApprovedStages(ctx, id); e != nil {
		return result, e
	}
	p, e := s.readDecPendingSnapshot(ctx, id)
	if e != nil {
		return result, e
	}
	result.Request = decLinkView(p, p.Terms.Created)
	if e = s.publishDecFrames(ctx, p); e != nil {
		result.Request = decPublicationAttention(result.Request, e)
	}
	return result, nil
}
