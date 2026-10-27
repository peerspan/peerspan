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

type DecOwnerApproval struct {
	Code     string `json:"code"`
	Network  string `json:"network_id"`
	Person   string `json:"person_public_key"`
	Provider string `json:"provider_id"`
	Format   string `json:"signature_format"`
	Scopes   uint64 `json:"scopes"`
	NotAfter string `json:"not_after"`
	Host     string `json:"expected_host_public_key"`
	Device   string `json:"expected_device_public_key"`
	Approve  bool   `json:"approve"`
}

type decCeremonyReview struct {
	Stage         string          `json:"stage"`
	Network       string          `json:"network_id"`
	Context       string          `json:"context_id"`
	PersonID      string          `json:"person_id"`
	Person        string          `json:"person_public_key"`
	Host          string          `json:"host_public_key"`
	Device        string          `json:"device_public_key"`
	Root          string          `json:"root_state_id"`
	Provider      DecProviderView `json:"provider"`
	Owner         string          `json:"owner_offer_id"`
	Selection     string          `json:"selection_id"`
	Administrator string          `json:"administrator_offer_id"`
	PersonLease   string          `json:"person_lease_id"`
	HostLease     string          `json:"host_lease_id"`
	BindingLease  string          `json:"binding_lease_id"`
	DeviceLease   string          `json:"device_lease_id"`
	Scopes        uint64          `json:"scopes"`
	NotAfter      string          `json:"not_after"`
	Warning       string          `json:"authority_warning"`
}

const decCeremonyReviewFields = "stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning"

type decApprovalResult struct {
	Request DecLinkView         `json:"request"`
	Review  decCeremonyReview   `json:"review"`
	Signing []DecSigningRequest `json:"signing_requests"`
}

type decOwnerPlan struct {
	Descriptor                                         dec.Descriptor
	Provider                                           decIntentProvider
	View                                               DecProviderView
	Root, PersonLease, HostLease, BindingLease, Member string
	Catalog                                            *dec.Catalog
	Seed                                               []byte
}

func readDecCeremonyReview(i decIntent) (decCeremonyReview, error) {
	var review decCeremonyReview
	raw, e := decBytes(i.Record.Review, 1<<20)
	if e != nil {
		return review, e
	}
	if e = dec.ReadPrivateRecord(raw, decCeremonyReviewFields, &review); e != nil {
		return review, e
	}
	if review.Network != i.Network || review.Context != i.Context || review.Person != i.Record.Person || review.Host != i.Record.Host || review.Device != i.Record.Device || review.Scopes != i.Record.Scopes || review.NotAfter != i.Record.NotAfter || review.Root != i.Record.Root {
		return review, decStorageError()
	}
	return review, nil
}

func (s *Store) decOwnerPlan(ctx context.Context, q dbQuerier, p decPending, input DecOwnerApproval, now string) (decOwnerPlan, error) {
	var plan decOwnerPlan
	if !dec.ValidID(input.Network, "net_") || !dec.ValidPublicKey(input.Person) || input.Host != p.Record.Host || input.Device != p.Record.Device || input.Scopes == 0 || input.Scopes > 15 || p.Record.Network != "-" && p.Record.Network != input.Network || p.Record.Person != "-" && p.Record.Person != input.Person {
		return plan, decFailure("invalid")
	}
	deadline, e := dec.ParseTime(input.NotAfter)
	if e != nil {
		return plan, e
	}
	at, e := dec.ParseTime(now)
	if e != nil {
		return plan, e
	}
	if !deadline.After(at) || deadline.After(at.Add(7*24*time.Hour)) {
		return plan, decFailure("invalid")
	}
	if p.Record.Migration != "-" {
		return s.decMigrationOwnerPlan(ctx, q, p, input, now)
	}
	state, e := s.loadDecSnapshot(ctx, q, input.Network)
	if errors.Is(e, ErrNotFound) {
		// Possession is available only on the invitation recipient's own pending
		// machine, with the original descriptor/member/person already fixed.
		if !containsString(p.Record.Roles, "requester") || p.Record.Invitation == "-" || p.Record.Mode != "new" || input.Provider != input.Person || input.Format != "auto" && input.Format != "sshsig" {
			return plan, decFailure("forbidden")
		}
		raw, e := decBytes(p.Record.Invitation, dec.MaxPairingToken)
		if e != nil {
			return plan, e
		}
		invitation, e := dec.ReadContactInvitationBody(raw)
		if e != nil {
			return plan, e
		}
		if e = invitation.Current(p.Terms.Created); e != nil {
			return plan, e
		}
		if invitation.Descriptor.NetworkID != input.Network || invitation.Person != "-" && invitation.Person != input.Person || p.Record.Context != invitation.Context {
			return plan, decFailure("invalid")
		}
		plan.Descriptor, plan.Root, plan.PersonLease, plan.HostLease, plan.BindingLease, plan.Member = invitation.Descriptor, "-", "-", "-", "-", invitation.Member
		plan.Provider = decIntentProvider{"original", input.Person, "sshsig", "-"}
		plan.View = DecProviderView{"original_person", input.Person, s.identity.PublicKey, "-", "-", "-", 0, "-"}
		return plan, nil
	}
	if e != nil {
		return plan, e
	}
	projection, e := verifyDecSnapshot(state, now)
	if e != nil {
		return plan, e
	}
	view, provider, _, e := s.decActionProvider(ctx, q, state, projection, input.Provider, input.Format)
	if e != nil {
		return plan, e
	}
	if provider.Kind == "root" || view.Person != input.Person || view.Scopes&4 == 0 || input.Scopes&^view.Scopes != 0 {
		return plan, decFailure("forbidden")
	}
	person, path, e := projection.Current([]string{"person", input.Person})
	if e != nil {
		return plan, e
	}
	if input.NotAfter > decEarlier(path.NotAfter, view.NotAfter) {
		return plan, decFailure("authority_expired")
	}
	if p.Record.Context != "-" && p.Record.Context != state.Descriptor.ContextID || p.Descriptor.ContextID != "" && !bytes.Equal(p.Descriptor.Raw, state.Descriptor.Raw) {
		return plan, decFailure("invalid")
	}
	if p.Record.Mode == "renew" {
		old := state.Catalog.Statements[p.Terms.RenewedDevice]
		if old == nil {
			return plan, decFailure("proof_required", p.Terms.RenewedDevice)
		}
		if !containsString(state.Prior.AdmittedStatements, old.ID) || old.Kind != "device_lease" || old.Lease.Subject.Person != input.Person || old.Lease.Subject.Host != p.Record.Host || old.Lease.Subject.Device != p.Record.Device || input.Scopes&^old.Lease.Subject.Scopes != 0 {
			return plan, decFailure("forbidden")
		}
		for _, id := range projection.Restrictions {
			restriction := state.Catalog.Statements[id]
			if restriction == nil || restriction.Restriction == nil {
				return plan, decFailure("proof_required", id)
			}
			if restriction.Kind == "device_revoke" && restriction.Restriction.Target.Person == input.Person && restriction.Restriction.Target.Device == p.Record.Device {
				return plan, decFailure("device_revoked")
			}
		}
		if provider.Kind == "device" {
			ancestor, e := decDeviceAncestor(state.Catalog, old.ID, provider.Lease)
			if e != nil {
				return plan, e
			}
			if !ancestor {
				return plan, decFailure("forbidden")
			}
		}
	}
	plan = decOwnerPlan{Descriptor: state.Descriptor, Provider: provider, View: view, Root: projection.Root.SelectedID, PersonLease: person.ID, HostLease: "-", BindingLease: "-", Member: person.Lease.Subject.Member, Catalog: state.Catalog}
	if p.Record.Mode == "renew" {
		if member, e := decCurrentMember(projection, p.Record.Host); e == nil && member.BindingError == nil && member.View.Person == input.Person && input.NotAfter <= member.View.NotAfter {
			plan.HostLease, plan.BindingLease = member.View.HostLease, member.View.Binding
		}
	}
	if plan.BindingLease == "-" && view.Scopes&2 == 0 {
		return plan, decFailure("forbidden")
	}
	if provider.Kind == "device" {
		if e = decDeviceChildKey(state.Catalog, provider.Lease, p.Record.Device); e != nil {
			return plan, e
		}
		plan.Seed, e = decOwnedDeviceSeed(ctx, q, provider.Signer)
		if e != nil {
			return plan, e
		}
		if provider.Signer == p.Record.Device {
			return plan, decFailure("forbidden")
		}
	}
	return plan, nil
}

func decDeviceChildKey(c *dec.Catalog, issuer, target string) error {
	seen := map[string]bool{}
	depth := 1 // the proposed child itself
	for issuer != "-" {
		if seen[issuer] {
			return decFailure("invalid")
		}
		seen[issuer] = true
		s := c.Statements[issuer]
		if s == nil {
			return decFailure("proof_required", issuer)
		}
		if s.Kind != "device_lease" {
			return decFailure("invalid")
		}
		depth++
		if s.Lease.Subject.Device == target || depth > 8 {
			return decFailure("forbidden")
		}
		issuer = "-"
		for _, parent := range s.Lease.Parents {
			if parent.Role == "issuer_device" {
				issuer = parent.ID
			}
		}
	}
	return nil
}

func decDeviceAncestor(c *dec.Catalog, child, ancestor string) (bool, error) {
	seen := map[string]bool{}
	for {
		if seen[child] {
			return false, decFailure("invalid")
		}
		seen[child] = true
		s := c.Statements[child]
		if s == nil {
			return false, decFailure("proof_required", child)
		}
		if s.Kind != "device_lease" {
			return false, decFailure("invalid")
		}
		next := "-"
		for _, parent := range s.Lease.Parents {
			if parent.Role == "issuer_device" {
				next = parent.ID
			}
		}
		if next == ancestor {
			return true, nil
		}
		if next == "-" {
			return false, nil
		}
		child = next
	}
}

func decPendingFromCode(token *dec.PairingToken) decPending {
	t := token.Terms
	p := decPending{ID: token.Request.RequestID, Deadline: t.Expires, Request: token.Request, Terms: t, Secret: append([]byte{}, token.Secret...), Frames: map[string]*dec.Frame{}, Record: decPendingRecord{Format: 1, Roles: []string{}, Mode: t.Mode, Migration: t.Migration, Network: t.Network, Context: t.Context, Person: t.Person, Invitation: "-", Descriptor: "-", Host: t.Host, Device: t.Device, Nonce: t.Nonce, Request: base64.StdEncoding.EncodeToString(token.Request.Raw), Owner: "-", Selection: "-", Administrator: "-", Finalization: "-", Commit: "-", Outcome: "-", Catalog: "-", OwnerID: "-", SelectionID: "-", AdministratorID: "-", FinalizationID: "-", ManifestID: "-", ActivationID: "-", OwnerIntent: "-", AdministratorIntent: "-", SelectionIntent: "-", CommitIntent: "-", Terminal: "-", Carriers: []decCarrier{}, Outbound: []decOutboundFrame{}}}
	for _, contact := range token.Contacts {
		for _, address := range contact.Addresses.Bootstrap {
			addDecCarriers(&p, decCarrier{"participant", address, contact.Host})
		}
	}
	for _, helper := range token.Helpers {
		addDecCarriers(&p, decCarrier{"helper", helper.Address, helper.PublicKey})
	}
	return p
}

func addDecPendingRole(p *decPending, role string) {
	if !containsString(p.Record.Roles, role) {
		p.Record.Roles = append(p.Record.Roles, role)
	}
	order := map[string]int{"requester": 1, "owner": 2, "administrator": 3}
	sort.Slice(p.Record.Roles, func(a, b int) bool { return order[p.Record.Roles[a]] < order[p.Record.Roles[b]] })
}

func decOwnerTemplate(plan decOwnerPlan, p decPending, input DecOwnerApproval, writer string) ([]byte, error) {
	refs := []string{}
	if plan.PersonLease != "-" {
		refs = append(refs, plan.PersonLease)
	}
	issuer := "-"
	if plan.Provider.Kind == "device" {
		issuer = plan.Provider.Lease
		refs = append(refs, issuer)
	}
	sort.Strings(refs)
	payload, e := json.Marshal(struct {
		Request    string          `json:"request_packet_id"`
		Descriptor json.RawMessage `json:"descriptor"`
		Root       string          `json:"root_state_id"`
		Person     string          `json:"person_lease_id"`
		Issuers    []string        `json:"issuer_lease_ids"`
		Mode       string          `json:"mode"`
		Member     string          `json:"member"`
		Host       string          `json:"host_public_key"`
		Device     string          `json:"device_public_key"`
		Scopes     uint64          `json:"scopes"`
		After      string          `json:"not_after"`
		Renewed    string          `json:"renewed_device_lease_id"`
	}{p.Request.ID, plan.Descriptor.Raw, plan.Root, plan.PersonLease, refs, p.Record.Mode, plan.Member, p.Record.Host, p.Record.Device, input.Scopes, input.NotAfter, p.Terms.RenewedDevice})
	if e != nil {
		return nil, e
	}
	return dec.PacketTemplate(plan.Descriptor, plan.Descriptor.ContextID, p.ID, "owner", writer, plan.Provider.Signer, input.Person, issuer, plan.Provider.Format, payload)
}

func decOwnerReview(plan decOwnerPlan, p decPending, input DecOwnerApproval, packet *dec.Packet) decCeremonyReview {
	key, _ := membership.DecodeKey(input.Person)
	return decCeremonyReview{"owner", plan.Descriptor.NetworkID, plan.Descriptor.ContextID, membership.PersonID(key), input.Person, p.Record.Host, p.Record.Device, plan.Root, plan.View, packet.ID, "-", "-", plan.PersonLease, plan.HostLease, plan.BindingLease, "-", input.Scopes, input.NotAfter, "Finite authority; scope8 also requires a current administrator role. Self trust/access and approving other machines remain conditional on the exact granted scopes."}
}

func decApprovalResponse(p decPending, i decIntent, now string) (decApprovalResult, error) {
	var result decApprovalResult
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return result, e
	}
	signing, e := decCeremonySigning(p.Descriptor, i, now)
	if e != nil {
		return result, e
	}
	return decApprovalResult{decLinkView(p, now), review, signing}, nil
}

func (s *Store) decCurrentOwner(ctx context.Context, q dbQuerier, p decPending, i decIntent, now string) (decOwnerPlan, error) {
	if i.Kind != "owner" {
		return decOwnerPlan{}, decStorageError()
	}
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return decOwnerPlan{}, e
	}
	if review.Stage == "owner_finalization" {
		final, e := s.decCurrentFinalization(ctx, q, p, i, review, now)
		return final.Owner, e
	}
	plan, e := s.decOwnerPlan(ctx, q, p, DecOwnerApproval{Network: i.Network, Person: i.Record.Person, Provider: decConcreteProvider(i.Record.Provider), Format: i.Record.Provider.Format, Scopes: i.Record.Scopes, NotAfter: i.Record.NotAfter, Host: i.Record.Host, Device: i.Record.Device}, now)
	if e != nil {
		return plan, e
	}
	if plan.Provider != i.Record.Provider || plan.Root != review.Root || plan.PersonLease != review.PersonLease || plan.HostLease != review.HostLease || plan.BindingLease != review.BindingLease || plan.Member == "" {
		return plan, decFailure("state_conflict")
	}
	if len(i.Record.Templates) == 0 {
		return plan, decStorageError()
	}
	owner, e := readDecCeremonyTemplate(plan.Descriptor, i, i.Record.Templates[0])
	if e != nil {
		return plan, e
	}
	if owner.Packet == nil || owner.Packet.Writer != s.identity.PublicKey {
		return plan, decStorageError()
	}
	return plan, nil
}

// Complete the immutable owner offer only. B/D/finalization remain blocked
// until the independently reviewed selection and administrator stage exist.
func (s *Store) retainDecOwnerPacket(ctx context.Context, tx *sql.Tx, p *decPending, i decIntent, plan decOwnerPlan, now string) (bool, error) {
	if p.Record.Owner != "-" {
		return false, nil
	}
	template, e := readDecCeremonyTemplate(plan.Descriptor, i, i.Record.Templates[0])
	if e != nil {
		return false, e
	}
	for _, role := range template.Roles {
		if role.Signature == "-" {
			return false, nil
		}
	}
	packet, e := dec.ReadPacket(plan.Descriptor, template.Body)
	if e != nil {
		return false, e
	}
	p.Record.Owner, p.Record.OwnerID = base64.StdEncoding.EncodeToString(packet.Raw), packet.ID
	if plan.Catalog != nil {
		p.Record.Catalog = base64.StdEncoding.EncodeToString(plan.Catalog.Raw)
	}
	return true, putDecPending(ctx, tx, *p)
}

func (s *Store) PrepareDecentralizedOwner(ctx context.Context, input DecOwnerApproval) (result decApprovalResult, err error) {
	token, e := dec.ReadPairingToken(input.Code)
	if e != nil {
		return result, e
	}
	if input.Host != token.Terms.Host || input.Device != token.Terms.Device {
		return result, decFailure("invalid")
	}
	facts := decCommittedFacts{operation: token.Request.RequestID}
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
		if err == nil && input.Approve {
			result, err = s.advanceDecOwnerIntent(ctx, token.Request.RequestID)
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
	now, e := decCreationClock(ctx, tx, input.Network)
	if e != nil {
		return result, e
	}
	if e = token.Current(now); e != nil {
		return result, e
	}
	p, e := readDecPending(ctx, tx, token.Request.RequestID)
	if errors.Is(e, ErrNotFound) {
		ids, e := decPendingIDs(ctx, tx)
		if e != nil {
			return result, e
		}
		active := 0
		for _, id := range ids {
			old, e := readDecPending(ctx, tx, id)
			if e != nil {
				return result, e
			}
			if !decPendingResolved(old.Record.Terminal) {
				active++
			}
		}
		if len(ids) >= 4096 || active >= 8 {
			return result, decFailure("quota_exceeded")
		}
		p = decPendingFromCode(token)
	} else if e != nil {
		return result, e
	} else if !bytes.Equal(p.Request.Raw, token.Request.Raw) || !bytes.Equal(p.Secret, token.Secret) {
		return result, decFailure("operation_conflict")
	}
	if p.Record.Terminal != "-" {
		return result, decFailure("operation_conflict")
	}
	plan, e := s.decOwnerPlan(ctx, tx, p, input, now)
	if e != nil {
		return result, e
	}
	if p.Record.OwnerIntent != "-" {
		i, e := readDecIntent(ctx, tx, p.Record.OwnerIntent)
		if e != nil {
			return result, e
		}
		review, e := readDecCeremonyReview(i)
		if e != nil {
			return result, e
		}
		if i.Record.Provider != plan.Provider || i.Record.Person != input.Person || i.Record.Scopes != input.Scopes || i.Record.NotAfter != input.NotAfter || review.Root != plan.Root || review.PersonLease != plan.PersonLease {
			return result, decFailure("state_conflict")
		}
		if input.Approve && !i.Record.Approved {
			i.Record.Approved, i.Record.ApprovedAt = true, now
			facts.add("dec.approval.after_commit")
		}
		if !input.Approve {
			return decApprovalResponse(p, i, now)
		}
		return s.saveDecOwnerPreparation(ctx, tx, p, i, plan, now)
	}
	if e = decIntentCapacity(ctx, tx); e != nil {
		return result, e
	}
	raw, e := decOwnerTemplate(plan, p, input, s.identity.PublicKey)
	if e != nil {
		return result, e
	}
	packet, e := dec.ReadPacketTemplate(plan.Descriptor, raw)
	if e != nil {
		return result, e
	}
	review := decOwnerReview(plan, p, input, packet)
	reviewRaw, _ := json.Marshal(review)
	id, e := decRandomID("dint_")
	if e != nil {
		return result, e
	}
	templates := []decIntentTemplate{{1, "owner_offer_packet", base64.StdEncoding.EncodeToString(raw)}}
	if plan.BindingLease == "-" {
		templates = append(templates, decIntentTemplate{2, "binding_lease", "-"})
	}
	templates = append(templates, decIntentTemplate{uint64(len(templates) + 1), "device_lease", "-"}, decIntentTemplate{uint64(len(templates) + 2), "owner_finalization_packet", "-"})
	i := decIntent{ID: id, Network: plan.Descriptor.NetworkID, Context: plan.Descriptor.ContextID, Kind: "owner", Record: decIntentRecord{Format: 1, Operation: p.ID, Approved: input.Approve, ApprovedAt: "-", Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: plan.Provider, Root: plan.Root, Person: input.Person, Host: p.Record.Host, Device: p.Record.Device, Scopes: input.Scopes, NotAfter: input.NotAfter, Created: now, Expires: p.Deadline, Templates: templates, Signatures: []decIntentSignature{}, Terminal: "-", Result: "-"}}
	if input.Approve {
		i.Record.ApprovedAt = now
		facts.add("dec.approval.after_commit")
	}
	p.Descriptor, p.Record.Descriptor, p.Record.OwnerIntent = plan.Descriptor, base64.StdEncoding.EncodeToString(plan.Descriptor.Raw), id
	addDecPendingRole(&p, "owner")
	if e = putDecPending(ctx, tx, p); e != nil {
		return result, e
	}
	if e = storeDecIntent(ctx, tx, i, true); e != nil {
		return result, e
	}
	facts.add("dec.intent.after_commit")
	return s.saveDecOwnerPreparation(ctx, tx, p, i, plan, now)
}

func (s *Store) saveDecOwnerPreparation(ctx context.Context, tx *sql.Tx, p decPending, i decIntent, plan decOwnerPlan, now string) (decApprovalResult, error) {
	var result decApprovalResult
	fresh, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	if fresh >= p.Deadline {
		return result, decFailure("expired")
	}
	plan, e = s.decCurrentOwner(ctx, tx, p, i, fresh)
	if e != nil {
		return result, e
	}
	if i.Record.Approved && i.Record.ApprovedAt == now {
		i.Record.ApprovedAt = fresh
	}
	now = fresh
	components, e := decCatalogComponents(plan.Catalog)
	if e != nil {
		return result, e
	}
	template, e := readDecCeremonyTemplate(plan.Descriptor, i, i.Record.Templates[0])
	if e != nil {
		return result, e
	}
	if p.Record.Owner == "-" {
		if e = decStageFrameCapacity(p, components, len(template.Body)+8192); e != nil {
			return result, e
		}
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return result, e
	}
	if i.Record.Approved {
		clock, _ := json.Marshal(decClockRecord{1, now})
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, i.Network, string(clock)); e != nil {
			return result, e
		}
	}
	result, e = decApprovalResponse(p, i, now)
	if e != nil {
		return result, e
	}
	return result, tx.Commit()
}

func (s *Store) advanceDecOwnerIntent(ctx context.Context, id string) (decApprovalResult, error) {
	var result decApprovalResult
	for n := 0; n < 12; n++ {
		before, e := s.decStageFingerprint(ctx, id)
		if e != nil {
			return result, e
		}
		result, e = s.advanceDecOwnerStep(ctx, id)
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
func (s *Store) advanceDecOwnerStep(ctx context.Context, id string) (result decApprovalResult, err error) {
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
	if p.Record.OwnerIntent == "-" {
		return result, decFailure("state_conflict")
	}
	i, e := readDecIntent(ctx, tx, p.Record.OwnerIntent)
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
	plan, e := s.decCurrentOwner(ctx, tx, p, i, now)
	if e != nil {
		return result, e
	}
	return s.saveDecOwner(ctx, tx, &p, &i, plan, now, &facts)
}

func (s *Store) saveDecOwner(ctx context.Context, tx *sql.Tx, p *decPending, i *decIntent, plan decOwnerPlan, now string, facts *decCommittedFacts) (decApprovalResult, error) {
	var result decApprovalResult
	// Recheck the actual local decision time immediately before any new owned
	// signature. The transaction retains one coherent authority snapshot.
	fresh, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	plan, e = s.decCurrentOwner(ctx, tx, *p, *i, fresh)
	if e != nil {
		return result, e
	}
	now = fresh
	components, e := decCatalogComponents(plan.Catalog)
	if e != nil {
		return result, e
	}
	template, e := readDecCeremonyTemplate(plan.Descriptor, *i, i.Record.Templates[0])
	if e != nil {
		return result, e
	}
	if p.Record.Owner == "-" {
		if e = decStageFrameCapacity(*p, components, len(template.Body)+8192); e != nil {
			return result, e
		}
	}
	phase, e := readDecCeremonyReview(*i)
	if e != nil {
		return result, e
	}
	if phase.Stage == "owner_finalization" && p.Record.Finalization == "-" {
		if e = decStageFrameCapacity(*p, components, dec.MaxObject); e != nil {
			return result, e
		}
	}
	review, e := readDecCeremonyReview(*i)
	if e != nil {
		return result, e
	}
	if review.Stage == "owner_finalization" {
		before, _ := json.Marshal(i.Record.Templates)
		final, e := s.decCurrentFinalization(ctx, tx, *p, *i, review, now)
		if e != nil {
			return result, e
		}
		if e = materializeDecFinalizationPacket(final, *p, i); e != nil {
			return result, e
		}
		after, _ := json.Marshal(i.Record.Templates)
		if !bytes.Equal(before, after) {
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
	}
	before := len(i.Record.Signatures)
	if e = s.signDecCeremonyOwned(plan.Descriptor, i, plan.Seed, now); e != nil {
		return result, e
	}
	if len(i.Record.Signatures) != before {
		facts.add("dec.signature.after_commit")
	}
	if e = storeDecIntent(ctx, tx, *i, false); e != nil {
		return result, e
	}
	complete, e := s.retainDecOwnerPacket(ctx, tx, p, *i, plan, now)
	if e != nil {
		return result, e
	}
	if complete {
		facts.add("dec.owner.after_commit")
	}
	if review.Stage == "owner_finalization" {
		retained, e := s.retainDecFinalization(ctx, tx, p, *i, plan, now)
		if e != nil {
			return result, e
		}
		if retained {
			facts.add("dec.owner_finalization.after_commit")
		}
	}
	if i.Record.Approved {
		clock, _ := json.Marshal(decClockRecord{1, now})
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_clock(network_id,record) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET record=excluded.record`, i.Network, string(clock)); e != nil {
			return result, e
		}
	}
	result, e = decApprovalResponse(*p, *i, now)
	if e != nil {
		return result, e
	}
	return result, tx.Commit()
}

func (s *Store) DecentralizedApproval(ctx context.Context, id string) (decApprovalResult, error) {
	var result decApprovalResult
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return result, e
	}
	i, e := decApprovalIntent(ctx, tx, p)
	if e != nil {
		return result, e
	}
	if !i.Record.Approved {
		return result, decFailure("state_conflict")
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	if i.Kind == "administrator" {
		_, e = s.decCurrentAdministrator(ctx, tx, p, i, now)
	} else {
		_, e = s.decCurrentOwner(ctx, tx, p, i, now)
	}
	if e != nil {
		return result, e
	}
	return decApprovalResponse(p, i, now)
}

func (s *Store) SignedDecentralizedApproval(ctx context.Context, id string, input DecSignatureBatch) (result decApprovalResult, err error) {
	if e := validateDecSignatureBatch(input); e != nil {
		return result, e
	}
	pending, e := s.readDecPendingSnapshot(ctx, id)
	if e != nil {
		return result, e
	}
	if pending.Record.AdministratorIntent == input.Intent {
		return s.advanceDecAdministrator(ctx, id, &input)
	}
	facts := decCommittedFacts{operation: id}
	defer func() {
		if err == nil {
			err = facts.wait(ctx)
		}
		if err == nil {
			result, err = s.advanceDecOwnerIntent(ctx, id)
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
	if p.Record.OwnerIntent != input.Intent {
		return result, decFailure("invalid")
	}
	i, e := readDecIntent(ctx, tx, input.Intent)
	if e != nil {
		return result, e
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return result, e
	}
	plan, e := s.decCurrentOwner(ctx, tx, p, i, now)
	if e != nil {
		return result, e
	}
	components, e := decCatalogComponents(plan.Catalog)
	if e != nil {
		return result, e
	}
	template, e := readDecCeremonyTemplate(plan.Descriptor, i, i.Record.Templates[0])
	if e != nil {
		return result, e
	}
	if p.Record.Owner == "-" {
		if e = decStageFrameCapacity(p, components, len(template.Body)+8192); e != nil {
			return result, e
		}
	}
	review, e := readDecCeremonyReview(i)
	if e != nil {
		return result, e
	}
	if review.Stage == "owner_finalization" && p.Record.Finalization == "-" {
		if e = decStageFrameCapacity(p, components, dec.MaxObject); e != nil {
			return result, e
		}
	}
	before := len(i.Record.Signatures)
	if e = acceptDecCeremonySignatures(plan.Descriptor, &i, input, now); e != nil {
		return result, e
	}
	if len(i.Record.Signatures) != before {
		facts.add("dec.signature.after_commit")
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return result, e
	}
	if retained, e := s.retainDecOwnerPacket(ctx, tx, &p, i, plan, now); e != nil {
		return result, e
	} else if retained {
		facts.add("dec.owner.after_commit")
	}
	if review.Stage == "owner_finalization" {
		if retained, e := s.retainDecFinalization(ctx, tx, &p, i, plan, now); e != nil {
			return result, e
		} else if retained {
			facts.add("dec.owner_finalization.after_commit")
		}
	}
	result, e = decApprovalResponse(p, i, now)
	if e != nil {
		return result, e
	}
	return result, tx.Commit()
}

// Replay requires the same actual current role as initial publication, even
// though its exact signed bytes already survived a prior process.
func (s *Store) checkDecStagePublication(ctx context.Context, id string, frame *dec.Frame) error {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return e
	}
	if containsString(p.Record.Roles, "requester") && p.Record.Selected && (frame.Role == "selection" || frame.Role == "proofs" && p.Record.OwnerIntent == "-") {
		now, e := decCreationClock(ctx, tx, p.Descriptor.NetworkID)
		if e != nil {
			return e
		}
		if _, e = s.decSelectedOwner(ctx, tx, p, p.Record.OwnerID, now); e != nil {
			return e
		}
		plain, e := decOpenPendingFrame(p, frame)
		if e != nil {
			return e
		}
		if frame.Role == "selection" && plain.Packet != p.Record.Selection {
			return decFailure("operation_conflict")
		}
		return checkDecFrameCatalog(p, plain)
	}
	if p.Record.AdministratorIntent != "-" && (frame.Role == "administrator" || frame.Role == "proofs" && p.Record.Administrator != "-") {
		i, e := readDecIntent(ctx, tx, p.Record.AdministratorIntent)
		if e != nil {
			return e
		}
		if !i.Record.Approved {
			return decFailure("review_required")
		}
		now, e := decCreationClock(ctx, tx, i.Network)
		if e != nil {
			return e
		}
		if _, e = s.decCurrentAdministrator(ctx, tx, p, i, now); e != nil {
			return e
		}
		plain, e := decOpenPendingFrame(p, frame)
		if e != nil {
			return e
		}
		if frame.Role == "administrator" && plain.Packet != p.Record.Administrator {
			return decFailure("operation_conflict")
		}
		return checkDecFrameCatalog(p, plain)
	}
	if p.Record.OwnerIntent == "-" {
		return decFailure("review_required")
	}
	i, e := readDecIntent(ctx, tx, p.Record.OwnerIntent)
	if e != nil {
		return e
	}
	if !i.Record.Approved {
		return decFailure("review_required")
	}
	now, e := decCreationClock(ctx, tx, i.Network)
	if e != nil {
		return e
	}
	if now >= p.Deadline {
		return decFailure("expired")
	}
	plan, e := s.decCurrentOwner(ctx, tx, p, i, now)
	if e != nil {
		return e
	}
	plain, _, e := dec.OpenFrame(plan.Descriptor, p.Secret, frame.Raw)
	if e != nil {
		return e
	}
	if frame.Role == "owner" {
		if plain.Packet != p.Record.Owner {
			return decFailure("operation_conflict")
		}
	} else if frame.Role == "owner_finalization" {
		if plain.Packet != p.Record.Finalization {
			return decFailure("operation_conflict")
		}
	} else if frame.Role != "proofs" {
		return decFailure("review_required")
	}
	return checkDecFrameCatalog(p, plain)
}

func checkDecFrameCatalog(p decPending, plain dec.FramePlaintext) error {
	if plain.Catalog != "-" {
		raw, e := decBytes(plain.Catalog, dec.MaxCatalogComponent)
		if e != nil {
			return e
		}
		part, e := dec.ReadCatalog(p.Descriptor, raw)
		if e != nil {
			return e
		}
		if p.Record.Catalog == "-" {
			return decStorageError()
		}
		raw, e = decBytes(p.Record.Catalog, dec.MaxCatalog)
		if e != nil {
			return e
		}
		frozen, e := dec.ReadCatalog(p.Descriptor, raw)
		if e != nil {
			return e
		}
		for _, object := range part.Objects {
			found := false
			for _, old := range frozen.Objects {
				if object.ID == old.ID && object.Kind == old.Kind && bytes.Equal(object.Body, old.Body) {
					found = true
					break
				}
			}
			if !found {
				return decFailure("operation_conflict")
			}
		}
	}
	return nil
}
