package host

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func linkTerminal(state string) bool {
	return state == "linked" || state == "cancelled" || state == "expired"
}
func (s *Store) retireExpiredLink(ctx context.Context, p *linkPending, now time.Time) error {
	deadline, e := linkStamp(p.Deadline)
	if e != nil {
		return e
	}
	if now.Before(deadline) || p.Record.CommitApproved || p.State == "linked" || len(p.Secret) == 0 {
		return nil
	}
	p.Secret = nil
	if p.Role == "approver" {
		p.State = "incomplete"
	} else {
		p.State = "expired"
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = putLinkPending(ctx, tx, *p); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM link_frames WHERE request_id=?`, p.ID); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) linkView(p linkPending, now time.Time) LinkRequestView {
	r := p.Record
	network, person := r.ExpectedNetworkID, r.ExpectedPersonPublicKey
	if r.NetworkBase64 != "-" {
		if b, e := linkBytes(r.NetworkBase64, linking.MaxObject); e == nil {
			var n struct {
				NetworkID string `json:"network_id"`
			}
			if json.Unmarshal(b, &n) == nil {
				network = n.NetworkID
			}
		}
	}
	if r.OwnerPacketBase64 != "-" {
		if b, e := linkBytes(r.OwnerPacketBase64, linking.MaxObject); e == nil {
			packet, _, e := decodeLinkPacket(b)
			if e == nil {
				person = packet.PersonPublicKey
			}
		}
	}
	personID := "-"
	if key, e := membership.DecodeKey(person); e == nil {
		personID = membership.PersonID(key)
	}
	hostID := "-"
	if key, e := membership.DecodeKey(r.HostPublicKey); e == nil {
		hostID = membership.HostID(key)
	}
	state := p.State
	until, e := linkStamp(p.Deadline)
	if e == nil && !now.Before(until) && !r.CommitApproved && !linkTerminal(state) {
		state = "expired"
	}
	out := LinkRequestView{RequestID: p.ID, Mode: p.Role, State: state, NetworkID: network, PersonID: personID, HostID: hostID, DeviceFingerprint: linkFingerprint(r.DevicePublicKey), ExpiresAt: p.Deadline, Completed: []string{"request_created"}, Attention: []string{}, Next: []string{}}
	if p.Role == "approver" {
		if packet, e := linkBytes(r.RequestPacketBase64, linking.MaxObject); e == nil {
			_, body, e := decodeLinkPacket(packet)
			if e == nil {
				var v struct {
					Mode string `json:"mode"`
				}
				if json.Unmarshal(body, &v) == nil {
					out.Mode = v.Mode
				}
			}
		}
	}
	if r.OwnerPacketBase64 != "-" {
		out.Completed = append(out.Completed, "owner_offered")
	}
	if r.SelectionPacketBase64 != "-" {
		out.Completed = append(out.Completed, "owner_selected")
	}
	if r.AdministratorPacketBase64 != "-" {
		out.Completed = append(out.Completed, "administrator_offered")
	}
	if r.CommitApproved && r.CommitPacketBase64 != "-" {
		out.Completed = append(out.Completed, "commit_persisted")
	}
	if p.State == "linked" {
		out.Completed = append(out.Completed, "locally_applied")
	}
	switch state {
	case "waiting_owner":
		out.Next = []string{"approve_on_existing_machine"}
	case "waiting_selection":
		out.Next = []string{"select_owner_offer"}
	case "awaiting_administrator":
		out.Next = []string{"admit_on_administrator_machine"}
	case "ready_to_commit":
		out.Next = []string{"review_and_commit"}
	case "finalizing":
		out.Next = []string{"resume"}
		out.Attention = []string{"commit_outcome_pending"}
	case "review":
		out.Next = []string{"review_and_approve"}
	case "offer_sent":
		out.Next = []string{"continue_on_requesting_machine"}
	case "incomplete":
		out.Next = []string{"repair_same_identity"}
		out.Attention = []string{"authority_incomplete"}
	case "expired":
		out.Next = []string{"create_fresh_request"}
	}
	return out
}
func (s *Store) pendingLinkIDs(ctx context.Context) ([]string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT request_id FROM link_pending ORDER BY request_id`)
	if e != nil {
		return nil, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			_ = rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	_ = rows.Close()
	return ids, e
}
func (s *Store) LinkRequests(ctx context.Context) ([]LinkRequestView, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	now, e := linkNow()
	if e != nil {
		return nil, e
	}
	ids, e := s.pendingLinkIDs(ctx)
	if e != nil {
		return nil, e
	}
	out := []LinkRequestView{}
	for _, id := range ids {
		p, e := readLinkPending(ctx, s.db, id)
		if e != nil {
			return nil, e
		}
		if e = s.retireExpiredLink(ctx, &p, now); e != nil {
			return nil, e
		}
		out = append(out, s.linkView(p, now))
	}
	return out, nil
}
func (s *Store) LinkRequest(ctx context.Context, id string) (LinkRequestView, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	now, e := linkNow()
	if e != nil {
		return LinkRequestView{}, e
	}
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkRequestView{}, e
	}
	if e = s.retireExpiredLink(ctx, &p, now); e != nil {
		return LinkRequestView{}, e
	}
	return s.linkView(p, now), nil
}
func (s *Store) resolveLinkRequest(ctx context.Context, r CreateLinkRequest) (CreateLinkRequest, *Network, string, error) {
	if r.Mode != "new" && r.Mode != "renew" || r.NetworkID != "-" && !linkID(r.NetworkID, "net_") || r.PersonPublicKey != "-" && !linkPublicKey(r.PersonPublicKey) {
		return r, nil, "", linkFail("invalid", "-", "request")
	}
	var known *Network
	if r.NetworkID != "-" {
		n, e := s.Network(ctx, r.NetworkID)
		if e == nil {
			known = &n
			if r.CoordinatorAddress != "-" && r.CoordinatorAddress != n.CoordinatorAddress || r.CoordinatorPublicKey != "-" && r.CoordinatorPublicKey != n.CoordinatorPublicKey {
				return r, nil, "", linkFail("invalid", "-", "coordinator")
			}
			r.CoordinatorAddress, r.CoordinatorPublicKey = n.CoordinatorAddress, n.CoordinatorPublicKey
		} else if !errors.Is(e, ErrNotFound) {
			return r, nil, "", e
		}
	}
	if r.CoordinatorAddress == "-" && r.CoordinatorPublicKey == "-" {
		defaults, e := withDefaultCoordinator(CreateNetwork{})
		if e != nil {
			return r, nil, "", linkFail("invalid", "-", "coordinator")
		}
		r.CoordinatorAddress, r.CoordinatorPublicKey = defaults.CoordinatorAddress, defaults.CoordinatorPublicKey
	}
	if !membership.ValidCoordinatorAddress(r.CoordinatorAddress) || !linkPublicKey(r.CoordinatorPublicKey) {
		return r, nil, "", linkFail("invalid", "-", "coordinator")
	}
	device := ""
	if r.Mode == "renew" {
		if known == nil {
			return r, nil, "", linkFail("proof_required", "-", "renewal")
		}
		var person, certificate string
		e := s.db.QueryRowContext(ctx, `SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?`, r.NetworkID).Scan(&person, &device, &certificate)
		if errors.Is(e, sql.ErrNoRows) {
			return r, nil, "", linkFail("proof_required", "-", "renewal")
		}
		if e != nil {
			return r, nil, "", e
		}
		if !linkPublicKey(person) || !linkPublicKey(device) || !linkID(certificate, "dc_") {
			return r, nil, "", linkFail("state_conflict", "-", "storage")
		}
		if r.PersonPublicKey != "-" && r.PersonPublicKey != person {
			return r, nil, "", linkFail("invalid", "-", "renewal")
		}
		r.PersonPublicKey = person
		if _, e = loadLinkDevice(ctx, s.db, device); e != nil {
			return r, nil, "", e
		}
	}
	return r, known, device, nil
}
func (s *Store) CreateLinkRequest(ctx context.Context, input CreateLinkRequest) (LinkRequestResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	now, e := linkNow()
	if e != nil {
		return LinkRequestResult{}, e
	}
	r, network, device, e := s.resolveLinkRequest(ctx, input)
	if e != nil {
		return LinkRequestResult{}, e
	}
	ids, e := s.pendingLinkIDs(ctx)
	if e != nil {
		return LinkRequestResult{}, e
	}
	reuseDeadline := ""
	for _, id := range ids {
		p, e := readLinkPending(ctx, s.db, id)
		if e != nil {
			return LinkRequestResult{}, e
		}
		if e = s.retireExpiredLink(ctx, &p, now); e != nil {
			return LinkRequestResult{}, e
		}
		v := s.linkView(p, now)
		old := p.Record
		if p.Role == r.Mode && !linkTerminal(v.State) && old.ExpectedNetworkID == r.NetworkID && old.ExpectedPersonPublicKey == r.PersonPublicKey && old.CoordinatorAddress == r.CoordinatorAddress && old.CoordinatorPublicKey == r.CoordinatorPublicKey && old.HostPublicKey == s.identity.PublicKey {
			if len(p.Secret) != 16 {
				return LinkRequestResult{}, linkFail("state_conflict", p.ID, "storage")
			}
			if e = s.publishLinkFrames(ctx, &p); e != nil {
				return LinkRequestResult{}, e
			}
			return LinkRequestResult{s.linkView(p, now), linkCode(p.Secret)}, nil
		}
		if r.Mode == "new" && p.Role == "new" && (v.State == "cancelled" || v.State == "expired") && !p.Record.CommitApproved && p.Deadline > reuseDeadline && old.ExpectedNetworkID == r.NetworkID && old.ExpectedPersonPublicKey == r.PersonPublicKey && old.CoordinatorAddress == r.CoordinatorAddress && old.CoordinatorPublicKey == r.CoordinatorPublicKey && old.HostPublicKey == s.identity.PublicKey {
			revoked := false
			if old.NetworkBase64 != "-" && old.CatalogBase64 != "-" {
				verification, catalog, err := pendingLinkContext(p, now)
				if err == nil {
					facts, err := linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: verification.Network, Epoch: verification.Epoch, KnownFeatureID: verification.KnownFeatureID, Now: now}, catalog)
					if err == nil {
						for subject, excluded := range facts.Facts.State.RevokedDevices {
							if excluded && subject.DevicePublicKey == old.DevicePublicKey {
								revoked = true
							}
						}
					}
				}
			}
			if !revoked {
				if _, err := loadLinkDevice(ctx, s.db, old.DevicePublicKey); err != nil {
					return LinkRequestResult{}, err
				}
				device, reuseDeadline = old.DevicePublicKey, p.Deadline
			}
		}
	}
	var nonce [32]byte
	var secret [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return LinkRequestResult{}, e
	}
	if _, e = rand.Read(secret[:]); e != nil {
		return LinkRequestResult{}, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return LinkRequestResult{}, e
	}
	defer tx.Rollback()
	if device == "" {
		device, _, e = createLinkDevice(ctx, tx, linkTime(now))
		if e != nil {
			return LinkRequestResult{}, e
		}
	}
	record := emptyLinkRecord()
	record.ExpectedNetworkID = r.NetworkID
	record.ExpectedPersonPublicKey = r.PersonPublicKey
	record.CoordinatorAddress = r.CoordinatorAddress
	record.CoordinatorPublicKey = r.CoordinatorPublicKey
	record.HostPublicKey = s.identity.PublicKey
	record.DevicePublicKey = device
	record.RequestNonce = base64.StdEncoding.EncodeToString(nonce[:])
	if network != nil {
		descriptor, e := linkJSON(linkNetworkDescriptor(*network))
		if e != nil {
			return LinkRequestResult{}, e
		}
		record.NetworkBase64 = base64.StdEncoding.EncodeToString(descriptor)
	}
	id := "link_" + linkHash(linkMessage("peerspan-link-request-id-v1", r.CoordinatorPublicKey, s.identity.PublicKey, device, record.RequestNonce))
	p := linkPending{ID: id, Role: r.Mode, State: "waiting_owner", Deadline: linkTime(now.Add(300 * time.Second)), Record: record, Secret: secret[:]}
	renewed := "-"
	if r.Mode == "renew" {
		if e = tx.QueryRowContext(ctx, `SELECT certificate_id FROM link_signers WHERE network_id=?`, r.NetworkID).Scan(&renewed); e != nil {
			return LinkRequestResult{}, e
		}
	}
	payload, e := linkJSON(map[string]any{"mode": r.Mode, "host_public_key": s.identity.PublicKey, "device_public_key": device, "request_nonce": record.RequestNonce, "coordinator_address": r.CoordinatorAddress, "coordinator_public_key": r.CoordinatorPublicKey, "created_at": linkTime(now), "expires_at": p.Deadline, "expected_network_id": r.NetworkID, "expected_person_public_key": r.PersonPublicKey, "renewed_certificate_id": renewed})
	if e != nil {
		return LinkRequestResult{}, e
	}
	packet, _, e := s.signRequesterPacket(ctx, tx, p, "request", "-", payload)
	if e != nil {
		return LinkRequestResult{}, e
	}
	p.Record.RequestPacketBase64 = base64.StdEncoding.EncodeToString(packet)
	plaintext, e := linkJSON(map[string]any{"request_id": id, "role": "request", "writer_public_key": s.identity.PublicKey, "packet": json.RawMessage(packet), "catalog": "-"})
	if e != nil {
		return LinkRequestResult{}, e
	}
	frame, raw, e := sealLinkFrame(p.Secret, r.CoordinatorPublicKey, id, "request", s.identity.PublicKey, plaintext)
	if e != nil {
		return LinkRequestResult{}, e
	}
	if _, e = storeLinkFrame(ctx, tx, &p, frame, raw); e != nil {
		return LinkRequestResult{}, e
	}
	p.Record.OutboundFrames = append(p.Record.OutboundFrames, linkOutboundFrame{Role: frame.Role, WriterPublicKey: frame.WriterPublicKey, FrameID: frame.FrameID})
	if e = putLinkPending(ctx, tx, p); e != nil {
		return LinkRequestResult{}, e
	}
	if e = appendEvent(ctx, tx, "link.request_created", id, linkTime(now)); e != nil {
		return LinkRequestResult{}, e
	}
	if e = tx.Commit(); e != nil {
		return LinkRequestResult{}, e
	}
	if e = linkBarrier(ctx, "host.request.after_commit", id); e != nil {
		return LinkRequestResult{}, e
	}
	if e = linkBarrier(ctx, "host.frame.after_commit", id); e != nil {
		return LinkRequestResult{}, e
	}
	if p.Role != "approver" {
		if e = s.publishLinkFrames(ctx, &p); e != nil {
			return LinkRequestResult{}, e
		}
	}
	if p.Record.CommitApproved {
		s.syncing.Lock()
		e = s.finalizeLinkOperation(ctx, &p, now)
		s.syncing.Unlock()
		if e != nil {
			return LinkRequestResult{}, e
		}
	} else if e = s.refreshLinkOffers(ctx, &p, now); e != nil {
		return LinkRequestResult{}, e
	}
	if p.Role == "approver" {
		s.syncing.Lock()
		if p.Record.OwnerIntent.Intent != nil && p.Record.OwnerIntent.Intent.Approved {
			e = s.advanceLinkIntent(ctx, &p, false, "", "", now)
		}
		if e == nil && p.Record.AdministratorIntent.Intent != nil && p.Record.AdministratorIntent.Intent.Approved && p.Record.SelectionPacketBase64 != "-" {
			e = s.advanceLinkIntent(ctx, &p, true, "", "", now)
		}
		s.syncing.Unlock()
		if e != nil {
			return LinkRequestResult{}, e
		}
	}
	if linkTerminal(p.State) {
		return LinkRequestResult{LinkRequestView: s.linkView(p, now)}, nil
	}
	return LinkRequestResult{s.linkView(p, now), linkCode(p.Secret)}, nil
}
func (s *Store) ResumeLinkRequest(ctx context.Context, id string) (LinkRequestResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	now, e := linkNow()
	if e != nil {
		return LinkRequestResult{}, e
	}
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkRequestResult{}, e
	}
	view := s.linkView(p, now)
	if e = s.retireExpiredLink(ctx, &p, now); e != nil {
		return LinkRequestResult{}, e
	}
	if linkTerminal(view.State) {
		return LinkRequestResult{LinkRequestView: view}, nil
	}
	if p.Role == "approver" && len(p.Secret) == 0 {
		return LinkRequestResult{LinkRequestView: s.linkView(p, now)}, nil
	}
	if len(p.Secret) != 16 {
		return LinkRequestResult{}, linkFail("state_conflict", id, "storage")
	}
	if p.Role != "approver" {
		if e = s.publishLinkFrames(ctx, &p); e != nil {
			return LinkRequestResult{}, e
		}
	}
	if p.Record.CommitApproved {
		s.syncing.Lock()
		e = s.finalizeLinkOperation(ctx, &p, now)
		s.syncing.Unlock()
		if e != nil {
			return LinkRequestResult{}, e
		}
	} else if e = s.refreshLinkOffers(ctx, &p, now); e != nil {
		return LinkRequestResult{}, e
	}
	if p.Role == "approver" {
		s.syncing.Lock()
		if p.Record.OwnerIntent.Intent != nil && p.Record.OwnerIntent.Intent.Approved {
			e = s.advanceLinkIntent(ctx, &p, false, "", "", now)
		}
		if e == nil && p.Record.AdministratorIntent.Intent != nil && p.Record.AdministratorIntent.Intent.Approved && p.Record.SelectionPacketBase64 != "-" {
			e = s.advanceLinkIntent(ctx, &p, true, "", "", now)
		}
		s.syncing.Unlock()
		if e != nil {
			return LinkRequestResult{}, e
		}
	}
	if linkTerminal(p.State) {
		return LinkRequestResult{LinkRequestView: s.linkView(p, now)}, nil
	}
	return LinkRequestResult{s.linkView(p, now), linkCode(p.Secret)}, nil
}
func (s *Store) CancelLinkRequest(ctx context.Context, id string) (LinkRequestView, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	now, e := linkNow()
	if e != nil {
		return LinkRequestView{}, e
	}
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkRequestView{}, e
	}
	if s.publicDecRuntime() && (p.Record.CommitApproved || p.Record.CommitPacketBase64 != "-") {
		return LinkRequestView{}, linkFail("recovery_required", id, "resume")
	}
	if p.State == "linked" {
		return s.linkView(p, now), nil
	}
	if p.Role == "approver" {
		if p.Record.OwnerPacketBase64 != "-" || p.Record.AdministratorPacketBase64 != "-" {
			p.State = "offer_sent"
		} else {
			p.State = "incomplete"
		}
		p.Secret = nil
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return LinkRequestView{}, e
		}
		defer tx.Rollback()
		if e = putLinkPending(ctx, tx, p); e != nil {
			return LinkRequestView{}, e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM link_frames WHERE request_id=?`, id); e != nil {
			return LinkRequestView{}, e
		}
		if e = tx.Commit(); e != nil {
			return LinkRequestView{}, e
		}
		return s.linkView(p, now), nil
	}
	if p.Record.CommitApproved {
		p.State = "finalizing"
		return s.linkView(p, now), s.saveLinkPending(ctx, p)
	}
	if p.State == "cancelled" {
		return s.linkView(p, now), nil
	}
	if len(p.Secret) != 16 {
		return LinkRequestView{}, linkFail("state_conflict", id, "storage")
	}
	secret := append([]byte{}, p.Secret...)
	p.Secret = nil
	p.State = "cancelled"
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return LinkRequestView{}, e
	}
	defer tx.Rollback()
	if e = putLinkPending(ctx, tx, p); e != nil {
		return LinkRequestView{}, e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM link_frames WHERE request_id=?`, id); e != nil {
		return LinkRequestView{}, e
	}
	if e = appendEvent(ctx, tx, "link.cancelled", id, linkTime(now)); e != nil {
		return LinkRequestView{}, e
	}
	if e = tx.Commit(); e != nil {
		return LinkRequestView{}, e
	}
	// In the coordinator-free runtime a retained legacy attempt is cancelled
	// locally only; no legacy coordinator mutation is sent (as in Rust).
	if s.publicDecRuntime() {
		return s.linkView(p, now), nil
	}
	_, e = s.linkCoordinator(ctx, linkPendingNetwork(p), http.MethodDelete, "/coord/v2/link-mailboxes/"+linkLocator(secret), nil)
	if e != nil {
		var f *linkFailure
		if !errors.As(e, &f) || f.Code != "not_found" {
			return s.linkView(p, now), e
		}
	}
	return s.linkView(p, now), nil
}

// RunLinking resumes only existing approved work. It never supplies consent or
// creates an identity. External SSH slots remain private local CLI work.
func (s *Store) RunLinking(ctx context.Context) {
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		ids, e := s.pendingLinkIDs(ctx)
		if e == nil {
			for _, id := range ids {
				p, err := readLinkPending(ctx, s.db, id)
				if err != nil {
					continue
				}
				approved := p.Role == "approver" && p.Record.OwnerPacketBase64 != "-" && p.Record.AdministratorPacketBase64 == "-" && p.Record.AdministratorIntent.Intent != nil && p.Record.AdministratorIntent.Intent.Approved
				if p.State == "finalizing" || approved {
					_, _ = s.ResumeLinkRequest(ctx, id)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
