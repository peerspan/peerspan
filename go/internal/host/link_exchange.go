package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
)

type linkPlaintext struct {
	RequestID       string          `json:"request_id"`
	Role            string          `json:"role"`
	WriterPublicKey string          `json:"writer_public_key"`
	Packet          json.RawMessage `json:"packet"`
	Catalog         json.RawMessage `json:"catalog"`
}

func linkAbsent(raw []byte) bool { return string(raw) == `"-"` }
func linkFrameUsage(ctx context.Context, tx *sql.Tx, request string) (int, int, error) {
	rows, e := tx.QueryContext(ctx, `SELECT record FROM link_frames WHERE request_id=?`, request)
	if e != nil {
		return 0, 0, e
	}
	defer rows.Close()
	count, total := 0, 0
	for rows.Next() {
		count++
		if count > 64 {
			return 0, 0, linkFail("quota_exceeded", request, "frame")
		}
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return 0, 0, e
		}
		var row struct {
			FrameBase64 string `json:"frame_base64"`
		}
		if linking.DecodeStoredJSON([]byte(raw), "frame_base64", &row) != nil {
			return 0, 0, linkFail("state_conflict", request, "storage")
		}
		frame, e := linkBytes(row.FrameBase64, linking.MaxObject)
		if e != nil {
			return 0, 0, linkFail("state_conflict", request, "storage")
		}
		total += len(frame)
		if total > 512<<10 {
			return 0, 0, linkFail("quota_exceeded", request, "frame")
		}
	}
	return count, total, rows.Err()
}
func decodeLinkPlaintext(p linkPending, frame linkFrame) (linkPlaintext, error) {
	var out linkPlaintext
	raw, e := openLinkFrame(p.Secret, p.Record.CoordinatorPublicKey, frame)
	if e != nil {
		return out, linkFail("invalid", p.ID, "frame")
	}
	if linking.DecodeMutation(raw, "request_id role writer_public_key packet catalog", &out) != nil || out.RequestID != p.ID || out.Role != frame.Role || out.WriterPublicKey != frame.WriterPublicKey || linkAbsent(out.Packet) && linkAbsent(out.Catalog) {
		return out, linkFail("invalid", p.ID, "frame")
	}
	if !linkAbsent(out.Packet) {
		packet, _, e := decodeLinkPacket(out.Packet)
		if e != nil || packet.RequestID != p.ID || packet.Role != frame.Role || packet.WriterPublicKey != frame.WriterPublicKey {
			return out, linkFail("invalid", p.ID, "frame")
		}
	}
	return out, nil
}
func queueLinkPacket(ctx context.Context, tx *sql.Tx, p *linkPending, role, writer string, packet, catalog []byte) error {
	// A published role always resumes its immutable frames, including chunks.
	for _, ref := range p.Record.OutboundFrames {
		if ref.Role == role && ref.WriterPublicKey == writer {
			return nil
		}
	}
	plain := func(packet, catalog json.RawMessage) ([]byte, error) {
		return linkJSON(linkPlaintext{p.ID, role, writer, packet, catalog})
	}
	chunks := [][]byte{}
	packetRaw := json.RawMessage(`"-"`)
	if len(packet) > 0 {
		packetRaw = packet
	}
	if len(catalog) == 0 {
		b, e := plain(packetRaw, json.RawMessage(`"-"`))
		if e != nil {
			return e
		}
		chunks = append(chunks, b)
	} else {
		var envelope struct {
			NetworkID string `json:"network_id"`
		}
		if json.Unmarshal(catalog, &envelope) != nil {
			return linkFail("invalid", p.ID, "catalog")
		}
		c, e := decodeLinkCatalog(catalog, envelope.NetworkID)
		if e != nil {
			return e
		}
		current := linkCatalog{1, c.NetworkID, []linkCatalogObject{}}
		for _, object := range c.Objects {
			candidate := current
			candidate.Objects = append(append([]linkCatalogObject{}, current.Objects...), object)
			b, e := linkJSON(candidate)
			if e != nil {
				return e
			}
			full, e := plain(packetRaw, b)
			if e != nil {
				return e
			}
			if len(full) > linkPlainLimit {
				b, e = linkJSON(current)
				if e != nil {
					return e
				}
				if len(current.Objects) == 0 {
					b = []byte(`"-"`)
				}
				full, e = plain(packetRaw, b)
				if e != nil || len(full) > linkPlainLimit {
					return linkFail("quota_exceeded", p.ID, "frame")
				}
				chunks = append(chunks, full)
				packetRaw = json.RawMessage(`"-"`)
				current = linkCatalog{1, c.NetworkID, []linkCatalogObject{object}}
				b, _ = linkJSON(current)
				full, _ = plain(packetRaw, b)
				if len(full) > linkPlainLimit {
					return linkFail("quota_exceeded", p.ID, "frame")
				}
			} else {
				current = candidate
			}
		}
		b, e := linkJSON(current)
		if e != nil {
			return e
		}
		if len(current.Objects) == 0 {
			b = []byte(`"-"`)
		}
		full, e := plain(packetRaw, b)
		if e != nil {
			return e
		}
		if !linkAbsent(packetRaw) || len(current.Objects) > 0 {
			chunks = append(chunks, full)
		}
	}
	if len(chunks) == 0 {
		return linkFail("invalid", p.ID, "frame")
	}
	count, total, e := linkFrameUsage(ctx, tx, p.ID)
	if e != nil {
		return e
	}
	if count+len(chunks) > 64 {
		return linkFail("quota_exceeded", p.ID, "frame")
	}
	type sealed struct {
		frame linkFrame
		raw   []byte
	}
	frames := []sealed{}
	for _, chunk := range chunks {
		frame, raw, e := sealLinkFrame(p.Secret, p.Record.CoordinatorPublicKey, p.ID, role, writer, chunk)
		if e != nil {
			return e
		}
		total += len(raw)
		if total > 512<<10 {
			return linkFail("quota_exceeded", p.ID, "frame")
		}
		frames = append(frames, sealed{frame, raw})
	}
	for _, entry := range frames {
		if _, e := storeLinkFrame(ctx, tx, p, entry.frame, entry.raw); e != nil {
			return e
		}
		p.Record.OutboundFrames = append(p.Record.OutboundFrames, linkOutboundFrame{Role: role, WriterPublicKey: writer, FrameID: entry.frame.FrameID})
	}
	return nil
}
func (s *Store) saveLinkPending(ctx context.Context, p linkPending) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = putLinkPending(ctx, tx, p); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) linkMailbox(ctx context.Context, p linkPending, after uint64) (linkMailbox, error) {
	raw, e := s.linkCoordinator(ctx, linkPendingNetwork(p), http.MethodGet, "/coord/v2/link-mailboxes/"+linkLocator(p.Secret)+"?after="+strconv.FormatUint(after, 10), nil)
	if e != nil {
		return linkMailbox{}, e
	}
	box, e := decodeLinkMailbox(raw)
	if e != nil {
		return box, e
	}
	if box.RequestID != p.ID || box.Locator != linkLocator(p.Secret) || box.ExpiresAt != p.Deadline {
		return box, linkFail("invalid", p.ID, "mailbox")
	}
	return box, nil
}
func (s *Store) linkPollDue(coordinator string, secret []byte, now time.Time) bool {
	last := s.linkPolls[coordinator+"|"+linkLocator(secret)]
	return last.IsZero() || now.Before(last) || now.Sub(last) >= 2*time.Second
}
func (s *Store) linkPolled(coordinator string, secret []byte, now time.Time) {
	if s.linkPolls == nil {
		s.linkPolls = map[string]time.Time{}
	}
	s.linkPolls[coordinator+"|"+linkLocator(secret)] = now
}
func (s *Store) receiveLinkFrames(ctx context.Context, p *linkPending) error {
	now, e := linkNow()
	if e != nil {
		return e
	}
	if !s.linkPollDue(p.Record.CoordinatorPublicKey, p.Secret, now) {
		return nil
	}
	box, e := s.linkMailbox(ctx, *p, p.Record.AfterSequence)
	if e != nil {
		return e
	}
	if e = s.receiveLinkMailbox(ctx, p, box); e != nil {
		return e
	}
	s.linkPolled(p.Record.CoordinatorPublicKey, p.Secret, now)
	return nil
}
func (s *Store) receiveLinkMailbox(ctx context.Context, p *linkPending, box linkMailbox) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	persisted := false
	for _, row := range box.Frames {
		if row.Sequence <= p.Record.AfterSequence {
			continue
		}
		frame, e := decodeLinkFrame(row.Frame)
		if e != nil {
			return e
		}
		if _, e = decodeLinkPlaintext(*p, frame); e != nil {
			return e
		}
		inserted, e := storeLinkFrame(ctx, tx, p, frame, row.Frame)
		if e != nil {
			return e
		}
		persisted = persisted || inserted
		p.Record.AfterSequence = row.Sequence
	}
	if _, _, e = linkFrameUsage(ctx, tx, p.ID); e != nil {
		return e
	}
	if e = putLinkPending(ctx, tx, *p); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if persisted {
		return linkBarrier(ctx, "host.frame.after_commit", p.ID)
	}
	return nil
}
func (s *Store) retainedLinkPackets(ctx context.Context, p linkPending) (map[string][][]byte, [][]byte, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT record FROM link_frames WHERE request_id=? ORDER BY role,writer_key,frame_id`, p.ID)
	if e != nil {
		return nil, nil, e
	}
	stored := []string{}
	for rows.Next() {
		var record string
		if e = rows.Scan(&record); e != nil {
			_ = rows.Close()
			return nil, nil, e
		}
		stored = append(stored, record)
	}
	e = rows.Err()
	_ = rows.Close()
	if e != nil {
		return nil, nil, e
	}
	packets := map[string][][]byte{}
	catalogs := [][]byte{}
	for _, record := range stored {
		var row struct {
			FrameBase64 string `json:"frame_base64"`
		}
		if linking.DecodeStoredJSON([]byte(record), "frame_base64", &row) != nil {
			return nil, nil, linkFail("state_conflict", p.ID, "storage")
		}
		raw, e := linkBytes(row.FrameBase64, linking.MaxObject)
		if e != nil {
			return nil, nil, e
		}
		frame, e := decodeLinkFrame(raw)
		if e != nil {
			return nil, nil, e
		}
		plain, e := decodeLinkPlaintext(p, frame)
		if e != nil {
			return nil, nil, e
		}
		if !linkAbsent(plain.Packet) {
			packets[plain.Role] = append(packets[plain.Role], plain.Packet)
		}
		if !linkAbsent(plain.Catalog) {
			catalogs = append(catalogs, plain.Catalog)
		}
	}
	for role := range packets {
		sort.Slice(packets[role], func(i, j int) bool { return string(packets[role][i]) < string(packets[role][j]) })
	}
	return packets, catalogs, nil
}
func pendingLinkContext(p linkPending, now time.Time) (linking.ActivationContext, []byte, error) {
	network, e := linkBytes(p.Record.NetworkBase64, linking.MaxObject)
	if e != nil {
		return linking.ActivationContext{}, nil, e
	}
	catalog, e := linkBytes(p.Record.CatalogBase64, linking.MaxStoredCatalog)
	if e != nil {
		return linking.ActivationContext{}, nil, e
	}
	var descriptor linkDescriptor
	if linking.DecodeMutation(network, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &descriptor) != nil || descriptor.CoordinatorAddress != p.Record.CoordinatorAddress || descriptor.CoordinatorPublicKey != p.Record.CoordinatorPublicKey {
		return linking.ActivationContext{}, nil, linkFail("invalid", p.ID, "coordinator")
	}
	objects, e := decodeLinkCatalog(catalog, descriptor.NetworkID)
	if e != nil {
		return linking.ActivationContext{}, nil, e
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return linking.ActivationContext{}, nil, e
	}
	feature := "-"
	facts, e := linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: network, Epoch: epoch, KnownFeatureID: "-", Now: now}, catalog)
	if e != nil {
		return linking.ActivationContext{}, nil, e
	}
	feature = facts.Facts.FeatureID
	return linking.ActivationContext{Network: network, Epoch: epoch, KnownFeatureID: feature, CallerHostPublicKey: p.Record.HostPublicKey, ExpectedPersonPublicKey: p.Record.ExpectedPersonPublicKey, Now: now, Verification: "first"}, catalog, nil
}
func (s *Store) refreshLinkOffers(ctx context.Context, p *linkPending, now time.Time, poll ...bool) error {
	if len(poll) == 0 || poll[0] {
		if e := s.receiveLinkFrames(ctx, p); e != nil {
			return e
		}
	}
	packets, catalogs, e := s.retainedLinkPackets(ctx, *p)
	if e != nil {
		return e
	}
	if p.Record.CatalogBase64 != "-" {
		prior, e := linkBytes(p.Record.CatalogBase64, linking.MaxStoredCatalog)
		if e != nil {
			return e
		}
		catalogs = append(catalogs, prior)
	}
	networkID := ""
	if p.Record.NetworkBase64 != "-" {
		var n linkDescriptor
		raw, _ := linkBytes(p.Record.NetworkBase64, linking.MaxObject)
		if json.Unmarshal(raw, &n) != nil {
			return linkFail("state_conflict", p.ID, "storage")
		}
		networkID = n.NetworkID
	}
	if networkID == "" {
		for _, raw := range packets["owner"] {
			_, body, e := decodeLinkPacket(raw)
			if e != nil {
				continue
			}
			var owner struct {
				Network json.RawMessage `json:"network"`
			}
			if json.Unmarshal(body, &owner) != nil {
				continue
			}
			var n linkDescriptor
			if linking.DecodeMutation(owner.Network, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &n) != nil || n.CoordinatorAddress != p.Record.CoordinatorAddress || n.CoordinatorPublicKey != p.Record.CoordinatorPublicKey || p.Record.ExpectedNetworkID != "-" && n.NetworkID != p.Record.ExpectedNetworkID {
				continue
			}
			networkID = n.NetworkID
			p.Record.NetworkBase64 = base64.StdEncoding.EncodeToString(owner.Network)
			break
		}
	}
	if networkID == "" || len(catalogs) == 0 {
		return nil
	}
	catalog, e := mergeLinkCatalog(networkID, catalogs...)
	if e != nil {
		return e
	}
	p.Record.CatalogBase64 = base64.StdEncoding.EncodeToString(catalog)
	verification, catalog, e := pendingLinkContext(*p, now)
	if e != nil {
		return e
	}
	request, e := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
	if e != nil {
		return e
	}
	if !p.Record.SelectionApproved && p.Role != "approver" {
		bestID, bestPacket := "", []byte(nil)
		for _, candidate := range packets["owner"] {
			proof, e := linking.VerifyStoredOwnerOffer(verification, catalog, request, candidate)
			if e != nil {
				continue
			}
			if bestID == "" || proof.OwnerOfferID < bestID {
				bestID, bestPacket = proof.OwnerOfferID, candidate
			}
		}
		if bestID != "" {
			p.Record.OwnerOfferID, p.Record.OwnerPacketBase64 = bestID, base64.StdEncoding.EncodeToString(bestPacket)
			p.State = "waiting_selection"
		}
	}
	if p.Record.OwnerPacketBase64 != "-" {
		owner, _ := linkBytes(p.Record.OwnerPacketBase64, linking.MaxObject)
		if p.Role == "approver" && p.Record.SelectionPacketBase64 == "-" {
			for _, candidate := range packets["selection"] {
				proof, e := linking.VerifyStoredSelection(verification, catalog, request, owner, candidate)
				if e == nil {
					p.Record.SelectionID, p.Record.SelectionPacketBase64 = proof.SelectionID, base64.StdEncoding.EncodeToString(candidate)
					break
				}
			}
		}
		if p.Record.SelectionPacketBase64 != "-" {
			selection, _ := linkBytes(p.Record.SelectionPacketBase64, linking.MaxObject)
			for _, candidate := range packets["administrator"] {
				proof, e := linking.VerifyStoredAdministratorOffer(verification, catalog, request, owner, selection, candidate)
				if e == nil && (p.Record.AdministratorOfferID == "-" || proof.AdministratorOfferID < p.Record.AdministratorOfferID) {
					p.Record.AdministratorOfferID, p.Record.AdministratorPacketBase64 = proof.AdministratorOfferID, base64.StdEncoding.EncodeToString(candidate)
				}
			}
			if p.Role != "approver" && !p.Record.CommitApproved && (p.Role == "renew" || p.Record.AdministratorPacketBase64 != "-") {
				p.State = "ready_to_commit"
			}
		}
	}
	return s.saveLinkPending(ctx, *p)
}
