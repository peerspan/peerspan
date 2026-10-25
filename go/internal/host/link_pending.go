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

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkPending struct {
	ID, Role, State, Deadline string
	Record                    linkRecord
	Secret                    []byte
}
type linkPacket struct {
	Format             uint64 `json:"format"`
	RequestID          string `json:"request_id"`
	Role               string `json:"role"`
	WriterPublicKey    string `json:"writer_public_key"`
	PersonPublicKey    string `json:"person_public_key"`
	CertificateID      string `json:"certificate_id"`
	PayloadBase64      string `json:"payload_base64"`
	HostSignature      string `json:"host_signature"`
	DeviceSignature    string `json:"device_signature"`
	AuthoritySignature string `json:"authority_signature"`
}

const linkPacketFields = "format request_id role writer_public_key person_public_key certificate_id payload_base64 host_signature device_signature authority_signature"

func decodeLinkPacket(raw []byte) (linkPacket, []byte, error) {
	var p linkPacket
	if e := linking.DecodeMutation(raw, linkPacketFields, &p); e != nil {
		return p, nil, e
	}
	b, e := linkBytes(p.PayloadBase64, linking.MaxPayload)
	return p, b, e
}
func packetLinkMessage(p linkPacket, payload []byte) []byte {
	return linkMessage("peerspan-link-packet-v1", p.RequestID, p.Role, p.WriterPublicKey, p.PersonPublicKey, p.CertificateID, linkHash(payload))
}
func createLinkDevice(ctx context.Context, tx *sql.Tx, now string) (string, ed25519.PrivateKey, error) {
	var seed [32]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return "", nil, e
	}
	key := ed25519.NewKeyFromSeed(seed[:])
	public := membership.EncodeKey(key.Public().(ed25519.PublicKey))
	if _, e := tx.ExecContext(ctx, `INSERT INTO link_device_keys(public_key,seed,created_at) VALUES(?,?,?)`, public, seed[:], now); e != nil {
		return "", nil, e
	}
	return public, key, nil
}
func loadLinkDevice(ctx context.Context, q dbQuerier, public string) (ed25519.PrivateKey, error) {
	var seed []byte
	var created string
	if e := q.QueryRowContext(ctx, `SELECT seed,created_at FROM link_device_keys WHERE public_key=?`, public).Scan(&seed, &created); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return nil, linkFail("proof_required", "-", "signer")
		}
		return nil, e
	}
	if len(seed) != 32 {
		return nil, linkFail("state_conflict", "-", "storage")
	}
	if _, e := linkStamp(created); e != nil {
		return nil, linkFail("state_conflict", "-", "storage")
	}
	key := ed25519.NewKeyFromSeed(seed)
	if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != public {
		return nil, linkFail("state_conflict", "-", "storage")
	}
	return key, nil
}
func readLinkPending(ctx context.Context, q dbQuerier, id string) (linkPending, error) {
	p := linkPending{ID: id}
	var raw string
	e := q.QueryRowContext(ctx, `SELECT role,state,deadline,record,secret FROM link_pending WHERE request_id=?`, id).Scan(&p.Role, &p.State, &p.Deadline, &raw, &p.Secret)
	if errors.Is(e, sql.ErrNoRows) {
		return p, linkFail("not_found", id, "request")
	}
	if e != nil {
		return p, e
	}
	p.Record, e = decodeLinkRecord([]byte(raw))
	if e != nil {
		return p, linkFail("state_conflict", id, "storage")
	}
	if !linkID(id, "link_") || p.Role != "new" && p.Role != "renew" && p.Role != "approver" || len(p.Secret) != 0 && len(p.Secret) != 16 {
		return p, linkFail("state_conflict", id, "storage")
	}
	if _, e = linkStamp(p.Deadline); e != nil {
		return p, linkFail("state_conflict", id, "storage")
	}
	request, e := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
	if e != nil {
		return p, linkFail("state_conflict", id, "storage")
	}
	packet, body, e := decodeLinkPacket(request)
	if e != nil {
		return p, linkFail("state_conflict", id, "storage")
	}
	proof, e := linking.Read("packet", request, p.Record.HostPublicKey, p.Record.DevicePublicKey)
	if e != nil || packet.RequestID != id || packet.Role != "request" || proof.Payload == nil {
		return p, linkFail("state_conflict", id, "storage")
	}
	var requestView struct {
		Mode                    string `json:"mode"`
		HostPublicKey           string `json:"host_public_key"`
		DevicePublicKey         string `json:"device_public_key"`
		RequestNonce            string `json:"request_nonce"`
		CoordinatorAddress      string `json:"coordinator_address"`
		CoordinatorPublicKey    string `json:"coordinator_public_key"`
		CreatedAt               string `json:"created_at"`
		ExpiresAt               string `json:"expires_at"`
		ExpectedNetworkID       string `json:"expected_network_id"`
		ExpectedPersonPublicKey string `json:"expected_person_public_key"`
		RenewedCertificateID    string `json:"renewed_certificate_id"`
	}
	if e = json.Unmarshal(body, &requestView); e != nil {
		return p, linkFail("state_conflict", id, "storage")
	}
	r := p.Record
	if requestView.HostPublicKey != r.HostPublicKey || requestView.DevicePublicKey != r.DevicePublicKey || requestView.RequestNonce != r.RequestNonce || requestView.CoordinatorAddress != r.CoordinatorAddress || requestView.CoordinatorPublicKey != r.CoordinatorPublicKey || requestView.ExpiresAt != p.Deadline || requestView.ExpectedNetworkID != r.ExpectedNetworkID || requestView.ExpectedPersonPublicKey != r.ExpectedPersonPublicKey {
		return p, linkFail("state_conflict", id, "storage")
	}
	expected := "link_" + linkHash(linkMessage("peerspan-link-request-id-v1", r.CoordinatorPublicKey, r.HostPublicKey, r.DevicePublicKey, r.RequestNonce))
	if expected != id || p.Role != "approver" && p.Role != requestView.Mode {
		return p, linkFail("state_conflict", id, "storage")
	}
	created, err := linkStamp(requestView.CreatedAt)
	until, untilErr := linkStamp(requestView.ExpiresAt)
	if err != nil || untilErr != nil || until.Sub(created) != 300*time.Second {
		return p, linkFail("state_conflict", id, "storage")
	}
	validState := false
	if p.Role == "approver" {
		validState = p.State == "review" || p.State == "offer_sent" || p.State == "incomplete"
	} else {
		switch p.State {
		case "waiting_owner", "waiting_selection", "awaiting_administrator", "ready_to_commit", "finalizing", "linked", "incomplete", "cancelled", "expired":
			validState = true
		}
		if p.Record.SelectionApproved != (p.Record.SelectionPacketBase64 != "-") || p.Record.CommitApproved != (p.Record.CommitPacketBase64 != "-") {
			validState = false
		}
	}
	if !validState {
		return p, linkFail("state_conflict", id, "storage")
	}
	if err = checkLinkPacketReferences(p); err != nil {
		return p, err
	}
	return p, nil
}
func putLinkPending(ctx context.Context, tx *sql.Tx, p linkPending) error {
	if len(p.Secret) != 0 && len(p.Secret) != 16 {
		return linkFail("internal", p.ID, "storage")
	}
	var oldRole, oldDeadline, oldRaw string
	e := tx.QueryRowContext(ctx, `SELECT role,deadline,record FROM link_pending WHERE request_id=?`, p.ID).Scan(&oldRole, &oldDeadline, &oldRaw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil && (oldRole != p.Role || oldDeadline != p.Deadline) {
		return linkFail("operation_conflict", p.ID, "storage")
	}
	if e == nil {
		previous, e := decodeLinkRecord([]byte(oldRaw))
		if e != nil {
			return linkFail("state_conflict", p.ID, "storage")
		}
		if !validLinkTransition(previous, p.Record, p.Role) {
			return linkFail("operation_conflict", p.ID, "storage")
		}
	}
	raw, e := linkJSON(p.Record)
	if e != nil {
		return e
	}
	if len(raw) > 32<<20 {
		return linkFail("quota_exceeded", p.ID, "storage")
	}
	if _, e = decodeLinkRecord(raw); e != nil {
		return linkFail("internal", p.ID, "storage")
	}
	var secret any
	if len(p.Secret) != 0 {
		secret = p.Secret
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO link_pending(request_id,role,state,deadline,record,secret) VALUES(?,?,?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET state=excluded.state,record=excluded.record,secret=excluded.secret`, p.ID, p.Role, p.State, p.Deadline, string(raw), secret)
	return e
}
func storeLinkFrame(ctx context.Context, tx *sql.Tx, p *linkPending, frame linkFrame, raw []byte) (bool, error) {
	var old string
	e := tx.QueryRowContext(ctx, `SELECT record FROM link_frames WHERE request_id=? AND role=? AND writer_key=? AND frame_id=?`, frame.RequestID, frame.Role, frame.WriterPublicKey, frame.FrameID).Scan(&old)
	encoded, eJSON := linkJSON(map[string]any{"frame_base64": base64.StdEncoding.EncodeToString(raw)})
	if eJSON != nil {
		return false, eJSON
	}
	if e == nil {
		if old != string(encoded) {
			return false, linkFail("operation_conflict", p.ID, "frame")
		}
		return false, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return false, e
	}
	if frame.RequestID != p.ID {
		return false, linkFail("invalid", p.ID, "frame")
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO link_frames(request_id,role,writer_key,frame_id,record) VALUES(?,?,?,?,?)`, frame.RequestID, frame.Role, frame.WriterPublicKey, frame.FrameID, string(encoded))
	return e == nil, e
}
func (s *Store) signRequesterPacket(ctx context.Context, q dbQuerier, p linkPending, role, person string, payload []byte) ([]byte, string, error) {
	if p.Record.HostPublicKey != s.identity.PublicKey {
		return nil, "", linkFail("forbidden", p.ID, role)
	}
	switch role {
	case "request", "selection", "commit":
	default:
		return nil, "", linkFail("invalid", p.ID, role)
	}
	key, e := loadLinkDevice(ctx, q, p.Record.DevicePublicKey)
	if e != nil {
		return nil, "", e
	}
	packet := linkPacket{Format: 1, RequestID: p.ID, Role: role, WriterPublicKey: s.identity.PublicKey, PersonPublicKey: person, CertificateID: "-", PayloadBase64: base64.StdEncoding.EncodeToString(payload), HostSignature: "-", DeviceSignature: "-", AuthoritySignature: "-"}
	message := packetLinkMessage(packet, payload)
	packet.HostSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, message))
	packet.DeviceSignature, e = membership.SignSSHSIG(membership.KeySigner{Key: key}, message)
	if e != nil {
		return nil, "", e
	}
	raw, e := linkJSON(packet)
	if e != nil {
		return nil, "", e
	}
	checked, e := linking.Read("packet", raw, s.identity.PublicKey, p.Record.DevicePublicKey)
	if e != nil {
		return nil, "", e
	}
	return raw, checked.ID, nil
}

func validLinkIntentTransition(old, next linkIntentValue) bool {
	if old.Intent == nil {
		return next.Intent == nil || validLinkIntent(next.Intent)
	}
	if next.Intent == nil || !validLinkIntent(next.Intent) {
		return false
	}
	a, b := *old.Intent, *next.Intent
	if a.Approved && !b.Approved || len(a.Signatures) != len(b.Signatures) {
		return false
	}
	if a.PacketTemplateBase64 != "-" && a.PacketTemplateBase64 != b.PacketTemplateBase64 {
		return false
	}
	for i, s := range a.Signatures {
		if s.ObjectType != b.Signatures[i].ObjectType || s.Signature != "-" && s.Signature != b.Signatures[i].Signature {
			return false
		}
	}
	a.Approved, b.Approved = false, false
	a.PacketTemplateBase64, b.PacketTemplateBase64 = "-", "-"
	a.Signatures, b.Signatures = nil, nil
	x, e := linkJSON(a)
	if e != nil {
		return false
	}
	y, e := linkJSON(b)
	return e == nil && string(x) == string(y)
}
func validLinkIntent(i *linkIntent) bool {
	if i.Format != 1 || i.Signatures == nil {
		return false
	}
	if !i.Approved {
		for _, s := range i.Signatures {
			if s.Signature != "-" {
				return false
			}
		}
	}
	return true
}
func validLinkTransition(old, next linkRecord, role string) bool {
	if old.Format != 1 || next.Format != 1 || next.SelectionApproved && next.SelectionPacketBase64 == "-" || next.CommitApproved && next.CommitPacketBase64 == "-" {
		return false
	}
	seen := map[string]bool{}
	for _, f := range next.OutboundFrames {
		key := f.Role + ":" + f.WriterPublicKey + ":" + f.FrameID
		if seen[key] || !linkPublicKey(f.WriterPublicKey) || !linkID(f.FrameID, "") || f.Published != (f.Sequence > 0) {
			return false
		}
		seen[key] = true
		switch f.Role {
		case "request", "owner", "selection", "administrator", "commit", "result":
		default:
			return false
		}
	}
	stable := [][2]string{{old.ExpectedNetworkID, next.ExpectedNetworkID}, {old.ExpectedPersonPublicKey, next.ExpectedPersonPublicKey}, {old.CoordinatorAddress, next.CoordinatorAddress}, {old.CoordinatorPublicKey, next.CoordinatorPublicKey}, {old.HostPublicKey, next.HostPublicKey}, {old.DevicePublicKey, next.DevicePublicKey}, {old.RequestNonce, next.RequestNonce}, {old.RequestPacketBase64, next.RequestPacketBase64}}
	for _, p := range stable {
		if p[0] != p[1] {
			return false
		}
	}
	locked := [][2]string{{old.NetworkBase64, next.NetworkBase64}, {old.SelectionPacketBase64, next.SelectionPacketBase64}, {old.AdministratorPacketBase64, next.AdministratorPacketBase64}, {old.CommitPacketBase64, next.CommitPacketBase64}, {old.ResultPacketBase64, next.ResultPacketBase64}, {old.SelectionID, next.SelectionID}, {old.AdministratorOfferID, next.AdministratorOfferID}, {old.ManifestID, next.ManifestID}}
	if role == "approver" || old.SelectionApproved {
		locked = append(locked, [2]string{old.OwnerPacketBase64, next.OwnerPacketBase64}, [2]string{old.OwnerOfferID, next.OwnerOfferID})
	}
	for _, p := range locked {
		if p[0] != "-" && p[0] != p[1] {
			return false
		}
	}
	if old.SelectionApproved && !next.SelectionApproved || old.CommitApproved && !next.CommitApproved || old.AfterSequence > next.AfterSequence || len(next.OutboundFrames) < len(old.OutboundFrames) || len(next.OutboundFrames) > 64 {
		return false
	}
	for i, f := range old.OutboundFrames {
		n := next.OutboundFrames[i]
		if f.Role != n.Role || f.WriterPublicKey != n.WriterPublicKey || f.FrameID != n.FrameID || f.Published && !n.Published || f.Sequence != 0 && f.Sequence != n.Sequence {
			return false
		}
	}
	return validLinkIntentTransition(old.OwnerIntent, next.OwnerIntent) && validLinkIntentTransition(old.AdministratorIntent, next.AdministratorIntent)
}

func checkLinkPacketReferences(p linkPending) error {
	bad := func() error { return linkFail("state_conflict", p.ID, "storage") }
	r := p.Record
	for _, slot := range []struct{ role, encoded, id string }{{"owner", r.OwnerPacketBase64, r.OwnerOfferID}, {"selection", r.SelectionPacketBase64, r.SelectionID}, {"administrator", r.AdministratorPacketBase64, r.AdministratorOfferID}, {"commit", r.CommitPacketBase64, r.ManifestID}, {"result", r.ResultPacketBase64, "-"}} {
		if slot.encoded == "-" {
			if slot.id != "-" {
				return bad()
			}
			continue
		}
		if slot.role != "result" && !linkID(slot.id, "lp_") {
			return bad()
		}
		raw, e := linkBytes(slot.encoded, linking.MaxObject)
		if e != nil {
			return bad()
		}
		packet, body, e := decodeLinkPacket(raw)
		if e != nil || packet.Role != slot.role || packet.RequestID != p.ID {
			return bad()
		}
		signer, device := packet.WriterPublicKey, "-"
		if slot.role == "selection" || slot.role == "commit" {
			signer, device = r.HostPublicKey, r.DevicePublicKey
		}
		if slot.role == "result" {
			signer = r.CoordinatorPublicKey
		}
		read, e := linking.Read("packet", raw, signer, device)
		if e != nil || slot.id != "-" && read.ID != slot.id {
			return bad()
		}
		var refs struct {
			OwnerOfferID         string `json:"owner_offer_id"`
			SelectionID          string `json:"selection_id"`
			AdministratorOfferID string `json:"administrator_offer_id"`
			ManifestID           string `json:"manifest_id"`
		}
		if json.Unmarshal(body, &refs) != nil {
			return bad()
		}
		switch slot.role {
		case "selection":
			if refs.OwnerOfferID != r.OwnerOfferID {
				return bad()
			}
		case "administrator":
			if refs.OwnerOfferID != r.OwnerOfferID || refs.SelectionID != r.SelectionID {
				return bad()
			}
		case "commit":
			if refs.OwnerOfferID != r.OwnerOfferID || refs.SelectionID != r.SelectionID || refs.AdministratorOfferID != r.AdministratorOfferID {
				return bad()
			}
		case "result":
			if refs.ManifestID != r.ManifestID {
				return bad()
			}
		}
	}
	return nil
}
