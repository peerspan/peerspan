package host

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type decCarrier struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
	Key     string `json:"public_key"`
}
type decFrameAck struct {
	Address string `json:"address"`
	Key     string `json:"public_key"`
}
type decOutboundFrame struct {
	Role         string        `json:"role"`
	Writer       string        `json:"writer_public_key"`
	ID           string        `json:"frame_id"`
	Acknowledged []decFrameAck `json:"acknowledged_by"`
}
type decPendingRecord struct {
	Format              uint64             `json:"format"`
	Roles               []string           `json:"roles"`
	Mode                string             `json:"mode"`
	Migration           string             `json:"migration_proposal_id"`
	Network             string             `json:"expected_network_id"`
	Context             string             `json:"expected_context_id"`
	Person              string             `json:"expected_person_public_key"`
	Invitation          string             `json:"contact_invitation_base64"`
	Descriptor          string             `json:"descriptor_base64"`
	Host                string             `json:"host_public_key"`
	Device              string             `json:"device_public_key"`
	Nonce               string             `json:"request_nonce"`
	Request             string             `json:"request_packet_base64"`
	Owner               string             `json:"owner_packet_base64"`
	Selection           string             `json:"selection_packet_base64"`
	Administrator       string             `json:"administrator_packet_base64"`
	Finalization        string             `json:"owner_finalization_packet_base64"`
	Commit              string             `json:"commit_packet_base64"`
	Outcome             string             `json:"outcome_packet_base64"`
	Catalog             string             `json:"catalog_base64"`
	OwnerID             string             `json:"owner_offer_id"`
	SelectionID         string             `json:"selection_id"`
	AdministratorID     string             `json:"administrator_offer_id"`
	FinalizationID      string             `json:"owner_finalization_id"`
	ManifestID          string             `json:"manifest_id"`
	ActivationID        string             `json:"activation_id"`
	Selected            bool               `json:"selection_approved"`
	Committed           bool               `json:"commit_approved"`
	OwnerIntent         string             `json:"owner_intent_id"`
	AdministratorIntent string             `json:"administrator_intent_id"`
	SelectionIntent     string             `json:"selection_intent_id"`
	CommitIntent        string             `json:"commit_intent_id"`
	Terminal            string             `json:"terminal"`
	Carriers            []decCarrier       `json:"carrier_endpoints"`
	Outbound            []decOutboundFrame `json:"outbound_frames"`
}

const decPendingFields = "format roles mode migration_proposal_id expected_network_id expected_context_id expected_person_public_key contact_invitation_base64 descriptor_base64 host_public_key device_public_key request_nonce request_packet_base64 owner_packet_base64 selection_packet_base64 administrator_packet_base64 owner_finalization_packet_base64 commit_packet_base64 outcome_packet_base64 catalog_base64 owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id selection_approved commit_approved owner_intent_id administrator_intent_id selection_intent_id commit_intent_id terminal carrier_endpoints outbound_frames"

type decPending struct {
	ID, Deadline        string
	Record              decPendingRecord
	Secret, TerminalCap []byte
	Request             *dec.Packet
	Terms               dec.RequestTerms
	Descriptor          dec.Descriptor
	Frames              map[string]*dec.Frame
	DecodeContexts      map[string]dec.Descriptor
}

func decPendingResolved(terminal string) bool {
	switch terminal {
	case "applied", "cancelled", "expired", "stopped", "migration_adopted":
		return true
	}
	return false
}
func decPendingIDs(ctx context.Context, q dbQuerier) ([]string, error) {
	rows, e := q.QueryContext(ctx, `SELECT request_id FROM dec_pending ORDER BY request_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		if len(ids) >= 4096 {
			return nil, decFailure("quota_exceeded")
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func decFrameKey(role, writer, id string) string { return role + "/" + writer + "/" + id }
func decCarrierLess(a, b decCarrier) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Address != b.Address {
		return a.Address < b.Address
	}
	return a.Key < b.Key
}
func decFrameAckLess(a, b decFrameAck) bool {
	return a.Address < b.Address || a.Address == b.Address && a.Key < b.Key
}
func validateDecPending(p *decPending) error {
	r := &p.Record
	if r.Format != 1 || !dec.ValidID(p.ID, "link_") || r.Roles == nil || len(r.Roles) < 1 || len(r.Roles) > 3 || r.Carriers == nil || r.Outbound == nil || len(r.Outbound) > 64 {
		return decStorageError()
	}
	order := map[string]int{"requester": 1, "owner": 2, "administrator": 3}
	last := 0
	for _, role := range r.Roles {
		if order[role] <= last {
			return decStorageError()
		}
		last = order[role]
	}
	if r.Mode != "new" && r.Mode != "renew" || r.Migration != "-" && !dec.ValidID(r.Migration, "ds_") || r.Network != "-" && !dec.ValidID(r.Network, "net_") || r.Context != "-" && !dec.ValidID(r.Context, "ctx_") || r.Person != "-" && !dec.ValidPublicKey(r.Person) || !dec.ValidPublicKey(r.Host) || !dec.ValidPublicKey(r.Device) {
		return decStorageError()
	}
	raw, e := decBytes(r.Request, dec.MaxRequest)
	if e != nil {
		return e
	}
	p.Request, e = dec.ReadPacket(dec.Descriptor{}, raw)
	if e != nil {
		return e
	}
	p.Terms, e = p.Request.RequestTerms()
	if e != nil {
		return e
	}
	t := p.Terms
	if p.ID != p.Request.RequestID || p.Deadline != t.Expires || r.Mode != t.Mode || r.Migration != t.Migration || r.Network != t.Network || r.Context != t.Context || r.Person != t.Person || r.Host != t.Host || r.Device != t.Device || r.Nonce != t.Nonce {
		return decStorageError()
	}
	if r.Descriptor != "-" {
		raw, e = decBytes(r.Descriptor, dec.MaxPayload)
		if e != nil {
			return e
		}
		p.Descriptor, e = dec.ReadDescriptor(raw)
		if e != nil {
			return e
		}
		if r.Network != "-" && r.Network != p.Descriptor.NetworkID || r.Context != "-" && r.Context != p.Descriptor.ContextID {
			return decStorageError()
		}
	}
	if r.Invitation != "-" {
		if !containsString(r.Roles, "requester") {
			return decStorageError()
		}
		raw, e = decBytes(r.Invitation, dec.MaxPairingToken)
		if e != nil {
			return e
		}
		inv, e := dec.ReadContactInvitationBody(raw)
		if e != nil {
			return e
		}
		if e = inv.Current(t.Created); e != nil {
			return e
		}
		if inv.Descriptor.NetworkID != r.Network || inv.Context != r.Context || inv.Person != "-" && inv.Person != r.Person || p.Descriptor.ContextID != inv.Context || !bytes.Equal(p.Descriptor.Raw, inv.Descriptor.Raw) {
			return decStorageError()
		}
	}
	packets := []struct{ body, role, id string }{{r.Owner, "owner", r.OwnerID}, {r.Selection, "selection", r.SelectionID}, {r.Administrator, "administrator", r.AdministratorID}, {r.Finalization, "owner_finalization", r.FinalizationID}, {r.Commit, "commit", "-"}, {r.Outcome, "outcome", "-"}}
	for _, entry := range packets {
		if entry.body == "-" {
			if entry.id != "-" {
				return decStorageError()
			}
			continue
		}
		if p.Descriptor.ContextID == "" {
			return decStorageError()
		}
		if entry.role != "commit" && entry.role != "outcome" && entry.id == "-" {
			return decStorageError()
		}
		raw, e = decBytes(entry.body, dec.MaxObject)
		if e != nil {
			return e
		}
		packet, e := dec.ReadPacket(p.Descriptor, raw)
		if e != nil {
			return e
		}
		if packet.RequestID != p.ID || packet.Role != entry.role || entry.id != "-" && packet.ID != entry.id {
			return decStorageError()
		}
		if entry.role == "selection" || entry.role == "commit" {
			if packet.Writer != r.Host || packet.Signer != r.Device {
				return decStorageError()
			}
		}
	}
	if containsString(r.Roles, "requester") && (r.Selected != (r.SelectionIntent != "-") || r.Committed != (r.CommitIntent != "-") || r.Selection != "-" && !r.Selected || r.Commit != "-" && !r.Committed || r.Committed && !r.Selected) || !containsString(r.Roles, "requester") && (r.Selected || r.Committed) {
		return decStorageError()
	}
	for _, id := range []string{r.OwnerIntent, r.AdministratorIntent, r.SelectionIntent, r.CommitIntent} {
		if id != "-" && !decLocalID(id, "dint_") {
			return decStorageError()
		}
	}
	for _, item := range []struct{ id, prefix string }{{r.ManifestID, "dm_"}, {r.ActivationID, "da_"}} {
		if item.id != "-" && !dec.ValidID(item.id, item.prefix) {
			return decStorageError()
		}
	}
	if r.Catalog != "-" {
		raw, e = decBytes(r.Catalog, 16<<20)
		if e != nil {
			return e
		}
		if _, e = dec.ReadCatalog(p.Descriptor, raw); e != nil {
			return e
		}
	}
	switch r.Terminal {
	case "-", "applied", "cancelled", "expired", "stopped", "migration_prepared", "migration_adopted":
	default:
		return decStorageError()
	}
	if r.Migration == "-" && (r.Terminal == "migration_prepared" || r.Terminal == "migration_adopted") || r.Migration != "-" && r.Terminal == "applied" {
		return decStorageError()
	}
	if r.Terminal == "applied" && r.Outcome == "-" || (r.Terminal == "migration_prepared" || r.Terminal == "migration_adopted") && (r.Commit == "-" || containsString(r.Roles, "requester") && !r.Committed || r.Outcome != "-") {
		return decStorageError()
	}
	if len(p.Secret) != 0 && (len(p.Secret) != 16 || decPendingResolved(r.Terminal)) || len(p.TerminalCap) != 0 && (len(p.TerminalCap) != 32 || r.Terminal != "applied" || len(p.Secret) != 0) {
		return decStorageError()
	}
	if len(p.Secret) == 0 {
		for _, frame := range p.Frames {
			if len(p.TerminalCap) == 0 || frame.Role != "outcome" {
				return decStorageError()
			}
		}
	}
	for i, c := range r.Carriers {
		if c.Kind != "participant" && c.Kind != "helper" || !dec.ValidEndpoint(c.Address) || !dec.ValidPublicKey(c.Key) || i > 0 && !decCarrierLess(r.Carriers[i-1], c) {
			return decStorageError()
		}
	}
	seen := map[string]bool{}
	for _, f := range r.Outbound {
		key := decFrameKey(f.Role, f.Writer, f.ID)
		if seen[key] || f.Acknowledged == nil || !dec.ValidID(f.ID, "") || !dec.ValidPublicKey(f.Writer) {
			return decStorageError()
		}
		seen[key] = true
		if len(p.Secret) > 0 || len(p.TerminalCap) > 0 {
			if p.Frames[key] == nil {
				return decStorageError()
			}
		}
		for i, a := range f.Acknowledged {
			if !dec.ValidEndpoint(a.Address) || !dec.ValidPublicKey(a.Key) || i > 0 && !decFrameAckLess(f.Acknowledged[i-1], a) {
				return decStorageError()
			}
		}
	}
	return nil
}

func readDecPending(ctx context.Context, q dbQuerier, id string) (decPending, error) {
	p := decPending{ID: id, Frames: map[string]*dec.Frame{}}
	var raw string
	e := q.QueryRowContext(ctx, `SELECT deadline,record,secret,terminal_read_cap FROM dec_pending WHERE request_id=?`, id).Scan(&p.Deadline, &raw, &p.Secret, &p.TerminalCap)
	if errors.Is(e, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if e != nil {
		return p, e
	}
	if len(raw) > 32<<20 {
		return p, decFailure("quota_exceeded")
	}
	if e = dec.ReadPrivateRecord([]byte(raw), decPendingFields, &p.Record); e != nil {
		return p, e
	}
	// Read once before frame decryption to validate every fixed request/pin.
	if e = validateDecPendingHeader(&p); e != nil {
		return p, e
	}
	rows, e := q.QueryContext(ctx, `SELECT role,writer_key,frame_id,record FROM dec_frames WHERE request_id=? ORDER BY role,writer_key,frame_id`, id)
	if e != nil {
		return p, e
	}
	total := 0
	defer rows.Close()
	for rows.Next() {
		var role, writer, frameID, record string
		if e = rows.Scan(&role, &writer, &frameID, &record); e != nil {
			return p, e
		}
		var stored struct {
			Frame string `json:"frame_base64"`
		}
		if len(record) > 32<<20 {
			return p, decFailure("quota_exceeded")
		}
		if e = dec.ReadPrivateRecord([]byte(record), "frame_base64", &stored); e != nil {
			return p, e
		}
		body, e := decBytes(stored.Frame, dec.MaxFrameWire)
		if e != nil {
			return p, e
		}
		frame, e := dec.ReadFrame(body)
		if e != nil {
			return p, e
		}
		if frame.Request != p.ID || frame.Role != role || frame.Writer != writer || frame.ID != frameID || frame.Created != p.Terms.Created || frame.Expires != p.Deadline {
			return p, decStorageError()
		}
		if len(p.Secret) > 0 {
			locator, e := dec.FrameLocator(p.Secret)
			if e != nil || frame.Locator != locator {
				return p, decStorageError()
			}
		}
		total += len(frame.Encrypted)
		if len(p.Frames) >= 64 || total > 32<<20 {
			return p, decFailure("quota_exceeded")
		}
		p.Frames[decFrameKey(role, writer, frameID)] = frame
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	if len(p.Secret) > 0 {
		p.DecodeContexts, e = decPendingDescriptors(p)
		if e != nil {
			return p, e
		}
		for _, frame := range p.Frames {
			if _, e = decOpenPendingFrame(p, frame); e != nil {
				return p, e
			}
		}
	}
	if e = validateDecPending(&p); e != nil {
		return p, e
	}
	if e = validateDecRequesterReferences(ctx, q, p); e != nil {
		return p, e
	}
	return p, nil
}
func validateDecPendingHeader(p *decPending) error {
	// Outbound references need the frame rows and are validated after loading.
	outbound := p.Record.Outbound
	p.Record.Outbound = []decOutboundFrame{}
	err := validateDecPending(p)
	p.Record.Outbound = outbound
	return err
}
func putDecPending(ctx context.Context, tx *sql.Tx, p decPending) error {
	if e := validateDecPending(&p); e != nil {
		return e
	}
	raw, e := json.Marshal(p.Record)
	if e != nil {
		return e
	}
	if len(raw) > 32<<20 {
		return decFailure("quota_exceeded")
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO dec_pending(request_id,deadline,record,secret,terminal_read_cap) VALUES(?,?,?,?,?) ON CONFLICT(request_id) DO UPDATE SET deadline=excluded.deadline,record=excluded.record,secret=excluded.secret,terminal_read_cap=excluded.terminal_read_cap`, p.ID, p.Deadline, string(raw), p.Secret, p.TerminalCap)
	return e
}
func insertDecFrame(ctx context.Context, tx *sql.Tx, p *decPending, raw []byte) (bool, error) {
	f, e := dec.ReadFrame(raw)
	if e != nil {
		return false, e
	}
	if f.Request != p.ID || f.Created != p.Terms.Created || f.Expires != p.Deadline || len(p.Secret) != 16 {
		return false, decStorageError()
	}
	locator, e := dec.FrameLocator(p.Secret)
	if e != nil || f.Locator != locator {
		return false, decStorageError()
	}
	if _, e = decOpenPendingFrame(*p, f); e != nil {
		return false, e
	}
	key := decFrameKey(f.Role, f.Writer, f.ID)
	if old := p.Frames[key]; old != nil {
		if !bytes.Equal(old.Raw, raw) {
			return false, decFailure("operation_conflict")
		}
		return false, nil
	}
	total := len(f.Encrypted)
	for _, old := range p.Frames {
		total += len(old.Encrypted)
	}
	if len(p.Frames) >= 64 || total > 32<<20 {
		return false, decFailure("quota_exceeded")
	}
	record, _ := json.Marshal(struct {
		Frame string `json:"frame_base64"`
	}{base64.StdEncoding.EncodeToString(raw)})
	if _, e = tx.ExecContext(ctx, `INSERT INTO dec_frames(request_id,role,writer_key,frame_id,record) VALUES(?,?,?,?,?)`, p.ID, f.Role, f.Writer, f.ID, string(record)); e != nil {
		return false, e
	}
	p.Frames[key] = f
	if f.Role == "owner" {
		p.DecodeContexts = nil
	}
	return true, nil
}
func addDecCarriers(p *decPending, carriers ...decCarrier) {
	for _, c := range carriers {
		found := false
		for _, old := range p.Record.Carriers {
			if old == c {
				found = true
				break
			}
		}
		if !found {
			p.Record.Carriers = append(p.Record.Carriers, c)
		}
	}
	sort.Slice(p.Record.Carriers, func(i, j int) bool { return decCarrierLess(p.Record.Carriers[i], p.Record.Carriers[j]) })
}
