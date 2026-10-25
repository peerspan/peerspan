package host

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
)

const linkFrameFields = "format request_id locator role writer_public_key frame_id ciphertext"

type linkMailboxFrame struct {
	Sequence uint64          `json:"sequence"`
	Frame    json.RawMessage `json:"frame"`
}
type linkMailbox struct {
	RequestID    string             `json:"request_id"`
	Locator      string             `json:"locator"`
	CreatedAt    string             `json:"created_at"`
	ExpiresAt    string             `json:"expires_at"`
	NextSequence uint64             `json:"next_sequence"`
	State        string             `json:"state"`
	Frames       []linkMailboxFrame `json:"frames"`
}

func (f *linkMailboxFrame) UnmarshalJSON(raw []byte) error {
	type plain linkMailboxFrame
	return linking.DecodeMutation(raw, "sequence frame", (*plain)(f))
}
func decodeLinkFrame(raw []byte) (linkFrame, error) {
	var frame linkFrame
	if e := linking.DecodeMutation(raw, linkFrameFields, &frame); e != nil {
		return frame, e
	}
	if frame.Format != 1 || !linkID(frame.RequestID, "link_") || !linkID(frame.Locator, "") || !linkID(frame.FrameID, "") || !linkPublicKey(frame.WriterPublicKey) {
		return frame, linkFail("invalid", frame.RequestID, "frame")
	}
	switch frame.Role {
	case "request", "owner", "selection", "administrator", "commit", "result":
	default:
		return frame, linkFail("invalid", frame.RequestID, "frame")
	}
	ciphertext, e := linkBytes(frame.Ciphertext, linkPlainLimit+16)
	if e != nil || len(ciphertext) < 16 {
		return frame, linkFail("invalid", frame.RequestID, "frame")
	}
	return frame, nil
}
func decodeLinkMailbox(raw []byte) (linkMailbox, error) {
	var box linkMailbox
	if e := linking.DecodeMutation(raw, "request_id locator created_at expires_at next_sequence state frames", &box); e != nil {
		return box, e
	}
	if !linkID(box.RequestID, "link_") || !linkID(box.Locator, "") || box.NextSequence == 0 || box.Frames == nil || len(box.Frames) > 64 {
		return box, linkFail("invalid", box.RequestID, "mailbox")
	}
	created, e := linkStamp(box.CreatedAt)
	if e != nil {
		return box, e
	}
	until, e := linkStamp(box.ExpiresAt)
	if e != nil || until.Sub(created) != 300*time.Second {
		return box, linkFail("invalid", box.RequestID, "mailbox")
	}
	switch box.State {
	case "open", "expired":
	case "deleted":
		if len(box.Frames) != 0 {
			return box, linkFail("invalid", box.RequestID, "mailbox")
		}
	default:
		return box, linkFail("invalid", box.RequestID, "mailbox")
	}
	var previous uint64
	total := 0
	for _, row := range box.Frames {
		if row.Sequence <= previous || row.Sequence >= box.NextSequence {
			return box, linkFail("invalid", box.RequestID, "mailbox")
		}
		f, e := decodeLinkFrame(row.Frame)
		if e != nil || f.RequestID != box.RequestID || f.Locator != box.Locator {
			return box, linkFail("invalid", box.RequestID, "mailbox")
		}
		total += len(row.Frame)
		if total > 512<<10 {
			return box, linkFail("quota_exceeded", box.RequestID, "mailbox")
		}
		previous = row.Sequence
	}
	return box, nil
}

// linkCoordinator uses pinned mTLS but retains only strict public linking error
// codes/details. Untrusted remote error text and response bodies never escape.
func (s *Store) linkCoordinator(ctx context.Context, n Network, method, path string, body []byte) ([]byte, error) {
	config, e := s.coordinatorTLS(n, "http/1.1")
	if e != nil {
		return nil, linkFail("invalid", "-", "coordinator")
	}
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, method, "https://"+n.CoordinatorAddress+path, bytes.NewReader(body))
	if e != nil {
		return nil, linkFail("invalid", "-", "coordinator")
	}
	if body != nil {
		if len(body) > 1<<20 {
			return nil, linkFail("quota_exceeded", "-", "coordinator")
		}
		request.Header.Set("Content-Type", "application/json")
	}
	response, e := client.Do(request)
	if e != nil {
		return nil, linkFail("unavailable", "-", "coordinator")
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if e != nil || len(raw) > 16<<20 {
		return nil, linkFail("unavailable", "-", "coordinator")
	}
	if response.StatusCode == 200 || response.StatusCode == 201 {
		return raw, nil
	}
	var failure struct {
		Code    string      `json:"code"`
		Error   string      `json:"error"`
		Details linkDetails `json:"details"`
	}
	if e = linking.DecodeMutation(raw, "code error details", &failure); e != nil {
		return nil, linkFail("unavailable", "-", "coordinator")
	}
	detailsRaw := struct {
		Details json.RawMessage `json:"details"`
	}{}
	if json.Unmarshal(raw, &detailsRaw) != nil {
		return nil, linkFail("unavailable", "-", "coordinator")
	}
	var detail linkDetails
	if e = linking.DecodeMutation(detailsRaw.Details, "request_id stage required_ids next", &detail); e != nil || detail.RequiredIDs == nil || detail.Next == nil {
		return nil, linkFail("unavailable", "-", "coordinator")
	}
	if detail.RequestID != "-" && !linkID(detail.RequestID, "link_") {
		return nil, linkFail("unavailable", "-", "coordinator")
	}
	result := linkFail(failure.Code, detail.RequestID, "coordinator", detail.RequiredIDs...)
	if result.Status != response.StatusCode || result.Code != failure.Code {
		return nil, linkFail("unavailable", "-", "coordinator")
	}
	if result.Code == "rate_limited" {
		retry, e := strconv.ParseInt(response.Header.Get("Retry-After"), 10, 64)
		if e != nil || retry <= 0 {
			return nil, linkFail("unavailable", detail.RequestID, "coordinator")
		}
		result.RetryAfter = retry
	}
	// Repair steps are derived locally; remote prose cannot inject CLI output.
	result.coordinatorResponse = true
	return nil, result
}
func linkPendingNetwork(p linkPending) Network {
	return Network{CoordinatorAddress: p.Record.CoordinatorAddress, CoordinatorPublicKey: p.Record.CoordinatorPublicKey}
}
func (s *Store) readOutboundLinkFrame(ctx context.Context, p linkPending, ref linkOutboundFrame) ([]byte, error) {
	var record string
	if e := s.db.QueryRowContext(ctx, `SELECT record FROM link_frames WHERE request_id=? AND role=? AND writer_key=? AND frame_id=?`, p.ID, ref.Role, ref.WriterPublicKey, ref.FrameID).Scan(&record); e != nil {
		return nil, e
	}
	var row struct {
		FrameBase64 string `json:"frame_base64"`
	}
	if e := linking.DecodeStoredJSON([]byte(record), "frame_base64", &row); e != nil {
		return nil, linkFail("state_conflict", p.ID, "storage")
	}
	raw, e := linkBytes(row.FrameBase64, 1<<20)
	if e != nil {
		return nil, linkFail("state_conflict", p.ID, "storage")
	}
	f, e := decodeLinkFrame(raw)
	if e != nil || f.RequestID != p.ID || f.Role != ref.Role || f.WriterPublicKey != ref.WriterPublicKey || f.FrameID != ref.FrameID || f.Locator != linkLocator(p.Secret) {
		return nil, linkFail("state_conflict", p.ID, "storage")
	}
	return raw, nil
}
func (s *Store) publishLinkFrames(ctx context.Context, p *linkPending) error {
	for i, ref := range p.Record.OutboundFrames {
		if ref.Published {
			continue
		}
		raw, e := s.readOutboundLinkFrame(ctx, *p, ref)
		if e != nil {
			return e
		}
		if p.Role == "approver" {
			administrator := ref.Role == "administrator"
			intent := p.Record.OwnerIntent.Intent
			if administrator {
				intent = p.Record.AdministratorIntent.Intent
			}
			if ref.Role != "owner" && !administrator || intent == nil || !intent.Approved {
				return linkFail("state_conflict", p.ID, "consent")
			}
			now, err := linkNow()
			if err != nil {
				return err
			}
			// Approver callers hold syncing. A frame committed before a crash or
			// barrier still needs fresh authority before its first publication.
			if _, err = s.intentSigningKey(ctx, p, intent, administrator, now); err != nil {
				return err
			}
		}
		path := "/coord/v2/link-mailboxes/" + linkLocator(p.Secret) + "/frames"
		value := map[string]any{"frame": json.RawMessage(raw)}
		if ref.Role == "request" {
			packet, e := linkBytes(p.Record.RequestPacketBase64, linking.MaxObject)
			if e != nil {
				return e
			}
			_, body, e := decodeLinkPacket(packet)
			if e != nil {
				return e
			}
			var times struct {
				CreatedAt string `json:"created_at"`
				ExpiresAt string `json:"expires_at"`
			}
			if json.Unmarshal(body, &times) != nil {
				return linkFail("state_conflict", p.ID, "storage")
			}
			path = "/coord/v2/link-mailboxes"
			value["created_at"] = times.CreatedAt
			value["expires_at"] = times.ExpiresAt
		}
		body, e := linkJSON(value)
		if e != nil {
			return e
		}
		response, e := s.linkCoordinator(ctx, linkPendingNetwork(*p), http.MethodPost, path, body)
		if e != nil {
			return e
		}
		var sequence uint64
		if ref.Role == "request" {
			box, e := decodeLinkMailbox(response)
			if e != nil || box.RequestID != p.ID || box.Locator != linkLocator(p.Secret) || box.ExpiresAt != p.Deadline {
				return linkFail("invalid", p.ID, "mailbox")
			}
			for _, row := range box.Frames {
				f, _ := decodeLinkFrame(row.Frame)
				if f.Role == ref.Role && f.WriterPublicKey == ref.WriterPublicKey && f.FrameID == ref.FrameID {
					a, _ := linkJSON(f)
					original, _ := decodeLinkFrame(raw)
					b, _ := linkJSON(original)
					if !bytes.Equal(a, b) {
						return linkFail("operation_conflict", p.ID, "frame")
					}
					sequence = row.Sequence
					break
				}
			}
		} else {
			var row struct {
				Sequence uint64 `json:"sequence"`
			}
			if linking.DecodeMutation(response, "sequence", &row) != nil {
				return linkFail("invalid", p.ID, "frame")
			}
			sequence = row.Sequence
		}
		if sequence == 0 {
			return linkFail("invalid", p.ID, "frame")
		}
		p.Record.OutboundFrames[i].Published = true
		p.Record.OutboundFrames[i].Sequence = sequence
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		e = putLinkPending(ctx, tx, *p)
		if e == nil {
			e = tx.Commit()
		}
		_ = tx.Rollback()
		if e != nil {
			return e
		}
	}
	return nil
}
