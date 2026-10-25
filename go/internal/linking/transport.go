package linking

import (
	"encoding/json"
	"time"
)

// Frame is opaque transport. Its writer and ciphertext establish no authority.
// Raw bytes, rather than a re-encoding of this value, identify an exact retry.
type Frame struct {
	Format          uint64 `json:"format"`
	RequestID       string `json:"request_id"`
	Locator         string `json:"locator"`
	Role            string `json:"role"`
	WriterPublicKey string `json:"writer_public_key"`
	FrameID         string `json:"frame_id"`
	Ciphertext      string `json:"ciphertext"`
}

// ParseFrame enforces the public primitive envelope without decrypting it.
func ParseFrame(raw []byte) (Frame, error) {
	var f Frame
	o, err := parse(raw)
	if err != nil || fields(o, "format request_id locator role writer_public_key frame_id ciphertext") != nil || version(o, 1) != nil {
		return f, invalid()
	}
	if err := json.Unmarshal(raw, &f); err != nil || !identifier(f.RequestID, "link_") || !identifier(f.Locator, "") || !identifier(f.FrameID, "") || !key(f.WriterPublicKey) {
		return Frame{}, invalid()
	}
	switch f.Role {
	case "request", "owner", "selection", "administrator", "commit", "result":
	default:
		return Frame{}, invalid()
	}
	ciphertext, err := decode(f.Ciphertext, (64<<10)+16)
	if err != nil || len(ciphertext) < 16 {
		return Frame{}, invalid()
	}
	return f, nil
}

// MailboxSubmission retains the exact original frame encoding.
type MailboxSubmission struct {
	Frame     Frame
	RawFrame  json.RawMessage
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ParseMailboxSubmission accepts exactly the create or append request shape.
func ParseMailboxSubmission(raw []byte, create bool) (MailboxSubmission, error) {
	var s MailboxSubmission
	o, err := parse(raw)
	required := "frame"
	if create {
		required += " created_at expires_at"
	}
	if err != nil || fields(o, required) != nil {
		return s, invalid()
	}
	s.RawFrame = o["frame"]
	if s.Frame, err = ParseFrame(s.RawFrame); err != nil {
		return MailboxSubmission{}, err
	}
	if create {
		c, e := text(o, "created_at")
		if e != nil {
			return MailboxSubmission{}, e
		}
		x, e := text(o, "expires_at")
		if e != nil {
			return MailboxSubmission{}, e
		}
		s.CreatedAt, err = stamp(c)
		if err != nil {
			return MailboxSubmission{}, err
		}
		s.ExpiresAt, err = stamp(x)
		if err != nil || s.Frame.Role != "request" || s.ExpiresAt.Sub(s.CreatedAt) != 300*time.Second {
			return MailboxSubmission{}, invalid()
		}
	}
	return s, nil
}
