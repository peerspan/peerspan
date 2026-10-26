package helper

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type mailboxCreate struct {
	Format      uint64          `json:"format"`
	RequestID   string          `json:"request_id"`
	Locator     string          `json:"locator"`
	ReadCapHash string          `json:"read_cap_hash"`
	Created     string          `json:"created_at"`
	Expires     string          `json:"expires_at"`
	Frame       json.RawMessage `json:"frame"`
}

type mailbox struct {
	Locator, RequestID, ReadCapHash, Created, Expires string
	ExpiresUnix                                       int64
	Creator, Source, Account, CreationHash, State     string
	Bytes                                             int64
}

const mailboxColumns = "locator,request_id,read_cap_hash,created_at,expires_at,expires_unix,creator_key,source_bucket,account_id,creation_identity_hash,state,ciphertext_bytes"

func scanMailbox(row interface{ Scan(...any) error }) (*mailbox, error) {
	b := &mailbox{}
	err := row.Scan(&b.Locator, &b.RequestID, &b.ReadCapHash, &b.Created, &b.Expires, &b.ExpiresUnix, &b.Creator, &b.Source, &b.Account, &b.CreationHash, &b.State, &b.Bytes)
	return b, err
}

func creationHash(c *mailboxCreate) string {
	return wireHash(wireLines("peerspan-decentralized-mailbox-create-v1", "1", c.RequestID, c.Locator, c.ReadCapHash, c.Created, c.Expires, wireHash(c.Frame)))
}

func parseCreation(raw []byte, key string, now time.Time) (*mailboxCreate, *carrierFrame, error) {
	var c mailboxCreate
	if strictJSON(raw, &c) != nil || c.Format != 1 || !wireID(c.RequestID, "link_") || !wireID(c.Locator, "") || !wireID(c.ReadCapHash, "") {
		return nil, nil, wireError("invalid")
	}
	f, err := parseCarrierFrame(c.Frame, key)
	if err != nil {
		return nil, nil, err
	}
	if f.RequestID != c.RequestID || f.Locator != c.Locator || f.Created != c.Created || f.Expires != c.Expires || f.Role != "request" {
		return nil, nil, wireError("invalid")
	}
	if err := carrierWindow(c.Created, c.Expires, now); err != nil {
		return nil, nil, err
	}
	return &c, f, nil
}

func (s *resourceStore) begin(ctx context.Context, now time.Time) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err := collectResources(ctx, tx, now); err != nil {
		tx.Rollback()
		return nil, err
	}
	// Cleanup is durable even when the following request is refused. It only
	// erases expired resources and never changes a live creation or capability.
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.db.BeginTx(ctx, nil)
}

func findMailbox(ctx context.Context, tx *sql.Tx, locator, capability string) (*mailbox, error) {
	b, err := scanMailbox(tx.QueryRowContext(ctx, "SELECT "+mailboxColumns+" FROM mailboxes WHERE locator=?", locator))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, wireError("not_found")
	}
	if err != nil {
		return nil, err
	}
	want := wireHash([]byte(capability))
	if subtle.ConstantTimeCompare([]byte(b.ReadCapHash), []byte(want)) != 1 {
		return nil, wireError("forbidden")
	}
	return b, nil
}

func insertFrame(ctx context.Context, tx *sql.Tx, f *carrierFrame) error {
	var rawBytes int64
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(sum(length(body)),0) FROM frames").Scan(&rawBytes); err != nil {
		return err
	}
	if rawBytes+int64(len(f.Raw)) > maxStoredFrames {
		return wireError("quota_exceeded")
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO frames(locator,frame_id,role,writer_key,body,ciphertext_bytes) VALUES(?,?,?,?,?,?)", f.Locator, f.FrameID, f.Role, f.Writer, f.Raw, f.Bytes)
	return err
}

func creationQuota(ctx context.Context, tx *sql.Tx, key, source, account string, added int64) error {
	// Account ceilings additionally aggregate different keys. Anonymous resources
	// retain both actual-key and actual-source limits.
	for _, q := range []struct {
		where string
		arg   string
		live  int
		all   int
	}{
		{"creator_key=?", key, 4, 64}, {"source_bucket=?", source, 16, 256},
		{"1=?", "1", 1024, 4096},
		{"account_id=? AND account_id!=''", account, 4, 64},
	} {
		var count, live int
		where, arg := q.where, any(q.arg)
		if q.where == "1=?" {
			arg = 1
		}
		if err := tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(state='active'),0) FROM mailboxes WHERE "+where, arg).Scan(&count, &live); err != nil {
			return err
		}
		if count >= q.all || live >= q.live {
			return wireError("quota_exceeded")
		}
	}
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(sum(ciphertext_bytes),0) FROM mailboxes").Scan(&total); err != nil {
		return err
	}
	if total+added > 256<<20 {
		return wireError("quota_exceeded")
	}
	return nil
}

func (s *resourceStore) create(ctx context.Context, c *mailboxCreate, f *carrierFrame, source, account string, now time.Time) (bool, error) {
	tx, err := s.begin(ctx, now)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := carrierWindow(c.Created, c.Expires, time.Now()); err != nil {
		return false, err
	}
	b, err := scanMailbox(tx.QueryRowContext(ctx, "SELECT "+mailboxColumns+" FROM mailboxes WHERE locator=?", c.Locator))
	if err == nil {
		if b.State != "active" {
			return false, wireError("expired")
		}
		if b.CreationHash != creationHash(c) {
			return false, wireError("operation_conflict")
		}
		return false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err := creationQuota(ctx, tx, f.Writer, source, account, f.Bytes); err != nil {
		return false, err
	}
	expires, _ := wholeUTC(c.Expires)
	_, err = tx.ExecContext(ctx, "INSERT INTO mailboxes("+mailboxColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", c.Locator, c.RequestID, c.ReadCapHash, c.Created, c.Expires, expires.Unix(), f.Writer, source, account, creationHash(c), "active", f.Bytes)
	if err == nil {
		err = insertFrame(ctx, tx, f)
	}
	if err == nil {
		err = tx.Commit()
	}
	return err == nil, err
}

func (s *resourceStore) append(ctx context.Context, f *carrierFrame, capability string, now time.Time) error {
	tx, err := s.begin(ctx, now)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := carrierWindow(f.Created, f.Expires, time.Now()); err != nil {
		return err
	}
	b, err := findMailbox(ctx, tx, f.Locator, capability)
	if err != nil {
		return err
	}
	if b.State != "active" {
		return wireError("expired")
	}
	if b.RequestID != f.RequestID || b.Created != f.Created || b.Expires != f.Expires {
		return wireError("invalid")
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM frames WHERE locator=? AND frame_id=?", f.Locator, f.FrameID).Scan(&previous)
	if err == nil {
		if !bytes.Equal(previous, f.Raw) {
			return wireError("state_conflict")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var count int
	var total int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM frames WHERE locator=?", f.Locator).Scan(&count); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(sum(ciphertext_bytes),0) FROM mailboxes").Scan(&total); err != nil {
		return err
	}
	if count >= 64 || b.Bytes+f.Bytes > maxBoxBytes || total+f.Bytes > 256<<20 {
		return wireError("quota_exceeded")
	}
	if err := insertFrame(ctx, tx, f); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE mailboxes SET ciphertext_bytes=ciphertext_bytes+? WHERE locator=?", f.Bytes, f.Locator); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *resourceStore) remove(ctx context.Context, locator, capability string, now time.Time) error {
	tx, err := s.begin(ctx, now)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b, err := findMailbox(ctx, tx, locator, capability)
	if err != nil {
		return err
	}
	if b.State == "active" {
		if _, err := tx.ExecContext(ctx, "DELETE FROM frames WHERE locator=?", locator); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE mailboxes SET state='deleted',ciphertext_bytes=0 WHERE locator=?", locator); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *resourceStore) get(ctx context.Context, locator, capability string, now time.Time) ([]byte, error) {
	tx, err := s.begin(ctx, now)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	b, err := findMailbox(ctx, tx, locator, capability)
	if err != nil {
		return nil, err
	}
	if b.State == "deleted" {
		return nil, wireError("not_found")
	}
	if b.State == "expired" {
		return nil, wireError("expired")
	}
	// The strings below have been validated as canonical literal ASCII IDs/time.
	// Append FRAME raw bytes directly: json.Marshal(RawMessage) would compact
	// whitespace and destroy the exact first-frame retry identity.
	result := []byte(fmt.Sprintf(`{"format":1,"request_id":%q,"created_at":%q,"expires_at":%q,"frames":[`, b.RequestID, b.Created, b.Expires))
	rows, err := tx.QueryContext(ctx, "SELECT body FROM frames WHERE locator=? ORDER BY role COLLATE BINARY,writer_key COLLATE BINARY,frame_id COLLATE BINARY", locator)
	if err != nil {
		return nil, err
	}
	count := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		if len(result)+len(raw)+3 > maxGetBody {
			rows.Close()
			return nil, wireError("quota_exceeded")
		}
		if count != 0 {
			result = append(result, ',')
		}
		result = append(result, raw...)
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result = append(result, ']', '}')
	return result, tx.Commit()
}
