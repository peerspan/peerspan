package helper

import (
	"database/sql"
	"net/netip"
	"regexp"
)

const maxStoredFrames = 512 << 20

// Existing resources are checked before enabling WAL, collecting expiry, or
// listening. Corrupt state is refused; a new key or repaired row is never used
// to conceal lost exact retry identity.
func validateResources(db *sql.DB) error {
	var count int
	var bodyBytes int64
	if err := db.QueryRow("SELECT count(*) FROM mailboxes").Scan(&count); err != nil || count > 4096 {
		return errState
	}
	if err := db.QueryRow("SELECT coalesce(sum(length(body)),0) FROM frames").Scan(&bodyBytes); err != nil || bodyBytes > maxStoredFrames {
		return errState
	}
	var bad int
	if err := db.QueryRow("SELECT count(*) FROM frames WHERE length(body)>? OR length(frame_id)!=64 OR length(role)>32 OR length(writer_key)!=44", maxMutationBody).Scan(&bad); err != nil || bad != 0 {
		return errState
	}
	if err := db.QueryRow("SELECT count(*) FROM mailboxes WHERE length(locator)!=64 OR length(request_id)!=69 OR length(read_cap_hash)!=64 OR length(created_at)!=20 OR length(expires_at)!=20 OR length(creator_key)!=44 OR length(source_bucket)>64 OR length(account_id)>128 OR length(creation_identity_hash)!=64 OR length(state)>8").Scan(&bad); err != nil || bad != 0 {
		return errState
	}
	rows, err := db.Query("SELECT " + mailboxColumns + " FROM mailboxes")
	if err != nil {
		return err
	}
	boxes := make([]*mailbox, 0, count)
	for rows.Next() {
		b, err := scanMailbox(rows)
		if err != nil {
			rows.Close()
			return errState
		}
		boxes = append(boxes, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	accountPattern := regexp.MustCompile(`^[a-z0-9_-]{1,128}$`)
	for _, b := range boxes {
		if !wireID(b.Locator, "") || !wireID(b.RequestID, "link_") || !wireID(b.ReadCapHash, "") || !wireID(b.CreationHash, "") || b.Bytes < 0 || b.Bytes > maxBoxBytes {
			return errState
		}
		if _, err := publicKey(b.Creator); err != nil {
			return errState
		}
		start, err := wholeUTC(b.Created)
		if err != nil {
			return errState
		}
		end, err := wholeUTC(b.Expires)
		if err != nil || end.Unix()-start.Unix() != 300 || end.Unix() != b.ExpiresUnix {
			return errState
		}
		if ip, err := netip.ParseAddr(b.Source); err == nil {
			if !ip.Is4() || ip.String() != b.Source {
				return errState
			}
		} else if prefix, err := netip.ParsePrefix(b.Source); err != nil || !prefix.Addr().Is6() || prefix.Bits() != 64 || prefix.Masked().String() != b.Source {
			return errState
		}
		if b.Account != "" && !accountPattern.MatchString(b.Account) {
			return errState
		}
		if b.State != "active" && b.State != "deleted" && b.State != "expired" {
			return errState
		}
		frames, err := db.Query("SELECT frame_id,role,writer_key,body,ciphertext_bytes FROM frames WHERE locator=?", b.Locator)
		if err != nil {
			return err
		}
		var sum int64
		frameCount, foundCreation := 0, false
		for frames.Next() {
			var id, role, writer string
			var raw []byte
			var size int64
			if frames.Scan(&id, &role, &writer, &raw, &size) != nil {
				frames.Close()
				return errState
			}
			f, err := parseCarrierFrame(raw, "")
			if err != nil || f.FrameID != id || f.Role != role || f.Writer != writer || f.Bytes != size || f.RequestID != b.RequestID || f.Locator != b.Locator || f.Created != b.Created || f.Expires != b.Expires {
				frames.Close()
				return errState
			}
			if role == "request" && writer == b.Creator {
				c := &mailboxCreate{Format: 1, RequestID: b.RequestID, Locator: b.Locator, ReadCapHash: b.ReadCapHash, Created: b.Created, Expires: b.Expires, Frame: raw}
				foundCreation = foundCreation || creationHash(c) == b.CreationHash
			}
			sum += size
			frameCount++
			if frameCount > 64 || sum > maxBoxBytes {
				frames.Close()
				return errState
			}
		}
		err = frames.Err()
		frames.Close()
		if err != nil || sum != b.Bytes || b.State == "active" && (!foundCreation || frameCount == 0) || b.State != "active" && frameCount != 0 {
			return errState
		}
	}
	for _, q := range []string{
		"SELECT count(*) FROM frames WHERE locator NOT IN (SELECT locator FROM mailboxes)",
		"SELECT count(*) FROM (SELECT creator_key FROM mailboxes GROUP BY creator_key HAVING count(*)>64 OR sum(state='active')>4)",
		"SELECT count(*) FROM (SELECT source_bucket FROM mailboxes GROUP BY source_bucket HAVING count(*)>256 OR sum(state='active')>16)",
		"SELECT count(*) FROM (SELECT account_id FROM mailboxes WHERE account_id!='' GROUP BY account_id HAVING count(*)>64 OR sum(state='active')>4)",
	} {
		if err := db.QueryRow(q).Scan(&bad); err != nil || bad != 0 {
			return errState
		}
	}
	var active int
	var ciphertext int64
	if err := db.QueryRow("SELECT coalesce(sum(state='active'),0),coalesce(sum(ciphertext_bytes),0) FROM mailboxes").Scan(&active, &ciphertext); err != nil || active > 1024 || ciphertext > 256<<20 {
		return errState
	}
	return nil
}
