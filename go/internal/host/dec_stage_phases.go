package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// Fingerprints observe progress only. They are never authority or a substitute
// for the next transaction's complete current proof and consent checks.
func (s *Store) decStageFingerprint(ctx context.Context, id string) (string, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var raw string
	if e = tx.QueryRowContext(ctx, `SELECT record FROM dec_pending WHERE request_id=?`, id).Scan(&raw); e != nil {
		return "", e
	}
	var r decPendingRecord
	if dec.ReadPrivateRecord([]byte(raw), decPendingFields, &r) != nil {
		return "", decStorageError()
	}
	parts := []string{raw}
	for _, intent := range []string{r.OwnerIntent, r.AdministratorIntent, r.SelectionIntent, r.CommitIntent} {
		if intent == "-" {
			continue
		}
		if e = tx.QueryRowContext(ctx, `SELECT record FROM dec_intents WHERE intent_id=?`, intent).Scan(&raw); e != nil {
			return "", e
		}
		parts = append(parts, raw)
	}
	body, e := json.Marshal(parts)
	if e != nil {
		return "", e
	}
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:]), nil
}
func decStageSealedBy(p decPending, role, writer string) bool {
	for _, frame := range p.Record.Outbound {
		if frame.Role == role && frame.Writer == writer {
			return true
		}
	}
	return false
}

// Packet signatures are already durable when this function starts. Encryption
// takes place in a later transaction, which retains its exact random ciphertext
// before any network attempt. Reopen never seals the same stage a second time.
func (s *Store) sealDecApprovedStages(ctx context.Context, id string) error {
	for n := 0; n < 3; n++ {
		changed, e := s.sealDecApprovedStage(ctx, id)
		if e != nil {
			return e
		}
		if !changed {
			return nil
		}
		if e = decBarrier(ctx, "dec.frame.after_commit", id); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) sealDecApprovedStage(ctx context.Context, id string) (bool, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	p, e := readDecPending(ctx, tx, id)
	if e != nil {
		return false, e
	}
	if p.Record.Terminal != "-" {
		return false, nil
	}
	for _, entry := range []struct{ role, raw, intent string }{{"owner", p.Record.Owner, p.Record.OwnerIntent}, {"administrator", p.Record.Administrator, p.Record.AdministratorIntent}, {"owner_finalization", p.Record.Finalization, p.Record.OwnerIntent}} {
		if entry.raw == "-" || entry.intent == "-" || decStageSealedBy(p, entry.role, s.identity.PublicKey) {
			continue
		}
		packet, e := dec.ReadPacket(p.Descriptor, mustDecBytes(entry.raw))
		if e != nil {
			return false, e
		}
		if packet.Writer != s.identity.PublicKey {
			continue
		}
		intent, e := readDecIntent(ctx, tx, entry.intent)
		if e != nil {
			return false, e
		}
		if !intent.Record.Approved {
			return false, decFailure("review_required")
		}
		now, e := decCreationClock(ctx, tx, intent.Network)
		if e != nil {
			return false, e
		}
		if now >= p.Deadline {
			return false, decFailure("expired")
		}
		var catalog *dec.Catalog
		if entry.role == "administrator" {
			plan, e := s.decCurrentAdministrator(ctx, tx, p, intent, now)
			if e != nil {
				return false, e
			}
			catalog = plan.Catalog
		} else {
			plan, e := s.decCurrentOwner(ctx, tx, p, intent, now)
			if e != nil {
				return false, e
			}
			catalog = plan.Catalog
			if entry.role == "owner_finalization" {
				review, e := readDecCeremonyReview(intent)
				if e != nil {
					return false, e
				}
				if _, e = s.decCurrentFinalization(ctx, tx, p, intent, review, now); e != nil {
					return false, e
				}
			}
		}
		components, e := decCatalogComponents(catalog)
		if e != nil {
			return false, e
		}
		if e = s.queueDecStage(ctx, tx, &p, packet, components, now); e != nil {
			return false, e
		}
		if e = putDecPending(ctx, tx, p); e != nil {
			return false, e
		}
		return true, tx.Commit()
	}
	return false, nil
}
