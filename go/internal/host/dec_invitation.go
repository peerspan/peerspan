package host

import (
	"context"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecInvitationRequest struct {
	Member string `json:"member"`
	Person string `json:"expected_person_public_key"`
}
type decInvitationResult struct {
	Network    string `json:"network_id"`
	Context    string `json:"context_id"`
	ID         string `json:"invitation_id"`
	Invitation string `json:"invitation"`
	Expires    string `json:"expires_at"`
}

// An introduction is host-signed contact metadata. It is neither consumed nor
// indexed in the authority catalog, and does not claim administrator consent.
func (s *Store) DecentralizedInvitation(ctx context.Context, id string, input DecInvitationRequest) (decInvitationResult, error) {
	var result decInvitationResult
	if !membership.ValidLabel(input.Member) || input.Person != "-" && !dec.ValidPublicKey(input.Person) {
		return result, decFailure("invalid")
	}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	now, e := decCreationClock(ctx, tx, id)
	if e != nil {
		return result, e
	}
	state, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		return result, e
	}
	p, e := verifyDecSnapshot(state, now)
	if e != nil {
		return result, e
	}
	if _, e = decCurrentMember(p, s.identity.PublicKey); e != nil {
		return result, e
	}
	at, _ := dec.ParseTime(now)
	expires := linkTime(at.Add(300 * time.Second))
	contacts, e := s.decOwnContact(ctx, tx, id, state.Descriptor.ContextID, now, expires)
	if e != nil {
		return result, e
	}
	helpers := []dec.ContactRelay{}
	rows, e := tx.QueryContext(ctx, `SELECT address,public_key,record FROM dec_helpers WHERE kind='rendezvous' ORDER BY address,public_key`)
	if e != nil {
		return result, e
	}
	for rows.Next() {
		var address, key, raw string
		if e = rows.Scan(&address, &key, &raw); e != nil {
			rows.Close()
			return result, e
		}
		var setting struct {
			Format  uint64 `json:"format"`
			Enabled bool   `json:"enabled"`
		}
		if e = dec.ReadPrivateRecord([]byte(raw), "format enabled", &setting); e != nil {
			rows.Close()
			return result, e
		}
		if setting.Format != 1 || !dec.ValidEndpoint(address) || !dec.ValidPublicKey(key) {
			rows.Close()
			return result, decStorageError()
		}
		if setting.Enabled {
			helpers = append(helpers, dec.ContactRelay{Address: address, PublicKey: key})
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, e
	}
	if len(helpers) > 4 {
		return result, decFailure("quota_exceeded")
	}
	sort.Slice(helpers, func(a, b int) bool {
		return helpers[a].Address < helpers[b].Address || helpers[a].Address == helpers[b].Address && helpers[a].PublicKey < helpers[b].PublicKey
	})
	code, e := dec.SignContactInvitation(state.Descriptor, input.Person, input.Member, now, contacts, helpers, s.privateKey)
	if e != nil {
		return result, e
	}
	inv, e := dec.ReadContactInvitation(code)
	if e != nil {
		return result, e
	}
	if e = tx.Commit(); e != nil {
		return result, e
	}
	return decInvitationResult{id, state.Descriptor.ContextID, inv.ID, code, inv.Expires}, nil
}
