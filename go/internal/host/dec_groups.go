package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

type DecGroupView struct {
	Name      string `json:"name"`
	Statement string `json:"statement_id"`
	Body      string `json:"statement_base64"`
}
type DecGroupsView struct {
	Context string         `json:"context_id"`
	Groups  []DecGroupView `json:"groups"`
}

// Conflict references belong to the runtime diagnostic, never the pure
// verifier's missing-proof array or a caller-supplied authority annotation.
type decReadConflict struct{ ids []string }

func (e *decReadConflict) Error() string                   { return "state_conflict" }
func (e *decReadConflict) Unwrap() error                   { return decFailure("state_conflict") }
func (e *decReadConflict) decConflictReferences() []string { return e.ids }

func decInactiveRead(code string) bool {
	switch code {
	case "expired", "authority_expired", "not_yet_valid", "forbidden", "device_revoked", "not_found":
		return true
	}
	return false
}

// DecentralizedGroups reads the complete aggregate from one held snapshot.
// It never opens a signer, fetches proofs or changes the clock/authority rows.
func (s *Store) DecentralizedGroups(ctx context.Context, network string) (DecGroupsView, error) {
	result := DecGroupsView{Groups: []DecGroupView{}}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return result, e
	}
	defer tx.Rollback()
	snapshot, e := s.loadDecSnapshot(ctx, tx, network)
	if e != nil {
		return result, e
	}
	result.Context = snapshot.Descriptor.ContextID
	now, e := decNow()
	if e != nil {
		return result, e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return result, e
	}
	if p.Root.Code != "-" {
		if p.Root.Code == "state_conflict" {
			return result, &decReadConflict{decSorted(decSet(p.Root.HeadIDs))}
		}
		return result, decFailure(p.Root.Code, p.Root.RequiredIDs...)
	}
	if _, _, e = p.Current([]string{"root"}); e != nil {
		return result, e
	}
	if len(snapshot.Fenced) != 0 {
		return result, decFailure("migration_pending", snapshot.Fenced...)
	}
	empty, _ := json.Marshal(result)
	size := len(empty)
	class := ""
	refs := map[string]bool{}
	for _, stream := range p.Streams {
		if len(stream.Stream) != 2 || stream.Stream[0] != "group" || len(stream.HeadIDs) == 0 {
			// An inherited floor has no selected new-context body to disclose.
			continue
		}
		statement, _, err := p.Current(stream.Stream)
		code := dec.Code(err)
		if len(stream.HeadIDs) > 1 {
			code, err = "state_conflict", decFailure("state_conflict")
		}
		if err != nil {
			if decInactiveRead(code) {
				continue
			}
			if class == "" {
				class = code
			}
			if class == code {
				for _, id := range dec.RequiredIDs(err) {
					refs[id] = true
				}
				if code == "state_conflict" && len(stream.HeadIDs) > 1 {
					for _, id := range stream.HeadIDs {
						refs[id] = true
					}
				}
			}
			continue
		}
		if class != "" {
			// Continue checking every required stream, but no successful body
			// can turn a failed aggregate into a partial response.
			continue
		}
		if statement == nil || statement.Kind != "group" || len(statement.Raw) > dec.MaxObject {
			return result, decStorageError()
		}
		row := DecGroupView{stream.Stream[1], statement.ID, base64.StdEncoding.EncodeToString(statement.Raw)}
		encoded, err := json.Marshal(row)
		if err != nil {
			return result, err
		}
		size += len(encoded)
		if len(result.Groups) > 0 {
			size++
		}
		if size > 32<<20 || len(result.Groups) >= 4096 {
			return result, decFailure("quota_exceeded")
		}
		result.Groups = append(result.Groups, row)
	}
	if class == "state_conflict" {
		return result, &decReadConflict{decSorted(refs)}
	}
	if class != "" {
		return result, decFailure(class, decSorted(refs)...)
	}
	return result, nil
}
