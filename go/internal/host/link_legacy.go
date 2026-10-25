package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path"
	"strings"

	"github.com/peerspan/peerspan/go/internal/linking"
)

// Existing local root/SSH commands retain their signed legacy wire statements.
// Once enabled, their public transport is the same verified v2 catalog writer.
func legacyLinkMutation(route string, body any) (string, []byte, bool, error) {
	raw, e := json.Marshal(body)
	if e != nil {
		return "", nil, false, e
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return "", nil, false, linkFail("invalid", "-", "statement")
	}
	kind, field := "", ""
	switch path.Base(route) {
	case "admins":
		kind, field = "admin_delegation", "delegation"
	case "admin-removals":
		kind, field = "admin_removal", "statement"
	case "groups":
		kind, field = "group", "group"
	case "policies":
		kind, field = "policy", "policy"
	case "hosts":
		kind, field = "host_admission", "admission"
	case "persons":
		kind, field = "person_admission", "admission"
		if _, ok := object["membership"]; ok {
			kind, field = "person_membership", "membership"
		}
	case "bindings":
		kind, field = "host_binding", "binding"
	case "leave":
		kind, field = "host_leave", "statement"
	case "revocations":
		var value string
		if json.Unmarshal(object["kind"], &value) != nil {
			return "", nil, true, linkFail("invalid", "-", "statement")
		}
		kind = map[string]string{"host": "host_revocation", "invite": "invite_revocation", "person": "person_removal", "admin": "admin_removal", "unbind": "host_unbinding", "leave": "host_leave"}[value]
		field = "statement"
	default:
		return "", nil, false, nil
	}
	statement, ok := object[field]
	if !ok || kind == "" || len(statement) == 0 || string(statement) == "null" {
		return "", nil, true, linkFail("invalid", "-", "statement")
	}
	return kind, statement, true, nil
}
func (s *Store) publishLinkLegacy(ctx context.Context, n Network, kind string, record []byte) error {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	return s.publishLinkLegacyLocked(ctx, n, kind, record)
}

type linkPublicationError struct{ error }

func (e *linkPublicationError) Unwrap() error { return e.error }

func (s *Store) publishLinkLegacyLocked(ctx context.Context, n Network, kind string, record []byte) error {
	now, e := linkNow()
	if e != nil {
		return e
	}
	prior, e := readLinkCatalog(ctx, s.db, n.ID)
	if e != nil {
		return e
	}
	delta, e := catalogWithLinkObject(n.ID, kind, record)
	if e != nil {
		return e
	}
	union, e := mergeLinkCatalog(n.ID, prior, delta)
	if e != nil {
		return e
	}
	projection, e := s.verifyLinkProjection(ctx, s.db, n, union, now)
	if e != nil {
		return e
	}
	fact := linking.CatalogFactContext{Network: projection.Descriptor, Epoch: projection.Network.Epoch, KnownFeatureID: projection.Network.Facts.FeatureID, Now: now}
	if e = linking.VerifyStoredCatalogAdditions(fact, prior, union); e != nil {
		return e
	}
	selected, e := linking.SelectStoredProofCatalog(fact, union, []linking.ProofSeed{{Kind: kind, Body: record}})
	if e != nil {
		return e
	}
	body, e := linkJSON(map[string]any{"catalog": json.RawMessage(selected)})
	if e != nil {
		return e
	}
	if len(body) > 1<<20 {
		return linkFail("quota_exceeded", "-", "statement")
	}
	restrictive := strings.HasSuffix(kind, "revocation") || kind == "person_removal" || kind == "admin_removal" || kind == "host_unbinding" || kind == "host_leave"
	if restrictive {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		members, e := readLinkMembers(ctx, tx, n.ID)
		if e != nil {
			return e
		}
		members = projectedLinkMembers(projection, members, linkTime(now))
		if e = s.applyLinkProjection(ctx, tx, &n, projection, members, linkTime(now)); e != nil {
			return e
		}
		if e = putLinkRestrictionMarker(ctx, tx, n.ID, linkProofID(kind, record)); e != nil {
			return e
		}
		if kind == "admin_removal" {
			previous, err := decodeLinkCatalog(prior, n.ID)
			if err != nil {
				return err
			}
			known := false
			for _, entry := range previous.Objects {
				if entry.ID == linkProofID(kind, record) {
					known = true
				}
			}
			if !known {
				var removal struct {
					Person string `json:"person_public_key"`
				}
				if json.Unmarshal(record, &removal) != nil {
					return linkFail("invalid", "-", "admin_removal")
				}
				if e = appendEvent(ctx, tx, "network.admin_removed", personIDOf(removal.Person), linkTime(now)); e != nil {
					return e
				}
			}
		}
		if e = tx.Commit(); e != nil {
			return e
		}
		s.mapApplied(n.ID, members)
	}
	raw, e := s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+n.ID+"/statements", body)
	if e != nil {
		return &linkPublicationError{e}
	}
	_, e = s.applyLinkMapWithHook(ctx, n, raw, func(ctx context.Context, tx *sql.Tx) error {
		if !restrictive {
			return nil
		}
		return clearLinkRestrictionMarkers(ctx, tx, n.ID, []string{linkProofID(kind, record)})
	})
	if e != nil {
		return &linkPublicationError{e}
	}
	return nil
}
