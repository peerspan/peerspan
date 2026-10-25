package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
)

const kindPendingLinkRestriction = "pending_link_restriction"

type linkRestrictionMarker struct {
	Format  uint64 `json:"format"`
	ProofID string `json:"proof_id"`
}

func putLinkRestrictionMarker(ctx context.Context, tx *sql.Tx, network, proof string) error {
	if !linkID(proof, "pf_") {
		return linkFail("invalid", "-", "restriction")
	}
	raw, e := linkJSON(linkRestrictionMarker{1, proof})
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?,?,?,?) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record`, network, kindPendingLinkRestriction, proof, string(raw))
	return e
}
func readLinkRestrictionMarkers(ctx context.Context, q dbQuerier, network string) ([]string, error) {
	rows, e := q.QueryContext(ctx, `SELECT subject,record FROM network_statements WHERE network_id=? AND kind=? ORDER BY subject`, network, kindPendingLinkRestriction)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var subject, record string
		if e = rows.Scan(&subject, &record); e != nil {
			return nil, e
		}
		var marker linkRestrictionMarker
		if linking.DecodeStoredJSON([]byte(record), "format proof_id", &marker) != nil || marker.Format != 1 || marker.ProofID != subject || !linkID(subject, "pf_") {
			return nil, linkFail("state_conflict", "-", "restriction")
		}
		out = append(out, subject)
		if len(out) > 4096 {
			return nil, linkFail("quota_exceeded", "-", "restriction")
		}
	}
	return out, rows.Err()
}
func clearLinkRestrictionMarkers(ctx context.Context, tx *sql.Tx, network string, proofs []string) error {
	for _, proof := range proofs {
		if _, e := tx.ExecContext(ctx, `DELETE FROM network_statements WHERE network_id=? AND kind=? AND subject=?`, network, kindPendingLinkRestriction, proof); e != nil {
			return e
		}
	}
	return nil
}
func linkRestrictiveProof(kind string, body []byte) bool {
	switch kind {
	case "admin_removal", "person_removal", "host_revocation", "invite_revocation", "host_unbinding", "host_leave", "device_revocation":
		return true
	case "person_record":
		var record struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(body, &record) != nil {
			return false
		}
		switch record.Kind {
		case "peerspan-person-remove-v1", "peerspan-revoke-host-v1", "peerspan-revoke-invite-v1", "peerspan-host-unbind-v1":
			return true
		}
	}
	return false
}

// Only actual remote publication failures may defer to verified transport
// following. Local proof and marker errors retain their hard failure boundary.
type linkRestrictionTransportError struct{ error }

func (e *linkRestrictionTransportError) Unwrap() error { return e.error }

func linkRestrictionRepairRequest(n Network, p *linkProjection, markers []string, now time.Time) ([]byte, error) {
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return nil, e
	}
	objects := map[string]linkCatalogObject{}
	for _, object := range p.Objects.Objects {
		objects[object.ID] = object
	}
	seeds := make([]linking.ProofSeed, 0, len(markers))
	seedBytes := 0
	for _, proof := range markers {
		object, ok := objects[proof]
		if !ok {
			return nil, linkFail("proof_required", "-", "restriction", proof)
		}
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return nil, e
		}
		if !linkRestrictiveProof(object.Kind, body) {
			return nil, linkFail("state_conflict", "-", "restriction")
		}
		seedBytes += len(body)
		seeds = append(seeds, linking.ProofSeed{Kind: object.Kind, Body: body})
	}
	catalog := p.Catalog
	request, e := linkJSON(map[string]any{"network": json.RawMessage(descriptor), "catalog": json.RawMessage(catalog), "feature_authorization": "-"})
	if e != nil {
		return nil, e
	}
	if len(request) > 1<<20 {
		if seedBytes > linking.MaxActivation {
			return nil, linkFail("quota_exceeded", "-", "restriction")
		}
		catalog, e = linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, seeds)
		if e != nil {
			return nil, e
		}
		request, e = linkJSON(map[string]any{"network": json.RawMessage(descriptor), "catalog": json.RawMessage(catalog), "feature_authorization": "-"})
		if e != nil {
			return nil, e
		}
		if len(request) > 1<<20 {
			return nil, linkFail("quota_exceeded", "-", "restriction")
		}
	}
	return request, nil
}

// Repair uses the existing live historical import, never a first-use grant or
// an immutable result receipt. Missing local evidence remains a hard refusal.
func (s *Store) resumeLinkRestrictionsLocked(ctx context.Context, n Network) (Network, error) {
	markers, e := readLinkRestrictionMarkers(ctx, s.db, n.ID)
	if e != nil || len(markers) == 0 {
		return n, e
	}
	now, e := linkNow()
	if e != nil {
		return n, e
	}
	p, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return n, e
	}
	if p == nil {
		return n, linkFail("upgrade_required", "-", "feature")
	}
	request, e := linkRestrictionRepairRequest(n, p, markers, now)
	if e != nil {
		return n, e
	}
	raw, e := s.linkCoordinator(ctx, n, "POST", "/coord/v2/networks/import", request)
	if e != nil {
		return n, &linkRestrictionTransportError{e}
	}
	pending, e := loadPendingRotation(ctx, s.db, n.ID)
	if e != nil {
		return n, e
	}
	if pending != nil {
		// A pending rotation owns the atomic root-seed/public-epoch transition.
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return n, e
		}
		defer tx.Rollback()
		if _, _, e = s.verifyLinkMap(ctx, tx, n, raw, now); e != nil {
			return n, e
		}
		if e = clearLinkRestrictionMarkers(ctx, tx, n.ID, markers); e != nil {
			return n, e
		}
		return n, tx.Commit()
	}
	return s.applyLinkMapWithHook(ctx, n, raw, func(ctx context.Context, tx *sql.Tx) error {
		return clearLinkRestrictionMarkers(ctx, tx, n.ID, markers)
	})
}
