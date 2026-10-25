package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkCatalogResponse struct {
	Catalog json.RawMessage `json:"catalog"`
}

func linkProjectionMember(p *linkProjection, host string) bool {
	for _, row := range p.Network.Members {
		public, e := membership.DecodeKey(row.HostPublicKey)
		if e == nil && membership.HostID(public) == host {
			return true
		}
	}
	return false
}
func readLinkMembers(ctx context.Context, q dbQuerier, network string) ([]NetworkMember, error) {
	rows, e := q.QueryContext(ctx, `SELECT record FROM network_members WHERE network_id=? ORDER BY host_id`, network)
	if e != nil {
		return nil, e
	}
	out := []NetworkMember{}
	for rows.Next() {
		member, e := readJSON[NetworkMember](rows)
		if e != nil {
			_ = rows.Close()
			return nil, e
		}
		out = append(out, member)
	}
	e = rows.Err()
	_ = rows.Close()
	return out, e
}
func (s *Store) LinkCatalog(ctx context.Context, sender, network string) (linkCatalogResponse, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, network)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	feature, _, e := readLinkFeature(ctx, s.db, network)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	if feature == "-" {
		return linkCatalogResponse{}, linkFail("upgrade_required", "-", "feature")
	}
	now, e := linkNow()
	if e != nil {
		return linkCatalogResponse{}, e
	}
	p, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	if !linkProjectionMember(p, sender) {
		return linkCatalogResponse{}, linkFail("forbidden", "-", "member")
	}
	response := linkCatalogResponse{Catalog: p.Catalog}
	raw, e := linkJSON(response)
	if e != nil {
		return response, e
	}
	if len(raw) > 16<<20 {
		return linkCatalogResponse{}, linkFail("quota_exceeded", "-", "catalog")
	}
	return response, nil
}
func (s *Store) ReceiveLinkCatalog(ctx context.Context, sender, network string, catalog []byte) (linkCatalogResponse, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, network)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	now, e := linkNow()
	if e != nil {
		return linkCatalogResponse{}, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	defer tx.Rollback()
	feature, _, e := readLinkFeature(ctx, tx, network)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	if feature == "-" {
		return linkCatalogResponse{}, linkFail("upgrade_required", "-", "feature")
	}
	prior, e := readLinkCatalog(ctx, tx, network)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	previousProjection, e := s.verifyLinkProjection(ctx, tx, n, prior, now)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	if !linkProjectionMember(previousProjection, sender) {
		return linkCatalogResponse{}, linkFail("forbidden", "-", "member")
	}
	merged, e := mergeLinkCatalog(network, prior, catalog)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	// Repair may supply a missing historical checkpoint/dependency. Resolve the
	// union first without omitting a single known restrictive or immutable row.
	p, e := s.verifyLinkProjection(ctx, tx, n, merged, now)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	if err := linking.VerifyStoredCatalogRepair(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: feature, Now: now}, prior, merged); err != nil {
		return linkCatalogResponse{}, err
	}
	response := linkCatalogResponse{Catalog: p.Catalog}
	raw, e := linkJSON(response)
	if e != nil {
		return response, e
	}
	if len(raw) > 16<<20 {
		return linkCatalogResponse{}, linkFail("quota_exceeded", "-", "catalog")
	}
	oldMembers, e := readLinkMembers(ctx, tx, network)
	if e != nil {
		return linkCatalogResponse{}, e
	}
	members := projectedLinkMembers(p, oldMembers, linkTime(now))
	if e = s.applyLinkProjection(ctx, tx, &n, p, members, linkTime(now)); e != nil {
		return linkCatalogResponse{}, e
	}
	if e = tx.Commit(); e != nil {
		return linkCatalogResponse{}, e
	}
	s.mapApplied(n.ID, members)
	return response, nil
}
func linkPeerRoutes(mux *http.ServeMux, s *Store, sender func(http.ResponseWriter, *http.Request) (string, bool)) {
	mux.HandleFunc("GET /peer/v1/networks/{network}/link-catalog", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" || r.ContentLength != 0 {
			respondLink(w, 0, nil, linkFail("invalid", "-", "request"), "-", "request")
			return
		}
		value, e := s.LinkCatalog(r.Context(), id, r.PathValue("network"))
		respondLink(w, http.StatusOK, value, e, "-", "catalog")
	})
	mux.HandleFunc("POST /peer/v1/networks/{network}/link-catalog", func(w http.ResponseWriter, r *http.Request) {
		id, ok := sender(w, r)
		if !ok {
			return
		}
		if r.URL.RawQuery != "" {
			respondLink(w, 0, nil, linkFail("invalid", "-", "request"), "-", "request")
			return
		}
		var request linkCatalogResponse
		if !decodeLinkMutation(w, r, "catalog", &request) {
			return
		}
		value, e := s.ReceiveLinkCatalog(r.Context(), id, r.PathValue("network"), request.Catalog)
		respondLink(w, http.StatusOK, value, e, "-", "catalog")
	})
}
func (s *Store) rejectLegacyLinkPeer(ctx context.Context, network string) error {
	feature, _, e := readLinkFeature(ctx, s.db, network)
	if e != nil {
		return e
	}
	if feature != "-" {
		return linkFail("upgrade_required", "-", "feature")
	}
	return nil
}
func decodePeerLinkCatalog(raw []byte, network string) ([]byte, error) {
	var response linkCatalogResponse
	if len(raw) > 16<<20 || linking.DecodeStoredJSON(raw, "catalog", &response) != nil {
		return nil, linkFail("invalid", "-", "catalog")
	}
	if _, e := decodeLinkCatalog(response.Catalog, network); e != nil {
		return nil, e
	}
	return response.Catalog, nil
}

func (s *Store) fetchLinkPeerCatalog(ctx context.Context, network, sibling string) error {
	peer, e := s.dialPeer(ctx, sibling)
	if e != nil {
		return e
	}
	status, raw, e := s.peerRequestLimit(ctx, peer, http.MethodGet, "/peer/v1/networks/"+url.PathEscape(network)+"/link-catalog", nil, 16<<20)
	if e != nil {
		return e
	}
	if status != http.StatusOK {
		return linkFail("unavailable", "-", "catalog")
	}
	catalog, e := decodePeerLinkCatalog(raw, network)
	if e != nil {
		return e
	}
	if _, e = s.ReceiveLinkCatalog(ctx, sibling, network, catalog); e != nil {
		return e
	}
	s.wakePolicyDeliveries()
	return nil
}
