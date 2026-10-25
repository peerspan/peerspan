package coord

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkMapMember struct {
	HostID            string   `json:"host_id"`
	HostPublicKey     string   `json:"host_public_key"`
	MembershipProofID string   `json:"membership_proof_id"`
	BindingProofID    string   `json:"binding_proof_id"`
	JoinProofID       string   `json:"join_proof_id"`
	Address           string   `json:"address"`
	Candidates        []string `json:"candidates"`
	UpdatedAt         string   `json:"updated_at"`
}
type linkMap struct {
	Format  uint64          `json:"format"`
	Network linkNetwork     `json:"network"`
	Catalog linkCatalog     `json:"catalog"`
	Members []linkMapMember `json:"members"`
}

func networkLinkMap(ctx context.Context, tx *sql.Tx, n linkNetwork, c linkCatalog, feature string, now time.Time) (*linkMap, error) {
	if feature == "-" {
		return nil, linkFailure(426, "upgrade_required")
	}
	network, _ := json.Marshal(n)
	catalog, _ := json.Marshal(c)
	verified, err := linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: network, Epoch: catalogEpoch(c), KnownFeatureID: feature, Now: now}, catalog)
	if err != nil {
		return nil, linkVerificationError(err)
	}
	byHost := map[string]linking.MemberProof{}
	for _, m := range verified.Members {
		key, _ := membership.DecodeKey(m.HostPublicKey)
		byHost[membership.HostID(key)] = m
	}
	out := &linkMap{Format: 2, Network: n, Catalog: c, Members: []linkMapMember{}}
	rows, err := tx.QueryContext(ctx, `SELECT m.host_id,m.address,m.updated_at,COALESCE(c.candidates,'[]') FROM members m LEFT JOIN member_candidates c ON c.network_id=m.network_id AND c.host_id=m.host_id WHERE m.network_id=? ORDER BY m.host_id`, n.NetworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var host, address, updated, candidates string
		if err = rows.Scan(&host, &address, &updated, &candidates); err != nil {
			return nil, err
		}
		proof, ok := byHost[host]
		if !ok {
			continue
		}
		addresses := []string{}
		if json.Unmarshal([]byte(candidates), &addresses) != nil || addresses == nil {
			addresses = []string{}
		}
		if validEndpoints(address, addresses) != nil {
			address = ""
			addresses = []string{}
		}
		out.Members = append(out.Members, linkMapMember{host, proof.HostPublicKey, proof.MembershipProofID, proof.BindingProofID, proof.JoinProofID, address, addresses, updated})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(encoded)+1 > 16<<20 {
		return nil, linkFailure(409, "quota_exceeded")
	}
	return out, nil
}

func (s *Server) linkMapRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v2/networks", s.linkRegisterHTTP)
	mux.HandleFunc("POST /coord/v2/networks/import", s.linkImportHTTP)
	mux.HandleFunc("GET /coord/v2/networks/{network}/map", s.linkMapHTTP)
	mux.HandleFunc("POST /coord/v2/networks/{network}/sync", s.linkMapHTTP)
	mux.HandleFunc("POST /coord/v2/networks/{network}/members", s.linkMembersHTTP)
}

func (s *Server) linkMapHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	now, err := linking.RuntimeNow(s.Now)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	var in struct {
		Address        string   `json:"address"`
		Candidates     []string `json:"candidates"`
		LinkingVersion uint64   `json:"linking_version"`
	}
	if r.Method == http.MethodPost {
		err = linkBody(w, r, "address candidates linking_version", &in)
		if err == nil && in.LinkingVersion != 1 {
			err = linkFailure(426, "upgrade_required")
		}
		if err == nil && validEndpoints(in.Address, in.Candidates) != nil {
			err = linkFailure(400, "invalid")
		}
	} else {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 1))
		_ = r.Body.Close()
		if readErr != nil || len(body) > 0 || r.URL.RawQuery != "" {
			err = linkFailure(400, "invalid")
		}
	}
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	defer tx.Rollback()
	n, err := s.linkDescriptor(r.Context(), tx, r.PathValue("network"), r)
	var feature string
	var c linkCatalog
	if err == nil {
		feature, err = activeLinkFeature(r.Context(), tx, n.NetworkID)
	}
	legacySync := err == nil && feature == "-" && r.Method == http.MethodPost
	if err == nil && !legacySync {
		c, err = linkCatalogOf(r.Context(), tx, n.NetworkID)
	}
	if err == nil && !legacySync {
		err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
	}
	if err == nil && r.Method == http.MethodPost {
		var result sql.Result
		result, err = tx.ExecContext(r.Context(), `UPDATE members SET address=?,updated_at=? WHERE network_id=? AND host_id=?`, in.Address, membership.Timestamp(now), n.NetworkID, caller)
		if err == nil {
			count, countErr := result.RowsAffected()
			err = countErr
			if err == nil && count != 1 {
				err = linkFailure(403, "forbidden")
			}
		}
		if err == nil {
			err = putCandidates(r.Context(), tx, n.NetworkID, caller, in.Candidates)
		}
	}
	var value any
	if err == nil {
		if feature == "-" && r.Method == http.MethodPost {
			var legacy *membership.Map
			legacy, err = networkMap(r.Context(), tx, n.NetworkID)
			value = s.withSuccessors(r, legacy)
		} else {
			value, err = networkLinkMap(r.Context(), tx, n, c, feature, now)
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	respondLink(w, 200, value, err, "")
}

func (s *Server) linkRegisterHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	var req struct {
		registerRequest
		LinkingVersion uint64 `json:"linking_version"`
	}
	err = linkBody(w, r, "name root_public_key membership address candidates linking_version", &req)
	if err == nil && req.LinkingVersion != 1 {
		err = linkFailure(426, "upgrade_required")
	}
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	// Registration is pre-feature. An existing upgraded network is read through
	// its verified format-2 map instead of returning a legacy snapshot.
	var active int
	err = s.db.QueryRowContext(r.Context(), `SELECT count(*) FROM link_features WHERE network_id=? AND active=1`, req.Membership.NetworkID).Scan(&active)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	if active > 0 {
		r.SetPathValue("network", req.Membership.NetworkID)
		r.Method = http.MethodGet
		r.Body = http.NoBody
		s.linkMapHTTP(w, r)
		return
	}
	status, value, err := s.registerFrom(r.Context(), caller, sourceOf(r.RemoteAddr), req.registerRequest)
	var limited *limitError
	if errors.As(err, &limited) {
		respond(w, 0, nil, err)
		return
	}
	if err != nil {
		err = linkLegacyError(err)
	}
	respondLink(w, status, s.withSuccessors(r, value), err, "")
	if err == nil && status == 201 {
		s.relay.changed(req.Membership.NetworkID)
	}
}

func linkLegacyError(err error) error {
	if err == nil {
		return nil
	}
	var limit *limitError
	if errors.As(err, &limit) {
		return linkFailure(409, "quota_exceeded")
	}
	switch {
	case errors.Is(err, errInvalid), errors.Is(err, membership.ErrInvalid):
		return linkFailure(400, "invalid")
	case errors.Is(err, errForbidden):
		return linkFailure(403, "forbidden")
	case errors.Is(err, errNotFound):
		return linkFailure(404, "not_found")
	case errors.Is(err, errConflict):
		return linkFailure(409, "state_conflict")
	}
	return err
}

func (s *Server) rejectLegacyLinking(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (strings.HasPrefix(r.URL.Path, "/coord/v1/networks") || strings.HasPrefix(r.URL.Path, "/coord/v2/networks")) {
			s.linkNetworkWrites.Lock()
			defer s.linkNetworkWrites.Unlock()
		}
		if r.Method == http.MethodPost {
			if rest, ok := strings.CutPrefix(r.URL.Path, "/coord/v1/networks/"); ok {
				network, _, _ := strings.Cut(rest, "/")
				var active int
				err := s.db.QueryRowContext(r.Context(), `SELECT count(*) FROM link_features WHERE network_id=? AND active=1`, network).Scan(&active)
				if err != nil {
					respondLink(w, 0, nil, err, "")
					return
				}
				if active > 0 {
					respondLink(w, 0, nil, linkFailure(426, "upgrade_required"), "")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Keep deterministic map order explicit when composing maps outside SQL.
func sortLinkMap(m *linkMap) {
	sort.Slice(m.Members, func(i, j int) bool { return m.Members[i].HostID < m.Members[j].HostID })
}
