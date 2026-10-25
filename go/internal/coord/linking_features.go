package coord

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type pendingLinkFeature struct {
	Catalog         linkCatalog `json:"catalog"`
	Acknowledgments []string    `json:"acknowledgments_base64"`
}
type linkFeatureView struct {
	Proposal        json.RawMessage   `json:"proposal"`
	Acknowledgments []json.RawMessage `json:"acknowledgments"`
}

func linkBody(w http.ResponseWriter, r *http.Request, required string, dst any) error {
	return linkBodyLimit(w, r, required, dst, 1<<20)
}

func linkBodyLimit(w http.ResponseWriter, r *http.Request, required string, dst any, limit int64) error {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil || r.URL.RawQuery != "" || linking.DecodeMutation(body, required, dst) != nil {
		return linkFailure(400, "invalid")
	}
	return nil
}

func catalogEpoch(c linkCatalog) uint64 {
	var epoch uint64
	for _, p := range c.Objects {
		if p.Kind == "rotation" {
			body, _ := base64Body(p)
			var o struct {
				Epoch uint64 `json:"epoch"`
			}
			if json.Unmarshal(body, &o) == nil && o.Epoch > epoch {
				epoch = o.Epoch
			}
		}
	}
	return epoch
}
func base64Body(p linkProof) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(p.BodyBase64)
}

func currentLinkMember(ctx context.Context, tx *sql.Tx, n linkNetwork, c linkCatalog, feature, caller string, now time.Time) error {
	if feature == "-" {
		return currentLegacyLinkMember(ctx, tx, n.NetworkID, caller)
	}
	network, _ := json.Marshal(n)
	catalog, _ := json.Marshal(c)
	state, err := linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: network, Epoch: catalogEpoch(c), KnownFeatureID: feature, Now: now}, catalog)
	if err != nil {
		return linkVerificationError(err)
	}
	for host, admitted := range state.Facts.State.Hosts {
		key, _ := membership.DecodeKey(host)
		if admitted && membership.HostID(key) == caller {
			return nil
		}
	}
	return linkFailure(403, "forbidden")
}

func currentLegacyLinkMember(ctx context.Context, tx *sql.Tx, network, caller string) error {
	chain, err := chainOf(ctx, tx, network)
	if err != nil {
		return err
	}
	revoked, err := revokedOf(ctx, tx, chain)
	if err != nil {
		return err
	}
	var member, admission string
	err = tx.QueryRowContext(ctx, `SELECT membership,COALESCE(admission,'') FROM members WHERE network_id=? AND host_id=?`, network, caller).Scan(&member, &admission)
	if errors.Is(err, sql.ErrNoRows) {
		return linkFailure(403, "forbidden")
	}
	if err != nil {
		return err
	}
	attestations := map[string]membership.Attestation{}
	raw, err := statementsOf(ctx, tx, network, kindAttestation)
	if err != nil {
		return err
	}
	for _, body := range raw {
		var a membership.Attestation
		if json.Unmarshal(body, &a) == nil && chain.VerifyAttestation(a) == nil {
			attestations[a.HostPublicKey] = a
		}
	}
	if member != "" {
		var m membership.Membership
		if json.Unmarshal([]byte(member), &m) != nil || revoked.Excludes(m) {
			return linkFailure(403, "forbidden")
		}
		id, verifyErr := chain.ValidMember(m, attestations)
		if verifyErr != nil || id != caller {
			return linkFailure(403, "forbidden")
		}
		return nil
	}
	var a membership.HostAdmission
	if json.Unmarshal([]byte(admission), &a) != nil || revoked.ExcludesHost(a.HostPublicKey, "") {
		return linkFailure(403, "forbidden")
	}
	id, verifyErr := chain.VerifyHostAdmission(a)
	if verifyErr != nil && a.Epoch >= 0 && a.Epoch < chain.Epoch() {
		old := chain
		old.Roots = chain.Roots[:a.Epoch+1]
		id, verifyErr = old.VerifyHostAdmission(a)
		attested, ok := attestations[a.HostPublicKey]
		if !ok || attested.Member != a.Member {
			verifyErr = errForbidden
		}
	}
	if verifyErr != nil || id != caller {
		return linkFailure(403, "forbidden")
	}
	return nil
}

func (s *Server) linkFeatureRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v2/networks/{network}/link-feature/proposals", s.linkFeatureHTTP)
	mux.HandleFunc("GET /coord/v2/networks/{network}/link-feature/proposals", s.linkFeatureHTTP)
	mux.HandleFunc("POST /coord/v2/networks/{network}/link-feature/acknowledgments", s.linkFeatureHTTP)
	mux.HandleFunc("POST /coord/v2/networks/{network}/link-feature", s.linkFeatureHTTP)
}

func (s *Server) linkFeatureHTTP(w http.ResponseWriter, r *http.Request) {
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
		Proposal       json.RawMessage `json:"proposal"`
		Acknowledgment json.RawMessage `json:"acknowledgment"`
		Feature        json.RawMessage `json:"feature"`
		Catalog        json.RawMessage `json:"catalog"`
	}
	kind := "feature"
	switch r.Pattern {
	case "POST /coord/v2/networks/{network}/link-feature/proposals":
		kind = "proposal"
	case "POST /coord/v2/networks/{network}/link-feature/acknowledgments":
		kind = "acknowledgment"
	}
	if r.Method == http.MethodPost {
		if err = linkBody(w, r, kind+" catalog", &in); err != nil {
			respondLink(w, 0, nil, err, "")
			return
		}
	} else {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 1))
		_ = r.Body.Close()
		if readErr != nil || len(body) > 0 || r.URL.RawQuery != "" {
			respondLink(w, 0, nil, linkFailure(400, "invalid"), "")
			return
		}
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	defer tx.Rollback()
	n, err := s.linkDescriptor(r.Context(), tx, r.PathValue("network"), r)
	var c linkCatalog
	var feature string
	if err == nil {
		c, err = linkCatalogOf(r.Context(), tx, n.NetworkID)
	}
	if err == nil {
		feature, err = activeLinkFeature(r.Context(), tx, n.NetworkID)
	}
	if err == nil {
		err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
	}
	var value any
	status := 200
	if err == nil {
		if r.Method == http.MethodGet {
			value, err = linkFeatureCandidates(r.Context(), tx, n.NetworkID)
		} else {
			prior := c
			c, err = mergeLinkCatalog(c, in.Catalog)
			if err == nil {
				switch kind {
				case "proposal":
					status, value, err = s.prepareLinkFeature(r.Context(), tx, n, c, feature, in.Proposal, caller, now)
				case "acknowledgment":
					status, value, err = s.acknowledgeLinkFeature(r.Context(), tx, n, c, feature, in.Acknowledgment, caller, now)
				default:
					status, value, err = s.activateLinkFeature(r.Context(), tx, n, prior, c, feature, in.Feature, now)
				}
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err == nil && r.Method == http.MethodPost {
		s.relay.changed(n.NetworkID)
	}
	respondLink(w, status, value, err, "")
}

func linkFeatureCandidates(ctx context.Context, tx *sql.Tx, network string) (any, error) {
	rows, err := tx.QueryContext(ctx, `SELECT proposal,feature,active FROM link_features WHERE network_id=? ORDER BY feature_id`, network)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []linkFeatureView{}
	for rows.Next() {
		var proposal, body []byte
		var active int
		if err = rows.Scan(&proposal, &body, &active); err != nil {
			return nil, err
		}
		view := linkFeatureView{Proposal: proposal, Acknowledgments: []json.RawMessage{}}
		if active == 1 {
			var f linkFeatureView
			if err = json.Unmarshal(body, &f); err != nil {
				return nil, err
			}
			view.Acknowledgments = f.Acknowledgments
		} else {
			var p pendingLinkFeature
			if err = json.Unmarshal(body, &p); err != nil {
				return nil, err
			}
			for _, encoded := range p.Acknowledgments {
				raw, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
				if decodeErr != nil {
					return nil, decodeErr
				}
				view.Acknowledgments = append(view.Acknowledgments, json.RawMessage(raw))
			}
		}
		out = append(out, view)
	}
	return map[string]any{"proposals": out}, rows.Err()
}

func (s *Server) prepareLinkFeature(ctx context.Context, tx *sql.Tx, n linkNetwork, c linkCatalog, feature string, proposal []byte, caller string, now time.Time) (int, any, error) {
	var id string
	// Validate immutable retries from stored exact bytes before current deadlines.
	var stored []byte
	err := tx.QueryRowContext(ctx, `SELECT feature_id,proposal FROM link_features WHERE network_id=? AND proposal=?`, n.NetworkID, proposal).Scan(&id, &stored)
	if err == nil {
		return 200, map[string]string{"feature_id": id}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, err
	}
	if feature != "-" {
		return 0, nil, linkFailure(409, "state_conflict")
	}
	network, _ := json.Marshal(n)
	catalog, _ := json.Marshal(c)
	verified, err := linking.VerifyStoredFeaturePreparation(linking.FeatureContext{Network: network, Epoch: catalogEpoch(c), KnownFeatureID: "-", Now: now}, catalog, proposal)
	if err != nil {
		return 0, nil, linkVerificationError(err)
	}
	allowed := false
	for host, admitted := range verified.State.Hosts {
		key, _ := membership.DecodeKey(host)
		if admitted && membership.HostID(key) == caller {
			allowed = true
		}
	}
	if !allowed {
		return 0, nil, linkFailure(403, "forbidden")
	}
	id = verified.FeatureID
	rows, cleanupErr := tx.QueryContext(ctx, `SELECT feature_id,proposal FROM link_features WHERE network_id=? AND active=0`, n.NetworkID)
	if cleanupErr != nil {
		return 0, nil, cleanupErr
	}
	expired := []string{}
	for rows.Next() {
		var candidate string
		var raw []byte
		if cleanupErr = rows.Scan(&candidate, &raw); cleanupErr != nil {
			break
		}
		var p struct {
			IssuedAt string `json:"issued_at"`
		}
		if json.Unmarshal(raw, &p) != nil {
			cleanupErr = linkFailure(409, "state_conflict")
			break
		}
		issued, parseErr := time.Parse("2006-01-02T15:04:05Z", p.IssuedAt)
		if parseErr != nil {
			cleanupErr = linkFailure(409, "state_conflict")
			break
		}
		if !now.Before(issued.Add(24 * time.Hour)) {
			expired = append(expired, candidate)
		}
	}
	cleanupErr = errors.Join(cleanupErr, rows.Err(), rows.Close())
	if cleanupErr != nil {
		return 0, nil, cleanupErr
	}
	for _, candidate := range expired {
		if _, err = tx.ExecContext(ctx, `DELETE FROM link_features WHERE network_id=? AND feature_id=? AND active=0`, n.NetworkID, candidate); err != nil {
			return 0, nil, err
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM link_features WHERE network_id=? AND active=0`, n.NetworkID).Scan(&count); err != nil {
		return 0, nil, err
	}
	if count >= 8 {
		return 0, nil, linkFailure(409, "quota_exceeded")
	}
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM link_features WHERE network_id=? AND feature_id=?`, n.NetworkID, id).Scan(&exists); err != nil {
		return 0, nil, err
	}
	if exists > 0 {
		return 0, nil, linkFailure(409, "operation_conflict")
	}
	pending, _ := json.Marshal(pendingLinkFeature{Catalog: c, Acknowledgments: []string{}})
	if _, err = tx.ExecContext(ctx, `INSERT INTO link_features(network_id,feature_id,proposal,feature,active) VALUES(?,?,?,?,0)`, n.NetworkID, id, proposal, pending); err != nil {
		return 0, nil, err
	}
	return 201, map[string]string{"feature_id": id}, nil
}

func (s *Server) acknowledgeLinkFeature(ctx context.Context, tx *sql.Tx, n linkNetwork, c linkCatalog, feature string, ack []byte, caller string, now time.Time) (int, any, error) {
	var a struct {
		FeatureID     string `json:"feature_id"`
		HostPublicKey string `json:"host_public_key"`
	}
	if json.Unmarshal(ack, &a) != nil {
		return 0, nil, linkFailure(400, "invalid")
	}
	pub, err := membership.DecodeKey(a.HostPublicKey)
	if err != nil || membership.HostID(pub) != caller {
		return 0, nil, linkFailure(403, "forbidden")
	}
	if _, err = linking.Read("feature_ack", ack, a.HostPublicKey, "-"); err != nil {
		return 0, nil, linkFailure(400, "invalid")
	}
	var proposal, body []byte
	var active int
	err = tx.QueryRowContext(ctx, `SELECT proposal,feature,active FROM link_features WHERE network_id=? AND feature_id=?`, n.NetworkID, a.FeatureID).Scan(&proposal, &body, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, linkFailure(404, "not_found")
	}
	if err != nil {
		return 0, nil, err
	}
	var pending pendingLinkFeature
	if active == 1 {
		var f linkFeatureView
		if err = json.Unmarshal(body, &f); err != nil {
			return 0, nil, err
		}
		for _, raw := range f.Acknowledgments {
			pending.Acknowledgments = append(pending.Acknowledgments, base64.StdEncoding.EncodeToString(raw))
		}
	} else {
		if err = json.Unmarshal(body, &pending); err != nil {
			return 0, nil, err
		}
		if c, err = combineLinkCatalog(c, pending.Catalog); err != nil {
			return 0, nil, err
		}
	}
	for _, encoded := range pending.Acknowledgments {
		old, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
		if decodeErr != nil {
			return 0, nil, decodeErr
		}
		var prior struct {
			HostPublicKey string `json:"host_public_key"`
		}
		_ = json.Unmarshal(old, &prior)
		if prior.HostPublicKey == a.HostPublicKey {
			if !bytes.Equal(old, ack) {
				return 0, nil, linkFailure(409, "operation_conflict")
			}
			return 200, map[string]string{"feature_id": a.FeatureID}, nil
		}
	}
	if feature != "-" || active == 1 {
		return 0, nil, linkFailure(409, "state_conflict")
	}
	network, _ := json.Marshal(n)
	catalog, _ := json.Marshal(c)
	if _, err = linking.VerifyStoredFeaturePreparation(linking.FeatureContext{Network: network, Epoch: catalogEpoch(c), KnownFeatureID: "-", Now: now}, catalog, proposal); err != nil {
		return 0, nil, linkVerificationError(err)
	}
	var p struct {
		Hosts []string `json:"host_public_keys"`
	}
	_ = json.Unmarshal(proposal, &p)
	listed := false
	for _, host := range p.Hosts {
		if host == a.HostPublicKey {
			listed = true
		}
	}
	if !listed {
		return 0, nil, linkFailure(403, "forbidden")
	}
	pending.Catalog = c
	pending.Acknowledgments = append(pending.Acknowledgments, base64.StdEncoding.EncodeToString(ack))
	sort.Slice(pending.Acknowledgments, func(i, j int) bool {
		var left, right struct {
			Host string `json:"host_public_key"`
		}
		leftRaw, _ := base64.StdEncoding.DecodeString(pending.Acknowledgments[i])
		rightRaw, _ := base64.StdEncoding.DecodeString(pending.Acknowledgments[j])
		_ = json.Unmarshal(leftRaw, &left)
		_ = json.Unmarshal(rightRaw, &right)
		return left.Host < right.Host
	})
	body, _ = json.Marshal(pending)
	_, err = tx.ExecContext(ctx, `UPDATE link_features SET feature=? WHERE network_id=? AND feature_id=? AND active=0`, body, n.NetworkID, a.FeatureID)
	return 201, map[string]string{"feature_id": a.FeatureID}, err
}

func (s *Server) activateLinkFeature(ctx context.Context, tx *sql.Tx, n linkNetwork, prior, c linkCatalog, known string, feature []byte, now time.Time) (int, any, error) {
	var incoming linkFeatureView
	if json.Unmarshal(feature, &incoming) != nil {
		return 0, nil, linkFailure(400, "invalid")
	}
	rows, loadErr := tx.QueryContext(ctx, `SELECT feature FROM link_features WHERE network_id=? AND proposal=? AND active=0`, n.NetworkID, []byte(incoming.Proposal))
	if loadErr != nil {
		return 0, nil, loadErr
	}
	for rows.Next() {
		var raw []byte
		var pending pendingLinkFeature
		if loadErr = rows.Scan(&raw); loadErr != nil {
			break
		}
		if loadErr = json.Unmarshal(raw, &pending); loadErr != nil {
			break
		}
		c, loadErr = combineLinkCatalog(c, pending.Catalog)
		if loadErr != nil {
			break
		}
	}
	loadErr = errors.Join(loadErr, rows.Err(), rows.Close())
	if loadErr != nil {
		return 0, nil, loadErr
	}
	network, _ := json.Marshal(n)
	catalog, _ := json.Marshal(c)
	verified, err := linking.VerifyStoredFeature(linking.FeatureContext{Network: network, Epoch: catalogEpoch(c), KnownFeatureID: known, Now: now}, catalog, feature)
	if err != nil {
		return 0, nil, linkVerificationError(err)
	}
	if known != "-" {
		var old []byte
		if err = tx.QueryRowContext(ctx, `SELECT feature FROM link_features WHERE network_id=? AND active=1`, n.NetworkID).Scan(&old); err != nil {
			return 0, nil, err
		}
		if !bytes.Equal(old, feature) {
			return 0, nil, linkFailure(409, "operation_conflict")
		}
		return 200, map[string]string{"feature_id": known}, nil
	}
	var f linkFeatureView
	_ = json.Unmarshal(feature, &f)
	addition := linkCatalog{Format: 1, NetworkID: n.NetworkID, Objects: []linkProof{linkProofOf("feature", feature)}}
	raw, _ := json.Marshal(addition)
	if c, err = mergeLinkCatalog(c, raw); err != nil {
		return 0, nil, err
	}
	before, _ := json.Marshal(prior)
	candidate, _ := json.Marshal(c)
	if err = linking.VerifyStoredCatalogAdditions(linkFactContext(n, c, verified.FeatureID, now), before, candidate); err != nil {
		return 0, nil, linkVerificationError(err)
	}
	if err = s.reconcileLinkMembers(ctx, tx, n, c, verified.FeatureID, now); err != nil {
		return 0, nil, err
	}
	if err = storeLinkCatalog(ctx, tx, c); err != nil {
		return 0, nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO link_features(network_id,feature_id,proposal,feature,active) VALUES(?,?,?,?,1) ON CONFLICT(network_id,feature_id) DO UPDATE SET feature=excluded.feature,active=1`, n.NetworkID, verified.FeatureID, []byte(f.Proposal), feature); err != nil {
		return 0, nil, err
	}
	return 201, map[string]string{"feature_id": verified.FeatureID}, nil
}
