package coord

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func sortLinkProofs(proofs []linkProof) []linkProof {
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].ID < proofs[j].ID })
	return proofs
}

func (s *Server) linkMutationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v2/networks/{network}/statements", s.linkStatementsHTTP)
	mux.HandleFunc("POST /coord/v2/networks/{network}/invite-redemptions", s.linkRedemptionHTTP)
	mux.HandleFunc("POST /coord/v2/networks/{network}/moves", s.linkMoveHTTP)
}

func (s *Server) linkState(ctx context.Context, tx *sql.Tx, r *http.Request) (linkNetwork, linkCatalog, string, error) {
	n, err := s.linkDescriptor(ctx, tx, r.PathValue("network"), r)
	var c linkCatalog
	var feature string
	if err == nil {
		feature, err = activeLinkFeature(ctx, tx, n.NetworkID)
	}
	if err == nil && feature == "-" {
		err = linkFailure(426, "upgrade_required")
	}
	if err == nil {
		c, err = linkCatalogOf(ctx, tx, n.NetworkID)
	}
	return n, c, feature, err
}

func linkFactContext(n linkNetwork, c linkCatalog, feature string, now time.Time) linking.CatalogFactContext {
	raw, _ := json.Marshal(n)
	return linking.CatalogFactContext{Network: raw, Epoch: catalogEpoch(c), KnownFeatureID: feature, Now: now}
}

// Reconcile reachability registrations after restrictions. Public proofs remain
// immutable, including the evidence for removed hosts.
func (s *Server) reconcileLinkMembers(ctx context.Context, tx *sql.Tx, n linkNetwork, c linkCatalog, feature string, now time.Time) error {
	raw, _ := json.Marshal(c)
	state, err := linking.VerifyStoredNetworkState(linkFactContext(n, c, feature, now), raw)
	if err != nil {
		return linkVerificationError(err)
	}
	allowed := map[string]bool{}
	for _, m := range state.Members {
		key, _ := membership.DecodeKey(m.HostPublicKey)
		allowed[membership.HostID(key)] = true
	}
	rows, err := tx.QueryContext(ctx, `SELECT host_id FROM members WHERE network_id=?`, n.NetworkID)
	if err != nil {
		return err
	}
	removed := []string{}
	registered := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		if !allowed[id] {
			removed = append(removed, id)
		}
		registered[id] = true
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	for _, id := range removed {
		if _, err = tx.ExecContext(ctx, `DELETE FROM members WHERE network_id=? AND host_id=?`, n.NetworkID, id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM member_candidates WHERE network_id=? AND host_id=?`, n.NetworkID, id); err != nil {
			return err
		}
	}
	for _, m := range state.Members {
		key, _ := membership.DecodeKey(m.HostPublicKey)
		id := membership.HostID(key)
		if registered[id] {
			continue
		}
		if err = s.checkMembers(ctx, tx, n.NetworkID); err != nil {
			return linkLegacyError(err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO members(network_id,host_id,invite_public_key,membership,address,updated_at,admission) VALUES(?,?,?,'','',?,'')`, n.NetworkID, id, "proof:"+m.HostPublicKey, membership.Timestamp(now)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) linkStatementsHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	var in struct {
		Catalog json.RawMessage `json:"catalog"`
	}
	if err == nil {
		err = linkBody(w, r, "catalog", &in)
	}
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	catalog, err := mergeLinkCatalog(linkCatalog{Format: 1, NetworkID: r.PathValue("network"), Objects: []linkProof{}}, in.Catalog)
	var value *linkMap
	if err == nil {
		value, err = s.applyLinkStatements(r, caller, catalog)
	}
	respondLink(w, 200, value, err, "")
}

func (s *Server) linkMoveHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	var in struct {
		Move    json.RawMessage `json:"move"`
		Catalog json.RawMessage `json:"catalog"`
	}
	if err == nil {
		err = linkBody(w, r, "move catalog", &in)
	}
	var catalog linkCatalog
	if err == nil {
		catalog, err = mergeLinkCatalog(linkCatalog{Format: 1, NetworkID: r.PathValue("network"), Objects: []linkProof{}}, in.Catalog)
	}
	if err == nil {
		catalog, err = combineLinkCatalog(catalog, linkCatalog{Format: 1, NetworkID: catalog.NetworkID, Objects: []linkProof{linkProofOf("coordinator_move", in.Move)}})
	}
	var value *linkMap
	if err == nil {
		value, err = s.applyLinkStatements(r, caller, catalog)
	}
	respondLink(w, 200, value, err, "")
}

func (s *Server) applyLinkStatements(r *http.Request, caller string, submitted linkCatalog) (*linkMap, error) {
	now, clockErr := linking.RuntimeNow(s.Now)
	if clockErr != nil {
		return nil, clockErr
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	n, c, feature, err := s.linkState(r.Context(), tx, r)
	var authorityErr error
	if err == nil {
		authorityErr = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
		var failure *linkError
		if authorityErr != nil && (!errors.As(authorityErr, &failure) || failure.code != "proof_required") {
			err = authorityErr
		}
	}
	prior, _ := json.Marshal(c)
	if err == nil {
		c, err = combineLinkCatalog(c, submitted)
	}
	if err == nil && authorityErr != nil {
		err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
	}
	if err == nil {
		raw, _ := json.Marshal(c)
		err = linking.VerifyStoredCatalogAdditions(linkFactContext(n, c, feature, now), prior, raw)
		if err != nil {
			err = linkVerificationError(err)
		}
	}
	if err == nil {
		err = storeLinkCatalog(r.Context(), tx, c)
	}
	if err == nil {
		err = s.reconcileLinkMembers(r.Context(), tx, n, c, feature, now)
	}
	var value *linkMap
	if err == nil {
		value, err = networkLinkMap(r.Context(), tx, n, c, feature, now)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err == nil {
		s.relay.changed(n.NetworkID)
	}
	return value, err
}

func linkInviteConflict(c linkCatalog, e linking.RedemptionEvidence) error {
	for _, p := range c.Objects {
		body, err := base64Body(p)
		if err != nil {
			return err
		}
		var o struct {
			Mode   string          `json:"mode"`
			Action string          `json:"person_action"`
			Key    string          `json:"invite_public_key"`
			Host   json.RawMessage `json:"host_invite"`
			Person json.RawMessage `json:"person_invite"`
		}
		if json.Unmarshal(body, &o) != nil {
			return linkFailure(409, "state_conflict")
		}
		host, person := "-", "-"
		switch p.Kind {
		case "host_membership":
			host = o.Key
		case "person_membership":
			person = o.Key
		case "invite_redemption":
			readKey := func(raw []byte) string {
				var invite struct {
					Key     string `json:"invite_public_key"`
					Payload string `json:"payload_base64"`
				}
				if json.Unmarshal(raw, &invite) != nil {
					return "-"
				}
				if invite.Payload != "" {
					decoded, _ := base64Body(linkProof{BodyBase64: invite.Payload})
					_ = json.Unmarshal(decoded, &invite)
				}
				return invite.Key
			}
			if o.Mode != "person" {
				host = readKey(o.Host)
			}
			if o.Action == "admit" {
				person = readKey(o.Person)
			}
		}
		if e.HostInvitePublicKey != "-" && host == e.HostInvitePublicKey || e.PersonInvitePublicKey != "-" && person == e.PersonInvitePublicKey {
			return linkFailure(409, "state_conflict")
		}
	}
	return nil
}

func (s *Server) linkRedemptionHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	var in struct {
		Redemption json.RawMessage `json:"redemption"`
		Catalog    json.RawMessage `json:"catalog"`
		Address    string          `json:"address"`
		Candidates []string        `json:"candidates"`
		JoinAck    json.RawMessage `json:"join_ack"`
	}
	if err == nil {
		err = linkBody(w, r, "redemption catalog address candidates join_ack", &in)
	}
	if err == nil && validEndpoints(in.Address, in.Candidates) != nil {
		err = linkFailure(400, "invalid")
	}
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	id := linkProofOf("invite_redemption", in.Redemption).ID
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	defer tx.Rollback()
	var oldNetwork, host string
	var stored []byte
	err = tx.QueryRowContext(r.Context(), `SELECT network_id,host_public_key,result FROM link_operations WHERE request_id=?`, "redemption:"+id).Scan(&oldNetwork, &host, &stored)
	if err == nil {
		if oldNetwork != r.PathValue("network") {
			err = linkFailure(409, "state_conflict")
		}
		var red struct {
			Mode string `json:"mode"`
		}
		_ = json.Unmarshal(in.Redemption, &red)
		if err == nil && red.Mode != "person" {
			key, _ := membership.DecodeKey(host)
			if membership.HostID(key) != caller {
				err = linkFailure(403, "forbidden")
			}
		}
		if err == nil && red.Mode == "person" {
			now, e := linking.RuntimeNow(s.Now)
			err = e
			if err == nil {
				n, c, feature, e := s.linkState(r.Context(), tx, r)
				err = e
				if err == nil {
					err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
				}
			}
		}
		respondLink(w, 200, json.RawMessage(stored), err, "")
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		respondLink(w, 0, nil, err, "")
		return
	}
	now, err := linking.RuntimeNow(s.Now)
	var n linkNetwork
	var c linkCatalog
	var feature string
	if err == nil {
		n, c, feature, err = s.linkState(r.Context(), tx, r)
	}
	prior, _ := json.Marshal(c)
	if err == nil {
		c, err = mergeLinkCatalog(c, in.Catalog)
	}
	if err == nil {
		catalog, _ := json.Marshal(c)
		err = linkVerificationError(linking.VerifyStoredCatalogAdditions(linkFactContext(n, c, feature, now), prior, catalog))
	}
	var verified linking.RedemptionEvidence
	if err == nil {
		raw, _ := json.Marshal(c)
		verified, err = linking.VerifyStoredFreshRedemption(linkFactContext(n, c, feature, now), raw, in.Redemption)
		if err != nil {
			err = linkVerificationError(err)
		}
	}
	if err == nil {
		err = linkInviteConflict(c, verified)
	}
	if err == nil && verified.Mode == "person" {
		if string(in.JoinAck) != `"-"` || in.Address != "" || len(in.Candidates) != 0 {
			err = linkFailure(400, "invalid")
		} else {
			err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
		}
	}
	if err == nil && verified.Mode != "person" {
		key, _ := membership.DecodeKey(verified.HostPublicKey)
		if membership.HostID(key) != caller {
			err = linkFailure(403, "forbidden")
		}
		var ack struct {
			Feature string `json:"feature_id"`
			Host    string `json:"host_public_key"`
		}
		if err == nil && (json.Unmarshal(in.JoinAck, &ack) != nil || ack.Host != verified.HostPublicKey || ack.Feature != feature) {
			err = linkFailure(400, "invalid")
		}
		if err == nil {
			if _, e := linking.Read("feature_ack", in.JoinAck, verified.HostPublicKey, "-"); e != nil {
				err = linkFailure(400, "invalid")
			}
		}
	}
	if err == nil {
		objects := []linkProof{linkProofOf("invite_redemption", in.Redemption)}
		if verified.Mode != "person" {
			objects = append(objects, linkProofOf("join_ack", in.JoinAck))
		}
		addition, _ := json.Marshal(linkCatalog{Format: 1, NetworkID: n.NetworkID, Objects: sortLinkProofs(objects)})
		c, err = mergeLinkCatalog(c, addition)
	}
	if err == nil {
		err = s.reconcileLinkMembers(r.Context(), tx, n, c, feature, now)
	}
	if err == nil && verified.Mode != "person" {
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `UPDATE members SET invite_public_key=?,membership='',address=?,updated_at=?,admission='' WHERE network_id=? AND host_id=?`, "redemption:"+verified.HostInvitePublicKey, in.Address, membership.Timestamp(now), n.NetworkID, caller)
		}
		if err == nil {
			err = putCandidates(r.Context(), tx, n.NetworkID, caller, in.Candidates)
		}
	}
	if err == nil {
		err = storeLinkCatalog(r.Context(), tx, c)
	}
	var value *linkMap
	if err == nil {
		value, err = networkLinkMap(r.Context(), tx, n, c, feature, now)
	}
	if err == nil {
		stored, err = json.Marshal(value)
	}
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO link_operations VALUES(?,?,?,?,?)`, "redemption:"+id, n.NetworkID, id, verified.HostPublicKey, stored)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err == nil {
		s.relay.changed(n.NetworkID)
	}
	respondLink(w, 201, value, linkLegacyError(err), "")
}
