package coord

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func (s *Server) linkMembersHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	_ = r.Body.Close()
	var shape map[string]json.RawMessage
	if err != nil || r.URL.RawQuery != "" || json.Unmarshal(raw, &shape) != nil {
		respondLink(w, 0, nil, linkFailure(400, "invalid"), "")
		return
	}
	var in struct {
		Membership json.RawMessage `json:"membership"`
		Admission  json.RawMessage `json:"admission"`
		Address    string          `json:"address"`
		Candidates []string        `json:"candidates"`
		JoinAck    json.RawMessage `json:"join_ack"`
		Version    uint64          `json:"linking_version"`
	}
	field, kind := "membership", "host_membership"
	if _, ok := shape["admission"]; ok {
		field, kind = "admission", "host_admission"
	}
	if linking.DecodeMutation(raw, field+" address candidates join_ack linking_version", &in) != nil || validEndpoints(in.Address, in.Candidates) != nil {
		respondLink(w, 0, nil, linkFailure(400, "invalid"), "")
		return
	}
	if in.Version != 1 {
		respondLink(w, 0, nil, linkFailure(426, "upgrade_required"), "")
		return
	}
	var active int
	err = s.db.QueryRowContext(r.Context(), `SELECT count(*) FROM link_features WHERE network_id=? AND active=1`, r.PathValue("network")).Scan(&active)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	body := in.Membership
	if field == "admission" {
		body = in.Admission
	}
	if active == 0 {
		if string(in.JoinAck) != `"-"` {
			respondLink(w, 0, nil, linkFailure(400, "invalid"), "")
			return
		}
		legacy := map[string]any{field: json.RawMessage(body), "address": in.Address, "candidates": in.Candidates}
		data, _ := json.Marshal(legacy)
		status, value, e := s.joinRequest(r.Context(), caller, r.PathValue("network"), data)
		respondLink(w, status, s.withSuccessors(r, value), linkLegacyError(e), "")
		if e == nil {
			s.relay.changed(r.PathValue("network"))
		}
		return
	}
	now, err := linking.RuntimeNow(s.Now)
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
	n, c, feature, err := s.linkState(r.Context(), tx, r)
	var target struct {
		Host string `json:"host_public_key"`
	}
	if err == nil && json.Unmarshal(body, &target) != nil {
		err = linkFailure(400, "invalid")
	}
	if err == nil {
		key, e := membership.DecodeKey(target.Host)
		if e != nil || membership.HostID(key) != caller {
			err = linkFailure(403, "forbidden")
		}
	}
	var ack struct {
		Host    string `json:"host_public_key"`
		Feature string `json:"feature_id"`
	}
	if err == nil && (json.Unmarshal(in.JoinAck, &ack) != nil || ack.Host != target.Host || ack.Feature != feature) {
		err = linkFailure(400, "invalid")
	}
	if err == nil {
		if _, e := linking.Read("feature_ack", in.JoinAck, target.Host, "-"); e != nil {
			err = linkFailure(400, "invalid")
		}
	}
	proof := linkProofOf(kind, body)
	known := false
	for _, p := range c.Objects {
		if p == proof {
			known = true
		}
	}
	var existing int
	if err == nil {
		err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM members WHERE network_id=? AND host_id=?`, n.NetworkID, caller).Scan(&existing)
	}
	status := 201
	if err == nil && existing > 0 {
		if !known {
			err = linkFailure(409, "state_conflict")
		} else {
			err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
			status = 200
		}
	}
	invite := "-"
	if err == nil && existing == 0 {
		catalog, _ := json.Marshal(c)
		_, invite, err = linking.VerifyStoredFreshLegacyJoin(linkFactContext(n, c, feature, now), catalog, kind, body)
		if err != nil {
			err = linkVerificationError(err)
		}
		if err == nil && invite != "-" {
			err = linkInviteConflict(c, linking.RedemptionEvidence{HostInvitePublicKey: invite, PersonInvitePublicKey: "-"})
		}
		if err == nil {
			err = s.checkMembers(r.Context(), tx, n.NetworkID)
		}
		if err == nil {
			membershipBody, admissionBody, inviteKey := "", "", "admission:"+target.Host
			if kind == "host_membership" {
				membershipBody = string(body)
				inviteKey = invite
			} else {
				admissionBody = string(body)
			}
			_, err = tx.ExecContext(r.Context(), `INSERT INTO members(network_id,host_id,invite_public_key,membership,address,updated_at,admission) VALUES(?,?,?,?,?,?,?)`, n.NetworkID, caller, inviteKey, membershipBody, in.Address, membership.Timestamp(now), admissionBody)
			if err == nil {
				err = putCandidates(r.Context(), tx, n.NetworkID, caller, in.Candidates)
			}
		}
	}
	if err == nil {
		addition, _ := json.Marshal(linkCatalog{Format: 1, NetworkID: n.NetworkID, Objects: sortLinkProofs([]linkProof{proof, linkProofOf("join_ack", in.JoinAck)})})
		c, err = mergeLinkCatalog(c, addition)
	}
	if err == nil {
		err = storeLinkCatalog(r.Context(), tx, c)
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
	respondLink(w, status, value, linkLegacyError(err), "")
}
