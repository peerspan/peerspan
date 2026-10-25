package coord

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func (s *Server) linkOperationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /coord/v2/networks/{network}/link-operations", s.linkOperationHTTP)
	mux.HandleFunc("GET /coord/v2/networks/{network}/link-operations/{request}", s.linkOperationHTTP)
}

// Request identity is verified independently of live authority so an exact lost
// response retry can recover its immutable outcome after expiry or withdrawal.
func linkOperationIdentity(raw []byte) (request, manifest, host string, err error) {
	var a struct {
		Request       json.RawMessage `json:"request"`
		Owner         json.RawMessage `json:"owner"`
		Selection     json.RawMessage `json:"selection"`
		Administrator json.RawMessage `json:"administrator"`
		Commit        json.RawMessage `json:"commit"`
	}
	if linking.DecodeMutation(raw, "request owner selection administrator commit", &a) != nil {
		return "", "", "", linkFailure(400, "invalid")
	}
	var req struct {
		RequestID string `json:"request_id"`
		Payload   string `json:"payload_base64"`
	}
	var payload struct {
		Host   string `json:"host_public_key"`
		Device string `json:"device_public_key"`
	}
	if json.Unmarshal(a.Request, &req) != nil {
		return "", "", "", linkFailure(400, "invalid")
	}
	p, decodeErr := base64.StdEncoding.Strict().DecodeString(req.Payload)
	if decodeErr != nil || json.Unmarshal(p, &payload) != nil {
		return "", "", "", linkFailure(400, "invalid")
	}
	if _, err = linking.Read("packet", a.Request, payload.Host, payload.Device); err != nil {
		return "", "", "", linkFailure(400, "invalid")
	}
	commit, readErr := linking.Read("packet", a.Commit, payload.Host, payload.Device)
	var com struct {
		RequestID string `json:"request_id"`
		Role      string `json:"role"`
	}
	if readErr != nil || json.Unmarshal(a.Commit, &com) != nil || com.Role != "commit" || com.RequestID != req.RequestID {
		return "", "", "", linkFailure(400, "invalid")
	}
	return req.RequestID, commit.ID, payload.Host, nil
}

func (s *Server) linkOperationHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	if err != nil {
		respondLink(w, 0, nil, err, "")
		return
	}
	var in struct {
		Activation json.RawMessage `json:"activation"`
		Catalog    json.RawMessage `json:"catalog"`
		Address    string          `json:"address"`
		Candidates []string        `json:"candidates"`
	}
	request, manifest, host := r.PathValue("request"), "", ""
	if r.Method == http.MethodPost {
		err = linkBodyLimit(w, r, "activation catalog address candidates", &in, 512<<10)
		if err == nil && validEndpoints(in.Address, in.Candidates) != nil {
			err = linkFailure(400, "invalid")
		}
		if err == nil {
			request, manifest, host, err = linkOperationIdentity(in.Activation)
		}
		if err == nil {
			key, _ := membership.DecodeKey(host)
			if membership.HostID(key) != caller {
				err = linkFailure(403, "forbidden")
			}
		}
	} else {
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 1))
		_ = r.Body.Close()
		if readErr != nil || len(body) != 0 || r.URL.RawQuery != "" || !linkRequestID(request) {
			err = linkFailure(400, "invalid")
		}
	}
	if err != nil {
		respondLink(w, 0, nil, err, request)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		respondLink(w, 0, nil, err, request)
		return
	}
	defer tx.Rollback()
	var oldNetwork, oldManifest, oldHost string
	var result []byte
	err = tx.QueryRowContext(r.Context(), `SELECT network_id,manifest_id,host_public_key,result FROM link_operations WHERE request_id=?`, request).Scan(&oldNetwork, &oldManifest, &oldHost, &result)
	if err == nil {
		if oldNetwork != r.PathValue("network") || r.Method == http.MethodPost && oldManifest != manifest {
			err = linkFailure(409, "operation_conflict")
		}
		key, _ := membership.DecodeKey(oldHost)
		if err == nil && membership.HostID(key) != caller {
			now, clockErr := linking.RuntimeNow(s.Now)
			err = clockErr
			if err == nil {
				var n linkNetwork
				var c linkCatalog
				var feature string
				n, err = s.linkDescriptor(r.Context(), tx, oldNetwork, r)
				if err == nil {
					c, err = linkCatalogOf(r.Context(), tx, oldNetwork)
				}
				if err == nil {
					feature, err = activeLinkFeature(r.Context(), tx, oldNetwork)
				}
				if err == nil {
					err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
				}
			}
		}
		respondLink(w, 200, json.RawMessage(result), err, request)
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		respondLink(w, 0, nil, err, request)
		return
	}
	if r.Method == http.MethodGet {
		respondLink(w, 0, nil, linkFailure(404, "not_found"), request)
		return
	}
	now, err := linking.RuntimeNow(s.Now)
	var n linkNetwork
	var c linkCatalog
	var feature string
	if err == nil {
		n, err = s.linkDescriptor(r.Context(), tx, r.PathValue("network"), r)
	}
	if err == nil {
		feature, err = activeLinkFeature(r.Context(), tx, n.NetworkID)
	}
	if err == nil && feature == "-" {
		err = linkFailure(426, "upgrade_required")
	}
	if err == nil {
		c, err = linkCatalogOf(r.Context(), tx, n.NetworkID)
	}
	prior, _ := json.Marshal(c)
	if err == nil {
		c, err = mergeLinkCatalog(c, in.Catalog)
	}
	if err == nil {
		catalog, _ := json.Marshal(c)
		err = linkVerificationError(linking.VerifyStoredCatalogAdditions(linkFactContext(n, c, feature, now), prior, catalog))
	}
	var verified linking.ActivationEvidence
	if err == nil {
		network, _ := json.Marshal(n)
		catalog, _ := json.Marshal(c)
		verified, err = linking.VerifyStoredActivation(linking.ActivationContext{Network: network, Epoch: catalogEpoch(c), KnownFeatureID: feature, CallerHostPublicKey: host, ExpectedPersonPublicKey: "-", Now: now, Verification: "first"}, catalog, in.Activation)
		if err != nil {
			err = linkVerificationError(err)
		}
	}
	if err == nil {
		addition, _ := json.Marshal(linkCatalog{Format: 1, NetworkID: n.NetworkID, Objects: []linkProof{linkProofOf("activation", in.Activation)}})
		c, err = mergeLinkCatalog(c, addition)
	}
	if err == nil {
		var count int
		err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM link_operations WHERE network_id=? AND request_id LIKE 'link_%'`, n.NetworkID).Scan(&count)
		if err == nil && count >= 4096 {
			err = linkFailure(409, "quota_exceeded")
		}
	}
	if err == nil {
		count := 0
		for _, raw := range verified.State.Certificates {
			var certificate struct {
				Person string `json:"person_public_key"`
			}
			if json.Unmarshal(raw, &certificate) != nil {
				err = linkFailure(409, "state_conflict")
				break
			}
			if certificate.Person == verified.PersonPublicKey {
				count++
			}
		}
		if count > 4096 {
			err = linkFailure(409, "quota_exceeded")
		}
	}
	if err == nil {
		result, err = s.linkResult(r, verified, in.Activation, c)
	}
	if err == nil && verified.Mode == "new" {
		var exists int
		err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM members WHERE network_id=? AND host_id=?`, n.NetworkID, caller).Scan(&exists)
		if err == nil && exists != 0 {
			err = linkFailure(409, "state_conflict")
		}
	}
	if err == nil {
		err = s.reconcileLinkMembers(r.Context(), tx, n, c, feature, now)
	}
	if err == nil && verified.Mode == "new" {
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `UPDATE members SET invite_public_key=?,membership='',address=?,updated_at=?,admission='' WHERE network_id=? AND host_id=?`, "link:"+host, in.Address, membership.Timestamp(now), n.NetworkID, caller)
		}
		if err == nil {
			err = putCandidates(r.Context(), tx, n.NetworkID, caller, in.Candidates)
		}
	}
	if err == nil {
		err = storeLinkCatalog(r.Context(), tx, c)
	}
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO link_operations VALUES(?,?,?,?,?)`, request, n.NetworkID, manifest, host, result)
	}
	if err == nil {
		err = linking.RuntimeBarrier(r.Context(), "coord.finalize.before_commit", request)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err == nil {
		err = linking.RuntimeBarrier(r.Context(), "coord.finalize.after_commit", request)
	}
	if err == nil {
		s.relay.changed(n.NetworkID)
	}
	respondLink(w, 201, json.RawMessage(result), err, request)
}

func linkRequestID(id string) bool {
	if len(id) != 69 || !strings.HasPrefix(id, "link_") {
		return false
	}
	for _, c := range id[5:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (s *Server) linkResult(r *http.Request, v linking.ActivationEvidence, activation []byte, c linkCatalog) ([]byte, error) {
	// Preserve exact nested transport bytes; RawMessage marshaling would compact
	// original statements and change their proof identifiers.
	full, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var n linkNetwork
	// The descriptor is already verified in the activation's owner packet. Use
	// its exact pins while selecting the public dependency closure.
	var transcript struct {
		Owner struct {
			Payload string `json:"payload_base64"`
		} `json:"owner"`
	}
	if json.Unmarshal(activation, &transcript) != nil {
		return nil, linkFailure(400, "invalid")
	}
	owner, err := base64.StdEncoding.Strict().DecodeString(transcript.Owner.Payload)
	var offer struct {
		Network linkNetwork `json:"network"`
	}
	if err != nil || json.Unmarshal(owner, &offer) != nil {
		return nil, linkFailure(400, "invalid")
	}
	n = offer.Network
	network, _ := json.Marshal(n)
	now, err := linking.RuntimeNow(s.Now)
	if err != nil {
		return nil, err
	}
	catalog, err := linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: network, Epoch: catalogEpoch(c), KnownFeatureID: v.FeatureID, Now: now}, full, []linking.ProofSeed{{Kind: "activation", Body: activation}})
	if err != nil {
		return nil, linkVerificationError(err)
	}
	manifest, _ := json.Marshal(v.ManifestID)
	payload := bytes.Join([][]byte{[]byte(`{"manifest_id":`), manifest, []byte(`,"activation":`), activation, []byte(`,"catalog":`), catalog, []byte(`}`)}, nil)
	if len(payload) > linking.MaxPayload {
		return nil, linkFailure(409, "quota_exceeded")
	}
	identity := s.identities[s.requestSequence(r.Context())]
	message := []byte(strings.Join([]string{"peerspan-link-packet-v1", v.RequestID, "result", identity.identity.PublicKey, "-", "coordinator", linkHash(payload)}, "\n"))
	out := map[string]any{"format": 1, "request_id": v.RequestID, "role": "result", "writer_public_key": identity.identity.PublicKey, "person_public_key": "-", "certificate_id": "coordinator", "payload_base64": base64.StdEncoding.EncodeToString(payload), "host_signature": "-", "device_signature": "-", "authority_signature": base64.StdEncoding.EncodeToString(ed25519.Sign(identity.key, message))}
	result, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(result) > 1<<20 {
		return nil, linkFailure(409, "quota_exceeded")
	}
	if _, err = linking.Read("packet", result, identity.identity.PublicKey, "-"); err != nil {
		return nil, err
	}
	return result, nil
}
