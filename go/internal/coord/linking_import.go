package coord

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkImportOutcome struct {
	Authorization string `json:"authorization_base64"`
	Catalog       string `json:"catalog_base64"`
	Map           string `json:"map_base64"`
}

const kindLinkFeatureImport = "link_feature_import"

func (s *Server) linkImportHTTP(w http.ResponseWriter, r *http.Request) {
	caller, err := linkCaller(r)
	var in struct {
		Network       json.RawMessage `json:"network"`
		Catalog       json.RawMessage `json:"catalog"`
		Authorization json.RawMessage `json:"feature_authorization"`
	}
	if err == nil {
		err = linkBody(w, r, "network catalog feature_authorization", &in)
	}
	var n linkNetwork
	if err == nil && linking.DecodeMutation(in.Network, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &n) != nil {
		err = linkFailure(400, "invalid")
	}
	if err == nil && (n.CoordinatorAddress != r.Host || n.CoordinatorPublicKey != s.identities[s.requestSequence(r.Context())].identity.PublicKey) {
		err = linkFailure(400, "invalid")
	}
	if err == nil {
		key, e := membership.DecodeKey(n.GenesisRootPublicKey)
		if e != nil || membership.NetworkID(key) != n.NetworkID || !membership.ValidLabel(n.Name) || !membership.ValidCoordinatorAddress(n.CoordinatorAddress) {
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
	operation := "feature-import:" + linkHash(in.Authorization)
	if string(in.Authorization) != `"-"` {
		var network, host string
		var result []byte
		e := tx.QueryRowContext(r.Context(), `SELECT network_id,host_public_key,result FROM link_operations WHERE request_id=?`, operation).Scan(&network, &host, &result)
		if e == nil {
			key, _ := membership.DecodeKey(host)
			if network != n.NetworkID || membership.HostID(key) != caller {
				e = linkFailure(403, "forbidden")
			}
			var record linkImportOutcome
			if e == nil && (linking.DecodeStoredJSON(result, "authorization_base64 catalog_base64 map_base64", &record) != nil || record.Authorization != base64.StdEncoding.EncodeToString(in.Authorization) || record.Catalog != base64.StdEncoding.EncodeToString(in.Catalog)) {
				e = linkFailure(409, "state_conflict")
			}
			if e == nil {
				var reference []byte
				if tx.QueryRowContext(r.Context(), `SELECT statement FROM statements WHERE network_id=? AND kind=? AND subject=?`, n.NetworkID, kindLinkFeatureImport, operation).Scan(&reference) != nil || string(reference) != string(in.Authorization) {
					e = linkFailure(409, "state_conflict")
				}
			}
			var snapshot []byte
			if e == nil {
				snapshot, e = base64.StdEncoding.Strict().DecodeString(record.Map)
				if e == nil && (len(snapshot) > 16<<20 || base64.StdEncoding.EncodeToString(snapshot) != record.Map) {
					e = linkFailure(409, "state_conflict")
				}
			}
			respondLink(w, 200, json.RawMessage(snapshot), e, "")
			return
		}
		if !errors.Is(e, sql.ErrNoRows) {
			respondLink(w, 0, nil, e, "")
			return
		}
	}
	now, err := linking.RuntimeNow(s.Now)
	var name, root string
	if err == nil {
		err = tx.QueryRowContext(r.Context(), `SELECT name,root_public_key FROM networks WHERE id=?`, n.NetworkID).Scan(&name, &root)
	}
	created := errors.Is(err, sql.ErrNoRows)
	if created {
		err = nil
		key, e := membership.DecodeKey(n.GenesisRootPublicKey)
		if e != nil || membership.NetworkID(key) != n.NetworkID || !membership.ValidLabel(n.Name) {
			err = linkFailure(400, "invalid")
		}
		if err == nil {
			err = s.checkRegistration(r.Context(), tx, sourceOf(r.RemoteAddr), n.NetworkID)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO networks VALUES(?,?,?,?)`, n.NetworkID, n.Name, n.GenesisRootPublicKey, membership.Timestamp(now))
		}
	} else if err == nil && (name != n.Name || root != n.GenesisRootPublicKey) {
		err = linkFailure(409, "state_conflict")
	}
	feature := "-"
	var prior, c linkCatalog
	if err == nil {
		feature, err = activeLinkFeature(r.Context(), tx, n.NetworkID)
	}
	if err == nil {
		prior, err = linkCatalogOf(r.Context(), tx, n.NetworkID)
		c = prior
	}
	var priorCaller string
	if err == nil && feature != "-" {
		raw, _ := json.Marshal(prior)
		state, e := linking.VerifyStoredNetworkState(linkFactContext(n, prior, feature, now), raw)
		if e != nil {
			var path *linking.PathError
			if !errors.As(e, &path) || path.Code != "proof_required" {
				err = linkVerificationError(e)
			}
		} else {
			for public, admitted := range state.Facts.State.Hosts {
				key, e := membership.DecodeKey(public)
				if e == nil && membership.HostID(key) == caller {
					if admitted {
						priorCaller = public
					} else {
						err = linkFailure(403, "forbidden")
					}
					break
				}
			}
		}
	}
	if err == nil {
		c, err = mergeLinkCatalog(c, in.Catalog)
	}
	first := feature == "-"
	if err == nil && first {
		verified, e := linking.VerifyStoredFeatureImport(linkFactContext(n, c, "-", now), in.Catalog, in.Authorization)
		if e != nil {
			err = linkVerificationError(e)
		} else {
			feature = verified.FeatureID
		}
	}
	if err == nil && !first && string(in.Authorization) != `"-"` {
		_, e := linking.VerifyStoredFeatureImport(linkFactContext(n, c, feature, now), in.Catalog, in.Authorization)
		if e != nil {
			err = linkVerificationError(e)
		}
	}
	callerPublic := priorCaller
	if err == nil {
		catalog, _ := json.Marshal(c)
		old, _ := json.Marshal(prior)
		err = linking.VerifyStoredCatalogRepair(linkFactContext(n, c, feature, now), old, catalog)
		if err != nil {
			err = linkVerificationError(err)
		}
	}
	if err == nil && priorCaller == "" {
		err = currentLinkMember(r.Context(), tx, n, c, feature, caller, now)
		if err == nil {
			catalog, _ := json.Marshal(c)
			state, e := linking.VerifyStoredNetworkState(linkFactContext(n, c, feature, now), catalog)
			err = e
			for _, m := range state.Members {
				key, _ := membership.DecodeKey(m.HostPublicKey)
				if membership.HostID(key) == caller {
					callerPublic = m.HostPublicKey
					break
				}
			}
			if err == nil && callerPublic == "" {
				err = linkFailure(403, "forbidden")
			}
		}
	}
	if err == nil && first {
		var featureBody []byte
		for _, p := range c.Objects {
			if p.Kind == "feature" {
				featureBody, _ = base64Body(p)
				break
			}
		}
		var f linkFeatureView
		if json.Unmarshal(featureBody, &f) != nil {
			err = linkFailure(400, "invalid")
		} else {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO link_features(network_id,feature_id,proposal,feature,active) VALUES(?,?,?,?,1) ON CONFLICT(network_id,feature_id) DO UPDATE SET proposal=excluded.proposal,feature=excluded.feature,active=1`, n.NetworkID, feature, []byte(f.Proposal), featureBody)
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
	if err == nil && string(in.Authorization) != `"-"` {
		var count int
		err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM link_operations WHERE network_id=? AND request_id LIKE 'feature-import:%'`, n.NetworkID).Scan(&count)
		if err == nil && count >= 4096 {
			err = linkFailure(409, "quota_exceeded")
		}
		if err == nil {
			snapshot, e := json.Marshal(value)
			err = e
			if err == nil {
				result, e := json.Marshal(linkImportOutcome{base64.StdEncoding.EncodeToString(in.Authorization), base64.StdEncoding.EncodeToString(in.Catalog), base64.StdEncoding.EncodeToString(snapshot)})
				err = e
				if err != nil {
					respondLink(w, 0, nil, err, "")
					return
				}
				_, err = tx.ExecContext(r.Context(), `INSERT INTO link_operations VALUES(?,?,?,?,?)`, operation, n.NetworkID, feature, callerPublic, result)
				if err == nil {
					_, err = tx.ExecContext(r.Context(), `INSERT INTO statements VALUES(?,?,?,?)`, n.NetworkID, kindLinkFeatureImport, operation, in.Authorization)
				}
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err == nil {
		s.relay.changed(n.NetworkID)
	}
	status := 200
	if first || created {
		status = 201
	}
	respondLink(w, status, value, linkLegacyError(err), "")
}
