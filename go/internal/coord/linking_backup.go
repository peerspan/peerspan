package coord

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// Saved outcomes prove what was committed, not what is authorized now. Check
// their exact retained references without applying today's expiry/revocations.
func checkSavedLinkState(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"link_objects", "link_features", "link_operations"} {
		var orphan int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` l LEFT JOIN networks n ON n.id=l.network_id WHERE n.id IS NULL`).Scan(&orphan); err != nil || orphan != 0 {
			return fmt.Errorf("incomplete coordinator linking network references")
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,name,root_public_key FROM networks`)
	if err != nil {
		return err
	}
	networks := []linkNetwork{}
	for rows.Next() {
		var n linkNetwork
		if err = rows.Scan(&n.NetworkID, &n.Name, &n.GenesisRootPublicKey); err != nil {
			break
		}
		networks = append(networks, n)
	}
	if err = errors.Join(err, rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, n := range networks {
		if err = checkSavedLinkNetwork(ctx, tx, n); err != nil {
			return fmt.Errorf("incomplete coordinator linking state: %w", err)
		}
	}
	return nil
}

func savedBase64(s string, limit int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(limit) {
		return nil, fmt.Errorf("saved linking bytes exceed limit")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > limit || base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("invalid saved linking bytes")
	}
	return b, nil
}

func savedCatalog(c linkCatalog, network string, known map[string]linkProof) error {
	if c.NetworkID != network {
		return fmt.Errorf("saved catalog network mismatch")
	}
	if _, err := combineLinkCatalog(linkCatalog{Format: 1, NetworkID: network, Objects: []linkProof{}}, c); err != nil {
		return err
	}
	if known != nil {
		for _, p := range c.Objects {
			if known[p.ID] != p {
				return fmt.Errorf("saved outcome has missing public proof")
			}
		}
	}
	return nil
}

func savedMap(raw []byte, n linkNetwork, feature string, known map[string]linkProof) (linkMap, error) {
	var m linkMap
	if len(raw) > 16<<20 || linking.DecodeStoredJSON(raw, "format network catalog members", &m) != nil || m.Format != 2 || m.Members == nil || m.Network.NetworkID != n.NetworkID || m.Network.Name != n.Name || m.Network.GenesisRootPublicKey != n.GenesisRootPublicKey || !membership.ValidCoordinatorAddress(m.Network.CoordinatorAddress) {
		return m, fmt.Errorf("invalid saved linking map")
	}
	if _, err := membership.DecodeKey(m.Network.CoordinatorPublicKey); err != nil {
		return m, err
	}
	if err := savedCatalog(m.Catalog, n.NetworkID, known); err != nil {
		return m, err
	}
	found := false
	for _, p := range m.Catalog.Objects {
		if p.Kind == "feature" && feature != "-" {
			found = true
		}
	}
	if !found {
		return m, fmt.Errorf("saved map lacks feature")
	}
	if err := savedMapMembers(m, feature); err != nil {
		return m, err
	}
	return m, nil
}

func checkSavedLinkNetwork(ctx context.Context, tx *sql.Tx, n linkNetwork) error {
	proofs := map[string]linkProof{}
	rotations := map[int64]membership.Rotation{}
	rows, err := tx.QueryContext(ctx, `SELECT proof_id,kind,body FROM link_objects WHERE network_id=? ORDER BY proof_id`, n.NetworkID)
	if err != nil {
		return err
	}
	c := linkCatalog{Format: 1, NetworkID: n.NetworkID, Objects: []linkProof{}}
	for rows.Next() {
		var id, kind string
		var body []byte
		if err = rows.Scan(&id, &kind, &body); err != nil {
			break
		}
		p := linkProofOf(kind, body)
		if p.ID != id {
			err = fmt.Errorf("saved proof digest mismatch")
			break
		}
		proofs[id] = p
		c.Objects = append(c.Objects, p)
		if kind == "rotation" {
			var rotation membership.Rotation
			if json.Unmarshal(body, &rotation) != nil {
				err = fmt.Errorf("invalid saved rotation")
				break
			}
			if old, ok := rotations[rotation.Epoch]; ok && !bytes.Equal(old.Message(), rotation.Message()) {
				err = fmt.Errorf("conflicting saved rotations")
				break
			}
			rotations[rotation.Epoch] = rotation
		}
	}
	if err = errors.Join(err, rows.Err(), rows.Close()); err != nil {
		return err
	}
	if err = savedCatalog(c, n.NetworkID, nil); err != nil {
		return err
	}
	legacy, err := chainOf(ctx, tx, n.NetworkID)
	if err != nil {
		return err
	}
	for _, rotation := range legacy.Rotations {
		if old, ok := rotations[rotation.Epoch]; ok && !bytes.Equal(old.Message(), rotation.Message()) {
			return fmt.Errorf("conflicting saved rotations")
		}
		rotations[rotation.Epoch] = rotation
	}
	ordered := []membership.Rotation{}
	for _, rotation := range rotations {
		ordered = append(ordered, rotation)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Epoch < ordered[j].Epoch })
	genesis, err := membership.DecodeKey(n.GenesisRootPublicKey)
	if err != nil {
		return err
	}
	chain, err := membership.VerifyChain(genesis, ordered)
	if err != nil {
		return err
	}
	feature, err := checkSavedFeatures(ctx, tx, n, chain, proofs)
	if err != nil {
		return err
	}
	if feature == "-" && len(proofs) != 0 {
		return fmt.Errorf("public proofs lack active feature")
	}
	localHosts, redemptions := map[string]bool{}, map[string]bool{}
	importReferences := map[string][]byte{}
	rows, err = tx.QueryContext(ctx, `SELECT subject,statement FROM statements WHERE network_id=? AND kind=?`, n.NetworkID, kindLinkFeatureImport)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var authorization []byte
		if err = rows.Scan(&id, &authorization); err != nil {
			break
		}
		if id != "feature-import:"+linkHash(authorization) {
			err = fmt.Errorf("invalid saved import provenance")
			break
		}
		importReferences[id] = authorization
	}
	if err = errors.Join(err, rows.Err(), rows.Close()); err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT request_id,manifest_id,host_public_key,result FROM link_operations WHERE network_id=?`, n.NetworkID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var request, manifest, host string
		var result []byte
		if err = rows.Scan(&request, &manifest, &host, &result); err != nil {
			break
		}
		switch {
		case linkRequestID(request):
			err = checkSavedLinkOperation(result, request, manifest, host, n, feature, proofs)
			localHosts[host] = err == nil
		case strings.HasPrefix(request, "redemption:"):
			p, ok := proofs[manifest]
			if !ok || p.Kind != "invite_redemption" || request != "redemption:"+manifest {
				err = fmt.Errorf("saved redemption lacks proof")
				break
			}
			var red struct {
				Host   string          `json:"host_public_key"`
				Mode   string          `json:"mode"`
				Invite json.RawMessage `json:"host_invite"`
			}
			body, _ := base64Body(p)
			if json.Unmarshal(body, &red) != nil || red.Host != host {
				err = fmt.Errorf("saved redemption host mismatch")
				break
			}
			var snapshot linkMap
			snapshot, err = savedMap(result, n, feature, proofs)
			if err == nil {
				found := false
				for _, entry := range snapshot.Catalog.Objects {
					if entry == p {
						found = true
						break
					}
				}
				if !found {
					err = fmt.Errorf("saved redemption snapshot lacks its committed proof")
				}
			}
			if red.Mode != "person" && err == nil {
				var invite struct {
					Key     string `json:"invite_public_key"`
					Payload string `json:"payload_base64"`
				}
				if json.Unmarshal(red.Invite, &invite) != nil {
					err = fmt.Errorf("invalid saved redemption invite")
					break
				}
				if invite.Payload != "" {
					payload, e := savedBase64(invite.Payload, linking.MaxPayload)
					if e != nil || json.Unmarshal(payload, &invite) != nil {
						err = fmt.Errorf("invalid saved redemption invite")
						break
					}
				}
				redemptions[host+":"+invite.Key] = true
			}
		case strings.HasPrefix(request, "feature-import:"):
			if reference, ok := importReferences[request]; ok {
				err = checkSavedFeatureImport(result, request, manifest, reference, n, feature, proofs)
				delete(importReferences, request)
			} else {
				err = fmt.Errorf("saved import outcome lacks provenance")
			}
		default:
			err = fmt.Errorf("invalid saved linking outcome category")
		}
		if err != nil {
			break
		}
	}
	if err = errors.Join(err, rows.Err(), rows.Close()); err != nil {
		return err
	}
	if len(importReferences) != 0 {
		return fmt.Errorf("saved import provenance lacks outcome")
	}
	var registered map[string]linkMapMember
	if feature != "-" {
		registered, err = savedRegistrationMembers(c, feature)
		if err != nil {
			return err
		}
	}
	registrationMap := linkMap{Network: n, Catalog: c, Members: []linkMapMember{}}
	rows, err = tx.QueryContext(ctx, `SELECT host_id,invite_public_key,COALESCE(membership,''),COALESCE(admission,'') FROM members WHERE network_id=? ORDER BY host_id`, n.NetworkID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var host, marker, membershipBody, admissionBody string
		if err = rows.Scan(&host, &marker, &membershipBody, &admissionBody); err != nil {
			break
		}
		if feature != "-" {
			member, ok := registered[host]
			if !ok {
				err = fmt.Errorf("saved registration lacks membership proof")
				break
			}
			for _, original := range []struct{ kind, body string }{{"host_membership", membershipBody}, {"host_admission", admissionBody}} {
				if original.body == "" || member.JoinProofID == "-" {
					continue
				}
				proof := linkProofOf(original.kind, []byte(original.body))
				if proofs[proof.ID] != proof {
					err = fmt.Errorf("saved registration lacks original membership bytes")
					break
				}
				member.MembershipProofID = proof.ID
			}
			if err != nil {
				break
			}
			registrationMap.Members = append(registrationMap.Members, member)
		}
		if key, ok := strings.CutPrefix(marker, "link:"); ok {
			pub, e := membership.DecodeKey(key)
			if e != nil || membership.HostID(pub) != host || !localHosts[key] {
				err = fmt.Errorf("local link registration lacks outcome")
				break
			}
		}
		if invite, ok := strings.CutPrefix(marker, "redemption:"); ok {
			found := false
			for key := range redemptions {
				pub, _, _ := strings.Cut(key, ":")
				decoded, e := membership.DecodeKey(pub)
				if e == nil && membership.HostID(decoded) == host && redemptions[pub+":"+invite] {
					found = true
					break
				}
			}
			if !found {
				err = fmt.Errorf("local redemption registration lacks outcome")
				break
			}
		}
	}
	if err = errors.Join(err, rows.Err(), rows.Close()); err != nil {
		return err
	}
	if feature != "-" {
		return savedMapMembers(registrationMap, feature)
	}
	return nil
}

func checkSavedFeatures(ctx context.Context, tx *sql.Tx, n linkNetwork, chain membership.Chain, known map[string]linkProof) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT feature_id,proposal,feature,active FROM link_features WHERE network_id=?`, n.NetworkID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	activeID := "-"
	for rows.Next() {
		var id string
		var proposal, body []byte
		var active int
		if err = rows.Scan(&id, &proposal, &body, &active); err != nil {
			return "", err
		}
		var p struct {
			Epoch   uint64 `json:"epoch"`
			Network string `json:"network_id"`
		}
		if json.Unmarshal(proposal, &p) != nil || p.Epoch >= uint64(len(chain.Roots)) || p.Network != n.NetworkID {
			return "", fmt.Errorf("invalid saved feature proposal")
		}
		root := membership.EncodeKey(chain.Roots[p.Epoch])
		r, e := linking.Read("feature_proposal", proposal, root, "-")
		if e != nil || r.ID != id {
			return "", fmt.Errorf("invalid saved feature identity")
		}
		if active == 1 {
			var f linkFeatureView
			r, e = linking.Read("feature", body, root, "-")
			if e != nil || r.ID != id || activeID != "-" || json.Unmarshal(body, &f) != nil || !bytes.Equal(f.Proposal, proposal) {
				return "", fmt.Errorf("invalid saved active feature")
			}
			proof := linkProofOf("feature", body)
			if known[proof.ID] != proof {
				return "", fmt.Errorf("active feature lacks retained proof")
			}
			activeID = id
		} else if active == 0 {
			var pending pendingLinkFeature
			if linking.DecodeStoredJSON(body, "catalog acknowledgments_base64", &pending) != nil || pending.Acknowledgments == nil || savedCatalog(pending.Catalog, n.NetworkID, nil) != nil {
				return "", fmt.Errorf("invalid saved pending feature")
			}
			for _, s := range pending.Acknowledgments {
				raw, e := savedBase64(s, linking.MaxObject)
				var ack struct {
					Host    string `json:"host_public_key"`
					Feature string `json:"feature_id"`
				}
				if e != nil || json.Unmarshal(raw, &ack) != nil || ack.Feature != id {
					return "", fmt.Errorf("invalid saved feature acknowledgment")
				}
				if _, e = linking.Read("feature_ack", raw, ack.Host, "-"); e != nil {
					return "", e
				}
			}
		} else {
			return "", fmt.Errorf("invalid saved feature status")
		}
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	for _, proof := range known {
		if proof.Kind != "feature" {
			continue
		}
		body, _ := base64Body(proof)
		var f linkFeatureView
		var p struct {
			Epoch uint64 `json:"epoch"`
		}
		if json.Unmarshal(body, &f) != nil || json.Unmarshal(f.Proposal, &p) != nil || p.Epoch >= uint64(len(chain.Roots)) {
			return "", fmt.Errorf("invalid saved feature proof")
		}
		r, e := linking.Read("feature", body, membership.EncodeKey(chain.Roots[p.Epoch]), "-")
		if e != nil || r.ID != activeID {
			return "", fmt.Errorf("saved feature proof conflicts with active pin")
		}
	}
	return activeID, nil
}

func checkSavedLinkOperation(raw []byte, request, manifest, host string, n linkNetwork, feature string, known map[string]linkProof) error {
	var packet struct {
		Request string `json:"request_id"`
		Role    string `json:"role"`
		Writer  string `json:"writer_public_key"`
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &packet) != nil || packet.Request != request || packet.Role != "result" {
		return fmt.Errorf("invalid saved result packet")
	}
	r, err := linking.Read("packet", raw, packet.Writer, "-")
	if err != nil {
		return err
	}
	var payload struct {
		Manifest   string          `json:"manifest_id"`
		Activation json.RawMessage `json:"activation"`
		Catalog    linkCatalog     `json:"catalog"`
	}
	if linking.DecodeMutation(r.Payload, "manifest_id activation catalog", &payload) != nil || payload.Manifest != manifest {
		return fmt.Errorf("saved result manifest mismatch")
	}
	a, m, h, err := linkOperationIdentity(payload.Activation)
	if err != nil || a != request || m != manifest || h != host {
		return fmt.Errorf("saved result activation mismatch")
	}
	proof := linkProofOf("activation", payload.Activation)
	if known[proof.ID] != proof {
		return fmt.Errorf("saved result lacks activation")
	}
	if err = savedCatalog(payload.Catalog, n.NetworkID, known); err != nil {
		return err
	}
	var activation struct {
		Owner struct {
			Payload string `json:"payload_base64"`
		} `json:"owner"`
	}
	var owner struct {
		Network linkNetwork `json:"network"`
		Feature string      `json:"feature_id"`
	}
	if json.Unmarshal(payload.Activation, &activation) != nil {
		return fmt.Errorf("invalid saved owner")
	}
	body, err := savedBase64(activation.Owner.Payload, linking.MaxPayload)
	if err != nil || json.Unmarshal(body, &owner) != nil || owner.Network.NetworkID != n.NetworkID || owner.Network.Name != n.Name || owner.Network.GenesisRootPublicKey != n.GenesisRootPublicKey || owner.Network.CoordinatorPublicKey != packet.Writer || owner.Feature != feature {
		return fmt.Errorf("saved result pin mismatch")
	}
	return nil
}

func checkSavedFeatureImport(raw []byte, request, manifest string, reference []byte, n linkNetwork, feature string, known map[string]linkProof) error {
	var record linkImportOutcome
	if linking.DecodeStoredJSON(raw, "authorization_base64 catalog_base64 map_base64", &record) != nil {
		return fmt.Errorf("invalid saved feature import")
	}
	authorization, err := savedBase64(record.Authorization, linking.MaxObject)
	if err != nil || !bytes.Equal(reference, authorization) || request != "feature-import:"+linkHash(authorization) || manifest != feature {
		return fmt.Errorf("saved feature import identity mismatch")
	}
	catalog, err := savedBase64(record.Catalog, 1<<20)
	if err != nil {
		return err
	}
	snapshot, err := savedBase64(record.Map, 16<<20)
	if err != nil {
		return err
	}
	m, err := savedMap(snapshot, n, feature, known)
	if err != nil {
		return err
	}
	var c linkCatalog
	if linking.DecodeStoredJSON(catalog, "format network_id objects", &c) != nil || savedCatalog(c, n.NetworkID, known) != nil {
		return fmt.Errorf("invalid saved feature import catalog")
	}
	snapshotProofs := map[string]linkProof{}
	for _, proof := range m.Catalog.Objects {
		snapshotProofs[proof.ID] = proof
	}
	if err = savedCatalog(c, n.NetworkID, snapshotProofs); err != nil {
		return fmt.Errorf("saved feature import snapshot lacks authorized proofs")
	}
	var auth struct {
		Issued string `json:"issued_at"`
	}
	if json.Unmarshal(authorization, &auth) != nil {
		return fmt.Errorf("invalid saved feature authorization")
	}
	issued, err := time.Parse("2006-01-02T15:04:05Z", auth.Issued)
	if err != nil {
		return err
	}
	_, err = linking.VerifyStoredFeatureImport(linkFactContext(m.Network, c, feature, issued), catalog, authorization)
	return err
}
