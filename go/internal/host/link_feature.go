package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type LinkFeatureView struct {
	State           string               `json:"state"`
	FeatureID       string               `json:"feature_id"`
	Proposal        json.RawMessage      `json:"proposal"`
	Acknowledgments []json.RawMessage    `json:"acknowledgments"`
	PendingHosts    []string             `json:"pending_hosts"`
	SigningRequests []LinkSigningRequest `json:"signing_requests"`
}
type linkFeatureProposal struct {
	Format         uint64   `json:"format"`
	NetworkID      string   `json:"network_id"`
	Epoch          uint64   `json:"epoch"`
	Version        uint64   `json:"version"`
	IssuedAt       string   `json:"issued_at"`
	HostPublicKeys []string `json:"host_public_keys"`
	Signature      string   `json:"signature"`
}

func (s *Store) resumeLinkFeatureLocked(ctx context.Context, n Network) error {
	id, record, e := readLinkFeature(ctx, s.db, n.ID)
	if e != nil || id != "-" {
		return e
	}
	now, e := linkNow()
	if e != nil {
		return e
	}
	catalog, e := s.legacyLinkCatalog(ctx, n)
	if e != nil {
		return e
	}
	if record != nil && record.Activate {
		p, e := decodeLinkFeatureProposal(record.Proposal)
		if e != nil {
			return e
		}
		if p.Signature != "-" {
			return s.publishLinkFeatureLocked(ctx, n, catalog, "lf_"+linkHash(p.message()), record, now)
		}
	}
	return s.ackLinkProposalsLocked(ctx, n, catalog, now)
}

func (p linkFeatureProposal) message() []byte {
	return linkMessage(append([]string{"peerspan-link-feature-v1", p.NetworkID, strconv.FormatUint(p.Epoch, 10), "1", p.IssuedAt, strconv.Itoa(len(p.HostPublicKeys))}, p.HostPublicKeys...)...)
}
func decodeLinkFeatureProposal(raw []byte) (linkFeatureProposal, error) {
	var p linkFeatureProposal
	if linking.DecodeMutation(raw, "format network_id epoch version issued_at host_public_keys signature", &p) != nil || p.Format != 1 || p.Version != 1 || p.HostPublicKeys == nil {
		return p, linkFail("invalid", "-", "feature")
	}
	return p, nil
}
func (s *Store) legacyLinkCatalog(ctx context.Context, n Network) ([]byte, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT kind,record FROM network_statements WHERE network_id=? ORDER BY kind,subject`, n.ID)
	if e != nil {
		return nil, e
	}
	objects := map[string]linkCatalogObject{}
	add := func(kind string, body []byte) {
		id := linkProofID(kind, body)
		objects[id] = linkCatalogObject{id, kind, base64.StdEncoding.EncodeToString(body)}
	}
	for rows.Next() {
		var kind, raw string
		if e = rows.Scan(&kind, &raw); e != nil {
			_ = rows.Close()
			return nil, e
		}
		body := []byte(raw)
		switch kind {
		case kindPersonStatement:
			var proof struct {
				Membership json.RawMessage `json:"membership"`
				Admission  json.RawMessage `json:"admission"`
			}
			if json.Unmarshal(body, &proof) != nil {
				_ = rows.Close()
				return nil, linkFail("state_conflict", "-", "storage")
			}
			if len(proof.Membership) > 0 && string(proof.Membership) != "null" {
				add("person_membership", proof.Membership)
			}
			if len(proof.Admission) > 0 && string(proof.Admission) != "null" {
				add("person_admission", proof.Admission)
			}
		case kindRotation, kindAttestation, kindHostAdmission, kindGroup, kindPolicy, kindAdminRemoval, kindPersonRemoval:
			add(kind, body)
		case kindAdmin:
			add("admin_delegation", body)
		case kindBinding:
			add("host_binding", body)
		case kindMembership:
			add("host_membership", body)
		case membership.KindHost:
			add("host_revocation", body)
		case membership.KindInvite:
			add("invite_revocation", body)
		case membership.KindLeave:
			add("host_leave", body)
		case membership.KindUnbind:
			add("host_unbinding", body)
		case kindMove:
			add("coordinator_move", body)
		}
	}
	e = rows.Err()
	_ = rows.Close()
	if e != nil {
		return nil, e
	}
	members, e := s.NetworkMembers(ctx, n.ID)
	if e != nil {
		return nil, e
	}
	for _, m := range members {
		if m.Membership != nil {
			b, e := linkJSON(m.Membership)
			if e != nil {
				return nil, e
			}
			add("host_membership", b)
		}
		if m.Admission != nil {
			b, e := linkJSON(m.Admission)
			if e != nil {
				return nil, e
			}
			add("host_admission", b)
		}
	}
	ids := make([]string, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	c := linkCatalog{1, n.ID, []linkCatalogObject{}}
	for _, id := range ids {
		c.Objects = append(c.Objects, objects[id])
	}
	raw, e := linkJSON(c)
	if e != nil {
		return nil, e
	}
	_, e = decodeLinkCatalog(raw, n.ID)
	return raw, e
}
func (s *Store) putLinkFeature(ctx context.Context, n Network, id string, record linkFeatureRecord) error {
	raw, e := linkJSON(record)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO link_features(network_id,feature_id,record) VALUES(?,?,?) ON CONFLICT(network_id) DO UPDATE SET feature_id=excluded.feature_id,record=excluded.record`, n.ID, id, string(raw))
	return e
}
func featureLinkView(id string, record linkFeatureRecord) (LinkFeatureView, error) {
	p, e := decodeLinkFeatureProposal(record.Proposal)
	if e != nil {
		return LinkFeatureView{}, e
	}
	acked := map[string]bool{}
	for _, raw := range record.Acknowledgments {
		var a struct {
			HostPublicKey string `json:"host_public_key"`
		}
		if json.Unmarshal(raw, &a) != nil {
			return LinkFeatureView{}, linkFail("state_conflict", "-", "feature")
		}
		acked[a.HostPublicKey] = true
	}
	view := LinkFeatureView{record.State, id, record.Proposal, record.Acknowledgments, []string{}, []LinkSigningRequest{}}
	for _, host := range p.HostPublicKeys {
		if !acked[host] {
			view.PendingHosts = append(view.PendingHosts, host)
		}
	}
	return view, nil
}
func (s *Store) LinkFeature(ctx context.Context, id string, activate bool, signature string) (LinkFeatureView, error) {
	if _, e := s.SyncNetwork(ctx, id); e != nil {
		return LinkFeatureView{}, e
	}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, id)
	if e != nil {
		return LinkFeatureView{}, e
	}
	if n.LastSyncError != nil {
		return LinkFeatureView{}, linkFail("unavailable", "-", "sync")
	}
	now, e := linkNow()
	if e != nil {
		return LinkFeatureView{}, e
	}
	feature, record, e := readLinkFeature(ctx, s.db, id)
	if e != nil {
		return LinkFeatureView{}, e
	}
	if feature != "-" {
		return featureLinkView(feature, *record)
	}
	if record != nil {
		p, err := decodeLinkFeatureProposal(record.Proposal)
		if err != nil {
			return LinkFeatureView{}, err
		}
		issued, err := linkStamp(p.IssuedAt)
		if err != nil {
			return LinkFeatureView{}, err
		}
		if !now.Before(issued.Add(24 * time.Hour)) {
			record = nil
		}
	}
	catalog, e := s.legacyLinkCatalog(ctx, n)
	if e != nil {
		return LinkFeatureView{}, e
	}
	if record == nil {
		if signature != "" {
			return LinkFeatureView{}, linkFail("state_conflict", "-", "feature")
		}
		members, e := s.NetworkMembers(ctx, id)
		if e != nil {
			return LinkFeatureView{}, e
		}
		hosts := []string{}
		for _, m := range members {
			hosts = append(hosts, m.PublicKey)
		}
		sort.Strings(hosts)
		proposal := linkFeatureProposal{1, id, uint64(n.RootEpoch), 1, linkTime(now), hosts, "-"}
		raw, e := linkJSON(proposal)
		if e != nil {
			return LinkFeatureView{}, e
		}
		record = &linkFeatureRecord{"preparing", raw, []json.RawMessage{}, false}
	}
	p, e := decodeLinkFeatureProposal(record.Proposal)
	if e != nil {
		return LinkFeatureView{}, e
	}
	fid := "lf_" + linkHash(p.message())
	if activate {
		record.Activate = true
	}
	if signature != "" {
		if !record.Activate {
			return LinkFeatureView{}, linkFail("forbidden", "-", "feature")
		}
		if p.Signature != "-" && p.Signature != signature {
			return LinkFeatureView{}, linkFail("operation_conflict", "-", "feature")
		}
		p.Signature = signature
	} else if record.Activate && p.Signature == "-" {
		_, key, err := s.administeredNetwork(ctx, s.db, id)
		if err == nil {
			if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != n.CurrentRootPublicKey {
				return LinkFeatureView{}, linkFail("forbidden", "-", "root")
			}
			p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, p.message()))
		}
	}
	if p.Signature != "-" {
		record.Proposal, e = linkJSON(p)
		if e != nil {
			return LinkFeatureView{}, e
		}
		descriptor, _ := linkJSON(linkNetworkDescriptor(n))
		if _, e = linking.VerifyStoredFeaturePreparation(linking.FeatureContext{Network: descriptor, Epoch: uint64(n.RootEpoch), KnownFeatureID: "-", Now: now}, catalog, record.Proposal); e != nil {
			return LinkFeatureView{}, e
		}
		record.State = "collecting"
	}
	if e = s.putLinkFeature(ctx, n, fid, *record); e != nil {
		return LinkFeatureView{}, e
	}
	if record.Activate && p.Signature != "-" {
		if e = s.publishLinkFeatureLocked(ctx, n, catalog, fid, record, now); e != nil {
			return LinkFeatureView{}, e
		}
	}
	view, e := featureLinkView(fid, *record)
	if e != nil {
		return view, e
	}
	if record.Activate && p.Signature == "-" {
		view.SigningRequests = []LinkSigningRequest{{"feature_proposal", base64.StdEncoding.EncodeToString(p.message()), n.CurrentRootPublicKey, "sshsig"}}
	}
	return view, nil
}
func (s *Store) publishLinkFeatureLocked(ctx context.Context, n Network, catalog []byte, id string, record *linkFeatureRecord, now time.Time) error {
	body, e := linkJSON(map[string]any{"proposal": record.Proposal, "catalog": json.RawMessage(catalog)})
	if e != nil {
		return e
	}
	if _, e = s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+n.ID+"/link-feature/proposals", body); e != nil {
		return e
	}
	if e = s.ackLinkProposalsLocked(ctx, n, catalog, now); e != nil {
		return e
	}
	raw, e := s.linkCoordinator(ctx, n, http.MethodGet, "/coord/v2/networks/"+n.ID+"/link-feature/proposals", nil)
	if e != nil {
		return e
	}
	var response struct {
		Proposals []struct {
			Proposal        json.RawMessage   `json:"proposal"`
			Acknowledgments []json.RawMessage `json:"acknowledgments"`
		} `json:"proposals"`
	}
	if linking.DecodeMutation(raw, "proposals", &response) != nil || response.Proposals == nil {
		return linkFail("invalid", "-", "feature")
	}
	for _, candidate := range response.Proposals {
		p, e := decodeLinkFeatureProposal(candidate.Proposal)
		if e != nil {
			return e
		}
		if "lf_"+linkHash(p.message()) != id {
			continue
		}
		if string(candidate.Proposal) != string(record.Proposal) {
			return linkFail("operation_conflict", "-", "feature")
		}
		record.Acknowledgments = candidate.Acknowledgments
		break
	}
	if e = s.putLinkFeature(ctx, n, id, *record); e != nil {
		return e
	}
	view, e := featureLinkView(id, *record)
	if e != nil {
		return e
	}
	if len(view.PendingHosts) > 0 {
		return nil
	}
	feature, e := linkJSON(map[string]any{"proposal": record.Proposal, "acknowledgments": record.Acknowledgments})
	if e != nil {
		return e
	}
	descriptor, _ := linkJSON(linkNetworkDescriptor(n))
	verifiedFeature, e := linking.VerifyStoredFeature(linking.FeatureContext{Network: descriptor, Epoch: uint64(n.RootEpoch), KnownFeatureID: "-", Now: now}, catalog, feature)
	if e != nil {
		return e
	}
	body, e = linkJSON(map[string]any{"feature": json.RawMessage(feature), "catalog": json.RawMessage(catalog)})
	if e != nil {
		return e
	}
	if _, e = s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+n.ID+"/link-feature", body); e != nil {
		return e
	}
	if _, e = s.fetchLinkMap(ctx, n, &linkFeatureAdoption{verifiedFeature.FeatureID}); e != nil {
		return e
	}
	record.State = "active"
	return nil
}
func (s *Store) ackLinkProposalsLocked(ctx context.Context, n Network, catalog []byte, now time.Time) error {
	raw, e := s.linkCoordinator(ctx, n, http.MethodGet, "/coord/v2/networks/"+n.ID+"/link-feature/proposals", nil)
	if e != nil {
		return e
	}
	var response struct {
		Proposals []struct {
			Proposal        json.RawMessage   `json:"proposal"`
			Acknowledgments []json.RawMessage `json:"acknowledgments"`
		} `json:"proposals"`
	}
	if linking.DecodeMutation(raw, "proposals", &response) != nil || response.Proposals == nil {
		return linkFail("invalid", "-", "feature")
	}
	descriptor, _ := linkJSON(linkNetworkDescriptor(n))
	for _, candidate := range response.Proposals {
		p, e := decodeLinkFeatureProposal(candidate.Proposal)
		if e != nil {
			return e
		}
		verified, e := linking.VerifyStoredFeaturePreparation(linking.FeatureContext{Network: descriptor, Epoch: uint64(n.RootEpoch), KnownFeatureID: "-", Now: now}, catalog, candidate.Proposal)
		if e != nil {
			continue
		}
		listed, already := false, false
		for _, host := range p.HostPublicKeys {
			if host == s.identity.PublicKey {
				listed = true
			}
		}
		for _, ack := range candidate.Acknowledgments {
			if _, e := linking.Read("feature_ack", ack, s.identity.PublicKey, "-"); e == nil {
				already = true
			}
		}
		if !listed || already {
			continue
		}
		message := linkMessage("peerspan-link-feature-ack-v1", verified.FeatureID, s.identity.PublicKey)
		ack, e := linkJSON(map[string]any{"format": 1, "feature_id": verified.FeatureID, "host_public_key": s.identity.PublicKey, "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, message))})
		if e != nil {
			return e
		}
		body, e := linkJSON(map[string]any{"acknowledgment": json.RawMessage(ack), "catalog": json.RawMessage(catalog)})
		if e != nil {
			return e
		}
		if _, e = s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+n.ID+"/link-feature/acknowledgments", body); e != nil {
			return e
		}
	}
	return nil
}
