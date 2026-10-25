package host

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

const kindLinkRedemptionIntent = "link_invite_redemption_intent"

type linkRedemptionRequest struct {
	Redemption json.RawMessage `json:"redemption"`
	Catalog    json.RawMessage `json:"catalog"`
	Address    string          `json:"address"`
	Candidates []string        `json:"candidates"`
	JoinAck    json.RawMessage `json:"join_ack"`
}
type linkRedemptionIntent struct {
	Format               uint64 `json:"format"`
	NetworkBase64        string `json:"network_base64"`
	FeatureID            string `json:"feature_id"`
	FeatureBindingBase64 string `json:"feature_binding_base64"`
	RedemptionBase64     string `json:"redemption_base64"`
	RequestBase64        string `json:"request_base64"`
	Submitted            bool   `json:"submitted"`
	ResultMapBase64      string `json:"result_map_base64"`
}
type linkRedemptionView struct {
	Mode            string `json:"mode"`
	PersonAction    string `json:"person_action"`
	HostPublicKey   string `json:"host_public_key"`
	PersonPublicKey string `json:"person_public_key"`
	JoinedAt        string `json:"joined_at"`
}
type inviteFeatureSeed struct {
	Binding            json.RawMessage `json:"binding"`
	HostInviteBase64   string          `json:"host_invite_base64"`
	PersonInviteBase64 string          `json:"person_invite_base64"`
}

func (i linkRedemptionIntent) materialize() (Network, linkRedemptionRequest, linkRedemptionView, inviteFeatureSeed, error) {
	bad := func() (Network, linkRedemptionRequest, linkRedemptionView, inviteFeatureSeed, error) {
		return Network{}, linkRedemptionRequest{}, linkRedemptionView{}, inviteFeatureSeed{}, linkFail("state_conflict", "-", "redemption")
	}
	if i.Format != 1 || !linkID(i.FeatureID, "lf_") || i.ResultMapBase64 != "-" && !i.Submitted {
		return bad()
	}
	descriptor, e := linkBytes(i.NetworkBase64, linking.MaxObject)
	if e != nil {
		return bad()
	}
	n, e := inviteNetwork(descriptor)
	if e != nil {
		return bad()
	}
	requestBytes, e := linkBytes(i.RequestBase64, 1<<20)
	if e != nil {
		return bad()
	}
	var request linkRedemptionRequest
	if linking.DecodeMutation(requestBytes, "redemption catalog address candidates join_ack", &request) != nil {
		return bad()
	}
	redemption, e := linkBytes(i.RedemptionBase64, linking.MaxObject)
	if e != nil || string(redemption) != string(request.Redemption) {
		return bad()
	}
	var view linkRedemptionView
	if json.Unmarshal(redemption, &view) != nil {
		return bad()
	}
	joined, e := linkStamp(view.JoinedAt)
	if e != nil {
		return bad()
	}
	seedBytes, e := linkBytes(i.FeatureBindingBase64, linking.MaxObject)
	if e != nil {
		return bad()
	}
	var seed inviteFeatureSeed
	if linking.DecodeMutation(seedBytes, "binding host_invite_base64 person_invite_base64", &seed) != nil {
		return bad()
	}
	halves := [][]byte{nil, nil}
	for j, encoded := range []string{seed.HostInviteBase64, seed.PersonInviteBase64} {
		if encoded != "-" {
			halves[j], e = linkBytes(encoded, linking.MaxObject)
			if e != nil {
				return bad()
			}
		}
	}
	objects, e := decodeLinkCatalog(request.Catalog, n.ID)
	if e != nil {
		return bad()
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return bad()
	}
	ctx := linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: i.FeatureID, Now: joined}
	if _, e = linking.VerifyStoredInviteFeature(ctx, request.Catalog, seed.Binding, halves[0], halves[1]); e != nil {
		return bad()
	}
	if _, e = linking.VerifyStoredFreshRedemption(ctx, request.Catalog, redemption); e != nil {
		return bad()
	}
	if view.Mode != "person" {
		var ack struct {
			Feature string `json:"feature_id"`
			Host    string `json:"host_public_key"`
		}
		if json.Unmarshal(request.JoinAck, &ack) != nil || ack.Feature != i.FeatureID || ack.Host != view.HostPublicKey {
			return bad()
		}
		if _, e = linking.Read("feature_ack", request.JoinAck, view.HostPublicKey, "-"); e != nil {
			return bad()
		}
	} else if string(request.JoinAck) != `"-"` || request.Address != "" || len(request.Candidates) != 0 {
		return bad()
	}
	if i.ResultMapBase64 != "-" {
		receipt, err := linkBytes(i.ResultMapBase64, 16<<20)
		if err != nil {
			return bad()
		}
		if _, err = decodeLinkMap(receipt, n); err != nil {
			return bad()
		}
	}
	return n, request, view, seed, nil
}
func readLinkRedemptionRecord(raw string) (linkRedemptionIntent, error) {
	var intent linkRedemptionIntent
	if linking.DecodeStoredJSON([]byte(raw), "format network_base64 feature_id feature_binding_base64 redemption_base64 request_base64 submitted result_map_base64", &intent) != nil {
		return intent, linkFail("state_conflict", "-", "redemption")
	}
	_, _, _, _, e := intent.materialize()
	return intent, e
}
func publicInviteKey(raw []byte) string {
	var object struct {
		InvitePublicKey string `json:"invite_public_key"`
		PayloadBase64   string `json:"payload_base64"`
	}
	if json.Unmarshal(raw, &object) != nil {
		return ""
	}
	if object.PayloadBase64 != "" {
		body, e := linkBytes(object.PayloadBase64, linking.MaxPayload)
		if e != nil {
			return ""
		}
		if json.Unmarshal(body, &object) != nil {
			return ""
		}
	}
	return object.InvitePublicKey
}
func (s *Store) saveLinkRedemption(ctx context.Context, network, id string, intent linkRedemptionIntent) error {
	if _, _, _, _, e := intent.materialize(); e != nil {
		return e
	}
	raw, e := linkJSON(intent)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?,?,?,?) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record`, network, kindLinkRedemptionIntent, id, string(raw))
	return e
}
func (s *Store) findLinkRedemption(ctx context.Context, network, inviteKey, hostKey string, now time.Time) (string, *linkRedemptionIntent, int, int, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT network_id,subject,record FROM network_statements WHERE kind=? ORDER BY network_id,subject`, kindLinkRedemptionIntent)
	if e != nil {
		return "", nil, 0, 0, e
	}
	type row struct{ network, id, raw string }
	retained := []row{}
	for rows.Next() {
		var r row
		if e = rows.Scan(&r.network, &r.id, &r.raw); e != nil {
			_ = rows.Close()
			return "", nil, 0, 0, e
		}
		retained = append(retained, r)
	}
	e = rows.Err()
	_ = rows.Close()
	if e != nil {
		return "", nil, 0, 0, e
	}
	var found *linkRedemptionIntent
	foundID := ""
	networkCount, hostCount := 0, 0
	for _, r := range retained {
		intent, e := readLinkRedemptionRecord(r.raw)
		if e != nil {
			return "", nil, 0, 0, e
		}
		_, _, view, seed, e := intent.materialize()
		if e != nil {
			return "", nil, 0, 0, e
		}
		var binding struct {
			ExpiresAt string `json:"expires_at"`
		}
		_ = json.Unmarshal(seed.Binding, &binding)
		until, e := linkStamp(binding.ExpiresAt)
		if e != nil {
			return "", nil, 0, 0, e
		}
		if now.After(until.Add(24*time.Hour)) && (intent.ResultMapBase64 != "-" || !intent.Submitted) {
			if _, e = s.db.ExecContext(ctx, `DELETE FROM network_statements WHERE network_id=? AND kind=? AND subject=?`, r.network, kindLinkRedemptionIntent, r.id); e != nil {
				return "", nil, 0, 0, e
			}
			continue
		}
		hostCount++
		if r.network == network {
			networkCount++
		}
		keyBytes := seed.HostInviteBase64
		if keyBytes == "-" {
			keyBytes = seed.PersonInviteBase64
		}
		body, e := linkBytes(keyBytes, linking.MaxObject)
		if e != nil {
			return "", nil, 0, 0, e
		}
		if r.network == network && view.HostPublicKey == hostKey && publicInviteKey(body) == inviteKey {
			if found != nil {
				return "", nil, 0, 0, linkFail("state_conflict", "-", "redemption")
			}
			copy := intent
			found = &copy
			foundID = r.id
		}
	}
	return foundID, found, networkCount, hostCount, nil
}

func (s *Store) redeemFeatureInvite(ctx context.Context, r JoinNetwork, personOnly bool) (Network, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	now, e := linkNow()
	if e != nil {
		return Network{}, e
	}
	outerRaw, e := decodeLinkToken(r.Token, FeatureInvitePrefix)
	if e != nil {
		return Network{}, e
	}
	var outer featureInviteToken
	if linking.DecodeStoredJSON(outerRaw, "format network token mode host_invite_base64 person_invite_base64 feature_binding catalog", &outer) != nil {
		return Network{}, linkFail("invalid", "-", "invite")
	}
	// Historical decoding is only a locator for a pre-existing immutable intent.
	// A first use below still requires the signed binding at the current clock.
	locator, e := decodeInnerLinkInvite(outer.Token, time.Time{})
	if e != nil {
		return Network{}, e
	}
	n, e := inviteNetwork(outer.Network)
	if e != nil {
		return n, e
	}
	person := "-"
	if r.PersonPublicKey != "" {
		person, e = membership.NormalizePersonKey(r.PersonPublicKey)
		if e != nil {
			return n, linkFail("invalid", "-", "person")
		}
	}
	mode := locator.Mode
	hostKey := s.identity.PublicKey
	if personOnly {
		if mode == "host" {
			return n, linkFail("invalid", "-", "invite")
		}
		mode, hostKey = "person", "-"
		if person == "-" {
			return n, linkFail("invalid", "-", "person")
		}
	} else if mode == "person" {
		return n, linkFail("invalid", "-", "invite")
	} else if mode == "member" && person == "-" {
		mode = "host"
	}
	id := "lri_" + linkHash(linkMessage("peerspan-invite-redemption-intent-v1", n.ID, mode, hostKey, person, locator.InvitePublicKey))
	oldID, old, networkCount, hostCount, e := s.findLinkRedemption(ctx, n.ID, locator.InvitePublicKey, hostKey, now)
	if e != nil {
		return n, e
	}
	if old != nil {
		if oldID != id {
			return n, linkFail("operation_conflict", "-", "redemption")
		}
		_, _, previous, seed, e := old.materialize()
		if e != nil {
			return n, e
		}
		joined, e := linkStamp(previous.JoinedAt)
		if e != nil {
			return n, e
		}
		if _, e = decodeFeatureInvite(r.Token, joined); e != nil {
			return n, e
		}
		if string(seed.Binding) != string(outer.FeatureBinding) || seed.HostInviteBase64 != outer.HostInviteBase64 || seed.PersonInviteBase64 != outer.PersonInviteBase64 {
			return n, linkFail("operation_conflict", "-", "redemption")
		}
		return s.advanceLinkRedemption(ctx, n, id, *old)
	}
	if networkCount >= 8 || hostCount >= 32 {
		return n, linkFail("quota_exceeded", "-", "redemption")
	}
	invite, e := decodeFeatureInvite(r.Token, now)
	if e != nil {
		return n, e
	}
	n = invite.Network
	if existing, err := s.Network(ctx, n.ID); err == nil {
		if !personOnly {
			return existing, linkFail("state_conflict", "-", "member")
		}
		if existing.CoordinatorAddress != n.CoordinatorAddress || existing.CoordinatorPublicKey != n.CoordinatorPublicKey {
			return existing, linkFail("invalid", "-", "coordinator")
		}
		n = existing
	} else if !errors.Is(err, ErrNotFound) {
		return n, err
	} else if personOnly {
		return n, linkFail("not_found", "-", "member")
	}
	publicCatalog := invite.Catalog
	if personOnly {
		prior, err := readLinkCatalog(ctx, s.db, n.ID)
		if err != nil {
			return n, err
		}
		publicCatalog, e = mergeLinkCatalog(n.ID, prior, publicCatalog)
		if e != nil {
			return n, e
		}
	}
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return n, e
	}
	objects, e := decodeLinkCatalog(publicCatalog, n.ID)
	if e != nil {
		return n, e
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return n, e
	}
	state, e := linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: invite.FeatureID, Now: now}, publicCatalog)
	if e != nil {
		return n, e
	}
	action := "none"
	publicPerson := "-"
	if mode == "member" || mode == "person" {
		action, publicPerson = "admit", person
		if mode == "member" && state.Facts.State.Persons[person].Admitted {
			action = "skip"
		}
	}
	fields := map[string]any{"format": 1, "mode": mode, "person_action": action, "host_public_key": hostKey, "person_public_key": publicPerson, "joined_at": linkTime(now), "host_invite": "-", "person_invite": "-", "host_member_signature": "-", "person_member_signature": "-"}
	if mode != "person" {
		fields["host_invite"] = json.RawMessage(invite.HostInvite)
		fields["host_member_signature"] = membership.EncodeKey(ed25519.Sign(invite.Key, membership.MemberStatement(n.ID, invite.InvitePublicKey, s.identity.PublicKey, linkTime(now))))
	}
	if action == "admit" {
		fields["person_invite"] = json.RawMessage(invite.PersonInvite)
		fields["person_member_signature"] = membership.EncodeKey(ed25519.Sign(invite.Key, membership.PersonMemberStatement(n.ID, invite.InvitePublicKey, publicPerson, linkTime(now))))
	}
	redemption, e := linkJSON(fields)
	if e != nil {
		return n, e
	}
	if _, e = linking.VerifyStoredFreshRedemption(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: invite.FeatureID, Now: now}, publicCatalog, redemption); e != nil {
		return n, e
	}
	ack := json.RawMessage(`"-"`)
	address := ""
	candidates := []string{}
	if mode != "person" {
		ack, e = linkJSON(map[string]any{"format": 1, "feature_id": invite.FeatureID, "host_public_key": s.identity.PublicKey, "signature": membership.EncodeKey(ed25519.Sign(s.privateKey, linkMessage("peerspan-link-feature-ack-v1", invite.FeatureID, s.identity.PublicKey)))})
		if e != nil {
			return n, e
		}
		address, _ = s.coordinationConfig()
		candidates = s.ownCandidates(ctx, n.CoordinatorAddress)
	}
	request, e := linkJSON(linkRedemptionRequest{redemption, publicCatalog, address, candidates, ack})
	if e != nil {
		return n, e
	}
	if len(request) > 1<<20 {
		return n, linkFail("quota_exceeded", "-", "redemption")
	}
	seed, e := linkJSON(inviteFeatureSeed{outer.FeatureBinding, outer.HostInviteBase64, outer.PersonInviteBase64})
	if e != nil {
		return n, e
	}
	intent := linkRedemptionIntent{1, base64.StdEncoding.EncodeToString(descriptor), invite.FeatureID, base64.StdEncoding.EncodeToString(seed), base64.StdEncoding.EncodeToString(redemption), base64.StdEncoding.EncodeToString(request), false, "-"}
	if e = s.saveLinkRedemption(ctx, n.ID, id, intent); e != nil {
		return n, e
	}
	return s.advanceLinkRedemption(ctx, n, id, intent)
}

func (s *Store) advanceLinkRedemption(ctx context.Context, n Network, id string, intent linkRedemptionIntent) (Network, error) {
	target, request, view, _, e := intent.materialize()
	if e != nil {
		return n, e
	}
	if intent.ResultMapBase64 != "-" {
		existing, err := s.Network(ctx, n.ID)
		if err != nil {
			return n, err
		}
		now, err := linkNow()
		if err != nil {
			return existing, err
		}
		// The retained commitment cannot bypass missing present retention.
		// This check neither republishes it nor reapplies its old projection.
		projection, err := s.readLinkProjection(ctx, s.db, existing, now)
		if err == nil && (projection == nil || projection.Network.Facts.FeatureID != intent.FeatureID) {
			err = linkFail("state_conflict", "-", "feature")
		}
		return existing, err
	}
	wasSubmitted := intent.Submitted
	intent.Submitted = true
	if e = s.saveLinkRedemption(ctx, n.ID, id, intent); e != nil {
		return n, e
	}
	body, e := linkBytes(intent.RequestBase64, 1<<20)
	if e != nil {
		return n, e
	}
	raw, e := s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/"+n.ID+"/invite-redemptions", body)
	if e != nil {
		code := linkCause(e, "-", "redemption").Code
		if !wasSubmitted && (code == "invalid" || code == "forbidden" || code == "state_conflict" || code == "quota_exceeded") {
			_, _ = s.db.ExecContext(ctx, `DELETE FROM network_statements WHERE network_id=? AND kind=? AND subject=?`, n.ID, kindLinkRedemptionIntent, id)
		}
		return n, e
	}
	now, e := linkNow()
	if e != nil {
		return n, e
	}
	wire, e := decodeLinkMap(raw, target)
	if e != nil {
		return n, e
	}
	receipt, e := decodeLinkCatalog(wire.Catalog, n.ID)
	if e != nil {
		return n, e
	}
	original, e := decodeLinkCatalog(request.Catalog, n.ID)
	if e != nil {
		return n, e
	}
	seen := map[string]bool{}
	for _, object := range receipt.Objects {
		seen[object.ID] = true
	}
	required := []string{linkProofID("invite_redemption", request.Redemption)}
	if view.Mode != "person" {
		required = append(required, linkProofID("join_ack", request.JoinAck))
	}
	for _, object := range original.Objects {
		required = append(required, object.ID)
	}
	for _, proof := range required {
		if !seen[proof] {
			return n, linkFail("proof_required", "-", "redemption", proof)
		}
	}
	epoch, e := linkCatalogEpoch(receipt)
	if e != nil {
		return n, e
	}
	descriptor, _ := linkBytes(intent.NetworkBase64, linking.MaxObject)
	joined, e := linkStamp(view.JoinedAt)
	if e != nil {
		return n, e
	}
	// The frozen receipt proves only the original commitment. Current local
	// retention must be joined below before it can supply present authority.
	ctxFacts := linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: intent.FeatureID, Now: joined}
	historical, e := linking.VerifyStoredNetworkState(ctxFacts, wire.Catalog)
	if e != nil {
		return n, e
	}
	_, originalHints, e := s.verifiedLinkMapMembers(&linkProjection{Network: historical}, wire)
	if e != nil {
		return n, e
	}
	if _, e = linking.VerifyStoredAccessState(linking.AccessContext{Network: descriptor, Epoch: epoch, KnownFeatureID: intent.FeatureID, Now: joined}, wire.Catalog); e != nil {
		return n, e
	}
	repair, e := s.linkRedemptionRepair(ctx, target, intent.FeatureID, receipt, wire.Catalog, now)
	if e != nil {
		return n, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return n, e
	}
	defer tx.Rollback()
	if existing, err := scanNetwork(tx.QueryRowContext(ctx, networkColumns+" WHERE id=?", n.ID)); err == nil {
		n = existing
	} else if errors.Is(err, ErrNotFound) {
		n = target
		n.Member = ""
		if _, e = tx.ExecContext(ctx, `INSERT INTO networks(id,record,root_seed) VALUES(?,?,NULL)`, n.ID, `{}`); e != nil {
			return n, e
		}
	} else {
		return n, err
	}
	prior, e := readLinkCatalog(ctx, tx, n.ID)
	if e != nil {
		return n, e
	}
	parts := [][]byte{prior, wire.Catalog}
	if len(repair) > 0 {
		parts = append(parts, repair)
	}
	union, e := mergeLinkCatalog(n.ID, parts...)
	if e != nil {
		return n, e
	}
	unionRows, e := decodeLinkCatalog(union, n.ID)
	if e != nil {
		return n, e
	}
	epoch, e = linkCatalogEpoch(unionRows)
	if e != nil {
		return n, e
	}
	if e = linking.VerifyStoredCatalogRepair(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: intent.FeatureID, Now: now}, prior, union); e != nil {
		return n, e
	}
	// The immutable receipt's references proved the historical commitment.
	// Its old binding references need not equal the current verified selection.
	// Repair responses contribute public proofs only, never reachability hints.
	p, e := s.verifyLinkProjection(ctx, tx, target, union, now, &linkFeatureAdoption{intent.FeatureID})
	if e != nil {
		return n, e
	}
	existing, e := readLinkMembers(ctx, tx, n.ID)
	if e != nil {
		return n, e
	}
	hints := map[string]NetworkMember{}
	for _, member := range originalHints {
		hints[member.PublicKey] = member
	}
	for _, member := range existing {
		if incoming, ok := hints[member.PublicKey]; !ok || member.UpdatedAt >= incoming.UpdatedAt {
			hints[member.PublicKey] = member
		}
	}
	allHints := []NetworkMember{}
	for _, member := range hints {
		allHints = append(allHints, member)
	}
	members := projectedLinkMembers(p, allHints, linkTime(now))
	for _, member := range members {
		if member.HostID == s.identity.ID {
			n.Member = member.Member
		}
	}
	if e = s.applyLinkProjection(ctx, tx, &n, p, members, linkTime(now)); e != nil {
		return n, e
	}
	intent.ResultMapBase64 = base64.StdEncoding.EncodeToString(raw)
	encoded, e := linkJSON(intent)
	if e != nil {
		return n, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE network_statements SET record=? WHERE network_id=? AND kind=? AND subject=?`, string(encoded), n.ID, kindLinkRedemptionIntent, id); e != nil {
		return n, e
	}
	event, subject := "network.joined", n.ID
	if view.Mode == "person" {
		event, subject = "network.person_admitted", personIDOf(view.PersonPublicKey)
	}
	if e = appendEvent(ctx, tx, event, subject, linkTime(now)); e != nil {
		return n, e
	}
	if e = tx.Commit(); e != nil {
		return n, e
	}
	s.mapApplied(n.ID, members)
	s.wakeRelays()
	return n, nil
}
