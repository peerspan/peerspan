package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

const kindPendingLinkMove = "pending_link_move"

type linkMoveIntent struct {
	Format              uint64 `json:"format"`
	SourceNetworkBase64 string `json:"source_network_base64"`
	NetworkBase64       string `json:"network_base64"`
	FeatureID           string `json:"feature_id"`
	MoveBase64          string `json:"move_base64"`
	RequestBase64       string `json:"request_base64"`
	Submitted           bool   `json:"submitted"`
	ResultMapBase64     string `json:"result_map_base64"`
}
type linkMoveRequest struct {
	Network              json.RawMessage `json:"network"`
	Catalog              json.RawMessage `json:"catalog"`
	FeatureAuthorization string          `json:"feature_authorization"`
}

func (i linkMoveIntent) materialize(n Network) (Network, Network, membership.Move, []byte, []byte, error) {
	var mv membership.Move
	fail := func() (Network, Network, membership.Move, []byte, []byte, error) {
		return Network{}, Network{}, mv, nil, nil, linkFail("state_conflict", "-", "move")
	}
	if i.Format != 1 || !linkID(i.FeatureID, "lf_") || !i.Submitted {
		return fail()
	}
	descriptors := []Network{}
	for _, encoded := range []string{i.SourceNetworkBase64, i.NetworkBase64} {
		raw, e := linkBytes(encoded, linking.MaxObject)
		if e != nil {
			return fail()
		}
		var d linkDescriptor
		if linking.DecodeMutation(raw, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &d) != nil || d.NetworkID != n.ID || d.Name != n.Name || d.GenesisRootPublicKey != n.RootPublicKey || !membership.ValidCoordinatorAddress(d.CoordinatorAddress) {
			return fail()
		}
		if _, e = membership.DecodeKey(d.CoordinatorPublicKey); e != nil {
			return fail()
		}
		copy := n
		copy.CoordinatorAddress = d.CoordinatorAddress
		copy.CoordinatorPublicKey = d.CoordinatorPublicKey
		copy.CoordinatorPending = nil
		descriptors = append(descriptors, copy)
	}
	move, e := linkBytes(i.MoveBase64, linking.MaxObject)
	if e != nil {
		return fail()
	}
	if linking.DecodeMutation(move, "network_id sequence address public_key moved_at signer signature", &mv) != nil || mv.NetworkID != n.ID || mv.Sequence <= 0 || mv.Address != descriptors[1].CoordinatorAddress || mv.PublicKey != descriptors[1].CoordinatorPublicKey {
		return fail()
	}
	request, e := linkBytes(i.RequestBase64, 1<<20)
	if e != nil {
		return fail()
	}
	var in linkMoveRequest
	if linking.DecodeStoredJSON(request, "network catalog feature_authorization", &in) != nil || in.FeatureAuthorization != "-" {
		return fail()
	}
	targetRaw, e := linkBytes(i.NetworkBase64, linking.MaxObject)
	if e != nil || !bytes.Equal(in.Network, targetRaw) {
		return fail()
	}
	c, e := decodeLinkCatalog(in.Catalog, n.ID)
	if e != nil {
		return fail()
	}
	found := false
	for _, p := range c.Objects {
		if p.ID == linkProofID("coordinator_move", move) && p.Kind == "coordinator_move" {
			b, e := linkBytes(p.BodyBase64, linking.MaxObject)
			if e != nil || !bytes.Equal(b, move) {
				return fail()
			}
			found = true
		}
	}
	if !found {
		return fail()
	}
	if i.ResultMapBase64 != "-" {
		if _, e = linkBytes(i.ResultMapBase64, 16<<20); e != nil {
			return fail()
		}
	}
	return descriptors[0], descriptors[1], mv, request, in.Catalog, nil
}
func readLinkMoveIntent(ctx context.Context, q dbQuerier, n Network) (*linkMoveIntent, error) {
	var raw string
	e := q.QueryRowContext(ctx, `SELECT record FROM network_statements WHERE network_id=? AND kind=? AND subject=''`, n.ID, kindPendingLinkMove).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var i linkMoveIntent
	if linking.DecodeStoredJSON([]byte(raw), "format source_network_base64 network_base64 feature_id move_base64 request_base64 submitted result_map_base64", &i) != nil {
		return nil, linkFail("state_conflict", "-", "move")
	}
	_, _, _, _, _, e = i.materialize(n)
	return &i, e
}
func saveLinkMoveIntent(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, network string, i linkMoveIntent) error {
	raw, e := linkJSON(i)
	if e != nil {
		return e
	}
	_, e = q.ExecContext(ctx, `INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?,?,'',?) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record`, network, kindPendingLinkMove, string(raw))
	return e
}

// Only a response to the exact persisted move intent receives historical-union
// handling. It cannot change the pin or claim a fresh live target sync.
func (s *Store) retainLinkMoveReceipt(ctx context.Context, n Network, i *linkMoveIntent, raw []byte) error {
	_, target, _, _, submitted, e := i.materialize(n)
	if e != nil {
		return e
	}
	wire, e := decodeLinkMap(raw, target)
	if e != nil {
		return e
	}
	received, e := decodeLinkCatalog(wire.Catalog, n.ID)
	if e != nil {
		return e
	}
	original, e := decodeLinkCatalog(submitted, n.ID)
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, p := range received.Objects {
		seen[p.ID] = true
	}
	for _, p := range original.Objects {
		if !seen[p.ID] {
			return linkFail("proof_required", "-", "move", p.ID)
		}
	}
	now, e := linkNow()
	if e != nil {
		return e
	}
	net, e := linkBytes(i.NetworkBase64, linking.MaxObject)
	if e != nil {
		return e
	}
	epoch, e := linkCatalogEpoch(received)
	if e != nil {
		return e
	}
	context := linking.CatalogFactContext{Network: net, Epoch: epoch, KnownFeatureID: i.FeatureID, Now: now}
	if _, e = linking.VerifyStoredNetworkState(context, wire.Catalog); e != nil {
		return e
	}
	if _, e = linking.VerifyStoredAccessState(linking.AccessContext{Network: net, Epoch: epoch, KnownFeatureID: i.FeatureID, Now: now}, wire.Catalog); e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	current, e := scanNetwork(tx.QueryRowContext(ctx, networkColumns+" WHERE id=?", n.ID))
	if e != nil {
		return e
	}
	feature, _, e := readLinkFeature(ctx, tx, n.ID)
	if e != nil {
		return e
	}
	if feature != i.FeatureID {
		return linkFail("state_conflict", "-", "move")
	}
	prior, e := readLinkCatalog(ctx, tx, n.ID)
	if e != nil {
		return e
	}
	union, e := mergeLinkCatalog(n.ID, prior, wire.Catalog)
	if e != nil {
		return e
	}
	objects, e := decodeLinkCatalog(union, n.ID)
	if e != nil {
		return e
	}
	context.Epoch, e = linkCatalogEpoch(objects)
	if e != nil {
		return e
	}
	if e = linking.VerifyStoredCatalogRepair(context, prior, union); e != nil {
		return e
	}
	wire.Catalog = union
	augmented, e := linkJSON(wire)
	if e != nil {
		return e
	}
	p, members, e := s.verifyLinkMap(ctx, tx, target, augmented, now)
	if e != nil {
		return e
	}
	old, e := readLinkMembers(ctx, tx, n.ID)
	if e != nil {
		return e
	}
	hints := map[string]NetworkMember{}
	for _, m := range members {
		hints[m.PublicKey] = m
	}
	for _, m := range old {
		if incoming, ok := hints[m.PublicKey]; !ok || m.UpdatedAt >= incoming.UpdatedAt {
			hints[m.PublicKey] = m
		}
	}
	merged := []NetworkMember{}
	for _, m := range hints {
		merged = append(merged, m)
	}
	members = projectedLinkMembers(p, merged, linkTime(now))
	if e = s.applyLinkProjection(ctx, tx, &current, p, members, linkTime(now)); e != nil {
		return e
	}
	i.ResultMapBase64 = base64.StdEncoding.EncodeToString(raw)
	if e = saveLinkMoveIntent(ctx, tx, n.ID, *i); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) moveLinkNetwork(ctx context.Context, network string, r MoveNetwork) (MoveResult, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	var result MoveResult
	g, e := s.loadGovernance(ctx, s.db, network)
	if e != nil {
		return result, e
	}
	if g.linking == nil {
		return result, linkFail("upgrade_required", "-", "move")
	}
	n := g.network
	firstAttempt := false
	intent, e := readLinkMoveIntent(ctx, s.db, n)
	if e != nil {
		return result, e
	}
	if intent != nil {
		if intent.FeatureID != g.linking.Network.Facts.FeatureID {
			return result, linkFail("state_conflict", "-", "move")
		}
		_, target, mv, _, _, e := intent.materialize(n)
		if e != nil {
			return result, e
		}
		held, _, e := heldMove(ctx, s.db, network)
		if e != nil {
			return result, e
		}
		if held != nil && held.Sequence == mv.Sequence {
			a, _ := linkJSON(*held)
			b, _ := linkJSON(mv)
			if !bytes.Equal(a, b) {
				return result, linkFail("operation_conflict", "-", "move")
			}
		}
		obsolete := false
		if held != nil && held.Sequence > mv.Sequence && g.verifyMove(*held) == nil {
			b, e := linkJSON(*held)
			if e != nil {
				return result, e
			}
			for _, p := range g.linking.Objects.Objects {
				if p.Kind == "coordinator_move" && p.ID == linkProofID("coordinator_move", b) {
					obsolete = true
				}
			}
		}
		completeElsewhere := intent.ResultMapBase64 != "-" && (target.CoordinatorAddress != r.CoordinatorAddress || target.CoordinatorPublicKey != r.CoordinatorPublicKey)
		if obsolete || completeElsewhere {
			if _, e = s.db.ExecContext(ctx, `DELETE FROM network_statements WHERE network_id=? AND kind=? AND subject=''`, network, kindPendingLinkMove); e != nil {
				return result, e
			}
			intent = nil
		} else {
			if target.CoordinatorAddress != r.CoordinatorAddress || target.CoordinatorPublicKey != r.CoordinatorPublicKey {
				return result, linkFail("operation_conflict", "-", "move")
			}
			if r.Move != nil {
				a, _ := linkJSON(*r.Move)
				b, _ := linkJSON(mv)
				if !bytes.Equal(a, b) {
					return result, linkFail("operation_conflict", "-", "move")
				}
			}
		}
	}
	if intent == nil {
		firstAttempt = true
		if n.CoordinatorAddress == r.CoordinatorAddress && n.CoordinatorPublicKey == r.CoordinatorPublicKey {
			return result, linkFail("state_conflict", "-", "move")
		}
		plan, e := s.MovePlan(ctx, network)
		if e != nil {
			return result, e
		}
		mv := r.Move
		if mv == nil {
			var seed []byte
			if e = s.db.QueryRowContext(ctx, `SELECT root_seed FROM networks WHERE id=?`, network).Scan(&seed); e != nil {
				return result, e
			}
			if len(seed) != ed25519.SeedSize {
				return result, linkFail("forbidden", "-", "move")
			}
			key := ed25519.NewKeyFromSeed(seed)
			if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != g.linking.Network.RootPublicKey {
				return result, linkFail("forbidden", "-", "move")
			}
			now, e := linkNow()
			if e != nil {
				return result, e
			}
			signed, e := membership.SignMove(membership.RawSigner{Key: key}, true, network, plan.NextSequence, r.CoordinatorAddress, r.CoordinatorPublicKey, linkTime(now))
			if e != nil {
				return result, e
			}
			mv = &signed
		}
		if mv.NetworkID != network || mv.Address != r.CoordinatorAddress || mv.PublicKey != r.CoordinatorPublicKey || mv.Sequence != plan.NextSequence {
			return result, linkFail("state_conflict", "-", "move")
		}
		if e = g.verifyMove(*mv); e != nil {
			return result, e
		}
		body, e := linkJSON(*mv)
		if e != nil {
			return result, e
		}
		delta, e := catalogWithLinkObject(network, "coordinator_move", body)
		if e != nil {
			return result, e
		}
		catalog, e := mergeLinkCatalog(network, g.linking.Catalog, delta)
		if e != nil {
			return result, e
		}
		now, e := linkNow()
		if e != nil {
			return result, e
		}
		context := linking.CatalogFactContext{Network: g.linking.Descriptor, Epoch: g.linking.Network.Epoch, KnownFeatureID: g.linking.Network.Facts.FeatureID, Now: now}
		if e = linking.VerifyStoredCatalogAdditions(context, g.linking.Catalog, catalog); e != nil {
			return result, e
		}
		target := n
		target.CoordinatorAddress = r.CoordinatorAddress
		target.CoordinatorPublicKey = r.CoordinatorPublicKey
		target.CoordinatorPending = nil
		source, _ := linkJSON(linkNetworkDescriptor(n))
		descriptor, _ := linkJSON(linkNetworkDescriptor(target))
		request, e := linkJSON(linkMoveRequest{Network: descriptor, Catalog: catalog, FeatureAuthorization: "-"})
		if e != nil {
			return result, e
		}
		if len(request) > 1<<20 {
			return result, linkFail("quota_exceeded", "-", "move")
		}
		intent = &linkMoveIntent{Format: 1, SourceNetworkBase64: base64.StdEncoding.EncodeToString(source), NetworkBase64: base64.StdEncoding.EncodeToString(descriptor), FeatureID: g.linking.Network.Facts.FeatureID, MoveBase64: base64.StdEncoding.EncodeToString(body), RequestBase64: base64.StdEncoding.EncodeToString(request), Submitted: true, ResultMapBase64: "-"}
		if e = saveLinkMoveIntent(ctx, s.db, network, *intent); e != nil {
			return result, e
		}
	}
	source, target, mv, request, _, e := intent.materialize(n)
	if e != nil {
		return result, e
	}
	if intent.ResultMapBase64 == "-" {
		raw, e := s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/import", request)
		if e != nil {
			var failure *linkFailure
			if errors.As(e, &failure) && firstAttempt && failure.Status >= 400 && failure.Status < 500 {
				if _, cleanup := s.db.ExecContext(ctx, `DELETE FROM network_statements WHERE network_id=? AND kind=? AND subject=''`, network, kindPendingLinkMove); cleanup != nil {
					return result, cleanup
				}
			}
			if failure != nil && failure.Code == "proof_required" {
				failure.Details.Next = []string{"Review and approve network repair for this exact target, then retry network move."}
			}
			return result, e
		}
		if e = s.retainLinkMoveReceipt(ctx, n, intent, raw); e != nil {
			return result, e
		}
	} else {
		raw, e := linkBytes(intent.ResultMapBase64, 16<<20)
		if e != nil {
			return result, e
		}
		if e = s.retainLinkMoveReceipt(ctx, n, intent, raw); e != nil {
			return result, e
		}
	}
	// Read the complete current projection again after receipt union; a retry
	// cannot publish a closure that omits restrictions learned in the meantime.
	current, e := s.loadGovernance(ctx, s.db, network)
	if e != nil {
		return result, e
	}
	if e = current.verifyMove(mv); e != nil {
		return result, e
	}
	now, e := linkNow()
	if e != nil {
		return result, e
	}
	moveBody, _ := linkJSON(mv)
	context := linking.CatalogFactContext{Network: current.linking.Descriptor, Epoch: current.linking.Network.Epoch, KnownFeatureID: current.linking.Network.Facts.FeatureID, Now: now}
	sufficient, e := linking.SelectStoredProofCatalog(context, current.linking.Catalog, []linking.ProofSeed{{Kind: "coordinator_move", Body: moveBody}})
	if e != nil {
		return result, e
	}
	publication, e := linkJSON(map[string]any{"move": json.RawMessage(moveBody), "catalog": json.RawMessage(sufficient)})
	if e != nil {
		return result, e
	}
	_, e = s.linkCoordinator(ctx, source, http.MethodPost, "/coord/v2/networks/"+url.PathEscape(network)+"/moves", publication)
	result = MoveResult{NetworkID: network, Sequence: mv.Sequence, Coordinator: MoveCoordinator{target.CoordinatorAddress, target.CoordinatorPublicKey}}
	var failure *linkFailure
	switch {
	case e == nil:
		result.PreviousCoordinator = "accepted"
	case errors.As(e, &failure) && failure.Code != "unavailable":
		result.PreviousCoordinator = "refused"
	default:
		result.PreviousCoordinator = "unreachable"
	}
	result.Pushed, result.Members = s.pushMove(ctx, network, mv)
	return result, nil
}
