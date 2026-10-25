package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func linkTransportEvidence(n Network, p *linkProjection) (*membership.Move, []json.RawMessage, error) {
	chain, e := linkChain(n, p)
	if e != nil {
		return nil, nil, e
	}
	admins := map[string]bool{}
	for person, state := range p.Network.Facts.State.Persons {
		if state.Admitted && state.Administrator {
			admins[person] = true
		}
	}
	var move *membership.Move
	type edge struct {
		value membership.Successor
		raw   json.RawMessage
	}
	edges := []edge{}
	for _, object := range p.Objects.Objects {
		if object.Kind != "coordinator_move" && object.Kind != "coordinator_successor" {
			continue
		}
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return nil, nil, e
		}
		if object.Kind == "coordinator_move" {
			var candidate membership.Move
			if json.Unmarshal(body, &candidate) == nil && chain.VerifyMove(candidate, admins) == nil && (move == nil || candidate.Sequence > move.Sequence) {
				move = &candidate
			}
		} else if successor, e := membership.DecodeSuccessor(body); e == nil {
			edges = append(edges, edge{successor, body})
		}
	}
	var first *edge
	for i := range edges {
		candidate := &edges[i]
		if candidate.value.PreviousPublicKey == n.CoordinatorPublicKey && (first == nil || candidate.value.Sequence > first.value.Sequence) {
			first = candidate
		}
	}
	successors := []json.RawMessage{}
	if first != nil {
		successors = append(successors, first.raw)
		last := first.value
		// Repeated keys are valid. Strictly increasing sequence and the finite
		// retained edge count bound traversal without rejecting address-only moves.
		for count := 1; count < len(edges); count++ {
			var next *edge
			for i := range edges {
				candidate := &edges[i]
				if candidate.value.PreviousPublicKey == last.PublicKey && candidate.value.Sequence == last.Sequence+1 {
					next = candidate
					break
				}
			}
			if next == nil {
				break
			}
			successors = append(successors, next.raw)
			last = next.value
		}
		if _, e = membership.VerifySuccessors(n.CoordinatorPublicKey, successors); e != nil {
			return nil, nil, e
		}
	}
	return move, successors, nil
}

func applyLinkTransport(ctx context.Context, tx *sql.Tx, n *Network, p *linkProjection) error {
	move, successors, e := linkTransportEvidence(*n, p)
	if e != nil {
		return e
	}
	_, applied, e := heldMove(ctx, tx, n.ID)
	if e != nil {
		return e
	}
	if move != nil {
		// The selection has already filtered current root/admin authority. A
		// historical higher signature cannot hide a lower currently valid move.
		if e = putRecord(ctx, tx, n.ID, kindMove, "", *move); e != nil {
			return e
		}
		_, next := considerMove(n, *move, applied)
		if next > applied {
			if e = storeApplied(ctx, tx, n.ID, next); e != nil {
				return e
			}
		}
	}
	var notice *string
	followChain(n, successors, &notice)
	return nil
}

func (s *Store) syncLinkFollowingLocked(ctx context.Context, n Network, body []byte, now time.Time) (Network, error) {
	prior, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		if linkCause(e, "-", "sync").Code == "proof_required" {
			markers, err := readLinkRestrictionMarkers(ctx, s.db, n.ID)
			if err != nil {
				return n, err
			}
			pending, err := loadPendingRotation(ctx, s.db, n.ID)
			if err != nil {
				return n, err
			}
			if len(markers) == 0 && pending == nil {
				// Missing retention cannot authorize a transport change. The
				// independently persisted actual pin can still supply public
				// proof, subject to the complete live-map retention checks.
				target := n
				target.CoordinatorPending = nil
				raw, err := s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/"+n.ID+"/sync", body)
				if err != nil {
					return n, err
				}
				return s.applyLinkMap(ctx, target, raw)
			}
		}
		return n, e
	}
	markers, e := readLinkRestrictionMarkers(ctx, s.db, n.ID)
	if e != nil {
		return n, e
	}
	if len(markers) > 0 {
		// Validate local source and quota before any transport alternative.
		if _, e = linkRestrictionRepairRequest(n, prior, markers, now); e != nil {
			return n, e
		}
	}
	move, _, e := linkTransportEvidence(n, prior)
	if e != nil {
		return n, e
	}
	held, applied, e := heldMove(ctx, s.db, n.ID)
	if e != nil {
		return n, e
	}
	if held != nil {
		chain, err := linkChain(n, prior)
		if err != nil {
			return n, err
		}
		admins := map[string]bool{}
		for person, state := range prior.Network.Facts.State.Persons {
			if state.Admitted && state.Administrator {
				admins[person] = true
			}
		}
		if chain.VerifyMove(*held, admins) == nil && (move == nil || held.Sequence > move.Sequence) {
			move = held
		}
	}
	if n.CoordinatorPending.isMove() && (move == nil || move.Sequence != n.CoordinatorPending.Sequence) {
		n.CoordinatorPending = nil
	}
	if move != nil {
		_, applied = considerMove(&n, *move, applied)
	}
	type response struct {
		raw        []byte
		projection *linkProjection
		members    []NetworkMember
	}
	responses := map[string]response{}
	request := func(target Network) (appliedMap, []json.RawMessage, error) {
		var raw []byte
		var err error
		if len(markers) > 0 {
			repair, err := linkRestrictionRepairRequest(target, prior, markers, now)
			if err != nil {
				return appliedMap{}, nil, err
			}
			// Historical repair returns a live map. In particular, a valid
			// self-removal can acknowledge its PF before later requests deny us.
			raw, err = s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/import", repair)
		} else {
			raw, err = s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/"+n.ID+"/sync", body)
		}
		var projection *linkProjection
		var members []NetworkMember
		if err == nil {
			projection, members, err = s.verifyLinkMap(ctx, s.db, target, raw, now)
		}
		if err != nil && len(markers) == 0 && s.importAllowed(n.ID) {
			// Existing active destinations may be repaired from historical public
			// evidence. A missing feature still requires explicit reviewed root intent.
			descriptor, de := linkJSON(linkNetworkDescriptor(target))
			if de == nil {
				importBody, ie := linkJSON(map[string]any{"network": json.RawMessage(descriptor), "catalog": json.RawMessage(prior.Catalog), "feature_authorization": "-"})
				if ie == nil && len(importBody) <= 1<<20 {
					if _, ie = s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/import", importBody); ie == nil {
						raw, err = s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/"+n.ID+"/sync", body)
						if err == nil {
							projection, members, err = s.verifyLinkMap(ctx, s.db, target, raw, now)
						}
					}
				}
			}
		}
		if err != nil {
			return appliedMap{}, nil, err
		}
		mv, successors, err := linkTransportEvidence(target, projection)
		if err != nil {
			return appliedMap{}, nil, err
		}
		responses[target.CoordinatorAddress+"|"+target.CoordinatorPublicKey] = response{raw, projection, members}
		return appliedMap{move: mv}, successors, nil
	}
	previous := n.CoordinatorAddress + "|" + n.CoordinatorPublicKey
	n, _, notice, applied, e := s.syncFollowing(n, applied, request)
	if e != nil {
		return n, e
	}
	chosen := responses[n.CoordinatorAddress+"|"+n.CoordinatorPublicKey]
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return n, e
	}
	defer tx.Rollback()
	stamp := linkTime(now)
	n.LastSyncAt = &stamp
	if e = s.applyLinkProjection(ctx, tx, &n, chosen.projection, chosen.members, linkTime(now)); e != nil {
		return n, e
	}
	n.LastSyncError = notice
	if e = clearLinkRestrictionMarkers(ctx, tx, n.ID, markers); e != nil {
		return n, e
	}
	if e = storeApplied(ctx, tx, n.ID, applied); e != nil {
		return n, e
	}
	if e = putJSON(ctx, tx, `UPDATE networks SET record=? WHERE id=?`, n, n.ID); e != nil {
		return n, e
	}
	if e = tx.Commit(); e != nil {
		return n, e
	}
	s.mapApplied(n.ID, chosen.members)
	if n.CoordinatorAddress+"|"+n.CoordinatorPublicKey != previous {
		s.wakeRelays()
	}
	s.reapplyIfUnsettled(ctx, n.ID)
	return n, nil
}
