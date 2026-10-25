package host

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// Called with the same rotation/sync lock as the legacy pending writer. The
// public rotation and new seed become local state in one accepted transaction.
func (s *Store) completeLinkRotation(ctx context.Context, n Network, pending *pendingRotation) (Network, error) {
	now, e := linkNow()
	if e != nil {
		return n, e
	}
	prior, e := readLinkCatalog(ctx, s.db, n.ID)
	if e != nil {
		return n, e
	}
	seeds := []linking.ProofSeed{}
	add := func(kind string, value any) error {
		body, err := linkJSON(value)
		if err != nil {
			return err
		}
		seeds = append(seeds, linking.ProofSeed{Kind: kind, Body: body})
		return nil
	}
	if e = add("rotation", pending.Rotation); e != nil {
		return n, e
	}
	for _, attestation := range pending.Attestations {
		if e = add("attestation", attestation); e != nil {
			return n, e
		}
	}
	for _, admission := range pending.Admissions {
		var shape map[string]json.RawMessage
		if json.Unmarshal(admission, &shape) != nil {
			return n, linkFail("invalid", "-", "rotation")
		}
		kind := "person_admission"
		if _, ok := shape["host_public_key"]; ok {
			kind = "host_admission"
		}
		if _, ok := shape["delegated_at"]; ok {
			kind = "admin_delegation"
		}
		if e = add(kind, admission); e != nil {
			return n, e
		}
	}
	for _, group := range pending.Groups {
		if e = add("group", group); e != nil {
			return n, e
		}
	}
	// Build the source through the canonical immutable merger.
	parts := [][]byte{prior}
	for _, seed := range seeds {
		part, err := catalogWithLinkObject(n.ID, seed.Kind, seed.Body)
		if err != nil {
			return n, err
		}
		parts = append(parts, part)
	}
	union, e := mergeLinkCatalog(n.ID, parts...)
	if e != nil {
		return n, e
	}
	projection, e := s.verifyLinkProjection(ctx, s.db, n, union, now)
	if e != nil {
		return n, e
	}
	fact := linking.CatalogFactContext{Network: projection.Descriptor, Epoch: projection.Network.Epoch, KnownFeatureID: projection.Network.Facts.FeatureID, Now: now}
	if e = linking.VerifyStoredCatalogAdditions(fact, prior, union); e != nil {
		return n, e
	}
	publication, e := linking.SelectStoredProofCatalog(fact, union, seeds)
	if e != nil {
		return n, e
	}
	publication, e = mergeLinkCatalog(n.ID, append([][]byte{publication}, parts[1:]...)...)
	if e != nil {
		return n, e
	}
	body, e := linkJSON(map[string]any{"catalog": json.RawMessage(publication)})
	if e != nil {
		return n, e
	}
	if len(body) > 1<<20 {
		return n, linkFail("quota_exceeded", "-", "rotation")
	}
	raw, e := s.linkCoordinator(ctx, n, http.MethodPost, "/coord/v2/networks/"+n.ID+"/statements", body)
	if e != nil {
		return n, s.rejectLinkRotation(ctx, n.ID, pending, e)
	}
	var seed []byte
	if pending.RootSeed != "" {
		key, err := membership.DecodeSeed(pending.RootSeed)
		if err != nil || membership.PublicKey(key) != pending.Rotation.RootPublicKey {
			return n, linkFail("state_conflict", "-", "rotation")
		}
		seed = key.Seed()
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return n, e
	}
	defer tx.Rollback()
	projection, members, e := s.verifyLinkMap(ctx, tx, n, raw, now)
	if e != nil {
		return n, e
	}
	if projection.Network.Epoch < uint64(pending.Rotation.Epoch) || projection.Network.RootPublicKey != pending.Rotation.RootPublicKey {
		return n, linkFail("state_conflict", "-", "rotation")
	}
	oldEpoch := n.RootEpoch
	n.RootSSH, n.Administrator = seed == nil, seed != nil
	stamp := linkTime(now)
	n.LastSyncAt, n.LastSyncError = &stamp, nil
	if e = s.applyLinkProjection(ctx, tx, &n, projection, members, linkTime(now)); e != nil {
		return n, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE networks SET root_seed=? WHERE id=?`, seed, n.ID); e != nil {
		return n, e
	}
	// Common projection retires the obsolete durable root first. Only this
	// exact verified accepted rotation may install its fixed pending seed.
	n.Administrator = seed != nil
	if e = putJSON(ctx, tx, "UPDATE networks SET record = ? WHERE id = ?", n, n.ID); e != nil {
		return n, e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM network_statements WHERE network_id=? AND kind=?`, n.ID, kindPendingRotation); e != nil {
		return n, e
	}
	if n.RootEpoch > oldEpoch {
		if e = appendEvent(ctx, tx, "network.root_rotated", n.ID, linkTime(now)); e != nil {
			return n, e
		}
	}
	if e = tx.Commit(); e != nil {
		return n, e
	}
	s.mapApplied(n.ID, members)
	return n, nil
}

func (s *Store) rejectLinkRotation(ctx context.Context, network string, pending *pendingRotation, cause error) error {
	var response *linkFailure
	if !errors.As(cause, &response) || !response.coordinatorResponse {
		return cause
	}
	failure := linkCause(cause, "-", "rotation")
	switch response.Code {
	case "forbidden":
		failure.Details.Next = append(failure.Details.Next, "repair current root authority before resuming the pending rotation")
		return failure
	case "invalid", "state_conflict", "operation_conflict":
	default:
		return cause
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, e := s.db.BeginTx(finish, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	current, e := loadPendingRotation(finish, tx, network)
	if e != nil {
		return e
	}
	if current == nil {
		return cause
	}
	wanted, e := linkJSON(pending)
	if e != nil {
		return e
	}
	actual, e := linkJSON(current)
	if e != nil {
		return e
	}
	if string(actual) != string(wanted) {
		failure.Details.Next = append(failure.Details.Next, "the pending rotation changed; resume the retained transition")
		return failure
	}
	if _, e = tx.ExecContext(finish, `DELETE FROM network_statements WHERE network_id=? AND kind=?`, network, kindPendingRotation); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	failure.Details.Next = append(failure.Details.Next, "the rejected rotation was discarded; sync the network before starting another rotation")
	return failure
}
