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

// An unapplied exact outcome may lack a later checkpoint. Its independently
// pinned coordinator can supply public proof, never a replacement outcome.
func (s *Store) linkRedemptionRepair(ctx context.Context, target Network, feature string, receipt linkCatalog, original []byte, now time.Time) ([]byte, error) {
	if _, e := s.Network(ctx, target.ID); e == nil {
		return nil, nil
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	prior, e := readLinkCatalog(ctx, s.db, target.ID)
	if e != nil {
		return nil, e
	}
	union, e := mergeLinkCatalog(target.ID, prior, original)
	if e != nil {
		return nil, e
	}
	rows, e := decodeLinkCatalog(union, target.ID)
	if e != nil {
		return nil, e
	}
	epoch, e := linkCatalogEpoch(rows)
	if e != nil {
		return nil, e
	}
	descriptor, e := linkJSON(linkNetworkDescriptor(target))
	if e != nil {
		return nil, e
	}
	facts := linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: feature, Now: now}
	e = linking.VerifyStoredCatalogRepair(facts, prior, union)
	if e == nil {
		_, e = linking.VerifyStoredAccessState(linking.AccessContext{Network: descriptor, Epoch: epoch, KnownFeatureID: feature, Now: now}, union)
	}
	if e == nil {
		return nil, nil
	}
	var missing *linking.PathError
	if !errors.As(e, &missing) || missing.Code != "proof_required" {
		return nil, e
	}
	raw, e := s.linkCoordinator(ctx, target, http.MethodGet, "/coord/v2/networks/"+target.ID+"/map", nil)
	if e != nil {
		return nil, e
	}
	wire, e := decodeLinkMap(raw, target)
	if e != nil {
		return nil, e
	}
	repair, e := decodeLinkCatalog(wire.Catalog, target.ID)
	if e != nil {
		return nil, e
	}
	chain, e := linkChain(target, &linkProjection{Objects: receipt})
	if e != nil {
		return nil, e
	}
	root := ""
	for _, object := range receipt.Objects {
		if object.Kind != "feature" {
			continue
		}
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return nil, e
		}
		var frozen struct {
			Proposal struct {
				Epoch uint64 `json:"epoch"`
			} `json:"proposal"`
		}
		if json.Unmarshal(body, &frozen) != nil || frozen.Proposal.Epoch >= uint64(len(chain.Roots)) {
			return nil, linkFail("invalid", "-", "feature")
		}
		root = membership.EncodeKey(chain.Roots[frozen.Proposal.Epoch])
		read, e := linking.Read("feature", body, root, "-")
		if e != nil || read.ID != feature {
			return nil, linkFail("state_conflict", "-", "feature")
		}
		break
	}
	found := false
	for _, object := range repair.Objects {
		if object.Kind != "feature" {
			continue
		}
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return nil, e
		}
		read, e := linking.Read("feature", body, root, "-")
		if root == "" || e != nil || read.ID != feature {
			return nil, linkFail("state_conflict", "-", "feature")
		}
		found = true
	}
	if !found {
		return nil, linkFail("proof_required", "-", "feature", feature)
	}
	// The caller unions this untrusted catalog with the frozen receipt and
	// all local proof, then verifies NOW inside its atomic apply transaction.
	return wire.Catalog, nil
}
