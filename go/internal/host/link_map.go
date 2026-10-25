package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkDescriptor struct {
	NetworkID            string `json:"network_id"`
	Name                 string `json:"name"`
	GenesisRootPublicKey string `json:"genesis_root_public_key"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
}
type linkMapMember struct {
	HostID            string   `json:"host_id"`
	HostPublicKey     string   `json:"host_public_key"`
	MembershipProofID string   `json:"membership_proof_id"`
	BindingProofID    string   `json:"binding_proof_id"`
	JoinProofID       string   `json:"join_proof_id"`
	Address           string   `json:"address"`
	Candidates        []string `json:"candidates"`
	UpdatedAt         string   `json:"updated_at"`
}

func (m *linkMapMember) UnmarshalJSON(raw []byte) error {
	type plain linkMapMember
	return linking.DecodeStoredJSON(raw, "host_id host_public_key membership_proof_id binding_proof_id join_proof_id address candidates updated_at", (*plain)(m))
}

type linkNetworkMap struct {
	Format  uint64          `json:"format"`
	Network json.RawMessage `json:"network"`
	Catalog json.RawMessage `json:"catalog"`
	Members []linkMapMember `json:"members"`
}

func decodeLinkMap(raw []byte, n Network) (linkNetworkMap, error) {
	var result linkNetworkMap
	if len(raw) > 16<<20 || linking.DecodeStoredJSON(raw, "format network catalog members", &result) != nil || result.Format != 2 || result.Members == nil {
		return result, linkFail("invalid", "-", "map")
	}
	var descriptor linkDescriptor
	if linking.DecodeMutation(result.Network, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &descriptor) != nil || descriptor.NetworkID != n.ID || descriptor.Name != n.Name || descriptor.GenesisRootPublicKey != n.RootPublicKey || descriptor.CoordinatorAddress != n.CoordinatorAddress || descriptor.CoordinatorPublicKey != n.CoordinatorPublicKey {
		return result, linkFail("invalid", "-", "coordinator")
	}
	return result, nil
}
func linkChain(n Network, p *linkProjection) (membership.Chain, error) {
	genesis, e := genesisOf(n)
	if e != nil {
		return membership.Chain{}, e
	}
	rotations := []membership.Rotation{}
	byEpoch := map[int64]membership.Rotation{}
	for _, entry := range p.Objects.Objects {
		if entry.Kind == "rotation" {
			body, e := linkBytes(entry.BodyBase64, linking.MaxObject)
			if e != nil {
				return membership.Chain{}, e
			}
			var rotation membership.Rotation
			if json.Unmarshal(body, &rotation) != nil {
				return membership.Chain{}, linkFail("invalid", "-", "root")
			}
			if old, ok := byEpoch[rotation.Epoch]; ok && old != rotation {
				return membership.Chain{}, linkFail("state_conflict", "-", "root")
			}
			byEpoch[rotation.Epoch] = rotation
		}
	}
	for _, rotation := range byEpoch {
		rotations = append(rotations, rotation)
	}
	sort.Slice(rotations, func(i, j int) bool { return rotations[i].Epoch < rotations[j].Epoch })
	return membership.VerifyChain(genesis, rotations)
}
func (s *Store) verifyLinkMap(ctx context.Context, q dbQuerier, n Network, raw []byte, now time.Time, adoptions ...*linkFeatureAdoption) (*linkProjection, []NetworkMember, error) {
	wire, e := decodeLinkMap(raw, n)
	if e != nil {
		return nil, nil, e
	}
	remote, e := decodeLinkCatalog(wire.Catalog, n.ID)
	if e != nil {
		return nil, nil, e
	}
	prior, e := readLinkCatalog(ctx, q, n.ID)
	if e != nil {
		return nil, nil, e
	}
	old, e := decodeLinkCatalog(prior, n.ID)
	if e != nil {
		return nil, nil, e
	}
	seen := map[string]bool{}
	for _, entry := range remote.Objects {
		seen[entry.ID] = true
	}
	missing := []string{}
	for _, entry := range old.Objects {
		if !seen[entry.ID] {
			missing = append(missing, entry.ID)
		}
	}
	if len(missing) > 0 {
		return nil, nil, linkFail("proof_required", "-", "map", missing...)
	}
	catalog, e := mergeLinkCatalog(n.ID, prior, wire.Catalog)
	if e != nil {
		return nil, nil, e
	}
	known, _, e := readLinkFeature(ctx, q, n.ID)
	if e != nil {
		return nil, nil, e
	}
	if known == "-" && (len(adoptions) == 0 || adoptions[0] == nil) {
		adoption, e := verifyFirstLinkMapFeature(n, catalog, now)
		if e != nil {
			return nil, nil, e
		}
		adoptions = []*linkFeatureAdoption{adoption}
	}
	projection, e := s.verifyLinkProjection(ctx, q, n, catalog, now, adoptions...)
	if e != nil {
		return nil, nil, e
	}
	return s.verifiedLinkMapMembers(projection, wire)
}

// verifiedLinkMapMembers attaches only hints whose exact references match an
// independently verified projection at the caller's decision time.
func (s *Store) verifiedLinkMapMembers(projection *linkProjection, wire linkNetworkMap) (*linkProjection, []NetworkMember, error) {
	proofRows := map[string]linking.MemberProof{}
	for _, row := range projection.Network.Members {
		proofRows[row.HostPublicKey] = row
	}
	members := []NetworkMember{}
	memberIDs := map[string]bool{}
	previous := ""
	for _, hint := range wire.Members {
		if hint.HostID <= previous {
			return nil, nil, linkFail("invalid", "-", "map")
		}
		previous = hint.HostID
		proof, ok := proofRows[hint.HostPublicKey]
		public, e := membership.DecodeKey(hint.HostPublicKey)
		if !ok || e != nil || hint.HostID != membership.HostID(public) || hint.MembershipProofID != proof.MembershipProofID || hint.BindingProofID != proof.BindingProofID || hint.JoinProofID != proof.JoinProofID {
			continue
		}
		if _, e = parseTime(hint.UpdatedAt); e != nil {
			continue
		}
		member := NetworkMember{HostID: hint.HostID, PublicKey: hint.HostPublicKey, Member: proof.Member, Address: hint.Address, Candidates: membership.FilterCandidates(hint.Candidates), UpdatedAt: hint.UpdatedAt}
		if !membership.ValidAddress(member.Address) {
			member.Address = ""
		}
		if proof.PersonPublicKey != "-" {
			id, label := personIDOf(proof.PersonPublicKey), projection.Network.Facts.PersonLabels[proof.PersonPublicKey]
			member.PersonID, member.PersonMember = &id, &label
		}
		members = append(members, member)
		memberIDs[member.HostID] = true
	}
	if projection.Network.Facts.State.Hosts[s.identity.PublicKey] && !memberIDs[s.identity.ID] {
		return nil, nil, linkFail("proof_required", "-", "map")
	}
	return projection, members, nil
}
func (s *Store) applyLinkProjection(ctx context.Context, tx *sql.Tx, n *Network, p *linkProjection, members []NetworkMember, stamp string) error {
	if p.Network.Epoch > 4096 {
		return linkFail("invalid", "-", "root")
	}
	rootSSH, e := verifiedLinkRootSSH(p)
	if e != nil {
		return e
	}
	previousRoot := n.CurrentRootPublicKey
	if previousRoot == "" {
		previousRoot = n.RootPublicKey
	}
	rootSSH = rootSSH || n.RootSSH && n.RootEpoch == int64(p.Network.Epoch) && previousRoot == p.Network.RootPublicKey
	var ownedSeed []byte
	if e = tx.QueryRowContext(ctx, `SELECT root_seed FROM networks WHERE id=?`, n.ID).Scan(&ownedSeed); e != nil {
		return e
	}
	n.Administrator = ownedSeed != nil
	if ownedSeed != nil {
		if len(ownedSeed) != ed25519.SeedSize {
			return linkFail("state_conflict", "-", "root")
		}
		if membership.PublicKey(ed25519.NewKeyFromSeed(ownedSeed)) != p.Network.RootPublicKey {
			if _, e = tx.ExecContext(ctx, `UPDATE networks SET root_seed=NULL WHERE id=?`, n.ID); e != nil {
				return e
			}
			n.Administrator = false
		}
	}
	oldPolicies, _, e := readLinkHighWater(ctx, tx, n.ID)
	if e != nil {
		return e
	}
	if e := persistLinkProjection(ctx, tx, *n, p); e != nil {
		return e
	}
	// Retain actual legacy rotation/delegation bytes for unchanged root tooling.
	// Device-authorized payload projections never enter network_statements.
	for _, entry := range p.Objects.Objects {
		if entry.Kind != "rotation" && entry.Kind != "admin_delegation" {
			continue
		}
		body, e := linkBytes(entry.BodyBase64, linking.MaxObject)
		if e != nil {
			return e
		}
		var row struct {
			Epoch           uint64 `json:"epoch"`
			PersonPublicKey string `json:"person_public_key"`
		}
		if json.Unmarshal(body, &row) != nil {
			return linkFail("invalid", "-", "catalog")
		}
		kind, subject := kindRotation, strconv.FormatUint(row.Epoch, 10)
		if entry.Kind == "admin_delegation" {
			kind, subject = kindAdmin, row.PersonPublicKey
			var previous string
			e = tx.QueryRowContext(ctx, `SELECT record FROM network_statements WHERE network_id=? AND kind=? AND subject=?`, n.ID, kind, subject).Scan(&previous)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if e == nil {
				var old struct {
					Epoch uint64 `json:"epoch"`
				}
				if json.Unmarshal([]byte(previous), &old) != nil {
					return linkFail("state_conflict", "-", "storage")
				}
				if old.Epoch > row.Epoch {
					continue
				}
			}
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?,?,?,?) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record`, n.ID, kind, subject, string(body)); e != nil {
			return e
		}
	}
	n.RootEpoch, n.CurrentRootPublicKey, n.RootSSH = int64(p.Network.Epoch), p.Network.RootPublicKey, rootSSH
	if e = applyLinkTransport(ctx, tx, n, p); e != nil {
		return e
	}
	if e := s.replaceMembers(ctx, tx, n.ID, members, stamp); e != nil {
		return e
	}
	if e := s.queueLinkPolicies(ctx, tx, *n, p, members, oldPolicies, stamp); e != nil {
		return e
	}
	now, e := linkStamp(stamp)
	if e != nil {
		return e
	}
	for _, policy := range p.Policies {
		if e := s.editsChanged(ctx, tx, n.ID, policy, now); e != nil {
			return e
		}
	}
	if e := putJSON(ctx, tx, "UPDATE networks SET record = ? WHERE id = ?", *n, n.ID); e != nil {
		return e
	}
	return nil
}
func (s *Store) applyLinkMap(ctx context.Context, n Network, raw []byte, adoptions ...*linkFeatureAdoption) (Network, error) {
	return s.applyLinkMapWithHook(ctx, n, raw, nil, adoptions...)
}
func (s *Store) applyLinkMapWithHook(ctx context.Context, n Network, raw []byte, hook func(context.Context, *sql.Tx) error, adoptions ...*linkFeatureAdoption) (Network, error) {
	now, e := linkNow()
	if e != nil {
		return n, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return n, e
	}
	defer tx.Rollback()
	projection, members, e := s.verifyLinkMap(ctx, tx, n, raw, now, adoptions...)
	if e != nil {
		return n, e
	}
	stamp := linkTime(now)
	n.LastSyncAt, n.LastSyncError = &stamp, nil
	if e = s.applyLinkProjection(ctx, tx, &n, projection, members, linkTime(now)); e != nil {
		return n, e
	}
	if hook != nil {
		if e = hook(ctx, tx); e != nil {
			return n, e
		}
	}
	if e = tx.Commit(); e != nil {
		return n, e
	}
	s.mapApplied(n.ID, members)
	return n, nil
}
func (s *Store) fetchLinkMap(ctx context.Context, n Network, adoptions ...*linkFeatureAdoption) (Network, error) {
	raw, e := s.linkCoordinator(ctx, n, http.MethodGet, "/coord/v2/networks/"+n.ID+"/map", nil)
	if e != nil {
		return n, e
	}
	return s.applyLinkMap(ctx, n, raw, adoptions...)
}

func verifyFirstLinkMapFeature(n Network, raw []byte, now time.Time) (*linkFeatureAdoption, error) {
	catalog, e := decodeLinkCatalog(raw, n.ID)
	if e != nil {
		return nil, e
	}
	var feature []byte
	prior := linkCatalog{1, n.ID, []linkCatalogObject{}}
	for _, entry := range catalog.Objects {
		if entry.Kind == "feature" {
			if feature != nil {
				return nil, linkFail("state_conflict", "-", "feature")
			}
			feature, e = linkBytes(entry.BodyBase64, linking.MaxObject)
			if e != nil {
				return nil, e
			}
		} else {
			prior.Objects = append(prior.Objects, entry)
		}
	}
	if feature == nil {
		return nil, linkFail("proof_required", "-", "feature")
	}
	epoch, e := linkCatalogEpoch(catalog)
	if e != nil {
		return nil, e
	}
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return nil, e
	}
	before, e := linkJSON(prior)
	if e != nil {
		return nil, e
	}
	evidence, e := linking.VerifyStoredFeature(linking.FeatureContext{Network: descriptor, Epoch: epoch, KnownFeatureID: "-", Now: now}, before, feature)
	if e != nil {
		return nil, e
	}
	return &linkFeatureAdoption{evidence.FeatureID}, nil
}

// The caller serializes the fresh request and subsequent action with syncing.
func (s *Store) syncLinkNetworkLocked(ctx context.Context, n Network, candidates []string) (Network, error) {
	feature, _, e := readLinkFeature(ctx, s.db, n.ID)
	if e != nil {
		return n, e
	}
	if feature == "-" {
		return n, linkFail("upgrade_required", "-", "sync")
	}
	n, e = s.resumeLinkRestrictionsLocked(ctx, n)
	if e != nil {
		var remote *linkRestrictionTransportError
		if !errors.As(e, &remote) {
			return n, e
		}
		pending, err := loadPendingRotation(ctx, s.db, n.ID)
		if err != nil {
			return n, err
		}
		if pending != nil {
			failure := linkCause(e, "-", "restriction")
			failure.Details.Next = append(failure.Details.Next, "resume the pending root rotation before following a coordinator move")
			return n, failure
		}
		// Keep every marker. Independently verified transport following below
		// may reach a prepared target that can acknowledge the same proofs.
	}
	pending, e := loadPendingRotation(ctx, s.db, n.ID)
	if e != nil {
		return n, e
	}
	if pending != nil {
		rotated, e := s.completeLinkRotation(ctx, n, pending)
		if e != nil {
			return rotated, e
		}
		n = rotated
	}
	advertise, _ := s.coordinationConfig()
	body, e := linkJSON(map[string]any{"address": advertise, "candidates": candidates, "linking_version": 1})
	if e != nil {
		return n, e
	}
	now, e := linkNow()
	if e != nil {
		return n, e
	}
	return s.syncLinkFollowingLocked(ctx, n, body, now)
}
func projectedLinkMembers(p *linkProjection, existing []NetworkMember, now string) []NetworkMember {
	hints := map[string]NetworkMember{}
	for _, member := range existing {
		hints[member.PublicKey] = member
	}
	out := []NetworkMember{}
	for _, proof := range p.Network.Members {
		public, _ := membership.DecodeKey(proof.HostPublicKey)
		member := NetworkMember{HostID: membership.HostID(public), PublicKey: proof.HostPublicKey, Member: proof.Member, Candidates: []string{}, UpdatedAt: now}
		if old, ok := hints[proof.HostPublicKey]; ok {
			member.Address, member.Candidates, member.UpdatedAt = old.Address, old.Candidates, old.UpdatedAt
		}
		if proof.PersonPublicKey != "-" {
			id, label := personIDOf(proof.PersonPublicKey), p.Network.Facts.PersonLabels[proof.PersonPublicKey]
			member.PersonID, member.PersonMember = &id, &label
		}
		out = append(out, member)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out
}
