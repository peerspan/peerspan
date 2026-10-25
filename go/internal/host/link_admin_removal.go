package host

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func (r *RemoveAdmin) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrInvalid
	}
	names := []string{}
	for name := range fields {
		if name != "person" && name != "revoke_admitted" && name != "removal" && name != "removal_base64" {
			return ErrInvalid
		}
		names = append(names, name)
	}
	if _, present := fields["removal_base64"]; present && len(fields) != 1 {
		return ErrInvalid
	}
	sort.Strings(names)
	type wire RemoveAdmin
	var decoded wire
	if linking.DecodeMutation(raw, strings.Join(names, " "), &decoded) != nil {
		return ErrInvalid
	}
	*r = RemoveAdmin(decoded)
	return nil
}

type LinkAdminRemovalPlan struct {
	Format          uint64   `json:"format"`
	PersonPublicKey string   `json:"person_public_key"`
	Kept            []string `json:"kept"`
}

func (s *Store) LinkAdminRemovalPlan(ctx context.Context, network, person string) (LinkAdminRemovalPlan, error) {
	g, e := s.loadGovernance(ctx, s.db, network)
	if e != nil {
		return LinkAdminRemovalPlan{}, e
	}
	if g.linking == nil {
		return LinkAdminRemovalPlan{}, linkFail("upgrade_required", "-", "feature")
	}
	key, e := g.resolveAny(person)
	if e != nil {
		return LinkAdminRemovalPlan{}, e
	}
	now, e := linkNow()
	if e != nil {
		return LinkAdminRemovalPlan{}, e
	}
	p := g.linking
	kept, e := linking.BuildStoredAdminRemovalPlan(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, key)
	return LinkAdminRemovalPlan{2, key, kept}, e
}
func SignAdminRemovalV2(signer membership.StatementSigner, network, person string, revoke bool, kept []string, at string) ([]byte, error) {
	if kept == nil {
		kept = []string{}
	}
	if !linkID(network, "net_") || !linkPublicKey(person) || revoke && len(kept) != 0 {
		return nil, ErrInvalid
	}
	if _, e := linkStamp(at); e != nil {
		return nil, ErrInvalid
	}
	previous := ""
	for _, tag := range kept {
		valid := strings.HasPrefix(tag, "legacy:") && linkID(strings.TrimPrefix(tag, "legacy:"), "") || strings.HasPrefix(tag, "record:") && linkID(strings.TrimPrefix(tag, "record:"), "ar_") || strings.HasPrefix(tag, "redemption:") && linkID(strings.TrimPrefix(tag, "redemption:"), "pf_")
		if !valid || tag <= previous {
			return nil, ErrInvalid
		}
		previous = tag
	}
	message := linkMessage(append([]string{"peerspan-admin-remove-v2", network, person, strconv.FormatBool(revoke), at, strconv.Itoa(len(kept))}, kept...)...)
	signature, e := signer.SignStatement(message)
	if e != nil {
		return nil, e
	}
	raw, e := linkJSON(map[string]any{"format": 2, "network_id": network, "person_public_key": person, "revoke_admitted": revoke, "removed_at": at, "kept": kept, "signature": signature})
	if e != nil {
		return nil, e
	}
	if _, e = linking.Read("admin_removal_v2", raw, membership.EncodeKey(signer.PublicKey()), "-"); e != nil {
		return nil, e
	}
	return raw, nil
}
func (s *Store) removeLinkAdmin(ctx context.Context, network string, r RemoveAdmin) (RevocationResult, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	if r.RemovalBase64 != "" && (r.Person != "" || r.Removal != nil || r.RevokeAdmitted) || r.RemovalBase64 == "" && ((r.Person == "") == (r.Removal == nil) || r.Removal != nil && r.RevokeAdmitted) {
		return RevocationResult{}, ErrInvalid
	}
	g, e := s.loadGovernance(ctx, s.db, network)
	if e != nil {
		return RevocationResult{}, e
	}
	now, e := linkNow()
	if e != nil {
		return RevocationResult{}, e
	}
	key := r.Person
	var record []byte
	if r.RemovalBase64 != "" {
		record, e = linkBytes(r.RemovalBase64, linking.MaxObject)
	} else if r.Removal != nil {
		record, e = linkJSON(r.Removal)
	} else {
		key, e = g.resolveAny(key)
	}
	if e != nil {
		return RevocationResult{}, e
	}
	if len(record) == 0 {
		// Generated retries retain the exact already-signed object, even after
		// a rotation or lost coordinator response. Only false->true may escalate.
		for _, entry := range g.linking.Objects.Objects {
			if entry.Kind != "admin_removal" {
				continue
			}
			body, e := linkBytes(entry.BodyBase64, linking.MaxObject)
			if e != nil {
				return RevocationResult{}, e
			}
			var previous struct {
				Person string `json:"person_public_key"`
				Revoke bool   `json:"revoke_admitted"`
			}
			if json.Unmarshal(body, &previous) != nil {
				return RevocationResult{}, ErrInvalid
			}
			if previous.Person == key && previous.Revoke && !r.RevokeAdmitted {
				return RevocationResult{}, linkFail("state_conflict", "-", "admin_removal")
			}
			if previous.Person == key && previous.Revoke == r.RevokeAdmitted {
				record = body
				break
			}
		}
		if len(record) == 0 {
			if _, ok := g.admins.Delegations[key]; !ok {
				return RevocationResult{}, ErrNotFound
			}
			_, root, e := s.administeredNetwork(ctx, s.db, network)
			if e != nil {
				return RevocationResult{}, e
			}
			kept := []string{}
			if !r.RevokeAdmitted {
				p := g.linking
				kept, e = linking.BuildStoredAdminRemovalPlan(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}, p.Catalog, key)
				if e != nil {
					return RevocationResult{}, e
				}
			}
			record, e = SignAdminRemovalV2(membership.RawSigner{Key: root}, network, key, r.RevokeAdmitted, kept, linkTime(now))
			if e != nil {
				return RevocationResult{}, e
			}
		}
	}
	var removal struct {
		Format  uint64 `json:"format"`
		Network string `json:"network_id"`
		Person  string `json:"person_public_key"`
	}
	if json.Unmarshal(record, &removal) != nil || removal.Network != network || !linkPublicKey(removal.Person) {
		return RevocationResult{}, ErrInvalid
	}
	if r.RemovalBase64 != "" && removal.Format != 2 {
		return RevocationResult{}, ErrInvalid
	}
	known := false
	for _, entry := range g.linking.Objects.Objects {
		if entry.ID == linkProofID("admin_removal", record) {
			known = true
		}
	}
	if !known {
		if removal.Format == 2 {
			if _, e = linking.Read("admin_removal_v2", record, g.chain.CurrentPublicKey(), "-"); e != nil {
				return RevocationResult{}, linkFail("forbidden", "-", "admin_removal")
			}
		} else if r.Removal == nil || g.chain.VerifyAdminRemoval(*r.Removal) != nil {
			return RevocationResult{}, linkFail("forbidden", "-", "admin_removal")
		}
	}
	result := RevocationResult{NetworkID: network, Kind: membership.KindAdmin, Subject: removal.Person}
	e = s.publishLinkLegacyLocked(ctx, g.network, "admin_removal", record)
	var publication *linkPublicationError
	if e != nil && !errors.As(e, &publication) {
		return result, e
	}
	result.Submitted = e == nil
	return result, nil
}
