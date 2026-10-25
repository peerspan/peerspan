package host

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func (s *Store) wrapRootLinkInvite(ctx context.Context, n Network, inner string, key ed25519.PrivateKey) (string, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	now, e := linkNow()
	if e != nil {
		return "", e
	}
	p, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return "", e
	}
	if p == nil {
		return inner, nil
	}
	unsigned, evidence, e := InviteFeatureIntent(n, p.Catalog, inner, "network_root", "-", "-", membership.PublicKey(key), now)
	if e != nil {
		return "", e
	}
	return WrapFeatureInvite(n, inner, p.Catalog, unsigned, membership.EncodeKey(ed25519.Sign(key, evidence.Message)), now)
}
func (s *Store) recordFeatureInvite(ctx context.Context, network string, r CreateInvite) (Invite, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	now, e := linkNow()
	if e != nil {
		return Invite{}, e
	}
	invite, e := decodeFeatureInvite(r.Token, now)
	if e != nil {
		return Invite{}, e
	}
	n, e := s.Network(ctx, network)
	if e != nil {
		return Invite{}, e
	}
	if invite.Network.ID != n.ID || invite.Network.Name != n.Name || invite.Network.CoordinatorAddress != n.CoordinatorAddress || invite.Network.CoordinatorPublicKey != n.CoordinatorPublicKey {
		return Invite{}, linkFail("invalid", "-", "invite")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Invite{}, e
	}
	defer tx.Rollback()
	feature, _, e := readLinkFeature(ctx, tx, network)
	if e != nil {
		return Invite{}, e
	}
	if feature == "-" {
		return Invite{}, linkFail("upgrade_required", "-", "feature")
	}
	if feature != invite.FeatureID {
		return Invite{}, linkFail("state_conflict", "-", "feature")
	}
	prior, e := readLinkCatalog(ctx, tx, network)
	if e != nil {
		return Invite{}, e
	}
	union, e := mergeLinkCatalog(network, prior, invite.Catalog)
	if e != nil {
		return Invite{}, e
	}
	p, e := s.verifyLinkProjection(ctx, tx, n, union, now)
	if e != nil {
		return Invite{}, e
	}
	raw, e := decodeLinkToken(r.Token, FeatureInvitePrefix)
	if e != nil {
		return Invite{}, e
	}
	var outer featureInviteToken
	if json.Unmarshal(raw, &outer) != nil {
		return Invite{}, linkFail("invalid", "-", "invite")
	}
	if _, e = linking.VerifyStoredInviteFeature(linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: feature, Now: now}, union, outer.FeatureBinding, invite.HostInvite, invite.PersonInvite); e != nil {
		return Invite{}, e
	}
	if e = appendEvent(ctx, tx, "network.invite_issued", network, linkTime(now)); e != nil {
		return Invite{}, e
	}
	return Invite{NetworkID: network, Member: invite.Member, InvitePublicKey: invite.InvitePublicKey, InviteExpiresAt: invite.ExpiresAt, Token: r.Token}, tx.Commit()
}
func floorLinkInviteExpiry(value string) (string, error) {
	expires, e := membership.ParseTime(value)
	if e != nil {
		return "", linkFail("invalid", "-", "invite")
	}
	return expires.UTC().Truncate(time.Second).Format(time.RFC3339), nil
}
