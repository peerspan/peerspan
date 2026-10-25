package host

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

const AuthorizedInvitePrefix = "peerspan-authorized-invite-v1."
const FeatureInvitePrefix = "peerspan-feature-invite-v1."

type authorizedInviteToken struct {
	Format       uint64          `json:"format"`
	Network      json.RawMessage `json:"network"`
	Mode         string          `json:"mode"`
	InviteSeed   string          `json:"invite_seed"`
	HostInvite   json.RawMessage `json:"host_invite"`
	PersonInvite json.RawMessage `json:"person_invite"`
	Catalog      json.RawMessage `json:"catalog"`
}
type featureInviteToken struct {
	Format             uint64          `json:"format"`
	Network            json.RawMessage `json:"network"`
	Token              string          `json:"token"`
	Mode               string          `json:"mode"`
	HostInviteBase64   string          `json:"host_invite_base64"`
	PersonInviteBase64 string          `json:"person_invite_base64"`
	FeatureBinding     json.RawMessage `json:"feature_binding"`
	Catalog            json.RawMessage `json:"catalog"`
}
type linkDecodedInvite struct {
	Network                                             Network
	Mode, Member, ExpiresAt, InvitePublicKey, FeatureID string
	Key                                                 ed25519.PrivateKey
	HostInvite, PersonInvite, Catalog                   []byte
}

func decodeLinkToken(value, prefix string) ([]byte, error) {
	encoded, ok := strings.CutPrefix(value, prefix)
	if !ok || len(encoded) > 32<<20 {
		return nil, linkFail("invalid", "-", "invite")
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, linkFail("invalid", "-", "invite")
	}
	return raw, nil
}
func inviteNetwork(raw []byte) (Network, error) {
	var descriptor linkDescriptor
	if linking.DecodeMutation(raw, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &descriptor) != nil || !membership.ValidLabel(descriptor.Name) || !membership.ValidCoordinatorAddress(descriptor.CoordinatorAddress) || !linkPublicKey(descriptor.CoordinatorPublicKey) {
		return Network{}, linkFail("invalid", "-", "invite")
	}
	root, e := membership.DecodeKey(descriptor.GenesisRootPublicKey)
	if e != nil || membership.NetworkID(root) != descriptor.NetworkID {
		return Network{}, linkFail("invalid", "-", "invite")
	}
	return Network{ID: descriptor.NetworkID, Name: descriptor.Name, RootPublicKey: descriptor.GenesisRootPublicKey, CurrentRootPublicKey: descriptor.GenesisRootPublicKey, CoordinatorAddress: descriptor.CoordinatorAddress, CoordinatorPublicKey: descriptor.CoordinatorPublicKey}, nil
}
func decodeInnerLinkInvite(value string, now time.Time) (linkDecodedInvite, error) {
	bad := func() (linkDecodedInvite, error) { return linkDecodedInvite{}, linkFail("invalid", "-", "invite") }
	var result linkDecodedInvite
	if strings.HasPrefix(value, AuthorizedInvitePrefix) {
		raw, e := decodeLinkToken(value, AuthorizedInvitePrefix)
		if e != nil {
			return result, e
		}
		var token authorizedInviteToken
		if linking.DecodeStoredJSON(raw, "format network mode invite_seed host_invite person_invite catalog", &token) != nil || token.Format != 1 || token.Mode != "host" && token.Mode != "person" && token.Mode != "member" {
			return bad()
		}
		result.Network, e = inviteNetwork(token.Network)
		if e != nil {
			return result, e
		}
		result.Mode, result.Catalog = token.Mode, token.Catalog
		result.Key, e = membership.DecodeSeed(token.InviteSeed)
		if e != nil {
			return bad()
		}
		for i, half := range []json.RawMessage{token.HostInvite, token.PersonInvite} {
			needed := i == 0 && token.Mode != "person" || i == 1 && token.Mode != "host"
			if needed == (string(half) == `"-"`) {
				return bad()
			}
			if !needed {
				continue
			}
			var record struct {
				Kind          string `json:"kind"`
				PayloadBase64 string `json:"payload_base64"`
			}
			if json.Unmarshal(half, &record) != nil || i == 0 && record.Kind != "peerspan-invite-v1" || i == 1 && record.Kind != "peerspan-person-invite-v1" {
				return bad()
			}
			payload, e := linkBytes(record.PayloadBase64, linking.MaxPayload)
			if e != nil {
				return result, e
			}
			var fields struct {
				NetworkID       string `json:"network_id"`
				InvitePublicKey string `json:"invite_public_key"`
				Member          string `json:"member"`
				ExpiresAt       string `json:"invite_expires_at"`
			}
			if json.Unmarshal(payload, &fields) != nil || fields.NetworkID != result.Network.ID || !membership.ValidLabel(fields.Member) {
				return bad()
			}
			if result.InvitePublicKey != "" && (result.InvitePublicKey != fields.InvitePublicKey || result.Member != fields.Member || result.ExpiresAt != fields.ExpiresAt) {
				return bad()
			}
			result.InvitePublicKey, result.Member, result.ExpiresAt = fields.InvitePublicKey, fields.Member, fields.ExpiresAt
			if i == 0 {
				result.HostInvite = half
			} else {
				result.PersonInvite = half
			}
		}
		if membership.PublicKey(result.Key) != result.InvitePublicKey {
			return bad()
		}
		if _, e = decodeLinkCatalog(result.Catalog, result.Network.ID); e != nil {
			return result, e
		}
	} else {
		var hostToken membership.Token
		var personToken *membership.PersonToken
		var e error
		switch {
		case strings.HasPrefix(value, membership.MemberTokenPrefix):
			token, err := membership.DecodeMemberToken(value, now)
			e = err
			hostToken = token.Token
			part := token.PersonToken()
			personToken = &part
			result.Mode = "member"
		case strings.HasPrefix(value, membership.PersonTokenPrefix):
			token, err := membership.DecodePersonToken(value, now)
			e = err
			hostToken = token.Token
			personToken = &token
			result.Mode = "person"
		default:
			hostToken, e = membership.DecodeToken(value, now)
			result.Mode = "host"
		}
		if e != nil {
			return result, e
		}
		result.Network = Network{ID: hostToken.NetworkID, Name: hostToken.NetworkName, CoordinatorAddress: hostToken.CoordinatorAddress, CoordinatorPublicKey: hostToken.CoordinatorPublicKey}
		result.Member, result.ExpiresAt, result.InvitePublicKey = hostToken.Member, hostToken.InviteExpiresAt, hostToken.InvitePublicKey
		result.Key, e = membership.DecodeSeed(hostToken.InviteSeed)
		if e != nil {
			return bad()
		}
		if result.Mode != "person" {
			result.HostInvite, e = linkJSON(map[string]any{"network_id": hostToken.NetworkID, "invite_public_key": hostToken.InvitePublicKey, "member": hostToken.Member, "invite_expires_at": hostToken.InviteExpiresAt, "signature": hostToken.InviteSignature})
			if e != nil {
				return result, e
			}
		}
		if personToken != nil {
			result.PersonInvite, e = linkJSON(map[string]any{"network_id": personToken.NetworkID, "invite_epoch": personToken.InviteEpoch, "invite_public_key": personToken.InvitePublicKey, "member": personToken.Member, "invite_expires_at": personToken.InviteExpiresAt, "signature": personToken.InviteSignature})
			if e != nil {
				return result, e
			}
		}
	}
	expires, e := membership.ParseTime(result.ExpiresAt)
	if e != nil || !now.Before(expires) {
		return result, linkFail("expired", "-", "invite")
	}
	return result, nil
}

// NewAuthorizedInvite preserves the exact public envelopes and owns only the
// one-time invitation seed. Device seeds are never included in bearer tokens.
func NewAuthorizedInvite(n Network, mode, seed string, hostInvite, personInvite, catalog []byte) (string, error) {
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return "", e
	}
	host, person := json.RawMessage(`"-"`), json.RawMessage(`"-"`)
	if len(hostInvite) > 0 {
		host = hostInvite
	}
	if len(personInvite) > 0 {
		person = personInvite
	}
	raw, e := linkJSON(authorizedInviteToken{1, descriptor, mode, seed, host, person, catalog})
	if e != nil {
		return "", e
	}
	return AuthorizedInvitePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// InviteFeatureIntent constructs only the fixed typed binding after validating
// the current catalog and inner invitation. Original keys remain CLI-side.
func InviteFeatureIntent(n Network, catalog []byte, inner, issuerKind, person, certificate, signer string, now time.Time) ([]byte, linking.InviteFeatureEvidence, error) {
	invite, e := decodeInnerLinkInvite(inner, now)
	if e != nil {
		return nil, linking.InviteFeatureEvidence{}, e
	}
	if invite.Network.ID != n.ID || invite.Network.Name != n.Name || invite.Network.CoordinatorAddress != n.CoordinatorAddress || invite.Network.CoordinatorPublicKey != n.CoordinatorPublicKey {
		return nil, linking.InviteFeatureEvidence{}, linkFail("invalid", "-", "invite")
	}
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return nil, linking.InviteFeatureEvidence{}, e
	}
	objects, e := decodeLinkCatalog(catalog, n.ID)
	if e != nil {
		return nil, linking.InviteFeatureEvidence{}, e
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return nil, linking.InviteFeatureEvidence{}, e
	}
	state, e := linking.VerifyStoredNetworkState(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: "-", Now: now}, catalog)
	if e != nil {
		return nil, linking.InviteFeatureEvidence{}, e
	}
	fields := map[string]any{"format": 1, "network_id": n.ID, "network_name": n.Name, "genesis_root_public_key": n.RootPublicKey, "epoch": epoch, "feature_id": state.Facts.FeatureID, "coordinator_address": n.CoordinatorAddress, "coordinator_public_key": n.CoordinatorPublicKey, "mode": invite.Mode, "host_invite_sha256": "-", "person_invite_sha256": "-", "issuer_kind": issuerKind, "person_public_key": person, "certificate_id": certificate, "signer_public_key": signer, "issued_at": linkTime(now), "expires_at": invite.ExpiresAt, "host_invite_base64": "-", "person_invite_base64": "-"}
	if len(invite.HostInvite) > 0 {
		fields["host_invite_sha256"], fields["host_invite_base64"] = linkHash(invite.HostInvite), base64.StdEncoding.EncodeToString(invite.HostInvite)
	}
	if len(invite.PersonInvite) > 0 {
		fields["person_invite_sha256"], fields["person_invite_base64"] = linkHash(invite.PersonInvite), base64.StdEncoding.EncodeToString(invite.PersonInvite)
	}
	unsigned, e := linkJSON(fields)
	if e != nil {
		return nil, linking.InviteFeatureEvidence{}, e
	}
	evidence, e := linking.VerifyStoredInviteFeatureIntent(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: state.Facts.FeatureID, Now: now}, catalog, unsigned)
	return unsigned, evidence, e
}

func WrapFeatureInvite(n Network, inner string, catalog, unsigned []byte, signature string, now time.Time) (string, error) {
	invite, e := decodeInnerLinkInvite(inner, now)
	if e != nil {
		return "", e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(unsigned, &fields) != nil {
		return "", linkFail("invalid", "-", "invite_feature")
	}
	for name, expected := range map[string][]byte{"host_invite_base64": invite.HostInvite, "person_invite_base64": invite.PersonInvite} {
		var encoded string
		if json.Unmarshal(fields[name], &encoded) != nil {
			return "", linkFail("invalid", "-", "invite_feature")
		}
		want := "-"
		if len(expected) > 0 {
			want = base64.StdEncoding.EncodeToString(expected)
		}
		if encoded != want {
			return "", linkFail("invalid", "-", "invite_feature")
		}
		delete(fields, name)
	}
	fields["signature"], _ = json.Marshal(signature)
	binding, e := linkJSON(fields)
	if e != nil {
		return "", e
	}
	return EncodeFeatureInvite(n, inner, catalog, binding, now)
}
func EncodeFeatureInvite(n Network, inner string, catalog, binding []byte, now time.Time) (string, error) {
	invite, e := decodeInnerLinkInvite(inner, now)
	if e != nil {
		return "", e
	}
	if invite.Network.ID != n.ID || invite.Network.Name != n.Name || invite.Network.CoordinatorAddress != n.CoordinatorAddress || invite.Network.CoordinatorPublicKey != n.CoordinatorPublicKey {
		return "", linkFail("invalid", "-", "invite")
	}
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return "", e
	}
	objects, e := decodeLinkCatalog(catalog, n.ID)
	if e != nil {
		return "", e
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return "", e
	}
	evidence, e := linking.VerifyStoredInviteFeature(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: "-", Now: now}, catalog, binding, invite.HostInvite, invite.PersonInvite)
	if e != nil {
		return "", e
	}
	host, person := "-", "-"
	if len(invite.HostInvite) > 0 {
		host = base64.StdEncoding.EncodeToString(invite.HostInvite)
	}
	if len(invite.PersonInvite) > 0 {
		person = base64.StdEncoding.EncodeToString(invite.PersonInvite)
	}
	seed, e := linkJSON(map[string]any{"binding": json.RawMessage(binding), "host_invite_base64": host, "person_invite_base64": person})
	if e != nil {
		return "", e
	}
	catalog, e = linking.SelectStoredProofCatalog(linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: evidence.FeatureID, Now: now}, catalog, []linking.ProofSeed{{Kind: "invite_feature", Body: seed}})
	if e != nil {
		return "", e
	}
	raw, e := linkJSON(featureInviteToken{1, descriptor, inner, invite.Mode, host, person, binding, catalog})
	if e != nil {
		return "", e
	}
	encoded := FeatureInvitePrefix + base64.RawURLEncoding.EncodeToString(raw)
	mutation, e := linkJSON(CreateInvite{Token: encoded})
	if e != nil {
		return "", e
	}
	if len(mutation) > 1<<20 {
		return "", linkFail("quota_exceeded", "-", "invite")
	}
	return encoded, nil
}
func decodeFeatureInvite(value string, now time.Time) (linkDecodedInvite, error) {
	raw, e := decodeLinkToken(value, FeatureInvitePrefix)
	if e != nil {
		return linkDecodedInvite{}, e
	}
	var token featureInviteToken
	if linking.DecodeStoredJSON(raw, "format network token mode host_invite_base64 person_invite_base64 feature_binding catalog", &token) != nil || token.Format != 1 {
		return linkDecodedInvite{}, linkFail("invalid", "-", "invite")
	}
	invite, e := decodeInnerLinkInvite(token.Token, now)
	if e != nil {
		return invite, e
	}
	n, e := inviteNetwork(token.Network)
	if e != nil {
		return invite, e
	}
	if invite.Network.ID != n.ID || invite.Network.Name != n.Name || invite.Network.CoordinatorAddress != n.CoordinatorAddress || invite.Network.CoordinatorPublicKey != n.CoordinatorPublicKey || invite.Mode != token.Mode {
		return invite, linkFail("invalid", "-", "invite")
	}
	for i, encoded := range []string{token.HostInviteBase64, token.PersonInviteBase64} {
		expected := invite.HostInvite
		if i == 1 {
			expected = invite.PersonInvite
		}
		want := "-"
		if len(expected) > 0 {
			want = base64.StdEncoding.EncodeToString(expected)
		}
		if encoded != want {
			return invite, linkFail("invalid", "-", "invite")
		}
	}
	objects, e := decodeLinkCatalog(token.Catalog, n.ID)
	if e != nil {
		return invite, e
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return invite, e
	}
	evidence, e := linking.VerifyStoredInviteFeature(linking.CatalogFactContext{Network: token.Network, Epoch: epoch, KnownFeatureID: "-", Now: now}, token.Catalog, token.FeatureBinding, invite.HostInvite, invite.PersonInvite)
	if e != nil {
		return invite, e
	}
	invite.Network, invite.FeatureID, invite.Catalog = n, evidence.FeatureID, token.Catalog
	return invite, nil
}

// InspectFeatureInvite validates the public typed wrapper for local CLI review.
// A zero clock requests only historical inspection at the binding's issued time;
// the actual writer always verifies again at its current clock before use.
func InspectFeatureInvite(value string, now time.Time) (membership.Token, error) {
	if now.IsZero() {
		raw, e := decodeLinkToken(value, FeatureInvitePrefix)
		if e != nil {
			return membership.Token{}, e
		}
		var outer featureInviteToken
		if linking.DecodeStoredJSON(raw, "format network token mode host_invite_base64 person_invite_base64 feature_binding catalog", &outer) != nil {
			return membership.Token{}, linkFail("invalid", "-", "invite")
		}
		var binding struct {
			IssuedAt string `json:"issued_at"`
		}
		if json.Unmarshal(outer.FeatureBinding, &binding) != nil {
			return membership.Token{}, linkFail("invalid", "-", "invite")
		}
		now, e = linkStamp(binding.IssuedAt)
		if e != nil {
			return membership.Token{}, e
		}
	}
	invite, e := decodeFeatureInvite(value, now)
	if e != nil {
		return membership.Token{}, e
	}
	return membership.Token{NetworkID: invite.Network.ID, NetworkName: invite.Network.Name, RootPublicKey: invite.Network.RootPublicKey, CoordinatorAddress: invite.Network.CoordinatorAddress, CoordinatorPublicKey: invite.Network.CoordinatorPublicKey, Member: invite.Member, InvitePublicKey: invite.InvitePublicKey, InviteExpiresAt: invite.ExpiresAt}, nil
}

// InspectCurrentFeatureInvite uses the same fixed runtime clock as the writer
// for CLI-side validation before persisting a newly selected person identity.
func InspectCurrentFeatureInvite(value string) (membership.Token, error) {
	now, e := linkNow()
	if e != nil {
		return membership.Token{}, e
	}
	return InspectFeatureInvite(value, now)
}
