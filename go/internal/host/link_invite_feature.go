package host

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func signLinkInviteFeature(p *linkProjection, provider linkDeviceProvider, unsigned []byte, now time.Time) (LinkActionResult, error) {
	ctx := linking.CatalogFactContext{Network: p.Descriptor, Epoch: p.Network.Epoch, KnownFeatureID: p.Network.Facts.FeatureID, Now: now}
	evidence, e := linking.VerifyStoredInviteFeatureIntent(ctx, p.Catalog, unsigned)
	if e != nil {
		return LinkActionResult{}, e
	}
	if evidence.IssuerKind != "person" || evidence.PersonPublicKey != provider.View.PersonPublicKey || evidence.CertificateID != provider.View.CertificateID || evidence.SignerPublicKey != provider.View.DevicePublicKey {
		return LinkActionResult{}, linkFail("forbidden", "-", "invite_feature")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(unsigned, &fields) != nil {
		return LinkActionResult{}, linkFail("invalid", "-", "invite_feature")
	}
	halves := [][]byte{nil, nil}
	seeds := []linking.ProofSeed{}
	for i, name := range []string{"host_invite_base64", "person_invite_base64"} {
		var encoded string
		if json.Unmarshal(fields[name], &encoded) != nil {
			return LinkActionResult{}, linkFail("invalid", "-", "invite_feature")
		}
		delete(fields, name)
		if encoded != "-" {
			halves[i], e = linkBytes(encoded, linking.MaxObject)
			if e != nil {
				return LinkActionResult{}, e
			}
			seeds = append(seeds, linking.ProofSeed{Kind: "person_record", Body: halves[i]})
		}
	}
	signature, e := membership.SignSSHSIG(membership.KeySigner{Key: provider.Key}, evidence.Message)
	if e != nil {
		return LinkActionResult{}, e
	}
	fields["signature"], _ = json.Marshal(signature)
	binding, e := linkJSON(fields)
	if e != nil {
		return LinkActionResult{}, e
	}
	if _, e = linking.VerifyStoredInviteFeature(ctx, p.Catalog, binding, halves[0], halves[1]); e != nil {
		return LinkActionResult{}, e
	}
	catalog, e := linking.SelectStoredProofCatalog(ctx, p.Catalog, seeds)
	if e != nil {
		return LinkActionResult{}, e
	}
	return LinkActionResult{RecordID: "-", ProofID: "-", RecordBase64: base64.StdEncoding.EncodeToString(binding), Catalog: catalog, Committed: false}, nil
}
