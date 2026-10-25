package host

import (
	"encoding/json"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// The projection has already verified every signature and completed activation.
// This records signature-format evidence only, never root signing authority.
func verifiedLinkRootSSH(p *linkProjection) (bool, error) {
	current := p.Network.RootPublicKey
	currentStatement := func(raw []byte) (bool, error) {
		var statement struct {
			Epoch     uint64 `json:"epoch"`
			Signature string `json:"signature"`
		}
		if json.Unmarshal(raw, &statement) != nil {
			return false, linkFail("state_conflict", "-", "root")
		}
		return statement.Epoch == p.Network.Epoch && membership.SignerOf(statement.Signature) == current, nil
	}
	for _, object := range p.Objects.Objects {
		switch object.Kind {
		case "attestation", "admin_delegation", "person_admission", "host_admission", "root_record", "feature", "activation":
		default:
			continue
		}
		body, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return false, e
		}
		if object.Kind == "feature" {
			var feature struct {
				Proposal json.RawMessage `json:"proposal"`
			}
			if json.Unmarshal(body, &feature) != nil {
				return false, linkFail("state_conflict", "-", "root")
			}
			body = feature.Proposal
		} else if object.Kind == "activation" {
			var activation struct {
				Administrator json.RawMessage `json:"administrator"`
			}
			if json.Unmarshal(body, &activation) != nil {
				return false, linkFail("state_conflict", "-", "root")
			}
			if linkAbsent(activation.Administrator) {
				continue
			}
			_, payload, e := decodeLinkPacket(activation.Administrator)
			if e != nil {
				return false, e
			}
			var offer struct {
				Admission json.RawMessage `json:"admission_record"`
			}
			if json.Unmarshal(payload, &offer) != nil {
				return false, linkFail("state_conflict", "-", "root")
			}
			var admission map[string]json.RawMessage
			if json.Unmarshal(offer.Admission, &admission) != nil {
				return false, linkFail("state_conflict", "-", "root")
			}
			if _, ordinary := admission["person_public_key"]; ordinary {
				continue
			}
			body = offer.Admission
		}
		if known, e := currentStatement(body); e != nil || known {
			return known, e
		}
	}
	for _, group := range p.Groups {
		if membership.SignerOf(group.Signature) == current {
			return true, nil
		}
	}
	return false, nil
}
