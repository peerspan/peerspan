package coord

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type savedMemberEvidence struct {
	kind   string
	object map[string]json.RawMessage
	body   []byte
}

func savedMemberScalar(o map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(o[k], &s)
	return s
}

func savedMemberPayload(o map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	b, e := savedBase64(savedMemberScalar(o, "payload_base64"), 1<<20)
	if e != nil {
		return nil, e
	}
	var out map[string]json.RawMessage
	e = json.Unmarshal(b, &out)
	return out, e
}

// Saved outcomes retain proof references as they were committed. Resolve exact
// original bytes and their subjects without reinterpreting today's authority.
func savedMemberCatalog(c linkCatalog) (map[string]savedMemberEvidence, map[string]bool, error) {
	proofs := map[string]savedMemberEvidence{}
	payload := savedMemberPayload
	var index func(string, []byte) error
	index = func(kind string, body []byte) error {
		p := linkProofOf(kind, body)
		if _, ok := proofs[p.ID]; ok {
			return nil
		}
		var o map[string]json.RawMessage
		if json.Unmarshal(body, &o) != nil {
			return fmt.Errorf("invalid saved member evidence")
		}
		proofs[p.ID] = savedMemberEvidence{kind, o, body}
		if kind != "activation" {
			return nil
		}
		for _, part := range []string{"commit", "administrator"} {
			if string(o[part]) == `"-"` {
				continue
			}
			var packet map[string]json.RawMessage
			if json.Unmarshal(o[part], &packet) != nil {
				return fmt.Errorf("invalid saved activation packet")
			}
			fields, e := payload(packet)
			if e != nil {
				return e
			}
			name := "binding_record"
			if part == "administrator" {
				name = "admission_record"
			}
			raw := fields[name]
			if len(raw) == 0 || string(raw) == `"-"` {
				continue
			}
			var record map[string]json.RawMessage
			if json.Unmarshal(raw, &record) != nil {
				return fmt.Errorf("invalid saved activation record")
			}
			nestedKind := "root_record"
			if _, ok := record["person_public_key"]; ok {
				nestedKind = "person_record"
			}
			if e = index(nestedKind, raw); e != nil {
				return e
			}
		}
		return nil
	}
	roster := map[string]bool{}
	for _, p := range c.Objects {
		body, e := base64.StdEncoding.Strict().DecodeString(p.BodyBase64)
		if e != nil {
			return nil, nil, e
		}
		if e = index(p.Kind, body); e != nil {
			return nil, nil, e
		}
		if p.Kind == "feature" {
			var f linkFeatureView
			var proposal struct {
				Hosts []string `json:"host_public_keys"`
			}
			if json.Unmarshal(body, &f) != nil || json.Unmarshal(f.Proposal, &proposal) != nil {
				return nil, nil, fmt.Errorf("invalid saved feature roster")
			}
			for _, h := range proposal.Hosts {
				roster[h] = true
			}

		}
	}
	return proofs, roster, nil
}

func savedRegistrationMembers(c linkCatalog, featureID string) (map[string]linkMapMember, error) {
	proofs, roster, e := savedMemberCatalog(c)
	if e != nil {
		return nil, e
	}
	scalar, payload := savedMemberScalar, savedMemberPayload
	members := map[string]linkMapMember{}
	joins := map[string]string{}
	ids := make([]string, 0, len(proofs))
	for id := range proofs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		proof := proofs[id]
		o := proof.object
		host := ""
		switch proof.kind {
		case "host_membership", "host_admission", "attestation":
			if scalar(o, "network_id") == c.NetworkID {
				host = scalar(o, "host_public_key")
			}
		case "person_record", "root_record":
			if scalar(o, "kind") == "peerspan-host-admit-v1" && scalar(o, "network_id") == c.NetworkID {
				value, err := payload(o)
				if err != nil {
					return nil, err
				}
				host = scalar(value, "host_public_key")
			}
		case "invite_redemption":
			if scalar(o, "mode") != "person" {
				host = scalar(o, "host_public_key")
			}
		case "join_ack":
			public := scalar(o, "host_public_key")
			if scalar(o, "feature_id") == featureID {
				if _, err := linking.Read("feature_ack", proof.body, public, "-"); err != nil {
					return nil, err
				}
				if joins[public] == "" {
					joins[public] = id
				}
			}
		case "activation":
			var request map[string]json.RawMessage
			if json.Unmarshal(o["request"], &request) != nil {
				return nil, fmt.Errorf("invalid saved activation request")
			}
			value, err := payload(request)
			if err != nil {
				return nil, err
			}
			public := scalar(value, "host_public_key")
			if joins[public] == "" {
				joins[public] = id
			}
		}
		if host == "" {
			continue
		}
		public, err := membership.DecodeKey(host)
		if err != nil {
			return nil, err
		}
		if _, ok := members[membership.HostID(public)]; !ok {
			members[membership.HostID(public)] = linkMapMember{HostID: membership.HostID(public), HostPublicKey: host, MembershipProofID: id, BindingProofID: "-"}
		}
	}
	for hostID, row := range members {
		row.JoinProofID = joins[row.HostPublicKey]
		if roster[row.HostPublicKey] {
			row.JoinProofID = "-"
		}
		members[hostID] = row
	}
	return members, nil
}

// A committed admission can outlive its issuer's current role. Its original
// administrator delegation must still be independently verifiable in this
// snapshot, even when no saved operation happens to reference that delegation.
func savedMemberAdministrators(n linkNetwork, proofs map[string]savedMemberEvidence) (map[string]bool, error) {
	genesis, err := membership.DecodeKey(n.GenesisRootPublicKey)
	if err != nil || membership.NetworkID(genesis) != n.NetworkID {
		return nil, fmt.Errorf("invalid saved membership root")
	}
	byEpoch := map[int64]membership.Rotation{}
	for _, p := range proofs {
		if p.kind == "rotation" {
			var rotation membership.Rotation
			if err = json.Unmarshal(p.body, &rotation); err != nil {
				return nil, err
			}
			if old, ok := byEpoch[rotation.Epoch]; ok && old != rotation {
				return nil, fmt.Errorf("conflicting saved membership rotations")
			}
			byEpoch[rotation.Epoch] = rotation
		}
	}
	rotations := make([]membership.Rotation, 0, len(byEpoch))
	for _, rotation := range byEpoch {
		rotations = append(rotations, rotation)
	}
	sort.Slice(rotations, func(i, j int) bool { return rotations[i].Epoch < rotations[j].Epoch })
	chain, err := membership.VerifyChain(genesis, rotations)
	if err != nil {
		return nil, err
	}
	administrators := map[string]bool{}
	for _, p := range proofs {
		if p.kind != "admin_delegation" {
			continue
		}
		var delegation membership.AdminDelegation
		if err = json.Unmarshal(p.body, &delegation); err != nil {
			return nil, err
		}
		person, err := chain.VerifyDelegation(delegation)
		if err != nil {
			return nil, err
		}
		administrators[person] = true
	}
	return administrators, nil
}

func savedMapMembers(m linkMap, featureID string) error {
	proofs, roster, e := savedMemberCatalog(m.Catalog)
	if e != nil {
		return e
	}
	administrators, e := savedMemberAdministrators(m.Network, proofs)
	if e != nil {
		return e
	}
	scalar, payload := savedMemberScalar, savedMemberPayload
	previous := ""
	for _, member := range m.Members {
		key, e := membership.DecodeKey(member.HostPublicKey)
		if e != nil || membership.HostID(key) != member.HostID || member.HostID <= previous {
			return fmt.Errorf("invalid saved member identity/order")
		}
		previous = member.HostID
		membershipProof, ok := proofs[member.MembershipProofID]
		if !ok {
			return fmt.Errorf("saved member lacks membership proof")
		}
		o := membershipProof.object
		switch membershipProof.kind {
		case "host_admission", "host_membership", "attestation":
			if scalar(o, "host_public_key") != member.HostPublicKey || scalar(o, "network_id") != m.Network.NetworkID {
				return fmt.Errorf("saved membership subject mismatch")
			}
		case "invite_redemption":
			if scalar(o, "host_public_key") != member.HostPublicKey || scalar(o, "mode") == "person" {
				return fmt.Errorf("saved redemption member mismatch")
			}
			var invite map[string]json.RawMessage
			if json.Unmarshal(o["host_invite"], &invite) != nil || scalar(invite, "network_id") != m.Network.NetworkID {
				return fmt.Errorf("saved redemption invite network mismatch")
			}
		case "person_record", "root_record":
			value, e := payload(o)
			if e != nil {
				return e
			}
			if scalar(o, "kind") != "peerspan-host-admit-v1" || scalar(o, "network_id") != m.Network.NetworkID || scalar(value, "host_public_key") != member.HostPublicKey || scalar(value, "network_id") != m.Network.NetworkID {
				return fmt.Errorf("saved admission reference mismatch")
			}
			if membershipProof.kind == "person_record" && !administrators[scalar(o, "person_public_key")] {
				return fmt.Errorf("saved admission lacks historical administrator delegation")
			}
		default:
			return fmt.Errorf("invalid saved membership proof kind")
		}
		if member.BindingProofID != "-" {
			binding, ok := proofs[member.BindingProofID]
			if !ok {
				return fmt.Errorf("saved member lacks binding proof")
			}
			o := binding.object
			if binding.kind == "person_record" {
				if scalar(o, "kind") != "peerspan-host-bind-v1" || scalar(o, "network_id") != m.Network.NetworkID {
					return fmt.Errorf("invalid saved binding kind")
				}
				o, e = payload(o)
				if e != nil {
					return e
				}
			} else if binding.kind != "host_binding" {
				return fmt.Errorf("invalid saved binding proof kind")
			}
			if scalar(o, "host_public_key") != member.HostPublicKey || scalar(o, "network_id") != m.Network.NetworkID {
				return fmt.Errorf("saved binding subject mismatch")
			}
		}
		if member.JoinProofID == "-" {
			if !roster[member.HostPublicKey] {
				return fmt.Errorf("saved member lacks feature participation")
			}
			continue
		}
		join, ok := proofs[member.JoinProofID]
		if !ok {
			return fmt.Errorf("saved member lacks join proof")
		}
		switch join.kind {
		case "join_ack":
			if scalar(join.object, "host_public_key") != member.HostPublicKey || scalar(join.object, "feature_id") != featureID {
				return fmt.Errorf("saved feature acknowledgment mismatch")
			}
		case "activation":
			var request map[string]json.RawMessage
			if json.Unmarshal(join.object["request"], &request) != nil {
				return fmt.Errorf("invalid saved activation request")
			}
			value, e := payload(request)
			if e != nil {
				return e
			}
			var owner map[string]json.RawMessage
			if json.Unmarshal(join.object["owner"], &owner) != nil {
				return fmt.Errorf("invalid saved activation owner")
			}
			bound, e := payload(owner)
			if e != nil {
				return e
			}
			var network linkNetwork
			if json.Unmarshal(bound["network"], &network) != nil || network.NetworkID != m.Network.NetworkID || scalar(bound, "feature_id") != featureID || scalar(value, "host_public_key") != member.HostPublicKey {
				return fmt.Errorf("saved activation member mismatch")
			}
		default:
			return fmt.Errorf("invalid saved join proof kind")
		}
	}
	return nil
}
