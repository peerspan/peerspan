package linking

import (
	"encoding/json"
	"sort"
	"strconv"
)

// MemberProof contains only independently verified authority references. A
// caller may attach untrusted reachability hints after matching these keys.
type MemberProof struct {
	HostPublicKey     string `json:"host_public_key"`
	Member            string `json:"member"`
	PersonPublicKey   string `json:"person_public_key"`
	MembershipProofID string `json:"membership_proof_id"`
	BindingProofID    string `json:"binding_proof_id"`
	JoinProofID       string `json:"join_proof_id"`
}
type NetworkState struct {
	Facts         CatalogFacts
	Members       []MemberProof
	Epoch         uint64
	RootPublicKey string
}

// VerifyStoredNetworkState materializes a complete durable network snapshot.
// Historical activation validity is separate from the resulting live paths.
func VerifyStoredNetworkState(ctx CatalogFactContext, catalog []byte) (NetworkState, error) {
	fail := func(err error) (NetworkState, error) { return NetworkState{}, err }
	if !verificationBudget(true, len(ctx.Network), len(catalog), 0) {
		return fail(pathError("invalid"))
	}
	v, err := newCatalogVerifierWithBudget(ctx.Network, ctx.Epoch, ctx.KnownFeatureID, ctx.Now, true)
	if err != nil {
		return fail(err)
	}
	if err = v.catalog(catalog); err != nil {
		return fail(err)
	}
	if err = v.bootstrap(true); err != nil {
		return fail(err)
	}
	requests := make([]string, 0, len(v.activations))
	for id := range v.activations {
		requests = append(requests, id)
	}
	sort.Strings(requests)
	for _, id := range requests {
		if _, err = v.activate(id, true, 0); err != nil {
			return fail(err)
		}
	}
	if err = v.revocations(); err != nil {
		return fail(err)
	}
	if err = v.verifyStoredObjects(); err != nil {
		return fail(err)
	}
	v.restrictState()
	memberships, bindings, joins := map[string]string{}, map[string]string{}, map[string]string{}
	roster := map[string]bool{}
	choose := func(m map[string]string, host, id string) {
		if old := m[host]; old == "" || id < old {
			m[host] = id
		}
	}
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		o := p.object
		switch p.kind {
		case "feature":
			proposal, _ := parse(o["proposal"])
			hosts, _ := stringsOf(proposal, "host_public_keys")
			for _, host := range hosts {
				roster[host] = true
			}
		case "join_ack":
			if scalar(o, "feature_id") == v.feature {
				choose(joins, scalar(o, "host_public_key"), id)
			}
		case "activation":
			request, _ := parse(o["request"])
			r, ok := v.done[scalar(request, "request_id")]
			if ok && r.FeatureID == v.feature {
				choose(joins, r.HostPublicKey, id)
			}
		case "host_admission":
			host, label := scalar(o, "host_public_key"), scalar(o, "member")
			epoch, _ := num(o, "epoch")
			m, sig := message("peerspan-host-admit-v1", v.net, strconv.FormatUint(epoch, 10), host, label, scalar(o, "admitted_at")), scalar(o, "signature")
			valid, verifyErr := v.legacyGrant(o, "epoch", m, sig)
			if verifyErr != nil {
				return fail(verifyErr)
			}
			if (valid || v.attested[host] == label && v.anyRootSignature(m, sig)) && v.hosts[host] == label {
				choose(memberships, host, id)
			}
		case "host_membership":
			valid, verifyErr := v.legacyMembership(p, false)
			if verifyErr != nil {
				return fail(verifyErr)
			}
			host := scalar(o, "host_public_key")
			if valid && scalar(o, "member") == v.hosts[host] {
				choose(memberships, host, id)
			}
		case "invite_redemption":
			if !v.redemptions[id] {
				continue
			}
			r, verifyErr := v.readRedemption(p)
			if verifyErr != nil {
				return fail(verifyErr)
			}
			for _, half := range r.halves {
				if !half.host {
					continue
				}
				valid, verifyErr := v.redemptionHalf(id, half)
				if verifyErr != nil {
					return fail(verifyErr)
				}
				host := scalar(o, "host_public_key")
				if valid && half.label == v.hosts[host] {
					choose(memberships, host, id)
				}
			}
		case "host_binding":
			host, person := scalar(o, "host_public_key"), scalar(o, "person_public_key")
			if v.state.Bindings[host] == person && !v.history.unbound[bindingPair{person, host}] {
				choose(bindings, host, id)
			}
		case "person_record", "root_record":
			if !v.activeRecords[id] {
				continue
			}
			_, payload, verifyErr := payload(o)
			if verifyErr != nil {
				return fail(verifyErr)
			}
			host := scalar(payload, "host_public_key")
			switch scalar(o, "kind") {
			case "peerspan-host-admit-v1":
				label := scalar(payload, "member")
				if p.kind == "root_record" {
					epoch, _ := num(o, "epoch")
					if epoch != v.epoch && v.attested[host] != label {
						continue
					}
				}
				if label == v.hosts[host] {
					choose(memberships, host, id)
				}
			case "peerspan-host-bind-v1":
				person := scalar(payload, "person_public_key")
				if v.state.Bindings[host] == person && !v.history.unbound[bindingPair{person, host}] {
					choose(bindings, host, id)
				}
			}
		}
	}
	// A current attestation is independently signed membership evidence. Prefer
	// an existing usable admission/invite proof when one exists.
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		if p.kind != "attestation" {
			continue
		}
		o := p.object
		host := scalar(o, "host_public_key")
		if memberships[host] == "" && epochIs(o, v.epoch) && scalar(o, "member") == v.hosts[host] {
			memberships[host] = id
		}
	}
	hosts := []string{}
	for host, admitted := range v.state.Hosts {
		if admitted {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	out := NetworkState{Facts: CatalogFacts{v.net, v.feature, v.state, v.persons, v.hosts}, Members: []MemberProof{}, Epoch: v.epoch, RootPublicKey: v.root}
	for _, host := range hosts {
		membershipID, joinID := memberships[host], joins[host]
		if roster[host] {
			joinID = "-"
		}
		if membershipID == "" || joinID == "" {
			return fail(pathError("proof_required"))
		}
		person, bindingID := v.state.Bindings[host], bindings[host]
		if person == "" || person == "-" {
			person, bindingID = "-", "-"
		} else if bindingID == "" {
			return fail(pathError("proof_required"))
		}
		out.Members = append(out.Members, MemberProof{host, v.hosts[host], person, membershipID, bindingID, joinID})
	}
	return out, nil
}

func (v *activationVerifier) verifyStoredObjects() error {
	for _, id := range v.orderedProofs() {
		p := v.proofs[id]
		o := p.object
		switch p.kind {
		case "certificate":
			cid, e := candidateCertificateID(o)
			if e != nil {
				return e
			}
			if _, e = v.structural(cid, scalar(o, "person_public_key")); e != nil {
				return e
			}
		case "checkpoint":
			person, issuer := scalar(o, "person_public_key"), scalar(o, "issuer_certificate_id")
			if scalar(o, "network_id") != v.net {
				return pathError("invalid")
			}
			signer := person
			if issuer != "root" {
				c, e := v.structural(issuer, person)
				if e != nil {
					return e
				}
				signer = c.device
			}
			if _, e := Read("checkpoint", p.body, signer, "-"); e != nil {
				return pathError("invalid")
			}
		case "person_record", "root_record":
			if scalar(o, "operation_id") == "-" {
				continue
			}
			signer, _, e := v.epochRoot(o, "epoch")
			if e != nil {
				return e
			}
			if p.kind == "person_record" {
				person, cert := scalar(o, "person_public_key"), scalar(o, "certificate_id")
				signer = person
				if cert != "root" {
					c, e := v.structural(cert, person)
					if e != nil {
						return e
					}
					signer = c.device
				}
			}
			if _, e = Read(p.kind, p.body, signer, "-"); e != nil {
				return pathError("invalid")
			}
			if !v.activeRecords[id] && !(v.projectHistory && v.inertRecords[id]) {
				operation := scalar(o, "operation_id")
				if _, ok := v.activations[operation]; !ok {
					return pathError("proof_required", operation)
				}
				return pathError("forbidden")
			}
		}
	}
	perPerson := map[string]int{}
	for _, body := range v.state.Certificates {
		var certificate struct {
			Person string `json:"person_public_key"`
		}
		if json.Unmarshal(body, &certificate) != nil || !key(certificate.Person) {
			return pathError("invalid")
		}
		perPerson[certificate.Person]++
		if perPerson[certificate.Person] > 4096 {
			return pathError("quota_exceeded")
		}
	}
	return nil
}
