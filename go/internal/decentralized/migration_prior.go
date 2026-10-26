package decentralized

import (
	"bytes"
	"encoding/json"
)

type LegacyPrior struct {
	Format          uint64   `json:"format"`
	Descriptor      string   `json:"legacy_descriptor_base64"`
	Catalog         string   `json:"legacy_catalog_base64"`
	Feature         string   `json:"legacy_feature_id"`
	Epoch           uint64   `json:"legacy_epoch"`
	Root            string   `json:"legacy_root_public_key"`
	Source          string   `json:"source_state_base64"`
	ClockGuard      string   `json:"clock_guard"`
	Pending         []string `json:"pending_operation_ids"`
	Proposal        string   `json:"acknowledged_proposal_id"`
	Prepared        string   `json:"acknowledged_prepared_sha256"`
	Acknowledgment  string   `json:"acknowledgment_base64"`
	AdoptedContext  string   `json:"adopted_context_id"`
	AdoptedProposal string   `json:"adopted_proposal_id"`
}

func readLegacyPrior(d Descriptor, raw []byte) (*LegacyPrior, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte(`"-"`)) {
		return nil, nil
	}
	o, e := readObjectLimit(raw, "format legacy_descriptor_base64 legacy_catalog_base64 legacy_feature_id legacy_epoch legacy_root_public_key source_state_base64 clock_guard pending_operation_ids acknowledged_proposal_id acknowledged_prepared_sha256 acknowledgment_base64 adopted_context_id adopted_proposal_id", MaxProbe)
	if e != nil {
		return nil, e
	}
	var p LegacyPrior
	if version(o, 1) != nil || json.Unmarshal(raw, &p) != nil || !literalOrID(p.Feature, "lf_") || !key(p.Root) || !literalOrID(p.Proposal, "ds_") || !literalOrID(p.Prepared, "") || !literalOrID(p.AdoptedContext, "ctx_") || !literalOrID(p.AdoptedProposal, "ds_") {
		return nil, invalid()
	}
	if p.ClockGuard != "-" {
		if _, e = stamp(p.ClockGuard); e != nil {
			return nil, e
		}
	}
	if (p.AdoptedContext == "-") != (p.AdoptedProposal == "-") || (p.Proposal == "-") != (p.Prepared == "-") || (p.Proposal == "-") != (p.Acknowledgment == "-") {
		return nil, invalid()
	}
	pending, e := stringsOf(o, "pending_operation_ids")
	if e != nil || !sorted(pending) {
		return nil, invalid()
	}
	if len(pending) > MaxObjects {
		return nil, failure("quota_exceeded")
	}
	for _, id := range pending {
		if id == "" || id == "-" {
			return nil, invalid()
		}
	}
	for _, field := range []string{"legacy_descriptor_base64", "legacy_catalog_base64", "source_state_base64"} {
		if _, e = probeBytes(o, field, MaxCatalog); e != nil {
			return nil, e
		}
	}
	return &p, nil
}

func verifyLegacyApproval(d Descriptor, p *LegacyPrior, v *migrationValidation, host string, adoption bool) (bool, error) {
	m := v.migration
	if p.AdoptedContext != "-" && (p.AdoptedContext != d.ContextID || p.AdoptedProposal != m.Proposal.ID) || p.Proposal != "-" && (p.Proposal != m.Proposal.ID || p.Prepared != digest(m.PreparedCatalog)) {
		return false, failure("state_conflict")
	}
	legacy, e := decode(p.Descriptor, MaxObject)
	if e != nil {
		return false, e
	}
	catalog, e := decode(p.Catalog, MaxCatalog)
	if e != nil {
		return false, e
	}
	source, e := decode(p.Source, MaxPayload)
	if e != nil {
		return false, e
	}
	at, _ := stamp(stringField(m.Proposal.Object, "issued_at"))
	state, facts, e := verifyLegacySnapshot(d, legacy, catalog, source, p.Epoch, p.Feature, p.Root, at)
	if e != nil {
		return false, e
	}
	epoch, _ := num(m.Proposal.Object, "legacy_epoch")
	if p.Epoch != epoch || p.Root != stringField(m.Proposal.Object, "legacy_root_public_key") || p.Feature != stringField(m.Proposal.Object, "legacy_feature_id") {
		return false, failure("state_conflict")
	}
	if len(p.Pending) > 0 {
		return false, failure("state_conflict")
	}
	for _, member := range facts.Members {
		found := false
		for _, row := range v.roster {
			if row.Host == member.HostPublicKey && row.Person == member.PersonPublicKey && row.Member == member.Member {
				found = true
				break
			}
		}
		if !found {
			return false, failure("proof_required", member.MembershipProofID)
		}
	}
	for _, host := range state.Hosts {
		if !contains(v.state.Hosts, host) {
			return false, failure("proof_required")
		}
	}
	for _, floor := range state.Maxima {
		found := false
		for _, candidate := range v.state.Maxima {
			if candidate.Kind == floor.Kind && candidate.Subject == floor.Subject && candidate.Version >= floor.Version && (candidate.Version > floor.Version || floor.Hash == "-" || candidate.Hash == floor.Hash) {
				found = true
				break
			}
		}
		if !found {
			return false, failure("state_conflict")
		}
	}
	for _, restriction := range state.Restrictions {
		found := false
		for _, candidate := range v.state.Restrictions {
			if candidate == restriction {
				found = true
				break
			}
		}
		if !found {
			return false, failure("proof_required", restriction.ProofID)
		}
	}
	if p.Proposal == "-" || host == "-" {
		return false, nil
	}
	raw, e := decode(p.Acknowledgment, MaxObject)
	if e != nil {
		return false, e
	}
	ack, e := ReadStatement(d, raw)
	if e != nil {
		return false, e
	}
	if ack.Kind != "migration_ack" || stringField(ack.Object, "proposal_id") != m.Proposal.ID || stringField(ack.Object, "prepared_catalog_sha256") != digest(m.PreparedCatalog) {
		return false, failure("state_conflict")
	}
	if stringField(ack.Object, "host_public_key") != host {
		return false, failure("forbidden")
	}
	for _, public := range m.Acknowledgments {
		if bytes.Equal(public.Raw, raw) {
			return true, nil
		}
	}
	if adoption {
		return false, failure("forbidden")
	}
	return false, nil
}
