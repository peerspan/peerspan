package decentralized

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

func hashString(s string) bool { return identifier(s, "") }
func (s *Statement) checkMigrationPayload(d Descriptor) ([]string, error) {
	p := s.Object
	switch s.Kind {
	case "migration_proposal":
		if fields(p, "proposal_nonce legacy_descriptor_base64 legacy_feature_id legacy_epoch legacy_root_public_key source_catalog_sha256 source_state_sha256 new_descriptor roster issued_at expires_at") != nil {
			return nil, invalid()
		}
		a, e := texts(p, "proposal_nonce", "legacy_descriptor_base64", "legacy_feature_id", "legacy_root_public_key", "source_catalog_sha256", "source_state_sha256", "issued_at", "expires_at")
		if e != nil {
			return nil, e
		}
		nonce, e := decode(a[0], 32)
		if e != nil {
			return nil, e
		}
		if len(nonce) != 32 || !literalOrID(a[2], "lf_") || !key(a[3]) || !hashString(a[4]) || !hashString(a[5]) {
			return nil, invalid()
		}
		legacy, e := decode(a[1], MaxObject)
		if e != nil {
			return nil, e
		}
		// The old descriptor retains its own complete strict reader and identity.
		ld, e := readObject(legacy, "network_id name genesis_root_public_key coordinator_address coordinator_public_key")
		if e != nil {
			return nil, e
		}
		if stringField(ld, "network_id") != d.NetworkID || stringField(ld, "name") != d.Name || stringField(ld, "genesis_root_public_key") != d.GenesisRootPublicKey || !key(stringField(ld, "coordinator_public_key")) || !membership.ValidCoordinatorAddress(stringField(ld, "coordinator_address")) {
			return nil, invalid()
		}
		nd, e := ReadDescriptor(p["new_descriptor"])
		if e != nil {
			return nil, e
		}
		if nd.ContextID != d.ContextID {
			return nil, invalid()
		}
		if _, e := num(p, "legacy_epoch"); e != nil {
			return nil, e
		}
		issued, e := stamp(a[6])
		if e != nil {
			return nil, e
		}
		expires, e := stamp(a[7])
		if e != nil || expires.Unix()-issued.Unix() != 86400 {
			return nil, invalid()
		}
		var roster []json.RawMessage
		if json.Unmarshal(p["roster"], &roster) != nil || roster == nil {
			return nil, invalid()
		}
		if len(roster) > MaxObjects {
			return nil, failure("quota_exceeded")
		}
		previous := ""
		for _, raw := range roster {
			o, e := readObject(raw, "host_public_key member person_public_key device_public_key scopes")
			if e != nil {
				return nil, e
			}
			a, e := texts(o, "host_public_key", "member", "person_public_key", "device_public_key")
			if e != nil || !key(a[0]) || a[0] <= previous || !membership.ValidLabel(a[1]) || !literalOrKey(a[2]) || !literalOrKey(a[3]) {
				return nil, invalid()
			}
			scopes, e := num(o, "scopes")
			if e != nil || a[2] == "-" && (a[3] != "-" || scopes != 0) || a[2] != "-" && (a[3] == "-" || scopes == 0 || scopes > 15) {
				return nil, invalid()
			}
			previous = a[0]
		}
		return []string{"issuer"}, nil
	case "migration_ack":
		if fields(p, "proposal_id root_state_id prepared_catalog_sha256 host_public_key person_public_key device_public_key host_lease_id binding_lease_id device_lease_id activation_id acknowledged_at") != nil {
			return nil, invalid()
		}
		a, e := texts(p, "proposal_id", "root_state_id", "prepared_catalog_sha256", "host_public_key", "person_public_key", "device_public_key", "host_lease_id", "binding_lease_id", "device_lease_id", "activation_id", "acknowledged_at")
		if e != nil {
			return nil, e
		}
		if !identifier(a[0], "ds_") || !identifier(a[1], "ds_") || !hashString(a[2]) || !key(a[3]) || !literalOrKey(a[4]) || !literalOrKey(a[5]) || !identifier(a[6], "ds_") || !literalOrID(a[7], "ds_") || !literalOrID(a[8], "ds_") || !literalOrID(a[9], "da_") {
			return nil, invalid()
		}
		if _, e = stamp(a[10]); e != nil {
			return nil, e
		}
		if a[4] == "-" {
			if a[5] != "-" || a[7] != "-" || a[8] != "-" || a[9] != "-" {
				return nil, invalid()
			}
			return []string{"host"}, nil
		}
		if a[5] == "-" || a[7] == "-" || a[8] == "-" || a[9] == "-" {
			return nil, invalid()
		}
		return []string{"device", "host"}, nil
	case "migration_commit":
		if fields(p, "proposal_id root_state_id prepared_catalog_sha256 acknowledgment_ids committed_at") != nil {
			return nil, invalid()
		}
		a, e := texts(p, "proposal_id", "root_state_id", "prepared_catalog_sha256", "committed_at")
		if e != nil || !identifier(a[0], "ds_") || !identifier(a[1], "ds_") || !hashString(a[2]) {
			return nil, invalid()
		}
		if _, e = stamp(a[3]); e != nil {
			return nil, e
		}
		if _, e = ids(p, "acknowledgment_ids", "ds_"); e != nil {
			return nil, e
		}
		return []string{"issuer"}, nil
	}
	return nil, invalid()
}

// ParsedMigration is structural evidence only. Current legacy provenance, every
// source-state/fence pin and adoption consent are checked by migration authority.
type ParsedMigration struct {
	Raw                                         []byte
	Proposal                                    *Statement
	Acknowledgments                             []*Statement
	Commit                                      *Statement
	SourceCatalog, SourceState, PreparedCatalog []byte
}

func readMigration(d Descriptor, raw []byte) (*ParsedMigration, error) {
	o, e := parse(raw)
	if e != nil {
		return nil, e
	}
	if fields(o, "format proposal source_catalog_base64 source_state_base64 prepared_catalog_base64 acknowledgments commit") != nil || version(o, 1) != nil {
		return nil, invalid()
	}
	proposal, e := ReadStatement(d, o["proposal"])
	if e != nil {
		return nil, e
	}
	if proposal.Kind != "migration_proposal" {
		return nil, invalid()
	}
	m := &ParsedMigration{Raw: append([]byte{}, raw...), Proposal: proposal, Acknowledgments: []*Statement{}}
	for _, f := range []struct {
		name string
		max  int
		dst  *[]byte
	}{{"source_catalog_base64", 512 << 10, &m.SourceCatalog}, {"source_state_base64", MaxPayload, &m.SourceState}, {"prepared_catalog_base64", MaxObject, &m.PreparedCatalog}} {
		str, e := text(o, f.name)
		if e != nil {
			return nil, e
		}
		*f.dst, e = decode(str, f.max)
		if e != nil {
			return nil, e
		}
	}
	// Old and prepared catalogs are complete strict structural catalogs; neither
	// is promoted to a prior. Prepared composites cannot recurse into migration.
	if _, e = parseLimit(m.SourceCatalog, 512<<10); e != nil {
		return nil, e
	}
	if _, e = readSourceState(d, m.SourceState); e != nil {
		return nil, e
	}
	if digest(m.SourceCatalog) != stringField(proposal.Object, "source_catalog_sha256") || digest(m.SourceState) != stringField(proposal.Object, "source_state_sha256") {
		return nil, invalid()
	}
	if _, e = readCatalog(d, m.PreparedCatalog, false); e != nil {
		return nil, e
	}
	var acks []json.RawMessage
	if json.Unmarshal(o["acknowledgments"], &acks) != nil || acks == nil {
		return nil, invalid()
	}
	if len(acks) > MaxObjects {
		return nil, failure("quota_exceeded")
	}
	last := ""
	for _, r := range acks {
		ack, e := ReadStatement(d, r)
		if e != nil {
			return nil, e
		}
		host := stringField(ack.Object, "host_public_key")
		if ack.Kind != "migration_ack" || host <= last || ack.Signer("host") != host || stringField(ack.Object, "proposal_id") != proposal.ID || stringField(ack.Object, "prepared_catalog_sha256") != digest(m.PreparedCatalog) {
			return nil, invalid()
		}
		if person := stringField(ack.Object, "person_public_key"); person != "-" && ack.Signer("device") != stringField(ack.Object, "device_public_key") {
			return nil, invalid()
		}
		m.Acknowledgments = append(m.Acknowledgments, ack)
		last = host
	}
	m.Commit, e = ReadStatement(d, o["commit"])
	if e != nil {
		return nil, e
	}
	if m.Commit.Kind != "migration_commit" || stringField(m.Commit.Object, "proposal_id") != proposal.ID || stringField(m.Commit.Object, "prepared_catalog_sha256") != digest(m.PreparedCatalog) || m.Commit.Signer("issuer") != proposal.Signer("issuer") {
		return nil, invalid()
	}

	expected := []string{}
	for _, ack := range m.Acknowledgments {
		expected = append(expected, ack.ID)
	}
	sort.Strings(expected)
	actual, e := ids(m.Commit.Object, "acknowledgment_ids", "ds_")
	if e != nil {
		return nil, e
	}
	if !equalStrings(expected, actual) {
		missing := []string{}
		for _, id := range actual {
			if !contains(expected, id) {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			return nil, failure("proof_required", missing...)
		}
		return nil, invalid()
	}
	issued := stringField(proposal.Object, "issued_at")
	expires := stringField(proposal.Object, "expires_at")
	for _, ack := range m.Acknowledgments {
		at := stringField(ack.Object, "acknowledged_at")
		if at < issued || at >= expires {
			return nil, invalid()
		}
	}
	committed := stringField(m.Commit.Object, "committed_at")
	if committed < issued || committed >= expires {
		return nil, invalid()
	}
	return m, nil
}
func stringField(o Object, k string) string { s, _ := text(o, k); return s }
func (s *Statement) issuedTime() time.Time {
	var at string
	if s.Root != nil {
		at = s.Root.Issued
	}
	if s.Lease != nil {
		at = s.Lease.Issued
	}
	if s.Access != nil {
		at = s.Access.Issued
	}
	if s.Restriction != nil {
		at = s.Restriction.Issued
	}
	t, _ := stamp(at)
	return t
}
