package decentralized

import (
	"encoding/json"
	"sort"
)

// MigrationPreparedHost identifies exact existing public facts in a fully
// checked prepared catalog. It confers no local acknowledgment or authority.
type MigrationPreparedHost struct {
	Host, Person, Device, HostLease, Binding, DeviceLease, Activation string
}

type MigrationPreparedEvidence struct {
	Proposal, Root, PreparedHash string
	Hosts                        []MigrationPreparedHost
}

// VerifyMigrationAcknowledgments validates the complete prepared catalog and
// every exact roster acknowledgment before the legacy root signs its commit.
// There is still no portable origin, adopted context, or local approval here.
func VerifyMigrationAcknowledgments(d Descriptor, proposalRaw, sourceRaw, stateRaw, preparedRaw []byte, acknowledgmentRaw [][]byte, now string) (*MigrationPreparedEvidence, []string, error) {
	evidence, e := VerifyMigrationPrepared(d, proposalRaw, sourceRaw, stateRaw, preparedRaw, now, "-")
	if e != nil {
		return nil, nil, e
	}
	proposal, e := ReadStatement(d, proposalRaw)
	if e != nil {
		return nil, nil, e
	}
	m := &ParsedMigration{Proposal: proposal, SourceCatalog: sourceRaw, SourceState: stateRaw, PreparedCatalog: preparedRaw, Acknowledgments: []*Statement{}}
	if len(acknowledgmentRaw) > MaxObjects {
		return nil, nil, failure("quota_exceeded")
	}
	last, ids := "", []string{}
	for _, raw := range acknowledgmentRaw {
		ack, e := ReadStatement(d, raw)
		if e != nil {
			return nil, nil, e
		}
		host := stringField(ack.Object, "host_public_key")
		at := stringField(ack.Object, "acknowledged_at")
		if ack.Kind != "migration_ack" || host <= last || ack.Signer("host") != host || stringField(ack.Object, "proposal_id") != proposal.ID || stringField(ack.Object, "prepared_catalog_sha256") != evidence.PreparedHash || at < stringField(proposal.Object, "issued_at") || at >= stringField(proposal.Object, "expires_at") {
			return nil, nil, invalid()
		}
		if person := stringField(ack.Object, "person_public_key"); person != "-" && ack.Signer("device") != stringField(ack.Object, "device_public_key") {
			return nil, nil, invalid()
		}
		m.Acknowledgments = append(m.Acknowledgments, ack)
		last = host
		ids = append(ids, ack.ID)
	}
	v, e := verifyMigrationParts(d, m, false)
	if e != nil {
		return nil, nil, e
	}
	if e = v.checkAcknowledgments(); e != nil {
		return nil, nil, e
	}
	sort.Strings(ids)
	return evidence, ids, nil
}

// VerifyMigrationPrepared verifies ALL source/roster/prepared components before
// the irreversible acknowledgment fence. No invented acknowledgment/commit or
// ordinary prior is created. localHost, when non-'-', additionally requires that
// exact host's current prepared finite path at the actual local decision time.
func VerifyMigrationPrepared(d Descriptor, proposalRaw, sourceRaw, stateRaw, preparedRaw []byte, now, localHost string) (*MigrationPreparedEvidence, error) {
	if !literalOrKey(localHost) {
		return nil, invalid()
	}
	proposal, e := ReadStatement(d, proposalRaw)
	if e != nil {
		return nil, e
	}
	if proposal.Kind != "migration_proposal" || digest(sourceRaw) != stringField(proposal.Object, "source_catalog_sha256") || digest(stateRaw) != stringField(proposal.Object, "source_state_sha256") {
		return nil, invalid()
	}
	if _, e = stamp(now); e != nil {
		return nil, e
	}
	if now < stringField(proposal.Object, "issued_at") {
		return nil, failure("clock_rollback")
	}
	if now >= stringField(proposal.Object, "expires_at") {
		return nil, failure("expired")
	}
	m := &ParsedMigration{Proposal: proposal, SourceCatalog: sourceRaw, SourceState: stateRaw, PreparedCatalog: preparedRaw}
	v, e := verifyMigrationParts(d, m, false)
	if e != nil {
		return nil, e
	}
	at, _ := stamp(now)
	a := v.currentAuthority(at)
	result := &MigrationPreparedEvidence{Proposal: proposal.ID, Root: v.root.ID, PreparedHash: digest(preparedRaw), Hosts: []MigrationPreparedHost{}}
	found := localHost == "-"
	for _, row := range v.roster {
		entry := MigrationPreparedHost{Host: row.Host, Person: row.Person, Device: row.Device, HostLease: "-", Binding: "-", DeviceLease: "-", Activation: "-"}
		for _, statement := range v.prepared.Statements {
			if statement.Kind == "host_lease" && statement.Lease.Subject.Host == row.Host {
				entry.HostLease = statement.ID
			}
		}
		if row.Person != "-" {
			for _, activation := range v.prepared.Activations {
				if activation.Request.Writer != row.Host {
					continue
				}
				entry.Activation = activation.ID
				entry.Binding = stringField(activation.Manifest, "binding_lease_id")
				entry.DeviceLease = stringField(activation.Manifest, "device_lease_id")
			}
		}
		if row.Host == localHost {
			found = true
			id := entry.HostLease
			if row.Person != "-" {
				id = entry.DeviceLease
			}
			statement, e := v.graph.get(id)
			if e != nil {
				return nil, e
			}
			if _, e = a.evaluate(statement); e != nil {
				return nil, e
			}
		}
		result.Hosts = append(result.Hosts, entry)
	}
	if !found {
		return nil, failure("forbidden")
	}
	return result, nil
}

// MigrationAcknowledgmentPayload uses only exact verified prepared references;
// the caller still needs its separate own review and final clock/TX check.
func MigrationAcknowledgmentPayload(evidence *MigrationPreparedEvidence, host, now string) ([]byte, error) {
	if evidence == nil {
		return nil, invalid()
	}
	for _, row := range evidence.Hosts {
		if row.Host == host {
			return json.Marshal(map[string]any{"proposal_id": evidence.Proposal, "root_state_id": evidence.Root, "prepared_catalog_sha256": evidence.PreparedHash, "host_public_key": row.Host, "person_public_key": row.Person, "device_public_key": row.Device, "host_lease_id": row.HostLease, "binding_lease_id": row.Binding, "device_lease_id": row.DeviceLease, "activation_id": row.Activation, "acknowledged_at": now})
		}
	}
	return nil, failure("forbidden")
}
