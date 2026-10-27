package host

import (
	"context"
	"encoding/json"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/linking"
)

type decMigrationOwnerFacts struct {
	Staged  *decMigrationLinkContext
	Row     DecMigrationRoster
	Catalog *dec.Catalog
	Person  *dec.Statement
	Root    *dec.Statement
	Profile bool
}

// Only the exact approved cutover can use the proposed initial root/shared P
// for original-person self-consent. This supplies no normal Snapshot/prior.
func (s *Store) decMigrationOwnerFacts(ctx context.Context, q dbQuerier, p decPending, d dec.Descriptor, person string, catalog *dec.Catalog, now string) (decMigrationOwnerFacts, error) {
	var result decMigrationOwnerFacts
	staged, e := s.migrationPreparationContext(ctx, q, d.NetworkID, p.Record.Migration, now)
	if e != nil {
		return result, e
	}
	if staged.Record.Fenced {
		return result, decFailure("migration_pending", p.Record.Migration)
	}
	compatible, e := dec.MigrationDescriptorsEqual(staged.Source.Descriptor.Raw, d.Raw)
	if e != nil {
		return result, e
	}
	if p.Record.Mode != "new" || p.Terms.Migration != staged.Prefix.Proposal.ID || p.Record.Network != d.NetworkID || p.Record.Context != d.ContextID || p.Record.Person != person || !compatible || p.Terms.RenewedDevice != "-" {
		return result, decFailure("invalid")
	}
	var row DecMigrationRoster
	for _, entry := range staged.Prefix.Fields.Roster {
		if entry.Host == p.Record.Host {
			row = entry
		}
	}
	if row.Host == "" || row.Person != person || row.Device != p.Record.Device || row.Person == "-" {
		return result, decFailure("forbidden")
	}
	if containsString(p.Record.Roles, "requester") {
		if _, e = s.decRequesterDeviceSeed(ctx, q, p, now); e != nil {
			return result, e
		}
	}
	if staged.Prefix.Catalog == nil || staged.Prefix.Root == nil {
		return result, decFailure("proof_required", staged.Prefix.Proposal.ID)
	}
	if catalog == nil {
		catalog = staged.Prefix.Catalog
	} else {
		catalog, e = dec.UnionCatalog(d, staged.Prefix.Catalog, catalog)
		if e != nil {
			return result, e
		}
	}
	// Recheck every exact supplied root alias against the frozen source. The
	// proposed descriptor/catalog are never promoted to ordinary origin here.
	evidence := migrationRecordEvidence(staged.Record)
	evidence.Catalog = catalog.Raw
	evidence.Acknowledgments = []json.RawMessage{}
	evidence.Commit = json.RawMessage(`"-"`)
	prefix, e := readMigrationPrefix(d, evidence)
	if e != nil {
		return result, e
	}
	root := prefix.Root
	if root == nil || root.ID != staged.Prefix.Root.ID || root.Root.Issued > now {
		return result, decFailure("state_conflict")
	}
	var parent *dec.Statement
	for _, statement := range catalog.Statements {
		if statement.Kind != "person_lease" || statement.Lease.Subject.Person != person {
			continue
		}
		lease := statement.Lease
		if parent != nil && parent.ID != statement.ID {
			return result, decFailure("state_conflict")
		}
		if lease.Root != root.ID || lease.Operation != "-" || lease.Sequence != 1 || len(lease.Predecessors) != 0 || len(lease.Resolves) != 0 || len(lease.Retained) != 0 || len(lease.Parents) != 0 || lease.Issuer.Kind != "root" || statement.Signer("issuer") != prefix.Fields.Root || lease.Subject.Member != prefix.Facts.Facts.PersonLabels[person] || !prefix.Facts.Facts.State.Persons[person].Admitted {
			return result, decFailure("forbidden")
		}
		if lease.Issued > now || lease.Before > now {
			return result, decFailure("not_yet_valid")
		}
		if lease.After <= now {
			return result, decFailure("authority_expired")
		}
		parent = statement
	}
	if parent == nil {
		return result, decFailure("proof_required")
	}
	if prefix.Facts.Facts.State.RevokedDevices[linking.DeviceKey{PersonPublicKey: person, DevicePublicKey: row.Device}] {
		return result, decFailure("device_revoked")
	}
	// The nominal8 exception is proven from the exact old signed activated
	// certificate for this tuple, not from a roster assertion. Each owned host
	// additionally checks its privately approved selection above.
	profile := false
	for id, raw := range prefix.Facts.Facts.State.Certificates {
		if !prefix.Facts.Facts.State.ActivatedCertificates[id] {
			continue
		}
		var old struct {
			Person string `json:"person_public_key"`
			Host   string `json:"host_public_key"`
			Device string `json:"device_public_key"`
			Scopes uint64 `json:"scopes"`
		}
		if json.Unmarshal(raw, &old) != nil {
			return result, decStorageError()
		}
		if old.Person == row.Person && old.Host == row.Host && old.Device == row.Device && old.Scopes == row.Scopes {
			profile = true
		}
	}
	return decMigrationOwnerFacts{staged, row, catalog, parent, root, profile}, nil
}

func (s *Store) decMigrationOwnerPlan(ctx context.Context, q dbQuerier, p decPending, input DecOwnerApproval, now string) (decOwnerPlan, error) {
	var plan decOwnerPlan
	if input.Provider != input.Person || input.Format != "auto" && input.Format != "sshsig" {
		return plan, decFailure("forbidden")
	}
	staged, e := s.migrationPreparationContext(ctx, q, input.Network, p.Record.Migration, now)
	if e != nil {
		return plan, e
	}
	facts, e := s.decMigrationOwnerFacts(ctx, q, p, staged.Source.Descriptor, input.Person, nil, now)
	if e != nil {
		return plan, e
	}
	if staged.Own.Person != input.Person || input.Scopes != facts.Row.Scopes || input.Scopes&^uint64(7) != 0 && !facts.Profile {
		return plan, decFailure("forbidden")
	}
	deadline, e := dec.ParseTime(input.NotAfter)
	if e != nil {
		return plan, e
	}
	at, _ := dec.ParseTime(now)
	if !deadline.After(at) || deadline.After(at.Add(7*24*time.Hour)) || input.NotAfter > facts.Person.Lease.After {
		return plan, decFailure("authority_expired")
	}
	plan = decOwnerPlan{Descriptor: staged.Source.Descriptor, Provider: decIntentProvider{"original", input.Person, "sshsig", "-"}, View: DecProviderView{"original_person", input.Person, s.identity.PublicKey, "-", facts.Person.ID, facts.Root.ID, 7, facts.Person.Lease.After}, Root: facts.Root.ID, PersonLease: facts.Person.ID, HostLease: "-", BindingLease: "-", Member: facts.Row.Member, Catalog: facts.Catalog}
	return plan, nil
}

func (s *Store) decSelectedMigrationOwner(ctx context.Context, q dbQuerier, p decPending, owner *dec.Packet, d dec.Descriptor, terms decOwnerTerms, catalog *dec.Catalog, now string) (decSelectedOffer, error) {
	result := decSelectedOffer{Owner: owner, Terms: terms, Descriptor: d, Catalog: catalog}
	facts, e := s.decMigrationOwnerFacts(ctx, q, p, d, owner.Person, catalog, now)
	if e != nil {
		return result, e
	}
	knownOwnerHost := false
	for _, member := range facts.Staged.Prefix.Facts.Members {
		knownOwnerHost = knownOwnerHost || member.HostPublicKey == owner.Writer && member.PersonPublicKey == owner.Person
	}
	if !knownOwnerHost || owner.Signer != owner.Person || owner.Issuer != "-" || owner.AuthorityFormat != "sshsig" || terms.Root != facts.Root.ID || terms.PersonLease != facts.Person.ID || len(terms.Issuers) != 1 || terms.Issuers[0] != facts.Person.ID || terms.Member != facts.Row.Member || terms.Scopes != facts.Row.Scopes || terms.Scopes&^uint64(7) != 0 && !facts.Profile || terms.NotAfter > facts.Person.Lease.After {
		return result, decFailure("forbidden")
	}
	result.Catalog = facts.Catalog
	result.Provider = DecProviderView{"original_person", owner.Person, owner.Writer, "-", facts.Person.ID, facts.Root.ID, 7, facts.Person.Lease.After}
	return result, nil
}
