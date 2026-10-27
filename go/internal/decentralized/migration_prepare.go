package decentralized

import (
	"encoding/json"

	"github.com/peerspan/peerspan/go/internal/linking"
)

// PrepareMigrationCeremonyProjection verifies one exact roster-bound prefix
// under its signed frozen legacy source. The proposed root/shared person are
// available only for this staged original-person ceremony. The result cannot
// produce an admitted prior and is never an ordinary context/signing provider.
// Callers must separately retain/check their own explicit proposal/tuple review.
func PrepareMigrationCeremonyProjection(d Descriptor, proposalRaw, sourceRaw, sourceStateRaw, catalogRaw []byte, request, owner, selection, administrator, final *Packet, now string) (*Projection, error) {
	proposal, e := readStatement(d, proposalRaw, false)
	if e != nil {
		return nil, e
	}
	if proposal.Kind != "migration_proposal" || request == nil || owner == nil || selection == nil {
		return nil, invalid()
	}
	issued, expires := stringField(proposal.Object, "issued_at"), stringField(proposal.Object, "expires_at")
	if _, e = stamp(now); e != nil {
		return nil, e
	}
	if now < issued {
		return nil, failure("clock_rollback")
	}
	if now >= expires {
		return nil, failure("expired")
	}
	legacy, e := decode(stringField(proposal.Object, "legacy_descriptor_base64"), MaxObject)
	if e != nil {
		return nil, e
	}
	epoch, _ := num(proposal.Object, "legacy_epoch")
	key := stringField(proposal.Object, "legacy_root_public_key")
	if digest(sourceRaw) != stringField(proposal.Object, "source_catalog_sha256") || digest(sourceStateRaw) != stringField(proposal.Object, "source_state_sha256") {
		return nil, invalid()
	}
	source, facts, e := VerifyMigrationSourceSnapshot(d, legacy, sourceRaw, sourceStateRaw, epoch, stringField(proposal.Object, "legacy_feature_id"), key, issued)
	if e != nil {
		return nil, e
	}
	if proposal.Signer("issuer") != facts.RootPublicKey {
		return nil, invalid()
	}
	var roster []migrationRoster
	if json.Unmarshal(proposal.Object["roster"], &roster) != nil || len(roster) != len(facts.Members) {
		return nil, invalid()
	}
	rows := map[string]migrationRoster{}
	for n, row := range roster {
		member := facts.Members[n]
		if row.Host != member.HostPublicKey || row.Person != member.PersonPublicKey || row.Member != member.Member {
			return nil, invalid()
		}
		rows[row.Host] = row
	}
	packets := []*Packet{request, owner, selection, administrator, final}
	for n, packet := range packets {
		if packet == nil {
			continue
		}
		parsed, e := readPacket(d, packet.Raw)
		if e != nil {
			return nil, e
		}
		if parsed.ID != packet.ID {
			return nil, invalid()
		}
		packets[n] = parsed
	}
	request, owner, selection, administrator, final = packets[0], packets[1], packets[2], packets[3], packets[4]
	row, exists := rows[request.Writer]
	if !exists || row.Person == "-" || request.Role != "request" || stringField(request.Object, "mode") != "new" || stringField(request.Object, "migration_proposal_id") != proposal.ID || request.Signer != row.Device || stringField(request.Object, "expected_network_id") != d.NetworkID || stringField(request.Object, "expected_context_id") != d.ContextID || stringField(request.Object, "expected_person_public_key") != row.Person || owner.Role != "owner" || owner.Person != row.Person || owner.Signer != row.Person || owner.Issuer != "-" || owner.AuthorityFormat != "sshsig" || rows[owner.Writer].Person != row.Person || owner.RequestID != request.RequestID || stringField(owner.Object, "request_packet_id") != request.ID || stringField(owner.Object, "member") != row.Member || stringField(owner.Object, "host_public_key") != row.Host || stringField(owner.Object, "device_public_key") != row.Device || selection.Role != "selection" || selection.RequestID != request.RequestID || stringField(selection.Object, "request_packet_id") != request.ID || stringField(selection.Object, "owner_offer_id") != owner.ID || selection.Writer != row.Host || selection.Signer != row.Device || selection.Person != row.Person {
		return nil, invalid()
	}
	scopes, _ := num(owner.Object, "scopes")
	if scopes != row.Scopes {
		return nil, failure("forbidden")
	}
	if facts.Facts.State.RevokedDevices[linking.DeviceKey{PersonPublicKey: row.Person, DevicePublicKey: row.Device}] {
		return nil, failure("device_revoked")
	}
	if !contains(source.Hosts, row.Host) || !contains(source.Hosts, owner.Writer) {
		return nil, failure("forbidden")
	}
	created, deadline := stringField(request.Object, "created_at"), stringField(request.Object, "expires_at")
	if now < created {
		return nil, failure("clock_rollback")
	}
	if now >= deadline {
		return nil, failure("expired")
	}
	if selected := stringField(selection.Object, "selected_at"); selected < created || selected >= deadline {
		return nil, invalid()
	}
	if scopes&^uint64(7) != 0 {
		preserved := false
		for id, raw := range facts.Facts.State.Certificates {
			var old struct {
				Person string `json:"person_public_key"`
				Host   string `json:"host_public_key"`
				Device string `json:"device_public_key"`
				Scopes uint64 `json:"scopes"`
			}
			if json.Unmarshal(raw, &old) == nil && facts.Facts.State.ActivatedCertificates[id] && old.Person == row.Person && old.Host == row.Host && old.Device == row.Device && old.Scopes == row.Scopes {
				preserved = true
			}
		}
		if !preserved {
			return nil, failure("forbidden")
		}
	}
	catalog, e := ReadCatalog(d, catalogRaw)
	if e != nil {
		return nil, e
	}
	if len(catalog.Migrations) != 0 {
		return nil, invalid()
	}
	view := *catalog
	view.Statements = map[string]*Statement{}
	for id, statement := range catalog.Statements {
		view.Statements[id] = statement
	}
	catalog = &view
	g := newGraph(d, catalog)
	g.pendingAdmissions = map[string]string{}
	adminID := "-"
	if administrator != nil {
		adminID = administrator.ID
		if administrator.Role != "administrator" || administrator.RequestID != request.RequestID || administrator.Signer != key || administrator.Person != "-" || administrator.Issuer != "-" || !contains(source.Hosts, administrator.Writer) || stringField(administrator.Object, "selection_id") != selection.ID || stringField(administrator.Object, "owner_offer_id") != owner.ID {
			return nil, invalid()
		}
		for _, statement := range administrator.Statements {
			// Every migrated person has ONE shared ordinary root grant. An
			// operation-specific replacement cannot substitute for that parent.
			if statement.Kind != "host_lease" || statement.Lease.Operation != request.RequestID {
				return nil, invalid()
			}
			catalog.Statements[statement.ID] = statement
			g.pendingAdmissions[statement.ID] = request.RequestID
		}
	}
	if final != nil {
		if administrator == nil || final.Role != "owner_finalization" || final.RequestID != request.RequestID || stringField(final.Object, "selection_id") != selection.ID || stringField(final.Object, "administrator_offer_id") != adminID {
			return nil, invalid()
		}
		for _, statement := range final.Statements {
			if statement.Lease == nil || statement.Kind != "binding_lease" && statement.Kind != "device_lease" || statement.Lease.Operation != request.RequestID {
				return nil, invalid()
			}
			if catalog.Statements[statement.ID] == nil {
				catalog.Statements[statement.ID] = statement
			}
			g.pendingAdmissions[statement.ID] = request.RequestID
		}
	}
	var root, person *Statement
	for _, statement := range catalog.Statements {
		if statement.Root != nil {
			if root != nil && root.ID != statement.ID {
				return nil, failure("state_conflict")
			}
			r := statement.Root
			if r.Migration != proposal.ID || r.Epoch != epoch || r.Key != key || r.Issued != issued || len(r.Predecessors)+len(r.Resolves)+len(r.Retained) != 0 || statement.Signer("issuer") != key {
				return nil, invalid()
			}
			root = statement
			g.migrationRoots[statement.ID] = source
		}
		if statement.Kind == "person_lease" && statement.Lease.Subject.Person == row.Person {
			if person != nil && person.ID != statement.ID {
				return nil, failure("state_conflict")
			}
			l := statement.Lease
			if l.Operation != "-" || l.Sequence != 1 || len(l.Predecessors)+len(l.Resolves)+len(l.Retained)+len(l.Parents) != 0 || l.Issuer.Kind != "root" || statement.Signer("issuer") != key || l.Subject.Member != facts.Facts.PersonLabels[row.Person] || !facts.Facts.State.Persons[row.Person].Admitted {
				return nil, invalid()
			}
			person = statement
		}
		if statement.Kind == "host_lease" && statement.Lease.Operation == proposal.ID {
			if rows[statement.Lease.Subject.Host].Person != "-" || rows[statement.Lease.Subject.Host].Host == "" {
				return nil, invalid()
			}
			if g.migrationHosts[proposal.ID] == nil {
				g.migrationHosts[proposal.ID] = map[string]bool{}
			}
			g.migrationHosts[proposal.ID][statement.ID] = true
		}
	}
	if root == nil || person == nil {
		return nil, failure("proof_required")
	}
	if person.Lease.Root != root.ID || stringField(owner.Object, "root_state_id") != root.ID || stringField(owner.Object, "person_lease_id") != person.ID {
		return nil, invalid()
	}
	refs, e := ids(owner.Object, "issuer_lease_ids", "ds_")
	if e != nil || len(refs) != 1 || refs[0] != person.ID {
		return nil, invalid()
	}
	if e = g.prepareConsent(); e != nil {
		return nil, e
	}
	for _, id := range keysSortedStatements(catalog.Statements) {
		if e = g.validate(id); e != nil {
			return nil, e
		}
	}
	if e = g.validateAliases(); e != nil {
		return nil, e
	}
	at, _ := stamp(now)
	if e = candidateWindow(person, at); e != nil {
		return nil, e
	}
	if stringField(owner.Object, "not_after") > person.Lease.After || stringField(owner.Object, "not_after") <= now {
		return nil, failure("authority_expired")
	}
	validation := &migrationValidation{migration: &ParsedMigration{SourceCatalog: sourceRaw}, state: source, legacy: facts}
	bans, e := validation.requiredBans()
	if e != nil {
		return nil, e
	}
	restrictions := map[string]bool{}
	for id, statement := range catalog.Statements {
		if statement.Restriction == nil {
			continue
		}
		r := statement.Restriction
		if _, ok := bans[migrationBanKey(statement.Kind, r.Target)]; !ok || r.Root != root.ID || r.Target.Statement != "-" || r.Ratifies != "-" || len(r.Kept) != 0 || statement.Kind == "device_revoke" && r.Issuer.Kind != "person" || statement.Kind != "device_revoke" && r.Issuer.Kind != "root" {
			return nil, invalid()
		}
		restrictions[id] = true
	}
	admitted := map[string]bool{root.ID: true, person.ID: true}
	a := &authority{graph: g, now: at, admitted: admitted, restrictions: restrictions, heads: headsFor(g, admitted), maxima: map[string]uint64{}, active: map[string]bool{}}
	// Existing complete staged activations remain evidence only. No P/H/B/D
	// from them enters this private current set, nor any transferable metadata.
	p := &Projection{OK: true, ContextID: d.ContextID, DecisionTime: now, Root: RootView{[]string{root.ID}, epoch, root.ID, false, "-", []string{}}, Streams: []StreamView{{Stream: person.stream(), HeadIDs: []string{person.ID}, Maximum: 1, SelectedID: person.ID, Active: true, Code: "-", RequiredIDs: []string{}}}, Restrictions: keysSorted(restrictions), Inert: []string{}, authority: a}
	if administrator != nil {
		if _, e = p.PrepareCeremonyAdmissions(request, owner, selection, administrator); e != nil {
			return nil, e
		}
	}
	if final != nil {
		if _, e = p.PrepareCeremonyFinalization(request, owner, selection, administrator, final); e != nil {
			return nil, e
		}
	}
	return p, nil
}
