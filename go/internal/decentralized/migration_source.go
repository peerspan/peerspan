package decentralized

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type LegacyMaximum struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Version uint64 `json:"version"`
	Hash    string `json:"message_hash"`
}
type LegacyRestriction struct {
	ProofID string `json:"proof_id"`
	Kind    string `json:"kind"`
	Person  string `json:"person_public_key"`
	Host    string `json:"host_public_key"`
	Device  string `json:"device_public_key"`
}
type SourceState struct {
	Format       uint64              `json:"format"`
	NetworkID    string              `json:"network_id"`
	RootMaximum  uint64              `json:"legacy_root_highwater"`
	Hosts        []string            `json:"known_admitted_hosts"`
	Maxima       []LegacyMaximum     `json:"access_maxima"`
	Restrictions []LegacyRestriction `json:"admitted_restrictions"`
}

func readSourceState(d Descriptor, raw []byte) (*SourceState, error) {
	o, e := parseLimit(raw, MaxPayload)
	if e != nil {
		return nil, e
	}
	if fields(o, "format network_id legacy_root_highwater known_admitted_hosts access_maxima admitted_restrictions") != nil || version(o, 1) != nil || stringField(o, "network_id") != d.NetworkID {
		return nil, invalid()
	}
	var state SourceState
	if json.Unmarshal(raw, &state) != nil {
		return nil, invalid()
	}
	hosts, e := stringsOf(o, "known_admitted_hosts")
	if e != nil {
		return nil, e
	}
	if !sorted(hosts) {
		return nil, invalid()
	}
	if len(hosts) > MaxObjects {
		return nil, failure("quota_exceeded")
	}
	for _, host := range hosts {
		if !key(host) {
			return nil, invalid()
		}
	}
	for _, f := range []string{"access_maxima", "admitted_restrictions"} {
		var rows []json.RawMessage
		if json.Unmarshal(o[f], &rows) != nil || rows == nil {
			return nil, invalid()
		}
		if len(rows) > MaxObjects {
			return nil, failure("quota_exceeded")
		}
		last := []string{}
		for _, raw := range rows {
			if f == "access_maxima" {
				row, e := readObject(raw, "kind subject version message_hash")
				if e != nil {
					return nil, e
				}
				a, e := texts(row, "kind", "subject", "message_hash")
				if e != nil {
					return nil, e
				}
				v, e := num(row, "version")
				if e != nil || v == 0 || !literalOrID(a[2], "") || a[0] != "policy" && a[0] != "group" || a[0] == "policy" && !key(a[1]) || a[0] == "group" && !membership.ValidGroupName(a[1]) {
					return nil, invalid()
				}
				tuple := []string{a[0], a[1]}
				if compareStreams(last, tuple) >= 0 {
					return nil, invalid()
				}
				last = tuple
			} else {
				row, e := readObject(raw, "proof_id kind person_public_key host_public_key device_public_key")
				if e != nil {
					return nil, e
				}
				a, e := texts(row, "proof_id", "kind", "person_public_key", "host_public_key", "device_public_key")
				if e != nil || !identifier(a[0], "pf_") || a[1] == "" || !literalOrKey(a[2]) || !literalOrKey(a[3]) || !literalOrKey(a[4]) {
					return nil, invalid()
				}
				if len(last) > 0 && last[0] >= a[0] {
					return nil, invalid()
				}
				last = []string{a[0]}
			}
		}
	}
	return &state, nil
}
func legacyFailure(e error) error {
	if p, ok := e.(*linking.PathError); ok {
		return failure(p.Code, p.RequiredIDs...)
	}
	return invalid()
}
func verifyMigrationSource(d Descriptor, m *ParsedMigration) (*SourceState, linking.NetworkState, error) {
	legacy, e := decode(stringField(m.Proposal.Object, "legacy_descriptor_base64"), MaxObject)
	if e != nil {
		return nil, linking.NetworkState{}, e
	}
	epoch, _ := num(m.Proposal.Object, "legacy_epoch")
	at, _ := stamp(stringField(m.Proposal.Object, "issued_at"))
	return verifyLegacySnapshot(d, legacy, m.SourceCatalog, m.SourceState, epoch, stringField(m.Proposal.Object, "legacy_feature_id"), stringField(m.Proposal.Object, "legacy_root_public_key"), at)
}

func verifyLegacySnapshot(d Descriptor, legacy, catalogRaw, stateRaw []byte, epoch uint64, feature, expectedRoot string, at time.Time) (*SourceState, linking.NetworkState, error) {
	state, e := readSourceState(d, stateRaw)
	if e != nil {
		return nil, linking.NetworkState{}, e
	}
	descriptor, e := readObject(legacy, "network_id name genesis_root_public_key coordinator_address coordinator_public_key")
	if e != nil {
		return nil, linking.NetworkState{}, e
	}
	if stringField(descriptor, "network_id") != d.NetworkID || stringField(descriptor, "name") != d.Name || stringField(descriptor, "genesis_root_public_key") != d.GenesisRootPublicKey {
		return nil, linking.NetworkState{}, invalid()
	}
	facts, e := linking.VerifyStoredLegacyMigrationSource(linking.CatalogFactContext{Network: legacy, Epoch: epoch, KnownFeatureID: feature, Now: at}, catalogRaw)
	if e != nil {
		return nil, facts, legacyFailure(e)
	}
	if facts.Epoch != epoch || facts.RootPublicKey != expectedRoot || state.RootMaximum != epoch {
		return nil, facts, invalid()
	}
	access, e := linking.VerifyStoredLegacyMigrationAccess(linking.AccessContext{Network: legacy, Epoch: epoch, KnownFeatureID: feature, Now: at}, catalogRaw)
	if e != nil {
		return nil, facts, legacyFailure(e)
	}
	floors := map[string]LegacyMaximum{}
	for _, maximum := range state.Maxima {
		floors[maximum.Kind+"\x00"+maximum.Subject] = maximum
	}
	checkFloor := func(kind, subject string, version uint64, hash string) error {
		floor, ok := floors[kind+"\x00"+subject]
		if !ok || floor.Version < version || floor.Version == version && floor.Hash != "-" && floor.Hash != hash {
			return failure("state_conflict")
		}
		return nil
	}
	for _, policy := range access.Policies {
		if e = checkFloor("policy", policy.PersonPublicKey, policy.Version, policy.MessageHash); e != nil {
			return nil, facts, e
		}
	}
	for _, group := range access.Groups {
		if e = checkFloor("group", group.Name, group.Version, group.MessageHash); e != nil {
			return nil, facts, e
		}
	}
	// Every remembered restriction names an exact old body; outer snapshots do
	// not manufacture authority or permit discarding a missing sticky restriction.
	catalog, e := readObjectLimit(catalogRaw, "format network_id objects", 512<<10)
	if e != nil {
		return nil, facts, e
	}
	var entries []json.RawMessage
	if json.Unmarshal(catalog["objects"], &entries) != nil || entries == nil {
		return nil, facts, invalid()
	}
	proofs := map[string]struct {
		kind string
		body []byte
	}{}
	for _, raw := range entries {
		row, e := readObject(raw, "id kind body_base64")
		if e != nil {
			return nil, facts, e
		}
		body, e := decode(stringField(row, "body_base64"), MaxObject)
		if e != nil {
			return nil, facts, e
		}
		proofs[stringField(row, "id")] = struct {
			kind string
			body []byte
		}{stringField(row, "kind"), body}
	}
	for _, restriction := range state.Restrictions {
		proof, ok := proofs[restriction.ProofID]
		if !ok {
			return nil, facts, failure("proof_required", restriction.ProofID)
		}
		if proof.kind != restriction.Kind {
			return nil, facts, invalid()
		}
		target, restrictive, e := legacyRestrictionTarget(proof.kind, proof.body)
		if e != nil {
			return nil, facts, e
		}
		if !restrictive || target.Person != restriction.Person || target.Host != restriction.Host || target.Device != restriction.Device {
			return nil, facts, invalid()
		}
		// The endorsed snapshot may preserve a genuinely previously admitted
		// stable ban whose old administrator later lost the signing role. Its
		// exact verified original proof remains necessary; copying that deny
		// cannot simultaneously require reviving its target as a positive
		// prepared person/host or in the acknowledged cutover roster.
		kind, e := legacyBanKind(proof.kind, proof.body)
		if e != nil {
			return nil, facts, e
		}
		if kind == "person_remove" {
			person := facts.Facts.State.Persons[target.Person]
			person.Admitted, person.Administrator = false, false
			facts.Facts.State.Persons[target.Person] = person
			for host, person := range facts.Facts.State.Bindings {
				if person == target.Person {
					facts.Facts.State.Bindings[host] = "-"
				}
			}
		} else if kind == "host_revoke" {
			facts.Facts.State.Hosts[target.Host] = false
			facts.Facts.State.Bindings[target.Host] = "-"
		}
	}
	retained := []linking.MemberProof{}
	hosts := []string{}
	for _, member := range facts.Members {
		if !facts.Facts.State.Hosts[member.HostPublicKey] {
			continue
		}
		if facts.Facts.State.Bindings[member.HostPublicKey] == "-" {
			member.PersonPublicKey, member.BindingProofID = "-", "-"
		}
		retained = append(retained, member)
		hosts = append(hosts, member.HostPublicKey)
	}
	facts.Members = retained
	sort.Strings(hosts)
	if !equalStrings(hosts, state.Hosts) {
		return nil, facts, invalid()
	}
	known := map[string]bool{}
	for _, restriction := range state.Restrictions {
		known[restriction.ProofID] = true
	}
	for id, proof := range proofs {
		if _, restrictive, e := legacyRestrictionTarget(proof.kind, proof.body); e != nil {
			return nil, facts, e
		} else if restrictive && facts.RestrictionApplies(id) && !known[id] {
			return nil, facts, failure("proof_required", id)
		}
	}
	return state, facts, nil
}

// Targets come from exact already verified old proof bytes, never from the
// migration snapshot's unsigned labels. Generation-scoped denials remain exact
// history; stable-key copies are checked separately in prepared authority.
func legacyRestrictionTarget(kind string, raw []byte) (Target, bool, error) {
	t := Target{Statement: "-", Person: "-", Host: "-", Device: "-"}
	o, e := parse(raw)
	if e != nil {
		return t, false, e
	}
	actual := kind
	if kind == "person_record" || kind == "root_record" {
		actual = stringField(o, "kind")
		payload, e := decode(stringField(o, "payload_base64"), MaxObject)
		if e != nil {
			return t, false, e
		}
		o, e = parse(payload)
		if e != nil {
			return t, false, e
		}
	}
	switch actual {
	case "admin_removal", "person_removal", "peerspan-person-remove-v1":
		t.Person = stringField(o, "person_public_key")
	case "host_revocation", "host_leave", "peerspan-revoke-host-v1":
		t.Host = stringField(o, "host_public_key")
	case "host_unbinding", "peerspan-host-unbind-v1":
		t.Person, t.Host = stringField(o, "person_public_key"), stringField(o, "host_public_key")
	case "device_revocation":
		t.Person, t.Device = stringField(o, "person_public_key"), stringField(o, "target_device_public_key")
	case "invite_revocation", "peerspan-revoke-invite-v1":
		// The snapshot schema has no invite-key slot. Preserve this exact old
		// proof without inventing a new-mode consumed invitation authority.
	default:
		return t, false, nil
	}
	return t, true, nil
}

func migrationBanKey(kind string, target Target) string {
	return kind + "\x00" + target.Person + "\x00" + target.Host + "\x00" + target.Device
}

func legacyBanKind(kind string, body []byte) (string, error) {
	o, e := parse(body)
	if e != nil {
		return "", e
	}
	if kind == "person_record" || kind == "root_record" {
		kind = stringField(o, "kind")
	}
	switch kind {
	case "person_removal", "peerspan-person-remove-v1":
		return "person_remove", nil
	case "admin_removal":
		var revoke bool
		if json.Unmarshal(o["revoke_admitted"], &revoke) != nil {
			return "", invalid()
		}
		if revoke {
			return "person_remove", nil
		}
	case "host_revocation", "host_leave", "peerspan-revoke-host-v1":
		return "host_revoke", nil
	case "device_revocation":
		return "device_revoke", nil
	}
	return "", nil
}

// The prepared context may ratify only exact active stable-key denials from
// this verified source. Withdrawal/unbinding generations remain old history.
func (v *migrationValidation) requiredBans() (map[string]string, error) {
	o, e := parseLimit(v.migration.SourceCatalog, 512<<10)
	if e != nil {
		return nil, e
	}
	var entries []struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Body string `json:"body_base64"`
	}
	if json.Unmarshal(o["objects"], &entries) != nil {
		return nil, invalid()
	}
	bans := map[string]string{}
	admitted := map[string]bool{}
	for _, restriction := range v.state.Restrictions {
		admitted[restriction.ProofID] = true
	}
	for _, entry := range entries {
		// Applicable current restrictions were required in the verified source
		// snapshot above. Its endorsed already-admitted stable bans also remain
		// sticky even when a later administrator withdrawal makes raw bytes inert.
		if !admitted[entry.ID] {
			continue
		}
		body, e := decode(entry.Body, MaxObject)
		if e != nil {
			return nil, e
		}
		target, restrictive, e := legacyRestrictionTarget(entry.Kind, body)
		if e != nil {
			return nil, e
		}
		if !restrictive {
			continue
		}
		copyKind, e := legacyBanKind(entry.Kind, body)
		if e != nil {
			return nil, e
		}
		if copyKind == "device_revoke" && (!v.legacy.Facts.State.Persons[target.Person].Admitted || !v.legacy.Facts.State.RevokedDevices[linking.DeviceKey{PersonPublicKey: target.Person, DevicePublicKey: target.Device}]) {
			continue
		}
		if copyKind != "" {
			bans[migrationBanKey(copyKind, target)] = entry.ID
		}
	}
	return bans, nil
}
