package host

import (
	"encoding/json"
	"sort"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/linking"
)

type DecMigrationInheritedBan struct {
	Kind   string
	Target dec.Target
	Proofs []string
}

type decMigrationBan = DecMigrationInheritedBan

// DecentralizedMigrationInheritedBans verifies the signed proposal and its exact
// endorsed legacy source for native signing review. Other prepared components
// cannot supply targets; this output grants no admission or signing authority.
func DecentralizedMigrationInheritedBans(d dec.Descriptor, input DecMigrationEvidence) ([]DecMigrationInheritedBan, error) {
	input.Catalog = []byte(`"-"`)
	input.Acknowledgments = []json.RawMessage{}
	input.Commit = []byte(`"-"`)
	prefix, e := readMigrationPrefix(d, input)
	if e != nil {
		return nil, e
	}
	return migrationRequiredBans(&decMigrationSource{Network: Network{ID: d.NetworkID}, Catalog: mustDecBytes(input.Source), Snapshot: prefix.Snapshot, Facts: prefix.Facts})
}

// The caller supplies one independently verified source snapshot/catalog.
// Raw inactive signatures never add targets, and this derives no new-mode
// admission or issuer power. Every original proof for a required stable target
// is retained for the copy-only human review.
func migrationRequiredBans(source *decMigrationSource) ([]decMigrationBan, error) {
	if source == nil || source.Snapshot == nil {
		return nil, decStorageError()
	}
	objects, e := decodeLinkCatalog(source.Catalog, source.Network.ID)
	if e != nil {
		return nil, e
	}
	indexed := map[string]linkCatalogObject{}
	for _, object := range objects.Objects {
		indexed[object.ID] = object
	}
	bans := map[string]*decMigrationBan{}
	for _, admitted := range source.Snapshot.Restrictions {
		object, ok := indexed[admitted.ProofID]
		if !ok {
			return nil, decFailure("proof_required", admitted.ProofID)
		}
		raw, e := linkBytes(object.BodyBase64, linking.MaxObject)
		if e != nil {
			return nil, e
		}
		target, kind, restrictive, e := dec.MigrationSourceRestriction(object.ID, object.Kind, raw)
		if e != nil {
			return nil, e
		}
		if !restrictive || target != admitted {
			return nil, decFailure("state_conflict")
		}
		if kind == "" {
			continue
		}
		if kind == "device_revoke" && (!source.Facts.Facts.State.Persons[target.Person].Admitted || !source.Facts.Facts.State.RevokedDevices[linking.DeviceKey{PersonPublicKey: target.Person, DevicePublicKey: target.Device}]) {
			continue
		}
		key := kind + "\x00" + target.Person + "\x00" + target.Host + "\x00" + target.Device
		if bans[key] == nil {
			bans[key] = &decMigrationBan{Kind: kind, Target: dec.Target{Person: target.Person, Host: target.Host, Device: target.Device, Statement: "-"}, Proofs: []string{}}
		}
		bans[key].Proofs = append(bans[key].Proofs, object.ID)
	}
	result := []decMigrationBan{}
	for _, key := range sortedKeys(bans) {
		ban := *bans[key]
		sort.Strings(ban.Proofs)
		result = append(result, ban)
	}
	return result, nil
}
