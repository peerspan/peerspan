package host

import (
	"bytes"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/linking"
)

// A local wrapper can be rematerialized by another implementation. Each
// original proof body and its declared kind/ID stay exact, including aliases.
func migrationLocalCatalogEqual(network string, a, b []byte) (bool, error) {
	if len(a) > 512<<10 || len(b) > 512<<10 {
		return false, decFailure("quota_exceeded")
	}
	left, e := decodeLinkCatalog(a, network)
	if e != nil {
		return false, e
	}
	right, e := decodeLinkCatalog(b, network)
	if e != nil {
		return false, e
	}
	if left.Format != right.Format || left.NetworkID != right.NetworkID || len(left.Objects) != len(right.Objects) {
		return false, nil
	}
	for n, entry := range left.Objects {
		other := right.Objects[n]
		if entry.ID != other.ID || entry.Kind != other.Kind {
			return false, nil
		}
		body, e := linkBytes(entry.BodyBase64, linking.MaxObject)
		if e != nil {
			return false, e
		}
		otherBody, e := linkBytes(other.BodyBase64, linking.MaxObject)
		if e != nil {
			return false, e
		}
		if !bytes.Equal(body, otherBody) {
			return false, nil
		}
	}
	return true, nil
}

func migrationLocalSourceEqual(source *decMigrationSource, p decMigrationProposal, r decMigrationRecord) (bool, error) {
	checks := []func() (bool, error){
		func() (bool, error) {
			return dec.MigrationLegacyDescriptorsEqual(source.Legacy, mustDecBytes(p.Legacy))
		},
		func() (bool, error) { return dec.MigrationDescriptorsEqual(source.Descriptor.Raw, p.Descriptor) },
		func() (bool, error) {
			return migrationLocalCatalogEqual(source.Network.ID, source.Catalog, mustDecBytes(r.SourceCatalog))
		},
		func() (bool, error) {
			return dec.MigrationSourceStatesEqual(source.Descriptor, source.State, mustDecBytes(r.SourceState))
		},
	}
	for _, check := range checks {
		equal, e := check()
		if e != nil || !equal {
			return false, e
		}
	}
	return true, nil
}
