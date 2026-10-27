package decentralized

import (
	"reflect"

	"github.com/peerspan/peerspan/go/internal/membership"
)

// These comparisons concern independently materialized LOCAL compatibility
// views only. They do not normalize any endorsed bytes or replace a declared
// source/prepared hash, proof body, signature or statement ID.
func MigrationLegacyDescriptorsEqual(a, b []byte) (bool, error) {
	read := func(raw []byte) ([5]string, error) {
		var result [5]string
		o, e := readObject(raw, "network_id name genesis_root_public_key coordinator_address coordinator_public_key")
		if e != nil {
			return result, e
		}
		fields, e := texts(o, "network_id", "name", "genesis_root_public_key", "coordinator_address", "coordinator_public_key")
		if e != nil {
			return result, e
		}
		copy(result[:], fields)
		public, e := membership.DecodeKey(result[2])
		if e != nil || !key(result[2]) || !key(result[4]) || membership.NetworkID(public) != result[0] || !membership.ValidLabel(result[1]) || !membership.ValidCoordinatorAddress(result[3]) {
			return result, invalid()
		}
		return result, nil
	}
	left, e := read(a)
	if e != nil {
		return false, e
	}
	right, e := read(b)
	return left == right, e
}

func MigrationDescriptorsEqual(a, b []byte) (bool, error) {
	left, e := ReadDescriptor(a)
	if e != nil {
		return false, e
	}
	right, e := ReadDescriptor(b)
	if e != nil {
		return false, e
	}
	return left.Format == right.Format && left.Protocol == right.Protocol && left.NetworkID == right.NetworkID && left.Name == right.Name && left.GenesisRootPublicKey == right.GenesisRootPublicKey && left.ContextID == right.ContextID, nil
}

func MigrationSourceStatesEqual(d Descriptor, a, b []byte) (bool, error) {
	left, e := readSourceState(d, a)
	if e != nil {
		return false, e
	}
	right, e := readSourceState(d, b)
	if e != nil {
		return false, e
	}
	return reflect.DeepEqual(left, right), nil
}
