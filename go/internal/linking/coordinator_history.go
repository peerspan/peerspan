package linking

import "github.com/peerspan/peerspan/go/internal/membership"

// Historical grants authenticate their original descriptor and internal packet
// references, without asserting that the old transport pin was ever trusted.
func operationDescriptor(network, request, current Object, historical bool) bool {
	if fields(network, "network_id name genesis_root_public_key coordinator_address coordinator_public_key") != nil || !key(scalar(network, "coordinator_public_key")) || !membership.ValidCoordinatorAddress(scalar(network, "coordinator_address")) {
		return false
	}
	for _, field := range []string{"network_id", "name", "genesis_root_public_key"} {
		if scalar(network, field) != scalar(current, field) {
			return false
		}
	}
	for _, field := range []string{"coordinator_address", "coordinator_public_key"} {
		if scalar(request, field) != scalar(network, field) {
			return false
		}
	}
	return historical || equivalent(network, current)
}
