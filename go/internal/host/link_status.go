package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/peerspan/peerspan/go/internal/linking"
)

// selectedPolicyAttention uses the caller's coherent status transaction and
// verified projection. It never selects an original signer after a device error.
func (s *Store) selectedPolicyAttention(ctx context.Context, q dbQuerier, g governance, owner string, attend func(kind, subject, detail, command string)) (bool, error) {
	network := g.network.ID
	var person, device, certificate string
	err := q.QueryRowContext(ctx, `SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?`, network).Scan(&person, &device, &certificate)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	now, err := linkNow()
	if err != nil {
		return true, err
	}
	if g.linking == nil {
		err = linkFail("state_conflict", "-", "feature")
	} else {
		var provider linkDeviceProvider
		provider, err = s.linkDeviceProvider(ctx, q, g.linking, "auto", 1, now)
		if err == nil && provider.View.PersonPublicKey != owner {
			err = linkFail("forbidden", "-", "person")
		}
	}
	if err == nil {
		return true, nil
	}
	failure := linkCause(err, "-", "signer")
	detail := fmt.Sprintf("selected device cannot renew this person's access policy: %s: %s", failure.Code, failure.Message)
	if failure.Code == "authority_expired" && renewableSelectedTarget(g.linking, s.identity.PublicKey, owner, person, device, certificate) {
		detail += "; after syncing, request renewal with peerspan link --renew --network " + network + "; another currently authorized machine must approve"
	}
	attend("person_device_signer_unavailable", network, detail, "peerspan network sync "+network)
	return true, nil
}

// The provider has already verified the owned seed before returning expiry.
// These additional verified target facts permit only a conditional review hint.
func renewableSelectedTarget(p *linkProjection, host, owner, person, device, certificate string) bool {
	if p == nil || person != owner {
		return false
	}
	state := p.Network.Facts.State
	if !state.Persons[owner].Admitted || !state.Hosts[host] || state.Bindings[host] != owner || !state.ActivatedCertificates[certificate] || state.RevokedDevices[linking.DeviceKey{PersonPublicKey: owner, DevicePublicKey: device}] {
		return false
	}
	var target struct {
		PersonPublicKey string `json:"person_public_key"`
		HostPublicKey   string `json:"host_public_key"`
		DevicePublicKey string `json:"device_public_key"`
	}
	return json.Unmarshal(state.Certificates[certificate], &target) == nil && target.PersonPublicKey == owner && target.HostPublicKey == host && target.DevicePublicKey == device
}
