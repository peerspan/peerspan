package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkAdminSubmission struct {
	Network string
	Request host.LinkActionRequest
	Result  any
}

func descriptorFromNetwork(n host.Network) (string, error) {
	return (membership.Descriptor{NetworkID: n.ID, NetworkName: n.Name, RootPublicKey: n.RootPublicKey, CoordinatorAddress: n.CoordinatorAddress, CoordinatorPublicKey: n.CoordinatorPublicKey}).Encode()
}
func hostIDFromKey(key string) string {
	public, _ := membership.DecodeKey(key)
	return membership.HostID(public)
}
func personIDFromKey(key string) string {
	public, _ := membership.DecodeKey(key)
	return membership.PersonID(public)
}
func (s linkAdminSubmission) submit(ctx context.Context, client host.Client) (json.RawMessage, error) {
	result, e := client.Call(ctx, "POST", "/v1/networks/"+url.PathEscape(s.Network)+"/link-actions", s.Request)
	if e != nil {
		return nil, e
	}
	if s.Result != nil {
		return json.Marshal(s.Result)
	}
	return result, nil
}
func selectedLinkAdministrator(ctx context.Context, client host.Client, network, keyPath string) (*host.LinkSignerView, error) {
	if keyPath != "" {
		return nil, nil
	}
	selected, e := call[host.LinkSignerView](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/link-signer")
	if e != nil {
		var failure *host.ClientError
		if errors.As(e, &failure) && failure.Status == 404 {
			return nil, nil
		}
		return nil, e
	}
	return &selected, nil
}
func deviceAdministration(ctx context.Context, client host.Client, route string, body any, keyPath string) (any, bool, error) {
	network := networkFromPath(route)
	n, e := networkOf(ctx, client, network)
	if e != nil {
		return nil, false, e
	}
	// A local root seed remains the selected provider for root administration.
	if n.Administrator {
		return nil, false, nil
	}
	selected, e := selectedLinkAdministrator(ctx, client, network, keyPath)
	if e != nil || selected == nil {
		return nil, false, e
	}
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	kind := ""
	var payload, output any
	switch request := body.(type) {
	case host.MoveNetwork:
		return nil, true, errors.New("coordinator moves require the current root or original administrator signer")
	case host.CreateInvite:
		return linkInviteSubmission{n, *selected, route, request}, true, nil
	case host.AdmitHost:
		kind = "peerspan-host-admit-v1"
		payload = map[string]any{"network_id": network, "epoch": n.RootEpoch, "host_public_key": request.HostPublicKey, "member": request.Member, "admitted_at": now}
		descriptor, err := descriptorFromNetwork(n)
		if err != nil {
			return nil, true, err
		}
		output = host.Admitted{HostID: hostIDFromKey(request.HostPublicKey), Descriptor: descriptor}
	case host.AdmitPerson:
		kind = "peerspan-person-admit-v1"
		payload = map[string]any{"network_id": network, "epoch": n.RootEpoch, "person_public_key": request.PersonPublicKey, "member": request.Member, "admitted_at": now}
		descriptor, err := descriptorFromNetwork(n)
		if err != nil {
			return nil, true, err
		}
		output = host.Admitted{PersonID: personIDFromKey(request.PersonPublicKey), Descriptor: descriptor}
	case host.RemovePerson:
		person, err := resolvePerson(ctx, client, network, request.PersonID)
		if err != nil {
			return nil, true, err
		}
		kind = "peerspan-person-remove-v1"
		payload = map[string]any{"network_id": network, "person_public_key": person.PublicKey, "removed_at": now}
	case host.RevokeMembership:
		if request.HostID != "" {
			members, err := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/members")
			if err != nil {
				return nil, true, err
			}
			key := ""
			for _, member := range members {
				if member.HostID == request.HostID {
					key = member.PublicKey
				}
			}
			if key == "" {
				return nil, true, errors.New("host is not a member of that network")
			}
			kind = "peerspan-revoke-host-v1"
			payload = map[string]any{"network_id": network, "host_public_key": key, "revoked_at": now}
		} else {
			kind = "peerspan-revoke-invite-v1"
			payload = map[string]any{"network_id": network, "invite_public_key": request.InvitePublicKey, "revoked_at": now}
		}
	default:
		return nil, false, nil
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return nil, true, e
	}
	return linkAdminSubmission{network, host.LinkActionRequest{Kind: kind, PayloadBase64: base64.StdEncoding.EncodeToString(raw), CertificateID: selected.CertificateID}, output}, true, nil
}
