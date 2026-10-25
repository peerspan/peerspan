package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

// errPersonCommand marks commands that need the person key or the daemon
// before their request can be built.
var errPersonCommand = errors.New("person command")

func personKey(fs *pflag.FlagSet) string { key, _ := fs.GetString("person-key"); return key }

// personShow prints the person identity without a daemon or state directory.
func personShow(fs *pflag.FlagSet, out io.Writer) error {
	path := personKey(fs)

	signer, err := person.Load(path)
	if err != nil {
		return err
	}
	defer signer.Close()
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(person.IdentityOf(signer.PublicKey()))
}

func call[T any](ctx context.Context, client host.Client, method, path string) (T, error) {
	var value T
	data, err := client.Call(ctx, method, path, nil)
	if err == nil {
		err = json.Unmarshal(data, &value)
	}
	return value, err
}

// personRequest builds requests for admit, redeem-person, bind, and unbind.
// Person signatures are made here, by the CLI; the daemon only submits them.
func personRequest(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet) (string, string, any, error) {
	var network, personKey, hostKey, member, token, hostID string
	switch args[1] {
	case "admit":
		network, _ = fs.GetString("network")
		personKey, _ = fs.GetString("person")
		hostKey, _ = fs.GetString("host")
		member, _ = fs.GetString("member")
		if network == "" || (personKey == "") == (hostKey == "") {
			return "", "", nil, errors.New("network admit needs --network and exactly one of --person or --host")
		}
		path := "/v1/networks/" + url.PathEscape(network)
		if hostKey != "" {
			return "POST", path + "/hosts", host.AdmitHost{HostPublicKey: hostKey, Member: member}, nil
		}
		key, err := person.ParsePublicKey(personKey)
		if err != nil {
			return "", "", nil, err
		}
		return "POST", path + "/persons", host.AdmitPerson{PersonPublicKey: membership.EncodeKey(key), Member: member}, nil
	case "redeem-person":
		path, _ := fs.GetString("person-key")
		token, _ = fs.GetString("token")
		signer, err := person.Load(path)
		if err != nil {
			return "", "", nil, err
		}
		defer signer.Close()
		return "POST", "/v1/networks/redeem-person", host.RedeemPerson{Token: token, PersonPublicKey: membership.EncodeKey(signer.PublicKey())}, nil
	case "bind", "unbind":
		path, _ := fs.GetString("person-key")
		network, _ = fs.GetString("network")
		if args[1] == "unbind" {
			hostID, _ = fs.GetString("host")
		}
		if network == "" || (args[1] == "unbind" && hostID == "") {
			return "", "", nil, invalidCommand()
		}
		target := ""
		if args[1] == "bind" {
			identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
			if err != nil {
				return "", "", nil, err
			}
			target = identity.PublicKey
		} else {
			members, err := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(network)+"/members")
			if err != nil {
				return "", "", nil, err
			}
			for _, m := range members {
				if m.HostID == hostID {
					target = m.PublicKey
				}
			}
			if target == "" {
				return "", "", nil, fmt.Errorf("host %s is not a member of that network", hostID)
			}
		}
		selected, err := selectedLinkAdministrator(ctx, client, network, path)
		if err != nil {
			return "", "", nil, err
		}
		if selected != nil {
			kind, field := "peerspan-host-bind-v1", "bound_at"
			var result any = host.Bound{NetworkID: network, HostID: hostIDFromKey(target), PersonID: personIDFromKey(selected.PersonPublicKey)}
			if args[1] == "unbind" {
				kind, field = "peerspan-host-unbind-v1", "unbound_at"
				result = host.RevocationResult{NetworkID: network, Kind: membership.KindUnbind, Subject: membership.UnbindSubject(selected.PersonPublicKey, target), Submitted: true}
			}
			payload, err := json.Marshal(map[string]any{"network_id": network, "person_public_key": selected.PersonPublicKey, "host_public_key": target, field: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)})
			if err != nil {
				return "", "", nil, err
			}
			return "POST", "/v1/networks/" + url.PathEscape(network) + "/link-actions", linkAdminSubmission{network, host.LinkActionRequest{Kind: kind, PayloadBase64: base64.StdEncoding.EncodeToString(payload), CertificateID: selected.CertificateID}, result}, nil
		}
		signer, err := person.Load(path)
		if err != nil {
			return "", "", nil, err
		}
		defer signer.Close()
		now := membership.Timestamp(time.Now())
		base := "/v1/networks/" + url.PathEscape(network)
		if args[1] == "bind" {
			binding, err := membership.SignHostBinding(signer, network, target, now)
			if err != nil {
				return "", "", nil, err
			}
			// host_signature is added by the daemon itself.
			data, err := json.Marshal(map[string]string{"network_id": binding.NetworkID, "person_public_key": binding.PersonPublicKey, "host_public_key": binding.HostPublicKey, "bound_at": binding.BoundAt, "signature": binding.Signature})
			return "POST", base + "/bindings", host.BindHost{Binding: data}, err
		}
		unbinding, err := membership.SignHostUnbinding(signer, network, target, now)
		return "POST", base + "/unbindings", host.UnbindHost{Unbinding: unbinding}, err
	}
	return "", "", nil, invalidCommand()
}
