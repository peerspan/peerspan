package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/person"
)

// errPersonCommand marks commands that need the person key or the daemon
// before their request can be built.
var errPersonCommand = errors.New("person command")

func personFlags(name string, args []string, errOut io.Writer, configure func(*flag.FlagSet)) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	key := fs.String("person-key", "", "ssh-ed25519 public key in ssh-agent, or an unencrypted OpenSSH private key file")
	configure(fs)
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return *key, nil
}

// personShow prints the person identity without a daemon or state directory.
func personShow(args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] != "show" {
		return errors.New("invalid command; see capsule-host --help")
	}
	path, err := personFlags("person show", args[1:], errOut, func(*flag.FlagSet) {})
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
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
func personRequest(ctx context.Context, client host.Client, args []string, errOut io.Writer) (string, string, any, error) {
	var network, personKey, hostKey, member, token, hostID string
	switch args[1] {
	case "admit":
		_, err := personFlags("network admit", args[2:], errOut, func(fs *flag.FlagSet) {
			fs.StringVar(&network, "network", "", "network ID")
			fs.StringVar(&personKey, "person", "", "person ssh-ed25519 public key line, or a path to one")
			fs.StringVar(&hostKey, "host", "", "host public key (Base64, from the host's info)")
			fs.StringVar(&member, "member", "", "member label")
		})
		if err != nil {
			return "", "", nil, err
		}
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
		path, err := personFlags("network redeem-person", args[2:], errOut, func(fs *flag.FlagSet) {
			fs.StringVar(&token, "token", "", "person invite token")
		})
		if err != nil {
			return "", "", nil, err
		}
		signer, err := person.Load(path)
		if err != nil {
			return "", "", nil, err
		}
		defer signer.Close()
		return "POST", "/v1/networks/redeem-person", host.RedeemPerson{Token: token, PersonPublicKey: membership.EncodeKey(signer.PublicKey())}, nil
	case "bind", "unbind":
		path, err := personFlags("network "+args[1], args[2:], errOut, func(fs *flag.FlagSet) {
			fs.StringVar(&network, "network", "", "network ID")
			if args[1] == "unbind" {
				fs.StringVar(&hostID, "host", "", "host ID to unbind")
			}
		})
		if err != nil {
			return "", "", nil, err
		}
		if network == "" || (args[1] == "unbind" && hostID == "") {
			return "", "", nil, errors.New("invalid command; see capsule-host --help")
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
	return "", "", nil, errors.New("invalid command; see capsule-host --help")
}
