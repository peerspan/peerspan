package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/person"
	"github.com/spf13/pflag"
)

// networkCreateOrJoin runs network create and network join. Unless
// --no-person is given, it finds the person key (--person-key, or the only
// ssh-ed25519 identity in ssh-agent) so the same command admits and binds the
// person. A missing person key only skips that part, with the reason and the
// command that finishes it.
func networkCreateOrJoin(ctx context.Context, client host.Client, command string, fs *pflag.FlagSet, state string, out, errOut io.Writer) error {
	var create host.CreateNetwork
	var join host.JoinNetwork
	var noPerson bool
	path, _ := fs.GetString("person-key")
	var err error
	noPerson, _ = fs.GetBool("no-person")
	if command == "create" {
		create.Name, _ = fs.GetString("name")
		create.Member, _ = fs.GetString("member")
		create.CoordinatorAddress, _ = fs.GetString("coordinator")
		create.CoordinatorPublicKey, _ = fs.GetString("coordinator-key")
	} else {
		join.Token, _ = fs.GetString("token")
		join.Descriptor, _ = fs.GetString("descriptor")
	}
	if command == "join" && (join.Token == "") == (join.Descriptor == "") {
		return errors.New("give exactly one of --token or --descriptor")
	}
	if noPerson && path != "" {
		return errors.New("give at most one of --person-key and --no-person")
	}
	var signer person.Signer
	skipped := "--no-person was given"
	if !noPerson {
		signer, err = person.Load(path)
		if err != nil {
			if path != "" {
				return err
			}
			skipped = err.Error()
			signer = nil
		} else {
			defer signer.Close()
		}
	}

	var result map[string]any
	if command == "create" {
		if signer != nil {
			create.PersonPublicKey = membership.EncodeKey(signer.PublicKey())
		}
		if err = callInto(ctx, client, "POST", "/v1/networks", create, &result); err != nil {
			return err
		}
		if signer != nil {
			bindAfterCreate(ctx, client, signer, result)
		}
	} else {
		if signer != nil {
			if network, err := membership.NetworkOf(join.Token + join.Descriptor); err == nil {
				identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
				if err != nil {
					return err
				}
				binding, err := signedBinding(signer, network, identity.PublicKey)
				if err != nil {
					return err
				}
				join.PersonPublicKey, join.Binding = membership.EncodeKey(signer.PublicKey()), binding
			}
		}
		if err = callInto(ctx, client, "POST", "/v1/networks/join", join, &result); err != nil {
			return err
		}
	}
	if result["person"] == nil {
		id, _ := result["id"].(string)
		next := "capsule-host network bind --network " + id
		if strings.HasPrefix(join.Token, membership.MemberTokenPrefix) {
			next = fmt.Sprintf("capsule-host network redeem-person --token %s, then %s", join.Token, next)
		} else if command == "create" {
			next = fmt.Sprintf("capsule-host network admit --network %s --person SSH_PUBLIC_KEY --member %s, then %s", id, create.Member, next)
		}
		result["person"] = map[string]any{"person_id": nil, "admitted": false, "bound": false, "skipped": skipped, "next": next}
	}
	withState(result, state)
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func callInto(ctx context.Context, client host.Client, method, path string, body any, into *map[string]any) error {
	data, err := client.Call(ctx, method, path, body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

// signedBinding signs a binding of hostKey as the person; the daemon adds the
// host signature.
func signedBinding(signer person.Signer, network, hostKey string) (json.RawMessage, error) {
	b, err := membership.SignHostBinding(signer, network, hostKey, membership.Timestamp(time.Now()))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"network_id": b.NetworkID, "person_public_key": b.PersonPublicKey, "host_public_key": b.HostPublicKey, "bound_at": b.BoundAt, "signature": b.Signature})
}

// bindAfterCreate binds the creator's host once the daemon has admitted the
// creator: the binding names the network, which exists only after creation.
func bindAfterCreate(ctx context.Context, client host.Client, signer person.Signer, result map[string]any) {
	outcome, _ := result["person"].(map[string]any)
	if outcome == nil || outcome["admitted"] != true {
		return
	}
	id, _ := result["id"].(string)
	fail := func(err error) {
		outcome["skipped"] = "this host was not bound: " + err.Error()
		outcome["next"] = "capsule-host network bind --network " + id
	}
	identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
	if err != nil {
		fail(err)
		return
	}
	binding, err := signedBinding(signer, id, identity.PublicKey)
	if err != nil {
		fail(err)
		return
	}
	if _, err = client.Call(ctx, "POST", "/v1/networks/"+url.PathEscape(id)+"/bindings", host.BindHost{Binding: binding}); err != nil {
		fail(err)
		return
	}
	outcome["bound"] = true
	outcome["skipped"] = nil
	outcome["next"] = nil
}

// withState makes follow-up commands exact when --state was given.
func withState(result map[string]any, state string) {
	outcome, _ := result["person"].(map[string]any)
	next, _ := outcome["next"].(string)
	if next == "" || state == "" {
		return
	}
	outcome["next"] = strings.ReplaceAll(next, "capsule-host network ", "capsule-host --state "+state+" network ")
}
