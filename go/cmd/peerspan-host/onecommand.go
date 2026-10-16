package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

// networkCreateOrJoin runs network create, network join, and join. Unless
// --no-person is given, it uses a person key so the same command admits and
// binds the person: --person-key, the generated key, the only ssh-ed25519
// identity in ssh-agent, or else a newly generated key, which is saved only
// once the network request has succeeded.
func networkCreateOrJoin(ctx context.Context, client host.Client, command string, positional []string, fs *pflag.FlagSet, state string, out, errOut io.Writer) error {
	var create host.CreateNetwork
	var join host.JoinNetwork
	var noPerson bool
	path, _ := fs.GetString("person-key")
	var err error
	noPerson, _ = fs.GetBool("no-person")
	if command == "create" {
		create.Name, _ = fs.GetString("name")
		if len(positional) == 1 {
			if fs.Changed("name") {
				return errors.New("give the network name once: as NAME or with --name")
			}
			create.Name = positional[0]
		}
		if create.Name == "" {
			return errors.New("network create needs a NAME")
		}
		label, _ := fs.GetString("as")
		alias, _ := fs.GetString("member")
		if fs.Changed("as") && fs.Changed("member") {
			return errors.New("give at most one of --as and its alias --member")
		}
		if alias != "" {
			label = alias
		}
		if label == "" {
			if label = loginName(); label == "" {
				return errors.New("cannot determine the login name; give --as LABEL")
			}
		}
		create.Member = label
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
	var choice *person.Choice
	skipped := "--no-person was given"
	if !noPerson {
		if choice, err = person.Choose(path); err != nil {
			return err
		}
		defer choice.Close()
		signer = choice
	}
	// save writes a new key once the network request has succeeded.
	save := func() error {
		if choice == nil {
			return nil
		}
		label := create.Member
		if command == "join" {
			label = tokenMember(join.Token)
		}
		hostname, _ := os.Hostname()
		if err := choice.Save(fmt.Sprintf("peerspan %s@%s", label, hostname)); err != nil {
			return fmt.Errorf("the host joined, but the new person key could not be saved to %s: %w", choice.Path, err)
		}
		return nil
	}

	var result map[string]any
	if command == "create" {
		if signer != nil {
			create.PersonPublicKey = membership.EncodeKey(signer.PublicKey())
		}
		if err = callInto(ctx, client, "POST", "/v1/networks", create, &result); err != nil {
			return err
		}
		if err = save(); err != nil {
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
		if err = save(); err != nil {
			return err
		}
	}
	if result["person"] == nil {
		id, _ := result["id"].(string)
		next := programName + " network bind --network " + id
		if strings.HasPrefix(join.Token, membership.MemberTokenPrefix) {
			next = fmt.Sprintf("%s network redeem-person --token %s, then %s", programName, join.Token, next)
		} else if command == "create" {
			next = fmt.Sprintf("%s network admit --network %s --person SSH_PUBLIC_KEY --member %s, then %s", programName, id, create.Member, next)
		}
		result["person"] = map[string]any{"person_id": nil, "admitted": false, "bound": false, "skipped": skipped, "next": next}
	}
	if choice != nil {
		describeKey(result, choice, command == "join" && strings.HasPrefix(join.Token, membership.MemberTokenPrefix))
	}
	withState(result, state)
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// describeKey adds person.key, {source, public_key, path}, and the follow-up
// a key needs: backing up a new key, or, when a join's person part failed
// with a generated or new key on a member invite, copying the first machine's key.
func describeKey(result map[string]any, choice *person.Choice, memberJoin bool) {
	outcome, _ := result["person"].(map[string]any)
	if outcome == nil {
		return
	}
	var path any
	if choice.Path != "" && choice.Source != person.SourceAgent {
		path = choice.Path
	}
	outcome["key"] = map[string]any{"source": choice.Source, "public_key": membership.EncodeKey(choice.PublicKey()), "path": path}
	next, _ := outcome["next"].(string)
	id, _ := result["id"].(string)
	if memberJoin && outcome["admitted"] != true && (choice.Source == person.SourceNew || choice.Source == person.SourceGenerated) {
		next = fmt.Sprintf("to use the same person as on your first machine, copy its %s (and .pub) to %s, then run %s network bind --network %s", filepath.Base(choice.Path), choice.Path, programName, id)
	}
	if choice.Source == person.SourceNew {
		backup := fmt.Sprintf("back up the new person key %s; copy it to your other machines to use the same identity there", choice.Path)
		if next != "" {
			next += "; " + backup
		} else {
			next = backup
		}
	}
	if next != "" {
		outcome["next"] = next
	}
}

// tokenMember is an invite token's member label, or the login name.
func tokenMember(token string) string {
	now := time.Now()
	if t, err := membership.DecodeMemberToken(token, now); err == nil {
		return t.Member
	}
	if t, err := membership.DecodeToken(token, now); err == nil {
		return t.Member
	}
	return loginName()
}

// loginName is the login name: the user name of the effective user ID,
// else $USER.
func loginName() string {
	if u, err := user.LookupId(strconv.Itoa(os.Geteuid())); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

// inviteOutput is the top-level invite's output: the member invite and the
// join command that redeems it.
func inviteOutput(result json.RawMessage) (json.RawMessage, error) {
	var invite host.Invite
	if err := json.Unmarshal(result, &invite); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"network_id": invite.NetworkID, "member": invite.Member, "invite_expires_at": invite.InviteExpiresAt, "token": invite.Token, "join": "peerspan join " + invite.Token})
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
		outcome["next"] = programName + " network bind --network " + id
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
	outcome["next"] = strings.ReplaceAll(next, programName+" network ", programName+" --state "+state+" network ")
}
