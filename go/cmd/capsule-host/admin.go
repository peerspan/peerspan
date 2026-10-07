package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/person"
)

// Administrators and groups. The signer is chosen automatically: a host that
// holds the root seed signs as the root; otherwise the CLI signs with the
// person key in ssh-agent, which must be a current administrator, and the
// daemon checks and submits the signed statement. Root-only commands without
// the seed sign with --root-key PATH.

// adminKey is --person-key on an administrator-signed command: the key to
// sign with when ssh-agent holds several. Empty means the only agent key.
var adminKey string

// takePersonKey removes --person-key PATH from an administrator-signed
// command's arguments.
func takePersonKey(args []string) ([]string, string) {
	out, key := []string{}, ""
	for i := 0; i < len(args); i++ {
		switch {
		case (args[i] == "--person-key" || args[i] == "-person-key") && i+1 < len(args):
			key = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--person-key="):
			key = strings.TrimPrefix(args[i], "--person-key=")
		default:
			out = append(out, args[i])
		}
	}
	return out, key
}

// errAdminCommand marks commands built here, which need the daemon's state.
var errAdminCommand = errors.New("administrator command")

// administeredCommands are the existing commands an administrator may sign.
var administeredCommands = map[string]bool{"invite": true, "invite-person": true, "admit": true, "revoke": true, "revoke-invite": true, "remove-person": true}

func networkOf(ctx context.Context, client host.Client, id string) (host.Network, error) {
	networks, err := call[[]host.Network](ctx, client, "GET", "/v1/networks")
	if err != nil {
		return host.Network{}, err
	}
	for _, n := range networks {
		if n.ID == id {
			return n, nil
		}
	}
	return host.Network{}, errNotJoined
}

// errNotJoined is reported as the daemon reports an unknown network.
var errNotJoined = &host.ClientError{Status: 404, Code: "not_found", Message: "not found"}

// networkFromPath extracts the network ID from /v1/networks/{id}/....
func networkFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return ""
	}
	id, _ := url.PathUnescape(parts[3])
	return id
}

func personsOf(ctx context.Context, client host.Client, id string) ([]host.Person, error) {
	return call[[]host.Person](ctx, client, "GET", "/v1/networks/"+url.PathEscape(id)+"/persons")
}

func resolvePerson(ctx context.Context, client host.Client, id, given string) (host.Person, error) {
	persons, err := personsOf(ctx, client, id)
	if err != nil {
		return host.Person{}, err
	}
	return host.ResolvePerson(persons, given)
}

// signAsAdministrator turns a request the daemon would sign with the root seed
// into one signed here by the administrator's person key, when this host does
// not hold the seed.
func signAsAdministrator(ctx context.Context, client host.Client, path string, body any) (any, error) {
	id := networkFromPath(path)
	n, err := networkOf(ctx, client, id)
	if err != nil {
		return nil, err
	}
	if n.Administrator {
		return body, nil
	}
	loaded, err := person.Load(adminKey)
	if err != nil {
		return nil, fmt.Errorf("forbidden: this host does not hold the network's root seed, and no administrator key was found: %w", err)
	}
	defer loaded.Close()
	signer := membership.SSHSigner{PersonSigner: loaded}
	now := membership.Timestamp(time.Now())
	switch r := body.(type) {
	case host.CreateInvite:
		if !membership.ValidLabel(r.Member) {
			return nil, errors.New("invalid member label")
		}
		var encoded string
		switch {
		case strings.HasSuffix(path, "/person-invites"):
			t, err := membership.PersonInviteWith(id, signer, n.RootEpoch, r.Member, r.ExpiresAt)
			if err != nil {
				return nil, err
			}
			t.NetworkName, t.CoordinatorAddress, t.CoordinatorPublicKey = n.Name, n.CoordinatorAddress, n.CoordinatorPublicKey
			encoded, err = t.Encode()
			if err != nil {
				return nil, err
			}
		case r.HostOnly:
			t, err := membership.InviteWith(id, signer, r.Member, r.ExpiresAt)
			if err != nil {
				return nil, err
			}
			t.NetworkName, t.CoordinatorAddress, t.CoordinatorPublicKey = n.Name, n.CoordinatorAddress, n.CoordinatorPublicKey
			encoded, err = t.Encode()
			if err != nil {
				return nil, err
			}
		default:
			t, err := membership.MemberInviteWith(id, signer, n.RootEpoch, r.Member, r.ExpiresAt)
			if err != nil {
				return nil, err
			}
			t.NetworkName, t.CoordinatorAddress, t.CoordinatorPublicKey = n.Name, n.CoordinatorAddress, n.CoordinatorPublicKey
			encoded, err = t.Encode()
			if err != nil {
				return nil, err
			}
		}
		return host.CreateInvite{Token: encoded}, nil
	case host.AdmitHost:
		a, err := membership.SignHostAdmissionWith(signer, id, n.RootEpoch, r.HostPublicKey, r.Member, now)
		return host.AdmitHost{Admission: &a}, err
	case host.AdmitPerson:
		a, err := membership.SignPersonAdmissionWith(signer, id, n.RootEpoch, r.PersonPublicKey, r.Member, now)
		return host.AdmitPerson{Admission: &a}, err
	case host.RevokeMembership:
		var statement any
		if r.HostID != "" {
			members, err := call[[]host.NetworkMember](ctx, client, "GET", "/v1/networks/"+url.PathEscape(id)+"/members")
			if err != nil {
				return nil, err
			}
			key := ""
			for _, m := range members {
				if m.HostID == r.HostID {
					key = m.PublicKey
				}
			}
			if key == "" {
				return nil, fmt.Errorf("host %s is not a member of that network", r.HostID)
			}
			statement, err = membership.SignHostRevocationWith(signer, id, key, now)
			if err != nil {
				return nil, err
			}
		} else {
			if statement, err = membership.SignInviteRevocationWith(signer, id, r.InvitePublicKey, now); err != nil {
				return nil, err
			}
		}
		data, err := json.Marshal(statement)
		return host.RevokeMembership{Revocation: data}, err
	case host.RemovePerson:
		p, err := resolvePerson(ctx, client, id, r.PersonID)
		if err != nil {
			return nil, err
		}
		removal, err := membership.SignPersonRemovalWith(signer, id, p.PublicKey, now)
		return host.RemovePerson{Removal: &removal}, err
	}
	return body, nil
}

// rootSigner loads --root-key and checks it is the network's current root.
func rootSigner(n host.Network, path string) (person.Signer, error) {
	if path == "" {
		return nil, errors.New("forbidden: this host does not hold the network's root seed; give --root-key PATH")
	}
	signer, err := person.Load(path)
	if err != nil {
		return nil, err
	}
	if membership.EncodeKey(signer.PublicKey()) != n.CurrentRootPublicKey {
		signer.Close()
		return nil, errors.New("--root-key is not the network's current root")
	}
	return signer, nil
}

func adminRequest(ctx context.Context, client host.Client, args []string, errOut io.Writer) (string, string, any, error) {
	parse := func(name string, args []string, configure func(*flag.FlagSet)) error {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(errOut)
		configure(fs)
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected arguments: %v", fs.Args())
		}
		return nil
	}
	var id, given, rootKey string
	now := membership.Timestamp(time.Now())
	switch args[1] {
	case "delegate-admin", "remove-admin":
		var revokeAdmitted bool
		err := parse("network "+args[1], args[2:], func(fs *flag.FlagSet) {
			fs.StringVar(&id, "network", "", "network ID")
			fs.StringVar(&given, "person", "", "person ID or label")
			fs.StringVar(&rootKey, "root-key", "", "the current SSH root: a .pub file selecting an ssh-agent identity, or an OpenSSH private key file")
			if args[1] == "remove-admin" {
				fs.BoolVar(&revokeAdmitted, "revoke-admitted", false, "also invalidate everything the administrator signed")
			}
		})
		if err != nil {
			return "", "", nil, err
		}
		if id == "" || given == "" {
			return "", "", nil, errors.New("invalid command; see capsule-host --help")
		}
		n, err := networkOf(ctx, client, id)
		if err != nil {
			return "", "", nil, err
		}
		path := "/v1/networks/" + url.PathEscape(id)
		if n.Administrator {
			if args[1] == "delegate-admin" {
				return "POST", path + "/admins", host.DelegateAdmin{Person: given}, nil
			}
			return "POST", path + "/admin-removals", host.RemoveAdmin{Person: given, RevokeAdmitted: revokeAdmitted}, nil
		}
		root, err := rootSigner(n, rootKey)
		if err != nil {
			return "", "", nil, err
		}
		defer root.Close()
		signer := membership.SSHSigner{PersonSigner: root}
		key := ""
		if p, err := resolvePerson(ctx, client, id, given); err == nil {
			key = p.PublicKey
		} else if normalized, keyErr := membership.NormalizePersonKey(given); keyErr == nil && args[1] == "remove-admin" {
			key = normalized // a removed person is no longer listed
		} else {
			return "", "", nil, err
		}
		if args[1] == "delegate-admin" {
			d, err := membership.SignAdminDelegation(signer, id, n.RootEpoch, key, now)
			return "POST", path + "/admins", host.DelegateAdmin{Delegation: &d}, err
		}
		// The removal keeps exactly the statements this host verified as
		// signed by that administrator.
		var kept []string
		if !revokeAdmitted {
			plan, err := call[host.AdminRemovalPlan](ctx, client, "GET", path+"/admin-removal-plan?person="+url.QueryEscape(key))
			if err != nil {
				return "", "", nil, err
			}
			kept = plan.Kept
		}
		r, err := membership.SignAdminRemoval(signer, id, key, revokeAdmitted, kept, now)
		return "POST", path + "/admin-removals", host.RemoveAdmin{Removal: &r}, err
	case "groups":
		if len(args) != 3 {
			return "", "", nil, errors.New("invalid command; see capsule-host --help")
		}
		return "GET", "/v1/networks/" + url.PathEscape(args[2]) + "/groups", nil, nil
	case "group":
		if len(args) < 3 || args[2] != "set" {
			return "", "", nil, errors.New("invalid command; see capsule-host --help")
		}
		var name string
		var members repeated
		err := parse("network group set", args[3:], func(fs *flag.FlagSet) {
			fs.StringVar(&id, "network", "", "network ID")
			fs.StringVar(&name, "group", "", "group name")
			fs.Var(&members, "person", "member person ID or label (repeatable; none deletes the group)")
		})
		if err != nil {
			return "", "", nil, err
		}
		if id == "" || name == "" {
			return "", "", nil, errors.New("invalid command; see capsule-host --help")
		}
		n, err := networkOf(ctx, client, id)
		if err != nil {
			return "", "", nil, err
		}
		path := "/v1/networks/" + url.PathEscape(id) + "/groups"
		if n.Administrator {
			return "POST", path, host.SetGroup{Name: name, Members: members}, nil
		}
		persons, err := personsOf(ctx, client, id)
		if err != nil {
			return "", "", nil, err
		}
		ids := []string{}
		for _, given := range members {
			p, err := host.ResolvePerson(persons, given)
			if err != nil {
				return "", "", nil, err
			}
			ids = append(ids, p.PersonID)
		}
		groups, err := call[[]host.Group](ctx, client, "GET", path+"?all=true")
		if err != nil {
			return "", "", nil, err
		}
		version := int64(1)
		for _, g := range groups {
			if g.Name == name {
				version = g.Version + 1
			}
		}
		loaded, err := person.Load(adminKey)
		if err != nil {
			return "", "", nil, fmt.Errorf("forbidden: this host does not hold the network's root seed, and no administrator key was found: %w", err)
		}
		defer loaded.Close()
		g, err := membership.SignGroup(membership.SSHSigner{PersonSigner: loaded}, id, name, version, ids, now)
		return "POST", path, host.SetGroup{Group: &g}, err
	case "rotate-root":
		var toSSH bool
		if len(args) < 3 {
			return "", "", nil, errors.New("invalid command; see capsule-host --help")
		}
		id = args[2]
		err := parse("network rotate-root", args[3:], func(fs *flag.FlagSet) {
			fs.BoolVar(&toSSH, "to-ssh", false, "rotate to the SSH key named by --root-key")
			fs.StringVar(&rootKey, "root-key", "", "the new SSH root: a .pub file selecting an ssh-agent identity, or an OpenSSH private key file")
		})
		if err != nil {
			return "", "", nil, err
		}
		if !toSSH || rootKey == "" {
			return "", "", nil, errors.New("rotate-root takes --to-ssh with --root-key PATH, or neither")
		}
		return rotateToSSH(ctx, client, id, rootKey, now)
	}
	return "", "", nil, errors.New("invalid command; see capsule-host --help")
}

// rotateToSSH signs everything the new root signs with the key at path. The
// rotation itself is signed by the daemon's root seed, or here by the current
// SSH root found in ssh-agent.
func rotateToSSH(ctx context.Context, client host.Client, id, path, now string) (string, string, any, error) {
	next, err := person.Load(path)
	if err != nil {
		return "", "", nil, err
	}
	defer next.Close()
	n, err := networkOf(ctx, client, id)
	if err != nil {
		return "", "", nil, err
	}
	base := "/v1/networks/" + url.PathEscape(id)
	plan, err := call[host.RotationPlan](ctx, client, "GET", base+"/rotation-plan")
	if err != nil {
		return "", "", nil, err
	}
	nextKey := membership.EncodeKey(next.PublicKey())
	if nextKey == plan.CurrentRootPublicKey {
		return "", "", nil, errors.New("that key is already the network's root")
	}
	signer := membership.SSHSigner{PersonSigner: next}
	signed, err := host.SignRotationPlan(plan, signer, now)
	if err != nil {
		return "", "", nil, err
	}
	req := host.RotateRoot{RootPublicKey: nextKey, Attestations: signed.Attestations, Admissions: signed.Admissions, Groups: signed.Groups}
	if !n.Administrator {
		current, err := membership.DecodeKey(plan.CurrentRootPublicKey)
		if err != nil {
			return "", "", nil, err
		}
		root, err := person.LoadKey(current)
		if err != nil {
			return "", "", nil, fmt.Errorf("this host does not hold the root seed, and the current root key is not in ssh-agent: %w", err)
		}
		defer root.Close()
		rotation, err := membership.SignRotationWith(membership.SSHSigner{PersonSigner: root}, id, plan.Epoch, next.PublicKey(), now)
		if err != nil {
			return "", "", nil, err
		}
		req.Rotation = &rotation
	}
	return "POST", base + "/rotate", req, nil
}
