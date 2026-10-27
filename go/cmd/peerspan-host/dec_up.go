package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/spf13/pflag"
)

func decPublicMap(value any) map[string]any {
	raw, _ := json.Marshal(value)
	result := map[string]any{}
	_ = json.Unmarshal(raw, &result)
	return result
}
func upLinkFlags(key string) *pflag.FlagSet {
	fs := pflag.NewFlagSet("link resume", pflag.ContinueOnError)
	fs.String("person-key", key, "")
	fs.String("root-key", "", "")
	return fs
}
func setupDecMembership(ctx context.Context, client host.Client, create string, join bool, token, label, key string, result *setupResult, state string, errOut io.Writer) (host.DecNetworkView, bool, error) {
	var empty host.DecNetworkView
	requests, e := call[[]host.DecLinkView](ctx, client, "GET", "/v2/link/requests")
	if e != nil {
		return empty, false, e
	}
	identity, e := call[host.Identity](ctx, client, "GET", "/v1/host")
	if e != nil {
		return empty, false, e
	}
	pending := []host.DecLinkView{}
	for _, request := range requests {
		if request.Role == "requester" && request.Host == identity.PublicKey && request.State != "linked" && request.State != "cancelled" && request.State != "expired" && request.State != "migration_adopted" {
			pending = append(pending, request)
		}
	}
	resumed := false
	if len(pending) > 0 {
		result.Network = map[string]any{"link_request": pending[0]}
		result.Next = "peerspan --state " + setupQuote(state) + " link resume " + pending[0].Request
		if len(pending) != 1 || create != "" || join {
			return empty, false, errors.New("resume or cancel the exact existing machine request before another setup choice")
		}
		if pending[0].State == "migration_prepared" {
			result.Next = "peerspan network migrate resume " + pending[0].Network
			return empty, false, errors.New("this machine's reviewed staging needs whole-network migration adoption before attachment")
		}
		runError := runLinkWithCodeDisplay(ctx, client, []string{"link", "resume", pending[0].Request}, upLinkFlags(key), io.Discard, errOut, false)
		view, e := call[host.DecLinkView](ctx, client, "GET", decLinkBase(pending[0].Request))
		if e != nil {
			return empty, false, e
		}
		result.Network = map[string]any{"link_request": view}
		if runError != nil {
			return empty, false, runError
		}
		if view.State != "linked" {
			return empty, false, errors.New("the exact machine link is incomplete; preserve this request and review its next action")
		}
		resumed = true
	}
	networks, e := call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
	if e != nil {
		return empty, false, e
	}
	if len(networks) > 1 {
		return empty, false, errors.New("guided up needs an explicit single network; inspect network list and use explicit commands")
	}
	existing := len(networks) == 1 && !resumed
	if len(networks) == 0 {
		legacy, e := call[[]host.Network](ctx, client, "GET", "/v1/networks")
		if e != nil {
			return empty, false, e
		}
		if len(legacy) > 0 {
			result.Next = "peerspan network migrate status " + legacy[0].ID
			return empty, false, errors.New("existing legacy network history requires explicit reviewed migration; up cannot create or enroll through a coordinator")
		}
	}
	if len(networks) == 0 && create == "" && !join {
		choice, e := setupPrompt(ctx, errOut, "Create a network, link this machine, or join with an invite (create/link/join)", "", false)
		if e != nil {
			return empty, false, e
		}
		switch strings.ToLower(choice) {
		case "create":
			create, e = setupPrompt(ctx, errOut, "Network name", "personal", false)
		case "join":
			join = true
			token, e = setupPrompt(ctx, errOut, "Private invitation (hidden)", "", true)
			if e == nil {
				_, e = inspectDecInvitation(token)
			}
		case "link":
			request, err := linkCall[decCLILink](ctx, client, "POST", "/v2/link/requests", host.DecLinkCreate{Mode: "new", Network: "-", Person: "-", Migration: "-", Invitation: "-", Helpers: []dec.ContactRelay{}})
			if err != nil {
				return empty, false, err
			}
			result.Network = map[string]any{"link_request": request.DecLinkView}
			result.Next = "peerspan --state " + setupQuote(state) + " link resume " + request.Request
			err = guideDecLink(ctx, client, request, io.Discard, errOut, true)
			view, readError := call[host.DecLinkView](ctx, client, "GET", decLinkBase(request.Request))
			if readError != nil {
				return empty, false, readError
			}
			result.Network = map[string]any{"link_request": view}
			if err != nil {
				return empty, false, err
			}
			if view.State != "linked" {
				return empty, false, errors.New("linking is incomplete; neither another person nor an attachment was created")
			}
			networks, e = call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
		default:
			e = errors.New("choose create, link or join")
		}
		if e != nil {
			return empty, false, e
		}
	}
	if len(networks) == 0 && join {
		request, e := createDecJoin(ctx, client, token, key, errOut)
		if e != nil {
			return empty, false, e
		}
		result.Network = map[string]any{"link_request": request.DecLinkView}
		result.Next = "peerspan --state " + setupQuote(state) + " link resume " + request.Request
		if !isTerminal(os.Stdin) {
			return empty, false, errors.New("admission is pending; show the reply code using peerspan link resume and complete explicit approvals before attachment")
		}
		runError := guideDecLink(ctx, client, request, io.Discard, errOut, true)
		view, e := call[host.DecLinkView](ctx, client, "GET", decLinkBase(request.Request))
		if e != nil {
			return empty, false, e
		}
		result.Network = map[string]any{"link_request": view}
		if runError != nil {
			return empty, false, runError
		}
		if view.State != "linked" {
			return empty, false, errors.New("admission is incomplete; preserve the same person and request")
		}
		networks, e = call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
		if e != nil {
			return empty, false, e
		}
	}
	if len(networks) == 0 && create != "" {
		f := pflag.NewFlagSet("network create", pflag.ContinueOnError)
		f.String("name", create, "")
		f.String("as", label, "")
		f.String("member", "", "")
		f.String("person-key", key, "")
		f.String("person-key-file", "", "")
		f.Bool("no-person", false, "")
		f.Bool("trusted", false, "")
		if e = onboardDecCreate(ctx, client, nil, f, errOut, func(value map[string]any) error { result.Network = value; return nil }); e != nil {
			return empty, false, e
		}
		networks, e = call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
		if e != nil {
			return empty, false, e
		}
	}
	if len(networks) != 1 {
		return empty, false, errors.New("membership changed; inspect the same network before retrying setup")
	}
	n := networks[0]
	result.Network = decPublicMap(n)
	if create != "" && n.Name != create {
		return empty, false, errors.New("creation inputs differ from the current network")
	}
	if join {
		invitation, e := inspectDecInvitation(token)
		if e != nil {
			return empty, false, e
		}
		if invitation.Descriptor.NetworkID != n.ID || invitation.Context != n.Context {
			return empty, false, errors.New("the introduction names another network")
		}
	}
	if label != "" && label != n.Member {
		return empty, false, errors.New("--as differs from this host's current person label")
	}
	result.Next = "peerspan network sync " + n.ID
	if n.Authority.State != "usable" || n.Person == "-" {
		return empty, false, fmt.Errorf("the same network/person requires repair: %s", n.Authority.State)
	}
	if n.Provider == nil || n.ProviderState.State != "available" {
		code := n.ProviderState.Code
		if code == "-" {
			code = "signer_unavailable"
		}
		return empty, false, fmt.Errorf("the exact selected provider requires repair: %s; no fallback or new person was selected", code)
	}
	if n.Provider.Person != n.Person || n.Provider.Host != identity.PublicKey {
		return empty, false, errors.New("the selected provider does not match this machine's independently verified binding")
	}
	fmt.Fprintf(errOut, "Network: %s (%s); person: %s; provider: %s\n", n.Name, n.ID, n.Person, n.Provider.Kind)
	return n, existing, nil
}
func setupDecTrust(ctx context.Context, client host.Client, n host.DecNetworkView, existing, trusted, untrusted bool, key string, errOut io.Writer) error {
	if !existing && !trusted && !untrusted {
		if isTerminal(os.Stdin) {
			answer, e := setupPrompt(ctx, errOut, "Let this machine use your capabilities on other machines, and source tools those hosts allow? (y/N)", "no", false)
			if e != nil {
				return e
			}
			trusted = strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
		}
		untrusted = !trusted
	}
	if !trusted && !untrusted {
		return nil
	}
	f := pflag.NewFlagSet("trust", pflag.ContinueOnError)
	f.String("network", n.ID, "")
	f.String("person-key", key, "")
	command := "trust"
	if untrusted {
		command = "untrust"
	}
	return runTrust(ctx, client, command, nil, f, io.Discard)
}
